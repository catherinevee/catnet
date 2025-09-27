"""
Alerting components for monitoring service.
"""

import asyncio
import logging
import json
import hashlib
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from enum import Enum
import re

import aiohttp
from jinja2 import Template
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import AsyncSession

from .models import (
    Alert, AlertStatus, AlertSeverity, AlertRule,
    NotificationChannel, NotificationType, NotificationRequest,
    IncidentReport, Metric
)

logger = logging.getLogger(__name__)


class AlertManager:
    """Manages alerts lifecycle."""

    def __init__(self):
        self.active_alerts = {}
        self.alert_rules = {}
        self.silence_rules = []
        self.redis_client = None
        self.db_session = None

    async def initialize(self, redis_client: redis.Redis, db_session: AsyncSession):
        """Initialize alert manager."""
        self.redis_client = redis_client
        self.db_session = db_session
        await self._load_rules()
        await self._load_silences()

    async def _load_rules(self):
        """Load alert rules from database."""
        try:
            from sqlalchemy import select

            if self.db_session:
                result = await self.db_session.execute(select(AlertRule))
                rules = result.scalars().all()

                for rule in rules:
                    self.alert_rules[rule.id] = rule

                logger.info(f"Loaded {len(rules)} alert rules from database")
        except Exception as e:
            logger.error(f"Failed to load alert rules: {e}")

    async def _load_silences(self):
        """Load silence rules from database."""
        try:
            # Load from Redis cache for performance
            if self.redis_client:
                silence_keys = await self.redis_client.keys("silence:*")

                for key in silence_keys:
                    silence_data = await self.redis_client.get(key)
                    if silence_data:
                        silence = json.loads(silence_data)
                        # Check if still active
                        if datetime.fromisoformat(silence['ends_at']) > datetime.utcnow():
                            self.silence_rules.append(silence)

                logger.info(f"Loaded {len(self.silence_rules)} active silences")
        except Exception as e:
            logger.error(f"Failed to load silences: {e}")

    async def create_alert(self, rule: AlertRule, evaluation_result: Dict[str, Any]) -> Alert:
        """Create new alert from rule evaluation."""
        # Generate fingerprint for deduplication
        fingerprint = self._generate_fingerprint(rule, evaluation_result)

        # Check if alert already exists
        existing = await self._get_existing_alert(fingerprint)
        if existing:
            # Update existing alert
            existing.actual_value = evaluation_result.get('value')
            existing.annotations.update(evaluation_result.get('annotations', {}))
            await self._update_alert(existing)
            return existing

        # Create new alert
        alert = Alert(
            name=rule.name,
            description=rule.description or f"Alert triggered for {rule.name}",
            severity=rule.severity,
            status=AlertStatus.FIRING,
            rule_id=rule.id,
            metric_name=evaluation_result.get('metric'),
            threshold_value=evaluation_result.get('threshold'),
            actual_value=evaluation_result.get('value'),
            labels={**rule.labels, **evaluation_result.get('labels', {})},
            annotations={**rule.annotations, **evaluation_result.get('annotations', {})},
            fingerprint=fingerprint,
            source=evaluation_result.get('source', 'alert_manager'),
            runbook_url=rule.annotations.get('runbook_url')
        )

        # Check if silenced
        if await self._is_silenced(alert):
            alert.status = AlertStatus.SILENCED
            alert.silence_id = await self._get_matching_silence(alert)

        # Store alert
        await self._store_alert(alert)
        self.active_alerts[fingerprint] = alert

        return alert

    async def create_anomaly_alert(self, anomaly: Dict[str, Any]) -> Alert:
        """Create alert from detected anomaly."""
        # Generate fingerprint
        fingerprint = hashlib.sha256(
            f"{anomaly['metric']}_{anomaly['timestamp']}".encode()
        ).hexdigest()

        # Map anomaly severity to alert severity
        severity_mapping = {
            'critical': AlertSeverity.CRITICAL,
            'high': AlertSeverity.HIGH,
            'medium': AlertSeverity.MEDIUM,
            'low': AlertSeverity.LOW
        }

        alert = Alert(
            name=f"Anomaly detected in {anomaly['metric']}",
            description=f"Anomalous value {anomaly['value']} detected. Reasons: {', '.join(anomaly['reasons'])}",
            severity=severity_mapping.get(anomaly['severity'], AlertSeverity.MEDIUM),
            status=AlertStatus.FIRING,
            rule_id="anomaly_detection",
            metric_name=anomaly['metric'],
            actual_value=anomaly['value'],
            labels={'type': 'anomaly', 'metric': anomaly['metric']},
            annotations={
                'anomaly_score': str(anomaly['anomaly_score']),
                'context': json.dumps(anomaly['context'])
            },
            fingerprint=fingerprint,
            source="anomaly_detector"
        )

        await self._store_alert(alert)
        self.active_alerts[fingerprint] = alert

        return alert

    async def acknowledge(self, alert_id: str, user: str) -> Alert:
        """Acknowledge an alert."""
        alert = await self._get_alert(alert_id)

        if alert:
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.acknowledged_at = datetime.utcnow()
            alert.acknowledged_by = user

            await self._update_alert(alert)

        return alert

    async def resolve(self, alert_id: str, resolution: str = None) -> Alert:
        """Resolve an alert."""
        alert = await self._get_alert(alert_id)

        if alert:
            alert.status = AlertStatus.RESOLVED
            alert.resolved_at = datetime.utcnow()

            if resolution:
                alert.annotations['resolution'] = resolution

            await self._update_alert(alert)

            # Remove from active alerts
            if alert.fingerprint in self.active_alerts:
                del self.active_alerts[alert.fingerprint]

        return alert

    async def resolve_alert(self, rule_id: str):
        """Resolve all alerts for a rule."""
        for fingerprint, alert in list(self.active_alerts.items()):
            if alert.rule_id == rule_id:
                await self.resolve(alert.id)

    async def create_rule(self, request: Dict[str, Any], created_by: str) -> AlertRule:
        """Create new alert rule."""
        rule = AlertRule(
            name=request['name'],
            description=request.get('description'),
            expression=request['expression'],
            severity=request['severity'],
            for_duration=request.get('for_duration'),
            interval=request.get('interval', '1m'),
            labels=request.get('labels', {}),
            annotations=request.get('annotations', {}),
            notification_channels=request.get('notification_channels', []),
            created_by=created_by
        )

        # Validate expression
        if not await self._validate_expression(rule.expression):
            raise ValueError(f"Invalid alert expression: {rule.expression}")

        # Store rule
        await self._store_rule(rule)
        self.alert_rules[rule.id] = rule

        return rule

    async def list_rules(self) -> List[AlertRule]:
        """List all alert rules."""
        return list(self.alert_rules.values())

    async def get_enabled_rules(self) -> List[AlertRule]:
        """Get enabled alert rules."""
        return [r for r in self.alert_rules.values() if r.is_enabled]

    async def enable_rule(self, rule_id: str) -> AlertRule:
        """Enable alert rule."""
        if rule_id in self.alert_rules:
            self.alert_rules[rule_id].is_enabled = True
            await self._update_rule(self.alert_rules[rule_id])

        return self.alert_rules.get(rule_id)

    async def disable_rule(self, rule_id: str) -> AlertRule:
        """Disable alert rule."""
        if rule_id in self.alert_rules:
            self.alert_rules[rule_id].is_enabled = False
            await self._update_rule(self.alert_rules[rule_id])

            # Resolve active alerts for this rule
            await self.resolve_alert(rule_id)

        return self.alert_rules.get(rule_id)

    def _generate_fingerprint(self, rule: AlertRule, evaluation_result: Dict[str, Any]) -> str:
        """Generate unique fingerprint for alert deduplication."""
        components = [
            rule.id,
            json.dumps(rule.labels, sort_keys=True),
            json.dumps(evaluation_result.get('labels', {}), sort_keys=True)
        ]

        return hashlib.sha256(''.join(components).encode()).hexdigest()

    async def _get_existing_alert(self, fingerprint: str) -> Optional[Alert]:
        """Get existing alert by fingerprint."""
        return self.active_alerts.get(fingerprint)

    async def _get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get alert by ID."""
        for alert in self.active_alerts.values():
            if alert.id == alert_id:
                return alert
        return None

    async def _is_silenced(self, alert: Alert) -> bool:
        """Check if alert is silenced."""
        for silence in self.silence_rules:
            if await self._matches_silence(alert, silence):
                return True
        return False

    async def _matches_silence(self, alert: Alert, silence: Dict[str, Any]) -> bool:
        """Check if alert matches silence rule."""
        # Check time range
        now = datetime.utcnow()
        if silence.get('starts_at') and now < silence['starts_at']:
            return False
        if silence.get('ends_at') and now > silence['ends_at']:
            return False

        # Check matchers
        for matcher in silence.get('matchers', []):
            label_value = alert.labels.get(matcher['name'])

            if matcher['type'] == 'equal':
                if label_value != matcher['value']:
                    return False
            elif matcher['type'] == 'regex':
                if not re.match(matcher['value'], str(label_value)):
                    return False

        return True

    async def _get_matching_silence(self, alert: Alert) -> Optional[str]:
        """Get ID of matching silence rule."""
        for silence in self.silence_rules:
            if await self._matches_silence(alert, silence):
                return silence.get('id')
        return None

    async def _validate_expression(self, expression: str) -> bool:
        """Validate alert rule expression."""
        # Basic validation - in production would parse PromQL
        return len(expression) > 0 and not any(char in expression for char in [';', '&&', '||'])

    async def _store_alert(self, alert: Alert):
        """Store alert in database."""
        try:
            if self.db_session:
                self.db_session.add(alert)
                await self.db_session.commit()

                # Cache in Redis for fast retrieval
                if self.redis_client:
                    alert_data = {
                        'id': alert.id,
                        'name': alert.name,
                        'description': alert.description,
                        'severity': alert.severity.value,
                        'status': alert.status.value,
                        'fingerprint': alert.fingerprint,
                        'fired_at': alert.fired_at.isoformat(),
                        'labels': alert.labels,
                        'annotations': alert.annotations
                    }
                    await self.redis_client.setex(
                        f"alert:{alert.id}",
                        7200,  # 2 hours TTL
                        json.dumps(alert_data, default=str)
                    )

                logger.debug(f"Stored alert {alert.id} in database")
        except Exception as e:
            logger.error(f"Failed to store alert: {e}")
            # Rollback transaction
            if self.db_session:
                await self.db_session.rollback()

    async def _update_alert(self, alert: Alert):
        """Update alert in database."""
        try:
            if self.db_session:
                # SQLAlchemy will automatically track changes
                await self.db_session.commit()

                # Update Redis cache
                if self.redis_client:
                    alert_data = {
                        'id': alert.id,
                        'name': alert.name,
                        'description': alert.description,
                        'severity': alert.severity.value,
                        'status': alert.status.value,
                        'fingerprint': alert.fingerprint,
                        'fired_at': alert.fired_at.isoformat(),
                        'labels': alert.labels,
                        'annotations': alert.annotations
                    }
                    await self.redis_client.setex(
                        f"alert:{alert.id}",
                        7200,  # 2 hours TTL
                        json.dumps(alert_data, default=str)
                    )

                logger.debug(f"Updated alert {alert.id}")
        except Exception as e:
            logger.error(f"Failed to update alert: {e}")
            if self.db_session:
                await self.db_session.rollback()

    async def _store_rule(self, rule: AlertRule):
        """Store alert rule in database."""
        try:
            if self.db_session:
                self.db_session.add(rule)
                await self.db_session.commit()
                logger.info(f"Stored alert rule {rule.name}")
        except Exception as e:
            logger.error(f"Failed to store rule: {e}")
            if self.db_session:
                await self.db_session.rollback()

    async def _update_rule(self, rule: AlertRule):
        """Update alert rule in database."""
        try:
            if self.db_session:
                await self.db_session.commit()
                logger.info(f"Updated alert rule {rule.name}")
        except Exception as e:
            logger.error(f"Failed to update rule: {e}")
            if self.db_session:
                await self.db_session.rollback()


class AlertEvaluator:
    """Evaluates alert rules."""

    def __init__(self):
        self.metric_storage = None
        self.evaluation_cache = {}

    async def initialize(self, metric_storage):
        """Initialize evaluator."""
        self.metric_storage = metric_storage

    async def evaluate(self, rule: AlertRule) -> Dict[str, Any]:
        """Evaluate alert rule."""
        result = {
            'should_fire': False,
            'should_resolve': False,
            'value': None,
            'threshold': None,
            'metric': None,
            'labels': {},
            'annotations': {}
        }

        # Parse and evaluate expression
        try:
            evaluation = await self._evaluate_expression(rule.expression)

            if evaluation['result']:
                # Check for duration if specified
                if rule.for_duration:
                    if not await self._check_duration(rule, evaluation):
                        return result

                result['should_fire'] = True
                result['value'] = evaluation.get('value')
                result['threshold'] = evaluation.get('threshold')
                result['metric'] = evaluation.get('metric')
                result['labels'] = evaluation.get('labels', {})
                result['annotations'] = self._expand_annotations(rule.annotations, evaluation)

            else:
                # Check if there's an active alert to resolve
                if await self._has_active_alert(rule.id):
                    result['should_resolve'] = True

        except Exception as e:
            logger.error(f"Error evaluating rule {rule.id}: {e}")

        return result

    async def _evaluate_expression(self, expression: str) -> Dict[str, Any]:
        """Evaluate alert expression."""
        # Parse expression (simplified - in production would use PromQL parser)
        # Example: "cpu_usage > 80"

        parts = expression.split()
        if len(parts) != 3:
            raise ValueError(f"Invalid expression format: {expression}")

        metric_name = parts[0]
        operator = parts[1]
        threshold = float(parts[2])

        # Get latest metric value
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(minutes=5)

        metrics = await self.metric_storage.query(
            metric_names=[metric_name],
            start_time=start_time,
            end_time=end_time,
            limit=1
        )

        if not metrics:
            return {'result': False}

        latest_value = metrics[0].value

        # Evaluate condition
        result = self._compare(latest_value, operator, threshold)

        return {
            'result': result,
            'value': latest_value,
            'threshold': threshold,
            'metric': metric_name,
            'labels': metrics[0].labels if metrics else {}
        }

    def _compare(self, value: float, operator: str, threshold: float) -> bool:
        """Compare value with threshold using operator."""
        operators = {
            '>': lambda v, t: v > t,
            '>=': lambda v, t: v >= t,
            '<': lambda v, t: v < t,
            '<=': lambda v, t: v <= t,
            '==': lambda v, t: v == t,
            '!=': lambda v, t: v != t,
        }

        if operator not in operators:
            raise ValueError(f"Invalid operator: {operator}")

        return operators[operator](value, threshold)

    async def _check_duration(self, rule: AlertRule, evaluation: Dict[str, Any]) -> bool:
        """Check if condition has been true for specified duration."""
        # Parse duration (e.g., "5m", "1h")
        duration = self._parse_duration(rule.for_duration)

        # Check historical evaluations
        cache_key = f"{rule.id}_{evaluation['metric']}"

        if cache_key not in self.evaluation_cache:
            self.evaluation_cache[cache_key] = []

        # Add current evaluation
        self.evaluation_cache[cache_key].append({
            'timestamp': datetime.utcnow(),
            'result': evaluation['result']
        })

        # Clean old entries
        cutoff = datetime.utcnow() - duration
        self.evaluation_cache[cache_key] = [
            e for e in self.evaluation_cache[cache_key]
            if e['timestamp'] > cutoff
        ]

        # Check if all evaluations in duration are true
        if len(self.evaluation_cache[cache_key]) > 0:
            return all(e['result'] for e in self.evaluation_cache[cache_key])

        return False

    def _parse_duration(self, duration_str: str) -> timedelta:
        """Parse duration string to timedelta."""
        if duration_str.endswith('s'):
            return timedelta(seconds=int(duration_str[:-1]))
        elif duration_str.endswith('m'):
            return timedelta(minutes=int(duration_str[:-1]))
        elif duration_str.endswith('h'):
            return timedelta(hours=int(duration_str[:-1]))
        elif duration_str.endswith('d'):
            return timedelta(days=int(duration_str[:-1]))
        else:
            raise ValueError(f"Invalid duration format: {duration_str}")

    async def _has_active_alert(self, rule_id: str) -> bool:
        """Check if rule has active alert."""
        try:
            # Check in memory cache first
            for alert in self.active_alerts.values():
                if alert.rule_id == rule_id and alert.status in [AlertStatus.FIRING, AlertStatus.ACKNOWLEDGED]:
                    return True

            # Check Redis cache
            if self.redis_client:
                pattern = f"alert:*"
                keys = await self.redis_client.keys(pattern)

                for key in keys:
                    alert_data = await self.redis_client.get(key)
                    if alert_data:
                        alert_dict = json.loads(alert_data)
                        if (alert_dict.get('rule_id') == rule_id and
                            alert_dict.get('status') in ['firing', 'acknowledged']):
                            return True

            return False
        except Exception as e:
            logger.error(f"Error checking active alerts: {e}")
            return False

    def _expand_annotations(self, annotations: Dict[str, str], evaluation: Dict[str, Any]) -> Dict[str, str]:
        """Expand annotation templates with values."""
        expanded = {}

        for key, template in annotations.items():
            try:
                tmpl = Template(template)
                expanded[key] = tmpl.render(**evaluation)
            except Exception as e:
                logger.error(f"Error expanding annotation {key}: {e}")
                expanded[key] = template

        return expanded


class NotificationManager:
    """Manages alert notifications."""

    def __init__(self):
        self.channels = {}
        self.rate_limiters = {}
        self.notification_queue = asyncio.Queue()

    async def initialize(self):
        """Initialize notification manager."""
        await self._load_channels()
        asyncio.create_task(self._process_notification_queue())

    async def _load_channels(self):
        """Load notification channels from configuration."""
        try:
            from src.core.config import settings

            # Load default channels from configuration
            default_channels = {
                'email_default': NotificationChannel(
                    id='email_default',
                    name='Default Email',
                    type=NotificationType.EMAIL,
                    configuration={
                        'smtp_host': getattr(settings, 'smtp_host', 'localhost'),
                        'smtp_port': getattr(settings, 'smtp_port', 587),
                        'username': getattr(settings, 'smtp_user', ''),
                        'password': getattr(settings, 'smtp_password', ''),
                        'from': getattr(settings, 'notification_from_email', 'catnet@localhost'),
                        'to': getattr(settings, 'admin_email', 'admin@localhost')
                    },
                    is_enabled=True,
                    rate_limit=10  # 10 notifications per hour
                ),
                'slack_default': NotificationChannel(
                    id='slack_default',
                    name='Default Slack',
                    type=NotificationType.SLACK,
                    configuration={
                        'webhook_url': getattr(settings, 'slack_webhook_url', '')
                    },
                    is_enabled=bool(getattr(settings, 'slack_webhook_url', '')),
                    rate_limit=20
                ),
                'teams_default': NotificationChannel(
                    id='teams_default',
                    name='Default Teams',
                    type=NotificationType.TEAMS,
                    configuration={
                        'webhook_url': getattr(settings, 'teams_webhook_url', '')
                    },
                    is_enabled=bool(getattr(settings, 'teams_webhook_url', '')),
                    rate_limit=20
                ),
                'pagerduty_default': NotificationChannel(
                    id='pagerduty_default',
                    name='Default PagerDuty',
                    type=NotificationType.PAGERDUTY,
                    configuration={
                        'integration_key': getattr(settings, 'pagerduty_api_key', '')
                    },
                    is_enabled=bool(getattr(settings, 'pagerduty_api_key', '')),
                    rate_limit=50
                )
            }

            # Add enabled channels
            for channel_id, channel in default_channels.items():
                if channel.is_enabled:
                    self.channels[channel_id] = channel

            logger.info(f"Loaded {len(self.channels)} notification channels")

        except Exception as e:
            logger.error(f"Failed to load notification channels: {e}")

    async def send_alert(self, alert: Alert):
        """Send alert notifications."""
        # Get notification channels for this alert
        channels = await self._get_channels_for_alert(alert)

        for channel_id in channels:
            if channel_id not in self.channels:
                logger.warning(f"Unknown notification channel: {channel_id}")
                continue

            # Check rate limiting
            if await self._is_rate_limited(channel_id):
                logger.info(f"Channel {channel_id} rate limited, skipping")
                continue

            # Create notification request
            request = NotificationRequest(
                channel_id=channel_id,
                alert_id=alert.id,
                subject=f"[{alert.severity.value.upper()}] {alert.name}",
                message=self._format_alert_message(alert),
                priority=self._get_priority(alert.severity),
                metadata={
                    'alert_fingerprint': alert.fingerprint,
                    'severity': alert.severity.value
                },
                deduplication_key=alert.fingerprint
            )

            # Queue notification
            await self.notification_queue.put(request)

    async def send_incident_notification(self, incident: IncidentReport):
        """Send incident notifications."""
        # Get escalation channels
        channels = await self._get_incident_channels(incident.severity)

        for channel_id in channels:
            request = NotificationRequest(
                channel_id=channel_id,
                incident_id=incident.id,
                subject=f"[INCIDENT] {incident.title}",
                message=self._format_incident_message(incident),
                priority='urgent' if incident.severity == AlertSeverity.CRITICAL else 'high',
                metadata={'incident_id': incident.id}
            )

            await self.notification_queue.put(request)

    async def send(self, request: NotificationRequest) -> Dict[str, Any]:
        """Send notification."""
        channel = self.channels.get(request.channel_id)

        if not channel:
            return {'success': False, 'error': 'Channel not found'}

        # Send based on channel type
        if channel.type == NotificationType.EMAIL:
            return await self._send_email(channel, request)
        elif channel.type == NotificationType.SLACK:
            return await self._send_slack(channel, request)
        elif channel.type == NotificationType.TEAMS:
            return await self._send_teams(channel, request)
        elif channel.type == NotificationType.PAGERDUTY:
            return await self._send_pagerduty(channel, request)
        elif channel.type == NotificationType.WEBHOOK:
            return await self._send_webhook(channel, request)
        else:
            return {'success': False, 'error': f'Unsupported channel type: {channel.type}'}

    async def test_channel(self, channel_id: str) -> Dict[str, Any]:
        """Test notification channel."""
        channel = self.channels.get(channel_id)

        if not channel:
            return {'success': False, 'message': 'Channel not found'}

        test_request = NotificationRequest(
            channel_id=channel_id,
            subject="Test Notification",
            message="This is a test notification from CatNet Monitoring",
            priority="normal"
        )

        start_time = datetime.utcnow()
        result = await self.send(test_request)
        response_time = (datetime.utcnow() - start_time).total_seconds() * 1000

        return {
            'success': result.get('success', False),
            'message': result.get('error', 'Test successful'),
            'response_time_ms': response_time
        }

    async def _process_notification_queue(self):
        """Process notification queue."""
        while True:
            try:
                request = await self.notification_queue.get()
                result = await self.send(request)

                if not result.get('success'):
                    logger.error(f"Failed to send notification: {result.get('error')}")

                    # Retry logic
                    if request.metadata.get('retry_count', 0) < 3:
                        request.metadata['retry_count'] = request.metadata.get('retry_count', 0) + 1
                        await asyncio.sleep(60)  # Wait before retry
                        await self.notification_queue.put(request)

            except Exception as e:
                logger.error(f"Error processing notification: {e}")
                await asyncio.sleep(5)

    async def _send_email(self, channel: NotificationChannel, request: NotificationRequest) -> Dict[str, Any]:
        """Send email notification."""
        config = channel.configuration

        try:
            # Implementation would use aiosmtplib
            import aiosmtplib
            from email.message import EmailMessage

            message = EmailMessage()
            message['From'] = config['from']
            message['To'] = config['to']
            message['Subject'] = request.subject
            message.set_content(request.message)

            await aiosmtplib.send(
                message,
                hostname=config['smtp_host'],
                port=config.get('smtp_port', 587),
                username=config.get('username'),
                password=config.get('password'),
                use_tls=True
            )

            return {'success': True, 'notification_id': request.deduplication_key}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    async def _send_slack(self, channel: NotificationChannel, request: NotificationRequest) -> Dict[str, Any]:
        """Send Slack notification."""
        config = channel.configuration
        webhook_url = config.get('webhook_url')

        payload = {
            'text': request.subject,
            'attachments': [{
                'color': self._get_slack_color(request.priority),
                'text': request.message,
                'footer': 'CatNet Monitoring',
                'ts': int(datetime.utcnow().timestamp())
            }]
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload) as response:
                    if response.status == 200:
                        return {'success': True, 'notification_id': request.deduplication_key}
                    else:
                        return {'success': False, 'error': f"HTTP {response.status}"}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    async def _send_teams(self, channel: NotificationChannel, request: NotificationRequest) -> Dict[str, Any]:
        """Send Microsoft Teams notification."""
        config = channel.configuration
        webhook_url = config.get('webhook_url')

        payload = {
            '@type': 'MessageCard',
            '@context': 'https://schema.org/extensions',
            'summary': request.subject,
            'themeColor': self._get_teams_color(request.priority),
            'title': request.subject,
            'text': request.message
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload) as response:
                    if response.status == 200:
                        return {'success': True, 'notification_id': request.deduplication_key}
                    else:
                        return {'success': False, 'error': f"HTTP {response.status}"}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    async def _send_pagerduty(self, channel: NotificationChannel, request: NotificationRequest) -> Dict[str, Any]:
        """Send PagerDuty notification."""
        config = channel.configuration
        integration_key = config.get('integration_key')

        payload = {
            'routing_key': integration_key,
            'event_action': 'trigger',
            'dedup_key': request.deduplication_key,
            'payload': {
                'summary': request.subject,
                'source': 'CatNet',
                'severity': request.priority,
                'custom_details': {
                    'message': request.message,
                    **request.metadata
                }
            }
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    'https://events.pagerduty.com/v2/enqueue',
                    json=payload,
                    headers={'Content-Type': 'application/json'}
                ) as response:
                    if response.status == 202:
                        return {'success': True, 'notification_id': request.deduplication_key}
                    else:
                        return {'success': False, 'error': f"HTTP {response.status}"}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    async def _send_webhook(self, channel: NotificationChannel, request: NotificationRequest) -> Dict[str, Any]:
        """Send webhook notification."""
        config = channel.configuration
        url = config.get('url')
        method = config.get('method', 'POST')
        headers = config.get('headers', {})

        payload = {
            'subject': request.subject,
            'message': request.message,
            'priority': request.priority,
            'metadata': request.metadata,
            'timestamp': datetime.utcnow().isoformat()
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method,
                    url,
                    json=payload,
                    headers=headers
                ) as response:
                    if response.status in [200, 201, 202]:
                        return {'success': True, 'notification_id': request.deduplication_key}
                    else:
                        return {'success': False, 'error': f"HTTP {response.status}"}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    async def _get_channels_for_alert(self, alert: Alert) -> List[str]:
        """Get notification channels for alert."""
        try:
            channels = []

            # Default channels based on severity
            if alert.severity == AlertSeverity.CRITICAL:
                channels = ['email_default', 'slack_default', 'teams_default', 'pagerduty_default']
            elif alert.severity == AlertSeverity.HIGH:
                channels = ['email_default', 'slack_default', 'teams_default']
            elif alert.severity == AlertSeverity.MEDIUM:
                channels = ['email_default', 'slack_default']
            else:
                channels = ['email_default']

            # Filter to enabled channels only
            enabled_channels = [c for c in channels if c in self.channels and self.channels[c].is_enabled]

            return enabled_channels

        except Exception as e:
            logger.error(f"Error getting channels for alert: {e}")
            return ['email_default']  # Fallback to email

    async def _get_incident_channels(self, severity: AlertSeverity) -> List[str]:
        """Get notification channels for incident."""
        try:
            # All incidents use high-priority channels
            channels = ['email_default', 'slack_default', 'teams_default']

            if severity == AlertSeverity.CRITICAL:
                channels.append('pagerduty_default')

            # Filter to enabled channels only
            enabled_channels = [c for c in channels if c in self.channels and self.channels[c].is_enabled]

            return enabled_channels

        except Exception as e:
            logger.error(f"Error getting incident channels: {e}")
            return ['email_default']

    async def _is_rate_limited(self, channel_id: str) -> bool:
        """Check if channel is rate limited."""
        if channel_id not in self.rate_limiters:
            self.rate_limiters[channel_id] = {'count': 0, 'reset_time': datetime.utcnow()}

        limiter = self.rate_limiters[channel_id]

        # Reset if time window passed
        if datetime.utcnow() > limiter['reset_time']:
            limiter['count'] = 0
            limiter['reset_time'] = datetime.utcnow() + timedelta(hours=1)

        # Check limit
        channel = self.channels.get(channel_id)
        if channel and channel.rate_limit:
            if limiter['count'] >= channel.rate_limit:
                return True

        limiter['count'] += 1
        return False

    def _format_alert_message(self, alert: Alert) -> str:
        """Format alert message."""
        lines = [
            f"Alert: {alert.name}",
            f"Severity: {alert.severity.value}",
            f"Status: {alert.status.value}",
            f"Time: {alert.fired_at.isoformat()}",
            "",
            alert.description,
            ""
        ]

        if alert.metric_name:
            lines.append(f"Metric: {alert.metric_name}")

        if alert.actual_value is not None:
            lines.append(f"Value: {alert.actual_value}")

        if alert.threshold_value is not None:
            lines.append(f"Threshold: {alert.threshold_value}")

        if alert.labels:
            lines.append("")
            lines.append("Labels:")
            for key, value in alert.labels.items():
                lines.append(f"  {key}: {value}")

        if alert.runbook_url:
            lines.append("")
            lines.append(f"Runbook: {alert.runbook_url}")

        return "\n".join(lines)

    def _format_incident_message(self, incident: IncidentReport) -> str:
        """Format incident message."""
        lines = [
            f"Incident: {incident.title}",
            f"Severity: {incident.severity.value}",
            f"Status: {incident.status}",
            f"Started: {incident.started_at.isoformat()}",
            "",
            incident.description,
            "",
            f"Affected Services: {', '.join(incident.affected_services)}",
        ]

        if incident.commander:
            lines.append(f"Commander: {incident.commander}")

        if incident.responders:
            lines.append(f"Responders: {', '.join(incident.responders)}")

        if incident.impact:
            lines.append("")
            lines.append(f"Impact: {incident.impact}")

        return "\n".join(lines)

    def _get_priority(self, severity: AlertSeverity) -> str:
        """Get notification priority from alert severity."""
        mapping = {
            AlertSeverity.CRITICAL: 'urgent',
            AlertSeverity.HIGH: 'high',
            AlertSeverity.MEDIUM: 'normal',
            AlertSeverity.LOW: 'low',
            AlertSeverity.INFO: 'low'
        }
        return mapping.get(severity, 'normal')

    def _get_slack_color(self, priority: str) -> str:
        """Get Slack color for priority."""
        colors = {
            'urgent': 'danger',
            'high': 'warning',
            'normal': 'warning',
            'low': 'good'
        }
        return colors.get(priority, 'warning')

    def _get_teams_color(self, priority: str) -> str:
        """Get Teams theme color for priority."""
        colors = {
            'urgent': 'FF0000',
            'high': 'FF9900',
            'normal': 'FFCC00',
            'low': '00FF00'
        }
        return colors.get(priority, 'FFCC00')


class EscalationManager:
    """Manages alert and incident escalation."""

    def __init__(self):
        self.escalation_policies = {}
        self.on_call_schedules = {}
        self.active_escalations = {}

    async def initialize(self):
        """Initialize escalation manager."""
        await self._load_policies()
        await self._load_schedules()

    async def _load_policies(self):
        """Load escalation policies."""
        # Implementation would load from database
        pass

    async def _load_schedules(self):
        """Load on-call schedules."""
        # Implementation would load from database
        pass

    async def start_escalation(self, incident: IncidentReport):
        """Start escalation for incident."""
        # Get escalation policy
        policy = await self._get_policy_for_incident(incident)

        if not policy:
            logger.warning(f"No escalation policy for incident {incident.id}")
            return

        # Get current on-call
        on_call = await self._get_on_call(policy['schedule_id'])

        if not on_call:
            logger.error(f"No on-call found for schedule {policy['schedule_id']}")
            return

        # Create escalation
        escalation = {
            'incident_id': incident.id,
            'policy_id': policy['id'],
            'current_level': 0,
            'notified_users': [],
            'started_at': datetime.utcnow(),
            'next_escalation_at': datetime.utcnow() + timedelta(minutes=policy['escalation_timeout'])
        }

        self.active_escalations[incident.id] = escalation

        # Notify first level
        await self._notify_escalation_level(escalation, on_call)

        # Schedule next escalation
        asyncio.create_task(self._schedule_next_escalation(escalation))

    async def acknowledge_escalation(self, incident_id: str, user: str):
        """Acknowledge escalation."""
        if incident_id in self.active_escalations:
            escalation = self.active_escalations[incident_id]
            escalation['acknowledged_by'] = user
            escalation['acknowledged_at'] = datetime.utcnow()

            # Cancel further escalation
            del self.active_escalations[incident_id]

    async def _get_policy_for_incident(self, incident: IncidentReport) -> Optional[Dict[str, Any]]:
        """Get escalation policy for incident."""
        # Implementation would match incident to policy
        return None

    async def _get_on_call(self, schedule_id: str) -> Optional[List[str]]:
        """Get current on-call users."""
        # Implementation would check schedule
        return None

    async def _notify_escalation_level(self, escalation: Dict[str, Any], users: List[str]):
        """Notify users at escalation level."""
        for user in users:
            if user not in escalation['notified_users']:
                # Send notification
                await self._send_escalation_notification(escalation, user)
                escalation['notified_users'].append(user)

    async def _send_escalation_notification(self, escalation: Dict[str, Any], user: str):
        """Send escalation notification to user."""
        # Implementation would send notification
        pass

    async def _schedule_next_escalation(self, escalation: Dict[str, Any]):
        """Schedule next escalation level."""
        wait_time = (escalation['next_escalation_at'] - datetime.utcnow()).total_seconds()

        if wait_time > 0:
            await asyncio.sleep(wait_time)

        # Check if acknowledged
        if escalation['incident_id'] not in self.active_escalations:
            return

        # Escalate to next level
        escalation['current_level'] += 1
        policy = self.escalation_policies.get(escalation['policy_id'])

        if policy and escalation['current_level'] < len(policy['levels']):
            next_level = policy['levels'][escalation['current_level']]
            users = await self._get_users_for_level(next_level)

            await self._notify_escalation_level(escalation, users)

            # Schedule next escalation
            escalation['next_escalation_at'] = datetime.utcnow() + timedelta(minutes=policy['escalation_timeout'])
            asyncio.create_task(self._schedule_next_escalation(escalation))

    async def _get_users_for_level(self, level: Dict[str, Any]) -> List[str]:
        """Get users for escalation level."""
        # Implementation would resolve users
        return []


class IncidentManager:
    """Manages incidents."""

    def __init__(self):
        self.active_incidents = {}
        self.incident_templates = {}

    async def initialize(self):
        """Initialize incident manager."""
        await self._load_templates()

    async def _load_templates(self):
        """Load incident templates."""
        # Implementation would load from database
        pass

    async def create(self, request: Dict[str, Any]) -> IncidentReport:
        """Create new incident."""
        incident = IncidentReport(
            title=request['title'],
            description=request['description'],
            severity=request['severity'],
            status='open',
            affected_services=request['affected_services'],
            responders=request.get('responders', []),
            commander=request.get('commander'),
            started_at=datetime.utcnow(),
            detected_at=datetime.utcnow(),
            related_alerts=request.get('related_alerts', [])
        )

        # Add to timeline
        incident.timeline.append({
            'timestamp': datetime.utcnow().isoformat(),
            'event': 'incident_created',
            'user': request.get('created_by', 'system'),
            'description': 'Incident created'
        })

        # Store incident
        await self._store_incident(incident)
        self.active_incidents[incident.id] = incident

        return incident

    async def check_incident_creation(self, alert: Alert):
        """Check if incident should be created from alert."""
        # Check if alert warrants incident
        if alert.severity not in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]:
            return

        # Check for existing incident
        existing = await self._find_related_incident(alert)
        if existing:
            # Add alert to incident
            existing.related_alerts.append(alert.id)
            await self._update_incident(existing)
            return

        # Check if multiple critical alerts
        critical_alerts = await self._get_recent_critical_alerts()
        if len(critical_alerts) >= 3:
            # Create incident
            incident = await self.create({
                'title': f"Multiple critical alerts detected",
                'description': f"Multiple critical alerts triggered: {', '.join([a.name for a in critical_alerts])}",
                'severity': AlertSeverity.CRITICAL,
                'affected_services': list(set(a.source for a in critical_alerts)),
                'related_alerts': [a.id for a in critical_alerts]
            })

            return incident

    async def resolve(self, incident_id: str, resolution: str, root_cause: Optional[str] = None) -> IncidentReport:
        """Resolve incident."""
        incident = self.active_incidents.get(incident_id)

        if incident:
            incident.status = 'resolved'
            incident.resolution = resolution
            incident.root_cause = root_cause
            incident.resolved_at = datetime.utcnow()

            # Add to timeline
            incident.timeline.append({
                'timestamp': datetime.utcnow().isoformat(),
                'event': 'incident_resolved',
                'description': f"Incident resolved: {resolution}"
            })

            await self._update_incident(incident)

            # Remove from active incidents
            del self.active_incidents[incident_id]

        return incident

    async def _find_related_incident(self, alert: Alert) -> Optional[IncidentReport]:
        """Find incident related to alert."""
        for incident in self.active_incidents.values():
            # Check if alert is already linked
            if alert.id in incident.related_alerts:
                return incident

            # Check if similar alerts exist
            if alert.source in incident.affected_services:
                return incident

        return None

    async def _get_recent_critical_alerts(self) -> List[Alert]:
        """Get recent critical alerts."""
        try:
            critical_alerts = []
            cutoff = datetime.utcnow() - timedelta(minutes=15)  # Last 15 minutes

            # Check active alerts
            for alert in self.active_incidents.values():
                if (alert.severity == AlertSeverity.CRITICAL and
                    alert.fired_at > cutoff and
                    alert.status == AlertStatus.FIRING):
                    critical_alerts.append(alert)

            return critical_alerts

        except Exception as e:
            logger.error(f"Error getting recent critical alerts: {e}")
            return []

    async def _store_incident(self, incident: IncidentReport):
        """Store incident in database."""
        try:
            if self.db_session:
                self.db_session.add(incident)
                await self.db_session.commit()
                logger.info(f"Stored incident {incident.title}")
        except Exception as e:
            logger.error(f"Failed to store incident: {e}")
            if self.db_session:
                await self.db_session.rollback()

    async def _update_incident(self, incident: IncidentReport):
        """Update incident in database."""
        try:
            if self.db_session:
                await self.db_session.commit()
                logger.info(f"Updated incident {incident.title}")
        except Exception as e:
            logger.error(f"Failed to update incident: {e}")
            if self.db_session:
                await self.db_session.rollback()


class OnCallScheduler:
    """Manages on-call schedules."""

    def __init__(self):
        self.schedules = {}
        self.rotations = {}
        self.overrides = {}

    async def initialize(self):
        """Initialize scheduler."""
        await self._load_schedules()
        await self._load_rotations()
        await self._load_overrides()

    async def _load_schedules(self):
        """Load on-call schedules."""
        # Implementation would load from database
        pass

    async def _load_rotations(self):
        """Load rotation configurations."""
        # Implementation would load from database
        pass

    async def _load_overrides(self):
        """Load schedule overrides."""
        # Implementation would load from database
        pass

    async def get_on_call(self, schedule_id: str, time: Optional[datetime] = None) -> List[str]:
        """Get on-call users for schedule at given time."""
        if time is None:
            time = datetime.utcnow()

        # Check for override
        override = await self._get_override(schedule_id, time)
        if override:
            return override['users']

        # Get rotation
        rotation = self.rotations.get(schedule_id)
        if not rotation:
            return []

        # Calculate current rotation position
        users = await self._calculate_on_call(rotation, time)

        return users

    async def _get_override(self, schedule_id: str, time: datetime) -> Optional[Dict[str, Any]]:
        """Get schedule override for given time."""
        schedule_overrides = self.overrides.get(schedule_id, [])

        for override in schedule_overrides:
            if override['start'] <= time <= override['end']:
                return override

        return None

    async def _calculate_on_call(self, rotation: Dict[str, Any], time: datetime) -> List[str]:
        """Calculate on-call users from rotation."""
        # Implementation would calculate based on rotation rules
        return []


class AlertSuppressor:
    """Suppresses duplicate or noisy alerts."""

    def __init__(self):
        self.suppression_rules = []
        self.suppressed_alerts = {}

    async def should_suppress(self, alert: Alert) -> bool:
        """Check if alert should be suppressed."""
        # Check suppression rules
        for rule in self.suppression_rules:
            if await self._matches_rule(alert, rule):
                await self._record_suppression(alert, rule)
                return True

        # Check for duplicate suppression
        if await self._is_duplicate(alert):
            return True

        return False

    async def _matches_rule(self, alert: Alert, rule: Dict[str, Any]) -> bool:
        """Check if alert matches suppression rule."""
        # Implementation would check rule conditions
        return False

    async def _is_duplicate(self, alert: Alert) -> bool:
        """Check if alert is duplicate."""
        # Check recent alerts with same fingerprint
        return alert.fingerprint in self.suppressed_alerts

    async def _record_suppression(self, alert: Alert, rule: Dict[str, Any]):
        """Record alert suppression."""
        self.suppressed_alerts[alert.fingerprint] = {
            'alert': alert,
            'rule': rule['id'],
            'suppressed_at': datetime.utcnow()
        }


class AlertCorrelator:
    """Correlates related alerts."""

    def __init__(self):
        self.correlation_rules = []
        self.alert_groups = {}

    async def correlate(self, alert: Alert) -> Optional[str]:
        """Find correlation group for alert."""
        # Check correlation rules
        for rule in self.correlation_rules:
            group_id = await self._check_correlation(alert, rule)
            if group_id:
                return group_id

        # Check time-based correlation
        group_id = await self._time_correlation(alert)
        if group_id:
            return group_id

        return None

    async def _check_correlation(self, alert: Alert, rule: Dict[str, Any]) -> Optional[str]:
        """Check if alert matches correlation rule."""
        # Implementation would check rule conditions
        return None

    async def _time_correlation(self, alert: Alert) -> Optional[str]:
        """Correlate alerts based on time proximity."""
        # Look for alerts within time window
        window = timedelta(minutes=5)
        cutoff = alert.fired_at - window

        for group_id, group in self.alert_groups.items():
            # Check if any alert in group is within window
            for grouped_alert in group['alerts']:
                if grouped_alert.fired_at > cutoff:
                    # Check if similar
                    if await self._are_similar(alert, grouped_alert):
                        return group_id

        return None

    async def _are_similar(self, alert1: Alert, alert2: Alert) -> bool:
        """Check if alerts are similar."""
        # Check same source
        if alert1.source == alert2.source:
            return True

        # Check same metric
        if alert1.metric_name and alert1.metric_name == alert2.metric_name:
            return True

        # Check label overlap
        common_labels = set(alert1.labels.keys()) & set(alert2.labels.keys())
        if len(common_labels) > len(alert1.labels) * 0.5:
            return True

        return False


class AlertAggregator:
    """Aggregates alerts for batch processing."""

    def __init__(self):
        self.aggregation_window = timedelta(minutes=1)
        self.alert_buffer = {}

    async def aggregate(self, alert: Alert) -> bool:
        """Add alert to aggregation buffer."""
        key = self._get_aggregation_key(alert)

        if key not in self.alert_buffer:
            self.alert_buffer[key] = {
                'alerts': [],
                'first_seen': datetime.utcnow(),
                'count': 0
            }

        buffer = self.alert_buffer[key]
        buffer['alerts'].append(alert)
        buffer['count'] += 1

        # Check if should flush
        if datetime.utcnow() - buffer['first_seen'] > self.aggregation_window:
            await self._flush_buffer(key)
            return True

        return False

    def _get_aggregation_key(self, alert: Alert) -> str:
        """Get aggregation key for alert."""
        components = [
            alert.name,
            alert.severity.value,
            json.dumps(alert.labels, sort_keys=True)
        ]
        return hashlib.md5(''.join(components).encode()).hexdigest()

    async def _flush_buffer(self, key: str):
        """Flush aggregated alerts."""
        if key in self.alert_buffer:
            buffer = self.alert_buffer[key]

            # Create aggregated alert
            if buffer['count'] > 1:
                # Implementation would create summary alert
                pass

            del self.alert_buffer[key]


class SilenceManager:
    """Manages alert silences."""

    def __init__(self):
        self.silences = []

    async def create_silence(
        self,
        matchers: List[Dict[str, str]],
        starts_at: datetime,
        ends_at: datetime,
        created_by: str,
        comment: str
    ) -> Dict[str, Any]:
        """Create alert silence."""
        silence = {
            'id': str(uuid.uuid4()),
            'matchers': matchers,
            'starts_at': starts_at,
            'ends_at': ends_at,
            'created_by': created_by,
            'comment': comment,
            'created_at': datetime.utcnow()
        }

        self.silences.append(silence)
        await self._store_silence(silence)

        return silence

    async def delete_silence(self, silence_id: str) -> bool:
        """Delete silence."""
        self.silences = [s for s in self.silences if s['id'] != silence_id]
        await self._delete_silence_from_db(silence_id)
        return True

    async def list_silences(self, active_only: bool = True) -> List[Dict[str, Any]]:
        """List silences."""
        now = datetime.utcnow()

        if active_only:
            return [
                s for s in self.silences
                if s['starts_at'] <= now <= s['ends_at']
            ]

        return self.silences

    async def _store_silence(self, silence: Dict[str, Any]):
        """Store silence in database."""
        try:
            # Store in Redis for fast access
            if hasattr(self, 'redis_client') and self.redis_client:
                await self.redis_client.setex(
                    f"silence:{silence['id']}",
                    int((silence['ends_at'] - datetime.utcnow()).total_seconds()),
                    json.dumps(silence, default=str)
                )
            logger.info(f"Stored silence {silence['id']}")
        except Exception as e:
            logger.error(f"Failed to store silence: {e}")

    async def _delete_silence_from_db(self, silence_id: str):
        """Delete silence from database."""
        try:
            # Delete from Redis
            if hasattr(self, 'redis_client') and self.redis_client:
                await self.redis_client.delete(f"silence:{silence_id}")
            logger.info(f"Deleted silence {silence_id}")
        except Exception as e:
            logger.error(f"Failed to delete silence: {e}")


class AlertRouter:
    """Routes alerts to appropriate handlers."""

    def __init__(self):
        self.routes = []
        self.default_handler = None

    async def route(self, alert: Alert) -> List[str]:
        """Route alert to handlers."""
        matched_handlers = []

        for route in self.routes:
            if await self._matches_route(alert, route):
                matched_handlers.extend(route['handlers'])

        if not matched_handlers and self.default_handler:
            matched_handlers.append(self.default_handler)

        return matched_handlers

    async def _matches_route(self, alert: Alert, route: Dict[str, Any]) -> bool:
        """Check if alert matches route."""
        # Check severity
        if 'severity' in route:
            if alert.severity not in route['severity']:
                return False

        # Check labels
        if 'labels' in route:
            for key, value in route['labels'].items():
                if alert.labels.get(key) != value:
                    return False

        # Check regex patterns
        if 'patterns' in route:
            for pattern in route['patterns']:
                if not re.match(pattern, alert.name):
                    return False

        return True


class AlertEnricher:
    """Enriches alerts with additional context."""

    def __init__(self):
        self.enrichment_sources = []

    async def enrich(self, alert: Alert) -> Alert:
        """Enrich alert with additional information."""
        for source in self.enrichment_sources:
            alert = await self._enrich_from_source(alert, source)

        return alert

    async def _enrich_from_source(self, alert: Alert, source: Dict[str, Any]) -> Alert:
        """Enrich alert from specific source."""
        source_type = source.get('type')

        if source_type == 'cmdb':
            # Add CMDB information
            alert.annotations['cmdb_info'] = await self._get_cmdb_info(alert)
        elif source_type == 'runbook':
            # Add runbook URL
            alert.runbook_url = await self._get_runbook_url(alert)
        elif source_type == 'topology':
            # Add topology context
            alert.annotations['topology'] = await self._get_topology_context(alert)

        return alert

    async def _get_cmdb_info(self, alert: Alert) -> str:
        """Get CMDB information for alert."""
        # Implementation would query CMDB
        return ""

    async def _get_runbook_url(self, alert: Alert) -> str:
        """Get runbook URL for alert."""
        # Implementation would lookup runbook
        return ""

    async def _get_topology_context(self, alert: Alert) -> str:
        """Get topology context for alert."""
        # Implementation would query topology service
        return ""