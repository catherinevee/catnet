"""
Alert management system for CatNet monitoring.
Provides alert rules, evaluation, and notification integration.
"""

import asyncio
import re
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field
import json

from src.monitoring.metrics import MetricsCollector
from src.workers.notification_worker import NotificationWorker
from src.core.exceptions import AlertError
from src.security.audit import AuditLogger
from src.db.models import Alert


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class AlertState(Enum):
    """Alert state."""
    INACTIVE = "inactive"
    PENDING = "pending"
    FIRING = "firing"
    RESOLVED = "resolved"


class AlertCondition(Enum):
    """Alert condition operators."""
    GREATER_THAN = ">"
    LESS_THAN = "<"
    EQUAL = "=="
    NOT_EQUAL = "!="
    GREATER_EQUAL = ">="
    LESS_EQUAL = "<="
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    REGEX = "regex"


@dataclass
class AlertRule:
    """
    Alert rule definition.
    """

    rule_id: str
    name: str
    description: str
    metric_name: str
    condition: AlertCondition
    threshold: float
    severity: AlertSeverity
    labels: Dict[str, str] = field(default_factory=dict)
    duration: int = 0  # Seconds the condition must be true
    frequency: int = 60  # Check frequency in seconds
    annotations: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    notify_channels: List[str] = field(default_factory=list)
    silence_duration: int = 3600  # Don't re-alert for this duration
    escalation_rules: List[Dict] = field(default_factory=list)

    def evaluate(self, value: float) -> bool:
        """
        Evaluate if alert condition is met.

        Args:
            value: Metric value to evaluate

        Returns:
            True if condition is met
        """
        if self.condition == AlertCondition.GREATER_THAN:
            return value > self.threshold
        elif self.condition == AlertCondition.LESS_THAN:
            return value < self.threshold
        elif self.condition == AlertCondition.EQUAL:
            return value == self.threshold
        elif self.condition == AlertCondition.NOT_EQUAL:
            return value != self.threshold
        elif self.condition == AlertCondition.GREATER_EQUAL:
            return value >= self.threshold
        elif self.condition == AlertCondition.LESS_EQUAL:
            return value <= self.threshold
        else:
            return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary."""
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'description': self.description,
            'metric_name': self.metric_name,
            'condition': self.condition.value,
            'threshold': self.threshold,
            'severity': self.severity.value,
            'labels': self.labels,
            'duration': self.duration,
            'frequency': self.frequency,
            'annotations': self.annotations,
            'enabled': self.enabled,
            'notify_channels': self.notify_channels,
            'silence_duration': self.silence_duration,
            'escalation_rules': self.escalation_rules
        }


@dataclass
class AlertInstance:
    """
    Instance of a firing alert.
    """

    alert_id: str
    rule: AlertRule
    state: AlertState
    value: float
    started_at: datetime
    last_evaluated: datetime
    resolved_at: Optional[datetime] = None
    notified_at: Optional[datetime] = None
    notification_count: int = 0
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert instance to dictionary."""
        return {
            'alert_id': self.alert_id,
            'rule_id': self.rule.rule_id,
            'rule_name': self.rule.name,
            'state': self.state.value,
            'value': self.value,
            'threshold': self.rule.threshold,
            'severity': self.rule.severity.value,
            'started_at': self.started_at.isoformat(),
            'last_evaluated': self.last_evaluated.isoformat(),
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'notified_at': self.notified_at.isoformat() if self.notified_at else None,
            'notification_count': self.notification_count,
            'labels': {**self.rule.labels, **self.labels},
            'annotations': {**self.rule.annotations, **self.annotations}
        }


class AlertManager:
    """
    Manages alert rules, evaluation, and notification.
    """

    def __init__(
        self,
        metrics_collector: MetricsCollector,
        notification_worker: Optional[NotificationWorker] = None
    ):
        """
        Initialize alert manager.

        Args:
            metrics_collector: Metrics collector instance
            notification_worker: Optional notification worker
        """
        self.metrics_collector = metrics_collector
        self.notification_worker = notification_worker
        self.audit = AuditLogger()

        self.rules: Dict[str, AlertRule] = {}
        self.active_alerts: Dict[str, AlertInstance] = {}
        self.silenced_alerts: Dict[str, datetime] = {}

        self._running = False
        self._evaluation_tasks = {}

        # Initialize default alert rules
        self._init_default_rules()

    def _init_default_rules(self):
        """Initialize default alert rules."""
        # High CPU usage alert
        self.add_rule(AlertRule(
            rule_id="high_cpu",
            name="High CPU Usage",
            description="CPU usage above 90%",
            metric_name="catnet_system_cpu_usage_percent",
            condition=AlertCondition.GREATER_THAN,
            threshold=90,
            severity=AlertSeverity.WARNING,
            duration=300,  # 5 minutes
            frequency=60,
            annotations={
                "summary": "High CPU usage detected",
                "description": "System CPU usage is above 90% for more than 5 minutes"
            },
            notify_channels=["email", "slack"]
        ))

        # High memory usage alert
        self.add_rule(AlertRule(
            rule_id="high_memory",
            name="High Memory Usage",
            description="Memory usage above 95%",
            metric_name="catnet_system_memory_usage_percent",
            condition=AlertCondition.GREATER_THAN,
            threshold=95,
            severity=AlertSeverity.CRITICAL,
            duration=120,  # 2 minutes
            frequency=30,
            annotations={
                "summary": "Critical memory usage",
                "description": "System memory usage is above 95%"
            },
            notify_channels=["email", "slack", "pagerduty"]
        ))

        # Disk space alert
        self.add_rule(AlertRule(
            rule_id="low_disk",
            name="Low Disk Space",
            description="Disk usage above 85%",
            metric_name="catnet_system_disk_usage_percent",
            condition=AlertCondition.GREATER_THAN,
            threshold=85,
            severity=AlertSeverity.WARNING,
            duration=0,
            frequency=300,
            annotations={
                "summary": "Low disk space warning",
                "description": "Disk usage is above 85%"
            },
            notify_channels=["email"]
        ))

        # Deployment failure rate alert
        self.add_rule(AlertRule(
            rule_id="deployment_failures",
            name="High Deployment Failure Rate",
            description="Deployment success rate below 80%",
            metric_name="catnet_deployment_success_rate_percent",
            condition=AlertCondition.LESS_THAN,
            threshold=80,
            severity=AlertSeverity.WARNING,
            duration=0,
            frequency=300,
            annotations={
                "summary": "High deployment failure rate",
                "description": "Deployment success rate has dropped below 80%"
            },
            notify_channels=["email", "slack"]
        ))

        # Security violations alert
        self.add_rule(AlertRule(
            rule_id="security_violations",
            name="Security Violations Detected",
            description="Security violations in last hour",
            metric_name="catnet_security_violations_last_hour",
            condition=AlertCondition.GREATER_THAN,
            threshold=5,
            severity=AlertSeverity.CRITICAL,
            duration=0,
            frequency=60,
            annotations={
                "summary": "Security violations detected",
                "description": "More than 5 security violations detected in the last hour"
            },
            notify_channels=["email", "slack", "pagerduty"]
        ))

        # Device health alert
        self.add_rule(AlertRule(
            rule_id="unhealthy_devices",
            name="Unhealthy Devices",
            description="Critical devices in unhealthy state",
            metric_name="catnet_devices_by_health",
            condition=AlertCondition.GREATER_THAN,
            threshold=0,
            severity=AlertSeverity.WARNING,
            labels={"health": "critical"},
            duration=60,
            frequency=60,
            annotations={
                "summary": "Critical devices unhealthy",
                "description": "One or more critical devices are in unhealthy state"
            },
            notify_channels=["email", "slack"]
        ))

        # Database connection pool alert
        self.add_rule(AlertRule(
            rule_id="db_pool_exhausted",
            name="Database Pool Exhausted",
            description="Database connection pool exhausted",
            metric_name="catnet_db_pool_available",
            condition=AlertCondition.LESS_THAN,
            threshold=2,
            severity=AlertSeverity.CRITICAL,
            duration=30,
            frequency=10,
            annotations={
                "summary": "Database connection pool exhausted",
                "description": "Less than 2 connections available in database pool"
            },
            notify_channels=["email", "slack", "pagerduty"]
        ))

        # Authentication failures alert
        self.add_rule(AlertRule(
            rule_id="auth_failures",
            name="High Authentication Failures",
            description="Suspicious authentication activity",
            metric_name="catnet_users_with_suspicious_activity",
            condition=AlertCondition.GREATER_THAN,
            threshold=5,
            severity=AlertSeverity.WARNING,
            duration=0,
            frequency=60,
            annotations={
                "summary": "Suspicious authentication activity",
                "description": "More than 5 users with suspicious authentication activity"
            },
            notify_channels=["email", "slack"]
        ))

        # Certificate expiry alert
        self.add_rule(AlertRule(
            rule_id="cert_expiry",
            name="Certificate Expiry Warning",
            description="Certificates expiring soon",
            metric_name="catnet_certificates_expiring_soon",
            condition=AlertCondition.GREATER_THAN,
            threshold=0,
            severity=AlertSeverity.WARNING,
            duration=0,
            frequency=3600,  # Check hourly
            annotations={
                "summary": "Certificates expiring soon",
                "description": "One or more certificates will expire within 30 days"
            },
            notify_channels=["email"]
        ))

        # System uptime alert
        self.add_rule(AlertRule(
            rule_id="system_restart",
            name="System Restarted",
            description="System uptime less than 1 hour",
            metric_name="catnet_system_uptime_seconds",
            condition=AlertCondition.LESS_THAN,
            threshold=3600,
            severity=AlertSeverity.INFO,
            duration=0,
            frequency=60,
            annotations={
                "summary": "System recently restarted",
                "description": "System uptime is less than 1 hour"
            },
            notify_channels=["email"]
        ))

    def add_rule(self, rule: AlertRule):
        """Add alert rule."""
        self.rules[rule.rule_id] = rule

    def remove_rule(self, rule_id: str):
        """Remove alert rule."""
        if rule_id in self.rules:
            del self.rules[rule_id]

            # Stop evaluation task if running
            if rule_id in self._evaluation_tasks:
                task = self._evaluation_tasks[rule_id]
                task.cancel()
                del self._evaluation_tasks[rule_id]

            # Remove active alerts for this rule
            alerts_to_remove = [
                alert_id for alert_id, alert in self.active_alerts.items()
                if alert.rule.rule_id == rule_id
            ]
            for alert_id in alerts_to_remove:
                del self.active_alerts[alert_id]

    def enable_rule(self, rule_id: str):
        """Enable alert rule."""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = True

    def disable_rule(self, rule_id: str):
        """Disable alert rule."""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = False

    async def start(self):
        """Start alert evaluation."""
        self._running = True

        # Start evaluation tasks for each rule
        for rule_id, rule in self.rules.items():
            if rule.enabled:
                task = asyncio.create_task(self._evaluate_rule_loop(rule))
                self._evaluation_tasks[rule_id] = task

        await self.audit.log_event(
            event_type="ALERT_MANAGER_STARTED",
            details={'rules_count': len(self.rules)}
        )

    async def stop(self):
        """Stop alert evaluation."""
        self._running = False

        # Cancel all evaluation tasks
        for task in self._evaluation_tasks.values():
            task.cancel()

        # Wait for tasks to complete
        await asyncio.gather(*self._evaluation_tasks.values(), return_exceptions=True)
        self._evaluation_tasks.clear()

        await self.audit.log_event(
            event_type="ALERT_MANAGER_STOPPED",
            details={'active_alerts': len(self.active_alerts)}
        )

    async def _evaluate_rule_loop(self, rule: AlertRule):
        """Continuous evaluation loop for a rule."""
        pending_since = None

        while self._running and rule.enabled:
            try:
                # Evaluate rule
                is_firing = await self._evaluate_rule(rule)

                alert_key = self._get_alert_key(rule)

                if is_firing:
                    # Check duration requirement
                    if rule.duration > 0:
                        if pending_since is None:
                            pending_since = datetime.utcnow()
                        elif (datetime.utcnow() - pending_since).total_seconds() >= rule.duration:
                            # Duration met, fire alert
                            await self._fire_alert(rule)
                            pending_since = None
                    else:
                        # No duration requirement, fire immediately
                        await self._fire_alert(rule)
                else:
                    # Condition not met
                    pending_since = None

                    # Resolve alert if it was firing
                    if alert_key in self.active_alerts:
                        await self._resolve_alert(alert_key)

                # Wait for next evaluation
                await asyncio.sleep(rule.frequency)

            except Exception as e:
                await self.audit.log_event(
                    event_type="ALERT_EVALUATION_ERROR",
                    details={
                        'rule_id': rule.rule_id,
                        'error': str(e)
                    }
                )
                await asyncio.sleep(rule.frequency)

    async def _evaluate_rule(self, rule: AlertRule) -> bool:
        """
        Evaluate if rule condition is met.

        Args:
            rule: Alert rule to evaluate

        Returns:
            True if condition is met
        """
        try:
            # Get metric value
            if rule.metric_name not in self.metrics_collector.metrics:
                return False

            metric = self.metrics_collector.metrics[rule.metric_name]

            # Get value based on metric type
            if hasattr(metric, 'get'):
                value = metric.get(labels=rule.labels)
            else:
                # For complex metrics, get the latest value
                values = metric.collect()
                if values:
                    # Find matching labels
                    for v in values:
                        if self._labels_match(v.labels, rule.labels):
                            value = v.value
                            break
                    else:
                        value = values[0].value if values else 0
                else:
                    value = 0

            # Store value for alert
            self._last_values[rule.rule_id] = value

            # Evaluate condition
            return rule.evaluate(value)

        except Exception as e:
            return False

    def _get_alert_key(self, rule: AlertRule) -> str:
        """Generate unique key for alert instance."""
        labels_str = json.dumps(rule.labels, sort_keys=True)
        return f"{rule.rule_id}:{labels_str}"

    def _labels_match(self, metric_labels: Dict, rule_labels: Dict) -> bool:
        """Check if metric labels match rule labels."""
        for key, value in rule_labels.items():
            if key not in metric_labels or metric_labels[key] != value:
                return False
        return True

    async def _fire_alert(self, rule: AlertRule):
        """Fire an alert."""
        alert_key = self._get_alert_key(rule)

        # Check if already firing
        if alert_key in self.active_alerts:
            # Update evaluation time
            self.active_alerts[alert_key].last_evaluated = datetime.utcnow()
            return

        # Check if silenced
        if alert_key in self.silenced_alerts:
            if datetime.utcnow() < self.silenced_alerts[alert_key]:
                return
            else:
                del self.silenced_alerts[alert_key]

        # Create alert instance
        import uuid
        alert = AlertInstance(
            alert_id=str(uuid.uuid4()),
            rule=rule,
            state=AlertState.FIRING,
            value=self._last_values.get(rule.rule_id, 0),
            started_at=datetime.utcnow(),
            last_evaluated=datetime.utcnow()
        )

        self.active_alerts[alert_key] = alert

        # Send notifications
        await self._send_notifications(alert)

        # Log alert
        await self.audit.log_event(
            event_type="ALERT_FIRED",
            details=alert.to_dict()
        )

        # Store in database
        await self._store_alert(alert)

    async def _resolve_alert(self, alert_key: str):
        """Resolve an alert."""
        if alert_key not in self.active_alerts:
            return

        alert = self.active_alerts[alert_key]
        alert.state = AlertState.RESOLVED
        alert.resolved_at = datetime.utcnow()

        # Send resolution notification
        await self._send_resolution_notification(alert)

        # Log resolution
        await self.audit.log_event(
            event_type="ALERT_RESOLVED",
            details=alert.to_dict()
        )

        # Update in database
        await self._update_alert(alert)

        # Remove from active alerts
        del self.active_alerts[alert_key]

    async def _send_notifications(self, alert: AlertInstance):
        """Send alert notifications."""
        if not self.notification_worker or not alert.rule.notify_channels:
            return

        # Check if we should notify (respect silence duration)
        if alert.notified_at:
            time_since_notification = (datetime.utcnow() - alert.notified_at).total_seconds()
            if time_since_notification < alert.rule.silence_duration:
                return

        # Prepare notification message
        message = self._format_alert_message(alert)

        # Send to each channel
        for channel in alert.rule.notify_channels:
            try:
                await self.notification_worker.submit_task(
                    task_type="send_alert",
                    payload={
                        'alert_id': alert.alert_id,
                        'channel': channel,
                        'subject': f"[{alert.rule.severity.value.upper()}] {alert.rule.name}",
                        'message': message,
                        'priority': self._severity_to_priority(alert.rule.severity),
                        'metadata': alert.to_dict()
                    }
                )

                alert.notified_at = datetime.utcnow()
                alert.notification_count += 1

            except Exception as e:
                await self.audit.log_event(
                    event_type="ALERT_NOTIFICATION_ERROR",
                    details={
                        'alert_id': alert.alert_id,
                        'channel': channel,
                        'error': str(e)
                    }
                )

    async def _send_resolution_notification(self, alert: AlertInstance):
        """Send alert resolution notification."""
        if not self.notification_worker or not alert.rule.notify_channels:
            return

        message = self._format_resolution_message(alert)

        for channel in alert.rule.notify_channels:
            try:
                await self.notification_worker.submit_task(
                    task_type="send_notification",
                    payload={
                        'channel': channel,
                        'subject': f"[RESOLVED] {alert.rule.name}",
                        'message': message,
                        'priority': 'normal',
                        'metadata': alert.to_dict()
                    }
                )
            except:
                pass

    def _format_alert_message(self, alert: AlertInstance) -> str:
        """Format alert notification message."""
        duration = (datetime.utcnow() - alert.started_at).total_seconds()

        message = f"""
Alert: {alert.rule.name}
Severity: {alert.rule.severity.value.upper()}
Status: FIRING

{alert.rule.description}

Current Value: {alert.value:.2f}
Threshold: {alert.rule.threshold:.2f}
Condition: {alert.rule.condition.value}

Started: {alert.started_at.isoformat()}
Duration: {self._format_duration(duration)}

Labels:
{self._format_labels(alert.labels)}

Annotations:
{self._format_annotations(alert.annotations)}
        """

        return message.strip()

    def _format_resolution_message(self, alert: AlertInstance) -> str:
        """Format resolution notification message."""
        duration = (alert.resolved_at - alert.started_at).total_seconds()

        message = f"""
Alert Resolved: {alert.rule.name}
Severity: {alert.rule.severity.value.upper()}
Status: RESOLVED

Alert has been resolved.

Started: {alert.started_at.isoformat()}
Resolved: {alert.resolved_at.isoformat()}
Duration: {self._format_duration(duration)}

Labels:
{self._format_labels(alert.labels)}
        """

        return message.strip()

    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format."""
        hours, remainder = divmod(int(seconds), 3600)
        minutes, seconds = divmod(remainder, 60)

        parts = []
        if hours:
            parts.append(f"{hours}h")
        if minutes:
            parts.append(f"{minutes}m")
        if seconds or not parts:
            parts.append(f"{seconds}s")

        return " ".join(parts)

    def _format_labels(self, labels: Dict[str, str]) -> str:
        """Format labels for display."""
        if not labels:
            return "  None"
        return "\n".join(f"  {k}: {v}" for k, v in labels.items())

    def _format_annotations(self, annotations: Dict[str, str]) -> str:
        """Format annotations for display."""
        if not annotations:
            return "  None"
        return "\n".join(f"  {k}: {v}" for k, v in annotations.items())

    def _severity_to_priority(self, severity: AlertSeverity) -> str:
        """Convert alert severity to notification priority."""
        mapping = {
            AlertSeverity.INFO: "low",
            AlertSeverity.WARNING: "normal",
            AlertSeverity.CRITICAL: "high",
            AlertSeverity.EMERGENCY: "critical"
        }
        return mapping.get(severity, "normal")

    async def _store_alert(self, alert: AlertInstance):
        """Store alert in database."""
        try:
            from src.db.session import get_db

            async with get_db() as db:
                db_alert = Alert(
                    id=alert.alert_id,
                    rule_id=alert.rule.rule_id,
                    rule_name=alert.rule.name,
                    severity=alert.rule.severity.value,
                    state=alert.state.value,
                    value=alert.value,
                    threshold=alert.rule.threshold,
                    started_at=alert.started_at,
                    labels=alert.labels,
                    annotations=alert.annotations
                )
                db.add(db_alert)
                await db.commit()
        except:
            pass

    async def _update_alert(self, alert: AlertInstance):
        """Update alert in database."""
        try:
            from src.db.session import get_db

            async with get_db() as db:
                db_alert = await db.get(Alert, alert.alert_id)
                if db_alert:
                    db_alert.state = alert.state.value
                    db_alert.resolved_at = alert.resolved_at
                    await db.commit()
        except:
            pass

    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get list of active alerts."""
        return [alert.to_dict() for alert in self.active_alerts.values()]

    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get specific alert by ID."""
        for alert in self.active_alerts.values():
            if alert.alert_id == alert_id:
                return alert.to_dict()
        return None

    def silence_alert(self, rule_id: str, duration: int = 3600):
        """
        Silence alert for specified duration.

        Args:
            rule_id: Rule ID to silence
            duration: Silence duration in seconds
        """
        alert_key = self._get_alert_key(self.rules[rule_id])
        self.silenced_alerts[alert_key] = datetime.utcnow() + timedelta(seconds=duration)

    def unsilence_alert(self, rule_id: str):
        """Remove alert silence."""
        alert_key = self._get_alert_key(self.rules[rule_id])
        if alert_key in self.silenced_alerts:
            del self.silenced_alerts[alert_key]


# Initialize storage for last metric values
AlertManager._last_values = {}


# Export main components
__all__ = [
    'AlertManager',
    'AlertRule',
    'AlertInstance',
    'AlertSeverity',
    'AlertState',
    'AlertCondition'
]