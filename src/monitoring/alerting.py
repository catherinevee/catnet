"""
Alerting System for CatNet

Handles:
- Alert rules and conditions
- Alert notifications
- Alert escalation
- Alert suppression
"""

from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import asyncio
from collections import defaultdict
import re


class AlertSeverity(Enum): """Alert severity levels"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertState(Enum):
    """Alert states"""

    PENDING = "pending"
    FIRING = "firing"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    ACKNOWLEDGED = "acknowledged"


class AlertChannel(Enum):
    """Alert notification channels"""

    EMAIL = "email"
    SLACK = "slack"
    WEBHOOK = "webhook"
    PAGERDUTY = "pagerduty"
    SMS = "sms"
    TEAMS = "teams"


@dataclass
class AlertCondition:
    """Alert condition definition"""

    metric: str
    operator: str  # >, <, ==, !=, >=, <=
    threshold: float
    duration: timedelta = timedelta(minutes=1)
    labels: Dict[str, str] = field(default_factory=dict)


@dataclass
class AlertRule: """Alert rule definition"""

    id: str
    name: str
    description: str
    severity: AlertSeverity
    conditions: List[AlertCondition]
    annotations: Dict[str, str] = field(default_factory=dict)
    labels: Dict[str, str] = field(default_factory=dict)
    channels: List[AlertChannel] = field(default_factory=list)
    cooldown: timedelta = timedelta(minutes=5)
    enabled: bool = True


@dataclass
class Alert: """Active alert instance"""

    id: str
    rule_id: str
    name: str
    severity: AlertSeverity
    state: AlertState
    message: str
    started_at: datetime
    ended_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    suppressed_until: Optional[datetime] = None
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    notification_sent: bool = False
    escalation_level: int = 0


@dataclass
class NotificationConfig: """Notification configuration"""

    channel: AlertChannel
    recipients: List[str]
    template: Optional[str] = None
    settings: Dict[str, Any] = field(default_factory=dict)


class AlertManager: """
    Manages alerts and notifications
    """

    def __init__(self, metrics_collector=None): """
        Initialize alert manager
    Args:
            metrics_collector: Metrics collector instance
        """
        self.metrics_collector = metrics_collector
        self.rules: Dict[str, AlertRule] = {}
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: List[Alert] = []
        self.notification_configs: Dict[AlertChannel, NotificationConfig] = {}
        self.suppression_rules: List[Dict[str, Any]] = []
        self.escalation_policies: Dict[str, List[Dict[str, Any]]] = {}

        # Alert evaluation
        self.evaluation_interval = timedelta(seconds=30)
        self.evaluation_task = None
        self.is_running = False

        # Notification handlers
        self.notification_handlers: Dict[AlertChannel, Callable] = {}

        # Initialize default rules
        self._initialize_default_rules()

    def _initialize_default_rules(self): """Initialize default alert rules"""
        # High CPU usage
        self.add_rule(
            AlertRule(
                id="high_cpu",
                name="High CPU Usage",
                description="CPU usage is above 80%",
                severity=AlertSeverity.HIGH,
                conditions=[
                    AlertCondition(
                        metric="system_cpu_usage",
                        operator=">",
                        threshold=80,
                        duration=timedelta(minutes=5),
                    )
                ],
                annotations={
                    "summary": "High CPU usage detected",
                    "description": "CPU usage has been above 80% for 5 \
                        minutes",
                },
                channels=[AlertChannel.EMAIL, AlertChannel.SLACK],
            )
        )

        # Deployment failures
        self.add_rule(
            AlertRule(
                id="deployment_failures",
                name="Deployment Failures",
                description="Multiple deployment failures detected",
                severity=AlertSeverity.CRITICAL,
                conditions=[
                    AlertCondition(
                        metric="deployments_total",
                        operator=">",
                        threshold=3,
                        duration=timedelta(minutes=10),
                        labels={"status": "failed"},
                    )
                ],
                annotations={
                    "summary": "Multiple deployment failures",
                    "description": "More than 3 deployments failed in the last \
    10 minutes",
                },
                channels=[AlertChannel.PAGERDUTY, AlertChannel.SLACK],
            )
        )

        # Device unreachable
        self.add_rule(
            AlertRule(
                id="device_unreachable",
                name="Device Unreachable",
                description="Device is not responding",
                severity=AlertSeverity.HIGH,
                conditions=[
                    AlertCondition(
                        metric="device_health_score",
                        operator="==",
                        threshold=0,
                        duration=timedelta(minutes=2),
                    )
                ],
                annotations={
                    "summary": "Device unreachable",
                    "description": "Device has been unreachable for 2 minutes",
                },
                channels=[AlertChannel.EMAIL, AlertChannel.WEBHOOK],
            )
        )

        # Security violations
        self.add_rule(
            AlertRule(
                id="security_violations",
                name="Security Violations",
                description="Security violations detected",
                severity=AlertSeverity.CRITICAL,
                conditions=[
                    AlertCondition(
                        metric="security_violations_total",
                        operator=">",
                        threshold=0,
                        duration=timedelta(seconds=30),
                        labels={"severity": "critical"},
                    )
                ],
                annotations={
                    "summary": "Critical security violation",
                    "description": "Critical security violation detected",
                },
                channels=[AlertChannel.PAGERDUTY, AlertChannel.SMS],
            )
        )

    def add_rule(self, rule: AlertRule):
        """
        Add an alert rule
    Args:
            rule: Alert rule"""
        self.rules[rule.id] = rule

    def remove_rule(self, rule_id: str):
        """
        Remove an alert rule
    Args:
            rule_id: Rule ID"""
        if rule_id in self.rules:
            del self.rules[rule_id]

    def add_notification_config(self, config: NotificationConfig):
        """
        Add notification configuration
    Args:
            config: Notification configuration"""
        self.notification_configs[config.channel] = config

        def register_notification_handler(
            self,
            channel: AlertChannel,
            handler: Callable
        ):
        """
        Register a notification handler
    Args:
            channel: Notification channel
            handler: Handler function"""
        self.notification_handlers[channel] = handler

    async def start(self):
        """Start alert evaluation"""
        if not self.is_running:
            self.is_running = True
            self.evaluation_task = asyncio.create_task(self._evaluation_loop())

    async def stop(self): """Stop alert evaluation"""
        self.is_running = False
        if self.evaluation_task:
            self.evaluation_task.cancel()
            await asyncio.gather(self.evaluation_task, return_exceptions=True)

    async def _evaluation_loop(self): """Alert evaluation loop"""
        while self.is_running:
            try:
                await self._evaluate_rules()
                await asyncio.sleep(self.evaluation_interval.total_seconds())
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Error in alert evaluation: {e}")

    async def _evaluate_rules(self):
        """Evaluate all alert rules"""
        if not self.metrics_collector:
            return

        for rule in self.rules.values():
            if not rule.enabled:
                continue

            try:
                # Check if all conditions are met
                conditions_met = await self._check_conditions(rule.conditions)

                if conditions_met:
                    await self._trigger_alert(rule)
                else:
                    await self._resolve_alert(rule.id)

            except Exception as e:
                print(f"Error evaluating rule {rule.id}: {e}")

        async def _check_conditions(
            self,
            conditions: List[AlertCondition]
        ) -> bool:
        """
        Check if alert conditions are met
    Args:
            conditions: List of conditions
    Returns:
            True if all conditions are met"""
        for condition in conditions:
            # Get metric time series
            time_series = self.metrics_collector.get_time_series(
                condition.metric,
                condition.labels,
                datetime.utcnow() - condition.duration,
                datetime.utcnow(),
            )

            if not time_series:
                return False

            # Check if condition is met for all values in duration
            for value in time_series:
                if not self._evaluate_condition(
                    value.value, condition.operator, condition.threshold
                ):
                    return False

        return True

    def _evaluate_condition(
        self, value: float, operator: str, threshold: float
    ) -> bool:
        """
        Evaluate a single condition
    Args:
            value: Metric value
            operator: Comparison operator
            threshold: Threshold value
    Returns:
            True if condition is met"""
        operators = {
            ">": lambda x, y: x > y,
            "<": lambda x, y: x < y,
            ">=": lambda x, y: x >= y,
            "<=": lambda x, y: x <= y,
            "==": lambda x, y: x == y,
            "!=": lambda x, y: x != y,
        }

        if operator not in operators:
            raise ValueError(f"Unknown operator: {operator}")

        return operators[operator](value, threshold)

    async def _trigger_alert(self, rule: AlertRule):
        """
        Trigger an alert
    Args:
            rule: Alert rule"""
        import uuid

        # Check if alert already exists
        if rule.id in self.active_alerts:
            alert = self.active_alerts[rule.id]
            if alert.state == AlertState.FIRING:
                return  # Already firing
            alert.state = AlertState.FIRING
        else:
            # Create new alert
            alert = Alert(
                id=str(uuid.uuid4())[:12],
                rule_id=rule.id,
                name=rule.name,
                severity=rule.severity,
                state=AlertState.FIRING,
                message=self._format_alert_message(rule),
                started_at=datetime.utcnow(),
                labels=rule.labels,
                annotations=rule.annotations,
            )
            self.active_alerts[rule.id] = alert

        # Check suppression
        if self._is_suppressed(alert):
            alert.state = AlertState.SUPPRESSED
            return

        # Send notifications
        if not alert.notification_sent:
            await self._send_notifications(alert, rule.channels)
            alert.notification_sent = True

        # Handle escalation
        await self._handle_escalation(alert)

    async def _resolve_alert(self, rule_id: str):
        """
        Resolve an alert
    Args:
            rule_id: Rule ID"""
        if rule_id not in self.active_alerts:
            return

        alert = self.active_alerts[rule_id]
        if alert.state != AlertState.FIRING:
            return

        alert.state = AlertState.RESOLVED
        alert.ended_at = datetime.utcnow()

        # Send resolution notification
        rule = self.rules.get(rule_id)
        if rule:
            await self._send_resolution_notification(alert, rule.channels)

        # Move to history
        self.alert_history.append(alert)
        del self.active_alerts[rule_id]

        async def _send_notifications(
            self,
            alert: Alert,
            channels: List[AlertChannel]
        ):
        """
        Send alert notifications
    Args:
            alert: Alert instance
            channels: Notification channels"""
        for channel in channels:
            if channel not in self.notification_handlers:
                continue

            try:
                handler = self.notification_handlers[channel]
                config = self.notification_configs.get(channel)

                if config:
                    await handler(alert, config)

            except Exception as e:
                print(f"Error sending {channel} notification: {e}")

    async def _send_resolution_notification(
        self, alert: Alert, channels: List[AlertChannel]
    ):
        """Send resolution notification"""
        alert.message = f"RESOLVED: {alert.message}"
        await self._send_notifications(alert, channels)

    def _format_alert_message(self, rule: AlertRule) -> str:
        """Format alert message"""
        message = rule.annotations.get("summary", rule.description)

        # Add details
        details = rule.annotations.get("description", "")
        if details:
            message += f"\n{details}"

        # Add labels
        if rule.labels:
            labels_str = ", ".join(f"{k}={v}" for k, v in rule.labels.items())
            message += f"\nLabels: {labels_str}"

        return message

    def _is_suppressed(self, alert: Alert) -> bool:
        """
        Check if alert is suppressed
    Args:
            alert: Alert instance
    Returns:
            True if suppressed"""
        # Check if alert has suppression time
        if alert.suppressed_until and alert.suppressed_until > \
                datetime.utcnow():
            return True

        # Check suppression rules
        for rule in self.suppression_rules:
            if self._matches_suppression_rule(alert, rule):
                return True

        return False

        def _matches_suppression_rule(
            self,
            alert: Alert,
            rule: Dict[str,
                       Any]
        ) -> bool:
        """Check if alert matches suppression rule"""
        # Check time window
        if "time_window" in rule:
            start = rule["time_window"]["start"]
            end = rule["time_window"]["end"]
            now = datetime.utcnow()
            if not (start <= now <= end):
                return False

        # Check alert patterns
        if "pattern" in rule:
            pattern = re.compile(rule["pattern"])
            if not pattern.match(alert.name):
                return False

        # Check labels
        if "labels" in rule:
            for key, value in rule["labels"].items():
                if alert.labels.get(key) != value:
                    return False

        return True

    async def _handle_escalation(self, alert: Alert):
        """
        Handle alert escalation
    Args:
            alert: Alert instance"""
        if alert.rule_id not in self.escalation_policies:
            return

        policy = self.escalation_policies[alert.rule_id]

        # Calculate time since alert started
        duration = datetime.utcnow() - alert.started_at

        # Find appropriate escalation level
        for level in policy:
            if duration >= level["after"]:
                if alert.escalation_level < level["level"]:
                    alert.escalation_level = level["level"]
                    # Send escalation notification
                    await self._send_escalation_notification(
                        alert,
                        level["channels"]
                    )

    async def _send_escalation_notification(
        self, alert: Alert, channels: List[AlertChannel]
    ):
        """Send escalation notification"""
        alert.message = f"ESCALATED (Level {alert.escalation_level}): \"
            {alert.message}"
        await self._send_notifications(alert, channels)

    def acknowledge_alert(self, alert_id: str, acknowledged_by: str) -> bool:
        """
        Acknowledge an alert
    Args:
            alert_id: Alert ID
            acknowledged_by: User acknowledging
    Returns:
            Success status"""
        for alert in self.active_alerts.values():
            if alert.id == alert_id:
                alert.state = AlertState.ACKNOWLEDGED
                alert.acknowledged_at = datetime.utcnow()
                alert.acknowledged_by = acknowledged_by
                return True
        return False

    def suppress_alert(self, alert_id: str, duration: timedelta) -> bool:
        """
        Suppress an alert
    Args:
            alert_id: Alert ID
            duration: Suppression duration
    Returns:
            Success status"""
        for alert in self.active_alerts.values():
            if alert.id == alert_id:
                alert.state = AlertState.SUPPRESSED
                alert.suppressed_until = datetime.utcnow() + duration
                return True
        return False

    def get_active_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
        state: Optional[AlertState] = None,
    ) -> List[Alert]:
        """
        Get active alerts
    Args:
            severity: Filter by severity
            state: Filter by state
    Returns:
            List of active alerts"""
        alerts = list(self.active_alerts.values())

        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        if state:
            alerts = [a for a in alerts if a.state == state]

        return sorted(alerts, key=lambda x: x.started_at, reverse=True)

    def get_alert_statistics(self) -> Dict[str, Any]:
        """
        Get alert statistics
    Returns:
            Alert statistics"""
        active = self.get_active_alerts()

        # Count by severity
        severity_counts = defaultdict(int)
        for alert in active:
            severity_counts[alert.severity.value] += 1

        # Count by state
        state_counts = defaultdict(int)
        for alert in active:
            state_counts[alert.state.value] += 1

        # Calculate MTTR (Mean Time To Resolve)
        resolved_alerts = [
            a
            for a in self.alert_history
            if a.ended_at and a.state == AlertState.RESOLVED
        ]

        if resolved_alerts:
            total_duration = sum(
                (a.ended_at - a.started_at).total_seconds() for a in
                resolved_alerts
            )
            mttr = total_duration / len(resolved_alerts)
        else:
            mttr = 0

        return {
            "total_active": len(active),
            "severity_counts": dict(severity_counts),
            "state_counts": dict(state_counts),
            "total_resolved": len(resolved_alerts),
            "mttr_seconds": mttr,
            "escalated": sum(1 for a in active if a.escalation_level > 0),
        }
