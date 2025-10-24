"""
Unit tests for alert management system.
Tests alert rules, evaluation, firing, and notification integration.
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, Any
from uuid import uuid4

from src.monitoring.alerts import (
    AlertManager,
    AlertRule,
    AlertInstance,
    AlertSeverity,
    AlertState,
    AlertCondition
)
from src.monitoring.metrics import MetricsCollector


class TestAlertSeverity:
    """Test alert severity enum."""

    def test_severity_values(self):
        """Test alert severity enum values."""
        assert AlertSeverity.INFO.value == "info"
        assert AlertSeverity.WARNING.value == "warning"
        assert AlertSeverity.CRITICAL.value == "critical"
        assert AlertSeverity.EMERGENCY.value == "emergency"


class TestAlertState:
    """Test alert state enum."""

    def test_state_values(self):
        """Test alert state enum values."""
        assert AlertState.INACTIVE.value == "inactive"
        assert AlertState.PENDING.value == "pending"
        assert AlertState.FIRING.value == "firing"
        assert AlertState.RESOLVED.value == "resolved"


class TestAlertCondition:
    """Test alert condition enum."""

    def test_condition_values(self):
        """Test alert condition enum values."""
        assert AlertCondition.GREATER_THAN.value == ">"
        assert AlertCondition.LESS_THAN.value == "<"
        assert AlertCondition.EQUAL.value == "=="
        assert AlertCondition.NOT_EQUAL.value == "!="
        assert AlertCondition.GREATER_EQUAL.value == ">="
        assert AlertCondition.LESS_EQUAL.value == "<="


class TestAlertRule:
    """Test alert rule."""

    def test_alert_rule_creation(self):
        """Test creating alert rule."""
        rule = AlertRule(
            rule_id="test_rule",
            name="Test Alert",
            description="Test alert description",
            metric_name="test_metric",
            condition=AlertCondition.GREATER_THAN,
            threshold=90,
            severity=AlertSeverity.WARNING
        )

        assert rule.rule_id == "test_rule"
        assert rule.name == "Test Alert"
        assert rule.threshold == 90
        assert rule.severity == AlertSeverity.WARNING

    def test_alert_rule_with_defaults(self):
        """Test alert rule with default values."""
        rule = AlertRule(
            rule_id="test",
            name="Test",
            description="Desc",
            metric_name="metric",
            condition=AlertCondition.GREATER_THAN,
            threshold=100,
            severity=AlertSeverity.INFO
        )

        assert rule.labels == {}
        assert rule.duration == 0
        assert rule.frequency == 60
        assert rule.enabled is True
        assert rule.notify_channels == []

    def test_alert_rule_evaluate_greater_than(self):
        """Test evaluating greater than condition."""
        rule = AlertRule(
            rule_id="test",
            name="Test",
            description="",
            metric_name="cpu",
            condition=AlertCondition.GREATER_THAN,
            threshold=80,
            severity=AlertSeverity.WARNING
        )

        assert rule.evaluate(85) is True
        assert rule.evaluate(80) is False
        assert rule.evaluate(75) is False

    def test_alert_rule_evaluate_less_than(self):
        """Test evaluating less than condition."""
        rule = AlertRule(
            rule_id="test",
            name="Test",
            description="",
            metric_name="free_space",
            condition=AlertCondition.LESS_THAN,
            threshold=10,
            severity=AlertSeverity.CRITICAL
        )

        assert rule.evaluate(5) is True
        assert rule.evaluate(10) is False
        assert rule.evaluate(15) is False

    def test_alert_rule_evaluate_equal(self):
        """Test evaluating equal condition."""
        rule = AlertRule(
            rule_id="test",
            name="Test",
            description="",
            metric_name="connections",
            condition=AlertCondition.EQUAL,
            threshold=0,
            severity=AlertSeverity.WARNING
        )

        assert rule.evaluate(0) is True
        assert rule.evaluate(1) is False

    def test_alert_rule_evaluate_not_equal(self):
        """Test evaluating not equal condition."""
        rule = AlertRule(
            rule_id="test",
            name="Test",
            description="",
            metric_name="status",
            condition=AlertCondition.NOT_EQUAL,
            threshold=1,
            severity=AlertSeverity.CRITICAL
        )

        assert rule.evaluate(0) is True
        assert rule.evaluate(1) is False
        assert rule.evaluate(2) is True

    def test_alert_rule_to_dict(self):
        """Test converting rule to dictionary."""
        rule = AlertRule(
            rule_id="test_rule",
            name="Test Alert",
            description="Description",
            metric_name="test_metric",
            condition=AlertCondition.GREATER_THAN,
            threshold=90,
            severity=AlertSeverity.WARNING,
            labels={"env": "prod"},
            notify_channels=["email", "slack"]
        )

        rule_dict = rule.to_dict()

        assert rule_dict["rule_id"] == "test_rule"
        assert rule_dict["name"] == "Test Alert"
        assert rule_dict["condition"] == ">"
        assert rule_dict["threshold"] == 90
        assert rule_dict["severity"] == "warning"
        assert rule_dict["labels"] == {"env": "prod"}
        assert rule_dict["notify_channels"] == ["email", "slack"]


class TestAlertInstance:
    """Test alert instance."""

    def test_alert_instance_creation(self):
        """Test creating alert instance."""
        rule = AlertRule(
            rule_id="test",
            name="Test",
            description="",
            metric_name="cpu",
            condition=AlertCondition.GREATER_THAN,
            threshold=80,
            severity=AlertSeverity.WARNING
        )

        started_at = datetime.utcnow()
        instance = AlertInstance(
            alert_id=str(uuid4()),
            rule=rule,
            state=AlertState.FIRING,
            value=90.5,
            started_at=started_at,
            last_evaluated=started_at
        )

        assert instance.rule is rule
        assert instance.state == AlertState.FIRING
        assert instance.value == 90.5
        assert instance.started_at == started_at

    def test_alert_instance_to_dict(self):
        """Test converting instance to dictionary."""
        rule = AlertRule(
            rule_id="test",
            name="Test",
            description="",
            metric_name="cpu",
            condition=AlertCondition.GREATER_THAN,
            threshold=80,
            severity=AlertSeverity.WARNING,
            labels={"host": "server1"}
        )

        instance = AlertInstance(
            alert_id="alert_123",
            rule=rule,
            state=AlertState.FIRING,
            value=90.5,
            started_at=datetime.utcnow(),
            last_evaluated=datetime.utcnow(),
            labels={"instance": "web1"}
        )

        instance_dict = instance.to_dict()

        assert instance_dict["alert_id"] == "alert_123"
        assert instance_dict["rule_id"] == "test"
        assert instance_dict["state"] == "firing"
        assert instance_dict["value"] == 90.5
        assert "host" in instance_dict["labels"]
        assert "instance" in instance_dict["labels"]


class TestAlertManager:
    """Test alert manager."""

    @pytest.fixture
    def metrics_collector(self):
        """Create metrics collector."""
        return MetricsCollector()

    @pytest.fixture
    def alert_manager(self, metrics_collector):
        """Create alert manager."""
        return AlertManager(metrics_collector)

    def test_alert_manager_initialization(self, alert_manager):
        """Test alert manager initialization."""
        assert isinstance(alert_manager.rules, dict)
        assert isinstance(alert_manager.active_alerts, dict)
        assert isinstance(alert_manager.silenced_alerts, dict)

    def test_alert_manager_has_default_rules(self, alert_manager):
        """Test alert manager has default alert rules."""
        assert len(alert_manager.rules) > 0

        # Check for specific default rules
        assert "high_cpu" in alert_manager.rules
        assert "high_memory" in alert_manager.rules
        assert "low_disk" in alert_manager.rules

    def test_add_rule(self, alert_manager):
        """Test adding alert rule."""
        rule = AlertRule(
            rule_id="custom_rule",
            name="Custom Alert",
            description="Custom alert",
            metric_name="custom_metric",
            condition=AlertCondition.GREATER_THAN,
            threshold=100,
            severity=AlertSeverity.INFO
        )

        alert_manager.add_rule(rule)

        assert "custom_rule" in alert_manager.rules
        assert alert_manager.rules["custom_rule"] is rule

    def test_remove_rule(self, alert_manager):
        """Test removing alert rule."""
        rule = AlertRule(
            rule_id="temp_rule",
            name="Temp",
            description="",
            metric_name="test",
            condition=AlertCondition.GREATER_THAN,
            threshold=1,
            severity=AlertSeverity.INFO
        )

        alert_manager.add_rule(rule)
        assert "temp_rule" in alert_manager.rules

        alert_manager.remove_rule("temp_rule")
        assert "temp_rule" not in alert_manager.rules

    def test_enable_disable_rule(self, alert_manager):
        """Test enabling and disabling rules."""
        rule = AlertRule(
            rule_id="toggle_rule",
            name="Toggle",
            description="",
            metric_name="test",
            condition=AlertCondition.GREATER_THAN,
            threshold=1,
            severity=AlertSeverity.INFO,
            enabled=True
        )

        alert_manager.add_rule(rule)

        alert_manager.disable_rule("toggle_rule")
        assert alert_manager.rules["toggle_rule"].enabled is False

        alert_manager.enable_rule("toggle_rule")
        assert alert_manager.rules["toggle_rule"].enabled is True

    @pytest.mark.asyncio
    async def test_start_alert_manager(self, alert_manager):
        """Test starting alert manager."""
        await alert_manager.start()

        assert alert_manager._running is True
        assert len(alert_manager._evaluation_tasks) > 0

        await alert_manager.stop()

    @pytest.mark.asyncio
    async def test_stop_alert_manager(self, alert_manager):
        """Test stopping alert manager."""
        await alert_manager.start()
        assert alert_manager._running is True

        await alert_manager.stop()

        assert alert_manager._running is False
        assert len(alert_manager._evaluation_tasks) == 0

    @pytest.mark.asyncio
    async def test_evaluate_rule_condition_met(self, alert_manager, metrics_collector):
        """Test evaluating rule when condition is met."""
        gauge = metrics_collector.gauge("test_metric")
        gauge.set(95)

        rule = AlertRule(
            rule_id="test_eval",
            name="Test",
            description="",
            metric_name="test_metric",
            condition=AlertCondition.GREATER_THAN,
            threshold=90,
            severity=AlertSeverity.WARNING
        )

        result = await alert_manager._evaluate_rule(rule)

        assert result is True

    @pytest.mark.asyncio
    async def test_evaluate_rule_condition_not_met(self, alert_manager, metrics_collector):
        """Test evaluating rule when condition is not met."""
        gauge = metrics_collector.gauge("test_metric")
        gauge.set(85)

        rule = AlertRule(
            rule_id="test_eval",
            name="Test",
            description="",
            metric_name="test_metric",
            condition=AlertCondition.GREATER_THAN,
            threshold=90,
            severity=AlertSeverity.WARNING
        )

        result = await alert_manager._evaluate_rule(rule)

        assert result is False

    @pytest.mark.asyncio
    async def test_evaluate_rule_with_labels(self, alert_manager, metrics_collector):
        """Test evaluating rule with label matching."""
        gauge = metrics_collector.gauge("temperature", labels=["location"])
        gauge.set(30, labels={"location": "datacenter"})

        rule = AlertRule(
            rule_id="temp_alert",
            name="Temperature",
            description="",
            metric_name="temperature",
            condition=AlertCondition.GREATER_THAN,
            threshold=25,
            severity=AlertSeverity.WARNING,
            labels={"location": "datacenter"}
        )

        result = await alert_manager._evaluate_rule(rule)

        assert result is True

    @pytest.mark.asyncio
    async def test_fire_alert(self, alert_manager, metrics_collector):
        """Test firing an alert."""
        gauge = metrics_collector.gauge("test_metric")
        gauge.set(95)

        rule = AlertRule(
            rule_id="fire_test",
            name="Fire Test",
            description="Test firing",
            metric_name="test_metric",
            condition=AlertCondition.GREATER_THAN,
            threshold=90,
            severity=AlertSeverity.WARNING
        )

        alert_manager.rules[rule.rule_id] = rule
        alert_manager._last_values[rule.rule_id] = 95

        with patch.object(alert_manager, '_send_notifications', new=AsyncMock()), \
             patch.object(alert_manager, '_store_alert', new=AsyncMock()):

            await alert_manager._fire_alert(rule)

            alert_key = alert_manager._get_alert_key(rule)
            assert alert_key in alert_manager.active_alerts
            assert alert_manager.active_alerts[alert_key].state == AlertState.FIRING

    @pytest.mark.asyncio
    async def test_resolve_alert(self, alert_manager):
        """Test resolving an alert."""
        rule = AlertRule(
            rule_id="resolve_test",
            name="Resolve Test",
            description="",
            metric_name="test",
            condition=AlertCondition.GREATER_THAN,
            threshold=1,
            severity=AlertSeverity.INFO
        )

        alert_key = alert_manager._get_alert_key(rule)
        alert_instance = AlertInstance(
            alert_id=str(uuid4()),
            rule=rule,
            state=AlertState.FIRING,
            value=100,
            started_at=datetime.utcnow(),
            last_evaluated=datetime.utcnow()
        )

        alert_manager.active_alerts[alert_key] = alert_instance

        with patch.object(alert_manager, '_send_resolution_notification', new=AsyncMock()), \
             patch.object(alert_manager, '_update_alert', new=AsyncMock()):

            await alert_manager._resolve_alert(alert_key)

            assert alert_instance.state == AlertState.RESOLVED
            assert alert_instance.resolved_at is not None
            assert alert_key not in alert_manager.active_alerts

    @pytest.mark.asyncio
    async def test_alert_not_fired_if_already_firing(self, alert_manager):
        """Test alert is not re-fired if already active."""
        rule = AlertRule(
            rule_id="duplicate_test",
            name="Duplicate Test",
            description="",
            metric_name="test",
            condition=AlertCondition.GREATER_THAN,
            threshold=1,
            severity=AlertSeverity.INFO
        )

        alert_key = alert_manager._get_alert_key(rule)
        alert_instance = AlertInstance(
            alert_id=str(uuid4()),
            rule=rule,
            state=AlertState.FIRING,
            value=100,
            started_at=datetime.utcnow(),
            last_evaluated=datetime.utcnow()
        )

        alert_manager.active_alerts[alert_key] = alert_instance
        alert_manager.rules[rule.rule_id] = rule
        alert_manager._last_values[rule.rule_id] = 100

        initial_alert_id = alert_instance.alert_id

        with patch.object(alert_manager, '_send_notifications', new=AsyncMock()):
            await alert_manager._fire_alert(rule)

            # Should not create a new alert
            assert alert_manager.active_alerts[alert_key].alert_id == initial_alert_id

    def test_silence_alert(self, alert_manager):
        """Test silencing an alert."""
        rule = AlertRule(
            rule_id="silence_test",
            name="Silence Test",
            description="",
            metric_name="test",
            condition=AlertCondition.GREATER_THAN,
            threshold=1,
            severity=AlertSeverity.INFO
        )

        alert_manager.rules[rule.rule_id] = rule
        alert_manager.silence_alert("silence_test", duration=3600)

        alert_key = alert_manager._get_alert_key(rule)
        assert alert_key in alert_manager.silenced_alerts

    def test_unsilence_alert(self, alert_manager):
        """Test unsilencing an alert."""
        rule = AlertRule(
            rule_id="unsilence_test",
            name="Unsilence Test",
            description="",
            metric_name="test",
            condition=AlertCondition.GREATER_THAN,
            threshold=1,
            severity=AlertSeverity.INFO
        )

        alert_manager.rules[rule.rule_id] = rule
        alert_manager.silence_alert("unsilence_test")

        alert_key = alert_manager._get_alert_key(rule)
        assert alert_key in alert_manager.silenced_alerts

        alert_manager.unsilence_alert("unsilence_test")
        assert alert_key not in alert_manager.silenced_alerts

    @pytest.mark.asyncio
    async def test_silenced_alert_not_fired(self, alert_manager):
        """Test silenced alert is not fired."""
        rule = AlertRule(
            rule_id="silenced_fire",
            name="Silenced Fire",
            description="",
            metric_name="test",
            condition=AlertCondition.GREATER_THAN,
            threshold=1,
            severity=AlertSeverity.INFO
        )

        alert_manager.rules[rule.rule_id] = rule
        alert_manager._last_values[rule.rule_id] = 100
        alert_manager.silence_alert("silenced_fire")

        await alert_manager._fire_alert(rule)

        # Alert should not be added to active alerts
        alert_key = alert_manager._get_alert_key(rule)
        assert alert_key not in alert_manager.active_alerts

    def test_get_active_alerts(self, alert_manager):
        """Test getting active alerts."""
        rule = AlertRule(
            rule_id="active_test",
            name="Active Test",
            description="",
            metric_name="test",
            condition=AlertCondition.GREATER_THAN,
            threshold=1,
            severity=AlertSeverity.INFO
        )

        alert_instance = AlertInstance(
            alert_id="test_alert",
            rule=rule,
            state=AlertState.FIRING,
            value=100,
            started_at=datetime.utcnow(),
            last_evaluated=datetime.utcnow()
        )

        alert_key = alert_manager._get_alert_key(rule)
        alert_manager.active_alerts[alert_key] = alert_instance

        active = alert_manager.get_active_alerts()

        assert len(active) == 1
        assert active[0]["alert_id"] == "test_alert"

    def test_get_alert_by_id(self, alert_manager):
        """Test getting specific alert by ID."""
        rule = AlertRule(
            rule_id="get_test",
            name="Get Test",
            description="",
            metric_name="test",
            condition=AlertCondition.GREATER_THAN,
            threshold=1,
            severity=AlertSeverity.INFO
        )

        alert_instance = AlertInstance(
            alert_id="specific_alert",
            rule=rule,
            state=AlertState.FIRING,
            value=100,
            started_at=datetime.utcnow(),
            last_evaluated=datetime.utcnow()
        )

        alert_key = alert_manager._get_alert_key(rule)
        alert_manager.active_alerts[alert_key] = alert_instance

        alert = alert_manager.get_alert("specific_alert")

        assert alert is not None
        assert alert["alert_id"] == "specific_alert"

    def test_get_nonexistent_alert(self, alert_manager):
        """Test getting non-existent alert returns None."""
        alert = alert_manager.get_alert("nonexistent")

        assert alert is None


class TestAlertFormatting:
    """Test alert message formatting."""

    @pytest.fixture
    def alert_manager(self):
        """Create alert manager."""
        return AlertManager(MetricsCollector())

    def test_format_alert_message(self, alert_manager):
        """Test formatting alert message."""
        rule = AlertRule(
            rule_id="test",
            name="High CPU",
            description="CPU usage is high",
            metric_name="cpu",
            condition=AlertCondition.GREATER_THAN,
            threshold=80,
            severity=AlertSeverity.WARNING,
            annotations={"summary": "CPU alert", "description": "Details"}
        )

        started_at = datetime.utcnow() - timedelta(minutes=5)
        alert = AlertInstance(
            alert_id="test_alert",
            rule=rule,
            state=AlertState.FIRING,
            value=95.5,
            started_at=started_at,
            last_evaluated=datetime.utcnow()
        )

        message = alert_manager._format_alert_message(alert)

        assert "High CPU" in message
        assert "WARNING" in message
        assert "95.5" in message
        assert "80" in message

    def test_format_resolution_message(self, alert_manager):
        """Test formatting resolution message."""
        rule = AlertRule(
            rule_id="test",
            name="High CPU",
            description="CPU usage is high",
            metric_name="cpu",
            condition=AlertCondition.GREATER_THAN,
            threshold=80,
            severity=AlertSeverity.WARNING
        )

        started_at = datetime.utcnow() - timedelta(minutes=10)
        resolved_at = datetime.utcnow()

        alert = AlertInstance(
            alert_id="test_alert",
            rule=rule,
            state=AlertState.RESOLVED,
            value=95.5,
            started_at=started_at,
            last_evaluated=resolved_at,
            resolved_at=resolved_at
        )

        message = alert_manager._format_resolution_message(alert)

        assert "Alert Resolved" in message
        assert "High CPU" in message
        assert "RESOLVED" in message

    def test_format_duration(self, alert_manager):
        """Test formatting duration."""
        assert "30s" in alert_manager._format_duration(30)
        assert "5m" in alert_manager._format_duration(300)
        assert "1h" in alert_manager._format_duration(3600)
        assert "2h 30m" in alert_manager._format_duration(9000)

    def test_format_labels(self, alert_manager):
        """Test formatting labels."""
        labels = {"env": "prod", "region": "us-east"}

        formatted = alert_manager._format_labels(labels)

        assert "env: prod" in formatted
        assert "region: us-east" in formatted

    def test_format_empty_labels(self, alert_manager):
        """Test formatting empty labels."""
        formatted = alert_manager._format_labels({})

        assert "None" in formatted

    def test_severity_to_priority(self, alert_manager):
        """Test converting severity to notification priority."""
        assert alert_manager._severity_to_priority(AlertSeverity.INFO) == "low"
        assert alert_manager._severity_to_priority(AlertSeverity.WARNING) == "normal"
        assert alert_manager._severity_to_priority(AlertSeverity.CRITICAL) == "high"
        assert alert_manager._severity_to_priority(AlertSeverity.EMERGENCY) == "critical"


class TestAlertNotifications:
    """Test alert notification integration."""

    @pytest.fixture
    def metrics_collector(self):
        """Create metrics collector."""
        return MetricsCollector()

    @pytest.fixture
    def notification_worker(self):
        """Create mock notification worker."""
        worker = AsyncMock()
        worker.submit_task = AsyncMock()
        return worker

    @pytest.fixture
    def alert_manager(self, metrics_collector, notification_worker):
        """Create alert manager with notification worker."""
        return AlertManager(metrics_collector, notification_worker)

    @pytest.mark.asyncio
    async def test_send_notifications(self, alert_manager, notification_worker):
        """Test sending alert notifications."""
        rule = AlertRule(
            rule_id="notify_test",
            name="Notify Test",
            description="",
            metric_name="test",
            condition=AlertCondition.GREATER_THAN,
            threshold=1,
            severity=AlertSeverity.CRITICAL,
            notify_channels=["email", "slack"]
        )

        alert = AlertInstance(
            alert_id="test_alert",
            rule=rule,
            state=AlertState.FIRING,
            value=100,
            started_at=datetime.utcnow(),
            last_evaluated=datetime.utcnow()
        )

        await alert_manager._send_notifications(alert)

        # Should send to both channels
        assert notification_worker.submit_task.call_count == 2

    @pytest.mark.asyncio
    async def test_notification_respects_silence_duration(self, alert_manager, notification_worker):
        """Test notification respects silence duration."""
        rule = AlertRule(
            rule_id="silence_notify",
            name="Silence Notify",
            description="",
            metric_name="test",
            condition=AlertCondition.GREATER_THAN,
            threshold=1,
            severity=AlertSeverity.WARNING,
            notify_channels=["email"],
            silence_duration=3600
        )

        alert = AlertInstance(
            alert_id="test_alert",
            rule=rule,
            state=AlertState.FIRING,
            value=100,
            started_at=datetime.utcnow(),
            last_evaluated=datetime.utcnow(),
            notified_at=datetime.utcnow() - timedelta(minutes=30)  # Recently notified
        )

        await alert_manager._send_notifications(alert)

        # Should not send notification (within silence duration)
        notification_worker.submit_task.assert_not_called()

    @pytest.mark.asyncio
    async def test_notification_after_silence_expires(self, alert_manager, notification_worker):
        """Test notification sent after silence expires."""
        rule = AlertRule(
            rule_id="expire_silence",
            name="Expire Silence",
            description="",
            metric_name="test",
            condition=AlertCondition.GREATER_THAN,
            threshold=1,
            severity=AlertSeverity.WARNING,
            notify_channels=["email"],
            silence_duration=3600
        )

        alert = AlertInstance(
            alert_id="test_alert",
            rule=rule,
            state=AlertState.FIRING,
            value=100,
            started_at=datetime.utcnow(),
            last_evaluated=datetime.utcnow(),
            notified_at=datetime.utcnow() - timedelta(hours=2)  # Old notification
        )

        await alert_manager._send_notifications(alert)

        # Should send notification (silence expired)
        notification_worker.submit_task.assert_called_once()


class TestAlertEvaluationLoop:
    """Test alert evaluation loop."""

    @pytest.mark.asyncio
    async def test_evaluate_rule_with_duration(self):
        """Test rule evaluation respects duration requirement."""
        metrics_collector = MetricsCollector()
        alert_manager = AlertManager(metrics_collector)

        gauge = metrics_collector.gauge("test_metric")
        gauge.set(95)

        rule = AlertRule(
            rule_id="duration_test",
            name="Duration Test",
            description="",
            metric_name="test_metric",
            condition=AlertCondition.GREATER_THAN,
            threshold=90,
            severity=AlertSeverity.WARNING,
            duration=2,  # 2 seconds
            frequency=1  # Check every second
        )

        alert_manager.rules[rule.rule_id] = rule
        alert_manager._last_values[rule.rule_id] = 95

        # Start evaluation (will run in background)
        with patch.object(alert_manager, '_fire_alert', new=AsyncMock()) as mock_fire:
            task = asyncio.create_task(alert_manager._evaluate_rule_loop(rule))

            # Wait for duration to be met
            await asyncio.sleep(3)

            # Cancel the loop
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

            # Alert should have been fired after duration
            mock_fire.assert_called()

    @pytest.mark.asyncio
    async def test_evaluate_rule_without_duration(self):
        """Test rule evaluation fires immediately without duration."""
        metrics_collector = MetricsCollector()
        alert_manager = AlertManager(metrics_collector)

        gauge = metrics_collector.gauge("test_metric")
        gauge.set(95)

        rule = AlertRule(
            rule_id="immediate_test",
            name="Immediate Test",
            description="",
            metric_name="test_metric",
            condition=AlertCondition.GREATER_THAN,
            threshold=90,
            severity=AlertSeverity.WARNING,
            duration=0,  # Fire immediately
            frequency=1
        )

        alert_manager.rules[rule.rule_id] = rule
        alert_manager._last_values[rule.rule_id] = 95

        with patch.object(alert_manager, '_fire_alert', new=AsyncMock()) as mock_fire:
            task = asyncio.create_task(alert_manager._evaluate_rule_loop(rule))

            # Wait a bit
            await asyncio.sleep(1.5)

            # Cancel the loop
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

            # Should fire immediately
            mock_fire.assert_called()
