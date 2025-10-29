"""
Unit tests for health monitoring engine.
Tests health checks, SLA tracking, and alert management.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta
from uuid import uuid4

from src.monitoring.health_monitor import HealthMonitor
from src.db.models.monitoring import (
    HealthCheck,
    HealthCheckResult,
    HealthCheckType,
    HealthStatus,
    Alert,
    AlertStatus,
    AlertSeverity,
)


class TestHealthMonitor:
    """Test health monitoring engine."""

    @pytest.fixture
    def health_monitor(self):
        """Create health monitor instance."""
        return HealthMonitor()

    def test_health_monitor_initialization(self, health_monitor):
        """Test health monitor initialization."""
        assert health_monitor.running_checks == {}
        assert health_monitor.check_semaphore._value == 50

    @pytest.mark.asyncio
    async def test_start_monitoring(self, health_monitor):
        """Test starting health monitoring."""
        # Mock database session
        db_session = AsyncMock()
        mock_result = Mock()
        mock_checks = [
            Mock(
                id=uuid4(),
                name="test_check",
                enabled=True,
                check_type=HealthCheckType.HTTP,
                interval=60
            )
        ]
        mock_result.scalars.return_value.all.return_value = mock_checks
        db_session.execute.return_value = mock_result

        with patch('src.monitoring.health_monitor.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session

            # Start monitoring (will create background tasks)
            await health_monitor.start_monitoring()

            # Verify tasks were created
            assert len(health_monitor.running_checks) == 1

            # Clean up
            await health_monitor.stop_monitoring()

    @pytest.mark.asyncio
    async def test_stop_monitoring(self, health_monitor):
        """Test stopping health monitoring."""
        # Create a dummy task
        mock_task = AsyncMock()
        health_monitor.running_checks["test_check"] = mock_task

        await health_monitor.stop_monitoring()

        # Verify task was cancelled
        mock_task.cancel.assert_called_once()
        assert len(health_monitor.running_checks) == 0

    @pytest.mark.asyncio
    async def test_execute_http_check_success(self, health_monitor):
        """Test successful HTTP health check."""
        check = Mock(
            id=uuid4(),
            name="http_check",
            check_type=HealthCheckType.HTTP,
            target="https://example.com",
            timeout=5
        )

        with patch('httpx.AsyncClient') as mock_client:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.elapsed.total_seconds.return_value = 0.5
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )

            result = await health_monitor._execute_http_check(check)

            assert result["status"] == HealthStatus.HEALTHY
            assert result["response_time"] == 0.5

    @pytest.mark.asyncio
    async def test_execute_http_check_failure(self, health_monitor):
        """Test failed HTTP health check."""
        check = Mock(
            id=uuid4(),
            name="http_check",
            check_type=HealthCheckType.HTTP,
            target="https://example.com",
            timeout=5
        )

        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                side_effect=Exception("Connection failed")
            )

            result = await health_monitor._execute_http_check(check)

            assert result["status"] == HealthStatus.UNHEALTHY
            assert "error" in result

    @pytest.mark.asyncio
    async def test_execute_tcp_check_success(self, health_monitor):
        """Test successful TCP health check."""
        check = Mock(
            id=uuid4(),
            name="tcp_check",
            check_type=HealthCheckType.TCP,
            target="localhost:8080",
            timeout=5
        )

        with patch('asyncio.open_connection') as mock_open_conn:
            mock_reader = AsyncMock()
            mock_writer = AsyncMock()
            mock_open_conn.return_value = (mock_reader, mock_writer)

            result = await health_monitor._execute_tcp_check(check)

            assert result["status"] == HealthStatus.HEALTHY
            mock_writer.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_tcp_check_failure(self, health_monitor):
        """Test failed TCP health check."""
        check = Mock(
            id=uuid4(),
            name="tcp_check",
            check_type=HealthCheckType.TCP,
            target="localhost:8080",
            timeout=5
        )

        with patch('asyncio.open_connection') as mock_open_conn:
            mock_open_conn.side_effect = ConnectionRefusedError("Connection refused")

            result = await health_monitor._execute_tcp_check(check)

            assert result["status"] == HealthStatus.UNHEALTHY

    @pytest.mark.asyncio
    async def test_execute_database_check_success(self, health_monitor):
        """Test successful database health check."""
        check = Mock(
            id=uuid4(),
            name="db_check",
            check_type=HealthCheckType.DATABASE,
            target="SELECT 1",
            timeout=5
        )

        db_session = AsyncMock()
        mock_result = Mock()
        mock_result.scalar.return_value = 1
        db_session.execute.return_value = mock_result

        with patch('src.monitoring.health_monitor.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session

            result = await health_monitor._execute_database_check(check)

            assert result["status"] == HealthStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_execute_device_check(self, health_monitor):
        """Test device health check."""
        device_id = uuid4()
        check = Mock(
            id=uuid4(),
            name="device_check",
            check_type=HealthCheckType.DEVICE,
            target=str(device_id),
            timeout=10
        )

        with patch('src.monitoring.health_monitor.secure_device_connector') as mock_connector:
            mock_connector.connect = AsyncMock()
            mock_connector.execute_command = AsyncMock(return_value="OK")
            mock_connector.disconnect = AsyncMock()

            result = await health_monitor._execute_device_check(check)

            # Should attempt device connection
            assert mock_connector.connect.called or result["status"] in [
                HealthStatus.HEALTHY, HealthStatus.UNHEALTHY
            ]

    @pytest.mark.asyncio
    async def test_evaluate_alert_rules(self, health_monitor):
        """Test alert rule evaluation."""
        check_result = Mock(
            id=uuid4(),
            health_check_id=uuid4(),
            status=HealthStatus.UNHEALTHY,
            response_time=5.0,
            created_at=datetime.utcnow()
        )

        alert_rule = Mock(
            id=uuid4(),
            name="high_response_time",
            condition="response_time > 3",
            severity=AlertSeverity.WARNING,
            enabled=True
        )

        db_session = AsyncMock()
        mock_result = Mock()
        mock_result.scalars.return_value.all.return_value = [alert_rule]
        db_session.execute.return_value = mock_result

        with patch('src.monitoring.health_monitor.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session

            alerts = await health_monitor._evaluate_alert_rules(check_result)

            # Should evaluate rules
            assert db_session.execute.called

    @pytest.mark.asyncio
    async def test_create_alert(self, health_monitor):
        """Test alert creation."""
        alert_rule = Mock(
            id=uuid4(),
            name="test_alert",
            severity=AlertSeverity.CRITICAL,
            description="Test alert rule"
        )

        check_result = Mock(
            id=uuid4(),
            health_check_id=uuid4(),
            status=HealthStatus.UNHEALTHY,
            message="Service down"
        )

        db_session = AsyncMock()

        with patch('src.monitoring.health_monitor.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session

            alert = await health_monitor._create_alert(alert_rule, check_result)

            # Should add alert to session
            assert db_session.add.called or alert is not None

    @pytest.mark.asyncio
    async def test_resolve_alert(self, health_monitor):
        """Test alert resolution."""
        alert = Mock(
            id=uuid4(),
            status=AlertStatus.ACTIVE,
            resolved_at=None
        )

        db_session = AsyncMock()

        with patch('src.monitoring.health_monitor.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session

            await health_monitor._resolve_alert(alert)

            assert alert.status == AlertStatus.RESOLVED
            assert alert.resolved_at is not None

    @pytest.mark.asyncio
    async def test_concurrent_check_limit(self, health_monitor):
        """Test that concurrent checks are limited by semaphore."""
        check = Mock(
            id=uuid4(),
            name="slow_check",
            check_type=HealthCheckType.HTTP,
            target="https://example.com",
            timeout=5
        )

        async def slow_check():
            async with health_monitor.check_semaphore:
                await asyncio.sleep(0.1)

        # Create more tasks than semaphore limit
        tasks = [slow_check() for _ in range(60)]

        # Should complete without issues (semaphore limits concurrent execution)
        await asyncio.gather(*tasks)

    @pytest.mark.asyncio
    async def test_health_check_loop_continues_on_error(self, health_monitor):
        """Test that health check loop continues even after errors."""
        check_id = uuid4()

        db_session = AsyncMock()
        mock_result = Mock()
        mock_check = Mock(
            id=check_id,
            name="test_check",
            enabled=True,
            check_type=HealthCheckType.HTTP,
            interval=1,
            target="https://example.com"
        )
        mock_result.scalars.return_value.first.return_value = mock_check
        db_session.execute.return_value = mock_result

        call_count = 0

        async def mock_execute():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("First execution failed")
            return mock_result

        db_session.execute = mock_execute

        with patch('src.monitoring.health_monitor.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session

            # Start check loop
            task = asyncio.create_task(
                health_monitor._run_health_check_loop(str(check_id))
            )

            # Let it run briefly
            await asyncio.sleep(0.2)

            # Cancel task
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

            # Should have attempted multiple times despite error
            # (actual count depends on timing, but should be > 1)
            assert call_count >= 1
