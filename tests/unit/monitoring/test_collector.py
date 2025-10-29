"""
Unit tests for metrics collectors (SystemMetricsCollector, etc).
Tests specialized metric collection for various subsystems.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta
from uuid import uuid4

from src.monitoring.collector import (
    SystemMetricsCollector,
    DeviceMetricsCollector,
    DeploymentMetricsCollector,
    DatabaseMetricsCollector,
)
from src.monitoring.metrics import MetricsCollector
from src.core.exceptions import MetricsError


class TestSystemMetricsCollector:
    """Test system metrics collection."""

    @pytest.fixture
    def metrics_collector(self):
        """Create metrics collector mock."""
        return Mock(spec=MetricsCollector)

    @pytest.fixture
    def system_collector(self, metrics_collector):
        """Create system metrics collector."""
        return SystemMetricsCollector(metrics_collector)

    @pytest.mark.asyncio
    async def test_system_collector_initialization(self, system_collector):
        """Test system metrics collector initialization."""
        assert system_collector.metrics is not None
        assert system_collector._collection_interval == 60
        assert system_collector._running is False

    @pytest.mark.asyncio
    async def test_start_stop_collection(self, system_collector):
        """Test starting and stopping metric collection."""
        # Start collection in background
        task = asyncio.create_task(system_collector.start_collection())
        await asyncio.sleep(0.1)  # Let it start

        assert system_collector._running is True

        # Stop collection
        await system_collector.stop_collection()
        await asyncio.sleep(0.1)

        assert system_collector._running is False
        task.cancel()

        try:
            await task
        except asyncio.CancelledError:
            pass

    @pytest.mark.asyncio
    @patch('src.monitoring.collector.psutil')
    async def test_collect_cpu_metrics(self, mock_psutil, system_collector, metrics_collector):
        """Test CPU metrics collection."""
        # Mock psutil
        mock_psutil.cpu_count.return_value = 8
        mock_psutil.cpu_percent.return_value = 45.5
        mock_cpu_freq = Mock()
        mock_cpu_freq.current = 2400.0
        mock_psutil.cpu_freq.return_value = mock_cpu_freq

        # Mock gauge
        mock_gauge = Mock()
        metrics_collector.gauge.return_value = mock_gauge

        await system_collector.collect()

        # Verify CPU metrics were recorded
        metrics_collector.gauge.assert_any_call("catnet_system_cpu_count")
        metrics_collector.gauge.assert_any_call("catnet_system_cpu_usage_percent")
        mock_gauge.set.assert_called()

    @pytest.mark.asyncio
    @patch('src.monitoring.collector.psutil')
    async def test_collect_memory_metrics(self, mock_psutil, system_collector, metrics_collector):
        """Test memory metrics collection."""
        # Mock memory info
        mock_memory = Mock()
        mock_memory.total = 16_000_000_000
        mock_memory.available = 8_000_000_000
        mock_memory.used = 8_000_000_000
        mock_memory.percent = 50.0
        mock_psutil.virtual_memory.return_value = mock_memory

        mock_swap = Mock()
        mock_swap.total = 4_000_000_000
        mock_swap.used = 1_000_000_000
        mock_swap.percent = 25.0
        mock_psutil.swap_memory.return_value = mock_swap

        mock_gauge = Mock()
        metrics_collector.gauge.return_value = mock_gauge

        await system_collector.collect()

        # Verify memory metrics were attempted
        assert mock_psutil.virtual_memory.called
        assert mock_psutil.swap_memory.called

    @pytest.mark.asyncio
    @patch('src.monitoring.collector.psutil')
    async def test_collect_handles_errors(self, mock_psutil, system_collector):
        """Test error handling during collection."""
        mock_psutil.cpu_count.side_effect = Exception("psutil error")

        # Should not raise, just log error
        await system_collector.collect()


class TestDeviceMetricsCollector:
    """Test device metrics collection."""

    @pytest.fixture
    def metrics_collector(self):
        """Create metrics collector mock."""
        return Mock(spec=MetricsCollector)

    @pytest.fixture
    async def db_session(self):
        """Create mock database session."""
        session = AsyncMock()
        session.execute = AsyncMock()
        return session

    @pytest.fixture
    def device_collector(self, metrics_collector):
        """Create device metrics collector."""
        return DeviceMetricsCollector(metrics_collector)

    @pytest.mark.asyncio
    async def test_device_collector_initialization(self, device_collector):
        """Test device metrics collector initialization."""
        assert device_collector.metrics is not None
        assert device_collector._collection_interval == 300

    @pytest.mark.asyncio
    async def test_collect_device_metrics(self, device_collector, metrics_collector, db_session):
        """Test device metrics collection."""
        # Mock device query result
        mock_result = Mock()
        mock_devices = [
            Mock(id=uuid4(), hostname="device1", status="online", vendor="cisco"),
            Mock(id=uuid4(), hostname="device2", status="offline", vendor="juniper"),
        ]
        mock_result.scalars.return_value.all.return_value = mock_devices
        db_session.execute.return_value = mock_result

        mock_gauge = Mock()
        mock_counter = Mock()
        metrics_collector.gauge.return_value = mock_gauge
        metrics_collector.counter.return_value = mock_counter

        with patch('src.monitoring.collector.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session
            await device_collector.collect()

        # Verify device metrics were collected
        assert db_session.execute.called


class TestDeploymentMetricsCollector:
    """Test deployment metrics collection."""

    @pytest.fixture
    def metrics_collector(self):
        """Create metrics collector mock."""
        return Mock(spec=MetricsCollector)

    @pytest.fixture
    def deployment_collector(self, metrics_collector):
        """Create deployment metrics collector."""
        return DeploymentMetricsCollector(metrics_collector)

    @pytest.mark.asyncio
    async def test_deployment_collector_initialization(self, deployment_collector):
        """Test deployment metrics collector initialization."""
        assert deployment_collector.metrics is not None
        assert deployment_collector._collection_interval == 60

    @pytest.mark.asyncio
    async def test_collect_deployment_metrics(self, deployment_collector, metrics_collector):
        """Test deployment metrics collection."""
        # Mock database session
        db_session = AsyncMock()
        mock_result = Mock()
        mock_deployments = [
            Mock(
                id=uuid4(),
                status="completed",
                created_at=datetime.utcnow() - timedelta(hours=1),
                completed_at=datetime.utcnow(),
            ),
        ]
        mock_result.scalars.return_value.all.return_value = mock_deployments
        db_session.execute.return_value = mock_result

        mock_counter = Mock()
        mock_histogram = Mock()
        metrics_collector.counter.return_value = mock_counter
        metrics_collector.histogram.return_value = mock_histogram

        with patch('src.monitoring.collector.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session
            await deployment_collector.collect()

        # Verify deployment metrics were attempted
        assert db_session.execute.called


class TestDatabaseMetricsCollector:
    """Test database metrics collection."""

    @pytest.fixture
    def metrics_collector(self):
        """Create metrics collector mock."""
        return Mock(spec=MetricsCollector)

    @pytest.fixture
    def database_collector(self, metrics_collector):
        """Create database metrics collector."""
        return DatabaseMetricsCollector(metrics_collector)

    @pytest.mark.asyncio
    async def test_database_collector_initialization(self, database_collector):
        """Test database metrics collector initialization."""
        assert database_collector.metrics is not None
        assert database_collector._collection_interval == 60

    @pytest.mark.asyncio
    async def test_collect_connection_pool_metrics(self, database_collector, metrics_collector):
        """Test database connection pool metrics."""
        db_session = AsyncMock()
        mock_engine = Mock()
        mock_pool = Mock()
        mock_pool.size.return_value = 10
        mock_pool.checked_out.return_value = 3
        mock_pool.overflow.return_value = 2
        mock_engine.pool = mock_pool
        db_session.get_bind.return_value = mock_engine

        mock_gauge = Mock()
        metrics_collector.gauge.return_value = mock_gauge

        with patch('src.monitoring.collector.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session
            await database_collector.collect()

        # Verify attempt to collect database metrics
        assert mock_get_db.called

    @pytest.mark.asyncio
    async def test_collect_handles_missing_pool(self, database_collector):
        """Test handling of missing connection pool."""
        db_session = AsyncMock()
        mock_engine = Mock()
        mock_engine.pool = None
        db_session.get_bind.return_value = mock_engine

        with patch('src.monitoring.collector.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session
            # Should not raise
            await database_collector.collect()
