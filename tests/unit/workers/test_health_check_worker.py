"""
Unit tests for health check worker.
Tests device health monitoring, interface checks, routing checks, and alerting.
"""

import pytest
from datetime import datetime, timedelta
from uuid import UUID, uuid4
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, Any

from src.workers.health_check_worker import HealthCheckWorker, HealthStatus
from src.workers.base import WorkerTask
from src.db.models import Device, HealthCheck, Alert
from src.core.exceptions import HealthCheckError


@pytest.fixture
def worker():
    """Create health check worker instance."""
    with patch('src.workers.health_check_worker.SecureDeviceConnector'), \
         patch('src.workers.health_check_worker.AuditLogger'):
        worker = HealthCheckWorker()
        worker.audit.log_event = AsyncMock()
        return worker


@pytest.fixture
def sample_device():
    """Sample device object."""
    device = Mock(spec=Device)
    device.id = uuid4()
    device.hostname = 'router-01'
    device.vendor = 'cisco'
    device.model = 'ISR4451'
    device.is_active = True
    device.health_status = 'healthy'
    device.last_health_check = None
    return device


class TestHealthCheckWorkerInitialization:
    """Test health check worker initialization."""

    def test_worker_initialization(self, worker):
        """Test worker initializes correctly."""
        assert worker.get_worker_type() == "health_check"
        assert hasattr(worker, 'device_connector')
        assert hasattr(worker, 'audit')
        assert hasattr(worker, 'thresholds')

    def test_thresholds_configured(self, worker):
        """Test health check thresholds are configured."""
        assert 'cpu_usage' in worker.thresholds
        assert 'memory_usage' in worker.thresholds
        assert 'disk_usage' in worker.thresholds
        assert 'interface_errors' in worker.thresholds
        assert 'packet_loss' in worker.thresholds
        assert 'latency_ms' in worker.thresholds

        # Check threshold structure
        assert 'warning' in worker.thresholds['cpu_usage']
        assert 'critical' in worker.thresholds['cpu_usage']

    def test_health_status_enum(self):
        """Test HealthStatus enum values."""
        assert HealthStatus.HEALTHY.value == "healthy"
        assert HealthStatus.DEGRADED.value == "degraded"
        assert HealthStatus.UNHEALTHY.value == "unhealthy"
        assert HealthStatus.CRITICAL.value == "critical"
        assert HealthStatus.UNKNOWN.value == "unknown"


class TestProcessTask:
    """Test task processing."""

    @pytest.mark.asyncio
    async def test_process_device_health_check_task(self, worker):
        """Test processing device health check task."""
        task = Mock(spec=WorkerTask)
        task.task_type = "device_health_check"
        task.payload = {
            'device_id': str(uuid4()),
            'check_type': 'full'
        }

        worker._device_health_check = AsyncMock(return_value={'status': 'success', 'health_status': 'healthy'})

        result = await worker.process_task(task)

        assert result['status'] == 'success'
        assert result['health_status'] == 'healthy'

    @pytest.mark.asyncio
    async def test_process_batch_health_check_task(self, worker):
        """Test processing batch health check task."""
        task = Mock(spec=WorkerTask)
        task.task_type = "batch_health_check"
        task.payload = {
            'device_ids': [str(uuid4()) for _ in range(5)],
            'check_type': 'basic'
        }

        worker._batch_health_check = AsyncMock(return_value={'status': 'completed', 'healthy': 5})

        result = await worker.process_task(task)

        assert result['status'] == 'completed'

    @pytest.mark.asyncio
    async def test_process_interface_health_check_task(self, worker):
        """Test processing interface health check task."""
        task = Mock(spec=WorkerTask)
        task.task_type = "interface_health_check"
        task.payload = {
            'device_id': str(uuid4()),
            'interfaces': ['GigabitEthernet0/0', 'GigabitEthernet0/1']
        }

        worker._interface_health_check = AsyncMock(return_value={'status': 'success'})

        result = await worker.process_task(task)

        assert result['status'] == 'success'

    @pytest.mark.asyncio
    async def test_process_routing_health_check_task(self, worker):
        """Test processing routing health check task."""
        task = Mock(spec=WorkerTask)
        task.task_type = "routing_health_check"
        task.payload = {'device_id': str(uuid4())}

        worker._routing_health_check = AsyncMock(return_value={'status': 'success', 'health_status': 'healthy'})

        result = await worker.process_task(task)

        assert result['status'] == 'success'

    @pytest.mark.asyncio
    async def test_process_service_health_check_task(self, worker):
        """Test processing service health check task."""
        task = Mock(spec=WorkerTask)
        task.task_type = "service_health_check"
        task.payload = {
            'device_id': str(uuid4()),
            'services': ['ssh', 'snmp', 'ntp']
        }

        worker._service_health_check = AsyncMock(return_value={'status': 'success', 'running': 3})

        result = await worker.process_task(task)

        assert result['status'] == 'success'

    @pytest.mark.asyncio
    async def test_process_connectivity_check_task(self, worker):
        """Test processing connectivity check task."""
        task = Mock(spec=WorkerTask)
        task.task_type = "connectivity_check"
        task.payload = {
            'device_id': str(uuid4()),
            'targets': [
                {'address': '8.8.8.8', 'name': 'Google DNS'},
                {'address': '1.1.1.1', 'name': 'Cloudflare DNS'}
            ]
        }

        worker._connectivity_check = AsyncMock(return_value={'status': 'success', 'reachable': 2})

        result = await worker.process_task(task)

        assert result['status'] == 'success'

    @pytest.mark.asyncio
    async def test_process_unknown_task_type_raises_error(self, worker):
        """Test unknown task type raises ValueError."""
        task = Mock(spec=WorkerTask)
        task.task_type = "unknown_task"
        task.payload = {}

        with pytest.raises(ValueError, match="Unknown task type"):
            await worker.process_task(task)


class TestDeviceHealthCheck:
    """Test device health check operations."""

    @pytest.mark.asyncio
    async def test_device_health_check_full(self, worker, sample_device):
        """Test full device health check."""
        payload = {
            'device_id': str(sample_device.id),
            'check_type': 'full'
        }

        mock_connection = AsyncMock()
        worker.device_connector.connect_to_device = AsyncMock(return_value=mock_connection)

        worker._check_resources = AsyncMock(return_value={'cpu_usage': 30, 'memory_usage': 50, 'issues': []})
        worker._check_interfaces = AsyncMock(return_value={'total': 10, 'up': 9, 'down': 1})
        worker._check_routing = AsyncMock(return_value={'routes_total': 1000, 'bgp_established': 5})
        worker._check_services = AsyncMock(return_value={'ssh': True, 'snmp': True})
        worker._check_configuration = AsyncMock(return_value={'unsaved_changes': False})
        worker._generate_alerts = AsyncMock(return_value=[])

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=sample_device)
        mock_db.add = Mock()
        mock_db.commit = AsyncMock()

        with patch('src.workers.health_check_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())), \
             patch('src.workers.health_check_worker.HealthCheck'):

            result = await worker._device_health_check(payload)

        assert result['status'] == 'success'
        assert 'health_status' in result
        assert 'health_data' in result

    @pytest.mark.asyncio
    async def test_device_health_check_resources_only(self, worker, sample_device):
        """Test health check for resources only."""
        payload = {
            'device_id': str(sample_device.id),
            'check_type': 'resources'
        }

        mock_connection = AsyncMock()
        worker.device_connector.connect_to_device = AsyncMock(return_value=mock_connection)

        worker._check_resources = AsyncMock(return_value={'cpu_usage': 25, 'issues': []})
        worker._generate_alerts = AsyncMock(return_value=[])

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=sample_device)
        mock_db.add = Mock()
        mock_db.commit = AsyncMock()

        with patch('src.workers.health_check_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())), \
             patch('src.workers.health_check_worker.HealthCheck'):

            result = await worker._device_health_check(payload)

        assert 'resources' in result['health_data']
        assert 'interfaces' not in result['health_data']

    @pytest.mark.asyncio
    async def test_device_health_check_generates_alerts(self, worker, sample_device):
        """Test health check generates alerts on issues."""
        payload = {
            'device_id': str(sample_device.id),
            'check_type': 'full'
        }

        mock_connection = AsyncMock()
        worker.device_connector.connect_to_device = AsyncMock(return_value=mock_connection)

        # High CPU usage should trigger alert
        worker._check_resources = AsyncMock(return_value={
            'cpu_usage': 95,  # Critical
            'memory_usage': 60,
            'issues': ['Critical CPU usage: 95%']
        })
        worker._check_interfaces = AsyncMock(return_value={'total': 10, 'up': 10})
        worker._check_routing = AsyncMock(return_value={})
        worker._check_services = AsyncMock(return_value={'ssh': True})
        worker._check_configuration = AsyncMock(return_value={})

        mock_alert = Mock(spec=Alert)
        worker._generate_alerts = AsyncMock(return_value=[mock_alert])

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=sample_device)
        mock_db.add = Mock()
        mock_db.commit = AsyncMock()

        with patch('src.workers.health_check_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())), \
             patch('src.workers.health_check_worker.HealthCheck'):

            result = await worker._device_health_check(payload)

        assert result['alerts'] > 0

    @pytest.mark.asyncio
    async def test_device_health_check_not_found(self, worker):
        """Test health check with non-existent device."""
        payload = {
            'device_id': str(uuid4()),
            'check_type': 'full'
        }

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=None)

        with patch('src.workers.health_check_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())):
            with pytest.raises(HealthCheckError, match="not found"):
                await worker._device_health_check(payload)


class TestBatchHealthCheck:
    """Test batch health check operations."""

    @pytest.mark.asyncio
    async def test_batch_health_check_all_healthy(self, worker):
        """Test batch health check with all healthy devices."""
        device_ids = [str(uuid4()) for _ in range(5)]

        payload = {
            'device_ids': device_ids,
            'check_type': 'basic'
        }

        worker._device_health_check = AsyncMock(return_value={
            'status': 'success',
            'health_status': 'healthy'
        })

        result = await worker._batch_health_check(payload)

        assert result['status'] == 'completed'
        assert result['healthy'] == 5
        assert result['unhealthy'] == 0
        assert result['failed'] == 0

    @pytest.mark.asyncio
    async def test_batch_health_check_mixed_results(self, worker):
        """Test batch health check with mixed health statuses."""
        device_ids = [str(uuid4()) for _ in range(6)]

        payload = {
            'device_ids': device_ids,
            'check_type': 'basic'
        }

        # Mix of healthy, unhealthy, and failed
        results = [
            {'status': 'success', 'health_status': 'healthy'},
            {'status': 'success', 'health_status': 'healthy'},
            {'status': 'success', 'health_status': 'unhealthy'},
            {'status': 'success', 'health_status': 'critical'},
            Exception("Check failed"),
            {'status': 'success', 'health_status': 'healthy'}
        ]

        worker._device_health_check = AsyncMock(side_effect=results)

        result = await worker._batch_health_check(payload)

        assert result['status'] == 'completed'
        assert result['healthy'] + result['unhealthy'] + result['failed'] == result['total']

    @pytest.mark.asyncio
    async def test_batch_health_check_processes_in_batches(self, worker):
        """Test batch processes devices in batches of 10."""
        device_ids = [str(uuid4()) for _ in range(25)]

        payload = {
            'device_ids': device_ids,
            'check_type': 'basic'
        }

        worker._device_health_check = AsyncMock(return_value={
            'status': 'success',
            'health_status': 'healthy'
        })

        result = await worker._batch_health_check(payload)

        assert result['total'] == 25


class TestInterfaceHealthCheck:
    """Test interface health check operations."""

    @pytest.mark.asyncio
    async def test_interface_health_check_all_healthy(self, worker):
        """Test interface check with healthy interfaces."""
        device_id = uuid4()
        interfaces = ['GigabitEthernet0/0', 'GigabitEthernet0/1']

        payload = {
            'device_id': str(device_id),
            'interfaces': interfaces
        }

        mock_connection = AsyncMock()
        mock_connection.get_interface_stats = AsyncMock(return_value={
            'state': 'up',
            'speed': '1000',
            'errors_in': 0,
            'errors_out': 0,
            'utilization_in': 30,
            'utilization_out': 25
        })

        worker.device_connector.connect_to_device = AsyncMock(return_value=mock_connection)

        result = await worker._interface_health_check(payload)

        assert result['status'] == 'success'
        assert len(result['interfaces']) == 2
        assert all(i['status'] == 'healthy' for i in result['interfaces'])

    @pytest.mark.asyncio
    async def test_interface_health_check_high_errors(self, worker):
        """Test interface check detects high errors."""
        device_id = uuid4()
        interfaces = ['GigabitEthernet0/0']

        payload = {
            'device_id': str(device_id),
            'interfaces': interfaces
        }

        mock_connection = AsyncMock()
        mock_connection.get_interface_stats = AsyncMock(return_value={
            'state': 'up',
            'speed': '1000',
            'errors_in': 2000,  # Above critical threshold
            'errors_out': 50,
            'utilization_in': 40,
            'utilization_out': 30
        })

        worker.device_connector.connect_to_device = AsyncMock(return_value=mock_connection)

        result = await worker._interface_health_check(payload)

        assert result['status'] == 'success'
        assert result['interfaces'][0]['status'] == 'critical'
        assert len(result['interfaces'][0]['issues']) > 0


class TestRoutingHealthCheck:
    """Test routing health check operations."""

    @pytest.mark.asyncio
    async def test_routing_health_check_all_established(self, worker):
        """Test routing check with all sessions established."""
        device_id = uuid4()

        payload = {'device_id': str(device_id)}

        bgp_sessions = [
            {'peer': '192.168.1.1', 'state': 'Established'},
            {'peer': '192.168.1.2', 'state': 'Established'}
        ]

        ospf_neighbors = [
            {'neighbor': '10.0.0.1', 'state': 'Full'},
            {'neighbor': '10.0.0.2', 'state': 'Full'}
        ]

        mock_connection = AsyncMock()
        mock_connection.get_bgp_sessions = AsyncMock(return_value=bgp_sessions)
        mock_connection.get_ospf_neighbors = AsyncMock(return_value=ospf_neighbors)

        worker.device_connector.connect_to_device = AsyncMock(return_value=mock_connection)

        result = await worker._routing_health_check(payload)

        assert result['status'] == 'success'
        assert result['health_status'] == 'healthy'
        assert result['routing']['bgp']['established'] == 2
        assert result['routing']['ospf']['full'] == 2

    @pytest.mark.asyncio
    async def test_routing_health_check_bgp_down(self, worker):
        """Test routing check detects BGP sessions down."""
        device_id = uuid4()

        payload = {'device_id': str(device_id)}

        bgp_sessions = [
            {'peer': '192.168.1.1', 'state': 'Idle'},
            {'peer': '192.168.1.2', 'state': 'Established'}
        ]

        ospf_neighbors = []

        mock_connection = AsyncMock()
        mock_connection.get_bgp_sessions = AsyncMock(return_value=bgp_sessions)
        mock_connection.get_ospf_neighbors = AsyncMock(return_value=ospf_neighbors)

        worker.device_connector.connect_to_device = AsyncMock(return_value=mock_connection)

        result = await worker._routing_health_check(payload)

        assert result['status'] == 'success'
        assert result['health_status'] in ['degraded', 'critical']
        assert result['routing']['bgp']['down'] > 0


class TestServiceHealthCheck:
    """Test service health check operations."""

    @pytest.mark.asyncio
    async def test_service_health_check_all_running(self, worker):
        """Test service check with all services running."""
        device_id = uuid4()
        services = ['ssh', 'snmp', 'ntp']

        payload = {
            'device_id': str(device_id),
            'services': services
        }

        mock_connection = AsyncMock()
        mock_connection.check_service = AsyncMock(return_value={
            'running': True,
            'port': 22,
            'pid': 1234,
            'memory_usage': 50,
            'cpu_usage': 2
        })

        worker.device_connector.connect_to_device = AsyncMock(return_value=mock_connection)

        result = await worker._service_health_check(payload)

        assert result['status'] == 'success'
        assert result['health_status'] == 'healthy'
        assert result['running'] == 3
        assert all(s['running'] for s in result['services'])

    @pytest.mark.asyncio
    async def test_service_health_check_some_down(self, worker):
        """Test service check detects down services."""
        device_id = uuid4()
        services = ['ssh', 'snmp', 'ntp']

        payload = {
            'device_id': str(device_id),
            'services': services
        }

        mock_connection = AsyncMock()

        # SSH running, SNMP and NTP down
        service_results = [
            {'running': True, 'port': 22},
            {'running': False},
            {'running': False}
        ]

        mock_connection.check_service = AsyncMock(side_effect=service_results)
        worker.device_connector.connect_to_device = AsyncMock(return_value=mock_connection)

        result = await worker._service_health_check(payload)

        assert result['status'] == 'success'
        assert result['health_status'] == 'degraded'
        assert result['running'] < result['total']


class TestConnectivityCheck:
    """Test connectivity check operations."""

    @pytest.mark.asyncio
    async def test_connectivity_check_all_reachable(self, worker):
        """Test connectivity check with all targets reachable."""
        device_id = uuid4()
        targets = [
            {'address': '8.8.8.8', 'name': 'Google DNS'},
            {'address': '1.1.1.1', 'name': 'Cloudflare DNS'}
        ]

        payload = {
            'device_id': str(device_id),
            'targets': targets
        }

        mock_connection = AsyncMock()
        mock_connection.ping = AsyncMock(return_value={
            'packet_loss': 0,
            'avg_latency': 10,
            'min_latency': 8,
            'max_latency': 15
        })

        worker.device_connector.connect_to_device = AsyncMock(return_value=mock_connection)

        result = await worker._connectivity_check(payload)

        assert result['status'] == 'success'
        assert result['health_status'] == 'healthy'
        assert result['reachable'] == 2
        assert result['unreachable'] == 0

    @pytest.mark.asyncio
    async def test_connectivity_check_high_packet_loss(self, worker):
        """Test connectivity check detects high packet loss."""
        device_id = uuid4()
        targets = [{'address': '8.8.8.8'}]

        payload = {
            'device_id': str(device_id),
            'targets': targets
        }

        mock_connection = AsyncMock()
        mock_connection.ping = AsyncMock(return_value={
            'packet_loss': 10,  # Above critical threshold
            'avg_latency': 50,
            'min_latency': 40,
            'max_latency': 60
        })

        worker.device_connector.connect_to_device = AsyncMock(return_value=mock_connection)

        result = await worker._connectivity_check(payload)

        assert result['connectivity'][0]['health_status'] == 'critical'

    @pytest.mark.asyncio
    async def test_connectivity_check_unreachable_target(self, worker):
        """Test connectivity check with unreachable target."""
        device_id = uuid4()
        targets = [{'address': '192.0.2.1'}]  # TEST-NET-1 (should be unreachable)

        payload = {
            'device_id': str(device_id),
            'targets': targets
        }

        mock_connection = AsyncMock()
        mock_connection.ping = AsyncMock(return_value={
            'packet_loss': 100,
            'avg_latency': 0,
            'min_latency': 0,
            'max_latency': 0
        })

        worker.device_connector.connect_to_device = AsyncMock(return_value=mock_connection)

        result = await worker._connectivity_check(payload)

        assert result['unreachable'] == 1
        assert not result['connectivity'][0]['reachable']


class TestCalculateOverallStatus:
    """Test overall health status calculation."""

    def test_calculate_status_healthy(self, worker):
        """Test calculation of healthy status."""
        health_data = {
            'resources': {'cpu_usage': 30, 'memory_usage': 40, 'issues': []},
            'interfaces': {'total': 10, 'up': 10, 'down': 0, 'errors': 0},
            'routing': {'bgp_sessions': 5, 'bgp_established': 5},
            'services': {'ssh': True, 'snmp': True}
        }

        status = worker._calculate_overall_status(health_data)

        assert status == HealthStatus.HEALTHY

    def test_calculate_status_critical_cpu(self, worker):
        """Test calculation detects critical CPU usage."""
        health_data = {
            'resources': {
                'cpu_usage': 95,
                'issues': ['Critical CPU usage: 95%']
            }
        }

        status = worker._calculate_overall_status(health_data)

        assert status == HealthStatus.CRITICAL

    def test_calculate_status_degraded_interfaces(self, worker):
        """Test calculation detects degraded interfaces."""
        health_data = {
            'resources': {'issues': []},
            'interfaces': {'total': 10, 'up': 9, 'down': 1, 'errors': 2}
        }

        status = worker._calculate_overall_status(health_data)

        assert status == HealthStatus.DEGRADED

    def test_calculate_status_critical_bgp_down(self, worker):
        """Test calculation detects all BGP sessions down."""
        health_data = {
            'resources': {'issues': []},
            'interfaces': {'down': 0, 'up': 10, 'errors': 0},
            'routing': {'bgp_sessions': 5, 'bgp_established': 0}
        }

        status = worker._calculate_overall_status(health_data)

        assert status == HealthStatus.CRITICAL


class TestGenerateAlerts:
    """Test alert generation."""

    @pytest.mark.asyncio
    async def test_generate_alerts_critical_status(self, worker, sample_device):
        """Test alert generated for critical status."""
        health_data = {
            'resources': {'cpu_usage': 95, 'memory_usage': 90}
        }

        alerts = await worker._generate_alerts(sample_device, health_data, HealthStatus.CRITICAL)

        assert len(alerts) > 0
        assert any(alert.severity == 'critical' for alert in alerts)

    @pytest.mark.asyncio
    async def test_generate_alerts_high_cpu(self, worker, sample_device):
        """Test alert generated for high CPU usage."""
        health_data = {
            'resources': {'cpu_usage': 95, 'memory_usage': 50}
        }

        alerts = await worker._generate_alerts(sample_device, health_data, HealthStatus.DEGRADED)

        assert len(alerts) > 0
        cpu_alerts = [a for a in alerts if 'CPU' in a.title]
        assert len(cpu_alerts) > 0

    @pytest.mark.asyncio
    async def test_generate_alerts_healthy_no_alerts(self, worker, sample_device):
        """Test no alerts generated for healthy status."""
        health_data = {
            'resources': {'cpu_usage': 30, 'memory_usage': 40}
        }

        alerts = await worker._generate_alerts(sample_device, health_data, HealthStatus.HEALTHY)

        # May have 0 alerts or just informational ones
        critical_alerts = [a for a in alerts if a.severity == 'critical']
        assert len(critical_alerts) == 0


class TestCheckHelpers:
    """Test helper check methods."""

    @pytest.mark.asyncio
    async def test_check_resources(self, worker, sample_device):
        """Test resource check helper."""
        mock_connection = AsyncMock()
        mock_connection.get_resource_utilization = AsyncMock(return_value={
            'cpu_usage': 85,  # High
            'memory_usage': 60,
            'disk_usage': 50,
            'temperature': 45,
            'uptime': 86400
        })

        result = await worker._check_resources(mock_connection, sample_device)

        assert 'cpu_usage' in result
        assert 'memory_usage' in result
        assert 'issues' in result
        assert len(result['issues']) > 0  # Should flag high CPU

    @pytest.mark.asyncio
    async def test_check_interfaces(self, worker, sample_device):
        """Test interface check helper."""
        mock_connection = AsyncMock()
        mock_connection.get_interfaces = AsyncMock(return_value=[
            {'name': 'Gi0/0', 'state': 'up', 'errors_in': 0, 'errors_out': 0, 'utilization': 40},
            {'name': 'Gi0/1', 'state': 'up', 'errors_in': 10, 'errors_out': 5, 'utilization': 85},
            {'name': 'Gi0/2', 'state': 'down', 'errors_in': 0, 'errors_out': 0, 'utilization': 0}
        ])

        result = await worker._check_interfaces(mock_connection, sample_device)

        assert result['total'] == 3
        assert result['up'] == 2
        assert result['down'] == 1
        assert result['errors'] == 1  # One interface with errors
        assert result['high_utilization'] == 1

    @pytest.mark.asyncio
    async def test_check_routing(self, worker, sample_device):
        """Test routing check helper."""
        mock_connection = AsyncMock()
        mock_connection.get_routes = AsyncMock(return_value=[{'network': '10.0.0.0/8'}] * 5000)
        mock_connection.get_bgp_sessions = AsyncMock(return_value=[
            {'peer': '192.168.1.1', 'state': 'Established'},
            {'peer': '192.168.1.2', 'state': 'Established'}
        ])
        mock_connection.get_ospf_neighbors = AsyncMock(return_value=[
            {'neighbor': '10.0.0.1', 'state': 'Full'}
        ])

        result = await worker._check_routing(mock_connection, sample_device)

        assert result['routes_total'] == 5000
        assert result['bgp_sessions'] == 2
        assert result['bgp_established'] == 2
        assert result['ospf_neighbors'] == 1
        assert result['ospf_full'] == 1

    @pytest.mark.asyncio
    async def test_check_services(self, worker, sample_device):
        """Test services check helper."""
        mock_connection = AsyncMock()

        service_statuses = {
            'ssh': {'running': True},
            'snmp': {'running': False},
            'ntp': {'running': True},
            'syslog': {'running': True}
        }

        async def mock_check_service(service):
            return service_statuses.get(service, {'running': False})

        mock_connection.check_service = mock_check_service

        result = await worker._check_services(mock_connection, sample_device)

        assert result['ssh'] is True
        assert result['snmp'] is False
        assert result['ntp'] is True
        assert result['syslog'] is True

    @pytest.mark.asyncio
    async def test_check_configuration(self, worker, sample_device):
        """Test configuration check helper."""
        mock_connection = AsyncMock()
        mock_connection.get_config_status = AsyncMock(return_value={
            'last_change': '2025-10-10T10:00:00',
            'unsaved_changes': True,
            'config_size': 50000
        })

        result = await worker._check_configuration(mock_connection, sample_device)

        assert result['last_change'] is not None
        assert result['unsaved_changes'] is True
        assert result['config_size'] == 50000
