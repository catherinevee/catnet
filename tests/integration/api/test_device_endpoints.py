"""
Integration tests for Device API endpoints
Tests device management, connection, and operations
"""

import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch, Mock
import json
from datetime import datetime

from src.api.app import app
from src.db.models import DeviceVendor


@pytest.fixture
async def client():
    """Async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def mock_auth():
    """Mock authentication."""
    with patch('src.api.routes.devices.get_current_user') as mock:
        mock.return_value = {
            'sub': 'user_123',
            'email': 'test@example.com',
            'roles': ['admin']
        }
        yield mock


@pytest.fixture
def mock_device_service():
    """Mock device service."""
    with patch('src.api.routes.devices.device_service') as mock:
        yield mock


@pytest.fixture
def mock_inventory_manager():
    """Mock inventory manager."""
    with patch('src.api.routes.devices.inventory_manager') as mock:
        yield mock


@pytest.fixture
def mock_device_manager():
    """Mock device manager."""
    with patch('src.api.routes.devices.device_manager') as mock:
        yield mock


@pytest.fixture
def sample_device():
    """Sample device data."""
    return {
        'id': 'device_001',
        'hostname': 'router-01',
        'ip_address': '10.0.0.1',
        'vendor': 'cisco',
        'device_type': 'router',
        'model': 'ISR4451',
        'os_version': '16.9.4',
        'site': 'datacenter1',
        'status': 'active',
        'ssh_port': 22,
        'tags': ['production', 'core'],
        'metadata': {},
        'created_at': datetime.utcnow().isoformat(),
        'updated_at': datetime.utcnow().isoformat()
    }


class TestDeviceInventoryEndpoints:
    """Test device inventory management."""

    @pytest.mark.asyncio
    async def test_get_device_inventory(self, client, mock_auth, mock_inventory_manager):
        """Test get device inventory with filters."""
        mock_inventory_manager.get_device_inventory.return_value = {
            'devices': [
                {'id': 'device_001', 'hostname': 'router-01'},
                {'id': 'device_002', 'hostname': 'switch-01'}
            ],
            'total_count': 2,
            'limit': 100,
            'offset': 0
        }

        response = await client.get("/api/devices/?vendor=cisco&site=datacenter1")

        assert response.status_code == 200
        data = response.json()
        assert 'devices' in data
        assert len(data['devices']) == 2

    @pytest.mark.asyncio
    async def test_get_device_inventory_invalid_vendor(self, client, mock_auth):
        """Test get inventory with invalid vendor."""
        response = await client.get("/api/devices/?vendor=invalid_vendor")

        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_get_device_statistics(self, client, mock_auth, mock_inventory_manager):
        """Test get device inventory statistics."""
        mock_stats = Mock()
        mock_stats.total_devices = 150
        mock_stats.by_vendor = {'cisco': 100, 'juniper': 50}
        mock_stats.by_type = {'router': 80, 'switch': 70}
        mock_stats.by_status = {'active': 140, 'maintenance': 10}
        mock_stats.by_site = {'datacenter1': 100, 'datacenter2': 50}
        mock_stats.needs_backup = 15
        mock_stats.stale_devices = 5
        mock_stats.active_connections = 50

        mock_inventory_manager.get_inventory_statistics.return_value = mock_stats

        response = await client.get("/api/devices/statistics")

        assert response.status_code == 200
        data = response.json()
        assert data['total_devices'] == 150
        assert data['by_vendor']['cisco'] == 100
        assert data['active_connections'] == 50

    @pytest.mark.asyncio
    async def test_register_device_success(self, client, mock_auth, mock_inventory_manager):
        """Test successful device registration."""
        mock_inventory_manager.register_device.return_value = 'device_new_001'

        response = await client.post("/api/devices/register", json={
            "hostname": "new-router-01",
            "ip_address": "10.0.0.50",
            "vendor": "cisco",
            "device_type": "router",
            "model": "ISR4451",
            "os_version": "16.9.4",
            "site": "datacenter1",
            "ssh_port": 22,
            "tags": ["production"],
            "metadata": {"location": "rack-01"}
        })

        assert response.status_code == 200
        data = response.json()
        assert data['device_id'] == 'device_new_001'
        assert 'successfully registered' in data['message'].lower()

    @pytest.mark.asyncio
    async def test_register_device_invalid_vendor(self, client, mock_auth):
        """Test device registration with invalid vendor."""
        response = await client.post("/api/devices/register", json={
            "hostname": "new-router-01",
            "ip_address": "10.0.0.50",
            "vendor": "invalid_vendor",
            "device_type": "router"
        })

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_get_device_details(self, client, mock_auth, mock_inventory_manager,
                                     mock_device_service, sample_device):
        """Test get device details."""
        mock_inventory_manager.get_device_inventory.return_value = {
            'devices': [sample_device]
        }
        mock_device_service._get_connection_status.return_value = 'connected'

        response = await client.get("/api/devices/device_001")

        assert response.status_code == 200
        data = response.json()
        assert data['id'] == 'device_001'
        assert data['hostname'] == 'router-01'

    @pytest.mark.asyncio
    async def test_get_device_not_found(self, client, mock_auth, mock_inventory_manager):
        """Test get device that doesn't exist."""
        mock_inventory_manager.get_device_inventory.return_value = {
            'devices': []
        }

        response = await client.get("/api/devices/nonexistent_device")

        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_update_device_success(self, client, mock_auth, mock_inventory_manager):
        """Test successful device update."""
        mock_inventory_manager.update_device.return_value = True

        response = await client.put("/api/devices/device_001", json={
            "hostname": "router-01-updated",
            "os_version": "16.9.5",
            "tags": ["production", "core", "updated"]
        })

        assert response.status_code == 200
        assert 'successfully updated' in response.json()['message'].lower()

    @pytest.mark.asyncio
    async def test_update_device_not_found(self, client, mock_auth, mock_inventory_manager):
        """Test update device that doesn't exist."""
        mock_inventory_manager.update_device.return_value = False

        response = await client.put("/api/devices/nonexistent", json={
            "hostname": "new-hostname"
        })

        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_remove_device_success(self, client, mock_auth, mock_inventory_manager):
        """Test successful device removal."""
        mock_inventory_manager.remove_device.return_value = True

        response = await client.delete("/api/devices/device_001")

        assert response.status_code == 200
        assert 'successfully removed' in response.json()['message'].lower()

    @pytest.mark.asyncio
    async def test_remove_device_force(self, client, mock_auth, mock_inventory_manager):
        """Test force device removal."""
        mock_inventory_manager.remove_device.return_value = True

        response = await client.delete("/api/devices/device_001?force=true")

        assert response.status_code == 200


class TestDeviceConnectionEndpoints:
    """Test device connection operations."""

    @pytest.mark.asyncio
    async def test_connect_to_device_success(self, client, mock_auth, mock_device_service):
        """Test successful device connection."""
        mock_device_service.connect_to_device.return_value = 'connection_123'

        response = await client.post("/api/devices/connect", json={
            "device_id": "device_001",
            "connection_type": "ssh"
        })

        assert response.status_code == 200
        data = response.json()
        assert data['connection_id'] == 'connection_123'
        assert data['status'] == 'connected'

    @pytest.mark.asyncio
    async def test_connect_to_device_connection_error(self, client, mock_auth, mock_device_service):
        """Test device connection error."""
        from src.core.exceptions import DeviceConnectionError
        mock_device_service.connect_to_device.side_effect = DeviceConnectionError("Connection refused")

        response = await client.post("/api/devices/connect", json={
            "device_id": "device_001",
            "connection_type": "ssh"
        })

        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_disconnect_from_device(self, client, mock_auth, mock_device_service):
        """Test device disconnection."""
        mock_device_service.disconnect_device.return_value = True

        response = await client.post("/api/devices/disconnect/device_001")

        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'disconnected'


class TestCommandExecutionEndpoints:
    """Test command execution on devices."""

    @pytest.mark.asyncio
    async def test_execute_command_success(self, client, mock_auth, mock_device_service):
        """Test successful command execution."""
        mock_result = Mock()
        mock_result.command = "show version"
        mock_result.output = "Cisco IOS Software, Version 16.9.4"
        mock_result.success = True
        mock_result.execution_time = 1.234
        mock_result.timestamp = datetime.utcnow()
        mock_result.error = None

        mock_device_service.execute_command.return_value = mock_result

        response = await client.post("/api/devices/execute", json={
            "device_id": "device_001",
            "command": "show version",
            "timeout": 30
        })

        assert response.status_code == 200
        data = response.json()
        assert data['success'] is True
        assert data['command'] == "show version"
        assert "Cisco IOS" in data['output']

    @pytest.mark.asyncio
    async def test_execute_command_permission_denied(self, client, mock_auth, mock_device_service):
        """Test command execution with insufficient permissions."""
        from src.core.exceptions import SecurityError
        mock_device_service.execute_command.side_effect = SecurityError("Permission denied")

        response = await client.post("/api/devices/execute", json={
            "device_id": "device_001",
            "command": "reload"
        })

        assert response.status_code == 403


class TestBackupEndpoints:
    """Test device backup operations."""

    @pytest.mark.asyncio
    async def test_backup_device_success(self, client, mock_auth, mock_device_service):
        """Test successful device backup."""
        mock_device_service.backup_device_config.return_value = 'backup_123'

        response = await client.post("/api/devices/backup", json={
            "device_id": "device_001",
            "backup_type": "running"
        })

        assert response.status_code == 200
        data = response.json()
        assert data['backup_id'] == 'backup_123'
        assert data['status'] == 'completed'

    @pytest.mark.asyncio
    async def test_deploy_configuration_success(self, client, mock_auth, mock_device_manager):
        """Test successful configuration deployment."""
        mock_device_manager.deploy_configuration_to_device.return_value = {
            'success': True,
            'device_id': 'device_001',
            'deployment_time': 5.678,
            'backup_id': 'backup_before_deploy'
        }

        response = await client.post("/api/devices/deploy-config", json={
            "device_id": "device_001",
            "configuration": "hostname new-router-01\n",
            "deployment_method": "merge",
            "backup_first": True
        })

        assert response.status_code == 200
        data = response.json()
        assert data['success'] is True


class TestHealthMonitoringEndpoints:
    """Test device health monitoring."""

    @pytest.mark.asyncio
    async def test_get_device_health(self, client, mock_auth, mock_device_service):
        """Test get device health status."""
        mock_device_service.get_device_health.return_value = {
            'device_id': 'device_001',
            'status': 'healthy',
            'cpu_usage': 25.5,
            'memory_usage': 45.2,
            'uptime': '150 days, 5 hours',
            'interface_status': {
                'up': 10,
                'down': 0
            }
        }

        response = await client.get("/api/devices/device_001/health")

        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'healthy'
        assert 'cpu_usage' in data

    @pytest.mark.asyncio
    async def test_bulk_health_check(self, client, mock_auth, mock_device_manager):
        """Test bulk health check on multiple devices."""
        mock_device_manager.perform_device_health_checks.return_value = {
            'device_001': {'status': 'healthy', 'checks_passed': 5},
            'device_002': {'status': 'warning', 'checks_passed': 4},
            'device_003': {'status': 'critical', 'checks_passed': 2}
        }

        response = await client.post("/api/devices/health-check", json={
            "device_ids": ["device_001", "device_002", "device_003"],
            "operation": "health_check"
        })

        assert response.status_code == 200
        data = response.json()
        assert data['operation'] == 'health_check'
        assert data['device_count'] == 3


class TestDiscoveryEndpoints:
    """Test device discovery operations."""

    @pytest.mark.asyncio
    async def test_discover_devices_success(self, client, mock_auth, mock_inventory_manager):
        """Test successful device discovery."""
        mock_inventory_manager.discover_devices.return_value = {
            'discovered_count': 5,
            'devices': [
                {'ip': '10.0.0.10', 'hostname': 'router-01', 'vendor': 'cisco'},
                {'ip': '10.0.0.11', 'hostname': 'router-02', 'vendor': 'cisco'},
                {'ip': '10.0.0.12', 'hostname': 'switch-01', 'vendor': 'juniper'}
            ],
            'discovery_time': 45.6
        }

        response = await client.post("/api/devices/discover", json={
            "ip_range": "10.0.0.0/24",
            "discovery_method": "ping_sweep"
        })

        assert response.status_code == 200
        data = response.json()
        assert data['discovered_count'] == 5
        assert len(data['devices']) == 3

    @pytest.mark.asyncio
    async def test_discover_devices_invalid_range(self, client, mock_auth, mock_inventory_manager):
        """Test device discovery with invalid IP range."""
        from src.core.exceptions import ValidationError
        mock_inventory_manager.discover_devices.side_effect = ValidationError("Invalid IP range")

        response = await client.post("/api/devices/discover", json={
            "ip_range": "invalid_range",
            "discovery_method": "ping_sweep"
        })

        assert response.status_code == 400


class TestBulkOperationsEndpoints:
    """Test bulk device operations."""

    @pytest.mark.asyncio
    async def test_bulk_backup_operation(self, client, mock_auth, mock_device_service):
        """Test bulk backup operation."""
        async def mock_backup(device_id, user_context, backup_type):
            if device_id == "device_001":
                return "backup_001"
            elif device_id == "device_002":
                return "backup_002"
            else:
                raise Exception("Backup failed")

        mock_device_service.backup_device_config.side_effect = mock_backup

        response = await client.post("/api/devices/bulk-operations", json={
            "device_ids": ["device_001", "device_002", "device_003"],
            "operation": "backup",
            "parameters": {"backup_type": "running"}
        })

        assert response.status_code == 200
        data = response.json()
        assert data['operation'] == 'backup'
        assert data['device_count'] == 3
        assert data['results']['device_001']['success'] is True
        assert data['results']['device_003']['success'] is False

    @pytest.mark.asyncio
    async def test_bulk_connect_operation(self, client, mock_auth, mock_device_manager):
        """Test bulk connect operation."""
        mock_device_manager.initialize_device_pool.return_value = {
            'device_001': True,
            'device_002': True,
            'device_003': False
        }

        response = await client.post("/api/devices/bulk-operations", json={
            "device_ids": ["device_001", "device_002", "device_003"],
            "operation": "connect"
        })

        assert response.status_code == 200
        data = response.json()
        assert data['operation'] == 'connect'
        assert data['results']['device_001']['success'] is True

    @pytest.mark.asyncio
    async def test_bulk_operation_unsupported(self, client, mock_auth):
        """Test unsupported bulk operation."""
        response = await client.post("/api/devices/bulk-operations", json={
            "device_ids": ["device_001"],
            "operation": "unsupported_operation"
        })

        assert response.status_code == 400
