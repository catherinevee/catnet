"""
Integration tests for Deployment API endpoints
Tests deployment creation, execution, scheduling, and management
"""

import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch, Mock
import json
from datetime import datetime, timedelta

from src.api.app import app
from src.db.models import DeploymentStrategy


@pytest.fixture
async def client():
    """Async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def mock_auth():
    """Mock authentication."""
    with patch('src.api.routes.deployments.get_current_user') as mock:
        mock.return_value = {
            'sub': 'user_123',
            'email': 'test@example.com',
            'roles': ['operator']
        }
        yield mock


@pytest.fixture
def mock_deployment_service():
    """Mock deployment service."""
    with patch('src.api.routes.deployments.deployment_service') as mock:
        yield mock


@pytest.fixture
def mock_deployment_scheduler():
    """Mock deployment scheduler."""
    with patch('src.api.routes.deployments.deployment_scheduler') as mock:
        yield mock


@pytest.fixture
def mock_audit():
    """Mock audit logger."""
    with patch('src.api.routes.deployments.audit') as mock:
        yield mock


@pytest.fixture
def sample_deployment_request():
    """Sample deployment request."""
    return {
        "configuration_content": "hostname router-01\ninterface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n",
        "target_devices": ["device_001", "device_002", "device_003"],
        "deployment_strategy": "rolling",
        "deployment_method": "merge",
        "require_approval": False,
        "backup_before_deploy": True,
        "auto_rollback_on_failure": True,
        "rollback_timeout_minutes": 15,
        "metadata": {"change_ticket": "CHG0001234"}
    }


class TestCreateDeploymentEndpoint:
    """Test deployment creation."""

    @pytest.mark.asyncio
    async def test_create_deployment_success(self, client, mock_auth, mock_deployment_service,
                                            sample_deployment_request):
        """Test successful deployment creation."""
        mock_deployment_service.create_deployment.return_value = 'deployment_001'

        response = await client.post("/api/deployments/", json=sample_deployment_request)

        assert response.status_code == 200
        data = response.json()
        assert data['deployment_id'] == 'deployment_001'
        assert data['status'] == 'pending'
        assert data['strategy'] == 'rolling'
        assert len(data['target_devices']) == 3

    @pytest.mark.asyncio
    async def test_create_deployment_invalid_strategy(self, client, mock_auth, sample_deployment_request):
        """Test deployment creation with invalid strategy."""
        sample_deployment_request['deployment_strategy'] = 'invalid_strategy'

        response = await client.post("/api/deployments/", json=sample_deployment_request)

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_create_deployment_invalid_method(self, client, mock_auth, sample_deployment_request):
        """Test deployment creation with invalid method."""
        sample_deployment_request['deployment_method'] = 'invalid_method'

        response = await client.post("/api/deployments/", json=sample_deployment_request)

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_create_deployment_validation_error(self, client, mock_auth, mock_deployment_service,
                                                     sample_deployment_request):
        """Test deployment creation with validation error."""
        from src.core.exceptions import ValidationError
        mock_deployment_service.create_deployment.side_effect = ValidationError("Invalid configuration")

        response = await client.post("/api/deployments/", json=sample_deployment_request)

        assert response.status_code == 400


class TestScheduleDeploymentEndpoint:
    """Test deployment scheduling."""

    @pytest.mark.asyncio
    async def test_schedule_deployment_success(self, client, mock_auth, mock_deployment_scheduler,
                                              sample_deployment_request):
        """Test successful deployment scheduling."""
        mock_deployment_scheduler.schedule_deployment.return_value = 'schedule_001'

        scheduled_time = (datetime.utcnow() + timedelta(hours=2)).isoformat()

        response = await client.post("/api/deployments/schedule", json={
            "deployment_request": sample_deployment_request,
            "scheduled_time": scheduled_time,
            "priority": "normal",
            "dependencies": [],
            "tags": ["maintenance"],
            "max_retries": 3,
            "timeout_minutes": 240
        })

        assert response.status_code == 200
        data = response.json()
        assert data['schedule_id'] == 'schedule_001'
        assert data['priority'] == 'normal'
        assert data['status'] == 'scheduled'

    @pytest.mark.asyncio
    async def test_schedule_deployment_immediate(self, client, mock_auth, mock_deployment_scheduler,
                                                sample_deployment_request):
        """Test scheduling deployment without specific time (immediate)."""
        mock_deployment_scheduler.schedule_deployment.return_value = 'schedule_002'

        response = await client.post("/api/deployments/schedule", json={
            "deployment_request": sample_deployment_request,
            "priority": "high",
            "tags": ["urgent"],
            "max_retries": 5
        })

        assert response.status_code == 200
        data = response.json()
        assert data['priority'] == 'high'

    @pytest.mark.asyncio
    async def test_schedule_deployment_invalid_priority(self, client, mock_auth, sample_deployment_request):
        """Test scheduling with invalid priority."""
        response = await client.post("/api/deployments/schedule", json={
            "deployment_request": sample_deployment_request,
            "priority": "invalid_priority"
        })

        assert response.status_code == 422


class TestExecuteDeploymentEndpoint:
    """Test deployment execution."""

    @pytest.mark.asyncio
    async def test_execute_deployment_success(self, client, mock_auth, mock_deployment_service):
        """Test successful deployment execution."""
        mock_result = Mock()
        mock_result.success = True
        mock_result.devices_affected = 3
        mock_result.deployment_duration = 45.6
        mock_result.details = {
            'device_001': {'status': 'success'},
            'device_002': {'status': 'success'},
            'device_003': {'status': 'success'}
        }

        mock_deployment_service.execute_deployment.return_value = mock_result

        response = await client.post("/api/deployments/deployment_001/execute")

        assert response.status_code == 200
        data = response.json()
        assert data['success'] is True
        assert data['devices_affected'] == 3
        assert data['deployment_duration'] == 45.6

    @pytest.mark.asyncio
    async def test_execute_deployment_partial_failure(self, client, mock_auth, mock_deployment_service):
        """Test deployment execution with partial failure."""
        mock_result = Mock()
        mock_result.success = False
        mock_result.devices_affected = 2
        mock_result.deployment_duration = 30.2
        mock_result.details = {
            'device_001': {'status': 'success'},
            'device_002': {'status': 'success'},
            'device_003': {'status': 'failed', 'error': 'Connection timeout'}
        }

        mock_deployment_service.execute_deployment.return_value = mock_result

        response = await client.post("/api/deployments/deployment_001/execute")

        assert response.status_code == 200
        data = response.json()
        assert data['success'] is False
        assert data['devices_affected'] == 2

    @pytest.mark.asyncio
    async def test_execute_deployment_not_found(self, client, mock_auth, mock_deployment_service):
        """Test executing nonexistent deployment."""
        from src.core.exceptions import DeploymentError
        mock_deployment_service.execute_deployment.side_effect = DeploymentError("Deployment not found")

        response = await client.post("/api/deployments/nonexistent/execute")

        assert response.status_code == 400


class TestApproveDeploymentEndpoint:
    """Test deployment approval."""

    @pytest.mark.asyncio
    async def test_approve_deployment_success(self, client, mock_auth, mock_deployment_service, mock_audit):
        """Test successful deployment approval and execution."""
        mock_result = Mock()
        mock_result.success = True
        mock_result.devices_affected = 5
        mock_result.deployment_duration = 60.0

        mock_deployment_service.execute_deployment.return_value = mock_result
        mock_audit.log_deployment_approval = AsyncMock()

        response = await client.post("/api/deployments/deployment_001/approve", json={
            "approved": True,
            "comments": "Looks good, approved for deployment"
        })

        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'approved_and_executed'
        assert data['execution_result']['success'] is True

    @pytest.mark.asyncio
    async def test_reject_deployment(self, client, mock_auth, mock_audit):
        """Test deployment rejection."""
        mock_audit.log_deployment_approval = AsyncMock()

        response = await client.post("/api/deployments/deployment_001/approve", json={
            "approved": False,
            "comments": "Configuration needs review"
        })

        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'rejected'
        assert 'needs review' in data['comments']


class TestRollbackDeploymentEndpoint:
    """Test deployment rollback."""

    @pytest.mark.asyncio
    async def test_rollback_deployment_success(self, client, mock_auth, mock_deployment_service):
        """Test successful deployment rollback."""
        mock_deployment_service.rollback_deployment.return_value = True

        response = await client.post("/api/deployments/deployment_001/rollback")

        assert response.status_code == 200
        data = response.json()
        assert data['rollback_success'] is True
        assert data['status'] == 'rolled_back'

    @pytest.mark.asyncio
    async def test_rollback_deployment_failed(self, client, mock_auth, mock_deployment_service):
        """Test failed deployment rollback."""
        mock_deployment_service.rollback_deployment.return_value = False

        response = await client.post("/api/deployments/deployment_001/rollback")

        assert response.status_code == 200
        data = response.json()
        assert data['rollback_success'] is False
        assert data['status'] == 'rollback_failed'

    @pytest.mark.asyncio
    async def test_rollback_deployment_force(self, client, mock_auth, mock_deployment_service):
        """Test force rollback deployment."""
        mock_deployment_service.rollback_deployment.return_value = True

        response = await client.post("/api/deployments/deployment_001/rollback?force=true")

        assert response.status_code == 200


class TestGetDeploymentStatusEndpoint:
    """Test deployment status retrieval."""

    @pytest.mark.asyncio
    async def test_get_deployment_status_success(self, client, mock_auth, mock_deployment_service):
        """Test get deployment status."""
        mock_deployment_service.get_deployment_status.return_value = {
            'deployment_id': 'deployment_001',
            'status': 'completed',
            'strategy': 'rolling',
            'target_devices': ['device_001', 'device_002'],
            'devices_completed': 2,
            'devices_failed': 0,
            'started_at': datetime.utcnow().isoformat(),
            'completed_at': datetime.utcnow().isoformat(),
            'duration': 45.6,
            'rollback_available': True
        }

        response = await client.get("/api/deployments/deployment_001")

        assert response.status_code == 200
        data = response.json()
        assert data['deployment_id'] == 'deployment_001'
        assert data['status'] == 'completed'
        assert data['rollback_available'] is True

    @pytest.mark.asyncio
    async def test_get_deployment_status_not_found(self, client, mock_auth, mock_deployment_service):
        """Test get status for nonexistent deployment."""
        from src.core.exceptions import DeploymentError
        mock_deployment_service.get_deployment_status.side_effect = DeploymentError("Deployment not found")

        response = await client.get("/api/deployments/nonexistent")

        assert response.status_code == 400


class TestListDeploymentsEndpoint:
    """Test listing deployments."""

    @pytest.mark.asyncio
    async def test_list_deployments_no_filters(self, client, mock_auth):
        """Test list deployments without filters."""
        response = await client.get("/api/deployments/")

        assert response.status_code == 200
        data = response.json()
        assert 'deployments' in data
        assert 'pagination' in data

    @pytest.mark.asyncio
    async def test_list_deployments_with_filters(self, client, mock_auth):
        """Test list deployments with filters."""
        response = await client.get("/api/deployments/?status_filter=completed&strategy_filter=rolling&limit=20")

        assert response.status_code == 200
        data = response.json()
        assert data['filters']['status'] == 'completed'
        assert data['filters']['strategy'] == 'rolling'
        assert data['pagination']['limit'] == 20


class TestScheduledDeploymentEndpoints:
    """Test scheduled deployment management."""

    @pytest.mark.asyncio
    async def test_list_scheduled_deployments(self, client, mock_auth, mock_deployment_scheduler):
        """Test list scheduled deployments."""
        mock_deployment_scheduler.list_scheduled_deployments.return_value = [
            {
                'schedule_id': 'schedule_001',
                'scheduled_time': datetime.utcnow().isoformat(),
                'priority': 'normal',
                'status': 'pending',
                'tags': ['maintenance']
            },
            {
                'schedule_id': 'schedule_002',
                'scheduled_time': (datetime.utcnow() + timedelta(hours=2)).isoformat(),
                'priority': 'high',
                'status': 'pending',
                'tags': ['urgent']
            }
        ]

        response = await client.get("/api/deployments/scheduled/")

        assert response.status_code == 200
        data = response.json()
        assert 'scheduled_deployments' in data
        assert data['count'] == 2

    @pytest.mark.asyncio
    async def test_list_scheduled_deployments_with_filters(self, client, mock_auth, mock_deployment_scheduler):
        """Test list scheduled deployments with filters."""
        mock_deployment_scheduler.list_scheduled_deployments.return_value = [
            {
                'schedule_id': 'schedule_001',
                'priority': 'high',
                'status': 'pending'
            }
        ]

        response = await client.get("/api/deployments/scheduled/?status_filter=pending&priority_filter=high")

        assert response.status_code == 200
        data = response.json()
        assert data['count'] == 1

    @pytest.mark.asyncio
    async def test_list_scheduled_deployments_invalid_filter(self, client, mock_auth):
        """Test list scheduled deployments with invalid filter."""
        response = await client.get("/api/deployments/scheduled/?status_filter=invalid_status")

        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_get_scheduled_deployment_status(self, client, mock_auth, mock_deployment_scheduler):
        """Test get scheduled deployment status."""
        mock_deployment_scheduler.get_schedule_status.return_value = {
            'schedule_id': 'schedule_001',
            'scheduled_time': datetime.utcnow().isoformat(),
            'status': 'pending',
            'priority': 'normal',
            'dependencies': [],
            'tags': ['maintenance'],
            'retries_remaining': 3
        }

        response = await client.get("/api/deployments/scheduled/schedule_001")

        assert response.status_code == 200
        data = response.json()
        assert data['schedule_id'] == 'schedule_001'
        assert data['status'] == 'pending'

    @pytest.mark.asyncio
    async def test_cancel_scheduled_deployment(self, client, mock_auth, mock_deployment_scheduler):
        """Test cancel scheduled deployment."""
        mock_deployment_scheduler.cancel_scheduled_deployment.return_value = True

        response = await client.delete("/api/deployments/scheduled/schedule_001?reason=No+longer+needed")

        assert response.status_code == 200
        data = response.json()
        assert data['cancelled'] is True
        assert 'reason' in data

    @pytest.mark.asyncio
    async def test_cancel_scheduled_deployment_not_found(self, client, mock_auth, mock_deployment_scheduler):
        """Test cancel nonexistent scheduled deployment."""
        from src.core.exceptions import DeploymentError
        mock_deployment_scheduler.cancel_scheduled_deployment.side_effect = DeploymentError("Schedule not found")

        response = await client.delete("/api/deployments/scheduled/nonexistent")

        assert response.status_code == 400


class TestDeploymentWindowEndpoints:
    """Test deployment window management."""

    @pytest.mark.asyncio
    async def test_create_deployment_window(self, client, mock_auth):
        """Test create deployment window (not yet implemented)."""
        response = await client.post("/api/deployments/windows", json={
            "start_time": datetime.utcnow().isoformat(),
            "end_time": (datetime.utcnow() + timedelta(hours=4)).isoformat(),
            "allowed_priorities": ["high", "critical"]
        })

        assert response.status_code == 200
        assert 'not yet implemented' in response.json()['message'].lower()

    @pytest.mark.asyncio
    async def test_create_maintenance_window(self, client, mock_auth):
        """Test create maintenance window (not yet implemented)."""
        response = await client.post("/api/deployments/maintenance-windows", json={
            "start_time": datetime.utcnow().isoformat(),
            "end_time": (datetime.utcnow() + timedelta(hours=2)).isoformat(),
            "reason": "Scheduled maintenance"
        })

        assert response.status_code == 200
        assert 'not yet implemented' in response.json()['message'].lower()


class TestDeploymentAnalyticsEndpoint:
    """Test deployment analytics."""

    @pytest.mark.asyncio
    async def test_get_deployment_analytics(self, client, mock_auth):
        """Test get deployment analytics."""
        response = await client.get("/api/deployments/analytics/summary?days=30")

        assert response.status_code == 200
        data = response.json()
        assert 'period_days' in data
        assert data['period_days'] == 30
        assert 'total_deployments' in data
        assert 'successful_deployments' in data
        assert 'failed_deployments' in data

    @pytest.mark.asyncio
    async def test_get_deployment_analytics_custom_period(self, client, mock_auth):
        """Test get deployment analytics for custom period."""
        response = await client.get("/api/deployments/analytics/summary?days=90")

        assert response.status_code == 200
        data = response.json()
        assert data['period_days'] == 90


class TestDeploymentStrategies:
    """Test different deployment strategies."""

    @pytest.mark.asyncio
    async def test_rolling_deployment_strategy(self, client, mock_auth, mock_deployment_service,
                                               sample_deployment_request):
        """Test rolling deployment strategy."""
        mock_deployment_service.create_deployment.return_value = 'deployment_rolling'
        sample_deployment_request['deployment_strategy'] = 'rolling'

        response = await client.post("/api/deployments/", json=sample_deployment_request)

        assert response.status_code == 200
        assert response.json()['strategy'] == 'rolling'

    @pytest.mark.asyncio
    async def test_parallel_deployment_strategy(self, client, mock_auth, mock_deployment_service,
                                                sample_deployment_request):
        """Test parallel deployment strategy."""
        mock_deployment_service.create_deployment.return_value = 'deployment_parallel'
        sample_deployment_request['deployment_strategy'] = 'parallel'

        response = await client.post("/api/deployments/", json=sample_deployment_request)

        assert response.status_code == 200
        assert response.json()['strategy'] == 'parallel'

    @pytest.mark.asyncio
    async def test_canary_deployment_strategy(self, client, mock_auth, mock_deployment_service,
                                              sample_deployment_request):
        """Test canary deployment strategy."""
        mock_deployment_service.create_deployment.return_value = 'deployment_canary'
        sample_deployment_request['deployment_strategy'] = 'canary'

        response = await client.post("/api/deployments/", json=sample_deployment_request)

        assert response.status_code == 200
        assert response.json()['strategy'] == 'canary'
