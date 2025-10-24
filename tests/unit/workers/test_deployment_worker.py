"""
Unit tests for deployment worker.
Tests deployment execution, monitoring, rollback, and strategies.
"""

import pytest
from datetime import datetime, timedelta
from uuid import UUID, uuid4
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, Any

from src.workers.deployment_worker import DeploymentWorker
from src.workers.base import WorkerTask
from src.db.models import Deployment, Device, DeploymentState
from src.core.exceptions import DeploymentError


@pytest.fixture
def worker():
    """Create deployment worker instance."""
    with patch('src.workers.deployment_worker.DeploymentExecutor'), \
         patch('src.workers.deployment_worker.SecureDeviceConnector'), \
         patch('src.workers.deployment_worker.AuditLogger'):
        worker = DeploymentWorker()
        worker.audit.log_event = AsyncMock()
        return worker


@pytest.fixture
def sample_deployment():
    """Sample deployment object."""
    deployment = Mock(spec=Deployment)
    deployment.id = uuid4()
    deployment.state = DeploymentState.PENDING
    deployment.configuration = {'commands': ['interface GigabitEthernet0/1', 'no shutdown']}
    deployment.created_by = uuid4()
    return deployment


@pytest.fixture
def sample_devices():
    """Sample device list."""
    devices = []
    for i in range(4):
        device = Mock(spec=Device)
        device.id = uuid4()
        device.hostname = f'device-{i}'
        device.vendor = 'cisco'
        device.is_active = True
        device.last_backup_id = None
        devices.append(device)
    return devices


class TestDeploymentWorkerInitialization:
    """Test deployment worker initialization."""

    def test_worker_initialization(self, worker):
        """Test worker initializes correctly."""
        assert worker.get_worker_type() == "deployment"
        assert hasattr(worker, 'executor')
        assert hasattr(worker, 'device_connector')
        assert hasattr(worker, 'audit')
        assert hasattr(worker, 'active_deployments')
        assert isinstance(worker.active_deployments, dict)

    def test_active_deployments_empty_on_init(self, worker):
        """Test active deployments starts empty."""
        assert len(worker.active_deployments) == 0


class TestProcessTask:
    """Test task processing."""

    @pytest.mark.asyncio
    async def test_process_execute_deployment_task(self, worker):
        """Test processing execute deployment task."""
        task = Mock(spec=WorkerTask)
        task.task_type = "execute_deployment"
        task.payload = {
            'deployment_id': str(uuid4()),
            'user_id': str(uuid4()),
            'strategy': 'canary'
        }

        worker._execute_deployment = AsyncMock(return_value={'status': 'success'})

        result = await worker.process_task(task)

        assert result['status'] == 'success'
        worker._execute_deployment.assert_called_once_with(task.payload)

    @pytest.mark.asyncio
    async def test_process_rollback_deployment_task(self, worker):
        """Test processing rollback deployment task."""
        task = Mock(spec=WorkerTask)
        task.task_type = "rollback_deployment"
        task.payload = {
            'deployment_id': str(uuid4()),
            'reason': 'Manual rollback'
        }

        worker._rollback_deployment = AsyncMock(return_value={'status': 'success'})

        result = await worker.process_task(task)

        assert result['status'] == 'success'
        worker._rollback_deployment.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_monitor_deployment_task(self, worker):
        """Test processing monitor deployment task."""
        deployment_id = uuid4()
        worker.active_deployments[deployment_id] = {
            'started_at': datetime.utcnow(),
            'devices': [],
            'strategy': 'rolling',
            'progress': 50
        }

        task = Mock(spec=WorkerTask)
        task.task_type = "monitor_deployment"
        task.payload = {'deployment_id': str(deployment_id)}

        result = await worker.process_task(task)

        assert result['status'] == 'active'
        assert result['progress'] == 50
        assert result['strategy'] == 'rolling'

    @pytest.mark.asyncio
    async def test_process_validate_deployment_task(self, worker):
        """Test processing validate deployment task."""
        task = Mock(spec=WorkerTask)
        task.task_type = "validate_deployment"
        task.payload = {'deployment_id': str(uuid4())}

        worker._validate_deployment = AsyncMock(return_value={'status': 'validated', 'ready': True})

        result = await worker.process_task(task)

        assert result['status'] == 'validated'
        assert result['ready'] is True

    @pytest.mark.asyncio
    async def test_process_health_check_task(self, worker):
        """Test processing health check task."""
        task = Mock(spec=WorkerTask)
        task.task_type = "health_check"
        task.payload = {
            'deployment_id': str(uuid4()),
            'device_ids': [str(uuid4()), str(uuid4())]
        }

        worker._health_check_deployment = AsyncMock(return_value={'status': 'completed', 'healthy': True})

        result = await worker.process_task(task)

        assert result['status'] == 'completed'
        assert result['healthy'] is True

    @pytest.mark.asyncio
    async def test_process_cancel_deployment_task(self, worker):
        """Test processing cancel deployment task."""
        deployment_id = uuid4()
        worker.active_deployments[deployment_id] = {'started_at': datetime.utcnow()}

        task = Mock(spec=WorkerTask)
        task.task_type = "cancel_deployment"
        task.payload = {
            'deployment_id': str(deployment_id),
            'reason': 'User cancellation'
        }

        with patch('src.workers.deployment_worker.get_db'):
            result = await worker.process_task(task)

        assert result['status'] == 'cancelled'
        assert deployment_id not in worker.active_deployments

    @pytest.mark.asyncio
    async def test_process_unknown_task_type_raises_error(self, worker):
        """Test unknown task type raises ValueError."""
        task = Mock(spec=WorkerTask)
        task.task_type = "unknown_task"
        task.payload = {}

        with pytest.raises(ValueError, match="Unknown task type"):
            await worker.process_task(task)


class TestExecuteDeployment:
    """Test deployment execution."""

    @pytest.mark.asyncio
    async def test_execute_canary_deployment_success(self, worker, sample_deployment, sample_devices):
        """Test successful canary deployment."""
        payload = {
            'deployment_id': str(sample_deployment.id),
            'user_id': str(uuid4()),
            'strategy': 'canary'
        }

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=sample_deployment)
        mock_db.commit = AsyncMock()

        worker._get_target_devices = AsyncMock(return_value=sample_devices)
        worker._execute_canary = AsyncMock(return_value={'status': 'success', 'deployed_devices': [d.id for d in sample_devices]})

        with patch('src.workers.deployment_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())):
            result = await worker._execute_deployment(payload)

        assert result['status'] == 'success'
        assert sample_deployment.state == DeploymentState.COMPLETED
        assert sample_deployment.id not in worker.active_deployments

    @pytest.mark.asyncio
    async def test_execute_rolling_deployment_success(self, worker, sample_deployment, sample_devices):
        """Test successful rolling deployment."""
        payload = {
            'deployment_id': str(sample_deployment.id),
            'user_id': str(uuid4()),
            'strategy': 'rolling'
        }

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=sample_deployment)
        mock_db.commit = AsyncMock()

        worker._get_target_devices = AsyncMock(return_value=sample_devices)
        worker._execute_rolling = AsyncMock(return_value={'status': 'success', 'deployed_devices': [d.id for d in sample_devices]})

        with patch('src.workers.deployment_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())):
            result = await worker._execute_deployment(payload)

        assert result['status'] == 'success'
        assert sample_deployment.state == DeploymentState.COMPLETED

    @pytest.mark.asyncio
    async def test_execute_blue_green_deployment_success(self, worker, sample_deployment, sample_devices):
        """Test successful blue-green deployment."""
        payload = {
            'deployment_id': str(sample_deployment.id),
            'user_id': str(uuid4()),
            'strategy': 'blue_green'
        }

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=sample_deployment)
        mock_db.commit = AsyncMock()

        worker._get_target_devices = AsyncMock(return_value=sample_devices)
        worker._execute_blue_green = AsyncMock(return_value={'status': 'success', 'deployed_devices': [d.id for d in sample_devices]})

        with patch('src.workers.deployment_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())):
            result = await worker._execute_deployment(payload)

        assert result['status'] == 'success'

    @pytest.mark.asyncio
    async def test_execute_deployment_not_found(self, worker):
        """Test execution with non-existent deployment."""
        payload = {
            'deployment_id': str(uuid4()),
            'user_id': str(uuid4()),
            'strategy': 'canary'
        }

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=None)

        with patch('src.workers.deployment_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())):
            with pytest.raises(DeploymentError, match="not found"):
                await worker._execute_deployment(payload)

    @pytest.mark.asyncio
    async def test_execute_deployment_tracks_active_deployment(self, worker, sample_deployment, sample_devices):
        """Test deployment is tracked in active deployments."""
        payload = {
            'deployment_id': str(sample_deployment.id),
            'user_id': str(uuid4()),
            'strategy': 'canary'
        }

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=sample_deployment)
        mock_db.commit = AsyncMock()

        worker._get_target_devices = AsyncMock(return_value=sample_devices)

        # Mock _execute_canary to check active_deployments during execution
        async def mock_execute_canary(deployment, devices):
            assert sample_deployment.id in worker.active_deployments
            assert worker.active_deployments[sample_deployment.id]['strategy'] == 'canary'
            return {'status': 'success', 'deployed_devices': []}

        worker._execute_canary = mock_execute_canary

        with patch('src.workers.deployment_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())):
            await worker._execute_deployment(payload)

    @pytest.mark.asyncio
    async def test_execute_deployment_failure_updates_state(self, worker, sample_deployment, sample_devices):
        """Test deployment failure updates state correctly."""
        payload = {
            'deployment_id': str(sample_deployment.id),
            'user_id': str(uuid4()),
            'strategy': 'canary'
        }

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=sample_deployment)
        mock_db.commit = AsyncMock()

        worker._get_target_devices = AsyncMock(return_value=sample_devices)
        worker._execute_canary = AsyncMock(side_effect=Exception("Deployment failed"))

        with patch('src.workers.deployment_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())):
            with pytest.raises(DeploymentError):
                await worker._execute_deployment(payload)

        # Deployment should be marked as failed
        assert sample_deployment.state == DeploymentState.FAILED
        assert sample_deployment.error_message is not None


class TestRollbackDeployment:
    """Test deployment rollback."""

    @pytest.mark.asyncio
    async def test_rollback_deployment_success(self, worker, sample_deployment, sample_devices):
        """Test successful rollback."""
        # Set backup IDs
        for device in sample_devices:
            device.last_backup_id = str(uuid4())

        payload = {
            'deployment_id': str(sample_deployment.id),
            'reason': 'Manual rollback'
        }

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=sample_deployment)
        mock_db.commit = AsyncMock()

        worker._get_deployed_devices = AsyncMock(return_value=sample_devices)

        # Mock device connector
        mock_connection = AsyncMock()
        mock_connection.restore_backup = AsyncMock()
        worker.device_connector.connect_to_device = AsyncMock(return_value=mock_connection)

        with patch('src.workers.deployment_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())):
            result = await worker._rollback_deployment(payload)

        assert result['status'] in ['success', 'partial']
        assert result['successful'] <= len(sample_devices)
        assert sample_deployment.state == DeploymentState.ROLLED_BACK

    @pytest.mark.asyncio
    async def test_rollback_deployment_no_backup(self, worker, sample_deployment, sample_devices):
        """Test rollback with missing backups."""
        # No backup IDs set
        for device in sample_devices:
            device.last_backup_id = None

        payload = {
            'deployment_id': str(sample_deployment.id),
            'reason': 'Emergency rollback'
        }

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=sample_deployment)
        mock_db.commit = AsyncMock()

        worker._get_deployed_devices = AsyncMock(return_value=sample_devices)

        with patch('src.workers.deployment_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())):
            result = await worker._rollback_deployment(payload)

        assert result['status'] == 'partial'
        assert result['successful'] == 0
        assert all('No backup available' in r.get('error', '') for r in result['results'] if r['status'] == 'failed')

    @pytest.mark.asyncio
    async def test_rollback_deployment_not_found(self, worker):
        """Test rollback with non-existent deployment."""
        payload = {
            'deployment_id': str(uuid4()),
            'reason': 'Rollback test'
        }

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=None)

        with patch('src.workers.deployment_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())):
            with pytest.raises(DeploymentError, match="not found"):
                await worker._rollback_deployment(payload)


class TestMonitorDeployment:
    """Test deployment monitoring."""

    @pytest.mark.asyncio
    async def test_monitor_active_deployment(self, worker):
        """Test monitoring active deployment."""
        deployment_id = uuid4()
        started_at = datetime.utcnow() - timedelta(seconds=60)

        worker.active_deployments[deployment_id] = {
            'started_at': started_at,
            'devices': [Mock(), Mock(), Mock()],
            'strategy': 'rolling',
            'progress': 33
        }

        payload = {'deployment_id': str(deployment_id)}

        result = await worker._monitor_deployment(payload)

        assert result['status'] == 'active'
        assert result['progress'] == 33
        assert result['strategy'] == 'rolling'
        assert result['devices_total'] == 3
        assert result['devices_completed'] == 0  # 33% of 3 = 0.99 -> 0

    @pytest.mark.asyncio
    async def test_monitor_inactive_deployment(self, worker):
        """Test monitoring inactive deployment."""
        payload = {'deployment_id': str(uuid4())}

        result = await worker._monitor_deployment(payload)

        assert result['status'] == 'not_found'
        assert 'not active' in result['message'].lower()


class TestCancelDeployment:
    """Test deployment cancellation."""

    @pytest.mark.asyncio
    async def test_cancel_active_deployment(self, worker, sample_deployment):
        """Test cancelling active deployment."""
        deployment_id = sample_deployment.id
        worker.active_deployments[deployment_id] = {'started_at': datetime.utcnow()}

        payload = {
            'deployment_id': str(deployment_id),
            'reason': 'User cancelled'
        }

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=sample_deployment)
        mock_db.commit = AsyncMock()

        with patch('src.workers.deployment_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())):
            result = await worker._cancel_deployment(payload)

        assert result['status'] == 'cancelled'
        assert deployment_id not in worker.active_deployments
        assert sample_deployment.state == DeploymentState.CANCELLED

    @pytest.mark.asyncio
    async def test_cancel_inactive_deployment(self, worker):
        """Test cancelling inactive deployment."""
        payload = {
            'deployment_id': str(uuid4()),
            'reason': 'Test cancel'
        }

        result = await worker._cancel_deployment(payload)

        assert result['status'] == 'not_found'


class TestDeploymentStrategies:
    """Test different deployment strategies."""

    @pytest.mark.asyncio
    async def test_canary_strategy_stages(self, worker, sample_deployment, sample_devices):
        """Test canary deployment progresses through stages."""
        worker._backup_device = AsyncMock()
        worker._deploy_to_device = AsyncMock()
        worker._check_device_health = AsyncMock(return_value={'healthy': True})
        worker._monitor_stage = AsyncMock()

        result = await worker._execute_canary(sample_deployment, sample_devices)

        assert result['status'] == 'success'
        assert len(result['deployed_devices']) == len(sample_devices)

    @pytest.mark.asyncio
    async def test_rolling_strategy_batches(self, worker, sample_deployment, sample_devices):
        """Test rolling deployment processes in batches."""
        worker._deploy_device_safe = AsyncMock(return_value=None)

        result = await worker._execute_rolling(sample_deployment, sample_devices)

        assert result['status'] == 'success'
        assert len(result['deployed_devices']) == len(sample_devices)

    @pytest.mark.asyncio
    async def test_blue_green_strategy_parallel(self, worker, sample_deployment, sample_devices):
        """Test blue-green deployment deploys in parallel."""
        worker._deploy_device_safe = AsyncMock(return_value=None)
        worker._check_device_health = AsyncMock(return_value={'healthy': True})

        result = await worker._execute_blue_green(sample_deployment, sample_devices)

        assert result['status'] == 'success'
        assert len(result['deployed_devices']) == len(sample_devices)


class TestValidateDeployment:
    """Test deployment validation."""

    @pytest.mark.asyncio
    async def test_validate_deployment_all_ready(self, worker, sample_deployment, sample_devices):
        """Test validation with all devices ready."""
        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=sample_deployment)

        worker._get_target_devices = AsyncMock(return_value=sample_devices)
        worker._check_device_health = AsyncMock(return_value={'healthy': True})
        worker._check_configuration_compatibility = AsyncMock(return_value=True)

        payload = {'deployment_id': str(sample_deployment.id)}

        with patch('src.workers.deployment_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())):
            result = await worker._validate_deployment(payload)

        assert result['status'] == 'validated'
        assert result['ready'] is True
        assert result['ready_count'] == len(sample_devices)

    @pytest.mark.asyncio
    async def test_validate_deployment_some_not_ready(self, worker, sample_deployment, sample_devices):
        """Test validation with some devices not ready."""
        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=sample_deployment)

        worker._get_target_devices = AsyncMock(return_value=sample_devices)

        # First device healthy, second not
        health_results = [{'healthy': True}, {'healthy': False}] * 2
        worker._check_device_health = AsyncMock(side_effect=health_results)
        worker._check_configuration_compatibility = AsyncMock(return_value=True)

        payload = {'deployment_id': str(sample_deployment.id)}

        with patch('src.workers.deployment_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())):
            result = await worker._validate_deployment(payload)

        assert result['status'] == 'validated'
        assert result['ready'] is False
        assert result['ready_count'] < result['total']


class TestHealthCheckDeployment:
    """Test deployment health checks."""

    @pytest.mark.asyncio
    async def test_health_check_all_healthy(self, worker):
        """Test health check with all devices healthy."""
        device_ids = [str(uuid4()) for _ in range(3)]

        mock_device = Mock(spec=Device)
        mock_device.hostname = 'test-device'

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=mock_device)

        worker._check_device_health = AsyncMock(return_value={'healthy': True, 'cpu_usage': 20})

        payload = {
            'deployment_id': str(uuid4()),
            'device_ids': device_ids
        }

        with patch('src.workers.deployment_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())):
            result = await worker._health_check_deployment(payload)

        assert result['status'] == 'completed'
        assert result['healthy'] is True
        assert result['healthy_count'] == len(device_ids)

    @pytest.mark.asyncio
    async def test_health_check_some_unhealthy(self, worker):
        """Test health check with some unhealthy devices."""
        device_ids = [str(uuid4()) for _ in range(3)]

        mock_device = Mock(spec=Device)
        mock_device.hostname = 'test-device'

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=mock_device)

        # Mix of healthy and unhealthy
        health_results = [
            {'healthy': True},
            {'healthy': False},
            {'healthy': True}
        ]
        worker._check_device_health = AsyncMock(side_effect=health_results)

        payload = {
            'deployment_id': str(uuid4()),
            'device_ids': device_ids
        }

        with patch('src.workers.deployment_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())):
            result = await worker._health_check_deployment(payload)

        assert result['status'] == 'completed'
        assert result['healthy'] is False
        assert result['healthy_count'] == 2
        assert result['total'] == 3
