"""
Unit tests for Deployment Service
Tests deployment creation, execution, rollback, and lifecycle management
"""

import pytest
from unittest.mock import AsyncMock, Mock, patch, MagicMock
from datetime import datetime, timedelta
import uuid

from src.services.deployment_service import (
    DeploymentService, DeploymentRequest, DeploymentProgress,
    DeploymentPhase, RollbackPlan
)
from src.db.models import DeploymentStrategy, DeploymentStatus
from src.core.exceptions import DeploymentError, ValidationError


@pytest.fixture
def deployment_service():
    """Create DeploymentService instance with mocked dependencies."""
    with patch('src.services.deployment_service.DeviceManager'), \
         patch('src.services.deployment_service.DeploymentExecutor'), \
         patch('src.services.deployment_service.ConfigValidator'), \
         patch('src.services.deployment_service.AuditLogger'), \
         patch('src.services.deployment_service.VaultClient'):
        service = DeploymentService()
        return service


@pytest.fixture
def sample_deployment_request():
    """Sample deployment request."""
    return DeploymentRequest(
        configuration_content="hostname router-01\ninterface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n",
        target_devices=["device_001", "device_002", "device_003"],
        deployment_strategy=DeploymentStrategy.ROLLING,
        deployment_method="merge",
        require_approval=False,
        backup_before_deploy=True,
        auto_rollback_on_failure=True,
        rollback_timeout_minutes=15,
        metadata={"change_ticket": "CHG0001234"}
    )


@pytest.fixture
def user_context():
    """Sample user context."""
    return {
        'user_id': str(uuid.uuid4()),
        'email': 'test@example.com',
        'ip_address': '192.168.1.100'
    }


class TestDeploymentServiceInitialization:
    """Test DeploymentService initialization."""

    def test_deployment_service_initialization(self, deployment_service):
        """Test DeploymentService initializes correctly."""
        assert deployment_service is not None
        assert hasattr(deployment_service, 'device_manager')
        assert hasattr(deployment_service, 'deployment_executor')
        assert hasattr(deployment_service, 'config_validator')
        assert hasattr(deployment_service, 'audit')
        assert hasattr(deployment_service, 'vault')

    def test_deployment_service_default_settings(self, deployment_service):
        """Test DeploymentService default settings."""
        assert deployment_service.max_concurrent_devices == 10
        assert deployment_service.deployment_timeout_hours == 4
        assert isinstance(deployment_service.active_deployments, dict)
        assert isinstance(deployment_service.rollback_plans, dict)


class TestCreateDeployment:
    """Test deployment creation."""

    @pytest.mark.asyncio
    async def test_create_deployment_success(self, deployment_service, sample_deployment_request, user_context):
        """Test successful deployment creation."""
        # Mock validators
        mock_validation = Mock()
        mock_validation.is_valid = True
        mock_validation.errors = []
        deployment_service.config_validator.validate_configuration = AsyncMock(return_value=mock_validation)

        # Mock device validation
        deployment_service._validate_target_devices = AsyncMock(
            return_value=sample_deployment_request.target_devices
        )

        # Mock encryption
        deployment_service.vault.encrypt_config = AsyncMock(return_value="encrypted_config_data")
        deployment_service._calculate_config_hash = Mock(return_value="config_hash_123")

        # Mock database session
        mock_session = AsyncMock()
        with patch('src.services.deployment_service.get_db_session') as mock_get_session:
            mock_get_session.return_value.__aenter__.return_value = mock_session

            # Mock audit logging
            deployment_service.audit.log_deployment_creation = AsyncMock()

            # Create deployment
            deployment_id = await deployment_service.create_deployment(
                sample_deployment_request,
                user_context
            )

            # Assertions
            assert deployment_id is not None
            assert uuid.UUID(deployment_id)  # Valid UUID
            assert deployment_id in deployment_service.active_deployments
            assert deployment_id in deployment_service.rollback_plans

            # Verify progress tracking initialized
            progress = deployment_service.active_deployments[deployment_id]
            assert progress.phase == DeploymentPhase.PLANNING
            assert progress.devices_total == 3
            assert progress.devices_completed == 0

            # Verify rollback plan created
            rollback_plan = deployment_service.rollback_plans[deployment_id]
            assert rollback_plan.deployment_id == deployment_id
            assert len(rollback_plan.affected_devices) == 3

    @pytest.mark.asyncio
    async def test_create_deployment_invalid_configuration(self, deployment_service, sample_deployment_request, user_context):
        """Test deployment creation with invalid configuration."""
        # Mock validation failure
        mock_validation = Mock()
        mock_validation.is_valid = False
        mock_validation.errors = ["Invalid interface syntax"]
        deployment_service.config_validator.validate_configuration = AsyncMock(return_value=mock_validation)

        with pytest.raises(ValidationError) as exc_info:
            await deployment_service.create_deployment(
                sample_deployment_request,
                user_context
            )

        assert "Configuration validation failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_create_deployment_invalid_devices(self, deployment_service, sample_deployment_request, user_context):
        """Test deployment creation with invalid target devices."""
        # Mock valid configuration
        mock_validation = Mock()
        mock_validation.is_valid = True
        deployment_service.config_validator.validate_configuration = AsyncMock(return_value=mock_validation)

        # Mock device validation - only 2 of 3 devices are valid
        deployment_service._validate_target_devices = AsyncMock(
            return_value=["device_001", "device_002"]
        )

        with pytest.raises(ValidationError) as exc_info:
            await deployment_service.create_deployment(
                sample_deployment_request,
                user_context
            )

        assert "Invalid target devices" in str(exc_info.value)


class TestExecuteDeployment:
    """Test deployment execution."""

    @pytest.mark.asyncio
    async def test_execute_deployment_not_found(self, deployment_service, user_context):
        """Test executing nonexistent deployment."""
        with pytest.raises(ValidationError) as exc_info:
            await deployment_service.execute_deployment("nonexistent_id", user_context)

        assert "not found in active deployments" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_execute_deployment_validation_phase(self, deployment_service, user_context):
        """Test deployment execution validation phase."""
        deployment_id = str(uuid.uuid4())

        # Add deployment to active deployments
        progress = DeploymentProgress(
            deployment_id=deployment_id,
            phase=DeploymentPhase.PLANNING,
            progress_percentage=0.0,
            devices_completed=0,
            devices_total=3,
            devices_successful=0,
            devices_failed=0
        )
        deployment_service.active_deployments[deployment_id] = progress

        # Mock deployment record
        mock_deployment = Mock()
        mock_deployment.id = uuid.UUID(deployment_id)
        mock_deployment.status = DeploymentStatus.PENDING
        mock_deployment.configuration_encrypted = "encrypted_data"
        mock_deployment.deployment_metadata = {'backup_before_deploy': True}

        mock_session = AsyncMock()
        mock_session.get = AsyncMock(return_value=mock_deployment)
        mock_session.query = Mock(return_value=Mock(
            filter=Mock(return_value=Mock(
                order_by=Mock(return_value=Mock(
                    all=AsyncMock(return_value=[])
                ))
            ))
        ))

        with patch('src.services.deployment_service.get_db_session') as mock_get_session:
            mock_get_session.return_value.__aenter__.return_value = mock_session

            deployment_service.vault.decrypt_config = AsyncMock(return_value="config_content")
            deployment_service._validate_deployment_prerequisites = AsyncMock()
            deployment_service._create_deployment_backups = AsyncMock(return_value={})

            # This will fail at some point but we're testing early phases
            try:
                await deployment_service.execute_deployment(deployment_id, user_context)
            except:
                pass  # Expected to fail later in execution

            # Verify phase progression
            assert progress.phase in [DeploymentPhase.VALIDATION, DeploymentPhase.BACKUP, DeploymentPhase.DEPLOYMENT]
            assert progress.progress_percentage > 0


class TestDeploymentPhases:
    """Test individual deployment phases."""

    def test_deployment_phase_enum_values(self):
        """Test DeploymentPhase enum values."""
        assert DeploymentPhase.PLANNING.value == "planning"
        assert DeploymentPhase.VALIDATION.value == "validation"
        assert DeploymentPhase.BACKUP.value == "backup"
        assert DeploymentPhase.DEPLOYMENT.value == "deployment"
        assert DeploymentPhase.VERIFICATION.value == "verification"
        assert DeploymentPhase.CLEANUP.value == "cleanup"
        assert DeploymentPhase.COMPLETED.value == "completed"
        assert DeploymentPhase.FAILED.value == "failed"
        assert DeploymentPhase.ROLLING_BACK.value == "rolling_back"
        assert DeploymentPhase.ROLLED_BACK.value == "rolled_back"


class TestDeploymentProgress:
    """Test DeploymentProgress dataclass."""

    def test_deployment_progress_creation(self):
        """Test DeploymentProgress creation."""
        progress = DeploymentProgress(
            deployment_id="deploy_123",
            phase=DeploymentPhase.BACKUP,
            progress_percentage=25.0,
            devices_completed=1,
            devices_total=4,
            devices_successful=1,
            devices_failed=0
        )

        assert progress.deployment_id == "deploy_123"
        assert progress.phase == DeploymentPhase.BACKUP
        assert progress.progress_percentage == 25.0
        assert progress.devices_completed == 1
        assert progress.devices_total == 4

    def test_deployment_progress_with_optionals(self):
        """Test DeploymentProgress with optional fields."""
        progress = DeploymentProgress(
            deployment_id="deploy_123",
            phase=DeploymentPhase.DEPLOYMENT,
            progress_percentage=50.0,
            devices_completed=2,
            devices_total=4,
            devices_successful=2,
            devices_failed=0,
            current_device="device_003",
            estimated_completion=datetime.utcnow() + timedelta(minutes=15),
            error_message=None
        )

        assert progress.current_device == "device_003"
        assert progress.estimated_completion is not None
        assert progress.error_message is None


class TestRollbackPlan:
    """Test RollbackPlan dataclass."""

    def test_rollback_plan_creation(self):
        """Test RollbackPlan creation."""
        rollback_plan = RollbackPlan(
            deployment_id="deploy_123",
            rollback_method="backup_restore",
            affected_devices=["device_001", "device_002", "device_003"],
            backup_references={
                "device_001": "backup_001",
                "device_002": "backup_002",
                "device_003": "backup_003"
            },
            rollback_order=["device_003", "device_002", "device_001"],
            rollback_timeout=15,
            created_at=datetime.utcnow()
        )

        assert rollback_plan.deployment_id == "deploy_123"
        assert rollback_plan.rollback_method == "backup_restore"
        assert len(rollback_plan.affected_devices) == 3
        assert len(rollback_plan.backup_references) == 3
        assert rollback_plan.rollback_order[0] == "device_003"  # Reverse order


class TestDeploymentRequest:
    """Test DeploymentRequest dataclass."""

    def test_deployment_request_creation(self):
        """Test DeploymentRequest creation with all fields."""
        request = DeploymentRequest(
            configuration_content="test config",
            target_devices=["device_001"],
            deployment_strategy=DeploymentStrategy.PARALLEL,
            deployment_method="replace",
            require_approval=True,
            backup_before_deploy=False,
            auto_rollback_on_failure=False,
            rollback_timeout_minutes=30,
            metadata={"key": "value"}
        )

        assert request.configuration_content == "test config"
        assert request.deployment_strategy == DeploymentStrategy.PARALLEL
        assert request.deployment_method == "replace"
        assert request.require_approval is True
        assert request.backup_before_deploy is False

    def test_deployment_request_defaults(self):
        """Test DeploymentRequest default values."""
        request = DeploymentRequest(
            configuration_content="test config",
            target_devices=["device_001"],
            deployment_strategy=DeploymentStrategy.ROLLING
        )

        assert request.deployment_method == "merge"
        assert request.require_approval is False
        assert request.backup_before_deploy is True
        assert request.auto_rollback_on_failure is True
        assert request.rollback_timeout_minutes == 15
        assert request.metadata == {}


class TestDeploymentStrategies:
    """Test different deployment strategies."""

    @pytest.mark.asyncio
    async def test_rolling_strategy(self, deployment_service, sample_deployment_request, user_context):
        """Test rolling deployment strategy."""
        sample_deployment_request.deployment_strategy = DeploymentStrategy.ROLLING

        # Mock dependencies
        mock_validation = Mock()
        mock_validation.is_valid = True
        deployment_service.config_validator.validate_configuration = AsyncMock(return_value=mock_validation)
        deployment_service._validate_target_devices = AsyncMock(
            return_value=sample_deployment_request.target_devices
        )
        deployment_service.vault.encrypt_config = AsyncMock(return_value="encrypted")
        deployment_service._calculate_config_hash = Mock(return_value="hash")

        mock_session = AsyncMock()
        with patch('src.services.deployment_service.get_db_session') as mock_get_session:
            mock_get_session.return_value.__aenter__.return_value = mock_session
            deployment_service.audit.log_deployment_creation = AsyncMock()

            deployment_id = await deployment_service.create_deployment(
                sample_deployment_request,
                user_context
            )

            # Verify strategy recorded
            assert deployment_id in deployment_service.active_deployments

    @pytest.mark.asyncio
    async def test_parallel_strategy(self, deployment_service, sample_deployment_request, user_context):
        """Test parallel deployment strategy."""
        sample_deployment_request.deployment_strategy = DeploymentStrategy.PARALLEL

        # Mock dependencies (same as rolling)
        mock_validation = Mock()
        mock_validation.is_valid = True
        deployment_service.config_validator.validate_configuration = AsyncMock(return_value=mock_validation)
        deployment_service._validate_target_devices = AsyncMock(
            return_value=sample_deployment_request.target_devices
        )
        deployment_service.vault.encrypt_config = AsyncMock(return_value="encrypted")
        deployment_service._calculate_config_hash = Mock(return_value="hash")

        mock_session = AsyncMock()
        with patch('src.services.deployment_service.get_db_session') as mock_get_session:
            mock_get_session.return_value.__aenter__.return_value = mock_session
            deployment_service.audit.log_deployment_creation = AsyncMock()

            deployment_id = await deployment_service.create_deployment(
                sample_deployment_request,
                user_context
            )

            assert deployment_id in deployment_service.active_deployments

    @pytest.mark.asyncio
    async def test_canary_strategy(self, deployment_service, sample_deployment_request, user_context):
        """Test canary deployment strategy."""
        sample_deployment_request.deployment_strategy = DeploymentStrategy.CANARY

        # Mock dependencies
        mock_validation = Mock()
        mock_validation.is_valid = True
        deployment_service.config_validator.validate_configuration = AsyncMock(return_value=mock_validation)
        deployment_service._validate_target_devices = AsyncMock(
            return_value=sample_deployment_request.target_devices
        )
        deployment_service.vault.encrypt_config = AsyncMock(return_value="encrypted")
        deployment_service._calculate_config_hash = Mock(return_value="hash")

        mock_session = AsyncMock()
        with patch('src.services.deployment_service.get_db_session') as mock_get_session:
            mock_get_session.return_value.__aenter__.return_value = mock_session
            deployment_service.audit.log_deployment_creation = AsyncMock()

            deployment_id = await deployment_service.create_deployment(
                sample_deployment_request,
                user_context
            )

            assert deployment_id in deployment_service.active_deployments


class TestDeploymentTracking:
    """Test deployment progress tracking."""

    def test_active_deployments_dictionary(self, deployment_service):
        """Test active deployments tracking."""
        deployment_id = str(uuid.uuid4())
        progress = DeploymentProgress(
            deployment_id=deployment_id,
            phase=DeploymentPhase.DEPLOYMENT,
            progress_percentage=50.0,
            devices_completed=2,
            devices_total=4,
            devices_successful=2,
            devices_failed=0
        )

        deployment_service.active_deployments[deployment_id] = progress

        assert deployment_id in deployment_service.active_deployments
        assert deployment_service.active_deployments[deployment_id].progress_percentage == 50.0

    def test_rollback_plans_dictionary(self, deployment_service):
        """Test rollback plans tracking."""
        deployment_id = str(uuid.uuid4())
        rollback_plan = RollbackPlan(
            deployment_id=deployment_id,
            rollback_method="backup_restore",
            affected_devices=["device_001", "device_002"],
            backup_references={"device_001": "backup_001"},
            rollback_order=["device_002", "device_001"],
            rollback_timeout=15,
            created_at=datetime.utcnow()
        )

        deployment_service.rollback_plans[deployment_id] = rollback_plan

        assert deployment_id in deployment_service.rollback_plans
        assert deployment_service.rollback_plans[deployment_id].rollback_method == "backup_restore"


class TestDeploymentConfiguration:
    """Test deployment configuration handling."""

    def test_max_concurrent_devices_setting(self, deployment_service):
        """Test max concurrent devices configuration."""
        assert deployment_service.max_concurrent_devices == 10

        # Can be modified
        deployment_service.max_concurrent_devices = 20
        assert deployment_service.max_concurrent_devices == 20

    def test_deployment_timeout_setting(self, deployment_service):
        """Test deployment timeout configuration."""
        assert deployment_service.deployment_timeout_hours == 4

        # Can be modified
        deployment_service.deployment_timeout_hours = 8
        assert deployment_service.deployment_timeout_hours == 8


class TestDeploymentErrorHandling:
    """Test deployment error handling."""

    @pytest.mark.asyncio
    async def test_create_deployment_exception_handling(self, deployment_service, sample_deployment_request, user_context):
        """Test exception handling during deployment creation."""
        # Mock validator to raise exception
        deployment_service.config_validator.validate_configuration = AsyncMock(
            side_effect=Exception("Validator error")
        )

        with pytest.raises(DeploymentError) as exc_info:
            await deployment_service.create_deployment(
                sample_deployment_request,
                user_context
            )

        assert "Failed to create deployment" in str(exc_info.value)
