"""
Tests for Deployment Service
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch
from src.deployment.executor import DeploymentExecutor, DeploymentStrategy, DeploymentResult
from src.db.models import Device, DeviceVendor


class TestDeploymentExecutor:
    @pytest.mark.asyncio
    async def test_canary_deployment_success(self, mock_device, mock_audit_logger):
        """Test successful canary deployment"""
        # Setup
        mock_connector = Mock()
        mock_connector.connect_to_device = AsyncMock()

        executor = DeploymentExecutor(
            device_connector=mock_connector,
            audit_logger=mock_audit_logger
        )

        # Mock backup and deployment methods
        executor.backup_device = AsyncMock(return_value="backup-123")
        executor.deploy_to_device = AsyncMock()
        executor.validate_device_health = AsyncMock(return_value=True)
        executor.monitor_health = AsyncMock()

        # Execute
        result = await executor.execute_canary_deployment(
            deployment_id="deploy-123",
            devices=[mock_device],
            configuration={"test": "config"},
            user_context={"user_id": "user-123"}
        )

        # Assert
        assert result.success is True
        assert len(result.devices) == 1
        assert mock_device.hostname in result.devices

        # Verify backup was called
        executor.backup_device.assert_called_once()

        # Verify health check was performed
        executor.validate_device_health.assert_called()

    @pytest.mark.asyncio
    async def test_canary_deployment_rollback(self, mock_device, mock_audit_logger):
        """Test canary deployment with rollback on failure"""
        # Setup
        mock_connector = Mock()
        executor = DeploymentExecutor(
            device_connector=mock_connector,
            audit_logger=mock_audit_logger
        )

        # Mock backup success but deployment failure
        executor.backup_device = AsyncMock(return_value="backup-123")
        executor.deploy_to_device = AsyncMock(side_effect=Exception("Deploy failed"))
        executor.rollback_all = AsyncMock()

        # Execute and expect failure
        with pytest.raises(Exception) as exc_info:
            await executor.execute_canary_deployment(
                deployment_id="deploy-123",
                devices=[mock_device],
                configuration={"test": "config"},
                user_context={"user_id": "user-123"}
            )

        assert "Deploy failed" in str(exc_info.value)

        # Verify rollback was called
        executor.rollback_all.assert_called_once()

    @pytest.mark.asyncio
    async def test_rolling_deployment(self, mock_device, mock_audit_logger):
        """Test rolling deployment strategy"""
        # Setup
        mock_connector = Mock()
        executor = DeploymentExecutor(
            device_connector=mock_connector,
            audit_logger=mock_audit_logger
        )

        # Mock successful deployment
        executor.backup_device = AsyncMock(return_value="backup-123")
        executor.deploy_to_device = AsyncMock()
        executor.validate_device_health = AsyncMock(return_value=True)

        # Execute
        result = await executor.execute_rolling_deployment(
            deployment_id="deploy-123",
            devices=[mock_device],
            configuration={"test": "config"},
            user_context={"user_id": "user-123"}
        )

        # Assert
        assert result.success is True
        assert len(result.devices) == 1

    @pytest.mark.asyncio
    async def test_blue_green_deployment(self, mock_device, mock_audit_logger):
        """Test blue-green deployment strategy"""
        # Setup
        mock_connector = Mock()
        executor = DeploymentExecutor(
            device_connector=mock_connector,
            audit_logger=mock_audit_logger
        )

        # Mock staging and activation
        executor.backup_device = AsyncMock(return_value="backup-123")
        executor.stage_configuration = AsyncMock()
        executor.validate_staged_config = AsyncMock(return_value=True)
        executor.activate_staged_config = AsyncMock()

        # Execute
        result = await executor.execute_blue_green_deployment(
            deployment_id="deploy-123",
            devices=[mock_device],
            configuration={"test": "config"},
            user_context={"user_id": "user-123"}
        )

        # Assert
        assert result.success is True

        # Verify staging and activation
        executor.stage_configuration.assert_called()
        executor.activate_staged_config.assert_called()

    def test_deployment_result(self):
        """Test deployment result object"""
        result = DeploymentResult(
            success=True,
            devices=["device1", "device2"],
            errors=[]
        )

        assert result.success is True
        assert len(result.devices) == 2
        assert len(result.errors) == 0


class TestDeploymentPatterns:
    """Test CLAUDE.md deployment patterns are followed"""

    @pytest.mark.asyncio
    async def test_always_backup_before_deploy(self, mock_device, mock_audit_logger):
        """Verify backup is always performed before deployment"""
        mock_connector = Mock()
        executor = DeploymentExecutor(mock_connector, mock_audit_logger)

        # Track method calls
        backup_called = False
        deploy_called = False

        async def mock_backup(*args, **kwargs):
            nonlocal backup_called
            backup_called = True
            return "backup-123"

        async def mock_deploy(*args, **kwargs):
            nonlocal deploy_called
            assert backup_called, "Deploy called before backup!"
            deploy_called = True

        executor.backup_device = mock_backup
        executor.deploy_to_device = mock_deploy
        executor.validate_device_health = AsyncMock(return_value=True)
        executor.monitor_health = AsyncMock()

        await executor.execute_canary_deployment(
            "deploy-123",
            [mock_device],
            {"config": "test"},
            {"user_id": "test"}
        )

        assert backup_called
        assert deploy_called

    @pytest.mark.asyncio
    async def test_health_validation_after_deployment(self, mock_device, mock_audit_logger):
        """Verify health check is performed after deployment"""
        mock_connector = Mock()
        executor = DeploymentExecutor(mock_connector, mock_audit_logger)

        health_checked = False

        async def mock_health_check(*args, **kwargs):
            nonlocal health_checked
            health_checked = True
            return True

        executor.backup_device = AsyncMock(return_value="backup-123")
        executor.deploy_to_device = AsyncMock()
        executor.validate_device_health = mock_health_check
        executor.monitor_health = AsyncMock()

        await executor.execute_canary_deployment(
            "deploy-123",
            [mock_device],
            {"config": "test"},
            {"user_id": "test"}
        )

        assert health_checked, "Health validation not performed!"