"""
Integration Tests for Deployment Service

Tests end-to-end deployment workflows including approvals, rollbacks, and strategies
"""

import pytest
import uuid
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch
from typing import List

from src.core.deployment_service import DeploymentService, DeploymentStrategy
from src.db.models import Deployment, Device, DeploymentState, User
from src.devices.secure_connector import SecureDeviceConnector
from src.core.validation import ConfigValidator


class TestDeploymentIntegration:
    """Integration tests for deployment service"""

    @pytest.fixture
    def deployment_service(self, test_db_session, mock_device_connector, mock_vault_client):
        """Create deployment service with mocks"""
        service = DeploymentService(db=test_db_session)
        service.device_connector = mock_device_connector
        service.vault_client = mock_vault_client
        service.validator = ConfigValidator()
        return service

    @pytest.mark.asyncio
    async def test_full_deployment_workflow(
        self,
        deployment_service,
        test_deployment,
        test_devices,
        admin_user
    ):
        """Test complete deployment workflow from creation to completion"""
        # Create deployment
        deployment = await deployment_service.create_deployment(
            configuration="interface GigabitEthernet0/1\n description Test",
            device_ids=[str(d.id) for d in test_devices[:2]],
            created_by=admin_user.id,
            strategy=DeploymentStrategy.ROLLING,
            requires_approval=True
        )

        assert deployment.state == DeploymentState.PENDING_APPROVAL

        # Approve deployment
        approved = await deployment_service.approve_deployment(
            deployment_id=deployment.id,
            approver_id=admin_user.id
        )

        assert approved is True
        assert deployment.state == DeploymentState.APPROVED

        # Execute deployment
        with patch.object(deployment_service, '_execute_on_device', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = True

            result = await deployment_service.execute_deployment(deployment.id)

            assert result is True
            assert deployment.state == DeploymentState.COMPLETED
            assert mock_execute.call_count == 2  # Two devices

        # Verify audit trail
        assert len(deployment.audit_log) > 0
        assert any("approved" in str(log).lower() for log in deployment.audit_log)
        assert any("completed" in str(log).lower() for log in deployment.audit_log)

    @pytest.mark.asyncio
    async def test_canary_deployment(
        self,
        deployment_service,
        test_devices,
        admin_user
    ):
        """Test canary deployment strategy"""
        devices = test_devices[:10]  # Use 10 devices

        deployment = await deployment_service.create_deployment(
            configuration="interface Vlan100\n description Canary Test",
            device_ids=[str(d.id) for d in devices],
            created_by=admin_user.id,
            strategy=DeploymentStrategy.CANARY,
            canary_percentage=20,  # Start with 20%
            requires_approval=False
        )

        # Mock device execution
        execution_order = []

        async def mock_execute(device_id):
            execution_order.append(device_id)
            await asyncio.sleep(0.1)  # Simulate execution time
            return True

        with patch.object(deployment_service, '_execute_on_device', side_effect=mock_execute):
            # Execute canary deployment
            result = await deployment_service.execute_canary_deployment(deployment)

            assert result is True

            # Verify canary stages
            # Stage 1: 20% = 2 devices
            assert len(execution_order) >= 2

            # Health check pause should have occurred
            # Then remaining devices

            assert len(execution_order) == 10
            assert deployment.state == DeploymentState.COMPLETED

    @pytest.mark.asyncio
    async def test_deployment_with_validation_failure(
        self,
        deployment_service,
        test_devices,
        admin_user
    ):
        """Test deployment with configuration validation failure"""
        # Invalid configuration
        invalid_config = "invalid command that will fail validation"

        with patch.object(deployment_service.validator, 'validate_config') as mock_validate:
            mock_validate.return_value = (False, ["Invalid syntax on line 1"])

            with pytest.raises(ValueError) as exc:
                await deployment_service.create_deployment(
                    configuration=invalid_config,
                    device_ids=[str(test_devices[0].id)],
                    created_by=admin_user.id,
                    strategy=DeploymentStrategy.ALL_AT_ONCE
                )

            assert "validation failed" in str(exc.value).lower()

    @pytest.mark.asyncio
    async def test_deployment_rollback(
        self,
        deployment_service,
        test_deployment,
        test_devices,
        admin_user
    ):
        """Test deployment rollback functionality"""
        # Start deployment
        deployment = test_deployment
        deployment.state = DeploymentState.IN_PROGRESS

        # Simulate partial failure
        with patch.object(deployment_service, '_execute_on_device') as mock_execute:
            # First device succeeds, second fails
            mock_execute.side_effect = [True, Exception("Device unreachable")]

            # This should trigger automatic rollback
            result = await deployment_service.execute_deployment(deployment.id)

            assert result is False
            assert deployment.state == DeploymentState.FAILED

        # Manual rollback
        with patch.object(deployment_service, '_restore_backup') as mock_restore:
            mock_restore.return_value = True

            rollback_result = await deployment_service.rollback_deployment(
                deployment_id=deployment.id,
                reason="Manual rollback due to issues"
            )

            assert rollback_result is True
            assert deployment.state == DeploymentState.ROLLED_BACK
            assert mock_restore.call_count > 0

    @pytest.mark.asyncio
    async def test_blue_green_deployment(
        self,
        deployment_service,
        test_devices,
        admin_user
    ):
        """Test blue-green deployment strategy"""
        # Split devices into blue and green groups
        blue_devices = test_devices[:3]
        green_devices = test_devices[3:6]

        deployment = await deployment_service.create_deployment(
            configuration="spanning-tree mode rapid-pvst",
            device_ids=[str(d.id) for d in blue_devices + green_devices],
            created_by=admin_user.id,
            strategy=DeploymentStrategy.BLUE_GREEN
        )

        with patch.object(deployment_service, '_execute_on_device') as mock_execute:
            mock_execute.return_value = True

            # Execute blue-green deployment
            result = await deployment_service.execute_blue_green_deployment(deployment)

            assert result is True

            # Should deploy to green first, then switch traffic, then blue
            assert mock_execute.call_count == len(blue_devices) + len(green_devices)

    @pytest.mark.asyncio
    async def test_deployment_with_device_health_check(
        self,
        deployment_service,
        test_deployment,
        test_devices,
        mock_device_connector
    ):
        """Test deployment with device health checks"""
        deployment = test_deployment

        # Mock health check responses
        health_responses = [
            {"status": "healthy", "cpu": 45, "memory": 60},
            {"status": "degraded", "cpu": 95, "memory": 85}  # High resource usage
        ]

        mock_device_connector.check_health = AsyncMock(side_effect=health_responses)

        # Execute deployment with health checks
        with patch.object(deployment_service, '_execute_on_device') as mock_execute:
            mock_execute.return_value = True

            # Should skip degraded device
            await deployment_service.execute_deployment(
                deployment_id=deployment.id,
                skip_unhealthy=True
            )

            # Only healthy device should be deployed to
            assert mock_execute.call_count == 1

    @pytest.mark.asyncio
    async def test_concurrent_deployment_prevention(
        self,
        deployment_service,
        test_devices,
        admin_user
    ):
        """Test prevention of concurrent deployments to same device"""
        device = test_devices[0]

        # Create first deployment
        deployment1 = await deployment_service.create_deployment(
            configuration="interface Vlan200",
            device_ids=[str(device.id)],
            created_by=admin_user.id,
            strategy=DeploymentStrategy.ALL_AT_ONCE
        )

        # Set first deployment as in progress
        deployment1.state = DeploymentState.IN_PROGRESS
        await deployment_service.db.commit()

        # Attempt to create second deployment to same device
        with pytest.raises(ValueError) as exc:
            await deployment_service.create_deployment(
                configuration="interface Vlan201",
                device_ids=[str(device.id)],
                created_by=admin_user.id,
                strategy=DeploymentStrategy.ALL_AT_ONCE
            )

        assert "already has active deployment" in str(exc.value).lower()

    @pytest.mark.asyncio
    async def test_deployment_approval_workflow(
        self,
        deployment_service,
        test_deployment,
        admin_user,
        test_user
    ):
        """Test multi-level approval workflow"""
        deployment = test_deployment
        deployment.required_approvals = 2

        # First approval (operator)
        approved = await deployment_service.approve_deployment(
            deployment_id=deployment.id,
            approver_id=test_user.id
        )

        assert approved is False  # Not enough approvals
        assert deployment.state == DeploymentState.PENDING_APPROVAL
        assert len(deployment.approved_by) == 1

        # Second approval (admin)
        approved = await deployment_service.approve_deployment(
            deployment_id=deployment.id,
            approver_id=admin_user.id
        )

        assert approved is True  # Now has enough approvals
        assert deployment.state == DeploymentState.APPROVED
        assert len(deployment.approved_by) == 2

        # Duplicate approval should be rejected
        with pytest.raises(ValueError) as exc:
            await deployment_service.approve_deployment(
                deployment_id=deployment.id,
                approver_id=admin_user.id
            )

        assert "already approved" in str(exc.value).lower()

    @pytest.mark.asyncio
    async def test_deployment_scheduling(
        self,
        deployment_service,
        test_devices,
        admin_user
    ):
        """Test scheduled deployment execution"""
        # Create scheduled deployment
        scheduled_time = datetime.utcnow() + timedelta(hours=2)

        deployment = await deployment_service.create_deployment(
            configuration="ntp server 10.0.0.123",
            device_ids=[str(test_devices[0].id)],
            created_by=admin_user.id,
            strategy=DeploymentStrategy.ALL_AT_ONCE,
            scheduled_at=scheduled_time
        )

        assert deployment.state == DeploymentState.SCHEDULED
        assert deployment.scheduled_at == scheduled_time

        # Verify deployment is not executed immediately
        with patch.object(deployment_service, '_execute_on_device') as mock_execute:
            result = await deployment_service.execute_deployment(deployment.id)

            # Should not execute before scheduled time
            assert result is False
            assert mock_execute.call_count == 0

        # Simulate time passing
        deployment.scheduled_at = datetime.utcnow() - timedelta(minutes=1)

        with patch.object(deployment_service, '_execute_on_device') as mock_execute:
            mock_execute.return_value = True

            result = await deployment_service.execute_deployment(deployment.id)

            # Now should execute
            assert result is True
            assert mock_execute.call_count == 1

    @pytest.mark.asyncio
    async def test_deployment_dry_run(
        self,
        deployment_service,
        test_devices,
        admin_user,
        mock_device_connector
    ):
        """Test dry run deployment mode"""
        deployment = await deployment_service.create_deployment(
            configuration="router bgp 65001",
            device_ids=[str(d.id) for d in test_devices[:2]],
            created_by=admin_user.id,
            strategy=DeploymentStrategy.ROLLING,
            dry_run=True
        )

        assert deployment.dry_run is True

        # Execute dry run
        with patch.object(mock_device_connector, 'apply_config') as mock_apply:
            result = await deployment_service.execute_deployment(deployment.id)

            assert result is True
            # Config should NOT be applied in dry run
            assert mock_apply.call_count == 0

            # But validation should have occurred
            assert deployment.state == DeploymentState.DRY_RUN_COMPLETED

    @pytest.mark.asyncio
    async def test_deployment_metrics_collection(
        self,
        deployment_service,
        test_deployment,
        test_devices
    ):
        """Test deployment metrics and statistics collection"""
        deployment = test_deployment

        # Mock execution with timing
        async def mock_execute_with_delay(device_id):
            await asyncio.sleep(0.5)  # Simulate execution time
            return True

        with patch.object(deployment_service, '_execute_on_device', side_effect=mock_execute_with_delay):
            start_time = datetime.utcnow()
            await deployment_service.execute_deployment(deployment.id)
            end_time = datetime.utcnow()

        # Verify metrics were collected
        assert deployment.started_at is not None
        assert deployment.completed_at is not None
        assert deployment.duration_seconds > 0
        assert deployment.duration_seconds < 10  # Should be quick in tests

        # Verify per-device metrics
        assert deployment.device_status is not None
        for device_id in deployment.device_ids:
            assert device_id in deployment.device_status
            assert deployment.device_status[device_id] == "completed"