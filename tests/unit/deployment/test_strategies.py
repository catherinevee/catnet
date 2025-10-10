"""
Unit tests for Deployment Strategies
Tests canary, rolling, blue-green, and all-at-once deployment patterns
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime
from uuid import uuid4

from src.deployment.strategies import (
    DeploymentStrategy,
    CanaryDeployment,
    RollingDeployment,
    BlueGreenDeployment,
    AllAtOnceDeployment
)
from src.core.constants import DeploymentState, TaskStatus
from src.core.exceptions import DeploymentFailed


@pytest.fixture
def mock_db():
    """Provide a mock database session."""
    db = AsyncMock()
    db.commit = AsyncMock()
    db.add = Mock()
    return db


@pytest.fixture
def mock_executor():
    """Provide a mock deployment executor."""
    executor = AsyncMock()
    executor.deploy_to_device = AsyncMock(return_value={"status": "success"})
    executor.verify_deployment = AsyncMock(return_value=True)
    executor.rollback_device = AsyncMock(return_value={"status": "rolled_back"})
    return executor


@pytest.fixture
def device_configs():
    """Provide sample device configurations."""
    return [
        {
            "device_id": str(uuid4()),
            "hostname": "router1",
            "config": "interface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0"
        },
        {
            "device_id": str(uuid4()),
            "hostname": "router2",
            "config": "interface GigabitEthernet0/0\n ip address 10.0.0.2 255.255.255.0"
        },
        {
            "device_id": str(uuid4()),
            "hostname": "router3",
            "config": "interface GigabitEthernet0/0\n ip address 10.0.0.3 255.255.255.0"
        }
    ]


class TestCanaryDeployment:
    """Test canary deployment strategy."""

    @pytest.mark.asyncio
    async def test_canary_deployment_success(self, mock_db, mock_executor, device_configs):
        """Test successful canary deployment."""
        strategy = CanaryDeployment(canary_percentage=33)
        deployment_id = str(uuid4())

        result = await strategy.execute(
            deployment_id=deployment_id,
            device_configs=device_configs,
            executor=mock_executor,
            db=mock_db
        )

        assert result["status"] == "success"
        assert result["total_devices"] == 3
        # Should deploy to at least 1 device (33% of 3)
        assert mock_executor.deploy_to_device.call_count >= 1

    @pytest.mark.asyncio
    async def test_canary_deployment_calculates_canary_size(self, mock_db, mock_executor):
        """Test canary deployment calculates correct canary size."""
        strategy = CanaryDeployment(canary_percentage=20)
        deployment_id = str(uuid4())

        # 10 devices, 20% = 2 devices
        configs = [{"device_id": str(uuid4()), "hostname": f"device{i}"} for i in range(10)]

        result = await strategy.execute(
            deployment_id=deployment_id,
            device_configs=configs,
            executor=mock_executor,
            db=mock_db
        )

        assert result["canary_devices"] == 2

    @pytest.mark.asyncio
    async def test_canary_deployment_fails_on_canary_failure(self, mock_db, mock_executor, device_configs):
        """Test canary deployment fails if canary devices fail."""
        strategy = CanaryDeployment(canary_percentage=33)
        deployment_id = str(uuid4())

        # Make canary deployment fail
        mock_executor.deploy_to_device.return_value = {"status": "failed", "error": "Connection timeout"}
        mock_executor.verify_deployment.return_value = False

        with pytest.raises(DeploymentFailed):
            await strategy.execute(
                deployment_id=deployment_id,
                device_configs=device_configs,
                executor=mock_executor,
                db=mock_db
            )

    @pytest.mark.asyncio
    async def test_canary_deployment_with_health_check(self, mock_db, mock_executor, device_configs):
        """Test canary deployment performs health checks."""
        strategy = CanaryDeployment(
            canary_percentage=33,
            health_check_interval=5,
            health_check_duration=30
        )
        deployment_id = str(uuid4())

        result = await strategy.execute(
            deployment_id=deployment_id,
            device_configs=device_configs,
            executor=mock_executor,
            db=mock_db
        )

        # Verify health checks were performed
        assert mock_executor.verify_deployment.called

    @pytest.mark.asyncio
    async def test_canary_deployment_progressive_rollout(self, mock_db, mock_executor):
        """Test canary progressively rolls out to all devices."""
        strategy = CanaryDeployment(canary_percentage=25)
        deployment_id = str(uuid4())

        configs = [{"device_id": str(uuid4()), "hostname": f"device{i}"} for i in range(8)]

        result = await strategy.execute(
            deployment_id=deployment_id,
            device_configs=configs,
            executor=mock_executor,
            db=mock_db
        )

        # With 8 devices and 25% canary, should deploy to 2 devices first, then remaining 6
        assert result["total_devices"] == 8
        assert mock_executor.deploy_to_device.call_count == 8


class TestRollingDeployment:
    """Test rolling deployment strategy."""

    @pytest.mark.asyncio
    async def test_rolling_deployment_success(self, mock_db, mock_executor, device_configs):
        """Test successful rolling deployment."""
        strategy = RollingDeployment(batch_size=1)
        deployment_id = str(uuid4())

        result = await strategy.execute(
            deployment_id=deployment_id,
            device_configs=device_configs,
            executor=mock_executor,
            db=mock_db
        )

        assert result["status"] == "success"
        assert result["total_devices"] == 3
        assert result["batches"] == 3  # 3 devices, batch size 1 = 3 batches

    @pytest.mark.asyncio
    async def test_rolling_deployment_batch_size(self, mock_db, mock_executor):
        """Test rolling deployment respects batch size."""
        strategy = RollingDeployment(batch_size=2)
        deployment_id = str(uuid4())

        configs = [{"device_id": str(uuid4()), "hostname": f"device{i}"} for i in range(6)]

        result = await strategy.execute(
            deployment_id=deployment_id,
            device_configs=configs,
            executor=mock_executor,
            db=mock_db
        )

        # 6 devices, batch size 2 = 3 batches
        assert result["batches"] == 3

    @pytest.mark.asyncio
    async def test_rolling_deployment_stops_on_failure(self, mock_db, mock_executor, device_configs):
        """Test rolling deployment stops on batch failure."""
        strategy = RollingDeployment(batch_size=1, stop_on_failure=True)
        deployment_id = str(uuid4())

        # Make second deployment fail
        mock_executor.deploy_to_device.side_effect = [
            {"status": "success"},
            {"status": "failed", "error": "Config syntax error"},
            {"status": "success"}
        ]

        with pytest.raises(DeploymentFailed):
            await strategy.execute(
                deployment_id=deployment_id,
                device_configs=device_configs,
                executor=mock_executor,
                db=mock_db
            )

        # Should have attempted only 2 deployments before stopping
        assert mock_executor.deploy_to_device.call_count == 2

    @pytest.mark.asyncio
    async def test_rolling_deployment_with_delay(self, mock_db, mock_executor, device_configs):
        """Test rolling deployment respects batch delay."""
        strategy = RollingDeployment(batch_size=1, batch_delay_seconds=2)
        deployment_id = str(uuid4())

        with patch('asyncio.sleep', new_callable=AsyncMock) as mock_sleep:
            result = await strategy.execute(
                deployment_id=deployment_id,
                device_configs=device_configs,
                executor=mock_executor,
                db=mock_db
            )

            # Should have delays between batches (3 devices, 1 per batch = 2 delays)
            assert mock_sleep.call_count >= 2

    @pytest.mark.asyncio
    async def test_rolling_deployment_percentage_based(self, mock_db, mock_executor):
        """Test rolling deployment with percentage-based batches."""
        strategy = RollingDeployment(batch_percentage=25)
        deployment_id = str(uuid4())

        configs = [{"device_id": str(uuid4()), "hostname": f"device{i}"} for i in range(8)}

        result = await strategy.execute(
            deployment_id=deployment_id,
            device_configs=configs,
            executor=mock_executor,
            db=mock_db
        )

        # 8 devices, 25% batches = 2 devices per batch = 4 batches
        assert result["batches"] == 4


class TestBlueGreenDeployment:
    """Test blue-green deployment strategy."""

    @pytest.mark.asyncio
    async def test_blue_green_deployment_success(self, mock_db, mock_executor, device_configs):
        """Test successful blue-green deployment."""
        strategy = BlueGreenDeployment()
        deployment_id = str(uuid4())

        result = await strategy.execute(
            deployment_id=deployment_id,
            device_configs=device_configs,
            executor=mock_executor,
            db=mock_db
        )

        assert result["status"] == "success"
        assert result["total_devices"] == 3

    @pytest.mark.asyncio
    async def test_blue_green_deploys_to_green_first(self, mock_db, mock_executor, device_configs):
        """Test blue-green deploys to green environment first."""
        strategy = BlueGreenDeployment()
        deployment_id = str(uuid4())

        result = await strategy.execute(
            deployment_id=deployment_id,
            device_configs=device_configs,
            executor=mock_executor,
            db=mock_db
        )

        # Verify deployment was staged to green environment
        assert "green_deployment" in result
        assert result["green_deployment"]["status"] == "success"

    @pytest.mark.asyncio
    async def test_blue_green_switches_traffic_after_validation(self, mock_db, mock_executor, device_configs):
        """Test blue-green switches traffic after green validation."""
        strategy = BlueGreenDeployment(validation_period_seconds=10)
        deployment_id = str(uuid4())

        with patch.object(strategy, '_switch_traffic', new_callable=AsyncMock) as mock_switch:
            mock_switch.return_value = {"status": "switched"}

            result = await strategy.execute(
                deployment_id=deployment_id,
                device_configs=device_configs,
                executor=mock_executor,
                db=mock_db
            )

            # Traffic switch should have been called
            mock_switch.assert_called_once()

    @pytest.mark.asyncio
    async def test_blue_green_rollback_on_green_failure(self, mock_db, mock_executor, device_configs):
        """Test blue-green rolls back if green deployment fails."""
        strategy = BlueGreenDeployment()
        deployment_id = str(uuid4())

        # Make green deployment fail
        mock_executor.deploy_to_device.return_value = {"status": "failed", "error": "Validation failed"}
        mock_executor.verify_deployment.return_value = False

        with pytest.raises(DeploymentFailed):
            await strategy.execute(
                deployment_id=deployment_id,
                device_configs=device_configs,
                executor=mock_executor,
                db=mock_db
            )

    @pytest.mark.asyncio
    async def test_blue_green_zero_downtime(self, mock_db, mock_executor, device_configs):
        """Test blue-green deployment maintains zero downtime."""
        strategy = BlueGreenDeployment()
        deployment_id = str(uuid4())

        result = await strategy.execute(
            deployment_id=deployment_id,
            device_configs=device_configs,
            executor=mock_executor,
            db=mock_db
        )

        # Should indicate zero downtime
        assert result.get("downtime_seconds", 0) == 0


class TestAllAtOnceDeployment:
    """Test all-at-once deployment strategy."""

    @pytest.mark.asyncio
    async def test_all_at_once_deployment_success(self, mock_db, mock_executor, device_configs):
        """Test successful all-at-once deployment."""
        strategy = AllAtOnceDeployment()
        deployment_id = str(uuid4())

        result = await strategy.execute(
            deployment_id=deployment_id,
            device_configs=device_configs,
            executor=mock_executor,
            db=mock_db
        )

        assert result["status"] == "success"
        assert result["total_devices"] == 3
        # All devices should be deployed to
        assert mock_executor.deploy_to_device.call_count == 3

    @pytest.mark.asyncio
    async def test_all_at_once_deploys_concurrently(self, mock_db, mock_executor, device_configs):
        """Test all-at-once deploys to all devices concurrently."""
        strategy = AllAtOnceDeployment()
        deployment_id = str(uuid4())

        with patch('asyncio.gather', new_callable=AsyncMock) as mock_gather:
            mock_gather.return_value = [{"status": "success"}] * 3

            result = await strategy.execute(
                deployment_id=deployment_id,
                device_configs=device_configs,
                executor=mock_executor,
                db=mock_db
            )

            # asyncio.gather should be used for concurrent execution
            mock_gather.assert_called()

    @pytest.mark.asyncio
    async def test_all_at_once_handles_partial_failure(self, mock_db, mock_executor, device_configs):
        """Test all-at-once handles partial failures."""
        strategy = AllAtOnceDeployment(fail_fast=False)
        deployment_id = str(uuid4())

        # Make one device fail
        mock_executor.deploy_to_device.side_effect = [
            {"status": "success"},
            {"status": "failed", "error": "Connection refused"},
            {"status": "success"}
        ]

        result = await strategy.execute(
            deployment_id=deployment_id,
            device_configs=device_configs,
            executor=mock_executor,
            db=mock_db
        )

        # Should complete with partial failure
        assert result["status"] == "partial_failure"
        assert result["failed_devices"] == 1
        assert result["successful_devices"] == 2

    @pytest.mark.asyncio
    async def test_all_at_once_fail_fast_mode(self, mock_db, mock_executor, device_configs):
        """Test all-at-once fails fast when enabled."""
        strategy = AllAtOnceDeployment(fail_fast=True)
        deployment_id = str(uuid4())

        # Make deployment fail
        mock_executor.deploy_to_device.return_value = {"status": "failed", "error": "Invalid config"}

        with pytest.raises(DeploymentFailed):
            await strategy.execute(
                deployment_id=deployment_id,
                device_configs=device_configs,
                executor=mock_executor,
                db=mock_db
            )


class TestDeploymentStrategyBase:
    """Test base deployment strategy functionality."""

    @pytest.mark.asyncio
    async def test_create_task_success(self, mock_db):
        """Test task creation."""
        strategy = AllAtOnceDeployment()
        deployment_id = str(uuid4())

        task = await strategy._create_task(
            db=mock_db,
            deployment_id=deployment_id,
            name="Deploy to device1",
            task_type="device_deployment",
            payload={"device_id": "123"}
        )

        assert task is not None
        assert task.name == "Deploy to device1"
        assert task.deployment_id == deployment_id
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_task_status(self, mock_db):
        """Test task status update."""
        strategy = AllAtOnceDeployment()

        mock_task = Mock()
        mock_task.started_at = datetime.utcnow()

        await strategy._update_task(
            db=mock_db,
            task=mock_task,
            status="completed",
            result={"status": "success"}
        )

        assert mock_task.status == "completed"
        assert mock_task.result == {"status": "success"}
        mock_db.commit.assert_called_once()


class TestEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.mark.asyncio
    async def test_deployment_with_empty_device_list(self, mock_db, mock_executor):
        """Test deployment with no devices."""
        strategy = AllAtOnceDeployment()
        deployment_id = str(uuid4())

        with pytest.raises(ValueError):
            await strategy.execute(
                deployment_id=deployment_id,
                device_configs=[],
                executor=mock_executor,
                db=mock_db
            )

    @pytest.mark.asyncio
    async def test_canary_with_invalid_percentage(self, mock_db, mock_executor, device_configs):
        """Test canary deployment with invalid percentage."""
        with pytest.raises(ValueError):
            CanaryDeployment(canary_percentage=150)

    @pytest.mark.asyncio
    async def test_rolling_with_zero_batch_size(self, mock_db, mock_executor, device_configs):
        """Test rolling deployment with invalid batch size."""
        with pytest.raises(ValueError):
            RollingDeployment(batch_size=0)

    @pytest.mark.asyncio
    async def test_deployment_with_none_executor(self, mock_db, device_configs):
        """Test deployment fails gracefully with None executor."""
        strategy = AllAtOnceDeployment()
        deployment_id = str(uuid4())

        with pytest.raises((ValueError, TypeError, AttributeError)):
            await strategy.execute(
                deployment_id=deployment_id,
                device_configs=device_configs,
                executor=None,
                db=mock_db
            )
