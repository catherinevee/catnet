"""
Deployment strategies for network configuration deployment.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
import asyncio
from enum import Enum

from ..core.logging import get_logger
from ..core.exceptions import DeploymentError
from ..db.models import Device, DeploymentState
from ..devices.connector import SecureDeviceConnector as DeviceConnector
from ..security.vault import VaultClient
from ..security.audit import AuditLogger

logger = get_logger(__name__)


class StrategyType(Enum):
    """Deployment strategy types."""

    CANARY = "canary"
    ROLLING = "rolling"
    BLUE_GREEN = "blue_green"
    ALL_AT_ONCE = "all_at_once"


@dataclass
class DeploymentStage:
    """Represents a deployment stage."""

    percentage: int
    wait_minutes: int
    validation_required: bool = True
    rollback_on_failure: bool = True


class BaseStrategy:
    """Base class for deployment strategies."""

    def __init__(self):
        self.connector = DeviceConnector()
        self.vault = VaultClient()
        self.audit = AuditLogger()
        self.deployed_devices: List[str] = []
        self.backup_map: Dict[str, str] = {}

    async def backup_device(self, device: Device) -> str:
        """Create device configuration backup."""
        logger.info(f"Creating backup for device {device.hostname}")
        try:
            # Connect to device
            connection = await self.connector.connect(device)

            # Get current configuration
            config = await connection.get_config()

            # Store backup with timestamp
            backup_id = f"{device.id}_{datetime.utcnow().isoformat()}"
            await self.vault.store_secret(
                f"backups/{backup_id}",
                {"config": config, "device_id": device.id, "timestamp": datetime.utcnow().isoformat()},
            )

            self.backup_map[device.id] = backup_id
            logger.info(f"Backup created for device {device.hostname}: {backup_id}")
            return backup_id

        except Exception as e:
            logger.error(f"Failed to backup device {device.hostname}: {e}")
            raise DeploymentError(f"Backup failed for {device.hostname}: {e}")

    async def deploy_to_device(self, device: Device, config: Dict[str, Any]) -> bool:
        """Deploy configuration to a single device."""
        logger.info(f"Deploying to device {device.hostname}")
        try:
            # Connect to device
            connection = await self.connector.connect(device)

            # Apply configuration
            result = await connection.apply_config(config)

            # Save configuration
            await connection.save_config()

            # Verify deployment
            if not await self.validate_device_health(device):
                raise DeploymentError(f"Health check failed for {device.hostname}")

            self.deployed_devices.append(device.id)
            logger.info(f"Successfully deployed to device {device.hostname}")
            return True

        except Exception as e:
            logger.error(f"Failed to deploy to device {device.hostname}: {e}")
            raise DeploymentError(f"Deployment failed for {device.hostname}: {e}")

    async def validate_device_health(self, device: Device) -> bool:
        """Validate device health after deployment."""
        logger.info(f"Validating health for device {device.hostname}")
        try:
            connection = await self.connector.connect(device)

            # Check basic connectivity
            if not await connection.test_connectivity():
                return False

            # Check interface status
            interfaces = await connection.get_interfaces()
            critical_down = any(i.get("critical") and not i.get("up") for i in interfaces)
            if critical_down:
                logger.warning(f"Critical interface down on {device.hostname}")
                return False

            # Check routing
            routes = await connection.get_routes()
            if not routes:
                logger.warning(f"No routes on {device.hostname}")
                return False

            logger.info(f"Health check passed for device {device.hostname}")
            return True

        except Exception as e:
            logger.error(f"Health check failed for {device.hostname}: {e}")
            return False

    async def rollback_device(self, device: Device, backup_id: str) -> bool:
        """Rollback device to previous configuration."""
        logger.warning(f"Rolling back device {device.hostname} to backup {backup_id}")
        try:
            # Get backup configuration
            backup = await self.vault.get_secret(f"backups/{backup_id}")
            if not backup:
                raise DeploymentError(f"Backup {backup_id} not found")

            # Connect and apply backup
            connection = await self.connector.connect(device)
            await connection.apply_config(backup["config"])
            await connection.save_config()

            # Verify rollback
            if await self.validate_device_health(device):
                logger.info(f"Successfully rolled back device {device.hostname}")
                return True
            else:
                logger.error(f"Rollback verification failed for {device.hostname}")
                return False

        except Exception as e:
            logger.error(f"Rollback failed for {device.hostname}: {e}")
            return False

    async def rollback_all(self, devices: List[Device]) -> int:
        """Rollback all devices."""
        logger.warning(f"Rolling back {len(devices)} devices")
        rollback_count = 0

        for device in devices:
            if device.id in self.backup_map:
                if await self.rollback_device(device, self.backup_map[device.id]):
                    rollback_count += 1
                    if device.id in self.deployed_devices:
                        self.deployed_devices.remove(device.id)

        logger.info(f"Rolled back {rollback_count}/{len(devices)} devices")
        return rollback_count

    async def monitor_health(self, devices: List[Device], duration_minutes: int) -> bool:
        """Monitor device health for specified duration."""
        logger.info(f"Monitoring {len(devices)} devices for {duration_minutes} minutes")
        end_time = datetime.utcnow() + timedelta(minutes=duration_minutes)
        check_interval = min(60, duration_minutes * 60 // 10)  # Check at least 10 times

        while datetime.utcnow() < end_time:
            unhealthy = []
            for device in devices:
                if not await self.validate_device_health(device):
                    unhealthy.append(device)

            if unhealthy:
                logger.error(f"{len(unhealthy)} devices unhealthy during monitoring")
                return False

            await asyncio.sleep(check_interval)

        logger.info("Monitoring period completed successfully")
        return True

    async def execute(self, devices: List[Device], config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute deployment strategy."""
        raise NotImplementedError("Subclasses must implement execute method")


class CanaryStrategy(BaseStrategy):
    """Canary deployment strategy - progressive rollout."""

    def __init__(self, stages: Optional[List[DeploymentStage]] = None):
        super().__init__()
        self.stages = stages or [
            DeploymentStage(percentage=5, wait_minutes=5),
            DeploymentStage(percentage=25, wait_minutes=10),
            DeploymentStage(percentage=50, wait_minutes=15),
            DeploymentStage(percentage=100, wait_minutes=0),
        ]

    async def execute(self, devices: List[Device], config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute canary deployment."""
        logger.info(f"Starting canary deployment for {len(devices)} devices")
        start_time = datetime.utcnow()
        deployed = []
        failed = []

        # Randomize device order for better distribution
        import random
        devices = devices.copy()
        random.shuffle(devices)

        # Backup all devices first
        logger.info("Creating backups for all devices")
        for device in devices:
            try:
                await self.backup_device(device)
            except Exception as e:
                logger.error(f"Backup failed for {device.hostname}: {e}")
                failed.append(device)

        # Remove failed devices from deployment
        devices = [d for d in devices if d not in failed]

        # Execute stages
        for stage_idx, stage in enumerate(self.stages):
            logger.info(
                f"Stage {stage_idx + 1}/{len(self.stages)}: "
                f"Deploying to {stage.percentage}% of devices"
            )

            # Calculate devices for this stage
            target_count = int(len(devices) * stage.percentage / 100)
            stage_devices = devices[:target_count]
            new_devices = [d for d in stage_devices if d not in deployed]

            # Deploy to new devices
            for device in new_devices:
                try:
                    await self.deploy_to_device(device, config)
                    deployed.append(device)
                except Exception as e:
                    logger.error(f"Deployment failed for {device.hostname}: {e}")
                    failed.append(device)

                    if stage.rollback_on_failure:
                        logger.warning("Rolling back due to failure")
                        await self.rollback_all(deployed)
                        raise DeploymentError(
                            f"Canary deployment failed at {stage.percentage}%: {e}"
                        )

            # Wait and monitor
            if stage.wait_minutes > 0 and deployed:
                logger.info(f"Waiting {stage.wait_minutes} minutes before next stage")
                if not await self.monitor_health(deployed, stage.wait_minutes):
                    logger.error("Health monitoring failed")
                    if stage.rollback_on_failure:
                        await self.rollback_all(deployed)
                        raise DeploymentError(
                            f"Health check failed at {stage.percentage}%"
                        )

        # Final result
        duration = (datetime.utcnow() - start_time).total_seconds()
        result = {
            "strategy": "canary",
            "total_devices": len(devices) + len(failed),
            "deployed": len(deployed),
            "failed": len(failed),
            "duration_seconds": duration,
            "success": len(failed) == 0,
            "state": DeploymentState.COMPLETED if len(failed) == 0 else DeploymentState.FAILED,
            "deployed_devices": [d.id for d in deployed],
            "failed_devices": [d.id for d in failed],
        }

        logger.info(f"Canary deployment completed: {result}")
        return result


class RollingStrategy(BaseStrategy):
    """Rolling deployment strategy - sequential deployment."""

    def __init__(self, batch_size: int = 5, wait_between_batches: int = 2):
        super().__init__()
        self.batch_size = batch_size
        self.wait_between_batches = wait_between_batches

    async def execute(self, devices: List[Device], config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute rolling deployment."""
        logger.info(
            f"Starting rolling deployment for {len(devices)} devices "
            f"(batch size: {self.batch_size})"
        )
        start_time = datetime.utcnow()
        deployed = []
        failed = []

        # Create batches
        batches = [
            devices[i : i + self.batch_size]
            for i in range(0, len(devices), self.batch_size)
        ]

        for batch_idx, batch in enumerate(batches):
            logger.info(
                f"Processing batch {batch_idx + 1}/{len(batches)} "
                f"({len(batch)} devices)"
            )

            # Backup batch
            for device in batch:
                try:
                    await self.backup_device(device)
                except Exception as e:
                    logger.error(f"Backup failed for {device.hostname}: {e}")
                    failed.append(device)

            # Deploy to batch (excluding failed backups)
            batch_to_deploy = [d for d in batch if d not in failed]
            batch_deployed = []

            for device in batch_to_deploy:
                try:
                    await self.deploy_to_device(device, config)
                    deployed.append(device)
                    batch_deployed.append(device)
                except Exception as e:
                    logger.error(f"Deployment failed for {device.hostname}: {e}")
                    failed.append(device)

            # Validate batch health
            if batch_deployed:
                if not await self.validate_batch_health(batch_deployed):
                    logger.warning(f"Batch {batch_idx + 1} health check failed")
                    # Rollback this batch
                    await self.rollback_all(batch_deployed)
                    for device in batch_deployed:
                        deployed.remove(device)
                        failed.append(device)

            # Wait between batches
            if batch_idx < len(batches) - 1 and self.wait_between_batches > 0:
                logger.info(
                    f"Waiting {self.wait_between_batches} minutes before next batch"
                )
                await asyncio.sleep(self.wait_between_batches * 60)

        # Final result
        duration = (datetime.utcnow() - start_time).total_seconds()
        result = {
            "strategy": "rolling",
            "total_devices": len(devices),
            "deployed": len(deployed),
            "failed": len(failed),
            "batches": len(batches),
            "batch_size": self.batch_size,
            "duration_seconds": duration,
            "success": len(failed) == 0,
            "state": DeploymentState.COMPLETED if len(failed) == 0 else DeploymentState.FAILED,
            "deployed_devices": [d.id for d in deployed],
            "failed_devices": [d.id for d in failed],
        }

        logger.info(f"Rolling deployment completed: {result}")
        return result

    async def validate_batch_health(self, devices: List[Device]) -> bool:
        """Validate health of a batch of devices."""
        logger.info(f"Validating batch health for {len(devices)} devices")
        results = await asyncio.gather(
            *[self.validate_device_health(device) for device in devices],
            return_exceptions=True,
        )

        healthy_count = sum(1 for r in results if r is True)
        logger.info(f"Batch health: {healthy_count}/{len(devices)} devices healthy")

        # Require at least 80% healthy
        return healthy_count >= len(devices) * 0.8


class BlueGreenStrategy(BaseStrategy):
    """Blue-Green deployment strategy - instant switchover."""

    def __init__(self, validation_time: int = 10):
        super().__init__()
        self.validation_time = validation_time
        self.green_configs: Dict[str, Any] = {}

    async def execute(self, devices: List[Device], config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute blue-green deployment."""
        logger.info(f"Starting blue-green deployment for {len(devices)} devices")
        start_time = datetime.utcnow()
        deployed = []
        failed = []

        # Phase 1: Prepare green environment (staging config)
        logger.info("Phase 1: Preparing green environment")
        for device in devices:
            try:
                # Backup current (blue) configuration
                await self.backup_device(device)

                # Prepare green configuration
                self.green_configs[device.id] = await self.prepare_green_config(
                    device, config
                )
            except Exception as e:
                logger.error(f"Green preparation failed for {device.hostname}: {e}")
                failed.append(device)

        # Remove failed devices
        devices_to_deploy = [d for d in devices if d not in failed]

        # Phase 2: Deploy to green (staged deployment)
        logger.info("Phase 2: Deploying to green environment")
        for device in devices_to_deploy:
            try:
                await self.deploy_green_config(device, self.green_configs[device.id])
                deployed.append(device)
            except Exception as e:
                logger.error(f"Green deployment failed for {device.hostname}: {e}")
                failed.append(device)

        if not deployed:
            raise DeploymentError("No devices successfully deployed to green")

        # Phase 3: Validation
        logger.info(
            f"Phase 3: Validating green environment for {self.validation_time} minutes"
        )
        validation_passed = await self.monitor_health(deployed, self.validation_time)

        if not validation_passed:
            # Rollback to blue
            logger.warning("Validation failed, rolling back to blue")
            await self.rollback_all(deployed)
            raise DeploymentError("Green environment validation failed")

        # Phase 4: Switch to green (make active)
        logger.info("Phase 4: Switching to green environment")
        switch_success = await self.switch_to_green(deployed)

        if not switch_success:
            logger.error("Switch to green failed")
            await self.rollback_all(deployed)
            raise DeploymentError("Failed to switch to green environment")

        # Final result
        duration = (datetime.utcnow() - start_time).total_seconds()
        result = {
            "strategy": "blue_green",
            "total_devices": len(devices) + len(failed),
            "deployed": len(deployed),
            "failed": len(failed),
            "validation_time": self.validation_time,
            "duration_seconds": duration,
            "success": len(failed) == 0 and switch_success,
            "deployed_devices": [d.id for d in deployed],
            "failed_devices": [d.id for d in failed],
        }

        logger.info(f"Blue-green deployment completed: {result}")
        return result

    async def prepare_green_config(self, device: Device, config: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare green (new) configuration for device."""
        logger.debug(f"Preparing green config for {device.hostname}")

        # Vendor-specific configuration preparation
        if device.vendor.lower() == "cisco":
            green_config = self.prepare_cisco_green(config)
        elif device.vendor.lower() == "juniper":
            green_config = self.prepare_juniper_green(config)
        else:
            green_config = config

        return green_config

    def prepare_cisco_green(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare Cisco green configuration."""
        # Add staging/green specific configuration
        green_config = config.copy()
        green_config["staging"] = True
        return green_config

    def prepare_juniper_green(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare Juniper green configuration."""
        # Add configuration groups for staging
        green_config = config.copy()
        green_config["apply_groups"] = ["green-deployment"]
        return green_config

    async def deploy_green_config(self, device: Device, green_config: Dict[str, Any]) -> bool:
        """Deploy green configuration to device."""
        logger.info(f"Deploying green config to {device.hostname}")

        # Deploy but don't activate yet
        connection = await self.connector.connect(device)
        await connection.stage_config(green_config)

        return True

    async def switch_to_green(self, devices: List[Device]) -> bool:
        """Switch from blue to green configuration."""
        logger.info(f"Switching {len(devices)} devices to green")

        switch_tasks = [self.activate_green_on_device(device) for device in devices]
        results = await asyncio.gather(*switch_tasks, return_exceptions=True)

        success_count = sum(1 for r in results if r is True)
        logger.info(f"Switched {success_count}/{len(devices)} devices to green")

        return success_count == len(devices)

    async def activate_green_on_device(self, device: Device) -> bool:
        """Activate green configuration on a single device."""
        try:
            connection = await self.connector.connect(device)
            await connection.activate_staged_config()
            await connection.save_config()
            logger.info(f"Activated green on {device.hostname}")
            return True
        except Exception as e:
            logger.error(f"Failed to activate green on {device.hostname}: {e}")
            return False


class AllAtOnceStrategy(BaseStrategy):
    """All-at-once deployment strategy - deploy to all devices simultaneously."""

    async def execute(self, devices: List[Device], config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute all-at-once deployment."""
        logger.info(f"Starting all-at-once deployment for {len(devices)} devices")
        start_time = datetime.utcnow()

        # Backup all devices first
        logger.info("Creating backups for all devices")
        backup_tasks = [self.backup_device(device) for device in devices]
        backup_results = await asyncio.gather(*backup_tasks, return_exceptions=True)

        # Identify backup failures
        backup_failed = []
        for idx, result in enumerate(backup_results):
            if isinstance(result, Exception):
                logger.error(f"Backup failed for {devices[idx].hostname}: {result}")
                backup_failed.append(devices[idx])

        # Deploy to all devices (excluding backup failures)
        devices_to_deploy = [d for d in devices if d not in backup_failed]
        logger.info(f"Deploying to {len(devices_to_deploy)} devices simultaneously")

        deploy_tasks = [
            self.deploy_to_device(device, config) for device in devices_to_deploy
        ]
        deploy_results = await asyncio.gather(*deploy_tasks, return_exceptions=True)

        # Categorize results
        deployed = []
        failed = backup_failed.copy()

        for idx, result in enumerate(deploy_results):
            if isinstance(result, Exception):
                logger.error(
                    f"Deployment failed for {devices_to_deploy[idx].hostname}: {result}"
                )
                failed.append(devices_to_deploy[idx])
            elif result:
                deployed.append(devices_to_deploy[idx])

        # Final validation
        if deployed:
            logger.info(f"Validating {len(deployed)} deployed devices")
            validation_passed = await self.validate_all_devices(deployed)
            if not validation_passed:
                logger.warning("Validation failed, consider rollback")

        # Final result
        duration = (datetime.utcnow() - start_time).total_seconds()
        result = {
            "strategy": "all_at_once",
            "total_devices": len(devices),
            "deployed": len(deployed),
            "failed": len(failed),
            "duration_seconds": duration,
            "success": len(failed) == 0,
            "deployed_devices": [d.id for d in deployed],
            "failed_devices": [d.id for d in failed],
        }

        logger.info(f"All-at-once deployment completed: {result}")
        return result

    async def validate_all_devices(self, devices: List[Device]) -> bool:
        """Validate all devices after deployment."""
        validation_tasks = [self.validate_device_health(device) for device in devices]
        results = await asyncio.gather(*validation_tasks, return_exceptions=True)

        healthy_count = sum(1 for r in results if r is True)
        logger.info(f"Validation: {healthy_count}/{len(devices)} devices healthy")

        return healthy_count == len(devices)


def get_strategy(strategy_type: str) -> BaseStrategy:
    """Get deployment strategy instance by type."""
    strategies = {
        "canary": CanaryStrategy,
        "rolling": RollingStrategy,
        "blue_green": BlueGreenStrategy,
        "all_at_once": AllAtOnceStrategy,
    }

    strategy_class = strategies.get(strategy_type.lower())
    if not strategy_class:
        raise ValueError(f"Unknown strategy type: {strategy_type}")

    return strategy_class()
