"""
Deployment strategy implementations.
"""

import asyncio
import random
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timedelta
import math

import httpx
import redis.asyncio as redis

from src.core.logging import get_logger
from src.core.config import get_settings
from src.security.vault import VaultClient
from .models import DeviceStatus, CanaryConfig, RollingConfig, BlueGreenConfig

logger = get_logger(__name__)
settings = get_settings()


class DeploymentResult:
    """Deployment execution result."""

    def __init__(self):
        self.success = False
        self.successful_devices = []
        self.failed_devices = []
        self.skipped_devices = []
        self.device_results = {}
        self.total_time = 0
        self.avg_device_time = 0
        self.errors = []
        self.rollback_performed = False
        self.rollback_result = None

    def dict(self):
        """Convert to dictionary."""
        return {
            'success': self.success,
            'successful_devices': self.successful_devices,
            'failed_devices': self.failed_devices,
            'skipped_devices': self.skipped_devices,
            'device_results': self.device_results,
            'total_time': self.total_time,
            'avg_device_time': self.avg_device_time,
            'errors': self.errors,
            'rollback_performed': self.rollback_performed,
            'rollback_result': self.rollback_result
        }


class DeploymentStrategy(ABC):
    """Base deployment strategy."""

    def __init__(self):
        self.vault = VaultClient()
        self.redis = None
        self.cancelled = False

    async def initialize(self):
        """Initialize strategy."""
        self.redis = await redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True
        )

    @abstractmethod
    async def execute(
        self,
        deployment_id: str,
        config: Dict[str, Any],
        devices: List[str],
        dry_run: bool = False,
        max_parallel: int = 10,
        timeout: int = 3600
    ) -> DeploymentResult:
        """
        Execute deployment strategy.

        Args:
            deployment_id: Deployment ID
            config: Configuration to deploy
            devices: Target devices
            dry_run: Perform dry run only
            max_parallel: Maximum parallel deployments
            timeout: Deployment timeout in seconds

        Returns:
            Deployment result
        """
        pass

    async def deploy_to_device(
        self,
        device_id: str,
        config: Dict[str, Any],
        deployment_id: str,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Deploy configuration to single device.

        Args:
            device_id: Device ID
            config: Configuration
            deployment_id: Deployment ID
            dry_run: Dry run mode

        Returns:
            Deployment result for device
        """
        try:
            start_time = datetime.utcnow()

            # Check if cancelled
            if await self._is_cancelled(deployment_id):
                return {
                    'device_id': device_id,
                    'status': 'cancelled',
                    'error': 'Deployment cancelled'
                }

            # Update device status
            await self._update_device_status(
                deployment_id,
                device_id,
                DeviceStatus.IN_PROGRESS
            )

            if dry_run:
                # Simulate deployment
                await asyncio.sleep(random.uniform(1, 3))
                success = random.random() > 0.1  # 90% success rate in dry run
            else:
                # Call device service to deploy
                success = await self._deploy_via_device_service(
                    device_id,
                    config,
                    deployment_id
                )

            # Update device status
            status = DeviceStatus.COMPLETED if success else DeviceStatus.FAILED
            await self._update_device_status(deployment_id, device_id, status)

            duration = (datetime.utcnow() - start_time).total_seconds()

            return {
                'device_id': device_id,
                'status': 'success' if success else 'failed',
                'duration': duration,
                'dry_run': dry_run
            }

        except Exception as e:
            logger.error(f"Failed to deploy to device {device_id}: {e}")
            await self._update_device_status(
                deployment_id,
                device_id,
                DeviceStatus.FAILED
            )
            return {
                'device_id': device_id,
                'status': 'failed',
                'error': str(e)
            }

    async def validate_device_health(
        self,
        device_id: str,
        deployment_id: str
    ) -> bool:
        """
        Validate device health after deployment.

        Args:
            device_id: Device ID
            deployment_id: Deployment ID

        Returns:
            True if healthy
        """
        try:
            # Call monitoring service
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://monitoring-service:8085/devices/{device_id}/health",
                    headers={"Authorization": f"Bearer {await self._get_service_token()}"}
                )

                if response.status_code == 200:
                    health = response.json()
                    return health['status'] == 'healthy'

            return False

        except Exception as e:
            logger.error(f"Health check failed for device {device_id}: {e}")
            return False

    async def backup_device(
        self,
        device_id: str,
        deployment_id: str
    ) -> Optional[str]:
        """
        Backup device configuration.

        Args:
            device_id: Device ID
            deployment_id: Deployment ID

        Returns:
            Backup ID if successful
        """
        try:
            # Call device service to create backup
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://device-service:8084/devices/{device_id}/backup",
                    json={"deployment_id": deployment_id},
                    headers={"Authorization": f"Bearer {await self._get_service_token()}"}
                )

                if response.status_code == 200:
                    result = response.json()
                    return result['backup_id']

            return None

        except Exception as e:
            logger.error(f"Backup failed for device {device_id}: {e}")
            return None

    async def _deploy_via_device_service(
        self,
        device_id: str,
        config: Dict[str, Any],
        deployment_id: str
    ) -> bool:
        """Deploy via device service."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://device-service:8084/devices/{device_id}/deploy",
                    json={
                        "deployment_id": deployment_id,
                        "config": config
                    },
                    headers={"Authorization": f"Bearer {await self._get_service_token()}"},
                    timeout=300  # 5 minutes
                )

                return response.status_code == 200

        except Exception as e:
            logger.error(f"Device service deployment failed: {e}")
            return False

    async def _update_device_status(
        self,
        deployment_id: str,
        device_id: str,
        status: DeviceStatus
    ):
        """Update device deployment status."""
        try:
            await self.redis.hset(
                f"deployment:{deployment_id}:devices",
                device_id,
                status.value
            )
        except Exception as e:
            logger.error(f"Failed to update device status: {e}")

    async def _is_cancelled(self, deployment_id: str) -> bool:
        """Check if deployment is cancelled."""
        try:
            cancelled = await self.redis.get(f"deployment:cancel:{deployment_id}")
            return cancelled == "1"
        except Exception:
            return False

    async def _get_service_token(self) -> str:
        """Get service authentication token."""
        token = await self.vault.get_secret("service/tokens/deployment")
        return token['token'] if token else ""


class CanaryStrategy(DeploymentStrategy):
    """
    Canary deployment strategy.

    Deploys to a small percentage of devices first,
    then gradually increases if successful.
    """

    def __init__(self, config: Optional[CanaryConfig] = None):
        super().__init__()
        self.config = config or CanaryConfig()

    async def execute(
        self,
        deployment_id: str,
        config: Dict[str, Any],
        devices: List[str],
        dry_run: bool = False,
        max_parallel: int = 10,
        timeout: int = 3600
    ) -> DeploymentResult:
        """Execute canary deployment."""
        await self.initialize()

        result = DeploymentResult()
        start_time = datetime.utcnow()
        deployed_devices = set()

        try:
            logger.info(f"Starting canary deployment {deployment_id} for {len(devices)} devices")

            # Backup all devices first
            logger.info("Creating backups for all devices")
            backup_tasks = [
                self.backup_device(device_id, deployment_id)
                for device_id in devices
            ]
            backup_ids = await asyncio.gather(*backup_tasks)

            # Execute canary stages
            for stage_index, stage in enumerate(self.config.stages):
                # Check if cancelled
                if await self._is_cancelled(deployment_id):
                    logger.info(f"Deployment {deployment_id} cancelled")
                    result.errors.append("Deployment cancelled")
                    break

                # Calculate devices for this stage
                target_count = math.ceil(len(devices) * stage['percentage'] / 100)
                stage_devices = devices[:target_count]
                new_devices = [d for d in stage_devices if d not in deployed_devices]

                if not new_devices:
                    continue

                logger.info(
                    f"Canary stage {stage_index + 1}: Deploying to {len(new_devices)} devices "
                    f"({stage['percentage']}% of total)"
                )

                # Deploy to new devices in parallel
                deployment_tasks = []
                for i in range(0, len(new_devices), max_parallel):
                    batch = new_devices[i:i + max_parallel]
                    batch_tasks = [
                        self.deploy_to_device(device_id, config, deployment_id, dry_run)
                        for device_id in batch
                    ]
                    batch_results = await asyncio.gather(*batch_tasks)

                    # Process batch results
                    for device_result in batch_results:
                        device_id = device_result['device_id']
                        if device_result['status'] == 'success':
                            result.successful_devices.append(device_id)
                            deployed_devices.add(device_id)
                        else:
                            result.failed_devices.append(device_id)
                            result.errors.append(
                                f"Device {device_id}: {device_result.get('error', 'Unknown error')}"
                            )
                        result.device_results[device_id] = device_result

                # Check error threshold
                if result.failed_devices:
                    error_rate = len(result.failed_devices) / len(deployed_devices)
                    if error_rate > self.config.error_threshold:
                        logger.error(
                            f"Error rate {error_rate:.2%} exceeds threshold "
                            f"{self.config.error_threshold:.2%}"
                        )

                        if self.config.auto_rollback:
                            logger.info("Initiating automatic rollback")
                            # Rollback will be handled by the service
                            result.rollback_performed = True

                        break

                # Health checks
                if stage['wait_minutes'] > 0:
                    logger.info(f"Waiting {stage['wait_minutes']} minutes for health checks")

                    # Monitor health during wait period
                    wait_until = datetime.utcnow() + timedelta(minutes=stage['wait_minutes'])
                    while datetime.utcnow() < wait_until:
                        # Check health of deployed devices
                        health_checks = await asyncio.gather(*[
                            self.validate_device_health(device_id, deployment_id)
                            for device_id in deployed_devices
                        ])

                        unhealthy_count = sum(1 for h in health_checks if not h)
                        if unhealthy_count > 0:
                            unhealthy_rate = unhealthy_count / len(deployed_devices)
                            if unhealthy_rate > self.config.error_threshold:
                                logger.error(f"Too many unhealthy devices: {unhealthy_count}")

                                if self.config.auto_rollback:
                                    result.rollback_performed = True

                                break

                        # Wait before next health check
                        await asyncio.sleep(self.config.health_check_interval)

                    # Break outer loop if health checks failed
                    if result.rollback_performed:
                        break

            # Calculate final metrics
            result.total_time = (datetime.utcnow() - start_time).total_seconds()
            if result.device_results:
                durations = [
                    r.get('duration', 0)
                    for r in result.device_results.values()
                    if 'duration' in r
                ]
                result.avg_device_time = sum(durations) / len(durations) if durations else 0

            # Determine overall success
            result.success = (
                len(result.successful_devices) > 0 and
                len(result.failed_devices) == 0 and
                not result.rollback_performed
            )

            logger.info(
                f"Canary deployment {deployment_id} completed. "
                f"Success: {len(result.successful_devices)}, "
                f"Failed: {len(result.failed_devices)}"
            )

        except Exception as e:
            logger.error(f"Canary deployment failed: {e}")
            result.errors.append(str(e))
            result.success = False

        return result


class RollingStrategy(DeploymentStrategy):
    """
    Rolling deployment strategy.

    Deploys to devices in batches with a delay between batches.
    """

    def __init__(self, config: Optional[RollingConfig] = None):
        super().__init__()
        self.config = config or RollingConfig()

    async def execute(
        self,
        deployment_id: str,
        config: Dict[str, Any],
        devices: List[str],
        dry_run: bool = False,
        max_parallel: int = 10,
        timeout: int = 3600
    ) -> DeploymentResult:
        """Execute rolling deployment."""
        await self.initialize()

        result = DeploymentResult()
        start_time = datetime.utcnow()
        failure_count = 0

        try:
            logger.info(
                f"Starting rolling deployment {deployment_id} for {len(devices)} devices "
                f"(batch_size: {self.config.batch_size})"
            )

            # Create device batches
            batches = []
            for i in range(0, len(devices), self.config.batch_size):
                batches.append(devices[i:i + self.config.batch_size])

            logger.info(f"Created {len(batches)} batches for rolling deployment")

            for batch_index, batch in enumerate(batches):
                # Check if cancelled
                if await self._is_cancelled(deployment_id):
                    logger.info(f"Deployment {deployment_id} cancelled")
                    result.errors.append("Deployment cancelled")
                    break

                logger.info(f"Processing batch {batch_index + 1}/{len(batches)}")

                # Backup devices in batch
                backup_tasks = [
                    self.backup_device(device_id, deployment_id)
                    for device_id in batch
                ]
                await asyncio.gather(*backup_tasks)

                # Deploy to batch
                if self.config.parallel_batches:
                    # Deploy to all devices in batch simultaneously
                    batch_tasks = [
                        self.deploy_to_device(device_id, config, deployment_id, dry_run)
                        for device_id in batch
                    ]
                    batch_results = await asyncio.gather(*batch_tasks)
                else:
                    # Deploy to devices in batch sequentially
                    batch_results = []
                    for device_id in batch:
                        device_result = await self.deploy_to_device(
                            device_id, config, deployment_id, dry_run
                        )
                        batch_results.append(device_result)

                # Process batch results
                batch_failures = 0
                for device_result in batch_results:
                    device_id = device_result['device_id']
                    if device_result['status'] == 'success':
                        result.successful_devices.append(device_id)
                    else:
                        result.failed_devices.append(device_id)
                        result.errors.append(
                            f"Device {device_id}: {device_result.get('error', 'Unknown error')}"
                        )
                        batch_failures += 1
                        failure_count += 1
                    result.device_results[device_id] = device_result

                # Check failure threshold
                if failure_count > self.config.max_failures:
                    logger.error(
                        f"Maximum failures ({self.config.max_failures}) exceeded"
                    )
                    break

                # Health check delay
                if self.config.health_check_delay > 0 and not dry_run:
                    logger.info(f"Waiting {self.config.health_check_delay}s for health checks")
                    await asyncio.sleep(self.config.health_check_delay)

                    # Validate health of devices in batch
                    health_checks = await asyncio.gather(*[
                        self.validate_device_health(device_id, deployment_id)
                        for device_id in batch
                        if device_id in result.successful_devices
                    ])

                    unhealthy_count = sum(1 for h in health_checks if not h)
                    if unhealthy_count > 0:
                        logger.warning(f"{unhealthy_count} devices unhealthy after deployment")

                # Batch delay (except for last batch)
                if batch_index < len(batches) - 1 and self.config.batch_delay > 0:
                    logger.info(f"Waiting {self.config.batch_delay}s before next batch")
                    await asyncio.sleep(self.config.batch_delay)

            # Calculate final metrics
            result.total_time = (datetime.utcnow() - start_time).total_seconds()
            if result.device_results:
                durations = [
                    r.get('duration', 0)
                    for r in result.device_results.values()
                    if 'duration' in r
                ]
                result.avg_device_time = sum(durations) / len(durations) if durations else 0

            # Determine overall success
            result.success = (
                len(result.successful_devices) > 0 and
                failure_count <= self.config.max_failures
            )

            logger.info(
                f"Rolling deployment {deployment_id} completed. "
                f"Success: {len(result.successful_devices)}, "
                f"Failed: {len(result.failed_devices)}"
            )

        except Exception as e:
            logger.error(f"Rolling deployment failed: {e}")
            result.errors.append(str(e))
            result.success = False

        return result


class BlueGreenStrategy(DeploymentStrategy):
    """
    Blue-green deployment strategy.

    Deploys to a parallel environment and switches traffic.
    """

    def __init__(self, config: Optional[BlueGreenConfig] = None):
        super().__init__()
        self.config = config or BlueGreenConfig()

    async def execute(
        self,
        deployment_id: str,
        config: Dict[str, Any],
        devices: List[str],
        dry_run: bool = False,
        max_parallel: int = 10,
        timeout: int = 3600
    ) -> DeploymentResult:
        """Execute blue-green deployment."""
        await self.initialize()

        result = DeploymentResult()
        start_time = datetime.utcnow()

        try:
            logger.info(
                f"Starting blue-green deployment {deployment_id} for {len(devices)} devices"
            )

            # Divide devices into blue and green groups
            split_point = len(devices) // 2
            blue_devices = devices[:split_point]
            green_devices = devices[split_point:]

            logger.info(f"Blue group: {len(blue_devices)} devices")
            logger.info(f"Green group: {len(green_devices)} devices")

            # Backup all devices
            logger.info("Creating backups for all devices")
            backup_tasks = [
                self.backup_device(device_id, deployment_id)
                for device_id in devices
            ]
            await asyncio.gather(*backup_tasks)

            # Deploy to green (new) environment
            logger.info("Deploying to green environment")
            green_tasks = []
            for i in range(0, len(green_devices), max_parallel):
                batch = green_devices[i:i + max_parallel]
                batch_tasks = [
                    self.deploy_to_device(device_id, config, deployment_id, dry_run)
                    for device_id in batch
                ]
                batch_results = await asyncio.gather(*batch_tasks)
                green_tasks.extend(batch_results)

            # Process green deployment results
            green_success = []
            green_failed = []
            for device_result in green_tasks:
                device_id = device_result['device_id']
                if device_result['status'] == 'success':
                    green_success.append(device_id)
                else:
                    green_failed.append(device_id)
                    result.errors.append(
                        f"Green device {device_id}: {device_result.get('error', 'Unknown error')}"
                    )
                result.device_results[device_id] = device_result

            # Check green deployment success
            if len(green_failed) > len(green_devices) * 0.1:  # More than 10% failed
                logger.error("Green deployment failed, aborting blue-green switch")
                result.failed_devices.extend(green_devices)
                result.success = False
                return result

            # Validation period
            if self.config.validation_period > 0 and not dry_run:
                logger.info(
                    f"Validating green environment for {self.config.validation_period}s"
                )

                validation_end = datetime.utcnow() + timedelta(
                    seconds=self.config.validation_period
                )

                while datetime.utcnow() < validation_end:
                    # Check if cancelled
                    if await self._is_cancelled(deployment_id):
                        logger.info(f"Deployment {deployment_id} cancelled")
                        result.errors.append("Deployment cancelled")
                        result.success = False
                        return result

                    # Validate green environment health
                    health_checks = await asyncio.gather(*[
                        self.validate_device_health(device_id, deployment_id)
                        for device_id in green_success
                    ])

                    unhealthy_count = sum(1 for h in health_checks if not h)
                    if unhealthy_count > len(green_success) * 0.1:
                        logger.error("Green environment unhealthy, aborting switch")
                        result.failed_devices.extend(green_devices)
                        result.success = False
                        return result

                    await asyncio.sleep(30)  # Check every 30 seconds

            # Switch traffic from blue to green
            if self.config.auto_switch:
                logger.info(f"Switching {self.config.switch_percentage}% traffic to green")

                # Deploy to blue devices (same config as green)
                logger.info("Updating blue environment")
                blue_tasks = []
                for i in range(0, len(blue_devices), max_parallel):
                    batch = blue_devices[i:i + max_parallel]
                    batch_tasks = [
                        self.deploy_to_device(device_id, config, deployment_id, dry_run)
                        for device_id in batch
                    ]
                    batch_results = await asyncio.gather(*batch_tasks)
                    blue_tasks.extend(batch_results)

                # Process blue deployment results
                for device_result in blue_tasks:
                    device_id = device_result['device_id']
                    if device_result['status'] == 'success':
                        result.successful_devices.append(device_id)
                    else:
                        result.failed_devices.append(device_id)
                        result.errors.append(
                            f"Blue device {device_id}: {device_result.get('error', 'Unknown error')}"
                        )
                    result.device_results[device_id] = device_result

                # Add green successes
                result.successful_devices.extend(green_success)
                result.failed_devices.extend(green_failed)
            else:
                logger.info("Manual switch required for blue-green deployment")
                result.successful_devices = green_success
                result.failed_devices = green_failed

            # Calculate final metrics
            result.total_time = (datetime.utcnow() - start_time).total_seconds()
            if result.device_results:
                durations = [
                    r.get('duration', 0)
                    for r in result.device_results.values()
                    if 'duration' in r
                ]
                result.avg_device_time = sum(durations) / len(durations) if durations else 0

            # Determine overall success
            result.success = len(result.failed_devices) == 0

            logger.info(
                f"Blue-green deployment {deployment_id} completed. "
                f"Success: {len(result.successful_devices)}, "
                f"Failed: {len(result.failed_devices)}"
            )

        except Exception as e:
            logger.error(f"Blue-green deployment failed: {e}")
            result.errors.append(str(e))
            result.success = False

        return result


class AllAtOnceStrategy(DeploymentStrategy):
    """
    All-at-once deployment strategy.

    Deploys to all devices simultaneously.
    """

    async def execute(
        self,
        deployment_id: str,
        config: Dict[str, Any],
        devices: List[str],
        dry_run: bool = False,
        max_parallel: int = 10,
        timeout: int = 3600
    ) -> DeploymentResult:
        """Execute all-at-once deployment."""
        await self.initialize()

        result = DeploymentResult()
        start_time = datetime.utcnow()

        try:
            logger.info(
                f"Starting all-at-once deployment {deployment_id} for {len(devices)} devices"
            )

            # Backup all devices first
            logger.info("Creating backups for all devices")
            backup_tasks = [
                self.backup_device(device_id, deployment_id)
                for device_id in devices
            ]
            await asyncio.gather(*backup_tasks)

            # Deploy to all devices
            logger.info(f"Deploying to all {len(devices)} devices")

            # Create batches based on max_parallel
            all_results = []
            for i in range(0, len(devices), max_parallel):
                # Check if cancelled
                if await self._is_cancelled(deployment_id):
                    logger.info(f"Deployment {deployment_id} cancelled")
                    result.errors.append("Deployment cancelled")
                    break

                batch = devices[i:i + max_parallel]
                batch_tasks = [
                    self.deploy_to_device(device_id, config, deployment_id, dry_run)
                    for device_id in batch
                ]
                batch_results = await asyncio.gather(*batch_tasks)
                all_results.extend(batch_results)

            # Process results
            for device_result in all_results:
                device_id = device_result['device_id']
                if device_result['status'] == 'success':
                    result.successful_devices.append(device_id)
                else:
                    result.failed_devices.append(device_id)
                    result.errors.append(
                        f"Device {device_id}: {device_result.get('error', 'Unknown error')}"
                    )
                result.device_results[device_id] = device_result

            # Calculate metrics
            result.total_time = (datetime.utcnow() - start_time).total_seconds()
            if result.device_results:
                durations = [
                    r.get('duration', 0)
                    for r in result.device_results.values()
                    if 'duration' in r
                ]
                result.avg_device_time = sum(durations) / len(durations) if durations else 0

            # Determine overall success
            result.success = len(result.failed_devices) == 0

            logger.info(
                f"All-at-once deployment {deployment_id} completed. "
                f"Success: {len(result.successful_devices)}, "
                f"Failed: {len(result.failed_devices)}"
            )

        except Exception as e:
            logger.error(f"All-at-once deployment failed: {e}")
            result.errors.append(str(e))
            result.success = False

        return result


def get_strategy(strategy_type: str) -> DeploymentStrategy:
    """
    Get deployment strategy instance.

    Args:
        strategy_type: Strategy type name

    Returns:
        Strategy instance
    """
    strategies = {
        'canary': CanaryStrategy,
        'rolling': RollingStrategy,
        'blue_green': BlueGreenStrategy,
        'all_at_once': AllAtOnceStrategy
    }

    strategy_class = strategies.get(strategy_type.lower())
    if not strategy_class:
        raise ValueError(f"Unknown strategy type: {strategy_type}")

    return strategy_class()