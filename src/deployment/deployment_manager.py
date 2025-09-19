"""
Deployment Manager for CatNet

Manages configuration deployments with:
- Multiple deployment strategies (canary, rolling, blue-green)
- Automatic rollback on failure
- Health checks and validation
- Deployment history tracking
"""

import asyncio
import uuid
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json


class DeploymentStrategy(Enum):
    """Deployment strategies"""

    CANARY = "canary"
    ROLLING = "rolling"
    BLUE_GREEN = "blue_green"
    DIRECT = "direct"


class DeploymentState(Enum):
    """Deployment states"""

    PENDING = "pending"
    VALIDATING = "validating"
    PRE_FLIGHT = "pre_flight"
    IN_PROGRESS = "in_progress"
    HEALTH_CHECK = "health_check"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    PAUSED = "paused"


class HealthCheckType(Enum):
    """Types of health checks"""

    CONNECTIVITY = "connectivity"
    PROTOCOL = "protocol"
    TRAFFIC = "traffic"
    SERVICE = "service"
    CUSTOM = "custom"


@dataclass
class DeploymentConfig:
    """Deployment configuration"""

    strategy: DeploymentStrategy = DeploymentStrategy.CANARY
    canary_percentage: int = 10
    canary_duration_minutes: int = 5
    rolling_batch_size: int = 5
    rolling_delay_seconds: int = 30
    health_check_interval_seconds: int = 60
    health_check_timeout_seconds: int = 30
    max_failures: int = 2
    auto_rollback: bool = True
    require_approval: bool = False
    dry_run: bool = False
    parallel_deployments: int = 1


@dataclass
class DeviceDeployment:
    """Individual device deployment"""

    device_id: str
    device_hostname: str
    deployment_id: str
    state: DeploymentState
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    backup_id: Optional[str] = None
    config_diff: Optional[str] = None
    errors: List[str] = field(default_factory=list)
    health_checks: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Deployment:
    """Deployment instance"""

    id: str
    name: str
    description: str
    config: DeploymentConfig
    devices: List[str]
    configuration: str
    state: DeploymentState
    created_by: str
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    device_deployments: Dict[str, DeviceDeployment] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    approval_status: Optional[str] = None
    approved_by: Optional[str] = None
    rollback_from: Optional[str] = None


class DeploymentManager:
    """
    Manages network configuration deployments
    """

    def __init__(self, device_service=None, backup_service=None, health_service=None):
        """
        Initialize deployment manager

        Args:
            device_service: Service for device operations
            backup_service: Service for backup operations
            health_service: Service for health checks
        """
        self.device_service = device_service
        self.backup_service = backup_service
        self.health_service = health_service

        self.deployments: Dict[str, Deployment] = {}
        self.active_deployments: List[str] = []
        self.deployment_history: List[str] = []

    async def create_deployment(
        self,
        name: str,
        description: str,
        devices: List[str],
        configuration: str,
        config: Optional[DeploymentConfig] = None,
        created_by: str = "system",
    ) -> str:
        """
        Create a new deployment

        Args:
            name: Deployment name
            description: Deployment description
            devices: List of device IDs
            configuration: Configuration to deploy
            config: Deployment configuration
            created_by: User creating deployment

        Returns:
            Deployment ID
        """
        deployment_id = str(uuid.uuid4())[:12]
        config = config or DeploymentConfig()

        deployment = Deployment(
            id=deployment_id,
            name=name,
            description=description,
            config=config,
            devices=devices,
            configuration=configuration,
            state=DeploymentState.PENDING,
            created_by=created_by,
            created_at=datetime.utcnow(),
        )

        # Create device deployments
        for device_id in devices:
            device_info = await self._get_device_info(device_id)
            deployment.device_deployments[device_id] = DeviceDeployment(
                device_id=device_id,
                device_hostname=device_info.get("hostname", device_id),
                deployment_id=deployment_id,
                state=DeploymentState.PENDING,
            )

        self.deployments[deployment_id] = deployment

        # Check if approval required
        if config.require_approval:
            deployment.state = DeploymentState.PENDING
            deployment.metadata["approval_required"] = True
        else:
            # Start deployment automatically
            asyncio.create_task(self.execute_deployment(deployment_id))

        return deployment_id

    async def execute_deployment(self, deployment_id: str) -> bool:
        """
        Execute a deployment

        Args:
            deployment_id: Deployment ID

        Returns:
            Success status
        """
        if deployment_id not in self.deployments:
            return False

        deployment = self.deployments[deployment_id]

        # Check if already running
        if deployment_id in self.active_deployments:
            return False

        self.active_deployments.append(deployment_id)

        try:
            # Update state
            deployment.state = DeploymentState.VALIDATING
            deployment.started_at = datetime.utcnow()

            # Pre-flight checks
            if not await self._pre_flight_checks(deployment):
                deployment.state = DeploymentState.FAILED
                deployment.errors.append("Pre-flight checks failed")
                return False

            # Execute based on strategy
            if deployment.config.strategy == DeploymentStrategy.CANARY:
                success = await self._execute_canary(deployment)
            elif deployment.config.strategy == DeploymentStrategy.ROLLING:
                success = await self._execute_rolling(deployment)
            elif deployment.config.strategy == DeploymentStrategy.BLUE_GREEN:
                success = await self._execute_blue_green(deployment)
            else:
                success = await self._execute_direct(deployment)

            # Update final state
            if success:
                deployment.state = DeploymentState.COMPLETED
            else:
                deployment.state = DeploymentState.FAILED
                if deployment.config.auto_rollback:
                    await self.rollback_deployment(deployment_id)

            deployment.completed_at = datetime.utcnow()
            self.deployment_history.append(deployment_id)

            return success

        except Exception as e:
            deployment.state = DeploymentState.FAILED
            deployment.errors.append(str(e))
            return False

        finally:
            self.active_deployments.remove(deployment_id)

    async def _execute_canary(self, deployment: Deployment) -> bool:
        """
        Execute canary deployment

        Args:
            deployment: Deployment instance

        Returns:
            Success status
        """
        deployment.state = DeploymentState.IN_PROGRESS
        total_devices = len(deployment.devices)

        # Calculate canary batch
        canary_count = max(
            1, int(total_devices * deployment.config.canary_percentage / 100)
        )
        canary_devices = deployment.devices[:canary_count]
        remaining_devices = deployment.devices[canary_count:]

        # Deploy to canary devices
        deployment.metadata["canary_phase"] = "canary"
        deployment.metadata["canary_devices"] = canary_devices

        success = await self._deploy_to_devices(deployment, canary_devices)
        if not success:
            return False

        # Wait and monitor canary
        await asyncio.sleep(deployment.config.canary_duration_minutes * 60)

        # Check canary health
        if not await self._check_deployment_health(deployment, canary_devices):
            deployment.errors.append("Canary health check failed")
            return False

        # Deploy to remaining devices
        deployment.metadata["canary_phase"] = "full"
        success = await self._deploy_to_devices(deployment, remaining_devices)

        return success

    async def _execute_rolling(self, deployment: Deployment) -> bool:
        """
        Execute rolling deployment

        Args:
            deployment: Deployment instance

        Returns:
            Success status
        """
        deployment.state = DeploymentState.IN_PROGRESS
        batch_size = deployment.config.rolling_batch_size
        delay = deployment.config.rolling_delay_seconds

        # Process in batches
        for i in range(0, len(deployment.devices), batch_size):
            batch = deployment.devices[i : i + batch_size]
            deployment.metadata["current_batch"] = i // batch_size + 1
            deployment.metadata["total_batches"] = (
                len(deployment.devices) + batch_size - 1
            ) // batch_size

            success = await self._deploy_to_devices(deployment, batch)
            if not success:
                return False

            # Wait between batches
            if i + batch_size < len(deployment.devices):
                await asyncio.sleep(delay)

        return True

    async def _execute_blue_green(self, deployment: Deployment) -> bool:
        """
        Execute blue-green deployment

        Args:
            deployment: Deployment instance

        Returns:
            Success status
        """
        deployment.state = DeploymentState.IN_PROGRESS

        # Deploy to green environment (standby)
        deployment.metadata["environment"] = "green"
        success = await self._deploy_to_devices(deployment, deployment.devices)
        if not success:
            return False

        # Validate green environment
        if not await self._check_deployment_health(deployment, deployment.devices):
            return False

        # Switch traffic to green
        deployment.metadata["environment"] = "switching"
        await self._switch_traffic(deployment)

        deployment.metadata["environment"] = "active"
        return True

    async def _execute_direct(self, deployment: Deployment) -> bool:
        """
        Execute direct deployment

        Args:
            deployment: Deployment instance

        Returns:
            Success status
        """
        deployment.state = DeploymentState.IN_PROGRESS
        return await self._deploy_to_devices(deployment, deployment.devices)

    async def _deploy_to_devices(
        self, deployment: Deployment, devices: List[str]
    ) -> bool:
        """
        Deploy to specific devices

        Args:
            deployment: Deployment instance
            devices: List of device IDs

        Returns:
            Success status
        """
        tasks = []
        for device_id in devices:
            if deployment.config.parallel_deployments > 1:
                task = asyncio.create_task(
                    self._deploy_to_device(deployment, device_id)
                )
                tasks.append(task)
            else:
                success = await self._deploy_to_device(deployment, device_id)
                if not success:
                    return False

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            failures = [r for r in results if isinstance(r, Exception) or not r]
            if len(failures) > deployment.config.max_failures:
                return False

        return True

    async def _deploy_to_device(self, deployment: Deployment, device_id: str) -> bool:
        """
        Deploy to a single device

        Args:
            deployment: Deployment instance
            device_id: Device ID

        Returns:
            Success status
        """
        device_deployment = deployment.device_deployments[device_id]
        device_deployment.state = DeploymentState.IN_PROGRESS
        device_deployment.started_at = datetime.utcnow()

        try:
            # Backup current configuration
            if not deployment.config.dry_run:
                backup_id = await self._backup_device(device_id)
                device_deployment.backup_id = backup_id

            # Generate configuration diff
            diff = await self._generate_diff(device_id, deployment.configuration)
            device_deployment.config_diff = diff

            # Apply configuration
            if not deployment.config.dry_run:
                success = await self._apply_configuration(
                    device_id, deployment.configuration
                )
                if not success:
                    device_deployment.state = DeploymentState.FAILED
                    device_deployment.errors.append("Configuration apply failed")
                    return False

            # Verify configuration
            if not await self._verify_configuration(
                device_id, deployment.configuration
            ):
                device_deployment.state = DeploymentState.FAILED
                device_deployment.errors.append("Configuration verification failed")
                return False

            # Health check
            if not await self._device_health_check(device_id, device_deployment):
                device_deployment.state = DeploymentState.FAILED
                device_deployment.errors.append("Health check failed")
                return False

            device_deployment.state = DeploymentState.COMPLETED
            device_deployment.completed_at = datetime.utcnow()
            return True

        except Exception as e:
            device_deployment.state = DeploymentState.FAILED
            device_deployment.errors.append(str(e))
            return False

    async def rollback_deployment(
        self, deployment_id: str, target_devices: Optional[List[str]] = None
    ) -> bool:
        """
        Rollback a deployment

        Args:
            deployment_id: Deployment ID
            target_devices: Specific devices to rollback (None for all)

        Returns:
            Success status
        """
        if deployment_id not in self.deployments:
            return False

        deployment = self.deployments[deployment_id]
        devices_to_rollback = target_devices or deployment.devices

        # Create rollback deployment
        rollback_id = await self.create_deployment(
            name=f"Rollback of {deployment.name}",
            description=f"Rollback deployment {deployment_id}",
            devices=devices_to_rollback,
            configuration="",  # Will restore from backup
            config=DeploymentConfig(
                strategy=DeploymentStrategy.DIRECT, auto_rollback=False
            ),
            created_by="system",
        )

        rollback = self.deployments[rollback_id]
        rollback.rollback_from = deployment_id
        rollback.state = DeploymentState.IN_PROGRESS

        # Rollback each device
        for device_id in devices_to_rollback:
            device_deployment = deployment.device_deployments.get(device_id)
            if device_deployment and device_deployment.backup_id:
                await self._restore_backup(device_id, device_deployment.backup_id)

        rollback.state = DeploymentState.COMPLETED
        deployment.state = DeploymentState.ROLLED_BACK
        return True

    async def pause_deployment(self, deployment_id: str) -> bool:
        """
        Pause a deployment

        Args:
            deployment_id: Deployment ID

        Returns:
            Success status
        """
        if deployment_id not in self.deployments:
            return False

        deployment = self.deployments[deployment_id]
        if deployment.state == DeploymentState.IN_PROGRESS:
            deployment.state = DeploymentState.PAUSED
            return True
        return False

    async def resume_deployment(self, deployment_id: str) -> bool:
        """
        Resume a paused deployment

        Args:
            deployment_id: Deployment ID

        Returns:
            Success status
        """
        if deployment_id not in self.deployments:
            return False

        deployment = self.deployments[deployment_id]
        if deployment.state == DeploymentState.PAUSED:
            deployment.state = DeploymentState.IN_PROGRESS
            asyncio.create_task(self.execute_deployment(deployment_id))
            return True
        return False

    async def approve_deployment(self, deployment_id: str, approved_by: str) -> bool:
        """
        Approve a deployment

        Args:
            deployment_id: Deployment ID
            approved_by: Approver

        Returns:
            Success status
        """
        if deployment_id not in self.deployments:
            return False

        deployment = self.deployments[deployment_id]
        if (
            deployment.config.require_approval
            and deployment.state == DeploymentState.PENDING
        ):
            deployment.approval_status = "approved"
            deployment.approved_by = approved_by
            asyncio.create_task(self.execute_deployment(deployment_id))
            return True
        return False

    def get_deployment_status(self, deployment_id: str) -> Optional[Dict[str, Any]]:
        """
        Get deployment status

        Args:
            deployment_id: Deployment ID

        Returns:
            Status dictionary or None
        """
        if deployment_id not in self.deployments:
            return None

        deployment = self.deployments[deployment_id]

        # Calculate progress
        total = len(deployment.devices)
        completed = sum(
            1
            for d in deployment.device_deployments.values()
            if d.state == DeploymentState.COMPLETED
        )
        failed = sum(
            1
            for d in deployment.device_deployments.values()
            if d.state == DeploymentState.FAILED
        )
        in_progress = sum(
            1
            for d in deployment.device_deployments.values()
            if d.state == DeploymentState.IN_PROGRESS
        )

        return {
            "id": deployment.id,
            "name": deployment.name,
            "state": deployment.state.value,
            "strategy": deployment.config.strategy.value,
            "progress": {
                "total": total,
                "completed": completed,
                "failed": failed,
                "in_progress": in_progress,
                "percentage": int((completed / total) * 100) if total > 0 else 0,
            },
            "started_at": (
                deployment.started_at.isoformat() if deployment.started_at else None
            ),
            "completed_at": (
                deployment.completed_at.isoformat() if deployment.completed_at else None
            ),
            "errors": deployment.errors,
            "metadata": deployment.metadata,
        }

    # Helper methods (would integrate with actual services)
    async def _get_device_info(self, device_id: str) -> Dict[str, Any]:
        """Get device information"""
        if self.device_service:
            return await self.device_service.get_device(device_id)
        return {"hostname": device_id}

    async def _backup_device(self, device_id: str) -> str:
        """Backup device configuration"""
        if self.backup_service:
            return await self.backup_service.create_backup(device_id)
        return f"backup-{device_id}-{datetime.utcnow().isoformat()}"

    async def _restore_backup(self, device_id: str, backup_id: str) -> bool:
        """Restore device backup"""
        if self.backup_service:
            return await self.backup_service.restore_backup(device_id, backup_id)
        return True

    async def _generate_diff(self, device_id: str, new_config: str) -> str:
        """Generate configuration diff"""
        # Would compare with current device config
        return f"Diff for {device_id}"

    async def _apply_configuration(self, device_id: str, configuration: str) -> bool:
        """Apply configuration to device"""
        if self.device_service:
            return await self.device_service.apply_config(device_id, configuration)
        return True

    async def _verify_configuration(self, device_id: str, configuration: str) -> bool:
        """Verify configuration on device"""
        # Would verify configuration was applied correctly
        return True

    async def _pre_flight_checks(self, deployment: Deployment) -> bool:
        """Run pre-flight checks"""
        # Verify devices are reachable
        # Verify user has permissions
        # Verify configuration is valid
        return True

    async def _check_deployment_health(
        self, deployment: Deployment, devices: List[str]
    ) -> bool:
        """Check deployment health"""
        for device_id in devices:
            device_deployment = deployment.device_deployments[device_id]
            if not await self._device_health_check(device_id, device_deployment):
                return False
        return True

    async def _device_health_check(
        self, device_id: str, device_deployment: DeviceDeployment
    ) -> bool:
        """Check device health"""
        if self.health_service:
            health = await self.health_service.check_health(device_id)
            device_deployment.health_checks = health
            return health.get("healthy", False)

        # Basic health check
        device_deployment.health_checks = {
            "connectivity": True,
            "protocols": True,
            "services": True,
        }
        return True

    async def _switch_traffic(self, deployment: Deployment) -> bool:
        """Switch traffic for blue-green deployment"""
        # Would coordinate traffic switching
        return True
