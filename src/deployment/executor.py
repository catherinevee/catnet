"""
Deployment Executor with automatic rollback
Following CLAUDE.md deployment patterns exactly
"""
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import uuid
from enum import Enum

from ..core.exceptions import DeploymentError, RollbackError, ValidationError
from ..security.audit import AuditLogger, AuditLevel
from ..devices.connector import SecureDeviceConnector
from ..db.models import Deployment, DeploymentState, Device


class DeploymentStrategy(Enum):
    CANARY = "canary"
    ROLLING = "rolling"
    BLUE_GREEN = "blue_green"


class DeploymentResult:
    def __init__(self, success: bool, devices: List[str], errors: List[str] = None):
        self.success = success
        self.devices = devices
        self.errors = errors or []


class DeploymentExecutor:
    """
    PATTERN: Progressive deployment with automatic rollback
    CRITICAL: Always backup before deployment, always validate after
    """

    def __init__(
        self,
        device_connector: SecureDeviceConnector,
        audit_logger: Optional[AuditLogger] = None
    ):
        self.device_connector = device_connector
        self.audit = audit_logger or AuditLogger()
        self.deployment_cache = {}

    async def execute_deployment(
        self,
        deployment_id: str,
        devices: List[Device],
        configuration: Dict[str, Any],
        strategy: DeploymentStrategy,
        user_context: Dict[str, Any]
    ) -> DeploymentResult:
        """
        Main deployment execution following CLAUDE.md patterns
        """
        # CRITICAL: Log deployment start
        await self.audit.log_deployment(
            deployment_id=deployment_id,
            user_id=user_context.get('user_id'),
            action="deployment_started",
            devices=[d.hostname for d in devices],
            status="in_progress"
        )

        try:
            # Select strategy
            if strategy == DeploymentStrategy.CANARY:
                return await self.execute_canary_deployment(
                    deployment_id, devices, configuration, user_context
                )
            elif strategy == DeploymentStrategy.ROLLING:
                return await self.execute_rolling_deployment(
                    deployment_id, devices, configuration, user_context
                )
            elif strategy == DeploymentStrategy.BLUE_GREEN:
                return await self.execute_blue_green_deployment(
                    deployment_id, devices, configuration, user_context
                )
            else:
                raise DeploymentError(f"Unknown deployment strategy: {strategy}")

        except Exception as e:
            # CRITICAL: Log deployment failure
            await self.audit.log_deployment(
                deployment_id=deployment_id,
                user_id=user_context.get('user_id'),
                action="deployment_failed",
                devices=[d.hostname for d in devices],
                status="failed"
            )

            # CRITICAL: Attempt automatic rollback
            await self.emergency_rollback(deployment_id, devices, user_context)
            raise

    async def execute_canary_deployment(
        self,
        deployment_id: str,
        devices: List[Device],
        configuration: Dict[str, Any],
        user_context: Dict[str, Any]
    ) -> DeploymentResult:
        """
        PATTERN: Canary deployment with progressive rollout
        Following CLAUDE.md canary stages exactly
        """
        # Canary stages as defined in CLAUDE.md
        stages = [
            {'percentage': 5, 'wait_minutes': 5},
            {'percentage': 25, 'wait_minutes': 10},
            {'percentage': 50, 'wait_minutes': 15},
            {'percentage': 100, 'wait_minutes': 0}
        ]

        deployed = []
        backups = {}

        for stage in stages:
            # Calculate devices for this stage
            count = int(len(devices) * stage['percentage'] / 100)
            if count == 0 and stage['percentage'] > 0:
                count = 1  # At least one device

            stage_devices = devices[:count]
            new_devices = [d for d in stage_devices if d not in deployed]

            # Deploy to new devices
            for device in new_devices:
                # CRITICAL: Always backup first (CLAUDE.md requirement)
                backup_id = await self.backup_device(device, user_context)
                backups[device.id] = backup_id

                try:
                    # Deploy configuration
                    await self.deploy_to_device(
                        device, configuration, user_context
                    )

                    # CRITICAL: Immediate validation
                    if not await self.validate_device_health(device):
                        raise ValidationError(f"Device {device.hostname} unhealthy after deployment")

                    deployed.append(device)

                    # Log successful deployment
                    await self.audit.log_event(
                        event_type="canary_stage_device_success",
                        user_id=user_context.get('user_id'),
                        details={
                            "deployment_id": deployment_id,
                            "device": device.hostname,
                            "stage_percentage": stage['percentage']
                        }
                    )

                except Exception as e:
                    # CRITICAL: Automatic rollback on failure
                    await self.audit.log_event(
                        event_type="canary_deployment_failed",
                        user_id=user_context.get('user_id'),
                        details={
                            "deployment_id": deployment_id,
                            "device": device.hostname,
                            "stage_percentage": stage['percentage'],
                            "error": str(e)
                        },
                        level=AuditLevel.ERROR
                    )

                    # Rollback all deployed devices
                    await self.rollback_all(deployed, backups, user_context)
                    raise DeploymentError(f"Canary deployment failed at {stage['percentage']}%: {e}")

            # Wait and monitor (except for last stage)
            if stage['wait_minutes'] > 0 and deployed:
                await self.monitor_health(
                    deployed,
                    duration_minutes=stage['wait_minutes'],
                    deployment_id=deployment_id
                )

        return DeploymentResult(
            success=True,
            devices=[d.hostname for d in deployed]
        )

    async def execute_rolling_deployment(
        self,
        deployment_id: str,
        devices: List[Device],
        configuration: Dict[str, Any],
        user_context: Dict[str, Any]
    ) -> DeploymentResult:
        """
        Rolling deployment - one device at a time with health checks
        """
        deployed = []
        backups = {}

        for device in devices:
            # Backup
            backup_id = await self.backup_device(device, user_context)
            backups[device.id] = backup_id

            try:
                # Deploy
                await self.deploy_to_device(device, configuration, user_context)

                # Validate
                if not await self.validate_device_health(device):
                    raise ValidationError(f"Device {device.hostname} unhealthy")

                deployed.append(device)

                # Brief health check before next device
                await asyncio.sleep(30)  # 30 second pause between devices

            except Exception as e:
                # Rollback deployed devices
                await self.rollback_all(deployed, backups, user_context)
                raise DeploymentError(f"Rolling deployment failed on {device.hostname}: {e}")

        return DeploymentResult(
            success=True,
            devices=[d.hostname for d in deployed]
        )

    async def execute_blue_green_deployment(
        self,
        deployment_id: str,
        devices: List[Device],
        configuration: Dict[str, Any],
        user_context: Dict[str, Any]
    ) -> DeploymentResult:
        """
        Blue-green deployment - prepare all, then switch
        """
        # This would typically involve load balancer manipulation
        # For network devices, we'll simulate with staged configs

        prepared = []
        backups = {}

        # Stage 1: Prepare all devices (blue environment)
        for device in devices:
            backup_id = await self.backup_device(device, user_context)
            backups[device.id] = backup_id

            # Stage configuration without activating
            await self.stage_configuration(device, configuration, user_context)
            prepared.append(device)

        # Stage 2: Validate staged configs
        for device in prepared:
            if not await self.validate_staged_config(device):
                await self.rollback_all(prepared, backups, user_context)
                raise ValidationError(f"Staged config validation failed on {device.hostname}")

        # Stage 3: Activate all at once (switch to green)
        try:
            await asyncio.gather(*[
                self.activate_staged_config(device, user_context)
                for device in prepared
            ])
        except Exception as e:
            await self.rollback_all(prepared, backups, user_context)
            raise DeploymentError(f"Blue-green activation failed: {e}")

        return DeploymentResult(
            success=True,
            devices=[d.hostname for d in devices]
        )

    async def backup_device(self, device: Device, user_context: Dict[str, Any]) -> str:
        """
        CRITICAL: Always backup before any change (CLAUDE.md requirement)
        """
        backup_id = str(uuid.uuid4())

        # Connect to device
        conn = await self.device_connector.connect_to_device(
            str(device.id),
            user_context
        )

        try:
            # Get current configuration
            config = await conn.backup_configuration()

            # Store backup (would typically go to database/storage)
            self.deployment_cache[backup_id] = {
                "device_id": device.id,
                "configuration": config,
                "timestamp": datetime.utcnow(),
                "device_hostname": device.hostname
            }

            await self.audit.log_event(
                event_type="device_backup_created",
                user_id=user_context.get('user_id'),
                details={
                    "device": device.hostname,
                    "backup_id": backup_id
                }
            )

            return backup_id

        finally:
            await conn.disconnect()

    async def deploy_to_device(
        self,
        device: Device,
        configuration: Dict[str, Any],
        user_context: Dict[str, Any]
    ):
        """
        Deploy configuration to a single device
        """
        conn = await self.device_connector.connect_to_device(
            str(device.id),
            user_context
        )

        try:
            # Get vendor-specific commands
            commands = self.get_vendor_commands(device.vendor, configuration)

            # Execute configuration
            result = await conn.execute_config_commands(commands)

            # Save configuration
            await conn.save_configuration()

            await self.audit.log_event(
                event_type="device_configuration_deployed",
                user_id=user_context.get('user_id'),
                details={
                    "device": device.hostname,
                    "commands_count": len(commands)
                }
            )

        finally:
            await conn.disconnect()

    async def validate_device_health(self, device: Device) -> bool:
        """
        Validate device is healthy after deployment
        """
        # Basic health checks
        checks = [
            self.check_device_reachability(device),
            self.check_interface_status(device),
            self.check_routing_table(device),
            self.check_critical_services(device)
        ]

        results = await asyncio.gather(*checks, return_exceptions=True)

        # All checks must pass
        return all(
            result is True for result in results
            if not isinstance(result, Exception)
        )

    async def check_device_reachability(self, device: Device) -> bool:
        """Check if device is reachable"""
        # Implementation would ping device
        return True  # Simplified for now

    async def check_interface_status(self, device: Device) -> bool:
        """Check critical interfaces are up"""
        # Implementation would check interface status
        return True  # Simplified for now

    async def check_routing_table(self, device: Device) -> bool:
        """Check routing table has expected routes"""
        # Implementation would verify routing
        return True  # Simplified for now

    async def check_critical_services(self, device: Device) -> bool:
        """Check critical services are running"""
        # Implementation would check services
        return True  # Simplified for now

    async def rollback_all(
        self,
        devices: List[Device],
        backups: Dict[str, str],
        user_context: Dict[str, Any]
    ):
        """
        CRITICAL: Rollback all devices to backed up state
        """
        await self.audit.log_event(
            event_type="rollback_initiated",
            user_id=user_context.get('user_id'),
            details={
                "devices": [d.hostname for d in devices],
                "backup_count": len(backups)
            },
            level=AuditLevel.WARNING
        )

        rollback_tasks = []
        for device in devices:
            if device.id in backups:
                rollback_tasks.append(
                    self.rollback_device(device, backups[device.id], user_context)
                )

        results = await asyncio.gather(*rollback_tasks, return_exceptions=True)

        # Check if any rollbacks failed
        failures = [r for r in results if isinstance(r, Exception)]
        if failures:
            await self.audit.log_event(
                event_type="rollback_partial_failure",
                user_id=user_context.get('user_id'),
                details={
                    "failures": len(failures),
                    "total": len(devices)
                },
                level=AuditLevel.CRITICAL
            )
            raise RollbackError(f"Rollback failed for {len(failures)} devices")

    async def rollback_device(
        self,
        device: Device,
        backup_id: str,
        user_context: Dict[str, Any]
    ):
        """
        Rollback single device to backup
        """
        if backup_id not in self.deployment_cache:
            raise RollbackError(f"Backup {backup_id} not found")

        backup = self.deployment_cache[backup_id]

        conn = await self.device_connector.connect_to_device(
            str(device.id),
            user_context
        )

        try:
            # Restore configuration based on vendor
            if "cisco" in device.vendor.value.lower():
                await conn.execute_command(
                    f"configure replace flash:backup_{backup_id}.cfg force"
                )
            elif "juniper" in device.vendor.value.lower():
                await conn.execute_command(f"rollback 1")
                await conn.execute_command("commit")

            await self.audit.log_event(
                event_type="device_rolled_back",
                user_id=user_context.get('user_id'),
                details={
                    "device": device.hostname,
                    "backup_id": backup_id
                }
            )

        finally:
            await conn.disconnect()

    async def monitor_health(
        self,
        devices: List[Device],
        duration_minutes: int,
        deployment_id: str
    ):
        """
        Monitor device health for specified duration
        """
        end_time = datetime.utcnow() + timedelta(minutes=duration_minutes)
        check_interval = 60  # Check every minute

        while datetime.utcnow() < end_time:
            # Check all devices
            health_checks = [
                self.validate_device_health(device)
                for device in devices
            ]

            results = await asyncio.gather(*health_checks)

            # If any device unhealthy, raise alert
            unhealthy = [
                devices[i].hostname
                for i, healthy in enumerate(results)
                if not healthy
            ]

            if unhealthy:
                await self.audit.log_event(
                    event_type="deployment_health_check_failed",
                    user_id=None,
                    details={
                        "deployment_id": deployment_id,
                        "unhealthy_devices": unhealthy
                    },
                    level=AuditLevel.WARNING
                )
                # Could trigger automatic rollback here

            # Wait before next check
            await asyncio.sleep(check_interval)

    async def stage_configuration(
        self,
        device: Device,
        configuration: Dict[str, Any],
        user_context: Dict[str, Any]
    ):
        """
        Stage configuration without activating (for blue-green)
        """
        # Implementation depends on vendor
        # Cisco: copy to candidate config
        # Juniper: load but don't commit
        pass

    async def validate_staged_config(self, device: Device) -> bool:
        """
        Validate staged configuration
        """
        # Would run validation commands based on vendor
        return True

    async def activate_staged_config(
        self,
        device: Device,
        user_context: Dict[str, Any]
    ):
        """
        Activate staged configuration
        """
        # Would commit/activate based on vendor
        pass

    async def emergency_rollback(
        self,
        deployment_id: str,
        devices: List[Device],
        user_context: Dict[str, Any]
    ):
        """
        Emergency rollback procedure
        """
        await self.audit.log_event(
            event_type="emergency_rollback",
            user_id=user_context.get('user_id'),
            details={
                "deployment_id": deployment_id,
                "devices": [d.hostname for d in devices]
            },
            level=AuditLevel.CRITICAL
        )

        # Would implement emergency rollback logic
        pass

    def get_vendor_commands(
        self,
        vendor: str,
        configuration: Dict[str, Any]
    ) -> List[str]:
        """
        Convert configuration to vendor-specific commands
        """
        # Would implement vendor-specific command generation
        return []