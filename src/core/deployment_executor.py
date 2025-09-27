from typing import Dict, Any, List, Optional
import asyncio
from datetime import datetime, timedelta
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from dataclasses import dataclass

from ..db.models import Deployment, DeploymentDevice, Device, DeviceConfig, DeploymentState
from ..db.database import database
from ..security.secure_connector import SecureDeviceConnector
from ..security.audit import AuditLogger
from ..security.vault import VaultClient
from ..security.encryption import EncryptionHandler
from .validator import ConfigValidator
from .exceptions import DeploymentError

logger = structlog.get_logger()

@dataclass
class DeploymentResult:
    success: bool
    devices_deployed: List[str]
    devices_failed: List[str]
    rollback_performed: bool = False
    error_message: Optional[str] = None
    deployment_duration: float = 0.0

class DeploymentExecutor:
    def __init__(self):
        self.connector = SecureDeviceConnector()
        self.audit = AuditLogger()
        self.vault = VaultClient()
        self.encryption = EncryptionHandler()
        self.validator = ConfigValidator()

    async def execute_canary_deployment(
        self,
        deployment_id: str,
        user_context: Dict[str, Any]
    ) -> DeploymentResult:
        start_time = datetime.utcnow()
        deployed_devices = []
        failed_devices = []

        try:
            async with database.get_session() as db:
                result = await db.execute(
                    select(Deployment).where(Deployment.id == deployment_id)
                )
                deployment = result.scalar_one_or_none()

                if not deployment:
                    raise DeploymentError(f"Deployment {deployment_id} not found")

                if deployment.state != DeploymentState.APPROVED:
                    raise DeploymentError(f"Deployment {deployment_id} is not approved")

                devices_result = await db.execute(
                    select(DeploymentDevice, Device)
                    .join(Device, DeploymentDevice.device_id == Device.id)
                    .where(DeploymentDevice.deployment_id == deployment_id)
                )
                device_pairs = devices_result.fetchall()

                if not device_pairs:
                    raise DeploymentError("No devices configured for deployment")

                deployment.state = DeploymentState.IN_PROGRESS
                deployment.started_at = start_time
                await db.commit()

                await self.audit.log_deployment_start(
                    deployment_id=deployment_id,
                    user_id=user_context.get('user_id'),
                    device_count=len(device_pairs),
                    strategy="canary"
                )

                canary_stages = [
                    {'percentage': deployment.canary_percentage, 'wait_minutes': 5},
                    {'percentage': 25, 'wait_minutes': 10},
                    {'percentage': 50, 'wait_minutes': 15},
                    {'percentage': 100, 'wait_minutes': 0}
                ]

                total_devices = len(device_pairs)

                for stage_idx, stage in enumerate(canary_stages):
                    device_count = int(total_devices * stage['percentage'] / 100)
                    stage_devices = device_pairs[:device_count]
                    new_devices = [
                        (dep_dev, device) for dep_dev, device in stage_devices
                        if device.id not in [d['device_id'] for d in deployed_devices]
                    ]

                    logger.info(f"Canary stage {stage_idx + 1}: deploying to {len(new_devices)} devices ({stage['percentage']}%)")

                    for deployment_device, device in new_devices:
                        try:
                            backup_id = await self._backup_device_config(
                                device, deployment_device, user_context
                            )

                            await self._deploy_to_device(
                                deployment, device, deployment_device, user_context
                            )

                            if not await self._validate_device_health(device, user_context):
                                raise DeploymentError(f"Device {device.name} failed health check")

                            deployed_devices.append({
                                'device_id': device.id,
                                'device_name': device.name,
                                'backup_id': backup_id
                            })

                            deployment_device.status = "deployed"
                            deployment_device.deployed_at = datetime.utcnow()
                            deployment_device.validation_passed = True
                            deployment_device.health_check_passed = True

                        except Exception as e:
                            logger.error(f"Failed to deploy to device {device.name}: {e}")

                            deployment_device.status = "failed"
                            deployment_device.error_message = str(e)

                            failed_devices.append({
                                'device_id': device.id,
                                'device_name': device.name,
                                'error': str(e)
                            })

                            if deployment.rollback_on_failure:
                                await self._rollback_all_devices(
                                    deployed_devices, deployment_id, user_context
                                )

                                deployment.state = DeploymentState.ROLLED_BACK
                                deployment.rolled_back_at = datetime.utcnow()

                                await db.commit()

                                return DeploymentResult(
                                    success=False,
                                    devices_deployed=[d['device_name'] for d in deployed_devices],
                                    devices_failed=[d['device_name'] for d in failed_devices],
                                    rollback_performed=True,
                                    error_message=f"Canary deployment failed at stage {stage_idx + 1}",
                                    deployment_duration=(datetime.utcnow() - start_time).total_seconds()
                                )

                    await db.commit()

                    if stage['wait_minutes'] > 0 and stage_idx < len(canary_stages) - 1:
                        logger.info(f"Waiting {stage['wait_minutes']} minutes before next stage")

                        monitor_result = await self._monitor_deployed_devices(
                            deployed_devices, stage['wait_minutes']
                        )

                        if not monitor_result['healthy']:
                            if deployment.rollback_on_failure:
                                await self._rollback_all_devices(
                                    deployed_devices, deployment_id, user_context
                                )

                                deployment.state = DeploymentState.ROLLED_BACK
                                deployment.rolled_back_at = datetime.utcnow()

                                return DeploymentResult(
                                    success=False,
                                    devices_deployed=[d['device_name'] for d in deployed_devices],
                                    devices_failed=[d['device_name'] for d in failed_devices],
                                    rollback_performed=True,
                                    error_message="Health monitoring failed during canary deployment",
                                    deployment_duration=(datetime.utcnow() - start_time).total_seconds()
                                )

                deployment.state = DeploymentState.COMPLETED
                deployment.completed_at = datetime.utcnow()
                await db.commit()

                return DeploymentResult(
                    success=True,
                    devices_deployed=[d['device_name'] for d in deployed_devices],
                    devices_failed=[d['device_name'] for d in failed_devices],
                    rollback_performed=False,
                    deployment_duration=(datetime.utcnow() - start_time).total_seconds()
                )

        except Exception as e:
            logger.error(f"Canary deployment failed: {e}")

            async with database.get_session() as db:
                await db.execute(
                    update(Deployment)
                    .where(Deployment.id == deployment_id)
                    .values(
                        state=DeploymentState.FAILED,
                        error_details={'error': str(e), 'timestamp': datetime.utcnow().isoformat()}
                    )
                )
                await db.commit()

            return DeploymentResult(
                success=False,
                devices_deployed=[],
                devices_failed=[],
                rollback_performed=False,
                error_message=str(e),
                deployment_duration=(datetime.utcnow() - start_time).total_seconds()
            )

    async def execute_rolling_deployment(
        self,
        deployment_id: str,
        user_context: Dict[str, Any],
        batch_size: int = 5
    ) -> DeploymentResult:
        start_time = datetime.utcnow()
        deployed_devices = []
        failed_devices = []

        try:
            async with database.get_session() as db:
                result = await db.execute(
                    select(Deployment).where(Deployment.id == deployment_id)
                )
                deployment = result.scalar_one_or_none()

                if not deployment:
                    raise DeploymentError(f"Deployment {deployment_id} not found")

                devices_result = await db.execute(
                    select(DeploymentDevice, Device)
                    .join(Device, DeploymentDevice.device_id == Device.id)
                    .where(DeploymentDevice.deployment_id == deployment_id)
                )
                device_pairs = devices_result.fetchall()

                deployment.state = DeploymentState.IN_PROGRESS
                deployment.started_at = start_time
                await db.commit()

                await self.audit.log_deployment_start(
                    deployment_id=deployment_id,
                    user_id=user_context.get('user_id'),
                    device_count=len(device_pairs),
                    strategy="rolling"
                )

                for i in range(0, len(device_pairs), batch_size):
                    batch = device_pairs[i:i + batch_size]
                    batch_results = await self._deploy_batch(
                        batch, deployment, user_context
                    )

                    for result in batch_results:
                        if result['success']:
                            deployed_devices.append(result)
                        else:
                            failed_devices.append(result)

                            if deployment.rollback_on_failure:
                                await self._rollback_all_devices(
                                    deployed_devices, deployment_id, user_context
                                )

                                deployment.state = DeploymentState.ROLLED_BACK
                                deployment.rolled_back_at = datetime.utcnow()
                                await db.commit()

                                return DeploymentResult(
                                    success=False,
                                    devices_deployed=[d['device_name'] for d in deployed_devices],
                                    devices_failed=[d['device_name'] for d in failed_devices],
                                    rollback_performed=True,
                                    error_message=f"Rolling deployment failed on device {result['device_name']}",
                                    deployment_duration=(datetime.utcnow() - start_time).total_seconds()
                                )

                    await asyncio.sleep(2)

                deployment.state = DeploymentState.COMPLETED
                deployment.completed_at = datetime.utcnow()
                await db.commit()

                return DeploymentResult(
                    success=len(failed_devices) == 0,
                    devices_deployed=[d['device_name'] for d in deployed_devices],
                    devices_failed=[d['device_name'] for d in failed_devices],
                    rollback_performed=False,
                    deployment_duration=(datetime.utcnow() - start_time).total_seconds()
                )

        except Exception as e:
            logger.error(f"Rolling deployment failed: {e}")

            async with database.get_session() as db:
                await db.execute(
                    update(Deployment)
                    .where(Deployment.id == deployment_id)
                    .values(
                        state=DeploymentState.FAILED,
                        error_details={'error': str(e), 'timestamp': datetime.utcnow().isoformat()}
                    )
                )
                await db.commit()

            return DeploymentResult(
                success=False,
                devices_deployed=[],
                devices_failed=[],
                rollback_performed=False,
                error_message=str(e),
                deployment_duration=(datetime.utcnow() - start_time).total_seconds()
            )

    async def _backup_device_config(
        self,
        device: Device,
        deployment_device: DeploymentDevice,
        user_context: Dict[str, Any]
    ) -> str:
        try:
            backup_path = await self.connector.backup_device_config(
                str(device.id), user_context
            )

            async with database.get_session() as db:
                latest_config = await db.execute(
                    select(DeviceConfig)
                    .where(DeviceConfig.device_id == device.id)
                    .order_by(DeviceConfig.created_at.desc())
                    .limit(1)
                )
                config = latest_config.scalar_one_or_none()

                if config:
                    deployment_device.backup_config_id = config.id
                    await db.commit()

            return backup_path

        except Exception as e:
            logger.error(f"Failed to backup device {device.name}: {e}")
            raise

    async def _deploy_to_device(
        self,
        deployment: Deployment,
        device: Device,
        deployment_device: DeploymentDevice,
        user_context: Dict[str, Any]
    ):
        try:
            device_connection = await self.connector.connect_to_device(
                str(device.id), user_context
            )

            config_data = await self._get_deployment_config(deployment, device)

            if device.vendor.value.startswith('cisco'):
                await self._deploy_cisco_config(
                    device_connection, config_data, user_context
                )
            elif device.vendor.value.startswith('juniper'):
                await self._deploy_juniper_config(
                    device_connection, config_data, user_context
                )
            else:
                raise DeploymentError(f"Unsupported device vendor: {device.vendor}")

            await self.connector.disconnect(
                device_connection.session_id, user_context
            )

        except Exception as e:
            logger.error(f"Failed to deploy to device {device.name}: {e}")
            raise

    async def _get_deployment_config(
        self,
        deployment: Deployment,
        device: Device
    ) -> str:
        try:
            if deployment.repository_id:
                from ..gitops.git_service import GitOpsService
                git_service = GitOpsService()
                configs = await git_service.list_configs(str(deployment.repository_id))

                for config in configs:
                    if str(device.id) in config.get('devices', []):
                        return config['content']

            return ""

        except Exception as e:
            logger.error(f"Failed to get deployment config: {e}")
            raise

    async def _deploy_cisco_config(
        self,
        device_connection,
        config_data: str,
        user_context: Dict[str, Any]
    ):
        try:
            await self.connector.execute_command(
                device_connection.session_id,
                "configure terminal",
                user_context
            )

            config_lines = config_data.split('\n')
            for line in config_lines:
                line = line.strip()
                if line and not line.startswith('!'):
                    await self.connector.execute_command(
                        device_connection.session_id,
                        line,
                        user_context
                    )

            await self.connector.execute_command(
                device_connection.session_id,
                "end",
                user_context
            )

            await self.connector.execute_command(
                device_connection.session_id,
                "write memory",
                user_context
            )

        except Exception as e:
            logger.error(f"Failed to deploy Cisco config: {e}")
            raise

    async def _deploy_juniper_config(
        self,
        device_connection,
        config_data: str,
        user_context: Dict[str, Any]
    ):
        try:
            await self.connector.execute_command(
                device_connection.session_id,
                "configure",
                user_context
            )

            config_lines = config_data.split('\n')
            for line in config_lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    await self.connector.execute_command(
                        device_connection.session_id,
                        line,
                        user_context
                    )

            await self.connector.execute_command(
                device_connection.session_id,
                "commit",
                user_context
            )

            await self.connector.execute_command(
                device_connection.session_id,
                "exit",
                user_context
            )

        except Exception as e:
            logger.error(f"Failed to deploy Juniper config: {e}")
            raise

    async def _validate_device_health(
        self,
        device: Device,
        user_context: Dict[str, Any]
    ) -> bool:
        try:
            device_connection = await self.connector.connect_to_device(
                str(device.id), user_context
            )

            if device.vendor.value.startswith('cisco'):
                health_commands = [
                    "show interfaces status",
                    "show ip interface brief",
                    "show running-config"
                ]
            elif device.vendor.value.startswith('juniper'):
                health_commands = [
                    "show interfaces terse",
                    "show system alarms",
                    "show configuration"
                ]
            else:
                return True

            for command in health_commands:
                result = await self.connector.execute_command(
                    device_connection.session_id,
                    command,
                    user_context
                )

                if "error" in result.lower() or "failed" in result.lower():
                    return False

            await self.connector.disconnect(
                device_connection.session_id, user_context
            )

            return True

        except Exception as e:
            logger.error(f"Health check failed for device {device.name}: {e}")
            return False

    async def _deploy_batch(
        self,
        device_batch: List,
        deployment: Deployment,
        user_context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        results = []

        deployment_tasks = []
        for deployment_device, device in device_batch:
            task = self._deploy_single_device(
                deployment, device, deployment_device, user_context
            )
            deployment_tasks.append(task)

        batch_results = await asyncio.gather(*deployment_tasks, return_exceptions=True)

        for i, result in enumerate(batch_results):
            deployment_device, device = device_batch[i]

            if isinstance(result, Exception):
                results.append({
                    'success': False,
                    'device_id': device.id,
                    'device_name': device.name,
                    'error': str(result)
                })
            else:
                results.append({
                    'success': True,
                    'device_id': device.id,
                    'device_name': device.name,
                    'backup_id': result
                })

        return results

    async def _deploy_single_device(
        self,
        deployment: Deployment,
        device: Device,
        deployment_device: DeploymentDevice,
        user_context: Dict[str, Any]
    ) -> str:
        backup_id = await self._backup_device_config(
            device, deployment_device, user_context
        )

        await self._deploy_to_device(
            deployment, device, deployment_device, user_context
        )

        if not await self._validate_device_health(device, user_context):
            raise DeploymentError(f"Device {device.name} failed health check")

        async with database.get_session() as db:
            deployment_device.status = "deployed"
            deployment_device.deployed_at = datetime.utcnow()
            deployment_device.validation_passed = True
            deployment_device.health_check_passed = True
            await db.commit()

        return backup_id

    async def _monitor_deployed_devices(
        self,
        deployed_devices: List[Dict[str, Any]],
        wait_minutes: int
    ) -> Dict[str, Any]:
        healthy_devices = []
        unhealthy_devices = []

        for device_info in deployed_devices:
            try:
                async with database.get_session() as db:
                    result = await db.execute(
                        select(Device).where(Device.id == device_info['device_id'])
                    )
                    device = result.scalar_one_or_none()

                    if device:
                        is_healthy = await self._validate_device_health(
                            device, {'user_id': 'system'}
                        )

                        if is_healthy:
                            healthy_devices.append(device_info['device_name'])
                        else:
                            unhealthy_devices.append(device_info['device_name'])

            except Exception as e:
                logger.error(f"Failed to monitor device {device_info['device_name']}: {e}")
                unhealthy_devices.append(device_info['device_name'])

        await asyncio.sleep(wait_minutes * 60)

        return {
            'healthy': len(unhealthy_devices) == 0,
            'healthy_devices': healthy_devices,
            'unhealthy_devices': unhealthy_devices
        }

    async def _rollback_all_devices(
        self,
        deployed_devices: List[Dict[str, Any]],
        deployment_id: str,
        user_context: Dict[str, Any]
    ):
        try:
            await self.audit.log_deployment_rollback(
                deployment_id=deployment_id,
                user_id=user_context.get('user_id'),
                reason="Automatic rollback due to deployment failure",
                devices_affected=len(deployed_devices)
            )

            for device_info in deployed_devices:
                try:
                    await self._rollback_single_device(device_info, user_context)
                except Exception as e:
                    logger.error(f"Failed to rollback device {device_info['device_name']}: {e}")

        except Exception as e:
            logger.error(f"Failed to rollback deployment {deployment_id}: {e}")
            raise

    async def _rollback_single_device(
        self,
        device_info: Dict[str, Any],
        user_context: Dict[str, Any]
    ):
        try:
            device_connection = await self.connector.connect_to_device(
                device_info['device_id'], user_context
            )

            backup_config = await self._get_backup_config(device_info['backup_id'])

            async with database.get_session() as db:
                result = await db.execute(
                    select(Device).where(Device.id == device_info['device_id'])
                )
                device = result.scalar_one_or_none()

                if device and device.vendor.value.startswith('cisco'):
                    await self.connector.execute_command(
                        device_connection.session_id,
                        f"configure replace flash:{device_info['backup_id']} force",
                        user_context
                    )
                elif device and device.vendor.value.startswith('juniper'):
                    await self.connector.execute_command(
                        device_connection.session_id,
                        "rollback 1",
                        user_context
                    )
                    await self.connector.execute_command(
                        device_connection.session_id,
                        "commit",
                        user_context
                    )

            await self.connector.disconnect(
                device_connection.session_id, user_context
            )

        except Exception as e:
            logger.error(f"Failed to rollback device {device_info['device_name']}: {e}")
            raise

    async def _get_backup_config(self, backup_id: str) -> str:
        try:
            backup_data = await self.vault.get_secret(f"backups/{backup_id}")

            if backup_data.get('algorithm') == 'AES-256-GCM':
                encryption_key = await self.vault.get_encryption_key("device-backup")
                config_text = self.encryption.decrypt_config(backup_data, encryption_key)
                return config_text

            return backup_data.get('config', '')

        except Exception as e:
            logger.error(f"Failed to get backup config {backup_id}: {e}")
            raise