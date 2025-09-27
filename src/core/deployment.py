import asyncio
import logging
import hashlib
import json
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_
import uuid

from ..db.models import (
    Deployment, DeploymentState, DeploymentDevice,
    DeploymentConfig, Device, DeviceConfig, User
)
from ..security.vault_client import VaultClient
from ..security.audit import AuditLogger
from ..security.encryption import EncryptionService
from ..devices.device_connector import SecureDeviceConnector
from .validators import ConfigValidator
from .rollback import RollbackManager

logger = logging.getLogger(__name__)

class DeploymentService:
    def __init__(
        self,
        db: Session,
        vault_client: Optional[VaultClient] = None,
        audit_logger: Optional[AuditLogger] = None
    ):
        self.db = db
        self.vault = vault_client or VaultClient()
        self.audit = audit_logger or AuditLogger(db)
        self.encryption = EncryptionService()
        self.validator = ConfigValidator()
        self.rollback_manager = RollbackManager(db, vault_client, audit_logger)
        self.device_connector = SecureDeviceConnector(db, vault_client, audit_logger)

    async def create_deployment(
        self,
        name: str,
        configs: List[Dict[str, Any]],
        user_id: str,
        strategy: str = "rolling",
        requires_approval: bool = True,
        approval_count_required: int = 2,
        canary_percentage: Optional[int] = None,
        max_parallel: int = 5,
        scheduled_at: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        configs_json = json.dumps(configs, sort_keys=True)
        config_hash = hashlib.sha256(configs_json.encode()).hexdigest()

        private_key, public_key = self.encryption.generate_rsa_keypair()
        signature = self.encryption.sign_data(configs_json.encode(), private_key)

        ciphertext, key_id = self.vault.encrypt_data(configs_json)

        deployment = Deployment(
            name=name,
            created_by=user_id,
            config_hash=config_hash,
            signature=signature.hex(),
            encryption_key_id=key_id,
            state=DeploymentState.PENDING,
            strategy=strategy,
            canary_percentage=canary_percentage,
            max_parallel=max_parallel,
            requires_approval=requires_approval,
            approval_count_required=approval_count_required,
            scheduled_at=scheduled_at,
            audit_log={"created": datetime.utcnow().isoformat(), "metadata": metadata}
        )

        self.db.add(deployment)

        for config in configs:
            validation_result = await self.validator.validate_configuration(config)

            deployment_config = DeploymentConfig(
                deployment_id=deployment.id,
                device_id=config.get("device_id"),
                config_content=json.dumps(config),
                config_encrypted=ciphertext,
                config_hash=hashlib.sha256(json.dumps(config).encode()).hexdigest(),
                config_type=config.get("type", "device"),
                validation_passed=validation_result.is_valid,
                validation_errors=validation_result.to_dict() if not validation_result.is_valid else None
            )
            self.db.add(deployment_config)

            if "device_id" in config:
                device = self.db.query(Device).filter(Device.id == config["device_id"]).first()
                if device:
                    deployment_device = DeploymentDevice(
                        deployment_id=deployment.id,
                        device_id=device.id,
                        sequence_order=config.get("sequence", 0),
                        status="pending"
                    )
                    self.db.add(deployment_device)

        self.db.commit()

        await self.audit.log_deployment(
            deployment_id=str(deployment.id),
            user_id=user_id,
            action="created",
            devices=[str(d.device_id) for d in deployment.devices],
            status="pending",
            details={"strategy": strategy, "configs": len(configs)}
        )

        return {
            "id": str(deployment.id),
            "name": name,
            "state": deployment.state.value,
            "created_at": deployment.created_at.isoformat(),
            "requires_approval": requires_approval,
            "approval_count_required": approval_count_required
        }

    async def approve_deployment(
        self,
        deployment_id: str,
        user_id: str,
        comment: Optional[str] = None
    ) -> bool:
        deployment = self.db.query(Deployment).filter(
            Deployment.id == deployment_id
        ).first()

        if not deployment:
            raise ValueError(f"Deployment {deployment_id} not found")

        if deployment.state != DeploymentState.PENDING:
            raise ValueError(f"Deployment is in state {deployment.state.value}, cannot approve")

        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            raise ValueError(f"User {user_id} not found")

        if user in deployment.approvers:
            raise ValueError("User has already approved this deployment")

        deployment.approvers.append(user)
        deployment.approved_count += 1

        if deployment.approved_count >= deployment.approval_count_required:
            deployment.state = DeploymentState.APPROVED

        self.db.commit()

        await self.audit.log_deployment(
            deployment_id=deployment_id,
            user_id=user_id,
            action="approved",
            devices=[str(d.device_id) for d in deployment.devices],
            status=deployment.state.value,
            details={"comment": comment, "approval_count": deployment.approved_count}
        )

        if deployment.state == DeploymentState.APPROVED and not deployment.scheduled_at:
            await self.execute_deployment(deployment_id, user_id)

        return deployment.state == DeploymentState.APPROVED

    async def execute_deployment(
        self,
        deployment_id: str,
        executor_user_id: str
    ) -> Dict[str, Any]:
        deployment = self.db.query(Deployment).filter(
            Deployment.id == deployment_id
        ).first()

        if not deployment:
            raise ValueError(f"Deployment {deployment_id} not found")

        if deployment.requires_approval and deployment.state != DeploymentState.APPROVED:
            raise ValueError("Deployment requires approval")

        deployment.state = DeploymentState.IN_PROGRESS
        deployment.started_at = datetime.utcnow()
        self.db.commit()

        executor = DeploymentExecutor(
            self.db,
            self.vault,
            self.audit,
            self.device_connector,
            self.rollback_manager
        )

        try:
            if deployment.strategy == "canary":
                result = await executor.execute_canary_deployment(deployment)
            elif deployment.strategy == "blue_green":
                result = await executor.execute_blue_green_deployment(deployment)
            else:
                result = await executor.execute_rolling_deployment(deployment)

            deployment.state = DeploymentState.COMPLETED
            deployment.completed_at = datetime.utcnow()
            self.db.commit()

            await self.audit.log_deployment(
                deployment_id=deployment_id,
                user_id=executor_user_id,
                action="completed",
                devices=[str(d.device_id) for d in deployment.devices],
                status="completed",
                details=result
            )

            return result

        except Exception as e:
            deployment.state = DeploymentState.FAILED
            deployment.completed_at = datetime.utcnow()
            self.db.commit()

            await self.audit.log_deployment(
                deployment_id=deployment_id,
                user_id=executor_user_id,
                action="failed",
                devices=[str(d.device_id) for d in deployment.devices],
                status="failed",
                details={"error": str(e)}
            )

            await self.rollback_deployment(deployment_id, executor_user_id)
            raise

    async def rollback_deployment(
        self,
        deployment_id: str,
        user_id: str,
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        deployment = self.db.query(Deployment).filter(
            Deployment.id == deployment_id
        ).first()

        if not deployment:
            raise ValueError(f"Deployment {deployment_id} not found")

        result = await self.rollback_manager.rollback_deployment(deployment, reason)

        deployment.state = DeploymentState.ROLLED_BACK
        self.db.commit()

        await self.audit.log_deployment(
            deployment_id=deployment_id,
            user_id=user_id,
            action="rolled_back",
            devices=[str(d.device_id) for d in deployment.devices],
            status="rolled_back",
            details={"reason": reason, "result": result}
        )

        return result

    async def get_deployment_status(
        self,
        deployment_id: str
    ) -> Dict[str, Any]:
        deployment = self.db.query(Deployment).filter(
            Deployment.id == deployment_id
        ).first()

        if not deployment:
            raise ValueError(f"Deployment {deployment_id} not found")

        device_statuses = []
        for dd in deployment.devices:
            device = self.db.query(Device).filter(Device.id == dd.device_id).first()
            device_statuses.append({
                "device_id": str(dd.device_id),
                "hostname": device.hostname if device else "Unknown",
                "status": dd.status,
                "started_at": dd.started_at.isoformat() if dd.started_at else None,
                "completed_at": dd.completed_at.isoformat() if dd.completed_at else None,
                "error": dd.error_message,
                "rollback_performed": dd.rollback_performed
            })

        return {
            "id": str(deployment.id),
            "name": deployment.name,
            "state": deployment.state.value,
            "strategy": deployment.strategy,
            "created_at": deployment.created_at.isoformat(),
            "started_at": deployment.started_at.isoformat() if deployment.started_at else None,
            "completed_at": deployment.completed_at.isoformat() if deployment.completed_at else None,
            "approval_status": {
                "required": deployment.requires_approval,
                "approved_count": deployment.approved_count,
                "required_count": deployment.approval_count_required,
                "approvers": [u.username for u in deployment.approvers]
            },
            "devices": device_statuses
        }


class DeploymentExecutor:
    def __init__(
        self,
        db: Session,
        vault_client: VaultClient,
        audit_logger: AuditLogger,
        device_connector: SecureDeviceConnector,
        rollback_manager: RollbackManager
    ):
        self.db = db
        self.vault = vault_client
        self.audit = audit_logger
        self.device_connector = device_connector
        self.rollback = rollback_manager

    async def execute_rolling_deployment(
        self,
        deployment: Deployment
    ) -> Dict[str, Any]:
        deployed_devices = []
        failed_devices = []

        sorted_devices = sorted(deployment.devices, key=lambda x: x.sequence_order)

        semaphore = asyncio.Semaphore(deployment.max_parallel or 5)

        async def deploy_to_device(deployment_device: DeploymentDevice):
            async with semaphore:
                device = self.db.query(Device).filter(
                    Device.id == deployment_device.device_id
                ).first()

                if not device:
                    failed_devices.append({
                        "device_id": str(deployment_device.device_id),
                        "error": "Device not found"
                    })
                    return

                backup_id = await self._backup_device_config(device)
                deployment_device.pre_config_backup_id = backup_id

                deployment_device.status = "in_progress"
                deployment_device.started_at = datetime.utcnow()
                self.db.commit()

                try:
                    config = self._get_device_config(deployment, device.id)
                    await self._apply_config_to_device(device, config)

                    if not await self._validate_device_health(device):
                        raise Exception("Device health check failed")

                    deployment_device.status = "completed"
                    deployment_device.completed_at = datetime.utcnow()
                    deployed_devices.append(device.hostname)

                except Exception as e:
                    deployment_device.status = "failed"
                    deployment_device.error_message = str(e)
                    deployment_device.completed_at = datetime.utcnow()
                    failed_devices.append({
                        "device_id": str(device.id),
                        "hostname": device.hostname,
                        "error": str(e)
                    })

                    if backup_id:
                        await self._rollback_device_config(device, backup_id)
                        deployment_device.rollback_performed = True

                self.db.commit()

        tasks = [deploy_to_device(dd) for dd in sorted_devices]
        await asyncio.gather(*tasks, return_exceptions=True)

        return {
            "strategy": "rolling",
            "total_devices": len(deployment.devices),
            "deployed": len(deployed_devices),
            "failed": len(failed_devices),
            "deployed_devices": deployed_devices,
            "failed_devices": failed_devices
        }

    async def execute_canary_deployment(
        self,
        deployment: Deployment
    ) -> Dict[str, Any]:
        stages = [
            {'percentage': 5, 'wait_minutes': 5},
            {'percentage': 25, 'wait_minutes': 10},
            {'percentage': 50, 'wait_minutes': 15},
            {'percentage': 100, 'wait_minutes': 0}
        ]

        if deployment.canary_percentage:
            stages = [
                {'percentage': deployment.canary_percentage, 'wait_minutes': 10},
                {'percentage': 100, 'wait_minutes': 0}
            ]

        devices = list(deployment.devices)
        deployed = []
        failed = []

        for stage in stages:
            count = int(len(devices) * stage['percentage'] / 100)
            stage_devices = devices[:count]
            new_devices = [d for d in stage_devices if d not in deployed]

            logger.info(f"Canary stage: {stage['percentage']}% - Deploying to {len(new_devices)} devices")

            for device_deployment in new_devices:
                device = self.db.query(Device).filter(
                    Device.id == device_deployment.device_id
                ).first()

                backup_id = await self._backup_device_config(device)
                device_deployment.pre_config_backup_id = backup_id

                try:
                    config = self._get_device_config(deployment, device.id)
                    await self._apply_config_to_device(device, config)

                    if not await self._validate_device_health(device):
                        raise Exception("Device health check failed")

                    deployed.append(device_deployment)
                    device_deployment.status = "completed"

                except Exception as e:
                    failed.append(device_deployment)
                    device_deployment.status = "failed"
                    device_deployment.error_message = str(e)

                    await self.rollback.rollback_all(deployed, "Canary deployment failure")
                    raise Exception(f"Canary deployment failed at {stage['percentage']}%: {e}")

            if stage['wait_minutes'] > 0:
                await self._monitor_health(deployed, stage['wait_minutes'])

        return {
            "strategy": "canary",
            "stages_completed": len(stages),
            "total_devices": len(devices),
            "deployed": len(deployed),
            "failed": len(failed)
        }

    async def execute_blue_green_deployment(
        self,
        deployment: Deployment
    ) -> Dict[str, Any]:
        return {
            "strategy": "blue_green",
            "status": "not_implemented"
        }

    async def _backup_device_config(self, device: Device) -> str:
        connection = await self.device_connector.connect_to_device(
            device.id,
            {"user_id": "system"}
        )

        backup_config = await connection.get_running_config()

        encrypted = self.encryption.encrypt_config(
            backup_config,
            {"device_id": str(device.id), "timestamp": datetime.utcnow().isoformat()}
        )

        backup = DeviceConfig(
            device_id=device.id,
            config_encrypted=json.dumps(encrypted),
            config_hash=hashlib.sha256(backup_config.encode()).hexdigest(),
            encryption_key_id=encrypted["encrypted_key"],
            backup_location=f"backups/{device.hostname}/{datetime.utcnow().isoformat()}",
            version=self._get_next_version(device),
            is_current=False
        )

        self.db.add(backup)
        self.db.commit()

        return str(backup.id)

    def _get_next_version(self, device: Device) -> int:
        latest = self.db.query(DeviceConfig).filter(
            DeviceConfig.device_id == device.id
        ).order_by(DeviceConfig.version.desc()).first()

        return (latest.version + 1) if latest else 1

    async def _apply_config_to_device(self, device: Device, config: Dict[str, Any]):
        connection = await self.device_connector.connect_to_device(
            device.id,
            {"user_id": "system"}
        )

        await connection.apply_configuration(config)

    async def _validate_device_health(self, device: Device) -> bool:
        connection = await self.device_connector.connect_to_device(
            device.id,
            {"user_id": "system"}
        )

        health = await connection.check_health()
        return health.get("status") == "healthy"

    async def _rollback_device_config(self, device: Device, backup_id: str):
        backup = self.db.query(DeviceConfig).filter(
            DeviceConfig.id == backup_id
        ).first()

        if not backup:
            logger.error(f"Backup {backup_id} not found for rollback")
            return

        encrypted_data = json.loads(backup.config_encrypted)
        config = self.encryption.decrypt_config(encrypted_data)

        connection = await self.device_connector.connect_to_device(
            device.id,
            {"user_id": "system"}
        )

        await connection.apply_configuration({"raw_config": config})

    def _get_device_config(self, deployment: Deployment, device_id: str) -> Dict[str, Any]:
        config = self.db.query(DeploymentConfig).filter(
            and_(
                DeploymentConfig.deployment_id == deployment.id,
                DeploymentConfig.device_id == device_id
            )
        ).first()

        if config:
            return json.loads(config.config_content)

        return {}

    async def _monitor_health(self, devices: List[DeploymentDevice], minutes: int):
        end_time = datetime.utcnow() + timedelta(minutes=minutes)

        while datetime.utcnow() < end_time:
            for device_deployment in devices:
                device = self.db.query(Device).filter(
                    Device.id == device_deployment.device_id
                ).first()

                if not await self._validate_device_health(device):
                    raise Exception(f"Device {device.hostname} became unhealthy during monitoring")

            await asyncio.sleep(60)