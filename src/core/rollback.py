import logging
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from sqlalchemy.orm import Session

from ..db.models import Deployment, DeploymentDevice, Device, DeviceConfig
from ..security.vault_client import VaultClient
from ..security.audit import AuditLogger
from ..security.encryption import EncryptionService

logger = logging.getLogger(__name__)

class RollbackManager:
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

    async def rollback_deployment(
        self,
        deployment: Deployment,
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        logger.info(f"Starting rollback for deployment {deployment.id}")

        rollback_results = {
            "deployment_id": str(deployment.id),
            "reason": reason,
            "devices": [],
            "success": True,
            "timestamp": datetime.utcnow().isoformat()
        }

        for device_deployment in deployment.devices:
            if device_deployment.status == "completed" and device_deployment.pre_config_backup_id:
                device = self.db.query(Device).filter(
                    Device.id == device_deployment.device_id
                ).first()

                if device:
                    result = await self.rollback_device(
                        device,
                        device_deployment.pre_config_backup_id
                    )

                    rollback_results["devices"].append({
                        "device_id": str(device.id),
                        "hostname": device.hostname,
                        "rollback_status": result["status"],
                        "error": result.get("error")
                    })

                    if result["status"] != "success":
                        rollback_results["success"] = False

                    device_deployment.rollback_performed = True

        self.db.commit()

        await self.audit.log_event(
            action="deployment_rollback_completed",
            resource_type="deployment",
            resource_id=str(deployment.id),
            details=rollback_results
        )

        return rollback_results

    async def rollback_device(
        self,
        device: Device,
        backup_config_id: str
    ) -> Dict[str, Any]:
        try:
            backup = self.db.query(DeviceConfig).filter(
                DeviceConfig.id == backup_config_id
            ).first()

            if not backup:
                return {
                    "status": "failed",
                    "error": f"Backup configuration {backup_config_id} not found"
                }

            import json
            encrypted_data = json.loads(backup.config_encrypted)
            config_content = self.encryption.decrypt_config(encrypted_data)

            from ..devices.device_connector import SecureDeviceConnector
            connector = SecureDeviceConnector(self.db, self.vault, self.audit)

            connection = await connector.connect_to_device(
                str(device.id),
                {"user_id": "system", "action": "rollback"}
            )

            await connection.apply_configuration({"raw_config": config_content})

            health_check = await connection.check_health()
            if not health_check.get("healthy", False):
                logger.error(f"Device {device.hostname} unhealthy after rollback")

            current_configs = self.db.query(DeviceConfig).filter(
                DeviceConfig.device_id == device.id,
                DeviceConfig.is_current == True
            ).all()

            for config in current_configs:
                config.is_current = False

            backup.is_current = True
            self.db.commit()

            await self.audit.log_event(
                action="device_rollback_success",
                resource_type="device",
                resource_id=str(device.id),
                details={
                    "hostname": device.hostname,
                    "backup_id": backup_config_id
                }
            )

            return {"status": "success"}

        except Exception as e:
            logger.error(f"Failed to rollback device {device.hostname}: {e}")

            await self.audit.log_event(
                action="device_rollback_failed",
                resource_type="device",
                resource_id=str(device.id),
                details={
                    "hostname": device.hostname,
                    "error": str(e)
                },
                severity="ERROR"
            )

            return {
                "status": "failed",
                "error": str(e)
            }

    async def rollback_all(
        self,
        deployed_devices: List[DeploymentDevice],
        reason: str
    ) -> Dict[str, Any]:
        results = {
            "reason": reason,
            "devices": [],
            "total": len(deployed_devices),
            "success": 0,
            "failed": 0
        }

        for device_deployment in deployed_devices:
            if device_deployment.pre_config_backup_id:
                device = self.db.query(Device).filter(
                    Device.id == device_deployment.device_id
                ).first()

                if device:
                    result = await self.rollback_device(
                        device,
                        device_deployment.pre_config_backup_id
                    )

                    if result["status"] == "success":
                        results["success"] += 1
                    else:
                        results["failed"] += 1

                    results["devices"].append({
                        "device": device.hostname,
                        "result": result
                    })

        return results

    async def create_rollback_checkpoint(
        self,
        device: Device,
        description: str = "Manual checkpoint"
    ) -> str:
        from ..devices.device_connector import SecureDeviceConnector
        connector = SecureDeviceConnector(self.db, self.vault, self.audit)

        connection = await connector.connect_to_device(
            str(device.id),
            {"user_id": "system", "action": "backup"}
        )

        current_config = await connection.get_running_config()

        encrypted = self.encryption.encrypt_config(
            current_config,
            {
                "device_id": str(device.id),
                "timestamp": datetime.utcnow().isoformat(),
                "description": description
            }
        )

        import hashlib
        config = DeviceConfig(
            device_id=device.id,
            config_encrypted=json.dumps(encrypted),
            config_hash=hashlib.sha256(current_config.encode()).hexdigest(),
            encryption_key_id=encrypted["encrypted_key"],
            backup_location=f"checkpoints/{device.hostname}/{datetime.utcnow().isoformat()}",
            version=self._get_next_version(device),
            is_current=False,
            validation_status="checkpoint"
        )

        self.db.add(config)
        self.db.commit()

        await self.audit.log_event(
            action="rollback_checkpoint_created",
            resource_type="device",
            resource_id=str(device.id),
            details={
                "hostname": device.hostname,
                "checkpoint_id": str(config.id),
                "description": description
            }
        )

        return str(config.id)

    def _get_next_version(self, device: Device) -> int:
        latest = self.db.query(DeviceConfig).filter(
            DeviceConfig.device_id == device.id
        ).order_by(DeviceConfig.version.desc()).first()

        return (latest.version + 1) if latest else 1

    async def list_checkpoints(
        self,
        device: Device,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        checkpoints = self.db.query(DeviceConfig).filter(
            DeviceConfig.device_id == device.id
        ).order_by(DeviceConfig.created_at.desc()).limit(limit).all()

        results = []
        for checkpoint in checkpoints:
            results.append({
                "id": str(checkpoint.id),
                "version": checkpoint.version,
                "created_at": checkpoint.created_at.isoformat(),
                "is_current": checkpoint.is_current,
                "validation_status": checkpoint.validation_status,
                "hash": checkpoint.config_hash[:8]
            })

        return results