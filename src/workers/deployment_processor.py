import asyncio
import json
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import structlog
from celery import Celery, Task
from celery.result import AsyncResult
from kombu import Queue, Exchange
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from ..db.database import database
from ..db.models import (
    Deployment, DeploymentState, DeploymentDevice,
    Device, DeviceConfig, User, AuditLog
)
from ..core.deployment_service import deployment_service
from ..devices.secure_connector import secure_device_connector
from ..security.encryption import encryption_service
from ..security.vault import VaultClient

logger = structlog.get_logger()

# Celery configuration
celery_app = Celery(
    'catnet_workers',
    broker=f'redis://{os.getenv("REDIS_HOST", "localhost")}:{os.getenv("REDIS_PORT", 6379)}/0',
    backend=f'redis://{os.getenv("REDIS_HOST", "localhost")}:{os.getenv("REDIS_PORT", 6379)}/1'
)

# Configure Celery
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour hard limit
    task_soft_time_limit=3000,  # 50 minutes soft limit
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=100,
    task_default_queue='default',
    task_queues=(
        Queue('default', Exchange('default'), routing_key='default'),
        Queue('deployments', Exchange('deployments'), routing_key='deployment.*'),
        Queue('high_priority', Exchange('high_priority'), routing_key='high.*'),
        Queue('device_ops', Exchange('device_ops'), routing_key='device.*'),
    ),
    task_routes={
        'workers.deployment_processor.process_deployment': {'queue': 'deployments'},
        'workers.deployment_processor.execute_device_deployment': {'queue': 'device_ops'},
        'workers.deployment_processor.rollback_deployment': {'queue': 'high_priority'},
        'workers.deployment_processor.validate_deployment_health': {'queue': 'deployments'},
    },
    beat_schedule={
        'check-stale-deployments': {
            'task': 'workers.deployment_processor.check_stale_deployments',
            'schedule': 300.0,  # Every 5 minutes
        },
        'cleanup-old-deployments': {
            'task': 'workers.deployment_processor.cleanup_old_deployments',
            'schedule': 86400.0,  # Daily
        },
    }
)


class DeploymentProcessor:
    """Async worker for processing deployments"""

    def __init__(self):
        self.vault = VaultClient()
        self.encryption = encryption_service
        self.active_deployments: Dict[str, Dict[str, Any]] = {}

    @celery_app.task(bind=True, name='workers.deployment_processor.process_deployment')
    async def process_deployment(
        self,
        deployment_id: str,
        user_id: str,
        strategy: str = "rolling"
    ) -> Dict[str, Any]:
        """Process a deployment asynchronously"""

        task_id = self.request.id
        logger.info(f"Starting deployment processing: {deployment_id}, Task: {task_id}")

        try:
            # Update task state
            self.update_state(
                state='PROGRESS',
                meta={
                    'current': 0,
                    'total': 100,
                    'status': 'Initializing deployment'
                }
            )

            async with database.get_session() as db:
                # Get deployment
                result = await db.execute(
                    select(Deployment).where(Deployment.id == uuid.UUID(deployment_id))
                )
                deployment = result.scalar_one_or_none()

                if not deployment:
                    raise ValueError(f"Deployment not found: {deployment_id}")

                # Verify state
                if deployment.state != DeploymentState.APPROVED:
                    raise ValueError(f"Deployment not approved: {deployment.state}")

                # Update deployment state
                deployment.state = DeploymentState.IN_PROGRESS
                deployment.started_at = datetime.utcnow()
                await db.commit()

                # Get deployment devices
                result = await db.execute(
                    select(DeploymentDevice)
                    .where(DeploymentDevice.deployment_id == deployment.id)
                    .join(Device)
                )
                deployment_devices = result.scalars().all()

                total_devices = len(deployment_devices)

                # Store in active deployments
                self.active_deployments[deployment_id] = {
                    'task_id': task_id,
                    'started_at': datetime.utcnow(),
                    'total_devices': total_devices,
                    'completed_devices': 0,
                    'failed_devices': 0
                }

                # Get encrypted configuration
                encrypted_config = await self.vault.get_secret(
                    f"deployments/{deployment_id}/config"
                )

                # Decrypt configuration
                encryption_key = await self.vault.get_encryption_key("catnet-configs")
                config_content = self.encryption.decrypt_config(
                    encrypted_config,
                    encryption_key
                )

                # Execute based on strategy
                if strategy == "canary":
                    result = await self._execute_canary_deployment(
                        db, deployment, deployment_devices, config_content, task_id
                    )
                elif strategy == "blue_green":
                    result = await self._execute_blue_green_deployment(
                        db, deployment, deployment_devices, config_content, task_id
                    )
                elif strategy == "all_at_once":
                    result = await self._execute_parallel_deployment(
                        db, deployment, deployment_devices, config_content, task_id
                    )
                else:
                    result = await self._execute_rolling_deployment(
                        db, deployment, deployment_devices, config_content, task_id
                    )

                # Update final state
                if result['success']:
                    deployment.state = DeploymentState.COMPLETED
                    deployment.completed_at = datetime.utcnow()
                else:
                    deployment.state = DeploymentState.FAILED
                    deployment.error_details = result.get('errors')

                await db.commit()

                # Clean up active deployment
                del self.active_deployments[deployment_id]

                # Log completion
                await self._log_audit(
                    db,
                    user_id,
                    "deployment.completed",
                    deployment_id=deployment_id,
                    result=result
                )

                return result

        except Exception as e:
            logger.error(f"Deployment processing failed: {e}")

            # Update deployment state
            try:
                async with database.get_session() as db:
                    await db.execute(
                        update(Deployment)
                        .where(Deployment.id == uuid.UUID(deployment_id))
                        .values(
                            state=DeploymentState.FAILED,
                            error_details={'error': str(e)}
                        )
                    )
                    await db.commit()
            except Exception:
                pass

            # Clean up
            if deployment_id in self.active_deployments:
                del self.active_deployments[deployment_id]

            raise

    async def _execute_rolling_deployment(
        self,
        db: AsyncSession,
        deployment: Deployment,
        deployment_devices: List[DeploymentDevice],
        config_content: str,
        task_id: str
    ) -> Dict[str, Any]:
        """Execute rolling deployment strategy"""

        batch_size = max(1, len(deployment_devices) // 10)
        deployed_successfully = []
        failed_devices = []
        total = len(deployment_devices)

        for i in range(0, len(deployment_devices), batch_size):
            batch = deployment_devices[i:i+batch_size]
            batch_num = (i // batch_size) + 1
            total_batches = (total + batch_size - 1) // batch_size

            # Update task progress
            progress = int((i / total) * 100)
            celery_app.current_task.update_state(
                state='PROGRESS',
                meta={
                    'current': progress,
                    'total': 100,
                    'status': f'Deploying batch {batch_num}/{total_batches}'
                }
            )

            # Process batch
            batch_results = await asyncio.gather(*[
                self._deploy_to_device(
                    db,
                    deployment_device,
                    config_content,
                    deployment.dry_run
                )
                for deployment_device in batch
            ], return_exceptions=True)

            # Process results
            for idx, result in enumerate(batch_results):
                deployment_device = batch[idx]

                if isinstance(result, Exception):
                    failed_devices.append(deployment_device.device_id)
                    deployment_device.status = "failed"
                    deployment_device.error_message = str(result)

                    if deployment.rollback_on_failure:
                        # Trigger rollback
                        await self._rollback_deployed_devices(
                            db, deployed_successfully, deployment_devices
                        )
                        return {
                            'success': False,
                            'deployed': len(deployed_successfully),
                            'failed': len(failed_devices),
                            'rolled_back': True
                        }
                else:
                    deployed_successfully.append(deployment_device.device_id)
                    deployment_device.status = "deployed"
                    deployment_device.deployed_at = datetime.utcnow()
                    deployment_device.health_check_passed = result.get('health_check', False)

                await db.commit()

            # Health monitoring between batches
            if i + batch_size < len(deployment_devices):
                await self._monitor_batch_health(deployed_successfully, 30)

        return {
            'success': len(failed_devices) == 0,
            'deployed': len(deployed_successfully),
            'failed': len(failed_devices),
            'total': total
        }

    async def _execute_canary_deployment(
        self,
        db: AsyncSession,
        deployment: Deployment,
        deployment_devices: List[DeploymentDevice],
        config_content: str,
        task_id: str
    ) -> Dict[str, Any]:
        """Execute canary deployment strategy"""

        stages = [
            {'percentage': deployment.canary_percentage, 'wait_minutes': 5},
            {'percentage': 25, 'wait_minutes': 10},
            {'percentage': 50, 'wait_minutes': 15},
            {'percentage': 100, 'wait_minutes': 0}
        ]

        devices = deployment_devices
        deployed_successfully = []
        failed_devices = []

        for stage_idx, stage in enumerate(stages):
            device_count = max(1, int(len(devices) * stage['percentage'] / 100))
            stage_devices = devices[:device_count]
            new_devices = [
                d for d in stage_devices
                if d.device_id not in deployed_successfully
            ]

            # Update progress
            stage_progress = int((stage_idx / len(stages)) * 100)
            celery_app.current_task.update_state(
                state='PROGRESS',
                meta={
                    'current': stage_progress,
                    'total': 100,
                    'status': f"Canary stage {stage['percentage']}%: {len(new_devices)} devices"
                }
            )

            # Deploy to new devices
            for deployment_device in new_devices:
                try:
                    result = await self._deploy_to_device(
                        db,
                        deployment_device,
                        config_content,
                        deployment.dry_run
                    )

                    if result['success']:
                        deployed_successfully.append(deployment_device.device_id)
                        deployment_device.status = "deployed"
                        deployment_device.deployed_at = datetime.utcnow()
                        deployment_device.health_check_passed = result.get('health_check', False)
                    else:
                        raise Exception(result.get('error', 'Deployment failed'))

                except Exception as e:
                    failed_devices.append(deployment_device.device_id)
                    deployment_device.status = "failed"
                    deployment_device.error_message = str(e)

                    if deployment.rollback_on_failure:
                        await self._rollback_deployed_devices(
                            db, deployed_successfully, deployment_devices
                        )
                        return {
                            'success': False,
                            'stage': f"{stage['percentage']}%",
                            'deployed': len(deployed_successfully),
                            'failed': len(failed_devices),
                            'rolled_back': True
                        }

                await db.commit()

            # Wait and monitor between stages
            if stage['wait_minutes'] > 0:
                await self._monitor_canary_health(
                    deployed_successfully,
                    stage['wait_minutes'] * 60
                )

        return {
            'success': len(failed_devices) == 0,
            'deployed': len(deployed_successfully),
            'failed': len(failed_devices),
            'total': len(devices)
        }

    async def _deploy_to_device(
        self,
        db: AsyncSession,
        deployment_device: DeploymentDevice,
        config_content: str,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """Deploy configuration to a single device"""

        try:
            device = deployment_device.device

            # Backup current configuration
            backup_id = await self._backup_device_config(db, device)
            deployment_device.backup_config_id = backup_id

            # Connect to device
            connection = await secure_device_connector.connect_to_device(
                str(device.id),
                {"system": True},
                db
            )

            try:
                if dry_run:
                    # Validate only
                    result = await connection.validate_configuration(config_content)
                    if not result['valid']:
                        raise ValueError(f"Validation failed: {result.get('errors')}")
                else:
                    # Apply configuration
                    result = await connection.apply_configuration(config_content)
                    if not result['success']:
                        raise ValueError(f"Apply failed: {result.get('error')}")

                    # Save configuration
                    await connection.save_configuration()

                # Run health check
                health_checks = await connection.run_health_checks()
                health_passed = all(check['passed'] for check in health_checks)

                return {
                    'success': True,
                    'health_check': health_passed,
                    'health_results': health_checks
                }

            finally:
                await connection.close()

        except Exception as e:
            logger.error(f"Device deployment failed for {device.name}: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    async def _backup_device_config(
        self,
        db: AsyncSession,
        device: Device
    ) -> uuid.UUID:
        """Create backup of device configuration"""

        try:
            connection = await secure_device_connector.connect_to_device(
                str(device.id),
                {"system": True},
                db
            )

            try:
                # Get current configuration
                current_config = await connection.get_configuration()

                # Encrypt configuration
                encryption_key = await self.vault.get_encryption_key("catnet-backups")
                encrypted_config = self.encryption.encrypt_config(
                    current_config,
                    encryption_key
                )

                # Store in Vault
                backup_location = f"backups/{device.id}/{datetime.utcnow().isoformat()}"
                await self.vault.store_secret(backup_location, encrypted_config)

                # Create database record
                config_backup = DeviceConfig(
                    device_id=device.id,
                    config_encrypted=json.dumps(encrypted_config),
                    config_hash=hashlib.sha256(current_config.encode()).hexdigest(),
                    encryption_key_id=encrypted_config.get("key_id"),
                    backup_location=backup_location,
                    version=await self._get_next_version(db, device.id),
                    is_current=False
                )

                db.add(config_backup)
                await db.commit()
                await db.refresh(config_backup)

                return config_backup.id

            finally:
                await connection.close()

        except Exception as e:
            logger.error(f"Failed to backup device {device.name}: {e}")
            raise

    async def _get_next_version(
        self,
        db: AsyncSession,
        device_id: uuid.UUID
    ) -> int:
        """Get next configuration version number"""

        result = await db.execute(
            select(DeviceConfig)
            .where(DeviceConfig.device_id == device_id)
            .order_by(DeviceConfig.version.desc())
            .limit(1)
        )
        last_config = result.scalar_one_or_none()
        return (last_config.version + 1) if last_config else 1

    async def _rollback_deployed_devices(
        self,
        db: AsyncSession,
        device_ids: List[uuid.UUID],
        deployment_devices: List[DeploymentDevice]
    ):
        """Rollback deployed devices to previous configuration"""

        for device_id in device_ids:
            try:
                deployment_device = next(
                    dd for dd in deployment_devices
                    if dd.device_id == device_id
                )

                if deployment_device.backup_config_id:
                    # Get backup configuration
                    result = await db.execute(
                        select(DeviceConfig).where(
                            DeviceConfig.id == deployment_device.backup_config_id
                        )
                    )
                    backup_config = result.scalar_one_or_none()

                    if backup_config:
                        # Decrypt configuration
                        encrypted_config = json.loads(backup_config.config_encrypted)
                        encryption_key = await self.vault.get_encryption_key("catnet-backups")
                        config_content = self.encryption.decrypt_config(
                            encrypted_config,
                            encryption_key
                        )

                        # Apply backup configuration
                        connection = await secure_device_connector.connect_to_device(
                            str(device_id),
                            {"system": True},
                            db
                        )

                        try:
                            await connection.apply_configuration(config_content)
                            await connection.save_configuration()

                            deployment_device.status = "rolled_back"
                            deployment_device.rolled_back_at = datetime.utcnow()
                            await db.commit()

                        finally:
                            await connection.close()

            except Exception as e:
                logger.error(f"Failed to rollback device {device_id}: {e}")

    async def _monitor_batch_health(
        self,
        device_ids: List[uuid.UUID],
        duration_seconds: int
    ):
        """Monitor health of deployed devices"""

        end_time = datetime.utcnow() + timedelta(seconds=duration_seconds)

        while datetime.utcnow() < end_time:
            for device_id in device_ids:
                try:
                    async with database.get_session() as db:
                        connection = await secure_device_connector.connect_to_device(
                            str(device_id),
                            {"system": True},
                            db
                        )

                        try:
                            health_checks = await connection.run_health_checks()
                            if not all(check['passed'] for check in health_checks):
                                raise Exception(f"Health degradation on device {device_id}")

                        finally:
                            await connection.close()

                except Exception as e:
                    logger.error(f"Health monitoring error: {e}")
                    raise

            await asyncio.sleep(10)

    async def _monitor_canary_health(
        self,
        device_ids: List[uuid.UUID],
        duration_seconds: int
    ):
        """Monitor canary devices during wait period"""

        await self._monitor_batch_health(device_ids, duration_seconds)

    async def _log_audit(
        self,
        db: AsyncSession,
        user_id: str,
        action: str,
        **details
    ):
        """Log audit entry"""

        audit = AuditLog(
            user_id=uuid.UUID(user_id) if user_id else None,
            action=action,
            details=details,
            success=True
        )
        db.add(audit)
        await db.commit()

    @celery_app.task(name='workers.deployment_processor.check_stale_deployments')
    async def check_stale_deployments():
        """Check for stale deployments that need cleanup"""

        async with database.get_session() as db:
            # Find deployments stuck in IN_PROGRESS for too long
            stale_time = datetime.utcnow() - timedelta(hours=2)

            result = await db.execute(
                select(Deployment).where(
                    Deployment.state == DeploymentState.IN_PROGRESS,
                    Deployment.started_at < stale_time
                )
            )
            stale_deployments = result.scalars().all()

            for deployment in stale_deployments:
                logger.warning(f"Found stale deployment: {deployment.id}")

                # Mark as failed
                deployment.state = DeploymentState.FAILED
                deployment.error_details = {"error": "Deployment timed out"}
                await db.commit()

    @celery_app.task(name='workers.deployment_processor.cleanup_old_deployments')
    async def cleanup_old_deployments():
        """Clean up old deployment records and artifacts"""

        async with database.get_session() as db:
            # Find old deployments
            old_time = datetime.utcnow() - timedelta(days=90)

            result = await db.execute(
                select(Deployment).where(
                    Deployment.created_at < old_time
                )
            )
            old_deployments = result.scalars().all()

            vault = VaultClient()

            for deployment in old_deployments:
                try:
                    # Delete Vault secrets
                    await vault.delete_secret(f"deployments/{deployment.id}/config")

                    logger.info(f"Cleaned up deployment artifacts: {deployment.id}")

                except Exception as e:
                    logger.error(f"Failed to cleanup deployment {deployment.id}: {e}")


# Initialize processor
deployment_processor = DeploymentProcessor()

# Export Celery tasks
process_deployment = deployment_processor.process_deployment
check_stale_deployments = deployment_processor.check_stale_deployments
cleanup_old_deployments = deployment_processor.cleanup_old_deployments