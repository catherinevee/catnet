"""
Backup worker for async backup operations.
Handles device configuration backups and restoration.
"""

import asyncio
import hashlib
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from pathlib import Path
from uuid import UUID
import aiofiles

from src.workers.base import BaseWorker, WorkerTask
from src.devices.connector import SecureDeviceConnector
from src.security.encryption import EncryptionManager
from src.security.vault import VaultClient
from src.core.exceptions import BackupError
from src.db.models import Device, ConfigBackup
from src.core.config import get_settings


class BackupWorker(BaseWorker):
    """
    Worker for processing backup tasks.
    Handles configuration backups, restoration, and retention management.
    """

    def __init__(self, **kwargs):
        """Initialize backup worker."""
        super().__init__(**kwargs)
        self.device_connector = SecureDeviceConnector()
        self.encryption = EncryptionManager()
        self.vault = VaultClient()
        self.settings = get_settings()

        # Backup storage configuration
        self.backup_base_path = Path(self.settings.BACKUP_STORAGE_PATH)
        self.backup_base_path.mkdir(parents=True, exist_ok=True)

    def get_worker_type(self) -> str:
        """Get worker type identifier."""
        return "backup"

    async def process_task(self, task: WorkerTask) -> Dict[str, Any]:
        """
        Process backup task.

        Args:
            task: Backup task

        Returns:
            Task result
        """
        task_type = task.task_type
        payload = task.payload

        if task_type == "create_backup":
            return await self._create_backup(payload)

        elif task_type == "restore_backup":
            return await self._restore_backup(payload)

        elif task_type == "scheduled_backup":
            return await self._scheduled_backup(payload)

        elif task_type == "cleanup_old_backups":
            return await self._cleanup_old_backups(payload)

        elif task_type == "verify_backup":
            return await self._verify_backup(payload)

        elif task_type == "bulk_backup":
            return await self._bulk_backup(payload)

        else:
            raise ValueError(f"Unknown task type: {task_type}")

    async def _create_backup(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Create device configuration backup."""
        device_id = UUID(payload['device_id'])
        user_id = payload.get('user_id')
        description = payload.get('description', 'Manual backup')

        try:
            async with get_db() as db:
                # Get device
                device = await db.get(Device, device_id)
                if not device:
                    raise BackupError(f"Device {device_id} not found")

                # Connect to device
                connection = await self.device_connector.connect_to_device(
                    device_id=str(device_id),
                    user_context={'user_id': str(user_id)} if user_id else {'system': True}
                )

                # Get current configuration
                config = await connection.get_configuration()

                # Generate backup metadata
                backup_id = UUID()
                timestamp = datetime.utcnow()
                config_hash = hashlib.sha256(config.encode()).hexdigest()

                # Encrypt configuration
                encrypted_config = await self.encryption.encrypt(config)

                # Store backup file
                backup_path = await self._store_backup_file(
                    device_id=device_id,
                    backup_id=backup_id,
                    encrypted_config=encrypted_config,
                    timestamp=timestamp
                )

                # Create database record
                backup = ConfigBackup(
                    id=backup_id,
                    device_id=device_id,
                    config_hash=config_hash,
                    file_path=str(backup_path),
                    size_bytes=len(encrypted_config),
                    description=description,
                    created_at=timestamp,
                    created_by=UUID(user_id) if user_id else None,
                    is_encrypted=True,
                    encryption_key_id=self.encryption.get_current_key_id(),
                    metadata={
                        'device_hostname': device.hostname,
                        'device_vendor': device.vendor,
                        'device_model': device.model,
                        'config_lines': len(config.split('\n'))
                    }
                )

                db.add(backup)
                await db.commit()

                # Update device last backup
                device.last_backup_id = backup_id
                device.last_backup_at = timestamp
                await db.commit()

                await self.audit.log_event(
                    event_type="BACKUP_CREATED",
                    user_id=str(user_id) if user_id else None,
                    details={
                        'device_id': str(device_id),
                        'backup_id': str(backup_id),
                        'size_bytes': len(encrypted_config)
                    }
                )

                return {
                    'status': 'success',
                    'backup_id': str(backup_id),
                    'device_id': str(device_id),
                    'timestamp': timestamp.isoformat(),
                    'config_hash': config_hash,
                    'size_bytes': len(encrypted_config)
                }

        except Exception as e:
            raise BackupError(f"Backup creation failed: {e}")

    async def _restore_backup(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Restore configuration from backup."""
        device_id = UUID(payload['device_id'])
        backup_id = UUID(payload['backup_id'])
        user_id = payload.get('user_id')
        verify = payload.get('verify', True)

        try:
            async with get_db() as db:
                # Get backup record
                backup = await db.get(ConfigBackup, backup_id)
                if not backup:
                    raise BackupError(f"Backup {backup_id} not found")

                # Verify backup belongs to device
                if backup.device_id != device_id:
                    raise BackupError(f"Backup {backup_id} does not belong to device {device_id}")

                # Get device
                device = await db.get(Device, device_id)
                if not device:
                    raise BackupError(f"Device {device_id} not found")

                # Load and decrypt backup
                encrypted_config = await self._load_backup_file(backup.file_path)
                config = await self.encryption.decrypt(encrypted_config)

                # Verify integrity if requested
                if verify:
                    config_hash = hashlib.sha256(config.encode()).hexdigest()
                    if config_hash != backup.config_hash:
                        raise BackupError("Backup integrity check failed")

                # Create current backup before restore
                pre_restore_backup = await self._create_backup({
                    'device_id': str(device_id),
                    'description': f'Pre-restore backup (restoring {backup_id})'
                })

                # Connect to device
                connection = await self.device_connector.connect_to_device(
                    device_id=str(device_id),
                    user_context={'user_id': str(user_id)} if user_id else {'system': True}
                )

                # Apply configuration
                await connection.apply_configuration(config)

                # Verify device is healthy
                health = await connection.check_health()
                if not health.get('healthy', False):
                    # Rollback to pre-restore backup
                    await self._restore_backup({
                        'device_id': str(device_id),
                        'backup_id': pre_restore_backup['backup_id'],
                        'verify': False
                    })
                    raise BackupError("Device unhealthy after restore, rolled back")

                # Update restore tracking
                backup.last_restored_at = datetime.utcnow()
                backup.restore_count = (backup.restore_count or 0) + 1
                await db.commit()

                await self.audit.log_event(
                    event_type="BACKUP_RESTORED",
                    user_id=str(user_id) if user_id else None,
                    details={
                        'device_id': str(device_id),
                        'backup_id': str(backup_id),
                        'pre_restore_backup': pre_restore_backup['backup_id']
                    }
                )

                return {
                    'status': 'success',
                    'device_id': str(device_id),
                    'backup_id': str(backup_id),
                    'pre_restore_backup': pre_restore_backup['backup_id'],
                    'restored_at': datetime.utcnow().isoformat()
                }

        except Exception as e:
            raise BackupError(f"Backup restore failed: {e}")

    async def _scheduled_backup(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Perform scheduled backup for devices."""
        schedule_name = payload.get('schedule_name', 'daily')
        device_filter = payload.get('device_filter', {})

        try:
            async with get_db() as db:
                # Get devices based on filter
                query = db.query(Device).filter(Device.is_active == True)

                # Apply filters
                if device_filter.get('vendor'):
                    query = query.filter(Device.vendor == device_filter['vendor'])
                if device_filter.get('location'):
                    query = query.filter(Device.location == device_filter['location'])
                if device_filter.get('is_critical') is not None:
                    query = query.filter(Device.is_critical == device_filter['is_critical'])

                devices = await query.all()

                # Create backups for each device
                results = []
                for device in devices:
                    try:
                        backup_result = await self._create_backup({
                            'device_id': str(device.id),
                            'description': f'Scheduled backup ({schedule_name})'
                        })
                        results.append({
                            'device_id': str(device.id),
                            'status': 'success',
                            'backup_id': backup_result['backup_id']
                        })
                    except Exception as e:
                        results.append({
                            'device_id': str(device.id),
                            'status': 'failed',
                            'error': str(e)
                        })

                # Calculate statistics
                successful = len([r for r in results if r['status'] == 'success'])
                failed = len([r for r in results if r['status'] == 'failed'])

                return {
                    'status': 'completed',
                    'schedule_name': schedule_name,
                    'total_devices': len(devices),
                    'successful': successful,
                    'failed': failed,
                    'results': results
                }

        except Exception as e:
            raise BackupError(f"Scheduled backup failed: {e}")

    async def _cleanup_old_backups(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Clean up old backup files based on retention policy."""
        retention_days = payload.get('retention_days', 30)
        keep_minimum = payload.get('keep_minimum', 5)

        try:
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

            async with get_db() as db:
                # Get devices
                devices = await db.query(Device).all()

                total_deleted = 0
                space_freed = 0

                for device in devices:
                    # Get backups for device
                    backups = await db.query(ConfigBackup).filter(
                        ConfigBackup.device_id == device.id
                    ).order_by(ConfigBackup.created_at.desc()).all()

                    # Keep minimum number of backups
                    if len(backups) <= keep_minimum:
                        continue

                    # Delete old backups
                    for backup in backups[keep_minimum:]:
                        if backup.created_at < cutoff_date:
                            # Delete file
                            backup_path = Path(backup.file_path)
                            if backup_path.exists():
                                file_size = backup_path.stat().st_size
                                backup_path.unlink()
                                space_freed += file_size

                            # Delete database record
                            await db.delete(backup)
                            total_deleted += 1

                await db.commit()

                await self.audit.log_event(
                    event_type="BACKUP_CLEANUP",
                    details={
                        'retention_days': retention_days,
                        'total_deleted': total_deleted,
                        'space_freed_bytes': space_freed
                    }
                )

                return {
                    'status': 'success',
                    'total_deleted': total_deleted,
                    'space_freed_bytes': space_freed,
                    'space_freed_mb': round(space_freed / (1024 * 1024), 2)
                }

        except Exception as e:
            raise BackupError(f"Backup cleanup failed: {e}")

    async def _verify_backup(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Verify backup integrity."""
        backup_id = UUID(payload['backup_id'])

        try:
            async with get_db() as db:
                backup = await db.get(ConfigBackup, backup_id)
                if not backup:
                    raise BackupError(f"Backup {backup_id} not found")

                # Check file exists
                backup_path = Path(backup.file_path)
                if not backup_path.exists():
                    return {
                        'status': 'failed',
                        'backup_id': str(backup_id),
                        'error': 'Backup file not found',
                        'valid': False
                    }

                # Load and decrypt
                try:
                    encrypted_config = await self._load_backup_file(backup.file_path)
                    config = await self.encryption.decrypt(encrypted_config)
                except Exception as e:
                    return {
                        'status': 'failed',
                        'backup_id': str(backup_id),
                        'error': f'Decryption failed: {e}',
                        'valid': False
                    }

                # Verify hash
                config_hash = hashlib.sha256(config.encode()).hexdigest()
                hash_match = config_hash == backup.config_hash

                # Update verification timestamp
                backup.last_verified_at = datetime.utcnow()
                backup.is_valid = hash_match
                await db.commit()

                return {
                    'status': 'success',
                    'backup_id': str(backup_id),
                    'valid': hash_match,
                    'file_exists': True,
                    'hash_match': hash_match,
                    'size_bytes': len(encrypted_config),
                    'created_at': backup.created_at.isoformat()
                }

        except Exception as e:
            raise BackupError(f"Backup verification failed: {e}")

    async def _bulk_backup(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Create backups for multiple devices in parallel."""
        device_ids = payload.get('device_ids', [])
        description = payload.get('description', 'Bulk backup')
        user_id = payload.get('user_id')

        # Process in batches
        batch_size = 10
        results = []

        for i in range(0, len(device_ids), batch_size):
            batch = device_ids[i:i + batch_size]

            # Create backups in parallel
            batch_tasks = [
                self._create_backup({
                    'device_id': device_id,
                    'user_id': user_id,
                    'description': description
                })
                for device_id in batch
            ]

            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)

            # Process results
            for device_id, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    results.append({
                        'device_id': device_id,
                        'status': 'failed',
                        'error': str(result)
                    })
                else:
                    results.append({
                        'device_id': device_id,
                        'status': 'success',
                        'backup_id': result['backup_id']
                    })

        # Calculate statistics
        successful = len([r for r in results if r['status'] == 'success'])
        failed = len([r for r in results if r['status'] == 'failed'])

        return {
            'status': 'completed',
            'total': len(device_ids),
            'successful': successful,
            'failed': failed,
            'results': results
        }

    async def _store_backup_file(
        self,
        device_id: UUID,
        backup_id: UUID,
        encrypted_config: bytes,
        timestamp: datetime
    ) -> Path:
        """Store backup file on disk."""
        # Create directory structure
        date_path = timestamp.strftime('%Y/%m/%d')
        device_path = self.backup_base_path / str(device_id) / date_path
        device_path.mkdir(parents=True, exist_ok=True)

        # Generate filename
        filename = f"{backup_id}_{timestamp.strftime('%H%M%S')}.bak"
        file_path = device_path / filename

        # Write file
        async with aiofiles.open(file_path, 'wb') as f:
            await f.write(encrypted_config)

        return file_path

    async def _load_backup_file(self, file_path: str) -> bytes:
        """Load backup file from disk."""
        async with aiofiles.open(file_path, 'rb') as f:
            return await f.read()


# Export main components
__all__ = ['BackupWorker']