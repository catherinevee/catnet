"""
Cleanup worker for maintenance and housekeeping tasks.
Handles log rotation, temporary file cleanup, and data retention.
"""

import asyncio
import shutil
import os
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from pathlib import Path
from uuid import UUID

from src.workers.base import BaseWorker, WorkerTask
from src.core.exceptions import CleanupError
from src.db.models import (
    AuditLog, Session, Deployment, ConfigBackup,
    HealthCheck, Notification, RequestLog
)
from src.security.audit import AuditLogger
from src.core.config import get_settings


class CleanupWorker(BaseWorker):
    """
    Worker for processing cleanup and maintenance tasks.
    Handles data retention, log rotation, and temporary file cleanup.
    """

    def __init__(self, **kwargs):
        """Initialize cleanup worker."""
        super().__init__(**kwargs)
        self.audit = AuditLogger()
        self.settings = get_settings()

        # Retention policies (in days)
        self.retention_policies = {
            'audit_logs': 365,
            'request_logs': 90,
            'sessions': 30,
            'health_checks': 60,
            'notifications': 30,
            'temp_files': 7,
            'deployment_logs': 180,
            'config_backups': 90
        }

        # Cleanup paths
        self.temp_paths = [
            Path('/tmp/catnet'),
            Path('/var/tmp/catnet'),
            Path(self.settings.TEMP_PATH)
        ]

        self.log_paths = [
            Path('/var/log/catnet'),
            Path(self.settings.LOG_PATH)
        ]

    def get_worker_type(self) -> str:
        """Get worker type identifier."""
        return "cleanup"

    async def process_task(self, task: WorkerTask) -> Dict[str, Any]:
        """
        Process cleanup task.

        Args:
            task: Cleanup task

        Returns:
            Task result
        """
        task_type = task.task_type
        payload = task.payload

        if task_type == "cleanup_audit_logs":
            return await self._cleanup_audit_logs(payload)

        elif task_type == "cleanup_sessions":
            return await self._cleanup_sessions(payload)

        elif task_type == "cleanup_temp_files":
            return await self._cleanup_temp_files(payload)

        elif task_type == "rotate_logs":
            return await self._rotate_logs(payload)

        elif task_type == "cleanup_old_deployments":
            return await self._cleanup_old_deployments(payload)

        elif task_type == "cleanup_health_checks":
            return await self._cleanup_health_checks(payload)

        elif task_type == "cleanup_notifications":
            return await self._cleanup_notifications(payload)

        elif task_type == "cleanup_request_logs":
            return await self._cleanup_request_logs(payload)

        elif task_type == "vacuum_database":
            return await self._vacuum_database(payload)

        elif task_type == "cleanup_orphaned_files":
            return await self._cleanup_orphaned_files(payload)

        elif task_type == "full_cleanup":
            return await self._full_cleanup(payload)

        else:
            raise ValueError(f"Unknown task type: {task_type}")

    async def _cleanup_audit_logs(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Clean up old audit logs."""
        retention_days = payload.get('retention_days', self.retention_policies['audit_logs'])
        archive = payload.get('archive', True)

        try:
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

            async with get_db() as db:
                # Get logs to delete
                old_logs = await db.query(AuditLog).filter(
                    AuditLog.created_at < cutoff_date
                ).all()

                if archive and old_logs:
                    # Archive before deletion
                    await self._archive_records(old_logs, 'audit_logs')

                # Delete old logs
                deleted_count = await db.query(AuditLog).filter(
                    AuditLog.created_at < cutoff_date
                ).delete()

                await db.commit()

                await self.audit.log_event(
                    event_type="AUDIT_LOGS_CLEANED",
                    details={
                        'deleted_count': deleted_count,
                        'retention_days': retention_days,
                        'archived': archive
                    }
                )

                return {
                    'status': 'success',
                    'deleted_count': deleted_count,
                    'cutoff_date': cutoff_date.isoformat(),
                    'archived': archive
                }

        except Exception as e:
            raise CleanupError(f"Failed to cleanup audit logs: {e}")

    async def _cleanup_sessions(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Clean up expired sessions."""
        retention_days = payload.get('retention_days', self.retention_policies['sessions'])

        try:
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

            async with get_db() as db:
                # Delete expired sessions
                deleted_count = await db.query(Session).filter(
                    Session.expires_at < datetime.utcnow()
                ).delete()

                # Delete old inactive sessions
                old_inactive = await db.query(Session).filter(
                    Session.last_activity < cutoff_date
                ).delete()

                await db.commit()

                total_deleted = deleted_count + old_inactive

                await self.audit.log_event(
                    event_type="SESSIONS_CLEANED",
                    details={
                        'expired': deleted_count,
                        'inactive': old_inactive,
                        'total': total_deleted
                    }
                )

                return {
                    'status': 'success',
                    'expired_sessions': deleted_count,
                    'inactive_sessions': old_inactive,
                    'total_deleted': total_deleted
                }

        except Exception as e:
            raise CleanupError(f"Failed to cleanup sessions: {e}")

    async def _cleanup_temp_files(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Clean up temporary files."""
        retention_days = payload.get('retention_days', self.retention_policies['temp_files'])

        try:
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
            total_files = 0
            total_size = 0

            for temp_path in self.temp_paths:
                if not temp_path.exists():
                    continue

                for file_path in temp_path.rglob('*'):
                    if file_path.is_file():
                        # Check file age
                        file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                        if file_mtime < cutoff_date:
                            file_size = file_path.stat().st_size
                            file_path.unlink()
                            total_files += 1
                            total_size += file_size

                # Clean empty directories
                for dir_path in sorted(temp_path.rglob('*'), reverse=True):
                    if dir_path.is_dir() and not any(dir_path.iterdir()):
                        dir_path.rmdir()

            await self.audit.log_event(
                event_type="TEMP_FILES_CLEANED",
                details={
                    'files_deleted': total_files,
                    'size_freed_bytes': total_size,
                    'size_freed_mb': round(total_size / (1024 * 1024), 2)
                }
            )

            return {
                'status': 'success',
                'files_deleted': total_files,
                'size_freed_bytes': total_size,
                'size_freed_mb': round(total_size / (1024 * 1024), 2)
            }

        except Exception as e:
            raise CleanupError(f"Failed to cleanup temp files: {e}")

    async def _rotate_logs(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Rotate log files."""
        max_size_mb = payload.get('max_size_mb', 100)
        max_files = payload.get('max_files', 10)
        compress = payload.get('compress', True)

        try:
            rotated_files = []

            for log_path in self.log_paths:
                if not log_path.exists():
                    continue

                for log_file in log_path.glob('*.log'):
                    file_size_mb = log_file.stat().st_size / (1024 * 1024)

                    if file_size_mb > max_size_mb:
                        # Rotate the log file
                        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                        rotated_name = f"{log_file.stem}_{timestamp}.log"
                        rotated_path = log_file.parent / rotated_name

                        # Move current log to rotated
                        log_file.rename(rotated_path)

                        # Compress if requested
                        if compress:
                            import gzip
                            with open(rotated_path, 'rb') as f_in:
                                with gzip.open(f"{rotated_path}.gz", 'wb') as f_out:
                                    shutil.copyfileobj(f_in, f_out)
                            rotated_path.unlink()
                            rotated_path = Path(f"{rotated_path}.gz")

                        rotated_files.append(str(rotated_path))

                        # Create new empty log file
                        log_file.touch()

                        # Clean old rotated logs
                        pattern = f"{log_file.stem}_*.log*"
                        old_logs = sorted(log_path.glob(pattern))[:-max_files]
                        for old_log in old_logs:
                            old_log.unlink()

            await self.audit.log_event(
                event_type="LOGS_ROTATED",
                details={
                    'rotated_count': len(rotated_files),
                    'max_size_mb': max_size_mb,
                    'compressed': compress
                }
            )

            return {
                'status': 'success',
                'rotated_files': rotated_files,
                'compressed': compress
            }

        except Exception as e:
            raise CleanupError(f"Failed to rotate logs: {e}")

    async def _cleanup_old_deployments(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Clean up old deployment records."""
        retention_days = payload.get('retention_days', self.retention_policies['deployment_logs'])
        keep_failed = payload.get('keep_failed', True)

        try:
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

            async with get_db() as db:
                # Build query
                query = db.query(Deployment).filter(
                    Deployment.created_at < cutoff_date
                )

                if keep_failed:
                    # Keep failed deployments for analysis
                    query = query.filter(
                        Deployment.state.in_(['completed', 'cancelled'])
                    )

                # Get deployments to delete
                old_deployments = await query.all()

                # Archive deployment data
                if old_deployments:
                    await self._archive_records(old_deployments, 'deployments')

                # Delete old deployments
                deleted_count = await query.delete()
                await db.commit()

                await self.audit.log_event(
                    event_type="DEPLOYMENTS_CLEANED",
                    details={
                        'deleted_count': deleted_count,
                        'retention_days': retention_days,
                        'keep_failed': keep_failed
                    }
                )

                return {
                    'status': 'success',
                    'deleted_count': deleted_count,
                    'cutoff_date': cutoff_date.isoformat()
                }

        except Exception as e:
            raise CleanupError(f"Failed to cleanup deployments: {e}")

    async def _cleanup_health_checks(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Clean up old health check records."""
        retention_days = payload.get('retention_days', self.retention_policies['health_checks'])
        keep_latest_per_device = payload.get('keep_latest_per_device', 10)

        try:
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
            total_deleted = 0

            async with get_db() as db:
                # Get all devices
                devices = await db.query(Device).all()

                for device in devices:
                    # Keep latest N health checks per device
                    latest_checks = await db.query(HealthCheck).filter(
                        HealthCheck.device_id == device.id
                    ).order_by(HealthCheck.checked_at.desc()).limit(keep_latest_per_device).all()

                    latest_ids = [check.id for check in latest_checks]

                    # Delete old checks
                    deleted = await db.query(HealthCheck).filter(
                        HealthCheck.device_id == device.id,
                        HealthCheck.checked_at < cutoff_date,
                        ~HealthCheck.id.in_(latest_ids)
                    ).delete()

                    total_deleted += deleted

                await db.commit()

                await self.audit.log_event(
                    event_type="HEALTH_CHECKS_CLEANED",
                    details={
                        'deleted_count': total_deleted,
                        'retention_days': retention_days,
                        'keep_latest_per_device': keep_latest_per_device
                    }
                )

                return {
                    'status': 'success',
                    'deleted_count': total_deleted,
                    'devices_processed': len(devices)
                }

        except Exception as e:
            raise CleanupError(f"Failed to cleanup health checks: {e}")

    async def _cleanup_notifications(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Clean up old notification records."""
        retention_days = payload.get('retention_days', self.retention_policies['notifications'])

        try:
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

            async with get_db() as db:
                # Delete old notifications
                deleted_count = await db.query(Notification).filter(
                    Notification.created_at < cutoff_date
                ).delete()

                await db.commit()

                await self.audit.log_event(
                    event_type="NOTIFICATIONS_CLEANED",
                    details={
                        'deleted_count': deleted_count,
                        'retention_days': retention_days
                    }
                )

                return {
                    'status': 'success',
                    'deleted_count': deleted_count,
                    'cutoff_date': cutoff_date.isoformat()
                }

        except Exception as e:
            raise CleanupError(f"Failed to cleanup notifications: {e}")

    async def _cleanup_request_logs(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Clean up old request logs."""
        retention_days = payload.get('retention_days', self.retention_policies['request_logs'])
        keep_errors = payload.get('keep_errors', True)

        try:
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

            async with get_db() as db:
                # Build query
                query = db.query(RequestLog).filter(
                    RequestLog.created_at < cutoff_date
                )

                if keep_errors:
                    # Keep error requests for debugging
                    query = query.filter(
                        RequestLog.status_code < 400
                    )

                # Delete old logs
                deleted_count = await query.delete()
                await db.commit()

                await self.audit.log_event(
                    event_type="REQUEST_LOGS_CLEANED",
                    details={
                        'deleted_count': deleted_count,
                        'retention_days': retention_days,
                        'keep_errors': keep_errors
                    }
                )

                return {
                    'status': 'success',
                    'deleted_count': deleted_count,
                    'cutoff_date': cutoff_date.isoformat()
                }

        except Exception as e:
            raise CleanupError(f"Failed to cleanup request logs: {e}")

    async def _vacuum_database(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Vacuum database to reclaim space."""
        analyze = payload.get('analyze', True)
        full = payload.get('full', False)

        try:
            async with get_db() as db:
                # Get database size before
                size_before = await self._get_database_size(db)

                # Run VACUUM
                if full:
                    await db.execute("VACUUM FULL")
                else:
                    await db.execute("VACUUM")

                # Run ANALYZE if requested
                if analyze:
                    await db.execute("ANALYZE")

                # Get database size after
                size_after = await self._get_database_size(db)

                space_freed = size_before - size_after

                await self.audit.log_event(
                    event_type="DATABASE_VACUUMED",
                    details={
                        'full': full,
                        'analyze': analyze,
                        'size_before_mb': round(size_before / (1024 * 1024), 2),
                        'size_after_mb': round(size_after / (1024 * 1024), 2),
                        'space_freed_mb': round(space_freed / (1024 * 1024), 2)
                    }
                )

                return {
                    'status': 'success',
                    'size_before_bytes': size_before,
                    'size_after_bytes': size_after,
                    'space_freed_bytes': space_freed,
                    'space_freed_mb': round(space_freed / (1024 * 1024), 2)
                }

        except Exception as e:
            raise CleanupError(f"Failed to vacuum database: {e}")

    async def _cleanup_orphaned_files(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Clean up orphaned files not referenced in database."""
        try:
            orphaned_files = []
            total_size = 0

            async with get_db() as db:
                # Get all backup files from database
                backups = await db.query(ConfigBackup).all()
                valid_backup_files = {backup.file_path for backup in backups}

                # Check backup directory
                backup_path = Path(self.settings.BACKUP_STORAGE_PATH)
                if backup_path.exists():
                    for file_path in backup_path.rglob('*.bak'):
                        if str(file_path) not in valid_backup_files:
                            file_size = file_path.stat().st_size
                            file_path.unlink()
                            orphaned_files.append(str(file_path))
                            total_size += file_size

            await self.audit.log_event(
                event_type="ORPHANED_FILES_CLEANED",
                details={
                    'files_deleted': len(orphaned_files),
                    'size_freed_bytes': total_size,
                    'size_freed_mb': round(total_size / (1024 * 1024), 2)
                }
            )

            return {
                'status': 'success',
                'orphaned_files': orphaned_files,
                'files_deleted': len(orphaned_files),
                'size_freed_bytes': total_size,
                'size_freed_mb': round(total_size / (1024 * 1024), 2)
            }

        except Exception as e:
            raise CleanupError(f"Failed to cleanup orphaned files: {e}")

    async def _full_cleanup(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Perform full system cleanup."""
        try:
            results = {}

            # Run all cleanup tasks
            cleanup_tasks = [
                ('audit_logs', self._cleanup_audit_logs),
                ('sessions', self._cleanup_sessions),
                ('temp_files', self._cleanup_temp_files),
                ('deployments', self._cleanup_old_deployments),
                ('health_checks', self._cleanup_health_checks),
                ('notifications', self._cleanup_notifications),
                ('request_logs', self._cleanup_request_logs),
                ('orphaned_files', self._cleanup_orphaned_files)
            ]

            for task_name, task_func in cleanup_tasks:
                try:
                    result = await task_func(payload)
                    results[task_name] = result
                except Exception as e:
                    results[task_name] = {
                        'status': 'failed',
                        'error': str(e)
                    }

            # Rotate logs
            try:
                results['log_rotation'] = await self._rotate_logs(payload)
            except Exception as e:
                results['log_rotation'] = {
                    'status': 'failed',
                    'error': str(e)
                }

            # Vacuum database last
            try:
                results['database_vacuum'] = await self._vacuum_database(payload)
            except Exception as e:
                results['database_vacuum'] = {
                    'status': 'failed',
                    'error': str(e)
                }

            # Calculate totals
            total_deleted = sum(
                r.get('deleted_count', 0) for r in results.values()
                if isinstance(r, dict) and 'deleted_count' in r
            )

            total_space_freed = sum(
                r.get('size_freed_bytes', 0) for r in results.values()
                if isinstance(r, dict) and 'size_freed_bytes' in r
            )

            await self.audit.log_event(
                event_type="FULL_CLEANUP_COMPLETED",
                details={
                    'total_deleted': total_deleted,
                    'total_space_freed_bytes': total_space_freed,
                    'total_space_freed_mb': round(total_space_freed / (1024 * 1024), 2),
                    'tasks_completed': len([r for r in results.values() if r.get('status') == 'success'])
                }
            )

            return {
                'status': 'success',
                'results': results,
                'total_deleted': total_deleted,
                'total_space_freed_bytes': total_space_freed,
                'total_space_freed_gb': round(total_space_freed / (1024 * 1024 * 1024), 2)
            }

        except Exception as e:
            raise CleanupError(f"Full cleanup failed: {e}")

    async def _archive_records(self, records: List, archive_type: str):
        """Archive records before deletion."""
        archive_path = Path(self.settings.ARCHIVE_PATH) / archive_type
        archive_path.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        archive_file = archive_path / f"{archive_type}_{timestamp}.json"

        # Convert records to JSON
        import json
        archive_data = []
        for record in records:
            if hasattr(record, 'to_dict'):
                archive_data.append(record.to_dict())
            else:
                archive_data.append(str(record))

        # Write archive file
        with open(archive_file, 'w') as f:
            json.dump(archive_data, f, indent=2, default=str)

        # Compress archive
        import gzip
        with open(archive_file, 'rb') as f_in:
            with gzip.open(f"{archive_file}.gz", 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

        archive_file.unlink()

    async def _get_database_size(self, db) -> int:
        """Get current database size in bytes."""
        result = await db.execute(
            "SELECT pg_database_size(current_database())"
        )
        row = result.fetchone()
        return row[0] if row else 0


# Export main components
__all__ = ['CleanupWorker']