"""
Synchronization worker for GitOps and configuration sync.
Handles repository synchronization and configuration updates.
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from uuid import UUID
from pathlib import Path

from src.workers.base import BaseWorker, WorkerTask
from src.gitops.sync import RepositorySynchronizer, SyncStatus, SyncStrategy
from src.gitops.workflow import GitOpsWorkflow
from src.gitops.scanner import ConfigurationScanner, ScanLevel
from src.gitops.parser import ConfigurationParser, ConfigFormat
from src.core.exceptions import SyncError
from src.db.models import GitRepository, Device, Configuration
from src.security.audit import AuditLogger
from src.core.config import get_settings


class SyncWorker(BaseWorker):
    """
    Worker for processing synchronization tasks.
    Handles GitOps repository sync, configuration updates, and drift detection.
    """

    def __init__(self, **kwargs):
        """Initialize sync worker."""
        super().__init__(**kwargs)
        self.synchronizer = RepositorySynchronizer()
        self.gitops_workflow = GitOpsWorkflow()
        self.scanner = ConfigurationScanner(ScanLevel.STANDARD)
        self.parser = ConfigurationParser()
        self.audit = AuditLogger()
        self.settings = get_settings()

        # Track active sync operations
        self.active_syncs: Dict[UUID, Dict] = {}

    def get_worker_type(self) -> str:
        """Get worker type identifier."""
        return "sync"

    async def process_task(self, task: WorkerTask) -> Dict[str, Any]:
        """
        Process synchronization task.

        Args:
            task: Sync task

        Returns:
            Task result
        """
        task_type = task.task_type
        payload = task.payload

        if task_type == "sync_repository":
            return await self._sync_repository(payload)

        elif task_type == "sync_all_repositories":
            return await self._sync_all_repositories(payload)

        elif task_type == "sync_device_config":
            return await self._sync_device_config(payload)

        elif task_type == "detect_drift":
            return await self._detect_drift(payload)

        elif task_type == "reconcile_configurations":
            return await self._reconcile_configurations(payload)

        elif task_type == "scheduled_sync":
            return await self._scheduled_sync(payload)

        elif task_type == "emergency_sync":
            return await self._emergency_sync(payload)

        else:
            raise ValueError(f"Unknown task type: {task_type}")

    async def _sync_repository(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Synchronize a single Git repository."""
        repository_id = UUID(payload['repository_id'])
        strategy = SyncStrategy(payload.get('strategy', 'pull_only'))
        force = payload.get('force', False)

        try:
            async with get_db() as db:
                repository = await db.get(GitRepository, repository_id)
                if not repository:
                    raise SyncError(f"Repository {repository_id} not found")

                # Check if already syncing
                if repository_id in self.active_syncs:
                    return {
                        'status': 'already_syncing',
                        'repository_id': str(repository_id),
                        'message': 'Repository sync already in progress'
                    }

                # Mark as syncing
                self.active_syncs[repository_id] = {
                    'started_at': datetime.utcnow(),
                    'strategy': strategy.value
                }

                # Prepare repository configuration
                repo_config = {
                    'id': str(repository.id),
                    'url': repository.url,
                    'branch': repository.branch,
                    'credentials_vault_path': repository.credentials_vault_path,
                    'ssh_key': repository.ssh_key_vault_path,
                    'gpg_sign': repository.gpg_verification
                }

                # Perform synchronization
                sync_result = await self.synchronizer.sync_repository(
                    repo_config=repo_config,
                    strategy=strategy,
                    force=force
                )

                # Process synchronized configurations
                if sync_result['status'] == SyncStatus.SYNCED.value:
                    # Get repository path
                    repo_path = Path(self.settings.GITOPS_REPO_PATH) / str(repository_id)

                    # Scan for configurations
                    config_files = await self._find_config_files(repo_path, repository.config_path_pattern)

                    # Process each configuration
                    processed_configs = []
                    for config_file in config_files:
                        try:
                            # Read file content
                            with open(config_file, 'r') as f:
                                content = f.read()

                            # Scan for security issues
                            scan_result = await self.scanner.scan_configuration(
                                content=content,
                                filename=str(config_file),
                                vendor=repository.default_vendor
                            )

                            if scan_result['statistics']['critical'] > 0:
                                # Quarantine if critical issues found
                                await self._quarantine_configuration(
                                    repository_id=repository_id,
                                    file_path=config_file,
                                    scan_result=scan_result
                                )
                                continue

                            # Parse configuration
                            parsed = await self.parser.parse_configuration(
                                content=content,
                                format=self._detect_format(config_file)
                            )

                            # Store in database
                            config = await self._store_configuration(
                                repository_id=repository_id,
                                file_path=config_file,
                                parsed_config=parsed,
                                scan_result=scan_result,
                                db=db
                            )

                            processed_configs.append({
                                'file': str(config_file.relative_to(repo_path)),
                                'config_id': str(config.id),
                                'status': 'processed'
                            })

                        except Exception as e:
                            processed_configs.append({
                                'file': str(config_file.relative_to(repo_path)),
                                'status': 'failed',
                                'error': str(e)
                            })

                    # Update repository sync status
                    repository.last_sync_at = datetime.utcnow()
                    repository.sync_status = SyncStatus.SYNCED.value
                    repository.last_commit_hash = sync_result.get('commit')
                    await db.commit()

                    # Clean up tracking
                    del self.active_syncs[repository_id]

                    await self.audit.log_event(
                        event_type="REPOSITORY_SYNCED",
                        details={
                            'repository_id': str(repository_id),
                            'strategy': strategy.value,
                            'configs_processed': len(processed_configs),
                            'commit': sync_result.get('commit')
                        }
                    )

                    return {
                        'status': 'success',
                        'repository_id': str(repository_id),
                        'sync_result': sync_result,
                        'configurations': processed_configs
                    }

                else:
                    # Sync failed
                    repository.sync_status = SyncStatus.ERROR.value
                    await db.commit()

                    # Clean up tracking
                    del self.active_syncs[repository_id]

                    return {
                        'status': 'failed',
                        'repository_id': str(repository_id),
                        'error': sync_result.get('error', 'Unknown error')
                    }

        except Exception as e:
            # Clean up tracking
            if repository_id in self.active_syncs:
                del self.active_syncs[repository_id]

            raise SyncError(f"Repository sync failed: {e}")

    async def _sync_all_repositories(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Synchronize all active repositories."""
        strategy = SyncStrategy(payload.get('strategy', 'pull_only'))
        parallel = payload.get('parallel', True)
        max_parallel = payload.get('max_parallel', 5)

        try:
            async with get_db() as db:
                # Get all active repositories
                repositories = await db.query(GitRepository).filter(
                    GitRepository.is_active == True
                ).all()

                if parallel:
                    # Sync in parallel with limit
                    results = []
                    for i in range(0, len(repositories), max_parallel):
                        batch = repositories[i:i + max_parallel]

                        batch_tasks = [
                            self._sync_repository({
                                'repository_id': str(repo.id),
                                'strategy': strategy.value
                            })
                            for repo in batch
                        ]

                        batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)

                        for repo, result in zip(batch, batch_results):
                            if isinstance(result, Exception):
                                results.append({
                                    'repository_id': str(repo.id),
                                    'repository_name': repo.name,
                                    'status': 'failed',
                                    'error': str(result)
                                })
                            else:
                                results.append({
                                    'repository_id': str(repo.id),
                                    'repository_name': repo.name,
                                    'status': result['status']
                                })

                else:
                    # Sync sequentially
                    results = []
                    for repo in repositories:
                        try:
                            result = await self._sync_repository({
                                'repository_id': str(repo.id),
                                'strategy': strategy.value
                            })
                            results.append({
                                'repository_id': str(repo.id),
                                'repository_name': repo.name,
                                'status': result['status']
                            })
                        except Exception as e:
                            results.append({
                                'repository_id': str(repo.id),
                                'repository_name': repo.name,
                                'status': 'failed',
                                'error': str(e)
                            })

                # Calculate statistics
                successful = len([r for r in results if r['status'] == 'success'])
                failed = len([r for r in results if r['status'] == 'failed'])

                return {
                    'status': 'completed',
                    'total': len(repositories),
                    'successful': successful,
                    'failed': failed,
                    'results': results
                }

        except Exception as e:
            raise SyncError(f"Failed to sync all repositories: {e}")

    async def _sync_device_config(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Synchronize device configuration with Git repository."""
        device_id = UUID(payload['device_id'])
        repository_id = UUID(payload.get('repository_id'))
        commit_message = payload.get('commit_message', 'Device configuration sync')

        try:
            async with get_db() as db:
                # Get device
                device = await db.get(Device, device_id)
                if not device:
                    raise SyncError(f"Device {device_id} not found")

                # Get repository
                repository = await db.get(GitRepository, repository_id)
                if not repository:
                    raise SyncError(f"Repository {repository_id} not found")

                # Connect to device and get configuration
                from src.devices.connector import SecureDeviceConnector
                connector = SecureDeviceConnector()
                connection = await connector.connect_to_device(
                    device_id=str(device_id),
                    user_context={'system': True}
                )

                current_config = await connection.get_configuration()

                # Get repository path
                repo_path = Path(self.settings.GITOPS_REPO_PATH) / str(repository_id)

                # Determine file path for device config
                config_filename = f"{device.hostname}_{device.vendor}.cfg"
                config_path = repo_path / "devices" / config_filename

                # Ensure directory exists
                config_path.parent.mkdir(parents=True, exist_ok=True)

                # Write configuration to file
                with open(config_path, 'w') as f:
                    f.write(current_config)

                # Commit and push changes
                from git import Repo
                repo = Repo(repo_path)

                # Stage changes
                repo.index.add([str(config_path.relative_to(repo_path))])

                # Commit
                repo.index.commit(commit_message)

                # Push if configured
                if repository.auto_push:
                    origin = repo.remotes.origin
                    origin.push(repository.branch)

                # Store configuration in database
                config = Configuration(
                    device_id=device_id,
                    repository_id=repository_id,
                    file_path=str(config_path.relative_to(repo_path)),
                    content_hash=hashlib.sha256(current_config.encode()).hexdigest(),
                    version=device.config_version + 1,
                    created_at=datetime.utcnow(),
                    metadata={
                        'sync_type': 'device_to_git',
                        'commit': repo.head.commit.hexsha
                    }
                )

                db.add(config)
                device.config_version += 1
                device.last_sync_at = datetime.utcnow()
                await db.commit()

                await self.audit.log_event(
                    event_type="DEVICE_CONFIG_SYNCED",
                    details={
                        'device_id': str(device_id),
                        'repository_id': str(repository_id),
                        'config_file': config_filename,
                        'commit': repo.head.commit.hexsha
                    }
                )

                return {
                    'status': 'success',
                    'device_id': str(device_id),
                    'repository_id': str(repository_id),
                    'config_file': config_filename,
                    'commit': repo.head.commit.hexsha,
                    'pushed': repository.auto_push
                }

        except Exception as e:
            raise SyncError(f"Device config sync failed: {e}")

    async def _detect_drift(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Detect configuration drift between Git and devices."""
        check_all = payload.get('check_all', False)
        device_ids = payload.get('device_ids', [])

        try:
            drift_results = []

            async with get_db() as db:
                if check_all:
                    devices = await db.query(Device).filter(
                        Device.is_active == True
                    ).all()
                else:
                    devices = []
                    for device_id in device_ids:
                        device = await db.get(Device, UUID(device_id))
                        if device:
                            devices.append(device)

                # Check each device for drift
                from src.devices.connector import SecureDeviceConnector
                connector = SecureDeviceConnector()

                for device in devices:
                    try:
                        # Get current device configuration
                        connection = await connector.connect_to_device(
                            device_id=str(device.id),
                            user_context={'system': True}
                        )
                        current_config = await connection.get_configuration()
                        current_hash = hashlib.sha256(current_config.encode()).hexdigest()

                        # Get last known configuration
                        last_config = await db.query(Configuration).filter(
                            Configuration.device_id == device.id
                        ).order_by(Configuration.created_at.desc()).first()

                        if last_config:
                            has_drift = current_hash != last_config.content_hash

                            if has_drift:
                                # Calculate diff
                                import difflib
                                diff = list(difflib.unified_diff(
                                    last_config.content.split('\n'),
                                    current_config.split('\n'),
                                    lineterm=''
                                ))

                                drift_results.append({
                                    'device_id': str(device.id),
                                    'device_name': device.hostname,
                                    'has_drift': True,
                                    'last_sync': last_config.created_at.isoformat(),
                                    'diff_lines': len(diff),
                                    'current_hash': current_hash,
                                    'stored_hash': last_config.content_hash
                                })
                            else:
                                drift_results.append({
                                    'device_id': str(device.id),
                                    'device_name': device.hostname,
                                    'has_drift': False,
                                    'last_sync': last_config.created_at.isoformat()
                                })
                        else:
                            drift_results.append({
                                'device_id': str(device.id),
                                'device_name': device.hostname,
                                'has_drift': True,
                                'message': 'No stored configuration found'
                            })

                    except Exception as e:
                        drift_results.append({
                            'device_id': str(device.id),
                            'device_name': device.hostname,
                            'status': 'error',
                            'error': str(e)
                        })

                # Calculate statistics
                devices_with_drift = len([r for r in drift_results if r.get('has_drift')])
                devices_without_drift = len([r for r in drift_results if not r.get('has_drift')])
                devices_errored = len([r for r in drift_results if r.get('status') == 'error'])

                await self.audit.log_event(
                    event_type="DRIFT_DETECTION_COMPLETED",
                    details={
                        'total_devices': len(devices),
                        'with_drift': devices_with_drift,
                        'without_drift': devices_without_drift,
                        'errors': devices_errored
                    }
                )

                return {
                    'status': 'completed',
                    'total_devices': len(devices),
                    'with_drift': devices_with_drift,
                    'without_drift': devices_without_drift,
                    'errors': devices_errored,
                    'results': drift_results
                }

        except Exception as e:
            raise SyncError(f"Drift detection failed: {e}")

    async def _reconcile_configurations(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Reconcile configuration differences between sources."""
        source = payload.get('source', 'git')  # 'git' or 'device'
        device_ids = payload.get('device_ids', [])
        auto_apply = payload.get('auto_apply', False)

        try:
            reconciliation_results = []

            async with get_db() as db:
                for device_id in device_ids:
                    device = await db.get(Device, UUID(device_id))
                    if not device:
                        continue

                    # Get configurations from both sources
                    git_config = await self._get_git_configuration(device, db)
                    device_config = await self._get_device_configuration(device)

                    # Compare configurations
                    if git_config != device_config:
                        if source == 'git':
                            # Apply Git configuration to device
                            if auto_apply:
                                await self._apply_configuration_to_device(
                                    device,
                                    git_config
                                )
                                result = 'applied_to_device'
                            else:
                                result = 'pending_device_update'
                        else:
                            # Update Git with device configuration
                            if auto_apply:
                                await self._update_git_configuration(
                                    device,
                                    device_config,
                                    db
                                )
                                result = 'updated_in_git'
                            else:
                                result = 'pending_git_update'

                        reconciliation_results.append({
                            'device_id': str(device.id),
                            'device_name': device.hostname,
                            'result': result,
                            'source': source
                        })
                    else:
                        reconciliation_results.append({
                            'device_id': str(device.id),
                            'device_name': device.hostname,
                            'result': 'no_changes_needed'
                        })

            return {
                'status': 'completed',
                'source': source,
                'auto_apply': auto_apply,
                'results': reconciliation_results
            }

        except Exception as e:
            raise SyncError(f"Configuration reconciliation failed: {e}")

    async def _scheduled_sync(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Perform scheduled synchronization."""
        schedule_name = payload.get('schedule_name', 'hourly')
        sync_type = payload.get('sync_type', 'repositories')  # 'repositories' or 'devices'

        try:
            if sync_type == 'repositories':
                result = await self._sync_all_repositories({
                    'strategy': 'pull_only',
                    'parallel': True
                })
            else:
                # Sync all device configurations
                async with get_db() as db:
                    devices = await db.query(Device).filter(
                        Device.is_active == True,
                        Device.auto_sync == True
                    ).all()

                    results = []
                    for device in devices:
                        try:
                            sync_result = await self._sync_device_config({
                                'device_id': str(device.id),
                                'repository_id': str(device.repository_id),
                                'commit_message': f'Scheduled sync - {schedule_name}'
                            })
                            results.append(sync_result)
                        except Exception as e:
                            results.append({
                                'device_id': str(device.id),
                                'status': 'failed',
                                'error': str(e)
                            })

                    result = {
                        'status': 'completed',
                        'sync_type': sync_type,
                        'devices_synced': len(results),
                        'results': results
                    }

            await self.audit.log_event(
                event_type="SCHEDULED_SYNC_COMPLETED",
                details={
                    'schedule_name': schedule_name,
                    'sync_type': sync_type,
                    'result': result
                }
            )

            return result

        except Exception as e:
            raise SyncError(f"Scheduled sync failed: {e}")

    async def _emergency_sync(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Perform emergency synchronization with priority."""
        target_type = payload.get('target_type', 'all')  # 'all', 'critical_devices', 'repositories'
        reason = payload.get('reason', 'Emergency sync requested')

        try:
            results = {}

            if target_type in ['all', 'repositories']:
                # Force sync all repositories
                repo_result = await self._sync_all_repositories({
                    'strategy': 'bidirectional',
                    'parallel': True,
                    'force': True
                })
                results['repositories'] = repo_result

            if target_type in ['all', 'critical_devices']:
                # Sync critical devices
                async with get_db() as db:
                    critical_devices = await db.query(Device).filter(
                        Device.is_active == True,
                        Device.is_critical == True
                    ).all()

                    device_results = []
                    for device in critical_devices:
                        try:
                            # Create backup first
                            from src.workers.backup_worker import BackupWorker
                            backup_worker = BackupWorker()
                            backup_result = await backup_worker._create_backup({
                                'device_id': str(device.id),
                                'description': f'Emergency sync backup - {reason}'
                            })

                            # Sync configuration
                            sync_result = await self._sync_device_config({
                                'device_id': str(device.id),
                                'repository_id': str(device.repository_id),
                                'commit_message': f'Emergency sync - {reason}'
                            })

                            device_results.append({
                                'device_id': str(device.id),
                                'device_name': device.hostname,
                                'backup_id': backup_result['backup_id'],
                                'sync_status': sync_result['status']
                            })

                        except Exception as e:
                            device_results.append({
                                'device_id': str(device.id),
                                'device_name': device.hostname,
                                'status': 'failed',
                                'error': str(e)
                            })

                    results['critical_devices'] = {
                        'total': len(critical_devices),
                        'synced': len([r for r in device_results if r.get('sync_status') == 'success']),
                        'results': device_results
                    }

            await self.audit.log_event(
                event_type="EMERGENCY_SYNC_COMPLETED",
                level="critical",
                details={
                    'target_type': target_type,
                    'reason': reason,
                    'results': results
                }
            )

            return {
                'status': 'completed',
                'target_type': target_type,
                'reason': reason,
                'results': results,
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            raise SyncError(f"Emergency sync failed: {e}")

    async def _find_config_files(
        self,
        repo_path: Path,
        pattern: Optional[str] = None
    ) -> List[Path]:
        """Find configuration files in repository."""
        pattern = pattern or "**/*.{cfg,conf,yaml,yml,json}"
        config_files = []

        for pattern_part in pattern.split(','):
            config_files.extend(repo_path.glob(pattern_part.strip()))

        return config_files

    def _detect_format(self, file_path: Path) -> ConfigFormat:
        """Detect configuration format from file extension."""
        extension = file_path.suffix.lower()

        format_map = {
            '.cfg': ConfigFormat.NATIVE,
            '.conf': ConfigFormat.NATIVE,
            '.yaml': ConfigFormat.YAML,
            '.yml': ConfigFormat.YAML,
            '.json': ConfigFormat.JSON,
            '.xml': ConfigFormat.XML
        }

        return format_map.get(extension, ConfigFormat.NATIVE)

    async def _quarantine_configuration(
        self,
        repository_id: UUID,
        file_path: Path,
        scan_result: Dict
    ):
        """Quarantine configuration with security issues."""
        quarantine_path = Path(self.settings.QUARANTINE_PATH) / str(repository_id)
        quarantine_path.mkdir(parents=True, exist_ok=True)

        # Move file to quarantine
        quarantine_file = quarantine_path / file_path.name
        shutil.move(str(file_path), str(quarantine_file))

        # Write scan results
        scan_file = quarantine_file.with_suffix('.scan.json')
        import json
        with open(scan_file, 'w') as f:
            json.dump(scan_result, f, indent=2)

        await self.audit.log_event(
            event_type="CONFIGURATION_QUARANTINED",
            level="warning",
            details={
                'repository_id': str(repository_id),
                'file': str(file_path),
                'critical_issues': scan_result['statistics']['critical'],
                'high_issues': scan_result['statistics']['high']
            }
        )

    async def _store_configuration(
        self,
        repository_id: UUID,
        file_path: Path,
        parsed_config: Dict,
        scan_result: Dict,
        db
    ) -> Configuration:
        """Store configuration in database."""
        import hashlib

        with open(file_path, 'r') as f:
            content = f.read()

        config = Configuration(
            repository_id=repository_id,
            file_path=str(file_path),
            content=content,
            content_hash=hashlib.sha256(content.encode()).hexdigest(),
            format=parsed_config['metadata']['format'],
            vendor=parsed_config.get('vendor'),
            platform=parsed_config.get('platform'),
            scan_result=scan_result,
            parsed_data=parsed_config,
            created_at=datetime.utcnow(),
            is_active=scan_result['statistics']['critical'] == 0
        )

        db.add(config)
        await db.commit()
        await db.refresh(config)

        return config

    async def _get_git_configuration(self, device: Device, db) -> Optional[str]:
        """Get device configuration from Git."""
        config = await db.query(Configuration).filter(
            Configuration.device_id == device.id,
            Configuration.is_active == True
        ).order_by(Configuration.created_at.desc()).first()

        return config.content if config else None

    async def _get_device_configuration(self, device: Device) -> str:
        """Get current configuration from device."""
        from src.devices.connector import SecureDeviceConnector
        connector = SecureDeviceConnector()

        connection = await connector.connect_to_device(
            device_id=str(device.id),
            user_context={'system': True}
        )

        return await connection.get_configuration()

    async def _apply_configuration_to_device(
        self,
        device: Device,
        configuration: str
    ):
        """Apply configuration to device."""
        from src.devices.connector import SecureDeviceConnector
        connector = SecureDeviceConnector()

        connection = await connector.connect_to_device(
            device_id=str(device.id),
            user_context={'system': True}
        )

        await connection.apply_configuration(configuration)

    async def _update_git_configuration(
        self,
        device: Device,
        configuration: str,
        db
    ):
        """Update Git repository with device configuration."""
        # Get repository for device
        repository = await db.get(GitRepository, device.repository_id)
        if not repository:
            raise SyncError(f"No repository configured for device {device.id}")

        repo_path = Path(self.settings.GITOPS_REPO_PATH) / str(repository.id)
        config_file = repo_path / "devices" / f"{device.hostname}.cfg"

        # Write configuration
        config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(config_file, 'w') as f:
            f.write(configuration)

        # Commit changes
        from git import Repo
        repo = Repo(repo_path)
        repo.index.add([str(config_file.relative_to(repo_path))])
        repo.index.commit(f"Update configuration for {device.hostname}")

        if repository.auto_push:
            repo.remotes.origin.push(repository.branch)


# Export main components
__all__ = ['SyncWorker']