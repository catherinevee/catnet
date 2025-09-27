from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import asyncio
from uuid import UUID
from fastapi import FastAPI, HTTPException, status, Depends, Header, Request
from sqlalchemy.ext.asyncio import AsyncSession
from .models import GitRepository, GitProvider, WebhookPayload, SyncOperation, ConfigFile
from .git_client import SecureGitClient
from .webhook_handler import WebhookHandler
from ..auth.auth_service import get_current_user
from ..auth.models import User
from ..auth.permissions import Permission, require_permissions
from ..core.config_parser import ConfigParser
from ..core.validation import ConfigValidator
from ..security.scanner import SecurityScanner
from ..security.vault import VaultClient
from ..db.database import get_db
import structlog


logger = structlog.get_logger()


class GitOpsService:
    def __init__(self, port: int = 8082):
        self.app = FastAPI(
            title="CatNet GitOps Service",
            description="Git repository management and webhook processing",
            version="1.0.0"
        )

        self.vault_client = VaultClient()
        self.git_client = SecureGitClient(self.vault_client)
        self.config_parser = ConfigParser()
        self.config_validator = ConfigValidator()
        self.security_scanner = SecurityScanner()
        self.webhook_handler = WebhookHandler(
            self.git_client,
            self.config_parser,
            self.config_validator,
            self.security_scanner
        )

        self.repositories: Dict[UUID, GitRepository] = {}
        self.sync_scheduler = {}

        self._setup_routes()
        self._setup_background_tasks()

    def _setup_routes(self):
        @self.app.post("/git/connect")
        @require_permissions([Permission.GIT_REPO_CREATE])
        async def connect_repository(
            repository: GitRepository,
            current_user: User = Depends(get_current_user),
            db: AsyncSession = Depends(get_db)
        ):
            try:
                # Validate repository URL
                if not await self._validate_repository_url(repository.url):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid repository URL"
                    )

                # Store credentials in Vault
                if repository.webhook_secret:
                    secret_path = f"git/webhook/{repository.id}"
                    await self.vault_client.store_secret(
                        secret_path,
                        {"secret": repository.webhook_secret}
                    )
                    repository.webhook_secret = secret_path

                # Clone repository to verify access
                repo_path = None
                try:
                    repo_path = await self.git_client.clone_repository(
                        repository,
                        depth=1
                    )

                    # Scan for secrets immediately
                    secrets = await self.git_client.scan_for_secrets(repo_path)
                    if secrets:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Repository contains {len(secrets)} secrets. Please remove them before connecting."
                        )

                    repository.status = "active"
                    repository.last_sync = datetime.utcnow()

                finally:
                    if repo_path:
                        self.git_client.cleanup_temp_dir(repo_path)

                # Store repository
                self.repositories[repository.id] = repository

                # Schedule periodic sync if enabled
                if repository.auto_sync:
                    await self._schedule_repository_sync(repository)

                # Log the action
                await self._audit_log(
                    db,
                    current_user.id,
                    "git.repository.connect",
                    repository.id,
                    {"name": repository.name, "url": str(repository.url)}
                )

                return {
                    "id": repository.id,
                    "name": repository.name,
                    "status": repository.status,
                    "webhook_url": f"/git/webhook/{repository.id}"
                }

            except Exception as e:
                logger.error(f"Failed to connect repository: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to connect repository: {str(e)}"
                )

        @self.app.post("/git/webhook/{repository_id}")
        async def process_webhook(
            repository_id: UUID,
            request: Request,
            x_github_event: Optional[str] = Header(None),
            x_gitlab_event: Optional[str] = Header(None),
            x_event_key: Optional[str] = Header(None)
        ):
            try:
                # Get repository
                if repository_id not in self.repositories:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Repository not found"
                    )

                repository = self.repositories[repository_id]

                # Determine provider
                provider = self._determine_provider(
                    x_github_event,
                    x_gitlab_event,
                    x_event_key
                )

                # Get headers and body
                headers = dict(request.headers)
                body = await request.body()

                # Process webhook
                webhook_payload = await self.webhook_handler.process_webhook(
                    provider,
                    headers,
                    body,
                    repository
                )

                return {
                    "id": webhook_payload.id,
                    "status": "processing",
                    "event_type": webhook_payload.event_type.value
                }

            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Webhook processing failed: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Webhook processing failed"
                )

        @self.app.get("/git/configs")
        @require_permissions([Permission.GIT_REPO_READ])
        async def list_configurations(
            repository_id: Optional[UUID] = None,
            current_user: User = Depends(get_current_user),
            db: AsyncSession = Depends(get_db)
        ):
            try:
                configs = []

                if repository_id:
                    if repository_id not in self.repositories:
                        raise HTTPException(
                            status_code=status.HTTP_404_NOT_FOUND,
                            detail="Repository not found"
                        )

                    repository = self.repositories[repository_id]
                    repo_path = None

                    try:
                        repo_path = await self.git_client.clone_repository(repository)
                        config_files = await self.git_client.get_config_files(repo_path)

                        for config in config_files:
                            configs.append({
                                "id": config.id,
                                "path": config.file_path,
                                "vendor": config.vendor,
                                "device_type": config.device_type,
                                "validated": config.validated,
                                "commit": config.commit_hash[:7],
                                "author": config.commit_author,
                                "committed_at": config.committed_at.isoformat()
                            })

                    finally:
                        if repo_path:
                            self.git_client.cleanup_temp_dir(repo_path)

                else:
                    # List configs from all repositories
                    for repo_id, repository in self.repositories.items():
                        repo_path = None
                        try:
                            repo_path = await self.git_client.clone_repository(repository)
                            config_files = await self.git_client.get_config_files(repo_path)

                            for config in config_files:
                                configs.append({
                                    "repository_id": repo_id,
                                    "repository_name": repository.name,
                                    "id": config.id,
                                    "path": config.file_path,
                                    "vendor": config.vendor,
                                    "device_type": config.device_type,
                                    "validated": config.validated
                                })

                        finally:
                            if repo_path:
                                self.git_client.cleanup_temp_dir(repo_path)

                return {"configs": configs, "total": len(configs)}

            except Exception as e:
                logger.error(f"Failed to list configurations: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to list configurations"
                )

        @self.app.post("/git/sync/{repository_id}")
        @require_permissions([Permission.GIT_REPO_SYNC])
        async def sync_repository(
            repository_id: UUID,
            force: bool = False,
            current_user: User = Depends(get_current_user),
            db: AsyncSession = Depends(get_db)
        ):
            try:
                if repository_id not in self.repositories:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Repository not found"
                    )

                repository = self.repositories[repository_id]

                # Check if already syncing
                if repository.status == "syncing":
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="Repository is already syncing"
                    )

                # Start sync operation
                sync_op = SyncOperation(
                    repository_id=repository_id,
                    trigger="manual",
                    triggered_by=current_user.id
                )

                # Run sync in background
                asyncio.create_task(
                    self._sync_repository(repository, sync_op, force)
                )

                # Log the action
                await self._audit_log(
                    db,
                    current_user.id,
                    "git.repository.sync",
                    repository_id,
                    {"force": force}
                )

                return {
                    "sync_id": sync_op.id,
                    "status": sync_op.status.value,
                    "message": "Sync started successfully"
                }

            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Failed to sync repository: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to sync repository"
                )

        @self.app.get("/git/repositories")
        @require_permissions([Permission.GIT_REPO_READ])
        async def list_repositories(
            current_user: User = Depends(get_current_user)
        ):
            repos = []
            for repo_id, repository in self.repositories.items():
                repos.append({
                    "id": repo_id,
                    "name": repository.name,
                    "url": str(repository.url),
                    "branch": repository.branch,
                    "provider": repository.provider.value,
                    "status": repository.status.value,
                    "last_sync": repository.last_sync.isoformat() if repository.last_sync else None,
                    "auto_sync": repository.auto_sync,
                    "gpg_verification": repository.gpg_verification_enabled
                })

            return {"repositories": repos, "total": len(repos)}

        @self.app.delete("/git/repositories/{repository_id}")
        @require_permissions([Permission.GIT_REPO_DELETE])
        async def delete_repository(
            repository_id: UUID,
            current_user: User = Depends(get_current_user),
            db: AsyncSession = Depends(get_db)
        ):
            try:
                if repository_id not in self.repositories:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Repository not found"
                    )

                repository = self.repositories[repository_id]

                # Cancel sync schedule
                if repository_id in self.sync_scheduler:
                    self.sync_scheduler[repository_id].cancel()
                    del self.sync_scheduler[repository_id]

                # Delete from Vault
                if repository.webhook_secret:
                    await self.vault_client.delete_secret(repository.webhook_secret)

                # Remove repository
                del self.repositories[repository_id]

                # Log the action
                await self._audit_log(
                    db,
                    current_user.id,
                    "git.repository.delete",
                    repository_id,
                    {"name": repository.name}
                )

                return {"message": "Repository deleted successfully"}

            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Failed to delete repository: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to delete repository"
                )

        @self.app.put("/git/repositories/{repository_id}")
        @require_permissions([Permission.GIT_REPO_UPDATE])
        async def update_repository(
            repository_id: UUID,
            updates: Dict[str, Any],
            current_user: User = Depends(get_current_user),
            db: AsyncSession = Depends(get_db)
        ):
            try:
                if repository_id not in self.repositories:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Repository not found"
                    )

                repository = self.repositories[repository_id]

                # Update allowed fields
                allowed_fields = [
                    'branch', 'auto_sync', 'sync_interval_minutes',
                    'gpg_verification_enabled', 'allowed_signers',
                    'path_filters', 'ignore_patterns'
                ]

                for field in allowed_fields:
                    if field in updates:
                        setattr(repository, field, updates[field])

                repository.updated_at = datetime.utcnow()

                # Update sync schedule if needed
                if 'auto_sync' in updates or 'sync_interval_minutes' in updates:
                    if repository.auto_sync:
                        await self._schedule_repository_sync(repository)
                    elif repository_id in self.sync_scheduler:
                        self.sync_scheduler[repository_id].cancel()
                        del self.sync_scheduler[repository_id]

                # Log the action
                await self._audit_log(
                    db,
                    current_user.id,
                    "git.repository.update",
                    repository_id,
                    updates
                )

                return {"message": "Repository updated successfully"}

            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Failed to update repository: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to update repository"
                )

    def _setup_background_tasks(self):
        @self.app.on_event("startup")
        async def startup_tasks():
            # Start periodic cleanup
            asyncio.create_task(self._cleanup_task())

            # Start webhook processor
            asyncio.create_task(self._process_webhook_queue())

    async def _validate_repository_url(self, url: str) -> bool:
        # Validate URL format and accessibility
        allowed_domains = [
            'github.com',
            'gitlab.com',
            'bitbucket.org',
            'dev.azure.com'
        ]

        from urllib.parse import urlparse
        parsed = urlparse(str(url))

        # Check if domain is allowed
        if not any(domain in parsed.netloc for domain in allowed_domains):
            # Check if it's an internal git server
            if not parsed.netloc.startswith('git.'):
                return False

        return True

    def _determine_provider(
        self,
        github_event: Optional[str],
        gitlab_event: Optional[str],
        bitbucket_event: Optional[str]
    ) -> GitProvider:
        if github_event:
            return GitProvider.GITHUB
        elif gitlab_event:
            return GitProvider.GITLAB
        elif bitbucket_event:
            return GitProvider.BITBUCKET
        else:
            return GitProvider.GENERIC

    async def _sync_repository(
        self,
        repository: GitRepository,
        sync_op: SyncOperation,
        force: bool = False
    ):
        repo_path = None
        try:
            repository.status = "syncing"
            sync_op.start()

            # Clone or pull repository
            repo_path = await self.git_client.clone_repository(repository)

            if repository.last_commit_hash:
                commits = await self.git_client.pull_latest(
                    repo_path,
                    repository,
                    force
                )
                sync_op.commits_processed = len(commits)

            # Scan for secrets
            secrets = await self.git_client.scan_for_secrets(repo_path)
            if secrets:
                sync_op.add_error(f"Found {len(secrets)} secrets")
                repository.status = "error"
                return

            # Extract configurations
            config_files = await self.git_client.get_config_files(
                repo_path,
                repository.path_filters
            )
            sync_op.files_processed = len(config_files)

            # Validate configurations
            for config in config_files:
                validation = await self.config_validator.validate(config)
                if not validation.is_valid:
                    sync_op.warnings.extend(validation.errors)
                    config.validated = False
                else:
                    config.validated = True
                    sync_op.configs_extracted += 1

            # Update repository status
            repository.status = "active"
            repository.last_sync = datetime.utcnow()

            # Get latest commit
            import git
            repo = git.Repo(repo_path)
            repository.last_commit_hash = repo.head.commit.hexsha

            sync_op.complete(success=True)

        except Exception as e:
            logger.error(f"Repository sync failed: {str(e)}")
            repository.status = "error"
            sync_op.add_error(str(e))
            sync_op.complete(success=False)

        finally:
            if repo_path:
                self.git_client.cleanup_temp_dir(repo_path)

    async def _schedule_repository_sync(self, repository: GitRepository):
        # Cancel existing schedule
        if repository.id in self.sync_scheduler:
            self.sync_scheduler[repository.id].cancel()

        async def periodic_sync():
            while repository.auto_sync:
                await asyncio.sleep(repository.sync_interval_minutes * 60)

                if repository.id not in self.repositories:
                    break

                sync_op = SyncOperation(
                    repository_id=repository.id,
                    trigger="scheduled"
                )

                await self._sync_repository(repository, sync_op)

        task = asyncio.create_task(periodic_sync())
        self.sync_scheduler[repository.id] = task

    async def _process_webhook_queue(self):
        while True:
            try:
                if self.webhook_handler.processing_queue.qsize() > 0:
                    # Process queued webhooks
                    await asyncio.sleep(0.1)
                else:
                    await asyncio.sleep(1)
            except Exception as e:
                logger.error(f"Webhook queue processing error: {str(e)}")

    async def _cleanup_task(self):
        while True:
            try:
                # Cleanup every hour
                await asyncio.sleep(3600)

                # Cleanup temp directories
                self.git_client.cleanup_all_temp_dirs()

                # Cleanup completed webhook tasks
                completed_tasks = []
                for task_id, task in self.webhook_handler.processing_tasks.items():
                    if task.done():
                        completed_tasks.append(task_id)

                for task_id in completed_tasks:
                    del self.webhook_handler.processing_tasks[task_id]

            except Exception as e:
                logger.error(f"Cleanup task error: {str(e)}")

    async def _audit_log(
        self,
        db: AsyncSession,
        user_id: UUID,
        action: str,
        resource_id: UUID,
        details: Dict[str, Any]
    ):
        # Implementation would log to database
        logger.info(
            f"Audit: {action}",
            user_id=str(user_id),
            resource_id=str(resource_id),
            details=details
        )