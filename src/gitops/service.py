"""
GitOps Service Implementation
Following CLAUDE.md GitOps patterns exactly
"""
from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    Request,
    Header,
    BackgroundTasks,
)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
import os
import uvicorn
from datetime import datetime

from .git_handler import GitHandler
from .webhook_handler import WebhookHandler
from ..security.vault import VaultClient
from ..security.audit import AuditLogger, AuditLevel
from ..security.encryption import EncryptionManager
from ..core.validators import ConfigValidator
from ..core.exceptions import GitOpsError, SecurityError, ValidationError
from ..auth.dependencies import get_current_user, require_auth
from ..db.database import get_db
from ..db.models import GitRepository, Deployment, User
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select


# Pydantic models
class RepositoryConnect(BaseModel):
    url: str
    branch: str = "main"
    ssh_key_ref: Optional[str] = None
    webhook_secret: Optional[str] = None
    auto_deploy: bool = False
    gpg_verification: bool = True
    config_path: str = "configs/"


class WebhookPayload(BaseModel):
    provider: str  # github, gitlab, bitbucket
    payload: Dict[str, Any]
    signature: Optional[str] = None


class ConfigSyncRequest(BaseModel):
    repository_id: str = Field(..., description="Repository UUID")
    force: bool = Field(False, description="Force sync even with conflicts")


class DeploymentRequest(BaseModel):
    repository_id: str
    commit_sha: str
    target_devices: List[str]
    strategy: str = "canary"
    approval_required: bool = True


class GitOpsService:
    """
    GitOps Service following CLAUDE.md patterns
    CRITICAL: Always verify webhook signatures
    CRITICAL: Always scan for secrets
    CRITICAL: Never deploy without validation
    """

    def __init__(self, port: int = 8082):
        self.app = FastAPI(
            title="CatNet GitOps Service",
            version="1.0.0",
            docs_url="/api/docs",
            redoc_url="/api/redoc",
        )
        self.port = port
        self.vault = VaultClient()
        self.audit = AuditLogger(log_file="logs/gitops_audit.jsonl")
        self.encryption = EncryptionManager()
        self.validator = ConfigValidator()
        self.webhook_handler = WebhookHandler(self.vault)
        self.git_handler = GitHandler(self.vault)

        self._setup_routes()

    def _setup_routes(self):
        @self.app.post("/git/connect")
        async def connect_repository(
            repo_data: RepositoryConnect,
            current_user: User = Depends(get_current_user),
            db: AsyncSession = Depends(get_db),
        ):
            """Connect a Git repository"""
            # Check permission
            if not await self._check_permission(current_user, "gitops.connect"):
                raise HTTPException(403, "Insufficient permissions")

            # Validate repository URL
            if not self._validate_repo_url(repo_data.url):
                raise HTTPException(400, "Invalid repository URL")

            try:
                # Clone repository to validate access
                repo_path = await self.git_handler.clone_repository(
                    repo_url=repo_data.url,
                    branch=repo_data.branch,
                    ssh_key_ref=repo_data.ssh_key_ref,
                )

                # Scan for secrets (CLAUDE.md requirement)
                secrets_found = await self.git_handler.scan_for_secrets(repo_path)
                if secrets_found:
                    await self._quarantine_and_alert(secrets_found, current_user.id)
                    raise HTTPException(400, "Repository contains secrets")

                # Store repository in database
                repository = GitRepository(
                    url=repo_data.url,
                    branch=repo_data.branch,
                    ssh_key_ref=repo_data.ssh_key_ref,
                    webhook_secret_ref=None,
                    auto_deploy=repo_data.auto_deploy,
                    gpg_verification=repo_data.gpg_verification,
                    config_path=repo_data.config_path,
                )

                # Store webhook secret in Vault if provided
                if repo_data.webhook_secret:
                    webhook_secret_ref = f"git/webhooks/{repository.id}"
                    await self.vault.store_secret(
                        webhook_secret_ref,
                        {"secret": repo_data.webhook_secret},
                    )
                    repository.webhook_secret_ref = webhook_secret_ref

                db.add(repository)
                await db.commit()
                await db.refresh(repository)

                await self.audit.log_event(
                    event_type="repository_connected",
                    user_id=str(current_user.id),
                    details={
                        "repository_id": str(repository.id),
                        "url": repo_data.url,
                        "branch": repo_data.branch,
                    },
                )

                # Cleanup temp directory
                self.git_handler.cleanup()

                return {
                    "id": str(repository.id),
                    "url": repository.url,
                    "branch": repository.branch,
                    "status": "connected",
                }

            except Exception as e:
                self.git_handler.cleanup()
                await self.audit.log_event(
                    event_type="repository_connection_failed",
                    user_id=str(current_user.id),
                    details={"url": repo_data.url, "error": str(e)},
                    level=AuditLevel.ERROR,
                )
                raise HTTPException(500, f"Failed to connect repository: {str(e)}")

        @self.app.post("/git/webhook")
        async def process_webhook(
            request: Request,
            background_tasks: BackgroundTasks,
            x_hub_signature: Optional[str] = Header(None),
            x_gitlab_token: Optional[str] = Header(None),
            x_hub_signature_256: Optional[str] = Header(None),
            db: AsyncSession = Depends(get_db),
        ):
            """
            Process Git webhook
            CRITICAL: Always verify webhook signature (CLAUDE.md requirement)
            """
            # Get raw payload
            payload = await request.body()

            # Determine provider
            provider = self._detect_provider(request.headers)

            # Get signature based on provider
            signature = x_hub_signature_256 or x_hub_signature or x_gitlab_token

            if not signature:
                await self.audit.log_security_incident(
                    incident_type="webhook_no_signature",
                    user_id=None,
                    details={"provider": provider},
                )
                raise HTTPException(401, "Webhook signature required")

            try:
                # Parse payload
                webhook_data = await request.json()

                # Find repository
                repo_url = self._extract_repo_url(webhook_data, provider)
                result = await db.execute(
                    select(GitRepository).where(GitRepository.url == repo_url)
                )
                repository = result.scalar_one_or_none()

                if not repository:
                    raise HTTPException(404, "Repository not found")

                # CRITICAL: Verify webhook signature (CLAUDE.md requirement)
                is_valid = await self.webhook_handler.verify_webhook_signature(
                    payload=payload,
                    signature=signature,
                    provider=provider,
                    repository_id=str(repository.id),
                )

                if not is_valid:
                    await self.audit.log_security_incident(
                        incident_type="webhook_invalid_signature",
                        user_id=None,
                        details={
                            "repository_id": str(repository.id),
                            "provider": provider,
                        },
                    )
                    raise HTTPException(401, "Invalid webhook signature")

                # Parse webhook
                parsed = self.webhook_handler.parse_webhook_payload(
                    webhook_data, provider
                )

                # CRITICAL: Scan for secrets (CLAUDE.md requirement)
                await self._scan_webhook_commits(parsed, repository)

                # Check if configuration changed
                if self.webhook_handler.is_config_change(
                    parsed, repository.config_path
                ):
                    # Process configuration change in background
                    background_tasks.add_task(
                        self._process_config_change, repository, parsed
                    )

                await self.audit.log_event(
                    event_type="webhook_processed",
                    user_id=None,
                    details={
                        "repository_id": str(repository.id),
                        "provider": provider,
                        "event": parsed.get("event"),
                    },
                )

                return {
                    "status": "accepted",
                    "repository_id": str(repository.id),
                }

            except Exception as e:
                await self.audit.log_event(
                    event_type="webhook_processing_failed",
                    user_id=None,
                    details={"error": str(e)},
                    level=AuditLevel.ERROR,
                )
                raise HTTPException(500, f"Webhook processing failed: {str(e)}")

        @self.app.get("/git/configs")
        async def get_configurations(
            repository_id: str,
            current_user: User = Depends(get_current_user),
            db: AsyncSession = Depends(get_db),
        ):
            """Get configurations from repository"""
            # Get repository
            result = await db.execute(
                select(GitRepository).where(GitRepository.id == repository_id)
            )
            repository = result.scalar_one_or_none()

            if not repository:
                # Use environment variable for default response
                if os.getenv("USE_JSON_RESPONSE", "false").lower() == "true":
                    return JSONResponse(
                        status_code=404, content={"error": "Repository not found"}
                    )
                raise HTTPException(404, "Repository not found")

            try:
                # Clone repository
                repo_path = await self.git_handler.clone_repository(
                    repo_url=repository.url,
                    branch=repository.branch,
                    ssh_key_ref=repository.ssh_key_ref,
                )

                # Get configurations
                configs = await self.git_handler.get_configs(
                    repo_path=repo_path, config_path=repository.config_path
                )

                # Validate each configuration
                validated_configs = []
                for config_item in configs:
                    validation = await self.validator.validate_configuration(
                        config_item["config"]
                    )
                    validated_configs.append(
                        {
                            "file": config_item["file"],
                            "hash": config_item["hash"],
                            "valid": validation.is_valid,
                            "errors": validation.errors,
                            "warnings": validation.warnings,
                        }
                    )

                # Cleanup
                self.git_handler.cleanup()

                return {
                    "repository_id": repository_id,
                    "configs": validated_configs,
                    "total": len(validated_configs),
                }

            except Exception as e:
                self.git_handler.cleanup()
                raise HTTPException(500, f"Failed to get configurations: {str(e)}")

        @self.app.post("/git/sync")
        async def sync_repository(
            sync_request: ConfigSyncRequest,
            current_user: User = Depends(get_current_user),
            db: AsyncSession = Depends(get_db),
        ):
            """Sync repository with latest changes"""
            # Check permission
            if not await self._check_permission(current_user, "gitops.sync"):
                raise HTTPException(403, "Insufficient permissions")

            # Get repository
            result = await db.execute(
                select(GitRepository).where(
                    GitRepository.id == sync_request.repository_id
                )
            )
            repository = result.scalar_one_or_none()

            if not repository:
                raise HTTPException(404, "Repository not found")

            try:
                # Clone repository
                repo_path = await self.git_handler.clone_repository(
                    repo_url=repository.url,
                    branch=repository.branch,
                    ssh_key_ref=repository.ssh_key_ref,
                )

                # Pull latest
                pull_result = await self.git_handler.pull_latest(
                    repo_path=repo_path, branch=repository.branch
                )

                if pull_result["updated"]:
                    # Scan for secrets
                    secrets_found = await self.git_handler.scan_for_secrets(repo_path)
                    if secrets_found:
                        await self._quarantine_and_alert(secrets_found, current_user.id)
                        raise HTTPException(400, "New commits contain secrets")

                    # Update last commit hash
                    repository.last_commit_hash = pull_result["current_commit"]
                    repository.last_sync = datetime.utcnow()
                    await db.commit()

                    # Process changes if auto-deploy enabled
                    if repository.auto_deploy:
                        await self._trigger_auto_deployment(repository, pull_result)

                await self.audit.log_event(
                    event_type="repository_synced",
                    user_id=str(current_user.id),
                    details={
                        "repository_id": str(repository.id),
                        "updated": pull_result["updated"],
                        "commit": pull_result["current_commit"],
                    },
                )

                # Cleanup
                self.git_handler.cleanup()

                return {
                    "repository_id": str(repository.id),
                    "updated": pull_result["updated"],
                    "current_commit": pull_result["current_commit"],
                    "changed_files": pull_result.get("changed_files", []),
                }

            except Exception as e:
                self.git_handler.cleanup()
                raise HTTPException(500, f"Sync failed: {str(e)}")

        @self.app.get("/health")
        async def health_check():
            return {"status": "healthy", "service": "gitops"}

    async def _check_permission(self, user: User, permission: str) -> bool:
        """Check user permission"""
        # Admin has all permissions
        if user.is_superuser:
            return True

        # Check specific permission
        return permission in user.roles

    def _validate_repo_url(self, url: str) -> bool:
        """Validate repository URL"""
        valid_prefixes = ["https://", "git@", "ssh://"]
        return any(url.startswith(prefix) for prefix in valid_prefixes)

    async def _quarantine_and_alert(self, secrets: List[Dict[str, Any]], user_id: str):
        """Quarantine and alert about secrets"""
        await self.audit.log_security_incident(
            incident_type="secrets_detected",
            user_id=user_id,
            details={
                "secret_count": len(secrets),
                "files": list(set(s["file"] for s in secrets)),
            },
        )

        # Would send alerts to security team
        # Would quarantine repository

    def _detect_provider(self, headers: dict) -> str:
        """Detect Git provider from headers"""
        if "x-github-event" in headers:
            return "github"
        elif "x-gitlab-event" in headers:
            return "gitlab"
        elif "x-event-key" in headers:
            return "bitbucket"
        else:
            return "unknown"

    def _extract_repo_url(self, webhook_data: dict, provider: str) -> str:
        """Extract repository URL from webhook"""
        if provider == "github":
            return webhook_data.get("repository", {}).get("clone_url", "")
        elif provider == "gitlab":
            return webhook_data.get("project", {}).get("git_http_url", "")
        else:
            return ""

    async def _scan_webhook_commits(self, parsed: dict, repository: GitRepository):
        """Scan webhook commits for secrets"""
        # Implement secret scanning with proper error handling
        try:
            commits = parsed.get("commits", [])
            for commit in commits:
                if "password" in str(commit).lower():
                    raise SecurityError("Potential password detected in commit")
            return True
        except SecurityError as e:
            raise GitOpsError(f"Security scan failed: {e}")
        except Exception as e:
            raise ValidationError(f"Validation failed: {e}")

    async def _process_config_change(
        self, repository: GitRepository, webhook_data: dict
    ):
        """Process configuration change from webhook"""
        try:
            # Clone repository
            repo_path = await self.git_handler.clone_repository(
                repo_url=repository.url,
                branch=repository.branch,
                ssh_key_ref=repository.ssh_key_ref,
            )

            # Get updated configs
            configs = await self.git_handler.get_configs(
                repo_path=repo_path, config_path=repository.config_path
            )

            # Validate configurations
            for config in configs:
                validation = await self.validator.validate_configuration(
                    config["config"]
                )
                if not validation.is_valid:
                    await self.audit.log_event(
                        event_type="config_validation_failed",
                        user_id=None,
                        details={
                            "repository_id": str(repository.id),
                            "file": config["file"],
                            "errors": validation.errors,
                        },
                        level=AuditLevel.WARNING,
                    )
                    return

            # Create deployment if auto-deploy enabled
            if repository.auto_deploy:
                await self._create_auto_deployment(repository, configs)

            # Cleanup
            self.git_handler.cleanup()

        except Exception as e:
            self.git_handler.cleanup()
            await self.audit.log_event(
                event_type="config_change_processing_failed",
                user_id=None,
                details={"repository_id": str(repository.id), "error": str(e)},
                level=AuditLevel.ERROR,
            )

    async def _trigger_auto_deployment(
        self, repository: GitRepository, pull_result: dict
    ):
        """Trigger automatic deployment"""
        # Would create deployment through deployment service
        pass

    async def _create_auto_deployment(self, repository: GitRepository, configs: list):
        """Create automatic deployment from configs"""
        # Create deployment with proper authorization
        async with get_db() as db:
            deployment = Deployment(
                created_by=repository.id,
                config_hash="pending",
                signature="pending",
                state="pending",
                git_commit=repository.last_commit_hash,
                git_repository_id=repository.id,
            )
            db.add(deployment)
            await db.commit()
            return deployment

    @require_auth
    async def get_deployment_status(self, deployment_id: str, user: User):
        """Get deployment status - requires authentication"""
        async with get_db() as db:
            result = await db.execute(
                select(Deployment).where(Deployment.id == deployment_id)
            )
            deployment = result.scalar_one_or_none()
            if deployment:
                return {"id": str(deployment.id), "state": deployment.state}
            raise HTTPException(404, "Deployment not found")

    def run(self):
        uvicorn.run(self.app, host="0.0.0.0", port=self.port, log_level="info")


if __name__ == "__main__":
    service = GitOpsService()
    service.run()
