"""
GitOps Service Implementation for CatNet
Handles repository connections, webhook processing, and configuration synchronization
"""

from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, Request, Response, status, BackgroundTasks, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, HttpUrl, validator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
import git
from git import Repo, InvalidGitRepositoryError
import asyncio
import hashlib
import hmac
import json
import re
import yaml
import base64
import tempfile
import shutil
from pathlib import Path
import uvicorn
import structlog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from src.core.config import settings
from src.db import get_db, db_manager
from src.db.models import (
    GitRepository, GitWebhook, Deployment, DeviceConfig,
    User, Device, WebhookStatus, DeploymentState
)
from src.security.vault import VaultClient
from src.security.encryption import EncryptionManager
from src.security.scanner import SecretScanner, SecurityScanner
from src.security.audit import AuditLogger
from src.core.exceptions import ValidationError, SecurityError

logger = structlog.get_logger()

app = FastAPI(
    title="CatNet GitOps Service",
    description="Repository connections and webhook processing",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=settings.cors_allow_methods,
    allow_headers=settings.cors_allow_headers,
)


class GitRepositoryRequest(BaseModel):
    """Git repository connection request"""
    name: str = Field(..., min_length=1, max_length=100)
    url: HttpUrl
    branch: str = Field("main", min_length=1, max_length=100)
    auth_type: str = Field("ssh", pattern="^(ssh|https|token)$")
    auto_sync: bool = True
    sync_interval_minutes: int = Field(5, ge=1, le=60)
    gpg_verification: bool = True
    scan_for_secrets: bool = True


class WebhookConfig(BaseModel):
    """Webhook configuration"""
    events: List[str] = ["push", "pull_request"]
    secret: str = Field(..., min_length=32)
    active: bool = True


class GitOpsService:
    """
    GitOps service managing repository synchronization and webhooks
    """

    def __init__(self):
        self.vault_client = VaultClient()
        self.encryption_manager = EncryptionManager()
        self.secret_scanner = SecretScanner()
        self.security_scanner = SecurityScanner()
        self.audit_logger = AuditLogger()
        self.webhook_handlers = {
            "push": self._handle_push_event,
            "pull_request": self._handle_pull_request,
            "release": self._handle_release_event
        }

    async def connect_repository(
        self,
        db: AsyncSession,
        request: GitRepositoryRequest,
        user: User
    ) -> GitRepository:
        """
        Connect and configure Git repository
        """
        existing = await db.execute(
            select(GitRepository).where(GitRepository.name == request.name)
        )
        if existing.scalar_one_or_none():
            raise ValidationError(f"Repository {request.name} already exists")

        deploy_key = await self._generate_deploy_key(request.name)

        if request.auth_type == "ssh":
            auth_secret = await self.vault_client.store_secret(
                f"gitops/repos/{request.name}/deploy_key",
                {"private_key": deploy_key["private_key"]}
            )
        else:
            auth_secret = None

        webhook_secret = self._generate_webhook_secret()
        webhook_ref = await self.vault_client.store_secret(
            f"gitops/repos/{request.name}/webhook_secret",
            {"secret": webhook_secret}
        )

        repository = GitRepository(
            name=request.name,
            url=str(request.url),
            branch=request.branch,
            auth_type=request.auth_type,
            webhook_secret_ref=webhook_ref,
            deploy_key_ref=auth_secret,
            auto_sync=request.auto_sync,
            sync_interval_minutes=request.sync_interval_minutes,
            gpg_verification=request.gpg_verification,
            scan_for_secrets=request.scan_for_secrets,
            is_active=True
        )

        db.add(repository)
        await db.commit()
        await db.refresh(repository)

        await self.audit_logger.log_event(
            db=db,
            user=user,
            action="gitops.repository.connect",
            details={
                "repository_name": request.name,
                "url": str(request.url),
                "branch": request.branch
            }
        )

        asyncio.create_task(self._initial_sync(repository.id))

        return {
            "repository": repository,
            "deploy_key_public": deploy_key["public_key"] if deploy_key else None,
            "webhook_url": f"{settings.base_url}/git/webhook/{repository.id}",
            "webhook_secret": webhook_secret
        }

    async def process_webhook(
        self,
        db: AsyncSession,
        repository_id: str,
        payload: Dict[str, Any],
        headers: Dict[str, str],
        signature: Optional[str] = None
    ) -> GitWebhook:
        """
        Process incoming webhook from Git provider
        """
        repository = await db.get(GitRepository, repository_id)
        if not repository:
            raise ValidationError("Repository not found")

        if not await self._verify_webhook_signature(repository, payload, signature):
            await self.audit_logger.log_event(
                db=db,
                action="gitops.webhook.signature_failed",
                details={
                    "repository_id": repository_id,
                    "event_type": headers.get("X-GitHub-Event", "unknown")
                }
            )
            raise SecurityError("Invalid webhook signature")

        event_type = headers.get("X-GitHub-Event") or headers.get("X-Gitlab-Event", "push")
        event_id = headers.get("X-GitHub-Delivery") or headers.get("X-Gitlab-Event-UUID", "")

        webhook = GitWebhook(
            repository_id=repository_id,
            event_type=event_type,
            event_id=event_id,
            payload=payload,
            headers=headers,
            signature=signature,
            signature_verified=True,
            processing_status=WebhookStatus.PROCESSING
        )

        db.add(webhook)
        await db.commit()
        await db.refresh(webhook)

        try:
            if repository.scan_for_secrets:
                secrets_found = await self._scan_for_secrets(payload)
                if secrets_found:
                    webhook.secrets_found = True
                    webhook.security_issues = {"secrets": secrets_found}
                    webhook.quarantined = True
                    webhook.processing_status = WebhookStatus.QUARANTINED
                    await db.commit()

                    await self._alert_security_team(repository, secrets_found)
                    return webhook

            handler = self.webhook_handlers.get(event_type)
            if handler:
                result = await handler(db, repository, webhook, payload)
                webhook.processing_result = result
                webhook.processing_status = WebhookStatus.PROCESSED
            else:
                webhook.processing_status = WebhookStatus.PROCESSED
                webhook.processing_result = {"message": f"No handler for event type: {event_type}"}

            webhook.processed_at = datetime.utcnow()
            await db.commit()

        except Exception as e:
            logger.error(f"Webhook processing failed: {e}")
            webhook.processing_status = WebhookStatus.FAILED
            webhook.processing_result = {"error": str(e)}
            webhook.processed_at = datetime.utcnow()
            await db.commit()

        return webhook

    async def sync_repository(
        self,
        db: AsyncSession,
        repository_id: str,
        force: bool = False
    ) -> Dict[str, Any]:
        """
        Synchronize repository configurations
        """
        repository = await db.get(GitRepository, repository_id)
        if not repository:
            raise ValidationError("Repository not found")

        temp_dir = tempfile.mkdtemp()
        try:
            repo_path = await self._clone_repository(repository, temp_dir)

            configs = await self._parse_configurations(repo_path)

            validation_results = []
            for config in configs:
                validation = await self._validate_configuration(config)
                validation_results.append(validation)

                if not validation["valid"]:
                    continue

                await self._process_configuration(db, repository, config)

            repository.last_sync = datetime.utcnow()
            repository.connection_status = "connected"
            await db.commit()

            return {
                "repository_id": repository_id,
                "configs_found": len(configs),
                "configs_valid": sum(1 for v in validation_results if v["valid"]),
                "last_commit": repository.last_commit_hash,
                "synced_at": repository.last_sync.isoformat()
            }

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    async def _handle_push_event(
        self,
        db: AsyncSession,
        repository: GitRepository,
        webhook: GitWebhook,
        payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handle push events from Git
        """
        commits = payload.get("commits", [])
        ref = payload.get("ref", "")
        branch = ref.split("/")[-1] if ref else ""

        if branch != repository.branch:
            return {"message": f"Ignoring push to branch {branch}"}

        modified_files = set()
        for commit in commits:
            if repository.gpg_verification:
                if not commit.get("verified"):
                    await self._quarantine_commit(db, webhook, commit, "Unsigned commit")
                    return {"error": "Unsigned commit detected"}

            modified_files.update(commit.get("modified", []))
            modified_files.update(commit.get("added", []))

        config_files = [f for f in modified_files if self._is_config_file(f)]

        if config_files:
            deployment = await self._create_deployment(
                db=db,
                repository=repository,
                files=config_files,
                commit_sha=payload.get("after"),
                commit_message=commits[-1].get("message") if commits else ""
            )

            return {
                "deployment_id": str(deployment.id),
                "config_files": config_files,
                "state": deployment.state.value
            }

        return {"message": "No configuration files modified"}

    async def _handle_pull_request(
        self,
        db: AsyncSession,
        repository: GitRepository,
        webhook: GitWebhook,
        payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handle pull request events
        """
        action = payload.get("action")
        pr = payload.get("pull_request", {})

        if action not in ["opened", "synchronize", "reopened"]:
            return {"message": f"Ignoring PR action: {action}"}

        pr_files = await self._get_pr_files(repository, pr.get("number"))

        validation_results = []
        for file in pr_files:
            if self._is_config_file(file["filename"]):
                content = await self._get_file_content(
                    repository,
                    file["filename"],
                    pr.get("head", {}).get("sha")
                )

                validation = await self._validate_configuration(content)
                validation_results.append({
                    "file": file["filename"],
                    "valid": validation["valid"],
                    "errors": validation.get("errors", []),
                    "warnings": validation.get("warnings", [])
                })

        await self._post_pr_comment(
            repository,
            pr.get("number"),
            self._format_validation_results(validation_results)
        )

        return {
            "pr_number": pr.get("number"),
            "validation_results": validation_results
        }

    async def _handle_release_event(
        self,
        db: AsyncSession,
        repository: GitRepository,
        webhook: GitWebhook,
        payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handle release events
        """
        release = payload.get("release", {})
        tag = release.get("tag_name")

        if release.get("prerelease") or release.get("draft"):
            return {"message": "Ignoring pre-release or draft"}

        deployment = await self._create_deployment(
            db=db,
            repository=repository,
            files=None,
            commit_sha=release.get("target_commitish"),
            commit_message=f"Release {tag}",
            is_release=True
        )

        deployment.requires_approval = True
        deployment.approval_required_count = 3
        await db.commit()

        return {
            "deployment_id": str(deployment.id),
            "release_tag": tag,
            "requires_approval": True
        }

    async def _verify_webhook_signature(
        self,
        repository: GitRepository,
        payload: Dict[str, Any],
        signature: Optional[str]
    ) -> bool:
        """
        Verify webhook signature
        """
        if not signature:
            return False

        secret_data = await self.vault_client.get_secret(repository.webhook_secret_ref)
        secret = secret_data.get("secret")

        if signature.startswith("sha256="):
            signature = signature[7:]

        payload_bytes = json.dumps(payload, separators=(",", ":")).encode()
        expected_signature = hmac.new(
            secret.encode(),
            payload_bytes,
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(signature, expected_signature)

    async def _scan_for_secrets(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Scan commits for secrets
        """
        secrets_found = []

        commits = payload.get("commits", [])
        for commit in commits:
            for file_change in ["added", "modified"]:
                for file_path in commit.get(file_change, []):
                    if self.secret_scanner.should_scan(file_path):
                        content = commit.get("content", {}).get(file_path)
                        if content:
                            secrets = self.secret_scanner.scan(content)
                            if secrets:
                                secrets_found.extend([{
                                    "file": file_path,
                                    "commit": commit["id"],
                                    "secrets": secrets
                                }])

        return secrets_found

    async def _clone_repository(
        self,
        repository: GitRepository,
        temp_dir: str
    ) -> Path:
        """
        Clone repository to temporary directory
        """
        repo_path = Path(temp_dir) / repository.name

        if repository.auth_type == "ssh":
            key_data = await self.vault_client.get_secret(repository.deploy_key_ref)
            ssh_key_path = Path(temp_dir) / "deploy_key"
            ssh_key_path.write_text(key_data["private_key"])
            ssh_key_path.chmod(0o600)

            ssh_command = f"ssh -i {ssh_key_path} -o StrictHostKeyChecking=no"
            repo = Repo.clone_from(
                repository.url,
                repo_path,
                branch=repository.branch,
                env={"GIT_SSH_COMMAND": ssh_command}
            )
        else:
            repo = Repo.clone_from(
                repository.url,
                repo_path,
                branch=repository.branch
            )

        repository.last_commit_hash = repo.head.commit.hexsha
        return repo_path

    async def _parse_configurations(self, repo_path: Path) -> List[Dict[str, Any]]:
        """
        Parse configuration files from repository
        """
        configs = []
        config_paths = [
            "configs/**/*.yaml",
            "configs/**/*.yml",
            "deployments/**/*.yaml",
            "deployments/**/*.yml"
        ]

        for pattern in config_paths:
            for config_file in repo_path.glob(pattern):
                try:
                    with open(config_file, 'r') as f:
                        config = yaml.safe_load(f)
                        config["_source_file"] = str(config_file.relative_to(repo_path))
                        configs.append(config)
                except Exception as e:
                    logger.error(f"Failed to parse {config_file}: {e}")

        return configs

    async def _validate_configuration(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate configuration against schema and security policies
        """
        validation_result = {
            "valid": True,
            "errors": [],
            "warnings": []
        }

        if not config.get("devices"):
            validation_result["errors"].append("No devices specified")
            validation_result["valid"] = False

        if not config.get("vendor") in ["cisco", "juniper"]:
            validation_result["errors"].append("Invalid or missing vendor")
            validation_result["valid"] = False

        if "commands" in config:
            dangerous_commands = self._check_dangerous_commands(config["commands"])
            if dangerous_commands:
                validation_result["errors"].extend(dangerous_commands)
                validation_result["valid"] = False

        security_issues = self.security_scanner.scan_configuration(config)
        if security_issues:
            validation_result["warnings"].extend(security_issues)

        return validation_result

    async def _process_configuration(
        self,
        db: AsyncSession,
        repository: GitRepository,
        config: Dict[str, Any]
    ):
        """
        Process valid configuration for deployment
        """
        encrypted_config = self.encryption_manager.encrypt(json.dumps(config))
        config_hash = hashlib.sha256(json.dumps(config).encode()).hexdigest()

        for device_name in config.get("devices", []):
            device = await db.execute(
                select(Device).where(Device.hostname == device_name)
            )
            device = device.scalar_one_or_none()

            if device:
                device_config = DeviceConfig(
                    device_id=device.id,
                    version=await self._get_next_version(db, device.id),
                    config_encrypted=encrypted_config,
                    config_hash=config_hash,
                    encryption_key_id=self.encryption_manager.current_key_id,
                    backup_location=f"s3://backups/{device.id}/{datetime.utcnow().isoformat()}",
                    change_description=f"GitOps sync from {repository.name}",
                    is_current=False
                )
                db.add(device_config)

        await db.commit()

    async def _create_deployment(
        self,
        db: AsyncSession,
        repository: GitRepository,
        files: Optional[List[str]],
        commit_sha: str,
        commit_message: str,
        is_release: bool = False
    ) -> Deployment:
        """
        Create deployment from Git changes
        """
        deployment = Deployment(
            name=f"GitOps-{repository.name}-{commit_sha[:8]}",
            description=commit_message,
            repository_id=repository.id,
            config_hash=hashlib.sha256(commit_sha.encode()).hexdigest(),
            signature=self._sign_deployment(commit_sha),
            state=DeploymentState.PENDING,
            requires_approval=True,
            created_by=None  # System created
        )

        db.add(deployment)
        await db.commit()
        await db.refresh(deployment)

        return deployment

    async def _quarantine_commit(
        self,
        db: AsyncSession,
        webhook: GitWebhook,
        commit: Dict[str, Any],
        reason: str
    ):
        """
        Quarantine suspicious commit
        """
        webhook.quarantined = True
        webhook.security_issues = {
            "quarantine_reason": reason,
            "commit": commit.get("id"),
            "author": commit.get("author")
        }
        webhook.processing_status = WebhookStatus.QUARANTINED
        await db.commit()

        await self._alert_security_team(None, {
            "type": "quarantined_commit",
            "reason": reason,
            "commit": commit
        })

    def _check_dangerous_commands(self, commands: List[str]) -> List[str]:
        """
        Check for dangerous commands in configuration
        """
        dangerous_patterns = [
            r"delete\s+.*",
            r"format\s+.*",
            r"reload.*",
            r"shutdown.*",
            r"clear\s+.*",
            r"debug\s+all.*",
            r"no\s+aaa.*",
            r"username\s+.*\s+password.*",
            r"enable\s+password.*"
        ]

        issues = []
        for command in commands:
            for pattern in dangerous_patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    issues.append(f"Dangerous command detected: {command}")
                    break

        return issues

    def _is_config_file(self, filename: str) -> bool:
        """
        Check if file is a configuration file
        """
        config_extensions = [".yaml", ".yml", ".json", ".conf", ".cfg"]
        return any(filename.endswith(ext) for ext in config_extensions)

    def _generate_webhook_secret(self) -> str:
        """
        Generate secure webhook secret
        """
        import secrets
        return secrets.token_urlsafe(32)

    async def _generate_deploy_key(self, repo_name: str) -> Dict[str, str]:
        """
        Generate SSH deploy key pair
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )

        return {
            "private_key": private_pem.decode(),
            "public_key": public_pem.decode() + f" catnet-{repo_name}"
        }

    def _sign_deployment(self, data: str) -> str:
        """
        Sign deployment data
        """
        return hashlib.sha256(f"{data}{settings.deployment_signing_key}".encode()).hexdigest()

    async def _get_next_version(self, db: AsyncSession, device_id: str) -> int:
        """
        Get next configuration version for device
        """
        result = await db.execute(
            select(DeviceConfig.version)
            .where(DeviceConfig.device_id == device_id)
            .order_by(DeviceConfig.version.desc())
            .limit(1)
        )
        current_version = result.scalar_one_or_none()
        return (current_version or 0) + 1

    async def _alert_security_team(
        self,
        repository: Optional[GitRepository],
        security_issue: Dict[str, Any]
    ):
        """
        Alert security team about issues
        """
        logger.critical(f"Security alert: {security_issue}")
        # Implement actual alerting (email, Slack, PagerDuty, etc.)

    async def _get_pr_files(
        self,
        repository: GitRepository,
        pr_number: int
    ) -> List[Dict[str, Any]]:
        """
        Get files modified in pull request
        """
        # Implement GitHub/GitLab API call to get PR files
        return []

    async def _get_file_content(
        self,
        repository: GitRepository,
        file_path: str,
        ref: str
    ) -> str:
        """
        Get file content from repository at specific ref
        """
        # Implement GitHub/GitLab API call to get file content
        return ""

    async def _post_pr_comment(
        self,
        repository: GitRepository,
        pr_number: int,
        comment: str
    ):
        """
        Post comment on pull request
        """
        # Implement GitHub/GitLab API call to post comment
        pass

    def _format_validation_results(
        self,
        results: List[Dict[str, Any]]
    ) -> str:
        """
        Format validation results for PR comment
        """
        comment = "## CatNet Configuration Validation Results\n\n"

        valid_count = sum(1 for r in results if r["valid"])
        total_count = len(results)

        if valid_count == total_count:
            comment += "✅ All configurations valid!\n\n"
        else:
            comment += f"⚠️ {total_count - valid_count} configurations have issues\n\n"

        for result in results:
            status = "✅" if result["valid"] else "❌"
            comment += f"### {status} {result['file']}\n"

            if result.get("errors"):
                comment += "**Errors:**\n"
                for error in result["errors"]:
                    comment += f"- {error}\n"

            if result.get("warnings"):
                comment += "**Warnings:**\n"
                for warning in result["warnings"]:
                    comment += f"- {warning}\n"

            comment += "\n"

        return comment

    async def _initial_sync(self, repository_id: str):
        """
        Perform initial repository sync
        """
        async with db_manager.get_session() as db:
            try:
                await self.sync_repository(db, repository_id)
            except Exception as e:
                logger.error(f"Initial sync failed for {repository_id}: {e}")


gitops_service = GitOpsService()


@app.post("/git/connect", tags=["Repository"])
async def connect_repository(
    request: GitRepositoryRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(lambda: None)
):
    """Connect new Git repository"""
    return await gitops_service.connect_repository(db, request, current_user)


@app.post("/git/webhook/{repository_id}", tags=["Webhook"])
async def process_webhook(
    repository_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_hub_signature_256: Optional[str] = Header(None),
    x_gitlab_token: Optional[str] = Header(None)
):
    """Process webhook from Git provider"""
    payload = await request.json()
    headers = dict(request.headers)
    signature = x_hub_signature_256 or x_gitlab_token

    return await gitops_service.process_webhook(
        db, repository_id, payload, headers, signature
    )


@app.post("/git/sync/{repository_id}", tags=["Sync"])
async def sync_repository(
    repository_id: str,
    force: bool = False,
    db: AsyncSession = Depends(get_db)
):
    """Manually trigger repository synchronization"""
    return await gitops_service.sync_repository(db, repository_id, force)


@app.get("/git/configs", tags=["Configuration"])
async def list_configurations(
    repository_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """List synchronized configurations"""
    query = select(DeviceConfig)
    if repository_id:
        query = query.join(Deployment).where(
            Deployment.repository_id == repository_id
        )

    result = await db.execute(query)
    configs = result.scalars().all()

    return [
        {
            "id": str(config.id),
            "device_id": str(config.device_id),
            "version": config.version,
            "hash": config.config_hash,
            "created_at": config.created_at.isoformat()
        }
        for config in configs
    ]


@app.get("/health", tags=["Health"])
async def health_check():
    """Service health check"""
    return {
        "status": "healthy",
        "service": "gitops",
        "timestamp": datetime.utcnow().isoformat()
    }


def run_service():
    """Run the GitOps service"""
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=settings.gitops_service_port,
        log_level=settings.log_level.lower()
    )


if __name__ == "__main__":
    run_service()