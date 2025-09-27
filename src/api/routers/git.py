"""
Git Router
Handles GitOps integration, repository management, webhooks
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from uuid import UUID, uuid4
import asyncio
import hashlib
import hmac
import json
import base64
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status, Request, BackgroundTasks, Query, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_, or_, func
from pydantic import BaseModel, Field, validator, HttpUrl
import git
from git import Repo
import pygit2
import aiofiles

from src.db.models import (
    GitRepository, GitCommit, GitWebhook, GitSyncStatus,
    ConfigurationFile, Deployment, User, AuditLog
)
from src.core.config import settings
from src.core.dependencies import (
    get_db,
    get_current_user,
    require_permission,
    get_redis,
    get_vault,
    get_audit_logger
)
from src.gitops.workflow import GitOpsWorkflow
from src.gitops.scanner import SecretScanner
from src.security.audit import AuditLogger
from src.security.encryption import EncryptionManager
from src.core.exceptions import (
    ValidationError,
    SecurityError,
    GitSyncError
)

router = APIRouter(prefix="/api/v1/git", tags=["gitops"])


class GitRepositoryRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    url: HttpUrl
    branch: str = Field(default="main", max_length=100)
    path: Optional[str] = Field(None, description="Path within repo to configs")
    auth_type: str = Field(default="ssh", regex="^(ssh|https|token)$")
    ssh_key_name: Optional[str] = Field(None, description="Vault key name for SSH")
    token_name: Optional[str] = Field(None, description="Vault key name for token")
    webhook_enabled: bool = True
    auto_sync: bool = True
    sync_interval_minutes: int = Field(default=5, ge=1, le=1440)
    validation_enabled: bool = True
    gpg_verification: bool = True
    allowed_signers: Optional[List[str]] = []
    tags: Optional[List[str]] = []


class GitRepositoryResponse(BaseModel):
    id: UUID
    name: str
    url: str
    branch: str
    path: Optional[str]
    auth_type: str
    webhook_enabled: bool
    webhook_url: Optional[str]
    webhook_secret: Optional[str]
    auto_sync: bool
    sync_interval_minutes: int
    last_sync: Optional[datetime]
    last_commit_hash: Optional[str]
    last_commit_author: Optional[str]
    last_commit_message: Optional[str]
    sync_status: Optional[str]
    validation_enabled: bool
    gpg_verification: bool
    created_at: datetime
    updated_at: datetime


class GitWebhookRequest(BaseModel):
    event: str
    signature: Optional[str]
    payload: Dict[str, Any]


class GitSyncRequest(BaseModel):
    force: bool = False
    validate: bool = True
    dry_run: bool = False


class GitCommitResponse(BaseModel):
    id: UUID
    repository_id: UUID
    commit_hash: str
    author: str
    email: str
    message: str
    files_changed: List[str]
    additions: int
    deletions: int
    verified: bool
    signature: Optional[str]
    committed_at: datetime
    processed: bool
    deployment_id: Optional[UUID]


class ConfigFileResponse(BaseModel):
    id: UUID
    repository_id: UUID
    file_path: str
    content_hash: str
    vendor: Optional[str]
    device_types: List[str]
    validation_status: Optional[str]
    last_modified: datetime
    size_bytes: int


@router.get("/repositories", response_model=List[GitRepositoryResponse])
async def list_repositories(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    sync_status: Optional[str] = None,
    tags: Optional[List[str]] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit: AuditLogger = Depends(get_audit_logger)
) -> List[GitRepositoryResponse]:
    """
    List configured Git repositories
    """

    await require_permission(current_user, "git.read")

    query = select(GitRepository)

    if sync_status:
        query = query.where(GitRepository.sync_status == sync_status)
    if tags:
        query = query.where(GitRepository.tags.contains(tags))

    query = query.offset(skip).limit(limit)

    result = await db.execute(query)
    repositories = result.scalars().all()

    responses = []
    for repo in repositories:
        webhook_url = None
        webhook_secret = None

        if repo.webhook_enabled:
            webhook_url = f"{settings.APP_BASE_URL}/api/v1/git/webhook/{repo.id}"
            # Don't expose actual secret, just indicate it's set
            webhook_secret = "***configured***" if repo.webhook_secret_ref else None

        responses.append(GitRepositoryResponse(
            id=repo.id,
            name=repo.name,
            url=repo.url,
            branch=repo.branch,
            path=repo.path,
            auth_type=repo.auth_type,
            webhook_enabled=repo.webhook_enabled,
            webhook_url=webhook_url,
            webhook_secret=webhook_secret,
            auto_sync=repo.auto_sync,
            sync_interval_minutes=repo.sync_interval_minutes,
            last_sync=repo.last_sync,
            last_commit_hash=repo.last_commit_hash,
            last_commit_author=repo.last_commit_author,
            last_commit_message=repo.last_commit_message,
            sync_status=repo.sync_status,
            validation_enabled=repo.validation_enabled,
            gpg_verification=repo.gpg_verification,
            created_at=repo.created_at,
            updated_at=repo.updated_at
        ))

    await audit.log_event(
        user_id=current_user.id,
        action="list_repositories",
        resource_type="git_repository",
        details={"count": len(repositories)}
    )

    return responses


@router.post("/connect", response_model=GitRepositoryResponse)
async def connect_repository(
    request: GitRepositoryRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis),
    vault = Depends(get_vault),
    audit: AuditLogger = Depends(get_audit_logger)
) -> GitRepositoryResponse:
    """
    Connect and configure a new Git repository
    """

    await require_permission(current_user, "git.create")

    # Check if repository already exists
    existing = await db.execute(
        select(GitRepository).where(GitRepository.url == str(request.url))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Repository already connected"
        )

    # Validate repository access
    gitops = GitOpsWorkflow(db, redis, vault, audit)

    try:
        # Test repository access
        test_result = await gitops.test_repository_access(
            url=str(request.url),
            branch=request.branch,
            auth_type=request.auth_type,
            ssh_key_name=request.ssh_key_name,
            token_name=request.token_name
        )

        if not test_result["accessible"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot access repository: {test_result.get('error', 'Unknown error')}"
            )

    except Exception as e:
        await audit.log_error(
            error_type="git_connection_error",
            error_message=str(e),
            context={
                "url": str(request.url),
                "user_id": str(current_user.id)
            }
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to connect to repository: {str(e)}"
        )

    # Generate webhook secret
    webhook_secret = None
    webhook_secret_ref = None
    if request.webhook_enabled:
        webhook_secret = base64.b64encode(hashlib.sha256(
            f"{request.url}{datetime.utcnow().isoformat()}".encode()
        ).digest()).decode()

        # Store webhook secret in Vault
        webhook_secret_ref = f"git/webhooks/{uuid4()}"
        await vault.store_secret(webhook_secret_ref, webhook_secret)

    # Create repository record
    repository = GitRepository(
        id=uuid4(),
        name=request.name,
        url=str(request.url),
        branch=request.branch,
        path=request.path,
        auth_type=request.auth_type,
        ssh_key_ref=f"git/keys/{request.ssh_key_name}" if request.ssh_key_name else None,
        token_ref=f"git/tokens/{request.token_name}" if request.token_name else None,
        webhook_enabled=request.webhook_enabled,
        webhook_secret_ref=webhook_secret_ref,
        auto_sync=request.auto_sync,
        sync_interval_minutes=request.sync_interval_minutes,
        validation_enabled=request.validation_enabled,
        gpg_verification=request.gpg_verification,
        allowed_signers=request.allowed_signers,
        tags=request.tags,
        sync_status="pending",
        created_by=current_user.id
    )

    db.add(repository)
    await db.commit()
    await db.refresh(repository)

    # Schedule initial sync
    if request.auto_sync:
        background_tasks.add_task(
            sync_repository,
            repository_id=repository.id,
            force=False,
            validate=request.validation_enabled,
            db=db,
            redis=redis,
            vault=vault,
            audit=audit
        )

    # Setup webhook if enabled
    if request.webhook_enabled:
        webhook_url = f"{settings.APP_BASE_URL}/api/v1/git/webhook/{repository.id}"

        # Register webhook with Git provider
        try:
            from ..gitops.webhook_registry import WebhookRegistry
            webhook_registry = WebhookRegistry(vault)

            # Register webhook with the Git provider
            webhook_result = await webhook_registry.register_webhook(
                repository=repository,
                events=["push", "pull_request", "create", "release"],  # Default events
                db=db
            )

            if webhook_result["success"]:
                # Update repository with webhook information
                repository.webhook_id = webhook_result["webhook_id"]
                repository.webhook_url = webhook_result["webhook_url"]
                await db.commit()

                await audit.log_event(
                    user_id=current_user.id,
                    action="webhook_registered",
                    resource_type="git_repository",
                    resource_id=str(repository.id),
                    details={
                        "webhook_id": webhook_result["webhook_id"],
                        "webhook_url": webhook_result["webhook_url"],
                        "events": webhook_result["events"],
                        "provider": webhook_result["provider"]
                    }
                )
            else:
                # Log webhook registration failure but don't fail repository creation
                await audit.log_event(
                    user_id=current_user.id,
                    action="webhook_registration_failed",
                    resource_type="git_repository",
                    resource_id=str(repository.id),
                    details={
                        "error": webhook_result.get("error", "Unknown error"),
                        "provider": repository.provider.value
                    }
                )

        except Exception as e:
            # Log webhook registration error but don't fail repository creation
            await audit.log_error(
                error_type="webhook_registration_error",
                error_message=str(e),
                context={
                    "repository_id": str(repository.id),
                    "webhook_url": webhook_url
                }
            )

    await audit.log_event(
        user_id=current_user.id,
        action="repository_connected",
        resource_type="git_repository",
        resource_id=str(repository.id),
        details={
            "name": repository.name,
            "url": str(request.url),
            "branch": request.branch
        }
    )

    return GitRepositoryResponse(
        id=repository.id,
        name=repository.name,
        url=repository.url,
        branch=repository.branch,
        path=repository.path,
        auth_type=repository.auth_type,
        webhook_enabled=repository.webhook_enabled,
        webhook_url=webhook_url if request.webhook_enabled else None,
        webhook_secret="***configured***" if webhook_secret else None,
        auto_sync=repository.auto_sync,
        sync_interval_minutes=repository.sync_interval_minutes,
        last_sync=repository.last_sync,
        last_commit_hash=repository.last_commit_hash,
        last_commit_author=repository.last_commit_author,
        last_commit_message=repository.last_commit_message,
        sync_status=repository.sync_status,
        validation_enabled=repository.validation_enabled,
        gpg_verification=repository.gpg_verification,
        created_at=repository.created_at,
        updated_at=repository.updated_at
    )


@router.post("/webhook/{repository_id}")
async def process_webhook(
    repository_id: UUID,
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: Optional[str] = Header(None),
    x_gitlab_token: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis),
    vault = Depends(get_vault),
    audit: AuditLogger = Depends(get_audit_logger)
) -> Dict[str, str]:
    """
    Process Git webhook events (GitHub, GitLab, Bitbucket)
    """

    # Get repository
    repository = await db.get(GitRepository, repository_id)
    if not repository:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found"
        )

    if not repository.webhook_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Webhooks not enabled for this repository"
        )

    # Get webhook secret from Vault
    webhook_secret = None
    if repository.webhook_secret_ref:
        webhook_secret = await vault.get_secret(repository.webhook_secret_ref)

    # Get request body
    body = await request.body()

    # Verify webhook signature based on provider
    verified = False

    # GitHub webhook verification
    if x_hub_signature_256 and webhook_secret:
        expected_signature = "sha256=" + hmac.new(
            webhook_secret.encode(),
            body,
            hashlib.sha256
        ).hexdigest()

        if hmac.compare_digest(x_hub_signature_256, expected_signature):
            verified = True

    # GitLab webhook verification
    elif x_gitlab_token and webhook_secret:
        if x_gitlab_token == webhook_secret:
            verified = True

    if not verified:
        await audit.log_security_event(
            event_type="webhook_verification_failed",
            severity="high",
            details={
                "repository_id": str(repository_id),
                "ip_address": request.client.host
            }
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature"
        )

    # Parse webhook payload
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload"
        )

    # Determine event type
    event_type = request.headers.get("X-GitHub-Event") or \
                 request.headers.get("X-Gitlab-Event") or \
                 payload.get("event_type", "push")

    # Create webhook record
    webhook = GitWebhook(
        repository_id=repository_id,
        event_type=event_type,
        payload=payload,
        headers=dict(request.headers),
        verified=verified,
        processed=False
    )
    db.add(webhook)
    await db.commit()

    # Process webhook based on event type
    if event_type in ["push", "Push Hook"]:
        # Handle push event
        background_tasks.add_task(
            process_push_event,
            repository_id=repository_id,
            webhook_id=webhook.id,
            payload=payload,
            db=db,
            redis=redis,
            vault=vault,
            audit=audit
        )

    elif event_type in ["pull_request", "Merge Request Hook"]:
        # Handle pull/merge request event
        background_tasks.add_task(
            process_pr_event,
            repository_id=repository_id,
            webhook_id=webhook.id,
            payload=payload,
            db=db,
            redis=redis,
            vault=vault,
            audit=audit
        )

    await audit.log_event(
        action="webhook_received",
        resource_type="git_repository",
        resource_id=str(repository_id),
        details={
            "event_type": event_type,
            "webhook_id": str(webhook.id)
        }
    )

    return {"status": "accepted", "webhook_id": str(webhook.id)}


@router.post("/{repository_id}/sync")
async def sync_repository_endpoint(
    repository_id: UUID,
    request: GitSyncRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis),
    vault = Depends(get_vault),
    audit: AuditLogger = Depends(get_audit_logger)
) -> Dict[str, Any]:
    """
    Manually trigger repository synchronization
    """

    await require_permission(current_user, "git.sync")

    # Get repository
    repository = await db.get(GitRepository, repository_id)
    if not repository:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found"
        )

    # Check if sync is already in progress
    if repository.sync_status == "syncing":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Sync already in progress"
        )

    # Update sync status
    repository.sync_status = "syncing"
    await db.commit()

    # Schedule sync task
    background_tasks.add_task(
        sync_repository,
        repository_id=repository_id,
        force=request.force,
        validate=request.validate,
        dry_run=request.dry_run,
        user_id=current_user.id,
        db=db,
        redis=redis,
        vault=vault,
        audit=audit
    )

    await audit.log_event(
        user_id=current_user.id,
        action="manual_sync_triggered",
        resource_type="git_repository",
        resource_id=str(repository_id),
        details={
            "force": request.force,
            "validate": request.validate,
            "dry_run": request.dry_run
        }
    )

    return {
        "repository_id": str(repository_id),
        "status": "syncing",
        "message": "Repository sync started"
    }


@router.get("/{repository_id}/commits", response_model=List[GitCommitResponse])
async def list_commits(
    repository_id: UUID,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    author: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit: AuditLogger = Depends(get_audit_logger)
) -> List[GitCommitResponse]:
    """
    List commits from repository
    """

    await require_permission(current_user, "git.read")

    # Get repository
    repository = await db.get(GitRepository, repository_id)
    if not repository:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found"
        )

    query = select(GitCommit).where(GitCommit.repository_id == repository_id)

    if author:
        query = query.where(GitCommit.author.contains(author))
    if since:
        query = query.where(GitCommit.committed_at >= since)
    if until:
        query = query.where(GitCommit.committed_at <= until)

    query = query.order_by(GitCommit.committed_at.desc())
    query = query.offset(skip).limit(limit)

    result = await db.execute(query)
    commits = result.scalars().all()

    return [
        GitCommitResponse(
            id=commit.id,
            repository_id=commit.repository_id,
            commit_hash=commit.commit_hash,
            author=commit.author,
            email=commit.email,
            message=commit.message,
            files_changed=commit.files_changed or [],
            additions=commit.additions or 0,
            deletions=commit.deletions or 0,
            verified=commit.verified,
            signature=commit.signature,
            committed_at=commit.committed_at,
            processed=commit.processed,
            deployment_id=commit.deployment_id
        )
        for commit in commits
    ]


@router.get("/{repository_id}/configs", response_model=List[ConfigFileResponse])
async def list_config_files(
    repository_id: UUID,
    vendor: Optional[str] = None,
    device_type: Optional[str] = None,
    validation_status: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit: AuditLogger = Depends(get_audit_logger)
) -> List[ConfigFileResponse]:
    """
    List configuration files from repository
    """

    await require_permission(current_user, "git.read")

    # Get repository
    repository = await db.get(GitRepository, repository_id)
    if not repository:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found"
        )

    query = select(ConfigurationFile).where(
        ConfigurationFile.repository_id == repository_id
    )

    if vendor:
        query = query.where(ConfigurationFile.vendor == vendor)
    if device_type:
        query = query.where(ConfigurationFile.device_types.contains([device_type]))
    if validation_status:
        query = query.where(ConfigurationFile.validation_status == validation_status)

    result = await db.execute(query)
    config_files = result.scalars().all()

    return [
        ConfigFileResponse(
            id=config_file.id,
            repository_id=config_file.repository_id,
            file_path=config_file.file_path,
            content_hash=config_file.content_hash,
            vendor=config_file.vendor,
            device_types=config_file.device_types or [],
            validation_status=config_file.validation_status,
            last_modified=config_file.last_modified,
            size_bytes=config_file.size_bytes
        )
        for config_file in config_files
    ]


@router.get("/{repository_id}/config/{file_id}/content")
async def get_config_content(
    repository_id: UUID,
    file_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    vault = Depends(get_vault),
    audit: AuditLogger = Depends(get_audit_logger)
) -> Dict[str, Any]:
    """
    Get configuration file content
    """

    await require_permission(current_user, "git.read")

    # Get config file
    result = await db.execute(
        select(ConfigurationFile).where(
            and_(
                ConfigurationFile.id == file_id,
                ConfigurationFile.repository_id == repository_id
            )
        )
    )
    config_file = result.scalar_one_or_none()

    if not config_file:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Configuration file not found"
        )

    # Decrypt content if encrypted
    content = config_file.content_encrypted
    if content:
        encryption_manager = EncryptionManager(vault)
        content = await encryption_manager.decrypt(content)
        content = content.decode()

    await audit.log_event(
        user_id=current_user.id,
        action="config_file_accessed",
        resource_type="configuration_file",
        resource_id=str(file_id),
        details={
            "repository_id": str(repository_id),
            "file_path": config_file.file_path
        }
    )

    return {
        "file_id": str(file_id),
        "file_path": config_file.file_path,
        "content": content,
        "vendor": config_file.vendor,
        "device_types": config_file.device_types,
        "validation_status": config_file.validation_status
    }


async def sync_repository(
    repository_id: UUID,
    force: bool,
    validate: bool,
    dry_run: bool = False,
    user_id: Optional[UUID] = None,
    db: AsyncSession = None,
    redis = None,
    vault = None,
    audit: AuditLogger = None
):
    """
    Background task to sync repository
    """

    repository = await db.get(GitRepository, repository_id)
    if not repository:
        return

    gitops = GitOpsWorkflow(db, redis, vault, audit)

    try:
        # Clone or pull repository
        repo_path = await gitops.clone_or_pull_repository(
            repository=repository,
            force=force
        )

        # Get latest commits
        commits = await gitops.get_commits(
            repository=repository,
            since=repository.last_sync
        )

        # Process each commit
        for commit_data in commits:
            # Check for secrets
            if not dry_run:
                scanner = SecretScanner()
                secrets_found = await scanner.scan_commit(commit_data)

                if secrets_found:
                    await audit.log_security_event(
                        event_type="secrets_detected",
                        severity="critical",
                        user_id=user_id,
                        details={
                            "repository_id": str(repository_id),
                            "commit": commit_data["hash"],
                            "secrets_count": len(secrets_found)
                        }
                    )
                    continue  # Skip this commit

            # Store commit
            commit = GitCommit(
                repository_id=repository_id,
                commit_hash=commit_data["hash"],
                author=commit_data["author"],
                email=commit_data["email"],
                message=commit_data["message"],
                files_changed=commit_data["files"],
                additions=commit_data["additions"],
                deletions=commit_data["deletions"],
                verified=commit_data.get("verified", False),
                signature=commit_data.get("signature"),
                committed_at=commit_data["date"],
                processed=False
            )
            db.add(commit)

            # Process configuration files
            if not dry_run:
                config_files = await gitops.extract_config_files(
                    repository=repository,
                    commit_hash=commit_data["hash"]
                )

                for config_data in config_files:
                    # Validate configuration if enabled
                    validation_status = None
                    if validate:
                        validation_result = await gitops.validate_config(
                            config_content=config_data["content"],
                            vendor=config_data.get("vendor")
                        )
                        validation_status = "valid" if validation_result["valid"] else "invalid"

                    # Encrypt content
                    encryption_manager = EncryptionManager(vault)
                    encrypted_content = await encryption_manager.encrypt(
                        config_data["content"].encode()
                    )

                    # Store configuration file
                    config_file = ConfigurationFile(
                        repository_id=repository_id,
                        commit_id=commit.id,
                        file_path=config_data["path"],
                        content_encrypted=encrypted_content,
                        content_hash=hashlib.sha256(config_data["content"].encode()).hexdigest(),
                        vendor=config_data.get("vendor"),
                        device_types=config_data.get("device_types", []),
                        validation_status=validation_status,
                        last_modified=datetime.utcnow(),
                        size_bytes=len(config_data["content"])
                    )
                    db.add(config_file)

        # Update repository status
        if commits:
            latest_commit = commits[0]
            repository.last_commit_hash = latest_commit["hash"]
            repository.last_commit_author = latest_commit["author"]
            repository.last_commit_message = latest_commit["message"][:500]

        repository.last_sync = datetime.utcnow()
        repository.sync_status = "synced"

        # Create sync status record
        sync_status = GitSyncStatus(
            repository_id=repository_id,
            status="success",
            commits_processed=len(commits),
            files_processed=sum(len(c.get("files", [])) for c in commits),
            errors=[],
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow()
        )
        db.add(sync_status)

        await db.commit()

        if user_id:
            await audit.log_event(
                user_id=user_id,
                action="repository_synced",
                resource_type="git_repository",
                resource_id=str(repository_id),
                details={
                    "commits_processed": len(commits),
                    "dry_run": dry_run
                }
            )

    except Exception as e:
        repository.sync_status = "failed"
        repository.sync_error = str(e)

        sync_status = GitSyncStatus(
            repository_id=repository_id,
            status="failed",
            errors=[str(e)],
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow()
        )
        db.add(sync_status)

        await db.commit()

        await audit.log_error(
            error_type="repository_sync_error",
            error_message=str(e),
            context={
                "repository_id": str(repository_id),
                "user_id": str(user_id) if user_id else None
            }
        )


async def process_push_event(
    repository_id: UUID,
    webhook_id: UUID,
    payload: Dict[str, Any],
    db: AsyncSession,
    redis,
    vault,
    audit: AuditLogger
):
    """
    Process Git push event from webhook
    """

    # Trigger repository sync
    await sync_repository(
        repository_id=repository_id,
        force=False,
        validate=True,
        dry_run=False,
        db=db,
        redis=redis,
        vault=vault,
        audit=audit
    )

    # Mark webhook as processed
    webhook = await db.get(GitWebhook, webhook_id)
    if webhook:
        webhook.processed = True
        webhook.processed_at = datetime.utcnow()
        await db.commit()


async def process_pr_event(
    repository_id: UUID,
    webhook_id: UUID,
    payload: Dict[str, Any],
    db: AsyncSession,
    redis,
    vault,
    audit: AuditLogger
):
    """
    Process pull/merge request event from webhook
    """

    # Validate PR changes
    gitops = GitOpsWorkflow(db, redis, vault, audit)

    pr_number = payload.get("pull_request", {}).get("number") or \
                payload.get("merge_request", {}).get("iid")

    if pr_number:
        # Validate PR changes
        validation_result = await gitops.validate_pr(
            repository_id=repository_id,
            pr_number=pr_number
        )

        # Post validation results as PR comment
        try:
            from ..gitops.webhook_handler import WebhookHandler
            from ..gitops.git_client import SecureGitClient
            from ..core.config_parser import ConfigParser
            from ..deployment.validator import ConfigValidator
            from ..security.scanner import SecretScanner
            from ..security.vault import VaultClient

            # Create webhook handler instance
            git_client = SecureGitClient(db, redis, vault, audit)
            config_parser = ConfigParser()
            config_validator = ConfigValidator()
            secret_scanner = SecretScanner()

            webhook_handler = WebhookHandler(
                git_client=git_client,
                config_parser=config_parser,
                config_validator=config_validator,
                security_scanner=secret_scanner,
                vault_client=vault
            )

            # Generate validation summary comment
            comment_text = await _generate_pr_comment(
                validation_result,
                repository,
                pr_number
            )

            # Post comment to PR
            comment_posted = await webhook_handler._post_pr_comment(
                repository=repository,
                pr_number=pr_number,
                comment=comment_text
            )

            if comment_posted:
                await audit.log_event(
                    action="pr_comment_posted",
                    resource_type="git_repository",
                    resource_id=str(repository_id),
                    details={
                        "pr_number": pr_number,
                        "comment_length": len(comment_text),
                        "validation_status": validation_result.get("status", "unknown")
                    }
                )
            else:
                await audit.log_event(
                    action="pr_comment_failed",
                    resource_type="git_repository",
                    resource_id=str(repository_id),
                    details={
                        "pr_number": pr_number,
                        "error": "Failed to post comment"
                    }
                )

        except Exception as e:
            await audit.log_error(
                error_type="pr_comment_error",
                error_message=str(e),
                context={
                    "repository_id": str(repository_id),
                    "pr_number": pr_number
                }
            )

    # Mark webhook as processed
    webhook = await db.get(GitWebhook, webhook_id)
    if webhook:
        webhook.processed = True
        webhook.processed_at = datetime.utcnow()
        await db.commit()


async def _generate_pr_comment(
    validation_result: Dict[str, Any],
    repository: GitRepository,
    pr_number: int
) -> str:
    """
    Generate comprehensive PR comment with validation results
    """
    status = validation_result.get("status", "unknown")
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Status emoji and color
    status_emoji = {
        "valid": "✅",
        "warning": "⚠️",
        "error": "❌",
        "pending": "⏳",
        "unknown": "❓"
    }.get(status, "❓")

    comment_parts = [
        f"## {status_emoji} CatNet Configuration Validation Report",
        f"**Status:** {status.title()}",
        f"**Repository:** {repository.name}",
        f"**PR #:** {pr_number}",
        f"**Analyzed at:** {timestamp}",
        ""
    ]

    # Summary section
    summary = validation_result.get("summary", {})
    if summary:
        comment_parts.extend([
            "### 📊 Summary",
            f"- **Files analyzed:** {summary.get(\"files_analyzed\", 0)}",
            f"- **Configurations found:** {summary.get(\"configs_found\", 0)}",
            f"- **Errors:** {summary.get(\"errors\", 0)}",
            f"- **Warnings:** {summary.get(\"warnings\", 0)}",
            f"- **Security issues:** {summary.get(\"security_issues\", 0)}",
            ""
        ])

    # Validation details
    if validation_result.get("errors"):
        comment_parts.extend([
            "### ❌ Errors",
            "The following errors must be addressed before deployment:",
            ""
        ])

        for i, error in enumerate(validation_result["errors"][:10], 1):  # Limit to 10
            file_path = error.get("file", "unknown")
            line = error.get("line", "")
            message = error.get("message", "Unknown error")
            location = f" (Line {line})" if line else ""
            comment_parts.append(f"{i}. **{file_path}**{location}: {message}")

        if len(validation_result["errors"]) > 10:
            remaining = len(validation_result["errors"]) - 10
            comment_parts.append(f"... and {remaining} more errors")

        comment_parts.append("")

    # Security findings
    security_issues = validation_result.get("security_issues", [])
    if security_issues:
        comment_parts.extend([
            "### 🔒 Security Issues",
            "**Critical security issues found - deployment blocked!**",
            ""
        ])

        for i, issue in enumerate(security_issues[:5], 1):  # Limit to 5
            severity = issue.get("severity", "unknown").upper()
            issue_type = issue.get("type", "unknown")
            file_path = issue.get("file", "unknown")
            description = issue.get("description", "Security issue detected")

            severity_emoji = {
                "CRITICAL": "🚨",
                "HIGH": "🔴",
                "MEDIUM": "🟡",
                "LOW": "🟢"
            }.get(severity, "⚠️")

            comment_parts.append(f"{i}. {severity_emoji} **{severity} - {issue_type}**")
            comment_parts.append(f"   - **File:** {file_path}")
            comment_parts.append(f"   - **Issue:** {description}")
            comment_parts.append("")

    # Deployment recommendation
    if status == "valid":
        comment_parts.extend([
            "### 🚀 Deployment Status",
            "✅ **Configuration is valid and ready for deployment!**",
            ""
        ])
    elif status == "warning":
        comment_parts.extend([
            "### ⚠️ Deployment Status",
            "⚠️ **Configuration has warnings but can be deployed with caution**",
            "Please review the warnings above before proceeding.",
            ""
        ])
    else:
        comment_parts.extend([
            "### ❌ Deployment Status",
            "❌ **Configuration has errors and cannot be deployed**",
            "Please fix the errors above before attempting deployment.",
            ""
        ])

    # Footer
    comment_parts.extend([
        "",
        "---",
        "*This comment was automatically generated by CatNet - Network Configuration Deployment System*",
        f"*Last updated: {timestamp}*"
    ])

    return "\n".join(comment_parts)
