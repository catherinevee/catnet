from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks, Request, Header
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional, Dict, Any
import uuid
import structlog
import json
import hmac
import hashlib

from ...db.database import get_db
from ...db.schemas import (
    GitRepositoryCreate, GitRepositoryUpdate, GitRepositoryResponse,
    WebhookPayload, DeploymentCreate, DeploymentResponse
)
from ...db.models import User, GitRepository, WebhookEvent, Deployment
from ...auth.auth_service import get_current_user
from ...auth.permissions import Permission, PermissionDependency
from ...gitops.gitops_service import gitops_service

logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1/gitops", tags=["GitOps"])


@router.post("/repositories", response_model=GitRepositoryResponse, status_code=status.HTTP_201_CREATED)
async def connect_repository(
    repo_data: GitRepositoryCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(
        PermissionDependency([Permission.GIT_REPO_CREATE])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Connect a Git repository.

    Security:
    - Requires GIT_REPO_CREATE permission
    - Validates repository access
    - Stores credentials in Vault
    - Scans for secrets
    """
    try:
        repository = await gitops_service.connect_repository(
            db=db,
            name=repo_data.name,
            url=repo_data.url,
            branch=repo_data.branch,
            webhook_secret=repo_data.webhook_secret_ref,
            ssh_key=repo_data.ssh_key_ref,
            gpg_verification=repo_data.gpg_verification,
            auto_deploy=repo_data.auto_deploy,
            user_id=current_user.id
        )

        # Schedule initial sync in background
        background_tasks.add_task(
            gitops_service.sync_repository,
            db,
            repository.id,
            current_user.id
        )

        return GitRepositoryResponse.from_orm(repository)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to connect repository: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to connect repository"
        )


@router.get("/repositories", response_model=List[GitRepositoryResponse])
async def list_repositories(
    is_active: Optional[bool] = None,
    auto_deploy: Optional[bool] = None,
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(
        PermissionDependency([Permission.GIT_REPO_READ])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    List connected repositories.

    Security:
    - Requires GIT_REPO_READ permission
    """
    try:
        from sqlalchemy import select, and_

        conditions = []
        if is_active is not None:
            conditions.append(GitRepository.is_active == is_active)
        if auto_deploy is not None:
            conditions.append(GitRepository.auto_deploy == auto_deploy)

        stmt = select(GitRepository)
        if conditions:
            stmt = stmt.where(and_(*conditions))

        stmt = stmt.order_by(GitRepository.created_at.desc())
        stmt = stmt.limit(limit).offset(offset)

        result = await db.execute(stmt)
        repositories = result.scalars().all()

        return [GitRepositoryResponse.from_orm(r) for r in repositories]

    except Exception as e:
        logger.error(f"Failed to list repositories: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list repositories"
        )


@router.get("/repositories/{repository_id}", response_model=GitRepositoryResponse)
async def get_repository(
    repository_id: uuid.UUID,
    current_user: User = Depends(
        PermissionDependency([Permission.GIT_REPO_READ])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Get repository details.

    Security:
    - Requires GIT_REPO_READ permission
    """
    try:
        from sqlalchemy import select

        result = await db.execute(
            select(GitRepository).where(GitRepository.id == repository_id)
        )
        repository = result.scalar_one_or_none()

        if not repository:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Repository not found"
            )

        return GitRepositoryResponse.from_orm(repository)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get repository: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get repository"
        )


@router.put("/repositories/{repository_id}", response_model=GitRepositoryResponse)
async def update_repository(
    repository_id: uuid.UUID,
    repo_update: GitRepositoryUpdate,
    current_user: User = Depends(
        PermissionDependency([Permission.GIT_REPO_UPDATE])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Update repository configuration.

    Security:
    - Requires GIT_REPO_UPDATE permission
    """
    try:
        from sqlalchemy import select

        result = await db.execute(
            select(GitRepository).where(GitRepository.id == repository_id)
        )
        repository = result.scalar_one_or_none()

        if not repository:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Repository not found"
            )

        # Update fields
        update_data = repo_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(repository, field, value)

        await db.commit()
        await db.refresh(repository)

        logger.info(f"Repository updated: {repository.name}")
        return GitRepositoryResponse.from_orm(repository)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update repository: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update repository"
        )


@router.delete("/repositories/{repository_id}")
async def delete_repository(
    repository_id: uuid.UUID,
    current_user: User = Depends(
        PermissionDependency([Permission.GIT_REPO_DELETE])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Delete a repository.

    Security:
    - Requires GIT_REPO_DELETE permission
    - Soft deletes by marking inactive
    """
    try:
        from sqlalchemy import select

        result = await db.execute(
            select(GitRepository).where(GitRepository.id == repository_id)
        )
        repository = result.scalar_one_or_none()

        if not repository:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Repository not found"
            )

        # Soft delete
        repository.is_active = False
        await db.commit()

        # Clean up Vault secrets
        from ...security.vault import VaultClient
        vault = VaultClient()

        if repository.webhook_secret_ref:
            await vault.delete_secret(repository.webhook_secret_ref)
        if repository.ssh_key_ref:
            await vault.delete_secret(repository.ssh_key_ref)

        logger.info(f"Repository deleted: {repository.name}")
        return {"message": "Repository deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete repository: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete repository"
        )


@router.post("/repositories/{repository_id}/sync")
async def sync_repository(
    repository_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(
        PermissionDependency([Permission.GIT_REPO_SYNC])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Sync repository with remote.

    Security:
    - Requires GIT_REPO_SYNC permission
    - Scans for secrets
    - Creates deployment if auto_deploy enabled
    """
    try:
        # Start sync in background
        background_tasks.add_task(
            gitops_service.sync_repository,
            db,
            repository_id,
            current_user.id
        )

        return {
            "message": "Repository sync started",
            "repository_id": str(repository_id)
        }

    except Exception as e:
        logger.error(f"Failed to sync repository: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to sync repository"
        )


@router.post("/webhook/{repository_id}")
async def receive_webhook(
    repository_id: uuid.UUID,
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: Optional[str] = Header(None),
    x_gitlab_token: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db)
):
    """
    Receive webhook from Git provider.

    Security:
    - Validates webhook signature
    - Scans commits for secrets
    - Triggers deployment if configured
    """
    try:
        # Get request body
        body = await request.body()
        payload = json.loads(body)

        # Determine signature based on provider
        signature = x_hub_signature_256 or x_gitlab_token

        # Get event type
        event_type = request.headers.get('X-GitHub-Event', 'push')
        if not event_type:
            event_type = request.headers.get('X-Gitlab-Event', 'push')

        # Verify repository exists
        from sqlalchemy import select
        result = await db.execute(
            select(GitRepository).where(GitRepository.id == repository_id)
        )
        repository = result.scalar_one_or_none()

        if not repository or not repository.is_active:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Repository not found or inactive"
            )

        # Verify signature if configured
        if repository.webhook_secret_ref:
            from ...security.vault import VaultClient
            vault = VaultClient()
            secret_data = await vault.get_secret(repository.webhook_secret_ref)
            webhook_secret = secret_data.get("secret")

            if not _verify_webhook_signature(body, signature, webhook_secret):
                logger.warning(f"Invalid webhook signature for repository {repository_id}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid webhook signature"
                )

        # Process webhook in background
        background_tasks.add_task(
            gitops_service.process_webhook,
            db,
            repository_id,
            payload,
            signature,
            event_type
        )

        return {"message": "Webhook received and queued for processing"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Webhook processing failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webhook processing failed"
        )


@router.get("/webhook-events")
async def list_webhook_events(
    repository_id: Optional[uuid.UUID] = None,
    processed: Optional[bool] = None,
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(
        PermissionDependency([Permission.GIT_REPO_READ])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    List webhook events.

    Security:
    - Requires GIT_REPO_READ permission
    """
    try:
        from sqlalchemy import select, and_

        conditions = []
        if repository_id:
            conditions.append(WebhookEvent.repository_id == repository_id)
        if processed is not None:
            conditions.append(WebhookEvent.processed == processed)

        stmt = select(WebhookEvent)
        if conditions:
            stmt = stmt.where(and_(*conditions))

        stmt = stmt.order_by(WebhookEvent.received_at.desc())
        stmt = stmt.limit(limit).offset(offset)

        result = await db.execute(stmt)
        events = result.scalars().all()

        return [
            {
                "id": str(event.id),
                "repository_id": str(event.repository_id) if event.repository_id else None,
                "event_type": event.event_type,
                "signature_verified": event.signature_verified,
                "processed": event.processed,
                "processing_error": event.processing_error,
                "deployment_id": str(event.deployment_id) if event.deployment_id else None,
                "received_at": event.received_at.isoformat(),
                "processed_at": event.processed_at.isoformat() if event.processed_at else None
            }
            for event in events
        ]

    except Exception as e:
        logger.error(f"Failed to list webhook events: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list webhook events"
        )


@router.post("/repositories/{repository_id}/scan")
async def scan_repository_for_secrets(
    repository_id: uuid.UUID,
    current_user: User = Depends(
        PermissionDependency([Permission.GIT_REPO_READ])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Scan repository for exposed secrets.

    Security:
    - Requires GIT_REPO_READ permission
    - Checks for credentials, API keys, etc.
    """
    try:
        from sqlalchemy import select

        # Get repository
        result = await db.execute(
            select(GitRepository).where(GitRepository.id == repository_id)
        )
        repository = result.scalar_one_or_none()

        if not repository:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Repository not found"
            )

        # Clone repository
        temp_dir = await gitops_service._clone_repository(
            repository.url,
            repository.branch,
            repository.ssh_key_ref
        )

        try:
            # Scan for secrets
            from ...security.secrets_scanner import SecretsScanner
            scanner = SecretsScanner()
            secrets_found = await scanner.scan_directory(temp_dir)

            # Clean up
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

            if secrets_found:
                # Log security event
                from ...db.models import SecurityEvent
                security_event = SecurityEvent(
                    event_type="secrets_detected",
                    severity="high",
                    target_resource=f"repository:{repository_id}",
                    user_id=current_user.id,
                    description=f"Secrets detected in repository {repository.name}",
                    details={"secrets": secrets_found[:10]}  # Limit details
                )
                db.add(security_event)
                await db.commit()

                return {
                    "secrets_found": True,
                    "count": len(secrets_found),
                    "samples": secrets_found[:5],  # Return limited samples
                    "message": "Secrets detected in repository"
                }
            else:
                return {
                    "secrets_found": False,
                    "message": "No secrets detected"
                }

        except Exception as e:
            # Clean up on error
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Secret scanning failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Secret scanning failed"
        )


@router.get("/repositories/{repository_id}/configs")
async def list_repository_configs(
    repository_id: uuid.UUID,
    path: Optional[str] = None,
    current_user: User = Depends(
        PermissionDependency([Permission.GIT_REPO_READ])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    List configuration files in repository.

    Security:
    - Requires GIT_REPO_READ permission
    - Parses and validates configurations
    """
    try:
        from sqlalchemy import select
        from pathlib import Path

        # Get repository
        result = await db.execute(
            select(GitRepository).where(GitRepository.id == repository_id)
        )
        repository = result.scalar_one_or_none()

        if not repository:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Repository not found"
            )

        # Clone repository
        temp_dir = await gitops_service._clone_repository(
            repository.url,
            repository.branch,
            repository.ssh_key_ref
        )

        try:
            # Parse configurations
            configs = await gitops_service._parse_repository_configs(temp_dir)

            # Filter by path if specified
            if path:
                configs = [c for c in configs if path in c.get('source_file', '')]

            # Clean up
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

            return {
                "repository_id": str(repository_id),
                "total_configs": len(configs),
                "configs": [
                    {
                        "file": c.get('source_file'),
                        "type": c.get('type', 'unknown'),
                        "devices": c.get('devices', []),
                        "size": len(json.dumps(c))
                    }
                    for c in configs
                ]
            }

        except Exception as e:
            # Clean up on error
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list configs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list configurations"
        )


@router.post("/repositories/{repository_id}/validate")
async def validate_repository_configs(
    repository_id: uuid.UUID,
    strict_mode: bool = Query(True),
    current_user: User = Depends(
        PermissionDependency([Permission.CONFIG_VALIDATE])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Validate all configurations in repository.

    Security:
    - Requires CONFIG_VALIDATE permission
    - Performs multi-layer validation
    """
    try:
        from sqlalchemy import select

        # Get repository
        result = await db.execute(
            select(GitRepository).where(GitRepository.id == repository_id)
        )
        repository = result.scalar_one_or_none()

        if not repository:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Repository not found"
            )

        # Clone repository
        temp_dir = await gitops_service._clone_repository(
            repository.url,
            repository.branch,
            repository.ssh_key_ref
        )

        try:
            # Parse configurations
            configs = await gitops_service._parse_repository_configs(temp_dir)

            # Validate each configuration
            validation_results = []
            from ...core.validation import config_validator

            for config in configs:
                result = await config_validator.validate_configuration(config)
                validation_results.append({
                    "file": config.get('source_file'),
                    "is_valid": result.is_valid,
                    "score": result.score,
                    "errors": len(result.errors),
                    "warnings": len(result.warnings)
                })

            # Clean up
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

            # Summary
            all_valid = all(r["is_valid"] for r in validation_results)
            avg_score = sum(r["score"] for r in validation_results) / len(validation_results) if validation_results else 0

            return {
                "all_valid": all_valid,
                "average_score": avg_score,
                "total_configs": len(configs),
                "validation_results": validation_results
            }

        except Exception as e:
            # Clean up on error
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Validation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Configuration validation failed"
        )


def _verify_webhook_signature(body: bytes, signature: str, secret: str) -> bool:
    """Verify webhook signature"""

    if not signature or not secret:
        return False

    # GitHub signature format: sha256=<signature>
    if signature.startswith("sha256="):
        expected = "sha256=" + hmac.new(
            secret.encode(),
            body,
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(signature, expected)

    # GitLab signature format
    expected = hmac.new(
        secret.encode(),
        body,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected)