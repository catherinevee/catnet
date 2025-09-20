"""
GitOps Service Endpoints - Webhook handlers and configuration management
"""
from fastapi import APIRouter, Request, HTTPException, Depends, Header, status
from typing import Dict, Optional, List, Any
from datetime import datetime
import hmac
import hashlib
import json
from pydantic import BaseModel

from ..security.auth import get_current_user
from ..security.vault import VaultClient
from ..security.audit import AuditLogger
from ..gitops.processor import GitOpsProcessor
from ..db.models import User, GitRepository, Deployment
from ..db.database import get_db
from ..core.logging import get_logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = get_logger(__name__)
router = APIRouter(prefix="/git", tags=["gitops"])



class WebhookPayload(BaseModel):
    """Generic webhook payload"""

    ref: str
    repository: Dict[str, Any]
    commits: List[Dict[str, Any]]
    pusher: Dict[str, str]
    sender: Dict[str, Any]



class ConfigDiff(BaseModel):
    """Configuration diff response"""

    commit_sha: str
    timestamp: datetime
    author: str
    message: str
    files_changed: List[str]
    additions: int
    deletions: int
    diff_content: str



def verify_github_signature(
    payload: bytes,
    signature: str,
    secret: str
) -> bool:
    """Verify GitHub webhook signature"""
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)



def verify_gitlab_signature(payload: bytes, token: str, secret: str) -> bool:
    """Verify GitLab webhook token"""
    return token == secret


@router.post("/webhook/github")
async def handle_github_webhook(
    request: Request,
    x_github_event: str = Header(None),
    x_hub_signature_256: str = Header(None),
    db: AsyncSession = Depends(get_db),
):
    """
    Handle GitHub webhook events

    Processes:
    - Push events
    - Pull request events
    - Release events

    Security:
    - Validates webhook signature
    - Scans for secrets
    - Triggers validation pipeline
    """
    logger.info(f"GitHub webhook received: {x_github_event}")

    try:
        # Get raw payload
        payload = await request.body()

        # Parse JSON
        data = json.loads(payload)
        repo_url = data.get("repository", {}).get("clone_url", "")

        # Get repository configuration from database
        result = await db.execute(
            select(GitRepository).where(GitRepository.url == repo_url)
        )
        repo = result.scalar_one_or_none()

        if not repo:
            logger.warning(f"Repository not configured: {repo_url}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Repository not configured",
            )

        # Get webhook secret from Vault
        vault = VaultClient()
        if repo.webhook_secret_ref:
            secret_data = await vault.get_secret(repo.webhook_secret_ref)
            webhook_secret = secret_data.get("webhook_secret", "")
        else:
            logger.warning(f"No webhook secret configured for {repo_url}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Webhook not configured",
            )

        # Verify signature
        if x_hub_signature_256:
            if not verify_github_signature(
                payload, x_hub_signature_256, webhook_secret
            ):
                logger.error(f"Invalid GitHub signature for {repo_url}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Invalid signature",
                )

        # Process based on event type
        if x_github_event == "push":
            # Process push event
            processor = GitOpsProcessor()
            result = await processor.process_push_event(data, repo)

            # Audit log
            audit = AuditLogger()
            await audit.log_event(
                event_type="github_webhook_processed",
                details={
                    "event": x_github_event,
                    "repository": repo_url,
                    "ref": data.get("ref"),
                    "commits": len(data.get("commits", [])),
                    "result": result,
                },
            )

            return {
                "status": "processed",
                "event": x_github_event,
                "repository": repo_url,
                "result": result,
            }

        elif x_github_event == "pull_request":
            # Process pull request event
            processor = GitOpsProcessor()
            result = await processor.process_pr_event(data, repo)

            return {
                "status": "processed",
                "event": x_github_event,
                "repository": repo_url,
                "result": result,
            }

        else:
            return {
                "status": "ignored",
                "event": x_github_event,
                "reason": "Event type not processed",
            }

    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload",
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"GitHub webhook processing failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webhook processing failed",
        )


@router.post("/webhook/gitlab")
async def handle_gitlab_webhook(
    request: Request,
    x_gitlab_event: str = Header(None),
    x_gitlab_token: str = Header(None),
    db: AsyncSession = Depends(get_db),
):
    """
    Handle GitLab webhook events

    Processes:
    - Push events
    - Merge request events
    - Tag push events

    Security:
    - Validates webhook token
    - Scans for secrets
    - Triggers validation pipeline
    """
    logger.info(f"GitLab webhook received: {x_gitlab_event}")

    try:
        # Get raw payload
        payload = await request.body()

        # Parse JSON
        data = json.loads(payload)
        repo_url = data.get("project", {}).get("git_http_url", "")

        # Get repository configuration from database
        result = await db.execute(
            select(GitRepository).where(GitRepository.url == repo_url)
        )
        repo = result.scalar_one_or_none()

        if not repo:
            logger.warning(f"Repository not configured: {repo_url}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Repository not configured",
            )

        # Get webhook secret from Vault
        vault = VaultClient()
        if repo.webhook_secret_ref:
            secret_data = await vault.get_secret(repo.webhook_secret_ref)
            webhook_secret = secret_data.get("webhook_secret", "")
        else:
            logger.warning(f"No webhook secret configured for {repo_url}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Webhook not configured",
            )

        # Verify token
        if x_gitlab_token:
                        if not verify_gitlab_signature(
                payload,
                x_gitlab_token,
                webhook_secret
            ):
                logger.error(f"Invalid GitLab token for {repo_url}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Invalid token",
                )

        # Process based on event type
        if x_gitlab_event == "Push Hook":
            # Process push event
            processor = GitOpsProcessor()
            result = await processor.process_push_event(data, repo)

            # Audit log
            audit = AuditLogger()
            await audit.log_event(
                event_type="gitlab_webhook_processed",
                details={
                    "event": x_gitlab_event,
                    "repository": repo_url,
                    "ref": data.get("ref"),
                    "commits": len(data.get("commits", [])),
                    "result": result,
                },
            )

            return {
                "status": "processed",
                "event": x_gitlab_event,
                "repository": repo_url,
                "result": result,
            }

        elif x_gitlab_event == "Merge Request Hook":
            # Process merge request event
            processor = GitOpsProcessor()
            result = await processor.process_mr_event(data, repo)

            return {
                "status": "processed",
                "event": x_gitlab_event,
                "repository": repo_url,
                "result": result,
            }

        else:
            return {
                "status": "ignored",
                "event": x_gitlab_event,
                "reason": "Event type not processed",
            }

    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload",
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"GitLab webhook processing failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webhook processing failed",
        )


@router.get("/diff/{commit_sha}", response_model=ConfigDiff)
async def get_configuration_diff(
    commit_sha: str,
    repository_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get configuration diff for a specific commit

    Shows:
    - Files changed
    - Lines added/removed
    - Full diff content
    - Commit metadata
    """
    logger.info(f"Configuration diff requested for commit {commit_sha}")

    try:
        import git

        # Get repository
        if repository_id:
            result = await db.execute(
                select(GitRepository).where(GitRepository.id == repository_id)
            )
            repo_config = result.scalar_one_or_none()
        else:
            # Try to find repository by commit
            result = await db.execute(
                select(Deployment).where(Deployment.git_commit == commit_sha)
            )
            deployment = result.scalar_one_or_none()
            if deployment and deployment.git_repository_id:
                result = await db.execute(
                    select(GitRepository).where(
                        GitRepository.id == deployment.git_repository_id
                    )
                )
                repo_config = result.scalar_one_or_none()
            else:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Repository not found for commit",
                )

        if not repo_config:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Repository not configured",
            )

        # Clone/pull repository
        processor = GitOpsProcessor()
        repo_path = await processor.sync_repository(repo_config)

        # Get diff using GitPython
        repo = git.Repo(repo_path)
        commit = repo.commit(commit_sha)

        # Get parent commit for diff
        if commit.parents:
            parent = commit.parents[0]
            diff_index = parent.diff(commit)
        else:
            # First commit
            diff_index = commit.diff(git.NULL_TREE)

        # Collect diff information
        files_changed = []
        additions = 0
        deletions = 0
        diff_content = ""

        for diff_item in diff_index:
            files_changed.append(diff_item.a_path or diff_item.b_path)

            # Count additions and deletions
            if diff_item.diff:
                diff_text = diff_item.diff.decode("utf-8", errors="ignore")
                diff_content += f"\n--- {diff_item.a_path}\n"
                diff_content += f"+++ {diff_item.b_path}\n"
                diff_content += diff_text

                for line in diff_text.split("\n"):
                    if line.startswith("+") and not line.startswith("+++"):
                        additions += 1
                    elif line.startswith("-") and not line.startswith("---"):
                        deletions += 1

        # Audit log
        audit = AuditLogger()
        await audit.log_event(
            event_type="configuration_diff_viewed",
            details={
                "user_id": str(current_user.id),
                "commit_sha": commit_sha,
                "repository_id": str(repo_config.id),
                "files_changed": len(files_changed),
            },
        )

        return ConfigDiff(
            commit_sha=str(commit.hexsha),
            timestamp=datetime.fromtimestamp(commit.committed_date),
            author=commit.author.name,
            message=commit.message,
            files_changed=files_changed,
            additions=additions,
            deletions=deletions,
            diff_content=diff_content[:10000],  # Limit diff size
        )

    except git.BadName:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Commit not found",
        )
    except Exception as e:
        logger.error(f"Failed to get configuration diff: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve diff",
        )
