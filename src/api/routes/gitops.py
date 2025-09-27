from typing import Dict, List, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
import structlog

from ...gitops.git_service import GitService
from ...gitops.webhook_handler import WebhookHandler
from ...security.audit import AuditLogger
from .auth import get_current_user

logger = structlog.get_logger()
router = APIRouter()

git_service = GitService()
webhook_handler = WebhookHandler()
audit = AuditLogger()

class GitRepositoryRequest(BaseModel):
    url: str
    branch: str = "main"
    ssh_key_id: Optional[str] = None
    webhook_secret: Optional[str] = None

@router.post("/repositories")
async def connect_repository(
    repo_request: GitRepositoryRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Connect a Git repository for GitOps"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            'ip_address': request.client.host if request.client else 'unknown'
        }

        repo_id = await git_service.connect_repository(
            url=repo_request.url,
            branch=repo_request.branch,
            ssh_key_id=repo_request.ssh_key_id,
            webhook_secret=repo_request.webhook_secret,
            user_context=user_context
        )

        return {'repository_id': repo_id, 'status': 'connected'}

    except Exception as e:
        logger.error(f"Repository connection error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to connect repository"
        )

@router.post("/webhook")
async def process_webhook(request: Request):
    """Process incoming Git webhook"""
    try:
        payload = await request.json()
        headers = dict(request.headers)

        result = await webhook_handler.handle_webhook(payload, headers)

        return {'processed': True, 'result': result}

    except Exception as e:
        logger.error(f"Webhook processing error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process webhook"
        )

@router.get("/repositories")
async def list_repositories(current_user: Dict[str, Any] = Depends(get_current_user)):
    """List connected repositories"""
    try:
        repositories = await git_service.list_repositories()
        return {'repositories': repositories}

    except Exception as e:
        logger.error(f"Repository list error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list repositories"
        )