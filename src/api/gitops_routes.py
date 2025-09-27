from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

from ..db.session import get_db
from ..auth.dependencies import get_current_user, require_permission
from ..db.models import User
from ..gitops.git_service import GitOpsService
from ..gitops.webhook_handler import WebhookHandler

router = APIRouter()

class RepositoryConnect(BaseModel):
    name: str
    url: str
    branch: str = "main"
    auto_deploy: bool = False

@router.post("/repositories")
async def connect_repository(
    repo: RepositoryConnect,
    current_user: User = Depends(require_permission("gitops", "manage")),
    db: Session = Depends(get_db)
):
    git_service = GitOpsService(db)
    repository = await git_service.connect_repository(
        name=repo.name,
        url=repo.url,
        branch=repo.branch,
        auto_deploy=repo.auto_deploy
    )
    return {
        "id": str(repository.id),
        "name": repository.name,
        "webhook_secret": "Generated and stored in Vault"
    }

@router.post("/repositories/{repo_name}/sync")
async def sync_repository(
    repo_name: str,
    current_user: User = Depends(require_permission("gitops", "sync")),
    db: Session = Depends(get_db)
):
    git_service = GitOpsService(db)
    return await git_service.sync_repository(repo_name)

@router.post("/webhook/{repo_name}")
async def process_webhook(
    repo_name: str,
    request: Request,
    db: Session = Depends(get_db)
):
    webhook_handler = WebhookHandler(db)

    payload = await request.json()
    signature = request.headers.get("X-Hub-Signature-256") or request.headers.get("X-Gitlab-Token")
    event_type = request.headers.get("X-GitHub-Event") or request.headers.get("X-Gitlab-Event")

    return await webhook_handler.process_webhook(
        repo_name=repo_name,
        event_type=event_type,
        payload=payload,
        signature=signature
    )

@router.get("/repositories/{repo_name}/configs")
async def get_repository_configs(
    repo_name: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    git_service = GitOpsService(db)
    return await git_service.get_configs_from_repo(repo_name)