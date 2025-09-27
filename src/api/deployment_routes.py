from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Dict, Any, List
from pydantic import BaseModel

from ..db.session import get_db
from ..auth.dependencies import get_current_user, require_permission
from ..db.models import User
from ..core.deployment import DeploymentService

router = APIRouter()

class DeploymentRequest(BaseModel):
    name: str
    configs: List[Dict[str, Any]]
    strategy: str = "rolling"
    requires_approval: bool = True

@router.post("/")
async def create_deployment(
    request: DeploymentRequest,
    current_user: User = Depends(require_permission("deployment", "create")),
    db: Session = Depends(get_db)
):
    deployment_service = DeploymentService(db)
    return await deployment_service.create_deployment(
        name=request.name,
        configs=request.configs,
        user_id=str(current_user.id),
        strategy=request.strategy,
        requires_approval=request.requires_approval
    )

@router.get("/{deployment_id}")
async def get_deployment(
    deployment_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    deployment_service = DeploymentService(db)
    return await deployment_service.get_deployment_status(deployment_id)

@router.post("/{deployment_id}/approve")
async def approve_deployment(
    deployment_id: str,
    current_user: User = Depends(require_permission("deployment", "approve")),
    db: Session = Depends(get_db)
):
    deployment_service = DeploymentService(db)
    approved = await deployment_service.approve_deployment(
        deployment_id,
        str(current_user.id)
    )
    return {"approved": approved}

@router.post("/{deployment_id}/rollback")
async def rollback_deployment(
    deployment_id: str,
    reason: str = "Manual rollback requested",
    current_user: User = Depends(require_permission("deployment", "rollback")),
    db: Session = Depends(get_db)
):
    deployment_service = DeploymentService(db)
    return await deployment_service.rollback_deployment(
        deployment_id,
        str(current_user.id),
        reason
    )