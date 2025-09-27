"""
Deployments Router
Handles configuration deployment, rollback, validation, and approval workflows
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from uuid import UUID, uuid4
import asyncio
import hashlib
import json
from enum import Enum

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Query, Body
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_, or_, func, distinct
from pydantic import BaseModel, Field, validator
import yaml

from src.db.models import (
    Deployment, DeploymentStage, DeploymentDevice, DeploymentApproval,
    ConfigurationValidation, Device, User, DeviceBackup, AuditLog
)
from src.core.config import settings
from src.core.dependencies import (
    get_db,
    get_current_user,
    require_permission,
    get_redis,
    get_vault,
    get_audit_logger,
    get_message_queue
)
from src.core.exceptions import (
    ValidationError,
    DeploymentError,
    ApprovalRequiredError,
    RollbackError
)
from src.deployments.executor import DeploymentExecutor
from src.deployments.strategies import CanaryStrategy, RollingStrategy, BlueGreenStrategy
from src.deployments.validator import ConfigValidator
from src.security.audit import AuditLogger
from src.security.encryption import EncryptionManager
from src.gitops.workflow import GitOpsWorkflow

router = APIRouter(prefix="/api/v1/deployments", tags=["deployments"])


class DeploymentStrategy(str, Enum):
    CANARY = "canary"
    ROLLING = "rolling"
    BLUE_GREEN = "blue_green"
    IMMEDIATE = "immediate"


class DeploymentCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str]
    config_source: str = Field(..., regex="^(git|upload|manual)$")
    git_repository_id: Optional[UUID]
    git_commit_hash: Optional[str]
    config_content: Optional[str]
    target_devices: List[UUID] = Field(..., min_items=1)
    strategy: DeploymentStrategy = DeploymentStrategy.CANARY
    strategy_config: Optional[Dict[str, Any]]
    validation_required: bool = True
    approval_required: bool = True
    approvers: Optional[List[UUID]]
    scheduled_at: Optional[datetime]
    rollback_on_failure: bool = True
    dry_run: bool = False
    tags: Optional[List[str]]

    @validator('strategy_config')
    def validate_strategy_config(cls, v, values):
        if not v:
            return v

        strategy = values.get('strategy')
        if strategy == DeploymentStrategy.CANARY:
            required_keys = ['stages']
            if not all(k in v for k in required_keys):
                raise ValueError(f"Canary strategy requires: {required_keys}")
        elif strategy == DeploymentStrategy.ROLLING:
            required_keys = ['batch_size', 'wait_between_batches']
            if not all(k in v for k in required_keys):
                raise ValueError(f"Rolling strategy requires: {required_keys}")
        return v


class DeploymentResponse(BaseModel):
    id: UUID
    name: str
    description: Optional[str]
    status: str
    strategy: str
    created_by: UUID
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    success_count: int
    failure_count: int
    rollback_count: int
    approval_status: Optional[str]
    approval_count: int
    approvals_required: int
    validation_status: Optional[str]
    config_hash: str
    dry_run: bool


class DeploymentApprovalRequest(BaseModel):
    approval_type: str = Field(default="approve", regex="^(approve|reject)$")
    comment: Optional[str]
    conditions: Optional[Dict[str, Any]]


class DeploymentRollbackRequest(BaseModel):
    reason: str = Field(..., min_length=1)
    rollback_to: Optional[UUID] = Field(None, description="Specific backup to rollback to")
    force: bool = False


class DeploymentStatusResponse(BaseModel):
    deployment_id: UUID
    status: str
    progress_percentage: float
    current_stage: Optional[str]
    devices_total: int
    devices_completed: int
    devices_failed: int
    devices_pending: int
    errors: List[Dict[str, Any]]
    warnings: List[Dict[str, Any]]
    estimated_completion: Optional[datetime]
    can_rollback: bool
    can_cancel: bool


class ValidationResultResponse(BaseModel):
    deployment_id: UUID
    validation_id: UUID
    status: str
    passed: bool
    errors: List[Dict[str, Any]]
    warnings: List[Dict[str, Any]]
    suggestions: List[str]
    validated_at: datetime
    validator_version: str


@router.get("", response_model=List[DeploymentResponse])
async def list_deployments(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    status: Optional[str] = None,
    strategy: Optional[str] = None,
    created_after: Optional[datetime] = None,
    created_before: Optional[datetime] = None,
    tags: Optional[List[str]] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit: AuditLogger = Depends(get_audit_logger)
) -> List[DeploymentResponse]:
    """
    List deployments with filtering and pagination
    """

    await require_permission(current_user, "deployments.read")

    query = select(Deployment)

    # Apply filters
    if status:
        query = query.where(Deployment.status == status)
    if strategy:
        query = query.where(Deployment.strategy == strategy)
    if created_after:
        query = query.where(Deployment.created_at >= created_after)
    if created_before:
        query = query.where(Deployment.created_at <= created_before)
    if tags:
        query = query.where(Deployment.tags.contains(tags))

    query = query.order_by(Deployment.created_at.desc())
    query = query.offset(skip).limit(limit)

    result = await db.execute(query)
    deployments = result.scalars().all()

    # Get approval counts
    deployment_responses = []
    for deployment in deployments:
        # Count approvals
        approval_result = await db.execute(
            select(func.count(DeploymentApproval.id))
            .where(
                and_(
                    DeploymentApproval.deployment_id == deployment.id,
                    DeploymentApproval.approval_type == "approve"
                )
            )
        )
        approval_count = approval_result.scalar()

        deployment_responses.append(DeploymentResponse(
            id=deployment.id,
            name=deployment.name,
            description=deployment.description,
            status=deployment.status,
            strategy=deployment.strategy,
            created_by=deployment.created_by,
            created_at=deployment.created_at,
            started_at=deployment.started_at,
            completed_at=deployment.completed_at,
            success_count=deployment.success_count or 0,
            failure_count=deployment.failure_count or 0,
            rollback_count=deployment.rollback_count or 0,
            approval_status=deployment.approval_status,
            approval_count=approval_count or 0,
            approvals_required=deployment.approvals_required or 0,
            validation_status=deployment.validation_status,
            config_hash=deployment.config_hash,
            dry_run=deployment.dry_run
        ))

    await audit.log_event(
        user_id=current_user.id,
        action="list_deployments",
        resource_type="deployment",
        details={
            "count": len(deployments),
            "filters": {
                "status": status,
                "strategy": strategy,
                "tags": tags
            }
        }
    )

    return deployment_responses


@router.post("", response_model=DeploymentResponse)
async def create_deployment(
    request: DeploymentCreateRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis),
    vault = Depends(get_vault),
    audit: AuditLogger = Depends(get_audit_logger),
    message_queue = Depends(get_message_queue)
) -> DeploymentResponse:
    """
    Create a new deployment with validation and approval workflow
    """

    await require_permission(current_user, "deployments.create")

    # Validate target devices exist and are reachable
    devices = []
    for device_id in request.target_devices:
        device = await db.get(Device, device_id)
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Device {device_id} not found"
            )
        if device.status == "offline" and not request.dry_run:
            raise HTTPException(
                status_code=status.HTTP_412_PRECONDITION_FAILED,
                detail=f"Device {device.hostname} is offline"
            )
        devices.append(device)

    # Get configuration content
    config_content = ""
    if request.config_source == "git":
        if not request.git_repository_id or not request.git_commit_hash:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Git repository and commit hash required for git source"
            )

        # Fetch config from git
        gitops = GitOpsWorkflow(db, redis, vault, audit)
        config_content = await gitops.fetch_config(
            repository_id=request.git_repository_id,
            commit_hash=request.git_commit_hash
        )

    elif request.config_source == "upload" or request.config_source == "manual":
        if not request.config_content:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Config content required for upload/manual source"
            )
        config_content = request.config_content

    # Calculate config hash
    config_hash = hashlib.sha256(config_content.encode()).hexdigest()

    # Check for duplicate deployment
    existing = await db.execute(
        select(Deployment)
        .where(
            and_(
                Deployment.config_hash == config_hash,
                Deployment.status.in_(["pending", "running"])
            )
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Deployment with same configuration already in progress"
        )

    # Encrypt configuration
    encryption_manager = EncryptionManager(vault)
    encrypted_config = await encryption_manager.encrypt(config_content.encode())

    # Create deployment
    deployment = Deployment(
        id=uuid4(),
        name=request.name,
        description=request.description,
        config_source=request.config_source,
        config_encrypted=encrypted_config,
        config_hash=config_hash,
        strategy=request.strategy.value,
        strategy_config=request.strategy_config or {},
        validation_required=request.validation_required,
        approval_required=request.approval_required,
        approvals_required=len(request.approvers) if request.approvers else 1,
        scheduled_at=request.scheduled_at,
        rollback_on_failure=request.rollback_on_failure,
        dry_run=request.dry_run,
        tags=request.tags,
        status="pending",
        created_by=current_user.id
    )

    if request.git_repository_id:
        deployment.git_repository_id = request.git_repository_id
        deployment.git_commit_hash = request.git_commit_hash

    db.add(deployment)

    # Add deployment devices
    for device in devices:
        deployment_device = DeploymentDevice(
            deployment_id=deployment.id,
            device_id=device.id,
            status="pending",
            order=devices.index(device)
        )
        db.add(deployment_device)

    # Add approvers
    if request.approvers:
        for approver_id in request.approvers:
            # Verify approver exists and has permission
            approver = await db.get(User, approver_id)
            if approver:
                # Store approver requirement
                deployment.approvers = request.approvers

    await db.commit()
    await db.refresh(deployment)

    # Schedule validation if required
    if request.validation_required:
        background_tasks.add_task(
            validate_deployment,
            deployment_id=deployment.id,
            config_content=config_content,
            devices=devices,
            db=db,
            redis=redis,
            audit=audit
        )

    # Send approval requests if required
    if request.approval_required and request.approvers:
        await send_approval_requests(
            deployment=deployment,
            approvers=request.approvers,
            message_queue=message_queue
        )

    # Schedule deployment if time specified
    if request.scheduled_at and request.scheduled_at > datetime.utcnow():
        await schedule_deployment(
            deployment_id=deployment.id,
            scheduled_at=request.scheduled_at,
            redis=redis
        )

    await audit.log_event(
        user_id=current_user.id,
        action="deployment_created",
        resource_type="deployment",
        resource_id=str(deployment.id),
        details={
            "name": deployment.name,
            "strategy": deployment.strategy,
            "device_count": len(devices),
            "dry_run": deployment.dry_run
        }
    )

    return DeploymentResponse(
        id=deployment.id,
        name=deployment.name,
        description=deployment.description,
        status=deployment.status,
        strategy=deployment.strategy,
        created_by=deployment.created_by,
        created_at=deployment.created_at,
        started_at=deployment.started_at,
        completed_at=deployment.completed_at,
        success_count=0,
        failure_count=0,
        rollback_count=0,
        approval_status=deployment.approval_status,
        approval_count=0,
        approvals_required=deployment.approvals_required,
        validation_status=deployment.validation_status,
        config_hash=deployment.config_hash,
        dry_run=deployment.dry_run
    )


@router.get("/{deployment_id}/status", response_model=DeploymentStatusResponse)
async def get_deployment_status(
    deployment_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis),
    audit: AuditLogger = Depends(get_audit_logger)
) -> DeploymentStatusResponse:
    """
    Get detailed deployment status and progress
    """

    await require_permission(current_user, "deployments.read")

    # Get deployment
    deployment = await db.get(Deployment, deployment_id)
    if not deployment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deployment not found"
        )

    # Get deployment devices
    result = await db.execute(
        select(DeploymentDevice)
        .where(DeploymentDevice.deployment_id == deployment_id)
    )
    deployment_devices = result.scalars().all()

    # Calculate statistics
    devices_total = len(deployment_devices)
    devices_completed = sum(1 for d in deployment_devices if d.status == "completed")
    devices_failed = sum(1 for d in deployment_devices if d.status == "failed")
    devices_pending = sum(1 for d in deployment_devices if d.status == "pending")

    progress_percentage = (devices_completed / devices_total * 100) if devices_total > 0 else 0

    # Get current stage if using staged deployment
    current_stage = None
    if deployment.strategy in ["canary", "rolling"]:
        stage_result = await db.execute(
            select(DeploymentStage)
            .where(
                and_(
                    DeploymentStage.deployment_id == deployment_id,
                    DeploymentStage.status == "running"
                )
            )
            .order_by(DeploymentStage.stage_number.desc())
            .limit(1)
        )
        current_stage_obj = stage_result.scalar_one_or_none()
        if current_stage_obj:
            current_stage = f"Stage {current_stage_obj.stage_number}: {current_stage_obj.name}"

    # Collect errors and warnings
    errors = []
    warnings = []

    for device in deployment_devices:
        if device.error:
            errors.append({
                "device_id": str(device.device_id),
                "error": device.error,
                "timestamp": device.updated_at.isoformat()
            })

    # Check if deployment can be rolled back
    can_rollback = (
        deployment.status in ["running", "failed", "completed"] and
        deployment.rollback_on_failure
    )

    # Check if deployment can be cancelled
    can_cancel = deployment.status in ["pending", "running", "scheduled"]

    # Estimate completion time
    estimated_completion = None
    if deployment.status == "running" and deployment.started_at:
        if devices_completed > 0:
            elapsed_time = (datetime.utcnow() - deployment.started_at).total_seconds()
            time_per_device = elapsed_time / devices_completed
            remaining_devices = devices_total - devices_completed
            estimated_seconds = time_per_device * remaining_devices
            estimated_completion = datetime.utcnow() + timedelta(seconds=estimated_seconds)

    # Get real-time status from Redis if available
    redis_status = await redis.get(f"deployment:{deployment_id}:status")
    if redis_status:
        redis_data = json.loads(redis_status)
        warnings.extend(redis_data.get("warnings", []))

    return DeploymentStatusResponse(
        deployment_id=deployment_id,
        status=deployment.status,
        progress_percentage=progress_percentage,
        current_stage=current_stage,
        devices_total=devices_total,
        devices_completed=devices_completed,
        devices_failed=devices_failed,
        devices_pending=devices_pending,
        errors=errors,
        warnings=warnings,
        estimated_completion=estimated_completion,
        can_rollback=can_rollback,
        can_cancel=can_cancel
    )


@router.post("/{deployment_id}/approve")
async def approve_deployment(
    deployment_id: UUID,
    request: DeploymentApprovalRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis),
    audit: AuditLogger = Depends(get_audit_logger),
    message_queue = Depends(get_message_queue)
) -> Dict[str, Any]:
    """
    Approve or reject a deployment
    """

    await require_permission(current_user, "deployments.approve")

    # Get deployment
    deployment = await db.get(Deployment, deployment_id)
    if not deployment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deployment not found"
        )

    # Check if deployment requires approval
    if not deployment.approval_required:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Deployment does not require approval"
        )

    # Check if already approved/rejected by this user
    existing_approval = await db.execute(
        select(DeploymentApproval)
        .where(
            and_(
                DeploymentApproval.deployment_id == deployment_id,
                DeploymentApproval.approver_id == current_user.id
            )
        )
    )
    if existing_approval.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You have already provided approval for this deployment"
        )

    # Create approval record
    approval = DeploymentApproval(
        deployment_id=deployment_id,
        approver_id=current_user.id,
        approval_type=request.approval_type,
        comment=request.comment,
        conditions=request.conditions
    )
    db.add(approval)

    # Count total approvals
    approval_result = await db.execute(
        select(func.count(DeploymentApproval.id))
        .where(
            and_(
                DeploymentApproval.deployment_id == deployment_id,
                DeploymentApproval.approval_type == "approve"
            )
        )
    )
    approval_count = approval_result.scalar() + (1 if request.approval_type == "approve" else 0)

    # Check if enough approvals
    if request.approval_type == "approve":
        if approval_count >= deployment.approvals_required:
            deployment.approval_status = "approved"
            deployment.status = "approved"

            # Trigger deployment if validation also passed
            if deployment.validation_status == "passed" or not deployment.validation_required:
                background_tasks.add_task(
                    execute_deployment,
                    deployment_id=deployment_id,
                    db=db,
                    redis=redis,
                    vault=vault,
                    audit=audit,
                    message_queue=message_queue
                )
        else:
            deployment.approval_status = "partial"

    elif request.approval_type == "reject":
        deployment.approval_status = "rejected"
        deployment.status = "rejected"

    await db.commit()

    await audit.log_event(
        user_id=current_user.id,
        action=f"deployment_{request.approval_type}d",
        resource_type="deployment",
        resource_id=str(deployment_id),
        details={
            "approval_type": request.approval_type,
            "comment": request.comment,
            "approval_count": approval_count,
            "required": deployment.approvals_required
        }
    )

    return {
        "deployment_id": str(deployment_id),
        "approval_type": request.approval_type,
        "approval_count": approval_count,
        "approvals_required": deployment.approvals_required,
        "status": deployment.approval_status,
        "message": f"Deployment {request.approval_type}d successfully"
    }


@router.post("/{deployment_id}/rollback")
async def rollback_deployment(
    deployment_id: UUID,
    request: DeploymentRollbackRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis),
    vault = Depends(get_vault),
    audit: AuditLogger = Depends(get_audit_logger)
) -> Dict[str, Any]:
    """
    Rollback a deployment to previous configuration
    """

    await require_permission(current_user, "deployments.rollback")

    # Get deployment
    deployment = await db.get(Deployment, deployment_id)
    if not deployment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deployment not found"
        )

    # Check if deployment can be rolled back
    if not deployment.rollback_on_failure and not request.force:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Deployment rollback is disabled"
        )

    if deployment.status not in ["running", "failed", "completed"]:
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail=f"Cannot rollback deployment in {deployment.status} status"
        )

    # Get deployment devices
    result = await db.execute(
        select(DeploymentDevice)
        .where(
            and_(
                DeploymentDevice.deployment_id == deployment_id,
                DeploymentDevice.status.in_(["completed", "failed"])
            )
        )
    )
    devices_to_rollback = result.scalars().all()

    if not devices_to_rollback:
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail="No devices to rollback"
        )

    # Update deployment status
    deployment.status = "rolling_back"
    deployment.rollback_count = (deployment.rollback_count or 0) + 1
    deployment.rollback_reason = request.reason
    deployment.rollback_by = current_user.id
    deployment.rollback_at = datetime.utcnow()

    await db.commit()

    # Schedule rollback task
    background_tasks.add_task(
        execute_rollback,
        deployment_id=deployment_id,
        devices_to_rollback=[d.device_id for d in devices_to_rollback],
        rollback_to=request.rollback_to,
        user_id=current_user.id,
        db=db,
        redis=redis,
        vault=vault,
        audit=audit
    )

    await audit.log_event(
        user_id=current_user.id,
        action="deployment_rollback_initiated",
        resource_type="deployment",
        resource_id=str(deployment_id),
        details={
            "reason": request.reason,
            "device_count": len(devices_to_rollback),
            "force": request.force
        }
    )

    return {
        "deployment_id": str(deployment_id),
        "status": "rolling_back",
        "devices_affected": len(devices_to_rollback),
        "message": "Rollback initiated successfully"
    }


@router.post("/{deployment_id}/cancel")
async def cancel_deployment(
    deployment_id: UUID,
    reason: str = Body(..., min_length=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis),
    audit: AuditLogger = Depends(get_audit_logger)
) -> Dict[str, Any]:
    """
    Cancel a pending or running deployment
    """

    await require_permission(current_user, "deployments.cancel")

    # Get deployment
    deployment = await db.get(Deployment, deployment_id)
    if not deployment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deployment not found"
        )

    # Check if deployment can be cancelled
    if deployment.status not in ["pending", "running", "scheduled"]:
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail=f"Cannot cancel deployment in {deployment.status} status"
        )

    # Update deployment status
    deployment.status = "cancelled"
    deployment.cancelled_by = current_user.id
    deployment.cancelled_at = datetime.utcnow()
    deployment.cancellation_reason = reason

    # Update all pending devices to cancelled
    await db.execute(
        update(DeploymentDevice)
        .where(
            and_(
                DeploymentDevice.deployment_id == deployment_id,
                DeploymentDevice.status == "pending"
            )
        )
        .values(status="cancelled", updated_at=datetime.utcnow())
    )

    # Clear scheduled task if any
    await redis.delete(f"scheduled:{deployment_id}")

    # Send cancellation signal to running tasks
    await redis.set(
        f"deployment:{deployment_id}:cancel",
        json.dumps({
            "cancelled_by": str(current_user.id),
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat()
        }),
        ex=3600
    )

    await db.commit()

    await audit.log_event(
        user_id=current_user.id,
        action="deployment_cancelled",
        resource_type="deployment",
        resource_id=str(deployment_id),
        details={"reason": reason}
    )

    return {
        "deployment_id": str(deployment_id),
        "status": "cancelled",
        "message": "Deployment cancelled successfully"
    }


@router.get("/{deployment_id}/validation", response_model=ValidationResultResponse)
async def get_deployment_validation(
    deployment_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit: AuditLogger = Depends(get_audit_logger)
) -> ValidationResultResponse:
    """
    Get deployment validation results
    """

    await require_permission(current_user, "deployments.read")

    # Get deployment
    deployment = await db.get(Deployment, deployment_id)
    if not deployment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deployment not found"
        )

    # Get validation record
    result = await db.execute(
        select(ConfigurationValidation)
        .where(ConfigurationValidation.deployment_id == deployment_id)
        .order_by(ConfigurationValidation.created_at.desc())
        .limit(1)
    )
    validation = result.scalar_one_or_none()

    if not validation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No validation found for this deployment"
        )

    return ValidationResultResponse(
        deployment_id=deployment_id,
        validation_id=validation.id,
        status=validation.status,
        passed=validation.passed,
        errors=validation.errors or [],
        warnings=validation.warnings or [],
        suggestions=validation.suggestions or [],
        validated_at=validation.created_at,
        validator_version=validation.validator_version or "1.0.0"
    )


@router.post("/{deployment_id}/validate")
async def validate_deployment_config(
    deployment_id: UUID,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis),
    vault = Depends(get_vault),
    audit: AuditLogger = Depends(get_audit_logger)
) -> Dict[str, Any]:
    """
    Trigger validation for deployment configuration
    """

    await require_permission(current_user, "deployments.validate")

    # Get deployment
    deployment = await db.get(Deployment, deployment_id)
    if not deployment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deployment not found"
        )

    # Get deployment devices
    result = await db.execute(
        select(DeploymentDevice.device_id)
        .where(DeploymentDevice.deployment_id == deployment_id)
    )
    device_ids = [row[0] for row in result.all()]

    devices = []
    for device_id in device_ids:
        device = await db.get(Device, device_id)
        if device:
            devices.append(device)

    # Decrypt configuration
    encryption_manager = EncryptionManager(vault)
    config_content = await encryption_manager.decrypt(deployment.config_encrypted)

    # Schedule validation
    background_tasks.add_task(
        validate_deployment,
        deployment_id=deployment_id,
        config_content=config_content.decode(),
        devices=devices,
        db=db,
        redis=redis,
        audit=audit
    )

    await audit.log_event(
        user_id=current_user.id,
        action="validation_triggered",
        resource_type="deployment",
        resource_id=str(deployment_id)
    )

    return {
        "deployment_id": str(deployment_id),
        "status": "validating",
        "message": "Validation started"
    }


async def validate_deployment(
    deployment_id: UUID,
    config_content: str,
    devices: List[Device],
    db: AsyncSession,
    redis,
    audit: AuditLogger
):
    """
    Background task to validate deployment configuration
    """

    validator = ConfigValidator()
    validation_results = await validator.validate_configuration(
        config_content=config_content,
        devices=devices
    )

    # Store validation results
    validation = ConfigurationValidation(
        deployment_id=deployment_id,
        status="completed",
        passed=validation_results.is_valid,
        errors=validation_results.errors,
        warnings=validation_results.warnings,
        suggestions=validation_results.suggestions,
        validator_version="1.0.0"
    )
    db.add(validation)

    # Update deployment validation status
    deployment = await db.get(Deployment, deployment_id)
    deployment.validation_status = "passed" if validation_results.is_valid else "failed"

    # If validation passed and approval not required, start deployment
    if validation_results.is_valid and not deployment.approval_required:
        deployment.status = "ready"

    await db.commit()

    # Store in Redis for quick access
    await redis.set(
        f"validation:{deployment_id}",
        json.dumps({
            "passed": validation_results.is_valid,
            "errors": len(validation_results.errors),
            "warnings": len(validation_results.warnings)
        }),
        ex=3600
    )


async def execute_deployment(
    deployment_id: UUID,
    db: AsyncSession,
    redis,
    vault,
    audit: AuditLogger,
    message_queue
):
    """
    Background task to execute deployment
    """

    deployment = await db.get(Deployment, deployment_id)
    if not deployment:
        return

    # Update deployment status
    deployment.status = "running"
    deployment.started_at = datetime.utcnow()
    await db.commit()

    # Get deployment executor based on strategy
    executor = DeploymentExecutor(db, redis, vault, audit)

    if deployment.strategy == "canary":
        strategy = CanaryStrategy(executor, deployment.strategy_config)
    elif deployment.strategy == "rolling":
        strategy = RollingStrategy(executor, deployment.strategy_config)
    elif deployment.strategy == "blue_green":
        strategy = BlueGreenStrategy(executor, deployment.strategy_config)
    else:
        strategy = None

    try:
        # Execute deployment
        result = await executor.execute_deployment(
            deployment=deployment,
            strategy=strategy,
            dry_run=deployment.dry_run
        )

        # Update deployment status
        deployment.status = "completed" if result.success else "failed"
        deployment.completed_at = datetime.utcnow()
        deployment.success_count = result.success_count
        deployment.failure_count = result.failure_count

        await db.commit()

        # Send notifications
        await send_deployment_notification(
            deployment=deployment,
            result=result,
            message_queue=message_queue
        )

    except Exception as e:
        deployment.status = "failed"
        deployment.error = str(e)
        deployment.completed_at = datetime.utcnow()
        await db.commit()

        await audit.log_error(
            error_type="deployment_execution_error",
            error_message=str(e),
            context={"deployment_id": str(deployment_id)}
        )


async def execute_rollback(
    deployment_id: UUID,
    devices_to_rollback: List[UUID],
    rollback_to: Optional[UUID],
    user_id: UUID,
    db: AsyncSession,
    redis,
    vault,
    audit: AuditLogger
):
    """
    Background task to execute rollback
    """

    deployment = await db.get(Deployment, deployment_id)
    if not deployment:
        return

    executor = DeploymentExecutor(db, redis, vault, audit)

    try:
        # Execute rollback for each device
        success_count = 0
        failure_count = 0

        for device_id in devices_to_rollback:
            try:
                # Get backup to rollback to
                if rollback_to:
                    backup = await db.get(DeviceBackup, rollback_to)
                else:
                    # Get latest backup before deployment
                    result = await db.execute(
                        select(DeviceBackup)
                        .where(
                            and_(
                                DeviceBackup.device_id == device_id,
                                DeviceBackup.created_at < deployment.created_at
                            )
                        )
                        .order_by(DeviceBackup.created_at.desc())
                        .limit(1)
                    )
                    backup = result.scalar_one_or_none()

                if backup:
                    await executor.rollback_device(
                        device_id=device_id,
                        backup_id=backup.id
                    )
                    success_count += 1
                else:
                    failure_count += 1

            except Exception as e:
                failure_count += 1
                await audit.log_error(
                    error_type="rollback_error",
                    error_message=str(e),
                    context={
                        "deployment_id": str(deployment_id),
                        "device_id": str(device_id)
                    }
                )

        # Update deployment status
        deployment.status = "rolled_back" if success_count > 0 else "rollback_failed"
        deployment.rollback_completed_at = datetime.utcnow()
        deployment.rollback_success_count = success_count
        deployment.rollback_failure_count = failure_count

        await db.commit()

    except Exception as e:
        deployment.status = "rollback_failed"
        deployment.rollback_error = str(e)
        await db.commit()


async def send_approval_requests(
    deployment: Deployment,
    approvers: List[UUID],
    message_queue
):
    """
    Send approval request notifications
    """

    for approver_id in approvers:
        message = {
            "type": "approval_request",
            "deployment_id": str(deployment.id),
            "deployment_name": deployment.name,
            "approver_id": str(approver_id),
            "created_at": datetime.utcnow().isoformat()
        }
        await message_queue.publish("notifications", json.dumps(message))


async def send_deployment_notification(
    deployment: Deployment,
    result: Any,
    message_queue
):
    """
    Send deployment completion notification
    """

    message = {
        "type": "deployment_complete",
        "deployment_id": str(deployment.id),
        "deployment_name": deployment.name,
        "status": deployment.status,
        "success_count": result.success_count,
        "failure_count": result.failure_count,
        "completed_at": deployment.completed_at.isoformat()
    }
    await message_queue.publish("notifications", json.dumps(message))


async def schedule_deployment(
    deployment_id: UUID,
    scheduled_at: datetime,
    redis
):
    """
    Schedule deployment for future execution
    """

    delay_seconds = (scheduled_at - datetime.utcnow()).total_seconds()
    if delay_seconds > 0:
        await redis.set(
            f"scheduled:{deployment_id}",
            json.dumps({
                "deployment_id": str(deployment_id),
                "scheduled_at": scheduled_at.isoformat()
            }),
            ex=int(delay_seconds)
        )