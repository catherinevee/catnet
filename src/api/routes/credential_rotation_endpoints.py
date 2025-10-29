"""
Credential Rotation API Endpoints
RESTful API for managing credential rotation policies and operations
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from typing import List, Optional
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
import structlog

from src.db.session import get_db
from src.db.models.credential_rotation import (
    CredentialRotationPolicy,
    CredentialRotationHistory,
    RotationFrequency,
    RotationStatus
)
from src.security.credential_rotation import credential_rotation_engine
from src.workers.credential_rotation_worker import rotation_scheduler
from src.auth.dependencies import get_current_user, get_current_admin_user

logger = structlog.get_logger()

router = APIRouter(
    prefix="/api/v1/credential-rotation",
    tags=["credential-rotation"]
)


# Pydantic Models

class RotationPolicyCreate(BaseModel):
    """Request model for creating a rotation policy"""
    device_id: str = Field(..., description="Device identifier")
    frequency: RotationFrequency = Field(..., description="Rotation frequency")
    rotation_window_hours: int = Field(2, ge=1, le=24, description="Time window for rotation")
    notify_on_rotation: bool = Field(True, description="Send notifications on rotation")
    auto_rollback_on_failure: bool = Field(True, description="Auto-rollback on failure")

    class Config:
        schema_extra = {
            "example": {
                "device_id": "router-nyc-01",
                "frequency": "monthly",
                "rotation_window_hours": 2,
                "notify_on_rotation": True,
                "auto_rollback_on_failure": True
            }
        }


class RotationPolicyUpdate(BaseModel):
    """Request model for updating a rotation policy"""
    frequency: Optional[RotationFrequency] = None
    enabled: Optional[bool] = None
    rotation_window_hours: Optional[int] = Field(None, ge=1, le=24)
    notify_on_rotation: Optional[bool] = None
    auto_rollback_on_failure: Optional[bool] = None


class RotationPolicyResponse(BaseModel):
    """Response model for rotation policy"""
    id: str
    device_id: str
    frequency: RotationFrequency
    next_rotation: datetime
    enabled: bool
    rotation_window_hours: int
    notify_on_rotation: bool
    auto_rollback_on_failure: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class RotationHistoryResponse(BaseModel):
    """Response model for rotation history"""
    id: str
    device_id: str
    status: RotationStatus
    started_at: datetime
    completed_at: Optional[datetime]
    duration_seconds: Optional[int]
    rotated_by: str
    error_message: Optional[str]

    class Config:
        orm_mode = True


class RotationTriggerResponse(BaseModel):
    """Response model for manual rotation trigger"""
    status: RotationStatus
    history_id: str
    message: str


class EmergencyLockoutResponse(BaseModel):
    """Response model for emergency lockout"""
    status: str
    device_id: str
    rotation_status: RotationStatus
    message: str


# API Endpoints

@router.post("/policies", response_model=RotationPolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_rotation_policy(
    policy_data: RotationPolicyCreate,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Create a new credential rotation policy

    Creates a rotation policy for a device that will automatically
    rotate credentials based on the specified frequency.

    Requires: User authentication
    """
    logger.info(
        "Creating rotation policy",
        device_id=policy_data.device_id,
        frequency=policy_data.frequency,
        user=current_user.id
    )

    # Calculate next rotation time
    now = datetime.utcnow()
    if policy_data.frequency == RotationFrequency.DAILY:
        next_rotation = now + timedelta(days=1)
    elif policy_data.frequency == RotationFrequency.WEEKLY:
        next_rotation = now + timedelta(weeks=1)
    elif policy_data.frequency == RotationFrequency.MONTHLY:
        next_rotation = now + timedelta(days=30)
    elif policy_data.frequency == RotationFrequency.QUARTERLY:
        next_rotation = now + timedelta(days=90)
    else:  # MANUAL
        next_rotation = now + timedelta(days=365)  # Far future

    # Create policy
    policy = CredentialRotationPolicy(
        **policy_data.dict(),
        next_rotation=next_rotation
    )

    db.add(policy)
    await db.commit()
    await db.refresh(policy)

    logger.info("Rotation policy created", policy_id=policy.id, device_id=policy.device_id)

    return policy


@router.get("/policies", response_model=List[RotationPolicyResponse])
async def list_rotation_policies(
    device_id: Optional[str] = Query(None, description="Filter by device"),
    enabled: Optional[bool] = Query(None, description="Filter by enabled status"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    List credential rotation policies

    Returns a list of rotation policies with optional filters.

    Requires: User authentication
    """
    query = db.query(CredentialRotationPolicy)

    if device_id:
        query = query.filter(CredentialRotationPolicy.device_id == device_id)

    if enabled is not None:
        query = query.filter(CredentialRotationPolicy.enabled == enabled)

    policies = await query.offset(offset).limit(limit).all()

    return policies


@router.get("/policies/{policy_id}", response_model=RotationPolicyResponse)
async def get_rotation_policy(
    policy_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get a specific rotation policy

    Requires: User authentication
    """
    policy = await db.query(CredentialRotationPolicy).filter(
        CredentialRotationPolicy.id == policy_id
    ).first()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rotation policy {policy_id} not found"
        )

    return policy


@router.patch("/policies/{policy_id}", response_model=RotationPolicyResponse)
async def update_rotation_policy(
    policy_id: str,
    policy_update: RotationPolicyUpdate,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Update a rotation policy

    Requires: User authentication
    """
    policy = await db.query(CredentialRotationPolicy).filter(
        CredentialRotationPolicy.id == policy_id
    ).first()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rotation policy {policy_id} not found"
        )

    # Update fields
    update_data = policy_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(policy, field, value)

    policy.updated_at = datetime.utcnow()

    await db.commit()
    await db.refresh(policy)

    logger.info("Rotation policy updated", policy_id=policy_id, fields=list(update_data.keys()))

    return policy


@router.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rotation_policy(
    policy_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """
    Delete a rotation policy

    Requires: Admin authentication
    """
    policy = await db.query(CredentialRotationPolicy).filter(
        CredentialRotationPolicy.id == policy_id
    ).first()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rotation policy {policy_id} not found"
        )

    await db.delete(policy)
    await db.commit()

    logger.info("Rotation policy deleted", policy_id=policy_id)


@router.post("/rotate/{device_id}", response_model=RotationTriggerResponse)
async def rotate_credentials_now(
    device_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Manually trigger credential rotation for a device

    Immediately rotates credentials for the specified device,
    bypassing the normal schedule.

    Requires: User authentication
    """
    logger.info(
        "Manual rotation triggered",
        device_id=device_id,
        user=current_user.id
    )

    # Find policy for device
    policy = await db.query(CredentialRotationPolicy).filter(
        CredentialRotationPolicy.device_id == device_id
    ).first()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No rotation policy found for device {device_id}"
        )

    # Execute rotation
    try:
        history = await credential_rotation_engine.rotate_device_credentials(
            device_id=device_id,
            policy=policy,
            initiated_by=current_user.id
        )

        db.add(history)
        await db.commit()

        return RotationTriggerResponse(
            status=history.status,
            history_id=history.id,
            message=f"Rotation {history.status.value} in {history.duration_seconds}s"
        )

    except Exception as e:
        logger.error("Manual rotation failed", device_id=device_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Rotation failed: {str(e)}"
        )


@router.get("/history", response_model=List[RotationHistoryResponse])
async def get_rotation_history(
    device_id: Optional[str] = Query(None, description="Filter by device"),
    status: Optional[RotationStatus] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get rotation history

    Returns historical records of credential rotations with optional filters.

    Requires: User authentication
    """
    query = db.query(CredentialRotationHistory)

    if device_id:
        query = query.filter(CredentialRotationHistory.device_id == device_id)

    if status:
        query = query.filter(CredentialRotationHistory.status == status)

    history = await query.order_by(
        CredentialRotationHistory.started_at.desc()
    ).offset(offset).limit(limit).all()

    return history


@router.get("/history/{device_id}", response_model=List[RotationHistoryResponse])
async def get_device_rotation_history(
    device_id: str,
    limit: int = Query(50, ge=1, le=500),
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get rotation history for a specific device

    Requires: User authentication
    """
    history = await db.query(CredentialRotationHistory).filter(
        CredentialRotationHistory.device_id == device_id
    ).order_by(
        CredentialRotationHistory.started_at.desc()
    ).limit(limit).all()

    return history


@router.post("/emergency-lockout/{device_id}", response_model=EmergencyLockoutResponse)
async def emergency_lockout(
    device_id: str,
    reason: str = Query(..., description="Reason for lockout"),
    db = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """
    Emergency lockout - immediately rotates credentials and disables device

    This is an emergency operation that should only be used when
    credentials have been compromised. It will:
    1. Immediately rotate device credentials
    2. Disable the device to prevent unauthorized access
    3. Send emergency notifications

    Requires: Admin authentication
    """
    logger.warning(
        "Emergency lockout initiated",
        device_id=device_id,
        user=current_user.id,
        reason=reason
    )

    # Find policy
    policy = await db.query(CredentialRotationPolicy).filter(
        CredentialRotationPolicy.device_id == device_id
    ).first()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No rotation policy found for device {device_id}"
        )

    try:
        # Rotate credentials immediately
        history = await credential_rotation_engine.rotate_device_credentials(
            device_id=device_id,
            policy=policy,
            initiated_by=f"EMERGENCY_{current_user.id}"
        )

        db.add(history)

        # Disable device (assuming Device model exists)
        from src.db.models.device import Device
        device = await db.query(Device).filter(Device.id == device_id).first()

        if device:
            device.enabled = False
            device.lockout_reason = reason
            device.locked_out_by = current_user.id
            device.locked_out_at = datetime.utcnow()

        await db.commit()

        logger.warning(
            "Emergency lockout completed",
            device_id=device_id,
            rotation_status=history.status
        )

        return EmergencyLockoutResponse(
            status="locked_out",
            device_id=device_id,
            rotation_status=history.status,
            message=f"Device {device_id} locked out. Credentials rotated and device disabled."
        )

    except Exception as e:
        logger.error("Emergency lockout failed", device_id=device_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Emergency lockout failed: {str(e)}"
        )


@router.get("/scheduler/status")
async def get_scheduler_status(
    current_user = Depends(get_current_user)
):
    """
    Get credential rotation scheduler status

    Returns information about the background scheduler including
    running status and scheduled jobs.

    Requires: User authentication
    """
    return rotation_scheduler.get_scheduler_status()
