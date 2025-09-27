"""
Admin Router
System administration, user management, configuration, and maintenance endpoints
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from uuid import UUID
import asyncio
import json
import os
import subprocess
import tarfile
import shutil
import tempfile
from pathlib import Path
import boto3
from botocore.exceptions import ClientError

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Query, Body
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, and_, or_, func, text
from pydantic import BaseModel, Field, EmailStr, validator

from src.db.models import (
    User, Role, Permission, UserRole, RolePermission,
    Device, Deployment, GitRepository, AuditLog, SecurityIncident,
    SystemConfiguration, MaintenanceWindow, BackupSchedule,
    NotificationRule, AlertChannel
)
from src.core.config import settings
from src.core.dependencies import (
    get_db,
    get_current_user,
    require_permission,
    require_admin,
    get_redis,
    get_vault,
    get_audit_logger
)
from src.security.audit import AuditLogger
from src.security.encryption import EncryptionManager
from src.auth.service import AuthenticationService
from src.core.exceptions import (
    ValidationError,
    AuthorizationError,
    ConfigurationError
)

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


class UserCreateRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    full_name: str = Field(..., max_length=100)
    password: str = Field(..., min_length=12)
    roles: List[str] = []
    is_active: bool = True
    mfa_required: bool = True
    password_expires_days: int = Field(default=90, ge=0, le=365)


class UserUpdateRequest(BaseModel):
    email: Optional[EmailStr]
    full_name: Optional[str] = Field(None, max_length=100)
    roles: Optional[List[str]]
    is_active: Optional[bool]
    mfa_required: Optional[bool]
    password_expires_days: Optional[int] = Field(None, ge=0, le=365)


class UserResponse(BaseModel):
    id: UUID
    username: str
    email: str
    full_name: str
    is_active: bool
    is_admin: bool
    mfa_enabled: bool
    mfa_required: bool
    roles: List[str]
    permissions: List[str]
    created_at: datetime
    last_login: Optional[datetime]
    password_changed_at: Optional[datetime]
    locked: bool
    lock_reason: Optional[str]


class RoleCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    description: Optional[str] = Field(None, max_length=255)
    permissions: List[str]
    is_system: bool = False


class RoleResponse(BaseModel):
    id: UUID
    name: str
    description: Optional[str]
    permissions: List[str]
    user_count: int
    is_system: bool
    created_at: datetime


class SystemConfigRequest(BaseModel):
    category: str = Field(..., max_length=50)
    key: str = Field(..., max_length=100)
    value: Any
    description: Optional[str]
    is_secret: bool = False
    validation_regex: Optional[str]


class SystemConfigResponse(BaseModel):
    id: UUID
    category: str
    key: str
    value: Any
    description: Optional[str]
    is_secret: bool
    updated_at: datetime
    updated_by: Optional[UUID]


class MaintenanceWindowRequest(BaseModel):
    name: str = Field(..., max_length=100)
    description: Optional[str]
    start_time: datetime
    end_time: datetime
    recurring: bool = False
    recurrence_pattern: Optional[str]
    affected_services: List[str]
    notification_advance_minutes: int = Field(default=60, ge=0)
    auto_disable_deployments: bool = True


class BackupRequest(BaseModel):
    backup_type: str = Field(..., regex="^(full|incremental|differential)$")
    include_configs: bool = True
    include_database: bool = True
    include_logs: bool = False
    include_vault: bool = True
    encryption_enabled: bool = True
    compression_enabled: bool = True
    retention_days: int = Field(default=30, ge=1, le=365)


class SystemStatsResponse(BaseModel):
    users_total: int
    users_active: int
    devices_total: int
    devices_connected: int
    deployments_total: int
    deployments_today: int
    deployments_success_rate: float
    repositories_total: int
    security_incidents_24h: int
    active_sessions: int
    system_uptime_hours: float
    database_size_mb: float


class AuditLogQuery(BaseModel):
    user_id: Optional[UUID]
    action: Optional[str]
    resource_type: Optional[str]
    resource_id: Optional[str]
    start_date: Optional[datetime]
    end_date: Optional[datetime]
    severity: Optional[str]
    limit: int = Field(default=100, ge=1, le=10000)


@router.get("/users", response_model=List[UserResponse])
async def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    is_active: Optional[bool] = None,
    role: Optional[str] = None,
    search: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit: AuditLogger = Depends(get_audit_logger)
) -> List[UserResponse]:
    """
    List all users (admin only)
    """

    await require_admin(current_user)

    query = select(User)

    if is_active is not None:
        query = query.where(User.is_active == is_active)

    if role:
        query = query.join(UserRole).join(Role).where(Role.name == role)

    if search:
        query = query.where(
            or_(
                User.username.ilike(f"%{search}%"),
                User.email.ilike(f"%{search}%"),
                User.full_name.ilike(f"%{search}%")
            )
        )

    query = query.offset(skip).limit(limit)

    result = await db.execute(query)
    users = result.scalars().all()

    user_responses = []
    for user in users:
        # Get roles
        roles = [role.name for role in user.roles]

        # Get permissions
        permissions = set()
        for role in user.roles:
            for perm in role.permissions:
                permissions.add(perm.name)

        user_responses.append(UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            is_active=user.is_active,
            is_admin=user.is_admin,
            mfa_enabled=user.mfa_enabled,
            mfa_required=user.mfa_required,
            roles=roles,
            permissions=list(permissions),
            created_at=user.created_at,
            last_login=user.last_login,
            password_changed_at=user.password_changed_at,
            locked=user.locked,
            lock_reason=user.lock_reason
        ))

    await audit.log_event(
        user_id=current_user.id,
        action="list_users",
        resource_type="user",
        details={"count": len(users), "filters": {"is_active": is_active, "role": role}}
    )

    return user_responses


@router.post("/users", response_model=UserResponse)
async def create_user(
    request: UserCreateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit: AuditLogger = Depends(get_audit_logger),
    vault = Depends(get_vault)
) -> UserResponse:
    """
    Create a new user (admin only)
    """

    await require_admin(current_user)

    # Check if username exists
    existing = await db.execute(
        select(User).where(
            or_(
                User.username == request.username,
                User.email == request.email
            )
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already exists"
        )

    # Hash password
    auth_service = AuthenticationService(db, None, vault, audit)
    password_hash = await auth_service.hash_password(request.password)

    # Create user
    user = User(
        username=request.username,
        email=request.email,
        full_name=request.full_name,
        password_hash=password_hash,
        is_active=request.is_active,
        is_admin=False,
        mfa_required=request.mfa_required,
        password_expires_days=request.password_expires_days,
        password_changed_at=datetime.utcnow(),
        created_by=current_user.id
    )

    db.add(user)
    await db.flush()

    # Assign roles
    for role_name in request.roles:
        role = await db.execute(select(Role).where(Role.name == role_name))
        role = role.scalar_one_or_none()
        if role:
            user_role = UserRole(user_id=user.id, role_id=role.id)
            db.add(user_role)

    await db.commit()
    await db.refresh(user)

    await audit.log_event(
        user_id=current_user.id,
        action="user_created",
        resource_type="user",
        resource_id=str(user.id),
        details={
            "username": user.username,
            "email": user.email,
            "roles": request.roles
        }
    )

    # Get roles and permissions for response
    roles = [role.name for role in user.roles]
    permissions = set()
    for role in user.roles:
        for perm in role.permissions:
            permissions.add(perm.name)

    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        is_admin=user.is_admin,
        mfa_enabled=user.mfa_enabled,
        mfa_required=user.mfa_required,
        roles=roles,
        permissions=list(permissions),
        created_at=user.created_at,
        last_login=user.last_login,
        password_changed_at=user.password_changed_at,
        locked=user.locked,
        lock_reason=user.lock_reason
    )


@router.patch("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: UUID,
    request: UserUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit: AuditLogger = Depends(get_audit_logger)
) -> UserResponse:
    """
    Update user details (admin only)
    """

    await require_admin(current_user)

    # Get user
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Prevent self-deactivation
    if user_id == current_user.id and request.is_active == False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own account"
        )

    # Update fields
    if request.email is not None:
        user.email = request.email
    if request.full_name is not None:
        user.full_name = request.full_name
    if request.is_active is not None:
        user.is_active = request.is_active
    if request.mfa_required is not None:
        user.mfa_required = request.mfa_required
    if request.password_expires_days is not None:
        user.password_expires_days = request.password_expires_days

    # Update roles
    if request.roles is not None:
        # Remove existing roles
        await db.execute(
            delete(UserRole).where(UserRole.user_id == user_id)
        )

        # Add new roles
        for role_name in request.roles:
            role = await db.execute(select(Role).where(Role.name == role_name))
            role = role.scalar_one_or_none()
            if role:
                user_role = UserRole(user_id=user.id, role_id=role.id)
                db.add(user_role)

    user.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(user)

    await audit.log_event(
        user_id=current_user.id,
        action="user_updated",
        resource_type="user",
        resource_id=str(user_id),
        details={
            "changes": request.dict(exclude_unset=True)
        }
    )

    # Get updated roles and permissions
    roles = [role.name for role in user.roles]
    permissions = set()
    for role in user.roles:
        for perm in role.permissions:
            permissions.add(perm.name)

    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        is_admin=user.is_admin,
        mfa_enabled=user.mfa_enabled,
        mfa_required=user.mfa_required,
        roles=roles,
        permissions=list(permissions),
        created_at=user.created_at,
        last_login=user.last_login,
        password_changed_at=user.password_changed_at,
        locked=user.locked,
        lock_reason=user.lock_reason
    )


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit: AuditLogger = Depends(get_audit_logger)
) -> Dict[str, str]:
    """
    Delete a user (admin only)
    """

    await require_admin(current_user)

    # Get user
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Prevent self-deletion
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )

    # Soft delete (deactivate)
    user.is_active = False
    user.deleted_at = datetime.utcnow()
    user.deleted_by = current_user.id

    await db.commit()

    await audit.log_event(
        user_id=current_user.id,
        action="user_deleted",
        resource_type="user",
        resource_id=str(user_id),
        details={"username": user.username}
    )

    return {"message": f"User {user.username} deleted successfully"}


@router.post("/users/{user_id}/lock")
async def lock_user(
    user_id: UUID,
    reason: str = Body(..., min_length=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis),
    audit: AuditLogger = Depends(get_audit_logger)
) -> Dict[str, str]:
    """
    Lock a user account (admin only)
    """

    await require_admin(current_user)

    # Get user
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Lock user
    user.locked = True
    user.lock_reason = reason
    user.locked_at = datetime.utcnow()
    user.locked_by = current_user.id

    # Invalidate all sessions
    from src.db.models import UserSession
    await db.execute(
        update(UserSession)
        .where(UserSession.user_id == user_id)
        .values(is_active=False, revoked_at=datetime.utcnow())
    )

    # Clear cache
    await redis.delete(f"user:{user_id}")
    await redis.delete(f"permissions:{user_id}")

    await db.commit()

    await audit.log_security_event(
        event_type="user_locked",
        severity="high",
        user_id=current_user.id,
        details={
            "locked_user_id": str(user_id),
            "username": user.username,
            "reason": reason
        }
    )

    return {"message": f"User {user.username} locked successfully"}


@router.post("/users/{user_id}/unlock")
async def unlock_user(
    user_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit: AuditLogger = Depends(get_audit_logger)
) -> Dict[str, str]:
    """
    Unlock a user account (admin only)
    """

    await require_admin(current_user)

    # Get user
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Unlock user
    user.locked = False
    user.lock_reason = None
    user.locked_at = None
    user.locked_by = None

    await db.commit()

    await audit.log_event(
        user_id=current_user.id,
        action="user_unlocked",
        resource_type="user",
        resource_id=str(user_id),
        details={"username": user.username}
    )

    return {"message": f"User {user.username} unlocked successfully"}


@router.get("/roles", response_model=List[RoleResponse])
async def list_roles(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit: AuditLogger = Depends(get_audit_logger)
) -> List[RoleResponse]:
    """
    List all roles (admin only)
    """

    await require_admin(current_user)

    result = await db.execute(select(Role))
    roles = result.scalars().all()

    role_responses = []
    for role in roles:
        # Count users with this role
        user_count_result = await db.execute(
            select(func.count(UserRole.user_id))
            .where(UserRole.role_id == role.id)
        )
        user_count = user_count_result.scalar()

        # Get permissions
        permissions = [perm.name for perm in role.permissions]

        role_responses.append(RoleResponse(
            id=role.id,
            name=role.name,
            description=role.description,
            permissions=permissions,
            user_count=user_count or 0,
            is_system=role.is_system,
            created_at=role.created_at
        ))

    return role_responses


@router.post("/roles", response_model=RoleResponse)
async def create_role(
    request: RoleCreateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit: AuditLogger = Depends(get_audit_logger)
) -> RoleResponse:
    """
    Create a new role (admin only)
    """

    await require_admin(current_user)

    # Check if role exists
    existing = await db.execute(select(Role).where(Role.name == request.name))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Role already exists"
        )

    # Create role
    role = Role(
        name=request.name,
        description=request.description,
        is_system=request.is_system,
        created_by=current_user.id
    )
    db.add(role)
    await db.flush()

    # Add permissions
    for perm_name in request.permissions:
        perm = await db.execute(select(Permission).where(Permission.name == perm_name))
        perm = perm.scalar_one_or_none()
        if perm:
            role_perm = RolePermission(role_id=role.id, permission_id=perm.id)
            db.add(role_perm)

    await db.commit()
    await db.refresh(role)

    await audit.log_event(
        user_id=current_user.id,
        action="role_created",
        resource_type="role",
        resource_id=str(role.id),
        details={
            "name": role.name,
            "permissions": request.permissions
        }
    )

    return RoleResponse(
        id=role.id,
        name=role.name,
        description=role.description,
        permissions=request.permissions,
        user_count=0,
        is_system=role.is_system,
        created_at=role.created_at
    )


@router.get("/config", response_model=List[SystemConfigResponse])
async def list_system_config(
    category: Optional[str] = None,
    show_secrets: bool = False,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    vault = Depends(get_vault),
    audit: AuditLogger = Depends(get_audit_logger)
) -> List[SystemConfigResponse]:
    """
    List system configuration (admin only)
    """

    await require_admin(current_user)

    query = select(SystemConfiguration)
    if category:
        query = query.where(SystemConfiguration.category == category)

    result = await db.execute(query)
    configs = result.scalars().all()

    config_responses = []
    for config in configs:
        value = config.value

        # Mask secrets unless requested
        if config.is_secret and not show_secrets:
            value = "***hidden***"
        elif config.is_secret and show_secrets:
            # Decrypt if encrypted
            if config.encrypted:
                encryption_manager = EncryptionManager(vault)
                value = await encryption_manager.decrypt(value)

        config_responses.append(SystemConfigResponse(
            id=config.id,
            category=config.category,
            key=config.key,
            value=value,
            description=config.description,
            is_secret=config.is_secret,
            updated_at=config.updated_at,
            updated_by=config.updated_by
        ))

    if show_secrets:
        await audit.log_security_event(
            event_type="config_secrets_accessed",
            severity="high",
            user_id=current_user.id,
            details={"category": category}
        )

    return config_responses


@router.put("/config", response_model=SystemConfigResponse)
async def update_system_config(
    request: SystemConfigRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis),
    vault = Depends(get_vault),
    audit: AuditLogger = Depends(get_audit_logger)
) -> SystemConfigResponse:
    """
    Update system configuration (admin only)
    """

    await require_admin(current_user)

    # Find or create config
    result = await db.execute(
        select(SystemConfiguration).where(
            and_(
                SystemConfiguration.category == request.category,
                SystemConfiguration.key == request.key
            )
        )
    )
    config = result.scalar_one_or_none()

    if not config:
        config = SystemConfiguration(
            category=request.category,
            key=request.key
        )
        db.add(config)

    # Encrypt secrets
    value = request.value
    if request.is_secret:
        encryption_manager = EncryptionManager(vault)
        value = await encryption_manager.encrypt(json.dumps(value).encode())
        config.encrypted = True

    config.value = value
    config.description = request.description
    config.is_secret = request.is_secret
    config.validation_regex = request.validation_regex
    config.updated_at = datetime.utcnow()
    config.updated_by = current_user.id

    await db.commit()

    # Clear config cache
    await redis.delete(f"config:{request.category}:{request.key}")

    await audit.log_event(
        user_id=current_user.id,
        action="config_updated",
        resource_type="system_configuration",
        resource_id=str(config.id),
        details={
            "category": request.category,
            "key": request.key,
            "is_secret": request.is_secret
        }
    )

    return SystemConfigResponse(
        id=config.id,
        category=config.category,
        key=config.key,
        value="***hidden***" if request.is_secret else request.value,
        description=config.description,
        is_secret=config.is_secret,
        updated_at=config.updated_at,
        updated_by=config.updated_by
    )


@router.get("/stats", response_model=SystemStatsResponse)
async def get_system_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis),
    audit: AuditLogger = Depends(get_audit_logger)
) -> SystemStatsResponse:
    """
    Get system statistics (admin only)
    """

    await require_admin(current_user)

    # User statistics
    user_stats = await db.execute(
        select(
            func.count(User.id).label("total"),
            func.count(User.id).filter(User.is_active == True).label("active")
        )
    )
    user_data = user_stats.first()

    # Device statistics
    device_stats = await db.execute(
        select(
            func.count(Device.id).label("total"),
            func.count(Device.id).filter(Device.status == "connected").label("connected")
        )
    )
    device_data = device_stats.first()

    # Deployment statistics
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    deployment_stats = await db.execute(
        select(
            func.count(Deployment.id).label("total"),
            func.count(Deployment.id).filter(
                Deployment.created_at >= today_start
            ).label("today"),
            func.avg(
                func.case(
                    (Deployment.status == "completed", 1.0),
                    else_=0.0
                )
            ).label("success_rate")
        )
    )
    deployment_data = deployment_stats.first()

    # Repository count
    repo_count = await db.execute(select(func.count(GitRepository.id)))
    repos_total = repo_count.scalar()

    # Security incidents (last 24h)
    incident_count = await db.execute(
        select(func.count(SecurityIncident.id))
        .where(SecurityIncident.created_at >= datetime.utcnow() - timedelta(hours=24))
    )
    incidents_24h = incident_count.scalar()

    # Active sessions
    from src.db.models import UserSession
    session_count = await db.execute(
        select(func.count(UserSession.id))
        .where(UserSession.is_active == True)
    )
    active_sessions = session_count.scalar()

    # System uptime
    uptime_hours = (datetime.utcnow() - settings.APP_START_TIME).total_seconds() / 3600

    # Database size
    db_size = await db.execute(
        text("SELECT pg_database_size(current_database()) / 1024 / 1024 as size_mb")
    )
    database_size_mb = db_size.scalar()

    return SystemStatsResponse(
        users_total=user_data.total if user_data else 0,
        users_active=user_data.active if user_data else 0,
        devices_total=device_data.total if device_data else 0,
        devices_connected=device_data.connected if device_data else 0,
        deployments_total=deployment_data.total if deployment_data else 0,
        deployments_today=deployment_data.today if deployment_data else 0,
        deployments_success_rate=float(deployment_data.success_rate) if deployment_data and deployment_data.success_rate else 0.0,
        repositories_total=repos_total or 0,
        security_incidents_24h=incidents_24h or 0,
        active_sessions=active_sessions or 0,
        system_uptime_hours=round(uptime_hours, 2),
        database_size_mb=float(database_size_mb) if database_size_mb else 0.0
    )


@router.post("/audit/query", response_model=List[Dict[str, Any]])
async def query_audit_logs(
    query: AuditLogQuery,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit: AuditLogger = Depends(get_audit_logger)
) -> List[Dict[str, Any]]:
    """
    Query audit logs (admin only)
    """

    await require_admin(current_user)

    sql_query = select(AuditLog)

    if query.user_id:
        sql_query = sql_query.where(AuditLog.user_id == query.user_id)
    if query.action:
        sql_query = sql_query.where(AuditLog.action == query.action)
    if query.resource_type:
        sql_query = sql_query.where(AuditLog.resource_type == query.resource_type)
    if query.resource_id:
        sql_query = sql_query.where(AuditLog.resource_id == query.resource_id)
    if query.start_date:
        sql_query = sql_query.where(AuditLog.created_at >= query.start_date)
    if query.end_date:
        sql_query = sql_query.where(AuditLog.created_at <= query.end_date)
    if query.severity:
        sql_query = sql_query.where(AuditLog.severity == query.severity)

    sql_query = sql_query.order_by(AuditLog.created_at.desc()).limit(query.limit)

    result = await db.execute(sql_query)
    logs = result.scalars().all()

    log_responses = []
    for log in logs:
        log_responses.append({
            "id": str(log.id),
            "user_id": str(log.user_id) if log.user_id else None,
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
            "details": log.details,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "severity": log.severity,
            "created_at": log.created_at.isoformat()
        })

    await audit.log_event(
        user_id=current_user.id,
        action="audit_logs_queried",
        resource_type="audit_log",
        details={"query": query.dict(), "results": len(log_responses)}
    )

    return log_responses


@router.post("/maintenance", response_model=Dict[str, Any])
async def create_maintenance_window(
    request: MaintenanceWindowRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis),
    audit: AuditLogger = Depends(get_audit_logger)
) -> Dict[str, Any]:
    """
    Create maintenance window (admin only)
    """

    await require_admin(current_user)

    maintenance = MaintenanceWindow(
        name=request.name,
        description=request.description,
        start_time=request.start_time,
        end_time=request.end_time,
        recurring=request.recurring,
        recurrence_pattern=request.recurrence_pattern,
        affected_services=request.affected_services,
        notification_advance_minutes=request.notification_advance_minutes,
        auto_disable_deployments=request.auto_disable_deployments,
        created_by=current_user.id
    )

    db.add(maintenance)
    await db.commit()

    # Store in Redis for quick access
    await redis.set(
        f"maintenance:{maintenance.id}",
        json.dumps({
            "start": maintenance.start_time.isoformat(),
            "end": maintenance.end_time.isoformat(),
            "services": maintenance.affected_services
        }),
        ex=int((maintenance.end_time - datetime.utcnow()).total_seconds())
    )

    await audit.log_event(
        user_id=current_user.id,
        action="maintenance_window_created",
        resource_type="maintenance_window",
        resource_id=str(maintenance.id),
        details={
            "name": maintenance.name,
            "start": maintenance.start_time.isoformat(),
            "end": maintenance.end_time.isoformat()
        }
    )

    return {
        "id": str(maintenance.id),
        "name": maintenance.name,
        "start_time": maintenance.start_time.isoformat(),
        "end_time": maintenance.end_time.isoformat(),
        "affected_services": maintenance.affected_services
    }


@router.post("/backup", response_model=Dict[str, Any])
async def create_system_backup(
    request: BackupRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis),
    vault = Depends(get_vault),
    audit: AuditLogger = Depends(get_audit_logger)
) -> Dict[str, Any]:
    """
    Create system backup (admin only)
    """

    await require_admin(current_user)

    # Check if another backup is already running
    running_backups = await redis.keys("backup_status:*")
    for backup_key in running_backups:
        backup_data = await redis.get(backup_key)
        if backup_data:
            status_info = json.loads(backup_data.decode())
            if status_info.get("status") == "in_progress":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Another backup is already in progress"
                )

    backup_id = f"backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

    # Schedule backup task
    background_tasks.add_task(
        execute_system_backup,
        backup_id=backup_id,
        request=request,
        user_id=current_user.id,
        db=db,
        redis=redis,
        vault=vault,
        audit=audit
    )

    await audit.log_event(
        user_id=current_user.id,
        action="backup_initiated",
        resource_type="system_backup",
        resource_id=backup_id,
        details={
            "type": request.backup_type,
            "include_configs": request.include_configs,
            "include_database": request.include_database,
            "include_logs": request.include_logs,
            "include_vault": request.include_vault
        }
    )

    return {
        "backup_id": backup_id,
        "status": "initiated",
        "message": "System backup started"
    }


@router.get("/backup/{backup_id}/status", response_model=Dict[str, Any])
async def get_backup_status(
    backup_id: str,
    current_user: User = Depends(get_current_user),
    redis = Depends(get_redis),
    audit: AuditLogger = Depends(get_audit_logger)
) -> Dict[str, Any]:
    """
    Get backup status (admin only)
    """
    await require_admin(current_user)

    # Get status from Redis
    status_data = await redis.get(f"backup_status:{backup_id}")

    if not status_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Backup not found or status expired"
        )

    backup_status = json.loads(status_data.decode())

    await audit.log_event(
        user_id=current_user.id,
        action="backup_status_checked",
        resource_type="system_backup",
        resource_id=backup_id,
        details={"status": backup_status.get("status")}
    )

    return backup_status


@router.get("/backups", response_model=List[Dict[str, Any]])
async def list_backups(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    status_filter: Optional[str] = Query(None, regex="^(completed|failed|in_progress)$"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit: AuditLogger = Depends(get_audit_logger)
) -> List[Dict[str, Any]]:
    """
    List system backups (admin only)
    """
    await require_admin(current_user)

    try:
        from src.db.models import SystemBackup

        query = select(SystemBackup).order_by(SystemBackup.created_at.desc())

        if status_filter:
            query = query.where(SystemBackup.status == status_filter)

        query = query.offset(offset).limit(limit)

        result = await db.execute(query)
        backups = result.scalars().all()

        backup_list = []
        for backup in backups:
            backup_list.append({
                "backup_id": backup.backup_id,
                "backup_type": backup.backup_type,
                "components": backup.components,
                "status": backup.status,
                "size_bytes": backup.size_bytes,
                "cloud_url": backup.cloud_url,
                "created_at": backup.created_at.isoformat(),
                "retention_until": backup.retention_until.isoformat() if backup.retention_until else None,
                "encryption_enabled": backup.encryption_enabled,
                "compression_enabled": backup.compression_enabled
            })

        await audit.log_event(
            user_id=current_user.id,
            action="backups_listed",
            resource_type="system_backup",
            details={"count": len(backup_list), "status_filter": status_filter}
        )

        return backup_list

    except Exception as e:
        # If SystemBackup model doesn't exist, return empty list
        return []


@router.delete("/backup/{backup_id}")
async def delete_backup(
    backup_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit: AuditLogger = Depends(get_audit_logger)
) -> Dict[str, str]:
    """
    Delete a backup (admin only)
    """
    await require_admin(current_user)

    try:
        from src.db.models import SystemBackup

        # Get backup record
        backup = await db.get(SystemBackup, backup_id)
        if not backup:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Backup not found"
            )

        # Delete physical files
        if backup.file_path and Path(backup.file_path).exists():
            os.remove(backup.file_path)

        # Delete cloud backup if exists
        if backup.cloud_url:
            # This would need implementation based on cloud provider
            pass

        # Delete database record
        await db.delete(backup)
        await db.commit()

        await audit.log_event(
            user_id=current_user.id,
            action="backup_deleted",
            resource_type="system_backup",
            resource_id=backup_id,
            details={"file_path": backup.file_path, "cloud_url": backup.cloud_url}
        )

        return {"message": f"Backup {backup_id} deleted successfully"}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete backup: {str(e)}"
        )


async def execute_system_backup(
    backup_id: str,
    request: BackupRequest,
    user_id: UUID,
    db: AsyncSession,
    redis,
    vault,
    audit: AuditLogger
):
    """
    Execute system backup (background task)
    """
    backup_status = {
        "backup_id": backup_id,
        "status": "in_progress",
        "started_at": datetime.utcnow().isoformat(),
        "components": {},
        "total_size_bytes": 0,
        "errors": []
    }

    # Store initial status in Redis
    await redis.setex(
        f"backup_status:{backup_id}",
        3600,  # 1 hour TTL
        json.dumps(backup_status)
    )

    temp_dir = None
    try:
        # Create temporary directory for backup
        temp_dir = tempfile.mkdtemp(prefix=f"catnet_backup_{backup_id}_")
        backup_path = Path(temp_dir)

        await audit.log_event(
            user_id=user_id,
            action="backup_started",
            resource_type="system_backup",
            resource_id=backup_id,
            details={"backup_path": str(backup_path)}
        )

        # 1. Database backup
        if request.include_database:
            try:
                db_backup_path = await _backup_database(
                    backup_path,
                    backup_id,
                    request.backup_type
                )
                backup_status["components"]["database"] = {
                    "status": "completed",
                    "path": str(db_backup_path),
                    "size_bytes": db_backup_path.stat().st_size
                }
                backup_status["total_size_bytes"] += db_backup_path.stat().st_size
            except Exception as e:
                backup_status["components"]["database"] = {
                    "status": "failed",
                    "error": str(e)
                }
                backup_status["errors"].append(f"Database backup failed: {str(e)}")

        # 2. Configuration files backup
        if request.include_configs:
            try:
                config_backup_path = await _backup_configurations(
                    backup_path,
                    backup_id
                )
                backup_status["components"]["configurations"] = {
                    "status": "completed",
                    "path": str(config_backup_path),
                    "size_bytes": _get_directory_size(config_backup_path)
                }
                backup_status["total_size_bytes"] += _get_directory_size(config_backup_path)
            except Exception as e:
                backup_status["components"]["configurations"] = {
                    "status": "failed",
                    "error": str(e)
                }
                backup_status["errors"].append(f"Configuration backup failed: {str(e)}")

        # 3. Logs backup
        if request.include_logs:
            try:
                logs_backup_path = await _backup_logs(
                    backup_path,
                    backup_id,
                    days_to_include=7  # Last 7 days of logs
                )
                backup_status["components"]["logs"] = {
                    "status": "completed",
                    "path": str(logs_backup_path),
                    "size_bytes": _get_directory_size(logs_backup_path)
                }
                backup_status["total_size_bytes"] += _get_directory_size(logs_backup_path)
            except Exception as e:
                backup_status["components"]["logs"] = {
                    "status": "failed",
                    "error": str(e)
                }
                backup_status["errors"].append(f"Logs backup failed: {str(e)}")

        # 4. Vault backup (secrets metadata only, not actual secrets)
        if request.include_vault:
            try:
                vault_backup_path = await _backup_vault_metadata(
                    backup_path,
                    backup_id,
                    vault
                )
                backup_status["components"]["vault"] = {
                    "status": "completed",
                    "path": str(vault_backup_path),
                    "size_bytes": vault_backup_path.stat().st_size
                }
                backup_status["total_size_bytes"] += vault_backup_path.stat().st_size
            except Exception as e:
                backup_status["components"]["vault"] = {
                    "status": "failed",
                    "error": str(e)
                }
                backup_status["errors"].append(f"Vault backup failed: {str(e)}")

        # 5. Create compressed archive
        try:
            archive_path = await _create_backup_archive(
                backup_path,
                backup_id,
                request.compression_enabled,
                request.encryption_enabled,
                vault
            )
            backup_status["archive_path"] = str(archive_path)
            backup_status["archive_size_bytes"] = archive_path.stat().st_size
        except Exception as e:
            backup_status["errors"].append(f"Archive creation failed: {str(e)}")
            raise

        # 6. Upload to cloud storage (if configured)
        try:
            cloud_url = await _upload_backup_to_cloud(
                archive_path,
                backup_id
            )
            if cloud_url:
                backup_status["cloud_url"] = cloud_url
        except Exception as e:
            backup_status["errors"].append(f"Cloud upload failed: {str(e)}")
            # Don't fail the entire backup for cloud upload failure

        # 7. Store backup metadata in database
        try:
            from src.db.models import SystemBackup
            backup_record = SystemBackup(
                backup_id=backup_id,
                backup_type=request.backup_type,
                components=list(backup_status["components"].keys()),
                file_path=str(archive_path),
                cloud_url=backup_status.get("cloud_url"),
                size_bytes=backup_status["archive_size_bytes"],
                compression_enabled=request.compression_enabled,
                encryption_enabled=request.encryption_enabled,
                retention_until=datetime.utcnow() + timedelta(days=request.retention_days),
                status="completed" if not backup_status["errors"] else "completed_with_errors",
                created_by=user_id,
                metadata=backup_status
            )
            db.add(backup_record)
            await db.commit()
        except Exception as e:
            backup_status["errors"].append(f"Database record creation failed: {str(e)}")

        # Update final status
        backup_status["status"] = "completed" if not backup_status["errors"] else "completed_with_errors"
        backup_status["completed_at"] = datetime.utcnow().isoformat()

        await redis.setex(
            f"backup_status:{backup_id}",
            86400,  # 24 hours TTL for completed backups
            json.dumps(backup_status)
        )

        await audit.log_event(
            user_id=user_id,
            action="backup_completed",
            resource_type="system_backup",
            resource_id=backup_id,
            details={
                "status": backup_status["status"],
                "components": list(backup_status["components"].keys()),
                "total_size_bytes": backup_status["total_size_bytes"],
                "errors_count": len(backup_status["errors"])
            }
        )

    except Exception as e:
        backup_status["status"] = "failed"
        backup_status["completed_at"] = datetime.utcnow().isoformat()
        backup_status["errors"].append(f"Backup failed: {str(e)}")

        await redis.setex(
            f"backup_status:{backup_id}",
            86400,
            json.dumps(backup_status)
        )

        await audit.log_error(
            error_type="backup_error",
            error_message=str(e),
            context={
                "backup_id": backup_id,
                "user_id": str(user_id)
            }
        )

    finally:
        # Cleanup temporary directory
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                await audit.log_error(
                    error_type="backup_cleanup_error",
                    error_message=f"Failed to cleanup temp directory: {str(e)}",
                    context={"backup_id": backup_id, "temp_dir": temp_dir}
                )


async def _backup_database(
    backup_path: Path,
    backup_id: str,
    backup_type: str
) -> Path:
    """
    Backup PostgreSQL database
    """
    db_backup_dir = backup_path / "database"
    db_backup_dir.mkdir(exist_ok=True)

    # Database connection info from settings
    db_url = settings.DATABASE_URL
    db_params = {}

    # Parse database URL
    if "postgresql://" in db_url or "postgres://" in db_url:
        import urllib.parse
        parsed = urllib.parse.urlparse(db_url)
        db_params = {
            "host": parsed.hostname,
            "port": parsed.port or 5432,
            "database": parsed.path.lstrip('/'),
            "username": parsed.username,
            "password": parsed.password
        }

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    dump_file = db_backup_dir / f"catnet_db_{backup_type}_{timestamp}.sql"

    # Build pg_dump command
    cmd = [
        "pg_dump",
        "-h", str(db_params["host"]),
        "-p", str(db_params["port"]),
        "-U", db_params["username"],
        "-d", db_params["database"],
        "-f", str(dump_file),
        "--verbose",
        "--no-password"
    ]

    # Add backup type specific options
    if backup_type == "full":
        cmd.extend(["--clean", "--create", "--if-exists"])
    elif backup_type == "incremental":
        # For incremental, we'll backup only recent changes
        # This is simplified - in production you'd use WAL archiving
        cmd.extend(["--data-only"])

    # Set password via environment variable
    env = os.environ.copy()
    env["PGPASSWORD"] = db_params["password"]

    # Execute pg_dump
    process = await asyncio.create_subprocess_exec(
        *cmd,
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        raise Exception(f"Database backup failed: {stderr.decode()}")

    return dump_file


async def _backup_configurations(
    backup_path: Path,
    backup_id: str
) -> Path:
    """
    Backup configuration files and settings
    """
    config_backup_dir = backup_path / "configurations"
    config_backup_dir.mkdir(exist_ok=True)

    # Directories to backup
    config_sources = [
        "/app/configs",  # Application configs
        "/app/src/core",  # Core configuration modules
        "/etc/catnet",   # System configs (if exists)
        "./configs"       # Local configs
    ]

    for source in config_sources:
        source_path = Path(source)
        if source_path.exists():
            dest_path = config_backup_dir / source_path.name
            if source_path.is_dir():
                shutil.copytree(source_path, dest_path, ignore=shutil.ignore_patterns('*.pyc', '__pycache__'))
            else:
                shutil.copy2(source_path, dest_path)

    # Backup environment variables (sanitized)
    env_file = config_backup_dir / "environment_vars.json"
    sensitive_patterns = ["password", "secret", "key", "token", "credential"]

    env_backup = {}
    for key, value in os.environ.items():
        if key.startswith("CATNET_") or key.startswith("APP_"):
            # Mask sensitive values
            if any(pattern.lower() in key.lower() for pattern in sensitive_patterns):
                env_backup[key] = "***MASKED***"
            else:
                env_backup[key] = value

    with open(env_file, 'w') as f:
        json.dump(env_backup, f, indent=2)

    return config_backup_dir


async def _backup_logs(
    backup_path: Path,
    backup_id: str,
    days_to_include: int = 7
) -> Path:
    """
    Backup log files
    """
    logs_backup_dir = backup_path / "logs"
    logs_backup_dir.mkdir(exist_ok=True)

    # Log directories to backup
    log_sources = [
        "/var/log/catnet",
        "/app/logs",
        "./logs"
    ]

    cutoff_date = datetime.utcnow() - timedelta(days=days_to_include)

    for source in log_sources:
        source_path = Path(source)
        if source_path.exists():
            dest_path = logs_backup_dir / source_path.name
            dest_path.mkdir(exist_ok=True)

            # Copy log files modified within the specified days
            for log_file in source_path.rglob("*.log*"):
                if log_file.is_file():
                    mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
                    if mtime >= cutoff_date:
                        relative_path = log_file.relative_to(source_path)
                        dest_file = dest_path / relative_path
                        dest_file.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(log_file, dest_file)

    return logs_backup_dir


async def _backup_vault_metadata(
    backup_path: Path,
    backup_id: str,
    vault
) -> Path:
    """
    Backup Vault metadata (NOT the actual secrets)
    """
    vault_backup_file = backup_path / "vault_metadata.json"

    try:
        # Get list of secret paths (not the actual secrets)
        secret_paths = await vault.list_secrets()

        vault_metadata = {
            "backup_id": backup_id,
            "backup_time": datetime.utcnow().isoformat(),
            "vault_server": vault.vault_url,
            "secret_count": len(secret_paths),
            "secret_paths": secret_paths,
            "note": "This backup contains only metadata, not actual secret values"
        }

        with open(vault_backup_file, 'w') as f:
            json.dump(vault_metadata, f, indent=2)

    except Exception as e:
        # If we can't access Vault, create a minimal metadata file
        vault_metadata = {
            "backup_id": backup_id,
            "backup_time": datetime.utcnow().isoformat(),
            "error": f"Could not access Vault: {str(e)}",
            "note": "Vault backup failed - secrets not included"
        }

        with open(vault_backup_file, 'w') as f:
            json.dump(vault_metadata, f, indent=2)

    return vault_backup_file


async def _create_backup_archive(
    backup_path: Path,
    backup_id: str,
    compression_enabled: bool,
    encryption_enabled: bool,
    vault
) -> Path:
    """
    Create compressed and optionally encrypted archive
    """
    archive_name = f"{backup_id}.tar.gz" if compression_enabled else f"{backup_id}.tar"
    archive_path = backup_path.parent / archive_name

    # Create tar archive
    mode = "w:gz" if compression_enabled else "w"

    with tarfile.open(archive_path, mode) as tar:
        tar.add(backup_path, arcname=backup_id)

    # Encrypt if requested
    if encryption_enabled:
        try:
            from src.security.encryption import EncryptionManager
            encryption_manager = EncryptionManager(vault)

            # Read archive
            with open(archive_path, 'rb') as f:
                archive_data = f.read()

            # Encrypt
            encrypted_data = await encryption_manager.encrypt(archive_data)

            # Write encrypted archive
            encrypted_path = archive_path.with_suffix(archive_path.suffix + '.enc')
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)

            # Remove unencrypted archive
            os.remove(archive_path)
            archive_path = encrypted_path

        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")

    return archive_path


async def _upload_backup_to_cloud(
    archive_path: Path,
    backup_id: str
) -> Optional[str]:
    """
    Upload backup to cloud storage (S3, Azure Blob, etc.)
    """
    try:
        # Check if cloud storage is configured
        cloud_config = getattr(settings, 'BACKUP_CLOUD_CONFIG', None)
        if not cloud_config:
            return None

        if cloud_config.get('provider') == 'aws_s3':
            return await _upload_to_s3(archive_path, backup_id, cloud_config)
        elif cloud_config.get('provider') == 'azure_blob':
            return await _upload_to_azure_blob(archive_path, backup_id, cloud_config)
        # Add other providers as needed

    except Exception as e:
        raise Exception(f"Cloud upload failed: {str(e)}")

    return None


async def _upload_to_s3(
    archive_path: Path,
    backup_id: str,
    config: Dict[str, Any]
) -> str:
    """
    Upload backup to AWS S3
    """
    s3_client = boto3.client(
        's3',
        aws_access_key_id=config['access_key_id'],
        aws_secret_access_key=config['secret_access_key'],
        region_name=config.get('region', 'us-east-1')
    )

    bucket = config['bucket']
    key = f"catnet-backups/{datetime.utcnow().strftime('%Y/%m/%d')}/{backup_id}/{archive_path.name}"

    # Upload file
    s3_client.upload_file(
        str(archive_path),
        bucket,
        key,
        ExtraArgs={
            'ServerSideEncryption': 'AES256',
            'Metadata': {
                'backup-id': backup_id,
                'created-by': 'catnet',
                'backup-time': datetime.utcnow().isoformat()
            }
        }
    )

    return f"s3://{bucket}/{key}"


async def _upload_to_azure_blob(
    archive_path: Path,
    backup_id: str,
    config: Dict[str, Any]
) -> str:
    """
    Upload backup to Azure Blob Storage
    """
    from azure.storage.blob import BlobServiceClient

    blob_service_client = BlobServiceClient(
        account_url=f"https://{config['account_name']}.blob.core.windows.net",
        credential=config['account_key']
    )

    container = config['container']
    blob_name = f"catnet-backups/{datetime.utcnow().strftime('%Y/%m/%d')}/{backup_id}/{archive_path.name}"

    # Upload file
    with open(archive_path, 'rb') as data:
        blob_service_client.get_blob_client(
            container=container,
            blob=blob_name
        ).upload_blob(
            data,
            overwrite=True,
            metadata={
                'backup_id': backup_id,
                'created_by': 'catnet',
                'backup_time': datetime.utcnow().isoformat()
            }
        )

    return f"azure://{config['account_name']}.blob.core.windows.net/{container}/{blob_name}"


def _get_directory_size(path: Path) -> int:
    """
    Calculate total size of directory
    """
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for filename in filenames:
            file_path = Path(dirpath) / filename
            if file_path.exists():
                total_size += file_path.stat().st_size
    return total_size