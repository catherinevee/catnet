from typing import List, Dict, Optional, Set
from enum import Enum
from functools import wraps
import structlog
from fastapi import HTTPException, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import uuid

from ..db.models import User, UserRole, AuditLog
from ..db.database import get_db

logger = structlog.get_logger()


class Permission(str, Enum):
    # Deployment permissions
    DEPLOYMENT_CREATE = "deployment.create"
    DEPLOYMENT_READ = "deployment.read"
    DEPLOYMENT_APPROVE = "deployment.approve"
    DEPLOYMENT_EXECUTE = "deployment.execute"
    DEPLOYMENT_ROLLBACK = "deployment.rollback"
    DEPLOYMENT_DELETE = "deployment.delete"

    # Device permissions
    DEVICE_CREATE = "device.create"
    DEVICE_READ = "device.read"
    DEVICE_UPDATE = "device.update"
    DEVICE_DELETE = "device.delete"
    DEVICE_CONNECT = "device.connect"
    DEVICE_EXECUTE_COMMAND = "device.execute_command"
    DEVICE_BACKUP = "device.backup"

    # Git repository permissions
    GIT_REPO_CREATE = "git_repo.create"
    GIT_REPO_READ = "git_repo.read"
    GIT_REPO_UPDATE = "git_repo.update"
    GIT_REPO_DELETE = "git_repo.delete"
    GIT_REPO_SYNC = "git_repo.sync"

    # User management permissions
    USER_CREATE = "user.create"
    USER_READ = "user.read"
    USER_UPDATE = "user.update"
    USER_DELETE = "user.delete"
    USER_RESET_PASSWORD = "user.reset_password"
    USER_MANAGE_ROLES = "user.manage_roles"

    # Audit and security permissions
    AUDIT_READ = "audit.read"
    AUDIT_EXPORT = "audit.export"
    SECURITY_READ = "security.read"
    SECURITY_MANAGE = "security.manage"

    # Configuration permissions
    CONFIG_VALIDATE = "config.validate"
    CONFIG_ENCRYPT = "config.encrypt"
    CONFIG_DECRYPT = "config.decrypt"

    # System permissions
    SYSTEM_HEALTH = "system.health"
    SYSTEM_METRICS = "system.metrics"
    SYSTEM_SETTINGS = "system.settings"
    SYSTEM_MAINTENANCE = "system.maintenance"


class PermissionChecker:
    def __init__(self):
        self.role_permissions: Dict[UserRole, Set[Permission]] = {
            UserRole.VIEWER: {
                Permission.DEPLOYMENT_READ,
                Permission.DEVICE_READ,
                Permission.GIT_REPO_READ,
                Permission.CONFIG_VALIDATE,
                Permission.SYSTEM_HEALTH,
                Permission.SYSTEM_METRICS,
            },
            UserRole.OPERATOR: {
                Permission.DEPLOYMENT_CREATE,
                Permission.DEPLOYMENT_READ,
                Permission.DEPLOYMENT_EXECUTE,
                Permission.DEVICE_READ,
                Permission.DEVICE_CONNECT,
                Permission.DEVICE_BACKUP,
                Permission.GIT_REPO_READ,
                Permission.GIT_REPO_SYNC,
                Permission.CONFIG_VALIDATE,
                Permission.CONFIG_ENCRYPT,
                Permission.CONFIG_DECRYPT,
                Permission.SYSTEM_HEALTH,
                Permission.SYSTEM_METRICS,
            },
            UserRole.ADMIN: {
                # Admins get all permissions except audit management
                Permission.DEPLOYMENT_CREATE,
                Permission.DEPLOYMENT_READ,
                Permission.DEPLOYMENT_APPROVE,
                Permission.DEPLOYMENT_EXECUTE,
                Permission.DEPLOYMENT_ROLLBACK,
                Permission.DEPLOYMENT_DELETE,
                Permission.DEVICE_CREATE,
                Permission.DEVICE_READ,
                Permission.DEVICE_UPDATE,
                Permission.DEVICE_DELETE,
                Permission.DEVICE_CONNECT,
                Permission.DEVICE_EXECUTE_COMMAND,
                Permission.DEVICE_BACKUP,
                Permission.GIT_REPO_CREATE,
                Permission.GIT_REPO_READ,
                Permission.GIT_REPO_UPDATE,
                Permission.GIT_REPO_DELETE,
                Permission.GIT_REPO_SYNC,
                Permission.USER_CREATE,
                Permission.USER_READ,
                Permission.USER_UPDATE,
                Permission.USER_DELETE,
                Permission.USER_RESET_PASSWORD,
                Permission.USER_MANAGE_ROLES,
                Permission.CONFIG_VALIDATE,
                Permission.CONFIG_ENCRYPT,
                Permission.CONFIG_DECRYPT,
                Permission.SYSTEM_HEALTH,
                Permission.SYSTEM_METRICS,
                Permission.SYSTEM_SETTINGS,
                Permission.SYSTEM_MAINTENANCE,
                Permission.SECURITY_READ,
                Permission.SECURITY_MANAGE,
            },
            UserRole.AUDITOR: {
                # Auditors have read-only access to everything
                Permission.DEPLOYMENT_READ,
                Permission.DEVICE_READ,
                Permission.GIT_REPO_READ,
                Permission.USER_READ,
                Permission.AUDIT_READ,
                Permission.AUDIT_EXPORT,
                Permission.SECURITY_READ,
                Permission.CONFIG_VALIDATE,
                Permission.SYSTEM_HEALTH,
                Permission.SYSTEM_METRICS,
            },
        }

        # Custom permission overrides (loaded from database or config)
        self.custom_permissions: Dict[uuid.UUID, Set[Permission]] = {}

        # Permission dependencies
        self.permission_dependencies: Dict[Permission, Set[Permission]] = {
            Permission.DEPLOYMENT_EXECUTE: {Permission.DEPLOYMENT_READ},
            Permission.DEPLOYMENT_ROLLBACK: {Permission.DEPLOYMENT_READ},
            Permission.DEPLOYMENT_APPROVE: {Permission.DEPLOYMENT_READ},
            Permission.DEVICE_EXECUTE_COMMAND: {Permission.DEVICE_CONNECT, Permission.DEVICE_READ},
            Permission.DEVICE_BACKUP: {Permission.DEVICE_CONNECT, Permission.DEVICE_READ},
            Permission.GIT_REPO_SYNC: {Permission.GIT_REPO_READ},
            Permission.USER_MANAGE_ROLES: {Permission.USER_UPDATE, Permission.USER_READ},
            Permission.SECURITY_MANAGE: {Permission.SECURITY_READ},
        }

    def has_permission(
        self,
        user: User,
        permission: Permission,
        resource_owner: Optional[uuid.UUID] = None
    ) -> bool:
        # Superusers have all permissions
        if user.is_superuser:
            return True

        # Check custom user permissions first
        if user.id in self.custom_permissions:
            if permission in self.custom_permissions[user.id]:
                return True

        # Check role-based permissions
        role_perms = self.role_permissions.get(user.role, set())
        if permission in role_perms:
            # Check resource ownership if applicable
            if resource_owner and permission in [
                Permission.USER_UPDATE,
                Permission.USER_DELETE,
            ]:
                # Users can only modify their own profile unless admin
                if user.role != UserRole.ADMIN and user.id != resource_owner:
                    return False
            return True

        # Check if user has dependent permissions
        deps = self.permission_dependencies.get(permission, set())
        for dep in deps:
            if not self.has_permission(user, dep, resource_owner):
                return False

        return False

    def check_permissions(
        self,
        user: User,
        permissions: List[Permission],
        require_all: bool = True,
        resource_owner: Optional[uuid.UUID] = None
    ) -> bool:
        if require_all:
            # User must have all permissions
            return all(
                self.has_permission(user, perm, resource_owner)
                for perm in permissions
            )
        else:
            # User must have at least one permission
            return any(
                self.has_permission(user, perm, resource_owner)
                for perm in permissions
            )

    def get_user_permissions(self, user: User) -> Set[Permission]:
        if user.is_superuser:
            return set(Permission)

        permissions = self.role_permissions.get(user.role, set()).copy()

        # Add custom permissions
        if user.id in self.custom_permissions:
            permissions.update(self.custom_permissions[user.id])

        # Add dependent permissions
        resolved_permissions = permissions.copy()
        for perm in permissions:
            if perm in self.permission_dependencies:
                resolved_permissions.update(self.permission_dependencies[perm])

        return resolved_permissions

    async def grant_permission(
        self,
        db: AsyncSession,
        user_id: uuid.UUID,
        permission: Permission,
        granted_by: uuid.UUID
    ):
        if user_id not in self.custom_permissions:
            self.custom_permissions[user_id] = set()

        self.custom_permissions[user_id].add(permission)

        # Log the grant
        audit_log = AuditLog(
            user_id=granted_by,
            action="permission.grant",
            resource_type="user",
            resource_id=str(user_id),
            details={
                "permission": permission.value,
                "user_id": str(user_id)
            },
            success=True
        )
        db.add(audit_log)
        await db.commit()

    async def revoke_permission(
        self,
        db: AsyncSession,
        user_id: uuid.UUID,
        permission: Permission,
        revoked_by: uuid.UUID
    ):
        if user_id in self.custom_permissions:
            self.custom_permissions[user_id].discard(permission)

        # Log the revocation
        audit_log = AuditLog(
            user_id=revoked_by,
            action="permission.revoke",
            resource_type="user",
            resource_id=str(user_id),
            details={
                "permission": permission.value,
                "user_id": str(user_id)
            },
            success=True
        )
        db.add(audit_log)
        await db.commit()


# Global permission checker instance
permission_checker = PermissionChecker()


def require_permissions(
    permissions: List[Permission],
    require_all: bool = True,
    resource_owner_param: Optional[str] = None
):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            from .auth_service import get_current_user

            # Get current user from kwargs
            user = kwargs.get('current_user')
            if not user:
                # Try to get from dependencies
                for arg in args:
                    if isinstance(arg, User):
                        user = arg
                        break

            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )

            # Get resource owner if specified
            resource_owner = None
            if resource_owner_param:
                resource_owner = kwargs.get(resource_owner_param)

            # Check permissions
            if not permission_checker.check_permissions(
                user, permissions, require_all, resource_owner
            ):
                await logger.awarning(
                    "Permission denied",
                    user_id=str(user.id),
                    permissions=[p.value for p in permissions],
                    require_all=require_all
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions"
                )

            return await func(*args, **kwargs)
        return wrapper
    return decorator


class PermissionDependency:
    def __init__(
        self,
        permissions: List[Permission],
        require_all: bool = True
    ):
        self.permissions = permissions
        self.require_all = require_all

    async def __call__(
        self,
        user: User = Depends(),
        db: AsyncSession = Depends(get_db)
    ) -> User:
        if not permission_checker.check_permissions(
            user, self.permissions, self.require_all
        ):
            # Log the permission denial
            audit_log = AuditLog(
                user_id=user.id,
                action="permission.denied",
                details={
                    "required_permissions": [p.value for p in self.permissions],
                    "require_all": self.require_all,
                    "user_role": user.role.value
                },
                success=False,
                severity="warning"
            )
            db.add(audit_log)
            await db.commit()

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )

        return user