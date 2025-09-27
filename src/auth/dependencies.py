from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional, List
from sqlalchemy.orm import Session
import logging

from ..db.session import get_db
from ..db.models import User, UserRole
from .authentication import AuthenticationService
from .jwt_handler import JWTHandler

logger = logging.getLogger(__name__)

security = HTTPBearer()

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    token = credentials.credentials
    auth_service = AuthenticationService(db)

    user = await auth_service.validate_token(token)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )

    return user

async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def require_role(allowed_roles: List[UserRole]):
    async def role_checker(
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        if current_user.is_superuser:
            return current_user

        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient privileges"
            )
        return current_user
    return role_checker

def require_permission(resource: str, action: str):
    async def permission_checker(
        current_user: User = Depends(get_current_active_user),
        db: Session = Depends(get_db)
    ) -> User:
        if current_user.is_superuser:
            return current_user

        auth_service = AuthenticationService(db)
        has_permission = await auth_service.check_permission(
            current_user,
            resource,
            action
        )

        if not has_permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission: {resource}:{action}"
            )

        return current_user
    return permission_checker

async def get_optional_current_user(
    authorization: Optional[str] = None,
    db: Session = Depends(get_db)
) -> Optional[User]:
    if not authorization or not authorization.startswith("Bearer "):
        return None

    token = authorization.replace("Bearer ", "")
    auth_service = AuthenticationService(db)
    return await auth_service.validate_token(token)