from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from typing import Optional, Dict, Any
from ..security.auth import AuthManager
from ..db.database import get_db
from ..db.models import User
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import os

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

auth_manager = AuthManager(
    secret_key=os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
)


async def get_current_user(
    token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = await auth_manager.verify_token(token, token_type="access")
        user_id: str = payload.get("sub")

        if user_id is None:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user"
        )

    return user


async def require_auth(
    permission: str, current_user: User = Depends(get_current_user)
) -> User:
    user_dict = {
        "sub": str(current_user.id),
        "username": current_user.username,
        "roles": current_user.roles,
    }

    if not await auth_manager.check_permission(user_dict, permission):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
        )

    return current_user


def require_roles(roles: list):
    async def role_checker(current_user: User = Depends(get_current_user)):
        if not any(role in current_user.roles for role in roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role privileges",
            )
        return current_user

    return role_checker
