"""Common API dependencies"""

from typing import Optional, Annotated
from fastapi import Depends, Header, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import uuid

from src.db import get_db
from src.db.models import User
from src.security.auth import auth_manager, authz_manager
from src.security.audit import audit_logger
from src.api import UnauthorizedError, ForbiddenError

# Security scheme
security_scheme = HTTPBearer()


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Get current authenticated user from JWT token

    Args:
        request: FastAPI request object
        credentials: Bearer token from header
        db: Database session

    Returns:
        Current user object

    Raises:
        UnauthorizedError: If authentication fails
    """
    try:
        # Verify token
        payload = auth_manager.verify_token(credentials.credentials)
        user_id = payload.get("sub")

        if not user_id:
            raise UnauthorizedError("Invalid authentication credentials")

        # Get user from database
        stmt = select(User).where(User.id == uuid.UUID(user_id))
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user or not user.is_active:
            raise UnauthorizedError("User account is not active")

        # Log successful authentication
        await audit_logger.log_authentication_attempt(
            username=user.username,
            success=True,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("User-Agent")
        )

        return user

    except Exception as e:
        # Log failed authentication
        await audit_logger.log_authentication_attempt(
            username="unknown",
            success=False,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("User-Agent"),
            error_message=str(e)
        )
        raise UnauthorizedError("Could not validate credentials")


async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current active user"""
    if not current_user.is_active:
        raise UnauthorizedError("Inactive user")
    return current_user


async def get_current_superuser(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current superuser"""
    if not current_user.is_superuser:
        raise ForbiddenError("Not enough permissions")
    return current_user


def require_permission(permission: str):
    """
    Dependency to require specific permission

    Args:
        permission: Required permission string

    Returns:
        Dependency function
    """
    async def check_permission(
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db)
    ) -> User:
        try:
            await authz_manager.authorize_action(
                db=db,
                user=current_user,
                action=permission
            )
            return current_user
        except Exception:
            raise ForbiddenError(f"Missing required permission: {permission}")

    return check_permission


async def get_request_id(
    x_request_id: Annotated[Optional[str], Header()] = None
) -> str:
    """Get or generate request ID for correlation"""
    if x_request_id:
        return x_request_id
    return str(uuid.uuid4())


async def get_client_info(request: Request) -> dict:
    """Extract client information from request"""
    return {
        "ip_address": request.client.host if request.client else None,
        "user_agent": request.headers.get("User-Agent"),
        "referer": request.headers.get("Referer"),
        "origin": request.headers.get("Origin"),
    }


class RateLimitDependency:
    """Rate limiting dependency"""

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._request_counts: dict = {}

    async def __call__(
        self,
        request: Request,
        current_user: User = Depends(get_current_user)
    ) -> None:
        """Check rate limit for user"""
        user_key = str(current_user.id)
        current_time = request.headers.get("X-Timestamp", "0")

        # Simplified rate limiting (in production, use Redis)
        if user_key not in self._request_counts:
            self._request_counts[user_key] = []

        # Remove old timestamps
        cutoff_time = float(current_time) - self.window_seconds
        self._request_counts[user_key] = [
            t for t in self._request_counts[user_key] if t > cutoff_time
        ]

        # Check limit
        if len(self._request_counts[user_key]) >= self.max_requests:
            raise ForbiddenError("Rate limit exceeded")

        # Add current request
        self._request_counts[user_key].append(float(current_time))


# Rate limit instances
rate_limit_standard = RateLimitDependency(max_requests=100, window_seconds=60)
rate_limit_strict = RateLimitDependency(max_requests=10, window_seconds=60)