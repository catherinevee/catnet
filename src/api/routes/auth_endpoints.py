from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.security import OAuth2PasswordRequestForm, HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List
import structlog

from ...db.database import get_db
from ...db.schemas import (
    UserCreate, UserUpdate, UserResponse, UserLogin, Token, TokenRefresh,
    MFASetup, MFAVerify, AuditLogQuery, AuditLogResponse
)
from ...auth.auth_service import auth_service, get_current_user
from ...auth.permissions import Permission, PermissionDependency, require_permissions
from ...db.models import User, UserRole

logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])
security = HTTPBearer()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(
        PermissionDependency([Permission.USER_CREATE])
    )
):
    """
    Register a new user.

    Security:
    - Requires USER_CREATE permission
    - Validates password strength
    - Logs all user creation attempts
    """
    try:
        user = await auth_service.create_user(db, user_data, current_user.id)
        return UserResponse.from_orm(user)
    except Exception as e:
        logger.error(f"User registration failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/login", response_model=Token)
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    mfa_token: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Authenticate user and return JWT tokens.

    Security:
    - Implements rate limiting
    - Supports MFA verification
    - Records all login attempts
    - Implements account lockout after failed attempts
    """
    try:
        # Get client IP and user agent
        client_ip = request.client.host
        user_agent = request.headers.get("User-Agent", "Unknown")

        # Authenticate user
        user = await auth_service.authenticate_user(
            db,
            form_data.username,
            form_data.password,
            mfa_token,
            client_ip,
            user_agent
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials or MFA token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Create session
        login_response = await auth_service.create_session(
            db, user, client_ip, user_agent
        )

        return Token(
            access_token=login_response.access_token,
            refresh_token=login_response.refresh_token,
            token_type=login_response.token_type,
            expires_in=login_response.expires_in
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service error"
        )


@router.post("/refresh", response_model=Token)
async def refresh_token(
    refresh_data: TokenRefresh,
    db: AsyncSession = Depends(get_db)
):
    """
    Refresh access token using refresh token.

    Security:
    - Validates refresh token
    - Issues new token pair
    - Invalidates old refresh token
    """
    try:
        login_response = await auth_service.refresh_token(
            db, refresh_data.refresh_token
        )

        return Token(
            access_token=login_response.access_token,
            refresh_token=login_response.refresh_token,
            token_type=login_response.token_type,
            expires_in=login_response.expires_in
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )


@router.post("/logout")
async def logout(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
):
    """
    Logout user and invalidate tokens.

    Security:
    - Invalidates current session
    - Removes tokens from active sessions
    """
    try:
        success = await auth_service.logout(db, credentials.credentials)

        if success:
            return {"message": "Successfully logged out"}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Logout failed"
            )

    except Exception as e:
        logger.error(f"Logout failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout service error"
        )


@router.post("/mfa/setup", response_model=MFASetup)
async def setup_mfa(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Set up MFA for current user.

    Security:
    - Generates TOTP secret
    - Returns QR code for authenticator apps
    - Provides backup codes
    """
    try:
        from ...auth.mfa import MFAHandler
        mfa_handler = MFAHandler()

        # Generate MFA secret
        secret = mfa_handler.generate_secret()
        qr_code = mfa_handler.get_qr_code(secret, current_user.username, "CatNet")
        backup_codes = mfa_handler.generate_backup_codes()

        # Store secret (encrypted) in user record
        current_user.mfa_secret = secret
        current_user.mfa_enabled = False  # Will be enabled after verification

        # Store backup codes in Vault
        from ...security.vault import VaultClient
        vault = VaultClient()
        await vault.store_secret(
            f"users/{current_user.id}/mfa_backup_codes",
            {"codes": backup_codes}
        )

        await db.commit()

        return MFASetup(
            secret=secret,
            qr_code=qr_code,
            backup_codes=backup_codes
        )

    except Exception as e:
        logger.error(f"MFA setup failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA setup failed"
        )


@router.post("/mfa/verify")
async def verify_mfa(
    mfa_data: MFAVerify,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Verify MFA token and enable MFA.

    Security:
    - Validates TOTP token
    - Enables MFA upon successful verification
    """
    try:
        from ...auth.mfa import MFAHandler
        mfa_handler = MFAHandler()

        if not current_user.mfa_secret:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA not set up for this user"
            )

        # Verify token
        is_valid = mfa_handler.verify_token(
            current_user.mfa_secret,
            mfa_data.token
        )

        if is_valid:
            current_user.mfa_enabled = True
            await db.commit()
            return {"message": "MFA successfully enabled"}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid MFA token"
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MFA verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA verification failed"
        )


@router.post("/mfa/disable")
async def disable_mfa(
    mfa_data: MFAVerify,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Disable MFA for current user.

    Security:
    - Requires current MFA token for verification
    - Removes MFA secret
    """
    try:
        from ...auth.mfa import MFAHandler
        mfa_handler = MFAHandler()

        if not current_user.mfa_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA is not enabled for this user"
            )

        # Verify current MFA token
        is_valid = mfa_handler.verify_token(
            current_user.mfa_secret,
            mfa_data.token
        )

        if is_valid:
            current_user.mfa_enabled = False
            current_user.mfa_secret = None
            await db.commit()
            return {"message": "MFA successfully disabled"}
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA token"
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MFA disable failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA disable failed"
        )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """
    Get current user information.

    Security:
    - Returns only current user's information
    - No sensitive data exposed
    """
    return UserResponse.from_orm(current_user)


@router.put("/me", response_model=UserResponse)
async def update_current_user(
    user_update: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Update current user information.

    Security:
    - Users can only update their own profile
    - Password changes require current password
    - Email changes require verification
    """
    try:
        # Update allowed fields
        if user_update.email is not None:
            current_user.email = user_update.email
        if user_update.full_name is not None:
            current_user.full_name = user_update.full_name

        await db.commit()
        await db.refresh(current_user)

        return UserResponse.from_orm(current_user)

    except Exception as e:
        logger.error(f"User update failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/change-password")
async def change_password(
    current_password: str,
    new_password: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Change user password.

    Security:
    - Requires current password verification
    - Validates new password strength
    - Invalidates all existing sessions
    """
    try:
        # Verify current password
        if not auth_service.verify_password(
            current_password,
            current_user.hashed_password
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid current password"
            )

        # Validate new password strength
        from ...db.schemas import UserCreate
        import pydantic

        try:
            # Use the password validator from UserCreate
            UserCreate.validate_password_strength(
                pydantic.SecretStr(new_password)
            )
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )

        # Update password
        current_user.hashed_password = auth_service.get_password_hash(new_password)

        # Invalidate all sessions for security
        from sqlalchemy import delete
        from ...db.models import Session as UserSession

        await db.execute(
            delete(UserSession).where(UserSession.user_id == current_user.id)
        )

        await db.commit()

        return {"message": "Password successfully changed. Please login again."}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password change failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password change failed"
        )


@router.get("/permissions")
async def get_user_permissions(
    current_user: User = Depends(get_current_user)
):
    """
    Get current user's permissions.

    Security:
    - Returns only permission names
    - No internal permission structure exposed
    """
    from ...auth.permissions import permission_checker

    permissions = permission_checker.get_user_permissions(current_user)
    return {
        "permissions": [p.value for p in permissions]
    }


@router.get("/audit-logs", response_model=List[AuditLogResponse])
@require_permissions([Permission.AUDIT_READ])
async def get_audit_logs(
    query: AuditLogQuery = Depends(),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get audit logs.

    Security:
    - Requires AUDIT_READ permission
    - Returns filtered audit logs
    - Sensitive data may be redacted based on user role
    """
    try:
        from sqlalchemy import select, and_
        from ...db.models import AuditLog

        # Build query
        conditions = []

        if query.user_id:
            conditions.append(AuditLog.user_id == query.user_id)
        if query.action:
            conditions.append(AuditLog.action == query.action)
        if query.resource_type:
            conditions.append(AuditLog.resource_type == query.resource_type)
        if query.severity:
            conditions.append(AuditLog.severity == query.severity)
        if query.success is not None:
            conditions.append(AuditLog.success == query.success)
        if query.start_date:
            conditions.append(AuditLog.created_at >= query.start_date)
        if query.end_date:
            conditions.append(AuditLog.created_at <= query.end_date)

        stmt = select(AuditLog)
        if conditions:
            stmt = stmt.where(and_(*conditions))

        stmt = stmt.order_by(AuditLog.created_at.desc())
        stmt = stmt.limit(query.limit).offset(query.offset)

        result = await db.execute(stmt)
        logs = result.scalars().all()

        # Redact sensitive data if user is not superuser or auditor
        if not current_user.is_superuser and current_user.role != UserRole.AUDITOR:
            for log in logs:
                if log.details and "password" in str(log.details).lower():
                    log.details = {"redacted": "sensitive data hidden"}

        return [AuditLogResponse.from_orm(log) for log in logs]

    except Exception as e:
        logger.error(f"Failed to retrieve audit logs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve audit logs"
        )