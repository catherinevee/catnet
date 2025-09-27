"""
Authentication Router
Handles OAuth2, SAML, MFA, JWT tokens with comprehensive security
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from uuid import UUID
import secrets
import hashlib
import base64

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response, Body
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_, or_, func
from pydantic import BaseModel, EmailStr, Field, SecretStr, validator
import jwt
import pyotp
import qrcode
import io
import aioredis

from src.db.models import User, UserSession, AuditLog, SecurityIncident, MFADevice
from src.core.config import settings
from src.core.dependencies import (
    get_db,
    get_current_user,
    get_redis,
    get_vault,
    get_audit_logger
)
from src.security.audit import AuditLogger
from src.security.encryption import EncryptionManager
from src.auth.service import AuthenticationService
from src.core.exceptions import (
    SecurityError,
    AuthenticationError,
    AuthorizationError,
    MFARequiredError,
    AccountLockedException
)

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: SecretStr = Field(..., min_length=8)
    mfa_code: Optional[str] = Field(None, regex="^[0-9]{6}$")
    remember_me: bool = False

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str]
    token_type: str = "bearer"
    expires_in: int
    mfa_required: bool = False
    mfa_setup_required: bool = False
    user_id: UUID
    username: str
    roles: List[str]
    permissions: List[str]

class MFASetupRequest(BaseModel):
    password: SecretStr
    mfa_type: str = Field(default="totp", regex="^(totp|sms|email)$")
    backup_email: Optional[EmailStr]
    backup_phone: Optional[str]

class MFASetupResponse(BaseModel):
    mfa_type: str
    secret: Optional[str]
    qr_code: Optional[str]
    backup_codes: List[str]
    recovery_email: Optional[str]
    setup_verified: bool = False

class MFAVerifyRequest(BaseModel):
    session_token: str
    mfa_code: str = Field(..., regex="^[0-9]{6}$")
    trust_device: bool = False

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class PasswordChangeRequest(BaseModel):
    current_password: SecretStr
    new_password: SecretStr = Field(..., min_length=12)
    confirm_password: SecretStr
    logout_all_sessions: bool = True

    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    reset_token: str
    new_password: SecretStr = Field(..., min_length=12)
    confirm_password: SecretStr

class SessionInfo(BaseModel):
    session_id: UUID
    ip_address: str
    user_agent: str
    created_at: datetime
    last_activity: datetime
    is_current: bool
    location: Optional[str]
    device_trusted: bool


@router.post("/login", response_model=LoginResponse)
async def login(
    request: LoginRequest,
    req: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
    audit: AuditLogger = Depends(get_audit_logger),
    vault = Depends(get_vault)
) -> LoginResponse:
    """
    Authenticate user with username/password and optional MFA
    Implements progressive security with account lockout protection
    """

    client_ip = req.client.host
    user_agent = req.headers.get('user-agent', 'unknown')

    try:
        auth_service = AuthenticationService(db, redis, vault, audit)

        # Check for account lockout
        lockout_key = f"lockout:{request.username}"
        attempts = await redis.get(lockout_key)
        if attempts and int(attempts) >= settings.MAX_LOGIN_ATTEMPTS:
            await audit.log_security_event(
                event_type="account_locked",
                severity="high",
                details={
                    "username": request.username,
                    "ip_address": client_ip,
                    "reason": "max_attempts_exceeded"
                }
            )
            raise AccountLockedException("Account temporarily locked due to multiple failed attempts")

        # Authenticate user
        user = await auth_service.authenticate_user(
            username=request.username,
            password=request.password.get_secret_value()
        )

        if not user:
            # Increment failed attempts
            await redis.incr(lockout_key)
            await redis.expire(lockout_key, settings.LOCKOUT_DURATION_MINUTES * 60)

            await audit.log_security_event(
                event_type="login_failed",
                severity="medium",
                details={
                    "username": request.username,
                    "ip_address": client_ip,
                    "user_agent": user_agent
                }
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )

        # Clear failed attempts on successful authentication
        await redis.delete(lockout_key)

        # Check if MFA is required
        if user.mfa_enabled and not request.mfa_code:
            # Generate temporary session token for MFA
            session_token = secrets.token_urlsafe(32)
            await redis.set(
                f"mfa_session:{session_token}",
                str(user.id),
                ex=300  # 5 minutes
            )

            await audit.log_event(
                user_id=user.id,
                action="mfa_required",
                resource_type="authentication",
                details={
                    "ip_address": client_ip,
                    "requires_mfa": True
                }
            )

            return LoginResponse(
                access_token="",
                refresh_token=session_token,
                token_type="bearer",
                expires_in=0,
                mfa_required=True,
                mfa_setup_required=not user.mfa_secret,
                user_id=user.id,
                username=user.username,
                roles=[],
                permissions=[]
            )

        # Verify MFA if provided
        if user.mfa_enabled and request.mfa_code:
            mfa_valid = await auth_service.verify_mfa(user.id, request.mfa_code)
            if not mfa_valid:
                await audit.log_security_event(
                    event_type="mfa_failed",
                    severity="high",
                    details={
                        "user_id": str(user.id),
                        "ip_address": client_ip
                    }
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid MFA code"
                )

        # Generate tokens
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = await auth_service.create_access_token(
            user_id=user.id,
            expires_delta=access_token_expires
        )

        refresh_token = None
        if request.remember_me:
            refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
            refresh_token = await auth_service.create_refresh_token(
                user_id=user.id,
                expires_delta=refresh_token_expires
            )

        # Create session
        session = UserSession(
            user_id=user.id,
            token_hash=hashlib.sha256(access_token.encode()).hexdigest(),
            ip_address=client_ip,
            user_agent=user_agent,
            expires_at=datetime.utcnow() + access_token_expires,
            is_active=True
        )
        db.add(session)

        # Get user roles and permissions
        roles = [role.name for role in user.roles]
        permissions = []
        for role in user.roles:
            permissions.extend([perm.name for perm in role.permissions])

        # Update last login
        user.last_login = datetime.utcnow()
        user.login_count = (user.login_count or 0) + 1

        await db.commit()

        await audit.log_event(
            user_id=user.id,
            action="login_success",
            resource_type="authentication",
            details={
                "ip_address": client_ip,
                "user_agent": user_agent,
                "session_id": str(session.id)
            }
        )

        # Set secure cookie
        if refresh_token:
            response.set_cookie(
                key="refresh_token",
                value=refresh_token,
                max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
                secure=True,
                httponly=True,
                samesite="strict"
            )

        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            mfa_required=False,
            mfa_setup_required=False,
            user_id=user.id,
            username=user.username,
            roles=roles,
            permissions=list(set(permissions))
        )

    except (AccountLockedException, HTTPException):
        raise
    except Exception as e:
        await audit.log_error(
            error_type="login_error",
            error_message=str(e),
            context={
                "username": request.username,
                "ip_address": client_ip
            }
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service error"
        )


@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(
    request: MFASetupRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit: AuditLogger = Depends(get_audit_logger),
    vault = Depends(get_vault)
) -> MFASetupResponse:
    """
    Setup MFA for user account
    Supports TOTP, SMS, and email methods
    """

    auth_service = AuthenticationService(db, audit, vault)

    # Verify password before MFA setup
    if not await auth_service.verify_password(
        current_user,
        request.password.get_secret_value()
    ):
        await audit.log_security_event(
            event_type="mfa_setup_failed",
            severity="medium",
            user_id=current_user.id,
            details={"reason": "invalid_password"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password"
        )

    # Generate MFA secret
    if request.mfa_type == "totp":
        # Generate TOTP secret
        secret = pyotp.random_base32()

        # Generate QR code
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=current_user.email,
            issuer_name='CatNet'
        )

        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)

        img_buffer = io.BytesIO()
        qr.make_image(fill_color="black", back_color="white").save(img_buffer, format='PNG')
        qr_code_base64 = base64.b64encode(img_buffer.getvalue()).decode()

        # Generate backup codes
        backup_codes = [secrets.token_hex(4) for _ in range(10)]
        backup_codes_hash = [
            hashlib.sha256(code.encode()).hexdigest()
            for code in backup_codes
        ]

        # Store MFA device info
        mfa_device = MFADevice(
            user_id=current_user.id,
            device_type=request.mfa_type,
            device_name="Primary TOTP",
            secret_encrypted=await vault.encrypt(secret),
            backup_codes=backup_codes_hash,
            is_primary=True,
            is_verified=False
        )
        db.add(mfa_device)

        # Update user
        current_user.mfa_secret = await vault.encrypt(secret)
        current_user.mfa_backup_codes = backup_codes_hash
        current_user.backup_email = request.backup_email
        current_user.backup_phone = request.backup_phone

        await db.commit()

        await audit.log_event(
            user_id=current_user.id,
            action="mfa_setup_initiated",
            resource_type="security",
            details={
                "mfa_type": request.mfa_type,
                "device_id": str(mfa_device.id)
            }
        )

        return MFASetupResponse(
            mfa_type=request.mfa_type,
            secret=secret,
            qr_code=f"data:image/png;base64,{qr_code_base64}",
            backup_codes=backup_codes,
            recovery_email=request.backup_email,
            setup_verified=False
        )

    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"MFA type {request.mfa_type} not yet implemented"
        )


@router.post("/mfa/verify")
async def verify_mfa(
    request: MFAVerifyRequest,
    req: Request,
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
    audit: AuditLogger = Depends(get_audit_logger),
    vault = Depends(get_vault)
) -> LoginResponse:
    """
    Verify MFA code and complete login
    """

    # Get user from MFA session
    user_id = await redis.get(f"mfa_session:{request.session_token}")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA session"
        )

    # Get user
    user = await db.get(User, UUID(user_id))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    auth_service = AuthenticationService(db, redis, vault, audit)

    # Verify MFA code
    mfa_valid = await auth_service.verify_mfa(user.id, request.mfa_code)
    if not mfa_valid:
        await audit.log_security_event(
            event_type="mfa_verification_failed",
            severity="high",
            user_id=user.id,
            details={
                "ip_address": req.client.host
            }
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA code"
        )

    # Clear MFA session
    await redis.delete(f"mfa_session:{request.session_token}")

    # Mark device as trusted if requested
    if request.trust_device:
        device_token = secrets.token_urlsafe(32)
        await redis.set(
            f"trusted_device:{user.id}:{device_token}",
            req.headers.get('user-agent', 'unknown'),
            ex=30 * 24 * 60 * 60  # 30 days
        )

    # Generate tokens
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = await auth_service.create_access_token(
        user_id=user.id,
        expires_delta=access_token_expires
    )

    refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_token = await auth_service.create_refresh_token(
        user_id=user.id,
        expires_delta=refresh_token_expires
    )

    # Create session
    session = UserSession(
        user_id=user.id,
        token_hash=hashlib.sha256(access_token.encode()).hexdigest(),
        ip_address=req.client.host,
        user_agent=req.headers.get('user-agent', 'unknown'),
        expires_at=datetime.utcnow() + access_token_expires,
        is_active=True,
        mfa_verified=True
    )
    db.add(session)

    # Get roles and permissions
    roles = [role.name for role in user.roles]
    permissions = []
    for role in user.roles:
        permissions.extend([perm.name for perm in role.permissions])

    await db.commit()

    await audit.log_event(
        user_id=user.id,
        action="mfa_verification_success",
        resource_type="authentication",
        details={
            "session_id": str(session.id),
            "device_trusted": request.trust_device
        }
    )

    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        mfa_required=False,
        mfa_setup_required=False,
        user_id=user.id,
        username=user.username,
        roles=roles,
        permissions=list(set(permissions))
    )


@router.post("/refresh", response_model=LoginResponse)
async def refresh_token(
    request: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
    audit: AuditLogger = Depends(get_audit_logger),
    vault = Depends(get_vault)
) -> LoginResponse:
    """
    Refresh access token using refresh token
    """

    auth_service = AuthenticationService(db, redis, vault, audit)

    try:
        # Verify refresh token
        payload = jwt.decode(
            request.refresh_token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )

        user_id = UUID(payload.get("sub"))
        token_type = payload.get("type")

        if token_type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )

        # Get user
        user = await db.get(User, user_id)
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid user"
            )

        # Generate new access token
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = await auth_service.create_access_token(
            user_id=user.id,
            expires_delta=access_token_expires
        )

        # Get roles and permissions
        roles = [role.name for role in user.roles]
        permissions = []
        for role in user.roles:
            permissions.extend([perm.name for perm in role.permissions])

        await audit.log_event(
            user_id=user.id,
            action="token_refreshed",
            resource_type="authentication",
            details={"new_token_expires": str(datetime.utcnow() + access_token_expires)}
        )

        return LoginResponse(
            access_token=access_token,
            refresh_token=request.refresh_token,  # Keep same refresh token
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            mfa_required=False,
            mfa_setup_required=False,
            user_id=user.id,
            username=user.username,
            roles=roles,
            permissions=list(set(permissions))
        )

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )


@router.delete("/logout")
async def logout(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
    audit: AuditLogger = Depends(get_audit_logger)
) -> Dict[str, str]:
    """
    Logout user and invalidate session
    """

    # Invalidate all active sessions
    result = await db.execute(
        update(UserSession)
        .where(
            and_(
                UserSession.user_id == current_user.id,
                UserSession.is_active == True
            )
        )
        .values(is_active=False, revoked_at=datetime.utcnow())
    )

    # Clear cache
    await redis.delete(f"user:{current_user.id}")
    await redis.delete(f"permissions:{current_user.id}")

    await db.commit()

    await audit.log_event(
        user_id=current_user.id,
        action="logout",
        resource_type="authentication",
        details={"sessions_invalidated": result.rowcount}
    )

    return {"message": "Logged out successfully"}


@router.post("/password/change")
async def change_password(
    request: PasswordChangeRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
    audit: AuditLogger = Depends(get_audit_logger),
    vault = Depends(get_vault)
) -> Dict[str, str]:
    """
    Change user password with strong validation
    """

    auth_service = AuthenticationService(db, redis, vault, audit)

    # Verify current password
    if not await auth_service.verify_password(
        current_user,
        request.current_password.get_secret_value()
    ):
        await audit.log_security_event(
            event_type="password_change_failed",
            severity="medium",
            user_id=current_user.id,
            details={"reason": "invalid_current_password"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect"
        )

    # Validate new password strength
    new_password = request.new_password.get_secret_value()

    # Check password complexity
    if len(new_password) < 12:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 12 characters long"
        )

    if not any(c.isupper() for c in new_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one uppercase letter"
        )

    if not any(c.islower() for c in new_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one lowercase letter"
        )

    if not any(c.isdigit() for c in new_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one digit"
        )

    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in new_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one special character"
        )

    # Check password history
    if current_user.password_history:
        for old_hash in current_user.password_history[-5:]:  # Check last 5 passwords
            if await auth_service.verify_password_hash(new_password, old_hash):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Password has been used recently"
                )

    # Hash new password
    new_hash = await auth_service.hash_password(new_password)

    # Update password
    current_user.password_hash = new_hash
    current_user.password_changed_at = datetime.utcnow()

    # Update password history
    if not current_user.password_history:
        current_user.password_history = []
    current_user.password_history.append(new_hash)

    # Invalidate all sessions if requested
    if request.logout_all_sessions:
        await db.execute(
            update(UserSession)
            .where(UserSession.user_id == current_user.id)
            .values(is_active=False, revoked_at=datetime.utcnow())
        )

        # Clear cache
        await redis.delete(f"user:{current_user.id}")

    await db.commit()

    await audit.log_event(
        user_id=current_user.id,
        action="password_changed",
        resource_type="security",
        details={
            "logout_all_sessions": request.logout_all_sessions
        }
    )

    return {"message": "Password changed successfully"}


@router.post("/password/reset")
async def reset_password(
    request: PasswordResetRequest,
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
    audit: AuditLogger = Depends(get_audit_logger)
) -> Dict[str, str]:
    """
    Initiate password reset process
    """

    # Find user by email
    result = await db.execute(
        select(User).where(User.email == request.email)
    )
    user = result.scalar_one_or_none()

    # Always return success to prevent email enumeration
    if not user:
        await audit.log_security_event(
            event_type="password_reset_requested",
            severity="low",
            details={"email": request.email, "user_found": False}
        )
        return {"message": "If the email exists, a reset link has been sent"}

    # Generate reset token
    reset_token = secrets.token_urlsafe(32)
    reset_token_hash = hashlib.sha256(reset_token.encode()).hexdigest()

    # Store token in Redis with expiration
    await redis.set(
        f"password_reset:{reset_token_hash}",
        str(user.id),
        ex=3600  # 1 hour expiration
    )

    # Send password reset email
    try:
        from src.services.notification_service import notification_service
        from src.core.config import settings

        # Generate reset URL
        reset_url = f"{settings.frontend_url}/auth/reset-password?token={reset_token}"

        # Prepare email content
        reset_email_subject = "CatNet Password Reset Request"
        reset_email_message = f"""
Hello {user.full_name or user.username},

A password reset was requested for your CatNet account ({user.email}).

To reset your password, click the link below:
{reset_url}

This link will expire in 1 hour for security reasons.

If you did not request this password reset, please ignore this email and your password will remain unchanged.

For security reasons, please ensure you:
1. Use a strong, unique password
2. Do not share your password with anyone
3. Log out from shared devices

If you have any concerns about the security of your account, please contact your system administrator immediately.

Best regards,
CatNet Security Team
"""

        # Send email notification
        await notification_service.send_notification(
            recipients=[user.email],
            subject=reset_email_subject,
            message=reset_email_message,
            priority=3,  # High priority for security notifications
            channels=['email'],
            metadata={
                'email_type': 'password_reset',
                'user_id': str(user.id),
                'username': user.username,
                'token_expires': '1 hour',
                'reset_url': reset_url,
                'requested_at': datetime.utcnow().isoformat()
            },
            template='password_reset',
            template_data={
                'user_name': user.full_name or user.username,
                'username': user.username,
                'email': user.email,
                'reset_url': reset_url,
                'expiry_time': '1 hour',
                'support_email': settings.support_email,
                'company_name': 'CatNet'
            }
        )

        logger.info(f"Password reset email sent to {user.email}")

    except Exception as email_error:
        logger.error(f"Failed to send password reset email to {user.email}: {email_error}")
        # Don't fail the request if email sending fails - user still gets the generic response
        await audit.log_error(
            error_type="password_reset_email_error",
            error_message=f"Failed to send password reset email: {str(email_error)}",
            context={
                "user_id": str(user.id),
                "email": user.email,
                "reset_token_hash": reset_token_hash
            }
        )

    await audit.log_event(
        user_id=user.id,
        action="password_reset_requested",
        resource_type="security",
        details={
            "email": request.email,
            "reset_email_sent": True,
            "token_expiry": "1 hour"
        }
    )

    return {"message": "If the email exists, a reset link has been sent"}


@router.post("/password/reset/confirm")
async def confirm_password_reset(
    request: PasswordResetConfirm,
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
    audit: AuditLogger = Depends(get_audit_logger),
    vault = Depends(get_vault)
) -> Dict[str, str]:
    """
    Confirm password reset with token
    """

    # Verify reset token
    reset_token_hash = hashlib.sha256(request.reset_token.encode()).hexdigest()
    user_id = await redis.get(f"password_reset:{reset_token_hash}")

    if not user_id:
        await audit.log_security_event(
            event_type="password_reset_failed",
            severity="medium",
            details={"reason": "invalid_token"}
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token"
        )

    # Get user
    user = await db.get(User, UUID(user_id))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    auth_service = AuthenticationService(db, redis, vault, audit)

    # Hash new password
    new_password = request.new_password.get_secret_value()
    new_hash = await auth_service.hash_password(new_password)

    # Update password
    user.password_hash = new_hash
    user.password_changed_at = datetime.utcnow()

    # Update password history
    if not user.password_history:
        user.password_history = []
    user.password_history.append(new_hash)

    # Invalidate all sessions
    await db.execute(
        update(UserSession)
        .where(UserSession.user_id == user.id)
        .values(is_active=False, revoked_at=datetime.utcnow())
    )

    # Delete reset token
    await redis.delete(f"password_reset:{reset_token_hash}")

    await db.commit()

    await audit.log_event(
        user_id=user.id,
        action="password_reset_completed",
        resource_type="security",
        details={"all_sessions_invalidated": True}
    )

    return {"message": "Password reset successfully"}


@router.get("/sessions", response_model=List[SessionInfo])
async def get_active_sessions(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit: AuditLogger = Depends(get_audit_logger)
) -> List[SessionInfo]:
    """
    Get all active sessions for current user
    """

    result = await db.execute(
        select(UserSession)
        .where(
            and_(
                UserSession.user_id == current_user.id,
                UserSession.is_active == True
            )
        )
        .order_by(UserSession.created_at.desc())
    )
    sessions = result.scalars().all()

    session_list = []
    for session in sessions:
        session_list.append(SessionInfo(
            session_id=session.id,
            ip_address=session.ip_address,
            user_agent=session.user_agent,
            created_at=session.created_at,
            last_activity=session.last_activity,
            is_current=(session.session_id == current_user.current_session_id if hasattr(current_user, 'current_session_id') else False),
            location=session.location,
            device_trusted=session.device_trusted or False
        ))

    return session_list


@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit: AuditLogger = Depends(get_audit_logger)
) -> Dict[str, str]:
    """
    Revoke a specific session
    """

    # Get session
    result = await db.execute(
        select(UserSession)
        .where(
            and_(
                UserSession.id == session_id,
                UserSession.user_id == current_user.id
            )
        )
    )
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )

    # Revoke session
    session.is_active = False
    session.revoked_at = datetime.utcnow()

    await db.commit()

    await audit.log_event(
        user_id=current_user.id,
        action="session_revoked",
        resource_type="authentication",
        resource_id=str(session_id),
        details={"ip_address": session.ip_address}
    )

    return {"message": "Session revoked successfully"}