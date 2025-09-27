"""Authentication Service implementation"""

from typing import Optional
from datetime import datetime
from fastapi import FastAPI, Depends, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr, SecretStr, validator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import uvicorn
import pyotp
import qrcode
import io
import base64

from src.core.config import settings
from src.db import get_db, db_manager
from src.db.models import User, Group
from src.security.auth import auth_manager, authz_manager
from src.security.audit import audit_logger
from src.api import UnauthorizedError, BadRequestError, ConflictError
from src.api.dependencies import get_current_user, get_request_id, get_client_info

# Create FastAPI app for Authentication Service
app = FastAPI(
    title="CatNet Authentication Service",
    description="OAuth2, SAML, MFA, JWT token management",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=settings.cors_allow_methods,
    allow_headers=settings.cors_allow_headers,
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"]  # Configure based on environment
)


# Request/Response models
class LoginRequest(BaseModel):
    """Login request model"""
    username: str = Field(..., description="Username or email")
    password: SecretStr = Field(..., description="User password")
    mfa_code: Optional[str] = Field(None, description="MFA code if enabled")


class LoginResponse(BaseModel):
    """Login response model"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict


class RegisterRequest(BaseModel):
    """User registration request"""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    full_name: str = Field(..., min_length=1, max_length=255)
    password: SecretStr = Field(..., min_length=12)

    @validator("password")
    def validate_password(cls, v: SecretStr) -> SecretStr:
        password = v.get_secret_value()
        if len(password) < settings.password_min_length:
            raise ValueError(f"Password must be at least {settings.password_min_length} characters")
        if settings.password_require_special and not any(c in "!@#$%^&*()_+-=" for c in password):
            raise ValueError("Password must contain at least one special character")
        return v


class RefreshTokenRequest(BaseModel):
    """Refresh token request"""
    refresh_token: str


class MFASetupResponse(BaseModel):
    """MFA setup response"""
    secret: str
    qr_code: str
    backup_codes: list[str]


class MFAVerifyRequest(BaseModel):
    """MFA verification request"""
    code: str


class PasswordChangeRequest(BaseModel):
    """Password change request"""
    current_password: SecretStr
    new_password: SecretStr

    @validator("new_password")
    def validate_password(cls, v: SecretStr) -> SecretStr:
        password = v.get_secret_value()
        if len(password) < settings.password_min_length:
            raise ValueError(f"Password must be at least {settings.password_min_length} characters")
        return v


# API Endpoints
@app.post("/auth/login", response_model=LoginResponse, tags=["Authentication"])
async def login(
    request: Request,
    login_request: LoginRequest,
    db: AsyncSession = Depends(get_db),
    request_id: str = Depends(get_request_id),
    client_info: dict = Depends(get_client_info)
) -> LoginResponse:
    """
    Authenticate user and return JWT tokens

    - **username**: Username or email address
    - **password**: User password
    - **mfa_code**: MFA code if MFA is enabled for user
    """
    try:
        # Authenticate user
        user = await auth_manager.authenticate_user(
            db=db,
            username=login_request.username,
            password=login_request.password.get_secret_value(),
            mfa_code=login_request.mfa_code
        )

        # Generate tokens
        access_token = auth_manager.create_access_token(
            user_id=str(user.id),
            additional_claims={
                "username": user.username,
                "email": user.email,
                "is_superuser": user.is_superuser
            }
        )
        refresh_token = auth_manager.create_refresh_token(user_id=str(user.id))

        # Log successful login
        await audit_logger.log_event(
            db=db,
            user=user,
            action="user.login",
            success=True,
            details={"mfa_used": bool(login_request.mfa_code)},
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"],
            request_id=request_id
        )

        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=settings.jwt_access_token_expire_minutes * 60,
            user={
                "id": str(user.id),
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name,
                "is_active": user.is_active,
                "is_superuser": user.is_superuser,
                "mfa_enabled": user.mfa_enabled
            }
        )

    except Exception as e:
        # Log failed login
        await audit_logger.log_authentication_attempt(
            username=login_request.username,
            success=False,
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"],
            error_message=str(e)
        )
        raise UnauthorizedError("Invalid credentials")


@app.post("/auth/register", status_code=status.HTTP_201_CREATED, tags=["Authentication"])
async def register(
    request: Request,
    register_request: RegisterRequest,
    db: AsyncSession = Depends(get_db),
    request_id: str = Depends(get_request_id),
    client_info: dict = Depends(get_client_info)
) -> dict:
    """
    Register new user account

    Note: In production, this endpoint should be restricted to administrators
    or implement email verification
    """
    # Check if username exists
    stmt = select(User).where(User.username == register_request.username)
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise ConflictError("Username already exists")

    # Check if email exists
    stmt = select(User).where(User.email == register_request.email)
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise ConflictError("Email already registered")

    # Create new user
    user = User(
        username=register_request.username,
        email=register_request.email,
        full_name=register_request.full_name,
        hashed_password=auth_manager.hash_password(register_request.password.get_secret_value()),
        is_active=True,
        is_superuser=False,
        mfa_enabled=settings.feature_mfa_enabled
    )

    db.add(user)
    await db.commit()
    await db.refresh(user)

    # Log registration
    await audit_logger.log_event(
        db=db,
        user=user,
        action="user.register",
        success=True,
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"],
        request_id=request_id
    )

    return {
        "message": "User registered successfully",
        "user_id": str(user.id),
        "username": user.username
    }


@app.post("/auth/refresh", response_model=LoginResponse, tags=["Authentication"])
async def refresh_token(
    refresh_request: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db)
) -> LoginResponse:
    """
    Refresh access token using refresh token
    """
    try:
        # Verify refresh token
        payload = auth_manager.verify_token(refresh_request.refresh_token, token_type="refresh")
        user_id = payload.get("sub")

        # Get user
        stmt = select(User).where(User.id == user_id)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user or not user.is_active:
            raise UnauthorizedError("Invalid refresh token")

        # Generate new tokens
        access_token = auth_manager.create_access_token(
            user_id=str(user.id),
            additional_claims={
                "username": user.username,
                "email": user.email,
                "is_superuser": user.is_superuser
            }
        )
        new_refresh_token = auth_manager.create_refresh_token(user_id=str(user.id))

        return LoginResponse(
            access_token=access_token,
            refresh_token=new_refresh_token,
            token_type="bearer",
            expires_in=settings.jwt_access_token_expire_minutes * 60,
            user={
                "id": str(user.id),
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name,
                "is_active": user.is_active,
                "is_superuser": user.is_superuser,
                "mfa_enabled": user.mfa_enabled
            }
        )

    except Exception:
        raise UnauthorizedError("Invalid refresh token")


@app.delete("/auth/logout", tags=["Authentication"])
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    request_id: str = Depends(get_request_id),
    client_info: dict = Depends(get_client_info)
) -> dict:
    """
    Logout user (invalidate tokens)

    Note: In production, implement token blacklisting
    """
    # Log logout
    await audit_logger.log_event(
        db=db,
        user=current_user,
        action="user.logout",
        success=True,
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"],
        request_id=request_id
    )

    # Clear permission cache
    authz_manager.clear_cache(str(current_user.id))

    return {"message": "Logged out successfully"}


@app.post("/auth/mfa/setup", response_model=MFASetupResponse, tags=["MFA"])
async def setup_mfa(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> MFASetupResponse:
    """
    Setup MFA for current user
    """
    if current_user.mfa_enabled and current_user.mfa_secret:
        raise BadRequestError("MFA is already enabled")

    # Generate MFA secret
    secret = auth_manager.generate_mfa_secret()

    # Generate provisioning URI
    provisioning_uri = auth_manager.generate_mfa_uri(secret, current_user.username)

    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()

    # Generate backup codes
    backup_codes = [auth_manager.generate_mfa_secret()[:8] for _ in range(10)]

    # Save secret (encrypted in production)
    current_user.mfa_secret = secret
    current_user.mfa_enabled = False  # Not enabled until verified
    await db.commit()

    return MFASetupResponse(
        secret=secret,
        qr_code=f"data:image/png;base64,{qr_code_base64}",
        backup_codes=backup_codes
    )


@app.post("/auth/mfa/verify", tags=["MFA"])
async def verify_mfa(
    verify_request: MFAVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> dict:
    """
    Verify MFA setup with code
    """
    if not current_user.mfa_secret:
        raise BadRequestError("MFA not configured")

    if not auth_manager.verify_mfa_code(current_user.mfa_secret, verify_request.code):
        raise UnauthorizedError("Invalid MFA code")

    # Enable MFA
    current_user.mfa_enabled = True
    await db.commit()

    return {"message": "MFA enabled successfully"}


@app.post("/auth/mfa/disable", tags=["MFA"])
async def disable_mfa(
    mfa_code: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> dict:
    """
    Disable MFA for current user
    """
    if not current_user.mfa_enabled:
        raise BadRequestError("MFA is not enabled")

    if not auth_manager.verify_mfa_code(current_user.mfa_secret, mfa_code):
        raise UnauthorizedError("Invalid MFA code")

    # Disable MFA
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    await db.commit()

    return {"message": "MFA disabled successfully"}


@app.post("/auth/password/change", tags=["Password"])
async def change_password(
    request: Request,
    password_request: PasswordChangeRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    request_id: str = Depends(get_request_id),
    client_info: dict = Depends(get_client_info)
) -> dict:
    """
    Change current user's password
    """
    # Verify current password
    if not auth_manager.verify_password(
        password_request.current_password.get_secret_value(),
        current_user.hashed_password
    ):
        raise UnauthorizedError("Current password is incorrect")

    # Update password
    current_user.hashed_password = auth_manager.hash_password(
        password_request.new_password.get_secret_value()
    )
    current_user.password_changed_at = datetime.utcnow()
    await db.commit()

    # Log password change
    await audit_logger.log_event(
        db=db,
        user=current_user,
        action="user.password_change",
        success=True,
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"],
        request_id=request_id
    )

    return {"message": "Password changed successfully"}


@app.get("/auth/me", tags=["User"])
async def get_current_user_info(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> dict:
    """
    Get current user information
    """
    # Get user permissions
    permissions = await authz_manager.get_user_permissions(db, current_user)

    return {
        "id": str(current_user.id),
        "username": current_user.username,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "is_active": current_user.is_active,
        "is_superuser": current_user.is_superuser,
        "mfa_enabled": current_user.mfa_enabled,
        "permissions": permissions,
        "groups": [{"id": str(g.id), "name": g.name} for g in current_user.groups],
        "created_at": current_user.created_at.isoformat(),
        "last_login_at": current_user.last_login_at.isoformat() if current_user.last_login_at else None
    }


@app.on_event("startup")
async def startup_event():
    """Initialize service on startup"""
    # Create database tables
    await db_manager.create_tables()
    print(f"Authentication Service started on port {settings.auth_service_port}")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    await db_manager.close()
    print("Authentication Service stopped")


# Health check endpoint
@app.get("/health", tags=["Health"])
async def health_check():
    """Service health check"""
    return {
        "status": "healthy",
        "service": "authentication",
        "timestamp": datetime.utcnow().isoformat()
    }


def run_service():
    """Run the authentication service"""
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=settings.auth_service_port,
        log_level=settings.log_level.lower()
    )


if __name__ == "__main__":
    run_service()