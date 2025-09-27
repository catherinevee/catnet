from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, validator
import structlog

from ...auth.auth_service import AuthenticationService
from ...auth.mfa import MFAService
from ...security.audit import AuditLogger
from ...core.exceptions import AuthenticationError, ValidationError

logger = structlog.get_logger()
router = APIRouter()
security = HTTPBearer()

# Initialize services
auth_service = AuthenticationService()
mfa_service = MFAService()
audit = AuditLogger()

# Request/Response Models
class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    mfa_code: Optional[str] = None
    remember_me: bool = False

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    confirm_password: str
    first_name: str
    last_name: str
    organization: Optional[str] = None

    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v

    @validator('password')
    def password_strength(cls, v):
        if len(v) < 12:
            raise ValueError('Password must be at least 12 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in v):
            raise ValueError('Password must contain at least one special character')
        return v

class MFASetupRequest(BaseModel):
    password: str

class MFAVerifyRequest(BaseModel):
    code: str
    backup_code: Optional[str] = None

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str

    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v

class TokenRefreshRequest(BaseModel):
    refresh_token: str

class AuthResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Dict[str, Any]
    mfa_required: bool = False
    mfa_setup_required: bool = False

class MFASetupResponse(BaseModel):
    secret: str
    qr_code: str
    backup_codes: list

# Helper functions
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Get current authenticated user from JWT token"""
    try:
        token = credentials.credentials
        user = await auth_service.verify_token(token)
        return user
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"}
        )

def get_client_ip(request: Request) -> str:
    """Extract client IP address from request"""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

# Authentication endpoints
@router.post("/login", response_model=AuthResponse)
async def login(request: LoginRequest, http_request: Request):
    """Authenticate user and return JWT tokens"""
    try:
        client_ip = get_client_ip(http_request)
        user_agent = http_request.headers.get("user-agent", "unknown")

        # Authenticate user
        auth_result = await auth_service.authenticate_user(
            email=request.email,
            password=request.password,
            client_ip=client_ip,
            user_agent=user_agent
        )

        if not auth_result['success']:
            await audit.log_authentication_failure(
                email=request.email,
                reason=auth_result.get('reason', 'authentication_failed'),
                client_ip=client_ip,
                user_agent=user_agent
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=auth_result.get('message', 'Authentication failed')
            )

        user = auth_result['user']

        # Check if MFA is required
        if user.get('mfa_enabled') and not request.mfa_code:
            await audit.log_authentication_event(
                user_id=str(user['id']),
                event_type='mfa_required',
                client_ip=client_ip,
                success=False
            )
            return AuthResponse(
                access_token="",
                refresh_token="",
                expires_in=0,
                user=user,
                mfa_required=True
            )

        # Verify MFA if provided
        if user.get('mfa_enabled') and request.mfa_code:
            mfa_valid = await mfa_service.verify_totp(
                user_id=str(user['id']),
                code=request.mfa_code
            )

            if not mfa_valid:
                await audit.log_authentication_failure(
                    email=request.email,
                    reason='invalid_mfa_code',
                    client_ip=client_ip,
                    user_agent=user_agent
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid MFA code"
                )

        # Generate tokens
        tokens = await auth_service.create_tokens(
            user_id=str(user['id']),
            email=user['email'],
            roles=user.get('roles', []),
            remember_me=request.remember_me
        )

        # Log successful authentication
        await audit.log_authentication_success(
            user_id=str(user['id']),
            email=user['email'],
            client_ip=client_ip,
            user_agent=user_agent,
            mfa_used=user.get('mfa_enabled', False)
        )

        return AuthResponse(
            access_token=tokens['access_token'],
            refresh_token=tokens['refresh_token'],
            expires_in=tokens['expires_in'],
            user={
                'id': str(user['id']),
                'email': user['email'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'roles': user.get('roles', []),
                'permissions': user.get('permissions', [])
            },
            mfa_setup_required=not user.get('mfa_enabled', False)
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        await audit.log_authentication_failure(
            email=request.email,
            reason='system_error',
            client_ip=get_client_ip(http_request),
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication system error"
        )

@router.post("/register", response_model=AuthResponse)
async def register(request: RegisterRequest, http_request: Request):
    """Register a new user account"""
    try:
        client_ip = get_client_ip(http_request)
        user_agent = http_request.headers.get("user-agent", "unknown")

        # Register user
        registration_result = await auth_service.register_user(
            email=request.email,
            password=request.password,
            first_name=request.first_name,
            last_name=request.last_name,
            organization=request.organization,
            client_ip=client_ip,
            user_agent=user_agent
        )

        if not registration_result['success']:
            await audit.log_registration_failure(
                email=request.email,
                reason=registration_result.get('reason', 'registration_failed'),
                client_ip=client_ip
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=registration_result.get('message', 'Registration failed')
            )

        user = registration_result['user']

        # Generate tokens for immediate login
        tokens = await auth_service.create_tokens(
            user_id=str(user['id']),
            email=user['email'],
            roles=user.get('roles', []),
            remember_me=False
        )

        # Log successful registration
        await audit.log_registration_success(
            user_id=str(user['id']),
            email=user['email'],
            client_ip=client_ip,
            user_agent=user_agent
        )

        return AuthResponse(
            access_token=tokens['access_token'],
            refresh_token=tokens['refresh_token'],
            expires_in=tokens['expires_in'],
            user={
                'id': str(user['id']),
                'email': user['email'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'roles': user.get('roles', []),
                'permissions': user.get('permissions', [])
            },
            mfa_setup_required=True
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {e}")
        await audit.log_registration_failure(
            email=request.email,
            reason='system_error',
            client_ip=get_client_ip(http_request),
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration system error"
        )

@router.post("/refresh", response_model=AuthResponse)
async def refresh_token(request: TokenRefreshRequest, http_request: Request):
    """Refresh access token using refresh token"""
    try:
        client_ip = get_client_ip(http_request)

        # Refresh tokens
        result = await auth_service.refresh_tokens(
            refresh_token=request.refresh_token,
            client_ip=client_ip
        )

        if not result['success']:
            await audit.log_token_refresh_failure(
                refresh_token=request.refresh_token[:10] + "...",
                reason=result.get('reason', 'invalid_refresh_token'),
                client_ip=client_ip
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=result.get('message', 'Invalid refresh token')
            )

        user = result['user']
        tokens = result['tokens']

        await audit.log_token_refresh_success(
            user_id=str(user['id']),
            client_ip=client_ip
        )

        return AuthResponse(
            access_token=tokens['access_token'],
            refresh_token=tokens['refresh_token'],
            expires_in=tokens['expires_in'],
            user={
                'id': str(user['id']),
                'email': user['email'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'roles': user.get('roles', []),
                'permissions': user.get('permissions', [])
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh system error"
        )

@router.post("/logout")
async def logout(
    http_request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Logout user and invalidate tokens"""
    try:
        client_ip = get_client_ip(http_request)

        # Get token from authorization header
        authorization = http_request.headers.get("authorization", "")
        token = authorization.replace("Bearer ", "") if authorization.startswith("Bearer ") else ""

        # Logout user
        await auth_service.logout_user(
            user_id=current_user['sub'],
            token=token,
            client_ip=client_ip
        )

        await audit.log_logout(
            user_id=current_user['sub'],
            client_ip=client_ip
        )

        return {"message": "Successfully logged out"}

    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout system error"
        )

# MFA endpoints
@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(
    request: MFASetupRequest,
    http_request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Set up MFA for user account"""
    try:
        client_ip = get_client_ip(http_request)

        # Verify current password
        password_valid = await auth_service.verify_password(
            user_id=current_user['sub'],
            password=request.password
        )

        if not password_valid:
            await audit.log_mfa_setup_failure(
                user_id=current_user['sub'],
                reason='invalid_password',
                client_ip=client_ip
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid password"
            )

        # Generate MFA secret and QR code
        mfa_setup = await mfa_service.setup_mfa(
            user_id=current_user['sub'],
            email=current_user.get('email')
        )

        await audit.log_mfa_setup_initiated(
            user_id=current_user['sub'],
            client_ip=client_ip
        )

        return MFASetupResponse(
            secret=mfa_setup['secret'],
            qr_code=mfa_setup['qr_code'],
            backup_codes=mfa_setup['backup_codes']
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MFA setup error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA setup system error"
        )

@router.post("/mfa/verify")
async def verify_mfa(
    request: MFAVerifyRequest,
    http_request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Verify and enable MFA for user account"""
    try:
        client_ip = get_client_ip(http_request)

        # Verify MFA code
        verification_result = await mfa_service.verify_and_enable_mfa(
            user_id=current_user['sub'],
            code=request.code,
            backup_code=request.backup_code
        )

        if not verification_result['success']:
            await audit.log_mfa_verification_failure(
                user_id=current_user['sub'],
                reason=verification_result.get('reason', 'invalid_code'),
                client_ip=client_ip
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=verification_result.get('message', 'Invalid MFA code')
            )

        await audit.log_mfa_enabled(
            user_id=current_user['sub'],
            client_ip=client_ip
        )

        return {"message": "MFA successfully enabled"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MFA verification error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA verification system error"
        )

@router.delete("/mfa")
async def disable_mfa(
    request: MFASetupRequest,  # Reuse for password verification
    http_request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Disable MFA for user account"""
    try:
        client_ip = get_client_ip(http_request)

        # Verify current password
        password_valid = await auth_service.verify_password(
            user_id=current_user['sub'],
            password=request.password
        )

        if not password_valid:
            await audit.log_mfa_disable_failure(
                user_id=current_user['sub'],
                reason='invalid_password',
                client_ip=client_ip
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid password"
            )

        # Disable MFA
        await mfa_service.disable_mfa(user_id=current_user['sub'])

        await audit.log_mfa_disabled(
            user_id=current_user['sub'],
            client_ip=client_ip
        )

        return {"message": "MFA successfully disabled"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MFA disable error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA disable system error"
        )

# Password management
@router.post("/password/change")
async def change_password(
    request: PasswordChangeRequest,
    http_request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Change user password"""
    try:
        client_ip = get_client_ip(http_request)

        # Change password
        result = await auth_service.change_password(
            user_id=current_user['sub'],
            current_password=request.current_password,
            new_password=request.new_password
        )

        if not result['success']:
            await audit.log_password_change_failure(
                user_id=current_user['sub'],
                reason=result.get('reason', 'invalid_current_password'),
                client_ip=client_ip
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get('message', 'Password change failed')
            )

        await audit.log_password_changed(
            user_id=current_user['sub'],
            client_ip=client_ip
        )

        return {"message": "Password successfully changed"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password change error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password change system error"
        )

# User profile
@router.get("/me")
async def get_current_user_profile(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get current user profile"""
    try:
        # Get full user profile
        profile = await auth_service.get_user_profile(user_id=current_user['sub'])

        return {
            'id': profile['id'],
            'email': profile['email'],
            'first_name': profile['first_name'],
            'last_name': profile['last_name'],
            'organization': profile.get('organization'),
            'roles': profile.get('roles', []),
            'permissions': profile.get('permissions', []),
            'mfa_enabled': profile.get('mfa_enabled', False),
            'last_login': profile.get('last_login'),
            'created_at': profile.get('created_at'),
            'updated_at': profile.get('updated_at')
        }

    except Exception as e:
        logger.error(f"Get profile error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Profile retrieval system error"
        )

@router.get("/sessions")
async def get_user_sessions(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get user's active sessions"""
    try:
        sessions = await auth_service.get_user_sessions(user_id=current_user['sub'])
        return {"sessions": sessions}

    except Exception as e:
        logger.error(f"Get sessions error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Session retrieval system error"
        )

@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    http_request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Revoke a specific user session"""
    try:
        client_ip = get_client_ip(http_request)

        result = await auth_service.revoke_session(
            user_id=current_user['sub'],
            session_id=session_id
        )

        if not result['success']:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found"
            )

        await audit.log_session_revoked(
            user_id=current_user['sub'],
            session_id=session_id,
            client_ip=client_ip
        )

        return {"message": "Session successfully revoked"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Session revocation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Session revocation system error"
        )