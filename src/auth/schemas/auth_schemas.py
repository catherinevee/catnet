"""
Authentication and Authorization schemas for CatNet API
"""
from pydantic import BaseModel, EmailStr, Field, validator, SecretStr
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
import re
from uuid import UUID


class AuthProvider(str, Enum):
    """Supported authentication providers"""
    LOCAL = "local"
    LDAP = "ldap"
    SAML = "saml"
    OAUTH2 = "oauth2"
    OIDC = "oidc"


class TokenType(str, Enum):
    """Token types"""
    ACCESS = "access"
    REFRESH = "refresh"
    MFA = "mfa"
    API_KEY = "api_key"


class MFAMethod(str, Enum):
    """Multi-factor authentication methods"""
    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"
    HARDWARE = "hardware"
    BACKUP_CODES = "backup_codes"


# Request Schemas

class LoginRequest(BaseModel):
    """Login request schema"""
    username: str = Field(..., min_length=3, max_length=100)
    password: SecretStr = Field(..., min_length=8)
    provider: AuthProvider = AuthProvider.LOCAL
    remember_me: bool = False
    device_id: Optional[str] = None
    device_name: Optional[str] = None
    ip_address: Optional[str] = None

    @validator('username')
    def validate_username(cls, v):
        """Validate username format"""
        if not re.match(r'^[a-zA-Z0-9_\-@.]+$', v):
            raise ValueError('Username contains invalid characters')
        return v.lower()

    class Config:
        schema_extra = {
            "example": {
                "username": "admin@catnet.local",
                "password": "SecurePassword123!",
                "provider": "local",
                "remember_me": False
            }
        }


class RegisterRequest(BaseModel):
    """User registration request schema"""
    username: str = Field(..., min_length=3, max_length=100)
    email: EmailStr
    password: SecretStr = Field(..., min_length=12)
    confirm_password: SecretStr
    full_name: str = Field(..., min_length=2, max_length=255)
    phone: Optional[str] = None
    department: Optional[str] = None
    accept_terms: bool

    @validator('username')
    def validate_username(cls, v):
        """Validate username format"""
        if not re.match(r'^[a-zA-Z0-9_\-]+$', v):
            raise ValueError('Username can only contain letters, numbers, underscores, and hyphens')
        return v.lower()

    @validator('password')
    def validate_password_strength(cls, v):
        """Validate password strength"""
        password = v.get_secret_value()

        if len(password) < 12:
            raise ValueError('Password must be at least 12 characters long')

        if not re.search(r'[A-Z]', password):
            raise ValueError('Password must contain at least one uppercase letter')

        if not re.search(r'[a-z]', password):
            raise ValueError('Password must contain at least one lowercase letter')

        if not re.search(r'[0-9]', password):
            raise ValueError('Password must contain at least one digit')

        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValueError('Password must contain at least one special character')

        # Check for common patterns
        common_patterns = ['123', 'abc', 'password', 'qwerty', 'admin']
        password_lower = password.lower()
        for pattern in common_patterns:
            if pattern in password_lower:
                raise ValueError(f'Password contains common pattern: {pattern}')

        return v

    @validator('confirm_password')
    def passwords_match(cls, v, values):
        """Validate passwords match"""
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v

    @validator('accept_terms')
    def terms_accepted(cls, v):
        """Validate terms acceptance"""
        if not v:
            raise ValueError('Terms and conditions must be accepted')
        return v

    @validator('phone')
    def validate_phone(cls, v):
        """Validate phone number format"""
        if v:
            # Remove all non-numeric characters
            cleaned = re.sub(r'\D', '', v)
            if len(cleaned) < 10 or len(cleaned) > 15:
                raise ValueError('Invalid phone number format')
        return v

    class Config:
        schema_extra = {
            "example": {
                "username": "johndoe",
                "email": "john.doe@example.com",
                "password": "SecurePassword123!@#",
                "confirm_password": "SecurePassword123!@#",
                "full_name": "John Doe",
                "phone": "+1-555-123-4567",
                "department": "Network Operations",
                "accept_terms": True
            }
        }


class MFASetupRequest(BaseModel):
    """MFA setup request schema"""
    method: MFAMethod
    phone_number: Optional[str] = None
    backup_email: Optional[EmailStr] = None

    @validator('phone_number')
    def validate_phone_for_sms(cls, v, values):
        """Validate phone number for SMS MFA"""
        if values.get('method') == MFAMethod.SMS and not v:
            raise ValueError('Phone number required for SMS MFA')
        return v

    @validator('backup_email')
    def validate_email_for_email_mfa(cls, v, values):
        """Validate email for email MFA"""
        if values.get('method') == MFAMethod.EMAIL and not v:
            raise ValueError('Email address required for email MFA')
        return v


class MFAVerifyRequest(BaseModel):
    """MFA verification request schema"""
    token: str = Field(..., min_length=6, max_length=10)
    method: MFAMethod
    backup_code: Optional[str] = None

    @validator('token')
    def validate_token_format(cls, v, values):
        """Validate token format based on method"""
        method = values.get('method')

        if method in [MFAMethod.TOTP, MFAMethod.SMS, MFAMethod.EMAIL]:
            if not re.match(r'^\d{6}$', v):
                raise ValueError('Token must be 6 digits')
        elif method == MFAMethod.BACKUP_CODES:
            if not re.match(r'^[A-Z0-9]{8}$', v):
                raise ValueError('Invalid backup code format')

        return v


class PasswordResetRequest(BaseModel):
    """Password reset request schema"""
    email: EmailStr

    class Config:
        schema_extra = {
            "example": {
                "email": "user@example.com"
            }
        }


class PasswordResetConfirm(BaseModel):
    """Password reset confirmation schema"""
    token: str
    new_password: SecretStr = Field(..., min_length=12)
    confirm_password: SecretStr

    @validator('new_password')
    def validate_password_strength(cls, v):
        """Validate password strength"""
        # Same validation as RegisterRequest
        password = v.get_secret_value()

        if len(password) < 12:
            raise ValueError('Password must be at least 12 characters long')

        if not any(c.isupper() for c in password):
            raise ValueError('Password must contain at least one uppercase letter')

        if not any(c.islower() for c in password):
            raise ValueError('Password must contain at least one lowercase letter')

        if not any(c.isdigit() for c in password):
            raise ValueError('Password must contain at least one digit')

        if not any(c in '!@#$%^&*(),.?":{}|<>' for c in password):
            raise ValueError('Password must contain at least one special character')

        return v

    @validator('confirm_password')
    def passwords_match(cls, v, values):
        """Validate passwords match"""
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v


class PasswordChangeRequest(BaseModel):
    """Password change request schema"""
    current_password: SecretStr
    new_password: SecretStr = Field(..., min_length=12)
    confirm_password: SecretStr

    @validator('new_password')
    def validate_password_strength(cls, v, values):
        """Validate password strength and ensure different from current"""
        password = v.get_secret_value()

        # Check if different from current password
        if 'current_password' in values:
            if v == values['current_password']:
                raise ValueError('New password must be different from current password')

        # Standard password validation
        if len(password) < 12:
            raise ValueError('Password must be at least 12 characters long')

        if not re.search(r'[A-Z]', password):
            raise ValueError('Password must contain at least one uppercase letter')

        if not re.search(r'[a-z]', password):
            raise ValueError('Password must contain at least one lowercase letter')

        if not re.search(r'[0-9]', password):
            raise ValueError('Password must contain at least one digit')

        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValueError('Password must contain at least one special character')

        return v

    @validator('confirm_password')
    def passwords_match(cls, v, values):
        """Validate passwords match"""
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v


class RefreshTokenRequest(BaseModel):
    """Token refresh request schema"""
    refresh_token: str

    class Config:
        schema_extra = {
            "example": {
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }


class APIKeyRequest(BaseModel):
    """API key creation request schema"""
    name: str = Field(..., min_length=3, max_length=100)
    description: Optional[str] = None
    expires_at: Optional[datetime] = None
    permissions: List[str] = []

    @validator('name')
    def validate_name(cls, v):
        """Validate API key name"""
        if not re.match(r'^[a-zA-Z0-9_\-\s]+$', v):
            raise ValueError('API key name contains invalid characters')
        return v

    @validator('expires_at')
    def validate_expiry(cls, v):
        """Validate expiry date"""
        if v and v <= datetime.utcnow():
            raise ValueError('Expiry date must be in the future')
        return v

    class Config:
        schema_extra = {
            "example": {
                "name": "CI/CD Pipeline",
                "description": "API key for automated deployments",
                "expires_at": "2024-12-31T23:59:59Z",
                "permissions": ["deployment.view", "deployment.create"]
            }
        }


# Response Schemas

class TokenResponse(BaseModel):
    """Token response schema"""
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    mfa_required: bool = False
    mfa_token: Optional[str] = None

    class Config:
        schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "mfa_required": False
            }
        }


class UserResponse(BaseModel):
    """User response schema"""
    id: UUID
    username: str
    email: EmailStr
    full_name: str
    is_active: bool
    is_admin: bool
    roles: List[str]
    permissions: List[str]
    created_at: datetime
    last_login_at: Optional[datetime]
    mfa_enabled: bool
    email_verified: bool
    phone_verified: bool

    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "username": "johndoe",
                "email": "john.doe@example.com",
                "full_name": "John Doe",
                "is_active": True,
                "is_admin": False,
                "roles": ["network_engineer", "deployment_approver"],
                "permissions": ["device.view", "deployment.create", "deployment.approve"],
                "created_at": "2024-01-01T00:00:00Z",
                "last_login_at": "2024-01-15T10:30:00Z",
                "mfa_enabled": True,
                "email_verified": True,
                "phone_verified": False
            }
        }


class SessionResponse(BaseModel):
    """Session response schema"""
    session_id: str
    user_id: UUID
    ip_address: str
    user_agent: Optional[str]
    device_name: Optional[str]
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    is_active: bool

    class Config:
        orm_mode = True


class MFASetupResponse(BaseModel):
    """MFA setup response schema"""
    method: MFAMethod
    secret: Optional[str] = None
    qr_code: Optional[str] = None
    backup_codes: Optional[List[str]] = None
    verify_required: bool = True

    class Config:
        schema_extra = {
            "example": {
                "method": "totp",
                "secret": "JBSWY3DPEHPK3PXP",
                "qr_code": "data:image/png;base64,iVBORw0KG...",
                "backup_codes": ["ABCD1234", "EFGH5678", "IJKL9012"],
                "verify_required": True
            }
        }


class APIKeyResponse(BaseModel):
    """API key response schema"""
    id: UUID
    name: str
    key: Optional[str] = None  # Only shown on creation
    key_hint: str  # Last 4 characters of key
    description: Optional[str]
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    permissions: List[str]
    is_active: bool

    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "name": "CI/CD Pipeline",
                "key": "catnet_ak_1234567890abcdef",  # Only on creation
                "key_hint": "...cdef",
                "description": "API key for automated deployments",
                "created_at": "2024-01-01T00:00:00Z",
                "expires_at": "2024-12-31T23:59:59Z",
                "last_used_at": "2024-01-15T10:30:00Z",
                "permissions": ["deployment.view", "deployment.create"],
                "is_active": True
            }
        }


class PermissionResponse(BaseModel):
    """Permission response schema"""
    resource: str
    action: str
    description: str
    category: str

    class Config:
        schema_extra = {
            "example": {
                "resource": "deployment",
                "action": "approve",
                "description": "Approve deployment requests",
                "category": "Deployment Management"
            }
        }


class RoleResponse(BaseModel):
    """Role response schema"""
    id: UUID
    name: str
    description: str
    permissions: List[PermissionResponse]
    user_count: int
    is_system: bool
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        orm_mode = True


class AuditLogResponse(BaseModel):
    """Audit log response schema"""
    id: UUID
    event_type: str
    event_description: str
    user_id: UUID
    user_email: str
    ip_address: Optional[str]
    user_agent: Optional[str]
    resource_type: Optional[str]
    resource_id: Optional[str]
    details: Dict[str, Any]
    timestamp: datetime

    class Config:
        orm_mode = True


# Error Response Schemas

class ErrorResponse(BaseModel):
    """Error response schema"""
    error: str
    message: str
    details: Optional[Dict[str, Any]] = None
    request_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        schema_extra = {
            "example": {
                "error": "authentication_failed",
                "message": "Invalid username or password",
                "request_id": "req_123456",
                "timestamp": "2024-01-15T10:30:00Z"
            }
        }


class ValidationErrorResponse(BaseModel):
    """Validation error response schema"""
    error: str = "validation_error"
    message: str
    fields: Dict[str, List[str]]
    request_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        schema_extra = {
            "example": {
                "error": "validation_error",
                "message": "Request validation failed",
                "fields": {
                    "password": ["Password must be at least 12 characters long"],
                    "email": ["Invalid email format"]
                },
                "request_id": "req_123456",
                "timestamp": "2024-01-15T10:30:00Z"
            }
        }


# Additional utility schemas

class TokenClaims(BaseModel):
    """JWT token claims schema"""
    sub: str  # Subject (user ID)
    iat: int  # Issued at
    exp: int  # Expiration
    jti: str  # JWT ID
    type: TokenType
    scope: Optional[List[str]] = []
    device_id: Optional[str] = None
    session_id: Optional[str] = None


class SecurityContext(BaseModel):
    """Security context for requests"""
    user_id: UUID
    username: str
    roles: List[str]
    permissions: List[str]
    ip_address: str
    user_agent: Optional[str]
    session_id: str
    mfa_verified: bool
    token_type: TokenType