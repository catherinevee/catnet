"""
Data models for authentication service.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
import uuid

from pydantic import BaseModel, EmailStr, Field, validator
from sqlalchemy import Column, String, Boolean, DateTime, JSON, Text, Integer
from sqlalchemy.dialects.postgresql import UUID

from src.db.models import Base


class AuthType(str, Enum):
    """Authentication types."""
    LOCAL = "local"
    LDAP = "ldap"
    SAML = "saml"
    OAUTH = "oauth"


class MFAMethod(str, Enum):
    """MFA methods."""
    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"
    WEBAUTHN = "webauthn"


class LoginRequest(BaseModel):
    """Login request model."""
    username: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=1)
    auth_type: AuthType = AuthType.LOCAL
    remember_me: bool = False
    device_id: Optional[str] = None
    device_fingerprint: Optional[str] = None


class LoginResponse(BaseModel):
    """Login response model."""
    success: bool
    token: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_at: Optional[datetime] = None
    mfa_required: bool = False
    mfa_token: Optional[str] = None
    mfa_methods: Optional[List[MFAMethod]] = None
    user: Optional[Dict[str, Any]] = None
    message: Optional[str] = None


class MFARequest(BaseModel):
    """MFA verification request."""
    mfa_token: str = Field(..., min_length=1)
    code: str = Field(..., min_length=6, max_length=10)
    method: MFAMethod = MFAMethod.TOTP
    trust_device: bool = False


class MFAResponse(BaseModel):
    """MFA verification response."""
    success: bool
    token: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_at: Optional[datetime] = None
    user: Optional[Dict[str, Any]] = None
    backup_codes_remaining: Optional[int] = None
    message: Optional[str] = None


class TokenRefreshRequest(BaseModel):
    """Token refresh request."""
    token: str = Field(..., min_length=1)
    refresh_token: Optional[str] = None


class TokenRefreshResponse(BaseModel):
    """Token refresh response."""
    token: str
    refresh_token: Optional[str] = None
    expires_at: datetime


class PasswordResetRequest(BaseModel):
    """Password reset request."""
    email: EmailStr
    recaptcha_token: Optional[str] = None


class PasswordResetConfirm(BaseModel):
    """Password reset confirmation."""
    token: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=12)
    confirm_password: str = Field(..., min_length=12)

    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v


class UserCreateRequest(BaseModel):
    """User creation request."""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=12)
    full_name: str = Field(..., min_length=1, max_length=255)
    roles: List[str] = []
    auth_type: AuthType = AuthType.LOCAL
    mfa_enabled: bool = False
    require_password_change: bool = False


class UserUpdateRequest(BaseModel):
    """User update request."""
    email: Optional[EmailStr] = None
    full_name: Optional[str] = Field(None, max_length=255)
    roles: Optional[List[str]] = None
    is_active: Optional[bool] = None
    mfa_enabled: Optional[bool] = None


class UserResponse(BaseModel):
    """User response model."""
    id: str
    username: str
    email: str
    full_name: str
    roles: List[str]
    permissions: List[str]
    auth_type: AuthType
    is_active: bool
    mfa_enabled: bool
    created_at: datetime
    last_login: Optional[datetime] = None
    password_changed_at: Optional[datetime] = None


class SessionInfo(BaseModel):
    """Session information."""
    id: str
    user_id: str
    username: str
    ip_address: str
    user_agent: str
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    is_active: bool


class AuditLogEntry(BaseModel):
    """Audit log entry."""
    id: str
    timestamp: datetime
    user_id: Optional[str] = None
    username: Optional[str] = None
    action: str
    resource: Optional[str] = None
    resource_id: Optional[str] = None
    details: Dict[str, Any]
    ip_address: str
    user_agent: Optional[str] = None
    result: str
    error_message: Optional[str] = None


class MFASetupRequest(BaseModel):
    """MFA setup request."""
    method: MFAMethod
    phone_number: Optional[str] = None  # For SMS
    email: Optional[EmailStr] = None  # For email


class MFASetupResponse(BaseModel):
    """MFA setup response."""
    method: MFAMethod
    secret: Optional[str] = None  # For TOTP
    qr_code: Optional[str] = None  # For TOTP (base64 encoded)
    backup_codes: Optional[List[str]] = None
    verification_required: bool
    verification_token: Optional[str] = None


class MFADisableRequest(BaseModel):
    """MFA disable request."""
    password: str = Field(..., min_length=1)
    code: str = Field(..., min_length=6, max_length=10)


class Permission(BaseModel):
    """Permission model."""
    id: str
    name: str
    resource: str
    action: str
    description: Optional[str] = None


class Role(BaseModel):
    """Role model."""
    id: str
    name: str
    description: Optional[str] = None
    permissions: List[Permission]
    is_system: bool = False
    created_at: datetime
    updated_at: datetime


class APIKey(BaseModel):
    """API key model."""
    id: str
    name: str
    key_hash: str
    user_id: str
    roles: List[str]
    permissions: List[str]
    expires_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    created_at: datetime
    is_active: bool


class OAuthProvider(BaseModel):
    """OAuth provider configuration."""
    name: str
    client_id: str
    authorization_url: str
    token_url: str
    user_info_url: str
    scopes: List[str]
    is_active: bool


class WebAuthnCredential(BaseModel):
    """WebAuthn credential model."""
    id: str
    user_id: str
    credential_id: str
    public_key: str
    sign_count: int
    device_name: str
    created_at: datetime
    last_used: Optional[datetime] = None


class TrustedDevice(BaseModel):
    """Trusted device model."""
    id: str
    user_id: str
    device_id: str
    device_fingerprint: str
    device_name: str
    device_type: str
    trusted_until: datetime
    created_at: datetime
    last_seen: datetime