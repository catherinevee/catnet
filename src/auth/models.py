from typing import Optional, List, Dict, Any
from datetime import datetime
from uuid import UUID, uuid4
from pydantic import BaseModel, EmailStr, Field, SecretStr, validator
from enum import Enum
import hashlib
import secrets


class UserRole(str, Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"
    AUDITOR = "auditor"
    DEPLOYER = "deployer"


class AuthMethod(str, Enum):
    PASSWORD = "password"
    OAUTH2 = "oauth2"
    SAML = "saml"
    LDAP = "ldap"
    CERTIFICATE = "certificate"


class MFAMethod(str, Enum):
    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"
    HARDWARE_TOKEN = "hardware_token"
    PUSH = "push"


class TokenType(str, Enum):
    ACCESS = "access"
    REFRESH = "refresh"
    MFA = "mfa"
    API_KEY = "api_key"


class User(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    full_name: str
    roles: List[UserRole] = Field(default_factory=list)
    permissions: List[str] = Field(default_factory=list)
    is_active: bool = True
    is_locked: bool = False
    failed_login_attempts: int = 0
    last_login: Optional[datetime] = None
    last_failed_login: Optional[datetime] = None
    password_hash: Optional[str] = None
    mfa_enabled: bool = False
    mfa_methods: List[MFAMethod] = Field(default_factory=list)
    auth_methods: List[AuthMethod] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    password_changed_at: Optional[datetime] = None
    must_change_password: bool = False
    certificates: List[str] = Field(default_factory=list)
    ssh_keys: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @validator('roles')
    def validate_roles(cls, v):
        if not v:
            v.append(UserRole.VIEWER)
        return v

    def has_permission(self, permission: str) -> bool:
        if UserRole.ADMIN in self.roles:
            return True
        return permission in self.permissions

    def has_role(self, role: UserRole) -> bool:
        return role in self.roles

    def increment_failed_login(self):
        self.failed_login_attempts += 1
        self.last_failed_login = datetime.utcnow()
        if self.failed_login_attempts >= 5:
            self.is_locked = True

    def reset_failed_login(self):
        self.failed_login_attempts = 0
        self.last_failed_login = None
        self.is_locked = False
        self.last_login = datetime.utcnow()


class Token(BaseModel):
    token: str
    token_type: TokenType
    user_id: UUID
    expires_at: datetime
    created_at: datetime = Field(default_factory=datetime.utcnow)
    revoked: bool = False
    revoked_at: Optional[datetime] = None
    scopes: List[str] = Field(default_factory=list)
    client_id: Optional[str] = None
    device_fingerprint: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    def is_valid(self) -> bool:
        return not self.revoked and not self.is_expired()

    def revoke(self):
        self.revoked = True
        self.revoked_at = datetime.utcnow()


class MFAConfig(BaseModel):
    user_id: UUID
    method: MFAMethod
    secret: Optional[SecretStr] = None
    backup_codes: List[str] = Field(default_factory=list)
    phone_number: Optional[str] = None
    email: Optional[EmailStr] = None
    device_id: Optional[str] = None
    is_primary: bool = False
    is_verified: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_used_at: Optional[datetime] = None

    def generate_backup_codes(self, count: int = 10) -> List[str]:
        codes = []
        for _ in range(count):
            code = secrets.token_hex(4).upper()
            code_formatted = f"{code[:4]}-{code[4:]}"
            codes.append(code_formatted)
        self.backup_codes = [hashlib.sha256(code.encode()).hexdigest() for code in codes]
        return codes

    def verify_backup_code(self, code: str) -> bool:
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        if code_hash in self.backup_codes:
            self.backup_codes.remove(code_hash)
            self.last_used_at = datetime.utcnow()
            return True
        return False


class LoginRequest(BaseModel):
    username: str
    password: SecretStr
    mfa_code: Optional[str] = None
    device_fingerprint: Optional[str] = None
    remember_me: bool = False


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int
    requires_mfa: bool = False
    mfa_methods: Optional[List[MFAMethod]] = None


class MFAVerifyRequest(BaseModel):
    user_id: UUID
    method: MFAMethod
    code: str
    session_token: Optional[str] = None


class OAuth2Config(BaseModel):
    provider: str
    client_id: str
    client_secret: SecretStr
    authorization_url: str
    token_url: str
    user_info_url: str
    scopes: List[str] = Field(default_factory=list)
    redirect_uri: str


class SAMLConfig(BaseModel):
    entity_id: str
    sso_url: str
    certificate: str
    attribute_mapping: Dict[str, str]
    signature_algorithm: str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    digest_algorithm: str = "http://www.w3.org/2001/04/xmlenc#sha256"


class LDAPConfig(BaseModel):
    server_url: str
    bind_dn: str
    bind_password: SecretStr
    base_dn: str
    user_filter: str = "(uid={username})"
    group_filter: str = "(memberUid={username})"
    attribute_mapping: Dict[str, str] = Field(default_factory=dict)
    use_ssl: bool = True
    verify_cert: bool = True


class Session(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    user_id: UUID
    token_id: UUID
    ip_address: str
    user_agent: str
    device_fingerprint: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_activity: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime
    is_active: bool = True

    def update_activity(self):
        self.last_activity = datetime.utcnow()

    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    def terminate(self):
        self.is_active = False


class AuditLog(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    user_id: Optional[UUID] = None
    username: Optional[str] = None
    action: str
    resource: Optional[str] = None
    resource_id: Optional[str] = None
    result: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[UUID] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    duration_ms: Optional[int] = None

    class Config:
        json_encoders = {
            UUID: str,
            datetime: lambda v: v.isoformat()
        }