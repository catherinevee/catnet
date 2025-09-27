from pydantic import BaseModel, Field, EmailStr, SecretStr, ConfigDict, field_validator, model_validator
from typing import Optional, List, Dict, Any, Union
from datetime import datetime
from enum import Enum
from uuid import UUID
import re


class UserRole(str, Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"
    AUDITOR = "auditor"


class DeploymentState(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class DeviceVendor(str, Enum):
    CISCO_IOS = "cisco_ios"
    CISCO_IOS_XE = "cisco_ios_xe"
    CISCO_NX_OS = "cisco_nx_os"
    JUNIPER_JUNOS = "juniper_junos"


class DeploymentStrategy(str, Enum):
    ROLLING = "rolling"
    CANARY = "canary"
    BLUE_GREEN = "blue_green"
    ALL_AT_ONCE = "all_at_once"


class ValidationSeverity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


# User Schemas
class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern="^[a-zA-Z0-9_-]+$")
    email: EmailStr
    full_name: Optional[str] = Field(None, max_length=255)
    role: UserRole = UserRole.VIEWER
    mfa_enabled: bool = False


class UserCreate(UserBase):
    password: SecretStr = Field(..., min_length=12, max_length=128)

    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v: SecretStr) -> SecretStr:
        password = v.get_secret_value()
        if not re.search(r'[A-Z]', password):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', password):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'[0-9]', password):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValueError('Password must contain at least one special character')
        return v


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = Field(None, max_length=255)
    role: Optional[UserRole] = None
    mfa_enabled: Optional[bool] = None
    is_active: Optional[bool] = None


class UserResponse(UserBase):
    id: UUID
    is_active: bool
    is_superuser: bool
    last_login: Optional[datetime] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class UserLogin(BaseModel):
    username: str
    password: SecretStr
    mfa_token: Optional[str] = Field(None, pattern="^[0-9]{6}$")


class MFASetup(BaseModel):
    secret: str
    qr_code: str
    backup_codes: List[str]


class MFAVerify(BaseModel):
    token: str = Field(..., pattern="^[0-9]{6}$")


# Token Schemas
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenRefresh(BaseModel):
    refresh_token: str


class TokenData(BaseModel):
    username: Optional[str] = None
    user_id: Optional[str] = None
    scopes: List[str] = []


# Device Schemas
class DeviceBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    hostname: str = Field(..., min_length=1, max_length=255)
    ip_address: str = Field(..., pattern="^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$")
    vendor: DeviceVendor
    model: Optional[str] = Field(None, max_length=255)
    serial_number: Optional[str] = Field(None, max_length=255)
    location: Optional[str] = Field(None, max_length=255)
    site: Optional[str] = Field(None, max_length=255)
    bastion_host: Optional[str] = Field(None, max_length=255)


class DeviceCreate(DeviceBase):
    vault_credential_path: str = Field(..., min_length=1, max_length=512)
    certificate_fingerprint: Optional[str] = Field(None, max_length=128)
    ssh_fingerprint: Optional[str] = Field(None, max_length=256)


class DeviceUpdate(BaseModel):
    hostname: Optional[str] = Field(None, max_length=255)
    ip_address: Optional[str] = Field(None, pattern="^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$")
    model: Optional[str] = Field(None, max_length=255)
    location: Optional[str] = Field(None, max_length=255)
    site: Optional[str] = Field(None, max_length=255)
    bastion_host: Optional[str] = Field(None, max_length=255)
    is_active: Optional[bool] = None


class DeviceResponse(DeviceBase):
    id: UUID
    is_active: bool
    last_seen: Optional[datetime] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class DeviceCommand(BaseModel):
    command: str = Field(..., min_length=1, max_length=1000)
    timeout: int = Field(30, ge=1, le=300)
    require_confirmation: bool = False


class DeviceBackup(BaseModel):
    device_id: UUID
    trigger_backup: bool = True
    compress: bool = True


# Git Repository Schemas
class GitRepositoryBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    url: str = Field(..., pattern="^(https?|git|ssh)://.+$")
    branch: str = Field("main", max_length=100)
    gpg_verification: bool = True
    auto_deploy: bool = False


class GitRepositoryCreate(GitRepositoryBase):
    webhook_secret_ref: str = Field(..., min_length=1, max_length=256)
    ssh_key_ref: Optional[str] = Field(None, max_length=256)


class GitRepositoryUpdate(BaseModel):
    branch: Optional[str] = Field(None, max_length=100)
    gpg_verification: Optional[bool] = None
    auto_deploy: Optional[bool] = None
    is_active: Optional[bool] = None


class GitRepositoryResponse(GitRepositoryBase):
    id: UUID
    last_commit_hash: Optional[str] = None
    last_sync: Optional[datetime] = None
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class WebhookPayload(BaseModel):
    repository: str
    ref: str
    commits: List[Dict[str, Any]]
    head_commit: Dict[str, Any]
    pusher: Dict[str, Any]
    signature: Optional[str] = None


# Deployment Schemas
class DeploymentBase(BaseModel):
    strategy: DeploymentStrategy = DeploymentStrategy.ROLLING
    approval_required: bool = True
    min_approvals: int = Field(2, ge=1, le=10)
    canary_percentage: int = Field(5, ge=1, le=100)
    rollback_on_failure: bool = True
    dry_run: bool = False


class DeploymentCreate(DeploymentBase):
    repository_id: UUID
    device_ids: List[UUID] = Field(..., min_items=1)
    config_hash: str = Field(..., min_length=64, max_length=64)
    commit_hash: Optional[str] = Field(None, min_length=40, max_length=40)
    commit_message: Optional[str] = None


class DeploymentApproval(BaseModel):
    deployment_id: UUID
    approve: bool
    comments: Optional[str] = Field(None, max_length=1000)


class DeploymentRollback(BaseModel):
    deployment_id: UUID
    reason: str = Field(..., min_length=1, max_length=1000)
    rollback_to_version: Optional[int] = None


class DeploymentResponse(DeploymentBase):
    id: UUID
    repository_id: Optional[UUID] = None
    created_by: UUID
    state: DeploymentState
    approved_by: List[UUID] = []
    approval_count: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    rolled_back_at: Optional[datetime] = None
    error_details: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class DeploymentStatus(BaseModel):
    deployment_id: UUID
    state: DeploymentState
    progress_percentage: int = Field(0, ge=0, le=100)
    devices_total: int
    devices_completed: int
    devices_failed: int
    current_stage: str
    estimated_completion: Optional[datetime] = None
    errors: List[str] = []
    warnings: List[str] = []


# Configuration Validation Schemas
class ConfigValidationRequest(BaseModel):
    config_content: str
    vendor: DeviceVendor
    device_id: Optional[UUID] = None
    strict_mode: bool = True


class ValidationIssue(BaseModel):
    severity: ValidationSeverity
    line_number: Optional[int] = None
    rule: str
    message: str
    suggestion: Optional[str] = None


class ConfigValidationResponse(BaseModel):
    is_valid: bool
    syntax_valid: bool
    security_compliant: bool
    business_rules_passed: bool
    issues: List[ValidationIssue] = []
    score: int = Field(0, ge=0, le=100)


# Audit Log Schemas
class AuditLogCreate(BaseModel):
    action: str = Field(..., min_length=1, max_length=255)
    resource_type: Optional[str] = Field(None, max_length=100)
    resource_id: Optional[str] = Field(None, max_length=255)
    details: Dict[str, Any] = {}
    severity: str = Field("info", pattern="^(info|warning|error|critical)$")
    success: bool = True
    error_message: Optional[str] = None


class AuditLogResponse(BaseModel):
    id: UUID
    user_id: Optional[UUID] = None
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    details: Dict[str, Any] = {}
    severity: str
    success: bool
    error_message: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuditLogQuery(BaseModel):
    user_id: Optional[UUID] = None
    action: Optional[str] = None
    resource_type: Optional[str] = None
    severity: Optional[str] = None
    success: Optional[bool] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    limit: int = Field(100, ge=1, le=1000)
    offset: int = Field(0, ge=0)


# Security Event Schemas
class SecurityEventCreate(BaseModel):
    event_type: str = Field(..., min_length=1, max_length=100)
    severity: str = Field(..., pattern="^(low|medium|high|critical)$")
    source_ip: Optional[str] = None
    target_resource: Optional[str] = Field(None, max_length=255)
    description: str
    details: Dict[str, Any] = {}


class SecurityEventResponse(BaseModel):
    id: UUID
    event_type: str
    severity: str
    source_ip: Optional[str] = None
    target_resource: Optional[str] = None
    user_id: Optional[UUID] = None
    description: str
    details: Dict[str, Any] = {}
    resolved: bool
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[UUID] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Health & Monitoring Schemas
class ServiceHealth(BaseModel):
    service_name: str
    status: str = Field(..., pattern="^(healthy|degraded|unhealthy|unknown)$")
    uptime_seconds: int = Field(..., ge=0)
    version: str
    checks: Dict[str, bool]
    metrics: Dict[str, Union[int, float]]
    last_check: datetime


class SystemHealth(BaseModel):
    overall_status: str = Field(..., pattern="^(healthy|degraded|unhealthy)$")
    services: List[ServiceHealth]
    database_connected: bool
    redis_connected: bool
    vault_connected: bool
    message_queue_connected: bool
    timestamp: datetime


# Device Config Schemas
class DeviceConfigBackup(BaseModel):
    device_id: UUID
    config_content: str
    version: int
    is_current: bool = False


class DeviceConfigRestore(BaseModel):
    device_id: UUID
    config_id: UUID
    verify_before_apply: bool = True
    create_backup: bool = True


class DeviceConfigCompare(BaseModel):
    device_id: UUID
    source_version: int
    target_version: int


class DeviceConfigDiff(BaseModel):
    device_id: UUID
    source_version: int
    target_version: int
    additions: List[str]
    deletions: List[str]
    modifications: List[str]
    unchanged_lines: int
    total_changes: int


# Batch Operations Schemas
class BatchDeviceOperation(BaseModel):
    device_ids: List[UUID] = Field(..., min_items=1, max_items=100)
    operation: str = Field(..., pattern="^(backup|health_check|sync|restart)$")
    parallel: bool = True
    stop_on_error: bool = False
    timeout_per_device: int = Field(60, ge=10, le=600)


class BatchOperationResult(BaseModel):
    operation_id: UUID
    total_devices: int
    successful: int
    failed: int
    in_progress: int
    results: Dict[str, Dict[str, Any]]
    started_at: datetime
    completed_at: Optional[datetime] = None


# Notification Schemas
class NotificationCreate(BaseModel):
    recipient_id: UUID
    notification_type: str = Field(..., pattern="^(email|slack|teams|webhook)$")
    subject: str = Field(..., max_length=255)
    message: str
    priority: str = Field("normal", pattern="^(low|normal|high|critical)$")
    metadata: Dict[str, Any] = {}


class NotificationResponse(BaseModel):
    id: UUID
    recipient_id: UUID
    notification_type: str
    subject: str
    sent: bool
    sent_at: Optional[datetime] = None
    error: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Pagination
class PaginationParams(BaseModel):
    page: int = Field(1, ge=1)
    page_size: int = Field(50, ge=1, le=1000)
    order_by: Optional[str] = None
    order_desc: bool = False


class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    page_size: int
    total_pages: int
    has_next: bool
    has_prev: bool