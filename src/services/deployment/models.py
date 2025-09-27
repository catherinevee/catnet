"""
Data models for deployment service.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
import uuid

from pydantic import BaseModel, Field, validator


class DeploymentStatus(str, Enum):
    """Deployment status."""
    PENDING = "pending"
    APPROVED = "approved"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ROLLED_BACK = "rolled_back"


class DeploymentStrategy(str, Enum):
    """Deployment strategies."""
    CANARY = "canary"
    ROLLING = "rolling"
    BLUE_GREEN = "blue_green"
    ALL_AT_ONCE = "all_at_once"
    CUSTOM = "custom"


class DeviceStatus(str, Enum):
    """Device deployment status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    SKIPPED = "skipped"


class ApprovalAction(str, Enum):
    """Approval actions."""
    APPROVE = "approve"
    REJECT = "reject"
    DEFER = "defer"


class Deployment(BaseModel):
    """Deployment model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    config: Dict[str, Any]
    config_hash: str
    config_encrypted: Optional[str] = None
    signature: Optional[str] = None
    strategy: DeploymentStrategy
    target_devices: List[str]
    target_groups: Optional[List[str]] = None
    target_tags: Optional[Dict[str, str]] = None
    status: DeploymentStatus = DeploymentStatus.PENDING
    requires_approval: bool = False
    approval_count: int = 1
    approved_by: List[str] = []
    approved_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    cancelled_at: Optional[datetime] = None
    cancelled_by: Optional[str] = None
    cancel_reason: Optional[str] = None
    successful_devices: List[str] = []
    failed_devices: List[str] = []
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    dry_run: bool = False
    scheduled_at: Optional[datetime] = None
    timeout_seconds: int = 3600
    max_parallel: int = 10
    rollback_on_failure: bool = True
    rollback_performed: bool = False
    rollback_at: Optional[datetime] = None
    rollback_by: Optional[str] = None
    rollback_reason: Optional[str] = None
    rollback_result: Optional[Dict[str, Any]] = None
    validation_errors: List[str] = []
    compliance_status: Optional[Dict[str, bool]] = None
    metrics: Optional[Dict[str, Any]] = None
    tags: Dict[str, str] = {}


class DeploymentDevice(BaseModel):
    """Deployment device status."""
    deployment_id: str
    device_id: str
    device_name: Optional[str] = None
    device_type: Optional[str] = None
    status: DeviceStatus = DeviceStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    config_applied: Optional[Dict[str, Any]] = None
    backup_id: Optional[str] = None
    rollback_id: Optional[str] = None
    error: Optional[str] = None
    retry_count: int = 0
    last_retry_at: Optional[datetime] = None
    validation_passed: bool = False
    health_check_passed: bool = False
    metrics: Optional[Dict[str, Any]] = None


class DeploymentRequest(BaseModel):
    """Deployment creation request."""
    config: Dict[str, Any]
    config_type: str = "yaml"
    strategy: DeploymentStrategy = DeploymentStrategy.ROLLING
    target: Dict[str, Any]  # Device selection criteria
    requires_approval: bool = False
    approval_count: int = Field(default=1, ge=1, le=10)
    dry_run: bool = False
    scheduled_at: Optional[datetime] = None
    timeout_seconds: int = Field(default=3600, ge=60, le=86400)
    max_parallel: int = Field(default=10, ge=1, le=100)
    rollback_on_failure: bool = True
    validate_only: bool = False
    tags: Dict[str, str] = {}
    notification_config: Optional[Dict[str, Any]] = None

    @validator('scheduled_at')
    def validate_schedule(cls, v):
        if v and v < datetime.utcnow():
            raise ValueError('Scheduled time must be in the future')
        return v


class DeploymentResponse(BaseModel):
    """Deployment response."""
    deployment_id: str
    status: DeploymentStatus
    strategy: DeploymentStrategy
    target_devices: List[str]
    requires_approval: bool
    created_at: datetime
    scheduled_at: Optional[datetime] = None
    estimated_completion: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    metrics: Optional['DeploymentMetrics'] = None
    validation: Optional['ValidationResult'] = None


class DeploymentUpdateRequest(BaseModel):
    """Deployment update request."""
    status: Optional[DeploymentStatus] = None
    config: Optional[Dict[str, Any]] = None
    target_devices: Optional[List[str]] = None
    scheduled_at: Optional[datetime] = None
    timeout_seconds: Optional[int] = Field(None, ge=60, le=86400)
    max_parallel: Optional[int] = Field(None, ge=1, le=100)
    rollback_on_failure: Optional[bool] = None
    tags: Optional[Dict[str, str]] = None


class DeploymentApproval(BaseModel):
    """Deployment approval record."""
    deployment_id: str
    user_id: str
    action: ApprovalAction
    comment: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ApprovalRequest(BaseModel):
    """Approval request."""
    action: ApprovalAction = ApprovalAction.APPROVE
    comment: Optional[str] = Field(None, max_length=1000)


class RollbackRequest(BaseModel):
    """Rollback request."""
    reason: Optional[str] = Field(None, max_length=1000)
    devices: Optional[List[str]] = None  # Specific devices to rollback
    force: bool = False


class ValidationRequest(BaseModel):
    """Configuration validation request."""
    config: Dict[str, Any]
    config_type: str = "yaml"
    schema: Optional[Dict[str, Any]] = None
    target_devices: Optional[List[str]] = None
    strict: bool = True


class ValidationResult(BaseModel):
    """Validation result."""
    valid: bool
    errors: List[str] = []
    warnings: List[str] = []
    suggestions: List[str] = []
    passed_checks: List[str] = []
    failed_checks: List[str] = []
    compatibility: Optional[Dict[str, bool]] = None
    compliance: Optional[Dict[str, bool]] = None
    schema_valid: bool = True
    syntax_valid: bool = True
    business_rules_valid: bool = True
    security_compliant: bool = True


class DeploymentMetrics(BaseModel):
    """Deployment metrics."""
    deployment_id: str
    total_devices: int
    successful_devices: int
    failed_devices: int
    skipped_devices: int = 0
    success_rate: float
    avg_device_time: float  # seconds
    total_time: float  # seconds
    config_size_bytes: int = 0
    rollback_count: int = 0
    retry_count: int = 0
    error_rate: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class DeploymentHealth(BaseModel):
    """Deployment health status."""
    deployment_id: str
    overall_health: str  # healthy, degraded, unhealthy
    device_health: Dict[str, str]  # device_id -> health status
    progress_percentage: float
    estimated_time_remaining: Optional[int] = None  # seconds
    current_phase: Optional[str] = None
    alerts: List[Dict[str, Any]] = []
    last_updated: datetime = Field(default_factory=datetime.utcnow)


class CanaryConfig(BaseModel):
    """Canary deployment configuration."""
    stages: List[Dict[str, Any]] = [
        {"percentage": 5, "wait_minutes": 5},
        {"percentage": 25, "wait_minutes": 10},
        {"percentage": 50, "wait_minutes": 15},
        {"percentage": 100, "wait_minutes": 0}
    ]
    health_check_interval: int = 60  # seconds
    error_threshold: float = 0.1  # 10% error rate threshold
    auto_promote: bool = True
    auto_rollback: bool = True


class RollingConfig(BaseModel):
    """Rolling deployment configuration."""
    batch_size: int = Field(default=5, ge=1, le=50)
    batch_delay: int = Field(default=60, ge=0, le=3600)  # seconds
    max_failures: int = Field(default=1, ge=0, le=10)
    health_check_delay: int = Field(default=30, ge=0, le=300)
    parallel_batches: bool = False


class BlueGreenConfig(BaseModel):
    """Blue-green deployment configuration."""
    switch_percentage: int = Field(default=100, ge=0, le=100)
    validation_period: int = Field(default=300, ge=60, le=3600)  # seconds
    traffic_split: Optional[Dict[str, int]] = None  # blue: 50, green: 50
    auto_switch: bool = True
    keep_previous: bool = True


class DeploymentHistory(BaseModel):
    """Deployment history entry."""
    deployment_id: str
    timestamp: datetime
    event: str  # started, completed, failed, rolled_back, etc
    details: Optional[Dict[str, Any]] = None
    user_id: Optional[str] = None
    device_id: Optional[str] = None


class DeploymentReport(BaseModel):
    """Deployment report."""
    deployment_id: str
    summary: Dict[str, Any]
    device_results: List[Dict[str, Any]]
    timeline: List[DeploymentHistory]
    metrics: DeploymentMetrics
    validation_results: Optional[ValidationResult] = None
    rollback_info: Optional[Dict[str, Any]] = None
    generated_at: datetime = Field(default_factory=datetime.utcnow)


class DeploymentSchedule(BaseModel):
    """Deployment schedule."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    deployment_request: DeploymentRequest
    schedule_type: str  # once, daily, weekly, monthly, cron
    schedule_config: Dict[str, Any]  # cron expression or schedule details
    enabled: bool = True
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: str


class DeploymentTemplate(BaseModel):
    """Deployment template."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    config_template: Dict[str, Any]
    variables: Dict[str, Any] = {}  # Variable definitions
    strategy: DeploymentStrategy
    default_values: Dict[str, Any] = {}
    validation_rules: List[Dict[str, Any]] = []
    tags: Dict[str, str] = {}
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: str
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    version: int = 1


class DeploymentComparison(BaseModel):
    """Deployment comparison result."""
    deployment1_id: str
    deployment2_id: str
    config_differences: List[Dict[str, Any]]
    device_differences: List[str]
    strategy_different: bool
    metrics_comparison: Dict[str, Any]
    recommendation: Optional[str] = None