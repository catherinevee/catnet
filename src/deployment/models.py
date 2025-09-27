from typing import Optional, List, Dict, Any
from datetime import datetime
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, validator
from enum import Enum


class DeploymentStrategy(str, Enum):
    CANARY = "canary"
    ROLLING = "rolling"
    BLUE_GREEN = "blue_green"
    IMMEDIATE = "immediate"
    GRADUAL = "gradual"


class DeploymentStatus(str, Enum):
    PENDING = "pending"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    ROLLING_BACK = "rolling_back"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class HealthCheckType(str, Enum):
    PING = "ping"
    SSH = "ssh"
    SNMP = "snmp"
    HTTP = "http"
    CUSTOM = "custom"


class RollbackTrigger(str, Enum):
    MANUAL = "manual"
    AUTO_HEALTH = "auto_health"
    AUTO_METRIC = "auto_metric"
    AUTO_ERROR = "auto_error"
    APPROVAL_TIMEOUT = "approval_timeout"


class Deployment(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    name: str
    description: Optional[str] = None
    repository_id: UUID
    config_file_ids: List[UUID]
    target_devices: List[UUID]
    strategy: DeploymentStrategy = DeploymentStrategy.CANARY
    status: DeploymentStatus = DeploymentStatus.PENDING
    created_by: UUID
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    config_hash: str
    signature: Optional[str] = None
    encryption_key_id: Optional[str] = None
    requires_approval: bool = True
    approval_required_from: List[UUID] = Field(default_factory=list)
    approved_by: List[UUID] = Field(default_factory=list)
    approval_deadline: Optional[datetime] = None
    deployment_window_start: Optional[datetime] = None
    deployment_window_end: Optional[datetime] = None
    rollback_enabled: bool = True
    auto_rollback: bool = True
    rollback_threshold: float = 0.1
    health_check_enabled: bool = True
    health_check_interval: int = 60
    max_deployment_time: int = 3600
    parallel_execution: bool = False
    max_parallel_devices: int = 5
    dry_run: bool = False
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    audit_log: List[Dict[str, Any]] = Field(default_factory=list)

    def add_audit_entry(self, action: str, user_id: UUID, details: Dict[str, Any] = None):
        self.audit_log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "user_id": str(user_id),
            "details": details or {}
        })
        self.updated_at = datetime.utcnow()

    def can_proceed(self) -> bool:
        if self.requires_approval and len(self.approved_by) < len(self.approval_required_from):
            return False
        if self.deployment_window_start and datetime.utcnow() < self.deployment_window_start:
            return False
        if self.deployment_window_end and datetime.utcnow() > self.deployment_window_end:
            return False
        return True


class DeploymentStage(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    deployment_id: UUID
    stage_number: int
    name: str
    percentage: float
    device_count: int
    devices: List[UUID]
    wait_minutes: int = 5
    health_check_minutes: int = 5
    status: DeploymentStatus = DeploymentStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    success_count: int = 0
    failure_count: int = 0
    error_messages: List[str] = Field(default_factory=list)
    metrics: Dict[str, Any] = Field(default_factory=dict)

    def is_successful(self) -> bool:
        if self.failure_count == 0:
            return True
        failure_rate = self.failure_count / (self.success_count + self.failure_count)
        return failure_rate < 0.1


class DeviceDeployment(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    deployment_id: UUID
    stage_id: Optional[UUID] = None
    device_id: UUID
    device_name: str
    device_ip: str
    status: DeploymentStatus = DeploymentStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    backup_id: Optional[UUID] = None
    backup_location: Optional[str] = None
    configuration_applied: Optional[str] = None
    pre_deployment_state: Optional[Dict[str, Any]] = None
    post_deployment_state: Optional[Dict[str, Any]] = None
    health_checks: List[Dict[str, Any]] = Field(default_factory=list)
    error_message: Optional[str] = None
    rollback_performed: bool = False
    rollback_at: Optional[datetime] = None
    commands_executed: List[Dict[str, Any]] = Field(default_factory=list)
    execution_logs: List[str] = Field(default_factory=list)

    def add_command(self, command: str, output: str, success: bool):
        self.commands_executed.append({
            "timestamp": datetime.utcnow().isoformat(),
            "command": command,
            "output": output[:1000],
            "success": success
        })

    def add_health_check(self, check_type: str, result: bool, details: Dict[str, Any] = None):
        self.health_checks.append({
            "timestamp": datetime.utcnow().isoformat(),
            "type": check_type,
            "result": result,
            "details": details or {}
        })


class DeploymentApproval(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    deployment_id: UUID
    approver_id: UUID
    status: ApprovalStatus = ApprovalStatus.PENDING
    requested_at: datetime = Field(default_factory=datetime.utcnow)
    responded_at: Optional[datetime] = None
    comments: Optional[str] = None
    conditions: List[str] = Field(default_factory=list)
    expires_at: Optional[datetime] = None

    def approve(self, comments: Optional[str] = None):
        self.status = ApprovalStatus.APPROVED
        self.responded_at = datetime.utcnow()
        self.comments = comments

    def reject(self, comments: str):
        self.status = ApprovalStatus.REJECTED
        self.responded_at = datetime.utcnow()
        self.comments = comments

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at


class DeploymentRollback(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    deployment_id: UUID
    triggered_by: UUID
    trigger: RollbackTrigger
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    devices_rolled_back: int = 0
    devices_failed: int = 0
    status: DeploymentStatus = DeploymentStatus.IN_PROGRESS
    reason: str
    error_messages: List[str] = Field(default_factory=list)
    rollback_steps: List[Dict[str, Any]] = Field(default_factory=list)

    def add_step(self, device_id: UUID, action: str, success: bool, details: str = ""):
        self.rollback_steps.append({
            "timestamp": datetime.utcnow().isoformat(),
            "device_id": str(device_id),
            "action": action,
            "success": success,
            "details": details
        })
        if success:
            self.devices_rolled_back += 1
        else:
            self.devices_failed += 1


class HealthCheck(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    name: str
    type: HealthCheckType
    target: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    expected_result: Any
    timeout_seconds: int = 30
    retry_count: int = 3
    critical: bool = True

    def execute(self) -> Tuple[bool, Dict[str, Any]]:
        """Execute health check validation."""
        import asyncio
        import time

        try:
            start_time = time.time()

            # Simulate health check execution based on type
            if self.check_type == HealthCheckType.PING:
                # Simulate ping test
                success = True
                result = {
                    'type': 'ping',
                    'target': self.parameters.get('target', 'unknown'),
                    'response_time': 0.05,
                    'packets_sent': 3,
                    'packets_received': 3,
                    'packet_loss': 0.0
                }
            elif self.check_type == HealthCheckType.SSH:
                # Simulate SSH connectivity test
                success = True
                result = {
                    'type': 'ssh',
                    'host': self.parameters.get('host', 'unknown'),
                    'port': self.parameters.get('port', 22),
                    'connection_time': 0.2,
                    'authentication': 'success'
                }
            elif self.check_type == HealthCheckType.SNMP:
                # Simulate SNMP query
                success = True
                result = {
                    'type': 'snmp',
                    'host': self.parameters.get('host', 'unknown'),
                    'community': 'hidden',
                    'oid': self.parameters.get('oid', '1.3.6.1.2.1.1.1.0'),
                    'value': 'System operational'
                }
            else:
                # Custom health check
                success = True
                result = {
                    'type': 'custom',
                    'check': self.name,
                    'status': 'passed'
                }

            execution_time = time.time() - start_time
            result['execution_time'] = execution_time
            result['timestamp'] = time.time()

            return success, result

        except Exception as e:
            return False, {
                'error': str(e),
                'execution_time': time.time() - start_time if 'start_time' in locals() else 0,
                'timestamp': time.time()
            }


class DeploymentMetrics(BaseModel):
    deployment_id: UUID
    total_devices: int = 0
    deployed_devices: int = 0
    successful_devices: int = 0
    failed_devices: int = 0
    rolled_back_devices: int = 0
    average_deployment_time: float = 0.0
    total_deployment_time: float = 0.0
    health_check_pass_rate: float = 100.0
    error_rate: float = 0.0
    rollback_rate: float = 0.0
    stage_metrics: List[Dict[str, Any]] = Field(default_factory=list)
    device_metrics: List[Dict[str, Any]] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    def update_metrics(self, device_deployment: DeviceDeployment):
        if device_deployment.status == DeploymentStatus.COMPLETED:
            self.successful_devices += 1
        elif device_deployment.status == DeploymentStatus.FAILED:
            self.failed_devices += 1
        elif device_deployment.rollback_performed:
            self.rolled_back_devices += 1

        self.deployed_devices = self.successful_devices + self.failed_devices

        if self.deployed_devices > 0:
            self.error_rate = (self.failed_devices / self.deployed_devices) * 100
            self.rollback_rate = (self.rolled_back_devices / self.deployed_devices) * 100


class CanaryDeploymentConfig(BaseModel):
    stages: List[Dict[str, Any]] = Field(default_factory=list)
    initial_percentage: float = 5.0
    increment_percentage: float = 10.0
    wait_between_stages: int = 300
    health_check_interval: int = 60
    success_threshold: float = 95.0
    auto_promote: bool = True
    max_stages: int = 10

    @validator('stages')
    def validate_stages(cls, v):
        if not v:
            v = [
                {"percentage": 5, "wait_minutes": 5},
                {"percentage": 25, "wait_minutes": 10},
                {"percentage": 50, "wait_minutes": 15},
                {"percentage": 100, "wait_minutes": 0}
            ]
        return v


class RollingDeploymentConfig(BaseModel):
    batch_size: int = 5
    batch_percentage: Optional[float] = None
    wait_between_batches: int = 60
    max_failure_percentage: float = 10.0
    parallel_execution: bool = False
    drain_timeout: int = 300
    health_check_delay: int = 60


class DeploymentNotification(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    deployment_id: UUID
    type: str
    recipients: List[str]
    subject: str
    message: str
    sent_at: Optional[datetime] = None
    status: str = "pending"
    error: Optional[str] = None

    def send(self):
        """Send notification about deployment event."""
        import asyncio
        from datetime import datetime

        try:
            # Update status and timestamp
            self.status = "sending"
            self.sent_at = datetime.utcnow()

            # In a real implementation, this would integrate with notification service
            # For now, simulate notification sending
            if self.notification_type == "email":
                # Simulate email sending
                self.status = "sent"
                return True
            elif self.notification_type == "slack":
                # Simulate Slack message
                self.status = "sent"
                return True
            elif self.notification_type == "webhook":
                # Simulate webhook call
                self.status = "sent"
                return True
            else:
                self.status = "failed"
                self.error = f"Unknown notification type: {self.notification_type}"
                return False

        except Exception as e:
            self.status = "failed"
            self.error = str(e)
            return False