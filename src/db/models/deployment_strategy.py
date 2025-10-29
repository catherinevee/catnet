"""
Advanced Deployment Strategy Models
Database models for sophisticated deployment patterns (Canary, Blue-Green, A/B Testing)
"""
from sqlalchemy import Column, String, DateTime, Enum, JSON, Integer, Float, Boolean, ForeignKey, Text
from sqlalchemy.orm import relationship
from src.db.base import Base
import enum
from datetime import datetime
import uuid


class DeploymentStrategy(str, enum.Enum):
    """Deployment strategy types"""
    BASIC = "basic"              # All devices at once (existing behavior)
    CANARY = "canary"            # Progressive rollout (10%, 25%, 50%, 100%)
    BLUE_GREEN = "blue_green"    # Zero-downtime cutover
    AB_TEST = "ab_test"          # Split testing for configuration validation


class DeploymentPhaseStatus(str, enum.Enum):
    """Status of a deployment phase"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    PAUSED = "paused"


class HealthCheckStatus(str, enum.Enum):
    """Health check result"""
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"


class AdvancedDeployment(Base):
    """
    Advanced deployment configuration

    Supports multiple deployment strategies with health monitoring
    and automatic rollback capabilities.

    Attributes:
        id: Unique identifier
        name: Deployment name
        strategy: Type of deployment (canary, blue-green, etc.)
        device_ids: List of target devices
        config_data: Configuration to deploy
        canary_percentages: Rollout percentages for canary deployments
        health_check_interval: Seconds between health checks
        auto_rollback_on_failure: Automatically rollback on failure
        error_rate_threshold: Max error rate before triggering rollback
        latency_threshold_ms: Max latency before triggering rollback
    """
    __tablename__ = "advanced_deployments"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    description = Column(Text)
    strategy = Column(Enum(DeploymentStrategy), nullable=False)

    # Target devices and configuration
    device_ids = Column(JSON, nullable=False)  # List of device IDs
    config_data = Column(JSON, nullable=False)  # Configuration to deploy

    # Canary deployment configuration
    canary_percentages = Column(JSON, default=lambda: [10, 25, 50, 100])

    # Health monitoring configuration
    health_check_interval = Column(Integer, default=60)  # seconds
    auto_rollback_on_failure = Column(Boolean, default=True)

    # Metrics thresholds for auto-rollback
    error_rate_threshold = Column(Float, default=0.05)  # 5% error rate
    latency_threshold_ms = Column(Integer, default=1000)  # 1 second
    min_success_rate = Column(Float, default=0.95)  # 95% success rate

    # Blue-Green specific
    blue_group = Column(JSON)  # List of blue device IDs
    green_group = Column(JSON)  # List of green device IDs
    active_group = Column(String)  # "blue" or "green"

    # A/B Testing specific
    variant_a_devices = Column(JSON)
    variant_b_devices = Column(JSON)
    success_metric = Column(String)  # Metric to compare

    # Deployment lifecycle
    created_by = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    rolled_back_at = Column(DateTime)

    overall_status = Column(Enum(DeploymentPhaseStatus), default=DeploymentPhaseStatus.PENDING)

    # Metadata
    metadata = Column(JSON, default=dict)

    # Relationships
    phases = relationship("DeploymentPhase", back_populates="deployment", cascade="all, delete-orphan")
    health_checks = relationship("DeploymentHealthCheck", back_populates="deployment", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<AdvancedDeployment(id={self.id}, strategy={self.strategy}, status={self.overall_status})>"


class DeploymentPhase(Base):
    """
    Individual phase within a deployment

    For canary: Each percentage increment (10%, 25%, etc.)
    For blue-green: Blue deployment, Green deployment, Cutover
    For A/B: Variant A, Variant B, Analysis

    Attributes:
        id: Unique identifier
        deployment_id: Parent deployment
        phase_number: Sequential phase number (1, 2, 3...)
        percentage: Percentage of devices (for canary)
        device_group: Group identifier (blue/green, A/B)
        target_devices: Specific devices in this phase
        status: Current phase status
        metrics: Collected metrics for this phase
    """
    __tablename__ = "deployment_phases"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    deployment_id = Column(String, ForeignKey("advanced_deployments.id"), nullable=False)
    phase_number = Column(Integer, nullable=False)

    # Phase configuration
    percentage = Column(Integer)  # For canary: 10, 25, 50, 100
    device_group = Column(String)  # blue/green for blue-green, A/B for A/B testing
    target_devices = Column(JSON)  # List of device IDs in this phase

    # Phase status
    status = Column(Enum(DeploymentPhaseStatus), default=DeploymentPhaseStatus.PENDING)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)

    # Collected metrics
    metrics = Column(JSON, default=dict)
    success_count = Column(Integer, default=0)
    failure_count = Column(Integer, default=0)
    avg_duration_ms = Column(Float)

    # Error details if failed
    error_message = Column(Text)
    failed_devices = Column(JSON)  # List of device IDs that failed

    # Relationships
    deployment = relationship("AdvancedDeployment", back_populates="phases")
    health_checks = relationship("DeploymentHealthCheck", back_populates="phase", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<DeploymentPhase(id={self.id}, phase={self.phase_number}, status={self.status})>"

    @property
    def success_rate(self) -> float:
        """Calculate success rate for this phase"""
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.0
        return self.success_count / total


class DeploymentHealthCheck(Base):
    """
    Health check results for deployment monitoring

    Tracks metrics like error rates, latency, and device health
    to determine if deployment should continue or rollback.

    Attributes:
        id: Unique identifier
        deployment_id: Parent deployment
        phase_id: Specific phase being checked
        checked_at: When check was performed
        success_rate: Percentage of successful operations
        avg_latency_ms: Average latency in milliseconds
        error_count: Number of errors detected
        warning_count: Number of warnings detected
        passed: Whether health check passed thresholds
        metrics_detail: Detailed metrics data
    """
    __tablename__ = "deployment_health_checks"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    deployment_id = Column(String, ForeignKey("advanced_deployments.id"), nullable=False)
    phase_id = Column(String, ForeignKey("deployment_phases.id"))

    # Check timing
    checked_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Health metrics
    success_rate = Column(Float)  # 0.0 to 1.0
    avg_latency_ms = Column(Float)
    error_count = Column(Integer, default=0)
    warning_count = Column(Integer, default=0)

    # Device-level metrics
    devices_healthy = Column(Integer)
    devices_unhealthy = Column(Integer)
    devices_unreachable = Column(Integer)

    # Overall result
    status = Column(Enum(HealthCheckStatus), nullable=False)
    passed = Column(Boolean, nullable=False)

    # Detailed metrics
    metrics_detail = Column(JSON, default=dict)

    # Failure details
    failure_reason = Column(Text)
    unhealthy_devices = Column(JSON)  # List of unhealthy device IDs

    # Relationships
    deployment = relationship("AdvancedDeployment", back_populates="health_checks")
    phase = relationship("DeploymentPhase", back_populates="health_checks")

    def __repr__(self):
        return f"<DeploymentHealthCheck(id={self.id}, status={self.status}, passed={self.passed})>"


class DeploymentRollback(Base):
    """
    Rollback record for failed deployments

    Tracks rollback operations including which devices were
    rolled back and the configuration restored.

    Attributes:
        id: Unique identifier
        deployment_id: Deployment that was rolled back
        triggered_by: User or system that triggered rollback
        triggered_at: When rollback was initiated
        reason: Why rollback was triggered
        devices_rolled_back: Devices that were rolled back
        completed: Whether rollback completed successfully
    """
    __tablename__ = "deployment_rollbacks"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    deployment_id = Column(String, ForeignKey("advanced_deployments.id"), nullable=False)

    triggered_by = Column(String)  # user_id or "system"
    triggered_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    completed_at = Column(DateTime)

    reason = Column(Text, nullable=False)
    devices_rolled_back = Column(JSON)  # List of device IDs

    # Rollback status
    completed = Column(Boolean, default=False)
    success = Column(Boolean)
    error_message = Column(Text)

    # Previous configuration restored
    restored_config = Column(JSON)

    def __repr__(self):
        return f"<DeploymentRollback(id={self.id}, completed={self.completed}, success={self.success})>"
