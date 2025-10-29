"""
Monitoring and Health Check Models
Database models for health monitoring, SLA tracking, and alerting
"""
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, JSON, Text, ForeignKey, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import enum

from ..database import Base


class HealthCheckType(str, enum.Enum):
    """Types of health checks"""
    HTTP = "http"
    TCP = "tcp"
    ICMP = "icmp"
    SSH = "ssh"
    SNMP = "snmp"
    NETCONF = "netconf"
    CUSTOM = "custom"


class HealthStatus(str, enum.Enum):
    """Health check status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class AlertSeverity(str, enum.Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, enum.Enum):
    """Alert status"""
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


class SLAStatus(str, enum.Enum):
    """SLA compliance status"""
    COMPLIANT = "compliant"
    AT_RISK = "at_risk"
    VIOLATED = "violated"


class NotificationChannel(str, enum.Enum):
    """Notification delivery channels"""
    EMAIL = "email"
    SLACK = "slack"
    WEBHOOK = "webhook"
    PAGERDUTY = "pagerduty"
    SMS = "sms"


class HealthCheck(Base):
    """
    Health Check Configuration
    Defines custom health checks for devices and services
    """
    __tablename__ = "health_checks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(200), nullable=False, index=True)
    description = Column(Text)

    # Check configuration
    check_type = Column(SQLEnum(HealthCheckType), nullable=False)
    target = Column(String(500), nullable=False)  # IP, URL, device ID
    check_config = Column(JSON, default={})  # Type-specific configuration

    # Scheduling
    interval_seconds = Column(Integer, default=60)  # How often to run
    timeout_seconds = Column(Integer, default=10)
    retry_count = Column(Integer, default=3)
    retry_interval_seconds = Column(Integer, default=5)

    # Thresholds
    expected_response = Column(JSON)  # Expected response for comparison
    success_threshold = Column(Integer, default=1)  # Consecutive successes
    failure_threshold = Column(Integer, default=3)  # Consecutive failures

    # Status
    enabled = Column(Boolean, default=True)
    current_status = Column(SQLEnum(HealthStatus), default=HealthStatus.UNKNOWN)
    last_check_at = Column(DateTime)
    consecutive_successes = Column(Integer, default=0)
    consecutive_failures = Column(Integer, default=0)

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))

    # Tags for grouping
    tags = Column(ARRAY(String), default=[])

    # Relationships
    results = relationship("HealthCheckResult", back_populates="health_check", cascade="all, delete-orphan")
    alert_rules = relationship("AlertRule", back_populates="health_check", cascade="all, delete-orphan")


class HealthCheckResult(Base):
    """
    Health Check Execution Results
    Stores individual check execution results
    """
    __tablename__ = "health_check_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    health_check_id = Column(UUID(as_uuid=True), ForeignKey("health_checks.id"), nullable=False, index=True)

    # Execution details
    executed_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    duration_ms = Column(Float)

    # Result
    status = Column(SQLEnum(HealthStatus), nullable=False)
    success = Column(Boolean, nullable=False)
    response_data = Column(JSON)
    error_message = Column(Text)

    # Metrics
    response_time_ms = Column(Float)
    status_code = Column(Integer)

    # Additional context
    metadata = Column(JSON, default={})

    # Relationship
    health_check = relationship("HealthCheck", back_populates="results")


class SLA(Base):
    """
    Service Level Agreement Configuration
    Tracks SLA targets and compliance
    """
    __tablename__ = "slas"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(200), nullable=False, index=True)
    description = Column(Text)

    # Target service/device
    target_type = Column(String(50), nullable=False)  # device, service, endpoint
    target_id = Column(String(200))  # Optional specific target

    # SLA metrics
    availability_target = Column(Float)  # e.g., 99.9%
    response_time_target_ms = Column(Float)  # Max acceptable response time
    error_rate_target = Column(Float)  # Max acceptable error rate (%)

    # Time windows
    measurement_window_hours = Column(Integer, default=24)
    evaluation_interval_minutes = Column(Integer, default=60)

    # Current compliance
    current_availability = Column(Float, default=100.0)
    current_response_time_ms = Column(Float)
    current_error_rate = Column(Float, default=0.0)
    compliance_status = Column(SQLEnum(SLAStatus), default=SLAStatus.COMPLIANT)

    # Tracking
    last_violation_at = Column(DateTime)
    violation_count = Column(Integer, default=0)
    last_evaluated_at = Column(DateTime)

    # Alerting
    alert_on_violation = Column(Boolean, default=True)
    alert_on_risk = Column(Boolean, default=True)  # Alert when approaching violation

    # Metadata
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))

    # Tags
    tags = Column(ARRAY(String), default=[])

    # Relationships
    violations = relationship("SLAViolation", back_populates="sla", cascade="all, delete-orphan")
    metrics = relationship("SLAMetric", back_populates="sla", cascade="all, delete-orphan")


class SLAViolation(Base):
    """
    SLA Violation Records
    Tracks when SLAs are violated
    """
    __tablename__ = "sla_violations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sla_id = Column(UUID(as_uuid=True), ForeignKey("slas.id"), nullable=False, index=True)

    # Violation details
    violation_type = Column(String(50), nullable=False)  # availability, response_time, error_rate
    detected_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    resolved_at = Column(DateTime)
    duration_minutes = Column(Integer)

    # Metrics at violation
    actual_value = Column(Float, nullable=False)
    target_value = Column(Float, nullable=False)
    deviation_percent = Column(Float)

    # Impact
    severity = Column(SQLEnum(AlertSeverity), nullable=False)
    affected_targets = Column(JSON, default=[])

    # Resolution
    resolved = Column(Boolean, default=False)
    resolution_notes = Column(Text)
    resolved_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))

    # Relationship
    sla = relationship("SLA", back_populates="violations")


class SLAMetric(Base):
    """
    SLA Metric History
    Time-series data for SLA metrics
    """
    __tablename__ = "sla_metrics"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sla_id = Column(UUID(as_uuid=True), ForeignKey("slas.id"), nullable=False, index=True)

    # Metric data
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    availability = Column(Float)
    response_time_ms = Column(Float)
    error_rate = Column(Float)
    request_count = Column(Integer)
    error_count = Column(Integer)

    # Compliance
    compliant = Column(Boolean, nullable=False)

    # Relationship
    sla = relationship("SLA", back_populates="metrics")


class AlertRule(Base):
    """
    Alert Rule Configuration
    Defines conditions and actions for alerts
    """
    __tablename__ = "alert_rules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(200), nullable=False, index=True)
    description = Column(Text)

    # Trigger source
    health_check_id = Column(UUID(as_uuid=True), ForeignKey("health_checks.id"), index=True)
    sla_id = Column(UUID(as_uuid=True), ForeignKey("slas.id"), index=True)

    # Conditions
    condition_type = Column(String(50), nullable=False)  # status_change, threshold, pattern
    condition_config = Column(JSON, nullable=False)  # Condition-specific settings

    # Trigger thresholds
    trigger_on_statuses = Column(ARRAY(String))  # Which statuses trigger alert
    consecutive_occurrences = Column(Integer, default=1)
    evaluation_window_minutes = Column(Integer, default=5)

    # Alert details
    severity = Column(SQLEnum(AlertSeverity), nullable=False)
    message_template = Column(Text, nullable=False)

    # Notification
    notification_channels = Column(ARRAY(String), nullable=False)  # email, slack, etc.
    notification_config = Column(JSON, default={})

    # Rate limiting
    cooldown_minutes = Column(Integer, default=30)  # Min time between alerts
    max_alerts_per_hour = Column(Integer, default=10)

    # Auto-resolution
    auto_resolve = Column(Boolean, default=True)
    auto_resolve_after_minutes = Column(Integer, default=15)

    # Status
    enabled = Column(Boolean, default=True)
    last_triggered_at = Column(DateTime)
    trigger_count = Column(Integer, default=0)

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))

    # Tags
    tags = Column(ARRAY(String), default=[])

    # Relationships
    health_check = relationship("HealthCheck", back_populates="alert_rules")
    alerts = relationship("Alert", back_populates="alert_rule", cascade="all, delete-orphan")


class Alert(Base):
    """
    Active Alerts
    Tracks triggered alerts and their lifecycle
    """
    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_rule_id = Column(UUID(as_uuid=True), ForeignKey("alert_rules.id"), nullable=False, index=True)

    # Alert details
    severity = Column(SQLEnum(AlertSeverity), nullable=False)
    title = Column(String(500), nullable=False)
    message = Column(Text, nullable=False)

    # Trigger context
    triggered_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    trigger_value = Column(JSON)  # Value that triggered alert
    trigger_context = Column(JSON)  # Additional context

    # Status tracking
    status = Column(SQLEnum(AlertStatus), default=AlertStatus.ACTIVE, nullable=False, index=True)
    acknowledged_at = Column(DateTime)
    acknowledged_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    resolved_at = Column(DateTime)
    resolved_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))

    # Notification tracking
    notifications_sent = Column(JSON, default=[])  # List of sent notifications
    notification_errors = Column(JSON, default=[])

    # Resolution
    resolution_notes = Column(Text)
    auto_resolved = Column(Boolean, default=False)

    # Escalation
    escalated = Column(Boolean, default=False)
    escalated_at = Column(DateTime)
    escalation_level = Column(Integer, default=0)

    # Suppression
    suppressed = Column(Boolean, default=False)
    suppressed_until = Column(DateTime)
    suppression_reason = Column(Text)

    # Metadata
    metadata = Column(JSON, default={})

    # Relationship
    alert_rule = relationship("AlertRule", back_populates="alerts")


class MonitoringDashboard(Base):
    """
    Monitoring Dashboard Configuration
    Custom dashboards for monitoring views
    """
    __tablename__ = "monitoring_dashboards"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(200), nullable=False, index=True)
    description = Column(Text)

    # Dashboard layout
    layout = Column(JSON, nullable=False)  # Widget positions and sizes
    widgets = Column(JSON, nullable=False)  # Widget configurations

    # Filters
    default_time_range = Column(String(50), default="24h")
    default_filters = Column(JSON, default={})

    # Sharing
    is_public = Column(Boolean, default=False)
    shared_with_users = Column(ARRAY(String), default=[])

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    # Tags
    tags = Column(ARRAY(String), default=[])


class MetricData(Base):
    """
    Time-Series Metric Storage
    Stores custom metrics for monitoring
    """
    __tablename__ = "metric_data"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Metric identification
    metric_name = Column(String(200), nullable=False, index=True)
    metric_type = Column(String(50), nullable=False)  # counter, gauge, histogram

    # Time series
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    value = Column(Float, nullable=False)

    # Labels/dimensions
    labels = Column(JSON, default={})

    # Source
    source_type = Column(String(50))  # device, service, check
    source_id = Column(String(200))

    # Metadata
    metadata = Column(JSON, default={})

    # Indexes for efficient querying
    # Create composite index: (metric_name, timestamp) for time-series queries
