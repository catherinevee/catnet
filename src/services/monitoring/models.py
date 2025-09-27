"""
Data models for monitoring service.
"""

from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Union
from enum import Enum
import uuid

from pydantic import BaseModel, Field, validator


class MetricType(str, Enum):
    """Metric types."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"
    RATE = "rate"
    PERCENTAGE = "percentage"
    BOOLEAN = "boolean"
    STRING = "string"
    COMPOSITE = "composite"


class AlertSeverity(str, Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, Enum):
    """Alert status."""
    FIRING = "firing"
    RESOLVED = "resolved"
    ACKNOWLEDGED = "acknowledged"
    SILENCED = "silenced"
    EXPIRED = "expired"


class HealthStatus(str, Enum):
    """Health check status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class WidgetType(str, Enum):
    """Dashboard widget types."""
    LINE_CHART = "line_chart"
    BAR_CHART = "bar_chart"
    PIE_CHART = "pie_chart"
    GAUGE_CHART = "gauge_chart"
    HEATMAP = "heatmap"
    TABLE = "table"
    STAT = "stat"
    TOPOLOGY = "topology"
    LOG_VIEWER = "log_viewer"
    ALERT_LIST = "alert_list"
    STATUS_INDICATOR = "status_indicator"
    HISTOGRAM = "histogram"
    SCATTER_PLOT = "scatter_plot"
    TIMESERIES = "timeseries"


class LogLevel(str, Enum):
    """Log levels."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class NotificationType(str, Enum):
    """Notification channel types."""
    EMAIL = "email"
    SMS = "sms"
    SLACK = "slack"
    TEAMS = "teams"
    PAGERDUTY = "pagerduty"
    WEBHOOK = "webhook"
    SNMP_TRAP = "snmp_trap"
    SYSLOG = "syslog"
    CUSTOM = "custom"


class AggregationType(str, Enum):
    """Metric aggregation types."""
    AVG = "avg"
    SUM = "sum"
    MIN = "min"
    MAX = "max"
    COUNT = "count"
    STDDEV = "stddev"
    PERCENTILE = "percentile"
    RATE = "rate"
    DELTA = "delta"


class Metric(BaseModel):
    """Metric model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    type: MetricType
    value: Union[float, int, bool, str]
    unit: Optional[str] = None
    labels: Dict[str, str] = {}
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: str
    description: Optional[str] = None
    metadata: Dict[str, Any] = {}


class MetricAggregation(BaseModel):
    """Metric aggregation model."""
    metric_name: str
    aggregation_type: AggregationType
    interval: str  # 1m, 5m, 1h, 1d, etc.
    value: float
    start_time: datetime
    end_time: datetime
    sample_count: int
    labels: Dict[str, str] = {}


class TimeSeriesData(BaseModel):
    """Time series data model."""
    metric_name: str
    timestamps: List[datetime]
    values: List[Union[float, int]]
    labels: Dict[str, str] = {}
    unit: Optional[str] = None
    aggregation: Optional[AggregationType] = None


class Alert(BaseModel):
    """Alert model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    severity: AlertSeverity
    status: AlertStatus = AlertStatus.FIRING
    rule_id: str
    metric_name: Optional[str] = None
    threshold_value: Optional[float] = None
    actual_value: Optional[float] = None
    labels: Dict[str, str] = {}
    annotations: Dict[str, str] = {}
    fired_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    silence_id: Optional[str] = None
    incident_id: Optional[str] = None
    fingerprint: str  # Unique identifier for deduplication
    source: str
    runbook_url: Optional[str] = None


class AlertRule(BaseModel):
    """Alert rule model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    expression: str  # PromQL or custom expression
    severity: AlertSeverity
    for_duration: Optional[str] = None  # How long condition must be true
    interval: str = "1m"  # Evaluation interval
    labels: Dict[str, str] = {}
    annotations: Dict[str, str] = {}
    notification_channels: List[str] = []
    is_enabled: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: str


class Threshold(BaseModel):
    """Threshold configuration."""
    metric_name: str
    operator: str  # >, <, >=, <=, ==, !=
    value: float
    duration: Optional[str] = None  # How long threshold must be exceeded
    severity: AlertSeverity
    description: Optional[str] = None


class NotificationChannel(BaseModel):
    """Notification channel model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    type: NotificationType
    configuration: Dict[str, Any]  # Channel-specific config
    is_enabled: bool = True
    rate_limit: Optional[int] = None  # Max notifications per hour
    silence_periods: List[Dict[str, str]] = []  # Quiet hours
    created_at: datetime = Field(default_factory=datetime.utcnow)


class NotificationRequest(BaseModel):
    """Notification request model."""
    channel_id: str
    alert_id: Optional[str] = None
    incident_id: Optional[str] = None
    subject: str
    message: str
    priority: str = "normal"  # low, normal, high, urgent
    metadata: Dict[str, Any] = {}
    deduplication_key: Optional[str] = None


class HealthCheck(BaseModel):
    """Health check model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    service: str
    endpoint: Optional[str] = None
    status: HealthStatus
    response_time_ms: Optional[float] = None
    status_code: Optional[int] = None
    error_message: Optional[str] = None
    last_check: datetime = Field(default_factory=datetime.utcnow)
    consecutive_failures: int = 0
    metadata: Dict[str, Any] = {}


class ServiceStatus(BaseModel):
    """Service status model."""
    service_name: str
    version: str
    status: HealthStatus
    uptime_seconds: int
    health_checks: List[HealthCheck]
    dependencies: List[Dict[str, str]]
    metrics: Dict[str, Any]
    last_updated: datetime = Field(default_factory=datetime.utcnow)


class Dashboard(BaseModel):
    """Dashboard model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    owner: str
    tags: List[str] = []
    widgets: List['Widget'] = []
    refresh_interval: str = "30s"
    time_range: str = "1h"  # 15m, 1h, 6h, 24h, 7d, 30d
    variables: Dict[str, Any] = {}
    is_public: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class Widget(BaseModel):
    """Dashboard widget model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: WidgetType
    title: str
    position: Dict[str, int]  # x, y, width, height
    queries: List[str] = []
    configuration: Dict[str, Any] = {}
    thresholds: List[Threshold] = []
    time_range_override: Optional[str] = None


class LogEntry(BaseModel):
    """Log entry model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    level: LogLevel
    service: str
    message: str
    logger: Optional[str] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = {}
    stack_trace: Optional[str] = None


class IncidentReport(BaseModel):
    """Incident report model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    severity: AlertSeverity
    status: str  # open, investigating, resolved, closed
    affected_services: List[str]
    root_cause: Optional[str] = None
    resolution: Optional[str] = None
    timeline: List[Dict[str, Any]] = []
    responders: List[str] = []
    commander: Optional[str] = None
    started_at: datetime
    detected_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    postmortem_url: Optional[str] = None
    related_alerts: List[str] = []
    impact: Optional[str] = None
    lessons_learned: List[str] = []


class SLAMetrics(BaseModel):
    """SLA metrics model."""
    service: str
    period: str  # daily, weekly, monthly
    availability_percentage: float
    uptime_seconds: int
    downtime_seconds: int
    incidents_count: int
    mean_time_to_recovery: Optional[float] = None  # MTTR in minutes
    mean_time_between_failures: Optional[float] = None  # MTBF in hours
    response_time_p50: Optional[float] = None
    response_time_p95: Optional[float] = None
    response_time_p99: Optional[float] = None
    error_rate: float
    calculated_at: datetime = Field(default_factory=datetime.utcnow)


class PerformanceMetrics(BaseModel):
    """Performance metrics model."""
    service: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    request_count: int
    error_count: int
    success_rate: float
    avg_response_time_ms: float
    p50_response_time_ms: float
    p95_response_time_ms: float
    p99_response_time_ms: float
    requests_per_second: float
    concurrent_users: int
    cpu_usage_percent: float
    memory_usage_percent: float
    disk_io_read_mbps: float
    disk_io_write_mbps: float
    network_in_mbps: float
    network_out_mbps: float


class NetworkMetrics(BaseModel):
    """Network metrics model."""
    device_id: str
    interface: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    bytes_in: int
    bytes_out: int
    packets_in: int
    packets_out: int
    errors_in: int
    errors_out: int
    discards_in: int
    discards_out: int
    utilization_percent: float
    bandwidth_mbps: float
    latency_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    packet_loss_percent: float


class DeviceMetrics(BaseModel):
    """Device metrics model."""
    device_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    cpu_usage_percent: float
    memory_usage_percent: float
    temperature_celsius: Optional[float] = None
    fan_speed_rpm: Optional[List[int]] = None
    power_consumption_watts: Optional[float] = None
    uptime_seconds: int
    session_count: int
    route_count: int
    arp_entries: int
    bgp_peers_up: Optional[int] = None
    bgp_peers_total: Optional[int] = None
    ospf_neighbors: Optional[int] = None
    interface_up_count: int
    interface_total_count: int


class SystemMetrics(BaseModel):
    """System metrics model."""
    host: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    cpu_cores: int
    cpu_usage_percent: float
    cpu_load_1m: float
    cpu_load_5m: float
    cpu_load_15m: float
    memory_total_gb: float
    memory_used_gb: float
    memory_free_gb: float
    memory_usage_percent: float
    swap_total_gb: float
    swap_used_gb: float
    swap_usage_percent: float
    disk_total_gb: float
    disk_used_gb: float
    disk_free_gb: float
    disk_usage_percent: float
    disk_read_mbps: float
    disk_write_mbps: float
    network_connections: int
    process_count: int
    thread_count: int
    open_files: int


class AuditLog(BaseModel):
    """Audit log model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    user: str
    action: str
    resource_type: str
    resource_id: str
    changes: Dict[str, Any] = {}
    result: str  # success, failure
    error_message: Optional[str] = None
    ip_address: str
    user_agent: Optional[str] = None
    session_id: str
    metadata: Dict[str, Any] = {}


class ComplianceReport(BaseModel):
    """Compliance report model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    framework: str  # PCI-DSS, HIPAA, SOC2, ISO27001, etc.
    period: str
    scan_date: datetime
    compliant: bool
    score: float  # 0-100
    total_controls: int
    passed_controls: int
    failed_controls: int
    not_applicable_controls: int
    critical_findings: List[Dict[str, Any]]
    high_findings: List[Dict[str, Any]]
    medium_findings: List[Dict[str, Any]]
    low_findings: List[Dict[str, Any]]
    recommendations: List[str]
    next_audit_date: Optional[datetime] = None
    auditor: Optional[str] = None
    report_url: Optional[str] = None


class MetricQuery(BaseModel):
    """Metric query request."""
    metric_names: List[str]
    start_time: datetime
    end_time: datetime
    aggregation: Optional[AggregationType] = None
    interval: Optional[str] = None  # 1m, 5m, 1h, etc.
    labels: Optional[Dict[str, str]] = None
    limit: int = Field(default=1000, ge=1, le=10000)


class AlertQuery(BaseModel):
    """Alert query request."""
    severity: Optional[List[AlertSeverity]] = None
    status: Optional[List[AlertStatus]] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    service: Optional[str] = None
    labels: Optional[Dict[str, str]] = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class DashboardCreateRequest(BaseModel):
    """Dashboard creation request."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    tags: List[str] = []
    widgets: List[Widget] = []
    refresh_interval: str = "30s"
    time_range: str = "1h"
    variables: Dict[str, Any] = {}
    is_public: bool = False


class AlertRuleCreateRequest(BaseModel):
    """Alert rule creation request."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    expression: str = Field(..., min_length=1)
    severity: AlertSeverity
    for_duration: Optional[str] = None
    interval: str = "1m"
    labels: Dict[str, str] = {}
    annotations: Dict[str, str] = {}
    notification_channels: List[str] = []


class HealthCheckRequest(BaseModel):
    """Health check request."""
    services: Optional[List[str]] = None
    include_dependencies: bool = True
    include_metrics: bool = False
    timeout_seconds: int = Field(default=30, ge=1, le=60)


class IncidentCreateRequest(BaseModel):
    """Incident creation request."""
    title: str = Field(..., min_length=1, max_length=255)
    description: str
    severity: AlertSeverity
    affected_services: List[str]
    commander: Optional[str] = None
    responders: List[str] = []
    related_alerts: List[str] = []


class MetricExportRequest(BaseModel):
    """Metric export request."""
    format: str = "prometheus"  # prometheus, json, csv
    metrics: Optional[List[str]] = None  # None means all metrics
    include_metadata: bool = True
    compression: Optional[str] = None  # gzip, bzip2, None