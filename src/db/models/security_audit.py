"""
Security Audit and Compliance Models
Database models for security auditing, compliance tracking, and vulnerability management
"""
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, JSON, Text, ForeignKey, Enum as SQLEnum, Index
from sqlalchemy.dialects.postgresql import UUID, ARRAY, INET
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import enum

from ..database import Base


class AuditEventType(str, enum.Enum):
    """Types of audit events"""
    # Authentication events
    AUTH_LOGIN = "auth.login"
    AUTH_LOGOUT = "auth.logout"
    AUTH_FAILED = "auth.failed"
    AUTH_MFA_ENABLED = "auth.mfa_enabled"
    AUTH_MFA_DISABLED = "auth.mfa_disabled"
    AUTH_PASSWORD_CHANGED = "auth.password_changed"

    # Resource events
    RESOURCE_CREATED = "resource.created"
    RESOURCE_UPDATED = "resource.updated"
    RESOURCE_DELETED = "resource.deleted"
    RESOURCE_ACCESSED = "resource.accessed"

    # Configuration events
    CONFIG_DEPLOYED = "config.deployed"
    CONFIG_ROLLED_BACK = "config.rolled_back"
    CONFIG_VALIDATED = "config.validated"

    # Security events
    SECURITY_POLICY_UPDATED = "security.policy_updated"
    SECURITY_SCAN_COMPLETED = "security.scan_completed"
    SECURITY_INCIDENT_REPORTED = "security.incident_reported"
    SECURITY_VULNERABILITY_DETECTED = "security.vulnerability_detected"

    # Permission events
    PERMISSION_GRANTED = "permission.granted"
    PERMISSION_REVOKED = "permission.revoked"
    PERMISSION_DENIED = "permission.denied"

    # API events
    API_KEY_CREATED = "api_key.created"
    API_KEY_REVOKED = "api_key.revoked"
    API_KEY_USED = "api_key.used"


class AuditSeverity(str, enum.Enum):
    """Audit event severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComplianceFramework(str, enum.Enum):
    """Supported compliance frameworks"""
    CIS = "cis"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    NIST = "nist"
    GDPR = "gdpr"


class ComplianceStatus(str, enum.Enum):
    """Compliance check status"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class VulnerabilitySeverity(str, enum.Enum):
    """Vulnerability severity levels (CVSS-based)"""
    CRITICAL = "critical"  # 9.0-10.0
    HIGH = "high"          # 7.0-8.9
    MEDIUM = "medium"      # 4.0-6.9
    LOW = "low"            # 0.1-3.9
    NONE = "none"          # 0.0


class IncidentStatus(str, enum.Enum):
    """Security incident status"""
    REPORTED = "reported"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    REMEDIATED = "remediated"
    CLOSED = "closed"


class SecurityAuditLog(Base):
    """
    Comprehensive Security Audit Log
    Immutable record of all security-relevant events
    """
    __tablename__ = "security_audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Event details
    event_type = Column(SQLEnum(AuditEventType), nullable=False, index=True)
    severity = Column(SQLEnum(AuditSeverity), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Actor information
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    username = Column(String(255))
    api_key_id = Column(UUID(as_uuid=True), index=True)

    # Source information
    ip_address = Column(INET)
    user_agent = Column(Text)
    session_id = Column(String(255), index=True)

    # Resource information
    resource_type = Column(String(100), index=True)
    resource_id = Column(String(255), index=True)
    resource_name = Column(String(500))

    # Event details
    action = Column(String(255), nullable=False)
    description = Column(Text)

    # State changes
    before_state = Column(JSON)
    after_state = Column(JSON)
    changes = Column(JSON)  # Computed diff

    # Result
    success = Column(Boolean, nullable=False, index=True)
    error_message = Column(Text)

    # Additional context
    metadata = Column(JSON, default={})
    tags = Column(ARRAY(String), default=[])

    # Geolocation (optional)
    country_code = Column(String(2))
    region = Column(String(100))

    # Compliance mapping
    compliance_frameworks = Column(ARRAY(String), default=[])

    # Indexes for efficient querying
    __table_args__ = (
        Index('idx_audit_user_time', 'user_id', 'timestamp'),
        Index('idx_audit_resource', 'resource_type', 'resource_id'),
        Index('idx_audit_event_severity', 'event_type', 'severity'),
    )


class SecurityPolicy(Base):
    """
    Security Policy Definitions
    Configurable security policies and rules
    """
    __tablename__ = "security_policies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(200), nullable=False, unique=True, index=True)
    description = Column(Text)

    # Policy configuration
    policy_type = Column(String(100), nullable=False, index=True)
    policy_rules = Column(JSON, nullable=False)

    # Password policy
    min_password_length = Column(Integer)
    require_uppercase = Column(Boolean, default=True)
    require_lowercase = Column(Boolean, default=True)
    require_numbers = Column(Boolean, default=True)
    require_special_chars = Column(Boolean, default=True)
    password_expiry_days = Column(Integer)
    password_history = Column(Integer)

    # Session policy
    session_timeout_minutes = Column(Integer)
    max_concurrent_sessions = Column(Integer)
    require_mfa = Column(Boolean, default=False)

    # Access policy
    allowed_ip_ranges = Column(ARRAY(String))
    blocked_countries = Column(ARRAY(String))
    working_hours_only = Column(Boolean, default=False)

    # API policy
    api_rate_limit = Column(Integer)
    api_key_expiry_days = Column(Integer)

    # Compliance
    compliance_frameworks = Column(ARRAY(String), default=[])

    # Status
    enabled = Column(Boolean, default=True, index=True)
    enforcement_mode = Column(String(50), default="enforcing")  # enforcing, permissive

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))


class VulnerabilityScan(Base):
    """
    Vulnerability Scan Results
    Tracks security vulnerabilities discovered in the system
    """
    __tablename__ = "vulnerability_scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Scan details
    scan_type = Column(String(100), nullable=False, index=True)
    scan_target = Column(String(500), nullable=False)
    scan_started_at = Column(DateTime, nullable=False, index=True)
    scan_completed_at = Column(DateTime)
    scan_duration_seconds = Column(Integer)

    # Scanner information
    scanner_name = Column(String(200))
    scanner_version = Column(String(50))

    # Results summary
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)

    # Status
    scan_status = Column(String(50), default="pending", index=True)

    # Metadata
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))

    # Relationships
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")


class Vulnerability(Base):
    """
    Individual Vulnerability Records
    Detailed information about discovered vulnerabilities
    """
    __tablename__ = "vulnerabilities"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("vulnerability_scans.id"), nullable=False, index=True)

    # Vulnerability details
    vulnerability_id = Column(String(200), index=True)  # CVE ID or internal ID
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)

    # Severity
    severity = Column(SQLEnum(VulnerabilitySeverity), nullable=False, index=True)
    cvss_score = Column(Float)
    cvss_vector = Column(String(200))

    # Affected resources
    resource_type = Column(String(100), nullable=False)
    resource_id = Column(String(255), nullable=False, index=True)
    resource_name = Column(String(500))

    # Vulnerability information
    category = Column(String(200))  # e.g., "weak_password", "expired_certificate"
    cwe_id = Column(String(50))  # Common Weakness Enumeration

    # Detection
    detected_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    first_detected_at = Column(DateTime)

    # Remediation
    remediation_steps = Column(Text)
    remediation_effort = Column(String(50))  # low, medium, high
    remediation_priority = Column(Integer)

    # Status
    status = Column(String(50), default="open", index=True)  # open, in_progress, resolved, false_positive
    resolved_at = Column(DateTime)
    resolved_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    resolution_notes = Column(Text)

    # Risk assessment
    exploitability = Column(String(50))
    impact = Column(String(50))
    risk_score = Column(Float)

    # Additional details
    evidence = Column(JSON)
    references = Column(ARRAY(String))
    tags = Column(ARRAY(String), default=[])

    # Relationship
    scan = relationship("VulnerabilityScan", back_populates="vulnerabilities")


class ComplianceReport(Base):
    """
    Compliance Report Records
    Tracks compliance status against various frameworks
    """
    __tablename__ = "compliance_reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Report details
    report_name = Column(String(500), nullable=False)
    framework = Column(SQLEnum(ComplianceFramework), nullable=False, index=True)
    report_type = Column(String(100))  # full, delta, summary

    # Scope
    scope = Column(JSON)  # What was assessed
    assessment_period_start = Column(DateTime)
    assessment_period_end = Column(DateTime)

    # Results summary
    total_controls = Column(Integer, default=0)
    compliant_controls = Column(Integer, default=0)
    non_compliant_controls = Column(Integer, default=0)
    partially_compliant_controls = Column(Integer, default=0)
    not_applicable_controls = Column(Integer, default=0)

    # Compliance score
    compliance_score = Column(Float)  # 0-100
    previous_score = Column(Float)

    # Status
    report_status = Column(String(50), default="draft", index=True)

    # Metadata
    generated_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    generated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    approved_at = Column(DateTime)
    approved_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))

    # Report data
    findings = Column(JSON)  # Detailed findings
    recommendations = Column(JSON)

    # Relationships
    control_assessments = relationship("ComplianceControlAssessment", back_populates="report", cascade="all, delete-orphan")


class ComplianceControlAssessment(Base):
    """
    Individual Compliance Control Assessments
    Detailed assessment of specific compliance controls
    """
    __tablename__ = "compliance_control_assessments"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    report_id = Column(UUID(as_uuid=True), ForeignKey("compliance_reports.id"), nullable=False, index=True)

    # Control details
    control_id = Column(String(200), nullable=False, index=True)
    control_name = Column(String(500), nullable=False)
    control_description = Column(Text)
    control_category = Column(String(200))

    # Assessment
    status = Column(SQLEnum(ComplianceStatus), nullable=False, index=True)
    assessed_at = Column(DateTime, default=datetime.utcnow)
    assessed_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))

    # Evidence
    evidence = Column(JSON)
    test_procedures = Column(Text)
    test_results = Column(JSON)

    # Findings
    finding = Column(Text)
    risk_level = Column(String(50))
    remediation_required = Column(Boolean, default=False)
    remediation_plan = Column(Text)
    remediation_deadline = Column(DateTime)

    # Relationship
    report = relationship("ComplianceReport", back_populates="control_assessments")


class SecurityIncident(Base):
    """
    Security Incident Tracking
    Records and tracks security incidents
    """
    __tablename__ = "security_incidents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Incident details
    incident_id = Column(String(100), unique=True, nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)

    # Classification
    incident_type = Column(String(200), nullable=False, index=True)
    severity = Column(SQLEnum(VulnerabilitySeverity), nullable=False, index=True)
    status = Column(SQLEnum(IncidentStatus), default=IncidentStatus.REPORTED, nullable=False, index=True)

    # Timeline
    reported_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    detected_at = Column(DateTime)
    occurred_at = Column(DateTime)
    contained_at = Column(DateTime)
    resolved_at = Column(DateTime)

    # Affected resources
    affected_resources = Column(JSON)  # List of affected devices, users, etc.
    affected_users = Column(ARRAY(String))

    # Reporter
    reported_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    # Assignment
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    assigned_at = Column(DateTime)

    # Investigation
    investigation_notes = Column(Text)
    root_cause = Column(Text)

    # Response
    response_actions = Column(JSON)  # List of actions taken
    containment_steps = Column(Text)
    remediation_steps = Column(Text)

    # Impact assessment
    impact_description = Column(Text)
    data_compromised = Column(Boolean, default=False)
    systems_compromised = Column(Integer, default=0)
    estimated_loss = Column(Float)

    # Compliance
    regulatory_notification_required = Column(Boolean, default=False)
    notifications_sent = Column(JSON)

    # Tags and metadata
    tags = Column(ARRAY(String), default=[])
    metadata = Column(JSON, default={})


class AccessReview(Base):
    """
    Periodic Access Reviews
    Tracks periodic reviews of user access and permissions
    """
    __tablename__ = "access_reviews"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Review details
    review_name = Column(String(500), nullable=False)
    review_type = Column(String(100))  # user_access, role_assignment, api_keys

    # Scope
    scope = Column(JSON)  # What is being reviewed
    review_period_start = Column(DateTime)
    review_period_end = Column(DateTime)

    # Status
    status = Column(String(50), default="pending", index=True)

    # Schedule
    scheduled_at = Column(DateTime, nullable=False)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    due_date = Column(DateTime, index=True)

    # Results
    total_items_reviewed = Column(Integer, default=0)
    items_approved = Column(Integer, default=0)
    items_revoked = Column(Integer, default=0)
    items_pending = Column(Integer, default=0)

    # Reviewer
    reviewer_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))

    # Findings
    findings = Column(JSON)
    recommendations = Column(Text)

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))


class APIKey(Base):
    """
    API Key Management
    Tracks API keys for programmatic access
    """
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Key details
    key_name = Column(String(200), nullable=False)
    key_hash = Column(String(255), nullable=False, unique=True, index=True)
    key_prefix = Column(String(20), nullable=False, index=True)  # First few chars for identification

    # Owner
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)

    # Permissions
    scopes = Column(ARRAY(String), nullable=False)  # List of allowed operations
    allowed_ips = Column(ARRAY(String))  # IP whitelist

    # Usage
    last_used_at = Column(DateTime, index=True)
    usage_count = Column(Integer, default=0)

    # Rate limiting
    rate_limit = Column(Integer)  # Requests per minute

    # Status
    enabled = Column(Boolean, default=True, index=True)

    # Lifecycle
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, index=True)
    revoked_at = Column(DateTime)
    revoked_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    revocation_reason = Column(Text)

    # Metadata
    description = Column(Text)
    metadata = Column(JSON, default={})


class MFADevice(Base):
    """
    Multi-Factor Authentication Devices
    Tracks registered MFA devices for users
    """
    __tablename__ = "mfa_devices"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)

    # Device details
    device_name = Column(String(200), nullable=False)
    device_type = Column(String(50), nullable=False)  # totp, sms, backup_codes

    # TOTP details
    secret_key_encrypted = Column(String(500))  # Encrypted TOTP secret

    # SMS details
    phone_number_encrypted = Column(String(500))

    # Backup codes
    backup_codes_encrypted = Column(JSON)  # List of encrypted backup codes

    # Status
    verified = Column(Boolean, default=False)
    enabled = Column(Boolean, default=True)

    # Usage
    last_used_at = Column(DateTime)
    usage_count = Column(Integer, default=0)

    # Lifecycle
    registered_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    verified_at = Column(DateTime)

    # Metadata
    metadata = Column(JSON, default={})
