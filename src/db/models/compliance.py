"""
Compliance Models
Database models for automated compliance scanning and policy enforcement
"""
from sqlalchemy import Column, String, DateTime, Enum, JSON, Boolean, Text, ForeignKey, Integer
from sqlalchemy.orm import relationship
from src.db.base import Base
import enum
from datetime import datetime
import uuid


class ComplianceFramework(str, enum.Enum):
    """Compliance framework types"""
    CIS = "cis"                    # CIS Benchmarks
    PCI_DSS = "pci_dss"           # Payment Card Industry Data Security Standard
    HIPAA = "hipaa"               # Health Insurance Portability and Accountability Act
    SOC2 = "soc2"                 # Service Organization Control 2
    NIST = "nist"                 # NIST Cybersecurity Framework
    ISO_27001 = "iso_27001"       # ISO/IEC 27001
    CUSTOM = "custom"             # Custom policies


class ComplianceSeverity(str, enum.Enum):
    """Severity levels for compliance violations"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ComplianceStatus(str, enum.Enum):
    """Compliance status"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    MANUAL_REVIEW = "manual_review"


class CompliancePolicy(Base):
    """
    Compliance policy definition

    Defines a specific compliance requirement that devices should meet.
    Can be based on industry frameworks (CIS, PCI-DSS, etc.) or custom.

    Attributes:
        id: Unique identifier
        name: Policy name
        framework: Compliance framework (CIS, PCI-DSS, etc.)
        control_id: Framework control identifier (e.g., "CIS-1.1.1")
        description: Detailed policy description
        rule: Policy check logic (Python code or regex)
        remediation: Instructions to fix violations
        severity: Violation severity level
        enabled: Whether policy is active
        vendor: Specific vendor (cisco, juniper) or "all"
        device_types: Applicable device types (ios, nxos, junos)
    """
    __tablename__ = "compliance_policies"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    framework = Column(Enum(ComplianceFramework), nullable=False)
    control_id = Column(String)  # e.g., "CIS-1.1.1", "PCI-DSS-2.2.4"
    description = Column(Text)

    # Policy rule
    rule_type = Column(String, default="regex")  # regex, python, custom
    rule = Column(Text, nullable=False)  # Actual rule logic
    expected_value = Column(String)  # What should be present/absent

    # Remediation
    remediation = Column(Text)  # How to fix violations
    remediation_commands = Column(JSON)  # Auto-remediation commands

    # Classification
    severity = Column(Enum(ComplianceSeverity), nullable=False)
    category = Column(String)  # e.g., "password", "logging", "snmp"

    # Applicability
    vendor = Column(String, default="all")  # cisco, juniper, all
    device_types = Column(JSON)  # ["ios", "nxos"] or null for all

    # Status
    enabled = Column(Boolean, default=True)
    auto_remediate = Column(Boolean, default=False)

    # Metadata
    created_by = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    metadata = Column(JSON, default=dict)

    # Relationships
    scans = relationship("ComplianceScan", back_populates="policy", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<CompliancePolicy(id={self.id}, framework={self.framework}, control={self.control_id})>"


class ComplianceScan(Base):
    """
    Compliance scan result

    Records the result of checking a device against a compliance policy.

    Attributes:
        id: Unique identifier
        device_id: Device that was scanned
        policy_id: Policy that was checked
        scanned_at: When scan was performed
        status: Compliance status
        violation_details: Details of non-compliance
        current_config: Relevant current configuration
        expected_config: Expected configuration
        auto_remediated: Whether violation was auto-fixed
    """
    __tablename__ = "compliance_scans"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    policy_id = Column(String, ForeignKey("compliance_policies.id"), nullable=False)

    # Scan timing
    scanned_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    scan_duration_ms = Column(Integer)

    # Result
    status = Column(Enum(ComplianceStatus), nullable=False)

    # Details of violation (if non-compliant)
    violation_details = Column(JSON)  # Structured violation data
    violation_summary = Column(Text)  # Human-readable summary

    # Configuration comparison
    current_config = Column(Text)  # Actual device config (relevant portion)
    expected_config = Column(Text)  # Expected config
    config_diff = Column(Text)  # Unified diff if applicable

    # Remediation
    auto_remediated = Column(Boolean, default=False)
    remediated_at = Column(DateTime)
    remediated_by = Column(String)  # user_id or "system"
    remediation_success = Column(Boolean)
    remediation_error = Column(Text)

    # Relationships
    device = relationship("Device")
    policy = relationship("CompliancePolicy", back_populates="scans")

    def __repr__(self):
        return f"<ComplianceScan(id={self.id}, device={self.device_id}, status={self.status})>"


class ComplianceReport(Base):
    """
    Compliance report

    Aggregates compliance scan results for reporting purposes.

    Attributes:
        id: Unique identifier
        name: Report name
        framework: Framework being reported on
        device_ids: Devices included in report
        generated_at: When report was generated
        total_policies: Total policies checked
        compliant_count: Number of compliant policies
        non_compliant_count: Number of violations
        compliance_percentage: Overall compliance percentage
    """
    __tablename__ = "compliance_reports"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    framework = Column(Enum(ComplianceFramework))

    # Scope
    device_ids = Column(JSON)  # Devices included
    policy_ids = Column(JSON)  # Policies checked

    # Timing
    generated_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    period_start = Column(DateTime)  # For time-range reports
    period_end = Column(DateTime)

    # Summary statistics
    total_policies = Column(Integer, default=0)
    compliant_count = Column(Integer, default=0)
    non_compliant_count = Column(Integer, default=0)
    not_applicable_count = Column(Integer, default=0)

    # Severity breakdown
    critical_violations = Column(Integer, default=0)
    high_violations = Column(Integer, default=0)
    medium_violations = Column(Integer, default=0)
    low_violations = Column(Integer, default=0)

    # Overall score
    compliance_percentage = Column(Integer)  # 0-100

    # Report data
    summary = Column(JSON)  # Structured summary data
    recommendations = Column(JSON)  # List of remediation recommendations

    # Metadata
    generated_by = Column(String)
    metadata = Column(JSON, default=dict)

    def __repr__(self):
        return f"<ComplianceReport(id={self.id}, compliance={self.compliance_percentage}%)>"

    def calculate_compliance_percentage(self):
        """Calculate overall compliance percentage"""
        total = self.compliant_count + self.non_compliant_count
        if total == 0:
            return 0
        return int((self.compliant_count / total) * 100)


class ComplianceException(Base):
    """
    Compliance exception

    Records approved exceptions to compliance policies for specific devices.

    Attributes:
        id: Unique identifier
        device_id: Device with exception
        policy_id: Policy being excepted
        reason: Why exception is granted
        approved_by: Who approved the exception
        expires_at: When exception expires
    """
    __tablename__ = "compliance_exceptions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    policy_id = Column(String, ForeignKey("compliance_policies.id"), nullable=False)

    # Exception details
    reason = Column(Text, nullable=False)
    business_justification = Column(Text)

    # Approval
    approved_by = Column(String, nullable=False)
    approved_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Validity
    expires_at = Column(DateTime)
    permanent = Column(Boolean, default=False)

    # Status
    active = Column(Boolean, default=True)
    revoked_at = Column(DateTime)
    revoked_by = Column(String)
    revoke_reason = Column(Text)

    # Relationships
    device = relationship("Device")
    policy = relationship("CompliancePolicy")

    def __repr__(self):
        return f"<ComplianceException(id={self.id}, device={self.device_id}, policy={self.policy_id})>"

    def is_expired(self) -> bool:
        """Check if exception has expired"""
        if self.permanent:
            return False
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at


class ComplianceSchedule(Base):
    """
    Compliance scan schedule

    Defines automated compliance scanning schedules.

    Attributes:
        id: Unique identifier
        name: Schedule name
        framework: Framework to scan
        device_ids: Devices to scan
        cron_expression: Schedule in cron format
        enabled: Whether schedule is active
    """
    __tablename__ = "compliance_schedules"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    description = Column(Text)

    # Scope
    framework = Column(Enum(ComplianceFramework))
    device_ids = Column(JSON)  # Specific devices or null for all
    policy_ids = Column(JSON)  # Specific policies or null for all

    # Schedule
    cron_expression = Column(String)  # e.g., "0 0 * * *" for daily at midnight
    timezone = Column(String, default="UTC")

    # Status
    enabled = Column(Boolean, default=True)
    last_run_at = Column(DateTime)
    next_run_at = Column(DateTime)

    # Notifications
    notify_on_violations = Column(Boolean, default=True)
    notification_emails = Column(JSON)  # List of email addresses

    # Metadata
    created_by = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<ComplianceSchedule(id={self.id}, name={self.name}, enabled={self.enabled})>"
