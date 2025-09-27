from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, JSON, ForeignKey, Table, Index, CheckConstraint, UniqueConstraint, ARRAY
from sqlalchemy.dialects.postgresql import UUID, JSONB, BYTEA, TIMESTAMP
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, validates
from sqlalchemy.sql import func
from datetime import datetime
import uuid
import hashlib
from typing import Optional, List, Dict, Any

Base = declarative_base()

# Association tables for many-to-many relationships
user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE')),
    Column('role_id', UUID(as_uuid=True), ForeignKey('roles.id', ondelete='CASCADE')),
    UniqueConstraint('user_id', 'role_id', name='uq_user_role')
)

deployment_approvers = Table(
    'deployment_approvers',
    Base.metadata,
    Column('deployment_id', UUID(as_uuid=True), ForeignKey('deployments.id', ondelete='CASCADE')),
    Column('user_id', UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE')),
    Column('approved_at', TIMESTAMP(timezone=True)),
    UniqueConstraint('deployment_id', 'user_id', name='uq_deployment_approver')
)

deployment_devices = Table(
    'deployment_devices',
    Base.metadata,
    Column('deployment_id', UUID(as_uuid=True), ForeignKey('deployments.id', ondelete='CASCADE')),
    Column('device_id', UUID(as_uuid=True), ForeignKey('devices.id', ondelete='CASCADE')),
    Column('status', String(50)),
    Column('deployed_at', TIMESTAMP(timezone=True)),
    UniqueConstraint('deployment_id', 'device_id', name='uq_deployment_device')
)

class User(Base):
    __tablename__ = 'users'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255))
    password_hash = Column(String(255))

    # MFA fields
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(255))
    mfa_backup_codes = Column(JSONB)

    # Security fields
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(TIMESTAMP(timezone=True))
    password_changed_at = Column(TIMESTAMP(timezone=True))
    must_change_password = Column(Boolean, default=False)

    # OAuth/SAML fields
    oauth_provider = Column(String(50))
    oauth_id = Column(String(255))
    saml_id = Column(String(255))

    # Certificate fields
    certificate_subject = Column(String(500))
    certificate_serial = Column(String(100))
    certificate_expiry = Column(TIMESTAMP(timezone=True))

    # API keys
    api_key_hash = Column(String(255))
    api_key_created_at = Column(TIMESTAMP(timezone=True))
    api_key_last_used = Column(TIMESTAMP(timezone=True))

    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    last_login_at = Column(TIMESTAMP(timezone=True))
    last_activity_at = Column(TIMESTAMP(timezone=True))

    # Relationships
    roles = relationship('Role', secondary=user_roles, back_populates='users')
    deployments_created = relationship('Deployment', back_populates='created_by_user', foreign_keys='Deployment.created_by')
    deployments_approved = relationship('Deployment', secondary=deployment_approvers, back_populates='approvers')
    audit_logs = relationship('AuditLog', back_populates='user')
    sessions = relationship('Session', back_populates='user', cascade='all, delete-orphan')
    notifications = relationship('Notification', back_populates='user', cascade='all, delete-orphan')

    __table_args__ = (
        Index('ix_users_email_active', 'email', 'is_active'),
        CheckConstraint('failed_login_attempts >= 0', name='check_failed_attempts_positive'),
    )

    @validates('email')
    def validate_email(self, key, email):
        if '@' not in email:
            raise ValueError("Invalid email address")
        return email.lower()


class Role(Base):
    __tablename__ = 'roles'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    permissions = Column(JSONB, nullable=False, default={})

    # Security fields
    is_system_role = Column(Boolean, default=False)
    max_session_duration = Column(Integer)  # minutes
    require_mfa = Column(Boolean, default=False)

    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    # Relationships
    users = relationship('User', secondary=user_roles, back_populates='roles')


class Device(Base):
    __tablename__ = 'devices'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hostname = Column(String(255), unique=True, nullable=False, index=True)
    management_ip = Column(String(45), nullable=False, index=True)
    vendor = Column(String(50), nullable=False)
    model = Column(String(100))
    os_version = Column(String(100))
    serial_number = Column(String(100), unique=True)

    # Connection details
    connection_type = Column(String(20), default='ssh')
    ssh_port = Column(Integer, default=22)
    netconf_port = Column(Integer)
    api_url = Column(String(500))

    # Credentials reference (stored in Vault)
    credential_ref = Column(String(255), nullable=False)
    enable_password_ref = Column(String(255))

    # Device metadata
    location = Column(String(255))
    site_id = Column(String(100))
    rack_id = Column(String(50))
    role = Column(String(50))  # core, edge, access, etc.
    environment = Column(String(50))  # production, staging, test
    tags = Column(JSONB, default=[])

    # Status fields
    is_active = Column(Boolean, default=True)
    is_managed = Column(Boolean, default=True)
    last_seen = Column(TIMESTAMP(timezone=True))
    last_backup = Column(TIMESTAMP(timezone=True))

    # Configuration
    current_config_hash = Column(String(64))
    desired_config_hash = Column(String(64))
    config_compliance = Column(Boolean)

    # Performance metrics
    cpu_usage = Column(Integer)
    memory_usage = Column(Integer)
    uptime_seconds = Column(Integer)

    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    commissioned_at = Column(TIMESTAMP(timezone=True))
    decommissioned_at = Column(TIMESTAMP(timezone=True))

    # Relationships
    configurations = relationship('DeviceConfig', back_populates='device', cascade='all, delete-orphan')
    deployments = relationship('Deployment', secondary=deployment_devices, back_populates='devices')
    health_checks = relationship('HealthCheck', back_populates='device', cascade='all, delete-orphan')

    __table_args__ = (
        Index('ix_devices_vendor_active', 'vendor', 'is_active'),
        Index('ix_devices_environment', 'environment'),
        CheckConstraint('ssh_port > 0 AND ssh_port < 65536', name='check_ssh_port_range'),
    )


class Deployment(Base):
    __tablename__ = 'deployments'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text)

    # Deployment configuration
    strategy = Column(String(50), nullable=False, default='canary')
    config_hash = Column(String(64), nullable=False)
    signature = Column(Text, nullable=False)
    encryption_key_id = Column(String(128))

    # State management
    state = Column(String(50), nullable=False, default='pending', index=True)
    approval_required = Column(Boolean, default=True)
    approvals_needed = Column(Integer, default=2)
    approvals_received = Column(Integer, default=0)

    # Scheduling
    scheduled_at = Column(TIMESTAMP(timezone=True))
    started_at = Column(TIMESTAMP(timezone=True))
    completed_at = Column(TIMESTAMP(timezone=True))

    # Rollback information
    rollback_available = Column(Boolean, default=True)
    rollback_deployment_id = Column(UUID(as_uuid=True), ForeignKey('deployments.id'))
    rolled_back_at = Column(TIMESTAMP(timezone=True))
    rolled_back_by = Column(UUID(as_uuid=True), ForeignKey('users.id'))

    # Git information
    repository_id = Column(UUID(as_uuid=True), ForeignKey('git_repositories.id'))
    commit_hash = Column(String(40))
    branch = Column(String(100))
    tag = Column(String(100))

    # Validation results
    validation_status = Column(String(50))
    validation_results = Column(JSONB)
    security_scan_passed = Column(Boolean)

    # Metrics
    devices_total = Column(Integer, default=0)
    devices_succeeded = Column(Integer, default=0)
    devices_failed = Column(Integer, default=0)
    duration_seconds = Column(Integer)

    # Audit fields
    created_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    audit_log = Column(JSONB, nullable=False, default={})

    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    # Relationships
    created_by_user = relationship('User', back_populates='deployments_created', foreign_keys=[created_by])
    approvers = relationship('User', secondary=deployment_approvers, back_populates='deployments_approved')
    devices = relationship('Device', secondary=deployment_devices, back_populates='deployments')
    repository = relationship('GitRepository', back_populates='deployments')
    tasks = relationship('Task', back_populates='deployment', cascade='all, delete-orphan')

    __table_args__ = (
        Index('ix_deployments_state_created', 'state', 'created_at'),
        Index('ix_deployments_repository_commit', 'repository_id', 'commit_hash'),
        CheckConstraint('approvals_received <= approvals_needed', name='check_approvals_valid'),
    )


class GitRepository(Base):
    __tablename__ = 'git_repositories'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    url = Column(Text, nullable=False, unique=True)
    branch = Column(String(100), default='main')

    # Authentication
    auth_type = Column(String(50))  # ssh, https, token
    ssh_key_ref = Column(String(255))  # Vault reference
    token_ref = Column(String(255))  # Vault reference

    # Webhook configuration
    webhook_url = Column(Text)
    webhook_secret_ref = Column(String(256))
    webhook_events = Column(JSONB, default=['push'])

    # Sync configuration
    auto_sync = Column(Boolean, default=True)
    sync_interval = Column(Integer, default=300)  # seconds
    last_sync = Column(TIMESTAMP(timezone=True))
    last_commit_hash = Column(String(40))

    # Security
    gpg_verification = Column(Boolean, default=True)
    allowed_signers = Column(JSONB, default=[])
    scan_for_secrets = Column(Boolean, default=True)

    # Path configuration
    config_path = Column(String(500), default='/')
    ignore_patterns = Column(JSONB, default=[])

    # Status
    is_active = Column(Boolean, default=True)
    sync_status = Column(String(50))
    sync_error = Column(Text)

    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    # Relationships
    deployments = relationship('Deployment', back_populates='repository')
    sync_history = relationship('GitSyncHistory', back_populates='repository', cascade='all, delete-orphan')


class GitSyncHistory(Base):
    __tablename__ = 'git_sync_history'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    repository_id = Column(UUID(as_uuid=True), ForeignKey('git_repositories.id'), nullable=False)

    # Sync details
    commit_hash = Column(String(40), nullable=False)
    commit_message = Column(Text)
    commit_author = Column(String(255))
    commit_date = Column(TIMESTAMP(timezone=True))

    # Changes
    files_changed = Column(Integer)
    files_added = Column(JSONB)
    files_modified = Column(JSONB)
    files_deleted = Column(JSONB)

    # Validation
    validation_passed = Column(Boolean)
    validation_errors = Column(JSONB)
    secrets_found = Column(Boolean, default=False)

    # Status
    sync_status = Column(String(50))
    error_message = Column(Text)

    # Timestamps
    synced_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())

    # Relationships
    repository = relationship('GitRepository', back_populates='sync_history')

    __table_args__ = (
        Index('ix_git_sync_history_repo_commit', 'repository_id', 'commit_hash'),
    )


class DeviceConfig(Base):
    __tablename__ = 'device_configs'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey('devices.id'), nullable=False)

    # Configuration content
    config_encrypted = Column(BYTEA, nullable=False)
    config_hash = Column(String(64), nullable=False)
    encryption_key_id = Column(String(128))

    # Versioning
    version = Column(Integer, nullable=False)
    is_current = Column(Boolean, default=False)

    # Backup details
    backup_type = Column(String(50))
    backup_location = Column(Text, nullable=False)
    backup_size = Column(Integer)

    # Metadata
    change_description = Column(Text)
    changed_by = Column(UUID(as_uuid=True), ForeignKey('users.id'))
    deployment_id = Column(UUID(as_uuid=True), ForeignKey('deployments.id'))

    # Compliance
    compliance_status = Column(String(50))
    compliance_violations = Column(JSONB)

    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())

    # Relationships
    device = relationship('Device', back_populates='configurations')

    __table_args__ = (
        Index('ix_device_configs_device_version', 'device_id', 'version'),
        UniqueConstraint('device_id', 'version', name='uq_device_config_version'),
    )


class AuditLog(Base):
    __tablename__ = 'audit_logs'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Event information
    event_type = Column(String(50), nullable=False, index=True)
    event_description = Column(Text)
    severity = Column(String(20), default='info')

    # Actor information
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'))
    user_email = Column(String(255))
    ip_address = Column(String(45))
    user_agent = Column(Text)
    session_id = Column(String(255))

    # Target information
    resource_type = Column(String(50))
    resource_id = Column(String(255))
    resource_name = Column(String(255))

    # Details
    details = Column(JSONB, nullable=False, default={})
    before_value = Column(JSONB)
    after_value = Column(JSONB)

    # Security
    is_security_event = Column(Boolean, default=False, index=True)
    threat_level = Column(String(20))

    # Compliance
    compliance_relevant = Column(Boolean, default=False)
    retention_years = Column(Integer, default=7)

    # Immutability
    hash_chain = Column(String(64))
    signature = Column(Text)

    # Timestamp (immutable)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())

    # Relationships
    user = relationship('User', back_populates='audit_logs')

    __table_args__ = (
        Index('ix_audit_logs_created_security', 'created_at', 'is_security_event'),
        Index('ix_audit_logs_user_created', 'user_id', 'created_at'),
        Index('ix_audit_logs_resource', 'resource_type', 'resource_id'),
    )


class Session(Base):
    __tablename__ = 'sessions'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id = Column(String(255), unique=True, nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)

    # Session details
    ip_address = Column(String(45))
    user_agent = Column(Text)
    device_fingerprint = Column(String(255))

    # Authentication
    auth_method = Column(String(50))
    mfa_verified = Column(Boolean, default=False)

    # State
    state = Column(String(20), default='active')
    last_activity = Column(TIMESTAMP(timezone=True))
    expires_at = Column(TIMESTAMP(timezone=True))

    # Security
    is_suspicious = Column(Boolean, default=False)
    risk_score = Column(Integer, default=0)

    # Recording
    recording_enabled = Column(Boolean, default=False)
    recording_path = Column(Text)

    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    terminated_at = Column(TIMESTAMP(timezone=True))

    # Relationships
    user = relationship('User', back_populates='sessions')

    __table_args__ = (
        Index('ix_sessions_user_state', 'user_id', 'state'),
        Index('ix_sessions_expires', 'expires_at'),
    )


class Task(Base):
    __tablename__ = 'tasks'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    task_type = Column(String(50), nullable=False)

    # Execution details
    status = Column(String(50), default='queued', index=True)
    priority = Column(Integer, default=5)
    queue_name = Column(String(100))

    # Task data
    payload = Column(JSONB)
    result = Column(JSONB)
    error = Column(Text)

    # Scheduling
    scheduled_at = Column(TIMESTAMP(timezone=True))
    started_at = Column(TIMESTAMP(timezone=True))
    completed_at = Column(TIMESTAMP(timezone=True))

    # Retry logic
    retry_count = Column(Integer, default=0)
    max_retries = Column(Integer, default=3)
    retry_delay = Column(Integer)  # seconds

    # References
    deployment_id = Column(UUID(as_uuid=True), ForeignKey('deployments.id'))
    created_by = Column(UUID(as_uuid=True), ForeignKey('users.id'))

    # Monitoring
    execution_time = Column(Integer)  # milliseconds
    memory_usage = Column(Integer)  # bytes

    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    # Relationships
    deployment = relationship('Deployment', back_populates='tasks')

    __table_args__ = (
        Index('ix_tasks_status_priority', 'status', 'priority'),
        Index('ix_tasks_scheduled', 'scheduled_at'),
    )


class HealthCheck(Base):
    __tablename__ = 'health_checks'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey('devices.id'), nullable=False)

    # Check details
    check_type = Column(String(50))  # ping, interface, routing, config
    status = Column(String(20), nullable=False)

    # Metrics
    response_time = Column(Integer)  # milliseconds
    packet_loss = Column(Integer)  # percentage
    cpu_usage = Column(Integer)
    memory_usage = Column(Integer)
    interface_errors = Column(Integer)

    # Results
    details = Column(JSONB)
    error_message = Column(Text)

    # Timestamp
    checked_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())

    # Relationships
    device = relationship('Device', back_populates='health_checks')

    __table_args__ = (
        Index('ix_health_checks_device_checked', 'device_id', 'checked_at'),
    )


class Notification(Base):
    __tablename__ = 'notifications'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)

    # Notification details
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    type = Column(String(50))  # info, warning, error, success
    channel = Column(String(50))  # email, slack, teams, sms

    # Status
    is_read = Column(Boolean, default=False)
    is_sent = Column(Boolean, default=False)
    sent_at = Column(TIMESTAMP(timezone=True))
    read_at = Column(TIMESTAMP(timezone=True))

    # References
    reference_type = Column(String(50))
    reference_id = Column(String(255))

    # Retry
    retry_count = Column(Integer, default=0)
    error_message = Column(Text)

    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    expires_at = Column(TIMESTAMP(timezone=True))

    # Relationships
    user = relationship('User', back_populates='notifications')

    __table_args__ = (
        Index('ix_notifications_user_read', 'user_id', 'is_read'),
        Index('ix_notifications_expires', 'expires_at'),
    )