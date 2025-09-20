from sqlalchemy import (
    Column,
    String,
    Integer,
    DateTime,
    Boolean,
    Text,
    JSON,
    ForeignKey,
    Enum as SQLEnum,
    TypeDecorator,
    CHAR,
)
from sqlalchemy.dialects.postgresql import UUID as postgresql_UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
import enum


# Custom UUID type that works with both PostgreSQL and SQLite


class UUID(TypeDecorator):
    """Platform-independent UUID type.

    Uses PostgreSQL's UUID type when available,
    otherwise stores as a 36-character string.
    """

    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(postgresql_UUID())
        else:
            return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == "postgresql":
            return value
        else:
            if isinstance(value, uuid.UUID):
                return str(value)
            else:
                return value

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == "postgresql":
            return value
        else:
            if not isinstance(value, uuid.UUID):
                value = uuid.UUID(value)
            return value


Base = declarative_base()


class DeploymentState(enum.Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    AWAITING_APPROVAL = "awaiting_approval"


class DeviceVendor(enum.Enum):
    CISCO_IOS = "cisco_ios"
    CISCO_IOS_XE = "cisco_ios_xe"
    CISCO_NX_OS = "cisco_nx_os"
    JUNIPER_JUNOS = "juniper_junos"


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    mfa_secret = Column(String(255))
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    roles = Column(JSON, default=list)  # Using JSON for SQLite compatibility
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_login = Column(DateTime(timezone=True))
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True))

    # Signing key fields
    signing_key_id = Column(String(255))
    signing_key_fingerprint = Column(String(128))
    signing_key_created_at = Column(DateTime(timezone=True))
    signing_key_expires_at = Column(DateTime(timezone=True))

    # SSH key fields
    ssh_public_keys = Column(JSON, default=[])  # List of SSH public keys
    ssh_key_added_at = Column(DateTime(timezone=True))
    ssh_key_fingerprints = Column(JSON, default=[])  # List of SSH key fingerprints

    # Relationships - Specify foreign keys to avoid ambiguity
    deployments = relationship(
        "Deployment", foreign_keys="Deployment.created_by", back_populates="creator"
    )
    audit_logs = relationship("AuditLog", back_populates="user")
    ssh_keys = relationship("UserSSHKey", back_populates="user")


class Device(Base):
    __tablename__ = "devices"

    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    hostname = Column(String(255), nullable=False, unique=True, index=True)
    ip_address = Column(String(45), nullable=False, index=True)
    vendor = Column(SQLEnum(DeviceVendor), nullable=False)
    model = Column(String(100))
    serial_number = Column(String(100), unique=True)
    location = Column(String(255))
    is_active = Column(Boolean, default=True)
    last_backup = Column(DateTime(timezone=True))
    last_seen = Column(DateTime(timezone=True))
    certificate_thumbprint = Column(String(255))
    bastion_host = Column(String(255))
    port = Column(Integer, default=22)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    device_metadata = Column(JSON, default={})

    # Certificate fields
    certificate_serial = Column(String(255), index=True)
    certificate_expires_at = Column(DateTime(timezone=True))
    certificate_fingerprint = Column(String(128), index=True)
    certificate_status = Column(String(50), default="pending", index=True)
    certificate_issued_at = Column(DateTime(timezone=True))
    certificate_revoked_at = Column(DateTime(timezone=True))
    certificate_revocation_reason = Column(String(255))

    # SSH key fields
    ssh_username = Column(String(100), default="catnet")
    ssh_key_ref = Column(String(255))  # Vault reference to SSH key
    ssh_port = Column(Integer, default=22)
    ssh_key_fingerprint = Column(String(128))
    ssh_auth_enabled = Column(Boolean, default=False)

    # Relationships
    configs = relationship("DeviceConfig", back_populates="device")
    deployments = relationship("DeploymentDevice", back_populates="device")


class Deployment(Base):
    __tablename__ = "deployments"

    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    created_by = Column(UUID(), ForeignKey("users.id"), nullable=False)
    config_hash = Column(String(64), nullable=False)  # SHA-256
    signature = Column(Text, nullable=False)  # Digital signature
    encryption_key_id = Column(String(128))  # KMS key reference
    state = Column(
        SQLEnum(DeploymentState),
        nullable=False,
        default=DeploymentState.PENDING,
    )
    approved_by = Column(JSON, default=list)  # Stores list of user IDs as strings
    approval_required = Column(Boolean, default=True)
    approval_count = Column(Integer, default=2)  # Number of approvals needed
    strategy = Column(String(50), default="rolling")  # canary, rolling, blue-green
    rollback_config = Column(JSON)
    scheduled_at = Column(DateTime(timezone=True))
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    error_message = Column(Text)
    audit_log = Column(JSON, nullable=False, default={})
    git_commit = Column(String(40))  # Git commit hash
    git_repository_id = Column(UUID(), ForeignKey("git_repositories.id"))

    # Signature fields
    config_signature = Column(Text)
    signed_by = Column(UUID(), ForeignKey("users.id"))
    signature_verified = Column(Boolean, default=False)
    signature_timestamp = Column(DateTime(timezone=True))

    # Relationships
    creator = relationship(
        "User", foreign_keys=[created_by], back_populates="deployments"
    )
    signer = relationship("User", foreign_keys=[signed_by])
    repository = relationship("GitRepository", back_populates="deployments")
    devices = relationship("DeploymentDevice", back_populates="deployment")


class DeploymentDevice(Base):
    __tablename__ = "deployment_devices"

    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    deployment_id = Column(UUID(), ForeignKey("deployments.id"), nullable=False)
    device_id = Column(UUID(), ForeignKey("devices.id"), nullable=False)
    status = Column(
        String(50), nullable=False
    )  # pending, in_progress, completed, failed
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    backup_id = Column(UUID())
    error_message = Column(Text)
    validation_results = Column(JSON)

    # Relationships
    deployment = relationship("Deployment", back_populates="devices")
    device = relationship("Device", back_populates="deployments")


class GitRepository(Base):
    __tablename__ = "git_repositories"

    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    url = Column(Text, nullable=False, unique=True)
    branch = Column(String(100), default="main")
    webhook_secret_ref = Column(String(256))  # Vault reference
    last_commit_hash = Column(String(40))
    gpg_verification = Column(Boolean, default=True)
    ssh_key_ref = Column(String(256))  # Vault reference for SSH key
    config_path = Column(String(500), default="configs/")
    auto_deploy = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_sync = Column(DateTime(timezone=True))
    repo_metadata = Column(JSON, default={})

    # Relationships
    deployments = relationship("Deployment", back_populates="repository")


class DeviceConfig(Base):
    __tablename__ = "device_configs"

    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(), ForeignKey("devices.id"), nullable=False)
    config_encrypted = Column(Text, nullable=False)  # Encrypted content
    backup_location = Column(Text, nullable=False)
    version = Column(Integer, nullable=False)
    config_hash = Column(String(64), nullable=False)  # SHA-256 of plaintext
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    created_by = Column(UUID(), ForeignKey("users.id"))
    deployment_id = Column(UUID(), ForeignKey("deployments.id"))
    is_active = Column(Boolean, default=False)
    validation_status = Column(String(50))
    validation_results = Column(JSON)
    config_metadata = Column(JSON, default={})

    # Relationships
    device = relationship("Device", back_populates="configs")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )
    event_type = Column(String(100), nullable=False, index=True)
    user_id = Column(UUID(), ForeignKey("users.id"), index=True)
    level = Column(
        String(20), nullable=False
    )  # INFO, WARNING, ERROR, CRITICAL, SECURITY
    details = Column(JSON, nullable=False)
    hash = Column(String(64), nullable=False)  # SHA-256 for integrity
    ip_address = Column(String(45))
    user_agent = Column(Text)
    session_id = Column(String(255))
    resource = Column(String(255))
    action = Column(String(100))
    result = Column(String(50))  # success, failure, partial

    # Relationships
    user = relationship("User", back_populates="audit_logs")


class ConfigTemplate(Base):
    __tablename__ = "config_templates"

    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False, unique=True)
    vendor = Column(SQLEnum(DeviceVendor), nullable=False)
    template_content = Column(Text, nullable=False)
    variables = Column(JSON, default={})  # Variable definitions
    validation_rules = Column(JSON, default={})
    version = Column(Integer, default=1)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    created_by = Column(UUID(), ForeignKey("users.id"))


class SecretRotation(Base):
    __tablename__ = "secret_rotations"

    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    secret_path = Column(String(500), nullable=False)
    secret_type = Column(String(50), nullable=False)  # device_credential, api_key, etc.
    last_rotation = Column(DateTime(timezone=True), nullable=False)
    next_rotation = Column(DateTime(timezone=True), nullable=False)
    rotation_interval_days = Column(Integer, default=90)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    rotation_metadata = Column(JSON, default={})


class Session(Base):
    __tablename__ = "sessions"

    id = Column(String(255), primary_key=True)
    user_id = Column(UUID(), ForeignKey("users.id"), nullable=False)
    device_id = Column(UUID(), ForeignKey("devices.id"))
    started_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    ended_at = Column(DateTime(timezone=True))
    commands = Column(JSON, default=[])  # List of executed commands
    is_active = Column(Boolean, default=True)
    recording_location = Column(String(500))  # Path to session recording


class UserSSHKey(Base):
    __tablename__ = "user_ssh_keys"

    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(), ForeignKey("users.id"), nullable=False)
    name = Column(String(255), nullable=False)
    public_key = Column(Text, nullable=False)
    fingerprint = Column(String(128), nullable=False, unique=True, index=True)
    key_type = Column(String(50))  # rsa, ed25519, ecdsa
    key_size = Column(Integer)
    comment = Column(String(500))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_used = Column(DateTime(timezone=True))
    expires_at = Column(DateTime(timezone=True))

    # Relationships
    user = relationship("User", back_populates="ssh_keys")


class SSHKey(Base):
    __tablename__ = "ssh_keys"

    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(), ForeignKey("devices.id"))
    name = Column(String(255), nullable=False)
    vault_path = Column(String(500), nullable=False)  # Path in Vault
    fingerprint = Column(String(128), nullable=False, index=True)
    key_type = Column(String(50))  # rsa, ed25519, ecdsa
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    rotated_at = Column(DateTime(timezone=True))
    expires_at = Column(DateTime(timezone=True))

    # Relationships
    device = relationship("Device")
