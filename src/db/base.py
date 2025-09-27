"""
Base classes and mixins for CatNet database models
Implements security-first patterns for all database operations
"""

from sqlalchemy import Column, DateTime, String, Boolean, Text, Integer
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.ext.declarative import declarative_base, declared_attr
from sqlalchemy.sql import func
from datetime import datetime, timedelta
import uuid
from typing import Optional, Dict, Any
import hashlib
import json

# Create declarative base
Base = declarative_base()

class TimestampMixin:
    """
    Mixin for automatic timestamp tracking
    """
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
        index=True
    )

    @property
    def age(self) -> float:
        """Get age of record in seconds"""
        if self.created_at:
            delta = datetime.utcnow() - self.created_at.replace(tzinfo=None)
            return delta.total_seconds()
        return 0.0

class SecurityMixin:
    """
    Mixin for security-related fields
    Implements encryption, signing, and audit requirements
    """

    # Unique identifier for security tracking
    security_id = Column(
        UUID(as_uuid=True),
        default=uuid.uuid4,
        nullable=False,
        unique=True,
        index=True
    )

    # Hash of the record content for integrity verification
    content_hash = Column(
        String(64),
        nullable=True,
        index=True
    )

    # Digital signature for non-repudiation
    signature = Column(
        Text,
        nullable=True
    )

    # Reference to encryption key in KMS/Vault
    encryption_key_id = Column(
        String(256),
        nullable=True
    )

    # Security classification level
    classification = Column(
        String(50),
        default='INTERNAL',
        nullable=False
    )

    # Encrypted data storage
    encrypted_data = Column(
        Text,
        nullable=True
    )

    # Security metadata
    security_metadata = Column(
        JSONB,
        default={},
        nullable=False
    )

    def calculate_content_hash(self, fields: Dict[str, Any]) -> str:
        """
        Calculate SHA-256 hash of specified fields
        """
        content = json.dumps(fields, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()

    def verify_integrity(self, fields: Dict[str, Any]) -> bool:
        """
        Verify content integrity using hash
        """
        if not self.content_hash:
            return False
        calculated_hash = self.calculate_content_hash(fields)
        return calculated_hash == self.content_hash

    def mark_as_sensitive(self, reason: str):
        """
        Mark record as containing sensitive data
        """
        if not self.security_metadata:
            self.security_metadata = {}
        self.security_metadata['sensitive'] = True
        self.security_metadata['sensitivity_reason'] = reason
        self.security_metadata['marked_at'] = datetime.utcnow().isoformat()

class AuditMixin:
    """
    Mixin for comprehensive audit logging
    """

    # Who created the record
    created_by = Column(
        UUID(as_uuid=True),
        nullable=True,
        index=True
    )

    # Who last modified the record
    modified_by = Column(
        UUID(as_uuid=True),
        nullable=True,
        index=True
    )

    # IP address of creator
    created_from_ip = Column(
        String(45),  # Supports IPv6
        nullable=True
    )

    # IP address of last modifier
    modified_from_ip = Column(
        String(45),
        nullable=True
    )

    # Audit trail of all changes
    audit_log = Column(
        JSONB,
        default=[],
        nullable=False
    )

    # Version number for optimistic locking
    version = Column(
        Integer,
        default=1,
        nullable=False
    )

    # Soft delete flag
    is_deleted = Column(
        Boolean,
        default=False,
        nullable=False,
        index=True
    )

    # Deletion timestamp
    deleted_at = Column(
        DateTime(timezone=True),
        nullable=True
    )

    # Who deleted the record
    deleted_by = Column(
        UUID(as_uuid=True),
        nullable=True
    )

    def add_audit_entry(
        self,
        action: str,
        user_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None
    ):
        """
        Add an entry to the audit log
        """
        if not self.audit_log:
            self.audit_log = []

        entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'action': action,
            'user_id': str(user_id) if user_id else None,
            'ip_address': ip_address,
            'details': details or {},
            'version': self.version
        }

        self.audit_log.append(entry)
        self.version += 1

    def soft_delete(self, user_id: Optional[str] = None):
        """
        Perform soft delete
        """
        self.is_deleted = True
        self.deleted_at = datetime.utcnow()
        if user_id:
            self.deleted_by = user_id
        self.add_audit_entry('SOFT_DELETE', user_id)

    def restore(self, user_id: Optional[str] = None):
        """
        Restore soft-deleted record
        """
        self.is_deleted = False
        self.deleted_at = None
        self.deleted_by = None
        self.add_audit_entry('RESTORE', user_id)

class EncryptionMixin:
    """
    Mixin for field-level encryption
    """

    # Encrypted fields storage
    encrypted_fields = Column(
        JSONB,
        default={},
        nullable=False
    )

    # Encryption algorithm used
    encryption_algorithm = Column(
        String(50),
        default='AES-256-GCM',
        nullable=False
    )

    # Initialization vector for encryption
    encryption_iv = Column(
        String(256),
        nullable=True
    )

    # Key rotation tracking
    last_key_rotation = Column(
        DateTime(timezone=True),
        nullable=True
    )

    # Number of key rotations
    key_rotation_count = Column(
        Integer,
        default=0,
        nullable=False
    )

    def mark_field_encrypted(self, field_name: str):
        """
        Mark a field as encrypted
        """
        if not self.encrypted_fields:
            self.encrypted_fields = {}
        self.encrypted_fields[field_name] = {
            'encrypted': True,
            'encrypted_at': datetime.utcnow().isoformat(),
            'algorithm': self.encryption_algorithm
        }

class ComplianceMixin:
    """
    Mixin for compliance and regulatory tracking
    """

    # Compliance tags
    compliance_tags = Column(
        JSONB,
        default=[],
        nullable=False
    )

    # Data retention policy
    retention_policy = Column(
        String(100),
        nullable=True
    )

    # Data expiration date
    expires_at = Column(
        DateTime(timezone=True),
        nullable=True,
        index=True
    )

    # Legal hold flag
    legal_hold = Column(
        Boolean,
        default=False,
        nullable=False
    )

    # GDPR compliance
    gdpr_consent = Column(
        Boolean,
        default=False,
        nullable=False
    )

    # Data residency requirements
    data_residency = Column(
        String(100),
        nullable=True
    )

    # Export control classification
    export_control = Column(
        String(100),
        nullable=True
    )

    def add_compliance_tag(self, tag: str, details: Optional[Dict[str, Any]] = None):
        """
        Add a compliance tag
        """
        if not self.compliance_tags:
            self.compliance_tags = []

        tag_entry = {
            'tag': tag,
            'added_at': datetime.utcnow().isoformat(),
            'details': details or {}
        }

        self.compliance_tags.append(tag_entry)

    def set_retention_policy(self, policy: str, days: int):
        """
        Set data retention policy
        """
        self.retention_policy = policy
        self.expires_at = datetime.utcnow() + timedelta(days=days)

class CacheMixin:
    """
    Mixin for caching support
    """

    # Cache key for this record
    cache_key = Column(
        String(256),
        nullable=True,
        unique=True,
        index=True
    )

    # Cache expiration timestamp
    cache_expires_at = Column(
        DateTime(timezone=True),
        nullable=True
    )

    # Cache hit count
    cache_hit_count = Column(
        Integer,
        default=0,
        nullable=False
    )

    # Last cache access
    last_cached_at = Column(
        DateTime(timezone=True),
        nullable=True
    )

    def generate_cache_key(self, prefix: str = '') -> str:
        """
        Generate cache key for this record
        """
        if hasattr(self, 'id'):
            key = f"{prefix}{self.__class__.__name__}:{self.id}"
            self.cache_key = hashlib.md5(key.encode()).hexdigest()
            return self.cache_key
        return ''

    def mark_cache_hit(self):
        """
        Record a cache hit
        """
        self.cache_hit_count = (self.cache_hit_count or 0) + 1
        self.last_cached_at = datetime.utcnow()

    def invalidate_cache(self):
        """
        Invalidate cache for this record
        """
        self.cache_expires_at = datetime.utcnow()

class FullAuditModel(Base, TimestampMixin, SecurityMixin, AuditMixin, EncryptionMixin):
    """
    Abstract base class with all security and audit features
    """
    __abstract__ = True

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False
    )

    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Convert model to dictionary with security filtering
        """
        result = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)

            # Skip sensitive fields unless explicitly requested
            if not include_sensitive and column.name in [
                'encrypted_data', 'encryption_key_id', 'signature',
                'encrypted_fields', 'encryption_iv'
            ]:
                continue

            # Convert special types
            if isinstance(value, uuid.UUID):
                value = str(value)
            elif isinstance(value, datetime):
                value = value.isoformat()

            result[column.name] = value

        return result

    def __repr__(self):
        """
        Safe string representation without sensitive data
        """
        return f"<{self.__class__.__name__}(id={self.id})>"