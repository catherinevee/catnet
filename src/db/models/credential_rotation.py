"""
Credential Rotation Models
Database models for automated credential rotation system
"""
from sqlalchemy import Column, String, DateTime, Enum, JSON, ForeignKey, Boolean, Integer
from sqlalchemy.orm import relationship
from src.db.base import Base
import enum
from datetime import datetime
import uuid


class RotationFrequency(str, enum.Enum):
    """Frequency options for credential rotation"""
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    MANUAL = "manual"


class RotationStatus(str, enum.Enum):
    """Status of a credential rotation operation"""
    SCHEDULED = "scheduled"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class CredentialRotationPolicy(Base):
    """
    Defines credential rotation policy for a device

    Attributes:
        id: Unique identifier
        device_id: Reference to device
        frequency: How often to rotate (daily, weekly, monthly, quarterly)
        next_rotation: When the next rotation should occur
        enabled: Whether rotation is active
        rotation_window_hours: Time window for rotation operations
        notify_on_rotation: Send notifications when rotating
        auto_rollback_on_failure: Automatically rollback failed rotations
        metadata: Additional policy configuration
    """
    __tablename__ = "credential_rotation_policies"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    frequency = Column(Enum(RotationFrequency), nullable=False)
    next_rotation = Column(DateTime, nullable=False)
    enabled = Column(Boolean, default=True)
    rotation_window_hours = Column(Integer, default=2)
    notify_on_rotation = Column(Boolean, default=True)
    auto_rollback_on_failure = Column(Boolean, default=True)
    metadata = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    device = relationship("Device", back_populates="rotation_policy")
    rotation_history = relationship(
        "CredentialRotationHistory",
        back_populates="policy",
        cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<CredentialRotationPolicy(id={self.id}, device={self.device_id}, freq={self.frequency})>"


class CredentialRotationHistory(Base):
    """
    Historical record of credential rotation operations

    Attributes:
        id: Unique identifier
        policy_id: Reference to rotation policy
        device_id: Reference to device
        status: Current status of rotation
        started_at: When rotation began
        completed_at: When rotation completed
        old_credential_path: Vault path to old credentials
        new_credential_path: Vault path to new credentials
        error_message: Error details if failed
        rotated_by: User or system that initiated rotation
    """
    __tablename__ = "credential_rotation_history"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    policy_id = Column(String, ForeignKey("credential_rotation_policies.id"))
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    status = Column(Enum(RotationStatus), nullable=False)
    started_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    completed_at = Column(DateTime)
    old_credential_path = Column(String)
    new_credential_path = Column(String)
    error_message = Column(String)
    rotated_by = Column(String)  # user_id or 'system'

    # Performance metrics
    duration_seconds = Column(Integer)
    retry_count = Column(Integer, default=0)

    # Relationships
    policy = relationship("CredentialRotationPolicy", back_populates="rotation_history")
    device = relationship("Device")

    def __repr__(self):
        return f"<CredentialRotationHistory(id={self.id}, device={self.device_id}, status={self.status})>"

    def calculate_duration(self):
        """Calculate rotation duration in seconds"""
        if self.started_at and self.completed_at:
            delta = self.completed_at - self.started_at
            self.duration_seconds = int(delta.total_seconds())
