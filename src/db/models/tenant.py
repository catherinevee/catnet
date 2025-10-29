"""
Multi-Tenancy Models
Database models for tenant isolation and resource management
"""
from sqlalchemy import Column, String, DateTime, JSON, Boolean, Integer, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
from src.db.base import Base
from datetime import datetime
import uuid


class Tenant(Base):
    """
    Tenant entity for multi-tenancy support

    Represents an isolated customer or organization using CatNet.
    All resources (devices, users, deployments) belong to a tenant.

    Attributes:
        id: Unique identifier
        name: Tenant name (unique)
        display_name: Human-friendly display name
        slug: URL-safe identifier
        max_devices: Maximum number of devices allowed
        max_users: Maximum number of users allowed
        max_deployments_per_day: Rate limit for deployments
        features: Feature flags for this tenant
        enabled: Whether tenant is active
    """
    __tablename__ = "tenants"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False, unique=True, index=True)
    display_name = Column(String)
    slug = Column(String, unique=True, index=True)  # URL-friendly identifier
    description = Column(String)

    # Resource quotas
    max_devices = Column(Integer, default=100)
    max_users = Column(Integer, default=10)
    max_deployments_per_day = Column(Integer, default=50)
    max_api_calls_per_hour = Column(Integer, default=1000)

    # Current usage (updated periodically)
    current_devices = Column(Integer, default=0)
    current_users = Column(Integer, default=0)
    deployments_today = Column(Integer, default=0)

    # Features enabled for this tenant
    features = Column(JSON, default=lambda: {
        "advanced_deployments": True,
        "compliance_scanning": True,
        "credential_rotation": True,
        "drift_detection": True,
        "multi_vendor": True
    })

    # Subscription/billing
    subscription_tier = Column(String, default="standard")  # free, standard, enterprise
    subscription_expires_at = Column(DateTime)

    # Status
    enabled = Column(Boolean, default=True)
    locked = Column(Boolean, default=False)
    lock_reason = Column(String)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Metadata
    metadata = Column(JSON, default=dict)
    settings = Column(JSON, default=dict)

    # Relationships
    users = relationship("TenantUser", back_populates="tenant", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Tenant(id={self.id}, name={self.name}, enabled={self.enabled})>"

    def has_feature(self, feature_name: str) -> bool:
        """Check if tenant has a specific feature enabled"""
        return self.features.get(feature_name, False)

    def can_add_device(self) -> bool:
        """Check if tenant can add more devices"""
        return self.current_devices < self.max_devices

    def can_add_user(self) -> bool:
        """Check if tenant can add more users"""
        return self.current_users < self.max_users

    def can_deploy(self) -> bool:
        """Check if tenant can run more deployments today"""
        return self.deployments_today < self.max_deployments_per_day


class TenantUser(Base):
    """
    Tenant user association

    Links users to tenants with specific roles and permissions.

    Attributes:
        id: Unique identifier
        tenant_id: Tenant reference
        user_id: User reference
        role: User role within tenant (admin, user, readonly)
        permissions: Specific permissions for this user
        enabled: Whether user access to tenant is active
    """
    __tablename__ = "tenant_users"
    __table_args__ = (
        UniqueConstraint('tenant_id', 'user_id', name='unique_tenant_user'),
    )

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)

    # Role within tenant
    role = Column(String, nullable=False, default="user")  # admin, user, readonly

    # Fine-grained permissions
    permissions = Column(JSON, default=lambda: {
        "devices": {"read": True, "write": False, "delete": False},
        "deployments": {"read": True, "write": False, "delete": False},
        "compliance": {"read": True, "write": False, "delete": False},
        "users": {"read": False, "write": False, "delete": False}
    })

    # Status
    enabled = Column(Boolean, default=True)
    invitation_accepted = Column(Boolean, default=False)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_access_at = Column(DateTime)

    # Relationships
    tenant = relationship("Tenant", back_populates="users")
    user = relationship("User")

    def __repr__(self):
        return f"<TenantUser(tenant={self.tenant_id}, user={self.user_id}, role={self.role})>"

    def has_permission(self, resource: str, action: str) -> bool:
        """Check if user has specific permission"""
        if self.role == "admin":
            return True  # Admins have all permissions

        resource_perms = self.permissions.get(resource, {})
        return resource_perms.get(action, False)


class TenantInvitation(Base):
    """
    Tenant invitation

    Tracks invitations sent to users to join a tenant.

    Attributes:
        id: Unique identifier
        tenant_id: Tenant extending invitation
        email: Email of invited user
        role: Role being offered
        token: Unique invitation token
        expires_at: When invitation expires
        accepted: Whether invitation was accepted
    """
    __tablename__ = "tenant_invitations"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False)
    email = Column(String, nullable=False, index=True)
    role = Column(String, nullable=False, default="user")

    # Invitation token
    token = Column(String, unique=True, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)

    # Status
    accepted = Column(Boolean, default=False)
    accepted_at = Column(DateTime)
    accepted_by = Column(String)  # user_id

    # Metadata
    invited_by = Column(String, nullable=False)  # user_id
    created_at = Column(DateTime, default=datetime.utcnow)
    message = Column(String)

    # Relationships
    tenant = relationship("Tenant")

    def __repr__(self):
        return f"<TenantInvitation(tenant={self.tenant_id}, email={self.email}, accepted={self.accepted})>"

    def is_expired(self) -> bool:
        """Check if invitation has expired"""
        return datetime.utcnow() > self.expires_at

    def is_valid(self) -> bool:
        """Check if invitation is valid and can be used"""
        return not self.accepted and not self.is_expired()


class TenantAuditLog(Base):
    """
    Tenant audit log

    Records all significant actions within a tenant for compliance
    and security auditing.

    Attributes:
        id: Unique identifier
        tenant_id: Tenant reference
        user_id: User who performed action
        action: Action type (create, update, delete, etc.)
        resource_type: Type of resource affected
        resource_id: ID of affected resource
        details: Additional action details
    """
    __tablename__ = "tenant_audit_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id"), index=True)

    # Action details
    action = Column(String, nullable=False, index=True)  # create, update, delete, login, etc.
    resource_type = Column(String, index=True)  # device, deployment, user, etc.
    resource_id = Column(String, index=True)

    # Context
    ip_address = Column(String)
    user_agent = Column(String)
    request_id = Column(String, index=True)

    # Details
    details = Column(JSON, default=dict)
    success = Column(Boolean, default=True)
    error_message = Column(String)

    # Timestamp
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    # Relationships
    tenant = relationship("Tenant")
    user = relationship("User")

    def __repr__(self):
        return f"<TenantAuditLog(tenant={self.tenant_id}, action={self.action}, resource={self.resource_type})>"


class TenantResourceQuota(Base):
    """
    Tenant resource quota tracking

    Tracks resource usage against quotas for billing and enforcement.

    Attributes:
        id: Unique identifier
        tenant_id: Tenant reference
        resource_type: Type of resource (devices, deployments, api_calls)
        quota_limit: Maximum allowed
        current_usage: Current usage
        period_start: Start of current period
        period_end: End of current period
    """
    __tablename__ = "tenant_resource_quotas"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)

    # Resource type and limits
    resource_type = Column(String, nullable=False)  # devices, users, deployments, api_calls
    quota_limit = Column(Integer, nullable=False)
    current_usage = Column(Integer, default=0)

    # Time period (for rate limits)
    period_start = Column(DateTime)
    period_end = Column(DateTime)

    # Status
    quota_exceeded = Column(Boolean, default=False)
    exceeded_at = Column(DateTime)

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    tenant = relationship("Tenant")

    def __repr__(self):
        return f"<TenantResourceQuota(tenant={self.tenant_id}, resource={self.resource_type}, usage={self.current_usage}/{self.quota_limit})>"

    def is_exceeded(self) -> bool:
        """Check if quota is exceeded"""
        return self.current_usage >= self.quota_limit

    def remaining(self) -> int:
        """Get remaining quota"""
        return max(0, self.quota_limit - self.current_usage)

    def usage_percentage(self) -> float:
        """Get usage as percentage"""
        if self.quota_limit == 0:
            return 0.0
        return (self.current_usage / self.quota_limit) * 100
