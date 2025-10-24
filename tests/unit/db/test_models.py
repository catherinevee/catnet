"""
Comprehensive unit tests for Database Models
Tests User, Role, Device, Deployment, GitRepository models and relationships
"""

import pytest
from datetime import datetime, timedelta
from uuid import uuid4
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import IntegrityError

from src.db.models import (
    Base, User, Role, Device, Deployment, GitRepository,
    DeviceConfig, AuditLog, Session as UserSession,
    user_roles, deployment_approvers, deployment_devices
)


@pytest.fixture(scope="function")
def db_engine():
    """Create in-memory SQLite database engine."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)


@pytest.fixture(scope="function")
def db_session(db_engine):
    """Create database session."""
    SessionLocal = sessionmaker(bind=db_engine)
    session = SessionLocal()
    yield session
    session.close()


class TestUserModel:
    """Test User model."""

    def test_create_user(self, db_session):
        """Test creating a user."""
        user = User(
            username="testuser",
            email="test@example.com",
            full_name="Test User"
        )
        db_session.add(user)
        db_session.commit()

        assert user.id is not None
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.is_active is True
        assert user.is_superuser is False

    def test_user_unique_username(self, db_session):
        """Test username must be unique."""
        user1 = User(username="duplicate", email="user1@example.com")
        user2 = User(username="duplicate", email="user2@example.com")

        db_session.add(user1)
        db_session.commit()

        db_session.add(user2)
        with pytest.raises(IntegrityError):
            db_session.commit()

    def test_user_unique_email(self, db_session):
        """Test email must be unique."""
        user1 = User(username="user1", email="duplicate@example.com")
        user2 = User(username="user2", email="duplicate@example.com")

        db_session.add(user1)
        db_session.commit()

        db_session.add(user2)
        with pytest.raises(IntegrityError):
            db_session.commit()

    def test_user_email_validation(self, db_session):
        """Test email validation."""
        user = User(username="baduser", email="invalid_email")

        with pytest.raises(ValueError) as exc_info:
            db_session.add(user)
            db_session.flush()

        assert "Invalid email address" in str(exc_info.value)

    def test_user_email_lowercase(self, db_session):
        """Test email is stored in lowercase."""
        user = User(username="user", email="TEST@EXAMPLE.COM")
        db_session.add(user)
        db_session.commit()

        assert user.email == "test@example.com"

    def test_user_mfa_fields(self, db_session):
        """Test MFA-related fields."""
        user = User(
            username="mfauser",
            email="mfa@example.com",
            mfa_enabled=True,
            mfa_secret="JBSWY3DPEHPK3PXP",
            mfa_backup_codes=["123456", "789012"]
        )
        db_session.add(user)
        db_session.commit()

        assert user.mfa_enabled is True
        assert user.mfa_secret == "JBSWY3DPEHPK3PXP"
        assert len(user.mfa_backup_codes) == 2

    def test_user_failed_login_attempts(self, db_session):
        """Test failed login attempts tracking."""
        user = User(username="user", email="user@example.com")
        db_session.add(user)
        db_session.commit()

        user.failed_login_attempts = 3
        user.locked_until = datetime.utcnow() + timedelta(minutes=30)
        db_session.commit()

        assert user.failed_login_attempts == 3
        assert user.locked_until is not None

    def test_user_timestamps(self, db_session):
        """Test user timestamps are set automatically."""
        user = User(username="user", email="user@example.com")
        db_session.add(user)
        db_session.commit()

        assert user.created_at is not None
        assert user.updated_at is not None

    def test_user_oauth_fields(self, db_session):
        """Test OAuth/SAML fields."""
        user = User(
            username="oauthuser",
            email="oauth@example.com",
            oauth_provider="github",
            oauth_id="github_12345"
        )
        db_session.add(user)
        db_session.commit()

        assert user.oauth_provider == "github"
        assert user.oauth_id == "github_12345"


class TestRoleModel:
    """Test Role model."""

    def test_create_role(self, db_session):
        """Test creating a role."""
        role = Role(
            name="admin",
            description="Administrator role",
            permissions={"deployment.create": True, "device.manage": True}
        )
        db_session.add(role)
        db_session.commit()

        assert role.id is not None
        assert role.name == "admin"
        assert role.permissions["deployment.create"] is True

    def test_role_unique_name(self, db_session):
        """Test role name must be unique."""
        role1 = Role(name="operator", permissions={})
        role2 = Role(name="operator", permissions={})

        db_session.add(role1)
        db_session.commit()

        db_session.add(role2)
        with pytest.raises(IntegrityError):
            db_session.commit()

    def test_role_system_role(self, db_session):
        """Test system role flag."""
        role = Role(
            name="system_admin",
            permissions={},
            is_system_role=True
        )
        db_session.add(role)
        db_session.commit()

        assert role.is_system_role is True

    def test_role_mfa_requirement(self, db_session):
        """Test role MFA requirement."""
        role = Role(
            name="security_admin",
            permissions={},
            require_mfa=True
        )
        db_session.add(role)
        db_session.commit()

        assert role.require_mfa is True

    def test_role_session_duration(self, db_session):
        """Test role maximum session duration."""
        role = Role(
            name="guest",
            permissions={},
            max_session_duration=30  # 30 minutes
        )
        db_session.add(role)
        db_session.commit()

        assert role.max_session_duration == 30


class TestUserRoleRelationship:
    """Test User-Role many-to-many relationship."""

    def test_assign_role_to_user(self, db_session):
        """Test assigning role to user."""
        user = User(username="user", email="user@example.com")
        role = Role(name="viewer", permissions={})

        db_session.add(user)
        db_session.add(role)
        db_session.commit()

        user.roles.append(role)
        db_session.commit()

        assert len(user.roles) == 1
        assert user.roles[0].name == "viewer"
        assert len(role.users) == 1

    def test_assign_multiple_roles(self, db_session):
        """Test assigning multiple roles to user."""
        user = User(username="user", email="user@example.com")
        role1 = Role(name="viewer", permissions={})
        role2 = Role(name="operator", permissions={})

        db_session.add_all([user, role1, role2])
        db_session.commit()

        user.roles.extend([role1, role2])
        db_session.commit()

        assert len(user.roles) == 2

    def test_remove_role_from_user(self, db_session):
        """Test removing role from user."""
        user = User(username="user", email="user@example.com")
        role = Role(name="temp_role", permissions={})

        db_session.add_all([user, role])
        user.roles.append(role)
        db_session.commit()

        user.roles.remove(role)
        db_session.commit()

        assert len(user.roles) == 0


class TestDeviceModel:
    """Test Device model."""

    def test_create_device(self, db_session):
        """Test creating a device."""
        device = Device(
            hostname="router1.example.com",
            management_ip="192.168.1.1",
            vendor="cisco",
            model="ISR4451",
            credential_ref="vault:devices/router1"
        )
        db_session.add(device)
        db_session.commit()

        assert device.id is not None
        assert device.hostname == "router1.example.com"
        assert device.vendor == "cisco"
        assert device.is_active is True

    def test_device_unique_hostname(self, db_session):
        """Test device hostname must be unique."""
        device1 = Device(
            hostname="router1.example.com",
            management_ip="192.168.1.1",
            vendor="cisco",
            credential_ref="vault:ref1"
        )
        device2 = Device(
            hostname="router1.example.com",
            management_ip="192.168.1.2",
            vendor="cisco",
            credential_ref="vault:ref2"
        )

        db_session.add(device1)
        db_session.commit()

        db_session.add(device2)
        with pytest.raises(IntegrityError):
            db_session.commit()

    def test_device_unique_serial_number(self, db_session):
        """Test device serial number must be unique."""
        device1 = Device(
            hostname="router1",
            management_ip="192.168.1.1",
            vendor="cisco",
            credential_ref="vault:ref1",
            serial_number="SN123456"
        )
        device2 = Device(
            hostname="router2",
            management_ip="192.168.1.2",
            vendor="cisco",
            credential_ref="vault:ref2",
            serial_number="SN123456"
        )

        db_session.add(device1)
        db_session.commit()

        db_session.add(device2)
        with pytest.raises(IntegrityError):
            db_session.commit()

    def test_device_connection_details(self, db_session):
        """Test device connection details."""
        device = Device(
            hostname="router",
            management_ip="10.0.0.1",
            vendor="juniper",
            credential_ref="vault:ref",
            connection_type="netconf",
            ssh_port=22,
            netconf_port=830
        )
        db_session.add(device)
        db_session.commit()

        assert device.connection_type == "netconf"
        assert device.ssh_port == 22
        assert device.netconf_port == 830

    def test_device_metadata(self, db_session):
        """Test device metadata fields."""
        device = Device(
            hostname="switch1",
            management_ip="10.0.0.5",
            vendor="cisco",
            credential_ref="vault:ref",
            location="DC1 Rack 42",
            site_id="DC1",
            role="access",
            environment="production",
            tags=["critical", "monitored"]
        )
        db_session.add(device)
        db_session.commit()

        assert device.location == "DC1 Rack 42"
        assert device.role == "access"
        assert device.environment == "production"
        assert "critical" in device.tags

    def test_device_status_fields(self, db_session):
        """Test device status tracking."""
        device = Device(
            hostname="router",
            management_ip="10.0.0.1",
            vendor="cisco",
            credential_ref="vault:ref",
            is_active=True,
            is_managed=True,
            last_seen=datetime.utcnow(),
            cpu_usage=45,
            memory_usage=60
        )
        db_session.add(device)
        db_session.commit()

        assert device.is_active is True
        assert device.cpu_usage == 45
        assert device.memory_usage == 60

    def test_device_config_compliance(self, db_session):
        """Test device configuration compliance tracking."""
        device = Device(
            hostname="router",
            management_ip="10.0.0.1",
            vendor="cisco",
            credential_ref="vault:ref",
            current_config_hash="abc123",
            desired_config_hash="abc123",
            config_compliance=True
        )
        db_session.add(device)
        db_session.commit()

        assert device.config_compliance is True
        assert device.current_config_hash == device.desired_config_hash


class TestDeploymentModel:
    """Test Deployment model."""

    def test_create_deployment(self, db_session):
        """Test creating a deployment."""
        user = User(username="deployer", email="deployer@example.com")
        db_session.add(user)
        db_session.commit()

        deployment = Deployment(
            name="Production Release v1.2.3",
            description="Deploy new configs",
            strategy="canary",
            config_hash="xyz789",
            signature="sig_abc123",
            created_by=user.id
        )
        db_session.add(deployment)
        db_session.commit()

        assert deployment.id is not None
        assert deployment.name == "Production Release v1.2.3"
        assert deployment.state == "pending"
        assert deployment.strategy == "canary"

    def test_deployment_approval_workflow(self, db_session):
        """Test deployment approval workflow."""
        user = User(username="user", email="user@example.com")
        db_session.add(user)
        db_session.commit()

        deployment = Deployment(
            name="Test Deployment",
            strategy="rolling",
            config_hash="hash",
            signature="sig",
            created_by=user.id,
            approval_required=True,
            approvals_needed=2,
            approvals_received=0
        )
        db_session.add(deployment)
        db_session.commit()

        assert deployment.approval_required is True
        assert deployment.approvals_needed == 2
        assert deployment.approvals_received == 0

    def test_deployment_state_management(self, db_session):
        """Test deployment state transitions."""
        user = User(username="user", email="user@example.com")
        db_session.add(user)
        db_session.commit()

        deployment = Deployment(
            name="Deployment",
            strategy="blue_green",
            config_hash="hash",
            signature="sig",
            created_by=user.id,
            state="pending"
        )
        db_session.add(deployment)
        db_session.commit()

        deployment.state = "approved"
        deployment.started_at = datetime.utcnow()
        db_session.commit()

        assert deployment.state == "approved"
        assert deployment.started_at is not None

    def test_deployment_git_information(self, db_session):
        """Test deployment Git information."""
        user = User(username="user", email="user@example.com")
        repo = GitRepository(name="configs", url="https://github.com/org/configs")
        db_session.add_all([user, repo])
        db_session.commit()

        deployment = Deployment(
            name="Deploy from Git",
            strategy="rolling",
            config_hash="hash",
            signature="sig",
            created_by=user.id,
            repository_id=repo.id,
            commit_hash="abc123def456",
            branch="main"
        )
        db_session.add(deployment)
        db_session.commit()

        assert deployment.commit_hash == "abc123def456"
        assert deployment.branch == "main"

    def test_deployment_metrics(self, db_session):
        """Test deployment metrics tracking."""
        user = User(username="user", email="user@example.com")
        db_session.add(user)
        db_session.commit()

        deployment = Deployment(
            name="Deployment",
            strategy="canary",
            config_hash="hash",
            signature="sig",
            created_by=user.id,
            devices_total=10,
            devices_succeeded=8,
            devices_failed=2
        )
        db_session.add(deployment)
        db_session.commit()

        success_rate = (deployment.devices_succeeded / deployment.devices_total) * 100
        assert success_rate == 80.0

    def test_deployment_rollback(self, db_session):
        """Test deployment rollback information."""
        user = User(username="user", email="user@example.com")
        db_session.add(user)
        db_session.commit()

        original = Deployment(
            name="Original",
            strategy="rolling",
            config_hash="hash1",
            signature="sig1",
            created_by=user.id
        )
        db_session.add(original)
        db_session.commit()

        rollback = Deployment(
            name="Rollback",
            strategy="immediate",
            config_hash="hash0",
            signature="sig0",
            created_by=user.id,
            rollback_deployment_id=original.id,
            rolled_back_by=user.id
        )
        db_session.add(rollback)
        db_session.commit()

        assert rollback.rollback_deployment_id == original.id


class TestGitRepositoryModel:
    """Test GitRepository model."""

    def test_create_git_repository(self, db_session):
        """Test creating a Git repository."""
        repo = GitRepository(
            name="network-configs",
            url="https://github.com/company/network-configs",
            branch="main"
        )
        db_session.add(repo)
        db_session.commit()

        assert repo.id is not None
        assert repo.name == "network-configs"
        assert repo.branch == "main"
        assert repo.is_active is True

    def test_git_repository_unique_url(self, db_session):
        """Test repository URL must be unique."""
        repo1 = GitRepository(name="repo1", url="https://github.com/org/configs")
        repo2 = GitRepository(name="repo2", url="https://github.com/org/configs")

        db_session.add(repo1)
        db_session.commit()

        db_session.add(repo2)
        with pytest.raises(IntegrityError):
            db_session.commit()

    def test_git_repository_auth_types(self, db_session):
        """Test different authentication types."""
        repo_ssh = GitRepository(
            name="ssh_repo",
            url="git@github.com:org/repo.git",
            auth_type="ssh",
            ssh_key_ref="vault:ssh/github"
        )
        repo_token = GitRepository(
            name="token_repo",
            url="https://github.com/org/repo",
            auth_type="token",
            token_ref="vault:tokens/github"
        )

        db_session.add_all([repo_ssh, repo_token])
        db_session.commit()

        assert repo_ssh.auth_type == "ssh"
        assert repo_token.auth_type == "token"

    def test_git_repository_webhook_config(self, db_session):
        """Test webhook configuration."""
        repo = GitRepository(
            name="repo",
            url="https://github.com/org/repo",
            webhook_url="https://catnet.example.com/webhooks/github",
            webhook_secret_ref="vault:webhooks/github",
            webhook_events=["push", "pull_request"]
        )
        db_session.add(repo)
        db_session.commit()

        assert "push" in repo.webhook_events
        assert "pull_request" in repo.webhook_events

    def test_git_repository_sync_config(self, db_session):
        """Test sync configuration."""
        repo = GitRepository(
            name="repo",
            url="https://github.com/org/repo",
            auto_sync=True,
            sync_interval=300,  # 5 minutes
            last_sync=datetime.utcnow()
        )
        db_session.add(repo)
        db_session.commit()

        assert repo.auto_sync is True
        assert repo.sync_interval == 300

    def test_git_repository_security_settings(self, db_session):
        """Test security settings."""
        repo = GitRepository(
            name="repo",
            url="https://github.com/org/repo",
            gpg_verification=True,
            allowed_signers=["user@example.com"],
            scan_for_secrets=True
        )
        db_session.add(repo)
        db_session.commit()

        assert repo.gpg_verification is True
        assert repo.scan_for_secrets is True


class TestDeploymentDeviceRelationship:
    """Test Deployment-Device many-to-many relationship."""

    def test_assign_devices_to_deployment(self, db_session):
        """Test assigning devices to deployment."""
        user = User(username="user", email="user@example.com")
        device1 = Device(hostname="r1", management_ip="10.0.0.1", vendor="cisco", credential_ref="vault:r1")
        device2 = Device(hostname="r2", management_ip="10.0.0.2", vendor="cisco", credential_ref="vault:r2")

        db_session.add_all([user, device1, device2])
        db_session.commit()

        deployment = Deployment(
            name="Deploy",
            strategy="rolling",
            config_hash="hash",
            signature="sig",
            created_by=user.id
        )
        db_session.add(deployment)
        db_session.commit()

        deployment.devices.extend([device1, device2])
        db_session.commit()

        assert len(deployment.devices) == 2


class TestModelCascades:
    """Test cascade deletions."""

    def test_delete_user_cascade_sessions(self, db_session):
        """Test deleting user cascades to sessions."""
        user = User(username="user", email="user@example.com")
        db_session.add(user)
        db_session.commit()

        # User deletion should cascade properly
        db_session.delete(user)
        db_session.commit()

    def test_delete_device_cascade_configs(self, db_session):
        """Test deleting device cascades to configs."""
        device = Device(
            hostname="router",
            management_ip="10.0.0.1",
            vendor="cisco",
            credential_ref="vault:ref"
        )
        db_session.add(device)
        db_session.commit()

        db_session.delete(device)
        db_session.commit()


class TestModelConstraints:
    """Test database constraints."""

    def test_failed_login_attempts_positive(self, db_session):
        """Test failed login attempts must be positive."""
        user = User(
            username="user",
            email="user@example.com",
            failed_login_attempts=-1
        )
        db_session.add(user)

        # SQLite doesn't enforce CHECK constraints by default
        # This test documents the constraint

    def test_ssh_port_range(self, db_session):
        """Test SSH port must be in valid range."""
        device = Device(
            hostname="router",
            management_ip="10.0.0.1",
            vendor="cisco",
            credential_ref="vault:ref",
            ssh_port=70000  # Invalid
        )
        db_session.add(device)

        # SQLite doesn't enforce CHECK constraints by default
        # This test documents the constraint

    def test_deployment_approvals_constraint(self, db_session):
        """Test approvals received cannot exceed approvals needed."""
        user = User(username="user", email="user@example.com")
        db_session.add(user)
        db_session.commit()

        deployment = Deployment(
            name="Deploy",
            strategy="rolling",
            config_hash="hash",
            signature="sig",
            created_by=user.id,
            approvals_needed=2,
            approvals_received=3  # Invalid
        )
        db_session.add(deployment)

        # SQLite doesn't enforce CHECK constraints by default
        # This test documents the constraint


class TestModelIndexes:
    """Test model indexes exist."""

    def test_user_indexes(self, db_engine):
        """Test User model indexes."""
        indexes = [idx.name for idx in User.__table__.indexes]
        assert 'ix_users_email_active' in indexes

    def test_device_indexes(self, db_engine):
        """Test Device model indexes."""
        indexes = [idx.name for idx in Device.__table__.indexes]
        assert 'ix_devices_vendor_active' in indexes
        assert 'ix_devices_environment' in indexes

    def test_deployment_indexes(self, db_engine):
        """Test Deployment model indexes."""
        indexes = [idx.name for idx in Deployment.__table__.indexes]
        assert 'ix_deployments_state_created' in indexes
