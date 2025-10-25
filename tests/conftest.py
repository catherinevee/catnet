"""
Global test configuration and fixtures for CatNet test suite.
Provides shared fixtures, test utilities, and configuration for all tests.
"""

import asyncio
import os
import pytest
import tempfile
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, AsyncGenerator, Generator
from unittest.mock import Mock, AsyncMock, patch

import asyncpg
import redis.asyncio as redis
from fastapi.testclient import TestClient
from httpx import AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import sessionmaker

from src.api.app import app
from src.db.base import Base
from src.db.session import get_session
from src.auth.models import User
from src.devices.models import Device
from src.core.security import SecurityManager, VaultClient
from src.auth.service import AuthService
from src.devices.device_service import DeviceService
from src.gitops.service import GitOpsService
from src.services.deployment_service import DeploymentService
from src.monitoring.metrics import MetricsCollector
from configs.settings import get_settings


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def test_settings():
    """Test settings with overrides for testing environment."""
    settings = get_settings()
    settings.TESTING = True
    settings.DEBUG = True
    settings.ENVIRONMENT = "testing"
    settings.database.POSTGRES_DB = "catnet_test"
    settings.database.REDIS_DB = 1
    settings.security.JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 1
    settings.vault.VAULT_SSL_VERIFY = False
    return settings


@pytest.fixture(scope="session")
async def test_db_engine(test_settings):
    """Create test database engine."""
    # Use in-memory SQLite for fast tests, or test PostgreSQL for integration
    if os.getenv("USE_POSTGRES_TESTS", "false").lower() == "true":
        engine = create_async_engine(
            test_settings.database.postgres_dsn,
            echo=test_settings.DEBUG,
            future=True
        )
    else:
        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            echo=test_settings.DEBUG,
            future=True
        )

    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    # Cleanup
    await engine.dispose()


@pytest.fixture
async def test_session(test_db_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create test database session."""
    async_session_maker = async_sessionmaker(
        test_db_engine,
        class_=AsyncSession,
        expire_on_commit=False
    )

    async with async_session_maker() as session:
        yield session
        await session.rollback()


@pytest.fixture
async def test_redis():
    """Create test Redis connection."""
    redis_client = redis.Redis(
        host="localhost",
        port=6379,
        db=1,  # Use test database
        decode_responses=True
    )

    yield redis_client

    # Cleanup
    await redis_client.flushdb()
    await redis_client.close()


@pytest.fixture
def mock_vault():
    """Mock Vault client for testing."""
    vault_mock = Mock(spec=VaultClient)
    vault_mock.get_secret = AsyncMock(return_value={"password": "test_password"})
    vault_mock.store_secret = AsyncMock(return_value=True)
    vault_mock.get_temporary_credentials = AsyncMock(return_value={
        "username": "test_user",
        "password": "test_password",
        "expires_at": datetime.utcnow() + timedelta(minutes=30)
    })
    vault_mock.delete_secret = AsyncMock(return_value=True)
    vault_mock.list_secrets = AsyncMock(return_value=["secret1", "secret2"])
    return vault_mock


@pytest.fixture
def mock_device_connection():
    """Mock device connection for testing."""
    connection_mock = AsyncMock()
    connection_mock.send_command = AsyncMock(return_value="Command output")
    connection_mock.send_config = AsyncMock(return_value="Config applied")
    connection_mock.get_config = AsyncMock(return_value="Current config")
    connection_mock.backup_config = AsyncMock(return_value="backup_id_123")
    connection_mock.restore_config = AsyncMock(return_value=True)
    connection_mock.is_alive = AsyncMock(return_value=True)
    connection_mock.disconnect = AsyncMock(return_value=True)
    return connection_mock


@pytest.fixture
async def test_user(test_session) -> User:
    """Create test user."""
    user = User(
        id=uuid.uuid4(),
        username="testuser",
        email="test@catnet.local",
        password_hash="$2b$12$test_hash",
        first_name="Test",
        last_name="User",
        is_active=True,
        is_superuser=False,
        mfa_enabled=False
    )

    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)

    return user


@pytest.fixture
async def test_admin_user(test_session) -> User:
    """Create test admin user."""
    admin = User(
        id=uuid.uuid4(),
        username="admin",
        email="admin@catnet.local",
        password_hash="$2b$12$admin_hash",
        first_name="Admin",
        last_name="User",
        is_active=True,
        is_superuser=True,
        mfa_enabled=True
    )

    test_session.add(admin)
    await test_session.commit()
    await test_session.refresh(admin)

    return admin


@pytest.fixture
async def test_device(test_session) -> Device:
    """Create test device."""
    device = Device(
        id=uuid.uuid4(),
        name="test-switch-01",
        hostname="switch01.catnet.local",
        ip_address="192.168.1.10",
        vendor="cisco",
        platform="ios",
        os_version="15.2(4)S7",
        model="WS-C3750X-24T",
        serial_number="FDO1234567",
        location="DC1-Rack-01",
        ssh_port=22,
        status="active"
    )

    test_session.add(device)
    await test_session.commit()
    await test_session.refresh(device)

    return device


@pytest.fixture
def test_client(test_session):
    """Create test client with dependency overrides."""

    def override_get_session():
        return test_session

    app.dependency_overrides[get_session] = override_get_session

    with TestClient(app) as client:
        yield client

    app.dependency_overrides.clear()


@pytest.fixture
async def async_test_client(test_session):
    """Create async test client."""

    def override_get_session():
        return test_session

    app.dependency_overrides[get_session] = override_get_session

    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client

    app.dependency_overrides.clear()


@pytest.fixture
def auth_headers(test_user):
    """Create authentication headers for test user."""
    token = "test_token_123"
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_auth_headers(test_admin_user):
    """Create authentication headers for admin user."""
    token = "admin_token_123"
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def sample_config():
    """Sample device configuration for testing."""
    return {
        "version": "1.0",
        "vendor": "cisco",
        "platform": "ios",
        "hostname": "test-device",
        "interfaces": {
            "GigabitEthernet0/1": {
                "description": "Uplink to Core",
                "switchport": {
                    "mode": "trunk",
                    "allowed_vlans": "1,10,20,30"
                }
            }
        },
        "vlans": {
            "10": {"name": "MGMT"},
            "20": {"name": "USERS"},
            "30": {"name": "SERVERS"}
        }
    }


@pytest.fixture
def sample_git_webhook():
    """Sample Git webhook payload for testing."""
    return {
        "ref": "refs/heads/main",
        "after": "1234567890abcdef",
        "before": "0987654321fedcba",
        "commits": [
            {
                "id": "1234567890abcdef",
                "message": "Update switch configuration",
                "author": {
                    "name": "Test User",
                    "email": "test@catnet.local"
                },
                "modified": ["configs/switches/switch01.yml"],
                "added": [],
                "removed": []
            }
        ],
        "repository": {
            "name": "catnet-configs",
            "full_name": "company/catnet-configs",
            "clone_url": "https://github.com/company/catnet-configs.git"
        }
    }


@pytest.fixture
async def mock_auth_service(mock_vault):
    """Mock authentication service."""
    auth_service = Mock(spec=AuthService)
    auth_service.vault = mock_vault
    auth_service.authenticate_user = AsyncMock(return_value=True)
    auth_service.create_access_token = AsyncMock(return_value="test_token")
    auth_service.verify_token = AsyncMock(return_value={"sub": "testuser"})
    auth_service.verify_mfa = AsyncMock(return_value=True)
    auth_service.generate_mfa_qr = AsyncMock(return_value="qr_code_data")
    return auth_service


@pytest.fixture
async def mock_device_service(mock_vault, mock_device_connection):
    """Mock device service."""
    device_service = Mock(spec=DeviceService)
    device_service.vault = mock_vault
    device_service.connect_to_device = AsyncMock(return_value="session_123")
    device_service.execute_command = AsyncMock(return_value={
        "success": True,
        "output": "Command executed successfully"
    })
    device_service.backup_device_config = AsyncMock(return_value="backup_123")
    device_service.deploy_config = AsyncMock(return_value=True)
    return device_service


@pytest.fixture
async def mock_gitops_service():
    """Mock GitOps service."""
    gitops_service = Mock(spec=GitOpsService)
    gitops_service.process_webhook = AsyncMock(return_value="webhook_processed")
    gitops_service.sync_repository = AsyncMock(return_value=True)
    gitops_service.validate_config = AsyncMock(return_value={"valid": True})
    gitops_service.scan_for_secrets = AsyncMock(return_value=[])
    return gitops_service


@pytest.fixture
async def mock_deployment_service():
    """Mock deployment service."""
    deployment_service = Mock(spec=DeploymentService)
    deployment_service.create_deployment = AsyncMock(return_value="deployment_123")
    deployment_service.execute_deployment = AsyncMock(return_value={"success": True})
    deployment_service.rollback_deployment = AsyncMock(return_value=True)
    deployment_service.get_deployment_status = AsyncMock(return_value="completed")
    return deployment_service


@pytest.fixture
def mock_metrics_collector():
    """Mock metrics collector."""
    metrics = Mock(spec=MetricsCollector)
    metrics.record_request = AsyncMock()
    metrics.record_deployment = AsyncMock()
    metrics.record_auth_attempt = AsyncMock()
    metrics.record_security_violation = AsyncMock()
    metrics.collect_all = Mock(return_value={})
    return metrics


@pytest.fixture
def temp_dir():
    """Create temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def mock_ssh_client():
    """Mock SSH client for network device connections."""
    ssh_mock = Mock()
    ssh_mock.connect = Mock()
    ssh_mock.exec_command = Mock(return_value=(
        Mock(),  # stdin
        Mock(read=Mock(return_value=b"Command output")),  # stdout
        Mock(read=Mock(return_value=b""))  # stderr
    ))
    ssh_mock.close = Mock()
    return ssh_mock


@pytest.fixture
def mock_git_repo():
    """Mock Git repository for testing."""
    repo_mock = Mock()
    repo_mock.clone = Mock()
    repo_mock.pull = Mock()
    repo_mock.commit = Mock()
    repo_mock.push = Mock()
    repo_mock.get_commits = Mock(return_value=[])
    repo_mock.get_files = Mock(return_value=[])
    return repo_mock


# Pytest plugins and hooks
def pytest_configure(config):
    """Configure pytest with custom markers and settings."""
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line("markers", "integration: mark test as integration test")
    config.addinivalue_line("markers", "security: mark test as security test")
    config.addinivalue_line("markers", "performance: mark test as performance test")


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on test location."""
    for item in items:
        # Add markers based on test file location
        if "integration" in item.nodeid:
            item.add_marker(pytest.mark.integration)
        if "security" in item.nodeid:
            item.add_marker(pytest.mark.security)
        if "performance" in item.nodeid:
            item.add_marker(pytest.mark.performance)
        if "e2e" in item.nodeid:
            item.add_marker(pytest.mark.e2e)

        # Mark slow tests
        if "slow" in item.name or "performance" in item.nodeid:
            item.add_marker(pytest.mark.slow)


@pytest.fixture(autouse=True)
def cleanup_after_test():
    """Cleanup after each test."""
    yield
    # Any cleanup logic that should run after every test