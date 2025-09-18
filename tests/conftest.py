"""
Pytest configuration and fixtures for CatNet tests
"""
import pytest
import asyncio
import sys
import os
from unittest.mock import Mock, AsyncMock

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


# Configure event loop
@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_database():
    """Mock database session"""
    mock_db = AsyncMock()
    mock_db.execute = AsyncMock()
    mock_db.commit = AsyncMock()
    mock_db.rollback = AsyncMock()
    mock_db.refresh = AsyncMock()
    return mock_db


@pytest.fixture
def mock_vault_client():
    """Mock Vault client"""
    mock_vault = Mock()
    mock_vault.get_secret = AsyncMock(
        return_value={"username": "test", "password": "test123"}
    )
    mock_vault.store_secret = AsyncMock()
    mock_vault.get_device_credentials = AsyncMock(
        return_value={
            "username": "admin",
            "password": "admin123",
            "enable_password": "enable123",
        }
    )
    return mock_vault


@pytest.fixture
def mock_audit_logger():
    """Mock audit logger"""
    mock_audit = Mock()
    mock_audit.log_event = AsyncMock()
    mock_audit.log_authentication = AsyncMock()
    mock_audit.log_deployment = AsyncMock()
    mock_audit.log_security_incident = AsyncMock()
    return mock_audit


@pytest.fixture
def mock_device():
    """Mock network device"""
    from src.db.models import DeviceVendor

    device = Mock()
    device.id = "test-device-1"
    device.hostname = "test-router"
    device.ip_address = "192.168.1.1"
    device.vendor = DeviceVendor.CISCO_IOS
    device.port = 22
    device.is_active = True
    return device


@pytest.fixture
def mock_user():
    """Mock user"""
    user = Mock()
    user.id = "test-user-1"
    user.username = "testuser"
    user.email = "test@catnet.local"
    user.roles = ["admin"]
    user.is_superuser = True
    user.is_active = True
    user.mfa_secret = None
    return user


@pytest.fixture
def test_config():
    """Test configuration"""
    return {
        "vendor": "cisco",
        "device_id": "test-device-1",
        "configuration": """
interface GigabitEthernet0/0
 description Test Interface
 ip address 192.168.1.1 255.255.255.0
 no shutdown
!
""",
        "metadata": {"author": "test", "timestamp": "2024-01-01T00:00:00Z"},
    }


@pytest.fixture
def mock_connection():
    """Mock device connection"""
    mock_conn = Mock()
    mock_conn.send_command = Mock(return_value="Command output")
    mock_conn.send_config_set = Mock(return_value="Config output")
    mock_conn.enable = Mock()
    mock_conn.disconnect = Mock()
    return mock_conn
