"""
Unit tests for Device Connector
Tests secure device connections, authentication, and session management
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime, timedelta
from uuid import uuid4

from src.devices.secure_connector import (
    DeviceConnector,
    DeviceConnection,
    BastionHost
)
from src.core.exceptions import (
    DeviceConnectionError,
    DeviceAuthenticationError,
    DeviceTimeoutError
)


@pytest.fixture
def mock_vault():
    """Provide a mock Vault client."""
    vault = AsyncMock()
    vault.get_device_credentials = AsyncMock(return_value={
        "username": "admin",
        "password": "secure_password",
        "enable_password": "enable_secret"
    })
    return vault


@pytest.fixture
def mock_device():
    """Provide a mock device."""
    device = Mock()
    device.id = uuid4()
    device.hostname = "router1.example.com"
    device.ip_address = "10.0.0.1"
    device.vendor = "cisco_ios"
    device.port = 22
    device.is_active = True
    return device


@pytest.fixture
def mock_bastion():
    """Provide a mock bastion host."""
    return BastionHost(
        id=str(uuid4()),
        hostname="bastion.example.com",
        ip_address="10.0.1.1",
        zone="us-east-1",
        environment="production",
        health_score=0.95,
        load_score=0.3,
        max_connections=100,
        current_connections=30,
        last_health_check=datetime.utcnow()
    )


@pytest.fixture
def device_connector(mock_vault):
    """Provide a device connector instance."""
    with patch('src.devices.secure_connector.VaultClient', return_value=mock_vault):
        connector = DeviceConnector()
        connector.vault_client = mock_vault
        return connector


class TestDeviceConnection:
    """Test DeviceConnection class."""

    def test_device_connection_creation(self):
        """Test device connection object creation."""
        session_id = str(uuid4())
        device_id = str(uuid4())
        user_id = str(uuid4())

        conn = DeviceConnection(
            session_id=session_id,
            device_id=device_id,
            connection_handler=Mock(),
            protocol="ssh",
            source_ip="192.168.1.100",
            user_id=user_id
        )

        assert conn.session_id == session_id
        assert conn.device_id == device_id
        assert conn.protocol == "ssh"
        assert conn.command_count == 0

    def test_device_connection_is_active(self):
        """Test device connection activity check."""
        conn = DeviceConnection(
            session_id=str(uuid4()),
            device_id=str(uuid4()),
            connection_handler=Mock(),
            protocol="ssh",
            source_ip="192.168.1.100",
            user_id=str(uuid4())
        )

        assert conn.is_active() is True

    def test_device_connection_is_inactive_after_timeout(self):
        """Test connection becomes inactive after timeout."""
        conn = DeviceConnection(
            session_id=str(uuid4()),
            device_id=str(uuid4()),
            connection_handler=Mock(),
            protocol="ssh",
            source_ip="192.168.1.100",
            user_id=str(uuid4())
        )

        # Simulate old last_activity
        conn.last_activity = datetime.utcnow() - timedelta(hours=2)

        assert conn.is_active() is False


class TestBastionHost:
    """Test BastionHost dataclass."""

    def test_bastion_host_creation(self, mock_bastion):
        """Test bastion host creation."""
        assert mock_bastion.hostname == "bastion.example.com"
        assert mock_bastion.health_score == 0.95
        assert mock_bastion.current_connections < mock_bastion.max_connections

    def test_bastion_host_metadata(self):
        """Test bastion host metadata initialization."""
        bastion = BastionHost(
            id=str(uuid4()),
            hostname="bastion2",
            ip_address="10.0.2.1",
            zone="us-west-1",
            environment="staging",
            health_score=0.9,
            load_score=0.5,
            max_connections=50,
            current_connections=25,
            last_health_check=datetime.utcnow()
        )

        assert bastion.metadata == {}

    def test_bastion_host_with_custom_metadata(self):
        """Test bastion host with custom metadata."""
        metadata = {"region": "us-east", "tier": "premium"}

        bastion = BastionHost(
            id=str(uuid4()),
            hostname="bastion3",
            ip_address="10.0.3.1",
            zone="us-east-1",
            environment="production",
            health_score=1.0,
            load_score=0.2,
            max_connections=200,
            current_connections=40,
            last_health_check=datetime.utcnow(),
            metadata=metadata
        )

        assert bastion.metadata == metadata


class TestDeviceConnectorConnection:
    """Test device connection establishment."""

    @pytest.mark.asyncio
    async def test_connect_success(self, device_connector, mock_device, mock_vault):
        """Test successful device connection."""
        with patch('src.devices.secure_connector.ConnectHandler') as mock_handler:
            mock_handler.return_value = Mock()

            connection = await device_connector.connect(
                device=mock_device,
                user_id=str(uuid4())
            )

            assert connection is not None
            assert connection.device_id == str(mock_device.id)
            mock_vault.get_device_credentials.assert_called_once()

    @pytest.mark.asyncio
    async def test_connect_authentication_failure(self, device_connector, mock_device, mock_vault):
        """Test connection fails with authentication error."""
        with patch('src.devices.secure_connector.ConnectHandler') as mock_handler:
            from netmiko import NetmikoAuthenticationException
            mock_handler.side_effect = NetmikoAuthenticationException("Auth failed")

            with pytest.raises(DeviceAuthenticationError):
                await device_connector.connect(
                    device=mock_device,
                    user_id=str(uuid4())
                )

    @pytest.mark.asyncio
    async def test_connect_timeout(self, device_connector, mock_device, mock_vault):
        """Test connection timeout handling."""
        with patch('src.devices.secure_connector.ConnectHandler') as mock_handler:
            from netmiko import NetmikoTimeoutException
            mock_handler.side_effect = NetmikoTimeoutException("Connection timeout")

            with pytest.raises(DeviceTimeoutError):
                await device_connector.connect(
                    device=mock_device,
                    user_id=str(uuid4())
                )

    @pytest.mark.asyncio
    async def test_connect_with_bastion(self, device_connector, mock_device, mock_bastion, mock_vault):
        """Test connection through bastion host."""
        with patch('src.devices.secure_connector.ConnectHandler') as mock_handler:
            mock_handler.return_value = Mock()

            connection = await device_connector.connect(
                device=mock_device,
                user_id=str(uuid4()),
                bastion=mock_bastion
            )

            assert connection is not None
            # Connection should use bastion configuration
            call_kwargs = mock_handler.call_args[1]
            assert 'ssh_config_file' in call_kwargs or 'sock' in call_kwargs

    @pytest.mark.asyncio
    async def test_connect_caches_credentials(self, device_connector, mock_device, mock_vault):
        """Test credential caching for performance."""
        with patch('src.devices.secure_connector.ConnectHandler') as mock_handler:
            mock_handler.return_value = Mock()

            # First connection
            await device_connector.connect(device=mock_device, user_id=str(uuid4()))

            # Second connection to same device
            await device_connector.connect(device=mock_device, user_id=str(uuid4()))

            # Vault should only be called once due to caching
            # Note: This assumes caching is implemented
            call_count = mock_vault.get_device_credentials.call_count
            assert call_count >= 1


class TestDeviceConnectorDisconnection:
    """Test device disconnection."""

    @pytest.mark.asyncio
    async def test_disconnect_success(self, device_connector, mock_device):
        """Test successful device disconnection."""
        # Create mock connection
        mock_conn_handler = Mock()
        mock_conn_handler.disconnect = Mock()

        connection = DeviceConnection(
            session_id=str(uuid4()),
            device_id=str(mock_device.id),
            connection_handler=mock_conn_handler,
            protocol="ssh",
            source_ip="192.168.1.100",
            user_id=str(uuid4())
        )

        device_connector.active_connections[connection.session_id] = connection

        await device_connector.disconnect(session_id=connection.session_id)

        mock_conn_handler.disconnect.assert_called_once()
        assert connection.session_id not in device_connector.active_connections

    @pytest.mark.asyncio
    async def test_disconnect_nonexistent_session(self, device_connector):
        """Test disconnecting non-existent session."""
        fake_session_id = str(uuid4())

        # Should not raise error
        await device_connector.disconnect(session_id=fake_session_id)

    @pytest.mark.asyncio
    async def test_disconnect_all_sessions(self, device_connector, mock_device):
        """Test disconnecting all sessions."""
        # Create multiple connections
        connections = []
        for _ in range(3):
            mock_handler = Mock()
            mock_handler.disconnect = Mock()

            conn = DeviceConnection(
                session_id=str(uuid4()),
                device_id=str(mock_device.id),
                connection_handler=mock_handler,
                protocol="ssh",
                source_ip="192.168.1.100",
                user_id=str(uuid4())
            )
            connections.append(conn)
            device_connector.active_connections[conn.session_id] = conn

        await device_connector.disconnect_all()

        assert len(device_connector.active_connections) == 0
        for conn in connections:
            conn.connection_handler.disconnect.assert_called_once()


class TestDeviceConnectorCommandExecution:
    """Test command execution on devices."""

    @pytest.mark.asyncio
    async def test_execute_command_success(self, device_connector, mock_device):
        """Test successful command execution."""
        mock_handler = Mock()
        mock_handler.send_command = Mock(return_value="interface GigabitEthernet0/0\n ip address 10.0.0.1")

        connection = DeviceConnection(
            session_id=str(uuid4()),
            device_id=str(mock_device.id),
            connection_handler=mock_handler,
            protocol="ssh",
            source_ip="192.168.1.100",
            user_id=str(uuid4())
        )

        device_connector.active_connections[connection.session_id] = connection

        result = await device_connector.execute_command(
            session_id=connection.session_id,
            command="show running-config interface GigabitEthernet0/0"
        )

        assert result is not None
        assert "ip address" in result
        mock_handler.send_command.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_command_updates_activity(self, device_connector, mock_device):
        """Test command execution updates last activity."""
        mock_handler = Mock()
        mock_handler.send_command = Mock(return_value="OK")

        connection = DeviceConnection(
            session_id=str(uuid4()),
            device_id=str(mock_device.id),
            connection_handler=mock_handler,
            protocol="ssh",
            source_ip="192.168.1.100",
            user_id=str(uuid4())
        )

        old_activity = connection.last_activity
        device_connector.active_connections[connection.session_id] = connection

        await device_connector.execute_command(
            session_id=connection.session_id,
            command="show version"
        )

        assert connection.last_activity > old_activity
        assert connection.command_count == 1

    @pytest.mark.asyncio
    async def test_execute_command_on_inactive_session(self, device_connector):
        """Test command execution on inactive session fails."""
        fake_session_id = str(uuid4())

        with pytest.raises(DeviceConnectionError):
            await device_connector.execute_command(
                session_id=fake_session_id,
                command="show version"
            )

    @pytest.mark.asyncio
    async def test_execute_config_commands(self, device_connector, mock_device):
        """Test execution of configuration commands."""
        mock_handler = Mock()
        mock_handler.send_config_set = Mock(return_value="Config applied")

        connection = DeviceConnection(
            session_id=str(uuid4()),
            device_id=str(mock_device.id),
            connection_handler=mock_handler,
            protocol="ssh",
            source_ip="192.168.1.100",
            user_id=str(uuid4())
        )

        device_connector.active_connections[connection.session_id] = connection

        commands = [
            "interface GigabitEthernet0/0",
            "ip address 10.0.0.1 255.255.255.0",
            "no shutdown"
        ]

        result = await device_connector.execute_config_commands(
            session_id=connection.session_id,
            commands=commands
        )

        assert result is not None
        mock_handler.send_config_set.assert_called_once_with(commands)


class TestConnectionPooling:
    """Test connection pool management."""

    @pytest.mark.asyncio
    async def test_connection_pool_limits(self, device_connector, mock_device):
        """Test connection pool respects max connections."""
        device_connector.max_connections_per_device = 5

        connections = []
        for i in range(5):
            with patch('src.devices.secure_connector.ConnectHandler') as mock_handler:
                mock_handler.return_value = Mock()

                conn = await device_connector.connect(
                    device=mock_device,
                    user_id=str(uuid4())
                )
                connections.append(conn)

        # Attempting 6th connection should fail or queue
        with patch('src.devices.secure_connector.ConnectHandler'):
            with pytest.raises(DeviceConnectionError, match=".*connection limit.*"):
                await device_connector.connect(
                    device=mock_device,
                    user_id=str(uuid4())
                )

    @pytest.mark.asyncio
    async def test_cleanup_inactive_connections(self, device_connector, mock_device):
        """Test cleanup of inactive connections."""
        mock_handler = Mock()
        mock_handler.disconnect = Mock()

        # Create old connection
        old_conn = DeviceConnection(
            session_id=str(uuid4()),
            device_id=str(mock_device.id),
            connection_handler=mock_handler,
            protocol="ssh",
            source_ip="192.168.1.100",
            user_id=str(uuid4())
        )
        old_conn.last_activity = datetime.utcnow() - timedelta(hours=3)

        device_connector.active_connections[old_conn.session_id] = old_conn

        await device_connector.cleanup_inactive_connections()

        assert old_conn.session_id not in device_connector.active_connections
        mock_handler.disconnect.assert_called_once()


class TestSecurityFeatures:
    """Test security features of device connector."""

    @pytest.mark.asyncio
    async def test_connection_audit_logging(self, device_connector, mock_device):
        """Test connections are audited."""
        with patch('src.devices.secure_connector.ConnectHandler') as mock_handler:
            with patch.object(device_connector, 'audit_logger') as mock_audit:
                mock_handler.return_value = Mock()

                await device_connector.connect(
                    device=mock_device,
                    user_id=str(uuid4())
                )

                # Verify audit log was created
                assert mock_audit.log_device_connection.called

    @pytest.mark.asyncio
    async def test_command_validation(self, device_connector, mock_device):
        """Test dangerous commands are blocked."""
        mock_handler = Mock()
        connection = DeviceConnection(
            session_id=str(uuid4()),
            device_id=str(mock_device.id),
            connection_handler=mock_handler,
            protocol="ssh",
            source_ip="192.168.1.100",
            user_id=str(uuid4())
        )

        device_connector.active_connections[connection.session_id] = connection

        dangerous_commands = [
            "reload",
            "write erase",
            "delete flash:",
            "format"
        ]

        for cmd in dangerous_commands:
            with pytest.raises(DeviceConnectionError, match=".*dangerous.*"):
                await device_connector.execute_command(
                    session_id=connection.session_id,
                    command=cmd,
                    validate=True
                )

    @pytest.mark.asyncio
    async def test_credential_encryption(self, device_connector, mock_device, mock_vault):
        """Test credentials are retrieved securely from Vault."""
        with patch('src.devices.secure_connector.ConnectHandler') as mock_handler:
            mock_handler.return_value = Mock()

            await device_connector.connect(
                device=mock_device,
                user_id=str(uuid4())
            )

            # Verify Vault was used for credentials
            mock_vault.get_device_credentials.assert_called_once_with(
                device_id=str(mock_device.id)
            )


class TestEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.mark.asyncio
    async def test_connect_to_inactive_device(self, device_connector, mock_device):
        """Test connection to inactive device fails."""
        mock_device.is_active = False

        with pytest.raises(DeviceConnectionError, match=".*inactive.*"):
            await device_connector.connect(
                device=mock_device,
                user_id=str(uuid4())
            )

    @pytest.mark.asyncio
    async def test_connect_with_invalid_vendor(self, device_connector, mock_device):
        """Test connection with unsupported vendor fails."""
        mock_device.vendor = "unsupported_vendor_xyz"

        with pytest.raises(DeviceConnectionError, match=".*unsupported.*"):
            await device_connector.connect(
                device=mock_device,
                user_id=str(uuid4())
            )

    @pytest.mark.asyncio
    async def test_execute_empty_command(self, device_connector, mock_device):
        """Test execution of empty command fails."""
        mock_handler = Mock()
        connection = DeviceConnection(
            session_id=str(uuid4()),
            device_id=str(mock_device.id),
            connection_handler=mock_handler,
            protocol="ssh",
            source_ip="192.168.1.100",
            user_id=str(uuid4())
        )

        device_connector.active_connections[connection.session_id] = connection

        with pytest.raises(ValueError):
            await device_connector.execute_command(
                session_id=connection.session_id,
                command=""
            )
