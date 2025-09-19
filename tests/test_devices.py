"""
Comprehensive tests for CatNet Device Management Service
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import uuid

from src.devices.device_manager import (
    DeviceManager,
    DeviceInfo,
    DeviceConnection,
    DeviceCredentials,
    DeviceVendor,
    DeviceType,
    DeviceState,
    ConnectionProtocol,
    DeviceAdapter,
)
from src.devices.adapters.cisco_adapter import CiscoAdapter
from src.devices.adapters.juniper_adapter import JuniperAdapter


class TestDeviceManager:
    """Test device manager"""

    def setup_method(self):
        """Setup test environment"""
        self.vault_service = Mock()
        self.audit_service = Mock()
        self.telemetry_service = Mock()

        self.manager = DeviceManager(
            vault_service=self.vault_service,
            audit_service=self.audit_service,
            telemetry_service=self.telemetry_service,
        )

    @pytest.mark.asyncio
    async def test_add_device(self):
        """Test adding a device to inventory"""
        # Add device
        device_id = await self.manager.add_device(
            hostname="router1",
            ip_address="192.168.1.1",
            vendor=DeviceVendor.CISCO_IOS,
            device_type=DeviceType.ROUTER,
            model="ISR4451",
            serial_number="FTX1234567",
            os_version="16.9.1",
            location="DC1-Rack1",
        )

        assert device_id is not None
        assert device_id in self.manager.devices

        device = self.manager.devices[device_id]
        assert device.hostname == "router1"
        assert device.vendor == DeviceVendor.CISCO_IOS
        assert device.state == DeviceState.ACTIVE

    @pytest.mark.asyncio
    async def test_connect_to_device(self):
        """Test connecting to a device"""
        # Add device
        device_id = await self.manager.add_device(
            hostname="switch1",
            ip_address="192.168.1.2",
            vendor=DeviceVendor.CISCO_IOS,
            device_type=DeviceType.SWITCH,
            model="Catalyst9300",
            serial_number="FCW2234567",
            os_version="17.3.1",
            location="DC1-Rack2",
        )

        # Register mock adapter
        mock_adapter = Mock(spec=DeviceAdapter)
        mock_connection = DeviceConnection(
            device_id=device_id,
            connection_id="conn-123",
            protocol=ConnectionProtocol.SSH,
            established_at=datetime.utcnow(),
            session_data=Mock(),
        )
        mock_adapter.connect = AsyncMock(return_value=mock_connection)
        self.manager.register_adapter(DeviceVendor.CISCO_IOS, mock_adapter)

        # Mock vault credentials
        self.vault_service.get_credentials = AsyncMock(
            return_value={
                "username": "admin",
                "password": "secret",
            }
        )

        # Connect to device
        connection = await self.manager.connect_to_device(device_id)

        assert connection is not None
        assert connection.device_id == device_id
        assert connection.connection_id in self.manager.connections

    @pytest.mark.asyncio
    async def test_execute_command(self):
        """Test executing command on device"""
        # Setup device and connection
        device_id = await self.manager.add_device(
            hostname="router2",
            ip_address="192.168.1.3",
            vendor=DeviceVendor.CISCO_IOS,
            device_type=DeviceType.ROUTER,
            model="ISR4331",
            serial_number="FTX3334567",
            os_version="16.12.1",
            location="DC1-Rack3",
        )

        # Mock adapter
        mock_adapter = Mock(spec=DeviceAdapter)
        mock_connection = DeviceConnection(
            device_id=device_id,
            connection_id="conn-456",
            protocol=ConnectionProtocol.SSH,
            established_at=datetime.utcnow(),
            session_data=Mock(),
        )
        mock_adapter.connect = AsyncMock(return_value=mock_connection)
        mock_adapter.execute_command = AsyncMock(
            return_value="GigabitEthernet0/0 is up"
        )
        self.manager.register_adapter(DeviceVendor.CISCO_IOS, mock_adapter)

        # Store connection
        self.manager.connections[mock_connection.connection_id] = mock_connection

        # Execute command
        output = await self.manager.execute_command(
            device_id,
            "show interface GigabitEthernet0/0",
            mock_connection.connection_id,
        )

        assert output == "GigabitEthernet0/0 is up"
        mock_adapter.execute_command.assert_called_once()

    @pytest.mark.asyncio
    async def test_bulk_execute(self):
        """Test bulk command execution"""
        # Add multiple devices
        device_ids = []
        for i in range(3):
            device_id = await self.manager.add_device(
                hostname=f"device{i}",
                ip_address=f"192.168.1.{10+i}",
                vendor=DeviceVendor.CISCO_IOS,
                device_type=DeviceType.SWITCH,
                model="Catalyst3850",
                serial_number=f"FCW444{i}567",
                os_version="16.12.1",
                location=f"DC1-Rack{i}",
            )
            device_ids.append(device_id)

        # Mock adapter and connections
        mock_adapter = Mock(spec=DeviceAdapter)
        mock_adapter.execute_command = AsyncMock(
            return_value="Command executed"
        )

        for device_id in device_ids:
            mock_connection = DeviceConnection(
                device_id=device_id,
                connection_id=f"conn-{device_id}",
                protocol=ConnectionProtocol.SSH,
                established_at=datetime.utcnow(),
                session_data=Mock(),
            )
            mock_adapter.connect = AsyncMock(return_value=mock_connection)
            self.manager.connections[mock_connection.connection_id] = mock_connection

        self.manager.register_adapter(DeviceVendor.CISCO_IOS, mock_adapter)

        # Execute bulk command
        results = await self.manager.bulk_execute(
            device_ids,
            "show version",
            parallel=True,
        )

        assert len(results) == 3
        for device_id in device_ids:
            assert device_id in results


class TestCiscoAdapter:
    """Test Cisco adapter"""

    def setup_method(self):
        """Setup test environment"""
        self.adapter = CiscoAdapter()

    @pytest.mark.asyncio
    async def test_connect_to_cisco_device(self):
        """Test connecting to Cisco device"""
        device = DeviceInfo(
            id="dev-cisco-1",
            hostname="cisco-router",
            ip_address="10.0.0.1",
            vendor=DeviceVendor.CISCO_IOS,
            device_type=DeviceType.ROUTER,
            model="ISR4451",
            serial_number="FTX1234567",
            os_version="16.9.1",
            location="DC1",
        )

        credentials = DeviceCredentials(
            username="admin",
            password="secret",
        )

        # Mock Netmiko ConnectHandler
        with patch("src.devices.adapters.cisco_adapter.ConnectHandler") as mock_connect:
            mock_session = Mock()
            mock_connect.return_value = mock_session

            # Connect
            connection = await self.adapter.connect(device, credentials)

            assert connection is not None
            assert connection.device_id == device.id
            assert connection.is_active
            mock_connect.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_cisco_command(self):
        """Test executing command on Cisco device"""
        # Create mock connection
        mock_session = Mock()
        mock_session.send_command = Mock(
            return_value="Interface GigabitEthernet0/0 is up"
        )

        connection = DeviceConnection(
            device_id="dev-cisco-1",
            connection_id="conn-cisco-1",
            protocol=ConnectionProtocol.SSH,
            established_at=datetime.utcnow(),
            session_data=mock_session,
            is_active=True,
        )

        # Execute command
        output = await self.adapter.execute_command(
            connection,
            "show interface GigabitEthernet0/0",
        )

        assert "GigabitEthernet0/0 is up" in output
        mock_session.send_command.assert_called_once()

    @pytest.mark.asyncio
    async def test_apply_cisco_configuration(self):
        """Test applying configuration to Cisco device"""
        # Create mock connection
        mock_session = Mock()
        mock_session.config_mode = Mock()
        mock_session.send_command = Mock(return_value="")
        mock_session.exit_config_mode = Mock()

        connection = DeviceConnection(
            device_id="dev-cisco-1",
            connection_id="conn-cisco-1",
            protocol=ConnectionProtocol.SSH,
            established_at=datetime.utcnow(),
            session_data=mock_session,
            is_active=True,
        )

        # Apply configuration
        config = """
        interface GigabitEthernet0/1
        ip address 192.168.1.1 255.255.255.0
        no shutdown
        """

        success = await self.adapter.apply_configuration(connection, config)

        assert success
        mock_session.config_mode.assert_called_once()
        mock_session.exit_config_mode.assert_called_once()


class TestJuniperAdapter:
    """Test Juniper adapter"""

    def setup_method(self):
        """Setup test environment"""
        self.adapter = JuniperAdapter()

    @pytest.mark.asyncio
    async def test_connect_to_juniper_device(self):
        """Test connecting to Juniper device"""
        device = DeviceInfo(
            id="dev-juniper-1",
            hostname="juniper-router",
            ip_address="10.0.1.1",
            vendor=DeviceVendor.JUNIPER_JUNOS,
            device_type=DeviceType.ROUTER,
            model="MX480",
            serial_number="JN1234567",
            os_version="19.4R1",
            location="DC2",
        )

        credentials = DeviceCredentials(
            username="admin",
            password="secret",
        )

        # Mock PyEZ Device
        with patch("src.devices.adapters.juniper_adapter.Device") as mock_device_class:
            mock_device = Mock()
            mock_device.open = Mock()
            mock_device.bind = Mock()
            mock_device_class.return_value = mock_device

            # Connect
            connection = await self.adapter.connect(device, credentials)

            assert connection is not None
            assert connection.device_id == device.id
            assert connection.is_active
            mock_device.open.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_juniper_command(self):
        """Test executing command on Juniper device"""
        # Create mock connection
        mock_device = Mock()
        mock_device.cli = Mock(
            return_value="ge-0/0/0 up up"
        )

        connection = DeviceConnection(
            device_id="dev-juniper-1",
            connection_id="conn-juniper-1",
            protocol=ConnectionProtocol.NETCONF,
            established_at=datetime.utcnow(),
            session_data=mock_device,
            is_active=True,
        )

        # Execute command
        output = await self.adapter.execute_command(
            connection,
            "show interfaces terse ge-0/0/0",
        )

        assert "ge-0/0/0" in output
        mock_device.cli.assert_called_once()

    @pytest.mark.asyncio
    async def test_apply_juniper_configuration(self):
        """Test applying configuration to Juniper device"""
        # Create mock connection
        mock_cu = Mock()
        mock_cu.lock = Mock()
        mock_cu.load = Mock()
        mock_cu.diff = Mock(return_value="+ new config")
        mock_cu.commit = Mock()
        mock_cu.unlock = Mock()

        mock_device = Mock()
        mock_device.cu = mock_cu

        connection = DeviceConnection(
            device_id="dev-juniper-1",
            connection_id="conn-juniper-1",
            protocol=ConnectionProtocol.NETCONF,
            established_at=datetime.utcnow(),
            session_data=mock_device,
            is_active=True,
        )

        # Apply configuration
        config = """
        set interfaces ge-0/0/1 unit 0 family inet address 192.168.2.1/24
        """

        success = await self.adapter.apply_configuration(connection, config)

        assert success
        mock_cu.lock.assert_called_once()
        mock_cu.load.assert_called_once()
        mock_cu.commit.assert_called_once()
        mock_cu.unlock.assert_called_once()


class TestDeviceHealthCheck:
    """Test device health checks"""

    def setup_method(self):
        """Setup test environment"""
        self.manager = DeviceManager()

    @pytest.mark.asyncio
    async def test_health_check(self):
        """Test device health check"""
        # Add device
        device_id = await self.manager.add_device(
            hostname="health-test",
            ip_address="10.10.10.10",
            vendor=DeviceVendor.CISCO_IOS,
            device_type=DeviceType.ROUTER,
            model="ISR4451",
            serial_number="FTX9999999",
            os_version="16.9.1",
            location="DC3",
        )

        # Mock connection and commands
        self.manager.connect_to_device = AsyncMock(
            return_value=Mock(connection_id="health-conn")
        )
        self.manager.execute_command = AsyncMock(
            side_effect=[
                "CPU utilization: 45%",
                "Memory used: 60%",
                "GigabitEthernet0/0 up",
            ]
        )
        self.manager.disconnect_device = AsyncMock(return_value=True)

        # Run health check
        health = await self.manager.health_check(device_id)

        assert health["reachable"] is True
        assert health["cpu_usage"] == 50  # Mocked value
        assert health["memory_usage"] == 60  # Mocked value
        assert len(health["issues"]) == 0


class TestDeviceInventory:
    """Test device inventory management"""

    def setup_method(self):
        """Setup test environment"""
        self.manager = DeviceManager()

    @pytest.mark.asyncio
    async def test_search_devices(self):
        """Test searching devices"""
        # Add various devices
        await self.manager.add_device(
            hostname="cisco1",
            ip_address="10.1.1.1",
            vendor=DeviceVendor.CISCO_IOS,
            device_type=DeviceType.ROUTER,
            model="ISR4451",
            serial_number="FTX111",
            os_version="16.9.1",
            location="DC1",
            tags=["production", "core"],
        )

        await self.manager.add_device(
            hostname="juniper1",
            ip_address="10.2.1.1",
            vendor=DeviceVendor.JUNIPER_JUNOS,
            device_type=DeviceType.ROUTER,
            model="MX480",
            serial_number="JN222",
            os_version="19.4R1",
            location="DC2",
            tags=["production", "edge"],
        )

        await self.manager.add_device(
            hostname="cisco2",
            ip_address="10.1.1.2",
            vendor=DeviceVendor.CISCO_IOS,
            device_type=DeviceType.SWITCH,
            model="Catalyst9300",
            serial_number="FCW333",
            os_version="17.3.1",
            location="DC1",
            tags=["development"],
        )

        # Search by vendor
        cisco_devices = self.manager.search_devices(vendor=DeviceVendor.CISCO_IOS)
        assert len(cisco_devices) == 2

        # Search by device type
        routers = self.manager.search_devices(device_type=DeviceType.ROUTER)
        assert len(routers) == 2

        # Search by tags
        prod_devices = self.manager.search_devices(tags=["production"])
        assert len(prod_devices) == 2

        # Combined search
        cisco_routers = self.manager.search_devices(
            vendor=DeviceVendor.CISCO_IOS,
            device_type=DeviceType.ROUTER,
        )
        assert len(cisco_routers) == 1

    @pytest.mark.asyncio
    async def test_device_state_management(self):
        """Test device state management"""
        # Add device
        device_id = await self.manager.add_device(
            hostname="state-test",
            ip_address="10.5.5.5",
            vendor=DeviceVendor.CISCO_IOS,
            device_type=DeviceType.SWITCH,
            model="Catalyst3850",
            serial_number="FCW555",
            os_version="16.12.1",
            location="DC5",
            state=DeviceState.ACTIVE,
        )

        # Check initial state
        device = self.manager.devices[device_id]
        assert device.state == DeviceState.ACTIVE

        # Update to maintenance
        device.state = DeviceState.MAINTENANCE
        maintenance_devices = self.manager.search_devices(
            state=DeviceState.MAINTENANCE
        )
        assert len(maintenance_devices) == 1

        # Update to decommissioned
        device.state = DeviceState.DECOMMISSIONED
        active_devices = self.manager.search_devices(state=DeviceState.ACTIVE)
        assert device_id not in [d["id"] for d in active_devices]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])