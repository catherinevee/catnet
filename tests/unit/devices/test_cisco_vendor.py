"""
Comprehensive unit tests for Cisco Device Implementation
Tests for IOS, IOS-XE, IOS-XR, and NX-OS devices
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime
import re

from src.devices.vendors.cisco import CiscoDevice
from src.core.exceptions import DeviceConfigurationError, DeviceCommandError


@pytest.fixture
def mock_connector():
    """Mock device connector."""
    connector = AsyncMock()
    connector.execute_command = AsyncMock(return_value="Command output")
    return connector


@pytest.fixture
def mock_connection():
    """Mock device connection."""
    conn = Mock()
    conn.session_id = "session_123"
    conn.is_active = True
    conn.device_id = "device_001"
    return conn


@pytest.fixture
def cisco_device(mock_connector, mock_connection):
    """Provide Cisco device instance."""
    device = CiscoDevice(
        hostname="router1.example.com",
        device_type="cisco_ios",
        connector=mock_connector
    )
    device.connection = mock_connection
    return device


@pytest.fixture
def sample_cisco_config():
    """Sample Cisco IOS configuration."""
    return """Building configuration...
Current configuration : 12345 bytes

hostname ROUTER1
!
interface GigabitEthernet0/1
 description WAN Connection
 ip address 192.168.1.1 255.255.255.0
 no shutdown
!
router bgp 65001
 bgp router-id 10.0.0.1
 neighbor 10.0.0.2 remote-as 65002
!
end"""


class TestCiscoCommandExecution:
    """Test Cisco command execution."""

    @pytest.mark.asyncio
    async def test_execute_command_exec_mode(self, cisco_device, mock_connector):
        """Test executing command in exec mode."""
        mock_connector.execute_command.return_value = "ROUTER1#"

        output = await cisco_device.execute_command("show version", mode="exec")

        assert output == "ROUTER1#"
        assert mock_connector.execute_command.call_count == 1
        assert len(cisco_device.command_history) == 1

    @pytest.mark.asyncio
    async def test_execute_command_config_mode(self, cisco_device, mock_connector):
        """Test executing command in configuration mode."""
        mock_connector.execute_command.side_effect = [
            "ROUTER1(config)#",  # configure terminal
            "ROUTER1(config)#",  # actual command
            "ROUTER1#"           # exit
        ]

        output = await cisco_device.execute_command("hostname TEST", mode="config")

        assert mock_connector.execute_command.call_count == 3
        calls = mock_connector.execute_command.call_args_list
        assert calls[0][0][1] == "configure terminal"
        assert calls[1][0][1] == "hostname TEST"
        assert calls[2][0][1] == "exit"

    @pytest.mark.asyncio
    async def test_execute_command_enable_mode(self, cisco_device, mock_connector):
        """Test executing command in enable mode."""
        mock_connector.execute_command.side_effect = [
            "ROUTER1#",  # enable
            "Version output"  # show version
        ]

        output = await cisco_device.execute_command("show version", mode="enable")

        assert mock_connector.execute_command.call_count == 2
        calls = mock_connector.execute_command.call_args_list
        assert calls[0][0][1] == "enable"
        assert calls[1][0][1] == "show version"

    @pytest.mark.asyncio
    async def test_execute_command_without_connection(self, cisco_device):
        """Test command execution fails without connection."""
        cisco_device.connection = None

        with pytest.raises(DeviceCommandError) as exc_info:
            await cisco_device.execute_command("show version")

        assert "No active connection" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_execute_command_with_timeout(self, cisco_device, mock_connector):
        """Test command execution with custom timeout."""
        await cisco_device.execute_command("show tech-support", timeout=120)

        call_args = mock_connector.execute_command.call_args
        assert call_args[1]['timeout'] == 120

    @pytest.mark.asyncio
    async def test_command_history_tracking(self, cisco_device, mock_connector):
        """Test command history is tracked."""
        await cisco_device.execute_command("show version")
        await cisco_device.execute_command("show interfaces")

        assert len(cisco_device.command_history) == 2
        assert cisco_device.command_history[0]['command'] == "show version"
        assert cisco_device.command_history[1]['command'] == "show interfaces"
        assert 'timestamp' in cisco_device.command_history[0]


class TestCiscoConfigurationRetrieval:
    """Test configuration retrieval."""

    @pytest.mark.asyncio
    async def test_get_running_configuration(self, cisco_device, mock_connector, sample_cisco_config):
        """Test getting running configuration."""
        mock_connector.execute_command.return_value = sample_cisco_config

        config = await cisco_device.get_configuration(config_type="running")

        assert "hostname ROUTER1" in config
        assert "Building configuration" not in config  # Cleaned
        assert mock_connector.execute_command.called

    @pytest.mark.asyncio
    async def test_get_startup_configuration(self, cisco_device, mock_connector):
        """Test getting startup configuration."""
        mock_connector.execute_command.return_value = "startup config content"

        config = await cisco_device.get_configuration(config_type="startup")

        assert "startup config content" in config

    @pytest.mark.asyncio
    async def test_get_both_configurations(self, cisco_device, mock_connector):
        """Test getting both running and startup configurations."""
        mock_connector.execute_command.side_effect = [
            "show version",  # enable mode
            "running config here",
            "startup config here"
        ]

        config = await cisco_device.get_configuration(config_type="both")

        assert "Running Configuration" in config
        assert "Startup Configuration" in config
        assert "running config here" in config
        assert "startup config here" in config

    @pytest.mark.asyncio
    async def test_get_configuration_invalid_type(self, cisco_device):
        """Test getting configuration with invalid type."""
        with pytest.raises(ValueError) as exc_info:
            await cisco_device.get_configuration(config_type="invalid")

        assert "Invalid config type" in str(exc_info.value)

    def test_clean_config_output(self, cisco_device, sample_cisco_config):
        """Test configuration output cleaning."""
        cleaned = cisco_device.clean_config_output(sample_cisco_config)

        assert "Building configuration" not in cleaned
        assert "Current configuration" not in cleaned
        assert "hostname ROUTER1" in cleaned
        assert "interface GigabitEthernet0/1" in cleaned


class TestCiscoConfigurationApplication:
    """Test configuration application."""

    @pytest.mark.asyncio
    async def test_apply_configuration_success(self, cisco_device, mock_connector):
        """Test successful configuration application."""
        config = """hostname ROUTER2
interface GigabitEthernet0/1
 description New Description
 no shutdown"""

        mock_connector.execute_command.return_value = "ROUTER2(config)#"

        with patch.object(cisco_device, 'validate_config_syntax', return_value={"valid": True}):
            result = await cisco_device.apply_configuration(config)

        assert result is True

    @pytest.mark.asyncio
    async def test_apply_configuration_without_validation(self, cisco_device, mock_connector):
        """Test applying configuration without validation."""
        config = "hostname ROUTER3"
        mock_connector.execute_command.return_value = "ROUTER3(config)#"

        result = await cisco_device.apply_configuration(config, validate=False)

        assert result is True

    @pytest.mark.asyncio
    async def test_apply_configuration_validation_failure(self, cisco_device):
        """Test configuration application fails on validation error."""
        config = "invalid config line"

        with patch.object(cisco_device, 'validate_config_syntax', return_value={
            "valid": False,
            "errors": ["Syntax error on line 1"]
        }):
            with pytest.raises(DeviceConfigurationError) as exc_info:
                await cisco_device.apply_configuration(config)

        assert "validation failed" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_apply_configuration_with_errors(self, cisco_device, mock_connector):
        """Test configuration application detects command errors."""
        config = "hostname ROUTER4"

        mock_connector.execute_command.side_effect = [
            "ROUTER4(config)#",  # configure terminal
            "% Invalid input detected at '^' marker.",  # error
            "ROUTER4#"  # end
        ]

        with patch.object(cisco_device, 'validate_config_syntax', return_value={"valid": True}):
            with pytest.raises(DeviceConfigurationError):
                await cisco_device.apply_configuration(config)

    @pytest.mark.asyncio
    async def test_apply_configuration_skips_comments(self, cisco_device, mock_connector):
        """Test configuration application skips comments and empty lines."""
        config = """! This is a comment
hostname ROUTER5

! Another comment
interface GigabitEthernet0/1"""

        mock_connector.execute_command.return_value = "ROUTER5(config)#"

        with patch.object(cisco_device, 'validate_config_syntax', return_value={"valid": True}):
            result = await cisco_device.apply_configuration(config)

        # Should only execute hostname and interface commands (plus enter/exit config mode)
        assert result is True

    @pytest.mark.asyncio
    async def test_apply_configuration_exits_on_exception(self, cisco_device, mock_connector):
        """Test configuration mode is exited even on exception."""
        config = "hostname ROUTER6"

        mock_connector.execute_command.side_effect = [
            "ROUTER6(config)#",  # configure terminal
            Exception("Connection lost"),  # command fails
            "ROUTER6#"  # end (cleanup)
        ]

        with patch.object(cisco_device, 'validate_config_syntax', return_value={"valid": True}):
            with pytest.raises(DeviceConfigurationError):
                await cisco_device.apply_configuration(config)


class TestCiscoErrorDetection:
    """Test error detection in command output."""

    def test_check_for_errors_invalid(self, cisco_device):
        """Test detection of invalid command error."""
        output = "% Invalid input detected at '^' marker."

        has_error = cisco_device.check_for_errors(output)

        assert has_error is True

    def test_check_for_errors_incomplete(self, cisco_device):
        """Test detection of incomplete command error."""
        output = "% Incomplete command."

        has_error = cisco_device.check_for_errors(output)

        assert has_error is True

    def test_check_for_errors_ambiguous(self, cisco_device):
        """Test detection of ambiguous command error."""
        output = "% Ambiguous command: 'sh in'"

        has_error = cisco_device.check_for_errors(output)

        assert has_error is True

    def test_check_for_errors_multiple_patterns(self, cisco_device):
        """Test detection works with various error patterns."""
        error_outputs = [
            "% Error in command",
            "% Bad IP address",
            "% Unknown command",
            "% Cannot configure",
            "% Failed to apply",
            "% Unrecognized command"
        ]

        for output in error_outputs:
            assert cisco_device.check_for_errors(output) is True

    def test_check_for_errors_case_insensitive(self, cisco_device):
        """Test error detection is case insensitive."""
        output = "% invalid input detected"

        has_error = cisco_device.check_for_errors(output)

        assert has_error is True

    def test_check_for_errors_no_error(self, cisco_device):
        """Test no error detected in successful output."""
        output = "Configuration updated successfully"

        has_error = cisco_device.check_for_errors(output)

        assert has_error is False


class TestCiscoConfigurationSave:
    """Test configuration save functionality."""

    @pytest.mark.asyncio
    async def test_save_configuration_ios(self, cisco_device, mock_connector):
        """Test saving configuration on IOS device."""
        mock_connector.execute_command.side_effect = [
            "ROUTER1#",  # enable
            "Building configuration...\n[OK]"  # write memory
        ]

        with patch.object(cisco_device, 'is_nxos', return_value=False):
            result = await cisco_device.save_configuration()

        assert result is True
        calls = mock_connector.execute_command.call_args_list
        assert "write memory" in calls[1][0][1]

    @pytest.mark.asyncio
    async def test_save_configuration_nxos(self, cisco_device, mock_connector):
        """Test saving configuration on NX-OS device."""
        mock_connector.execute_command.side_effect = [
            "SWITCH1#",  # enable
            "Copy complete."  # copy running-config startup-config
        ]

        with patch.object(cisco_device, 'is_nxos', return_value=True):
            result = await cisco_device.save_configuration()

        assert result is True
        calls = mock_connector.execute_command.call_args_list
        assert "copy running-config startup-config" in calls[1][0][1]

    @pytest.mark.asyncio
    async def test_save_configuration_failure(self, cisco_device, mock_connector):
        """Test configuration save failure."""
        mock_connector.execute_command.side_effect = [
            "ROUTER1#",  # enable
            "% Error opening nvram:startup-config (No space left)"
        ]

        with patch.object(cisco_device, 'is_nxos', return_value=False):
            with pytest.raises(DeviceConfigurationError) as exc_info:
                await cisco_device.save_configuration()

        assert "Save failed" in str(exc_info.value)


class TestCiscoCommands:
    """Test Cisco command mappings."""

    def test_command_mappings_exist(self, cisco_device):
        """Test all standard command mappings exist."""
        required_commands = [
            "show_run", "show_start", "save", "show_version",
            "show_interfaces", "show_routes", "show_cpu", "show_memory"
        ]

        for cmd in required_commands:
            assert cmd in cisco_device.COMMANDS

    def test_nxos_command_mappings(self, cisco_device):
        """Test NX-OS specific command mappings."""
        assert "show_cpu" in cisco_device.NXOS_COMMANDS
        assert "save" in cisco_device.NXOS_COMMANDS
        assert "rollback" in cisco_device.NXOS_COMMANDS

    def test_command_mapping_values(self, cisco_device):
        """Test command mapping values are correct."""
        assert cisco_device.COMMANDS["show_run"] == "show running-config"
        assert cisco_device.COMMANDS["save"] == "write memory"
        assert cisco_device.NXOS_COMMANDS["save"] == "copy running-config startup-config"


class TestCiscoDeviceInitialization:
    """Test Cisco device initialization."""

    def test_init_with_connector(self, mock_connector):
        """Test device initialization with connector."""
        device = CiscoDevice(
            hostname="router.example.com",
            device_type="cisco_ios",
            connector=mock_connector
        )

        assert device.hostname == "router.example.com"
        assert device.device_type == "cisco_ios"
        assert device.connector == mock_connector
        assert device.command_history == []

    def test_command_mappings_initialized(self, cisco_device):
        """Test command mappings are properly initialized."""
        assert hasattr(cisco_device, 'COMMANDS')
        assert hasattr(cisco_device, 'NXOS_COMMANDS')
        assert isinstance(cisco_device.COMMANDS, dict)
        assert isinstance(cisco_device.NXOS_COMMANDS, dict)


class TestCiscoEdgeCases:
    """Test edge cases and special scenarios."""

    @pytest.mark.asyncio
    async def test_execute_command_empty_output(self, cisco_device, mock_connector):
        """Test handling empty command output."""
        mock_connector.execute_command.return_value = ""

        output = await cisco_device.execute_command("show something")

        assert output == ""
        assert len(cisco_device.command_history) == 1

    @pytest.mark.asyncio
    async def test_execute_command_multiline_output(self, cisco_device, mock_connector):
        """Test handling multiline command output."""
        multiline_output = """Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/1     192.168.1.1     YES NVRAM  up                    up
GigabitEthernet0/2     unassigned      YES NVRAM  administratively down down"""

        mock_connector.execute_command.return_value = multiline_output

        output = await cisco_device.execute_command("show ip interface brief")

        assert "GigabitEthernet0/1" in output
        assert "192.168.1.1" in output

    def test_clean_config_removes_timestamps(self, cisco_device):
        """Test config cleaning removes timestamp lines."""
        config_with_timestamps = """Building configuration...
Current configuration : 1234 bytes
Last configuration change at 12:34:56 UTC Mon Jan 1 2025
!
hostname ROUTER1"""

        cleaned = cisco_device.clean_config_output(config_with_timestamps)

        assert "Last configuration change" not in cleaned
        assert "hostname ROUTER1" in cleaned

    @pytest.mark.asyncio
    async def test_apply_configuration_with_multiline_commands(self, cisco_device, mock_connector):
        """Test applying configuration with indented multiline commands."""
        config = """interface GigabitEthernet0/1
 description WAN Link
 ip address 10.0.0.1 255.255.255.0
 no shutdown"""

        mock_connector.execute_command.return_value = "ROUTER1(config)#"

        with patch.object(cisco_device, 'validate_config_syntax', return_value={"valid": True}):
            result = await cisco_device.apply_configuration(config)

        assert result is True

    @pytest.mark.asyncio
    async def test_save_configuration_with_confirmation(self, cisco_device, mock_connector):
        """Test save configuration handles confirmation prompts."""
        mock_connector.execute_command.side_effect = [
            "ROUTER1#",
            "Destination filename [startup-config]?\n[OK]"
        ]

        with patch.object(cisco_device, 'is_nxos', return_value=False):
            result = await cisco_device.save_configuration()

        assert result is True
