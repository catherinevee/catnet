"""
Comprehensive unit tests for Juniper Junos Device Implementation
Tests for Junos configuration modes, commit operations, and rollback functionality
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime
import re

from src.devices.vendors.juniper import JuniperDevice
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
    conn.session_id = "session_juniper_123"
    conn.is_active = True
    conn.device_id = "juniper_device_001"
    return conn


@pytest.fixture
def mock_device():
    """Mock device object."""
    device = Mock()
    device.hostname = "router1.example.com"
    device.device_type = "juniper_junos"
    device.model = "MX480"
    return device


@pytest.fixture
def juniper_device(mock_connector, mock_device, mock_connection):
    """Provide Juniper device instance."""
    device = JuniperDevice(
        connector=mock_connector,
        device=mock_device,
        connection=mock_connection
    )
    return device


@pytest.fixture
def sample_junos_config():
    """Sample Junos configuration."""
    return """## Last commit: 2025-01-10 12:00:00 UTC
version 20.2R1.10;
system {
    host-name ROUTER1;
    root-authentication {
        encrypted-password "$1$abc123";
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 192.168.1.1/24;
            }
        }
    }
}
routing-options {
    autonomous-system 65001;
}"""


class TestJuniperCommandExecution:
    """Test Juniper command execution."""

    @pytest.mark.asyncio
    async def test_execute_command_exec_mode(self, juniper_device, mock_connector):
        """Test executing command in exec mode."""
        mock_connector.execute_command.return_value = "admin@ROUTER1>"

        output = await juniper_device.execute_command("show version", mode="exec")

        assert output == "admin@ROUTER1>"
        assert mock_connector.execute_command.call_count == 1
        assert len(juniper_device.command_history) == 1

    @pytest.mark.asyncio
    async def test_execute_command_operational_mode(self, juniper_device, mock_connector):
        """Test executing command in operational mode."""
        juniper_device.config_mode = None
        mock_connector.execute_command.return_value = "Version output"

        output = await juniper_device.execute_command("show version", mode="operational")

        assert output == "Version output"

    @pytest.mark.asyncio
    async def test_execute_command_config_mode(self, juniper_device, mock_connector):
        """Test executing command in configuration mode."""
        juniper_device.config_mode = "private"
        mock_connector.execute_command.return_value = "[edit]\nadmin@ROUTER1#"

        output = await juniper_device.execute_command("set system host-name TEST", mode="config")

        assert "set system host-name TEST" in juniper_device.candidate_config

    @pytest.mark.asyncio
    async def test_execute_command_enters_config_mode(self, juniper_device, mock_connector):
        """Test command execution enters config mode when needed."""
        juniper_device.config_mode = None
        mock_connector.execute_command.side_effect = [
            "Entering configuration mode\n[edit]",  # configure private
            "[edit]\nadmin@ROUTER1#"  # actual command
        ]

        await juniper_device.execute_command("set system host-name TEST", mode="config")

        assert juniper_device.config_mode == "private"

    @pytest.mark.asyncio
    async def test_execute_command_without_connection(self, juniper_device):
        """Test command execution fails without connection."""
        juniper_device.connection = None

        with pytest.raises(DeviceCommandError) as exc_info:
            await juniper_device.execute_command("show version")

        assert "No active connection" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_execute_command_exits_config_for_operational(self, juniper_device, mock_connector):
        """Test operational commands exit config mode."""
        juniper_device.config_mode = "private"

        with patch.object(juniper_device, 'exit_config_mode', new_callable=AsyncMock) as mock_exit:
            await juniper_device.execute_command("show version", mode="operational")

            assert mock_exit.called


class TestJuniperConfigurationMode:
    """Test Juniper configuration mode management."""

    @pytest.mark.asyncio
    async def test_enter_config_mode_private(self, juniper_device, mock_connector):
        """Test entering private configuration mode."""
        mock_connector.execute_command.return_value = "Entering configuration mode\n[edit]"

        result = await juniper_device.enter_config_mode("private")

        assert result is True
        assert juniper_device.config_mode == "private"
        calls = mock_connector.execute_command.call_args_list
        assert "configure private" in calls[0][0][1]

    @pytest.mark.asyncio
    async def test_enter_config_mode_exclusive(self, juniper_device, mock_connector):
        """Test entering exclusive configuration mode."""
        mock_connector.execute_command.return_value = "[edit]"

        result = await juniper_device.enter_config_mode("exclusive")

        assert result is True
        assert juniper_device.config_mode == "exclusive"

    @pytest.mark.asyncio
    async def test_enter_config_mode_already_in_mode(self, juniper_device):
        """Test entering config mode when already in it."""
        juniper_device.config_mode = "private"

        result = await juniper_device.enter_config_mode("private")

        assert result is True

    @pytest.mark.asyncio
    async def test_enter_config_mode_failure(self, juniper_device, mock_connector):
        """Test config mode entry failure."""
        mock_connector.execute_command.return_value = "error: configuration database locked"

        with pytest.raises(DeviceConfigurationError) as exc_info:
            await juniper_device.enter_config_mode("exclusive")

        assert "Failed to enter config mode" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_exit_config_mode_success(self, juniper_device, mock_connector):
        """Test exiting configuration mode."""
        juniper_device.config_mode = "private"
        juniper_device.candidate_config = ["set system host-name TEST"]
        mock_connector.execute_command.return_value = "Exiting configuration mode"

        result = await juniper_device.exit_config_mode()

        assert result is True
        assert juniper_device.config_mode is None
        assert juniper_device.candidate_config == []

    @pytest.mark.asyncio
    async def test_exit_config_mode_with_rollback(self, juniper_device, mock_connector):
        """Test exiting config mode with rollback."""
        juniper_device.config_mode = "private"
        mock_connector.execute_command.side_effect = [
            "load complete",  # rollback 0
            "Exiting configuration mode"  # exit
        ]

        result = await juniper_device.exit_config_mode(rollback=True)

        assert result is True
        calls = mock_connector.execute_command.call_args_list
        assert "rollback 0" in calls[0][0][1]

    @pytest.mark.asyncio
    async def test_exit_config_mode_with_commit(self, juniper_device, mock_connector):
        """Test exiting config mode with commit."""
        juniper_device.config_mode = "private"

        with patch.object(juniper_device, 'commit_changes', new_callable=AsyncMock) as mock_commit:
            mock_commit.return_value = "commit complete"
            await juniper_device.exit_config_mode(commit=True)

            assert mock_commit.called

    @pytest.mark.asyncio
    async def test_exit_config_mode_not_in_mode(self, juniper_device):
        """Test exiting when not in config mode."""
        juniper_device.config_mode = None

        result = await juniper_device.exit_config_mode()

        assert result is True


class TestJuniperConfigurationRetrieval:
    """Test configuration retrieval."""

    @pytest.mark.asyncio
    async def test_get_configuration_default(self, juniper_device, mock_connector, sample_junos_config):
        """Test getting configuration in default format."""
        mock_connector.execute_command.return_value = sample_junos_config

        config = await juniper_device.get_configuration()

        assert "host-name ROUTER1" in config
        assert "## Last commit" not in config  # Cleaned

    @pytest.mark.asyncio
    async def test_get_configuration_set_format(self, juniper_device, mock_connector):
        """Test getting configuration in set format."""
        set_config = """set system host-name ROUTER1
set interfaces ge-0/0/0 unit 0 family inet address 192.168.1.1/24"""

        mock_connector.execute_command.return_value = set_config

        config = await juniper_device.get_configuration(config_type="set")

        assert "set system host-name ROUTER1" in config

    @pytest.mark.asyncio
    async def test_get_configuration_xml_format(self, juniper_device, mock_connector):
        """Test getting configuration in XML format."""
        xml_config = """<configuration>
    <system>
        <host-name>ROUTER1</host-name>
    </system>
</configuration>"""

        mock_connector.execute_command.return_value = xml_config

        config = await juniper_device.get_configuration(config_type="xml")

        assert "<configuration>" in config
        assert "<host-name>ROUTER1</host-name>" in config

    @pytest.mark.asyncio
    async def test_get_configuration_json_format(self, juniper_device, mock_connector):
        """Test getting configuration in JSON format."""
        json_config = '{"configuration": {"system": {"host-name": "ROUTER1"}}}'

        mock_connector.execute_command.return_value = json_config

        config = await juniper_device.get_configuration(config_type="json")

        assert "ROUTER1" in config

    def test_clean_config_output(self, juniper_device, sample_junos_config):
        """Test configuration output cleaning."""
        cleaned = juniper_device.clean_config_output(sample_junos_config)

        assert "## Last commit" not in cleaned
        assert "version 20.2R1.10" in cleaned
        assert "host-name ROUTER1" in cleaned


class TestJuniperConfigurationApplication:
    """Test configuration application."""

    @pytest.mark.asyncio
    async def test_apply_configuration_set_format(self, juniper_device, mock_connector):
        """Test applying configuration in set format."""
        config = """set system host-name ROUTER2
set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24"""

        mock_connector.execute_command.side_effect = [
            "[edit]",  # enter config mode
            "[edit]",  # load set terminal
            "[edit]",  # first set command
            "[edit]",  # second set command
            "[edit]",  # Ctrl-D
            "configuration check succeeds",  # commit check
        ]

        with patch.object(juniper_device, 'validate_config_syntax', return_value={"valid": True}):
            result = await juniper_device.apply_configuration(config)

        assert result is True

    @pytest.mark.asyncio
    async def test_apply_configuration_hierarchical_format(self, juniper_device, mock_connector):
        """Test applying hierarchical configuration."""
        config = """system {
    host-name ROUTER3;
}"""

        mock_connector.execute_command.side_effect = [
            "[edit]",  # enter config mode
            "[edit]",  # load override terminal
            "[edit]",  # config line
            "[edit]",  # Ctrl-D
            "configuration check succeeds",  # commit check
        ]

        with patch.object(juniper_device, 'validate_config_syntax', return_value={"valid": True}):
            result = await juniper_device.apply_configuration(config)

        assert result is True

    @pytest.mark.asyncio
    async def test_apply_configuration_xml_format(self, juniper_device, mock_connector):
        """Test applying XML configuration."""
        config = """<configuration>
    <system>
        <host-name>ROUTER4</host-name>
    </system>
</configuration>"""

        mock_connector.execute_command.side_effect = [
            "[edit]",  # enter config mode
            "[edit]",  # load override terminal
            "load complete",  # XML load
            "configuration check succeeds",  # commit check
        ]

        with patch.object(juniper_device, 'validate_config_syntax', return_value={"valid": True}):
            result = await juniper_device.apply_configuration(config)

        assert result is True

    @pytest.mark.asyncio
    async def test_apply_configuration_validation_failure(self, juniper_device):
        """Test configuration application fails on validation."""
        config = "invalid config"

        with patch.object(juniper_device, 'validate_config_syntax', return_value={
            "valid": False,
            "errors": ["Syntax error"]
        }):
            with pytest.raises(DeviceConfigurationError) as exc_info:
                await juniper_device.apply_configuration(config)

        assert "validation failed" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_apply_configuration_commit_check_failure(self, juniper_device, mock_connector):
        """Test configuration application fails on commit check."""
        config = "set system host-name TEST"

        mock_connector.execute_command.side_effect = [
            "[edit]",  # enter config mode
            "[edit]",  # load set terminal
            "[edit]",  # set command
            "[edit]",  # Ctrl-D
            "error: missing mandatory statement: 'root-authentication'",  # commit check
            "load complete"  # rollback
        ]

        with patch.object(juniper_device, 'validate_config_syntax', return_value={"valid": True}):
            with pytest.raises(DeviceConfigurationError) as exc_info:
                await juniper_device.apply_configuration(config)

        assert "check failed" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_apply_configuration_without_validation(self, juniper_device, mock_connector):
        """Test applying configuration without validation."""
        config = "set system host-name ROUTER5"

        mock_connector.execute_command.side_effect = [
            "[edit]",
            "[edit]",
            "[edit]",
            "[edit]",
            "configuration check succeeds"
        ]

        result = await juniper_device.apply_configuration(config, validate=False)

        assert result is True


class TestJuniperCommitOperations:
    """Test Juniper commit operations."""

    @pytest.mark.asyncio
    async def test_commit_changes_success(self, juniper_device, mock_connector):
        """Test successful commit."""
        juniper_device.config_mode = "private"
        juniper_device.candidate_config = ["set system host-name TEST"]

        mock_connector.execute_command.side_effect = [
            "configuration check succeeds",  # commit check
            "commit complete"  # commit
        ]

        output = await juniper_device.commit_changes()

        assert "commit complete" in output.lower()
        assert juniper_device.candidate_config == []

    @pytest.mark.asyncio
    async def test_commit_changes_with_comment(self, juniper_device, mock_connector):
        """Test commit with comment."""
        juniper_device.config_mode = "private"

        mock_connector.execute_command.side_effect = [
            "configuration check succeeds",
            "commit complete"
        ]

        await juniper_device.commit_changes(comment="Test commit")

        calls = mock_connector.execute_command.call_args_list
        assert 'comment "Test commit"' in calls[1][0][1]

    @pytest.mark.asyncio
    async def test_commit_changes_confirmed(self, juniper_device, mock_connector):
        """Test confirmed commit with auto-rollback."""
        juniper_device.config_mode = "private"

        mock_connector.execute_command.side_effect = [
            "configuration check succeeds",
            "commit complete, configuration will be rolled back in 10 minutes"
        ]

        output = await juniper_device.commit_changes(confirmed=10)

        calls = mock_connector.execute_command.call_args_list
        assert "confirmed 10" in calls[1][0][1]

    @pytest.mark.asyncio
    async def test_commit_changes_check_failure(self, juniper_device, mock_connector):
        """Test commit fails on check error."""
        juniper_device.config_mode = "private"

        mock_connector.execute_command.return_value = "error: missing statement"

        with pytest.raises(DeviceConfigurationError) as exc_info:
            await juniper_device.commit_changes()

        assert "Commit check failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_commit_changes_not_in_config_mode(self, juniper_device):
        """Test commit fails when not in config mode."""
        juniper_device.config_mode = None

        with pytest.raises(DeviceConfigurationError) as exc_info:
            await juniper_device.commit_changes()

        assert "Not in configuration mode" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_save_configuration(self, juniper_device, mock_connector):
        """Test saving configuration (commit)."""
        juniper_device.config_mode = "private"

        mock_connector.execute_command.side_effect = [
            "configuration check succeeds",
            "commit complete"
        ]

        result = await juniper_device.save_configuration()

        assert result is True


class TestJuniperErrorDetection:
    """Test error detection in command output."""

    def test_check_for_errors_error_keyword(self, juniper_device):
        """Test detection of error keyword."""
        output = "error: configuration database locked by 'admin'"

        has_error = juniper_device.check_for_errors(output)

        assert has_error is True

    def test_check_for_errors_syntax_error(self, juniper_device):
        """Test detection of syntax error."""
        output = "syntax error, expecting <identifier>"

        has_error = juniper_device.check_for_errors(output)

        assert has_error is True

    def test_check_for_errors_commit_failed(self, juniper_device):
        """Test detection of commit failure."""
        output = "commit failed: (statements constraint check failed)"

        has_error = juniper_device.check_for_errors(output)

        assert has_error is True

    def test_check_for_errors_multiple_patterns(self, juniper_device):
        """Test detection with various error patterns."""
        error_outputs = [
            "failed: permission denied",
            "invalid input",
            "unknown command",
            "missing argument",
            "configuration check-out failed",
            "Error: cannot delete"
        ]

        for output in error_outputs:
            assert juniper_device.check_for_errors(output) is True

    def test_check_for_errors_no_error(self, juniper_device):
        """Test no error detected in successful output."""
        output = "configuration check succeeds\ncommit complete"

        has_error = juniper_device.check_for_errors(output)

        assert has_error is False


class TestJuniperBackupAndRollback:
    """Test backup and rollback functionality."""

    @pytest.mark.asyncio
    async def test_create_backup(self, juniper_device, mock_connector):
        """Test creating configuration backup."""
        mock_connector.execute_command.side_effect = [
            "set system host-name ROUTER1\nset interfaces ge-0/0/0 unit 0",  # get config
            "Rescue configuration saved",  # rescue save
            "0   2025-01-10 12:00:00 UTC"  # rollback info
        ]

        backup_id = await juniper_device.create_backup()

        assert "router1.example.com" in backup_id
        assert juniper_device.rollback_id is not None

    @pytest.mark.asyncio
    async def test_rollback_to_previous(self, juniper_device, mock_connector):
        """Test rollback to previous configuration."""
        juniper_device.rollback_id = "1"

        mock_connector.execute_command.side_effect = [
            "[edit]",  # enter config mode
            "load complete",  # rollback 1
            "configuration check succeeds",  # commit check
            "commit complete",  # commit
            "Exiting configuration mode"  # exit
        ]

        result = await juniper_device.rollback()

        assert result is True

    @pytest.mark.asyncio
    async def test_rollback_to_rescue(self, juniper_device, mock_connector):
        """Test rollback to rescue configuration."""
        mock_connector.execute_command.side_effect = [
            "[edit]",  # enter config mode
            "load complete",  # load rescue
            "configuration check succeeds",  # commit check
            "commit complete",  # commit
            "Exiting configuration mode"  # exit
        ]

        result = await juniper_device.rollback(backup_id="rescue")

        assert result is True
        calls = mock_connector.execute_command.call_args_list
        assert "load override rescue" in calls[1][0][1]

    @pytest.mark.asyncio
    async def test_rollback_failure(self, juniper_device, mock_connector):
        """Test rollback failure."""
        mock_connector.execute_command.side_effect = [
            "[edit]",  # enter config mode
            "error: rollback 1 not available"  # rollback error
        ]

        with pytest.raises(DeviceConfigurationError) as exc_info:
            await juniper_device.rollback()

        assert "Rollback failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_get_rollback_id(self, juniper_device, mock_connector):
        """Test getting rollback ID."""
        rollback_output = """0   2025-01-10 12:00:00 UTC by admin via cli
1   2025-01-09 10:30:00 UTC by admin via cli
2   2025-01-08 15:45:00 UTC by admin via netconf"""

        mock_connector.execute_command.return_value = rollback_output

        rollback_id = await juniper_device.get_rollback_id()

        assert rollback_id == "0"


class TestJuniperDeviceInfo:
    """Test device information retrieval."""

    @pytest.mark.asyncio
    async def test_get_device_info(self, juniper_device, mock_connector):
        """Test getting device information."""
        version_output = """Hostname: ROUTER1
Model: mx480
Junos: 20.2R1.10"""

        inventory_output = """Chassis   REV 01  JN1234567890"""

        mock_connector.execute_command.side_effect = [
            version_output,
            inventory_output
        ]

        info = await juniper_device.get_device_info()

        assert info['hostname'] == "ROUTER1"
        assert info['model'] == "mx480"
        assert info['version'] == "20.2R1.10"

    def test_parse_hostname(self, juniper_device):
        """Test hostname parsing."""
        output = "Hostname: ROUTER1\nModel: mx480"

        hostname = juniper_device.parse_hostname(output)

        assert hostname == "ROUTER1"

    def test_parse_model(self, juniper_device):
        """Test model parsing."""
        output = "Model: mx960\nJunos: 20.1R1"

        model = juniper_device.parse_model(output)

        assert model == "mx960"

    def test_parse_version(self, juniper_device):
        """Test version parsing."""
        output = "Junos: 21.1R1.11"

        version = juniper_device.parse_version(output)

        assert version == "21.1R1.11"


class TestJuniperInterfaceManagement:
    """Test interface management."""

    @pytest.mark.asyncio
    async def test_get_interfaces(self, juniper_device, mock_connector):
        """Test getting interface information."""
        interface_output = """Interface           Admin Link Proto Local Remote
ge-0/0/0            up    up   inet  192.168.1.1/24
ge-0/0/1            up    down
xe-0/0/0            up    up"""

        detail_output = """Physical interface: ge-0/0/0, Enabled, Physical link is Up
  Description: WAN Connection
  Link-level type: Ethernet, MTU: 1514, Speed: 1000mbps
  Current address: 00:11:22:33:44:55, Hardware address: 00:11:22:33:44:55
  Input packets: 123456
  Output packets: 234567"""

        mock_connector.execute_command.side_effect = [
            interface_output,
            detail_output,
            detail_output,
            detail_output
        ]

        interfaces = await juniper_device.get_interfaces()

        assert len(interfaces) == 3
        assert interfaces[0]['name'] == "ge-0/0/0"
        assert interfaces[0]['admin_status'] == "up"
        assert interfaces[0]['status'] == "up"

    @pytest.mark.asyncio
    async def test_configure_interface(self, juniper_device, mock_connector):
        """Test configuring interface."""
        mock_connector.execute_command.side_effect = [
            "[edit]",  # enter config mode
            "[edit interfaces ge-0/0/0]",  # edit interface
            "[edit interfaces ge-0/0/0]",  # set description
            "[edit interfaces ge-0/0/0]",  # set ip
            "[edit interfaces ge-0/0/0]",  # delete disable
            "[edit]",  # top
            "configuration check succeeds",  # commit check
            "commit complete",  # commit
            "Exiting configuration mode"  # exit
        ]

        result = await juniper_device.configure_interface(
            interface="ge-0/0/0",
            ip_address="10.0.0.1/24",
            description="Test Interface",
            enabled=True
        )

        assert result is True

    def test_parse_interface_details(self, juniper_device):
        """Test parsing interface details."""
        output = """Physical interface: ge-0/0/0
  Description: WAN Link
  Current address: 00:11:22:33:44:55
  MTU: 1514
  Speed: 1000mbps, Duplex: Full-duplex
  Input packets: 1000000
  Output packets: 2000000"""

        details = juniper_device.parse_interface_details(output)

        assert details['description'] == "WAN Link"
        assert details['mac_address'] == "00:11:22:33:44:55"
        assert details['mtu'] == 1514
        assert details['speed'] == "1000mbps"
        assert details['input_packets'] == 1000000
        assert details['output_packets'] == 2000000


class TestJuniperRoutingAndBGP:
    """Test routing and BGP functionality."""

    @pytest.mark.asyncio
    async def test_get_routing_table(self, juniper_device, mock_connector):
        """Test getting routing table."""
        route_output = """10.0.0.0/8          *[Static/5] 00:15:30
                            > to 192.168.1.1 via ge-0/0/0
192.168.1.0/24      *[Direct/0] 1d 2:30:00
                            > via ge-0/0/0.0"""

        mock_connector.execute_command.return_value = route_output

        routes = await juniper_device.get_routing_table()

        assert len(routes) >= 1
        assert routes[0]['network'] == "10.0.0.0/8"
        assert routes[0]['protocol'] == "static"
        assert routes[0]['preference'] == 5

    @pytest.mark.asyncio
    async def test_get_bgp_neighbors(self, juniper_device, mock_connector):
        """Test getting BGP neighbors."""
        bgp_output = """Peer            AS  InPkt  OutPkt  OutQ Flaps Last Up/Dwn  State|#Active/Received/Accepted
192.168.1.1  65001  12345  12345      0     0     1w2d 10 Established"""

        mock_connector.execute_command.return_value = bgp_output

        neighbors = await juniper_device.get_bgp_neighbors()

        assert len(neighbors) >= 1
        assert neighbors[0]['peer'] == "192.168.1.1"
        assert neighbors[0]['as_number'] == 65001
        assert neighbors[0]['uptime'] == "1w2d"

    @pytest.mark.asyncio
    async def test_configure_bgp(self, juniper_device, mock_connector):
        """Test configuring BGP."""
        mock_connector.execute_command.side_effect = [
            "[edit]",  # enter config mode
            "[edit]",  # set AS
            "[edit]",  # set group type
            "[edit]",  # set peer-as
            "[edit]",  # set neighbor
            "[edit]",  # set description
            "configuration check succeeds",  # commit check
            "commit complete",  # commit
            "Exiting configuration mode"  # exit
        ]

        result = await juniper_device.configure_bgp(
            local_as=65001,
            neighbor_ip="192.168.1.2",
            remote_as=65002,
            description="Test Peer"
        )

        assert result is True


class TestJuniperSystemMonitoring:
    """Test system monitoring functionality."""

    @pytest.mark.asyncio
    async def test_get_cpu_usage(self, juniper_device, mock_connector):
        """Test getting CPU usage."""
        cpu_output = """Routing Engine status:
  Slot 0:
    CPU utilization:
      User                 5 percent
      Background          0 percent
      Kernel              3 percent
      Interrupt           0 percent
      Idle               92 percent"""

        mock_connector.execute_command.return_value = cpu_output

        cpu_usage = await juniper_device.get_cpu_usage()

        assert cpu_usage == 8.0  # 100 - 92

    @pytest.mark.asyncio
    async def test_get_memory_usage(self, juniper_device, mock_connector):
        """Test getting memory usage."""
        memory_output = """Memory utilization:
  Total memory: 2048 MB
  Free memory: 512 MB"""

        mock_connector.execute_command.return_value = memory_output

        memory_usage = await juniper_device.get_memory_usage()

        assert memory_usage == 75.0  # (2048-512)/2048 * 100


class TestJuniperUtilities:
    """Test utility functions."""

    def test_get_ping_command(self, juniper_device):
        """Test ping command generation."""
        cmd = juniper_device.get_ping_command("8.8.8.8", 5)

        assert cmd == "ping 8.8.8.8 count 5"

    def test_parse_ping_output(self, juniper_device):
        """Test parsing ping output."""
        output = """PING 8.8.8.8 (8.8.8.8): 56 data bytes
64 bytes from 8.8.8.8: icmp_seq=0 ttl=118 time=10.5 ms
5 packets transmitted, 5 packets received, 0% packet loss
round-trip min/avg/max/stddev = 10.469/11.566/12.686/0.881 ms"""

        result = juniper_device.parse_ping_output(output)

        assert result['success'] is True
        assert result['packets_sent'] == 5
        assert result['packets_received'] == 5
        assert result['packet_loss'] == 0.0
        assert result['min_rtt'] == 10.469
        assert result['avg_rtt'] == 11.566

    def test_get_deprecated_commands(self, juniper_device):
        """Test getting deprecated commands."""
        deprecated = juniper_device.get_deprecated_commands()

        assert isinstance(deprecated, dict)
        assert len(deprecated) > 0


class TestJuniperCommandMappings:
    """Test Juniper command mappings."""

    def test_command_mappings_exist(self, juniper_device):
        """Test all standard command mappings exist."""
        required_commands = [
            "show_config", "show_version", "show_interfaces",
            "show_routes", "show_cpu", "show_memory"
        ]

        for cmd in required_commands:
            assert cmd in juniper_device.COMMANDS

    def test_config_mode_mappings(self, juniper_device):
        """Test configuration mode mappings."""
        assert "private" in juniper_device.CONFIG_MODES
        assert "exclusive" in juniper_device.CONFIG_MODES
        assert juniper_device.CONFIG_MODES["private"] == "configure private"


class TestJuniperEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.mark.asyncio
    async def test_commit_with_warnings(self, juniper_device, mock_connector):
        """Test commit with warnings but no errors."""
        juniper_device.config_mode = "private"

        mock_connector.execute_command.side_effect = [
            "configuration check succeeds\nwarning: statement has no effect",
            "commit complete\nwarning: statement has no effect"
        ]

        output = await juniper_device.commit_changes()

        assert "commit complete" in output.lower()

    @pytest.mark.asyncio
    async def test_configure_interface_with_vlan(self, juniper_device, mock_connector):
        """Test configuring interface with VLAN."""
        mock_connector.execute_command.side_effect = [
            "[edit]",
            "[edit interfaces ge-0/0/0]",
            "[edit interfaces ge-0/0/0]",
            "[edit interfaces ge-0/0/0]",
            "[edit interfaces ge-0/0/0]",
            "[edit interfaces ge-0/0/0]",
            "[edit]",
            "configuration check succeeds",
            "commit complete",
            "Exiting configuration mode"
        ]

        result = await juniper_device.configure_interface(
            interface="ge-0/0/0",
            description="VLAN Interface",
            enabled=True,
            vlan=100
        )

        assert result is True
        calls = mock_connector.execute_command.call_args_list
        assert any("vlan-id 100" in str(call) for call in calls)

    @pytest.mark.asyncio
    async def test_get_vlans(self, juniper_device, mock_connector):
        """Test getting VLAN information."""
        vlan_output = """Name      Tag  Status    Interfaces
default   100  Active    ge-0/0/1.0, ge-0/0/2.0
guest     200  Active    ge-0/0/3.0"""

        mock_connector.execute_command.return_value = vlan_output

        vlans = await juniper_device.get_vlans()

        assert len(vlans) == 2
        assert vlans[0]['name'] == "default"
        assert vlans[0]['id'] == 100
        assert len(vlans[0]['interfaces']) == 2
