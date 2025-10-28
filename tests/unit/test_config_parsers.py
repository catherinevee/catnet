"""
Unit tests for enhanced configuration parsers.

Tests Cisco IOS and Juniper Junos parsers with real configuration examples.
"""
import pytest
from src.core.config_parsers import (
    CiscoIOSParser,
    JuniperJunosParser,
    ParsedConfig,
    ConfigSection
)


class TestCiscoIOSParser:
    """Test Cisco IOS configuration parser."""

    def setup_method(self):
        """Initialize parser for each test."""
        self.parser = CiscoIOSParser()

    def test_parse_hostname(self):
        """Test hostname parsing."""
        config_text = """
hostname Router1
!
        """
        parsed = self.parser.parse(config_text)

        assert parsed.hostname == "Router1"

    def test_parse_interface_basic(self):
        """Test basic interface parsing."""
        config_text = """
interface GigabitEthernet0/1
 description Uplink to Core
 ip address 192.168.1.1 255.255.255.0
 no shutdown
!
        """
        parsed = self.parser.parse(config_text)

        assert len(parsed.interfaces) == 1
        interface = parsed.interfaces[0]
        assert interface['name'] == 'GigabitEthernet0/1'
        assert interface['description'] == 'Uplink to Core'
        assert interface['ip_address'] == '192.168.1.1'
        assert interface['subnet_mask'] == '255.255.255.0'
        assert interface['shutdown'] is False

    def test_parse_interface_shutdown(self):
        """Test shutdown interface parsing."""
        config_text = """
interface GigabitEthernet0/2
 shutdown
!
        """
        parsed = self.parser.parse(config_text)

        assert len(parsed.interfaces) == 1
        assert parsed.interfaces[0]['shutdown'] is True

    def test_parse_interface_switchport(self):
        """Test switchport configuration parsing."""
        config_text = """
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 10
!
interface GigabitEthernet0/2
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30-40
!
        """
        parsed = self.parser.parse(config_text)

        assert len(parsed.interfaces) == 2

        # Access port
        access_port = parsed.interfaces[0]
        assert access_port['switchport_mode'] == 'access'
        assert access_port['access_vlan'] == 10

        # Trunk port
        trunk_port = parsed.interfaces[1]
        assert trunk_port['switchport_mode'] == 'trunk'
        assert 10 in trunk_port['trunk_vlans']
        assert 20 in trunk_port['trunk_vlans']
        assert 35 in trunk_port['trunk_vlans']
        assert 40 in trunk_port['trunk_vlans']

    def test_parse_static_routes(self):
        """Test static route parsing."""
        config_text = """
ip route 0.0.0.0 0.0.0.0 192.168.1.1
ip route 10.0.0.0 255.0.0.0 192.168.1.254
!
        """
        parsed = self.parser.parse(config_text)

        assert 'static_routes' in parsed.routing
        assert len(parsed.routing['static_routes']) == 2

        default_route = parsed.routing['static_routes'][0]
        assert default_route['network'] == '0.0.0.0'
        assert default_route['mask'] == '0.0.0.0'
        assert default_route['next_hop'] == '192.168.1.1'

    def test_parse_router_ospf(self):
        """Test OSPF configuration parsing."""
        config_text = """
router ospf 1
 network 192.168.1.0 0.0.0.255 area 0
 network 10.0.0.0 0.255.255.255 area 1
!
        """
        parsed = self.parser.parse(config_text)

        assert 'protocols' in parsed.routing
        assert len(parsed.routing['protocols']) == 1

        ospf = parsed.routing['protocols'][0]
        assert ospf['type'] == 'ospf'
        assert ospf['process_id'] == '1'
        assert len(ospf['networks']) == 2
        assert ospf['networks'][0]['network'] == '192.168.1.0'
        assert ospf['networks'][0]['area'] == '0'

    def test_parse_router_bgp(self):
        """Test BGP configuration parsing."""
        config_text = """
router bgp 65001
 neighbor 192.168.1.1
 neighbor 192.168.1.2
!
        """
        parsed = self.parser.parse(config_text)

        bgp = parsed.routing['protocols'][0]
        assert bgp['type'] == 'bgp'
        assert bgp['process_id'] == '65001'
        assert len(bgp['neighbors']) == 2

    def test_parse_access_list(self):
        """Test access-list parsing."""
        config_text = """
access-list 100 permit ip any any
access-list 100 deny ip 10.0.0.0 0.255.255.255 any
ip access-list extended BLOCK_TRAFFIC
!
        """
        parsed = self.parser.parse(config_text)

        assert len(parsed.access_lists) == 2
        assert parsed.access_lists[0]['name'] == '100'
        assert len(parsed.access_lists[0]['entries']) == 2
        assert parsed.access_lists[1]['name'] == 'BLOCK_TRAFFIC'

    def test_parse_multiple_interfaces(self):
        """Test parsing multiple interfaces."""
        config_text = """
interface GigabitEthernet0/1
 ip address 192.168.1.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/2
 ip address 192.168.2.1 255.255.255.0
 no shutdown
!
interface Loopback0
 ip address 10.0.0.1 255.255.255.255
!
        """
        parsed = self.parser.parse(config_text)

        assert len(parsed.interfaces) == 3
        assert parsed.interfaces[0]['name'] == 'GigabitEthernet0/1'
        assert parsed.interfaces[1]['name'] == 'GigabitEthernet0/2'
        assert parsed.interfaces[2]['name'] == 'Loopback0'

    def test_parse_port_channel(self):
        """Test port-channel configuration parsing."""
        config_text = """
interface GigabitEthernet0/1
 channel-group 1 mode active
!
interface Port-channel1
 switchport mode trunk
!
        """
        parsed = self.parser.parse(config_text)

        assert len(parsed.interfaces) == 2
        assert parsed.interfaces[0]['channel_group'] == 1
        assert parsed.interfaces[1]['name'] == 'Port-channel1'

    def test_parse_vlan_list(self):
        """Test VLAN list parsing."""
        vlans = self.parser._parse_vlan_list("1-10,20,30-35")

        assert 1 in vlans
        assert 10 in vlans
        assert 20 in vlans
        assert 30 in vlans
        assert 35 in vlans
        assert 11 not in vlans
        assert len(vlans) == 17  # 1-10 (10) + 20 (1) + 30-35 (6)

    def test_parse_empty_config(self):
        """Test parsing empty configuration."""
        parsed = self.parser.parse("")

        assert parsed.hostname is None
        assert len(parsed.interfaces) == 0
        assert len(parsed.access_lists) == 0

    def test_parse_comments_only(self):
        """Test parsing configuration with only comments."""
        config_text = """
! This is a comment
! Another comment
        """
        parsed = self.parser.parse(config_text)

        assert parsed.hostname is None
        assert len(parsed.interfaces) == 0


class TestJuniperJunosParser:
    """Test Juniper Junos configuration parser."""

    def setup_method(self):
        """Initialize parser for each test."""
        self.parser = JuniperJunosParser()

    def test_parse_hostname_set_format(self):
        """Test hostname parsing in set format."""
        config_text = """
set system host-name JuniperRouter1
        """
        parsed = self.parser.parse(config_text)

        assert parsed.hostname == "JuniperRouter1"

    def test_parse_interface_set_format(self):
        """Test interface parsing in set format."""
        config_text = """
set interfaces ge-0/0/0 unit 0 family inet address 192.168.1.1/24
set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/30
        """
        parsed = self.parser.parse(config_text)

        assert len(parsed.interfaces) == 2
        assert parsed.interfaces[0]['name'] == 'ge-0/0/0'
        assert parsed.interfaces[0]['units']['0']['address'] == '192.168.1.1/24'

    def test_parse_multiple_interface_units(self):
        """Test parsing interface with multiple units."""
        config_text = """
set interfaces ge-0/0/0 unit 0 family inet address 192.168.1.1/24
set interfaces ge-0/0/0 unit 100 family inet address 10.0.0.1/24
        """
        parsed = self.parser.parse(config_text)

        assert len(parsed.interfaces) == 1
        interface = parsed.interfaces[0]
        assert '0' in interface['units']
        assert '100' in interface['units']
        assert interface['units']['0']['address'] == '192.168.1.1/24'
        assert interface['units']['100']['address'] == '10.0.0.1/24'

    def test_detect_set_format(self):
        """Test detection of set command format."""
        config_text = """
set system host-name Router1
set interfaces ge-0/0/0 description Uplink
        """
        parsed = self.parser.parse(config_text)

        # Should successfully parse set format
        assert parsed.hostname == "Router1"
        assert len(parsed.interfaces) == 1

    def test_detect_hierarchical_format(self):
        """Test detection of hierarchical format."""
        config_text = """
system {
    host-name Router1;
}
        """
        parsed = self.parser.parse(config_text)

        # Should detect hierarchical format
        assert parsed.hostname == "Router1"
        assert len(parsed.warnings) > 0  # Should warn about basic parsing

    def test_parse_empty_config(self):
        """Test parsing empty Junos configuration."""
        parsed = self.parser.parse("")

        assert parsed.hostname is None
        assert len(parsed.interfaces) == 0


class TestParsedConfig:
    """Test ParsedConfig dataclass."""

    def test_empty_parsed_config(self):
        """Test empty ParsedConfig initialization."""
        config = ParsedConfig()

        assert config.raw_lines == []
        assert config.sections == {}
        assert config.hostname is None
        assert config.interfaces == []
        assert config.routing == {}
        assert config.access_lists == []
        assert config.errors == []
        assert config.warnings == []

    def test_parsed_config_with_data(self):
        """Test ParsedConfig with data."""
        config = ParsedConfig(
            hostname="TestRouter",
            interfaces=[
                {'name': 'GigabitEthernet0/1', 'ip_address': '192.168.1.1'}
            ],
            errors=['Test error'],
            warnings=['Test warning']
        )

        assert config.hostname == "TestRouter"
        assert len(config.interfaces) == 1
        assert len(config.errors) == 1
        assert len(config.warnings) == 1


@pytest.mark.integration
class TestConfigParserIntegration:
    """Integration tests with real-world configurations."""

    def test_cisco_complete_config(self):
        """Test parsing complete Cisco configuration."""
        config_text = """
!
version 15.2
!
hostname CoreRouter
!
interface GigabitEthernet0/0
 description Uplink to ISP
 ip address 203.0.113.1 255.255.255.252
 no shutdown
!
interface GigabitEthernet0/1
 description LAN Interface
 ip address 192.168.1.1 255.255.255.0
 no shutdown
!
interface Loopback0
 ip address 10.0.0.1 255.255.255.255
!
router ospf 1
 network 192.168.1.0 0.0.0.255 area 0
 network 10.0.0.1 0.0.0.0 area 0
!
ip route 0.0.0.0 0.0.0.0 203.0.113.2
!
access-list 100 permit ip 192.168.1.0 0.0.0.255 any
!
end
        """

        parser = CiscoIOSParser()
        parsed = parser.parse(config_text)

        # Verify all major components
        assert parsed.hostname == "CoreRouter"
        assert len(parsed.interfaces) == 3
        assert len(parsed.routing['static_routes']) == 1
        assert len(parsed.routing['protocols']) == 1
        assert len(parsed.access_lists) == 1

    def test_juniper_complete_config(self):
        """Test parsing complete Juniper configuration."""
        config_text = """
set system host-name CoreSwitch
set interfaces ge-0/0/0 description "Uplink"
set interfaces ge-0/0/0 unit 0 family inet address 192.168.1.1/24
set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/30
set interfaces lo0 unit 0 family inet address 10.255.255.1/32
        """

        parser = JuniperJunosParser()
        parsed = parser.parse(config_text)

        assert parsed.hostname == "CoreSwitch"
        assert len(parsed.interfaces) == 3
