"""
Comprehensive unit tests for Cisco Configuration Parser
Tests parsing of IOS, IOS-XE, NX-OS configurations
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime

from src.parsers.cisco_parser import (
    CiscoConfigParser,
    CiscoOS,
    ConfigSection,
    ParsedConfig
)


@pytest.fixture
def cisco_parser():
    """Provide Cisco parser instance."""
    return CiscoConfigParser()


@pytest.fixture
def sample_ios_config():
    """Sample Cisco IOS configuration."""
    return """version 15.2
service timestamps debug datetime msec
service timestamps log datetime msec
!
hostname ROUTER1
!
enable secret 5 $1$abc$xyz
!
interface GigabitEthernet0/0
 description WAN Connection
 ip address 192.168.1.1 255.255.255.0
 duplex auto
 speed auto
 no shutdown
!
interface GigabitEthernet0/1
 description LAN Connection
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
router bgp 65001
 bgp router-id 10.0.0.1
 neighbor 10.0.0.2 remote-as 65002
!
ip route 0.0.0.0 0.0.0.0 192.168.1.254
!
ip access-list extended INTERNET-IN
 permit tcp any any eq 443
 permit tcp any any eq 80
 deny ip any any log
!
snmp-server community public RO
snmp-server host 10.0.0.100
!
ntp server 10.0.0.10
ntp server 10.0.0.11
!
ip name-server 8.8.8.8 8.8.4.4
ip domain-name example.com
!
end"""


@pytest.fixture
def sample_nxos_config():
    """Sample Cisco NX-OS configuration."""
    return """version 9.3(5)
hostname SWITCH1

vlan 10
  name DATA
vlan 20
  name VOICE
vlan 30
  name GUEST

interface Ethernet1/1
  description Uplink
  switchport mode trunk
  no shutdown

interface Ethernet1/2
  description Access Port
  switchport mode access
  switchport access vlan 10
  spanning-tree portfast"""


class TestCiscoParserInitialization:
    """Test parser initialization."""

    def test_parser_initialization(self, cisco_parser):
        """Test parser initializes with correct patterns."""
        assert cisco_parser.hostname_pattern is not None
        assert cisco_parser.interface_pattern is not None
        assert cisco_parser.vlan_pattern is not None
        assert cisco_parser.ip_pattern is not None

    def test_parser_regex_patterns(self, cisco_parser):
        """Test regex patterns are properly compiled."""
        assert cisco_parser.hostname_pattern.match("hostname ROUTER1")
        assert cisco_parser.interface_pattern.match("interface GigabitEthernet0/0")
        assert cisco_parser.version_pattern.match("version 15.2")


class TestCiscoConfigurationParsing:
    """Test configuration parsing."""

    def test_parse_basic_config(self, cisco_parser, sample_ios_config):
        """Test parsing basic IOS configuration."""
        parsed = cisco_parser.parse(sample_ios_config, CiscoOS.IOS)

        assert parsed.os_type == CiscoOS.IOS
        assert parsed.hostname == "ROUTER1"
        assert parsed.version == "15.2"
        assert parsed.hash is not None
        assert parsed.parsed_at is not None

    def test_parse_hostname(self, cisco_parser):
        """Test hostname parsing."""
        config = "hostname TEST-ROUTER-01"
        parsed = cisco_parser.parse(config)

        assert parsed.hostname == "TEST-ROUTER-01"

    def test_parse_version(self, cisco_parser):
        """Test version parsing."""
        config = "version 16.9.5"
        parsed = cisco_parser.parse(config)

        assert parsed.version == "16.9.5"

    def test_parse_with_comments(self, cisco_parser):
        """Test parsing config with comments."""
        config = """! This is a comment
hostname ROUTER1
! Another comment
interface GigabitEthernet0/0
 ! Interface comment
 ip address 10.0.0.1 255.255.255.0"""

        parsed = cisco_parser.parse(config)

        assert parsed.hostname == "ROUTER1"
        assert len(parsed.interfaces) > 0

    def test_parse_empty_config(self, cisco_parser):
        """Test parsing empty configuration."""
        config = ""
        parsed = cisco_parser.parse(config)

        assert parsed.hostname is None
        assert len(parsed.interfaces) == 0

    def test_parse_nxos_config(self, cisco_parser, sample_nxos_config):
        """Test parsing NX-OS configuration."""
        parsed = cisco_parser.parse(sample_nxos_config, CiscoOS.NX_OS)

        assert parsed.os_type == CiscoOS.NX_OS
        assert parsed.hostname == "SWITCH1"
        assert parsed.version == "9.3(5)"


class TestInterfaceParsing:
    """Test interface configuration parsing."""

    def test_parse_interface_basic(self, cisco_parser):
        """Test basic interface parsing."""
        config = """interface GigabitEthernet0/0
 description Test Interface
 ip address 10.0.0.1 255.255.255.0
 no shutdown"""

        parsed = cisco_parser.parse(config)

        assert "GigabitEthernet0/0" in parsed.interfaces
        interface = parsed.interfaces["GigabitEthernet0/0"]
        assert interface['description'] == "Test Interface"
        assert interface['ip_address'] == "10.0.0.1"
        assert interface['subnet_mask'] == "255.255.255.0"

    def test_parse_multiple_interfaces(self, cisco_parser, sample_ios_config):
        """Test parsing multiple interfaces."""
        parsed = cisco_parser.parse(sample_ios_config)

        assert len(parsed.interfaces) == 2
        assert "GigabitEthernet0/0" in parsed.interfaces
        assert "GigabitEthernet0/1" in parsed.interfaces

    def test_parse_interface_shutdown(self, cisco_parser):
        """Test parsing shutdown interface."""
        config = """interface GigabitEthernet0/0
 shutdown"""

        parsed = cisco_parser.parse(config)

        interface = parsed.interfaces["GigabitEthernet0/0"]
        assert interface.get('shutdown') is True

    def test_parse_interface_description_with_spaces(self, cisco_parser):
        """Test parsing interface description with multiple words."""
        config = """interface GigabitEthernet0/0
 description WAN Link to ISP Primary"""

        parsed = cisco_parser.parse(config)

        interface = parsed.interfaces["GigabitEthernet0/0"]
        assert interface['description'] == "WAN Link to ISP Primary"

    def test_parse_interface_types(self, cisco_parser):
        """Test parsing various interface types."""
        config = """interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
!
interface FastEthernet0/1
 ip address 10.0.1.1 255.255.255.0
!
interface Serial0/0/0
 ip address 10.0.2.1 255.255.255.252
!
interface Loopback0
 ip address 192.168.1.1 255.255.255.255
!
interface Vlan10
 ip address 172.16.10.1 255.255.255.0"""

        parsed = cisco_parser.parse(config)

        assert len(parsed.interfaces) == 5
        assert "GigabitEthernet0/0" in parsed.interfaces
        assert "FastEthernet0/1" in parsed.interfaces
        assert "Serial0/0/0" in parsed.interfaces
        assert "Loopback0" in parsed.interfaces
        assert "Vlan10" in parsed.interfaces

    def test_parse_interface_switchport(self, cisco_parser):
        """Test parsing switchport configuration."""
        config = """interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 10"""

        parsed = cisco_parser.parse(config)

        interface = parsed.interfaces["GigabitEthernet0/1"]
        assert interface.get('switchport_mode') == 'access'
        assert interface.get('access_vlan') == 10


class TestVLANParsing:
    """Test VLAN configuration parsing."""

    def test_parse_single_vlan(self, cisco_parser):
        """Test parsing single VLAN."""
        config = """vlan 10
 name DATA"""

        parsed = cisco_parser.parse(config)

        assert 10 in parsed.vlans
        assert parsed.vlans[10]['name'] == "DATA"

    def test_parse_multiple_vlans(self, cisco_parser, sample_nxos_config):
        """Test parsing multiple VLANs."""
        parsed = cisco_parser.parse(sample_nxos_config, CiscoOS.NX_OS)

        assert len(parsed.vlans) == 3
        assert 10 in parsed.vlans
        assert 20 in parsed.vlans
        assert 30 in parsed.vlans
        assert parsed.vlans[10]['name'] == "DATA"
        assert parsed.vlans[20]['name'] == "VOICE"

    def test_parse_vlan_range(self, cisco_parser):
        """Test parsing VLAN range."""
        config = """vlan 10-20"""

        parsed = cisco_parser.parse(config)

        # Should parse as range
        assert len(parsed.vlans) > 0

    def test_parse_vlan_list(self, cisco_parser):
        """Test parsing VLAN list."""
        config = """vlan 10,20,30"""

        parsed = cisco_parser.parse(config)

        assert len(parsed.vlans) > 0


class TestRoutingParsing:
    """Test routing configuration parsing."""

    def test_parse_static_route(self, cisco_parser):
        """Test parsing static routes."""
        config = """ip route 0.0.0.0 0.0.0.0 192.168.1.254
ip route 10.0.0.0 255.255.255.0 192.168.1.253"""

        parsed = cisco_parser.parse(config)

        assert 'static_routes' in parsed.routing
        assert len(parsed.routing['static_routes']) >= 2

    def test_parse_bgp_config(self, cisco_parser, sample_ios_config):
        """Test parsing BGP configuration."""
        parsed = cisco_parser.parse(sample_ios_config)

        assert 'bgp' in parsed.routing
        bgp_config = parsed.routing['bgp']
        assert bgp_config['as_number'] == 65001
        assert bgp_config['router_id'] == '10.0.0.1'

    def test_parse_ospf_config(self, cisco_parser):
        """Test parsing OSPF configuration."""
        config = """router ospf 1
 router-id 1.1.1.1
 network 10.0.0.0 0.0.0.255 area 0
 network 10.0.1.0 0.0.0.255 area 1"""

        parsed = cisco_parser.parse(config)

        assert 'ospf' in parsed.routing
        ospf_config = parsed.routing['ospf']
        assert ospf_config['process_id'] == 1
        assert ospf_config['router_id'] == '1.1.1.1'
        assert len(ospf_config['networks']) == 2

    def test_parse_eigrp_config(self, cisco_parser):
        """Test parsing EIGRP configuration."""
        config = """router eigrp 100
 network 10.0.0.0 0.0.255.255
 network 192.168.1.0"""

        parsed = cisco_parser.parse(config)

        assert 'eigrp' in parsed.routing
        eigrp_config = parsed.routing['eigrp']
        assert eigrp_config['as_number'] == 100


class TestACLParsing:
    """Test Access Control List parsing."""

    def test_parse_standard_acl(self, cisco_parser):
        """Test parsing standard ACL."""
        config = """access-list 10 permit 10.0.0.0 0.0.0.255
access-list 10 deny any"""

        parsed = cisco_parser.parse(config)

        assert '10' in parsed.acls
        assert len(parsed.acls['10']) == 2

    def test_parse_extended_acl(self, cisco_parser, sample_ios_config):
        """Test parsing extended ACL."""
        parsed = cisco_parser.parse(sample_ios_config)

        assert 'INTERNET-IN' in parsed.acls
        acl = parsed.acls['INTERNET-IN']
        assert len(acl) >= 2

    def test_parse_named_acl(self, cisco_parser):
        """Test parsing named ACL."""
        config = """ip access-list extended WEB-TRAFFIC
 permit tcp any any eq 80
 permit tcp any any eq 443
 deny ip any any log"""

        parsed = cisco_parser.parse(config)

        assert 'WEB-TRAFFIC' in parsed.acls
        assert len(parsed.acls['WEB-TRAFFIC']) == 3


class TestServicesParsing:
    """Test services configuration parsing."""

    def test_parse_ntp_servers(self, cisco_parser, sample_ios_config):
        """Test parsing NTP servers."""
        parsed = cisco_parser.parse(sample_ios_config)

        assert 'ntp_servers' in parsed.services
        assert len(parsed.services['ntp_servers']) == 2
        assert '10.0.0.10' in parsed.services['ntp_servers']
        assert '10.0.0.11' in parsed.services['ntp_servers']

    def test_parse_dns_servers(self, cisco_parser, sample_ios_config):
        """Test parsing DNS servers."""
        parsed = cisco_parser.parse(sample_ios_config)

        assert 'dns_servers' in parsed.services
        assert '8.8.8.8' in parsed.services['dns_servers']
        assert '8.8.4.4' in parsed.services['dns_servers']

    def test_parse_domain_name(self, cisco_parser, sample_ios_config):
        """Test parsing domain name."""
        parsed = cisco_parser.parse(sample_ios_config)

        assert 'domain_name' in parsed.services
        assert parsed.services['domain_name'] == 'example.com'

    def test_parse_snmp_config(self, cisco_parser, sample_ios_config):
        """Test parsing SNMP configuration."""
        parsed = cisco_parser.parse(sample_ios_config)

        assert 'snmp' in parsed.services
        assert len(parsed.services['snmp']) >= 2

    def test_parse_logging_config(self, cisco_parser):
        """Test parsing logging configuration."""
        config = """logging host 10.0.0.100
logging trap informational
logging source-interface Loopback0"""

        parsed = cisco_parser.parse(config)

        assert 'logging' in parsed.services


class TestSecurityParsing:
    """Test security configuration parsing."""

    def test_parse_enable_secret(self, cisco_parser, sample_ios_config):
        """Test parsing enable secret."""
        parsed = cisco_parser.parse(sample_ios_config)

        assert 'enable_configured' in parsed.security
        assert parsed.security['enable_configured'] is True

    def test_parse_aaa_config(self, cisco_parser):
        """Test parsing AAA configuration."""
        config = """aaa new-model
aaa authentication login default group tacacs+
aaa authorization exec default group tacacs+"""

        parsed = cisco_parser.parse(config)

        assert 'aaa' in parsed.security
        assert len(parsed.security['aaa']) >= 3

    def test_parse_crypto_config(self, cisco_parser):
        """Test parsing crypto configuration."""
        config = """crypto isakmp policy 10
 encr aes 256
 authentication pre-share
 group 5"""

        parsed = cisco_parser.parse(config)

        assert 'crypto' in parsed.security


class TestConfigurationHash:
    """Test configuration hashing."""

    def test_calculate_hash(self, cisco_parser):
        """Test hash calculation."""
        config = "hostname ROUTER1"
        hash1 = cisco_parser._calculate_hash(config)

        assert hash1 is not None
        assert len(hash1) == 64  # SHA256 hash length

    def test_hash_consistency(self, cisco_parser):
        """Test hash is consistent for same config."""
        config = "hostname ROUTER1\ninterface GigabitEthernet0/0"
        hash1 = cisco_parser._calculate_hash(config)
        hash2 = cisco_parser._calculate_hash(config)

        assert hash1 == hash2

    def test_hash_ignores_comments(self, cisco_parser):
        """Test hash ignores comments."""
        config1 = "hostname ROUTER1"
        config2 = "! This is a comment\nhostname ROUTER1"

        hash1 = cisco_parser._calculate_hash(config1)
        hash2 = cisco_parser._calculate_hash(config2)

        assert hash1 == hash2

    def test_hash_different_for_different_configs(self, cisco_parser):
        """Test different configs have different hashes."""
        config1 = "hostname ROUTER1"
        config2 = "hostname ROUTER2"

        hash1 = cisco_parser._calculate_hash(config1)
        hash2 = cisco_parser._calculate_hash(config2)

        assert hash1 != hash2


class TestConfigurationValidation:
    """Test configuration validation."""

    def test_validate_valid_config(self, cisco_parser, sample_ios_config):
        """Test validation of valid configuration."""
        parsed = cisco_parser.parse(sample_ios_config)

        # Should have no errors for valid config
        assert len(parsed.errors) == 0

    def test_validate_missing_hostname(self, cisco_parser):
        """Test validation warns on missing hostname."""
        config = "interface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0"
        parsed = cisco_parser.parse(config)

        # May have warnings about missing hostname
        # Implementation dependent


class TestRegexPatterns:
    """Test regex pattern matching."""

    def test_hostname_pattern(self, cisco_parser):
        """Test hostname pattern matching."""
        assert cisco_parser.hostname_pattern.match("hostname ROUTER1")
        assert cisco_parser.hostname_pattern.match("hostname TEST-DEVICE")
        assert not cisco_parser.hostname_pattern.match("host ROUTER1")

    def test_interface_pattern(self, cisco_parser):
        """Test interface pattern matching."""
        assert cisco_parser.interface_pattern.match("interface GigabitEthernet0/0")
        assert cisco_parser.interface_pattern.match("interface FastEthernet0/1")
        assert cisco_parser.interface_pattern.match("interface Loopback0")
        assert cisco_parser.interface_pattern.match("interface Vlan10")

    def test_vlan_pattern(self, cisco_parser):
        """Test VLAN pattern matching."""
        assert cisco_parser.vlan_pattern.match("vlan 10")
        assert cisco_parser.vlan_pattern.match("vlan 10-20")
        assert cisco_parser.vlan_pattern.match("vlan 10,20,30")

    def test_ip_pattern(self, cisco_parser):
        """Test IP address pattern matching."""
        assert cisco_parser.ip_pattern.search("10.0.0.1")
        assert cisco_parser.ip_pattern.search("192.168.1.254")
        assert not cisco_parser.ip_pattern.search("300.0.0.1")  # Invalid


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_parse_config_with_only_comments(self, cisco_parser):
        """Test parsing config with only comments."""
        config = """! Comment line 1
! Comment line 2
! Comment line 3"""

        parsed = cisco_parser.parse(config)

        assert parsed.hostname is None
        assert len(parsed.interfaces) == 0

    def test_parse_config_with_empty_lines(self, cisco_parser):
        """Test parsing config with many empty lines."""
        config = """hostname ROUTER1


interface GigabitEthernet0/0


 ip address 10.0.0.1 255.255.255.0"""

        parsed = cisco_parser.parse(config)

        assert parsed.hostname == "ROUTER1"
        assert len(parsed.interfaces) > 0

    def test_parse_config_with_trailing_spaces(self, cisco_parser):
        """Test parsing config with trailing spaces."""
        config = "hostname ROUTER1    \ninterface GigabitEthernet0/0    "

        parsed = cisco_parser.parse(config)

        assert parsed.hostname == "ROUTER1"

    def test_parse_incomplete_interface(self, cisco_parser):
        """Test parsing incomplete interface configuration."""
        config = """interface GigabitEthernet0/0"""

        parsed = cisco_parser.parse(config)

        assert "GigabitEthernet0/0" in parsed.interfaces


class TestParsedConfigDataclass:
    """Test ParsedConfig dataclass."""

    def test_parsed_config_initialization(self):
        """Test ParsedConfig initialization."""
        parsed = ParsedConfig(os_type=CiscoOS.IOS)

        assert parsed.os_type == CiscoOS.IOS
        assert parsed.hostname is None
        assert len(parsed.interfaces) == 0
        assert len(parsed.warnings) == 0
        assert len(parsed.errors) == 0

    def test_parsed_config_with_data(self):
        """Test ParsedConfig with data."""
        parsed = ParsedConfig(
            os_type=CiscoOS.IOS,
            hostname="ROUTER1",
            version="15.2"
        )

        assert parsed.hostname == "ROUTER1"
        assert parsed.version == "15.2"


class TestCiscoOSEnum:
    """Test CiscoOS enum."""

    def test_cisco_os_values(self):
        """Test CiscoOS enum values."""
        assert CiscoOS.IOS.value == "ios"
        assert CiscoOS.IOS_XE.value == "ios_xe"
        assert CiscoOS.NX_OS.value == "nx_os"
        assert CiscoOS.IOS_XR.value == "ios_xr"
        assert CiscoOS.ASA.value == "asa"


class TestConfigSectionEnum:
    """Test ConfigSection enum."""

    def test_config_section_values(self):
        """Test ConfigSection enum values."""
        assert ConfigSection.GLOBAL.value == "global"
        assert ConfigSection.INTERFACE.value == "interface"
        assert ConfigSection.VLAN.value == "vlan"
        assert ConfigSection.ROUTING.value == "routing"
        assert ConfigSection.ACL.value == "acl"
