"""
CatNet Configuration Parser Factory

Factory for creating vendor-specific configuration parsers
"""

from enum import Enum
from typing import Union, Optional, Dict, Any, List, Tuple
import structlog

from .cisco_parser import CiscoConfigParser, CiscoOS, ParsedConfig as ParsedCiscoConfig
from .juniper_parser import JuniperConfigParser, JunosFormat, ParsedJunosConfig

logger = structlog.get_logger()


class VendorType(Enum):
    """Supported network device vendors"""
    CISCO = "cisco"
    JUNIPER = "juniper"
    ARISTA = "arista"
    FORTINET = "fortinet"
    PALOALTO = "paloalto"
    CHECKPOINT = "checkpoint"
    F5 = "f5"
    CITRIX = "citrix"


class ConfigParserFactory:
    """Factory for creating configuration parsers"""

    @staticmethod
    def create_parser(vendor: VendorType):
        """
        Create parser for specific vendor

        Args:
            vendor: Vendor type

        Returns:
            Configuration parser instance
        """
        if vendor == VendorType.CISCO:
            return CiscoConfigParser()
        elif vendor == VendorType.JUNIPER:
            return JuniperConfigParser()
        else:
            raise ValueError(f"Unsupported vendor: {vendor}")

    @staticmethod
    def parse_config(
        config: str,
        vendor: VendorType,
        **kwargs
    ) -> Union[ParsedCiscoConfig, ParsedJunosConfig]:
        """
        Parse configuration for specific vendor

        Args:
            config: Raw configuration text
            vendor: Vendor type
            **kwargs: Additional vendor-specific parameters

        Returns:
            Parsed configuration object
        """
        parser = ConfigParserFactory.create_parser(vendor)

        if vendor == VendorType.CISCO:
            os_type = kwargs.get('os_type', CiscoOS.IOS)
            return parser.parse(config, os_type)
        elif vendor == VendorType.JUNIPER:
            return parser.parse(config)
        else:
            raise ValueError(f"Unsupported vendor: {vendor}")

    @staticmethod
    def validate_syntax(
        config: str,
        vendor: VendorType,
        **kwargs
    ) -> Tuple[bool, List[str]]:
        """
        Validate configuration syntax

        Args:
            config: Configuration to validate
            vendor: Vendor type
            **kwargs: Additional vendor-specific parameters

        Returns:
            Tuple of (is_valid, errors)
        """
        parser = ConfigParserFactory.create_parser(vendor)

        if vendor == VendorType.CISCO:
            os_type = kwargs.get('os_type', CiscoOS.IOS)
            return parser.validate_syntax(config, os_type)
        elif vendor == VendorType.JUNIPER:
            return parser.validate_syntax(config)
        else:
            raise ValueError(f"Unsupported vendor: {vendor}")

    @staticmethod
    def generate_diff(
        old_config: str,
        new_config: str,
        vendor: VendorType
    ) -> Dict[str, Any]:
        """
        Generate diff between configurations

        Args:
            old_config: Previous configuration
            new_config: New configuration
            vendor: Vendor type

        Returns:
            Dictionary with diff information
        """
        parser = ConfigParserFactory.create_parser(vendor)
        return parser.generate_diff(old_config, new_config)

    @staticmethod
    def detect_vendor(config: str) -> Optional[VendorType]:
        """
        Attempt to detect vendor from configuration

        Args:
            config: Configuration text

        Returns:
            Detected vendor type or None
        """
        config_lower = config.lower()

        # Cisco indicators
        cisco_indicators = [
            'hostname ',
            'interface gigabitethernet',
            'interface fastethernet',
            'interface vlan',
            'router ospf',
            'router eigrp',
            'ip route ',
            'access-list ',
            'switchport mode',
            'spanning-tree mode',
            'vtp mode',
            'crypto isakmp',
            'aaa new-model'
        ]

        # Juniper indicators
        juniper_indicators = [
            'set system host-name',
            'set interfaces',
            'set routing-options',
            'set protocols',
            'set security',
            'set firewall',
            'set vlans',
            'set policy-options',
            'set class-of-service',
            'delete ',
            'deactivate ',
            'routing-instances',
            'forwarding-options'
        ]

        # Count indicators
        cisco_count = sum(1 for indicator in cisco_indicators if indicator in config_lower)
        juniper_count = sum(1 for indicator in juniper_indicators if indicator in config_lower)

        # Determine vendor based on indicator count
        if cisco_count > juniper_count and cisco_count > 0:
            return VendorType.CISCO
        elif juniper_count > cisco_count and juniper_count > 0:
            return VendorType.JUNIPER

        # Check for XML format (likely Juniper)
        if config.strip().startswith('<?xml') or '<configuration>' in config[:1000]:
            return VendorType.JUNIPER

        # Check for JSON format with Juniper structure
        if config.strip().startswith('{') and '"configuration"' in config[:1000]:
            return VendorType.JUNIPER

        return None

    @staticmethod
    def detect_os_type(config: str, vendor: VendorType) -> Optional[Union[CiscoOS, str]]:
        """
        Detect OS type for specific vendor

        Args:
            config: Configuration text
            vendor: Vendor type

        Returns:
            OS type or None
        """
        if vendor == VendorType.CISCO:
            config_lower = config.lower()

            # Check for NX-OS
            if 'nx-os' in config_lower or 'nexus' in config_lower:
                return CiscoOS.NX_OS

            # Check for IOS-XR
            if 'ios-xr' in config_lower or 'ios xr' in config_lower:
                return CiscoOS.IOS_XR

            # Check for ASA
            if 'asa version' in config_lower or 'firewall mode' in config_lower:
                return CiscoOS.ASA

            # Check for IOS-XE
            if 'ios-xe' in config_lower or 'ios xe' in config_lower:
                return CiscoOS.IOS_XE

            # Default to IOS
            return CiscoOS.IOS

        return None

    @staticmethod
    def convert_to_json(
        config: str,
        vendor: VendorType,
        **kwargs
    ) -> str:
        """
        Convert configuration to JSON format

        Args:
            config: Raw configuration text
            vendor: Vendor type
            **kwargs: Additional vendor-specific parameters

        Returns:
            JSON representation of configuration
        """
        parsed = ConfigParserFactory.parse_config(config, vendor, **kwargs)
        parser = ConfigParserFactory.create_parser(vendor)
        return parser.to_json(parsed)

    @staticmethod
    def normalize_config(config: str, vendor: VendorType) -> str:
        """
        Normalize configuration format

        Args:
            config: Raw configuration
            vendor: Vendor type

        Returns:
            Normalized configuration
        """
        lines = config.strip().split('\n')
        normalized = []

        for line in lines:
            # Remove trailing whitespace
            line = line.rstrip()

            # Skip empty lines and comments
            if not line:
                continue

            if vendor == VendorType.CISCO:
                # Skip Cisco comments
                if line.strip().startswith('!'):
                    continue
            elif vendor == VendorType.JUNIPER:
                # Skip Juniper comments
                if line.strip().startswith('#'):
                    continue

            normalized.append(line)

        return '\n'.join(normalized)

    @staticmethod
    def extract_critical_configs(
        config: str,
        vendor: VendorType
    ) -> Dict[str, Any]:
        """
        Extract critical configuration elements

        Args:
            config: Configuration text
            vendor: Vendor type

        Returns:
            Dictionary of critical configuration elements
        """
        critical = {
            'passwords': [],
            'crypto_keys': [],
            'snmp_communities': [],
            'radius_servers': [],
            'tacacs_servers': [],
            'management_ips': [],
            'acls': [],
            'nat_rules': []
        }

        lines = config.strip().split('\n')

        for line in lines:
            line = line.strip()

            # Skip comments
            if not line or line.startswith('!') or line.startswith('#'):
                continue

            # Check for passwords (obscured)
            if 'password' in line.lower() or 'secret' in line.lower():
                # Obscure the actual password
                obscured = line.split()[0] + ' ***REDACTED***'
                critical['passwords'].append(obscured)

            # Check for crypto keys
            if 'crypto' in line.lower() and 'key' in line.lower():
                critical['crypto_keys'].append(line.split()[0] + ' ***REDACTED***')

            # Check for SNMP communities
            if 'snmp' in line.lower() and 'community' in line.lower():
                critical['snmp_communities'].append(line.split()[0] + ' ***REDACTED***')

            # Check for RADIUS servers
            if 'radius' in line.lower() and 'server' in line.lower():
                parts = line.split()
                for part in parts:
                    if ConfigParserFactory._is_ip_address(part):
                        critical['radius_servers'].append(part)

            # Check for TACACS servers
            if 'tacacs' in line.lower() and 'server' in line.lower():
                parts = line.split()
                for part in parts:
                    if ConfigParserFactory._is_ip_address(part):
                        critical['tacacs_servers'].append(part)

            # Check for management IPs
            if vendor == VendorType.CISCO:
                if line.startswith('interface') and ('management' in line.lower() or 'mgmt' in line.lower()):
                    critical['management_ips'].append(line)
            elif vendor == VendorType.JUNIPER:
                if 'set interfaces' in line and 'fxp0' in line:
                    critical['management_ips'].append(line)

        return critical

    @staticmethod
    def _is_ip_address(text: str) -> bool:
        """Check if text is an IP address"""
        import ipaddress
        try:
            ipaddress.ip_address(text)
            return True
        except ValueError:
            return False

    @staticmethod
    def get_config_summary(
        config: str,
        vendor: VendorType,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Get configuration summary

        Args:
            config: Configuration text
            vendor: Vendor type
            **kwargs: Additional vendor-specific parameters

        Returns:
            Configuration summary
        """
        parsed = ConfigParserFactory.parse_config(config, vendor, **kwargs)

        summary = {
            'vendor': vendor.value,
            'hostname': None,
            'version': None,
            'interface_count': 0,
            'vlan_count': 0,
            'acl_count': 0,
            'routing_protocols': [],
            'services': [],
            'warnings': [],
            'errors': []
        }

        if vendor == VendorType.CISCO:
            summary['hostname'] = parsed.hostname
            summary['version'] = parsed.version
            summary['interface_count'] = len(parsed.interfaces)
            summary['vlan_count'] = len(parsed.vlans)
            summary['acl_count'] = len(parsed.acls)
            summary['services'] = list(parsed.services.keys())
            summary['warnings'] = parsed.warnings
            summary['errors'] = parsed.errors

            # Check routing protocols
            if parsed.routing.get('ospf'):
                summary['routing_protocols'].append('ospf')
            if parsed.routing.get('eigrp'):
                summary['routing_protocols'].append('eigrp')
            if parsed.routing.get('bgp'):
                summary['routing_protocols'].append('bgp')
            if parsed.routing.get('rip'):
                summary['routing_protocols'].append('rip')

        elif vendor == VendorType.JUNIPER:
            summary['hostname'] = parsed.hostname
            summary['version'] = parsed.version
            summary['interface_count'] = len(parsed.interfaces)
            summary['vlan_count'] = len(parsed.vlans)
            summary['services'] = list(parsed.system.get('services', {}).keys())
            summary['warnings'] = parsed.warnings
            summary['errors'] = parsed.errors
            summary['routing_protocols'] = list(parsed.protocols.keys())

            # Count firewall rules
            if parsed.firewall:
                for family in parsed.firewall.values():
                    if 'filters' in family:
                        summary['acl_count'] += len(family['filters'])

        return summary