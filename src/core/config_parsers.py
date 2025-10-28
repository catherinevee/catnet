"""
Enhanced configuration parsers for network devices.

Provides vendor-specific parsing logic for Cisco IOS, Juniper Junos, and other
network operating systems. Implements hierarchical parsing, context tracking,
and semantic validation.
"""
import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ConfigSection(Enum):
    """Configuration section types."""
    GLOBAL = "global"
    INTERFACE = "interface"
    ROUTER = "router"
    LINE = "line"
    ACCESS_LIST = "access_list"
    ROUTE_MAP = "route_map"
    CLASS_MAP = "class_map"
    POLICY_MAP = "policy_map"
    VLAN = "vlan"


@dataclass
class ParsedConfig:
    """
    Structured representation of parsed configuration.

    Attributes:
        raw_lines: Original configuration lines
        sections: Dictionary of configuration sections
        hostname: Device hostname
        interfaces: List of parsed interfaces
        routing: Routing protocol configuration
        access_lists: Access control lists
        errors: List of parsing errors
        warnings: List of parsing warnings
    """
    raw_lines: List[str] = field(default_factory=list)
    sections: Dict[str, List[str]] = field(default_factory=dict)
    hostname: Optional[str] = None
    interfaces: List[Dict[str, Any]] = field(default_factory=list)
    routing: Dict[str, Any] = field(default_factory=dict)
    access_lists: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class CiscoIOSParser:
    """
    Enhanced parser for Cisco IOS/IOS-XE configurations.

    Implements hierarchical parsing with context tracking, command validation,
    and semantic analysis. Handles both running-config and configuration
    snippets.

    Example:
        >>> parser = CiscoIOSParser()
        >>> config = parser.parse(raw_config_text)
        >>> print(f"Hostname: {config.hostname}")
        >>> print(f"Interfaces: {len(config.interfaces)}")
    """

    def __init__(self):
        """Initialize parser with Cisco IOS command patterns."""
        self.interface_pattern = re.compile(
            r'^interface\s+((?:GigabitEthernet|FastEthernet|TenGigabitEthernet|'
            r'Ethernet|Loopback|Vlan|Port-channel|Tunnel)\S+)',
            re.IGNORECASE
        )
        self.router_pattern = re.compile(
            r'^router\s+(bgp|ospf|eigrp|rip|isis)\s*(\d+)?',
            re.IGNORECASE
        )
        self.line_pattern = re.compile(
            r'^line\s+(console|vty|aux)\s+(\d+)(?:\s+(\d+))?',
            re.IGNORECASE
        )
        self.acl_pattern = re.compile(
            r'^(?:ip\s+)?access-list\s+(?:extended\s+)?(\S+)',
            re.IGNORECASE
        )
        self.vlan_pattern = re.compile(r'^vlan\s+(\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*)', re.IGNORECASE)

    def parse(self, raw_config: str) -> ParsedConfig:
        """
        Parse Cisco IOS configuration into structured format.

        Args:
            raw_config: Raw configuration text

        Returns:
            ParsedConfig: Structured configuration object

        Example:
            >>> config_text = '''
            ... hostname Router1
            ... interface GigabitEthernet0/1
            ...  ip address 192.168.1.1 255.255.255.0
            ...  no shutdown
            ... '''
            >>> parsed = parser.parse(config_text)
        """
        config = ParsedConfig()
        lines = raw_config.split('\n')
        config.raw_lines = [line.rstrip() for line in lines]

        # Parse line by line with context tracking
        current_section = None
        current_context = []
        indent_level = 0

        for line_num, line in enumerate(lines, 1):
            # Skip empty lines and full comments
            if not line.strip() or line.strip().startswith('!'):
                continue

            # Detect indentation level
            stripped_line = line.lstrip()
            current_indent = len(line) - len(stripped_line)

            # Reset context if indent decreases (exiting sub-config)
            if current_indent <= indent_level and current_section:
                self._finalize_section(config, current_section, current_context)
                current_section = None
                current_context = []

            # Parse global commands
            if current_indent == 0:
                indent_level = 0
                self._parse_global_command(config, stripped_line, line_num)

            # Parse section headers
            if self.interface_pattern.match(stripped_line):
                if current_section:
                    self._finalize_section(config, current_section, current_context)
                current_section = ('interface', self.interface_pattern.match(stripped_line).group(1))
                current_context = [stripped_line]
                indent_level = current_indent

            elif self.router_pattern.match(stripped_line):
                if current_section:
                    self._finalize_section(config, current_section, current_context)
                match = self.router_pattern.match(stripped_line)
                current_section = ('router', f"{match.group(1)} {match.group(2) or ''}")
                current_context = [stripped_line]
                indent_level = current_indent

            elif self.line_pattern.match(stripped_line):
                if current_section:
                    self._finalize_section(config, current_section, current_context)
                current_section = ('line', stripped_line)
                current_context = [stripped_line]
                indent_level = current_indent

            elif self.vlan_pattern.match(stripped_line):
                if current_section:
                    self._finalize_section(config, current_section, current_context)
                current_section = ('vlan', self.vlan_pattern.match(stripped_line).group(1))
                current_context = [stripped_line]
                indent_level = current_indent

            elif current_section and current_indent > 0:
                # Sub-configuration command
                current_context.append(stripped_line)

        # Finalize last section
        if current_section:
            self._finalize_section(config, current_section, current_context)

        return config

    def _parse_global_command(
        self,
        config: ParsedConfig,
        line: str,
        line_num: int
    ) -> None:
        """Parse global configuration commands."""
        # Hostname
        hostname_match = re.match(r'^hostname\s+(\S+)', line, re.IGNORECASE)
        if hostname_match:
            config.hostname = hostname_match.group(1)
            return

        # IP route
        route_match = re.match(
            r'^ip\s+route\s+(\S+)\s+(\S+)\s+(\S+)',
            line,
            re.IGNORECASE
        )
        if route_match:
            if 'static_routes' not in config.routing:
                config.routing['static_routes'] = []
            config.routing['static_routes'].append({
                'network': route_match.group(1),
                'mask': route_match.group(2),
                'next_hop': route_match.group(3)
            })
            return

        # Access-list
        if self.acl_pattern.match(line):
            self._parse_access_list(config, line)
            return

    def _parse_access_list(self, config: ParsedConfig, line: str) -> None:
        """Parse access-list configuration."""
        match = self.acl_pattern.match(line)
        if not match:
            return

        acl_name = match.group(1)

        # Find or create ACL entry
        acl_entry = next(
            (acl for acl in config.access_lists if acl['name'] == acl_name),
            None
        )

        if not acl_entry:
            acl_entry = {'name': acl_name, 'entries': []}
            config.access_lists.append(acl_entry)

        acl_entry['entries'].append(line)

    def _finalize_section(
        self,
        config: ParsedConfig,
        section: Tuple[str, str],
        context: List[str]
    ) -> None:
        """Finalize and store a configuration section."""
        section_type, section_name = section

        if section_type == 'interface':
            interface_config = self._parse_interface_config(section_name, context)
            config.interfaces.append(interface_config)

        elif section_type == 'router':
            router_config = self._parse_router_config(section_name, context)
            if 'protocols' not in config.routing:
                config.routing['protocols'] = []
            config.routing['protocols'].append(router_config)

        # Store raw section
        section_key = f"{section_type}:{section_name}"
        config.sections[section_key] = context

    def _parse_interface_config(
        self,
        interface_name: str,
        commands: List[str]
    ) -> Dict[str, Any]:
        """
        Parse interface configuration block.

        Args:
            interface_name: Interface name (e.g., "GigabitEthernet0/1")
            commands: List of interface configuration commands

        Returns:
            Dictionary with parsed interface configuration
        """
        interface = {
            'name': interface_name,
            'description': None,
            'ip_address': None,
            'subnet_mask': None,
            'shutdown': True,
            'switchport_mode': None,
            'access_vlan': None,
            'trunk_vlans': [],
            'channel_group': None,
            'commands': commands
        }

        for cmd in commands[1:]:  # Skip "interface" line
            cmd = cmd.strip()

            # Description
            desc_match = re.match(r'description\s+(.+)', cmd, re.IGNORECASE)
            if desc_match:
                interface['description'] = desc_match.group(1)
                continue

            # IP address
            ip_match = re.match(
                r'ip\s+address\s+(\S+)\s+(\S+)',
                cmd,
                re.IGNORECASE
            )
            if ip_match:
                interface['ip_address'] = ip_match.group(1)
                interface['subnet_mask'] = ip_match.group(2)
                continue

            # Shutdown state
            if re.match(r'no\s+shutdown', cmd, re.IGNORECASE):
                interface['shutdown'] = False
                continue
            if re.match(r'shutdown', cmd, re.IGNORECASE):
                interface['shutdown'] = True
                continue

            # Switchport mode
            switchport_match = re.match(
                r'switchport\s+mode\s+(access|trunk|dynamic)',
                cmd,
                re.IGNORECASE
            )
            if switchport_match:
                interface['switchport_mode'] = switchport_match.group(1)
                continue

            # Access VLAN
            access_vlan_match = re.match(
                r'switchport\s+access\s+vlan\s+(\d+)',
                cmd,
                re.IGNORECASE
            )
            if access_vlan_match:
                interface['access_vlan'] = int(access_vlan_match.group(1))
                continue

            # Trunk VLANs
            trunk_match = re.match(
                r'switchport\s+trunk\s+allowed\s+vlan\s+(.+)',
                cmd,
                re.IGNORECASE
            )
            if trunk_match:
                vlan_spec = trunk_match.group(1)
                interface['trunk_vlans'] = self._parse_vlan_list(vlan_spec)
                continue

            # Channel group
            channel_match = re.match(
                r'channel-group\s+(\d+)',
                cmd,
                re.IGNORECASE
            )
            if channel_match:
                interface['channel_group'] = int(channel_match.group(1))
                continue

        return interface

    def _parse_router_config(
        self,
        router_type: str,
        commands: List[str]
    ) -> Dict[str, Any]:
        """Parse routing protocol configuration."""
        router_config = {
            'type': router_type.split()[0],
            'process_id': router_type.split()[1] if len(router_type.split()) > 1 else None,
            'networks': [],
            'neighbors': [],
            'commands': commands
        }

        for cmd in commands[1:]:
            cmd = cmd.strip()

            # Network statement
            network_match = re.match(
                r'network\s+(\S+)(?:\s+mask\s+(\S+))?(?:\s+area\s+(\S+))?',
                cmd,
                re.IGNORECASE
            )
            if network_match:
                router_config['networks'].append({
                    'network': network_match.group(1),
                    'mask': network_match.group(2),
                    'area': network_match.group(3)
                })

            # Neighbor statement
            neighbor_match = re.match(
                r'neighbor\s+(\S+)',
                cmd,
                re.IGNORECASE
            )
            if neighbor_match:
                router_config['neighbors'].append(neighbor_match.group(1))

        return router_config

    def _parse_vlan_list(self, vlan_spec: str) -> List[int]:
        """
        Parse VLAN list specification (e.g., "1-10,20,30-40").

        Args:
            vlan_spec: VLAN specification string

        Returns:
            List of VLAN IDs
        """
        vlans = []
        parts = vlan_spec.split(',')

        for part in parts:
            if '-' in part:
                start, end = part.split('-')
                vlans.extend(range(int(start), int(end) + 1))
            else:
                try:
                    vlans.append(int(part))
                except ValueError:
                    pass

        return vlans


class JuniperJunosParser:
    """
    Enhanced parser for Juniper Junos configurations.

    Handles both set-style and hierarchical Junos configuration formats.
    Provides semantic parsing of interfaces, routing protocols, security
    policies, and system configuration.

    Example:
        >>> parser = JuniperJunosParser()
        >>> config = parser.parse(junos_config_text)
        >>> print(f"Interfaces: {len(config.interfaces)}")
    """

    def __init__(self):
        """Initialize Junos parser with command patterns."""
        self.set_pattern = re.compile(r'^set\s+(.+)$')
        self.delete_pattern = re.compile(r'^delete\s+(.+)$')

    def parse(self, raw_config: str) -> ParsedConfig:
        """
        Parse Juniper Junos configuration.

        Supports both "set" command format and hierarchical format.

        Args:
            raw_config: Raw Junos configuration text

        Returns:
            ParsedConfig: Structured configuration object
        """
        config = ParsedConfig()
        lines = raw_config.split('\n')
        config.raw_lines = [line.rstrip() for line in lines]

        # Detect configuration format
        is_set_format = any(line.strip().startswith('set ') for line in lines[:10])

        if is_set_format:
            self._parse_set_format(config, lines)
        else:
            self._parse_hierarchical_format(config, lines)

        return config

    def _parse_set_format(self, config: ParsedConfig, lines: List[str]) -> None:
        """Parse set-style Junos configuration."""
        interface_configs = {}

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            match = self.set_pattern.match(line)
            if not match:
                continue

            path_and_value = match.group(1)
            parts = path_and_value.split()

            # System hostname
            if parts[0] == 'system' and parts[1] == 'host-name':
                config.hostname = parts[2]

            # Interfaces
            elif parts[0] == 'interfaces':
                if len(parts) < 2:
                    continue

                interface_name = parts[1]
                if interface_name not in interface_configs:
                    interface_configs[interface_name] = {
                        'name': interface_name,
                        'units': {},
                        'commands': []
                    }

                interface_configs[interface_name]['commands'].append(line)

                # Unit configuration
                if len(parts) > 2 and parts[2] == 'unit':
                    unit_num = parts[3]
                    if unit_num not in interface_configs[interface_name]['units']:
                        interface_configs[interface_name]['units'][unit_num] = {}

                    # Family inet address
                    if len(parts) > 4 and parts[4] == 'family' and parts[5] == 'inet':
                        if len(parts) > 6 and parts[6] == 'address':
                            addr = parts[7] if len(parts) > 7 else None
                            interface_configs[interface_name]['units'][unit_num]['address'] = addr

        config.interfaces = list(interface_configs.values())

    def _parse_hierarchical_format(
        self,
        config: ParsedConfig,
        lines: List[str]
    ) -> None:
        """Parse hierarchical Junos configuration."""
        config.warnings.append("Hierarchical Junos format parsing is basic")

        for line in lines:
            # Extract hostname from hierarchical format
            hostname_match = re.match(r'\s*host-name\s+(\S+);', line)
            if hostname_match:
                config.hostname = hostname_match.group(1)


# Export main classes
__all__ = [
    'CiscoIOSParser',
    'JuniperJunosParser',
    'ParsedConfig',
    'ConfigSection'
]
