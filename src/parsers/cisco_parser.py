"""
CatNet Cisco Configuration Parser

Parses and validates Cisco IOS, IOS-XE, and NX-OS configurations
"""

import re
import json
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import ipaddress
import structlog
from datetime import datetime

logger = structlog.get_logger()


class CiscoOS(Enum):
    """Cisco operating system types"""
    IOS = "ios"
    IOS_XE = "ios_xe"
    NX_OS = "nx_os"
    IOS_XR = "ios_xr"
    ASA = "asa"


class ConfigSection(Enum):
    """Configuration sections"""
    GLOBAL = "global"
    INTERFACE = "interface"
    VLAN = "vlan"
    ROUTING = "routing"
    ACL = "acl"
    NAT = "nat"
    VPN = "vpn"
    QOS = "qos"
    SERVICES = "services"
    MANAGEMENT = "management"
    SECURITY = "security"
    SPANNING_TREE = "spanning_tree"
    MULTICAST = "multicast"


@dataclass
class ParsedConfig:
    """Parsed configuration result"""
    os_type: CiscoOS
    hostname: Optional[str] = None
    version: Optional[str] = None
    interfaces: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    vlans: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    routing: Dict[str, Any] = field(default_factory=dict)
    acls: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    services: Dict[str, Any] = field(default_factory=dict)
    security: Dict[str, Any] = field(default_factory=dict)
    raw_config: str = ""
    hash: Optional[str] = None
    parsed_at: Optional[datetime] = None
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class CiscoConfigParser:
    """Parser for Cisco device configurations"""

    def __init__(self):
        self.indent_pattern = re.compile(r'^(\s*)')
        self.comment_pattern = re.compile(r'^\s*!')
        self.hostname_pattern = re.compile(r'^hostname\s+(\S+)')
        self.version_pattern = re.compile(r'^version\s+([\d\.]+)')
        self.interface_pattern = re.compile(r'^interface\s+(\S+)')
        self.vlan_pattern = re.compile(r'^vlan\s+(\d+(?:[-,]\d+)*)')
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.subnet_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/\d{1,2}\b')

    def parse(self, config: str, os_type: CiscoOS = CiscoOS.IOS) -> ParsedConfig:
        """
        Parse Cisco configuration

        Args:
            config: Raw configuration text
            os_type: Cisco OS type

        Returns:
            ParsedConfig object
        """
        parsed = ParsedConfig(
            os_type=os_type,
            raw_config=config,
            hash=self._calculate_hash(config),
            parsed_at=datetime.utcnow()
        )

        # Split into lines
        lines = config.strip().split('\n')

        # Parse configuration
        self._parse_global_config(lines, parsed)
        self._parse_interfaces(lines, parsed)
        self._parse_vlans(lines, parsed)
        self._parse_routing(lines, parsed)
        self._parse_acls(lines, parsed)
        self._parse_services(lines, parsed)
        self._parse_security(lines, parsed)

        # Validate configuration
        self._validate_config(parsed)

        return parsed

    def _calculate_hash(self, config: str) -> str:
        """Calculate configuration hash"""
        # Remove comments and blank lines for consistent hashing
        cleaned = '\n'.join(
            line for line in config.split('\n')
            if line.strip() and not line.strip().startswith('!')
        )
        return hashlib.sha256(cleaned.encode()).hexdigest()

    def _parse_global_config(self, lines: List[str], parsed: ParsedConfig):
        """Parse global configuration settings"""
        for line in lines:
            line = line.rstrip()

            # Skip comments and empty lines
            if not line or self.comment_pattern.match(line):
                continue

            # Hostname
            match = self.hostname_pattern.match(line)
            if match:
                parsed.hostname = match.group(1)
                continue

            # Version
            match = self.version_pattern.match(line)
            if match:
                parsed.version = match.group(1)
                continue

            # Services
            if line.startswith('service '):
                service = line.split()[1]
                parsed.services[service] = True

            # Security settings
            if line.startswith('enable secret') or line.startswith('enable password'):
                parsed.security['enable_configured'] = True

            # AAA
            if line.startswith('aaa '):
                if 'aaa' not in parsed.security:
                    parsed.security['aaa'] = []
                parsed.security['aaa'].append(line)

            # SNMP
            if line.startswith('snmp-server'):
                if 'snmp' not in parsed.services:
                    parsed.services['snmp'] = []
                parsed.services['snmp'].append(line)

            # NTP
            if line.startswith('ntp server'):
                if 'ntp_servers' not in parsed.services:
                    parsed.services['ntp_servers'] = []
                parts = line.split()
                if len(parts) > 2:
                    parsed.services['ntp_servers'].append(parts[2])

            # DNS
            if line.startswith('ip name-server'):
                parts = line.split()
                parsed.services['dns_servers'] = parts[2:]

            # Domain name
            if line.startswith('ip domain-name') or line.startswith('ip domain name'):
                parts = line.split()
                if len(parts) > 2:
                    parsed.services['domain_name'] = parts[-1]

    def _parse_interfaces(self, lines: List[str], parsed: ParsedConfig):
        """Parse interface configurations"""
        current_interface = None
        interface_config = {}

        for i, line in enumerate(lines):
            line = line.rstrip()

            # Check for interface declaration
            match = self.interface_pattern.match(line)
            if match:
                # Save previous interface if exists
                if current_interface:
                    parsed.interfaces[current_interface] = interface_config

                # Start new interface
                current_interface = match.group(1)
                interface_config = {
                    'name': current_interface,
                    'type': self._get_interface_type(current_interface),
                    'config_lines': []
                }
                continue

            # If we're inside an interface block
            if current_interface:
                # Check if we've exited the interface block
                if line and not line.startswith(' ') and not line.startswith('\t'):
                    parsed.interfaces[current_interface] = interface_config
                    current_interface = None
                    interface_config = {}
                    continue

                # Parse interface settings
                stripped = line.strip()
                if stripped:
                    interface_config['config_lines'].append(stripped)

                    # Parse specific settings
                    if stripped.startswith('description '):
                        interface_config['description'] = stripped[12:]

                    elif stripped.startswith('ip address '):
                        parts = stripped.split()
                        if len(parts) >= 4:
                            interface_config['ip_address'] = parts[2]
                            interface_config['subnet_mask'] = parts[3]

                    elif stripped.startswith('ipv6 address '):
                        if 'ipv6_addresses' not in interface_config:
                            interface_config['ipv6_addresses'] = []
                        interface_config['ipv6_addresses'].append(stripped[13:])

                    elif stripped == 'shutdown':
                        interface_config['shutdown'] = True

                    elif stripped == 'no shutdown':
                        interface_config['shutdown'] = False

                    elif stripped.startswith('switchport mode '):
                        interface_config['switchport_mode'] = stripped[16:]

                    elif stripped.startswith('switchport access vlan '):
                        interface_config['access_vlan'] = int(stripped.split()[-1])

                    elif stripped.startswith('switchport trunk allowed vlan '):
                        interface_config['trunk_vlans'] = stripped[30:]

                    elif stripped.startswith('channel-group '):
                        parts = stripped.split()
                        if len(parts) >= 2:
                            interface_config['channel_group'] = int(parts[1])

                    elif stripped.startswith('speed '):
                        interface_config['speed'] = stripped[6:]

                    elif stripped.startswith('duplex '):
                        interface_config['duplex'] = stripped[7:]

                    elif stripped.startswith('mtu '):
                        interface_config['mtu'] = int(stripped[4:])

        # Save last interface if exists
        if current_interface:
            parsed.interfaces[current_interface] = interface_config

    def _parse_vlans(self, lines: List[str], parsed: ParsedConfig):
        """Parse VLAN configurations"""
        current_vlan = None
        vlan_config = {}

        for line in lines:
            line = line.rstrip()

            # Check for VLAN declaration
            match = self.vlan_pattern.match(line)
            if match:
                # Save previous VLAN if exists
                if current_vlan:
                    parsed.vlans[current_vlan] = vlan_config

                # Parse VLAN number(s)
                vlan_str = match.group(1)
                vlan_nums = self._parse_vlan_range(vlan_str)

                if vlan_nums:
                    current_vlan = vlan_nums[0]  # Use first VLAN for config
                    vlan_config = {'id': current_vlan}

                    # Store all VLANs if it's a range
                    if len(vlan_nums) > 1:
                        vlan_config['range'] = vlan_nums
                continue

            # If we're inside a VLAN block
            if current_vlan:
                # Check if we've exited the VLAN block
                if line and not line.startswith(' ') and not line.startswith('\t'):
                    parsed.vlans[current_vlan] = vlan_config
                    current_vlan = None
                    vlan_config = {}
                    continue

                # Parse VLAN settings
                stripped = line.strip()
                if stripped.startswith('name '):
                    vlan_config['name'] = stripped[5:]
                elif stripped == 'shutdown':
                    vlan_config['shutdown'] = True
                elif stripped == 'no shutdown':
                    vlan_config['shutdown'] = False

        # Save last VLAN if exists
        if current_vlan:
            parsed.vlans[current_vlan] = vlan_config

    def _parse_routing(self, lines: List[str], parsed: ParsedConfig):
        """Parse routing configuration"""
        parsed.routing = {
            'static_routes': [],
            'ospf': {},
            'eigrp': {},
            'bgp': {},
            'rip': {}
        }

        current_protocol = None
        protocol_config = {}

        for line in lines:
            line = line.rstrip()

            # Static routes
            if line.startswith('ip route '):
                parts = line.split()
                if len(parts) >= 5:
                    route = {
                        'network': parts[2],
                        'mask': parts[3],
                        'next_hop': parts[4]
                    }
                    if len(parts) > 5:
                        route['metric'] = parts[5]
                    parsed.routing['static_routes'].append(route)

            # OSPF
            elif line.startswith('router ospf '):
                current_protocol = 'ospf'
                process_id = line.split()[-1]
                protocol_config = {'process_id': process_id, 'networks': []}

            # EIGRP
            elif line.startswith('router eigrp '):
                current_protocol = 'eigrp'
                as_number = line.split()[-1]
                protocol_config = {'as_number': as_number, 'networks': []}

            # BGP
            elif line.startswith('router bgp '):
                current_protocol = 'bgp'
                as_number = line.split()[-1]
                protocol_config = {'as_number': as_number, 'neighbors': []}

            # RIP
            elif line.startswith('router rip'):
                current_protocol = 'rip'
                protocol_config = {'version': 2, 'networks': []}

            # Inside routing protocol block
            elif current_protocol:
                if line and not line.startswith(' ') and not line.startswith('\t'):
                    # Exited protocol block
                    parsed.routing[current_protocol] = protocol_config
                    current_protocol = None
                    protocol_config = {}
                else:
                    stripped = line.strip()
                    if stripped.startswith('network '):
                        parts = stripped.split()
                        if current_protocol in ['ospf', 'eigrp', 'rip']:
                            protocol_config['networks'].append({
                                'network': parts[1],
                                'wildcard': parts[2] if len(parts) > 2 else None,
                                'area': parts[4] if len(parts) > 4 and parts[3] == 'area' else None
                            })
                    elif stripped.startswith('neighbor ') and current_protocol == 'bgp':
                        parts = stripped.split()
                        if len(parts) >= 4:
                            protocol_config['neighbors'].append({
                                'ip': parts[1],
                                'remote_as': parts[3] if parts[2] == 'remote-as' else None
                            })

        # Save last protocol if exists
        if current_protocol:
            parsed.routing[current_protocol] = protocol_config

    def _parse_acls(self, lines: List[str], parsed: ParsedConfig):
        """Parse access control lists"""
        current_acl = None
        acl_entries = []

        for line in lines:
            line = line.rstrip()

            # Standard ACL
            if line.startswith('access-list '):
                parts = line.split(maxsplit=2)
                if len(parts) >= 3:
                    acl_num = parts[1]
                    acl_line = parts[2]

                    if acl_num not in parsed.acls:
                        parsed.acls[acl_num] = []

                    # Parse ACL entry
                    entry = self._parse_acl_entry(acl_line)
                    if entry:
                        entry['number'] = acl_num
                        parsed.acls[acl_num].append(entry)

            # Extended/Named ACL
            elif line.startswith('ip access-list '):
                parts = line.split()
                if len(parts) >= 4:
                    acl_type = parts[2]  # standard/extended
                    acl_name = parts[3]
                    current_acl = acl_name
                    if acl_name not in parsed.acls:
                        parsed.acls[acl_name] = []

            # Inside named ACL
            elif current_acl:
                if line and not line.startswith(' ') and not line.startswith('\t'):
                    current_acl = None
                else:
                    stripped = line.strip()
                    if stripped and not stripped.startswith('!'):
                        entry = self._parse_acl_entry(stripped)
                        if entry:
                            parsed.acls[current_acl].append(entry)

    def _parse_acl_entry(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single ACL entry"""
        parts = line.split()
        if not parts:
            return None

        entry = {}

        # Action (permit/deny)
        if parts[0] in ['permit', 'deny']:
            entry['action'] = parts[0]
            parts = parts[1:]
        else:
            return None

        # Protocol (for extended ACLs)
        if parts and parts[0] in ['ip', 'tcp', 'udp', 'icmp', 'gre', 'esp', 'ahp']:
            entry['protocol'] = parts[0]
            parts = parts[1:]

        # Source
        if parts:
            if parts[0] == 'any':
                entry['source'] = 'any'
                parts = parts[1:]
            elif parts[0] == 'host':
                entry['source'] = parts[1]
                entry['source_type'] = 'host'
                parts = parts[2:]
            elif self.ip_pattern.match(parts[0]):
                entry['source'] = parts[0]
                if len(parts) > 1 and self.ip_pattern.match(parts[1]):
                    entry['source_wildcard'] = parts[1]
                    parts = parts[2:]
                else:
                    parts = parts[1:]

        # Destination (for extended ACLs)
        if parts and 'protocol' in entry:
            if parts[0] == 'any':
                entry['destination'] = 'any'
                parts = parts[1:]
            elif parts[0] == 'host':
                entry['destination'] = parts[1]
                entry['destination_type'] = 'host'
                parts = parts[2:]
            elif self.ip_pattern.match(parts[0]):
                entry['destination'] = parts[0]
                if len(parts) > 1 and self.ip_pattern.match(parts[1]):
                    entry['destination_wildcard'] = parts[1]
                    parts = parts[2:]
                else:
                    parts = parts[1:]

        # Port specifications
        if parts and entry.get('protocol') in ['tcp', 'udp']:
            # Source port
            if parts[0] in ['eq', 'neq', 'lt', 'gt', 'range']:
                entry['source_port_op'] = parts[0]
                if parts[0] == 'range':
                    entry['source_port'] = [parts[1], parts[2]]
                    parts = parts[3:]
                else:
                    entry['source_port'] = parts[1]
                    parts = parts[2:]

            # Destination port
            if parts and parts[0] in ['eq', 'neq', 'lt', 'gt', 'range']:
                entry['dest_port_op'] = parts[0]
                if parts[0] == 'range':
                    entry['dest_port'] = [parts[1], parts[2]]
                    parts = parts[3:]
                else:
                    entry['dest_port'] = parts[1]
                    parts = parts[2:]

        # Additional options
        if parts:
            entry['options'] = ' '.join(parts)

        return entry

    def _parse_services(self, lines: List[str], parsed: ParsedConfig):
        """Parse service configurations"""
        for line in lines:
            line = line.strip()

            # SSH
            if line.startswith('ip ssh'):
                if 'ssh' not in parsed.services:
                    parsed.services['ssh'] = {}

                if 'version' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        parsed.services['ssh']['version'] = parts[3]
                elif 'time-out' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        parsed.services['ssh']['timeout'] = int(parts[3])
                elif 'authentication-retries' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        parsed.services['ssh']['retries'] = int(parts[3])

            # HTTP/HTTPS
            elif line == 'ip http server':
                parsed.services['http'] = True
            elif line == 'ip http secure-server':
                parsed.services['https'] = True
            elif line == 'no ip http server':
                parsed.services['http'] = False
            elif line == 'no ip http secure-server':
                parsed.services['https'] = False

            # Telnet (check in VTY lines)
            elif line.startswith('line vty'):
                parsed.services['vty_configured'] = True

            # CDP
            elif line == 'cdp run':
                parsed.services['cdp'] = True
            elif line == 'no cdp run':
                parsed.services['cdp'] = False

            # LLDP
            elif line == 'lldp run':
                parsed.services['lldp'] = True
            elif line == 'no lldp run':
                parsed.services['lldp'] = False

    def _parse_security(self, lines: List[str], parsed: ParsedConfig):
        """Parse security configurations"""
        in_line_con = False
        in_line_vty = False

        for line in lines:
            stripped = line.strip()

            # Console security
            if line.startswith('line con'):
                in_line_con = True
                in_line_vty = False
                if 'console' not in parsed.security:
                    parsed.security['console'] = {}
            elif line.startswith('line vty'):
                in_line_vty = True
                in_line_con = False
                if 'vty' not in parsed.security:
                    parsed.security['vty'] = {}
            elif line and not line.startswith(' ') and not line.startswith('\t'):
                in_line_con = False
                in_line_vty = False

            # Inside line configuration
            if in_line_con and stripped:
                if stripped.startswith('password'):
                    parsed.security['console']['password_configured'] = True
                elif stripped.startswith('login'):
                    parsed.security['console']['login'] = stripped
                elif stripped.startswith('exec-timeout'):
                    parts = stripped.split()
                    if len(parts) >= 3:
                        parsed.security['console']['exec_timeout'] = f"{parts[1]} {parts[2]}"

            if in_line_vty and stripped:
                if stripped.startswith('password'):
                    parsed.security['vty']['password_configured'] = True
                elif stripped.startswith('login'):
                    parsed.security['vty']['login'] = stripped
                elif stripped.startswith('transport input'):
                    parsed.security['vty']['transport_input'] = stripped[16:]
                elif stripped.startswith('access-class'):
                    parts = stripped.split()
                    if len(parts) >= 2:
                        parsed.security['vty']['access_class'] = parts[1]

            # Port security
            if stripped.startswith('switchport port-security'):
                if 'port_security' not in parsed.security:
                    parsed.security['port_security'] = []
                parsed.security['port_security'].append(stripped)

            # Storm control
            if stripped.startswith('storm-control'):
                if 'storm_control' not in parsed.security:
                    parsed.security['storm_control'] = []
                parsed.security['storm_control'].append(stripped)

            # DHCP snooping
            if 'dhcp snooping' in stripped:
                if 'dhcp_snooping' not in parsed.security:
                    parsed.security['dhcp_snooping'] = []
                parsed.security['dhcp_snooping'].append(stripped)

    def _get_interface_type(self, interface_name: str) -> str:
        """Determine interface type from name"""
        name_lower = interface_name.lower()

        if name_lower.startswith('gi') or name_lower.startswith('gigabit'):
            return 'gigabit'
        elif name_lower.startswith('fa') or name_lower.startswith('fast'):
            return 'fastethernet'
        elif name_lower.startswith('te') or name_lower.startswith('ten'):
            return 'tengigabit'
        elif name_lower.startswith('fo') or name_lower.startswith('forty'):
            return 'fortygigabit'
        elif name_lower.startswith('hu') or name_lower.startswith('hundred'):
            return 'hundredgigabit'
        elif name_lower.startswith('vlan'):
            return 'vlan'
        elif name_lower.startswith('lo'):
            return 'loopback'
        elif name_lower.startswith('tu'):
            return 'tunnel'
        elif name_lower.startswith('po'):
            return 'portchannel'
        elif name_lower.startswith('serial'):
            return 'serial'
        elif name_lower.startswith('mgmt'):
            return 'management'
        else:
            return 'unknown'

    def _parse_vlan_range(self, vlan_str: str) -> List[int]:
        """Parse VLAN range string (e.g., '10-20,30,40-45')"""
        vlans = []

        for part in vlan_str.split(','):
            part = part.strip()
            if '-' in part:
                # Range
                start, end = part.split('-')
                vlans.extend(range(int(start), int(end) + 1))
            else:
                # Single VLAN
                vlans.append(int(part))

        return sorted(set(vlans))

    def _validate_config(self, parsed: ParsedConfig):
        """Validate parsed configuration and add warnings"""

        # Check hostname
        if not parsed.hostname:
            parsed.warnings.append("No hostname configured")

        # Check enable secret
        if not parsed.security.get('enable_configured'):
            parsed.warnings.append("No enable secret/password configured")

        # Check SSH version
        ssh_config = parsed.services.get('ssh', {})
        if ssh_config.get('version') == '1':
            parsed.warnings.append("SSH version 1 is insecure, use version 2")

        # Check Telnet
        if parsed.services.get('vty_configured'):
            vty_transport = parsed.security.get('vty', {}).get('transport_input', '')
            if 'telnet' in vty_transport or vty_transport == 'all':
                parsed.warnings.append("Telnet is enabled, consider using SSH only")

        # Check HTTP server
        if parsed.services.get('http'):
            parsed.warnings.append("HTTP server is enabled, consider using HTTPS only")

        # Check default VLANs
        if 1 in parsed.vlans:
            parsed.warnings.append("VLAN 1 (default) is in use, consider using a different VLAN")

        # Check interface shutdown status
        active_interfaces = sum(
            1 for iface in parsed.interfaces.values()
            if not iface.get('shutdown', False)
        )
        if active_interfaces == 0:
            parsed.warnings.append("No interfaces are active")

        # Check routing
        if not parsed.routing.get('static_routes') and \
           not parsed.routing.get('ospf') and \
           not parsed.routing.get('eigrp') and \
           not parsed.routing.get('bgp'):
            parsed.warnings.append("No routing configured")

        # Check ACLs
        if not parsed.acls:
            parsed.warnings.append("No access control lists configured")

        # Check NTP
        if not parsed.services.get('ntp_servers'):
            parsed.warnings.append("No NTP servers configured")

        # Check AAA
        if not parsed.security.get('aaa'):
            parsed.warnings.append("AAA not configured")

        # Check console security
        console = parsed.security.get('console', {})
        if not console.get('password_configured'):
            parsed.warnings.append("Console password not configured")
        if not console.get('exec_timeout'):
            parsed.warnings.append("Console exec-timeout not configured")

    def generate_diff(self, old_config: str, new_config: str) -> Dict[str, Any]:
        """
        Generate diff between two configurations

        Args:
            old_config: Previous configuration
            new_config: New configuration

        Returns:
            Dictionary with diff information
        """
        import difflib

        old_lines = old_config.strip().split('\n')
        new_lines = new_config.strip().split('\n')

        # Generate unified diff
        diff = list(difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile='old_config',
            tofile='new_config',
            lineterm=''
        ))

        # Analyze changes
        added_lines = []
        removed_lines = []
        changed_sections = set()

        for line in diff:
            if line.startswith('+') and not line.startswith('+++'):
                added_lines.append(line[1:])
                section = self._identify_section(line[1:])
                if section:
                    changed_sections.add(section)
            elif line.startswith('-') and not line.startswith('---'):
                removed_lines.append(line[1:])
                section = self._identify_section(line[1:])
                if section:
                    changed_sections.add(section)

        return {
            'diff': diff,
            'added_lines': added_lines,
            'removed_lines': removed_lines,
            'changed_sections': list(changed_sections),
            'additions': len(added_lines),
            'deletions': len(removed_lines),
            'has_changes': bool(added_lines or removed_lines)
        }

    def _identify_section(self, line: str) -> Optional[str]:
        """Identify configuration section from line"""
        line = line.strip()

        if line.startswith('interface '):
            return 'interfaces'
        elif line.startswith('vlan '):
            return 'vlans'
        elif line.startswith('router ') or line.startswith('ip route'):
            return 'routing'
        elif 'access-list' in line or line.startswith('ip access-list'):
            return 'acls'
        elif line.startswith('line '):
            return 'line_config'
        elif 'spanning-tree' in line:
            return 'spanning_tree'
        elif any(svc in line for svc in ['ssh', 'http', 'snmp', 'ntp', 'cdp', 'lldp']):
            return 'services'
        elif any(sec in line for sec in ['aaa', 'username', 'enable', 'password']):
            return 'security'

        return None

    def to_json(self, parsed_config: ParsedConfig) -> str:
        """Convert parsed configuration to JSON"""
        return json.dumps({
            'os_type': parsed_config.os_type.value,
            'hostname': parsed_config.hostname,
            'version': parsed_config.version,
            'interfaces': parsed_config.interfaces,
            'vlans': parsed_config.vlans,
            'routing': parsed_config.routing,
            'acls': parsed_config.acls,
            'services': parsed_config.services,
            'security': parsed_config.security,
            'hash': parsed_config.hash,
            'parsed_at': parsed_config.parsed_at.isoformat() if parsed_config.parsed_at else None,
            'warnings': parsed_config.warnings,
            'errors': parsed_config.errors
        }, indent=2, default=str)

    def validate_syntax(self, config: str, os_type: CiscoOS = CiscoOS.IOS) -> Tuple[bool, List[str]]:
        """
        Validate configuration syntax

        Args:
            config: Configuration to validate
            os_type: Cisco OS type

        Returns:
            Tuple of (is_valid, errors)
        """
        errors = []
        lines = config.strip().split('\n')

        # Track indentation level
        indent_stack = []
        current_block = None

        for line_num, line in enumerate(lines, 1):
            # Skip comments and empty lines
            if not line.strip() or line.strip().startswith('!'):
                continue

            # Check for invalid characters
            if any(char in line for char in ['<', '>', '&', '|', ';'] if char not in ['!', '#']):
                errors.append(f"Line {line_num}: Contains invalid characters")

            # Check indentation
            indent = len(line) - len(line.lstrip())

            # Validate command structure
            stripped = line.strip()
            parts = stripped.split()

            if not parts:
                continue

            # Check for known command prefixes
            if not self._is_valid_command(parts[0], os_type):
                if current_block is None:  # Only check at global level
                    errors.append(f"Line {line_num}: Unknown command '{parts[0]}'")

        return len(errors) == 0, errors

    def _is_valid_command(self, command: str, os_type: CiscoOS) -> bool:
        """Check if command is valid for the OS type"""
        # Common valid commands across all Cisco OS
        common_commands = {
            'hostname', 'interface', 'vlan', 'ip', 'ipv6', 'router', 'line',
            'access-list', 'crypto', 'class-map', 'policy-map', 'service',
            'enable', 'username', 'aaa', 'snmp-server', 'ntp', 'logging',
            'banner', 'boot', 'spanning-tree', 'cdp', 'lldp', 'monitor',
            'mac', 'arp', 'route-map', 'prefix-list', 'bgp', 'ospf', 'eigrp',
            'rip', 'isis', 'mpls', 'vpn', 'tunnel', 'bridge', 'vrf', 'vtp',
            'channel-group', 'lacp', 'pagp', 'udld', 'bpduguard', 'rootguard',
            'description', 'shutdown', 'no', 'default', 'exit', 'end',
            'switchport', 'speed', 'duplex', 'mtu', 'bandwidth', 'delay',
            'clock', 'timezone', 'summertime', 'ntp', 'dns', 'domain',
            'tftp', 'ftp', 'ssh', 'telnet', 'console', 'vty', 'aux',
            'privilege', 'parser', 'scheduler', 'archive', 'configuration'
        }

        # OS-specific commands
        ios_xe_commands = common_commands | {
            'license', 'diagnostic', 'platform', 'hw-module', 'redundancy',
            'install', 'request', 'wireless', 'ap', 'mobility'
        }

        nx_os_commands = common_commands | {
            'feature', 'vdc', 'vpc', 'fabricpath', 'otv', 'lisp', 'evpn',
            'nve', 'segment-routing', 'system', 'hardware', 'module'
        }

        ios_xr_commands = common_commands | {
            'rpl', 'task', 'taskgroup', 'usergroup', 'aaa', 'diameter',
            'radius', 'tacacs', 'controller', 'l2vpn', 'l3vpn'
        }

        asa_commands = common_commands | {
            'firewall', 'object', 'object-group', 'nat', 'access-group',
            'class', 'inspect', 'fixup', 'filter', 'url-cache', 'threat-detection'
        }

        # Check based on OS type
        if os_type == CiscoOS.IOS:
            return command in common_commands
        elif os_type == CiscoOS.IOS_XE:
            return command in ios_xe_commands
        elif os_type == CiscoOS.NX_OS:
            return command in nx_os_commands
        elif os_type == CiscoOS.IOS_XR:
            return command in ios_xr_commands
        elif os_type == CiscoOS.ASA:
            return command in asa_commands

        return command in common_commands