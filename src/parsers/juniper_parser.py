"""
CatNet Juniper Configuration Parser

Parses and validates Juniper Junos configurations
"""

import re
import json
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import ipaddress
import structlog
from datetime import datetime

logger = structlog.get_logger()


class JunosFormat(Enum):
    """Junos configuration formats"""
    SET = "set"
    HIERARCHICAL = "hierarchical"
    XML = "xml"
    JSON = "json"


class ConfigSection(Enum):
    """Configuration sections in Junos"""
    SYSTEM = "system"
    INTERFACES = "interfaces"
    ROUTING_OPTIONS = "routing-options"
    PROTOCOLS = "protocols"
    SECURITY = "security"
    FIREWALL = "firewall"
    VLANS = "vlans"
    BRIDGE_DOMAINS = "bridge-domains"
    ROUTING_INSTANCES = "routing-instances"
    CLASS_OF_SERVICE = "class-of-service"
    SERVICES = "services"
    CHASSIS = "chassis"
    FORWARDING_OPTIONS = "forwarding-options"


@dataclass
class JunosInterface:
    """Juniper interface configuration"""
    name: str
    description: Optional[str] = None
    unit: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    mtu: Optional[int] = None
    disable: bool = False
    speed: Optional[str] = None
    link_mode: Optional[str] = None
    encapsulation: Optional[str] = None
    vlan_members: List[str] = field(default_factory=list)
    native_vlan_id: Optional[int] = None
    aggregated_ether_options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class JunosSecurityZone:
    """Security zone configuration"""
    name: str
    interfaces: List[str] = field(default_factory=list)
    host_inbound_traffic: Dict[str, List[str]] = field(default_factory=dict)
    address_book: Dict[str, str] = field(default_factory=dict)
    screen: Optional[str] = None


@dataclass
class JunosPolicy:
    """Security policy configuration"""
    name: str
    from_zone: str
    to_zone: str
    match: Dict[str, Any] = field(default_factory=dict)
    then: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ParsedJunosConfig:
    """Parsed Junos configuration"""
    format: JunosFormat
    hostname: Optional[str] = None
    version: Optional[str] = None
    system: Dict[str, Any] = field(default_factory=dict)
    interfaces: Dict[str, JunosInterface] = field(default_factory=dict)
    vlans: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    routing_options: Dict[str, Any] = field(default_factory=dict)
    protocols: Dict[str, Any] = field(default_factory=dict)
    security: Dict[str, Any] = field(default_factory=dict)
    firewall: Dict[str, Any] = field(default_factory=dict)
    routing_instances: Dict[str, Any] = field(default_factory=dict)
    raw_config: str = ""
    hash: Optional[str] = None
    parsed_at: Optional[datetime] = None
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class JuniperConfigParser:
    """Parser for Juniper Junos configurations"""

    def __init__(self):
        self.set_command_pattern = re.compile(r'^set\s+(.+)')
        self.delete_command_pattern = re.compile(r'^delete\s+(.+)')
        self.deactivate_command_pattern = re.compile(r'^deactivate\s+(.+)')
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.ipv6_pattern = re.compile(r'([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')

    def parse(self, config: str) -> ParsedJunosConfig:
        """
        Parse Juniper configuration

        Args:
            config: Raw configuration text

        Returns:
            ParsedJunosConfig object
        """
        # Detect format
        config_format = self._detect_format(config)

        parsed = ParsedJunosConfig(
            format=config_format,
            raw_config=config,
            hash=self._calculate_hash(config),
            parsed_at=datetime.utcnow()
        )

        # Parse based on format
        if config_format == JunosFormat.SET:
            self._parse_set_format(config, parsed)
        elif config_format == JunosFormat.HIERARCHICAL:
            self._parse_hierarchical_format(config, parsed)
        elif config_format == JunosFormat.XML:
            self._parse_xml_format(config, parsed)
        elif config_format == JunosFormat.JSON:
            self._parse_json_format(config, parsed)
        else:
            parsed.errors.append("Unknown configuration format")

        # Validate configuration
        self._validate_config(parsed)

        return parsed

    def _detect_format(self, config: str) -> JunosFormat:
        """Detect configuration format"""
        config = config.strip()

        if config.startswith('set ') or 'set ' in config[:100]:
            return JunosFormat.SET
        elif config.startswith('<?xml') or '<configuration>' in config[:100]:
            return JunosFormat.XML
        elif config.startswith('{') and '"configuration"' in config[:100]:
            return JunosFormat.JSON
        else:
            # Assume hierarchical if not other formats
            return JunosFormat.HIERARCHICAL

    def _calculate_hash(self, config: str) -> str:
        """Calculate configuration hash"""
        # Remove comments and blank lines
        cleaned = '\n'.join(
            line for line in config.split('\n')
            if line.strip() and not line.strip().startswith('#')
        )
        return hashlib.sha256(cleaned.encode()).hexdigest()

    def _parse_set_format(self, config: str, parsed: ParsedJunosConfig):
        """Parse set format configuration"""
        lines = config.strip().split('\n')

        for line in lines:
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue

            # Match set commands
            match = self.set_command_pattern.match(line)
            if match:
                command = match.group(1)
                self._process_set_command(command, parsed)

    def _process_set_command(self, command: str, parsed: ParsedJunosConfig):
        """Process a single set command"""
        parts = command.split()
        if not parts:
            return

        # System configuration
        if parts[0] == 'system':
            self._parse_system_command(parts[1:], parsed)

        # Interface configuration
        elif parts[0] == 'interfaces':
            self._parse_interface_command(parts[1:], parsed)

        # VLAN configuration
        elif parts[0] == 'vlans':
            self._parse_vlan_command(parts[1:], parsed)

        # Routing options
        elif parts[0] == 'routing-options':
            self._parse_routing_options_command(parts[1:], parsed)

        # Protocol configuration
        elif parts[0] == 'protocols':
            self._parse_protocol_command(parts[1:], parsed)

        # Security configuration
        elif parts[0] == 'security':
            self._parse_security_command(parts[1:], parsed)

        # Firewall configuration
        elif parts[0] == 'firewall':
            self._parse_firewall_command(parts[1:], parsed)

        # Routing instances
        elif parts[0] == 'routing-instances':
            self._parse_routing_instance_command(parts[1:], parsed)

    def _parse_system_command(self, parts: List[str], parsed: ParsedJunosConfig):
        """Parse system commands"""
        if not parts:
            return

        if parts[0] == 'host-name' and len(parts) > 1:
            parsed.hostname = parts[1]

        elif parts[0] == 'domain-name' and len(parts) > 1:
            parsed.system['domain_name'] = parts[1]

        elif parts[0] == 'name-server' and len(parts) > 1:
            if 'name_servers' not in parsed.system:
                parsed.system['name_servers'] = []
            parsed.system['name_servers'].append(parts[1])

        elif parts[0] == 'ntp' and len(parts) > 1:
            if 'ntp_servers' not in parsed.system:
                parsed.system['ntp_servers'] = []
            if parts[1] == 'server' and len(parts) > 2:
                parsed.system['ntp_servers'].append(parts[2])

        elif parts[0] == 'login':
            if 'login' not in parsed.system:
                parsed.system['login'] = {}
            if len(parts) > 1:
                if parts[1] == 'user' and len(parts) > 2:
                    username = parts[2]
                    if 'users' not in parsed.system['login']:
                        parsed.system['login']['users'] = {}
                    if username not in parsed.system['login']['users']:
                        parsed.system['login']['users'][username] = {}
                    # Parse user attributes
                    if len(parts) > 3:
                        if parts[3] == 'class' and len(parts) > 4:
                            parsed.system['login']['users'][username]['class'] = parts[4]
                        elif parts[3] == 'uid' and len(parts) > 4:
                            parsed.system['login']['users'][username]['uid'] = parts[4]

        elif parts[0] == 'services':
            if 'services' not in parsed.system:
                parsed.system['services'] = {}
            if len(parts) > 1:
                service = parts[1]
                if service not in parsed.system['services']:
                    parsed.system['services'][service] = {}
                if len(parts) > 2:
                    parsed.system['services'][service][parts[2]] = True

        elif parts[0] == 'syslog':
            if 'syslog' not in parsed.system:
                parsed.system['syslog'] = {}
            if len(parts) > 1:
                if parts[1] == 'host' and len(parts) > 2:
                    if 'hosts' not in parsed.system['syslog']:
                        parsed.system['syslog']['hosts'] = []
                    parsed.system['syslog']['hosts'].append(parts[2])
                elif parts[1] == 'file' and len(parts) > 2:
                    if 'files' not in parsed.system['syslog']:
                        parsed.system['syslog']['files'] = {}
                    filename = parts[2]
                    parsed.system['syslog']['files'][filename] = {}

    def _parse_interface_command(self, parts: List[str], parsed: ParsedJunosConfig):
        """Parse interface commands"""
        if not parts:
            return

        # Interface name is first part
        iface_name = parts[0]

        # Create interface if not exists
        if iface_name not in parsed.interfaces:
            parsed.interfaces[iface_name] = JunosInterface(name=iface_name)

        interface = parsed.interfaces[iface_name]

        # Parse interface attributes
        if len(parts) > 1:
            if parts[1] == 'unit' and len(parts) > 2:
                unit_num = int(parts[2])
                if unit_num not in interface.unit:
                    interface.unit[unit_num] = {}

                # Parse unit configuration
                if len(parts) > 3:
                    if parts[3] == 'description' and len(parts) > 4:
                        interface.unit[unit_num]['description'] = ' '.join(parts[4:])
                    elif parts[3] == 'vlan-id' and len(parts) > 4:
                        interface.unit[unit_num]['vlan_id'] = int(parts[4])
                    elif parts[3] == 'family' and len(parts) > 4:
                        family = parts[4]
                        if 'family' not in interface.unit[unit_num]:
                            interface.unit[unit_num]['family'] = {}
                        if family not in interface.unit[unit_num]['family']:
                            interface.unit[unit_num]['family'][family] = {}

                        # Parse family configuration
                        if len(parts) > 5:
                            if parts[5] == 'address' and len(parts) > 6:
                                if 'addresses' not in interface.unit[unit_num]['family'][family]:
                                    interface.unit[unit_num]['family'][family]['addresses'] = []
                                interface.unit[unit_num]['family'][family]['addresses'].append(parts[6])

            elif parts[1] == 'description' and len(parts) > 2:
                interface.description = ' '.join(parts[2:])

            elif parts[1] == 'mtu' and len(parts) > 2:
                interface.mtu = int(parts[2])

            elif parts[1] == 'disable':
                interface.disable = True

            elif parts[1] == 'speed' and len(parts) > 2:
                interface.speed = parts[2]

            elif parts[1] == 'link-mode' and len(parts) > 2:
                interface.link_mode = parts[2]

            elif parts[1] == 'encapsulation' and len(parts) > 2:
                interface.encapsulation = parts[2]

            elif parts[1] == 'native-vlan-id' and len(parts) > 2:
                interface.native_vlan_id = int(parts[2])

            elif parts[1] == 'vlan' and len(parts) > 2:
                if parts[2] == 'members':
                    interface.vlan_members.extend(parts[3:])

            elif parts[1] == 'aggregated-ether-options':
                if len(parts) > 2:
                    if parts[2] == 'lacp' and len(parts) > 3:
                        if 'lacp' not in interface.aggregated_ether_options:
                            interface.aggregated_ether_options['lacp'] = {}
                        if parts[3] == 'active':
                            interface.aggregated_ether_options['lacp']['active'] = True
                        elif parts[3] == 'passive':
                            interface.aggregated_ether_options['lacp']['passive'] = True

    def _parse_vlan_command(self, parts: List[str], parsed: ParsedJunosConfig):
        """Parse VLAN commands"""
        if not parts:
            return

        vlan_name = parts[0]

        if vlan_name not in parsed.vlans:
            parsed.vlans[vlan_name] = {}

        vlan = parsed.vlans[vlan_name]

        if len(parts) > 1:
            if parts[1] == 'vlan-id' and len(parts) > 2:
                vlan['vlan_id'] = int(parts[2])
            elif parts[1] == 'description' and len(parts) > 2:
                vlan['description'] = ' '.join(parts[2:])
            elif parts[1] == 'interface' and len(parts) > 2:
                if 'interfaces' not in vlan:
                    vlan['interfaces'] = []
                vlan['interfaces'].append(parts[2])
            elif parts[1] == 'l3-interface' and len(parts) > 2:
                vlan['l3_interface'] = parts[2]

    def _parse_routing_options_command(self, parts: List[str], parsed: ParsedJunosConfig):
        """Parse routing-options commands"""
        if not parts:
            return

        if parts[0] == 'static' and len(parts) > 1:
            if 'static_routes' not in parsed.routing_options:
                parsed.routing_options['static_routes'] = []

            if parts[1] == 'route' and len(parts) > 2:
                route = {'destination': parts[2]}
                if len(parts) > 3:
                    if parts[3] == 'next-hop' and len(parts) > 4:
                        route['next_hop'] = parts[4]
                    elif parts[3] == 'discard':
                        route['discard'] = True
                    elif parts[3] == 'reject':
                        route['reject'] = True
                parsed.routing_options['static_routes'].append(route)

        elif parts[0] == 'router-id' and len(parts) > 1:
            parsed.routing_options['router_id'] = parts[1]

        elif parts[0] == 'autonomous-system' and len(parts) > 1:
            parsed.routing_options['autonomous_system'] = parts[1]

        elif parts[0] == 'graceful-restart':
            parsed.routing_options['graceful_restart'] = True

    def _parse_protocol_command(self, parts: List[str], parsed: ParsedJunosConfig):
        """Parse protocol commands"""
        if not parts:
            return

        protocol = parts[0]

        if protocol not in parsed.protocols:
            parsed.protocols[protocol] = {}

        # OSPF configuration
        if protocol == 'ospf' and len(parts) > 1:
            if parts[1] == 'area' and len(parts) > 2:
                area = parts[2]
                if 'areas' not in parsed.protocols['ospf']:
                    parsed.protocols['ospf']['areas'] = {}
                if area not in parsed.protocols['ospf']['areas']:
                    parsed.protocols['ospf']['areas'][area] = {}

                if len(parts) > 3:
                    if parts[3] == 'interface' and len(parts) > 4:
                        if 'interfaces' not in parsed.protocols['ospf']['areas'][area]:
                            parsed.protocols['ospf']['areas'][area]['interfaces'] = []
                        parsed.protocols['ospf']['areas'][area]['interfaces'].append(parts[4])

        # BGP configuration
        elif protocol == 'bgp' and len(parts) > 1:
            if parts[1] == 'group' and len(parts) > 2:
                group_name = parts[2]
                if 'groups' not in parsed.protocols['bgp']:
                    parsed.protocols['bgp']['groups'] = {}
                if group_name not in parsed.protocols['bgp']['groups']:
                    parsed.protocols['bgp']['groups'][group_name] = {}

                if len(parts) > 3:
                    if parts[3] == 'type' and len(parts) > 4:
                        parsed.protocols['bgp']['groups'][group_name]['type'] = parts[4]
                    elif parts[3] == 'peer-as' and len(parts) > 4:
                        parsed.protocols['bgp']['groups'][group_name]['peer_as'] = parts[4]
                    elif parts[3] == 'neighbor' and len(parts) > 4:
                        if 'neighbors' not in parsed.protocols['bgp']['groups'][group_name]:
                            parsed.protocols['bgp']['groups'][group_name]['neighbors'] = []
                        parsed.protocols['bgp']['groups'][group_name]['neighbors'].append(parts[4])

        # LLDP configuration
        elif protocol == 'lldp' and len(parts) > 1:
            if parts[1] == 'interface' and len(parts) > 2:
                if 'interfaces' not in parsed.protocols['lldp']:
                    parsed.protocols['lldp']['interfaces'] = []
                parsed.protocols['lldp']['interfaces'].append(parts[2])

        # STP configuration
        elif protocol in ['rstp', 'mstp', 'vstp'] and len(parts) > 1:
            if parts[1] == 'interface' and len(parts) > 2:
                if 'interfaces' not in parsed.protocols[protocol]:
                    parsed.protocols[protocol]['interfaces'] = {}
                interface = parts[2]
                parsed.protocols[protocol]['interfaces'][interface] = {}

                if len(parts) > 3:
                    if parts[3] == 'cost' and len(parts) > 4:
                        parsed.protocols[protocol]['interfaces'][interface]['cost'] = int(parts[4])
                    elif parts[3] == 'priority' and len(parts) > 4:
                        parsed.protocols[protocol]['interfaces'][interface]['priority'] = int(parts[4])

    def _parse_security_command(self, parts: List[str], parsed: ParsedJunosConfig):
        """Parse security commands"""
        if not parts:
            return

        if 'security' not in parsed.security:
            parsed.security = {}

        # Security zones
        if parts[0] == 'zones' and len(parts) > 1:
            if 'zones' not in parsed.security:
                parsed.security['zones'] = {}

            if parts[1] == 'security-zone' and len(parts) > 2:
                zone_name = parts[2]
                if zone_name not in parsed.security['zones']:
                    parsed.security['zones'][zone_name] = JunosSecurityZone(name=zone_name)

                zone = parsed.security['zones'][zone_name]

                if len(parts) > 3:
                    if parts[3] == 'interfaces' and len(parts) > 4:
                        zone.interfaces.append(parts[4])
                    elif parts[3] == 'host-inbound-traffic' and len(parts) > 4:
                        if parts[4] == 'system-services' and len(parts) > 5:
                            if 'system-services' not in zone.host_inbound_traffic:
                                zone.host_inbound_traffic['system-services'] = []
                            zone.host_inbound_traffic['system-services'].append(parts[5])
                        elif parts[4] == 'protocols' and len(parts) > 5:
                            if 'protocols' not in zone.host_inbound_traffic:
                                zone.host_inbound_traffic['protocols'] = []
                            zone.host_inbound_traffic['protocols'].append(parts[5])

        # Security policies
        elif parts[0] == 'policies' and len(parts) > 1:
            if 'policies' not in parsed.security:
                parsed.security['policies'] = []

            if parts[1] == 'from-zone' and len(parts) > 4:
                from_zone = parts[2]
                to_zone = parts[4] if parts[3] == 'to-zone' else None

                if to_zone and len(parts) > 5 and parts[5] == 'policy' and len(parts) > 6:
                    policy_name = parts[6]
                    policy = JunosPolicy(
                        name=policy_name,
                        from_zone=from_zone,
                        to_zone=to_zone
                    )

                    if len(parts) > 7:
                        if parts[7] == 'match' and len(parts) > 8:
                            if parts[8] == 'source-address' and len(parts) > 9:
                                policy.match['source_address'] = parts[9]
                            elif parts[8] == 'destination-address' and len(parts) > 9:
                                policy.match['destination_address'] = parts[9]
                            elif parts[8] == 'application' and len(parts) > 9:
                                policy.match['application'] = parts[9]
                        elif parts[7] == 'then' and len(parts) > 8:
                            policy.then['action'] = parts[8]

                    parsed.security['policies'].append(policy)

        # NAT configuration
        elif parts[0] == 'nat' and len(parts) > 1:
            if 'nat' not in parsed.security:
                parsed.security['nat'] = {}

            if parts[1] == 'source' and len(parts) > 2:
                if 'source' not in parsed.security['nat']:
                    parsed.security['nat']['source'] = {}

                if parts[2] == 'rule-set' and len(parts) > 3:
                    ruleset_name = parts[3]
                    if 'rule_sets' not in parsed.security['nat']['source']:
                        parsed.security['nat']['source']['rule_sets'] = {}
                    if ruleset_name not in parsed.security['nat']['source']['rule_sets']:
                        parsed.security['nat']['source']['rule_sets'][ruleset_name] = {}

    def _parse_firewall_command(self, parts: List[str], parsed: ParsedJunosConfig):
        """Parse firewall commands"""
        if not parts:
            return

        if parts[0] == 'family' and len(parts) > 1:
            family = parts[1]  # inet, inet6, ethernet-switching, etc.
            if family not in parsed.firewall:
                parsed.firewall[family] = {}

            if len(parts) > 2 and parts[2] == 'filter' and len(parts) > 3:
                filter_name = parts[3]
                if 'filters' not in parsed.firewall[family]:
                    parsed.firewall[family]['filters'] = {}
                if filter_name not in parsed.firewall[family]['filters']:
                    parsed.firewall[family]['filters'][filter_name] = {'terms': []}

                if len(parts) > 4 and parts[4] == 'term' and len(parts) > 5:
                    term_name = parts[5]
                    term = {'name': term_name}

                    if len(parts) > 6:
                        if parts[6] == 'from' and len(parts) > 7:
                            if 'from' not in term:
                                term['from'] = {}
                            if parts[7] == 'source-address' and len(parts) > 8:
                                term['from']['source_address'] = parts[8]
                            elif parts[7] == 'destination-address' and len(parts) > 8:
                                term['from']['destination_address'] = parts[8]
                            elif parts[7] == 'protocol' and len(parts) > 8:
                                term['from']['protocol'] = parts[8]
                        elif parts[6] == 'then' and len(parts) > 7:
                            if 'then' not in term:
                                term['then'] = {}
                            term['then']['action'] = parts[7]

                    parsed.firewall[family]['filters'][filter_name]['terms'].append(term)

    def _parse_routing_instance_command(self, parts: List[str], parsed: ParsedJunosConfig):
        """Parse routing-instance commands"""
        if not parts:
            return

        instance_name = parts[0]
        if instance_name not in parsed.routing_instances:
            parsed.routing_instances[instance_name] = {}

        instance = parsed.routing_instances[instance_name]

        if len(parts) > 1:
            if parts[1] == 'instance-type' and len(parts) > 2:
                instance['type'] = parts[2]
            elif parts[1] == 'interface' and len(parts) > 2:
                if 'interfaces' not in instance:
                    instance['interfaces'] = []
                instance['interfaces'].append(parts[2])
            elif parts[1] == 'route-distinguisher' and len(parts) > 2:
                instance['route_distinguisher'] = parts[2]
            elif parts[1] == 'vrf-target' and len(parts) > 2:
                if 'vrf_targets' not in instance:
                    instance['vrf_targets'] = []
                instance['vrf_targets'].append(' '.join(parts[2:]))

    def _parse_hierarchical_format(self, config: str, parsed: ParsedJunosConfig):
        """Parse hierarchical format configuration"""
        # This would require a more complex parser for hierarchical format
        # For now, we'll add a warning
        parsed.warnings.append("Hierarchical format parsing not fully implemented")

    def _parse_xml_format(self, config: str, parsed: ParsedJunosConfig):
        """Parse XML format configuration"""
        try:
            root = ET.fromstring(config)

            # Parse system configuration
            system = root.find('.//system')
            if system is not None:
                hostname = system.find('host-name')
                if hostname is not None:
                    parsed.hostname = hostname.text

                domain = system.find('domain-name')
                if domain is not None:
                    parsed.system['domain_name'] = domain.text

            # Parse interfaces
            interfaces = root.find('.//interfaces')
            if interfaces is not None:
                for interface in interfaces.findall('interface'):
                    name = interface.find('name')
                    if name is not None:
                        iface = JunosInterface(name=name.text)

                        desc = interface.find('description')
                        if desc is not None:
                            iface.description = desc.text

                        parsed.interfaces[name.text] = iface

        except ET.ParseError as e:
            parsed.errors.append(f"XML parsing error: {e}")

    def _parse_json_format(self, config: str, parsed: ParsedJunosConfig):
        """Parse JSON format configuration"""
        try:
            config_json = json.loads(config)

            if 'configuration' in config_json:
                conf = config_json['configuration']

                # Parse system
                if 'system' in conf:
                    system = conf['system']
                    if 'host-name' in system:
                        parsed.hostname = system['host-name']
                    if 'domain-name' in system:
                        parsed.system['domain_name'] = system['domain-name']

                # Parse interfaces
                if 'interfaces' in conf:
                    for interface in conf['interfaces']:
                        if 'name' in interface:
                            iface = JunosInterface(name=interface['name'])
                            if 'description' in interface:
                                iface.description = interface['description']
                            parsed.interfaces[interface['name']] = iface

        except json.JSONDecodeError as e:
            parsed.errors.append(f"JSON parsing error: {e}")

    def _validate_config(self, parsed: ParsedJunosConfig):
        """Validate parsed configuration"""

        # Check hostname
        if not parsed.hostname:
            parsed.warnings.append("No hostname configured")

        # Check system services
        if 'services' in parsed.system:
            services = parsed.system['services']
            if 'telnet' in services:
                parsed.warnings.append("Telnet is enabled, consider using SSH only")
            if 'ftp' in services:
                parsed.warnings.append("FTP is enabled, consider using SFTP/SCP")
            if 'http' in services:
                parsed.warnings.append("HTTP is enabled, consider using HTTPS only")

        # Check for root authentication
        if 'login' in parsed.system and 'users' in parsed.system['login']:
            if 'root' not in parsed.system['login']['users']:
                parsed.warnings.append("Root authentication not configured")

        # Check NTP servers
        if 'ntp_servers' not in parsed.system or not parsed.system.get('ntp_servers'):
            parsed.warnings.append("No NTP servers configured")

        # Check interfaces
        active_interfaces = sum(
            1 for iface in parsed.interfaces.values()
            if not iface.disable
        )
        if active_interfaces == 0:
            parsed.warnings.append("No interfaces are active")

        # Check routing
        if not parsed.routing_options.get('static_routes') and not parsed.protocols:
            parsed.warnings.append("No routing configured")

        # Check security zones (for SRX devices)
        if parsed.security and 'zones' in parsed.security:
            zones = parsed.security['zones']
            if not zones:
                parsed.warnings.append("No security zones configured")
            else:
                # Check for untrust zone without policies
                if 'untrust' in zones and not parsed.security.get('policies'):
                    parsed.warnings.append("Untrust zone configured but no security policies defined")

        # Check firewall filters
        if not parsed.firewall:
            parsed.warnings.append("No firewall filters configured")

    def generate_diff(self, old_config: str, new_config: str) -> Dict[str, Any]:
        """Generate diff between two configurations"""
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
        added_commands = []
        deleted_commands = []
        changed_sections = set()

        for line in diff:
            if line.startswith('+') and not line.startswith('+++'):
                added_commands.append(line[1:])
                section = self._identify_section_from_set(line[1:])
                if section:
                    changed_sections.add(section)
            elif line.startswith('-') and not line.startswith('---'):
                deleted_commands.append(line[1:])
                section = self._identify_section_from_set(line[1:])
                if section:
                    changed_sections.add(section)

        return {
            'diff': diff,
            'added_commands': added_commands,
            'deleted_commands': deleted_commands,
            'changed_sections': list(changed_sections),
            'additions': len(added_commands),
            'deletions': len(deleted_commands),
            'has_changes': bool(added_commands or deleted_commands)
        }

    def _identify_section_from_set(self, command: str) -> Optional[str]:
        """Identify configuration section from set command"""
        if command.startswith('set '):
            parts = command[4:].split()
            if parts:
                return parts[0]
        return None

    def to_json(self, parsed_config: ParsedJunosConfig) -> str:
        """Convert parsed configuration to JSON"""
        return json.dumps({
            'format': parsed_config.format.value,
            'hostname': parsed_config.hostname,
            'version': parsed_config.version,
            'system': parsed_config.system,
            'interfaces': {
                name: {
                    'name': iface.name,
                    'description': iface.description,
                    'unit': iface.unit,
                    'mtu': iface.mtu,
                    'disable': iface.disable,
                    'speed': iface.speed,
                    'link_mode': iface.link_mode,
                    'encapsulation': iface.encapsulation,
                    'vlan_members': iface.vlan_members,
                    'native_vlan_id': iface.native_vlan_id
                }
                for name, iface in parsed_config.interfaces.items()
            },
            'vlans': parsed_config.vlans,
            'routing_options': parsed_config.routing_options,
            'protocols': parsed_config.protocols,
            'security': self._serialize_security(parsed_config.security),
            'firewall': parsed_config.firewall,
            'routing_instances': parsed_config.routing_instances,
            'hash': parsed_config.hash,
            'parsed_at': parsed_config.parsed_at.isoformat() if parsed_config.parsed_at else None,
            'warnings': parsed_config.warnings,
            'errors': parsed_config.errors
        }, indent=2, default=str)

    def _serialize_security(self, security: Dict[str, Any]) -> Dict[str, Any]:
        """Serialize security configuration"""
        serialized = {}

        for key, value in security.items():
            if key == 'zones' and isinstance(value, dict):
                serialized['zones'] = {}
                for zone_name, zone in value.items():
                    if isinstance(zone, JunosSecurityZone):
                        serialized['zones'][zone_name] = {
                            'name': zone.name,
                            'interfaces': zone.interfaces,
                            'host_inbound_traffic': zone.host_inbound_traffic,
                            'address_book': zone.address_book,
                            'screen': zone.screen
                        }
                    else:
                        serialized['zones'][zone_name] = zone
            elif key == 'policies' and isinstance(value, list):
                serialized['policies'] = []
                for policy in value:
                    if isinstance(policy, JunosPolicy):
                        serialized['policies'].append({
                            'name': policy.name,
                            'from_zone': policy.from_zone,
                            'to_zone': policy.to_zone,
                            'match': policy.match,
                            'then': policy.then
                        })
                    else:
                        serialized['policies'].append(policy)
            else:
                serialized[key] = value

        return serialized

    def validate_syntax(self, config: str) -> Tuple[bool, List[str]]:
        """Validate Junos configuration syntax"""
        errors = []
        config_format = self._detect_format(config)

        if config_format == JunosFormat.SET:
            lines = config.strip().split('\n')
            for line_num, line in enumerate(lines, 1):
                line = line.strip()

                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue

                # Check for set/delete/deactivate commands
                if not (line.startswith('set ') or
                        line.startswith('delete ') or
                        line.startswith('deactivate ')):
                    errors.append(f"Line {line_num}: Invalid command format")
                    continue

                # Basic syntax validation
                if line.startswith('set '):
                    parts = line[4:].split()
                    if not parts:
                        errors.append(f"Line {line_num}: Empty set command")
                    elif parts[0] not in self._get_valid_top_level_statements():
                        errors.append(f"Line {line_num}: Unknown top-level statement '{parts[0]}'")

        elif config_format == JunosFormat.XML:
            try:
                ET.fromstring(config)
            except ET.ParseError as e:
                errors.append(f"XML parsing error: {e}")

        elif config_format == JunosFormat.JSON:
            try:
                json.loads(config)
            except json.JSONDecodeError as e:
                errors.append(f"JSON parsing error: {e}")

        return len(errors) == 0, errors

    def _get_valid_top_level_statements(self) -> Set[str]:
        """Get valid top-level Junos statements"""
        return {
            'system', 'interfaces', 'routing-options', 'protocols',
            'policy-options', 'class-of-service', 'firewall', 'security',
            'services', 'vlans', 'bridge-domains', 'routing-instances',
            'chassis', 'forwarding-options', 'snmp', 'event-options',
            'access', 'applications', 'multi-chassis', 'redundant-power-system',
            'poe', 'virtual-chassis', 'ethernet-switching-options', 'groups'
        }