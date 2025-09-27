"""
Configuration parser for GitOps integration.
Parses various configuration formats and converts them to CatNet internal format.
"""

import re
import json
import yaml
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
from datetime import datetime
from enum import Enum
import asyncio

from src.core.exceptions import ConfigurationError, ParsingError
from src.security.audit import AuditLogger


class ConfigFormat(Enum):
    """Supported configuration formats."""
    CISCO_IOS = "cisco_ios"
    CISCO_NXOS = "cisco_nxos"
    CISCO_XR = "cisco_xr"
    JUNIPER_JUNOS = "juniper_junos"
    JUNIPER_SET = "juniper_set"
    YAML = "yaml"
    JSON = "json"
    XML = "xml"
    NATIVE = "native"


class ConfigurationParser:
    """
    Universal configuration parser for multiple vendors and formats.
    Converts various configuration formats to standardized CatNet format.
    """

    def __init__(self):
        """Initialize configuration parser."""
        self.audit = AuditLogger()
        self.parsers = {
            ConfigFormat.CISCO_IOS: self._parse_cisco_ios,
            ConfigFormat.CISCO_NXOS: self._parse_cisco_nxos,
            ConfigFormat.CISCO_XR: self._parse_cisco_xr,
            ConfigFormat.JUNIPER_JUNOS: self._parse_juniper_junos,
            ConfigFormat.JUNIPER_SET: self._parse_juniper_set,
            ConfigFormat.YAML: self._parse_yaml,
            ConfigFormat.JSON: self._parse_json,
            ConfigFormat.XML: self._parse_xml,
            ConfigFormat.NATIVE: self._parse_native
        }

    async def parse_configuration(
        self,
        content: str,
        format: Optional[ConfigFormat] = None,
        metadata: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Parse configuration content.

        Args:
            content: Configuration content to parse
            format: Configuration format (auto-detect if None)
            metadata: Additional metadata

        Returns:
            Parsed configuration in CatNet format
        """
        # Auto-detect format if not specified
        if format is None:
            format = self._detect_format(content)

        if format not in self.parsers:
            raise ParsingError(f"Unsupported configuration format: {format}")

        try:
            # Parse configuration
            parser = self.parsers[format]
            parsed_config = await parser(content)

            # Add metadata
            parsed_config['metadata'] = {
                'format': format.value,
                'parsed_at': datetime.utcnow().isoformat(),
                'parser_version': '1.0.0',
                **(metadata or {})
            }

            # Validate parsed configuration
            self._validate_parsed_config(parsed_config)

            await self.audit.log_event(
                event_type="CONFIGURATION_PARSED",
                details={
                    'format': format.value,
                    'size': len(content),
                    'elements': len(parsed_config.get('elements', []))
                }
            )

            return parsed_config

        except Exception as e:
            raise ParsingError(f"Failed to parse configuration: {e}")

    def _detect_format(self, content: str) -> ConfigFormat:
        """
        Auto-detect configuration format.

        Args:
            content: Configuration content

        Returns:
            Detected configuration format
        """
        # Try structured formats first
        if content.strip().startswith('{'):
            return ConfigFormat.JSON
        if content.strip().startswith('---') or ':' in content[:100]:
            return ConfigFormat.YAML
        if content.strip().startswith('<'):
            return ConfigFormat.XML

        # Detect vendor-specific formats
        if re.search(r'^set\s+', content, re.MULTILINE):
            return ConfigFormat.JUNIPER_SET
        if re.search(r'^\s*<.*>\s*$', content, re.MULTILINE):
            return ConfigFormat.JUNIPER_JUNOS
        if 'configure terminal' in content or 'interface ' in content:
            return ConfigFormat.CISCO_IOS
        if 'feature ' in content or 'vdc ' in content:
            return ConfigFormat.CISCO_NXOS

        # Default to native format
        return ConfigFormat.NATIVE

    async def _parse_cisco_ios(self, content: str) -> Dict[str, Any]:
        """Parse Cisco IOS configuration."""
        config = {
            'vendor': 'cisco',
            'platform': 'ios',
            'elements': [],
            'interfaces': {},
            'routing': {},
            'acls': {},
            'services': {}
        }

        current_context = []
        current_element = None

        for line in content.split('\n'):
            line = line.rstrip()

            if not line or line.startswith('!'):
                continue

            # Calculate indentation level
            indent = len(line) - len(line.lstrip())

            # Update context based on indentation
            while current_context and len(current_context) > indent // 1:
                current_context.pop()

            # Parse different configuration sections
            if line.startswith('hostname'):
                config['hostname'] = line.split()[1]

            elif line.startswith('interface'):
                interface_name = line.replace('interface ', '')
                current_element = {
                    'type': 'interface',
                    'name': interface_name,
                    'configuration': []
                }
                config['interfaces'][interface_name] = current_element
                current_context = ['interface']

            elif line.startswith('router'):
                protocol = line.split()[1]
                current_element = {
                    'type': 'routing',
                    'protocol': protocol,
                    'configuration': []
                }
                config['routing'][protocol] = current_element
                current_context = ['router']

            elif line.startswith('ip access-list'):
                parts = line.split()
                acl_type = parts[2] if len(parts) > 2 else 'standard'
                acl_name = parts[3] if len(parts) > 3 else 'unnamed'
                current_element = {
                    'type': 'acl',
                    'acl_type': acl_type,
                    'name': acl_name,
                    'rules': []
                }
                config['acls'][acl_name] = current_element
                current_context = ['acl']

            elif current_context:
                # Add to current context
                if current_element:
                    if current_context[0] == 'interface':
                        current_element['configuration'].append(line.strip())
                    elif current_context[0] == 'router':
                        current_element['configuration'].append(line.strip())
                    elif current_context[0] == 'acl':
                        current_element['rules'].append(line.strip())

            else:
                # Global configuration
                config['elements'].append({
                    'type': 'global',
                    'command': line
                })

        return config

    async def _parse_cisco_nxos(self, content: str) -> Dict[str, Any]:
        """Parse Cisco NX-OS configuration."""
        config = {
            'vendor': 'cisco',
            'platform': 'nxos',
            'elements': [],
            'features': [],
            'vlans': {},
            'interfaces': {},
            'vrfs': {}
        }

        for line in content.split('\n'):
            line = line.strip()

            if not line or line.startswith('!'):
                continue

            if line.startswith('feature'):
                feature = line.split()[1]
                config['features'].append(feature)

            elif line.startswith('vlan'):
                vlan_id = line.split()[1]
                config['vlans'][vlan_id] = {'id': vlan_id, 'configuration': []}

            elif line.startswith('interface'):
                interface_name = line.replace('interface ', '')
                config['interfaces'][interface_name] = {
                    'name': interface_name,
                    'configuration': []
                }

            elif line.startswith('vrf context'):
                vrf_name = line.replace('vrf context ', '')
                config['vrfs'][vrf_name] = {
                    'name': vrf_name,
                    'configuration': []
                }

            else:
                config['elements'].append({
                    'type': 'command',
                    'value': line
                })

        return config

    async def _parse_cisco_xr(self, content: str) -> Dict[str, Any]:
        """Parse Cisco IOS-XR configuration."""
        config = {
            'vendor': 'cisco',
            'platform': 'ios-xr',
            'elements': [],
            'commit_history': [],
            'interfaces': {},
            'routing': {}
        }

        # IOS-XR specific parsing
        in_interface = False
        current_interface = None

        for line in content.split('\n'):
            line = line.strip()

            if not line or line.startswith('!'):
                continue

            if line.startswith('interface'):
                interface_name = line.replace('interface ', '')
                in_interface = True
                current_interface = interface_name
                config['interfaces'][interface_name] = {
                    'name': interface_name,
                    'configuration': []
                }

            elif in_interface and line == 'exit':
                in_interface = False
                current_interface = None

            elif in_interface and current_interface:
                config['interfaces'][current_interface]['configuration'].append(line)

            elif line.startswith('router'):
                protocol = line.split()[1]
                config['routing'][protocol] = {
                    'protocol': protocol,
                    'configuration': []
                }

            else:
                config['elements'].append({
                    'type': 'command',
                    'value': line
                })

        return config

    async def _parse_juniper_junos(self, content: str) -> Dict[str, Any]:
        """Parse Juniper Junos hierarchical configuration."""
        config = {
            'vendor': 'juniper',
            'platform': 'junos',
            'elements': [],
            'hierarchy': {}
        }

        # Build configuration hierarchy
        current_path = []
        current_level = config['hierarchy']

        for line in content.split('\n'):
            line = line.rstrip()

            if not line or line.startswith('#'):
                continue

            # Calculate indentation
            indent = len(line) - len(line.lstrip())
            line = line.strip()

            # Handle hierarchy navigation
            if line.endswith('{'):
                # Entering new level
                key = line[:-1].strip()
                if key not in current_level:
                    current_level[key] = {}
                current_path.append(key)
                current_level = current_level[key]

            elif line == '}':
                # Exiting level
                if current_path:
                    current_path.pop()
                    current_level = config['hierarchy']
                    for key in current_path:
                        current_level = current_level[key]

            elif ';' in line:
                # Leaf statement
                statement = line.replace(';', '').strip()
                parts = statement.split(' ', 1)
                if len(parts) == 2:
                    current_level[parts[0]] = parts[1]
                else:
                    current_level[statement] = True

        # Flatten hierarchy for easier processing
        self._flatten_hierarchy(config['hierarchy'], config['elements'])

        return config

    async def _parse_juniper_set(self, content: str) -> Dict[str, Any]:
        """Parse Juniper set commands."""
        config = {
            'vendor': 'juniper',
            'platform': 'junos',
            'format': 'set',
            'elements': [],
            'commands': []
        }

        for line in content.split('\n'):
            line = line.strip()

            if not line or line.startswith('#'):
                continue

            if line.startswith('set'):
                # Parse set command
                parts = line.split()
                if len(parts) > 1:
                    path = parts[1:]
                    config['commands'].append({
                        'action': 'set',
                        'path': path,
                        'full_command': line
                    })

            elif line.startswith('delete'):
                # Parse delete command
                parts = line.split()
                if len(parts) > 1:
                    path = parts[1:]
                    config['commands'].append({
                        'action': 'delete',
                        'path': path,
                        'full_command': line
                    })

            config['elements'].append({
                'type': 'command',
                'value': line
            })

        return config

    async def _parse_yaml(self, content: str) -> Dict[str, Any]:
        """Parse YAML configuration."""
        try:
            data = yaml.safe_load(content)

            config = {
                'format': 'yaml',
                'elements': [],
                'data': data
            }

            # Extract vendor and platform if present
            if isinstance(data, dict):
                config['vendor'] = data.get('vendor', 'generic')
                config['platform'] = data.get('platform', 'unknown')

                # Process configuration elements
                if 'configuration' in data:
                    config['elements'] = self._process_yaml_configuration(data['configuration'])

            return config

        except yaml.YAMLError as e:
            raise ParsingError(f"Invalid YAML format: {e}")

    async def _parse_json(self, content: str) -> Dict[str, Any]:
        """Parse JSON configuration."""
        try:
            data = json.loads(content)

            config = {
                'format': 'json',
                'elements': [],
                'data': data
            }

            # Extract vendor and platform if present
            if isinstance(data, dict):
                config['vendor'] = data.get('vendor', 'generic')
                config['platform'] = data.get('platform', 'unknown')

                # Process configuration elements
                if 'configuration' in data:
                    config['elements'] = self._process_json_configuration(data['configuration'])

            return config

        except json.JSONDecodeError as e:
            raise ParsingError(f"Invalid JSON format: {e}")

    async def _parse_xml(self, content: str) -> Dict[str, Any]:
        """Parse XML configuration."""
        try:
            root = ET.fromstring(content)

            config = {
                'format': 'xml',
                'elements': [],
                'root_tag': root.tag
            }

            # Extract vendor and platform from attributes
            config['vendor'] = root.get('vendor', 'generic')
            config['platform'] = root.get('platform', 'unknown')

            # Process XML elements recursively
            config['elements'] = self._process_xml_element(root)

            return config

        except ET.ParseError as e:
            raise ParsingError(f"Invalid XML format: {e}")

    async def _parse_native(self, content: str) -> Dict[str, Any]:
        """Parse native/raw configuration."""
        config = {
            'format': 'native',
            'vendor': 'unknown',
            'platform': 'unknown',
            'elements': [],
            'raw_content': content
        }

        # Try to extract some structure
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                config['elements'].append({
                    'type': 'raw',
                    'value': line
                })

        return config

    def _flatten_hierarchy(
        self,
        hierarchy: Dict,
        elements: List,
        path: List[str] = None
    ):
        """Flatten hierarchical configuration to list of elements."""
        if path is None:
            path = []

        for key, value in hierarchy.items():
            current_path = path + [key]

            if isinstance(value, dict):
                # Recursive descent
                self._flatten_hierarchy(value, elements, current_path)
            else:
                # Leaf node
                elements.append({
                    'path': current_path,
                    'value': value
                })

    def _process_yaml_configuration(self, config_data: Any) -> List[Dict]:
        """Process YAML configuration data."""
        elements = []

        if isinstance(config_data, dict):
            for key, value in config_data.items():
                elements.append({
                    'type': 'yaml_element',
                    'key': key,
                    'value': value
                })
        elif isinstance(config_data, list):
            for item in config_data:
                elements.append({
                    'type': 'yaml_item',
                    'value': item
                })

        return elements

    def _process_json_configuration(self, config_data: Any) -> List[Dict]:
        """Process JSON configuration data."""
        elements = []

        if isinstance(config_data, dict):
            for key, value in config_data.items():
                elements.append({
                    'type': 'json_element',
                    'key': key,
                    'value': value
                })
        elif isinstance(config_data, list):
            for item in config_data:
                elements.append({
                    'type': 'json_item',
                    'value': item
                })

        return elements

    def _process_xml_element(self, element: ET.Element) -> List[Dict]:
        """Process XML element recursively."""
        elements = []

        elem_data = {
            'type': 'xml_element',
            'tag': element.tag,
            'attributes': element.attrib,
            'text': element.text,
            'children': []
        }

        for child in element:
            elem_data['children'].extend(self._process_xml_element(child))

        elements.append(elem_data)
        return elements

    def _validate_parsed_config(self, config: Dict):
        """Validate parsed configuration structure."""
        required_fields = ['vendor', 'elements']

        for field in required_fields:
            if field not in config:
                raise ValidationError(f"Missing required field: {field}")

        if not isinstance(config['elements'], list):
            raise ValidationError("Elements must be a list")


class ConfigurationConverter:
    """
    Convert between different configuration formats.
    Supports bi-directional conversion between formats.
    """

    def __init__(self):
        """Initialize configuration converter."""
        self.audit = AuditLogger()

    async def convert(
        self,
        config: Dict[str, Any],
        target_format: ConfigFormat
    ) -> str:
        """
        Convert configuration to target format.

        Args:
            config: Parsed configuration
            target_format: Target format

        Returns:
            Configuration in target format
        """
        converters = {
            ConfigFormat.CISCO_IOS: self._to_cisco_ios,
            ConfigFormat.JUNIPER_SET: self._to_juniper_set,
            ConfigFormat.YAML: self._to_yaml,
            ConfigFormat.JSON: self._to_json
        }

        if target_format not in converters:
            raise ConfigurationError(f"Unsupported target format: {target_format}")

        converter = converters[target_format]
        return await converter(config)

    async def _to_cisco_ios(self, config: Dict) -> str:
        """Convert to Cisco IOS format."""
        lines = []

        # Add hostname if present
        if 'hostname' in config:
            lines.append(f"hostname {config['hostname']}")

        # Add interfaces
        for iface_name, iface_config in config.get('interfaces', {}).items():
            lines.append(f"interface {iface_name}")
            for cmd in iface_config.get('configuration', []):
                lines.append(f" {cmd}")

        # Add routing
        for protocol, routing_config in config.get('routing', {}).items():
            lines.append(f"router {protocol}")
            for cmd in routing_config.get('configuration', []):
                lines.append(f" {cmd}")

        # Add ACLs
        for acl_name, acl_config in config.get('acls', {}).items():
            lines.append(f"ip access-list {acl_config.get('acl_type', 'standard')} {acl_name}")
            for rule in acl_config.get('rules', []):
                lines.append(f" {rule}")

        # Add global configuration
        for element in config.get('elements', []):
            if element.get('type') == 'global':
                lines.append(element.get('command', ''))

        return '\n'.join(lines)

    async def _to_juniper_set(self, config: Dict) -> str:
        """Convert to Juniper set format."""
        lines = []

        # Convert hierarchical structure to set commands
        def process_hierarchy(obj, path=[]):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    process_hierarchy(value, path + [key])
            else:
                lines.append(f"set {' '.join(path)} {obj}")

        if 'hierarchy' in config:
            process_hierarchy(config['hierarchy'])

        # Add raw commands if present
        for cmd in config.get('commands', []):
            if cmd.get('action') == 'set':
                lines.append(cmd.get('full_command', ''))

        return '\n'.join(lines)

    async def _to_yaml(self, config: Dict) -> str:
        """Convert to YAML format."""
        output = {
            'vendor': config.get('vendor', 'unknown'),
            'platform': config.get('platform', 'unknown'),
            'configuration': {}
        }

        # Add configuration elements
        if 'interfaces' in config:
            output['configuration']['interfaces'] = config['interfaces']
        if 'routing' in config:
            output['configuration']['routing'] = config['routing']
        if 'acls' in config:
            output['configuration']['acls'] = config['acls']

        # Add raw elements
        if config.get('elements'):
            output['configuration']['elements'] = config['elements']

        return yaml.dump(output, default_flow_style=False)

    async def _to_json(self, config: Dict) -> str:
        """Convert to JSON format."""
        output = {
            'vendor': config.get('vendor', 'unknown'),
            'platform': config.get('platform', 'unknown'),
            'configuration': {}
        }

        # Add configuration elements
        for key in ['interfaces', 'routing', 'acls', 'elements']:
            if key in config:
                output['configuration'][key] = config[key]

        return json.dumps(output, indent=2)


# Export main components
__all__ = [
    'ConfigurationParser',
    'ConfigurationConverter',
    'ConfigFormat'
]