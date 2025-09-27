import re
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    is_valid: bool = True
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    info: List[str] = field(default_factory=list)

    def add_error(self, message: str):
        self.errors.append(message)
        self.is_valid = False

    def add_warning(self, message: str):
        self.warnings.append(message)

    def add_info(self, message: str):
        self.info.append(message)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "errors": self.errors,
            "warnings": self.warnings,
            "info": self.info
        }


class ConfigValidator:
    def __init__(self):
        self.cisco_validators = CiscoValidator()
        self.juniper_validators = JuniperValidator()
        self.security_validator = SecurityValidator()
        self.business_validator = BusinessRuleValidator()

    async def validate_configuration(self, config: Dict[str, Any]) -> ValidationResult:
        result = ValidationResult()

        if not self.validate_schema(config):
            result.add_error("Schema validation failed")
            return result

        vendor = config.get('vendor', '').lower()
        if 'cisco' in vendor:
            syntax_result = await self.cisco_validators.validate_syntax(config)
        elif 'juniper' in vendor:
            syntax_result = await self.juniper_validators.validate_syntax(config)
        else:
            result.add_error(f"Unsupported vendor: {vendor}")
            return result

        if not syntax_result.is_valid:
            for error in syntax_result.errors:
                result.add_error(f"Syntax: {error}")

        security_result = await self.security_validator.check_compliance(config)
        for issue in security_result.warnings:
            result.add_warning(f"Security: {issue}")

        business_result = await self.business_validator.check_rules(config)
        for violation in business_result.errors:
            result.add_error(f"Business rule: {violation}")

        conflict_result = await self.detect_conflicts(config)
        for conflict in conflict_result.warnings:
            result.add_warning(f"Conflict: {conflict}")

        return result

    def validate_schema(self, config: Dict[str, Any]) -> bool:
        required_fields = ['vendor', 'hostname']
        for field in required_fields:
            if field not in config:
                return False
        return True

    async def detect_conflicts(self, config: Dict[str, Any]) -> ValidationResult:
        result = ValidationResult()

        interfaces = config.get('interfaces', [])
        vlans = config.get('vlans', [])

        seen_ips = {}
        for interface in interfaces:
            if 'ip_address' in interface:
                ip = interface['ip_address']
                if ip in seen_ips:
                    result.add_warning(f"IP {ip} configured on multiple interfaces")
                seen_ips[ip] = interface['name']

        seen_vlans = set()
        for vlan in vlans:
            vlan_id = vlan.get('id')
            if vlan_id in seen_vlans:
                result.add_warning(f"VLAN {vlan_id} defined multiple times")
            seen_vlans.add(vlan_id)

        return result


class CiscoValidator:
    def __init__(self):
        self.ios_commands = self._load_ios_commands()
        self.dangerous_commands = [
            'reload', 'write erase', 'delete flash:', 'format',
            'request system reboot', 'request system halt'
        ]

    def _load_ios_commands(self) -> List[str]:
        return [
            'interface', 'vlan', 'router', 'ip route', 'access-list',
            'hostname', 'enable secret', 'username', 'line', 'service',
            'spanning-tree', 'vtp', 'channel-group', 'switchport'
        ]

    async def validate_syntax(self, config: Dict[str, Any]) -> ValidationResult:
        result = ValidationResult()

        raw_config = config.get('raw_config', '')
        if raw_config:
            lines = raw_config.split('\n')
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith('!'):
                    continue

                if self._is_dangerous_command(line):
                    result.add_error(f"Line {line_num}: Dangerous command detected: {line}")

                if not self._is_valid_command(line):
                    result.add_warning(f"Line {line_num}: Potentially invalid command: {line[:50]}")

        if 'interfaces' in config:
            for interface in config['interfaces']:
                self._validate_interface(interface, result)

        if 'vlans' in config:
            for vlan in config['vlans']:
                self._validate_vlan(vlan, result)

        return result

    def _is_dangerous_command(self, command: str) -> bool:
        for dangerous in self.dangerous_commands:
            if dangerous in command.lower():
                return True
        return False

    def _is_valid_command(self, command: str) -> bool:
        for valid_cmd in self.ios_commands:
            if command.startswith(valid_cmd):
                return True
        return True

    def _validate_interface(self, interface: Dict[str, Any], result: ValidationResult):
        name = interface.get('name', '')

        valid_patterns = [
            r'^GigabitEthernet\d+/\d+(/\d+)?$',
            r'^FastEthernet\d+/\d+$',
            r'^Vlan\d+$',
            r'^Loopback\d+$',
            r'^Port-channel\d+$'
        ]

        valid = False
        for pattern in valid_patterns:
            if re.match(pattern, name):
                valid = True
                break

        if not valid:
            result.add_warning(f"Non-standard interface name: {name}")

        if 'ip_address' in interface:
            if not self._validate_ip_address(interface['ip_address']):
                result.add_error(f"Invalid IP address on {name}: {interface['ip_address']}")

    def _validate_vlan(self, vlan: Dict[str, Any], result: ValidationResult):
        vlan_id = vlan.get('id')
        if vlan_id:
            try:
                vid = int(vlan_id)
                if vid < 1 or vid > 4094:
                    result.add_error(f"Invalid VLAN ID: {vlan_id}")
            except ValueError:
                result.add_error(f"VLAN ID must be numeric: {vlan_id}")

    def _validate_ip_address(self, ip: str) -> bool:
        pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
        if not re.match(pattern, ip):
            return False

        parts = ip.split('/')[0].split('.')
        for part in parts:
            if int(part) > 255:
                return False

        return True


class JuniperValidator:
    def __init__(self):
        self.junos_commands = [
            'set interfaces', 'set vlans', 'set routing-options',
            'set protocols', 'set security', 'set system'
        ]

    async def validate_syntax(self, config: Dict[str, Any]) -> ValidationResult:
        result = ValidationResult()

        raw_config = config.get('raw_config', '')
        if raw_config:
            lines = raw_config.split('\n')
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                if line.startswith('set '):
                    if not self._is_valid_set_command(line):
                        result.add_warning(f"Line {line_num}: Potentially invalid command: {line[:50]}")

                elif line.startswith('delete '):
                    result.add_warning(f"Line {line_num}: Delete command found - verify intention")

        return result

    def _is_valid_set_command(self, command: str) -> bool:
        for valid_cmd in self.junos_commands:
            if command.startswith(valid_cmd):
                return True
        return False


class SecurityValidator:
    def __init__(self):
        self.weak_passwords = ['cisco', 'admin', 'password', '123456', 'default']
        self.required_security = [
            'service password-encryption',
            'no ip http server',
            'no ip http secure-server'
        ]

    async def check_compliance(self, config: Dict[str, Any]) -> ValidationResult:
        result = ValidationResult()

        raw_config = config.get('raw_config', '')

        for weak_pass in self.weak_passwords:
            if weak_pass in raw_config.lower():
                result.add_warning(f"Potential weak password detected")

        if 'enable password' in raw_config and 'enable secret' not in raw_config:
            result.add_warning("Using 'enable password' instead of 'enable secret'")

        if 'password 0 ' in raw_config or 'secret 0 ' in raw_config:
            result.add_warning("Unencrypted password detected")

        if 'snmp-server community public' in raw_config.lower():
            result.add_warning("Default SNMP community string 'public' detected")

        if 'snmp-server community private' in raw_config.lower():
            result.add_warning("Default SNMP community string 'private' detected")

        for required in self.required_security:
            if required not in raw_config:
                result.add_info(f"Recommended security config missing: {required}")

        return result


class BusinessRuleValidator:
    def __init__(self):
        self.rules = {
            'max_vlans': 100,
            'max_interfaces': 48,
            'reserved_vlans': [1, 1002, 1003, 1004, 1005],
            'reserved_ips': ['0.0.0.0', '255.255.255.255']
        }

    async def check_rules(self, config: Dict[str, Any]) -> ValidationResult:
        result = ValidationResult()

        vlans = config.get('vlans', [])
        if len(vlans) > self.rules['max_vlans']:
            result.add_error(f"Too many VLANs: {len(vlans)} (max: {self.rules['max_vlans']})")

        for vlan in vlans:
            vlan_id = vlan.get('id')
            if vlan_id and int(vlan_id) in self.rules['reserved_vlans']:
                result.add_error(f"Cannot use reserved VLAN ID: {vlan_id}")

        interfaces = config.get('interfaces', [])
        if len(interfaces) > self.rules['max_interfaces']:
            result.add_warning(f"High number of interfaces: {len(interfaces)}")

        return result