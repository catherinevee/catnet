from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
import jsonschema
import yaml
import re
import ipaddress
import structlog
from datetime import datetime

from ..db.models import DeviceVendor
from ..security.audit import AuditLogger

logger = structlog.get_logger()

@dataclass
class ValidationResult:
    is_valid: bool = True
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    validation_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def add_error(self, error: str):
        self.errors.append(error)
        self.is_valid = False

    def add_warning(self, warning: str):
        self.warnings.append(warning)

class ConfigValidator:
    def __init__(self):
        self.audit = AuditLogger()
        self.cisco_dangerous_commands = [
            'reload', 'reboot', 'shutdown', 'erase startup-config',
            'format flash:', 'delete flash:', 'clear configuration'
        ]
        self.juniper_dangerous_commands = [
            'request system reboot', 'request system halt',
            'request system zeroize', 'delete'
        ]

    async def validate_configuration(self, config: Dict[str, Any]) -> ValidationResult:
        result = ValidationResult()

        try:
            config_hash = self._calculate_hash(str(config))

            if not config:
                result.add_error("Configuration is empty")
                return result

            result = await self._validate_schema(config, result)
            if not result.is_valid:
                return result

            result = await self._validate_syntax(config, result)
            result = await self._check_security_compliance(config, result)
            result = await self._check_business_rules(config, result)
            result = await self._detect_conflicts(config, result)

            await self.audit.log_config_validation(
                config_hash=config_hash,
                validation_type="full",
                passed=result.is_valid,
                errors=result.errors,
                warnings=result.warnings
            )

            return result

        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            result.add_error(f"Validation error: {str(e)}")
            return result

    async def _validate_schema(self, config: Dict[str, Any], result: ValidationResult) -> ValidationResult:
        schema = {
            "type": "object",
            "required": ["version", "metadata"],
            "properties": {
                "version": {"type": "string"},
                "metadata": {
                    "type": "object",
                    "required": ["name"],
                    "properties": {
                        "name": {"type": "string"},
                        "description": {"type": "string"},
                        "author": {"type": "string"},
                        "created": {"type": "string"}
                    }
                },
                "devices": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "configurations": {
                    "type": "object"
                }
            }
        }

        try:
            jsonschema.validate(config, schema)
            result.details["schema_validation"] = "passed"
        except jsonschema.ValidationError as e:
            result.add_error(f"Schema validation failed: {e.message}")
            result.details["schema_validation"] = "failed"

        return result

    async def _validate_syntax(self, config: Dict[str, Any], result: ValidationResult) -> ValidationResult:
        configurations = config.get("configurations", {})
        vendor = config.get("metadata", {}).get("vendor", "").lower()

        for config_name, config_content in configurations.items():
            if isinstance(config_content, str):
                if "cisco" in vendor or "ios" in vendor:
                    syntax_result = await self._validate_cisco_syntax(config_content)
                elif "juniper" in vendor or "junos" in vendor:
                    syntax_result = await self._validate_juniper_syntax(config_content)
                else:
                    syntax_result = await self._validate_generic_syntax(config_content)

                if not syntax_result["valid"]:
                    result.add_error(f"Syntax validation failed for {config_name}: {syntax_result['error']}")
                else:
                    result.details[f"syntax_{config_name}"] = "passed"

        return result

    async def _validate_cisco_syntax(self, config_text: str) -> Dict[str, Any]:
        try:
            lines = config_text.split('\n')
            errors = []

            for i, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith('!'):
                    continue

                if not self._is_valid_cisco_command(line):
                    errors.append(f"Line {i}: Invalid Cisco command syntax")

                if any(dangerous in line.lower() for dangerous in self.cisco_dangerous_commands):
                    errors.append(f"Line {i}: Dangerous command detected: {line}")

                if not self._validate_cisco_interfaces(line):
                    errors.append(f"Line {i}: Invalid interface configuration")

                if not self._validate_ip_addresses(line):
                    errors.append(f"Line {i}: Invalid IP address format")

            return {
                "valid": len(errors) == 0,
                "errors": errors,
                "line_count": len(lines)
            }

        except Exception as e:
            return {
                "valid": False,
                "error": f"Syntax validation error: {str(e)}"
            }

    async def _validate_juniper_syntax(self, config_text: str) -> Dict[str, Any]:
        try:
            errors = []

            if not config_text.strip().startswith('set') and not config_text.strip().startswith('{'):
                errors.append("Juniper configuration must start with 'set' commands or bracket notation")

            lines = config_text.split('\n')
            bracket_count = 0

            for i, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                if line.startswith('set '):
                    if not self._is_valid_juniper_set_command(line):
                        errors.append(f"Line {i}: Invalid Juniper set command")

                bracket_count += line.count('{') - line.count('}')

                if any(dangerous in line.lower() for dangerous in self.juniper_dangerous_commands):
                    errors.append(f"Line {i}: Dangerous command detected: {line}")

                if not self._validate_ip_addresses(line):
                    errors.append(f"Line {i}: Invalid IP address format")

            if bracket_count != 0:
                errors.append("Mismatched brackets in configuration")

            return {
                "valid": len(errors) == 0,
                "errors": errors,
                "line_count": len(lines)
            }

        except Exception as e:
            return {
                "valid": False,
                "error": f"Syntax validation error: {str(e)}"
            }

    async def _validate_generic_syntax(self, config_text: str) -> Dict[str, Any]:
        try:
            yaml.safe_load(config_text)
            return {"valid": True, "format": "yaml"}
        except yaml.YAMLError:
            try:
                import json
                json.loads(config_text)
                return {"valid": True, "format": "json"}
            except json.JSONDecodeError:
                return {
                    "valid": False,
                    "error": "Configuration is not valid YAML or JSON"
                }

    def _is_valid_cisco_command(self, line: str) -> bool:
        cisco_command_patterns = [
            r'^interface\s+\w+',
            r'^ip\s+address\s+',
            r'^shutdown',
            r'^no\s+shutdown',
            r'^description\s+',
            r'^switchport\s+',
            r'^vlan\s+\d+',
            r'^router\s+\w+',
            r'^access-list\s+',
            r'^hostname\s+\w+',
            r'^enable\s+secret\s+',
            r'^line\s+\w+',
            r'^username\s+\w+',
            r'^spanning-tree\s+',
            r'^!\s*$'
        ]

        for pattern in cisco_command_patterns:
            if re.match(pattern, line, re.IGNORECASE):
                return True

        return False

    def _is_valid_juniper_set_command(self, line: str) -> bool:
        juniper_set_patterns = [
            r'^set interfaces \w+',
            r'^set protocols \w+',
            r'^set routing-options',
            r'^set system host-name',
            r'^set security zones',
            r'^set vlans \w+',
            r'^set policy-options',
            r'^set firewall family',
            r'^set chassis'
        ]

        for pattern in juniper_set_patterns:
            if re.match(pattern, line, re.IGNORECASE):
                return True

        return False

    def _validate_cisco_interfaces(self, line: str) -> bool:
        if 'interface' not in line.lower():
            return True

        interface_patterns = [
            r'GigabitEthernet\d+/\d+(/\d+)?',
            r'FastEthernet\d+/\d+(/\d+)?',
            r'Ethernet\d+/\d+(/\d+)?',
            r'Serial\d+/\d+(/\d+)?',
            r'Loopback\d+',
            r'Vlan\d+',
            r'Port-channel\d+',
            r'Tunnel\d+'
        ]

        line_clean = line.replace('interface ', '').strip()
        for pattern in interface_patterns:
            if re.match(pattern, line_clean, re.IGNORECASE):
                return True

        return False

    def _validate_ip_addresses(self, line: str) -> bool:
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b'
        ip_matches = re.findall(ip_pattern, line)

        for ip_match in ip_matches:
            try:
                if '/' in ip_match:
                    ipaddress.ip_network(ip_match, strict=False)
                else:
                    ipaddress.ip_address(ip_match)
            except ipaddress.AddressValueError:
                return False

        return True

    async def _check_security_compliance(self, config: Dict[str, Any], result: ValidationResult) -> ValidationResult:
        configurations = config.get("configurations", {})

        for config_name, config_content in configurations.items():
            if isinstance(config_content, str):
                security_issues = []

                if "enable secret" not in config_content and "enable password" not in config_content:
                    security_issues.append("No enable password configured")

                if "service password-encryption" not in config_content:
                    security_issues.append("Password encryption not enabled")

                if "access-list" not in config_content and "ip access-group" not in config_content:
                    security_issues.append("No access control lists configured")

                if re.search(r'password\s+\w+', config_content, re.IGNORECASE):
                    security_issues.append("Plaintext passwords detected")

                weak_passwords = re.findall(r'secret\s+(\w+)', config_content, re.IGNORECASE)
                for password in weak_passwords:
                    if len(password) < 8 or password.lower() in ['password', 'admin', '123456']:
                        security_issues.append(f"Weak password detected: {password}")

                snmp_community = re.findall(r'snmp-server community (\w+)', config_content, re.IGNORECASE)
                for community in snmp_community:
                    if community.lower() in ['public', 'private']:
                        security_issues.append(f"Default SNMP community detected: {community}")

                for issue in security_issues:
                    result.add_warning(f"Security issue in {config_name}: {issue}")

        return result

    async def _check_business_rules(self, config: Dict[str, Any], result: ValidationResult) -> ValidationResult:
        metadata = config.get("metadata", {})
        configurations = config.get("configurations", {})

        if not metadata.get("author"):
            result.add_error("Configuration must have an author specified")

        if not metadata.get("description"):
            result.add_warning("Configuration should have a description")

        devices = config.get("devices", [])
        if len(devices) > 100:
            result.add_error("Configuration cannot target more than 100 devices")

        for config_name, config_content in configurations.items():
            if isinstance(config_content, str):
                if len(config_content.split('\n')) > 10000:
                    result.add_error(f"Configuration {config_name} exceeds maximum line limit")

                if "shutdown" in config_content and "no shutdown" not in config_content:
                    result.add_warning(f"Configuration {config_name} contains shutdown commands without corresponding no shutdown")

        return result

    async def _detect_conflicts(self, config: Dict[str, Any], result: ValidationResult) -> ValidationResult:
        configurations = config.get("configurations", {})

        vlan_ids = []
        ip_addresses = []

        for config_name, config_content in configurations.items():
            if isinstance(config_content, str):
                vlan_matches = re.findall(r'vlan (\d+)', config_content, re.IGNORECASE)
                vlan_ids.extend(vlan_matches)

                ip_matches = re.findall(r'ip address (\d+\.\d+\.\d+\.\d+)', config_content, re.IGNORECASE)
                ip_addresses.extend(ip_matches)

        duplicate_vlans = [vlan for vlan in set(vlan_ids) if vlan_ids.count(vlan) > 1]
        for vlan in duplicate_vlans:
            result.add_warning(f"VLAN {vlan} configured multiple times")

        duplicate_ips = [ip for ip in set(ip_addresses) if ip_addresses.count(ip) > 1]
        for ip in duplicate_ips:
            result.add_warning(f"IP address {ip} configured multiple times")

        return result

    def _calculate_hash(self, content: str) -> str:
        import hashlib
        return hashlib.sha256(content.encode()).hexdigest()

    async def validate_device_compatibility(
        self,
        config: Dict[str, Any],
        device_vendor: DeviceVendor
    ) -> ValidationResult:
        result = ValidationResult()

        config_vendor = config.get("metadata", {}).get("vendor", "").lower()

        vendor_mapping = {
            DeviceVendor.CISCO_IOS: ["cisco", "ios"],
            DeviceVendor.CISCO_IOS_XE: ["cisco", "ios-xe", "xe"],
            DeviceVendor.CISCO_NX_OS: ["cisco", "nxos", "nx-os"],
            DeviceVendor.JUNIPER_JUNOS: ["juniper", "junos"]
        }

        compatible_vendors = vendor_mapping.get(device_vendor, [])

        if config_vendor and not any(vendor in config_vendor for vendor in compatible_vendors):
            result.add_error(f"Configuration vendor '{config_vendor}' not compatible with device vendor '{device_vendor.value}'")

        return result

    async def validate_deployment_readiness(self, config: Dict[str, Any]) -> ValidationResult:
        result = ValidationResult()

        required_metadata = ["name", "version", "author"]
        metadata = config.get("metadata", {})

        for field in required_metadata:
            if not metadata.get(field):
                result.add_error(f"Missing required metadata field: {field}")

        if not config.get("devices"):
            result.add_error("No target devices specified")

        if not config.get("configurations"):
            result.add_error("No configurations specified")

        backup_strategy = metadata.get("backup_strategy")
        if not backup_strategy:
            result.add_warning("No backup strategy specified")

        rollback_plan = metadata.get("rollback_plan")
        if not rollback_plan:
            result.add_warning("No rollback plan specified")

        return result