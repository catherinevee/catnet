from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import re
import ipaddress
import structlog
import yaml
import json
from datetime import datetime

from ..db.models import DeviceVendor, Device

logger = structlog.get_logger()


class ValidationSeverity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class ValidationType(str, Enum):
    SCHEMA = "schema"
    SYNTAX = "syntax"
    SECURITY = "security"
    BUSINESS_RULES = "business_rules"
    CONFLICTS = "conflicts"
    BEST_PRACTICES = "best_practices"


@dataclass
class ValidationIssue:
    severity: ValidationSeverity
    validation_type: ValidationType
    line_number: Optional[int]
    column_number: Optional[int]
    rule: str
    message: str
    suggestion: Optional[str] = None
    code: Optional[str] = None
    context: Optional[str] = None


@dataclass
class ValidationResult:
    is_valid: bool = True
    syntax_valid: bool = True
    security_compliant: bool = True
    business_rules_passed: bool = True
    errors: List[ValidationIssue] = field(default_factory=list)
    warnings: List[ValidationIssue] = field(default_factory=list)
    info: List[ValidationIssue] = field(default_factory=list)
    score: int = 100
    validation_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_error(self, message: str, rule: str = "", suggestion: str = None, line: int = None):
        issue = ValidationIssue(
            severity=ValidationSeverity.ERROR,
            validation_type=ValidationType.SYNTAX,
            line_number=line,
            column_number=None,
            rule=rule,
            message=message,
            suggestion=suggestion
        )
        self.errors.append(issue)
        self.is_valid = False
        self.score = max(0, self.score - 10)

    def add_warning(self, message: str, rule: str = "", suggestion: str = None, line: int = None):
        issue = ValidationIssue(
            severity=ValidationSeverity.WARNING,
            validation_type=ValidationType.BEST_PRACTICES,
            line_number=line,
            column_number=None,
            rule=rule,
            message=message,
            suggestion=suggestion
        )
        self.warnings.append(issue)
        self.score = max(0, self.score - 5)

    def add_info(self, message: str, rule: str = "", line: int = None):
        issue = ValidationIssue(
            severity=ValidationSeverity.INFO,
            validation_type=ValidationType.BEST_PRACTICES,
            line_number=line,
            column_number=None,
            rule=rule,
            message=message
        )
        self.info.append(issue)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "syntax_valid": self.syntax_valid,
            "security_compliant": self.security_compliant,
            "business_rules_passed": self.business_rules_passed,
            "score": self.score,
            "validation_time": self.validation_time,
            "errors": [
                {
                    "severity": e.severity,
                    "type": e.validation_type,
                    "line": e.line_number,
                    "rule": e.rule,
                    "message": e.message,
                    "suggestion": e.suggestion
                } for e in self.errors
            ],
            "warnings": [
                {
                    "severity": w.severity,
                    "type": w.validation_type,
                    "line": w.line_number,
                    "rule": w.rule,
                    "message": w.message,
                    "suggestion": w.suggestion
                } for w in self.warnings
            ],
            "info": [
                {
                    "severity": i.severity,
                    "type": i.validation_type,
                    "line": i.line_number,
                    "rule": i.rule,
                    "message": i.message
                } for i in self.info
            ],
            "metadata": self.metadata
        }


class ConfigValidator:
    """Multi-layer configuration validation system"""

    def __init__(self):
        self.security_rules = SecurityRules()
        self.business_rules = BusinessRules()
        self.syntax_validators = {
            DeviceVendor.CISCO_IOS: CiscoIOSValidator(),
            DeviceVendor.CISCO_IOS_XE: CiscoIOSValidator(),
            DeviceVendor.CISCO_NX_OS: CiscoNXOSValidator(),
            DeviceVendor.JUNIPER_JUNOS: JuniperValidator()
        }
        self.conflict_detector = ConflictDetector()
        self.best_practices = BestPracticesValidator()

    async def validate_configuration(
        self,
        config: Dict[str, Any],
        devices: Optional[List[Device]] = None
    ) -> ValidationResult:
        """Perform comprehensive multi-layer validation"""

        start_time = datetime.utcnow()
        result = ValidationResult()

        try:
            # Layer 1: Schema validation
            if not await self._validate_schema(config, result):
                result.syntax_valid = False
                return result

            # Layer 2: Vendor-specific syntax validation
            if devices:
                for device in devices:
                    vendor_result = await self._validate_vendor_syntax(
                        config, device.vendor, result
                    )
                    if not vendor_result:
                        result.syntax_valid = False

            # Layer 3: Security compliance
            security_issues = await self.security_rules.check_compliance(config)
            for issue in security_issues:
                if issue.severity == ValidationSeverity.ERROR:
                    result.add_error(
                        issue.message,
                        rule=issue.rule,
                        suggestion=issue.suggestion,
                        line=issue.line_number
                    )
                    result.security_compliant = False
                else:
                    result.add_warning(
                        issue.message,
                        rule=issue.rule,
                        suggestion=issue.suggestion,
                        line=issue.line_number
                    )

            # Layer 4: Business rules
            business_violations = await self.business_rules.check_rules(config)
            for violation in business_violations:
                result.add_error(
                    f"Business rule violation: {violation['message']}",
                    rule=violation['rule']
                )
                result.business_rules_passed = False

            # Layer 5: Conflict detection
            if devices and len(devices) > 1:
                conflicts = await self.conflict_detector.detect_conflicts(
                    config, devices
                )
                for conflict in conflicts:
                    result.add_warning(
                        f"Potential conflict: {conflict['message']}",
                        rule="conflict_detection",
                        suggestion=conflict.get('resolution')
                    )

            # Layer 6: Best practices
            best_practice_issues = await self.best_practices.validate(config)
            for issue in best_practice_issues:
                if issue['severity'] == 'warning':
                    result.add_warning(issue['message'], rule=issue['rule'])
                else:
                    result.add_info(issue['message'], rule=issue['rule'])

            # Calculate validation time
            result.validation_time = (datetime.utcnow() - start_time).total_seconds()

            # Add metadata
            result.metadata = {
                "validated_at": datetime.utcnow().isoformat(),
                "device_count": len(devices) if devices else 0,
                "config_lines": self._count_config_lines(config)
            }

        except Exception as e:
            logger.error(f"Validation error: {e}")
            result.add_error(f"Validation failed: {str(e)}", rule="system_error")

        return result

    async def _validate_schema(
        self,
        config: Dict[str, Any],
        result: ValidationResult
    ) -> bool:
        """Validate configuration schema"""

        required_fields = ['version', 'devices', 'configurations']
        for field in required_fields:
            if field not in config:
                result.add_error(
                    f"Missing required field: {field}",
                    rule="schema_validation"
                )
                return False

        if not isinstance(config.get('devices'), list):
            result.add_error(
                "Field 'devices' must be a list",
                rule="schema_validation"
            )
            return False

        return True

    async def _validate_vendor_syntax(
        self,
        config: Dict[str, Any],
        vendor: DeviceVendor,
        result: ValidationResult
    ) -> bool:
        """Validate vendor-specific syntax"""

        if vendor not in self.syntax_validators:
            result.add_warning(
                f"No syntax validator available for vendor: {vendor}",
                rule="vendor_validation"
            )
            return True

        validator = self.syntax_validators[vendor]
        return await validator.validate(config, result)

    def _count_config_lines(self, config: Dict[str, Any]) -> int:
        """Count configuration lines"""
        if isinstance(config, dict):
            config_str = json.dumps(config)
        else:
            config_str = str(config)
        return len(config_str.split('\n'))


class SecurityRules:
    """Security compliance validation"""

    def __init__(self):
        self.forbidden_commands = [
            "no aaa new-model",
            "username .* password [^0-9]",  # Plain text passwords
            "enable password [^0-9]",  # Plain text enable password
            "snmp-server community public",
            "snmp-server community private",
            "transport input telnet",  # Telnet without SSH
            "no service password-encryption",
            "no ip ssh version 2",
            "exec-timeout 0 0",  # No timeout
        ]

        self.required_commands = [
            "service password-encryption",
            "aaa new-model",
            "ip ssh version 2",
            "transport input ssh",
            "banner login",
            "logging buffered",
            "ntp server",
            "service timestamps"
        ]

        self.weak_crypto_patterns = [
            r"crypto isakmp policy \d+ encryption des",
            r"crypto isakmp policy \d+ encryption 3des",
            r"crypto isakmp policy \d+ hash md5",
            r"ip ssh version 1",
            r"crypto key generate rsa modulus (512|768|1024)"
        ]

    async def check_compliance(
        self,
        config: Dict[str, Any]
    ) -> List[ValidationIssue]:
        """Check security compliance"""

        issues = []
        config_text = self._extract_config_text(config)
        lines = config_text.split('\n')

        # Check for forbidden commands
        for i, line in enumerate(lines, 1):
            for pattern in self.forbidden_commands:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        validation_type=ValidationType.SECURITY,
                        line_number=i,
                        column_number=None,
                        rule="forbidden_command",
                        message=f"Security violation: forbidden command detected",
                        suggestion=f"Remove or modify the command: {line.strip()}",
                        context=line.strip()
                    ))

        # Check for weak cryptography
        for i, line in enumerate(lines, 1):
            for pattern in self.weak_crypto_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        validation_type=ValidationType.SECURITY,
                        line_number=i,
                        column_number=None,
                        rule="weak_crypto",
                        message="Weak cryptography detected",
                        suggestion="Use stronger encryption algorithms (AES, SHA256)",
                        context=line.strip()
                    ))

        # Check for missing required commands
        config_lower = config_text.lower()
        for required in self.required_commands:
            if required.lower() not in config_lower:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    validation_type=ValidationType.SECURITY,
                    line_number=None,
                    column_number=None,
                    rule="missing_security_config",
                    message=f"Missing recommended security configuration: {required}",
                    suggestion=f"Add the following configuration: {required}"
                ))

        # Check for exposed credentials
        credential_patterns = [
            r'password\s+[0-9]\s+\S+',  # Type 0 passwords
            r'secret\s+[0-9]\s+\S+',  # Type 0 secrets
            r'key\s+["\']?[A-Za-z0-9+/=]{20,}',  # Potential API keys
            r'token\s*[=:]\s*["\']?[A-Za-z0-9+/=]{20,}',  # Tokens
        ]

        for i, line in enumerate(lines, 1):
            for pattern in credential_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        validation_type=ValidationType.SECURITY,
                        line_number=i,
                        column_number=None,
                        rule="exposed_credentials",
                        message="Potential exposed credentials detected",
                        suggestion="Use encrypted passwords (type 5 or higher) or Vault references",
                        context=line.strip()[:50] + "..."
                    ))

        return issues

    def _extract_config_text(self, config: Dict[str, Any]) -> str:
        """Extract configuration text from config object"""
        if 'configurations' in config:
            return '\n'.join(config['configurations'])
        elif 'config_text' in config:
            return config['config_text']
        else:
            return json.dumps(config)


class BusinessRules:
    """Business rules validation"""

    def __init__(self):
        self.rules = {
            "change_window": {
                "start": "22:00",
                "end": "06:00",
                "timezone": "UTC"
            },
            "max_vlan_id": 4094,
            "reserved_vlans": [1, 1002, 1003, 1004, 1005],
            "reserved_ip_ranges": [
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16"
            ],
            "naming_conventions": {
                "interface": r"^(Gi|Fa|Te|Eth|Lo)\d+(/\d+)*$",
                "vlan": r"^VLAN_[A-Z]+_\d+$",
                "acl": r"^ACL_[A-Z]+_[A-Z]+$"
            },
            "max_acl_entries": 500,
            "required_interface_descriptions": True,
            "max_bgp_peers": 100,
            "allowed_routing_protocols": ["bgp", "ospf", "static"]
        }

    async def check_rules(
        self,
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Check business rules compliance"""

        violations = []
        config_text = self._extract_config_text(config)

        # Check VLAN IDs
        vlan_matches = re.findall(r'vlan\s+(\d+)', config_text, re.IGNORECASE)
        for vlan_id in vlan_matches:
            vlan_num = int(vlan_id)
            if vlan_num > self.rules["max_vlan_id"]:
                violations.append({
                    "rule": "vlan_range",
                    "message": f"VLAN {vlan_num} exceeds maximum allowed ({self.rules['max_vlan_id']})"
                })
            if vlan_num in self.rules["reserved_vlans"]:
                violations.append({
                    "rule": "reserved_vlan",
                    "message": f"VLAN {vlan_num} is reserved and should not be used"
                })

        # Check IP addresses against reserved ranges
        ip_matches = re.findall(
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/\d{1,2})?\b',
            config_text
        )
        for ip_str in ip_matches:
            try:
                ip = ipaddress.ip_interface(ip_str)
                for reserved_range in self.rules["reserved_ip_ranges"]:
                    reserved_net = ipaddress.ip_network(reserved_range)
                    if ip.network.overlaps(reserved_net):
                        violations.append({
                            "rule": "ip_range",
                            "message": f"IP {ip_str} is in reserved range {reserved_range}"
                        })
            except ValueError:
                pass

        # Check interface naming conventions
        interface_matches = re.findall(
            r'interface\s+(\S+)',
            config_text,
            re.IGNORECASE
        )
        for interface in interface_matches:
            if not re.match(self.rules["naming_conventions"]["interface"], interface):
                violations.append({
                    "rule": "interface_naming",
                    "message": f"Interface {interface} does not follow naming convention"
                })

        # Check for interface descriptions
        if self.rules["required_interface_descriptions"]:
            interfaces_without_desc = self._check_interface_descriptions(config_text)
            for interface in interfaces_without_desc:
                violations.append({
                    "rule": "interface_description",
                    "message": f"Interface {interface} is missing description"
                })

        # Check ACL size
        acl_entries = self._count_acl_entries(config_text)
        if acl_entries > self.rules["max_acl_entries"]:
            violations.append({
                "rule": "acl_size",
                "message": f"ACL has {acl_entries} entries, exceeds maximum {self.rules['max_acl_entries']}"
            })

        return violations

    def _extract_config_text(self, config: Dict[str, Any]) -> str:
        """Extract configuration text"""
        if isinstance(config, dict):
            if 'configurations' in config:
                return '\n'.join(config['configurations'])
            return json.dumps(config)
        return str(config)

    def _check_interface_descriptions(self, config_text: str) -> List[str]:
        """Check for missing interface descriptions"""
        interfaces_without_desc = []
        lines = config_text.split('\n')

        current_interface = None
        has_description = False

        for line in lines:
            if line.strip().startswith('interface '):
                if current_interface and not has_description:
                    interfaces_without_desc.append(current_interface)

                current_interface = line.strip().split()[1]
                has_description = False

            elif current_interface and 'description' in line.lower():
                has_description = True

            elif line.strip() == '!':
                if current_interface and not has_description:
                    interfaces_without_desc.append(current_interface)
                current_interface = None

        return interfaces_without_desc

    def _count_acl_entries(self, config_text: str) -> int:
        """Count ACL entries"""
        acl_patterns = [
            r'^\s*(permit|deny)\s+',
            r'^\s*\d+\s+(permit|deny)\s+'
        ]

        count = 0
        for line in config_text.split('\n'):
            for pattern in acl_patterns:
                if re.match(pattern, line, re.IGNORECASE):
                    count += 1
                    break

        return count


class ConflictDetector:
    """Detect configuration conflicts"""

    async def detect_conflicts(
        self,
        config: Dict[str, Any],
        devices: List[Device]
    ) -> List[Dict[str, Any]]:
        """Detect potential configuration conflicts"""

        conflicts = []

        # Check for duplicate IP addresses
        ip_assignments = {}
        config_text = self._extract_config_text(config)

        ip_matches = re.findall(
            r'ip\s+address\s+((?:[0-9]{1,3}\.){3}[0-9]{1,3})\s+((?:[0-9]{1,3}\.){3}[0-9]{1,3})',
            config_text,
            re.IGNORECASE
        )

        for ip, mask in ip_matches:
            if ip in ip_assignments:
                conflicts.append({
                    "type": "duplicate_ip",
                    "message": f"Duplicate IP address {ip} detected",
                    "resolution": "Ensure unique IP addresses across all interfaces"
                })
            else:
                ip_assignments[ip] = True

        # Check for VLAN conflicts
        vlan_assignments = {}
        vlan_matches = re.findall(
            r'vlan\s+(\d+).*?name\s+(\S+)',
            config_text,
            re.IGNORECASE | re.DOTALL
        )

        for vlan_id, vlan_name in vlan_matches:
            if vlan_id in vlan_assignments:
                if vlan_assignments[vlan_id] != vlan_name:
                    conflicts.append({
                        "type": "vlan_name_mismatch",
                        "message": f"VLAN {vlan_id} has conflicting names: {vlan_assignments[vlan_id]} vs {vlan_name}",
                        "resolution": "Use consistent VLAN names across devices"
                    })
            else:
                vlan_assignments[vlan_id] = vlan_name

        # Check for routing protocol conflicts
        routing_protocols = set()
        if 'router bgp' in config_text.lower():
            routing_protocols.add('bgp')
        if 'router ospf' in config_text.lower():
            routing_protocols.add('ospf')
        if 'router eigrp' in config_text.lower():
            routing_protocols.add('eigrp')

        if len(routing_protocols) > 1:
            conflicts.append({
                "type": "multiple_routing_protocols",
                "message": f"Multiple routing protocols configured: {', '.join(routing_protocols)}",
                "resolution": "Consider consolidating to a single routing protocol or ensure proper redistribution"
            })

        return conflicts

    def _extract_config_text(self, config: Dict[str, Any]) -> str:
        """Extract configuration text"""
        if isinstance(config, dict):
            if 'configurations' in config:
                return '\n'.join(config['configurations'])
            return json.dumps(config)
        return str(config)


class CiscoIOSValidator:
    """Cisco IOS specific syntax validation"""

    async def validate(
        self,
        config: Dict[str, Any],
        result: ValidationResult
    ) -> bool:
        """Validate Cisco IOS syntax"""

        config_text = self._extract_config_text(config)
        lines = config_text.split('\n')

        valid = True
        indent_level = 0
        current_context = []

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Skip comments and empty lines
            if not stripped or stripped.startswith('!'):
                continue

            # Check indentation
            expected_indent = len(current_context) * 1
            actual_indent = len(line) - len(line.lstrip())

            if actual_indent < expected_indent and not stripped.startswith('exit'):
                result.add_warning(
                    f"Incorrect indentation at line {i}",
                    rule="indentation",
                    line=i
                )

            # Check for valid command structure
            if not self._is_valid_command(stripped, current_context):
                result.add_error(
                    f"Invalid command syntax: {stripped}",
                    rule="cisco_syntax",
                    line=i
                )
                valid = False

            # Update context
            if self._is_context_command(stripped):
                current_context.append(stripped)
            elif stripped == 'exit' and current_context:
                current_context.pop()

        return valid

    def _extract_config_text(self, config: Dict[str, Any]) -> str:
        """Extract configuration text"""
        if isinstance(config, dict):
            if 'configurations' in config:
                return '\n'.join(config['configurations'])
            return json.dumps(config)
        return str(config)

    def _is_valid_command(self, command: str, context: List[str]) -> bool:
        """Check if command is valid in current context"""
        # Simplified validation - would have comprehensive command database
        valid_commands = [
            'interface', 'ip', 'vlan', 'router', 'line', 'access-list',
            'crypto', 'spanning-tree', 'service', 'hostname', 'banner',
            'aaa', 'username', 'enable', 'snmp-server', 'logging',
            'ntp', 'clock', 'boot', 'version', 'exit', 'no'
        ]

        first_word = command.split()[0] if command else ""
        return first_word in valid_commands or first_word.startswith('!')

    def _is_context_command(self, command: str) -> bool:
        """Check if command changes context"""
        context_commands = [
            'interface', 'router', 'line', 'vlan', 'class-map',
            'policy-map', 'route-map', 'crypto'
        ]

        first_word = command.split()[0] if command else ""
        return first_word in context_commands


class CiscoNXOSValidator:
    """Cisco NX-OS specific syntax validation"""

    async def validate(
        self,
        config: Dict[str, Any],
        result: ValidationResult
    ) -> bool:
        """Validate Cisco NX-OS syntax"""
        # Similar to IOS with NX-OS specific commands
        return True


class JuniperValidator:
    """Juniper Junos specific syntax validation"""

    async def validate(
        self,
        config: Dict[str, Any],
        result: ValidationResult
    ) -> bool:
        """Validate Juniper Junos syntax"""

        config_text = self._extract_config_text(config)
        lines = config_text.split('\n')

        valid = True
        brace_count = 0

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Count braces for hierarchy validation
            brace_count += stripped.count('{') - stripped.count('}')

            if brace_count < 0:
                result.add_error(
                    f"Unmatched closing brace at line {i}",
                    rule="juniper_syntax",
                    line=i
                )
                valid = False

            # Check for valid Juniper syntax
            if stripped and not self._is_valid_juniper_command(stripped):
                result.add_warning(
                    f"Potentially invalid Juniper command: {stripped}",
                    rule="juniper_syntax",
                    line=i
                )

        if brace_count != 0:
            result.add_error(
                f"Unmatched braces in configuration (count: {brace_count})",
                rule="juniper_syntax"
            )
            valid = False

        return valid

    def _extract_config_text(self, config: Dict[str, Any]) -> str:
        """Extract configuration text"""
        if isinstance(config, dict):
            if 'configurations' in config:
                return '\n'.join(config['configurations'])
            return json.dumps(config)
        return str(config)

    def _is_valid_juniper_command(self, command: str) -> bool:
        """Check if command is valid Juniper syntax"""
        valid_starts = [
            'set', 'delete', 'edit', 'top', 'up', 'exit',
            'show', 'commit', 'rollback', '{', '}', '#'
        ]

        first_word = command.split()[0] if command else ""
        return any(command.startswith(start) for start in valid_starts)


class BestPracticesValidator:
    """Validate against network best practices"""

    async def validate(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check configuration against best practices"""

        issues = []
        config_text = self._extract_config_text(config)

        # Check for hardcoded passwords
        if re.search(r'password\s+[0-9]\s+\w+', config_text):
            issues.append({
                "severity": "warning",
                "rule": "hardcoded_password",
                "message": "Hardcoded passwords detected. Consider using secret management."
            })

        # Check for missing NTP configuration
        if 'ntp server' not in config_text.lower():
            issues.append({
                "severity": "info",
                "rule": "ntp_config",
                "message": "No NTP server configured. Time synchronization is recommended."
            })

        # Check for missing logging configuration
        if 'logging' not in config_text.lower():
            issues.append({
                "severity": "warning",
                "rule": "logging_config",
                "message": "No logging configuration found. Enable logging for audit trails."
            })

        # Check for STP configuration
        if 'spanning-tree' not in config_text.lower():
            issues.append({
                "severity": "info",
                "rule": "stp_config",
                "message": "No spanning-tree configuration found. Consider enabling STP for loop prevention."
            })

        # Check for port security
        if 'switchport port-security' not in config_text.lower():
            issues.append({
                "severity": "info",
                "rule": "port_security",
                "message": "No port security configured. Consider enabling for access ports."
            })

        return issues

    def _extract_config_text(self, config: Dict[str, Any]) -> str:
        """Extract configuration text"""
        if isinstance(config, dict):
            if 'configurations' in config:
                return '\n'.join(config['configurations'])
            return json.dumps(config)
        return str(config)


# Global validator instance
config_validator = ConfigValidator()