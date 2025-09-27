"""
Configuration Validator - Multi-layer validation for network configurations
"""
import re
import json
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import asyncio
import ipaddress
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..core.exceptions import ValidationError, SecurityError
from ..core.constants import DeviceVendor, AuditEventType
from ..db.models import Device, DeviceConfig, ComplianceRule


class ValidationResult:
    """Container for validation results"""

    def __init__(self):
        self.is_valid = True
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.info: List[str] = []
        self.security_issues: List[Dict[str, Any]] = []
        self.timestamp = datetime.utcnow()

    def add_error(self, message: str, details: Optional[Dict] = None):
        """Add an error to the validation result"""
        self.is_valid = False
        self.errors.append({
            'message': message,
            'details': details or {},
            'timestamp': datetime.utcnow().isoformat()
        })

    def add_warning(self, message: str, details: Optional[Dict] = None):
        """Add a warning to the validation result"""
        self.warnings.append({
            'message': message,
            'details': details or {},
            'timestamp': datetime.utcnow().isoformat()
        })

    def add_info(self, message: str):
        """Add informational message"""
        self.info.append(message)

    def add_security_issue(self, issue_type: str, severity: str, description: str):
        """Add a security issue"""
        self.security_issues.append({
            'type': issue_type,
            'severity': severity,
            'description': description,
            'timestamp': datetime.utcnow().isoformat()
        })
        if severity in ['critical', 'high']:
            self.is_valid = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'is_valid': self.is_valid,
            'errors': self.errors,
            'warnings': self.warnings,
            'info': self.info,
            'security_issues': self.security_issues,
            'timestamp': self.timestamp.isoformat()
        }


class ConfigValidator:
    """
    Multi-layer configuration validator with security scanning
    """

    def __init__(self):
        # Regex patterns for security scanning
        self.secret_patterns = {
            'password': re.compile(r'(password|passwd|pwd)\s*[=:]\s*[\S]+', re.IGNORECASE),
            'api_key': re.compile(r'(api[_-]?key|apikey)\s*[=:]\s*[\S]+', re.IGNORECASE),
            'token': re.compile(r'(token|auth[_-]?token)\s*[=:]\s*[\S]+', re.IGNORECASE),
            'secret': re.compile(r'(secret|private[_-]?key)\s*[=:]\s*[\S]+', re.IGNORECASE),
            'community': re.compile(r'snmp[_-]?community\s+[\S]+', re.IGNORECASE),
            'enable_secret': re.compile(r'enable\s+secret\s+\d+\s+[\S]+', re.IGNORECASE)
        }

        # Dangerous commands
        self.dangerous_commands = {
            'cisco': [
                'no aaa new-model',
                'no service password-encryption',
                'transport input all',
                'no shutdown',  # on management interfaces
                'debug all',
                'logging console debugging'
            ],
            'juniper': [
                'delete system services ssh',
                'set system root-authentication',
                'delete security',
                'set system services telnet'
            ]
        }

        # Required security configurations
        self.required_configs = {
            'cisco': [
                'service password-encryption',
                'aaa new-model',
                'transport input ssh',
                'login local',
                'banner motd'
            ],
            'juniper': [
                'system services ssh',
                'security ssh-known-hosts',
                'system login message'
            ]
        }

    async def validate_configuration(
        self,
        config: Dict[str, Any],
        db: Optional[AsyncSession] = None
    ) -> ValidationResult:
        """
        Perform multi-layer validation on configuration

        Args:
            config: Configuration to validate
            db: Optional database session for compliance checks

        Returns:
            ValidationResult object
        """
        result = ValidationResult()

        # Layer 1: Schema validation
        schema_result = await self.validate_schema(config)
        if not schema_result['valid']:
            result.add_error(f"Schema validation failed: {schema_result['error']}")
            return result

        # Layer 2: Syntax validation (vendor-specific)
        vendor = config.get('vendor', '').lower()
        if vendor in ['cisco', 'cisco_ios', 'cisco_ios_xe', 'cisco_nxos']:
            syntax_result = await self.validate_cisco_syntax(config)
        elif vendor in ['juniper', 'juniper_junos']:
            syntax_result = await self.validate_juniper_syntax(config)
        else:
            result.add_error(f"Unsupported vendor: {vendor}")
            return result

        if not syntax_result['valid']:
            for error in syntax_result['errors']:
                result.add_error(f"Syntax error: {error}")

        # Layer 3: Security compliance
        security_issues = await self.check_security_compliance(config)
        for issue in security_issues:
            result.add_security_issue(
                issue['type'],
                issue['severity'],
                issue['description']
            )

        # Layer 4: Business rules
        if db:
            business_violations = await self.check_business_rules(config, db)
            for violation in business_violations:
                result.add_error(f"Business rule violation: {violation}")

        # Layer 5: Conflict detection
        conflicts = await self.detect_conflicts(config)
        for conflict in conflicts:
            result.add_warning(f"Configuration conflict: {conflict}")

        # Layer 6: Best practices
        best_practice_issues = await self.check_best_practices(config)
        for issue in best_practice_issues:
            result.add_warning(f"Best practice: {issue}")

        return result

    async def validate_schema(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate configuration schema"""
        required_fields = ['vendor', 'device_type', 'configuration']

        for field in required_fields:
            if field not in config:
                return {
                    'valid': False,
                    'error': f"Missing required field: {field}"
                }

        if not isinstance(config.get('configuration'), str):
            return {
                'valid': False,
                'error': "Configuration must be a string"
            }

        return {'valid': True}

    async def validate_cisco_syntax(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate Cisco configuration syntax"""
        errors = []
        config_text = config.get('configuration', '')
        lines = config_text.split('\n')

        # Check for basic syntax patterns
        interface_open = False
        router_open = False
        acl_open = False
        indent_level = 0

        for i, line in enumerate(lines, 1):
            line = line.rstrip()
            if not line or line.startswith('!'):
                continue

            # Check indentation
            current_indent = len(line) - len(line.lstrip())

            # Interface configuration
            if line.strip().startswith('interface '):
                interface_open = True
                indent_level = 0
                # Validate interface name
                if not re.match(r'interface\s+\S+', line):
                    errors.append(f"Line {i}: Invalid interface syntax")

            elif interface_open and not line.startswith(' '):
                interface_open = False

            # Routing protocol configuration
            elif line.strip().startswith('router '):
                router_open = True
                indent_level = 0
                if not re.match(r'router\s+(ospf|eigrp|bgp|rip)\s*\d*', line):
                    errors.append(f"Line {i}: Invalid router syntax")

            elif router_open and not line.startswith(' '):
                router_open = False

            # Access list configuration
            elif line.strip().startswith('ip access-list'):
                acl_open = True
                if not re.match(r'ip\s+access-list\s+(standard|extended)\s+\S+', line):
                    errors.append(f"Line {i}: Invalid ACL syntax")

            elif acl_open and not line.startswith(' '):
                acl_open = False

            # Check for invalid characters
            if any(char in line for char in ['<', '>', '&', '|', ';'] if not line.startswith('banner')):
                errors.append(f"Line {i}: Contains potentially dangerous characters")

            # Validate IP addresses in the line
            ip_pattern = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
            for ip in ip_pattern:
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    errors.append(f"Line {i}: Invalid IP address: {ip}")

        return {
            'valid': len(errors) == 0,
            'errors': errors
        }

    async def validate_juniper_syntax(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate Juniper configuration syntax"""
        errors = []
        config_text = config.get('configuration', '')
        lines = config_text.split('\n')

        # Juniper uses 'set' commands or hierarchical format
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Check for set command format
            if line.startswith('set '):
                # Validate basic set command structure
                if not re.match(r'set\s+[\w\-]+(?:\s+[\w\-\.\/:]+)*', line):
                    errors.append(f"Line {i}: Invalid set command syntax")

                # Check for dangerous commands
                if 'delete security' in line.lower():
                    errors.append(f"Line {i}: Dangerous command detected")

            elif line.startswith('delete '):
                # Validate delete command
                if not re.match(r'delete\s+[\w\-]+(?:\s+[\w\-\.\/:]+)*', line):
                    errors.append(f"Line {i}: Invalid delete command syntax")

            # Hierarchical format validation
            elif '{' in line or '}' in line:
                # Basic bracket validation
                if line.count('{') != line.count('}'):
                    errors.append(f"Line {i}: Unmatched brackets")

        return {
            'valid': len(errors) == 0,
            'errors': errors
        }

    async def check_security_compliance(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for security compliance issues"""
        issues = []
        config_text = config.get('configuration', '').lower()
        vendor = config.get('vendor', '').lower()

        # Check for exposed secrets
        for secret_type, pattern in self.secret_patterns.items():
            matches = pattern.findall(config_text)
            if matches:
                issues.append({
                    'type': 'exposed_secret',
                    'severity': 'critical',
                    'description': f"Potential {secret_type} exposed in configuration"
                })

        # Check for dangerous commands
        if vendor in self.dangerous_commands:
            for dangerous_cmd in self.dangerous_commands[vendor]:
                if dangerous_cmd.lower() in config_text:
                    issues.append({
                        'type': 'dangerous_command',
                        'severity': 'high',
                        'description': f"Dangerous command detected: {dangerous_cmd}"
                    })

        # Check for missing security configurations
        if vendor in self.required_configs:
            for required_config in self.required_configs[vendor]:
                if required_config.lower() not in config_text:
                    issues.append({
                        'type': 'missing_security_config',
                        'severity': 'medium',
                        'description': f"Missing recommended security configuration: {required_config}"
                    })

        # Check for weak encryption
        if 'des' in config_text and 'encryption' in config_text:
            issues.append({
                'type': 'weak_encryption',
                'severity': 'high',
                'description': "DES encryption detected - use AES instead"
            })

        # Check for telnet usage
        if 'telnet' in config_text and 'transport input' in config_text:
            issues.append({
                'type': 'insecure_protocol',
                'severity': 'high',
                'description': "Telnet protocol enabled - use SSH instead"
            })

        # Check for SNMP v1/v2c
        if ('snmp-server community' in config_text or
            'snmp community' in config_text):
            issues.append({
                'type': 'weak_snmp',
                'severity': 'medium',
                'description': "SNMPv1/v2c detected - consider using SNMPv3"
            })

        return issues

    async def check_business_rules(
        self,
        config: Dict[str, Any],
        db: AsyncSession
    ) -> List[str]:
        """Check business rule compliance"""
        violations = []

        try:
            # Get compliance rules from database
            stmt = select(ComplianceRule).where(
                ComplianceRule.is_active == True
            )
            result = await db.execute(stmt)
            rules = result.scalars().all()

            config_text = config.get('configuration', '')

            for rule in rules:
                # Check if rule applies to this vendor
                if rule.vendor and rule.vendor.lower() != config.get('vendor', '').lower():
                    continue

                # Evaluate rule based on type
                if rule.rule_type == 'required_pattern':
                    pattern = rule.rule_definition.get('pattern')
                    if pattern and not re.search(pattern, config_text):
                        violations.append(f"{rule.name}: Required pattern not found")

                elif rule.rule_type == 'forbidden_pattern':
                    pattern = rule.rule_definition.get('pattern')
                    if pattern and re.search(pattern, config_text):
                        violations.append(f"{rule.name}: Forbidden pattern detected")

                elif rule.rule_type == 'ip_range':
                    allowed_ranges = rule.rule_definition.get('allowed_ranges', [])
                    ip_pattern = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', config_text)
                    for ip in ip_pattern:
                        try:
                            ip_obj = ipaddress.ip_address(ip)
                            allowed = False
                            for range_str in allowed_ranges:
                                if '/' in range_str:
                                    network = ipaddress.ip_network(range_str, strict=False)
                                    if ip_obj in network:
                                        allowed = True
                                        break
                            if not allowed:
                                violations.append(f"{rule.name}: IP {ip} not in allowed ranges")
                        except ValueError:
                            pass

        except Exception as e:
            violations.append(f"Error checking business rules: {str(e)}")

        return violations

    async def detect_conflicts(self, config: Dict[str, Any]) -> List[str]:
        """Detect configuration conflicts"""
        conflicts = []
        config_text = config.get('configuration', '')
        lines = config_text.split('\n')

        # Track configured elements
        interfaces = {}
        ip_addresses = {}
        vlans = set()
        routes = []

        for line in lines:
            line = line.strip()

            # Check for duplicate interface configurations
            if line.startswith('interface '):
                interface_name = line.replace('interface ', '').strip()
                if interface_name in interfaces:
                    conflicts.append(f"Duplicate interface configuration: {interface_name}")
                interfaces[interface_name] = True

            # Check for duplicate IP addresses
            ip_match = re.search(r'ip address ([\d\.]+)\s+([\d\.]+)', line)
            if ip_match:
                ip = ip_match.group(1)
                mask = ip_match.group(2)
                if ip in ip_addresses:
                    conflicts.append(f"Duplicate IP address: {ip}")
                ip_addresses[ip] = mask

            # Check for VLAN conflicts
            vlan_match = re.search(r'vlan (\d+)', line)
            if vlan_match:
                vlan_id = vlan_match.group(1)
                if vlan_id in vlans:
                    conflicts.append(f"Duplicate VLAN configuration: {vlan_id}")
                vlans.add(vlan_id)

            # Check for routing conflicts
            route_match = re.search(r'ip route ([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)', line)
            if route_match:
                network = route_match.group(1)
                mask = route_match.group(2)
                next_hop = route_match.group(3)
                route_key = f"{network}/{mask}"

                for existing_route in routes:
                    if existing_route['network'] == route_key and existing_route['next_hop'] != next_hop:
                        conflicts.append(f"Conflicting routes for {route_key}")

                routes.append({
                    'network': route_key,
                    'next_hop': next_hop
                })

        return conflicts

    async def check_best_practices(self, config: Dict[str, Any]) -> List[str]:
        """Check for best practice violations"""
        issues = []
        config_text = config.get('configuration', '').lower()
        vendor = config.get('vendor', '').lower()

        # General best practices
        if 'description' not in config_text and 'interface' in config_text:
            issues.append("Interfaces lack descriptions")

        if 'ntp server' not in config_text and 'set system ntp' not in config_text:
            issues.append("NTP not configured")

        if 'logging' not in config_text and 'syslog' not in config_text:
            issues.append("Logging not configured")

        # Cisco-specific best practices
        if 'cisco' in vendor:
            if 'spanning-tree portfast' not in config_text:
                issues.append("Spanning-tree portfast not configured on access ports")

            if 'storm-control' not in config_text:
                issues.append("Storm control not configured")

            if 'ip verify source' not in config_text:
                issues.append("IP source guard not configured")

        # Juniper-specific best practices
        if 'juniper' in vendor:
            if 'rpf-check' not in config_text:
                issues.append("Reverse path forwarding check not configured")

            if 'tcp-mss' not in config_text:
                issues.append("TCP MSS not configured")

        return issues

    async def validate_deployment_config(
        self,
        deployment_config: Dict[str, Any],
        target_devices: List[Device]
    ) -> ValidationResult:
        """
        Validate configuration for deployment to specific devices

        Args:
            deployment_config: Configuration to deploy
            target_devices: List of target devices

        Returns:
            ValidationResult
        """
        result = ValidationResult()

        # Check device compatibility
        for device in target_devices:
            device_vendor = device.vendor.lower() if device.vendor else ''
            config_vendor = deployment_config.get('vendor', '').lower()

            if device_vendor and config_vendor:
                # Check vendor compatibility
                if not self._is_vendor_compatible(device_vendor, config_vendor):
                    result.add_error(
                        f"Configuration vendor {config_vendor} incompatible with device {device.hostname} ({device_vendor})"
                    )

            # Check device-specific constraints
            if device.max_config_size:
                config_size = len(deployment_config.get('configuration', ''))
                if config_size > device.max_config_size:
                    result.add_error(
                        f"Configuration size ({config_size}) exceeds device {device.hostname} limit ({device.max_config_size})"
                    )

        # Validate the configuration itself
        config_validation = await self.validate_configuration(deployment_config)

        # Merge results
        result.errors.extend(config_validation.errors)
        result.warnings.extend(config_validation.warnings)
        result.security_issues.extend(config_validation.security_issues)
        result.is_valid = config_validation.is_valid and result.is_valid

        return result

    def _is_vendor_compatible(self, device_vendor: str, config_vendor: str) -> bool:
        """Check if vendor types are compatible"""
        compatibility_map = {
            'cisco_ios': ['cisco', 'cisco_ios', 'cisco_ios_xe'],
            'cisco_ios_xe': ['cisco', 'cisco_ios', 'cisco_ios_xe'],
            'cisco_nxos': ['cisco', 'cisco_nxos', 'cisco_nexus'],
            'juniper': ['juniper', 'juniper_junos', 'junos'],
            'juniper_junos': ['juniper', 'juniper_junos', 'junos']
        }

        compatible_vendors = compatibility_map.get(device_vendor, [device_vendor])
        return config_vendor in compatible_vendors

    async def scan_for_secrets(self, text: str) -> List[Dict[str, Any]]:
        """
        Scan text for exposed secrets

        Args:
            text: Text to scan

        Returns:
            List of found secrets
        """
        found_secrets = []

        for secret_type, pattern in self.secret_patterns.items():
            matches = pattern.finditer(text)
            for match in matches:
                found_secrets.append({
                    'type': secret_type,
                    'match': match.group(0),
                    'position': match.span(),
                    'line': text[:match.start()].count('\n') + 1
                })

        # Additional patterns for specific secret formats

        # AWS credentials
        aws_key_pattern = re.compile(r'AKIA[0-9A-Z]{16}')
        for match in aws_key_pattern.finditer(text):
            found_secrets.append({
                'type': 'aws_access_key',
                'match': match.group(0),
                'position': match.span(),
                'line': text[:match.start()].count('\n') + 1
            })

        # Private keys
        private_key_pattern = re.compile(
            r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----'
        )
        for match in private_key_pattern.finditer(text):
            found_secrets.append({
                'type': 'private_key',
                'match': 'Private key detected',
                'position': match.span(),
                'line': text[:match.start()].count('\n') + 1
            })

        return found_secrets

    def generate_validation_report(self, result: ValidationResult) -> str:
        """Generate human-readable validation report"""
        report = []
        report.append("=" * 60)
        report.append("Configuration Validation Report")
        report.append("=" * 60)
        report.append(f"Timestamp: {result.timestamp}")
        report.append(f"Overall Status: {'PASSED' if result.is_valid else 'FAILED'}")
        report.append("")

        if result.errors:
            report.append(f"ERRORS ({len(result.errors)}):")
            report.append("-" * 40)
            for error in result.errors:
                if isinstance(error, dict):
                    report.append(f"  - {error['message']}")
                else:
                    report.append(f"  - {error}")
            report.append("")

        if result.warnings:
            report.append(f"WARNINGS ({len(result.warnings)}):")
            report.append("-" * 40)
            for warning in result.warnings:
                if isinstance(warning, dict):
                    report.append(f"  - {warning['message']}")
                else:
                    report.append(f"  - {warning}")
            report.append("")

        if result.security_issues:
            report.append(f"SECURITY ISSUES ({len(result.security_issues)}):")
            report.append("-" * 40)
            for issue in result.security_issues:
                report.append(f"  - [{issue['severity'].upper()}] {issue['type']}: {issue['description']}")
            report.append("")

        if result.info:
            report.append(f"INFORMATION ({len(result.info)}):")
            report.append("-" * 40)
            for info in result.info:
                report.append(f"  - {info}")
            report.append("")

        report.append("=" * 60)

        return "\n".join(report)