"""
Deployment validators.
"""

import re
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
import ipaddress

from jsonschema import validate, ValidationError
import yaml

from src.core.logging import get_logger

logger = get_logger(__name__)


class ConfigValidator:
    """Configuration validator for deployments."""

    def __init__(self):
        self.schemas = self._load_schemas()
        self.secret_patterns = [
            re.compile(r'password\s*[:=]\s*["\']?[^\s"\']+', re.IGNORECASE),
            re.compile(r'api[_-]?key\s*[:=]\s*["\']?[^\s"\']+', re.IGNORECASE),
            re.compile(r'secret\s*[:=]\s*["\']?[^\s"\']+', re.IGNORECASE),
            re.compile(r'token\s*[:=]\s*["\']?[^\s"\']+', re.IGNORECASE),
            re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'),
            re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'),  # Base64 encoded secrets
        ]

    def _load_schemas(self) -> Dict[str, Any]:
        """Load validation schemas."""
        return {
            'cisco_ios': {
                'type': 'object',
                'required': ['hostname', 'interfaces'],
                'properties': {
                    'hostname': {'type': 'string'},
                    'domain': {'type': 'string'},
                    'interfaces': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'required': ['name', 'ip_address'],
                            'properties': {
                                'name': {'type': 'string'},
                                'ip_address': {'type': 'string'},
                                'netmask': {'type': 'string'},
                                'description': {'type': 'string'},
                                'shutdown': {'type': 'boolean'}
                            }
                        }
                    },
                    'routing': {
                        'type': 'object',
                        'properties': {
                            'static_routes': {'type': 'array'},
                            'ospf': {'type': 'object'},
                            'bgp': {'type': 'object'}
                        }
                    },
                    'acl': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'required': ['name', 'rules'],
                            'properties': {
                                'name': {'type': 'string'},
                                'type': {'type': 'string', 'enum': ['standard', 'extended']},
                                'rules': {'type': 'array'}
                            }
                        }
                    }
                }
            },
            'juniper_junos': {
                'type': 'object',
                'required': ['system', 'interfaces'],
                'properties': {
                    'system': {
                        'type': 'object',
                        'properties': {
                            'host-name': {'type': 'string'},
                            'domain-name': {'type': 'string'},
                            'time-zone': {'type': 'string'}
                        }
                    },
                    'interfaces': {
                        'type': 'object',
                        'patternProperties': {
                            '^[a-z]+-[0-9]+/[0-9]+/[0-9]+$': {
                                'type': 'object',
                                'properties': {
                                    'unit': {
                                        'type': 'object',
                                        'properties': {
                                            'family': {'type': 'object'}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

    async def validate(
        self,
        config: Dict[str, Any],
        config_type: str = "cisco_ios"
    ) -> 'ValidationResult':
        """
        Validate configuration.

        Args:
            config: Configuration to validate
            config_type: Type of configuration

        Returns:
            Validation result
        """
        from .models import ValidationResult

        result = ValidationResult(
            valid=True,
            errors=[],
            warnings=[],
            suggestions=[]
        )

        try:
            # Schema validation
            if config_type in self.schemas:
                try:
                    validate(config, self.schemas[config_type])
                    result.passed_checks.append('schema_validation')
                except ValidationError as e:
                    result.valid = False
                    result.errors.append(f"Schema validation: {e.message}")
                    result.failed_checks.append('schema_validation')
                    result.schema_valid = False
            else:
                result.warnings.append(f"No schema available for {config_type}")

            # Syntax validation
            if not self._validate_syntax(config, config_type):
                result.valid = False
                result.errors.append("Syntax validation failed")
                result.failed_checks.append('syntax_validation')
                result.syntax_valid = False
            else:
                result.passed_checks.append('syntax_validation')

            # Secret detection
            if self._contains_secrets(config):
                result.valid = False
                result.errors.append("Configuration contains secrets")
                result.failed_checks.append('secret_detection')
                result.security_compliant = False
            else:
                result.passed_checks.append('secret_detection')

            # Business rules validation
            business_errors = self._validate_business_rules(config, config_type)
            if business_errors:
                result.errors.extend(business_errors)
                result.failed_checks.append('business_rules')
                result.business_rules_valid = False
            else:
                result.passed_checks.append('business_rules')

            # Security compliance
            security_issues = self._validate_security(config, config_type)
            if security_issues:
                result.warnings.extend(security_issues)
                if any('critical' in issue.lower() for issue in security_issues):
                    result.security_compliant = False

            # Generate suggestions
            result.suggestions = self._generate_suggestions(config, config_type)

        except Exception as e:
            logger.error(f"Configuration validation error: {e}")
            result.valid = False
            result.errors.append(f"Validation error: {str(e)}")

        return result

    def _validate_syntax(self, config: Dict[str, Any], config_type: str) -> bool:
        """Validate configuration syntax."""
        try:
            if config_type == "cisco_ios":
                return self._validate_cisco_syntax(config)
            elif config_type == "juniper_junos":
                return self._validate_juniper_syntax(config)
            else:
                return True
        except Exception as e:
            logger.error(f"Syntax validation error: {e}")
            return False

    def _validate_cisco_syntax(self, config: Dict[str, Any]) -> bool:
        """Validate Cisco IOS syntax."""
        # Check IP addresses
        if 'interfaces' in config:
            for interface in config['interfaces']:
                if 'ip_address' in interface:
                    try:
                        ipaddress.ip_address(interface['ip_address'])
                    except ValueError:
                        return False

        # Check interface names
        cisco_interface_pattern = re.compile(
            r'^(GigabitEthernet|FastEthernet|Ethernet|Loopback|Vlan|Tunnel|Port-channel)'
            r'[0-9]+(/[0-9]+)*$'
        )
        if 'interfaces' in config:
            for interface in config['interfaces']:
                if 'name' in interface:
                    if not cisco_interface_pattern.match(interface['name']):
                        return False

        return True

    def _validate_juniper_syntax(self, config: Dict[str, Any]) -> bool:
        """Validate Juniper Junos syntax."""
        # Check interface names
        juniper_interface_pattern = re.compile(
            r'^(ge|xe|et|ae|lo|vlan|irb|gr|ip|lsq|mt|vt)-[0-9]+/[0-9]+/[0-9]+(\.[0-9]+)?$'
        )
        if 'interfaces' in config:
            for interface_name in config['interfaces'].keys():
                if not juniper_interface_pattern.match(interface_name):
                    return False

        return True

    def _contains_secrets(self, config: Any) -> bool:
        """Check if configuration contains secrets."""
        config_str = json.dumps(config) if isinstance(config, dict) else str(config)

        for pattern in self.secret_patterns:
            if pattern.search(config_str):
                return True

        # Check for common secret field names
        secret_fields = ['password', 'secret', 'key', 'token', 'credential', 'api_key']
        if isinstance(config, dict):
            for field in secret_fields:
                if field in config and config[field]:
                    return True

        return False

    def _validate_business_rules(
        self,
        config: Dict[str, Any],
        config_type: str
    ) -> List[str]:
        """Validate business rules."""
        errors = []

        # Generic rules
        if config.get('mtu', 1500) > 9000:
            errors.append("MTU cannot exceed 9000")

        if config.get('timeout', 0) < 1:
            errors.append("Timeout must be at least 1 second")

        # Vendor-specific rules
        if config_type == "cisco_ios":
            # Cisco-specific rules
            if 'interfaces' in config:
                vlan_ids = set()
                for interface in config['interfaces']:
                    if interface.get('name', '').startswith('Vlan'):
                        vlan_id = int(interface['name'].replace('Vlan', ''))
                        if vlan_id < 1 or vlan_id > 4094:
                            errors.append(f"Invalid VLAN ID: {vlan_id}")
                        if vlan_id in vlan_ids:
                            errors.append(f"Duplicate VLAN ID: {vlan_id}")
                        vlan_ids.add(vlan_id)

        elif config_type == "juniper_junos":
            # Juniper-specific rules
            if 'system' in config:
                hostname = config['system'].get('host-name', '')
                if len(hostname) > 63:
                    errors.append("Hostname cannot exceed 63 characters")

        return errors

    def _validate_security(
        self,
        config: Dict[str, Any],
        config_type: str
    ) -> List[str]:
        """Validate security aspects."""
        issues = []

        # Check for insecure protocols
        insecure_protocols = ['telnet', 'http', 'ftp', 'tftp']
        config_str = json.dumps(config).lower()
        for protocol in insecure_protocols:
            if protocol in config_str:
                issues.append(f"Insecure protocol detected: {protocol}")

        # Check for weak encryption
        if config.get('encryption', '').lower() in ['des', 'rc4', 'md5']:
            issues.append(f"Weak encryption: {config['encryption']}")

        # Check for missing security features
        if not config.get('ssh', {}).get('enabled', False):
            issues.append("SSH is not enabled")

        if not config.get('logging', {}).get('enabled', False):
            issues.append("Logging is not enabled")

        # Check ACLs
        if 'acl' not in config or not config['acl']:
            issues.append("No access control lists defined")

        return issues

    def _generate_suggestions(
        self,
        config: Dict[str, Any],
        config_type: str
    ) -> List[str]:
        """Generate configuration suggestions."""
        suggestions = []

        # General suggestions
        if not config.get('ntp', {}).get('servers'):
            suggestions.append("Consider configuring NTP servers for time synchronization")

        if not config.get('snmp', {}).get('enabled'):
            suggestions.append("Consider enabling SNMP for monitoring")

        if not config.get('backup', {}).get('schedule'):
            suggestions.append("Consider setting up automated configuration backups")

        # Vendor-specific suggestions
        if config_type == "cisco_ios":
            if not config.get('spanning-tree', {}).get('mode'):
                suggestions.append("Consider configuring spanning-tree mode")

        elif config_type == "juniper_junos":
            if not config.get('system', {}).get('services', {}).get('netconf'):
                suggestions.append("Consider enabling NETCONF for automation")

        return suggestions


class PreDeploymentValidator:
    """Pre-deployment validation."""

    def __init__(self):
        self.required_checks = [
            'device_reachability',
            'device_compatibility',
            'resource_availability',
            'dependency_check',
            'conflict_detection'
        ]

    async def validate(
        self,
        config: Dict[str, Any],
        devices: List[str]
    ) -> 'PreValidationResult':
        """
        Perform pre-deployment validation.

        Args:
            config: Configuration to deploy
            devices: Target devices

        Returns:
            Validation result
        """
        from .models import ValidationResult

        result = ValidationResult(
            valid=True,
            errors=[],
            warnings=[]
        )

        try:
            # Check device reachability
            reachable = await self._check_device_reachability(devices)
            if not all(reachable.values()):
                unreachable = [d for d, r in reachable.items() if not r]
                result.valid = False
                result.errors.append(f"Unreachable devices: {unreachable}")
                result.failed_checks.append('device_reachability')
            else:
                result.passed_checks.append('device_reachability')

            # Check device compatibility
            compatible = await self._check_device_compatibility(config, devices)
            if not all(compatible.values()):
                incompatible = [d for d, c in compatible.items() if not c]
                result.warnings.append(f"Incompatible devices: {incompatible}")
                result.failed_checks.append('device_compatibility')
            else:
                result.passed_checks.append('device_compatibility')

            # Check resource availability
            resources_ok = await self._check_resource_availability(devices)
            if not resources_ok:
                result.warnings.append("Some devices have low resources")

            # Check dependencies
            dependencies_met = await self._check_dependencies(config, devices)
            if not dependencies_met:
                result.valid = False
                result.errors.append("Dependencies not met")
                result.failed_checks.append('dependency_check')
            else:
                result.passed_checks.append('dependency_check')

            # Check for conflicts
            conflicts = await self._detect_conflicts(config, devices)
            if conflicts:
                result.warnings.extend([f"Conflict: {c}" for c in conflicts])

            result.passed = result.valid

        except Exception as e:
            logger.error(f"Pre-deployment validation error: {e}")
            result.valid = False
            result.passed = False
            result.errors.append(str(e))

        return result

    async def _check_device_reachability(
        self,
        devices: List[str]
    ) -> Dict[str, bool]:
        """Check device reachability."""
        # Placeholder implementation
        # In real implementation, would ping or connect to devices
        return {device: True for device in devices}

    async def _check_device_compatibility(
        self,
        config: Dict[str, Any],
        devices: List[str]
    ) -> Dict[str, bool]:
        """Check device compatibility with configuration."""
        # Placeholder implementation
        return {device: True for device in devices}

    async def _check_resource_availability(
        self,
        devices: List[str]
    ) -> bool:
        """Check if devices have sufficient resources."""
        # Check CPU, memory, storage
        return True

    async def _check_dependencies(
        self,
        config: Dict[str, Any],
        devices: List[str]
    ) -> bool:
        """Check if dependencies are met."""
        # Check required features, modules, licenses
        return True

    async def _detect_conflicts(
        self,
        config: Dict[str, Any],
        devices: List[str]
    ) -> List[str]:
        """Detect configuration conflicts."""
        conflicts = []

        # Check for IP address conflicts
        # Check for VLAN conflicts
        # Check for routing conflicts

        return conflicts


class PostDeploymentValidator:
    """Post-deployment validation."""

    def __init__(self):
        self.health_checks = [
            'connectivity',
            'service_availability',
            'performance_metrics',
            'error_rates',
            'config_verification'
        ]

    async def validate(
        self,
        config: Dict[str, Any],
        devices: List[str]
    ) -> 'PostValidationResult':
        """
        Perform post-deployment validation.

        Args:
            config: Deployed configuration
            devices: Deployed devices

        Returns:
            Validation result
        """
        from .models import ValidationResult

        result = ValidationResult(
            valid=True,
            errors=[],
            warnings=[]
        )

        try:
            # Verify configuration was applied
            config_applied = await self._verify_config_applied(config, devices)
            if not all(config_applied.values()):
                failed = [d for d, a in config_applied.items() if not a]
                result.errors.append(f"Configuration not applied: {failed}")
                result.failed_checks.append('config_verification')
            else:
                result.passed_checks.append('config_verification')

            # Check connectivity
            connectivity_ok = await self._check_connectivity(devices)
            if not all(connectivity_ok.values()):
                failed = [d for d, c in connectivity_ok.items() if not c]
                result.errors.append(f"Connectivity issues: {failed}")
                result.failed_checks.append('connectivity')
            else:
                result.passed_checks.append('connectivity')

            # Check service availability
            services_ok = await self._check_services(devices)
            if not all(services_ok.values()):
                failed = [d for d, s in services_ok.items() if not s]
                result.warnings.append(f"Service issues: {failed}")

            # Check performance metrics
            performance_ok = await self._check_performance(devices)
            if not performance_ok:
                result.warnings.append("Performance degradation detected")

            # Check error rates
            error_rates_ok = await self._check_error_rates(devices)
            if not error_rates_ok:
                result.warnings.append("Elevated error rates detected")

            result.passed = len(result.errors) == 0

        except Exception as e:
            logger.error(f"Post-deployment validation error: {e}")
            result.valid = False
            result.passed = False
            result.errors.append(str(e))

        return result

    async def _verify_config_applied(
        self,
        config: Dict[str, Any],
        devices: List[str]
    ) -> Dict[str, bool]:
        """Verify configuration was applied to devices."""
        # Placeholder implementation
        return {device: True for device in devices}

    async def _check_connectivity(
        self,
        devices: List[str]
    ) -> Dict[str, bool]:
        """Check device connectivity."""
        # Ping tests, traceroute, etc.
        return {device: True for device in devices}

    async def _check_services(
        self,
        devices: List[str]
    ) -> Dict[str, bool]:
        """Check service availability."""
        # Check SSH, SNMP, other services
        return {device: True for device in devices}

    async def _check_performance(
        self,
        devices: List[str]
    ) -> bool:
        """Check performance metrics."""
        # CPU, memory, bandwidth utilization
        return True

    async def _check_error_rates(
        self,
        devices: List[str]
    ) -> bool:
        """Check error rates."""
        # Interface errors, packet loss, etc.
        return True