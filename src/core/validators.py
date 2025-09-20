"""
Multi-layer Configuration Validation
Following CLAUDE.md validation patterns exactly
"""

import re
import ipaddress
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum
from .logging import get_logger

# ValidationError and ComplianceError defined in exceptions module
logger = get_logger(__name__)


class ValidationLevel(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ValidationResult:
    """Validation result container"""

    is_valid: bool = True
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    info: List[str] = field(default_factory=list)

    def add_error(self, message: str):
        """TODO: Add docstring"""
        self.errors.append(message)
        self.is_valid = False

    def add_warning(self, message: str):
        """TODO: Add docstring"""
        self.warnings.append(message)

    def add_info(self, message: str):
        """TODO: Add docstring"""
        self.info.append(message)


class ConfigValidator: """
    PATTERN: Multi-layer validation before deployment
    Following CLAUDE.md validation layers exactly
    """

    def __init__(self):
        """Initialize validator"""
        pass
        self.syntax_validators = {}
        self.security_rules = []
        self.business_rules = []
        self.load_validation_rules()

    def load_validation_rules(self): """Load all validation rules"""
        # Security compliance rules
        self.security_rules = [
            self.no_plaintext_passwords,
            self.no_weak_encryption,
            self.required_access_lists,
            self.no_default_communities,
            self.ssh_only_access,
            self.ntp_configured,
            self.logging_configured,
        ]

        # Business rules
        self.business_rules = [
            self.approved_ip_ranges,
            self.naming_conventions,
            self.vlan_restrictions,
            self.interface_descriptions_required,
        ]

        async def validate_configuration(
            self,
            config: Dict[str,
                         Any]
        ) -> ValidationResult: """
        Main validation method following CLAUDE.md pattern
        """
        result = ValidationResult()

        # Layer 1: Schema validation
        schema_result = await self.validate_schema(config)
        if not schema_result.is_valid:
            result.add_error("Schema validation failed")
            result.errors.extend(schema_result.errors)
            return result  # Stop if schema invalid

        # Layer 2: Syntax validation (vendor-specific)
        vendor = config.get("vendor")
        if not vendor:
            result.add_error("Vendor not specified")
            return result

        syntax_result = await self.validate_syntax(config, vendor)
        if not syntax_result.is_valid:
            result.add_error("Syntax validation failed")
            result.errors.extend(syntax_result.errors)

        # Layer 3: Security compliance
        security_result = await self.check_security_compliance(config)
        for issue in security_result.warnings:
            result.add_warning(f"Security: {issue}")
        for issue in security_result.errors:
            result.add_error(f"Security: {issue}")

        # Layer 4: Business rules
        business_result = await self.check_business_rules(config)
        for violation in business_result.errors:
            result.add_error(f"Business rule: {violation}")

        # Layer 5: Conflict detection
        conflict_result = await self.detect_conflicts(config)
        for conflict in conflict_result.warnings:
            result.add_warning(f"Conflict: {conflict}")

        return result

        async def validate_schema(
            self,
            config: Dict[str,
                         Any]
        ) -> ValidationResult:
        """Layer 1: Schema validation"""
        result = ValidationResult()

        # Required fields
        required_fields = ["vendor", "device_id", "configuration"]
        for field_name in required_fields:
            if field_name not in config:
                result.add_error(f"Required field missing: {field_name}")

        # Field types
        if "configuration" in config and not isinstance(
            config["configuration"], (dict, str)
        ):
            result.add_error("Configuration must be dict or string")

        # Metadata validation
        if "metadata" in config:
            if not isinstance(config["metadata"], dict):
                result.add_error("Metadata must be a dictionary")

        return result

    async def validate_syntax(
        self, config: Dict[str, Any], vendor: str
    ) -> ValidationResult:
        """Layer 2: Vendor-specific syntax validation"""
        result = ValidationResult()

        config_text = config.get("configuration", "")
        if isinstance(config_text, dict):
            config_text = self.dict_to_config_text(config_text, vendor)

        if vendor.lower() == "cisco":
            return await self.validate_cisco_syntax(config_text)
        elif vendor.lower() == "juniper":
            return await self.validate_juniper_syntax(config_text)
        else:
            result.add_error(f"Unsupported vendor: {vendor}")

        return result

    async def validate_cisco_syntax(self, config: str) -> ValidationResult:
        """Validate Cisco IOS/IOS-XE/NX-OS syntax"""
        result = ValidationResult()

        lines = config.strip().split("\n")
        current_context = []
        # interface_context tracks the current interface being configured
        interface_context = None

        for line_num, line in enumerate(lines, 1):
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("!"):
                continue

            # Interface context
            if line.startswith("interface "):
                interface_context = line
                current_context = ["interface"]
                logger.debug(f"Validating interface: {interface_context}")
                # Validate interface name
                if not re.match(r"interface \S+", line):
                    result.add_error(f"Line {line_num}: Invalid interface \"
                        syntax")

            # Exit context
            elif line == "exit" or line == "end":
                current_context = []

            # IP address validation
            elif "ip address" in line:
                if "interface" not in current_context:
                    result.add_warning(
                        f"Line {line_num}: IP address outside interface \"
                            context"
                    )

                # Extract and validate IP
                match = re.search(r"ip address (\S+) (\S+)", line)
                if match:
                    try:
                        ipaddress.IPv4Interface(f"{match.group(}"
                            1)}/{match.group(2)}")
                    except ValueError:
                        result.add_error(
                            f"Line {line_num}: Invalid IP address \"
                            or mask")

            # ACL validation
            elif line.startswith("access-list"):
                if not re.match(r"access-list \d+ (permit|deny)", line):
                    result.add_error(f"Line {line_num}: Invalid ACL syntax")

            # VLAN validation
            elif line.startswith("vlan "):
                match = re.match(r"vlan (\d+)", line)
                if match:
                    vlan_id = int(match.group(1))
                    if vlan_id < 1 or vlan_id > 4094:
                        result.add_error(f"Line {line_num}: Invalid VLAN ID \"
                            {vlan_id}")

        return result

    async def validate_juniper_syntax(self, config: str) -> ValidationResult:
        """Validate Juniper Junos syntax"""
        result = ValidationResult()

        lines = config.strip().split("\n")

        for line_num, line in enumerate(lines, 1):
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            # Set commands
            if line.startswith("set "):
                # Basic syntax check
                if not re.match(r"set \S+ \S+", line):
                    result.add_error(f"Line {line_num}: Invalid set command \"
                        syntax")

                # Interface validation
                if "interfaces" in line:
                    # Check for valid interface format
                    if not re.search(r"(ge-|xe-|et-)\d+/\d+/\d+", line):
                        result.add_warning(
                            f"Line {line_num}: Non-standard interface naming"
                        )

                # IP address validation
                if "address" in line:
                    match = re.search(r"address (\S+)", line)
                    if match:
                        try:
                            ipaddress.IPv4Interface(match.group(1))
                        except ValueError:
                            result.add_error(f"Line {line_num}: Invalid IP \"
                                address")

            # Delete commands
            elif line.startswith("delete "):
                if not re.match(r"delete \S+", line):
                    result.add_error(
                        f"Line {line_num}: Invalid delete command \"
                        syntax")

        return result

    async def check_security_compliance(
        self, config: Dict[str, Any]
    ) -> ValidationResult:
        """Layer 3: Security compliance validation"""
        result = ValidationResult()

        config_text = config.get("configuration", "")
        if isinstance(config_text, dict):
            config_text = str(config_text)

        # Run all security rules
        for rule in self.security_rules:
            rule_result = rule(config_text)
            if rule_result:
                result.add_warning(rule_result)

        return result

    def no_plaintext_passwords(self, config: str) -> Optional[str]:
        """Check for plaintext passwords"""
        # Check for common plaintext password patterns
        patterns = [
            r"password [^0-9]\S+",  # Non-encrypted password
            r"enable password [^0-9]",  # Non-encrypted enable
            r"username \S+ password [^0-9]",  # User password not encrypted
        ]

        for pattern in patterns:
            if re.search(pattern, config, re.IGNORECASE):
                return "Plaintext passwords detected - use encryption"

        return None

    def no_weak_encryption(self, config: str) -> Optional[str]:
        """Check for weak encryption algorithms"""
        weak_algorithms = ["des", "md5", "3des", "rc4"]

        for algo in weak_algorithms:
            if algo in config.lower():
                return f"Weak encryption algorithm detected: {algo}"

        return None

    def required_access_lists(self, config: str) -> Optional[str]:
        """Check for required access lists"""
        if "vty" in config.lower():
            if "access-class" not in config.lower():
                return "VTY lines without access-class"

        return None

    def no_default_communities(self, config: str) -> Optional[str]:
        """Check for default SNMP communities"""
        default_communities = ["public", "private"]

        for community in default_communities:
            if f"community {community}" in config.lower():
                return f"Default SNMP community detected: {community}"

        return None

    def ssh_only_access(self, config: str) -> Optional[str]:
        """Ensure SSH-only access"""
        if "transport input telnet" in config.lower():
            return "Telnet access enabled - use SSH only"

        if "line vty" in config.lower() and "transport input ssh" not in \
                config.lower():
            return "VTY lines should specify SSH-only access"

        return None

    def ntp_configured(self, config: str) -> Optional[str]:
        """Check NTP is configured"""
        if "ntp server" not in config.lower():
            return "NTP not configured - time synchronization required"

        return None

    def logging_configured(self, config: str) -> Optional[str]:
        """Check logging is configured"""
        if "logging" not in config.lower():
            return "Logging not configured"

        return None

        async def check_business_rules(
            self,
            config: Dict[str,
                         Any]
        ) -> ValidationResult:
        """Layer 4: Business rules validation"""
        result = ValidationResult()

        config_text = config.get("configuration", "")
        if isinstance(config_text, dict):
            config_text = str(config_text)

        for rule in self.business_rules:
            violation = rule(config_text)
            if violation:
                result.add_error(violation)

        return result

    def approved_ip_ranges(self, config: str) -> Optional[str]:
        """Check for approved IP ranges"""
        # Extract all IP addresses
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        ips = re.findall(ip_pattern, config)

        # Define approved ranges (example)
        approved_ranges = [
            ipaddress.IPv4Network("10.0.0.0/8"),
            ipaddress.IPv4Network("172.16.0.0/12"),
            ipaddress.IPv4Network("192.168.0.0/16"),
        ]

        for ip_str in ips:
            try:
                ip = ipaddress.IPv4Address(ip_str)
                if not any(ip in network for network in approved_ranges):
                    return f"IP address {ip} not in approved ranges"
            except ValueError:
                pass

        return None

    def naming_conventions(self, config: str) -> Optional[str]:
        """Check naming conventions"""
        # Check interface descriptions
        if "interface " in config:
            if "description" not in config:
                return "Interface missing description"

        # Check hostname format (example: must start with site code)
        hostname_match = re.search(r"hostname (\S+)", config)
        if hostname_match:
            hostname = hostname_match.group(1)
            if not re.match(r"^[A-Z]{3}-", hostname):
                return f"Hostname {hostname} doesn't follow naming convention"

        return None

    def vlan_restrictions(self, config: str) -> Optional[str]:
        """Check VLAN restrictions"""
        # Reserved VLANs
        reserved_vlans = [1, 1002, 1003, 1004, 1005]

        vlan_matches = re.findall(r"vlan (\d+)", config)
        for vlan_str in vlan_matches:
            vlan_id = int(vlan_str)
            if vlan_id in reserved_vlans:
                return f"VLAN {vlan_id} is reserved"

        return None

    def interface_descriptions_required(self, config: str) -> Optional[str]:
        """Ensure all interfaces have descriptions"""
        lines = config.split("\n")
        in_interface = False

        for line in lines:
            if line.strip().startswith("interface "):
                in_interface = True
                has_description = False
            elif in_interface and line.strip().startswith("description"):
                has_description = True
            elif in_interface and (
                line.strip() == "!" or line.strip().startswith("interface")
            ):
                if not has_description:
                    return "Interface missing description"
                in_interface = False

        return None

        async def detect_conflicts(
            self,
            config: Dict[str,
                         Any]
        ) -> ValidationResult:
        """Layer 5: Conflict detection"""
        result = ValidationResult()

        config_text = config.get("configuration", "")
        if isinstance(config_text, dict):
            config_text = str(config_text)

        # Check for duplicate IP addresses
        ip_pattern = r"ip address (\S+) (\S+)"
        ip_matches = re.findall(ip_pattern, config_text)
        seen_ips = set()

        for ip, mask in ip_matches:
            if ip in seen_ips:
                result.add_warning(f"Duplicate IP address: {ip}")
            seen_ips.add(ip)

        # Check for overlapping ACLs
        acl_pattern = r"access-list (\d+)"
        acl_matches = re.findall(acl_pattern, config_text)
        acl_counts = {}

        for acl_num in acl_matches:
            acl_counts[acl_num] = acl_counts.get(acl_num, 0) + 1

        for acl_num, count in acl_counts.items():
            if count > 10:  # Arbitrary threshold
                result.add_warning(
                    f"ACL {acl_num} has {count} entries - consider \"
                        optimization"
                )

        # Check for routing conflicts
        static_routes = re.findall(r"ip route (\S+) (\S+) (\S+)", config_text)
        for i, route1 in enumerate(static_routes):
            for route2 in static_routes[i + 1:]:
                if route1[0] == route2[0] and route1[1] == route2[1]:
                    result.add_warning(
                        f"Duplicate static route for {route1[0]}/{route1[1]}"
                    )

        return result

        def dict_to_config_text(
            self,
            config_dict: Dict[str,
                              Any],
            vendor: str
        ) -> str:
        """Convert configuration dictionary to text format"""
        # Simple conversion - would be more complex in production
        lines = []
        for key, value in config_dict.items():
            if isinstance(value, dict):
                lines.append(f"{key}")
                for subkey, subvalue in value.items():
                    lines.append(f"  {subkey} {subvalue}")
            else:
                lines.append(f"{key} {value}")

        return "\n".join(lines)
