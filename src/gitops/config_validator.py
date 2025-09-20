"""
Configuration Validator for CatNet GitOps

Validates network device configurations:
- Syntax validation for Cisco/Juniper
- Security compliance checks
- Business rule validation
- Conflict detection
"""

import re
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum


class ValidationType(Enum):"""Types of validation"""

    SYNTAX = "syntax"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    BUSINESS = "business"
    CONFLICT = "conflict"


class Severity(Enum):
    """Issue severity levels"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ValidationIssue:
    """Represents a validation issue"""

    type: ValidationType
    severity: Severity
    message: str
    line_number: Optional[int] = None
    config_section: Optional[str] = None
    recommendation: Optional[str] = None


@dataclass
class ValidationResult:"""Result of configuration validation"""

    is_valid: bool
    config_file: str
    vendor: str
    issues: List[ValidationIssue] = field(default_factory=list)
    warnings: List[ValidationIssue] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ConfigValidator:"""
    Validates network device configurations
    """

    def __init__(self):"""Initialize configuration validator"""
        # Security patterns to check
        self.security_patterns = {
            "weak_encryption": [
                r"enable password [^7]",  # Cleartext enable password
                r"username \S+ password [^7]",  # Cleartext user password
                r"snmp-server community \S+ (RO|RW)",  # SNMP community strings
                r"key-string \S+",  # Cleartext keys
            ],
            "insecure_protocols": [
                r"ip http server(?! secure)",  # HTTP without HTTPS
                r"telnet",  # Telnet enabled
                r"snmp-server.*v[12](?!c)",  # SNMPv1/v2 without v2c
                r"ftp-server",  # FTP server
            ],
            "missing_security": [
                                r"^(
                    ?!.*service password-encryption" \
                )",  # Missing password encryption
                r"^(?!.*aaa new-model)",  # Missing AAA
                r"^(?!.*login on-failure)",  # Missing login failure logging
            ],
        }

        # Compliance rules
        self.compliance_rules = {
            "password_policy": {
                "min_length": 14,
                "complexity": r"(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])",
            },
            "required_features": [
                "ntp server",  # Time synchronization
                "logging host",  # Centralized logging
                "banner motd",  # Login banner
                "ip access-list",  # Access control
            ],
            "prohibited_features": [
                "ip source-route",  # Source routing
                "ip directed-broadcast",  # Directed broadcasts
                "ip proxy-arp",  # Proxy ARP
            ],
        }

        # Business rules
        self.business_rules = {
            "vlan_range": (1, 4094),
                        "interface_naming": r"^(
                GigabitEthernet|FastEthernet|Vlan|Loopback|Tunnel" \
            )",
            "ip_ranges": [
                r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # RFC1918
                r"172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}",
                r"192\.168\.\d{1,3}\.\d{1,3}",
            ],
        }

    def validate_configuration(
        self,
        config_content: str,
        vendor: str,
        config_file: str = "unknown",
        full_validation: bool = True,
    ) -> ValidationResult:
        """
        Validate network device configuration

        Args:
            config_content: Configuration content
            vendor: Device vendor (cisco, juniper)
            config_file: Configuration file name
            full_validation: Perform all validation types

        Returns:
            ValidationResult object"""
        result = ValidationResult(
            is_valid=True, config_file=config_file, vendor=vendor.lower()
        )

        # Vendor-specific syntax validation
        if vendor.lower() == "cisco":
            self._validate_cisco_syntax(config_content, result)
        elif vendor.lower() == "juniper":
            self._validate_juniper_syntax(config_content, result)
        else:
            result.issues.append(
                ValidationIssue(
                    type=ValidationType.SYNTAX,
                    severity=Severity.CRITICAL,
                    message=f"Unsupported vendor: {vendor}",
                )
            )
            result.is_valid = False
            return result

        if full_validation:
            # Security validation
            self._validate_security(config_content, vendor, result)

            # Compliance validation
            self._validate_compliance(config_content, vendor, result)

            # Business rules validation
            self._validate_business_rules(config_content, vendor, result)

            # Conflict detection
            self._detect_conflicts(config_content, vendor, result)

        # Determine overall validity
        critical_issues = [i for i in result.issues if i.severity == \
            Severity.CRITICAL]
        high_issues = [i for i in result.issues if i.severity == Severity.HIGH]

        result.is_valid = len(critical_issues) == 0 and len(high_issues) == 0

        # Add metadata
        result.metadata = {
            "total_issues": len(result.issues),
            "total_warnings": len(result.warnings),
            "critical_count": len(critical_issues),
            "high_count": len(high_issues),
            "line_count": len(config_content.splitlines()),
        }

        return result

        def _validate_cisco_syntax(
        self,
        config: str,
        result: ValidationResult
    ) -> None:
        """
        Validate Cisco IOS/IOS-XE/NX-OS syntax

        Args:
            config: Configuration content
            result: ValidationResult to update"""
        lines = config.splitlines()

        # Track configuration context
        current_context = "global"
        interface_stack = []
        acl_stack = []

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()

            # Skip comments and empty lines
            if not stripped or stripped.startswith("!"):
                continue

            # Check interface context
            if stripped.startswith("interface "):
                interface_name = stripped.replace("interface ", "")
                if not self._is_valid_cisco_interface(interface_name):
                    result.issues.append(
                        ValidationIssue(
                            type=ValidationType.SYNTAX,
                            severity=Severity.HIGH,
                            message=f"Invalid interface name: {interface_name}",
                                
                            line_number=line_num,
                        )
                    )
                current_context = "interface"
                interface_stack.append(interface_name)

            # Check ACL context
            elif stripped.startswith("ip access-list "):
                acl_name = stripped.split()[-1]
                current_context = "acl"
                acl_stack.append(acl_name)

            # Check for exit
            elif stripped == "exit" or stripped == "end":
                if interface_stack:
                    interface_stack.pop()
                if acl_stack:
                    acl_stack.pop()
                current_context = "global"

            # Validate IP addresses
            ip_addresses = re.findall(
                r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b", stripped
            )
            for ip in ip_addresses:
                if not self._is_valid_ip(ip):
                    result.issues.append(
                        ValidationIssue(
                            type=ValidationType.SYNTAX,
                            severity=Severity.HIGH,
                            message=f"Invalid IP address: {ip}",
                            line_number=line_num,
                        )
                    )

            # Check for common syntax errors
            if current_context == "interface":
                if stripped.startswith("ip address") and "secondary" not in \
                    stripped:
                    parts = stripped.split()
                    if len(parts) != 4:  # ip address <ip> <mask>
                        result.issues.append(
                            ValidationIssue(
                                type=ValidationType.SYNTAX,
                                severity=Severity.HIGH,
                                message="Invalid IP address configuration",
                                line_number=line_num,
                                config_section=interface_stack[-1]
                                if interface_stack
                                else None,
                            )
                        )

        def _validate_juniper_syntax(
        self,
        config: str,
        result: ValidationResult
    ) -> None:
        """
        Validate Juniper Junos syntax

        Args:
            config: Configuration content
            result: ValidationResult to update"""
        lines = config.splitlines()

        # Check for hierarchy
        brace_count = 0

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()

            # Track braces
            brace_count += stripped.count("{")
            brace_count -= stripped.count("}")

            # Check for semicolons at end of statements
            if (
                stripped
                and not stripped.endswith(";")
                and not stripped.endswith("{")
                and not stripped.endswith("}")
                and not stripped.startswith("#")
            ):
                result.issues.append(
                    ValidationIssue(
                        type=ValidationType.SYNTAX,
                        severity=Severity.MEDIUM,
                        message="Missing semicolon at end of statement",
                        line_number=line_num,
                    )
                )

            # Check IP addresses
            ip_addresses = re.findall(
                r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b", stripped
            )
            for ip in ip_addresses:
                if not self._is_valid_ip(ip):
                    result.issues.append(
                        ValidationIssue(
                            type=ValidationType.SYNTAX,
                            severity=Severity.HIGH,
                            message=f"Invalid IP address: {ip}",
                            line_number=line_num,
                        )
                    )

        # Check brace matching
        if brace_count != 0:
            result.issues.append(
                ValidationIssue(
                    type=ValidationType.SYNTAX,
                    severity=Severity.CRITICAL,
                    message=f"Unmatched braces in configuration ({brace_count} \"
                        {}"
    'open' if brace_count > 0 else 'close'} braces)",
                )
            )

    def _validate_security(
        self, config: str, vendor: str, result: ValidationResult
    ) -> None:
        """
        Validate security aspects of configuration

        Args:
            config: Configuration content
            vendor: Device vendor
            result: ValidationResult to update"""
        lines = config.splitlines()

        # Check for weak encryption
        for pattern_type, patterns in self.security_patterns.items():
            for pattern in patterns:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        if pattern_type == "weak_encryption":
                            severity = Severity.CRITICAL
                            message = "Weak or no encryption detected"
                            recommendation = "Use type 7 or stronger \"
                                encryption"
                        elif pattern_type == "insecure_protocols":
                            severity = Severity.HIGH
                            message = f"Insecure protocol enabled: \"
                                {line.strip()}"
                            recommendation = "Disable insecure protocols"
                        else:
                            severity = Severity.HIGH
                            message = f"Missing security feature: \"
                                {line.strip()}"
                            recommendation = "Enable recommended security \"
                                features"

                        result.issues.append(
                            ValidationIssue(
                                type=ValidationType.SECURITY,
                                severity=severity,
                                message=message,
                                line_number=line_num,
                                recommendation=recommendation,
                            )
                        )

        # Check for hardcoded secrets
        secret_patterns = [
            r"password\s+\S+",
            r"secret\s+\S+",
            r"key\s+\S+",
            r"community\s+\S+",
        ]

        for pattern in secret_patterns:
            for line_num, line in enumerate(lines, 1):
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    # Check if it's not a variable or reference
                    value = match.group().split()[-1]
                    if not value.startswith("$") and not value.startswith("%"):
                        result.warnings.append(
                            ValidationIssue(
                                type=ValidationType.SECURITY,
                                severity=Severity.MEDIUM,
                                message="Potential hardcoded credential \
                                    detected",
                                line_number=line_num,
                                recommendation="Use vault or environment 
    variables for secrets",
                            )
                        )

    def _validate_compliance(
        self, config: str, vendor: str, result: ValidationResult
    ) -> None:
        """
        Validate compliance with policies

        Args:
            config: Configuration content
            vendor: Device vendor
            result: ValidationResult to update"""
        # Check for required features
        for feature in self.compliance_rules["required_features"]:
            if feature not in config.lower():
                result.issues.append(
                    ValidationIssue(
                        type=ValidationType.COMPLIANCE,
                        severity=Severity.HIGH,
                        message=f"Missing required feature: {feature}",
                        recommendation=f"Configure {feature}",
                    )
                )

        # Check for prohibited features
        for feature in self.compliance_rules["prohibited_features"]:
            if feature in config.lower():
                result.issues.append(
                    ValidationIssue(
                        type=ValidationType.COMPLIANCE,
                        severity=Severity.HIGH,
                        message=f"Prohibited feature detected: {feature}",
                        recommendation=f"Remove or disable {feature}",
                    )
                )

    def _validate_business_rules(
        self, config: str, vendor: str, result: ValidationResult
    ) -> None:
        """
        Validate business rules

        Args:
            config: Configuration content
            vendor: Device vendor
            result: ValidationResult to update"""
        lines = config.splitlines()

        # Check VLAN ranges
        vlan_pattern = r"vlan\s+(\d+)"
        for line_num, line in enumerate(lines, 1):
            match = re.search(vlan_pattern, line, re.IGNORECASE)
            if match:
                vlan_id = int(match.group(1))
                min_vlan, max_vlan = self.business_rules["vlan_range"]
                if vlan_id < min_vlan or vlan_id > max_vlan:
                    result.issues.append(
                        ValidationIssue(
                            type=ValidationType.BUSINESS,
                            severity=Severity.MEDIUM,
                            message=f"VLAN {vlan_id} outside allowed range ({ }"
    min_vlan}-{max_vlan})",
                            line_number=line_num,
                        )
                    )

        # Check IP ranges
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        for line_num, line in enumerate(lines, 1):
            ips = re.findall(ip_pattern, line)
            for ip in ips:
                # Check if IP is in allowed ranges
                is_allowed = False
                for allowed_pattern in self.business_rules["ip_ranges"]:
                    if re.match(allowed_pattern, ip):
                        is_allowed = True
                        break

                if not is_allowed and not ip.startswith("255."):  # Skip masks
                    result.warnings.append(
                        ValidationIssue(
                            type=ValidationType.BUSINESS,
                            severity=Severity.LOW,
                            message=f"IP {ip} not in standard private ranges",
                            line_number=line_num,
                            recommendation="Use RFC1918 private IP ranges",
                        )
                    )

    def _detect_conflicts(
        self, config: str, vendor: str, result: ValidationResult
    ) -> None:
        """
        Detect configuration conflicts

        Args:
            config: Configuration content
            vendor: Device vendor
            result: ValidationResult to update"""
        lines = config.splitlines()

        # Check for duplicate IP addresses
        ip_addresses = {}
        ip_pattern = r"ip address\s+([\d\.]+)\s+([\d\.]+)"

        for line_num, line in enumerate(lines, 1):
            match = re.search(ip_pattern, line)
            if match:
                ip = match.group(1)
                if ip in ip_addresses:
                    result.issues.append(
                        ValidationIssue(
                            type=ValidationType.CONFLICT,
                            severity=Severity.CRITICAL,
                            message=f"Duplicate IP address: {ip}",
                            line_number=line_num,
                            config_section=f"Conflicts with line {ip_addresses[ip]}",
                                
                        )
                    )
                else:
                    ip_addresses[ip] = line_num

        # Check for overlapping ACLs
        acls = {}
        acl_pattern = r"access-list\s+(\S+)\s+"

        for line_num, line in enumerate(lines, 1):
            match = re.search(acl_pattern, line)
            if match:
                acl_name = match.group(1)
                if acl_name not in acls:
                    acls[acl_name] = []
                acls[acl_name].append(line_num)

        # Check for potential ACL conflicts
        for acl_name, line_nums in acls.items():
            if len(line_nums) > 10:  # Arbitrary threshold
                result.warnings.append(
                    ValidationIssue(
                        type=ValidationType.CONFLICT,
                        severity=Severity.LOW,
                                                message=f"ACL {acl_name} has many entries ("
                            {len(line_nums)}
                        )",
                        recommendation="Consider consolidating ACL rules",
                    )
                )

    def _is_valid_cisco_interface(self, interface: str) -> bool:
        """
        Check if Cisco interface name is valid

        Args:
            interface: Interface name

        Returns:
            Validation status"""
        valid_prefixes = [
            "GigabitEthernet",
            "TenGigabitEthernet",
            "FastEthernet",
            "Ethernet",
            "Vlan",
            "Loopback",
            "Tunnel",
            "Port-channel",
            "Serial",
        ]

        return any(interface.startswith(prefix) for prefix in valid_prefixes)

    def _is_valid_ip(self, ip: str) -> bool:
        """
        Check if IP address is valid

        Args:
            ip: IP address string

        Returns:
            Validation status"""
        # Remove CIDR notation if present
        if "/" in ip:
            ip, cidr = ip.split("/")
            try:
                cidr_int = int(cidr)
                if cidr_int < 0 or cidr_int > 32:
                    return False
            except ValueError:
                return False

        # Check IP octets
        octets = ip.split(".")
        if len(octets) != 4:
            return False

        for octet in octets:
            try:
                octet_int = int(octet)
                if octet_int < 0 or octet_int > 255:
                    return False
            except ValueError:
                return False

        return True
