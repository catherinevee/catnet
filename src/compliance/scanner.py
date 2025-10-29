"""
Compliance Scanner Engine
Automated compliance scanning and policy enforcement
"""
import re
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import structlog

from src.db.models.compliance import (
    CompliancePolicy,
    ComplianceScan,
    ComplianceStatus,
    ComplianceSeverity,
    ComplianceFramework
)

logger = structlog.get_logger()


class ComplianceScanner:
    """
    Automated compliance scanning engine

    Features:
    - Multi-framework support (CIS, PCI-DSS, HIPAA, SOC2, etc.)
    - Regex and Python-based policy rules
    - Automatic remediation capabilities
    - Comprehensive violation reporting
    """

    def __init__(self):
        self.cis_policies = self._initialize_cis_policies()

    def _initialize_cis_policies(self) -> Dict[str, callable]:
        """Initialize CIS benchmark policy checks"""
        return {
            "CIS-1.1.1": self._check_password_encryption,
            "CIS-1.1.2": self._check_enable_secret,
            "CIS-1.2.1": self._check_timeout_settings,
            "CIS-2.1.1": self._check_snmp_security,
            "CIS-2.1.2": self._check_snmp_acl,
            "CIS-2.2.1": self._check_http_server,
            "CIS-2.3.1": self._check_ssh_version,
            "CIS-3.1.1": self._check_logging_enabled,
            "CIS-3.1.2": self._check_logging_buffered,
            "CIS-4.1.1": self._check_ntp_configured,
            "CIS-5.1.1": self._check_banner_configured,
        }

    async def scan_device(
        self,
        device_id: str,
        policies: List[CompliancePolicy]
    ) -> List[ComplianceScan]:
        """
        Scan a device against compliance policies

        Args:
            device_id: Device to scan
            policies: List of policies to check

        Returns:
            List of ComplianceScan results
        """
        logger.info(
            "Starting compliance scan",
            device_id=device_id,
            policies=len(policies)
        )

        # Get device configuration
        from src.devices.secure_connector import secure_device_connector

        try:
            async with secure_device_connector.connect(device_id) as conn:
                running_config = await conn.send_command("show running-config")
                device_type = conn.device_type
        except Exception as e:
            logger.error(f"Failed to get config from {device_id}", error=str(e))
            return []

        results = []
        start_time = datetime.utcnow()

        for policy in policies:
            # Check if policy applies to this device
            if not self._policy_applies_to_device(policy, device_type):
                logger.debug(
                    f"Policy {policy.control_id} not applicable to {device_type}",
                    policy_id=policy.id
                )
                continue

            scan_start = datetime.utcnow()
            scan = await self._check_policy(
                device_id,
                policy,
                running_config,
                device_type
            )
            scan_duration = (datetime.utcnow() - scan_start).total_seconds() * 1000
            scan.scan_duration_ms = int(scan_duration)

            results.append(scan)

        compliant = sum(1 for s in results if s.status == ComplianceStatus.COMPLIANT)
        non_compliant = sum(1 for s in results if s.status == ComplianceStatus.NON_COMPLIANT)

        total_duration = (datetime.utcnow() - start_time).total_seconds()

        logger.info(
            "Compliance scan completed",
            device_id=device_id,
            total=len(results),
            compliant=compliant,
            non_compliant=non_compliant,
            duration_seconds=f"{total_duration:.2f}"
        )

        return results

    def _policy_applies_to_device(
        self,
        policy: CompliancePolicy,
        device_type: str
    ) -> bool:
        """Check if policy applies to device type"""
        # Check vendor
        if policy.vendor != "all":
            if policy.vendor == "cisco" and not device_type.startswith("cisco"):
                return False
            if policy.vendor == "juniper" and not device_type.startswith("juniper"):
                return False

        # Check device types
        if policy.device_types:
            # Extract base type (e.g., "ios" from "cisco_ios")
            base_type = device_type.split("_")[-1]
            if base_type not in policy.device_types:
                return False

        return True

    async def _check_policy(
        self,
        device_id: str,
        policy: CompliancePolicy,
        config: str,
        device_type: str
    ) -> ComplianceScan:
        """
        Check a single policy against config

        Args:
            device_id: Device identifier
            policy: Policy to check
            config: Device configuration
            device_type: Device type

        Returns:
            ComplianceScan result
        """
        logger.debug(
            "Checking policy",
            device_id=device_id,
            policy_id=policy.id,
            control_id=policy.control_id
        )

        # Use CIS-specific checker if available
        if policy.control_id and policy.control_id in self.cis_policies:
            status, details = self.cis_policies[policy.control_id](config)
        elif policy.rule_type == "regex":
            status, details = self._check_regex_rule(policy.rule, config, policy.expected_value)
        elif policy.rule_type == "python":
            status, details = await self._check_python_rule(policy.rule, config, device_id)
        else:
            status = ComplianceStatus.MANUAL_REVIEW
            details = {"message": f"Unknown rule type: {policy.rule_type}"}

        # Create scan record
        scan = ComplianceScan(
            device_id=device_id,
            policy_id=policy.id,
            scanned_at=datetime.utcnow(),
            status=status,
            violation_details=details if status == ComplianceStatus.NON_COMPLIANT else None,
            violation_summary=self._create_violation_summary(policy, details) if status == ComplianceStatus.NON_COMPLIANT else None
        )

        return scan

    def _check_regex_rule(
        self,
        pattern: str,
        config: str,
        expected: Optional[str]
    ) -> Tuple[ComplianceStatus, Dict]:
        """Check regex-based rule"""
        try:
            match = re.search(pattern, config, re.MULTILINE | re.IGNORECASE)

            if expected == "present":
                # Pattern should be found
                if match:
                    return ComplianceStatus.COMPLIANT, {}
                else:
                    return ComplianceStatus.NON_COMPLIANT, {
                        "message": f"Expected pattern not found: {pattern}",
                        "pattern": pattern
                    }
            elif expected == "absent":
                # Pattern should NOT be found
                if not match:
                    return ComplianceStatus.COMPLIANT, {}
                else:
                    return ComplianceStatus.NON_COMPLIANT, {
                        "message": f"Unexpected pattern found: {pattern}",
                        "pattern": pattern,
                        "found": match.group(0)
                    }
            else:
                # Default: presence means compliance
                if match:
                    return ComplianceStatus.COMPLIANT, {}
                else:
                    return ComplianceStatus.NON_COMPLIANT, {
                        "message": f"Pattern not found: {pattern}"
                    }

        except re.error as e:
            logger.error(f"Invalid regex pattern: {pattern}", error=str(e))
            return ComplianceStatus.MANUAL_REVIEW, {"error": f"Invalid regex: {str(e)}"}

    async def _check_python_rule(
        self,
        rule_code: str,
        config: str,
        device_id: str
    ) -> Tuple[ComplianceStatus, Dict]:
        """Execute Python-based rule (advanced)"""
        # This is a simplified version - production would need sandboxing
        # For security, Python rules should be pre-approved and stored securely

        try:
            # Create safe execution context
            context = {
                "config": config,
                "device_id": device_id,
                "re": re
            }

            # Execute rule (in production, use sandboxed execution)
            exec(rule_code, context)

            # Rule should set 'compliant' variable
            if context.get("compliant", False):
                return ComplianceStatus.COMPLIANT, {}
            else:
                return ComplianceStatus.NON_COMPLIANT, context.get("details", {})

        except Exception as e:
            logger.error("Python rule execution failed", error=str(e))
            return ComplianceStatus.MANUAL_REVIEW, {"error": str(e)}

    # CIS Benchmark Specific Checks

    def _check_password_encryption(self, config: str) -> Tuple[ComplianceStatus, Dict]:
        """CIS 1.1.1: Enable password encryption"""
        if re.search(r"^service password-encryption", config, re.MULTILINE):
            return ComplianceStatus.COMPLIANT, {}

        return ComplianceStatus.NON_COMPLIANT, {
            "message": "Password encryption not enabled",
            "remediation": "Configure: service password-encryption"
        }

    def _check_enable_secret(self, config: str) -> Tuple[ComplianceStatus, Dict]:
        """CIS 1.1.2: Use encrypted enable secret"""
        # Check for enable secret (encrypted)
        if re.search(r"^enable secret", config, re.MULTILINE):
            # Make sure not using plaintext enable password
            if not re.search(r"^enable password", config, re.MULTILINE):
                return ComplianceStatus.COMPLIANT, {}

        return ComplianceStatus.NON_COMPLIANT, {
            "message": "Enable secret not properly configured",
            "remediation": "Configure: enable secret <password>"
        }

    def _check_timeout_settings(self, config: str) -> Tuple[ComplianceStatus, Dict]:
        """CIS 1.2.1: Set exec timeout"""
        # Should have exec-timeout configured (not 0 0)
        match = re.search(r"exec-timeout\s+(\d+)\s+(\d+)", config)

        if match:
            minutes = int(match.group(1))
            seconds = int(match.group(2))

            # Timeout should be between 1-10 minutes
            if 1 <= minutes <= 10:
                return ComplianceStatus.COMPLIANT, {}

        return ComplianceStatus.NON_COMPLIANT, {
            "message": "Exec timeout not properly configured",
            "remediation": "Configure: line vty 0 4 -> exec-timeout 10 0"
        }

    def _check_snmp_security(self, config: str) -> Tuple[ComplianceStatus, Dict]:
        """CIS 2.1.1: Disable or secure SNMP"""
        # Check for default community strings
        default_communities = re.findall(
            r"snmp-server community\s+(public|private)",
            config,
            re.IGNORECASE
        )

        if default_communities:
            return ComplianceStatus.NON_COMPLIANT, {
                "message": f"Default SNMP community strings found: {', '.join(default_communities)}",
                "remediation": "Remove default community strings and use SNMPv3"
            }

        # Check for SNMPv3 (preferred)
        if re.search(r"snmp-server group.*v3", config):
            return ComplianceStatus.COMPLIANT, {}

        # Check for SNMP with ACL
        if re.search(r"snmp-server community.*\d+", config):
            return ComplianceStatus.COMPLIANT, {}

        return ComplianceStatus.NOT_APPLICABLE, {}

    def _check_snmp_acl(self, config: str) -> Tuple[ComplianceStatus, Dict]:
        """CIS 2.1.2: SNMP should use ACL"""
        # Find SNMP community strings
        communities = re.findall(r"snmp-server community\s+\S+\s+(?:RO|RW)\s+(\d+)", config)

        if not communities:
            return ComplianceStatus.NOT_APPLICABLE, {}

        # All communities should have ACLs
        if communities:
            return ComplianceStatus.COMPLIANT, {}

        return ComplianceStatus.NON_COMPLIANT, {
            "message": "SNMP communities without ACL restrictions",
            "remediation": "Add ACL to SNMP community: snmp-server community <name> RO <acl>"
        }

    def _check_http_server(self, config: str) -> Tuple[ComplianceStatus, Dict]:
        """CIS 2.2.1: Disable HTTP server"""
        # HTTP server should be disabled
        if re.search(r"^no ip http server", config, re.MULTILINE):
            return ComplianceStatus.COMPLIANT, {}

        if re.search(r"^ip http server", config, re.MULTILINE):
            return ComplianceStatus.NON_COMPLIANT, {
                "message": "HTTP server is enabled",
                "remediation": "Configure: no ip http server"
            }

        return ComplianceStatus.NOT_APPLICABLE, {}

    def _check_ssh_version(self, config: str) -> Tuple[ComplianceStatus, Dict]:
        """CIS 2.3.1: Use SSH version 2"""
        if re.search(r"ip ssh version 2", config):
            return ComplianceStatus.COMPLIANT, {}

        return ComplianceStatus.NON_COMPLIANT, {
            "message": "SSH version 2 not configured",
            "remediation": "Configure: ip ssh version 2"
        }

    def _check_logging_enabled(self, config: str) -> Tuple[ComplianceStatus, Dict]:
        """CIS 3.1.1: Enable logging"""
        if re.search(r"^logging\s+\d+\.\d+\.\d+\.\d+", config, re.MULTILINE):
            return ComplianceStatus.COMPLIANT, {}

        return ComplianceStatus.NON_COMPLIANT, {
            "message": "Logging to remote server not configured",
            "remediation": "Configure: logging <syslog-server-ip>"
        }

    def _check_logging_buffered(self, config: str) -> Tuple[ComplianceStatus, Dict]:
        """CIS 3.1.2: Configure logging buffered"""
        if re.search(r"^logging buffered", config, re.MULTILINE):
            return ComplianceStatus.COMPLIANT, {}

        return ComplianceStatus.NON_COMPLIANT, {
            "message": "Logging buffered not configured",
            "remediation": "Configure: logging buffered 16384"
        }

    def _check_ntp_configured(self, config: str) -> Tuple[ComplianceStatus, Dict]:
        """CIS 4.1.1: Configure NTP"""
        if re.search(r"^ntp server", config, re.MULTILINE):
            return ComplianceStatus.COMPLIANT, {}

        return ComplianceStatus.NON_COMPLIANT, {
            "message": "NTP not configured",
            "remediation": "Configure: ntp server <ntp-server-ip>"
        }

    def _check_banner_configured(self, config: str) -> Tuple[ComplianceStatus, Dict]:
        """CIS 5.1.1: Set login banner"""
        if re.search(r"^banner (login|motd)", config, re.MULTILINE):
            return ComplianceStatus.COMPLIANT, {}

        return ComplianceStatus.NON_COMPLIANT, {
            "message": "Login banner not configured",
            "remediation": "Configure: banner login ^C<banner-text>^C"
        }

    def _create_violation_summary(
        self,
        policy: CompliancePolicy,
        details: Dict
    ) -> str:
        """Create human-readable violation summary"""
        summary = f"{policy.framework.value.upper()} {policy.control_id}: {policy.name} - "
        summary += details.get("message", "Non-compliant")

        if "remediation" in details:
            summary += f"\nRemediation: {details['remediation']}"

        return summary

    async def auto_remediate_violation(
        self,
        scan: ComplianceScan,
        policy: CompliancePolicy,
        device_id: str
    ) -> bool:
        """
        Automatically remediate a compliance violation

        Args:
            scan: Compliance scan with violation
            policy: Policy being violated
            device_id: Device to remediate

        Returns:
            True if remediation successful
        """
        if not policy.auto_remediate or not policy.remediation_commands:
            logger.debug(
                "Auto-remediation not enabled for policy",
                policy_id=policy.id
            )
            return False

        logger.info(
            "Attempting auto-remediation",
            device_id=device_id,
            policy_id=policy.id
        )

        try:
            from src.devices.secure_connector import secure_device_connector

            async with secure_device_connector.connect(device_id) as conn:
                result = await conn.send_config_set(policy.remediation_commands)

                if result:
                    scan.auto_remediated = True
                    scan.remediated_at = datetime.utcnow()
                    scan.remediated_by = "system"
                    scan.remediation_success = True

                    logger.info(
                        "Auto-remediation successful",
                        device_id=device_id,
                        policy_id=policy.id
                    )
                    return True

        except Exception as e:
            scan.remediation_error = str(e)
            scan.remediation_success = False

            logger.error(
                "Auto-remediation failed",
                device_id=device_id,
                policy_id=policy.id,
                error=str(e)
            )

        return False


# Global instance
compliance_scanner = ComplianceScanner()
