"""
Configuration scanner for GitOps integration.
Scans configurations for compliance, secrets, and policy violations.
"""

import re
import json
import yaml
import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple
from pathlib import Path
from datetime import datetime
from enum import Enum

from src.core.exceptions import SecurityError, ValidationError
from src.security.audit import AuditLogger
from src.core.config import get_settings


class ScanLevel(Enum):
    """Scanning level enumeration."""
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    FORENSIC = "forensic"


class ViolationType(Enum):
    """Security violation types."""
    SECRET_EXPOSED = "secret_exposed"
    WEAK_ENCRYPTION = "weak_encryption"
    INSECURE_PROTOCOL = "insecure_protocol"
    DEFAULT_CREDENTIAL = "default_credential"
    COMPLIANCE_VIOLATION = "compliance_violation"
    MISCONFIGURATION = "misconfiguration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    NETWORK_EXPOSURE = "network_exposure"


class ConfigurationScanner:
    """
    Comprehensive configuration scanner for security and compliance.
    Performs multi-level scanning including secrets detection, compliance checks,
    and vulnerability assessment.
    """

    def __init__(self, scan_level: ScanLevel = ScanLevel.STANDARD):
        """
        Initialize configuration scanner.

        Args:
            scan_level: Level of scanning depth
        """
        self.scan_level = scan_level
        self.audit = AuditLogger()
        self.settings = get_settings()

        # Initialize pattern sets
        self._init_secret_patterns()
        self._init_compliance_rules()
        self._init_vulnerability_patterns()

    def _init_secret_patterns(self):
        """Initialize secret detection patterns."""
        self.secret_patterns = {
            # API Keys and Tokens
            'generic_api_key': re.compile(
                r'(?i)(api[_\-\s]*key|apikey|api_key_id|api_secret)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{32,})["\']?'
            ),
            'aws_access_key': re.compile(r'AKIA[0-9A-Z]{16}'),
            'aws_secret_key': re.compile(
                r'(?i)aws[_\-\s]*(secret[_\-\s]*access[_\-\s]*key|secret[_\-\s]*key|secret)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?'
            ),
            'github_token': re.compile(r'(ghp|gho|ghs|ghr)_[a-zA-Z0-9]{36,}'),
            'slack_token': re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'),
            'google_api': re.compile(r'AIza[0-9A-Za-z\-_]{35}'),

            # Passwords
            'password': re.compile(
                r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\']{6,})["\']'
            ),
            'enable_password': re.compile(
                r'(?i)enable\s+(password|secret)\s+\d+\s+(\S+)'
            ),

            # Private Keys
            'private_key': re.compile(
                r'-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE KEY-----'
            ),
            'ssh_private': re.compile(r'ssh-rsa\s+[A-Za-z0-9+/]+={0,2}'),

            # Database Credentials
            'db_connection': re.compile(
                r'(mongodb|mysql|postgres|redis|cassandra)://[^@]+:[^@]+@[^\s]+'
            ),
            'sql_password': re.compile(
                r'(?i)(sa_password|db_password|database_password)["\']?\s*[:=]\s*["\']([^"\']+)["\']'
            ),

            # Network Device Specific
            'snmp_community': re.compile(
                r'(?i)snmp[_\-\s]*(community|string)["\']?\s*[:=]\s*["\']([^"\']+)["\']'
            ),
            'tacacs_key': re.compile(
                r'(?i)tacacs[_\-\s]*key["\']?\s*[:=]\s*["\']([^"\']+)["\']'
            ),
            'radius_secret': re.compile(
                r'(?i)radius[_\-\s]*(secret|key)["\']?\s*[:=]\s*["\']([^"\']+)["\']'
            ),

            # Certificates
            'certificate': re.compile(r'-----BEGIN CERTIFICATE-----'),
            'jwt_token': re.compile(r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'),
        }

    def _init_compliance_rules(self):
        """Initialize compliance checking rules."""
        self.compliance_rules = {
            'pci_dss': {
                'no_telnet': re.compile(r'(?i)telnet\s+enable'),
                'encrypted_passwords': re.compile(r'(?i)password\s+0\s+'),
                'strong_encryption': re.compile(r'(?i)(des|3des|rc4)'),
                'secure_protocols': re.compile(r'(?i)(sslv2|sslv3|tlsv1\.0)'),
            },
            'hipaa': {
                'encryption_required': re.compile(r'(?i)encryption\s+disable'),
                'audit_logging': re.compile(r'(?i)no\s+logging'),
                'access_control': re.compile(r'(?i)permit\s+any\s+any'),
            },
            'sox': {
                'change_control': re.compile(r'(?i)no\s+archive'),
                'audit_trail': re.compile(r'(?i)no\s+(logging|syslog)'),
                'segregation': re.compile(r'(?i)privilege\s+15'),
            },
            'gdpr': {
                'data_protection': re.compile(r'(?i)no\s+encryption'),
                'privacy_settings': re.compile(r'(?i)snmp.*public'),
            },
            'nist': {
                'strong_crypto': re.compile(r'(?i)(md5|sha1)\s+'),
                'secure_channels': re.compile(r'(?i)http\s+server\s+enable'),
                'access_restrictions': re.compile(r'(?i)no\s+access-list'),
            }
        }

    def _init_vulnerability_patterns(self):
        """Initialize vulnerability detection patterns."""
        self.vulnerability_patterns = {
            'weak_protocols': {
                'telnet': re.compile(r'(?i)line\s+vty.*\n.*transport\s+input\s+telnet'),
                'http': re.compile(r'(?i)ip\s+http\s+server'),
                'snmpv1': re.compile(r'(?i)snmp-server\s+community.*\s+ro'),
                'snmpv2': re.compile(r'(?i)snmp-server\s+community.*\s+rw'),
            },
            'default_credentials': {
                'cisco_default': re.compile(r'(?i)username\s+(cisco|admin)\s+password'),
                'juniper_default': re.compile(r'(?i)user\s+(root|admin)\s+.*\s+password'),
                'snmp_public': re.compile(r'(?i)snmp.*\s+(public|private)\s'),
            },
            'misconfigurations': {
                'any_any_rule': re.compile(r'(?i)permit\s+ip\s+any\s+any'),
                'no_timeout': re.compile(r'(?i)exec-timeout\s+0\s+0'),
                'debug_enabled': re.compile(r'(?i)debug\s+all'),
                'no_encryption': re.compile(r'(?i)service\s+password-encryption\s+disable'),
            },
            'network_exposure': {
                'public_ip': re.compile(
                    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
                ),
                'management_exposure': re.compile(r'(?i)interface\s+.*management.*\n.*ip\s+address'),
                'any_source': re.compile(r'(?i)source\s+0\.0\.0\.0\s+0\.0\.0\.0'),
            }
        }

    async def scan_configuration(
        self,
        content: str,
        filename: str = "unknown",
        vendor: str = "generic"
    ) -> Dict[str, Any]:
        """
        Perform comprehensive configuration scan.

        Args:
            content: Configuration content to scan
            filename: Name of configuration file
            vendor: Vendor type (cisco, juniper, etc.)

        Returns:
            Scan results with violations and recommendations
        """
        scan_id = datetime.utcnow().isoformat()

        results = {
            'scan_id': scan_id,
            'filename': filename,
            'vendor': vendor,
            'scan_level': self.scan_level.value,
            'timestamp': datetime.utcnow().isoformat(),
            'violations': [],
            'warnings': [],
            'recommendations': [],
            'statistics': {}
        }

        # Run all scanning modules
        tasks = [
            self._scan_for_secrets(content, filename),
            self._scan_compliance(content, vendor),
            self._scan_vulnerabilities(content, vendor),
            self._scan_best_practices(content, vendor)
        ]

        if self.scan_level in [ScanLevel.DEEP, ScanLevel.FORENSIC]:
            tasks.append(self._scan_entropy(content))
            tasks.append(self._scan_patterns(content, vendor))

        scan_results = await asyncio.gather(*tasks)

        # Aggregate results
        for scan_result in scan_results:
            results['violations'].extend(scan_result.get('violations', []))
            results['warnings'].extend(scan_result.get('warnings', []))
            results['recommendations'].extend(scan_result.get('recommendations', []))

        # Calculate statistics
        results['statistics'] = {
            'total_violations': len(results['violations']),
            'critical': len([v for v in results['violations'] if v.get('severity') == 'critical']),
            'high': len([v for v in results['violations'] if v.get('severity') == 'high']),
            'medium': len([v for v in results['violations'] if v.get('severity') == 'medium']),
            'low': len([v for v in results['violations'] if v.get('severity') == 'low']),
            'total_warnings': len(results['warnings'])
        }

        # Log scan completion
        await self.audit.log_event(
            event_type="CONFIGURATION_SCAN_COMPLETED",
            details={
                'scan_id': scan_id,
                'filename': filename,
                'statistics': results['statistics']
            }
        )

        return results

    async def _scan_for_secrets(self, content: str, filename: str) -> Dict[str, List]:
        """Scan for exposed secrets and credentials."""
        violations = []
        warnings = []

        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern in self.secret_patterns.items():
                matches = pattern.finditer(line)
                for match in matches:
                    violation = {
                        'type': ViolationType.SECRET_EXPOSED.value,
                        'severity': self._get_secret_severity(pattern_name),
                        'pattern': pattern_name,
                        'line': line_num,
                        'column': match.start(),
                        'matched_text': self._sanitize_secret(match.group(0)),
                        'description': f"Potential {pattern_name.replace('_', ' ')} detected",
                        'remediation': self._get_secret_remediation(pattern_name)
                    }
                    violations.append(violation)

        return {'violations': violations, 'warnings': warnings}

    async def _scan_compliance(self, content: str, vendor: str) -> Dict[str, List]:
        """Scan for compliance violations."""
        violations = []
        warnings = []

        for framework, rules in self.compliance_rules.items():
            for rule_name, pattern in rules.items():
                if pattern.search(content):
                    violation = {
                        'type': ViolationType.COMPLIANCE_VIOLATION.value,
                        'severity': 'high',
                        'framework': framework.upper(),
                        'rule': rule_name,
                        'description': f"{framework.upper()} compliance violation: {rule_name.replace('_', ' ')}",
                        'remediation': self._get_compliance_remediation(framework, rule_name)
                    }
                    violations.append(violation)

        return {'violations': violations, 'warnings': warnings}

    async def _scan_vulnerabilities(self, content: str, vendor: str) -> Dict[str, List]:
        """Scan for security vulnerabilities."""
        violations = []
        warnings = []

        for vuln_category, patterns in self.vulnerability_patterns.items():
            for vuln_name, pattern in patterns.items():
                if pattern.search(content):
                    severity = self._get_vulnerability_severity(vuln_category, vuln_name)

                    item = {
                        'type': ViolationType.MISCONFIGURATION.value,
                        'category': vuln_category,
                        'vulnerability': vuln_name,
                        'severity': severity,
                        'description': f"Security vulnerability: {vuln_name.replace('_', ' ')}",
                        'remediation': self._get_vulnerability_remediation(vuln_category, vuln_name),
                        'cve_references': self._get_cve_references(vuln_name)
                    }

                    if severity in ['critical', 'high']:
                        violations.append(item)
                    else:
                        warnings.append(item)

        return {'violations': violations, 'warnings': warnings}

    async def _scan_best_practices(self, content: str, vendor: str) -> Dict[str, List]:
        """Scan for best practice violations."""
        recommendations = []

        # Vendor-specific best practices
        if vendor == 'cisco':
            recommendations.extend(await self._cisco_best_practices(content))
        elif vendor == 'juniper':
            recommendations.extend(await self._juniper_best_practices(content))

        # General network security best practices
        general_checks = [
            ('service timestamps', 'Enable service timestamps for accurate logging'),
            ('ntp server', 'Configure NTP for time synchronization'),
            ('banner', 'Configure login banner for legal warning'),
            ('logging buffer', 'Configure logging buffer for audit trails'),
            ('aaa new-model', 'Enable AAA for centralized authentication'),
        ]

        for check, recommendation in general_checks:
            if check not in content.lower():
                recommendations.append({
                    'type': 'best_practice',
                    'recommendation': recommendation,
                    'priority': 'medium'
                })

        return {'recommendations': recommendations}

    async def _scan_entropy(self, content: str) -> Dict[str, List]:
        """Scan for high-entropy strings that might be secrets."""
        import math

        violations = []
        MIN_ENTROPY = 4.5  # Threshold for suspicious entropy
        MIN_LENGTH = 16    # Minimum string length to check

        # Extract potential secret strings
        words = re.findall(r'[a-zA-Z0-9+/=]{' + str(MIN_LENGTH) + r',}', content)

        for word in words:
            entropy = self._calculate_entropy(word)
            if entropy > MIN_ENTROPY:
                violations.append({
                    'type': ViolationType.SECRET_EXPOSED.value,
                    'severity': 'medium',
                    'pattern': 'high_entropy_string',
                    'entropy': round(entropy, 2),
                    'description': f"High entropy string detected (entropy: {entropy:.2f})",
                    'matched_text': word[:20] + '...' if len(word) > 20 else word
                })

        return {'violations': violations}

    async def _scan_patterns(self, content: str, vendor: str) -> Dict[str, List]:
        """Advanced pattern matching for deep scanning."""
        violations = []

        # Check for suspicious command patterns
        suspicious_patterns = [
            (r'(?i)delete\s+flash:', 'Destructive command detected'),
            (r'(?i)format\s+flash:', 'Destructive command detected'),
            (r'(?i)erase\s+startup', 'Configuration erase command detected'),
            (r'(?i)reload\s+in', 'Scheduled reload detected'),
        ]

        for pattern, description in suspicious_patterns:
            if re.search(pattern, content):
                violations.append({
                    'type': ViolationType.MISCONFIGURATION.value,
                    'severity': 'high',
                    'description': description,
                    'pattern': pattern
                })

        return {'violations': violations}

    async def _cisco_best_practices(self, content: str) -> List[Dict]:
        """Cisco-specific best practices."""
        recommendations = []

        checks = [
            ('service password-encryption', 'Enable password encryption'),
            ('no ip http server', 'Disable HTTP server'),
            ('no ip http secure-server', 'Disable HTTPS server if not needed'),
            ('ip ssh version 2', 'Use SSH version 2 only'),
            ('transport input ssh', 'Restrict VTY lines to SSH only'),
            ('exec-timeout', 'Configure exec timeout for sessions'),
            ('logging trap', 'Configure syslog level'),
            ('spanning-tree guard', 'Configure spanning-tree security features'),
        ]

        for check, recommendation in checks:
            if check not in content.lower():
                recommendations.append({
                    'vendor': 'cisco',
                    'recommendation': recommendation,
                    'command': check
                })

        return recommendations

    async def _juniper_best_practices(self, content: str) -> List[Dict]:
        """Juniper-specific best practices."""
        recommendations = []

        checks = [
            ('services ssh protocol-version v2', 'Use SSH version 2 only'),
            ('system login retry-options', 'Configure login retry options'),
            ('system services ssh root-login deny', 'Disable root SSH login'),
            ('system syslog', 'Configure syslog server'),
            ('system ntp', 'Configure NTP server'),
            ('interfaces lo0 unit 0 family inet filter', 'Configure loopback filter'),
        ]

        for check, recommendation in checks:
            if check not in content.lower():
                recommendations.append({
                    'vendor': 'juniper',
                    'recommendation': recommendation,
                    'command': check
                })

        return recommendations

    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string."""
        import math

        if not string:
            return 0.0

        prob = [float(string.count(c)) / len(string) for c in set(string)]
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])

        return entropy

    def _get_secret_severity(self, pattern_name: str) -> str:
        """Determine severity based on secret type."""
        critical = ['private_key', 'aws_secret_key', 'db_connection']
        high = ['password', 'api_key', 'snmp_community', 'tacacs_key']
        medium = ['jwt_token', 'certificate']

        if pattern_name in critical:
            return 'critical'
        elif pattern_name in high:
            return 'high'
        elif pattern_name in medium:
            return 'medium'
        else:
            return 'low'

    def _get_vulnerability_severity(self, category: str, vuln_name: str) -> str:
        """Determine vulnerability severity."""
        critical = ['telnet', 'snmp_public', 'any_any_rule', 'debug_enabled']
        high = ['http', 'snmpv2', 'no_timeout', 'no_encryption']

        if vuln_name in critical:
            return 'critical'
        elif vuln_name in high:
            return 'high'
        else:
            return 'medium'

    def _sanitize_secret(self, text: str) -> str:
        """Sanitize secret for safe logging."""
        if len(text) <= 8:
            return '*' * len(text)
        return text[:3] + '*' * (len(text) - 6) + text[-3:]

    def _get_secret_remediation(self, pattern_name: str) -> str:
        """Get remediation advice for exposed secret."""
        remediations = {
            'password': 'Remove hardcoded password and use secure credential management',
            'api_key': 'Store API keys in secure vault, not in configuration',
            'private_key': 'Remove private key immediately and rotate credentials',
            'snmp_community': 'Use SNMPv3 with encryption instead of community strings',
            'db_connection': 'Use environment variables or secure vault for database credentials'
        }
        return remediations.get(pattern_name, 'Remove sensitive information from configuration')

    def _get_compliance_remediation(self, framework: str, rule: str) -> str:
        """Get compliance remediation advice."""
        return f"Review {framework.upper()} requirements for {rule.replace('_', ' ')} and update configuration"

    def _get_vulnerability_remediation(self, category: str, vuln: str) -> str:
        """Get vulnerability remediation advice."""
        remediations = {
            'telnet': 'Disable Telnet and use SSH for remote access',
            'http': 'Disable HTTP server or use HTTPS with proper certificates',
            'snmp_public': 'Change SNMP community string from default and use SNMPv3',
            'any_any_rule': 'Implement specific access control rules instead of permit any',
            'no_timeout': 'Configure appropriate session timeout values',
            'debug_enabled': 'Disable debug mode in production environments'
        }
        return remediations.get(vuln, f"Review and remediate {vuln.replace('_', ' ')}")

    def _get_cve_references(self, vuln_name: str) -> List[str]:
        """Get relevant CVE references for vulnerability."""
        # In production, would query CVE database
        cve_map = {
            'telnet': ['CVE-2001-0554', 'CVE-2011-4862'],
            'snmp_public': ['CVE-2002-0012', 'CVE-2002-0013'],
            'http': ['CVE-2018-0171', 'CVE-2018-0172']
        }
        return cve_map.get(vuln_name, [])


# Export main components
__all__ = [
    'ConfigurationScanner',
    'ScanLevel',
    'ViolationType'
]