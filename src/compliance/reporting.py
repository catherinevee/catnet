"""
Compliance Reporting for CatNet

Handles:
- Compliance assessment
- Regulatory reporting
- Security audits
- Configuration compliance
- Report generation
"""

from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
import csv
import html
from collections import defaultdict
import hashlib


class ComplianceFramework(Enum):
    """Supported compliance frameworks"""

    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    ISO_27001 = "iso_27001"
    NIST = "nist"
    CIS = "cis"
    GDPR = "gdpr"
    CUSTOM = "custom"


class ComplianceStatus(Enum):
    """Compliance check status"""

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"
    NOT_CHECKED = "not_checked"


class ControlCategory(Enum):
    """Control categories"""

    ACCESS_CONTROL = "access_control"
    NETWORK_SECURITY = "network_security"
    DATA_PROTECTION = "data_protection"
    CONFIGURATION_MANAGEMENT = "configuration_management"
    INCIDENT_RESPONSE = "incident_response"
    AUDIT_LOGGING = "audit_logging"
    PHYSICAL_SECURITY = "physical_security"
    RISK_ASSESSMENT = "risk_assessment"


@dataclass
class ComplianceControl:
    """Compliance control definition"""

    id: str
    name: str
    description: str
    category: ControlCategory
    framework: ComplianceFramework
    requirements: List[str]
    validation_script: Optional[str] = None
    remediation_steps: List[str] = field(default_factory=list)
    severity: str = "medium"  # low, medium, high, critical
    automated: bool = False


@dataclass
class ComplianceCheck:
    """Compliance check result"""

    control_id: str
    device_id: str
    status: ComplianceStatus
    checked_at: datetime
    details: Dict[str, Any] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)
    violations: List[str] = field(default_factory=list)
    remediation_applied: bool = False


@dataclass
class ComplianceReport:
    """Compliance report"""

    id: str
    framework: ComplianceFramework
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    overall_status: ComplianceStatus
    compliance_score: float  # 0-100
    total_controls: int
    compliant_controls: int
    non_compliant_controls: int
    checks: List[ComplianceCheck]
    summary: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)


class ComplianceManager:
    """
    Manages compliance checking and reporting
    """

    def __init__(
        self,
        device_service=None,
        config_service=None,
        audit_service=None
    ):
        """
        Initialize compliance manager

        Args:
            device_service: Device management service
            config_service: Configuration service
            audit_service: Audit logging service
        """
        self.device_service = device_service
        self.config_service = config_service
        self.audit_service = audit_service

        # Control definitions
        self.controls: Dict[str, ComplianceControl] = {}
        self.framework_controls: Dict[ComplianceFramework, List[str]] = defaultdict(list)

        # Check results
        self.check_results: Dict[str, ComplianceCheck] = {}
        self.report_history: List[ComplianceReport] = []

        # Policies
        self.policies: Dict[str, Dict[str, Any]] = {}

        # Initialize controls
        self._initialize_controls()

    def _initialize_controls(self):
        """Initialize compliance controls"""
        # PCI DSS Controls
        self.add_control(
            ComplianceControl(
                id="PCI_1.1",
                name="Firewall Configuration Standards",
                description="Establish firewall and router configuration standards",
                category=ControlCategory.NETWORK_SECURITY,
                framework=ComplianceFramework.PCI_DSS,
                requirements=[
                    "Firewall rules documented",
                    "Inbound traffic restricted",
                    "Outbound traffic controlled"
                ],
                severity="high",
                automated=True
            )
        )

        self.add_control(
            ComplianceControl(
                id="PCI_2.1",
                name="Default Passwords Changed",
                description="Change vendor-supplied defaults for passwords",
                category=ControlCategory.ACCESS_CONTROL,
                framework=ComplianceFramework.PCI_DSS,
                requirements=[
                    "No default passwords",
                    "Strong password policy",
                    "Password rotation enabled"
                ],
                severity="critical",
                automated=True
            )
        )

        # CIS Controls
        self.add_control(
            ComplianceControl(
                id="CIS_1.1",
                name="Asset Inventory",
                description="Maintain inventory of authorized devices",
                category=ControlCategory.CONFIGURATION_MANAGEMENT,
                framework=ComplianceFramework.CIS,
                requirements=[
                    "Complete device inventory",
                    "Regular inventory updates",
                    "Unauthorized device detection"
                ],
                severity="medium",
                automated=True
            )
        )

        self.add_control(
            ComplianceControl(
                id="CIS_4.1",
                name="Administrative Privileges",
                description="Controlled use of administrative privileges",
                category=ControlCategory.ACCESS_CONTROL,
                framework=ComplianceFramework.CIS,
                requirements=[
                    "Limited admin accounts",
                    "Privilege escalation logging",
                    "Regular privilege audits"
                ],
                severity="high",
                automated=True
            )
        )

        # NIST Controls
        self.add_control(
            ComplianceControl(
                id="NIST_AC-2",
                name="Account Management",
                description="Manage information system accounts",
                category=ControlCategory.ACCESS_CONTROL,
                framework=ComplianceFramework.NIST,
                requirements=[
                    "Account creation process",
                    "Account review process",
                    "Account termination process"
                ],
                severity="high",
                automated=True
            )
        )

        self.add_control(
            ComplianceControl(
                id="NIST_AU-2",
                name="Audit Events",
                description="Determine audit events to be logged",
                category=ControlCategory.AUDIT_LOGGING,
                framework=ComplianceFramework.NIST,
                requirements=[
                    "Authentication events logged",
                    "Authorization events logged",
                    "System events logged"
                ],
                severity="medium",
                automated=True
            )
        )

    def add_control(self, control: ComplianceControl):
        """
        Add a compliance control

        Args:
            control: Control definition
        """
        self.controls[control.id] = control
        self.framework_controls[control.framework].append(control.id)

    async def check_compliance(
        self,
        framework: ComplianceFramework,
        device_ids: Optional[List[str]] = None
    ) -> List[ComplianceCheck]:
        """
        Check compliance for specified framework

        Args:
            framework: Compliance framework
            device_ids: Devices to check (all if None)

        Returns:
            List of compliance check results
        """
        # Get applicable controls
        control_ids = self.framework_controls.get(framework, [])

        if not device_ids and self.device_service:
            # Get all devices
            device_ids = await self.device_service.get_all_device_ids()

        results = []

        for device_id in device_ids:
            for control_id in control_ids:
                control = self.controls[control_id]
                check = await self._check_control(control, device_id)
                results.append(check)

                # Store result
                key = f"{device_id}:{control_id}"
                self.check_results[key] = check

        return results

    async def _check_control(
        self,
        control: ComplianceControl,
        device_id: str
    ) -> ComplianceCheck:
        """
        Check a specific control for a device

        Args:
            control: Control to check
            device_id: Device ID

        Returns:
            Check result
        """
        check = ComplianceCheck(
            control_id=control.id,
            device_id=device_id,
            status=ComplianceStatus.NOT_CHECKED,
            checked_at=datetime.utcnow()
        )

        try:
            # Run validation based on control category
            if control.category == ControlCategory.ACCESS_CONTROL:
                check = await self._check_access_control(control, device_id, check)
            elif control.category == ControlCategory.NETWORK_SECURITY:
                check = await self._check_network_security(control, device_id, check)
            elif control.category == ControlCategory.AUDIT_LOGGING:
                check = await self._check_audit_logging(control, device_id, check)
            elif control.category == ControlCategory.CONFIGURATION_MANAGEMENT:
                check = await self._check_configuration(control, device_id, check)
            else:
                # Run custom validation script if provided
                if control.validation_script:
                    check = await self._run_validation_script(control, device_id, check)

        except Exception as e:
            check.status = ComplianceStatus.NOT_CHECKED
            check.details['error'] = str(e)

        return check

    async def _check_access_control(
        self,
        control: ComplianceControl,
        device_id: str,
        check: ComplianceCheck
    ) -> ComplianceCheck:
        """Check access control compliance"""
        violations = []
        evidence = []

        # Check for default passwords
        if "default passwords" in control.name.lower():
            config = await self._get_device_config(device_id)
            if config:
                # Check for common default passwords
                default_patterns = [
                    "password cisco",
                    "password admin",
                    "password 123",
                    "username admin password admin"
                ]

                for pattern in default_patterns:
                    if pattern in config.lower():
                        violations.append(f"Default password pattern found: {pattern}")

                evidence.append(f"Configuration checked for default passwords")

        # Check for admin privileges
        if "administrative" in control.name.lower():
            # Check admin account count
            admin_count = await self._count_admin_accounts(device_id)
            if admin_count > 5:  # Threshold
                violations.append(f"Excessive admin accounts: {admin_count}")
            evidence.append(f"Admin account count: {admin_count}")

        # Determine status
        if violations:
            check.status = ComplianceStatus.NON_COMPLIANT
        else:
            check.status = ComplianceStatus.COMPLIANT

        check.violations = violations
        check.evidence = evidence

        return check

    async def _check_network_security(
        self,
        control: ComplianceControl,
        device_id: str,
        check: ComplianceCheck
    ) -> ComplianceCheck:
        """Check network security compliance"""
        violations = []
        evidence = []

        # Check firewall rules
        if "firewall" in control.name.lower():
            config = await self._get_device_config(device_id)
            if config:
                # Check for any-any rules
                if "permit any any" in config:
                    violations.append("Overly permissive firewall rule detected")

                # Check for documented rules
                if "description" not in config:
                    violations.append("Firewall rules lack documentation")

                evidence.append("Firewall configuration analyzed")

        # Check for encryption
        if "encryption" in ' '.join(control.requirements).lower():
            # Check for SSH v2
            if not await self._check_ssh_v2(device_id):
                violations.append("SSH v2 not enabled")

            evidence.append("Encryption protocols checked")

        # Determine status
        if violations:
            check.status = ComplianceStatus.NON_COMPLIANT
        else:
            check.status = ComplianceStatus.COMPLIANT

        check.violations = violations
        check.evidence = evidence

        return check

    async def _check_audit_logging(
        self,
        control: ComplianceControl,
        device_id: str,
        check: ComplianceCheck
    ) -> ComplianceCheck:
        """Check audit logging compliance"""
        violations = []
        evidence = []

        # Check logging configuration
        config = await self._get_device_config(device_id)
        if config:
            # Check for logging enabled
            if "logging" not in config:
                violations.append("Logging not configured")
            else:
                # Check specific log levels
                required_logs = ["logging trap informational", "logging buffer"]
                for req in required_logs:
                    if req not in config:
                        violations.append(f"Missing: {req}")

                evidence.append("Logging configuration verified")

        # Check audit trail integrity
        if self.audit_service:
            integrity = await self.audit_service.verify_integrity(device_id)
            if not integrity:
                violations.append("Audit trail integrity check failed")
            evidence.append("Audit trail integrity checked")

        # Determine status
        if violations:
            check.status = ComplianceStatus.NON_COMPLIANT
        else:
            check.status = ComplianceStatus.COMPLIANT

        check.violations = violations
        check.evidence = evidence

        return check

    async def _check_configuration(
        self,
        control: ComplianceControl,
        device_id: str,
        check: ComplianceCheck
    ) -> ComplianceCheck:
        """Check configuration compliance"""
        violations = []
        evidence = []

        # Check configuration standards
        config = await self._get_device_config(device_id)
        if config:
            # Check for required configurations
            required_configs = [
                "service password-encryption",
                "no ip http server",
                "banner motd"
            ]

            for req in required_configs:
                if req not in config:
                    violations.append(f"Missing required configuration: {req}")

            evidence.append("Configuration standards checked")

        # Check configuration backups
        last_backup = await self._get_last_backup_time(device_id)
        if last_backup:
            days_since = (datetime.utcnow() - last_backup).days
            if days_since > 7:  # Weekly backup requirement
                violations.append(f"Backup overdue: {days_since} days old")
            evidence.append(f"Last backup: {last_backup.isoformat()}")

        # Determine status
        if violations:
            check.status = ComplianceStatus.NON_COMPLIANT
        else:
            check.status = ComplianceStatus.COMPLIANT

        check.violations = violations
        check.evidence = evidence

        return check

    async def generate_report(
        self,
        framework: ComplianceFramework,
        start_date: datetime,
        end_date: datetime
    ) -> ComplianceReport:
        """
        Generate compliance report

        Args:
            framework: Compliance framework
            start_date: Report start date
            end_date: Report end date

        Returns:
            Compliance report
        """
        import uuid

        # Get checks for period
        checks = []
        for check in self.check_results.values():
            if (check.control_id in self.framework_controls[framework] and
                start_date <= check.checked_at <= end_date):
                checks.append(check)

        # Calculate compliance score
        total = len(checks)
        compliant = sum(1 for c in checks if c.status == ComplianceStatus.COMPLIANT)
        non_compliant = sum(1 for c in checks if c.status == ComplianceStatus.NON_COMPLIANT)

        compliance_score = (compliant / total * 100) if total > 0 else 0

        # Determine overall status
        if compliance_score >= 95:
            overall_status = ComplianceStatus.COMPLIANT
        elif compliance_score >= 80:
            overall_status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            overall_status = ComplianceStatus.NON_COMPLIANT

        # Generate summary
        summary = self._generate_summary(checks, framework)

        # Generate recommendations
        recommendations = self._generate_recommendations(checks)

        report = ComplianceReport(
            id=str(uuid.uuid4())[:12],
            framework=framework,
            generated_at=datetime.utcnow(),
            period_start=start_date,
            period_end=end_date,
            overall_status=overall_status,
            compliance_score=compliance_score,
            total_controls=len(self.framework_controls[framework]),
            compliant_controls=compliant,
            non_compliant_controls=non_compliant,
            checks=checks,
            summary=summary,
            recommendations=recommendations
        )

        # Store report
        self.report_history.append(report)

        return report

    def _generate_summary(
        self,
        checks: List[ComplianceCheck],
        framework: ComplianceFramework
    ) -> Dict[str, Any]:
        """Generate report summary"""
        # Group by category
        by_category = defaultdict(lambda: {'total': 0, 'compliant': 0})

        for check in checks:
            control = self.controls.get(check.control_id)
            if control:
                category = control.category.value
                by_category[category]['total'] += 1
                if check.status == ComplianceStatus.COMPLIANT:
                    by_category[category]['compliant'] += 1

        # Group by severity
        by_severity = defaultdict(lambda: {'total': 0, 'non_compliant': 0})

        for check in checks:
            control = self.controls.get(check.control_id)
            if control:
                severity = control.severity
                by_severity[severity]['total'] += 1
                if check.status == ComplianceStatus.NON_COMPLIANT:
                    by_severity[severity]['non_compliant'] += 1

        # Top violations
        violation_counts = defaultdict(int)
        for check in checks:
            for violation in check.violations:
                violation_counts[violation] += 1

        top_violations = sorted(
            violation_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        return {
            'by_category': dict(by_category),
            'by_severity': dict(by_severity),
            'top_violations': top_violations,
            'framework': framework.value
        }

    def _generate_recommendations(
        self,
        checks: List[ComplianceCheck]
    ) -> List[str]:
        """Generate recommendations based on checks"""
        recommendations = []

        # Analyze non-compliant checks
        non_compliant = [c for c in checks if c.status == ComplianceStatus.NON_COMPLIANT]

        # Group by control
        by_control = defaultdict(list)
        for check in non_compliant:
            by_control[check.control_id].append(check)

        for control_id, control_checks in by_control.items():
            control = self.controls.get(control_id)
            if control:
                # Add control-specific recommendations
                if control.remediation_steps:
                    for step in control.remediation_steps:
                        recommendations.append(f"{control.name}: {step}")
                else:
                    # Generic recommendation
                    recommendations.append(
                        f"Address {control.name} violations on {len(control_checks)} devices"
                    )

        # Add priority recommendations
        critical_controls = [
            c for c in non_compliant
            if self.controls.get(c.control_id) and
            self.controls[c.control_id].severity == "critical"
        ]

        if critical_controls:
            recommendations.insert(
                0,
                f"PRIORITY: Address {len(critical_controls)} critical control violations immediately"
            )

        return recommendations[:20]  # Limit to top 20

    def export_report(
        self,
        report: ComplianceReport,
        format: str = "json"
    ) -> str:
        """
        Export report in specified format

        Args:
            report: Compliance report
            format: Export format (json, html, csv)

        Returns:
            Exported report
        """
        if format == "json":
            return self._export_json(report)
        elif format == "html":
            return self._export_html(report)
        elif format == "csv":
            return self._export_csv(report)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _export_json(self, report: ComplianceReport) -> str:
        """Export report as JSON"""
        data = {
            'id': report.id,
            'framework': report.framework.value,
            'generated_at': report.generated_at.isoformat(),
            'period': {
                'start': report.period_start.isoformat(),
                'end': report.period_end.isoformat()
            },
            'overall_status': report.overall_status.value,
            'compliance_score': report.compliance_score,
            'statistics': {
                'total_controls': report.total_controls,
                'compliant': report.compliant_controls,
                'non_compliant': report.non_compliant_controls
            },
            'summary': report.summary,
            'recommendations': report.recommendations,
            'checks': [
                {
                    'control_id': c.control_id,
                    'device_id': c.device_id,
                    'status': c.status.value,
                    'violations': c.violations
                }
                for c in report.checks
            ]
        }
        return json.dumps(data, indent=2, default=str)

    def _export_html(self, report: ComplianceReport) -> str:
        """Export report as HTML"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Compliance Report - {report.framework.value.upper()}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                .score {{ font-size: 48px; font-weight: bold; }}
                .compliant {{ color: green; }}
                .non-compliant {{ color: red; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>Compliance Report - {report.framework.value.upper()}</h1>
            <p>Generated: {report.generated_at.isoformat()}</p>
            <p>Period: {report.period_start.date()} to {report.period_end.date()}</p>

            <h2>Overall Compliance Score</h2>
            <div class="score {('compliant' if report.compliance_score >= 80 else 'non-compliant')}">
                {report.compliance_score:.1f}%
            </div>

            <h2>Summary</h2>
            <table>
                <tr>
                    <th>Metric</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td>Total Controls</td>
                    <td>{report.total_controls}</td>
                </tr>
                <tr>
                    <td>Compliant Controls</td>
                    <td class="compliant">{report.compliant_controls}</td>
                </tr>
                <tr>
                    <td>Non-Compliant Controls</td>
                    <td class="non-compliant">{report.non_compliant_controls}</td>
                </tr>
            </table>

            <h2>Recommendations</h2>
            <ol>
                {''.join(f'<li>{html.escape(rec)}</li>' for rec in report.recommendations)}
            </ol>
        </body>
        </html>
        """
        return html_content

    def _export_csv(self, report: ComplianceReport) -> str:
        """Export report as CSV"""
        import io
        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow([
            'Control ID',
            'Device ID',
            'Status',
            'Checked At',
            'Violations'
        ])

        # Write checks
        for check in report.checks:
            writer.writerow([
                check.control_id,
                check.device_id,
                check.status.value,
                check.checked_at.isoformat(),
                '; '.join(check.violations)
            ])

        return output.getvalue()

    # Helper methods
    async def _get_device_config(self, device_id: str) -> Optional[str]:
        """Get device configuration"""
        if self.device_service:
            return await self.device_service.get_configuration(device_id)
        return None

    async def _count_admin_accounts(self, device_id: str) -> int:
        """Count admin accounts on device"""
        # Simplified implementation
        config = await self._get_device_config(device_id)
        if config:
            return config.count("privilege 15")
        return 0

    async def _check_ssh_v2(self, device_id: str) -> bool:
        """Check if SSH v2 is enabled"""
        config = await self._get_device_config(device_id)
        if config:
            return "ip ssh version 2" in config
        return False

    async def _get_last_backup_time(self, device_id: str) -> Optional[datetime]:
        """Get last backup time for device"""
        # Would query backup service
        return datetime.utcnow() - timedelta(days=3)  # Mock

    async def _run_validation_script(
        self,
        control: ComplianceControl,
        device_id: str,
        check: ComplianceCheck
    ) -> ComplianceCheck:
        """Run custom validation script"""
        # Would execute validation script
        check.status = ComplianceStatus.COMPLIANT
        return check