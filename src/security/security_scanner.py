"""
Security Scanner Engine
Automated security scanning and vulnerability detection
"""
import asyncio
import structlog
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime, timedelta
import re
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models.security_audit import (
    VulnerabilityScan,
    Vulnerability,
    VulnerabilitySeverity,
    SecurityPolicy,
    ComplianceReport,
    ComplianceControlAssessment,
    ComplianceFramework,
    ComplianceStatus
)
from ..db.models.device import Device
from ..db.models.user import User
from ..db.session import get_db

logger = structlog.get_logger()


class SecurityScanner:
    """
    Security Scanner Engine

    Performs automated security scans to detect vulnerabilities,
    policy violations, and compliance issues.
    """

    def __init__(self):
        self.scan_semaphore = asyncio.Semaphore(10)  # Max concurrent scans

    async def start_scan(
        self,
        scan_type: str,
        scan_target: str,
        db: AsyncSession,
        user_id: str
    ) -> VulnerabilityScan:
        """
        Start a new security scan

        Args:
            scan_type: Type of scan (password_policy, certificate, privilege, etc.)
            scan_target: Target for scan (all, device_id, user_id, etc.)
            db: Database session
            user_id: User initiating scan

        Returns:
            VulnerabilityScan object
        """
        logger.info(
            "Starting security scan",
            scan_type=scan_type,
            target=scan_target,
            user=user_id
        )

        # Create scan record
        scan = VulnerabilityScan(
            scan_type=scan_type,
            scan_target=scan_target,
            scan_started_at=datetime.utcnow(),
            scan_status="running",
            scanner_name="CatNet Security Scanner",
            scanner_version="1.0.0",
            created_by=user_id
        )

        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        # Execute scan asynchronously
        asyncio.create_task(self._execute_scan(scan.id, scan_type, scan_target))

        return scan

    async def _execute_scan(
        self,
        scan_id: str,
        scan_type: str,
        scan_target: str
    ):
        """Execute scan in background"""
        async with self.scan_semaphore:
            try:
                async with get_db() as db:
                    # Get scan record
                    result = await db.execute(
                        select(VulnerabilityScan).filter(VulnerabilityScan.id == scan_id)
                    )
                    scan = result.scalar_one()

                    # Execute appropriate scan
                    if scan_type == "password_policy":
                        vulnerabilities = await self._scan_password_policies(db)
                    elif scan_type == "certificate":
                        vulnerabilities = await self._scan_certificates(db)
                    elif scan_type == "privilege":
                        vulnerabilities = await self._scan_excessive_privileges(db)
                    elif scan_type == "inactive_accounts":
                        vulnerabilities = await self._scan_inactive_accounts(db)
                    elif scan_type == "configuration":
                        vulnerabilities = await self._scan_device_configurations(scan_target, db)
                    elif scan_type == "api_keys":
                        vulnerabilities = await self._scan_api_keys(db)
                    elif scan_type == "full":
                        # Run all scans
                        vulnerabilities = []
                        vulnerabilities.extend(await self._scan_password_policies(db))
                        vulnerabilities.extend(await self._scan_certificates(db))
                        vulnerabilities.extend(await self._scan_excessive_privileges(db))
                        vulnerabilities.extend(await self._scan_inactive_accounts(db))
                        vulnerabilities.extend(await self._scan_api_keys(db))
                    else:
                        vulnerabilities = []

                    # Save vulnerabilities
                    for vuln_data in vulnerabilities:
                        vulnerability = Vulnerability(
                            scan_id=scan.id,
                            **vuln_data
                        )
                        db.add(vulnerability)

                    # Update scan summary
                    scan.scan_completed_at = datetime.utcnow()
                    scan.scan_duration_seconds = int(
                        (scan.scan_completed_at - scan.scan_started_at).total_seconds()
                    )
                    scan.total_vulnerabilities = len(vulnerabilities)
                    scan.critical_count = sum(1 for v in vulnerabilities if v.get("severity") == VulnerabilitySeverity.CRITICAL)
                    scan.high_count = sum(1 for v in vulnerabilities if v.get("severity") == VulnerabilitySeverity.HIGH)
                    scan.medium_count = sum(1 for v in vulnerabilities if v.get("severity") == VulnerabilitySeverity.MEDIUM)
                    scan.low_count = sum(1 for v in vulnerabilities if v.get("severity") == VulnerabilitySeverity.LOW)
                    scan.scan_status = "completed"

                    await db.commit()

                    logger.info(
                        "Security scan completed",
                        scan_id=scan_id,
                        vulnerabilities=len(vulnerabilities),
                        critical=scan.critical_count,
                        high=scan.high_count
                    )

            except Exception as e:
                logger.error(f"Security scan failed: {e}", scan_id=scan_id)
                async with get_db() as db:
                    result = await db.execute(
                        select(VulnerabilityScan).filter(VulnerabilityScan.id == scan_id)
                    )
                    scan = result.scalar_one()
                    scan.scan_status = "failed"
                    scan.scan_completed_at = datetime.utcnow()
                    await db.commit()

    async def _scan_password_policies(self, db: AsyncSession) -> List[Dict]:
        """Scan for password policy violations"""
        logger.info("Scanning password policies")
        vulnerabilities = []

        # Get active security policy
        result = await db.execute(
            select(SecurityPolicy).filter(
                and_(
                    SecurityPolicy.enabled == True,
                    SecurityPolicy.policy_type == "password"
                )
            )
        )
        policy = result.scalar_one_or_none()

        if not policy:
            return vulnerabilities

        # Get all users
        result = await db.execute(select(User))
        users = result.scalars().all()

        for user in users:
            # Check password age
            if policy.password_expiry_days and user.password_changed_at:
                days_since_change = (datetime.utcnow() - user.password_changed_at).days

                if days_since_change > policy.password_expiry_days:
                    vulnerabilities.append({
                        "vulnerability_id": f"PWD-{user.id}-EXPIRED",
                        "title": "Expired Password",
                        "description": f"User '{user.username}' password has not been changed in {days_since_change} days",
                        "severity": VulnerabilitySeverity.MEDIUM,
                        "cvss_score": 5.0,
                        "resource_type": "user",
                        "resource_id": str(user.id),
                        "resource_name": user.username,
                        "category": "password_policy",
                        "remediation_steps": f"Force password change for user '{user.username}'",
                        "remediation_effort": "low",
                        "remediation_priority": 2,
                        "status": "open",
                        "risk_score": 5.0
                    })

            # Check for default/weak passwords (if we have password strength tracking)
            if hasattr(user, 'password_strength') and user.password_strength == "weak":
                vulnerabilities.append({
                    "vulnerability_id": f"PWD-{user.id}-WEAK",
                    "title": "Weak Password",
                    "description": f"User '{user.username}' is using a weak password",
                    "severity": VulnerabilitySeverity.HIGH,
                    "cvss_score": 7.5,
                    "resource_type": "user",
                    "resource_id": str(user.id),
                    "resource_name": user.username,
                    "category": "password_policy",
                    "remediation_steps": f"Enforce strong password for user '{user.username}'",
                    "remediation_effort": "low",
                    "remediation_priority": 1,
                    "status": "open",
                    "risk_score": 7.5
                    })

        return vulnerabilities

    async def _scan_certificates(self, db: AsyncSession) -> List[Dict]:
        """Scan for certificate expiration issues"""
        logger.info("Scanning certificates")
        vulnerabilities = []

        # Get all devices with certificates
        result = await db.execute(
            select(Device).filter(Device.has_certificate == True)
        )
        devices = result.scalars().all()

        for device in devices:
            if device.certificate_expiry:
                days_until_expiry = (device.certificate_expiry - datetime.utcnow()).days

                if days_until_expiry < 0:
                    # Certificate expired
                    vulnerabilities.append({
                        "vulnerability_id": f"CERT-{device.id}-EXPIRED",
                        "title": "Expired TLS Certificate",
                        "description": f"Device '{device.hostname}' certificate expired {abs(days_until_expiry)} days ago",
                        "severity": VulnerabilitySeverity.CRITICAL,
                        "cvss_score": 9.0,
                        "resource_type": "device",
                        "resource_id": str(device.id),
                        "resource_name": device.hostname,
                        "category": "certificate",
                        "cwe_id": "CWE-295",
                        "remediation_steps": f"Renew and install new certificate on device '{device.hostname}'",
                        "remediation_effort": "medium",
                        "remediation_priority": 1,
                        "status": "open",
                        "risk_score": 9.0,
                        "evidence": {
                            "expiry_date": device.certificate_expiry.isoformat(),
                            "days_expired": abs(days_until_expiry)
                        }
                    })

                elif days_until_expiry < 30:
                    # Certificate expiring soon
                    severity = VulnerabilitySeverity.HIGH if days_until_expiry < 7 else VulnerabilitySeverity.MEDIUM
                    cvss = 7.0 if days_until_expiry < 7 else 5.0

                    vulnerabilities.append({
                        "vulnerability_id": f"CERT-{device.id}-EXPIRING",
                        "title": "TLS Certificate Expiring Soon",
                        "description": f"Device '{device.hostname}' certificate expires in {days_until_expiry} days",
                        "severity": severity,
                        "cvss_score": cvss,
                        "resource_type": "device",
                        "resource_id": str(device.id),
                        "resource_name": device.hostname,
                        "category": "certificate",
                        "remediation_steps": f"Plan certificate renewal for device '{device.hostname}'",
                        "remediation_effort": "medium",
                        "remediation_priority": 2,
                        "status": "open",
                        "risk_score": cvss,
                        "evidence": {
                            "expiry_date": device.certificate_expiry.isoformat(),
                            "days_remaining": days_until_expiry
                        }
                    })

        return vulnerabilities

    async def _scan_excessive_privileges(self, db: AsyncSession) -> List[Dict]:
        """Scan for users with excessive privileges"""
        logger.info("Scanning for excessive privileges")
        vulnerabilities = []

        # Get all users
        result = await db.execute(select(User))
        users = result.scalars().all()

        for user in users:
            # Check for admin users with no recent activity
            if user.is_admin and user.last_login_at:
                days_since_login = (datetime.utcnow() - user.last_login_at).days

                if days_since_login > 90:
                    vulnerabilities.append({
                        "vulnerability_id": f"PRIV-{user.id}-INACTIVE-ADMIN",
                        "title": "Inactive Admin Account",
                        "description": f"Admin user '{user.username}' has not logged in for {days_since_login} days",
                        "severity": VulnerabilitySeverity.HIGH,
                        "cvss_score": 7.0,
                        "resource_type": "user",
                        "resource_id": str(user.id),
                        "resource_name": user.username,
                        "category": "privilege",
                        "remediation_steps": f"Review and potentially revoke admin privileges for '{user.username}'",
                        "remediation_effort": "low",
                        "remediation_priority": 2,
                        "status": "open",
                        "risk_score": 7.0,
                        "evidence": {
                            "last_login": user.last_login_at.isoformat() if user.last_login_at else None,
                            "days_inactive": days_since_login
                        }
                    })

            # Check for users with multiple high-privilege roles
            if hasattr(user, 'roles') and len(user.roles) > 3:
                vulnerabilities.append({
                    "vulnerability_id": f"PRIV-{user.id}-MULTI-ROLE",
                    "title": "User with Multiple Privileged Roles",
                    "description": f"User '{user.username}' has {len(user.roles)} roles assigned",
                    "severity": VulnerabilitySeverity.MEDIUM,
                    "cvss_score": 5.0,
                    "resource_type": "user",
                    "resource_id": str(user.id),
                    "resource_name": user.username,
                    "category": "privilege",
                    "remediation_steps": f"Review role assignments for '{user.username}' and apply principle of least privilege",
                    "remediation_effort": "medium",
                    "remediation_priority": 3,
                    "status": "open",
                    "risk_score": 5.0
                })

        return vulnerabilities

    async def _scan_inactive_accounts(self, db: AsyncSession) -> List[Dict]:
        """Scan for inactive user accounts"""
        logger.info("Scanning for inactive accounts")
        vulnerabilities = []

        # Get all users
        result = await db.execute(
            select(User).filter(User.is_active == True)
        )
        users = result.scalars().all()

        for user in users:
            if user.last_login_at:
                days_since_login = (datetime.utcnow() - user.last_login_at).days

                if days_since_login > 180:
                    vulnerabilities.append({
                        "vulnerability_id": f"ACCT-{user.id}-INACTIVE",
                        "title": "Inactive User Account",
                        "description": f"User account '{user.username}' has been inactive for {days_since_login} days",
                        "severity": VulnerabilitySeverity.MEDIUM,
                        "cvss_score": 4.0,
                        "resource_type": "user",
                        "resource_id": str(user.id),
                        "resource_name": user.username,
                        "category": "account_management",
                        "remediation_steps": f"Disable or remove inactive account '{user.username}'",
                        "remediation_effort": "low",
                        "remediation_priority": 3,
                        "status": "open",
                        "risk_score": 4.0,
                        "evidence": {
                            "last_login": user.last_login_at.isoformat(),
                            "days_inactive": days_since_login
                        }
                    })

        return vulnerabilities

    async def _scan_device_configurations(
        self,
        target: str,
        db: AsyncSession
    ) -> List[Dict]:
        """Scan device configurations for security issues"""
        logger.info("Scanning device configurations", target=target)
        vulnerabilities = []

        # Get devices to scan
        if target == "all":
            result = await db.execute(select(Device))
            devices = result.scalars().all()
        else:
            result = await db.execute(
                select(Device).filter(Device.id == target)
            )
            devices = [result.scalar_one_or_none()]

        for device in devices:
            if not device or not device.last_config:
                continue

            config = device.last_config

            # Check for plain text passwords
            if re.search(r'password\s+\d+\s+[^\s]+', config, re.IGNORECASE):
                vulnerabilities.append({
                    "vulnerability_id": f"CONFIG-{device.id}-PLAINTEXT-PWD",
                    "title": "Plain Text Passwords in Configuration",
                    "description": f"Device '{device.hostname}' configuration contains plain text passwords",
                    "severity": VulnerabilitySeverity.HIGH,
                    "cvss_score": 7.5,
                    "resource_type": "device",
                    "resource_id": str(device.id),
                    "resource_name": device.hostname,
                    "category": "configuration",
                    "cwe_id": "CWE-256",
                    "remediation_steps": "Enable password encryption: service password-encryption",
                    "remediation_effort": "low",
                    "remediation_priority": 1,
                    "status": "open",
                    "risk_score": 7.5
                })

            # Check for weak SNMP community strings
            if re.search(r'snmp-server\s+community\s+(public|private)', config, re.IGNORECASE):
                vulnerabilities.append({
                    "vulnerability_id": f"CONFIG-{device.id}-WEAK-SNMP",
                    "title": "Weak SNMP Community String",
                    "description": f"Device '{device.hostname}' uses default SNMP community strings",
                    "severity": VulnerabilitySeverity.HIGH,
                    "cvss_score": 7.0,
                    "resource_type": "device",
                    "resource_id": str(device.id),
                    "resource_name": device.hostname,
                    "category": "configuration",
                    "cwe_id": "CWE-798",
                    "remediation_steps": "Change SNMP community strings to non-default values",
                    "remediation_effort": "low",
                    "remediation_priority": 1,
                    "status": "open",
                    "risk_score": 7.0
                })

            # Check for enabled Telnet
            if re.search(r'line\s+vty.*\n.*transport\s+input.*telnet', config, re.IGNORECASE | re.DOTALL):
                vulnerabilities.append({
                    "vulnerability_id": f"CONFIG-{device.id}-TELNET",
                    "title": "Insecure Telnet Protocol Enabled",
                    "description": f"Device '{device.hostname}' has Telnet enabled",
                    "severity": VulnerabilitySeverity.HIGH,
                    "cvss_score": 8.0,
                    "resource_type": "device",
                    "resource_id": str(device.id),
                    "resource_name": device.hostname,
                    "category": "configuration",
                    "cwe_id": "CWE-319",
                    "remediation_steps": "Disable Telnet and use SSH only: transport input ssh",
                    "remediation_effort": "low",
                    "remediation_priority": 1,
                    "status": "open",
                    "risk_score": 8.0
                })

        return vulnerabilities

    async def _scan_api_keys(self, db: AsyncSession) -> List[Dict]:
        """Scan for API key security issues"""
        logger.info("Scanning API keys")
        vulnerabilities = []

        from ..db.models.security_audit import APIKey

        # Get all API keys
        result = await db.execute(select(APIKey))
        api_keys = result.scalars().all()

        for key in api_keys:
            # Check for expired keys still enabled
            if key.enabled and key.expires_at and key.expires_at < datetime.utcnow():
                vulnerabilities.append({
                    "vulnerability_id": f"APIKEY-{key.id}-EXPIRED",
                    "title": "Expired API Key Still Enabled",
                    "description": f"API key '{key.key_name}' expired but is still enabled",
                    "severity": VulnerabilitySeverity.MEDIUM,
                    "cvss_score": 6.0,
                    "resource_type": "api_key",
                    "resource_id": str(key.id),
                    "resource_name": key.key_name,
                    "category": "api_security",
                    "remediation_steps": f"Revoke expired API key '{key.key_name}'",
                    "remediation_effort": "low",
                    "remediation_priority": 2,
                    "status": "open",
                    "risk_score": 6.0
                })

            # Check for unused keys
            if key.last_used_at:
                days_since_use = (datetime.utcnow() - key.last_used_at).days

                if days_since_use > 90 and key.enabled:
                    vulnerabilities.append({
                        "vulnerability_id": f"APIKEY-{key.id}-UNUSED",
                        "title": "Unused API Key",
                        "description": f"API key '{key.key_name}' has not been used in {days_since_use} days",
                        "severity": VulnerabilitySeverity.LOW,
                        "cvss_score": 3.0,
                        "resource_type": "api_key",
                        "resource_id": str(key.id),
                        "resource_name": key.key_name,
                        "category": "api_security",
                        "remediation_steps": f"Review and potentially revoke unused API key '{key.key_name}'",
                        "remediation_effort": "low",
                        "remediation_priority": 3,
                        "status": "open",
                        "risk_score": 3.0,
                        "evidence": {
                            "last_used": key.last_used_at.isoformat(),
                            "days_unused": days_since_use
                        }
                    })

        return vulnerabilities


# Singleton instance
security_scanner = SecurityScanner()
