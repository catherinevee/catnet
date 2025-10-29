"""Unit tests for security scanner"""
import pytest
from datetime import datetime, timedelta

from src.security.security_scanner import security_scanner
from src.db.models.security_audit import VulnerabilityScan, VulnerabilitySeverity


@pytest.mark.asyncio
async def test_start_scan(db_session, admin_user):
    """Test starting security scan"""
    scan = await security_scanner.start_scan(
        scan_type="password_policy",
        scan_target="all",
        db=db_session,
        user_id=str(admin_user.id)
    )
    
    assert scan is not None
    assert scan.scan_type == "password_policy"
    assert scan.scan_target == "all"
    assert scan.scan_status == "running"


@pytest.mark.asyncio
async def test_scan_password_policies(db_session, test_user):
    """Test password policy scanning"""
    # Create user with old password
    test_user.password_changed_at = datetime.utcnow() - timedelta(days=100)
    await db_session.commit()
    
    vulnerabilities = await security_scanner._scan_password_policies(db_session)
    
    assert len(vulnerabilities) > 0
    assert any(v["category"] == "password_policy" for v in vulnerabilities)


@pytest.mark.asyncio
async def test_scan_certificates(db_session, test_device):
    """Test certificate scanning"""
    # Set expired certificate
    test_device.has_certificate = True
    test_device.certificate_expiry = datetime.utcnow() - timedelta(days=10)
    await db_session.commit()
    
    vulnerabilities = await security_scanner._scan_certificates(db_session)
    
    assert len(vulnerabilities) > 0
    assert vulnerabilities[0]["severity"] == VulnerabilitySeverity.CRITICAL
    assert "expired" in vulnerabilities[0]["title"].lower()


@pytest.mark.asyncio
async def test_scan_inactive_accounts(db_session, test_user):
    """Test inactive account scanning"""
    # Set last login to 200 days ago
    test_user.last_login_at = datetime.utcnow() - timedelta(days=200)
    await db_session.commit()
    
    vulnerabilities = await security_scanner._scan_inactive_accounts(db_session)
    
    assert len(vulnerabilities) > 0
    assert vulnerabilities[0]["category"] == "account_management"
