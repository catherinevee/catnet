"""
Security tests for CatNet system.
Tests for vulnerability detection, penetration testing scenarios, and security compliance.
"""

import pytest
import asyncio
import hashlib
import base64
from typing import List, Dict, Any
from unittest.mock import Mock, AsyncMock, patch

from httpx import AsyncClient
from fastapi import status

from src.gitops.secret_scanner import SecretScanner, SecretPattern
from src.core.security import SecurityManager
from src.auth.service import AuthService


class TestSecurityScanner:
    """Test security scanning functionality."""

    @pytest.fixture
    def secret_scanner(self):
        """Create secret scanner instance."""
        return SecretScanner()

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_detect_aws_keys(self, secret_scanner):
        """Test detection of AWS access keys."""
        content = """
        # Configuration file
        aws_access_key_id = AKIAIOSFODNN7EXAMPLE
        aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
        """

        secrets = await secret_scanner.scan_content(content)

        assert len(secrets) >= 2
        aws_keys = [s for s in secrets if 'aws' in s.pattern_name.lower()]
        assert len(aws_keys) >= 2

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_detect_private_keys(self, secret_scanner):
        """Test detection of private keys."""
        content = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEjWT2btNiisUckMs8n
        -----END RSA PRIVATE KEY-----
        """

        secrets = await secret_scanner.scan_content(content)

        assert len(secrets) >= 1
        private_key_secrets = [s for s in secrets if 'private' in s.pattern_name.lower()]
        assert len(private_key_secrets) >= 1

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_detect_database_urls(self, secret_scanner):
        """Test detection of database connection strings."""
        content = """
        DATABASE_URL=postgresql://user:password@localhost:5432/dbname
        REDIS_URL=redis://user:password@localhost:6379/0
        """

        secrets = await secret_scanner.scan_content(content)

        assert len(secrets) >= 2
        db_secrets = [s for s in secrets if any(db in s.pattern_name.lower()
                     for db in ['postgres', 'redis', 'database'])]
        assert len(db_secrets) >= 2

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_detect_api_tokens(self, secret_scanner):
        """Test detection of API tokens."""
        content = """
        GITHUB_TOKEN=ghp_test1234567890abcdefghijklmnopqrstuv
        SLACK_TOKEN=xoxb-test-1234-5678-testslacktoken123456
        """

        secrets = await secret_scanner.scan_content(content)

        assert len(secrets) >= 2

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_detect_high_entropy_strings(self, secret_scanner):
        """Test detection of high entropy strings."""
        content = """
        # This looks like a secret
        secret_key = aB3dE6fG9hI2jK5lM8nO1pQ4rS7tU0vW3xY6zA9bC2dE5fG8hI1jK4lM7nO0pQ3rS6t
        """

        secrets = await secret_scanner.scan_content(content)

        assert len(secrets) >= 1
        entropy_secrets = [s for s in secrets if 'entropy' in s.pattern_name.lower()]
        assert len(entropy_secrets) >= 1

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_detect_passwords_in_config(self, secret_scanner):
        """Test detection of passwords in configuration."""
        content = """
        # Device configuration
        username admin
        password ThisIsASecretPassword123!
        enable secret EnablePasswordHere
        """

        secrets = await secret_scanner.scan_content(content)

        assert len(secrets) >= 2

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_scan_multiple_files(self, secret_scanner, temp_dir):
        """Test scanning multiple files for secrets."""
        import os

        # Create test files with secrets
        files = {
            "config.yml": "api_key: sk_1234567890abcdef",
            "secrets.env": "PASSWORD=supersecret123",
            ".env": "DATABASE_URL=postgresql://user:pass@localhost/db"
        }

        for filename, content in files.items():
            with open(os.path.join(temp_dir, filename), 'w') as f:
                f.write(content)

        results = await secret_scanner.scan_directory(temp_dir)

        assert len(results) >= 3
        assert all(isinstance(r, dict) for r in results)

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_false_positive_filtering(self, secret_scanner):
        """Test filtering of false positives."""
        content = """
        # This should not be detected as secrets
        example_key = "EXAMPLE_KEY_NOT_REAL"
        test_password = "test123"
        placeholder = "your_api_key_here"
        """

        secrets = await secret_scanner.scan_content(content)

        # Should filter out obvious false positives
        false_positives = [s for s in secrets if any(word in s.value.lower()
                          for word in ['example', 'test', 'placeholder', 'your_'])]
        assert len(false_positives) == 0

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_base64_encoded_secrets(self, secret_scanner):
        """Test detection of base64 encoded secrets."""
        # Base64 encoded secret
        secret = "supersecretpassword123"
        encoded = base64.b64encode(secret.encode()).decode()

        content = f"""
        # Base64 encoded secret
        encoded_secret = {encoded}
        """

        secrets = await secret_scanner.scan_content(content)

        assert len(secrets) >= 1

    @pytest.mark.security
    def test_custom_pattern_addition(self, secret_scanner):
        """Test adding custom secret patterns."""
        custom_pattern = SecretPattern(
            name="custom_token",
            pattern=r"CUSTOM_[A-Z0-9]{32}",
            description="Custom API token"
        )

        secret_scanner.add_pattern(custom_pattern)

        content = "CUSTOM_ABCD1234EFGH5678IJKL9012MNOP3456"

        # This should now be detected
        secrets = asyncio.run(secret_scanner.scan_content(content))
        assert len(secrets) >= 1

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_entropy_threshold_tuning(self, secret_scanner):
        """Test entropy threshold configuration."""
        # Low entropy string
        low_entropy = "password123"

        # High entropy string
        high_entropy = "aB3dE6fG9hI2jK5lM8nO1pQ4rS7tU0vW"

        # Test with different thresholds
        secret_scanner.entropy_threshold = 3.0  # Low threshold
        secrets_low = await secret_scanner.scan_content(f"secret={low_entropy}")

        secret_scanner.entropy_threshold = 5.0  # High threshold
        secrets_high = await secret_scanner.scan_content(f"secret={high_entropy}")

        # High entropy string should always be detected
        assert len(secrets_high) >= 1


class TestSecurityCompliance:
    """Test security compliance and hardening."""

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_password_strength_requirements(self):
        """Test password strength validation."""
        from src.core.security import validate_password_strength

        weak_passwords = [
            "123456",
            "password",
            "qwerty",
            "admin",
            "letmein",
            "welcome",
            "monkey",
            "dragon"
        ]

        for password in weak_passwords:
            with pytest.raises(Exception):
                validate_password_strength(password)

        strong_passwords = [
            "MyStrongP@ssw0rd123!",
            "C0mpl3x&Secure#P@ss",
            "Ungu3ss@bl3*P4ssw0rd"
        ]

        for password in strong_passwords:
            # Should not raise exception
            validate_password_strength(password)

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_rate_limiting_enforcement(self, async_test_client: AsyncClient):
        """Test rate limiting is properly enforced."""
        # Test API rate limiting
        responses = []

        for i in range(20):  # Exceed rate limit
            response = await async_test_client.get("/api/v1/health")
            responses.append(response)

        # Should eventually get rate limited
        rate_limited = [r for r in responses if r.status_code == 429]
        assert len(rate_limited) > 0

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sql_injection_protection(self, async_test_client: AsyncClient):
        """Test SQL injection protection."""
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "1; DELETE FROM devices; --",
            "admin'/*",
            "' UNION SELECT * FROM users --"
        ]

        for payload in malicious_inputs:
            # Test in various endpoints
            response = await async_test_client.get(
                f"/api/v1/devices",
                params={"search": payload}
            )

            # Should not cause database errors
            assert response.status_code != 500

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_xss_protection(self, async_test_client: AsyncClient, auth_headers):
        """Test XSS protection in user inputs."""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'; alert('XSS'); //"
        ]

        for payload in xss_payloads:
            # Test in profile update
            response = await async_test_client.put(
                "/api/v1/auth/profile",
                json={"first_name": payload},
                headers=auth_headers
            )

            if response.status_code == 200:
                data = response.json()
                # Should be sanitized
                assert "<script>" not in data.get("first_name", "")
                assert "javascript:" not in data.get("first_name", "")

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_csrf_protection(self, async_test_client: AsyncClient):
        """Test CSRF protection."""
        # Attempt state-changing operation without proper headers
        response = await async_test_client.post(
            "/api/v1/auth/login",
            data={"username": "test", "password": "test"},
            headers={"Origin": "http://malicious-site.com"}
        )

        # Should be protected against CSRF
        assert response.status_code in [403, 401, 400]

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_directory_traversal_protection(self, async_test_client: AsyncClient, auth_headers):
        """Test directory traversal protection."""
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f",
            "....//....//....//etc/passwd"
        ]

        for payload in traversal_payloads:
            response = await async_test_client.get(
                f"/api/v1/configs/{payload}",
                headers=auth_headers
            )

            # Should not allow directory traversal
            assert response.status_code in [400, 403, 404]

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_command_injection_protection(self, async_test_client: AsyncClient, auth_headers):
        """Test command injection protection."""
        injection_payloads = [
            "; cat /etc/passwd",
            "| whoami",
            "&& rm -rf /",
            "`id`",
            "$(whoami)"
        ]

        for payload in injection_payloads:
            # Test in device command execution
            response = await async_test_client.post(
                "/api/v1/devices/test-device/commands",
                json={"command": f"show version {payload}"},
                headers=auth_headers
            )

            # Should sanitize or reject
            if response.status_code == 200:
                data = response.json()
                # Should not contain injection results
                assert "root" not in data.get("output", "")
                assert "/etc/passwd" not in data.get("output", "")

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_file_upload_security(self, async_test_client: AsyncClient, auth_headers):
        """Test file upload security."""
        # Test malicious file types
        malicious_files = [
            ("test.php", "<?php system($_GET['cmd']); ?>", "application/x-php"),
            ("test.jsp", "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>", "text/plain"),
            ("test.exe", b"\x4d\x5a\x90\x00", "application/octet-stream")
        ]

        for filename, content, content_type in malicious_files:
            files = {"file": (filename, content, content_type)}

            response = await async_test_client.post(
                "/api/v1/configs/upload",
                files=files,
                headers=auth_headers
            )

            # Should reject malicious files
            assert response.status_code in [400, 403, 415]

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_session_security(self, async_test_client: AsyncClient):
        """Test session security measures."""
        # Test session fixation protection
        response1 = await async_test_client.get("/api/v1/health")
        session1 = response1.cookies.get("session_id")

        # Login
        login_response = await async_test_client.post(
            "/api/v1/auth/login",
            data={"username": "testuser", "password": "testpass"}
        )

        if login_response.status_code == 200:
            session2 = login_response.cookies.get("session_id")
            # Session should change after login
            assert session1 != session2

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_information_disclosure_prevention(self, async_test_client: AsyncClient):
        """Test prevention of information disclosure."""
        # Test that error messages don't leak sensitive info
        response = await async_test_client.get("/api/v1/nonexistent-endpoint")

        assert response.status_code == 404
        data = response.json()

        # Should not reveal internal paths or implementation details
        sensitive_keywords = [
            "/var/www",
            "/home/",
            "c:\\",
            "stacktrace",
            "exception",
            "traceback"
        ]

        response_text = str(data).lower()
        for keyword in sensitive_keywords:
            assert keyword not in response_text

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_encryption_at_rest(self, test_session):
        """Test that sensitive data is encrypted at rest."""
        from src.devices.models import Device

        # Create device with sensitive data
        device = Device(
            name="test-device",
            hostname="test.example.com",
            ip_address="192.168.1.1",
            vendor="cisco",
            platform="ios"
        )

        test_session.add(device)
        await test_session.commit()

        # Verify sensitive fields are encrypted in database
        result = await test_session.execute(
            "SELECT * FROM devices WHERE name = 'test-device'"
        )
        row = result.fetchone()

        # SSH key references should be encrypted vault paths, not plaintext
        if hasattr(device, 'ssh_key_ref') and device.ssh_key_ref:
            assert not device.ssh_key_ref.startswith("-----BEGIN")

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_audit_trail_integrity(self, test_session):
        """Test audit trail integrity and immutability."""
        from src.security.audit import AuditLogger

        audit = AuditLogger()

        # Log an event
        await audit.log_event(
            event_type="TEST_EVENT",
            user_id="test_user",
            details={"action": "test"}
        )

        # Verify audit log exists and is properly formatted
        result = await test_session.execute(
            "SELECT * FROM audit.audit_log WHERE event_type = 'TEST_EVENT'"
        )
        row = result.fetchone()

        assert row is not None
        assert row.hash_chain is not None  # Should have integrity hash

    @pytest.mark.security
    def test_secure_random_generation(self):
        """Test secure random number generation."""
        import secrets

        # Generate random values
        random_values = [secrets.token_urlsafe(32) for _ in range(100)]

        # Should all be unique (extremely high probability)
        assert len(set(random_values)) == 100

        # Should be proper length
        assert all(len(v) >= 32 for v in random_values)


class TestPenetrationTesting:
    """Simulated penetration testing scenarios."""

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_brute_force_protection(self, async_test_client: AsyncClient):
        """Test brute force attack protection."""
        # Attempt multiple failed logins
        for i in range(10):
            response = await async_test_client.post(
                "/api/v1/auth/login",
                data={"username": "admin", "password": f"wrong{i}"}
            )

        # Should implement account lockout or rate limiting
        final_response = await async_test_client.post(
            "/api/v1/auth/login",
            data={"username": "admin", "password": "wrong_final"}
        )

        assert final_response.status_code in [429, 423, 401]

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_privilege_escalation_prevention(self, async_test_client: AsyncClient, auth_headers):
        """Test prevention of privilege escalation."""
        # Regular user trying to access admin functions
        admin_endpoints = [
            "/api/v1/admin/users",
            "/api/v1/admin/system",
            "/api/v1/admin/audit-logs"
        ]

        for endpoint in admin_endpoints:
            response = await async_test_client.get(endpoint, headers=auth_headers)

            # Should be forbidden for regular users
            assert response.status_code in [403, 401]

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_timing_attack_resistance(self, async_test_client: AsyncClient):
        """Test resistance to timing attacks."""
        import time

        # Test login timing for existing vs non-existing users
        times_existing = []
        times_nonexisting = []

        for _ in range(10):
            # Existing user
            start = time.time()
            await async_test_client.post(
                "/api/v1/auth/login",
                data={"username": "testuser", "password": "wrong"}
            )
            times_existing.append(time.time() - start)

            # Non-existing user
            start = time.time()
            await async_test_client.post(
                "/api/v1/auth/login",
                data={"username": "nonexistent", "password": "wrong"}
            )
            times_nonexisting.append(time.time() - start)

        # Timing should be similar to prevent user enumeration
        avg_existing = sum(times_existing) / len(times_existing)
        avg_nonexisting = sum(times_nonexisting) / len(times_nonexisting)

        # Difference should be minimal (within 50ms)
        assert abs(avg_existing - avg_nonexisting) < 0.05

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_jwt_token_security(self):
        """Test JWT token security implementation."""
        from src.core.security import SecurityManager

        security = SecurityManager()

        # Test token generation
        payload = {"sub": "testuser", "exp": 1234567890}
        token = security.generate_token(payload)

        # Verify token structure
        assert len(token.split('.')) == 3  # Header.Payload.Signature

        # Test token verification
        verified = security.verify_token(token)
        assert verified["sub"] == "testuser"

        # Test tampered token
        tampered_token = token[:-5] + "XXXXX"
        with pytest.raises(Exception):
            security.verify_token(tampered_token)

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_cors_security(self, async_test_client: AsyncClient):
        """Test CORS security configuration."""
        # Test with malicious origin
        response = await async_test_client.options(
            "/api/v1/auth/login",
            headers={
                "Origin": "http://malicious-site.com",
                "Access-Control-Request-Method": "POST"
            }
        )

        # Should not allow malicious origins
        cors_header = response.headers.get("Access-Control-Allow-Origin")
        assert cors_header != "http://malicious-site.com"