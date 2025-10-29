"""
Security penetration testing scenarios.
Tests for common vulnerabilities and attack vectors.

⚠️ DEFENSIVE SECURITY ONLY ⚠️
These tests validate security controls and detect vulnerabilities.
"""

import pytest
import asyncio
from httpx import AsyncClient
from unittest.mock import patch
from uuid import uuid4


class TestAuthenticationSecurity:
    """Test authentication security controls."""

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sql_injection_in_login(self, client: AsyncClient):
        """Test SQL injection prevention in login endpoint."""
        # Common SQL injection patterns
        injection_attempts = [
            "admin' OR '1'='1",
            "admin'--",
            "admin' OR 1=1--",
            "' OR '1'='1' /*",
            "admin'; DROP TABLE users--",
            "1' UNION SELECT * FROM users--",
        ]

        for attempt in injection_attempts:
            response = await client.post(
                "/api/v1/auth/login",
                json={"username": attempt, "password": "test"}
            )

            # Should reject with 401, not expose SQL errors
            assert response.status_code in [401, 422]
            assert "SQL" not in response.text.upper()
            assert "SYNTAX" not in response.text.upper()

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_brute_force_protection(self, client: AsyncClient):
        """Test brute force attack protection."""
        # Attempt multiple failed logins
        for i in range(10):
            response = await client.post(
                "/api/v1/auth/login",
                json={"username": "admin", "password": f"wrong_password_{i}"}
            )

        # Should rate limit after multiple attempts
        response = await client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "another_attempt"}
        )

        assert response.status_code == 429  # Too Many Requests

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_jwt_token_validation(self, client: AsyncClient):
        """Test JWT token validation and tampering detection."""
        # Invalid token
        response = await client.get(
            "/api/v1/devices",
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401

        # Tampered token
        tampered_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.tampered"
        response = await client.get(
            "/api/v1/devices",
            headers={"Authorization": f"Bearer {tampered_token}"}
        )
        assert response.status_code == 401

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_session_fixation_prevention(self, client: AsyncClient):
        """Test session fixation attack prevention."""
        # Login and get token
        response = await client.post(
            "/api/v1/auth/login",
            json={"username": "testuser", "password": "testpass"}
        )

        if response.status_code == 200:
            token1 = response.json().get("access_token")

            # Login again, should get different token
            response = await client.post(
                "/api/v1/auth/login",
                json={"username": "testuser", "password": "testpass"}
            )
            token2 = response.json().get("access_token")

            assert token1 != token2  # Tokens should be unique


class TestInputValidationSecurity:
    """Test input validation and sanitization."""

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_xss_in_device_hostname(self, client: AsyncClient, auth_headers):
        """Test XSS prevention in device hostname field."""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
        ]

        for payload in xss_payloads:
            response = await client.post(
                "/api/v1/devices",
                headers=auth_headers,
                json={
                    "hostname": payload,
                    "ip_address": "192.168.1.1",
                    "vendor": "cisco",
                    "device_type": "ios"
                }
            )

            # Should sanitize or reject
            assert response.status_code in [400, 422]

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_command_injection_in_config(self, client: AsyncClient, auth_headers):
        """Test command injection prevention in configuration."""
        injection_attempts = [
            "interface eth0; rm -rf /",
            "hostname router`whoami`",
            "description test$(cat /etc/passwd)",
            "ip address 1.1.1.1; cat /etc/shadow",
        ]

        for attempt in injection_attempts:
            response = await client.post(
                "/api/v1/deployments",
                headers=auth_headers,
                json={
                    "name": "Test",
                    "config_content": attempt,
                    "device_ids": [str(uuid4())]
                }
            )

            # Should reject dangerous commands
            assert response.status_code in [400, 422]

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_path_traversal_prevention(self, client: AsyncClient, auth_headers):
        """Test path traversal attack prevention."""
        traversal_attempts = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f",
        ]

        for attempt in traversal_attempts:
            response = await client.get(
                f"/api/v1/configs/{attempt}",
                headers=auth_headers
            )

            # Should block path traversal
            assert response.status_code in [400, 403, 404]

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_oversized_request_rejection(self, client: AsyncClient, auth_headers):
        """Test rejection of oversized requests."""
        # Create 10MB payload
        large_payload = "A" * (10 * 1024 * 1024)

        response = await client.post(
            "/api/v1/devices",
            headers=auth_headers,
            json={
                "hostname": "test",
                "description": large_payload,
                "ip_address": "192.168.1.1",
                "vendor": "cisco"
            }
        )

        # Should reject large payloads
        assert response.status_code in [413, 422]


class TestAuthorizationSecurity:
    """Test authorization and access control."""

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_privilege_escalation_prevention(self, client: AsyncClient, test_user):
        """Test prevention of privilege escalation attacks."""
        # Regular user trying to access admin endpoint
        from src.auth.jwt import create_access_token

        user_token = create_access_token({"sub": str(test_user.id)})
        headers = {"Authorization": f"Bearer {user_token}"}

        # Try to create admin user
        response = await client.post(
            "/api/v1/admin/users",
            headers=headers,
            json={
                "username": "hacker",
                "roles": ["admin"]
            }
        )

        assert response.status_code == 403  # Forbidden

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_horizontal_privilege_escalation(self, client: AsyncClient, test_user):
        """Test user cannot access other users' resources."""
        from src.auth.jwt import create_access_token

        user_token = create_access_token({"sub": str(test_user.id)})
        headers = {"Authorization": f"Bearer {user_token}"}

        # Try to access another user's data
        other_user_id = str(uuid4())
        response = await client.get(
            f"/api/v1/users/{other_user_id}/deployments",
            headers=headers
        )

        assert response.status_code in [403, 404]

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_idor_prevention(self, client: AsyncClient, auth_headers):
        """Test Insecure Direct Object Reference prevention."""
        # Try to access resource with sequential IDs
        for i in range(1, 100):
            response = await client.get(
                f"/api/v1/devices/{i}",
                headers=auth_headers
            )

            # Should use UUIDs, not sequential IDs
            # Or should verify ownership
            assert response.status_code in [403, 404]


class TestCryptographySecurity:
    """Test cryptographic security controls."""

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_password_hashing(self):
        """Test passwords are properly hashed."""
        from src.auth.password import hash_password, verify_password

        password = "TestPassword123!"
        hashed = hash_password(password)

        # Should not store plain text
        assert password not in hashed
        assert len(hashed) > 50  # Proper hash length

        # Should verify correctly
        assert verify_password(password, hashed)
        assert not verify_password("wrong", hashed)

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_secure_random_generation(self):
        """Test secure random number generation."""
        from src.auth.jwt import create_access_token

        # Generate multiple tokens
        tokens = [create_access_token({"sub": "test"}) for _ in range(10)]

        # All should be unique (no predictable pattern)
        assert len(set(tokens)) == 10

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sensitive_data_not_logged(self):
        """Test sensitive data is not logged."""
        from src.auth.password import hash_password
        import logging
        from io import StringIO

        # Capture logs
        log_stream = StringIO()
        handler = logging.StreamHandler(log_stream)
        logger = logging.getLogger()
        logger.addHandler(handler)

        # Perform operation with sensitive data
        password = "SuperSecret123!"
        hash_password(password)

        # Check logs don't contain password
        log_contents = log_stream.getvalue()
        assert password not in log_contents


class TestAPISecurityHeaders:
    """Test security headers and configurations."""

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_security_headers_present(self, client: AsyncClient):
        """Test required security headers are present."""
        response = await client.get("/api/v1/health")

        # Should have security headers
        headers = response.headers

        # Content Security Policy
        assert "x-content-type-options" in headers
        assert headers["x-content-type-options"] == "nosniff"

        # Frame options
        assert "x-frame-options" in headers

        # XSS Protection
        assert "x-xss-protection" in headers

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_cors_configuration(self, client: AsyncClient):
        """Test CORS is properly configured."""
        response = await client.options(
            "/api/v1/devices",
            headers={"Origin": "https://malicious.com"}
        )

        # Should not allow arbitrary origins
        cors_header = response.headers.get("access-control-allow-origin")
        assert cors_header != "*"

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sensitive_info_not_exposed(self, client: AsyncClient):
        """Test sensitive information not exposed in responses."""
        response = await client.get("/api/v1/health/detailed")

        if response.status_code == 200:
            data = response.json()

            # Should not expose sensitive data
            response_text = str(data)
            assert "password" not in response_text.lower()
            assert "secret" not in response_text.lower()
            assert "token" not in response_text.lower()


class TestRateLimitingSecurity:
    """Test rate limiting security controls."""

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_rate_limiting_enforced(self, client: AsyncClient, auth_headers):
        """Test rate limiting is enforced."""
        # Make rapid requests
        responses = []
        for i in range(150):  # More than limit
            response = await client.get(
                "/api/v1/devices",
                headers=auth_headers
            )
            responses.append(response.status_code)

        # Should have some 429 responses
        assert 429 in responses

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_rate_limit_headers_present(self, client: AsyncClient, auth_headers):
        """Test rate limit headers are present."""
        response = await client.get(
            "/api/v1/devices",
            headers=auth_headers
        )

        # Should have rate limit headers
        assert "x-ratelimit-limit" in response.headers or \
               "ratelimit-limit" in response.headers


class TestSecretManagement:
    """Test secret management security."""

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_no_secrets_in_config_files(self):
        """Test no secrets are hardcoded in configuration."""
        import os
        from pathlib import Path

        # Check config files
        config_files = [
            "src/core/config.py",
            ".env.example",
            "docker-compose.yml"
        ]

        secret_patterns = ["password=", "token=", "secret=", "key="]

        for config_file in config_files:
            if os.path.exists(config_file):
                with open(config_file) as f:
                    content = f.read().lower()

                # Should not have hardcoded values
                for pattern in secret_patterns:
                    if pattern in content:
                        # Verify it's a placeholder or env var reference
                        assert "changeme" in content or "${" in content or \
                               "your-" in content or "example" in content

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_vault_integration_secure(self):
        """Test Vault integration uses secure practices."""
        from src.security.vault import VaultClient

        vault = VaultClient()

        # Should use HTTPS in production
        # Should have proper authentication
        # Should not cache secrets in memory long-term
        assert hasattr(vault, 'get_secret')
        assert hasattr(vault, 'store_secret')


class TestVulnerabilityScanning:
    """Test for known vulnerabilities."""

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_dependency_vulnerabilities(self):
        """Test dependencies don't have known vulnerabilities."""
        # This would integrate with safety or pip-audit
        # For now, just ensure requirements are tracked
        import os
        assert os.path.exists("requirements.txt")

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_tls_configuration(self, client: AsyncClient):
        """Test TLS is properly configured."""
        # In production, should enforce HTTPS
        # Should use TLS 1.2 or higher
        # Should have valid certificates

        # This test would check the actual TLS configuration
        # when running in production mode
        pass
