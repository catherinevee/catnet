"""
Integration tests for authentication API endpoints.
Tests the complete authentication flow including registration, login, MFA, and token management.
"""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import patch

from fastapi import status
from httpx import AsyncClient


class TestAuthAPI:
    """Test authentication API endpoints."""

    @pytest.fixture
    def valid_registration_data(self):
        """Valid user registration data."""
        return {
            "username": "newuser",
            "email": "newuser@catnet.local",
            "password": "SecurePassword123!",
            "first_name": "New",
            "last_name": "User"
        }

    @pytest.fixture
    def valid_login_data(self, test_user):
        """Valid login credentials."""
        return {
            "username": test_user.username,
            "password": "test_password"
        }

    @pytest.mark.asyncio
    async def test_register_user_success(self, async_test_client: AsyncClient, valid_registration_data):
        """Test successful user registration."""
        response = await async_test_client.post(
            "/api/v1/auth/register",
            json=valid_registration_data
        )

        assert response.status_code == status.HTTP_201_CREATED

        data = response.json()
        assert data["username"] == valid_registration_data["username"]
        assert data["email"] == valid_registration_data["email"]
        assert data["first_name"] == valid_registration_data["first_name"]
        assert data["last_name"] == valid_registration_data["last_name"]
        assert "password" not in data  # Password should not be returned
        assert "id" in data
        assert data["is_active"] is True
        assert data["is_superuser"] is False

    @pytest.mark.asyncio
    async def test_register_user_duplicate_username(
        self,
        async_test_client: AsyncClient,
        valid_registration_data,
        test_user
    ):
        """Test registration with duplicate username."""
        valid_registration_data["username"] = test_user.username

        response = await async_test_client.post(
            "/api/v1/auth/register",
            json=valid_registration_data
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

        data = response.json()
        assert "username" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_register_user_duplicate_email(
        self,
        async_test_client: AsyncClient,
        valid_registration_data,
        test_user
    ):
        """Test registration with duplicate email."""
        valid_registration_data["email"] = test_user.email

        response = await async_test_client.post(
            "/api/v1/auth/register",
            json=valid_registration_data
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

        data = response.json()
        assert "email" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_register_user_weak_password(self, async_test_client: AsyncClient, valid_registration_data):
        """Test registration with weak password."""
        valid_registration_data["password"] = "weak"

        response = await async_test_client.post(
            "/api/v1/auth/register",
            json=valid_registration_data
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

        data = response.json()
        assert "password" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_register_user_invalid_email(self, async_test_client: AsyncClient, valid_registration_data):
        """Test registration with invalid email format."""
        valid_registration_data["email"] = "invalid-email"

        response = await async_test_client.post(
            "/api/v1/auth/register",
            json=valid_registration_data
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_login_success(self, async_test_client: AsyncClient, valid_login_data):
        """Test successful login."""
        response = await async_test_client.post(
            "/api/v1/auth/login",
            data=valid_login_data
        )

        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert "expires_in" in data

    @pytest.mark.asyncio
    async def test_login_invalid_credentials(self, async_test_client: AsyncClient, test_user):
        """Test login with invalid credentials."""
        login_data = {
            "username": test_user.username,
            "password": "wrong_password"
        }

        response = await async_test_client.post(
            "/api/v1/auth/login",
            data=login_data
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        data = response.json()
        assert "invalid credentials" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_login_inactive_user(self, async_test_client: AsyncClient, test_user):
        """Test login with inactive user."""
        test_user.is_active = False

        login_data = {
            "username": test_user.username,
            "password": "test_password"
        }

        response = await async_test_client.post(
            "/api/v1/auth/login",
            data=login_data
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_login_with_mfa_required(self, async_test_client: AsyncClient, test_user):
        """Test login when MFA is required."""
        test_user.mfa_enabled = True

        login_data = {
            "username": test_user.username,
            "password": "test_password"
        }

        response = await async_test_client.post(
            "/api/v1/auth/login",
            data=login_data
        )

        assert response.status_code == status.HTTP_202_ACCEPTED

        data = response.json()
        assert "mfa_required" in data
        assert data["mfa_required"] is True
        assert "mfa_token" in data

    @pytest.mark.asyncio
    async def test_verify_mfa_success(self, async_test_client: AsyncClient, test_user):
        """Test successful MFA verification."""
        test_user.mfa_enabled = True
        test_user.mfa_secret = "JBSWY3DPEHPK3PXP"  # Test secret

        # First login to get MFA token
        login_data = {
            "username": test_user.username,
            "password": "test_password"
        }

        login_response = await async_test_client.post(
            "/api/v1/auth/login",
            data=login_data
        )

        mfa_token = login_response.json()["mfa_token"]

        # Generate valid TOTP code for test
        import pyotp
        totp = pyotp.TOTP(test_user.mfa_secret)
        code = totp.now()

        # Verify MFA
        mfa_data = {
            "mfa_token": mfa_token,
            "code": code
        }

        response = await async_test_client.post(
            "/api/v1/auth/mfa/verify",
            json=mfa_data
        )

        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data

    @pytest.mark.asyncio
    async def test_verify_mfa_invalid_code(self, async_test_client: AsyncClient, test_user):
        """Test MFA verification with invalid code."""
        test_user.mfa_enabled = True

        # First login to get MFA token
        login_data = {
            "username": test_user.username,
            "password": "test_password"
        }

        login_response = await async_test_client.post(
            "/api/v1/auth/login",
            data=login_data
        )

        mfa_token = login_response.json()["mfa_token"]

        # Try with invalid MFA code
        mfa_data = {
            "mfa_token": mfa_token,
            "code": "000000"
        }

        response = await async_test_client.post(
            "/api/v1/auth/mfa/verify",
            json=mfa_data
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_refresh_token_success(self, async_test_client: AsyncClient, valid_login_data):
        """Test successful token refresh."""
        # First login to get refresh token
        login_response = await async_test_client.post(
            "/api/v1/auth/login",
            data=valid_login_data
        )

        refresh_token = login_response.json()["refresh_token"]

        # Use refresh token to get new access token
        refresh_data = {
            "refresh_token": refresh_token
        }

        response = await async_test_client.post(
            "/api/v1/auth/refresh",
            json=refresh_data
        )

        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert "access_token" in data
        assert "expires_in" in data

    @pytest.mark.asyncio
    async def test_refresh_token_invalid(self, async_test_client: AsyncClient):
        """Test token refresh with invalid refresh token."""
        refresh_data = {
            "refresh_token": "invalid_refresh_token"
        }

        response = await async_test_client.post(
            "/api/v1/auth/refresh",
            json=refresh_data
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_logout_success(self, async_test_client: AsyncClient, auth_headers):
        """Test successful logout."""
        response = await async_test_client.post(
            "/api/v1/auth/logout",
            headers=auth_headers
        )

        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["message"] == "Successfully logged out"

    @pytest.mark.asyncio
    async def test_logout_without_auth(self, async_test_client: AsyncClient):
        """Test logout without authentication."""
        response = await async_test_client.post("/api/v1/auth/logout")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_get_current_user(self, async_test_client: AsyncClient, auth_headers, test_user):
        """Test getting current user information."""
        response = await async_test_client.get(
            "/api/v1/auth/me",
            headers=auth_headers
        )

        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["id"] == str(test_user.id)
        assert data["username"] == test_user.username
        assert data["email"] == test_user.email
        assert "password" not in data

    @pytest.mark.asyncio
    async def test_update_profile(self, async_test_client: AsyncClient, auth_headers):
        """Test updating user profile."""
        update_data = {
            "first_name": "Updated",
            "last_name": "Name"
        }

        response = await async_test_client.put(
            "/api/v1/auth/profile",
            json=update_data,
            headers=auth_headers
        )

        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["first_name"] == "Updated"
        assert data["last_name"] == "Name"

    @pytest.mark.asyncio
    async def test_change_password_success(self, async_test_client: AsyncClient, auth_headers):
        """Test successful password change."""
        password_data = {
            "current_password": "test_password",
            "new_password": "NewSecurePassword123!"
        }

        response = await async_test_client.post(
            "/api/v1/auth/change-password",
            json=password_data,
            headers=auth_headers
        )

        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["message"] == "Password changed successfully"

    @pytest.mark.asyncio
    async def test_change_password_invalid_current(self, async_test_client: AsyncClient, auth_headers):
        """Test password change with invalid current password."""
        password_data = {
            "current_password": "wrong_password",
            "new_password": "NewSecurePassword123!"
        }

        response = await async_test_client.post(
            "/api/v1/auth/change-password",
            json=password_data,
            headers=auth_headers
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.asyncio
    async def test_enable_mfa(self, async_test_client: AsyncClient, auth_headers):
        """Test enabling MFA."""
        response = await async_test_client.post(
            "/api/v1/auth/mfa/enable",
            headers=auth_headers
        )

        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert "secret" in data
        assert "qr_code" in data
        assert len(data["secret"]) == 32

    @pytest.mark.asyncio
    async def test_disable_mfa(self, async_test_client: AsyncClient, auth_headers, test_user):
        """Test disabling MFA."""
        test_user.mfa_enabled = True

        response = await async_test_client.post(
            "/api/v1/auth/mfa/disable",
            headers=auth_headers
        )

        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["message"] == "MFA disabled successfully"

    @pytest.mark.asyncio
    async def test_generate_backup_codes(self, async_test_client: AsyncClient, auth_headers, test_user):
        """Test generating backup codes."""
        test_user.mfa_enabled = True

        response = await async_test_client.post(
            "/api/v1/auth/mfa/backup-codes",
            headers=auth_headers
        )

        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert "codes" in data
        assert len(data["codes"]) == 10
        assert all(len(code) == 8 for code in data["codes"])

    @pytest.mark.asyncio
    async def test_get_sessions(self, async_test_client: AsyncClient, auth_headers):
        """Test getting user sessions."""
        response = await async_test_client.get(
            "/api/v1/auth/sessions",
            headers=auth_headers
        )

        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_revoke_session(self, async_test_client: AsyncClient, auth_headers):
        """Test revoking a specific session."""
        # First get sessions
        sessions_response = await async_test_client.get(
            "/api/v1/auth/sessions",
            headers=auth_headers
        )

        sessions = sessions_response.json()
        if sessions:
            session_id = sessions[0]["id"]

            response = await async_test_client.delete(
                f"/api/v1/auth/sessions/{session_id}",
                headers=auth_headers
            )

            assert response.status_code == status.HTTP_200_OK

    @pytest.mark.asyncio
    async def test_revoke_all_sessions(self, async_test_client: AsyncClient, auth_headers):
        """Test revoking all sessions."""
        response = await async_test_client.delete(
            "/api/v1/auth/sessions",
            headers=auth_headers
        )

        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert "revoked" in data["message"].lower()

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_rate_limiting_login(self, async_test_client: AsyncClient, test_user):
        """Test rate limiting on login attempts."""
        login_data = {
            "username": test_user.username,
            "password": "wrong_password"
        }

        # Make multiple failed login attempts
        for _ in range(10):
            response = await async_test_client.post(
                "/api/v1/auth/login",
                data=login_data
            )

        # Should eventually get rate limited
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sql_injection_protection(self, async_test_client: AsyncClient):
        """Test protection against SQL injection in login."""
        malicious_data = {
            "username": "admin'; DROP TABLE users; --",
            "password": "password"
        }

        response = await async_test_client.post(
            "/api/v1/auth/login",
            data=malicious_data
        )

        # Should not cause database error, just invalid credentials
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_xss_protection(self, async_test_client: AsyncClient, valid_registration_data):
        """Test protection against XSS in registration."""
        valid_registration_data["first_name"] = "<script>alert('xss')</script>"

        response = await async_test_client.post(
            "/api/v1/auth/register",
            json=valid_registration_data
        )

        if response.status_code == status.HTTP_201_CREATED:
            data = response.json()
            # Should be sanitized
            assert "<script>" not in data["first_name"]

    @pytest.mark.asyncio
    async def test_concurrent_login_sessions(self, async_test_client: AsyncClient, valid_login_data):
        """Test handling of concurrent login sessions."""
        import asyncio

        # Create multiple concurrent login sessions
        tasks = []
        for _ in range(5):
            task = async_test_client.post("/api/v1/auth/login", data=valid_login_data)
            tasks.append(task)

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        # All should succeed (up to session limit)
        successful_logins = [r for r in responses if not isinstance(r, Exception) and r.status_code == 200]
        assert len(successful_logins) > 0

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_auth_api_performance(self, async_test_client: AsyncClient, valid_login_data):
        """Test authentication API performance."""
        import time

        start_time = time.time()

        # Perform 50 login attempts
        for _ in range(50):
            await async_test_client.post("/api/v1/auth/login", data=valid_login_data)

        end_time = time.time()
        duration = end_time - start_time

        # Should complete 50 requests in reasonable time
        assert duration < 10.0  # Less than 10 seconds