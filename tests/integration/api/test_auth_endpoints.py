"""
Integration tests for Authentication API endpoints
Tests full request-response cycles for auth operations
"""

import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch, Mock
import json
from datetime import datetime, timedelta

from src.api.app import app
from src.db.models import User, Role


@pytest.fixture
def mock_auth_service():
    """Mock authentication service."""
    with patch('src.api.routes.auth.auth_service') as mock:
        yield mock


@pytest.fixture
def mock_mfa_service():
    """Mock MFA service."""
    with patch('src.api.routes.auth.mfa_service') as mock:
        yield mock


@pytest.fixture
def mock_audit():
    """Mock audit logger."""
    with patch('src.api.routes.auth.audit') as mock:
        yield mock


@pytest.fixture
async def client():
    """Async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def sample_user():
    """Sample user data."""
    return {
        'id': 'user_123',
        'email': 'test@example.com',
        'first_name': 'Test',
        'last_name': 'User',
        'roles': ['viewer'],
        'permissions': ['deployment.view', 'device.view'],
        'mfa_enabled': False
    }


@pytest.fixture
def valid_tokens():
    """Valid authentication tokens."""
    return {
        'access_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        'refresh_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        'expires_in': 3600
    }


class TestLoginEndpoint:
    """Test /api/auth/login endpoint."""

    @pytest.mark.asyncio
    async def test_login_success(self, client, mock_auth_service, mock_audit, sample_user, valid_tokens):
        """Test successful login without MFA."""
        # Mock authentication
        mock_auth_service.authenticate_user.return_value = {
            'success': True,
            'user': sample_user
        }
        mock_auth_service.create_tokens.return_value = valid_tokens
        mock_audit.log_authentication_success = AsyncMock()

        # Make request
        response = await client.post("/api/auth/login", json={
            "email": "test@example.com",
            "password": "SecurePassword123!",
            "remember_me": False
        })

        # Assertions
        assert response.status_code == 200
        data = response.json()
        assert data['access_token'] == valid_tokens['access_token']
        assert data['refresh_token'] == valid_tokens['refresh_token']
        assert data['token_type'] == 'bearer'
        assert data['user']['email'] == 'test@example.com'
        assert data['mfa_required'] is False

    @pytest.mark.asyncio
    async def test_login_mfa_required(self, client, mock_auth_service, mock_audit, sample_user):
        """Test login requiring MFA code."""
        sample_user['mfa_enabled'] = True

        mock_auth_service.authenticate_user.return_value = {
            'success': True,
            'user': sample_user
        }
        mock_audit.log_authentication_event = AsyncMock()

        response = await client.post("/api/auth/login", json={
            "email": "test@example.com",
            "password": "SecurePassword123!"
        })

        assert response.status_code == 200
        data = response.json()
        assert data['mfa_required'] is True
        assert data['access_token'] == ""

    @pytest.mark.asyncio
    async def test_login_with_valid_mfa(self, client, mock_auth_service, mock_mfa_service,
                                        mock_audit, sample_user, valid_tokens):
        """Test login with valid MFA code."""
        sample_user['mfa_enabled'] = True

        mock_auth_service.authenticate_user.return_value = {
            'success': True,
            'user': sample_user
        }
        mock_mfa_service.verify_totp.return_value = True
        mock_auth_service.create_tokens.return_value = valid_tokens
        mock_audit.log_authentication_success = AsyncMock()

        response = await client.post("/api/auth/login", json={
            "email": "test@example.com",
            "password": "SecurePassword123!",
            "mfa_code": "123456"
        })

        assert response.status_code == 200
        data = response.json()
        assert data['access_token'] == valid_tokens['access_token']
        assert data['mfa_required'] is False

    @pytest.mark.asyncio
    async def test_login_invalid_credentials(self, client, mock_auth_service, mock_audit):
        """Test login with invalid credentials."""
        mock_auth_service.authenticate_user.return_value = {
            'success': False,
            'reason': 'invalid_credentials',
            'message': 'Invalid email or password'
        }
        mock_audit.log_authentication_failure = AsyncMock()

        response = await client.post("/api/auth/login", json={
            "email": "test@example.com",
            "password": "wrongpassword"
        })

        assert response.status_code == 401
        assert "authentication failed" in response.json()['detail'].lower()

    @pytest.mark.asyncio
    async def test_login_invalid_mfa_code(self, client, mock_auth_service, mock_mfa_service,
                                          mock_audit, sample_user):
        """Test login with invalid MFA code."""
        sample_user['mfa_enabled'] = True

        mock_auth_service.authenticate_user.return_value = {
            'success': True,
            'user': sample_user
        }
        mock_mfa_service.verify_totp.return_value = False
        mock_audit.log_authentication_failure = AsyncMock()

        response = await client.post("/api/auth/login", json={
            "email": "test@example.com",
            "password": "SecurePassword123!",
            "mfa_code": "000000"
        })

        assert response.status_code == 401
        assert "invalid mfa code" in response.json()['detail'].lower()

    @pytest.mark.asyncio
    async def test_login_missing_email(self, client):
        """Test login with missing email."""
        response = await client.post("/api/auth/login", json={
            "password": "SecurePassword123!"
        })

        assert response.status_code == 422  # Validation error

    @pytest.mark.asyncio
    async def test_login_invalid_email_format(self, client):
        """Test login with invalid email format."""
        response = await client.post("/api/auth/login", json={
            "email": "not-an-email",
            "password": "SecurePassword123!"
        })

        assert response.status_code == 422


class TestRegisterEndpoint:
    """Test /api/auth/register endpoint."""

    @pytest.mark.asyncio
    async def test_register_success(self, client, mock_auth_service, mock_audit, sample_user, valid_tokens):
        """Test successful user registration."""
        mock_auth_service.register_user.return_value = {
            'success': True,
            'user': sample_user
        }
        mock_auth_service.create_tokens.return_value = valid_tokens
        mock_audit.log_registration_success = AsyncMock()

        response = await client.post("/api/auth/register", json={
            "email": "newuser@example.com",
            "password": "SecurePassword123!",
            "confirm_password": "SecurePassword123!",
            "first_name": "New",
            "last_name": "User",
            "organization": "Test Org"
        })

        assert response.status_code == 200
        data = response.json()
        assert data['access_token'] == valid_tokens['access_token']
        assert data['mfa_setup_required'] is True

    @pytest.mark.asyncio
    async def test_register_password_mismatch(self, client):
        """Test registration with mismatched passwords."""
        response = await client.post("/api/auth/register", json={
            "email": "newuser@example.com",
            "password": "SecurePassword123!",
            "confirm_password": "DifferentPassword456!",
            "first_name": "New",
            "last_name": "User"
        })

        assert response.status_code == 422
        assert "passwords do not match" in str(response.json()).lower()

    @pytest.mark.asyncio
    async def test_register_weak_password(self, client):
        """Test registration with weak password."""
        response = await client.post("/api/auth/register", json={
            "email": "newuser@example.com",
            "password": "weak",
            "confirm_password": "weak",
            "first_name": "New",
            "last_name": "User"
        })

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_register_duplicate_email(self, client, mock_auth_service, mock_audit):
        """Test registration with existing email."""
        mock_auth_service.register_user.return_value = {
            'success': False,
            'reason': 'email_exists',
            'message': 'Email already registered'
        }
        mock_audit.log_registration_failure = AsyncMock()

        response = await client.post("/api/auth/register", json={
            "email": "existing@example.com",
            "password": "SecurePassword123!",
            "confirm_password": "SecurePassword123!",
            "first_name": "Existing",
            "last_name": "User"
        })

        assert response.status_code == 400


class TestTokenRefreshEndpoint:
    """Test /api/auth/refresh endpoint."""

    @pytest.mark.asyncio
    async def test_refresh_token_success(self, client, mock_auth_service, mock_audit,
                                         sample_user, valid_tokens):
        """Test successful token refresh."""
        mock_auth_service.refresh_tokens.return_value = {
            'success': True,
            'user': sample_user,
            'tokens': valid_tokens
        }
        mock_audit.log_token_refresh_success = AsyncMock()

        response = await client.post("/api/auth/refresh", json={
            "refresh_token": "valid_refresh_token"
        })

        assert response.status_code == 200
        data = response.json()
        assert data['access_token'] == valid_tokens['access_token']

    @pytest.mark.asyncio
    async def test_refresh_token_invalid(self, client, mock_auth_service, mock_audit):
        """Test refresh with invalid token."""
        mock_auth_service.refresh_tokens.return_value = {
            'success': False,
            'reason': 'invalid_token',
            'message': 'Invalid or expired refresh token'
        }
        mock_audit.log_token_refresh_failure = AsyncMock()

        response = await client.post("/api/auth/refresh", json={
            "refresh_token": "invalid_token"
        })

        assert response.status_code == 401


class TestLogoutEndpoint:
    """Test /api/auth/logout endpoint."""

    @pytest.mark.asyncio
    async def test_logout_success(self, client, mock_auth_service, mock_audit):
        """Test successful logout."""
        mock_auth_service.verify_token.return_value = {'sub': 'user_123', 'email': 'test@example.com'}
        mock_auth_service.logout_user = AsyncMock()
        mock_audit.log_logout = AsyncMock()

        response = await client.post(
            "/api/auth/logout",
            headers={"Authorization": "Bearer valid_token"}
        )

        assert response.status_code == 200
        assert "successfully logged out" in response.json()['message'].lower()

    @pytest.mark.asyncio
    async def test_logout_no_token(self, client):
        """Test logout without authentication token."""
        response = await client.post("/api/auth/logout")

        assert response.status_code == 403


class TestMFAEndpoints:
    """Test MFA management endpoints."""

    @pytest.mark.asyncio
    async def test_mfa_setup_success(self, client, mock_auth_service, mock_mfa_service, mock_audit):
        """Test successful MFA setup."""
        mock_auth_service.verify_token.return_value = {
            'sub': 'user_123',
            'email': 'test@example.com'
        }
        mock_auth_service.verify_password.return_value = True
        mock_mfa_service.setup_mfa.return_value = {
            'secret': 'ABCDEFGH12345678',
            'qr_code': 'data:image/png;base64,iVBORw0KGgo...',
            'backup_codes': ['12345678', '87654321']
        }
        mock_audit.log_mfa_setup_initiated = AsyncMock()

        response = await client.post(
            "/api/auth/mfa/setup",
            headers={"Authorization": "Bearer valid_token"},
            json={"password": "CurrentPassword123!"}
        )

        assert response.status_code == 200
        data = response.json()
        assert 'secret' in data
        assert 'qr_code' in data
        assert 'backup_codes' in data
        assert len(data['backup_codes']) > 0

    @pytest.mark.asyncio
    async def test_mfa_setup_wrong_password(self, client, mock_auth_service, mock_audit):
        """Test MFA setup with wrong password."""
        mock_auth_service.verify_token.return_value = {
            'sub': 'user_123',
            'email': 'test@example.com'
        }
        mock_auth_service.verify_password.return_value = False
        mock_audit.log_mfa_setup_failure = AsyncMock()

        response = await client.post(
            "/api/auth/mfa/setup",
            headers={"Authorization": "Bearer valid_token"},
            json={"password": "WrongPassword"}
        )

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_mfa_verify_success(self, client, mock_auth_service, mock_mfa_service, mock_audit):
        """Test successful MFA verification."""
        mock_auth_service.verify_token.return_value = {
            'sub': 'user_123',
            'email': 'test@example.com'
        }
        mock_mfa_service.verify_and_enable_mfa.return_value = {
            'success': True
        }
        mock_audit.log_mfa_enabled = AsyncMock()

        response = await client.post(
            "/api/auth/mfa/verify",
            headers={"Authorization": "Bearer valid_token"},
            json={"code": "123456"}
        )

        assert response.status_code == 200
        assert "successfully enabled" in response.json()['message'].lower()

    @pytest.mark.asyncio
    async def test_mfa_verify_invalid_code(self, client, mock_auth_service, mock_mfa_service, mock_audit):
        """Test MFA verification with invalid code."""
        mock_auth_service.verify_token.return_value = {
            'sub': 'user_123',
            'email': 'test@example.com'
        }
        mock_mfa_service.verify_and_enable_mfa.return_value = {
            'success': False,
            'reason': 'invalid_code',
            'message': 'Invalid MFA code'
        }
        mock_audit.log_mfa_verification_failure = AsyncMock()

        response = await client.post(
            "/api/auth/mfa/verify",
            headers={"Authorization": "Bearer valid_token"},
            json={"code": "000000"}
        )

        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_mfa_disable_success(self, client, mock_auth_service, mock_mfa_service, mock_audit):
        """Test successful MFA disable."""
        mock_auth_service.verify_token.return_value = {
            'sub': 'user_123',
            'email': 'test@example.com'
        }
        mock_auth_service.verify_password.return_value = True
        mock_mfa_service.disable_mfa = AsyncMock()
        mock_audit.log_mfa_disabled = AsyncMock()

        response = await client.delete(
            "/api/auth/mfa",
            headers={"Authorization": "Bearer valid_token"},
            json={"password": "CurrentPassword123!"}
        )

        assert response.status_code == 200
        assert "successfully disabled" in response.json()['message'].lower()


class TestPasswordManagement:
    """Test password management endpoints."""

    @pytest.mark.asyncio
    async def test_change_password_success(self, client, mock_auth_service, mock_audit):
        """Test successful password change."""
        mock_auth_service.verify_token.return_value = {
            'sub': 'user_123',
            'email': 'test@example.com'
        }
        mock_auth_service.change_password.return_value = {
            'success': True
        }
        mock_audit.log_password_changed = AsyncMock()

        response = await client.post(
            "/api/auth/password/change",
            headers={"Authorization": "Bearer valid_token"},
            json={
                "current_password": "OldPassword123!",
                "new_password": "NewPassword456!",
                "confirm_password": "NewPassword456!"
            }
        )

        assert response.status_code == 200
        assert "successfully changed" in response.json()['message'].lower()

    @pytest.mark.asyncio
    async def test_change_password_wrong_current(self, client, mock_auth_service, mock_audit):
        """Test password change with wrong current password."""
        mock_auth_service.verify_token.return_value = {
            'sub': 'user_123',
            'email': 'test@example.com'
        }
        mock_auth_service.change_password.return_value = {
            'success': False,
            'reason': 'invalid_current_password',
            'message': 'Current password is incorrect'
        }
        mock_audit.log_password_change_failure = AsyncMock()

        response = await client.post(
            "/api/auth/password/change",
            headers={"Authorization": "Bearer valid_token"},
            json={
                "current_password": "WrongPassword",
                "new_password": "NewPassword456!",
                "confirm_password": "NewPassword456!"
            }
        )

        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_change_password_mismatch(self, client):
        """Test password change with mismatched new passwords."""
        response = await client.post(
            "/api/auth/password/change",
            headers={"Authorization": "Bearer valid_token"},
            json={
                "current_password": "OldPassword123!",
                "new_password": "NewPassword456!",
                "confirm_password": "DifferentPassword789!"
            }
        )

        assert response.status_code == 422


class TestUserProfile:
    """Test user profile endpoints."""

    @pytest.mark.asyncio
    async def test_get_profile_success(self, client, mock_auth_service, sample_user):
        """Test successful profile retrieval."""
        mock_auth_service.verify_token.return_value = {
            'sub': 'user_123',
            'email': 'test@example.com'
        }

        profile_data = {
            **sample_user,
            'organization': 'Test Org',
            'last_login': datetime.utcnow().isoformat(),
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat()
        }
        mock_auth_service.get_user_profile.return_value = profile_data

        response = await client.get(
            "/api/auth/me",
            headers={"Authorization": "Bearer valid_token"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data['email'] == 'test@example.com'
        assert 'roles' in data
        assert 'permissions' in data

    @pytest.mark.asyncio
    async def test_get_sessions(self, client, mock_auth_service):
        """Test get user sessions."""
        mock_auth_service.verify_token.return_value = {
            'sub': 'user_123',
            'email': 'test@example.com'
        }
        mock_auth_service.get_user_sessions.return_value = [
            {
                'session_id': 'session_1',
                'created_at': datetime.utcnow().isoformat(),
                'last_activity': datetime.utcnow().isoformat(),
                'ip_address': '192.168.1.100',
                'user_agent': 'Mozilla/5.0'
            }
        ]

        response = await client.get(
            "/api/auth/sessions",
            headers={"Authorization": "Bearer valid_token"}
        )

        assert response.status_code == 200
        data = response.json()
        assert 'sessions' in data
        assert len(data['sessions']) > 0

    @pytest.mark.asyncio
    async def test_revoke_session(self, client, mock_auth_service, mock_audit):
        """Test session revocation."""
        mock_auth_service.verify_token.return_value = {
            'sub': 'user_123',
            'email': 'test@example.com'
        }
        mock_auth_service.revoke_session.return_value = {
            'success': True
        }
        mock_audit.log_session_revoked = AsyncMock()

        response = await client.delete(
            "/api/auth/sessions/session_1",
            headers={"Authorization": "Bearer valid_token"}
        )

        assert response.status_code == 200
        assert "successfully revoked" in response.json()['message'].lower()
