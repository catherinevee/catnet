"""
Unit tests for authentication service.
Tests OAuth2, JWT tokens, MFA, and user management functionality.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch
import uuid
import pyotp

from src.auth.service import AuthService
from src.auth.models import User, UserSession
from src.core.exceptions import AuthenticationError, AuthorizationError
from src.core.security import SecurityManager


class TestAuthService:
    """Test authentication service functionality."""

    @pytest.fixture
    def mock_vault(self):
        """Mock Vault client."""
        vault = Mock()
        vault.get_secret = AsyncMock(return_value={"value": "test_secret"})
        vault.store_secret = AsyncMock(return_value=True)
        return vault

    @pytest.fixture
    def mock_security_manager(self):
        """Mock security manager."""
        security = Mock(spec=SecurityManager)
        security.hash_password = Mock(return_value="hashed_password")
        security.verify_password = Mock(return_value=True)
        security.generate_token = Mock(return_value="test_token")
        security.verify_token = Mock(return_value={"sub": "testuser", "exp": datetime.utcnow().timestamp() + 3600})
        return security

    @pytest.fixture
    def auth_service(self, test_session, mock_vault, mock_security_manager):
        """Create auth service instance."""
        service = AuthService(
            session=test_session,
            vault=mock_vault,
            security=mock_security_manager
        )
        return service

    @pytest.fixture
    def valid_user_data(self):
        """Valid user registration data."""
        return {
            "username": "testuser",
            "email": "test@catnet.local",
            "password": "SecurePassword123!",
            "first_name": "Test",
            "last_name": "User"
        }

    @pytest.mark.asyncio
    async def test_register_user_success(self, auth_service, valid_user_data):
        """Test successful user registration."""
        user = await auth_service.register_user(valid_user_data)

        assert user.username == valid_user_data["username"]
        assert user.email == valid_user_data["email"]
        assert user.first_name == valid_user_data["first_name"]
        assert user.last_name == valid_user_data["last_name"]
        assert user.is_active is True
        assert user.is_superuser is False
        assert user.password_hash == "hashed_password"

    @pytest.mark.asyncio
    async def test_register_user_duplicate_username(self, auth_service, valid_user_data, test_user):
        """Test registration with duplicate username."""
        valid_user_data["username"] = test_user.username

        with pytest.raises(AuthenticationError) as exc_info:
            await auth_service.register_user(valid_user_data)

        assert "username already exists" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_register_user_duplicate_email(self, auth_service, valid_user_data, test_user):
        """Test registration with duplicate email."""
        valid_user_data["email"] = test_user.email

        with pytest.raises(AuthenticationError) as exc_info:
            await auth_service.register_user(valid_user_data)

        assert "email already exists" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_authenticate_user_success(self, auth_service, test_user):
        """Test successful user authentication."""
        result = await auth_service.authenticate_user(
            test_user.username,
            "test_password"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_authenticate_user_invalid_password(self, auth_service, test_user, mock_security_manager):
        """Test authentication with invalid password."""
        mock_security_manager.verify_password.return_value = False

        result = await auth_service.authenticate_user(
            test_user.username,
            "wrong_password"
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_authenticate_user_not_found(self, auth_service):
        """Test authentication with non-existent user."""
        result = await auth_service.authenticate_user(
            "nonexistent",
            "password"
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_authenticate_user_inactive(self, auth_service, test_user):
        """Test authentication with inactive user."""
        test_user.is_active = False

        result = await auth_service.authenticate_user(
            test_user.username,
            "test_password"
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_create_access_token(self, auth_service, test_user):
        """Test access token creation."""
        token = await auth_service.create_access_token(test_user)

        assert token == "test_token"

    @pytest.mark.asyncio
    async def test_create_refresh_token(self, auth_service, test_user):
        """Test refresh token creation and storage."""
        token = await auth_service.create_refresh_token(test_user, "192.168.1.1", "test-agent")

        assert isinstance(token, str)
        assert len(token) > 0

    @pytest.mark.asyncio
    async def test_verify_token_valid(self, auth_service):
        """Test verification of valid token."""
        payload = await auth_service.verify_token("test_token")

        assert payload["sub"] == "testuser"
        assert "exp" in payload

    @pytest.mark.asyncio
    async def test_verify_token_invalid(self, auth_service, mock_security_manager):
        """Test verification of invalid token."""
        mock_security_manager.verify_token.side_effect = Exception("Invalid token")

        with pytest.raises(AuthenticationError):
            await auth_service.verify_token("invalid_token")

    @pytest.mark.asyncio
    async def test_verify_token_expired(self, auth_service, mock_security_manager):
        """Test verification of expired token."""
        expired_payload = {
            "sub": "testuser",
            "exp": datetime.utcnow().timestamp() - 3600  # Expired 1 hour ago
        }
        mock_security_manager.verify_token.return_value = expired_payload

        with pytest.raises(AuthenticationError) as exc_info:
            await auth_service.verify_token("expired_token")

        assert "token has expired" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_refresh_access_token_success(self, auth_service, test_user):
        """Test successful token refresh."""
        # Create refresh token first
        refresh_token = await auth_service.create_refresh_token(
            test_user, "192.168.1.1", "test-agent"
        )

        new_token = await auth_service.refresh_access_token(refresh_token)

        assert new_token == "test_token"

    @pytest.mark.asyncio
    async def test_refresh_access_token_invalid(self, auth_service):
        """Test token refresh with invalid refresh token."""
        with pytest.raises(AuthenticationError):
            await auth_service.refresh_access_token("invalid_refresh_token")

    @pytest.mark.asyncio
    async def test_enable_mfa(self, auth_service, test_user):
        """Test MFA enablement."""
        secret, qr_code = await auth_service.enable_mfa(test_user)

        assert isinstance(secret, str)
        assert len(secret) == 32  # TOTP secret length
        assert isinstance(qr_code, str)
        assert test_user.mfa_enabled is True
        assert test_user.mfa_secret == secret

    @pytest.mark.asyncio
    async def test_verify_mfa_success(self, auth_service, test_user):
        """Test successful MFA verification."""
        # Set up MFA secret
        secret = pyotp.random_base32()
        test_user.mfa_secret = secret
        test_user.mfa_enabled = True

        # Generate valid TOTP code
        totp = pyotp.TOTP(secret)
        code = totp.now()

        result = await auth_service.verify_mfa(test_user, code)

        assert result is True

    @pytest.mark.asyncio
    async def test_verify_mfa_invalid_code(self, auth_service, test_user):
        """Test MFA verification with invalid code."""
        test_user.mfa_secret = pyotp.random_base32()
        test_user.mfa_enabled = True

        result = await auth_service.verify_mfa(test_user, "000000")

        assert result is False

    @pytest.mark.asyncio
    async def test_verify_mfa_not_enabled(self, auth_service, test_user):
        """Test MFA verification when MFA is not enabled."""
        test_user.mfa_enabled = False

        with pytest.raises(AuthenticationError) as exc_info:
            await auth_service.verify_mfa(test_user, "123456")

        assert "mfa not enabled" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_disable_mfa(self, auth_service, test_user):
        """Test MFA disabling."""
        test_user.mfa_enabled = True
        test_user.mfa_secret = "test_secret"

        await auth_service.disable_mfa(test_user)

        assert test_user.mfa_enabled is False
        assert test_user.mfa_secret is None

    @pytest.mark.asyncio
    async def test_generate_backup_codes(self, auth_service, test_user):
        """Test backup codes generation."""
        codes = await auth_service.generate_backup_codes(test_user)

        assert len(codes) == 10  # Default number of backup codes
        assert all(len(code) == 8 for code in codes)  # 8-character codes

    @pytest.mark.asyncio
    async def test_verify_backup_code_success(self, auth_service, test_user):
        """Test successful backup code verification."""
        # Generate backup codes first
        codes = await auth_service.generate_backup_codes(test_user)

        result = await auth_service.verify_backup_code(test_user, codes[0])

        assert result is True

    @pytest.mark.asyncio
    async def test_verify_backup_code_already_used(self, auth_service, test_user):
        """Test backup code verification when code already used."""
        codes = await auth_service.generate_backup_codes(test_user)

        # Use the code once
        await auth_service.verify_backup_code(test_user, codes[0])

        # Try to use again
        result = await auth_service.verify_backup_code(test_user, codes[0])

        assert result is False

    @pytest.mark.asyncio
    async def test_get_user_by_username(self, auth_service, test_user):
        """Test getting user by username."""
        user = await auth_service.get_user_by_username(test_user.username)

        assert user.id == test_user.id
        assert user.username == test_user.username

    @pytest.mark.asyncio
    async def test_get_user_by_email(self, auth_service, test_user):
        """Test getting user by email."""
        user = await auth_service.get_user_by_email(test_user.email)

        assert user.id == test_user.id
        assert user.email == test_user.email

    @pytest.mark.asyncio
    async def test_update_user_profile(self, auth_service, test_user):
        """Test updating user profile."""
        update_data = {
            "first_name": "Updated",
            "last_name": "Name"
        }

        updated_user = await auth_service.update_user_profile(test_user, update_data)

        assert updated_user.first_name == "Updated"
        assert updated_user.last_name == "Name"

    @pytest.mark.asyncio
    async def test_change_password_success(self, auth_service, test_user, mock_security_manager):
        """Test successful password change."""
        mock_security_manager.verify_password.return_value = True

        await auth_service.change_password(
            test_user,
            "old_password",
            "NewSecurePassword123!"
        )

        # Verify password was hashed and updated
        mock_security_manager.hash_password.assert_called_with("NewSecurePassword123!")

    @pytest.mark.asyncio
    async def test_change_password_invalid_old(self, auth_service, test_user, mock_security_manager):
        """Test password change with invalid old password."""
        mock_security_manager.verify_password.return_value = False

        with pytest.raises(AuthenticationError) as exc_info:
            await auth_service.change_password(
                test_user,
                "wrong_old_password",
                "NewSecurePassword123!"
            )

        assert "current password is incorrect" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_deactivate_user(self, auth_service, test_user):
        """Test user deactivation."""
        await auth_service.deactivate_user(test_user)

        assert test_user.is_active is False

    @pytest.mark.asyncio
    async def test_activate_user(self, auth_service, test_user):
        """Test user activation."""
        test_user.is_active = False

        await auth_service.activate_user(test_user)

        assert test_user.is_active is True

    @pytest.mark.asyncio
    async def test_login_attempt_tracking(self, auth_service, test_user, mock_security_manager):
        """Test login attempt tracking for failed logins."""
        mock_security_manager.verify_password.return_value = False

        # Make several failed attempts
        for _ in range(3):
            await auth_service.authenticate_user(test_user.username, "wrong_password")

        assert test_user.failed_login_attempts == 3

    @pytest.mark.asyncio
    async def test_account_lockout(self, auth_service, test_user, mock_security_manager):
        """Test account lockout after too many failed attempts."""
        mock_security_manager.verify_password.return_value = False

        # Make too many failed attempts
        for _ in range(6):  # Assuming 5 is the limit
            await auth_service.authenticate_user(test_user.username, "wrong_password")

        # Account should be locked
        assert test_user.locked_until is not None
        assert test_user.locked_until > datetime.utcnow()

    @pytest.mark.asyncio
    async def test_session_cleanup(self, auth_service, test_user):
        """Test cleaning up expired sessions."""
        # Create expired session
        expired_session = UserSession(
            user_id=test_user.id,
            session_token="expired_token",
            expires_at=datetime.utcnow() - timedelta(hours=1)
        )

        auth_service.session.add(expired_session)
        await auth_service.session.commit()

        # Clean up expired sessions
        await auth_service.cleanup_expired_sessions()

        # Session should be removed
        remaining_sessions = await auth_service.session.execute(
            "SELECT COUNT(*) FROM user_sessions WHERE session_token = 'expired_token'"
        )
        assert remaining_sessions.scalar() == 0

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_password_security_requirements(self, auth_service):
        """Test password security requirements."""
        weak_passwords = [
            "123456",
            "password",
            "abc123",
            "short",
            "NoNumbers!",
            "nonumbers123",
            "NOCAPITALS123!",
            "NoSpecialChars123"
        ]

        for weak_password in weak_passwords:
            user_data = {
                "username": f"user_{weak_password}",
                "email": f"user_{weak_password}@test.com",
                "password": weak_password,
                "first_name": "Test",
                "last_name": "User"
            }

            with pytest.raises(AuthenticationError) as exc_info:
                await auth_service.register_user(user_data)

            assert "password" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_concurrent_login_limit(self, auth_service, test_user):
        """Test concurrent login session limit."""
        # Create multiple sessions for the same user
        for i in range(10):
            await auth_service.create_refresh_token(
                test_user,
                f"192.168.1.{i}",
                f"client-{i}"
            )

        # Should enforce maximum concurrent sessions
        active_sessions = await auth_service.get_active_sessions(test_user)
        assert len(active_sessions) <= 5  # Assuming max 5 concurrent sessions

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_auth_performance(self, auth_service, test_user):
        """Test authentication performance."""
        import time

        start_time = time.time()

        # Perform 100 authentication attempts
        for _ in range(100):
            await auth_service.authenticate_user(test_user.username, "test_password")

        end_time = time.time()
        duration = end_time - start_time

        # Should complete 100 authentications in reasonable time
        assert duration < 2.0  # Less than 2 seconds