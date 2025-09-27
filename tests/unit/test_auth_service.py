"""
Unit Tests for Authentication Service

Tests authentication, authorization, JWT handling, and MFA
"""

import pytest
import uuid
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch
import pyotp

from src.auth.auth_service import auth_service
from src.auth.jwt_handler import JWTHandler
from src.auth.permissions import Permission, check_permission
from src.db.models import User, UserRole


class TestAuthService:
    """Test authentication service"""

    def test_password_hashing(self):
        """Test password hashing and verification"""
        password = "SecurePassword123!"

        # Hash password
        hashed = auth_service.get_password_hash(password)
        assert hashed != password
        assert len(hashed) > 50  # Bcrypt hash length

        # Verify correct password
        assert auth_service.verify_password(password, hashed) is True

        # Verify incorrect password
        assert auth_service.verify_password("WrongPassword", hashed) is False

    def test_password_complexity_validation(self):
        """Test password complexity requirements"""
        # Valid passwords
        assert auth_service.validate_password_complexity("SecurePass123!") is True
        assert auth_service.validate_password_complexity("Complex@Pass9") is True

        # Invalid passwords
        assert auth_service.validate_password_complexity("short") is False  # Too short
        assert auth_service.validate_password_complexity("NoNumbers!") is False  # No digits
        assert auth_service.validate_password_complexity("NoSpecial123") is False  # No special chars
        assert auth_service.validate_password_complexity("nouppercase123!") is False  # No uppercase
        assert auth_service.validate_password_complexity("NOLOWERCASE123!") is False  # No lowercase

    @pytest.mark.asyncio
    async def test_authenticate_user(self, test_db_session, test_user):
        """Test user authentication"""
        # Mock the database query
        with patch.object(auth_service, 'get_user_by_username', new_callable=AsyncMock) as mock_get_user:
            mock_get_user.return_value = test_user

            # Test successful authentication
            user = await auth_service.authenticate_user(
                test_db_session,
                "testuser",
                "TestPassword123!"
            )
            assert user is not None
            assert user.username == "testuser"

            # Test failed authentication - wrong password
            user = await auth_service.authenticate_user(
                test_db_session,
                "testuser",
                "WrongPassword"
            )
            assert user is None

            # Test failed authentication - user not found
            mock_get_user.return_value = None
            user = await auth_service.authenticate_user(
                test_db_session,
                "nonexistent",
                "TestPassword123!"
            )
            assert user is None

    def test_generate_mfa_secret(self):
        """Test MFA secret generation"""
        secret = auth_service.generate_mfa_secret()

        assert secret is not None
        assert len(secret) == 32  # Base32 encoded secret length
        assert secret.isupper()  # Base32 uses uppercase

        # Verify it's a valid TOTP secret
        totp = pyotp.TOTP(secret)
        code = totp.now()
        assert len(code) == 6
        assert code.isdigit()

    def test_verify_mfa_code(self):
        """Test MFA code verification"""
        secret = auth_service.generate_mfa_secret()
        totp = pyotp.TOTP(secret)

        # Test valid code
        valid_code = totp.now()
        assert auth_service.verify_mfa_code(secret, valid_code) is True

        # Test invalid code
        assert auth_service.verify_mfa_code(secret, "000000") is False
        assert auth_service.verify_mfa_code(secret, "invalid") is False

    def test_generate_qr_code(self):
        """Test QR code generation for MFA"""
        secret = auth_service.generate_mfa_secret()
        username = "testuser"

        qr_code = auth_service.generate_qr_code(username, secret)

        assert qr_code is not None
        assert qr_code.startswith("data:image/png;base64,")
        assert len(qr_code) > 100  # Should contain actual image data


class TestJWTHandler:
    """Test JWT token handling"""

    def setup_method(self):
        """Setup JWT handler for tests"""
        self.jwt_handler = JWTHandler(
            secret_key="test-secret-key",
            algorithm="HS256",
            access_token_expire_minutes=30,
            refresh_token_expire_days=7
        )

    def test_create_access_token(self):
        """Test access token creation"""
        user_id = str(uuid.uuid4())
        data = {"sub": user_id, "role": "operator"}

        token = self.jwt_handler.create_access_token(data)

        assert token is not None
        assert isinstance(token, str)
        assert len(token.split('.')) == 3  # JWT format: header.payload.signature

        # Decode and verify token
        decoded = self.jwt_handler.decode_token(token)
        assert decoded["sub"] == user_id
        assert decoded["role"] == "operator"
        assert "exp" in decoded

    def test_create_refresh_token(self):
        """Test refresh token creation"""
        user_id = str(uuid.uuid4())
        data = {"sub": user_id}

        token = self.jwt_handler.create_refresh_token(data)

        assert token is not None
        assert isinstance(token, str)

        # Decode and verify token
        decoded = self.jwt_handler.decode_token(token)
        assert decoded["sub"] == user_id
        assert decoded["type"] == "refresh"
        assert "exp" in decoded

    def test_decode_token_valid(self):
        """Test decoding valid token"""
        user_id = str(uuid.uuid4())
        data = {"sub": user_id, "custom": "value"}

        token = self.jwt_handler.create_access_token(data)
        decoded = self.jwt_handler.decode_token(token)

        assert decoded["sub"] == user_id
        assert decoded["custom"] == "value"

    def test_decode_token_expired(self):
        """Test decoding expired token"""
        user_id = str(uuid.uuid4())
        data = {"sub": user_id}

        # Create token with negative expiration
        token = self.jwt_handler.create_access_token(
            data,
            expires_delta=timedelta(minutes=-1)
        )

        with pytest.raises(Exception) as exc:
            self.jwt_handler.decode_token(token)

        assert "expired" in str(exc.value).lower()

    def test_decode_token_invalid(self):
        """Test decoding invalid token"""
        invalid_tokens = [
            "invalid.token.here",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid",
            "",
            "not-a-jwt"
        ]

        for token in invalid_tokens:
            with pytest.raises(Exception):
                self.jwt_handler.decode_token(token)

    def test_refresh_access_token(self):
        """Test refreshing access token"""
        user_id = str(uuid.uuid4())
        refresh_data = {"sub": user_id}

        refresh_token = self.jwt_handler.create_refresh_token(refresh_data)
        new_access_token = self.jwt_handler.refresh_access_token(refresh_token)

        assert new_access_token is not None

        # Verify new token
        decoded = self.jwt_handler.decode_token(new_access_token)
        assert decoded["sub"] == user_id


class TestPermissions:
    """Test permission system"""

    def test_permission_enum(self):
        """Test permission enumeration"""
        assert Permission.DEVICE_READ.value == "device:read"
        assert Permission.DEPLOYMENT_CREATE.value == "deployment:create"
        assert Permission.ADMIN_ALL.value == "admin:*"

    def test_check_permission_admin(self):
        """Test admin permission check"""
        user = Mock(role=UserRole.ADMIN)

        # Admin should have all permissions
        assert check_permission(user, Permission.DEVICE_READ) is True
        assert check_permission(user, Permission.DEPLOYMENT_CREATE) is True
        assert check_permission(user, Permission.DEPLOYMENT_APPROVE) is True
        assert check_permission(user, Permission.USER_MANAGE) is True

    def test_check_permission_operator(self):
        """Test operator permission check"""
        user = Mock(role=UserRole.OPERATOR)

        # Operator permissions
        assert check_permission(user, Permission.DEVICE_READ) is True
        assert check_permission(user, Permission.DEPLOYMENT_CREATE) is True
        assert check_permission(user, Permission.DEPLOYMENT_APPROVE) is False
        assert check_permission(user, Permission.USER_MANAGE) is False

    def test_check_permission_viewer(self):
        """Test viewer permission check"""
        user = Mock(role=UserRole.VIEWER)

        # Viewer permissions - read only
        assert check_permission(user, Permission.DEVICE_READ) is True
        assert check_permission(user, Permission.DEPLOYMENT_READ) is True
        assert check_permission(user, Permission.DEPLOYMENT_CREATE) is False
        assert check_permission(user, Permission.DEVICE_WRITE) is False

    def test_check_permission_superuser(self):
        """Test superuser bypass"""
        user = Mock(role=UserRole.VIEWER, is_superuser=True)

        # Superuser should have all permissions regardless of role
        assert check_permission(user, Permission.ADMIN_ALL) is True
        assert check_permission(user, Permission.USER_MANAGE) is True

    def test_permission_dependencies(self):
        """Test permission dependencies"""
        # DEPLOYMENT_APPROVE requires DEPLOYMENT_CREATE
        assert Permission.DEPLOYMENT_CREATE in Permission.DEPLOYMENT_APPROVE.dependencies()

        # DEVICE_EXECUTE requires DEVICE_WRITE
        assert Permission.DEVICE_WRITE in Permission.DEVICE_EXECUTE.dependencies()

    @pytest.mark.asyncio
    async def test_require_permission_decorator(self):
        """Test permission requirement decorator"""
        from src.auth.dependencies import require_permission

        # Mock function with permission requirement
        @require_permission(Permission.DEPLOYMENT_CREATE)
        async def protected_function(current_user):
            return "success"

        # Test with authorized user
        authorized_user = Mock(role=UserRole.OPERATOR)
        result = await protected_function(authorized_user)
        assert result == "success"

        # Test with unauthorized user
        unauthorized_user = Mock(role=UserRole.VIEWER)
        with pytest.raises(Exception) as exc:
            await protected_function(unauthorized_user)
        assert "permission" in str(exc.value).lower()


class TestSessionManagement:
    """Test session management"""

    @pytest.mark.asyncio
    async def test_create_session(self, test_db_session, test_user):
        """Test session creation"""
        session_token = auth_service.create_session(test_user)

        assert session_token is not None
        assert len(session_token) >= 32

        # Verify session is stored
        stored_session = await auth_service.get_session(test_db_session, session_token)
        assert stored_session is not None
        assert stored_session.user_id == test_user.id

    @pytest.mark.asyncio
    async def test_validate_session(self, test_db_session, test_user):
        """Test session validation"""
        session_token = auth_service.create_session(test_user)

        # Valid session
        is_valid = await auth_service.validate_session(test_db_session, session_token)
        assert is_valid is True

        # Invalid session
        is_valid = await auth_service.validate_session(test_db_session, "invalid_token")
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_invalidate_session(self, test_db_session, test_user):
        """Test session invalidation"""
        session_token = auth_service.create_session(test_user)

        # Invalidate session
        await auth_service.invalidate_session(test_db_session, session_token)

        # Session should no longer be valid
        is_valid = await auth_service.validate_session(test_db_session, session_token)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_session_expiration(self, test_db_session, test_user):
        """Test session expiration"""
        # Create session with short expiration
        session_token = auth_service.create_session(
            test_user,
            expire_minutes=0  # Immediate expiration
        )

        # Session should be expired
        is_valid = await auth_service.validate_session(test_db_session, session_token)
        assert is_valid is False


class TestPasswordReset:
    """Test password reset functionality"""

    @pytest.mark.asyncio
    async def test_create_reset_token(self, test_db_session, test_user):
        """Test password reset token creation"""
        token = await auth_service.create_password_reset_token(
            test_db_session,
            test_user.email
        )

        assert token is not None
        assert len(token) >= 32

        # Verify token is stored
        stored_token = await auth_service.get_reset_token(test_db_session, token)
        assert stored_token is not None
        assert stored_token.user_id == test_user.id

    @pytest.mark.asyncio
    async def test_reset_password(self, test_db_session, test_user):
        """Test password reset"""
        token = await auth_service.create_password_reset_token(
            test_db_session,
            test_user.email
        )

        new_password = "NewSecurePassword123!"

        # Reset password
        success = await auth_service.reset_password(
            test_db_session,
            token,
            new_password
        )
        assert success is True

        # Verify new password works
        authenticated = await auth_service.authenticate_user(
            test_db_session,
            test_user.username,
            new_password
        )
        assert authenticated is not None

        # Token should be invalidated after use
        stored_token = await auth_service.get_reset_token(test_db_session, token)
        assert stored_token is None

    @pytest.mark.asyncio
    async def test_reset_token_expiration(self, test_db_session, test_user):
        """Test reset token expiration"""
        token = await auth_service.create_password_reset_token(
            test_db_session,
            test_user.email,
            expire_minutes=0  # Immediate expiration
        )

        # Attempt reset with expired token
        success = await auth_service.reset_password(
            test_db_session,
            token,
            "NewPassword123!"
        )
        assert success is False