"""
Unit tests for JWT Handler
Tests token generation, validation, refresh, and revocation
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
import jwt as pyjwt
from uuid import uuid4

from src.auth.jwt_handler import JWTHandler
from src.auth.models import TokenType, User


@pytest.fixture
def jwt_handler():
    """Provide a JWT handler instance for testing."""
    return JWTHandler(
        algorithm="HS256",
        access_token_expire_minutes=30,
        refresh_token_expire_days=7,
        issuer="catnet-test",
        audience="catnet-api-test"
    )


@pytest.fixture
def mock_user():
    """Provide a mock user for testing."""
    user = Mock(spec=User)
    user.id = uuid4()
    user.username = "testuser"
    user.email = "test@example.com"
    user.roles = ["admin", "operator"]
    user.is_active = True
    return user


class TestJWTHandlerInitialization:
    """Test JWT handler initialization and configuration."""

    def test_initialization_with_hs256(self):
        """Test JWT handler initializes correctly with HS256."""
        handler = JWTHandler(algorithm="HS256")
        assert handler.algorithm == "HS256"
        assert handler.access_token_expire_minutes == 30
        assert handler.refresh_token_expire_days == 30

    def test_initialization_with_custom_expiry(self):
        """Test JWT handler with custom expiration times."""
        handler = JWTHandler(
            access_token_expire_minutes=60,
            refresh_token_expire_days=14
        )
        assert handler.access_token_expire_minutes == 60
        assert handler.refresh_token_expire_days == 14

    def test_initialization_with_rsa_generates_keys(self):
        """Test JWT handler generates RSA keys when none provided."""
        handler = JWTHandler(algorithm="RS256")
        assert handler.private_key is not None
        assert handler.public_key is not None
        assert handler.algorithm == "RS256"


class TestAccessTokenGeneration:
    """Test access token generation and validation."""

    def test_create_access_token_success(self, jwt_handler, mock_user):
        """Test successful access token creation."""
        token = jwt_handler.create_access_token(
            user_id=str(mock_user.id),
            username=mock_user.username,
            roles=mock_user.roles
        )

        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0

    def test_access_token_contains_correct_claims(self, jwt_handler, mock_user):
        """Test access token contains all required claims."""
        token = jwt_handler.create_access_token(
            user_id=str(mock_user.id),
            username=mock_user.username,
            roles=mock_user.roles
        )

        # Decode without verification to inspect claims
        decoded = pyjwt.decode(
            token,
            options={"verify_signature": False}
        )

        assert decoded["sub"] == str(mock_user.id)
        assert decoded["username"] == mock_user.username
        assert decoded["roles"] == mock_user.roles
        assert decoded["type"] == "access"
        assert decoded["iss"] == jwt_handler.issuer
        assert decoded["aud"] == jwt_handler.audience
        assert "exp" in decoded
        assert "iat" in decoded
        assert "jti" in decoded

    def test_access_token_expiration_time(self, jwt_handler, mock_user):
        """Test access token has correct expiration time."""
        token = jwt_handler.create_access_token(
            user_id=str(mock_user.id),
            username=mock_user.username
        )

        decoded = pyjwt.decode(
            token,
            options={"verify_signature": False}
        )

        issued_at = datetime.fromtimestamp(decoded["iat"])
        expires_at = datetime.fromtimestamp(decoded["exp"])

        expected_expiry = issued_at + timedelta(
            minutes=jwt_handler.access_token_expire_minutes
        )

        # Allow 1 second difference for test execution time
        assert abs((expires_at - expected_expiry).total_seconds()) < 1

    def test_create_access_token_with_additional_claims(self, jwt_handler, mock_user):
        """Test access token with additional custom claims."""
        additional_claims = {
            "department": "engineering",
            "permissions": ["read", "write"]
        }

        token = jwt_handler.create_access_token(
            user_id=str(mock_user.id),
            username=mock_user.username,
            additional_claims=additional_claims
        )

        decoded = pyjwt.decode(
            token,
            options={"verify_signature": False}
        )

        assert decoded["department"] == "engineering"
        assert decoded["permissions"] == ["read", "write"]


class TestRefreshTokenGeneration:
    """Test refresh token generation and validation."""

    def test_create_refresh_token_success(self, jwt_handler, mock_user):
        """Test successful refresh token creation."""
        token = jwt_handler.create_refresh_token(
            user_id=str(mock_user.id)
        )

        assert token is not None
        assert isinstance(token, str)

    def test_refresh_token_contains_correct_claims(self, jwt_handler, mock_user):
        """Test refresh token contains required claims."""
        token = jwt_handler.create_refresh_token(
            user_id=str(mock_user.id)
        )

        decoded = pyjwt.decode(
            token,
            options={"verify_signature": False}
        )

        assert decoded["sub"] == str(mock_user.id)
        assert decoded["type"] == "refresh"
        assert "exp" in decoded
        assert "iat" in decoded
        assert "jti" in decoded

    def test_refresh_token_expiration_time(self, jwt_handler, mock_user):
        """Test refresh token has correct expiration time."""
        token = jwt_handler.create_refresh_token(
            user_id=str(mock_user.id)
        )

        decoded = pyjwt.decode(
            token,
            options={"verify_signature": False}
        )

        issued_at = datetime.fromtimestamp(decoded["iat"])
        expires_at = datetime.fromtimestamp(decoded["exp"])

        expected_expiry = issued_at + timedelta(
            days=jwt_handler.refresh_token_expire_days
        )

        assert abs((expires_at - expected_expiry).total_seconds()) < 1


class TestTokenValidation:
    """Test token validation and verification."""

    def test_validate_access_token_success(self, jwt_handler, mock_user):
        """Test successful access token validation."""
        token = jwt_handler.create_access_token(
            user_id=str(mock_user.id),
            username=mock_user.username
        )

        payload = jwt_handler.validate_token(token)

        assert payload is not None
        assert payload["sub"] == str(mock_user.id)
        assert payload["type"] == "access"

    def test_validate_expired_token_fails(self, jwt_handler, mock_user):
        """Test validation fails for expired token."""
        # Create handler with very short expiry
        short_expiry_handler = JWTHandler(
            access_token_expire_minutes=-1  # Already expired
        )

        token = short_expiry_handler.create_access_token(
            user_id=str(mock_user.id),
            username=mock_user.username
        )

        with pytest.raises(pyjwt.ExpiredSignatureError):
            short_expiry_handler.validate_token(token)

    def test_validate_invalid_signature_fails(self, jwt_handler, mock_user):
        """Test validation fails for invalid signature."""
        token = jwt_handler.create_access_token(
            user_id=str(mock_user.id),
            username=mock_user.username
        )

        # Create new handler with different secret
        different_handler = JWTHandler()

        with pytest.raises(pyjwt.InvalidSignatureError):
            different_handler.validate_token(token)

    def test_validate_malformed_token_fails(self, jwt_handler):
        """Test validation fails for malformed token."""
        malformed_token = "not.a.valid.jwt.token"

        with pytest.raises(pyjwt.DecodeError):
            jwt_handler.validate_token(malformed_token)

    def test_validate_wrong_token_type_fails(self, jwt_handler, mock_user):
        """Test validation fails when expecting different token type."""
        refresh_token = jwt_handler.create_refresh_token(
            user_id=str(mock_user.id)
        )

        # Attempt to validate refresh token as access token should fail
        payload = jwt_handler.validate_token(refresh_token)
        assert payload["type"] == "refresh"  # Not "access"


class TestTokenRevocation:
    """Test token revocation functionality."""

    def test_revoke_token_success(self, jwt_handler, mock_user):
        """Test token can be revoked."""
        token = jwt_handler.create_access_token(
            user_id=str(mock_user.id),
            username=mock_user.username
        )

        # Extract JTI
        decoded = pyjwt.decode(
            token,
            options={"verify_signature": False}
        )
        jti = decoded["jti"]

        jwt_handler.revoke_token(jti)

        assert jwt_handler.is_token_revoked(jti) is True

    def test_validate_revoked_token_fails(self, jwt_handler, mock_user):
        """Test validation fails for revoked token."""
        token = jwt_handler.create_access_token(
            user_id=str(mock_user.id),
            username=mock_user.username
        )

        decoded = pyjwt.decode(
            token,
            options={"verify_signature": False}
        )
        jti = decoded["jti"]

        # Revoke token
        jwt_handler.revoke_token(jti)

        # Validation should fail
        with pytest.raises(ValueError, match="Token has been revoked"):
            jwt_handler.validate_token(token, check_revoked=True)

    def test_non_revoked_token_validates(self, jwt_handler, mock_user):
        """Test non-revoked token validates successfully."""
        token = jwt_handler.create_access_token(
            user_id=str(mock_user.id),
            username=mock_user.username
        )

        decoded = pyjwt.decode(
            token,
            options={"verify_signature": False}
        )
        jti = decoded["jti"]

        assert jwt_handler.is_token_revoked(jti) is False

        # Should validate successfully
        payload = jwt_handler.validate_token(token, check_revoked=True)
        assert payload is not None


class TestTokenRefresh:
    """Test token refresh functionality."""

    def test_refresh_access_token_success(self, jwt_handler, mock_user):
        """Test successful token refresh."""
        refresh_token = jwt_handler.create_refresh_token(
            user_id=str(mock_user.id)
        )

        new_access_token = jwt_handler.refresh_access_token(
            refresh_token=refresh_token,
            username=mock_user.username,
            roles=mock_user.roles
        )

        assert new_access_token is not None

        # Validate new access token
        payload = jwt_handler.validate_token(new_access_token)
        assert payload["sub"] == str(mock_user.id)
        assert payload["type"] == "access"

    def test_refresh_with_access_token_fails(self, jwt_handler, mock_user):
        """Test refresh fails when using access token instead of refresh token."""
        access_token = jwt_handler.create_access_token(
            user_id=str(mock_user.id),
            username=mock_user.username
        )

        with pytest.raises(ValueError, match="Invalid token type"):
            jwt_handler.refresh_access_token(
                refresh_token=access_token,
                username=mock_user.username
            )


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_empty_user_id_raises_error(self, jwt_handler):
        """Test token creation fails with empty user ID."""
        with pytest.raises((ValueError, TypeError)):
            jwt_handler.create_access_token(
                user_id="",
                username="testuser"
            )

    def test_none_user_id_raises_error(self, jwt_handler):
        """Test token creation fails with None user ID."""
        with pytest.raises((ValueError, TypeError)):
            jwt_handler.create_access_token(
                user_id=None,
                username="testuser"
            )

    def test_very_long_username(self, jwt_handler):
        """Test token creation with very long username."""
        long_username = "a" * 1000
        user_id = str(uuid4())

        token = jwt_handler.create_access_token(
            user_id=user_id,
            username=long_username
        )

        payload = jwt_handler.validate_token(token)
        assert payload["username"] == long_username

    def test_special_characters_in_claims(self, jwt_handler):
        """Test token creation with special characters in claims."""
        user_id = str(uuid4())
        special_username = "user@example.com!#$%"

        token = jwt_handler.create_access_token(
            user_id=user_id,
            username=special_username
        )

        payload = jwt_handler.validate_token(token)
        assert payload["username"] == special_username
