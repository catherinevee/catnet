"""
Comprehensive tests for CatNet Authentication
"""

import pytest
from unittest.mock import Mock, patch
import pyotp

from src.auth.jwt_handler import JWTHandler
from src.auth.mfa import MFAProvider
from src.auth.oauth import OAuthProvider
from src.auth.saml import SAMLProvider
from src.auth.session import SessionManager



class TestJWTHandler:
    """Test JWT token handler"""

    def test_create_access_token(self):
        """Test access token creation"""
        handler = JWTHandler()

        token = handler.create_token(
            user_id="user123",
            username="testuser",
            roles=["admin", "operator"],
            permissions=["read", "write"],
            token_type="access",
        )

        assert token is not None
        assert isinstance(token, str)

        # Verify token can be decoded
        is_valid, claims = handler.verify_token(token, token_type="access")
        assert is_valid
        assert claims["sub"] == "user123"
        assert claims["username"] == "testuser"
        assert "admin" in claims["roles"]
        assert "write" in claims["permissions"]

    def test_token_expiration(self):
        """Test token expiration validation"""
        handler = JWTHandler(token_lifetime=1)  # 1 second

        token = handler.create_token(
            user_id="user123", username="testuser", token_type="access"
        )

        # Token should be valid immediately
        is_valid, claims = handler.verify_token(token)
        assert is_valid

        # Wait for expiration
        import time

        time.sleep(2)

        # Token should be expired
        is_valid, claims = handler.verify_token(token)
        assert not is_valid
        assert claims["error"] == "Token has expired"

    def test_refresh_token_flow(self):
        """Test refresh token generation and usage"""
        handler = JWTHandler()

        # Create refresh token
        refresh_token = handler.create_token(
            user_id="user123",
                username="testuser"
                roles=["user"]
                token_type="refresh"
        )

        # Use refresh token to get new tokens
        new_access, new_refresh = handler.refresh_token(refresh_token)

        assert new_access is not None
        assert new_refresh is not None

        # Verify new access token
                is_valid, claims = handler.verify_token(
            new_access,
            token_type="access"
        )
        assert is_valid
        assert claims["username"] == "testuser"

        # Old refresh token should be revoked
        is_valid, _ = handler.verify_token(refresh_token, token_type="refresh")
        assert not is_valid

    def test_token_revocation(self):
        """Test token revocation"""
        handler = JWTHandler()

        token = handler.create_token(
            user_id="user123", username="testuser", token_type="access"
        )

        # Token should be valid
        is_valid, _ = handler.verify_token(token)
        assert is_valid

        # Revoke token
        success = handler.revoke_token(token)
        assert success

        # Token should now be invalid
        is_valid, claims = handler.verify_token(token)
        assert not is_valid
        assert claims["error"] == "Token has been revoked"

    def test_invalid_token_type(self):
        """Test token type validation"""
        handler = JWTHandler()

        # Create access token
        token = handler.create_token(
            user_id="user123", username="testuser", token_type="access"
        )

        # Try to verify as refresh token
        is_valid, claims = handler.verify_token(token, token_type="refresh")
        assert not is_valid
        assert "Invalid token type" in claims["error"]



class TestMFAProvider:
    """Test Multi-Factor Authentication"""

    def test_enable_mfa(self):
        """Test MFA enablement"""
        provider = MFAProvider()

        result = provider.enable_mfa(user_id="user123", username="testuser")

        assert "secret" in result
        assert "qr_code" in result
        assert "backup_codes" in result
        assert len(result["backup_codes"]) == 10
        assert result["digits"] == 6
        assert result["period"] == 30

    def test_totp_verification(self):
        """Test TOTP token verification"""
        provider = MFAProvider()

        # Enable MFA
        result = provider.enable_mfa("user123", "testuser")
        secret = result["secret"]

        # Generate valid TOTP
        totp = pyotp.TOTP(secret)
        token = totp.now()

        # Verify token
        is_valid, error = provider.verify_totp("user123", token)
        assert is_valid
        assert error is None

    def test_invalid_totp(self):
        """Test invalid TOTP rejection"""
        provider = MFAProvider()

        # Enable MFA
        provider.enable_mfa("user123", "testuser")

        # Try invalid token
        is_valid, error = provider.verify_totp("user123", "000000")
        assert not is_valid
        assert "Invalid TOTP token" in error

    def test_backup_codes(self):
        """Test backup code usage"""
        provider = MFAProvider()

        # Enable MFA
        result = provider.enable_mfa("user123", "testuser")
        backup_codes = result["backup_codes"]

        # Use backup code
        is_valid, message = provider.verify_totp("user123", backup_codes[0])
        assert is_valid
        assert message == "Backup code used"

        # Same backup code should not work again
        is_valid, _ = provider.verify_totp("user123", backup_codes[0])
        assert not is_valid

    def test_regenerate_backup_codes(self):
        """Test backup code regeneration"""
        provider = MFAProvider()

        # Enable MFA
        result = provider.enable_mfa("user123", "testuser")
        old_codes = result["backup_codes"]

        # Regenerate codes
        new_codes = provider.regenerate_backup_codes("user123")

        assert new_codes is not None
        assert len(new_codes) == 10
        assert new_codes != old_codes

    def test_disable_mfa(self):
        """Test MFA disablement"""
        provider = MFAProvider()

        # Enable then disable MFA
        provider.enable_mfa("user123", "testuser")
        success = provider.disable_mfa("user123")
        assert success

        # Should not be able to verify tokens anymore
        is_valid, error = provider.verify_totp("user123", "123456")
        assert not is_valid
        assert "MFA not enabled" in error



class TestOAuthProvider:
    """Test OAuth2 authentication"""

    def test_register_provider(self):
        """Test OAuth provider registration"""
        provider = OAuthProvider()

        config = provider.register_provider(
            provider_name="google",
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="http://localhost/callback",
        )

        assert config.provider_name == "google"
        assert config.client_id == "test_client_id"
        assert "accounts.google.com" in config.authorize_url
        assert "openid" in config.scopes

    def test_generate_auth_url(self):
        """Test OAuth authorization URL generation"""
        provider = OAuthProvider()

        provider.register_provider(
            provider_name="github",
            client_id="test_client",
            client_secret="test_secret",
            redirect_uri="http://localhost/callback",
        )

        result = provider.generate_auth_url("github", use_pkce=True)

        assert "auth_url" in result
        assert "state" in result
        assert "code_verifier" in result
        assert "github.com/login/oauth/authorize" in result["auth_url"]
        assert "client_id=test_client" in result["auth_url"]

    @pytest.mark.asyncio
    async def test_token_exchange(self):
        """Test OAuth code exchange"""
        provider = OAuthProvider()

        provider.register_provider(
            provider_name="google",
            client_id="test_client",
            client_secret="test_secret",
            redirect_uri="http://localhost/callback",
        )

        # Generate auth URL and state
        auth_result = provider.generate_auth_url("google")
        state = auth_result["state"]

        # Mock token exchange
        with patch("httpx.AsyncClient.post") as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "access_token": "test_access_token",
                "refresh_token": "test_refresh_token",
                "expires_in": 3600,
            }
            mock_post.return_value = mock_response

            result = await provider.exchange_code(
                provider_name="google", code="test_code", state=state
            )

            assert result["access_token"] == "test_access_token"
            assert result["refresh_token"] == "test_refresh_token"

    @pytest.mark.asyncio
    async def test_get_user_info(self):
        """Test fetching user info from OAuth provider"""
        provider = OAuthProvider()

        provider.register_provider(
            provider_name="github",
            client_id="test_client",
            client_secret="test_secret",
            redirect_uri="http://localhost/callback",
        )

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "id": "12345",
                "login": "testuser",
                "email": "test@example.com",
            }
            mock_get.return_value = mock_response

            user_info = await provider.get_user_info("github", "test_token")

            assert user_info["login"] == "testuser"
            assert user_info["email"] == "test@example.com"



class TestSAMLProvider:
    """Test SAML authentication"""

    def test_register_config(self):
        """Test SAML configuration registration"""
        provider = SAMLProvider()

        from src.auth.saml import SAMLConfig

        config = SAMLConfig(
            entity_id="http://localhost/saml",
            acs_url="http://localhost/saml/acs",
            sls_url="http://localhost/saml/sls",
            idp_entity_id="http://idp.example.com",
            idp_sso_url="http://idp.example.com/sso",
            idp_sls_url="http://idp.example.com/sls",
            idp_cert="-----BEGIN CERTIFICATE-----\n...\n-----END \
                CERTIFICATE-----",
        )

        provider.register_config("test", config)

        assert "test" in provider.configs
        assert provider.configs["test"].entity_id == "http://localhost/saml"

    def test_create_authn_request(self):
        """Test SAML authentication request creation"""
        provider = SAMLProvider()

        from src.auth.saml import SAMLConfig

        config = SAMLConfig(
            entity_id="http://localhost/saml",
            acs_url="http://localhost/saml/acs",
            sls_url="http://localhost/saml/sls",
            idp_entity_id="http://idp.example.com",
            idp_sso_url="http://idp.example.com/sso",
            idp_sls_url="http://idp.example.com/sls",
            idp_cert="cert",
        )

        provider.register_config("test", config)

        result = provider.create_authn_request(
            config_name="test", relay_state="test_state"
        )

        assert "request_url" in result
        assert "request_id" in result
        assert "saml_request" in result
        assert "SAMLRequest=" in result["request_url"]
        assert "RelayState=test_state" in result["request_url"]

    def test_generate_metadata(self):
        """Test SAML metadata generation"""
        provider = SAMLProvider()

        from src.auth.saml import SAMLConfig

        config = SAMLConfig(
            entity_id="http://localhost/saml",
            acs_url="http://localhost/saml/acs",
            sls_url="http://localhost/saml/sls",
            idp_entity_id="http://idp.example.com",
            idp_sso_url="http://idp.example.com/sso",
            idp_sls_url="http://idp.example.com/sls",
            idp_cert="cert",
        )

        provider.register_config("test", config)

        metadata = provider.generate_metadata("test")

        assert '<?xml version="1.0"?>' in metadata
        assert "EntityDescriptor" in metadata
        assert config.entity_id in metadata
        assert config.acs_url in metadata



class TestSessionManager:
    """Test session management"""

    def test_create_session(self):
        """Test session creation"""
        manager = SessionManager()

        session = manager.create_session(
            user_id="user123",
            username="testuser",
            ip_address="192.168.1.1",
            user_agent="TestBrowser/1.0",
            roles=["admin"],
            permissions=["read", "write"],
        )

        assert session.session_id is not None
        assert session.user_id == "user123"
        assert session.username == "testuser"
        assert session.is_active
        assert "admin" in session.roles

    def test_session_validation(self):
        """Test session validation"""
        manager = SessionManager()

        session = manager.create_session(
            user_id="user123",
            username="testuser",
            ip_address="192.168.1.1",
            user_agent="TestBrowser/1.0",
        )

        # Valid session
        is_valid, error = manager.validate_session(
            session.session_id, ip_address="192.168.1.1"
        )
        assert is_valid
        assert error is None

        # Invalid IP
        is_valid, error = manager.validate_session(
            session.session_id, ip_address="10.0.0.1"
        )
        assert not is_valid
        assert "IP address mismatch" in error

    def test_session_expiration(self):
        """Test session expiration"""
        manager = SessionManager(session_lifetime=1)  # 1 second

        session = manager.create_session(
            user_id="user123",
            username="testuser",
            ip_address="192.168.1.1",
            user_agent="TestBrowser/1.0",
        )

        # Session should be valid immediately
        retrieved = manager.get_session(session.session_id)
        assert retrieved is not None

        # Wait for expiration
        import time

        time.sleep(2)

        # Session should be expired
        retrieved = manager.get_session(session.session_id)
        assert retrieved is None

    def test_concurrent_session_limit(self):
        """Test concurrent session limits"""
        manager = SessionManager(max_sessions_per_user=2)

        # Create max sessions
        session1 = manager.create_session(
            user_id="user123",
            username="testuser",
            ip_address="192.168.1.1",
            user_agent="Browser1",
        )

        session2 = manager.create_session(
            user_id="user123",
            username="testuser",
            ip_address="192.168.1.2",
            user_agent="Browser2",
        )

        # Creating another should remove oldest
        session3 = manager.create_session(
            user_id="user123",
            username="testuser",
            ip_address="192.168.1.3",
            user_agent="Browser3",
        )

        # First session should be terminated
        assert manager.get_session(session1.session_id) is None
        assert manager.get_session(session2.session_id) is not None
        assert manager.get_session(session3.session_id) is not None

    def test_terminate_session(self):
        """Test session termination"""
        manager = SessionManager()

        session = manager.create_session(
            user_id="user123",
            username="testuser",
            ip_address="192.168.1.1",
            user_agent="TestBrowser/1.0",
        )

        # Terminate session
        success = manager.terminate_session(session.session_id)
        assert success

        # Session should not be retrievable
        retrieved = manager.get_session(session.session_id)
        assert retrieved is None

    def test_terminate_user_sessions(self):
        """Test terminating all user sessions"""
        manager = SessionManager()

        # Create multiple sessions for user
        for i in range(3):
            manager.create_session(
                user_id="user123",
                username="testuser",
                ip_address=f"192.168.1.{i}",
                user_agent="TestBrowser/1.0",
            )

        # Terminate all
        count = manager.terminate_user_sessions("user123")
        assert count == 3

        # No sessions should remain
        sessions = manager.get_user_sessions("user123")
        assert len(sessions) == 0

    def test_session_activity_update(self):
        """Test session activity tracking"""
        manager = SessionManager(session_lifetime=60)

        session = manager.create_session(
            user_id="user123",
            username="testuser",
            ip_address="192.168.1.1",
            user_agent="TestBrowser/1.0",
        )

        original_activity = session.last_activity
        original_expiry = session.expires_at

        # Wait a bit
        import time

        time.sleep(1)

        # Update activity
        manager.update_activity(session.session_id)

        # Get updated session
        updated = manager.get_session(session.session_id)
        assert updated.last_activity > original_activity
        assert updated.expires_at > original_expiry

    def test_mfa_requirement_check(self):
        """Test MFA requirement checking"""
        manager = SessionManager(require_mfa_for_sensitive=True)

        # Session without MFA
        session = manager.create_session(
            user_id="user123",
            username="testuser",
            ip_address="192.168.1.1",
            user_agent="TestBrowser/1.0",
            mfa_verified=False,
        )

        # Should require MFA for sensitive operations
        requires = manager.requires_mfa(session.session_id, "delete_device")
        assert requires

        # Should not require for regular operations
        requires = manager.requires_mfa(session.session_id, "read_config")
        assert not requires

        # Session with MFA
        session_mfa = manager.create_session(
            user_id="user456",
            username="testuser2",
            ip_address="192.168.1.2",
            user_agent="TestBrowser/1.0",
            mfa_verified=True,
        )

        # Should not require MFA even for sensitive operations
                requires = manager.requires_mfa(
            session_mfa.session_id,
            "delete_device"
        )
        assert not requires


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
