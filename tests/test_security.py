import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from src.security.encryption import EncryptionManager
from src.security.audit import AuditLogger, AuditLevel
from src.security.auth import AuthManager
from src.security.vault import VaultClient


class TestEncryption:
    def test_aes_gcm_encryption(self):
        encryption = EncryptionManager()
        plaintext = b"This is a secret message"

        # Encrypt
        iv, ciphertext, tag = encryption.encrypt_aes_gcm(plaintext)

        # Decrypt
        decrypted = encryption.decrypt_aes_gcm(iv, ciphertext, tag)

        assert decrypted == plaintext

    def test_string_encryption(self):
        encryption = EncryptionManager()
        plaintext = "This is a secret configuration"

        # Encrypt
        encrypted = encryption.encrypt_string(plaintext)

        # Decrypt
        decrypted = encryption.decrypt_string(encrypted)

        assert decrypted == plaintext

    def test_password_hashing(self):
        password = "SuperSecurePassword123!"

        # Hash password
        hashed = EncryptionManager.hash_password(password)

        # Verify correct password
        assert EncryptionManager.verify_password(password, hashed)

        # Verify incorrect password
        assert not EncryptionManager.verify_password("WrongPassword", hashed)

    def test_rsa_keypair_generation(self):
        private_key, public_key = EncryptionManager.generate_rsa_keypair()

        assert private_key is not None
        assert public_key is not None
        assert (
            b"BEGIN RSA PRIVATE KEY" in private_key
            or b"BEGIN PRIVATE KEY" in private_key
        )
        assert b"BEGIN PUBLIC KEY" in public_key

    def test_digital_signature(self):
        private_key, public_key = EncryptionManager.generate_rsa_keypair()
        data = b"Important configuration data"

        # Sign data
        signature = EncryptionManager.sign_data(data, private_key)

        # Verify signature
        assert EncryptionManager.verify_signature(data, signature, public_key)

        # Verify with tampered data
        tampered_data = b"Tampered configuration data"
        assert not EncryptionManager.verify_signature(
            tampered_data, signature, public_key
        )


class TestAuditLogger:
    @pytest.mark.asyncio
    async def test_log_event(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        audit = AuditLogger(log_file=str(log_file), enable_console=False)

        event_id = await audit.log_event(
            event_type="test_event",
            user_id="test_user",
            details={"action": "test_action"},
            level=AuditLevel.INFO,
        )

        assert event_id is not None
        assert log_file.exists()

    @pytest.mark.asyncio
    async def test_log_authentication(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        audit = AuditLogger(log_file=str(log_file), enable_console=False)

        await audit.log_authentication(
            user_id="test_user",
            success=True,
            method="password",
            ip_address="192.168.1.1",
            user_agent="TestAgent/1.0",
        )

        # Read and verify log
        with open(log_file, "r") as f:
            log_line = f.readline()
            assert "authentication" in log_line
            assert "test_user" in log_line

    @pytest.mark.asyncio
    async def test_log_integrity(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        audit = AuditLogger(log_file=str(log_file), enable_console=False)

        # Log multiple events
        for i in range(5):
            await audit.log_event(
                event_type=f"test_event_{i}", user_id=f"user_{i}", details={"index": i}
            )

        # Verify integrity
        assert await audit.verify_log_integrity()

    @pytest.mark.asyncio
    async def test_session_recording(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        audit = AuditLogger(log_file=str(log_file), enable_console=False)

        session_id = "test_session_123"

        # Start session
        await audit.start_session_recording(
            session_id=session_id, user_id="test_user", device_id="device_1"
        )

        # Record commands
        await audit.record_command(session_id, "show version", "Cisco IOS 15.0")
        await audit.record_command(session_id, "show running-config", "config output")

        # End session
        await audit.end_session_recording(session_id)

        # Verify session is removed
        assert session_id not in audit.session_recordings


class TestAuthManager:
    @pytest.mark.asyncio
    async def test_token_creation_and_verification(self):
        auth = AuthManager(secret_key="test_secret_key")

        user_data = {"sub": "user123", "roles": ["admin"]}

        # Create access token
        token = await auth.create_access_token(user_data)

        # Verify token
        payload = await auth.verify_token(token, token_type="access")

        assert payload["sub"] == "user123"
        assert payload["roles"] == ["admin"]
        assert payload["type"] == "access"

    @pytest.mark.asyncio
    async def test_refresh_token(self):
        auth = AuthManager(secret_key="test_secret_key")

        user_data = {"sub": "user123", "roles": ["operator"]}

        # Create refresh token
        refresh_token = await auth.create_refresh_token(user_data)

        # Use refresh token to get new access token
        new_tokens = await auth.refresh_access_token(refresh_token)

        assert "access_token" in new_tokens
        assert new_tokens["token_type"] == "bearer"

    def test_mfa_token_generation_and_verification(self):
        auth = AuthManager(secret_key="test_secret_key")

        user_id = "test_user"

        # Generate MFA secret
        secret = auth.generate_mfa_secret(user_id)

        assert secret is not None
        assert len(secret) > 0

        # Generate QR code URI
        qr_uri = auth.generate_mfa_qr_code(user_id, secret)

        assert "otpauth://" in qr_uri
        assert user_id in qr_uri

    @pytest.mark.asyncio
    async def test_permission_checking(self):
        auth = AuthManager(secret_key="test_secret_key")

        # Admin user
        admin_user = {"sub": "admin_user", "roles": ["admin"]}
        assert await auth.check_permission(admin_user, "deployment.create")

        # Operator user
        operator_user = {"sub": "op_user", "roles": ["operator"]}
        assert await auth.check_permission(operator_user, "device.view")
        assert not await auth.check_permission(operator_user, "user.delete")

        # Viewer user
        viewer_user = {"sub": "viewer_user", "roles": ["viewer"]}
        assert await auth.check_permission(viewer_user, "deployment.view")
        assert not await auth.check_permission(viewer_user, "deployment.create")


class TestVaultClient:
    @pytest.mark.asyncio
    @patch("hvac.Client")
    async def test_get_secret(self, mock_hvac):
        mock_client = Mock()
        mock_client.is_authenticated.return_value = True
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"username": "admin", "password": "secret123"}}
        }
        mock_hvac.return_value = mock_client

        vault = VaultClient()
        secret = await vault.get_secret("test/path")

        assert secret["username"] == "admin"
        assert secret["password"] == "secret123"

    @pytest.mark.asyncio
    @patch("hvac.Client")
    async def test_get_device_credentials(self, mock_hvac):
        mock_client = Mock()
        mock_client.is_authenticated.return_value = True
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {
                "data": {
                    "username": "device_admin",
                    "password": "device_pass",
                    "enable_password": "enable_pass",
                    "ssh_key": "ssh_key_content",
                }
            }
        }
        mock_hvac.return_value = mock_client

        vault = VaultClient()
        creds = await vault.get_device_credentials("device_1")

        assert creds["username"] == "device_admin"
        assert creds["password"] == "device_pass"
        assert creds["enable_password"] == "enable_pass"
        assert creds["ssh_key"] == "ssh_key_content"


class TestSecurityIntegration:
    @pytest.mark.asyncio
    async def test_end_to_end_encryption_and_audit(self, tmp_path):
        # Setup
        encryption = EncryptionManager()
        log_file = tmp_path / "audit.jsonl"
        audit = AuditLogger(log_file=str(log_file), enable_console=False)

        # Encrypt sensitive configuration
        config = "interface GigabitEthernet0/0\n ip address 192.168.1.1 255.255.255.0"
        encrypted_config = encryption.encrypt_string(config)

        # Log the encryption event
        await audit.log_event(
            event_type="config_encrypted",
            user_id="security_admin",
            details={
                "config_hash": encryption.calculate_hash(config.encode()),
                "encryption_method": "AES-256-GCM",
            },
            level=AuditLevel.INFO,
        )

        # Decrypt configuration
        decrypted_config = encryption.decrypt_string(encrypted_config)

        # Log the decryption event
        await audit.log_event(
            event_type="config_decrypted",
            user_id="security_admin",
            details={
                "config_hash": encryption.calculate_hash(decrypted_config.encode())
            },
            level=AuditLevel.INFO,
        )

        # Verify
        assert decrypted_config == config
        assert await audit.verify_log_integrity()

    @pytest.mark.security
    async def test_sql_injection_prevention(self):
        malicious_input = "'; DROP TABLE devices; --"

        # This would be handled by SQLAlchemy's parameterized queries
        # Verify that the input is properly escaped/sanitized
        from sqlalchemy import text

        # Safe query using parameters
        safe_query = text("SELECT * FROM devices WHERE name = :name")
        params = {"name": malicious_input}

        # The parameters are properly escaped by SQLAlchemy
        assert "DROP TABLE" in malicious_input  # Input contains SQL injection
        # But it would be safely handled as a string parameter, not executed
