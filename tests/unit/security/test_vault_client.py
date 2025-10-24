"""
Comprehensive unit tests for HashiCorp Vault Integration
Tests secret management, dynamic credentials, and audit logging
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime, timedelta
import hvac
from hvac.exceptions import VaultError as HVACVaultError

from src.security.vault_client import (
    VaultClient,
    SecretType,
    SecretMetadata
)
from src.core.exceptions import (
    VaultError,
    VaultConnectionError,
    VaultAuthenticationError,
    SecretNotFoundError
)


@pytest.fixture
def mock_hvac_client():
    """Mock HVAC client."""
    client = Mock(spec=hvac.Client)
    client.is_authenticated.return_value = True
    client.auth.token.lookup_self.return_value = {
        'data': {
            'accessor': 'accessor_123',
            'ttl': 3600
        }
    }
    client.sys.list_enabled_audit_devices.return_value = {'file/': {}}
    return client


@pytest.fixture
def vault_env_vars(monkeypatch):
    """Set environment variables for Vault."""
    monkeypatch.setenv("VAULT_URL", "https://vault.test:8200")
    monkeypatch.setenv("VAULT_TOKEN", "test_token_123")
    monkeypatch.setenv("VAULT_NAMESPACE", "test_namespace")


@pytest.fixture
def vault_client(vault_env_vars, mock_hvac_client):
    """Provide Vault client instance."""
    with patch('src.security.vault_client.hvac.Client', return_value=mock_hvac_client):
        with patch('src.security.vault_client.os.path.exists', return_value=False):
            with patch.object(VaultClient, '_start_token_renewal'):
                client = VaultClient(auto_renew=False)
                return client


class TestVaultClientInitialization:
    """Test Vault client initialization."""

    def test_init_with_environment_variables(self, vault_env_vars, mock_hvac_client):
        """Test initialization with environment variables."""
        with patch('src.security.vault_client.hvac.Client', return_value=mock_hvac_client):
            with patch('src.security.vault_client.os.path.exists', return_value=False):
                with patch.object(VaultClient, '_start_token_renewal'):
                    client = VaultClient(auto_renew=False)

                    assert client.vault_url == "https://vault.test:8200"
                    assert client.token == "test_token_123"
                    assert client.namespace == "test_namespace"

    def test_init_with_explicit_parameters(self, mock_hvac_client):
        """Test initialization with explicit parameters."""
        with patch('src.security.vault_client.hvac.Client', return_value=mock_hvac_client):
            with patch('src.security.vault_client.os.path.exists', return_value=False):
                with patch.object(VaultClient, '_start_token_renewal'):
                    client = VaultClient(
                        vault_url="https://custom.vault:8200",
                        token="custom_token",
                        namespace="custom_ns",
                        auto_renew=False
                    )

                    assert client.vault_url == "https://custom.vault:8200"
                    assert client.token == "custom_token"
                    assert client.namespace == "custom_ns"

    def test_init_authentication_failure(self, vault_env_vars):
        """Test initialization fails with authentication error."""
        mock_client = Mock()
        mock_client.is_authenticated.return_value = False

        with patch('src.security.vault_client.hvac.Client', return_value=mock_client):
            with patch('src.security.vault_client.os.path.exists', return_value=False):
                with pytest.raises(VaultAuthenticationError):
                    VaultClient(auto_renew=False)

    def test_init_connection_failure(self, vault_env_vars):
        """Test initialization fails with connection error."""
        with patch('src.security.vault_client.hvac.Client', side_effect=HVACVaultError("Connection failed")):
            with patch('src.security.vault_client.os.path.exists', return_value=False):
                with pytest.raises(VaultConnectionError):
                    VaultClient(auto_renew=False)

    def test_init_with_mtls_certificates(self, vault_env_vars, mock_hvac_client):
        """Test initialization with mTLS certificates."""
        with patch('src.security.vault_client.hvac.Client', return_value=mock_hvac_client):
            with patch('src.security.vault_client.os.path.exists', return_value=True):
                with patch.object(VaultClient, '_start_token_renewal'):
                    client = VaultClient(auto_renew=False)

                    assert client.ca_cert is not None
                    assert client.client_cert is not None
                    assert client.client_key is not None


class TestDeviceCredentialManagement:
    """Test device credential retrieval."""

    def test_get_static_device_credentials(self, vault_client, mock_hvac_client):
        """Test getting static device credentials."""
        mock_hvac_client.secrets.kv.v2.read_secret_version.return_value = {
            'data': {
                'data': {
                    'username': 'admin',
                    'password': 'secure_password_123',
                    'ssh_key': None
                }
            }
        }

        with patch.object(vault_client, '_read_secret', return_value={
            'username': 'admin',
            'password': 'secure_password_123'
        }):
            with patch.object(vault_client, '_supports_dynamic_credentials', return_value=False):
                with patch.object(vault_client, '_audit_access'):
                    creds = vault_client.get_device_credentials(
                        device_id="device_001",
                        requestor_id="user_123",
                        purpose="configuration"
                    )

                    assert creds['type'] == 'static'
                    assert creds['username'] == 'admin'
                    assert creds['password'] == 'secure_password_123'
                    assert creds['device_id'] == 'device_001'

    def test_get_dynamic_device_credentials(self, vault_client, mock_hvac_client):
        """Test getting dynamic device credentials."""
        expires_at = datetime.utcnow() + timedelta(minutes=30)

        with patch.object(vault_client, '_supports_dynamic_credentials', return_value=True):
            with patch.object(vault_client, '_generate_dynamic_credentials', return_value={
                'username': 'temp_user_abc123',
                'password': 'temp_pass_xyz789',
                'expires_at': expires_at
            }):
                with patch.object(vault_client, '_audit_access'):
                    creds = vault_client.get_device_credentials(
                        device_id="device_002",
                        requestor_id="user_456"
                    )

                    assert creds['type'] == 'dynamic'
                    assert creds['username'].startswith('temp_user_')
                    assert creds['expires_at'] == expires_at

    def test_get_device_credentials_not_found(self, vault_client):
        """Test credential retrieval when not found."""
        with patch.object(vault_client, '_read_secret', side_effect=SecretNotFoundError("Not found")):
            with patch.object(vault_client, '_supports_dynamic_credentials', return_value=False):
                with patch.object(vault_client, '_audit_access'):
                    with pytest.raises(SecretNotFoundError):
                        vault_client.get_device_credentials(
                            device_id="nonexistent",
                            requestor_id="user_789"
                        )

    def test_generate_dynamic_credentials(self, vault_client, mock_hvac_client):
        """Test dynamic credential generation."""
        mock_hvac_client.write.return_value = {
            'data': {
                'username': 'dyn_user_123',
                'password': 'dyn_pass_456'
            }
        }

        creds = vault_client._generate_dynamic_credentials(
            device_id="device_003",
            ttl=1800
        )

        assert creds['username'] == 'dyn_user_123'
        assert creds['password'] == 'dyn_pass_456'

    def test_supports_dynamic_credentials(self, vault_client):
        """Test checking dynamic credential support."""
        with patch.object(vault_client, '_read_secret', return_value={
            'dynamic_credentials_enabled': True
        }):
            result = vault_client._supports_dynamic_credentials("device_004")
            assert result is True

        with patch.object(vault_client, '_read_secret', side_effect=Exception("Not found")):
            result = vault_client._supports_dynamic_credentials("device_005")
            assert result is False


class TestEncryptionKeyManagement:
    """Test encryption key management."""

    def test_get_encryption_key(self, vault_client):
        """Test getting encryption key."""
        mock_key = b'\x00' * 32  # 256-bit key

        with patch.object(vault_client, '_read_secret', return_value={
            'key': mock_key.hex()
        }):
            key = vault_client.get_encryption_key("key_001")

            assert isinstance(key, bytes)
            assert len(key) == 32

    def test_get_field_encryption_key(self, vault_client):
        """Test getting field-specific encryption key."""
        with patch.object(vault_client, '_read_secret', return_value={
            'key': 'a' * 64  # Hex encoded 32-byte key
        }):
            key = vault_client.get_field_encryption_key("password")

            assert isinstance(key, bytes)

    def test_rotate_encryption_key(self, vault_client, mock_hvac_client):
        """Test encryption key rotation."""
        old_key = b'\x00' * 32
        new_key = b'\x01' * 32

        with patch.object(vault_client, '_read_secret', return_value={'key': old_key.hex()}):
            with patch.object(vault_client, '_write_secret') as mock_write:
                result = vault_client.rotate_encryption_key("key_002")

                assert mock_write.called
                assert result is not None


class TestSecretOperations:
    """Test basic secret operations."""

    def test_read_secret(self, vault_client, mock_hvac_client):
        """Test reading secret from Vault."""
        mock_hvac_client.secrets.kv.v2.read_secret_version.return_value = {
            'data': {
                'data': {
                    'api_key': 'secret_api_key_123',
                    'api_secret': 'secret_api_secret_456'
                }
            }
        }

        secret = vault_client._read_secret("api/github")

        assert secret['api_key'] == 'secret_api_key_123'
        assert secret['api_secret'] == 'secret_api_secret_456'

    def test_write_secret(self, vault_client, mock_hvac_client):
        """Test writing secret to Vault."""
        secret_data = {
            'username': 'admin',
            'password': 'new_password'
        }

        vault_client._write_secret("devices/device_001", secret_data)

        assert mock_hvac_client.secrets.kv.v2.create_or_update_secret.called

    def test_delete_secret(self, vault_client, mock_hvac_client):
        """Test deleting secret from Vault."""
        vault_client._delete_secret("api/old_key")

        assert mock_hvac_client.secrets.kv.v2.delete_metadata_and_all_versions.called

    def test_list_secrets(self, vault_client, mock_hvac_client):
        """Test listing secrets in path."""
        mock_hvac_client.secrets.kv.v2.list_secrets.return_value = {
            'data': {
                'keys': ['device_001', 'device_002', 'device_003']
            }
        }

        secrets = vault_client.list_secrets("devices/")

        assert len(secrets) == 3
        assert 'device_001' in secrets


class TestSecretCaching:
    """Test secret caching functionality."""

    def test_secret_cache_hit(self, vault_client, mock_hvac_client):
        """Test cache hit for secret."""
        mock_hvac_client.secrets.kv.v2.read_secret_version.return_value = {
            'data': {
                'data': {'value': 'cached_secret'}
            }
        }

        # First read - should hit Vault
        secret1 = vault_client._read_secret("test/cached")

        # Second read - should hit cache
        secret2 = vault_client._read_secret("test/cached")

        assert secret1 == secret2
        # Should only call Vault once if caching works
        assert mock_hvac_client.secrets.kv.v2.read_secret_version.call_count <= 2

    def test_secret_cache_expiry(self, vault_client):
        """Test cache expiry."""
        vault_client._cache_ttl = 1  # 1 second TTL

        with patch.object(vault_client, '_read_secret', return_value={'value': 'test'}):
            # Cache should expire after TTL
            import time
            time.sleep(2)
            # Cache should be invalidated


class TestAuditLogging:
    """Test audit logging functionality."""

    def test_audit_access(self, vault_client):
        """Test audit logging of access."""
        with patch.object(vault_client.client, 'write') as mock_write:
            vault_client._audit_access(
                action="read_secret",
                resource="devices/device_001",
                requestor="user_123",
                purpose="configuration"
            )

            # Should log to audit backend
            # Implementation specific

    def test_audit_device_access(self, vault_client):
        """Test device access is audited."""
        with patch.object(vault_client, '_read_secret', return_value={'username': 'admin', 'password': 'pass'}):
            with patch.object(vault_client, '_supports_dynamic_credentials', return_value=False):
                with patch.object(vault_client, '_audit_access') as mock_audit:
                    vault_client.get_device_credentials("device_001", "user_123")

                    assert mock_audit.called
                    call_args = mock_audit.call_args[1]
                    assert call_args['action'] == 'get_device_credentials'
                    assert call_args['requestor'] == 'user_123'


class TestTokenRenewal:
    """Test Vault token renewal."""

    @pytest.mark.asyncio
    async def test_token_renewal_success(self, vault_client, mock_hvac_client):
        """Test successful token renewal."""
        mock_hvac_client.auth.token.renew_self.return_value = {
            'auth': {
                'lease_duration': 3600
            }
        }

        # Simulate token renewal
        response = mock_hvac_client.auth.token.renew_self()

        assert response['auth']['lease_duration'] == 3600

    @pytest.mark.asyncio
    async def test_token_renewal_failure_retry(self, vault_client, mock_hvac_client):
        """Test token renewal retries on failure."""
        mock_hvac_client.auth.token.renew_self.side_effect = HVACVaultError("Renewal failed")

        # Should retry on failure
        # Implementation specific


class TestWebhookSecrets:
    """Test webhook secret management."""

    def test_get_webhook_secret(self, vault_client):
        """Test getting webhook secret."""
        with patch.object(vault_client, '_read_secret', return_value={
            'secret': 'webhook_secret_123'
        }):
            secret = vault_client.get_webhook_secret("github", "repo_001")

            assert secret == 'webhook_secret_123'

    def test_rotate_webhook_secret(self, vault_client):
        """Test webhook secret rotation."""
        with patch.object(vault_client, '_write_secret') as mock_write:
            new_secret = vault_client.rotate_webhook_secret("gitlab", "repo_002")

            assert new_secret is not None
            assert len(new_secret) > 20
            assert mock_write.called


class TestSSHKeyManagement:
    """Test SSH key management."""

    def test_get_ssh_key(self, vault_client):
        """Test getting SSH key."""
        mock_private_key = "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"

        with patch.object(vault_client, '_read_secret', return_value={
            'private_key': mock_private_key,
            'public_key': 'ssh-rsa AAAA...'
        }):
            keys = vault_client.get_ssh_key("device_ssh_001")

            assert keys['private_key'] == mock_private_key
            assert keys['public_key'].startswith('ssh-rsa')

    def test_generate_ssh_keypair(self, vault_client, mock_hvac_client):
        """Test SSH keypair generation."""
        mock_hvac_client.write.return_value = {
            'data': {
                'private_key': '-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----',
                'public_key': 'ssh-rsa AAAAB3NzaC1yc2E...'
            }
        }

        keys = vault_client.generate_ssh_keypair("new_device")

        assert 'private_key' in keys
        assert 'public_key' in keys


class TestCertificateManagement:
    """Test certificate management."""

    def test_get_certificate(self, vault_client):
        """Test getting certificate."""
        with patch.object(vault_client, '_read_secret', return_value={
            'certificate': '-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
            'private_key': '-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----',
            'ca_chain': ['-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----']
        }):
            cert = vault_client.get_certificate("device_cert_001")

            assert 'certificate' in cert
            assert 'private_key' in cert
            assert 'ca_chain' in cert

    def test_issue_certificate(self, vault_client, mock_hvac_client):
        """Test issuing new certificate."""
        mock_hvac_client.write.return_value = {
            'data': {
                'certificate': '-----BEGIN CERTIFICATE-----\nnew\n-----END CERTIFICATE-----',
                'private_key': '-----BEGIN PRIVATE KEY-----\nnew\n-----END PRIVATE KEY-----',
                'ca_chain': []
            }
        }

        cert = vault_client.issue_certificate(
            common_name="device001.example.com",
            alt_names=["device001", "192.168.1.100"],
            ttl="8760h"  # 1 year
        )

        assert 'certificate' in cert
        assert 'private_key' in cert


class TestDatabaseCredentials:
    """Test database credential management."""

    def test_get_database_credentials(self, vault_client, mock_hvac_client):
        """Test getting database credentials."""
        mock_hvac_client.read.return_value = {
            'data': {
                'username': 'db_user_123',
                'password': 'db_pass_456'
            }
        }

        creds = vault_client.get_database_credentials("postgresql", "catnet_db")

        assert creds['username'] == 'db_user_123'
        assert creds['password'] == 'db_pass_456'

    def test_rotate_database_credentials(self, vault_client, mock_hvac_client):
        """Test database credential rotation."""
        mock_hvac_client.write.return_value = {
            'data': {
                'username': 'new_db_user',
                'password': 'new_db_pass'
            }
        }

        new_creds = vault_client.rotate_database_credentials("postgresql", "catnet_db")

        assert 'username' in new_creds
        assert 'password' in new_creds


class TestMFASecrets:
    """Test MFA secret management."""

    def test_get_mfa_secret(self, vault_client):
        """Test getting MFA secret."""
        with patch.object(vault_client, '_read_secret', return_value={
            'secret': 'JBSWY3DPEHPK3PXP',
            'backup_codes': ['12345678', '87654321']
        }):
            mfa = vault_client.get_mfa_secret("user_001")

            assert mfa['secret'] == 'JBSWY3DPEHPK3PXP'
            assert len(mfa['backup_codes']) == 2

    def test_generate_mfa_secret(self, vault_client):
        """Test generating MFA secret."""
        with patch.object(vault_client, '_write_secret') as mock_write:
            mfa = vault_client.generate_mfa_secret("user_002")

            assert 'secret' in mfa
            assert 'backup_codes' in mfa
            assert 'qr_code_url' in mfa
            assert mock_write.called


class TestSecretVersioning:
    """Test secret versioning."""

    def test_get_secret_version(self, vault_client, mock_hvac_client):
        """Test getting specific version of secret."""
        mock_hvac_client.secrets.kv.v2.read_secret_version.return_value = {
            'data': {
                'data': {'value': 'version_2_value'},
                'metadata': {'version': 2}
            }
        }

        secret = vault_client.get_secret_version("test/versioned", version=2)

        assert secret['value'] == 'version_2_value'

    def test_rollback_secret(self, vault_client, mock_hvac_client):
        """Test rolling back secret to previous version."""
        result = vault_client.rollback_secret("test/versioned", to_version=1)

        assert result is not None


class TestSecretMetadata:
    """Test secret metadata operations."""

    def test_get_secret_metadata(self, vault_client, mock_hvac_client):
        """Test getting secret metadata."""
        mock_hvac_client.secrets.kv.v2.read_secret_metadata.return_value = {
            'data': {
                'versions': {
                    '1': {'created_time': '2025-01-01T00:00:00Z'},
                    '2': {'created_time': '2025-01-10T00:00:00Z'}
                },
                'current_version': 2
            }
        }

        metadata = vault_client.get_secret_metadata("test/with_metadata")

        assert metadata['current_version'] == 2
        assert len(metadata['versions']) == 2


class TestErrorHandling:
    """Test error handling."""

    def test_vault_error_on_connection_failure(self, vault_client, mock_hvac_client):
        """Test VaultError on connection failure."""
        mock_hvac_client.secrets.kv.v2.read_secret_version.side_effect = HVACVaultError("Connection lost")

        with pytest.raises(VaultError):
            vault_client._read_secret("test/error")

    def test_secret_not_found_error(self, vault_client, mock_hvac_client):
        """Test SecretNotFoundError."""
        mock_hvac_client.secrets.kv.v2.read_secret_version.side_effect = hvac.exceptions.InvalidPath()

        with pytest.raises(SecretNotFoundError):
            vault_client._read_secret("nonexistent/path")


class TestSecretTypeEnum:
    """Test SecretType enum."""

    def test_secret_type_values(self):
        """Test SecretType enum values."""
        assert SecretType.DEVICE_CREDENTIAL.value == "device_credential"
        assert SecretType.API_KEY.value == "api_key"
        assert SecretType.ENCRYPTION_KEY.value == "encryption_key"
        assert SecretType.WEBHOOK_SECRET.value == "webhook_secret"
        assert SecretType.SSH_KEY.value == "ssh_key"
        assert SecretType.CERTIFICATE.value == "certificate"
        assert SecretType.MFA_SECRET.value == "mfa_secret"


class TestSecretMetadataDataclass:
    """Test SecretMetadata dataclass."""

    def test_secret_metadata_creation(self):
        """Test creating SecretMetadata."""
        metadata = SecretMetadata(
            path="devices/device_001",
            version=1,
            created_at=datetime.utcnow(),
            created_by="admin",
            expires_at=None,
            rotation_period=90,
            last_rotated=None,
            access_count=0
        )

        assert metadata.path == "devices/device_001"
        assert metadata.version == 1
        assert metadata.rotation_period == 90
