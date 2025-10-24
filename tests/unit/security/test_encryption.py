"""
Comprehensive unit tests for CatNet Encryption Service
Tests AES-256-GCM encryption, RSA keypair generation, digital signatures, and key management
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import base64
import os
import json
import hashlib
from datetime import datetime

from src.security.encryption import (
    EncryptionService,
    EncryptionAlgorithm,
    EncryptedData
)
from src.core.exceptions import EncryptionError, SecurityError


@pytest.fixture
def encryption_service():
    """Provide encryption service instance without Vault client."""
    return EncryptionService(vault_client=None)


@pytest.fixture
def encryption_service_with_vault():
    """Provide encryption service with mocked Vault client."""
    mock_vault = Mock()
    mock_vault.get_encryption_key = Mock(return_value=os.urandom(32))
    mock_vault.get_field_encryption_key = Mock(return_value=os.urandom(32))
    return EncryptionService(vault_client=mock_vault)


@pytest.fixture
def sample_plaintext():
    """Provide sample plaintext for testing."""
    return b"This is sensitive network configuration data"


@pytest.fixture
def sample_config_text():
    """Provide sample config text."""
    return """
interface GigabitEthernet0/1
 description WAN Connection
 ip address 192.168.1.1 255.255.255.0
 no shutdown
"""


class TestKeyGeneration:
    """Test encryption key generation."""

    def test_generate_aes_256_key(self, encryption_service):
        """Test AES-256 key generation."""
        key = encryption_service.generate_key(EncryptionAlgorithm.AES_256_GCM)

        assert isinstance(key, bytes)
        assert len(key) == 32  # 256 bits

    def test_generate_aes_cbc_key(self, encryption_service):
        """Test AES-256-CBC key generation."""
        key = encryption_service.generate_key(EncryptionAlgorithm.AES_256_CBC)

        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_generate_chacha20_key(self, encryption_service):
        """Test ChaCha20-Poly1305 key generation."""
        key = encryption_service.generate_key(EncryptionAlgorithm.CHACHA20_POLY1305)

        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_generate_key_unsupported_algorithm(self, encryption_service):
        """Test key generation with unsupported algorithm raises error."""
        with pytest.raises(EncryptionError) as exc_info:
            encryption_service.generate_key(EncryptionAlgorithm.RSA_4096)

        assert "Unsupported key generation" in str(exc_info.value)

    def test_generated_keys_are_unique(self, encryption_service):
        """Test that generated keys are cryptographically random and unique."""
        key1 = encryption_service.generate_key()
        key2 = encryption_service.generate_key()

        assert key1 != key2


class TestAESGCMEncryption:
    """Test AES-256-GCM encryption and decryption."""

    def test_encrypt_aes_gcm_success(self, encryption_service, sample_plaintext):
        """Test successful AES-GCM encryption."""
        key = encryption_service.generate_key()

        nonce, ciphertext, tag = encryption_service.encrypt_aes_gcm(
            plaintext=sample_plaintext,
            key=key
        )

        assert isinstance(nonce, bytes)
        assert len(nonce) == 12  # 96 bits for GCM
        assert isinstance(ciphertext, bytes)
        assert len(ciphertext) > 0
        assert isinstance(tag, bytes)
        assert len(tag) == 16  # 128 bits authentication tag

    def test_decrypt_aes_gcm_success(self, encryption_service, sample_plaintext):
        """Test successful AES-GCM decryption."""
        key = encryption_service.generate_key()
        nonce, ciphertext, tag = encryption_service.encrypt_aes_gcm(sample_plaintext, key)

        decrypted = encryption_service.decrypt_aes_gcm(
            ciphertext=ciphertext,
            key=key,
            nonce=nonce,
            tag=tag
        )

        assert decrypted == sample_plaintext

    def test_encrypt_aes_gcm_with_associated_data(self, encryption_service, sample_plaintext):
        """Test AES-GCM encryption with associated data (AEAD)."""
        key = encryption_service.generate_key()
        associated_data = b"metadata:device=router1"

        nonce, ciphertext, tag = encryption_service.encrypt_aes_gcm(
            plaintext=sample_plaintext,
            key=key,
            associated_data=associated_data
        )

        # Decrypt with correct associated data
        decrypted = encryption_service.decrypt_aes_gcm(
            ciphertext=ciphertext,
            key=key,
            nonce=nonce,
            tag=tag,
            associated_data=associated_data
        )

        assert decrypted == sample_plaintext

    def test_decrypt_fails_with_wrong_associated_data(self, encryption_service, sample_plaintext):
        """Test decryption fails when associated data doesn't match."""
        key = encryption_service.generate_key()
        associated_data = b"metadata:device=router1"

        nonce, ciphertext, tag = encryption_service.encrypt_aes_gcm(
            plaintext=sample_plaintext,
            key=key,
            associated_data=associated_data
        )

        # Try to decrypt with wrong associated data
        wrong_associated_data = b"metadata:device=router2"

        with pytest.raises(EncryptionError) as exc_info:
            encryption_service.decrypt_aes_gcm(
                ciphertext=ciphertext,
                key=key,
                nonce=nonce,
                tag=tag,
                associated_data=wrong_associated_data
            )

        assert "decryption failed" in str(exc_info.value).lower()

    def test_encrypt_with_invalid_key_length(self, encryption_service):
        """Test encryption fails with invalid key length."""
        invalid_key = os.urandom(16)  # Only 128 bits, need 256

        with pytest.raises(EncryptionError) as exc_info:
            encryption_service.encrypt_aes_gcm(
                plaintext=b"test",
                key=invalid_key
            )

        assert "32-byte key" in str(exc_info.value)

    def test_decrypt_with_invalid_key_length(self, encryption_service):
        """Test decryption fails with invalid key length."""
        invalid_key = os.urandom(16)

        with pytest.raises(EncryptionError) as exc_info:
            encryption_service.decrypt_aes_gcm(
                ciphertext=b"test",
                key=invalid_key,
                nonce=os.urandom(12),
                tag=os.urandom(16)
            )

        assert "32-byte key" in str(exc_info.value)

    def test_decrypt_with_invalid_nonce_length(self, encryption_service):
        """Test decryption fails with invalid nonce length."""
        key = encryption_service.generate_key()
        invalid_nonce = os.urandom(8)  # Should be 12 bytes

        with pytest.raises(EncryptionError) as exc_info:
            encryption_service.decrypt_aes_gcm(
                ciphertext=b"test",
                key=key,
                nonce=invalid_nonce,
                tag=os.urandom(16)
            )

        assert "12-byte nonce" in str(exc_info.value)

    def test_decrypt_with_invalid_tag_length(self, encryption_service):
        """Test decryption fails with invalid tag length."""
        key = encryption_service.generate_key()
        invalid_tag = os.urandom(8)  # Should be 16 bytes

        with pytest.raises(EncryptionError) as exc_info:
            encryption_service.decrypt_aes_gcm(
                ciphertext=b"test",
                key=key,
                nonce=os.urandom(12),
                tag=invalid_tag
            )

        assert "16-byte tag" in str(exc_info.value)

    def test_decrypt_with_wrong_key(self, encryption_service, sample_plaintext):
        """Test decryption fails with wrong key."""
        key1 = encryption_service.generate_key()
        key2 = encryption_service.generate_key()

        nonce, ciphertext, tag = encryption_service.encrypt_aes_gcm(sample_plaintext, key1)

        with pytest.raises(EncryptionError):
            encryption_service.decrypt_aes_gcm(ciphertext, key2, nonce, tag)

    def test_decrypt_with_tampered_ciphertext(self, encryption_service, sample_plaintext):
        """Test decryption fails with tampered ciphertext."""
        key = encryption_service.generate_key()
        nonce, ciphertext, tag = encryption_service.encrypt_aes_gcm(sample_plaintext, key)

        # Tamper with ciphertext
        tampered_ciphertext = bytearray(ciphertext)
        tampered_ciphertext[0] ^= 0xFF
        tampered_ciphertext = bytes(tampered_ciphertext)

        with pytest.raises(EncryptionError):
            encryption_service.decrypt_aes_gcm(tampered_ciphertext, key, nonce, tag)


class TestConfigEncryption:
    """Test configuration encryption and decryption."""

    def test_encrypt_config_without_vault(self, encryption_service, sample_config_text):
        """Test config encryption without Vault client."""
        encrypted = encryption_service.encrypt_config(sample_config_text)

        assert encrypted["version"] == "2.0"
        assert encrypted["algorithm"] == "AES-256-GCM"
        assert "ciphertext" in encrypted
        assert "nonce" in encrypted
        assert "tag" in encrypted
        assert "key_id" in encrypted
        assert "metadata" in encrypted

    def test_encrypt_config_with_vault(self, encryption_service_with_vault, sample_config_text):
        """Test config encryption with Vault client."""
        key_id = "test-key-id"

        encrypted = encryption_service_with_vault.encrypt_config(
            sample_config_text,
            key_id=key_id
        )

        assert encrypted["key_id"] == key_id
        assert encryption_service_with_vault.vault_client.get_encryption_key.called

    def test_encrypt_config_includes_integrity_hash(self, encryption_service, sample_config_text):
        """Test encrypted config includes integrity hash."""
        encrypted = encryption_service.encrypt_config(sample_config_text)

        metadata = encrypted["metadata"]
        assert "content_hash" in metadata
        assert "original_size" in metadata
        assert "timestamp" in metadata

        # Verify hash is correct
        expected_hash = hashlib.sha256(sample_config_text.encode('utf-8')).hexdigest()
        assert metadata["content_hash"] == expected_hash

    def test_decrypt_config_success(self, encryption_service_with_vault, sample_config_text):
        """Test successful config decryption."""
        encrypted = encryption_service_with_vault.encrypt_config(sample_config_text)

        decrypted = encryption_service_with_vault.decrypt_config(encrypted)

        assert decrypted == sample_config_text

    def test_decrypt_config_without_vault_fails(self, encryption_service, sample_config_text):
        """Test decryption without Vault client fails."""
        encrypted = encryption_service.encrypt_config(sample_config_text)

        with pytest.raises(EncryptionError) as exc_info:
            encryption_service.decrypt_config(encrypted)

        assert "Cannot decrypt without key access" in str(exc_info.value)

    def test_decrypt_config_verifies_integrity(self, encryption_service_with_vault, sample_config_text):
        """Test decryption verifies data integrity."""
        encrypted = encryption_service_with_vault.encrypt_config(sample_config_text)

        # Tamper with metadata hash
        encrypted["metadata"]["content_hash"] = "0" * 64

        with pytest.raises(EncryptionError) as exc_info:
            encryption_service_with_vault.decrypt_config(encrypted)

        assert "Integrity check failed" in str(exc_info.value)

    def test_encrypt_config_with_empty_string(self, encryption_service):
        """Test encrypting empty config."""
        encrypted = encryption_service.encrypt_config("")

        assert "ciphertext" in encrypted
        assert encrypted["metadata"]["original_size"] == 0


class TestFieldEncryption:
    """Test database field encryption."""

    def test_encrypt_field_with_vault(self, encryption_service_with_vault):
        """Test encrypting database field."""
        field_value = "sensitive_password_123"
        field_name = "password"

        encrypted = encryption_service_with_vault.encrypt_field(field_value, field_name)

        assert isinstance(encrypted, str)
        assert encrypted != field_value
        assert len(encrypted) > len(field_value)

    def test_decrypt_field_with_vault(self, encryption_service_with_vault):
        """Test decrypting database field."""
        field_value = "api_key_xyz789"
        field_name = "api_key"

        encrypted = encryption_service_with_vault.encrypt_field(field_value, field_name)
        decrypted = encryption_service_with_vault.decrypt_field(encrypted, field_name)

        assert decrypted == field_value

    def test_decrypt_field_without_vault_fails(self, encryption_service):
        """Test decrypting field without Vault fails."""
        encrypted_value = "some_encrypted_value"

        with pytest.raises(EncryptionError) as exc_info:
            encryption_service.decrypt_field(encrypted_value, "password")

        assert "Cannot decrypt field without key access" in str(exc_info.value)

    def test_field_encryption_is_deterministic_per_field(self, encryption_service_with_vault):
        """Test field encryption produces consistent results for same field."""
        field_value = "test_value"
        field_name = "username"

        # Since we use Fernet with same key, two encryptions will differ due to timestamp/IV
        encrypted1 = encryption_service_with_vault.encrypt_field(field_value, field_name)
        encrypted2 = encryption_service_with_vault.encrypt_field(field_value, field_name)

        # They should be different due to Fernet's IV
        # But both should decrypt to same value
        decrypted1 = encryption_service_with_vault.decrypt_field(encrypted1, field_name)
        decrypted2 = encryption_service_with_vault.decrypt_field(encrypted2, field_name)

        assert decrypted1 == field_value
        assert decrypted2 == field_value


class TestRSAEncryption:
    """Test RSA asymmetric encryption."""

    def test_generate_rsa_keypair(self, encryption_service):
        """Test RSA keypair generation."""
        private_pem, public_pem = encryption_service.generate_rsa_keypair(key_size=2048)

        assert isinstance(private_pem, bytes)
        assert isinstance(public_pem, bytes)
        assert b"BEGIN PRIVATE KEY" in private_pem
        assert b"BEGIN PUBLIC KEY" in public_pem

    def test_generate_rsa_4096_keypair(self, encryption_service):
        """Test generating RSA-4096 keypair."""
        private_pem, public_pem = encryption_service.generate_rsa_keypair(key_size=4096)

        assert len(private_pem) > 3000  # 4096-bit keys are larger
        assert len(public_pem) > 500

    def test_rsa_encrypt_decrypt(self, encryption_service):
        """Test RSA encryption and decryption."""
        private_pem, public_pem = encryption_service.generate_rsa_keypair(key_size=2048)
        plaintext = b"Symmetric encryption key: " + os.urandom(32)

        encrypted = encryption_service.encrypt_rsa(plaintext, public_pem)
        decrypted = encryption_service.decrypt_rsa(encrypted, private_pem)

        assert decrypted == plaintext

    def test_rsa_encryption_size_limit(self, encryption_service):
        """Test RSA encryption has size limits."""
        private_pem, public_pem = encryption_service.generate_rsa_keypair(key_size=2048)

        # RSA-2048 with OAEP can encrypt up to 190 bytes
        # Try encrypting data that's too large
        large_plaintext = b"X" * 500

        with pytest.raises(EncryptionError):
            encryption_service.encrypt_rsa(large_plaintext, public_pem)

    def test_rsa_decrypt_with_wrong_key_fails(self, encryption_service):
        """Test RSA decryption fails with wrong key."""
        private_pem1, public_pem1 = encryption_service.generate_rsa_keypair(key_size=2048)
        private_pem2, public_pem2 = encryption_service.generate_rsa_keypair(key_size=2048)

        plaintext = b"secret data"
        encrypted = encryption_service.encrypt_rsa(plaintext, public_pem1)

        with pytest.raises(EncryptionError):
            encryption_service.decrypt_rsa(encrypted, private_pem2)


class TestDigitalSignatures:
    """Test digital signature creation and verification."""

    def test_sign_data(self, encryption_service):
        """Test creating digital signature."""
        private_pem, public_pem = encryption_service.generate_rsa_keypair(key_size=2048)
        data = b"Important configuration data to sign"

        signature = encryption_service.sign_data(data, private_pem)

        assert isinstance(signature, bytes)
        assert len(signature) == 256  # RSA-2048 signature is 256 bytes

    def test_verify_signature(self, encryption_service):
        """Test verifying valid signature."""
        private_pem, public_pem = encryption_service.generate_rsa_keypair(key_size=2048)
        data = b"Data to be signed"

        signature = encryption_service.sign_data(data, private_pem)
        is_valid = encryption_service.verify_signature(data, signature, public_pem)

        assert is_valid is True

    def test_verify_signature_fails_with_tampered_data(self, encryption_service):
        """Test signature verification fails with tampered data."""
        private_pem, public_pem = encryption_service.generate_rsa_keypair(key_size=2048)
        data = b"Original data"

        signature = encryption_service.sign_data(data, private_pem)

        # Tamper with data
        tampered_data = b"Tampered data"
        is_valid = encryption_service.verify_signature(tampered_data, signature, public_pem)

        assert is_valid is False

    def test_verify_signature_fails_with_wrong_public_key(self, encryption_service):
        """Test signature verification fails with wrong public key."""
        private_pem1, public_pem1 = encryption_service.generate_rsa_keypair(key_size=2048)
        private_pem2, public_pem2 = encryption_service.generate_rsa_keypair(key_size=2048)
        data = b"Signed data"

        signature = encryption_service.sign_data(data, private_pem1)
        is_valid = encryption_service.verify_signature(data, signature, public_pem2)

        assert is_valid is False

    def test_sign_empty_data(self, encryption_service):
        """Test signing empty data."""
        private_pem, public_pem = encryption_service.generate_rsa_keypair(key_size=2048)
        data = b""

        signature = encryption_service.sign_data(data, private_pem)
        is_valid = encryption_service.verify_signature(data, signature, public_pem)

        assert is_valid is True


class TestEncryptionErrors:
    """Test error handling in encryption operations."""

    def test_encrypt_with_none_plaintext(self, encryption_service):
        """Test encryption handles None input gracefully."""
        key = encryption_service.generate_key()

        with pytest.raises((EncryptionError, TypeError, AttributeError)):
            encryption_service.encrypt_aes_gcm(None, key)

    def test_decrypt_with_corrupted_base64(self, encryption_service_with_vault):
        """Test decryption handles corrupted base64 encoding."""
        corrupted_data = {
            "version": "2.0",
            "algorithm": "AES-256-GCM",
            "key_id": "test-key",
            "ciphertext": "not-valid-base64!!!",
            "nonce": "also-invalid!!!",
            "tag": "bad-base64!!!",
            "associated_data": "corrupted!!!",
            "metadata": {"content_hash": "abc123"}
        }

        with pytest.raises(EncryptionError):
            encryption_service_with_vault.decrypt_config(corrupted_data)


class TestEncryptionServiceInitialization:
    """Test encryption service initialization."""

    def test_init_without_vault(self):
        """Test initialization without Vault client."""
        service = EncryptionService(vault_client=None)

        assert service.vault_client is None
        assert service._algorithm == EncryptionAlgorithm.AES_256_GCM

    def test_init_with_vault(self):
        """Test initialization with Vault client."""
        mock_vault = Mock()
        service = EncryptionService(vault_client=mock_vault)

        assert service.vault_client is mock_vault

    def test_service_uses_default_backend(self, encryption_service):
        """Test service uses cryptography default backend."""
        assert encryption_service.backend is not None


class TestEncryptionEdgeCases:
    """Test edge cases in encryption operations."""

    def test_encrypt_large_config(self, encryption_service):
        """Test encrypting large configuration."""
        large_config = "config line\n" * 100000  # ~1MB of config

        encrypted = encryption_service.encrypt_config(large_config)

        assert "ciphertext" in encrypted
        assert encrypted["metadata"]["original_size"] == len(large_config.encode('utf-8'))

    def test_encrypt_unicode_config(self, encryption_service):
        """Test encrypting config with Unicode characters."""
        unicode_config = "Configuration with émojis 🔐 and spëciål çhars"

        encrypted = encryption_service.encrypt_config(unicode_config)

        assert "ciphertext" in encrypted

    def test_encrypt_config_with_special_characters(self, encryption_service):
        """Test encrypting config with special characters."""
        special_config = "Config with null\x00byte and\ttabs\nand\rnewlines"

        encrypted = encryption_service.encrypt_config(special_config)

        assert encrypted["metadata"]["original_size"] == len(special_config.encode('utf-8'))
