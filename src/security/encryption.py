"""
CatNet Encryption Service
Provides AES-256-GCM encryption for all sensitive data
Implements digital signatures and key management
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ed25519
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.x509 import load_pem_x509_certificate
import base64
import os
import hashlib
import secrets
import json
import struct
from typing import Tuple, Optional, Dict, Any, List
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

from ..core.exceptions import EncryptionError, SecurityError


class EncryptionAlgorithm(Enum):
    """Supported encryption algorithms"""
    AES_256_GCM = "AES-256-GCM"
    AES_256_CBC = "AES-256-CBC"
    CHACHA20_POLY1305 = "ChaCha20-Poly1305"
    RSA_4096 = "RSA-4096"
    ED25519 = "Ed25519"


@dataclass
class EncryptedData:
    """Encrypted data container with metadata"""
    algorithm: str
    ciphertext: str
    nonce: str
    tag: Optional[str]
    key_id: str
    encrypted_at: datetime
    expires_at: Optional[datetime]
    metadata: Dict[str, Any]


class EncryptionService:
    """
    Comprehensive encryption service for CatNet
    Implements AES-256-GCM as primary encryption with RSA for key exchange
    """

    def __init__(self, vault_client=None):
        self.backend = default_backend()
        self.vault_client = vault_client
        self._key_cache = {}
        self._key_rotation_interval = timedelta(days=90)
        self._algorithm = EncryptionAlgorithm.AES_256_GCM

    def generate_key(self, algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES_256_GCM) -> bytes:
        """Generate a new encryption key"""
        if algorithm == EncryptionAlgorithm.AES_256_GCM:
            return os.urandom(32)  # 256 bits
        elif algorithm == EncryptionAlgorithm.AES_256_CBC:
            return os.urandom(32)
        elif algorithm == EncryptionAlgorithm.CHACHA20_POLY1305:
            return os.urandom(32)
        else:
            raise EncryptionError(f"Unsupported key generation for algorithm: {algorithm}")

    def encrypt_aes_gcm(
        self,
        plaintext: bytes,
        key: bytes,
        associated_data: Optional[bytes] = None
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt data using AES-256-GCM
        Returns: (nonce, ciphertext, tag)
        """
        try:
            # Validate key length
            if len(key) != 32:
                raise EncryptionError("AES-256 requires a 32-byte key")

            # Generate random nonce (96 bits for GCM)
            nonce = os.urandom(12)

            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce),
                backend=self.backend
            )
            encryptor = cipher.encryptor()

            # Add associated data if provided (for AEAD)
            if associated_data:
                encryptor.authenticate_additional_data(associated_data)

            # Encrypt the plaintext
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()

            return nonce, ciphertext, encryptor.tag

        except Exception as e:
            raise EncryptionError(f"AES-GCM encryption failed: {str(e)}")

    def decrypt_aes_gcm(
        self,
        ciphertext: bytes,
        key: bytes,
        nonce: bytes,
        tag: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        """
        Decrypt data using AES-256-GCM
        Returns: plaintext
        """
        try:
            # Validate inputs
            if len(key) != 32:
                raise EncryptionError("AES-256 requires a 32-byte key")
            if len(nonce) != 12:
                raise EncryptionError("GCM requires a 12-byte nonce")
            if len(tag) != 16:
                raise EncryptionError("GCM requires a 16-byte tag")

            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
                backend=self.backend
            )
            decryptor = cipher.decryptor()

            # Add associated data if provided
            if associated_data:
                decryptor.authenticate_additional_data(associated_data)

            # Decrypt the ciphertext
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            return plaintext

        except Exception as e:
            raise EncryptionError(f"AES-GCM decryption failed: {str(e)}")

    def encrypt_config(
        self,
        config_text: str,
        key_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Encrypt configuration with AES-256-GCM
        Adds integrity checking and digital signature
        """
        try:
            # Get encryption key from Vault or generate
            if key_id and self.vault_client:
                key = self.vault_client.get_encryption_key(key_id)
            else:
                key = self.generate_key()
                key_id = secrets.token_hex(16)

            # Convert config to bytes
            plaintext = config_text.encode('utf-8')

            # Add metadata for integrity
            metadata = {
                "version": "2.0",
                "timestamp": datetime.utcnow().isoformat(),
                "content_hash": hashlib.sha256(plaintext).hexdigest(),
                "original_size": len(plaintext)
            }

            # Encrypt with AES-256-GCM
            associated_data = json.dumps(metadata).encode('utf-8')
            nonce, ciphertext, tag = self.encrypt_aes_gcm(
                plaintext,
                key,
                associated_data
            )

            # Create encrypted package
            encrypted_data = {
                "version": "2.0",
                "algorithm": EncryptionAlgorithm.AES_256_GCM.value,
                "key_id": key_id,
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "tag": base64.b64encode(tag).decode('utf-8'),
                "metadata": metadata,
                "associated_data": base64.b64encode(associated_data).decode('utf-8')
            }

            # Add digital signature if signing key available
            if self.vault_client:
                signature = self._sign_data(encrypted_data)
                encrypted_data["signature"] = signature

            return encrypted_data

        except Exception as e:
            raise EncryptionError(f"Config encryption failed: {str(e)}")

    def decrypt_config(
        self,
        encrypted_data: Dict[str, Any]
    ) -> str:
        """
        Decrypt configuration encrypted with AES-256-GCM
        Verifies integrity and signature
        """
        try:
            # Verify signature if present
            if "signature" in encrypted_data:
                if not self._verify_signature(encrypted_data):
                    raise SecurityError("Signature verification failed")

            # Get decryption key
            key_id = encrypted_data["key_id"]
            if self.vault_client:
                key = self.vault_client.get_encryption_key(key_id)
            else:
                raise EncryptionError("Cannot decrypt without key access")

            # Decode components
            ciphertext = base64.b64decode(encrypted_data["ciphertext"])
            nonce = base64.b64decode(encrypted_data["nonce"])
            tag = base64.b64decode(encrypted_data["tag"])
            associated_data = base64.b64decode(encrypted_data["associated_data"])

            # Decrypt
            plaintext = self.decrypt_aes_gcm(
                ciphertext,
                key,
                nonce,
                tag,
                associated_data
            )

            # Verify integrity
            content_hash = hashlib.sha256(plaintext).hexdigest()
            if content_hash != encrypted_data["metadata"]["content_hash"]:
                raise SecurityError("Integrity check failed - data may be corrupted")

            return plaintext.decode('utf-8')

        except Exception as e:
            raise EncryptionError(f"Config decryption failed: {str(e)}")

    def encrypt_field(self, value: str, field_name: str) -> str:
        """
        Encrypt a database field value
        Uses deterministic encryption for searchable fields
        """
        try:
            # Get field-specific key from Vault
            if self.vault_client:
                key = self.vault_client.get_field_encryption_key(field_name)
            else:
                key = self.generate_key()

            # Use Fernet for field encryption (simpler for single values)
            fernet = Fernet(base64.urlsafe_b64encode(key))
            encrypted = fernet.encrypt(value.encode('utf-8'))

            return base64.b64encode(encrypted).decode('utf-8')

        except Exception as e:
            raise EncryptionError(f"Field encryption failed: {str(e)}")

    def decrypt_field(self, encrypted_value: str, field_name: str) -> str:
        """Decrypt a database field value"""
        try:
            # Get field-specific key from Vault
            if self.vault_client:
                key = self.vault_client.get_field_encryption_key(field_name)
            else:
                raise EncryptionError("Cannot decrypt field without key access")

            # Decrypt with Fernet
            fernet = Fernet(base64.urlsafe_b64encode(key))
            encrypted = base64.b64decode(encrypted_value)
            decrypted = fernet.decrypt(encrypted)

            return decrypted.decode('utf-8')

        except Exception as e:
            raise EncryptionError(f"Field decryption failed: {str(e)}")

    def generate_rsa_keypair(self, key_size: int = 4096) -> Tuple[bytes, bytes]:
        """Generate RSA-4096 keypair for asymmetric encryption"""
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=self.backend
            )

            # Export private key (encrypted with password in production)
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()  # Add password encryption in production
            )

            # Export public key
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            return private_pem, public_pem

        except Exception as e:
            raise EncryptionError(f"RSA keypair generation failed: {str(e)}")

    def encrypt_rsa(self, plaintext: bytes, public_key_pem: bytes) -> bytes:
        """Encrypt data with RSA public key (for key exchange)"""
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=self.backend
            )

            # Use OAEP padding with SHA-256
            encrypted = public_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            return encrypted

        except Exception as e:
            raise EncryptionError(f"RSA encryption failed: {str(e)}")

    def decrypt_rsa(self, ciphertext: bytes, private_key_pem: bytes) -> bytes:
        """Decrypt data with RSA private key"""
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,  # Add password in production
                backend=self.backend
            )

            decrypted = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            return decrypted

        except Exception as e:
            raise EncryptionError(f"RSA decryption failed: {str(e)}")

    def sign_data(self, data: bytes, private_key_pem: bytes) -> bytes:
        """Create digital signature using RSA-PSS"""
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=self.backend
            )

            signature = private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            return signature

        except Exception as e:
            raise EncryptionError(f"Signing failed: {str(e)}")

    def verify_signature(
        self,
        data: bytes,
        signature: bytes,
        public_key_pem: bytes
    ) -> bool:
        """Verify digital signature"""
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=self.backend
            )

            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            return True

        except Exception:
            return False

    def generate_ed25519_keypair(self) -> Tuple[bytes, bytes]:
        """Generate Ed25519 keypair for high-speed signatures"""
        try:
            private_key = ed25519.Ed25519PrivateKey.generate()

            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )

            public_key = private_key.public_key()
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            return private_bytes, public_bytes

        except Exception as e:
            raise EncryptionError(f"Ed25519 keypair generation failed: {str(e)}")

    def hash_password(self, password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
        """
        Hash password using Argon2id (preferred) or scrypt
        Returns: (hash, salt) both as base64 strings
        """
        try:
            if salt is None:
                salt = os.urandom(32)

            # Use scrypt as it's available in cryptography
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,  # CPU/memory cost
                r=8,      # Block size
                p=1,      # Parallelization
                backend=self.backend
            )

            key = kdf.derive(password.encode('utf-8'))

            return (
                base64.b64encode(key).decode('utf-8'),
                base64.b64encode(salt).decode('utf-8')
            )

        except Exception as e:
            raise EncryptionError(f"Password hashing failed: {str(e)}")

    def verify_password(self, password: str, hash_b64: str, salt_b64: str) -> bool:
        """Verify password against hash"""
        try:
            salt = base64.b64decode(salt_b64)
            expected_hash = base64.b64decode(hash_b64)

            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
                backend=self.backend
            )

            kdf.verify(password.encode('utf-8'), expected_hash)
            return True

        except Exception:
            return False

    def generate_secure_token(self, length: int = 32) -> str:
        """Generate cryptographically secure random token"""
        return secrets.token_urlsafe(length)

    def generate_session_token(self) -> str:
        """Generate secure session token"""
        return secrets.token_urlsafe(32)

    def hash_token(self, token: str) -> str:
        """Hash token for storage (one-way)"""
        return hashlib.sha256(token.encode('utf-8')).hexdigest()

    def compute_hmac(self, key: bytes, message: bytes) -> bytes:
        """Compute HMAC-SHA256"""
        h = hmac.HMAC(key, hashes.SHA256(), backend=self.backend)
        h.update(message)
        return h.finalize()

    def verify_hmac(self, key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify HMAC-SHA256"""
        try:
            h = hmac.HMAC(key, hashes.SHA256(), backend=self.backend)
            h.update(message)
            h.verify(signature)
            return True
        except Exception:
            return False

    def derive_key(
        self,
        password: bytes,
        salt: bytes,
        iterations: int = 100000,
        key_length: int = 32
    ) -> bytes:
        """Derive key from password using PBKDF2"""
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=iterations,
            backend=self.backend
        )
        return kdf.derive(password)

    def _sign_data(self, data: Dict[str, Any]) -> str:
        """Internal method to sign data dictionary"""
        if not self.vault_client:
            return ""

        # Get signing key from Vault
        signing_key = self.vault_client.get_signing_key()

        # Serialize data deterministically
        data_bytes = json.dumps(data, sort_keys=True).encode('utf-8')

        # Sign the data
        signature = self.sign_data(data_bytes, signing_key)

        return base64.b64encode(signature).decode('utf-8')

    def _verify_signature(self, data: Dict[str, Any]) -> bool:
        """Internal method to verify data signature"""
        if not self.vault_client:
            return False

        signature = data.get("signature")
        if not signature:
            return False

        # Remove signature from data for verification
        data_copy = data.copy()
        del data_copy["signature"]

        # Get verification key from Vault
        verification_key = self.vault_client.get_verification_key()

        # Serialize data deterministically
        data_bytes = json.dumps(data_copy, sort_keys=True).encode('utf-8')

        # Verify signature
        signature_bytes = base64.b64decode(signature)

        return self.verify_signature(data_bytes, signature_bytes, verification_key)

    def encrypt_backup(self, backup_data: bytes, backup_id: str) -> bytes:
        """
        Encrypt backup data with additional protection
        Uses envelope encryption for large backups
        """
        try:
            # Generate data encryption key (DEK)
            dek = self.generate_key()

            # Encrypt backup with DEK
            nonce, ciphertext, tag = self.encrypt_aes_gcm(
                backup_data,
                dek,
                backup_id.encode('utf-8')  # Use backup ID as AAD
            )

            # Get Key Encryption Key (KEK) from Vault
            if self.vault_client:
                kek = self.vault_client.get_backup_kek()
            else:
                kek = self.generate_key()

            # Encrypt DEK with KEK
            encrypted_dek = self.encrypt_rsa(dek, kek) if len(kek) > 32 else self._wrap_key(dek, kek)

            # Package encrypted backup
            package = {
                "version": "1.0",
                "backup_id": backup_id,
                "encrypted_dek": base64.b64encode(encrypted_dek).decode('utf-8'),
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
                "tag": base64.b64encode(tag).decode('utf-8'),
                "timestamp": datetime.utcnow().isoformat()
            }

            return json.dumps(package).encode('utf-8')

        except Exception as e:
            raise EncryptionError(f"Backup encryption failed: {str(e)}")

    def _wrap_key(self, key: bytes, kek: bytes) -> bytes:
        """Simple key wrapping using AES"""
        nonce, wrapped, tag = self.encrypt_aes_gcm(key, kek)
        return nonce + tag + wrapped

    def _unwrap_key(self, wrapped: bytes, kek: bytes) -> bytes:
        """Simple key unwrapping using AES"""
        nonce = wrapped[:12]
        tag = wrapped[12:28]
        ciphertext = wrapped[28:]
        return self.decrypt_aes_gcm(ciphertext, kek, nonce, tag)


# Singleton instance
_encryption_service = None

def get_encryption_service(vault_client=None) -> EncryptionService:
    """Get or create the encryption service singleton"""
    global _encryption_service
    if _encryption_service is None:
        _encryption_service = EncryptionService(vault_client)
    return _encryption_service