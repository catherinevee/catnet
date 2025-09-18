import os
import base64
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import (
    hashes,
    serialization,
    padding as crypto_padding,
)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
import hashlib
import secrets


class EncryptionManager:
    def __init__(self, key: Optional[bytes] = None):
        self.backend = default_backend()
        self.key = key or self._generate_key()

    @staticmethod
    def _generate_key() -> bytes:
        return secrets.token_bytes(32)  # 256-bit key for AES-256

    @staticmethod
    def generate_salt() -> bytes:
        return secrets.token_bytes(16)

    def derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend,
        )
        return kdf.derive(password.encode())

    def encrypt_aes_gcm(
        self, plaintext: bytes, associated_data: Optional[bytes] = None
    ) -> Tuple[bytes, bytes, bytes]:
        iv = os.urandom(12)  # 96-bit IV for GCM

        cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        if associated_data:
            encryptor.authenticate_additional_data(associated_data)

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return iv, ciphertext, encryptor.tag

    def decrypt_aes_gcm(
        self,
        iv: bytes,
        ciphertext: bytes,
        tag: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        cipher = Cipher(
            algorithms.AES(self.key), modes.GCM(iv, tag), backend=self.backend
        )
        decryptor = cipher.decryptor()

        if associated_data:
            decryptor.authenticate_additional_data(associated_data)

        return decryptor.update(ciphertext) + decryptor.finalize()

    def encrypt_string(self, plaintext: str) -> str:
        plaintext_bytes = plaintext.encode("utf-8")
        iv, ciphertext, tag = self.encrypt_aes_gcm(plaintext_bytes)

        # Combine IV, tag, and ciphertext
        combined = iv + tag + ciphertext

        # Base64 encode for storage
        return base64.b64encode(combined).decode("utf-8")

    def decrypt_string(self, encrypted_data: str) -> str:
        # Base64 decode
        combined = base64.b64decode(encrypted_data.encode("utf-8"))

        # Extract IV, tag, and ciphertext
        iv = combined[:12]
        tag = combined[12:28]
        ciphertext = combined[28:]

        # Decrypt
        plaintext_bytes = self.decrypt_aes_gcm(iv, ciphertext, tag)

        return plaintext_bytes.decode("utf-8")

    @staticmethod
    def hash_password(password: str) -> str:
        from passlib.context import CryptContext

        pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        from passlib.context import CryptContext

        pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def generate_rsa_keypair(key_size: int = 4096) -> Tuple[bytes, bytes]:
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend()
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return private_pem, public_pem

    @staticmethod
    def sign_data(data: bytes, private_key_pem: bytes) -> bytes:
        private_key = load_pem_private_key(
            private_key_pem, password=None, backend=default_backend()
        )

        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        return signature

    @staticmethod
    def verify_signature(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
        try:
            public_key = load_pem_public_key(public_key_pem, backend=default_backend())

            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    @staticmethod
    def calculate_hash(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def generate_secure_token() -> str:
        return secrets.token_urlsafe(32)
