"""
HashiCorp Vault Integration Service for CatNet

Handles:
- Secret storage and retrieval
- Dynamic credentials generation
- Encryption as a service
- Certificate management
- Key rotation
"""

from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import asyncio
import json
import base64
from pathlib import Path
import hvac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
import os


class SecretType(Enum):
    """Types of secrets"""

    STATIC = "static"
    DYNAMIC = "dynamic"
    ROTATING = "rotating"
    CERTIFICATE = "certificate"
    ENCRYPTION_KEY = "encryption_key"


class SecretEngine(Enum):
    """Vault secret engines"""

    KV = "kv"  # Key-Value store
    DATABASE = "database"  # Dynamic database credentials
    PKI = "pki"  # Public Key Infrastructure
    TRANSIT = "transit"  # Encryption as a service
    SSH = "ssh"  # SSH credentials
    AWS = "aws"  # AWS credentials
    AZURE = "azure"  # Azure credentials


@dataclass
class Secret:
    """Secret object"""

    path: str
    key: str
    value: Any
    type: SecretType
    engine: SecretEngine
    version: int = 1
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    rotation_period: Optional[timedelta] = None


@dataclass
class EncryptionKey:
    """Encryption key object"""

    key_id: str
    key_material: bytes
    algorithm: str
    created_at: datetime
    rotated_at: Optional[datetime] = None
    version: int = 1
    active: bool = True


@dataclass
class Certificate:
    """Certificate object"""

    cert_id: str
    common_name: str
    certificate: str
    private_key: str
    ca_chain: Optional[str] = None
    serial_number: str = ""
    issued_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    revoked: bool = False


class VaultService:
    """
    HashiCorp Vault integration service
    """

    def __init__(
        self,
        vault_url: str = "http://localhost:8200",
        vault_token: Optional[str] = None,
        vault_namespace: Optional[str] = None,
        use_tls: bool = True,
    ):
        """
        Initialize Vault service

        Args:
            vault_url: Vault server URL
            vault_token: Vault token
            vault_namespace: Vault namespace
            use_tls: Use TLS for connection
        """
        self.vault_url = vault_url
        self.vault_namespace = vault_namespace
        self.use_tls = use_tls

        # Initialize Vault client
        self.client = hvac.Client(
            url=vault_url,
            token=vault_token,
            namespace=vault_namespace,
            verify=use_tls,
        )

        # Cache for frequently accessed secrets
        self.secret_cache: Dict[str, Tuple[Secret, datetime]] = {}
        self.cache_ttl = timedelta(minutes=5)

        # Encryption keys
        self.encryption_keys: Dict[str, EncryptionKey] = {}
        self.current_key_id: Optional[str] = None

        # Audit log
        self.audit_log: List[Dict[str, Any]] = []

    async def initialize(self) -> bool:
        """
        Initialize Vault connection and setup

        Returns:
            Success status
        """
        try:
            # Check if Vault is initialized and unsealed
            if not self.client.sys.is_initialized():
                # Initialize Vault (only in dev/test)
                result = self.client.sys.initialize(
                    secret_shares=5,
                    secret_threshold=3,
                )
                # Store keys securely (not shown here)
                print(f"Vault initialized: {result}")

            if self.client.sys.is_sealed():
                # Unseal Vault (would use stored keys)
                print("Vault is sealed, needs unsealing")
                return False

            # Enable required secret engines
            await self._enable_secret_engines()

            # Setup encryption keys
            await self._setup_encryption_keys()

            # Configure audit
            await self._configure_audit()

            return True

        except Exception as e:
            print(f"Vault initialization failed: {e}")
            return False

    async def _enable_secret_engines(self):
        """Enable required secret engines"""
        engines = [
            ("secret/", SecretEngine.KV),
            ("database/", SecretEngine.DATABASE),
            ("pki/", SecretEngine.PKI),
            ("transit/", SecretEngine.TRANSIT),
            ("ssh/", SecretEngine.SSH),
        ]

        for path, engine in engines:
            try:
                self.client.sys.enable_secrets_engine(
                    backend_type=engine.value,
                    path=path,
                )
            except Exception:
                # Engine might already be enabled
                pass

    async def _setup_encryption_keys(self):
        """Setup encryption keys"""
        # Generate master encryption key
        key_id = "master-key-1"
        key_material = os.urandom(32)  # 256-bit key

        self.encryption_keys[key_id] = EncryptionKey(
            key_id=key_id,
            key_material=key_material,
            algorithm="AES-256-GCM",
            created_at=datetime.utcnow(),
        )
        self.current_key_id = key_id

    async def _configure_audit(self):
        """Configure audit logging"""
        try:
            self.client.sys.enable_audit_device(
                device_type="file",
                path="file/",
                options={"file_path": "/vault/logs/audit.log"},
            )
        except Exception:
            # Audit might already be enabled
            pass

    # Secret Management

    async def store_secret(
        self,
        path: str,
        key: str,
        value: Any,
        secret_type: SecretType = SecretType.STATIC,
        engine: SecretEngine = SecretEngine.KV,
        metadata: Optional[Dict[str, Any]] = None,
        ttl: Optional[timedelta] = None,
    ) -> bool:
        """
        Store a secret in Vault

        Args:
            path: Secret path
            key: Secret key
            value: Secret value
            secret_type: Type of secret
            engine: Secret engine to use
            metadata: Additional metadata
            ttl: Time to live

        Returns:
            Success status
        """
        try:
            # Prepare secret data
            secret_data = {
                key: value,
                "type": secret_type.value,
                "metadata": metadata or {},
                "created_at": datetime.utcnow().isoformat(),
            }

            # Add TTL if specified
            if ttl:
                secret_data["ttl"] = int(ttl.total_seconds())
                secret_data["expires_at"] = (
                    datetime.utcnow() + ttl
                ).isoformat()

            # Store in Vault
            if engine == SecretEngine.KV:
                self.client.secrets.kv.v2.create_or_update_secret(
                    path=path,
                    secret=secret_data,
                    mount_point="secret",
                )
            else:
                # Handle other engines
                pass

            # Clear cache for this path
            cache_key = f"{path}:{key}"
            if cache_key in self.secret_cache:
                del self.secret_cache[cache_key]

            # Audit log
            self._audit_log("store_secret", path, key, success=True)

            return True

        except Exception as e:
            self._audit_log("store_secret", path, key, success=False, error=str(e))
            raise

    async def get_secret(
        self,
        path: str,
        key: Optional[str] = None,
        version: Optional[int] = None,
        use_cache: bool = True,
    ) -> Optional[Secret]:
        """
        Retrieve a secret from Vault

        Args:
            path: Secret path
            key: Secret key (optional, returns all if not specified)
            version: Secret version
            use_cache: Use cached value if available

        Returns:
            Secret object or None
        """
        try:
            cache_key = f"{path}:{key or '*'}"

            # Check cache
            if use_cache and cache_key in self.secret_cache:
                cached_secret, cached_time = self.secret_cache[cache_key]
                if datetime.utcnow() - cached_time < self.cache_ttl:
                    return cached_secret

            # Retrieve from Vault
            response = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                version=version,
                mount_point="secret",
            )

            if not response or "data" not in response:
                return None

            secret_data = response["data"]["data"]

            # Extract specific key or return all
            if key and key in secret_data:
                value = secret_data[key]
            else:
                value = secret_data

            # Create Secret object
            secret = Secret(
                path=path,
                key=key or "*",
                value=value,
                type=SecretType(secret_data.get("type", "static")),
                engine=SecretEngine.KV,
                version=response["data"]["metadata"]["version"],
                created_at=datetime.fromisoformat(
                    secret_data.get("created_at", datetime.utcnow().isoformat())
                ),
                metadata=secret_data.get("metadata", {}),
            )

            # Cache the secret
            self.secret_cache[cache_key] = (secret, datetime.utcnow())

            # Audit log
            self._audit_log("get_secret", path, key, success=True)

            return secret

        except Exception as e:
            self._audit_log("get_secret", path, key, success=False, error=str(e))
            return None

    async def delete_secret(
        self, path: str, versions: Optional[List[int]] = None
    ) -> bool:
        """
        Delete a secret from Vault

        Args:
            path: Secret path
            versions: Specific versions to delete

        Returns:
            Success status
        """
        try:
            if versions:
                # Delete specific versions
                self.client.secrets.kv.v2.delete_secret_versions(
                    path=path,
                    versions=versions,
                    mount_point="secret",
                )
            else:
                # Delete all versions
                self.client.secrets.kv.v2.delete_metadata_and_all_versions(
                    path=path,
                    mount_point="secret",
                )

            # Clear cache
            keys_to_remove = [k for k in self.secret_cache if k.startswith(f"{path}:")]
            for key in keys_to_remove:
                del self.secret_cache[key]

            # Audit log
            self._audit_log("delete_secret", path, versions=versions, success=True)

            return True

        except Exception as e:
            self._audit_log("delete_secret", path, success=False, error=str(e))
            return False

    # Dynamic Credentials

    async def generate_database_credentials(
        self,
        database: str,
        role: str,
        ttl: timedelta = timedelta(hours=1),
    ) -> Optional[Dict[str, str]]:
        """
        Generate dynamic database credentials

        Args:
            database: Database name
            role: Database role
            ttl: Credential lifetime

        Returns:
            Credentials dictionary
        """
        try:
            response = self.client.read(
                f"database/creds/{role}",
                ttl=int(ttl.total_seconds()),
            )

            if response and "data" in response:
                creds = {
                    "username": response["data"]["username"],
                    "password": response["data"]["password"],
                    "expires_at": (datetime.utcnow() + ttl).isoformat(),
                }

                # Audit log
                self._audit_log(
                    "generate_db_creds",
                    database,
                    role,
                    success=True
                )

                return creds

            return None

        except Exception as e:
            self._audit_log(
                "generate_db_creds",
                database,
                role,
                success=False,
                error=str(e)
            )
            return None

    async def generate_ssh_credentials(
        self,
        role: str,
        username: str,
        ip: str,
        ttl: timedelta = timedelta(hours=1),
    ) -> Optional[Dict[str, str]]:
        """
        Generate SSH credentials

        Args:
            role: SSH role
            username: SSH username
            ip: Target IP address
            ttl: Credential lifetime

        Returns:
            SSH credentials
        """
        try:
            response = self.client.write(
                f"ssh/creds/{role}",
                username=username,
                ip=ip,
                ttl=int(ttl.total_seconds()),
            )

            if response and "data" in response:
                return {
                    "key": response["data"]["key"],
                    "key_type": response["data"]["key_type"],
                    "username": username,
                    "ip": ip,
                    "expires_at": (datetime.utcnow() + ttl).isoformat(),
                }

            return None

        except Exception as e:
            self._audit_log(
                "generate_ssh_creds",
                role,
                username,
                success=False,
                error=str(e)
            )
            return None

    # Encryption Services

    async def encrypt_data(
        self,
        data: bytes,
        key_id: Optional[str] = None,
    ) -> Tuple[bytes, str]:
        """
        Encrypt data using Vault's transit engine

        Args:
            data: Data to encrypt
            key_id: Encryption key ID

        Returns:
            Tuple of (encrypted data, key ID used)
        """
        try:
            # Use current key if not specified
            key_id = key_id or self.current_key_id

            if self.use_tls and self.client.is_authenticated():
                # Use Vault's transit engine
                plaintext = base64.b64encode(data).decode("utf-8")
                response = self.client.write(
                    "transit/encrypt/catnet",
                    plaintext=plaintext,
                )

                if response and "data" in response:
                    ciphertext = response["data"]["ciphertext"]
                    return base64.b64decode(ciphertext), key_id
            else:
                # Fallback to local encryption
                return self._local_encrypt(data, key_id), key_id

        except Exception as e:
            raise Exception(f"Encryption failed: {e}")

    async def decrypt_data(
        self,
        encrypted_data: bytes,
        key_id: str,
    ) -> bytes:
        """
        Decrypt data

        Args:
            encrypted_data: Encrypted data
            key_id: Encryption key ID

        Returns:
            Decrypted data
        """
        try:
            if self.use_tls and self.client.is_authenticated():
                # Use Vault's transit engine
                ciphertext = base64.b64encode(encrypted_data).decode("utf-8")
                response = self.client.write(
                    "transit/decrypt/catnet",
                    ciphertext=ciphertext,
                )

                if response and "data" in response:
                    plaintext = response["data"]["plaintext"]
                    return base64.b64decode(plaintext)
            else:
                # Fallback to local decryption
                return self._local_decrypt(encrypted_data, key_id)

        except Exception as e:
            raise Exception(f"Decryption failed: {e}")

    def _local_encrypt(self, data: bytes, key_id: str) -> bytes:
        """Local encryption fallback"""
        if key_id not in self.encryption_keys:
            raise ValueError(f"Unknown key ID: {key_id}")

        key = self.encryption_keys[key_id]
        iv = os.urandom(12)  # 96-bit IV for GCM

        cipher = Cipher(
            algorithms.AES(key.key_material),
            modes.GCM(iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()

        # Return IV + ciphertext + tag
        return iv + ciphertext + encryptor.tag

    def _local_decrypt(self, encrypted_data: bytes, key_id: str) -> bytes:
        """Local decryption fallback"""
        if key_id not in self.encryption_keys:
            raise ValueError(f"Unknown key ID: {key_id}")

        key = self.encryption_keys[key_id]

        # Extract IV, ciphertext, and tag
        iv = encrypted_data[:12]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[12:-16]

        cipher = Cipher(
            algorithms.AES(key.key_material),
            modes.GCM(iv, tag),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    # Certificate Management

    async def issue_certificate(
        self,
        common_name: str,
        alt_names: Optional[List[str]] = None,
        ttl: timedelta = timedelta(days=365),
    ) -> Optional[Certificate]:
        """
        Issue a certificate

        Args:
            common_name: Certificate common name
            alt_names: Alternative names
            ttl: Certificate lifetime

        Returns:
            Certificate object
        """
        try:
            response = self.client.write(
                "pki/issue/catnet",
                common_name=common_name,
                alt_names=",".join(alt_names) if alt_names else None,
                ttl=int(ttl.total_seconds()),
            )

            if response and "data" in response:
                cert_data = response["data"]
                return Certificate(
                    cert_id=cert_data.get("serial_number", ""),
                    common_name=common_name,
                    certificate=cert_data["certificate"],
                    private_key=cert_data["private_key"],
                    ca_chain=cert_data.get("ca_chain"),
                    serial_number=cert_data.get("serial_number", ""),
                    expires_at=datetime.utcnow() + ttl,
                )

            return None

        except Exception as e:
            self._audit_log(
                "issue_certificate",
                common_name,
                success=False,
                error=str(e)
            )
            return None

    async def revoke_certificate(self, serial_number: str) -> bool:
        """
        Revoke a certificate

        Args:
            serial_number: Certificate serial number

        Returns:
            Success status
        """
        try:
            self.client.write(
                "pki/revoke",
                serial_number=serial_number,
            )

            self._audit_log("revoke_certificate", serial_number, success=True)
            return True

        except Exception as e:
            self._audit_log(
                "revoke_certificate",
                serial_number,
                success=False,
                error=str(e)
            )
            return False

    # Key Rotation

    async def rotate_encryption_key(self) -> str:
        """
        Rotate encryption key

        Returns:
            New key ID
        """
        try:
            # Generate new key
            new_key_id = f"key-{datetime.utcnow().timestamp()}"
            new_key_material = os.urandom(32)

            # Store new key
            self.encryption_keys[new_key_id] = EncryptionKey(
                key_id=new_key_id,
                key_material=new_key_material,
                algorithm="AES-256-GCM",
                created_at=datetime.utcnow(),
                version=len(self.encryption_keys) + 1,
            )

            # Mark old key as rotated
            if self.current_key_id:
                old_key = self.encryption_keys[self.current_key_id]
                old_key.rotated_at = datetime.utcnow()
                old_key.active = False

            # Update current key
            self.current_key_id = new_key_id

            # Audit log
            self._audit_log("rotate_key", new_key_id, success=True)

            return new_key_id

        except Exception as e:
            self._audit_log("rotate_key", success=False, error=str(e))
            raise

    async def rotate_secret(
        self,
        path: str,
        key: str,
        new_value: Any,
    ) -> bool:
        """
        Rotate a secret

        Args:
            path: Secret path
            key: Secret key
            new_value: New secret value

        Returns:
            Success status
        """
        try:
            # Get current secret
            current = await self.get_secret(path, key)

            # Store new version
            success = await self.store_secret(
                path=path,
                key=key,
                value=new_value,
                secret_type=current.type if current else SecretType.ROTATING,
                metadata={
                    "rotated_at": datetime.utcnow().isoformat(),
                    "previous_version": current.version if current else 0,
                },
            )

            if success and current:
                # Schedule deletion of old version
                asyncio.create_task(
                    self._schedule_version_deletion(
                        path,
                        [current.version],
                        delay=timedelta(days=7),
                    )
                )

            return success

        except Exception as e:
            self._audit_log(
                "rotate_secret",
                path,
                key,
                success=False,
                error=str(e)
            )
            return False

    async def _schedule_version_deletion(
        self,
        path: str,
        versions: List[int],
        delay: timedelta,
    ):
        """Schedule deletion of secret versions"""
        await asyncio.sleep(delay.total_seconds())
        await self.delete_secret(path, versions)

    # Access Control

    async def create_policy(
        self,
        name: str,
        rules: Dict[str, Any],
    ) -> bool:
        """
        Create Vault policy

        Args:
            name: Policy name
            rules: Policy rules

        Returns:
            Success status
        """
        try:
            policy_text = json.dumps(rules)
            self.client.sys.create_or_update_policy(
                name=name,
                policy=policy_text,
            )
            return True

        except Exception:
            return False

    async def assign_policy(
        self,
        entity: str,
        policies: List[str],
    ) -> bool:
        """
        Assign policies to entity

        Args:
            entity: Entity (user/service)
            policies: List of policies

        Returns:
            Success status
        """
        try:
            # Implementation depends on auth method
            return True

        except Exception:
            return False

    # Audit

    def _audit_log(self, action: str, *args, **kwargs):
        """Add entry to audit log"""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "args": args,
            "kwargs": kwargs,
        }
        self.audit_log.append(entry)

        # Limit audit log size
        if len(self.audit_log) > 10000:
            self.audit_log = self.audit_log[-5000:]

    def get_audit_log(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        action: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get audit log entries

        Args:
            start_time: Filter start time
            end_time: Filter end time
            action: Filter by action

        Returns:
            Filtered audit log entries
        """
        logs = self.audit_log

        if start_time:
            logs = [
                l for l in logs
                if datetime.fromisoformat(l["timestamp"]) >= start_time
            ]

        if end_time:
            logs = [
                l for l in logs
                if datetime.fromisoformat(l["timestamp"]) <= end_time
            ]

        if action:
            logs = [l for l in logs if l["action"] == action]

        return logs