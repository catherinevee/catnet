"""
CatNet HashiCorp Vault Integration
Manages all secrets, credentials, and encryption keys
NEVER stores actual secrets in code or database
"""

import hvac
import os
import json
import base64
import hashlib
from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime, timedelta
import asyncio
from functools import lru_cache
from dataclasses import dataclass
from enum import Enum

from ..core.exceptions import (
    VaultError, VaultConnectionError, VaultAuthenticationError,
    SecretNotFoundError, SecurityError
)


class SecretType(Enum):
    """Types of secrets managed in Vault"""
    DEVICE_CREDENTIAL = "device_credential"
    API_KEY = "api_key"
    ENCRYPTION_KEY = "encryption_key"
    SIGNING_KEY = "signing_key"
    WEBHOOK_SECRET = "webhook_secret"
    DATABASE_CREDENTIAL = "database_credential"
    SSH_KEY = "ssh_key"
    CERTIFICATE = "certificate"
    MFA_SECRET = "mfa_secret"


@dataclass
class SecretMetadata:
    """Metadata for secret management"""
    path: str
    version: int
    created_at: datetime
    created_by: str
    expires_at: Optional[datetime]
    rotation_period: Optional[int]
    last_rotated: Optional[datetime]
    access_count: int


class VaultClient:
    """
    Comprehensive Vault client for CatNet
    Implements zero-trust secret management
    """

    def __init__(
        self,
        vault_url: Optional[str] = None,
        token: Optional[str] = None,
        namespace: Optional[str] = None,
        auto_renew: bool = True
    ):
        # Configuration
        self.vault_url = vault_url or os.getenv("VAULT_URL", "https://vault.local:8200")
        self.token = token or os.getenv("VAULT_TOKEN")
        self.namespace = namespace or os.getenv("VAULT_NAMESPACE", "catnet")

        # TLS Configuration for mTLS
        self.ca_cert = os.getenv("VAULT_CACERT", "/etc/catnet/certs/vault-ca.crt")
        self.client_cert = os.getenv("VAULT_CLIENT_CERT", "/etc/catnet/certs/client.crt")
        self.client_key = os.getenv("VAULT_CLIENT_KEY", "/etc/catnet/certs/client.key")

        # Client state
        self.client = None
        self.auto_renew = auto_renew
        self._token_accessor = None
        self._token_ttl = None
        self._renewal_task = None

        # Secret caching (with TTL)
        self._secret_cache = {}
        self._cache_ttl = 300  # 5 minutes

        # Initialize client
        self._initialize_client()

        # Start token renewal if enabled
        if self.auto_renew:
            self._start_token_renewal()

    def _initialize_client(self):
        """Initialize Vault client with mTLS"""
        try:
            # Configure TLS for mTLS
            tls_config = {
                'ca_cert': self.ca_cert,
                'client_cert': self.client_cert,
                'client_key': self.client_key
            } if os.path.exists(self.ca_cert) else True

            self.client = hvac.Client(
                url=self.vault_url,
                token=self.token,
                namespace=self.namespace,
                verify=tls_config
            )

            # Verify authentication
            if not self.client.is_authenticated():
                raise VaultAuthenticationError("Vault authentication failed")

            # Get token information
            token_info = self.client.auth.token.lookup_self()
            self._token_accessor = token_info['data']['accessor']
            self._token_ttl = token_info['data']['ttl']

            # Enable audit logging
            self._ensure_audit_enabled()

        except hvac.exceptions.VaultError as e:
            raise VaultConnectionError(f"Failed to connect to Vault: {str(e)}")
        except Exception as e:
            raise VaultError(f"Vault initialization failed: {str(e)}")

    def _ensure_audit_enabled(self):
        """Ensure audit logging is enabled"""
        try:
            audit_devices = self.client.sys.list_enabled_audit_devices()
            if 'file/' not in audit_devices:
                self.client.sys.enable_audit_device(
                    device_type='file',
                    path='file',
                    options={
                        'file_path': '/var/log/vault/audit.log',
                        'log_raw': False,
                        'hmac_accessor': True,
                        'prefix': 'CATNET_'
                    }
                )
        except Exception:
            pass  # Audit might already be enabled

    def _start_token_renewal(self):
        """Start automatic token renewal"""
        if self._token_ttl and self._token_ttl > 0:
            loop = asyncio.new_event_loop()
            self._renewal_task = loop.create_task(self._renew_token_periodically())

    async def _renew_token_periodically(self):
        """Periodically renew the Vault token"""
        while True:
            try:
                # Renew at 75% of TTL
                sleep_time = int(self._token_ttl * 0.75)
                await asyncio.sleep(sleep_time)

                # Renew token
                response = self.client.auth.token.renew_self()
                self._token_ttl = response['auth']['lease_duration']

            except Exception as e:
                # Log error and retry
                await asyncio.sleep(60)  # Retry after 1 minute

    # Device Credential Management
    def get_device_credentials(
        self,
        device_id: str,
        requestor_id: str,
        purpose: str = "configuration"
    ) -> Dict[str, Any]:
        """
        Get temporary device credentials with audit trail
        Implements dynamic credential generation
        """
        try:
            # Audit the access request
            self._audit_access(
                action="get_device_credentials",
                resource=f"device/{device_id}",
                requestor=requestor_id,
                purpose=purpose
            )

            # Check if static credentials exist
            static_path = f"devices/{device_id}/credentials"
            try:
                static_creds = self._read_secret(static_path)
            except SecretNotFoundError:
                static_creds = None

            # Generate dynamic credentials if supported
            dynamic_creds = None
            if self._supports_dynamic_credentials(device_id):
                dynamic_creds = self._generate_dynamic_credentials(
                    device_id=device_id,
                    ttl=1800  # 30 minutes
                )

            # Return appropriate credentials
            if dynamic_creds:
                return {
                    "type": "dynamic",
                    "username": dynamic_creds["username"],
                    "password": dynamic_creds["password"],
                    "ssh_key": dynamic_creds.get("ssh_key"),
                    "expires_at": dynamic_creds["expires_at"],
                    "device_id": device_id,
                    "requestor": requestor_id
                }
            elif static_creds:
                return {
                    "type": "static",
                    "username": static_creds["username"],
                    "password": static_creds["password"],
                    "ssh_key": static_creds.get("ssh_key"),
                    "device_id": device_id,
                    "requestor": requestor_id
                }
            else:
                raise SecretNotFoundError(f"No credentials found for device {device_id}")

        except Exception as e:
            raise VaultError(f"Failed to get device credentials: {str(e)}")

    def _supports_dynamic_credentials(self, device_id: str) -> bool:
        """Check if device supports dynamic credentials"""
        try:
            device_info = self._read_secret(f"devices/{device_id}/metadata")
            return device_info.get("dynamic_credentials_enabled", False)
        except:
            return False

    def _generate_dynamic_credentials(
        self,
        device_id: str,
        ttl: int = 1800
    ) -> Dict[str, Any]:
        """Generate temporary dynamic credentials"""
        try:
            response = self.client.write(
                path=f"database/creds/device-{device_id}",
                ttl=f"{ttl}s"
            )

            if response and 'data' in response:
                return {
                    "username": response['data']['username'],
                    "password": response['data']['password'],
                    "expires_at": (datetime.utcnow() + timedelta(seconds=ttl)).isoformat(),
                    "lease_id": response.get('lease_id')
                }
            else:
                raise VaultError("Failed to generate dynamic credentials")

        except Exception as e:
            raise VaultError(f"Dynamic credential generation failed: {str(e)}")

    # Encryption Key Management
    def get_encryption_key(self, key_id: str) -> bytes:
        """Get encryption key from Vault"""
        try:
            path = f"encryption/keys/{key_id}"
            secret = self._read_secret(path)

            if 'key' not in secret:
                raise SecretNotFoundError(f"Encryption key {key_id} not found")

            # Decode the key
            key_data = secret['key']
            if isinstance(key_data, str):
                return base64.b64decode(key_data)
            return key_data

        except Exception as e:
            raise VaultError(f"Failed to get encryption key: {str(e)}")

    def store_encryption_key(
        self,
        key_id: str,
        key: bytes,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Store encryption key in Vault"""
        try:
            path = f"encryption/keys/{key_id}"
            secret_data = {
                "key": base64.b64encode(key).decode('utf-8'),
                "created_at": datetime.utcnow().isoformat(),
                "algorithm": "AES-256-GCM",
                "key_size": len(key) * 8
            }

            if metadata:
                secret_data.update(metadata)

            self._write_secret(path, secret_data)

        except Exception as e:
            raise VaultError(f"Failed to store encryption key: {str(e)}")

    def rotate_encryption_key(self, key_id: str) -> bytes:
        """Rotate an encryption key"""
        try:
            # Generate new key
            new_key = os.urandom(32)  # 256 bits for AES-256

            # Get old key for re-encryption if needed
            old_key = self.get_encryption_key(key_id)

            # Store new key with versioning
            path = f"encryption/keys/{key_id}"
            self._write_secret(
                path,
                {
                    "key": base64.b64encode(new_key).decode('utf-8'),
                    "rotated_at": datetime.utcnow().isoformat(),
                    "previous_version": base64.b64encode(old_key).decode('utf-8')
                }
            )

            # Audit the rotation
            self._audit_access(
                action="rotate_encryption_key",
                resource=f"key/{key_id}",
                requestor="system",
                purpose="scheduled_rotation"
            )

            return new_key

        except Exception as e:
            raise VaultError(f"Failed to rotate encryption key: {str(e)}")

    # Transit Encryption (using Vault's encryption as a service)
    def encrypt_data(self, plaintext: str, key_name: str = "catnet") -> Dict[str, str]:
        """Encrypt data using Vault's transit engine"""
        try:
            # Ensure transit engine is mounted
            self._ensure_transit_mounted()

            # Base64 encode the plaintext
            encoded = base64.b64encode(plaintext.encode('utf-8')).decode('utf-8')

            # Encrypt using transit
            response = self.client.write(
                path=f"transit/encrypt/{key_name}",
                plaintext=encoded
            )

            return {
                "ciphertext": response['data']['ciphertext'],
                "key_version": str(response['data'].get('key_version', 1))
            }

        except Exception as e:
            raise VaultError(f"Transit encryption failed: {str(e)}")

    def decrypt_data(self, ciphertext: str, key_name: str = "catnet") -> str:
        """Decrypt data using Vault's transit engine"""
        try:
            response = self.client.write(
                path=f"transit/decrypt/{key_name}",
                ciphertext=ciphertext
            )

            # Decode the plaintext
            decoded = base64.b64decode(response['data']['plaintext']).decode('utf-8')
            return decoded

        except Exception as e:
            raise VaultError(f"Transit decryption failed: {str(e)}")

    def _ensure_transit_mounted(self):
        """Ensure transit engine is mounted"""
        try:
            mounts = self.client.sys.list_mounted_secrets_engines()
            if 'transit/' not in mounts:
                self.client.sys.enable_secrets_engine(
                    backend_type='transit',
                    path='transit'
                )

                # Create default encryption key
                self.client.write(
                    path='transit/keys/catnet',
                    type='aes256-gcm96'
                )
        except:
            pass  # Transit might already be mounted

    # Certificate Management
    def issue_certificate(
        self,
        common_name: str,
        ttl: str = "24h",
        alt_names: Optional[List[str]] = None
    ) -> Dict[str, str]:
        """Issue a new TLS certificate"""
        try:
            # Ensure PKI is configured
            self._ensure_pki_mounted()

            params = {
                "common_name": common_name,
                "ttl": ttl,
                "format": "pem"
            }

            if alt_names:
                params["alt_names"] = ",".join(alt_names)

            response = self.client.write(
                path="pki_int/issue/catnet",
                **params
            )

            return {
                "certificate": response['data']['certificate'],
                "private_key": response['data']['private_key'],
                "ca_chain": response['data']['ca_chain'],
                "serial_number": response['data']['serial_number'],
                "expiration": response['data']['expiration']
            }

        except Exception as e:
            raise VaultError(f"Certificate issuance failed: {str(e)}")

    def _ensure_pki_mounted(self):
        """Ensure PKI engine is mounted"""
        try:
            mounts = self.client.sys.list_mounted_secrets_engines()
            if 'pki_int/' not in mounts:
                # This would normally be done during setup
                pass
        except:
            pass

    # SSH Key Management
    def sign_ssh_key(
        self,
        public_key: str,
        username: str,
        ttl: str = "8h"
    ) -> Dict[str, str]:
        """Sign an SSH public key"""
        try:
            response = self.client.write(
                path="ssh-client-signer/sign/catnet",
                public_key=public_key,
                valid_principals=username,
                ttl=ttl
            )

            return {
                "signed_key": response['data']['signed_key'],
                "serial": response['data']['serial'],
                "valid_until": response['data']['valid_until']
            }

        except Exception as e:
            raise VaultError(f"SSH key signing failed: {str(e)}")

    def get_ssh_ca_public_key(self) -> str:
        """Get SSH CA public key for verification"""
        try:
            response = self.client.read("ssh-client-signer/config/ca")
            return response['data']['public_key']
        except Exception as e:
            raise VaultError(f"Failed to get SSH CA key: {str(e)}")

    # Webhook Secret Management
    def get_webhook_secret(self, repository_id: str) -> str:
        """Get webhook secret for repository"""
        try:
            path = f"webhooks/{repository_id}/secret"
            secret = self._read_secret(path)
            return secret['secret']
        except Exception as e:
            raise VaultError(f"Failed to get webhook secret: {str(e)}")

    def generate_webhook_secret(self, repository_id: str) -> str:
        """Generate and store a new webhook secret"""
        try:
            # Generate strong random secret
            secret = base64.b64encode(os.urandom(32)).decode('utf-8')

            # Store in Vault
            path = f"webhooks/{repository_id}/secret"
            self._write_secret(
                path,
                {
                    "secret": secret,
                    "created_at": datetime.utcnow().isoformat(),
                    "repository_id": repository_id
                }
            )

            return secret

        except Exception as e:
            raise VaultError(f"Failed to generate webhook secret: {str(e)}")

    # MFA Secret Management
    def store_mfa_secret(
        self,
        user_id: str,
        secret: str,
        backup_codes: List[str]
    ) -> None:
        """Store MFA secret and backup codes"""
        try:
            path = f"mfa/{user_id}/secret"

            # Hash backup codes for storage
            hashed_codes = [
                hashlib.sha256(code.encode('utf-8')).hexdigest()
                for code in backup_codes
            ]

            self._write_secret(
                path,
                {
                    "secret": secret,
                    "backup_codes": hashed_codes,
                    "created_at": datetime.utcnow().isoformat()
                }
            )

        except Exception as e:
            raise VaultError(f"Failed to store MFA secret: {str(e)}")

    def get_mfa_secret(self, user_id: str) -> str:
        """Get MFA secret for user"""
        try:
            path = f"mfa/{user_id}/secret"
            secret = self._read_secret(path)
            return secret['secret']
        except Exception as e:
            raise VaultError(f"Failed to get MFA secret: {str(e)}")

    def verify_backup_code(self, user_id: str, code: str) -> bool:
        """Verify and consume a backup code"""
        try:
            path = f"mfa/{user_id}/secret"
            secret = self._read_secret(path)

            # Hash the provided code
            code_hash = hashlib.sha256(code.encode('utf-8')).hexdigest()

            # Check if code exists
            if code_hash in secret.get('backup_codes', []):
                # Remove used code
                secret['backup_codes'].remove(code_hash)
                self._write_secret(path, secret)
                return True

            return False

        except Exception as e:
            return False

    # Token Management
    def create_token(
        self,
        policies: List[str],
        ttl: str = "1h",
        renewable: bool = True,
        display_name: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Create a new Vault token"""
        try:
            params = {
                "policies": policies,
                "ttl": ttl,
                "renewable": renewable
            }

            if display_name:
                params["display_name"] = display_name

            if metadata:
                params["meta"] = metadata

            response = self.client.auth.token.create(**params)

            return {
                "token": response['auth']['client_token'],
                "accessor": response['auth']['accessor'],
                "policies": response['auth']['policies'],
                "ttl": response['auth']['lease_duration'],
                "renewable": response['auth']['renewable']
            }

        except Exception as e:
            raise VaultError(f"Token creation failed: {str(e)}")

    def revoke_token(self, token_accessor: str) -> None:
        """Revoke a token by accessor"""
        try:
            self.client.auth.token.revoke_accessor(token_accessor)
        except Exception as e:
            raise VaultError(f"Token revocation failed: {str(e)}")

    # Database Credential Management
    def get_database_credentials(
        self,
        database: str = "postgresql",
        role: str = "catnet"
    ) -> Dict[str, str]:
        """Get dynamic database credentials"""
        try:
            response = self.client.read(f"database/creds/{role}")

            return {
                "username": response['data']['username'],
                "password": response['data']['password'],
                "expires_at": datetime.utcnow() + timedelta(seconds=response['lease_duration'])
            }

        except Exception as e:
            raise VaultError(f"Failed to get database credentials: {str(e)}")

    # Backup and Recovery
    def backup_secrets(self, backup_path: str) -> None:
        """Backup critical secrets (encrypted)"""
        try:
            # This would implement secure backup logic
            # Never exports actual secrets, only encrypted references
            pass
        except Exception as e:
            raise VaultError(f"Backup failed: {str(e)}")

    def restore_secrets(self, backup_path: str) -> None:
        """Restore secrets from backup"""
        try:
            # This would implement secure restore logic
            pass
        except Exception as e:
            raise VaultError(f"Restore failed: {str(e)}")

    # Internal Helper Methods
    def _read_secret(
        self,
        path: str,
        mount_point: str = "secret"
    ) -> Dict[str, Any]:
        """Read secret from KV v2"""
        try:
            # Check cache first
            cache_key = f"{mount_point}/{path}"
            if cache_key in self._secret_cache:
                cached = self._secret_cache[cache_key]
                if cached['expires'] > datetime.utcnow():
                    return cached['data']

            # Read from Vault
            response = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=mount_point
            )

            if not response or 'data' not in response:
                raise SecretNotFoundError(f"Secret not found: {path}")

            data = response['data']['data']

            # Cache the secret
            self._secret_cache[cache_key] = {
                'data': data,
                'expires': datetime.utcnow() + timedelta(seconds=self._cache_ttl)
            }

            return data

        except hvac.exceptions.InvalidPath:
            raise SecretNotFoundError(f"Secret not found: {path}")
        except Exception as e:
            raise VaultError(f"Failed to read secret: {str(e)}")

    def _write_secret(
        self,
        path: str,
        secret: Dict[str, Any],
        mount_point: str = "secret"
    ) -> None:
        """Write secret to KV v2"""
        try:
            self.client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=secret,
                mount_point=mount_point
            )

            # Invalidate cache
            cache_key = f"{mount_point}/{path}"
            if cache_key in self._secret_cache:
                del self._secret_cache[cache_key]

        except Exception as e:
            raise VaultError(f"Failed to write secret: {str(e)}")

    def _delete_secret(
        self,
        path: str,
        mount_point: str = "secret"
    ) -> None:
        """Delete secret from KV v2"""
        try:
            self.client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=path,
                mount_point=mount_point
            )

            # Invalidate cache
            cache_key = f"{mount_point}/{path}"
            if cache_key in self._secret_cache:
                del self._secret_cache[cache_key]

        except Exception as e:
            raise VaultError(f"Failed to delete secret: {str(e)}")

    def _audit_access(
        self,
        action: str,
        resource: str,
        requestor: str,
        purpose: str = "operational"
    ) -> None:
        """Audit secret access"""
        try:
            audit_entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "action": action,
                "resource": resource,
                "requestor": requestor,
                "purpose": purpose,
                "namespace": self.namespace
            }

            # Write to audit backend
            self.client.write(
                path="sys/audit-hash/file",
                input=json.dumps(audit_entry)
            )

        except:
            pass  # Don't fail operations due to audit failures

    # Health and Status
    def check_health(self) -> Dict[str, Any]:
        """Check Vault health status"""
        try:
            response = self.client.sys.read_health_status(
                standby_ok=True,
                perfstandby_ok=True
            )

            return {
                "initialized": response.get('initialized', False),
                "sealed": response.get('sealed', True),
                "standby": response.get('standby', False),
                "cluster_name": response.get('cluster_name'),
                "cluster_id": response.get('cluster_id'),
                "version": response.get('version'),
                "healthy": not response.get('sealed', True)
            }

        except Exception as e:
            return {
                "healthy": False,
                "error": str(e)
            }

    def seal(self) -> None:
        """Seal Vault (emergency operation)"""
        try:
            self.client.sys.seal()
        except Exception as e:
            raise VaultError(f"Failed to seal Vault: {str(e)}")

    def __del__(self):
        """Cleanup on deletion"""
        if self._renewal_task:
            self._renewal_task.cancel()


# Singleton instance
_vault_client = None

def get_vault_client() -> VaultClient:
    """Get or create Vault client singleton"""
    global _vault_client
    if _vault_client is None:
        _vault_client = VaultClient()
    return _vault_client