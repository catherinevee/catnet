from typing import Optional, Dict, Any, List
import hvac
from pydantic_settings import BaseSettings
import structlog
import os
import json
from datetime import datetime, timedelta
import secrets
import string

logger = structlog.get_logger()

class VaultSettings(BaseSettings):
    vault_url: str = os.getenv("VAULT_URL", "http://localhost:8200")
    vault_token: str = os.getenv("VAULT_TOKEN", "")
    vault_namespace: str = os.getenv("VAULT_NAMESPACE", "")
    vault_mount_point: str = "secret"
    vault_kv_version: int = 2
    vault_ssl_verify: bool = True
    vault_timeout: int = 30

    class Config:
        env_file = ".env"

class VaultClient:
    def __init__(self):
        self.settings = VaultSettings()
        self.client = None
        self._initialize_client()

    def _initialize_client(self):
        try:
            self.client = hvac.Client(
                url=self.settings.vault_url,
                token=self.settings.vault_token,
                namespace=self.settings.vault_namespace if self.settings.vault_namespace else None,
                verify=self.settings.vault_ssl_verify,
                timeout=self.settings.vault_timeout
            )

            if not self.client.is_authenticated():
                logger.error("Failed to authenticate with Vault")
                raise Exception("Vault authentication failed")

            logger.info("Successfully connected to Vault")

        except Exception as e:
            logger.error(f"Failed to initialize Vault client: {e}")
            raise

    async def get_secret(
        self,
        path: str,
        mount_point: Optional[str] = None
    ) -> Dict[str, Any]:
        try:
            mount_point = mount_point or self.settings.vault_mount_point

            if self.settings.vault_kv_version == 2:
                response = self.client.secrets.kv.v2.read_secret_version(
                    path=path,
                    mount_point=mount_point
                )
                return response["data"]["data"]
            else:
                response = self.client.secrets.kv.v1.read_secret(
                    path=path,
                    mount_point=mount_point
                )
                return response["data"]

        except Exception as e:
            logger.error(f"Failed to get secret from path {path}: {e}")
            raise

    async def store_secret(
        self,
        path: str,
        secret: Dict[str, Any],
        mount_point: Optional[str] = None
    ) -> bool:
        try:
            mount_point = mount_point or self.settings.vault_mount_point

            if self.settings.vault_kv_version == 2:
                self.client.secrets.kv.v2.create_or_update_secret(
                    path=path,
                    secret=secret,
                    mount_point=mount_point
                )
            else:
                self.client.secrets.kv.v1.create_or_update_secret(
                    path=path,
                    secret=secret,
                    mount_point=mount_point
                )

            logger.info(f"Successfully stored secret at path {path}")
            return True

        except Exception as e:
            logger.error(f"Failed to store secret at path {path}: {e}")
            return False

    async def delete_secret(
        self,
        path: str,
        mount_point: Optional[str] = None
    ) -> bool:
        try:
            mount_point = mount_point or self.settings.vault_mount_point

            if self.settings.vault_kv_version == 2:
                self.client.secrets.kv.v2.delete_metadata_and_all_versions(
                    path=path,
                    mount_point=mount_point
                )
            else:
                self.client.secrets.kv.v1.delete_secret(
                    path=path,
                    mount_point=mount_point
                )

            logger.info(f"Successfully deleted secret at path {path}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete secret at path {path}: {e}")
            return False

    async def get_temporary_credentials(
        self,
        device_id: str,
        requestor: str,
        ttl: int = 1800
    ) -> Dict[str, Any]:
        try:
            lease_path = f"database/creds/catnet-{device_id}"
            response = self.client.read(lease_path)

            if response:
                creds = {
                    "username": response["data"]["username"],
                    "password": response["data"]["password"],
                    "lease_id": response["lease_id"],
                    "lease_duration": response["lease_duration"],
                    "expires_at": (datetime.utcnow() + timedelta(seconds=response["lease_duration"])).isoformat()
                }

                await self._audit_credential_request(
                    device_id, requestor, creds["username"], ttl
                )

                return creds

            return await self._generate_dynamic_credentials(device_id, requestor, ttl)

        except Exception as e:
            logger.error(f"Failed to get temporary credentials for device {device_id}: {e}")
            raise

    async def _generate_dynamic_credentials(
        self,
        device_id: str,
        requestor: str,
        ttl: int
    ) -> Dict[str, Any]:
        username = f"temp_{device_id[:8]}_{requestor[:8]}_{secrets.token_hex(4)}"
        password = ''.join(secrets.choice(string.ascii_letters + string.digits + '!@#$%^&*') for _ in range(32))

        creds = {
            "username": username,
            "password": password,
            "lease_id": f"temp/{device_id}/{secrets.token_hex(8)}",
            "lease_duration": ttl,
            "expires_at": (datetime.utcnow() + timedelta(seconds=ttl)).isoformat()
        }

        await self.store_secret(
            f"temp-creds/{device_id}/{requestor}",
            creds
        )

        return creds

    async def _audit_credential_request(
        self,
        device_id: str,
        requestor: str,
        username: str,
        ttl: int
    ):
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "device_id": device_id,
            "requestor": requestor,
            "username": username,
            "ttl": ttl,
            "action": "credential_request"
        }

        await self.store_secret(
            f"audit/credentials/{datetime.utcnow().strftime('%Y%m%d')}/{secrets.token_hex(8)}",
            audit_entry
        )

    async def get_encryption_key(
        self,
        key_name: str
    ) -> bytes:
        try:
            response = self.client.secrets.transit.read_key(
                name=key_name
            )

            if response and "data" in response:
                key_data = response["data"]
                return key_data.get("keys", {}).get("1", {}).get("key", "").encode()

            response = self.client.secrets.transit.create_key(
                name=key_name,
                key_type="aes256-gcm96"
            )

            return await self.get_encryption_key(key_name)

        except Exception as e:
            logger.error(f"Failed to get encryption key {key_name}: {e}")
            raise

    async def encrypt_data(
        self,
        plaintext: str,
        key_name: str = "catnet-default"
    ) -> str:
        try:
            import base64
            encoded = base64.b64encode(plaintext.encode()).decode()

            response = self.client.secrets.transit.encrypt_data(
                name=key_name,
                plaintext=encoded
            )

            return response["data"]["ciphertext"]

        except Exception as e:
            logger.error(f"Failed to encrypt data: {e}")
            raise

    async def decrypt_data(
        self,
        ciphertext: str,
        key_name: str = "catnet-default"
    ) -> str:
        try:
            response = self.client.secrets.transit.decrypt_data(
                name=key_name,
                ciphertext=ciphertext
            )

            import base64
            plaintext = base64.b64decode(response["data"]["plaintext"]).decode()
            return plaintext

        except Exception as e:
            logger.error(f"Failed to decrypt data: {e}")
            raise

    async def rotate_secret(
        self,
        path: str,
        mount_point: Optional[str] = None
    ) -> bool:
        try:
            current_secret = await self.get_secret(path, mount_point)

            if "password" in current_secret:
                new_password = ''.join(
                    secrets.choice(string.ascii_letters + string.digits + '!@#$%^&*')
                    for _ in range(32)
                )
                current_secret["password"] = new_password
                current_secret["rotated_at"] = datetime.utcnow().isoformat()

            return await self.store_secret(path, current_secret, mount_point)

        except Exception as e:
            logger.error(f"Failed to rotate secret at path {path}: {e}")
            return False

    async def list_secrets(
        self,
        path: str = "",
        mount_point: Optional[str] = None
    ) -> List[str]:
        try:
            mount_point = mount_point or self.settings.vault_mount_point

            if self.settings.vault_kv_version == 2:
                response = self.client.secrets.kv.v2.list_secrets(
                    path=path,
                    mount_point=mount_point
                )
            else:
                response = self.client.secrets.kv.v1.list_secrets(
                    path=path,
                    mount_point=mount_point
                )

            return response.get("data", {}).get("keys", [])

        except Exception as e:
            logger.error(f"Failed to list secrets at path {path}: {e}")
            return []

    def health_check(self) -> bool:
        try:
            return self.client.is_authenticated()
        except Exception:
            return False