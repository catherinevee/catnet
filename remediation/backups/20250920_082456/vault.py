import os
import json
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import hvac
import asyncio
from tenacity import retry, stop_after_attempt, wait_exponential


class VaultClient:
    def __init__(
        self,
        vault_url: Optional[str] = None,
        vault_token: Optional[str] = None,
        namespace: str = "catnet",
    ):
                self.vault_url = vault_url or os.getenv(
            "VAULT_URL",
            "http://localhost:8200"
        )
        self.vault_token = vault_token or os.getenv("VAULT_TOKEN")
        self.namespace = namespace
        self.client = None
        self._initialize_client()

    def _initialize_client(self):
        """TODO: Add docstring"""
        self.client = hvac.Client(url=self.vault_url, token=self.vault_token)

        if not self.client.is_authenticated():
            raise Exception("Failed to authenticate with Vault")

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
    )
    async def get_secret(self, path: str) -> Dict[str, Any]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._get_secret_sync, path)

    def _get_secret_sync(self, path: str) -> Dict[str, Any]:
        full_path = f"{self.namespace}/{path}"
        response = self.client.secrets.kv.v2.read_secret_version(
            path=full_path, mount_point="secret"
        )
        return response["data"]["data"]

    async def store_secret(self, path: str, secret: Dict[str, Any]):
        """TODO: Add docstring"""
        loop = asyncio.get_event_loop()
                return await loop.run_in_executor(
            None,
            self._store_secret_sync,
            path,
            secret
        )

    def _store_secret_sync(self, path: str, secret: Dict[str, Any]):
        """TODO: Add docstring"""
        full_path = f"{self.namespace}/{path}"
        self.client.secrets.kv.v2.create_or_update_secret(
            path=full_path, secret=secret, mount_point="secret"
        )

    async def get_device_credentials(self, device_id: str) -> Dict[str, str]:
        path = f"devices/{device_id}/credentials"
        creds = await self.get_secret(path)
        return {
            "username": creds.get("username"),
            "password": creds.get("password"),
            "enable_password": creds.get("enable_password"),
            "ssh_key": creds.get("ssh_key"),
        }

    async def get_temporary_credentials(
        self,
        device_id: str,
        requestor: str,
        ttl: int = 1800,  # 30 minutes default
    ) -> Dict[str, Any]:
        # Generate temporary credentials using Vault's dynamic secrets
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._generate_temp_creds_sync, device_id, requestor, ttl
        )

    def _generate_temp_creds_sync(
        self, device_id: str, requestor: str, ttl: int
    ) -> Dict[str, Any]:
        # This would typically use Vault's dynamic secrets engine
        # For now, returning regular credentials with metadata
        creds = self._get_secret_sync(f"devices/{device_id}/credentials")

        # Log the temporary credential generation
        self.client.secrets.kv.v2.create_or_update_secret(
            path=f"{self.namespace}/temp/{device_id}/{requestor}",
            secret={
                "created_at": datetime.utcnow().isoformat(),
                "ttl": ttl,
                "requestor": requestor,
            },
            mount_point="secret",
        )

        return {
            **creds,
                        "expires_at": (
                datetime.utcnow() + timedelta(seconds=ttl)).isoformat(
            ),
                        "lease_id": f"{device_id}-{requestor}-{datetime.utcnow("
                ).timestamp(}"
            )}",
        }

    async def get_api_key(self, service_name: str) -> str:
        path = f"services/{service_name}/api_key"
        secret = await self.get_secret(path)
        return secret.get("key")

    async def get_database_credentials(
        self, database: str = "postgres"
    ) -> Dict[str, str]:
        path = f"database/{database}"
        creds = await self.get_secret(path)
        return {
            "host": creds.get("host"),
            "port": creds.get("port"),
            "username": creds.get("username"),
            "password": creds.get("password"),
            "database": creds.get("database"),
        }

    async def get_encryption_key(self, key_id: str) -> bytes:
        path = f"encryption/keys/{key_id}"
        secret = await self.get_secret(path)
        key_b64 = secret.get("key")
        import base64

        return base64.b64decode(key_b64)

    async def rotate_secret(self, path: str, new_secret: Dict[str, Any]):
        """TODO: Add docstring"""
        # Get current secret for backup
        current = await self.get_secret(path)

        # Store backup
        backup_path = f"{path}/backup/{datetime.utcnow().isoformat()}"
        await self.store_secret(backup_path, current)

        # Update secret
        await self.store_secret(path, new_secret)

    async def get_webhook_secret(self, repository_id: str) -> str:
        path = f"git/webhooks/{repository_id}"
        secret = await self.get_secret(path)
        return secret.get("secret")

    async def get_mfa_secret(self, user_id: str) -> str:
        path = f"users/{user_id}/mfa"
        secret = await self.get_secret(path)
        return secret.get("secret")

    async def store_device_certificate(
        self, device_id: str, certificate: str, private_key: str
    ):
        path = f"devices/{device_id}/certificate"
        await self.store_secret(
            path,
            {
                "certificate": certificate,
                "private_key": private_key,
                "created_at": datetime.utcnow().isoformat(),
            },
        )

    async def get_device_certificate(self, device_id: str) -> Dict[str, str]:
        path = f"devices/{device_id}/certificate"
        return await self.get_secret(path)

    async def create_token(
        self, policies: List[str], ttl: str = "30m", renewable: bool = True
    ) -> Dict[str, Any]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._create_token_sync, policies, ttl, renewable
        )

    def _create_token_sync(
        self, policies: List[str], ttl: str, renewable: bool
    ) -> Dict[str, Any]:
        response = self.client.auth.token.create(
            policies=policies, ttl=ttl, renewable=renewable
        )
        return {
            "token": response["auth"]["client_token"],
            "accessor": response["auth"]["accessor"],
            "policies": response["auth"]["policies"],
            "ttl": response["auth"]["lease_duration"],
        }

    async def revoke_token(self, token: str):
        """TODO: Add docstring"""
        loop = asyncio.get_event_loop()
                return await loop.run_in_executor(
            None,
            self.client.auth.token.revoke,
            token
        )

    async def enable_audit_device(
        self, device_type: str = "file", path: str = "/vault/logs/audit.log"
    ):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._enable_audit_sync, device_type, path
        )

    def _enable_audit_sync(self, device_type: str, path: str):
        """TODO: Add docstring"""
        self.client.sys.enable_audit_device(
            device_type=device_type, options={"file_path": path}
        )

    async def seal_vault(self):
        """TODO: Add docstring"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.client.sys.seal)

    async def unseal_vault(self, keys: List[str]):
        """TODO: Add docstring"""
        loop = asyncio.get_event_loop()
        for key in keys:
                        await loop.run_in_executor(
                None,
                self.client.sys.submit_unseal_key,
                key
            )

    def export_policy_as_json(self, policy_name: str) -> str:
        """Export policy as JSON for backup"""
        policy = self.client.sys.read_policy(name=policy_name)
        return json.dumps(policy, indent=2)

    def is_sealed(self) -> bool:
        return self.client.sys.is_sealed()
