import hmac
import hashlib
from typing import Dict, Any, Optional, List
import json
from datetime import datetime
from ..security.vault import VaultClient


class WebhookHandler:
    def __init__(self, vault_client: Optional[VaultClient] = None):
        self.vault = vault_client or VaultClient()

    async def verify_github_signature(
        self, payload: bytes, signature: str, secret: str
    ) -> bool:
        if not signature:
            return False

        # GitHub sends the signature in the format "sha256=<signature>"
        if signature.startswith("sha256="):
            signature = signature[7:]

            expected_sig = hmac.new(
                secret.encode(), payload, hashlib.sha256
            ).hexdigest()

        return hmac.compare_digest(expected_sig, signature)

    async def verify_gitlab_signature(
        self, payload: bytes, signature: str, secret: str
    ) -> bool:
        if not signature:
            return False

        return signature == secret

    async def verify_bitbucket_signature(
        self, payload: bytes, signature: str, secret: str
    ) -> bool:
        if not signature:
            return False

            expected_sig = hmac.new(
                secret.encode(), payload, hashlib.sha256
            ).hexdigest()

        return hmac.compare_digest(expected_sig, signature)

    async def verify_webhook_signature(
        self, payload: bytes, signature: str, provider: str, repository_id: str
    ) -> bool:
        # Get webhook secret from vault
        secret = await self.vault.get_webhook_secret(repository_id)

        if provider.lower() == "github":
            return await self.verify_github_signature(payload, signature, secret)
        elif provider.lower() == "gitlab":
            return await self.verify_gitlab_signature(payload, signature, secret)
        elif provider.lower() == "bitbucket":
            return await self.verify_bitbucket_signature(payload, signature, secret)
        else:
            return False

    def parse_github_webhook(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "provider": "github",
            "event": payload.get("action", "push"),
            "repository": {
                "name": payload.get("repository", {}).get("name"),
                "url": payload.get("repository", {}).get("clone_url"),
                "branch": payload.get("ref", "").replace("refs/heads/", ""),
            },
            "commits": [
                {
                    "id": commit.get("id"),
                    "message": commit.get("message"),
                    "author": commit.get("author", {}).get("name"),
                    "timestamp": commit.get("timestamp"),
                    "added": commit.get("added", []),
                    "modified": commit.get("modified", []),
                    "removed": commit.get("removed", []),
                }
                for commit in payload.get("commits", [])
            ],
            "sender": {
                "username": payload.get("sender", {}).get("login"),
                "email": payload.get("sender", {}).get("email"),
            },
        }

    def parse_gitlab_webhook(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "provider": "gitlab",
            "event": payload.get("object_kind", "push"),
            "repository": {
                "name": payload.get("project", {}).get("name"),
                "url": payload.get("project", {}).get("git_http_url"),
                "branch": payload.get("ref", "").replace("refs/heads/", ""),
            },
            "commits": [
                {
                    "id": commit.get("id"),
                    "message": commit.get("message"),
                    "author": commit.get("author", {}).get("name"),
                    "timestamp": commit.get("timestamp"),
                    "added": commit.get("added", []),
                    "modified": commit.get("modified", []),
                    "removed": commit.get("removed", []),
                }
                for commit in payload.get("commits", [])
            ],
            "sender": {
                "username": payload.get("user_username"),
                "email": payload.get("user_email"),
            },
        }

    def parse_webhook_payload(
        self, payload: Dict[str, Any], provider: str
    ) -> Dict[str, Any]:
        if provider.lower() == "github":
            return self.parse_github_webhook(payload)
        elif provider.lower() == "gitlab":
            return self.parse_gitlab_webhook(payload)
        else:
            # Return raw payload for unsupported providers
            return {"provider": provider, "raw": payload}

    def get_changed_files(self, parsed_webhook: Dict[str, Any]) -> List[str]:
        changed_files = set()

        for commit in parsed_webhook.get("commits", []):
            changed_files.update(commit.get("added", []))
            changed_files.update(commit.get("modified", []))
            changed_files.update(commit.get("removed", []))

        return list(changed_files)

    def is_config_change(
        self, parsed_webhook: Dict[str, Any], config_path: str = "configs/"
    ) -> bool:
        changed_files = self.get_changed_files(parsed_webhook)

        for file in changed_files:
            if file.startswith(config_path):
                return True

        return False

    def log_webhook_event(self, webhook_data: Dict[str, Any]) -> str:
        """Log webhook event with timestamp"""
        event = {"timestamp": datetime.now().isoformat(), "data": webhook_data}
        # Convert to JSON for logging
        event_json = json.dumps(event, indent=2)
        return event_json
