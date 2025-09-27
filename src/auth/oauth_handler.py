from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import secrets
import hashlib
import base64
import json
import aiohttp
from urllib.parse import urlencode, parse_qs, urlparse
from .models import OAuth2Config, User, UserRole
import jwt
from authlib.integrations.starlette_client import OAuth
from authlib.oauth2.rfc6749 import OAuth2Token
import asyncio


class OAuth2Handler:
    def __init__(self):
        self.oauth_configs: Dict[str, OAuth2Config] = {}
        self.oauth_clients: Dict[str, OAuth] = {}
        self.state_store: Dict[str, Dict[str, Any]] = {}
        self.pkce_store: Dict[str, str] = {}

    def register_provider(self, provider_name: str, config: OAuth2Config):
        self.oauth_configs[provider_name] = config

        oauth = OAuth()
        oauth.register(
            name=provider_name,
            client_id=config.client_id,
            client_secret=config.client_secret.get_secret_value(),
            server_metadata_url=f"{config.authorization_url}/.well-known/openid-configuration"
            if config.authorization_url.startswith("https://")
            else None,
            client_kwargs={"scope": " ".join(config.scopes)}
        )
        self.oauth_clients[provider_name] = oauth

    def generate_state(self, provider: str, user_agent: Optional[str] = None) -> str:
        state = secrets.token_urlsafe(32)
        self.state_store[state] = {
            "provider": provider,
            "created_at": datetime.utcnow(),
            "user_agent": user_agent
        }
        return state

    def verify_state(self, state: str, provider: str) -> bool:
        if state not in self.state_store:
            return False

        stored_state = self.state_store[state]

        if stored_state["provider"] != provider:
            return False

        state_age = (datetime.utcnow() - stored_state["created_at"]).total_seconds()
        if state_age > 600:
            del self.state_store[state]
            return False

        return True

    def generate_pkce_challenge(self) -> tuple[str, str]:
        verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).decode('utf-8').rstrip('=')
        return verifier, challenge

    def get_authorization_url(self,
                             provider: str,
                             redirect_uri: str,
                             state: Optional[str] = None,
                             use_pkce: bool = True) -> str:

        if provider not in self.oauth_configs:
            raise ValueError(f"Provider {provider} not registered")

        config = self.oauth_configs[provider]

        if not state:
            state = self.generate_state(provider)

        params = {
            "client_id": config.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(config.scopes),
            "state": state,
            "access_type": "offline",
            "prompt": "consent"
        }

        if use_pkce:
            verifier, challenge = self.generate_pkce_challenge()
            self.pkce_store[state] = verifier
            params["code_challenge"] = challenge
            params["code_challenge_method"] = "S256"

        return f"{config.authorization_url}?{urlencode(params)}"

    async def exchange_code_for_token(self,
                                     provider: str,
                                     code: str,
                                     redirect_uri: str,
                                     state: str) -> OAuth2Token:

        if not self.verify_state(state, provider):
            raise ValueError("Invalid or expired state")

        if provider not in self.oauth_configs:
            raise ValueError(f"Provider {provider} not registered")

        config = self.oauth_configs[provider]

        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": config.client_id,
            "client_secret": config.client_secret.get_secret_value()
        }

        if state in self.pkce_store:
            data["code_verifier"] = self.pkce_store[state]
            del self.pkce_store[state]

        async with aiohttp.ClientSession() as session:
            async with session.post(
                config.token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise ValueError(f"Token exchange failed: {error_text}")

                token_data = await response.json()

        del self.state_store[state]

        return OAuth2Token(token_data)

    async def get_user_info(self, provider: str, access_token: str) -> Dict[str, Any]:
        if provider not in self.oauth_configs:
            raise ValueError(f"Provider {provider} not registered")

        config = self.oauth_configs[provider]

        headers = {"Authorization": f"Bearer {access_token}"}

        async with aiohttp.ClientSession() as session:
            async with session.get(config.user_info_url, headers=headers) as response:
                if response.status != 200:
                    raise ValueError("Failed to fetch user info")

                return await response.json()

    async def refresh_token(self, provider: str, refresh_token: str) -> OAuth2Token:
        if provider not in self.oauth_configs:
            raise ValueError(f"Provider {provider} not registered")

        config = self.oauth_configs[provider]

        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": config.client_id,
            "client_secret": config.client_secret.get_secret_value()
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                config.token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            ) as response:
                if response.status != 200:
                    raise ValueError("Token refresh failed")

                token_data = await response.json()

        return OAuth2Token(token_data)

    def map_oauth_user_to_internal(self,
                                  provider: str,
                                  user_info: Dict[str, Any]) -> User:

        mapping = self._get_provider_mapping(provider)

        user_id = user_info.get(mapping.get("id", "sub"))
        email = user_info.get(mapping.get("email", "email"))
        name = user_info.get(mapping.get("name", "name"))
        username = user_info.get(mapping.get("username", "preferred_username"), email)

        if not email:
            raise ValueError("Email not provided by OAuth provider")

        user = User(
            username=username or email.split("@")[0],
            email=email,
            full_name=name or username,
            roles=[UserRole.VIEWER],
            auth_methods=["oauth2"],
            metadata={
                f"{provider}_id": user_id,
                "oauth_provider": provider,
                "oauth_data": user_info
            }
        )

        if provider == "google" and user_info.get("hd"):
            user.metadata["google_domain"] = user_info["hd"]

        if provider == "github":
            if user_info.get("site_admin"):
                user.roles = [UserRole.ADMIN]
            user.metadata["github_login"] = user_info.get("login")

        if provider == "azure":
            user.metadata["azure_tenant"] = user_info.get("tid")
            groups = user_info.get("groups", [])
            user.metadata["azure_groups"] = groups
            self._map_azure_groups_to_roles(user, groups)

        return user

    def _get_provider_mapping(self, provider: str) -> Dict[str, str]:
        mappings = {
            "google": {
                "id": "sub",
                "email": "email",
                "name": "name",
                "username": "email"
            },
            "github": {
                "id": "id",
                "email": "email",
                "name": "name",
                "username": "login"
            },
            "azure": {
                "id": "oid",
                "email": "email",
                "name": "name",
                "username": "preferred_username"
            },
            "okta": {
                "id": "sub",
                "email": "email",
                "name": "name",
                "username": "preferred_username"
            }
        }
        return mappings.get(provider, {})

    def _map_azure_groups_to_roles(self, user: User, groups: List[str]):
        role_mapping = {
            "catnet-admins": UserRole.ADMIN,
            "catnet-operators": UserRole.OPERATOR,
            "catnet-deployers": UserRole.DEPLOYER,
            "catnet-auditors": UserRole.AUDITOR,
            "catnet-viewers": UserRole.VIEWER
        }

        for group in groups:
            if group in role_mapping:
                if role_mapping[group] not in user.roles:
                    user.roles.append(role_mapping[group])

    async def validate_oauth_token(self, provider: str, token: str) -> Dict[str, Any]:
        if provider not in self.oauth_configs:
            raise ValueError(f"Provider {provider} not registered")

        config = self.oauth_configs[provider]

        if provider == "google":
            return await self._validate_google_token(token)
        elif provider == "github":
            return await self._validate_github_token(token)
        elif provider == "azure":
            return await self._validate_azure_token(token, config)
        else:
            return await self.get_user_info(provider, token)

    async def _validate_google_token(self, token: str) -> Dict[str, Any]:
        url = f"https://oauth2.googleapis.com/tokeninfo?access_token={token}"

        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status != 200:
                    raise ValueError("Invalid Google token")

                token_info = await response.json()

                if "error" in token_info:
                    raise ValueError(f"Token validation error: {token_info['error']}")

                return token_info

    async def _validate_github_token(self, token: str) -> Dict[str, Any]:
        headers = {"Authorization": f"token {token}"}

        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://api.github.com/user",
                headers=headers
            ) as response:
                if response.status != 200:
                    raise ValueError("Invalid GitHub token")

                return await response.json()

    async def _validate_azure_token(self, token: str, config: OAuth2Config) -> Dict[str, Any]:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        import requests

        jwks_uri = "https://login.microsoftonline.com/common/discovery/v2.0/keys"

        async with aiohttp.ClientSession() as session:
            async with session.get(jwks_uri) as response:
                jwks = await response.json()

        header = jwt.get_unverified_header(token)
        kid = header["kid"]

        key_data = None
        for key in jwks["keys"]:
            if key["kid"] == kid:
                key_data = key
                break

        if not key_data:
            raise ValueError("Token signing key not found")

        try:
            decoded = jwt.decode(
                token,
                key=key_data,
                algorithms=["RS256"],
                audience=config.client_id
            )
            return decoded
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid Azure token: {str(e)}")

    def cleanup_expired_states(self):
        current_time = datetime.utcnow()
        expired_states = []

        for state, data in self.state_store.items():
            age = (current_time - data["created_at"]).total_seconds()
            if age > 600:
                expired_states.append(state)

        for state in expired_states:
            del self.state_store[state]
            if state in self.pkce_store:
                del self.pkce_store[state]

    def revoke_token(self, provider: str, token: str, token_type: str = "access_token"):
        """Revoke OAuth token."""
        logger.info(f"Revoking {token_type} token for provider {provider}")

        if provider not in self.oauth_configs:
            logger.warning(f"Provider {provider} not configured for token revocation")
            return False

        try:
            # In a real implementation, this would make HTTP request to provider's revocation endpoint
            # For now, just log the action
            logger.info(f"Token revocation simulated for provider {provider}")
            return True
        except Exception as e:
            logger.error(f"Failed to revoke token for provider {provider}: {e}")
            return False

    async def get_provider_metadata(self, provider: str) -> Dict[str, Any]:
        if provider not in self.oauth_configs:
            raise ValueError(f"Provider {provider} not registered")

        config = self.oauth_configs[provider]

        well_known_url = None
        if provider == "google":
            well_known_url = "https://accounts.google.com/.well-known/openid-configuration"
        elif provider == "azure":
            well_known_url = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"
        elif provider == "okta":
            domain = urlparse(config.authorization_url).netloc
            well_known_url = f"https://{domain}/.well-known/openid-configuration"

        if well_known_url:
            async with aiohttp.ClientSession() as session:
                async with session.get(well_known_url) as response:
                    if response.status == 200:
                        return await response.json()

        return {
            "authorization_endpoint": config.authorization_url,
            "token_endpoint": config.token_url,
            "userinfo_endpoint": config.user_info_url,
            "scopes_supported": config.scopes
        }