"""
OAuth2 Provider for CatNet Authentication

Implements OAuth2 authentication with support for:
- Multiple OAuth providers (Google, GitHub, Azure AD, etc.)
- Authorization Code flow with PKCE
- Token refresh
- Scope management
"""

import secrets
import hashlib
import base64
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime, timedelta
import httpx
from urllib.parse import urlencode, parse_qs, urlparse
import json


@dataclass
class OAuthConfig:
    """OAuth provider configuration"""

    provider_name: str
    client_id: str
    client_secret: str
    authorize_url: str
    token_url: str
    userinfo_url: str
    redirect_uri: str
    scopes: List[str]
    jwks_uri: Optional[str] = None
    issuer: Optional[str] = None


class OAuth2Provider:
    """
    Handles OAuth2 authentication flows
    """

    # Well-known OAuth2 provider configurations
    PROVIDERS = {
        "google": {
            "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "userinfo_url": "https://www.googleapis.com/oauth2/v2/userinfo",
            "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
            "issuer": "https://accounts.google.com",
            "scopes": ["openid", "email", "profile"],
        },
        "github": {
            "authorize_url": "https://github.com/login/oauth/authorize",
            "token_url": "https://github.com/login/oauth/access_token",
            "userinfo_url": "https://api.github.com/user",
            "scopes": ["user:email", "read:user"],
        },
        "azure": {
            "authorize_url": "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
            "token_url": "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            "userinfo_url": "https://graph.microsoft.com/v1.0/me",
            "jwks_uri": "https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys",
            "issuer": "https://login.microsoftonline.com/{tenant}/v2.0",
            "scopes": ["openid", "email", "profile"],
        },
        "okta": {
            "authorize_url": "https://{domain}/oauth2/v1/authorize",
            "token_url": "https://{domain}/oauth2/v1/token",
            "userinfo_url": "https://{domain}/oauth2/v1/userinfo",
            "jwks_uri": "https://{domain}/oauth2/v1/keys",
            "issuer": "https://{domain}",
            "scopes": ["openid", "email", "profile"],
        },
    }

    def __init__(self):
        """Initialize OAuth2 provider"""
        self.configs: Dict[str, OAuthConfig] = {}
        self.state_store: Dict[str, Dict[str, Any]] = {}  # In production, use Redis
        self.pkce_store: Dict[str, str] = {}  # Store PKCE verifiers

    def register_provider(
        self,
        provider_name: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        tenant: Optional[str] = None,
        domain: Optional[str] = None,
        custom_config: Optional[Dict[str, Any]] = None,
    ) -> OAuthConfig:
        """
        Register an OAuth2 provider

        Args:
            provider_name: Name of the provider (google, github, azure, okta, custom)
            client_id: OAuth client ID
            client_secret: OAuth client secret
            redirect_uri: Redirect URI for OAuth callback
            tenant: Azure AD tenant ID (for Azure)
            domain: Okta domain (for Okta)
            custom_config: Custom provider configuration

        Returns:
            OAuthConfig instance
        """
        if custom_config:
            config_dict = custom_config
        elif provider_name in self.PROVIDERS:
            config_dict = self.PROVIDERS[provider_name].copy()

            # Replace placeholders for Azure/Okta
            if provider_name == "azure" and tenant:
                for key in config_dict:
                    if isinstance(config_dict[key], str):
                        config_dict[key] = config_dict[key].replace("{tenant}", tenant)
            elif provider_name == "okta" and domain:
                for key in config_dict:
                    if isinstance(config_dict[key], str):
                        config_dict[key] = config_dict[key].replace("{domain}", domain)
        else:
            raise ValueError(f"Unknown provider: {provider_name}")

        config = OAuthConfig(
            provider_name=provider_name,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            authorize_url=config_dict["authorize_url"],
            token_url=config_dict["token_url"],
            userinfo_url=config_dict["userinfo_url"],
            scopes=config_dict.get("scopes", ["openid", "email", "profile"]),
            jwks_uri=config_dict.get("jwks_uri"),
            issuer=config_dict.get("issuer"),
        )

        self.configs[provider_name] = config
        return config

    def generate_auth_url(
        self,
        provider_name: str,
        state: Optional[str] = None,
        nonce: Optional[str] = None,
        use_pkce: bool = True,
        additional_params: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        """
        Generate OAuth2 authorization URL

        Args:
            provider_name: Name of the OAuth provider
            state: State parameter for CSRF protection
            nonce: Nonce for OpenID Connect
            use_pkce: Use PKCE flow for enhanced security
            additional_params: Additional OAuth parameters

        Returns:
            Dict containing auth_url, state, and optional code_verifier
        """
        if provider_name not in self.configs:
            raise ValueError(f"Provider {provider_name} not registered")

        config = self.configs[provider_name]

        # Generate state for CSRF protection
        if not state:
            state = secrets.token_urlsafe(32)

        # Generate PKCE challenge if enabled
        code_verifier = None
        code_challenge = None
        if use_pkce:
            code_verifier = secrets.token_urlsafe(96)
            code_challenge = self._generate_code_challenge(code_verifier)
            self.pkce_store[state] = code_verifier

        # Build authorization URL parameters
        params = {
            "client_id": config.client_id,
            "redirect_uri": config.redirect_uri,
            "response_type": "code",
            "scope": " ".join(config.scopes),
            "state": state,
        }

        if use_pkce:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"

        if nonce:
            params["nonce"] = nonce

        if additional_params:
            params.update(additional_params)

        # Store state for validation
        self.state_store[state] = {
            "provider": provider_name,
            "nonce": nonce,
            "timestamp": datetime.utcnow().isoformat(),
            "pkce": use_pkce,
        }

        auth_url = f"{config.authorize_url}?{urlencode(params)}"

        return {
            "auth_url": auth_url,
            "state": state,
            "code_verifier": code_verifier,
        }

    async def exchange_code(
        self,
        provider_name: str,
        code: str,
        state: str,
        code_verifier: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Exchange authorization code for access token

        Args:
            provider_name: Name of the OAuth provider
            code: Authorization code
            state: State parameter for validation
            code_verifier: PKCE code verifier

        Returns:
            Dict containing access_token, refresh_token, etc.
        """
        if provider_name not in self.configs:
            raise ValueError(f"Provider {provider_name} not registered")

        # Validate state
        if state not in self.state_store:
            raise ValueError("Invalid state parameter")

        state_data = self.state_store[state]
        if state_data["provider"] != provider_name:
            raise ValueError("Provider mismatch")

        # Check state expiry (5 minutes)
        state_time = datetime.fromisoformat(state_data["timestamp"])
        if datetime.utcnow() - state_time > timedelta(minutes=5):
            del self.state_store[state]
            raise ValueError("State expired")

        config = self.configs[provider_name]

        # Prepare token request
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": config.redirect_uri,
            "client_id": config.client_id,
            "client_secret": config.client_secret,
        }

        # Add PKCE verifier if used
        if state_data.get("pkce") and state in self.pkce_store:
            token_data["code_verifier"] = self.pkce_store[state]
            del self.pkce_store[state]
        elif code_verifier:
            token_data["code_verifier"] = code_verifier

        # Exchange code for token
        async with httpx.AsyncClient() as client:
            response = await client.post(
                config.token_url,
                data=token_data,
                headers={"Accept": "application/json"},
            )

            if response.status_code != 200:
                raise Exception(f"Token exchange failed: {response.text}")

            token_response = response.json()

        # Clean up state
        del self.state_store[state]

        return token_response

    async def get_user_info(
        self, provider_name: str, access_token: str
    ) -> Dict[str, Any]:
        """
        Get user information from OAuth provider

        Args:
            provider_name: Name of the OAuth provider
            access_token: OAuth access token

        Returns:
            User information dict
        """
        if provider_name not in self.configs:
            raise ValueError(f"Provider {provider_name} not registered")

        config = self.configs[provider_name]

        async with httpx.AsyncClient() as client:
            response = await client.get(
                config.userinfo_url,
                headers={"Authorization": f"Bearer {access_token}"},
            )

            if response.status_code != 200:
                raise Exception(f"Failed to get user info: {response.text}")

            return response.json()

    async def refresh_token(
        self, provider_name: str, refresh_token: str
    ) -> Dict[str, Any]:
        """
        Refresh OAuth access token

        Args:
            provider_name: Name of the OAuth provider
            refresh_token: OAuth refresh token

        Returns:
            New token response
        """
        if provider_name not in self.configs:
            raise ValueError(f"Provider {provider_name} not registered")

        config = self.configs[provider_name]

        token_data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": config.client_id,
            "client_secret": config.client_secret,
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                config.token_url,
                data=token_data,
                headers={"Accept": "application/json"},
            )

            if response.status_code != 200:
                raise Exception(f"Token refresh failed: {response.text}")

            return response.json()

    async def revoke_token(
        self, provider_name: str, token: str, token_type: str = "access_token"
    ) -> bool:
        """
        Revoke OAuth token

        Args:
            provider_name: Name of the OAuth provider
            token: Token to revoke
            token_type: Type of token (access_token or refresh_token)

        Returns:
            Success status
        """
        if provider_name not in self.configs:
            raise ValueError(f"Provider {provider_name} not registered")

        config = self.configs[provider_name]

        # Not all providers support token revocation
        revoke_urls = {
            "google": "https://oauth2.googleapis.com/revoke",
            "github": None,  # GitHub doesn't support programmatic revocation
            "okta": f"{config.authorize_url.replace('/authorize', '/revoke')}",
        }

        revoke_url = revoke_urls.get(provider_name)
        if not revoke_url:
            return False

        async with httpx.AsyncClient() as client:
            response = await client.post(
                revoke_url,
                data={
                    "token": token,
                    "token_type_hint": token_type,
                    "client_id": config.client_id,
                    "client_secret": config.client_secret,
                },
            )

            return response.status_code == 200

    def _generate_code_challenge(self, verifier: str) -> str:
        """
        Generate PKCE code challenge from verifier

        Args:
            verifier: Code verifier

        Returns:
            Base64 URL encoded code challenge
        """
        digest = hashlib.sha256(verifier.encode()).digest()
        return base64.urlsafe_b64encode(digest).decode().rstrip("=")


# Convenience functions
_default_provider = None


def get_oauth_provider() -> OAuth2Provider:
    """Get default OAuth2 provider instance"""
    global _default_provider
    if _default_provider is None:
        _default_provider = OAuth2Provider()
    return _default_provider
