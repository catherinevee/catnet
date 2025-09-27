from typing import Optional, Dict, Any
from fastapi import HTTPException, status
from httpx import AsyncClient
import structlog
from pydantic import BaseModel
import os

logger = structlog.get_logger()

class OAuth2Config(BaseModel):
    client_id: str
    client_secret: str
    authorization_url: str
    token_url: str
    userinfo_url: str
    scope: str = "openid profile email"
    redirect_uri: str

class OAuth2Handler:
    def __init__(self):
        self.providers = self._load_providers()
        self.http_client = AsyncClient()

    def _load_providers(self) -> Dict[str, OAuth2Config]:
        providers = {}

        if os.getenv("OAUTH_AZURE_CLIENT_ID"):
            providers["azure"] = OAuth2Config(
                client_id=os.getenv("OAUTH_AZURE_CLIENT_ID"),
                client_secret=os.getenv("OAUTH_AZURE_CLIENT_SECRET"),
                authorization_url=f"https://login.microsoftonline.com/{os.getenv('OAUTH_AZURE_TENANT_ID')}/oauth2/v2.0/authorize",
                token_url=f"https://login.microsoftonline.com/{os.getenv('OAUTH_AZURE_TENANT_ID')}/oauth2/v2.0/token",
                userinfo_url="https://graph.microsoft.com/v1.0/me",
                redirect_uri=os.getenv("OAUTH_AZURE_REDIRECT_URI", "http://localhost:8081/auth/callback")
            )

        if os.getenv("OAUTH_OKTA_CLIENT_ID"):
            providers["okta"] = OAuth2Config(
                client_id=os.getenv("OAUTH_OKTA_CLIENT_ID"),
                client_secret=os.getenv("OAUTH_OKTA_CLIENT_SECRET"),
                authorization_url=f"{os.getenv('OAUTH_OKTA_DOMAIN')}/oauth2/v1/authorize",
                token_url=f"{os.getenv('OAUTH_OKTA_DOMAIN')}/oauth2/v1/token",
                userinfo_url=f"{os.getenv('OAUTH_OKTA_DOMAIN')}/oauth2/v1/userinfo",
                redirect_uri=os.getenv("OAUTH_OKTA_REDIRECT_URI", "http://localhost:8081/auth/callback")
            )

        if os.getenv("OAUTH_GOOGLE_CLIENT_ID"):
            providers["google"] = OAuth2Config(
                client_id=os.getenv("OAUTH_GOOGLE_CLIENT_ID"),
                client_secret=os.getenv("OAUTH_GOOGLE_CLIENT_SECRET"),
                authorization_url="https://accounts.google.com/o/oauth2/v2/auth",
                token_url="https://oauth2.googleapis.com/token",
                userinfo_url="https://www.googleapis.com/oauth2/v1/userinfo",
                redirect_uri=os.getenv("OAUTH_GOOGLE_REDIRECT_URI", "http://localhost:8081/auth/callback")
            )

        return providers

    def get_authorization_url(
        self,
        provider: str,
        state: str
    ) -> str:
        if provider not in self.providers:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Provider {provider} not configured"
            )

        config = self.providers[provider]
        params = {
            "client_id": config.client_id,
            "response_type": "code",
            "redirect_uri": config.redirect_uri,
            "scope": config.scope,
            "state": state,
            "access_type": "offline",
            "prompt": "consent"
        }

        query_string = "&".join([f"{k}={v}" for k, v in params.items()])
        return f"{config.authorization_url}?{query_string}"

    async def exchange_code(
        self,
        provider: str,
        code: str
    ) -> Dict[str, Any]:
        if provider not in self.providers:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Provider {provider} not configured"
            )

        config = self.providers[provider]

        try:
            response = await self.http_client.post(
                config.token_url,
                data={
                    "client_id": config.client_id,
                    "client_secret": config.client_secret,
                    "code": code,
                    "redirect_uri": config.redirect_uri,
                    "grant_type": "authorization_code"
                }
            )

            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Failed to exchange authorization code"
                )

            return response.json()

        except Exception as e:
            await logger.aerror(f"OAuth code exchange error: {e}")
            raise

    async def get_user_info(
        self,
        provider: str,
        access_token: str
    ) -> Dict[str, Any]:
        if provider not in self.providers:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Provider {provider} not configured"
            )

        config = self.providers[provider]

        try:
            response = await self.http_client.get(
                config.userinfo_url,
                headers={"Authorization": f"Bearer {access_token}"}
            )

            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Failed to get user information"
                )

            user_info = response.json()

            normalized = {
                "sub": user_info.get("sub") or user_info.get("id"),
                "email": user_info.get("email") or user_info.get("mail"),
                "name": user_info.get("name") or user_info.get("displayName"),
                "given_name": user_info.get("given_name") or user_info.get("givenName"),
                "family_name": user_info.get("family_name") or user_info.get("surname"),
                "picture": user_info.get("picture"),
                "email_verified": user_info.get("email_verified", False),
                "raw": user_info
            }

            return normalized

        except Exception as e:
            await logger.aerror(f"OAuth user info error: {e}")
            raise

    async def refresh_token(
        self,
        provider: str,
        refresh_token: str
    ) -> Dict[str, Any]:
        if provider not in self.providers:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Provider {provider} not configured"
            )

        config = self.providers[provider]

        try:
            response = await self.http_client.post(
                config.token_url,
                data={
                    "client_id": config.client_id,
                    "client_secret": config.client_secret,
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token"
                }
            )

            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Failed to refresh token"
                )

            return response.json()

        except Exception as e:
            await logger.aerror(f"OAuth token refresh error: {e}")
            raise

    async def close(self):
        await self.http_client.aclose()