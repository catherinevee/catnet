"""
OAuth2 Provider Implementation for CatNet
Supports multiple OAuth2 flows: Authorization Code, Implicit, Client Credentials
"""

from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import secrets
import hashlib
import base64
from urllib.parse import urlencode, parse_qs
from fastapi import HTTPException, Request, Response, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2AuthorizationCodeBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import httpx
import jwt

from src.core.config import settings
from src.db.models import User, OAuthClient, OAuthCode, OAuthToken
from src.security.encryption import EncryptionManager
from src.security.audit import AuditLogger

class OAuth2Provider:
    """
    Complete OAuth2 provider implementation
    Supports Authorization Code, Implicit, Client Credentials, and PKCE flows
    """

    def __init__(self):
        self.encryption_manager = EncryptionManager()
        self.audit_logger = AuditLogger()
        self.jwt_secret = settings.jwt_secret_key
        self.jwt_algorithm = settings.jwt_algorithm

    async def register_client(
        self,
        db: AsyncSession,
        client_name: str,
        redirect_uris: List[str],
        grant_types: List[str],
        response_types: List[str],
        scope: str,
        owner_id: str,
        client_type: str = "confidential"
    ) -> OAuthClient:
        """
        Register new OAuth2 client application
        """
        client_id = secrets.token_urlsafe(32)
        client_secret = secrets.token_urlsafe(64) if client_type == "confidential" else None

        client = OAuthClient(
            client_id=client_id,
            client_secret=self.encryption_manager.encrypt(client_secret) if client_secret else None,
            client_name=client_name,
            redirect_uris=redirect_uris,
            grant_types=grant_types,
            response_types=response_types,
            scope=scope,
            owner_id=owner_id,
            client_type=client_type,
            is_active=True
        )

        db.add(client)
        await db.commit()
        await db.refresh(client)

        await self.audit_logger.log_event(
            db=db,
            user_id=owner_id,
            action="oauth2.client.register",
            details={
                "client_id": client_id,
                "client_name": client_name,
                "grant_types": grant_types
            }
        )

        return client

    async def validate_client(
        self,
        db: AsyncSession,
        client_id: str,
        client_secret: Optional[str] = None,
        grant_type: Optional[str] = None
    ) -> Optional[OAuthClient]:
        """
        Validate OAuth2 client credentials
        """
        stmt = select(OAuthClient).where(
            OAuthClient.client_id == client_id,
            OAuthClient.is_active == True
        )
        result = await db.execute(stmt)
        client = result.scalar_one_or_none()

        if not client:
            return None

        if client.client_type == "confidential" and client_secret:
            stored_secret = self.encryption_manager.decrypt(client.client_secret)
            if stored_secret != client_secret:
                return None

        if grant_type and grant_type not in client.grant_types:
            return None

        return client

    async def generate_authorization_code(
        self,
        db: AsyncSession,
        client_id: str,
        user_id: str,
        redirect_uri: str,
        scope: str,
        state: Optional[str] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None
    ) -> str:
        """
        Generate authorization code for OAuth2 flow
        """
        code = secrets.token_urlsafe(48)
        expires_at = datetime.utcnow() + timedelta(minutes=10)

        auth_code = OAuthCode(
            code=self.encryption_manager.encrypt(code),
            client_id=client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=expires_at,
            used=False
        )

        db.add(auth_code)
        await db.commit()

        await self.audit_logger.log_event(
            db=db,
            user_id=user_id,
            action="oauth2.code.generate",
            details={
                "client_id": client_id,
                "scope": scope,
                "pkce": bool(code_challenge)
            }
        )

        return code

    async def exchange_authorization_code(
        self,
        db: AsyncSession,
        code: str,
        client_id: str,
        redirect_uri: str,
        code_verifier: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Exchange authorization code for access token
        """
        stmt = select(OAuthCode).where(
            OAuthCode.client_id == client_id,
            OAuthCode.redirect_uri == redirect_uri,
            OAuthCode.used == False,
            OAuthCode.expires_at > datetime.utcnow()
        )
        result = await db.execute(stmt)
        auth_codes = result.scalars().all()

        valid_code = None
        for auth_code in auth_codes:
            if self.encryption_manager.decrypt(auth_code.code) == code:
                valid_code = auth_code
                break

        if not valid_code:
            raise HTTPException(status_code=400, detail="Invalid authorization code")

        if valid_code.code_challenge and code_verifier:
            if not self._verify_pkce(code_verifier, valid_code.code_challenge, valid_code.code_challenge_method):
                raise HTTPException(status_code=400, detail="Invalid PKCE verification")

        valid_code.used = True
        await db.commit()

        access_token = self._generate_access_token(
            user_id=str(valid_code.user_id),
            client_id=client_id,
            scope=valid_code.scope
        )

        refresh_token = self._generate_refresh_token(
            user_id=str(valid_code.user_id),
            client_id=client_id
        )

        token_record = OAuthToken(
            access_token=self.encryption_manager.encrypt(access_token),
            refresh_token=self.encryption_manager.encrypt(refresh_token),
            client_id=client_id,
            user_id=valid_code.user_id,
            scope=valid_code.scope,
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )

        db.add(token_record)
        await db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": valid_code.scope
        }

    async def refresh_access_token(
        self,
        db: AsyncSession,
        refresh_token: str,
        client_id: str,
        client_secret: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Refresh access token using refresh token
        """
        client = await self.validate_client(db, client_id, client_secret)
        if not client:
            raise HTTPException(status_code=401, detail="Invalid client credentials")

        try:
            payload = jwt.decode(refresh_token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            if payload.get("type") != "refresh":
                raise HTTPException(status_code=401, detail="Invalid token type")

            user_id = payload.get("sub")
            scope = payload.get("scope", "")

            new_access_token = self._generate_access_token(
                user_id=user_id,
                client_id=client_id,
                scope=scope
            )

            new_refresh_token = self._generate_refresh_token(
                user_id=user_id,
                client_id=client_id
            )

            return {
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": scope
            }

        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid refresh token")

    async def client_credentials_grant(
        self,
        db: AsyncSession,
        client_id: str,
        client_secret: str,
        scope: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Client credentials OAuth2 flow for machine-to-machine auth
        """
        client = await self.validate_client(db, client_id, client_secret, "client_credentials")
        if not client:
            raise HTTPException(status_code=401, detail="Invalid client credentials")

        if scope and not all(s in client.scope.split() for s in scope.split()):
            raise HTTPException(status_code=400, detail="Invalid scope")

        access_token = self._generate_access_token(
            user_id=None,
            client_id=client_id,
            scope=scope or client.scope
        )

        token_record = OAuthToken(
            access_token=self.encryption_manager.encrypt(access_token),
            refresh_token=None,
            client_id=client_id,
            user_id=None,
            scope=scope or client.scope,
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )

        db.add(token_record)
        await db.commit()

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": scope or client.scope
        }

    async def revoke_token(
        self,
        db: AsyncSession,
        token: str,
        token_type_hint: Optional[str] = None,
        client_id: Optional[str] = None
    ) -> bool:
        """
        Revoke OAuth2 token (access or refresh)
        """
        stmt = select(OAuthToken).where(OAuthToken.revoked == False)
        if client_id:
            stmt = stmt.where(OAuthToken.client_id == client_id)

        result = await db.execute(stmt)
        tokens = result.scalars().all()

        for token_record in tokens:
            decrypted_access = self.encryption_manager.decrypt(token_record.access_token)
            if decrypted_access == token:
                token_record.revoked = True
                await db.commit()
                return True

            if token_record.refresh_token:
                decrypted_refresh = self.encryption_manager.decrypt(token_record.refresh_token)
                if decrypted_refresh == token:
                    token_record.revoked = True
                    await db.commit()
                    return True

        return False

    async def introspect_token(
        self,
        db: AsyncSession,
        token: str,
        token_type_hint: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Token introspection endpoint for resource servers
        """
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])

            stmt = select(OAuthToken).where(
                OAuthToken.revoked == False,
                OAuthToken.expires_at > datetime.utcnow()
            )
            result = await db.execute(stmt)
            tokens = result.scalars().all()

            for token_record in tokens:
                decrypted = self.encryption_manager.decrypt(token_record.access_token)
                if decrypted == token:
                    return {
                        "active": True,
                        "scope": token_record.scope,
                        "client_id": token_record.client_id,
                        "username": payload.get("username"),
                        "exp": int(token_record.expires_at.timestamp()),
                        "iat": int(token_record.created_at.timestamp()),
                        "sub": str(token_record.user_id) if token_record.user_id else None,
                        "aud": payload.get("aud", []),
                        "iss": settings.app_name
                    }

            return {"active": False}

        except jwt.InvalidTokenError:
            return {"active": False}

    def _generate_access_token(
        self,
        user_id: Optional[str],
        client_id: str,
        scope: str
    ) -> str:
        """
        Generate JWT access token
        """
        payload = {
            "sub": user_id,
            "client_id": client_id,
            "scope": scope,
            "type": "access",
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(hours=1),
            "iss": settings.app_name,
            "aud": [settings.app_name]
        }

        return jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)

    def _generate_refresh_token(
        self,
        user_id: Optional[str],
        client_id: str
    ) -> str:
        """
        Generate JWT refresh token
        """
        payload = {
            "sub": user_id,
            "client_id": client_id,
            "type": "refresh",
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(days=30),
            "iss": settings.app_name
        }

        return jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)

    def _verify_pkce(
        self,
        verifier: str,
        challenge: str,
        method: str = "S256"
    ) -> bool:
        """
        Verify PKCE code challenge
        """
        if method == "plain":
            return verifier == challenge
        elif method == "S256":
            verifier_hash = hashlib.sha256(verifier.encode()).digest()
            verifier_challenge = base64.urlsafe_b64encode(verifier_hash).decode().rstrip("=")
            return verifier_challenge == challenge

        return False

    async def get_authorization_url(
        self,
        client_id: str,
        redirect_uri: str,
        scope: str,
        state: Optional[str] = None,
        response_type: str = "code",
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None
    ) -> str:
        """
        Build OAuth2 authorization URL
        """
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "scope": scope
        }

        if state:
            params["state"] = state

        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = code_challenge_method or "S256"

        return f"{settings.oauth2_authorization_endpoint}?{urlencode(params)}"


oauth2_provider = OAuth2Provider()