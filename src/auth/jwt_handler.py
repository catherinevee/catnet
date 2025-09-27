from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import jwt
from uuid import UUID
import secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from .models import Token, TokenType, User
import hashlib
import base64
from functools import lru_cache


class JWTHandler:
    def __init__(self,
                 private_key: Optional[str] = None,
                 public_key: Optional[str] = None,
                 algorithm: str = "RS256",
                 access_token_expire_minutes: int = 30,
                 refresh_token_expire_days: int = 30,
                 issuer: str = "catnet",
                 audience: str = "catnet-api"):

        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days
        self.issuer = issuer
        self.audience = audience

        if algorithm in ["RS256", "RS384", "RS512"]:
            if not private_key or not public_key:
                self._generate_rsa_keys()
            else:
                self.private_key = private_key
                self.public_key = public_key
        else:
            self.secret_key = private_key or secrets.token_urlsafe(64)

        self.revoked_tokens = set()
        self._token_cache = {}

    def _generate_rsa_keys(self):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )

        self.private_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        self.public_key = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def create_access_token(self,
                           user: User,
                           scopes: Optional[List[str]] = None,
                           additional_claims: Optional[Dict[str, Any]] = None) -> Token:

        expires_at = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)

        payload = {
            "sub": str(user.id),
            "username": user.username,
            "email": user.email,
            "roles": [role.value for role in user.roles],
            "permissions": user.permissions,
            "scopes": scopes or [],
            "iat": datetime.utcnow(),
            "exp": expires_at,
            "iss": self.issuer,
            "aud": self.audience,
            "jti": secrets.token_urlsafe(32),
            "token_type": TokenType.ACCESS.value
        }

        if additional_claims:
            payload.update(additional_claims)

        if self.algorithm.startswith("RS"):
            token_string = jwt.encode(payload, self.private_key, algorithm=self.algorithm)
        else:
            token_string = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

        token = Token(
            token=token_string,
            token_type=TokenType.ACCESS,
            user_id=user.id,
            expires_at=expires_at,
            scopes=scopes or []
        )

        self._cache_token(token)

        return token

    def create_refresh_token(self,
                            user: User,
                            device_fingerprint: Optional[str] = None) -> Token:

        expires_at = datetime.utcnow() + timedelta(days=self.refresh_token_expire_days)

        payload = {
            "sub": str(user.id),
            "username": user.username,
            "iat": datetime.utcnow(),
            "exp": expires_at,
            "iss": self.issuer,
            "aud": self.audience,
            "jti": secrets.token_urlsafe(32),
            "token_type": TokenType.REFRESH.value,
            "device_fingerprint": device_fingerprint
        }

        if self.algorithm.startswith("RS"):
            token_string = jwt.encode(payload, self.private_key, algorithm=self.algorithm)
        else:
            token_string = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

        token = Token(
            token=token_string,
            token_type=TokenType.REFRESH,
            user_id=user.id,
            expires_at=expires_at,
            device_fingerprint=device_fingerprint
        )

        self._cache_token(token)

        return token

    def create_mfa_token(self, user: User, ttl_minutes: int = 5) -> Token:
        expires_at = datetime.utcnow() + timedelta(minutes=ttl_minutes)

        payload = {
            "sub": str(user.id),
            "username": user.username,
            "purpose": "mfa_verification",
            "iat": datetime.utcnow(),
            "exp": expires_at,
            "iss": self.issuer,
            "jti": secrets.token_urlsafe(32),
            "token_type": TokenType.MFA.value
        }

        if self.algorithm.startswith("RS"):
            token_string = jwt.encode(payload, self.private_key, algorithm=self.algorithm)
        else:
            token_string = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

        token = Token(
            token=token_string,
            token_type=TokenType.MFA,
            user_id=user.id,
            expires_at=expires_at
        )

        return token

    def verify_token(self, token_string: str, token_type: Optional[TokenType] = None) -> Dict[str, Any]:
        if self._is_revoked(token_string):
            raise jwt.InvalidTokenError("Token has been revoked")

        cached_payload = self._get_cached_token(token_string)
        if cached_payload:
            return cached_payload

        try:
            if self.algorithm.startswith("RS"):
                payload = jwt.decode(
                    token_string,
                    self.public_key,
                    algorithms=[self.algorithm],
                    issuer=self.issuer,
                    audience=self.audience
                )
            else:
                payload = jwt.decode(
                    token_string,
                    self.secret_key,
                    algorithms=[self.algorithm],
                    issuer=self.issuer,
                    audience=self.audience
                )

            if token_type and payload.get("token_type") != token_type.value:
                raise jwt.InvalidTokenError(f"Invalid token type. Expected {token_type.value}")

            self._cache_token_payload(token_string, payload)

            return payload

        except jwt.ExpiredSignatureError:
            raise jwt.InvalidTokenError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise jwt.InvalidTokenError(f"Invalid token: {str(e)}")
        except Exception as e:
            raise jwt.InvalidTokenError(f"Token verification failed: {str(e)}")

    def refresh_access_token(self, refresh_token_string: str, user: User) -> Token:
        payload = self.verify_token(refresh_token_string, TokenType.REFRESH)

        if str(user.id) != payload.get("sub"):
            raise jwt.InvalidTokenError("Token does not belong to user")

        self.revoke_token(refresh_token_string)

        new_access_token = self.create_access_token(
            user=user,
            scopes=payload.get("scopes", [])
        )

        return new_access_token

    def revoke_token(self, token_string: str):
        token_hash = self._hash_token(token_string)
        self.revoked_tokens.add(token_hash)

        if token_string in self._token_cache:
            del self._token_cache[token_string]

    def _is_revoked(self, token_string: str) -> bool:
        token_hash = self._hash_token(token_string)
        return token_hash in self.revoked_tokens

    def _hash_token(self, token_string: str) -> str:
        return hashlib.sha256(token_string.encode()).hexdigest()

    def _cache_token(self, token: Token):
        self._token_cache[token.token] = {
            "payload": None,
            "token": token,
            "cached_at": datetime.utcnow()
        }

    def _cache_token_payload(self, token_string: str, payload: Dict[str, Any]):
        self._token_cache[token_string] = {
            "payload": payload,
            "cached_at": datetime.utcnow()
        }

    def _get_cached_token(self, token_string: str) -> Optional[Dict[str, Any]]:
        if token_string in self._token_cache:
            cached = self._token_cache[token_string]
            cache_age = (datetime.utcnow() - cached["cached_at"]).total_seconds()

            if cache_age < 300:
                return cached.get("payload")
            else:
                del self._token_cache[token_string]

        return None

    def extract_claims(self, token_string: str) -> Dict[str, Any]:
        parts = token_string.split('.')
        if len(parts) != 3:
            raise jwt.InvalidTokenError("Invalid token format")

        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding

        try:
            decoded = base64.urlsafe_b64decode(payload)
            import json
            return json.loads(decoded)
        except Exception as e:
            raise jwt.InvalidTokenError(f"Failed to extract claims: {str(e)}")

    def create_api_key(self, user: User, name: str, expires_days: int = 365) -> Token:
        expires_at = datetime.utcnow() + timedelta(days=expires_days)

        api_key = secrets.token_urlsafe(48)

        payload = {
            "sub": str(user.id),
            "username": user.username,
            "key_name": name,
            "iat": datetime.utcnow(),
            "exp": expires_at,
            "iss": self.issuer,
            "token_type": TokenType.API_KEY.value
        }

        if self.algorithm.startswith("RS"):
            token_string = jwt.encode(payload, self.private_key, algorithm=self.algorithm)
        else:
            token_string = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

        token = Token(
            token=f"cnk_{api_key}",
            token_type=TokenType.API_KEY,
            user_id=user.id,
            expires_at=expires_at,
            client_id=name
        )

        return token

    def cleanup_expired_cache(self):
        current_time = datetime.utcnow()
        expired_keys = []

        for token_string, cached_data in self._token_cache.items():
            cache_age = (current_time - cached_data["cached_at"]).total_seconds()
            if cache_age > 3600:
                expired_keys.append(token_string)

        for key in expired_keys:
            del self._token_cache[key]