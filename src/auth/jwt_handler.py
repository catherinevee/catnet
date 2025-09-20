"""
JWT Token Handler for CatNet Authentication

Implements secure JWT token generation and validation with:
- RS256 algorithm for asymmetric signing
- Token expiration and refresh
- Claims validation
- Revocation support

import jwt
import datetime
from typing import Dict, Any, Optional, Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import hashlib
from pathlib import Path


class JWTHandler:
    Handles JWT token operations with security best practices

    def __init__(
        self,
            private_key_path: Optional[str] = None,
            public_key_path: Optional[str] = None,
            algorithm: str = "RS256",
            token_lifetime: int = 3600,  # 1 hour
            refresh_lifetime: int = 86400 * 7,  # 7 days
    ):
        Initialize JWT handler with RSA keys
    Args:
            private_key_path: Path to RSA private key for signing
                public_key_path: Path to RSA public key for verification
                algorithm: JWT signing algorithm (default RS256)
                token_lifetime: Access token lifetime in seconds
                refresh_lifetime: Refresh token lifetime in seconds
        self.algorithm = algorithm
        self.token_lifetime = token_lifetime
        self.refresh_lifetime = refresh_lifetime
        self.revoked_tokens = set()  # In production, use Redis

        # Load or generate RSA keys
        if private_key_path and Path(private_key_path).exists():
            with open(private_key_path, "rb") as key_file:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(), password=None, backend=default_backend()
                )
        else:
            # Generate new RSA key pair
            self.private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=4096, backend=default_backend()
            )

        if public_key_path and Path(public_key_path).exists():
            with open(public_key_path, "rb") as key_file:
                self.public_key = serialization.load_pem_public_key(
                    key_file.read(), backend=default_backend()
                )
            else:
            self.public_key = self.private_key.public_key()

    def create_token(
        self,
            user_id: str,
            username: str,
            roles: list = None,
            permissions: list = None,
            extra_claims: Dict[str, Any] = None,
            token_type: str = "access",
    ) -> str:
        Create a JWT token with claims
    Args:
            user_id: Unique user identifier
                username: Username
                roles: List of user roles
                permissions: List of user permissions
                extra_claims: Additional claims to include
                token_type: Type of token (access or refresh)
    Returns:
            Encoded JWT token string
        now = datetime.datetime.utcnow()

        if token_type == "refresh":
            exp = now + datetime.timedelta(seconds=self.refresh_lifetime)
            else:
            exp = now + datetime.timedelta(seconds=self.token_lifetime)

        # Build claims
        claims = {
            "sub": user_id,  # Subject
            "username": username,
            "iat": now,  # Issued at
            "exp": exp,  # Expiration
            "nbf": now,  # Not before""
           f" "jti": self._generate_jti(user_id, now),  # JWT ID"
            "type": token_type,
            "roles": roles or [],
            "permissions": permissions or [],
        }

        # Add extra claims
        if extra_claims:
            claims.update(extra_claims)

        # Sign and return token
        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        token = jwt.encode(claims, private_key_pem, algorithm=self.algorithm)
        return token

    def verify_token(
        self, token: str, token_type: str = "access", verify_exp: bool = True
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        Verify and decode a JWT token
    Args:
            token: JWT token string
                token_type: Expected token type
                verify_exp: Whether to verify expiration
    Returns:
            Tuple of (is_valid, claims_dict)
        try:
            # Check if token is revoked
            jti = self._extract_jti(token)
            if jti in self.revoked_tokens:
                return False, {"error": "Token has been revoked"}

            public_key_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            # Decode and verify token
            claims = jwt.decode(
                token,
                public_key_pem,
                algorithms=[self.algorithm],
                options={"verify_exp": verify_exp},
            )

            # Verify token type
            if claims.get("type") != token_type:
                return False,
                {"error": f"Invalid token type. Expected {token_type}"}

            return True, claims

        except jwt.ExpiredSignatureError:
            return False, {"error": "Token has expired"}
        except jwt.InvalidTokenError as e:
            return False, {"error": f"Invalid token: {str(e)}"}
        except Exception as e:
            return False, {"error": f"Token verification failed: {str(e)}"}

        def refresh_token(
            self,
                refresh_token: str
        ) -> Tuple[Optional[str], Optional[str]]:
        Generate new access token from refresh token
    Args:
            refresh_token: Valid refresh token
    Returns:
                        Tuple of (
                new_access_token,
                new_refresh_token) or (None,
                None
            ) if invalid
        is_valid, claims = self.verify_token(
            refresh_token,
            token_type="refresh"
        )

        if not is_valid:
            return None, None

        # Create new tokens
        new_access = self.create_token(
            user_id=claims["sub"],
            username=claims["username"],
            roles=claims.get("roles", []),
            permissions=claims.get("permissions", []),
            token_type="access",
        )

        new_refresh = self.create_token(
            user_id=claims["sub"],
            username=claims["username"],
            roles=claims.get("roles", []),
            permissions=claims.get("permissions", []),
            token_type="refresh",
        )

        # Revoke old refresh token
        self.revoke_token(refresh_token)

        return new_access, new_refresh

    def revoke_token(self, token: str) -> bool:
        Revoke a token by adding its JTI to revocation list
    Args:
            token: Token to revoke
    Returns:
            Success status
            try:
            jti = self._extract_jti(token)
            if jti:
                self.revoked_tokens.add(jti)
                # In production, store in Redis with expiration
                return True
            return False
        except Exception:
            return False

    def _generate_jti(self, user_id: str, timestamp: datetime.datetime) -> str:
        Generate unique JWT ID
    Args:
            user_id: User identifier
                timestamp: Token creation timestamp
    Returns:
            Unique JTI string
        data = f"{user_id}:{timestamp.isoformat()}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def _extract_jti(self, token: str) -> Optional[str]:
        Extract JTI from token without full verification
    Args:
            token: JWT token
    Returns:
            JTI string or None
        try:
            # Decode without verification to get JTI
            claims = jwt.decode(
                token, options={"verify_signature": False, "verify_exp": False}
            )
            return claims.get("jti")
        except Exception:
            return None

    def get_public_key(self) -> str:
        Get public key in PEM format for sharing
    Returns:
            PEM formatted public key
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")


# Convenience functions
_default_handler = None


def get_jwt_handler() -> JWTHandler:
    """Get default JWT handler instance"""
    """
    global _default_handler
    if _default_handler is None:
        _default_handler = JWTHandler()
    return _default_handler


def create_access_token(
        user_id: str, username: str, roles: list = None, **kwargs
) -> str:
    Create an access token
    Args:
        user_id: User identifier
            username: Username
            roles: User roles
        **kwargs: Additional claims
    Returns:
        JWT access token
    handler = get_jwt_handler()
    return handler.create_token(
        user_id=user_id,
        username=username,
        roles=roles,
        extra_claims=kwargs,
        token_type="access",
    )


def verify_token(
        token: str,
        token_type: str = "access"
) -> Tuple[bool, Optional[dict]]:
    Verify a token
    Args:
        token: JWT token
            token_type: Expected token type
    Returns:
        Tuple of (is_valid, claims)
    handler = get_jwt_handler()
    return handler.verify_token(token, token_type=token_type)
