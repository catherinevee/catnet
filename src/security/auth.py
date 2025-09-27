"""Authentication and authorization for CatNet"""

import jwt
import pyotp
import secrets
from typing import Optional, Dict, Any, List, Union
from datetime import datetime, timedelta
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
import logging

from src.core.config import settings
from src.db.models import User, Group, APIKey
from src.security import AuthenticationError, AuthorizationError
from src.security.vault import vault_client

logger = logging.getLogger(__name__)

# Password hashing context
pwd_context = CryptContext(
    schemes=["bcrypt", "argon2"],
    deprecated="auto",
    bcrypt__rounds=12,
    argon2__memory_cost=65536,
    argon2__time_cost=3,
    argon2__parallelism=4
)


class AuthenticationManager:
    """Manages user authentication"""

    def __init__(self):
        """Initialize authentication manager"""
        self.jwt_algorithm = settings.jwt_algorithm
        self.access_token_expire = timedelta(minutes=settings.jwt_access_token_expire_minutes)
        self.refresh_token_expire = timedelta(days=settings.jwt_refresh_token_expire_days)
        self._private_key: Optional[str] = None
        self._public_key: Optional[str] = None
        self._setup_keys()

    def _setup_keys(self) -> None:
        """Setup JWT signing keys"""
        if self.jwt_algorithm.startswith("RS"):
            # RSA keys for RS256, RS384, RS512
            try:
                # Try to get keys from Vault
                keys = vault_client.client.secrets.kv.v2.read_secret_version(
                    path="jwt/keys",
                    mount_point=settings.vault_mount_point
                )
                if keys:
                    self._private_key = keys['data']['data'].get('private_key')
                    self._public_key = keys['data']['data'].get('public_key')
            except Exception:
                # Generate new keys if not in Vault
                from cryptography.hazmat.primitives.asymmetric import rsa
                from cryptography.hazmat.primitives import serialization

                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )

                self._private_key = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')

                self._public_key = private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
        else:
            # Symmetric key for HS algorithms (not recommended for production)
            self._private_key = settings.secret_key.get_secret_value()
            self._public_key = self._private_key

    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt/argon2"""
        return pwd_context.hash(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return pwd_context.verify(plain_password, hashed_password)

    def create_access_token(self, user_id: str, additional_claims: Optional[dict] = None) -> str:
        """Create JWT access token"""
        now = datetime.utcnow()
        expire = now + self.access_token_expire

        payload = {
            "sub": user_id,
            "iat": now,
            "exp": expire,
            "type": "access",
            "jti": secrets.token_urlsafe(16)
        }

        if additional_claims:
            payload.update(additional_claims)

        return jwt.encode(payload, self._private_key, algorithm=self.jwt_algorithm)

    def create_refresh_token(self, user_id: str) -> str:
        """Create JWT refresh token"""
        now = datetime.utcnow()
        expire = now + self.refresh_token_expire

        payload = {
            "sub": user_id,
            "iat": now,
            "exp": expire,
            "type": "refresh",
            "jti": secrets.token_urlsafe(16)
        }

        return jwt.encode(payload, self._private_key, algorithm=self.jwt_algorithm)

    def verify_token(self, token: str, token_type: str = "access") -> Dict[str, Any]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(
                token,
                self._public_key,
                algorithms=[self.jwt_algorithm]
            )

            if payload.get("type") != token_type:
                raise AuthenticationError(f"Invalid token type: expected {token_type}")

            return payload

        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except jwt.JWTError as e:
            raise AuthenticationError(f"Invalid token: {e}")

    def generate_mfa_secret(self) -> str:
        """Generate TOTP MFA secret"""
        return pyotp.random_base32()

    def generate_mfa_uri(self, secret: str, username: str) -> str:
        """Generate MFA provisioning URI"""
        return pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name="CatNet"
        )

    def verify_mfa_code(self, secret: str, code: str) -> bool:
        """Verify TOTP MFA code"""
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)

    async def authenticate_user(
        self,
        db: AsyncSession,
        username: str,
        password: str,
        mfa_code: Optional[str] = None
    ) -> User:
        """
        Authenticate user with username, password, and optional MFA

        Args:
            db: Database session
            username: Username or email
            password: User password
            mfa_code: Optional MFA code

        Returns:
            Authenticated user object

        Raises:
            AuthenticationError: If authentication fails
        """
        # Get user from database
        stmt = select(User).where(
            and_(
                User.is_active == True,
                (User.username == username) | (User.email == username)
            )
        )
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
            # Don't reveal if user exists
            raise AuthenticationError("Invalid username or password")

        # Check if account is locked
        if user.locked_until and user.locked_until > datetime.utcnow():
            raise AuthenticationError("Account is locked due to too many failed attempts")

        # Verify password
        if not self.verify_password(password, user.hashed_password):
            # Increment failed attempts
            user.failed_login_attempts += 1

            # Lock account after 5 failed attempts
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                await db.commit()
                raise AuthenticationError("Account locked due to too many failed attempts")

            await db.commit()
            raise AuthenticationError("Invalid username or password")

        # Verify MFA if enabled
        if user.mfa_enabled:
            if not mfa_code:
                raise AuthenticationError("MFA code required")

            if not self.verify_mfa_code(user.mfa_secret, mfa_code):
                user.failed_login_attempts += 1
                await db.commit()
                raise AuthenticationError("Invalid MFA code")

        # Reset failed attempts on successful login
        user.failed_login_attempts = 0
        user.last_login_at = datetime.utcnow()
        await db.commit()

        return user

    async def authenticate_api_key(self, db: AsyncSession, api_key: str) -> User:
        """
        Authenticate using API key

        Args:
            db: Database session
            api_key: API key

        Returns:
            User associated with API key

        Raises:
            AuthenticationError: If authentication fails
        """
        # Hash the API key
        key_hash = pwd_context.hash(api_key)

        # Find API key in database
        stmt = select(APIKey).where(
            and_(
                APIKey.key_hash == key_hash,
                APIKey.is_active == True
            )
        )
        result = await db.execute(stmt)
        api_key_obj = result.scalar_one_or_none()

        if not api_key_obj:
            raise AuthenticationError("Invalid API key")

        # Check expiration
        if api_key_obj.expires_at and api_key_obj.expires_at < datetime.utcnow():
            api_key_obj.is_active = False
            await db.commit()
            raise AuthenticationError("API key has expired")

        # Update last used
        api_key_obj.last_used_at = datetime.utcnow()
        await db.commit()

        # Get associated user
        stmt = select(User).where(User.id == api_key_obj.user_id)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user or not user.is_active:
            raise AuthenticationError("User account is not active")

        return user


class AuthorizationManager:
    """Manages user authorization and permissions"""

    def __init__(self):
        """Initialize authorization manager"""
        self.permissions_cache: Dict[str, List[str]] = {}

    async def get_user_permissions(self, db: AsyncSession, user: User) -> List[str]:
        """
        Get all permissions for a user

        Args:
            db: Database session
            user: User object

        Returns:
            List of permission strings
        """
        # Check cache
        cache_key = str(user.id)
        if cache_key in self.permissions_cache:
            return self.permissions_cache[cache_key]

        permissions = set()

        # Add superuser permissions
        if user.is_superuser:
            permissions.add("*")  # All permissions
        else:
            # Get permissions from groups
            for group in user.groups:
                if group.is_active and group.permissions:
                    permissions.update(group.permissions)

        # Cache permissions for 5 minutes
        self.permissions_cache[cache_key] = list(permissions)

        return list(permissions)

    def check_permission(
        self,
        required_permission: str,
        user_permissions: List[str]
    ) -> bool:
        """
        Check if user has required permission

        Args:
            required_permission: Permission to check
            user_permissions: User's permissions

        Returns:
            True if user has permission
        """
        # Superuser has all permissions
        if "*" in user_permissions:
            return True

        # Check exact match
        if required_permission in user_permissions:
            return True

        # Check wildcard permissions (e.g., "deployment.*" matches "deployment.create")
        for perm in user_permissions:
            if perm.endswith("*"):
                prefix = perm[:-1]
                if required_permission.startswith(prefix):
                    return True

        return False

    async def authorize_action(
        self,
        db: AsyncSession,
        user: User,
        action: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None
    ) -> bool:
        """
        Authorize user action

        Args:
            db: Database session
            user: User object
            action: Action to perform
            resource_type: Optional resource type
            resource_id: Optional resource ID

        Returns:
            True if authorized

        Raises:
            AuthorizationError: If not authorized
        """
        # Build permission string
        if resource_type:
            permission = f"{resource_type}.{action}"
        else:
            permission = action

        # Get user permissions
        user_permissions = await self.get_user_permissions(db, user)

        # Check permission
        if not self.check_permission(permission, user_permissions):
            logger.warning(
                f"Authorization failed for user {user.username}: "
                f"required={permission}, has={user_permissions}"
            )
            raise AuthorizationError(f"Insufficient permissions for {permission}")

        return True

    def clear_cache(self, user_id: Optional[str] = None) -> None:
        """Clear permissions cache"""
        if user_id:
            self.permissions_cache.pop(str(user_id), None)
        else:
            self.permissions_cache.clear()


# Global instances
auth_manager = AuthenticationManager()
authz_manager = AuthorizationManager()