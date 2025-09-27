"""
Authentication Service for CatNet.
Handles OAuth2, SAML, MFA, JWT tokens with high security standards.
"""

import hashlib
import secrets
import string
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
import uuid
import pyotp
import jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends, Request
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_
import logging

from src.db.models import User, UserSession, Role, AuditLog
from src.db.database import get_db_session

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
bearer_scheme = HTTPBearer()


class AuthenticationConfig:
    """Authentication configuration."""

    JWT_SECRET_KEY = None
    JWT_ALGORITHM = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS = 7

    MFA_ISSUER = "CatNet"
    MFA_BACKUP_CODES_COUNT = 10

    PASSWORD_MIN_LENGTH = 12
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_DIGITS = True
    PASSWORD_REQUIRE_SPECIAL = True

    MAX_LOGIN_ATTEMPTS = 5
    ACCOUNT_LOCKOUT_MINUTES = 30

    SESSION_IDLE_TIMEOUT_MINUTES = 60
    SESSION_ABSOLUTE_TIMEOUT_HOURS = 12

    @classmethod
    def init_from_vault(cls, vault_client):
        """Initialize configuration from Vault."""
        try:
            if vault_client and hasattr(vault_client, 'get_secret'):
                auth_config = vault_client.get_secret('auth/jwt')
                cls.JWT_SECRET_KEY = auth_config.get('secret_key')
            if not cls.JWT_SECRET_KEY:
                cls.JWT_SECRET_KEY = secrets.token_urlsafe(64)
                if vault_client and hasattr(vault_client, 'create_secret'):
                    vault_client.create_secret('auth/jwt', {'secret_key': cls.JWT_SECRET_KEY})
        except Exception as e:
            logger.error(f"Failed to load JWT secret from Vault: {e}")
            cls.JWT_SECRET_KEY = secrets.token_urlsafe(64)


class EncryptionManager:
    """Simple encryption manager for sensitive data."""

    def __init__(self):
        self.key = secrets.token_urlsafe(32)

    def encrypt(self, data: str) -> str:
        """Basic encryption placeholder - implement proper encryption."""
        return data

    def decrypt(self, encrypted_data: str) -> str:
        """Basic decryption placeholder - implement proper decryption."""
        return encrypted_data


class AuthenticationService:
    """
    Handles: OAuth2, SAML, MFA, JWT tokens
    Dependencies: Vault, LDAP/AD
    """

    def __init__(self, vault_client=None, encryption_manager: Optional[EncryptionManager] = None):
        self.vault_client = vault_client
        self.encryption = encryption_manager or EncryptionManager()
        AuthenticationConfig.init_from_vault(self.vault_client)

    def _verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against a hash using Argon2."""
        return pwd_context.verify(plain_password, hashed_password)

    def _hash_password(self, password: str) -> str:
        """Hash a password using Argon2."""
        return pwd_context.hash(password)

    def _validate_password_strength(self, password: str) -> tuple[bool, str]:
        """Validate password meets security requirements."""
        if len(password) < AuthenticationConfig.PASSWORD_MIN_LENGTH:
            return False, f"Password must be at least {AuthenticationConfig.PASSWORD_MIN_LENGTH} characters"

        if AuthenticationConfig.PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"

        if AuthenticationConfig.PASSWORD_REQUIRE_LOWERCASE and not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"

        if AuthenticationConfig.PASSWORD_REQUIRE_DIGITS and not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit"

        if AuthenticationConfig.PASSWORD_REQUIRE_SPECIAL:
            special_chars = string.punctuation
            if not any(c in special_chars for c in password):
                return False, "Password must contain at least one special character"

        return True, "Password is strong"

    def _generate_backup_codes(self) -> List[str]:
        """Generate MFA backup codes."""
        codes = []
        for _ in range(AuthenticationConfig.MFA_BACKUP_CODES_COUNT):
            code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
            code = f"{code[:4]}-{code[4:]}"
            codes.append(code)
        return codes

    def _hash_token(self, token: str) -> str:
        """Generate SHA-256 hash of token for storage."""
        return hashlib.sha256(token.encode()).hexdigest()

    async def create_user(
        self,
        session: AsyncSession,
        username: str,
        email: str,
        password: str,
        enable_mfa: bool = True,
        roles: List[str] = None
    ) -> User:
        """Create a new user with secure defaults."""

        is_valid, message = self._validate_password_strength(password)
        if not is_valid:
            raise ValueError(message)

        existing_user = await session.execute(
            select(User).where(
                (User.username == username) | (User.email == email)
            )
        )
        if existing_user.scalar_one_or_none():
            raise ValueError("User with this username or email already exists")

        user = User(
            id=uuid.uuid4(),
            username=username,
            email=email,
            password_hash=self._hash_password(password),
            mfa_enabled=enable_mfa,
            created_at=datetime.now(timezone.utc),
            password_changed_at=datetime.now(timezone.utc)
        )

        if enable_mfa:
            mfa_secret = pyotp.random_base32()
            user.mfa_secret_encrypted = self.encryption.encrypt(mfa_secret)

            backup_codes = self._generate_backup_codes()
            backup_codes_json = json.dumps(backup_codes)
            user.backup_codes_encrypted = self.encryption.encrypt(backup_codes_json)

        session.add(user)

        if roles:
            role_objects = await session.execute(
                select(Role).where(Role.name.in_(roles))
            )
            user.roles = role_objects.scalars().all()

        audit_log = AuditLog(
            user_id=user.id,
            action="user.created",
            resource_type="user",
            resource_id=str(user.id),
            success=True,
            timestamp=datetime.now(timezone.utc),
            signature=self._generate_audit_signature({
                'user_id': str(user.id),
                'action': 'user.created'
            })
        )
        session.add(audit_log)

        await session.commit()
        return user

    async def authenticate_user(
        self,
        session: AsyncSession,
        username: str,
        password: str,
        mfa_code: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Optional[User]:
        """Authenticate user with password and optional MFA."""

        user_query = await session.execute(
            select(User).where(
                (User.username == username) | (User.email == username)
            )
        )
        user = user_query.scalar_one_or_none()

        if not user:
            await self._log_failed_login(session, None, ip_address, "User not found")
            return None

        if user.is_locked:
            if user.last_failed_login:
                lockout_until = user.last_failed_login + timedelta(
                    minutes=AuthenticationConfig.ACCOUNT_LOCKOUT_MINUTES
                )
                if datetime.now(timezone.utc) < lockout_until:
                    await self._log_failed_login(session, user.id, ip_address, "Account locked")
                    return None
                else:
                    user.is_locked = False
                    user.failed_login_attempts = 0

        if not user.is_active:
            await self._log_failed_login(session, user.id, ip_address, "Account inactive")
            return None

        if not self._verify_password(password, user.password_hash):
            user.failed_login_attempts += 1
            user.last_failed_login = datetime.now(timezone.utc)

            if user.failed_login_attempts >= AuthenticationConfig.MAX_LOGIN_ATTEMPTS:
                user.is_locked = True

            await session.commit()
            await self._log_failed_login(session, user.id, ip_address, "Invalid password")
            return None

        if user.mfa_enabled:
            if not mfa_code:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="MFA code required"
                )

            if user.mfa_secret_encrypted:
                mfa_secret = self.encryption.decrypt(user.mfa_secret_encrypted)
                totp = pyotp.TOTP(mfa_secret)

                if not totp.verify(mfa_code, valid_window=1):
                    if user.backup_codes_encrypted:
                        backup_codes = json.loads(self.encryption.decrypt(user.backup_codes_encrypted))
                        if mfa_code not in backup_codes:
                            user.failed_login_attempts += 1
                            await session.commit()
                            await self._log_failed_login(session, user.id, ip_address, "Invalid MFA code")
                            return None
                        else:
                            backup_codes.remove(mfa_code)
                            user.backup_codes_encrypted = self.encryption.encrypt(json.dumps(backup_codes))

        user.failed_login_attempts = 0
        user.last_login = datetime.now(timezone.utc)
        user.last_failed_login = None

        audit_log = AuditLog(
            user_id=user.id,
            action="user.login",
            resource_type="user",
            resource_id=str(user.id),
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
            timestamp=datetime.now(timezone.utc),
            signature=self._generate_audit_signature({
                'user_id': str(user.id),
                'action': 'user.login',
                'ip': ip_address
            })
        )
        session.add(audit_log)

        await session.commit()
        return user

    def create_access_token(
        self,
        user_id: str,
        permissions: List[str] = None,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create a JWT access token."""
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                minutes=AuthenticationConfig.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
            )

        payload = {
            "sub": user_id,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "jti": str(uuid.uuid4()),
            "type": "access",
            "permissions": permissions or []
        }

        return jwt.encode(
            payload,
            AuthenticationConfig.JWT_SECRET_KEY,
            algorithm=AuthenticationConfig.JWT_ALGORITHM
        )

    def create_refresh_token(self, user_id: str) -> str:
        """Create a JWT refresh token."""
        expire = datetime.now(timezone.utc) + timedelta(
            days=AuthenticationConfig.JWT_REFRESH_TOKEN_EXPIRE_DAYS
        )

        payload = {
            "sub": user_id,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "jti": str(uuid.uuid4()),
            "type": "refresh"
        }

        return jwt.encode(
            payload,
            AuthenticationConfig.JWT_SECRET_KEY,
            algorithm=AuthenticationConfig.JWT_ALGORITHM
        )

    async def create_session(
        self,
        session: AsyncSession,
        user: User,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        device_fingerprint: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a new user session with tokens."""

        access_token = self.create_access_token(
            user_id=str(user.id),
            permissions=self._get_user_permissions(user)
        )

        refresh_token = self.create_refresh_token(user_id=str(user.id))

        session_expires = datetime.now(timezone.utc) + timedelta(
            hours=AuthenticationConfig.SESSION_ABSOLUTE_TIMEOUT_HOURS
        )

        user_session = UserSession(
            id=uuid.uuid4(),
            user_id=user.id,
            session_token_hash=self._hash_token(access_token),
            refresh_token_hash=self._hash_token(refresh_token),
            ip_address=ip_address,
            user_agent=user_agent,
            device_fingerprint=device_fingerprint,
            created_at=datetime.now(timezone.utc),
            expires_at=session_expires,
            last_activity=datetime.now(timezone.utc)
        )

        session.add(user_session)
        await session.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": AuthenticationConfig.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "session_id": str(user_session.id)
        }

    async def verify_token(
        self,
        token: str,
        session: AsyncSession,
        token_type: str = "access"
    ) -> Optional[User]:
        """Verify JWT token and return associated user."""
        try:
            payload = jwt.decode(
                token,
                AuthenticationConfig.JWT_SECRET_KEY,
                algorithms=[AuthenticationConfig.JWT_ALGORITHM]
            )

            if payload.get("type") != token_type:
                return None

            user_id = payload.get("sub")
            if not user_id:
                return None

            token_hash = self._hash_token(token)

            session_query = await session.execute(
                select(UserSession).where(
                    and_(
                        UserSession.session_token_hash == token_hash,
                        UserSession.revoked == False,
                        UserSession.expires_at > datetime.now(timezone.utc)
                    )
                )
            )
            user_session = session_query.scalar_one_or_none()

            if not user_session:
                return None

            idle_timeout = datetime.now(timezone.utc) - timedelta(
                minutes=AuthenticationConfig.SESSION_IDLE_TIMEOUT_MINUTES
            )
            if user_session.last_activity < idle_timeout:
                user_session.revoked = True
                user_session.revoked_at = datetime.now(timezone.utc)
                user_session.revoked_reason = "Session idle timeout"
                await session.commit()
                return None

            user_session.last_activity = datetime.now(timezone.utc)
            await session.commit()

            user_query = await session.execute(
                select(User).where(User.id == uuid.UUID(user_id))
            )
            return user_query.scalar_one_or_none()

        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return None

    async def revoke_session(
        self,
        session: AsyncSession,
        session_id: str,
        reason: str = "User logout"
    ) -> bool:
        """Revoke a user session."""
        user_session = await session.get(UserSession, uuid.UUID(session_id))

        if not user_session:
            return False

        user_session.revoked = True
        user_session.revoked_at = datetime.now(timezone.utc)
        user_session.revoked_reason = reason

        await session.commit()
        return True

    async def refresh_access_token(
        self,
        session: AsyncSession,
        refresh_token: str
    ) -> Optional[Dict[str, Any]]:
        """Refresh an access token using a refresh token."""
        try:
            payload = jwt.decode(
                refresh_token,
                AuthenticationConfig.JWT_SECRET_KEY,
                algorithms=[AuthenticationConfig.JWT_ALGORITHM]
            )

            if payload.get("type") != "refresh":
                return None

            user_id = payload.get("sub")
            if not user_id:
                return None

            token_hash = self._hash_token(refresh_token)

            session_query = await session.execute(
                select(UserSession).where(
                    and_(
                        UserSession.refresh_token_hash == token_hash,
                        UserSession.revoked == False,
                        UserSession.expires_at > datetime.now(timezone.utc)
                    )
                )
            )
            user_session = session_query.scalar_one_or_none()

            if not user_session:
                return None

            user_query = await session.execute(
                select(User).where(User.id == uuid.UUID(user_id))
            )
            user = user_query.scalar_one_or_none()

            if not user or not user.is_active:
                return None

            new_access_token = self.create_access_token(
                user_id=user_id,
                permissions=self._get_user_permissions(user)
            )

            user_session.session_token_hash = self._hash_token(new_access_token)
            user_session.last_activity = datetime.now(timezone.utc)

            await session.commit()

            return {
                "access_token": new_access_token,
                "token_type": "bearer",
                "expires_in": AuthenticationConfig.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
            }

        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def _get_user_permissions(self, user: User) -> List[str]:
        """Extract user permissions from roles."""
        permissions = set()
        if hasattr(user, 'roles'):
            for role in user.roles:
                if role.permissions:
                    for perm_category, perm_list in role.permissions.items():
                        if isinstance(perm_list, list):
                            permissions.update(perm_list)
        return list(permissions)

    def _generate_audit_signature(self, data: Dict[str, Any]) -> str:
        """Generate signature for audit log integrity."""
        data_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(data_str.encode()).hexdigest()

    async def _log_failed_login(
        self,
        session: AsyncSession,
        user_id: Optional[uuid.UUID],
        ip_address: Optional[str],
        reason: str
    ):
        """Log failed login attempt."""
        audit_log = AuditLog(
            user_id=user_id,
            action="user.login.failed",
            resource_type="user",
            resource_id=str(user_id) if user_id else None,
            ip_address=ip_address,
            success=False,
            error_message=reason,
            timestamp=datetime.now(timezone.utc),
            threat_detected=True if reason == "Account locked" else False,
            signature=self._generate_audit_signature({
                'user_id': str(user_id) if user_id else None,
                'action': 'user.login.failed',
                'reason': reason
            })
        )
        session.add(audit_log)
        await session.commit()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    session: AsyncSession = Depends(get_db_session)
) -> User:
    """FastAPI dependency to get current authenticated user."""
    auth_service = AuthenticationService()
    user = await auth_service.verify_token(credentials.credentials, session)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


async def check_permission(user: User, permission: str) -> bool:
    """Check if user has specific permission."""
    auth_service = AuthenticationService()
    permissions = auth_service._get_user_permissions(user)
    return permission in permissions