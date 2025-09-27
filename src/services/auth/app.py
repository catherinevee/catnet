"""
Authentication microservice application.

Provides centralized authentication and authorization for CatNet.
"""

import os
from typing import Dict, Any, Optional
from contextlib import asynccontextmanager
import asyncio
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, Depends, Security, status
from fastapi.security import OAuth2PasswordBearer, HTTPBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
import uvicorn
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
import jwt
from passlib.context import CryptContext
import redis.asyncio as redis
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import pyotp
import ldap3
import saml2
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

from src.core.config import get_settings
from src.core.logging import get_logger
from src.security.vault import VaultClient
from src.security.mtls import MTLSMiddleware
from src.db.models import Base, User, Session, MFAToken, AuditLog
from .models import LoginRequest, LoginResponse, MFARequest, MFAResponse, TokenRefreshRequest
from .handlers import LoginHandler, MFAHandler, TokenHandler, LogoutHandler, UserManagementHandler
from .validators import LoginValidator, MFAValidator, TokenValidator
from .middleware import AuthenticationMiddleware, RateLimitMiddleware, SecurityHeadersMiddleware

logger = get_logger(__name__)
settings = get_settings()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
http_bearer = HTTPBearer()
pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")


class AuthenticationService:
    """
    Main authentication service implementation.

    Handles:
    - User authentication (username/password, LDAP, SAML)
    - Multi-factor authentication (TOTP, SMS, Email)
    - JWT token management
    - Session management
    - User authorization
    - Audit logging
    """

    def __init__(self):
        self.vault = VaultClient()
        self.redis = None
        self.db_session = None
        self.login_handler = LoginHandler()
        self.mfa_handler = MFAHandler()
        self.token_handler = TokenHandler()
        self.logout_handler = LogoutHandler()
        self.user_handler = UserManagementHandler()
        self.login_validator = LoginValidator()
        self.mfa_validator = MFAValidator()
        self.token_validator = TokenValidator()
        self.ldap_conn = None
        self.saml_client = None

    async def initialize(self):
        """Initialize service connections."""
        # Initialize Redis
        self.redis = await redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            ssl_cert_reqs="required" if settings.REDIS_SSL else None,
            ssl_keyfile=settings.REDIS_SSL_KEY if settings.REDIS_SSL else None,
            ssl_certfile=settings.REDIS_SSL_CERT if settings.REDIS_SSL else None,
            ssl_ca_certs=settings.REDIS_SSL_CA if settings.REDIS_SSL else None,
        )

        # Initialize database
        engine = create_async_engine(
            settings.DATABASE_URL,
            pool_size=20,
            max_overflow=0,
            pool_pre_ping=True,
            echo=False,
        )
        async_session = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        self.db_session = async_session

        # Initialize LDAP if configured
        if settings.LDAP_ENABLED:
            self.ldap_conn = await self._init_ldap()

        # Initialize SAML if configured
        if settings.SAML_ENABLED:
            self.saml_client = await self._init_saml()

        logger.info("Authentication service initialized successfully")

    async def _init_ldap(self) -> Optional[ldap3.Connection]:
        """Initialize LDAP connection."""
        try:
            server = ldap3.Server(
                settings.LDAP_SERVER,
                port=settings.LDAP_PORT,
                use_ssl=settings.LDAP_USE_SSL,
                get_info=ldap3.ALL
            )

            # Get LDAP credentials from Vault
            ldap_creds = await self.vault.get_secret("ldap/service-account")

            conn = ldap3.Connection(
                server,
                user=ldap_creds['username'],
                password=ldap_creds['password'],
                auto_bind=True,
                authentication=ldap3.NTLM if settings.LDAP_USE_NTLM else ldap3.SIMPLE
            )

            logger.info("LDAP connection established")
            return conn

        except Exception as e:
            logger.error(f"Failed to initialize LDAP: {e}")
            return None

    async def _init_saml(self) -> Optional[Saml2Client]:
        """Initialize SAML client."""
        try:
            saml_settings = {
                'metadata': {
                    'local': [settings.SAML_METADATA_URL]
                },
                'service': {
                    'sp': {
                        'name': 'CatNet Authentication Service',
                        'endpoints': {
                            'assertion_consumer_service': [
                                (f"{settings.BASE_URL}/auth/saml/acs", saml2.BINDING_HTTP_POST),
                            ],
                            'single_logout_service': [
                                (f"{settings.BASE_URL}/auth/saml/sls", saml2.BINDING_HTTP_REDIRECT),
                            ],
                        },
                        'allow_unsolicited': False,
                        'authn_requests_signed': True,
                        'logout_requests_signed': True,
                        'want_assertions_signed': True,
                        'want_response_signed': True,
                    },
                },
            }

            saml_config = Saml2Config()
            saml_config.load(saml_settings)
            client = Saml2Client(config=saml_config)

            logger.info("SAML client initialized")
            return client

        except Exception as e:
            logger.error(f"Failed to initialize SAML: {e}")
            return None

    async def authenticate_user(
        self,
        username: str,
        password: str,
        auth_type: str = "local"
    ) -> Optional[User]:
        """
        Authenticate user with various methods.

        Args:
            username: Username or email
            password: User password
            auth_type: Authentication type (local, ldap, saml)

        Returns:
            User object if authenticated, None otherwise
        """
        # Validate input
        if not await self.login_validator.validate(username, password):
            return None

        # Check rate limiting
        if await self._is_rate_limited(username):
            logger.warning(f"Rate limit exceeded for user: {username}")
            return None

        user = None

        if auth_type == "ldap" and self.ldap_conn:
            user = await self._authenticate_ldap(username, password)
        elif auth_type == "saml" and self.saml_client:
            user = await self._authenticate_saml(username, password)
        else:
            user = await self._authenticate_local(username, password)

        if user:
            # Log successful authentication
            await self._log_auth_event(user.id, "login_success", auth_type)
            # Reset rate limit
            await self._reset_rate_limit(username)
        else:
            # Log failed authentication
            await self._log_auth_event(None, "login_failed", auth_type, username=username)
            # Increment rate limit
            await self._increment_rate_limit(username)

        return user

    async def _authenticate_local(self, username: str, password: str) -> Optional[User]:
        """Authenticate against local database."""
        async with self.db_session() as session:
            # Find user
            result = await session.execute(
                "SELECT * FROM users WHERE username = :username OR email = :username",
                {"username": username}
            )
            user_data = result.fetchone()

            if not user_data:
                return None

            # Verify password
            if not pwd_context.verify(password, user_data.password_hash):
                return None

            # Check if user is active
            if not user_data.is_active:
                logger.warning(f"Inactive user attempted login: {username}")
                return None

            # Check if user is locked
            if user_data.locked_until and user_data.locked_until > datetime.utcnow():
                logger.warning(f"Locked user attempted login: {username}")
                return None

            # Create user object
            user = User(
                id=user_data.id,
                username=user_data.username,
                email=user_data.email,
                full_name=user_data.full_name,
                roles=user_data.roles,
                permissions=user_data.permissions,
                mfa_enabled=user_data.mfa_enabled,
                mfa_secret=user_data.mfa_secret
            )

            # Update last login
            await session.execute(
                "UPDATE users SET last_login = :now WHERE id = :id",
                {"now": datetime.utcnow(), "id": user.id}
            )
            await session.commit()

            return user

    async def _authenticate_ldap(self, username: str, password: str) -> Optional[User]:
        """Authenticate against LDAP server."""
        if not self.ldap_conn:
            return None

        try:
            # Search for user
            self.ldap_conn.search(
                settings.LDAP_BASE_DN,
                f"({settings.LDAP_USER_ATTR}={username})",
                attributes=['*']
            )

            if not self.ldap_conn.entries:
                return None

            user_dn = self.ldap_conn.entries[0].entry_dn

            # Bind with user credentials
            test_conn = ldap3.Connection(
                self.ldap_conn.server,
                user=user_dn,
                password=password,
                auto_bind=True
            )
            test_conn.unbind()

            # Get or create user in database
            ldap_user = self.ldap_conn.entries[0]
            user = await self._sync_ldap_user(ldap_user)

            return user

        except Exception as e:
            logger.error(f"LDAP authentication failed: {e}")
            return None

    async def _authenticate_saml(self, username: str, password: str) -> Optional[User]:
        """Authenticate via SAML (placeholder for SSO flow)."""
        # SAML authentication typically involves browser redirects
        # This is a simplified placeholder
        logger.info(f"SAML authentication requested for user: {username}")
        return None

    async def _sync_ldap_user(self, ldap_user) -> User:
        """Sync LDAP user to local database."""
        async with self.db_session() as session:
            # Check if user exists
            result = await session.execute(
                "SELECT * FROM users WHERE username = :username",
                {"username": ldap_user.sAMAccountName.value}
            )
            user_data = result.fetchone()

            if user_data:
                # Update existing user
                await session.execute(
                    """
                    UPDATE users
                    SET email = :email, full_name = :full_name, last_sync = :now
                    WHERE username = :username
                    """,
                    {
                        "email": ldap_user.mail.value,
                        "full_name": ldap_user.displayName.value,
                        "now": datetime.utcnow(),
                        "username": ldap_user.sAMAccountName.value
                    }
                )
            else:
                # Create new user
                await session.execute(
                    """
                    INSERT INTO users (username, email, full_name, auth_type, is_active)
                    VALUES (:username, :email, :full_name, 'ldap', true)
                    """,
                    {
                        "username": ldap_user.sAMAccountName.value,
                        "email": ldap_user.mail.value,
                        "full_name": ldap_user.displayName.value
                    }
                )

            await session.commit()

            # Get user data
            result = await session.execute(
                "SELECT * FROM users WHERE username = :username",
                {"username": ldap_user.sAMAccountName.value}
            )
            user_data = result.fetchone()

            return User(
                id=user_data.id,
                username=user_data.username,
                email=user_data.email,
                full_name=user_data.full_name,
                roles=user_data.roles,
                permissions=user_data.permissions
            )

    async def create_session(self, user: User) -> Session:
        """Create new user session."""
        session_id = jwt.encode(
            {
                "user_id": str(user.id),
                "username": user.username,
                "exp": datetime.utcnow() + timedelta(hours=settings.SESSION_TIMEOUT_HOURS),
                "iat": datetime.utcnow(),
                "session_id": os.urandom(32).hex()
            },
            settings.JWT_SECRET_KEY,
            algorithm="HS256"
        )

        # Store session in Redis
        await self.redis.setex(
            f"session:{session_id}",
            settings.SESSION_TIMEOUT_HOURS * 3600,
            {
                "user_id": str(user.id),
                "username": user.username,
                "roles": user.roles,
                "permissions": user.permissions,
                "created_at": datetime.utcnow().isoformat(),
                "last_activity": datetime.utcnow().isoformat()
            }
        )

        # Store in database
        async with self.db_session() as db:
            await db.execute(
                """
                INSERT INTO sessions (id, user_id, token, expires_at, created_at)
                VALUES (:id, :user_id, :token, :expires_at, :created_at)
                """,
                {
                    "id": session_id,
                    "user_id": user.id,
                    "token": session_id,
                    "expires_at": datetime.utcnow() + timedelta(hours=settings.SESSION_TIMEOUT_HOURS),
                    "created_at": datetime.utcnow()
                }
            )
            await db.commit()

        return Session(
            id=session_id,
            user_id=user.id,
            token=session_id,
            expires_at=datetime.utcnow() + timedelta(hours=settings.SESSION_TIMEOUT_HOURS)
        )

    async def validate_mfa(self, user_id: str, token: str, method: str = "totp") -> bool:
        """
        Validate MFA token.

        Args:
            user_id: User ID
            token: MFA token
            method: MFA method (totp, sms, email)

        Returns:
            True if valid, False otherwise
        """
        # Validate input
        if not await self.mfa_validator.validate(token):
            return False

        async with self.db_session() as session:
            # Get user
            result = await session.execute(
                "SELECT * FROM users WHERE id = :id",
                {"id": user_id}
            )
            user = result.fetchone()

            if not user or not user.mfa_enabled:
                return False

            if method == "totp":
                # Validate TOTP token
                totp = pyotp.TOTP(user.mfa_secret)
                if totp.verify(token, valid_window=1):
                    await self._log_auth_event(user_id, "mfa_success", method)
                    return True
            elif method == "sms":
                # Validate SMS token from cache
                cached_token = await self.redis.get(f"mfa:sms:{user_id}")
                if cached_token and cached_token == token:
                    await self.redis.delete(f"mfa:sms:{user_id}")
                    await self._log_auth_event(user_id, "mfa_success", method)
                    return True
            elif method == "email":
                # Validate email token from cache
                cached_token = await self.redis.get(f"mfa:email:{user_id}")
                if cached_token and cached_token == token:
                    await self.redis.delete(f"mfa:email:{user_id}")
                    await self._log_auth_event(user_id, "mfa_success", method)
                    return True

        await self._log_auth_event(user_id, "mfa_failed", method)
        return False

    async def refresh_token(self, token: str) -> Optional[str]:
        """
        Refresh JWT token.

        Args:
            token: Current JWT token

        Returns:
            New JWT token if valid, None otherwise
        """
        try:
            # Decode token
            payload = jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=["HS256"]
            )

            # Check if token is expired
            if payload['exp'] < datetime.utcnow().timestamp():
                return None

            # Check if session exists
            session_data = await self.redis.get(f"session:{token}")
            if not session_data:
                return None

            # Create new token
            new_token = jwt.encode(
                {
                    "user_id": payload['user_id'],
                    "username": payload['username'],
                    "exp": datetime.utcnow() + timedelta(hours=settings.SESSION_TIMEOUT_HOURS),
                    "iat": datetime.utcnow(),
                    "session_id": payload['session_id']
                },
                settings.JWT_SECRET_KEY,
                algorithm="HS256"
            )

            # Update session
            await self.redis.rename(f"session:{token}", f"session:{new_token}")
            await self.redis.expire(
                f"session:{new_token}",
                settings.SESSION_TIMEOUT_HOURS * 3600
            )

            # Update database
            async with self.db_session() as db:
                await db.execute(
                    """
                    UPDATE sessions
                    SET token = :new_token, expires_at = :expires_at
                    WHERE token = :old_token
                    """,
                    {
                        "new_token": new_token,
                        "expires_at": datetime.utcnow() + timedelta(hours=settings.SESSION_TIMEOUT_HOURS),
                        "old_token": token
                    }
                )
                await db.commit()

            await self._log_auth_event(payload['user_id'], "token_refresh", "jwt")
            return new_token

        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            return None

    async def logout(self, token: str) -> bool:
        """
        Logout user by invalidating session.

        Args:
            token: JWT token

        Returns:
            True if successful, False otherwise
        """
        try:
            # Decode token
            payload = jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=["HS256"]
            )

            # Delete session from Redis
            await self.redis.delete(f"session:{token}")

            # Delete from database
            async with self.db_session() as db:
                await db.execute(
                    "DELETE FROM sessions WHERE token = :token",
                    {"token": token}
                )
                await db.commit()

            # Add token to blacklist
            await self.redis.setex(
                f"blacklist:{token}",
                settings.SESSION_TIMEOUT_HOURS * 3600,
                "1"
            )

            await self._log_auth_event(payload['user_id'], "logout", "user")
            return True

        except Exception as e:
            logger.error(f"Logout failed: {e}")
            return False

    async def _is_rate_limited(self, username: str) -> bool:
        """Check if user is rate limited."""
        key = f"rate_limit:{username}"
        attempts = await self.redis.get(key)
        if attempts and int(attempts) >= settings.MAX_LOGIN_ATTEMPTS:
            return True
        return False

    async def _increment_rate_limit(self, username: str):
        """Increment rate limit counter."""
        key = f"rate_limit:{username}"
        await self.redis.incr(key)
        await self.redis.expire(key, settings.RATE_LIMIT_WINDOW_SECONDS)

    async def _reset_rate_limit(self, username: str):
        """Reset rate limit counter."""
        key = f"rate_limit:{username}"
        await self.redis.delete(key)

    async def _log_auth_event(
        self,
        user_id: Optional[str],
        event: str,
        method: str,
        username: Optional[str] = None
    ):
        """Log authentication event."""
        async with self.db_session() as session:
            await session.execute(
                """
                INSERT INTO audit_logs (user_id, username, event, method, timestamp, ip_address)
                VALUES (:user_id, :username, :event, :method, :timestamp, :ip_address)
                """,
                {
                    "user_id": user_id,
                    "username": username,
                    "event": event,
                    "method": method,
                    "timestamp": datetime.utcnow(),
                    "ip_address": "0.0.0.0"  # Should get from request context
                }
            )
            await session.commit()

    async def shutdown(self):
        """Shutdown service connections."""
        if self.redis:
            await self.redis.close()
        if self.ldap_conn:
            self.ldap_conn.unbind()
        logger.info("Authentication service shutdown complete")


auth_service = AuthenticationService()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    await auth_service.initialize()
    yield
    await auth_service.shutdown()


def create_app() -> FastAPI:
    """Create FastAPI application."""
    app = FastAPI(
        title="CatNet Authentication Service",
        description="Centralized authentication and authorization service",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/auth/docs",
        redoc_url="/auth/redoc",
        openapi_url="/auth/openapi.json",
    )

    # Add middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS.split(","),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.ALLOWED_HOSTS.split(",")
    )

    app.add_middleware(MTLSMiddleware)
    app.add_middleware(AuthenticationMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)

    # Add Prometheus metrics
    Instrumentator().instrument(app).expose(app, endpoint="/auth/metrics")

    # Add routes
    @app.post("/auth/login", response_model=LoginResponse)
    async def login(request: LoginRequest):
        """User login endpoint."""
        user = await auth_service.authenticate_user(
            request.username,
            request.password,
            request.auth_type
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )

        # Check if MFA is required
        if user.mfa_enabled:
            # Generate MFA challenge
            mfa_token = os.urandom(32).hex()
            await auth_service.redis.setex(
                f"mfa:pending:{mfa_token}",
                300,  # 5 minutes
                str(user.id)
            )

            return LoginResponse(
                success=False,
                mfa_required=True,
                mfa_token=mfa_token
            )

        # Create session
        session = await auth_service.create_session(user)

        return LoginResponse(
            success=True,
            token=session.token,
            expires_at=session.expires_at,
            user={
                "id": str(user.id),
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name,
                "roles": user.roles
            }
        )

    @app.post("/auth/mfa/verify", response_model=MFAResponse)
    async def verify_mfa(request: MFARequest):
        """Verify MFA token."""
        # Get pending MFA
        user_id = await auth_service.redis.get(f"mfa:pending:{request.mfa_token}")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired MFA token"
            )

        # Validate MFA
        valid = await auth_service.validate_mfa(
            user_id,
            request.code,
            request.method
        )

        if not valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA code"
            )

        # Get user
        async with auth_service.db_session() as session:
            result = await session.execute(
                "SELECT * FROM users WHERE id = :id",
                {"id": user_id}
            )
            user_data = result.fetchone()

            user = User(
                id=user_data.id,
                username=user_data.username,
                email=user_data.email,
                full_name=user_data.full_name,
                roles=user_data.roles,
                permissions=user_data.permissions
            )

        # Create session
        session = await auth_service.create_session(user)

        # Clean up pending MFA
        await auth_service.redis.delete(f"mfa:pending:{request.mfa_token}")

        return MFAResponse(
            success=True,
            token=session.token,
            expires_at=session.expires_at,
            user={
                "id": str(user.id),
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name,
                "roles": user.roles
            }
        )

    @app.post("/auth/refresh")
    async def refresh(request: TokenRefreshRequest):
        """Refresh JWT token."""
        new_token = await auth_service.refresh_token(request.token)

        if not new_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token"
            )

        return {
            "token": new_token,
            "expires_at": datetime.utcnow() + timedelta(hours=settings.SESSION_TIMEOUT_HOURS)
        }

    @app.delete("/auth/logout")
    async def logout(token: str = Depends(oauth2_scheme)):
        """Logout user."""
        success = await auth_service.logout(token)

        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Logout failed"
            )

        return {"message": "Logged out successfully"}

    @app.get("/auth/health")
    async def health():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "service": "authentication",
            "timestamp": datetime.utcnow().isoformat()
        }

    return app


if __name__ == "__main__":
    app = create_app()
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8081,
        ssl_keyfile=settings.SSL_KEY_PATH,
        ssl_certfile=settings.SSL_CERT_PATH,
        ssl_ca_certs=settings.SSL_CA_PATH,
        ssl_cert_reqs=2,  # CERT_REQUIRED
        log_config={
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {
                    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                },
            },
            "handlers": {
                "default": {
                    "formatter": "default",
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                },
            },
            "root": {
                "level": "INFO",
                "handlers": ["default"],
            },
        }
    )