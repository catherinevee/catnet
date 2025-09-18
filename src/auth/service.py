from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional, List
import os

import ssl
from datetime import datetime, timedelta
import uvicorn
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from ..security.auth import AuthManager
from ..security.audit import AuditLogger
from ..db.database import get_db
from ..db.models import User

from ..core.mtls import MTLSManager, MTLSMiddleware, MTLSServer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..core.logging import get_logger

logger = get_logger(__name__)


# Pydantic models
class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_token: Optional[str] = None


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class MFASetupResponse(BaseModel):
    secret: str
    qr_code_uri: str


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    roles: List[str] = []


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    roles: List[str]
    is_active: bool
    mfa_enabled: bool


class AuthenticationService:
    def __init__(self, port: int = 8081):
        self.app = FastAPI(
            title="CatNet Authentication Service",
            version="1.0.0",
            docs_url="/api/docs",
            redoc_url="/api/redoc",
        )
        self.port = port
        self.secret_key = os.getenv(
            "JWT_SECRET_KEY", "your-secret-key-change-in-production"
        )
        self.auth_manager = AuthManager(secret_key=self.secret_key)
        self.audit_logger = AuditLogger(log_file="logs/auth_audit.jsonl")

        # Rate limiter
        self.limiter = Limiter(key_func=get_remote_address)
        self.app.state.limiter = self.limiter
        self.app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

        self._setup_middleware()
        self._setup_routes()

    def _setup_middleware(self):
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # Configure based on environment
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    def _setup_routes(self):
        @self.app.post("/auth/login", response_model=LoginResponse)
        @self.limiter.limit("5/minute")
        async def login(
            request: Request,
            login_data: LoginRequest,
            db: AsyncSession = Depends(get_db),
        ):
            # Get user from database
            result = await db.execute(
                select(User).where(User.username == login_data.username)
            )
            user = result.scalar_one_or_none()

            if not user:
                await self.audit_logger.log_authentication(
                    user_id=login_data.username,
                    success=False,
                    method="password",
                    ip_address=request.client.host,
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials",
                )

            # Check if account is locked
            if user.locked_until and user.locked_until > datetime.utcnow():
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED, detail="Account is locked"
                )

            # Verify password
            if not self.auth_manager.verify_password(
                login_data.password, user.password_hash
            ):
                user.failed_login_attempts += 1

                # Lock account after 5 failed attempts
                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=30)

                await db.commit()

                await self.audit_logger.log_authentication(
                    user_id=login_data.username,
                    success=False,
                    method="password",
                    ip_address=request.client.host,
                )

                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials",
                )

            # Verify MFA if enabled
            if user.mfa_secret and login_data.mfa_token:
                if not self.auth_manager.verify_mfa_token(
                    user.username, login_data.mfa_token, user.mfa_secret
                ):
                    await self.audit_logger.log_authentication(
                        user_id=user.username,
                        success=False,
                        method="mfa",
                        ip_address=request.client.host,
                    )
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid MFA token",
                    )

            # Reset failed login attempts
            user.failed_login_attempts = 0
            user.last_login = datetime.utcnow()
            await db.commit()

            # Generate tokens
            user_data = {
                "sub": str(user.id),
                "username": user.username,
                "roles": user.roles,
            }

            access_token = await self.auth_manager.create_access_token(data=user_data)
            refresh_token = await self.auth_manager.create_refresh_token(data=user_data)

            await self.audit_logger.log_authentication(
                user_id=user.username,
                success=True,
                method="password+mfa" if user.mfa_secret else "password",
                ip_address=request.client.host,
            )

            return LoginResponse(access_token=access_token, refresh_token=refresh_token)

        @self.app.post("/auth/mfa/verify")
        async def verify_mfa(
            token: str, user_id: str, db: AsyncSession = Depends(get_db)
        ):
            result = await db.execute(select(User).where(User.id == user_id))
            user = result.scalar_one_or_none()

            if not user or not user.mfa_secret:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="MFA not configured for user",
                )

            is_valid = self.auth_manager.verify_mfa_token(
                user.username, token, user.mfa_secret
            )

            if not is_valid:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA token"
                )

            return {"verified": True}

        @self.app.post("/auth/mfa/setup", response_model=MFASetupResponse)
        async def setup_mfa(user_id: str, db: AsyncSession = Depends(get_db)):
            result = await db.execute(select(User).where(User.id == user_id))
            user = result.scalar_one_or_none()

            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
                )

            # Generate MFA secret
            secret = self.auth_manager.generate_mfa_secret(user.username)
            qr_code_uri = self.auth_manager.generate_mfa_qr_code(user.username, secret)

            # Save secret to user (would typically be encrypted)
            user.mfa_secret = secret
            await db.commit()

            return MFASetupResponse(secret=secret, qr_code_uri=qr_code_uri)

        @self.app.post("/auth/refresh", response_model=LoginResponse)
        async def refresh_token(refresh_data: RefreshRequest):
            try:
                tokens = await self.auth_manager.refresh_access_token(
                    refresh_data.refresh_token
                )

                return LoginResponse(
                    access_token=tokens["access_token"],
                    # Return same refresh token
                    refresh_token=refresh_data.refresh_token,
                )
            except Exception:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid refresh token",
                )

        @self.app.delete("/auth/logout")
        async def logout(request: Request, token: str):
            await self.auth_manager.revoke_token(token)

            await self.audit_logger.log_event(
                event_type="logout",
                user_id=None,  # Extract from token if needed
                details={"ip_address": request.client.host},
            )

            return {"message": "Logged out successfully"}

        @self.app.post("/auth/users", response_model=UserResponse)
        @self.limiter.limit("10/hour")
        async def create_user(
            request: Request, user_data: UserCreate, db: AsyncSession = Depends(get_db)
        ):
            # Check if user exists
            result = await db.execute(
                select(User).where(
                    (User.username == user_data.username)
                    | (User.email == user_data.email)
                )
            )
            existing_user = result.scalar_one_or_none()

            if existing_user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User already exists",
                )

            # Create new user
            password_hash = self.auth_manager.get_password_hash(user_data.password)

            new_user = User(
                username=user_data.username,
                email=user_data.email,
                password_hash=password_hash,
                roles=user_data.roles,
            )

            db.add(new_user)
            await db.commit()
            await db.refresh(new_user)

            await self.audit_logger.log_event(
                event_type="user_created",
                user_id=str(new_user.id),
                details={
                    "username": new_user.username,
                    "email": new_user.email,
                    "roles": new_user.roles,
                },
            )

            return UserResponse(
                id=str(new_user.id),
                username=new_user.username,
                email=new_user.email,
                roles=new_user.roles,
                is_active=new_user.is_active,
                mfa_enabled=bool(new_user.mfa_secret),
            )

        @self.app.get("/health")
        async def health_check():
            return {"status": "healthy", "service": "authentication"}

    def run(self):
        # Configure SSL context for production
        ssl_context = None
        if os.getenv("ENABLE_SSL", "false").lower() == "true":
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(
                certfile=os.getenv("SSL_CERT_FILE", "cert.pem"),
                keyfile=os.getenv("SSL_KEY_FILE", "key.pem"),
            )

        # Initialize mTLS if configured
        if os.getenv("ENABLE_MTLS", "false").lower() == "true":
            mtls_manager = MTLSManager()
            self.app.add_middleware(MTLSMiddleware, manager=mtls_manager)
            logger.info("mTLS enabled for authentication service")

            # Create mTLS server for inter-service communication
            mtls_server = MTLSServer(
                app=self.app,
                host="0.0.0.0",
                port=self.port + 1000,  # mTLS port
                mtls_manager=mtls_manager,
            )
            logger.info(f"mTLS server configured on port {self.port + 1000}")
            # Store mTLS server for potential future use
            self.mtls_server = mtls_server

        uvicorn.run(
            self.app, host="0.0.0.0", port=self.port, log_level="info", ssl=ssl_context
        )


if __name__ == "__main__":
    service = AuthenticationService()
    service.run()
