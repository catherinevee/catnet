from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from passlib.context import CryptContext
from jose import JWTError, jwt
import structlog
import pyotp
import secrets
import uuid
from pydantic import BaseModel, EmailStr

from ..db.database import get_db
from ..db.models import User, Session as UserSession, AuditLog, SecurityEvent, UserRole
from ..security.vault import VaultClient
from .mfa import MFAHandler
from .jwt_handler import JWTHandler

logger = structlog.get_logger()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_token: Optional[str] = None

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    requires_mfa: bool = False
    mfa_qr_code: Optional[str] = None

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    full_name: str
    password: str
    role: UserRole = UserRole.VIEWER
    enable_mfa: bool = False

class AuthenticationService:
    def __init__(self):
        self.pwd_context = CryptContext(
            schemes=["argon2", "bcrypt"],
            deprecated="auto",
            argon2__rounds=4,
            argon2__memory_cost=65536,
            argon2__parallelism=2
        )
        self.jwt_handler = JWTHandler()
        self.mfa_handler = MFAHandler()
        self.vault_client = VaultClient()
        self.max_login_attempts = 5
        self.lockout_duration = timedelta(minutes=30)

    async def authenticate_user(
        self,
        db: AsyncSession,
        username: str,
        password: str,
        mfa_token: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Optional[User]:
        try:
            result = await db.execute(
                select(User).where(User.username == username)
            )
            user = result.scalar_one_or_none()

            if not user:
                await self._log_failed_login(db, None, username, ip_address, "User not found")
                return None

            if user.locked_until and user.locked_until > datetime.utcnow():
                await self._log_failed_login(db, user.id, username, ip_address, "Account locked")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Account locked until {user.locked_until.isoformat()}"
                )

            if not self.verify_password(password, user.hashed_password):
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= self.max_login_attempts:
                    user.locked_until = datetime.utcnow() + self.lockout_duration
                    await self._create_security_event(
                        db, "account_locked", user.id, ip_address,
                        f"Account locked after {self.max_login_attempts} failed attempts"
                    )
                await db.commit()
                await self._log_failed_login(db, user.id, username, ip_address, "Invalid password")
                return None

            if user.mfa_enabled:
                if not mfa_token:
                    return None
                if not self.mfa_handler.verify_token(user.mfa_secret, mfa_token):
                    await self._log_failed_login(db, user.id, username, ip_address, "Invalid MFA token")
                    return None

            user.failed_login_attempts = 0
            user.last_login = datetime.utcnow()
            await db.commit()

            await self._log_successful_login(db, user.id, ip_address)
            return user

        except Exception as e:
            await logger.aerror(f"Authentication error: {e}")
            raise

    async def create_user(
        self,
        db: AsyncSession,
        user_data: UserCreate,
        created_by: Optional[uuid.UUID] = None
    ) -> User:
        try:
            existing = await db.execute(
                select(User).where(
                    (User.username == user_data.username) |
                    (User.email == user_data.email)
                )
            )
            if existing.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Username or email already exists"
                )

            hashed_password = self.get_password_hash(user_data.password)

            user = User(
                username=user_data.username,
                email=user_data.email,
                full_name=user_data.full_name,
                hashed_password=hashed_password,
                role=user_data.role,
                mfa_enabled=user_data.enable_mfa
            )

            if user_data.enable_mfa:
                user.mfa_secret = self.mfa_handler.generate_secret()

            db.add(user)
            await db.commit()
            await db.refresh(user)

            await self._log_audit(
                db, created_by, "user.create",
                resource_type="user", resource_id=str(user.id),
                details={"username": user.username, "role": user.role.value}
            )

            return user

        except HTTPException:
            raise
        except Exception as e:
            await logger.aerror(f"User creation error: {e}")
            raise

    async def create_session(
        self,
        db: AsyncSession,
        user: User,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> LoginResponse:
        try:
            access_token_expires = timedelta(minutes=30)
            refresh_token_expires = timedelta(days=7)

            access_token = self.jwt_handler.create_token(
                data={"sub": str(user.id), "username": user.username, "role": user.role.value},
                expires_delta=access_token_expires
            )

            refresh_token = self.jwt_handler.create_token(
                data={"sub": str(user.id), "type": "refresh"},
                expires_delta=refresh_token_expires
            )

            session = UserSession(
                user_id=user.id,
                token=access_token,
                refresh_token=refresh_token,
                ip_address=ip_address,
                user_agent=user_agent,
                expires_at=datetime.utcnow() + access_token_expires
            )

            db.add(session)
            await db.commit()

            response = LoginResponse(
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in=int(access_token_expires.total_seconds())
            )

            if user.mfa_enabled and not user.mfa_secret:
                secret = self.mfa_handler.generate_secret()
                user.mfa_secret = secret
                await db.commit()
                response.requires_mfa = True
                response.mfa_qr_code = self.mfa_handler.get_qr_code(
                    secret, user.username, "CatNet"
                )

            return response

        except Exception as e:
            await logger.aerror(f"Session creation error: {e}")
            raise

    async def refresh_token(
        self,
        db: AsyncSession,
        refresh_token: str
    ) -> LoginResponse:
        try:
            payload = self.jwt_handler.decode_token(refresh_token)
            if payload.get("type") != "refresh":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid refresh token"
                )

            user_id = payload.get("sub")
            result = await db.execute(
                select(User).where(User.id == user_id)
            )
            user = result.scalar_one_or_none()

            if not user or not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found or inactive"
                )

            return await self.create_session(db, user)

        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )

    async def logout(
        self,
        db: AsyncSession,
        token: str
    ) -> bool:
        try:
            result = await db.execute(
                select(UserSession).where(UserSession.token == token)
            )
            session = result.scalar_one_or_none()

            if session:
                await db.delete(session)
                await db.commit()
                return True

            return False

        except Exception as e:
            await logger.aerror(f"Logout error: {e}")
            raise

    def get_password_hash(self, password: str) -> str:
        return self.pwd_context.hash(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        return self.pwd_context.verify(plain_password, hashed_password)

    async def _log_audit(
        self,
        db: AsyncSession,
        user_id: Optional[uuid.UUID],
        action: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
        ip_address: Optional[str] = None
    ):
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            success=success,
            ip_address=ip_address
        )
        db.add(audit_log)
        await db.commit()

    async def _log_failed_login(
        self,
        db: AsyncSession,
        user_id: Optional[uuid.UUID],
        username: str,
        ip_address: Optional[str],
        reason: str
    ):
        await self._log_audit(
            db, user_id, "auth.login",
            details={"username": username, "reason": reason},
            success=False,
            ip_address=ip_address
        )

    async def _log_successful_login(
        self,
        db: AsyncSession,
        user_id: uuid.UUID,
        ip_address: Optional[str]
    ):
        await self._log_audit(
            db, user_id, "auth.login",
            success=True,
            ip_address=ip_address
        )

    async def _create_security_event(
        self,
        db: AsyncSession,
        event_type: str,
        user_id: Optional[uuid.UUID],
        source_ip: Optional[str],
        description: str,
        severity: str = "high"
    ):
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            source_ip=source_ip,
            description=description
        )
        db.add(event)
        await db.commit()

auth_service = AuthenticationService()

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    try:
        payload = auth_service.jwt_handler.decode_token(token)
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        result = await db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()

        if user is None or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return user

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def require_role(allowed_roles: List[UserRole]):
    async def role_checker(user: User = Depends(get_current_user)):
        if user.role not in allowed_roles and not user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        return user
    return role_checker