from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from jose import JWTError, jwt
from passlib.context import CryptContext
import pyotp
import secrets
import uuid
from .audit import AuditLogger, AuditLevel


class AuthManager:
    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        access_token_expire_minutes: int = 30,
        refresh_token_expire_days: int = 7,
        audit_logger: Optional[AuditLogger] = None,
    ):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days
        self.pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
        self.audit = audit_logger or AuditLogger()
        self.active_sessions = {}
        self.mfa_secrets = {}

    def verify_password(
        self, plain_password: str, hashed_password: str
    ) -> bool:
        return self.pwd_context.verify(plain_password, hashed_password)

    def get_password_hash(self, password: str) -> str:
        return self.pwd_context.hash(password)

    async def create_access_token(
        self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None
    ) -> str:
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                minutes=self.access_token_expire_minutes
            )

        to_encode.update(
            {
                "exp": expire,
                "iat": datetime.now(timezone.utc),
                "jti": str(uuid.uuid4()),  # JWT ID for tracking
                "type": "access",
            }
        )

        encoded_jwt = jwt.encode(
            to_encode, self.secret_key, algorithm=self.algorithm
        )

        # Log token creation
        await self.audit.log_event(
            event_type="token_created",
            user_id=data.get("sub"),
            details={
                "token_type": "access",
                "jti": to_encode["jti"],
                "expires_at": expire.isoformat(),
            },
            level=AuditLevel.INFO,
        )

        return encoded_jwt

    async def create_refresh_token(
        self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None
    ) -> str:
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                days=self.refresh_token_expire_days
            )

        to_encode.update(
            {
                "exp": expire,
                "iat": datetime.now(timezone.utc),
                "jti": str(uuid.uuid4()),
                "type": "refresh",
            }
        )

        encoded_jwt = jwt.encode(
            to_encode, self.secret_key, algorithm=self.algorithm
        )

        # Store refresh token in active sessions
        self.active_sessions[to_encode["jti"]] = {
            "user_id": data.get("sub"),
            "created_at": datetime.now(timezone.utc),
            "expires_at": expire,
        }

        await self.audit.log_event(
            event_type="token_created",
            user_id=data.get("sub"),
            details={
                "token_type": "refresh",
                "jti": to_encode["jti"],
                "expires_at": expire.isoformat(),
            },
            level=AuditLevel.INFO,
        )

        return encoded_jwt

    async def verify_token(
        self, token: str, token_type: str = "access"
    ) -> Dict[str, Any]:
        try:
            payload = jwt.decode(
                token, self.secret_key, algorithms=[self.algorithm]
            )

            # Verify token type
            if payload.get("type") != token_type:
                raise JWTError("Invalid token type")

            # Check if token is revoked
            jti = payload.get("jti")
            if jti and self._is_token_revoked(jti):
                raise JWTError("Token has been revoked")

            return payload

        except JWTError as e:
            await self.audit.log_event(
                event_type="token_verification_failed",
                user_id=None,
                details={"error": str(e)},
                level=AuditLevel.WARNING,
            )
            raise

    def _is_token_revoked(self, jti: str) -> bool:
        # Check if token is in revoked list or session is invalid
        return (
            jti in self.revoked_tokens
            if hasattr(self, "revoked_tokens")
            else False
        )

    async def revoke_token(self, token: str):
        try:
            payload = jwt.decode(
                token, self.secret_key, algorithms=[self.algorithm]
            )
            jti = payload.get("jti")

            if jti:
                if not hasattr(self, "revoked_tokens"):
                    self.revoked_tokens = set()
                self.revoked_tokens.add(jti)

                # Remove from active sessions if refresh token
                if jti in self.active_sessions:
                    del self.active_sessions[jti]

                await self.audit.log_event(
                    event_type="token_revoked",
                    user_id=payload.get("sub"),
                    details={"jti": jti},
                    level=AuditLevel.INFO,
                )
        except JWTError:
            pass

    def generate_mfa_secret(self, user_id: str) -> str:
        secret = pyotp.random_base32()
        self.mfa_secrets[user_id] = secret
        return secret

    def generate_mfa_qr_code(
        self, user_id: str, secret: str, issuer: str = "CatNet"
    ) -> str:
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user_id, issuer_name=issuer
        )
        return provisioning_uri

    def verify_mfa_token(
        self, user_id: str, token: str, secret: Optional[str] = None
    ) -> bool:
        if not secret:
            secret = self.mfa_secrets.get(user_id)

        if not secret:
            return False

        totp = pyotp.TOTP(secret)
        # Allow for time drift (accepts tokens from 30 seconds ago to 30 seconds in future)
        return totp.verify(token, valid_window=1)

    async def authenticate_user(
        self,
        username: str,
        password: str,
        mfa_token: Optional[str] = None,
        require_mfa: bool = True,
        ip_address: Optional[str] = None,
    ) -> Dict[str, Any]:
        # This would typically check against database
        # For now, returning mock authentication

        # Verify password (mock)
        if not self.verify_password(
            password, self.get_password_hash(password)
        ):
            await self.audit.log_authentication(
                user_id=username,
                success=False,
                method="password",
                ip_address=ip_address or "unknown",
            )
            return {"authenticated": False, "error": "Invalid credentials"}

        # Verify MFA if required
        if require_mfa and mfa_token:
            if not self.verify_mfa_token(username, mfa_token):
                await self.audit.log_authentication(
                    user_id=username,
                    success=False,
                    method="mfa",
                    ip_address=ip_address or "unknown",
                )
                return {"authenticated": False, "error": "Invalid MFA token"}

        # Generate tokens
        user_data = {"sub": username, "roles": ["admin"]}  # Mock roles
        access_token = await self.create_access_token(data=user_data)
        refresh_token = await self.create_refresh_token(data=user_data)

        await self.audit.log_authentication(
            user_id=username,
            success=True,
            method="password+mfa" if require_mfa else "password",
            ip_address=ip_address or "unknown",
        )

        return {
            "authenticated": True,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        }

    async def refresh_access_token(self, refresh_token: str) -> Dict[str, str]:
        payload = await self.verify_token(refresh_token, token_type="refresh")

        # Create new access token
        user_data = {
            "sub": payload.get("sub"),
            "roles": payload.get("roles", []),
        }
        new_access_token = await self.create_access_token(data=user_data)

        return {"access_token": new_access_token, "token_type": "bearer"}

    async def check_permission(
        self, user: Dict[str, Any], permission: str
    ) -> bool:
        user_roles = user.get("roles", [])

        # Define role-permission mapping
        role_permissions = {
            "admin": ["*"],  # Admin has all permissions
            "operator": [
                "deployment.view",
                "deployment.create",
                "device.view",
                "device.backup",
            ],
            "viewer": ["deployment.view", "device.view"],
        }

        # Check if user has permission
        for role in user_roles:
            if role in role_permissions:
                perms = role_permissions[role]
                if "*" in perms or permission in perms:
                    return True

        await self.audit.log_unauthorized_attempt(
            user_context=user,
            resource=permission.split(".")[0],
            action=permission.split(".")[1],
        )

        return False

    def generate_api_key(self) -> str:
        return secrets.token_urlsafe(32)

    async def verify_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        # This would check against database
        # For now, returning mock verification
        if api_key:
            return {"sub": "api_user", "roles": ["api"], "key_id": api_key[:8]}
        return None
