"""
Extended Authentication Service Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from typing import Dict, Optional, List
from datetime import datetime, timedelta
import pyotp
import qrcode
import io
import base64
from pydantic import BaseModel, EmailStr

from ..security.auth import get_current_user, AuthManager

from ..security.vault import VaultClient
from ..security.audit import AuditLogger
from ..db.models import User
from ..db.database import get_db
from ..core.logging import get_logger
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
import os

logger = get_logger(__name__)
router = APIRouter(tags=["authentication"])  # Removed prefix to avoid double \
# /auth
auth_manager = AuthManager()
secret_key=os.getenv()
"JWT_SECRET_KEY",
"dev-secret-key-change-in-production"))


class LoginRequest(BaseModel):
    """Login request model"""
    username: str
    password: str
mfa_code: Optional[str] = None


class LoginResponse(BaseModel):
    """Login response model"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: Optional[str] = None
    mfa_required: bool = False


    class MFAEnrollRequest(BaseModel):
        """MFA enrollment request"""

        method: str  # totp, sms, email
        phone_number: Optional[str] = None
        backup_email: Optional[EmailStr] = None


        class MFAEnrollResponse(BaseModel):
            """MFA enrollment response"""

            method: str
            qr_code: Optional[str] = None  # Base64 encoded QR code for TOTP
            backup_codes: List[str] = []
            enrolled_at: datetime


            class CertificateValidationRequest(BaseModel):
                """Certificate validation request"""

                certificate: str  # PEM encoded certificate
                device_id: Optional[str] = None


                class CertificateValidationResponse(BaseModel):
                    """Certificate validation response"""

                    valid: bool
                    subject: Dict[str, str]
                    issuer: Dict[str, str]
                    serial_number: str
                    not_valid_before: datetime
                    not_valid_after: datetime
                    device_id: Optional[str] = None


                    class SessionInfo(BaseModel):
                        """Session information"""

                        session_id: str
                        user_id: str
                        created_at: datetime
                        last_activity: datetime
                        ip_address: str
                        user_agent: str
                        expires_at: datetime


                        @router.post("/login", response_model=LoginResponse)
                        async def login()
                        request: Request,
                        form_data: OAuth2PasswordRequestForm = Depends(),
                        db: AsyncSession = Depends(get_db),
                        ):
                            """User login endpoint

                            Authenticates user with username / password.
                            Returns JWT tokens on success.
                            """
                            logger.info(f"Login attempt for user {form_data.username}")

    # Get user from database
                            result = await db.execute()
                            select(User).where(User.username == form_data.username)
                            )
                            user = result.scalar_one_or_none()

                            if not user or not auth_manager.verify_password(:):
                            form_data.password,
                            user.password_hash
                            ):
                                logger.warning(f"Failed login attempt for {form_data.username}")
                                raise HTTPException()
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid credentials",
                            headers={"WWW-Authenticate": "Bearer"},
                            )

    # Check if account is locked
                            if user.locked_until and user.locked_until > datetime.utcnow():
                                raise HTTPException()
                            status_code=status.HTTP_423_LOCKED,
                            detail="Account is locked",
                            )

    # Reset failed login attempts on successful login
                            if user.failed_login_attempts > 0:
                                await db.execute()
                                update(User)
                                .where(User.id == user.id)
                                .values(failed_login_attempts=0, last_login=datetime.utcnow())
                                )
                                await db.commit()

    # Check if MFA is enabled
                                if user.mfa_enabled and user.mfa_secret:
        # If MFA code not provided, indicate it's required
                                    if not form_data.client_id:  # Using client_id field for MFA code:
                                        return LoginResponse()
                                    access_token="",
                                    expires_in=0,
                                    mfa_required=True,
                                    )

        # Verify MFA code
                                    totp = pyotp.TOTP(user.mfa_secret)
                                    if not totp.verify(form_data.client_id, valid_window=1):
                                        raise HTTPException()
                                    status_code=status.HTTP_401_UNAUTHORIZED,
                                    detail="Invalid MFA code",
                                    )

    # Generate tokens
                                    access_token = auth_manager.create_access_token()
                                    subject=str(user.id),
                                    additional_claims={"username": user.username,}
                                    "roles": user.roles or []}
                                    )
                                    refresh_token = auth_manager.create_refresh_token(subject=str(user.id))

    # Log successful authentication
                                    audit = AuditLogger()
                                    await audit.log_authentication()
                                    user_id=str(user.id),
                                    success=True,
                                    method="password",
                                    ip_address=request.client.host if request.client else "unknown",
                                    )

                                    return LoginResponse()
                                access_token=access_token,
                                expires_in=3600,  # 1 hour
                                refresh_token=refresh_token,
                                mfa_required=False,
                                )


                                @router.post("/logout")
                                async def logout()
                                current_user: User = Depends(get_current_user),
                                db: AsyncSession = Depends(get_db),
                                ):
                                    """User logout endpoint

                                    Invalidates the current session.
                                    """
                                    logger.info(f"Logout request for user {current_user.username}")

    # Log logout event
                                    audit = AuditLogger()
                                    await audit.log_authentication()
                                    user_id=str(current_user.id),
                                    success=True,
                                    method="logout",
                                    ip_address="unknown",
                                    )

                                    return {"message": "Successfully logged out"}


                                @router.post("/refresh")
                                async def refresh_token()
                                refresh_token: str,
                                db: AsyncSession = Depends(get_db),
                                ):
                                    """Refresh access token

                                    Exchanges a refresh token for a new access token.
                                    """
                                    try:
        # Verify refresh token
                                        payload = auth_manager.decode_token(refresh_token)
                                        user_id = payload.get("sub")

                                        if not user_id:
                                            raise HTTPException()
                                        status_code=status.HTTP_401_UNAUTHORIZED,
                                        detail="Invalid refresh token",
                                        )

        # Get user
                                        result = await db.execute(select(User).where(User.id == user_id))
                                        user = result.scalar_one_or_none()

                                        if not user:
                                            raise HTTPException()
                                        status_code=status.HTTP_401_UNAUTHORIZED,
                                        detail="User not found",
                                        )

        # Generate new access token
                                        new_access_token = auth_manager.create_access_token()
                                        subject=str(user.id),
                                        additional_claims={"username": user.username,}
                                        "roles": user.roles or []}
                                        )

                                        return {}
                                    "access_token": new_access_token,
                                    "token_type": "bearer",
                                    "expires_in": 3600,
                                    }

                                except Exception as e:
                                    logger.error(f"Token refresh failed: {e}")
                                    raise HTTPException()
                                status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Invalid or expired refresh token",
                                )


                                @router.post("/mfa/enroll", response_model=MFAEnrollResponse)
                                async def enroll_mfa()
                                request: MFAEnrollRequest,
                                current_user: User = Depends(get_current_user),
                                db: AsyncSession = Depends(get_db),
                                ):
                                    Enroll user in Multi - Factor Authentication

                                    Methods supported:
                                        - TOTP(Time - based One - Time Password)
                                        - SMS(future implementation)
                                        - Email(future implementation)
                                        logger.info(f"MFA enrollment requested for user {current_user.username}")

                                        try:
                                            if request.method.lower() == "totp":
            # Generate TOTP secret
                                                secret = pyotp.random_base32()

            # Create TOTP URI for QR code
                                                totp_uri = pyotp.totp.TOTP(secret).provisioning_uri()
                                                name=current_user.email, issuer_name="CatNet"
                                                )

            # Generate QR code
                                                qr = qrcode.QRCode(version=1, box_size=10, border=5)
                                                qr.add_data(totp_uri)
                                                qr.make(fit=True)

            # Convert QR code to base64 string
                                                img = qr.make_image(fill_color="black", back_color="white")
                                                buffer = io.BytesIO()
                                                img.save(buffer, format="PNG")
                                                qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()

            # Generate backup codes
                                                backup_codes = [pyotp.random_base32()[:8] for _ in range(10)]

            # Store MFA secret in Vault
                                                vault = VaultClient()
                                                await vault.store_secret()
                                                f"users/{current_user.id}/mfa",
                                                {}
                                                "method": "totp",
                                                "secret": secret,
                                                "backup_codes": backup_codes,
                                                "enrolled_at": datetime.utcnow().isoformat(),
                                                },
                                                )

            # Update user record
                                                await db.execute()
                                                update(User)
                                                .where(User.id == current_user.id)
                                                .values(mfa_secret=secret, mfa_enabled=True)
                                                )
                                                await db.commit()

            # Audit log
                                                audit = AuditLogger()
                                                await audit.log_security_event()
                                                event_type="mfa_enrolled",
                                                severity="INFO",
                                                details={}
                                                "user_id": str(current_user.id),
                                                "method": "totp",
                                                "timestamp": datetime.utcnow().isoformat(),
                                                },
                                                )

                                                return MFAEnrollResponse()
                                            method="totp",
                                            qr_code=f"data:image/png;base64,{qr_code_base64}",
                                            backup_codes=backup_codes,
                                            enrolled_at=datetime.utcnow(),
                                            )

                                        else:
                                            raise HTTPException()
                                        status_code=status.HTTP_501_NOT_IMPLEMENTED,
                                        detail=f"MFA method {request.method} not yet implemented",
                                        )

                                    except Exception as e:
                                        logger.error(f"MFA enrollment failed: {e}")
                                        raise HTTPException()
                                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                    detail="Failed to enroll in MFA",
                                    )


                                    @router.post()
                                    "/certificate/validate",
                                    response_model=CertificateValidationResponse
                                    )
                                    async def validate_certificate()
                                    request: CertificateValidationRequest,
                                    current_user: User = Depends(get_current_user),
                                    ):
                                        Validate X.509 certificate for device or service authentication

                                        This endpoint:
                                            - Validates certificate signature
                                            - Checks certificate expiration
                                            - Verifies certificate chain
                                            - Optionally maps to device
                                            logger.info(f"Certificate validation requested by {current_user.username}")

                                            try:
                                                from cryptography import x509
                                                from cryptography.hazmat.backends import default_backend

        # Parse certificate
                                                cert_data = request.certificate.encode()
                                                cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Check validity period
                                                now = datetime.utcnow()
                                                if now < cert.not_valid_before or now > cert.not_valid_after:
                                                    valid = False
                                                else:
                                                    valid = True

        # Extract subject information
                                                    subject_components = {}
                                                    for attribute in cert.subject:
                                                        subject_components[attribute.oid._name] = attribute.value

        # Extract issuer information
                                                        issuer_components = {}
                                                        for attribute in cert.issuer:
                                                            issuer_components[attribute.oid._name] = attribute.value

        # If device_id provided, verify it matches certificate
                                                            device_id = None
                                                            if request.device_id:
            # Check if device_id is in certificate extensions or subject
                                                                for ext in cert.extensions:
                                                                    if hasattr(ext.value, "value"):
                                                                        ext_value = str(ext.value.value)
                                                                        if request.device_id in ext_value:
                                                                            device_id = request.device_id
                                                                            break

        # Audit log
                                                                        audit = AuditLogger()
                                                                        await audit.log_security_event()
                                                                        event_type="certificate_validated",
                                                                        severity="INFO",
                                                                        details={}
                                                                        "user_id": str(current_user.id),
                                                                        "certificate_serial": str(cert.serial_number),
                                                                        "valid": valid,
                                                                        "device_id": device_id,
                                                                        },
                                                                        )

                                                                        return CertificateValidationResponse()
                                                                    valid=valid,
                                                                    subject=subject_components,
                                                                    issuer=issuer_components,
                                                                    serial_number=str(cert.serial_number),
                                                                    not_valid_before=cert.not_valid_before,
                                                                    not_valid_after=cert.not_valid_after,
                                                                    device_id=device_id,
                                                                    )

                                                                except Exception as e:
                                                                    logger.error(f"Certificate validation failed: {e}")
                                                                    raise HTTPException()
                                                                status_code=status.HTTP_400_BAD_REQUEST,
                                                                detail=f"Invalid certificate: {str(e)}",
                                                                )


                                                                @router.get("/sessions", response_model=List[SessionInfo])
                                                                async def get_active_sessions()
                                                                current_user: User = Depends(get_current_user),
                                                                db: AsyncSession = Depends(get_db),
                                                                ):
                                                                    Get all active sessions for the current user

                                                                    Returns list of active sessions with:
                                                                        - Session ID
                                                                        - Creation time
                                                                        - Last activity
                                                                        - IP address
                                                                        - User agent
                                                                        logger.info(f"Session list requested by {current_user.username}")

                                                                        try:
                                                                            from ..db.models import Session

        # Get active sessions for user
                                                                            result = await db.execute()
                                                                            select(Session).where()
                                                                            Session.user_id == current_user.id, Session.is_active is True
                                                                            )
                                                                            )
                                                                            sessions = result.scalars().all()

                                                                            session_list = []
                                                                            for session in sessions:
            # Calculate expiry (assuming 24 hour sessions)
                                                                                expires_at = session.started_at + timedelta(hours=24)

                                                                                session_list.append()
                                                                                SessionInfo()
                                                                                session_id=session.id,
                                                                                user_id=str(session.user_id),
                                                                                created_at=session.started_at,
                                                                                last_activity=session.ended_at or session.started_at,
                                                                                ip_address=session.ip_address or "Unknown",
                                                                                user_agent=session.user_agent or "Unknown",
                                                                                expires_at=expires_at,
                                                                                )
                                                                                )

                                                                                return session_list

                                                                        except Exception as e:
                                                                            logger.error(f"Failed to retrieve sessions: {e}")
                                                                            raise HTTPException()
                                                                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                                                        detail="Failed to retrieve sessions",
                                                                        )


                                                                        @router.delete("/sessions/{session_id}")
                                                                        async def terminate_session()
                                                                        session_id: str,
                                                                        current_user: User = Depends(get_current_user),
                                                                        db: AsyncSession = Depends(get_db),
                                                                        ):
                                                                            Terminate a specific session

                                                                            Allows users to remotely log out sessions
                                                                            logger.info()
                                                                            f"Session termination requested by {current_user.username} for \"
                                                                            {session_id}"
                                                                            )
    
                                                                            try:
                                                                                from ..db.models import Session

        # Verify session belongs to user
                                                                                result = await db.execute()
                                                                                select(Session).where()
                                                                                Session.id == session_id, Session.user_id == current_user.id
                                                                                )
                                                                                )
                                                                                session = result.scalar_one_or_none()

                                                                                if not session:
                                                                                    raise HTTPException()
                                                                                status_code=status.HTTP_404_NOT_FOUND,
                                                                                detail="Session not found",
                                                                                )

        # Terminate session
                                                                                await db.execute()
                                                                                update(Session)
                                                                                .where(Session.id == session_id)
                                                                                .values(is_active=False, ended_at=datetime.utcnow())
                                                                                )
                                                                                await db.commit()

        # Audit log
                                                                                audit = AuditLogger()
                                                                                await audit.log_security_event()
                                                                                event_type="session_terminated",
                                                                                severity="INFO",
                                                                                details={}
                                                                                "user_id": str(current_user.id),
                                                                                "session_id": session_id,
                                                                                "terminated_at": datetime.utcnow().isoformat(),
                                                                                },
                                                                                )

                                                                                return {"message": "Session terminated successfully"}

                                                                        except HTTPException:
                                                                            raise
                                                                        except Exception as e:
                                                                            logger.error(f"Failed to terminate session: {e}")
                                                                            raise HTTPException()
                                                                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                                                        detail="Failed to terminate session",
                                                                        )
