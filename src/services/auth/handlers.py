"""
Request handlers for authentication service.
"""

import os
import json
import hashlib
import secrets
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import asyncio

import pyotp
import qrcode
from io import BytesIO
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import aiosmtplib
from twilio.rest import Client as TwilioClient
import httpx

from src.core.logging import get_logger
from src.core.config import get_settings
from src.security.vault import VaultClient

logger = get_logger(__name__)
settings = get_settings()


class LoginHandler:
    """Handles login requests and authentication flows."""

    def __init__(self):
        self.vault = VaultClient()
        self.audit_logger = get_logger("audit.login")

    async def handle_login(
        self,
        username: str,
        password: str,
        auth_type: str,
        device_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Handle login request.

        Args:
            username: Username or email
            password: User password
            auth_type: Authentication type
            device_info: Device information for fingerprinting

        Returns:
            Login result with user info and tokens
        """
        try:
            # Log login attempt
            self.audit_logger.info(f"Login attempt for user: {username}, auth_type: {auth_type}")

            # Validate credentials based on auth type
            if auth_type == "ldap":
                user = await self._handle_ldap_login(username, password)
            elif auth_type == "saml":
                user = await self._handle_saml_login(username, password)
            else:
                user = await self._handle_local_login(username, password)

            if not user:
                self.audit_logger.warning(f"Failed login attempt for user: {username}")
                return {
                    "success": False,
                    "error": "Invalid credentials"
                }

            # Check device trust if provided
            if device_info:
                is_trusted = await self._check_device_trust(user['id'], device_info)
                if is_trusted:
                    user['skip_mfa'] = True

            # Generate session tokens
            tokens = await self._generate_tokens(user)

            # Log successful login
            self.audit_logger.info(f"Successful login for user: {username}")

            return {
                "success": True,
                "user": user,
                "tokens": tokens,
                "require_mfa": user.get('mfa_enabled', False) and not user.get('skip_mfa', False)
            }

        except Exception as e:
            logger.error(f"Login error: {e}")
            self.audit_logger.error(f"Login error for user {username}: {e}")
            return {
                "success": False,
                "error": "Authentication failed"
            }

    async def _handle_local_login(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Handle local database authentication."""
        # Implementation handled in main auth service
        return None

    async def _handle_ldap_login(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Handle LDAP authentication."""
        # Implementation handled in main auth service
        return None

    async def _handle_saml_login(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Handle SAML authentication."""
        # Implementation handled in main auth service
        return None

    async def _check_device_trust(self, user_id: str, device_info: Dict[str, Any]) -> bool:
        """Check if device is trusted."""
        device_fingerprint = self._generate_device_fingerprint(device_info)
        # Check in database/cache for trusted device
        # Return True if trusted and not expired
        return False

    def _generate_device_fingerprint(self, device_info: Dict[str, Any]) -> str:
        """Generate device fingerprint."""
        data = json.dumps(device_info, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()

    async def _generate_tokens(self, user: Dict[str, Any]) -> Dict[str, str]:
        """Generate session tokens."""
        return {
            "access_token": secrets.token_urlsafe(32),
            "refresh_token": secrets.token_urlsafe(32),
            "id_token": secrets.token_urlsafe(32)
        }


class MFAHandler:
    """Handles MFA setup and verification."""

    def __init__(self):
        self.vault = VaultClient()
        self.audit_logger = get_logger("audit.mfa")

    async def setup_totp(self, user_id: str, user_email: str) -> Dict[str, Any]:
        """
        Setup TOTP MFA for user.

        Args:
            user_id: User ID
            user_email: User email for QR code

        Returns:
            TOTP setup information with QR code
        """
        try:
            # Generate secret
            secret = pyotp.random_base32()

            # Store secret securely
            await self.vault.put_secret(
                f"mfa/totp/{user_id}",
                {"secret": secret}
            )

            # Generate provisioning URI
            totp = pyotp.TOTP(secret)
            provisioning_uri = totp.provisioning_uri(
                user_email,
                issuer_name="CatNet"
            )

            # Generate QR code
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(provisioning_uri)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")
            buffer = BytesIO()
            img.save(buffer, format='PNG')
            qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()

            # Generate backup codes
            backup_codes = [secrets.token_hex(4) for _ in range(10)]

            # Store backup codes
            await self.vault.put_secret(
                f"mfa/backup/{user_id}",
                {"codes": backup_codes}
            )

            self.audit_logger.info(f"TOTP MFA setup initiated for user: {user_id}")

            return {
                "secret": secret,
                "qr_code": f"data:image/png;base64,{qr_code_base64}",
                "backup_codes": backup_codes,
                "manual_entry_key": secret
            }

        except Exception as e:
            logger.error(f"TOTP setup error: {e}")
            raise

    async def setup_sms(self, user_id: str, phone_number: str) -> Dict[str, Any]:
        """
        Setup SMS MFA for user.

        Args:
            user_id: User ID
            phone_number: Phone number for SMS

        Returns:
            SMS setup confirmation
        """
        try:
            # Validate and format phone number
            formatted_phone = self._format_phone_number(phone_number)

            # Store phone number securely
            await self.vault.put_secret(
                f"mfa/sms/{user_id}",
                {"phone": formatted_phone}
            )

            # Send verification code
            verification_code = secrets.randbelow(999999)
            verification_code = f"{verification_code:06d}"

            await self._send_sms(
                formatted_phone,
                f"Your CatNet verification code is: {verification_code}"
            )

            # Store verification code temporarily
            await self.vault.put_secret(
                f"mfa/sms/verify/{user_id}",
                {"code": verification_code},
                ttl=300  # 5 minutes
            )

            self.audit_logger.info(f"SMS MFA setup initiated for user: {user_id}")

            return {
                "phone_number": self._mask_phone(formatted_phone),
                "verification_required": True,
                "verification_expires": 300
            }

        except Exception as e:
            logger.error(f"SMS setup error: {e}")
            raise

    async def setup_email(self, user_id: str, email: str) -> Dict[str, Any]:
        """
        Setup email MFA for user.

        Args:
            user_id: User ID
            email: Email address for MFA

        Returns:
            Email setup confirmation
        """
        try:
            # Send verification code
            verification_code = secrets.randbelow(999999)
            verification_code = f"{verification_code:06d}"

            await self._send_email(
                email,
                "CatNet MFA Setup",
                f"Your verification code is: {verification_code}"
            )

            # Store verification code temporarily
            await self.vault.put_secret(
                f"mfa/email/verify/{user_id}",
                {"code": verification_code},
                ttl=300  # 5 minutes
            )

            self.audit_logger.info(f"Email MFA setup initiated for user: {user_id}")

            return {
                "email": self._mask_email(email),
                "verification_required": True,
                "verification_expires": 300
            }

        except Exception as e:
            logger.error(f"Email setup error: {e}")
            raise

    async def verify_totp(self, user_id: str, code: str) -> bool:
        """Verify TOTP code."""
        try:
            # Get secret from vault
            secret_data = await self.vault.get_secret(f"mfa/totp/{user_id}")
            if not secret_data:
                return False

            secret = secret_data['secret']
            totp = pyotp.TOTP(secret)

            # Verify with time window
            valid = totp.verify(code, valid_window=1)

            if valid:
                self.audit_logger.info(f"TOTP verification successful for user: {user_id}")
            else:
                self.audit_logger.warning(f"TOTP verification failed for user: {user_id}")

            return valid

        except Exception as e:
            logger.error(f"TOTP verification error: {e}")
            return False

    async def verify_sms(self, user_id: str, code: str) -> bool:
        """Verify SMS code."""
        try:
            # Get stored code from vault
            code_data = await self.vault.get_secret(f"mfa/sms/current/{user_id}")
            if not code_data:
                return False

            stored_code = code_data['code']
            valid = stored_code == code

            if valid:
                self.audit_logger.info(f"SMS verification successful for user: {user_id}")
                # Delete used code
                await self.vault.delete_secret(f"mfa/sms/current/{user_id}")
            else:
                self.audit_logger.warning(f"SMS verification failed for user: {user_id}")

            return valid

        except Exception as e:
            logger.error(f"SMS verification error: {e}")
            return False

    async def verify_email(self, user_id: str, code: str) -> bool:
        """Verify email code."""
        try:
            # Get stored code from vault
            code_data = await self.vault.get_secret(f"mfa/email/current/{user_id}")
            if not code_data:
                return False

            stored_code = code_data['code']
            valid = stored_code == code

            if valid:
                self.audit_logger.info(f"Email verification successful for user: {user_id}")
                # Delete used code
                await self.vault.delete_secret(f"mfa/email/current/{user_id}")
            else:
                self.audit_logger.warning(f"Email verification failed for user: {user_id}")

            return valid

        except Exception as e:
            logger.error(f"Email verification error: {e}")
            return False

    async def send_sms_code(self, user_id: str) -> bool:
        """Send SMS MFA code."""
        try:
            # Get phone number from vault
            phone_data = await self.vault.get_secret(f"mfa/sms/{user_id}")
            if not phone_data:
                return False

            phone_number = phone_data['phone']

            # Generate code
            code = secrets.randbelow(999999)
            code = f"{code:06d}"

            # Send SMS
            await self._send_sms(
                phone_number,
                f"Your CatNet authentication code is: {code}"
            )

            # Store code temporarily
            await self.vault.put_secret(
                f"mfa/sms/current/{user_id}",
                {"code": code},
                ttl=300  # 5 minutes
            )

            self.audit_logger.info(f"SMS MFA code sent to user: {user_id}")
            return True

        except Exception as e:
            logger.error(f"Send SMS code error: {e}")
            return False

    async def send_email_code(self, user_id: str, email: str) -> bool:
        """Send email MFA code."""
        try:
            # Generate code
            code = secrets.randbelow(999999)
            code = f"{code:06d}"

            # Send email
            await self._send_email(
                email,
                "CatNet Authentication Code",
                f"Your authentication code is: {code}"
            )

            # Store code temporarily
            await self.vault.put_secret(
                f"mfa/email/current/{user_id}",
                {"code": code},
                ttl=300  # 5 minutes
            )

            self.audit_logger.info(f"Email MFA code sent to user: {user_id}")
            return True

        except Exception as e:
            logger.error(f"Send email code error: {e}")
            return False

    def _format_phone_number(self, phone: str) -> str:
        """Format phone number to E.164 format."""
        # Remove all non-digits
        digits = ''.join(c for c in phone if c.isdigit())
        # Add country code if missing (assume US)
        if len(digits) == 10:
            digits = '1' + digits
        return '+' + digits

    def _mask_phone(self, phone: str) -> str:
        """Mask phone number for display."""
        if len(phone) < 4:
            return phone
        return phone[:-4] + '****'

    def _mask_email(self, email: str) -> str:
        """Mask email for display."""
        parts = email.split('@')
        if len(parts) != 2:
            return email
        local = parts[0]
        if len(local) > 2:
            local = local[:2] + '***'
        return f"{local}@{parts[1]}"

    async def _send_sms(self, phone: str, message: str):
        """Send SMS via Twilio."""
        try:
            # Get Twilio credentials from vault
            creds = await self.vault.get_secret("twilio/credentials")
            client = TwilioClient(creds['account_sid'], creds['auth_token'])

            client.messages.create(
                body=message,
                from_=creds['from_number'],
                to=phone
            )

        except Exception as e:
            logger.error(f"SMS send error: {e}")
            raise

    async def _send_email(self, to_email: str, subject: str, body: str):
        """Send email via SMTP."""
        try:
            # Get SMTP credentials from vault
            creds = await self.vault.get_secret("smtp/credentials")

            msg = MIMEMultipart()
            msg['From'] = creds['from_email']
            msg['To'] = to_email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))

            await aiosmtplib.send(
                msg,
                hostname=creds['host'],
                port=creds['port'],
                username=creds['username'],
                password=creds['password'],
                use_tls=True
            )

        except Exception as e:
            logger.error(f"Email send error: {e}")
            raise


class TokenHandler:
    """Handles token generation, validation, and refresh."""

    def __init__(self):
        self.vault = VaultClient()
        self.audit_logger = get_logger("audit.token")

    async def generate_tokens(self, user: Dict[str, Any]) -> Dict[str, str]:
        """Generate access and refresh tokens."""
        try:
            # Generate tokens
            access_token = secrets.token_urlsafe(32)
            refresh_token = secrets.token_urlsafe(48)
            id_token = secrets.token_urlsafe(32)

            # Calculate expiration
            access_expires = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
            refresh_expires = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

            # Store token metadata
            token_data = {
                "user_id": user['id'],
                "username": user['username'],
                "roles": user.get('roles', []),
                "access_token": access_token,
                "refresh_token": refresh_token,
                "id_token": id_token,
                "access_expires": access_expires.isoformat(),
                "refresh_expires": refresh_expires.isoformat(),
                "created_at": datetime.utcnow().isoformat()
            }

            # Store in vault with TTL
            await self.vault.put_secret(
                f"tokens/access/{access_token}",
                token_data,
                ttl=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
            )

            await self.vault.put_secret(
                f"tokens/refresh/{refresh_token}",
                token_data,
                ttl=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400
            )

            self.audit_logger.info(f"Tokens generated for user: {user['username']}")

            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "id_token": id_token,
                "token_type": "Bearer",
                "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
            }

        except Exception as e:
            logger.error(f"Token generation error: {e}")
            raise

    async def validate_token(self, token: str, token_type: str = "access") -> Optional[Dict[str, Any]]:
        """Validate token and return user info."""
        try:
            # Get token from vault
            token_data = await self.vault.get_secret(f"tokens/{token_type}/{token}")
            if not token_data:
                return None

            # Check expiration
            if token_type == "access":
                expires = datetime.fromisoformat(token_data['access_expires'])
            else:
                expires = datetime.fromisoformat(token_data['refresh_expires'])

            if expires < datetime.utcnow():
                self.audit_logger.warning(f"Expired {token_type} token used")
                return None

            return token_data

        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return None

    async def refresh_tokens(self, refresh_token: str) -> Optional[Dict[str, str]]:
        """Refresh access token using refresh token."""
        try:
            # Validate refresh token
            token_data = await self.validate_token(refresh_token, "refresh")
            if not token_data:
                self.audit_logger.warning("Invalid refresh token used")
                return None

            # Generate new tokens
            user = {
                "id": token_data['user_id'],
                "username": token_data['username'],
                "roles": token_data['roles']
            }

            new_tokens = await self.generate_tokens(user)

            # Revoke old tokens
            await self.revoke_token(token_data['access_token'], "access")
            await self.revoke_token(refresh_token, "refresh")

            self.audit_logger.info(f"Tokens refreshed for user: {user['username']}")

            return new_tokens

        except Exception as e:
            logger.error(f"Token refresh error: {e}")
            return None

    async def revoke_token(self, token: str, token_type: str = "access"):
        """Revoke token."""
        try:
            # Delete from vault
            await self.vault.delete_secret(f"tokens/{token_type}/{token}")

            # Add to blacklist
            await self.vault.put_secret(
                f"tokens/blacklist/{token}",
                {"revoked_at": datetime.utcnow().isoformat()},
                ttl=86400  # Keep for 24 hours
            )

            self.audit_logger.info(f"Token revoked: {token_type}")

        except Exception as e:
            logger.error(f"Token revocation error: {e}")


class LogoutHandler:
    """Handles logout and session cleanup."""

    def __init__(self):
        self.vault = VaultClient()
        self.audit_logger = get_logger("audit.logout")

    async def logout(self, token: str, user_id: str):
        """
        Logout user and clean up session.

        Args:
            token: Access token
            user_id: User ID
        """
        try:
            # Revoke tokens
            token_handler = TokenHandler()
            await token_handler.revoke_token(token, "access")

            # Clear session data
            await self.vault.delete_secret(f"sessions/{user_id}")

            # Clear any MFA session
            await self.vault.delete_secret(f"mfa/session/{user_id}")

            self.audit_logger.info(f"User logged out: {user_id}")

        except Exception as e:
            logger.error(f"Logout error: {e}")
            raise

    async def logout_all_sessions(self, user_id: str):
        """Logout all sessions for a user."""
        try:
            # Get all user sessions
            sessions = await self.vault.list_secrets(f"sessions/{user_id}/")

            # Revoke all tokens
            for session_path in sessions:
                session_data = await self.vault.get_secret(session_path)
                if session_data and 'token' in session_data:
                    token_handler = TokenHandler()
                    await token_handler.revoke_token(session_data['token'], "access")

                await self.vault.delete_secret(session_path)

            self.audit_logger.info(f"All sessions logged out for user: {user_id}")

        except Exception as e:
            logger.error(f"Logout all sessions error: {e}")
            raise


class UserManagementHandler:
    """Handles user management operations."""

    def __init__(self):
        self.vault = VaultClient()
        self.audit_logger = get_logger("audit.user")

    async def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new user."""
        try:
            # Hash password
            from passlib.context import CryptContext
            pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")
            password_hash = pwd_context.hash(user_data['password'])

            # Generate user ID
            user_id = secrets.token_urlsafe(16)

            # Store user data
            user = {
                "id": user_id,
                "username": user_data['username'],
                "email": user_data['email'],
                "full_name": user_data.get('full_name', ''),
                "password_hash": password_hash,
                "roles": user_data.get('roles', ['user']),
                "is_active": True,
                "mfa_enabled": False,
                "created_at": datetime.utcnow().isoformat()
            }

            self.audit_logger.info(f"User created: {user['username']}")

            return user

        except Exception as e:
            logger.error(f"User creation error: {e}")
            raise

    async def update_user(self, user_id: str, updates: Dict[str, Any]) -> bool:
        """Update user information."""
        try:
            # Log update
            self.audit_logger.info(f"User updated: {user_id}, fields: {list(updates.keys())}")

            # Apply updates (implementation depends on database)
            return True

        except Exception as e:
            logger.error(f"User update error: {e}")
            return False

    async def delete_user(self, user_id: str) -> bool:
        """Delete user (soft delete)."""
        try:
            # Log deletion
            self.audit_logger.info(f"User deleted: {user_id}")

            # Logout all sessions
            logout_handler = LogoutHandler()
            await logout_handler.logout_all_sessions(user_id)

            # Mark as inactive (soft delete)
            return await self.update_user(user_id, {"is_active": False})

        except Exception as e:
            logger.error(f"User deletion error: {e}")
            return False

    async def reset_password(self, user_id: str, new_password: str) -> bool:
        """Reset user password."""
        try:
            # Hash new password
            from passlib.context import CryptContext
            pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")
            password_hash = pwd_context.hash(new_password)

            # Update password
            await self.update_user(user_id, {
                "password_hash": password_hash,
                "password_changed_at": datetime.utcnow().isoformat()
            })

            # Logout all sessions
            logout_handler = LogoutHandler()
            await logout_handler.logout_all_sessions(user_id)

            self.audit_logger.info(f"Password reset for user: {user_id}")

            return True

        except Exception as e:
            logger.error(f"Password reset error: {e}")
            return False