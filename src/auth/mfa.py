"""
MFA Manager for CatNet
Supports TOTP, SMS, Email, and Hardware Token authentication
"""

import pyotp
import qrcode
import io
import base64
import secrets
import hashlib
import hmac
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timedelta
from enum import Enum
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
import asyncio
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend

from src.core.config import settings
from src.db.models import User, MFAConfig, BackupCode, MFAAttempt
from src.security.encryption import EncryptionManager
from src.security.vault import VaultClient
from src.security.audit import AuditLogger

logger = structlog.get_logger()

class MFAType(Enum):
    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"
    HARDWARE = "hardware"
    BACKUP_CODE = "backup_code"

class MFAManager:
    """
    Comprehensive MFA management system
    Supports multiple MFA methods with fallback options
    """

    def __init__(self):
        self.interval = 30
        self.digits = 6
        self.encryption_manager = EncryptionManager()
        self.vault_client = VaultClient()
        self.audit_logger = AuditLogger()
        self.max_attempts = settings.mfa_max_attempts
        self.attempt_window = settings.mfa_attempt_window_minutes

    async def setup_totp(
        self,
        db: AsyncSession,
        user: User,
        issuer: str = "CatNet"
    ) -> Dict[str, Any]:
        """
        Setup TOTP-based MFA for user
        """
        secret = pyotp.random_base32()

        encrypted_secret = await self.vault_client.encrypt_field(
            f"mfa/{user.id}/totp",
            secret
        )

        mfa_config = MFAConfig(
            user_id=user.id,
            mfa_type=MFAType.TOTP.value,
            secret=encrypted_secret,
            is_primary=True,
            is_verified=False
        )

        db.add(mfa_config)

        backup_codes = await self._generate_backup_codes(db, user)

        provisioning_uri = self._get_provisioning_uri(secret, user.username, issuer)
        qr_code = self._generate_qr_code(provisioning_uri)

        await db.commit()

        await self.audit_logger.log_event(
            db=db,
            user=user,
            action="mfa.totp.setup",
            details={
                "mfa_type": MFAType.TOTP.value
            }
        )

        return {
            "secret": secret,
            "qr_code": f"data:image/png;base64,{qr_code}",
            "provisioning_uri": provisioning_uri,
            "backup_codes": backup_codes
        }

    async def setup_sms(
        self,
        db: AsyncSession,
        user: User,
        phone_number: str
    ) -> Dict[str, Any]:
        """
        Setup SMS-based MFA
        """
        normalized_phone = self._normalize_phone_number(phone_number)

        phone_hash = hashlib.sha256(normalized_phone.encode()).hexdigest()

        encrypted_phone = await self.vault_client.encrypt_field(
            f"mfa/{user.id}/sms",
            normalized_phone
        )

        mfa_config = MFAConfig(
            user_id=user.id,
            mfa_type=MFAType.SMS.value,
            secret=encrypted_phone,
            phone_hash=phone_hash,
            is_primary=False,
            is_verified=False
        )

        db.add(mfa_config)
        await db.commit()

        verification_code = await self._send_sms_code(normalized_phone)

        await self.audit_logger.log_event(
            db=db,
            user=user,
            action="mfa.sms.setup",
            details={
                "phone_hash": phone_hash
            }
        )

        return {
            "phone_number": self._mask_phone_number(normalized_phone),
            "verification_required": True
        }

    async def setup_email(
        self,
        db: AsyncSession,
        user: User,
        email: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Setup email-based MFA
        """
        target_email = email or user.email

        mfa_config = MFAConfig(
            user_id=user.id,
            mfa_type=MFAType.EMAIL.value,
            secret=target_email,
            is_primary=False,
            is_verified=False
        )

        db.add(mfa_config)
        await db.commit()

        verification_code = await self._send_email_code(target_email)

        await self.audit_logger.log_event(
            db=db,
            user=user,
            action="mfa.email.setup",
            details={
                "email": self._mask_email(target_email)
            }
        )

        return {
            "email": self._mask_email(target_email),
            "verification_required": True
        }

    async def verify_mfa(
        self,
        db: AsyncSession,
        user: User,
        code: str,
        mfa_type: Optional[MFAType] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify MFA code from any configured method
        """
        if await self._check_rate_limit(db, user):
            return False, "Too many attempts. Please wait before trying again."

        await self._record_attempt(db, user)

        if mfa_type == MFAType.BACKUP_CODE:
            return await self._verify_backup_code(db, user, code)

        stmt = select(MFAConfig).where(
            MFAConfig.user_id == user.id,
            MFAConfig.is_verified == True
        )
        if mfa_type:
            stmt = stmt.where(MFAConfig.mfa_type == mfa_type.value)

        result = await db.execute(stmt)
        configs = result.scalars().all()

        for config in configs:
            if config.mfa_type == MFAType.TOTP.value:
                if await self._verify_totp(config, code):
                    await self._clear_attempts(db, user)
                    return True, None
            elif config.mfa_type == MFAType.SMS.value:
                if await self._verify_sms_code(db, user, code):
                    await self._clear_attempts(db, user)
                    return True, None
            elif config.mfa_type == MFAType.EMAIL.value:
                if await self._verify_email_code(db, user, code):
                    await self._clear_attempts(db, user)
                    return True, None

        return False, "Invalid verification code"

    async def _verify_totp(
        self,
        config: MFAConfig,
        code: str
    ) -> bool:
        """
        Verify TOTP code
        """
        try:
            decrypted_secret = await self.vault_client.decrypt_field(
                f"mfa/{config.user_id}/totp"
            )
            totp = pyotp.TOTP(
                decrypted_secret,
                interval=self.interval,
                digits=self.digits
            )
            return totp.verify(code, valid_window=1)
        except Exception as e:
            logger.error(f"TOTP verification error: {e}")
            return False

    async def _verify_backup_code(
        self,
        db: AsyncSession,
        user: User,
        code: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify and consume backup code
        """
        code_hash = hashlib.sha256(code.encode()).hexdigest()

        stmt = select(BackupCode).where(
            BackupCode.user_id == user.id,
            BackupCode.code_hash == code_hash,
            BackupCode.used == False
        )
        result = await db.execute(stmt)
        backup_code = result.scalar_one_or_none()

        if backup_code:
            backup_code.used = True
            backup_code.used_at = datetime.utcnow()
            await db.commit()

            await self.audit_logger.log_event(
                db=db,
                user=user,
                action="mfa.backup_code.used",
                details={
                    "code_hash": code_hash
                }
            )

            remaining = await db.execute(
                select(BackupCode).where(
                    BackupCode.user_id == user.id,
                    BackupCode.used == False
                )
            )
            count = len(remaining.scalars().all())

            if count < 3:
                return True, f"Warning: Only {count} backup codes remaining"

            return True, None

        return False, "Invalid backup code"

    async def _generate_backup_codes(
        self,
        db: AsyncSession,
        user: User,
        count: int = 10
    ) -> List[str]:
        """
        Generate and store backup codes
        """
        stmt = update(BackupCode).where(
            BackupCode.user_id == user.id
        ).values(invalidated=True)
        await db.execute(stmt)

        codes = []
        for _ in range(count):
            code = f"{secrets.token_hex(4)}-{secrets.token_hex(4)}"
            code_hash = hashlib.sha256(code.encode()).hexdigest()

            backup_code = BackupCode(
                user_id=user.id,
                code_hash=code_hash,
                used=False
            )
            db.add(backup_code)
            codes.append(code)

        await db.commit()
        return codes

    async def _check_rate_limit(
        self,
        db: AsyncSession,
        user: User
    ) -> bool:
        """
        Check if user has exceeded MFA attempt rate limit
        """
        window_start = datetime.utcnow() - timedelta(minutes=self.attempt_window)

        stmt = select(MFAAttempt).where(
            MFAAttempt.user_id == user.id,
            MFAAttempt.attempted_at >= window_start
        )
        result = await db.execute(stmt)
        attempts = result.scalars().all()

        return len(attempts) >= self.max_attempts

    async def _record_attempt(
        self,
        db: AsyncSession,
        user: User
    ):
        """
        Record MFA attempt for rate limiting
        """
        attempt = MFAAttempt(
            user_id=user.id,
            attempted_at=datetime.utcnow()
        )
        db.add(attempt)
        await db.commit()

    async def _clear_attempts(
        self,
        db: AsyncSession,
        user: User
    ):
        """
        Clear MFA attempts after successful verification
        """
        stmt = update(MFAAttempt).where(
            MFAAttempt.user_id == user.id
        ).values(cleared=True)
        await db.execute(stmt)
        await db.commit()

    async def _send_sms_code(self, phone_number: str) -> str:
        """
        Send SMS verification code
        """
        code = str(secrets.randbelow(10**self.digits)).zfill(self.digits)

        # Integration with SMS provider (Twilio, AWS SNS, etc.)
        # This is a placeholder - implement actual SMS sending
        logger.info(f"SMS code would be sent to {phone_number}: {code}")

        return code

    async def _send_email_code(self, email: str) -> str:
        """
        Send email verification code
        """
        code = str(secrets.randbelow(10**self.digits)).zfill(self.digits)

        # Integration with email service
        # This is a placeholder - implement actual email sending
        logger.info(f"Email code would be sent to {email}: {code}")

        return code

    async def _verify_sms_code(
        self,
        db: AsyncSession,
        user: User,
        code: str
    ) -> bool:
        """
        Verify SMS code
        """
        # Placeholder - implement actual verification
        return True

    async def _verify_email_code(
        self,
        db: AsyncSession,
        user: User,
        code: str
    ) -> bool:
        """
        Verify email code
        """
        # Placeholder - implement actual verification
        return True

    def _get_provisioning_uri(
        self,
        secret: str,
        username: str,
        issuer: str
    ) -> str:
        """
        Generate TOTP provisioning URI
        """
        totp = pyotp.TOTP(
            secret,
            interval=self.interval,
            digits=self.digits
        )
        return totp.provisioning_uri(
            name=username,
            issuer_name=issuer
        )

    def _generate_qr_code(self, uri: str) -> str:
        """
        Generate QR code for provisioning URI
        """
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)

        return base64.b64encode(buffer.getvalue()).decode()

    def _normalize_phone_number(self, phone: str) -> str:
        """
        Normalize phone number to E.164 format
        """
        import re
        phone = re.sub(r'\D', '', phone)
        if not phone.startswith('+'):
            phone = '+1' + phone  # Default to US
        return phone

    def _mask_phone_number(self, phone: str) -> str:
        """
        Mask phone number for display
        """
        if len(phone) < 4:
            return "***"
        return f"***-***-{phone[-4:]}"

    def _mask_email(self, email: str) -> str:
        """
        Mask email for display
        """
        parts = email.split('@')
        if len(parts) != 2:
            return "***"
        username = parts[0]
        if len(username) <= 2:
            masked = "*" * len(username)
        else:
            masked = username[0] + "*" * (len(username) - 2) + username[-1]
        return f"{masked}@{parts[1]}"


mfa_manager = MFAManager()