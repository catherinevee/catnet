"""
Multi-Factor Authentication (MFA) Enhancement
TOTP-based MFA with backup codes and device management
"""
import pyotp
import qrcode
import io
import base64
import secrets
import structlog
from typing import Optional, Tuple, List
from datetime import datetime
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from cryptography.fernet import Fernet

from ..db.models.security_audit import MFADevice
from ..db.models.user import User
from ..core.config import settings

logger = structlog.get_logger()


class MFAManager:
    """
    Multi-Factor Authentication Manager

    Handles TOTP-based MFA, backup codes, and device management
    """

    def __init__(self):
        # Initialize encryption key (should be from settings in production)
        self.encryption_key = getattr(settings, 'mfa_encryption_key', Fernet.generate_key())
        self.cipher = Fernet(self.encryption_key)

    def _encrypt(self, data: str) -> str:
        """Encrypt sensitive data"""
        return self.cipher.encrypt(data.encode()).decode()

    def _decrypt(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        return self.cipher.decrypt(encrypted_data.encode()).decode()

    async def setup_totp(
        self,
        user: User,
        device_name: str,
        db: AsyncSession
    ) -> Tuple[str, str, str]:
        """Setup TOTP for user"""
        logger.info("Setting up TOTP MFA", user_id=user.id, device_name=device_name)
        secret = pyotp.random_base32()
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="CatNet")
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        qr_code_data_uri = f"data:image/png;base64,{img_str}"
        encrypted_secret = self._encrypt(secret)
        mfa_device = MFADevice(user_id=user.id, device_name=device_name, device_type="totp", secret_key_encrypted=encrypted_secret, verified=False)
        db.add(mfa_device)
        await db.commit()
        await db.refresh(mfa_device)
        return str(mfa_device.id), secret, qr_code_data_uri

    async def verify_totp_token(self, user_id: str, token: str, db: AsyncSession) -> bool:
        """Verify TOTP token"""
        result = await db.execute(select(MFADevice).filter(MFADevice.user_id == user_id, MFADevice.device_type == "totp", MFADevice.verified == True, MFADevice.enabled == True))
        devices = result.scalars().all()
        if not devices:
            return False
        for device in devices:
            secret = self._decrypt(device.secret_key_encrypted)
            totp = pyotp.TOTP(secret)
            if totp.verify(token, valid_window=1):
                device.last_used_at = datetime.utcnow()
                device.usage_count += 1
                await db.commit()
                return True
        return False

    async def generate_backup_codes(self, user: User, db: AsyncSession, count: int = 10) -> List[str]:
        """Generate backup codes"""
        backup_codes = []
        encrypted_codes = []
        for _ in range(count):
            code = ''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(8))
            formatted_code = f"{code[:4]}-{code[4:]}"
            backup_codes.append(formatted_code)
            encrypted_codes.append(self._encrypt(formatted_code))
        backup_device = MFADevice(user_id=user.id, device_name="Backup Codes", device_type="backup_codes", backup_codes_encrypted=encrypted_codes, verified=True, verified_at=datetime.utcnow())
        db.add(backup_device)
        await db.commit()
        return backup_codes

    async def has_mfa_enabled(self, user_id: str, db: AsyncSession) -> bool:
        """Check if user has MFA enabled"""
        result = await db.execute(select(MFADevice).filter(MFADevice.user_id == user_id, MFADevice.verified == True, MFADevice.enabled == True))
        devices = result.scalars().all()
        return len(devices) > 0


# Singleton instance
mfa_manager = MFAManager()
