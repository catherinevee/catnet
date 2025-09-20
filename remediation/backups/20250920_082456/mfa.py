"""
Multi-Factor Authentication (MFA) Provider for CatNet

Implements TOTP (Time-based One-Time Password) authentication
compatible with Google Authenticator, Authy, and other TOTP apps.

import pyotp
import qrcode
import io
import base64
import secrets
from typing import Optional, Dict, List, Tuple


class MFAProvider:
    Provides MFA functionality using TOTP algorithm

    def __init__(
        self,
            issuer_name: str = "CatNet",
            period: int = 30,
            digits: int = 6,
            algorithm: str = "SHA1",
    ):
        Initialize MFA provider
    Args:
            issuer_name: Name shown in authenticator apps
                period: Time period for TOTP in seconds (default 30)
                digits: Number of digits in TOTP code (default 6)
                algorithm: Hash algorithm (SHA1, SHA256, SHA512)
        self.issuer_name = issuer_name
        self.period = period
        self.digits = digits
        self.algorithm = algorithm

        # In production, these would be stored in a database
        self.user_secrets = {}  # user_id -> secret mapping
        self.backup_codes = {}  # user_id -> list of backup codes
        self.used_backup_codes = {}  # Track used backup codes

    def enable_mfa(self, user_id: str, username: str) -> Dict[str, any]:
        Enable MFA for a user
    Args:
            user_id: Unique user identifier
                username: Username for display
    Returns:
            Dict containing secret, QR code, and backup codes
        # Generate secret
        secret = pyotp.random_base32()
        self.user_secrets[user_id] = secret

        # Generate backup codes
        backup_codes = self._generate_backup_codes(user_id)

        # Generate provisioning URI for QR code
        totp = pyotp.TOTP(
            secret, issuer_name=self.issuer_name, period=self.period,
            digits=self.digits
        )
        provisioning_uri = totp.provisioning_uri(
            name=username, issuer_name=self.issuer_name
        )

        # Generate QR code
        qr_code_data = self._generate_qr_code(provisioning_uri)

        return {
            "secret": secret,
            "qr_code": qr_code_data,
            "provisioning_uri": provisioning_uri,
            "backup_codes": backup_codes,
            "algorithm": self.algorithm,
            "digits": self.digits,
            "period": self.period,
        }

    def verify_totp(
        self, user_id: str, token: str, window: int = 1
    ) -> Tuple[bool, Optional[str]]:
        Verify a TOTP token
    Args:
            user_id: User identifier
                token: TOTP token to verify
                window: Number of time windows to check (for clock skew)
    Returns:
            Tuple of (is_valid, error_message)
        if user_id not in self.user_secrets:
            return False, "MFA not enabled for user"

        secret = self.user_secrets[user_id]
        totp = pyotp.TOTP(secret, period=self.period, digits=self.digits)

        # Verify with time window for clock skew tolerance
        is_valid = totp.verify(token, valid_window=window)

        if is_valid:
            return True, None
        else:
            # Check if it's a backup code
            if self._verify_backup_code(user_id, token):
                return True, "Backup code used"
            return False, "Invalid TOTP token"

    def disable_mfa(self, user_id: str) -> bool:
        Disable MFA for a user
    Args:
            user_id: User identifier
    Returns:
            Success status
        if user_id in self.user_secrets:
            del self.user_secrets[user_id]
        if user_id in self.backup_codes:
            del self.backup_codes[user_id]
        if user_id in self.used_backup_codes:
            del self.used_backup_codes[user_id]
        return True

    def regenerate_backup_codes(self, user_id: str) -> Optional[List[str]]:
        Generate new backup codes for a user
    Args:
            user_id: User identifier
    Returns:
            List of new backup codes or None if MFA not enabled
        if user_id not in self.user_secrets:
            return None

        # Clear old codes
        if user_id in self.used_backup_codes:
            del self.used_backup_codes[user_id]

        # Generate new codes
        return self._generate_backup_codes(user_id)

    def get_recovery_codes_status(self, user_id: str) -> Dict[str, any]:
        Get status of user's recovery codes
    Args:
            user_id: User identifier
    Returns:
            Dict with recovery codes status
        if user_id not in self.backup_codes:
            return {"enabled": False}

        total_codes = len(self.backup_codes.get(user_id, []))
        used_codes = len(self.used_backup_codes.get(user_id, []))

        return {
            "enabled": True,
            "total_codes": total_codes,
            "used_codes": used_codes,
            "remaining_codes": total_codes - used_codes,
        }

        def _generate_backup_codes(
            self,
                user_id: str,
                count: int = 10
        ) -> List[str]:
        Generate backup codes for account recovery
    Args:
            user_id: User identifier
                count: Number of backup codes to generate
    Returns:
            List of backup codes
        codes = []
        for _ in range(count):
            # Generate cryptographically secure backup code
            code = secrets.token_hex(4).upper()  # 8 character hex code
            formatted_code = f"{code[:4]}-{code[4:]}"  # Format as XXXX-XXXX
            codes.append(formatted_code)

        self.backup_codes[user_id] = codes
        self.used_backup_codes[user_id] = []
        return codes

    def _verify_backup_code(self, user_id: str, code: str) -> bool:
        Verify and consume a backup code
    Args:
            user_id: User identifier
                code: Backup code to verify
    Returns:
            Verification status
        if user_id not in self.backup_codes:
            return False

        # Normalize code format
        code = code.upper().replace("-", "").replace(" ", "")
        formatted_code = f"{code[:4]}-{code[4:]}" if len(code) == 8 else code

        # Check if code exists and hasn't been used
        if formatted_code in self.backup_codes[user_id]:
            if formatted_code not in self.used_backup_codes.get(user_id, []):
                # Mark code as used
                if user_id not in self.used_backup_codes:
                    self.used_backup_codes[user_id] = []
                self.used_backup_codes[user_id].append(formatted_code)
                return True

        return False

    def _generate_qr_code(self, data: str) -> str:
        Generate QR code as base64 encoded PNG
    Args:
            data: Data to encode in QR code
    Returns:
            Base64 encoded PNG image
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(data)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)

        return base64.b64encode(buffer.getvalue()).decode()


# Convenience functions
_default_provider = None


def get_mfa_provider() -> MFAProvider:
    """Get default MFA provider instance"""
    global _default_provider
    if _default_provider is None:
        _default_provider = MFAProvider()
    return _default_provider


def generate_totp_secret() -> str:
    Generate a new TOTP secret
    Returns:
        Base32 encoded secret
    return pyotp.random_base32()


def verify_totp_token(
        user_id: str, token: str, secret: Optional[str] = None
) -> Tuple[bool, Optional[str]]:
    Verify a TOTP token
    Args:
        user_id: User identifier
            token: TOTP token to verify
            secret: Optional secret (if not using stored secret)
    Returns:
        Tuple of (is_valid, error_message)
    if secret:
        # Direct verification with provided secret
        totp = pyotp.TOTP(secret)
        is_valid = totp.verify(token, valid_window=1)
        return is_valid, None if is_valid else "Invalid token"
    else:
        # Use stored secret via provider
        provider = get_mfa_provider()
        return provider.verify_totp(user_id, token)
