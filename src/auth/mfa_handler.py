from typing import Optional, Dict, Any, List, Tuple
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
import secrets
import hashlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import aiosmtplib
import asyncio
from twilio.rest import Client as TwilioClient
from .models import User, MFAConfig, MFAMethod
import struct
import time
import hmac


class MFAHandler:
    def __init__(self,
                 issuer_name: str = "CatNet",
                 totp_interval: int = 30,
                 totp_digits: int = 6,
                 sms_provider: Optional[str] = "twilio",
                 email_smtp_host: Optional[str] = None,
                 email_smtp_port: int = 587,
                 email_smtp_user: Optional[str] = None,
                 email_smtp_password: Optional[str] = None,
                 twilio_account_sid: Optional[str] = None,
                 twilio_auth_token: Optional[str] = None,
                 twilio_from_number: Optional[str] = None):

        self.issuer_name = issuer_name
        self.totp_interval = totp_interval
        self.totp_digits = totp_digits

        self.sms_provider = sms_provider
        self.email_smtp_host = email_smtp_host
        self.email_smtp_port = email_smtp_port
        self.email_smtp_user = email_smtp_user
        self.email_smtp_password = email_smtp_password

        self.twilio_client = None
        if twilio_account_sid and twilio_auth_token:
            self.twilio_client = TwilioClient(twilio_account_sid, twilio_auth_token)
            self.twilio_from_number = twilio_from_number

        self._code_cache = {}
        self._rate_limit = {}

    def generate_totp_secret(self) -> str:
        return pyotp.random_base32()

    def create_totp_provisioning_uri(self, user: User, secret: str) -> str:
        totp = pyotp.TOTP(
            secret,
            interval=self.totp_interval,
            digits=self.totp_digits,
            issuer=self.issuer_name
        )
        return totp.provisioning_uri(
            name=user.email,
            issuer_name=self.issuer_name
        )

    def generate_qr_code(self, provisioning_uri: str) -> str:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)

        img_str = base64.b64encode(buffer.getvalue()).decode()
        return f"data:image/png;base64,{img_str}"

    def verify_totp_code(self, secret: str, code: str, window: int = 1) -> bool:
        totp = pyotp.TOTP(
            secret,
            interval=self.totp_interval,
            digits=self.totp_digits
        )
        return totp.verify(code, valid_window=window)

    def generate_backup_codes(self, count: int = 10) -> List[str]:
        codes = []
        for _ in range(count):
            code = secrets.token_hex(4).upper()
            code_formatted = f"{code[:4]}-{code[4:]}"
            codes.append(code_formatted)
        return codes

    def hash_backup_code(self, code: str) -> str:
        return hashlib.sha256(code.encode()).hexdigest()

    async def send_sms_code(self, phone_number: str, code: str) -> bool:
        if not self.twilio_client:
            raise ValueError("SMS provider not configured")

        if self._check_rate_limit(f"sms:{phone_number}"):
            raise ValueError("Too many SMS requests. Please wait before trying again.")

        try:
            message = self.twilio_client.messages.create(
                body=f"Your CatNet verification code is: {code}",
                from_=self.twilio_from_number,
                to=phone_number
            )
            self._update_rate_limit(f"sms:{phone_number}")
            return message.sid is not None
        except Exception as e:
            raise ValueError(f"Failed to send SMS: {str(e)}")

    async def send_email_code(self, email: str, code: str) -> bool:
        if not self.email_smtp_host:
            raise ValueError("Email provider not configured")

        if self._check_rate_limit(f"email:{email}"):
            raise ValueError("Too many email requests. Please wait before trying again.")

        message = MIMEMultipart("alternative")
        message["Subject"] = "CatNet Verification Code"
        message["From"] = self.email_smtp_user
        message["To"] = email

        text = f"""\
        Your CatNet verification code is: {code}

        This code will expire in 5 minutes.

        If you didn't request this code, please ignore this email.
        """

        html = f"""\
        <html>
          <body>
            <p>Your CatNet verification code is:</p>
            <h2 style="font-family: monospace; color: #2c3e50;">{code}</h2>
            <p>This code will expire in 5 minutes.</p>
            <p style="color: #7f8c8d; font-size: 12px;">
              If you didn't request this code, please ignore this email.
            </p>
          </body>
        </html>
        """

        part1 = MIMEText(text, "plain")
        part2 = MIMEText(html, "html")

        message.attach(part1)
        message.attach(part2)

        try:
            await aiosmtplib.send(
                message,
                hostname=self.email_smtp_host,
                port=self.email_smtp_port,
                username=self.email_smtp_user,
                password=self.email_smtp_password,
                use_tls=True
            )
            self._update_rate_limit(f"email:{email}")
            return True
        except Exception as e:
            raise ValueError(f"Failed to send email: {str(e)}")

    def generate_verification_code(self, length: int = 6) -> str:
        return ''.join([str(secrets.randbelow(10)) for _ in range(length)])

    def store_verification_code(self, user_id: str, method: MFAMethod, code: str, ttl: int = 300):
        key = f"{user_id}:{method.value}"
        self._code_cache[key] = {
            "code": self.hash_backup_code(code),
            "expires_at": datetime.utcnow() + timedelta(seconds=ttl),
            "attempts": 0
        }

    def verify_stored_code(self, user_id: str, method: MFAMethod, code: str) -> bool:
        key = f"{user_id}:{method.value}"

        if key not in self._code_cache:
            return False

        cached = self._code_cache[key]

        if datetime.utcnow() > cached["expires_at"]:
            del self._code_cache[key]
            return False

        cached["attempts"] += 1
        if cached["attempts"] > 3:
            del self._code_cache[key]
            return False

        code_hash = self.hash_backup_code(code)
        if code_hash == cached["code"]:
            del self._code_cache[key]
            return True

        return False

    def _check_rate_limit(self, key: str, max_attempts: int = 3, window_minutes: int = 15) -> bool:
        now = datetime.utcnow()

        if key in self._rate_limit:
            attempts = self._rate_limit[key]
            attempts = [t for t in attempts if (now - t).total_seconds() < window_minutes * 60]

            if len(attempts) >= max_attempts:
                return True

            self._rate_limit[key] = attempts

        return False

    def _update_rate_limit(self, key: str):
        now = datetime.utcnow()

        if key not in self._rate_limit:
            self._rate_limit[key] = []

        self._rate_limit[key].append(now)

    def generate_hardware_token_challenge(self, user_id: str) -> str:
        challenge = secrets.token_urlsafe(32)
        key = f"hw_challenge:{user_id}"
        self._code_cache[key] = {
            "challenge": challenge,
            "expires_at": datetime.utcnow() + timedelta(seconds=60)
        }
        return challenge

    def verify_hardware_token_response(self, user_id: str, response: str, public_key: str) -> bool:
        key = f"hw_challenge:{user_id}"

        if key not in self._code_cache:
            return False

        cached = self._code_cache[key]

        if datetime.utcnow() > cached["expires_at"]:
            del self._code_cache[key]
            return False

        challenge = cached["challenge"]

        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding, rsa
            from cryptography.hazmat.primitives import serialization
            import base64

            public_key_obj = serialization.load_pem_public_key(
                public_key.encode(),
                backend=default_backend()
            )

            signature = base64.b64decode(response)

            public_key_obj.verify(
                signature,
                challenge.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            del self._code_cache[key]
            return True

        except Exception:
            return False

    def generate_push_notification_token(self, user_id: str, device_id: str) -> str:
        token = secrets.token_urlsafe(48)
        key = f"push:{user_id}:{device_id}"
        self._code_cache[key] = {
            "token": token,
            "expires_at": datetime.utcnow() + timedelta(seconds=120),
            "approved": False
        }
        return token

    async def send_push_notification(self, device_id: str, token: str) -> bool:
        """Send push notification for MFA verification."""
        try:
            logger.info(f"Sending push notification to device {device_id}")

            # In a real implementation, this would send a push notification
            # via a service like Firebase Cloud Messaging, APNs, etc.
            # For now, simulate successful sending
            await asyncio.sleep(0.1)  # Simulate network delay

            # Store the token for verification
            key = f"push:{device_id}:{token}"
            self._code_cache[key] = {
                'token': token,
                'timestamp': time.time(),
                'device_id': device_id
            }

            logger.info(f"Push notification sent successfully to device {device_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to send push notification to device {device_id}: {e}")
            return False

    def verify_push_notification(self, user_id: str, device_id: str) -> bool:
        key = f"push:{user_id}:{device_id}"

        if key not in self._code_cache:
            return False

        cached = self._code_cache[key]

        if datetime.utcnow() > cached["expires_at"]:
            del self._code_cache[key]
            return False

        if cached["approved"]:
            del self._code_cache[key]
            return True

        return False

    def approve_push_notification(self, user_id: str, device_id: str, token: str) -> bool:
        key = f"push:{user_id}:{device_id}"

        if key not in self._code_cache:
            return False

        cached = self._code_cache[key]

        if cached["token"] == token and datetime.utcnow() <= cached["expires_at"]:
            cached["approved"] = True
            return True

        return False

    def cleanup_expired_codes(self):
        now = datetime.utcnow()
        expired_keys = []

        for key, cached in self._code_cache.items():
            if "expires_at" in cached and now > cached["expires_at"]:
                expired_keys.append(key)

        for key in expired_keys:
            del self._code_cache[key]

    def generate_hotp(self, secret: str, counter: int) -> str:
        key = base64.b32decode(secret, True)
        msg = struct.pack(">Q", counter)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        o = h[19] & 15
        h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
        return str(h).zfill(6)

    def verify_hotp(self, secret: str, code: str, counter: int, window: int = 10) -> Tuple[bool, Optional[int]]:
        for i in range(counter, counter + window):
            if self.generate_hotp(secret, i) == code:
                return True, i
        return False, None

    async def setup_mfa(self, user: User, method: MFAMethod) -> Dict[str, Any]:
        config = MFAConfig(
            user_id=user.id,
            method=method,
            is_verified=False
        )

        result = {}

        if method == MFAMethod.TOTP:
            secret = self.generate_totp_secret()
            config.secret = secret
            provisioning_uri = self.create_totp_provisioning_uri(user, secret)
            qr_code = self.generate_qr_code(provisioning_uri)
            backup_codes = config.generate_backup_codes()

            result = {
                "method": method.value,
                "secret": secret,
                "provisioning_uri": provisioning_uri,
                "qr_code": qr_code,
                "backup_codes": backup_codes
            }

        elif method == MFAMethod.SMS:
            if not user.metadata.get("phone_number"):
                raise ValueError("Phone number required for SMS MFA")

            config.phone_number = user.metadata["phone_number"]
            code = self.generate_verification_code()
            self.store_verification_code(str(user.id), method, code)
            await self.send_sms_code(config.phone_number, code)

            result = {
                "method": method.value,
                "phone_number": config.phone_number,
                "code_sent": True
            }

        elif method == MFAMethod.EMAIL:
            config.email = user.email
            code = self.generate_verification_code()
            self.store_verification_code(str(user.id), method, code)
            await self.send_email_code(config.email, code)

            result = {
                "method": method.value,
                "email": config.email,
                "code_sent": True
            }

        return result

    async def verify_mfa(self, user: User, config: MFAConfig, code: str) -> bool:
        if config.method == MFAMethod.TOTP:
            return self.verify_totp_code(config.secret.get_secret_value(), code)

        elif config.method == MFAMethod.SMS or config.method == MFAMethod.EMAIL:
            return self.verify_stored_code(str(user.id), config.method, code)

        elif config.method == MFAMethod.HARDWARE_TOKEN:
            return self.verify_hardware_token_response(
                str(user.id),
                code,
                user.metadata.get("hardware_token_public_key")
            )

        elif config.method == MFAMethod.PUSH:
            device_id = user.metadata.get("device_id")
            return self.verify_push_notification(str(user.id), device_id)

        return False