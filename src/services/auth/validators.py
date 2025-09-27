"""
Input validators for authentication service.
"""

import re
import ipaddress
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import hashlib

from src.core.logging import get_logger

logger = get_logger(__name__)


class LoginValidator:
    """Validates login requests."""

    # Password complexity requirements
    MIN_PASSWORD_LENGTH = 12
    PASSWORD_REGEX = re.compile(
        r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]'
    )

    # Username requirements
    USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_.-]{3,50}$')
    EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

    # Blacklisted passwords
    COMMON_PASSWORDS = {
        'password', 'Password1!', 'Admin123!', 'Welcome123!',
        'P@ssw0rd', 'Passw0rd!', 'Password123!', 'Admin@123'
    }

    def __init__(self):
        self.failed_attempts = {}
        self.blocked_ips = set()
        self.blocked_users = set()

    async def validate(self, username: str, password: str, ip_address: Optional[str] = None) -> bool:
        """
        Validate login credentials.

        Args:
            username: Username or email
            password: Password
            ip_address: Client IP address

        Returns:
            True if valid, False otherwise
        """
        try:
            # Check if IP is blocked
            if ip_address and ip_address in self.blocked_ips:
                logger.warning(f"Blocked IP attempted login: {ip_address}")
                return False

            # Check if user is blocked
            if username in self.blocked_users:
                logger.warning(f"Blocked user attempted login: {username}")
                return False

            # Validate username format
            if not self._validate_username(username):
                logger.warning(f"Invalid username format: {username}")
                return False

            # Validate password format
            if not self._validate_password(password):
                logger.warning(f"Invalid password format for user: {username}")
                return False

            # Check for SQL injection patterns
            if self._contains_sql_injection(username) or self._contains_sql_injection(password):
                logger.error(f"SQL injection attempt detected from {ip_address}")
                if ip_address:
                    self.blocked_ips.add(ip_address)
                return False

            # Check for LDAP injection patterns
            if self._contains_ldap_injection(username) or self._contains_ldap_injection(password):
                logger.error(f"LDAP injection attempt detected from {ip_address}")
                if ip_address:
                    self.blocked_ips.add(ip_address)
                return False

            return True

        except Exception as e:
            logger.error(f"Login validation error: {e}")
            return False

    def _validate_username(self, username: str) -> bool:
        """Validate username format."""
        if not username or len(username) < 3 or len(username) > 50:
            return False

        # Check if it's an email
        if '@' in username:
            return bool(self.EMAIL_REGEX.match(username))

        # Check username format
        return bool(self.USERNAME_REGEX.match(username))

    def _validate_password(self, password: str) -> bool:
        """Validate password strength."""
        if not password or len(password) < self.MIN_PASSWORD_LENGTH:
            return False

        # Check against common passwords
        if password in self.COMMON_PASSWORDS:
            return False

        # Check complexity requirements
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '@$!%*?&#^()_+-=[]{}|;:,.<>?' for c in password)

        if not (has_lower and has_upper and has_digit and has_special):
            return False

        # Check for sequential characters
        if self._has_sequential_chars(password):
            return False

        # Check for repeated characters
        if self._has_excessive_repeats(password):
            return False

        return True

    def _has_sequential_chars(self, password: str, max_sequence: int = 3) -> bool:
        """Check for sequential characters."""
        for i in range(len(password) - max_sequence + 1):
            seq = password[i:i + max_sequence]
            # Check alphabetical sequence
            if seq.isalpha() and all(
                ord(seq[j]) == ord(seq[j-1]) + 1
                for j in range(1, len(seq))
            ):
                return True
            # Check numerical sequence
            if seq.isdigit() and all(
                int(seq[j]) == int(seq[j-1]) + 1
                for j in range(1, len(seq))
            ):
                return True
        return False

    def _has_excessive_repeats(self, password: str, max_repeat: int = 3) -> bool:
        """Check for excessive character repetition."""
        for i in range(len(password) - max_repeat + 1):
            if password[i:i + max_repeat] == password[i] * max_repeat:
                return True
        return False

    def _contains_sql_injection(self, value: str) -> bool:
        """Check for SQL injection patterns."""
        sql_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|CREATE|ALTER)\b)",
            r"(--|#|/\*|\*/)",
            r"(\bOR\b\s*\d+\s*=\s*\d+)",
            r"(\bAND\b\s*\d+\s*=\s*\d+)",
            r"(';|';--|';\s*--)",
            r"(\bEXEC\b|\bEXECUTE\b)",
            r"(\bxp_\w+)",
            r"(\bsp_\w+)",
        ]

        value_upper = value.upper()
        for pattern in sql_patterns:
            if re.search(pattern, value_upper):
                return True

        return False

    def _contains_ldap_injection(self, value: str) -> bool:
        """Check for LDAP injection patterns."""
        ldap_patterns = [
            r"[)(|\*\\]",
            r"(\(|\))\s*(\(|\))",
            r"\*\|",
            r"^\*",
            r"\*$",
        ]

        for pattern in ldap_patterns:
            if re.search(pattern, value):
                return True

        return False


class MFAValidator:
    """Validates MFA tokens and codes."""

    TOTP_CODE_LENGTH = 6
    SMS_CODE_LENGTH = 6
    EMAIL_CODE_LENGTH = 6
    BACKUP_CODE_LENGTH = 8

    def __init__(self):
        self.used_codes = set()

    async def validate(self, code: str, method: str = "totp") -> bool:
        """
        Validate MFA code format.

        Args:
            code: MFA code
            method: MFA method

        Returns:
            True if valid format, False otherwise
        """
        try:
            if not code:
                return False

            # Check if code was already used
            code_hash = hashlib.sha256(f"{code}:{method}".encode()).hexdigest()
            if code_hash in self.used_codes:
                logger.warning("Attempted to reuse MFA code")
                return False

            # Validate based on method
            if method == "totp":
                valid = self._validate_totp_code(code)
            elif method == "sms":
                valid = self._validate_sms_code(code)
            elif method == "email":
                valid = self._validate_email_code(code)
            elif method == "backup":
                valid = self._validate_backup_code(code)
            else:
                logger.warning(f"Unknown MFA method: {method}")
                return False

            if valid:
                # Mark code as used
                self.used_codes.add(code_hash)
                # Clean up old codes (keep last 1000)
                if len(self.used_codes) > 1000:
                    self.used_codes = set(list(self.used_codes)[-1000:])

            return valid

        except Exception as e:
            logger.error(f"MFA validation error: {e}")
            return False

    def _validate_totp_code(self, code: str) -> bool:
        """Validate TOTP code format."""
        if len(code) != self.TOTP_CODE_LENGTH:
            return False

        if not code.isdigit():
            return False

        return True

    def _validate_sms_code(self, code: str) -> bool:
        """Validate SMS code format."""
        if len(code) != self.SMS_CODE_LENGTH:
            return False

        if not code.isdigit():
            return False

        return True

    def _validate_email_code(self, code: str) -> bool:
        """Validate email code format."""
        if len(code) != self.EMAIL_CODE_LENGTH:
            return False

        if not code.isdigit():
            return False

        return True

    def _validate_backup_code(self, code: str) -> bool:
        """Validate backup code format."""
        if len(code) != self.BACKUP_CODE_LENGTH:
            return False

        # Backup codes are typically alphanumeric
        if not code.isalnum():
            return False

        return True


class TokenValidator:
    """Validates tokens and sessions."""

    TOKEN_MIN_LENGTH = 32
    TOKEN_MAX_LENGTH = 512
    TOKEN_REGEX = re.compile(r'^[A-Za-z0-9_-]+$')

    def __init__(self):
        self.revoked_tokens = set()
        self.suspicious_patterns = []

    async def validate(self, token: str, token_type: str = "access") -> bool:
        """
        Validate token format and status.

        Args:
            token: Token string
            token_type: Type of token (access, refresh, id)

        Returns:
            True if valid, False otherwise
        """
        try:
            if not token:
                return False

            # Check length
            if len(token) < self.TOKEN_MIN_LENGTH or len(token) > self.TOKEN_MAX_LENGTH:
                logger.warning(f"Invalid token length: {len(token)}")
                return False

            # Check format
            if not self.TOKEN_REGEX.match(token):
                logger.warning("Invalid token format")
                return False

            # Check if revoked
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            if token_hash in self.revoked_tokens:
                logger.warning("Attempted to use revoked token")
                return False

            # Check for suspicious patterns
            if self._contains_suspicious_pattern(token):
                logger.warning("Token contains suspicious pattern")
                return False

            return True

        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return False

    def _contains_suspicious_pattern(self, token: str) -> bool:
        """Check for suspicious patterns in token."""
        suspicious = [
            r'<script',
            r'javascript:',
            r'onerror=',
            r'onclick=',
            r'<img',
            r'<iframe',
            r'eval\(',
            r'alert\(',
        ]

        token_lower = token.lower()
        for pattern in suspicious:
            if pattern in token_lower:
                return True

        return False

    async def revoke_token(self, token: str):
        """Mark token as revoked."""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        self.revoked_tokens.add(token_hash)

        # Clean up old revoked tokens (keep last 10000)
        if len(self.revoked_tokens) > 10000:
            self.revoked_tokens = set(list(self.revoked_tokens)[-10000:])


class SessionValidator:
    """Validates user sessions."""

    MAX_CONCURRENT_SESSIONS = 5
    SESSION_TIMEOUT_MINUTES = 60
    MAX_SESSION_DURATION_HOURS = 24

    def __init__(self):
        self.active_sessions = {}

    async def validate_session(
        self,
        session_id: str,
        user_id: str,
        ip_address: Optional[str] = None
    ) -> bool:
        """
        Validate user session.

        Args:
            session_id: Session ID
            user_id: User ID
            ip_address: Client IP address

        Returns:
            True if valid, False otherwise
        """
        try:
            # Check if session exists
            if session_id not in self.active_sessions:
                logger.warning(f"Unknown session: {session_id}")
                return False

            session = self.active_sessions[session_id]

            # Check user ID
            if session['user_id'] != user_id:
                logger.warning(f"Session user mismatch: {session_id}")
                return False

            # Check session timeout
            last_activity = session.get('last_activity')
            if last_activity:
                timeout = timedelta(minutes=self.SESSION_TIMEOUT_MINUTES)
                if datetime.utcnow() - last_activity > timeout:
                    logger.warning(f"Session timeout: {session_id}")
                    await self.invalidate_session(session_id)
                    return False

            # Check maximum session duration
            created_at = session.get('created_at')
            if created_at:
                max_duration = timedelta(hours=self.MAX_SESSION_DURATION_HOURS)
                if datetime.utcnow() - created_at > max_duration:
                    logger.warning(f"Session expired: {session_id}")
                    await self.invalidate_session(session_id)
                    return False

            # Check IP address if provided
            if ip_address and session.get('ip_address') != ip_address:
                logger.warning(f"Session IP mismatch: {session_id}")
                return False

            # Update last activity
            session['last_activity'] = datetime.utcnow()

            return True

        except Exception as e:
            logger.error(f"Session validation error: {e}")
            return False

    async def create_session(
        self,
        session_id: str,
        user_id: str,
        ip_address: Optional[str] = None
    ) -> bool:
        """Create new session."""
        try:
            # Check concurrent sessions
            user_sessions = [
                s for s in self.active_sessions.values()
                if s['user_id'] == user_id
            ]

            if len(user_sessions) >= self.MAX_CONCURRENT_SESSIONS:
                logger.warning(f"Max concurrent sessions reached for user: {user_id}")
                # Remove oldest session
                oldest = min(user_sessions, key=lambda s: s['created_at'])
                await self.invalidate_session(oldest['id'])

            # Create session
            self.active_sessions[session_id] = {
                'id': session_id,
                'user_id': user_id,
                'ip_address': ip_address,
                'created_at': datetime.utcnow(),
                'last_activity': datetime.utcnow()
            }

            return True

        except Exception as e:
            logger.error(f"Session creation error: {e}")
            return False

    async def invalidate_session(self, session_id: str):
        """Invalidate session."""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
            logger.info(f"Session invalidated: {session_id}")


class PasswordValidator:
    """Validates password requirements and history."""

    MIN_LENGTH = 12
    MAX_LENGTH = 128
    PASSWORD_HISTORY_SIZE = 10
    MIN_PASSWORD_AGE_DAYS = 1
    MAX_PASSWORD_AGE_DAYS = 90

    def __init__(self):
        self.password_history = {}

    async def validate_new_password(
        self,
        user_id: str,
        new_password: str,
        current_password: Optional[str] = None
    ) -> tuple[bool, Optional[str]]:
        """
        Validate new password against policy.

        Args:
            user_id: User ID
            new_password: New password
            current_password: Current password

        Returns:
            Tuple of (valid, error_message)
        """
        try:
            # Check length
            if len(new_password) < self.MIN_LENGTH:
                return False, f"Password must be at least {self.MIN_LENGTH} characters"

            if len(new_password) > self.MAX_LENGTH:
                return False, f"Password must not exceed {self.MAX_LENGTH} characters"

            # Check complexity
            validator = LoginValidator()
            if not validator._validate_password(new_password):
                return False, "Password does not meet complexity requirements"

            # Check if same as current
            if current_password and new_password == current_password:
                return False, "New password must be different from current password"

            # Check password history
            if not await self._check_password_history(user_id, new_password):
                return False, f"Password was recently used. Choose a different password"

            # Check for personal information
            if await self._contains_personal_info(user_id, new_password):
                return False, "Password must not contain personal information"

            return True, None

        except Exception as e:
            logger.error(f"Password validation error: {e}")
            return False, "Password validation failed"

    async def _check_password_history(self, user_id: str, password: str) -> bool:
        """Check if password was recently used."""
        if user_id not in self.password_history:
            self.password_history[user_id] = []

        # Hash password for comparison
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Check against history
        if password_hash in self.password_history[user_id]:
            return False

        return True

    async def _contains_personal_info(self, user_id: str, password: str) -> bool:
        """Check if password contains personal information."""
        # This would check against user's name, email, etc.
        # Placeholder implementation
        return False

    async def add_to_history(self, user_id: str, password: str):
        """Add password to history."""
        if user_id not in self.password_history:
            self.password_history[user_id] = []

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        self.password_history[user_id].append(password_hash)

        # Keep only last N passwords
        if len(self.password_history[user_id]) > self.PASSWORD_HISTORY_SIZE:
            self.password_history[user_id] = self.password_history[user_id][-self.PASSWORD_HISTORY_SIZE:]