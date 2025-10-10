"""
Unit tests for MFA Manager
Tests TOTP, SMS, Email, and backup code authentication
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime, timedelta
import pyotp
from uuid import uuid4

from src.auth.mfa import MFAManager, MFAType
from src.auth.models import User, MFAConfig, BackupCode


@pytest.fixture
def mfa_manager():
    """Provide an MFA manager instance for testing."""
    return MFAManager()


@pytest.fixture
def mock_user():
    """Provide a mock user for testing."""
    user = Mock(spec=User)
    user.id = uuid4()
    user.username = "testuser"
    user.email = "test@example.com"
    user.phone = "+1234567890"
    user.is_active = True
    return user


@pytest.fixture
def mock_mfa_config():
    """Provide a mock MFA configuration."""
    config = Mock(spec=MFAConfig)
    config.id = uuid4()
    config.user_id = uuid4()
    config.mfa_type = MFAType.TOTP
    config.secret = pyotp.random_base32()
    config.is_enabled = True
    config.verified_at = datetime.utcnow()
    return config


class TestTOTPGeneration:
    """Test TOTP secret generation and QR code creation."""

    def test_generate_totp_secret(self, mfa_manager, mock_user):
        """Test TOTP secret generation."""
        secret = mfa_manager.generate_totp_secret(mock_user.username)

        assert secret is not None
        assert isinstance(secret, str)
        assert len(secret) == 32  # Base32 secret

    def test_generate_qr_code(self, mfa_manager, mock_user):
        """Test QR code generation for TOTP setup."""
        secret = pyotp.random_base32()

        qr_code = mfa_manager.generate_qr_code(
            username=mock_user.username,
            secret=secret,
            issuer="CatNet"
        )

        assert qr_code is not None
        assert isinstance(qr_code, str)
        assert qr_code.startswith("data:image/png;base64,")

    def test_generate_provisioning_uri(self, mfa_manager, mock_user):
        """Test provisioning URI generation."""
        secret = pyotp.random_base32()

        uri = mfa_manager.generate_provisioning_uri(
            username=mock_user.username,
            secret=secret,
            issuer="CatNet"
        )

        assert uri.startswith("otpauth://totp/")
        assert mock_user.username in uri
        assert "CatNet" in uri
        assert secret in uri


class TestTOTPVerification:
    """Test TOTP code verification."""

    def test_verify_totp_code_success(self, mfa_manager):
        """Test successful TOTP code verification."""
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        current_code = totp.now()

        is_valid = mfa_manager.verify_totp_code(
            secret=secret,
            code=current_code
        )

        assert is_valid is True

    def test_verify_totp_code_invalid(self, mfa_manager):
        """Test TOTP verification fails with invalid code."""
        secret = pyotp.random_base32()
        invalid_code = "000000"

        is_valid = mfa_manager.verify_totp_code(
            secret=secret,
            code=invalid_code
        )

        assert is_valid is False

    def test_verify_totp_code_with_window(self, mfa_manager):
        """Test TOTP verification with time window."""
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)

        # Generate code from 30 seconds ago
        previous_code = totp.at(datetime.utcnow() - timedelta(seconds=30))

        # Should be valid with window=1
        is_valid = mfa_manager.verify_totp_code(
            secret=secret,
            code=previous_code,
            window=1
        )

        assert is_valid is True

    def test_verify_totp_code_empty_string(self, mfa_manager):
        """Test TOTP verification fails with empty code."""
        secret = pyotp.random_base32()

        is_valid = mfa_manager.verify_totp_code(
            secret=secret,
            code=""
        )

        assert is_valid is False

    def test_verify_totp_code_wrong_length(self, mfa_manager):
        """Test TOTP verification fails with wrong code length."""
        secret = pyotp.random_base32()

        is_valid = mfa_manager.verify_totp_code(
            secret=secret,
            code="12345"  # Only 5 digits
        )

        assert is_valid is False


class TestBackupCodes:
    """Test backup code generation and verification."""

    def test_generate_backup_codes(self, mfa_manager, mock_user):
        """Test backup code generation."""
        codes = mfa_manager.generate_backup_codes(count=10)

        assert codes is not None
        assert len(codes) == 10
        assert all(isinstance(code, str) for code in codes)
        assert all(len(code) == 8 for code in codes)
        assert len(codes) == len(set(codes))  # All unique

    def test_generate_backup_codes_custom_count(self, mfa_manager):
        """Test backup code generation with custom count."""
        codes = mfa_manager.generate_backup_codes(count=5)

        assert len(codes) == 5

    def test_hash_backup_code(self, mfa_manager):
        """Test backup code hashing."""
        code = "ABC12345"

        hashed = mfa_manager.hash_backup_code(code)

        assert hashed is not None
        assert isinstance(hashed, str)
        assert hashed != code  # Should be hashed
        assert len(hashed) > len(code)  # Hash is longer

    def test_verify_backup_code_success(self, mfa_manager):
        """Test successful backup code verification."""
        code = "ABC12345"
        hashed = mfa_manager.hash_backup_code(code)

        is_valid = mfa_manager.verify_backup_code(
            code=code,
            hashed_code=hashed
        )

        assert is_valid is True

    def test_verify_backup_code_invalid(self, mfa_manager):
        """Test backup code verification fails with invalid code."""
        code = "ABC12345"
        hashed = mfa_manager.hash_backup_code(code)

        is_valid = mfa_manager.verify_backup_code(
            code="WRONG123",
            hashed_code=hashed
        )

        assert is_valid is False

    def test_backup_code_case_insensitive(self, mfa_manager):
        """Test backup code verification is case-insensitive."""
        code = "ABC12345"
        hashed = mfa_manager.hash_backup_code(code)

        is_valid = mfa_manager.verify_backup_code(
            code="abc12345",  # Lowercase
            hashed_code=hashed
        )

        assert is_valid is True


class TestMFAEnrollment:
    """Test MFA enrollment process."""

    @pytest.mark.asyncio
    async def test_enroll_totp_success(self, mfa_manager, mock_user):
        """Test successful TOTP enrollment."""
        with patch.object(mfa_manager, '_save_mfa_config', new_callable=AsyncMock) as mock_save:
            mock_save.return_value = Mock(spec=MFAConfig)

            result = await mfa_manager.enroll_totp(
                user_id=mock_user.id,
                username=mock_user.username
            )

            assert result is not None
            assert "secret" in result
            assert "qr_code" in result
            assert "backup_codes" in result
            mock_save.assert_called_once()

    @pytest.mark.asyncio
    async def test_enroll_sms_success(self, mfa_manager, mock_user):
        """Test successful SMS MFA enrollment."""
        with patch.object(mfa_manager, '_save_mfa_config', new_callable=AsyncMock) as mock_save:
            with patch.object(mfa_manager, '_send_sms', new_callable=AsyncMock) as mock_sms:
                mock_save.return_value = Mock(spec=MFAConfig)
                mock_sms.return_value = True

                result = await mfa_manager.enroll_sms(
                    user_id=mock_user.id,
                    phone=mock_user.phone
                )

                assert result is not None
                mock_save.assert_called_once()

    @pytest.mark.asyncio
    async def test_enroll_email_success(self, mfa_manager, mock_user):
        """Test successful email MFA enrollment."""
        with patch.object(mfa_manager, '_save_mfa_config', new_callable=AsyncMock) as mock_save:
            with patch.object(mfa_manager, '_send_email', new_callable=AsyncMock) as mock_email:
                mock_save.return_value = Mock(spec=MFAConfig)
                mock_email.return_value = True

                result = await mfa_manager.enroll_email(
                    user_id=mock_user.id,
                    email=mock_user.email
                )

                assert result is not None
                mock_save.assert_called_once()


class TestMFAVerification:
    """Test MFA verification flow."""

    @pytest.mark.asyncio
    async def test_verify_mfa_totp_success(self, mfa_manager, mock_user, mock_mfa_config):
        """Test successful TOTP MFA verification."""
        totp = pyotp.TOTP(mock_mfa_config.secret)
        current_code = totp.now()

        with patch.object(mfa_manager, '_get_mfa_config', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_mfa_config

            is_valid = await mfa_manager.verify_mfa(
                user_id=mock_user.id,
                code=current_code,
                mfa_type=MFAType.TOTP
            )

            assert is_valid is True

    @pytest.mark.asyncio
    async def test_verify_mfa_invalid_code(self, mfa_manager, mock_user, mock_mfa_config):
        """Test MFA verification fails with invalid code."""
        with patch.object(mfa_manager, '_get_mfa_config', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_mfa_config

            is_valid = await mfa_manager.verify_mfa(
                user_id=mock_user.id,
                code="000000",
                mfa_type=MFAType.TOTP
            )

            assert is_valid is False

    @pytest.mark.asyncio
    async def test_verify_mfa_not_enrolled(self, mfa_manager, mock_user):
        """Test MFA verification fails when user not enrolled."""
        with patch.object(mfa_manager, '_get_mfa_config', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = None

            is_valid = await mfa_manager.verify_mfa(
                user_id=mock_user.id,
                code="123456",
                mfa_type=MFAType.TOTP
            )

            assert is_valid is False

    @pytest.mark.asyncio
    async def test_verify_mfa_disabled_config(self, mfa_manager, mock_user, mock_mfa_config):
        """Test MFA verification fails when config is disabled."""
        mock_mfa_config.is_enabled = False

        with patch.object(mfa_manager, '_get_mfa_config', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_mfa_config

            is_valid = await mfa_manager.verify_mfa(
                user_id=mock_user.id,
                code="123456",
                mfa_type=MFAType.TOTP
            )

            assert is_valid is False


class TestMFARateLimiting:
    """Test MFA rate limiting and attempt tracking."""

    @pytest.mark.asyncio
    async def test_track_failed_attempt(self, mfa_manager, mock_user):
        """Test failed MFA attempt tracking."""
        with patch.object(mfa_manager, '_record_attempt', new_callable=AsyncMock) as mock_record:
            await mfa_manager.track_failed_attempt(
                user_id=mock_user.id,
                mfa_type=MFAType.TOTP
            )

            mock_record.assert_called_once()

    @pytest.mark.asyncio
    async def test_check_rate_limit_not_exceeded(self, mfa_manager, mock_user):
        """Test rate limit check when not exceeded."""
        with patch.object(mfa_manager, '_get_recent_attempts', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = []  # No recent attempts

            is_allowed = await mfa_manager.check_rate_limit(
                user_id=mock_user.id
            )

            assert is_allowed is True

    @pytest.mark.asyncio
    async def test_check_rate_limit_exceeded(self, mfa_manager, mock_user):
        """Test rate limit check when exceeded."""
        # Mock 10 failed attempts in last minute
        mock_attempts = [Mock() for _ in range(10)]

        with patch.object(mfa_manager, '_get_recent_attempts', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_attempts

            is_allowed = await mfa_manager.check_rate_limit(
                user_id=mock_user.id,
                max_attempts=5
            )

            assert is_allowed is False


class TestMFADisabling:
    """Test MFA disabling and removal."""

    @pytest.mark.asyncio
    async def test_disable_mfa_success(self, mfa_manager, mock_user):
        """Test successful MFA disabling."""
        with patch.object(mfa_manager, '_disable_mfa_config', new_callable=AsyncMock) as mock_disable:
            mock_disable.return_value = True

            result = await mfa_manager.disable_mfa(
                user_id=mock_user.id,
                mfa_type=MFAType.TOTP
            )

            assert result is True
            mock_disable.assert_called_once()

    @pytest.mark.asyncio
    async def test_remove_all_mfa_methods(self, mfa_manager, mock_user):
        """Test removing all MFA methods for a user."""
        with patch.object(mfa_manager, '_remove_all_mfa', new_callable=AsyncMock) as mock_remove:
            mock_remove.return_value = True

            result = await mfa_manager.remove_all_mfa(
                user_id=mock_user.id
            )

            assert result is True
            mock_remove.assert_called_once()


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_verify_totp_with_none_secret(self, mfa_manager):
        """Test TOTP verification handles None secret gracefully."""
        with pytest.raises((ValueError, TypeError)):
            mfa_manager.verify_totp_code(
                secret=None,
                code="123456"
            )

    def test_generate_backup_codes_zero_count(self, mfa_manager):
        """Test backup code generation with zero count."""
        codes = mfa_manager.generate_backup_codes(count=0)

        assert codes == []

    def test_generate_backup_codes_negative_count(self, mfa_manager):
        """Test backup code generation with negative count."""
        with pytest.raises(ValueError):
            mfa_manager.generate_backup_codes(count=-5)

    @pytest.mark.asyncio
    async def test_verify_mfa_with_expired_config(self, mfa_manager, mock_user, mock_mfa_config):
        """Test MFA verification with expired configuration."""
        # Set config as expired (e.g., verified more than 90 days ago)
        mock_mfa_config.verified_at = datetime.utcnow() - timedelta(days=91)

        with patch.object(mfa_manager, '_get_mfa_config', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_mfa_config

            is_valid = await mfa_manager.verify_mfa(
                user_id=mock_user.id,
                code="123456",
                mfa_type=MFAType.TOTP,
                check_expiry=True
            )

            assert is_valid is False
