"""Unit tests for MFA"""
import pytest
import pyotp

from src.auth.mfa import mfa_manager


@pytest.mark.asyncio
async def test_setup_totp(db_session, test_user):
    """Test TOTP setup"""
    device_id, secret, qr_code = await mfa_manager.setup_totp(
        user=test_user,
        device_name="Test Authenticator",
        db=db_session
    )
    
    assert device_id is not None
    assert secret is not None
    assert qr_code.startswith("data:image/png;base64,")


@pytest.mark.asyncio
async def test_verify_totp_token(db_session, test_user):
    """Test TOTP token verification"""
    # Setup TOTP
    device_id, secret, _ = await mfa_manager.setup_totp(
        user=test_user,
        device_name="Test Authenticator",
        db=db_session
    )
    
    # Verify device
    totp = pyotp.TOTP(secret)
    token = totp.now()
    
    verified = await mfa_manager.verify_totp_setup(
        device_id=device_id,
        token=token,
        db=db_session
    )
    
    assert verified is True


@pytest.mark.asyncio
async def test_generate_backup_codes(db_session, test_user):
    """Test backup code generation"""
    codes = await mfa_manager.generate_backup_codes(
        user=test_user,
        db=db_session,
        count=10
    )
    
    assert len(codes) == 10
    assert all("-" in code for code in codes)
    assert all(len(code) == 9 for code in codes)  # XXXX-XXXX format


@pytest.mark.asyncio
async def test_verify_backup_code(db_session, test_user):
    """Test backup code verification"""
    # Generate codes
    codes = await mfa_manager.generate_backup_codes(
        user=test_user,
        db=db_session,
        count=5
    )
    
    # Verify first code
    verified = await mfa_manager.verify_backup_code(
        user_id=str(test_user.id),
        code=codes[0],
        db=db_session
    )
    
    assert verified is True
    
    # Try to use same code again (should fail)
    verified_again = await mfa_manager.verify_backup_code(
        user_id=str(test_user.id),
        code=codes[0],
        db=db_session
    )
    
    assert verified_again is False


@pytest.mark.asyncio
async def test_has_mfa_enabled(db_session, test_user):
    """Test checking if MFA is enabled"""
    # Initially no MFA
    has_mfa = await mfa_manager.has_mfa_enabled(
        user_id=str(test_user.id),
        db=db_session
    )
    assert has_mfa is False
    
    # Setup TOTP
    device_id, secret, _ = await mfa_manager.setup_totp(
        user=test_user,
        device_name="Test",
        db=db_session
    )
    
    # Verify device
    totp = pyotp.TOTP(secret)
    await mfa_manager.verify_totp_setup(device_id, totp.now(), db_session)
    
    # Now should have MFA
    has_mfa = await mfa_manager.has_mfa_enabled(
        user_id=str(test_user.id),
        db=db_session
    )
    assert has_mfa is True
