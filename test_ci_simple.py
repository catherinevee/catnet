import sys
import os
sys.path.insert(0, os.path.abspath('.'))

print("Testing CatNet CI/CD readiness...")

# Test 1: Core imports
try:
    from src.security.encryption import EncryptionManager
    from src.security.audit import AuditLogger
    from src.core.validators import ConfigValidator
    from src.core.exceptions import CatNetError
    print("[PASS] Core module imports successful")
except ImportError as e:
    print(f"[FAIL] Import failed: {e}")
    sys.exit(1)

# Test 2: Basic encryption
try:
    enc = EncryptionManager()
    test_string = "CatNet Test"
    encrypted = enc.encrypt_string(test_string)
    decrypted = enc.decrypt_string(encrypted)
    assert decrypted == test_string
    print("[PASS] Encryption/Decryption works")
except Exception as e:
    print(f"[FAIL] Encryption test failed: {e}")
    sys.exit(1)

# Test 3: Password hashing
try:
    password = "TestPassword123!"
    hashed = EncryptionManager.hash_password(password)
    assert EncryptionManager.verify_password(password, hashed)
    assert not EncryptionManager.verify_password("WrongPassword", hashed)
    print("[PASS] Password hashing works")
except Exception as e:
    print(f"[FAIL] Password test failed: {e}")
    sys.exit(1)

print("\n" + "="*50)
print("SUCCESS: CatNet CI/CD Basic Tests PASSED!")
print("="*50)
sys.exit(0)
