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
    print("✓ Core module imports successful")
except ImportError as e:
    print(f"✗ Import failed: {e}")
    sys.exit(1)

# Test 2: Basic encryption
try:
    enc = EncryptionManager()
    test_string = "CatNet Test"
    encrypted = enc.encrypt_string(test_string)
    decrypted = enc.decrypt_string(encrypted)
    assert decrypted == test_string
    print("✓ Encryption/Decryption works")
except Exception as e:
    print(f"✗ Encryption test failed: {e}")
    sys.exit(1)

# Test 3: Password hashing
try:
    password = "TestPassword123!"
    hashed = EncryptionManager.hash_password(password)
    assert EncryptionManager.verify_password(password, hashed)
    assert not EncryptionManager.verify_password("WrongPassword", hashed)
    print("✓ Password hashing works")
except Exception as e:
    print(f"✗ Password test failed: {e}")
    sys.exit(1)

# Test 4: Validator
try:
    from src.core.validators import ValidationResult
    result = ValidationResult()
    assert result.is_valid == True
    result.add_error("Test error")
    assert result.is_valid == False
    assert len(result.errors) == 1
    print("✓ Validation system works")
except Exception as e:
    print(f"✗ Validator test failed: {e}")
    sys.exit(1)

# Test 5: Check project structure
import os
required_dirs = [
    "src/api", "src/auth", "src/core", "src/db", 
    "src/deployment", "src/devices", "src/gitops", "src/security"
]
missing_dirs = [d for d in required_dirs if not os.path.isdir(d)]
if missing_dirs:
    print(f"✗ Missing directories: {missing_dirs}")
    sys.exit(1)
else:
    print("✓ Project structure complete")

print("\n" + "="*50)
print("✅ CatNet CI/CD Basic Tests PASSED!")
print("="*50)
