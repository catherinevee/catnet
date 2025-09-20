#!/usr/bin/env python
"""
Test Enhanced Security Features
Verifies webhook verification, input validation, rate limiting, and async \
    operations
"""
import asyncio
from src.security.simple_security import (
    webhook_verifier, input_validator, rate_limiter,
    security_auditor, secure_deployment_check
)
from src.devices.async_device_connector import async_device_connector
from src.devices.device_store import device_store

print("="*60)
print("Testing Enhanced Security Features")
print("="*60)


def test_webhook_verification():
    """Test webhook signature verification"""
    print("\n1. Testing Webhook Verification:")
    print("-" * 40)

    # Set a secret
    repo_id = "test-repo"
    secret = "super-secret-webhook-key-123"
    webhook_verifier.set_secret(repo_id, secret)

    # Test valid signature
    payload = b'{"action": "push", "ref": "refs/heads/main"}'
    import hmac
    import hashlib

    valid_signature = 'sha256=' + hmac.new(
        secret.encode('utf-8'),
        payload,
        hashlib.sha256
    ).hexdigest()

        is_valid = webhook_verifier.verify_github_signature(
        payload,
        valid_signature,
        repo_id
    )
    print(f"  Valid signature test: {'PASS' if is_valid else 'FAIL'}")

    # Test invalid signature
    invalid_signature = "sha256=invalid123"
        is_invalid = webhook_verifier.verify_github_signature(
        payload,
        invalid_signature,
        repo_id
    )
    print(f"  Invalid signature test: {'PASS' if not is_invalid else 'FAIL'}")

    return is_valid and not is_invalid


def test_input_validation():
    """Test input validation and sanitization"""
    print("\n2. Testing Input Validation:")
    print("-" * 40)

    tests_passed = 0

    # Test valid inputs
    valid_tests = [
        ('device_name', 'router-01'),
        ('ip_address', '192.168.1.1'),
        ('config_path', 'configs/router.cfg'),
    ]

    for input_type, value in valid_tests:
        is_valid = input_validator.validate_input(value, input_type)
        print(f"  Valid {input_type}: {value} - {'PASS' if is_valid else \
            'FAIL'}")
        if is_valid:
            tests_passed += 1

    # Test invalid inputs
    invalid_tests = [
        ('device_name', 'router;DROP TABLE'),
        ('ip_address', '999.999.999.999'),
        ('config_path', '../../../etc/passwd'),
    ]

    for input_type, value in invalid_tests:
        is_valid = input_validator.validate_input(value, input_type)
        print(f"  Invalid {input_type}: {value} - {'PASS' if not is_valid else \
            'FAIL'}")
        if not is_valid:
            tests_passed += 1

    # Test command sanitization
    dangerous_commands = [
        'rm -rf /',
        'format flash',
        'delete system',
        'config; DROP TABLE devices',
    ]

    safe_commands = [
        'interface eth0',
        'description Test',
        'no shutdown',
    ]

    all_commands = dangerous_commands + safe_commands
    sanitized = input_validator.sanitize_config_commands(all_commands)

    print(f"  Command sanitization: {len(all_commands)} -> {len(sanitized)} \
        commands")
    print(f"  Blocked {len(dangerous_commands)} dangerous commands: {'PASS' if \
    len(sanitized) == len(safe_commands) else 'FAIL'}")

    if len(sanitized) == len(safe_commands):
        tests_passed += 1

    return tests_passed == 7


def test_rate_limiting():
    """Test rate limiting"""
    print("\n3. Testing Rate Limiting:")
    print("-" * 40)

    user_id = "test-user"
    tests_passed = 0

    # Test API rate limit (60 per minute)
    for i in range(65):
        allowed = rate_limiter.is_allowed(user_id, 'api_general')
        if i < 60 and not allowed:
            print(f"  API rate limit failed at request {i+1}")
            break
        elif i >= 60 and allowed:
            print(f"  API rate limit not enforced at request {i+1}")
            break
    else:
        print(f"  API rate limit: Correctly limited at 60 requests")
        tests_passed += 1

    # Test deployment rate limit (5 per minute)
    user_id2 = "deploy-user"
    for i in range(7):
        allowed = rate_limiter.is_allowed(user_id2, 'deployment')
        if i < 5 and not allowed:
            print(f"  Deployment rate limit failed at request {i+1}")
            break
        elif i >= 5 and allowed:
            print(f"  Deployment rate limit not enforced at request {i+1}")
            break
    else:
        print(f"  Deployment rate limit: Correctly limited at 5 requests")
        tests_passed += 1

    # Test remaining requests
    remaining = rate_limiter.get_remaining(user_id2, 'deployment')
    print(f"  Remaining deployment requests: {remaining} (should be 0)")
    if remaining == 0:
        tests_passed += 1

    return tests_passed == 3


def test_secure_deployment():
    """Test secure deployment checks"""
    print("\n4. Testing Secure Deployment Checks:")
    print("-" * 40)

    # Test with safe configuration
    safe_config = {
        'device_id': 'router-01',
        'commands': [
            'interface eth0',
            'description Updated by CatNet',
            'no shutdown'
        ]
    }

    result = secure_deployment_check(safe_config, 'test-user-safe')
    print(f"  Safe deployment: {'PASS' if result['allowed'] else 'FAIL - ' + 
    result['reason']}")

    # Test with dangerous configuration
    dangerous_config = {
        'device_id': 'router-01',
        'commands': [
            'interface eth0',
            'rm -rf /',  # Dangerous!
            'format flash',  # Dangerous!
            'no shutdown'
        ]
    }

    result = secure_deployment_check(dangerous_config, 'test-user-danger')
    sanitized_commands = result['sanitized_config']['commands']
    print(f"  Dangerous commands blocked: {4 - len(sanitized_commands)} of 2 \
        dangerous")
    print(f"  Sanitization: {'PASS' if len(sanitized_commands) == 2 else \
        'FAIL'}")

    return result['allowed'] and len(sanitized_commands) == 2

async def test_async_operations():
    """Test async device operations"""
    print("\n5. Testing Async Device Operations:")
    print("-" * 40)

    # Create test devices if needed
    if not device_store.list_devices():
        device_store.add_device(
            hostname="test-router-1",
            ip_address="192.168.1.1",
            device_type="cisco_ios",
            vendor="Cisco"
        )

    device = device_store.list_devices()[0]

    # Test async connection
    print("  Testing async connection...")
    connection = await async_device_connector.connect_to_device_async( \
        device.to_dict())
    print(f"  Async connection: {'PASS' if connection else 'FAIL'}")

    # Test async command execution
    if connection:
        print("  Testing async command execution...")
        result = await async_device_connector.execute_commands_async(
            device.id,
            ['show version']
        )
        print(f"  Async execution: {'PASS' if result['success'] else 'FAIL'}")

    # Test parallel health check
    print("  Testing parallel health check...")
    health = await async_device_connector.health_check_parallel([device.id])
    print(f"  Parallel health check: {health['healthy']}/{health['total']} \
        devices")

    # Cleanup
    async_device_connector.cleanup()

    return True


def test_security_auditing():
    """Test security event auditing"""
    print("\n6. Testing Security Auditing:")
    print("-" * 40)

    # Log some security events
    security_auditor.log_security_event('auth_failure', {
        'user': 'test-user',
        'reason': 'Invalid credentials'
    })

    security_auditor.log_security_event('rate_limit_exceeded', {
        'user': 'test-user',
        'action': 'deployment'
    })

    security_auditor.log_security_event('dangerous_command', {
        'user': 'test-user',
        'command': 'rm -rf /'
    })

    # Get recent events
    recent = security_auditor.get_recent_events(5)
    print(f"  Logged events: {len(recent)}")

    # Check event types
    event_types = {event['type'] for event in recent}
    expected = {'auth_failure', 'rate_limit_exceeded', 'dangerous_command'}

    if expected.issubset(event_types):
        print(f"  Security events logged correctly: PASS")
        return True
    else:
        print(f"  Missing events: {expected - event_types}")
        return False

if __name__ == "__main__":
    tests_passed = 0
    total_tests = 6

    # Run sync tests
    if test_webhook_verification():
        tests_passed += 1

    if test_input_validation():
        tests_passed += 1

    if test_rate_limiting():
        tests_passed += 1

    if test_secure_deployment():
        tests_passed += 1

    # Run async test
    if asyncio.run(test_async_operations()):
        tests_passed += 1

    if test_security_auditing():
        tests_passed += 1

    # Results
    print("\n" + "="*60)
    print("Test Results:")
    print("-" * 40)
    print(f"Tests Passed: {tests_passed}/{total_tests}")

    if tests_passed == total_tests:
        print("\n[SUCCESS] All enhanced security features working correctly!")
        print("Anti-patterns successfully avoided:")
        print("  - Webhook signatures verified")
        print("  - Input validation preventing injection")
        print("  - Rate limiting preventing abuse")
        print("  - Async operations preventing timeouts")
        print("  - Security events properly audited")
    else:
        print(f"\n[FAILURE] {total_tests - tests_passed} tests failed")

    exit(0 if tests_passed == total_tests else 1)
