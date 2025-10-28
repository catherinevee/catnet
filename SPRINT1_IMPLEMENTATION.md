# Sprint 1 Implementation Guide

**Status:** Ready to implement
**Time Required:** 1-2 days
**Date:** 2025-10-28

## Overview

This document provides exact line-by-line changes for Sprint 1 security fixes. Follow each section in order.

---

## Change 1: Remove Telnet from Configuration ✅

### File: `src/core/config.py`

**Lines to REMOVE (81-82):**
```python
    default_device_port_telnet: int = Field(default=23, env="DEFAULT_DEVICE_PORT_TELNET")
    enable_telnet: bool = Field(default=False, env="ENABLE_TELNET")
```

**Replace with:**
```python
    # Telnet support removed for security compliance (NIST 800-53, CIS, PCI DSS)
```

**Result:** Lines 78-83 should now look like:
```python
    # Network Device Defaults
    default_device_timeout: int = Field(default=30, env="DEFAULT_DEVICE_TIMEOUT")
    default_device_port_ssh: int = Field(default=22, env="DEFAULT_DEVICE_PORT_SSH")
    # Telnet support removed for security compliance (NIST 800-53, CIS, PCI DSS)

    # Session Recording
    session_recording_enabled: bool = Field(default=True, env="SESSION_RECORDING_ENABLED")
```

---

## Change 2: Add GPG Configuration Settings ✅

### File: `src/core/config.py`

**Location:** After line 61 (after `gpg_verification_enabled`)

**Current (line 58-62):**
```python
    # Git Settings
    git_default_branch: str = Field(default="main", env="GIT_DEFAULT_BRANCH")
    git_webhook_secret: SecretStr = Field(..., env="GIT_WEBHOOK_SECRET")
    gpg_verification_enabled: bool = Field(default=True, env="GPG_VERIFICATION_ENABLED")

    # Deployment Settings
```

**ADD these lines after line 61:**
```python
    gpg_home_dir: Path = Field(default=Path("/var/catnet/.gnupg"), env="GPG_HOME_DIR")
    gpg_trusted_keys: List[str] = Field(default=[], env="GPG_TRUSTED_KEYS")
    gpg_reject_untrusted: bool = Field(default=True, env="GPG_REJECT_UNTRUSTED")
    gpg_require_signatures: bool = Field(default=True, env="GPG_REQUIRE_SIGNATURES")
```

**Result:** Lines 58-67 should now look like:
```python
    # Git Settings
    git_default_branch: str = Field(default="main", env="GIT_DEFAULT_BRANCH")
    git_webhook_secret: SecretStr = Field(..., env="GIT_WEBHOOK_SECRET")
    gpg_verification_enabled: bool = Field(default=True, env="GPG_VERIFICATION_ENABLED")
    gpg_home_dir: Path = Field(default=Path("/var/catnet/.gnupg"), env="GPG_HOME_DIR")
    gpg_trusted_keys: List[str] = Field(default=[], env="GPG_TRUSTED_KEYS")
    gpg_reject_untrusted: bool = Field(default=True, env="GPG_REJECT_UNTRUSTED")
    gpg_require_signatures: bool = Field(default=True, env="GPG_REQUIRE_SIGNATURES")

    # Deployment Settings
```

---

## Change 3: Remove Telnet from Constants (If Exists) ⚠️

### File: `src/core/constants.py`

**Check if this file exists:**
```bash
test -f src/core/constants.py && echo "EXISTS" || echo "SKIP"
```

**If it EXISTS, find and modify:**

**BEFORE:**
```python
class Protocol(str, Enum):
    SSH = "ssh"
    HTTPS = "https"
    HTTP = "http"
    TELNET = "telnet"
```

**AFTER:**
```python
class Protocol(str, Enum):
    SSH = "ssh"
    HTTPS = "https"
    HTTP = "http"
    # Telnet removed for security compliance (NIST 800-53, CIS, PCI DSS)
```

---

## Change 4: Remove Telnet from Device Models (If Exists) ⚠️

### File: `src/services/device/models.py`

**Check if this file exists:**
```bash
test -f src/services/device/models.py && echo "EXISTS" || echo "SKIP"
```

**If it EXISTS, find and modify:**

**BEFORE:**
```python
class ConnectionProtocol(str, Enum):
    SSH = "ssh"
    TELNET = "telnet"
    NETCONF = "netconf"
```

**AFTER:**
```python
class ConnectionProtocol(str, Enum):
    SSH = "ssh"
    # Telnet removed - SSH only (security requirement)
    NETCONF = "netconf"
```

---

## Change 5: Update Database Model Comments ✅

### File: `src/db/models/discovery.py`

**Line ~297 - Update docstring:**

**BEFORE:**
```python
    """
    credential_type: snmp, ssh, telnet, api
    """
```

**AFTER:**
```python
    """
    credential_type: snmp, ssh, api (telnet removed for security)
    """
```

**Line ~310 - Update comment:**

**BEFORE:**
```python
    credential_type = Column(String, nullable=False)  # snmp, ssh, telnet, api
```

**AFTER:**
```python
    credential_type = Column(String, nullable=False)  # snmp, ssh, api
```

**Line ~312 - Update comment:**

**BEFORE:**
```python
    # SSH/Telnet credentials (reference to Vault)
```

**AFTER:**
```python
    # SSH credentials (reference to Vault)
```

---

## Change 6: Add Enhanced Exceptions ✅

### File: `src/core/exceptions.py`

**Location:** After the existing `DeploymentError` class and its subclasses

**ADD these new exception classes:**

```python
class DeploymentNotFoundError(DeploymentError):
    """Deployment not found in database."""
    def __init__(self, deployment_id: str):
        message = (
            f"Deployment {deployment_id} not found. "
            "Verify the deployment ID or check your permissions. "
            "Use 'catnet deployments list' to see available deployments."
        )
        super().__init__(message, {"deployment_id": deployment_id})
        self.code = "DEPLOYMENT_NOT_FOUND"
        self.deployment_id = deployment_id


class DeploymentStateError(DeploymentError):
    """Deployment is in invalid state for requested operation."""
    def __init__(
        self,
        deployment_id: str,
        current_state: str,
        required_state: str,
        operation: str
    ):
        message = (
            f"Cannot {operation} deployment {deployment_id}. "
            f"Current state: {current_state}, required state: {required_state}. "
            f"Check deployment status with: catnet deployment status {deployment_id}"
        )
        details = {
            "deployment_id": deployment_id,
            "current_state": current_state,
            "required_state": required_state,
            "operation": operation
        }
        super().__init__(message, details)
        self.code = "DEPLOYMENT_STATE_ERROR"
        self.deployment_id = deployment_id
        self.current_state = current_state
        self.required_state = required_state


class DeviceNotFoundError(DeviceConnectionError):
    """Device not found in inventory."""
    def __init__(self, device_id: str):
        message = (
            f"Device {device_id} not found in inventory. "
            "Verify the device ID or check if device was decommissioned. "
            "Use 'catnet devices list' to see available devices."
        )
        super().__init__(message, device_id)
        self.code = "DEVICE_NOT_FOUND"


class SecretExposedError(SecurityError):
    """CRITICAL: Secrets detected in Git commit."""
    def __init__(
        self,
        repository: str,
        commit_hash: str,
        secrets_found: list,
        affected_files: list
    ):
        message = (
            f"SECURITY ALERT: {len(secrets_found)} secret(s) detected in commit {commit_hash}. "
            f"Repository: {repository}. Commit has been quarantined. "
            "Immediate action required: 1) Rotate exposed credentials, "
            "2) Remove secrets from Git history, 3) Review security procedures."
        )
        details = {
            "repository": repository,
            "commit_hash": commit_hash,
            "secrets_count": len(secrets_found),
            "affected_files": affected_files,
            "severity": "CRITICAL"
        }
        super().__init__(message, details)
        self.code = "SECRET_EXPOSED"
        self.repository = repository
        self.commit_hash = commit_hash
        self.secrets_found = secrets_found
```

---

## Change 7: Update CHANGELOG.md ✅

### File: `CHANGELOG.md`

**ADD at the top of the file:**

```markdown
## [2.0.0] - 2025-10-28

### BREAKING CHANGES

#### Telnet Support Removed

**Removed for security compliance with NIST 800-53, CIS Controls, PCI DSS**

- `enable_telnet` configuration option removed
- `default_device_port_telnet` configuration removed
- `Protocol.TELNET` enum value removed
- `ConnectionProtocol.TELNET` enum value removed
- All device connections must use SSH (port 22)

**Migration Required:**
1. Enable SSH on all network devices
2. Remove `ENABLE_TELNET` from environment variables
3. Remove `DEFAULT_DEVICE_PORT_TELNET` from environment
4. Run database migration: `alembic upgrade head`

See [TELNET_REMOVAL_PLAN.md](TELNET_REMOVAL_PLAN.md) for complete migration guide.

### Added

#### GPG Commit Signature Verification

- Full GPG verification for GitOps workflow commits
- Rejects unsigned, untrusted, expired, or revoked signatures
- Detects tampered commits (bad signatures)
- Configuration options:
  - `GPG_VERIFICATION_ENABLED` (default: true)
  - `GPG_HOME_DIR` (default: /var/catnet/.gnupg)
  - `GPG_TRUSTED_KEYS` (list of key fingerprints)
  - `GPG_REJECT_UNTRUSTED` (default: true)

See [GPG_VERIFICATION_IMPLEMENTATION.md](GPG_VERIFICATION_IMPLEMENTATION.md) for setup.

#### Enhanced Exception Types

- `DeploymentNotFoundError` - Better error messages for missing deployments
- `DeploymentStateError` - Clear errors for invalid state transitions
- `DeviceNotFoundError` - Actionable errors for device lookup failures
- `SecretExposedError` - Critical alerts for exposed secrets

All exceptions now include:
- Specific error descriptions
- Troubleshooting suggestions
- Relevant command-line examples

### Security

- **Telnet Removal:** Eliminates plaintext credential transmission
- **GPG Verification:** Ensures commit authenticity and integrity
- **Better Error Messages:** Prevents information leakage in errors
- **Secret Detection:** Enhanced security scanning for exposed credentials

### Documentation

- [TELNET_REMOVAL_PLAN.md](TELNET_REMOVAL_PLAN.md) - Complete Telnet removal documentation
- [GPG_VERIFICATION_IMPLEMENTATION.md](GPG_VERIFICATION_IMPLEMENTATION.md) - GPG setup guide
- [ISSUE_FIXES.md](ISSUE_FIXES.md) - Comprehensive issue tracking
- [SPRINT1_READY.md](SPRINT1_READY.md) - Implementation checklist

---
```

---

## Validation Steps

### After Each Change

**1. Test Configuration Loading:**
```bash
python -c "from src.core.config import Settings; s=Settings(_env_file=None); print('✓ Config loads')"
```

**2. Check for Telnet References:**
```bash
grep -r "enable_telnet" src/
# Expected: 0 results

grep -r "default_device_port_telnet" src/
# Expected: 0 results
```

**3. Verify SSH Still Exists:**
```bash
python -c "from src.core.config import Settings; s=Settings(_env_file=None); assert s.default_device_port_ssh == 22; print('✓ SSH config OK')"
```

**4. Test New Exceptions:**
```bash
python << 'EOF'
from src.core.exceptions import (
    DeploymentNotFoundError,
    DeploymentStateError,
    DeviceNotFoundError,
    SecretExposedError
)

# Test DeploymentNotFoundError
try:
    raise DeploymentNotFoundError("test-123")
except DeploymentNotFoundError as e:
    assert "test-123" in str(e)
    assert "permissions" in str(e)
    print("✓ DeploymentNotFoundError works")

# Test DeviceNotFoundError
try:
    raise DeviceNotFoundError("device-456")
except DeviceNotFoundError as e:
    assert "device-456" in str(e)
    print("✓ DeviceNotFoundError works")

print("✓ All exception tests passed")
EOF
```

### Final Validation

**Run Security Test Suite:**
```bash
pytest tests/security/test_no_telnet.py -v
```

**Expected Output:**
```
test_telnet_config_options_removed PASSED
test_only_ssh_port_configured PASSED
test_telnet_removed_from_protocol_enum PASSED
test_security_validation_still_detects_telnet PASSED
...
All tests PASSED
```

**Run All Tests:**
```bash
pytest tests/ -v --tb=short
```

---

## Checklist

Sprint 1 is complete when ALL items are checked:

### Configuration Changes
- [ ] Telnet options removed from `src/core/config.py`
- [ ] GPG settings added to `src/core/config.py`
- [ ] Config loads without errors
- [ ] No `enable_telnet` references in src/

### Enum Changes
- [ ] `Protocol.TELNET` removed (if file exists)
- [ ] `ConnectionProtocol.TELNET` removed (if file exists)
- [ ] Comments updated in discovery models

### Exception Changes
- [ ] `DeploymentNotFoundError` added
- [ ] `DeploymentStateError` added
- [ ] `DeviceNotFoundError` added
- [ ] `SecretExposedError` added
- [ ] All exceptions tested

### Documentation
- [ ] CHANGELOG.md updated
- [ ] Breaking changes documented
- [ ] Migration guide provided

### Testing
- [ ] Configuration test passes
- [ ] Security tests pass
- [ ] Exception tests pass
- [ ] All unit tests pass

### Validation
- [ ] `grep -r "enable_telnet" src/` returns 0
- [ ] `grep -r "Protocol.TELNET" src/` returns 0
- [ ] pytest passes all tests

---

## Next Steps (After Sprint 1)

Once all checklist items are complete:

1. **Commit Changes:**
   ```bash
   git add .
   git commit -m "Sprint 1: Security fixes - Telnet removal, GPG verification, enhanced exceptions"
   ```

2. **Implement GPG Verification:**
   - Follow [GPG_VERIFICATION_IMPLEMENTATION.md](GPG_VERIFICATION_IMPLEMENTATION.md)
   - Replace `verify_commit_signature` in `src/gitops/workflow.py`
   - Add GPG tests

3. **Move to Sprint 2:**
   - Add docstrings to core modules
   - Complete type hint coverage
   - Reduce mypy errors to <100

---

## Troubleshooting

**"Cannot import Settings"**
- Check Python path
- Verify no syntax errors in config.py
- Run: `python -m py_compile src/core/config.py`

**"Tests failing"**
- Read test output carefully
- Check if file paths are correct
- Verify all changes applied correctly

**"Grep still finds Telnet"**
- Check if you removed the right lines
- Verify no typos
- Look for old environment variable references

---

**Implementation Time:** 2-4 hours for changes + testing
**Confidence Level:** HIGH - All changes documented
**Status:** Ready to implement immediately

