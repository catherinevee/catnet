# Telnet Removal Plan

**Date:** 2025-10-28
**Priority:** P0 - Critical Security

## Analysis

After scanning the codebase, Telnet references fall into two categories:

### ✅ KEEP - Security Validation (Detection & Warning)
These references **detect Telnet being enabled** and warn users. **Must be kept** for security compliance.

**Files with security validation (KEEP):**
- [src/deployment/validator.py](src/deployment/validator.py):104,356-361 - Detects Telnet in configs
- [src/core/validation.py](src/core/validation.py):302 - Validates against Telnet
- [src/gitops/scanner.py](src/gitops/scanner.py):120,150,473,507,520 - Scans for Telnet vulnerabilities
- [src/gitops/workflow.py](src/gitops/workflow.py):347-348 - Security compliance check
- [src/parsers/juniper_parser.py](src/parsers/juniper_parser.py):704-705 - Warns about Telnet
- [src/parsers/cisco_parser.py](src/parsers/cisco_parser.py):560,701,704-705 - Detects Telnet in VTY
- [src/services/deployment/app.py](src/services/deployment/app.py):855 - Protocol security check
- [src/services/gitops/handlers.py](src/services/gitops/handlers.py):1047,1069 - Insecure protocol check
- [src/services/device/managers.py](src/services/device/managers.py):512-514 - Configuration security check
- [src/security/security_scanner.py](src/security/security_scanner.py):463-476 - Vulnerability scanner
- [src/services/deployment/validators.py](src/services/deployment/validators.py):306 - Insecure protocol list

**Example (KEEP THIS):**
```python
# src/gitops/workflow.py:347-348
if 'telnet' in config_text.lower():
    issues.append("Telnet is not allowed - use SSH")
```

### ❌ REMOVE - CatNet Configuration (Allowing Telnet)
These references **enable CatNet to use Telnet** for connections. **Must be removed** for security.

**Files to modify (REMOVE):**
1. [src/core/config.py](src/core/config.py):81-82 - Config options
2. [src/core/constants.py](src/core/constants.py):38 - Protocol constant
3. [src/services/device/models.py](src/services/device/models.py):53 - Protocol enum
4. [src/db/models/discovery.py](src/db/models/discovery.py):297,310,312 - Comments about Telnet credentials

## Implementation Plan

### Step 1: Remove Configuration Options

**File:** [src/core/config.py](src/core/config.py)

**Remove lines 81-82:**
```python
# REMOVE THESE LINES:
default_device_port_telnet: int = Field(default=23, env="DEFAULT_DEVICE_PORT_TELNET")
enable_telnet: bool = Field(default=False, env="ENABLE_TELNET")
```

**Impact:** Any code referencing `settings.enable_telnet` or `settings.default_device_port_telnet` will fail.

**Search for usage:**
```bash
grep -r "enable_telnet" src/
grep -r "default_device_port_telnet" src/
```

**Expected:** Should return zero results (no code uses these settings)

### Step 2: Remove Protocol Constant

**File:** [src/core/constants.py](src/core/constants.py)

**Current (line 38):**
```python
class Protocol(str, Enum):
    SSH = "ssh"
    HTTPS = "https"
    HTTP = "http"
    TELNET = "telnet"  # ← REMOVE THIS LINE
```

**After:**
```python
class Protocol(str, Enum):
    SSH = "ssh"
    HTTPS = "https"
    HTTP = "http"
    # Telnet removed for security compliance (NIST 800-53, CIS)
```

**Impact:** Any code using `Protocol.TELNET` will fail at import time.

**Search for usage:**
```bash
grep -r "Protocol\.TELNET" src/
grep -r "Protocol\.telnet" src/
```

### Step 3: Remove from Device Models

**File:** [src/services/device/models.py](src/services/device/models.py)

**Current (line 53):**
```python
class ConnectionProtocol(str, Enum):
    SSH = "ssh"
    TELNET = "telnet"  # ← REMOVE THIS LINE
    NETCONF = "netconf"
```

**After:**
```python
class ConnectionProtocol(str, Enum):
    SSH = "ssh"
    # Telnet removed - use SSH only (security requirement)
    NETCONF = "netconf"
```

**Impact:** Database records with `protocol='telnet'` will be invalid.

**Migration needed:** Update any existing database records.

### Step 4: Update Database Model Comments

**File:** [src/db/models/discovery.py](src/db/models/discovery.py)

**Update comment on line 297:**
```python
# Before:
"""
    credential_type: snmp, ssh, telnet, api
"""

# After:
"""
    credential_type: snmp, ssh, api (telnet removed for security)
"""
```

**Update comment on line 310:**
```python
# Before:
credential_type = Column(String, nullable=False)  # snmp, ssh, telnet, api

# After:
credential_type = Column(String, nullable=False)  # snmp, ssh, api
```

**Update comment on line 312:**
```python
# Before:
# SSH/Telnet credentials (reference to Vault)

# After:
# SSH credentials (reference to Vault)
```

### Step 5: Database Migration

**Create migration to handle existing data:**

```python
# migrations/versions/YYYYMMDD_remove_telnet.py
"""Remove Telnet protocol support

Revision ID: remove_telnet_001
Revises: <previous>
Create Date: 2025-10-28

"""
from alembic import op
import sqlalchemy as sa

def upgrade():
    """Remove Telnet protocol from existing records."""

    # Update any devices using Telnet to SSH
    op.execute("""
        UPDATE devices
        SET protocol = 'ssh',
            notes = CONCAT(COALESCE(notes, ''),
                          '\nMigrated from Telnet to SSH on 2025-10-28 for security compliance')
        WHERE protocol = 'telnet'
    """)

    # Update discovery credentials
    op.execute("""
        UPDATE discovery_credentials
        SET credential_type = 'ssh',
            notes = CONCAT(COALESCE(notes, ''),
                          '\nMigrated from Telnet to SSH on 2025-10-28')
        WHERE credential_type = 'telnet'
    """)

    # Add constraint to prevent Telnet in future
    op.execute("""
        ALTER TABLE devices
        ADD CONSTRAINT check_no_telnet
        CHECK (protocol != 'telnet')
    """)

    op.execute("""
        ALTER TABLE discovery_credentials
        ADD CONSTRAINT check_no_telnet_creds
        CHECK (credential_type != 'telnet')
    """)

def downgrade():
    """Rollback Telnet removal."""

    op.execute("ALTER TABLE devices DROP CONSTRAINT IF EXISTS check_no_telnet")
    op.execute("ALTER TABLE discovery_credentials DROP CONSTRAINT IF EXISTS check_no_telnet_creds")
```

### Step 6: Update Documentation

**Files to update:**
1. **SECURITY.md** - Add note about Telnet removal
2. **CHANGELOG.md** - Add breaking change entry
3. **Migration guide** - Document upgrade path

**SECURITY.md addition:**
```markdown
## Security Compliance

### Insecure Protocols Removed

CatNet does not support the following protocols due to security requirements:

- **Telnet** - Transmits credentials in plaintext (violates NIST 800-53, CIS benchmarks)
- All device connections must use SSH (port 22)

### Compliance Standards

- NIST 800-53: SC-8 (Transmission Confidentiality)
- CIS Critical Security Controls: v8 Control 3.10
- PCI DSS: Requirement 2.3
```

**CHANGELOG.md entry:**
```markdown
## [2.0.0] - 2025-10-28

### BREAKING CHANGES

- **Removed Telnet support** for security compliance
  - `enable_telnet` configuration option removed
  - `default_device_port_telnet` configuration removed
  - `Protocol.TELNET` enum value removed
  - `ConnectionProtocol.TELNET` enum value removed

### Migration Guide

If you have devices configured to use Telnet:

1. **Enable SSH on all network devices**
   ```
   configure terminal
   ip domain-name example.com
   crypto key generate rsa modulus 2048
   line vty 0 4
     transport input ssh
   ```

2. **Run database migration**
   ```bash
   alembic upgrade head
   ```

3. **Update device inventory**
   - All devices automatically migrated to SSH
   - Review migrated devices: `SELECT * FROM devices WHERE notes LIKE '%Migrated from Telnet%'`

4. **Remove environment variables**
   - Delete `ENABLE_TELNET` from .env
   - Delete `DEFAULT_DEVICE_PORT_TELNET` from .env

### Security Justification

Telnet has been removed to comply with:
- NIST 800-53 (Federal systems)
- CIS Benchmarks (Industry best practices)
- PCI DSS (Payment card security)

Telnet transmits all data, including credentials, in plaintext. This is unacceptable in modern security environments.
```

## Validation Steps

### 1. Search for Telnet References

```bash
# Should only return security validation code (not configuration):
grep -r -i "telnet" src/ | grep -v "# Telnet" | grep -v "Telnet is not allowed"

# Expected: Only security scanner/validator references
```

### 2. Check Environment Variables

```bash
# Ensure these are NOT used:
grep -r "ENABLE_TELNET" .
grep -r "DEFAULT_DEVICE_PORT_TELNET" .

# Expected: Only .env.example (as comment/deprecated), no active code
```

### 3. Run Tests

```bash
# All tests should pass:
pytest tests/ -v

# Specific security test:
pytest tests/security/test_no_telnet.py -v
```

### 4. Database Migration Test

```bash
# Test migration on dev database:
alembic upgrade head

# Verify no Telnet records remain:
psql -d catnet_dev -c "SELECT COUNT(*) FROM devices WHERE protocol = 'telnet';"
# Expected: 0

psql -d catnet_dev -c "SELECT COUNT(*) FROM discovery_credentials WHERE credential_type = 'telnet';"
# Expected: 0
```

### 5. Configuration Validation

```python
# This should fail (expected):
from src.core.config import Settings
settings = Settings()
print(settings.enable_telnet)  # AttributeError (expected)
```

## Rollback Plan

If issues arise, rollback using:

```bash
# Revert code changes
git revert <commit-hash>

# Rollback database migration
alembic downgrade -1

# Restore environment variables
# (Add back to .env if needed for legacy systems)
```

## Testing Checklist

- [ ] Configuration loads without `enable_telnet` or `default_device_port_telnet`
- [ ] No Python import errors (`Protocol.TELNET` removed)
- [ ] Database migration runs successfully
- [ ] All existing tests pass
- [ ] New security test passes (`test_no_telnet.py`)
- [ ] Security scanners still detect Telnet in configs (validation code intact)
- [ ] Documentation updated (SECURITY.md, CHANGELOG.md)
- [ ] No grep results for config-level Telnet support

## Security Test

**Create:** `tests/security/test_no_telnet.py`

```python
"""
Test that Telnet support has been completely removed.

This test ensures CatNet cannot be configured to use Telnet
while still maintaining ability to detect Telnet in device configs.
"""
import pytest
from src.core.config import Settings
from src.core import constants
from src.services.device import models


def test_telnet_removed_from_config():
    """Verify Telnet configuration options removed."""
    settings = Settings()

    # These should not exist:
    assert not hasattr(settings, 'enable_telnet'), "enable_telnet should be removed"
    assert not hasattr(settings, 'default_device_port_telnet'), "Telnet port config should be removed"


def test_telnet_removed_from_protocol_enum():
    """Verify Telnet removed from Protocol enum."""
    # Protocol.TELNET should not exist
    with pytest.raises(AttributeError):
        _ = constants.Protocol.TELNET


def test_telnet_removed_from_connection_protocol():
    """Verify Telnet removed from ConnectionProtocol enum."""
    # ConnectionProtocol.TELNET should not exist
    with pytest.raises(AttributeError):
        _ = models.ConnectionProtocol.TELNET


def test_security_validation_still_detects_telnet():
    """Verify security scanners still detect Telnet in configs."""
    from src.gitops.workflow import GitOpsWorkflow

    # Security validation should still work
    workflow = GitOpsWorkflow()

    config_with_telnet = {
        'vendor': 'cisco',
        'configuration': 'line vty 0 4\n transport input telnet'
    }

    issues = await workflow._check_security_compliance(config_with_telnet)

    # Should detect Telnet as security issue
    assert any('telnet' in issue.lower() for issue in issues), \
        "Security validation should still detect Telnet"


@pytest.mark.integration
def test_database_rejects_telnet_protocol(db_session):
    """Verify database constraint prevents Telnet."""
    from src.db.models import Device
    from sqlalchemy.exc import IntegrityError

    # Try to create device with Telnet
    device = Device(
        hostname="test-router",
        ip_address="10.0.0.1",
        protocol="telnet"  # Should be rejected
    )

    db_session.add(device)

    # Should raise constraint violation
    with pytest.raises(IntegrityError) as exc_info:
        db_session.commit()

    assert "check_no_telnet" in str(exc_info.value).lower()
```

## Communication Plan

### Internal Team

**Email/Slack:**
```
Subject: BREAKING CHANGE - Telnet Support Removed in CatNet v2.0

Team,

We are removing Telnet support from CatNet for security compliance
(NIST 800-53, CIS, PCI DSS).

IMPACT:
- All devices must use SSH (no exceptions)
- Database migration will auto-convert Telnet → SSH
- Configuration options removed

ACTION REQUIRED:
1. Ensure all network devices support SSH
2. Run migration: `alembic upgrade head`
3. Remove ENABLE_TELNET from environment configs

TIMELINE:
- Dev: 2025-10-28
- Staging: 2025-10-30
- Production: 2025-11-05

See CHANGELOG.md for full migration guide.

Questions? #catnet-support
```

### Customer Communication

**Release Notes:**
```markdown
## CatNet v2.0 - Security Compliance Update

### Telnet Protocol Removed

For security compliance, CatNet no longer supports Telnet for device connections.

**What Changed:**
- Telnet configuration options removed
- All connections now require SSH

**What You Need to Do:**
1. Enable SSH on all network devices (if not already)
2. Upgrade CatNet: `docker-compose pull && docker-compose up -d`
3. Database migration runs automatically

**Why:**
Telnet transmits credentials in cleartext, violating:
- NIST 800-53 requirements
- CIS Security Benchmarks
- PCI DSS standards

**Support:**
SSH has been industry standard since 2006. If you have devices
without SSH support, contact support@catnet.example.com.
```

## Success Criteria

✅ **Complete when:**
- [ ] Zero Telnet config options in codebase
- [ ] `grep -r "enable_telnet" src/` returns zero results
- [ ] All tests pass
- [ ] Database migration tested
- [ ] Documentation updated
- [ ] Security test passes
- [ ] Team notified
- [ ] Customers notified (for production)

## Timeline

- **Development:** 2 hours (code changes + migration)
- **Testing:** 1 hour (unit + integration tests)
- **Documentation:** 30 minutes
- **Review:** 1 hour
- **Deployment:** Staged rollout

**Total:** ~1 day for complete implementation

---

**Status:** Ready for implementation
**Approved by:** [Pending]
**Implementation date:** 2025-10-28
