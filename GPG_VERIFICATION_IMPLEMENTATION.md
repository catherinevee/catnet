# GPG Commit Verification Implementation

**Date:** 2025-10-28
**Priority:** P0 - Critical Security
**File:** [src/gitops/workflow.py](src/gitops/workflow.py):549-567

## Current State (Stubbed)

```python
async def verify_commit_signature(
    self,
    repository: GitRepository,
    commit_hash: str
) -> bool:
    """Verify GPG signature of commit."""
    if not repository.gpg_verification:
        return True

    repo_path = self.repos_path / repository.name
    repo = git.Repo(repo_path)

    try:
        commit = repo.commit(commit_hash)
        # In production, would verify GPG signature  ⬅️ STUB
        return True  # ⬅️ ALWAYS RETURNS TRUE
    except Exception as e:
        logger.error(f"Failed to verify commit signature: {e}")
        return False
```

**Problem:** Always returns True, providing no actual verification.

## Proposed Implementation

### Option 1: Using GitPython Built-in (Recommended)

**Advantages:**
- No additional dependencies
- Uses system GPG
- Integrated with existing GitPython usage

**Implementation:**

```python
import logging
from pathlib import Path
from typing import Optional, Dict, Any
import git

from src.core.exceptions import SecurityError, GitOperationError
from src.db.models import GitRepository

logger = logging.getLogger(__name__)


async def verify_commit_signature(
    self,
    repository: GitRepository,
    commit_hash: str
) -> bool:
    """
    Verify GPG signature of Git commit.

    Uses Git's built-in GPG verification. Requires GPG keys to be
    imported into the system keyring and trusted.

    Args:
        repository: Repository configuration with GPG settings
        commit_hash: Commit hash to verify

    Returns:
        True if signature is valid and from trusted key

    Raises:
        SecurityError: If signature is invalid, untrusted, or missing
        GitOperationError: If verification process fails

    Security:
        - Rejects unsigned commits if GPG verification enabled
        - Rejects commits signed by untrusted keys
        - Rejects commits with expired/revoked keys
        - Logs all verification attempts for audit

    Example:
        >>> repo = GitRepository(name="configs", gpg_verification=True)
        >>> is_valid = await manager.verify_commit_signature(repo, "abc123")
        >>> if is_valid:
        ...     print("Commit signature verified!")
    """
    if not repository.gpg_verification:
        logger.warning(
            f"GPG verification disabled for repository {repository.name}",
            extra={"repository": repository.name, "commit": commit_hash}
        )
        return True

    repo_path = self.repos_path / repository.name

    if not repo_path.exists():
        raise GitOperationError(
            f"Repository path does not exist: {repo_path}",
            repository=repository.name,
            operation="gpg_verify"
        )

    try:
        repo = git.Repo(repo_path)
        commit = repo.commit(commit_hash)

        # Get signature verification status using Git's format codes
        # %G?: Show "G" for good, "B" for bad, etc.
        # %GS: Signer name
        # %GK: Key fingerprint
        verification_status = repo.git.show(
            commit_hash,
            format="%G?",
            s=True  # Show signature
        )

        signer_name = repo.git.show(commit_hash, format="%GS")
        key_fingerprint = repo.git.show(commit_hash, format="%GK")

        # Git signature status codes:
        # G = Good signature from trusted key
        # U = Good signature from untrusted key
        # B = Bad signature
        # N = No signature
        # X = Good signature that has expired
        # Y = Good signature from expired key
        # R = Good signature from revoked key
        # E = Cannot verify (missing key)

        logger.info(
            f"GPG verification for commit {commit_hash}",
            extra={
                "repository": repository.name,
                "commit": commit_hash,
                "status": verification_status,
                "signer": signer_name,
                "key": key_fingerprint
            }
        )

        if verification_status == "G":
            # Good signature from trusted key - PASS
            logger.info(
                f"Valid GPG signature verified for commit {commit_hash}",
                extra={
                    "repository": repository.name,
                    "signer": signer_name,
                    "key_fingerprint": key_fingerprint
                }
            )
            return True

        elif verification_status == "U":
            # Good signature but key not trusted
            error_msg = (
                f"Commit {commit_hash} signed by untrusted key: {key_fingerprint}. "
                f"Signer: {signer_name}. Trust the key with: "
                f"gpg --edit-key {key_fingerprint} trust"
            )

            logger.error(error_msg, extra={
                "repository": repository.name,
                "commit": commit_hash,
                "key": key_fingerprint,
                "signer": signer_name
            })

            raise SecurityError(
                error_msg,
                {
                    "repository": repository.name,
                    "commit": commit_hash,
                    "key_fingerprint": key_fingerprint,
                    "signer": signer_name,
                    "status": "untrusted_key"
                }
            )

        elif verification_status == "B":
            # Bad signature - possible tampering
            error_msg = (
                f"SECURITY ALERT: Bad GPG signature for commit {commit_hash}. "
                f"Commit may have been tampered with!"
            )

            logger.critical(error_msg, extra={
                "repository": repository.name,
                "commit": commit_hash,
                "signer": signer_name,
                "key": key_fingerprint
            })

            raise SecurityError(
                error_msg,
                {
                    "repository": repository.name,
                    "commit": commit_hash,
                    "status": "bad_signature",
                    "severity": "critical"
                }
            )

        elif verification_status == "N":
            # No signature present
            error_msg = (
                f"Commit {commit_hash} is not signed. "
                f"All commits must be GPG signed. "
                f"Configure Git: git config commit.gpgsign true"
            )

            logger.error(error_msg, extra={
                "repository": repository.name,
                "commit": commit_hash
            })

            raise SecurityError(
                error_msg,
                {
                    "repository": repository.name,
                    "commit": commit_hash,
                    "status": "unsigned"
                }
            )

        elif verification_status in ["X", "Y"]:
            # Expired signature or key
            error_msg = (
                f"Commit {commit_hash} signed with expired signature or key. "
                f"Signer: {signer_name}, Key: {key_fingerprint}"
            )

            logger.error(error_msg, extra={
                "repository": repository.name,
                "commit": commit_hash,
                "key": key_fingerprint,
                "status": verification_status
            })

            raise SecurityError(
                error_msg,
                {
                    "repository": repository.name,
                    "commit": commit_hash,
                    "key_fingerprint": key_fingerprint,
                    "status": "expired"
                }
            )

        elif verification_status == "R":
            # Revoked key - critical security issue
            error_msg = (
                f"SECURITY ALERT: Commit {commit_hash} signed with REVOKED key! "
                f"Key: {key_fingerprint}, Signer: {signer_name}"
            )

            logger.critical(error_msg, extra={
                "repository": repository.name,
                "commit": commit_hash,
                "key": key_fingerprint,
                "signer": signer_name
            })

            raise SecurityError(
                error_msg,
                {
                    "repository": repository.name,
                    "commit": commit_hash,
                    "key_fingerprint": key_fingerprint,
                    "status": "revoked_key",
                    "severity": "critical"
                }
            )

        elif verification_status == "E":
            # Cannot verify - missing public key
            error_msg = (
                f"Cannot verify commit {commit_hash} - public key not found. "
                f"Import key with: gpg --recv-keys {key_fingerprint}"
            )

            logger.error(error_msg, extra={
                "repository": repository.name,
                "commit": commit_hash,
                "key": key_fingerprint
            })

            raise SecurityError(
                error_msg,
                {
                    "repository": repository.name,
                    "commit": commit_hash,
                    "key_fingerprint": key_fingerprint,
                    "status": "missing_key"
                }
            )

        else:
            # Unknown status
            error_msg = f"Unknown GPG verification status: {verification_status}"

            logger.error(error_msg, extra={
                "repository": repository.name,
                "commit": commit_hash,
                "status": verification_status
            })

            raise GitOperationError(
                error_msg,
                repository=repository.name,
                operation="gpg_verify"
            )

    except SecurityError:
        # Re-raise security errors
        raise

    except git.GitCommandError as e:
        logger.error(f"Git command error during GPG verification: {e}")
        raise GitOperationError(
            f"Git GPG verification failed: {e}",
            repository=repository.name,
            operation="gpg_verify"
        )

    except Exception as e:
        logger.exception(f"Unexpected error during GPG verification")
        raise GitOperationError(
            f"GPG verification error: {e}",
            repository=repository.name,
            operation="gpg_verify"
        )
```

### Option 2: Using python-gnupg Library

**Advantages:**
- More control over GPG operations
- Can import/manage keys programmatically
- Better error messages

**Disadvantages:**
- Additional dependency
- Requires GPG binary installed

**Implementation:**

```python
import gnupg
from pathlib import Path

async def verify_commit_signature_gnupg(
    self,
    repository: GitRepository,
    commit_hash: str
) -> bool:
    """Verify GPG signature using python-gnupg library."""

    if not repository.gpg_verification:
        return True

    # Initialize GPG with CatNet keyring
    gpg_home = Path("/var/catnet/.gnupg")
    gpg = gnupg.GPG(gnupghome=str(gpg_home))

    repo_path = self.repos_path / repository.name
    repo = git.Repo(repo_path)

    try:
        commit = repo.commit(commit_hash)

        # Get raw signature data
        signature_data = repo.git.show(commit_hash, show_signature=True)

        # Verify signature
        verified = gpg.verify(signature_data)

        if verified.valid:
            logger.info(f"GPG signature valid for {commit_hash}")
            return True
        else:
            raise SecurityError(
                f"Invalid GPG signature: {verified.status}",
                {"commit": commit_hash, "reason": verified.stderr}
            )

    except Exception as e:
        logger.error(f"GPG verification failed: {e}")
        raise
```

## Setup Requirements

### System Configuration

```bash
# Install GPG
apt-get install gnupg  # Debian/Ubuntu
yum install gnupg2     # RHEL/CentOS

# Create GPG home for CatNet
mkdir -p /var/catnet/.gnupg
chmod 700 /var/catnet/.gnupg
chown catnet:catnet /var/catnet/.gnupg

# Set GPG home in environment
export GNUPGHOME=/var/catnet/.gnupg
```

### Import Trusted Developer Keys

```bash
# Option 1: Import from keyserver
gpg --homedir /var/catnet/.gnupg --keyserver keys.openpgp.org --recv-keys <KEY_ID>

# Option 2: Import from file
gpg --homedir /var/catnet/.gnupg --import /path/to/public-keys.asc

# Set trust level (5 = ultimate trust)
gpg --homedir /var/catnet/.gnupg --edit-key <KEY_ID>
> trust
> 5
> quit
```

### Configure Git to Use GPG

```bash
# For developers - sign all commits
git config --global commit.gpgsign true
git config --global user.signingkey <YOUR_KEY_ID>

# Verify configuration
git config --get commit.gpgsign  # Should return: true
```

## Configuration Changes

### Add to src/core/config.py

```python
# GPG Verification Settings
gpg_verification_enabled: bool = Field(default=True, env="GPG_VERIFICATION_ENABLED")
gpg_home_dir: Path = Field(default=Path("/var/catnet/.gnupg"), env="GPG_HOME_DIR")
gpg_trusted_keys: List[str] = Field(default=[], env="GPG_TRUSTED_KEYS")
gpg_reject_untrusted: bool = Field(default=True, env="GPG_REJECT_UNTRUSTED")
gpg_require_signatures: bool = Field(default=True, env="GPG_REQUIRE_SIGNATURES")
```

### Environment Variables

```bash
# .env
GPG_VERIFICATION_ENABLED=true
GPG_HOME_DIR=/var/catnet/.gnupg
GPG_TRUSTED_KEYS=ABCD1234,EFGH5678  # Key fingerprints
GPG_REJECT_UNTRUSTED=true
GPG_REQUIRE_SIGNATURES=true
```

## Testing

### Unit Tests

```python
# tests/unit/gitops/test_gpg_verification.py
import pytest
from unittest.mock import Mock, patch
from src.gitops.workflow import GitRepositoryManager
from src.core.exceptions import SecurityError

@pytest.fixture
def repo_manager():
    return GitRepositoryManager()

@pytest.mark.asyncio
async def test_gpg_verification_valid_signature(repo_manager, tmp_path):
    """Test GPG verification accepts valid signatures."""
    # Setup test repo with signed commit
    # ...
    result = await repo_manager.verify_commit_signature(repo, "valid_commit")
    assert result is True

@pytest.mark.asyncio
async def test_gpg_verification_rejects_unsigned(repo_manager):
    """Test GPG verification rejects unsigned commits."""
    with pytest.raises(SecurityError) as exc_info:
        await repo_manager.verify_commit_signature(repo, "unsigned_commit")

    assert "not signed" in str(exc_info.value).lower()

@pytest.mark.asyncio
async def test_gpg_verification_rejects_untrusted_key(repo_manager):
    """Test GPG verification rejects untrusted keys."""
    with pytest.raises(SecurityError) as exc_info:
        await repo_manager.verify_commit_signature(repo, "untrusted_commit")

    assert "untrusted" in str(exc_info.value).lower()

@pytest.mark.asyncio
async def test_gpg_verification_rejects_bad_signature(repo_manager):
    """Test GPG verification detects tampered commits."""
    with pytest.raises(SecurityError) as exc_info:
        await repo_manager.verify_commit_signature(repo, "tampered_commit")

    assert "bad" in str(exc_info.value).lower() or "tamper" in str(exc_info.value).lower()
```

### Integration Tests

```python
# tests/integration/test_gitops_gpg.py
@pytest.mark.integration
@pytest.mark.asyncio
async def test_gitops_workflow_with_gpg():
    """Test complete GitOps workflow with GPG verification."""

    # Create signed commit
    # Trigger webhook
    # Verify deployment created
    # Ensure GPG verified before deployment

    pass
```

## Documentation

### User Guide

**docs/GPG_SETUP.md:**

```markdown
# GPG Commit Signing Setup

## For Developers

### 1. Generate GPG Key

\`\`\`bash
# Generate key
gpg --full-generate-key

# Select:
# - RSA and RSA
# - 4096 bits
# - Expires in 1 year
# - Your name and email

# List keys
gpg --list-secret-keys --keyid-format LONG
\`\`\`

### 2. Configure Git

\`\`\`bash
# Set signing key
git config --global user.signingkey <YOUR_KEY_ID>

# Sign all commits
git config --global commit.gpgsign true

# Verify
git config --get commit.gpgsign
\`\`\`

### 3. Export Public Key

\`\`\`bash
# Export for sharing
gpg --armor --export <YOUR_KEY_ID> > my-public-key.asc

# Upload to keyserver
gpg --send-keys <YOUR_KEY_ID>
\`\`\`

### 4. Test Signing

\`\`\`bash
# Make a signed commit
git commit -S -m "Test signed commit"

# Verify signature
git log --show-signature
\`\`\`

## For Administrators

### 1. Import Developer Keys

\`\`\`bash
# Import from file
gpg --homedir /var/catnet/.gnupg --import developer-keys.asc

# Import from keyserver
gpg --homedir /var/catnet/.gnupg --recv-keys <KEY_ID>
\`\`\`

### 2. Trust Keys

\`\`\`bash
gpg --homedir /var/catnet/.gnupg --edit-key <KEY_ID>
> trust
> 5  # Ultimate trust
> quit
\`\`\`

### 3. Configure CatNet

\`\`\`bash
# Enable GPG verification
echo "GPG_VERIFICATION_ENABLED=true" >> .env
echo "GPG_HOME_DIR=/var/catnet/.gnupg" >> .env

# Restart services
docker-compose restart
\`\`\`

## Troubleshooting

### "gpg: cannot open tty"

\`\`\`bash
export GPG_TTY=$(tty)
\`\`\`

### "No secret key"

\`\`\`bash
# Ensure key is in keyring
gpg --list-secret-keys

# Generate if missing
gpg --full-generate-key
\`\`\`

### "Untrusted key"

\`\`\`bash
# Trust the key
gpg --edit-key <KEY_ID> trust
\`\`\`
```

## Rollout Plan

### Phase 1: Development (Week 1)
- Implement GPG verification
- Unit tests
- Documentation

### Phase 2: Staging (Week 2)
- Deploy to staging
- Test with real signed commits
- Train team on GPG signing

### Phase 3: Production (Week 3)
- Enable GPG verification in production
- Monitor for issues
- Support team with GPG setup

## Success Criteria

✅ **Complete when:**
- [ ] GPG verification implemented
- [ ] All signature statuses handled (G, U, B, N, X, Y, R, E)
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Documentation complete
- [ ] Team trained on GPG signing
- [ ] All repos configured for signed commits

---

**Recommendation:** Use **Option 1 (GitPython Built-in)** for simplicity and fewer dependencies.

**Implementation Time:** 4-6 hours (coding + testing + documentation)
