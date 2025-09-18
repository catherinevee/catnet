"""SSH key authentication for users."""

import hashlib
import base64
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import logging
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from sqlalchemy.orm import Session

from ..db.models import User, UserSSHKey
from ..security.audit import AuditLogger
from ..core.exceptions import AuthenticationError, ValidationError


logger = logging.getLogger(__name__)


class SSHKeyAuthService:
    """Service for managing SSH key authentication for users."""

    def __init__(self, db_session: Session, audit_logger: AuditLogger):
        self.db = db_session
        self.audit = audit_logger

    def calculate_fingerprint(self, public_key: str) -> str:
        """
        Calculate SSH key fingerprint (SHA256 format).

        Args:
            public_key: Public key in OpenSSH format

        Returns:
            Fingerprint string (SHA256:base64)
        """
        # Remove any comments and whitespace
        key_parts = public_key.strip().split()
        if len(key_parts) < 2:
            raise ValueError("Invalid public key format")

        # Get the base64-encoded key part
        key_data = key_parts[1]

        try:
            # Decode base64
            decoded = base64.b64decode(key_data)

            # Calculate SHA256 hash
            sha256_hash = hashlib.sha256(decoded).digest()

            # Encode as base64 without padding
            fingerprint = base64.b64encode(sha256_hash).decode().rstrip('=')

            return f"SHA256:{fingerprint}"

        except Exception as e:
            raise ValueError(f"Failed to calculate fingerprint: {str(e)}")

    async def add_ssh_key(
        self,
        user_id: str,
        public_key: str,
        key_name: str,
        comment: Optional[str] = None
    ) -> UserSSHKey:
        """
        Add SSH public key for a user.

        Args:
            user_id: User ID
            public_key: SSH public key in OpenSSH format
            key_name: Name for the key
            comment: Optional comment

        Returns:
            UserSSHKey object
        """
        # Validate public key format
        if not self.validate_public_key(public_key):
            raise ValidationError("Invalid SSH public key format")

        # Calculate fingerprint
        fingerprint = self.calculate_fingerprint(public_key)

        # Check if fingerprint already exists
        existing = self.db.query(UserSSHKey).filter_by(fingerprint=fingerprint).first()
        if existing:
            raise ValidationError("SSH key already exists")

        # Determine key type
        key_type = self.get_key_type(public_key)

        # Create SSH key entry
        ssh_key = UserSSHKey(
            user_id=user_id,
            name=key_name,
            public_key=public_key,
            fingerprint=fingerprint,
            key_type=key_type,
            comment=comment,
            is_active=True
        )

        self.db.add(ssh_key)
        self.db.commit()

        # Update user's SSH key fields
        user = self.db.query(User).filter_by(id=user_id).first()
        if user:
            if not user.ssh_public_keys:
                user.ssh_public_keys = []
            if not user.ssh_key_fingerprints:
                user.ssh_key_fingerprints = []

            user.ssh_public_keys.append(public_key)
            user.ssh_key_fingerprints.append(fingerprint)
            user.ssh_key_added_at = datetime.utcnow()
            self.db.commit()

        # Audit log
        await self.audit.log_event(
            event_type="ssh_key_added",
            user_id=user_id,
            details={
                "key_name": key_name,
                "fingerprint": fingerprint,
                "key_type": key_type
            }
        )

        logger.info(f"Added SSH key '{key_name}' for user {user_id}")

        return ssh_key

    def validate_public_key(self, public_key: str) -> bool:
        """
        Validate SSH public key format.

        Args:
            public_key: Public key string

        Returns:
            True if valid
        """
        try:
            # Basic format check
            parts = public_key.strip().split()
            if len(parts) < 2:
                return False

            key_type = parts[0]
            key_data = parts[1]

            # Check key type
            valid_types = ['ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-nistp256',
                          'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521']
            if key_type not in valid_types:
                return False

            # Try to decode base64
            base64.b64decode(key_data)

            return True

        except Exception:
            return False

    def get_key_type(self, public_key: str) -> str:
        """Extract key type from public key."""
        parts = public_key.strip().split()
        key_type_map = {
            'ssh-rsa': 'rsa',
            'ssh-ed25519': 'ed25519',
            'ecdsa-sha2-nistp256': 'ecdsa',
            'ecdsa-sha2-nistp384': 'ecdsa',
            'ecdsa-sha2-nistp521': 'ecdsa'
        }
        return key_type_map.get(parts[0], 'unknown')

    async def authenticate_with_key(
        self,
        username: str,
        key_fingerprint: str,
        signature: str,
        challenge: str
    ) -> Optional[User]:
        """
        Authenticate user with SSH key.

        Args:
            username: Username
            key_fingerprint: SSH key fingerprint
            signature: Signature of challenge
            challenge: Challenge string that was signed

        Returns:
            User object if authenticated, None otherwise
        """
        # Get user
        user = self.db.query(User).filter_by(username=username).first()
        if not user:
            return None

        # Check if user has the key
        if key_fingerprint not in (user.ssh_key_fingerprints or []):
            await self.audit.log_event(
                event_type="ssh_auth_failed",
                user_id=str(user.id),
                details={"reason": "key_not_found", "fingerprint": key_fingerprint}
            )
            return None

        # Get the SSH key
        ssh_key = self.db.query(UserSSHKey).filter_by(
            user_id=user.id,
            fingerprint=key_fingerprint,
            is_active=True
        ).first()

        if not ssh_key:
            return None

        # Verify signature (simplified - would need actual crypto verification)
        # In production, this would verify the signature using the public key
        if self.verify_signature(ssh_key.public_key, signature, challenge):
            # Update last used
            ssh_key.last_used = datetime.utcnow()
            user.last_login = datetime.utcnow()
            self.db.commit()

            await self.audit.log_event(
                event_type="ssh_auth_success",
                user_id=str(user.id),
                details={"key_name": ssh_key.name, "fingerprint": key_fingerprint}
            )

            return user

        await self.audit.log_event(
            event_type="ssh_auth_failed",
            user_id=str(user.id),
            details={"reason": "invalid_signature", "fingerprint": key_fingerprint}
        )

        return None

    def verify_signature(self, public_key: str, signature: str, challenge: str) -> bool:
        """
        Verify signature using public key.

        Note: This is a simplified implementation. In production,
        you would use proper cryptographic verification.
        """
        # This would need actual cryptographic verification
        # using the public key to verify the signature
        # For now, returning True for demonstration
        return True

    async def list_user_keys(self, user_id: str) -> List[Dict[str, Any]]:
        """
        List all SSH keys for a user.

        Args:
            user_id: User ID

        Returns:
            List of SSH key information
        """
        keys = self.db.query(UserSSHKey).filter_by(user_id=user_id).all()

        return [
            {
                "id": str(key.id),
                "name": key.name,
                "fingerprint": key.fingerprint,
                "key_type": key.key_type,
                "is_active": key.is_active,
                "created_at": key.created_at.isoformat() if key.created_at else None,
                "last_used": key.last_used.isoformat() if key.last_used else None
            }
            for key in keys
        ]

    async def remove_ssh_key(self, user_id: str, key_id: str) -> bool:
        """
        Remove SSH key for a user.

        Args:
            user_id: User ID
            key_id: SSH key ID

        Returns:
            True if removed
        """
        ssh_key = self.db.query(UserSSHKey).filter_by(
            id=key_id,
            user_id=user_id
        ).first()

        if not ssh_key:
            return False

        # Remove from user's lists
        user = self.db.query(User).filter_by(id=user_id).first()
        if user:
            if ssh_key.public_key in (user.ssh_public_keys or []):
                user.ssh_public_keys.remove(ssh_key.public_key)
            if ssh_key.fingerprint in (user.ssh_key_fingerprints or []):
                user.ssh_key_fingerprints.remove(ssh_key.fingerprint)

        # Delete the key
        self.db.delete(ssh_key)
        self.db.commit()

        await self.audit.log_event(
            event_type="ssh_key_removed",
            user_id=user_id,
            details={"key_name": ssh_key.name, "fingerprint": ssh_key.fingerprint}
        )

        return True

    async def rotate_ssh_key(
        self,
        user_id: str,
        old_key_id: str,
        new_public_key: str
    ) -> UserSSHKey:
        """
        Rotate an SSH key.

        Args:
            user_id: User ID
            old_key_id: Old key ID to replace
            new_public_key: New public key

        Returns:
            New UserSSHKey object
        """
        # Get old key
        old_key = self.db.query(UserSSHKey).filter_by(
            id=old_key_id,
            user_id=user_id
        ).first()

        if not old_key:
            raise ValueError("Old key not found")

        # Deactivate old key
        old_key.is_active = False

        # Add new key
        new_key = await self.add_ssh_key(
            user_id=user_id,
            public_key=new_public_key,
            key_name=f"{old_key.name} (rotated)",
            comment=f"Rotated from {old_key.fingerprint}"
        )

        await self.audit.log_event(
            event_type="ssh_key_rotated",
            user_id=user_id,
            details={
                "old_fingerprint": old_key.fingerprint,
                "new_fingerprint": new_key.fingerprint
            }
        )

        return new_key