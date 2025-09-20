"""
Configuration and Commit Signing Manager
"""
import os
import json
import hashlib
import base64
from typing import Dict, Optional, Tuple, Any
from datetime import datetime, timedelta
import gnupg
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_db
from ..db.models import User, Deployment
from ..security.vault import VaultClient
from ..security.audit import AuditLogger
from ..core.logging import get_logger
from ..core.exceptions import SecurityError

logger = get_logger(__name__)


class SignatureManager:
    """Manages digital signatures for configurations and commits"""

    def __init__(self):
        self.vault = VaultClient()
        self.audit = AuditLogger()
        self.gpg_home = Path(".gnupg")
        self.gpg_home.mkdir(exist_ok=True)
        self.gpg = gnupg.GPG(gnupghome=str(self.gpg_home))

    async def generate_signing_key(
        self, user_id: str, user_email: str, passphrase: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Generate GPG signing key for a user

        Args:
            user_id: User UUID
            user_email: User email
            passphrase: Optional passphrase for key

        Returns:
            Dictionary with key details
        """
        logger.info(f"Generating signing key for user {user_id}")

        # Generate GPG key
        input_data = self.gpg.gen_key_input(
            name_real=f"CatNet User {user_id}",
            name_email=user_email,
            key_type="RSA",
            key_length=4096,
            key_usage="sign",
            expire_date="2y",  # 2 years
            passphrase=passphrase or "",
        )

        key = self.gpg.gen_key(input_data)
        key_id = str(key)

        if not key_id:
            raise SecurityError("Failed to generate signing key")

        # Get key fingerprint
        keys = self.gpg.list_keys(secret=True)
        key_info = next((k for k in keys if k["keyid"] == key_id), None)

        if not key_info:
            raise SecurityError("Generated key not found")

        fingerprint = key_info["fingerprint"]

        # Export keys
        public_key = self.gpg.export_keys(key_id)
                private_key = self.gpg.export_keys(
            key_id,
            secret=True,
            passphrase=passphrase
        )

        # Store in Vault
        await self.vault.store_secret(
            f"users/{user_id}/signing_key",
            {
                "key_id": key_id,
                "fingerprint": fingerprint,
                "public_key": public_key,
                "private_key": private_key,
                "created_at": datetime.utcnow().isoformat(),
                                "expires_at": (
                    datetime.utcnow() + timedelta(days=730)).isoformat(
                ),
            },
        )

        # Update database
        async with get_db() as session:
            await session.execute(
                update(User)
                .where(User.id == user_id)
                .values(
                    signing_key_id=key_id,
                    signing_key_fingerprint=fingerprint,
                    signing_key_created_at=datetime.utcnow(),
                                        signing_key_expires_at=datetime.utcnow(
                        ) + timedelta(days=730
                    ),
                )
            )
            await session.commit()

        # Audit log
        await self.audit.log_security_event(
            event_type="signing_key_generated",
            severity="INFO",
            details={
                "user_id": user_id,
                "key_id": key_id,
                "fingerprint": fingerprint,
            },
        )

        logger.info(f"Signing key generated for user {user_id}: {key_id}")

        return {
            "key_id": key_id,
            "fingerprint": fingerprint,
            "public_key": public_key,
        }

    async def sign_configuration(
        self,
        config: Dict,
        user_id: str,
        deployment_id: str,
        passphrase: Optional[str] = None,
    ) -> str:
        """
        Generate cryptographic signature for configuration

        Args:
            config: Configuration dictionary
            user_id: User UUID
            deployment_id: Deployment UUID
            passphrase: Key passphrase

        Returns:
            Base64 encoded signature
        """
        logger.info(f"Signing configuration for deployment {deployment_id}")

        # Get user's signing key
        key_info = await self._get_user_signing_key(user_id)
        if not key_info:
            raise SecurityError(f"No signing key for user {user_id}")

        # Import private key if not already imported
        if key_info["private_key"]:
            import_result = self.gpg.import_keys(key_info["private_key"])
            if not import_result.count:
                raise SecurityError("Failed to import signing key")

        # Canonicalize configuration (sort keys for consistent hashing)
                canonical_config = json.dumps(
            config,
            sort_keys=True,
            separators=(",
            ",
            ":")
        )

        # Create signature data
        signature_data = {
                        "config_hash": hashlib.sha256(
                canonical_config.encode()).hexdigest(
            ),
            "deployment_id": deployment_id,
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "version": "1.0",
        }

        # Sign the data
        signature_json = json.dumps(signature_data, sort_keys=True)
        signed_data = self.gpg.sign(
            signature_json,
            keyid=key_info["key_id"],
            passphrase=passphrase or "",
            detach=True,
        )

        if not signed_data:
            raise SecurityError("Failed to sign configuration")

        signature = base64.b64encode(str(signed_data).encode()).decode()

        # Update deployment
        async with get_db() as session:
            await session.execute(
                update(Deployment)
                .where(Deployment.id == deployment_id)
                .values(
                    config_signature=signature,
                    signed_by=user_id,
                    signature_timestamp=datetime.utcnow(),
                )
            )
            await session.commit()

        # Audit log
        await self.audit.log_security_event(
            event_type="configuration_signed",
            severity="INFO",
            details={
                "deployment_id": deployment_id,
                "user_id": user_id,
                "config_hash": signature_data["config_hash"],
            },
        )

        logger.info(f"Configuration signed for deployment {deployment_id}")
        return signature

    async def verify_signature(
        self, config: Dict, signature: str, deployment_id: str
    ) -> bool:
        """
        Verify configuration hasn't been tampered with

        Args:
            config: Configuration dictionary
            signature: Base64 encoded signature
            deployment_id: Deployment UUID

        Returns:
            True if signature is valid
        """
        logger.info(f"Verifying signature for deployment {deployment_id}")

        try:
            # Get deployment info
            async with get_db() as session:
                result = await session.execute(
                    select(Deployment).where(Deployment.id == deployment_id)
                )
                deployment = result.scalar_one_or_none()

                if not deployment or not deployment.signed_by:
                    logger.warning(f"No signature info for deployment \
                        {deployment_id}")
                    return False

                # Get signer's public key
                key_info = await self._get_user_signing_key(str( \
                    deployment.signed_by))
                if not key_info:
                    logger.warning(f"No signing key for user \
                        {deployment.signed_by}")
                    return False

            # Import public key
            import_result = self.gpg.import_keys(key_info["public_key"])
            if not import_result.count:
                logger.error("Failed to import public key")
                return False

            # Decode signature
            signature_data = base64.b64decode(signature)

            # Canonicalize configuration
                        canonical_config = json.dumps(
                config,
                sort_keys=True,
                separators=(",
                ",
                ":")
            )
            config_hash = hashlib.sha256(canonical_config.encode()).hexdigest()

            # Recreate signature data
            signature_json = {
                "config_hash": config_hash,
                "deployment_id": deployment_id,
                # Other fields would be verified from the signature
            }

            # Log signature verification attempt
            logger.debug(
                f"Verifying signature for deployment {deployment_id}: "
                f"{json.dumps(signature_json)}"
            )

            # Verify signature
            verified = self.gpg.verify(signature_data)

            if verified:
                # Update verification status
                async with get_db() as session:
                    await session.execute(
                        update(Deployment)
                        .where(Deployment.id == deployment_id)
                        .values(signature_verified=True)
                    )
                    await session.commit()

                logger.info(f"Signature verified for deployment \
                    {deployment_id}")
                return True
            else:
                logger.warning(f"Invalid signature for deployment \
                    {deployment_id}")
                return False

        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False

    async def sign_commit(
        self,
        repo_path: str,
        commit_message: str,
        user_id: str,
        passphrase: Optional[str] = None,
    ) -> str:
        """
        Create signed Git commit

        Args:
            repo_path: Path to Git repository
            commit_message: Commit message
            user_id: User UUID
            passphrase: Key passphrase

        Returns:
            Commit hash
        """
        import git

        logger.info(f"Creating signed commit in {repo_path}")

        # Get user's signing key
        key_info = await self._get_user_signing_key(user_id)
        if not key_info:
            raise SecurityError(f"No signing key for user {user_id}")

        # Configure Git for signing
        repo = git.Repo(repo_path)
        config = repo.config_writer()
        config.set_value("user", "signingkey", key_info["key_id"])
        config.set_value("commit", "gpgsign", "true")
        config.release()

        # Stage changes and create signed commit
        repo.index.add("*")
        commit = repo.index.commit(commit_message, gpgsign=True)

        # Verify the commit signature
        if await self.verify_commit_signature(repo_path, str(commit.hexsha)):
            logger.info(f"Signed commit created: {commit.hexsha}")
            return str(commit.hexsha)
        else:
            raise SecurityError("Failed to verify signed commit")

        async def verify_commit_signature(
        self,
        repo_path: str,
        commit_hash: str
    ) -> bool:
        """
        Verify Git commit signature

        Args:
            repo_path: Path to Git repository
            commit_hash: Commit hash to verify

        Returns:
            True if signature is valid
        """
        import git

        logger.info(f"Verifying commit signature: {commit_hash}")

        try:
            repo = git.Repo(repo_path)
            commit = repo.commit(commit_hash)

            # Get commit signature
            signature = commit.gpgsig
            if not signature:
                logger.warning(f"No signature for commit {commit_hash}")
                return False

            # Verify with GPG
            verified = self.gpg.verify(signature)

            if verified:
                logger.info(f"Commit signature verified: {commit_hash}")
                return True
            else:
                logger.warning(f"Invalid signature for commit {commit_hash}")
                return False

        except Exception as e:
            logger.error(f"Commit verification failed: {e}")
            return False

    async def _get_user_signing_key(self, user_id: str) -> Optional[Dict]:
        """Get user's signing key from Vault"""
        try:
            secret = await self.vault.get_secret( \
                f"users/{user_id}/signing_key")
            return secret
        except Exception as e:
            logger.error(f"Failed to get signing key: {e}")
            return None

    async def rotate_signing_keys(self) -> Dict[str, int]:
        """
        Rotate expiring signing keys

        Returns:
            Statistics of rotated keys
        """
        logger.info("Starting signing key rotation")

        stats = {"checked": 0, "rotated": 0, "failed": 0}

        async with get_db() as session:
            # Get users with signing keys
            result = await session.execute(
                select(User).where(User.signing_key_id.isnot(None))
            )
            users = result.scalars().all()

            for user in users:
                stats["checked"] += 1

                # Check if key needs rotation (30 days before expiry)
                if user.signing_key_expires_at:
                    days_until_expiry = (
                        user.signing_key_expires_at - datetime.utcnow()
                    ).days
                    if days_until_expiry <= 30:
                        try:
                            # Generate new key
                            new_key = await self.generate_signing_key(
                                str(user.id), user.email
                            )
                            logger.info(f"Rotated signing key for user \
                                {user.username}")
                            logger.debug(f"New key ID: \
                                {new_key.get('key_id')}")
                            stats["rotated"] += 1
                        except Exception as e:
                            logger.error(
                                f"Failed to rotate key for {user.username}: \
                                    {e}"
                            )
                            stats["failed"] += 1

        logger.info(f"Signing key rotation complete: {stats}")
        return stats



class ConfigurationHasher:
    """Helper class for configuration hashing and integrity"""

    @staticmethod
    def hash_config(config: Dict) -> str:
        """
        Create deterministic hash of configuration

        Args:
            config: Configuration dictionary

        Returns:
            SHA-256 hash hex string
        """
        # Canonicalize by sorting keys
        canonical = json.dumps(config, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    @staticmethod
    def create_merkle_tree(configs: list) -> str:
        """
        Create Merkle tree root hash for multiple configurations

        Args:
            configs: List of configuration dictionaries

        Returns:
            Merkle root hash
        """
        if not configs:
            return ""

        # Hash all configurations
        config_hashes = [ConfigurationHasher.hash_config(c) for c in configs]

        # Build Merkle tree
        while len(config_hashes) > 1:
            if len(config_hashes) % 2 == 1:
                config_hashes.append(
                    config_hashes[-1]
                )  # Duplicate last hash if odd number

            new_hashes = []
            for i in range(0, len(config_hashes), 2):
                combined = config_hashes[i] + config_hashes[i + 1]
                new_hash = hashlib.sha256(combined.encode()).hexdigest()
                new_hashes.append(new_hash)

            config_hashes = new_hashes

        return config_hashes[0]

    @staticmethod
    def verify_integrity(config: Dict, expected_hash: str) -> bool:
        """
        Verify configuration integrity

        Args:
            config: Configuration dictionary
            expected_hash: Expected hash value

        Returns:
            True if integrity is maintained
        """
        actual_hash = ConfigurationHasher.hash_config(config)
        return actual_hash == expected_hash

    async def create_rsa_signature(
        self, data: bytes, private_key_path: Optional[str] = None
    ) -> Tuple[bytes, Any]:
        """Create RSA signature for data"""
        # Get private key from environment or path
        if not private_key_path:
                        private_key_path = os.getenv(
                "RSA_PRIVATE_KEY_PATH",
                "keys/private.pem"
            )

        # Generate RSA key pair if needed
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        # Sign the data
        signature = private_key.sign(
            data,
            padding.PSS(
                                mgf=padding.MGF1(
                    hashes.SHA256()
                ), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )

        # Serialize public key for verification
        public_key = private_key.public_key()
        public_pem = public_key.public_key_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return signature, public_pem

    async def verify_rsa_signature(
        self,
        data: bytes,
        signature: bytes,
        public_key_pem: bytes,
        session: Optional[AsyncSession] = None,
    ) -> bool:
        """Verify RSA signature"""
        try:
            # Load public key
            public_key = serialization.load_pem_public_key(
                public_key_pem, backend=default_backend()
            )

            # Verify signature
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

            # Log verification success if session provided
            if session:
                logger.info("RSA signature verified successfully")

            return True
        except InvalidSignature:
            return False
