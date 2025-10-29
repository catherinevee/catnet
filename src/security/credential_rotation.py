"""
Credential Rotation Engine
Handles automated credential rotation for network devices
"""
import asyncio
from datetime import datetime, timedelta
from typing import List, Optional, Dict
import secrets
import string
import structlog

from src.db.models.credential_rotation import (
    CredentialRotationPolicy,
    CredentialRotationHistory,
    RotationStatus,
    RotationFrequency
)

logger = structlog.get_logger()


class CredentialRotationEngine:
    """
    Handles automated credential rotation for network devices

    Features:
    - Cryptographically secure password generation
    - Device credential updates via SSH/NETCONF
    - Vault integration for credential storage
    - Automatic rollback on failures
    - Comprehensive audit logging
    """

    def __init__(self):
        self.min_password_length = 24
        self.max_password_length = 32
        self.password_complexity_required = True

    def generate_password(self, length: int = 24) -> str:
        """
        Generate cryptographically secure password

        Args:
            length: Password length (default 24)

        Returns:
            Secure password meeting complexity requirements

        Complexity Requirements:
        - At least one lowercase letter
        - At least one uppercase letter
        - At least one digit
        - At least one special character (!@#$%^&*)
        """
        if length < self.min_password_length:
            length = self.min_password_length
        if length > self.max_password_length:
            length = self.max_password_length

        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*"
        all_chars = lowercase + uppercase + digits + special

        while True:
            # Generate password
            password = ''.join(secrets.choice(all_chars) for _ in range(length))

            # Verify complexity requirements
            if (any(c in lowercase for c in password)
                and any(c in uppercase for c in password)
                and any(c in digits for c in password)
                and any(c in special for c in password)):
                return password

    async def rotate_device_credentials(
        self,
        device_id: str,
        policy: CredentialRotationPolicy,
        initiated_by: str = "system"
    ) -> CredentialRotationHistory:
        """
        Rotate credentials for a single device

        Args:
            device_id: Device identifier
            policy: Rotation policy configuration
            initiated_by: User or system initiating rotation

        Returns:
            CredentialRotationHistory record

        Process:
        1. Generate new secure password
        2. Retrieve current credentials from Vault
        3. Connect to device with current credentials
        4. Update password on device
        5. Verify new password works
        6. Store new credentials in Vault
        7. Update rotation schedule
        8. Rollback if any step fails
        """
        history = CredentialRotationHistory(
            policy_id=policy.id,
            device_id=device_id,
            status=RotationStatus.IN_PROGRESS,
            started_at=datetime.utcnow(),
            rotated_by=initiated_by
        )

        try:
            logger.info(
                "Starting credential rotation",
                device_id=device_id,
                policy_id=policy.id,
                initiated_by=initiated_by
            )

            # Step 1: Generate new password
            new_password = self.generate_password()
            logger.debug("New password generated", device_id=device_id)

            # Step 2: Get current credentials from Vault
            # Import here to avoid circular dependencies
            from src.security.vault_client import vault_client

            old_creds = await vault_client.get_device_credentials(device_id)
            history.old_credential_path = old_creds.get("_path")
            logger.debug("Retrieved current credentials from Vault", device_id=device_id)

            # Step 3: Connect to device with current credentials
            from src.devices.secure_connector import secure_device_connector

            async with secure_device_connector.connect(device_id) as conn:
                # Step 4: Update password on device
                await self._update_device_password(
                    conn,
                    old_creds['username'],
                    new_password,
                    device_id
                )
                logger.debug("Password updated on device", device_id=device_id)

            # Step 5: Verify new password works
            await self._verify_new_password(
                device_id,
                old_creds['username'],
                new_password
            )
            logger.debug("New password verified", device_id=device_id)

            # Step 6: Store new credentials in Vault
            new_path = await vault_client.store_device_credentials(
                device_id,
                username=old_creds['username'],
                password=new_password,
                version=f"{datetime.utcnow().isoformat()}"
            )
            history.new_credential_path = new_path
            logger.debug("New credentials stored in Vault", device_id=device_id)

            # Step 7: Update rotation policy next rotation time
            await self._schedule_next_rotation(policy)
            logger.debug("Next rotation scheduled", device_id=device_id, next_rotation=policy.next_rotation)

            # Mark as completed
            history.status = RotationStatus.COMPLETED
            history.completed_at = datetime.utcnow()
            history.calculate_duration()

            logger.info(
                "Credential rotation successful",
                device_id=device_id,
                duration_seconds=history.duration_seconds,
                policy_id=policy.id
            )

        except Exception as e:
            history.status = RotationStatus.FAILED
            history.error_message = str(e)
            history.completed_at = datetime.utcnow()
            history.calculate_duration()

            logger.error(
                "Credential rotation failed",
                device_id=device_id,
                error=str(e),
                policy_id=policy.id,
                duration_seconds=history.duration_seconds
            )

            # Auto-rollback if configured
            if policy.auto_rollback_on_failure:
                try:
                    await self._rollback_rotation(history)
                except Exception as rollback_error:
                    logger.error(
                        "Rollback also failed",
                        device_id=device_id,
                        rollback_error=str(rollback_error)
                    )

        return history

    async def _update_device_password(
        self,
        connection,
        username: str,
        new_password: str,
        device_id: str
    ):
        """
        Update password on the device based on vendor type

        Args:
            connection: Device connection object
            username: Username to update
            new_password: New password
            device_id: Device identifier for logging

        Supports:
        - Cisco IOS
        - Cisco NX-OS
        - Juniper Junos
        """
        device_type = connection.device_type

        logger.debug(
            "Updating password on device",
            device_id=device_id,
            device_type=device_type,
            username=username
        )

        # Cisco IOS
        if device_type == "cisco_ios":
            commands = [
                "configure terminal",
                f"username {username} secret {new_password}",
                "end",
                "write memory"
            ]
            output = await connection.send_config_set(commands)
            logger.debug("Cisco IOS password updated", device_id=device_id, output=output[:200])

        # Cisco NX-OS
        elif device_type == "cisco_nxos":
            commands = [
                "configure terminal",
                f"username {username} password {new_password}",
                "end",
                "copy running-config startup-config"
            ]
            output = await connection.send_config_set(commands)
            logger.debug("Cisco NX-OS password updated", device_id=device_id, output=output[:200])

        # Juniper Junos
        elif device_type == "juniper_junos":
            commands = [
                "configure",
                f"set system login user {username} authentication plain-text-password",
                new_password,  # Junos prompts for password
                new_password,  # Confirm password
                "commit and-quit"
            ]
            output = await connection.send_config_set(commands)
            logger.debug("Juniper Junos password updated", device_id=device_id, output=output[:200])

        else:
            raise Exception(f"Unsupported device type for credential rotation: {device_type}")

    async def _verify_new_password(
        self,
        device_id: str,
        username: str,
        password: str
    ):
        """
        Verify new credentials work by establishing a test connection

        Args:
            device_id: Device identifier
            username: Username to test
            password: Password to test

        Raises:
            Exception if verification fails
        """
        from src.devices.secure_connector import secure_device_connector

        logger.debug("Verifying new password", device_id=device_id, username=username)

        try:
            # Temporarily override credentials for verification
            async with secure_device_connector.connect(
                device_id,
                override_username=username,
                override_password=password
            ) as conn:
                # Simple command to verify connectivity
                result = await conn.send_command("show version")

                if not result or len(result) < 10:
                    raise Exception("Verification command returned insufficient data")

                logger.debug(
                    "Password verification successful",
                    device_id=device_id,
                    response_length=len(result)
                )

        except Exception as e:
            logger.error("Password verification failed", device_id=device_id, error=str(e))
            raise Exception(f"Failed to verify new credentials: {str(e)}")

    async def _schedule_next_rotation(self, policy: CredentialRotationPolicy):
        """
        Calculate and update next rotation time based on frequency

        Args:
            policy: Rotation policy to update
        """
        now = datetime.utcnow()

        if policy.frequency == RotationFrequency.DAILY:
            policy.next_rotation = now + timedelta(days=1)
        elif policy.frequency == RotationFrequency.WEEKLY:
            policy.next_rotation = now + timedelta(weeks=1)
        elif policy.frequency == RotationFrequency.MONTHLY:
            policy.next_rotation = now + timedelta(days=30)
        elif policy.frequency == RotationFrequency.QUARTERLY:
            policy.next_rotation = now + timedelta(days=90)
        elif policy.frequency == RotationFrequency.MANUAL:
            # Manual frequency doesn't auto-schedule
            pass

        logger.debug(
            "Next rotation scheduled",
            policy_id=policy.id,
            frequency=policy.frequency,
            next_rotation=policy.next_rotation
        )

    async def _rollback_rotation(self, history: CredentialRotationHistory):
        """
        Rollback failed rotation by restoring old credentials

        Args:
            history: Rotation history record with old credential path

        Process:
        1. Retrieve old credentials from Vault
        2. Make them active again
        3. Update history status
        """
        logger.warning(
            "Rolling back failed rotation",
            device_id=history.device_id,
            history_id=history.id
        )

        try:
            from src.security.vault_client import vault_client

            # Restore old credentials from Vault
            if history.old_credential_path:
                old_creds = await vault_client.get_credentials_by_path(
                    history.old_credential_path
                )

                await vault_client.store_device_credentials(
                    history.device_id,
                    username=old_creds['username'],
                    password=old_creds['password']
                )

                history.status = RotationStatus.ROLLED_BACK

                logger.info(
                    "Rotation rolled back successfully",
                    device_id=history.device_id,
                    history_id=history.id
                )
            else:
                logger.error(
                    "Cannot rollback - no old credential path",
                    device_id=history.device_id
                )

        except Exception as e:
            logger.error(
                "Rollback failed",
                device_id=history.device_id,
                error=str(e)
            )
            raise

    async def rotate_multiple_devices(
        self,
        device_ids: List[str],
        policies: Dict[str, CredentialRotationPolicy],
        initiated_by: str = "system",
        max_concurrent: int = 10
    ) -> List[CredentialRotationHistory]:
        """
        Rotate credentials for multiple devices concurrently

        Args:
            device_ids: List of device identifiers
            policies: Mapping of device_id to rotation policy
            initiated_by: User or system initiating rotation
            max_concurrent: Maximum concurrent rotations

        Returns:
            List of rotation history records
        """
        logger.info(
            "Starting batch credential rotation",
            device_count=len(device_ids),
            max_concurrent=max_concurrent,
            initiated_by=initiated_by
        )

        # Create semaphore to limit concurrency
        semaphore = asyncio.Semaphore(max_concurrent)

        async def rotate_with_limit(device_id: str):
            async with semaphore:
                policy = policies.get(device_id)
                if not policy:
                    logger.error("No policy found for device", device_id=device_id)
                    return None

                return await self.rotate_device_credentials(
                    device_id,
                    policy,
                    initiated_by
                )

        # Execute rotations concurrently with limit
        tasks = [rotate_with_limit(device_id) for device_id in device_ids]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out None results and exceptions
        histories = [r for r in results if isinstance(r, CredentialRotationHistory)]

        successful = sum(1 for h in histories if h.status == RotationStatus.COMPLETED)
        failed = sum(1 for h in histories if h.status == RotationStatus.FAILED)

        logger.info(
            "Batch rotation completed",
            total=len(device_ids),
            successful=successful,
            failed=failed
        )

        return histories


# Global instance
credential_rotation_engine = CredentialRotationEngine()
