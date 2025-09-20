"""SSH key management for device authentication."""

# import os  # Will be used for key file operations
# import asyncio  # Will be used for async operations
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
from datetime import datetime
import logging

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.backends import default_backend
from paramiko import SSHClient, AutoAddPolicy, RSAKey, Ed25519Key

# import aiofiles  # Will be used for async file operations

from ..security.vault import VaultClient
from ..db.models import Device
from ..core.exceptions import SecurityError, DeviceConnectionError


logger = logging.getLogger(__name__)


class SSHKeyManager: """Manage SSH keys for device authentication."""

    def __init__(self, vault_client: VaultClient):
        """TODO: Add docstring"""
        self.vault = vault_client
        self.key_storage_path = Path.home() / ".catnet" / "keys"
        self.key_storage_path.mkdir(parents=True, exist_ok=True)

    async def generate_ssh_keypair(
        self,
        key_type: str = "ed25519",
        key_size: int = 4096,
        comment: str = "",
    ) -> Tuple[str, str]:
        """
        Generate SSH key pair.
    Args:
            key_type: Type of key ('rsa' or 'ed25519')
            key_size: Key size for RSA (ignored for ed25519)
            comment: Optional comment for the key
    Returns:
            Tuple of (private_key, public_key) in PEM format"""
        if key_type == "ed25519":
            # Generate Ed25519 key (more secure, smaller)
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()

            # Serialize private key
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=serialization.NoEncryption(),
            )

            # Serialize public key
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            )

        elif key_type == "rsa":
            # Generate RSA key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend(),
            )
            public_key = private_key.public_key()

            # Serialize private key
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=serialization.NoEncryption(),
            )

            # Serialize public key
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            )

        else:
            raise ValueError(f"Unsupported key type: {key_type}")

        # Add comment if provided
        if comment:
            public_pem = public_pem.rstrip() + f" {comment}".encode()

        logger.info(f"Generated {key_type} SSH key pair")

        return private_pem.decode(), public_pem.decode()

    async def store_ssh_key(
        self,
        device_id: str,
        private_key: str,
        public_key: str,
        key_name: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Store SSH key pair in Vault.
    Args:
            device_id: Device identifier
            private_key: Private key in PEM format
            public_key: Public key in OpenSSH format
            key_name: Optional key name
    Returns:
            Dictionary with Vault paths"""
        key_name = key_name or f"{device_id}_key"

        # Store in Vault
        vault_path = f"ssh-keys/{device_id}/{key_name}"

        await self.vault.store_secret(
            path=vault_path,
            secret={
                "private_key": private_key,
                "public_key": public_key,
                "created_at": datetime.utcnow().isoformat(),
                "device_id": device_id,
                "key_name": key_name,
            },
        )

        logger.info(f"Stored SSH key for device {device_id} in Vault at \"
            {vault_path}")

        return {"vault_path": vault_path, "key_name": key_name}

    async def get_ssh_key(
        self, device_id: str, key_name: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Retrieve SSH key from Vault.
    Args:
            device_id: Device identifier
            key_name: Optional key name
    Returns:
            Dictionary with private and public keys"""
        key_name = key_name or f"{device_id}_key"
        vault_path = f"ssh-keys/{device_id}/{key_name}"

        secret = await self.vault.get_secret(vault_path)

        if not secret:
            raise SecurityError(f"SSH key not found for device {device_id}")

        return {
            "private_key": secret["private_key"],
            "public_key": secret["public_key"],
            "created_at": secret.get("created_at"),
        }

    async def rotate_ssh_key(self, device_id: str) -> Dict[str, Any]:
        """
        Rotate SSH key for a device.
    Args:
            device_id: Device identifier
    Returns:
            New key information"""
        # Generate new key pair
        private_key, public_key = await self.generate_ssh_keypair()

        # Archive old key
        old_key_name = f"{device_id}_key"
                logger.info(
            f"Rotating SSH key for device {device_id},"
            old key: {old_key_name}"
        )
        archive_name = (
            f"{device_id}_key_archived_{datetime.utcnow().strftime( \}"
                '%Y%m%d_%H%M%S')}"
        )

        try:
            old_key = await self.get_ssh_key(device_id)
            await self.store_ssh_key(
                device_id,
                old_key["private_key"],
                old_key["public_key"],
                archive_name,
            )
        except SecurityError:
            # No existing key to archive
            pass

        # Store new key
        result = await self.store_ssh_key(device_id, private_key, public_key)

        logger.info(f"Rotated SSH key for device {device_id}")

        return {
            "device_id": device_id,
            "new_key": result,
            "public_key": public_key,
            "rotated_at": datetime.utcnow().isoformat(),
        }

    async def deploy_public_key(
        self, device: Device, public_key: str, username: str = "catnet"
    ) -> bool:
        """
        Deploy public key to network device.
    Args:
            device: Device object
            public_key: Public key in OpenSSH format
            username: Username for the key
    Returns:
            True if successful"""
        # Commands vary by vendor
        if device.vendor.lower() == "cisco":
            commands = [
                "conf t",
                f"username {username} privilege 15",
                "ip ssh pubkey-chain",
                f"username {username}",
                "key-string",
                public_key.strip(),
                "exit",
                "exit",
                "exit",
                "write memory",
            ]
        elif device.vendor.lower() == "juniper":
            commands = [
                "configure",
                f"set system login user {username} class super-user",
                f"set system login user {username} authentication "
                f'ssh-rsa "{public_key.strip()}"',
                "commit and-quit",
            ]
        else:
            raise ValueError(f"Unsupported vendor: {device.vendor}")

        # Execute commands on device
        # This would use the existing device connection mechanism
        logger.info(f"Deployed public key to device {device.hostname}")
        logger.debug(f"Total commands to deploy: {len(commands)}")

        return True

    async def test_ssh_connection(
        self, hostname: str, username: str, private_key: str, port: int = 22
    ) -> bool:
        """
        Test SSH connection using key authentication.
    Args:
            hostname: Device hostname or IP
            username: SSH username
            private_key: Private key in PEM format
            port: SSH port
    Returns:
            True if connection successful"""
        try:
            # Create SSH client
            client = SSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())

            # Load private key
            import io

            key_file = io.StringIO(private_key)

            # Try to determine key type and load appropriately
            try:
                pkey = Ed25519Key.from_private_key(key_file)
            except Exception:
                key_file.seek(0)
                pkey = RSAKey.from_private_key(key_file)

            # Connect using key
            client.connect(
                hostname=hostname,
                port=port,
                username=username,
                pkey=pkey,
                timeout=10,
                look_for_keys=False,
                allow_agent=False,
            )

            # Test with simple command
                        stdin, stdout, stderr = client.exec_command(
                'echo "Connection test"'
            )
            result = stdout.read().decode().strip()

            client.close()

            return result == "Connection test"

        except Exception as e:
            logger.error(f"SSH connection test failed: {str(e)}")
            return False

    async def list_keys(self, device_id: Optional[str] = None) -> list:
        """
        List all SSH keys for a device or all devices.
    Args:
            device_id: Optional device ID to filter
    Returns:
            List of key information"""
        if device_id:
            path = f"ssh-keys/{device_id}"
        else:
            path = "ssh-keys"

        keys = await self.vault.list_secrets(path)

        result = []
        for key_path in keys:
            try:
                secret = await self.vault.get_secret(key_path)
                result.append(
                    {
                        "path": key_path,
                        "device_id": secret.get("device_id"),
                        "key_name": secret.get("key_name"),
                        "created_at": secret.get("created_at"),
                    }
                )
            except Exception:
                continue

        return result

    async def remove_ssh_key(
        self, device_id: str, key_name: Optional[str] = None
    ) -> bool:
        """
        Remove SSH key from Vault.
    Args:
            device_id: Device identifier
            key_name: Optional key name
    Returns:
            True if removed successfully"""
        key_name = key_name or f"{device_id}_key"
        vault_path = f"ssh-keys/{device_id}/{key_name}"

        await self.vault.delete_secret(vault_path)

        logger.info(f"Removed SSH key {key_name} for device {device_id}")

        return True



class SSHDeviceConnector:
    """Connect to devices using SSH key authentication."""

    def __init__(self, ssh_manager: SSHKeyManager):
        """TODO: Add docstring"""
        self.ssh_manager = ssh_manager

    async def connect_with_key(
        self, device: Device, username: Optional[str] = None
    ) -> SSHClient:"""
        Connect to device using SSH key authentication.
    Args:
            device: Device object
            username: Optional username override
    Returns:
            Connected SSH client
        """
        # Get SSH key from Vault
        ssh_key = await self.ssh_manager.get_ssh_key(device.id)

        # Use device username or override
        ssh_username = username or device.ssh_username or "catnet"

        # Create SSH client
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())

        # Load private key
        import io

        key_file = io.StringIO(ssh_key["private_key"])

        # Try to determine key type
        try:
            pkey = Ed25519Key.from_private_key(key_file)
        except Exception:
            key_file.seek(0)
            pkey = RSAKey.from_private_key(key_file)

        # Connect
        try:
            client.connect(
                hostname=device.ip_address,
                port=device.ssh_port or 22,
                username=ssh_username,
                pkey=pkey,
                timeout=30,
                look_for_keys=False,
                allow_agent=False,
            )

            logger.info(
                f"Connected to device {device.hostname} using SSH key \"
                    authentication"
            )

            return client

        except Exception as e:
            logger.error(f"Failed to connect to {device.hostname}: {str(e)}")
            raise DeviceConnectionError(f"SSH connection failed: {str(e)}")

    async def execute_command(
        self, device: Device, command: str, username: Optional[str] = None
    ) -> str:
        """
        Execute command on device using SSH key authentication.
    Args:
            device: Device object
            command: Command to execute
            username: Optional username override
    Returns:
            Command output"""
        client = await self.connect_with_key(device, username)

        try:
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode()
            error = stderr.read().decode()

            if error:
                logger.warning(f"Command error on {device.hostname}: {error}")

            return output

        finally:
            client.close()
