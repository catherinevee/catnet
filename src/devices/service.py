"""
Device Service - Main device management service
"""
from typing import Dict, List, Optional, Any
from datetime import datetime
from uuid import UUID

from ..core.logging import get_logger
from ..db.models import Device, DeviceVendor
from .connector import SecureDeviceConnector
from .ssh_manager import SSHKeyManager
from ..security.vault import VaultClient

logger = get_logger(__name__)


class DeviceService:
    """Main device management service"""

    def __init__(self):
        self.connector = SecureDeviceConnector()
        self.vault = VaultClient()
        self.ssh_manager = SSHKeyManager(self.vault)

    async def connect_to_device(
        self, device_id: str, user_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Connect to a network device"""
        logger.info(f"Connecting to device {device_id}")

        try:
            connection = await self.connector.connect_to_device(
                device_id, user_context
            )

            if connection:
                return {
                    "success": True,
                    "device_id": device_id,
                    "connection_id": connection.connection_id,
                    "session_id": connection.session_id,
                }
            else:
                return {
                    "success": False,
                    "device_id": device_id,
                    "error": "Failed to connect",
                }

        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return {
                "success": False,
                "device_id": device_id,
                "error": str(e),
            }

    async def execute_command(
        self,
        device_id: str,
        command: str,
        user_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute command on device"""
        logger.info(f"Executing command on device {device_id}")

        try:
            connection = await self.connector.connect_to_device(
                device_id, user_context
            )

            if connection:
                output = await connection.execute_command(command)
                await connection.disconnect()

                return {
                    "success": True,
                    "device_id": device_id,
                    "command": command,
                    "output": output,
                }
            else:
                return {
                    "success": False,
                    "device_id": device_id,
                    "error": "Failed to connect",
                }

        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return {
                "success": False,
                "device_id": device_id,
                "error": str(e),
            }

    async def backup_device_config(
        self, device_id: str, user_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Backup device configuration"""
        logger.info(f"Backing up configuration for device {device_id}")

        try:
            connection = await self.connector.connect_to_device(
                device_id, user_context
            )

            if connection:
                config = await connection.backup_configuration()
                await connection.disconnect()

                # Store backup (would save to database)
                backup_id = (
                    f"backup_{device_id}_{datetime.utcnow().isoformat()}"
                )

                return {
                    "success": True,
                    "device_id": device_id,
                    "backup_id": backup_id,
                    "size": len(config),
                }
            else:
                return {
                    "success": False,
                    "device_id": device_id,
                    "error": "Failed to connect",
                }

        except Exception as e:
            logger.error(f"Backup failed: {e}")
            return {
                "success": False,
                "device_id": device_id,
                "error": str(e),
            }

    async def get_device_info(self, device_id: str) -> Dict[str, Any]:
        """Get device information"""
        # Would fetch from database
        return {
            "device_id": device_id,
            "hostname": "router1",
            "ip_address": "192.168.1.1",
            "vendor": "cisco_ios",
            "model": "ISR4451",
            "status": "active",
            "last_seen": datetime.utcnow().isoformat(),
        }

    async def list_devices(
        self,
        vendor: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List devices with optional filters"""
        # Would query from database
        devices = []

        # Mock data
        sample_device = {
            "device_id": "device1",
            "hostname": "router1",
            "ip_address": "192.168.1.1",
            "vendor": "cisco_ios",
            "status": "active",
        }

        if not vendor or vendor == "cisco_ios":
            if not status or status == "active":
                devices.append(sample_device)

        return devices

    async def update_device_ssh_key(
        self, device_id: str, user_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update SSH key for device"""
        logger.info(f"Updating SSH key for device {device_id}")

        try:
            # Rotate SSH key
            result = await self.ssh_manager.rotate_ssh_key(device_id)

            return {
                "success": True,
                "device_id": device_id,
                "new_fingerprint": result.get("public_key", "")[:50] + "...",
                "rotated_at": result.get("rotated_at"),
            }

        except Exception as e:
            logger.error(f"SSH key update failed: {e}")
            return {
                "success": False,
                "device_id": device_id,
                "error": str(e),
            }
