from typing import Optional, Dict, Any, List
import asyncio
from netmiko import ConnectHandler
from napalm import get_network_driver
import structlog
import uuid
from datetime import datetime

from .vault import VaultClient
from .audit import AuditLogger
from ..db.models import Device, DeviceVendor

logger = structlog.get_logger()

class DeviceConnection:
    def __init__(self, connection, session_id: str, device_id: str):
        self.connection = connection
        self.session_id = session_id
        self.device_id = device_id
        self.start_time = datetime.utcnow()
        self.commands_executed = []

class SecureDeviceConnector:
    def __init__(self):
        self.vault = VaultClient()
        self.audit = AuditLogger()
        self.active_connections = {}
        self.bastion_hosts = self._load_bastion_hosts()

    def _load_bastion_hosts(self) -> Dict[str, str]:
        import os
        return {
            "us-east": os.getenv("BASTION_US_EAST", "bastion-us-east.catnet.internal"),
            "us-west": os.getenv("BASTION_US_WEST", "bastion-us-west.catnet.internal"),
            "eu-west": os.getenv("BASTION_EU_WEST", "bastion-eu-west.catnet.internal"),
            "ap-south": os.getenv("BASTION_AP_SOUTH", "bastion-ap-south.catnet.internal")
        }

    async def check_authorization(
        self,
        user_context: dict,
        device_id: str
    ) -> bool:
        try:
            user_role = user_context.get("role", "viewer")
            user_id = user_context.get("user_id")

            if user_role in ["admin", "operator"]:
                await self.audit.log_authorization_check(
                    user_id, device_id, True, user_role
                )
                return True

            if user_role == "viewer":
                await self.audit.log_authorization_check(
                    user_id, device_id, False, user_role
                )
                return False

            device_permissions = await self._get_device_permissions(user_id, device_id)
            authorized = device_id in device_permissions

            await self.audit.log_authorization_check(
                user_id, device_id, authorized, user_role
            )

            return authorized

        except Exception as e:
            logger.error(f"Authorization check failed: {e}")
            return False

    async def _get_device_permissions(
        self,
        user_id: str,
        device_id: str
    ) -> List[str]:
        try:
            permissions = await self.vault.get_secret(
                f"permissions/users/{user_id}/devices"
            )
            return permissions.get("allowed_devices", [])
        except:
            return []

    def select_bastion(self, device_id: str) -> Optional[str]:
        device_region = device_id.split("-")[0] if "-" in device_id else "us-east"
        return self.bastion_hosts.get(device_region, self.bastion_hosts["us-east"])

    async def establish_secure_connection(
        self,
        device_id: str,
        credentials: dict,
        jump_host: Optional[str] = None
    ) -> ConnectHandler:
        try:
            device = await self._get_device_info(device_id)

            device_params = {
                "device_type": self._map_vendor_to_netmiko(device.vendor),
                "host": device.ip_address,
                "username": credentials["username"],
                "password": credentials["password"],
                "port": 22,
                "timeout": 30,
                "session_log": f"/var/log/catnet/sessions/{device_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.log"
            }

            if jump_host:
                device_params["ssh_config_file"] = self._create_ssh_config(
                    device.ip_address, jump_host, credentials
                )

            connection = ConnectHandler(**device_params)

            await self.audit.log_device_connection(
                device_id=device_id,
                username=credentials["username"],
                source_ip=jump_host,
                success=True
            )

            return connection

        except Exception as e:
            await self.audit.log_device_connection(
                device_id=device_id,
                username=credentials.get("username"),
                source_ip=jump_host,
                success=False,
                error=str(e)
            )
            raise

    def _map_vendor_to_netmiko(self, vendor: DeviceVendor) -> str:
        vendor_map = {
            DeviceVendor.CISCO_IOS: "cisco_ios",
            DeviceVendor.CISCO_IOS_XE: "cisco_xe",
            DeviceVendor.CISCO_NX_OS: "cisco_nxos",
            DeviceVendor.JUNIPER_JUNOS: "juniper_junos"
        }
        return vendor_map.get(vendor, "cisco_ios")

    def _create_ssh_config(
        self,
        target_host: str,
        jump_host: str,
        credentials: dict
    ) -> str:
        import tempfile
        config_content = f"""
Host bastion
    HostName {jump_host}
    User {credentials['username']}
    Port 22

Host {target_host}
    ProxyJump bastion
    User {credentials['username']}
    Port 22
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ssh_config') as f:
            f.write(config_content)
            return f.name

    async def connect_to_device(
        self,
        device_id: str,
        user_context: dict
    ) -> Optional[DeviceConnection]:
        try:
            if not await self.check_authorization(user_context, device_id):
                await self.audit.log_unauthorized_attempt(user_context, device_id)
                raise UnauthorizedException(f"User {user_context['user_id']} not authorized for device {device_id}")

            creds = await self.vault.get_temporary_credentials(
                device_id=device_id,
                requestor=user_context['user_id'],
                ttl=1800
            )

            jump_host = self.select_bastion(device_id)

            connection = await self.establish_secure_connection(
                device_id=device_id,
                credentials=creds,
                jump_host=jump_host
            )

            session_id = str(uuid.uuid4())
            await self.audit.start_session_recording(session_id)

            device_connection = DeviceConnection(
                connection=connection,
                session_id=session_id,
                device_id=device_id
            )

            self.active_connections[session_id] = device_connection

            return device_connection

        except Exception as e:
            logger.error(f"Failed to connect to device {device_id}: {e}")
            raise

    async def execute_command(
        self,
        session_id: str,
        command: str,
        user_context: dict
    ) -> str:
        try:
            if session_id not in self.active_connections:
                raise ValueError(f"Invalid session ID: {session_id}")

            device_conn = self.active_connections[session_id]

            if not self._is_command_safe(command):
                await self.audit.log_dangerous_command_blocked(
                    user_context['user_id'],
                    device_conn.device_id,
                    command
                )
                raise ValueError(f"Command blocked for safety: {command}")

            result = device_conn.connection.send_command(command)

            device_conn.commands_executed.append({
                "command": command,
                "timestamp": datetime.utcnow().isoformat(),
                "result_length": len(result)
            })

            await self.audit.log_command_execution(
                session_id=session_id,
                user_id=user_context['user_id'],
                device_id=device_conn.device_id,
                command=command,
                success=True
            )

            return result

        except Exception as e:
            await self.audit.log_command_execution(
                session_id=session_id,
                user_id=user_context.get('user_id'),
                device_id=self.active_connections.get(session_id, {}).get('device_id'),
                command=command,
                success=False,
                error=str(e)
            )
            raise

    def _is_command_safe(self, command: str) -> bool:
        dangerous_commands = [
            "reload", "reboot", "shutdown",
            "write erase", "delete flash",
            "format", "request system zeroize"
        ]

        command_lower = command.lower().strip()
        for dangerous in dangerous_commands:
            if dangerous in command_lower:
                return False

        return True

    async def disconnect(
        self,
        session_id: str,
        user_context: dict
    ) -> bool:
        try:
            if session_id not in self.active_connections:
                return False

            device_conn = self.active_connections[session_id]

            device_conn.connection.disconnect()

            session_duration = (datetime.utcnow() - device_conn.start_time).total_seconds()

            await self.audit.log_session_end(
                session_id=session_id,
                user_id=user_context['user_id'],
                device_id=device_conn.device_id,
                duration=session_duration,
                commands_count=len(device_conn.commands_executed)
            )

            del self.active_connections[session_id]

            return True

        except Exception as e:
            logger.error(f"Failed to disconnect session {session_id}: {e}")
            return False

    async def _get_device_info(self, device_id: str) -> Device:
        from ..db.database import database

        async with database.get_session() as db:
            from sqlalchemy import select
            result = await db.execute(
                select(Device).where(Device.id == device_id)
            )
            device = result.scalar_one_or_none()

            if not device:
                raise ValueError(f"Device {device_id} not found")

            return device

    async def backup_device_config(
        self,
        device_id: str,
        user_context: dict
    ) -> str:
        try:
            device_conn = await self.connect_to_device(device_id, user_context)

            device = await self._get_device_info(device_id)

            if device.vendor in [DeviceVendor.CISCO_IOS, DeviceVendor.CISCO_IOS_XE]:
                config = await self.execute_command(
                    device_conn.session_id,
                    "show running-config",
                    user_context
                )
            elif device.vendor == DeviceVendor.CISCO_NX_OS:
                config = await self.execute_command(
                    device_conn.session_id,
                    "show running-config",
                    user_context
                )
            elif device.vendor == DeviceVendor.JUNIPER_JUNOS:
                config = await self.execute_command(
                    device_conn.session_id,
                    "show configuration | display set",
                    user_context
                )
            else:
                raise ValueError(f"Unsupported vendor: {device.vendor}")

            from .encryption import EncryptionHandler
            encryption = EncryptionHandler()
            encryption_key = await self.vault.get_encryption_key(f"device-{device_id}")

            encrypted_config = encryption.encrypt_config(config, encryption_key)

            backup_path = f"backups/{device_id}/{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            await self.vault.store_secret(backup_path, encrypted_config)

            await self.disconnect(device_conn.session_id, user_context)

            await self.audit.log_backup_created(
                device_id=device_id,
                user_id=user_context['user_id'],
                backup_path=backup_path
            )

            return backup_path

        except Exception as e:
            logger.error(f"Failed to backup device {device_id}: {e}")
            raise

class UnauthorizedException(Exception):
    pass