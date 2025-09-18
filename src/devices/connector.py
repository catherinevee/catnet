import asyncio
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import uuid
import io
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from paramiko import SSHClient, AutoAddPolicy, RSAKey, Ed25519Key
from ..security.vault import VaultClient
from ..security.audit import AuditLogger
from ..db.models import Device, DeviceVendor
from .ssh_manager import SSHKeyManager, SSHDeviceConnector
import paramiko


class UnauthorizedException(Exception):
    pass


class DeviceConnection:
    def __init__(
        self,
        connection_id: str,
        device: Device,
        connection_handler: Any,
        audit_logger: AuditLogger,
    ):
        self.connection_id = connection_id
        self.device = device
        self.handler = connection_handler
        self.audit = audit_logger
        self.session_id = str(uuid.uuid4())
        self.connected_at = datetime.utcnow()
        self.commands_executed = []

    async def execute_command(self, command: str, enable_mode: bool = False) -> str:
        try:
            # Record command for audit
            self.commands_executed.append(
                {
                    "command": command,
                    "timestamp": datetime.utcnow().isoformat(),
                    "enable_mode": enable_mode,
                }
            )

            # Execute command
            if enable_mode and hasattr(self.handler, "enable"):
                self.handler.enable()

            output = await asyncio.get_event_loop().run_in_executor(
                None, self.handler.send_command, command
            )

            # Record output for audit
            await self.audit.record_command(self.session_id, command, output)

            return output

        except Exception as e:
            await self.audit.log_event(
                event_type="command_execution_failed",
                user_id=None,
                details={
                    "device_id": str(self.device.id),
                    "command": command,
                    "error": str(e),
                },
            )
            raise

    async def execute_config_commands(self, commands: List[str]) -> str:
        try:
            # Record configuration change
            await self.audit.log_event(
                event_type="configuration_change_started",
                user_id=None,
                details={
                    "device_id": str(self.device.id),
                    "commands_count": len(commands),
                },
            )

            # Execute configuration commands
            output = await asyncio.get_event_loop().run_in_executor(
                None, self.handler.send_config_set, commands
            )

            return output

        except Exception as e:
            await self.audit.log_event(
                event_type="configuration_change_failed",
                user_id=None,
                details={"device_id": str(self.device.id), "error": str(e)},
            )
            raise

    async def backup_configuration(self) -> str:
        vendor = self.device.vendor

        if vendor in [DeviceVendor.CISCO_IOS, DeviceVendor.CISCO_IOS_XE]:
            command = "show running-config"
        elif vendor == DeviceVendor.CISCO_NX_OS:
            command = "show running-config"
        elif vendor == DeviceVendor.JUNIPER_JUNOS:
            command = "show configuration | display set"
        else:
            raise ValueError(f"Unsupported vendor: {vendor}")

        return await self.execute_command(command)

    async def save_configuration(self) -> str:
        vendor = self.device.vendor

        if vendor in [DeviceVendor.CISCO_IOS, DeviceVendor.CISCO_IOS_XE]:
            command = "write memory"
        elif vendor == DeviceVendor.CISCO_NX_OS:
            command = "copy running-config startup-config"
        elif vendor == DeviceVendor.JUNIPER_JUNOS:
            command = "commit"
        else:
            raise ValueError(f"Unsupported vendor: {vendor}")

        return await self.execute_command(command, enable_mode=True)

    async def disconnect(self):
        try:
            if self.handler:
                self.handler.disconnect()

            await self.audit.end_session_recording(self.session_id)

        except Exception as e:
            print(f"Error disconnecting: {e}")

    def __del__(self):
        try:
            if hasattr(self, "handler") and self.handler:
                self.handler.disconnect()
        except Exception:
            pass


class SecureDeviceConnector:
    def __init__(
        self,
        vault_client: Optional[VaultClient] = None,
        audit_logger: Optional[AuditLogger] = None,
    ):
        self.vault = vault_client or VaultClient()
        self.audit = audit_logger or AuditLogger()
        self.active_connections = {}
        self.bastion_hosts = {
            "us-east": "bastion1.example.com",
            "us-west": "bastion2.example.com",
            "eu-west": "bastion3.example.com",
        }
        self.ssh_manager = SSHKeyManager(self.vault)
        self.ssh_connector = SSHDeviceConnector(self.ssh_manager)

    async def check_authorization(
        self, user_context: Dict[str, Any], device_id: str
    ) -> bool:
        # Check user permissions
        required_permission = "device.connect"
        user_roles = user_context.get("roles", [])

        # Admin always has access
        if "admin" in user_roles:
            return True

        # Check specific device permissions
        user_permissions = user_context.get("permissions", [])
        if required_permission in user_permissions:
            return True

        return False

    def select_bastion(self, device: Device) -> Optional[str]:
        # Select bastion based on device location
        location = device.location or "default"

        if "us-east" in location.lower():
            return self.bastion_hosts.get("us-east")
        elif "us-west" in location.lower():
            return self.bastion_hosts.get("us-west")
        elif "eu" in location.lower():
            return self.bastion_hosts.get("eu-west")

        return device.bastion_host

    async def establish_secure_connection(
        self,
        device: Device,
        credentials: Dict[str, Any],
        jump_host: Optional[str] = None,
    ) -> Any:
        # Map vendor to device type
        device_type_map = {
            DeviceVendor.CISCO_IOS: "cisco_ios",
            DeviceVendor.CISCO_IOS_XE: "cisco_xe",
            DeviceVendor.CISCO_NX_OS: "cisco_nxos",
            DeviceVendor.JUNIPER_JUNOS: "juniper_junos",
        }

        device_type = device_type_map.get(device.vendor)
        if not device_type:
            raise ValueError(f"Unsupported vendor: {device.vendor}")

        connection_params = {
            "device_type": device_type,
            "host": device.ip_address,
            "username": credentials["username"],
            "password": credentials["password"],
            "port": device.port or 22,
            "timeout": 30,
            "session_log": f"logs/sessions/{device.hostname}_{datetime.utcnow().isoformat()}.log",
        }

        # Add enable password if available
        if credentials.get("enable_password"):
            connection_params["secret"] = credentials["enable_password"]

        # Configure jump host if needed
        if jump_host:
            # Create SSH tunnel through bastion
            connection_params["ssh_config_file"] = self._create_ssh_config(
                device.ip_address, jump_host
            )

        # Establish connection
        loop = asyncio.get_event_loop()
        connection = await loop.run_in_executor(
            None, ConnectHandler, **connection_params
        )

        return connection

    def _create_ssh_config(self, target_host: str, jump_host: str) -> str:
        # Create temporary SSH config for jump host
        import tempfile

        config_content = f"""
Host target
    HostName {target_host}
    ProxyJump {jump_host}
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
"""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".conf") as f:
            f.write(config_content)
            return f.name

    async def connect_to_device(
        self, device_id: str, user_context: Dict[str, Any]
    ) -> Optional[DeviceConnection]:
        try:
            # Step 1: Verify user authorization
            if not await self.check_authorization(user_context, device_id):
                await self.audit.log_unauthorized_attempt(
                    user_context, f"device:{device_id}", "connect"
                )
                raise UnauthorizedException("Unauthorized access attempt")

            # Get device from database (mock for now)
            device = Device(
                id=device_id,
                hostname="router1",
                ip_address="192.168.1.1",
                vendor=DeviceVendor.CISCO_IOS,
                port=22,
            )

            # Step 2: Get temporary credentials from Vault
            creds = await self.vault.get_temporary_credentials(
                device_id=device_id,
                requestor=user_context["user_id"],
                ttl=1800,  # 30 minutes
            )

            # Step 3: Connect through bastion
            jump_host = self.select_bastion(device)
            connection = await self.establish_secure_connection(
                device=device, credentials=creds, jump_host=jump_host
            )

            # Step 4: Create DeviceConnection wrapper
            device_conn = DeviceConnection(
                connection_id=str(uuid.uuid4()),
                device=device,
                connection_handler=connection,
                audit_logger=self.audit,
            )

            # Step 5: Enable session recording
            await self.audit.start_session_recording(
                device_conn.session_id, user_context["user_id"], device_id
            )

            # Store active connection
            self.active_connections[device_conn.connection_id] = device_conn

            await self.audit.log_event(
                event_type="device_connected",
                user_id=user_context["user_id"],
                details={
                    "device_id": device_id,
                    "connection_id": device_conn.connection_id,
                    "session_id": device_conn.session_id,
                },
            )

            return device_conn

        except Exception as e:
            await self.audit.log_event(
                event_type="device_connection_failed",
                user_id=user_context.get("user_id"),
                details={"device_id": device_id, "error": str(e)},
            )
            raise

    async def connect_to_device_with_ssh_key(
        self, device_id: str, user_context: Dict[str, Any], use_ssh_key: bool = True
    ) -> Optional[DeviceConnection]:
        """Connect to device using SSH key authentication."""
        try:
            # Step 1: Verify user authorization
            if not await self.check_authorization(user_context, device_id):
                await self.audit.log_unauthorized_attempt(
                    user_context, f"device:{device_id}", "connect"
                )
                raise UnauthorizedException("Unauthorized access attempt")

            # Get device from database (mock for now)
            device = Device(
                id=device_id,
                hostname="router1",
                ip_address="192.168.1.1",
                vendor=DeviceVendor.CISCO_IOS,
                port=22,
            )

            # Step 2: Connect using SSH key
            if use_ssh_key:
                # Check if SSH key exists for device
                try:
                    ssh_key = await self.ssh_manager.get_ssh_key(device_id)

                    # Connect using SSH key
                    ssh_client = await self.ssh_connector.connect_with_key(device)

                    # Wrap in DeviceConnection
                    device_conn = DeviceConnection(
                        connection_id=str(uuid.uuid4()),
                        device=device,
                        connection_handler=ssh_client,
                        audit_logger=self.audit,
                    )

                    # Enable session recording
                    await self.audit.start_session_recording(
                        device_conn.session_id, user_context["user_id"], device_id
                    )

                    # Store active connection
                    self.active_connections[device_conn.connection_id] = device_conn

                    await self.audit.log_event(
                        event_type="device_connected_ssh_key",
                        user_id=user_context["user_id"],
                        details={
                            "device_id": device_id,
                            "connection_id": device_conn.connection_id,
                            "session_id": device_conn.session_id,
                            "auth_method": "ssh_key",
                        },
                    )

                    return device_conn

                except Exception as e:
                    # Fall back to credential-based authentication
                    return await self.connect_to_device(device_id, user_context)
            else:
                return await self.connect_to_device(device_id, user_context)

        except Exception as e:
            await self.audit.log_event(
                event_type="device_connection_failed",
                user_id=user_context.get("user_id"),
                details={"device_id": device_id, "error": str(e)},
            )
            raise

    async def disconnect_device(self, connection_id: str):
        if connection_id in self.active_connections:
            conn = self.active_connections[connection_id]
            await conn.disconnect()
            del self.active_connections[connection_id]

    async def execute_on_multiple_devices(
        self,
        device_ids: List[str],
        commands: List[str],
        user_context: Dict[str, Any],
        parallel: bool = True,
    ) -> Dict[str, Any]:
        results = {}

        if parallel:
            tasks = []
            for device_id in device_ids:
                task = self._execute_on_device(device_id, commands, user_context)
                tasks.append(task)

            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for device_id, response in zip(device_ids, responses):
                if isinstance(response, Exception):
                    results[device_id] = {"success": False, "error": str(response)}
                else:
                    results[device_id] = response
        else:
            for device_id in device_ids:
                try:
                    result = await self._execute_on_device(
                        device_id, commands, user_context
                    )
                    results[device_id] = result
                except Exception as e:
                    results[device_id] = {"success": False, "error": str(e)}

        return results

    async def _execute_on_device(
        self, device_id: str, commands: List[str], user_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        conn = None
        try:
            # Connect to device
            conn = await self.connect_to_device(device_id, user_context)

            # Execute commands
            outputs = []
            for command in commands:
                output = await conn.execute_command(command)
                outputs.append(output)

            return {"success": True, "outputs": outputs}

        finally:
            if conn:
                await conn.disconnect()
