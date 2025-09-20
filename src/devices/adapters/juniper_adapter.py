"""
Juniper Device Adapter for CatNet

Supports:
- Juniper Junos
"""

from typing import Dict, Any
import asyncio
from datetime import datetime
from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.exception import (
    ConnectAuthError,
    ConnectTimeoutError,
    ConfigLoadError,
    CommitError,
)

from ..device_manager import (
    DeviceAdapter,
    DeviceInfo,
    DeviceCredentials,
    DeviceConnection,
    ConnectionProtocol,
)


class JuniperAdapter(DeviceAdapter):"""
    Juniper device adapter implementation
    """

    # Configuration commands
    CONFIG_COMMANDS = {
        "running": "show configuration",
        "candidate": "show configuration | compare",
        "version": "show version",
        "inventory": "show chassis hardware",
        "interfaces": "show interfaces terse",
        "routing": "show route summary",
    }

    def __init__(self):
        """Initialize Juniper adapter"""
        self.connections = {}
        self.connection_timeout = 30
        self.commit_timeout = 60
        self.auto_probe = True

    async def connect(
        self, device: DeviceInfo, credentials: DeviceCredentials
    ) -> DeviceConnection:"""
        Connect to Juniper device

        Args:
            device: Device information
            credentials: Device credentials

        Returns:
            DeviceConnection
        """
        import uuid

        connection_id = str(uuid.uuid4())[:12]

        # Build connection parameters
        device_params = self._build_connection_params(device, credentials)

        try:
            # Create device object
            dev = Device(**device_params)

            # Connect (run in executor for async)
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, dev.open, self.auto_probe)

            # Bind configuration utility
            dev.bind(Config)

            # Create connection object
            device_connection = DeviceConnection(
                device_id=device.id,
                connection_id=connection_id,
                protocol=device.protocol,
                established_at=datetime.utcnow(),
                session_data=dev,
                is_active=True,
            )

            # Store connection
            self.connections[connection_id] = device_connection

            return device_connection

        except ConnectAuthError as e:
            raise Exception(f"Authentication failed: {str(e)}")
        except ConnectTimeoutError as e:
            raise Exception(f"Connection timeout: {str(e)}")
        except Exception as e:
            raise Exception(f"Connection failed: {str(e)}")

    async def disconnect(self, connection: DeviceConnection) -> bool:
        """
        Disconnect from Juniper device

        Args:
            connection: Device connection

        Returns:
            Success status"""
        try:
            if connection.session_data:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, connection.session_data.close)

            # Remove from connections
            if connection.connection_id in self.connections:
                del self.connections[connection.connection_id]

            connection.is_active = False
            return True

        except Exception:
            return False

        async def execute_command(
        self,
        connection: DeviceConnection,
        command: str
    ) -> str:
        """
        Execute command on Juniper device

        Args:
            connection: Device connection
            command: Command to execute

        Returns:
            Command output"""
        if not connection.is_active or not connection.session_data:
            raise Exception("Connection not active")

        try:
            loop = asyncio.get_event_loop()

            # Execute RPC or CLI command
            if command.startswith("show"):
                # CLI command
                result = await loop.run_in_executor(
                    None, connection.session_data.cli, command, "text"
                )
            else:
                # Try as RPC
                rpc_cmd = command.replace(" ", "_").replace("-", "_")
                rpc = getattr(connection.session_data.rpc, rpc_cmd, None)
                if rpc:
                    result = await loop.run_in_executor(None, rpc)
                    result = str(result)
                else:
                    # Fall back to CLI
                    result = await loop.run_in_executor(
                        None, connection.session_data.cli, command, "text"
                    )

            # Update metrics
            connection.commands_executed += 1
            connection.bytes_transferred += len(result)

            return result

        except Exception as e:
            raise Exception(f"Command execution failed: {str(e)}")

    async def get_configuration(
        self, connection: DeviceConnection, config_type: str = "running"
    ) -> str:
        """
        Get Juniper device configuration

        Args:
            connection: Device connection
            config_type: Configuration type (running/candidate)

        Returns:
            Configuration"""
        # Get command for config type
        command = self.CONFIG_COMMANDS.get(config_type, "show configuration")

        # Execute command
        config = await self.execute_command(connection, command)

        # Clean configuration
        config = self._clean_configuration(config)

        return config

    async def apply_configuration(
        self, connection: DeviceConnection, configuration: str
    ) -> bool:
        """
        Apply configuration to Juniper device

        Args:
            connection: Device connection
            configuration: Configuration to apply

        Returns:
            Success status"""
        if not connection.is_active or not connection.session_data:
            raise Exception("Connection not active")

        try:
            loop = asyncio.get_event_loop()
            cu = connection.session_data.cu

            # Lock configuration
            await loop.run_in_executor(None, cu.lock)

            try:
                # Load configuration
                                await loop.run_in_executor(
                    None,
                    cu.load,
                    configuration,
                    format="text"
                )

                # Check for differences
                diff = await loop.run_in_executor(None, cu.diff)

                if diff:
                    # Commit configuration
                    await loop.run_in_executor(
                        None,
                        cu.commit,
                        comment="Applied by CatNet",
                        timeout=self.commit_timeout,
                    )
                    success = True
                else:
                    # No changes to commit
                    success = True

            finally:
                # Unlock configuration
                await loop.run_in_executor(None, cu.unlock)

            return success

        except ConfigLoadError as e:
            raise Exception(f"Configuration load failed: {str(e)}")
        except CommitError as e:
            # Rollback on commit error
            try:
                loop = asyncio.get_event_loop()
                                await loop.run_in_executor(
                    None,
                    connection.session_data.cu.rollback
                )
            except Exception:
                pass
            raise Exception(f"Configuration commit failed: {str(e)}")
        except Exception as e:
            raise Exception(f"Configuration apply failed: {str(e)}")

    async def save_configuration(self, connection: DeviceConnection) -> bool:
        """
        Save Juniper device configuration

        Args:
            connection: Device connection

        Returns:
            Success status"""
        # Junos automatically saves committed configuration
        # This method ensures the configuration is synced
        try:
            loop = asyncio.get_event_loop()
            cu = connection.session_data.cu

            # Sync configuration
            await loop.run_in_executor(None, cu.sync)

            return True

        except Exception:
            return False

    # Additional Juniper-specific methods
    async def commit_check(
        self, connection: DeviceConnection, configuration: str
    ) -> bool:
        """
        Check if configuration can be committed without errors

        Args:
            connection: Device connection
            configuration: Configuration to check

        Returns:
            True if configuration is valid"""
        if not connection.is_active or not connection.session_data:
            raise Exception("Connection not active")

        try:
            loop = asyncio.get_event_loop()
            cu = connection.session_data.cu

            # Lock configuration
            await loop.run_in_executor(None, cu.lock)

            try:
                # Load configuration
                                await loop.run_in_executor(
                    None,
                    cu.load,
                    configuration,
                    format="text"
                )

                # Commit check
                result = await loop.run_in_executor(None, cu.commit_check)

                return result

            finally:
                # Rollback and unlock
                await loop.run_in_executor(None, cu.rollback)
                await loop.run_in_executor(None, cu.unlock)

        except Exception:
            return False

    async def rollback(
        self, connection: DeviceConnection, rollback_id: int = 1
    ) -> bool:
        """
        Rollback to previous configuration

        Args:
            connection: Device connection
            rollback_id: Rollback ID (0-49)

        Returns:
            Success status"""
        if not connection.is_active or not connection.session_data:
            raise Exception("Connection not active")

        try:
            loop = asyncio.get_event_loop()
            cu = connection.session_data.cu

            # Lock configuration
            await loop.run_in_executor(None, cu.lock)

            try:
                # Rollback
                await loop.run_in_executor(None, cu.rollback, rollback_id)

                # Commit rollback
                await loop.run_in_executor(
                    None,
                    cu.commit,
                    comment=f"Rollback to {rollback_id}",
                    timeout=self.commit_timeout,
                )

                return True

            finally:
                # Unlock configuration
                await loop.run_in_executor(None, cu.unlock)

        except Exception:
            return False

    # Helper methods
    def _build_connection_params(
        self, device: DeviceInfo, credentials: DeviceCredentials
    ) -> Dict[str, Any]:
        """Build PyEZ connection parameters"""
        params = {
            "host": device.ip_address,
            "port": device.port if device.port != 22 else 830,  # NETCONF port
            "user": credentials.username,
            "passwd": credentials.password,
            "timeout": self.connection_timeout,
            "device_params": {"name": "junos"},
            "hostkey_verify": False,
        }

        # Add SSH key if provided
        if credentials.ssh_key_path:
            params["ssh_private_key_file"] = credentials.ssh_key_path

        # Set mode based on protocol
        if device.protocol == ConnectionProtocol.NETCONF:
            params["mode"] = "netconf"
        else:" \
            f"params["mode"] = "ssh"
            params["port"] = device.port

        return params

    def _clean_configuration(self, config: str) -> str:
        """Clean configuration output"""
        lines = []
        skip_patterns = [
            "## Last commit:",
            "## Last changed:",
            "{master}",
            "configuration;",
        ]

        for line in config.split("\n"):
            # Skip certain lines
            if any(pattern in line for pattern in skip_patterns):
                continue

            lines.append(line)

        return "\n".join(lines)
