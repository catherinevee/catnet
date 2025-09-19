"""
Cisco Device Adapter for CatNet

Supports:
- Cisco IOS
- Cisco IOS-XE
- Cisco NX-OS
"""

from typing import Dict, Any, Optional
import asyncio
from datetime import datetime
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from ..device_manager import (
    DeviceAdapter,
    DeviceInfo,
    DeviceCredentials,
    DeviceConnection,
    ConnectionProtocol,
    DeviceVendor,
)


class CiscoAdapter(DeviceAdapter):
    """
    Cisco device adapter implementation
    """

    # Device type mappings for Netmiko
    DEVICE_TYPE_MAP = {
        DeviceVendor.CISCO_IOS: "cisco_ios",
        DeviceVendor.CISCO_IOSXE: "cisco_xe",
        DeviceVendor.CISCO_NXOS: "cisco_nxos",
    }

    # Configuration commands
    CONFIG_COMMANDS = {
        DeviceVendor.CISCO_IOS: {
            "save": "write memory",
            "running": "show running-config",
            "startup": "show startup-config",
            "version": "show version",
            "inventory": "show inventory",
        },
        DeviceVendor.CISCO_IOSXE: {
            "save": "write memory",
            "running": "show running-config",
            "startup": "show startup-config",
            "version": "show version",
            "inventory": "show inventory",
        },
        DeviceVendor.CISCO_NXOS: {
            "save": "copy running-config startup-config",
            "running": "show running-config",
            "startup": "show startup-config",
            "version": "show version",
            "inventory": "show inventory",
        },
    }

    def __init__(self):
        """Initialize Cisco adapter"""
        self.connections = {}
        self.connection_pool_size = 5
        self.command_timeout = 30
        self.global_delay_factor = 2

    async def connect(
        self, device: DeviceInfo, credentials: DeviceCredentials
    ) -> DeviceConnection:
        """
        Connect to Cisco device

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
            # Connect using Netmiko (run in executor for async)
            loop = asyncio.get_event_loop()
            connection = await loop.run_in_executor(
                None, ConnectHandler, **device_params
            )

            # Enable mode if required
            if credentials.enable_password:
                await loop.run_in_executor(
                    None, connection.enable, credentials.enable_password
                )

            # Create connection object
            device_connection = DeviceConnection(
                device_id=device.id,
                connection_id=connection_id,
                protocol=device.protocol,
                established_at=datetime.utcnow(),
                session_data=connection,
                is_active=True,
            )

            # Store connection
            self.connections[connection_id] = device_connection

            return device_connection

        except NetmikoAuthenticationException as e:
            raise Exception(f"Authentication failed: {str(e)}")
        except NetmikoTimeoutException as e:
            raise Exception(f"Connection timeout: {str(e)}")
        except Exception as e:
            raise Exception(f"Connection failed: {str(e)}")

    async def disconnect(self, connection: DeviceConnection) -> bool:
        """
        Disconnect from Cisco device

        Args:
            connection: Device connection

        Returns:
            Success status
        """
        try:
            if connection.session_data:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, connection.session_data.disconnect)

            # Remove from connections
            if connection.connection_id in self.connections:
                del self.connections[connection.connection_id]

            connection.is_active = False
            return True

        except Exception:
            return False

    async def execute_command(self, connection: DeviceConnection, command: str) -> str:
        """
        Execute command on Cisco device

        Args:
            connection: Device connection
            command: Command to execute

        Returns:
            Command output
        """
        if not connection.is_active or not connection.session_data:
            raise Exception("Connection not active")

        try:
            loop = asyncio.get_event_loop()
            output = await loop.run_in_executor(
                None,
                connection.session_data.send_command,
                command,
                self.command_timeout,
            )

            # Update metrics
            connection.commands_executed += 1
            connection.bytes_transferred += len(output)

            return output

        except Exception as e:
            raise Exception(f"Command execution failed: {str(e)}")

    async def get_configuration(
        self, connection: DeviceConnection, config_type: str = "running"
    ) -> str:
        """
        Get Cisco device configuration

        Args:
            connection: Device connection
            config_type: Configuration type (running/startup)

        Returns:
            Configuration
        """
        # Get vendor from connection
        device_id = connection.device_id
        vendor = self._get_vendor_from_connection(connection)

        # Get command for config type
        commands = self.CONFIG_COMMANDS.get(vendor, {})
        command = commands.get(config_type, "show running-config")

        # Execute command
        config = await self.execute_command(connection, command)

        # Clean configuration (remove timestamps, etc.)
        config = self._clean_configuration(config)

        return config

    async def apply_configuration(
        self, connection: DeviceConnection, configuration: str
    ) -> bool:
        """
        Apply configuration to Cisco device

        Args:
            connection: Device connection
            configuration: Configuration to apply

        Returns:
            Success status
        """
        if not connection.is_active or not connection.session_data:
            raise Exception("Connection not active")

        try:
            # Split configuration into lines
            config_lines = [
                line.strip()
                for line in configuration.split("\n")
                if line.strip() and not line.strip().startswith("!")
            ]

            # Enter configuration mode
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, connection.session_data.config_mode)

            # Send configuration commands
            for line in config_lines:
                await loop.run_in_executor(
                    None,
                    connection.session_data.send_command,
                    line,
                    self.command_timeout,
                )

            # Exit configuration mode
            await loop.run_in_executor(None, connection.session_data.exit_config_mode)

            return True

        except Exception as e:
            # Try to exit config mode on error
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None, connection.session_data.exit_config_mode
                )
            except:
                pass

            raise Exception(f"Configuration apply failed: {str(e)}")

    async def save_configuration(self, connection: DeviceConnection) -> bool:
        """
        Save Cisco device configuration

        Args:
            connection: Device connection

        Returns:
            Success status
        """
        # Get vendor from connection
        vendor = self._get_vendor_from_connection(connection)

        # Get save command
        commands = self.CONFIG_COMMANDS.get(vendor, {})
        save_command = commands.get("save", "write memory")

        try:
            # Execute save command
            output = await self.execute_command(connection, save_command)

            # Check for success indicators
            success_indicators = [
                "[OK]",
                "Copy complete",
                "Building configuration",
                "Startup-config",
            ]

            return any(indicator in output for indicator in success_indicators)

        except Exception:
            return False

    # Helper methods
    def _build_connection_params(
        self, device: DeviceInfo, credentials: DeviceCredentials
    ) -> Dict[str, Any]:
        """Build Netmiko connection parameters"""
        params = {
            "device_type": self.DEVICE_TYPE_MAP.get(device.vendor, "cisco_ios"),
            "host": device.ip_address,
            "port": device.port,
            "username": credentials.username,
            "password": credentials.password,
            "global_delay_factor": self.global_delay_factor,
            "timeout": self.command_timeout,
            "session_log": None,  # Could enable for debugging
        }

        # Add optional parameters
        if credentials.ssh_key_path:
            params["key_file"] = credentials.ssh_key_path
            params["use_keys"] = True

        if device.protocol == ConnectionProtocol.SSH:
            params["ssh_strict"] = False
            params["allow_agent"] = False

        return params

    def _get_vendor_from_connection(self, connection: DeviceConnection) -> DeviceVendor:
        """Get device vendor from connection"""
        # In real implementation, would look up from device info
        return DeviceVendor.CISCO_IOS

    def _clean_configuration(self, config: str) -> str:
        """Clean configuration output"""
        lines = []
        skip_patterns = [
            "Building configuration",
            "Current configuration",
            "Last configuration",
            "NVRAM",
            "startup-config",
        ]

        for line in config.split("\n"):
            # Skip certain lines
            if any(pattern in line for pattern in skip_patterns):
                continue

            # Remove timestamps
            if line.startswith("! Last"):
                continue

            lines.append(line)

        return "\n".join(lines)
