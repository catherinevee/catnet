"""
Device connectors for different vendors and protocols.
"""

import asyncio
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from datetime import datetime
import uuid

from netmiko import ConnectHandler
from napalm import get_network_driver
import paramiko
from ncclient import manager as nc_manager
import textfsm
import re

from src.core.logging import get_logger

logger = get_logger(__name__)


class DeviceConnector(ABC):
    """Base device connector."""

    def __init__(self):
        self.connection = None
        self.id = str(uuid.uuid4())
        self.protocol = "unknown"
        self.established_at = None
        self.last_activity = None

    @abstractmethod
    async def connect(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        **kwargs
    ) -> 'DeviceConnector':
        """Establish connection to device."""
        pass

    @abstractmethod
    async def disconnect(self):
        """Disconnect from device."""
        pass

    @abstractmethod
    async def send_command(
        self,
        command: str,
        timeout: int = 30
    ) -> str:
        """Send command to device."""
        pass

    @abstractmethod
    async def send_config_commands(
        self,
        commands: List[str],
        save: bool = False
    ) -> str:
        """Send configuration commands."""
        pass

    @abstractmethod
    async def get_config(
        self,
        config_type: str = "running"
    ) -> str:
        """Get device configuration."""
        pass

    @abstractmethod
    async def save_config(self) -> bool:
        """Save configuration."""
        pass

    def is_alive(self) -> bool:
        """Check if connection is alive."""
        return self.connection is not None

    async def enable_mode(self, enable_password: Optional[str] = None) -> bool:
        """Enter enable/privileged mode."""
        return True


class CiscoConnector(DeviceConnector):
    """Cisco device connector (IOS, IOS-XE, NX-OS)."""

    def __init__(self, os_type: str = "ios"):
        super().__init__()
        self.os_type = os_type
        self.protocol = "ssh"

    async def connect(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        **kwargs
    ) -> 'CiscoConnector':
        """Connect to Cisco device."""
        try:
            device_type = self._get_device_type()
            enable_password = kwargs.get('enable_password', password)

            # Use netmiko for SSH connections
            device = {
                'device_type': device_type,
                'host': host,
                'port': port,
                'username': username,
                'password': password,
                'secret': enable_password,
                'timeout': kwargs.get('timeout', 30),
                'session_log': kwargs.get('session_log', None),
                'fast_cli': kwargs.get('fast_cli', True)
            }

            # Run in executor to avoid blocking
            loop = asyncio.get_event_loop()
            self.connection = await loop.run_in_executor(
                None,
                ConnectHandler,
                **device
            )

            # Enter enable mode
            if not self.connection.check_enable_mode():
                self.connection.enable()

            self.established_at = datetime.utcnow()
            self.last_activity = datetime.utcnow()

            logger.info(f"Connected to Cisco device {host}")
            return self

        except Exception as e:
            logger.error(f"Failed to connect to Cisco device {host}: {e}")
            raise

    async def disconnect(self):
        """Disconnect from Cisco device."""
        try:
            if self.connection:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None,
                    self.connection.disconnect
                )
                self.connection = None
                logger.info("Disconnected from Cisco device")

        except Exception as e:
            logger.error(f"Error disconnecting from Cisco device: {e}")

    async def send_command(
        self,
        command: str,
        timeout: int = 30
    ) -> str:
        """Send command to Cisco device."""
        try:
            if not self.connection:
                raise ConnectionError("Not connected to device")

            loop = asyncio.get_event_loop()
            output = await loop.run_in_executor(
                None,
                self.connection.send_command,
                command,
                timeout
            )

            self.last_activity = datetime.utcnow()
            return output

        except Exception as e:
            logger.error(f"Failed to send command to Cisco device: {e}")
            raise

    async def send_config_commands(
        self,
        commands: List[str],
        save: bool = False
    ) -> str:
        """Send configuration commands to Cisco device."""
        try:
            if not self.connection:
                raise ConnectionError("Not connected to device")

            loop = asyncio.get_event_loop()

            # Enter config mode and send commands
            output = await loop.run_in_executor(
                None,
                self.connection.send_config_set,
                commands
            )

            # Save configuration if requested
            if save:
                await self.save_config()

            self.last_activity = datetime.utcnow()
            return output

        except Exception as e:
            logger.error(f"Failed to send config commands to Cisco device: {e}")
            raise

    async def get_config(
        self,
        config_type: str = "running"
    ) -> str:
        """Get Cisco device configuration."""
        try:
            if config_type == "running":
                command = "show running-config"
            elif config_type == "startup":
                command = "show startup-config"
            elif config_type == "candidate" and self.os_type == "nxos":
                command = "show running-config diff"
            else:
                command = "show running-config"

            config = await self.send_command(command)

            # Clean up the output
            config = self._clean_config_output(config)

            return config

        except Exception as e:
            logger.error(f"Failed to get config from Cisco device: {e}")
            raise

    async def save_config(self) -> bool:
        """Save Cisco device configuration."""
        try:
            if self.os_type == "ios" or self.os_type == "ios-xe":
                command = "write memory"
            elif self.os_type == "nxos":
                command = "copy running-config startup-config"
            else:
                command = "write memory"

            output = await self.send_command(command)

            # Check for success
            if "OK" in output or "100%" in output or "[OK]" in output:
                logger.info("Configuration saved successfully")
                return True

            logger.warning(f"Configuration save uncertain: {output}")
            return False

        except Exception as e:
            logger.error(f"Failed to save config on Cisco device: {e}")
            return False

    def _get_device_type(self) -> str:
        """Get netmiko device type."""
        device_types = {
            'ios': 'cisco_ios',
            'ios-xe': 'cisco_xe',
            'ios-xr': 'cisco_xr',
            'nxos': 'cisco_nxos',
            'asa': 'cisco_asa'
        }
        return device_types.get(self.os_type, 'cisco_ios')

    def _clean_config_output(self, config: str) -> str:
        """Clean configuration output."""
        # Remove command echo
        lines = config.split('\n')

        # Remove common headers/footers
        clean_lines = []
        skip_patterns = [
            r'^Building configuration',
            r'^Current configuration',
            r'^!$',
            r'^end$'
        ]

        for line in lines:
            skip = False
            for pattern in skip_patterns:
                if re.match(pattern, line.strip()):
                    skip = True
                    break
            if not skip:
                clean_lines.append(line)

        return '\n'.join(clean_lines)


class JuniperConnector(DeviceConnector):
    """Juniper device connector (Junos)."""

    def __init__(self):
        super().__init__()
        self.protocol = "netconf"
        self.candidate_config = None

    async def connect(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        **kwargs
    ) -> 'JuniperConnector':
        """Connect to Juniper device."""
        try:
            # Use NETCONF for Juniper devices
            netconf_port = kwargs.get('netconf_port', 830)

            loop = asyncio.get_event_loop()
            self.connection = await loop.run_in_executor(
                None,
                nc_manager.connect,
                host,
                netconf_port,
                username,
                password,
                None,  # hostkey_verify
                None,  # key_filename
                False,  # allow_agent
                False,  # look_for_keys
                30,  # timeout
                'juniper'  # device_params
            )

            self.established_at = datetime.utcnow()
            self.last_activity = datetime.utcnow()

            logger.info(f"Connected to Juniper device {host}")
            return self

        except Exception as e:
            logger.error(f"Failed to connect to Juniper device {host}: {e}")
            raise

    async def disconnect(self):
        """Disconnect from Juniper device."""
        try:
            if self.connection:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None,
                    self.connection.close_session
                )
                self.connection = None
                logger.info("Disconnected from Juniper device")

        except Exception as e:
            logger.error(f"Error disconnecting from Juniper device: {e}")

    async def send_command(
        self,
        command: str,
        timeout: int = 30
    ) -> str:
        """Send command to Juniper device."""
        try:
            if not self.connection:
                raise ConnectionError("Not connected to device")

            # For Juniper, use RPC or CLI commands via NETCONF
            if command.startswith('show'):
                # Use CLI command
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    None,
                    self.connection.command,
                    command,
                    'text'
                )
                output = result.text if hasattr(result, 'text') else str(result)
            else:
                # Try as RPC
                output = await self._send_rpc(command)

            self.last_activity = datetime.utcnow()
            return output

        except Exception as e:
            logger.error(f"Failed to send command to Juniper device: {e}")
            raise

    async def send_config_commands(
        self,
        commands: List[str],
        save: bool = False
    ) -> str:
        """Send configuration commands to Juniper device."""
        try:
            if not self.connection:
                raise ConnectionError("Not connected to device")

            loop = asyncio.get_event_loop()

            # Lock configuration
            await loop.run_in_executor(
                None,
                self.connection.lock,
                'candidate'
            )

            try:
                # Load configuration
                config_str = '\n'.join(commands)
                await loop.run_in_executor(
                    None,
                    self.connection.load_configuration,
                    config=config_str,
                    format='text'
                )

                # Validate configuration
                await loop.run_in_executor(
                    None,
                    self.connection.validate
                )

                # Commit configuration
                if save:
                    await loop.run_in_executor(
                        None,
                        self.connection.commit
                    )
                    output = "Configuration committed successfully"
                else:
                    # Just validate, don't commit
                    output = "Configuration validated (not committed)"

            finally:
                # Unlock configuration
                await loop.run_in_executor(
                    None,
                    self.connection.unlock,
                    'candidate'
                )

            self.last_activity = datetime.utcnow()
            return output

        except Exception as e:
            logger.error(f"Failed to send config commands to Juniper device: {e}")
            raise

    async def get_config(
        self,
        config_type: str = "running"
    ) -> str:
        """Get Juniper device configuration."""
        try:
            loop = asyncio.get_event_loop()

            if config_type == "running":
                # Get running configuration
                config = await loop.run_in_executor(
                    None,
                    self.connection.get_configuration,
                    format='text'
                )
            elif config_type == "candidate":
                # Get candidate configuration
                config = await loop.run_in_executor(
                    None,
                    self.connection.get_configuration,
                    format='text',
                    {'source': 'candidate'}
                )
            else:
                # Default to running
                config = await loop.run_in_executor(
                    None,
                    self.connection.get_configuration,
                    format='text'
                )

            return config

        except Exception as e:
            logger.error(f"Failed to get config from Juniper device: {e}")
            raise

    async def save_config(self) -> bool:
        """Save Juniper device configuration."""
        try:
            loop = asyncio.get_event_loop()

            # Commit configuration
            await loop.run_in_executor(
                None,
                self.connection.commit
            )

            logger.info("Configuration committed successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to save config on Juniper device: {e}")
            return False

    async def _send_rpc(self, rpc_command: str) -> str:
        """Send RPC command to Juniper device."""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                self.connection.rpc,
                rpc_command
            )
            return str(result)

        except Exception as e:
            logger.error(f"RPC command failed: {e}")
            raise


class AristaConnector(DeviceConnector):
    """Arista device connector (EOS)."""

    def __init__(self):
        super().__init__()
        self.protocol = "eapi"

    async def connect(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        **kwargs
    ) -> 'AristaConnector':
        """Connect to Arista device."""
        try:
            # Use pyeapi or netmiko for Arista
            device = {
                'device_type': 'arista_eos',
                'host': host,
                'port': port,
                'username': username,
                'password': password,
                'secret': kwargs.get('enable_password', password),
                'timeout': kwargs.get('timeout', 30)
            }

            loop = asyncio.get_event_loop()
            self.connection = await loop.run_in_executor(
                None,
                ConnectHandler,
                **device
            )

            self.established_at = datetime.utcnow()
            self.last_activity = datetime.utcnow()

            logger.info(f"Connected to Arista device {host}")
            return self

        except Exception as e:
            logger.error(f"Failed to connect to Arista device {host}: {e}")
            raise

    async def disconnect(self):
        """Disconnect from Arista device."""
        try:
            if self.connection:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None,
                    self.connection.disconnect
                )
                self.connection = None
                logger.info("Disconnected from Arista device")

        except Exception as e:
            logger.error(f"Error disconnecting from Arista device: {e}")

    async def send_command(
        self,
        command: str,
        timeout: int = 30
    ) -> str:
        """Send command to Arista device."""
        try:
            if not self.connection:
                raise ConnectionError("Not connected to device")

            loop = asyncio.get_event_loop()
            output = await loop.run_in_executor(
                None,
                self.connection.send_command,
                command,
                timeout
            )

            self.last_activity = datetime.utcnow()
            return output

        except Exception as e:
            logger.error(f"Failed to send command to Arista device: {e}")
            raise

    async def send_config_commands(
        self,
        commands: List[str],
        save: bool = False
    ) -> str:
        """Send configuration commands to Arista device."""
        try:
            if not self.connection:
                raise ConnectionError("Not connected to device")

            loop = asyncio.get_event_loop()
            output = await loop.run_in_executor(
                None,
                self.connection.send_config_set,
                commands
            )

            if save:
                await self.save_config()

            self.last_activity = datetime.utcnow()
            return output

        except Exception as e:
            logger.error(f"Failed to send config commands to Arista device: {e}")
            raise

    async def get_config(
        self,
        config_type: str = "running"
    ) -> str:
        """Get Arista device configuration."""
        try:
            if config_type == "running":
                command = "show running-config"
            elif config_type == "startup":
                command = "show startup-config"
            else:
                command = "show running-config"

            config = await self.send_command(command)
            return config

        except Exception as e:
            logger.error(f"Failed to get config from Arista device: {e}")
            raise

    async def save_config(self) -> bool:
        """Save Arista device configuration."""
        try:
            command = "write memory"
            output = await self.send_command(command)

            if "Copy completed successfully" in output:
                logger.info("Configuration saved successfully")
                return True

            return False

        except Exception as e:
            logger.error(f"Failed to save config on Arista device: {e}")
            return False


def get_connector(device_type: str) -> DeviceConnector:
    """
    Get appropriate connector for device type.

    Args:
        device_type: Device type string

    Returns:
        Device connector instance
    """
    device_type_lower = device_type.lower()

    if 'cisco' in device_type_lower:
        if 'nxos' in device_type_lower or 'nexus' in device_type_lower:
            return CiscoConnector('nxos')
        elif 'xr' in device_type_lower:
            return CiscoConnector('ios-xr')
        elif 'xe' in device_type_lower:
            return CiscoConnector('ios-xe')
        elif 'asa' in device_type_lower:
            return CiscoConnector('asa')
        else:
            return CiscoConnector('ios')
    elif 'juniper' in device_type_lower or 'junos' in device_type_lower:
        return JuniperConnector()
    elif 'arista' in device_type_lower or 'eos' in device_type_lower:
        return AristaConnector()
    else:
        # Default to Cisco IOS connector
        logger.warning(f"Unknown device type {device_type}, defaulting to Cisco IOS")
        return CiscoConnector('ios')