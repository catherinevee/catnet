"""
Device Connector using Netmiko
Phase 5 Implementation - Real SSH connections to network devices
"""
import os
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class DeviceConnector:
    """
    Connects to network devices using SSH
    Supports both real connections and simulation mode
    """

    def __init__(self, simulation_mode: bool = True):
        """
        Initialize device connector

        Args:
            simulation_mode: If True, simulate connections (safe for testing)
                           If False, attempt real SSH connections
        """
        self.simulation_mode = simulation_mode
        self.connection_logs_dir = Path("data/connection_logs")
        self.connection_logs_dir.mkdir(parents=True, exist_ok=True)

        # Try to import netmiko if not in simulation mode
        if not simulation_mode:
            try:
                from netmiko import ConnectHandler
                self.netmiko_available = True
                self.ConnectHandler = ConnectHandler
            except ImportError:
                                logger.warning(
                    "Netmiko not available,
                    falling back to simulation mode"
                )
                self.simulation_mode = True
                self.netmiko_available = False
        else:
            self.netmiko_available = False

    def connect_to_device(
        self,
        device_info: Dict[str, Any],
        password: Optional[str] = None
    ) -> Optional['DeviceConnection']:
        """
        Connect to a network device

        Args:
            device_info: Device information dictionary
            password: Device password (optional, will prompt if needed)

        Returns:
            DeviceConnection object or None if failed
        """
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "device": device_info.get("hostname", "unknown"),
            "ip": device_info.get("ip_address"),
            "vendor": device_info.get("vendor", "cisco_ios"),
            "simulation_mode": self.simulation_mode
        }

        if self.simulation_mode:
            # Simulate connection
            connection = SimulatedDeviceConnection(device_info)
            log_entry["status"] = "connected (simulated)"
            log_entry["message"] = "Simulated connection successful"
        else:
            # Real SSH connection
            try:
                # Map vendor to netmiko device type
                device_type_map = {
                    "cisco_ios": "cisco_ios",
                    "cisco_xe": "cisco_xe",
                    "cisco_nxos": "cisco_nxos",
                    "juniper_junos": "juniper_junos"
                }

                device_type = device_type_map.get(
                    device_info.get("vendor", "cisco_ios"),
                    "cisco_ios"
                )

                # Prepare connection parameters
                connection_params = {
                    "device_type": device_type,
                    "host": device_info.get("ip_address"),
                    "username": device_info.get("username", "admin"),
                    "port": device_info.get("ssh_port", 22),
                                        "password": password or os.getenv(
                        "DEVICE_PASSWORD",
                        "admin"
                    ),
                    "timeout": 30,
                    "global_delay_factor": 2,
                }

                # Attempt connection
                net_connect = self.ConnectHandler(**connection_params)
                connection = RealDeviceConnection(net_connect, device_info)

                log_entry["status"] = "connected"
                log_entry["message"] = "SSH connection successful"

            except Exception as e:
                logger.error(f"Failed to connect to device: {e}")
                log_entry["status"] = "failed"
                log_entry["error"] = str(e)
                connection = None

        # Save connection log
        self._save_connection_log(log_entry)

        return connection

    def _save_connection_log(self, log_entry: dict):
        """Save connection log to file"""
        log_file = self.connection_logs_dir / f"connections_{datetime.utcnow() \
    .strftime('%Y%m%d')}.jsonl"

        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')



class DeviceConnection:
    """Base class for device connections"""

    def send_command(self, command: str) -> str:
        """Send a command to the device"""
        raise NotImplementedError

    def send_config_commands(self, commands: List[str]) -> str:
        """Send configuration commands to the device"""
        raise NotImplementedError

    def save_config(self) -> bool:
        """Save the running configuration"""
        raise NotImplementedError

    def backup_config(self) -> str:
        """Backup the current configuration"""
        raise NotImplementedError

    def disconnect(self):
        """Disconnect from the device"""
        raise NotImplementedError



class SimulatedDeviceConnection(DeviceConnection):
    """Simulated device connection for testing"""

    def __init__(self, device_info: dict):
        self.device_info = device_info
        self.hostname = device_info.get("hostname", "unknown")
        self.command_history = []
        self.config_mode = False

    def send_command(self, command: str) -> str:
        """Simulate sending a command"""
        self.command_history.append(command)

        # Simulate common commands
        if command == "show running-config":
            return self._generate_sample_config()
        elif command == "show version":
            return f"Simulated {self.device_info.get('vendor', 'cisco_ios')} \
    device\nHostname: {self.hostname}"
        elif command == "show ip interface brief":
            return "Interface              IP-Address      OK? Method Status \
    Protocol\nGigabitEthernet0/0     192.168.1.1     YES manual up \
    up"
        else:
            return f"Simulated output for: {command}"

    def send_config_commands(self, commands: List[str]) -> str:
        """Simulate sending configuration commands"""
        self.config_mode = True
        output = []

        for cmd in commands:
            self.command_history.append(f"(config) {cmd}")
            output.append(f"Applied: {cmd}")

        self.config_mode = False
        return "\n".join(output)

    def save_config(self) -> bool:
        """Simulate saving configuration"""
        self.command_history.append("write memory")
        return True

    def backup_config(self) -> str:
        """Simulate configuration backup"""
        return self._generate_sample_config()

    def disconnect(self):
        """Simulate disconnection"""
        logger.info(f"Disconnected from {self.hostname} (simulated)")

    def _generate_sample_config(self) -> str:
        """Generate sample configuration"""
        return f"""!
! Simulated configuration for {self.hostname}
!
hostname {self.hostname}
!
interface GigabitEthernet0/0
 description Management Interface
 ip address {self.device_info.get('ip_address', '192.168.1.1')} 255.255.255.0
 no shutdown
!
line vty 0 4
 transport input ssh
!
end"""



class RealDeviceConnection(DeviceConnection):
    """Real device connection using Netmiko"""

    def __init__(self, net_connect, device_info: dict):
        self.net_connect = net_connect
        self.device_info = device_info
        self.hostname = device_info.get("hostname", "unknown")

    def send_command(self, command: str) -> str:
        """Send a command to the device"""
        try:
            output = self.net_connect.send_command(command)
            return output
        except Exception as e:
            logger.error(f"Error sending command: {e}")
            return f"Error: {e}"

    def send_config_commands(self, commands: List[str]) -> str:
        """Send configuration commands to the device"""
        try:
            output = self.net_connect.send_config_set(commands)
            return output
        except Exception as e:
            logger.error(f"Error sending config commands: {e}")
            return f"Error: {e}"

    def save_config(self) -> bool:
        """Save the running configuration"""
        try:
            # Vendor-specific save commands
            vendor = self.device_info.get("vendor", "cisco_ios")

            if vendor in ["cisco_ios", "cisco_xe", "cisco_nxos"]:
                self.net_connect.send_command("write memory")
            elif vendor == "juniper_junos":
                self.net_connect.send_command("commit")

            return True
        except Exception as e:
            logger.error(f"Error saving config: {e}")
            return False

    def backup_config(self) -> str:
        """Backup the current configuration"""
        try:
            # Vendor-specific show commands
            vendor = self.device_info.get("vendor", "cisco_ios")

            if vendor in ["cisco_ios", "cisco_xe", "cisco_nxos"]:
                config = self.net_connect.send_command("show running-config")
            elif vendor == "juniper_junos":
                config = self.net_connect.send_command("show configuration | 
    display set")
            else:
                config = self.net_connect.send_command("show running-config")

            return config
        except Exception as e:
            logger.error(f"Error backing up config: {e}")
            return ""

    def disconnect(self):
        """Disconnect from the device"""
        try:
            self.net_connect.disconnect()
            logger.info(f"Disconnected from {self.hostname}")
        except Exception as e:
            logger.error(f"Error disconnecting: {e}")


# Global connector instance (default to simulation mode for safety)
device_connector = DeviceConnector(simulation_mode=True)
