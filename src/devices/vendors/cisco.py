"""
Cisco Device Implementation
Support for Cisco IOS, IOS-XE, IOS-XR, NX-OS
"""

from typing import Optional, Dict, Any, List
from datetime import datetime
import re
import asyncio

from src.devices.vendors.base import BaseDevice
from src.core.exceptions import DeviceConfigurationError, DeviceCommandError


class CiscoDevice(BaseDevice):
    """
    Cisco device implementation supporting IOS, IOS-XE, IOS-XR, NX-OS
    """

    # Cisco command mappings
    COMMANDS = {
        "show_run": "show running-config",
        "show_start": "show startup-config",
        "save": "write memory",
        "show_version": "show version",
        "show_interfaces": "show interfaces",
        "show_routes": "show ip route",
        "show_cpu": "show processes cpu sorted",
        "show_memory": "show memory statistics",
        "show_inventory": "show inventory",
        "show_log": "show logging",
        "show_cdp": "show cdp neighbors detail",
        "show_vlan": "show vlan brief",
        "show_spanning": "show spanning-tree",
        "show_mac": "show mac address-table"
    }

    # NX-OS specific commands
    NXOS_COMMANDS = {
        "show_cpu": "show system resources",
        "save": "copy running-config startup-config",
        "rollback": "rollback running-config checkpoint"
    }

    async def execute_command(
        self,
        command: str,
        mode: str = "exec",
        timeout: int = 30
    ) -> str:
        """
        Execute command on Cisco device
        """

        if not self.connection:
            raise DeviceCommandError("No active connection")

        # Determine command mode
        if mode == "config":
            # Enter configuration mode
            await self.connector.execute_command(
                self.connection.session_id,
                "configure terminal",
                timeout=5
            )

            # Execute configuration commands
            output = await self.connector.execute_command(
                self.connection.session_id,
                command,
                timeout=timeout
            )

            # Exit configuration mode
            await self.connector.execute_command(
                self.connection.session_id,
                "exit",
                timeout=5
            )

        elif mode == "enable":
            # Ensure we're in enable mode
            await self.connector.execute_command(
                self.connection.session_id,
                "enable",
                timeout=5
            )

            output = await self.connector.execute_command(
                self.connection.session_id,
                command,
                timeout=timeout
            )

        else:  # exec mode
            output = await self.connector.execute_command(
                self.connection.session_id,
                command,
                timeout=timeout
            )

        # Store in command history
        self.command_history.append({
            "command": command,
            "mode": mode,
            "timestamp": datetime.utcnow(),
            "output_length": len(output)
        })

        return output

    async def get_configuration(self, config_type: str = "running") -> str:
        """
        Get device configuration
        """

        if config_type == "running":
            command = self.COMMANDS["show_run"]
        elif config_type == "startup":
            command = self.COMMANDS["show_start"]
        elif config_type == "both":
            running = await self.execute_command(self.COMMANDS["show_run"])
            startup = await self.execute_command(self.COMMANDS["show_start"])
            return f"!Running Configuration:\n{running}\n\n!Startup Configuration:\n{startup}"
        else:
            raise ValueError(f"Invalid config type: {config_type}")

        config = await self.execute_command(command, mode="enable", timeout=60)

        # Clean configuration
        config = self.clean_config_output(config)

        return config

    def clean_config_output(self, config: str) -> str:
        """
        Clean Cisco configuration output
        """

        lines = []
        skip_lines = [
            "Building configuration...",
            "Current configuration",
            "Last configuration change",
            "NVRAM config last updated"
        ]

        for line in config.splitlines():
            # Skip header lines
            if any(skip in line for skip in skip_lines):
                continue

            lines.append(line)

        return "\n".join(lines).strip()

    async def apply_configuration(self, config: str, validate: bool = True) -> bool:
        """
        Apply configuration to Cisco device
        """

        if validate:
            validation = await self.validate_config_syntax(config)
            if not validation["valid"]:
                raise DeviceConfigurationError(
                    f"Configuration validation failed: {validation['errors']}"
                )

        try:
            # Enter configuration mode
            await self.execute_command("configure terminal", mode="enable")

            # Apply each configuration line
            for line in config.splitlines():
                line = line.strip()

                # Skip comments and empty lines
                if not line or line.startswith("!"):
                    continue

                # Apply configuration command
                output = await self.connector.execute_command(
                    self.connection.session_id,
                    line,
                    timeout=10
                )

                # Check for errors
                if self.check_for_errors(output):
                    # Exit configuration mode
                    await self.execute_command("end", mode="exec")
                    raise DeviceConfigurationError(f"Configuration error: {output}")

            # Exit configuration mode
            await self.execute_command("end", mode="exec")

            return True

        except Exception as e:
            # Attempt to exit configuration mode
            try:
                await self.execute_command("end", mode="exec")
            except:
                pass

            raise DeviceConfigurationError(f"Failed to apply configuration: {str(e)}")

    def check_for_errors(self, output: str) -> bool:
        """
        Check command output for errors
        """

        error_patterns = [
            r"% Invalid",
            r"% Incomplete",
            r"% Ambiguous",
            r"% Error",
            r"% Bad",
            r"% Unknown",
            r"% Cannot",
            r"% Failed",
            r"% Unrecognized"
        ]

        for pattern in error_patterns:
            if re.search(pattern, output, re.IGNORECASE):
                return True

        return False

    async def save_configuration(self) -> bool:
        """
        Save running configuration to startup
        """

        try:
            # Determine save command based on platform
            if self.is_nxos():
                command = self.NXOS_COMMANDS["save"]
            else:
                command = self.COMMANDS["save"]

            output = await self.execute_command(command, mode="enable", timeout=30)

            # Check for success
            if "[OK]" in output or "Copy complete" in output or not self.check_for_errors(output):
                return True

            raise DeviceConfigurationError(f"Save failed: {output}")

        except Exception as e:
            raise DeviceConfigurationError(f"Failed to save configuration: {str(e)}")

    async def create_backup(self, backup_type: str = "full") -> str:
        """
        Create configuration backup
        """

        # Get current configuration
        config = await self.get_configuration("running")

        # Generate backup ID
        backup_id = f"{self.device.hostname}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

        # For NX-OS, create checkpoint
        if self.is_nxos():
            checkpoint_name = f"backup_{backup_id}"
            await self.execute_command(
                f"checkpoint {checkpoint_name}",
                mode="enable"
            )

        # Store backup (in real implementation, this would go to storage)
        # For now, we'll store the backup ID and assume config is saved elsewhere

        return backup_id

    async def rollback(self, backup_id: str) -> bool:
        """
        Rollback to previous configuration
        """

        try:
            if self.is_nxos():
                # NX-OS rollback using checkpoint
                checkpoint_name = f"backup_{backup_id}"
                output = await self.execute_command(
                    f"rollback running-config checkpoint {checkpoint_name}",
                    mode="enable",
                    timeout=60
                )

                if not self.check_for_errors(output):
                    return True

            else:
                # IOS rollback using configure replace
                # This assumes backup is available in flash
                backup_file = f"flash:backup_{backup_id}.cfg"
                output = await self.execute_command(
                    f"configure replace {backup_file} force",
                    mode="enable",
                    timeout=60
                )

                if "Rollback Done" in output or not self.check_for_errors(output):
                    return True

            raise DeviceConfigurationError(f"Rollback failed: {output}")

        except Exception as e:
            raise DeviceConfigurationError(f"Failed to rollback: {str(e)}")

    def is_nxos(self) -> bool:
        """
        Check if device is running NX-OS
        """

        return self.device.os_version and "nx-os" in self.device.os_version.lower()

    async def get_device_info(self) -> Dict[str, Any]:
        """
        Get device system information
        """

        output = await self.execute_command(self.COMMANDS["show_version"], mode="enable")

        info = {
            "hostname": self.parse_hostname(output),
            "version": self.parse_version(output),
            "serial": self.parse_serial(output),
            "model": self.parse_model(output),
            "uptime": self.parse_uptime(output),
            "image": self.parse_image(output)
        }

        return info

    def parse_hostname(self, output: str) -> str:
        """Parse hostname from show version"""
        match = re.search(r"^(\S+)\s+uptime", output, re.MULTILINE)
        return match.group(1) if match else "unknown"

    def parse_version(self, output: str) -> str:
        """Parse IOS version"""
        match = re.search(r"Version\s+([^\s,]+)", output)
        return match.group(1) if match else "unknown"

    def parse_serial(self, output: str) -> str:
        """Parse serial number"""
        match = re.search(r"Processor board ID\s+(\S+)", output)
        return match.group(1) if match else "unknown"

    def parse_model(self, output: str) -> str:
        """Parse device model"""
        match = re.search(r"cisco\s+(\S+)", output, re.IGNORECASE)
        return match.group(1) if match else "unknown"

    def parse_uptime(self, output: str) -> str:
        """Parse device uptime"""
        match = re.search(r"uptime is\s+(.+)", output)
        return match.group(1) if match else "unknown"

    def parse_image(self, output: str) -> str:
        """Parse IOS image"""
        match = re.search(r"System image file is\s+\"(.+)\"", output)
        return match.group(1) if match else "unknown"

    async def get_interfaces(self) -> List[Dict[str, Any]]:
        """
        Get interface information
        """

        output = await self.execute_command(self.COMMANDS["show_interfaces"], mode="enable")

        interfaces = []
        current_interface = None

        for line in output.splitlines():
            # New interface
            match = re.match(r"^(\S+)\s+is\s+(\S+),\s+line protocol is\s+(\S+)", line)
            if match:
                if current_interface:
                    interfaces.append(current_interface)

                current_interface = {
                    "name": match.group(1),
                    "admin_status": "up" if match.group(2) != "administratively down" else "down",
                    "status": match.group(3),
                    "description": None,
                    "ip_address": None,
                    "mac_address": None,
                    "speed": None,
                    "duplex": None,
                    "mtu": None
                }

            # Parse interface details
            if current_interface:
                # Description
                if "Description:" in line:
                    current_interface["description"] = line.split("Description:")[1].strip()

                # IP address
                match = re.search(r"Internet address is\s+(\S+)", line)
                if match:
                    current_interface["ip_address"] = match.group(1)

                # MAC address
                match = re.search(r"Hardware is.*address is\s+(\S+)", line)
                if match:
                    current_interface["mac_address"] = match.group(1)

                # MTU
                match = re.search(r"MTU\s+(\d+)", line)
                if match:
                    current_interface["mtu"] = int(match.group(1))

                # Speed and duplex
                match = re.search(r"(\S+)-duplex,\s+(\S+)", line)
                if match:
                    current_interface["duplex"] = match.group(1)
                    current_interface["speed"] = match.group(2)

        if current_interface:
            interfaces.append(current_interface)

        return interfaces

    async def get_routing_table(self) -> List[Dict[str, Any]]:
        """
        Get routing table
        """

        output = await self.execute_command(self.COMMANDS["show_routes"], mode="enable")

        routes = []

        for line in output.splitlines():
            # Parse route entries
            # Example: C    192.168.1.0/24 is directly connected, GigabitEthernet0/1
            match = re.match(r"^([CDORSB])\s+(\S+)\s+", line)
            if match:
                protocol_map = {
                    "C": "connected",
                    "S": "static",
                    "R": "rip",
                    "O": "ospf",
                    "B": "bgp",
                    "D": "eigrp"
                }

                route = {
                    "protocol": protocol_map.get(match.group(1), "unknown"),
                    "network": match.group(2),
                    "next_hop": None,
                    "interface": None,
                    "metric": None
                }

                # Parse next hop and interface
                if "via" in line:
                    via_match = re.search(r"via\s+(\S+),\s+(\S+)", line)
                    if via_match:
                        route["next_hop"] = via_match.group(1)
                        route["interface"] = via_match.group(2)
                elif "directly connected" in line:
                    conn_match = re.search(r"directly connected,\s+(\S+)", line)
                    if conn_match:
                        route["interface"] = conn_match.group(1)

                # Parse metric
                metric_match = re.search(r"\[(\d+)/(\d+)\]", line)
                if metric_match:
                    route["metric"] = int(metric_match.group(2))

                routes.append(route)

        return routes

    async def get_cpu_usage(self) -> float:
        """
        Get CPU usage percentage
        """

        if self.is_nxos():
            output = await self.execute_command(self.NXOS_COMMANDS["show_cpu"], mode="enable")
            # Parse NX-OS CPU output
            match = re.search(r"CPU states\s+:\s+([\d.]+)% user", output)
            if match:
                return float(match.group(1))
        else:
            output = await self.execute_command(self.COMMANDS["show_cpu"], mode="enable")
            # Parse IOS CPU output
            # Example: CPU utilization for five seconds: 4%/0%; one minute: 3%; five minutes: 2%
            match = re.search(r"CPU utilization for five seconds:\s+([\d]+)%", output)
            if match:
                return float(match.group(1))

        return 0.0

    async def get_memory_usage(self) -> float:
        """
        Get memory usage percentage
        """

        output = await self.execute_command(self.COMMANDS["show_memory"], mode="enable")

        # Parse memory statistics
        # Example: Processor  12345678  98765432  23456789
        match = re.search(r"Processor\s+(\d+)\s+(\d+)\s+(\d+)", output)
        if match:
            total = int(match.group(1))
            used = int(match.group(2))
            if total > 0:
                return (used / total) * 100

        return 0.0

    def get_deprecated_commands(self) -> Dict[str, str]:
        """
        Get Cisco deprecated commands
        """

        return {
            r"^ip nat-control": "no longer needed in newer IOS versions",
            r"^mls qos": "use 'qos' commands instead",
            r"^fair-queue": "use modern QoS mechanisms",
            r"^frame-relay": "deprecated technology"
        }

    def get_ping_command(self, target: str, count: int) -> str:
        """
        Get Cisco ping command
        """

        return f"ping {target} repeat {count}"

    def parse_ping_output(self, output: str) -> Dict[str, Any]:
        """
        Parse Cisco ping output
        """

        result = {
            "success": False,
            "packets_sent": 0,
            "packets_received": 0,
            "packet_loss": 100.0,
            "min_rtt": None,
            "avg_rtt": None,
            "max_rtt": None
        }

        # Parse success rate
        # Example: Success rate is 100 percent (5/5)
        match = re.search(r"Success rate is (\d+) percent \((\d+)/(\d+)\)", output)
        if match:
            result["success"] = int(match.group(1)) > 0
            result["packets_received"] = int(match.group(2))
            result["packets_sent"] = int(match.group(3))
            result["packet_loss"] = 100 - int(match.group(1))

        # Parse RTT
        # Example: round-trip min/avg/max = 1/2/4 ms
        match = re.search(r"round-trip min/avg/max = ([\d.]+)/([\d.]+)/([\d.]+)", output)
        if match:
            result["min_rtt"] = float(match.group(1))
            result["avg_rtt"] = float(match.group(2))
            result["max_rtt"] = float(match.group(3))

        return result

    async def get_vlans(self) -> List[Dict[str, Any]]:
        """
        Get VLAN information
        """

        output = await self.execute_command(self.COMMANDS["show_vlan"], mode="enable")

        vlans = []
        for line in output.splitlines():
            # Parse VLAN entries
            # Example: 1    default                          active    Gi0/1, Gi0/2
            match = re.match(r"^(\d+)\s+(\S+)\s+(\S+)", line)
            if match:
                vlan = {
                    "id": int(match.group(1)),
                    "name": match.group(2),
                    "status": match.group(3),
                    "ports": []
                }

                # Parse ports
                ports_part = line[48:].strip() if len(line) > 48 else ""
                if ports_part:
                    vlan["ports"] = [p.strip() for p in ports_part.split(",")]

                vlans.append(vlan)

        return vlans

    async def get_neighbors(self) -> List[Dict[str, Any]]:
        """
        Get CDP neighbors
        """

        output = await self.execute_command(self.COMMANDS["show_cdp"], mode="enable")

        neighbors = []
        current_neighbor = None

        for line in output.splitlines():
            # New neighbor entry
            if line.startswith("Device ID:"):
                if current_neighbor:
                    neighbors.append(current_neighbor)

                current_neighbor = {
                    "device_id": line.split("Device ID:")[1].strip(),
                    "ip_address": None,
                    "platform": None,
                    "capabilities": None,
                    "local_interface": None,
                    "remote_interface": None
                }

            if current_neighbor:
                # Parse neighbor details
                if "IP address:" in line:
                    current_neighbor["ip_address"] = line.split("IP address:")[1].strip()

                elif "Platform:" in line:
                    parts = line.split("Platform:")[1].split("Capabilities:")
                    current_neighbor["platform"] = parts[0].strip()
                    if len(parts) > 1:
                        current_neighbor["capabilities"] = parts[1].strip()

                elif "Interface:" in line:
                    parts = line.split("Interface:")[1].split("Port ID")
                    current_neighbor["local_interface"] = parts[0].strip().rstrip(",")
                    if len(parts) > 1:
                        current_neighbor["remote_interface"] = parts[1].strip().lstrip("(outgoing port):").strip()

        if current_neighbor:
            neighbors.append(current_neighbor)

        return neighbors