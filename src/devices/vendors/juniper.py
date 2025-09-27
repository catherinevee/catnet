"""
Juniper Device Implementation
Support for Juniper Junos devices
"""

from typing import Optional, Dict, Any, List
from datetime import datetime
import re
import xml.etree.ElementTree as ET
import asyncio

from src.devices.vendors.base import BaseDevice
from src.core.exceptions import DeviceConfigurationError, DeviceCommandError


class JuniperDevice(BaseDevice):
    """
    Juniper Junos device implementation
    """

    # Juniper command mappings
    COMMANDS = {
        "show_config": "show configuration",
        "show_config_set": "show configuration | display set",
        "show_version": "show version",
        "show_interfaces": "show interfaces terse",
        "show_interfaces_detail": "show interfaces extensive",
        "show_routes": "show route",
        "show_bgp": "show bgp summary",
        "show_ospf": "show ospf neighbor",
        "show_cpu": "show chassis routing-engine",
        "show_memory": "show system memory",
        "show_inventory": "show chassis hardware",
        "show_log": "show log messages",
        "show_lldp": "show lldp neighbors",
        "show_vlans": "show vlans",
        "show_security": "show security policies",
        "show_nat": "show security nat source summary",
        "show_alarms": "show chassis alarms"
    }

    # Junos configuration modes
    CONFIG_MODES = {
        "edit": "edit",
        "private": "configure private",
        "exclusive": "configure exclusive",
        "batch": "configure batch"
    }

    def __init__(self, connector, device, connection=None):
        super().__init__(connector, device, connection)
        self.config_mode = None
        self.candidate_config = []
        self.rollback_id = None

    async def execute_command(
        self,
        command: str,
        mode: str = "exec",
        timeout: int = 30
    ) -> str:
        """
        Execute command on Juniper device
        """

        if not self.connection:
            raise DeviceCommandError("No active connection")

        # Handle different command modes
        if mode == "config":
            # Enter configuration mode if not already there
            if not self.config_mode:
                await self.enter_config_mode("private")

            # Execute configuration command
            output = await self.connector.execute_command(
                self.connection.session_id,
                command,
                timeout=timeout
            )

            # Store in candidate configuration
            self.candidate_config.append(command)

        elif mode == "operational":
            # Exit config mode if in it
            if self.config_mode:
                await self.exit_config_mode(rollback=True)

            # Execute operational command
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

    async def enter_config_mode(self, mode: str = "private") -> bool:
        """
        Enter Junos configuration mode
        """

        if self.config_mode:
            return True

        try:
            config_command = self.CONFIG_MODES.get(mode, "configure")
            output = await self.connector.execute_command(
                self.connection.session_id,
                config_command,
                timeout=10
            )

            if not self.check_for_errors(output):
                self.config_mode = mode
                return True

            raise DeviceConfigurationError(f"Failed to enter config mode: {output}")

        except Exception as e:
            raise DeviceConfigurationError(f"Error entering config mode: {str(e)}")

    async def exit_config_mode(self, rollback: bool = False, commit: bool = False) -> bool:
        """
        Exit Junos configuration mode
        """

        if not self.config_mode:
            return True

        try:
            if rollback:
                # Rollback changes
                await self.connector.execute_command(
                    self.connection.session_id,
                    "rollback 0",
                    timeout=10
                )

            if commit:
                # Commit changes
                await self.commit_changes()

            # Exit configuration mode
            await self.connector.execute_command(
                self.connection.session_id,
                "exit configuration-mode",
                timeout=10
            )

            self.config_mode = None
            self.candidate_config = []
            return True

        except Exception as e:
            raise DeviceConfigurationError(f"Error exiting config mode: {str(e)}")

    async def get_configuration(self, config_type: str = "running") -> str:
        """
        Get device configuration
        """

        # Junos doesn't distinguish between running/startup like Cisco
        # Configuration is committed to be active

        if config_type == "set":
            # Get configuration in set format
            command = self.COMMANDS["show_config_set"]
        elif config_type == "xml":
            # Get configuration in XML format
            command = "show configuration | display xml"
        elif config_type == "json":
            # Get configuration in JSON format
            command = "show configuration | display json"
        else:
            # Get standard hierarchical configuration
            command = self.COMMANDS["show_config"]

        config = await self.execute_command(command, mode="operational", timeout=60)

        # Clean configuration output
        config = self.clean_config_output(config)

        return config

    def clean_config_output(self, config: str) -> str:
        """
        Clean Juniper configuration output
        """

        lines = []
        skip_patterns = [
            r"^## Last commit:",
            r"^## Last changed:",
            r"^# Generated by"
        ]

        for line in config.splitlines():
            # Skip metadata lines
            if any(re.match(pattern, line) for pattern in skip_patterns):
                continue

            lines.append(line)

        return "\n".join(lines).strip()

    async def apply_configuration(self, config: str, validate: bool = True) -> bool:
        """
        Apply configuration to Juniper device
        """

        if validate:
            validation = await self.validate_config_syntax(config)
            if not validation["valid"]:
                raise DeviceConfigurationError(
                    f"Configuration validation failed: {validation['errors']}"
                )

        try:
            # Enter configuration mode
            await self.enter_config_mode("exclusive")

            # Load configuration
            if config.strip().startswith("<"):
                # XML format
                load_command = "load override terminal"
                terminator = "</configuration>"
            elif all(line.strip().startswith("set ") for line in config.splitlines() if line.strip()):
                # Set commands format
                load_command = "load set terminal"
                terminator = None
            else:
                # Hierarchical format
                load_command = "load override terminal"
                terminator = None

            # Send load command
            await self.connector.execute_command(
                self.connection.session_id,
                load_command,
                timeout=10
            )

            # Send configuration
            if terminator:
                # For XML, send all at once
                await self.connector.execute_command(
                    self.connection.session_id,
                    config + "\n" + terminator,
                    timeout=30
                )
            else:
                # For set commands, send line by line
                for line in config.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        await self.connector.execute_command(
                            self.connection.session_id,
                            line,
                            timeout=10
                        )

                # Send Ctrl-D to end input
                await self.connector.execute_command(
                    self.connection.session_id,
                    "\x04",  # Ctrl-D
                    timeout=5
                )

            # Check configuration
            check_output = await self.connector.execute_command(
                self.connection.session_id,
                "commit check",
                timeout=30
            )

            if self.check_for_errors(check_output):
                # Rollback on error
                await self.connector.execute_command(
                    self.connection.session_id,
                    "rollback 0",
                    timeout=10
                )
                raise DeviceConfigurationError(f"Configuration check failed: {check_output}")

            return True

        except Exception as e:
            # Attempt to rollback and exit
            try:
                await self.exit_config_mode(rollback=True)
            except:
                pass

            raise DeviceConfigurationError(f"Failed to apply configuration: {str(e)}")

    def check_for_errors(self, output: str) -> bool:
        """
        Check command output for Junos errors
        """

        error_patterns = [
            r"error:",
            r"failed:",
            r"invalid",
            r"unknown command",
            r"syntax error",
            r"missing argument",
            r"configuration check-out failed",
            r"commit failed",
            r"^Error"
        ]

        for pattern in error_patterns:
            if re.search(pattern, output, re.IGNORECASE | re.MULTILINE):
                return True

        return False

    async def save_configuration(self) -> bool:
        """
        Save configuration (commit in Junos)
        """

        try:
            output = await self.commit_changes()
            return not self.check_for_errors(output)

        except Exception as e:
            raise DeviceConfigurationError(f"Failed to save configuration: {str(e)}")

    async def commit_changes(self, comment: str = None, confirmed: int = None) -> str:
        """
        Commit configuration changes in Junos
        """

        if not self.config_mode:
            raise DeviceConfigurationError("Not in configuration mode")

        try:
            # Build commit command
            commit_cmd = "commit"

            if confirmed:
                # Confirmed commit (auto-rollback if not confirmed)
                commit_cmd += f" confirmed {confirmed}"

            if comment:
                # Add commit comment
                commit_cmd += f' comment "{comment}"'

            # Check configuration first
            check_output = await self.connector.execute_command(
                self.connection.session_id,
                "commit check",
                timeout=30
            )

            if self.check_for_errors(check_output):
                raise DeviceConfigurationError(f"Commit check failed: {check_output}")

            # Perform commit
            commit_output = await self.connector.execute_command(
                self.connection.session_id,
                commit_cmd,
                timeout=60
            )

            if "commit complete" in commit_output.lower():
                self.candidate_config = []
                return commit_output

            raise DeviceConfigurationError(f"Commit failed: {commit_output}")

        except Exception as e:
            raise DeviceConfigurationError(f"Failed to commit changes: {str(e)}")

    async def create_backup(self, backup_type: str = "full") -> str:
        """
        Create configuration backup
        """

        # Get current configuration
        config = await self.get_configuration("set")

        # Generate backup ID
        backup_id = f"{self.device.hostname}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

        # Save rescue configuration
        await self.execute_command(
            "request system configuration rescue save",
            mode="operational"
        )

        # Create rollback point
        self.rollback_id = await self.get_rollback_id()

        return backup_id

    async def rollback(self, backup_id: str = None) -> bool:
        """
        Rollback to previous configuration
        """

        try:
            # Enter configuration mode
            await self.enter_config_mode("exclusive")

            if backup_id and backup_id.startswith("rescue"):
                # Load rescue configuration
                output = await self.connector.execute_command(
                    self.connection.session_id,
                    "load override rescue",
                    timeout=30
                )
            else:
                # Rollback to specific revision or last
                rollback_num = self.rollback_id if self.rollback_id else "1"
                output = await self.connector.execute_command(
                    self.connection.session_id,
                    f"rollback {rollback_num}",
                    timeout=30
                )

            if self.check_for_errors(output):
                raise DeviceConfigurationError(f"Rollback failed: {output}")

            # Commit rollback
            await self.commit_changes(comment="Rollback configuration")

            # Exit configuration mode
            await self.exit_config_mode()

            return True

        except Exception as e:
            raise DeviceConfigurationError(f"Failed to rollback: {str(e)}")

    async def get_rollback_id(self) -> str:
        """
        Get current rollback ID
        """

        output = await self.execute_command(
            "show system rollback",
            mode="operational"
        )

        # Parse rollback ID from output
        match = re.search(r"^0\s+\d{4}-\d{2}-\d{2}", output, re.MULTILINE)
        if match:
            return "0"

        return "1"

    async def get_device_info(self) -> Dict[str, Any]:
        """
        Get device system information
        """

        output = await self.execute_command(self.COMMANDS["show_version"], mode="operational")

        info = {
            "hostname": self.parse_hostname(output),
            "model": self.parse_model(output),
            "version": self.parse_version(output),
            "serial": self.parse_serial(output),
            "uptime": self.parse_uptime(output)
        }

        return info

    def parse_hostname(self, output: str) -> str:
        """Parse hostname from show version"""
        match = re.search(r"Hostname:\s+(\S+)", output)
        return match.group(1) if match else "unknown"

    def parse_model(self, output: str) -> str:
        """Parse device model"""
        match = re.search(r"Model:\s+(\S+)", output)
        return match.group(1) if match else "unknown"

    def parse_version(self, output: str) -> str:
        """Parse Junos version"""
        match = re.search(r"Junos:\s+(\S+)", output)
        return match.group(1) if match else "unknown"

    def parse_serial(self, output: str) -> str:
        """Parse serial number"""
        # Get chassis hardware for serial
        hw_output = asyncio.run(self.execute_command(
            self.COMMANDS["show_inventory"],
            mode="operational"
        ))
        match = re.search(r"Chassis\s+\S+\s+(\S+)", hw_output)
        return match.group(1) if match else "unknown"

    def parse_uptime(self, output: str) -> str:
        """Parse system uptime"""
        match = re.search(r"System booted:\s+(.+)", output)
        if match:
            boot_time = match.group(1)
            # Calculate uptime from boot time
            return boot_time
        return "unknown"

    async def get_interfaces(self) -> List[Dict[str, Any]]:
        """
        Get interface information
        """

        output = await self.execute_command(
            self.COMMANDS["show_interfaces"],
            mode="operational"
        )

        interfaces = []

        for line in output.splitlines():
            # Parse interface entries
            # Example: ge-0/0/0        up    up  inet     192.168.1.1/24
            parts = line.split()
            if len(parts) >= 3 and not line.startswith("Interface"):
                interface = {
                    "name": parts[0],
                    "admin_status": parts[1],
                    "status": parts[2],
                    "protocol": parts[3] if len(parts) > 3 else None,
                    "ip_address": parts[4] if len(parts) > 4 else None
                }

                # Get detailed info for physical interfaces
                if interface["name"].startswith(("ge-", "xe-", "et-", "fe-")):
                    detail_output = await self.execute_command(
                        f"show interfaces {interface['name']} extensive",
                        mode="operational"
                    )
                    interface.update(self.parse_interface_details(detail_output))

                interfaces.append(interface)

        return interfaces

    def parse_interface_details(self, output: str) -> Dict[str, Any]:
        """
        Parse detailed interface information
        """

        details = {
            "description": None,
            "mac_address": None,
            "mtu": None,
            "speed": None,
            "duplex": None,
            "input_packets": 0,
            "output_packets": 0,
            "input_errors": 0,
            "output_errors": 0
        }

        # Parse description
        match = re.search(r"Description:\s+(.+)", output)
        if match:
            details["description"] = match.group(1)

        # Parse MAC address
        match = re.search(r"Current address:\s+(\S+)", output)
        if match:
            details["mac_address"] = match.group(1)

        # Parse MTU
        match = re.search(r"MTU:\s+(\d+)", output)
        if match:
            details["mtu"] = int(match.group(1))

        # Parse speed
        match = re.search(r"Speed:\s+(\S+),", output)
        if match:
            details["speed"] = match.group(1)

        # Parse duplex
        match = re.search(r"Duplex:\s+(\S+)", output)
        if match:
            details["duplex"] = match.group(1)

        # Parse statistics
        match = re.search(r"Input packets:\s+(\d+)", output)
        if match:
            details["input_packets"] = int(match.group(1))

        match = re.search(r"Output packets:\s+(\d+)", output)
        if match:
            details["output_packets"] = int(match.group(1))

        return details

    async def get_routing_table(self) -> List[Dict[str, Any]]:
        """
        Get routing table
        """

        output = await self.execute_command(self.COMMANDS["show_routes"], mode="operational")

        routes = []
        current_destination = None

        for line in output.splitlines():
            # Parse destination
            # Example: 10.0.0.0/8          *[Static/5] 00:15:30
            match = re.match(r"^([\d.]+/\d+)\s+", line)
            if match:
                current_destination = match.group(1)

            # Parse route details
            # Example: *[BGP/170] 00:15:30, MED 100, localpref 100
            match = re.search(r"\*?\[(\S+)/(\d+)\]", line)
            if match and current_destination:
                protocol = match.group(1)
                preference = int(match.group(2))

                route = {
                    "network": current_destination,
                    "protocol": protocol.lower(),
                    "preference": preference,
                    "next_hop": None,
                    "interface": None,
                    "metric": None
                }

                # Parse next hop
                nh_match = re.search(r"to\s+([\d.]+)", line)
                if nh_match:
                    route["next_hop"] = nh_match.group(1)

                # Parse interface
                via_match = re.search(r"via\s+(\S+)", line)
                if via_match:
                    route["interface"] = via_match.group(1)

                # Parse metric
                metric_match = re.search(r"metric\s+(\d+)", line)
                if metric_match:
                    route["metric"] = int(metric_match.group(1))

                routes.append(route)

        return routes

    async def get_bgp_neighbors(self) -> List[Dict[str, Any]]:
        """
        Get BGP neighbor information
        """

        output = await self.execute_command(self.COMMANDS["show_bgp"], mode="operational")

        neighbors = []

        for line in output.splitlines():
            # Parse BGP neighbor entries
            # Example: 192.168.1.1  65001  12345  12345       0       0     1w2d 10/20/2
            parts = line.split()
            if len(parts) >= 8 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
                neighbor = {
                    "peer": parts[0],
                    "as_number": int(parts[1]) if parts[1].isdigit() else parts[1],
                    "input_messages": int(parts[2]) if parts[2].isdigit() else 0,
                    "output_messages": int(parts[3]) if parts[3].isdigit() else 0,
                    "out_queue": int(parts[4]) if parts[4].isdigit() else 0,
                    "flaps": int(parts[5]) if parts[5].isdigit() else 0,
                    "uptime": parts[6],
                    "state": parts[7] if len(parts) > 7 else "Established",
                    "prefixes_received": int(parts[8].split("/")[0]) if len(parts) > 8 else 0
                }

                neighbors.append(neighbor)

        return neighbors

    async def get_cpu_usage(self) -> float:
        """
        Get CPU usage percentage
        """

        output = await self.execute_command(self.COMMANDS["show_cpu"], mode="operational")

        # Parse routing engine CPU
        # Example: Routing Engine status:
        #            Slot 0:
        #              Current state                  Master
        #              CPU utilization:
        #                User                        5 percent
        #                Background                  0 percent
        #                Kernel                      3 percent
        #                Interrupt                   0 percent
        #                Idle                       92 percent

        cpu_total = 0.0
        match = re.search(r"Idle\s+([\d.]+)\s+percent", output)
        if match:
            idle = float(match.group(1))
            cpu_total = 100.0 - idle

        return cpu_total

    async def get_memory_usage(self) -> float:
        """
        Get memory usage percentage
        """

        output = await self.execute_command(self.COMMANDS["show_memory"], mode="operational")

        # Parse memory statistics
        # Example: Memory utilization:
        #            Total memory: 2048 MB
        #            Reserved memory: 150 MB
        #            Wired memory: 450 MB
        #            Active memory: 800 MB
        #            Inactive memory: 200 MB
        #            Cache memory: 300 MB
        #            Free memory: 148 MB

        total_match = re.search(r"Total memory:\s+(\d+)", output)
        free_match = re.search(r"Free memory:\s+(\d+)", output)

        if total_match and free_match:
            total = float(total_match.group(1))
            free = float(free_match.group(1))
            if total > 0:
                used = total - free
                return (used / total) * 100

        return 0.0

    async def get_security_policies(self) -> List[Dict[str, Any]]:
        """
        Get security policies (for SRX devices)
        """

        if not self.device.model or "SRX" not in self.device.model.upper():
            return []

        output = await self.execute_command(
            self.COMMANDS["show_security"],
            mode="operational"
        )

        policies = []
        # Parse security policies
        # Implementation depends on specific output format

        return policies

    async def get_vlans(self) -> List[Dict[str, Any]]:
        """
        Get VLAN information
        """

        output = await self.execute_command(self.COMMANDS["show_vlans"], mode="operational")

        vlans = []

        for line in output.splitlines():
            # Parse VLAN entries
            # Example: default  100    Active    ge-0/0/1.0, ge-0/0/2.0
            parts = line.split()
            if len(parts) >= 3 and parts[0] != "Name":
                vlan = {
                    "name": parts[0],
                    "id": int(parts[1]) if parts[1].isdigit() else None,
                    "status": parts[2],
                    "interfaces": []
                }

                # Parse interfaces
                if len(parts) > 3:
                    interfaces_str = " ".join(parts[3:])
                    vlan["interfaces"] = [i.strip() for i in interfaces_str.split(",")]

                vlans.append(vlan)

        return vlans

    def get_deprecated_commands(self) -> Dict[str, str]:
        """
        Get Juniper deprecated commands
        """

        return {
            r"^firewall family": "use 'security policies' instead",
            r"^interfaces .* family inet filter": "use 'firewall family' instead",
            r"^routing-options static route .* install": "deprecated option"
        }

    def get_ping_command(self, target: str, count: int) -> str:
        """
        Get Juniper ping command
        """

        return f"ping {target} count {count}"

    def parse_ping_output(self, output: str) -> Dict[str, Any]:
        """
        Parse Juniper ping output
        """

        result = {
            "success": False,
            "packets_sent": 0,
            "packets_received": 0,
            "packet_loss": 100.0,
            "min_rtt": None,
            "avg_rtt": None,
            "max_rtt": None,
            "stddev_rtt": None
        }

        # Parse packet statistics
        # Example: 5 packets transmitted, 5 packets received, 0% packet loss
        match = re.search(
            r"(\d+) packets transmitted, (\d+) packets received, ([\d.]+)% packet loss",
            output
        )
        if match:
            result["packets_sent"] = int(match.group(1))
            result["packets_received"] = int(match.group(2))
            result["packet_loss"] = float(match.group(3))
            result["success"] = result["packet_loss"] < 100

        # Parse RTT statistics
        # Example: round-trip min/avg/max/stddev = 0.469/0.566/0.686/0.081 ms
        match = re.search(
            r"round-trip min/avg/max/stddev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)",
            output
        )
        if match:
            result["min_rtt"] = float(match.group(1))
            result["avg_rtt"] = float(match.group(2))
            result["max_rtt"] = float(match.group(3))
            result["stddev_rtt"] = float(match.group(4))

        return result

    async def configure_interface(
        self,
        interface: str,
        ip_address: str = None,
        description: str = None,
        enabled: bool = True,
        vlan: int = None
    ) -> bool:
        """
        Configure interface settings
        """

        try:
            await self.enter_config_mode("exclusive")

            # Navigate to interface configuration
            await self.connector.execute_command(
                self.connection.session_id,
                f"edit interfaces {interface}",
                timeout=10
            )

            # Set description
            if description:
                await self.connector.execute_command(
                    self.connection.session_id,
                    f'set description "{description}"',
                    timeout=10
                )

            # Set IP address
            if ip_address:
                await self.connector.execute_command(
                    self.connection.session_id,
                    f"set unit 0 family inet address {ip_address}",
                    timeout=10
                )

            # Enable/disable interface
            if enabled:
                await self.connector.execute_command(
                    self.connection.session_id,
                    "delete disable",
                    timeout=10
                )
            else:
                await self.connector.execute_command(
                    self.connection.session_id,
                    "set disable",
                    timeout=10
                )

            # Set VLAN
            if vlan:
                await self.connector.execute_command(
                    self.connection.session_id,
                    f"set unit 0 vlan-id {vlan}",
                    timeout=10
                )

            # Return to top level
            await self.connector.execute_command(
                self.connection.session_id,
                "top",
                timeout=10
            )

            # Commit changes
            await self.commit_changes(comment=f"Configure interface {interface}")

            # Exit configuration mode
            await self.exit_config_mode()

            return True

        except Exception as e:
            await self.exit_config_mode(rollback=True)
            raise DeviceConfigurationError(f"Failed to configure interface: {str(e)}")

    async def configure_bgp(
        self,
        local_as: int,
        neighbor_ip: str,
        remote_as: int,
        description: str = None
    ) -> bool:
        """
        Configure BGP neighbor
        """

        try:
            await self.enter_config_mode("exclusive")

            # Configure BGP
            commands = [
                f"set routing-options autonomous-system {local_as}",
                f"set protocols bgp group external type external",
                f"set protocols bgp group external peer-as {remote_as}",
                f"set protocols bgp group external neighbor {neighbor_ip}"
            ]

            if description:
                commands.append(
                    f'set protocols bgp group external neighbor {neighbor_ip} description "{description}"'
                )

            for cmd in commands:
                await self.connector.execute_command(
                    self.connection.session_id,
                    cmd,
                    timeout=10
                )

            # Commit changes
            await self.commit_changes(comment=f"Configure BGP neighbor {neighbor_ip}")

            # Exit configuration mode
            await self.exit_config_mode()

            return True

        except Exception as e:
            await self.exit_config_mode(rollback=True)
            raise DeviceConfigurationError(f"Failed to configure BGP: {str(e)}")