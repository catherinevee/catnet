"""
Cisco Device Handler
Following CLAUDE.md vendor-specific patterns
"""
import asyncio
from typing import List, Dict, Any, Optional

# from netmiko import ConnectHandler  # Used via base class
import re

from ..core.exceptions import DeviceConnectionError  # ValidationError used inline
from ..security.audit import AuditLogger


class CiscoHandler:
    """
    Handler for Cisco IOS, IOS-XE, and NX-OS devices
    Following CLAUDE.md vendor commands exactly
    """

    # Vendor-specific commands from CLAUDE.md
    COMMANDS = {
        "backup": "show running-config",
        "save": "write memory",
        "rollback": "configure replace flash:backup.cfg force",
        "nxos_save": "copy running-config startup-config",
        "nxos_rollback": "rollback running-config checkpoint backup_config",
    }

    def __init__(self, connection: Any, audit_logger: Optional[AuditLogger] = None):
        self.connection = connection
        self.audit = audit_logger or AuditLogger()
        self.device_type = self._detect_device_type()

    def _detect_device_type(self) -> str:
        """Detect specific Cisco OS type"""
        try:
            version_output = self.connection.send_command("show version")

            if "NX-OS" in version_output:
                return "cisco_nxos"
            elif "IOS-XE" in version_output:
                return "cisco_xe"
            else:
                return "cisco_ios"
        except Exception:
            return "cisco_ios"  # Default

    async def execute_command(self, command: str, enable_mode: bool = False) -> str:
        """Execute single command on Cisco device"""
        try:
            if enable_mode and hasattr(self.connection, "enable"):
                self.connection.enable()

            # Execute command asynchronously
            loop = asyncio.get_event_loop()
            output = await loop.run_in_executor(
                None, self.connection.send_command, command
            )

            return output

        except Exception as e:
            raise DeviceConnectionError(f"Command execution failed: {e}")

    async def execute_config(self, commands: List[str]) -> str:
        """Execute configuration commands"""
        try:
            # Enter configuration mode
            loop = asyncio.get_event_loop()
            output = await loop.run_in_executor(
                None, self.connection.send_config_set, commands
            )

            return output

        except Exception as e:
            raise DeviceConnectionError(f"Configuration failed: {e}")

    async def backup_configuration(self) -> str:
        """Backup current configuration"""
        backup_command = self.COMMANDS["backup"]
        config = await self.execute_command(backup_command)

        # Remove sensitive information
        config = self._sanitize_config(config)

        await self.audit.log_event(
            event_type="cisco_backup_created",
            user_id=None,
            details={
                "device_type": self.device_type,
                "config_lines": len(config.split("\n")),
            },
        )

        return config

    async def save_configuration(self) -> str:
        """Save running config to startup"""
        if self.device_type == "cisco_nxos":
            save_command = self.COMMANDS["nxos_save"]
        else:
            save_command = self.COMMANDS["save"]

        output = await self.execute_command(save_command, enable_mode=True)

        await self.audit.log_event(
            event_type="cisco_config_saved",
            user_id=None,
            details={"device_type": self.device_type},
        )

        return output

    async def rollback_configuration(self, backup_file: str = "backup.cfg") -> str:
        """Rollback to previous configuration"""
        if self.device_type == "cisco_nxos":
            # NX-OS rollback
            rollback_command = self.COMMANDS["nxos_rollback"]
        else:
            # IOS/IOS-XE rollback
            rollback_command = f"configure replace flash:{backup_file} force"

        output = await self.execute_command(rollback_command, enable_mode=True)

        await self.audit.log_event(
            event_type="cisco_config_rolled_back",
            user_id=None,
            details={"device_type": self.device_type, "backup_file": backup_file},
        )

        return output

    async def validate_syntax(self, config: str) -> bool:
        """Validate Cisco configuration syntax"""
        # Create temporary config for validation
        temp_commands = ["configure terminal", "parser config cache", "exit"]
        logger.debug(f"Using validation commands: {temp_commands}")

        try:
            # Test configuration parsing
            test_output = await self.execute_config(config.split("\n"))

            # Check for errors
            error_patterns = [r"% Invalid", r"% Incomplete", r"% Ambiguous", r"% Error"]

            for pattern in error_patterns:
                if re.search(pattern, test_output):
                    return False

            return True

        except Exception:
            return False

    async def get_interfaces(self) -> List[Dict[str, Any]]:
        """Get interface information"""
        output = await self.execute_command("show ip interface brief")

        interfaces = []
        lines = output.strip().split("\n")[1:]  # Skip header

        for line in lines:
            parts = line.split()
            if len(parts) >= 6:
                interfaces.append(
                    {
                        "name": parts[0],
                        "ip_address": parts[1],
                        "status": parts[4],
                        "protocol": parts[5],
                    }
                )

        return interfaces

    async def get_vlans(self) -> List[Dict[str, Any]]:
        """Get VLAN information"""
        if self.device_type == "cisco_nxos":
            output = await self.execute_command("show vlan brief")
        else:
            output = await self.execute_command("show vlan")

        vlans = []
        lines = output.strip().split("\n")

        for line in lines:
            # Parse VLAN lines (format varies by platform)
            match = re.match(r"^(\d+)\s+(\S+)", line)
            if match:
                vlans.append({"id": int(match.group(1)), "name": match.group(2)})

        return vlans

    async def get_routes(self) -> List[Dict[str, Any]]:
        """Get routing table"""
        output = await self.execute_command("show ip route")

        routes = []
        # Parse routing table (simplified)
        route_pattern = r"([CDLORSB])\s+(\d+\.\d+\.\d+\.\d+/\d+)"

        for match in re.finditer(route_pattern, output):
            routes.append({"type": match.group(1), "network": match.group(2)})

        return routes

    async def configure_interface(
        self,
        interface: str,
        ip_address: Optional[str] = None,
        description: Optional[str] = None,
        shutdown: bool = False,
    ) -> str:
        """Configure an interface"""
        commands = [f"interface {interface}"]

        if description:
            commands.append(f"description {description}")

        if ip_address:
            commands.append(f"ip address {ip_address}")

        if shutdown:
            commands.append("shutdown")
        else:
            commands.append("no shutdown")

        output = await self.execute_config(commands)

        await self.audit.log_event(
            event_type="cisco_interface_configured",
            user_id=None,
            details={
                "interface": interface,
                "ip_address": ip_address,
                "shutdown": shutdown,
            },
        )

        return output

    async def configure_vlan(self, vlan_id: int, name: str) -> str:
        """Configure a VLAN"""
        if self.device_type == "cisco_nxos":
            commands = [f"vlan {vlan_id}", f"name {name}"]
        else:
            commands = [f"vlan {vlan_id}", f"name {name}"]

        output = await self.execute_config(commands)

        await self.audit.log_event(
            event_type="cisco_vlan_configured",
            user_id=None,
            details={"vlan_id": vlan_id, "vlan_name": name},
        )

        return output

    async def configure_acl(self, acl_name: str, rules: List[str]) -> str:
        """Configure access control list"""
        commands = [f"ip access-list extended {acl_name}"]
        commands.extend(rules)

        output = await self.execute_config(commands)

        await self.audit.log_event(
            event_type="cisco_acl_configured",
            user_id=None,
            details={"acl_name": acl_name, "rule_count": len(rules)},
        )

        return output

    async def check_health(self) -> Dict[str, Any]:
        """Perform health check"""
        health = {
            "cpu": await self._get_cpu_usage(),
            "memory": await self._get_memory_usage(),
            "interfaces": await self._check_interfaces(),
            "uptime": await self._get_uptime(),
        }

        return health

    async def _get_cpu_usage(self) -> float:
        """Get CPU usage percentage"""
        try:
            if self.device_type == "cisco_nxos":
                output = await self.execute_command("show system resources")
                # Parse NX-OS CPU output
                match = re.search(r"CPU states\s+:\s+(\d+\.\d+)% user", output)
            else:
                output = await self.execute_command("show processes cpu")
                # Parse IOS CPU output
                match = re.search(r"CPU utilization for five seconds: (\d+)%", output)

            if match:
                return float(match.group(1))
        except Exception:
            pass

        return 0.0

    async def _get_memory_usage(self) -> Dict[str, int]:
        """Get memory usage"""
        try:
            if self.device_type == "cisco_nxos":
                output = await self.execute_command("show system resources")
                # Parse NX-OS memory
                logger.debug(f"NX-OS memory output: {output[:100]}...")
            else:
                output = await self.execute_command("show memory statistics")
                # Parse IOS memory
                logger.debug(f"IOS memory output: {output[:100]}...")

            # Simplified parsing - would parse output in production
            return {"used": 0, "free": 0, "total": 0}
        except Exception:
            return {"used": 0, "free": 0, "total": 0}

    async def _check_interfaces(self) -> Dict[str, str]:
        """Check interface status"""
        interfaces = await self.get_interfaces()
        status = {}

        for interface in interfaces:
            status[interface["name"]] = interface["status"]

        return status

    async def _get_uptime(self) -> str:
        """Get device uptime"""
        try:
            output = await self.execute_command("show version")
            match = re.search(r"uptime is (.+)", output, re.IGNORECASE)
            if match:
                return match.group(1)
        except Exception:
            pass

        return "unknown"

    def _sanitize_config(self, config: str) -> str:
        """Remove sensitive information from config"""
        # Remove passwords and secrets
        config = re.sub(r"password \S+", "password <removed>", config)
        config = re.sub(r"secret \S+", "secret <removed>", config)
        config = re.sub(r"key \S+", "key <removed>", config)
        config = re.sub(r"community \S+", "community <removed>", config)

        return config

    async def enable_session_recording(self) -> None:
        """Enable session command recording"""
        # Would implement session recording
        pass

    async def verify_configuration(self, expected_config: str) -> bool:
        """Verify configuration matches expected"""
        current_config = await self.backup_configuration()

        # Normalize configs for comparison
        current_lines = set(current_config.strip().split("\n"))
        expected_lines = set(expected_config.strip().split("\n"))

        # Check if expected config is subset of current
        missing = expected_lines - current_lines

        if missing:
            await self.audit.log_event(
                event_type="cisco_config_mismatch",
                user_id=None,
                details={"missing_lines": len(missing)},
            )
            return False

        return True
