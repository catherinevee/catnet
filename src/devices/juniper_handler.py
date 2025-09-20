"""
Juniper Device Handler
Following CLAUDE.md vendor-specific patterns
"""
import asyncio
from typing import List, Dict, Any, Optional
import re
import json

from ..core.exceptions import DeviceConnectionError
from ..security.audit import AuditLogger


class JuniperHandler:
    """
    Handler for Juniper Junos devices
    Following CLAUDE.md vendor commands exactly
    """

    # Vendor-specific commands from CLAUDE.md
    COMMANDS = {
        "backup": "show configuration | display set",
        "save": "commit",
        "rollback": "rollback 1 && commit",
        "commit_check": "commit check",
        "commit_confirmed": "commit confirmed 5",
        "show_config_json": "show configuration | display json",
    }

    def __init__(self, connection: Any, audit_logger: Optional[AuditLogger] = None):
        self.connection = connection
        self.audit = audit_logger or AuditLogger()
        self.in_config_mode = False

    async def execute_command(self, command: str) -> str:
        """Execute single command on Juniper device"""
        try:
            loop = asyncio.get_event_loop()
            output = await loop.run_in_executor(
                None, self.connection.send_command, command
            )

            return output

        except Exception as e:
            raise DeviceConnectionError(f"Command execution failed: {e}")

    async def execute_config(self, commands: List[str]) -> str:
        """Execute configuration commands in Junos"""
        try:
            # Enter configuration mode
            await self.enter_config_mode()

            outputs = []
            for command in commands:
                output = await self.execute_command(command)
                outputs.append(output)

            # Exit configuration mode
            await self.exit_config_mode()

            return "\n".join(outputs)

        except Exception as e:
            # Ensure we exit config mode on error
            await self.exit_config_mode()
            raise DeviceConnectionError(f"Configuration failed: {e}")

    async def enter_config_mode(self) -> None:
        """Enter configuration mode"""
        if not self.in_config_mode:
            await self.execute_command("configure")
            self.in_config_mode = True

    async def exit_config_mode(self) -> None:
        """Exit configuration mode"""
        if self.in_config_mode:
            await self.execute_command("exit")
            self.in_config_mode = False

    async def backup_configuration(self) -> str:
        """Backup current configuration"""
        # Get config in 'set' format as specified in CLAUDE.md
        config = await self.execute_command(self.COMMANDS["backup"])

        # Remove sensitive information
        config = self._sanitize_config(config)

        await self.audit.log_event(
            event_type="juniper_backup_created",
            user_id=None,
            details={"config_lines": len(config.split("\n"))},
        )

        return config

    async def save_configuration(self) -> str:
        """Commit configuration changes"""
        output = await self.execute_command(self.COMMANDS["save"])

        await self.audit.log_event(
            event_type="juniper_config_committed", user_id=None, details={}
        )

        return output

    async def rollback_configuration(self, rollback_index: int = 1) -> str:
        """Rollback to previous configuration"""
        # Junos maintains rollback history
        rollback_command = f"rollback {rollback_index}"

        await self.enter_config_mode()
        output = await self.execute_command(rollback_command)

        # Commit the rollback
        commit_output = await self.execute_command("commit")
        await self.exit_config_mode()

        await self.audit.log_event(
            event_type="juniper_config_rolled_back",
            user_id=None,
            details={"rollback_index": rollback_index},
        )

        return output + "\n" + commit_output

    async def validate_syntax(self, config: str) -> bool:
        """Validate Juniper configuration syntax"""
        try:
            await self.enter_config_mode()

            # Load configuration
            for line in config.split("\n"):
                if line.strip():
                    await self.execute_command(line)

            # Check configuration without committing
            check_output = await self.execute_command(self.COMMANDS["commit_check"])

            # Rollback changes
            await self.execute_command("rollback 0")
            await self.exit_config_mode()

            # Check for errors
            if "error" in check_output.lower() or "failed" in check_output.lower():
                return False

            return True

        except Exception:
            await self.exit_config_mode()
            return False

    async def commit_config(
        self, confirmed: bool = True, confirm_timeout: int = 5
    ) -> str:
        """
        Commit configuration with optional confirmation
        Junos-specific feature for safe commits
        """
        if confirmed:
            # Commit with automatic rollback if not confirmed
            command = f"commit confirmed {confirm_timeout}"
        else:
            command = "commit"

        await self.enter_config_mode()
        output = await self.execute_command(command)
        await self.exit_config_mode()

        if confirmed:
            # Confirm the commit
            await asyncio.sleep(2)  # Wait a bit before confirming
            await self.enter_config_mode()
            confirm_output = await self.execute_command("commit")
            await self.exit_config_mode()
            output += "\n" + confirm_output

        await self.audit.log_event(
            event_type="juniper_config_committed",
            user_id=None,
            details={
                "confirmed": confirmed,
                "timeout": confirm_timeout if confirmed else None,
            },
        )

        return output

    async def get_interfaces(self) -> List[Dict[str, Any]]:
        """Get interface information"""
        output = await self.execute_command("show interfaces terse")

        interfaces = []
        lines = output.strip().split("\n")[1:]  # Skip header

        for line in lines:
            parts = line.split()
            if len(parts) >= 3:
                interfaces.append(
                    {
                        "name": parts[0],
                        "admin_status": parts[1],
                        "link_status": parts[2],
                        "ip_address": parts[3] if len(parts) > 3 else None,
                    }
                )

        return interfaces

    async def get_vlans(self) -> List[Dict[str, Any]]:
        """Get VLAN information"""
        output = await self.execute_command("show vlans")

        vlans = []
        # Parse VLAN output
        vlan_pattern = r"(\S+)\s+(\d+)"

        for match in re.finditer(vlan_pattern, output):
            vlans.append({"name": match.group(1), "id": int(match.group(2))})

        return vlans

    async def get_routes(self) -> List[Dict[str, Any]]:
        """Get routing table"""
        output = await self.execute_command("show route")

        routes = []
        # Parse routing table
        route_pattern = r"(\d+\.\d+\.\d+\.\d+/\d+)\s+\*?\[([^\]]+)\]"

        for match in re.finditer(route_pattern, output):
            routes.append(
                {
                    "network": match.group(1),
                    "protocol": match.group(2).split("/")[0],
                }
            )

        return routes

    async def configure_interface(
        self,
        interface: str,
        ip_address: Optional[str] = None,
        description: Optional[str] = None,
        enabled: bool = True,
    ) -> str:
        """Configure an interface"""
        commands = []

        if description:
            commands.append(
                f'set interfaces {interface} description \
                "{description}"'
            )

        if ip_address:
            commands.append(
                f"set interfaces {interface} unit 0 family inet address \
                    {ip_address}"
            )

        if not enabled:
            commands.append(f"set interfaces {interface} disable")
        else:
            commands.append(f"delete interfaces {interface} disable")

        output = await self.execute_config(commands)

        # Commit changes
        commit_output = await self.commit_config()

        await self.audit.log_event(
            event_type="juniper_interface_configured",
            user_id=None,
            details={
                "interface": interface,
                "ip_address": ip_address,
                "enabled": enabled,
            },
        )

        return output + "\n" + commit_output

    async def configure_vlan(
        self, vlan_name: str, vlan_id: int, description: str = ""
    ) -> str:
        """Configure a VLAN"""
        commands = [f"set vlans {vlan_name} vlan-id {vlan_id}"]

        if description:
            commands.append(
                f'set vlans {vlan_name} description \
                "{description}"'
            )

        output = await self.execute_config(commands)

        # Commit changes
        commit_output = await self.commit_config()

        await self.audit.log_event(
            event_type="juniper_vlan_configured",
            user_id=None,
            details={"vlan_name": vlan_name, "vlan_id": vlan_id},
        )

        return output + "\n" + commit_output

    async def configure_firewall_filter(
        self, filter_name: str, rules: List[Dict[str, Any]]
    ) -> str:
        """Configure firewall filter (Juniper's ACL)"""
        commands = []

        for i, rule in enumerate(rules, start=1):
            term_name = f"term{i}"
            from_clause = rule.get("from", "")
            commands.append(
                f"set firewall filter {filter_name} term {term_name} from \
                    {from_clause}"
            )
            then_action = rule.get("then", "accept")
            commands.append(
                f"set firewall filter {filter_name} term {term_name} then \
                    {then_action}"
            )

        output = await self.execute_config(commands)

        # Commit changes
        commit_output = await self.commit_config()

        await self.audit.log_event(
            event_type="juniper_firewall_configured",
            user_id=None,
            details={"filter_name": filter_name, "rule_count": len(rules)},
        )

        return output + "\n" + commit_output

    async def check_health(self) -> Dict[str, Any]:
        """Perform health check"""
        health = {
            "routing_engine": await self._get_re_status(),
            "memory": await self._get_memory_usage(),
            "interfaces": await self._check_interfaces(),
            "uptime": await self._get_uptime(),
            "alarms": await self._check_alarms(),
        }

        return health

    async def _get_re_status(self) -> Dict[str, Any]:
        """Get routing engine status"""
        try:
            output = await self.execute_command("show chassis routing-engine")

            # Parse RE status
            cpu_match = re.search(r"CPU utilization:\s+(\d+) percent", output)
            temp_match = re.search(r"Temperature\s+(\d+) degrees", output)

            return {
                "cpu_usage": int(cpu_match.group(1)) if cpu_match else 0,
                "temperature": int(temp_match.group(1)) if temp_match else 0,
            }
        except Exception:
            return {"cpu_usage": 0, "temperature": 0}

    async def _get_memory_usage(self) -> Dict[str, int]:
        """Get memory usage"""
        try:
            output = await self.execute_command("show system memory")

            # Parse memory info
            total_match = re.search(r"Total:\s+(\d+)", output)
            used_match = re.search(r"Used:\s+(\d+)", output)
            free_match = re.search(r"Free:\s+(\d+)", output)

            return {
                "total": int(total_match.group(1)) if total_match else 0,
                "used": int(used_match.group(1)) if used_match else 0,
                "free": int(free_match.group(1)) if free_match else 0,
            }
        except Exception:
            return {"total": 0, "used": 0, "free": 0}

    async def _check_interfaces(self) -> Dict[str, str]:
        """Check interface status"""
        interfaces = await self.get_interfaces()
        status = {}

        for interface in interfaces:
            status[interface["name"]] = interface["link_status"]

        return status

    async def _get_uptime(self) -> str:
        """Get device uptime"""
        try:
            output = await self.execute_command("show system uptime")
            match = re.search(r"System booted: (.+)", output)
            if match:
                return match.group(1)
        except Exception:
            pass

        return "unknown"

    async def _check_alarms(self) -> List[str]:
        """Check system alarms"""
        try:
            output = await self.execute_command("show system alarms")

            if "No alarms currently active" in output:
                return []

            # Parse alarms
            alarms = []
            for line in output.split("\n"):
                if line.strip() and not line.startswith("Class"):
                    alarms.append(line.strip())

            return alarms
        except Exception:
            return []

    def _sanitize_config(self, config: str) -> str:
        """Remove sensitive information from config"""
        # Remove passwords and secrets
        config = re.sub(
            r'encrypted-password "[^"]+"',
            'encrypted-password "<removed>"',
            config,
        )
        config = re.sub(
            r'authentication-key "[^"]+"',
            'authentication-key "<removed>"',
            config,
        )
        config = re.sub(r'secret "[^"]+"', 'secret "<removed>"', config)
        config = re.sub(r'pre-shared-key "[^"]+"', 'pre-shared-key "<removed>"', config)

        return config

    async def get_configuration_json(self) -> Dict[str, Any]:
        """Get configuration in JSON format (Juniper feature)"""
        try:
            output = await self.execute_command(self.COMMANDS["show_config_json"])
            return json.loads(output)
        except Exception as e:
            raise DeviceConnectionError(f"Failed to get JSON config: {e}")

    async def compare_configs(self, config1: str, config2: str) -> List[str]:
        """Compare two configurations and return differences"""
        # Convert to sets of lines for comparison
        lines1 = set(config1.strip().split("\n"))
        lines2 = set(config2.strip().split("\n"))

        added = lines2 - lines1
        removed = lines1 - lines2

        differences = []
        for line in removed:
            differences.append(f"- {line}")
        for line in added:
            differences.append(f"+ {line}")

        return differences

    async def verify_configuration(self, expected_config: str) -> bool:
        """Verify configuration matches expected"""
        current_config = await self.backup_configuration()

        differences = await self.compare_configs(current_config, expected_config)

        if differences:
            await self.audit.log_event(
                event_type="juniper_config_mismatch",
                user_id=None,
                details={"difference_count": len(differences)},
            )
            return False

        return True
