"""
Base Device Implementation
Common functionality for all network device types
"""

from typing import Optional, Dict, Any, List
from datetime import datetime
from abc import ABC, abstractmethod
import re
import hashlib

from src.db.models import Device, DeviceConnection, DeviceBackup
from src.devices.connector import SecureDeviceConnector
from src.core.exceptions import DeviceConfigurationError, DeviceCommandError


class BaseDevice(ABC):
    """
    Abstract base class for device implementations
    """

    def __init__(
        self,
        connector: SecureDeviceConnector,
        device: Device,
        connection: Optional[DeviceConnection] = None
    ):
        self.connector = connector
        self.device = device
        self.connection = connection
        self.command_history = []

    @abstractmethod
    async def execute_command(
        self,
        command: str,
        mode: str = "exec",
        timeout: int = 30
    ) -> str:
        """Execute command on device"""
        pass

    @abstractmethod
    async def get_configuration(self, config_type: str = "running") -> str:
        """Get device configuration"""
        pass

    @abstractmethod
    async def apply_configuration(self, config: str, validate: bool = True) -> bool:
        """Apply configuration to device"""
        pass

    @abstractmethod
    async def save_configuration(self) -> bool:
        """Save running configuration to startup"""
        pass

    @abstractmethod
    async def create_backup(self, backup_type: str = "full") -> str:
        """Create configuration backup"""
        pass

    @abstractmethod
    async def rollback(self, backup_id: str) -> bool:
        """Rollback to previous configuration"""
        pass

    @abstractmethod
    async def get_device_info(self) -> Dict[str, Any]:
        """Get device system information"""
        pass

    @abstractmethod
    async def get_interfaces(self) -> List[Dict[str, Any]]:
        """Get interface information"""
        pass

    @abstractmethod
    async def get_routing_table(self) -> List[Dict[str, Any]]:
        """Get routing table"""
        pass

    @abstractmethod
    async def get_cpu_usage(self) -> float:
        """Get CPU usage percentage"""
        pass

    @abstractmethod
    async def get_memory_usage(self) -> float:
        """Get memory usage percentage"""
        pass

    async def validate_config_syntax(self, config: str) -> Dict[str, Any]:
        """
        Validate configuration syntax
        """

        validation_result = {
            "valid": True,
            "errors": [],
            "warnings": []
        }

        # Check for common configuration errors
        lines = config.split("\n")
        for line_num, line in enumerate(lines, 1):
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("!") or line.startswith("#"):
                continue

            # Check for incomplete commands
            if line.endswith(","):
                validation_result["errors"].append(
                    f"Line {line_num}: Incomplete command"
                )
                validation_result["valid"] = False

            # Check for deprecated commands
            deprecated_patterns = self.get_deprecated_commands()
            for pattern, replacement in deprecated_patterns.items():
                if re.match(pattern, line):
                    validation_result["warnings"].append(
                        f"Line {line_num}: Deprecated command. Use '{replacement}' instead"
                    )

        return validation_result

    @abstractmethod
    def get_deprecated_commands(self) -> Dict[str, str]:
        """Get vendor-specific deprecated commands"""
        pass

    async def compare_configurations(self, config1: str, config2: str) -> Dict[str, Any]:
        """
        Compare two configurations and return differences
        """

        import difflib

        lines1 = config1.splitlines()
        lines2 = config2.splitlines()

        differ = difflib.unified_diff(
            lines1, lines2,
            fromfile="Current",
            tofile="New",
            lineterm=""
        )

        differences = list(differ)

        added = [line for line in differences if line.startswith("+") and not line.startswith("+++")]
        removed = [line for line in differences if line.startswith("-") and not line.startswith("---")]

        return {
            "has_changes": len(differences) > 0,
            "added_lines": len(added),
            "removed_lines": len(removed),
            "diff": "\n".join(differences)
        }

    async def get_config_hash(self, config: str) -> str:
        """
        Generate hash of configuration for comparison
        """

        # Normalize configuration
        normalized = self.normalize_config(config)

        # Generate hash
        return hashlib.sha256(normalized.encode()).hexdigest()

    def normalize_config(self, config: str) -> str:
        """
        Normalize configuration for consistent comparison
        """

        lines = []
        for line in config.splitlines():
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("!") or line.startswith("#"):
                continue

            # Remove timestamps and dynamic values
            line = re.sub(r"! Last configuration change at .*", "", line)
            line = re.sub(r"! NVRAM config last updated at .*", "", line)
            line = re.sub(r"ntp clock-period \d+", "", line)

            if line:
                lines.append(line)

        return "\n".join(sorted(lines))

    async def test_connectivity(self, target: str, count: int = 4) -> Dict[str, Any]:
        """
        Test connectivity to target
        """

        ping_cmd = self.get_ping_command(target, count)
        output = await self.execute_command(ping_cmd, mode="exec")

        return self.parse_ping_output(output)

    @abstractmethod
    def get_ping_command(self, target: str, count: int) -> str:
        """Get vendor-specific ping command"""
        pass

    @abstractmethod
    def parse_ping_output(self, output: str) -> Dict[str, Any]:
        """Parse vendor-specific ping output"""
        pass

    async def get_interface_status(self) -> Dict[str, Any]:
        """
        Get status of all interfaces
        """

        interfaces = await self.get_interfaces()

        total = len(interfaces)
        up = sum(1 for i in interfaces if i.get("status") == "up")
        down = sum(1 for i in interfaces if i.get("status") == "down")
        admin_down = sum(1 for i in interfaces if i.get("admin_status") == "down")

        return {
            "total": total,
            "up": up,
            "down": down,
            "admin_down": admin_down,
            "interfaces": interfaces
        }

    async def get_routing_status(self) -> Dict[str, Any]:
        """
        Get routing protocol status
        """

        routes = await self.get_routing_table()

        # Count routes by protocol
        protocol_counts = {}
        for route in routes:
            protocol = route.get("protocol", "unknown")
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

        return {
            "total_routes": len(routes),
            "protocols": protocol_counts,
            "routes": routes
        }

    async def get_health_summary(self) -> Dict[str, Any]:
        """
        Get overall device health summary
        """

        health = {
            "status": "healthy",
            "checks": {},
            "issues": []
        }

        # CPU check
        try:
            cpu = await self.get_cpu_usage()
            health["checks"]["cpu"] = {
                "value": cpu,
                "status": "healthy" if cpu < 80 else "warning" if cpu < 90 else "critical"
            }
            if cpu >= 80:
                health["issues"].append(f"High CPU usage: {cpu}%")
        except Exception as e:
            health["checks"]["cpu"] = {"status": "unknown", "error": str(e)}

        # Memory check
        try:
            memory = await self.get_memory_usage()
            health["checks"]["memory"] = {
                "value": memory,
                "status": "healthy" if memory < 80 else "warning" if memory < 90 else "critical"
            }
            if memory >= 80:
                health["issues"].append(f"High memory usage: {memory}%")
        except Exception as e:
            health["checks"]["memory"] = {"status": "unknown", "error": str(e)}

        # Interface check
        try:
            interfaces = await self.get_interface_status()
            health["checks"]["interfaces"] = {
                "up": interfaces["up"],
                "down": interfaces["down"],
                "status": "healthy" if interfaces["down"] == 0 else "warning"
            }
            if interfaces["down"] > 0:
                health["issues"].append(f"{interfaces['down']} interfaces down")
        except Exception as e:
            health["checks"]["interfaces"] = {"status": "unknown", "error": str(e)}

        # Determine overall status
        if any(check.get("status") == "critical" for check in health["checks"].values()):
            health["status"] = "critical"
        elif any(check.get("status") == "warning" for check in health["checks"].values()):
            health["status"] = "warning"

        return health

    async def commit_changes(self) -> bool:
        """
        Commit configuration changes (for vendors that support it)
        """
        # Default implementation for vendors without commit (like Cisco)
        return True

    async def validate_and_commit(self, config: str) -> Dict[str, Any]:
        """
        Validate configuration and commit if valid
        """

        # Validate syntax
        validation = await self.validate_config_syntax(config)

        if not validation["valid"]:
            return {
                "success": False,
                "validation": validation,
                "message": "Configuration validation failed"
            }

        # Create backup before applying
        backup_id = await self.create_backup("pre_change")

        try:
            # Apply configuration
            success = await self.apply_configuration(config)

            if success:
                # Save configuration
                await self.save_configuration()

                return {
                    "success": True,
                    "backup_id": backup_id,
                    "validation": validation,
                    "message": "Configuration applied successfully"
                }
            else:
                # Rollback on failure
                await self.rollback(backup_id)

                return {
                    "success": False,
                    "backup_id": backup_id,
                    "message": "Configuration application failed, rolled back"
                }

        except Exception as e:
            # Rollback on error
            try:
                await self.rollback(backup_id)
            except Exception as rollback_error:
                logger.warning(f"Rollback failed during error recovery: {rollback_error}")

            return {
                "success": False,
                "backup_id": backup_id,
                "error": str(e),
                "message": "Configuration failed with error, attempted rollback"
            }