from typing import Dict, Any, Optional, List
import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass
import structlog

from netmiko import ConnectHandler
from napalm import get_network_driver
import textfsm

from ..db.models import DeviceVendor
from ..core.exceptions import DeviceConnectionError, ValidationError

logger = structlog.get_logger()

@dataclass
class DeviceCapabilities:
    supports_config_replace: bool = False
    supports_config_merge: bool = True
    supports_rollback: bool = False
    supports_commit_confirm: bool = False
    config_format: str = "text"
    backup_commands: List[str] = None
    health_commands: List[str] = None

class BaseDeviceHandler(ABC):
    def __init__(self, connection_params: Dict[str, Any]):
        self.connection_params = connection_params
        self.connection = None
        self.capabilities = self._get_capabilities()

    @abstractmethod
    def _get_capabilities(self) -> DeviceCapabilities:
        pass

    @abstractmethod
    async def connect(self) -> bool:
        pass

    @abstractmethod
    async def disconnect(self) -> bool:
        pass

    @abstractmethod
    async def get_config(self, config_type: str = "running") -> str:
        pass

    @abstractmethod
    async def deploy_config(
        self,
        config_content: str,
        deployment_method: str = "merge"
    ) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def get_health_metrics(self) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def create_checkpoint(self, name: str) -> str:
        pass

    @abstractmethod
    async def rollback_to_checkpoint(self, checkpoint_name: str) -> bool:
        pass

class CiscoIOSHandler(BaseDeviceHandler):
    def _get_capabilities(self) -> DeviceCapabilities:
        return DeviceCapabilities(
            supports_config_replace=True,
            supports_config_merge=True,
            supports_rollback=True,
            supports_commit_confirm=False,
            config_format="text",
            backup_commands=[
                "show running-config",
                "show startup-config",
                "show version",
                "show inventory"
            ],
            health_commands=[
                "show processes cpu",
                "show memory",
                "show interfaces",
                "show environment all"
            ]
        )

    async def connect(self) -> bool:
        try:
            self.connection = ConnectHandler(**self.connection_params)

            # Verify connection with a simple command
            output = self.connection.send_command("show version")
            if "IOS" not in output and "Version" not in output:
                raise DeviceConnectionError("Device response validation failed")

            logger.info("Successfully connected to Cisco IOS device")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to Cisco IOS device: {e}")
            raise DeviceConnectionError(f"Connection failed: {str(e)}")

    async def disconnect(self) -> bool:
        try:
            if self.connection:
                self.connection.disconnect()
                self.connection = None
            return True
        except Exception as e:
            logger.error(f"Disconnect error: {e}")
            return False

    async def get_config(self, config_type: str = "running") -> str:
        if not self.connection:
            raise DeviceConnectionError("No active connection")

        command_map = {
            "running": "show running-config",
            "startup": "show startup-config",
            "candidate": "show running-config"
        }

        command = command_map.get(config_type, "show running-config")

        try:
            config = self.connection.send_command(command, delay_factor=2)
            return config
        except Exception as e:
            raise DeviceConnectionError(f"Failed to get {config_type} config: {str(e)}")

    async def deploy_config(
        self,
        config_content: str,
        deployment_method: str = "merge"
    ) -> Dict[str, Any]:
        if not self.connection:
            raise DeviceConnectionError("No active connection")

        try:
            result = {
                "success": False,
                "method": deployment_method,
                "changes": [],
                "warnings": [],
                "errors": []
            }

            if deployment_method == "replace":
                # Use configure replace for atomic configuration replacement
                config_lines = config_content.split('\n')

                # Write config to flash
                config_file = "flash:catnet_temp_config.txt"
                self.connection.send_command(f"copy running-config {config_file}")

                # Apply configuration with replace
                output = self.connection.send_command(
                    f"configure replace {config_file} force",
                    expect_string=r"#",
                    delay_factor=5
                )

                if "Replace operation completed" in output:
                    result["success"] = True
                    result["changes"] = ["Configuration replaced successfully"]
                else:
                    result["errors"] = [f"Replace failed: {output}"]

            elif deployment_method == "merge":
                # Use configuration mode for merge
                config_lines = [line.strip() for line in config_content.split('\n')
                              if line.strip() and not line.strip().startswith('!')]

                output = self.connection.send_config_set(
                    config_lines,
                    delay_factor=2,
                    cmd_verify=True
                )

                result["success"] = True
                result["changes"] = config_lines

                # Check for configuration errors
                if "Invalid" in output or "Error" in output:
                    result["warnings"] = ["Configuration warnings detected"]

            # Save configuration
            if result["success"]:
                save_output = self.connection.send_command("write memory")
                if "OK" in save_output or "Building configuration" in save_output:
                    result["saved"] = True
                else:
                    result["warnings"].append("Configuration not saved")

            return result

        except Exception as e:
            logger.error(f"Configuration deployment failed: {e}")
            raise DeviceConnectionError(f"Deploy failed: {str(e)}")

    async def get_health_metrics(self) -> Dict[str, Any]:
        if not self.connection:
            raise DeviceConnectionError("No active connection")

        metrics = {}

        try:
            # CPU utilization
            cpu_output = self.connection.send_command("show processes cpu")
            cpu_lines = cpu_output.split('\n')
            for line in cpu_lines:
                if "CPU utilization" in line:
                    # Parse: CPU utilization for five seconds: 2%/0%; one minute: 3%; five minutes: 3%
                    import re
                    match = re.search(r'five seconds:\s*(\d+)%', line)
                    if match:
                        metrics["cpu_5sec"] = int(match.group(1))
                    match = re.search(r'one minute:\s*(\d+)%', line)
                    if match:
                        metrics["cpu_1min"] = int(match.group(1))

            # Memory utilization
            memory_output = self.connection.send_command("show memory")
            memory_lines = memory_output.split('\n')
            for line in memory_lines:
                if "Processor" in line and "bytes" in line:
                    # Parse memory information
                    import re
                    total_match = re.search(r'Total:\s*(\d+)', line)
                    used_match = re.search(r'Used:\s*(\d+)', line)
                    if total_match and used_match:
                        total = int(total_match.group(1))
                        used = int(used_match.group(1))
                        metrics["memory_total"] = total
                        metrics["memory_used"] = used
                        metrics["memory_utilization"] = round((used / total) * 100, 2)

            # Interface status
            interface_output = self.connection.send_command("show interfaces summary")
            metrics["interfaces"] = self._parse_interface_summary(interface_output)

            # System uptime
            version_output = self.connection.send_command("show version")
            uptime_match = re.search(r'uptime is (.+)', version_output)
            if uptime_match:
                metrics["uptime"] = uptime_match.group(1)

            return metrics

        except Exception as e:
            logger.error(f"Failed to get health metrics: {e}")
            raise DeviceConnectionError(f"Health check failed: {str(e)}")

    async def create_checkpoint(self, name: str) -> str:
        if not self.connection:
            raise DeviceConnectionError("No active connection")

        try:
            checkpoint_file = f"flash:checkpoint_{name}.cfg"
            output = self.connection.send_command(f"copy running-config {checkpoint_file}")

            if "bytes copied" in output or "OK" in output:
                logger.info(f"Checkpoint {name} created successfully")
                return checkpoint_file
            else:
                raise DeviceConnectionError(f"Failed to create checkpoint: {output}")

        except Exception as e:
            logger.error(f"Checkpoint creation failed: {e}")
            raise DeviceConnectionError(f"Checkpoint failed: {str(e)}")

    async def rollback_to_checkpoint(self, checkpoint_name: str) -> bool:
        if not self.connection:
            raise DeviceConnectionError("No active connection")

        try:
            checkpoint_file = f"flash:checkpoint_{checkpoint_name}.cfg"

            # Verify checkpoint exists
            dir_output = self.connection.send_command("dir flash:")
            if checkpoint_name not in dir_output:
                raise ValidationError(f"Checkpoint {checkpoint_name} not found")

            # Perform rollback using configure replace
            output = self.connection.send_command(
                f"configure replace {checkpoint_file} force",
                expect_string=r"#",
                delay_factor=5
            )

            if "Replace operation completed" in output:
                logger.info(f"Successfully rolled back to checkpoint {checkpoint_name}")
                return True
            else:
                raise DeviceConnectionError(f"Rollback failed: {output}")

        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            raise DeviceConnectionError(f"Rollback error: {str(e)}")

    def _parse_interface_summary(self, output: str) -> Dict[str, Any]:
        interfaces = {
            "total": 0,
            "up": 0,
            "down": 0,
            "admin_down": 0
        }

        lines = output.split('\n')
        for line in lines:
            if "Ethernet" in line or "Serial" in line or "Loopback" in line:
                interfaces["total"] += 1
                if " up " in line:
                    interfaces["up"] += 1
                elif "administratively down" in line:
                    interfaces["admin_down"] += 1
                else:
                    interfaces["down"] += 1

        return interfaces

class CiscoNXOSHandler(CiscoIOSHandler):
    def _get_capabilities(self) -> DeviceCapabilities:
        caps = super()._get_capabilities()
        caps.supports_commit_confirm = True
        caps.backup_commands.extend([
            "show running-config all",
            "show startup-config"
        ])
        return caps

    async def deploy_config(
        self,
        config_content: str,
        deployment_method: str = "merge"
    ) -> Dict[str, Any]:
        if deployment_method == "replace":
            # NX-OS specific replace method using checkpoint rollback
            return await self._nxos_replace_config(config_content)
        else:
            return await super().deploy_config(config_content, deployment_method)

    async def _nxos_replace_config(self, config_content: str) -> Dict[str, Any]:
        try:
            # Create checkpoint before making changes
            checkpoint_name = f"catnet_backup_{int(asyncio.get_event_loop().time())}"
            self.connection.send_command(f"checkpoint {checkpoint_name}")

            # Apply new configuration
            config_lines = [line.strip() for line in config_content.split('\n')
                          if line.strip() and not line.strip().startswith('!')]

            output = self.connection.send_config_set(config_lines, delay_factor=3)

            # Verify configuration
            if "Invalid" in output or "Error" in output:
                # Rollback on error
                self.connection.send_command(f"rollback running-config checkpoint {checkpoint_name}")
                return {
                    "success": False,
                    "method": "replace",
                    "errors": [f"Configuration error, rolled back: {output}"]
                }

            # Save configuration
            self.connection.send_command("copy running-config startup-config")

            return {
                "success": True,
                "method": "replace",
                "changes": config_lines,
                "checkpoint": checkpoint_name
            }

        except Exception as e:
            logger.error(f"NX-OS replace config failed: {e}")
            raise DeviceConnectionError(f"Replace failed: {str(e)}")

class JuniperJunosHandler(BaseDeviceHandler):
    def _get_capabilities(self) -> DeviceCapabilities:
        return DeviceCapabilities(
            supports_config_replace=True,
            supports_config_merge=True,
            supports_rollback=True,
            supports_commit_confirm=True,
            config_format="set",
            backup_commands=[
                "show configuration | display set",
                "show configuration",
                "show version",
                "show chassis hardware"
            ],
            health_commands=[
                "show chassis routing-engine",
                "show chassis environment",
                "show interfaces terse",
                "show system uptime"
            ]
        )

    async def connect(self) -> bool:
        try:
            self.connection = ConnectHandler(**self.connection_params)

            # Enter configuration mode to verify access
            output = self.connection.send_command("show version")
            if "Junos" not in output and "JUNOS" not in output:
                raise DeviceConnectionError("Device response validation failed")

            logger.info("Successfully connected to Juniper JunOS device")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to Juniper device: {e}")
            raise DeviceConnectionError(f"Connection failed: {str(e)}")

    async def disconnect(self) -> bool:
        try:
            if self.connection:
                # Exit configuration mode if in it
                self.connection.send_command("exit")
                self.connection.disconnect()
                self.connection = None
            return True
        except Exception as e:
            logger.error(f"Disconnect error: {e}")
            return False

    async def get_config(self, config_type: str = "running") -> str:
        if not self.connection:
            raise DeviceConnectionError("No active connection")

        command_map = {
            "running": "show configuration | display set",
            "candidate": "show configuration | display set",
            "committed": "show configuration | display set"
        }

        command = command_map.get(config_type, "show configuration | display set")

        try:
            config = self.connection.send_command(command, delay_factor=3)
            return config
        except Exception as e:
            raise DeviceConnectionError(f"Failed to get {config_type} config: {str(e)}")

    async def deploy_config(
        self,
        config_content: str,
        deployment_method: str = "merge"
    ) -> Dict[str, Any]:
        if not self.connection:
            raise DeviceConnectionError("No active connection")

        try:
            result = {
                "success": False,
                "method": deployment_method,
                "changes": [],
                "warnings": [],
                "errors": []
            }

            # Enter configuration mode
            self.connection.send_command("configure")

            if deployment_method == "replace":
                # Load replace for atomic configuration replacement
                self.connection.send_command("load replace terminal")
                self.connection.send_multiline(config_content)
                self.connection.send_command("")  # End multiline input

            elif deployment_method == "merge":
                # Load merge for incremental changes
                config_lines = [line.strip() for line in config_content.split('\n')
                              if line.strip() and line.strip().startswith('set')]

                for line in config_lines:
                    output = self.connection.send_command(line)
                    if "error" in output.lower():
                        result["errors"].append(f"Error in command '{line}': {output}")

            # Check configuration
            check_output = self.connection.send_command("commit check")
            if "error" in check_output.lower():
                result["errors"].append(f"Commit check failed: {check_output}")
                self.connection.send_command("rollback 0")
                self.connection.send_command("exit")
                return result

            # Commit configuration with confirm (safety feature)
            commit_output = self.connection.send_command("commit confirmed 5")

            if "commit complete" in commit_output.lower():
                # Configuration applied successfully, confirm it
                final_commit = self.connection.send_command("commit")
                if "commit complete" in final_commit.lower():
                    result["success"] = True
                    result["changes"] = config_content.split('\n')
                else:
                    result["errors"].append(f"Final commit failed: {final_commit}")
            else:
                result["errors"].append(f"Commit failed: {commit_output}")

            # Exit configuration mode
            self.connection.send_command("exit")

            return result

        except Exception as e:
            # Ensure we exit configuration mode
            try:
                self.connection.send_command("rollback 0")
                self.connection.send_command("exit")
            except:
                pass

            logger.error(f"JunOS configuration deployment failed: {e}")
            raise DeviceConnectionError(f"Deploy failed: {str(e)}")

    async def get_health_metrics(self) -> Dict[str, Any]:
        if not self.connection:
            raise DeviceConnectionError("No active connection")

        metrics = {}

        try:
            # Routing engine status
            re_output = self.connection.send_command("show chassis routing-engine")
            metrics["routing_engine"] = self._parse_routing_engine(re_output)

            # Environment status
            env_output = self.connection.send_command("show chassis environment")
            metrics["environment"] = self._parse_environment(env_output)

            # Interface summary
            int_output = self.connection.send_command("show interfaces terse")
            metrics["interfaces"] = self._parse_junos_interfaces(int_output)

            # System uptime
            uptime_output = self.connection.send_command("show system uptime")
            metrics["uptime"] = uptime_output.strip()

            return metrics

        except Exception as e:
            logger.error(f"Failed to get JunOS health metrics: {e}")
            raise DeviceConnectionError(f"Health check failed: {str(e)}")

    async def create_checkpoint(self, name: str) -> str:
        if not self.connection:
            raise DeviceConnectionError("No active connection")

        try:
            # Create rescue configuration
            output = self.connection.send_command(f"request system configuration rescue save {name}")

            if "Rescue configuration saved" in output:
                logger.info(f"JunOS checkpoint {name} created successfully")
                return name
            else:
                raise DeviceConnectionError(f"Failed to create checkpoint: {output}")

        except Exception as e:
            logger.error(f"JunOS checkpoint creation failed: {e}")
            raise DeviceConnectionError(f"Checkpoint failed: {str(e)}")

    async def rollback_to_checkpoint(self, checkpoint_name: str) -> bool:
        if not self.connection:
            raise DeviceConnectionError("No active connection")

        try:
            # Enter configuration mode and rollback
            self.connection.send_command("configure")

            # Load rescue configuration
            output = self.connection.send_command(f"load rescue {checkpoint_name}")

            if "load complete" in output.lower():
                # Commit the rollback
                commit_output = self.connection.send_command("commit")
                if "commit complete" in commit_output.lower():
                    self.connection.send_command("exit")
                    logger.info(f"Successfully rolled back to checkpoint {checkpoint_name}")
                    return True
                else:
                    self.connection.send_command("rollback 0")
                    self.connection.send_command("exit")
                    raise DeviceConnectionError(f"Rollback commit failed: {commit_output}")
            else:
                self.connection.send_command("exit")
                raise DeviceConnectionError(f"Rollback load failed: {output}")

        except Exception as e:
            logger.error(f"JunOS rollback failed: {e}")
            raise DeviceConnectionError(f"Rollback error: {str(e)}")

    def _parse_routing_engine(self, output: str) -> Dict[str, Any]:
        re_info = {"status": "unknown", "cpu": 0, "memory": 0}

        lines = output.split('\n')
        for line in lines:
            if "CPU utilization" in line:
                import re
                match = re.search(r'(\d+)%', line)
                if match:
                    re_info["cpu"] = int(match.group(1))
            elif "Memory utilization" in line:
                import re
                match = re.search(r'(\d+)%', line)
                if match:
                    re_info["memory"] = int(match.group(1))
            elif "Status" in line and "Online" in line:
                re_info["status"] = "online"

        return re_info

    def _parse_environment(self, output: str) -> Dict[str, Any]:
        env_info = {"temperature": "unknown", "fans": "unknown", "power": "unknown"}

        if "OK" in output:
            env_info["status"] = "OK"

        return env_info

    def _parse_junos_interfaces(self, output: str) -> Dict[str, Any]:
        interfaces = {"total": 0, "up": 0, "down": 0}

        lines = output.split('\n')
        for line in lines:
            if "up/up" in line:
                interfaces["up"] += 1
                interfaces["total"] += 1
            elif "down" in line and "/" in line:
                interfaces["down"] += 1
                interfaces["total"] += 1

        return interfaces

class DeviceHandlerFactory:
    _handlers = {
        DeviceVendor.CISCO_IOS: CiscoIOSHandler,
        DeviceVendor.CISCO_IOS_XE: CiscoIOSHandler,
        DeviceVendor.CISCO_NX_OS: CiscoNXOSHandler,
        DeviceVendor.JUNIPER_JUNOS: JuniperJunosHandler
    }

    @classmethod
    def create_handler(
        cls,
        vendor: DeviceVendor,
        connection_params: Dict[str, Any]
    ) -> BaseDeviceHandler:
        if vendor not in cls._handlers:
            raise ValidationError(f"Unsupported device vendor: {vendor.value}")

        handler_class = cls._handlers[vendor]
        return handler_class(connection_params)

    @classmethod
    def get_supported_vendors(cls) -> List[DeviceVendor]:
        return list(cls._handlers.keys())

    @classmethod
    def get_vendor_capabilities(cls, vendor: DeviceVendor) -> Optional[DeviceCapabilities]:
        if vendor not in cls._handlers:
            return None

        # Create a temporary handler to get capabilities
        temp_handler = cls._handlers[vendor]({})
        return temp_handler._get_capabilities()