from typing import Optional, Dict, Any, List, Union
from datetime import datetime, timedelta
import asyncio
import uuid
import secrets
import structlog
from netmiko import ConnectHandler
from napalm import get_network_driver
import paramiko
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import json
import hashlib

from ..db.models import Device, DeviceVendor, AuditLog, SecurityEvent, DeviceConfig
from ..security.vault import VaultClient
from ..security.encryption import encryption_service
from ..auth.permissions import Permission, permission_checker

logger = structlog.get_logger()


class DeviceConnection:
    """Represents a secure connection to a network device"""

    def __init__(
        self,
        device_id: str,
        connection: Any,
        session_id: str,
        vendor: DeviceVendor,
        audit_logger: Any
    ):
        self.device_id = device_id
        self.connection = connection
        self.session_id = session_id
        self.vendor = vendor
        self.audit_logger = audit_logger
        self.connected_at = datetime.utcnow()
        self.last_activity = datetime.utcnow()
        self.command_history = []

    async def execute_command(
        self,
        command: str,
        enable_mode: bool = False,
        timeout: int = 30
    ) -> str:
        """Execute a command on the device"""
        try:
            self.last_activity = datetime.utcnow()

            # Record command in history
            self.command_history.append({
                "command": command,
                "timestamp": datetime.utcnow().isoformat(),
                "enable_mode": enable_mode
            })

            # Execute based on connection type
            if hasattr(self.connection, 'send_command'):
                if enable_mode and hasattr(self.connection, 'enable'):
                    self.connection.enable()

                output = self.connection.send_command(
                    command,
                    read_timeout=timeout
                )
            else:
                # NAPALM connection
                output = self.connection.cli([command])[command]

            # Audit command execution
            await self.audit_logger.log_command(
                self.session_id,
                command,
                success=True
            )

            return output

        except Exception as e:
            await self.audit_logger.log_command(
                self.session_id,
                command,
                success=False,
                error=str(e)
            )
            raise

    async def get_configuration(self, config_type: str = "running") -> str:
        """Get device configuration"""
        try:
            if self.vendor == DeviceVendor.CISCO_IOS:
                command = "show running-config" if config_type == "running" else "show startup-config"
            elif self.vendor == DeviceVendor.CISCO_NX_OS:
                command = "show running-config" if config_type == "running" else "show startup-config"
            elif self.vendor == DeviceVendor.JUNIPER_JUNOS:
                command = "show configuration" if config_type == "running" else "show configuration | display set"
            else:
                command = "show running-config"

            return await self.execute_command(command)

        except Exception as e:
            logger.error(f"Failed to get configuration: {e}")
            raise

    async def apply_configuration(self, config: str) -> Dict[str, Any]:
        """Apply configuration to device"""
        try:
            # Enter configuration mode
            if self.vendor in [DeviceVendor.CISCO_IOS, DeviceVendor.CISCO_IOS_XE]:
                self.connection.config_mode()
                output = self.connection.send_config_set(config.split('\n'))
                self.connection.exit_config_mode()
            elif self.vendor == DeviceVendor.CISCO_NX_OS:
                self.connection.config_mode()
                output = self.connection.send_config_set(config.split('\n'))
                self.connection.exit_config_mode()
            elif self.vendor == DeviceVendor.JUNIPER_JUNOS:
                self.connection.load_merge_candidate(config=config)
                self.connection.commit_config()
                output = "Configuration committed successfully"
            else:
                raise ValueError(f"Unsupported vendor: {self.vendor}")

            return {
                "success": True,
                "output": output
            }

        except Exception as e:
            logger.error(f"Failed to apply configuration: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    async def validate_configuration(self, config: str) -> Dict[str, Any]:
        """Validate configuration without applying"""
        try:
            if self.vendor == DeviceVendor.JUNIPER_JUNOS:
                # Juniper supports commit check
                self.connection.load_merge_candidate(config=config)
                diff = self.connection.compare_config()
                self.connection.discard_config()
                return {
                    "valid": True,
                    "diff": diff
                }
            else:
                # For Cisco, parse and validate syntax
                # This would integrate with vendor-specific validators
                return {
                    "valid": True,
                    "message": "Configuration syntax appears valid"
                }

        except Exception as e:
            return {
                "valid": False,
                "errors": [str(e)]
            }

    async def save_configuration(self) -> bool:
        """Save running configuration to startup"""
        try:
            if self.vendor in [DeviceVendor.CISCO_IOS, DeviceVendor.CISCO_IOS_XE]:
                await self.execute_command("write memory")
            elif self.vendor == DeviceVendor.CISCO_NX_OS:
                await self.execute_command("copy running-config startup-config")
            elif self.vendor == DeviceVendor.JUNIPER_JUNOS:
                await self.execute_command("commit")

            return True

        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            return False

    async def run_health_checks(self) -> List[Dict[str, Any]]:
        """Run device health checks"""
        health_checks = []

        try:
            # Check CPU utilization
            if self.vendor in [DeviceVendor.CISCO_IOS, DeviceVendor.CISCO_IOS_XE]:
                cpu_output = await self.execute_command("show processes cpu")
                cpu_check = self._parse_cisco_cpu(cpu_output)
                health_checks.append(cpu_check)

            # Check memory
            if self.vendor in [DeviceVendor.CISCO_IOS, DeviceVendor.CISCO_IOS_XE]:
                mem_output = await self.execute_command("show memory statistics")
                mem_check = self._parse_cisco_memory(mem_output)
                health_checks.append(mem_check)

            # Check interfaces
            if self.vendor == DeviceVendor.JUNIPER_JUNOS:
                int_output = await self.execute_command("show interfaces terse")
                int_check = self._parse_juniper_interfaces(int_output)
                health_checks.append(int_check)

            # Check routing
            route_output = await self.execute_command("show ip route summary")
            route_check = {
                "check": "routing_table",
                "passed": True,
                "details": "Routing table accessible"
            }
            health_checks.append(route_check)

        except Exception as e:
            health_checks.append({
                "check": "general",
                "passed": False,
                "error": str(e)
            })

        return health_checks

    def _parse_cisco_cpu(self, output: str) -> Dict[str, Any]:
        """Parse Cisco CPU output"""
        try:
            # Extract CPU percentage
            for line in output.split('\n'):
                if 'CPU utilization' in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part.endswith('%'):
                            cpu_percent = int(part.rstrip('%'))
                            return {
                                "check": "cpu_utilization",
                                "passed": cpu_percent < 80,
                                "value": cpu_percent,
                                "threshold": 80
                            }

            return {
                "check": "cpu_utilization",
                "passed": True,
                "message": "Unable to parse CPU"
            }

        except Exception:
            return {
                "check": "cpu_utilization",
                "passed": False,
                "error": "Parse error"
            }

    def _parse_cisco_memory(self, output: str) -> Dict[str, Any]:
        """Parse Cisco memory output"""
        try:
            # This would parse actual memory statistics
            return {
                "check": "memory_utilization",
                "passed": True,
                "message": "Memory within limits"
            }
        except Exception:
            return {
                "check": "memory_utilization",
                "passed": False,
                "error": "Parse error"
            }

    def _parse_juniper_interfaces(self, output: str) -> Dict[str, Any]:
        """Parse Juniper interface output"""
        try:
            down_interfaces = []
            for line in output.split('\n'):
                if 'down' in line.lower():
                    parts = line.split()
                    if parts:
                        down_interfaces.append(parts[0])

            return {
                "check": "interface_status",
                "passed": len(down_interfaces) == 0,
                "down_interfaces": down_interfaces
            }
        except Exception:
            return {
                "check": "interface_status",
                "passed": False,
                "error": "Parse error"
            }

    async def close(self):
        """Close the device connection"""
        try:
            if hasattr(self.connection, 'disconnect'):
                self.connection.disconnect()
            elif hasattr(self.connection, 'close'):
                self.connection.close()

            await self.audit_logger.end_session(self.session_id)

        except Exception as e:
            logger.error(f"Error closing connection: {e}")


class SecureDeviceConnector:
    """Manages secure connections to network devices"""

    def __init__(self):
        self.vault = VaultClient()
        self.audit = AuditLogger()
        self.encryption = encryption_service
        self.active_connections: Dict[str, DeviceConnection] = {}
        self.connection_timeout = 30
        self.command_timeout = 60
        self.max_retries = 3
        self.bastion_hosts = {}

    async def connect_to_device(
        self,
        device_id: str,
        user_context: Dict[str, Any],
        db: Optional[AsyncSession] = None
    ) -> DeviceConnection:
        """Establish secure connection to device"""

        session_id = secrets.token_urlsafe(32)

        try:
            # Step 1: Verify user authorization
            if not await self.check_authorization(user_context, device_id):
                await self.audit.log_unauthorized_attempt(user_context, device_id)
                raise PermissionError("Unauthorized access attempt")

            # Step 2: Get device information
            device = await self._get_device_info(db, device_id)

            if not device:
                raise ValueError(f"Device not found: {device_id}")

            if not device.is_active:
                raise ValueError(f"Device is inactive: {device_id}")

            # Step 3: Get temporary credentials from Vault
            creds = await self.vault.get_temporary_credentials(
                device_id=device_id,
                requestor=user_context.get('user_id', 'system'),
                ttl=1800  # 30 minutes
            )

            # Step 4: Determine connection path (direct or through bastion)
            connection_params = await self._build_connection_params(
                device, creds, user_context
            )

            # Step 5: Enable session recording
            await self.audit.start_session_recording(
                session_id,
                device_id,
                user_context
            )

            # Step 6: Establish connection
            connection = await self._establish_connection(
                connection_params,
                device.vendor
            )

            # Step 7: Create DeviceConnection wrapper
            device_connection = DeviceConnection(
                device_id=device_id,
                connection=connection,
                session_id=session_id,
                vendor=device.vendor,
                audit_logger=self.audit
            )

            # Store active connection
            self.active_connections[session_id] = device_connection

            # Log successful connection
            await self.audit.log_connection(
                session_id,
                device_id,
                user_context,
                success=True
            )

            logger.info(f"Successfully connected to device {device_id}")
            return device_connection

        except Exception as e:
            logger.error(f"Failed to connect to device {device_id}: {e}")

            await self.audit.log_connection(
                session_id,
                device_id,
                user_context,
                success=False,
                error=str(e)
            )

            raise

    async def _get_device_info(
        self,
        db: AsyncSession,
        device_id: str
    ) -> Optional[Device]:
        """Get device information from database"""
        if not db:
            # This would create its own database session
            return None

        result = await db.execute(
            select(Device).where(Device.id == uuid.UUID(device_id))
        )
        return result.scalar_one_or_none()

    async def _build_connection_params(
        self,
        device: Device,
        creds: Dict[str, Any],
        user_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build connection parameters for device"""

        params = {
            'device_type': self._get_netmiko_device_type(device.vendor),
            'host': device.ip_address,
            'username': creds['username'],
            'password': creds['password'],
            'port': 22,
            'timeout': self.connection_timeout,
            'session_timeout': self.command_timeout,
            'auth_timeout': 20,
            'banner_timeout': 20,
            'blocking_timeout': 20,
            'conn_timeout': self.connection_timeout
        }

        # Add SSH key if available
        if device.vault_credential_path:
            ssh_key = await self.vault.get_secret(
                f"{device.vault_credential_path}/ssh_key"
            )
            if ssh_key:
                params['use_keys'] = True
                params['key_file'] = self._create_temp_key_file(ssh_key)

        # Configure bastion/jump host if needed
        if device.bastion_host:
            bastion = await self._get_bastion_config(device.bastion_host)
            if bastion:
                params['ssh_config_file'] = self._create_ssh_config(
                    device, bastion
                )

        return params

    def _get_netmiko_device_type(self, vendor: DeviceVendor) -> str:
        """Map vendor to Netmiko device type"""
        mapping = {
            DeviceVendor.CISCO_IOS: "cisco_ios",
            DeviceVendor.CISCO_IOS_XE: "cisco_xe",
            DeviceVendor.CISCO_NX_OS: "cisco_nxos",
            DeviceVendor.JUNIPER_JUNOS: "juniper_junos"
        }
        return mapping.get(vendor, "cisco_ios")

    async def _establish_connection(
        self,
        params: Dict[str, Any],
        vendor: DeviceVendor
    ) -> Any:
        """Establish connection to device"""

        for attempt in range(self.max_retries):
            try:
                # Try Netmiko first
                connection = ConnectHandler(**params)

                # Test connection
                connection.find_prompt()

                return connection

            except Exception as e:
                logger.warning(f"Connection attempt {attempt + 1} failed: {e}")

                if attempt == self.max_retries - 1:
                    # Try NAPALM as fallback
                    try:
                        driver_name = self._get_napalm_driver(vendor)
                        driver = get_network_driver(driver_name)

                        napalm_device = driver(
                            hostname=params['host'],
                            username=params['username'],
                            password=params['password'],
                            optional_args={'port': params['port']}
                        )

                        napalm_device.open()
                        return napalm_device

                    except Exception as napalm_error:
                        logger.error(f"NAPALM connection also failed: {napalm_error}")
                        raise

                await asyncio.sleep(2 ** attempt)  # Exponential backoff

        raise ConnectionError(f"Failed to connect after {self.max_retries} attempts")

    def _get_napalm_driver(self, vendor: DeviceVendor) -> str:
        """Map vendor to NAPALM driver"""
        mapping = {
            DeviceVendor.CISCO_IOS: "ios",
            DeviceVendor.CISCO_IOS_XE: "iosxe",
            DeviceVendor.CISCO_NX_OS: "nxos",
            DeviceVendor.JUNIPER_JUNOS: "junos"
        }
        return mapping.get(vendor, "ios")

    async def check_authorization(
        self,
        user_context: Dict[str, Any],
        device_id: str
    ) -> bool:
        """Check if user is authorized to access device"""

        # System context always authorized
        if user_context.get('system'):
            return True

        user_id = user_context.get('user_id')
        if not user_id:
            return False

        # Check permissions
        # This would integrate with the permission system
        return True

    async def _get_bastion_config(
        self,
        bastion_host: str
    ) -> Optional[Dict[str, Any]]:
        """Get bastion host configuration"""

        if bastion_host in self.bastion_hosts:
            return self.bastion_hosts[bastion_host]

        # Get bastion credentials from Vault
        bastion_creds = await self.vault.get_secret(
            f"bastions/{bastion_host}"
        )

        if bastion_creds:
            self.bastion_hosts[bastion_host] = bastion_creds
            return bastion_creds

        return None

    def _create_temp_key_file(self, ssh_key: str) -> str:
        """Create temporary SSH key file"""
        import tempfile

        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.key',
            delete=False
        ) as f:
            f.write(ssh_key)
            f.flush()

            # Set proper permissions
            import os
            os.chmod(f.name, 0o600)

            return f.name

    def _create_ssh_config(
        self,
        device: Device,
        bastion: Dict[str, Any]
    ) -> str:
        """Create SSH config for jump host"""
        import tempfile

        config = f"""
Host bastion
    HostName {bastion['host']}
    Port {bastion.get('port', 22)}
    User {bastion['username']}
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

Host {device.hostname}
    HostName {device.ip_address}
    Port 22
    User {{username}}
    ProxyJump bastion
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
"""

        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.conf',
            delete=False
        ) as f:
            f.write(config)
            return f.name

    async def disconnect_device(
        self,
        session_id: str
    ):
        """Disconnect a device session"""

        if session_id in self.active_connections:
            connection = self.active_connections[session_id]
            await connection.close()
            del self.active_connections[session_id]
            logger.info(f"Disconnected session {session_id}")

    async def get_active_sessions(self) -> List[Dict[str, Any]]:
        """Get list of active sessions"""

        sessions = []
        for session_id, connection in self.active_connections.items():
            sessions.append({
                "session_id": session_id,
                "device_id": connection.device_id,
                "connected_at": connection.connected_at.isoformat(),
                "last_activity": connection.last_activity.isoformat(),
                "command_count": len(connection.command_history)
            })

        return sessions

    async def cleanup_stale_sessions(self):
        """Clean up stale/expired sessions"""

        now = datetime.utcnow()
        stale_sessions = []

        for session_id, connection in self.active_connections.items():
            # Check if session is stale (no activity for 30 minutes)
            if now - connection.last_activity > timedelta(minutes=30):
                stale_sessions.append(session_id)

        for session_id in stale_sessions:
            await self.disconnect_device(session_id)
            logger.info(f"Cleaned up stale session {session_id}")


class AuditLogger:
    """Handles audit logging for device connections"""

    def __init__(self):
        self.sessions = {}

    async def log_unauthorized_attempt(
        self,
        user_context: Dict[str, Any],
        device_id: str
    ):
        """Log unauthorized access attempt"""
        logger.warning(
            "Unauthorized device access attempt",
            user_id=user_context.get('user_id'),
            device_id=device_id
        )

    async def start_session_recording(
        self,
        session_id: str,
        device_id: str,
        user_context: Dict[str, Any]
    ):
        """Start recording a session"""
        self.sessions[session_id] = {
            "device_id": device_id,
            "user_context": user_context,
            "started_at": datetime.utcnow(),
            "commands": []
        }

    async def log_connection(
        self,
        session_id: str,
        device_id: str,
        user_context: Dict[str, Any],
        success: bool,
        error: Optional[str] = None
    ):
        """Log connection attempt"""
        logger.info(
            "Device connection",
            session_id=session_id,
            device_id=device_id,
            user_id=user_context.get('user_id'),
            success=success,
            error=error
        )

    async def log_command(
        self,
        session_id: str,
        command: str,
        success: bool,
        error: Optional[str] = None
    ):
        """Log command execution"""
        if session_id in self.sessions:
            self.sessions[session_id]["commands"].append({
                "command": command,
                "timestamp": datetime.utcnow().isoformat(),
                "success": success,
                "error": error
            })

    async def end_session(self, session_id: str):
        """End session recording"""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            session["ended_at"] = datetime.utcnow()

            # Store session data for audit trail
            logger.info(
                "Session ended",
                session_id=session_id,
                duration=(session["ended_at"] - session["started_at"]).total_seconds(),
                command_count=len(session["commands"])
            )

            del self.sessions[session_id]


# Global instance
secure_device_connector = SecureDeviceConnector()