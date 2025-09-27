from typing import Dict, List, Optional, Any, Union
import asyncio
import json
import structlog
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import uuid

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from napalm import get_network_driver
import paramiko

from ..db.models import Device, DeviceVendor, DeviceConnection, ConfigBackup
from ..db.database import get_db_session
from ..security.vault import VaultClient
from ..security.secure_connector import SecureDeviceConnector
from ..security.audit import AuditLogger
from ..core.exceptions import (
    DeviceConnectionError, SecurityError, ValidationError,
    AuthenticationError, NetworkError
)

logger = structlog.get_logger()

class ConnectionStatus(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"
    MAINTENANCE = "maintenance"

class DeviceType(Enum):
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    LOAD_BALANCER = "load_balancer"
    WIRELESS_CONTROLLER = "wireless_controller"

@dataclass
class DeviceConnectionInfo:
    device_id: str
    connection_id: str
    status: ConnectionStatus
    connected_at: Optional[datetime] = None
    last_activity: Optional[datetime] = None
    session_info: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None

@dataclass
class CommandResult:
    command: str
    output: str
    success: bool
    execution_time: float
    timestamp: datetime
    device_id: str
    error: Optional[str] = None

class DeviceService:
    def __init__(self):
        self.vault = VaultClient()
        self.secure_connector = SecureDeviceConnector()
        self.audit = AuditLogger()
        self.active_connections: Dict[str, DeviceConnectionInfo] = {}
        self.connection_pool_size = 10
        self.command_timeout = 30
        self.connection_timeout = 60

        self.vendor_drivers = {
            DeviceVendor.CISCO_IOS: "ios",
            DeviceVendor.CISCO_IOS_XE: "ios",
            DeviceVendor.CISCO_NX_OS: "nxos",
            DeviceVendor.JUNIPER_JUNOS: "junos",
            DeviceVendor.PALO_ALTO: "panos",
            DeviceVendor.FORTINET: "fortios",
            DeviceVendor.ARUBA: "aruba_os"
        }

    async def get_device_inventory(
        self,
        user_context: Dict[str, Any],
        filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        try:
            async with get_db_session() as session:
                query = session.query(Device)

                if filters:
                    if filters.get('vendor'):
                        query = query.filter(Device.vendor == filters['vendor'])
                    if filters.get('device_type'):
                        query = query.filter(Device.device_type == filters['device_type'])
                    if filters.get('site'):
                        query = query.filter(Device.site == filters['site'])
                    if filters.get('status'):
                        query = query.filter(Device.status == filters['status'])

                devices = await query.all()

                device_list = []
                for device in devices:
                    device_info = {
                        'id': str(device.id),
                        'hostname': device.hostname,
                        'ip_address': device.ip_address,
                        'vendor': device.vendor.value,
                        'device_type': device.device_type,
                        'model': device.model,
                        'os_version': device.os_version,
                        'site': device.site,
                        'status': device.status,
                        'last_backup': device.last_backup.isoformat() if device.last_backup else None,
                        'created_at': device.created_at.isoformat(),
                        'connection_status': self._get_connection_status(str(device.id))
                    }
                    device_list.append(device_info)

                await self.audit.log_device_inventory_access(
                    user_id=user_context['user_id'],
                    device_count=len(device_list),
                    filters=filters
                )

                return device_list

        except Exception as e:
            logger.error(f"Failed to get device inventory: {e}")
            raise NetworkError(f"Failed to retrieve device inventory: {str(e)}")

    async def connect_to_device(
        self,
        device_id: str,
        user_context: Dict[str, Any],
        connection_type: str = "ssh"
    ) -> str:
        try:
            if device_id in self.active_connections:
                connection_info = self.active_connections[device_id]
                if connection_info.status == ConnectionStatus.CONNECTED:
                    logger.info(f"Reusing existing connection to device {device_id}")
                    return connection_info.connection_id

            async with get_db_session() as session:
                device = await session.get(Device, device_id)
                if not device:
                    raise ValidationError(f"Device {device_id} not found")

                if not await self._check_device_authorization(user_context, device_id):
                    await self.audit.log_unauthorized_device_access(
                        user_id=user_context['user_id'],
                        device_id=device_id,
                        action="connect"
                    )
                    raise AuthenticationError(
                        f"User not authorized to access device {device_id}",
                        user_id=user_context['user_id']
                    )

                connection_id = str(uuid.uuid4())

                connection_info = DeviceConnectionInfo(
                    device_id=device_id,
                    connection_id=connection_id,
                    status=ConnectionStatus.CONNECTING
                )
                self.active_connections[device_id] = connection_info

                try:
                    credentials = await self.vault.get_device_credentials(
                        device_id=device_id,
                        user_id=user_context['user_id'],
                        ttl_seconds=3600
                    )

                    connection_params = {
                        'device_type': self.vendor_drivers.get(device.vendor, 'generic'),
                        'host': device.ip_address,
                        'username': credentials['username'],
                        'password': credentials['password'],
                        'timeout': self.connection_timeout,
                        'session_log': f"/tmp/catnet_session_{connection_id}.log"
                    }

                    if device.ssh_port and device.ssh_port != 22:
                        connection_params['port'] = device.ssh_port

                    if device.jump_host:
                        bastion_creds = await self.vault.get_bastion_credentials(
                            device.jump_host,
                            user_context['user_id']
                        )
                        connection_params.update({
                            'ssh_config_file': None,
                            'sock': self._create_ssh_tunnel(
                                device.jump_host,
                                bastion_creds,
                                device.ip_address,
                                device.ssh_port or 22
                            )
                        })

                    netmiko_connection = ConnectHandler(**connection_params)

                    connection_info.status = ConnectionStatus.CONNECTED
                    connection_info.connected_at = datetime.utcnow()
                    connection_info.last_activity = datetime.utcnow()
                    connection_info.session_info = {
                        'connection_type': connection_type,
                        'netmiko_connection': netmiko_connection,
                        'device_vendor': device.vendor.value,
                        'credentials_expires': (
                            datetime.utcnow() + timedelta(seconds=3600)
                        ).isoformat()
                    }

                    device_conn = DeviceConnection(
                        id=uuid.UUID(connection_id),
                        device_id=device.id,
                        user_id=uuid.UUID(user_context['user_id']),
                        connection_type=connection_type,
                        status="active",
                        connected_at=connection_info.connected_at,
                        session_data={
                            'user_agent': user_context.get('user_agent'),
                            'ip_address': user_context.get('ip_address'),
                            'session_id': user_context.get('session_id')
                        }
                    )

                    session.add(device_conn)
                    await session.commit()

                    await self.audit.log_device_connection(
                        user_id=user_context['user_id'],
                        device_id=device_id,
                        connection_id=connection_id,
                        connection_type=connection_type,
                        success=True
                    )

                    logger.info(
                        f"Successfully connected to device {device_id}",
                        device_id=device_id,
                        connection_id=connection_id,
                        user_id=user_context['user_id']
                    )

                    return connection_id

                except NetmikoAuthenticationException as e:
                    connection_info.status = ConnectionStatus.ERROR
                    connection_info.error_message = "Authentication failed"
                    await self.audit.log_device_connection(
                        user_id=user_context['user_id'],
                        device_id=device_id,
                        connection_id=connection_id,
                        connection_type=connection_type,
                        success=False,
                        error=str(e)
                    )
                    raise AuthenticationError(
                        f"Authentication failed for device {device_id}",
                        device_id=device_id
                    )

                except NetmikoTimeoutException as e:
                    connection_info.status = ConnectionStatus.ERROR
                    connection_info.error_message = "Connection timeout"
                    raise NetworkError(
                        f"Connection timeout for device {device_id}",
                        host=device.ip_address,
                        port=device.ssh_port or 22
                    )

                except Exception as e:
                    connection_info.status = ConnectionStatus.ERROR
                    connection_info.error_message = str(e)
                    raise DeviceConnectionError(
                        f"Failed to connect to device {device_id}: {str(e)}",
                        device_id=device_id,
                        connection_type=connection_type
                    )

        except Exception as e:
            if device_id in self.active_connections:
                del self.active_connections[device_id]
            logger.error(f"Device connection failed: {e}")
            raise

    async def execute_command(
        self,
        device_id: str,
        command: str,
        user_context: Dict[str, Any],
        timeout: Optional[int] = None
    ) -> CommandResult:
        try:
            if device_id not in self.active_connections:
                raise DeviceConnectionError(
                    f"No active connection to device {device_id}",
                    device_id=device_id
                )

            connection_info = self.active_connections[device_id]
            if connection_info.status != ConnectionStatus.CONNECTED:
                raise DeviceConnectionError(
                    f"Device {device_id} not connected",
                    device_id=device_id
                )

            if not await self._validate_command_safety(command, device_id):
                await self.audit.log_dangerous_command_attempt(
                    user_id=user_context['user_id'],
                    device_id=device_id,
                    command=command
                )
                raise SecurityError(
                    f"Command '{command}' is not allowed on device {device_id}",
                    details={'command': command, 'device_id': device_id}
                )

            netmiko_connection = connection_info.session_info['netmiko_connection']
            start_time = datetime.utcnow()

            try:
                output = netmiko_connection.send_command(
                    command,
                    delay_factor=2,
                    max_loops=500,
                    cmd_verify=True
                )

                end_time = datetime.utcnow()
                execution_time = (end_time - start_time).total_seconds()

                connection_info.last_activity = end_time

                result = CommandResult(
                    command=command,
                    output=output,
                    success=True,
                    execution_time=execution_time,
                    timestamp=start_time,
                    device_id=device_id
                )

                await self.audit.log_command_execution(
                    user_id=user_context['user_id'],
                    device_id=device_id,
                    command=command,
                    success=True,
                    execution_time=execution_time,
                    output_length=len(output)
                )

                logger.info(
                    f"Command executed successfully",
                    device_id=device_id,
                    command=command,
                    execution_time=execution_time
                )

                return result

            except Exception as e:
                end_time = datetime.utcnow()
                execution_time = (end_time - start_time).total_seconds()

                result = CommandResult(
                    command=command,
                    output="",
                    success=False,
                    execution_time=execution_time,
                    timestamp=start_time,
                    device_id=device_id,
                    error=str(e)
                )

                await self.audit.log_command_execution(
                    user_id=user_context['user_id'],
                    device_id=device_id,
                    command=command,
                    success=False,
                    execution_time=execution_time,
                    error=str(e)
                )

                logger.error(
                    f"Command execution failed",
                    device_id=device_id,
                    command=command,
                    error=str(e)
                )

                return result

        except Exception as e:
            logger.error(f"Command execution error: {e}")
            raise

    async def backup_device_config(
        self,
        device_id: str,
        user_context: Dict[str, Any],
        backup_type: str = "running"
    ) -> str:
        try:
            if device_id not in self.active_connections:
                await self.connect_to_device(device_id, user_context)

            connection_info = self.active_connections[device_id]
            device_vendor = connection_info.session_info['device_vendor']

            backup_commands = {
                'cisco_ios': {
                    'running': 'show running-config',
                    'startup': 'show startup-config'
                },
                'cisco_nxos': {
                    'running': 'show running-config',
                    'startup': 'show startup-config'
                },
                'juniper_junos': {
                    'running': 'show configuration | display set',
                    'startup': 'show configuration'
                }
            }

            vendor_key = device_vendor.lower().replace('_', '_')
            if vendor_key not in backup_commands:
                vendor_key = 'cisco_ios'

            command = backup_commands[vendor_key].get(backup_type,
                                                    backup_commands[vendor_key]['running'])

            result = await self.execute_command(device_id, command, user_context)

            if not result.success:
                raise DeviceConnectionError(
                    f"Failed to backup device {device_id}: {result.error}",
                    device_id=device_id
                )

            config_content = result.output
            encrypted_content = await self.vault.encrypt_config(config_content)

            backup_id = str(uuid.uuid4())

            async with get_db_session() as session:
                device = await session.get(Device, device_id)

                backup = ConfigBackup(
                    id=uuid.UUID(backup_id),
                    device_id=uuid.UUID(device_id),
                    config_type=backup_type,
                    content_encrypted=encrypted_content,
                    size_bytes=len(config_content),
                    created_by=uuid.UUID(user_context['user_id']),
                    backup_metadata={
                        'command_used': command,
                        'device_vendor': device_vendor,
                        'device_hostname': device.hostname,
                        'backup_trigger': 'manual'
                    }
                )

                session.add(backup)

                device.last_backup = datetime.utcnow()
                await session.commit()

            await self.audit.log_config_backup(
                user_id=user_context['user_id'],
                device_id=device_id,
                backup_id=backup_id,
                backup_type=backup_type,
                config_size=len(config_content)
            )

            logger.info(
                f"Device backup completed",
                device_id=device_id,
                backup_id=backup_id,
                backup_type=backup_type
            )

            return backup_id

        except Exception as e:
            logger.error(f"Device backup failed: {e}")
            raise DeviceConnectionError(
                f"Failed to backup device {device_id}: {str(e)}",
                device_id=device_id,
                operation="backup"
            )

    async def disconnect_device(
        self,
        device_id: str,
        user_context: Dict[str, Any]
    ) -> bool:
        try:
            if device_id not in self.active_connections:
                logger.warning(f"No active connection to device {device_id}")
                return True

            connection_info = self.active_connections[device_id]

            if 'netmiko_connection' in connection_info.session_info:
                try:
                    connection_info.session_info['netmiko_connection'].disconnect()
                except Exception as e:
                    logger.warning(f"Error during netmiko disconnect: {e}")

            async with get_db_session() as session:
                device_conn = await session.get(DeviceConnection, connection_info.connection_id)
                if device_conn:
                    device_conn.status = "disconnected"
                    device_conn.disconnected_at = datetime.utcnow()
                    await session.commit()

            del self.active_connections[device_id]

            await self.audit.log_device_disconnection(
                user_id=user_context['user_id'],
                device_id=device_id,
                connection_id=connection_info.connection_id
            )

            logger.info(f"Disconnected from device {device_id}")
            return True

        except Exception as e:
            logger.error(f"Error disconnecting from device {device_id}: {e}")
            return False

    async def get_device_health(
        self,
        device_id: str,
        user_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        try:
            health_commands = [
                "show version",
                "show memory",
                "show processes cpu",
                "show interfaces summary"
            ]

            health_data = {
                'device_id': device_id,
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'unknown',
                'metrics': {}
            }

            for command in health_commands:
                try:
                    result = await self.execute_command(device_id, command, user_context)
                    if result.success:
                        health_data['metrics'][command.replace(' ', '_')] = {
                            'output': result.output,
                            'execution_time': result.execution_time
                        }
                except Exception as e:
                    logger.warning(f"Health check command failed: {command} - {e}")
                    health_data['metrics'][command.replace(' ', '_')] = {
                        'error': str(e)
                    }

            health_data['status'] = 'healthy' if len(health_data['metrics']) > 0 else 'unhealthy'

            await self.audit.log_device_health_check(
                user_id=user_context['user_id'],
                device_id=device_id,
                health_status=health_data['status']
            )

            return health_data

        except Exception as e:
            logger.error(f"Device health check failed: {e}")
            raise DeviceConnectionError(
                f"Failed to check health of device {device_id}: {str(e)}",
                device_id=device_id
            )

    def _get_connection_status(self, device_id: str) -> str:
        if device_id in self.active_connections:
            return self.active_connections[device_id].status.value
        return ConnectionStatus.DISCONNECTED.value

    async def _check_device_authorization(
        self,
        user_context: Dict[str, Any],
        device_id: str
    ) -> bool:
        try:
            async with get_db_session() as session:
                device = await session.get(Device, device_id)
                if not device:
                    return False

                return True

        except Exception as e:
            logger.error(f"Authorization check failed: {e}")
            return False

    async def _validate_command_safety(
        self,
        command: str,
        device_id: str
    ) -> bool:
        dangerous_patterns = [
            r'reload',
            r'reboot',
            r'shutdown',
            r'erase\s+startup-config',
            r'format\s+flash',
            r'delete\s+flash',
            r'clear\s+configuration',
            r'request\s+system\s+reboot',
            r'request\s+system\s+halt',
            r'request\s+system\s+zeroize',
            r'factory-reset',
            r'reset\s+system'
        ]

        import re
        command_lower = command.lower()

        for pattern in dangerous_patterns:
            if re.search(pattern, command_lower):
                return False

        return True

    def _create_ssh_tunnel(
        self,
        bastion_host: str,
        bastion_creds: Dict[str, str],
        target_host: str,
        target_port: int
    ):
        try:
            import socket

            bastion_ssh = paramiko.SSHClient()
            bastion_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            bastion_ssh.connect(
                hostname=bastion_host,
                username=bastion_creds['username'],
                password=bastion_creds['password'],
                timeout=30
            )

            transport = bastion_ssh.get_transport()
            dest_addr = (target_host, target_port)
            local_addr = ('127.0.0.1', 0)

            channel = transport.open_channel("direct-tcpip", dest_addr, local_addr)
            return channel

        except Exception as e:
            logger.error(f"Failed to create SSH tunnel: {e}")
            raise NetworkError(
                f"Failed to create SSH tunnel to {target_host}:{target_port} via {bastion_host}",
                host=target_host,
                port=target_port
            )

    async def cleanup_stale_connections(self):
        try:
            current_time = datetime.utcnow()
            stale_threshold = timedelta(hours=2)

            stale_connections = []
            for device_id, connection_info in self.active_connections.items():
                if connection_info.last_activity:
                    if current_time - connection_info.last_activity > stale_threshold:
                        stale_connections.append(device_id)

            for device_id in stale_connections:
                try:
                    connection_info = self.active_connections[device_id]
                    if 'netmiko_connection' in connection_info.session_info:
                        connection_info.session_info['netmiko_connection'].disconnect()
                    del self.active_connections[device_id]
                    logger.info(f"Cleaned up stale connection to device {device_id}")
                except Exception as e:
                    logger.error(f"Error cleaning up connection {device_id}: {e}")

            async with get_db_session() as session:
                stale_db_connections = await session.execute(
                    "UPDATE device_connections SET status = 'timeout' "
                    "WHERE status = 'active' AND connected_at < %s",
                    (current_time - stale_threshold,)
                )
                await session.commit()

            logger.info(f"Cleaned up {len(stale_connections)} stale connections")

        except Exception as e:
            logger.error(f"Connection cleanup failed: {e}")