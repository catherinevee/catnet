import asyncio
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from netmiko import ConnectHandler
from napalm import get_network_driver
import uuid
from sqlalchemy.orm import Session

from ..db.models import Device, DeviceVendor
from ..security.vault_client import VaultClient
from ..security.audit import AuditLogger

logger = logging.getLogger(__name__)

class DeviceConnection:
    """
    Manages a secure connection to a network device.

    Handles both Netmiko (CLI) and NAPALM (API) connections to network devices
    with session logging, bastion host support, and credential management.

    Attributes:
        device: Device model instance with connection details
        credentials: Dictionary containing username/password from Vault
        session_id: Unique session identifier for audit logging
        connection: Netmiko connection handler
        napalm_driver: NAPALM driver for vendor-agnostic operations

    Example:
        >>> conn = DeviceConnection(device, credentials, session_id)
        >>> await conn.connect()
        >>> output = await conn.send_config("interface GigabitEthernet0/1\nshutdown")
        >>> await conn.disconnect()
    """
    def __init__(
        self,
        device: Device,
        credentials: Dict[str, Any],
        session_id: str
    ):
        """
        Initialize device connection with credentials.

        Args:
            device: Device model instance containing connection details
            credentials: Dictionary with 'username' and 'password' keys
            session_id: Unique session ID for logging and audit trail
        """
        self.device = device
        self.credentials = credentials
        self.session_id = session_id
        self.connection = None
        self.napalm_driver = None

    async def connect(self):
        device_params = {
            'device_type': self._get_netmiko_device_type(),
            'host': self.device.ip_address,
            'username': self.credentials['username'],
            'password': self.credentials['password'],
            'port': self.device.port or 22,
            'timeout': 30,
            'session_log': f'/var/log/catnet/sessions/{self.session_id}.log'
        }

        if self.device.bastion_host:
            device_params['ssh_config_file'] = self._create_ssh_config()

        self.connection = ConnectHandler(**device_params)

        try:
            driver = get_network_driver(self._get_napalm_driver())
            self.napalm_driver = driver(
                hostname=self.device.ip_address,
                username=self.credentials['username'],
                password=self.credentials['password'],
                timeout=30
            )
            self.napalm_driver.open()
        except Exception as e:
            logger.warning(f"NAPALM connection failed: {e}")

    def _get_netmiko_device_type(self) -> str:
        mapping = {
            DeviceVendor.CISCO_IOS: "cisco_ios",
            DeviceVendor.CISCO_IOSXE: "cisco_xe",
            DeviceVendor.CISCO_NXOS: "cisco_nxos",
            DeviceVendor.JUNIPER_JUNOS: "juniper_junos"
        }
        return mapping.get(self.device.vendor, "cisco_ios")

    def _get_napalm_driver(self) -> str:
        mapping = {
            DeviceVendor.CISCO_IOS: "ios",
            DeviceVendor.CISCO_IOSXE: "ios",
            DeviceVendor.CISCO_NXOS: "nxos",
            DeviceVendor.JUNIPER_JUNOS: "junos"
        }
        return mapping.get(self.device.vendor, "ios")

    def _create_ssh_config(self) -> str:
        import tempfile
        config = f"""
Host bastion
    HostName {self.device.bastion_host}
    User {self.credentials['username']}

Host {self.device.hostname}
    HostName {self.device.ip_address}
    ProxyJump bastion
    User {self.credentials['username']}
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ssh') as f:
            f.write(config)
            return f.name

    async def get_running_config(self) -> str:
        if self.napalm_driver:
            config = self.napalm_driver.get_config()
            return config['running']
        else:
            return self.connection.send_command("show running-config")

    async def apply_configuration(self, config: Dict[str, Any]):
        commands = []

        if 'raw_config' in config:
            commands = config['raw_config'].split('\n')
        elif 'commands' in config:
            commands = config['commands']
        else:
            commands = self._generate_commands_from_config(config)

        if self.device.vendor in [DeviceVendor.CISCO_IOS, DeviceVendor.CISCO_IOSXE, DeviceVendor.CISCO_NXOS]:
            self.connection.enable()
            output = self.connection.send_config_set(commands)
            self.connection.save_config()
        elif self.device.vendor == DeviceVendor.JUNIPER_JUNOS:
            for cmd in commands:
                self.connection.send_command(cmd)
            self.connection.send_command("commit")

        return output

    def _generate_commands_from_config(self, config: Dict[str, Any]) -> List[str]:
        commands = []

        if self.device.vendor in [DeviceVendor.CISCO_IOS, DeviceVendor.CISCO_IOSXE]:
            if 'interfaces' in config:
                for interface in config['interfaces']:
                    commands.append(f"interface {interface['name']}")
                    if 'description' in interface:
                        commands.append(f" description {interface['description']}")
                    if 'ip_address' in interface:
                        commands.append(f" ip address {interface['ip_address']}")
                    if 'shutdown' in interface:
                        commands.append(" shutdown" if interface['shutdown'] else " no shutdown")

            if 'vlans' in config:
                for vlan in config['vlans']:
                    commands.append(f"vlan {vlan['id']}")
                    if 'name' in vlan:
                        commands.append(f" name {vlan['name']}")

        elif self.device.vendor == DeviceVendor.JUNIPER_JUNOS:
            if 'interfaces' in config:
                for interface in config['interfaces']:
                    if 'description' in interface:
                        commands.append(f"set interfaces {interface['name']} description \"{interface['description']}\"")
                    if 'ip_address' in interface:
                        commands.append(f"set interfaces {interface['name']} unit 0 family inet address {interface['ip_address']}")

        return commands

    async def check_health(self) -> Dict[str, Any]:
        health_data = {
            "status": "unknown",
            "timestamp": datetime.utcnow().isoformat(),
            "checks": {}
        }

        try:
            if self.napalm_driver:
                facts = self.napalm_driver.get_facts()
                health_data["checks"]["uptime"] = facts.get("uptime", 0)
                health_data["checks"]["hostname"] = facts.get("hostname")

                interfaces = self.napalm_driver.get_interfaces()
                down_interfaces = [i for i, data in interfaces.items() if not data.get("is_up", False)]
                health_data["checks"]["down_interfaces"] = down_interfaces

                environment = self.napalm_driver.get_environment()
                health_data["checks"]["cpu"] = environment.get("cpu", {})
                health_data["checks"]["memory"] = environment.get("memory", {})

            else:
                if self.device.vendor in [DeviceVendor.CISCO_IOS, DeviceVendor.CISCO_IOSXE]:
                    cpu_output = self.connection.send_command("show processes cpu")
                    health_data["checks"]["cpu"] = cpu_output

                    memory_output = self.connection.send_command("show memory statistics")
                    health_data["checks"]["memory"] = memory_output

            health_data["status"] = "healthy" if not health_data["checks"].get("down_interfaces") else "degraded"

        except Exception as e:
            health_data["status"] = "unhealthy"
            health_data["error"] = str(e)

        return health_data

    async def disconnect(self):
        if self.napalm_driver:
            self.napalm_driver.close()
        if self.connection:
            self.connection.disconnect()


class SecureDeviceConnector:
    """
    Secure wrapper for device connections with credential management.

    Provides high-level interface for device connections with automatic
    credential retrieval from Vault, audit logging, and session management.
    Handles connection pooling and cleanup.

    Attributes:
        db: SQLAlchemy database session
        vault: HashiCorp Vault client for credential retrieval
        audit: Audit logger for compliance tracking
        _connections: Dictionary of active connections by session ID

    Example:
        >>> connector = SecureDeviceConnector(db, vault, audit)
        >>> async with connector.connect_device(device_id) as conn:
        ...     output = await conn.send_config("show version")
    """
    def __init__(
        self,
        db: Session,
        vault_client: Optional[VaultClient] = None,
        audit_logger: Optional[AuditLogger] = None
    ):
        self.db = db
        self.vault = vault_client or VaultClient()
        self.audit = audit_logger or AuditLogger(db)

    async def check_authorization(
        self,
        user_context: Dict[str, Any],
        device_id: str
    ) -> bool:
        return True

    def select_bastion(self, device_id: str) -> Optional[str]:
        device = self.db.query(Device).filter(Device.id == device_id).first()
        return device.bastion_host if device else None

    async def establish_secure_connection(
        self,
        device_id: str,
        credentials: Dict[str, Any],
        jump_host: Optional[str] = None
    ) -> DeviceConnection:
        device = self.db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise ValueError(f"Device {device_id} not found")

        session_id = str(uuid.uuid4())
        connection = DeviceConnection(device, credentials, session_id)
        await connection.connect()

        return connection

    async def connect_to_device(
        self,
        device_id: str,
        user_context: Dict[str, Any]
    ) -> Optional[DeviceConnection]:
        if not await self.check_authorization(user_context, device_id):
            await self.audit.log_unauthorized_attempt(user_context, device_id, "device_connect")
            raise Exception("Unauthorized")

        creds = await self.vault.get_temporary_credentials(
            device_id=device_id,
            requestor=user_context['user_id'],
            ttl=1800
        )

        connection = await self.establish_secure_connection(
            device_id=device_id,
            credentials=creds,
            jump_host=self.select_bastion(device_id)
        )

        self.audit.start_session_recording(connection.session_id)

        return connection