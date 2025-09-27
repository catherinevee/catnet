"""
Data models for device service.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
import uuid

from pydantic import BaseModel, Field, validator, IPvAnyAddress


class DeviceType(str, Enum):
    """Device types."""
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    LOAD_BALANCER = "load_balancer"
    WIRELESS_AP = "wireless_ap"
    WIRELESS_CONTROLLER = "wireless_controller"
    VPN_GATEWAY = "vpn_gateway"
    IDS_IPS = "ids_ips"
    OTHER = "other"


class DeviceVendor(str, Enum):
    """Device vendors."""
    CISCO = "cisco"
    JUNIPER = "juniper"
    ARISTA = "arista"
    HUAWEI = "huawei"
    FORTINET = "fortinet"
    PALO_ALTO = "palo_alto"
    F5 = "f5"
    OTHER = "other"


class DeviceStatus(str, Enum):
    """Device status."""
    REGISTERED = "registered"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    MAINTENANCE = "maintenance"
    DECOMMISSIONED = "decommissioned"
    ERROR = "error"


class ConnectionProtocol(str, Enum):
    """Connection protocols."""
    SSH = "ssh"
    TELNET = "telnet"
    NETCONF = "netconf"
    RESTCONF = "restconf"
    SNMP = "snmp"
    API = "api"
    GNMI = "gnmi"


class Device(BaseModel):
    """Device model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    hostname: str
    ip_address: str
    device_type: DeviceType
    vendor: DeviceVendor
    model: Optional[str] = None
    os_version: Optional[str] = None
    serial_number: Optional[str] = None
    location: Optional[str] = None
    site: Optional[str] = None
    rack: Optional[str] = None
    port: int = 22
    protocol: ConnectionProtocol = ConnectionProtocol.SSH
    credential_path: Optional[str] = None
    status: DeviceStatus = DeviceStatus.REGISTERED
    tags: Dict[str, str] = {}
    metadata: Dict[str, Any] = {}
    last_seen: Optional[datetime] = None
    last_backup: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None


class DeviceCredential(BaseModel):
    """Device credential model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    username: str
    password: Optional[str] = None
    enable_password: Optional[str] = None
    private_key: Optional[str] = None
    public_key: Optional[str] = None
    passphrase: Optional[str] = None
    community_string: Optional[str] = None  # SNMP
    api_key: Optional[str] = None
    certificate: Optional[str] = None
    credential_type: str  # primary, backup, read-only, etc.
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None


class DeviceConnection(BaseModel):
    """Device connection model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    connection_id: str
    protocol: ConnectionProtocol
    is_alive: bool
    established_at: datetime
    last_activity: datetime
    session_data: Optional[Dict[str, Any]] = None


class DeviceCommand(BaseModel):
    """Device command model."""
    command: str
    output: Optional[str] = None
    error: Optional[str] = None
    success: bool = False
    execution_time: Optional[float] = None  # seconds
    executed_at: Optional[datetime] = None


class DeviceConfiguration(BaseModel):
    """Device configuration model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    configuration: str
    configuration_encrypted: Optional[str] = None
    config_type: str  # running, startup, candidate
    version: int = 1
    hash: Optional[str] = None
    deployment_id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None


class DeviceBackup(BaseModel):
    """Device backup model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    backup_type: str  # scheduled, manual, pre_deployment
    configuration: str
    configuration_encrypted: Optional[str] = None
    size_bytes: int
    hash: str
    storage_location: Optional[str] = None
    deployment_id: Optional[str] = None
    description: Optional[str] = None
    retention_days: int = 30
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None


class DeviceInterface(BaseModel):
    """Device interface model."""
    name: str
    description: Optional[str] = None
    type: Optional[str] = None  # ethernet, serial, loopback, vlan
    speed: Optional[str] = None
    duplex: Optional[str] = None
    mtu: Optional[int] = None
    mac_address: Optional[str] = None
    ip_address: Optional[str] = None
    netmask: Optional[str] = None
    vlan: Optional[int] = None
    status: str  # up, down, admin-down
    admin_status: str  # up, down
    last_change: Optional[datetime] = None
    statistics: Optional[Dict[str, Any]] = None


class DeviceRoute(BaseModel):
    """Device routing entry model."""
    destination: str
    netmask: str
    gateway: Optional[str] = None
    interface: Optional[str] = None
    metric: Optional[int] = None
    protocol: str  # connected, static, ospf, bgp, etc.
    admin_distance: Optional[int] = None
    tag: Optional[int] = None
    is_best: bool = False


class DeviceNeighbor(BaseModel):
    """Device neighbor model (CDP/LLDP)."""
    local_interface: str
    remote_device: str
    remote_interface: str
    remote_ip: Optional[str] = None
    platform: Optional[str] = None
    capabilities: Optional[List[str]] = None
    discovery_protocol: str  # cdp, lldp


class DeviceCreateRequest(BaseModel):
    """Device creation request."""
    hostname: str = Field(..., min_length=1, max_length=255)
    ip_address: str
    device_type: DeviceType
    vendor: DeviceVendor
    model: Optional[str] = Field(None, max_length=100)
    os_version: Optional[str] = Field(None, max_length=100)
    serial_number: Optional[str] = Field(None, max_length=100)
    location: Optional[str] = Field(None, max_length=255)
    site: Optional[str] = Field(None, max_length=100)
    port: int = Field(default=22, ge=1, le=65535)
    protocol: ConnectionProtocol = ConnectionProtocol.SSH
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1)
    enable_password: Optional[str] = None
    private_key: Optional[str] = None
    tags: Dict[str, str] = {}
    validate_connectivity: bool = True

    @validator('ip_address')
    def validate_ip(cls, v):
        try:
            IPvAnyAddress(v)
            return v
        except ValueError:
            raise ValueError('Invalid IP address')


class DeviceUpdateRequest(BaseModel):
    """Device update request."""
    hostname: Optional[str] = Field(None, max_length=255)
    ip_address: Optional[str] = None
    device_type: Optional[DeviceType] = None
    vendor: Optional[DeviceVendor] = None
    model: Optional[str] = Field(None, max_length=100)
    os_version: Optional[str] = Field(None, max_length=100)
    location: Optional[str] = Field(None, max_length=255)
    site: Optional[str] = Field(None, max_length=100)
    port: Optional[int] = Field(None, ge=1, le=65535)
    protocol: Optional[ConnectionProtocol] = None
    status: Optional[DeviceStatus] = None
    tags: Optional[Dict[str, str]] = None


class DeviceResponse(BaseModel):
    """Device response model."""
    id: str
    hostname: str
    ip_address: str
    device_type: str
    vendor: str
    model: Optional[str] = None
    os_version: Optional[str] = None
    status: str
    location: Optional[str] = None
    site: Optional[str] = None
    tags: Dict[str, str] = {}
    last_seen: Optional[datetime] = None
    created_at: datetime
    updated_at: Optional[datetime] = None


class ConnectionRequest(BaseModel):
    """Connection request."""
    persistent: bool = False
    timeout: int = Field(default=30, ge=1, le=300)
    retry_count: int = Field(default=3, ge=1, le=10)


class ConnectionResponse(BaseModel):
    """Connection response."""
    device_id: str
    connected: bool
    connection_id: Optional[str] = None
    protocol: Optional[str] = None
    established_at: Optional[datetime] = None
    error: Optional[str] = None


class ConfigurationRequest(BaseModel):
    """Configuration request."""
    configuration: str
    config_type: str = "running"
    save_to_startup: bool = False
    commit: bool = True
    rollback_on_failure: bool = True
    backup_before_apply: bool = True
    validate: bool = True
    deployment_id: Optional[str] = None


class ConfigurationResponse(BaseModel):
    """Configuration response."""
    device_id: str
    configuration_id: Optional[str] = None
    config_type: str
    content: str
    applied: bool = False
    validated: bool = False
    errors: List[str] = []
    warnings: List[str] = []
    retrieved_at: datetime


class BackupRequest(BaseModel):
    """Backup request."""
    backup_type: str = "manual"  # manual, scheduled, pre_deployment
    config_type: str = "running"
    description: Optional[str] = None
    retention_days: int = Field(default=30, ge=1, le=365)
    compress: bool = False
    encrypt: bool = True
    deployment_id: Optional[str] = None


class BackupResponse(BaseModel):
    """Backup response."""
    device_id: str
    backup_id: str
    backup_type: str
    size_bytes: int
    compressed: bool = False
    encrypted: bool = True
    storage_location: Optional[str] = None
    created_at: datetime
    expires_at: Optional[datetime] = None


class ExecuteRequest(BaseModel):
    """Command execution request."""
    commands: List[str]
    timeout: int = Field(default=30, ge=1, le=300)
    allow_dangerous: bool = False
    persistent_connection: bool = False
    save_output: bool = True


class ExecuteResponse(BaseModel):
    """Command execution response."""
    device_id: str
    results: List[DeviceCommand]
    executed_at: datetime
    total_execution_time: Optional[float] = None


class DeviceQueryRequest(BaseModel):
    """Device query request."""
    device_type: Optional[DeviceType] = None
    vendor: Optional[DeviceVendor] = None
    status: Optional[DeviceStatus] = None
    location: Optional[str] = None
    site: Optional[str] = None
    tags: Optional[Dict[str, str]] = None
    ip_range: Optional[str] = None  # CIDR notation
    hostname_pattern: Optional[str] = None  # Regex pattern
    last_seen_after: Optional[datetime] = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class DeviceHealth(BaseModel):
    """Device health status."""
    device_id: str
    status: str  # healthy, degraded, unhealthy, error
    cpu_usage: Optional[float] = None  # percentage
    memory_usage: Optional[float] = None  # percentage
    temperature: Optional[float] = None  # celsius
    uptime: Optional[int] = None  # seconds
    interface_status: Dict[str, str] = {}  # interface -> status
    alerts: List[str] = []
    error: Optional[str] = None
    last_check: datetime


class DeviceMetrics(BaseModel):
    """Device metrics."""
    device_id: str
    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    bandwidth_usage: Dict[str, float] = {}  # interface -> Mbps
    packet_loss: float = 0.0
    latency: Optional[float] = None  # ms
    temperature: Optional[float] = None
    power_status: Optional[str] = None
    fan_status: Optional[List[str]] = None
    interface_errors: Dict[str, int] = {}
    bgp_peers_up: Optional[int] = None
    bgp_peers_total: Optional[int] = None
    ospf_neighbors: Optional[int] = None
    active_sessions: Optional[int] = None


class DeviceEvent(BaseModel):
    """Device event model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    event_type: str  # config_change, interface_down, high_cpu, etc.
    severity: str  # critical, high, medium, low, info
    description: str
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None


class DeviceCompliance(BaseModel):
    """Device compliance status."""
    device_id: str
    compliant: bool
    checks: List[Dict[str, Any]]
    policy_version: str
    last_check: datetime
    violations: List[str] = []
    remediation: Optional[List[str]] = None


class BulkOperationRequest(BaseModel):
    """Bulk operation request."""
    device_ids: List[str]
    operation: str  # backup, reboot, update, configure
    parameters: Dict[str, Any] = {}
    parallel_execution: bool = False
    max_parallel: int = Field(default=10, ge=1, le=50)
    continue_on_error: bool = True


class BulkOperationResponse(BaseModel):
    """Bulk operation response."""
    operation_id: str
    total_devices: int
    successful: List[str]
    failed: List[Dict[str, str]]  # device_id -> error
    skipped: List[str]
    execution_time: float
    status: str  # completed, partial, failed