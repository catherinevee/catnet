"""
Network Discovery Models
Database models for automated network discovery and inventory management
"""
from sqlalchemy import Column, String, DateTime, JSON, Boolean, Integer, Text, ForeignKey, Enum
from sqlalchemy.orm import relationship
from src.db.base import Base
import enum
from datetime import datetime
import uuid


class DiscoveryMethod(str, enum.Enum):
    """Discovery method types"""
    CDP = "cdp"          # Cisco Discovery Protocol
    LLDP = "lldp"        # Link Layer Discovery Protocol
    SNMP = "snmp"        # Simple Network Management Protocol
    MANUAL = "manual"    # Manually added
    API = "api"          # API integration


class DiscoveryStatus(str, enum.Enum):
    """Discovery job status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class DeviceInventory(Base):
    """
    Complete device inventory with auto-discovery

    Tracks all discovered devices including managed and unmanaged
    devices found through network discovery.

    Attributes:
        id: Unique identifier
        hostname: Device hostname
        ip_address: Primary IP address
        vendor: Device vendor (cisco, juniper, arista, etc.)
        model: Device model number
        serial_number: Serial number (unique)
        os_version: Operating system version
        discovery_method: How device was discovered
        discovered_at: When first discovered
        last_seen_at: Last time device was reachable
        is_managed: Whether device is under CatNet management
        is_reachable: Current reachability status
    """
    __tablename__ = "device_inventory"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    hostname = Column(String, nullable=False, index=True)
    ip_address = Column(String, nullable=False, index=True)

    # Device identification
    vendor = Column(String, index=True)  # cisco, juniper, arista, hp, dell
    model = Column(String)
    serial_number = Column(String, unique=True, index=True)
    os_version = Column(String)
    platform = Column(String)  # IOS, NX-OS, Junos, etc.

    # Discovery info
    discovery_method = Column(Enum(DiscoveryMethod), nullable=False)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    discovered_by = Column(String)  # discovery_job_id or user_id
    last_seen_at = Column(DateTime, default=datetime.utcnow)

    # Status
    is_managed = Column(Boolean, default=False)
    is_reachable = Column(Boolean, default=True)
    management_candidate = Column(Boolean, default=True)  # Eligible for management

    # Device capabilities (from CDP/LLDP)
    capabilities = Column(JSON, default=dict)
    # Example: {"router": true, "switch": true, "bridge": false}

    # Hardware information
    cpu_count = Column(Integer)
    memory_mb = Column(Integer)
    uptime_seconds = Column(Integer)
    last_reboot_reason = Column(String)

    # Network interfaces
    interfaces = Column(JSON, default=list)
    # Example: [{"name": "GigabitEthernet0/0", "ip": "10.0.0.1", "status": "up"}]

    # CDP/LLDP neighbors
    neighbors = Column(JSON, default=list)
    # Example: [{"device": "router-2", "interface": "Gi0/1", "remote_interface": "Gi0/0"}]

    # SNMP information
    snmp_community = Column(String)  # Encrypted
    snmp_version = Column(String)  # v2c, v3

    # Location information
    site = Column(String)
    rack = Column(String)
    position = Column(String)
    physical_location = Column(String)

    # Metadata
    tags = Column(JSON, default=list)
    metadata = Column(JSON, default=dict)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<DeviceInventory(hostname={self.hostname}, ip={self.ip_address}, vendor={self.vendor})>"


class NetworkTopology(Base):
    """
    Network topology mapping

    Represents the physical/logical topology of the network
    including nodes (devices) and edges (connections).

    Attributes:
        id: Unique identifier
        name: Topology name
        nodes: List of devices in topology
        edges: List of connections between devices
        generated_at: When topology was generated
        topology_type: physical, logical, layer2, layer3
    """
    __tablename__ = "network_topology"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    description = Column(Text)

    # Topology type
    topology_type = Column(String, default="physical")  # physical, logical, layer2, layer3

    # Topology data
    nodes = Column(JSON, nullable=False, default=list)
    # Example: [{"id": "device-1", "label": "Core Router", "type": "router"}]

    edges = Column(JSON, nullable=False, default=list)
    # Example: [{"source": "device-1", "target": "device-2", "interface": "Gi0/0"}]

    # Statistics
    device_count = Column(Integer, default=0)
    connection_count = Column(Integer, default=0)

    # Metadata
    generated_at = Column(DateTime, default=datetime.utcnow)
    generated_by = Column(String)  # discovery_job_id or user_id
    discovery_job_id = Column(String, ForeignKey("discovery_jobs.id"))

    # Version tracking
    version = Column(Integer, default=1)
    parent_topology_id = Column(String, ForeignKey("network_topology.id"))

    def __repr__(self):
        return f"<NetworkTopology(name={self.name}, devices={self.device_count})>"


class DiscoveryJob(Base):
    """
    Discovery job tracking

    Tracks automated discovery operations including progress,
    results, and errors.

    Attributes:
        id: Unique identifier
        name: Job name
        seed_devices: Starting devices for discovery
        discovery_depth: How many hops to discover
        methods: Discovery methods to use (CDP, LLDP, SNMP)
        status: Current job status
        devices_discovered: Number of devices found
        devices_failed: Number of devices that failed
    """
    __tablename__ = "discovery_jobs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    description = Column(Text)

    # Discovery parameters
    seed_devices = Column(JSON, nullable=False)  # List of IPs to start from
    discovery_depth = Column(Integer, default=3)  # How many hops
    methods = Column(JSON, default=lambda: ["cdp", "lldp"])  # Discovery methods

    # Filters
    vendor_filter = Column(JSON)  # Only discover specific vendors
    exclude_devices = Column(JSON)  # Devices to skip

    # Progress tracking
    status = Column(Enum(DiscoveryStatus), default=DiscoveryStatus.PENDING)
    devices_discovered = Column(Integer, default=0)
    devices_reachable = Column(Integer, default=0)
    devices_failed = Column(Integer, default=0)
    connections_found = Column(Integer, default=0)

    # Results
    discovered_device_ids = Column(JSON, default=list)
    failed_device_ips = Column(JSON, default=list)
    error_messages = Column(JSON, default=list)

    # Timing
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    duration_seconds = Column(Integer)

    # Configuration
    parallel_workers = Column(Integer, default=10)
    timeout_seconds = Column(Integer, default=30)
    retry_attempts = Column(Integer, default=2)

    # User context
    created_by = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    topology = relationship("NetworkTopology", back_populates="discovery_job", uselist=False)

    def __repr__(self):
        return f"<DiscoveryJob(name={self.name}, status={self.status}, discovered={self.devices_discovered})>"

    def calculate_duration(self):
        """Calculate job duration in seconds"""
        if self.started_at and self.completed_at:
            delta = self.completed_at - self.started_at
            self.duration_seconds = int(delta.total_seconds())


# Add back-reference to NetworkTopology
NetworkTopology.discovery_job = relationship("DiscoveryJob", back_populates="topology")


class DeviceChange(Base):
    """
    Device change tracking

    Tracks changes to discovered devices for change detection
    and alerting.

    Attributes:
        id: Unique identifier
        device_id: Device that changed
        change_type: Type of change (added, removed, modified, etc.)
        field_changed: Which field changed
        old_value: Previous value
        new_value: New value
        detected_at: When change was detected
    """
    __tablename__ = "device_changes"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = Column(String, ForeignKey("device_inventory.id"), nullable=False)

    # Change details
    change_type = Column(String, nullable=False, index=True)
    # Values: added, removed, modified, neighbor_added, neighbor_removed, unreachable, recovered

    field_changed = Column(String)  # hostname, os_version, neighbor, etc.
    old_value = Column(Text)
    new_value = Column(Text)

    # Change context
    detected_at = Column(DateTime, default=datetime.utcnow, index=True)
    detected_by = Column(String)  # discovery_job_id or monitoring_task_id

    # Severity for alerting
    severity = Column(String, default="info")  # info, warning, critical

    # Acknowledgment
    acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(String)
    acknowledged_at = Column(DateTime)

    # Metadata
    metadata = Column(JSON, default=dict)

    def __repr__(self):
        return f"<DeviceChange(device={self.device_id}, type={self.change_type}, detected={self.detected_at})>"


class DiscoveryCredential(Base):
    """
    Discovery credentials

    Stores credentials used for device discovery (SNMP, SSH, etc.)
    organized by credential sets for different device groups.

    Attributes:
        id: Unique identifier
        name: Credential set name
        credential_type: snmp, ssh, telnet, api
        username: Username (encrypted)
        password: Password (encrypted in Vault)
        snmp_community: SNMP community string (encrypted)
        priority: Order to try credentials
    """
    __tablename__ = "discovery_credentials"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    description = Column(Text)

    # Credential type
    credential_type = Column(String, nullable=False)  # snmp, ssh, telnet, api

    # SSH/Telnet credentials (reference to Vault)
    username = Column(String)
    password_vault_path = Column(String)  # Path in Vault
    enable_password_vault_path = Column(String)

    # SNMP credentials
    snmp_version = Column(String)  # v2c, v3
    snmp_community_vault_path = Column(String)  # For v2c
    snmp_username = Column(String)  # For v3
    snmp_auth_protocol = Column(String)  # MD5, SHA for v3
    snmp_priv_protocol = Column(String)  # DES, AES for v3

    # Applicability
    device_pattern = Column(String)  # Regex pattern for device IPs/hostnames
    priority = Column(Integer, default=10)  # Lower = tried first
    enabled = Column(Boolean, default=True)

    # Usage tracking
    success_count = Column(Integer, default=0)
    failure_count = Column(Integer, default=0)
    last_used_at = Column(DateTime)

    # Metadata
    created_by = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<DiscoveryCredential(name={self.name}, type={self.credential_type}, priority={self.priority})>"
