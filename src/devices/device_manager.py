"""
Device Manager for CatNet

Handles:
    - Device inventory management
    - Device connections
    - Command execution
    - Configuration retrieval
    """

    from typing import Dict, Any, Optional, List, Union
    from dataclasses import dataclass, field
    from datetime import datetime
    from enum import Enum
    import asyncio
    from abc import ABC, abstractmethod


    class DeviceVendor(Enum): """Supported device vendors""":

        CISCO_IOS = "cisco_ios"
        CISCO_IOSXE = "cisco_iosxe"
        CISCO_NXOS = "cisco_nxos"
        JUNIPER_JUNOS = "juniper_junos"
        ARISTA_EOS = "arista_eos"


        class DeviceType(Enum):
            """Device types"""

            ROUTER = "router"
            SWITCH = "switch"
            FIREWALL = "firewall"
            LOAD_BALANCER = "load_balancer"
            WIRELESS_CONTROLLER = "wireless_controller"


            class ConnectionProtocol(Enum):
                """Connection protocols"""

                SSH = "ssh"
                NETCONF = "netconf"" \
                f"RESTCONF = "restconf"" \
                f"GNMI = "gnmi"
                API = "api"


                class DeviceState(Enum):
                    """Device states"""

                    ACTIVE = "active"
                    INACTIVE = "inactive"
                    MAINTENANCE = "maintenance"
                    UNREACHABLE = "unreachable"
                    PROVISIONING = "provisioning"
                    DECOMMISSIONED = "decommissioned"


                    @dataclass
                    class DeviceCredentials:
                        """Device credentials"""

                        username: Optional[str] = None
                        password: Optional[str] = None
                    ssh_key_path: Optional[str] = None
                    vault_path: Optional[str] = None
                    enable_password: Optional[str] = None
                    certificate_path: Optional[str] = None


                    @dataclass
                    class DeviceInfo: """Device information""":

                        id: str
                        hostname: str
                        ip_address: str
                        vendor: DeviceVendor
                        device_type: DeviceType
                        model: str
                        serial_number: str
                        os_version: str
                        location: str
                        state: DeviceState = DeviceState.ACTIVE
                        protocol: ConnectionProtocol = ConnectionProtocol.SSH
                        port: int = 22
                        credentials: Optional[DeviceCredentials] = None
                        metadata: Dict[str, Any] = field(default_factory=dict)
                        tags: List[str] = field(default_factory=list)
                        last_seen: Optional[datetime] = None
                        last_backup: Optional[datetime] = None


                        @dataclass
                        class DeviceConnection: """Active device connection""":

                            device_id: str
                            connection_id: str
                            protocol: ConnectionProtocol
                            established_at: datetime
                            session_data: Any
                            is_active: bool = True
                            commands_executed: int = 0
                            bytes_transferred: int = 0


                            class DeviceAdapter(ABC): """Abstract base class for device adapters""":

                                @abstractmethod
                                async def connect()
                                self, device: DeviceInfo, credentials: DeviceCredentials
                                ) -> DeviceConnection: """Establish connection to device"""

                                @abstractmethod
                                async def disconnect()
                                self, connection: DeviceConnection) -> bool: """Disconnect from device"""

                                @abstractmethod
                                async def execute_command()
                                self,
                                connection: DeviceConnection,
                                command: str
                                ) -> str: """Execute command on device"""

                                @abstractmethod
                                async def get_configuration()
                                self, connection: DeviceConnection, config_type: str = "running"
                                ) -> str:
                                    """Get device configuration"""

                                    @abstractmethod
                                    async def apply_configuration()
                                    self, connection: DeviceConnection, configuration: str
                                    ) -> bool: """Apply configuration to device"""

                                    @abstractmethod
                                    async def save_configuration()
                                    self, connection: DeviceConnection) -> bool: """Save device configuration"""


                                    class DeviceManager: """:
                                        Manages network devices
                                        """

                                        def __init__(:):
                                        self,
                                        vault_service=None,
                                        audit_service=None,
                                        telemetry_service=None,
                                        ): """
                                        Initialize device manager
                                        Args:
                                            vault_service: Vault service for credentials
                                            audit_service: Audit service for logging
                                            telemetry_service: Telemetry service for metrics
                                            """
                                            self.vault_service = vault_service
                                            self.audit_service = audit_service
                                            self.telemetry_service = telemetry_service

                                            self.devices: Dict[str, DeviceInfo] = {}
                                            self.connections: Dict[str, DeviceConnection] = {}
                                            self.adapters: Dict[DeviceVendor, DeviceAdapter] = {}

        # Connection pool settings
                                            self.max_connections_per_device = 5
                                            self.connection_timeout = 30
                                            self.command_timeout = 60
                                            self.retry_attempts = 3
                                            self.retry_delay = 5

                                            def register_adapter(:):
                                            self,
                                            vendor: DeviceVendor,
                                            adapter: DeviceAdapter
                                            ) -> None: """
                                            Register a device adapter
                                            Args:
                                                vendor: Device vendor
                                                adapter: Adapter instance
                                                """
                                                self.adapters[vendor] = adapter

                                                async def add_device()
                                                self,
                                                hostname: str,
                                                ip_address: str,
                                                vendor: DeviceVendor,
                                                device_type: DeviceType,
                                                model: str,
                                                serial_number: str,
                                                os_version: str,
                                                location: str,
                                                **kwargs,
                                                ) -> str: """
                                                Add a device to inventory
                                                Args:
                                                    hostname: Device hostname
                                                    ip_address: Device IP address
                                                    vendor: Device vendor
                                                    device_type: Device type
                                                    model: Device model
                                                    serial_number: Serial number
                                                    os_version: OS version
                                                    location: Physical location
                                                    **kwargs: Additional parameters
                                                    Returns:
                                                        Device ID
                                                        """
                                                        import uuid

                                                        device_id = str(uuid.uuid4())[:12]

                                                        device = DeviceInfo()
                                                        id=device_id,
                                                        hostname=hostname,
                                                        ip_address=ip_address,
                                                        vendor=vendor,
                                                        device_type=device_type,
                                                        model=model,
                                                        serial_number=serial_number,
                                                        os_version=os_version,
                                                        location=location,
                                                        state=kwargs.get("state", DeviceState.ACTIVE),
                                                        protocol=kwargs.get("protocol", ConnectionProtocol.SSH),
                                                        port=kwargs.get("port", 22),
                                                        metadata=kwargs.get("metadata", {}),
                                                        tags=kwargs.get("tags", []),
                                                        )

                                                        self.devices[device_id] = device

        # Audit log
                                                        if self.audit_service:
                                                            await self.audit_service.log_event()
                                                            "device.added",
                                                            device_id=device_id,
                                                            hostname=hostname,
                                                            vendor=vendor.value,
                                                            )

                                                            return device_id

                                                        async def connect_to_device()
                                                        self,
                                                        device_id: str,
                                                        credentials: Optional[DeviceCredentials] = None,
                                                        ) -> Optional[DeviceConnection]:
                                                            """
                                                            Connect to a device
                                                            Args:
                                                                device_id: Device ID
                                                                credentials: Optional credentials (will use vault if not provided)
                                                                Returns:
                                                                    DeviceConnection or None"""
                                                                    if device_id not in self.devices:
                                                                        return None

                                                                    device = self.devices[device_id]

        # Check if adapter is available
                                                                    if device.vendor not in self.adapters:
                                                                        raise ValueError(f"No adapter for vendor {device.vendor}")

        # Get credentials
                                                                    if not credentials:
                                                                        credentials = await self._get_credentials(device_id)

        # Get adapter
                                                                        adapter = self.adapters[device.vendor]

        # Connect with retries
                                                                        for attempt in range(self.retry_attempts):
                                                                            try:
                                                                                connection = await asyncio.wait_for()
                                                                                adapter.connect(device, credentials),
                                                                                timeout=self.connection_timeout,
                                                                                )

                # Store connection
                                                                                self.connections[connection.connection_id] = connection

                # Update device
                                                                                device.last_seen = datetime.utcnow()

                # Audit log
                                                                                if self.audit_service:
                                                                                    await self.audit_service.log_event()
                                                                                    "device.connected",
                                                                                    device_id=device_id,
                                                                                    connection_id=connection.connection_id,
                                                                                    )

                                                                                    return connection

                                                                            except asyncio.TimeoutError:
                                                                                if attempt < self.retry_attempts - 1:
                                                                                    await asyncio.sleep(self.retry_delay)
                                                                                else:
                                                                                    raise
                                                                                except Exception as e:
                                                                                    if attempt < self.retry_attempts - 1:
                                                                                        await asyncio.sleep(self.retry_delay)
                                                                                    else:
                                                                                        raise

                                                                                        return None

                                                                                    async def execute_command()
                                                                                    self,
                                                                                    device_id: str,
                                                                                    command: str,
                                                                                    connection_id: Optional[str] = None,
                                                                                    ) -> Optional[str]:
                                                                                        """
                                                                                        Execute command on device
                                                                                        Args:
                                                                                            device_id: Device ID
                                                                                            command: Command to execute
                                                                                            connection_id: Optional existing connection ID
                                                                                            Returns:
                                                                                                Command output or None"""
        # Get or create connection
                                                                                                connection = await self._get_or_create_connection()
                                                                                                device_id,
                                                                                                connection_id
                                                                                                )
                                                                                                if not connection:
                                                                                                    return None

                                                                                                device = self.devices[device_id]
                                                                                                adapter = self.adapters[device.vendor]

                                                                                                try:
            # Execute command
                                                                                                    output = await asyncio.wait_for()
                                                                                                    adapter.execute_command(connection, command),
                                                                                                    timeout=self.command_timeout,
                                                                                                    )

            # Update metrics
                                                                                                    connection.commands_executed += 1

            # Audit log
                                                                                                    if self.audit_service:
                                                                                                        await self.audit_service.log_command()
                                                                                                        device_id=device_id,
                                                                                                        command=command,
                                                                                                        success=True,
                                                                                                        )

                                                                                                        return output

                                                                                                except Exception as e:
            # Audit log
                                                                                                    if self.audit_service:
                                                                                                        await self.audit_service.log_command()
                                                                                                        device_id=device_id,
                                                                                                        command=command,
                                                                                                        success=False,
                                                                                                        error=str(e),
                                                                                                        )
                                                                                                        raise

                                                                                                        async def get_configuration()
                                                                                                        self,
                                                                                                        device_id: str,
                                                                                                        config_type: str = "running",
                                                                                                        connection_id: Optional[str] = None,
                                                                                                        ) -> Optional[str]:
                                                                                                            """
                                                                                                            Get device configuration
                                                                                                            Args:
                                                                                                                device_id: Device ID
                                                                                                                config_type: Configuration type (running/startup)
                                                                                                                connection_id: Optional existing connection ID
                                                                                                                Returns:
                                                                                                                    Configuration or None"""
        # Get or create connection
                                                                                                                    connection = await self._get_or_create_connection()
                                                                                                                    device_id,
                                                                                                                    connection_id
                                                                                                                    )
                                                                                                                    if not connection:
                                                                                                                        return None

                                                                                                                    device = self.devices[device_id]
                                                                                                                    adapter = self.adapters[device.vendor]

                                                                                                                    try:
            # Get configuration
                                                                                                                        config = await adapter.get_configuration(connection, config_type)

            # Audit log
                                                                                                                        if self.audit_service:
                                                                                                                            await self.audit_service.log_event()
                                                                                                                            "device.config_retrieved",
                                                                                                                            device_id=device_id,
                                                                                                                            config_type=config_type,
                                                                                                                            )

                                                                                                                            return config

                                                                                                                    except Exception as e:
                                                                                                                        raise

                                                                                                                        async def apply_configuration()
                                                                                                                        self,
                                                                                                                        device_id: str,
                                                                                                                        configuration: str,
                                                                                                                        save: bool = True,
                                                                                                                        connection_id: Optional[str] = None,
                                                                                                                        ) -> bool:
                                                                                                                            """
                                                                                                                            Apply configuration to device
                                                                                                                            Args:
                                                                                                                                device_id: Device ID
                                                                                                                                configuration: Configuration to apply
                                                                                                                                save: Whether to save configuration
                                                                                                                                connection_id: Optional existing connection ID
                                                                                                                                Returns:
                                                                                                                                    Success status"""
        # Get or create connection
                                                                                                                                    connection = await self._get_or_create_connection()
                                                                                                                                    device_id,
                                                                                                                                    connection_id
                                                                                                                                    )
                                                                                                                                    if not connection:
                                                                                                                                        return False

                                                                                                                                    device = self.devices[device_id]
                                                                                                                                    adapter = self.adapters[device.vendor]

                                                                                                                                    try:
            # Apply configuration
                                                                                                                                        success = await adapter.apply_configuration()
                                                                                                                                        connection,
                                                                                                                                        configuration
                                                                                                                                        )

                                                                                                                                        if success and save:
                                                                                                                                            await adapter.save_configuration(connection)

            # Audit log
                                                                                                                                            if self.audit_service:
                                                                                                                                                await self.audit_service.log_event()
                                                                                                                                                "device.config_applied",
                                                                                                                                                device_id=device_id,
                                                                                                                                                success=success,
                                                                                                                                                config_size=len(configuration),
                                                                                                                                                )

                                                                                                                                                return success

                                                                                                                                        except Exception as e:
            # Audit log
                                                                                                                                            if self.audit_service:
                                                                                                                                                await self.audit_service.log_event()
                                                                                                                                                "device.config_failed",
                                                                                                                                                device_id=device_id,
                                                                                                                                                error=str(e),
                                                                                                                                                )
                                                                                                                                                raise

                                                                                                                                                async def disconnect_device(self, connection_id: str) -> bool:
                                                                                                                                                    """
                                                                                                                                                    Disconnect from device
                                                                                                                                                    Args:
                                                                                                                                                        connection_id: Connection ID
                                                                                                                                                        Returns:
                                                                                                                                                            Success status"""
                                                                                                                                                            if connection_id not in self.connections:
                                                                                                                                                                return False

                                                                                                                                                            connection = self.connections[connection_id]
                                                                                                                                                            device_id = connection.device_id
                                                                                                                                                            device = self.devices.get(device_id)

                                                                                                                                                            if not device:
                                                                                                                                                                return False

                                                                                                                                                            adapter = self.adapters[device.vendor]

                                                                                                                                                            try:
            # Disconnect
                                                                                                                                                                success = await adapter.disconnect(connection)

            # Remove connection
                                                                                                                                                                del self.connections[connection_id]

            # Audit log
                                                                                                                                                                if self.audit_service:
                                                                                                                                                                    await self.audit_service.log_event()
                                                                                                                                                                    "device.disconnected",
                                                                                                                                                                    device_id=device_id,
                                                                                                                                                                    connection_id=connection_id,
                                                                                                                                                                    )

                                                                                                                                                                    return success

                                                                                                                                                            except Exception:
                                                                                                                                                                return False

                                                                                                                                                            def get_device_info(self, device_id: str) -> Optional[Dict[str, Any]]:
                                                                                                                                                                """
                                                                                                                                                                Get device information
                                                                                                                                                                Args:
                                                                                                                                                                    device_id: Device ID
                                                                                                                                                                    Returns:
                                                                                                                                                                        Device information or None"""
                                                                                                                                                                        if device_id not in self.devices:
                                                                                                                                                                            return None

                                                                                                                                                                        device = self.devices[device_id]
                                                                                                                                                                        return {}
                                                                                                                                                                    "id": device.id,
                                                                                                                                                                    "hostname": device.hostname,
                                                                                                                                                                    "ip_address": device.ip_address,
                                                                                                                                                                    "vendor": device.vendor.value,
                                                                                                                                                                    "device_type": device.device_type.value,
                                                                                                                                                                    "model": device.model,
                                                                                                                                                                    "serial_number": device.serial_number,
                                                                                                                                                                    "os_version": device.os_version,
                                                                                                                                                                    "location": device.location,
                                                                                                                                                                    "state": device.state.value,
                                                                                                                                                                    "protocol": device.protocol.value,
                                                                                                                                                                    "port": device.port,
                                                                                                                                                                    "tags": device.tags,
                                                                                                                                                                    "metadata": device.metadata,
                                                                                                                                                                    "last_seen": ()
                                                                                                                                                                    device.last_seen.isoformat() if device.last_seen else None
                                                                                                                                                                    ),
                                                                                                                                                                    "last_backup": ()
                                                                                                                                                                    device.last_backup.isoformat() if device.last_backup else None
                                                                                                                                                                    ),
                                                                                                                                                                    }

                                                                                                                                                                    def search_devices(:):
                                                                                                                                                                    self,
                                                                                                                                                                    vendor: Optional[DeviceVendor] = None,
                                                                                                                                                                    device_type: Optional[DeviceType] = None,
                                                                                                                                                                    state: Optional[DeviceState] = None,
                                                                                                                                                                    tags: Optional[List[str]] = None,
                                                                                                                                                                    ) -> List[Dict[str, Any]]:
                                                                                                                                                                        """
                                                                                                                                                                        Search devices
                                                                                                                                                                        Args:
                                                                                                                                                                            vendor: Filter by vendor
                                                                                                                                                                            device_type: Filter by type
                                                                                                                                                                            state: Filter by state
                                                                                                                                                                            tags: Filter by tags
                                                                                                                                                                            Returns:
                                                                                                                                                                                List of matching devices"""
                                                                                                                                                                                results = []

                                                                                                                                                                                for device in self.devices.values():
            # Apply filters
                                                                                                                                                                                    if vendor and device.vendor != vendor:
                                                                                                                                                                                        continue
                                                                                                                                                                                    if device_type and device.device_type != device_type:
                                                                                                                                                                                        continue
                                                                                                                                                                                    if state and device.state != state:
                                                                                                                                                                                        continue
                                                                                                                                                                                    if tags and not any(tag in device.tags for tag in tags):
                                                                                                                                                                                        continue

                                                                                                                                                                                    results.append(self.get_device_info(device.id))

                                                                                                                                                                                    return results

                                                                                                                                                                                async def bulk_execute()
                                                                                                                                                                                self,
                                                                                                                                                                                device_ids: List[str],
                                                                                                                                                                                command: str,
                                                                                                                                                                                parallel: bool = True,
                                                                                                                                                                                ) -> Dict[str, Union[str, Exception]]:
                                                                                                                                                                                    """
                                                                                                                                                                                    Execute command on multiple devices
                                                                                                                                                                                    Args:
                                                                                                                                                                                        device_ids: List of device IDs
                                                                                                                                                                                        command: Command to execute
                                                                                                                                                                                        parallel: Execute in parallel
                                                                                                                                                                                        Returns:
                                                                                                                                                                                            Results dictionary"""
                                                                                                                                                                                            results = {}

                                                                                                                                                                                            if parallel:
            # Parallel execution
                                                                                                                                                                                                tasks = []
                                                                                                                                                                                                for device_id in device_ids:
                                                                                                                                                                                                    task = self.execute_command(device_id, command)
                                                                                                                                                                                                    tasks.append((device_id, task))

                                                                                                                                                                                                    for device_id, task in tasks:
                                                                                                                                                                                                        try:
                                                                                                                                                                                                            results[device_id] = await task
                                                                                                                                                                                                        except Exception as e:
                                                                                                                                                                                                            results[device_id] = e
                                                                                                                                                                                                        else:
            # Sequential execution
                                                                                                                                                                                                            for device_id in device_ids:
                                                                                                                                                                                                                try:
                                                                                                                                                                                                                    results[device_id] = await self.execute_command()
                                                                                                                                                                                                                    device_id,
                                                                                                                                                                                                                    command
                                                                                                                                                                                                                    )
                                                                                                                                                                                                                except Exception as e:
                                                                                                                                                                                                                    results[device_id] = e

                                                                                                                                                                                                                    return results

                                                                                                                                                                                                                async def health_check(self, device_id: str) -> Dict[str, Any]:
                                                                                                                                                                                                                    """
                                                                                                                                                                                                                    Perform device health check
                                                                                                                                                                                                                    Args:
                                                                                                                                                                                                                        device_id: Device ID
                                                                                                                                                                                                                        Returns:
                                                                                                                                                                                                                            Health status"""
                                                                                                                                                                                                                            health = {}
                                                                                                                                                                                                                            "device_id": device_id,
                                                                                                                                                                                                                            "timestamp": datetime.utcnow().isoformat(),
                                                                                                                                                                                                                            "reachable": False,
                                                                                                                                                                                                                            "cpu_usage": None,
                                                                                                                                                                                                                            "memory_usage": None,
                                                                                                                                                                                                                            "interface_status": {},
                                                                                                                                                                                                                            "issues": [],
                                                                                                                                                                                                                            }

                                                                                                                                                                                                                            try:
            # Try to connect
                                                                                                                                                                                                                                connection = await self.connect_to_device(device_id)
                                                                                                                                                                                                                                if not connection:
                                                                                                                                                                                                                                    health["issues"].append("Cannot connect to device")
                                                                                                                                                                                                                                    return health

                                                                                                                                                                                                                                health["reachable"] = True

            # Get CPU usage (vendor-specific commands would be used)
                                                                                                                                                                                                                                cpu_output = await self.execute_command()
                                                                                                                                                                                                                                device_id, "show processes cpu", connection.connection_id
                                                                                                                                                                                                                                )
                                                                                                                                                                                                                                if cpu_output:
                # Parse output (simplified)
                                                                                                                                                                                                                                    health["cpu_usage"] = 50  # Would parse actual output

            # Get memory usage
                                                                                                                                                                                                                                    memory_output = await self.execute_command()
                                                                                                                                                                                                                                    device_id, "show memory", connection.connection_id
                                                                                                                                                                                                                                    )
                                                                                                                                                                                                                                    if memory_output:
                # Parse output (simplified)
                                                                                                                                                                                                                                        health["memory_usage"] = 60  # Would parse actual output

            # Check interfaces
                                                                                                                                                                                                                                        interface_output = await self.execute_command()
                                                                                                                                                                                                                                        device_id, "show interfaces status", connection.connection_id
                                                                                                                                                                                                                                        )
                                                                                                                                                                                                                                        if interface_output:
                # Parse output (simplified)
                                                                                                                                                                                                                                            health["interface_status"] = {}
                                                                                                                                                                                                                                            "up": 10,
                                                                                                                                                                                                                                            "down": 2,
                                                                                                                                                                                                                                            "admin_down": 1,
                                                                                                                                                                                                                                            }

            # Disconnect
                                                                                                                                                                                                                                            await self.disconnect_device(connection.connection_id)

                                                                                                                                                                                                                                        except Exception as e:
                                                                                                                                                                                                                                            health["issues"].append(str(e))

                                                                                                                                                                                                                                            return health

    # Helper methods
                                                                                                                                                                                                                                        async def _get_credentials(self, device_id: str) -> DeviceCredentials:
                                                                                                                                                                                                                                            """Get device credentials from vault"""
                                                                                                                                                                                                                                            if self.vault_service:
                                                                                                                                                                                                                                                vault_creds = await self.vault_service.get_credentials(device_id)
                                                                                                                                                                                                                                                return DeviceCredentials()
                                                                                                                                                                                                                                            username=vault_creds.get("username"),
                                                                                                                                                                                                                                            password=vault_creds.get("password"),
                                                                                                                                                                                                                                        enable_password=vault_creds.get("enable_password"),
                                                                                                                                                                                                                                        ssh_key_path=vault_creds.get("ssh_key_path"),
                                                                                                                                                                                                                                        )
                                                                                                                                                                                                                                        return DeviceCredentials()

                                                                                                                                                                                                                                    async def _get_or_create_connection()
                                                                                                                                                                                                                                    self, device_id: str, connection_id: Optional[str] = None
                                                                                                                                                                                                                                    ) -> Optional[DeviceConnection]:
                                                                                                                                                                                                                                        """Get existing or create new connection"""
                                                                                                                                                                                                                                        if connection_id and connection_id in self.connections:
                                                                                                                                                                                                                                            return self.connections[connection_id]

        # Find existing connection for device
                                                                                                                                                                                                                                        for conn in self.connections.values():
                                                                                                                                                                                                                                            if conn.device_id == device_id and conn.is_active:
                                                                                                                                                                                                                                                return conn

        # Create new connection
                                                                                                                                                                                                                                            return await self.connect_to_device(device_id)
