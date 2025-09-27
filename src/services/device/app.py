"""
Device microservice application.

Manages network device connections and configurations.
"""

import asyncio
import json
from typing import Dict, Any, List, Optional
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
import uuid

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, status, Query, Body
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
import uvicorn
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
import redis.asyncio as redis

from src.core.config import get_settings
from src.core.logging import get_logger
from src.security.vault import VaultClient
from src.security.encryption import EncryptionService
from src.db.models import Base, Device, DeviceCredential, DeviceConfiguration, DeviceBackup
from .models import (
    DeviceCreateRequest,
    DeviceUpdateRequest,
    DeviceResponse,
    DeviceStatus,
    DeviceType,
    ConnectionRequest,
    ConnectionResponse,
    ConfigurationRequest,
    ConfigurationResponse,
    BackupRequest,
    BackupResponse,
    ExecuteRequest,
    ExecuteResponse,
    DeviceQueryRequest,
    DeviceHealth,
    DeviceMetrics
)
from .connectors import get_connector
from .managers import (
    ConnectionManager,
    ConfigurationManager,
    BackupManager,
    CommandExecutor
)

logger = get_logger(__name__)
settings = get_settings()


class DeviceService:
    """
    Main device service implementation.

    Handles:
    - Device inventory management
    - Device connections (SSH, NETCONF, API)
    - Configuration management
    - Backup and restore
    - Command execution
    - Health monitoring
    - Multi-vendor support (Cisco, Juniper)
    """

    def __init__(self):
        self.vault = VaultClient()
        self.encryption = EncryptionService()
        self.redis = None
        self.db_session = None
        self.connection_manager = ConnectionManager()
        self.config_manager = ConfigurationManager()
        self.backup_manager = BackupManager()
        self.command_executor = CommandExecutor()
        self.active_connections: Dict[str, Any] = {}
        self.connection_lock = asyncio.Lock()

    async def initialize(self):
        """Initialize service connections."""
        # Initialize Redis
        self.redis = await redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            ssl_cert_reqs="required" if settings.REDIS_SSL else None,
        )

        # Initialize database
        engine = create_async_engine(
            settings.DATABASE_URL,
            pool_size=20,
            max_overflow=0,
            pool_pre_ping=True,
            echo=False,
        )
        async_session = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        self.db_session = async_session

        # Initialize managers
        await self.connection_manager.initialize()
        await self.config_manager.initialize()
        await self.backup_manager.initialize()
        await self.command_executor.initialize()

        logger.info("Device service initialized successfully")

    async def register_device(
        self,
        request: DeviceCreateRequest,
        user_id: str
    ) -> Device:
        """
        Register new device.

        Args:
            request: Device registration request
            user_id: User registering device

        Returns:
            Registered device
        """
        try:
            device_id = str(uuid.uuid4())

            # Validate device connectivity
            if request.validate_connectivity:
                reachable = await self._test_connectivity(
                    request.ip_address,
                    request.port or 22
                )
                if not reachable:
                    raise ValueError(f"Device {request.ip_address} is not reachable")

            # Store credentials in Vault
            credential_path = f"devices/{device_id}/credentials"
            await self.vault.put_secret(
                credential_path,
                {
                    "username": request.username,
                    "password": request.password,
                    "enable_password": request.enable_password,
                    "private_key": request.private_key
                }
            )

            # Create device record
            async with self.db_session() as session:
                device = Device(
                    id=device_id,
                    hostname=request.hostname,
                    ip_address=request.ip_address,
                    device_type=request.device_type.value,
                    vendor=request.vendor,
                    model=request.model,
                    os_version=request.os_version,
                    location=request.location,
                    site=request.site,
                    port=request.port or 22,
                    protocol=request.protocol,
                    credential_path=credential_path,
                    status=DeviceStatus.REGISTERED.value,
                    tags=request.tags,
                    created_by=user_id,
                    created_at=datetime.utcnow()
                )

                session.add(device)
                await session.commit()

            # Cache device info
            await self.redis.setex(
                f"device:{device_id}",
                3600,
                json.dumps({
                    "id": device_id,
                    "hostname": request.hostname,
                    "ip_address": request.ip_address,
                    "device_type": request.device_type.value,
                    "status": DeviceStatus.REGISTERED.value
                })
            )

            logger.info(f"Device registered: {device_id} ({request.hostname})")

            return device

        except Exception as e:
            logger.error(f"Failed to register device: {e}")
            raise

    async def connect_to_device(
        self,
        device_id: str,
        persistent: bool = False
    ) -> ConnectionResponse:
        """
        Connect to device.

        Args:
            device_id: Device ID
            persistent: Keep connection open

        Returns:
            Connection response
        """
        try:
            async with self.connection_lock:
                # Check if already connected
                if device_id in self.active_connections:
                    connection = self.active_connections[device_id]
                    if connection.is_alive():
                        return ConnectionResponse(
                            device_id=device_id,
                            connected=True,
                            connection_id=connection.id,
                            protocol=connection.protocol,
                            established_at=connection.established_at
                        )

            # Get device info
            device = await self._get_device(device_id)
            if not device:
                raise ValueError(f"Device {device_id} not found")

            # Get credentials from Vault
            credentials = await self.vault.get_secret(device.credential_path)
            if not credentials:
                raise ValueError(f"No credentials found for device {device_id}")

            # Get appropriate connector
            connector = get_connector(device.device_type)

            # Establish connection
            connection = await connector.connect(
                host=device.ip_address,
                port=device.port,
                username=credentials['username'],
                password=credentials['password'],
                device_type=device.device_type,
                enable_password=credentials.get('enable_password'),
                private_key=credentials.get('private_key'),
                timeout=30
            )

            if persistent:
                async with self.connection_lock:
                    self.active_connections[device_id] = connection

            # Update device status
            await self._update_device_status(device_id, DeviceStatus.CONNECTED)

            # Store connection info
            await self.redis.setex(
                f"device:{device_id}:connection",
                300,  # 5 minutes
                json.dumps({
                    "connection_id": connection.id,
                    "protocol": connection.protocol,
                    "established_at": datetime.utcnow().isoformat()
                })
            )

            logger.info(f"Connected to device {device_id}")

            return ConnectionResponse(
                device_id=device_id,
                connected=True,
                connection_id=connection.id,
                protocol=connection.protocol,
                established_at=datetime.utcnow()
            )

        except Exception as e:
            logger.error(f"Failed to connect to device {device_id}: {e}")
            await self._update_device_status(device_id, DeviceStatus.UNREACHABLE)
            raise

    async def disconnect_device(
        self,
        device_id: str
    ) -> bool:
        """
        Disconnect from device.

        Args:
            device_id: Device ID

        Returns:
            True if disconnected
        """
        try:
            async with self.connection_lock:
                if device_id in self.active_connections:
                    connection = self.active_connections[device_id]
                    await connection.disconnect()
                    del self.active_connections[device_id]

            # Update device status
            await self._update_device_status(device_id, DeviceStatus.DISCONNECTED)

            # Clear connection info
            await self.redis.delete(f"device:{device_id}:connection")

            logger.info(f"Disconnected from device {device_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to disconnect device {device_id}: {e}")
            return False

    async def execute_command(
        self,
        device_id: str,
        request: ExecuteRequest
    ) -> ExecuteResponse:
        """
        Execute command on device.

        Args:
            device_id: Device ID
            request: Execution request

        Returns:
            Execution response
        """
        try:
            # Connect to device if not connected
            connection = await self._ensure_connection(device_id)

            # Execute commands
            results = []
            for command in request.commands:
                # Check if command is allowed
                if not await self._is_command_allowed(command, request.allow_dangerous):
                    results.append({
                        "command": command,
                        "output": "",
                        "error": "Command not allowed",
                        "success": False
                    })
                    continue

                # Execute command
                result = await self.command_executor.execute(
                    connection,
                    command,
                    timeout=request.timeout
                )

                results.append({
                    "command": command,
                    "output": result.output,
                    "error": result.error,
                    "success": result.success,
                    "execution_time": result.execution_time
                })

                # Store command history
                await self._store_command_history(
                    device_id,
                    command,
                    result
                )

            # Disconnect if not persistent
            if not request.persistent_connection:
                await self.disconnect_device(device_id)

            return ExecuteResponse(
                device_id=device_id,
                results=results,
                executed_at=datetime.utcnow()
            )

        except Exception as e:
            logger.error(f"Failed to execute commands on device {device_id}: {e}")
            raise

    async def get_configuration(
        self,
        device_id: str,
        config_type: str = "running"
    ) -> ConfigurationResponse:
        """
        Get device configuration.

        Args:
            device_id: Device ID
            config_type: Configuration type (running/startup)

        Returns:
            Configuration response
        """
        try:
            # Connect to device
            connection = await self._ensure_connection(device_id)

            # Get device info
            device = await self._get_device(device_id)

            # Get configuration
            config = await self.config_manager.get_config(
                connection,
                device.device_type,
                config_type
            )

            # Disconnect
            await self.disconnect_device(device_id)

            # Store configuration
            config_id = await self._store_configuration(
                device_id,
                config,
                config_type
            )

            return ConfigurationResponse(
                device_id=device_id,
                configuration_id=config_id,
                config_type=config_type,
                content=config,
                retrieved_at=datetime.utcnow()
            )

        except Exception as e:
            logger.error(f"Failed to get configuration from device {device_id}: {e}")
            raise

    async def apply_configuration(
        self,
        device_id: str,
        request: ConfigurationRequest
    ) -> ConfigurationResponse:
        """
        Apply configuration to device.

        Args:
            device_id: Device ID
            request: Configuration request

        Returns:
            Configuration response
        """
        try:
            # Validate configuration
            device = await self._get_device(device_id)
            validation = await self.config_manager.validate_config(
                request.configuration,
                device.device_type
            )

            if not validation['valid']:
                raise ValueError(f"Configuration validation failed: {validation['errors']}")

            # Check for secrets
            if await self._contains_secrets(request.configuration):
                raise ValueError("Configuration contains secrets")

            # Backup current configuration
            if request.backup_before_apply:
                backup = await self.create_backup(
                    device_id,
                    BackupRequest(
                        backup_type="pre_configuration",
                        description=f"Backup before applying configuration"
                    )
                )
                logger.info(f"Created backup {backup.backup_id} before configuration")

            # Connect to device
            connection = await self._ensure_connection(device_id)

            # Apply configuration
            result = await self.config_manager.apply_config(
                connection,
                device.device_type,
                request.configuration,
                save_to_startup=request.save_to_startup,
                commit=request.commit
            )

            if not result['success']:
                # Rollback if specified
                if request.rollback_on_failure and backup:
                    await self.restore_backup(device_id, backup.backup_id)
                raise ValueError(f"Configuration apply failed: {result.get('error')}")

            # Disconnect
            await self.disconnect_device(device_id)

            # Store applied configuration
            config_id = await self._store_configuration(
                device_id,
                request.configuration,
                "applied",
                deployment_id=request.deployment_id
            )

            return ConfigurationResponse(
                device_id=device_id,
                configuration_id=config_id,
                config_type="applied",
                content=request.configuration,
                applied=True,
                retrieved_at=datetime.utcnow()
            )

        except Exception as e:
            logger.error(f"Failed to apply configuration to device {device_id}: {e}")
            raise

    async def create_backup(
        self,
        device_id: str,
        request: BackupRequest
    ) -> BackupResponse:
        """
        Create device configuration backup.

        Args:
            device_id: Device ID
            request: Backup request

        Returns:
            Backup response
        """
        try:
            # Connect to device
            connection = await self._ensure_connection(device_id)

            # Get device info
            device = await self._get_device(device_id)

            # Get current configuration
            config = await self.config_manager.get_config(
                connection,
                device.device_type,
                request.config_type or "running"
            )

            # Disconnect
            await self.disconnect_device(device_id)

            # Create backup
            backup_id = await self.backup_manager.create_backup(
                device_id,
                config,
                backup_type=request.backup_type,
                description=request.description,
                deployment_id=request.deployment_id
            )

            logger.info(f"Created backup {backup_id} for device {device_id}")

            return BackupResponse(
                device_id=device_id,
                backup_id=backup_id,
                backup_type=request.backup_type,
                size_bytes=len(config.encode()),
                created_at=datetime.utcnow()
            )

        except Exception as e:
            logger.error(f"Failed to create backup for device {device_id}: {e}")
            raise

    async def restore_backup(
        self,
        device_id: str,
        backup_id: str
    ) -> ConfigurationResponse:
        """
        Restore device configuration from backup.

        Args:
            device_id: Device ID
            backup_id: Backup ID

        Returns:
            Configuration response
        """
        try:
            # Get backup
            backup = await self.backup_manager.get_backup(backup_id)
            if not backup:
                raise ValueError(f"Backup {backup_id} not found")

            if backup['device_id'] != device_id:
                raise ValueError(f"Backup {backup_id} does not belong to device {device_id}")

            # Apply backup configuration
            result = await self.apply_configuration(
                device_id,
                ConfigurationRequest(
                    configuration=backup['configuration'],
                    save_to_startup=True,
                    commit=True,
                    backup_before_apply=False  # Already a restore operation
                )
            )

            logger.info(f"Restored backup {backup_id} to device {device_id}")

            return result

        except Exception as e:
            logger.error(f"Failed to restore backup {backup_id} to device {device_id}: {e}")
            raise

    async def get_device_status(
        self,
        device_id: str
    ) -> DeviceResponse:
        """
        Get device status.

        Args:
            device_id: Device ID

        Returns:
            Device status
        """
        try:
            # Check cache first
            cached = await self.redis.get(f"device:{device_id}")
            if cached:
                return DeviceResponse(**json.loads(cached))

            # Get from database
            device = await self._get_device(device_id)
            if not device:
                raise ValueError(f"Device {device_id} not found")

            # Check connectivity
            reachable = await self._test_connectivity(
                device.ip_address,
                device.port
            )

            status = DeviceStatus.REACHABLE if reachable else DeviceStatus.UNREACHABLE

            # Update status
            await self._update_device_status(device_id, status)

            return DeviceResponse(
                id=device.id,
                hostname=device.hostname,
                ip_address=device.ip_address,
                device_type=device.device_type,
                vendor=device.vendor,
                model=device.model,
                os_version=device.os_version,
                status=status.value,
                location=device.location,
                site=device.site,
                tags=device.tags,
                last_seen=device.last_seen,
                created_at=device.created_at,
                updated_at=device.updated_at
            )

        except Exception as e:
            logger.error(f"Failed to get device status: {e}")
            raise

    async def query_devices(
        self,
        query: DeviceQueryRequest
    ) -> List[DeviceResponse]:
        """
        Query devices based on criteria.

        Args:
            query: Query criteria

        Returns:
            List of matching devices
        """
        try:
            async with self.db_session() as session:
                # Build query
                sql = "SELECT * FROM devices WHERE 1=1"
                params = {}

                if query.device_type:
                    sql += " AND device_type = :device_type"
                    params["device_type"] = query.device_type

                if query.vendor:
                    sql += " AND vendor = :vendor"
                    params["vendor"] = query.vendor

                if query.location:
                    sql += " AND location = :location"
                    params["location"] = query.location

                if query.site:
                    sql += " AND site = :site"
                    params["site"] = query.site

                if query.status:
                    sql += " AND status = :status"
                    params["status"] = query.status

                if query.tags:
                    # PostgreSQL JSONB query
                    sql += " AND tags @> :tags"
                    params["tags"] = json.dumps(query.tags)

                # Execute query
                result = await session.execute(sql, params)
                devices = result.fetchall()

                return [
                    DeviceResponse(
                        id=d.id,
                        hostname=d.hostname,
                        ip_address=d.ip_address,
                        device_type=d.device_type,
                        vendor=d.vendor,
                        model=d.model,
                        os_version=d.os_version,
                        status=d.status,
                        location=d.location,
                        site=d.site,
                        tags=d.tags,
                        last_seen=d.last_seen,
                        created_at=d.created_at,
                        updated_at=d.updated_at
                    )
                    for d in devices
                ]

        except Exception as e:
            logger.error(f"Failed to query devices: {e}")
            raise

    async def get_device_health(
        self,
        device_id: str
    ) -> DeviceHealth:
        """
        Get device health metrics.

        Args:
            device_id: Device ID

        Returns:
            Device health
        """
        try:
            # Connect to device
            connection = await self._ensure_connection(device_id)

            # Get device info
            device = await self._get_device(device_id)

            # Collect health metrics
            health_data = await self._collect_health_metrics(
                connection,
                device.device_type
            )

            # Disconnect
            await self.disconnect_device(device_id)

            return DeviceHealth(
                device_id=device_id,
                status="healthy" if health_data['healthy'] else "unhealthy",
                cpu_usage=health_data.get('cpu_usage', 0),
                memory_usage=health_data.get('memory_usage', 0),
                temperature=health_data.get('temperature'),
                uptime=health_data.get('uptime'),
                interface_status=health_data.get('interface_status', {}),
                last_check=datetime.utcnow()
            )

        except Exception as e:
            logger.error(f"Failed to get device health: {e}")
            return DeviceHealth(
                device_id=device_id,
                status="error",
                error=str(e),
                last_check=datetime.utcnow()
            )

    async def _get_device(self, device_id: str) -> Optional[Device]:
        """Get device from database."""
        async with self.db_session() as session:
            result = await session.execute(
                "SELECT * FROM devices WHERE id = :id",
                {"id": device_id}
            )
            return result.fetchone()

    async def _update_device_status(
        self,
        device_id: str,
        status: DeviceStatus
    ):
        """Update device status."""
        try:
            async with self.db_session() as session:
                await session.execute(
                    """
                    UPDATE devices
                    SET status = :status, last_seen = :now, updated_at = :now
                    WHERE id = :id
                    """,
                    {
                        "status": status.value,
                        "now": datetime.utcnow(),
                        "id": device_id
                    }
                )
                await session.commit()

            # Update cache
            await self.redis.hset(
                f"device:{device_id}",
                "status",
                status.value
            )

        except Exception as e:
            logger.error(f"Failed to update device status: {e}")

    async def _ensure_connection(self, device_id: str):
        """Ensure device is connected."""
        if device_id in self.active_connections:
            return self.active_connections[device_id]

        response = await self.connect_to_device(device_id, persistent=True)
        return self.active_connections[device_id]

    async def _test_connectivity(
        self,
        ip_address: str,
        port: int
    ) -> bool:
        """Test device connectivity."""
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((ip_address, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    async def _is_command_allowed(
        self,
        command: str,
        allow_dangerous: bool
    ) -> bool:
        """Check if command is allowed."""
        dangerous_commands = [
            'reload',
            'shutdown',
            'format',
            'delete',
            'erase',
            'write erase',
            'request system zeroize'
        ]

        command_lower = command.lower()
        for dangerous in dangerous_commands:
            if dangerous in command_lower and not allow_dangerous:
                return False

        return True

    async def _contains_secrets(self, config: str) -> bool:
        """Check if configuration contains secrets."""
        import re
        secret_patterns = [
            r'password\s+\S+',
            r'secret\s+\S+',
            r'key\s+\S+',
            r'community\s+\S+',
            r'snmp-server\s+community\s+\S+'
        ]

        for pattern in secret_patterns:
            if re.search(pattern, config, re.IGNORECASE):
                return True

        return False

    async def _store_configuration(
        self,
        device_id: str,
        config: str,
        config_type: str,
        deployment_id: Optional[str] = None
    ) -> str:
        """Store device configuration."""
        try:
            config_id = str(uuid.uuid4())

            # Encrypt configuration
            encrypted = await self.encryption.encrypt(config)

            async with self.db_session() as session:
                config_record = DeviceConfiguration(
                    id=config_id,
                    device_id=device_id,
                    configuration=config,
                    configuration_encrypted=encrypted,
                    config_type=config_type,
                    deployment_id=deployment_id,
                    created_at=datetime.utcnow()
                )
                session.add(config_record)
                await session.commit()

            return config_id

        except Exception as e:
            logger.error(f"Failed to store configuration: {e}")
            raise

    async def _store_command_history(
        self,
        device_id: str,
        command: str,
        result: Any
    ):
        """Store command execution history."""
        try:
            await self.redis.lpush(
                f"device:{device_id}:commands",
                json.dumps({
                    "command": command,
                    "output": result.output[:1000],  # Limit output size
                    "success": result.success,
                    "executed_at": datetime.utcnow().isoformat()
                })
            )

            # Keep only last 100 commands
            await self.redis.ltrim(f"device:{device_id}:commands", 0, 99)

        except Exception as e:
            logger.error(f"Failed to store command history: {e}")

    async def _collect_health_metrics(
        self,
        connection: Any,
        device_type: str
    ) -> Dict[str, Any]:
        """Collect device health metrics."""
        health_data = {
            'healthy': True,
            'cpu_usage': 0,
            'memory_usage': 0,
            'temperature': None,
            'uptime': None,
            'interface_status': {}
        }

        try:
            if 'cisco' in device_type.lower():
                # Cisco commands
                cpu_output = await connection.send_command("show processes cpu")
                memory_output = await connection.send_command("show memory")
                interface_output = await connection.send_command("show ip interface brief")

                # Parse outputs (simplified)
                if "Five seconds" in cpu_output:
                    # Extract CPU usage
                    import re
                    match = re.search(r'Five seconds:\s+(\d+)%', cpu_output)
                    if match:
                        health_data['cpu_usage'] = int(match.group(1))

            elif 'juniper' in device_type.lower():
                # Juniper commands
                cpu_output = await connection.send_command("show chassis routing-engine")
                memory_output = await connection.send_command("show system memory")
                interface_output = await connection.send_command("show interfaces terse")

            # Determine health status
            if health_data['cpu_usage'] > 90 or health_data['memory_usage'] > 90:
                health_data['healthy'] = False

        except Exception as e:
            logger.error(f"Failed to collect health metrics: {e}")
            health_data['healthy'] = False

        return health_data

    async def shutdown(self):
        """Shutdown service connections."""
        # Disconnect all devices
        for device_id in list(self.active_connections.keys()):
            await self.disconnect_device(device_id)

        if self.redis:
            await self.redis.close()

        logger.info("Device service shutdown complete")


device_service = DeviceService()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    await device_service.initialize()
    yield
    await device_service.shutdown()


def create_app() -> FastAPI:
    """Create FastAPI application."""
    app = FastAPI(
        title="CatNet Device Service",
        description="Network device management service",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/device/docs",
        redoc_url="/device/redoc",
        openapi_url="/device/openapi.json",
    )

    # Add middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS.split(","),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add Prometheus metrics
    Instrumentator().instrument(app).expose(app, endpoint="/device/metrics")

    # Add routes
    @app.post("/devices/register", response_model=DeviceResponse)
    async def register_device(
        request: DeviceCreateRequest,
        user_id: str = Query(...)
    ):
        """Register new device."""
        device = await device_service.register_device(request, user_id)

        return DeviceResponse(
            id=device.id,
            hostname=device.hostname,
            ip_address=device.ip_address,
            device_type=device.device_type,
            vendor=device.vendor,
            model=device.model,
            os_version=device.os_version,
            status=device.status,
            location=device.location,
            site=device.site,
            tags=device.tags,
            created_at=device.created_at
        )

    @app.post("/devices/{device_id}/connect", response_model=ConnectionResponse)
    async def connect_device(
        device_id: str,
        persistent: bool = Query(False)
    ):
        """Connect to device."""
        return await device_service.connect_to_device(device_id, persistent)

    @app.post("/devices/{device_id}/disconnect")
    async def disconnect_device(device_id: str):
        """Disconnect from device."""
        success = await device_service.disconnect_device(device_id)
        return {"success": success}

    @app.post("/devices/{device_id}/execute", response_model=ExecuteResponse)
    async def execute_commands(
        device_id: str,
        request: ExecuteRequest
    ):
        """Execute commands on device."""
        return await device_service.execute_command(device_id, request)

    @app.get("/devices/{device_id}/config", response_model=ConfigurationResponse)
    async def get_configuration(
        device_id: str,
        config_type: str = Query("running")
    ):
        """Get device configuration."""
        return await device_service.get_configuration(device_id, config_type)

    @app.post("/devices/{device_id}/configure", response_model=ConfigurationResponse)
    async def apply_configuration(
        device_id: str,
        request: ConfigurationRequest
    ):
        """Apply configuration to device."""
        return await device_service.apply_configuration(device_id, request)

    @app.post("/devices/{device_id}/deploy")
    async def deploy_configuration(
        device_id: str,
        deployment_id: str = Body(...),
        config: Dict[str, Any] = Body(...)
    ):
        """Deploy configuration from deployment service."""
        request = ConfigurationRequest(
            configuration=json.dumps(config),
            save_to_startup=True,
            commit=True,
            backup_before_apply=True,
            deployment_id=deployment_id
        )
        result = await device_service.apply_configuration(device_id, request)
        return {"success": result.applied}

    @app.post("/devices/{device_id}/backup", response_model=BackupResponse)
    async def create_backup(
        device_id: str,
        request: BackupRequest
    ):
        """Create device configuration backup."""
        return await device_service.create_backup(device_id, request)

    @app.post("/devices/{device_id}/restore")
    async def restore_backup(
        device_id: str,
        backup_id: str = Body(...)
    ):
        """Restore device configuration from backup."""
        result = await device_service.restore_backup(device_id, backup_id)
        return {"success": result.applied}

    @app.get("/devices/{device_id}/status", response_model=DeviceResponse)
    async def get_device_status(device_id: str):
        """Get device status."""
        return await device_service.get_device_status(device_id)

    @app.get("/devices/{device_id}/health", response_model=DeviceHealth)
    async def get_device_health(device_id: str):
        """Get device health metrics."""
        return await device_service.get_device_health(device_id)

    @app.post("/devices/query")
    async def query_devices(request: DeviceQueryRequest):
        """Query devices based on criteria."""
        devices = await device_service.query_devices(request)
        return {"devices": devices}

    @app.get("/devices/{device_id}/config/previous")
    async def get_previous_config(
        device_id: str,
        before_deployment: Optional[str] = Query(None)
    ):
        """Get previous device configuration."""
        # Implementation for deployment service rollback
        async with device_service.db_session() as session:
            sql = """
                SELECT configuration FROM device_configurations
                WHERE device_id = :device_id
            """
            params = {"device_id": device_id}

            if before_deployment:
                sql += " AND created_at < (SELECT created_at FROM deployments WHERE id = :dep_id)"
                params["dep_id"] = before_deployment

            sql += " ORDER BY created_at DESC LIMIT 1"

            result = await session.execute(sql, params)
            config = result.fetchone()

            if config:
                return {"config": json.loads(config.configuration)}

            return {"config": None}

    @app.get("/device/health")
    async def health():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "service": "device",
            "timestamp": datetime.utcnow().isoformat()
        }

    return app


if __name__ == "__main__":
    app = create_app()
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8084,
        ssl_keyfile=settings.SSL_KEY_PATH,
        ssl_certfile=settings.SSL_CERT_PATH,
        log_config={
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {
                    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                },
            },
            "handlers": {
                "default": {
                    "formatter": "default",
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                },
            },
            "root": {
                "level": "INFO",
                "handlers": ["default"],
            },
        }
    )