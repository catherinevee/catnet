"""
Devices Router
Handles device connections, command execution, backup operations
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from uuid import UUID
import asyncio
import hashlib
import json

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Query, Body
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_, or_, func
from pydantic import BaseModel, Field, validator, IPvAnyAddress
import ipaddress

from src.db.models import (
    Device, DeviceCredential, DeviceConfig, DeviceBackup,
    DeviceCommand, DeviceHealth, DeviceInventory, DeviceConnection,
    AuditLog, User
)
from src.core.config import settings
from src.core.dependencies import (
    get_db,
    get_current_user,
    require_permission,
    get_redis,
    get_vault,
    get_audit_logger
)
from src.devices.connector import SecureDeviceConnector
from src.devices.vendors import CiscoDevice, JuniperDevice
from src.security.audit import AuditLogger
from src.security.encryption import EncryptionManager
from src.core.exceptions import (
    DeviceConnectionError,
    DeviceAuthenticationError,
    DeviceConfigurationError,
    ValidationError
)

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])


class DeviceCreateRequest(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=255)
    ip_address: IPvAnyAddress
    vendor: str = Field(..., regex="^(cisco|juniper)$")
    model: str = Field(..., max_length=100)
    os_version: Optional[str] = Field(None, max_length=100)
    location: Optional[str] = Field(None, max_length=255)
    environment: str = Field(default="production", regex="^(production|staging|development|test)$")
    tags: Optional[List[str]] = []
    management_ip: Optional[IPvAnyAddress]
    serial_number: Optional[str]
    asset_tag: Optional[str]
    notes: Optional[str]

class DeviceResponse(BaseModel):
    id: UUID
    hostname: str
    ip_address: str
    vendor: str
    model: str
    os_version: Optional[str]
    status: str
    health_status: Optional[str]
    last_seen: Optional[datetime]
    location: Optional[str]
    environment: str
    tags: List[str]
    created_at: datetime
    updated_at: datetime

class DeviceConnectionRequest(BaseModel):
    protocol: str = Field(default="ssh", regex="^(ssh|telnet|netconf|restconf)$")
    port: Optional[int]
    use_jumphost: bool = False
    jumphost_id: Optional[UUID]
    connection_timeout: int = Field(default=30, ge=5, le=300)
    command_timeout: int = Field(default=60, ge=10, le=600)

class DeviceCommandRequest(BaseModel):
    commands: List[str] = Field(..., min_items=1, max_items=50)
    mode: str = Field(default="exec", regex="^(exec|config|enable)$")
    commit: bool = Field(default=False, description="Commit changes after commands")
    rollback_on_error: bool = Field(default=True)
    save_config: bool = Field(default=False)

    @validator('commands')
    def validate_commands(cls, v):
        dangerous_commands = ['reload', 'shutdown', 'format', 'delete', 'erase']
        for cmd in v:
            for dangerous in dangerous_commands:
                if dangerous in cmd.lower():
                    raise ValueError(f"Potentially dangerous command detected: {cmd}")
        return v

class DeviceCommandResponse(BaseModel):
    command_id: UUID
    device_id: UUID
    commands: List[str]
    outputs: List[Dict[str, Any]]
    status: str
    executed_at: datetime
    execution_time_ms: int
    error: Optional[str]

class DeviceBackupRequest(BaseModel):
    backup_type: str = Field(default="full", regex="^(full|running|startup|both)$")
    include_credentials: bool = False
    compress: bool = True
    encrypt: bool = True
    retention_days: int = Field(default=30, ge=1, le=365)

class DeviceBackupResponse(BaseModel):
    backup_id: UUID
    device_id: UUID
    backup_type: str
    size_bytes: int
    checksum: str
    encrypted: bool
    compressed: bool
    created_at: datetime
    expires_at: datetime
    location: str

class DeviceHealthCheckRequest(BaseModel):
    check_types: List[str] = Field(
        default=["cpu", "memory", "interfaces", "routing"],
        description="Types of health checks to perform"
    )
    include_diagnostics: bool = False
    alert_on_issues: bool = True

class DeviceHealthResponse(BaseModel):
    device_id: UUID
    overall_status: str
    cpu_usage: Optional[float]
    memory_usage: Optional[float]
    interface_status: Optional[Dict[str, Any]]
    routing_status: Optional[Dict[str, Any]]
    uptime_seconds: Optional[int]
    temperature: Optional[Dict[str, float]]
    issues: List[Dict[str, Any]]
    last_check: datetime

class BulkDeviceOperation(BaseModel):
    device_ids: List[UUID] = Field(..., min_items=1, max_items=100)
    operation: str = Field(..., regex="^(backup|health_check|inventory|reboot|save_config)$")
    parallel: bool = Field(default=True)
    max_parallel: int = Field(default=10, ge=1, le=50)
    continue_on_error: bool = Field(default=True)


@router.get("", response_model=List[DeviceResponse])
async def list_devices(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    vendor: Optional[str] = None,
    status: Optional[str] = None,
    environment: Optional[str] = None,
    tags: Optional[List[str]] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit: AuditLogger = Depends(get_audit_logger)
) -> List[DeviceResponse]:
    """
    List all devices with optional filtering
    """

    await require_permission(current_user, "devices.read")

    query = select(Device)

    if vendor:
        query = query.where(Device.vendor == vendor)
    if status:
        query = query.where(Device.status == status)
    if environment:
        query = query.where(Device.environment == environment)
    if tags:
        query = query.where(Device.tags.contains(tags))

    query = query.offset(skip).limit(limit)

    result = await db.execute(query)
    devices = result.scalars().all()

    await audit.log_event(
        user_id=current_user.id,
        action="list_devices",
        resource_type="device",
        details={
            "count": len(devices),
            "filters": {
                "vendor": vendor,
                "status": status,
                "environment": environment,
                "tags": tags
            }
        }
    )

    return [
        DeviceResponse(
            id=device.id,
            hostname=device.hostname,
            ip_address=str(device.ip_address),
            vendor=device.vendor,
            model=device.model,
            os_version=device.os_version,
            status=device.status,
            health_status=device.health_status,
            last_seen=device.last_seen,
            location=device.location,
            environment=device.environment,
            tags=device.tags or [],
            created_at=device.created_at,
            updated_at=device.updated_at
        )
        for device in devices
    ]


@router.post("", response_model=DeviceResponse)
async def create_device(
    request: DeviceCreateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit: AuditLogger = Depends(get_audit_logger),
    vault = Depends(get_vault)
) -> DeviceResponse:
    """
    Create a new device
    """

    await require_permission(current_user, "devices.create")

    # Check if device already exists
    existing = await db.execute(
        select(Device).where(
            or_(
                Device.hostname == request.hostname,
                Device.ip_address == str(request.ip_address)
            )
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Device with this hostname or IP already exists"
        )

    # Create device
    device = Device(
        hostname=request.hostname,
        ip_address=str(request.ip_address),
        vendor=request.vendor,
        model=request.model,
        os_version=request.os_version,
        location=request.location,
        environment=request.environment,
        tags=request.tags,
        management_ip=str(request.management_ip) if request.management_ip else None,
        serial_number=request.serial_number,
        asset_tag=request.asset_tag,
        notes=request.notes,
        status="disconnected",
        created_by=current_user.id
    )

    db.add(device)
    await db.commit()
    await db.refresh(device)

    await audit.log_event(
        user_id=current_user.id,
        action="device_created",
        resource_type="device",
        resource_id=str(device.id),
        details={
            "hostname": device.hostname,
            "ip_address": device.ip_address,
            "vendor": device.vendor
        }
    )

    return DeviceResponse(
        id=device.id,
        hostname=device.hostname,
        ip_address=device.ip_address,
        vendor=device.vendor,
        model=device.model,
        os_version=device.os_version,
        status=device.status,
        health_status=device.health_status,
        last_seen=device.last_seen,
        location=device.location,
        environment=device.environment,
        tags=device.tags or [],
        created_at=device.created_at,
        updated_at=device.updated_at
    )


@router.get("/{device_id}", response_model=DeviceResponse)
async def get_device(
    device_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit: AuditLogger = Depends(get_audit_logger)
) -> DeviceResponse:
    """
    Get device details by ID
    """

    await require_permission(current_user, "devices.read")

    device = await db.get(Device, device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )

    await audit.log_event(
        user_id=current_user.id,
        action="get_device",
        resource_type="device",
        resource_id=str(device_id)
    )

    return DeviceResponse(
        id=device.id,
        hostname=device.hostname,
        ip_address=device.ip_address,
        vendor=device.vendor,
        model=device.model,
        os_version=device.os_version,
        status=device.status,
        health_status=device.health_status,
        last_seen=device.last_seen,
        location=device.location,
        environment=device.environment,
        tags=device.tags or [],
        created_at=device.created_at,
        updated_at=device.updated_at
    )


@router.post("/{device_id}/connect")
async def connect_to_device(
    device_id: UUID,
    request: DeviceConnectionRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis),
    vault = Depends(get_vault),
    audit: AuditLogger = Depends(get_audit_logger)
) -> Dict[str, Any]:
    """
    Establish connection to device
    """

    await require_permission(current_user, "devices.connect")

    # Get device
    device = await db.get(Device, device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )

    connector = SecureDeviceConnector(db, redis, vault, audit)

    try:
        # Establish connection
        connection = await connector.connect_to_device(
            device_id=str(device_id),
            user_context={
                "user_id": str(current_user.id),
                "username": current_user.username,
                "roles": [role.name for role in current_user.roles]
            },
            protocol=request.protocol,
            port=request.port,
            use_jumphost=request.use_jumphost,
            jumphost_id=str(request.jumphost_id) if request.jumphost_id else None,
            connection_timeout=request.connection_timeout
        )

        # Store connection info
        device_connection = DeviceConnection(
            device_id=device_id,
            user_id=current_user.id,
            connection_id=connection.session_id,
            protocol=request.protocol,
            source_ip=connection.source_ip,
            established_at=datetime.utcnow(),
            is_active=True
        )
        db.add(device_connection)

        # Update device status
        device.status = "connected"
        device.last_seen = datetime.utcnow()

        await db.commit()

        await audit.log_event(
            user_id=current_user.id,
            action="device_connected",
            resource_type="device",
            resource_id=str(device_id),
            details={
                "protocol": request.protocol,
                "connection_id": connection.session_id,
                "jumphost_used": request.use_jumphost
            }
        )

        return {
            "status": "connected",
            "connection_id": connection.session_id,
            "device_id": str(device_id),
            "protocol": request.protocol,
            "established_at": datetime.utcnow().isoformat()
        }

    except DeviceAuthenticationError as e:
        await audit.log_security_event(
            event_type="device_auth_failed",
            severity="high",
            user_id=current_user.id,
            details={
                "device_id": str(device_id),
                "error": str(e)
            }
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Device authentication failed"
        )

    except DeviceConnectionError as e:
        await audit.log_error(
            error_type="device_connection_error",
            error_message=str(e),
            context={
                "device_id": str(device_id),
                "user_id": str(current_user.id)
            }
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Failed to connect to device: {str(e)}"
        )


@router.post("/{device_id}/execute", response_model=DeviceCommandResponse)
async def execute_commands(
    device_id: UUID,
    request: DeviceCommandRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis),
    vault = Depends(get_vault),
    audit: AuditLogger = Depends(get_audit_logger)
) -> DeviceCommandResponse:
    """
    Execute commands on device with rollback protection
    """

    await require_permission(current_user, "devices.execute")

    # Get device
    device = await db.get(Device, device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )

    # Check if device is connected
    if device.status != "connected":
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail="Device is not connected"
        )

    connector = SecureDeviceConnector(db, redis, vault, audit)

    # Get active connection
    connection_result = await db.execute(
        select(DeviceConnection)
        .where(
            and_(
                DeviceConnection.device_id == device_id,
                DeviceConnection.is_active == True
            )
        )
        .order_by(DeviceConnection.established_at.desc())
        .limit(1)
    )
    active_connection = connection_result.scalar_one_or_none()

    if not active_connection:
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail="No active connection to device"
        )

    # Create command record
    command_record = DeviceCommand(
        device_id=device_id,
        user_id=current_user.id,
        commands=request.commands,
        mode=request.mode,
        status="executing"
    )
    db.add(command_record)
    await db.commit()

    start_time = datetime.utcnow()
    outputs = []
    error = None

    try:
        # Execute commands based on vendor
        if device.vendor == "cisco":
            device_handler = CiscoDevice(connector, device, active_connection)
        elif device.vendor == "juniper":
            device_handler = JuniperDevice(connector, device, active_connection)
        else:
            raise ValueError(f"Unsupported vendor: {device.vendor}")

        # Backup current config if rollback enabled
        if request.rollback_on_error:
            backup_id = await device_handler.create_backup("rollback")

        # Execute commands
        for command in request.commands:
            try:
                output = await device_handler.execute_command(
                    command=command,
                    mode=request.mode,
                    timeout=request.command_timeout
                )
                outputs.append({
                    "command": command,
                    "output": output,
                    "success": True,
                    "timestamp": datetime.utcnow().isoformat()
                })

            except Exception as cmd_error:
                outputs.append({
                    "command": command,
                    "error": str(cmd_error),
                    "success": False,
                    "timestamp": datetime.utcnow().isoformat()
                })

                if request.rollback_on_error:
                    # Rollback to backup
                    await device_handler.rollback(backup_id)
                    error = f"Command failed, rolled back: {str(cmd_error)}"
                    break

        # Commit changes if requested
        if request.commit and not error:
            await device_handler.commit_changes()

        # Save config if requested
        if request.save_config and not error:
            await device_handler.save_configuration()

        # Update command record
        command_record.outputs = outputs
        command_record.status = "failed" if error else "completed"
        command_record.error = error
        command_record.completed_at = datetime.utcnow()

        await db.commit()

        execution_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)

        await audit.log_event(
            user_id=current_user.id,
            action="commands_executed",
            resource_type="device",
            resource_id=str(device_id),
            details={
                "command_count": len(request.commands),
                "mode": request.mode,
                "success": not error,
                "execution_time_ms": execution_time
            }
        )

        return DeviceCommandResponse(
            command_id=command_record.id,
            device_id=device_id,
            commands=request.commands,
            outputs=outputs,
            status="failed" if error else "completed",
            executed_at=command_record.created_at,
            execution_time_ms=execution_time,
            error=error
        )

    except Exception as e:
        # Update command record with error
        command_record.status = "failed"
        command_record.error = str(e)
        command_record.completed_at = datetime.utcnow()
        await db.commit()

        await audit.log_error(
            error_type="command_execution_error",
            error_message=str(e),
            context={
                "device_id": str(device_id),
                "commands": request.commands
            }
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Command execution failed: {str(e)}"
        )


@router.post("/{device_id}/backup", response_model=DeviceBackupResponse)
async def create_backup(
    device_id: UUID,
    request: DeviceBackupRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis),
    vault = Depends(get_vault),
    audit: AuditLogger = Depends(get_audit_logger)
) -> DeviceBackupResponse:
    """
    Create device configuration backup
    """

    await require_permission(current_user, "devices.backup")

    # Get device
    device = await db.get(Device, device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )

    # Get active connection
    connection_result = await db.execute(
        select(DeviceConnection)
        .where(
            and_(
                DeviceConnection.device_id == device_id,
                DeviceConnection.is_active == True
            )
        )
        .order_by(DeviceConnection.established_at.desc())
        .limit(1)
    )
    active_connection = connection_result.scalar_one_or_none()

    if not active_connection:
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail="No active connection to device"
        )

    connector = SecureDeviceConnector(db, redis, vault, audit)

    # Get device handler
    if device.vendor == "cisco":
        device_handler = CiscoDevice(connector, device, active_connection)
    elif device.vendor == "juniper":
        device_handler = JuniperDevice(connector, device, active_connection)
    else:
        raise ValueError(f"Unsupported vendor: {device.vendor}")

    # Create backup
    config_data = await device_handler.get_configuration(request.backup_type)

    # Calculate checksum
    checksum = hashlib.sha256(config_data.encode()).hexdigest()

    # Compress if requested
    if request.compress:
        import gzip
        config_data = gzip.compress(config_data.encode())
        size_bytes = len(config_data)
    else:
        size_bytes = len(config_data.encode())

    # Encrypt if requested
    if request.encrypt:
        encryption_manager = EncryptionManager(vault)
        config_data = await encryption_manager.encrypt(config_data)

    # Store backup
    backup_location = f"backups/{device.hostname}/{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

    # Save to storage (S3, local, etc.)
    # For now, store metadata in database
    backup_record = DeviceBackup(
        device_id=device_id,
        backup_type=request.backup_type,
        config_hash=checksum,
        size_bytes=size_bytes,
        compressed=request.compress,
        encrypted=request.encrypt,
        location=backup_location,
        retention_days=request.retention_days,
        created_by=current_user.id,
        expires_at=datetime.utcnow() + timedelta(days=request.retention_days)
    )

    db.add(backup_record)
    await db.commit()

    await audit.log_event(
        user_id=current_user.id,
        action="backup_created",
        resource_type="device",
        resource_id=str(device_id),
        details={
            "backup_id": str(backup_record.id),
            "backup_type": request.backup_type,
            "size_bytes": size_bytes,
            "encrypted": request.encrypt,
            "compressed": request.compress
        }
    )

    return DeviceBackupResponse(
        backup_id=backup_record.id,
        device_id=device_id,
        backup_type=backup_record.backup_type,
        size_bytes=backup_record.size_bytes,
        checksum=backup_record.config_hash,
        encrypted=backup_record.encrypted,
        compressed=backup_record.compressed,
        created_at=backup_record.created_at,
        expires_at=backup_record.expires_at,
        location=backup_record.location
    )


@router.post("/{device_id}/health", response_model=DeviceHealthResponse)
async def check_device_health(
    device_id: UUID,
    request: DeviceHealthCheckRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis),
    vault = Depends(get_vault),
    audit: AuditLogger = Depends(get_audit_logger)
) -> DeviceHealthResponse:
    """
    Perform comprehensive device health check
    """

    await require_permission(current_user, "devices.health")

    # Get device
    device = await db.get(Device, device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )

    connector = SecureDeviceConnector(db, redis, vault, audit)

    # Get device handler
    if device.vendor == "cisco":
        device_handler = CiscoDevice(connector, device, None)
    elif device.vendor == "juniper":
        device_handler = JuniperDevice(connector, device, None)
    else:
        raise ValueError(f"Unsupported vendor: {device.vendor}")

    health_data = {
        "device_id": device_id,
        "overall_status": "healthy",
        "issues": [],
        "last_check": datetime.utcnow()
    }

    # Perform health checks
    for check_type in request.check_types:
        try:
            if check_type == "cpu":
                cpu_usage = await device_handler.get_cpu_usage()
                health_data["cpu_usage"] = cpu_usage
                if cpu_usage > 80:
                    health_data["issues"].append({
                        "type": "cpu",
                        "severity": "high" if cpu_usage > 90 else "medium",
                        "message": f"High CPU usage: {cpu_usage}%"
                    })

            elif check_type == "memory":
                memory_usage = await device_handler.get_memory_usage()
                health_data["memory_usage"] = memory_usage
                if memory_usage > 80:
                    health_data["issues"].append({
                        "type": "memory",
                        "severity": "high" if memory_usage > 90 else "medium",
                        "message": f"High memory usage: {memory_usage}%"
                    })

            elif check_type == "interfaces":
                interface_status = await device_handler.get_interface_status()
                health_data["interface_status"] = interface_status

                # Check for down interfaces
                down_interfaces = [
                    iface for iface, status in interface_status.items()
                    if status.get("status") == "down"
                ]
                if down_interfaces:
                    health_data["issues"].append({
                        "type": "interfaces",
                        "severity": "medium",
                        "message": f"Interfaces down: {', '.join(down_interfaces)}"
                    })

            elif check_type == "routing":
                routing_status = await device_handler.get_routing_status()
                health_data["routing_status"] = routing_status

                # Check for routing issues
                if routing_status.get("bgp_sessions_down", 0) > 0:
                    health_data["issues"].append({
                        "type": "routing",
                        "severity": "high",
                        "message": f"BGP sessions down: {routing_status['bgp_sessions_down']}"
                    })

        except Exception as e:
            health_data["issues"].append({
                "type": check_type,
                "severity": "low",
                "message": f"Failed to check {check_type}: {str(e)}"
            })

    # Update overall status based on issues
    if any(issue["severity"] == "high" for issue in health_data["issues"]):
        health_data["overall_status"] = "critical"
    elif any(issue["severity"] == "medium" for issue in health_data["issues"]):
        health_data["overall_status"] = "warning"
    else:
        health_data["overall_status"] = "healthy"

    # Store health check results
    health_record = DeviceHealth(
        device_id=device_id,
        status=health_data["overall_status"],
        cpu_usage=health_data.get("cpu_usage"),
        memory_usage=health_data.get("memory_usage"),
        interface_errors=len(health_data["issues"]),
        last_check=datetime.utcnow()
    )
    db.add(health_record)

    # Update device health status
    device.health_status = health_data["overall_status"]
    device.last_health_check = datetime.utcnow()

    await db.commit()

    # Alert if requested and issues found
    if request.alert_on_issues and health_data["issues"]:
        from src.services.notification_service import send_device_alert

        # Determine overall severity based on issues
        max_severity = "low"
        for issue in health_data["issues"]:
            if issue["severity"] == "high":
                max_severity = "critical"
                break
            elif issue["severity"] == "medium" and max_severity != "critical":
                max_severity = "high"

        # Prepare alert message
        issue_summary = []
        for issue in health_data["issues"]:
            issue_summary.append(f"- [{issue['severity'].upper()}] {issue['message']}")

        alert_message = f"Device health check revealed {len(health_data['issues'])} issue(s):\n\n" + "\n".join(issue_summary)

        if health_data.get("cpu_usage"):
            alert_message += f"\n\nCPU Usage: {health_data['cpu_usage']}%"
        if health_data.get("memory_usage"):
            alert_message += f"\nMemory Usage: {health_data['memory_usage']}%"

        alert_message += f"\n\nDevice Information:\n"
        alert_message += f"- Hostname: {device.hostname}\n"
        alert_message += f"- IP Address: {device.ip_address}\n"
        alert_message += f"- Vendor: {device.vendor}\n"
        alert_message += f"- Model: {device.model}\n"
        alert_message += f"- Environment: {device.environment}\n"
        alert_message += f"- Location: {device.location or 'Unknown'}\n"
        alert_message += f"- Overall Status: {health_data['overall_status']}\n"
        alert_message += f"- Last Check: {health_data['last_check'].isoformat()}"

        # Send device alert
        try:
            await send_device_alert(
                device_id=str(device_id),
                device_name=device.hostname,
                alert_type="Health Check",
                message=alert_message,
                severity=max_severity
            )

            logger.info(f"Device health alert sent for {device.hostname} (severity: {max_severity})")

        except Exception as alert_error:
            logger.error(f"Failed to send device health alert for {device.hostname}: {alert_error}")
            # Don't fail the health check if alerting fails
            await audit.log_error(
                error_type="notification_error",
                error_message=f"Failed to send device health alert: {str(alert_error)}",
                context={
                    "device_id": str(device_id),
                    "device_hostname": device.hostname,
                    "health_status": health_data["overall_status"],
                    "issue_count": len(health_data["issues"])
                }
            )

    await audit.log_event(
        user_id=current_user.id,
        action="health_check_performed",
        resource_type="device",
        resource_id=str(device_id),
        details={
            "status": health_data["overall_status"],
            "issue_count": len(health_data["issues"]),
            "check_types": request.check_types
        }
    )

    return DeviceHealthResponse(**health_data)


@router.post("/bulk", response_model=Dict[str, Any])
async def bulk_device_operation(
    request: BulkDeviceOperation,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis),
    vault = Depends(get_vault),
    audit: AuditLogger = Depends(get_audit_logger)
) -> Dict[str, Any]:
    """
    Perform bulk operations on multiple devices
    """

    await require_permission(current_user, "devices.bulk_operations")

    # Validate all devices exist
    devices = []
    for device_id in request.device_ids:
        device = await db.get(Device, device_id)
        if not device:
            if not request.continue_on_error:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Device {device_id} not found"
                )
        else:
            devices.append(device)

    # Create bulk operation task
    task_id = f"bulk_{request.operation}_{datetime.utcnow().timestamp()}"

    # Store task metadata in Redis
    await redis.set(
        f"bulk_task:{task_id}",
        json.dumps({
            "operation": request.operation,
            "device_count": len(devices),
            "user_id": str(current_user.id),
            "started_at": datetime.utcnow().isoformat(),
            "status": "processing"
        }),
        ex=3600  # 1 hour expiration
    )

    # Schedule background task
    background_tasks.add_task(
        execute_bulk_operation,
        task_id=task_id,
        devices=devices,
        operation=request.operation,
        parallel=request.parallel,
        max_parallel=request.max_parallel,
        continue_on_error=request.continue_on_error,
        user_id=current_user.id,
        db=db,
        redis=redis,
        vault=vault,
        audit=audit
    )

    await audit.log_event(
        user_id=current_user.id,
        action="bulk_operation_started",
        resource_type="device",
        details={
            "task_id": task_id,
            "operation": request.operation,
            "device_count": len(devices)
        }
    )

    return {
        "task_id": task_id,
        "operation": request.operation,
        "device_count": len(devices),
        "status": "processing",
        "message": f"Bulk {request.operation} operation started for {len(devices)} devices"
    }


async def execute_bulk_operation(
    task_id: str,
    devices: List[Device],
    operation: str,
    parallel: bool,
    max_parallel: int,
    continue_on_error: bool,
    user_id: UUID,
    db: AsyncSession,
    redis,
    vault,
    audit: AuditLogger
):
    """
    Execute bulk operation on devices (background task)
    """

    results = []

    if parallel:
        # Execute operations in parallel with semaphore
        semaphore = asyncio.Semaphore(max_parallel)

        async def execute_with_semaphore(device):
            async with semaphore:
                return await execute_device_operation(
                    device, operation, user_id, db, redis, vault, audit
                )

        tasks = [execute_with_semaphore(device) for device in devices]
        results = await asyncio.gather(*tasks, return_exceptions=continue_on_error)

    else:
        # Execute operations sequentially
        for device in devices:
            try:
                result = await execute_device_operation(
                    device, operation, user_id, db, redis, vault, audit
                )
                results.append(result)
            except Exception as e:
                if not continue_on_error:
                    raise
                results.append({"device_id": str(device.id), "error": str(e)})

    # Update task status
    await redis.set(
        f"bulk_task:{task_id}",
        json.dumps({
            "operation": operation,
            "device_count": len(devices),
            "user_id": str(user_id),
            "completed_at": datetime.utcnow().isoformat(),
            "status": "completed",
            "results": results
        }),
        ex=3600
    )


async def execute_device_operation(
    device: Device,
    operation: str,
    user_id: UUID,
    db: AsyncSession,
    redis,
    vault,
    audit: AuditLogger
) -> Dict[str, Any]:
    """
    Execute single device operation
    """

    # Implementation for each operation type
    # This would call the appropriate handler based on operation
    return {
        "device_id": str(device.id),
        "operation": operation,
        "status": "completed"
    }