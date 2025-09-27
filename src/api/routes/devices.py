from typing import Dict, List, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Query, status
from pydantic import BaseModel, validator
import structlog

from ...devices.device_service import DeviceService
from ...devices.device_manager import DeviceManager
from ...devices.inventory import DeviceInventoryManager, DeviceInventoryFilter
from ...db.models import DeviceVendor
from ...security.audit import AuditLogger
from ...core.exceptions import DeviceConnectionError, ValidationError, SecurityError
from .auth import get_current_user

logger = structlog.get_logger()
router = APIRouter()

# Initialize services
device_service = DeviceService()
device_manager = DeviceManager()
inventory_manager = DeviceInventoryManager()
audit = AuditLogger()

# Request/Response Models
class DeviceConnectRequest(BaseModel):
    device_id: str
    connection_type: str = "ssh"

class DeviceCommandRequest(BaseModel):
    device_id: str
    command: str
    timeout: Optional[int] = 30

class DeviceBackupRequest(BaseModel):
    device_id: str
    backup_type: str = "running"

class DeviceConfigDeployRequest(BaseModel):
    device_id: str
    configuration: str
    deployment_method: str = "merge"
    backup_first: bool = True

class DeviceRegistrationRequest(BaseModel):
    hostname: str
    ip_address: str
    vendor: str
    device_type: str
    model: Optional[str] = None
    os_version: Optional[str] = None
    site: Optional[str] = "default"
    ssh_port: Optional[int] = 22
    jump_host: Optional[str] = None
    management_ip: Optional[str] = None
    tags: List[str] = []
    metadata: Dict[str, Any] = {}

    @validator('vendor')
    def validate_vendor(cls, v):
        try:
            DeviceVendor(v)
            return v
        except ValueError:
            valid_vendors = [vendor.value for vendor in DeviceVendor]
            raise ValueError(f"Invalid vendor. Must be one of: {valid_vendors}")

class DeviceUpdateRequest(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    model: Optional[str] = None
    os_version: Optional[str] = None
    site: Optional[str] = None
    status: Optional[str] = None
    ssh_port: Optional[int] = None
    jump_host: Optional[str] = None
    management_ip: Optional[str] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None

class DeviceDiscoveryRequest(BaseModel):
    ip_range: str
    discovery_method: str = "ping_sweep"

class BulkDeviceOperationRequest(BaseModel):
    device_ids: List[str]
    operation: str
    parameters: Dict[str, Any] = {}

def get_client_info(request: Request) -> Dict[str, Any]:
    """Extract client information from request"""
    return {
        'ip_address': request.client.host if request.client else 'unknown',
        'user_agent': request.headers.get('user-agent', 'unknown'),
        'session_id': getattr(request.state, 'request_id', 'unknown')
    }

# Device inventory endpoints
@router.get("/")
async def get_device_inventory(
    request: Request,
    vendor: Optional[str] = Query(None),
    device_type: Optional[str] = Query(None),
    site: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    hostname_pattern: Optional[str] = Query(None),
    limit: Optional[int] = Query(100, le=1000),
    offset: Optional[int] = Query(0, ge=0),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get device inventory with filtering and pagination"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            **get_client_info(request)
        }

        # Build filter
        filters = DeviceInventoryFilter()
        if vendor:
            try:
                filters.vendor = DeviceVendor(vendor)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid vendor: {vendor}"
                )
        if device_type:
            filters.device_type = device_type
        if site:
            filters.site = site
        if status:
            filters.status = status
        if hostname_pattern:
            filters.hostname_pattern = hostname_pattern

        # Get inventory
        result = await inventory_manager.get_device_inventory(
            user_context=user_context,
            filters=filters,
            limit=limit,
            offset=offset
        )

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Device inventory error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve device inventory"
        )

@router.get("/statistics")
async def get_inventory_statistics(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get device inventory statistics"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            **get_client_info(request)
        }

        stats = await inventory_manager.get_inventory_statistics(user_context)

        return {
            'total_devices': stats.total_devices,
            'by_vendor': stats.by_vendor,
            'by_type': stats.by_type,
            'by_status': stats.by_status,
            'by_site': stats.by_site,
            'needs_backup': stats.needs_backup,
            'stale_devices': stats.stale_devices,
            'active_connections': stats.active_connections
        }

    except Exception as e:
        logger.error(f"Device statistics error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve device statistics"
        )

@router.post("/register")
async def register_device(
    device_data: DeviceRegistrationRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Register a new device in inventory"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            **get_client_info(request)
        }

        device_id = await inventory_manager.register_device(
            device_data=device_data.dict(),
            user_context=user_context
        )

        return {
            'device_id': device_id,
            'message': 'Device successfully registered'
        }

    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Device registration error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register device"
        )

@router.get("/{device_id}")
async def get_device_details(
    device_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get detailed information about a specific device"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            **get_client_info(request)
        }

        # Get device from inventory
        inventory_result = await inventory_manager.get_device_inventory(
            user_context=user_context,
            filters=None,
            limit=1,
            offset=0
        )

        device = None
        for dev in inventory_result['devices']:
            if dev['id'] == device_id:
                device = dev
                break

        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )

        # Get connection status
        device['connection_status'] = device_service._get_connection_status(device_id)

        return device

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Device details error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve device details"
        )

@router.put("/{device_id}")
async def update_device(
    device_id: str,
    updates: DeviceUpdateRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Update device information"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            **get_client_info(request)
        }

        # Filter out None values
        update_data = {k: v for k, v in updates.dict().items() if v is not None}

        success = await inventory_manager.update_device(
            device_id=device_id,
            updates=update_data,
            user_context=user_context
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found or no changes applied"
            )

        return {'message': 'Device successfully updated'}

    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Device update error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update device"
        )

@router.delete("/{device_id}")
async def remove_device(
    device_id: str,
    force: bool = Query(False),
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Remove device from inventory"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            **get_client_info(request)
        }

        success = await inventory_manager.remove_device(
            device_id=device_id,
            user_context=user_context,
            force=force
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )

        return {'message': 'Device successfully removed'}

    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Device removal error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to remove device"
        )

# Device connection endpoints
@router.post("/connect")
async def connect_to_device(
    connect_request: DeviceConnectRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Establish connection to a device"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            **get_client_info(request)
        }

        connection_id = await device_service.connect_to_device(
            device_id=connect_request.device_id,
            user_context=user_context,
            connection_type=connect_request.connection_type
        )

        return {
            'connection_id': connection_id,
            'device_id': connect_request.device_id,
            'status': 'connected'
        }

    except DeviceConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except SecurityError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Device connection error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to connect to device"
        )

@router.post("/disconnect/{device_id}")
async def disconnect_from_device(
    device_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Disconnect from a device"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            **get_client_info(request)
        }

        success = await device_service.disconnect_device(
            device_id=device_id,
            user_context=user_context
        )

        return {
            'device_id': device_id,
            'status': 'disconnected' if success else 'error'
        }

    except Exception as e:
        logger.error(f"Device disconnection error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to disconnect from device"
        )

# Command execution endpoints
@router.post("/execute")
async def execute_command(
    command_request: DeviceCommandRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Execute command on a device"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            **get_client_info(request)
        }

        result = await device_service.execute_command(
            device_id=command_request.device_id,
            command=command_request.command,
            user_context=user_context,
            timeout=command_request.timeout
        )

        return {
            'device_id': command_request.device_id,
            'command': result.command,
            'output': result.output,
            'success': result.success,
            'execution_time': result.execution_time,
            'timestamp': result.timestamp.isoformat(),
            'error': result.error
        }

    except DeviceConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except SecurityError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Command execution error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to execute command"
        )

# Backup endpoints
@router.post("/backup")
async def backup_device_config(
    backup_request: DeviceBackupRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Create backup of device configuration"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            **get_client_info(request)
        }

        backup_id = await device_service.backup_device_config(
            device_id=backup_request.device_id,
            user_context=user_context,
            backup_type=backup_request.backup_type
        )

        return {
            'backup_id': backup_id,
            'device_id': backup_request.device_id,
            'backup_type': backup_request.backup_type,
            'status': 'completed'
        }

    except DeviceConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Device backup error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to backup device configuration"
        )

@router.post("/deploy-config")
async def deploy_configuration(
    deploy_request: DeviceConfigDeployRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Deploy configuration to a device"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            **get_client_info(request)
        }

        result = await device_manager.deploy_configuration_to_device(
            device_id=deploy_request.device_id,
            config_content=deploy_request.configuration,
            deployment_method=deploy_request.deployment_method,
            user_context=user_context,
            backup_first=deploy_request.backup_first
        )

        return result

    except DeviceConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except SecurityError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Configuration deployment error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to deploy configuration"
        )

# Health and monitoring endpoints
@router.get("/{device_id}/health")
async def get_device_health(
    device_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get device health status"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            **get_client_info(request)
        }

        health_data = await device_service.get_device_health(
            device_id=device_id,
            user_context=user_context
        )

        return health_data

    except DeviceConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Device health check error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to check device health"
        )

@router.post("/health-check")
async def bulk_health_check(
    bulk_request: BulkDeviceOperationRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Perform health checks on multiple devices"""
    try:
        if bulk_request.operation != "health_check":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Operation must be 'health_check'"
            )

        user_context = {
            'user_id': current_user['sub'],
            **get_client_info(request)
        }

        results = await device_manager.perform_device_health_checks(
            device_ids=bulk_request.device_ids,
            user_context=user_context
        )

        return {
            'operation': 'health_check',
            'device_count': len(bulk_request.device_ids),
            'results': results
        }

    except Exception as e:
        logger.error(f"Bulk health check error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to perform bulk health check"
        )

# Discovery endpoints
@router.post("/discover")
async def discover_devices(
    discovery_request: DeviceDiscoveryRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Discover devices on the network"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            **get_client_info(request)
        }

        discovery_result = await inventory_manager.discover_devices(
            ip_range=discovery_request.ip_range,
            user_context=user_context,
            discovery_method=discovery_request.discovery_method
        )

        return discovery_result

    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Device discovery error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to discover devices"
        )

# Bulk operations
@router.post("/bulk-operations")
async def bulk_device_operations(
    bulk_request: BulkDeviceOperationRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Perform bulk operations on multiple devices"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            **get_client_info(request)
        }

        if bulk_request.operation == "backup":
            # Bulk backup operation
            results = {}
            for device_id in bulk_request.device_ids:
                try:
                    backup_id = await device_service.backup_device_config(
                        device_id=device_id,
                        user_context=user_context,
                        backup_type=bulk_request.parameters.get("backup_type", "running")
                    )
                    results[device_id] = {'success': True, 'backup_id': backup_id}
                except Exception as e:
                    results[device_id] = {'success': False, 'error': str(e)}

        elif bulk_request.operation == "connect":
            # Bulk connection operation
            connection_results = await device_manager.initialize_device_pool(
                device_ids=bulk_request.device_ids,
                user_context=user_context
            )
            results = {
                device_id: {'success': success}
                for device_id, success in connection_results.items()
            }

        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported bulk operation: {bulk_request.operation}"
            )

        return {
            'operation': bulk_request.operation,
            'device_count': len(bulk_request.device_ids),
            'results': results
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Bulk operation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to perform bulk operation"
        )