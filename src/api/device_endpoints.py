"""
Device Management API Endpoints
Phase 2 Implementation - Simple device CRUD operations
"""
from fastapi import APIRouter, HTTPException, status, Query
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime

from ..devices.device_store import device_store, DeviceInfo

router = APIRouter(tags=["devices"])


class DeviceCreateRequest(BaseModel):
    """Request model for creating a device"""

    hostname: str = Field(..., description="Device hostname")
    ip_address: str = Field(..., description="Device IP address")
    vendor: str = Field(default="cisco_ios", description="Device vendor")
    username: str = Field(default="admin", description="SSH username")
    ssh_port: int = Field(default=22, description="SSH port")
    tags: List[str] = Field(default_factory=list, description="Device tags")


class DeviceUpdateRequest(BaseModel):
    """Request model for updating a device"""

    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    vendor: Optional[str] = None
    username: Optional[str] = None
    ssh_port: Optional[int] = None
    is_active: Optional[bool] = None
    tags: Optional[List[str]] = None


class DeviceResponse(BaseModel):
    """Response model for device information"""

    id: str
    hostname: str
    ip_address: str
    vendor: str
    username: str
    ssh_port: int
    added_at: str
    last_seen: Optional[str] = None
    is_active: bool
    tags: List[str]


@router.post("", response_model=DeviceResponse, status_code=status.HTTP_201_CREATED)
async def create_device(request: DeviceCreateRequest):
    """
    Add a new device to the inventory

    Simple implementation - no complex validation
    """
    try:
        device = DeviceInfo(
            hostname=request.hostname,
            ip_address=request.ip_address,
            vendor=request.vendor,
            username=request.username,
            ssh_port=request.ssh_port,
            tags=request.tags,
        )

        added_device = device_store.add_device(device)

        return DeviceResponse(**added_device.to_dict())

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to add device: {str(e)}",
        )


@router.get("", response_model=List[DeviceResponse])
async def list_devices(
    active_only: bool = Query(False, description="Only return active devices"),
    vendor: Optional[str] = Query(None, description="Filter by vendor"),
    tag: Optional[str] = Query(None, description="Filter by tag"),
):
    """
    List all devices in the inventory

    Supports basic filtering
    """
    devices = device_store.list_devices(active_only=active_only)

    # Apply filters
    if vendor:
        devices = [d for d in devices if d.vendor == vendor]

    if tag:
        devices = [d for d in devices if tag in d.tags]

    return [DeviceResponse(**d.to_dict()) for d in devices]


@router.get("/{device_id}", response_model=DeviceResponse)
async def get_device(device_id: str):
    """Get device by ID"""
    device = device_store.get_device(device_id)

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found",
        )

    return DeviceResponse(**device.to_dict())


@router.get("/hostname/{hostname}", response_model=DeviceResponse)
async def get_device_by_hostname(hostname: str):
    """Get device by hostname"""
    device = device_store.get_device_by_hostname(hostname)

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with hostname {hostname} not found",
        )

    return DeviceResponse(**device.to_dict())


@router.patch("/{device_id}", response_model=DeviceResponse)
async def update_device(device_id: str, request: DeviceUpdateRequest):
    """Update device information"""
    updates = request.dict(exclude_unset=True)

    if not updates:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="No updates provided"
        )

    device = device_store.update_device(device_id, updates)

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found",
        )

    return DeviceResponse(**device.to_dict())


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(device_id: str):
    """Delete a device from inventory"""
    if not device_store.delete_device(device_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found",
        )


@router.post("/{device_id}/seen", response_model=DeviceResponse)
async def mark_device_seen(device_id: str):
    """Update device last seen timestamp"""
    device = device_store.mark_device_seen(device_id)

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found",
        )

    return DeviceResponse(**device.to_dict())


@router.get("/stats/count")
async def get_device_count():
    """Get device statistics"""
    total = device_store.count_devices()
    by_vendor = {}

    for vendor in ["cisco_ios", "cisco_xe", "cisco_nxos", "juniper_junos"]:
        devices = device_store.get_devices_by_vendor(vendor)
        if devices:
            by_vendor[vendor] = len(devices)

    return {
        "total": total,
        "by_vendor": by_vendor,
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.post("/sample", status_code=status.HTTP_201_CREATED)
async def add_sample_devices():
    """
    Add sample devices for testing

    Useful for quick testing without complex setup
    """
    try:
        devices = device_store.add_sample_devices()
        return {
            "message": f"Added {len(devices)} sample devices",
            "devices": [d.to_dict() for d in devices],
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to add sample devices: {str(e)}",
        )


@router.delete("/all/clear", status_code=status.HTTP_204_NO_CONTENT)
async def clear_all_devices():
    """
    Clear all devices from inventory

    WARNING: This deletes all devices. Use with caution!
    """
    device_store.clear_all()
