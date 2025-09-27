from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from pydantic import BaseModel

from ..db.session import get_db
from ..auth.dependencies import get_current_user, require_permission
from ..db.models import User, Device, DeviceVendor

router = APIRouter()

class DeviceCreate(BaseModel):
    hostname: str
    ip_address: str
    vendor: str
    port: int = 22

@router.get("/")
async def list_devices(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    devices = db.query(Device).filter(Device.is_active == True).all()
    return [
        {
            "id": str(d.id),
            "hostname": d.hostname,
            "ip_address": d.ip_address,
            "vendor": d.vendor.value,
            "site": d.site,
            "environment": d.environment
        }
        for d in devices
    ]

@router.post("/")
async def create_device(
    device: DeviceCreate,
    current_user: User = Depends(require_permission("device", "create")),
    db: Session = Depends(get_db)
):
    vendor_map = {
        "cisco_ios": DeviceVendor.CISCO_IOS,
        "cisco_iosxe": DeviceVendor.CISCO_IOSXE,
        "cisco_nxos": DeviceVendor.CISCO_NXOS,
        "juniper_junos": DeviceVendor.JUNIPER_JUNOS
    }

    new_device = Device(
        hostname=device.hostname,
        ip_address=device.ip_address,
        vendor=vendor_map.get(device.vendor, DeviceVendor.CISCO_IOS),
        port=device.port,
        credentials_ref=f"devices/{device.hostname}/credentials",
        is_active=True
    )

    db.add(new_device)
    db.commit()

    return {"id": str(new_device.id), "hostname": new_device.hostname}

@router.get("/{device_id}/health")
async def check_device_health(
    device_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    from ..devices.device_connector import SecureDeviceConnector
    connector = SecureDeviceConnector(db)

    try:
        connection = await connector.connect_to_device(
            device_id,
            {"user_id": str(current_user.id)}
        )
        health = await connection.check_health()
        await connection.disconnect()
        return health
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))