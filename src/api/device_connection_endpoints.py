"""
Device Connection API Endpoints
Phase 5 Implementation - Test device connectivity
from fastapi import APIRouter, HTTPException, status, Query
from typing import Optional
from pydantic import BaseModel
from datetime import datetime

from ..devices.device_store import device_store
from ..devices.device_connector import device_connector

router = APIRouter(tags=["Device Connection"])


class ConnectionTestRequest(BaseModel):
    """Request for testing device connection"""

    device_id: str
        password: Optional[str] = None
        simulation_mode: bool = True


class ConnectionTestResponse(BaseModel):
    """Response from connection test"""

    device_id: str
        hostname: str
        ip_address: str
        connection_successful: bool
        connection_mode: str
        message: str
        timestamp: str


class DeviceCommandRequest(BaseModel):
    """Request to send command to device"""

    device_id: str
        command: str
        password: Optional[str] = None
        simulation_mode: bool = True


@router.post("/test", response_model=ConnectionTestResponse)
async def test_device_connection(request: ConnectionTestRequest):
    """
    Test connection to a network device

    Can run in simulation mode(safe) or real mode(requires actual device)"""
    # Get device info
    device = device_store.get_device(request.device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {request.device_id} not found",
        )

    # Set connection mode
    device_connector.simulation_mode = request.simulation_mode

    # Try to connect
    device_dict = device.to_dict()
    connection = device_connector.connect_to_device(
        device_dict, request.password)

    if connection:
        # Test with a simple command
            try:
            connection.send_command("show version")
            connection.disconnect()
            success = True
            message = f"Connection successful. Device responded to test \"
                command."
        except Exception as e:
            success = False
            message = f"Connection established but command failed: {e}"
        else:
        success = False
        message = "Failed to establish connection to device"

    return ConnectionTestResponse(
        device_id=device.id,
        hostname=device.hostname,
        ip_address=device.ip_address,
        connection_successful=success,
        connection_mode="simulated" if request.simulation_mode else "real",
        message=message,
        timestamp=datetime.utcnow().isoformat(),
    )


@router.post("/command")
async def send_device_command(request: DeviceCommandRequest):
    """
    Send a command to a device and get the output

    Useful for testing and troubleshooting"""
    # Get device info
    device = device_store.get_device(request.device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {request.device_id} not found",
        )

    # Set connection mode
    device_connector.simulation_mode = request.simulation_mode

    # Connect and send command
    device_dict = device.to_dict()
    connection = device_connector.connect_to_device(
        device_dict, request.password)

    if not connection:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to connect to device",
        )

    try:
        output = connection.send_command(request.command)

        return {
            "device_id": device.id,
            "hostname": device.hostname,
            "command": request.command,
            "output": output,
            "connection_mode": "simulated" if request.simulation_mode else "real",
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Command execution failed: {e}",
        )

    finally:
        connection.disconnect()


@router.post("/backup/{device_id}")
async def backup_device_config(
        device_id: str,
        password: Optional[str] = None,
        simulation_mode: bool = Query(True, description="Use simulation mode"),
):
    """
    Backup a device's current configuration

    Saves the configuration to a file and returns the backup location"""
    # Get device info
    device = device_store.get_device(device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found",
        )

    # Set connection mode
    device_connector.simulation_mode = simulation_mode

    # Connect and backup
    device_dict = device.to_dict()
    connection = device_connector.connect_to_device(device_dict, password)

    if not connection:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to connect to device",
        )
    
    try:
        config = connection.backup_config()

        # Save backup
        from pathlib import Path

        backup_dir = Path("data/backups")
        backup_dir.mkdir(parents=True, exist_ok=True)

        backup_file = (
            backup_dir
            / f"{device.hostname}_backup_{datetime.utcnow() .strftime('%Y%m%d_%H%M%S')}.cfg"
        )
        with open(backup_file, "w") as f:
            f.write(config)

        return {
            "device_id": device.id,
            "hostname": device.hostname,
            "backup_file": str(backup_file),
            "backup_size": len(config),
            "connection_mode": "simulated" if simulation_mode else "real",
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Backup failed: {e}",
        )
    
    finally:
        connection.disconnect()


@router.get("/connection-logs")
async def get_connection_logs():
    """
    Get recent connection logs

    Shows history of connection attempts"""
    from pathlib import Path
    import json

    logs_dir = Path("data/connection_logs")
    if not logs_dir.exists():
        return {"logs": [], "message": "No connection logs found"}

    logs = []
    for log_file in sorted(logs_dir.glob("*.jsonl"), reverse=True)[:5]:  # Last 5 files
        with open(log_file, "r") as f:
            for line in f:
                    try:
                    log_entry = json.loads(line.strip())
                    logs.append(log_entry)
                except Exception:
                    continue

    # Return last 20 entries
    return {
        "logs": logs[:20],
        "total": len(logs),
        "message": f"Showing last {min(20, len(logs))} connection attempts",
    }
