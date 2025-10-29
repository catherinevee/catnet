"""
Network Discovery API Endpoints
RESTful API for automated network discovery and inventory management
"""
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field
import structlog

from src.db.session import get_db
from src.db.models.discovery import (
    DeviceInventory,
    NetworkTopology,
    DiscoveryJob,
    DeviceChange,
    DiscoveryCredential,
    DiscoveryMethod,
    DiscoveryStatus
)
from src.discovery.discovery_engine import discovery_engine
from src.auth.dependencies import get_current_user, get_current_admin_user

logger = structlog.get_logger()

router = APIRouter(
    prefix="/api/v1/discovery",
    tags=["discovery"]
)


# Pydantic Models

class DiscoveryRequest(BaseModel):
    """Request model for starting network discovery"""
    name: str = Field(..., description="Discovery job name")
    seed_devices: List[str] = Field(..., description="Starting device IPs")
    methods: List[str] = Field(["cdp", "lldp"], description="Discovery methods")
    max_depth: int = Field(3, ge=1, le=10, description="Maximum discovery depth")
    parallel_workers: int = Field(10, ge=1, le=50, description="Concurrent workers")
    timeout_seconds: int = Field(30, ge=10, le=300, description="Per-device timeout")
    vendor_filter: Optional[List[str]] = Field(None, description="Filter by vendors")

    class Config:
        schema_extra = {
            "example": {
                "name": "Core Network Discovery",
                "seed_devices": ["10.0.0.1", "10.0.0.2"],
                "methods": ["cdp", "lldp"],
                "max_depth": 3,
                "parallel_workers": 10,
                "timeout_seconds": 30,
                "vendor_filter": ["cisco", "juniper"]
            }
        }


class DiscoveryJobResponse(BaseModel):
    """Response model for discovery job"""
    id: str
    name: str
    status: DiscoveryStatus
    devices_discovered: int
    devices_failed: int
    connections_found: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    duration_seconds: Optional[int]

    class Config:
        orm_mode = True


class DeviceInventoryResponse(BaseModel):
    """Response model for device inventory"""
    id: str
    hostname: str
    ip_address: str
    vendor: Optional[str]
    model: Optional[str]
    os_version: Optional[str]
    serial_number: Optional[str]
    discovery_method: DiscoveryMethod
    discovered_at: datetime
    last_seen_at: datetime
    is_managed: bool
    is_reachable: bool

    class Config:
        orm_mode = True


class TopologyResponse(BaseModel):
    """Response model for network topology"""
    id: str
    name: str
    topology_type: str
    device_count: int
    connection_count: int
    generated_at: datetime
    nodes: List[dict]
    edges: List[dict]

    class Config:
        orm_mode = True


class DeviceChangeResponse(BaseModel):
    """Response model for device changes"""
    id: str
    device_id: str
    change_type: str
    field_changed: Optional[str]
    old_value: Optional[str]
    new_value: Optional[str]
    detected_at: datetime
    severity: str
    acknowledged: bool

    class Config:
        orm_mode = True


# API Endpoints

@router.post("/start", response_model=DiscoveryJobResponse, status_code=status.HTTP_201_CREATED)
async def start_discovery(
    request: DiscoveryRequest,
    background_tasks: BackgroundTasks,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Start network discovery job

    Initiates automated discovery of network devices using CDP/LLDP
    starting from seed devices and recursively discovering neighbors.

    **Process:**
    1. Connect to seed devices
    2. Get neighbor information via CDP/LLDP
    3. Recursively discover neighbors up to max_depth
    4. Build topology map
    5. Store devices in inventory
    6. Detect changes from previous discovery

    Requires: User authentication
    """
    logger.info(
        "Starting network discovery",
        name=request.name,
        seed_devices=len(request.seed_devices),
        max_depth=request.max_depth,
        user=current_user.id
    )

    # Create discovery job
    job = DiscoveryJob(
        name=request.name,
        seed_devices=request.seed_devices,
        discovery_depth=request.max_depth,
        methods=request.methods,
        vendor_filter=request.vendor_filter,
        parallel_workers=request.parallel_workers,
        timeout_seconds=request.timeout_seconds,
        status=DiscoveryStatus.PENDING,
        created_by=current_user.id
    )

    db.add(job)
    await db.commit()
    await db.refresh(job)

    # Execute discovery in background
    background_tasks.add_task(
        _run_discovery,
        job.id
    )

    logger.info("Discovery job created", job_id=job.id)

    return DiscoveryJobResponse(
        id=job.id,
        name=job.name,
        status=job.status,
        devices_discovered=0,
        devices_failed=0,
        connections_found=0,
        started_at=None,
        completed_at=None,
        duration_seconds=None
    )


@router.get("/jobs", response_model=List[DiscoveryJobResponse])
async def list_discovery_jobs(
    status: Optional[DiscoveryStatus] = None,
    limit: int = 50,
    offset: int = 0,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    List discovery jobs

    Returns a list of discovery jobs with optional status filter.

    Requires: User authentication
    """
    query = db.query(DiscoveryJob)

    if status:
        query = query.filter(DiscoveryJob.status == status)

    jobs = await query.order_by(
        DiscoveryJob.created_at.desc()
    ).offset(offset).limit(limit).all()

    return jobs


@router.get("/jobs/{job_id}", response_model=DiscoveryJobResponse)
async def get_discovery_job(
    job_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get discovery job details

    Requires: User authentication
    """
    job = await db.query(DiscoveryJob).filter(
        DiscoveryJob.id == job_id
    ).first()

    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Discovery job {job_id} not found"
        )

    return job


@router.post("/jobs/{job_id}/cancel")
async def cancel_discovery_job(
    job_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Cancel a running discovery job

    Requires: User authentication
    """
    job = await db.query(DiscoveryJob).filter(
        DiscoveryJob.id == job_id
    ).first()

    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Discovery job {job_id} not found"
        )

    if job.status not in [DiscoveryStatus.PENDING, DiscoveryStatus.RUNNING]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel job with status {job.status}"
        )

    job.status = DiscoveryStatus.CANCELLED
    job.completed_at = datetime.utcnow()
    await db.commit()

    logger.info("Discovery job cancelled", job_id=job_id, user=current_user.id)

    return {"status": "cancelled", "job_id": job_id}


@router.get("/inventory", response_model=List[DeviceInventoryResponse])
async def get_device_inventory(
    vendor: Optional[str] = None,
    is_managed: Optional[bool] = None,
    is_reachable: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get device inventory

    Returns discovered devices with optional filters.

    Requires: User authentication
    """
    query = db.query(DeviceInventory)

    if vendor:
        query = query.filter(DeviceInventory.vendor == vendor)

    if is_managed is not None:
        query = query.filter(DeviceInventory.is_managed == is_managed)

    if is_reachable is not None:
        query = query.filter(DeviceInventory.is_reachable == is_reachable)

    devices = await query.order_by(
        DeviceInventory.last_seen_at.desc()
    ).offset(offset).limit(limit).all()

    return devices


@router.get("/inventory/{device_id}", response_model=DeviceInventoryResponse)
async def get_device_details(
    device_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get detailed device information

    Requires: User authentication
    """
    device = await db.query(DeviceInventory).filter(
        DeviceInventory.id == device_id
    ).first()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found in inventory"
        )

    return device


@router.patch("/inventory/{device_id}/manage")
async def manage_device(
    device_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Mark device as managed

    Adds discovered device to CatNet management.

    Requires: User authentication
    """
    device = await db.query(DeviceInventory).filter(
        DeviceInventory.id == device_id
    ).first()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found"
        )

    device.is_managed = True
    await db.commit()

    logger.info(
        "Device marked as managed",
        device_id=device_id,
        hostname=device.hostname,
        user=current_user.id
    )

    return {"status": "managed", "device_id": device_id, "hostname": device.hostname}


@router.get("/topology", response_model=List[TopologyResponse])
async def list_topologies(
    limit: int = 10,
    offset: int = 0,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    List network topologies

    Returns discovered network topologies ordered by most recent.

    Requires: User authentication
    """
    topologies = await db.query(NetworkTopology).order_by(
        NetworkTopology.generated_at.desc()
    ).offset(offset).limit(limit).all()

    return topologies


@router.get("/topology/{topology_id}", response_model=TopologyResponse)
async def get_topology(
    topology_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get network topology

    Returns topology including nodes (devices) and edges (connections).

    Requires: User authentication
    """
    topology = await db.query(NetworkTopology).filter(
        NetworkTopology.id == topology_id
    ).first()

    if not topology:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Topology {topology_id} not found"
        )

    return topology


@router.get("/topology/latest")
async def get_latest_topology(
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get latest network topology

    Returns the most recently generated topology.

    Requires: User authentication
    """
    topology = await db.query(NetworkTopology).order_by(
        NetworkTopology.generated_at.desc()
    ).first()

    if not topology:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No topology found. Run a discovery job first."
        )

    return topology


@router.get("/changes", response_model=List[DeviceChangeResponse])
async def get_device_changes(
    device_id: Optional[str] = None,
    change_type: Optional[str] = None,
    acknowledged: Optional[bool] = False,
    limit: int = 100,
    offset: int = 0,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get device changes

    Returns detected changes in network devices.

    Requires: User authentication
    """
    query = db.query(DeviceChange)

    if device_id:
        query = query.filter(DeviceChange.device_id == device_id)

    if change_type:
        query = query.filter(DeviceChange.change_type == change_type)

    if acknowledged is not None:
        query = query.filter(DeviceChange.acknowledged == acknowledged)

    changes = await query.order_by(
        DeviceChange.detected_at.desc()
    ).offset(offset).limit(limit).all()

    return changes


@router.post("/changes/{change_id}/acknowledge")
async def acknowledge_change(
    change_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Acknowledge a device change

    Marks a detected change as acknowledged.

    Requires: User authentication
    """
    change = await db.query(DeviceChange).filter(
        DeviceChange.id == change_id
    ).first()

    if not change:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Change {change_id} not found"
        )

    change.acknowledged = True
    change.acknowledged_by = current_user.id
    change.acknowledged_at = datetime.utcnow()

    await db.commit()

    logger.info("Change acknowledged", change_id=change_id, user=current_user.id)

    return {"status": "acknowledged", "change_id": change_id}


@router.get("/inventory/stats")
async def get_inventory_stats(
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get inventory statistics

    Returns summary statistics about discovered devices.

    Requires: User authentication
    """
    total_devices = await db.query(DeviceInventory).count()
    managed_devices = await db.query(DeviceInventory).filter(
        DeviceInventory.is_managed == True
    ).count()
    reachable_devices = await db.query(DeviceInventory).filter(
        DeviceInventory.is_reachable == True
    ).count()

    # Count by vendor
    from sqlalchemy import func
    vendor_counts = await db.query(
        DeviceInventory.vendor,
        func.count(DeviceInventory.id)
    ).group_by(DeviceInventory.vendor).all()

    vendor_stats = {vendor: count for vendor, count in vendor_counts if vendor}

    return {
        "total_devices": total_devices,
        "managed_devices": managed_devices,
        "unmanaged_devices": total_devices - managed_devices,
        "reachable_devices": reachable_devices,
        "unreachable_devices": total_devices - reachable_devices,
        "by_vendor": vendor_stats
    }


# Background task helper

async def _run_discovery(job_id: str):
    """Execute discovery job in background"""
    from src.db.session import get_db

    async with get_db() as db:
        job = await db.query(DiscoveryJob).filter(
            DiscoveryJob.id == job_id
        ).first()

        if not job:
            logger.error(f"Discovery job {job_id} not found")
            return

        try:
            # Run discovery
            topology = await discovery_engine.discover_network(job)

            # Save topology
            db.add(topology)
            await db.commit()

            logger.info(
                "Discovery completed successfully",
                job_id=job_id,
                devices=job.devices_discovered
            )

        except Exception as e:
            logger.error(f"Discovery failed for job {job_id}", error=str(e))
            job.status = DiscoveryStatus.FAILED
            job.error_messages.append(str(e))
            await db.commit()
