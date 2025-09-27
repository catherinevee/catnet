from typing import Dict, List, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Query, status
from pydantic import BaseModel
import structlog

from ...devices.inventory import DeviceInventoryManager
from ...security.audit import AuditLogger
from .auth import get_current_user

logger = structlog.get_logger()
router = APIRouter()

inventory_manager = DeviceInventoryManager()
audit = AuditLogger()

class BulkUpdateRequest(BaseModel):
    device_updates: List[Dict[str, Any]]

@router.get("/summary")
async def get_inventory_summary(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get inventory summary statistics"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            'ip_address': request.client.host if request.client else 'unknown'
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
        logger.error(f"Inventory summary error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get inventory summary"
        )

@router.post("/bulk-update")
async def bulk_update_devices(
    bulk_request: BulkUpdateRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Perform bulk updates on device inventory"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            'ip_address': request.client.host if request.client else 'unknown'
        }

        results = await inventory_manager.bulk_update_devices(
            device_updates=bulk_request.device_updates,
            user_context=user_context
        )

        return results

    except Exception as e:
        logger.error(f"Bulk update error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to perform bulk update"
        )