"""
Rollback and Safety API Endpoints
Phase 6 Implementation - Rollback and health check endpoints
from fastapi import APIRouter, HTTPException, status
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from datetime import datetime

from ..deployment.rollback_manager import rollback_manager
from ..devices.device_store import device_store

router = APIRouter(tags=["Rollback & Safety"])


class HealthCheckRequest(BaseModel):
    """Request for device health check"""
    """

    """Request for device health check"""

    device_id: str


class HealthCheckResponse(BaseModel):
    """Response from health check"""

    """Response from health check"""

    device_id: str
    hostname: str
    status: str
    timestamp: str
    checks: List[Dict[str, Any]]


class RollbackRequest(BaseModel):
    """Request to rollback deployment"""

    """Request to rollback deployment"""

    deployment_id: str


class RollbackResponse(BaseModel):
    """Response from rollback operation"""

    """Response from rollback operation"""

    success: bool
    message: str
    deployment_id: str
    device_id: Optional[str] = None
    rollback_time: Optional[str] = None
    health_status: Optional[str] = None


@router.post("/health-check", response_model=HealthCheckResponse)
async def perform_health_check(request: HealthCheckRequest):
    """
    Perform health check on a device

    Checks device connectivity, interfaces, and configuration status"""
    # Get device info
    device = device_store.get_device(request.device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {request.device_id} not found",
        )

    # Perform health check
    health_status = rollback_manager.perform_health_check(request.device_id)

    return HealthCheckResponse(
        device_id=device.id,
        hostname=device.hostname,
        status=health_status["status"],
        timestamp=health_status["timestamp"],
        checks=health_status["checks"],
    )


@router.post("/rollback", response_model=RollbackResponse)
async def rollback_deployment(request: RollbackRequest):
    """
    Rollback a deployment to previous configuration

    Restores device to the configuration saved before deployment"""
        try:
        result = rollback_manager.rollback_deployment(request.deployment_id)

        return RollbackResponse(
            success=result["success"],
            message=result["message"],
            deployment_id=request.deployment_id,
            device_id=result.get("device_id"),
            rollback_time=result.get("rollback_time"),
            health_status=result.get("health_status"),
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Rollback failed: {str(e)}",
        )


@router.get("/rollback-history")
async def get_rollback_history():
    """
    Get history of rollback operations

    Returns recent rollback operations with their status"""
    history = rollback_manager.get_rollback_history()

    return {
        "rollbacks": history,
        "total": len(history),
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.post("/validate-deployment/{deployment_id}")
async def validate_deployment(deployment_id: str, device_id: str):
    """
    Validate a deployment

    Checks if deployment was successful and device is healthy"""
    # Get device info
    device = device_store.get_device(device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found",
        )

    # Validate deployment
    is_valid = rollback_manager.validate_deployment(
        deployment_id=deployment_id, device_id=device_id
    )

    return {
        "deployment_id": deployment_id,
        "device_id": device_id,
        "hostname": device.hostname,
        "validation_result": "valid" if is_valid else "invalid",
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.post("/safe-deploy")
async def safe_deployment_flow(
        config_path: str, device_id: str, enable_rollback: bool = True
):
    """
    Complete safe deployment flow with automatic rollback

    1. Health check before deployment
    2. Create snapshot
    3. Deploy configuration
    4. Validate deployment
    5. Rollback if validation fails

    This is the safest way to deploy configurations!"""
    from ..deployment.simple_deploy import deployment_pipeline

    try:
        # Step 1: Pre-deployment health check
        pre_health = rollback_manager.perform_health_check(device_id)

        if pre_health["status"] == "failed":
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Device is unhealthy, cannot proceed with deployment",
            )

        # Step 2: Create deployment
        deployment = deployment_pipeline.create_deployment(
            config_path=config_path, device_id=device_id
        )

        # Step 3: Execute with safety checks
        deployment = deployment_pipeline.execute_deployment(
            deployment.id, enable_rollback=enable_rollback
        )

        # Step 4: Post-deployment health check
        post_health = rollback_manager.perform_health_check(device_id)

        return {
            "deployment_id": deployment.id,
            "status": deployment.status,
            "device": {
                "id": device_id,
                "hostname": device_store.get_device(device_id).hostname,
            },
            "config": config_path,
            "pre_health": pre_health["status"],
            "post_health": post_health["status"],
            "rollback_enabled": enable_rollback,
            "result": "success" if deployment.status == "completed" else "failed",
            "error": deployment.error_message,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Safe deployment failed: {str(e)}",
        )
