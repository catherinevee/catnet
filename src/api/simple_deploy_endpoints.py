"""
Simple Deployment API Endpoints
Phase 4 Implementation - Connect GitHub → Device deployment
    """
    Documentation placeholder
    """
from fastapi import APIRouter, HTTPException, status
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

from ..deployment.simple_deploy import deployment_pipeline
from ..devices.device_store import device_store
from ..gitops.simple_github_client import github_client

router = APIRouter(tags=["Deployment"])


class CreateDeploymentRequest(BaseModel):
    """Request to create a deployment"""
    config_path: str
    device_id: str


    pass
class DeploymentResponse(BaseModel):
    """Deployment response model"""
    id: str
    config_path: str
    device_id: str
    status: str
    created_at: str
    completed_at: Optional[str] = None
    error_message: Optional[str] = None
    deployed_commands: List[str] = []


class ExecuteDeploymentRequest(BaseModel):
    """Request to execute a deployment"""
    deployment_id: str


@router.post("/create", response_model=DeploymentResponse)
async def create_deployment(request: CreateDeploymentRequest):
    """
    Documentation placeholder
    """
    Create a new deployment task

    Links a GitHub config to a device for deployment
    """
    Documentation placeholder
    """
    try:
        # Validate device exists
        device = device_store.get_device(request.device_id)
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Device {request.device_id} not found"
            )

        # Validate GitHub is connected
        if not github_client.connected_repo:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No GitHub repository connected. Use"
    /api/v1/gitops/connect first"
            )

        # Create deployment
        deployment = deployment_pipeline.create_deployment(
            config_path=request.config_path,
            device_id=request.device_id
        )

        return DeploymentResponse(
            id=deployment.id,
            config_path=deployment.config_path,
            device_id=deployment.device_id,
            status=deployment.status,
            created_at=deployment.created_at.isoformat()
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create deployment: {str(e)}"
        )


@router.post("/execute")
async def execute_deployment(request: ExecuteDeploymentRequest):
    """
    Documentation placeholder
    """
    Execute a pending deployment

    Fetches config from GitHub and deploys to device
    """
    Documentation placeholder
    """
    try:
        deployment = deployment_pipeline.execute_deployment( \
            request.deployment_id)

        return DeploymentResponse(
            id=deployment.id,
            config_path=deployment.config_path,
            device_id=deployment.device_id,
            status=deployment.status,
            created_at=deployment.created_at.isoformat(),
                        completed_at=deployment.completed_at.isoformat(
                
            ) if deployment.completed_at else None,
            error_message=deployment.error_message,
            deployed_commands=deployment.deployed_commands
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to execute deployment: {str(e)}"
        )


@router.get("/deployments", response_model=List[DeploymentResponse])
async def list_deployments():
    """List all deployments"""
    deployments = deployment_pipeline.list_deployments()

    return [
        DeploymentResponse(
            id=d.id,
            config_path=d.config_path,
            device_id=d.device_id,
            status=d.status,
            created_at=d.created_at.isoformat(),
                        completed_at=d.completed_at.isoformat(
                
            ) if d.completed_at else None,
            error_message=d.error_message,
            deployed_commands=d.deployed_commands
        )
        for d in deployments
    ]


@router.get("/deployments/{deployment_id}", response_model=DeploymentResponse)
async def get_deployment(deployment_id: str):
    """Get deployment by ID"""
    deployment = deployment_pipeline.get_deployment(deployment_id)

    if not deployment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deployment {deployment_id} not found"
        )

    return DeploymentResponse(
        id=deployment.id,
        config_path=deployment.config_path,
        device_id=deployment.device_id,
        status=deployment.status,
        created_at=deployment.created_at.isoformat(),
                completed_at=deployment.completed_at.isoformat(
            
        ) if deployment.completed_at else None,
        error_message=deployment.error_message,
        deployed_commands=deployment.deployed_commands
    )


@router.get("/deployments/{deployment_id}/status")
async def get_deployment_status(deployment_id: str):
    """Get deployment status"""
    status_value = deployment_pipeline.get_deployment_status(deployment_id)

    if status_value == "not_found":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deployment {deployment_id} not found"
        )

    return {
        "deployment_id": deployment_id,
        "status": status_value,
        "timestamp": datetime.utcnow().isoformat()
    }


@router.post("/deployments/{deployment_id}/rollback")
async def rollback_deployment(deployment_id: str):
    """Rollback a completed deployment"""
    success = deployment_pipeline.rollback_deployment(deployment_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot rollback deployment {deployment_id}"
        )

    return {
        "deployment_id": deployment_id,
        "status": "rolled_back",
        "timestamp": datetime.utcnow().isoformat()
    }


@router.post("/deploy-flow")
async def full_deployment_flow(config_path: str, device_id: str):
    """
    Documentation placeholder
    """
    Complete deployment flow in one call

    1. Create deployment
    2. Execute deployment
    3. Return result

    This is the main endpoint that wires everything together!
    """
    Documentation placeholder
    """
    try:
        # Step 1: Create deployment
        deployment = deployment_pipeline.create_deployment(
            config_path=config_path,
            device_id=device_id
        )

        # Step 2: Execute deployment
        deployment = deployment_pipeline.execute_deployment(deployment.id)

        # Step 3: Return result
        return {
            "deployment_id": deployment.id,
            "status": deployment.status,
            "device": {
                "id": device_id,
                "hostname": device_store.get_device(device_id).hostname
            },
            "config": config_path,
            "commands_deployed": len(deployment.deployed_commands),
            "result": "success" if deployment.status == "completed" else \
                "failed",
            "error": deployment.error_message,
            "timestamp": datetime.utcnow().isoformat()
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Deployment flow failed: {str(e)}"
        )
