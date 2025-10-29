"""
Advanced Deployment Strategy API Endpoints
RESTful API for managing sophisticated deployment patterns
"""
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field
import structlog

from src.db.session import get_db
from src.db.models.deployment_strategy import (
    AdvancedDeployment,
    DeploymentPhase,
    DeploymentHealthCheck,
    DeploymentRollback,
    DeploymentStrategy,
    DeploymentPhaseStatus
)
from src.deployments.strategy_engine import strategy_engine
from src.auth.dependencies import get_current_user

logger = structlog.get_logger()

router = APIRouter(
    prefix="/api/v1/deployments/advanced",
    tags=["deployment-strategies"]
)


# Pydantic Models

class CanaryDeploymentRequest(BaseModel):
    """Request model for canary deployment"""
    name: str = Field(..., description="Deployment name")
    description: Optional[str] = Field(None, description="Deployment description")
    device_ids: List[str] = Field(..., description="List of device IDs to deploy to")
    config_data: dict = Field(..., description="Configuration to deploy")
    percentages: List[int] = Field([10, 25, 50, 100], description="Canary rollout percentages")
    health_check_interval: int = Field(60, ge=10, le=600, description="Seconds between health checks")
    auto_rollback_on_failure: bool = Field(True, description="Auto-rollback on failure")
    error_rate_threshold: float = Field(0.05, ge=0.0, le=1.0, description="Max error rate (0-1)")
    min_success_rate: float = Field(0.95, ge=0.0, le=1.0, description="Min success rate (0-1)")

    class Config:
        schema_extra = {
            "example": {
                "name": "ACL Update - Canary Rollout",
                "description": "Progressive rollout of new ACL rules",
                "device_ids": ["router-nyc-01", "router-nyc-02", "router-sfo-01", "router-sfo-02"],
                "config_data": {
                    "commands": [
                        "ip access-list extended NEW_ACL",
                        "permit tcp any any eq 443",
                        "deny ip any any"
                    ]
                },
                "percentages": [10, 25, 50, 100],
                "health_check_interval": 120,
                "auto_rollback_on_failure": True
            }
        }


class BlueGreenDeploymentRequest(BaseModel):
    """Request model for blue-green deployment"""
    name: str = Field(..., description="Deployment name")
    description: Optional[str] = Field(None, description="Deployment description")
    blue_devices: List[str] = Field(..., description="Blue (active) device IDs")
    green_devices: List[str] = Field(..., description="Green (inactive) device IDs")
    config_data: dict = Field(..., description="Configuration to deploy")
    health_check_interval: int = Field(60, ge=10, le=600)
    auto_rollback_on_failure: bool = Field(True)

    class Config:
        schema_extra = {
            "example": {
                "name": "Routing Protocol Update - Blue-Green",
                "description": "Zero-downtime OSPF configuration update",
                "blue_devices": ["router-prod-01", "router-prod-02"],
                "green_devices": ["router-standby-01", "router-standby-02"],
                "config_data": {
                    "commands": [
                        "router ospf 1",
                        "network 10.0.0.0 0.255.255.255 area 0"
                    ]
                },
                "health_check_interval": 300
            }
        }


class ABTestDeploymentRequest(BaseModel):
    """Request model for A/B test deployment"""
    name: str = Field(..., description="Deployment name")
    description: Optional[str] = Field(None, description="Deployment description")
    variant_a_devices: List[str] = Field(..., description="Variant A device IDs")
    variant_b_devices: List[str] = Field(..., description="Variant B device IDs")
    variant_a_config: dict = Field(..., description="Variant A configuration")
    variant_b_config: dict = Field(..., description="Variant B configuration")
    success_metric: str = Field(..., description="Metric to compare (e.g., 'latency', 'throughput')")
    health_check_interval: int = Field(60, ge=10, le=600)


class DeploymentResponse(BaseModel):
    """Response model for deployment"""
    id: str
    name: str
    strategy: DeploymentStrategy
    overall_status: DeploymentPhaseStatus
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    device_count: int

    class Config:
        orm_mode = True


class DeploymentPhaseResponse(BaseModel):
    """Response model for deployment phase"""
    id: str
    phase_number: int
    percentage: Optional[int]
    device_group: Optional[str]
    status: DeploymentPhaseStatus
    success_rate: float
    started_at: Optional[datetime]
    completed_at: Optional[datetime]

    class Config:
        orm_mode = True


class HealthCheckResponse(BaseModel):
    """Response model for health check"""
    id: str
    checked_at: datetime
    success_rate: float
    avg_latency_ms: float
    devices_healthy: int
    devices_unhealthy: int
    passed: bool
    failure_reason: Optional[str]

    class Config:
        orm_mode = True


# API Endpoints

@router.post("/canary", response_model=DeploymentResponse, status_code=status.HTTP_201_CREATED)
async def create_canary_deployment(
    request: CanaryDeploymentRequest,
    background_tasks: BackgroundTasks,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Create and execute a canary deployment

    Canary deployments progressively roll out changes to subsets of devices,
    with health monitoring between each phase. If any phase fails health checks,
    the deployment automatically rolls back.

    **Process:**
    1. Deploy to 10% of devices
    2. Monitor health for configured interval
    3. If healthy, deploy to 25%, then 50%, then 100%
    4. Automatic rollback if any phase fails

    Requires: User authentication
    """
    logger.info(
        "Creating canary deployment",
        name=request.name,
        devices=len(request.device_ids),
        user=current_user.id
    )

    # Create deployment record
    deployment = AdvancedDeployment(
        name=request.name,
        description=request.description,
        strategy=DeploymentStrategy.CANARY,
        device_ids=request.device_ids,
        config_data=request.config_data,
        canary_percentages=request.percentages,
        health_check_interval=request.health_check_interval,
        auto_rollback_on_failure=request.auto_rollback_on_failure,
        error_rate_threshold=request.error_rate_threshold,
        min_success_rate=request.min_success_rate,
        created_by=current_user.id
    )

    db.add(deployment)
    await db.commit()
    await db.refresh(deployment)

    # Execute deployment in background
    background_tasks.add_task(
        _execute_deployment_background,
        deployment.id
    )

    logger.info("Canary deployment created", deployment_id=deployment.id)

    return DeploymentResponse(
        id=deployment.id,
        name=deployment.name,
        strategy=deployment.strategy,
        overall_status=deployment.overall_status,
        created_at=deployment.created_at,
        started_at=deployment.started_at,
        completed_at=deployment.completed_at,
        device_count=len(deployment.device_ids)
    )


@router.post("/blue-green", response_model=DeploymentResponse, status_code=status.HTTP_201_CREATED)
async def create_blue_green_deployment(
    request: BlueGreenDeploymentRequest,
    background_tasks: BackgroundTasks,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Create and execute a blue-green deployment

    Blue-green deployments enable zero-downtime updates by deploying to an
    inactive (green) environment, validating it, then switching traffic.

    **Process:**
    1. Deploy to green (inactive) environment
    2. Run comprehensive health checks on green
    3. If healthy, switch traffic to green
    4. Keep blue as rollback option

    Requires: User authentication
    """
    logger.info(
        "Creating blue-green deployment",
        name=request.name,
        blue_devices=len(request.blue_devices),
        green_devices=len(request.green_devices),
        user=current_user.id
    )

    deployment = AdvancedDeployment(
        name=request.name,
        description=request.description,
        strategy=DeploymentStrategy.BLUE_GREEN,
        device_ids=request.blue_devices + request.green_devices,
        config_data=request.config_data,
        blue_group=request.blue_devices,
        green_group=request.green_devices,
        active_group="blue",
        health_check_interval=request.health_check_interval,
        auto_rollback_on_failure=request.auto_rollback_on_failure,
        created_by=current_user.id
    )

    db.add(deployment)
    await db.commit()
    await db.refresh(deployment)

    background_tasks.add_task(
        _execute_deployment_background,
        deployment.id
    )

    logger.info("Blue-green deployment created", deployment_id=deployment.id)

    return DeploymentResponse(
        id=deployment.id,
        name=deployment.name,
        strategy=deployment.strategy,
        overall_status=deployment.overall_status,
        created_at=deployment.created_at,
        started_at=deployment.started_at,
        completed_at=deployment.completed_at,
        device_count=len(deployment.device_ids)
    )


@router.post("/ab-test", response_model=DeploymentResponse, status_code=status.HTTP_201_CREATED)
async def create_ab_test_deployment(
    request: ABTestDeploymentRequest,
    background_tasks: BackgroundTasks,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Create and execute an A/B test deployment

    A/B testing deploys two different configurations to separate device groups
    to compare their performance and determine the better option.

    **Process:**
    1. Deploy variant A to A devices
    2. Deploy variant B to B devices
    3. Monitor success metrics for both
    4. Compare results

    Requires: User authentication
    """
    logger.info(
        "Creating A/B test deployment",
        name=request.name,
        variant_a=len(request.variant_a_devices),
        variant_b=len(request.variant_b_devices),
        user=current_user.id
    )

    # Store both configs in metadata
    config_data = {
        "variant_a": request.variant_a_config,
        "variant_b": request.variant_b_config
    }

    deployment = AdvancedDeployment(
        name=request.name,
        description=request.description,
        strategy=DeploymentStrategy.AB_TEST,
        device_ids=request.variant_a_devices + request.variant_b_devices,
        config_data=config_data,
        variant_a_devices=request.variant_a_devices,
        variant_b_devices=request.variant_b_devices,
        success_metric=request.success_metric,
        health_check_interval=request.health_check_interval,
        created_by=current_user.id
    )

    db.add(deployment)
    await db.commit()
    await db.refresh(deployment)

    background_tasks.add_task(
        _execute_deployment_background,
        deployment.id
    )

    logger.info("A/B test deployment created", deployment_id=deployment.id)

    return DeploymentResponse(
        id=deployment.id,
        name=deployment.name,
        strategy=deployment.strategy,
        overall_status=deployment.overall_status,
        created_at=deployment.created_at,
        started_at=deployment.started_at,
        completed_at=deployment.completed_at,
        device_count=len(deployment.device_ids)
    )


@router.get("/deployments", response_model=List[DeploymentResponse])
async def list_deployments(
    strategy: Optional[DeploymentStrategy] = None,
    status: Optional[DeploymentPhaseStatus] = None,
    limit: int = 50,
    offset: int = 0,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    List advanced deployments

    Returns a list of deployments with optional filters.

    Requires: User authentication
    """
    query = db.query(AdvancedDeployment)

    if strategy:
        query = query.filter(AdvancedDeployment.strategy == strategy)

    if status:
        query = query.filter(AdvancedDeployment.overall_status == status)

    deployments = await query.order_by(
        AdvancedDeployment.created_at.desc()
    ).offset(offset).limit(limit).all()

    return [
        DeploymentResponse(
            id=d.id,
            name=d.name,
            strategy=d.strategy,
            overall_status=d.overall_status,
            created_at=d.created_at,
            started_at=d.started_at,
            completed_at=d.completed_at,
            device_count=len(d.device_ids)
        )
        for d in deployments
    ]


@router.get("/deployments/{deployment_id}", response_model=DeploymentResponse)
async def get_deployment(
    deployment_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get deployment details

    Requires: User authentication
    """
    deployment = await db.query(AdvancedDeployment).filter(
        AdvancedDeployment.id == deployment_id
    ).first()

    if not deployment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deployment {deployment_id} not found"
        )

    return DeploymentResponse(
        id=deployment.id,
        name=deployment.name,
        strategy=deployment.strategy,
        overall_status=deployment.overall_status,
        created_at=deployment.created_at,
        started_at=deployment.started_at,
        completed_at=deployment.completed_at,
        device_count=len(deployment.device_ids)
    )


@router.get("/deployments/{deployment_id}/phases", response_model=List[DeploymentPhaseResponse])
async def get_deployment_phases(
    deployment_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get deployment phases

    Returns all phases for a deployment in order.

    Requires: User authentication
    """
    phases = await db.query(DeploymentPhase).filter(
        DeploymentPhase.deployment_id == deployment_id
    ).order_by(DeploymentPhase.phase_number).all()

    return [
        DeploymentPhaseResponse(
            id=p.id,
            phase_number=p.phase_number,
            percentage=p.percentage,
            device_group=p.device_group,
            status=p.status,
            success_rate=p.success_rate,
            started_at=p.started_at,
            completed_at=p.completed_at
        )
        for p in phases
    ]


@router.get("/deployments/{deployment_id}/health", response_model=List[HealthCheckResponse])
async def get_deployment_health_checks(
    deployment_id: str,
    limit: int = 50,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get deployment health checks

    Returns health check history for a deployment.

    Requires: User authentication
    """
    checks = await db.query(DeploymentHealthCheck).filter(
        DeploymentHealthCheck.deployment_id == deployment_id
    ).order_by(
        DeploymentHealthCheck.checked_at.desc()
    ).limit(limit).all()

    return [
        HealthCheckResponse(
            id=c.id,
            checked_at=c.checked_at,
            success_rate=c.success_rate,
            avg_latency_ms=c.avg_latency_ms,
            devices_healthy=c.devices_healthy,
            devices_unhealthy=c.devices_unhealthy,
            passed=c.passed,
            failure_reason=c.failure_reason
        )
        for c in checks
    ]


@router.post("/deployments/{deployment_id}/pause", status_code=status.HTTP_200_OK)
async def pause_deployment(
    deployment_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Pause an in-progress deployment

    Pauses a canary deployment between phases to allow manual review.

    Requires: User authentication
    """
    deployment = await db.query(AdvancedDeployment).filter(
        AdvancedDeployment.id == deployment_id
    ).first()

    if not deployment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deployment {deployment_id} not found"
        )

    if deployment.overall_status != DeploymentPhaseStatus.IN_PROGRESS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Can only pause in-progress deployments"
        )

    deployment.overall_status = DeploymentPhaseStatus.PAUSED
    await db.commit()

    logger.info("Deployment paused", deployment_id=deployment_id, user=current_user.id)

    return {"status": "paused", "deployment_id": deployment_id}


@router.post("/deployments/{deployment_id}/resume", status_code=status.HTTP_200_OK)
async def resume_deployment(
    deployment_id: str,
    background_tasks: BackgroundTasks,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Resume a paused deployment

    Resumes a paused deployment to continue with remaining phases.

    Requires: User authentication
    """
    deployment = await db.query(AdvancedDeployment).filter(
        AdvancedDeployment.id == deployment_id
    ).first()

    if not deployment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deployment {deployment_id} not found"
        )

    if deployment.overall_status != DeploymentPhaseStatus.PAUSED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Can only resume paused deployments"
        )

    deployment.overall_status = DeploymentPhaseStatus.IN_PROGRESS
    await db.commit()

    background_tasks.add_task(
        _execute_deployment_background,
        deployment.id
    )

    logger.info("Deployment resumed", deployment_id=deployment_id, user=current_user.id)

    return {"status": "resumed", "deployment_id": deployment_id}


# Background task helper

async def _execute_deployment_background(deployment_id: str):
    """Execute deployment in background"""
    from src.db.session import get_db

    async with get_db() as db:
        deployment = await db.query(AdvancedDeployment).filter(
            AdvancedDeployment.id == deployment_id
        ).first()

        if deployment:
            await strategy_engine.execute_deployment(deployment)
            await db.commit()
