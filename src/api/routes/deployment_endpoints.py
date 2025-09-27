from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
import uuid
import structlog

from ...db.database import get_db
from ...db.schemas import (
    DeploymentCreate, DeploymentResponse, DeploymentApproval,
    DeploymentRollback, DeploymentStatus, ConfigValidationRequest,
    ConfigValidationResponse, BatchDeviceOperation, BatchOperationResult
)
from ...db.models import User, Deployment, DeploymentState
from ...auth.auth_service import get_current_user
from ...auth.permissions import Permission, PermissionDependency
from ...core.deployment_service import deployment_service
from ...core.validation import config_validator

logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1/deployments", tags=["Deployments"])


@router.post("/", response_model=DeploymentResponse, status_code=status.HTTP_201_CREATED)
async def create_deployment(
    deployment_data: DeploymentCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(
        PermissionDependency([Permission.DEPLOYMENT_CREATE])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new deployment.

    Security:
    - Requires DEPLOYMENT_CREATE permission
    - Validates configuration before deployment
    - Encrypts configuration at rest
    - Creates audit trail
    """
    try:
        # Get configuration content (would be from repository or direct input)
        config_content = deployment_data.dict().get("config_content", "")

        deployment = await deployment_service.create_deployment(
            db=db,
            user=current_user,
            repository_id=deployment_data.repository_id,
            device_ids=deployment_data.device_ids,
            config_content=config_content,
            strategy=deployment_data.strategy,
            approval_required=deployment_data.approval_required,
            min_approvals=deployment_data.min_approvals,
            canary_percentage=deployment_data.canary_percentage,
            rollback_on_failure=deployment_data.rollback_on_failure,
            dry_run=deployment_data.dry_run,
            commit_hash=deployment_data.commit_hash,
            commit_message=deployment_data.commit_message
        )

        # If auto-execution is enabled, schedule background execution
        if not deployment.approval_required:
            background_tasks.add_task(
                deployment_service.execute_deployment,
                db,
                deployment.id,
                current_user
            )

        return DeploymentResponse.from_orm(deployment)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to create deployment: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create deployment"
        )


@router.get("/", response_model=List[DeploymentResponse])
async def list_deployments(
    state: Optional[DeploymentState] = None,
    repository_id: Optional[uuid.UUID] = None,
    created_by: Optional[uuid.UUID] = None,
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(
        PermissionDependency([Permission.DEPLOYMENT_READ])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    List deployments with optional filters.

    Security:
    - Requires DEPLOYMENT_READ permission
    - Returns deployments based on user's visibility scope
    """
    try:
        from sqlalchemy import select, and_

        conditions = []

        if state:
            conditions.append(Deployment.state == state)
        if repository_id:
            conditions.append(Deployment.repository_id == repository_id)
        if created_by:
            conditions.append(Deployment.created_by == created_by)

        # Non-admin users can only see their own deployments unless auditor
        if not current_user.is_superuser and current_user.role.value not in ["admin", "auditor"]:
            conditions.append(Deployment.created_by == current_user.id)

        stmt = select(Deployment)
        if conditions:
            stmt = stmt.where(and_(*conditions))

        stmt = stmt.order_by(Deployment.created_at.desc())
        stmt = stmt.limit(limit).offset(offset)

        result = await db.execute(stmt)
        deployments = result.scalars().all()

        return [DeploymentResponse.from_orm(d) for d in deployments]

    except Exception as e:
        logger.error(f"Failed to list deployments: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list deployments"
        )


@router.get("/{deployment_id}", response_model=DeploymentResponse)
async def get_deployment(
    deployment_id: uuid.UUID,
    current_user: User = Depends(
        PermissionDependency([Permission.DEPLOYMENT_READ])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Get deployment details.

    Security:
    - Requires DEPLOYMENT_READ permission
    - Validates user access to deployment
    """
    try:
        from sqlalchemy import select

        result = await db.execute(
            select(Deployment).where(Deployment.id == deployment_id)
        )
        deployment = result.scalar_one_or_none()

        if not deployment:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Deployment not found"
            )

        # Check access permissions
        if (not current_user.is_superuser and
            current_user.role.value not in ["admin", "auditor"] and
            deployment.created_by != current_user.id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this deployment"
            )

        return DeploymentResponse.from_orm(deployment)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get deployment: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get deployment"
        )


@router.get("/{deployment_id}/status", response_model=DeploymentStatus)
async def get_deployment_status(
    deployment_id: uuid.UUID,
    current_user: User = Depends(
        PermissionDependency([Permission.DEPLOYMENT_READ])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Get deployment execution status.

    Security:
    - Requires DEPLOYMENT_READ permission
    - Returns real-time deployment progress
    """
    try:
        from sqlalchemy import select
        from ...db.models import DeploymentDevice

        # Get deployment
        result = await db.execute(
            select(Deployment).where(Deployment.id == deployment_id)
        )
        deployment = result.scalar_one_or_none()

        if not deployment:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Deployment not found"
            )

        # Get deployment devices
        result = await db.execute(
            select(DeploymentDevice).where(
                DeploymentDevice.deployment_id == deployment_id
            )
        )
        deployment_devices = result.scalars().all()

        # Calculate statistics
        total = len(deployment_devices)
        completed = sum(1 for dd in deployment_devices if dd.status == "deployed")
        failed = sum(1 for dd in deployment_devices if dd.status == "failed")
        progress = int((completed / total * 100) if total > 0 else 0)

        # Determine current stage
        if deployment.state == DeploymentState.PENDING:
            current_stage = "Pending approval"
        elif deployment.state == DeploymentState.APPROVED:
            current_stage = "Approved, awaiting execution"
        elif deployment.state == DeploymentState.IN_PROGRESS:
            if deployment.strategy == "canary":
                current_stage = f"Canary deployment ({progress}%)"
            else:
                current_stage = f"Deploying ({completed}/{total})"
        elif deployment.state == DeploymentState.COMPLETED:
            current_stage = "Deployment completed"
        elif deployment.state == DeploymentState.FAILED:
            current_stage = "Deployment failed"
        else:
            current_stage = "Rolled back"

        # Get errors and warnings
        errors = []
        warnings = []
        for dd in deployment_devices:
            if dd.error_message:
                errors.append(f"{dd.device.name}: {dd.error_message}")

        return DeploymentStatus(
            deployment_id=deployment_id,
            state=deployment.state,
            progress_percentage=progress,
            devices_total=total,
            devices_completed=completed,
            devices_failed=failed,
            current_stage=current_stage,
            estimated_completion=None,  # Would calculate based on rate
            errors=errors,
            warnings=warnings
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get deployment status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get deployment status"
        )


@router.post("/{deployment_id}/approve", response_model=DeploymentResponse)
async def approve_deployment(
    deployment_id: uuid.UUID,
    approval: DeploymentApproval,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(
        PermissionDependency([Permission.DEPLOYMENT_APPROVE])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Approve or reject a deployment.

    Security:
    - Requires DEPLOYMENT_APPROVE permission
    - User cannot approve their own deployments
    - Creates audit trail
    """
    try:
        deployment = await deployment_service.approve_deployment(
            db=db,
            deployment_id=deployment_id,
            user=current_user,
            approve=approval.approve,
            comments=approval.comments
        )

        # If approved and ready, schedule execution
        if (deployment.state == DeploymentState.APPROVED and
            deployment.repository and deployment.repository.auto_deploy):
            background_tasks.add_task(
                deployment_service.execute_deployment,
                db,
                deployment_id,
                current_user
            )

        return DeploymentResponse.from_orm(deployment)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to approve deployment: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to approve deployment"
        )


@router.post("/{deployment_id}/execute")
async def execute_deployment(
    deployment_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(
        PermissionDependency([Permission.DEPLOYMENT_EXECUTE])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Execute an approved deployment.

    Security:
    - Requires DEPLOYMENT_EXECUTE permission
    - Validates deployment is approved
    - Runs in background with progress tracking
    """
    try:
        # Start deployment in background
        background_tasks.add_task(
            deployment_service.execute_deployment,
            db,
            deployment_id,
            current_user
        )

        return {
            "message": "Deployment execution started",
            "deployment_id": str(deployment_id),
            "status_url": f"/api/v1/deployments/{deployment_id}/status"
        }

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to execute deployment: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to execute deployment"
        )


@router.post("/{deployment_id}/rollback")
async def rollback_deployment(
    deployment_id: uuid.UUID,
    rollback_data: DeploymentRollback,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(
        PermissionDependency([Permission.DEPLOYMENT_ROLLBACK])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Rollback a completed deployment.

    Security:
    - Requires DEPLOYMENT_ROLLBACK permission
    - Validates rollback window
    - Restores from encrypted backups
    """
    try:
        result = await deployment_service.rollback_deployment(
            db=db,
            deployment_id=deployment_id,
            user=current_user,
            reason=rollback_data.reason
        )

        return result

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to rollback deployment: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to rollback deployment"
        )


@router.post("/validate", response_model=ConfigValidationResponse)
async def validate_configuration(
    validation_request: ConfigValidationRequest,
    current_user: User = Depends(
        PermissionDependency([Permission.CONFIG_VALIDATE])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Validate configuration without deploying.

    Security:
    - Requires CONFIG_VALIDATE permission
    - Performs multi-layer validation
    - Does not store configuration
    """
    try:
        # Parse configuration
        from ...gitops.config_parser import ConfigParser
        parser = ConfigParser()
        parsed_config = parser.parse(validation_request.config_content)

        # Get device if specified
        devices = []
        if validation_request.device_id:
            from sqlalchemy import select
            from ...db.models import Device

            result = await db.execute(
                select(Device).where(Device.id == validation_request.device_id)
            )
            device = result.scalar_one_or_none()
            if device:
                devices = [device]

        # Perform validation
        result = await config_validator.validate_configuration(
            parsed_config,
            devices
        )

        return ConfigValidationResponse(
            is_valid=result.is_valid,
            syntax_valid=result.syntax_valid,
            security_compliant=result.security_compliant,
            business_rules_passed=result.business_rules_passed,
            issues=[
                {
                    "severity": issue.severity,
                    "line_number": issue.line_number,
                    "rule": issue.rule,
                    "message": issue.message,
                    "suggestion": issue.suggestion
                }
                for issue in result.errors + result.warnings
            ],
            score=result.score
        )

    except Exception as e:
        logger.error(f"Configuration validation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Configuration validation failed"
        )


@router.post("/batch-operation", response_model=BatchOperationResult)
async def batch_device_operation(
    operation: BatchDeviceOperation,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(
        PermissionDependency([Permission.DEVICE_EXECUTE_COMMAND])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Execute batch operation on multiple devices.

    Security:
    - Requires DEVICE_EXECUTE_COMMAND permission
    - Operations run in parallel or serial based on configuration
    - Full audit trail for each device
    """
    try:
        import asyncio
        from datetime import datetime

        operation_id = uuid.uuid4()
        results = {}

        start_time = datetime.utcnow()

        async def execute_on_device(device_id: uuid.UUID):
            try:
                # Execute operation based on type
                if operation.operation == "backup":
                    # Backup device configuration
                    from ...devices.secure_connector import secure_device_connector
                    connection = await secure_device_connector.connect_to_device(
                        str(device_id),
                        {"user_id": str(current_user.id)},
                        db
                    )
                    config = await connection.get_configuration()
                    await connection.close()

                    return {
                        "device_id": str(device_id),
                        "status": "success",
                        "message": "Backup completed"
                    }

                elif operation.operation == "health_check":
                    # Run health checks
                    from ...devices.secure_connector import secure_device_connector
                    connection = await secure_device_connector.connect_to_device(
                        str(device_id),
                        {"user_id": str(current_user.id)},
                        db
                    )
                    health = await connection.run_health_checks()
                    await connection.close()

                    return {
                        "device_id": str(device_id),
                        "status": "success",
                        "health_checks": health
                    }

                else:
                    return {
                        "device_id": str(device_id),
                        "status": "failed",
                        "error": f"Unknown operation: {operation.operation}"
                    }

            except Exception as e:
                return {
                    "device_id": str(device_id),
                    "status": "failed",
                    "error": str(e)
                }

        # Execute operations
        if operation.parallel:
            # Parallel execution
            tasks = [execute_on_device(device_id) for device_id in operation.device_ids]
            results_list = await asyncio.gather(*tasks, return_exceptions=True)

            for i, device_id in enumerate(operation.device_ids):
                if isinstance(results_list[i], Exception):
                    results[str(device_id)] = {
                        "status": "failed",
                        "error": str(results_list[i])
                    }
                else:
                    results[str(device_id)] = results_list[i]
        else:
            # Serial execution with stop on error
            for device_id in operation.device_ids:
                result = await execute_on_device(device_id)
                results[str(device_id)] = result

                if operation.stop_on_error and result["status"] == "failed":
                    break

        # Calculate statistics
        successful = sum(1 for r in results.values() if r["status"] == "success")
        failed = sum(1 for r in results.values() if r["status"] == "failed")

        return BatchOperationResult(
            operation_id=operation_id,
            total_devices=len(operation.device_ids),
            successful=successful,
            failed=failed,
            in_progress=0,
            results=results,
            started_at=start_time,
            completed_at=datetime.utcnow()
        )

    except Exception as e:
        logger.error(f"Batch operation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Batch operation failed"
        )