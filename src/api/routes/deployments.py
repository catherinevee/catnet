from typing import Dict, List, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Query, status
from pydantic import BaseModel, validator
import structlog

from ...services.deployment_service import DeploymentService, DeploymentRequest
from ...services.deployment_scheduler import DeploymentScheduler, SchedulePriority
from ...db.models import DeploymentStrategy
from ...security.audit import AuditLogger
from ...core.exceptions import DeploymentError, ValidationError
from .auth import get_current_user

logger = structlog.get_logger()
router = APIRouter()

# Initialize services
deployment_service = DeploymentService()
deployment_scheduler = DeploymentScheduler()
audit = AuditLogger()

# Request/Response Models
class CreateDeploymentRequest(BaseModel):
    configuration_content: str
    target_devices: List[str]
    deployment_strategy: str = "rolling"
    deployment_method: str = "merge"
    require_approval: bool = False
    backup_before_deploy: bool = True
    auto_rollback_on_failure: bool = True
    rollback_timeout_minutes: int = 15
    metadata: Dict[str, Any] = {}

    @validator('deployment_strategy')
    def validate_strategy(cls, v):
        try:
            DeploymentStrategy(v)
            return v
        except ValueError:
            valid_strategies = [strategy.value for strategy in DeploymentStrategy]
            raise ValueError(f"Invalid deployment strategy. Must be one of: {valid_strategies}")

    @validator('deployment_method')
    def validate_method(cls, v):
        valid_methods = ["merge", "replace"]
        if v not in valid_methods:
            raise ValueError(f"Invalid deployment method. Must be one of: {valid_methods}")
        return v

class ScheduleDeploymentRequest(BaseModel):
    deployment_request: CreateDeploymentRequest
    scheduled_time: Optional[str] = None  # ISO format
    priority: str = "normal"
    dependencies: List[str] = []
    tags: List[str] = []
    max_retries: int = 3
    timeout_minutes: int = 240

    @validator('priority')
    def validate_priority(cls, v):
        try:
            SchedulePriority[v.upper()]
            return v.lower()
        except KeyError:
            valid_priorities = [p.name.lower() for p in SchedulePriority]
            raise ValueError(f"Invalid priority. Must be one of: {valid_priorities}")

class ApproveDeploymentRequest(BaseModel):
    approved: bool
    comments: Optional[str] = None

class DeploymentUpdateRequest(BaseModel):
    status: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

def get_client_info(request: Request) -> Dict[str, Any]:
    """Extract client information from request"""
    return {
        'ip_address': request.client.host if request.client else 'unknown',
        'user_agent': request.headers.get('user-agent', 'unknown'),
        'session_id': getattr(request.state, 'request_id', 'unknown')
    }

# Deployment management endpoints
@router.post("/")
async def create_deployment(
    deployment_request: CreateDeploymentRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Create a new deployment"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            **get_client_info(request)
        }

        # Convert to internal deployment request
        internal_request = DeploymentRequest(
            configuration_content=deployment_request.configuration_content,
            target_devices=deployment_request.target_devices,
            deployment_strategy=DeploymentStrategy(deployment_request.deployment_strategy),
            deployment_method=deployment_request.deployment_method,
            require_approval=deployment_request.require_approval,
            backup_before_deploy=deployment_request.backup_before_deploy,
            auto_rollback_on_failure=deployment_request.auto_rollback_on_failure,
            rollback_timeout_minutes=deployment_request.rollback_timeout_minutes,
            metadata=deployment_request.metadata
        )

        deployment_id = await deployment_service.create_deployment(
            request=internal_request,
            user_context=user_context
        )

        return {
            'deployment_id': deployment_id,
            'status': 'pending',
            'target_devices': deployment_request.target_devices,
            'strategy': deployment_request.deployment_strategy
        }

    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except DeploymentError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Deployment creation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create deployment"
        )

@router.post("/schedule")
async def schedule_deployment(
    schedule_request: ScheduleDeploymentRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Schedule a deployment for future execution"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            **get_client_info(request)
        }

        # Convert to internal deployment request
        internal_deployment_request = DeploymentRequest(
            configuration_content=schedule_request.deployment_request.configuration_content,
            target_devices=schedule_request.deployment_request.target_devices,
            deployment_strategy=DeploymentStrategy(schedule_request.deployment_request.deployment_strategy),
            deployment_method=schedule_request.deployment_request.deployment_method,
            require_approval=schedule_request.deployment_request.require_approval,
            backup_before_deploy=schedule_request.deployment_request.backup_before_deploy,
            auto_rollback_on_failure=schedule_request.deployment_request.auto_rollback_on_failure,
            rollback_timeout_minutes=schedule_request.deployment_request.rollback_timeout_minutes,
            metadata=schedule_request.deployment_request.metadata
        )

        # Parse scheduled time
        scheduled_time = None
        if schedule_request.scheduled_time:
            from datetime import datetime
            scheduled_time = datetime.fromisoformat(schedule_request.scheduled_time.replace('Z', '+00:00'))

        schedule_id = await deployment_scheduler.schedule_deployment(
            deployment_request=internal_deployment_request,
            user_context=user_context,
            scheduled_time=scheduled_time,
            priority=SchedulePriority[schedule_request.priority.upper()],
            dependencies=schedule_request.dependencies,
            tags=schedule_request.tags,
            max_retries=schedule_request.max_retries,
            timeout_minutes=schedule_request.timeout_minutes
        )

        return {
            'schedule_id': schedule_id,
            'scheduled_time': schedule_request.scheduled_time,
            'priority': schedule_request.priority,
            'status': 'scheduled'
        }

    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Deployment scheduling error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to schedule deployment"
        )

@router.post("/{deployment_id}/execute")
async def execute_deployment(
    deployment_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Execute a pending deployment"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            **get_client_info(request)
        }

        result = await deployment_service.execute_deployment(
            deployment_id=deployment_id,
            user_context=user_context
        )

        return {
            'deployment_id': deployment_id,
            'success': result.success,
            'devices_affected': result.devices_affected,
            'deployment_duration': result.deployment_duration,
            'details': result.details
        }

    except DeploymentError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Deployment execution error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to execute deployment"
        )

@router.post("/{deployment_id}/approve")
async def approve_deployment(
    deployment_id: str,
    approval_request: ApproveDeploymentRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Approve or reject a deployment requiring approval"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            **get_client_info(request)
        }

        # Log approval action
        await audit.log_deployment_approval(
            user_id=current_user['sub'],
            deployment_id=deployment_id,
            approved=approval_request.approved,
            comments=approval_request.comments,
            client_ip=user_context['ip_address']
        )

        if approval_request.approved:
            # Execute the deployment
            result = await deployment_service.execute_deployment(
                deployment_id=deployment_id,
                user_context=user_context
            )

            return {
                'deployment_id': deployment_id,
                'status': 'approved_and_executed',
                'execution_result': {
                    'success': result.success,
                    'devices_affected': result.devices_affected,
                    'deployment_duration': result.deployment_duration
                }
            }
        else:
            # Reject the deployment
            # Note: Would need to implement deployment rejection in service
            return {
                'deployment_id': deployment_id,
                'status': 'rejected',
                'comments': approval_request.comments
            }

    except DeploymentError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Deployment approval error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process deployment approval"
        )

@router.post("/{deployment_id}/rollback")
async def rollback_deployment(
    deployment_id: str,
    force: bool = Query(False),
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Rollback a completed deployment"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            **get_client_info(request)
        }

        success = await deployment_service.rollback_deployment(
            deployment_id=deployment_id,
            user_context=user_context,
            force=force
        )

        return {
            'deployment_id': deployment_id,
            'rollback_success': success,
            'status': 'rolled_back' if success else 'rollback_failed'
        }

    except DeploymentError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Deployment rollback error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to rollback deployment"
        )

@router.get("/{deployment_id}")
async def get_deployment_status(
    deployment_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get detailed deployment status"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            **get_client_info(request)
        }

        status_info = await deployment_service.get_deployment_status(
            deployment_id=deployment_id,
            user_context=user_context
        )

        return status_info

    except DeploymentError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Deployment status error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get deployment status"
        )

@router.get("/")
async def list_deployments(
    request: Request,
    status_filter: Optional[str] = Query(None),
    strategy_filter: Optional[str] = Query(None),
    user_filter: Optional[str] = Query(None),
    limit: Optional[int] = Query(50, le=100),
    offset: Optional[int] = Query(0, ge=0),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """List deployments with filtering"""
    try:
        # This would require implementing a list method in deployment service
        # For now, return a placeholder response
        return {
            'deployments': [],
            'total_count': 0,
            'filters': {
                'status': status_filter,
                'strategy': strategy_filter,
                'user': user_filter
            },
            'pagination': {
                'limit': limit,
                'offset': offset
            }
        }

    except Exception as e:
        logger.error(f"Deployment list error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list deployments"
        )

# Scheduled deployment endpoints
@router.get("/scheduled/")
async def list_scheduled_deployments(
    request: Request,
    status_filter: Optional[str] = Query(None),
    priority_filter: Optional[str] = Query(None),
    tags_filter: Optional[str] = Query(None),
    limit: Optional[int] = Query(50, le=100),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """List scheduled deployments"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            **get_client_info(request)
        }

        # Parse filters
        from ...services.deployment_scheduler import ScheduleStatus
        status_enum = None
        if status_filter:
            try:
                status_enum = ScheduleStatus(status_filter)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid status filter: {status_filter}"
                )

        priority_enum = None
        if priority_filter:
            try:
                priority_enum = SchedulePriority[priority_filter.upper()]
            except KeyError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid priority filter: {priority_filter}"
                )

        tags_list = None
        if tags_filter:
            tags_list = tags_filter.split(',')

        deployments = await deployment_scheduler.list_scheduled_deployments(
            user_context=user_context,
            status_filter=status_enum,
            priority_filter=priority_enum,
            tags_filter=tags_list,
            limit=limit
        )

        return {
            'scheduled_deployments': deployments,
            'count': len(deployments)
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Scheduled deployment list error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list scheduled deployments"
        )

@router.get("/scheduled/{schedule_id}")
async def get_scheduled_deployment_status(
    schedule_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get status of a scheduled deployment"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            **get_client_info(request)
        }

        status_info = await deployment_scheduler.get_schedule_status(
            schedule_id=schedule_id,
            user_context=user_context
        )

        return status_info

    except DeploymentError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Scheduled deployment status error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get scheduled deployment status"
        )

@router.delete("/scheduled/{schedule_id}")
async def cancel_scheduled_deployment(
    schedule_id: str,
    reason: str = Query(""),
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Cancel a scheduled deployment"""
    try:
        user_context = {
            'user_id': current_user['sub'],
            **get_client_info(request)
        }

        success = await deployment_scheduler.cancel_scheduled_deployment(
            schedule_id=schedule_id,
            user_context=user_context,
            reason=reason
        )

        return {
            'schedule_id': schedule_id,
            'cancelled': success,
            'reason': reason
        }

    except DeploymentError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Scheduled deployment cancellation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cancel scheduled deployment"
        )

# Deployment window management
@router.post("/windows")
async def create_deployment_window(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Create a deployment window for controlled scheduling"""
    # This would require implementing window management
    return {'message': 'Deployment window creation not yet implemented'}

@router.post("/maintenance-windows")
async def create_maintenance_window(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Create a maintenance window that blocks deployments"""
    # This would require implementing maintenance window management
    return {'message': 'Maintenance window creation not yet implemented'}

# Deployment analytics and reporting
@router.get("/analytics/summary")
async def get_deployment_analytics(
    request: Request,
    days: int = Query(30, le=365),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get deployment analytics and summary"""
    try:
        # This would require implementing analytics in the deployment service
        return {
            'period_days': days,
            'total_deployments': 0,
            'successful_deployments': 0,
            'failed_deployments': 0,
            'rollbacks_performed': 0,
            'average_deployment_time': 0,
            'deployment_frequency': {},
            'success_rate_by_strategy': {},
            'most_deployed_devices': [],
            'failure_reasons': {}
        }

    except Exception as e:
        logger.error(f"Deployment analytics error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve deployment analytics"
        )