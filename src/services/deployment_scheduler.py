from typing import Dict, List, Optional, Any, Callable
import asyncio
import uuid
import structlog
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import heapq

from ..db.models import Deployment, DeploymentStatus, DeploymentStrategy
from ..db.database import get_db_session
from ..services.deployment_service import DeploymentService, DeploymentRequest
from ..security.audit import AuditLogger
from ..core.exceptions import DeploymentError, ValidationError

logger = structlog.get_logger()

class SchedulePriority(Enum):
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5

class ScheduleStatus(Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"

@dataclass
class ScheduledDeployment:
    id: str
    deployment_request: DeploymentRequest
    user_context: Dict[str, Any]
    scheduled_time: datetime
    priority: SchedulePriority
    max_retries: int = 3
    retry_count: int = 0
    status: ScheduleStatus = ScheduleStatus.QUEUED
    dependencies: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    timeout_minutes: int = 240
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None

    def __lt__(self, other):
        # Priority queue comparison: higher priority and earlier time come first
        if self.priority.value != other.priority.value:
            return self.priority.value > other.priority.value
        return self.scheduled_time < other.scheduled_time

@dataclass
class DeploymentWindow:
    start_time: datetime
    end_time: datetime
    max_concurrent: int
    allowed_strategies: List[DeploymentStrategy]
    device_groups: Optional[List[str]] = None
    description: str = ""

class DeploymentScheduler:
    def __init__(self):
        self.deployment_service = DeploymentService()
        self.audit = AuditLogger()

        self.scheduled_deployments: Dict[str, ScheduledDeployment] = {}
        self.deployment_queue: List[ScheduledDeployment] = []
        self.running_deployments: Dict[str, str] = {}  # schedule_id -> deployment_id
        self.deployment_windows: List[DeploymentWindow] = []

        self.max_concurrent_deployments = 3
        self.scheduler_running = False
        self.scheduler_task: Optional[asyncio.Task] = None
        self.maintenance_windows: List[Dict[str, Any]] = []

    async def start_scheduler(self):
        """Start the deployment scheduler"""
        if self.scheduler_running:
            logger.warning("Scheduler is already running")
            return

        self.scheduler_running = True
        self.scheduler_task = asyncio.create_task(self._scheduler_loop())
        logger.info("Deployment scheduler started")

    async def stop_scheduler(self):
        """Stop the deployment scheduler"""
        if not self.scheduler_running:
            return

        self.scheduler_running = False
        if self.scheduler_task:
            self.scheduler_task.cancel()
            try:
                await self.scheduler_task
            except asyncio.CancelledError:
                pass

        logger.info("Deployment scheduler stopped")

    async def schedule_deployment(
        self,
        deployment_request: DeploymentRequest,
        user_context: Dict[str, Any],
        scheduled_time: Optional[datetime] = None,
        priority: SchedulePriority = SchedulePriority.NORMAL,
        dependencies: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        max_retries: int = 3,
        timeout_minutes: int = 240
    ) -> str:
        """Schedule a deployment for execution"""
        try:
            schedule_id = str(uuid.uuid4())

            if scheduled_time is None:
                scheduled_time = datetime.utcnow()

            # Validate scheduling conflicts
            if not await self._validate_schedule_time(scheduled_time, deployment_request.target_devices):
                raise ValidationError(
                    f"Deployment conflicts with maintenance window or other deployments"
                )

            scheduled_deployment = ScheduledDeployment(
                id=schedule_id,
                deployment_request=deployment_request,
                user_context=user_context,
                scheduled_time=scheduled_time,
                priority=priority,
                dependencies=dependencies or [],
                tags=tags or [],
                max_retries=max_retries,
                timeout_minutes=timeout_minutes
            )

            self.scheduled_deployments[schedule_id] = scheduled_deployment
            heapq.heappush(self.deployment_queue, scheduled_deployment)

            await self.audit.log_deployment_scheduled(
                user_id=user_context['user_id'],
                schedule_id=schedule_id,
                scheduled_time=scheduled_time.isoformat(),
                priority=priority.value,
                device_count=len(deployment_request.target_devices)
            )

            logger.info(
                f"Deployment scheduled: {schedule_id} for {scheduled_time}",
                schedule_id=schedule_id,
                priority=priority.value,
                device_count=len(deployment_request.target_devices)
            )

            return schedule_id

        except Exception as e:
            logger.error(f"Failed to schedule deployment: {e}")
            raise DeploymentError(f"Scheduling failed: {str(e)}")

    async def cancel_scheduled_deployment(
        self,
        schedule_id: str,
        user_context: Dict[str, Any],
        reason: str = ""
    ) -> bool:
        """Cancel a scheduled deployment"""
        try:
            if schedule_id not in self.scheduled_deployments:
                raise ValidationError(f"Scheduled deployment {schedule_id} not found")

            scheduled_deployment = self.scheduled_deployments[schedule_id]

            if scheduled_deployment.status == ScheduleStatus.RUNNING:
                # If deployment is running, we need to cancel the actual deployment
                if schedule_id in self.running_deployments:
                    deployment_id = self.running_deployments[schedule_id]
                    # Note: Would need to implement deployment cancellation in deployment service
                    logger.warning(f"Deployment {deployment_id} is running, cannot cancel schedule")
                    return False

            scheduled_deployment.status = ScheduleStatus.CANCELLED
            scheduled_deployment.completed_at = datetime.utcnow()
            scheduled_deployment.error_message = f"Cancelled by user: {reason}"

            # Remove from queue if still queued
            if scheduled_deployment in self.deployment_queue:
                self.deployment_queue.remove(scheduled_deployment)
                heapq.heapify(self.deployment_queue)

            await self.audit.log_deployment_cancelled(
                user_id=user_context['user_id'],
                schedule_id=schedule_id,
                reason=reason
            )

            logger.info(f"Scheduled deployment cancelled: {schedule_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to cancel scheduled deployment: {e}")
            raise DeploymentError(f"Cancellation failed: {str(e)}")

    async def get_schedule_status(
        self,
        schedule_id: str,
        user_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Get status of a scheduled deployment"""
        try:
            if schedule_id not in self.scheduled_deployments:
                raise ValidationError(f"Scheduled deployment {schedule_id} not found")

            scheduled_deployment = self.scheduled_deployments[schedule_id]

            status_info = {
                'schedule_id': schedule_id,
                'status': scheduled_deployment.status.value,
                'priority': scheduled_deployment.priority.value,
                'scheduled_time': scheduled_deployment.scheduled_time.isoformat(),
                'created_at': scheduled_deployment.created_at.isoformat(),
                'started_at': scheduled_deployment.started_at.isoformat() if scheduled_deployment.started_at else None,
                'completed_at': scheduled_deployment.completed_at.isoformat() if scheduled_deployment.completed_at else None,
                'retry_count': scheduled_deployment.retry_count,
                'max_retries': scheduled_deployment.max_retries,
                'dependencies': scheduled_deployment.dependencies,
                'tags': scheduled_deployment.tags,
                'error_message': scheduled_deployment.error_message,
                'target_devices': scheduled_deployment.deployment_request.target_devices,
                'deployment_strategy': scheduled_deployment.deployment_request.deployment_strategy.value
            }

            # Add deployment information if running
            if schedule_id in self.running_deployments:
                deployment_id = self.running_deployments[schedule_id]
                deployment_status = await self.deployment_service.get_deployment_status(
                    deployment_id, user_context
                )
                status_info['deployment_status'] = deployment_status

            return status_info

        except Exception as e:
            logger.error(f"Failed to get schedule status: {e}")
            raise DeploymentError(f"Status query failed: {str(e)}")

    async def list_scheduled_deployments(
        self,
        user_context: Dict[str, Any],
        status_filter: Optional[ScheduleStatus] = None,
        priority_filter: Optional[SchedulePriority] = None,
        tags_filter: Optional[List[str]] = None,
        limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """List scheduled deployments with filtering"""
        try:
            filtered_deployments = []

            for scheduled_deployment in self.scheduled_deployments.values():
                # Apply filters
                if status_filter and scheduled_deployment.status != status_filter:
                    continue

                if priority_filter and scheduled_deployment.priority != priority_filter:
                    continue

                if tags_filter:
                    if not any(tag in scheduled_deployment.tags for tag in tags_filter):
                        continue

                deployment_info = {
                    'schedule_id': scheduled_deployment.id,
                    'status': scheduled_deployment.status.value,
                    'priority': scheduled_deployment.priority.value,
                    'scheduled_time': scheduled_deployment.scheduled_time.isoformat(),
                    'created_at': scheduled_deployment.created_at.isoformat(),
                    'device_count': len(scheduled_deployment.deployment_request.target_devices),
                    'strategy': scheduled_deployment.deployment_request.deployment_strategy.value,
                    'tags': scheduled_deployment.tags
                }

                filtered_deployments.append(deployment_info)

            # Sort by scheduled time
            filtered_deployments.sort(key=lambda x: x['scheduled_time'])

            # Apply limit
            if limit:
                filtered_deployments = filtered_deployments[:limit]

            return filtered_deployments

        except Exception as e:
            logger.error(f"Failed to list scheduled deployments: {e}")
            raise DeploymentError(f"List query failed: {str(e)}")

    async def add_deployment_window(
        self,
        start_time: datetime,
        end_time: datetime,
        max_concurrent: int,
        allowed_strategies: List[DeploymentStrategy],
        device_groups: Optional[List[str]] = None,
        description: str = ""
    ) -> str:
        """Add a deployment window for controlled deployment scheduling"""
        try:
            if start_time >= end_time:
                raise ValidationError("Start time must be before end time")

            deployment_window = DeploymentWindow(
                start_time=start_time,
                end_time=end_time,
                max_concurrent=max_concurrent,
                allowed_strategies=allowed_strategies,
                device_groups=device_groups,
                description=description
            )

            self.deployment_windows.append(deployment_window)

            logger.info(
                f"Deployment window added: {start_time} - {end_time}",
                max_concurrent=max_concurrent,
                strategies=len(allowed_strategies)
            )

            return str(uuid.uuid4())

        except Exception as e:
            logger.error(f"Failed to add deployment window: {e}")
            raise DeploymentError(f"Window creation failed: {str(e)}")

    async def add_maintenance_window(
        self,
        start_time: datetime,
        end_time: datetime,
        affected_devices: Optional[List[str]] = None,
        description: str = ""
    ) -> str:
        """Add a maintenance window that blocks deployments"""
        try:
            if start_time >= end_time:
                raise ValidationError("Start time must be before end time")

            maintenance_id = str(uuid.uuid4())
            maintenance_window = {
                'id': maintenance_id,
                'start_time': start_time,
                'end_time': end_time,
                'affected_devices': affected_devices or [],
                'description': description,
                'created_at': datetime.utcnow()
            }

            self.maintenance_windows.append(maintenance_window)

            logger.info(
                f"Maintenance window added: {start_time} - {end_time}",
                maintenance_id=maintenance_id,
                affected_devices=len(affected_devices) if affected_devices else 0
            )

            return maintenance_id

        except Exception as e:
            logger.error(f"Failed to add maintenance window: {e}")
            raise DeploymentError(f"Maintenance window creation failed: {str(e)}")

    async def _scheduler_loop(self):
        """Main scheduler loop"""
        logger.info("Starting scheduler loop")

        while self.scheduler_running:
            try:
                current_time = datetime.utcnow()

                # Process due deployments
                await self._process_due_deployments(current_time)

                # Check for completed deployments
                await self._check_completed_deployments()

                # Clean up old scheduled deployments
                await self._cleanup_old_schedules()

                # Wait before next iteration
                await asyncio.sleep(30)  # Check every 30 seconds

            except asyncio.CancelledError:
                logger.info("Scheduler loop cancelled")
                break
            except Exception as e:
                logger.error(f"Scheduler loop error: {e}")
                await asyncio.sleep(60)  # Wait longer on error

    async def _process_due_deployments(self, current_time: datetime):
        """Process deployments that are due for execution"""
        deployments_to_run = []

        # Check if we're at max concurrent deployments
        if len(self.running_deployments) >= self.max_concurrent_deployments:
            return

        # Find deployments that are due
        while (self.deployment_queue and
               self.deployment_queue[0].scheduled_time <= current_time and
               len(deployments_to_run) < (self.max_concurrent_deployments - len(self.running_deployments))):

            scheduled_deployment = heapq.heappop(self.deployment_queue)

            # Check if deployment is still valid
            if scheduled_deployment.status != ScheduleStatus.QUEUED:
                continue

            # Check dependencies
            if not await self._check_dependencies(scheduled_deployment):
                # Re-queue with slight delay
                scheduled_deployment.scheduled_time = current_time + timedelta(minutes=5)
                heapq.heappush(self.deployment_queue, scheduled_deployment)
                continue

            # Check deployment windows and maintenance
            if not await self._validate_schedule_time(
                current_time,
                scheduled_deployment.deployment_request.target_devices
            ):
                # Re-queue for later
                scheduled_deployment.scheduled_time = current_time + timedelta(minutes=15)
                heapq.heappush(self.deployment_queue, scheduled_deployment)
                continue

            deployments_to_run.append(scheduled_deployment)

        # Execute the deployments
        for scheduled_deployment in deployments_to_run:
            try:
                await self._execute_scheduled_deployment(scheduled_deployment)
            except Exception as e:
                logger.error(f"Failed to execute scheduled deployment {scheduled_deployment.id}: {e}")
                await self._handle_deployment_failure(scheduled_deployment, str(e))

    async def _execute_scheduled_deployment(self, scheduled_deployment: ScheduledDeployment):
        """Execute a scheduled deployment"""
        try:
            scheduled_deployment.status = ScheduleStatus.RUNNING
            scheduled_deployment.started_at = datetime.utcnow()

            logger.info(f"Executing scheduled deployment {scheduled_deployment.id}")

            # Create the deployment
            deployment_id = await self.deployment_service.create_deployment(
                scheduled_deployment.deployment_request,
                scheduled_deployment.user_context
            )

            # Track the running deployment
            self.running_deployments[scheduled_deployment.id] = deployment_id

            # Execute the deployment (this will run in background)
            asyncio.create_task(
                self._monitor_deployment_execution(scheduled_deployment, deployment_id)
            )

        except Exception as e:
            logger.error(f"Failed to execute scheduled deployment: {e}")
            await self._handle_deployment_failure(scheduled_deployment, str(e))

    async def _monitor_deployment_execution(
        self,
        scheduled_deployment: ScheduledDeployment,
        deployment_id: str
    ):
        """Monitor a deployment execution and handle completion"""
        try:
            # Execute the deployment
            result = await self.deployment_service.execute_deployment(
                deployment_id,
                scheduled_deployment.user_context
            )

            # Handle successful completion
            scheduled_deployment.status = ScheduleStatus.COMPLETED
            scheduled_deployment.completed_at = datetime.utcnow()

            # Remove from running deployments
            if scheduled_deployment.id in self.running_deployments:
                del self.running_deployments[scheduled_deployment.id]

            await self.audit.log_scheduled_deployment_completed(
                user_id=scheduled_deployment.user_context['user_id'],
                schedule_id=scheduled_deployment.id,
                deployment_id=deployment_id,
                success=True
            )

            logger.info(f"Scheduled deployment completed successfully: {scheduled_deployment.id}")

        except Exception as e:
            logger.error(f"Scheduled deployment failed: {scheduled_deployment.id} - {e}")
            await self._handle_deployment_failure(scheduled_deployment, str(e))

    async def _handle_deployment_failure(
        self,
        scheduled_deployment: ScheduledDeployment,
        error_message: str
    ):
        """Handle deployment failure with retry logic"""
        try:
            scheduled_deployment.retry_count += 1
            scheduled_deployment.error_message = error_message

            # Remove from running deployments if it was running
            if scheduled_deployment.id in self.running_deployments:
                del self.running_deployments[scheduled_deployment.id]

            # Check if we should retry
            if scheduled_deployment.retry_count <= scheduled_deployment.max_retries:
                # Calculate retry delay (exponential backoff)
                retry_delay = min(2 ** scheduled_deployment.retry_count, 60)  # Max 60 minutes
                retry_time = datetime.utcnow() + timedelta(minutes=retry_delay)

                scheduled_deployment.status = ScheduleStatus.QUEUED
                scheduled_deployment.scheduled_time = retry_time

                heapq.heappush(self.deployment_queue, scheduled_deployment)

                logger.info(
                    f"Scheduled deployment will retry: {scheduled_deployment.id} "
                    f"(attempt {scheduled_deployment.retry_count}/{scheduled_deployment.max_retries})"
                )
            else:
                # Max retries exceeded
                scheduled_deployment.status = ScheduleStatus.FAILED
                scheduled_deployment.completed_at = datetime.utcnow()

                await self.audit.log_scheduled_deployment_completed(
                    user_id=scheduled_deployment.user_context['user_id'],
                    schedule_id=scheduled_deployment.id,
                    deployment_id=None,
                    success=False,
                    error=error_message
                )

                logger.error(f"Scheduled deployment failed permanently: {scheduled_deployment.id}")

        except Exception as e:
            logger.error(f"Error handling deployment failure: {e}")

    async def _check_dependencies(self, scheduled_deployment: ScheduledDeployment) -> bool:
        """Check if deployment dependencies are satisfied"""
        for dependency_id in scheduled_deployment.dependencies:
            if dependency_id in self.scheduled_deployments:
                dependency = self.scheduled_deployments[dependency_id]
                if dependency.status != ScheduleStatus.COMPLETED:
                    return False
            else:
                # Dependency not found, assume it's an external dependency that's satisfied
                pass

        return True

    async def _validate_schedule_time(
        self,
        scheduled_time: datetime,
        target_devices: List[str]
    ) -> bool:
        """Validate that a deployment can be scheduled at the given time"""
        # Check maintenance windows
        for maintenance in self.maintenance_windows:
            if (maintenance['start_time'] <= scheduled_time <= maintenance['end_time']):
                # Check if any target devices are affected
                if not maintenance['affected_devices']:  # Global maintenance
                    return False

                affected_devices = set(maintenance['affected_devices'])
                if any(device in affected_devices for device in target_devices):
                    return False

        # Check deployment windows
        current_deployments_in_window = 0
        for window in self.deployment_windows:
            if window.start_time <= scheduled_time <= window.end_time:
                # Count current deployments in this window
                for running_schedule_id in self.running_deployments:
                    running_deployment = self.scheduled_deployments[running_schedule_id]
                    if (window.start_time <= running_deployment.started_at <= window.end_time):
                        current_deployments_in_window += 1

                if current_deployments_in_window >= window.max_concurrent:
                    return False

        return True

    async def _check_completed_deployments(self):
        """Check for deployments that have completed or timed out"""
        current_time = datetime.utcnow()
        completed_schedules = []

        for schedule_id, deployment_id in self.running_deployments.items():
            scheduled_deployment = self.scheduled_deployments[schedule_id]

            # Check for timeout
            if scheduled_deployment.started_at:
                elapsed_time = current_time - scheduled_deployment.started_at
                if elapsed_time.total_seconds() > (scheduled_deployment.timeout_minutes * 60):
                    logger.warning(f"Deployment timed out: {schedule_id}")
                    await self._handle_deployment_failure(
                        scheduled_deployment,
                        f"Deployment timed out after {scheduled_deployment.timeout_minutes} minutes"
                    )
                    completed_schedules.append(schedule_id)

        # Remove completed schedules from running deployments
        for schedule_id in completed_schedules:
            if schedule_id in self.running_deployments:
                del self.running_deployments[schedule_id]

    async def _cleanup_old_schedules(self):
        """Clean up old completed/failed scheduled deployments"""
        current_time = datetime.utcnow()
        cutoff_time = current_time - timedelta(days=7)  # Keep for 7 days

        old_schedules = []
        for schedule_id, scheduled_deployment in self.scheduled_deployments.items():
            if (scheduled_deployment.status in [ScheduleStatus.COMPLETED, ScheduleStatus.FAILED, ScheduleStatus.CANCELLED] and
                scheduled_deployment.completed_at and
                scheduled_deployment.completed_at < cutoff_time):
                old_schedules.append(schedule_id)

        for schedule_id in old_schedules:
            del self.scheduled_deployments[schedule_id]

        if old_schedules:
            logger.info(f"Cleaned up {len(old_schedules)} old scheduled deployments")