"""
Base worker class for async operations.
Provides common functionality for all worker processes.
"""

import asyncio
import signal
import sys
import json
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from enum import Enum
from uuid import UUID, uuid4
import aioredis
from pydantic import BaseModel, Field

from src.core.config import get_settings
from src.security.audit import AuditLogger
from src.core.exceptions import WorkerError
from src.db.session import get_db


class WorkerStatus(Enum):
    """Worker status enumeration."""
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"


class TaskStatus(Enum):
    """Task status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRY = "retry"


class TaskPriority(Enum):
    """Task priority levels."""
    LOW = 1
    NORMAL = 5
    HIGH = 10
    CRITICAL = 20


class WorkerTask(BaseModel):
    """Worker task model."""

    id: UUID = Field(default_factory=uuid4)
    worker_type: str
    task_type: str
    payload: Dict[str, Any]
    priority: TaskPriority = TaskPriority.NORMAL
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    retry_count: int = 0
    max_retries: int = 3
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class BaseWorker(ABC):
    """
    Base class for all worker processes.
    Provides common functionality like task queue management,
    error handling, and lifecycle management.
    """

    def __init__(
        self,
        worker_id: str = None,
        max_concurrent_tasks: int = 10,
        task_timeout: int = 300
    ):
        """
        Initialize base worker.

        Args:
            worker_id: Unique worker identifier
            max_concurrent_tasks: Maximum concurrent tasks
            task_timeout: Task timeout in seconds
        """
        self.worker_id = worker_id or f"{self.__class__.__name__}_{uuid4().hex[:8]}"
        self.max_concurrent_tasks = max_concurrent_tasks
        self.task_timeout = task_timeout

        self.settings = get_settings()
        self.audit = AuditLogger()

        self.status = WorkerStatus.IDLE
        self.tasks: Dict[UUID, WorkerTask] = {}
        self.running_tasks: List[asyncio.Task] = []

        # Redis connection for task queue
        self.redis: Optional[aioredis.Redis] = None
        self.queue_name = f"catnet:queue:{self.get_worker_type()}"
        self.result_queue = f"catnet:results:{self.get_worker_type()}"

        # Control flags
        self._shutdown = False
        self._pause = False

    @abstractmethod
    def get_worker_type(self) -> str:
        """Get worker type identifier."""
        pass

    @abstractmethod
    async def process_task(self, task: WorkerTask) -> Dict[str, Any]:
        """
        Process a single task.

        Args:
            task: Task to process

        Returns:
            Task result
        """
        pass

    async def start(self):
        """Start the worker process."""
        try:
            # Initialize Redis connection
            await self._init_redis()

            # Register signal handlers
            self._register_signal_handlers()

            # Update status
            self.status = WorkerStatus.RUNNING

            # Log worker start
            await self.audit.log_event(
                event_type="WORKER_STARTED",
                details={
                    'worker_id': self.worker_id,
                    'worker_type': self.get_worker_type(),
                    'max_concurrent_tasks': self.max_concurrent_tasks
                }
            )

            # Start main processing loop
            await self._run_worker_loop()

        except Exception as e:
            self.status = WorkerStatus.ERROR
            await self.audit.log_event(
                event_type="WORKER_ERROR",
                details={
                    'worker_id': self.worker_id,
                    'error': str(e)
                }
            )
            raise WorkerError(f"Worker failed to start: {e}")

    async def stop(self, graceful: bool = True):
        """
        Stop the worker process.

        Args:
            graceful: Wait for running tasks to complete
        """
        self.status = WorkerStatus.STOPPING
        self._shutdown = True

        if graceful:
            # Wait for running tasks to complete
            await self._wait_for_tasks()

        else:
            # Cancel all running tasks
            await self._cancel_all_tasks()

        # Close Redis connection
        if self.redis:
            await self.redis.close()

        self.status = WorkerStatus.STOPPED

        await self.audit.log_event(
            event_type="WORKER_STOPPED",
            details={
                'worker_id': self.worker_id,
                'graceful': graceful
            }
        )

    async def pause(self):
        """Pause task processing."""
        self._pause = True
        self.status = WorkerStatus.PAUSED

        await self.audit.log_event(
            event_type="WORKER_PAUSED",
            details={'worker_id': self.worker_id}
        )

    async def resume(self):
        """Resume task processing."""
        self._pause = False
        self.status = WorkerStatus.RUNNING

        await self.audit.log_event(
            event_type="WORKER_RESUMED",
            details={'worker_id': self.worker_id}
        )

    async def submit_task(
        self,
        task_type: str,
        payload: Dict[str, Any],
        priority: TaskPriority = TaskPriority.NORMAL,
        metadata: Dict[str, Any] = None
    ) -> UUID:
        """
        Submit a new task to the queue.

        Args:
            task_type: Type of task
            payload: Task payload
            priority: Task priority
            metadata: Additional metadata

        Returns:
            Task ID
        """
        task = WorkerTask(
            worker_type=self.get_worker_type(),
            task_type=task_type,
            payload=payload,
            priority=priority,
            metadata=metadata or {}
        )

        # Store task
        self.tasks[task.id] = task

        # Add to Redis queue
        await self._enqueue_task(task)

        await self.audit.log_event(
            event_type="TASK_SUBMITTED",
            details={
                'task_id': str(task.id),
                'task_type': task_type,
                'priority': priority.value
            }
        )

        return task.id

    async def get_task_status(self, task_id: UUID) -> Optional[WorkerTask]:
        """
        Get task status.

        Args:
            task_id: Task ID

        Returns:
            Task object or None
        """
        # Check in-memory tasks
        if task_id in self.tasks:
            return self.tasks[task_id]

        # Check Redis for result
        result = await self._get_task_result(task_id)
        if result:
            return WorkerTask(**result)

        return None

    async def cancel_task(self, task_id: UUID) -> bool:
        """
        Cancel a task.

        Args:
            task_id: Task ID

        Returns:
            True if cancelled successfully
        """
        if task_id in self.tasks:
            task = self.tasks[task_id]

            if task.status == TaskStatus.PENDING:
                task.status = TaskStatus.CANCELLED
                await self._remove_from_queue(task_id)
                return True

            elif task.status == TaskStatus.RUNNING:
                # Find and cancel the asyncio task
                for running_task in self.running_tasks:
                    if running_task.get_name() == str(task_id):
                        running_task.cancel()
                        task.status = TaskStatus.CANCELLED
                        return True

        return False

    async def _init_redis(self):
        """Initialize Redis connection."""
        self.redis = await aioredis.create_redis_pool(
            self.settings.REDIS_URL,
            encoding='utf-8'
        )

    async def _run_worker_loop(self):
        """Main worker processing loop."""
        while not self._shutdown:
            if self._pause:
                await asyncio.sleep(1)
                continue

            # Check if we can process more tasks
            if len(self.running_tasks) >= self.max_concurrent_tasks:
                # Wait for a task to complete
                await asyncio.sleep(0.1)
                continue

            # Get next task from queue
            task = await self._dequeue_task()
            if task:
                # Start processing task
                asyncio_task = asyncio.create_task(
                    self._process_task_wrapper(task)
                )
                asyncio_task.set_name(str(task.id))
                self.running_tasks.append(asyncio_task)

            else:
                # No tasks available, wait
                await asyncio.sleep(1)

            # Clean up completed tasks
            self.running_tasks = [
                t for t in self.running_tasks
                if not t.done()
            ]

    async def _process_task_wrapper(self, task: WorkerTask):
        """Wrapper for task processing with error handling."""
        try:
            # Update task status
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.utcnow()

            # Process task with timeout
            result = await asyncio.wait_for(
                self.process_task(task),
                timeout=self.task_timeout
            )

            # Update task with result
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.utcnow()
            task.result = result

            # Store result in Redis
            await self._store_task_result(task)

            await self.audit.log_event(
                event_type="TASK_COMPLETED",
                details={
                    'task_id': str(task.id),
                    'task_type': task.task_type,
                    'duration': (task.completed_at - task.started_at).total_seconds()
                }
            )

        except asyncio.TimeoutError:
            await self._handle_task_timeout(task)

        except Exception as e:
            await self._handle_task_error(task, e)

        finally:
            # Remove from in-memory tasks
            if task.id in self.tasks:
                del self.tasks[task.id]

    async def _handle_task_error(self, task: WorkerTask, error: Exception):
        """Handle task processing error."""
        task.status = TaskStatus.FAILED
        task.error = str(error)
        task.completed_at = datetime.utcnow()

        # Check if we should retry
        if task.retry_count < task.max_retries:
            task.retry_count += 1
            task.status = TaskStatus.RETRY

            # Re-queue with exponential backoff
            delay = 2 ** task.retry_count
            await asyncio.sleep(delay)
            await self._enqueue_task(task)

            await self.audit.log_event(
                event_type="TASK_RETRY",
                details={
                    'task_id': str(task.id),
                    'retry_count': task.retry_count,
                    'error': str(error)
                }
            )
        else:
            # Store failed result
            await self._store_task_result(task)

            await self.audit.log_event(
                event_type="TASK_FAILED",
                details={
                    'task_id': str(task.id),
                    'error': str(error),
                    'retry_count': task.retry_count
                }
            )

    async def _handle_task_timeout(self, task: WorkerTask):
        """Handle task timeout."""
        task.status = TaskStatus.FAILED
        task.error = "Task timeout"
        task.completed_at = datetime.utcnow()

        await self._store_task_result(task)

        await self.audit.log_event(
            event_type="TASK_TIMEOUT",
            details={
                'task_id': str(task.id),
                'task_type': task.task_type,
                'timeout': self.task_timeout
            }
        )

    async def _enqueue_task(self, task: WorkerTask):
        """Add task to Redis queue."""
        if self.redis:
            # Priority queue implementation
            score = -task.priority.value  # Negative for reverse order
            await self.redis.zadd(
                self.queue_name,
                score,
                task.json()
            )

    async def _dequeue_task(self) -> Optional[WorkerTask]:
        """Get next task from Redis queue."""
        if not self.redis:
            return None

        # Get highest priority task
        result = await self.redis.zpopmax(self.queue_name)
        if result:
            task_data = result[0][0]  # First element is the member
            return WorkerTask.parse_raw(task_data)

        return None

    async def _remove_from_queue(self, task_id: UUID):
        """Remove task from queue."""
        if self.redis:
            # Find and remove task from queue
            # This requires scanning the queue (not ideal for large queues)
            members = await self.redis.zrange(self.queue_name, 0, -1)
            for member in members:
                task = WorkerTask.parse_raw(member)
                if task.id == task_id:
                    await self.redis.zrem(self.queue_name, member)
                    break

    async def _store_task_result(self, task: WorkerTask):
        """Store task result in Redis."""
        if self.redis:
            # Store with TTL
            await self.redis.setex(
                f"{self.result_queue}:{task.id}",
                86400,  # 24 hours
                task.json()
            )

    async def _get_task_result(self, task_id: UUID) -> Optional[Dict]:
        """Get task result from Redis."""
        if self.redis:
            result = await self.redis.get(f"{self.result_queue}:{task_id}")
            if result:
                return json.loads(result)
        return None

    async def _wait_for_tasks(self):
        """Wait for all running tasks to complete."""
        if self.running_tasks:
            await asyncio.gather(*self.running_tasks, return_exceptions=True)

    async def _cancel_all_tasks(self):
        """Cancel all running tasks."""
        for task in self.running_tasks:
            task.cancel()

        # Wait for cancellation
        await asyncio.gather(*self.running_tasks, return_exceptions=True)

    def _register_signal_handlers(self):
        """Register signal handlers for graceful shutdown."""
        def signal_handler(sig, frame):
            asyncio.create_task(self.stop(graceful=True))

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    async def get_metrics(self) -> Dict[str, Any]:
        """Get worker metrics."""
        queue_size = 0
        if self.redis:
            queue_size = await self.redis.zcard(self.queue_name)

        return {
            'worker_id': self.worker_id,
            'worker_type': self.get_worker_type(),
            'status': self.status.value,
            'running_tasks': len(self.running_tasks),
            'queue_size': queue_size,
            'total_processed': len(self.tasks),
            'uptime': datetime.utcnow().isoformat()
        }


# Export main components
__all__ = [
    'BaseWorker',
    'WorkerStatus',
    'WorkerTask',
    'TaskStatus',
    'TaskPriority'
]