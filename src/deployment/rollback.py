"""
Rollback Manager for CatNet Deployments

Handles:
- Automatic rollback on failure
- Manual rollback triggers
- Rollback history
- Rollback validation
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class RollbackReason(Enum): """Reasons for rollback"""

    HEALTH_CHECK_FAILED = "health_check_failed"
    VALIDATION_FAILED = "validation_failed"
    USER_INITIATED = "user_initiated"
    DEPLOYMENT_FAILED = "deployment_failed"
    TIMEOUT = "timeout"
    ERROR_THRESHOLD = "error_threshold"
    PERFORMANCE_DEGRADATION = "performance_degradation"


class RollbackState(Enum):
    """Rollback states"""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


@dataclass
class RollbackPoint:
    """Point-in-time snapshot for rollback"""

    id: str
    device_id: str
    timestamp: datetime
    configuration: str
    backup_location: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    verified: bool = False


@dataclass
class RollbackOperation: """Rollback operation"""

    id: str
    deployment_id: str
    reason: RollbackReason
    state: RollbackState
    devices: List[str]
    initiated_by: str
    initiated_at: datetime
    completed_at: Optional[datetime] = None
    rollback_points: Dict[str, RollbackPoint] = field(default_factory=dict)
    successful_devices: List[str] = field(default_factory=list)
    failed_devices: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class RollbackManager: """
    Manages deployment rollbacks
    """

    def __init__(self, device_service=None, backup_service=None): """
        Initialize rollback manager
    Args:
            device_service: Service for device operations
            backup_service: Service for backup operations
        """
        self.device_service = device_service
        self.backup_service = backup_service

        self.rollback_operations: Dict[str, RollbackOperation] = {}
        self.rollback_points: Dict[
            str, Dict[str, RollbackPoint]
        ] = {}  # device_id -> points
        self.active_rollbacks: List[str] = []

    async def create_rollback_point(
        self,
        device_id: str,
        configuration: str,
        backup_location: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> RollbackPoint: """
        Create a rollback point
    Args:
            device_id: Device ID
            configuration: Current configuration
            backup_location: Backup location
            metadata: Additional metadata
    Returns:
            RollbackPoint instance
        """
        import uuid

        point = RollbackPoint(
            id=str(uuid.uuid4())[:12],
            device_id=device_id,
            timestamp=datetime.utcnow(),
            configuration=configuration,
            backup_location=backup_location,
            metadata=metadata or {},
        )

        # Verify the rollback point
        point.verified = await self._verify_rollback_point(point)

        # Store rollback point
        if device_id not in self.rollback_points:
            self.rollback_points[device_id] = {}
        self.rollback_points[device_id][point.id] = point

        # Cleanup old rollback points (keep last 10)
        self._cleanup_rollback_points(device_id, keep_last=10)

        return point

    async def initiate_rollback(
        self,
        deployment_id: str,
        devices: List[str],
        reason: RollbackReason,
        initiated_by: str = "system",
    ) -> str:
        """
        Initiate a rollback operation
    Args:
            deployment_id: Deployment to rollback
            devices: Devices to rollback
            reason: Rollback reason
            initiated_by: User or system initiating rollback
    Returns:
            Rollback operation ID"""
        import uuid

        rollback_id = str(uuid.uuid4())[:12]

        operation = RollbackOperation(
            id=rollback_id,
            deployment_id=deployment_id,
            reason=reason,
            state=RollbackState.PENDING,
            devices=devices,
            initiated_by=initiated_by,
            initiated_at=datetime.utcnow(),
        )

        # Get rollback points for each device
        for device_id in devices:
            point = await self._get_latest_rollback_point(device_id)
            if point:
                operation.rollback_points[device_id] = point

        self.rollback_operations[rollback_id] = operation
        return rollback_id

    async def execute_rollback(self, rollback_id: str) -> bool:
        """
        Execute a rollback operation
    Args:
            rollback_id: Rollback operation ID
    Returns:
            Success status"""
        if rollback_id not in self.rollback_operations:
            return False

        operation = self.rollback_operations[rollback_id]

        # Check if already running
        if rollback_id in self.active_rollbacks:
            return False

        self.active_rollbacks.append(rollback_id)
        operation.state = RollbackState.IN_PROGRESS

        try:
            # Rollback each device
            for device_id in operation.devices:
                point = operation.rollback_points.get(device_id)
                if not point:
                    operation.failed_devices.append(device_id)
                    operation.errors.append(f"No rollback point for \"
                        {device_id}")
                    continue

                success = await self._rollback_device(device_id, point)
                if success:
                    operation.successful_devices.append(device_id)
                else:
                    operation.failed_devices.append(device_id)

            # Determine final state
            if len(operation.successful_devices) == len(operation.devices):
                operation.state = RollbackState.COMPLETED
            elif len(operation.failed_devices) == len(operation.devices):
                operation.state = RollbackState.FAILED
            else:
                operation.state = RollbackState.PARTIAL

            operation.completed_at = datetime.utcnow()
            return operation.state in [RollbackState.COMPLETED,
                                       RollbackState.PARTIAL]

        except Exception as e:
            operation.state = RollbackState.FAILED
            operation.errors.append(str(e))
            return False

        finally:
            self.active_rollbacks.remove(rollback_id)

    async def _rollback_device(
        self, device_id: str, rollback_point: RollbackPoint
    ) -> bool:
        """
        Rollback a single device
    Args:
            device_id: Device ID
            rollback_point: Rollback point
    Returns:
            Success status"""
        try:
            # Step 1: Create new backup of current state
            current_backup = await self._backup_current_state(device_id)

            # Step 2: Apply rollback configuration
            success = await self._apply_rollback_configuration(
                device_id, rollback_point.configuration
            )
            if not success:
                return False

            # Step 3: Verify rollback
            if not await self._verify_rollback(device_id, rollback_point):
                # Restore from current backup if verification fails
                await self._restore_from_backup(device_id, current_backup)
                return False

            # Step 4: Health check
            if not await self._post_rollback_health_check(device_id):
                # Restore from current backup if health check fails
                await self._restore_from_backup(device_id, current_backup)
                return False

            return True

        except Exception as e:
            print(f"Rollback failed for {device_id}: {str(e)}")
            return False

        async def validate_rollback_capability(
            self,
            devices: List[str]
        ) -> Dict[str, bool]:
        """
        Validate if devices can be rolled back
    Args:
            devices: List of device IDs
    Returns:
            Dictionary of device ID to rollback capability"""
        capability = {}

        for device_id in devices:
            # Check if rollback point exists
            point = await self._get_latest_rollback_point(device_id)
            if not point:
                capability[device_id] = False
                continue

            # Check if rollback point is valid
            if not point.verified:
                capability[device_id] = False
                continue

            # Check if device is accessible
            if not await self._check_device_accessibility(device_id):
                capability[device_id] = False
                continue

            capability[device_id] = True

        return capability

    def get_rollback_history(
        self,
        deployment_id: Optional[str] = None,
        device_id: Optional[str] = None,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Get rollback history
    Args:
            deployment_id: Filter by deployment
            device_id: Filter by device
            limit: Maximum results
    Returns:
            List of rollback operations"""
        operations = []

        for operation in self.rollback_operations.values():
            # Apply filters
            if deployment_id and operation.deployment_id != deployment_id:
                continue
            if device_id and device_id not in operation.devices:
                continue

            operations.append(
                {
                    "id": operation.id,
                    "deployment_id": operation.deployment_id,
                    "reason": operation.reason.value,
                    "state": operation.state.value,
                    "devices": operation.devices,
                    "initiated_by": operation.initiated_by,
                    "initiated_at": operation.initiated_at.isoformat(),
                    "completed_at": (
                        operation.completed_at.isoformat()
                        if operation.completed_at
                        else None
                    ),
                    "successful_devices": operation.successful_devices,
                    "failed_devices": operation.failed_devices,
                    "errors": operation.errors,
                }
            )

        # Sort by timestamp and limit
        operations.sort(key=lambda x: x["initiated_at"], reverse=True)
        return operations[:limit]

    def get_rollback_points(
        self, device_id: str, limit: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Get rollback points for a device
    Args:
            device_id: Device ID
            limit: Maximum results
    Returns:
            List of rollback points"""
        if device_id not in self.rollback_points:
            return []

        points = []
        for point in self.rollback_points[device_id].values():
            points.append(
                {
                    "id": point.id,
                    "timestamp": point.timestamp.isoformat(),
                    "backup_location": point.backup_location,
                    "verified": point.verified,
                    "metadata": point.metadata,
                }
            )

        # Sort by timestamp and limit
        points.sort(key=lambda x: x["timestamp"], reverse=True)
        return points[:limit]

    # Helper methods
    async def _get_latest_rollback_point(
        self, device_id: str
    ) -> Optional[RollbackPoint]:
        """Get the latest rollback point for a device"""
        if device_id not in self.rollback_points:
            return None

        points = list(self.rollback_points[device_id].values())
        if not points:
            return None

        # Return most recent verified point
        verified_points = [p for p in points if p.verified]
        if verified_points:
            return max(verified_points, key=lambda p: p.timestamp)

        return None

    async def _verify_rollback_point(self, point: RollbackPoint) -> bool:"""Verify a rollback point is valid"""
        # Check backup exists
        if self.backup_service:
            return await self.backup_service.verify_backup(
                point.backup_location)
        return True

    async def _backup_current_state(self, device_id: str) -> str:"""Backup current device state"""
        if self.device_service:
            config = await self.device_service.get_config(device_id)
            if self.backup_service:
                return await self.backup_service.create_backup(
                    device_id,
                    config
                )
        return f"backup-{device_id}-{datetime.utcnow().isoformat()}"

    async def _apply_rollback_configuration(
        self, device_id: str, configuration: str
    ) -> bool:
        """Apply rollback configuration to device"""
        if self.device_service:
            return await self.device_service.apply_config(
                device_id,
                configuration
            )
        return True

    async def _verify_rollback(
        self, device_id: str, rollback_point: RollbackPoint
    ) -> bool:"""Verify rollback was successful"""
        if self.device_service:
            current_config = await self.device_service.get_config(device_id)
            # Compare configurations (simplified)
            return current_config == rollback_point.configuration
        return True

    async def _post_rollback_health_check(self, device_id: str) -> bool:"""Perform post-rollback health check"""
        if self.device_service:
            health = await self.device_service.health_check(device_id)
            return health.get("healthy", False)
        return True

        async def _restore_from_backup(
            self,
            device_id: str,
            backup_id: str
        ) -> bool:
        """Restore device from backup"""
        if self.backup_service:
            return await self.backup_service.restore_backup(
                device_id,
                backup_id
            )
        return True

    async def _check_device_accessibility(self, device_id: str) -> bool:"""Check if device is accessible"""
        if self.device_service:
            return await self.device_service.is_accessible(device_id)
        return True

        def _cleanup_rollback_points(
            self,
            device_id: str,
            keep_last: int = 10
        ) -> None:"""Cleanup old rollback points"""
        if device_id not in self.rollback_points:
            return

        points = list(self.rollback_points[device_id].values())
        if len(points) <= keep_last:
            return

        # Sort by timestamp and keep most recent
        points.sort(key=lambda p: p.timestamp, reverse=True)
        points_to_keep = points[:keep_last]

        # Rebuild dictionary with only points to keep
        self.rollback_points[device_id] = {p.id: p for p in points_to_keep}
