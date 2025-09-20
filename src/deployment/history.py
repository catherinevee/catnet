"""
Deployment History Tracking for CatNet

Maintains comprehensive deployment history:
- Deployment audit trail
- Change tracking
- Compliance reporting
- Analytics and insights
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
from collections import defaultdict



class HistoryEventType(Enum):
    """Types of history events"""

    DEPLOYMENT_CREATED = "deployment_created"
    DEPLOYMENT_STARTED = "deployment_started"
    DEPLOYMENT_COMPLETED = "deployment_completed"
    DEPLOYMENT_FAILED = "deployment_failed"
    DEPLOYMENT_ROLLED_BACK = "deployment_rolled_back"
    DEPLOYMENT_PAUSED = "deployment_paused"
    DEPLOYMENT_RESUMED = "deployment_resumed"
    DEPLOYMENT_APPROVED = "deployment_approved"
    DEVICE_DEPLOYED = "device_deployed"
    DEVICE_FAILED = "device_failed"
    DEVICE_ROLLED_BACK = "device_rolled_back"
    HEALTH_CHECK = "health_check"
    VALIDATION = "validation"
    CONFIG_CHANGE = "config_change"


@dataclass

class HistoryEvent:
    """Deployment history event"""

    id: str
    event_type: HistoryEventType
    deployment_id: str
    timestamp: datetime
    user: str
    device_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass

class DeploymentSummary:
    """Deployment summary for history"""

    deployment_id: str
    name: str
    created_at: datetime
    completed_at: Optional[datetime]
    duration_minutes: Optional[int]
    devices_total: int
    devices_successful: int
    devices_failed: int
    strategy: str
    status: str
    created_by: str
    configuration_size: int
    rollback_count: int = 0


@dataclass

class DeviceHistory:
    """Device deployment history"""

    device_id: str
    device_hostname: str
    deployments: List[str] = field(default_factory=list)
    last_deployment: Optional[datetime] = None
    total_deployments: int = 0
    successful_deployments: int = 0
    failed_deployments: int = 0
    average_deployment_time: Optional[float] = None
    last_health_check: Optional[datetime] = None
    health_status: Optional[str] = None



class DeploymentHistory:
    """
    Tracks and manages deployment history
    """

    def __init__(self):
        """Initialize deployment history"""
        self.events: List[HistoryEvent] = []
        self.deployment_summaries: Dict[str, DeploymentSummary] = {}
        self.device_histories: Dict[str, DeviceHistory] = {}
        self.event_index: Dict[str, List[HistoryEvent]] = defaultdict(list)

    def record_event(
        self,
        event_type: HistoryEventType,
        deployment_id: str,
        user: str,
        device_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Record a history event

        Args:
            event_type: Type of event
            deployment_id: Deployment ID
            user: User who triggered event
            device_id: Device ID (if applicable)
            details: Event details
            metadata: Additional metadata

        Returns:
            Event ID
        """
        import uuid

        event = HistoryEvent(
            id=str(uuid.uuid4())[:12],
            event_type=event_type,
            deployment_id=deployment_id,
            timestamp=datetime.utcnow(),
            user=user,
            device_id=device_id,
            details=details or {},
            metadata=metadata or {},
        )

        # Store event
        self.events.append(event)
        self.event_index[deployment_id].append(event)

        if device_id:
            self.event_index[f"device:{device_id}"].append(event)

        # Update summaries based on event type
        self._update_summaries(event)

        # Keep events limited (last 10000)
        if len(self.events) > 10000:
            self.events = self.events[-10000:]

        return event.id

    def record_deployment_start(
        self,
        deployment_id: str,
        name: str,
        devices: List[str],
        strategy: str,
        created_by: str,
        configuration_size: int,
    ) -> None:
        """
        Record deployment start

        Args:
            deployment_id: Deployment ID
            name: Deployment name
            devices: List of devices
            strategy: Deployment strategy
            created_by: User who created deployment
            configuration_size: Size of configuration
        """
        # Create summary
        summary = DeploymentSummary(
            deployment_id=deployment_id,
            name=name,
            created_at=datetime.utcnow(),
            completed_at=None,
            duration_minutes=None,
            devices_total=len(devices),
            devices_successful=0,
            devices_failed=0,
            strategy=strategy,
            status="in_progress",
            created_by=created_by,
            configuration_size=configuration_size,
        )

        self.deployment_summaries[deployment_id] = summary

        # Record event
        self.record_event(
            HistoryEventType.DEPLOYMENT_STARTED,
            deployment_id,
            created_by,
            details={
                "name": name,
                "devices": devices,
                "strategy": strategy,
            },
        )

        # Update device histories
        for device_id in devices:
            if device_id not in self.device_histories:
                self.device_histories[device_id] = DeviceHistory(
                    device_id=device_id,
                    device_hostname=device_id,  # Would get actual hostname
                )

            self.device_histories[device_id].deployments.append(deployment_id)
            self.device_histories[device_id].total_deployments += 1

    def record_deployment_completion(
        self,
        deployment_id: str,
        status: str,
        successful_devices: List[str],
        failed_devices: List[str],
    ) -> None:
        """
        Record deployment completion

        Args:
            deployment_id: Deployment ID
            status: Final status
            successful_devices: List of successful devices
            failed_devices: List of failed devices
        """
        if deployment_id not in self.deployment_summaries:
            return

        summary = self.deployment_summaries[deployment_id]
        summary.completed_at = datetime.utcnow()
        summary.duration_minutes = int(
            (summary.completed_at - summary.created_at).total_seconds() / 60
        )
        summary.devices_successful = len(successful_devices)
        summary.devices_failed = len(failed_devices)
        summary.status = status

        # Update device histories
        for device_id in successful_devices:
            if device_id in self.device_histories:
                self.device_histories[device_id].successful_deployments += 1
                self.device_histories[device_id].last_deployment = \
                    datetime.utcnow()

        for device_id in failed_devices:
            if device_id in self.device_histories:
                self.device_histories[device_id].failed_deployments += 1

    def record_rollback(
        self,
        deployment_id: str,
        user: str,
        devices: List[str],
        reason: str,
    ) -> None:
        """
        Record deployment rollback

        Args:
            deployment_id: Deployment ID
            user: User who initiated rollback
            devices: Devices that were rolled back
            reason: Rollback reason
        """
        self.record_event(
            HistoryEventType.DEPLOYMENT_ROLLED_BACK,
            deployment_id,
            user,
            details={
                "devices": devices,
                "reason": reason,
            },
        )

        if deployment_id in self.deployment_summaries:
            self.deployment_summaries[deployment_id].rollback_count += 1
            self.deployment_summaries[deployment_id].status = "rolled_back"

    def get_deployment_history(
        self,
        deployment_id: Optional[str] = None,
        device_id: Optional[str] = None,
        user: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Get deployment history

        Args:
            deployment_id: Filter by deployment
            device_id: Filter by device
            user: Filter by user
            start_date: Start date filter
            end_date: End date filter
            limit: Maximum results

        Returns:
            List of history events
        """
        events = self.events

        # Apply filters
        if deployment_id:
            events = [e for e in events if e.deployment_id == deployment_id]
        if device_id:
            events = [e for e in events if e.device_id == device_id]
        if user:
            events = [e for e in events if e.user == user]
        if start_date:
            events = [e for e in events if e.timestamp >= start_date]
        if end_date:
            events = [e for e in events if e.timestamp <= end_date]

        # Sort by timestamp descending
        events.sort(key=lambda x: x.timestamp, reverse=True)

        # Convert to dictionaries and limit
        return [self._event_to_dict(e) for e in events[:limit]]

        def get_deployment_summary(
        self,
        deployment_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get deployment summary

        Args:
            deployment_id: Deployment ID

        Returns:
            Deployment summary or None
        """
        if deployment_id not in self.deployment_summaries:
            return None

        summary = self.deployment_summaries[deployment_id]
        return {
            "deployment_id": summary.deployment_id,
            "name": summary.name,
            "created_at": summary.created_at.isoformat(),
            "completed_at": summary.completed_at.isoformat()
            if summary.completed_at
            else None,
            "duration_minutes": summary.duration_minutes,
            "devices_total": summary.devices_total,
            "devices_successful": summary.devices_successful,
            "devices_failed": summary.devices_failed,
            "success_rate": (
                (summary.devices_successful / summary.devices_total * 100)
                if summary.devices_total > 0
                else 0
            ),
            "strategy": summary.strategy,
            "status": summary.status,
            "created_by": summary.created_by,
            "configuration_size": summary.configuration_size,
            "rollback_count": summary.rollback_count,
        }

    def get_device_history(self, device_id: str) -> Optional[Dict[str, Any]]:
        """
        Get device deployment history

        Args:
            device_id: Device ID

        Returns:
            Device history or None
        """
        if device_id not in self.device_histories:
            return None

        history = self.device_histories[device_id]
        return {
            "device_id": history.device_id,
            "device_hostname": history.device_hostname,
            "total_deployments": history.total_deployments,
            "successful_deployments": history.successful_deployments,
            "failed_deployments": history.failed_deployments,
            "success_rate": (
                (history.successful_deployments / history.total_deployments * \
                    100)
                if history.total_deployments > 0
                else 0
            ),
            "last_deployment": history.last_deployment.isoformat()
            if history.last_deployment
            else None,
            "average_deployment_time": history.average_deployment_time,
            "last_health_check": history.last_health_check.isoformat()
            if history.last_health_check
            else None,
            "health_status": history.health_status,
            "recent_deployments": history.deployments[-10:],
                # Last 10 deployments
        }

    def get_statistics(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Get deployment statistics

        Args:
            start_date: Start date for statistics
            end_date: End date for statistics

        Returns:
            Statistics dictionary
        """
        # Filter summaries by date
        summaries = list(self.deployment_summaries.values())
        if start_date:
            summaries = [s for s in summaries if s.created_at >= start_date]
        if end_date:
            summaries = [s for s in summaries if s.created_at <= end_date]

        if not summaries:
            return {
                "total_deployments": 0,
                "successful_deployments": 0,
                "failed_deployments": 0,
                "average_duration_minutes": 0,
                "total_devices_deployed": 0,
                "success_rate": 0,
                "rollback_rate": 0,
            }

        # Calculate statistics
        total = len(summaries)
        successful = len([s for s in summaries if s.status == "completed"])
        failed = len([s for s in summaries if s.status == "failed"])
        rolled_back = len([s for s in summaries if s.rollback_count > 0])

        durations = [s.duration_minutes for s in summaries if \
            s.duration_minutes]
        avg_duration = sum(durations) / len(durations) if durations else 0

        total_devices = sum(s.devices_total for s in summaries)
        sum(s.devices_successful for s in summaries)

        return {
            "total_deployments": total,
            "successful_deployments": successful,
            "failed_deployments": failed,
            "average_duration_minutes": round(avg_duration, 2),
            "total_devices_deployed": total_devices,
                        "success_rate": round(
                (successful / total * 100) if total > 0 else 0,
                2
            ),
                        "rollback_rate": round(
                (rolled_back / total * 100) if total > 0 else 0,
                2
            ),
            "deployments_by_strategy": self._count_by_strategy(summaries),
            "deployments_by_status": self._count_by_status(summaries),
            "top_deployers": self._get_top_deployers(summaries),
        }

    def get_compliance_report(
        self,
        start_date: datetime,
        end_date: datetime,
    ) -> Dict[str, Any]:
        """
        Generate compliance report

        Args:
            start_date: Report start date
            end_date: Report end date

        Returns:
            Compliance report
        """
        events = [e for e in self.events if start_date <= e.timestamp <= \
            end_date]

        # Group events by type
        events_by_type = defaultdict(list)
        for event in events:
            events_by_type[event.event_type.value].append(event)

        # Calculate compliance metrics
        total_deployments = len(
            events_by_type[HistoryEventType.DEPLOYMENT_STARTED.value]
        )
        approved_deployments = len(
            events_by_type[HistoryEventType.DEPLOYMENT_APPROVED.value]
        )
        failed_deployments = len(
            events_by_type[HistoryEventType.DEPLOYMENT_FAILED.value]
        )
        rollbacks = len(events_by_type[HistoryEventType.DEPLOYMENT_ROLLED_BACK. \
            value])

        return {
            "report_period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
            },
            "total_deployments": total_deployments,
            "approved_deployments": approved_deployments,
            "approval_rate": (
                (approved_deployments / total_deployments * 100)
                if total_deployments > 0
                else 0
            ),
            "failed_deployments": failed_deployments,
            "failure_rate": (
                (failed_deployments / total_deployments * 100)
                if total_deployments > 0
                else 0
            ),
            "rollback_count": rollbacks,
            "events_by_type": {k: len(v) for k, v in events_by_type.items()},
            "unique_users": len(set(e.user for e in events)),
                        "unique_devices": len(
                set(e.device_id for e in events if e.device_id)
            ),
        }

    def export_history(
        self,
        format: str = "json",
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> str:
        """
        Export history in specified format

        Args:
            format: Export format (json, csv)
            start_date: Start date filter
            end_date: End date filter

        Returns:
            Exported data as string
        """
        events = self.get_deployment_history(
            start_date=start_date,
            end_date=end_date,
            limit=999999,
        )

        if format == "json":
            return json.dumps(events, indent=2)
        elif format == "csv":
            import csv
            import io

            output = io.StringIO()
            if events:
                writer = csv.DictWriter(output, fieldnames=events[0].keys())
                writer.writeheader()
                writer.writerows(events)
            return output.getvalue()
        else:
            raise ValueError(f"Unsupported format: {format}")

    # Helper methods
    def _update_summaries(self, event: HistoryEvent) -> None:
        """Update summaries based on event"""
        if event.device_id and event.device_id in self.device_histories:
            history = self.device_histories[event.device_id]

            if event.event_type == HistoryEventType.HEALTH_CHECK:
                history.last_health_check = event.timestamp
                history.health_status = event.details.get("status", "unknown")

    def _event_to_dict(self, event: HistoryEvent) -> Dict[str, Any]:
        """Convert event to dictionary"""
        return {
            "id": event.id,
            "event_type": event.event_type.value,
            "deployment_id": event.deployment_id,
            "timestamp": event.timestamp.isoformat(),
            "user": event.user,
            "device_id": event.device_id,
            "details": event.details,
            "metadata": event.metadata,
        }

        def _count_by_strategy(
        self,
        summaries: List[DeploymentSummary]
    ) -> Dict[str, int]:
        """Count deployments by strategy"""
        counts = defaultdict(int)
        for summary in summaries:
            counts[summary.strategy] += 1
        return dict(counts)

        def _count_by_status(
        self,
        summaries: List[DeploymentSummary]
    ) -> Dict[str, int]:
        """Count deployments by status"""
        counts = defaultdict(int)
        for summary in summaries:
            counts[summary.status] += 1
        return dict(counts)

    def _get_top_deployers(
        self, summaries: List[DeploymentSummary], limit: int = 5
    ) -> List[Dict[str, Any]]:
        """Get top deployers"""
        user_counts = defaultdict(int)
        for summary in summaries:
            user_counts[summary.created_by] += 1

                sorted_users = sorted(
            user_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return [
            {"user": user, "deployment_count": count}
            for user, count in sorted_users[:limit]
        ]
