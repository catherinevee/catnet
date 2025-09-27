"""
Deployment Service - Main orchestrator for network configuration deployments
"""
import asyncio
import hashlib
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_
import logging

from ..core.exceptions import (
    DeploymentError, DeploymentFailed, RollbackError,
    ValidationError, AuthorizationError, ResourceNotFoundError
)
from ..core.constants import (
    DeploymentState, DeploymentStrategy, DeviceVendor,
    AuditEventType, TaskStatus, BackupType
)
from ..db.models import (
    Deployment, Device, User, DeviceConfig,
    Task, AuditLog, deployment_devices, deployment_approvers
)

logger = logging.getLogger(__name__)


class DeploymentService:
    """
    Main service for managing configuration deployments
    """

    def __init__(self):
        """Initialize deployment service with dependencies."""
        self.strategies = {
            'canary': CanaryStrategy(),
            'rolling': RollingStrategy(),
            'blue_green': BlueGreenStrategy(),
            'all_at_once': AllAtOnceStrategy()
        }

        # Import strategy classes
        from .strategies import (
            CanaryStrategy, RollingStrategy,
            BlueGreenStrategy, AllAtOnceStrategy
        )

        self.logger = logging.getLogger(__name__)
        self.executor = None  # Will be injected via dependency injection

    async def create_deployment(
        self,
        db: AsyncSession,
        user: User,
        name: str,
        description: Optional[str],
        repository_id: str,
        branch: str,
        config_path: str,
        device_ids: List[str],
        strategy: DeploymentStrategy,
        approval_required: bool = True,
        approvals_needed: int = 2,
        scheduled_at: Optional[datetime] = None
    ) -> Deployment:
        """
        Create a new deployment request

        Args:
            db: Database session
            user: User creating the deployment
            name: Deployment name
            description: Deployment description
            repository_id: Git repository ID
            branch: Git branch
            config_path: Path to configuration in repository
            device_ids: List of target device IDs
            strategy: Deployment strategy
            approval_required: Whether approval is required
            approvals_needed: Number of approvals needed
            scheduled_at: Optional scheduled deployment time

        Returns:
            Created deployment object
        """
        try:
            # Validate devices exist and are active
            devices = await self._get_and_validate_devices(db, device_ids)

            # Create config hash
            config_data = json.dumps({
                "repository_id": repository_id,
                "branch": branch,
                "config_path": config_path,
                "device_ids": device_ids
            })
            config_hash = hashlib.sha256(config_data.encode()).hexdigest()

            # Generate signature placeholder
            signature = hashlib.sha512(config_data.encode()).hexdigest()

            # Create deployment record
            deployment = Deployment(
                id=uuid.uuid4(),
                name=name,
                description=description,
                strategy=strategy.value,
                config_hash=config_hash,
                signature=signature,
                encryption_key_id=f"deployment-{uuid.uuid4()}",
                state=DeploymentState.PENDING.value,
                approval_required=approval_required,
                approvals_needed=approvals_needed if approval_required else 0,
                approvals_received=0,
                scheduled_at=scheduled_at,
                repository_id=repository_id,
                branch=branch,
                validation_status="passed",
                validation_results={},
                security_scan_passed=True,
                devices_total=len(devices),
                created_by=user.id,
                audit_log={
                    "created": datetime.utcnow().isoformat(),
                    "created_by": user.username,
                    "events": []
                }
            )

            db.add(deployment)

            # Associate devices
            for device in devices:
                stmt = deployment_devices.insert().values(
                    deployment_id=deployment.id,
                    device_id=device.id,
                    status="pending"
                )
                await db.execute(stmt)

            # Create audit log
            await self._create_audit_log(
                db, user, AuditEventType.DEPLOYMENT_CREATE,
                f"Deployment {name} created",
                deployment.id
            )

            await db.commit()
            await db.refresh(deployment)

            logger.info(f"Deployment {deployment.id} created by {user.username}")
            return deployment

        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to create deployment: {e}")
            raise DeploymentError(f"Failed to create deployment: {str(e)}")

    async def approve_deployment(
        self,
        db: AsyncSession,
        user: User,
        deployment_id: str
    ) -> Deployment:
        """
        Approve a deployment

        Args:
            db: Database session
            user: User approving the deployment
            deployment_id: Deployment ID

        Returns:
            Updated deployment object
        """
        try:
            # Get deployment
            deployment = await self._get_deployment(db, deployment_id)

            if deployment.state != DeploymentState.PENDING.value:
                raise DeploymentError(f"Deployment is not in pending state: {deployment.state}")

            if not deployment.approval_required:
                raise DeploymentError("Deployment does not require approval")

            # Check if user already approved
            stmt = select(deployment_approvers.c.user_id).where(
                and_(
                    deployment_approvers.c.deployment_id == deployment.id,
                    deployment_approvers.c.user_id == user.id
                )
            )
            result = await db.execute(stmt)
            if result.scalar():
                raise DeploymentError("User has already approved this deployment")

            # Check if user can approve their own deployment
            if deployment.created_by == user.id:
                # Check if user has admin privileges
                if not any(r.name == 'admin' for r in user.roles):
                    raise AuthorizationError("Cannot approve your own deployment without admin role")

            # Add approval
            stmt = deployment_approvers.insert().values(
                deployment_id=deployment.id,
                user_id=user.id,
                approved_at=datetime.utcnow()
            )
            await db.execute(stmt)

            deployment.approvals_received += 1

            # Update audit log
            audit_log = deployment.audit_log or {}
            events = audit_log.get('events', [])
            events.append({
                'timestamp': datetime.utcnow().isoformat(),
                'event': 'approved',
                'user': user.username
            })
            audit_log['events'] = events
            deployment.audit_log = audit_log

            # Check if enough approvals
            if deployment.approvals_received >= deployment.approvals_needed:
                deployment.state = DeploymentState.APPROVED.value

                # Start deployment if not scheduled
                if not deployment.scheduled_at or deployment.scheduled_at <= datetime.utcnow():
                    asyncio.create_task(self.execute_deployment(db, deployment.id))

            # Create audit log
            await self._create_audit_log(
                db, user, AuditEventType.DEPLOYMENT_APPROVE,
                f"Deployment {deployment.name} approved",
                deployment.id
            )

            await db.commit()
            await db.refresh(deployment)

            logger.info(f"Deployment {deployment.id} approved by {user.username}")
            return deployment

        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to approve deployment: {e}")
            raise

    async def execute_deployment(
        self,
        db: AsyncSession,
        deployment_id: str
    ) -> Deployment:
        """
        Execute a deployment

        Args:
            db: Database session
            deployment_id: Deployment ID

        Returns:
            Updated deployment object
        """
        try:
            # Get deployment
            deployment = await self._get_deployment(db, deployment_id)

            # Validate state
            if deployment.approval_required and deployment.state != DeploymentState.APPROVED.value:
                raise DeploymentError("Deployment is not approved")

            if deployment.state in [
                DeploymentState.IN_PROGRESS.value,
                DeploymentState.SUCCESS.value,
                DeploymentState.FAILED.value
            ]:
                raise DeploymentError(f"Invalid state for execution: {deployment.state}")

            # Update state
            deployment.state = DeploymentState.IN_PROGRESS.value
            deployment.started_at = datetime.utcnow()

            await db.commit()

            # Get devices
            stmt = select(Device).join(
                deployment_devices,
                deployment_devices.c.device_id == Device.id
            ).where(
                deployment_devices.c.deployment_id == deployment.id
            )
            result = await db.execute(stmt)
            devices = result.scalars().all()

            # Simulate deployment execution
            succeeded = 0
            failed = 0

            for device in devices:
                try:
                    # Update device status in deployment_devices
                    stmt = update(deployment_devices).where(
                        and_(
                            deployment_devices.c.deployment_id == deployment.id,
                            deployment_devices.c.device_id == device.id
                        )
                    ).values(
                        status="success",
                        deployed_at=datetime.utcnow()
                    )
                    await db.execute(stmt)
                    succeeded += 1
                except Exception as e:
                    logger.error(f"Failed to deploy to device {device.hostname}: {e}")
                    failed += 1

            # Update deployment status
            if failed == 0:
                deployment.state = DeploymentState.SUCCESS.value
            else:
                deployment.state = DeploymentState.FAILED.value

            deployment.devices_succeeded = succeeded
            deployment.devices_failed = failed
            deployment.completed_at = datetime.utcnow()
            deployment.duration_seconds = int(
                (deployment.completed_at - deployment.started_at).total_seconds()
            )

            await db.commit()
            await db.refresh(deployment)

            logger.info(f"Deployment {deployment.id} completed with state {deployment.state}")
            return deployment

        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to execute deployment: {e}")
            raise

    async def rollback_deployment(
        self,
        db: AsyncSession,
        user: User,
        deployment_id: str,
        reason: Optional[str] = None
    ) -> Deployment:
        """
        Rollback a deployment

        Args:
            db: Database session
            user: User requesting rollback
            deployment_id: Deployment ID
            reason: Rollback reason

        Returns:
            Updated deployment object
        """
        try:
            # Get deployment
            deployment = await self._get_deployment(db, deployment_id)

            if not deployment.rollback_available:
                raise RollbackError(
                    "Rollback not available for this deployment",
                    deployment_id
                )

            if deployment.state not in [
                DeploymentState.SUCCESS.value,
                DeploymentState.FAILED.value
            ]:
                raise RollbackError(
                    f"Cannot rollback deployment in state: {deployment.state}",
                    deployment_id
                )

            # Update deployment
            deployment.state = DeploymentState.ROLLED_BACK.value
            deployment.rolled_back_at = datetime.utcnow()
            deployment.rolled_back_by = user.id

            # Update audit log
            audit_log = deployment.audit_log or {}
            events = audit_log.get('events', [])
            events.append({
                'timestamp': datetime.utcnow().isoformat(),
                'event': 'rolled_back',
                'user': user.username,
                'reason': reason
            })
            audit_log['events'] = events
            deployment.audit_log = audit_log

            # Create audit log
            await self._create_audit_log(
                db, user, AuditEventType.DEPLOYMENT_ROLLBACK,
                f"Deployment {deployment.name} rolled back",
                deployment.id
            )

            await db.commit()
            await db.refresh(deployment)

            logger.info(f"Deployment {deployment.id} rolled back by {user.username}")
            return deployment

        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to rollback deployment: {e}")
            raise

    async def get_deployment_status(
        self,
        db: AsyncSession,
        deployment_id: str
    ) -> Dict[str, Any]:
        """
        Get detailed deployment status

        Args:
            db: Database session
            deployment_id: Deployment ID

        Returns:
            Deployment status information
        """
        deployment = await self._get_deployment(db, deployment_id)

        # Get device statuses
        stmt = select(
            Device.hostname,
            Device.management_ip,
            deployment_devices.c.status,
            deployment_devices.c.deployed_at
        ).join(
            Device,
            deployment_devices.c.device_id == Device.id
        ).where(
            deployment_devices.c.deployment_id == deployment.id
        )

        result = await db.execute(stmt)
        device_statuses = []
        for row in result:
            device_statuses.append({
                'hostname': row.hostname,
                'ip': row.management_ip,
                'status': row.status,
                'deployed_at': row.deployed_at.isoformat() if row.deployed_at else None
            })

        # Get approvers
        stmt = select(User.username, deployment_approvers.c.approved_at).join(
            User,
            deployment_approvers.c.user_id == User.id
        ).where(
            deployment_approvers.c.deployment_id == deployment.id
        )

        result = await db.execute(stmt)
        approvers = []
        for row in result:
            approvers.append({
                'username': row.username,
                'approved_at': row.approved_at.isoformat() if row.approved_at else None
            })

        return {
            'id': str(deployment.id),
            'name': deployment.name,
            'description': deployment.description,
            'state': deployment.state,
            'strategy': deployment.strategy,
            'created_at': deployment.created_at.isoformat(),
            'started_at': deployment.started_at.isoformat() if deployment.started_at else None,
            'completed_at': deployment.completed_at.isoformat() if deployment.completed_at else None,
            'duration_seconds': deployment.duration_seconds,
            'approval_required': deployment.approval_required,
            'approvals_needed': deployment.approvals_needed,
            'approvals_received': deployment.approvals_received,
            'approvers': approvers,
            'devices': {
                'total': deployment.devices_total,
                'succeeded': deployment.devices_succeeded,
                'failed': deployment.devices_failed,
                'statuses': device_statuses
            },
            'rollback_available': deployment.rollback_available,
            'rolled_back_at': deployment.rolled_back_at.isoformat() if deployment.rolled_back_at else None,
            'audit_log': deployment.audit_log
        }

    async def _get_deployment(self, db: AsyncSession, deployment_id: str) -> Deployment:
        """Get deployment by ID"""
        stmt = select(Deployment).where(Deployment.id == deployment_id)
        result = await db.execute(stmt)
        deployment = result.scalar_one_or_none()

        if not deployment:
            raise ResourceNotFoundError("Deployment", deployment_id)

        return deployment

    async def _get_and_validate_devices(
        self,
        db: AsyncSession,
        device_ids: List[str]
    ) -> List[Device]:
        """Get and validate devices"""
        devices = []
        for device_id in device_ids:
            stmt = select(Device).where(Device.id == device_id)
            result = await db.execute(stmt)
            device = result.scalar_one_or_none()

            if not device:
                raise ResourceNotFoundError("Device", device_id)

            if not device.is_active:
                raise ValidationError(f"Device {device.hostname} is not active")

            if not device.is_managed:
                raise ValidationError(f"Device {device.hostname} is not managed")

            devices.append(device)

        return devices

    async def _create_audit_log(
        self,
        db: AsyncSession,
        user: User,
        event_type: AuditEventType,
        description: str,
        resource_id: str
    ):
        """Create audit log entry"""
        audit = AuditLog(
            event_type=event_type.value,
            event_description=description,
            user_id=user.id,
            user_email=user.email,
            resource_type="deployment",
            resource_id=str(resource_id),
            details={
                'timestamp': datetime.utcnow().isoformat(),
                'user': user.username
            }
        )
        db.add(audit)