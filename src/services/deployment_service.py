from typing import Dict, List, Optional, Any, Tuple
import asyncio
import uuid
import structlog
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum

from ..db.models import (
    Deployment, DeploymentStatus, DeploymentDevice, DeploymentStrategy,
    Device, ConfigBackup
)
from ..db.database import get_db_session
from ..devices.device_manager import DeviceManager
from ..core.deployment_executor import DeploymentExecutor, DeploymentResult
from ..core.validator import ConfigValidator
from ..security.audit import AuditLogger
from ..security.vault import VaultClient
from ..core.exceptions import (
    DeploymentError, ValidationError, SecurityError,
    DeviceConnectionError, VaultError
)

logger = structlog.get_logger()

class DeploymentPhase(Enum):
    PLANNING = "planning"
    VALIDATION = "validation"
    BACKUP = "backup"
    DEPLOYMENT = "deployment"
    VERIFICATION = "verification"
    CLEANUP = "cleanup"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"

@dataclass
class DeploymentRequest:
    configuration_content: str
    target_devices: List[str]
    deployment_strategy: DeploymentStrategy
    deployment_method: str = "merge"
    require_approval: bool = False
    backup_before_deploy: bool = True
    auto_rollback_on_failure: bool = True
    rollback_timeout_minutes: int = 15
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DeploymentProgress:
    deployment_id: str
    phase: DeploymentPhase
    progress_percentage: float
    devices_completed: int
    devices_total: int
    devices_successful: int
    devices_failed: int
    current_device: Optional[str] = None
    estimated_completion: Optional[datetime] = None
    error_message: Optional[str] = None

@dataclass
class RollbackPlan:
    deployment_id: str
    rollback_method: str
    affected_devices: List[str]
    backup_references: Dict[str, str]
    rollback_order: List[str]
    rollback_timeout: int
    created_at: datetime

class DeploymentService:
    def __init__(self):
        self.device_manager = DeviceManager()
        self.deployment_executor = DeploymentExecutor()
        self.config_validator = ConfigValidator()
        self.audit = AuditLogger()
        self.vault = VaultClient()

        self.active_deployments: Dict[str, DeploymentProgress] = {}
        self.rollback_plans: Dict[str, RollbackPlan] = {}
        self.max_concurrent_devices = 10
        self.deployment_timeout_hours = 4

    async def create_deployment(
        self,
        request: DeploymentRequest,
        user_context: Dict[str, Any]
    ) -> str:
        """Create a new deployment with comprehensive validation"""
        try:
            deployment_id = str(uuid.uuid4())

            # Validate configuration
            config_validation = await self.config_validator.validate_configuration(
                {"configurations": {"main": request.configuration_content}}
            )

            if not config_validation.is_valid:
                raise ValidationError(
                    f"Configuration validation failed: {config_validation.errors}",
                    validation_errors=config_validation.errors
                )

            # Validate target devices exist and are accessible
            valid_devices = await self._validate_target_devices(
                request.target_devices, user_context
            )

            if len(valid_devices) != len(request.target_devices):
                invalid_devices = set(request.target_devices) - set(valid_devices)
                raise ValidationError(f"Invalid target devices: {list(invalid_devices)}")

            # Encrypt configuration for storage
            encrypted_config = await self.vault.encrypt_config(request.configuration_content)

            # Create deployment record
            async with get_db_session() as session:
                deployment = Deployment(
                    id=uuid.UUID(deployment_id),
                    configuration_encrypted=encrypted_config,
                    config_hash=self._calculate_config_hash(request.configuration_content),
                    deployment_strategy=request.deployment_strategy,
                    deployment_method=request.deployment_method,
                    status=DeploymentStatus.PENDING,
                    created_by=uuid.UUID(user_context['user_id']),
                    require_approval=request.require_approval,
                    auto_rollback=request.auto_rollback_on_failure,
                    deployment_metadata={
                        'backup_before_deploy': request.backup_before_deploy,
                        'rollback_timeout_minutes': request.rollback_timeout_minutes,
                        'user_metadata': request.metadata
                    }
                )

                session.add(deployment)

                # Create deployment device associations
                for device_id in valid_devices:
                    deployment_device = DeploymentDevice(
                        deployment_id=uuid.UUID(deployment_id),
                        device_id=uuid.UUID(device_id),
                        status="pending",
                        deployment_order=valid_devices.index(device_id)
                    )
                    session.add(deployment_device)

                await session.commit()

            # Initialize deployment progress tracking
            progress = DeploymentProgress(
                deployment_id=deployment_id,
                phase=DeploymentPhase.PLANNING,
                progress_percentage=0.0,
                devices_completed=0,
                devices_total=len(valid_devices),
                devices_successful=0,
                devices_failed=0
            )
            self.active_deployments[deployment_id] = progress

            # Create rollback plan
            rollback_plan = RollbackPlan(
                deployment_id=deployment_id,
                rollback_method="backup_restore",
                affected_devices=valid_devices,
                backup_references={},
                rollback_order=valid_devices[::-1],  # Reverse order for rollback
                rollback_timeout=request.rollback_timeout_minutes,
                created_at=datetime.utcnow()
            )
            self.rollback_plans[deployment_id] = rollback_plan

            await self.audit.log_deployment_creation(
                user_id=user_context['user_id'],
                deployment_id=deployment_id,
                device_count=len(valid_devices),
                strategy=request.deployment_strategy.value
            )

            logger.info(
                f"Deployment {deployment_id} created with {len(valid_devices)} devices",
                deployment_id=deployment_id,
                strategy=request.deployment_strategy.value
            )

            return deployment_id

        except Exception as e:
            logger.error(f"Deployment creation failed: {e}")
            raise DeploymentError(
                f"Failed to create deployment: {str(e)}",
                stage="creation"
            )

    async def execute_deployment(
        self,
        deployment_id: str,
        user_context: Dict[str, Any]
    ) -> DeploymentResult:
        """Execute a deployment with comprehensive error handling and rollback"""
        try:
            if deployment_id not in self.active_deployments:
                raise ValidationError(f"Deployment {deployment_id} not found in active deployments")

            progress = self.active_deployments[deployment_id]
            progress.phase = DeploymentPhase.VALIDATION
            progress.progress_percentage = 5.0

            # Get deployment details
            async with get_db_session() as session:
                deployment = await session.get(Deployment, deployment_id)
                if not deployment:
                    raise ValidationError(f"Deployment {deployment_id} not found")

                if deployment.status != DeploymentStatus.PENDING:
                    raise ValidationError(f"Deployment {deployment_id} is not in pending status")

                # Get target devices
                deployment_devices = await session.query(DeploymentDevice).filter(
                    DeploymentDevice.deployment_id == deployment.id
                ).order_by(DeploymentDevice.deployment_order).all()

                target_devices = [str(dd.device_id) for dd in deployment_devices]

                # Decrypt configuration
                configuration_content = await self.vault.decrypt_config(
                    deployment.configuration_encrypted
                )

                # Update status to in progress
                deployment.status = DeploymentStatus.IN_PROGRESS
                deployment.started_at = datetime.utcnow()
                await session.commit()

            # Phase 1: Pre-deployment validation
            logger.info(f"Starting deployment {deployment_id} validation phase")
            await self._validate_deployment_prerequisites(
                deployment_id, target_devices, user_context
            )

            progress.phase = DeploymentPhase.BACKUP
            progress.progress_percentage = 15.0

            # Phase 2: Create backups
            if deployment.deployment_metadata.get('backup_before_deploy', True):
                logger.info(f"Creating backups for deployment {deployment_id}")
                backup_results = await self._create_deployment_backups(
                    deployment_id, target_devices, user_context
                )

                # Update rollback plan with backup references
                rollback_plan = self.rollback_plans[deployment_id]
                rollback_plan.backup_references = backup_results

            progress.phase = DeploymentPhase.DEPLOYMENT
            progress.progress_percentage = 25.0

            # Phase 3: Execute deployment based on strategy
            deployment_result = None
            try:
                if deployment.deployment_strategy == DeploymentStrategy.CANARY:
                    deployment_result = await self._execute_canary_deployment(
                        deployment_id, configuration_content, target_devices,
                        deployment.deployment_method, user_context
                    )
                elif deployment.deployment_strategy == DeploymentStrategy.ROLLING:
                    deployment_result = await self._execute_rolling_deployment(
                        deployment_id, configuration_content, target_devices,
                        deployment.deployment_method, user_context
                    )
                elif deployment.deployment_strategy == DeploymentStrategy.BLUE_GREEN:
                    deployment_result = await self._execute_blue_green_deployment(
                        deployment_id, configuration_content, target_devices,
                        deployment.deployment_method, user_context
                    )
                else:  # ALL_AT_ONCE
                    deployment_result = await self._execute_parallel_deployment(
                        deployment_id, configuration_content, target_devices,
                        deployment.deployment_method, user_context
                    )

                if not deployment_result.success:
                    raise DeploymentError(
                        f"Deployment execution failed: {deployment_result.error_message}",
                        deployment_id=deployment_id,
                        stage="execution"
                    )

            except Exception as e:
                logger.error(f"Deployment {deployment_id} failed during execution: {e}")

                # Trigger automatic rollback if enabled
                if deployment.auto_rollback:
                    logger.warning(f"Triggering automatic rollback for deployment {deployment_id}")
                    try:
                        await self.rollback_deployment(deployment_id, user_context)
                        progress.phase = DeploymentPhase.ROLLED_BACK
                    except Exception as rollback_error:
                        logger.error(f"Automatic rollback failed: {rollback_error}")
                        progress.phase = DeploymentPhase.FAILED
                        progress.error_message = f"Deployment and rollback failed: {str(e)}, {str(rollback_error)}"
                else:
                    progress.phase = DeploymentPhase.FAILED
                    progress.error_message = str(e)

                # Update deployment status
                async with get_db_session() as session:
                    deployment = await session.get(Deployment, deployment_id)
                    deployment.status = DeploymentStatus.FAILED
                    deployment.completed_at = datetime.utcnow()
                    deployment.error_message = str(e)
                    await session.commit()

                raise

            # Phase 4: Post-deployment verification
            progress.phase = DeploymentPhase.VERIFICATION
            progress.progress_percentage = 85.0

            logger.info(f"Starting post-deployment verification for {deployment_id}")
            verification_results = await self._verify_deployment_success(
                deployment_id, target_devices, user_context
            )

            if not verification_results['all_healthy']:
                if deployment.auto_rollback:
                    logger.warning(f"Verification failed, triggering rollback for {deployment_id}")
                    await self.rollback_deployment(deployment_id, user_context)
                    raise DeploymentError(
                        f"Post-deployment verification failed: {verification_results['issues']}",
                        deployment_id=deployment_id,
                        stage="verification"
                    )

            # Phase 5: Cleanup and completion
            progress.phase = DeploymentPhase.CLEANUP
            progress.progress_percentage = 95.0

            await self._cleanup_deployment(deployment_id, user_context)

            # Mark deployment as completed
            async with get_db_session() as session:
                deployment = await session.get(Deployment, deployment_id)
                deployment.status = DeploymentStatus.COMPLETED
                deployment.completed_at = datetime.utcnow()
                await session.commit()

            progress.phase = DeploymentPhase.COMPLETED
            progress.progress_percentage = 100.0
            progress.devices_completed = len(target_devices)
            progress.devices_successful = len(target_devices)

            await self.audit.log_deployment_completion(
                user_id=user_context['user_id'],
                deployment_id=deployment_id,
                success=True,
                devices_affected=len(target_devices)
            )

            logger.info(f"Deployment {deployment_id} completed successfully")

            return DeploymentResult(
                deployment_id=deployment_id,
                success=True,
                devices_affected=target_devices,
                deployment_duration=(datetime.utcnow() - deployment.started_at).total_seconds(),
                details=deployment_result.details if deployment_result else {}
            )

        except Exception as e:
            logger.error(f"Deployment {deployment_id} failed: {e}")

            await self.audit.log_deployment_completion(
                user_id=user_context['user_id'],
                deployment_id=deployment_id,
                success=False,
                error=str(e)
            )

            raise DeploymentError(
                f"Deployment failed: {str(e)}",
                deployment_id=deployment_id
            )

    async def rollback_deployment(
        self,
        deployment_id: str,
        user_context: Dict[str, Any],
        force: bool = False
    ) -> bool:
        """Rollback a deployment using stored backup configurations"""
        try:
            if deployment_id not in self.rollback_plans:
                raise ValidationError(f"No rollback plan found for deployment {deployment_id}")

            rollback_plan = self.rollback_plans[deployment_id]

            # Update progress tracking
            if deployment_id in self.active_deployments:
                progress = self.active_deployments[deployment_id]
                progress.phase = DeploymentPhase.ROLLING_BACK
                progress.progress_percentage = 0.0

            logger.warning(f"Starting rollback for deployment {deployment_id}")

            rollback_results = {
                'deployment_id': deployment_id,
                'rollback_method': rollback_plan.rollback_method,
                'devices_processed': 0,
                'devices_successful': 0,
                'devices_failed': 0,
                'errors': []
            }

            # Execute rollback for each device in reverse order
            for device_id in rollback_plan.rollback_order:
                try:
                    if device_id not in rollback_plan.backup_references:
                        rollback_results['errors'].append(
                            f"No backup reference found for device {device_id}"
                        )
                        rollback_results['devices_failed'] += 1
                        continue

                    backup_id = rollback_plan.backup_references[device_id]

                    # Get backup configuration
                    async with get_db_session() as session:
                        backup = await session.get(ConfigBackup, backup_id)
                        if not backup:
                            rollback_results['errors'].append(
                                f"Backup {backup_id} not found for device {device_id}"
                            )
                            rollback_results['devices_failed'] += 1
                            continue

                        backup_content = await self.vault.decrypt_config(
                            backup.content_encrypted
                        )

                    # Deploy backup configuration
                    deployment_result = await self.device_manager.deploy_configuration_to_device(
                        device_id=device_id,
                        config_content=backup_content,
                        deployment_method="replace",
                        user_context=user_context,
                        backup_first=False
                    )

                    if deployment_result['success']:
                        rollback_results['devices_successful'] += 1
                        logger.info(f"Rollback successful for device {device_id}")
                    else:
                        rollback_results['devices_failed'] += 1
                        rollback_results['errors'].append(
                            f"Rollback failed for device {device_id}: {deployment_result.get('error')}"
                        )

                    rollback_results['devices_processed'] += 1

                    # Update progress
                    if deployment_id in self.active_deployments:
                        progress = self.active_deployments[deployment_id]
                        progress.progress_percentage = (
                            rollback_results['devices_processed'] / len(rollback_plan.rollback_order)
                        ) * 100
                        progress.current_device = device_id

                    # Small delay between device rollbacks
                    await asyncio.sleep(2)

                except Exception as e:
                    logger.error(f"Rollback failed for device {device_id}: {e}")
                    rollback_results['devices_failed'] += 1
                    rollback_results['errors'].append(f"Device {device_id}: {str(e)}")

            # Update deployment status
            async with get_db_session() as session:
                deployment = await session.get(Deployment, deployment_id)
                if deployment:
                    deployment.status = DeploymentStatus.ROLLED_BACK
                    deployment.rollback_completed_at = datetime.utcnow()
                    deployment.rollback_metadata = rollback_results
                    await session.commit()

            # Update progress tracking
            if deployment_id in self.active_deployments:
                progress = self.active_deployments[deployment_id]
                progress.phase = DeploymentPhase.ROLLED_BACK
                progress.progress_percentage = 100.0

            success = rollback_results['devices_failed'] == 0

            await self.audit.log_deployment_rollback(
                user_id=user_context['user_id'],
                deployment_id=deployment_id,
                success=success,
                devices_processed=rollback_results['devices_processed'],
                devices_successful=rollback_results['devices_successful'],
                errors=rollback_results['errors']
            )

            if success:
                logger.info(f"Rollback completed successfully for deployment {deployment_id}")
            else:
                logger.error(
                    f"Rollback completed with errors for deployment {deployment_id}: "
                    f"{rollback_results['errors']}"
                )

            return success

        except Exception as e:
            logger.error(f"Rollback failed for deployment {deployment_id}: {e}")
            raise DeploymentError(
                f"Rollback failed: {str(e)}",
                deployment_id=deployment_id,
                stage="rollback"
            )

    async def get_deployment_status(
        self,
        deployment_id: str,
        user_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Get comprehensive deployment status"""
        try:
            async with get_db_session() as session:
                deployment = await session.get(Deployment, deployment_id)
                if not deployment:
                    raise ValidationError(f"Deployment {deployment_id} not found")

                deployment_devices = await session.query(DeploymentDevice).filter(
                    DeploymentDevice.deployment_id == deployment.id
                ).all()

                device_statuses = {}
                for dd in deployment_devices:
                    device_statuses[str(dd.device_id)] = {
                        'status': dd.status,
                        'started_at': dd.started_at.isoformat() if dd.started_at else None,
                        'completed_at': dd.completed_at.isoformat() if dd.completed_at else None,
                        'error_message': dd.error_message,
                        'backup_id': str(dd.backup_id) if dd.backup_id else None
                    }

                status_info = {
                    'deployment_id': deployment_id,
                    'status': deployment.status.value,
                    'strategy': deployment.deployment_strategy.value,
                    'method': deployment.deployment_method,
                    'created_at': deployment.created_at.isoformat(),
                    'started_at': deployment.started_at.isoformat() if deployment.started_at else None,
                    'completed_at': deployment.completed_at.isoformat() if deployment.completed_at else None,
                    'rollback_completed_at': deployment.rollback_completed_at.isoformat() if deployment.rollback_completed_at else None,
                    'error_message': deployment.error_message,
                    'device_statuses': device_statuses,
                    'require_approval': deployment.require_approval,
                    'auto_rollback': deployment.auto_rollback
                }

                # Add progress information if available
                if deployment_id in self.active_deployments:
                    progress = self.active_deployments[deployment_id]
                    status_info['progress'] = {
                        'phase': progress.phase.value,
                        'percentage': progress.progress_percentage,
                        'devices_completed': progress.devices_completed,
                        'devices_total': progress.devices_total,
                        'devices_successful': progress.devices_successful,
                        'devices_failed': progress.devices_failed,
                        'current_device': progress.current_device,
                        'estimated_completion': progress.estimated_completion.isoformat() if progress.estimated_completion else None
                    }

                return status_info

        except Exception as e:
            logger.error(f"Failed to get deployment status: {e}")
            raise DeploymentError(f"Status query failed: {str(e)}")

    async def _validate_target_devices(
        self,
        device_ids: List[str],
        user_context: Dict[str, Any]
    ) -> List[str]:
        """Validate that target devices exist and are accessible"""
        valid_devices = []

        async with get_db_session() as session:
            for device_id in device_ids:
                device = await session.get(Device, device_id)
                if device and device.status == 'active':
                    valid_devices.append(device_id)

        return valid_devices

    async def _validate_deployment_prerequisites(
        self,
        deployment_id: str,
        target_devices: List[str],
        user_context: Dict[str, Any]
    ) -> bool:
        """Validate deployment prerequisites"""
        # Check device connectivity
        connectivity_results = await self.device_manager.perform_device_health_checks(
            target_devices, user_context
        )

        unhealthy_devices = []
        for device_id, health_data in connectivity_results.items():
            if health_data.get('status') != 'healthy':
                unhealthy_devices.append(device_id)

        if unhealthy_devices:
            raise DeploymentError(
                f"Devices not healthy for deployment: {unhealthy_devices}",
                deployment_id=deployment_id,
                stage="prerequisites"
            )

        return True

    async def _create_deployment_backups(
        self,
        deployment_id: str,
        target_devices: List[str],
        user_context: Dict[str, Any]
    ) -> Dict[str, str]:
        """Create backups for all target devices"""
        backup_results = {}
        failed_backups = []

        for device_id in target_devices:
            try:
                backup_id = await self.device_manager.device_service.backup_device_config(
                    device_id, user_context, "running"
                )
                backup_results[device_id] = backup_id
                logger.info(f"Backup created for device {device_id}: {backup_id}")
            except Exception as e:
                failed_backups.append(f"Device {device_id}: {str(e)}")
                logger.error(f"Backup failed for device {device_id}: {e}")

        if failed_backups:
            raise DeploymentError(
                f"Backup failures: {failed_backups}",
                deployment_id=deployment_id,
                stage="backup"
            )

        return backup_results

    async def _execute_canary_deployment(
        self,
        deployment_id: str,
        configuration_content: str,
        target_devices: List[str],
        deployment_method: str,
        user_context: Dict[str, Any]
    ) -> DeploymentResult:
        """Execute canary deployment strategy"""
        return await self.deployment_executor.execute_canary_deployment(
            deployment_id, target_devices
        )

    async def _execute_rolling_deployment(
        self,
        deployment_id: str,
        configuration_content: str,
        target_devices: List[str],
        deployment_method: str,
        user_context: Dict[str, Any]
    ) -> DeploymentResult:
        """Execute rolling deployment strategy"""
        return await self.deployment_executor.execute_rolling_deployment(
            deployment_id, target_devices
        )

    async def _execute_blue_green_deployment(
        self,
        deployment_id: str,
        configuration_content: str,
        target_devices: List[str],
        deployment_method: str,
        user_context: Dict[str, Any]
    ) -> DeploymentResult:
        """Execute blue-green deployment strategy"""
        batch_size = max(1, len(target_devices) // 2)

        deployment_targets = []
        for device_id in target_devices:
            deployment_targets.append({
                'device_id': device_id,
                'config_content': configuration_content,
                'deployment_method': deployment_method,
                'backup_first': True
            })

        # Deploy to half the devices first (blue group)
        blue_targets = deployment_targets[:batch_size]
        blue_results = await self.device_manager.parallel_device_deployment(
            blue_targets, user_context, max_concurrent=self.max_concurrent_devices
        )

        if blue_results['failed_deployments'] > 0:
            raise DeploymentError(
                f"Blue group deployment failed: {blue_results['failed_deployments']} devices failed",
                deployment_id=deployment_id,
                stage="blue_deployment"
            )

        # Wait and monitor blue group
        await asyncio.sleep(30)  # Monitor period

        # Deploy to remaining devices (green group)
        green_targets = deployment_targets[batch_size:]
        green_results = await self.device_manager.parallel_device_deployment(
            green_targets, user_context, max_concurrent=self.max_concurrent_devices
        )

        total_successful = blue_results['successful_deployments'] + green_results['successful_deployments']
        total_failed = blue_results['failed_deployments'] + green_results['failed_deployments']

        return DeploymentResult(
            deployment_id=deployment_id,
            success=total_failed == 0,
            devices_affected=target_devices,
            devices_successful=total_successful,
            devices_failed=total_failed,
            details={
                'blue_results': blue_results,
                'green_results': green_results
            }
        )

    async def _execute_parallel_deployment(
        self,
        deployment_id: str,
        configuration_content: str,
        target_devices: List[str],
        deployment_method: str,
        user_context: Dict[str, Any]
    ) -> DeploymentResult:
        """Execute parallel deployment to all devices"""
        deployment_targets = []
        for device_id in target_devices:
            deployment_targets.append({
                'device_id': device_id,
                'config_content': configuration_content,
                'deployment_method': deployment_method,
                'backup_first': True
            })

        results = await self.device_manager.parallel_device_deployment(
            deployment_targets, user_context, max_concurrent=self.max_concurrent_devices
        )

        return DeploymentResult(
            deployment_id=deployment_id,
            success=results['failed_deployments'] == 0,
            devices_affected=target_devices,
            devices_successful=results['successful_deployments'],
            devices_failed=results['failed_deployments'],
            details=results
        )

    async def _verify_deployment_success(
        self,
        deployment_id: str,
        target_devices: List[str],
        user_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Verify deployment success across all devices"""
        verification_results = {
            'all_healthy': True,
            'device_results': {},
            'issues': []
        }

        health_results = await self.device_manager.perform_device_health_checks(
            target_devices, user_context
        )

        for device_id, health_data in health_results.items():
            is_healthy = health_data.get('status') == 'healthy'
            verification_results['device_results'][device_id] = {
                'healthy': is_healthy,
                'health_data': health_data
            }

            if not is_healthy:
                verification_results['all_healthy'] = False
                verification_results['issues'].append(
                    f"Device {device_id} unhealthy: {health_data.get('error', 'Unknown issue')}"
                )

        return verification_results

    async def _cleanup_deployment(
        self,
        deployment_id: str,
        user_context: Dict[str, Any]
    ) -> bool:
        """Cleanup deployment resources"""
        try:
            # Clean up active connections
            await self.device_manager.cleanup_stale_handlers()

            # Remove from active deployments tracking
            if deployment_id in self.active_deployments:
                del self.active_deployments[deployment_id]

            # Keep rollback plan for some time in case manual rollback is needed
            # Can be cleaned up later by a scheduled task

            logger.info(f"Cleanup completed for deployment {deployment_id}")
            return True

        except Exception as e:
            logger.error(f"Cleanup failed for deployment {deployment_id}: {e}")
            return False

    def _calculate_config_hash(self, config_content: str) -> str:
        """Calculate SHA-256 hash of configuration content"""
        import hashlib
        return hashlib.sha256(config_content.encode()).hexdigest()