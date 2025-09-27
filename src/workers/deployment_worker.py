"""
Deployment worker for async deployment operations.
Handles deployment execution, monitoring, and rollback.
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from uuid import UUID

from src.workers.base import BaseWorker, WorkerTask
from src.deployments.executor import DeploymentExecutor
from src.deployments.strategies import CanaryStrategy, RollingStrategy, BlueGreenStrategy
from src.devices.connector import SecureDeviceConnector
from src.core.exceptions import DeploymentError
from src.db.models import Deployment, Device, DeploymentState
from src.security.audit import AuditLogger


class DeploymentWorker(BaseWorker):
    """
    Worker for processing deployment tasks.
    Handles deployment execution, monitoring, and rollback operations.
    """

    def __init__(self, **kwargs):
        """Initialize deployment worker."""
        super().__init__(**kwargs)
        self.executor = DeploymentExecutor()
        self.device_connector = SecureDeviceConnector()
        self.audit = AuditLogger()

        # Track active deployments
        self.active_deployments: Dict[UUID, Dict] = {}

    def get_worker_type(self) -> str:
        """Get worker type identifier."""
        return "deployment"

    async def process_task(self, task: WorkerTask) -> Dict[str, Any]:
        """
        Process deployment task.

        Args:
            task: Deployment task

        Returns:
            Task result
        """
        task_type = task.task_type
        payload = task.payload

        if task_type == "execute_deployment":
            return await self._execute_deployment(payload)

        elif task_type == "rollback_deployment":
            return await self._rollback_deployment(payload)

        elif task_type == "monitor_deployment":
            return await self._monitor_deployment(payload)

        elif task_type == "validate_deployment":
            return await self._validate_deployment(payload)

        elif task_type == "health_check":
            return await self._health_check_deployment(payload)

        elif task_type == "cancel_deployment":
            return await self._cancel_deployment(payload)

        else:
            raise ValueError(f"Unknown task type: {task_type}")

    async def _execute_deployment(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a deployment."""
        deployment_id = UUID(payload['deployment_id'])
        user_id = UUID(payload.get('user_id'))
        strategy = payload.get('strategy', 'canary')

        try:
            # Get deployment from database
            async with get_db() as db:
                deployment = await db.get(Deployment, deployment_id)
                if not deployment:
                    raise DeploymentError(f"Deployment {deployment_id} not found")

                # Update deployment state
                deployment.state = DeploymentState.IN_PROGRESS
                deployment.started_at = datetime.utcnow()
                await db.commit()

                # Get target devices
                devices = await self._get_target_devices(deployment, db)

                # Track deployment
                self.active_deployments[deployment_id] = {
                    'started_at': datetime.utcnow(),
                    'devices': devices,
                    'strategy': strategy,
                    'progress': 0
                }

                # Execute based on strategy
                if strategy == 'canary':
                    result = await self._execute_canary(deployment, devices)
                elif strategy == 'rolling':
                    result = await self._execute_rolling(deployment, devices)
                elif strategy == 'blue_green':
                    result = await self._execute_blue_green(deployment, devices)
                else:
                    raise ValueError(f"Unknown strategy: {strategy}")

                # Update deployment state
                if result['status'] == 'success':
                    deployment.state = DeploymentState.COMPLETED
                    deployment.completed_at = datetime.utcnow()
                else:
                    deployment.state = DeploymentState.FAILED
                    deployment.error_message = result.get('error')

                await db.commit()

                # Clean up tracking
                del self.active_deployments[deployment_id]

                # Log completion
                await self.audit.log_event(
                    event_type="DEPLOYMENT_COMPLETED",
                    user_id=str(user_id),
                    details={
                        'deployment_id': str(deployment_id),
                        'status': result['status'],
                        'devices_affected': len(devices)
                    }
                )

                return result

        except Exception as e:
            # Update deployment state
            async with get_db() as db:
                deployment = await db.get(Deployment, deployment_id)
                if deployment:
                    deployment.state = DeploymentState.FAILED
                    deployment.error_message = str(e)
                    await db.commit()

            # Clean up tracking
            if deployment_id in self.active_deployments:
                del self.active_deployments[deployment_id]

            raise DeploymentError(f"Deployment failed: {e}")

    async def _rollback_deployment(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Rollback a deployment."""
        deployment_id = UUID(payload['deployment_id'])
        reason = payload.get('reason', 'Manual rollback')

        try:
            async with get_db() as db:
                deployment = await db.get(Deployment, deployment_id)
                if not deployment:
                    raise DeploymentError(f"Deployment {deployment_id} not found")

                # Get devices that were deployed to
                devices = await self._get_deployed_devices(deployment, db)

                # Perform rollback
                rollback_results = []
                for device in devices:
                    try:
                        # Connect to device
                        connection = await self.device_connector.connect_to_device(
                            device_id=str(device.id),
                            user_context={'user_id': str(deployment.created_by)}
                        )

                        # Rollback configuration
                        if device.last_backup_id:
                            await connection.restore_backup(device.last_backup_id)
                            rollback_results.append({
                                'device_id': str(device.id),
                                'status': 'success'
                            })
                        else:
                            rollback_results.append({
                                'device_id': str(device.id),
                                'status': 'failed',
                                'error': 'No backup available'
                            })

                    except Exception as e:
                        rollback_results.append({
                            'device_id': str(device.id),
                            'status': 'failed',
                            'error': str(e)
                        })

                # Update deployment state
                deployment.state = DeploymentState.ROLLED_BACK
                deployment.rollback_reason = reason
                deployment.rollback_at = datetime.utcnow()
                await db.commit()

                # Calculate success rate
                successful = len([r for r in rollback_results if r['status'] == 'success'])
                total = len(rollback_results)

                return {
                    'status': 'success' if successful == total else 'partial',
                    'successful': successful,
                    'total': total,
                    'results': rollback_results
                }

        except Exception as e:
            raise DeploymentError(f"Rollback failed: {e}")

    async def _monitor_deployment(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Monitor ongoing deployment."""
        deployment_id = UUID(payload['deployment_id'])

        if deployment_id not in self.active_deployments:
            return {
                'status': 'not_found',
                'message': 'Deployment not active'
            }

        deployment_info = self.active_deployments[deployment_id]

        # Calculate progress
        elapsed = (datetime.utcnow() - deployment_info['started_at']).total_seconds()

        return {
            'status': 'active',
            'deployment_id': str(deployment_id),
            'strategy': deployment_info['strategy'],
            'progress': deployment_info['progress'],
            'elapsed_seconds': elapsed,
            'devices_total': len(deployment_info['devices']),
            'devices_completed': int(deployment_info['progress'] * len(deployment_info['devices']) / 100)
        }

    async def _validate_deployment(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Validate deployment before execution."""
        deployment_id = UUID(payload['deployment_id'])

        try:
            async with get_db() as db:
                deployment = await db.get(Deployment, deployment_id)
                if not deployment:
                    raise DeploymentError(f"Deployment {deployment_id} not found")

                # Get target devices
                devices = await self._get_target_devices(deployment, db)

                validation_results = []

                for device in devices:
                    # Check device health
                    health = await self._check_device_health(device)

                    # Check configuration compatibility
                    compatible = await self._check_configuration_compatibility(
                        device,
                        deployment.configuration
                    )

                    validation_results.append({
                        'device_id': str(device.id),
                        'device_name': device.hostname,
                        'health': health,
                        'compatible': compatible,
                        'ready': health['healthy'] and compatible
                    })

                # Calculate readiness
                ready_count = len([r for r in validation_results if r['ready']])
                total = len(validation_results)

                return {
                    'status': 'validated',
                    'ready': ready_count == total,
                    'ready_count': ready_count,
                    'total': total,
                    'validation_results': validation_results
                }

        except Exception as e:
            raise DeploymentError(f"Validation failed: {e}")

    async def _health_check_deployment(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Perform health check after deployment."""
        deployment_id = UUID(payload['deployment_id'])
        device_ids = payload.get('device_ids', [])

        health_results = []

        for device_id in device_ids:
            try:
                async with get_db() as db:
                    device = await db.get(Device, UUID(device_id))
                    if device:
                        health = await self._check_device_health(device)
                        health_results.append({
                            'device_id': device_id,
                            'device_name': device.hostname,
                            **health
                        })
            except Exception as e:
                health_results.append({
                    'device_id': device_id,
                    'healthy': False,
                    'error': str(e)
                })

        # Calculate overall health
        healthy_count = len([h for h in health_results if h.get('healthy')])
        total = len(health_results)

        return {
            'status': 'completed',
            'healthy': healthy_count == total,
            'healthy_count': healthy_count,
            'total': total,
            'health_results': health_results
        }

    async def _cancel_deployment(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Cancel ongoing deployment."""
        deployment_id = UUID(payload['deployment_id'])
        reason = payload.get('reason', 'Manual cancellation')

        if deployment_id not in self.active_deployments:
            return {
                'status': 'not_found',
                'message': 'Deployment not active'
            }

        # Mark for cancellation
        self.active_deployments[deployment_id]['cancelled'] = True

        # Update database
        async with get_db() as db:
            deployment = await db.get(Deployment, deployment_id)
            if deployment:
                deployment.state = DeploymentState.CANCELLED
                deployment.error_message = reason
                deployment.completed_at = datetime.utcnow()
                await db.commit()

        # Clean up tracking
        del self.active_deployments[deployment_id]

        return {
            'status': 'cancelled',
            'deployment_id': str(deployment_id),
            'reason': reason
        }

    async def _execute_canary(
        self,
        deployment: Deployment,
        devices: List[Device]
    ) -> Dict[str, Any]:
        """Execute canary deployment strategy."""
        strategy = CanaryStrategy()
        stages = [
            {'percentage': 5, 'wait_minutes': 5},
            {'percentage': 25, 'wait_minutes': 10},
            {'percentage': 50, 'wait_minutes': 15},
            {'percentage': 100, 'wait_minutes': 0}
        ]

        deployed_devices = []
        deployment_id = deployment.id

        for stage_idx, stage in enumerate(stages):
            # Check if cancelled
            if deployment_id in self.active_deployments:
                if self.active_deployments[deployment_id].get('cancelled'):
                    return {
                        'status': 'cancelled',
                        'deployed_devices': deployed_devices
                    }

            # Calculate devices for this stage
            count = int(len(devices) * stage['percentage'] / 100)
            stage_devices = devices[:count]
            new_devices = [d for d in stage_devices if d not in deployed_devices]

            # Deploy to new devices
            for device in new_devices:
                try:
                    # Create backup first
                    await self._backup_device(device)

                    # Deploy configuration
                    await self._deploy_to_device(device, deployment.configuration)

                    # Health check
                    health = await self._check_device_health(device)
                    if not health['healthy']:
                        # Rollback this device
                        await self._rollback_device(device)
                        raise DeploymentError(f"Device {device.hostname} unhealthy after deployment")

                    deployed_devices.append(device)

                    # Update progress
                    if deployment_id in self.active_deployments:
                        self.active_deployments[deployment_id]['progress'] = \
                            (len(deployed_devices) / len(devices)) * 100

                except Exception as e:
                    # Rollback all deployed devices
                    for deployed in deployed_devices:
                        await self._rollback_device(deployed)

                    return {
                        'status': 'failed',
                        'error': str(e),
                        'stage': stage_idx,
                        'deployed_devices': [d.id for d in deployed_devices]
                    }

            # Wait and monitor (except for last stage)
            if stage['wait_minutes'] > 0:
                await self._monitor_stage(deployed_devices, stage['wait_minutes'])

        return {
            'status': 'success',
            'deployed_devices': [d.id for d in deployed_devices],
            'total_devices': len(devices)
        }

    async def _execute_rolling(
        self,
        deployment: Deployment,
        devices: List[Device]
    ) -> Dict[str, Any]:
        """Execute rolling deployment strategy."""
        strategy = RollingStrategy()
        batch_size = max(1, len(devices) // 4)  # 25% batches

        deployed_devices = []
        deployment_id = deployment.id

        for i in range(0, len(devices), batch_size):
            # Check if cancelled
            if deployment_id in self.active_deployments:
                if self.active_deployments[deployment_id].get('cancelled'):
                    return {
                        'status': 'cancelled',
                        'deployed_devices': deployed_devices
                    }

            batch = devices[i:i + batch_size]

            # Deploy batch
            batch_results = await asyncio.gather(
                *[self._deploy_device_safe(d, deployment.configuration) for d in batch],
                return_exceptions=True
            )

            # Check results
            for device, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    # Rollback all deployed devices
                    for deployed in deployed_devices:
                        await self._rollback_device(deployed)

                    return {
                        'status': 'failed',
                        'error': str(result),
                        'batch': i // batch_size,
                        'deployed_devices': [d.id for d in deployed_devices]
                    }

                deployed_devices.append(device)

            # Update progress
            if deployment_id in self.active_deployments:
                self.active_deployments[deployment_id]['progress'] = \
                    (len(deployed_devices) / len(devices)) * 100

            # Brief pause between batches
            if i + batch_size < len(devices):
                await asyncio.sleep(30)

        return {
            'status': 'success',
            'deployed_devices': [d.id for d in deployed_devices],
            'total_devices': len(devices)
        }

    async def _execute_blue_green(
        self,
        deployment: Deployment,
        devices: List[Device]
    ) -> Dict[str, Any]:
        """Execute blue-green deployment strategy."""
        strategy = BlueGreenStrategy()

        # Deploy to all devices in parallel (green environment)
        deployment_id = deployment.id

        # Check if cancelled
        if deployment_id in self.active_deployments:
            if self.active_deployments[deployment_id].get('cancelled'):
                return {
                    'status': 'cancelled',
                    'deployed_devices': []
                }

        # Deploy to all devices
        deploy_results = await asyncio.gather(
            *[self._deploy_device_safe(d, deployment.configuration) for d in devices],
            return_exceptions=True
        )

        # Check results
        failed_devices = []
        deployed_devices = []

        for device, result in zip(devices, deploy_results):
            if isinstance(result, Exception):
                failed_devices.append({
                    'device': device.id,
                    'error': str(result)
                })
            else:
                deployed_devices.append(device)

        if failed_devices:
            # Rollback all devices
            for device in deployed_devices:
                await self._rollback_device(device)

            return {
                'status': 'failed',
                'failed_devices': failed_devices,
                'deployed_devices': []
            }

        # Verify all devices
        health_checks = await asyncio.gather(
            *[self._check_device_health(d) for d in deployed_devices]
        )

        unhealthy = [
            d for d, health in zip(deployed_devices, health_checks)
            if not health['healthy']
        ]

        if unhealthy:
            # Rollback all devices
            for device in deployed_devices:
                await self._rollback_device(device)

            return {
                'status': 'failed',
                'error': 'Health check failed',
                'unhealthy_devices': [d.id for d in unhealthy]
            }

        return {
            'status': 'success',
            'deployed_devices': [d.id for d in deployed_devices],
            'total_devices': len(devices)
        }

    async def _get_target_devices(
        self,
        deployment: Deployment,
        db
    ) -> List[Device]:
        """Get target devices for deployment."""
        # This would query based on deployment configuration
        # Simplified for now
        devices = await db.query(Device).filter(
            Device.is_active == True
        ).all()
        return devices

    async def _get_deployed_devices(
        self,
        deployment: Deployment,
        db
    ) -> List[Device]:
        """Get devices that were deployed to."""
        # This would track which devices received the deployment
        # Simplified for now
        return await self._get_target_devices(deployment, db)

    async def _backup_device(self, device: Device):
        """Create device backup before deployment."""
        connection = await self.device_connector.connect_to_device(
            device_id=str(device.id),
            user_context={'system': True}
        )
        backup_id = await connection.create_backup()
        device.last_backup_id = backup_id

    async def _deploy_to_device(self, device: Device, configuration: Dict):
        """Deploy configuration to device."""
        connection = await self.device_connector.connect_to_device(
            device_id=str(device.id),
            user_context={'system': True}
        )
        await connection.apply_configuration(configuration)

    async def _deploy_device_safe(
        self,
        device: Device,
        configuration: Dict
    ) -> Optional[Exception]:
        """Deploy to device with error handling."""
        try:
            await self._backup_device(device)
            await self._deploy_to_device(device, configuration)
            return None
        except Exception as e:
            return e

    async def _rollback_device(self, device: Device):
        """Rollback device configuration."""
        if device.last_backup_id:
            connection = await self.device_connector.connect_to_device(
                device_id=str(device.id),
                user_context={'system': True}
            )
            await connection.restore_backup(device.last_backup_id)

    async def _check_device_health(self, device: Device) -> Dict[str, Any]:
        """Check device health status."""
        try:
            connection = await self.device_connector.connect_to_device(
                device_id=str(device.id),
                user_context={'system': True}
            )
            health = await connection.check_health()
            return health
        except Exception as e:
            return {
                'healthy': False,
                'error': str(e)
            }

    async def _check_configuration_compatibility(
        self,
        device: Device,
        configuration: Dict
    ) -> bool:
        """Check if configuration is compatible with device."""
        # This would perform compatibility checks
        # Simplified for now
        return True

    async def _monitor_stage(self, devices: List[Device], minutes: int):
        """Monitor devices during canary stage."""
        end_time = datetime.utcnow() + timedelta(minutes=minutes)

        while datetime.utcnow() < end_time:
            # Check device health
            for device in devices:
                health = await self._check_device_health(device)
                if not health['healthy']:
                    raise DeploymentError(f"Device {device.hostname} became unhealthy")

            # Wait before next check
            await asyncio.sleep(60)  # Check every minute


# Export main components
__all__ = ['DeploymentWorker']