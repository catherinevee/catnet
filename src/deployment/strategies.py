"""
Deployment Strategies - Implementation of different deployment patterns
"""
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import logging
import math
from abc import ABC, abstractmethod
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.exceptions import DeploymentFailed
from ..core.constants import DeploymentState, TaskStatus
from ..db.models import Task

logger = logging.getLogger(__name__)


class DeploymentStrategy(ABC):
    """Base class for deployment strategies"""

    @abstractmethod
    async def execute(
        self,
        deployment_id: str,
        device_configs: List[Dict[str, Any]],
        executor: Any,
        db: AsyncSession
    ) -> Dict[str, Any]:
        """Execute deployment strategy"""
        pass

    async def _create_task(
        self,
        db: AsyncSession,
        deployment_id: str,
        name: str,
        task_type: str,
        payload: Dict[str, Any]
    ) -> Task:
        """Create a deployment task"""
        task = Task(
            name=name,
            task_type=task_type,
            status=TaskStatus.RUNNING.value,
            deployment_id=deployment_id,
            payload=payload,
            started_at=datetime.utcnow()
        )
        db.add(task)
        await db.commit()
        return task

    async def _update_task(
        self,
        db: AsyncSession,
        task: Task,
        status: str,
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None
    ):
        """Update task status"""
        task.status = status
        task.completed_at = datetime.utcnow()
        task.execution_time = int((task.completed_at - task.started_at).total_seconds() * 1000)

        if result:
            task.result = result
        if error:
            task.error = error

        await db.commit()

    async def _deploy_batch(
        self,
        batch: List[Dict[str, Any]],
        executor: Any,
        deployment_id: str,
        db: AsyncSession,
        batch_name: str = "batch"
    ) -> Dict[str, Any]:
        """Deploy to a batch of devices"""
        results = {
            'total': len(batch),
            'succeeded': 0,
            'failed': 0,
            'devices': []
        }

        # Deploy to devices in parallel within the batch
        tasks = []
        for device_config in batch:
            device = device_config['device']
            config = device_config['config']

            task = asyncio.create_task(
                executor.deploy_to_device(
                    device, config, deployment_id, db
                )
            )
            tasks.append((device, task))

        # Wait for all deployments in batch to complete
        for device, task in tasks:
            try:
                result = await task
                results['devices'].append(result)

                if result['success']:
                    results['succeeded'] += 1
                    logger.info(f"{batch_name}: Successfully deployed to {device.hostname}")
                else:
                    results['failed'] += 1
                    logger.error(f"{batch_name}: Failed to deploy to {device.hostname}: {result.get('error')}")

            except Exception as e:
                results['failed'] += 1
                results['devices'].append({
                    'device_id': str(device.id),
                    'hostname': device.hostname,
                    'success': False,
                    'error': str(e)
                })
                logger.error(f"{batch_name}: Exception deploying to {device.hostname}: {e}")

        return results

    async def _health_check(
        self,
        devices: List[Dict[str, Any]],
        executor: Any,
        wait_time: int = 30
    ) -> bool:
        """Perform health check on deployed devices"""
        logger.info(f"Waiting {wait_time} seconds for devices to stabilize...")
        await asyncio.sleep(wait_time)

        logger.info(f"Performing health checks on {len(devices)} devices")

        all_healthy = True
        for device_config in devices:
            device = device_config['device']
            try:
                # Simulate health check
                verification_result = await executor.verify_deployment(
                    device, device_config['config']
                )

                if not verification_result['passed']:
                    logger.warning(f"Health check failed for device {device.hostname}")
                    all_healthy = False
                else:
                    logger.info(f"Health check passed for device {device.hostname}")

            except Exception as e:
                logger.error(f"Health check exception for device {device.hostname}: {e}")
                all_healthy = False

        return all_healthy


class CanaryStrategy(DeploymentStrategy):
    """
    Canary deployment strategy
    Deploy to a small percentage first, then gradually increase
    """

    def __init__(self, stages: Optional[List[Dict[str, int]]] = None):
        self.stages = stages or [
            {'percentage': 5, 'wait_minutes': 5},
            {'percentage': 25, 'wait_minutes': 10},
            {'percentage': 50, 'wait_minutes': 15},
            {'percentage': 100, 'wait_minutes': 0}
        ]

    async def execute(
        self,
        deployment_id: str,
        device_configs: List[Dict[str, Any]],
        executor: Any,
        db: AsyncSession
    ) -> Dict[str, Any]:
        """Execute canary deployment"""

        total_devices = len(device_configs)
        logger.info(f"Starting canary deployment for {total_devices} devices")

        result = {
            'strategy': 'canary',
            'total_devices': total_devices,
            'stages_completed': 0,
            'succeeded': 0,
            'failed': 0,
            'success': False,
            'devices': []
        }

        deployed_indices = set()

        for stage_num, stage in enumerate(self.stages, 1):
            percentage = stage['percentage']
            wait_minutes = stage['wait_minutes']

            # Calculate devices for this stage
            target_count = math.ceil(total_devices * percentage / 100)
            new_count = target_count - len(deployed_indices)

            # Select new devices for this stage
            available_indices = [i for i in range(total_devices) if i not in deployed_indices]
            stage_indices = available_indices[:new_count]
            stage_devices = [device_configs[i] for i in stage_indices]

            if not stage_devices:
                logger.info(f"Stage {stage_num}: No new devices to deploy")
                continue

            logger.info(f"Stage {stage_num}: Deploying to {len(stage_devices)} devices ({percentage}% total)")

            # Create task for this stage
            task = await self._create_task(
                db, deployment_id,
                f"Canary Stage {stage_num} - {percentage}%",
                "canary_stage",
                {'stage': stage_num, 'percentage': percentage, 'device_count': len(stage_devices)}
            )

            try:
                # Deploy to this stage's devices
                stage_result = await self._deploy_batch(
                    stage_devices, executor, deployment_id, db,
                    f"Canary Stage {stage_num}"
                )

                result['devices'].extend(stage_result['devices'])
                result['succeeded'] += stage_result['succeeded']
                result['failed'] += stage_result['failed']

                # Check if stage was successful
                if stage_result['failed'] > 0:
                    failure_rate = stage_result['failed'] / stage_result['total']
                    if failure_rate > 0.1:  # More than 10% failure rate
                        logger.error(f"Stage {stage_num} failed with {failure_rate*100:.1f}% failure rate")
                        await self._update_task(db, task, TaskStatus.FAILED.value, stage_result,
                                              f"High failure rate: {failure_rate*100:.1f}%")

                        # Rollback if needed
                        logger.info(f"Initiating rollback for {len(stage_devices)} devices")
                        await executor.rollback_devices(
                            [dc['device'] for dc in stage_devices],
                            deployment_id,
                            db
                        )

                        raise DeploymentFailed(f"Canary deployment failed at stage {stage_num}")

                # Update deployed indices
                deployed_indices.update(stage_indices)

                # Perform health check and wait
                if wait_minutes > 0:
                    logger.info(f"Stage {stage_num}: Monitoring for {wait_minutes} minutes")

                    # Health check after deployment
                    health_ok = await self._health_check(
                        stage_devices, executor, min(wait_minutes * 60, 60)
                    )

                    if not health_ok:
                        logger.error(f"Stage {stage_num}: Health check failed")
                        await self._update_task(db, task, TaskStatus.FAILED.value, stage_result,
                                              "Health check failed")

                        # Rollback
                        await executor.rollback_devices(
                            [dc['device'] for dc in stage_devices],
                            deployment_id,
                            db
                        )

                        raise DeploymentFailed(f"Health check failed at stage {stage_num}")

                    # Wait remaining time
                    remaining_wait = max(0, (wait_minutes * 60) - 60)
                    if remaining_wait > 0:
                        await asyncio.sleep(remaining_wait)

                await self._update_task(db, task, TaskStatus.COMPLETED.value, stage_result)
                result['stages_completed'] += 1

            except Exception as e:
                await self._update_task(db, task, TaskStatus.FAILED.value, error=str(e))
                raise

        result['success'] = result['failed'] == 0
        return result


class RollingStrategy(DeploymentStrategy):
    """
    Rolling deployment strategy
    Deploy to devices in fixed-size batches
    """

    def __init__(self, batch_size: int = 5, batch_delay_seconds: int = 30):
        self.batch_size = batch_size
        self.batch_delay_seconds = batch_delay_seconds

    async def execute(
        self,
        deployment_id: str,
        device_configs: List[Dict[str, Any]],
        executor: Any,
        db: AsyncSession
    ) -> Dict[str, Any]:
        """Execute rolling deployment"""

        total_devices = len(device_configs)
        logger.info(f"Starting rolling deployment for {total_devices} devices (batch size: {self.batch_size})")

        result = {
            'strategy': 'rolling',
            'total_devices': total_devices,
            'batch_size': self.batch_size,
            'batches_completed': 0,
            'succeeded': 0,
            'failed': 0,
            'success': False,
            'devices': []
        }

        # Split devices into batches
        batches = []
        for i in range(0, total_devices, self.batch_size):
            batch = device_configs[i:i + self.batch_size]
            batches.append(batch)

        logger.info(f"Created {len(batches)} batches for rolling deployment")

        for batch_num, batch in enumerate(batches, 1):
            logger.info(f"Batch {batch_num}/{len(batches)}: Deploying to {len(batch)} devices")

            # Create task for this batch
            task = await self._create_task(
                db, deployment_id,
                f"Rolling Batch {batch_num}/{len(batches)}",
                "rolling_batch",
                {'batch': batch_num, 'total_batches': len(batches), 'device_count': len(batch)}
            )

            try:
                # Deploy to batch
                batch_result = await self._deploy_batch(
                    batch, executor, deployment_id, db,
                    f"Rolling Batch {batch_num}"
                )

                result['devices'].extend(batch_result['devices'])
                result['succeeded'] += batch_result['succeeded']
                result['failed'] += batch_result['failed']

                # Check batch success
                if batch_result['failed'] > 0:
                    logger.warning(f"Batch {batch_num} had {batch_result['failed']} failures")

                    # Decide whether to continue or abort
                    failure_rate = batch_result['failed'] / batch_result['total']
                    if failure_rate > 0.5:  # More than 50% failure in batch
                        await self._update_task(db, task, TaskStatus.FAILED.value, batch_result,
                                              f"High failure rate in batch: {failure_rate*100:.1f}%")
                        raise DeploymentFailed(f"Rolling deployment aborted at batch {batch_num}")

                await self._update_task(db, task, TaskStatus.COMPLETED.value, batch_result)
                result['batches_completed'] += 1

                # Wait between batches (except for last batch)
                if batch_num < len(batches) and self.batch_delay_seconds > 0:
                    logger.info(f"Waiting {self.batch_delay_seconds} seconds before next batch")
                    await asyncio.sleep(self.batch_delay_seconds)

            except Exception as e:
                await self._update_task(db, task, TaskStatus.FAILED.value, error=str(e))
                raise

        result['success'] = result['failed'] == 0
        return result


class BlueGreenStrategy(DeploymentStrategy):
    """
    Blue-Green deployment strategy
    Deploy to standby environment, then switch
    """

    async def execute(
        self,
        deployment_id: str,
        device_configs: List[Dict[str, Any]],
        executor: Any,
        db: AsyncSession
    ) -> Dict[str, Any]:
        """Execute blue-green deployment"""

        total_devices = len(device_configs)
        logger.info(f"Starting blue-green deployment for {total_devices} devices")

        result = {
            'strategy': 'blue_green',
            'total_devices': total_devices,
            'succeeded': 0,
            'failed': 0,
            'success': False,
            'devices': []
        }

        # Split devices into blue and green groups
        mid_point = total_devices // 2
        green_devices = device_configs[:mid_point]  # Current active
        blue_devices = device_configs[mid_point:]   # Standby to update

        if not blue_devices:
            # If odd number, use all as blue (full replacement)
            blue_devices = device_configs
            green_devices = []

        logger.info(f"Blue-Green: {len(blue_devices)} blue (standby), {len(green_devices)} green (active)")

        # Phase 1: Deploy to blue (standby) environment
        blue_task = await self._create_task(
            db, deployment_id,
            "Blue-Green: Deploy to Blue Environment",
            "blue_green_deploy",
            {'phase': 'blue', 'device_count': len(blue_devices)}
        )

        try:
            logger.info("Phase 1: Deploying to blue (standby) environment")
            blue_result = await self._deploy_batch(
                blue_devices, executor, deployment_id, db,
                "Blue Environment"
            )

            result['devices'].extend(blue_result['devices'])
            result['succeeded'] += blue_result['succeeded']
            result['failed'] += blue_result['failed']

            if blue_result['failed'] > 0:
                await self._update_task(db, blue_task, TaskStatus.FAILED.value, blue_result,
                                      f"Blue deployment failed: {blue_result['failed']} devices")
                raise DeploymentFailed("Blue environment deployment failed")

            await self._update_task(db, blue_task, TaskStatus.COMPLETED.value, blue_result)

            # Phase 2: Validate blue environment
            logger.info("Phase 2: Validating blue environment")
            validation_task = await self._create_task(
                db, deployment_id,
                "Blue-Green: Validate Blue Environment",
                "blue_green_validate",
                {'phase': 'validate'}
            )

            health_ok = await self._health_check(blue_devices, executor, 60)

            if not health_ok:
                await self._update_task(db, validation_task, TaskStatus.FAILED.value,
                                      error="Blue environment validation failed")

                # Rollback blue environment
                await executor.rollback_devices(
                    [dc['device'] for dc in blue_devices],
                    deployment_id,
                    db
                )
                raise DeploymentFailed("Blue environment validation failed")

            await self._update_task(db, validation_task, TaskStatus.COMPLETED.value)

            # Phase 3: Switch traffic (simulated)
            logger.info("Phase 3: Switching traffic from green to blue")
            switch_task = await self._create_task(
                db, deployment_id,
                "Blue-Green: Switch Traffic",
                "blue_green_switch",
                {'phase': 'switch'}
            )

            # In real implementation, this would update load balancers, routing, etc.
            await asyncio.sleep(5)  # Simulate switch time

            await self._update_task(db, switch_task, TaskStatus.COMPLETED.value)

            # Phase 4: Deploy to green (now standby)
            if green_devices:
                logger.info("Phase 4: Deploying to green (now standby) environment")
                green_task = await self._create_task(
                    db, deployment_id,
                    "Blue-Green: Update Green Environment",
                    "blue_green_update_green",
                    {'phase': 'green', 'device_count': len(green_devices)}
                )

                green_result = await self._deploy_batch(
                    green_devices, executor, deployment_id, db,
                    "Green Environment"
                )

                result['devices'].extend(green_result['devices'])
                result['succeeded'] += green_result['succeeded']
                result['failed'] += green_result['failed']

                # Green failures are non-critical since blue is active
                if green_result['failed'] > 0:
                    logger.warning(f"Green deployment had {green_result['failed']} failures (non-critical)")

                await self._update_task(db, green_task, TaskStatus.COMPLETED.value, green_result)

        except Exception as e:
            logger.error(f"Blue-Green deployment failed: {e}")
            raise

        result['success'] = result['failed'] == 0 or (result['failed'] <= len(green_devices))
        return result


class AllAtOnceStrategy(DeploymentStrategy):
    """
    All-at-once deployment strategy
    Deploy to all devices simultaneously
    """

    async def execute(
        self,
        deployment_id: str,
        device_configs: List[Dict[str, Any]],
        executor: Any,
        db: AsyncSession
    ) -> Dict[str, Any]:
        """Execute all-at-once deployment"""

        total_devices = len(device_configs)
        logger.info(f"Starting all-at-once deployment for {total_devices} devices")

        # Create task
        task = await self._create_task(
            db, deployment_id,
            f"All-at-once Deployment",
            "all_at_once",
            {'device_count': total_devices}
        )

        try:
            # Deploy to all devices at once
            result = await self._deploy_batch(
                device_configs, executor, deployment_id, db,
                "All-at-once"
            )

            result['strategy'] = 'all_at_once'
            result['total_devices'] = total_devices
            result['success'] = result['failed'] == 0

            await self._update_task(db, task,
                                  TaskStatus.COMPLETED.value if result['success'] else TaskStatus.FAILED.value,
                                  result)

            return result

        except Exception as e:
            await self._update_task(db, task, TaskStatus.FAILED.value, error=str(e))
            raise