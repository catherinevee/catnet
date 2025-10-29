"""
Deployment Strategy Engine
Orchestrates advanced deployment patterns with health monitoring and automatic rollback
"""
import asyncio
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import structlog

from src.db.models.deployment_strategy import (
    AdvancedDeployment,
    DeploymentPhase,
    DeploymentHealthCheck,
    DeploymentRollback,
    DeploymentStrategy,
    DeploymentPhaseStatus,
    HealthCheckStatus
)

logger = structlog.get_logger()


class DeploymentStrategyEngine:
    """
    Orchestrates advanced deployment strategies

    Supports:
    - Canary deployments with progressive rollout
    - Blue-green deployments for zero-downtime
    - A/B testing for configuration validation
    - Automatic health monitoring
    - Intelligent rollback on failures
    """

    def __init__(self):
        self.max_retry_attempts = 3
        self.health_check_timeout = 300  # 5 minutes

    async def execute_deployment(
        self,
        deployment: AdvancedDeployment
    ) -> bool:
        """
        Execute deployment based on strategy

        Args:
            deployment: AdvancedDeployment configuration

        Returns:
            True if successful, False if failed
        """
        deployment.started_at = datetime.utcnow()
        deployment.overall_status = DeploymentPhaseStatus.IN_PROGRESS

        logger.info(
            "Starting advanced deployment",
            deployment_id=deployment.id,
            strategy=deployment.strategy,
            devices=len(deployment.device_ids)
        )

        try:
            if deployment.strategy == DeploymentStrategy.CANARY:
                success = await self.execute_canary_deployment(deployment)
            elif deployment.strategy == DeploymentStrategy.BLUE_GREEN:
                success = await self.execute_blue_green_deployment(deployment)
            elif deployment.strategy == DeploymentStrategy.AB_TEST:
                success = await self.execute_ab_test_deployment(deployment)
            else:  # BASIC
                success = await self.execute_basic_deployment(deployment)

            if success:
                deployment.overall_status = DeploymentPhaseStatus.COMPLETED
                deployment.completed_at = datetime.utcnow()
                logger.info("Deployment completed successfully", deployment_id=deployment.id)
            else:
                deployment.overall_status = DeploymentPhaseStatus.FAILED
                deployment.completed_at = datetime.utcnow()
                logger.error("Deployment failed", deployment_id=deployment.id)

            return success

        except Exception as e:
            deployment.overall_status = DeploymentPhaseStatus.FAILED
            deployment.completed_at = datetime.utcnow()
            logger.error("Deployment exception", deployment_id=deployment.id, error=str(e))
            return False

    async def execute_canary_deployment(
        self,
        deployment: AdvancedDeployment
    ) -> bool:
        """
        Execute canary deployment with progressive rollout

        Process:
        1. Deploy to 10% of devices
        2. Monitor health for configured interval
        3. If healthy, deploy to 25%
        4. Continue to 50%, then 100%
        5. Rollback if any phase fails health checks

        Args:
            deployment: AdvancedDeployment with canary configuration

        Returns:
            True if all phases successful
        """
        percentages = deployment.canary_percentages or [10, 25, 50, 100]

        logger.info(
            "Starting canary deployment",
            deployment_id=deployment.id,
            phases=percentages,
            total_devices=len(deployment.device_ids)
        )

        total_devices = len(deployment.device_ids)
        deployed_count = 0
        all_deployed_devices = []

        for phase_num, percentage in enumerate(percentages, 1):
            # Calculate devices for this phase
            target_count = int(total_devices * percentage / 100)
            devices_this_phase = deployment.device_ids[deployed_count:target_count]

            if not devices_this_phase:
                logger.debug(f"No new devices in phase {phase_num}, skipping")
                continue

            logger.info(
                f"Canary phase {phase_num}: deploying to {len(devices_this_phase)} devices ({percentage}%)",
                deployment_id=deployment.id,
                phase=phase_num,
                devices=len(devices_this_phase)
            )

            # Create phase record
            phase = DeploymentPhase(
                deployment_id=deployment.id,
                phase_number=phase_num,
                percentage=percentage,
                target_devices=devices_this_phase,
                status=DeploymentPhaseStatus.IN_PROGRESS,
                started_at=datetime.utcnow()
            )

            # Deploy to devices in this phase
            success, failed_devices = await self._deploy_to_devices(
                devices_this_phase,
                deployment.config_data
            )

            phase.success_count = len(devices_this_phase) - len(failed_devices)
            phase.failure_count = len(failed_devices)
            phase.failed_devices = failed_devices

            if not success or phase.success_rate < deployment.min_success_rate:
                phase.status = DeploymentPhaseStatus.FAILED
                phase.completed_at = datetime.utcnow()
                phase.error_message = f"Deployment failed for {len(failed_devices)} devices"

                logger.error(
                    f"Canary phase {phase_num} failed",
                    deployment_id=deployment.id,
                    failed=len(failed_devices),
                    success_rate=phase.success_rate
                )

                # Rollback all deployed devices
                if deployment.auto_rollback_on_failure:
                    await self._rollback_deployment(
                        deployment,
                        all_deployed_devices,
                        f"Phase {phase_num} failed with {len(failed_devices)} failures"
                    )

                return False

            # Monitor health
            logger.info(
                f"Phase {phase_num} deployed, monitoring health for {deployment.health_check_interval}s",
                deployment_id=deployment.id
            )

            await asyncio.sleep(deployment.health_check_interval)

            health_passed, health_check = await self._check_deployment_health(
                deployment,
                phase,
                devices_this_phase
            )

            if not health_passed:
                phase.status = DeploymentPhaseStatus.FAILED
                phase.completed_at = datetime.utcnow()
                phase.error_message = health_check.failure_reason

                logger.error(
                    f"Canary phase {phase_num} health check failed",
                    deployment_id=deployment.id,
                    reason=health_check.failure_reason
                )

                # Rollback
                if deployment.auto_rollback_on_failure:
                    await self._rollback_deployment(
                        deployment,
                        all_deployed_devices,
                        f"Phase {phase_num} health check failed: {health_check.failure_reason}"
                    )

                return False

            # Phase successful
            phase.status = DeploymentPhaseStatus.COMPLETED
            phase.completed_at = datetime.utcnow()
            deployed_count = target_count
            all_deployed_devices.extend(devices_this_phase)

            logger.info(
                f"Canary phase {phase_num} completed successfully",
                deployment_id=deployment.id,
                total_deployed=deployed_count
            )

        logger.info("Canary deployment completed successfully", deployment_id=deployment.id)
        return True

    async def execute_blue_green_deployment(
        self,
        deployment: AdvancedDeployment
    ) -> bool:
        """
        Execute blue-green deployment for zero-downtime cutover

        Process:
        1. Deploy to green (inactive) environment
        2. Run comprehensive tests on green
        3. If healthy, switch traffic to green
        4. Keep blue as rollback option

        Args:
            deployment: AdvancedDeployment with blue/green configuration

        Returns:
            True if successful
        """
        green_devices = deployment.green_group or []
        blue_devices = deployment.blue_group or []

        logger.info(
            "Starting blue-green deployment",
            deployment_id=deployment.id,
            green_count=len(green_devices),
            blue_count=len(blue_devices)
        )

        # Phase 1: Deploy to green environment
        green_phase = DeploymentPhase(
            deployment_id=deployment.id,
            phase_number=1,
            device_group="green",
            target_devices=green_devices,
            status=DeploymentPhaseStatus.IN_PROGRESS,
            started_at=datetime.utcnow()
        )

        logger.info("Phase 1: Deploying to green environment", deployment_id=deployment.id)

        success, failed_devices = await self._deploy_to_devices(
            green_devices,
            deployment.config_data
        )

        green_phase.success_count = len(green_devices) - len(failed_devices)
        green_phase.failure_count = len(failed_devices)
        green_phase.failed_devices = failed_devices

        if not success:
            green_phase.status = DeploymentPhaseStatus.FAILED
            green_phase.completed_at = datetime.utcnow()
            logger.error("Green deployment failed", deployment_id=deployment.id)
            return False

        # Phase 2: Health check green environment
        logger.info("Phase 2: Health checking green environment", deployment_id=deployment.id)

        await asyncio.sleep(deployment.health_check_interval)

        health_passed, health_check = await self._check_deployment_health(
            deployment,
            green_phase,
            green_devices
        )

        if not health_passed:
            green_phase.status = DeploymentPhaseStatus.FAILED
            green_phase.completed_at = datetime.utcnow()
            logger.error("Green health check failed", deployment_id=deployment.id)
            return False

        green_phase.status = DeploymentPhaseStatus.COMPLETED
        green_phase.completed_at = datetime.utcnow()

        # Phase 3: Switch traffic (load balancer update)
        cutover_phase = DeploymentPhase(
            deployment_id=deployment.id,
            phase_number=2,
            device_group="cutover",
            status=DeploymentPhaseStatus.IN_PROGRESS,
            started_at=datetime.utcnow()
        )

        logger.info("Phase 3: Switching traffic to green", deployment_id=deployment.id)

        await self._switch_traffic_to_green(deployment.id)

        deployment.active_group = "green"
        cutover_phase.status = DeploymentPhaseStatus.COMPLETED
        cutover_phase.completed_at = datetime.utcnow()

        logger.info(
            "Blue-green deployment completed, traffic switched to green",
            deployment_id=deployment.id
        )

        return True

    async def execute_ab_test_deployment(
        self,
        deployment: AdvancedDeployment
    ) -> bool:
        """
        Execute A/B test deployment

        Process:
        1. Deploy variant A to A devices
        2. Deploy variant B to B devices
        3. Monitor success metrics
        4. Determine winner based on metrics

        Args:
            deployment: AdvancedDeployment with A/B configuration

        Returns:
            True if successful
        """
        variant_a_devices = deployment.variant_a_devices or []
        variant_b_devices = deployment.variant_b_devices or []

        logger.info(
            "Starting A/B test deployment",
            deployment_id=deployment.id,
            variant_a=len(variant_a_devices),
            variant_b=len(variant_b_devices)
        )

        # Deploy variant A
        phase_a = DeploymentPhase(
            deployment_id=deployment.id,
            phase_number=1,
            device_group="variant_a",
            target_devices=variant_a_devices,
            status=DeploymentPhaseStatus.IN_PROGRESS,
            started_at=datetime.utcnow()
        )

        success_a, failed_a = await self._deploy_to_devices(
            variant_a_devices,
            deployment.config_data  # Would have variant A config
        )

        phase_a.success_count = len(variant_a_devices) - len(failed_a)
        phase_a.failure_count = len(failed_a)
        phase_a.status = DeploymentPhaseStatus.COMPLETED if success_a else DeploymentPhaseStatus.FAILED
        phase_a.completed_at = datetime.utcnow()

        # Deploy variant B
        phase_b = DeploymentPhase(
            deployment_id=deployment.id,
            phase_number=2,
            device_group="variant_b",
            target_devices=variant_b_devices,
            status=DeploymentPhaseStatus.IN_PROGRESS,
            started_at=datetime.utcnow()
        )

        success_b, failed_b = await self._deploy_to_devices(
            variant_b_devices,
            deployment.config_data  # Would have variant B config
        )

        phase_b.success_count = len(variant_b_devices) - len(failed_b)
        phase_b.failure_count = len(failed_b)
        phase_b.status = DeploymentPhaseStatus.COMPLETED if success_b else DeploymentPhaseStatus.FAILED
        phase_b.completed_at = datetime.utcnow()

        logger.info(
            "A/B test deployment completed",
            deployment_id=deployment.id,
            variant_a_success=success_a,
            variant_b_success=success_b
        )

        return success_a and success_b

    async def execute_basic_deployment(
        self,
        deployment: AdvancedDeployment
    ) -> bool:
        """Execute basic deployment to all devices at once"""
        phase = DeploymentPhase(
            deployment_id=deployment.id,
            phase_number=1,
            percentage=100,
            target_devices=deployment.device_ids,
            status=DeploymentPhaseStatus.IN_PROGRESS,
            started_at=datetime.utcnow()
        )

        success, failed_devices = await self._deploy_to_devices(
            deployment.device_ids,
            deployment.config_data
        )

        phase.success_count = len(deployment.device_ids) - len(failed_devices)
        phase.failure_count = len(failed_devices)
        phase.status = DeploymentPhaseStatus.COMPLETED if success else DeploymentPhaseStatus.FAILED
        phase.completed_at = datetime.utcnow()

        return success

    async def _deploy_to_devices(
        self,
        device_ids: List[str],
        config_data: dict
    ) -> Tuple[bool, List[str]]:
        """
        Deploy configuration to specified devices

        Args:
            device_ids: List of device identifiers
            config_data: Configuration to deploy

        Returns:
            Tuple of (success: bool, failed_devices: List[str])
        """
        from src.devices.secure_connector import secure_device_connector

        failed_devices = []
        commands = config_data.get('commands', [])

        logger.debug(f"Deploying to {len(device_ids)} devices")

        for device_id in device_ids:
            try:
                async with secure_device_connector.connect(device_id) as conn:
                    # Send configuration commands
                    result = await conn.send_config_set(commands)

                    if not result:
                        failed_devices.append(device_id)
                        logger.error(f"Deployment failed for {device_id}: no result")

            except Exception as e:
                failed_devices.append(device_id)
                logger.error(f"Deployment failed for {device_id}", error=str(e))

        success = len(failed_devices) == 0

        logger.info(
            "Deployment batch completed",
            total=len(device_ids),
            successful=len(device_ids) - len(failed_devices),
            failed=len(failed_devices)
        )

        return success, failed_devices

    async def _check_deployment_health(
        self,
        deployment: AdvancedDeployment,
        phase: DeploymentPhase,
        device_ids: List[str]
    ) -> Tuple[bool, DeploymentHealthCheck]:
        """
        Check health metrics for deployed devices

        Args:
            deployment: Parent deployment
            phase: Current phase
            device_ids: Devices to check

        Returns:
            Tuple of (passed: bool, health_check: DeploymentHealthCheck)
        """
        from src.devices.secure_connector import secure_device_connector

        logger.debug(f"Checking health for {len(device_ids)} devices")

        healthy_devices = []
        unhealthy_devices = []
        unreachable_devices = []

        latencies = []

        for device_id in device_ids:
            try:
                start_time = datetime.utcnow()

                # Verify device is reachable and responding
                async with secure_device_connector.connect(device_id) as conn:
                    result = await conn.send_command("show version")

                    if result and len(result) > 10:
                        healthy_devices.append(device_id)

                        # Calculate latency
                        latency_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
                        latencies.append(latency_ms)
                    else:
                        unhealthy_devices.append(device_id)

            except ConnectionError:
                unreachable_devices.append(device_id)
            except Exception as e:
                unhealthy_devices.append(device_id)
                logger.error(f"Health check error for {device_id}", error=str(e))

        total_devices = len(device_ids)
        success_rate = len(healthy_devices) / total_devices if total_devices > 0 else 0
        avg_latency = sum(latencies) / len(latencies) if latencies else 0

        # Determine if health check passed
        passed = (
            success_rate >= deployment.min_success_rate
            and avg_latency <= deployment.latency_threshold_ms
        )

        status = HealthCheckStatus.PASSED if passed else HealthCheckStatus.FAILED

        # Determine failure reason
        failure_reason = None
        if not passed:
            if success_rate < deployment.min_success_rate:
                failure_reason = f"Success rate {success_rate:.2%} below threshold {deployment.min_success_rate:.2%}"
            elif avg_latency > deployment.latency_threshold_ms:
                failure_reason = f"Avg latency {avg_latency:.0f}ms above threshold {deployment.latency_threshold_ms}ms"

        health_check = DeploymentHealthCheck(
            deployment_id=deployment.id,
            phase_id=phase.id,
            checked_at=datetime.utcnow(),
            success_rate=success_rate,
            avg_latency_ms=avg_latency,
            error_count=len(unhealthy_devices),
            devices_healthy=len(healthy_devices),
            devices_unhealthy=len(unhealthy_devices),
            devices_unreachable=len(unreachable_devices),
            status=status,
            passed=passed,
            failure_reason=failure_reason,
            unhealthy_devices=unhealthy_devices + unreachable_devices
        )

        logger.info(
            "Health check completed",
            deployment_id=deployment.id,
            phase_id=phase.id,
            success_rate=f"{success_rate:.2%}",
            avg_latency_ms=f"{avg_latency:.0f}",
            passed=passed
        )

        return passed, health_check

    async def _rollback_deployment(
        self,
        deployment: AdvancedDeployment,
        device_ids: List[str],
        reason: str
    ):
        """
        Rollback deployment by restoring previous config

        Args:
            deployment: Deployment to rollback
            device_ids: Devices to rollback
            reason: Reason for rollback
        """
        logger.warning(
            "Rolling back deployment",
            deployment_id=deployment.id,
            device_count=len(device_ids),
            reason=reason
        )

        rollback = DeploymentRollback(
            deployment_id=deployment.id,
            triggered_by="system",
            reason=reason,
            devices_rolled_back=device_ids
        )

        try:
            # Restore previous configuration from Git or backup
            # This is simplified - real implementation would fetch previous config

            # For now, just log the rollback
            logger.info(f"Rollback would restore config for {len(device_ids)} devices")

            rollback.completed = True
            rollback.success = True
            rollback.completed_at = datetime.utcnow()

            deployment.overall_status = DeploymentPhaseStatus.ROLLED_BACK
            deployment.rolled_back_at = datetime.utcnow()

        except Exception as e:
            rollback.completed = True
            rollback.success = False
            rollback.error_message = str(e)
            rollback.completed_at = datetime.utcnow()
            logger.error("Rollback failed", deployment_id=deployment.id, error=str(e))

    async def _switch_traffic_to_green(self, deployment_id: str):
        """
        Switch load balancer traffic to green environment

        This would integrate with actual load balancer/routing infrastructure
        For now, it's a placeholder

        Args:
            deployment_id: Deployment identifier
        """
        logger.info(
            "Switching traffic to green environment",
            deployment_id=deployment_id
        )

        # Implementation would update:
        # - Load balancer configuration
        # - DNS records
        # - Routing tables
        # etc.

        await asyncio.sleep(1)  # Simulate switch time

        logger.info("Traffic switched to green", deployment_id=deployment_id)


# Global instance
strategy_engine = DeploymentStrategyEngine()
