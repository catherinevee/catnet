"""
Health Monitoring Engine
Executes health checks, tracks SLAs, and manages alerts
"""
import asyncio
import structlog
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
import httpx
import socket
from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models.monitoring import (
    HealthCheck,
    HealthCheckResult,
    HealthCheckType,
    HealthStatus,
    SLA,
    SLAViolation,
    SLAMetric,
    SLAStatus,
    AlertRule,
    Alert,
    AlertStatus,
    AlertSeverity,
    MetricData
)
from ..db.session import get_db
from ..devices.secure_connector import secure_device_connector

logger = structlog.get_logger()


class HealthMonitor:
    """
    Health Monitoring Engine

    Executes various types of health checks, evaluates results,
    and triggers alerts based on configured rules.
    """

    def __init__(self):
        self.running_checks: Dict[str, asyncio.Task] = {}
        self.check_semaphore = asyncio.Semaphore(50)  # Max concurrent checks

    async def start_monitoring(self):
        """Start all enabled health checks"""
        logger.info("Starting health monitoring engine")

        async with get_db() as db:
            # Get all enabled health checks
            result = await db.execute(
                select(HealthCheck).filter(HealthCheck.enabled == True)
            )
            health_checks = result.scalars().all()

            logger.info(f"Starting {len(health_checks)} health checks")

            # Start each health check as background task
            for check in health_checks:
                task = asyncio.create_task(self._run_health_check_loop(check.id))
                self.running_checks[str(check.id)] = task

    async def stop_monitoring(self):
        """Stop all running health checks"""
        logger.info("Stopping health monitoring engine")

        for task in self.running_checks.values():
            task.cancel()

        # Wait for all tasks to complete
        await asyncio.gather(*self.running_checks.values(), return_exceptions=True)
        self.running_checks.clear()

    async def _run_health_check_loop(self, check_id: str):
        """Run health check on schedule"""
        while True:
            try:
                async with get_db() as db:
                    # Get health check configuration
                    result = await db.execute(
                        select(HealthCheck).filter(HealthCheck.id == check_id)
                    )
                    check = result.scalar_one_or_none()

                    if not check or not check.enabled:
                        logger.info(f"Health check {check_id} disabled or deleted")
                        break

                    # Execute check
                    async with self.check_semaphore:
                        await self.execute_health_check(check, db)

                    # Wait for next interval
                    await asyncio.sleep(check.interval_seconds)

            except asyncio.CancelledError:
                logger.info(f"Health check {check_id} cancelled")
                break
            except Exception as e:
                logger.error(f"Error in health check loop {check_id}: {e}")
                await asyncio.sleep(60)  # Wait before retry

    async def execute_health_check(
        self,
        check: HealthCheck,
        db: AsyncSession
    ) -> HealthCheckResult:
        """Execute a single health check"""
        start_time = datetime.utcnow()
        logger.debug(f"Executing health check: {check.name}")

        try:
            # Execute check based on type
            if check.check_type == HealthCheckType.HTTP:
                status, response_data, error = await self._check_http(check)
            elif check.check_type == HealthCheckType.TCP:
                status, response_data, error = await self._check_tcp(check)
            elif check.check_type == HealthCheckType.ICMP:
                status, response_data, error = await self._check_icmp(check)
            elif check.check_type == HealthCheckType.SSH:
                status, response_data, error = await self._check_ssh(check)
            elif check.check_type == HealthCheckType.SNMP:
                status, response_data, error = await self._check_snmp(check)
            elif check.check_type == HealthCheckType.NETCONF:
                status, response_data, error = await self._check_netconf(check)
            elif check.check_type == HealthCheckType.CUSTOM:
                status, response_data, error = await self._check_custom(check)
            else:
                status = HealthStatus.UNKNOWN
                response_data = {}
                error = f"Unsupported check type: {check.check_type}"

            duration = (datetime.utcnow() - start_time).total_seconds() * 1000
            success = status == HealthStatus.HEALTHY

            # Create result record
            result = HealthCheckResult(
                health_check_id=check.id,
                executed_at=start_time,
                duration_ms=duration,
                status=status,
                success=success,
                response_data=response_data,
                error_message=error,
                response_time_ms=response_data.get("response_time_ms")
            )

            db.add(result)

            # Update health check status
            await self._update_health_check_status(check, success, db)

            # Evaluate alert rules
            await self._evaluate_alert_rules(check, result, db)

            await db.commit()

            logger.info(
                f"Health check completed: {check.name}",
                status=status.value,
                duration_ms=duration
            )

            return result

        except Exception as e:
            duration = (datetime.utcnow() - start_time).total_seconds() * 1000
            logger.error(f"Health check execution failed: {check.name}", error=str(e))

            result = HealthCheckResult(
                health_check_id=check.id,
                executed_at=start_time,
                duration_ms=duration,
                status=HealthStatus.UNKNOWN,
                success=False,
                error_message=str(e)
            )

            db.add(result)
            await self._update_health_check_status(check, False, db)
            await db.commit()

            return result

    async def _check_http(self, check: HealthCheck) -> Tuple[HealthStatus, Dict, Optional[str]]:
        """Execute HTTP health check"""
        config = check.check_config or {}
        method = config.get("method", "GET")
        headers = config.get("headers", {})
        expected_status = config.get("expected_status", 200)
        expected_body = config.get("expected_body")

        try:
            async with httpx.AsyncClient(timeout=check.timeout_seconds) as client:
                start = datetime.utcnow()

                if method == "GET":
                    response = await client.get(check.target, headers=headers)
                elif method == "POST":
                    response = await client.post(check.target, headers=headers, json=config.get("body"))
                else:
                    return HealthStatus.UNKNOWN, {}, f"Unsupported HTTP method: {method}"

                response_time = (datetime.utcnow() - start).total_seconds() * 1000

                # Check status code
                if response.status_code != expected_status:
                    return HealthStatus.UNHEALTHY, {
                        "status_code": response.status_code,
                        "response_time_ms": response_time
                    }, f"Unexpected status code: {response.status_code}"

                # Check response body if expected
                if expected_body and expected_body not in response.text:
                    return HealthStatus.UNHEALTHY, {
                        "status_code": response.status_code,
                        "response_time_ms": response_time
                    }, "Expected body content not found"

                return HealthStatus.HEALTHY, {
                    "status_code": response.status_code,
                    "response_time_ms": response_time,
                    "body_length": len(response.text)
                }, None

        except httpx.TimeoutException:
            return HealthStatus.UNHEALTHY, {}, "Request timeout"
        except Exception as e:
            return HealthStatus.UNHEALTHY, {}, str(e)

    async def _check_tcp(self, check: HealthCheck) -> Tuple[HealthStatus, Dict, Optional[str]]:
        """Execute TCP port check"""
        config = check.check_config or {}

        try:
            host, port = check.target.split(":")
            port = int(port)

            start = datetime.utcnow()

            # Try to connect to TCP port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(check.timeout_seconds)

            result = sock.connect_ex((host, port))
            sock.close()

            response_time = (datetime.utcnow() - start).total_seconds() * 1000

            if result == 0:
                return HealthStatus.HEALTHY, {
                    "response_time_ms": response_time,
                    "port_open": True
                }, None
            else:
                return HealthStatus.UNHEALTHY, {
                    "response_time_ms": response_time,
                    "port_open": False
                }, f"Port {port} not accessible"

        except Exception as e:
            return HealthStatus.UNHEALTHY, {}, str(e)

    async def _check_icmp(self, check: HealthCheck) -> Tuple[HealthStatus, Dict, Optional[str]]:
        """Execute ICMP ping check"""
        try:
            # Use system ping command
            import subprocess

            start = datetime.utcnow()

            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(check.timeout_seconds), check.target],
                capture_output=True,
                text=True
            )

            response_time = (datetime.utcnow() - start).total_seconds() * 1000

            if result.returncode == 0:
                return HealthStatus.HEALTHY, {
                    "response_time_ms": response_time,
                    "reachable": True
                }, None
            else:
                return HealthStatus.UNHEALTHY, {
                    "response_time_ms": response_time,
                    "reachable": False
                }, "Host not reachable"

        except Exception as e:
            return HealthStatus.UNHEALTHY, {}, str(e)

    async def _check_ssh(self, check: HealthCheck) -> Tuple[HealthStatus, Dict, Optional[str]]:
        """Execute SSH connectivity check"""
        config = check.check_config or {}
        command = config.get("command", "show version")

        try:
            start = datetime.utcnow()

            # Use secure connector to connect and execute command
            connection = await secure_device_connector.connect_device({
                "ip_address": check.target,
                "vendor": config.get("vendor", "cisco_ios")
            })

            if connection:
                output = await connection.send_command(command)
                response_time = (datetime.utcnow() - start).total_seconds() * 1000

                return HealthStatus.HEALTHY, {
                    "response_time_ms": response_time,
                    "output_length": len(output)
                }, None
            else:
                return HealthStatus.UNHEALTHY, {}, "Failed to connect"

        except Exception as e:
            return HealthStatus.UNHEALTHY, {}, str(e)

    async def _check_snmp(self, check: HealthCheck) -> Tuple[HealthStatus, Dict, Optional[str]]:
        """Execute SNMP check"""
        config = check.check_config or {}
        oid = config.get("oid", "1.3.6.1.2.1.1.1.0")  # sysDescr

        try:
            # Implement SNMP check using pysnmp or similar
            # For now, return placeholder
            return HealthStatus.HEALTHY, {"oid": oid}, None

        except Exception as e:
            return HealthStatus.UNHEALTHY, {}, str(e)

    async def _check_netconf(self, check: HealthCheck) -> Tuple[HealthStatus, Dict, Optional[str]]:
        """Execute NETCONF check"""
        try:
            # Implement NETCONF check using ncclient or similar
            # For now, return placeholder
            return HealthStatus.HEALTHY, {}, None

        except Exception as e:
            return HealthStatus.UNHEALTHY, {}, str(e)

    async def _check_custom(self, check: HealthCheck) -> Tuple[HealthStatus, Dict, Optional[str]]:
        """Execute custom health check"""
        config = check.check_config or {}

        # Custom checks can execute Python code or scripts
        # Implement based on requirements

        return HealthStatus.UNKNOWN, {}, "Custom checks not implemented"

    async def _update_health_check_status(
        self,
        check: HealthCheck,
        success: bool,
        db: AsyncSession
    ):
        """Update health check status based on result"""
        if success:
            check.consecutive_successes += 1
            check.consecutive_failures = 0

            # Check if we've reached success threshold
            if check.consecutive_successes >= check.success_threshold:
                check.current_status = HealthStatus.HEALTHY

        else:
            check.consecutive_failures += 1
            check.consecutive_successes = 0

            # Check if we've reached failure threshold
            if check.consecutive_failures >= check.failure_threshold:
                check.current_status = HealthStatus.UNHEALTHY
            else:
                check.current_status = HealthStatus.DEGRADED

        check.last_check_at = datetime.utcnow()
        await db.commit()

    async def _evaluate_alert_rules(
        self,
        check: HealthCheck,
        result: HealthCheckResult,
        db: AsyncSession
    ):
        """Evaluate alert rules for health check result"""
        # Get all alert rules for this health check
        query = await db.execute(
            select(AlertRule).filter(
                and_(
                    AlertRule.health_check_id == check.id,
                    AlertRule.enabled == True
                )
            )
        )
        alert_rules = query.scalars().all()

        for rule in alert_rules:
            await self._evaluate_alert_rule(rule, check, result, db)

    async def _evaluate_alert_rule(
        self,
        rule: AlertRule,
        check: HealthCheck,
        result: HealthCheckResult,
        db: AsyncSession
    ):
        """Evaluate single alert rule"""
        # Check if status matches trigger conditions
        if rule.trigger_on_statuses and result.status.value not in rule.trigger_on_statuses:
            return

        # Check cooldown period
        if rule.last_triggered_at:
            cooldown_end = rule.last_triggered_at + timedelta(minutes=rule.cooldown_minutes)
            if datetime.utcnow() < cooldown_end:
                logger.debug(f"Alert rule {rule.name} in cooldown period")
                return

        # Check rate limit
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        recent_alerts = await db.execute(
            select(Alert).filter(
                and_(
                    Alert.alert_rule_id == rule.id,
                    Alert.triggered_at >= one_hour_ago
                )
            )
        )
        if len(recent_alerts.scalars().all()) >= rule.max_alerts_per_hour:
            logger.warning(f"Alert rule {rule.name} rate limit exceeded")
            return

        # Create alert
        alert = Alert(
            alert_rule_id=rule.id,
            severity=rule.severity,
            title=f"Health Check Alert: {check.name}",
            message=rule.message_template.format(
                check_name=check.name,
                status=result.status.value,
                error=result.error_message or "N/A"
            ),
            trigger_value={"status": result.status.value},
            trigger_context={
                "check_id": str(check.id),
                "result_id": str(result.id),
                "duration_ms": result.duration_ms
            }
        )

        db.add(alert)

        rule.last_triggered_at = datetime.utcnow()
        rule.trigger_count += 1

        await db.commit()

        logger.info(
            f"Alert triggered: {rule.name}",
            severity=rule.severity.value,
            check=check.name
        )

        # TODO: Send notifications through configured channels


class SLAMonitor:
    """
    SLA Monitoring and Tracking

    Evaluates SLA compliance and triggers violations
    """

    async def evaluate_slas(self):
        """Evaluate all active SLAs"""
        logger.info("Evaluating SLAs")

        async with get_db() as db:
            result = await db.execute(
                select(SLA).filter(SLA.enabled == True)
            )
            slas = result.scalars().all()

            for sla in slas:
                await self._evaluate_sla(sla, db)

    async def _evaluate_sla(self, sla: SLA, db: AsyncSession):
        """Evaluate single SLA"""
        window_start = datetime.utcnow() - timedelta(hours=sla.measurement_window_hours)

        # Calculate metrics from health check results or metric data
        # This is a simplified implementation

        # Get metric data for the time window
        result = await db.execute(
            select(MetricData).filter(
                and_(
                    MetricData.source_id == sla.target_id,
                    MetricData.timestamp >= window_start
                )
            )
        )
        metrics = result.scalars().all()

        if not metrics:
            logger.debug(f"No metrics found for SLA: {sla.name}")
            return

        # Calculate availability
        total_checks = len(metrics)
        successful_checks = sum(1 for m in metrics if m.value > 0)
        availability = (successful_checks / total_checks * 100) if total_checks > 0 else 100.0

        # Calculate average response time
        response_times = [m.value for m in metrics if m.metric_type == "response_time"]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0

        # Update SLA metrics
        sla.current_availability = availability
        sla.current_response_time_ms = avg_response_time
        sla.last_evaluated_at = datetime.utcnow()

        # Check for violations
        violation = False
        violation_type = None

        if sla.availability_target and availability < sla.availability_target:
            violation = True
            violation_type = "availability"
            sla.compliance_status = SLAStatus.VIOLATED
        elif sla.response_time_target_ms and avg_response_time > sla.response_time_target_ms:
            violation = True
            violation_type = "response_time"
            sla.compliance_status = SLAStatus.VIOLATED
        else:
            sla.compliance_status = SLAStatus.COMPLIANT

        # Create SLA metric record
        metric_record = SLAMetric(
            sla_id=sla.id,
            availability=availability,
            response_time_ms=avg_response_time,
            compliant=not violation
        )
        db.add(metric_record)

        # Create violation record if needed
        if violation:
            sla_violation = SLAViolation(
                sla_id=sla.id,
                violation_type=violation_type,
                actual_value=availability if violation_type == "availability" else avg_response_time,
                target_value=sla.availability_target if violation_type == "availability" else sla.response_time_target_ms,
                severity=AlertSeverity.HIGH
            )
            db.add(sla_violation)

            sla.last_violation_at = datetime.utcnow()
            sla.violation_count += 1

            logger.warning(
                f"SLA violation detected: {sla.name}",
                type=violation_type,
                actual=sla_violation.actual_value,
                target=sla_violation.target_value
            )

        await db.commit()


# Singleton instances
health_monitor = HealthMonitor()
sla_monitor = SLAMonitor()
