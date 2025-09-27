"""
Specialized metrics collectors for different subsystems.
Provides targeted metric collection for various CatNet components.
"""

import asyncio
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from uuid import UUID

from src.monitoring.metrics import MetricsCollector
from src.db.models import Device, Deployment, HealthCheck, User
from src.core.exceptions import MetricsError
from src.security.audit import AuditLogger


class SystemMetricsCollector:
    """
    Collects system-level metrics.
    Monitors CPU, memory, disk, network, and process metrics.
    """

    def __init__(self, metrics_collector: MetricsCollector):
        """
        Initialize system metrics collector.

        Args:
            metrics_collector: Main metrics collector instance
        """
        self.metrics = metrics_collector
        self.audit = AuditLogger()
        self._collection_interval = 60  # seconds
        self._running = False

    async def start_collection(self):
        """Start periodic metric collection."""
        self._running = True
        while self._running:
            try:
                await self.collect()
                await asyncio.sleep(self._collection_interval)
            except Exception as e:
                await self.audit.log_event(
                    event_type="SYSTEM_METRICS_ERROR",
                    details={'error': str(e)}
                )
                await asyncio.sleep(self._collection_interval)

    async def stop_collection(self):
        """Stop metric collection."""
        self._running = False

    async def collect(self):
        """Collect system metrics once."""
        import psutil

        try:
            # CPU metrics
            cpu_count = psutil.cpu_count()
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_freq = psutil.cpu_freq()

            self.metrics.gauge("catnet_system_cpu_count").set(cpu_count)
            self.metrics.gauge("catnet_system_cpu_usage_percent").set(cpu_percent)
            if cpu_freq:
                self.metrics.gauge("catnet_system_cpu_frequency_mhz").set(cpu_freq.current)

            # Per-CPU metrics
            cpu_percent_per_core = psutil.cpu_percent(interval=0.1, percpu=True)
            for i, percent in enumerate(cpu_percent_per_core):
                self.metrics.gauge("catnet_system_cpu_core_usage_percent").set(
                    percent,
                    labels={"core": str(i)}
                )

            # Memory metrics
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()

            self.metrics.gauge("catnet_system_memory_total_bytes").set(memory.total)
            self.metrics.gauge("catnet_system_memory_available_bytes").set(memory.available)
            self.metrics.gauge("catnet_system_memory_used_bytes").set(memory.used)
            self.metrics.gauge("catnet_system_memory_free_bytes").set(memory.free)
            self.metrics.gauge("catnet_system_memory_usage_percent").set(memory.percent)

            self.metrics.gauge("catnet_system_swap_total_bytes").set(swap.total)
            self.metrics.gauge("catnet_system_swap_used_bytes").set(swap.used)
            self.metrics.gauge("catnet_system_swap_free_bytes").set(swap.free)
            self.metrics.gauge("catnet_system_swap_usage_percent").set(swap.percent)

            # Disk metrics
            for partition in psutil.disk_partitions():
                if partition.fstype:
                    try:
                        usage = psutil.disk_usage(partition.mountpoint)
                        labels = {
                            "mount_point": partition.mountpoint,
                            "device": partition.device,
                            "fstype": partition.fstype
                        }

                        self.metrics.gauge("catnet_system_disk_total_bytes").set(usage.total, labels=labels)
                        self.metrics.gauge("catnet_system_disk_used_bytes").set(usage.used, labels=labels)
                        self.metrics.gauge("catnet_system_disk_free_bytes").set(usage.free, labels=labels)
                        self.metrics.gauge("catnet_system_disk_usage_percent").set(usage.percent, labels=labels)
                    except:
                        pass

            # Disk I/O metrics
            disk_io = psutil.disk_io_counters()
            if disk_io:
                self.metrics.counter("catnet_system_disk_read_bytes_total").inc(disk_io.read_bytes)
                self.metrics.counter("catnet_system_disk_write_bytes_total").inc(disk_io.write_bytes)
                self.metrics.counter("catnet_system_disk_read_count_total").inc(disk_io.read_count)
                self.metrics.counter("catnet_system_disk_write_count_total").inc(disk_io.write_count)

            # Network metrics
            net_io = psutil.net_io_counters()
            self.metrics.counter("catnet_system_network_bytes_sent_total").inc(net_io.bytes_sent)
            self.metrics.counter("catnet_system_network_bytes_recv_total").inc(net_io.bytes_recv)
            self.metrics.counter("catnet_system_network_packets_sent_total").inc(net_io.packets_sent)
            self.metrics.counter("catnet_system_network_packets_recv_total").inc(net_io.packets_recv)
            self.metrics.counter("catnet_system_network_errors_in_total").inc(net_io.errin)
            self.metrics.counter("catnet_system_network_errors_out_total").inc(net_io.errout)
            self.metrics.counter("catnet_system_network_drop_in_total").inc(net_io.dropin)
            self.metrics.counter("catnet_system_network_drop_out_total").inc(net_io.dropout)

            # Per-interface metrics
            net_if_stats = psutil.net_if_stats()
            for interface, stats in net_if_stats.items():
                labels = {"interface": interface}
                self.metrics.gauge("catnet_system_network_interface_up").set(
                    1 if stats.isup else 0,
                    labels=labels
                )
                self.metrics.gauge("catnet_system_network_interface_speed_mbps").set(
                    stats.speed,
                    labels=labels
                )

            # System load
            load = psutil.getloadavg()
            self.metrics.gauge("catnet_system_load_1min").set(load[0])
            self.metrics.gauge("catnet_system_load_5min").set(load[1])
            self.metrics.gauge("catnet_system_load_15min").set(load[2])

            # System uptime
            boot_time = psutil.boot_time()
            uptime = time.time() - boot_time
            self.metrics.gauge("catnet_system_uptime_seconds").set(uptime)

            # Process metrics
            process = psutil.Process()
            self.metrics.gauge("catnet_process_cpu_percent").set(process.cpu_percent())
            self.metrics.gauge("catnet_process_memory_rss_bytes").set(process.memory_info().rss)
            self.metrics.gauge("catnet_process_memory_vms_bytes").set(process.memory_info().vms)
            self.metrics.gauge("catnet_process_open_files_count").set(len(process.open_files()))
            self.metrics.gauge("catnet_process_num_threads").set(process.num_threads())
            self.metrics.gauge("catnet_process_num_fds").set(process.num_fds())

        except Exception as e:
            raise MetricsError(f"Failed to collect system metrics: {e}")


class DeviceMetricsCollector:
    """
    Collects device-related metrics.
    Monitors device health, connectivity, and configuration status.
    """

    def __init__(self, metrics_collector: MetricsCollector):
        """
        Initialize device metrics collector.

        Args:
            metrics_collector: Main metrics collector instance
        """
        self.metrics = metrics_collector
        self.audit = AuditLogger()
        self._collection_interval = 300  # 5 minutes
        self._running = False

    async def start_collection(self):
        """Start periodic metric collection."""
        self._running = True
        while self._running:
            try:
                await self.collect()
                await asyncio.sleep(self._collection_interval)
            except Exception as e:
                await self.audit.log_event(
                    event_type="DEVICE_METRICS_ERROR",
                    details={'error': str(e)}
                )
                await asyncio.sleep(self._collection_interval)

    async def stop_collection(self):
        """Stop metric collection."""
        self._running = False

    async def collect(self):
        """Collect device metrics once."""
        try:
            from src.db.session import get_db

            async with get_db() as db:
                # Device counts
                devices = await db.query(Device).all()

                # Count by vendor and status
                vendor_counts = {}
                status_counts = {'active': 0, 'inactive': 0}
                health_counts = {'healthy': 0, 'degraded': 0, 'unhealthy': 0, 'critical': 0, 'unknown': 0}

                for device in devices:
                    # Vendor counts
                    vendor = device.vendor or 'unknown'
                    vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1

                    # Status counts
                    status = 'active' if device.is_active else 'inactive'
                    status_counts[status] += 1

                    # Health counts
                    health = device.health_status or 'unknown'
                    health_counts[health] = health_counts.get(health, 0) + 1

                    # Individual device metrics
                    labels = {
                        "device_id": str(device.id),
                        "device_name": device.hostname,
                        "vendor": vendor,
                        "model": device.model or 'unknown'
                    }

                    # Device health status
                    health_value = {
                        'healthy': 1,
                        'degraded': 0.5,
                        'unhealthy': 0,
                        'critical': 0,
                        'unknown': -1
                    }.get(health, -1)

                    self.metrics.gauge("catnet_device_health_status").set(health_value, labels=labels)

                    # Device connectivity
                    is_reachable = await self._check_device_reachability(device)
                    self.metrics.gauge("catnet_device_reachable").set(
                        1 if is_reachable else 0,
                        labels=labels
                    )

                    # Configuration version
                    self.metrics.gauge("catnet_device_config_version").set(
                        device.config_version or 0,
                        labels=labels
                    )

                    # Last sync timestamp
                    if device.last_sync_at:
                        age = (datetime.utcnow() - device.last_sync_at).total_seconds()
                        self.metrics.gauge("catnet_device_last_sync_age_seconds").set(age, labels=labels)

                # Set aggregate metrics
                for vendor, count in vendor_counts.items():
                    self.metrics.gauge("catnet_devices_by_vendor").set(
                        count,
                        labels={"vendor": vendor}
                    )

                for status, count in status_counts.items():
                    self.metrics.gauge("catnet_devices_by_status").set(
                        count,
                        labels={"status": status}
                    )

                for health, count in health_counts.items():
                    self.metrics.gauge("catnet_devices_by_health").set(
                        count,
                        labels={"health": health}
                    )

                # Total devices
                self.metrics.gauge("catnet_devices_total").set(len(devices))

                # Critical devices
                critical_count = len([d for d in devices if d.is_critical])
                self.metrics.gauge("catnet_critical_devices_total").set(critical_count)

                # Recent health checks
                recent_checks = await db.query(HealthCheck).filter(
                    HealthCheck.checked_at > datetime.utcnow() - timedelta(hours=1)
                ).count()
                self.metrics.gauge("catnet_health_checks_last_hour").set(recent_checks)

        except Exception as e:
            raise MetricsError(f"Failed to collect device metrics: {e}")

    async def _check_device_reachability(self, device: Device) -> bool:
        """Check if device is reachable."""
        # This would perform actual connectivity check
        # Simplified for now
        return device.is_active and device.health_status != 'critical'


class DeploymentMetricsCollector:
    """
    Collects deployment-related metrics.
    Monitors deployment status, success rates, and duration.
    """

    def __init__(self, metrics_collector: MetricsCollector):
        """
        Initialize deployment metrics collector.

        Args:
            metrics_collector: Main metrics collector instance
        """
        self.metrics = metrics_collector
        self.audit = AuditLogger()
        self._collection_interval = 60  # 1 minute
        self._running = False

    async def start_collection(self):
        """Start periodic metric collection."""
        self._running = True
        while self._running:
            try:
                await self.collect()
                await asyncio.sleep(self._collection_interval)
            except Exception as e:
                await self.audit.log_event(
                    event_type="DEPLOYMENT_METRICS_ERROR",
                    details={'error': str(e)}
                )
                await asyncio.sleep(self._collection_interval)

    async def stop_collection(self):
        """Stop metric collection."""
        self._running = False

    async def collect(self):
        """Collect deployment metrics once."""
        try:
            from src.db.session import get_db

            async with get_db() as db:
                # Deployment counts by state
                deployment_states = await db.execute(
                    "SELECT state, COUNT(*) FROM deployments GROUP BY state"
                )

                for state, count in deployment_states:
                    self.metrics.gauge("catnet_deployments_by_state").set(
                        count,
                        labels={"state": state}
                    )

                # Deployment counts by strategy
                deployment_strategies = await db.execute(
                    "SELECT strategy, COUNT(*) FROM deployments GROUP BY strategy"
                )

                for strategy, count in deployment_strategies:
                    self.metrics.gauge("catnet_deployments_by_strategy").set(
                        count,
                        labels={"strategy": strategy}
                    )

                # Recent deployments (last 24 hours)
                recent_deployments = await db.query(Deployment).filter(
                    Deployment.created_at > datetime.utcnow() - timedelta(hours=24)
                ).all()

                self.metrics.gauge("catnet_deployments_last_24h").set(len(recent_deployments))

                # Calculate success rate
                successful = len([d for d in recent_deployments if d.state == 'completed'])
                failed = len([d for d in recent_deployments if d.state == 'failed'])
                total = len(recent_deployments)

                if total > 0:
                    success_rate = (successful / total) * 100
                    self.metrics.gauge("catnet_deployment_success_rate_percent").set(success_rate)

                # Active deployments
                active_deployments = await db.query(Deployment).filter(
                    Deployment.state.in_(['pending', 'in_progress', 'awaiting_approval'])
                ).all()

                self.metrics.gauge("catnet_active_deployments").set(len(active_deployments))

                # Deployment queue size
                pending_deployments = await db.query(Deployment).filter(
                    Deployment.state == 'pending'
                ).count()

                self.metrics.gauge("catnet_deployment_queue_size").set(pending_deployments)

                # Average deployment duration
                completed_deployments = await db.query(Deployment).filter(
                    Deployment.state == 'completed',
                    Deployment.completed_at.isnot(None),
                    Deployment.started_at.isnot(None)
                ).limit(100).all()

                if completed_deployments:
                    durations = []
                    for deployment in completed_deployments:
                        duration = (deployment.completed_at - deployment.started_at).total_seconds()
                        durations.append(duration)

                        # Record individual deployment duration
                        self.metrics.histogram("catnet_deployment_duration_seconds").observe(
                            duration,
                            labels={
                                "strategy": deployment.strategy,
                                "state": deployment.state
                            }
                        )

                    avg_duration = sum(durations) / len(durations)
                    self.metrics.gauge("catnet_deployment_avg_duration_seconds").set(avg_duration)

                # Rollback metrics
                rollbacks = await db.query(Deployment).filter(
                    Deployment.state == 'rolled_back'
                ).count()

                self.metrics.gauge("catnet_deployment_rollbacks_total").set(rollbacks)

                # Approval metrics
                awaiting_approval = await db.query(Deployment).filter(
                    Deployment.state == 'awaiting_approval'
                ).count()

                self.metrics.gauge("catnet_deployments_awaiting_approval").set(awaiting_approval)

        except Exception as e:
            raise MetricsError(f"Failed to collect deployment metrics: {e}")


class SecurityMetricsCollector:
    """
    Collects security-related metrics.
    Monitors authentication, authorization, and security events.
    """

    def __init__(self, metrics_collector: MetricsCollector):
        """
        Initialize security metrics collector.

        Args:
            metrics_collector: Main metrics collector instance
        """
        self.metrics = metrics_collector
        self.audit = AuditLogger()
        self._collection_interval = 60  # 1 minute
        self._running = False

    async def start_collection(self):
        """Start periodic metric collection."""
        self._running = True
        while self._running:
            try:
                await self.collect()
                await asyncio.sleep(self._collection_interval)
            except Exception as e:
                await self.audit.log_event(
                    event_type="SECURITY_METRICS_ERROR",
                    details={'error': str(e)}
                )
                await asyncio.sleep(self._collection_interval)

    async def stop_collection(self):
        """Stop metric collection."""
        self._running = False

    async def collect(self):
        """Collect security metrics once."""
        try:
            from src.db.session import get_db

            async with get_db() as db:
                # Active sessions
                active_sessions = await db.execute(
                    "SELECT COUNT(*) FROM sessions WHERE expires_at > NOW()"
                )
                session_count = active_sessions.scalar() or 0
                self.metrics.gauge("catnet_active_sessions").set(session_count)

                # MFA enabled users
                mfa_users = await db.execute(
                    "SELECT COUNT(*) FROM users WHERE mfa_enabled = true"
                )
                mfa_count = mfa_users.scalar() or 0
                self.metrics.gauge("catnet_users_mfa_enabled").set(mfa_count)

                # Total users
                total_users = await db.execute(
                    "SELECT COUNT(*) FROM users WHERE is_active = true"
                )
                user_count = total_users.scalar() or 0
                self.metrics.gauge("catnet_users_total").set(user_count)

                # Recent login attempts (last hour)
                recent_logins = await db.execute(
                    """
                    SELECT
                        CASE WHEN success THEN 'success' ELSE 'failure' END as result,
                        COUNT(*)
                    FROM audit_logs
                    WHERE event_type = 'LOGIN_ATTEMPT'
                    AND created_at > NOW() - INTERVAL '1 hour'
                    GROUP BY success
                    """
                )

                for result, count in recent_logins:
                    self.metrics.counter("catnet_auth_attempts_last_hour").inc(
                        count,
                        labels={"result": result}
                    )

                # Failed login attempts by user (for detecting brute force)
                failed_by_user = await db.execute(
                    """
                    SELECT user_id, COUNT(*) as failures
                    FROM audit_logs
                    WHERE event_type = 'LOGIN_FAILED'
                    AND created_at > NOW() - INTERVAL '10 minutes'
                    GROUP BY user_id
                    HAVING COUNT(*) > 3
                    """
                )

                suspicious_users = 0
                for user_id, failures in failed_by_user:
                    if failures > 5:
                        suspicious_users += 1
                        self.metrics.gauge("catnet_suspicious_login_activity").set(
                            failures,
                            labels={"user_id": str(user_id)}
                        )

                self.metrics.gauge("catnet_users_with_suspicious_activity").set(suspicious_users)

                # Certificate expiry monitoring
                cert_expiry = await db.execute(
                    """
                    SELECT COUNT(*)
                    FROM certificates
                    WHERE expires_at < NOW() + INTERVAL '30 days'
                    AND is_active = true
                    """
                )
                expiring_certs = cert_expiry.scalar() or 0
                self.metrics.gauge("catnet_certificates_expiring_soon").set(expiring_certs)

                # Vault seal status (if accessible)
                try:
                    from src.security.vault import VaultClient
                    vault = VaultClient()
                    is_sealed = await vault.is_sealed()
                    self.metrics.gauge("catnet_vault_sealed").set(1 if is_sealed else 0)
                except:
                    pass

                # Security violations (last hour)
                violations = await db.execute(
                    """
                    SELECT
                        severity,
                        COUNT(*)
                    FROM security_violations
                    WHERE created_at > NOW() - INTERVAL '1 hour'
                    GROUP BY severity
                    """
                )

                for severity, count in violations:
                    self.metrics.counter("catnet_security_violations_last_hour").inc(
                        count,
                        labels={"severity": severity}
                    )

                # API key usage
                api_key_usage = await db.execute(
                    """
                    SELECT
                        api_key_id,
                        COUNT(*) as usage_count
                    FROM api_key_usage
                    WHERE used_at > NOW() - INTERVAL '1 hour'
                    GROUP BY api_key_id
                    ORDER BY usage_count DESC
                    LIMIT 10
                    """
                )

                for key_id, usage in api_key_usage:
                    self.metrics.gauge("catnet_api_key_usage_last_hour").set(
                        usage,
                        labels={"key_id": str(key_id)}
                    )

                # Encryption operations
                encryption_ops = await db.execute(
                    """
                    SELECT
                        operation_type,
                        COUNT(*)
                    FROM encryption_operations
                    WHERE timestamp > NOW() - INTERVAL '5 minutes'
                    GROUP BY operation_type
                    """
                )

                for op_type, count in encryption_ops:
                    self.metrics.counter("catnet_encryption_operations").inc(
                        count,
                        labels={"operation": op_type}
                    )

        except Exception as e:
            raise MetricsError(f"Failed to collect security metrics: {e}")


# Export main components
__all__ = [
    'SystemMetricsCollector',
    'DeviceMetricsCollector',
    'DeploymentMetricsCollector',
    'SecurityMetricsCollector'
]