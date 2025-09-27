"""
Prometheus exporter for CatNet metrics.
Provides Prometheus-compatible metrics endpoint.
"""

import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
import re

from src.monitoring.metrics import (
    MetricsCollector,
    Counter,
    Gauge,
    Histogram,
    Summary
)
from src.core.config import get_settings
from src.security.audit import AuditLogger


class PrometheusRegistry:
    """
    Registry for Prometheus metrics.
    Manages metric registration and collection.
    """

    def __init__(self):
        """Initialize Prometheus registry."""
        self.metrics = {}
        self.audit = AuditLogger()

    def register(self, metric):
        """Register a metric with the registry."""
        if metric.name in self.metrics:
            raise ValueError(f"Metric {metric.name} already registered")
        self.metrics[metric.name] = metric

    def unregister(self, name: str):
        """Unregister a metric."""
        if name in self.metrics:
            del self.metrics[name]

    def collect(self) -> List[str]:
        """Collect all metrics in Prometheus format."""
        lines = []

        for name, metric in self.metrics.items():
            # Add metric help
            if metric.description:
                lines.append(f"# HELP {name} {metric.description}")

            # Add metric type
            metric_type = self._get_prometheus_type(metric)
            lines.append(f"# TYPE {name} {metric_type}")

            # Add metric values
            lines.extend(self._format_metric_values(name, metric))

        return lines

    def _get_prometheus_type(self, metric) -> str:
        """Get Prometheus metric type."""
        if isinstance(metric, Counter):
            return "counter"
        elif isinstance(metric, Gauge):
            return "gauge"
        elif isinstance(metric, Histogram):
            return "histogram"
        elif isinstance(metric, Summary):
            return "summary"
        else:
            return "untyped"

    def _format_metric_values(self, name: str, metric) -> List[str]:
        """Format metric values for Prometheus."""
        lines = []

        if isinstance(metric, (Counter, Gauge)):
            for value in metric.collect():
                labels_str = self._format_labels(value.labels)
                lines.append(f"{name}{labels_str} {value.value} {int(value.timestamp * 1000)}")

        elif isinstance(metric, Histogram):
            data = metric.collect()
            for labels_key, hist_data in data.items():
                labels = {'key': labels_key} if labels_key else {}
                labels_str = self._format_labels(labels)

                # Add bucket values
                for bucket, count in sorted(hist_data['buckets'].items()):
                    bucket_labels = {**labels, 'le': str(bucket)}
                    bucket_labels_str = self._format_labels(bucket_labels)
                    lines.append(f"{name}_bucket{bucket_labels_str} {count}")

                # Add +Inf bucket
                inf_labels = {**labels, 'le': '+Inf'}
                inf_labels_str = self._format_labels(inf_labels)
                lines.append(f"{name}_bucket{inf_labels_str} {hist_data['count']}")

                # Add sum and count
                lines.append(f"{name}_sum{labels_str} {hist_data['sum']}")
                lines.append(f"{name}_count{labels_str} {hist_data['count']}")

        elif isinstance(metric, Summary):
            data = metric.collect()
            for labels_key, summary_data in data.items():
                labels = {'key': labels_key} if labels_key else {}
                labels_str = self._format_labels(labels)

                # Add quantiles
                for quantile, value in summary_data['quantiles'].items():
                    if value is not None:
                        quantile_labels = {**labels, 'quantile': str(quantile)}
                        quantile_labels_str = self._format_labels(quantile_labels)
                        lines.append(f"{name}{quantile_labels_str} {value}")

                # Add sum and count
                lines.append(f"{name}_sum{labels_str} {summary_data['sum']}")
                lines.append(f"{name}_count{labels_str} {summary_data['count']}")

        return lines

    def _format_labels(self, labels: Dict[str, str]) -> str:
        """Format labels for Prometheus."""
        if not labels:
            return ""

        label_pairs = []
        for key, value in sorted(labels.items()):
            # Escape special characters
            value = value.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
            label_pairs.append(f'{key}="{value}"')

        return "{" + ",".join(label_pairs) + "}"


class PrometheusExporter:
    """
    Prometheus metrics exporter for CatNet.
    Provides HTTP endpoint for Prometheus scraping.
    """

    def __init__(self, metrics_collector: MetricsCollector):
        """
        Initialize Prometheus exporter.

        Args:
            metrics_collector: Metrics collector instance
        """
        self.metrics_collector = metrics_collector
        self.registry = PrometheusRegistry()
        self.settings = get_settings()
        self.audit = AuditLogger()

        # Register all metrics with Prometheus registry
        self._register_metrics()

        # Custom metrics
        self._init_custom_metrics()

    def _register_metrics(self):
        """Register all metrics with Prometheus registry."""
        for name, metric in self.metrics_collector.metrics.items():
            self.registry.register(metric)

    def _init_custom_metrics(self):
        """Initialize custom Prometheus metrics."""
        # Build info
        self.build_info = self.metrics_collector.gauge(
            "catnet_build_info",
            "CatNet build information",
            labels=["version", "build_date", "git_commit"]
        )

        # Set build info
        self.build_info.set(1, labels={
            "version": self.settings.VERSION,
            "build_date": self.settings.BUILD_DATE,
            "git_commit": self.settings.GIT_COMMIT
        })

        # Process info
        self.process_start_time = self.metrics_collector.gauge(
            "catnet_process_start_time_seconds",
            "Start time of the process in Unix epoch seconds"
        )
        self.process_start_time.set(datetime.utcnow().timestamp())

        # Go-style metrics for compatibility
        self.go_info = self.metrics_collector.gauge(
            "go_info",
            "Go environment information (for compatibility)",
            labels=["version"]
        )
        self.go_info.set(1, labels={"version": "python"})

    async def export(self) -> str:
        """
        Export metrics in Prometheus format.

        Returns:
            Prometheus-formatted metrics string
        """
        try:
            # Collect system metrics
            await self._collect_system_metrics()

            # Collect application metrics
            await self._collect_application_metrics()

            # Get all metrics in Prometheus format
            lines = self.registry.collect()

            # Add timestamp
            lines.append(f"# Generated at {datetime.utcnow().isoformat()}")

            return "\n".join(lines)

        except Exception as e:
            await self.audit.log_event(
                event_type="PROMETHEUS_EXPORT_ERROR",
                details={'error': str(e)}
            )
            raise

    async def _collect_system_metrics(self):
        """Collect system-level metrics."""
        import psutil

        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=0.1)
        self.metrics_collector.gauge("catnet_system_cpu_usage_percent").set(cpu_percent)

        # Memory usage
        memory = psutil.virtual_memory()
        self.metrics_collector.gauge("catnet_system_memory_usage_percent").set(memory.percent)
        self.metrics_collector.gauge("catnet_system_memory_used_bytes").set(memory.used)
        self.metrics_collector.gauge("catnet_system_memory_total_bytes").set(memory.total)

        # Disk usage
        for partition in psutil.disk_partitions():
            if partition.fstype:
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    self.metrics_collector.gauge("catnet_system_disk_usage_percent").set(
                        usage.percent,
                        labels={"mount_point": partition.mountpoint}
                    )
                    self.metrics_collector.gauge("catnet_system_disk_used_bytes").set(
                        usage.used,
                        labels={"mount_point": partition.mountpoint}
                    )
                    self.metrics_collector.gauge("catnet_system_disk_total_bytes").set(
                        usage.total,
                        labels={"mount_point": partition.mountpoint}
                    )
                except:
                    pass

        # Network I/O
        net_io = psutil.net_io_counters()
        self.metrics_collector.counter("catnet_network_bytes_sent_total").inc(net_io.bytes_sent)
        self.metrics_collector.counter("catnet_network_bytes_received_total").inc(net_io.bytes_recv)
        self.metrics_collector.counter("catnet_network_packets_sent_total").inc(net_io.packets_sent)
        self.metrics_collector.counter("catnet_network_packets_received_total").inc(net_io.packets_recv)

        # Process metrics
        process = psutil.Process()
        self.metrics_collector.gauge("catnet_process_cpu_usage_percent").set(process.cpu_percent())
        self.metrics_collector.gauge("catnet_process_memory_rss_bytes").set(process.memory_info().rss)
        self.metrics_collector.gauge("catnet_process_memory_vms_bytes").set(process.memory_info().vms)
        self.metrics_collector.gauge("catnet_process_open_files").set(len(process.open_files()))
        self.metrics_collector.gauge("catnet_process_num_threads").set(process.num_threads())

    async def _collect_application_metrics(self):
        """Collect application-specific metrics."""
        # This would query database for current statistics
        # Simplified for now

        # Database metrics
        try:
            from src.db.session import get_db

            async with get_db() as db:
                # Count devices
                device_count_query = "SELECT vendor, is_active, COUNT(*) FROM devices GROUP BY vendor, is_active"
                result = await db.execute(device_count_query)
                for row in result:
                    vendor, is_active, count = row
                    status = "active" if is_active else "inactive"
                    self.metrics_collector.gauge("catnet_devices_total").set(
                        count,
                        labels={"vendor": vendor or "unknown", "status": status}
                    )

                # Count deployments by state
                deployment_query = "SELECT state, COUNT(*) FROM deployments GROUP BY state"
                result = await db.execute(deployment_query)
                for row in result:
                    state, count = row
                    self.metrics_collector.gauge("catnet_deployments_by_state").set(
                        count,
                        labels={"state": state}
                    )

                # Active sessions
                session_query = "SELECT COUNT(*) FROM sessions WHERE expires_at > NOW()"
                result = await db.execute(session_query)
                active_sessions = result.scalar()
                self.metrics_collector.gauge("catnet_active_sessions").set(active_sessions or 0)

                # Database connection pool stats
                pool_stats = db.pool.status()
                self.metrics_collector.gauge("catnet_db_pool_size").set(pool_stats.get('size', 0))
                self.metrics_collector.gauge("catnet_db_pool_available").set(pool_stats.get('available', 0))
                self.metrics_collector.gauge("catnet_db_pool_in_use").set(pool_stats.get('in_use', 0))

        except Exception as e:
            # Log error but don't fail export
            pass

        # Redis metrics
        try:
            import aioredis

            redis = await aioredis.create_redis_pool(self.settings.REDIS_URL)
            info = await redis.info()

            # Redis memory
            self.metrics_collector.gauge("catnet_redis_memory_used_bytes").set(
                info.get('used_memory', 0)
            )
            self.metrics_collector.gauge("catnet_redis_memory_peak_bytes").set(
                info.get('used_memory_peak', 0)
            )

            # Redis connections
            self.metrics_collector.gauge("catnet_redis_connected_clients").set(
                info.get('connected_clients', 0)
            )

            # Redis operations
            self.metrics_collector.counter("catnet_redis_commands_processed_total").inc(
                info.get('total_commands_processed', 0)
            )

            redis.close()
            await redis.wait_closed()

        except Exception:
            pass

    def format_for_pushgateway(self, job: str, instance: Optional[str] = None) -> str:
        """
        Format metrics for Prometheus Pushgateway.

        Args:
            job: Job name
            instance: Instance name

        Returns:
            Formatted metrics string
        """
        lines = self.registry.collect()

        # Add job and instance labels to all metrics
        formatted_lines = []
        for line in lines:
            if line.startswith('#'):
                formatted_lines.append(line)
            else:
                # Parse metric line
                match = re.match(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(.*?)(\s+[\d\.]+(?:e[+-]?\d+)?)\s*(\d*)$', line)
                if match:
                    metric_name = match.group(1)
                    labels = match.group(2)
                    value = match.group(3)
                    timestamp = match.group(4)

                    # Add job and instance labels
                    if labels and labels.startswith('{'):
                        # Insert job and instance into existing labels
                        labels = labels[1:-1]  # Remove braces
                        new_labels = [f'job="{job}"']
                        if instance:
                            new_labels.append(f'instance="{instance}"')
                        if labels:
                            new_labels.append(labels)
                        labels = '{' + ','.join(new_labels) + '}'
                    else:
                        # Create new labels
                        new_labels = [f'job="{job}"']
                        if instance:
                            new_labels.append(f'instance="{instance}"')
                        labels = '{' + ','.join(new_labels) + '}'

                    formatted_line = f"{metric_name}{labels}{value}"
                    if timestamp:
                        formatted_line += f" {timestamp}"
                    formatted_lines.append(formatted_line)
                else:
                    formatted_lines.append(line)

        return "\n".join(formatted_lines)

    async def push_to_gateway(
        self,
        gateway_url: str,
        job: str,
        instance: Optional[str] = None
    ):
        """
        Push metrics to Prometheus Pushgateway.

        Args:
            gateway_url: Pushgateway URL
            job: Job name
            instance: Instance name
        """
        import aiohttp

        try:
            # Format metrics
            metrics_data = self.format_for_pushgateway(job, instance)

            # Build URL
            url = f"{gateway_url}/metrics/job/{job}"
            if instance:
                url += f"/instance/{instance}"

            # Push metrics
            async with aiohttp.ClientSession() as session:
                async with session.put(url, data=metrics_data) as response:
                    if response.status != 200:
                        raise Exception(f"Push failed: {response.status}")

            await self.audit.log_event(
                event_type="PROMETHEUS_PUSH_SUCCESS",
                details={
                    'gateway_url': gateway_url,
                    'job': job,
                    'instance': instance
                }
            )

        except Exception as e:
            await self.audit.log_event(
                event_type="PROMETHEUS_PUSH_ERROR",
                details={
                    'gateway_url': gateway_url,
                    'job': job,
                    'error': str(e)
                }
            )
            raise


# Export main components
__all__ = [
    'PrometheusExporter',
    'PrometheusRegistry'
]