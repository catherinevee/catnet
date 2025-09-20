"""
Simple Metrics Collection
Phase 7 Implementation - Monitoring and observability
"""
from typing import Dict, List, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from pathlib import Path
import json
import threading


@dataclass
class Metric:
    """Simple metric data point"""
    name: str
    value: float
    timestamp: datetime = field(default_factory=datetime.utcnow)
    labels: Dict[str, str] = field(default_factory=dict)
    metric_type: str = "gauge"  # gauge, counter, histogram


class SimpleMetricsCollector:
    """
    Simple metrics collection system
    Tracks deployments, health checks, and system status
    """

    def __init__(self):
        self._metrics: Dict[str, List[Metric]] = {}
        self._counters: Dict[str, float] = {}
        self._lock = threading.Lock()
        self.metrics_dir = Path("data/metrics")
        self.metrics_dir.mkdir(parents=True, exist_ok=True)

        # Initialize counters
        self._counters["deployments_total"] = 0
        self._counters["deployments_success"] = 0
        self._counters["deployments_failed"] = 0
        self._counters["rollbacks_total"] = 0
        self._counters["health_checks_total"] = 0
        self._counters["devices_connected"] = 0
        self._counters["github_connections"] = 0

        # Track deployment timing
        self._deployment_durations = []

        def increment_counter(
            self,
            name: str,
            value: float = 1.0,
            labels: Dict[str,
                         str] = None
        ):
        """Increment a counter metric"""
        with self._lock:
            if name not in self._counters:
                self._counters[name] = 0
            self._counters[name] += value

            # Store metric
            metric = Metric(
                name=name,
                value=self._counters[name],
                metric_type="counter",
                labels=labels or {}
            )

            if name not in self._metrics:
                self._metrics[name] = []
            self._metrics[name].append(metric)

            # Keep only last 1000 metrics per name
            if len(self._metrics[name]) > 1000:
                self._metrics[name] = self._metrics[name][-1000:]

        def set_gauge(
            self,
            name: str,
            value: float,
            labels: Dict[str,
                         str] = None
        ):
        """Set a gauge metric"""
        with self._lock:
            metric = Metric(
                name=name,
                value=value,
                metric_type="gauge",
                labels=labels or {}
            )

            if name not in self._metrics:
                self._metrics[name] = []
            self._metrics[name].append(metric)

            # Keep only last 1000 metrics per name
            if len(self._metrics[name]) > 1000:
                self._metrics[name] = self._metrics[name][-1000:]

        def record_histogram(
            self,
            name: str,
            value: float,
            labels: Dict[str,
                         str] = None
        ):
        """Record a histogram metric (e.g., duration)"""
        with self._lock:
            metric = Metric(
                name=name,
                value=value,
                metric_type="histogram",
                labels=labels or {}
            )

            if name not in self._metrics:
                self._metrics[name] = []
            self._metrics[name].append(metric)

            # Special handling for deployment durations
            if name == "deployment_duration_seconds":
                self._deployment_durations.append(value)
                if len(self._deployment_durations) > 100:
                    self._deployment_durations = \
                        self._deployment_durations[-100:]

        def track_deployment(
            self,
            deployment_id: str,
            status: str,
            duration_seconds: float = None
        ):
        """Track deployment metrics"""
        self.increment_counter("deployments_total")

        if status == "completed":
            self.increment_counter("deployments_success")
        elif status == "failed":
            self.increment_counter("deployments_failed")

        if duration_seconds:
            self.record_histogram("deployment_duration_seconds",
                                  duration_seconds,
                                  {"deployment_id": deployment_id,
                                   "status": status})

    def track_rollback(self, deployment_id: str, success: bool):
        """Track rollback metrics"""
        self.increment_counter("rollbacks_total")

        if success:
            self.increment_counter("rollbacks_success")
        else:
            self.increment_counter("rollbacks_failed")

    def track_health_check(self, device_id: str, status: str):
        """Track health check metrics"""
        self.increment_counter("health_checks_total")

        self.set_gauge(f"device_health_{device_id}",
                       1.0 if status == "healthy" else 0.0,
                       {"device_id": device_id, "status": status})

    def track_device_connection(self, device_id: str, connected: bool):
        """Track device connection metrics"""
        if connected:
            self.increment_counter("device_connections_total")
            self.set_gauge(f"device_connected_{device_id}", 1.0)
        else:
            self.set_gauge(f"device_connected_{device_id}", 0.0)

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get current metrics summary"""
        with self._lock:
            # Calculate deployment statistics
            avg_duration = 0
            if self._deployment_durations:
                avg_duration = sum(self._deployment_durations) / \
                    len(self._deployment_durations)

            # Calculate success rate
            total_deployments = self._counters.get("deployments_total", 0)
            success_deployments = self._counters.get("deployments_success", 0)
            success_rate = 0
            if total_deployments > 0:
                success_rate = (success_deployments / total_deployments) * 100

            return {
                "timestamp": datetime.utcnow().isoformat(),
                "counters": {
                    "deployments": {
                        "total": self._counters.get("deployments_total", 0),
                        "success": self._counters.get(
                            "deployments_success",
                            0
                        ),
                        "failed": self._counters.get("deployments_failed", 0)
                    },
                    "rollbacks": {
                        "total": self._counters.get("rollbacks_total", 0),
                        "success": self._counters.get("rollbacks_success", 0),
                        "failed": self._counters.get("rollbacks_failed", 0)
                    },
                    "health_checks": self._counters.get(
                        "health_checks_total",
                        0
                    ),
                    "device_connections": self._counters.get(
                        "device_connections_total", 0),
                    "github_connections": self._counters.get(
                        "github_connections",
                        0
                    )
                },
                "statistics": {
                    "deployment_success_rate": round(success_rate, 2),
                    "average_deployment_duration_seconds": round(
                        avg_duration,
                        2
                    ),
                    "total_operations": sum([
                        self._counters.get("deployments_total", 0),
                        self._counters.get("rollbacks_total", 0),
                        self._counters.get("health_checks_total", 0)
                    ])
                }
            }

    def get_prometheus_metrics(self) -> str:
        """Get metrics in Prometheus format"""
        lines = []

        with self._lock:
            # Export counters
            for name, value in self._counters.items():
                lines.append(f"# TYPE catnet_{name} counter")
                lines.append(f"catnet_{name} {value}")

            # Export latest gauge values
            gauge_latest = {}
            for name, metrics in self._metrics.items():
                if metrics and metrics[-1].metric_type == "gauge":
                    gauge_latest[name] = metrics[-1].value

            for name, value in gauge_latest.items():
                lines.append(f"# TYPE catnet_{name} gauge")
                lines.append(f"catnet_{name} {value}")

            # Export histogram statistics
            if self._deployment_durations:
                avg_duration = sum(self._deployment_durations) / \
                    len(self._deployment_durations)
                max_duration = max(self._deployment_durations)
                min_duration = min(self._deployment_durations)

                lines.append("# TYPE catnet_deployment_duration_seconds \
                    histogram")
                lines.append(f"catnet_deployment_duration_seconds_sum {sum(
                    self._deployment_durations)}")
                lines.append(f"catnet_deployment_duration_seconds_count {len(
                    self._deployment_durations)}")
                lines.append(f"catnet_deployment_duration_seconds_avg \
                    {avg_duration}")
                lines.append(f"catnet_deployment_duration_seconds_max \
                    {max_duration}")
                lines.append(f"catnet_deployment_duration_seconds_min \
                    {min_duration}")

        return "\n".join(lines)

        def get_recent_metrics(
            self,
            metric_name: str = None,
            minutes: int = 60
        ) -> List[Dict[str, Any]]:
        """Get recent metrics for a specific metric or all metrics"""
        with self._lock:
            cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
            recent = []

            if metric_name:
                if metric_name in self._metrics:
                    for metric in self._metrics[metric_name]:
                        if metric.timestamp > cutoff_time:
                            recent.append({
                                "name": metric.name,
                                "value": metric.value,
                                "timestamp": metric.timestamp.isoformat(),
                                "type": metric.metric_type,
                                "labels": metric.labels
                            })
            else:
                for name, metrics in self._metrics.items():
                    for metric in metrics:
                        if metric.timestamp > cutoff_time:
                            recent.append({
                                "name": metric.name,
                                "value": metric.value,
                                "timestamp": metric.timestamp.isoformat(),
                                "type": metric.metric_type,
                                "labels": metric.labels
                            })

                        return sorted(
                            recent,
                            key=lambda x: x["timestamp"],
                            reverse=True
                        )[:100]

    def save_metrics_snapshot(self):
        """Save current metrics to disk"""
        snapshot_file = self.metrics_dir / \
            f"snapshot_{datetime.utcnow() .strftime('%Y%m%d_%H%M%S')}.json"

        with self._lock:
            snapshot = {
                "timestamp": datetime.utcnow().isoformat(),
                "counters": self._counters.copy(),
                "summary": self.get_metrics_summary()
            }

        with open(snapshot_file, 'w') as f:
            json.dump(snapshot, f, indent=2)

        return str(snapshot_file)


# Global metrics collector instance
metrics_collector = SimpleMetricsCollector()
