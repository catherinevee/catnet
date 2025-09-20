"""
Core Metrics Module for CatNet

Provides metrics collection and tracking for deployments, operations, and \
    system health.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
import time
from collections import defaultdict, deque
import statistics



class MetricType(Enum):
    """Types of metrics we collect"""

    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"
    TIMER = "timer"


@dataclass

class Metric:
    """Represents a single metric"""

    name: str
    type: MetricType
    value: float
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    description: str = ""
    unit: str = ""



class MetricsCollector:
    """Collects and manages system metrics"""

    def __init__(self, namespace: str = "catnet"):
        self.namespace = namespace
        self.metrics: Dict[str, List[Metric]] = defaultdict(list)
        self.counters: Dict[str, float] = defaultdict(float)
        self.gauges: Dict[str, float] = {}
                self.histograms: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=1000)
        )
        self.timers: Dict[str, float] = {}

    def increment_counter(
        self, name: str, value: float = 1.0, labels: Dict[str, str] = None
    ):
        """Increment a counter metric"""
        key = self._make_key(name, labels)
        self.counters[key] += value
        self.metrics[name].append(
            Metric(
                name=name,
                type=MetricType.COUNTER,
                value=self.counters[key],
                labels=labels or {},
                timestamp=datetime.utcnow(),
            )
        )

        def set_gauge(
        self,
        name: str,
        value: float,
        labels: Dict[str,
        str] = None
    ):
        """Set a gauge metric value"""
        key = self._make_key(name, labels)
        self.gauges[key] = value
        self.metrics[name].append(
            Metric(
                name=name,
                type=MetricType.GAUGE,
                value=value,
                labels=labels or {},
                timestamp=datetime.utcnow(),
            )
        )

        def observe_histogram(
        self,
        name: str,
        value: float,
        labels: Dict[str,
        str] = None
    ):
        """Add an observation to a histogram"""
        key = self._make_key(name, labels)
        self.histograms[key].append(value)
        self.metrics[name].append(
            Metric(
                name=name,
                type=MetricType.HISTOGRAM,
                value=value,
                labels=labels or {},
                timestamp=datetime.utcnow(),
            )
        )

    def start_timer(self, name: str) -> str:
        """Start a timer and return its ID"""
        timer_id = f"{name}_{time.time()}"
        self.timers[timer_id] = time.time()
        return timer_id

    def stop_timer(self, timer_id: str, labels: Dict[str, str] = None):
        """Stop a timer and record the duration"""
        if timer_id not in self.timers:
            return

        start_time = self.timers.pop(timer_id)
        duration = time.time() - start_time
        name = timer_id.split("_")[0]

        self.observe_histogram(f"{name}_duration_seconds", duration, labels)

    def get_metrics(self) -> Dict[str, List[Metric]]:
        """Get all collected metrics"""
        return dict(self.metrics)

    def get_summary(self, name: str) -> Dict[str, Any]:
        """Get summary statistics for a metric"""
        if name not in self.metrics:
            return {}

        values = [m.value for m in self.metrics[name]]
        if not values:
            return {}

        return {
            "count": len(values),
            "sum": sum(values),
            "mean": statistics.mean(values),
            "min": min(values),
            "max": max(values),
            "stdev": statistics.stdev(values) if len(values) > 1 else 0,
            "median": statistics.median(values),
        }

    def get_prometheus_format(self) -> str:
        """Export metrics in Prometheus format"""
        lines = []

        # Add counters
        for key, value in self.counters.items():
            name, labels = self._parse_key(key)
            lines.append(f"# TYPE {self.namespace}_{name} counter")
            lines.append(
                f"{self.namespace}_{name}{self._format_labels(labels)} {value}"
            )

        # Add gauges
        for key, value in self.gauges.items():
            name, labels = self._parse_key(key)
            lines.append(f"# TYPE {self.namespace}_{name} gauge")
            lines.append(
                f"{self.namespace}_{name}{self._format_labels(labels)} {value}"
            )

        # Add histograms
        for key, values in self.histograms.items():
            if not values:
                continue
            name, labels = self._parse_key(key)
            lines.append(f"# TYPE {self.namespace}_{name} histogram")

            # Calculate buckets
            buckets = [0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0]
            for bucket in buckets:
                count = sum(1 for v in values if v <= bucket)
                bucket_labels = {**labels, "le": str(bucket)}
                lines.append(
                    f"{self.namespace}_{name}_bucket{self._format_labels( 
    bucket_labels)} {count}"
                )

            # Add +Inf bucket and summary
            lines.append(
                f"{self.namespace}_{name}_bucket{self._format_labels({**labels, 
    'le': '+Inf'})} {len(values)}"
            )
            lines.append(
                f"{self.namespace}_{name}_sum{self._format_labels(labels)} \
                    {sum(
    values)}"
            )
            lines.append(
                f"{self.namespace}_{name}_count{self._format_labels(labels)} { \
    len(values)}"
            )

        return "\n".join(lines)

    def _make_key(self, name: str, labels: Optional[Dict[str, str]]) -> str:
        """Create a unique key for a metric"""
        if not labels:
            return name
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name},{label_str}"

    def _parse_key(self, key: str) -> tuple[str, Dict[str, str]]:
        """Parse a metric key back into name and labels"""
        parts = key.split(",", 1)
        name = parts[0]
        labels = {}

        if len(parts) > 1:
            for item in parts[1].split(","):
                if "=" in item:
                    k, v = item.split("=", 1)
                    labels[k] = v

        return name, labels

    def _format_labels(self, labels: Dict[str, str]) -> str:
        """Format labels for Prometheus export"""
        if not labels:
            return ""
        items = [f'{k}="{v}"' for k, v in sorted(labels.items())]
        return "{" + ",".join(items) + "}"

    def clear(self):
        """Clear all metrics"""
        self.metrics.clear()
        self.counters.clear()
        self.gauges.clear()
        self.histograms.clear()
        self.timers.clear()



class DeploymentMetrics:
    """Specialized metrics for deployment tracking"""

    def __init__(self, collector: Optional[MetricsCollector] = None):
        self.collector = collector or MetricsCollector("catnet_deployments")

    def record_deployment_start(
        self, deployment_id: str, strategy: str, device_count: int
    ):
        """Record the start of a deployment"""
        self.collector.increment_counter(
            "deployments_started_total", labels={"strategy": strategy}
        )
        self.collector.set_gauge(
            "deployment_devices",
                device_count
                labels={"deployment_id": deployment_id}
        )
        return self.collector.start_timer(f"deployment_{deployment_id}")

        def record_deployment_end(
        self,
        deployment_id: str,
        timer_id: str,
        success: bool
    ):
        """Record the end of a deployment"""
        status = "success" if success else "failure"
        self.collector.stop_timer(timer_id, labels={"status": status})
        self.collector.increment_counter(
            "deployments_completed_total", labels={"status": status}
        )

        def record_device_deployment(
        self,
        device_id: str,
        success: bool,
        duration: float
    ):
        """Record a single device deployment"""
        status = "success" if success else "failure"
        self.collector.increment_counter(
            "device_deployments_total", labels={"status": status}
        )
        self.collector.observe_histogram(
            "device_deployment_duration_seconds",
                duration
                labels={"status": status}
        )

    def record_rollback(self, deployment_id: str, reason: str):
        """Record a deployment rollback"""
        self.collector.increment_counter(
            "deployment_rollbacks_total", labels={"reason": reason}
        )

    def record_validation_result(self, validation_type: str, success: bool):
        """Record validation results"""
        status = "pass" if success else "fail"
        self.collector.increment_counter(
            "config_validations_total",
            labels={"type": validation_type, "status": status},
        )

    def get_deployment_stats(self) -> Dict[str, Any]:
        """Get deployment statistics"""
        return {
            "total_started": sum(
                v
                for k, v in self.collector.counters.items()
                if "deployments_started" in k
            ),
            "total_completed": sum(
                v
                for k, v in self.collector.counters.items()
                if "deployments_completed" in k
            ),
            "success_rate": self._calculate_success_rate(),
            "average_duration": self._calculate_average_duration(),
        }

    def _calculate_success_rate(self) -> float:
        """Calculate deployment success rate"""
        success = sum(
            v
            for k, v in self.collector.counters.items()
            if "deployments_completed" in k and "success" in k
        )
        total = sum(
            v
            for k, v in self.collector.counters.items()
            if "deployments_completed" in k
        )
        return (success / total * 100) if total > 0 else 0.0

    def _calculate_average_duration(self) -> float:
        """Calculate average deployment duration"""
        durations = []
        for key, values in self.collector.histograms.items():
            if "deployment_duration" in key:
                durations.extend(values)
        return statistics.mean(durations) if durations else 0.0



class SystemMetrics:
    """System-wide metrics collection"""

    def __init__(self):
        self.collector = MetricsCollector("catnet_system")
        self.deployment_metrics = DeploymentMetrics(self.collector)

    def record_api_request(
        self, endpoint: str, method: str, status_code: int, duration: float
    ):
        """Record API request metrics"""
        self.collector.increment_counter(
            "api_requests_total",
                        labels={"endpoint": endpoint, "method": method, "status": str(
                status_code
            )},
        )
        self.collector.observe_histogram(
            "api_request_duration_seconds",
            duration,
            labels={"endpoint": endpoint, "method": method},
        )

    def record_auth_attempt(self, method: str, success: bool):
        """Record authentication attempt"""
        status = "success" if success else "failure"
        self.collector.increment_counter(
            "auth_attempts_total", labels={"method": method, "status": status}
        )

        def record_database_query(
        self,
        operation: str,
        table: str,
        duration: float
    ):
        """Record database query metrics"""
        self.collector.observe_histogram(
            "database_query_duration_seconds",
            duration,
            labels={"operation": operation, "table": table},
        )

    def record_cache_operation(self, operation: str, hit: bool):
        """Record cache operation"""
        status = "hit" if hit else "miss"
        self.collector.increment_counter(
            "cache_operations_total",
                labels={"operation": operation
                "status": status}
        )

    def set_active_connections(self, count: int):
        """Set the number of active connections"""
        self.collector.set_gauge("active_connections", count)

    def set_queue_size(self, queue_name: str, size: int):
        """Set queue size metric"""
                self.collector.set_gauge(
            "queue_size",
            size,
            labels={"queue": queue_name}
        )

    async def get_all_metrics(self) -> Dict[str, Any]:
        """Get all system metrics"""
        return {
            "deployment": self.deployment_metrics.get_deployment_stats(),
            "api": self._get_api_stats(),
            "auth": self._get_auth_stats(),
            "database": self._get_database_stats(),
            "prometheus": self.collector.get_prometheus_format(),
        }

    def _get_api_stats(self) -> Dict[str, Any]:
        """Get API statistics"""
        total_requests = sum(
                        v for k, v in self.collector.counters.items(
                
            ) if "api_requests" in k
        )

        # Calculate average response time
        durations = []
        for key, values in self.collector.histograms.items():
            if "api_request_duration" in key:
                durations.extend(values)

        return {
            "total_requests": total_requests,
                        "average_response_time": statistics.mean(
                durations
            ) if durations else 0,
            "p95_response_time": statistics.quantiles(durations, n=20)[18]
            if durations
            else 0,
            "p99_response_time": statistics.quantiles(durations, n=100)[98]
            if durations
            else 0,
        }

    def _get_auth_stats(self) -> Dict[str, Any]:
        """Get authentication statistics"""
        success = sum(
            v
            for k, v in self.collector.counters.items()
            if "auth_attempts" in k and "success" in k
        )
        total = sum(
                        v for k, v in self.collector.counters.items(
                
            ) if "auth_attempts" in k
        )

        return {
            "total_attempts": total,
            "successful": success,
            "failed": total - success,
            "success_rate": (success / total * 100) if total > 0 else 0,
        }

    def _get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        durations = []
        for key, values in self.collector.histograms.items():
            if "database_query_duration" in key:
                durations.extend(values)

        return {
            "total_queries": len(durations),
                        "average_query_time": statistics.mean(
                durations
            ) if durations else 0,
            "slowest_query": max(durations) if durations else 0,
        }


# Global metrics instance
system_metrics = SystemMetrics()

# Export deployment_metrics for compatibility
deployment_metrics = system_metrics.deployment_metrics
