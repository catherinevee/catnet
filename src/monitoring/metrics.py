"""
Metrics Collection System for CatNet

Handles:
- Performance metrics
- Business metrics
- Security metrics
- Custom metrics
"""

from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from prometheus_client import Counter, Histogram, Gauge, Summary
import asyncio
from collections import defaultdict, deque


class MetricType(Enum):
    """Types of metrics"""

    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


class MetricUnit(Enum):
    """Metric units"""

    COUNT = "count"
    BYTES = "bytes"
    SECONDS = "seconds"
    MILLISECONDS = "milliseconds"
    PERCENTAGE = "percentage"
    ERRORS = "errors"
    REQUESTS = "requests"


@dataclass
class MetricValue:
    """Single metric value"""

    timestamp: datetime
    value: float
    labels: Dict[str, str] = field(default_factory=dict)
    unit: MetricUnit = MetricUnit.COUNT


@dataclass
class MetricDefinition:
    """Metric definition"""

    name: str
    type: MetricType
    description: str
    unit: MetricUnit
    labels: List[str] = field(default_factory=list)
    buckets: Optional[List[float]] = None
    quantiles: Optional[List[float]] = None


class MetricsCollector:
    """
    Collects and manages metrics
    """

    def __init__(self, namespace: str = "catnet"):
        """
        Initialize metrics collector

        Args:
            namespace: Prometheus namespace
        """
        self.namespace = namespace
        self.metrics: Dict[str, Any] = {}
        self.time_series: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=1000)
        )

        # Initialize default metrics
        self._initialize_default_metrics()

    def _initialize_default_metrics(self):
        """Initialize default system metrics"""
        # Deployment metrics
        self.register_metric(
            MetricDefinition(
                name="deployments_total",
                type=MetricType.COUNTER,
                description="Total number of deployments",
                unit=MetricUnit.COUNT,
                labels=["status", "strategy", "environment"],
            )
        )

        self.register_metric(
            MetricDefinition(
                name="deployment_duration_seconds",
                type=MetricType.HISTOGRAM,
                description="Time taken for deployments",
                unit=MetricUnit.SECONDS,
                labels=["strategy", "result"],
                buckets=[10, 30, 60, 120, 300, 600, 1800, 3600],
            )
        )

        # Device metrics
        self.register_metric(
            MetricDefinition(
                name="devices_total",
                type=MetricType.GAUGE,
                description="Total number of devices",
                unit=MetricUnit.COUNT,
                labels=["vendor", "type", "state"],
            )
        )

        self.register_metric(
            MetricDefinition(
                name="device_connection_duration",
                type=MetricType.HISTOGRAM,
                description="Device connection duration",
                unit=MetricUnit.SECONDS,
                labels=["vendor", "protocol"],
                buckets=[0.1, 0.5, 1, 2, 5, 10, 30],
            )
        )

        # Command execution metrics
        self.register_metric(
            MetricDefinition(
                name="commands_executed_total",
                type=MetricType.COUNTER,
                description="Total commands executed",
                unit=MetricUnit.COUNT,
                labels=["device_type", "command_type", "status"],
            )
        )

        # Configuration metrics
        self.register_metric(
            MetricDefinition(
                name="config_changes_total",
                type=MetricType.COUNTER,
                description="Total configuration changes",
                unit=MetricUnit.COUNT,
                labels=["device_type", "change_type", "status"],
            )
        )

        # Security metrics
        self.register_metric(
            MetricDefinition(
                name="auth_attempts_total",
                type=MetricType.COUNTER,
                description="Authentication attempts",
                unit=MetricUnit.COUNT,
                labels=["method", "result"],
            )
        )

        self.register_metric(
            MetricDefinition(
                name="security_violations_total",
                type=MetricType.COUNTER,
                description="Security violations detected",
                unit=MetricUnit.COUNT,
                labels=["type", "severity"],
            )
        )

        # Health metrics
        self.register_metric(
            MetricDefinition(
                name="service_health",
                type=MetricType.GAUGE,
                description="Service health status",
                unit=MetricUnit.COUNT,
                labels=["service", "component"],
            )
        )

        self.register_metric(
            MetricDefinition(
                name="device_health_score",
                type=MetricType.GAUGE,
                description="Device health score",
                unit=MetricUnit.PERCENTAGE,
                labels=["device_id", "vendor"],
            )
        )

        # Performance metrics
        self.register_metric(
            MetricDefinition(
                name="api_request_duration",
                type=MetricType.HISTOGRAM,
                description="API request duration",
                unit=MetricUnit.SECONDS,
                labels=["method", "endpoint", "status_code"],
                buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
            )
        )

        self.register_metric(
            MetricDefinition(
                name="database_query_duration",
                type=MetricType.HISTOGRAM,
                description="Database query duration",
                unit=MetricUnit.SECONDS,
                labels=["operation", "table"],
                buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1],
            )
        )

        # Error metrics
        self.register_metric(
            MetricDefinition(
                name="errors_total",
                type=MetricType.COUNTER,
                description="Total errors",
                unit=MetricUnit.ERRORS,
                labels=["service", "error_type", "severity"],
            )
        )

    def register_metric(self, definition: MetricDefinition):
        """
        Register a new metric

        Args:
            definition: Metric definition
        """
        metric_name = f"{self.namespace}_{definition.name}"

        if definition.type == MetricType.COUNTER:
            metric = Counter(
                metric_name,
                definition.description,
                definition.labels,
                namespace="",
            )
        elif definition.type == MetricType.GAUGE:
            metric = Gauge(
                metric_name,
                definition.description,
                definition.labels,
                namespace="",
            )
        elif definition.type == MetricType.HISTOGRAM:
            metric = Histogram(
                metric_name,
                definition.description,
                definition.labels,
                namespace="",
                buckets=definition.buckets or Histogram.DEFAULT_BUCKETS,
            )
        elif definition.type == MetricType.SUMMARY:
            metric = Summary(
                metric_name,
                definition.description,
                definition.labels,
                namespace="",
            )
        else:
            raise ValueError(f"Unknown metric type: {definition.type}")

        self.metrics[definition.name] = {
            "metric": metric,
            "definition": definition,
        }

    def increment_counter(
        self, name: str, value: float = 1, labels: Optional[Dict[str, str]] = None
    ):
        """
        Increment a counter metric

        Args:
            name: Metric name
            value: Increment value
            labels: Metric labels
        """
        if name not in self.metrics:
            raise ValueError(f"Metric {name} not found")

        metric_info = self.metrics[name]
        if metric_info["definition"].type != MetricType.COUNTER:
            raise ValueError(f"Metric {name} is not a counter")

        labels = labels or {}
        metric_info["metric"].labels(**labels).inc(value)

        # Store in time series
        self._store_time_series(name, value, labels)

    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """
        Set a gauge metric

        Args:
            name: Metric name
            value: Gauge value
            labels: Metric labels
        """
        if name not in self.metrics:
            raise ValueError(f"Metric {name} not found")

        metric_info = self.metrics[name]
        if metric_info["definition"].type != MetricType.GAUGE:
            raise ValueError(f"Metric {name} is not a gauge")

        labels = labels or {}
        metric_info["metric"].labels(**labels).set(value)

        # Store in time series
        self._store_time_series(name, value, labels)

    def observe_histogram(
        self, name: str, value: float, labels: Optional[Dict[str, str]] = None
    ):
        """
        Observe a histogram metric

        Args:
            name: Metric name
            value: Observed value
            labels: Metric labels
        """
        if name not in self.metrics:
            raise ValueError(f"Metric {name} not found")

        metric_info = self.metrics[name]
        if metric_info["definition"].type != MetricType.HISTOGRAM:
            raise ValueError(f"Metric {name} is not a histogram")

        labels = labels or {}
        metric_info["metric"].labels(**labels).observe(value)

        # Store in time series
        self._store_time_series(name, value, labels)

    def observe_summary(
        self, name: str, value: float, labels: Optional[Dict[str, str]] = None
    ):
        """
        Observe a summary metric

        Args:
            name: Metric name
            value: Observed value
            labels: Metric labels
        """
        if name not in self.metrics:
            raise ValueError(f"Metric {name} not found")

        metric_info = self.metrics[name]
        if metric_info["definition"].type != MetricType.SUMMARY:
            raise ValueError(f"Metric {name} is not a summary")

        labels = labels or {}
        metric_info["metric"].labels(**labels).observe(value)

        # Store in time series
        self._store_time_series(name, value, labels)

    def _store_time_series(
        self, name: str, value: float, labels: Dict[str, str]
    ):
        """Store metric value in time series"""
        key = f"{name}:{':'.join(f'{k}={v}' for k, v in sorted(labels.items()))}"
        metric_value = MetricValue(
            timestamp=datetime.utcnow(),
            value=value,
            labels=labels,
            unit=self.metrics[name]["definition"].unit,
        )
        self.time_series[key].append(metric_value)

    def get_time_series(
        self,
        name: str,
        labels: Optional[Dict[str, str]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[MetricValue]:
        """
        Get time series data for a metric

        Args:
            name: Metric name
            labels: Filter by labels
            start_time: Start time filter
            end_time: End time filter

        Returns:
            List of metric values
        """
        labels = labels or {}
        key_prefix = f"{name}:{':'.join(f'{k}={v}' for k, v in sorted(labels.items()))}"

        results = []
        for key, values in self.time_series.items():
            if key.startswith(key_prefix):
                for value in values:
                    if start_time and value.timestamp < start_time:
                        continue
                    if end_time and value.timestamp > end_time:
                        continue
                    results.append(value)

        return sorted(results, key=lambda x: x.timestamp)

    def calculate_rate(
        self,
        name: str,
        labels: Optional[Dict[str, str]] = None,
        window: timedelta = timedelta(minutes=5),
    ) -> float:
        """
        Calculate rate of change for a counter

        Args:
            name: Metric name
            labels: Metric labels
            window: Time window

        Returns:
            Rate of change
        """
        end_time = datetime.utcnow()
        start_time = end_time - window

        time_series = self.get_time_series(name, labels, start_time, end_time)
        if len(time_series) < 2:
            return 0.0

        first_value = time_series[0].value
        last_value = time_series[-1].value
        time_diff = (time_series[-1].timestamp - time_series[0].timestamp).total_seconds()

        if time_diff == 0:
            return 0.0

        return (last_value - first_value) / time_diff

    def calculate_percentile(
        self,
        name: str,
        percentile: float,
        labels: Optional[Dict[str, str]] = None,
        window: timedelta = timedelta(minutes=5),
    ) -> float:
        """
        Calculate percentile for a metric

        Args:
            name: Metric name
            percentile: Percentile to calculate (0-100)
            labels: Metric labels
            window: Time window

        Returns:
            Percentile value
        """
        end_time = datetime.utcnow()
        start_time = end_time - window

        time_series = self.get_time_series(name, labels, start_time, end_time)
        if not time_series:
            return 0.0

        values = sorted([v.value for v in time_series])
        index = int(len(values) * percentile / 100)
        return values[min(index, len(values) - 1)]

    def get_metric_summary(
        self, name: str, labels: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Get summary statistics for a metric

        Args:
            name: Metric name
            labels: Metric labels

        Returns:
            Summary statistics
        """
        time_series = self.get_time_series(name, labels)
        if not time_series:
            return {
                "count": 0,
                "min": 0,
                "max": 0,
                "mean": 0,
                "p50": 0,
                "p95": 0,
                "p99": 0,
            }

        values = [v.value for v in time_series]
        return {
            "count": len(values),
            "min": min(values),
            "max": max(values),
            "mean": sum(values) / len(values),
            "p50": self.calculate_percentile(name, 50, labels),
            "p95": self.calculate_percentile(name, 95, labels),
            "p99": self.calculate_percentile(name, 99, labels),
        }

    async def collect_system_metrics(self):
        """Collect system-level metrics"""
        import psutil

        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        self.set_gauge("system_cpu_usage", cpu_percent, {"host": "localhost"})

        # Memory usage
        memory = psutil.virtual_memory()
        self.set_gauge("system_memory_usage", memory.percent, {"host": "localhost"})
        self.set_gauge("system_memory_available", memory.available, {"host": "localhost"})

        # Disk usage
        disk = psutil.disk_usage("/")
        self.set_gauge("system_disk_usage", disk.percent, {"host": "localhost"})
        self.set_gauge("system_disk_free", disk.free, {"host": "localhost"})

        # Network I/O
        net_io = psutil.net_io_counters()
        self.set_gauge("system_network_bytes_sent", net_io.bytes_sent, {"host": "localhost"})
        self.set_gauge("system_network_bytes_recv", net_io.bytes_recv, {"host": "localhost"})

    def export_metrics(self, format: str = "prometheus") -> str:
        """
        Export metrics in specified format

        Args:
            format: Export format (prometheus, json)

        Returns:
            Exported metrics
        """
        if format == "prometheus":
            from prometheus_client import generate_latest
            return generate_latest().decode("utf-8")
        elif format == "json":
            import json
            metrics_data = {}
            for name, metric_info in self.metrics.items():
                metrics_data[name] = {
                    "type": metric_info["definition"].type.value,
                    "description": metric_info["definition"].description,
                    "unit": metric_info["definition"].unit.value,
                    "summary": self.get_metric_summary(name),
                }
            return json.dumps(metrics_data, indent=2, default=str)
        else:
            raise ValueError(f"Unknown format: {format}")