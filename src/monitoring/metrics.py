"""
Core metrics implementation for CatNet monitoring.
Provides metric types and collection interfaces.
"""

import time
import asyncio
from typing import Dict, List, Optional, Any, Union, Callable
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict, deque
import threading
from dataclasses import dataclass, field

from src.core.exceptions import MetricsError
from src.security.audit import AuditLogger


class MetricType(Enum):
    """Metric type enumeration."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


@dataclass
class MetricValue:
    """Single metric value with metadata."""

    value: float
    timestamp: float = field(default_factory=time.time)
    labels: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseMetric:
    """Base class for all metric types."""

    def __init__(
        self,
        name: str,
        description: str = "",
        labels: Optional[List[str]] = None,
        unit: str = ""
    ):
        """
        Initialize base metric.

        Args:
            name: Metric name
            description: Metric description
            labels: Label names
            unit: Unit of measurement
        """
        self.name = name
        self.description = description
        self.labels = labels or []
        self.unit = unit
        self._lock = threading.Lock()
        self._values = defaultdict(lambda: MetricValue(0))

    def _get_labels_key(self, labels: Dict[str, str]) -> str:
        """Generate key from labels."""
        if not labels:
            return ""
        return "|".join(f"{k}:{v}" for k, v in sorted(labels.items()))

    def reset(self):
        """Reset metric values."""
        with self._lock:
            self._values.clear()


class Counter(BaseMetric):
    """
    Counter metric - monotonically increasing value.
    Used for counting events, requests, errors, etc.
    """

    def inc(self, amount: float = 1, labels: Optional[Dict[str, str]] = None):
        """
        Increment counter.

        Args:
            amount: Amount to increment
            labels: Label values
        """
        if amount < 0:
            raise ValueError("Counter can only be incremented")

        labels_key = self._get_labels_key(labels or {})

        with self._lock:
            if labels_key not in self._values:
                self._values[labels_key] = MetricValue(0, labels=labels or {})
            self._values[labels_key].value += amount
            self._values[labels_key].timestamp = time.time()

    def get(self, labels: Optional[Dict[str, str]] = None) -> float:
        """Get current counter value."""
        labels_key = self._get_labels_key(labels or {})
        with self._lock:
            return self._values.get(labels_key, MetricValue(0)).value

    def collect(self) -> List[MetricValue]:
        """Collect all metric values."""
        with self._lock:
            return list(self._values.values())


class Gauge(BaseMetric):
    """
    Gauge metric - value that can go up or down.
    Used for current values like temperature, memory usage, etc.
    """

    def set(self, value: float, labels: Optional[Dict[str, str]] = None):
        """
        Set gauge value.

        Args:
            value: Value to set
            labels: Label values
        """
        labels_key = self._get_labels_key(labels or {})

        with self._lock:
            self._values[labels_key] = MetricValue(value, labels=labels or {})

    def inc(self, amount: float = 1, labels: Optional[Dict[str, str]] = None):
        """Increment gauge value."""
        labels_key = self._get_labels_key(labels or {})

        with self._lock:
            if labels_key not in self._values:
                self._values[labels_key] = MetricValue(0, labels=labels or {})
            self._values[labels_key].value += amount
            self._values[labels_key].timestamp = time.time()

    def dec(self, amount: float = 1, labels: Optional[Dict[str, str]] = None):
        """Decrement gauge value."""
        self.inc(-amount, labels)

    def get(self, labels: Optional[Dict[str, str]] = None) -> float:
        """Get current gauge value."""
        labels_key = self._get_labels_key(labels or {})
        with self._lock:
            return self._values.get(labels_key, MetricValue(0)).value

    def collect(self) -> List[MetricValue]:
        """Collect all metric values."""
        with self._lock:
            return list(self._values.values())


class Histogram(BaseMetric):
    """
    Histogram metric - samples observations and counts them in buckets.
    Used for request durations, response sizes, etc.
    """

    def __init__(
        self,
        name: str,
        description: str = "",
        labels: Optional[List[str]] = None,
        unit: str = "",
        buckets: Optional[List[float]] = None
    ):
        """Initialize histogram with buckets."""
        super().__init__(name, description, labels, unit)
        self.buckets = buckets or [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]
        self._observations = defaultdict(list)
        self._bucket_counts = defaultdict(lambda: defaultdict(int))
        self._sums = defaultdict(float)
        self._counts = defaultdict(int)

    def observe(self, value: float, labels: Optional[Dict[str, str]] = None):
        """
        Record an observation.

        Args:
            value: Observed value
            labels: Label values
        """
        labels_key = self._get_labels_key(labels or {})

        with self._lock:
            # Update buckets
            for bucket in self.buckets:
                if value <= bucket:
                    self._bucket_counts[labels_key][bucket] += 1

            # Update sum and count
            self._sums[labels_key] += value
            self._counts[labels_key] += 1

            # Store observation (keep last 1000)
            observations = self._observations[labels_key]
            observations.append(value)
            if len(observations) > 1000:
                observations.pop(0)

    def get_percentile(
        self,
        percentile: float,
        labels: Optional[Dict[str, str]] = None
    ) -> Optional[float]:
        """Get percentile value."""
        if not 0 <= percentile <= 100:
            raise ValueError("Percentile must be between 0 and 100")

        labels_key = self._get_labels_key(labels or {})

        with self._lock:
            observations = self._observations.get(labels_key, [])
            if not observations:
                return None

            sorted_obs = sorted(observations)
            index = int(len(sorted_obs) * percentile / 100)
            return sorted_obs[min(index, len(sorted_obs) - 1)]

    def collect(self) -> Dict[str, Any]:
        """Collect histogram data."""
        with self._lock:
            result = {}
            for labels_key in self._counts:
                result[labels_key] = {
                    'buckets': dict(self._bucket_counts[labels_key]),
                    'sum': self._sums[labels_key],
                    'count': self._counts[labels_key],
                    'mean': self._sums[labels_key] / self._counts[labels_key] if self._counts[labels_key] > 0 else 0,
                    'p50': self.get_percentile(50, labels={'key': labels_key}),
                    'p95': self.get_percentile(95, labels={'key': labels_key}),
                    'p99': self.get_percentile(99, labels={'key': labels_key})
                }
            return result


class Summary(BaseMetric):
    """
    Summary metric - similar to histogram but calculates percentiles.
    Used for request sizes, latencies, etc.
    """

    def __init__(
        self,
        name: str,
        description: str = "",
        labels: Optional[List[str]] = None,
        unit: str = "",
        max_age: int = 600,
        age_buckets: int = 5
    ):
        """Initialize summary with time windows."""
        super().__init__(name, description, labels, unit)
        self.max_age = max_age
        self.age_buckets = age_buckets
        self._observations = defaultdict(lambda: deque(maxlen=10000))
        self._time_windows = defaultdict(lambda: deque(maxlen=age_buckets))

    def observe(self, value: float, labels: Optional[Dict[str, str]] = None):
        """Record an observation."""
        labels_key = self._get_labels_key(labels or {})
        current_time = time.time()

        with self._lock:
            # Add to observations
            self._observations[labels_key].append((current_time, value))

            # Clean old observations
            cutoff_time = current_time - self.max_age
            observations = self._observations[labels_key]
            while observations and observations[0][0] < cutoff_time:
                observations.popleft()

    def get_quantiles(
        self,
        quantiles: List[float],
        labels: Optional[Dict[str, str]] = None
    ) -> Dict[float, Optional[float]]:
        """Get multiple quantiles."""
        labels_key = self._get_labels_key(labels or {})

        with self._lock:
            observations = self._observations.get(labels_key, deque())
            if not observations:
                return {q: None for q in quantiles}

            values = sorted([v for _, v in observations])
            result = {}

            for quantile in quantiles:
                if not 0 <= quantile <= 1:
                    raise ValueError("Quantile must be between 0 and 1")
                index = int(len(values) * quantile)
                result[quantile] = values[min(index, len(values) - 1)]

            return result

    def collect(self) -> Dict[str, Any]:
        """Collect summary data."""
        with self._lock:
            result = {}
            for labels_key, observations in self._observations.items():
                if observations:
                    values = [v for _, v in observations]
                    result[labels_key] = {
                        'count': len(values),
                        'sum': sum(values),
                        'mean': sum(values) / len(values),
                        'min': min(values),
                        'max': max(values),
                        'quantiles': self.get_quantiles([0.5, 0.9, 0.95, 0.99], labels={'key': labels_key})
                    }
            return result


class MetricsCollector:
    """
    Central metrics collector for the application.
    Manages all metrics and provides collection interface.
    """

    def __init__(self):
        """Initialize metrics collector."""
        self.metrics: Dict[str, BaseMetric] = {}
        self._lock = threading.Lock()
        self.audit = AuditLogger()

        # Register default metrics
        self._register_default_metrics()

    def _register_default_metrics(self):
        """Register default system metrics."""
        # Request metrics
        self.counter(
            "catnet_requests_total",
            "Total number of HTTP requests",
            labels=["method", "endpoint", "status"]
        )

        self.histogram(
            "catnet_request_duration_seconds",
            "HTTP request duration in seconds",
            labels=["method", "endpoint"],
            buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]
        )

        # Device metrics
        self.gauge(
            "catnet_devices_total",
            "Total number of devices",
            labels=["vendor", "status"]
        )

        self.gauge(
            "catnet_device_health_status",
            "Device health status (1=healthy, 0=unhealthy)",
            labels=["device_id", "device_name"]
        )

        # Deployment metrics
        self.counter(
            "catnet_deployments_total",
            "Total number of deployments",
            labels=["status", "strategy"]
        )

        self.histogram(
            "catnet_deployment_duration_seconds",
            "Deployment duration in seconds",
            labels=["strategy", "result"]
        )

        # Security metrics
        self.counter(
            "catnet_auth_attempts_total",
            "Total authentication attempts",
            labels=["result", "method"]
        )

        self.counter(
            "catnet_security_violations_total",
            "Total security violations",
            labels=["type", "severity"]
        )

        # System metrics
        self.gauge(
            "catnet_system_cpu_usage_percent",
            "System CPU usage percentage"
        )

        self.gauge(
            "catnet_system_memory_usage_percent",
            "System memory usage percentage"
        )

        self.gauge(
            "catnet_system_disk_usage_percent",
            "System disk usage percentage",
            labels=["mount_point"]
        )

    def counter(
        self,
        name: str,
        description: str = "",
        labels: Optional[List[str]] = None,
        unit: str = ""
    ) -> Counter:
        """
        Create or get a counter metric.

        Args:
            name: Metric name
            description: Metric description
            labels: Label names
            unit: Unit of measurement

        Returns:
            Counter instance
        """
        with self._lock:
            if name not in self.metrics:
                self.metrics[name] = Counter(name, description, labels, unit)
            return self.metrics[name]

    def gauge(
        self,
        name: str,
        description: str = "",
        labels: Optional[List[str]] = None,
        unit: str = ""
    ) -> Gauge:
        """Create or get a gauge metric."""
        with self._lock:
            if name not in self.metrics:
                self.metrics[name] = Gauge(name, description, labels, unit)
            return self.metrics[name]

    def histogram(
        self,
        name: str,
        description: str = "",
        labels: Optional[List[str]] = None,
        unit: str = "",
        buckets: Optional[List[float]] = None
    ) -> Histogram:
        """Create or get a histogram metric."""
        with self._lock:
            if name not in self.metrics:
                self.metrics[name] = Histogram(name, description, labels, unit, buckets)
            return self.metrics[name]

    def summary(
        self,
        name: str,
        description: str = "",
        labels: Optional[List[str]] = None,
        unit: str = "",
        max_age: int = 600,
        age_buckets: int = 5
    ) -> Summary:
        """Create or get a summary metric."""
        with self._lock:
            if name not in self.metrics:
                self.metrics[name] = Summary(name, description, labels, unit, max_age, age_buckets)
            return self.metrics[name]

    def collect_all(self) -> Dict[str, Any]:
        """Collect all metrics."""
        result = {}

        with self._lock:
            for name, metric in self.metrics.items():
                if isinstance(metric, (Counter, Gauge)):
                    result[name] = {
                        'type': metric.__class__.__name__.lower(),
                        'description': metric.description,
                        'values': [
                            {
                                'value': mv.value,
                                'labels': mv.labels,
                                'timestamp': mv.timestamp
                            }
                            for mv in metric.collect()
                        ]
                    }
                elif isinstance(metric, (Histogram, Summary)):
                    result[name] = {
                        'type': metric.__class__.__name__.lower(),
                        'description': metric.description,
                        'data': metric.collect()
                    }

        return result

    def reset_all(self):
        """Reset all metrics."""
        with self._lock:
            for metric in self.metrics.values():
                metric.reset()

    async def record_request(
        self,
        method: str,
        endpoint: str,
        status: int,
        duration: float
    ):
        """Record HTTP request metrics."""
        # Increment request counter
        self.counter("catnet_requests_total").inc(
            labels={"method": method, "endpoint": endpoint, "status": str(status)}
        )

        # Record request duration
        self.histogram("catnet_request_duration_seconds").observe(
            duration,
            labels={"method": method, "endpoint": endpoint}
        )

    async def record_deployment(
        self,
        deployment_id: str,
        strategy: str,
        status: str,
        duration: float = None
    ):
        """Record deployment metrics."""
        # Increment deployment counter
        self.counter("catnet_deployments_total").inc(
            labels={"status": status, "strategy": strategy}
        )

        # Record deployment duration if provided
        if duration is not None:
            self.histogram("catnet_deployment_duration_seconds").observe(
                duration,
                labels={"strategy": strategy, "result": status}
            )

    async def record_auth_attempt(
        self,
        method: str,
        success: bool
    ):
        """Record authentication attempt."""
        result = "success" if success else "failure"
        self.counter("catnet_auth_attempts_total").inc(
            labels={"result": result, "method": method}
        )

    async def record_security_violation(
        self,
        violation_type: str,
        severity: str
    ):
        """Record security violation."""
        self.counter("catnet_security_violations_total").inc(
            labels={"type": violation_type, "severity": severity}
        )

        # Log to audit
        await self.audit.log_event(
            event_type="SECURITY_VIOLATION_METRIC",
            details={
                'type': violation_type,
                'severity': severity,
                'timestamp': datetime.utcnow().isoformat()
            }
        )


# Global metrics collector instance
metrics_collector = MetricsCollector()


# Export main components
__all__ = [
    'MetricsCollector',
    'MetricType',
    'MetricValue',
    'Counter',
    'Gauge',
    'Histogram',
    'Summary',
    'metrics_collector'
]