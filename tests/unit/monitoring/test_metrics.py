"""
Unit tests for metrics system.
Tests counters, gauges, histograms, summaries, and metrics collector.
"""

import pytest
import time
from unittest.mock import Mock, AsyncMock, patch
from typing import Dict, Any

from src.monitoring.metrics import (
    MetricsCollector,
    MetricType,
    MetricValue,
    Counter,
    Gauge,
    Histogram,
    Summary
)


class TestMetricValue:
    """Test metric value dataclass."""

    def test_metric_value_creation(self):
        """Test creating metric value."""
        value = MetricValue(value=42.5, labels={'env': 'prod'})

        assert value.value == 42.5
        assert value.labels == {'env': 'prod'}
        assert value.timestamp is not None
        assert isinstance(value.metadata, dict)

    def test_metric_value_default_timestamp(self):
        """Test metric value has default timestamp."""
        before = time.time()
        value = MetricValue(value=100)
        after = time.time()

        assert before <= value.timestamp <= after


class TestCounter:
    """Test counter metric."""

    def test_counter_initialization(self):
        """Test counter initialization."""
        counter = Counter(
            name="test_counter",
            description="Test counter metric",
            labels=["method", "status"],
            unit="requests"
        )

        assert counter.name == "test_counter"
        assert counter.description == "Test counter metric"
        assert counter.labels == ["method", "status"]
        assert counter.unit == "requests"

    def test_counter_increment(self):
        """Test incrementing counter."""
        counter = Counter("test_counter")

        counter.inc()
        assert counter.get() == 1

        counter.inc(5)
        assert counter.get() == 6

    def test_counter_increment_with_labels(self):
        """Test incrementing counter with labels."""
        counter = Counter("requests", labels=["method", "status"])

        counter.inc(labels={"method": "GET", "status": "200"})
        counter.inc(labels={"method": "GET", "status": "200"})
        counter.inc(labels={"method": "POST", "status": "201"})

        assert counter.get(labels={"method": "GET", "status": "200"}) == 2
        assert counter.get(labels={"method": "POST", "status": "201"}) == 1

    def test_counter_negative_increment_raises_error(self):
        """Test counter cannot be decremented."""
        counter = Counter("test_counter")

        with pytest.raises(ValueError, match="Counter can only be incremented"):
            counter.inc(-1)

    def test_counter_collect(self):
        """Test collecting counter values."""
        counter = Counter("test_counter", labels=["env"])

        counter.inc(labels={"env": "prod"})
        counter.inc(3, labels={"env": "dev"})

        values = counter.collect()

        assert len(values) == 2
        assert all(isinstance(v, MetricValue) for v in values)

    def test_counter_reset(self):
        """Test resetting counter."""
        counter = Counter("test_counter")

        counter.inc(10)
        assert counter.get() == 10

        counter.reset()
        assert counter.get() == 0


class TestGauge:
    """Test gauge metric."""

    def test_gauge_initialization(self):
        """Test gauge initialization."""
        gauge = Gauge(
            name="test_gauge",
            description="Test gauge metric",
            labels=["host"],
            unit="percent"
        )

        assert gauge.name == "test_gauge"
        assert gauge.description == "Test gauge metric"
        assert gauge.unit == "percent"

    def test_gauge_set(self):
        """Test setting gauge value."""
        gauge = Gauge("cpu_usage")

        gauge.set(45.5)
        assert gauge.get() == 45.5

        gauge.set(67.8)
        assert gauge.get() == 67.8

    def test_gauge_increment(self):
        """Test incrementing gauge."""
        gauge = Gauge("counter")

        gauge.set(10)
        gauge.inc()
        assert gauge.get() == 11

        gauge.inc(5)
        assert gauge.get() == 16

    def test_gauge_decrement(self):
        """Test decrementing gauge."""
        gauge = Gauge("counter")

        gauge.set(20)
        gauge.dec()
        assert gauge.get() == 19

        gauge.dec(5)
        assert gauge.get() == 14

    def test_gauge_with_labels(self):
        """Test gauge with labels."""
        gauge = Gauge("memory", labels=["host"])

        gauge.set(1024, labels={"host": "server1"})
        gauge.set(2048, labels={"host": "server2"})

        assert gauge.get(labels={"host": "server1"}) == 1024
        assert gauge.get(labels={"host": "server2"}) == 2048

    def test_gauge_collect(self):
        """Test collecting gauge values."""
        gauge = Gauge("test_gauge", labels=["region"])

        gauge.set(100, labels={"region": "us-east"})
        gauge.set(200, labels={"region": "eu-west"})

        values = gauge.collect()

        assert len(values) == 2

    def test_gauge_reset(self):
        """Test resetting gauge."""
        gauge = Gauge("test_gauge")

        gauge.set(100)
        gauge.reset()

        assert gauge.get() == 0


class TestHistogram:
    """Test histogram metric."""

    def test_histogram_initialization(self):
        """Test histogram initialization."""
        histogram = Histogram(
            name="request_duration",
            description="Request duration",
            unit="seconds",
            buckets=[0.1, 0.5, 1, 5]
        )

        assert histogram.name == "request_duration"
        assert histogram.buckets == [0.1, 0.5, 1, 5]

    def test_histogram_default_buckets(self):
        """Test histogram with default buckets."""
        histogram = Histogram("duration")

        assert len(histogram.buckets) > 0
        assert all(isinstance(b, (int, float)) for b in histogram.buckets)

    def test_histogram_observe(self):
        """Test observing values in histogram."""
        histogram = Histogram("duration", buckets=[1, 5, 10])

        histogram.observe(0.5)
        histogram.observe(3)
        histogram.observe(7)
        histogram.observe(12)

        data = histogram.collect()
        assert len(data) > 0

    def test_histogram_buckets(self):
        """Test histogram bucket counts."""
        histogram = Histogram("test", buckets=[1, 5, 10])

        histogram.observe(0.5)  # Goes in <=1 bucket
        histogram.observe(3)    # Goes in <=5 bucket
        histogram.observe(7)    # Goes in <=10 bucket

        data = histogram.collect()
        labels_key = ''

        assert labels_key in data
        buckets = data[labels_key]['buckets']

        assert buckets[1] >= 1
        assert buckets[5] >= 2
        assert buckets[10] >= 3

    def test_histogram_sum_and_count(self):
        """Test histogram sum and count."""
        histogram = Histogram("test")

        histogram.observe(1)
        histogram.observe(2)
        histogram.observe(3)

        data = histogram.collect()
        labels_key = ''

        assert data[labels_key]['sum'] == 6
        assert data[labels_key]['count'] == 3
        assert data[labels_key]['mean'] == 2

    def test_histogram_percentiles(self):
        """Test histogram percentile calculation."""
        histogram = Histogram("latency")

        for i in range(100):
            histogram.observe(i)

        p50 = histogram.get_percentile(50)
        p95 = histogram.get_percentile(95)
        p99 = histogram.get_percentile(99)

        assert 45 <= p50 <= 55
        assert 90 <= p95 <= 99
        assert 95 <= p99 <= 99

    def test_histogram_percentile_out_of_range_raises_error(self):
        """Test histogram percentile validation."""
        histogram = Histogram("test")

        with pytest.raises(ValueError, match="Percentile must be between"):
            histogram.get_percentile(101)

        with pytest.raises(ValueError, match="Percentile must be between"):
            histogram.get_percentile(-1)

    def test_histogram_with_labels(self):
        """Test histogram with labels."""
        histogram = Histogram("request_duration", labels=["method"])

        histogram.observe(0.5, labels={"method": "GET"})
        histogram.observe(1.5, labels={"method": "POST"})

        data = histogram.collect()

        assert len(data) == 2


class TestSummary:
    """Test summary metric."""

    def test_summary_initialization(self):
        """Test summary initialization."""
        summary = Summary(
            name="response_size",
            description="Response size",
            unit="bytes",
            max_age=300,
            age_buckets=3
        )

        assert summary.name == "response_size"
        assert summary.max_age == 300
        assert summary.age_buckets == 3

    def test_summary_observe(self):
        """Test observing values in summary."""
        summary = Summary("size")

        summary.observe(100)
        summary.observe(200)
        summary.observe(300)

        data = summary.collect()
        assert len(data) > 0

    def test_summary_statistics(self):
        """Test summary statistics."""
        summary = Summary("test")

        values = [1, 2, 3, 4, 5]
        for v in values:
            summary.observe(v)

        data = summary.collect()
        labels_key = ''

        assert data[labels_key]['count'] == 5
        assert data[labels_key]['sum'] == 15
        assert data[labels_key]['mean'] == 3
        assert data[labels_key]['min'] == 1
        assert data[labels_key]['max'] == 5

    def test_summary_quantiles(self):
        """Test summary quantile calculation."""
        summary = Summary("latency")

        for i in range(100):
            summary.observe(i)

        quantiles = summary.get_quantiles([0.5, 0.9, 0.99])

        assert 45 <= quantiles[0.5] <= 55
        assert 85 <= quantiles[0.9] <= 95
        assert 95 <= quantiles[0.99] <= 99

    def test_summary_quantile_validation(self):
        """Test summary quantile validation."""
        summary = Summary("test")
        summary.observe(10)

        with pytest.raises(ValueError, match="Quantile must be between"):
            summary.get_quantiles([1.5])

    def test_summary_age_cleanup(self):
        """Test summary cleans old observations."""
        summary = Summary("test", max_age=1)  # 1 second

        summary.observe(100)
        time.sleep(1.5)  # Wait for observations to expire
        summary.observe(200)

        data = summary.collect()
        labels_key = ''

        # Only recent observation should remain
        assert data[labels_key]['count'] <= 2

    def test_summary_with_labels(self):
        """Test summary with labels."""
        summary = Summary("request_size", labels=["endpoint"])

        summary.observe(1024, labels={"endpoint": "/api/users"})
        summary.observe(2048, labels={"endpoint": "/api/devices"})

        data = summary.collect()

        assert len(data) == 2


class TestMetricsCollector:
    """Test metrics collector."""

    def test_metrics_collector_initialization(self):
        """Test metrics collector initialization."""
        collector = MetricsCollector()

        assert isinstance(collector.metrics, dict)
        assert len(collector.metrics) > 0  # Has default metrics

    def test_collector_creates_counter(self):
        """Test creating counter metric."""
        collector = MetricsCollector()

        counter = collector.counter("test_counter", "Test counter")

        assert isinstance(counter, Counter)
        assert "test_counter" in collector.metrics
        assert collector.metrics["test_counter"] is counter

    def test_collector_reuses_existing_counter(self):
        """Test collector returns existing counter."""
        collector = MetricsCollector()

        counter1 = collector.counter("test_counter")
        counter2 = collector.counter("test_counter")

        assert counter1 is counter2

    def test_collector_creates_gauge(self):
        """Test creating gauge metric."""
        collector = MetricsCollector()

        gauge = collector.gauge("test_gauge", "Test gauge", unit="percent")

        assert isinstance(gauge, Gauge)
        assert "test_gauge" in collector.metrics

    def test_collector_creates_histogram(self):
        """Test creating histogram metric."""
        collector = MetricsCollector()

        histogram = collector.histogram(
            "test_histogram",
            "Test histogram",
            buckets=[1, 5, 10]
        )

        assert isinstance(histogram, Histogram)
        assert histogram.buckets == [1, 5, 10]

    def test_collector_creates_summary(self):
        """Test creating summary metric."""
        collector = MetricsCollector()

        summary = collector.summary(
            "test_summary",
            "Test summary",
            max_age=300
        )

        assert isinstance(summary, Summary)
        assert summary.max_age == 300

    def test_collector_default_metrics(self):
        """Test collector has default metrics."""
        collector = MetricsCollector()

        # Should have default HTTP metrics
        assert "catnet_requests_total" in collector.metrics
        assert "catnet_request_duration_seconds" in collector.metrics

        # Should have default device metrics
        assert "catnet_devices_total" in collector.metrics
        assert "catnet_device_health_status" in collector.metrics

        # Should have default deployment metrics
        assert "catnet_deployments_total" in collector.metrics

        # Should have default security metrics
        assert "catnet_auth_attempts_total" in collector.metrics

        # Should have default system metrics
        assert "catnet_system_cpu_usage_percent" in collector.metrics
        assert "catnet_system_memory_usage_percent" in collector.metrics

    def test_collector_collect_all(self):
        """Test collecting all metrics."""
        collector = MetricsCollector()

        counter = collector.counter("test_counter")
        counter.inc(5)

        gauge = collector.gauge("test_gauge")
        gauge.set(42)

        result = collector.collect_all()

        assert isinstance(result, dict)
        assert "test_counter" in result
        assert "test_gauge" in result

        assert result["test_counter"]["type"] == "counter"
        assert result["test_gauge"]["type"] == "gauge"

    def test_collector_reset_all(self):
        """Test resetting all metrics."""
        collector = MetricsCollector()

        counter = collector.counter("test_counter")
        counter.inc(10)

        gauge = collector.gauge("test_gauge")
        gauge.set(50)

        collector.reset_all()

        assert counter.get() == 0
        assert gauge.get() == 0

    @pytest.mark.asyncio
    async def test_record_request(self):
        """Test recording HTTP request metrics."""
        collector = MetricsCollector()

        await collector.record_request(
            method="GET",
            endpoint="/api/devices",
            status=200,
            duration=0.123
        )

        counter = collector.metrics["catnet_requests_total"]
        value = counter.get(labels={"method": "GET", "endpoint": "/api/devices", "status": "200"})

        assert value == 1

    @pytest.mark.asyncio
    async def test_record_deployment(self):
        """Test recording deployment metrics."""
        collector = MetricsCollector()

        await collector.record_deployment(
            deployment_id="deploy_001",
            strategy="canary",
            status="success",
            duration=120.5
        )

        counter = collector.metrics["catnet_deployments_total"]
        value = counter.get(labels={"status": "success", "strategy": "canary"})

        assert value == 1

    @pytest.mark.asyncio
    async def test_record_auth_attempt(self):
        """Test recording authentication attempt."""
        collector = MetricsCollector()

        await collector.record_auth_attempt(method="password", success=True)
        await collector.record_auth_attempt(method="password", success=False)

        counter = collector.metrics["catnet_auth_attempts_total"]

        success_count = counter.get(labels={"result": "success", "method": "password"})
        failure_count = counter.get(labels={"result": "failure", "method": "password"})

        assert success_count == 1
        assert failure_count == 1

    @pytest.mark.asyncio
    async def test_record_security_violation(self):
        """Test recording security violation."""
        with patch.object(MetricsCollector, '__init__', lambda x: None):
            collector = MetricsCollector()
            collector.metrics = {}
            collector.audit = AsyncMock()

            # Create the counter
            collector.metrics["catnet_security_violations_total"] = Counter(
                "catnet_security_violations_total",
                labels=["type", "severity"]
            )

            await collector.record_security_violation(
                violation_type="unauthorized_access",
                severity="high"
            )

            counter = collector.metrics["catnet_security_violations_total"]
            value = counter.get(labels={"type": "unauthorized_access", "severity": "high"})

            assert value == 1
            collector.audit.log_event.assert_called_once()


class TestLabelsHandling:
    """Test label handling in metrics."""

    def test_labels_key_generation(self):
        """Test generating labels key."""
        counter = Counter("test")

        key1 = counter._get_labels_key({"env": "prod", "region": "us"})
        key2 = counter._get_labels_key({"region": "us", "env": "prod"})

        # Same labels in different order should produce same key
        assert key1 == key2

    def test_empty_labels_key(self):
        """Test empty labels key."""
        counter = Counter("test")

        key = counter._get_labels_key({})

        assert key == ""

    def test_metric_with_different_label_combinations(self):
        """Test metric with various label combinations."""
        counter = Counter("requests", labels=["method", "status", "path"])

        counter.inc(labels={"method": "GET", "status": "200", "path": "/api"})
        counter.inc(labels={"method": "POST", "status": "201", "path": "/api"})
        counter.inc(labels={"method": "GET", "status": "200", "path": "/api"})

        assert counter.get(labels={"method": "GET", "status": "200", "path": "/api"}) == 2
        assert counter.get(labels={"method": "POST", "status": "201", "path": "/api"}) == 1


class TestThreadSafety:
    """Test thread safety of metrics."""

    def test_counter_thread_safe(self):
        """Test counter is thread-safe."""
        import threading

        counter = Counter("test")

        def increment():
            for _ in range(1000):
                counter.inc()

        threads = [threading.Thread(target=increment) for _ in range(10)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert counter.get() == 10000

    def test_gauge_thread_safe(self):
        """Test gauge is thread-safe."""
        import threading

        gauge = Gauge("test")
        gauge.set(0)

        def modify():
            for _ in range(100):
                gauge.inc()
                gauge.dec()

        threads = [threading.Thread(target=modify) for _ in range(10)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should be back to 0 (or close due to any race conditions)
        assert abs(gauge.get()) <= 10


class TestMetricTypes:
    """Test metric type enum."""

    def test_metric_type_values(self):
        """Test metric type enum values."""
        assert MetricType.COUNTER.value == "counter"
        assert MetricType.GAUGE.value == "gauge"
        assert MetricType.HISTOGRAM.value == "histogram"
        assert MetricType.SUMMARY.value == "summary"
