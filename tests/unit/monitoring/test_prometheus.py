"""
Unit tests for Prometheus exporter.
Tests Prometheus registry, metric formatting, and export functionality.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, Any

from src.monitoring.prometheus import PrometheusRegistry, PrometheusExporter
from src.monitoring.metrics import MetricsCollector, Counter, Gauge, Histogram, Summary


class TestPrometheusRegistry:
    """Test Prometheus registry."""

    def test_registry_initialization(self):
        """Test registry initialization."""
        registry = PrometheusRegistry()

        assert isinstance(registry.metrics, dict)
        assert len(registry.metrics) == 0

    def test_register_metric(self):
        """Test registering a metric."""
        registry = PrometheusRegistry()
        counter = Counter("test_counter", "Test metric")

        registry.register(counter)

        assert "test_counter" in registry.metrics
        assert registry.metrics["test_counter"] is counter

    def test_register_duplicate_metric_raises_error(self):
        """Test registering duplicate metric raises error."""
        registry = PrometheusRegistry()
        counter = Counter("test_counter")

        registry.register(counter)

        with pytest.raises(ValueError, match="already registered"):
            registry.register(counter)

    def test_unregister_metric(self):
        """Test unregistering a metric."""
        registry = PrometheusRegistry()
        counter = Counter("test_counter")

        registry.register(counter)
        assert "test_counter" in registry.metrics

        registry.unregister("test_counter")
        assert "test_counter" not in registry.metrics

    def test_unregister_nonexistent_metric(self):
        """Test unregistering non-existent metric."""
        registry = PrometheusRegistry()

        # Should not raise error
        registry.unregister("nonexistent")

    def test_collect_empty_registry(self):
        """Test collecting from empty registry."""
        registry = PrometheusRegistry()

        lines = registry.collect()

        assert isinstance(lines, list)
        assert len(lines) == 0

    def test_collect_counter_metric(self):
        """Test collecting counter metric."""
        registry = PrometheusRegistry()
        counter = Counter("test_counter", "Test counter metric")
        counter.inc(5)

        registry.register(counter)
        lines = registry.collect()

        assert any("# HELP test_counter Test counter metric" in line for line in lines)
        assert any("# TYPE test_counter counter" in line for line in lines)
        assert any("test_counter" in line and "5" in line for line in lines)

    def test_collect_gauge_metric(self):
        """Test collecting gauge metric."""
        registry = PrometheusRegistry()
        gauge = Gauge("test_gauge", "Test gauge metric")
        gauge.set(42.5)

        registry.register(gauge)
        lines = registry.collect()

        assert any("# TYPE test_gauge gauge" in line for line in lines)
        assert any("42.5" in line for line in lines)

    def test_collect_histogram_metric(self):
        """Test collecting histogram metric."""
        registry = PrometheusRegistry()
        histogram = Histogram("request_duration", "Request duration", buckets=[0.1, 0.5, 1])

        histogram.observe(0.3)
        histogram.observe(0.7)

        registry.register(histogram)
        lines = registry.collect()

        assert any("# TYPE request_duration histogram" in line for line in lines)
        assert any("_bucket" in line for line in lines)
        assert any("_sum" in line for line in lines)
        assert any("_count" in line for line in lines)

    def test_collect_summary_metric(self):
        """Test collecting summary metric."""
        registry = PrometheusRegistry()
        summary = Summary("response_size", "Response size")

        summary.observe(100)
        summary.observe(200)

        registry.register(summary)
        lines = registry.collect()

        assert any("# TYPE response_size summary" in line for line in lines)
        assert any("_sum" in line for line in lines)
        assert any("_count" in line for line in lines)

    def test_format_labels(self):
        """Test label formatting."""
        registry = PrometheusRegistry()

        labels_str = registry._format_labels({"method": "GET", "status": "200"})

        assert labels_str.startswith("{")
        assert labels_str.endswith("}")
        assert 'method="GET"' in labels_str
        assert 'status="200"' in labels_str

    def test_format_empty_labels(self):
        """Test formatting empty labels."""
        registry = PrometheusRegistry()

        labels_str = registry._format_labels({})

        assert labels_str == ""

    def test_format_labels_escapes_special_chars(self):
        """Test label formatting escapes special characters."""
        registry = PrometheusRegistry()

        labels_str = registry._format_labels({"path": '/api/v1"test\n'})

        assert '\\"' in labels_str  # Escaped quote
        assert '\\n' in labels_str  # Escaped newline

    def test_get_prometheus_type(self):
        """Test getting Prometheus metric type."""
        registry = PrometheusRegistry()

        assert registry._get_prometheus_type(Counter("c")) == "counter"
        assert registry._get_prometheus_type(Gauge("g")) == "gauge"
        assert registry._get_prometheus_type(Histogram("h")) == "histogram"
        assert registry._get_prometheus_type(Summary("s")) == "summary"

    def test_collect_multiple_metrics(self):
        """Test collecting multiple metrics."""
        registry = PrometheusRegistry()

        counter = Counter("requests_total")
        counter.inc(10)

        gauge = Gauge("cpu_usage")
        gauge.set(75.5)

        registry.register(counter)
        registry.register(gauge)

        lines = registry.collect()

        # Should have help and type for each metric
        assert sum(1 for line in lines if "# HELP" in line) == 2
        assert sum(1 for line in lines if "# TYPE" in line) == 2


class TestPrometheusExporter:
    """Test Prometheus exporter."""

    @pytest.fixture
    def metrics_collector(self):
        """Create metrics collector."""
        return MetricsCollector()

    @pytest.fixture
    def exporter(self, metrics_collector):
        """Create Prometheus exporter."""
        with patch('src.monitoring.prometheus.get_settings') as mock_settings:
            mock_settings.return_value.VERSION = "1.0.0"
            mock_settings.return_value.BUILD_DATE = "2025-10-10"
            mock_settings.return_value.GIT_COMMIT = "abc123"

            return PrometheusExporter(metrics_collector)

    def test_exporter_initialization(self, exporter):
        """Test exporter initialization."""
        assert exporter.metrics_collector is not None
        assert isinstance(exporter.registry, PrometheusRegistry)

    def test_exporter_registers_metrics(self, exporter, metrics_collector):
        """Test exporter registers collector metrics."""
        # Exporter should register all metrics from collector
        for name in metrics_collector.metrics:
            assert name in exporter.registry.metrics

    def test_exporter_creates_build_info(self, exporter):
        """Test exporter creates build info metric."""
        assert "catnet_build_info" in exporter.metrics_collector.metrics

        build_info = exporter.metrics_collector.metrics["catnet_build_info"]
        value = build_info.get(labels={"version": "1.0.0", "build_date": "2025-10-10", "git_commit": "abc123"})

        assert value == 1

    def test_exporter_creates_process_start_time(self, exporter):
        """Test exporter creates process start time metric."""
        assert "catnet_process_start_time_seconds" in exporter.metrics_collector.metrics

        start_time = exporter.metrics_collector.metrics["catnet_process_start_time_seconds"]
        value = start_time.get()

        assert value > 0

    @pytest.mark.asyncio
    async def test_export_metrics(self, exporter):
        """Test exporting metrics."""
        with patch.object(exporter, '_collect_system_metrics', new=AsyncMock()), \
             patch.object(exporter, '_collect_application_metrics', new=AsyncMock()):

            result = await exporter.export()

            assert isinstance(result, str)
            assert len(result) > 0
            assert "# Generated at" in result

    @pytest.mark.asyncio
    async def test_export_includes_all_metrics(self, exporter, metrics_collector):
        """Test export includes all registered metrics."""
        counter = metrics_collector.counter("test_counter")
        counter.inc(5)

        with patch.object(exporter, '_collect_system_metrics', new=AsyncMock()), \
             patch.object(exporter, '_collect_application_metrics', new=AsyncMock()):

            result = await exporter.export()

            assert "test_counter" in result

    @pytest.mark.asyncio
    async def test_export_error_handling(self, exporter):
        """Test export handles errors gracefully."""
        with patch.object(exporter, '_collect_system_metrics', side_effect=Exception("Test error")):
            with pytest.raises(Exception):
                await exporter.export()

            exporter.audit.log_event.assert_called()

    @pytest.mark.asyncio
    async def test_collect_system_metrics(self, exporter):
        """Test collecting system metrics."""
        with patch('src.monitoring.prometheus.psutil') as mock_psutil:
            mock_psutil.cpu_percent.return_value = 45.5
            mock_psutil.virtual_memory.return_value = MagicMock(
                percent=60.0,
                used=8589934592,
                total=17179869184
            )
            mock_psutil.disk_partitions.return_value = []
            mock_psutil.net_io_counters.return_value = MagicMock(
                bytes_sent=1000000,
                bytes_recv=2000000,
                packets_sent=5000,
                packets_recv=10000
            )
            mock_process = MagicMock()
            mock_process.cpu_percent.return_value = 5.5
            mock_process.memory_info.return_value = MagicMock(rss=1073741824, vms=2147483648)
            mock_process.open_files.return_value = []
            mock_process.num_threads.return_value = 10
            mock_psutil.Process.return_value = mock_process

            await exporter._collect_system_metrics()

            # Check CPU metric was set
            cpu_gauge = exporter.metrics_collector.metrics["catnet_system_cpu_usage_percent"]
            assert cpu_gauge.get() == 45.5

            # Check memory metric was set
            memory_gauge = exporter.metrics_collector.metrics["catnet_system_memory_usage_percent"]
            assert memory_gauge.get() == 60.0

    @pytest.mark.asyncio
    async def test_collect_application_metrics(self, exporter):
        """Test collecting application metrics."""
        # Mock database queries
        with patch('src.monitoring.prometheus.get_db') as mock_get_db:
            mock_db = AsyncMock()
            mock_db.execute = AsyncMock(return_value=[])
            mock_db.pool.status.return_value = {'size': 10, 'available': 5, 'in_use': 5}

            mock_get_db.return_value.__aenter__.return_value = mock_db
            mock_get_db.return_value.__aexit__.return_value = AsyncMock()

            # Should not raise exception even if queries fail
            await exporter._collect_application_metrics()

    def test_format_for_pushgateway(self, exporter, metrics_collector):
        """Test formatting metrics for Pushgateway."""
        counter = metrics_collector.counter("test_counter")
        counter.inc(5)

        formatted = exporter.format_for_pushgateway(job="catnet", instance="server1")

        assert isinstance(formatted, str)
        assert 'job="catnet"' in formatted
        assert 'instance="server1"' in formatted

    def test_format_for_pushgateway_without_instance(self, exporter, metrics_collector):
        """Test formatting for Pushgateway without instance."""
        counter = metrics_collector.counter("test_counter")
        counter.inc(3)

        formatted = exporter.format_for_pushgateway(job="catnet")

        assert 'job="catnet"' in formatted
        assert "instance=" not in formatted

    @pytest.mark.asyncio
    async def test_push_to_gateway_success(self, exporter):
        """Test pushing metrics to Pushgateway."""
        with patch('src.monitoring.prometheus.aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200

            mock_put = AsyncMock()
            mock_put.__aenter__.return_value = mock_response
            mock_put.__aexit__.return_value = AsyncMock()

            mock_session.return_value.__aenter__.return_value.put = mock_put
            mock_session.return_value.__aexit__.return_value = AsyncMock()

            await exporter.push_to_gateway(
                gateway_url="http://pushgateway:9091",
                job="catnet",
                instance="server1"
            )

            exporter.audit.log_event.assert_called_with(
                event_type="PROMETHEUS_PUSH_SUCCESS",
                details={
                    'gateway_url': "http://pushgateway:9091",
                    'job': "catnet",
                    'instance': "server1"
                }
            )

    @pytest.mark.asyncio
    async def test_push_to_gateway_failure(self, exporter):
        """Test push to Pushgateway handles failures."""
        with patch('src.monitoring.prometheus.aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 500

            mock_put = AsyncMock()
            mock_put.__aenter__.return_value = mock_response
            mock_put.__aexit__.return_value = AsyncMock()

            mock_session.return_value.__aenter__.return_value.put = mock_put
            mock_session.return_value.__aexit__.return_value = AsyncMock()

            with pytest.raises(Exception, match="Push failed"):
                await exporter.push_to_gateway(
                    gateway_url="http://pushgateway:9091",
                    job="catnet"
                )

            # Should log error
            assert exporter.audit.log_event.call_count >= 1


class TestPrometheusFormatting:
    """Test Prometheus format compatibility."""

    def test_counter_format(self):
        """Test counter Prometheus format."""
        registry = PrometheusRegistry()
        counter = Counter("http_requests_total", "Total HTTP requests")
        counter.inc(10)

        registry.register(counter)
        lines = registry.collect()

        # Should have standard Prometheus format
        help_line = [l for l in lines if "# HELP" in l][0]
        type_line = [l for l in lines if "# TYPE" in l][0]

        assert "http_requests_total" in help_line
        assert "counter" in type_line

    def test_histogram_buckets_format(self):
        """Test histogram bucket format."""
        registry = PrometheusRegistry()
        histogram = Histogram("http_request_duration_seconds", buckets=[0.1, 0.5, 1])

        histogram.observe(0.3)

        registry.register(histogram)
        lines = registry.collect()

        # Should have bucket lines
        bucket_lines = [l for l in lines if "_bucket" in l]
        assert len(bucket_lines) > 0

        # Should have +Inf bucket
        inf_line = [l for l in bucket_lines if '+Inf' in l]
        assert len(inf_line) > 0

    def test_label_sorting(self):
        """Test labels are sorted in output."""
        registry = PrometheusRegistry()
        counter = Counter("test", labels=["z", "a", "m"])

        counter.inc(labels={"z": "1", "a": "2", "m": "3"})

        registry.register(counter)
        lines = registry.collect()

        metric_line = [l for l in lines if "test{" in l][0]

        # Labels should be alphabetically sorted
        labels_part = metric_line.split("{")[1].split("}")[0]
        label_keys = [l.split("=")[0] for l in labels_part.split(",")]

        assert label_keys == sorted(label_keys)

    def test_timestamp_format(self):
        """Test metric timestamps are in milliseconds."""
        registry = PrometheusRegistry()
        counter = Counter("test")
        counter.inc()

        registry.register(counter)
        lines = registry.collect()

        metric_line = [l for l in lines if "test" in l and "# " not in l][0]

        # Should have timestamp in milliseconds
        parts = metric_line.split()
        if len(parts) == 3:
            timestamp = int(parts[2])
            # Should be in milliseconds (13 digits)
            assert len(str(timestamp)) == 13


class TestMetricsWithLabels:
    """Test metrics with label handling."""

    def test_counter_with_multiple_label_values(self):
        """Test counter with multiple label value combinations."""
        registry = PrometheusRegistry()
        counter = Counter("requests", labels=["method", "status"])

        counter.inc(labels={"method": "GET", "status": "200"})
        counter.inc(labels={"method": "POST", "status": "201"})

        registry.register(counter)
        lines = registry.collect()

        # Should have separate lines for each label combination
        metric_lines = [l for l in lines if "requests{" in l]
        assert len(metric_lines) == 2

    def test_gauge_label_consistency(self):
        """Test gauge maintains label consistency."""
        registry = PrometheusRegistry()
        gauge = Gauge("temperature", labels=["location"])

        gauge.set(20, labels={"location": "room1"})
        gauge.set(25, labels={"location": "room2"})

        registry.register(gauge)
        lines = registry.collect()

        metric_lines = [l for l in lines if "temperature{" in l]

        # Each location should have its own value
        room1_line = [l for l in metric_lines if "room1" in l][0]
        room2_line = [l for l in metric_lines if "room2" in l][0]

        assert "20" in room1_line
        assert "25" in room2_line
