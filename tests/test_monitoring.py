"""
Comprehensive tests for CatNet Monitoring and Observability
"""

import pytest
import asyncio
from datetime import datetime, timedelta
import json

from src.monitoring.metrics import (
    MetricsCollector,
    MetricType,
    MetricUnit,
    MetricDefinition,
)
from src.monitoring.alerting import (
    AlertManager,
    Alert,
    AlertRule,
    AlertCondition,
    AlertSeverity,
    AlertState,
)
from src.monitoring.observability import (
    ObservabilityService,
    SpanKind,
    TraceLevel,
)



class TestMetricsCollector:
    """Test metrics collection"""

    def setup_method(self):
        """Setup test environment"""
        self.collector = MetricsCollector(namespace="test")

    def test_register_metric(self):
        """Test registering custom metrics"""
        # Register a counter
        self.collector.register_metric(
            MetricDefinition(
                name="test_counter",
                type=MetricType.COUNTER,
                description="Test counter",
                unit=MetricUnit.COUNT,
                labels=["test_label"],
            )
        )

        assert "test_counter" in self.collector.metrics

    def test_increment_counter(self):
        """Test incrementing counter metric"""
        # Register counter
        self.collector.register_metric(
            MetricDefinition(
                name="request_count",
                type=MetricType.COUNTER,
                description="Request count",
                unit=MetricUnit.REQUESTS,
                labels=["method", "status"],
            )
        )

        # Increment counter
        self.collector.increment_counter(
            "request_count",
            value=1,
            labels={"method": "GET", "status": "200"},
        )

        # Check time series
        time_series = self.collector.get_time_series("request_count")
        assert len(time_series) > 0
        assert time_series[0].value == 1

    def test_set_gauge(self):
        """Test setting gauge metric"""
        # Register gauge
        self.collector.register_metric(
            MetricDefinition(
                name="cpu_usage",
                type=MetricType.GAUGE,
                description="CPU usage",
                unit=MetricUnit.PERCENTAGE,
                labels=["host"],
            )
        )

        # Set gauge value
        self.collector.set_gauge(
            "cpu_usage",
            value=75.5,
            labels={"host": "server1"},
        )

        # Check time series
        time_series = self.collector.get_time_series("cpu_usage")
        assert len(time_series) > 0
        assert time_series[0].value == 75.5

    def test_observe_histogram(self):
        """Test observing histogram metric"""
        # Register histogram
        self.collector.register_metric(
            MetricDefinition(
                name="response_time",
                type=MetricType.HISTOGRAM,
                description="Response time",
                unit=MetricUnit.MILLISECONDS,
                labels=["endpoint"],
                buckets=[10, 50, 100, 500, 1000],
            )
        )

        # Observe values
        for value in [25, 75, 150, 450, 1200]:
            self.collector.observe_histogram(
                "response_time",
                value=value,
                labels={"endpoint": "/api/test"},
            )

        # Check time series
        time_series = self.collector.get_time_series("response_time")
        assert len(time_series) == 5

    def test_calculate_rate(self):
        """Test rate calculation for counters"""
        # Register counter
        self.collector.register_metric(
            MetricDefinition(
                name="bytes_sent",
                type=MetricType.COUNTER,
                description="Bytes sent",
                unit=MetricUnit.BYTES,
            )
        )

        # Add values over time
        for i in range(10):
            self.collector.increment_counter("bytes_sent", value=100)

        # Calculate rate
        rate = self.collector.calculate_rate(
            "bytes_sent",
            window=timedelta(seconds=10),
        )

        assert rate >= 0

    def test_calculate_percentile(self):
        """Test percentile calculation"""
        # Register metric
        self.collector.register_metric(
            MetricDefinition(
                name="latency",
                type=MetricType.HISTOGRAM,
                description="Latency",
                unit=MetricUnit.MILLISECONDS,
            )
        )

        # Add values
        values = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
        for value in values:
            self.collector.observe_histogram("latency", value)

        # Calculate percentiles
        p50 = self.collector.calculate_percentile("latency", 50)
        p95 = self.collector.calculate_percentile("latency", 95)

        assert 40 <= p50 <= 60
        assert p95 >= 90

    def test_export_metrics(self):
        """Test metrics export"""
        # Add some metrics
        self.collector.register_metric(
            MetricDefinition(
                name="test_metric",
                type=MetricType.GAUGE,
                description="Test metric",
                unit=MetricUnit.COUNT,
            )
        )
        self.collector.set_gauge("test_metric", 42)

        # Export as JSON
        json_export = self.collector.export_metrics(format="json")
        data = json.loads(json_export)

        assert "test_metric" in data
        assert data["test_metric"]["type"] == "gauge"



class TestAlertManager:
    """Test alert management"""

    def setup_method(self):
        """Setup test environment"""
        self.metrics_collector = MetricsCollector()
        self.alert_manager = AlertManager( \
            metrics_collector=self.metrics_collector)

    def test_add_alert_rule(self):
        """Test adding alert rules"""
        rule = AlertRule(
            id="test_rule",
            name="Test Alert",
            description="Test alert rule",
            severity=AlertSeverity.MEDIUM,
            conditions=[
                AlertCondition(
                    metric="test_metric",
                    operator=">",
                    threshold=100,
                    duration=timedelta(minutes=1),
                )
            ],
        )

        self.alert_manager.add_rule(rule)
        assert "test_rule" in self.alert_manager.rules

    @pytest.mark.asyncio
    async def test_trigger_alert(self):
        """Test alert triggering"""
        # Setup metric
        self.metrics_collector.register_metric(
            MetricDefinition(
                name="error_count",
                type=MetricType.COUNTER,
                description="Error count",
                unit=MetricUnit.ERRORS,
            )
        )

        # Add alert rule
        rule = AlertRule(
            id="high_errors",
            name="High Error Count",
            description="Too many errors",
            severity=AlertSeverity.HIGH,
            conditions=[
                AlertCondition(
                    metric="error_count",
                    operator=">",
                    threshold=10,
                    duration=timedelta(seconds=0),
                )
            ],
        )
        self.alert_manager.add_rule(rule)

        # Add metric values that trigger alert
        for _ in range(15):
            self.metrics_collector.increment_counter("error_count")

        # Evaluate rules
        await self.alert_manager._evaluate_rules()

        # Check if alert fired
        active_alerts = self.alert_manager.get_active_alerts()
        assert len(active_alerts) > 0
        assert active_alerts[0].severity == AlertSeverity.HIGH

    def test_acknowledge_alert(self):
        """Test alert acknowledgement"""
        # Create alert
        alert = Alert(
            id="alert-1",
            rule_id="test_rule",
            name="Test Alert",
            severity=AlertSeverity.MEDIUM,
            state=AlertState.FIRING,
            message="Test alert message",
            started_at=datetime.utcnow(),
        )
        self.alert_manager.active_alerts["test_rule"] = alert

        # Acknowledge alert
        success = self.alert_manager.acknowledge_alert("alert-1", "user1")

        assert success
        assert alert.state == AlertState.ACKNOWLEDGED
        assert alert.acknowledged_by == "user1"

    def test_suppress_alert(self):
        """Test alert suppression"""
        # Create alert
        alert = Alert(
            id="alert-2",
            rule_id="test_rule",
            name="Test Alert",
            severity=AlertSeverity.LOW,
            state=AlertState.FIRING,
            message="Test alert",
            started_at=datetime.utcnow(),
        )
        self.alert_manager.active_alerts["test_rule"] = alert

        # Suppress alert
        success = self.alert_manager.suppress_alert(
            "alert-2",
            duration=timedelta(hours=1),
        )

        assert success
        assert alert.state == AlertState.SUPPRESSED
        assert alert.suppressed_until is not None

    def test_get_alert_statistics(self):
        """Test alert statistics"""
        # Add some alerts
        for i in range(5):
            alert = Alert(
                id=f"alert-{i}",
                rule_id=f"rule-{i}",
                name=f"Alert {i}",
                severity=AlertSeverity.MEDIUM if i < 3 else AlertSeverity.HIGH,
                state=AlertState.FIRING if i < 2 else AlertState.ACKNOWLEDGED,
                message="Test alert",
                started_at=datetime.utcnow(),
            )
            self.alert_manager.active_alerts[f"rule-{i}"] = alert

        # Get statistics
        stats = self.alert_manager.get_alert_statistics()

        assert stats["total_active"] == 5
        assert stats["severity_counts"]["medium"] == 3
        assert stats["severity_counts"]["high"] == 2



class TestObservabilityService:
    """Test observability service"""

    def setup_method(self):
        """Setup test environment"""
        self.metrics_collector = MetricsCollector()
        self.alert_manager = AlertManager(self.metrics_collector)
        self.observability = ObservabilityService(
            metrics_collector=self.metrics_collector,
            alert_manager=self.alert_manager,
        )

    def test_create_trace(self):
        """Test trace creation"""
        trace_id = self.observability.create_trace(
            operation_name="test_operation",
            service_name="test_service",
        )

        assert trace_id is not None
        assert trace_id in self.observability.active_traces

        trace = self.observability.active_traces[trace_id]
        assert trace.root_span.operation_name == "test_operation"

    @pytest.mark.asyncio
    async def test_trace_span_context_manager(self):
        """Test span tracing with context manager"""
        trace_id = self.observability.create_trace("main_operation")

        # Use context manager for span
        async with self.observability.trace_span(
            trace_id,
            "child_operation",
            kind=SpanKind.CLIENT,
        ) as span:
            assert span is not None
            assert span.operation_name == "child_operation"
            assert span.span_id in self.observability.active_spans

        # Span should be completed
        assert span.span_id not in self.observability.active_spans
        assert span.end_time is not None
        assert span.duration_ms is not None

    def test_add_span_tags_and_logs(self):
        """Test adding tags and logs to spans"""
        trace_id = self.observability.create_trace("test_trace")
        span = self.observability.start_span(trace_id, "test_span")

        # Add tags
        self.observability.add_span_tag(span.span_id, "user_id", "12345")
                self.observability.add_span_tag(
            span.span_id,
            "environment",
            "production"
        )

        # Add logs
        self.observability.add_span_log(
            span.span_id,
            TraceLevel.INFO,
            "Processing started",
            {"item_count": 100},
        )

        assert span.tags["user_id"] == "12345"
        assert len(span.logs) == 1
        assert span.logs[0]["message"] == "Processing started"

        # End span
        self.observability.end_span(span.span_id)

    def test_structured_logging(self):
        """Test structured logging"""
        # Log messages
        self.observability.log(
            TraceLevel.INFO,
            "Application started",
            "main_service",
            context={"version": "1.0.0"},
            tags={"environment": "production"},
        )

        self.observability.log(
            TraceLevel.ERROR,
            "Database connection failed",
            "db_service",
            context={"error": "Connection timeout"},
        )

        # Check log buffer
        assert len(self.observability.log_buffer) == 2

        # Get log insights
        insights = self.observability.get_log_insights()
        assert insights["total_logs"] == 2
        assert insights["level_distribution"]["info"] == 1
        assert insights["level_distribution"]["error"] == 1

    def test_service_health_monitoring(self):
        """Test service health monitoring"""
        # Update service health
        self.observability.update_service_health(
            service_name="api_service",
            response_time_ms=250,
            error_rate=0.02,
            throughput_rps=100,
            dependencies=["db_service", "cache_service"],
        )

        # Check service map
        assert "api_service" in self.observability.service_map
        health = self.observability.service_map["api_service"]
        assert health.status == "healthy"
        assert health.response_time_ms == 250

        # Update with degraded performance
        self.observability.update_service_health(
            service_name="api_service",
            response_time_ms=1500,
            error_rate=0.08,
            throughput_rps=50,
        )

        health = self.observability.service_map["api_service"]
        assert health.status == "degraded"
        assert len(health.issues) > 0

    def test_service_topology(self):
        """Test service topology mapping"""
        # Add multiple services
        self.observability.update_service_health(
            "frontend",
            response_time_ms=100,
            error_rate=0.01,
            throughput_rps=200,
            dependencies=["api"],
        )

        self.observability.update_service_health(
            "api",
            response_time_ms=50,
            error_rate=0.02,
            throughput_rps=500,
            dependencies=["database", "cache"],
        )

        self.observability.update_service_health(
            "database",
            response_time_ms=10,
            error_rate=0.001,
            throughput_rps=1000,
        )

        # Get topology
        topology = self.observability.get_service_topology()

        assert len(topology["nodes"]) == 3
        assert len(topology["edges"]) >= 2

        # Check dependencies
        api_deps = self.observability.service_dependencies["api"]
        assert "database" in api_deps

    def test_anomaly_detection(self):
        """Test performance anomaly detection"""
        # Establish baseline
        self.observability.update_service_health(
            "test_service",
            response_time_ms=100,
            error_rate=0.01,
            throughput_rps=100,
        )

        # Update with anomalous values
        self.observability.update_service_health(
            "test_service",
            response_time_ms=500,  # 5x baseline
            error_rate=0.1,  # 10x baseline
            throughput_rps=30,  # 30% of baseline
        )

        # Check anomaly detection
        assert len(self.observability.anomaly_detections) > 0
        anomaly = self.observability.anomaly_detections[0]
        assert anomaly["service"] == "test_service"
        assert len(anomaly["anomalies"]) > 0

    def test_trace_summary(self):
        """Test trace summary generation"""
        # Create trace with multiple spans
        trace_id = self.observability.create_trace("main_request")

        # Add child spans
        span1 = self.observability.start_span(
            trace_id,
            "database_query",
            parent_span_id=self.observability.active_traces[trace_id].root_span.span_id,
                
        )
        self.observability.end_span(span1.span_id)

        span2 = self.observability.start_span(
            trace_id,
            "cache_lookup",
            parent_span_id=self.observability.active_traces[trace_id].root_span.span_id,
                
        )
        self.observability.end_span(span2.span_id)

        # End trace
        self.observability.end_trace(trace_id)

        # Get summary
        summary = self.observability.get_trace_summary(trace_id)

        assert summary is not None
        assert summary["trace_id"] == trace_id
        assert summary["span_count"] == 3  # root + 2 children



class TestIntegration:
    """Integration tests for monitoring components"""

    @pytest.mark.asyncio
    async def test_metrics_to_alerts_flow(self):
        """Test flow from metrics to alerts"""
        # Setup
        metrics = MetricsCollector()
        alerts = AlertManager(metrics_collector=metrics)

        # Register metric
        metrics.register_metric(
            MetricDefinition(
                name="api_errors",
                type=MetricType.COUNTER,
                description="API errors",
                unit=MetricUnit.ERRORS,
            )
        )

        # Add alert rule
        rule = AlertRule(
            id="api_error_alert",
            name="High API Errors",
            description="Too many API errors",
            severity=AlertSeverity.HIGH,
            conditions=[
                AlertCondition(
                    metric="api_errors",
                    operator=">",
                    threshold=5,
                    duration=timedelta(seconds=0),
                )
            ],
        )
        alerts.add_rule(rule)

        # Generate errors
        for _ in range(10):
            metrics.increment_counter("api_errors")

        # Evaluate alerts
        await alerts._evaluate_rules()

        # Check alert triggered
        active = alerts.get_active_alerts()
        assert len(active) > 0

    @pytest.mark.asyncio
    async def test_observability_with_metrics(self):
        """Test observability integrated with metrics"""
        # Setup
        metrics = MetricsCollector()
        observability = ObservabilityService(metrics_collector=metrics)

        # Create traced operation
        trace_id = observability.create_trace("user_request")

        async with observability.trace_span(
            trace_id,
            "process_request",
        ) as span:
            # Simulate processing
            await asyncio.sleep(0.01)

        # Check metrics were recorded
        time_series = metrics.get_time_series("span_duration_ms")
        assert len(time_series) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
