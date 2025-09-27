"""
Monitoring microservice application.
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
import uvicorn
from prometheus_client import Counter, Histogram, Gauge, generate_latest
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from .models import (
    Metric, MetricQuery, Alert, AlertQuery, AlertRule, AlertRuleCreateRequest,
    Dashboard, DashboardCreateRequest, HealthCheck, HealthCheckRequest,
    IncidentReport, IncidentCreateRequest, NotificationRequest,
    MetricExportRequest, ServiceStatus, SLAMetrics, PerformanceMetrics,
    NetworkMetrics, DeviceMetrics, SystemMetrics, AuditLog, ComplianceReport
)
from .collectors import (
    MetricCollector, PrometheusCollector, DeviceMetricCollector,
    ServiceMetricCollector, LogCollector, NetworkMetricCollector,
    SNMPCollector, StreamTelemetryCollector
)
from .analyzers import (
    MetricAnalyzer, AnomalyDetector, TrendAnalyzer, ThresholdAnalyzer,
    CorrelationAnalyzer, PredictiveAnalyzer, RootCauseAnalyzer
)
from .alerting import (
    AlertManager, AlertEvaluator, NotificationManager, IncidentManager,
    AlertCorrelator, EscalationManager
)
from .storage import (
    MetricStorage, TimeSeriesDB, AlertStorage, IncidentStorage,
    DashboardStorage, LogStorage
)
from .visualization import (
    DashboardBuilder, ChartGenerator, ReportGenerator,
    NetworkTopology, StatusBoard
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Prometheus metrics
api_requests_total = Counter(
    'catnet_monitoring_api_requests_total',
    'Total API requests',
    ['method', 'endpoint', 'status']
)
api_request_duration = Histogram(
    'catnet_monitoring_api_request_duration_seconds',
    'API request duration',
    ['method', 'endpoint']
)
active_alerts = Gauge(
    'catnet_monitoring_active_alerts',
    'Number of active alerts',
    ['severity']
)
metrics_collected = Counter(
    'catnet_monitoring_metrics_collected_total',
    'Total metrics collected',
    ['source', 'type']
)
incidents_open = Gauge(
    'catnet_monitoring_incidents_open',
    'Number of open incidents'
)

# Global instances
metric_collector: Optional[MetricCollector] = None
prometheus_collector: Optional[PrometheusCollector] = None
device_collector: Optional[DeviceMetricCollector] = None
service_collector: Optional[ServiceMetricCollector] = None
network_collector: Optional[NetworkMetricCollector] = None
snmp_collector: Optional[SNMPCollector] = None
telemetry_collector: Optional[StreamTelemetryCollector] = None
log_collector: Optional[LogCollector] = None

anomaly_detector: Optional[AnomalyDetector] = None
trend_analyzer: Optional[TrendAnalyzer] = None
threshold_analyzer: Optional[ThresholdAnalyzer] = None
correlation_analyzer: Optional[CorrelationAnalyzer] = None
predictive_analyzer: Optional[PredictiveAnalyzer] = None
root_cause_analyzer: Optional[RootCauseAnalyzer] = None

alert_manager: Optional[AlertManager] = None
alert_evaluator: Optional[AlertEvaluator] = None
notification_manager: Optional[NotificationManager] = None
incident_manager: Optional[IncidentManager] = None
alert_correlator: Optional[AlertCorrelator] = None
escalation_manager: Optional[EscalationManager] = None

metric_storage: Optional[MetricStorage] = None
timeseries_db: Optional[TimeSeriesDB] = None
alert_storage: Optional[AlertStorage] = None
incident_storage: Optional[IncidentStorage] = None
dashboard_storage: Optional[DashboardStorage] = None
log_storage: Optional[LogStorage] = None

dashboard_builder: Optional[DashboardBuilder] = None
chart_generator: Optional[ChartGenerator] = None
report_generator: Optional[ReportGenerator] = None
network_topology: Optional[NetworkTopology] = None
status_board: Optional[StatusBoard] = None

redis_client: Optional[redis.Redis] = None
db_engine: Optional[Any] = None
async_session: Optional[sessionmaker] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("Starting Monitoring microservice...")

    # Initialize Redis
    global redis_client
    redis_client = redis.Redis(
        host='localhost',
        port=6379,
        decode_responses=True,
        ssl=True,
        ssl_cert_reqs='required'
    )

    # Initialize database
    global db_engine, async_session
    db_engine = create_async_engine(
        "postgresql+asyncpg://catnet:password@localhost/catnet_monitoring",
        echo=False,
        pool_size=20,
        max_overflow=40
    )
    async_session = sessionmaker(
        db_engine,
        class_=AsyncSession,
        expire_on_commit=False
    )

    # Initialize collectors
    global metric_collector, prometheus_collector, device_collector
    global service_collector, network_collector, snmp_collector
    global telemetry_collector, log_collector

    metric_collector = MetricCollector()
    prometheus_collector = PrometheusCollector()
    device_collector = DeviceMetricCollector()
    service_collector = ServiceMetricCollector()
    network_collector = NetworkMetricCollector()
    snmp_collector = SNMPCollector()
    telemetry_collector = StreamTelemetryCollector()
    log_collector = LogCollector()

    # Initialize analyzers
    global anomaly_detector, trend_analyzer, threshold_analyzer
    global correlation_analyzer, predictive_analyzer, root_cause_analyzer

    anomaly_detector = AnomalyDetector()
    trend_analyzer = TrendAnalyzer()
    threshold_analyzer = ThresholdAnalyzer()
    correlation_analyzer = CorrelationAnalyzer()
    predictive_analyzer = PredictiveAnalyzer()
    root_cause_analyzer = RootCauseAnalyzer()

    # Initialize alerting
    global alert_manager, alert_evaluator, notification_manager
    global incident_manager, alert_correlator, escalation_manager

    alert_manager = AlertManager()
    alert_evaluator = AlertEvaluator()
    notification_manager = NotificationManager()
    incident_manager = IncidentManager()
    alert_correlator = AlertCorrelator()
    escalation_manager = EscalationManager()

    # Initialize storage
    global metric_storage, timeseries_db, alert_storage
    global incident_storage, dashboard_storage, log_storage

    metric_storage = MetricStorage()
    timeseries_db = TimeSeriesDB()
    alert_storage = AlertStorage()
    incident_storage = IncidentStorage()
    dashboard_storage = DashboardStorage()
    log_storage = LogStorage()

    # Initialize visualization
    global dashboard_builder, chart_generator, report_generator
    global network_topology, status_board

    dashboard_builder = DashboardBuilder()
    chart_generator = ChartGenerator()
    report_generator = ReportGenerator()
    network_topology = NetworkTopology()
    status_board = StatusBoard()

    # Start background tasks
    asyncio.create_task(collect_metrics_task())
    asyncio.create_task(evaluate_alerts_task())
    asyncio.create_task(analyze_metrics_task())
    asyncio.create_task(cleanup_old_data_task())
    asyncio.create_task(generate_reports_task())

    logger.info("Monitoring microservice started successfully")

    yield

    # Cleanup
    logger.info("Shutting down Monitoring microservice...")
    await redis_client.close()
    await db_engine.dispose()
    logger.info("Monitoring microservice stopped")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="CatNet Monitoring Service",
        description="Metrics, alerting, and observability service",
        version="1.0.0",
        lifespan=lifespan
    )

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://catnet.local"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )

    return app


# Create application instance
app = create_app()


# Background tasks
async def collect_metrics_task():
    """Background task to collect metrics."""
    while True:
        try:
            # Collect from various sources
            prometheus_metrics = await prometheus_collector.collect()
            device_metrics = await device_collector.collect()
            service_metrics = await service_collector.collect()
            network_metrics = await network_collector.collect()

            # Store metrics
            for metric in prometheus_metrics + device_metrics + service_metrics + network_metrics:
                await metric_storage.store(metric)
                metrics_collected.labels(
                    source=metric.source,
                    type=metric.type.value
                ).inc()

            # Collect logs
            logs = await log_collector.collect()
            for log in logs:
                await log_storage.store(log)

            await asyncio.sleep(30)  # Collect every 30 seconds

        except Exception as e:
            logger.error(f"Error in metrics collection: {e}")
            await asyncio.sleep(60)


async def evaluate_alerts_task():
    """Background task to evaluate alert rules."""
    while True:
        try:
            # Get all enabled alert rules
            rules = await alert_manager.get_enabled_rules()

            for rule in rules:
                # Evaluate rule
                result = await alert_evaluator.evaluate(rule)

                if result.should_fire:
                    # Create or update alert
                    alert = await alert_manager.create_alert(rule, result)
                    active_alerts.labels(severity=alert.severity.value).inc()

                    # Send notifications
                    await notification_manager.send_alert(alert)

                    # Check for incident creation
                    if alert.severity in ['critical', 'high']:
                        await incident_manager.check_incident_creation(alert)

                elif result.should_resolve:
                    # Resolve existing alert
                    await alert_manager.resolve_alert(rule.id)
                    active_alerts.labels(severity=rule.severity.value).dec()

            await asyncio.sleep(60)  # Evaluate every minute

        except Exception as e:
            logger.error(f"Error in alert evaluation: {e}")
            await asyncio.sleep(60)


async def analyze_metrics_task():
    """Background task to analyze metrics."""
    while True:
        try:
            # Get recent metrics
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=1)
            metrics = await metric_storage.query(start_time, end_time)

            # Anomaly detection
            anomalies = await anomaly_detector.detect(metrics)
            for anomaly in anomalies:
                await alert_manager.create_anomaly_alert(anomaly)

            # Trend analysis
            trends = await trend_analyzer.analyze(metrics)
            await metric_storage.store_trends(trends)

            # Correlation analysis
            correlations = await correlation_analyzer.analyze(metrics)
            await metric_storage.store_correlations(correlations)

            # Predictive analysis
            predictions = await predictive_analyzer.predict(metrics)
            await metric_storage.store_predictions(predictions)

            await asyncio.sleep(300)  # Analyze every 5 minutes

        except Exception as e:
            logger.error(f"Error in metrics analysis: {e}")
            await asyncio.sleep(300)


async def cleanup_old_data_task():
    """Background task to cleanup old data."""
    while True:
        try:
            # Clean old metrics (keep 30 days)
            await metric_storage.cleanup(days=30)

            # Clean old logs (keep 7 days)
            await log_storage.cleanup(days=7)

            # Clean old alerts (keep 90 days)
            await alert_storage.cleanup(days=90)

            # Archive old incidents
            await incident_storage.archive_old(days=180)

            await asyncio.sleep(3600)  # Cleanup every hour

        except Exception as e:
            logger.error(f"Error in data cleanup: {e}")
            await asyncio.sleep(3600)


async def generate_reports_task():
    """Background task to generate reports."""
    while True:
        try:
            # Daily SLA report
            sla_report = await report_generator.generate_sla_report('daily')
            await dashboard_storage.store_report(sla_report)

            # Weekly performance report
            if datetime.utcnow().weekday() == 0:  # Monday
                perf_report = await report_generator.generate_performance_report('weekly')
                await dashboard_storage.store_report(perf_report)

            # Monthly compliance report
            if datetime.utcnow().day == 1:  # First day of month
                compliance_report = await report_generator.generate_compliance_report('monthly')
                await dashboard_storage.store_report(compliance_report)

            await asyncio.sleep(3600)  # Check every hour

        except Exception as e:
            logger.error(f"Error in report generation: {e}")
            await asyncio.sleep(3600)


# Metrics endpoints
@app.post("/api/v1/metrics")
async def ingest_metrics(
    metrics: List[Metric],
    background_tasks: BackgroundTasks
) -> Dict[str, Any]:
    """Ingest metrics."""
    api_requests_total.labels(method="POST", endpoint="/metrics", status="200").inc()

    # Store metrics asynchronously
    background_tasks.add_task(store_metrics, metrics)

    return {
        "status": "accepted",
        "count": len(metrics),
        "timestamp": datetime.utcnow()
    }


async def store_metrics(metrics: List[Metric]):
    """Store metrics in background."""
    for metric in metrics:
        await metric_storage.store(metric)
        metrics_collected.labels(
            source=metric.source,
            type=metric.type.value
        ).inc()


@app.post("/api/v1/metrics/query")
async def query_metrics(
    query: MetricQuery
) -> Dict[str, Any]:
    """Query metrics."""
    api_requests_total.labels(method="POST", endpoint="/metrics/query", status="200").inc()

    # Query metrics from storage
    results = await metric_storage.query(
        metric_names=query.metric_names,
        start_time=query.start_time,
        end_time=query.end_time,
        aggregation=query.aggregation,
        interval=query.interval,
        labels=query.labels,
        limit=query.limit
    )

    return {
        "results": results,
        "count": len(results),
        "query": query.dict()
    }


@app.get("/api/v1/metrics/export")
async def export_metrics(
    format: str = Query(default="prometheus"),
    metrics: Optional[List[str]] = Query(default=None)
) -> StreamingResponse:
    """Export metrics in various formats."""
    api_requests_total.labels(method="GET", endpoint="/metrics/export", status="200").inc()

    if format == "prometheus":
        # Generate Prometheus format
        output = generate_latest()
        return StreamingResponse(
            iter([output]),
            media_type="text/plain; version=0.0.4"
        )
    elif format == "json":
        # Export as JSON
        data = await metric_storage.export_json(metrics)
        return StreamingResponse(
            iter([data]),
            media_type="application/json"
        )
    else:
        raise HTTPException(400, f"Unsupported format: {format}")


# Alert endpoints
@app.get("/api/v1/alerts")
async def list_alerts(
    query: AlertQuery = Depends()
) -> Dict[str, Any]:
    """List alerts."""
    api_requests_total.labels(method="GET", endpoint="/alerts", status="200").inc()

    alerts = await alert_storage.query(
        severity=query.severity,
        status=query.status,
        start_time=query.start_time,
        end_time=query.end_time,
        service=query.service,
        labels=query.labels,
        limit=query.limit,
        offset=query.offset
    )

    return {
        "alerts": alerts,
        "total": len(alerts),
        "offset": query.offset,
        "limit": query.limit
    }


@app.post("/api/v1/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    user: str
) -> Dict[str, Any]:
    """Acknowledge an alert."""
    api_requests_total.labels(method="POST", endpoint="/alerts/acknowledge", status="200").inc()

    alert = await alert_manager.acknowledge(alert_id, user)

    return {
        "status": "acknowledged",
        "alert": alert,
        "acknowledged_by": user,
        "acknowledged_at": datetime.utcnow()
    }


@app.post("/api/v1/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    resolution: str
) -> Dict[str, Any]:
    """Resolve an alert."""
    api_requests_total.labels(method="POST", endpoint="/alerts/resolve", status="200").inc()

    alert = await alert_manager.resolve(alert_id, resolution)
    active_alerts.labels(severity=alert.severity.value).dec()

    return {
        "status": "resolved",
        "alert": alert,
        "resolution": resolution,
        "resolved_at": datetime.utcnow()
    }


# Alert rules endpoints
@app.post("/api/v1/alerts/rules")
async def create_alert_rule(
    request: AlertRuleCreateRequest,
    created_by: str
) -> Dict[str, Any]:
    """Create alert rule."""
    api_requests_total.labels(method="POST", endpoint="/alerts/rules", status="200").inc()

    rule = await alert_manager.create_rule(request, created_by)

    return {
        "status": "created",
        "rule": rule
    }


@app.get("/api/v1/alerts/rules")
async def list_alert_rules() -> Dict[str, Any]:
    """List alert rules."""
    api_requests_total.labels(method="GET", endpoint="/alerts/rules", status="200").inc()

    rules = await alert_manager.list_rules()

    return {
        "rules": rules,
        "total": len(rules)
    }


@app.put("/api/v1/alerts/rules/{rule_id}/enable")
async def enable_alert_rule(rule_id: str) -> Dict[str, Any]:
    """Enable alert rule."""
    api_requests_total.labels(method="PUT", endpoint="/alerts/rules/enable", status="200").inc()

    rule = await alert_manager.enable_rule(rule_id)

    return {
        "status": "enabled",
        "rule": rule
    }


@app.put("/api/v1/alerts/rules/{rule_id}/disable")
async def disable_alert_rule(rule_id: str) -> Dict[str, Any]:
    """Disable alert rule."""
    api_requests_total.labels(method="PUT", endpoint="/alerts/rules/disable", status="200").inc()

    rule = await alert_manager.disable_rule(rule_id)

    return {
        "status": "disabled",
        "rule": rule
    }


# Dashboard endpoints
@app.post("/api/v1/dashboards")
async def create_dashboard(
    request: DashboardCreateRequest,
    owner: str
) -> Dict[str, Any]:
    """Create dashboard."""
    api_requests_total.labels(method="POST", endpoint="/dashboards", status="200").inc()

    dashboard = await dashboard_builder.create(request, owner)
    await dashboard_storage.store(dashboard)

    return {
        "status": "created",
        "dashboard": dashboard
    }


@app.get("/api/v1/dashboards")
async def list_dashboards(
    owner: Optional[str] = None,
    tags: Optional[List[str]] = Query(default=None)
) -> Dict[str, Any]:
    """List dashboards."""
    api_requests_total.labels(method="GET", endpoint="/dashboards", status="200").inc()

    dashboards = await dashboard_storage.list(owner=owner, tags=tags)

    return {
        "dashboards": dashboards,
        "total": len(dashboards)
    }


@app.get("/api/v1/dashboards/{dashboard_id}")
async def get_dashboard(dashboard_id: str) -> Dict[str, Any]:
    """Get dashboard."""
    api_requests_total.labels(method="GET", endpoint="/dashboards/get", status="200").inc()

    dashboard = await dashboard_storage.get(dashboard_id)

    if not dashboard:
        raise HTTPException(404, "Dashboard not found")

    # Render dashboard with current data
    rendered = await dashboard_builder.render(dashboard)

    return {
        "dashboard": dashboard,
        "rendered": rendered
    }


# Health check endpoints
@app.post("/api/v1/health/check")
async def perform_health_check(
    request: HealthCheckRequest
) -> Dict[str, Any]:
    """Perform health check."""
    api_requests_total.labels(method="POST", endpoint="/health/check", status="200").inc()

    results = []

    # Check specified services or all
    services = request.services or await get_all_services()

    for service in services:
        health = await check_service_health(
            service,
            request.include_dependencies,
            request.include_metrics,
            request.timeout_seconds
        )
        results.append(health)

    overall_status = "healthy"
    if any(r.status == "unhealthy" for r in results):
        overall_status = "unhealthy"
    elif any(r.status == "degraded" for r in results):
        overall_status = "degraded"

    return {
        "status": overall_status,
        "services": results,
        "timestamp": datetime.utcnow()
    }


async def check_service_health(
    service: str,
    include_dependencies: bool,
    include_metrics: bool,
    timeout: int
) -> ServiceStatus:
    """Check health of a service."""
    # Implementation would check actual service health
    pass


async def get_all_services() -> List[str]:
    """Get list of all services."""
    return [
        "authentication",
        "gitops",
        "deployment",
        "device",
        "monitoring",
        "api-gateway"
    ]


# Incident endpoints
@app.post("/api/v1/incidents")
async def create_incident(
    request: IncidentCreateRequest
) -> Dict[str, Any]:
    """Create incident."""
    api_requests_total.labels(method="POST", endpoint="/incidents", status="200").inc()

    incident = await incident_manager.create(request)
    incidents_open.inc()

    # Send notifications
    await notification_manager.send_incident_notification(incident)

    # Start escalation if needed
    if incident.severity in ['critical', 'high']:
        await escalation_manager.start_escalation(incident)

    return {
        "status": "created",
        "incident": incident
    }


@app.get("/api/v1/incidents")
async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000)
) -> Dict[str, Any]:
    """List incidents."""
    api_requests_total.labels(method="GET", endpoint="/incidents", status="200").inc()

    incidents = await incident_storage.list(
        status=status,
        severity=severity,
        limit=limit
    )

    return {
        "incidents": incidents,
        "total": len(incidents)
    }


@app.put("/api/v1/incidents/{incident_id}/resolve")
async def resolve_incident(
    incident_id: str,
    resolution: str,
    root_cause: Optional[str] = None
) -> Dict[str, Any]:
    """Resolve incident."""
    api_requests_total.labels(method="PUT", endpoint="/incidents/resolve", status="200").inc()

    incident = await incident_manager.resolve(
        incident_id,
        resolution,
        root_cause
    )
    incidents_open.dec()

    return {
        "status": "resolved",
        "incident": incident
    }


# Notification endpoints
@app.post("/api/v1/notifications/send")
async def send_notification(
    request: NotificationRequest
) -> Dict[str, Any]:
    """Send notification."""
    api_requests_total.labels(method="POST", endpoint="/notifications/send", status="200").inc()

    result = await notification_manager.send(request)

    return {
        "status": "sent" if result.success else "failed",
        "notification_id": result.notification_id,
        "channel": request.channel_id,
        "error": result.error
    }


@app.post("/api/v1/notifications/test")
async def test_notification(
    channel_id: str
) -> Dict[str, Any]:
    """Test notification channel."""
    api_requests_total.labels(method="POST", endpoint="/notifications/test", status="200").inc()

    result = await notification_manager.test_channel(channel_id)

    return {
        "status": "success" if result.success else "failed",
        "channel": channel_id,
        "message": result.message,
        "response_time_ms": result.response_time_ms
    }


# SLA and reporting endpoints
@app.get("/api/v1/sla/{service}")
async def get_sla_metrics(
    service: str,
    period: str = Query(default="daily")  # daily, weekly, monthly
) -> SLAMetrics:
    """Get SLA metrics for a service."""
    api_requests_total.labels(method="GET", endpoint="/sla", status="200").inc()

    metrics = await calculate_sla_metrics(service, period)

    return metrics


async def calculate_sla_metrics(service: str, period: str) -> SLAMetrics:
    """Calculate SLA metrics."""
    # Implementation would calculate actual SLA metrics
    pass


@app.get("/api/v1/reports/performance")
async def get_performance_report(
    service: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None
) -> List[PerformanceMetrics]:
    """Get performance report."""
    api_requests_total.labels(method="GET", endpoint="/reports/performance", status="200").inc()

    if not end_time:
        end_time = datetime.utcnow()
    if not start_time:
        start_time = end_time - timedelta(hours=24)

    report = await report_generator.generate_performance_metrics(
        service=service,
        start_time=start_time,
        end_time=end_time
    )

    return report


@app.get("/api/v1/reports/compliance")
async def get_compliance_report(
    framework: str
) -> ComplianceReport:
    """Get compliance report."""
    api_requests_total.labels(method="GET", endpoint="/reports/compliance", status="200").inc()

    report = await report_generator.generate_compliance_report(framework)

    return report


# Status and topology endpoints
@app.get("/api/v1/status")
async def get_system_status() -> Dict[str, Any]:
    """Get overall system status."""
    api_requests_total.labels(method="GET", endpoint="/status", status="200").inc()

    status = await status_board.get_overall_status()

    return status


@app.get("/api/v1/topology")
async def get_network_topology() -> Dict[str, Any]:
    """Get network topology."""
    api_requests_total.labels(method="GET", endpoint="/topology", status="200").inc()

    topology = await network_topology.get_current_topology()

    return topology


@app.get("/api/v1/topology/devices/{device_id}/neighbors")
async def get_device_neighbors(device_id: str) -> Dict[str, Any]:
    """Get device neighbors."""
    api_requests_total.labels(method="GET", endpoint="/topology/neighbors", status="200").inc()

    neighbors = await network_topology.get_device_neighbors(device_id)

    return {
        "device_id": device_id,
        "neighbors": neighbors
    }


# Admin endpoints
@app.post("/api/v1/admin/retention")
async def update_retention_policy(
    metric_days: int = 30,
    log_days: int = 7,
    alert_days: int = 90,
    incident_days: int = 180
) -> Dict[str, Any]:
    """Update data retention policy."""
    api_requests_total.labels(method="POST", endpoint="/admin/retention", status="200").inc()

    # Update retention settings
    await metric_storage.set_retention(metric_days)
    await log_storage.set_retention(log_days)
    await alert_storage.set_retention(alert_days)
    await incident_storage.set_retention(incident_days)

    return {
        "status": "updated",
        "retention": {
            "metrics": metric_days,
            "logs": log_days,
            "alerts": alert_days,
            "incidents": incident_days
        }
    }


@app.post("/api/v1/admin/cleanup")
async def trigger_cleanup() -> Dict[str, Any]:
    """Trigger immediate cleanup."""
    api_requests_total.labels(method="POST", endpoint="/admin/cleanup", status="200").inc()

    # Run cleanup tasks
    metrics_cleaned = await metric_storage.cleanup()
    logs_cleaned = await log_storage.cleanup()
    alerts_cleaned = await alert_storage.cleanup()

    return {
        "status": "completed",
        "cleaned": {
            "metrics": metrics_cleaned,
            "logs": logs_cleaned,
            "alerts": alerts_cleaned
        }
    }


if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8085,
        ssl_keyfile="/etc/catnet/certs/monitoring-key.pem",
        ssl_certfile="/etc/catnet/certs/monitoring-cert.pem",
        log_level="info",
        reload=False
    )