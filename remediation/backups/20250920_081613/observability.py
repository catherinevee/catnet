"""
Observability Service for CatNet

Handles:
- Distributed tracing
- Log aggregation
- Service mesh observability
- Application performance monitoring
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict
from contextlib import asynccontextmanager
import uuid


class TraceLevel(Enum):
    """Trace levels"""

   DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class SpanKind(Enum):
    """Span kinds for distributed tracing"""

    INTERNAL = "internal"
    SERVER = "server"
    CLIENT = "client"
    PRODUCER = "producer"
    CONSUMER = "consumer"


@dataclass
class Span:
    """Distributed tracing span"""

    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    operation_name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_ms: Optional[float] = None
    kind: SpanKind = SpanKind.INTERNAL
    status: str = "ok"
    tags: Dict[str, Any] = field(default_factory=dict)
    logs: List[Dict[str, Any]] = field(default_factory=list)
    service_name: str = "catnet"


@dataclass
class Trace:
    """Complete trace with all spans"""

    trace_id: str
    root_span: Span
    spans: List[Span] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    duration_ms: Optional[float] = None
    service_dependencies: List[str] = field(default_factory=list)


@dataclass
class LogEntry:
    """Structured log entry"""

   timestamp: datetime
    level: TraceLevel
    message: str
    service: str
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
    tags: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ServiceHealth:
    """Service health status"""

   service_name: str
    status: str  # healthy, degraded, unhealthy
    last_check: datetime
    response_time_ms: float
    error_rate: float
    throughput_rps: float
    dependencies: List[str] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)


class ObservabilityService:
    """
    Provides comprehensive observability features
    """

    def __init__(self, metrics_collector=None, alert_manager=None): """
        Initialize observability service
    Args:
            metrics_collector: Metrics collector instance
            alert_manager: Alert manager instance
        """
       self.metrics_collector = metrics_collector
        self.alert_manager = alert_manager

        # Tracing
        self.active_traces: Dict[str, Trace] = {}
        self.completed_traces: List[Trace] = []
        self.active_spans: Dict[str, Span] = {}

        # Logging
        self.log_buffer: List[LogEntry] = []
        self.log_aggregations: Dict[str, List[LogEntry]] = defaultdict(list)

        # Service map
        self.service_map: Dict[str, ServiceHealth] = {}
        self.service_dependencies: Dict[str, List[str]] = defaultdict(list)

        # Performance metrics
        self.performance_baselines: Dict[str, Dict[str, float]] = {}
        self.anomaly_detections: List[Dict[str, Any]] = []

        # Configuration
        self.sampling_rate = 1.0  # 100% sampling
        self.max_trace_duration = timedelta(minutes=5)
        self.log_retention = timedelta(days=7)

        def create_trace(
            self,
            operation_name: str,
            service_name: str = "catnet"
        ) -> str:
        """
        Create a new trace
    Args:
            operation_name: Operation name
            service_name: Service name
    Returns:
            Trace ID"""
        trace_id = str(uuid.uuid4())
        span_id = str(uuid.uuid4())[:12]

        # Create root span
        root_span = Span(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=None,
            operation_name=operation_name,
            start_time=datetime.utcnow(),
            service_name=service_name,
            kind=SpanKind.SERVER,
        )

        # Create trace
        trace = Trace(
            trace_id=trace_id,
            root_span=root_span,
            spans=[root_span],
        )

        self.active_traces[trace_id] = trace
        self.active_spans[span_id] = root_span

        return trace_id

    @asynccontextmanager
    async def trace_span(
        self,
        trace_id: str,
        operation_name: str,
        parent_span_id: Optional[str] = None,
        kind: SpanKind = SpanKind.INTERNAL,
    ):
        """
        Context manager for tracing a span
    Args:
            trace_id: Trace ID
            operation_name: Operation name
            parent_span_id: Parent span ID
            kind: Span kind"""
        span = self.start_span(trace_id, operation_name, parent_span_id, kind)

        try:
            yield span
            span.status = "ok"
        except Exception as e:
            span.status = "error"
            self.add_span_log(
                span.span_id,
                TraceLevel.ERROR,
                f"Error: {str(e)}",
            )
            raise
        finally:
            self.end_span(span.span_id)

    def start_span(
        self,
        trace_id: str,
        operation_name: str,
        parent_span_id: Optional[str] = None,
        kind: SpanKind = SpanKind.INTERNAL,
    ) -> Span:
        """
        Start a new span
    Args:
            trace_id: Trace ID
            operation_name: Operation name
            parent_span_id: Parent span ID
            kind: Span kind
    Returns:
            Span instance"""
        span_id = str(uuid.uuid4())[:12]

        span = Span(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            operation_name=operation_name,
            start_time=datetime.utcnow(),
            kind=kind,
        )

        # Add to active spans
        self.active_spans[span_id] = span

        # Add to trace
        if trace_id in self.active_traces:
            self.active_traces[trace_id].spans.append(span)

        return span

    def end_span(self, span_id: str):
        """
        End a span
    Args:
            span_id: Span ID"""
        if span_id not in self.active_spans:
            return

        span = self.active_spans[span_id]
        span.end_time = datetime.utcnow()
        span.duration_ms = (
            span.end_time - span.start_time).total_seconds() * 1000

        # Remove from active spans
        del self.active_spans[span_id]

        # Record metrics
        if self.metrics_collector:
            self.metrics_collector.observe_histogram(
                "span_duration_ms",
                span.duration_ms,
                {
                    "operation": span.operation_name,
                    "kind": span.kind.value,
                    "status": span.status,
                },
            )

    def add_span_tag(self, span_id: str, key: str, value: Any):
        """
        Add tag to span
    Args:
            span_id: Span ID
            key: Tag key
            value: Tag value"""
        if span_id in self.active_spans:
            self.active_spans[span_id].tags[key] = value

    def add_span_log(
        self,
        span_id: str,
        level: TraceLevel,
        message: str,
        context: Optional[Dict[str, Any]] = None,
    ):
        """
        Add log to span
    Args:
            span_id: Span ID
            level: Log level
            message: Log message
            context: Additional context"""
        if span_id in self.active_spans:
            log_entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "level": level.value,
                "message": message,
                "context": context or {},
            }
            self.active_spans[span_id].logs.append(log_entry)

    def end_trace(self, trace_id: str):
        """
        End a trace
    Args:
            trace_id: Trace ID"""
        if trace_id not in self.active_traces:
            return

        trace = self.active_traces[trace_id]
        trace.end_time = datetime.utcnow()
        trace.duration_ms = (trace.end_time -
                             trace.start_time).total_seconds() * 1000

        # End root span if still active
        if trace.root_span.span_id in self.active_spans:
            self.end_span(trace.root_span.span_id)

        # Move to completed traces
        self.completed_traces.append(trace)
        del self.active_traces[trace_id]

        # Analyze trace for issues
        self._analyze_trace(trace)

        # Clean up old traces
        self._cleanup_old_traces()

    def _analyze_trace(self, trace: Trace):
        """
        Analyze trace for performance issues
    Args:
            trace: Trace to analyze"""
        # Check for slow operations
        slow_spans = [
            s
            for s in trace.spans
            if s.duration_ms and s.duration_ms > 1000  # > 1 second
        ]

        if slow_spans:
            self.log(
                TraceLevel.WARNING,
                f"Slow operations detected in trace {trace.trace_id}",
                "observability",
                trace_id=trace.trace_id,
                context={"slow_spans": len(slow_spans)},
            )

        # Check for errors
        error_spans = [s for s in trace.spans if s.status == "error"]

        if error_spans:
            self.log(
                TraceLevel.ERROR,
                f"Errors detected in trace {trace.trace_id}",
                "observability",
                trace_id=trace.trace_id,
                context={"error_spans": len(error_spans)},
            )

        # Detect service dependencies
        services = set(s.service_name for s in trace.spans)
        trace.service_dependencies = list(services)

    def _cleanup_old_traces(self):
        """Cleanup old completed traces"""
        cutoff = datetime.utcnow() - self.max_trace_duration
        self.completed_traces = [
            t for t in self.completed_traces if t.start_time > cutoff
        ]

    def log(
        self,
        level: TraceLevel,
        message: str,
        service: str,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        tags: Optional[Dict[str, Any]] = None,
    ): """
        Log a message
    Args:
            level: Log level
            message: Log message
            service: Service name
            trace_id: Associated trace ID
            span_id: Associated span ID
            context: Additional context
            tags: Log tags
        """
       log_entry = LogEntry(
            timestamp=datetime.utcnow(),
            level=level,
            message=message,
            service=service,
            trace_id=trace_id,
            span_id=span_id,
            context=context or {},
            tags=tags or {},
        )

        # Add to buffer
        self.log_buffer.append(log_entry)

        # Aggregate by service
        self.log_aggregations[service].append(log_entry)

        # Check for critical logs
        if level == TraceLevel.CRITICAL:
            self._handle_critical_log(log_entry)

        # Clean up old logs
        self._cleanup_old_logs()

    def _handle_critical_log(self, log_entry: LogEntry): """Handle critical log entries"""
       if self.alert_manager:
            # Create alert for critical log
            pass  # Would trigger alert

    def _cleanup_old_logs(self): """Cleanup old log entries"""
       cutoff = datetime.utcnow() - self.log_retention
        self.log_buffer = [log for log in self.log_buffer if log.timestamp >
                           cutoff]

    def update_service_health(
        self,
        service_name: str,
        response_time_ms: float,
        error_rate: float,
        throughput_rps: float,
        dependencies: Optional[List[str]] = None,
    ): """
        Update service health status
    Args:
            service_name: Service name
            response_time_ms: Response time in milliseconds
            error_rate: Error rate (0-1)
            throughput_rps: Throughput in requests per second
            dependencies: Service dependencies
        """
       # Determine health status
       if error_rate > 0.1:  # > 10% errors
            status = "unhealthy"
        elif error_rate > 0.05 or response_time_ms > 1000:
            status = "degraded"
        else:
            status = "healthy"

        # Identify issues
        issues = []
        if error_rate > 0.05:
            issues.append(f"High error rate: {error_rate:.2%}")
        if response_time_ms > 1000:
            issues.append(f"Slow response time: {response_time_ms:.0f}ms")
        if throughput_rps < 1:
            issues.append(f"Low throughput: {throughput_rps:.2f} RPS")

        health = ServiceHealth(
            service_name=service_name,
            status=status,
            last_check=datetime.utcnow(),
            response_time_ms=response_time_ms,
            error_rate=error_rate,
            throughput_rps=throughput_rps,
            dependencies=dependencies or [],
            issues=issues,
        )

        self.service_map[service_name] = health

        # Update service dependencies
        if dependencies:
            self.service_dependencies[service_name] = dependencies

        # Check for anomalies
        self._detect_anomalies(service_name, health)

    def _detect_anomalies(self, service_name: str, health: ServiceHealth):
        """
        Detect anomalies in service performance
    Args:
            service_name: Service name
            health: Service health"""
        if service_name not in self.performance_baselines:
            # Establish baseline
            self.performance_baselines[service_name] = {
                "response_time_ms": health.response_time_ms,
                "error_rate": health.error_rate,
                "throughput_rps": health.throughput_rps,
            }
            return

        baseline = self.performance_baselines[service_name]

        # Check for significant deviations
        anomalies = []

        # Response time anomaly (> 2x baseline)
        if health.response_time_ms > baseline["response_time_ms"] * 2:
            anomalies.append(
                {
                    "type": "response_time",
                    "severity": "high",
                    "message": f"Response time 2x above baseline",
                    "current": health.response_time_ms,
                    "baseline": baseline["response_time_ms"],
                }
            )

        # Error rate anomaly (> 5x baseline)
        if health.error_rate > baseline["error_rate"] * 5:
            anomalies.append(
                {
                    "type": "error_rate",
                    "severity": "critical",
                    "message": f"Error rate 5x above baseline",
                    "current": health.error_rate,
                    "baseline": baseline["error_rate"],
                }
            )

        # Throughput anomaly (< 50% baseline)
        if health.throughput_rps < baseline["throughput_rps"] * 0.5:
            anomalies.append(
                {
                    "type": "throughput",
                    "severity": "medium",
                    "message": f"Throughput 50% below baseline",
                    "current": health.throughput_rps,
                    "baseline": baseline["throughput_rps"],
                }
            )

        if anomalies:
            anomaly_detection = {
                "service": service_name,
                "timestamp": datetime.utcnow(),
                "anomalies": anomalies,
            }
            self.anomaly_detections.append(anomaly_detection)

            # Log anomalies
            self.log(
                TraceLevel.WARNING,
                f"Performance anomalies detected for {service_name}",
                "observability",
                context=anomaly_detection,
            )

    def get_service_topology(self) -> Dict[str, Any]:
        """
        Get service topology map
    Returns:
            Service topology"""
        nodes = []
        edges = []

        # Create nodes for each service
        for service_name, health in self.service_map.items():
            nodes.append(
                {
                    "id": service_name,
                    "label": service_name,
                    "status": health.status,
                    "metrics": {
                        "response_time_ms": health.response_time_ms,
                        "error_rate": health.error_rate,
                        "throughput_rps": health.throughput_rps,
                    },
                    "issues": health.issues,
                }
            )

        # Create edges for dependencies
        for service, deps in self.service_dependencies.items():
            for dep in deps:
                edges.append(
                    {
                        "source": service,
                        "target": dep,
                    }
                )

        return {
            "nodes": nodes,
            "edges": edges,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def get_trace_summary(self, trace_id: str) -> Optional[Dict[str, Any]]:
        """
        Get trace summary
    Args:
            trace_id: Trace ID
    Returns:
            Trace summary"""
        # Check active traces
        if trace_id in self.active_traces:
            trace = self.active_traces[trace_id]
        else:
            # Check completed traces
            trace = next(
                (
                    t for t in self.completed_traces if t.trace_id == trace_id
                ), None
            )

        if not trace:
            return None

        # Build span tree
        span_tree = self._build_span_tree(trace.spans)

        return {
            "trace_id": trace.trace_id,
            "start_time": trace.start_time.isoformat(),
            "end_time": trace.end_time.isoformat() if trace.end_time else None,
            "duration_ms": trace.duration_ms,
            "span_count": len(trace.spans),
            "service_count": len(set(s.service_name for s in trace.spans)),
            "error_count": sum(1 for s in trace.spans if s.status == "error"),
            "span_tree": span_tree,
        }

    def _build_span_tree(self, spans: List[Span]) -> Dict[str, Any]:
        """Build hierarchical span tree"""
        span_map = {s.span_id: s for s in spans}
        tree = {}

        for span in spans:
            if span.parent_span_id is None:
                # Root span
                tree[span.span_id] = {
                    "operation": span.operation_name,
                    "duration_ms": span.duration_ms,
                    "status": span.status,
                    "children": self._get_child_spans(span.span_id, span_map),
                }

        return tree

    def _get_child_spans(
        self, parent_id: str, span_map: Dict[str, Span]
    ) -> List[Dict[str, Any]]:
        """Get child spans recursively"""
        children = []
        for span in span_map.values():
            if span.parent_span_id == parent_id:
                children.append(
                    {
                        "operation": span.operation_name,
                        "duration_ms": span.duration_ms,
                        "status": span.status,
                        "children": self._get_child_spans(
                            span.span_id,
                            span_map
                        ),
                    }
                )
        return children

    def get_log_insights(
        self,
        service: Optional[str] = None,
        level: Optional[TraceLevel] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Get log insights and analytics
    Args:
            service: Filter by service
            level: Filter by log level
            start_time: Start time filter
            end_time: End time filter
    Returns:
            Log insights"""
        # Filter logs
        logs = self.log_buffer
        if service:
            logs = [log for log in logs if log.service == service]
        if level:
            logs = [log for log in logs if log.level == level]
        if start_time:
            logs = [log for log in logs if log.timestamp >= start_time]
        if end_time:
            logs = [log for log in logs if log.timestamp <= end_time]

        # Count by level
        level_counts = defaultdict(int)
        for log in logs:
            level_counts[log.level.value] += 1

        # Count by service
        service_counts = defaultdict(int)
        for log in logs:
            service_counts[log.service] += 1

        # Find error patterns
        error_patterns = defaultdict(int)
        error_logs = [
            log for log in logs if log.level in [TraceLevel.ERROR,
                                                 TraceLevel.CRITICAL]
        ]
        for log in error_logs:
            # Simple pattern extraction (would be more sophisticated)
            pattern = log.message[:50]
            error_patterns[pattern] += 1

        return {
            "total_logs": len(logs),
            "level_distribution": dict(level_counts),
            "service_distribution": dict(service_counts),
            "error_patterns": dict(error_patterns),
            "error_rate": len(error_logs) / len(logs) if logs else 0,
            "time_range": {
                "start": min(log.timestamp for log in logs).isoformat()
                if logs
                else None,
                "end": max(
                    log.timestamp for log in logs).isoformat(
                ) if logs else None,
            },
        }


class DistributedTracer:
    """
    Distributed tracing system for tracking requests across services"""

    def __init__(self):
        """TODO: Add docstring"""
        self.traces: Dict[str, Trace] = {}
        self.spans: Dict[str, Span] = {}
        self.completed_traces: List[Trace] = []

    def start_span(
        self,
        operation_name: str,
        kind: SpanKind = SpanKind.INTERNAL,
        parent_span_id: Optional[str] = None,
        attributes: Dict[str, Any] = None,
    ) -> Span:
        """Start a new span"""
        trace_id = (
            str(uuid.uuid4())
            if not parent_span_id
            else self._get_trace_id(parent_span_id)
        )
        span = Span(
            trace_id=trace_id,
            span_id=str(uuid.uuid4()),
            parent_span_id=parent_span_id,
            operation_name=operation_name,
            start_time=datetime.now(),
            end_time=None,
            kind=kind,
            attributes=attributes or {},
            events=[],
            status="in_progress",
            tags={},
        )
        self.spans[span.span_id] = span
        return span

        def end_span(
            self,
            span_id: str,
            status: str = "ok",
            error: Optional[str] = None
        ):
        """End a span"""
        if span_id in self.spans:
            span = self.spans[span_id]
            span.end_time = datetime.now()
            span.status = status
            if error:
                span.attributes["error"] = error

    def get_traces(self, service: Optional[str] = None) -> List[Trace]:
        """Get traces, optionally filtered by service"""
        traces = list(self.traces.values()) + self.completed_traces
        if service:
            traces = [t for t in traces if t.service_name == service]
        return traces

    def _get_trace_id(self, span_id: str) -> str: """Get trace ID for a span"""
       if span_id in self.spans:
            return self.spans[span_id].trace_id
        return str(uuid.uuid4())


class LogAggregator:
    """
    Log aggregation system for centralized logging
    """

   def __init__(self):
        """TODO: Add docstring"""
        self.log_buffer: List[LogEntry] = []
        self.max_buffer_size = 10000

    async def log(
        self,
        level: TraceLevel,
        message: str,
        service: str = "catnet",
        metadata: Dict[str, Any] = None,
    ):
        """Add a log entry"""
        entry = LogEntry(
            timestamp=datetime.now(),
            level=level,
            message=message,
            service=service,
            metadata=metadata or {},
            trace_id=None,
            span_id=None,
            tags={},
        )
        self.log_buffer.append(entry)

        # Trim buffer if too large
        if len(self.log_buffer) > self.max_buffer_size:
            self.log_buffer = self.log_buffer[-self.max_buffer_size:]

    async def query_logs(
        self,
        service: Optional[str] = None,
        level: Optional[TraceLevel] = None,
        limit: int = 100,
    ) -> List[LogEntry]: """Query logs with filters"""
       logs = self.log_buffer

        if service:
            logs = [log for log in logs if log.service == service]
        if level:
            logs = [log for log in logs if log.level == level]

        return logs[-limit:]


class ObservabilityManager:
    """
    Main observability manager that coordinates all monitoring components
    """

   def __init__(self):
        """TODO: Add docstring"""
        self.tracer = DistributedTracer()
        self.log_aggregator = LogAggregator()
        self.metrics = {}
        self.health_checks = {}
        self.initialized = False

    async def initialize(self): """Initialize observability components"""
       self.initialized = True
        return self

        async def start_trace(
            self,
            operation: str,
            service: str = "catnet"
        ) -> Span:
        """Start a new trace"""
        return self.tracer.start_span(
            operation_name=operation,
            kind=SpanKind.INTERNAL,
            attributes={"service": service},
        )

    async def log(
        self, level: TraceLevel, message: str, service: str = "catnet",
            **metadata
    ):
        """Log a message"""
        await self.log_aggregator.log(
            level=level, message=message, service=service, metadata=metadata
        )

    async def record_metric(
        self, name: str, value: float, labels: Dict[str, str] = None
    ): """Record a metric"""
       key = f"{name}_{labels}" if labels else name
        self.metrics[key] = {
            "name": name,
            "value": value,
            "labels": labels or {},
            "timestamp": datetime.now(),
        }

    async def check_health(self, component: str) -> bool:
        """Check health of a component"""
        return self.health_checks.get(component, True)

    async def set_health(self, component: str, healthy: bool): """Set health status of a component"""
       self.health_checks[component] = healthy

    async def get_traces(self, service: Optional[str] = None) -> List[Trace]: """Get traces"""
       return self.tracer.get_traces(service)

    async def get_logs(
        self,
        service: Optional[str] = None,
        level: Optional[TraceLevel] = None,
        limit: int = 100,
    ) -> List[LogEntry]: """Get logs"""
       return await self.log_aggregator.query_logs(
            service=service, level=level, limit=limit
        )

    async def get_metrics_summary(self) -> Dict[str, Any]: """Get metrics summary"""
       return {
            "metrics": self.metrics,
            "health_status": self.health_checks,
            "trace_count": len(self.tracer.traces),
            "log_count": len(self.log_aggregator.log_buffer),
        }

    async def export_prometheus(self) -> str:
        """Export metrics in Prometheus format"""
        lines = []
        for key, metric in self.metrics.items():
            name = metric["name"]
            value = metric["value"]
            labels = metric.get("labels", {})

            label_str = ""
            if labels:
                label_items = [f'{k}="{v}"' for k, v in labels.items()]
                label_str = "{" + ",".join(label_items) + "}"

            lines.append(f"# TYPE catnet_{name} gauge")
            lines.append(f"catnet_{name}{label_str} {value}")

        return "\n".join(lines)

    async def shutdown(self):
        """Shutdown observability components"""
        self.initialized = False
        self.metrics.clear()
        self.health_checks.clear()
