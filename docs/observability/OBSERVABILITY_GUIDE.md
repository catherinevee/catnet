# CatNet Observability Guide

**Version:** 1.0
**Last Updated:** 2025-10-25
**Owner:** Platform Team

---

## Table of Contents

1. [Overview](#overview)
2. [Distributed Tracing](#distributed-tracing)
3. [Correlation IDs](#correlation-ids)
4. [Structured Logging](#structured-logging)
5. [Metrics & Monitoring](#metrics--monitoring)
6. [Grafana Dashboards](#grafana-dashboards)
7. [Alerting](#alerting)
8. [Troubleshooting](#troubleshooting)

---

## Overview

CatNet implements comprehensive observability using the **three pillars**:

1. **Logs** - Structured logs with correlation IDs
2. **Metrics** - Prometheus metrics for monitoring
3. **Traces** - Distributed tracing with OpenTelemetry

### Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  CatNet API  │────▶│  Jaeger      │────▶│  Grafana     │
│  (FastAPI)   │     │  (Traces)    │     │  (Dashboards)│
└──────────────┘     └──────────────┘     └──────────────┘
       │                     │                     │
       │              ┌──────────────┐            │
       ├──────────────│ Prometheus   │────────────┘
       │              │ (Metrics)    │
       │              └──────────────┘
       │                     │
       │              ┌──────────────┐
       └──────────────│ Loki/ELK     │
                      │ (Logs)       │
                      └──────────────┘
```

---

## Distributed Tracing

### What is Distributed Tracing?

Distributed tracing tracks a request as it flows through microservices, providing:
- **End-to-end visibility** across services
- **Performance bottleneck** identification
- **Dependency mapping**
- **Root cause analysis**

### Implementation

**File:** `src/observability/tracing.py`

#### Setup in main.py

```python
from src.observability.tracing import setup_tracing

# Configure tracing
setup_tracing(
    app=app,
    service_name="catnet-api",
    service_version="1.0.0",
    jaeger_endpoint="localhost:6831",  # Jaeger collector
    sample_rate=1.0,  # 100% sampling in dev, 0.1 (10%) in prod
)
```

#### Automatic Instrumentation

Tracing automatically instruments:
- ✅ **FastAPI** - All HTTP requests
- ✅ **PostgreSQL** - Database queries
- ✅ **Redis** - Cache operations
- ✅ **HTTP Clients** - External API calls (httpx, requests)

#### Manual Instrumentation

**Decorator approach:**
```python
from src.observability.tracing import trace_function

@trace_function(span_name="deploy_configuration")
async def deploy_config(device_id: str, config: dict):
    # Automatically traced
    ...
```

**Context manager approach:**
```python
from src.observability.tracing import trace_span

async def complex_operation():
    with trace_span("validate_config", {"config_size": len(config)}) as span:
        result = await validate(config)
        span.set_attribute("validation_result", result)

    with trace_span("apply_config") as span:
        await apply(config)
```

**Add attributes to current span:**
```python
from src.observability.tracing import add_span_attributes, add_span_event

# Add attributes
add_span_attributes(
    device_id="router-1",
    vendor="cisco",
    config_lines=150
)

# Add events (milestones)
add_span_event("config_validated", {"rules_passed": 10})
```

### Trace Propagation

Traces automatically propagate across:
- HTTP requests (via headers)
- Background tasks
- Message queues

**Manual propagation:**
```python
from src.observability.tracing import inject_trace_context

headers = {"Authorization": "Bearer token"}
inject_trace_context(headers)  # Adds traceparent header

response = await httpx.get("https://api.example.com", headers=headers)
```

### Viewing Traces

**Jaeger UI:** http://localhost:16686

1. Select service: `catnet-api`
2. Select operation: `POST /api/v1/deployments`
3. View trace timeline
4. Click spans for details

**Example Trace:**
```
POST /api/v1/deployments [200ms]
  ├─ validate_deployment [20ms]
  ├─ get_devices_from_db [30ms]
  │  └─ SELECT * FROM devices [25ms]
  ├─ get_credentials_from_vault [50ms]
  │  └─ vault.get_secret [45ms]
  ├─ deploy_configuration [80ms]
  │  ├─ connect_to_device [30ms]
  │  ├─ send_config [40ms]
  │  └─ verify_config [10ms]
  └─ audit_log [20ms]
```

### Performance Analysis

**Find slow spans:**
```promql
# Jaeger query
service_name="catnet-api" AND duration > 1s

# Or in Grafana
histogram_quantile(0.99,
  sum(rate(catnet_span_duration_seconds_bucket[5m])) by (le, span_name)
)
```

---

## Correlation IDs

### What are Correlation IDs?

Correlation IDs link all logs, traces, and metrics for a single request, enabling:
- **Request tracking** across services
- **Log aggregation** for debugging
- **User session tracking**

### Types of IDs

| ID Type | Purpose | Scope |
|---------|---------|-------|
| **Correlation ID** | Request family tracking | Multiple requests |
| **Request ID** | Single request tracking | One request |
| **Session ID** | User session tracking | User session |
| **User ID** | User identification | Authenticated user |

### Implementation

**File:** `src/observability/correlation.py`

#### Setup

```python
from src.observability.correlation import CorrelationMiddleware

# Add middleware
app.add_middleware(CorrelationMiddleware)
```

#### Automatic Behavior

- Extracts `X-Correlation-ID` from request headers
- Generates new ID if not present
- Adds to all logs automatically
- Includes in response headers
- Propagates to OpenTelemetry spans

#### Usage in Code

```python
from src.observability.correlation import (
    get_correlation_id,
    get_request_id,
    set_user_id,
    inject_correlation_headers,
)

# Get current correlation ID
correlation_id = get_correlation_id()
logger.info("Processing request", correlation_id=correlation_id)

# Set user ID (after authentication)
set_user_id(str(user.id))

# Propagate to external service
headers = {}
inject_correlation_headers(headers)
response = await httpx.get("https://api.example.com", headers=headers)
```

#### Background Tasks

```python
from src.observability.correlation import propagate_correlation

@propagate_correlation
async def background_task():
    # This task inherits correlation context from caller
    logger.info("Background task started")  # Includes correlation_id
```

#### Manual Context

```python
from src.observability.correlation import correlation_context

async def scheduled_job():
    async with correlation_context() as corr_id:
        # All operations here share the same correlation ID
        logger.info("Job started")
        await do_work()
```

### HTTP Headers

**Request headers:**
- `X-Correlation-ID` - Correlation ID (reused if provided)
- `X-Request-ID` - Unique request ID
- `X-Session-ID` - Session ID (if authenticated)

**Response headers:**
- `X-Correlation-ID` - Same as request
- `X-Request-ID` - Same as request

**Example:**
```bash
curl -H "X-Correlation-ID: abc-123" https://api.catnet.io/devices

# Response includes:
# X-Correlation-ID: abc-123
# X-Request-ID: def-456
```

### Log Correlation

All logs automatically include correlation context:

```json
{
  "timestamp": "2025-10-25T10:30:00Z",
  "level": "info",
  "message": "Deployment started",
  "correlation_id": "abc-123",
  "request_id": "def-456",
  "session_id": "ghi-789",
  "user_id": "user-001",
  "deployment_id": "deploy-123"
}
```

**Search logs by correlation ID:**
```bash
# In Loki/Grafana
{job="catnet-api"} |= "abc-123"

# In ELK
correlation_id:"abc-123"

# In grep (local)
grep "abc-123" /var/log/catnet/app.log
```

---

## Structured Logging

### What is Structured Logging?

Structured logging outputs logs as JSON for machine parsing:

**Traditional (unstructured):**
```
2025-10-25 10:30:00 INFO Deployment deploy-123 started by user-001
```

**Structured:**
```json
{
  "timestamp": "2025-10-25T10:30:00Z",
  "level": "info",
  "message": "Deployment started",
  "deployment_id": "deploy-123",
  "user_id": "user-001",
  "correlation_id": "abc-123"
}
```

### Benefits

- **Easy parsing** by log aggregation tools
- **Powerful queries** (filter by any field)
- **Consistent format** across services
- **Automatic context** injection

### Implementation

CatNet uses `structlog` for structured logging.

**Configuration:**
```python
import structlog

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,  # Add correlation context
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer()  # JSON output
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
)
```

### Usage

```python
import structlog

logger = structlog.get_logger(__name__)

# Simple logging
logger.info("User logged in")

# With context
logger.info(
    "Deployment started",
    deployment_id=deployment.id,
    strategy="canary",
    device_count=len(devices)
)

# Error logging
try:
    await deploy()
except Exception as e:
    logger.error(
        "Deployment failed",
        deployment_id=deployment.id,
        error=str(e),
        exc_info=True  # Include stack trace
    )
```

### Log Levels

| Level | Usage | Example |
|-------|-------|---------|
| **DEBUG** | Detailed debugging | Variable values, function entry/exit |
| **INFO** | Normal operations | Request started, deployment completed |
| **WARNING** | Unexpected but handled | Retry attempts, deprecated API usage |
| **ERROR** | Errors that need attention | Failed deployments, connection errors |
| **CRITICAL** | System-level failures | Database down, Vault unavailable |

### Security Filtering

Sensitive data is automatically filtered:

```python
# Passwords, tokens, secrets are redacted
logger.info("User authenticated", password="secret123")
# Output: {"message": "User authenticated", "password": "[REDACTED]"}
```

**File:** `src/core/logger.py` - SecurityFilter class

---

## Metrics & Monitoring

### Prometheus Metrics

CatNet exposes metrics at `/metrics` endpoint.

#### Built-in Metrics

**HTTP Metrics:**
```promql
# Request rate
rate(catnet_requests_total[5m])

# Request duration (p95)
histogram_quantile(0.95,
  rate(catnet_request_duration_seconds_bucket[5m])
)

# Error rate
rate(catnet_requests_total{status=~"5.."}[5m]) /
  rate(catnet_requests_total[5m])
```

**Deployment Metrics:**
```promql
# Deployment success rate
sum(catnet_deployments_total{status="completed"}) /
  sum(catnet_deployments_total) * 100

# Deployment duration
catnet_deployment_duration_seconds
```

**Authentication Metrics:**
```promql
# Auth failure rate
rate(catnet_auth_failures_total[5m])

# Active sessions
catnet_active_sessions
```

**Infrastructure Metrics:**
```promql
# Database connections
pg_stat_activity_count

# Redis memory
redis_memory_used_bytes

# Active device connections
catnet_device_connections_active
```

### Custom Metrics

**Define custom metrics:**
```python
from prometheus_client import Counter, Histogram, Gauge

# Counter (always increasing)
config_validations_total = Counter(
    'catnet_config_validations_total',
    'Total configuration validations',
    ['result', 'vendor']
)

config_validations_total.labels(result='success', vendor='cisco').inc()

# Histogram (for durations)
backup_duration = Histogram(
    'catnet_backup_duration_seconds',
    'Time to backup device configuration',
    ['device_type']
)

with backup_duration.labels(device_type='router').time():
    await backup_device()

# Gauge (current value)
queue_size = Gauge(
    'catnet_queue_size',
    'Current deployment queue size'
)

queue_size.set(len(deployment_queue))
```

### Monitoring Best Practices

1. **Use labels wisely** - Not too many (cardinality explosion)
2. **Histogram for latencies** - Get percentiles (p50, p95, p99)
3. **Counter for events** - Track totals over time
4. **Gauge for states** - Current values (connections, queue size)

---

## Grafana Dashboards

### Available Dashboards

1. **CatNet - System Overview**
   - System health
   - Request rate & error rate
   - Response time percentiles
   - Top endpoints
   - Deployment success rate

2. **CatNet - Deployments**
   - Active deployments
   - Deployment duration
   - Success/failure trends
   - Rollback rate

3. **CatNet - Security**
   - Authentication failures
   - MFA usage
   - Suspicious activity
   - Audit events

4. **CatNet - Infrastructure**
   - Database metrics
   - Redis metrics
   - Device connections
   - Resource usage

### Accessing Dashboards

**Grafana UI:** http://localhost:3000

**Default credentials:**
- Username: `admin`
- Password: Check `GRAFANA_PASSWORD` env var

### Dashboard Features

#### Variables

Filter data by environment, service, time range:

```
$environment - development, staging, production
$service - catnet-api, catnet-worker, catnet-gitops
$time_range - Last 1h, 6h, 24h, 7d
```

#### Annotations

Deployments are automatically annotated on graphs.

#### Alerts

Dashboards include alert rules for:
- High error rate (> 5%)
- Slow response time (p99 > 1s)
- High auth failure rate
- Low system health

### Creating Custom Dashboards

1. Go to Grafana → Create → Dashboard
2. Add panel
3. Select data source: Prometheus
4. Enter query:
   ```promql
   rate(catnet_requests_total[5m])
   ```
5. Configure visualization
6. Save dashboard

---

## Alerting

### Alert Rules

**File:** `configs/prometheus/alerts.yml`

#### Critical Alerts

**Service Down:**
```yaml
- alert: CatNetAPIDown
  expr: up{job="catnet-api"} == 0
  for: 1m
  severity: critical
  summary: "CatNet API is down"
```

**High Error Rate:**
```yaml
- alert: HighErrorRate
  expr: |
    sum(rate(catnet_requests_total{status=~"5.."}[5m])) /
    sum(rate(catnet_requests_total[5m])) > 0.05
  for: 5m
  severity: critical
  summary: "Error rate above 5%"
```

**Database Down:**
```yaml
- alert: DatabaseDown
  expr: pg_up == 0
  for: 1m
  severity: critical
  summary: "PostgreSQL database is down"
```

#### Warning Alerts

**Slow Requests:**
```yaml
- alert: SlowRequests
  expr: |
    histogram_quantile(0.99,
      rate(catnet_request_duration_seconds_bucket[5m])
    ) > 1
  for: 10m
  severity: warning
  summary: "p99 latency above 1 second"
```

**High Auth Failures:**
```yaml
- alert: HighAuthFailures
  expr: rate(catnet_auth_failures_total[5m]) > 10
  for: 5m
  severity: warning
  summary: "High authentication failure rate"
```

### Alert Channels

Configure alerting destinations:

**Slack:**
```yaml
receivers:
  - name: slack
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/...'
        channel: '#catnet-alerts'
        title: '{{ .GroupLabels.alertname }}'
        text: '{{ .CommonAnnotations.summary }}'
```

**PagerDuty:**
```yaml
receivers:
  - name: pagerduty
    pagerduty_configs:
      - service_key: '...'
        severity: '{{ .GroupLabels.severity }}'
```

**Email:**
```yaml
receivers:
  - name: email
    email_configs:
      - to: 'ops@catnet.io'
        from: 'alerts@catnet.io'
        smarthost: 'smtp.gmail.com:587'
```

---

## Troubleshooting

### Common Scenarios

#### "I can't find logs for a specific request"

**Solution:** Use correlation ID

1. Get correlation ID from API response headers:
   ```bash
   curl -I https://api.catnet.io/devices
   # X-Correlation-ID: abc-123
   ```

2. Search logs:
   ```bash
   # Loki
   {job="catnet-api"} |= "abc-123"

   # Files
   grep "abc-123" /var/log/catnet/*.log
   ```

#### "Request is slow, where's the bottleneck?"

**Solution:** Use distributed tracing

1. Get trace ID from logs or headers
2. Open Jaeger UI: http://localhost:16686
3. Search for trace ID
4. View trace timeline
5. Identify slowest span

#### "How do I track a deployment end-to-end?"

**Solution:** Combine correlation, traces, and logs

1. Start deployment → Note correlation ID
2. View trace in Jaeger for timeline
3. Search logs for detailed steps:
   ```
   {job="catnet-api"} |= "correlation_id: abc-123"
   ```
4. Check metrics for errors:
   ```promql
   catnet_deployments_total{deployment_id="deploy-123"}
   ```

#### "Alert fired, what do I check?"

**Solution:** Follow runbook

1. Check Grafana dashboard for system health
2. View recent logs:
   ```
   {job="catnet-api"} | level="error" | line_format "{{.message}}"
   ```
3. Check traces for failed requests
4. Review metrics for patterns
5. Check infrastructure (DB, Redis, Vault)

### Debug Mode

Enable verbose logging:

```bash
export LOG_LEVEL=DEBUG
export DEBUG=true
```

**In code:**
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Performance Debugging

**Enable query logging:**
```python
# In settings
DATABASE_ECHO = True  # Log all SQL queries
```

**Profile slow endpoints:**
```python
from line_profiler import LineProfiler

@profile
async def slow_function():
    ...
```

---

## Best Practices

1. ✅ **Always use structured logging**
2. ✅ **Add correlation IDs to external API calls**
3. ✅ **Trace expensive operations** (database, external APIs)
4. ✅ **Use appropriate log levels** (don't log everything at INFO)
5. ✅ **Filter sensitive data** from logs and traces
6. ✅ **Set up alerts** for critical metrics
7. ✅ **Review dashboards** regularly
8. ✅ **Use sampling** in production (10-20% trace sampling)

---

**Last Updated:** 2025-10-25
**Next Review:** Quarterly
