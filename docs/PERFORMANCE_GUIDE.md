# CatNet Performance Testing & Benchmarking Guide

## Overview

This guide covers performance testing, benchmarking, and optimization strategies for CatNet. It provides detailed instructions for running load tests, interpreting results, and tuning the system for production workloads.

## Table of Contents

- [Load Testing with Locust](#load-testing-with-locust)
- [Performance Baselines](#performance-baselines)
- [Load Test Scenarios](#load-test-scenarios)
- [Interpreting Results](#interpreting-results)
- [Performance Tuning](#performance-tuning)
- [Stress Testing](#stress-testing)
- [Monitoring During Tests](#monitoring-during-tests)
- [Common Bottlenecks](#common-bottlenecks)

## Load Testing with Locust

### Prerequisites

```bash
# Install Locust
pip install locust

# Ensure CatNet is running
docker-compose up -d

# Verify services are healthy
curl http://localhost:8000/health
```

### Running Basic Load Tests

```bash
# Web UI mode (recommended for initial testing)
locust -f tests/performance/locustfile.py --host=http://localhost:8000

# Then open http://localhost:8089 in your browser
# Configure: 100 users, spawn rate 10 users/second
```

```bash
# Headless mode (for CI/CD pipelines)
locust -f tests/performance/locustfile.py \
  --host=http://localhost:8000 \
  --users 100 \
  --spawn-rate 10 \
  --run-time 5m \
  --headless \
  --html=results/load_test_report.html \
  --csv=results/load_test_stats
```

### Distributed Load Testing

For high-load scenarios, distribute across multiple machines:

```bash
# Master node
locust -f tests/performance/locustfile.py \
  --master \
  --expect-workers=3 \
  --host=http://your-catnet-instance.com

# Worker nodes (run on separate machines)
locust -f tests/performance/locustfile.py \
  --worker \
  --master-host=<master-ip>
```

## Performance Baselines

### Target Metrics (Single Instance)

| Metric | Target | Acceptable | Critical |
|--------|--------|------------|----------|
| API Response Time (p50) | < 100ms | < 200ms | < 500ms |
| API Response Time (p95) | < 300ms | < 500ms | < 1000ms |
| API Response Time (p99) | < 500ms | < 1000ms | < 2000ms |
| Requests per Second | > 500 | > 200 | > 100 |
| Error Rate | < 0.1% | < 1% | < 5% |
| Database Connection Pool | > 80% available | > 50% | > 20% |
| Memory Usage | < 2GB | < 4GB | < 6GB |
| CPU Usage | < 70% | < 85% | < 95% |

### Expected Throughput

**Light Load (1-50 concurrent users):**
- Authentication: 200-300 req/s
- Device Listing: 500-700 req/s
- Configuration Retrieval: 300-500 req/s
- Deployment Creation: 50-100 req/s

**Medium Load (50-200 concurrent users):**
- Authentication: 400-600 req/s
- Device Listing: 800-1200 req/s
- Configuration Retrieval: 500-800 req/s
- Deployment Creation: 100-200 req/s

**High Load (200-500 concurrent users):**
- Authentication: 600-1000 req/s
- Device Listing: 1200-2000 req/s
- Configuration Retrieval: 800-1500 req/s
- Deployment Creation: 200-400 req/s

## Load Test Scenarios

### Scenario 1: Standard User Load

**Purpose:** Simulate typical daily operations

```bash
locust -f tests/performance/locustfile.py \
  --users 100 \
  --spawn-rate 5 \
  --run-time 10m \
  --headless
```

**User Distribution:**
- 70% CatNetUser (general operations)
- 20% DeviceMonitoringUser (monitoring dashboards)
- 10% AdminUser (administrative tasks)

**Expected Behavior:**
- Stable response times
- Error rate < 0.5%
- No memory leaks
- Database connections stable

### Scenario 2: Peak Load

**Purpose:** Test system under peak usage conditions

```bash
locust -f tests/performance/locustfile.py \
  --users 300 \
  --spawn-rate 20 \
  --run-time 15m \
  --headless
```

**User Distribution:**
- 60% CatNetUser
- 30% DeviceMonitoringUser
- 10% AdminUser

**Expected Behavior:**
- Response times increase but stay within acceptable range
- Error rate < 2%
- Auto-scaling triggers (if configured)
- Rate limiting may activate

### Scenario 3: Stress Test

**Purpose:** Find breaking point and test failure modes

```bash
locust -f tests/performance/locustfile.py \
  --users 1000 \
  --spawn-rate 50 \
  --run-time 20m \
  --headless
```

**Expected Behavior:**
- System degrades gracefully
- Circuit breakers activate
- Rate limiting enforces limits
- No data corruption
- System recovers after load decrease

### Scenario 4: Deployment Spike

**Purpose:** Test handling of sudden deployment activity

**Load Shape:** SpikeLoadShape (built into locustfile.py)

```bash
# Uses custom load shape defined in locustfile.py
locust -f tests/performance/locustfile.py \
  --users 500 \
  --run-time 30m \
  --headless
```

**Pattern:**
1. Ramp up to 100 users over 5 minutes
2. Spike to 500 users instantly
3. Hold for 10 minutes
4. Drop to 50 users
5. Repeat cycle

### Scenario 5: Endurance Test

**Purpose:** Detect memory leaks and resource exhaustion

```bash
locust -f tests/performance/locustfile.py \
  --users 200 \
  --spawn-rate 10 \
  --run-time 4h \
  --headless
```

**Monitor:**
- Memory usage trends (should be stable)
- Database connection leaks
- File descriptor usage
- Log file growth
- Background worker performance

## Interpreting Results

### Locust Web UI Metrics

**Statistics Tab:**
- **RPS (Requests Per Second):** Higher is better, watch for sudden drops
- **Response Time (ms):** Check p50, p95, p99 percentiles
- **Failures:** Should be minimal; investigate any spikes
- **Users:** Current simulated user count

**Charts Tab:**
- **Total Requests per Second:** Should be stable under steady load
- **Response Times:** Should show consistent pattern
- **Number of Users:** Correlate with response time changes

### Key Indicators of Issues

#### 1. Increasing Response Times

```
Time   Users  RPS   p50   p95   p99
0:00   100    500   50ms  200ms 400ms
5:00   100    500   80ms  300ms 600ms  ← Degrading
10:00  100    500   120ms 500ms 1200ms ← Critical
```

**Possible Causes:**
- Database query performance degradation
- Memory pressure causing GC pauses
- Connection pool exhaustion
- External service slowdown (Vault, Redis)

**Investigation:**
```bash
# Check database performance
docker-compose exec postgres psql -U catnet -c "
  SELECT query, calls, mean_exec_time
  FROM pg_stat_statements
  ORDER BY mean_exec_time DESC
  LIMIT 10;"

# Check memory usage
docker stats catnet-api

# Check connection pools
curl http://localhost:8000/api/v1/health/detailed | jq '.database.pool'
```

#### 2. High Error Rate

```
Type        Failures  %
POST /login 150      5%  ← High error rate
GET /devices 20      0.5%
```

**Common Errors:**
- **401 Unauthorized:** Authentication issues, check token generation
- **429 Too Many Requests:** Rate limiting active (expected under high load)
- **500 Internal Server Error:** Application errors, check logs
- **503 Service Unavailable:** Overload or dependency failure

**Investigation:**
```bash
# Check application logs
docker-compose logs catnet-api --tail=100 | grep ERROR

# Check rate limiting
curl -I http://localhost:8000/api/v1/devices \
  -H "Authorization: Bearer $TOKEN" | grep -i ratelimit

# Check worker queue depth
docker-compose exec redis redis-cli INFO stats
```

#### 3. Throughput Ceiling

```
Users  RPS
100    500
200    800
300    950  ← Plateauing
400    960
```

**Possible Causes:**
- CPU bottleneck
- Database connection limit
- Upstream service rate limiting
- Network bandwidth saturation

**Investigation:**
```bash
# CPU usage by container
docker stats --no-stream

# Database connections
docker-compose exec postgres psql -U catnet -c "
  SELECT count(*) as connections, state
  FROM pg_stat_activity
  GROUP BY state;"

# Network I/O
docker stats --format "table {{.Name}}\t{{.NetIO}}"
```

### Analyzing HTML Reports

Generated reports contain:
- **Response time distribution:** Histograms showing latency patterns
- **Requests per second over time:** Identify throughput trends
- **Failures over time:** Correlate with load increases
- **Response time percentiles:** p50, p75, p95, p99 over time

**Red flags:**
- Bimodal distribution (two peaks) suggests inconsistent performance
- Increasing p99 latency indicates tail latency problems
- Sudden RPS drops suggest system overload or crashes

## Performance Tuning

### Application Level

#### 1. Uvicorn Workers

```yaml
# docker-compose.yml
services:
  catnet-api:
    command: uvicorn src.main:app --host 0.0.0.0 --port 8000 --workers 4
    # Rule of thumb: (2 x CPU cores) + 1
```

#### 2. Database Connection Pool

```python
# src/db/session.py
engine = create_async_engine(
    settings.DATABASE_URL,
    pool_size=20,          # Increase for high concurrency
    max_overflow=10,       # Additional connections under load
    pool_pre_ping=True,    # Verify connections before use
    pool_recycle=3600,     # Recycle connections hourly
)
```

#### 3. Redis Configuration

```yaml
# docker-compose.yml
redis:
  command: redis-server --maxmemory 2gb --maxmemory-policy allkeys-lru
```

#### 4. Async Task Optimization

```python
# Use asyncio.gather for parallel operations
devices = await asyncio.gather(*[
    get_device(device_id) for device_id in device_ids
])

# Use connection pooling
async with aiohttp.ClientSession() as session:
    tasks = [fetch_config(session, device) for device in devices]
    results = await asyncio.gather(*tasks)
```

### Database Level

#### 1. Index Optimization

```sql
-- Add indexes for common queries
CREATE INDEX CONCURRENTLY idx_deployments_status_created
  ON deployments(status, created_at DESC);

CREATE INDEX CONCURRENTLY idx_devices_vendor_type
  ON devices(vendor, device_type);

CREATE INDEX CONCURRENTLY idx_audit_logs_timestamp
  ON audit_logs(timestamp DESC) WHERE timestamp > NOW() - INTERVAL '30 days';
```

#### 2. Query Optimization

```python
# Use select_in_loading for relationships
devices = await session.execute(
    select(Device)
    .options(selectinload(Device.deployments))
    .where(Device.status == "active")
)

# Use pagination for large result sets
query = select(Device).limit(100).offset(page * 100)
```

#### 3. Connection Pooling

```bash
# PostgreSQL configuration (postgresql.conf)
max_connections = 100
shared_buffers = 256MB
effective_cache_size = 1GB
maintenance_work_mem = 64MB
work_mem = 16MB
```

### Caching Strategies

#### 1. Redis Caching

```python
# Cache device lists
@cache(ttl=300)  # 5 minutes
async def get_devices_cached():
    return await get_all_devices()

# Cache user permissions
@cache(ttl=600)  # 10 minutes
async def get_user_permissions(user_id: UUID):
    return await db.get_user_roles(user_id)
```

#### 2. HTTP Caching Headers

```python
# In FastAPI routes
@router.get("/devices")
async def list_devices(response: Response):
    response.headers["Cache-Control"] = "public, max-age=60"
    return devices
```

### Rate Limiting Tuning

```python
# src/api/middleware/rate_limiter.py
RATE_LIMITS = {
    "default": "100/minute",
    "auth": "5/minute",      # Prevent brute force
    "deployments": "20/minute",  # Resource-intensive operations
    "monitoring": "200/minute",  # High-frequency polling
}
```

## Stress Testing

### Finding the Breaking Point

**Incremental Load Test:**

```bash
# Start conservative
locust -f tests/performance/locustfile.py \
  --users 100 --spawn-rate 10 --run-time 5m --headless

# Increase until failure
locust -f tests/performance/locustfile.py \
  --users 500 --spawn-rate 50 --run-time 5m --headless

locust -f tests/performance/locustfile.py \
  --users 1000 --spawn-rate 100 --run-time 5m --headless

# Continue until error rate > 10% or crashes occur
```

**Monitor:**
- CPU usage approaching 100%
- Memory exhaustion (OOM killer)
- Database connection refusals
- Queue depths growing unbounded

### Chaos Engineering

Test resilience by introducing failures:

```bash
# Kill API instance mid-test
docker-compose kill catnet-api

# Simulate network latency
tc qdisc add dev eth0 root netem delay 100ms

# Simulate packet loss
tc qdisc add dev eth0 root netem loss 5%

# Fill disk
dd if=/dev/zero of=/tmp/fill bs=1M count=10000
```

**Expected Behavior:**
- Circuit breakers trigger
- Graceful degradation
- Automatic recovery
- No data corruption

## Monitoring During Tests

### Prometheus Metrics

```bash
# Query during load test
curl http://localhost:8000/metrics | grep catnet_

# Key metrics:
# - catnet_http_requests_total
# - catnet_http_request_duration_seconds
# - catnet_deployment_duration_seconds
# - catnet_device_connections_active
```

### Real-time Monitoring

```bash
# Terminal 1: Run load test
locust -f tests/performance/locustfile.py --headless

# Terminal 2: Monitor containers
watch docker stats

# Terminal 3: Monitor API logs
docker-compose logs -f catnet-api | grep -E "ERROR|WARN"

# Terminal 4: Monitor database
watch -n 5 'docker-compose exec postgres psql -U catnet -c "
  SELECT count(*), state FROM pg_stat_activity GROUP BY state;"'
```

### Grafana Dashboards

**Pre-built Dashboards:**
1. **API Performance:** Response times, RPS, error rates
2. **Database Metrics:** Query performance, connection usage
3. **System Resources:** CPU, memory, disk, network
4. **Business Metrics:** Deployments/hour, device count

Access: http://localhost:3000 (default credentials: admin/admin)

## Common Bottlenecks

### 1. Database Connection Exhaustion

**Symptoms:**
- "connection pool exhausted" errors
- Increasing p99 latency
- Timeouts under load

**Solutions:**
- Increase pool_size and max_overflow
- Optimize slow queries
- Implement connection pooling in workers
- Use read replicas for read-heavy operations

### 2. Synchronous I/O Operations

**Symptoms:**
- High response times for specific endpoints
- Workers blocking on I/O

**Solutions:**
- Convert to async/await patterns
- Use asyncio.gather for parallel operations
- Offload blocking operations to thread pool
- Use async libraries (aiohttp, asyncpg)

### 3. Vault API Latency

**Symptoms:**
- Slow credential retrieval
- Deployments delayed

**Solutions:**
- Cache credentials with short TTL
- Use batch credential fetching
- Implement local secret cache with Vault agent
- Pre-fetch credentials for scheduled deployments

### 4. Git Operations

**Symptoms:**
- Slow webhook processing
- Deployment queue backlog

**Solutions:**
- Use shallow clones
- Cache repositories locally
- Implement differential sync
- Offload git operations to dedicated workers

### 5. Device Connection Timeouts

**Symptoms:**
- Failed deployments
- High timeout error rates

**Solutions:**
- Increase connection timeout settings
- Implement connection pooling for devices
- Use parallel device connections with limits
- Retry with exponential backoff

## Performance Testing Checklist

### Pre-Test

- [ ] Baseline metrics recorded
- [ ] Monitoring dashboards configured
- [ ] Test environment matches production
- [ ] Database properly indexed
- [ ] Logs rotated/cleared
- [ ] Sufficient disk space

### During Test

- [ ] Monitor CPU, memory, disk, network
- [ ] Watch error rates
- [ ] Track response time percentiles
- [ ] Observe database query performance
- [ ] Check queue depths
- [ ] Review application logs

### Post-Test

- [ ] Analyze Locust HTML report
- [ ] Review Grafana dashboards
- [ ] Check for memory leaks
- [ ] Identify slow queries
- [ ] Document findings
- [ ] Create optimization tickets

## CI/CD Integration

### GitHub Actions Example

```yaml
# .github/workflows/performance-test.yml
name: Performance Test

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:

jobs:
  performance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Start CatNet
        run: docker-compose up -d

      - name: Wait for health
        run: |
          timeout 60 bash -c 'until curl -f http://localhost:8000/health; do sleep 2; done'

      - name: Run load test
        run: |
          pip install locust
          locust -f tests/performance/locustfile.py \
            --host=http://localhost:8000 \
            --users 100 \
            --spawn-rate 10 \
            --run-time 5m \
            --headless \
            --html=results/report.html

      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: performance-report
          path: results/

      - name: Check performance thresholds
        run: |
          # Parse results and fail if thresholds exceeded
          python scripts/check_performance.py results/load_test_stats.csv
```

## Best Practices

1. **Run tests regularly:** Weekly baseline tests, daily smoke tests
2. **Test in staging:** Match production configuration as closely as possible
3. **Version your tests:** Track locustfile.py changes with your code
4. **Set SLAs:** Define acceptable performance metrics
5. **Automate alerts:** Notify on performance regressions
6. **Document baselines:** Track performance over time
7. **Test failure modes:** Don't just test happy paths
8. **Clean data between tests:** Ensure consistent test conditions

## Resources

- [Locust Documentation](https://docs.locust.io/)
- [FastAPI Performance](https://fastapi.tiangolo.com/deployment/concepts/)
- [PostgreSQL Performance Tuning](https://wiki.postgresql.org/wiki/Performance_Optimization)
- [Redis Performance Best Practices](https://redis.io/topics/optimization)

---

**Last Updated:** 2025-10-28
