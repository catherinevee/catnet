# CatNet Performance Testing

Performance and load testing for CatNet using Locust.

## Setup

### Install Locust

```bash
pip install locust
```

Or add to [requirements-dev.txt](../../requirements-dev.txt):
```
locust==2.17.0
```

## Running Tests

### 1. Basic Load Test

Start CatNet:
```bash
docker-compose up -d
```

Run Locust:
```bash
locust -f tests/performance/locustfile.py --host http://localhost:8000
```

Open web UI: http://localhost:8089

### 2. Headless Mode (CI/CD)

```bash
# Run with 100 users, spawn rate 10/sec, for 5 minutes
locust -f tests/performance/locustfile.py \
       --host http://localhost:8000 \
       --users 100 \
       --spawn-rate 10 \
       --run-time 5m \
       --headless \
       --html report.html
```

### 3. Distributed Load Testing

**Master:**
```bash
locust -f tests/performance/locustfile.py \
       --host http://localhost:8000 \
       --master
```

**Workers (run on multiple machines):**
```bash
locust -f tests/performance/locustfile.py \
       --host http://localhost:8000 \
       --worker \
       --master-host=<master-ip>
```

### 4. Specific User Types

Test only authentication:
```bash
locust -f tests/performance/locustfile.py \
       --host http://localhost:8000 \
       --tags authentication
```

### 5. Load Shape Tests

**Step Load (gradual increase):**
```bash
locust -f tests/performance/locustfile.py \
       --host http://localhost:8000 \
       --shape-class StepLoadShape
```

**Spike Load (sudden bursts):**
```bash
locust -f tests/performance/locustfile.py \
       --host http://localhost:8000 \
       --shape-class SpikeLoadShape
```

## Test Scenarios

### User Types

1. **HealthCheckUser** (Weight: 1)
   - Basic health checks
   - Readiness probes
   - Prometheus metrics
   - Wait time: 1-3 seconds

2. **AuthenticationUser** (Weight: 3)
   - User registration
   - Login/logout
   - Profile retrieval
   - Wait time: 2-5 seconds

3. **DeviceManagementUser** (Weight: 2)
   - List devices
   - Get device details
   - Check device health
   - Wait time: 3-7 seconds

4. **DeploymentUser** (Weight: 2)
   - List deployments
   - Create deployments
   - Check deployment status
   - Wait time: 5-10 seconds

5. **APIBrowser** (Weight: 1)
   - Browse various endpoints
   - View analytics
   - Check API docs
   - Wait time: 1-5 seconds

6. **StressTestUser** (Weight: 5)
   - Rapid fire requests
   - Minimal wait time (0.5-2 seconds)
   - Used for stress testing

### Load Shapes

1. **StepLoadShape**: Gradual load increase
   - 100 users → 250 → 500 → 750 → 1000
   - 2 minutes per step
   - Total: 10 minutes

2. **SpikeLoadShape**: Sudden traffic bursts
   - Baseline: 50 users
   - Spikes to 500 and 1000 users
   - Tests resilience to sudden load

## Performance Targets

### Baseline Requirements

| Metric | Target | Critical |
|--------|--------|----------|
| Concurrent Users | 1000+ | 500+ |
| Requests/Second | 10,000+ | 5,000+ |
| Response Time (p50) | < 100ms | < 200ms |
| Response Time (p95) | < 300ms | < 500ms |
| Response Time (p99) | < 500ms | < 1000ms |
| Error Rate | < 0.1% | < 1% |
| CPU Usage | < 70% | < 90% |
| Memory Usage | < 80% | < 95% |

### Endpoint-Specific Targets

| Endpoint | p50 | p95 | p99 |
|----------|-----|-----|-----|
| /health | < 10ms | < 20ms | < 50ms |
| /ready | < 50ms | < 100ms | < 200ms |
| GET /api/v1/devices | < 100ms | < 300ms | < 500ms |
| POST /api/v1/auth/login | < 200ms | < 500ms | < 1000ms |
| POST /api/v1/deployments | < 500ms | < 1000ms | < 2000ms |

## Test Data Setup

### Create Test Users

```python
# scripts/create_test_users.py
import requests

BASE_URL = "http://localhost:8000"

for i in range(100):
    response = requests.post(
        f"{BASE_URL}/api/v1/auth/register",
        json={
            "username": f"test_user_{i}",
            "email": f"test_user_{i}@example.com",
            "password": "SecurePassword123!",
        }
    )
    print(f"Created user {i}: {response.status_code}")
```

### Create Test Devices

```python
# scripts/create_test_devices.py
import requests

BASE_URL = "http://localhost:8000"
TOKEN = "your-admin-token"

for i in range(100):
    response = requests.post(
        f"{BASE_URL}/api/v1/devices",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={
            "hostname": f"router-{i}.example.com",
            "ip_address": f"10.0.{i // 255}.{i % 255}",
            "vendor": "cisco_ios",
            "device_type": "router",
        }
    )
    print(f"Created device {i}: {response.status_code}")
```

## Monitoring During Tests

### Prometheus Queries

1. **Request Rate:**
   ```promql
   rate(catnet_requests_total[1m])
   ```

2. **Response Time:**
   ```promql
   histogram_quantile(0.95, rate(catnet_request_duration_seconds_bucket[1m]))
   ```

3. **Error Rate:**
   ```promql
   rate(catnet_requests_total{status=~"5.."}[1m])
   ```

### System Metrics

Monitor with:
```bash
# CPU and Memory
docker stats

# Database connections
docker exec catnet-postgres psql -U catnet -c "SELECT count(*) FROM pg_stat_activity;"

# Redis memory
docker exec catnet-redis redis-cli info memory
```

## Interpreting Results

### Good Performance Indicators

- ✅ Response times within targets
- ✅ Error rate < 0.1%
- ✅ Consistent performance over time
- ✅ Graceful degradation under load
- ✅ Quick recovery after spike

### Warning Signs

- ⚠️ Response times increasing over time (memory leak?)
- ⚠️ Error rate > 0.1%
- ⚠️ Database connection pool exhaustion
- ⚠️ Redis memory growing unbounded
- ⚠️ Timeouts on specific endpoints

### Critical Issues

- 🔴 Error rate > 1%
- 🔴 Response times > 1 second (p99)
- 🔴 Service crashes under load
- 🔴 Database/Redis connection failures
- 🔴 Memory exhaustion

## Optimization Tips

### If Response Times Are High:

1. **Check Database Queries**
   - Add indexes
   - Optimize N+1 queries
   - Use connection pooling

2. **Enable Caching**
   - Redis for session data
   - Cache expensive queries
   - Set appropriate TTLs

3. **Optimize Code**
   - Profile hot paths
   - Use async/await properly
   - Avoid blocking operations

### If Error Rate Is High:

1. **Check Logs**
   ```bash
   docker logs catnet-main
   ```

2. **Increase Timeouts**
   - Database connection timeout
   - HTTP client timeout
   - Worker timeout

3. **Scale Resources**
   - Add more workers
   - Increase database connections
   - Scale Redis

## CI/CD Integration

Add to GitHub Actions:

```yaml
# .github/workflows/performance.yml
name: Performance Tests

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly
  workflow_dispatch:

jobs:
  performance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install locust

      - name: Start services
        run: docker-compose up -d

      - name: Wait for services
        run: sleep 30

      - name: Run performance tests
        run: |
          locust -f tests/performance/locustfile.py \\
                 --host http://localhost:8000 \\
                 --users 100 \\
                 --spawn-rate 10 \\
                 --run-time 5m \\
                 --headless \\
                 --html performance-report.html \\
                 --csv performance-results

      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: performance-report
          path: |
            performance-report.html
            performance-results_*.csv

      - name: Check performance thresholds
        run: |
          # Fail if p95 > 500ms or error rate > 1%
          python scripts/check_performance.py performance-results_stats.csv
```

## Troubleshooting

### Locust Won't Start

```bash
# Check Python version (requires 3.7+)
python --version

# Reinstall Locust
pip uninstall locust
pip install locust

# Check for port conflicts
lsof -i :8089
```

### Connection Refused

```bash
# Verify CatNet is running
curl http://localhost:8000/health

# Check Docker containers
docker ps

# Check logs
docker logs catnet-main
```

### Performance Degradation

```bash
# Restart services
docker-compose restart

# Clear Redis cache
docker exec catnet-redis redis-cli FLUSHALL

# Check database connections
docker exec catnet-postgres psql -U catnet -c "SELECT * FROM pg_stat_activity;"
```

## Resources

- [Locust Documentation](https://docs.locust.io/)
- [Performance Testing Guide](https://www.nginx.com/blog/performance-testing/)
- [Grafana Dashboard for Locust](https://grafana.com/grafana/dashboards/13906)

---

**Last Updated:** 2025-10-25
