# CatNet Troubleshooting Guide

**Quick reference for diagnosing and resolving common issues**

---

## 🔍 Quick Diagnostic Commands

```bash
# System health
curl http://localhost:8000/api/v1/health/detailed

# Service status
docker-compose ps

# Recent errors
docker-compose logs --tail=50 --timestamps catnet-api | grep ERROR

# Database connections
docker-compose exec postgres psql -U catnet -c "SELECT count(*) FROM pg_stat_activity;"

# Worker queue
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/admin/workers
```

---

## 🚨 Common Issues

### 1. API Not Responding

**Symptoms:** Connection timeout, 502/503 errors

**Quick Fix:**
```bash
docker-compose restart catnet-api
```

**Root Causes:**
- **High memory usage:** Check `docker stats`, increase limits
- **Database connection pool exhausted:** Restart API, increase pool size
- **Network issues:** Check Docker network with `docker network inspect catnet-network`

### 2. Deployment Stuck

**Symptoms:** Deployment shows "in_progress" for >30 minutes

**Diagnosis:**
```bash
DEPLOYMENT_ID=<uuid>
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/deployments/$DEPLOYMENT_ID/logs
```

**Solutions:**
```bash
# Option 1: Cancel and retry
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/deployments/$DEPLOYMENT_ID/cancel

# Option 2: Force complete (admin only, use with caution)
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8000/api/v1/admin/deployments/$DEPLOYMENT_ID/force-complete
```

### 3. Device Connection Failures

**Symptoms:** Devices showing offline, SSH timeouts

**Diagnosis:**
```bash
# Test from CatNet container
docker-compose exec catnet-api ssh admin@192.168.1.1

# Check Vault credentials
docker-compose exec vault vault kv get secret/catnet/devices/<device-id>

# Verify network path
docker-compose exec catnet-api traceroute 192.168.1.1
```

**Solutions:**
- Update device credentials in Vault
- Check firewall rules allow CatNet IP
- Verify device SSH is enabled
- Increase timeout: `DEFAULT_DEVICE_TIMEOUT=60`

### 4. Vault Sealed/Unavailable

**Symptoms:** "Vault is sealed" errors, cannot retrieve credentials

**Solution:**
```bash
# Check status
curl http://localhost:8200/v1/sys/seal-status

# Unseal (requires 3 of 5 keys)
vault operator unseal <key1>
vault operator unseal <key2>
vault operator unseal <key3>

# Verify
curl http://localhost:8200/v1/sys/seal-status | jq '.sealed'  # Should be false
```

### 5. Database Performance Issues

**Symptoms:** Slow API responses, timeout errors

**Diagnosis:**
```bash
# Check slow queries
docker-compose exec postgres psql -U catnet -c \
  "SELECT pid, now() - query_start as duration, query
   FROM pg_stat_activity
   WHERE state = 'active' AND now() - query_start > interval '5 seconds';"

# Check table bloat
docker-compose exec postgres psql -U catnet -c "VACUUM ANALYZE VERBOSE;"
```

**Solutions:**
```bash
# Add indexes
docker-compose exec postgres psql -U catnet -c \
  "CREATE INDEX CONCURRENTLY idx_deployments_status ON deployments(status);"

# Increase connection pool
# In .env: DATABASE_POOL_SIZE=50

# Restart database
docker-compose restart postgres
```

### 6. GitOps Webhook Not Triggering

**Symptoms:** Git pushes don't trigger deployments

**Checklist:**
- [ ] Webhook URL configured in GitHub/GitLab
- [ ] Webhook secret matches CatNet configuration
- [ ] Repository registered in CatNet
- [ ] Firewall allows incoming webhook requests

**Test Webhook:**
```bash
curl -X POST http://localhost:8000/api/v1/git/webhook \
  -H "X-Hub-Signature-256: sha256=test" \
  -H "Content-Type: application/json" \
  -d '{"ref": "refs/heads/main", "repository": {"full_name": "test/repo"}}'
```

### 7. High CPU Usage

**Symptoms:** System slow, high load average

**Diagnosis:**
```bash
# Check container CPU
docker stats --no-stream

# Check processes
docker-compose exec catnet-api top -b -n 1

# Check worker tasks
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/admin/workers | jq '.active_tasks'
```

**Solutions:**
- Scale workers: `docker-compose up -d --scale catnet-workers=5`
- Limit concurrent deployments: `MAX_PARALLEL_DEPLOYMENTS=5`
- Add CPU limits in docker-compose.yml

### 8. Authentication Failures

**Symptoms:** "Invalid credentials" despite correct password

**Diagnosis:**
```bash
# Check user status
curl -X POST http://localhost:8000/api/v1/auth/login \
  -d '{"username": "admin", "password": "password"}' | jq

# Check MFA requirement
docker-compose exec postgres psql -U catnet -c \
  "SELECT username, mfa_enabled, is_active FROM users WHERE username='admin';"
```

**Solutions:**
```bash
# Reset password (admin)
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"new_password": "NewSecure123!"}' \
  http://localhost:8000/api/v1/admin/users/{user_id}/reset-password

# Disable MFA temporarily
docker-compose exec postgres psql -U catnet -c \
  "UPDATE users SET mfa_enabled=false WHERE username='admin';"
```

### 9. Memory Leaks

**Symptoms:** Gradual memory increase, eventual OOM

**Diagnosis:**
```bash
# Monitor memory over time
watch -n 5 'docker stats --no-stream --format "table {{.Name}}\t{{.MemUsage}}"'

# Check Redis memory
docker-compose exec redis redis-cli INFO memory | grep used_memory_human
```

**Solutions:**
```bash
# Restart leaking service
docker-compose restart catnet-api

# Clear Redis cache
docker-compose exec redis redis-cli FLUSHDB

# Increase memory limit
# docker-compose.yml: memory: 2G
```

### 10. Configuration Validation Errors

**Symptoms:** Deployments rejected with "validation failed"

**Debug:**
```bash
# Validate configuration manually
curl -X POST http://localhost:8000/api/v1/validate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @config.json | jq '.errors'
```

**Common Issues:**
- Syntax errors in config files
- Missing required fields
- Invalid IP addresses/ranges
- Unsupported device commands

---

## 🔧 Advanced Diagnostics

### Enable Debug Logging

```bash
# Temporarily enable debug mode
docker-compose exec catnet-api \
  export LOG_LEVEL=DEBUG && \
  supervisorctl restart catnet-api

# Check logs
docker-compose logs -f catnet-api
```

### Database Query Analysis

```bash
# Enable query logging
docker-compose exec postgres psql -U catnet -c \
  "ALTER SYSTEM SET log_statement = 'all';"

docker-compose restart postgres

# View queries
docker-compose exec postgres tail -f /var/log/postgresql/postgresql-*.log
```

### Network Trace

```bash
# Capture traffic
docker-compose exec catnet-api tcpdump -i any -w /tmp/capture.pcap port 22

# Analyze
wireshark /tmp/capture.pcap
```

---

## 📞 When to Escalate

Escalate immediately if:
- ⚠️ Complete system outage >15 minutes
- ⚠️ Security breach suspected
- ⚠️ Data corruption detected
- ⚠️ Multiple devices offline unexpectedly
- ⚠️ Vault compromised

**Escalation:** #catnet-oncall (Slack) or +1-XXX-XXX-XXXX

---

## 📚 Additional Resources

- [Operational Runbook](OPERATIONAL_RUNBOOK.md)
- [API Documentation](API_GUIDE.md)
- [Deployment Guide](../README.md#deployment)
- [GitHub Issues](https://github.com/your-org/catnet/issues)

---

**Last Updated:** 2025-10-28
