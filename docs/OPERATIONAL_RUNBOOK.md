# CatNet Operational Runbook

**Purpose:** Step-by-step procedures for common operational tasks
**Audience:** System administrators, DevOps engineers, on-call engineers
**Last Updated:** 2025-10-28

---

## 📋 Table of Contents

1. [Deployment Procedures](#deployment-procedures)
2. [Backup & Recovery](#backup--recovery)
3. [Scaling Operations](#scaling-operations)
4. [Troubleshooting](#troubleshooting)
5. [Maintenance Tasks](#maintenance-tasks)
6. [Security Operations](#security-operations)
7. [Monitoring & Alerts](#monitoring--alerts)
8. [Emergency Procedures](#emergency-procedures)

---

## 🚀 Deployment Procedures

### Standard Deployment Process

**When to use:** Regular configuration deployments

**Prerequisites:**
- [ ] Configuration tested in staging
- [ ] Change request approved
- [ ] Rollback plan documented
- [ ] On-call engineer notified

**Steps:**

1. **Pre-deployment Check**
   ```bash
   # Check system health
   curl http://localhost:8000/api/v1/health/detailed

   # Verify no active deployments
   curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:8000/api/v1/deployments?status=in_progress
   ```

2. **Create Deployment**
   ```bash
   DEPLOYMENT_ID=$(curl -X POST \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "ACL Update - CHANGE-12345",
       "strategy": "canary",
       "device_ids": ["device-uuid-1", "device-uuid-2"],
       "config_source": "git",
       "repository_id": "repo-uuid",
       "rollback_on_failure": true
     }' \
     http://localhost:8000/api/v1/deployments | jq -r '.id')

   echo "Deployment ID: $DEPLOYMENT_ID"
   ```

3. **Approve Deployment**
   ```bash
   curl -X POST \
     -H "Authorization: Bearer $TOKEN" \
     http://localhost:8000/api/v1/deployments/$DEPLOYMENT_ID/approve
   ```

4. **Monitor Progress**
   ```bash
   # Watch deployment status
   watch -n 5 "curl -s -H 'Authorization: Bearer \$TOKEN' \
     http://localhost:8000/api/v1/deployments/\$DEPLOYMENT_ID | jq '.progress'"
   ```

5. **Verify Success**
   ```bash
   # Check final status
   STATUS=$(curl -s -H "Authorization: Bearer $TOKEN" \
     http://localhost:8000/api/v1/deployments/$DEPLOYMENT_ID | jq -r '.status')

   if [ "$STATUS" = "completed" ]; then
     echo "✅ Deployment successful"
   else
     echo "❌ Deployment failed: $STATUS"
   fi
   ```

6. **Post-deployment Validation**
   ```bash
   # Run health checks
   curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:8000/api/v1/deployments/$DEPLOYMENT_ID/health-checks

   # Check device connectivity
   curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:8000/api/v1/devices/device-uuid-1/ping
   ```

**Rollback Procedure:**
```bash
# If deployment fails or causes issues
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Unexpected packet loss"}' \
  http://localhost:8000/api/v1/deployments/$DEPLOYMENT_ID/rollback
```

---

### Emergency Deployment

**When to use:** Critical security patches, urgent fixes

**Time Estimate:** 15-30 minutes

**Steps:**

1. **Enable Fast-Track Mode**
   ```bash
   # Bypass approval requirements (requires admin)
   curl -X POST \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     http://localhost:8000/api/v1/admin/fast-track/enable
   ```

2. **Create Emergency Deployment**
   ```json
   {
     "name": "EMERGENCY: Security Patch CVE-2024-XXXX",
     "strategy": "immediate",
     "device_ids": ["all"],
     "config_source": "inline",
     "config_content": "...",
     "approval_required": false,
     "priority": "critical"
   }
   ```

3. **Monitor Closely**
   - Watch all device statuses
   - Check for error patterns
   - Prepare rollback immediately if issues detected

4. **Disable Fast-Track**
   ```bash
   curl -X POST \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     http://localhost:8000/api/v1/admin/fast-track/disable
   ```

---

## 💾 Backup & Recovery

### Database Backup

**Frequency:** Daily at 2 AM, before major changes

**Manual Backup:**
```bash
# Create backup
docker-compose exec postgres pg_dump -U catnet catnet | gzip > \
  backups/catnet_$(date +%Y%m%d_%H%M%S).sql.gz

# Verify backup
gunzip -t backups/catnet_$(date +%Y%m%d_%H%M%S).sql.gz

# Upload to S3 (if configured)
aws s3 cp backups/catnet_$(date +%Y%m%d_%H%M%S).sql.gz \
  s3://catnet-backups/database/
```

**Automated Backup:**
```bash
# Trigger via API
curl -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8000/api/v1/admin/backup
```

### Device Configuration Backup

**Frequency:** Before every deployment, daily automated

**Manual Backup:**
```bash
# Backup all devices
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/devices/backup-all

# Backup specific device
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/devices/{device_id}/backup
```

**Verify Backups:**
```bash
# List recent backups
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/backups?days=7"
```

### Restore from Backup

**Database Restore:**
```bash
# Stop services
docker-compose stop catnet-api catnet-workers

# Restore database
gunzip -c backups/catnet_20251028_020000.sql.gz | \
  docker-compose exec -T postgres psql -U catnet catnet

# Restart services
docker-compose up -d catnet-api catnet-workers

# Verify
curl http://localhost:8000/api/v1/health/detailed
```

**Device Configuration Restore:**
```bash
# Restore device to previous configuration
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": "device-uuid",
    "backup_id": "backup-uuid",
    "verify_before_commit": true
  }' \
  http://localhost:8000/api/v1/devices/restore
```

---

## ⚖️ Scaling Operations

### Horizontal Scaling

**Add API Instance:**
```bash
# Scale API service
docker-compose up -d --scale catnet-api=3

# Verify load balancing
for i in {1..10}; do
  curl -s http://localhost:8000/api/v1/health | jq -r '.hostname'
done
```

**Add Worker Instance:**
```bash
# Scale background workers
docker-compose up -d --scale catnet-workers=5

# Verify workers
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/admin/workers
```

### Vertical Scaling

**Increase Database Resources:**
```yaml
# docker-compose.yml
postgres:
  deploy:
    resources:
      limits:
        cpus: '4'
        memory: 8G
      reservations:
        cpus: '2'
        memory: 4G
```

**Increase Worker Concurrency:**
```bash
# Update environment variable
export MAX_WORKER_CONCURRENCY=20

# Restart workers
docker-compose restart catnet-workers
```

---

## 🔧 Troubleshooting

### Device Connection Issues

**Symptoms:** Devices showing as offline, cannot connect

**Diagnosis:**
```bash
# Check device status
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/devices/{device_id}

# Test connectivity
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/devices/{device_id}/test-connection

# Check Vault credentials
docker-compose exec vault vault kv get secret/catnet/devices/{device_id}
```

**Solutions:**

1. **Network Connectivity**
   ```bash
   # Ping device
   ping 192.168.1.1

   # Check SSH port
   nc -zv 192.168.1.1 22

   # Test from container
   docker-compose exec catnet-api ping 192.168.1.1
   ```

2. **Credential Issues**
   ```bash
   # Rotate credentials
   curl -X POST \
     -H "Authorization: Bearer $TOKEN" \
     http://localhost:8000/api/v1/devices/{device_id}/rotate-credentials
   ```

3. **Firewall Rules**
   - Verify CatNet IP is allowed on device
   - Check security groups/ACLs
   - Ensure SSH is enabled

### Deployment Failures

**Symptoms:** Deployment stuck or failing

**Diagnosis:**
```bash
# Get deployment logs
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/deployments/{deployment_id}/logs

# Check worker status
docker-compose logs catnet-workers | grep ERROR

# View device-specific errors
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/deployments/{deployment_id}/devices
```

**Solutions:**

1. **Stuck Deployment**
   ```bash
   # Cancel deployment
   curl -X POST \
     -H "Authorization: Bearer $TOKEN" \
     http://localhost:8000/api/v1/deployments/{deployment_id}/cancel
   ```

2. **Configuration Syntax Errors**
   ```bash
   # Validate configuration
   curl -X POST \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d @config.json \
     http://localhost:8000/api/v1/validate
   ```

3. **Device Timeout**
   ```bash
   # Increase timeout
   export DEFAULT_DEVICE_TIMEOUT=60
   docker-compose restart catnet-workers
   ```

### High Memory Usage

**Symptoms:** OOM errors, slow responses

**Diagnosis:**
```bash
# Check container stats
docker stats

# Check database connections
docker-compose exec postgres psql -U catnet -c \
  "SELECT count(*) FROM pg_stat_activity;"

# Check Redis memory
docker-compose exec redis redis-cli INFO memory
```

**Solutions:**

1. **Restart Services**
   ```bash
   docker-compose restart catnet-api catnet-workers
   ```

2. **Clear Redis Cache**
   ```bash
   docker-compose exec redis redis-cli FLUSHDB
   ```

3. **Increase Memory Limits**
   ```yaml
   # docker-compose.yml
   catnet-api:
     deploy:
       resources:
         limits:
           memory: 2G
   ```

---

## 🛠️ Maintenance Tasks

### Weekly Tasks

**Every Monday 6 AM:**

1. **Review Logs**
   ```bash
   # Check error logs
   docker-compose logs --since 7d catnet-api | grep ERROR

   # Check deployment failures
   curl -H "Authorization: Bearer $TOKEN" \
     "http://localhost:8000/api/v1/deployments?status=failed&days=7"
   ```

2. **Database Maintenance**
   ```bash
   # Vacuum database
   docker-compose exec postgres psql -U catnet -c "VACUUM ANALYZE;"

   # Check table sizes
   docker-compose exec postgres psql -U catnet -c \
     "SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename))
      FROM pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
      ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC LIMIT 10;"
   ```

3. **Cleanup Old Data**
   ```bash
   # Trigger cleanup worker
   curl -X POST \
     -H "Authorization: Bearer $TOKEN" \
     http://localhost:8000/api/v1/admin/cleanup/run
   ```

### Monthly Tasks

**First of Month:**

1. **Credential Rotation**
   ```bash
   # Rotate device credentials (automated)
   curl -X POST \
     -H "Authorization: Bearer $TOKEN" \
     http://localhost:8000/api/v1/admin/credentials/rotate-due
   ```

2. **Certificate Renewal**
   ```bash
   # Check certificate expiry
   openssl x509 -in /etc/catnet/certs/server.crt -noout -dates

   # Renew if needed
   certbot renew
   ```

3. **Dependency Updates**
   ```bash
   # Check for updates
   pip list --outdated

   # Update in staging first
   pip install --upgrade -r requirements.txt

   # Test thoroughly before production
   pytest
   ```

---

## 🔒 Security Operations

### Rotate API Keys

```bash
# List API keys
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/admin/api-keys

# Revoke old key
curl -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/admin/api-keys/{key_id}

# Generate new key
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Production API Key", "expires_days": 90}' \
  http://localhost:8000/api/v1/admin/api-keys
```

### Review Audit Logs

```bash
# Get recent audit events
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/admin/audit-logs?days=1"

# Search for specific user actions
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/admin/audit-logs?user_id=user-uuid"

# Export for compliance
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/admin/audit-logs/export?format=csv&days=30" \
  > audit_logs_$(date +%Y%m).csv
```

### Security Incident Response

**If suspicious activity detected:**

1. **Isolate System**
   ```bash
   # Enable maintenance mode
   curl -X POST \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     http://localhost:8000/api/v1/admin/maintenance/enable
   ```

2. **Capture Evidence**
   ```bash
   # Export recent logs
   docker-compose logs > incident_logs_$(date +%Y%m%d_%H%M%S).log

   # Export audit trail
   curl -H "Authorization: Bearer $TOKEN" \
     "http://localhost:8000/api/v1/admin/audit-logs/export?days=7" \
     > incident_audit_$(date +%Y%m%d_%H%M%S).json
   ```

3. **Revoke Access**
   ```bash
   # Disable user
   curl -X POST \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     http://localhost:8000/api/v1/admin/users/{user_id}/disable

   # Revoke all sessions
   curl -X POST \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     http://localhost:8000/api/v1/admin/users/{user_id}/revoke-sessions
   ```

4. **Investigate & Report**
   - Review audit logs for unauthorized actions
   - Check deployment history for malicious changes
   - Document timeline of events
   - Report to security team

---

## 📊 Monitoring & Alerts

### Configure Alerting

**Prometheus Alert Rules:**
```yaml
# /etc/prometheus/alert.rules.yml
groups:
  - name: catnet
    rules:
      - alert: HighDeploymentFailureRate
        expr: rate(catnet_deployments_total{status="failed"}[5m]) > 0.1
        annotations:
          summary: "High deployment failure rate"

      - alert: DatabaseConnectionPoolExhausted
        expr: catnet_db_pool_active / catnet_db_pool_size > 0.9
        annotations:
          summary: "Database connection pool nearly full"
```

### Check Alert Status

```bash
# View active alerts
curl http://localhost:9090/api/v1/alerts

# Silence alert
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "matchers": [{"name": "alertname", "value": "HighDeploymentFailureRate"}],
    "startsAt": "2025-10-28T12:00:00Z",
    "endsAt": "2025-10-28T14:00:00Z",
    "comment": "Maintenance window"
  }' \
  http://localhost:9093/api/v2/silences
```

---

## 🚨 Emergency Procedures

### Complete System Failure

**Steps:**

1. **Assess Situation**
   ```bash
   # Check all services
   docker-compose ps

   # Check logs
   docker-compose logs --tail=100
   ```

2. **Restart Services**
   ```bash
   # Full restart
   docker-compose down
   docker-compose up -d

   # Wait for healthy
   sleep 30
   curl http://localhost:8000/api/v1/health/detailed
   ```

3. **If Still Failing - Restore from Backup**
   ```bash
   # Stop everything
   docker-compose down -v

   # Restore database
   gunzip -c backups/latest.sql.gz | \
     docker-compose exec -T postgres psql -U catnet catnet

   # Restart
   docker-compose up -d
   ```

### Vault Sealed

**Steps:**
```bash
# Check Vault status
curl http://localhost:8200/v1/sys/seal-status

# Unseal with keys (requires 3 of 5 key holders)
vault operator unseal <key1>
vault operator unseal <key2>
vault operator unseal <key3>

# Verify unsealed
curl http://localhost:8200/v1/sys/seal-status | jq '.sealed'
```

---

## 📞 Escalation Contacts

| Issue | Contact | Phone | Slack |
|-------|---------|-------|-------|
| System Down | On-Call Engineer | +1-XXX-XXX-XXXX | #catnet-oncall |
| Security Incident | Security Team | +1-XXX-XXX-XXXX | #security-incidents |
| Database Issues | DBA Team | +1-XXX-XXX-XXXX | #database-support |
| Network Issues | NetOps | +1-XXX-XXX-XXXX | #netops |

---

**Document Version:** 1.0
**Last Reviewed:** 2025-10-28
**Next Review:** 2025-11-28
