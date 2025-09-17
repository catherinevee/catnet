# CatNet Operational Runbooks

## Table of Contents
1. [System Deployment](#system-deployment)
2. [Incident Response](#incident-response)
3. [Disaster Recovery](#disaster-recovery)
4. [Security Procedures](#security-procedures)
5. [Maintenance Procedures](#maintenance-procedures)
6. [Troubleshooting Guide](#troubleshooting-guide)

---

## System Deployment

### Initial Deployment Runbook

#### Prerequisites
- [ ] Docker and Docker Compose installed
- [ ] PostgreSQL 14+ with TimescaleDB
- [ ] Redis 7+
- [ ] HashiCorp Vault configured
- [ ] SSL certificates generated
- [ ] DNS configured

#### Step 1: Environment Setup
```bash
# Clone repository
git clone https://github.com/catherinevee/catnet.git
cd catnet

# Create environment file
cp .env.example .env

# Edit environment variables
vim .env
```

Required environment variables:
```bash
DATABASE_URL=postgresql://catnet:password@localhost:5432/catnet
REDIS_URL=redis://localhost:6379
VAULT_URL=http://localhost:8200
VAULT_TOKEN=your-vault-token
JWT_SECRET_KEY=generate-strong-secret
ENVIRONMENT=production
```

#### Step 2: Database Setup
```bash
# Run database migrations
alembic upgrade head

# Create initial admin user
python scripts/create_admin.py

# Load initial data
python scripts/create_test_data.py
```

#### Step 3: Generate Certificates
```bash
# Generate CA and service certificates
python scripts/generate_ca.py

# Verify certificates
openssl verify -CAfile certs/ca.crt certs/*.crt
```

#### Step 4: Configure Vault
```bash
# Initialize Vault
vault operator init

# Unseal Vault
vault operator unseal <key1>
vault operator unseal <key2>
vault operator unseal <key3>

# Configure secrets engine
vault secrets enable -path=catnet kv-v2

# Store initial secrets
vault kv put catnet/database username=catnet password=secure-password
```

#### Step 5: Deploy Services
```bash
# Build Docker images
docker-compose build

# Start services
docker-compose up -d

# Verify services are running
docker-compose ps

# Check logs
docker-compose logs -f
```

#### Step 6: Verify Deployment
```bash
# Health check
curl https://api.catnet.local/health

# API test
curl -H "Authorization: Bearer $TOKEN" https://api.catnet.local/api/v1/devices

# Check metrics
curl https://api.catnet.local/metrics
```

#### Post-Deployment Checklist
- [ ] All services healthy
- [ ] Database connections working
- [ ] Redis cache operational
- [ ] Vault accessible
- [ ] API endpoints responding
- [ ] Monitoring configured
- [ ] Backups scheduled
- [ ] Documentation updated

---

### Rolling Update Deployment

#### Pre-Update
```bash
# Backup current state
docker-compose exec db pg_dump catnet > backup_$(date +%Y%m%d).sql

# Tag current version
docker tag catnet:latest catnet:rollback

# Notify users
python scripts/send_maintenance_notice.py
```

#### Update Process
```bash
# Pull latest code
git pull origin main

# Build new images
docker-compose build

# Rolling update - one service at a time
docker-compose up -d --no-deps auth-service
sleep 30 && docker-compose exec auth-service /health_check.sh

docker-compose up -d --no-deps gitops-service
sleep 30 && docker-compose exec gitops-service /health_check.sh

docker-compose up -d --no-deps deployment-service
sleep 30 && docker-compose exec deployment-service /health_check.sh

docker-compose up -d --no-deps device-service
sleep 30 && docker-compose exec device-service /health_check.sh
```

#### Rollback Procedure
```bash
# If update fails, rollback immediately
docker-compose down

# Restore previous version
docker tag catnet:rollback catnet:latest

# Restart services
docker-compose up -d

# Restore database if needed
docker-compose exec db psql catnet < backup_$(date +%Y%m%d).sql
```

---

## Incident Response

### Security Incident Response

#### Severity Levels
- **P1 (Critical)**: Active security breach, data exposure
- **P2 (High)**: Attempted breach, suspicious activity
- **P3 (Medium)**: Policy violation, misconfiguration
- **P4 (Low)**: Informational, no immediate risk

#### Initial Response (First 15 minutes)

1. **Assess the Situation**
```bash
# Check active sessions
python scripts/list_active_sessions.py

# Review recent audit logs
python scripts/audit_search.py --last-hour --type=security

# Check for anomalies
python scripts/detect_anomalies.py
```

2. **Contain the Threat**
```bash
# Block suspicious IP
iptables -A INPUT -s <suspicious_ip> -j DROP

# Disable compromised account
python scripts/disable_user.py --user=<username>

# Revoke all sessions for user
python scripts/revoke_sessions.py --user=<username>
```

3. **Preserve Evidence**
```bash
# Capture network traffic
tcpdump -i any -w incident_$(date +%Y%m%d_%H%M%S).pcap

# Export audit logs
python scripts/export_audit_logs.py --start="1 hour ago"

# Snapshot system state
docker-compose exec catnet-api ps aux > processes.txt
docker-compose exec catnet-api netstat -an > connections.txt
```

#### Investigation Phase

1. **Analyze Logs**
```bash
# Search for specific user activity
grep <user_id> /var/log/catnet/audit.log

# Check for authentication failures
grep "auth_failed" /var/log/catnet/security.log | tail -100

# Review deployment history
python scripts/deployment_history.py --user=<user_id>
```

2. **Check for Persistence**
```bash
# Look for scheduled tasks
crontab -l
at -l

# Check for new services
systemctl list-units --all

# Review SSH keys
find /home -name "authorized_keys" -exec cat {} \;
```

#### Remediation

1. **Remove Threat**
```bash
# Remove malicious files
rm -f /tmp/suspicious_file

# Reset compromised credentials
python scripts/force_password_reset.py --user=all

# Rotate secrets
vault kv put catnet/rotated/$(date +%Y%m%d) @old_secrets.json
```

2. **Patch Vulnerabilities**
```bash
# Update vulnerable packages
apt-get update && apt-get upgrade

# Apply security patches
docker-compose pull
docker-compose up -d
```

#### Recovery

1. **Restore Services**
```bash
# Restart affected services
docker-compose restart

# Verify functionality
python scripts/health_check_all.py
```

2. **Monitor for Recurrence**
```bash
# Enhanced monitoring
python scripts/enhanced_monitoring.py --duration=24h

# Review alerts
tail -f /var/log/catnet/alerts.log
```

#### Post-Incident

1. **Documentation**
   - Timeline of events
   - Actions taken
   - Lessons learned
   - Process improvements

2. **Communication**
   - Stakeholder notification
   - Customer communication (if required)
   - Regulatory reporting (if required)

---

## Disaster Recovery

### Database Recovery

#### Backup Procedures
```bash
# Automated daily backup
0 2 * * * /usr/local/bin/backup_database.sh

# Manual backup
pg_dump -h localhost -U catnet -d catnet > catnet_backup_$(date +%Y%m%d).sql

# Backup to S3
aws s3 cp catnet_backup_*.sql s3://catnet-backups/database/
```

#### Restore Procedures
```bash
# Stop application
docker-compose stop

# Restore database
psql -h localhost -U catnet -d catnet < catnet_backup_20250917.sql

# Verify data integrity
psql -h localhost -U catnet -d catnet -c "SELECT COUNT(*) FROM devices;"

# Restart application
docker-compose start
```

### Service Recovery

#### Single Service Failure
```bash
# Identify failed service
docker-compose ps

# Check logs
docker-compose logs <service_name> --tail=100

# Restart service
docker-compose restart <service_name>

# If restart fails, rebuild
docker-compose up -d --build --no-deps <service_name>
```

#### Complete System Recovery
```bash
# Full system restore from backup
./scripts/disaster_recovery.sh

# Verify all services
for service in auth gitops deployment device; do
    curl -f http://localhost:808X/health || echo "$service is down"
done

# Resync data
python scripts/sync_from_backup.py
```

### Data Center Failover

#### Failover Process
```bash
# Update DNS to point to DR site
aws route53 change-resource-record-sets --hosted-zone-id Z123456 \
    --change-batch file://failover-dns.json

# Start services at DR site
ssh dr-site "cd /opt/catnet && docker-compose up -d"

# Verify DR site
curl https://dr.catnet.local/health

# Sync recent data
rsync -avz primary:/var/lib/catnet/ dr-site:/var/lib/catnet/
```

---

## Security Procedures

### Certificate Rotation

#### Rotating Service Certificates
```bash
# Generate new certificates
python scripts/generate_ca.py --rotate

# Deploy new certificates
for service in auth gitops deployment device; do
    docker cp certs/${service}.crt catnet_${service}_1:/etc/ssl/
    docker cp certs/${service}.key catnet_${service}_1:/etc/ssl/
    docker-compose restart ${service}
done

# Verify new certificates
openssl s_client -connect localhost:8081 -showcerts
```

#### Rotating Device Certificates
```python
# Python script for device cert rotation
import asyncio
from src.devices.cert_manager import DeviceCertificateManager

async def rotate_all_certs():
    manager = DeviceCertificateManager()
    result = await manager.rotate_device_certs(force=True)
    print(f"Rotated {result['rotated']} certificates")

asyncio.run(rotate_all_certs())
```

### Key Rotation

#### Vault Key Rotation
```bash
# Generate new key
vault operator generate-root -init

# Rotate encryption key
vault operator rekey -init -key-shares=5 -key-threshold=3

# Update stored keys
vault kv put catnet/keys/new encryption_key=<new_key>
```

#### JWT Secret Rotation
```bash
# Generate new secret
openssl rand -base64 64 > jwt_secret.txt

# Update environment
export JWT_SECRET_KEY=$(cat jwt_secret.txt)

# Restart services
docker-compose restart

# Invalidate old tokens
python scripts/invalidate_all_tokens.py
```

### Security Audit

#### Weekly Security Check
```bash
# Check for vulnerabilities
docker scan catnet:latest

# Review user permissions
python scripts/audit_permissions.py

# Check certificate expiry
python scripts/check_cert_expiry.py

# Review firewall rules
iptables -L -n -v

# Check for unused accounts
python scripts/find_inactive_users.py --days=30
```

---

## Maintenance Procedures

### Database Maintenance

#### Regular Maintenance
```bash
# Vacuum and analyze
psql -h localhost -U catnet -d catnet -c "VACUUM ANALYZE;"

# Reindex
psql -h localhost -U catnet -d catnet -c "REINDEX DATABASE catnet;"

# Check for bloat
psql -h localhost -U catnet -d catnet -f check_bloat.sql

# Archive old data
python scripts/archive_old_data.py --older-than=90days
```

### Log Rotation

#### Configure Log Rotation
```bash
# /etc/logrotate.d/catnet
/var/log/catnet/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 catnet catnet
    sharedscripts
    postrotate
        docker-compose kill -s USR1 catnet-api
    endscript
}
```

### System Updates

#### Monthly Update Process
```bash
# Backup system
./scripts/full_backup.sh

# Update packages
apt-get update && apt-get upgrade

# Update Docker images
docker-compose pull

# Update application
git pull origin main
pip install -r requirements.txt

# Run migrations
alembic upgrade head

# Restart services
docker-compose down && docker-compose up -d

# Verify
python scripts/post_update_check.py
```

---

## Troubleshooting Guide

### Common Issues

#### API Not Responding
```bash
# Check service status
docker-compose ps

# Check logs
docker-compose logs api --tail=50

# Check port binding
netstat -tlnp | grep 8080

# Test connectivity
curl -v http://localhost:8080/health

# Restart if needed
docker-compose restart api
```

#### Database Connection Issues
```bash
# Test connection
psql -h localhost -U catnet -d catnet -c "SELECT 1;"

# Check connection pool
python scripts/check_db_pool.py

# Reset connections
psql -h localhost -U catnet -d catnet -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='catnet' AND pid <> pg_backend_pid();"

# Increase connection limit if needed
psql -h localhost -U postgres -c "ALTER DATABASE catnet CONNECTION LIMIT 100;"
```

#### High Memory Usage
```bash
# Check memory usage
docker stats

# Find memory leaks
python scripts/memory_profiler.py

# Clear cache
redis-cli FLUSHALL

# Restart services with memory limits
docker-compose down
docker-compose up -d --memory=2g
```

#### Slow Performance
```bash
# Check slow queries
psql -h localhost -U catnet -d catnet -c "SELECT * FROM pg_stat_statements ORDER BY total_time DESC LIMIT 10;"

# Check cache hit rate
redis-cli INFO stats | grep hit

# Profile application
python -m cProfile -o profile.stats scripts/performance_test.py

# Optimize database
python scripts/optimize_database.py
```

### Debug Mode

#### Enable Debug Logging
```bash
# Set debug environment
export LOG_LEVEL=DEBUG
export DEBUG=True

# Restart with debug
docker-compose down
docker-compose up

# Watch debug logs
tail -f /var/log/catnet/debug.log
```

#### Remote Debugging
```python
# Add to application
import debugpy
debugpy.listen(("0.0.0.0", 5678))
debugpy.wait_for_client()

# Connect with VS Code
# launch.json configuration
{
    "name": "Python: Remote Attach",
    "type": "python",
    "request": "attach",
    "connect": {
        "host": "localhost",
        "port": 5678
    }
}
```

### Performance Tuning

#### Database Tuning
```sql
-- Adjust PostgreSQL settings
ALTER SYSTEM SET shared_buffers = '4GB';
ALTER SYSTEM SET effective_cache_size = '12GB';
ALTER SYSTEM SET maintenance_work_mem = '1GB';
ALTER SYSTEM SET work_mem = '16MB';
ALTER SYSTEM SET max_connections = 200;

-- Reload configuration
SELECT pg_reload_conf();
```

#### Redis Tuning
```bash
# Edit redis.conf
maxmemory 2gb
maxmemory-policy lru
timeout 300
tcp-keepalive 60

# Restart Redis
redis-cli SHUTDOWN
redis-server /etc/redis/redis.conf
```

#### Application Tuning
```python
# Adjust connection pools
DB_POOL_SIZE = 20
DB_MAX_OVERFLOW = 10
REDIS_MAX_CONNECTIONS = 50

# Adjust timeouts
REQUEST_TIMEOUT = 30
DATABASE_TIMEOUT = 10
CACHE_TTL = 300

# Adjust workers
WORKER_COUNT = 4
WORKER_THREADS = 2
```

---

## Emergency Contacts

| Role | Name | Phone | Email |
|------|------|-------|-------|
| On-Call Lead | DevOps Team | +1-555-0100 | oncall@catnet.local |
| Security Team | Security | +1-555-0911 | security@catnet.local |
| Database Admin | DBA Team | +1-555-0102 | dba@catnet.local |
| Network Team | Network Ops | +1-555-0103 | network@catnet.local |
| Management | CTO | +1-555-0104 | cto@catnet.local |

## Escalation Matrix

| Severity | Response Time | Escalation Path |
|----------|--------------|-----------------|
| P1 (Critical) | 15 minutes | On-Call → Team Lead → CTO |
| P2 (High) | 1 hour | On-Call → Team Lead |
| P3 (Medium) | 4 hours | On-Call |
| P4 (Low) | Next business day | Regular support |

---

## Quick Commands Reference

```bash
# Service Management
docker-compose up -d                 # Start all services
docker-compose down                  # Stop all services
docker-compose restart <service>     # Restart specific service
docker-compose logs -f <service>     # Follow logs

# Database
psql -h localhost -U catnet -d catnet    # Connect to database
pg_dump catnet > backup.sql              # Backup database
psql catnet < backup.sql                 # Restore database

# Redis
redis-cli ping                       # Check Redis
redis-cli FLUSHALL                   # Clear all cache
redis-cli INFO                       # Redis statistics

# Vault
vault status                         # Check Vault status
vault kv list catnet/                # List secrets
vault kv get catnet/database         # Get secret

# Monitoring
curl http://localhost:8080/health    # Health check
curl http://localhost:8080/metrics   # Prometheus metrics
docker stats                          # Container statistics

# Security
python scripts/rotate_certs.py       # Rotate certificates
python scripts/audit_permissions.py  # Audit permissions
python scripts/check_vulnerabilities.py  # Security scan
```

---

*Last Updated: 2025-09-17*
*Version: 1.0*
*Classification: Internal Use Only*