# CatNet Deployment Guide

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Deployment Options](#deployment-options)
3. [Production Deployment](#production-deployment)
4. [Docker Deployment](#docker-deployment)
5. [Kubernetes Deployment](#kubernetes-deployment)
6. [Configuration](#configuration)
7. [Security Hardening](#security-hardening)
8. [Monitoring Setup](#monitoring-setup)
9. [Backup and Recovery](#backup-and-recovery)
10. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

#### Minimum Requirements (up to 100 devices)
- CPU: 4 cores
- RAM: 8 GB
- Storage: 50 GB SSD
- Network: 1 Gbps

#### Recommended Requirements (up to 1000 devices)
- CPU: 8 cores
- RAM: 32 GB
- Storage: 200 GB SSD
- Network: 10 Gbps

#### Enterprise Requirements (1000+ devices)
- CPU: 16+ cores
- RAM: 64+ GB
- Storage: 500+ GB SSD (NVMe preferred)
- Network: 10+ Gbps

### Software Requirements

- Operating System: Ubuntu 22.04 LTS, RHEL 8+, or Docker
- Python: 3.11+
- PostgreSQL: 14+ with TimescaleDB extension
- Redis: 7+
- HashiCorp Vault: 1.13+
- Nginx or HAProxy for load balancing

## Deployment Options

### Option 1: Standalone Server

Best for: Small to medium deployments, proof of concept

### Option 2: High Availability Cluster

Best for: Production environments requiring high availability

### Option 3: Cloud Native (Kubernetes)

Best for: Large scale, multi-region deployments

## Production Deployment

### Step 1: Prepare the Environment

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3.11 python3.11-venv python3-pip \
  postgresql-14 postgresql-client-14 redis-server nginx \
  git curl wget unzip

# Install TimescaleDB
sudo apt install -y postgresql-14-timescaledb

# Configure PostgreSQL for TimescaleDB
sudo timescaledb-tune --quiet --yes

# Restart PostgreSQL
sudo systemctl restart postgresql
```

### Step 2: Setup PostgreSQL

```bash
# Create database and user
sudo -u postgres psql <<EOF
CREATE USER catnet WITH PASSWORD 'secure_password_here';
CREATE DATABASE catnet OWNER catnet;
\c catnet
CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS uuid-ossp;
GRANT ALL PRIVILEGES ON DATABASE catnet TO catnet;
EOF

# Configure PostgreSQL for production
sudo tee -a /etc/postgresql/14/main/postgresql.conf <<EOF

# CatNet optimizations
max_connections = 200
shared_buffers = 8GB
effective_cache_size = 24GB
maintenance_work_mem = 2GB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
work_mem = 20MB
min_wal_size = 1GB
max_wal_size = 4GB
max_worker_processes = 8
max_parallel_workers_per_gather = 4
max_parallel_workers = 8
max_parallel_maintenance_workers = 4
EOF

sudo systemctl restart postgresql
```

### Step 3: Setup Redis

```bash
# Configure Redis for production
sudo tee -a /etc/redis/redis.conf <<EOF

# CatNet configuration
maxmemory 2gb
maxmemory-policy allkeys-lru
appendonly yes
appendfilename "catnet.aof"
appendfsync everysec
no-appendfsync-on-rewrite no
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb
EOF

# Set Redis password
sudo sed -i 's/# requirepass foobared/requirepass your_redis_password_here/' /etc/redis/redis.conf

sudo systemctl restart redis-server
```

### Step 4: Install HashiCorp Vault

```bash
# Download and install Vault
wget https://releases.hashicorp.com/vault/1.15.0/vault_1.15.0_linux_amd64.zip
unzip vault_1.15.0_linux_amd64.zip
sudo mv vault /usr/local/bin/
sudo chmod +x /usr/local/bin/vault

# Create Vault config
sudo mkdir -p /etc/vault /var/lib/vault

sudo tee /etc/vault/vault.hcl <<EOF
storage "file" {
  path = "/var/lib/vault"
}

listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = 0
  tls_cert_file = "/etc/vault/tls/cert.pem"
  tls_key_file  = "/etc/vault/tls/key.pem"
}

api_addr = "https://127.0.0.1:8200"
cluster_addr = "https://127.0.0.1:8201"
ui = true
EOF

# Create systemd service
sudo tee /etc/systemd/system/vault.service <<EOF
[Unit]
Description=HashiCorp Vault
Documentation=https://www.vaultproject.io/docs/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/vault/vault.hcl

[Service]
User=vault
Group=vault
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
SecureBits=keep-caps
AmbientCapabilities=CAP_IPC_LOCK
Capabilities=CAP_IPC_LOCK+ep
CapabilityBoundingSet=CAP_SYSLOG CAP_IPC_LOCK
NoNewPrivileges=yes
ExecStart=/usr/local/bin/vault server -config=/etc/vault/vault.hcl
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
StartLimitBurst=3
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

# Create vault user
sudo useradd --system --home /var/lib/vault --shell /bin/false vault
sudo chown -R vault:vault /var/lib/vault /etc/vault

# Start Vault
sudo systemctl enable vault
sudo systemctl start vault

# Initialize Vault (save the output!)
vault operator init -key-shares=5 -key-threshold=3
```

### Step 5: Deploy CatNet

```bash
# Create application user
sudo useradd -m -s /bin/bash catnet

# Clone repository
sudo -u catnet git clone https://github.com/catherinevee/catnet.git /opt/catnet
cd /opt/catnet

# Setup Python environment
sudo -u catnet python3.11 -m venv venv
sudo -u catnet venv/bin/pip install --upgrade pip
sudo -u catnet venv/bin/pip install -r requirements.txt

# Create environment file
sudo -u catnet tee .env <<EOF
# Database
DATABASE_URL=postgresql://catnet:secure_password_here@localhost/catnet
REDIS_URL=redis://:your_redis_password_here@localhost:6379

# Security
SECRET_KEY=$(openssl rand -hex 32)
JWT_SECRET=$(openssl rand -hex 32)

# Vault
VAULT_URL=https://127.0.0.1:8200
VAULT_TOKEN=your_vault_token_here

# API Configuration
API_HOST=0.0.0.0
API_PORT=8080
WORKERS=4

# Environment
ENVIRONMENT=production
LOG_LEVEL=INFO
EOF

# Run database migrations
sudo -u catnet venv/bin/alembic upgrade head

# Create systemd service
sudo tee /etc/systemd/system/catnet.service <<EOF
[Unit]
Description=CatNet Network Configuration Management
After=network.target postgresql.service redis.service vault.service

[Service]
Type=exec
User=catnet
Group=catnet
WorkingDirectory=/opt/catnet
Environment="PATH=/opt/catnet/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/opt/catnet/venv/bin/uvicorn src.main:app --host 0.0.0.0 --port 8080 --workers 4
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Start CatNet
sudo systemctl enable catnet
sudo systemctl start catnet
```

### Step 6: Setup Nginx Reverse Proxy

```bash
# Create SSL certificate
sudo mkdir -p /etc/nginx/ssl
sudo openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout /etc/nginx/ssl/catnet.key \
  -out /etc/nginx/ssl/catnet.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=catnet.local"

# Configure Nginx
sudo tee /etc/nginx/sites-available/catnet <<EOF
upstream catnet_backend {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 80;
    server_name catnet.local;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name catnet.local;

    ssl_certificate /etc/nginx/ssl/catnet.crt;
    ssl_certificate_key /etc/nginx/ssl/catnet.key;

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        proxy_pass http://catnet_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/catnet /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

## Docker Deployment

### Using Docker Compose

```bash
# Clone repository
git clone https://github.com/catherinevee/catnet.git
cd catnet

# Create environment file
cp .env.example .env
# Edit .env with your configuration

# Start services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

### Docker Compose Production Configuration

```yaml
version: '3.8'

services:
  postgres:
    image: timescale/timescaledb:latest-pg14
    environment:
      POSTGRES_DB: catnet
      POSTGRES_USER: catnet
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - catnet
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    networks:
      - catnet
    restart: unless-stopped

  vault:
    image: hashicorp/vault:latest
    cap_add:
      - IPC_LOCK
    environment:
      VAULT_ADDR: http://0.0.0.0:8200
    volumes:
      - vault_data:/vault/data
      - ./vault-config:/vault/config
    networks:
      - catnet
    restart: unless-stopped

  catnet:
    build: .
    environment:
      DATABASE_URL: postgresql://catnet:${DB_PASSWORD}@postgres/catnet
      REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379
      VAULT_URL: http://vault:8200
      VAULT_TOKEN: ${VAULT_TOKEN}
    depends_on:
      - postgres
      - redis
      - vault
    ports:
      - "8080:8080"
    networks:
      - catnet
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
  vault_data:

networks:
  catnet:
    driver: bridge
```

## Kubernetes Deployment

### Helm Chart Installation

```bash
# Add CatNet Helm repository
helm repo add catnet https://charts.catnet.io
helm repo update

# Install CatNet
helm install catnet catnet/catnet \
  --namespace catnet \
  --create-namespace \
  --values values.yaml
```

### Sample values.yaml

```yaml
replicaCount: 3

image:
  repository: catnet/catnet
  tag: "1.0.0"
  pullPolicy: IfNotPresent

service:
  type: LoadBalancer
  port: 443

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: catnet.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: catnet-tls
      hosts:
        - catnet.example.com

postgresql:
  enabled: true
  auth:
    username: catnet
    database: catnet
  persistence:
    size: 100Gi

redis:
  enabled: true
  auth:
    enabled: true
  persistence:
    size: 10Gi

vault:
  enabled: true
  server:
    ha:
      enabled: true
      replicas: 3

monitoring:
  enabled: true
  prometheus:
    enabled: true
  grafana:
    enabled: true

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
```

## Configuration

### Environment Variables

```bash
# Core Configuration
DATABASE_URL=postgresql://user:pass@host/db
REDIS_URL=redis://user:pass@host:port
VAULT_URL=https://vault.example.com
VAULT_TOKEN=s.xxxxxxxxxxxx

# Security
SECRET_KEY=<random-string>
JWT_SECRET=<random-string>
ENCRYPTION_KEY=<base64-encoded-32-bytes>

# API Settings
API_HOST=0.0.0.0
API_PORT=8080
WORKERS=4
CORS_ORIGINS=["https://app.example.com"]

# Monitoring
PROMETHEUS_ENABLED=true
TRACING_ENABLED=true
JAEGER_ENDPOINT=http://jaeger:14268

# Feature Flags
ENABLE_ML_ANOMALY=true
ENABLE_COMPLIANCE=true
ENABLE_AUTOMATION=true
```

## Security Hardening

### 1. Network Security

```bash
# Configure firewall
sudo ufw allow 22/tcp
sudo ufw allow 443/tcp
sudo ufw allow 8080/tcp
sudo ufw enable
```

### 2. TLS Configuration

```bash
# Generate strong DH parameters
openssl dhparam -out /etc/ssl/dhparam.pem 4096
```

### 3. Vault Policies

```hcl
# catnet-policy.hcl
path "catnet/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "pki/issue/*" {
  capabilities = ["create", "update"]
}

path "database/creds/*" {
  capabilities = ["read"]
}

# Apply policy
vault policy write catnet catnet-policy.hcl
```

### 4. Database Security

```sql
-- Enable row-level security
ALTER TABLE deployments ENABLE ROW LEVEL SECURITY;

-- Create policies
CREATE POLICY deployment_isolation ON deployments
  FOR ALL
  USING (user_id = current_user_id());
```

## Monitoring Setup

### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'catnet'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
```

### Grafana Dashboards

Import dashboard ID: `14537` for CatNet monitoring

### Alert Rules

```yaml
# alerts.yml
groups:
  - name: catnet
    rules:
      - alert: HighErrorRate
        expr: rate(catnet_errors_total[5m]) > 0.05
        for: 5m
        annotations:
          summary: High error rate detected
```

## Backup and Recovery

### Database Backup

```bash
#!/bin/bash
# backup.sh
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backup/postgres"

# Create backup
pg_dump -h localhost -U catnet -d catnet | \
  gzip > "${BACKUP_DIR}/catnet_${DATE}.sql.gz"

# Upload to S3 (optional)
aws s3 cp "${BACKUP_DIR}/catnet_${DATE}.sql.gz" \
  s3://backups/catnet/postgres/

# Cleanup old backups (keep 30 days)
find ${BACKUP_DIR} -type f -mtime +30 -delete
```

### Configuration Backup

```bash
# Backup device configurations
curl -X POST https://catnet.local/api/v1/devices/backup \
  -H "Authorization: Bearer ${TOKEN}"
```

### Disaster Recovery

1. **RPO (Recovery Point Objective)**: 1 hour
2. **RTO (Recovery Time Objective)**: 4 hours

Recovery procedure:
```bash
# Restore database
gunzip < backup.sql.gz | psql -h localhost -U catnet -d catnet

# Restore Vault
vault operator unseal
vault auth enable userpass

# Restart services
systemctl restart catnet
```

## Troubleshooting

### Common Issues

#### Service Won't Start

```bash
# Check logs
journalctl -u catnet -f

# Verify dependencies
systemctl status postgresql redis vault

# Test database connection
psql $DATABASE_URL -c "SELECT 1"
```

#### Authentication Failures

```bash
# Check Vault status
vault status

# Renew token
vault token renew

# Verify JWT secret
echo $JWT_SECRET | base64 -d | wc -c  # Should be 32
```

#### Performance Issues

```bash
# Check resource usage
htop

# Database slow queries
psql -c "SELECT * FROM pg_stat_statements ORDER BY total_time DESC LIMIT 10"

# Redis memory
redis-cli INFO memory
```

### Health Checks

```bash
# API health
curl https://catnet.local/health

# Database health
pg_isready -h localhost -U catnet

# Redis health
redis-cli PING

# Vault health
vault status
```

## Performance Tuning

### Database Optimization

```sql
-- Create indexes
CREATE INDEX idx_deployments_created ON deployments(created_at);
CREATE INDEX idx_devices_status ON devices(status);
CREATE INDEX idx_configs_device ON configurations(device_id);

-- Analyze tables
ANALYZE deployments;
ANALYZE devices;
ANALYZE configurations;
```

### Redis Optimization

```bash
# Set maxmemory policy
redis-cli CONFIG SET maxmemory-policy allkeys-lru

# Enable persistence
redis-cli CONFIG SET save "900 1 300 10 60 10000"
```

### Application Optimization

```python
# gunicorn_config.py
workers = 4
worker_class = "uvicorn.workers.UvicornWorker"
worker_connections = 1000
keepalive = 5
max_requests = 1000
max_requests_jitter = 50
```

## Maintenance

### Regular Tasks

#### Daily
- Check service health
- Review error logs
- Verify backup completion

#### Weekly
- Update device inventory
- Review security alerts
- Test failover procedures

#### Monthly
- Apply security patches
- Review access logs
- Update compliance reports
- Performance analysis

### Upgrade Procedure

```bash
# 1. Backup current installation
tar -czf catnet_backup_$(date +%Y%m%d).tar.gz /opt/catnet

# 2. Pull latest code
cd /opt/catnet
git fetch origin
git checkout v1.1.0

# 3. Update dependencies
venv/bin/pip install -r requirements.txt

# 4. Run migrations
venv/bin/alembic upgrade head

# 5. Restart service
systemctl restart catnet

# 6. Verify
curl https://catnet.local/health
```

## Support

For production support:
- Documentation: https://docs.catnet.io
- Enterprise Support: enterprise@catnet.io
- Community Forum: https://forum.catnet.io