# CatNet Usage Guide

## Table of Contents
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Advanced Features](#advanced-features)
- [Common Workflows](#common-workflows)
- [Troubleshooting](#troubleshooting)

## Quick Start

```bash
# Install CatNet
pip install -r requirements.txt
python setup.py install

# Start the API server
python run_catnet.py

# Or use the CLI
python catnet_cli.py --help
```

## Installation

### Prerequisites
- Python 3.11+
- PostgreSQL 14+ (or SQLite for development)
- Redis (optional, for caching)
- HashiCorp Vault (optional, for production)

### Development Setup

1. **Clone the repository:**
```bash
git clone https://github.com/yourusername/catnet.git
cd catnet
```

2. **Set up environment:**
```bash
# Copy environment template
cp config/.env.example config/.env

# Edit config/.env with your settings
# Key settings to configure:
# - DATABASE_URL (defaults to SQLite)
# - VAULT_URL (if using Vault)
# - JWT_SECRET_KEY (change for production)
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

4. **Initialize database:**
```bash
# Run migrations
alembic upgrade head
```

5. **Start the server:**
```bash
python run_catnet.py
# API will be available at http://localhost:8000
```

### Production Setup

For production, use Docker:
```bash
docker-compose -f docker/docker-compose.yml up -d
```

## Basic Usage

### 1. Command Line Interface (CLI)

The CLI provides quick access to common operations:

```bash
# Login to CatNet
python catnet_cli.py login --username admin --password yourpassword

# List all devices
python catnet_cli.py device list

# Add a new device
python catnet_cli.py device add \
  --hostname router1.example.com \
  --ip 192.168.1.1 \
  --vendor cisco \
  --model "ISR 4451"

# Deploy configuration
python catnet_cli.py deploy \
  --device router1.example.com \
  --config ./configs/router1.cfg \
  --strategy canary

# Check deployment status
python catnet_cli.py deployment status --id deployment-123

# Rollback a deployment
python catnet_cli.py deployment rollback --id deployment-123
```

### 2. Web API

The REST API provides full programmatic access:

```python
import requests

# Base URL
base_url = "http://localhost:8000/api/v1"

# Authenticate
response = requests.post(f"{base_url}/auth/login", json={
    "username": "admin",
    "password": "yourpassword"
})
token = response.json()["access_token"]

headers = {"Authorization": f"Bearer {token}"}

# Get devices
devices = requests.get(f"{base_url}/devices", headers=headers).json()

# Create deployment
deployment = requests.post(f"{base_url}/deployments",
    headers=headers,
    json={
        "device_ids": ["device-1", "device-2"],
        "configuration": "interface GigabitEthernet0/1\n description Updated",
        "strategy": "rolling",
        "validation_required": True
    }
).json()

# Check deployment status
status = requests.get(
    f"{base_url}/deployments/{deployment['id']}",
    headers=headers
).json()
```

### 3. GitOps Integration

CatNet supports GitOps workflows where configurations are stored in Git:

```bash
# Connect a Git repository
python catnet_cli.py gitops connect \
  --repo https://github.com/yourorg/network-configs \
  --branch main \
  --path configs/

# Set up webhook (in your Git provider)
# Webhook URL: https://your-catnet.com/api/v1/gitops/webhook
# Secret: your-webhook-secret

# Enable auto-deployment
python catnet_cli.py gitops auto-deploy --enable
```

## Advanced Features

### 1. Deployment Strategies

CatNet supports multiple deployment strategies:

#### Canary Deployment
Gradually roll out changes to a subset of devices:
```bash
python catnet_cli.py deploy \
  --strategy canary \
  --canary-percentage 10,25,50,100 \
  --canary-wait 5m
```

#### Rolling Deployment
Deploy to devices one at a time:
```bash
python catnet_cli.py deploy \
  --strategy rolling \
  --batch-size 5 \
  --batch-wait 2m
```

#### Blue-Green Deployment
Prepare staging config and switch:
```bash
python catnet_cli.py deploy \
  --strategy blue-green \
  --validation-time 10m
```

### 2. Compliance Checking

Run compliance checks against frameworks:

```bash
# Check PCI-DSS compliance
python catnet_cli.py compliance check --framework pci-dss

# Generate compliance report
python catnet_cli.py compliance report \
  --framework hipaa \
  --format pdf \
  --output compliance_report.pdf

# Fix compliance issues automatically
python catnet_cli.py compliance remediate --auto-fix
```

### 3. Automation Workflows

Create and run automation workflows:

```bash
# List available workflows
python catnet_cli.py workflow list

# Run a remediation workflow
python catnet_cli.py workflow run high-cpu-remediation \
  --device router1 \
  --threshold 90

# Create custom workflow
python catnet_cli.py workflow create \
  --file my_workflow.yaml
```

Example workflow file:
```yaml
name: Interface Recovery
trigger:
  type: event
  event: interface_down
steps:
  - name: Check Interface
    type: command
    command: show interface status
  - name: Reset Interface
    type: command
    command: |
      interface {{ interface }}
      shutdown
      no shutdown
  - name: Verify
    type: validation
    wait: 30
    command: show interface {{ interface }} | include up
```

### 4. ML-Powered Anomaly Detection

Enable anomaly detection for predictive maintenance:

```bash
# Train anomaly detection model
python catnet_cli.py ml train \
  --type network-traffic \
  --data-source last-30-days

# Enable real-time anomaly detection
python catnet_cli.py ml detect --enable \
  --threshold 0.95 \
  --alert-channel ops-team
```

### 5. Multi-Factor Authentication (MFA)

Set up MFA for enhanced security:

```bash
# Enable MFA for user
python catnet_cli.py user mfa enable --method totp

# Will display QR code to scan with authenticator app
# Then verify with code:
python catnet_cli.py user mfa verify --code 123456
```

## Common Workflows

### 1. Emergency Configuration Rollback

```bash
# Quick rollback to last known good config
python catnet_cli.py emergency rollback \
  --device router1 \
  --confirm

# Rollback to specific backup
python catnet_cli.py device restore \
  --device router1 \
  --backup-id backup-xyz
```

### 2. Bulk Configuration Update

```bash
# Update multiple devices from CSV
python catnet_cli.py bulk update \
  --csv device_updates.csv \
  --template config_template.j2 \
  --dry-run  # Preview changes first

# Apply after review
python catnet_cli.py bulk update \
  --csv device_updates.csv \
  --template config_template.j2 \
  --apply
```

### 3. Scheduled Maintenance

```bash
# Schedule configuration change
python catnet_cli.py schedule create \
  --name "Weekend Maintenance" \
  --time "2024-01-20 02:00 UTC" \
  --devices router1,router2 \
  --config maintenance.cfg \
  --rollback-on-failure
```

### 4. Security Incident Response

```bash
# Immediate security response
python catnet_cli.py security quarantine \
  --source-ip 192.168.1.100 \
  --action block \
  --duration 1h

# Apply emergency ACL
python catnet_cli.py security apply-acl \
  --name emergency-block \
  --devices all-edge-routers
```

## API Endpoints Reference

### Authentication
- `POST /api/v1/auth/login` - Login
- `POST /api/v1/auth/logout` - Logout
- `POST /api/v1/auth/refresh` - Refresh token
- `POST /api/v1/auth/mfa/verify` - Verify MFA code

### Devices
- `GET /api/v1/devices` - List devices
- `POST /api/v1/devices` - Add device
- `GET /api/v1/devices/{id}` - Get device details
- `PUT /api/v1/devices/{id}` - Update device
- `DELETE /api/v1/devices/{id}` - Remove device
- `POST /api/v1/devices/{id}/backup` - Backup configuration

### Deployments
- `GET /api/v1/deployments` - List deployments
- `POST /api/v1/deployments` - Create deployment
- `GET /api/v1/deployments/{id}` - Get deployment status
- `POST /api/v1/deployments/{id}/approve` - Approve deployment
- `POST /api/v1/deployments/{id}/rollback` - Rollback deployment

### GitOps
- `POST /api/v1/gitops/connect` - Connect repository
- `POST /api/v1/gitops/webhook` - Webhook endpoint
- `GET /api/v1/gitops/configs` - List configurations
- `POST /api/v1/gitops/sync` - Sync with repository

### Compliance
- `GET /api/v1/compliance/check` - Run compliance check
- `GET /api/v1/compliance/report` - Generate report
- `POST /api/v1/compliance/remediate` - Fix issues

## Configuration Files

### Device Configuration Template
```jinja2
! Generated by CatNet
hostname {{ device.hostname }}
!
interface GigabitEthernet0/0
 description {{ device.uplink_description }}
 ip address {{ device.ip_address }} {{ device.subnet_mask }}
 no shutdown
!
{% for vlan in device.vlans %}
vlan {{ vlan.id }}
 name {{ vlan.name }}
{% endfor %}
!
```

### GitOps Repository Structure
```
network-configs/
├── devices/
│   ├── routers/
│   │   ├── router1.cfg
│   │   └── router2.cfg
│   └── switches/
│       ├── switch1.cfg
│       └── switch2.cfg
├── templates/
│   ├── base_router.j2
│   └── base_switch.j2
└── catnet.yaml  # CatNet configuration
```

### CatNet Configuration (catnet.yaml)
```yaml
version: 1
deployment:
  strategy: canary
  validation_required: true
  approval_required: true
  auto_rollback: true

compliance:
  frameworks:
    - pci-dss
    - hipaa
  check_before_deploy: true

notifications:
  slack:
    webhook_url: ${SLACK_WEBHOOK}
    channel: "#network-ops"
  email:
    smtp_server: smtp.example.com
    recipients:
      - ops-team@example.com
```

## Troubleshooting

### Common Issues

#### 1. Connection Failed
```bash
# Check device connectivity
python catnet_cli.py device test --hostname router1

# Verify credentials in Vault
python catnet_cli.py vault check --device router1
```

#### 2. Deployment Stuck
```bash
# Check deployment logs
python catnet_cli.py deployment logs --id deployment-123

# Force rollback if needed
python catnet_cli.py deployment force-rollback --id deployment-123
```

#### 3. GitOps Sync Issues
```bash
# Check webhook delivery
python catnet_cli.py gitops webhook-test

# Manual sync
python catnet_cli.py gitops sync --force
```

#### 4. Performance Issues
```bash
# Check system health
python catnet_cli.py health check

# View metrics
python catnet_cli.py metrics show --last 1h
```

### Debug Mode

Enable debug mode for detailed logging:
```bash
export CATNET_DEBUG=true
export CATNET_LOG_LEVEL=DEBUG
python catnet_cli.py [command]
```

### Getting Help

```bash
# General help
python catnet_cli.py --help

# Command-specific help
python catnet_cli.py device --help
python catnet_cli.py deploy --help

# Interactive shell
python catnet_cli.py shell
>>> help()
>>> device.list()
>>> deployment.status('deployment-123')
```

## Security Best Practices

1. **Always use MFA** for production environments
2. **Rotate credentials** regularly using Vault
3. **Enable audit logging** for all changes
4. **Use GitOps** for configuration tracking
5. **Implement approval workflows** for critical changes
6. **Regular backups** before any changes
7. **Test in staging** before production
8. **Monitor anomalies** with ML detection
9. **Encrypt sensitive data** at rest and in transit
10. **Follow compliance frameworks** (PCI-DSS, HIPAA, etc.)

## Support

- Documentation: `/docs` folder
- API Reference: http://localhost:8000/docs (when running)
- Issues: GitHub Issues
- Logs: Check `/logs` folder or `data/` for errors

## License

See LICENSE file in the project root.