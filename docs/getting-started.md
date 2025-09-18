# Getting Started with CatNet

This guide will help you get CatNet up and running quickly.

## Prerequisites

Before you begin, ensure you have:

- Python 3.11 or higher
- Docker and Docker Compose (optional, for containerized deployment)
- PostgreSQL 14+ (or use Docker)
- Redis 7+ (or use Docker)
- HashiCorp Vault (or use Docker)

## Installation Methods

### Method 1: Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/catnet/catnet.git
cd catnet

# Copy environment template
cp .env.example .env
# Edit .env with your settings

# Start all services
docker-compose up -d

# Check service health
docker-compose ps
```

### Method 2: Local Installation

```bash
# Clone the repository
git clone https://github.com/catnet/catnet.git
cd catnet

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install CatNet
pip install -e .

# Install development dependencies (optional)
pip install -e ".[dev]"
```

## Initial Configuration

### 1. Database Setup

```bash
# Run migrations
alembic upgrade head

# Create initial admin user
python scripts/create_admin.py
```

### 2. Vault Setup

```bash
# Initialize Vault (if not already done)
vault operator init -key-shares=5 -key-threshold=3

# Unseal Vault (use 3 of the 5 keys)
vault operator unseal <key1>
vault operator unseal <key2>
vault operator unseal <key3>

# Login to Vault
vault login <root-token>

# Enable KV secrets engine
vault secrets enable -path=catnet kv-v2
```

### 3. Generate Certificates

```bash
# Generate CA and certificates for mTLS
python scripts/generate_ca.py
```

## Your First Deployment

### Step 1: Start CatNet Services

```bash
# Using Docker
docker-compose up -d

# Or locally
make run
```

### Step 2: Login via CLI

```bash
# Authenticate
catnet auth login
Username: admin
Password: ********
MFA Token: 123456

✓ Authentication successful
```

### Step 3: Add a Device

```bash
# Add a network device
catnet device add \
  --hostname router1 \
  --ip 192.168.1.1 \
  --vendor cisco \
  --model ISR4451

✓ Device added successfully
Device ID: dev-abc-123
```

### Step 4: Connect Git Repository

```bash
# Connect your configuration repository
catnet gitops connect \
  --url https://github.com/yourorg/network-configs \
  --branch main

✓ Repository connected successfully
Repository ID: repo-xyz-789
Webhook URL: https://catnet.example.com/webhook/repo-xyz-789
```

### Step 5: Deploy Configuration

```bash
# Create a deployment
catnet deploy create \
  --config-file configs/router1.yml \
  --target router1 \
  --strategy canary

✓ Deployment created successfully
Deployment ID: dep-123-456
Status: pending
```

### Step 6: Monitor Deployment

```bash
# Check deployment status
catnet deploy status dep-123-456

Deployment: dep-123-456
Status: in_progress
Progress: 50%

Device status:
  ✓ router1: success
```

## Using the API

### Authentication

```python
import requests

# Login
response = requests.post('http://localhost:8081/auth/login', json={
    'username': 'admin',
    'password': 'your_password',
    'mfa_token': '123456'
})

token = response.json()['access_token']
headers = {'Authorization': f'Bearer {token}'}
```

### List Devices

```python
# Get all devices
response = requests.get('http://localhost:8084/devices', headers=headers)
devices = response.json()

for device in devices:
    print(f"{device['hostname']} - {device['ip_address']}")
```

### Create Deployment

```python
# Deploy configuration
deployment_data = {
    'config': open('config.yml').read(),
    'targets': ['router1', 'router2'],
    'strategy': 'rolling'
}

response = requests.post(
    'http://localhost:8083/deployments',
    json=deployment_data,
    headers=headers
)

deployment_id = response.json()['id']
print(f"Deployment created: {deployment_id}")
```

## SSH Key Authentication

### Generate SSH Keys

```bash
# Generate new SSH key pair
catnet ssh generate --type ed25519 --output ~/.ssh/catnet_key

✓ SSH key pair generated
Private key: ~/.ssh/catnet_key
Public key: ~/.ssh/catnet_key.pub
```

### Add SSH Key to User Account

```bash
# Add public key for authentication
catnet ssh add-user \
  --key-file ~/.ssh/catnet_key.pub \
  --name "My Workstation"

✓ SSH key added successfully
```

### Configure Device for SSH

```bash
# Generate and deploy SSH key to device
catnet ssh add-device router1 --generate --deploy

✓ SSH key generated and stored
✓ Public key deployed to device
```

## GitOps Workflow

### Repository Structure

```
network-configs/
├── devices/
│   ├── router1.yml
│   ├── router2.yml
│   └── switch1.yml
├── templates/
│   ├── cisco_base.j2
│   └── juniper_base.j2
├── deployments/
│   ├── production.yml
│   └── staging.yml
└── catnet.yml  # CatNet configuration
```

### Webhook Configuration

1. Add webhook in GitHub/GitLab:
   - URL: `https://catnet.example.com/webhook/repo-xyz-789`
   - Content Type: `application/json`
   - Secret: Use the secret from `catnet gitops connect`

2. Configure branch protection:
   - Require pull request reviews
   - Require status checks
   - Include CatNet validation checks

### Automatic Deployment

When you push to your repository:

1. CatNet receives webhook
2. Validates configuration syntax
3. Checks security compliance
4. Creates deployment plan
5. Executes deployment (if auto-deploy enabled)
6. Reports status back to Git

## Monitoring and Observability

### Prometheus Metrics

```bash
# View metrics
curl http://localhost:8000/metrics
```

### Health Checks

```bash
# Check service health
catnet status

✓ Authenticated
Service Status:
  ✓ Authentication Service
  ✓ GitOps Service
  ✓ Deployment Service
  ✓ Device Service
```

### Audit Logs

```bash
# View recent audit events
catnet audit logs --limit 10
```

## Best Practices

1. **Always test in staging**: Deploy to staging environment first
2. **Use canary deployments**: Start with a small percentage of devices
3. **Enable automatic rollback**: Configure rollback on failure
4. **Monitor health checks**: Ensure devices are healthy post-deployment
5. **Use version control**: Store all configurations in Git
6. **Enable MFA**: Require multi-factor authentication for all users
7. **Rotate credentials**: Regularly rotate device and user credentials
8. **Review audit logs**: Monitor for suspicious activity

## Next Steps

- [Configure MFA](security/mfa-setup.md)
- [Setup GitOps Pipeline](gitops/pipeline-setup.md)
- [Advanced Deployment Strategies](deployment/strategies.md)
- [API Reference](API_DOCUMENTATION.md)
- [Troubleshooting Guide](troubleshooting.md)

## Need Help?

- Check the [FAQ](faq.md)
- Browse [Examples](../examples/)
- Report [Issues](https://github.com/catnet/catnet/issues)
- Contact support@catnet.io