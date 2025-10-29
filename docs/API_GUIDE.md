# CatNet API Guide

**Version:** 1.0.0
**Base URL:** `http://localhost:8000/api/v1`
**Authentication:** Bearer JWT Token

---

## 📚 Table of Contents

1. [Authentication](#authentication)
2. [Devices](#devices)
3. [Deployments](#deployments)
4. [GitOps](#gitops)
5. [Health & Monitoring](#health--monitoring)
6. [Admin Operations](#admin-operations)
7. [Inventory Management](#inventory-management)
8. [Error Responses](#error-responses)
9. [Rate Limiting](#rate-limiting)
10. [Code Examples](#code-examples)

---

## 🔐 Authentication

### Login

Obtain a JWT token for API access.

**Endpoint:** `POST /auth/login`

**Request:**
```json
{
  "username": "admin",
  "password": "SecurePassword123!"
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

**cURL Example:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "SecurePassword123!"
  }'
```

**Python Example:**
```python
import requests

response = requests.post(
    'http://localhost:8000/api/v1/auth/login',
    json={
        'username': 'admin',
        'password': 'SecurePassword123!'
    }
)

token = response.json()['access_token']
headers = {'Authorization': f'Bearer {token}'}
```

**JavaScript Example:**
```javascript
const response = await fetch('http://localhost:8000/api/v1/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    username: 'admin',
    password: 'SecurePassword123!'
  })
});

const { access_token } = await response.json();
const headers = { 'Authorization': `Bearer ${access_token}` };
```

### MFA Setup

Enable multi-factor authentication.

**Endpoint:** `POST /auth/mfa/setup`

**Request Headers:**
```
Authorization: Bearer <token>
```

**Response (200 OK):**
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg...",
  "backup_codes": [
    "1234-5678",
    "9012-3456",
    "7890-1234"
  ]
}
```

### MFA Verification

Verify TOTP code during login.

**Endpoint:** `POST /auth/mfa/verify`

**Request:**
```json
{
  "username": "admin",
  "password": "SecurePassword123!",
  "totp_code": "123456"
}
```

---

## 🖥️ Devices

### List Devices

Retrieve all network devices.

**Endpoint:** `GET /devices`

**Query Parameters:**
- `vendor` (optional): Filter by vendor (cisco, juniper)
- `status` (optional): Filter by status (online, offline)
- `page` (optional): Page number (default: 1)
- `limit` (optional): Items per page (default: 50)

**Request:**
```bash
curl -X GET "http://localhost:8000/api/v1/devices?vendor=cisco&status=online" \
  -H "Authorization: Bearer <token>"
```

**Response (200 OK):**
```json
{
  "items": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "hostname": "core-router-01",
      "ip_address": "192.168.1.1",
      "vendor": "cisco",
      "device_type": "ios",
      "status": "online",
      "last_seen": "2025-10-28T10:30:00Z",
      "created_at": "2025-01-15T08:00:00Z",
      "tags": ["production", "core", "datacenter-1"]
    }
  ],
  "total": 142,
  "page": 1,
  "pages": 3
}
```

### Get Device Details

**Endpoint:** `GET /devices/{device_id}`

**Response (200 OK):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "hostname": "core-router-01",
  "ip_address": "192.168.1.1",
  "vendor": "cisco",
  "device_type": "ios",
  "model": "Cisco ISR 4451",
  "software_version": "17.3.4a",
  "status": "online",
  "last_backup": "2025-10-28T06:00:00Z",
  "uptime_seconds": 8640000,
  "interfaces": [
    {
      "name": "GigabitEthernet0/0/0",
      "status": "up",
      "ip_address": "10.0.1.1/24"
    }
  ],
  "neighbors": [
    {
      "device_id": "core-switch-01",
      "interface": "GigabitEthernet1/0/1"
    }
  ]
}
```

### Create Device

Add a new network device.

**Endpoint:** `POST /devices`

**Request:**
```json
{
  "hostname": "new-router-01",
  "ip_address": "192.168.1.10",
  "vendor": "cisco",
  "device_type": "ios",
  "username": "admin",
  "password": "DevicePassword123!",
  "enable_password": "EnableSecret456!",
  "port": 22,
  "tags": ["new", "testing"]
}
```

**Response (201 Created):**
```json
{
  "id": "660e8400-e29b-41d4-a716-446655440001",
  "hostname": "new-router-01",
  "ip_address": "192.168.1.10",
  "vendor": "cisco",
  "device_type": "ios",
  "status": "pending",
  "created_at": "2025-10-28T11:00:00Z"
}
```

**Note:** Credentials are automatically stored in HashiCorp Vault, not in the database.

### Update Device

**Endpoint:** `PUT /devices/{device_id}`

**Request:**
```json
{
  "hostname": "core-router-01-updated",
  "tags": ["production", "core", "datacenter-1", "critical"]
}
```

### Delete Device

**Endpoint:** `DELETE /devices/{device_id}`

**Response (204 No Content)**

---

## 🚀 Deployments

### Create Deployment

Deploy configuration changes to devices.

**Endpoint:** `POST /deployments`

**Request:**
```json
{
  "name": "Update ACLs for Security Policy 2025-Q4",
  "description": "Apply new security ACLs across core routers",
  "strategy": "canary",
  "device_ids": [
    "550e8400-e29b-41d4-a716-446655440000",
    "660e8400-e29b-41d4-a716-446655440001"
  ],
  "config_source": "git",
  "repository_id": "770e8400-e29b-41d4-a716-446655440002",
  "config_path": "configs/acl_update.yaml",
  "approval_required": true,
  "canary_stages": [5, 25, 50, 100],
  "health_check_enabled": true,
  "rollback_on_failure": true
}
```

**Deployment Strategies:**
- `rolling`: Sequential deployment with batch size
- `canary`: Staged rollout with health checks
- `blue_green`: Prepare new config, switch atomically
- `immediate`: Deploy to all devices simultaneously

**Response (201 Created):**
```json
{
  "id": "880e8400-e29b-41d4-a716-446655440003",
  "name": "Update ACLs for Security Policy 2025-Q4",
  "status": "pending_approval",
  "strategy": "canary",
  "created_at": "2025-10-28T11:15:00Z",
  "created_by": "admin",
  "total_devices": 2,
  "approval_url": "/api/v1/deployments/880e8400-e29b-41d4-a716-446655440003/approve"
}
```

### Approve Deployment

**Endpoint:** `POST /deployments/{deployment_id}/approve`

**Request:**
```json
{
  "comment": "Approved after security review"
}
```

**Response (200 OK):**
```json
{
  "id": "880e8400-e29b-41d4-a716-446655440003",
  "status": "in_progress",
  "approved_at": "2025-10-28T11:20:00Z",
  "approved_by": "admin"
}
```

### Get Deployment Status

**Endpoint:** `GET /deployments/{deployment_id}`

**Response (200 OK):**
```json
{
  "id": "880e8400-e29b-41d4-a716-446655440003",
  "name": "Update ACLs for Security Policy 2025-Q4",
  "status": "in_progress",
  "strategy": "canary",
  "progress": {
    "current_stage": 2,
    "total_stages": 4,
    "percentage": 25,
    "devices_completed": 1,
    "devices_total": 2,
    "devices_failed": 0
  },
  "timeline": [
    {
      "timestamp": "2025-10-28T11:20:00Z",
      "event": "deployment_started",
      "details": "Canary deployment initiated"
    },
    {
      "timestamp": "2025-10-28T11:22:00Z",
      "event": "stage_completed",
      "details": "Stage 1 (5%) completed successfully"
    }
  ],
  "health_checks": [
    {
      "device_id": "550e8400-e29b-41d4-a716-446655440000",
      "status": "healthy",
      "checks_passed": 3,
      "checks_failed": 0
    }
  ]
}
```

### Rollback Deployment

**Endpoint:** `POST /deployments/{deployment_id}/rollback`

**Request:**
```json
{
  "reason": "Unexpected packet loss detected"
}
```

**Response (200 OK):**
```json
{
  "id": "880e8400-e29b-41d4-a716-446655440003",
  "status": "rolling_back",
  "rollback_started_at": "2025-10-28T11:25:00Z"
}
```

---

## 📦 GitOps

### Register Git Repository

**Endpoint:** `POST /git/repositories`

**Request:**
```json
{
  "name": "network-configs",
  "url": "https://github.com/myorg/network-configs.git",
  "branch": "main",
  "webhook_secret": "MySecureWebhookSecret123!",
  "auto_sync": true,
  "sync_interval_minutes": 15,
  "gpg_verification": true
}
```

**Response (201 Created):**
```json
{
  "id": "770e8400-e29b-41d4-a716-446655440002",
  "name": "network-configs",
  "url": "https://github.com/myorg/network-configs.git",
  "branch": "main",
  "webhook_url": "https://catnet.example.com/api/v1/git/webhook",
  "last_sync": null,
  "status": "active"
}
```

### Webhook Endpoint

**Endpoint:** `POST /git/webhook`

**Headers:**
```
X-Hub-Signature-256: sha256=<signature>
X-GitHub-Event: push
```

**GitHub Webhook Payload:**
```json
{
  "ref": "refs/heads/main",
  "repository": {
    "full_name": "myorg/network-configs",
    "clone_url": "https://github.com/myorg/network-configs.git"
  },
  "commits": [
    {
      "id": "abc123def456",
      "message": "Update router-01 ACLs",
      "modified": ["configs/router-01.conf"],
      "author": {
        "name": "John Doe",
        "email": "john@example.com"
      }
    }
  ]
}
```

**Response (202 Accepted):**
```json
{
  "message": "Webhook received, processing deployment",
  "deployment_id": "990e8400-e29b-41d4-a716-446655440004"
}
```

---

## 🏥 Health & Monitoring

### Health Check

**Endpoint:** `GET /health`

**Response (200 OK):**
```json
{
  "status": "healthy",
  "timestamp": "2025-10-28T11:30:00Z",
  "version": "1.0.0"
}
```

### Detailed Health Check

**Endpoint:** `GET /health/detailed`

**Response (200 OK):**
```json
{
  "status": "healthy",
  "components": {
    "database": {
      "status": "healthy",
      "response_time_ms": 12,
      "connections": {
        "active": 5,
        "idle": 15,
        "max": 50
      }
    },
    "redis": {
      "status": "healthy",
      "response_time_ms": 3,
      "used_memory_mb": 45
    },
    "vault": {
      "status": "healthy",
      "sealed": false
    },
    "workers": {
      "status": "healthy",
      "active_tasks": 3,
      "queued_tasks": 7
    }
  },
  "metrics": {
    "total_devices": 142,
    "online_devices": 138,
    "active_deployments": 2,
    "failed_deployments_24h": 0
  }
}
```

### Prometheus Metrics

**Endpoint:** `GET /metrics`

**Response (200 OK):**
```
# HELP catnet_deployments_total Total deployments by status
# TYPE catnet_deployments_total counter
catnet_deployments_total{status="completed"} 847
catnet_deployments_total{status="failed"} 12

# HELP catnet_deployment_duration_seconds Deployment execution time
# TYPE catnet_deployment_duration_seconds histogram
catnet_deployment_duration_seconds_bucket{le="10.0"} 234
catnet_deployment_duration_seconds_bucket{le="30.0"} 456

# HELP catnet_device_connections_active Active device connections
# TYPE catnet_device_connections_active gauge
catnet_device_connections_active 138
```

---

## 👤 Admin Operations

### List Users

**Endpoint:** `GET /admin/users`

**Requires:** Admin role

**Response (200 OK):**
```json
{
  "items": [
    {
      "id": "user-001",
      "username": "admin",
      "email": "admin@example.com",
      "roles": ["admin", "operator"],
      "is_active": true,
      "mfa_enabled": true,
      "last_login": "2025-10-28T10:00:00Z"
    }
  ],
  "total": 15
}
```

### Create User

**Endpoint:** `POST /admin/users`

**Request:**
```json
{
  "username": "newoperator",
  "email": "operator@example.com",
  "password": "SecurePassword123!",
  "roles": ["operator"],
  "mfa_required": true
}
```

### Enable Maintenance Mode

**Endpoint:** `POST /admin/maintenance/enable`

**Request:**
```json
{
  "reason": "System upgrade",
  "estimated_duration_minutes": 30
}
```

**Response (200 OK):**
```json
{
  "maintenance_mode": true,
  "enabled_at": "2025-10-28T12:00:00Z",
  "message": "System in maintenance mode"
}
```

---

## 📊 Inventory Management

### Device Discovery

**Endpoint:** `POST /inventory/discover`

**Request:**
```json
{
  "subnet": "192.168.1.0/24",
  "protocols": ["ssh", "snmp"],
  "port_range": [22, 23, 161],
  "timeout_seconds": 5
}
```

**Response (202 Accepted):**
```json
{
  "task_id": "discovery-task-001",
  "status": "in_progress",
  "estimated_completion": "2025-10-28T12:15:00Z"
}
```

### Bulk Import Devices

**Endpoint:** `POST /inventory/import`

**Request:**
```json
{
  "format": "csv",
  "devices": [
    {
      "hostname": "router-10",
      "ip_address": "192.168.1.10",
      "vendor": "cisco",
      "device_type": "ios"
    },
    {
      "hostname": "router-11",
      "ip_address": "192.168.1.11",
      "vendor": "juniper",
      "device_type": "junos"
    }
  ]
}
```

### Export Inventory

**Endpoint:** `GET /inventory/export?format=csv`

**Response (200 OK):**
```csv
hostname,ip_address,vendor,device_type,status
core-router-01,192.168.1.1,cisco,ios,online
core-router-02,192.168.1.2,cisco,ios,online
```

---

## ⚠️ Error Responses

### Standard Error Format

```json
{
  "error": {
    "code": "DEVICE_NOT_FOUND",
    "message": "Device with ID 550e8400... not found",
    "details": {
      "device_id": "550e8400-e29b-41d4-a716-446655440000"
    },
    "timestamp": "2025-10-28T12:00:00Z",
    "request_id": "req-abc123"
  }
}
```

### Common Error Codes

| Code | Status | Description |
|------|--------|-------------|
| `AUTHENTICATION_FAILED` | 401 | Invalid credentials |
| `UNAUTHORIZED` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `VALIDATION_ERROR` | 422 | Invalid request data |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server error |
| `DEVICE_UNREACHABLE` | 503 | Cannot connect to device |
| `DEPLOYMENT_FAILED` | 500 | Deployment execution failed |

---

## 🚦 Rate Limiting

CatNet implements rate limiting to prevent abuse:

**Limits:**
- **Authenticated users:** 100 requests/minute
- **Admin endpoints:** 50 requests/minute
- **Unauthenticated:** 20 requests/minute

**Headers:**
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1635432000
```

**Rate Limit Exceeded Response (429):**
```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Try again in 42 seconds",
    "retry_after": 42
  }
}
```

---

## 💻 Code Examples

### Python SDK Example

```python
from catnet import CatNetClient

# Initialize client
client = CatNetClient(
    base_url='http://localhost:8000',
    username='admin',
    password='SecurePassword123!'
)

# List devices
devices = client.devices.list(vendor='cisco', status='online')
for device in devices:
    print(f"{device.hostname}: {device.status}")

# Create deployment
deployment = client.deployments.create(
    name='ACL Update',
    strategy='canary',
    device_ids=['550e8400-e29b-41d4-a716-446655440000'],
    config_source='git',
    repository_id='770e8400-e29b-41d4-a716-446655440002'
)

# Approve and monitor
deployment.approve()
while deployment.status != 'completed':
    print(f"Progress: {deployment.progress.percentage}%")
    time.sleep(10)
    deployment.refresh()
```

### JavaScript/TypeScript Example

```typescript
import { CatNetAPI } from '@catnet/api-client';

const api = new CatNetAPI({
  baseURL: 'http://localhost:8000',
  auth: {
    username: 'admin',
    password: 'SecurePassword123!'
  }
});

// List devices
const devices = await api.devices.list({
  vendor: 'cisco',
  status: 'online'
});

// Create deployment
const deployment = await api.deployments.create({
  name: 'ACL Update',
  strategy: 'canary',
  deviceIds: ['550e8400-e29b-41d4-a716-446655440000'],
  configSource: 'git',
  repositoryId: '770e8400-e29b-41d4-a716-446655440002'
});

// Monitor progress
await deployment.approve();
deployment.on('progress', (progress) => {
  console.log(`Progress: ${progress.percentage}%`);
});
```

### Go Example

```go
package main

import (
    "github.com/myorg/catnet-go"
)

func main() {
    client := catnet.NewClient(&catnet.Config{
        BaseURL: "http://localhost:8000",
        Username: "admin",
        Password: "SecurePassword123!",
    })

    // List devices
    devices, err := client.Devices.List(&catnet.DeviceFilter{
        Vendor: "cisco",
        Status: "online",
    })

    // Create deployment
    deployment, err := client.Deployments.Create(&catnet.DeploymentRequest{
        Name: "ACL Update",
        Strategy: catnet.StrategyCanary,
        DeviceIDs: []string{"550e8400-e29b-41d4-a716-446655440000"},
    })
}
```

---

## 📚 Additional Resources

- **Postman Collection:** [Download](../postman/CatNet-API.postman_collection.json)
- **OpenAPI Spec:** [Download](../openapi/catnet-api-v1.yaml)
- **SDK Documentation:** [Python](../sdk/python.md) | [JavaScript](../sdk/javascript.md) | [Go](../sdk/go.md)
- **Authentication Guide:** [docs/authentication.md](authentication.md)
- **Webhook Setup:** [docs/webhooks.md](webhooks.md)

---

**API Version:** 1.0.0
**Last Updated:** 2025-10-28
**Support:** https://github.com/your-org/catnet/issues
