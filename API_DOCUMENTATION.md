# CatNet API Documentation

## Base URL

```
https://api.catnet.local/api/v1
```

## Authentication

CatNet uses JWT bearer tokens for API authentication. Obtain a token through the login endpoint and include it in the Authorization header for all subsequent requests.

```http
Authorization: Bearer <token>
```

## API Endpoints

### Authentication Service (Port 8081)

#### POST /auth/login
Authenticate user and receive access token.

**Request:**
```json
{
  "username": "admin",
  "password": "password123",
  "mfa_code": "123456"  // Optional if MFA enabled
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 3600,
  "requires_mfa": false
}
```

#### POST /auth/refresh
Refresh access token using refresh token.

**Request:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

#### POST /auth/mfa/setup
Setup MFA for current user.

**Response:**
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code": "data:image/png;base64,...",
  "backup_codes": ["12345678", "87654321", ...]
}
```

#### POST /auth/logout
Invalidate current session and tokens.

### GitOps Service (Port 8082)

#### POST /git/connect
Connect a Git repository for configuration management.

**Request:**
```json
{
  "repository_url": "https://github.com/org/network-configs.git",
  "branch": "main",
  "webhook_secret": "secret123",
  "auth": {
    "type": "token",
    "token": "github_pat_..."
  }
}
```

**Response:**
```json
{
  "repository_id": "repo_123",
  "webhook_url": "https://api.catnet.local/git/webhook/repo_123",
  "status": "connected"
}
```

#### POST /git/webhook
Process Git webhook events (GitHub/GitLab/Bitbucket).

**Headers:**
```
X-Hub-Signature-256: sha256=...  // GitHub
X-Gitlab-Token: ...               // GitLab
```

**Request:**
```json
{
  "ref": "refs/heads/main",
  "commits": [...],
  "pusher": {...}
}
```

#### GET /git/configs
List configurations from connected repositories.

**Query Parameters:**
- `repository_id`: Filter by repository
- `path`: Filter by path pattern
- `device`: Filter by device

**Response:**
```json
{
  "configs": [
    {
      "id": "config_123",
      "path": "configs/routers/router1.conf",
      "repository": "repo_123",
      "last_modified": "2024-01-15T10:30:00Z",
      "commit": "abc123def",
      "signed": true
    }
  ]
}
```

### Deployment Service (Port 8083)

#### POST /deployments
Create a new deployment.

**Request:**
```json
{
  "config_source": "git://repo_123/configs/router1.conf",
  "devices": ["device_001", "device_002"],
  "strategy": "canary",
  "strategy_config": {
    "stages": [
      {"percentage": 10, "wait_minutes": 5},
      {"percentage": 50, "wait_minutes": 10},
      {"percentage": 100}
    ]
  },
  "approval_required": true,
  "rollback_on_failure": true,
  "health_checks": ["interface_status", "bgp_neighbors"],
  "schedule": "2024-01-20T02:00:00Z"  // Optional scheduled deployment
}
```

**Response:**
```json
{
  "deployment_id": "deploy_789",
  "status": "pending_approval",
  "created_at": "2024-01-15T12:00:00Z",
  "approval_url": "https://api.catnet.local/deployments/deploy_789/approve"
}
```

#### GET /deployments/{id}
Get deployment status and details.

**Response:**
```json
{
  "deployment_id": "deploy_789",
  "status": "in_progress",
  "stage": "canary",
  "progress": {
    "total_devices": 10,
    "completed": 3,
    "failed": 0,
    "pending": 7
  },
  "started_at": "2024-01-15T14:00:00Z",
  "health_status": "healthy",
  "logs": [...]
}
```

#### POST /deployments/{id}/approve
Approve a pending deployment.

**Request:**
```json
{
  "comment": "Approved after review",
  "approver": "admin"
}
```

#### POST /deployments/{id}/rollback
Initiate rollback for a deployment.

**Request:**
```json
{
  "reason": "Health checks failing",
  "rollback_to": "previous"  // or specific version
}
```

#### GET /deployments/{id}/diff
Get configuration diff for deployment.

**Response:**
```json
{
  "devices": {
    "device_001": {
      "current": "interface GigabitEthernet0/0\n ip address 192.168.1.1 255.255.255.0",
      "proposed": "interface GigabitEthernet0/0\n ip address 192.168.1.2 255.255.255.0",
      "diff": "@@ -1,2 +1,2 @@\n interface GigabitEthernet0/0\n- ip address 192.168.1.1 255.255.255.0\n+ ip address 192.168.1.2 255.255.255.0"
    }
  }
}
```

### Device Service (Port 8084)

#### GET /devices
List all managed devices.

**Query Parameters:**
- `vendor`: Filter by vendor (cisco, juniper)
- `model`: Filter by model
- `status`: Filter by status (online, offline, maintenance)
- `tag`: Filter by tags

**Response:**
```json
{
  "devices": [
    {
      "id": "device_001",
      "hostname": "core-router-01",
      "ip_address": "10.0.1.1",
      "vendor": "cisco",
      "model": "ISR4451",
      "software_version": "16.12.4",
      "status": "online",
      "last_seen": "2024-01-15T15:30:00Z",
      "tags": ["production", "core"],
      "location": "DC-1"
    }
  ],
  "total": 150,
  "page": 1
}
```

#### POST /devices
Add a new device.

**Request:**
```json
{
  "hostname": "new-switch-01",
  "ip_address": "10.0.2.1",
  "vendor": "cisco",
  "model": "Catalyst9300",
  "credentials": {
    "type": "vault",
    "path": "catnet/devices/new-switch-01"
  },
  "tags": ["production", "access"],
  "monitoring": {
    "snmp": true,
    "netflow": true
  }
}
```

#### GET /devices/{id}
Get device details.

**Response:**
```json
{
  "id": "device_001",
  "hostname": "core-router-01",
  "configuration": {
    "current": "...",
    "last_changed": "2024-01-10T10:00:00Z",
    "backed_up": true
  },
  "metrics": {
    "cpu": 45,
    "memory": 62,
    "uptime_days": 127
  },
  "interfaces": [...]
}
```

#### POST /devices/{id}/backup
Create configuration backup.

**Response:**
```json
{
  "backup_id": "backup_456",
  "timestamp": "2024-01-15T16:00:00Z",
  "size_bytes": 45678,
  "checksum": "sha256:abc123...",
  "location": "vault://catnet/backups/device_001/backup_456"
}
```

#### POST /devices/{id}/execute
Execute command on device (requires elevated permissions).

**Request:**
```json
{
  "command": "show interfaces status",
  "timeout": 30
}
```

**Response:**
```json
{
  "output": "Port      Name   Status       Vlan       Duplex  Speed Type\nGi0/1     Server connected    1          full    1000  1000BaseTX",
  "execution_time": 0.234,
  "timestamp": "2024-01-15T16:15:00Z"
}
```

### Compliance Service

#### POST /compliance/check
Run compliance check against devices.

**Request:**
```json
{
  "framework": "pci-dss",  // or "hipaa", "soc2", "iso27001", "nist", "cis"
  "devices": ["device_001", "device_002"],
  "controls": ["1.1", "1.2", "2.3"]  // Optional specific controls
}
```

**Response:**
```json
{
  "report_id": "report_123",
  "framework": "pci-dss",
  "compliance_score": 92.5,
  "checks": [
    {
      "control_id": "PCI-1.1",
      "description": "Firewall configuration standards",
      "status": "compliant",
      "devices": {
        "device_001": "compliant",
        "device_002": "compliant"
      }
    }
  ],
  "non_compliant_count": 2,
  "recommendations": [...]
}
```

#### GET /compliance/reports
List compliance reports.

**Query Parameters:**
- `framework`: Filter by framework
- `start_date`: Start date (ISO 8601)
- `end_date`: End date (ISO 8601)

#### GET /compliance/reports/{id}
Get detailed compliance report.

**Query Parameters:**
- `format`: Response format (json, html, pdf, csv)

### Monitoring Service

#### GET /metrics
Get Prometheus metrics.

**Response (Prometheus format):**
```
# HELP catnet_deployments_total Total number of deployments
# TYPE catnet_deployments_total counter
catnet_deployments_total{status="success"} 245
catnet_deployments_total{status="failed"} 12

# HELP catnet_device_connections Current device connections
# TYPE catnet_device_connections gauge
catnet_device_connections{vendor="cisco"} 85
catnet_device_connections{vendor="juniper"} 42
```

#### GET /health
Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "services": {
    "database": "healthy",
    "redis": "healthy",
    "vault": "healthy"
  },
  "timestamp": "2024-01-15T17:00:00Z"
}
```

#### POST /alerts
Create custom alert rule.

**Request:**
```json
{
  "name": "High CPU Alert",
  "condition": "device.metrics.cpu > 90",
  "duration": "5m",
  "severity": "warning",
  "channels": ["email", "slack"],
  "devices": ["device_001", "device_002"]
}
```

### Automation Service

#### POST /workflows
Create automation workflow.

**Request:**
```json
{
  "name": "Interface Flapping Remediation",
  "trigger": {
    "type": "event",
    "conditions": {
      "event_type": "interface.flapping",
      "threshold": 5
    }
  },
  "steps": [
    {
      "type": "device_command",
      "device": "{{event.device_id}}",
      "commands": ["interface {{event.interface}}", "shutdown"]
    },
    {
      "type": "wait",
      "duration": "30s"
    },
    {
      "type": "device_command",
      "device": "{{event.device_id}}",
      "commands": ["interface {{event.interface}}", "no shutdown"]
    },
    {
      "type": "notification",
      "channel": "slack",
      "message": "Interface {{event.interface}} remediated"
    }
  ]
}
```

#### GET /workflows
List automation workflows.

**Response:**
```json
{
  "workflows": [
    {
      "id": "workflow_123",
      "name": "Interface Flapping Remediation",
      "trigger_type": "event",
      "enabled": true,
      "last_executed": "2024-01-15T14:00:00Z",
      "execution_count": 12
    }
  ]
}
```

#### POST /workflows/{id}/execute
Manually trigger workflow execution.

**Request:**
```json
{
  "context": {
    "device_id": "device_001",
    "interface": "GigabitEthernet0/0"
  }
}
```

### ML Anomaly Detection Service

#### POST /ml/models
Train new anomaly detection model.

**Request:**
```json
{
  "name": "Network Traffic Anomaly",
  "model_type": "isolation_forest",
  "training_data": {
    "source": "prometheus",
    "metrics": ["packet_rate", "error_rate", "cpu_usage"],
    "time_range": "7d",
    "devices": ["device_001", "device_002"]
  }
}
```

#### GET /ml/models/{id}/predict
Get anomaly predictions.

**Request:**
```json
{
  "data": {
    "packet_rate": 15000,
    "error_rate": 0.15,
    "cpu_usage": 95
  }
}
```

**Response:**
```json
{
  "anomaly_score": 0.89,
  "is_anomaly": true,
  "confidence": 0.92,
  "explanation": "Unusually high error rate combined with high CPU usage"
}
```

## Error Responses

All API errors follow a consistent format:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input parameters",
    "details": {
      "field": "devices",
      "issue": "Device 'device_999' not found"
    },
    "request_id": "req_abc123",
    "timestamp": "2024-01-15T18:00:00Z"
  }
}
```

### Common Error Codes

- `AUTHENTICATION_ERROR`: Invalid or expired token
- `AUTHORIZATION_ERROR`: Insufficient permissions
- `VALIDATION_ERROR`: Invalid request parameters
- `NOT_FOUND`: Resource not found
- `CONFLICT`: Resource conflict (e.g., deployment already in progress)
- `RATE_LIMITED`: Too many requests
- `INTERNAL_ERROR`: Internal server error

## Rate Limiting

API requests are rate-limited per user:

- Standard tier: 1000 requests per hour
- Premium tier: 10000 requests per hour
- Enterprise tier: Unlimited

Rate limit headers are included in responses:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 995
X-RateLimit-Reset: 1642267200
```

## Pagination

List endpoints support pagination:

**Query Parameters:**
- `page`: Page number (default: 1)
- `per_page`: Items per page (default: 20, max: 100)

**Response Headers:**
```
X-Total-Count: 245
X-Page: 1
X-Per-Page: 20
Link: <https://api.catnet.local/devices?page=2>; rel="next"
```

## Webhooks

Configure webhooks for real-time notifications:

```json
{
  "url": "https://your-server.com/webhook",
  "events": ["deployment.completed", "device.offline", "compliance.failed"],
  "secret": "webhook_secret_123"
}
```

Webhook payload:

```json
{
  "event": "deployment.completed",
  "timestamp": "2024-01-15T19:00:00Z",
  "data": {...},
  "signature": "sha256=..."
}
```

## SDKs and Client Libraries

Official SDKs available for:

- Python: `pip install catnet-client`
- Go: `go get github.com/catnet/catnet-go`
- JavaScript/TypeScript: `npm install @catnet/client`
- Ruby: `gem install catnet`

## API Versioning

The API uses URL versioning:

- Current version: `/api/v1`
- Beta features: `/api/v2-beta`
- Deprecated endpoints are marked with `Deprecation` headers

## Support

- API Status: https://status.catnet.io
- Documentation: https://docs.catnet.io/api
- Support: api-support@catnet.io