# CatNet API Documentation

## Overview
CatNet provides a comprehensive RESTful API for network configuration management with GitOps integration. All API endpoints are secured with authentication, rate limiting, and encryption.

## Base URL
```
Production: https://api.catnet.local/api/v1
Staging: https://api-staging.catnet.local/api/v1
```

## Authentication
All API requests require authentication using JWT tokens or API keys.

### JWT Authentication
```http
Authorization: Bearer <jwt_token>
```

### API Key Authentication
```http
X-API-Key: <api_key>
```

## Rate Limiting
API endpoints are rate limited to prevent abuse:
- **Authentication**: 5 requests per minute
- **Read operations**: 100 requests per minute
- **Write operations**: 50 requests per minute
- **Deployment operations**: 10 requests per 5 minutes

Rate limit headers are included in all responses:
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1631234567
```

## API Versioning
The API version can be specified in two ways:

1. **URL Path**: `/api/v1/resource`
2. **Header**: `X-API-Version: v1`

## Common Response Codes
| Code | Description |
|------|-------------|
| 200 | Success |
| 201 | Created |
| 204 | No Content |
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 409 | Conflict |
| 429 | Too Many Requests |
| 500 | Internal Server Error |

## Error Response Format
```json
{
    "success": false,
    "error": "Error message",
    "message": "Detailed error description",
    "timestamp": "2025-09-17T10:00:00Z",
    "request_id": "uuid"
}
```

---

## Authentication Endpoints

### Login
**POST** `/auth/login`

Authenticate user and receive JWT token.

**Request Body:**
```json
{
    "username": "admin",
    "password": "SecurePassword123!"
}
```

**Response:**
```json
{
    "access_token": "eyJhbGc...",
    "refresh_token": "eyJhbGc...",
    "token_type": "Bearer",
    "expires_in": 3600
}
```

### MFA Verification
**POST** `/auth/mfa/verify`

Verify multi-factor authentication code.

**Request Body:**
```json
{
    "code": "123456"
}
```

### Enroll MFA
**POST** `/auth/mfa/enroll`

Enroll in multi-factor authentication.

**Request Body:**
```json
{
    "method": "totp",
    "phone_number": null,
    "backup_email": null
}
```

**Response:**
```json
{
    "method": "totp",
    "qr_code": "data:image/png;base64,...",
    "backup_codes": ["ABC123", "DEF456", ...],
    "enrolled_at": "2025-09-17T10:00:00Z"
}
```

### Validate Certificate
**POST** `/auth/certificate/validate`

Validate X.509 certificate for authentication.

**Request Body:**
```json
{
    "certificate": "-----BEGIN CERTIFICATE-----...",
    "device_id": "uuid"
}
```

**Response:**
```json
{
    "valid": true,
    "subject": {...},
    "issuer": {...},
    "serial_number": "123456",
    "not_valid_before": "2025-01-01T00:00:00Z",
    "not_valid_after": "2026-01-01T00:00:00Z"
}
```

### Get Sessions
**GET** `/auth/sessions`

Get all active sessions for current user.

**Response:**
```json
[
    {
        "session_id": "uuid",
        "user_id": "uuid",
        "created_at": "2025-09-17T10:00:00Z",
        "last_activity": "2025-09-17T10:30:00Z",
        "ip_address": "192.168.1.1",
        "user_agent": "Mozilla/5.0...",
        "expires_at": "2025-09-18T10:00:00Z"
    }
]
```

### Refresh Token
**POST** `/auth/refresh`

Refresh access token using refresh token.

### Logout
**DELETE** `/auth/logout`

Terminate current session.

---

## Device Management Endpoints

### List Devices
**GET** `/devices`

Get list of all network devices.

**Query Parameters:**
- `page` (int): Page number (default: 1)
- `per_page` (int): Items per page (default: 20)
- `vendor` (string): Filter by vendor
- `is_active` (boolean): Filter by active status
- `location` (string): Filter by location

**Response:**
```json
{
    "data": [
        {
            "id": "uuid",
            "hostname": "router-01",
            "ip_address": "192.168.1.1",
            "vendor": "cisco_ios",
            "model": "ISR4451",
            "serial_number": "FTX1234567",
            "location": "DC1",
            "is_active": true,
            "last_seen": "2025-09-17T10:00:00Z",
            "certificate_status": "active"
        }
    ],
    "total": 100,
    "page": 1,
    "per_page": 20
}
```

### Get Device
**GET** `/devices/{device_id}`

Get specific device details.

### Create Device
**POST** `/devices`

Register new network device.

**Request Body:**
```json
{
    "hostname": "router-02",
    "ip_address": "192.168.1.2",
    "vendor": "cisco_ios",
    "model": "ISR4451",
    "serial_number": "FTX1234568",
    "location": "DC1",
    "port": 22,
    "bastion_host": null
}
```

### Update Device
**PUT** `/devices/{device_id}`

Update device information.

### Delete Device
**DELETE** `/devices/{device_id}`

Remove device from inventory.

### Backup Device
**POST** `/devices/{device_id}/backup`

Create backup of device configuration.

### Execute Command
**POST** `/devices/{device_id}/execute`

Execute command on device (requires elevated permissions).

**Request Body:**
```json
{
    "commands": ["show version", "show running-config"],
    "timeout": 30
}
```

---

## Deployment Endpoints

### Create Deployment
**POST** `/deploy/create`

Create new configuration deployment.

**Request Body:**
```json
{
    "config_ids": ["uuid1", "uuid2"],
    "device_ids": ["uuid1", "uuid2"],
    "strategy": "canary",
    "approval_required": true,
    "scheduled_at": null
}
```

### Get Deployment Status
**GET** `/deploy/{deployment_id}/status`

Get current deployment status.

**Response:**
```json
{
    "id": "uuid",
    "state": "in_progress",
    "created_at": "2025-09-17T10:00:00Z",
    "started_at": "2025-09-17T10:05:00Z",
    "progress": 50,
    "devices_total": 10,
    "devices_completed": 5,
    "devices_failed": 0
}
```

### Approve Deployment
**POST** `/deploy/{deployment_id}/approve`

Approve pending deployment.

### Rollback Deployment
**POST** `/deploy/{deployment_id}/rollback`

Rollback failed or in-progress deployment.

### Dry Run Deployment
**POST** `/deploy/dry-run`

Simulate deployment without applying changes.

**Request Body:**
```json
{
    "config_ids": ["uuid1", "uuid2"],
    "device_ids": ["uuid1", "uuid2"],
    "strategy": "rolling",
    "validation_only": false
}
```

**Response:**
```json
{
    "simulation_id": "uuid",
    "validation_results": {...},
    "affected_devices": [...],
    "estimated_duration": 300,
    "warnings": [],
    "errors": [],
    "recommendations": []
}
```

### Get Deployment Metrics
**GET** `/deploy/metrics`

Get deployment statistics and metrics.

**Query Parameters:**
- `days` (int): Number of days to include (default: 30)

**Response:**
```json
{
    "total_deployments": 150,
    "successful_deployments": 145,
    "failed_deployments": 5,
    "rollback_count": 3,
    "average_duration": 180.5,
    "success_rate": 96.7,
    "deployments_by_strategy": {
        "canary": 50,
        "rolling": 75,
        "blue_green": 25
    }
}
```

### Schedule Deployment
**POST** `/deploy/schedule`

Schedule deployment for future execution.

**Request Body:**
```json
{
    "config_ids": ["uuid1"],
    "device_ids": ["uuid1", "uuid2"],
    "strategy": "rolling",
    "scheduled_time": "2025-09-18T02:00:00Z",
    "approval_required": true,
    "notification_emails": ["ops@example.com"]
}
```

---

## GitOps Endpoints

### Connect Repository
**POST** `/git/connect`

Connect Git repository for configuration management.

**Request Body:**
```json
{
    "url": "https://github.com/org/configs.git",
    "branch": "main",
    "config_path": "configs/",
    "auto_deploy": false,
    "gpg_verification": true
}
```

### GitHub Webhook
**POST** `/git/webhook/github`

Handle GitHub webhook events.

**Headers:**
```http
X-GitHub-Event: push
X-Hub-Signature-256: sha256=...
```

### GitLab Webhook
**POST** `/git/webhook/gitlab`

Handle GitLab webhook events.

**Headers:**
```http
X-Gitlab-Event: Push Hook
X-Gitlab-Token: ...
```

### Get Configuration Diff
**GET** `/git/diff/{commit_sha}`

Get configuration diff for specific commit.

**Response:**
```json
{
    "commit_sha": "abc123...",
    "timestamp": "2025-09-17T10:00:00Z",
    "author": "john.doe",
    "message": "Update router config",
    "files_changed": ["router-01.cfg"],
    "additions": 10,
    "deletions": 5,
    "diff_content": "..."
}
```

### Sync Repository
**POST** `/git/sync`

Manually sync repository with latest changes.

### List Configurations
**GET** `/git/configs`

Get list of configurations from repository.

---

## User Management Endpoints

### List Users
**GET** `/users`

Get list of all users (admin only).

### Get User
**GET** `/users/{user_id}`

Get user details.

### Create User
**POST** `/users`

Create new user account (admin only).

**Request Body:**
```json
{
    "username": "john.doe",
    "email": "john@example.com",
    "password": "SecurePassword123!",
    "roles": ["operator"],
    "is_active": true
}
```

### Update User
**PUT** `/users/{user_id}`

Update user information.

### Delete User
**DELETE** `/users/{user_id}`

Delete user account (admin only).

### Change Password
**POST** `/users/password/change`

Change current user password.

### Reset Password
**POST** `/users/password/reset`

Request password reset.

---

## Configuration Templates

### List Templates
**GET** `/templates`

Get list of configuration templates.

### Get Template
**GET** `/templates/{template_id}`

Get template details.

### Create Template
**POST** `/templates`

Create new configuration template.

**Request Body:**
```json
{
    "name": "interface-config",
    "vendor": "cisco_ios",
    "template_content": "interface {{ interface_name }}\n  description {{ description }}",
    "variables": {
        "interface_name": "string",
        "description": "string"
    },
    "validation_rules": {}
}
```

### Update Template
**PUT** `/templates/{template_id}`

Update configuration template.

### Delete Template
**DELETE** `/templates/{template_id}`

Delete configuration template.

### Render Template
**POST** `/templates/{template_id}/render`

Render template with variables.

---

## Audit Log Endpoints

### Get Audit Logs
**GET** `/audit/logs`

Retrieve audit logs.

**Query Parameters:**
- `start_date` (datetime): Start date filter
- `end_date` (datetime): End date filter
- `event_type` (string): Event type filter
- `user_id` (uuid): User ID filter
- `page` (int): Page number
- `per_page` (int): Items per page

### Get Security Events
**GET** `/audit/security`

Get security-related audit events.

### Export Audit Logs
**GET** `/audit/export`

Export audit logs in CSV or JSON format.

**Query Parameters:**
- `format` (string): Export format (csv, json)
- `start_date` (datetime): Start date
- `end_date` (datetime): End date

---

## Health & Monitoring

### Health Check
**GET** `/health`

Get service health status.

**Response:**
```json
{
    "status": "healthy",
    "version": "1.0.0",
    "timestamp": "2025-09-17T10:00:00Z",
    "services": {
        "database": "healthy",
        "redis": "healthy",
        "vault": "healthy"
    }
}
```

### Readiness Check
**GET** `/ready`

Check if service is ready to accept requests.

### Metrics
**GET** `/metrics`

Get Prometheus metrics.

---

## WebSocket Endpoints

### Real-time Deployments
**WS** `/ws/deployments`

Subscribe to real-time deployment updates.

**Message Format:**
```json
{
    "type": "deployment.update",
    "deployment_id": "uuid",
    "state": "in_progress",
    "progress": 75,
    "timestamp": "2025-09-17T10:00:00Z"
}
```

### Device Status
**WS** `/ws/devices`

Subscribe to device status changes.

---

## SDK Examples

### Python
```python
import requests

class CatNetClient:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.headers = {
            "X-API-Key": api_key,
            "Content-Type": "application/json"
        }

    def get_devices(self):
        response = requests.get(
            f"{self.base_url}/devices",
            headers=self.headers
        )
        return response.json()

    def create_deployment(self, config_ids, device_ids):
        data = {
            "config_ids": config_ids,
            "device_ids": device_ids,
            "strategy": "canary"
        }
        response = requests.post(
            f"{self.base_url}/deploy/create",
            json=data,
            headers=self.headers
        )
        return response.json()

# Usage
client = CatNetClient("https://api.catnet.local/api/v1", "your-api-key")
devices = client.get_devices()
```

### cURL
```bash
# Get devices
curl -X GET "https://api.catnet.local/api/v1/devices" \
  -H "X-API-Key: your-api-key"

# Create deployment
curl -X POST "https://api.catnet.local/api/v1/deploy/create" \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "config_ids": ["uuid1"],
    "device_ids": ["uuid1", "uuid2"],
    "strategy": "rolling"
  }'
```

### JavaScript
```javascript
class CatNetClient {
    constructor(baseUrl, apiKey) {
        this.baseUrl = baseUrl;
        this.headers = {
            'X-API-Key': apiKey,
            'Content-Type': 'application/json'
        };
    }

    async getDevices() {
        const response = await fetch(`${this.baseUrl}/devices`, {
            headers: this.headers
        });
        return await response.json();
    }

    async createDeployment(configIds, deviceIds) {
        const response = await fetch(`${this.baseUrl}/deploy/create`, {
            method: 'POST',
            headers: this.headers,
            body: JSON.stringify({
                config_ids: configIds,
                device_ids: deviceIds,
                strategy: 'canary'
            })
        });
        return await response.json();
    }
}

// Usage
const client = new CatNetClient('https://api.catnet.local/api/v1', 'your-api-key');
const devices = await client.getDevices();
```

---

## API Changelog

### Version 2.0 (Upcoming)
- GraphQL support
- Batch operations
- Webhooks for external systems
- Advanced filtering

### Version 1.0 (Current)
- Initial release
- Full REST API
- Authentication and authorization
- Device management
- Deployment automation
- GitOps integration

---

## Support

For API support, contact:
- Email: api-support@catnet.local
- Documentation: https://docs.catnet.local
- Status Page: https://status.catnet.local

---

*Last Updated: 2025-09-17*
*API Version: 1.0*