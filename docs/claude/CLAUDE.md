# CatNet - Network Configuration Deployment System Specification

You are implementing CatNet, a security-first, GitOps-enabled network configuration deployment system for Cisco and Juniper devices. Follow this architecture specification exactly.

## PROJECT CONTEXT
- **System Name**: CatNet
- **Purpose**: Automated, secure network configuration deployment
- **Supported Vendors**: Cisco (IOS, IOS-XE, NX-OS), Juniper (Junos)
- **Architecture Pattern**: Zero-trust, microservices, GitOps-enabled
- **Security Level**: Critical (financial/government grade)

## CORE REQUIREMENTS

### Security Requirements (MANDATORY)
```python
# Every component MUST implement:
- mTLS for all inter-service communication
- No hardcoded credentials (use HashiCorp Vault)
- All configs encrypted at rest (AES-256-GCM)
- Audit logging for every action (immutable)
- MFA for all user authentication
- Certificate-based device authentication
- Signed commits and configurations
```

### Technology Stack
```yaml
Backend:
  Language: Python 3.11+
  Framework: FastAPI (async)
  Database: PostgreSQL 14+ with TimescaleDB
  Cache: Redis 7+
  Queue: RabbitMQ or Kafka
  Secrets: HashiCorp Vault
  
Libraries:
  Network: netmiko, napalm, nornir
  Async: asyncio, aiohttp
  Security: cryptography, PyJWT
  Validation: pydantic
  Git: GitPython, pygit2
  Testing: pytest, pytest-asyncio
```

## SYSTEM ARCHITECTURE

### 1. Directory Structure
```
catnet/
├── src/
│   ├── api/           # FastAPI endpoints
│   ├── auth/          # Authentication/authorization
│   ├── core/          # Core business logic
│   ├── db/            # Database models and migrations
│   ├── devices/       # Device communication layer
│   ├── gitops/        # Git integration
│   ├── security/      # Security components
│   └── workers/       # Async job processors
├── tests/
├── configs/           # Configuration files
├── scripts/           # Utility scripts
└── docs/
```

### 2. Core Services (Microservices)

```python
# SERVICE 1: Authentication Service (port 8081)
class AuthenticationService:
    """
    Handles: OAuth2, SAML, MFA, JWT tokens
    Dependencies: Vault, LDAP/AD
    """
    endpoints = [
        "POST /auth/login",
        "POST /auth/mfa/verify",
        "POST /auth/refresh",
        "DELETE /auth/logout"
    ]

# SERVICE 2: GitOps Service (port 8082)
class GitOpsService:
    """
    Handles: Repository connections, webhook processing
    Dependencies: Auth, Validation
    """
    endpoints = [
        "POST /git/connect",
        "POST /git/webhook",
        "GET /git/configs",
        "POST /git/sync"
    ]

# SERVICE 3: Deployment Service (port 8083)
class DeploymentService:
    """
    Handles: Config deployment, rollback, validation
    Dependencies: Auth, Inventory, Device
    """
    endpoints = [
        "POST /deploy/create",
        "GET /deploy/{id}/status",
        "POST /deploy/{id}/approve",
        "POST /deploy/{id}/rollback"
    ]

# SERVICE 4: Device Service (port 8084)
class DeviceService:
    """
    Handles: Device connections, command execution
    Dependencies: Vault, Audit
    """
    endpoints = [
        "GET /devices",
        "POST /devices/connect",
        "POST /devices/{id}/backup",
        "POST /devices/{id}/execute"
    ]
```

### 3. Database Schema

```sql
-- Core tables with security fields
CREATE TABLE deployments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL REFERENCES users(id),
    config_hash VARCHAR(64) NOT NULL,  -- SHA-256
    signature TEXT NOT NULL,           -- Digital signature
    encryption_key_id VARCHAR(128),    -- KMS key reference
    state VARCHAR(50) NOT NULL,
    approved_by UUID[] DEFAULT '{}',
    audit_log JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE git_repositories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url TEXT NOT NULL,
    branch VARCHAR(100) DEFAULT 'main',
    webhook_secret_ref VARCHAR(256),  -- Vault reference
    last_commit_hash VARCHAR(40),
    gpg_verification BOOLEAN DEFAULT true
);

CREATE TABLE device_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID REFERENCES devices(id),
    config_encrypted TEXT NOT NULL,    -- Encrypted content
    backup_location TEXT NOT NULL,
    version INTEGER NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

## IMPLEMENTATION PATTERNS

### 4. Secure Device Connection Pattern

```python
from typing import Optional
import asyncio
from netmiko import ConnectHandler
from hashicorp_vault import VaultClient

class SecureDeviceConnector:
    """
    PATTERN: Always use this pattern for device connections
    NEVER store credentials in code or config files
    """
    
    def __init__(self):
        self.vault = VaultClient()
        self.audit = AuditLogger()
        
    async def connect_to_device(
        self, 
        device_id: str, 
        user_context: dict
    ) -> Optional[DeviceConnection]:
        # Step 1: Verify user authorization
        if not await self.check_authorization(user_context, device_id):
            self.audit.log_unauthorized_attempt(user_context, device_id)
            raise UnauthorizedException()
        
        # Step 2: Get temporary credentials from Vault
        creds = await self.vault.get_temporary_credentials(
            device_id=device_id,
            requestor=user_context['user_id'],
            ttl=1800  # 30 minutes
        )
        
        # Step 3: Connect through bastion
        connection = await self.establish_secure_connection(
            device_id=device_id,
            credentials=creds,
            jump_host=self.select_bastion(device_id)
        )
        
        # Step 4: Enable session recording
        self.audit.start_session_recording(connection.session_id)
        
        return connection
```

### 5. GitOps Workflow Pattern

```python
class GitOpsWorkflow:
    """
    PATTERN: GitOps configuration processing pipeline
    """
    
    async def process_git_push(self, webhook_payload: dict):
        # Step 1: Verify webhook signature (MANDATORY)
        if not self.verify_webhook_signature(webhook_payload):
            raise SecurityException("Invalid webhook")
        
        # Step 2: Scan for secrets (MANDATORY)
        secrets = await self.scan_for_secrets(webhook_payload['commits'])
        if secrets:
            await self.quarantine_and_alert(secrets)
            return
        
        # Step 3: Parse configurations
        configs = await self.parse_configs(webhook_payload)
        
        # Step 4: Validate configurations
        for config in configs:
            validation = await self.validate_config(config)
            if not validation.is_valid:
                await self.notify_validation_failure(validation)
                return
        
        # Step 5: Create deployment with approval workflow
        deployment = await self.create_deployment(
            configs=configs,
            requires_approval=self.check_approval_required(configs)
        )
        
        # Step 6: Execute deployment strategy
        if deployment.strategy == 'canary':
            await self.canary_deploy(deployment)
        else:
            await self.rolling_deploy(deployment)
```

### 6. Configuration Validation Pattern

```python
class ConfigValidator:
    """
    PATTERN: Multi-layer validation before deployment
    """
    
    async def validate_configuration(self, config: dict) -> ValidationResult:
        result = ValidationResult()
        
        # Layer 1: Schema validation
        if not self.validate_schema(config):
            result.add_error("Schema validation failed")
            return result
        
        # Layer 2: Syntax validation (vendor-specific)
        vendor = config.get('vendor')
        if vendor == 'cisco':
            syntax_valid = await self.validate_cisco_syntax(config)
        elif vendor == 'juniper':
            syntax_valid = await self.validate_juniper_syntax(config)
        else:
            result.add_error(f"Unsupported vendor: {vendor}")
            return result
            
        if not syntax_valid:
            result.add_error("Syntax validation failed")
        
        # Layer 3: Security compliance
        security_issues = await self.check_security_compliance(config)
        for issue in security_issues:
            result.add_warning(f"Security: {issue}")
        
        # Layer 4: Business rules
        business_violations = await self.check_business_rules(config)
        for violation in business_violations:
            result.add_error(f"Business rule: {violation}")
        
        # Layer 5: Conflict detection
        conflicts = await self.detect_conflicts(config)
        for conflict in conflicts:
            result.add_warning(f"Conflict: {conflict}")
        
        return result
```

### 7. Deployment Execution Pattern

```python
class DeploymentExecutor:
    """
    PATTERN: Progressive deployment with automatic rollback
    """
    
    async def execute_canary_deployment(
        self, 
        deployment_id: str,
        devices: list
    ) -> DeploymentResult:
        # Canary stages with increasing scope
        stages = [
            {'percentage': 5, 'wait_minutes': 5},
            {'percentage': 25, 'wait_minutes': 10},
            {'percentage': 50, 'wait_minutes': 15},
            {'percentage': 100, 'wait_minutes': 0}
        ]
        
        deployed = []
        
        for stage in stages:
            # Calculate devices for this stage
            count = int(len(devices) * stage['percentage'] / 100)
            stage_devices = devices[:count]
            new_devices = [d for d in stage_devices if d not in deployed]
            
            # Deploy to new devices
            for device in new_devices:
                # Always backup first
                backup_id = await self.backup_device(device)
                
                try:
                    # Deploy configuration
                    await self.deploy_to_device(device)
                    
                    # Immediate validation
                    if not await self.validate_device_health(device):
                        raise ValidationError(f"Device {device} unhealthy")
                    
                    deployed.append(device)
                    
                except Exception as e:
                    # Automatic rollback
                    await self.rollback_all(deployed, backup_id)
                    raise DeploymentFailed(f"Failed at {stage['percentage']}%: {e}")
            
            # Wait and monitor
            if stage['wait_minutes'] > 0:
                await self.monitor_health(deployed, stage['wait_minutes'])
        
        return DeploymentResult(success=True, devices=deployed)
```

## CRITICAL ANTI-PATTERNS TO AVOID

```python
# ❌ NEVER DO THESE:

# 1. NEVER hardcode credentials
password = "admin123"  # WRONG!

# 2. NEVER skip webhook verification
def process_webhook(payload):
    # Missing signature verification!
    deploy(payload)  # WRONG!

# 3. NEVER deploy without backup
def deploy(device):
    # No backup!
    apply_config(device)  # WRONG!

# 4. NEVER use synchronous blocking operations
for device in devices:
    deploy_blocking(device)  # WRONG! Will timeout

# 5. NEVER store secrets in Git
config = {
    "password": "secret123"  # WRONG!
}

# 6. NEVER allow configuration drift
# Always reconcile Git with device state

# 7. NEVER skip validation layers
deploy_without_validation(config)  # WRONG!

# 8. NEVER use MD5 or SHA1 for security
hashlib.md5(password)  # WRONG! Use bcrypt/argon2

# 9. NEVER trust user input
query = f"SELECT * FROM devices WHERE name = '{user_input}'"  # SQL Injection!

# 10. NEVER expose internal errors to users
return {"error": str(exception)}  # WRONG! Leaks internals
```

## API ENDPOINT SPECIFICATIONS

```python
# All endpoints must follow this pattern:

from fastapi import FastAPI, Depends, HTTPException
from typing import Optional
import uuid

app = FastAPI(title="CatNet API")

@app.post("/api/v1/deployments")
async def create_deployment(
    request: DeploymentRequest,
    current_user: User = Depends(get_current_user),  # Auth required
    db: Database = Depends(get_db)
) -> DeploymentResponse:
    """
    Create deployment request.
    
    Security:
    - Requires authentication
    - Validates user permissions
    - Logs all actions
    - Encrypts sensitive data
    """
    # Input validation (automatic with pydantic)
    
    # Authorization check
    if not await check_permission(current_user, "deployment.create"):
        raise HTTPException(403, "Insufficient permissions")
    
    # Audit logging
    audit_id = await log_audit_event(
        user=current_user,
        action="deployment.create",
        details=request.dict()
    )
    
    try:
        # Business logic
        deployment = await create_deployment_internal(request)
        
        # Return sanitized response
        return DeploymentResponse(
            id=deployment.id,
            status="pending",
            created_at=deployment.created_at
        )
        
    except Exception as e:
        # Log error internally
        await log_error(audit_id, e)
        
        # Return generic error to user
        raise HTTPException(500, "Deployment creation failed")
```

## TESTING REQUIREMENTS

```python
# Every component must have tests:

import pytest
import asyncio
from unittest.mock import Mock, patch

class TestDeploymentService:
    """
    Test coverage requirements:
    - Unit tests: >80% coverage
    - Integration tests: All API endpoints
    - Security tests: Auth, injection, encryption
    """
    
    @pytest.mark.asyncio
    async def test_deployment_with_rollback(self):
        """Test automatic rollback on failure"""
        
        # Arrange
        mock_device = Mock()
        mock_device.deploy.side_effect = Exception("Deploy failed")
        
        # Act
        with pytest.raises(DeploymentFailed):
            await deploy_with_rollback(mock_device)
        
        # Assert
        mock_device.rollback.assert_called_once()
    
    @pytest.mark.security
    async def test_sql_injection_prevention(self):
        """Verify SQL injection is prevented"""
        
        malicious_input = "'; DROP TABLE devices; --"
        
        # Should sanitize input, not execute injection
        result = await search_devices(malicious_input)
        
        # Verify tables still exist
        assert await check_table_exists('devices')
```

## DEPLOYMENT CHECKLIST

```yaml
Pre-Deployment:
  ✓ All secrets in Vault
  ✓ mTLS certificates configured
  ✓ Database encrypted (TDE enabled)
  ✓ Audit logging enabled
  ✓ MFA configured for all users
  ✓ Backup strategy tested
  ✓ Rollback procedures documented
  ✓ Security scan passed
  ✓ Load testing completed
  ✓ Disaster recovery plan ready

Production Requirements:
  ✓ Rate limiting enabled
  ✓ DDoS protection active
  ✓ WAF configured
  ✓ Monitoring dashboards ready
  ✓ Alerts configured
  ✓ On-call rotation set
  ✓ Runbooks created
  ✓ Compliance validation passed
```

## MONITORING & OBSERVABILITY

```python
# Required metrics for every service:

from prometheus_client import Counter, Histogram, Gauge

# Performance metrics
deployment_duration = Histogram(
    'catnet_deployment_duration_seconds',
    'Time taken for deployment',
    ['strategy', 'result']
)

# Business metrics
deployments_total = Counter(
    'catnet_deployments_total',
    'Total deployments',
    ['status', 'vendor']
)

# Security metrics
auth_failures = Counter(
    'catnet_auth_failures_total',
    'Authentication failures',
    ['reason']
)

# Health metrics
service_health = Gauge(
    'catnet_service_health',
    'Service health status',
    ['service']
)
```

## ERROR HANDLING PATTERN

```python
class CatNetError(Exception):
    """Base exception for CatNet"""
    pass

class SecurityError(CatNetError):
    """Security-related errors"""
    pass

class DeploymentError(CatNetError):
    """Deployment-related errors"""
    pass

def handle_errors(func):
    """Decorator for consistent error handling"""
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except SecurityError as e:
            # Log security incident
            await log_security_incident(e)
            # Alert security team
            await alert_security_team(e)
            raise
        except DeploymentError as e:
            # Log deployment failure
            await log_deployment_failure(e)
            # Attempt rollback
            await attempt_rollback()
            raise
        except Exception as e:
            # Log unexpected error
            await log_unexpected_error(e)
            # Return generic error
            raise CatNetError("Operation failed")
    return wrapper
```

## QUICK REFERENCE

```bash
# Development commands
pip install -r requirements.txt
pytest tests/ --cov=src --cov-report=html
black src/ --check
mypy src/ --strict
bandit -r src/  # Security linting

# Docker commands
docker-compose up -d
docker-compose logs -f catnet-api
docker exec -it catnet-db psql -U catnet

# Vault commands
vault kv put secret/catnet/devices/router1 username=admin password=secure
vault token create -policy=catnet-deploy -ttl=30m

# Database migrations
alembic upgrade head
alembic revision --autogenerate -m "Add new field"

# Git workflow
git checkout -b feature/CNT-123-new-feature
git commit -S -m "feat: add new deployment strategy"  # Signed commit
git push origin feature/CNT-123-new-feature
# Create PR with 2 reviewers required
```

## VENDOR-SPECIFIC COMMANDS

```python
# Cisco IOS/IOS-XE
cisco_commands = {
    'backup': 'show running-config',
    'save': 'write memory',
    'rollback': 'configure replace flash:backup.cfg force'
}

# Juniper Junos
juniper_commands = {
    'backup': 'show configuration | display set',
    'save': 'commit',
    'rollback': 'rollback 1 && commit'
}

# NX-OS
nxos_commands = {
    'backup': 'show running-config',
    'save': 'copy running-config startup-config',
    'rollback': 'rollback running-config checkpoint backup_config'
}
```

---

**REMEMBER**: 
1. Security is NOT optional - every component must implement security controls
2. Never trust user input - always validate and sanitize
3. Audit everything - compliance depends on complete audit trails
4. Test everything - untested code is broken code
5. Document everything - future you will thank present you

This is your complete implementation guide. Follow these patterns exactly for a secure, scalable CatNet implementation.