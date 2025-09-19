# CatNet Implementation Plan: CLAUDE-commandreference.txt Features

## Overview
This plan incorporates all features from CLAUDE-commandreference.txt into CatNet without simplifying existing functionality. Each phase maintains backward compatibility and passes CI/CD checks.

## Guiding Principles
- **No Simplification**: All existing functionality remains intact
- **Incremental Delivery**: Each phase is deployable and testable
- **CI/CD First**: GitHub Actions must pass after each phase
- **Security Maintained**: All security features remain active
- **Full Testing**: Every new feature includes comprehensive tests

## Phase 1: CLI Foundation (Week 1-2)

### 1.1 Create CLI Package Structure
```python
# New files to create:
catnet_cli/
├── __init__.py
├── cli.py              # Main Click group
├── commands/
│   ├── __init__.py
│   ├── auth.py        # Auth subcommands
│   ├── gitops.py      # GitOps subcommands
│   ├── deploy.py      # Deployment subcommands
│   ├── device.py      # Device subcommands
│   └── vault.py       # Vault subcommands
├── config.py          # CLI configuration loader
├── utils.py           # CLI utilities
└── client.py          # API client wrapper
```

### 1.2 Implement Core CLI with Click
```python
# catnet_cli/cli.py
import click
from .commands import auth, gitops, deploy, device, vault

@click.group()
@click.option('--config', '-c', type=click.Path())
@click.option('--debug/--no-debug', default=False)
@click.pass_context
def cli(ctx, config, debug):
    """CatNet CLI for network configuration management"""
    ctx.ensure_object(dict)
    ctx.obj['config'] = config
    ctx.obj['debug'] = debug

cli.add_command(auth.auth)
cli.add_command(gitops.gitops)
cli.add_command(deploy.deploy)
cli.add_command(device.device)
cli.add_command(vault.vault)
```

### 1.3 Setup Entry Point
```python
# setup.py modification
entry_points={
    'console_scripts': [
        'catnet=catnet_cli.cli:cli',
    ],
}
```

### 1.4 Tests for CLI Foundation
```python
# tests/test_cli/test_cli_base.py
def test_cli_help():
    result = runner.invoke(cli, ['--help'])
    assert result.exit_code == 0
    assert 'CatNet CLI' in result.output

def test_cli_version():
    result = runner.invoke(cli, ['version'])
    assert result.exit_code == 0
```

### 1.5 GitHub Actions Check
- Run existing CI/CD pipeline
- Ensure all tests pass
- Verify new CLI doesn't break existing functionality

## Phase 2: Authentication Commands (Week 3)

### 2.1 Implement Auth Commands
```python
# catnet_cli/commands/auth.py
@click.group()
def auth():
    """Authentication commands"""
    pass

@auth.command()
@click.option('--username', '-u', prompt=True)
@click.option('--password', '-p', prompt=True, hide_input=True)
@click.option('--mfa-token', '-m')
async def login(username, password, mfa_token):
    """Login to CatNet"""
    # Call existing AuthManager.authenticate_user()
    # Store tokens in ~/.catnet/tokens.json
    # Maintain all existing security features

@auth.command()
async def logout():
    """Logout from CatNet"""
    # Call existing AuthManager.revoke_token()
    # Clear stored credentials

@auth.command()
async def refresh():
    """Refresh authentication token"""
    # Call existing AuthManager.refresh_access_token()
```

### 2.2 Token Storage
```python
# catnet_cli/config.py
class TokenManager:
    def __init__(self):
        self.token_path = Path.home() / '.catnet' / 'tokens.json'
        # Encrypt tokens at rest using existing EncryptionManager

    def save_token(self, token_data):
        # Use existing encryption from src/security/encryption.py

    def get_token(self):
        # Decrypt and return token
```

### 2.3 Tests
```python
# tests/test_cli/test_auth_commands.py
@pytest.mark.asyncio
async def test_login_with_mfa():
    # Test login preserving MFA functionality

async def test_token_encryption():
    # Verify tokens are encrypted at rest
```

### 2.4 GitHub Actions Check
- Verify auth commands work
- Check security tests still pass
- Ensure MFA functionality intact

## Phase 3: Device Commands (Week 4-5)

### 3.1 Enhance Device Connectors
```python
# src/devices/executor.py (NEW)
class DeviceExecutor:
    """Execute commands on devices with full security"""

    def __init__(self):
        self.vault = VaultClient()  # Existing
        self.audit = AuditLogger()  # Existing
        self.encryption = EncryptionManager()  # Existing

    async def execute_command(self, device_id, command, user_context):
        # Get credentials from Vault (existing)
        # Establish secure connection
        # Execute with session recording (existing audit)
        # Return encrypted results
```

### 3.2 Implement Device CLI Commands
```python
# catnet_cli/commands/device.py
@device.command('list')
@click.option('--vendor', type=click.Choice(['cisco', 'juniper']))
@click.option('--status', type=click.Choice(['online', 'offline', 'maintenance']))
async def list_devices(vendor, status):
    """List all managed devices"""
    # Query existing database models
    # Use existing Device model from src/db/models.py

@device.command('add')
@click.option('--hostname', '-h', required=True)
@click.option('--ip', '-i', required=True)
@click.option('--vendor', required=True)
@click.option('--model', '-m', required=True)
async def add_device(hostname, ip, vendor, model):
    """Add new device"""
    # Create Device using existing model
    # Store credentials in Vault (existing)
    # Add audit log entry (existing)

@device.command('backup')
@click.argument('device_id')
async def backup_device(device_id):
    """Backup device configuration"""
    # Use existing backup functionality from deployment/executor.py
    # Encrypt backup using existing EncryptionManager
    # Store with existing audit trail

@device.command('execute')
@click.argument('device_id')
@click.option('--command', '-c', required=True)
@click.option('--confirm/--no-confirm', default=True)
async def execute_command(device_id, command, confirm):
    """Execute command on device"""
    # Full audit logging (existing)
    # Session recording (existing)
    # Use DeviceExecutor created above
```

### 3.3 Complete Netmiko Integration
```python
# src/devices/connectors/cisco_connector.py (ENHANCE)
class CiscoConnector(BaseConnector):
    """Enhanced with all existing security"""

    async def connect(self):
        # Use existing VaultClient for credentials
        # Maintain existing mTLS if configured
        # Keep session recording

    async def execute_command(self, command):
        # Full command validation
        # Audit logging before/after
        # Encrypted transmission
```

### 3.4 Tests
```python
# tests/test_cli/test_device_commands.py
async def test_device_add_with_vault():
    # Verify credentials stored in Vault

async def test_device_backup_encrypted():
    # Verify backups are encrypted

async def test_command_execution_audit():
    # Verify audit trail created
```

### 3.5 GitHub Actions Check

## Phase 4: GitOps Commands (Week 6-7)

### 4.1 Complete GitOps Service
```python
# src/gitops/repository_manager.py (NEW)
class RepositoryManager:
    """Manage Git repositories with full security"""

    async def connect_repository(self, url, branch, webhook_secret):
        # Store webhook secret in Vault
        # Verify repository access
        # Set up webhook with signature validation (existing)

    async def sync_repository(self, repo_id, force=False):
        # Pull latest changes
        # Validate all configurations (existing validators)
        # Check for secrets (existing scanner)
        # Sign configurations (existing signing.py)
```

### 4.2 Implement GitOps CLI
```python
# catnet_cli/commands/gitops.py
@gitops.command('connect')
@click.option('--url', '-u', required=True)
@click.option('--branch', '-b', default='main')
@click.option('--webhook-secret')
async def connect_repo(url, branch, webhook_secret):
    """Connect Git repository"""
    # Generate webhook secret if not provided
    # Store in Vault
    # Create GitRepository in database

@gitops.command('sync')
@click.option('--repo-id', '-r', required=True)
@click.option('--force/--no-force', default=False)
async def sync_repo(repo_id, force):
    """Sync repository"""
    # Use RepositoryManager
    # Full validation pipeline
    # Audit all changes
```

### 4.3 Webhook Processing Enhancement
```python
# src/gitops/webhook_processor.py (ENHANCE)
class WebhookProcessor:
    """Enhanced webhook processing"""

    async def process_push_event(self, payload):
        # Existing signature verification
        # Parse changed files
        # Validate configurations
        # Trigger deployments if approved
        # Full audit trail
```

### 4.4 Tests
```python
# tests/test_cli/test_gitops_commands.py
async def test_webhook_secret_vault_storage():
    # Verify secrets in Vault

async def test_config_validation_on_sync():
    # Verify all validations run

async def test_signature_verification():
    # Test webhook signatures
```

### 4.5 GitHub Actions Check

## Phase 5: Deployment Commands (Week 8-9)

### 5.1 Complete Deployment Strategies
```python
# src/deployment/strategies/ (ENHANCE ALL)
class CanaryStrategy:
    """Complete canary implementation"""
    # Implement full percentage-based rollout
    # Health monitoring at each stage
    # Automatic rollback on failure

class RollingStrategy:
    """Complete rolling deployment"""
    # Wave-based deployment
    # Configurable batch sizes
    # Inter-wave health checks

class BlueGreenStrategy:
    """Complete blue-green deployment"""
    # Staging environment
    # Validation before swap
    # Instant rollback capability
```

### 5.2 Approval Workflow
```python
# src/deployment/approval.py (NEW)
class ApprovalWorkflow:
    """Multi-stage approval system"""

    async def create_approval_request(self, deployment_id, approvers):
        # Create approval request
        # Send notifications
        # Set expiration

    async def approve_deployment(self, deployment_id, user_id, comment):
        # Verify user authorization
        # Record approval with signature
        # Trigger next stage

    async def check_approval_requirements(self, deployment):
        # Check if all required approvals received
        # Verify signatures
        # Return approval status
```

### 5.3 Implement Deployment CLI
```python
# catnet_cli/commands/deploy.py
@deploy.command('create')
@click.option('--config-file', '-f', required=True)
@click.option('--target', '-t', multiple=True, required=True)
@click.option('--strategy', type=click.Choice(['rolling', 'canary', 'blue-green']))
@click.option('--dry-run/--no-dry-run', default=False)
async def create_deployment(config_file, target, strategy, dry_run):
    """Create deployment"""
    # Load and validate config
    # Check device availability
    # Create deployment with strategy
    # Initialize approval workflow if required

@deploy.command('approve')
@click.argument('deployment_id')
@click.option('--comment', '-c')
async def approve_deployment(deployment_id, comment):
    """Approve deployment"""
    # Verify user permissions
    # Add signed approval
    # Trigger deployment if all approvals received

@deploy.command('rollback')
@click.argument('deployment_id')
@click.option('--reason', '-r', required=True)
async def rollback_deployment(deployment_id, reason):
    """Rollback deployment"""
    # Initiate rollback
    # Restore from backup
    # Log reason with audit
```

### 5.4 Tests
```python
# tests/test_cli/test_deployment_commands.py
async def test_deployment_approval_workflow():
    # Test multi-stage approval

async def test_automatic_rollback():
    # Test rollback on failure

async def test_deployment_strategies():
    # Test all three strategies
```

### 5.5 GitHub Actions Check

## Phase 6: Vault Commands (Week 10)

### 6.1 Credential Rotation System
```python
# src/security/credential_manager.py (NEW)
class CredentialManager:
    """Automated credential rotation"""

    async def rotate_device_credentials(self, device_id):
        # Generate new credentials
        # Update on device
        # Store in Vault
        # Update database
        # Audit rotation

    async def schedule_rotation(self, policy):
        # Set up automatic rotation
        # Based on policy (30/60/90 days)
```

### 6.2 Implement Vault CLI
```python
# catnet_cli/commands/vault.py
@vault.command('status')
async def vault_status():
    """Check Vault connection"""
    # Test Vault connectivity
    # Show seal status
    # Display mount points

@vault.command('rotate')
@click.argument('device_id')
async def rotate_credentials(device_id):
    """Rotate device credentials"""
    # Use CredentialManager
    # Full audit trail
    # Notification on completion
```

### 6.3 Tests
```python
# tests/test_cli/test_vault_commands.py
async def test_credential_rotation():
    # Verify rotation works

async def test_vault_connectivity():
    # Test status command
```

### 6.4 GitHub Actions Check

## Phase 7: Microservices Architecture (Week 11-12)

### 7.1 Split Services
```python
# services/auth_service/ (Port 8081)
# Move all auth endpoints here
# Maintain existing functionality

# services/gitops_service/ (Port 8082)
# Move GitOps endpoints here
# Keep webhook processing

# services/deployment_service/ (Port 8083)
# Move deployment logic here
# Maintain strategies

# services/device_service/ (Port 8084)
# Move device management here
# Keep connectors
```

### 7.2 Service Communication
```python
# src/core/service_mesh.py (NEW)
class ServiceMesh:
    """mTLS communication between services"""

    async def call_service(self, service, endpoint, data):
        # mTLS certificate validation
        # Encrypted communication
        # Service discovery
        # Circuit breaker pattern
```

### 7.3 API Gateway
```python
# src/gateway/router.py (NEW)
class APIGateway:
    """Route requests to appropriate services"""

    async def route_request(self, request):
        # Authenticate request
        # Route to correct service
        # Aggregate responses
        # Return unified response
```

### 7.4 Docker Compose for Services
```yaml
# docker-compose.yml (ENHANCE)
services:
  auth-service:
    build: ./services/auth_service
    ports:
      - "8081:8081"

  gitops-service:
    build: ./services/gitops_service
    ports:
      - "8082:8082"

  deployment-service:
    build: ./services/deployment_service
    ports:
      - "8083:8083"

  device-service:
    build: ./services/device_service
    ports:
      - "8084:8084"
```

### 7.5 Tests
```python
# tests/test_microservices/
async def test_service_communication():
    # Test mTLS between services

async def test_api_gateway_routing():
    # Test request routing

async def test_service_discovery():
    # Test service mesh discovery
```

### 7.6 GitHub Actions Check

## Phase 8: Integration Testing (Week 13)

### 8.1 End-to-End Tests
```python
# tests/test_e2e/test_full_workflow.py
async def test_complete_deployment_workflow():
    # Login with MFA
    # Connect Git repository
    # Add devices
    # Create deployment
    # Approve deployment
    # Verify deployment
    # Test rollback

async def test_gitops_automation():
    # Push to repository
    # Verify webhook triggers
    # Check deployment created
    # Verify validation runs
```

### 8.2 Performance Tests
```python
# tests/test_performance/
async def test_deployment_performance():
    # Deploy to 100 devices
    # Measure time
    # Verify success rate

async def test_concurrent_operations():
    # Multiple simultaneous deployments
    # Verify isolation
    # Check audit accuracy
```

### 8.3 Security Tests
```python
# tests/test_security/
async def test_credential_isolation():
    # Verify credential separation

async def test_audit_immutability():
    # Verify audit logs cannot be modified

async def test_encryption_everywhere():
    # Check all data encrypted
```

### 8.4 Final GitHub Actions Check

## Phase 9: Documentation and Examples (Week 14)

### 9.1 Update Documentation
- Update README with all new CLI commands
- Create comprehensive API documentation
- Write deployment guides
- Document security architecture

### 9.2 Create Examples
```bash
# examples/
├── basic_deployment.sh
├── gitops_workflow.sh
├── multi_vendor_deployment.sh
├── disaster_recovery.sh
└── security_hardening.sh
```

### 9.3 Video Tutorials
- Record CLI usage demo
- Create deployment workflow walkthrough
- Show rollback procedures

## Testing Strategy Throughout

### After Each Phase:
1. Run existing test suite - must pass 100%
2. Run new feature tests - must pass 100%
3. Run security scans (Bandit, Safety, Trivy)
4. Run integration tests
5. Check code coverage (maintain or improve)
6. Run GitHub Actions CI/CD pipeline
7. Deploy to staging environment
8. Perform manual testing
9. Document any issues found
10. Fix all issues before proceeding

### CI/CD Requirements:
- All existing tests continue passing
- New tests for each feature
- Security scans remain clean
- Code coverage doesn't decrease
- Documentation updated
- No breaking changes to existing APIs

## Risk Mitigation

### Backward Compatibility
- All existing APIs remain functional
- Database migrations are non-destructive
- Existing configurations continue working
- Security features never disabled

### Rollback Plan
- Each phase is independently revertible
- Database migrations have rollback scripts
- Git tags for each phase completion
- Backup before each phase

### Security Maintenance
- No credentials in code
- All secrets in Vault
- Audit logging for everything
- Encryption remains mandatory
- MFA stays enabled

## Success Criteria

### Phase Completion:
- All tests passing (100%)
- GitHub Actions green
- Security scans clean
- Documentation updated
- Code reviewed
- Deployed to staging

### Project Completion:
- All CLAUDE-commandreference.txt commands working
- Microservices architecture operational
- Complete test coverage (>80%)
- Full security implementation maintained
- Performance benchmarks met
- Documentation comprehensive

## Timeline Summary

- **Phase 1**: CLI Foundation (2 weeks)
- **Phase 2**: Authentication Commands (1 week)
- **Phase 3**: Device Commands (2 weeks)
- **Phase 4**: GitOps Commands (2 weeks)
- **Phase 5**: Deployment Commands (2 weeks)
- **Phase 6**: Vault Commands (1 week)
- **Phase 7**: Microservices Architecture (2 weeks)
- **Phase 8**: Integration Testing (1 week)
- **Phase 9**: Documentation (1 week)

**Total Duration**: 14 weeks (3.5 months)

## Notes

- No optimization for time as requested
- Every existing feature preserved and enhanced
- Security never compromised
- Full testing at each stage
- GitHub Actions must pass after every phase
- Complete implementation of all CLAUDE-commandreference.txt features

---

This plan ensures complete feature parity with CLAUDE-commandreference.txt while maintaining and enhancing all existing CatNet functionality. Each phase is thoroughly tested and verified through CI/CD before proceeding.