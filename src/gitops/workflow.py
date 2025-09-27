"""GitOps workflow implementation"""

import hashlib
import hmac
import json
import re
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path
import git
import yaml
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import logging

from src.core import DeploymentState, DeploymentStrategy
from src.db.models import GitRepository, Deployment, User, ValidationResult
from src.security.vault import vault_client
from src.security.encryption import encryption_manager
from src.gitops import WebhookVerificationError, ConfigParsingError, WebhookEvent

logger = logging.getLogger(__name__)


class GitOpsWorkflow:
    """GitOps configuration processing pipeline"""

    def __init__(self):
        """Initialize GitOps workflow"""
        self.secret_patterns = [
            re.compile(r'password\s*[:=]\s*["\']?([^"\'\s]+)', re.IGNORECASE),
            re.compile(r'api[_-]?key\s*[:=]\s*["\']?([^"\'\s]+)', re.IGNORECASE),
            re.compile(r'secret\s*[:=]\s*["\']?([^"\'\s]+)', re.IGNORECASE),
            re.compile(r'token\s*[:=]\s*["\']?([^"\'\s]+)', re.IGNORECASE),
            re.compile(r'["\']?password["\']?\s*:\s*["\']([^"\']+)["\']'),
            re.compile(r'BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY'),
        ]

    async def process_git_push(
        self,
        webhook_payload: Dict[str, Any],
        repository: GitRepository,
        db: AsyncSession,
        user: User
    ) -> Optional[Deployment]:
        """
        Process Git push webhook

        Args:
            webhook_payload: Webhook payload from Git provider
            repository: Git repository configuration
            db: Database session
            user: User triggering deployment

        Returns:
            Created deployment or None if validation fails
        """
        # Step 1: Verify webhook signature
        if not await self.verify_webhook_signature(webhook_payload, repository):
            raise WebhookVerificationError("Invalid webhook signature")

        # Step 2: Scan for secrets
        secrets = await self.scan_for_secrets(webhook_payload.get('commits', []))
        if secrets:
            await self.quarantine_and_alert(secrets, repository, user)
            return None

        # Step 3: Parse configurations
        configs = await self.parse_configs(webhook_payload, repository)
        if not configs:
            logger.info("No configuration changes detected")
            return None

        # Step 4: Validate configurations
        validation_results = []
        for config in configs:
            validation = await self.validate_config(config)
            validation_results.append(validation)
            if not validation.is_valid:
                await self.notify_validation_failure(validation, repository, user)
                return None

        # Step 5: Create deployment with approval workflow
        deployment = await self.create_deployment(
            db=db,
            repository=repository,
            configs=configs,
            validation_results=validation_results,
            user=user,
            requires_approval=await self.check_approval_required(configs)
        )

        # Step 6: Execute deployment strategy if auto-deploy
        if repository.auto_deploy and not deployment.approval_required:
            await self.trigger_deployment(deployment)

        return deployment

    async def verify_webhook_signature(
        self,
        payload: Dict[str, Any],
        repository: GitRepository
    ) -> bool:
        """
        Verify webhook signature

        Args:
            payload: Webhook payload
            repository: Repository configuration

        Returns:
            True if signature is valid
        """
        try:
            # Get webhook secret from Vault
            if not repository.webhook_secret_ref:
                logger.warning(f"No webhook secret configured for repository {repository.name}")
                return False

            secret = await vault_client.get_webhook_secret(repository.name)
            if not secret:
                return False

            # Calculate expected signature
            payload_str = json.dumps(payload, sort_keys=True)
            expected_signature = hmac.new(
                secret.encode(),
                payload_str.encode(),
                hashlib.sha256
            ).hexdigest()

            # Compare with received signature
            received_signature = payload.get('signature', '')
            return hmac.compare_digest(expected_signature, received_signature)

        except Exception as e:
            logger.error(f"Webhook signature verification failed: {e}")
            return False

    async def scan_for_secrets(self, commits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Scan commits for exposed secrets

        Args:
            commits: List of commit data

        Returns:
            List of detected secrets
        """
        detected_secrets = []

        for commit in commits:
            # Check commit message
            message = commit.get('message', '')
            for pattern in self.secret_patterns:
                if pattern.search(message):
                    detected_secrets.append({
                        'commit': commit.get('id'),
                        'type': 'commit_message',
                        'pattern': pattern.pattern
                    })

            # Check modified files
            for file_change in commit.get('modified', []):
                content = file_change.get('content', '')
                for pattern in self.secret_patterns:
                    if pattern.search(content):
                        detected_secrets.append({
                            'commit': commit.get('id'),
                            'file': file_change.get('filename'),
                            'type': 'file_content',
                            'pattern': pattern.pattern
                        })

        return detected_secrets

    async def quarantine_and_alert(
        self,
        secrets: List[Dict[str, Any]],
        repository: GitRepository,
        user: User
    ) -> None:
        """
        Quarantine commits with secrets and alert security team

        Args:
            secrets: List of detected secrets
            repository: Repository configuration
            user: User who pushed commits
        """
        logger.critical(
            f"SECURITY ALERT: Secrets detected in repository {repository.name}",
            extra={
                'repository': repository.name,
                'user': user.username,
                'secrets_count': len(secrets),
                'secrets': secrets
            }
        )

        # In production, would:
        # 1. Block the commits
        # 2. Rotate exposed credentials
        # 3. Alert security team
        # 4. Create incident ticket

    async def parse_configs(
        self,
        webhook_payload: Dict[str, Any],
        repository: GitRepository
    ) -> List[Dict[str, Any]]:
        """
        Parse configuration files from webhook payload

        Args:
            webhook_payload: Webhook payload
            repository: Repository configuration

        Returns:
            List of parsed configurations
        """
        configs = []

        # Extract changed files
        for commit in webhook_payload.get('commits', []):
            for file_path in commit.get('modified', []) + commit.get('added', []):
                # Check if file matches config pattern
                if self._matches_config_pattern(file_path, repository.config_path_pattern):
                    try:
                        config = await self._parse_config_file(file_path, commit.get('id'))
                        if config:
                            configs.append(config)
                    except Exception as e:
                        logger.error(f"Failed to parse config file {file_path}: {e}")

        return configs

    def _matches_config_pattern(self, file_path: str, pattern: str) -> bool:
        """Check if file path matches configuration pattern"""
        import fnmatch
        return fnmatch.fnmatch(file_path, pattern)

    async def _parse_config_file(
        self,
        file_path: str,
        commit_id: str
    ) -> Optional[Dict[str, Any]]:
        """Parse individual configuration file"""
        try:
            # In production, would fetch file content from Git
            # For now, return mock config
            return {
                'file_path': file_path,
                'commit_id': commit_id,
                'vendor': 'cisco',
                'devices': [],
                'configuration': {},
                'metadata': {
                    'parsed_at': datetime.utcnow().isoformat()
                }
            }
        except Exception as e:
            raise ConfigParsingError(f"Failed to parse {file_path}: {e}")

    async def validate_config(self, config: Dict[str, Any]) -> ValidationResult:
        """
        Validate configuration

        Args:
            config: Configuration to validate

        Returns:
            Validation result
        """
        from src.core import ValidationLevel

        result = ValidationResult(
            validation_level=ValidationLevel.FULL,
            is_valid=True,
            errors=[],
            warnings=[],
            metadata=config.get('metadata', {}),
            validated_at=datetime.utcnow()
        )

        # Layer 1: Schema validation
        if not self._validate_schema(config):
            result.is_valid = False
            result.errors.append("Schema validation failed")
            return result

        # Layer 2: Syntax validation
        vendor = config.get('vendor')
        if vendor == 'cisco':
            syntax_valid = await self._validate_cisco_syntax(config)
        elif vendor == 'juniper':
            syntax_valid = await self._validate_juniper_syntax(config)
        else:
            result.is_valid = False
            result.errors.append(f"Unsupported vendor: {vendor}")
            return result

        if not syntax_valid:
            result.is_valid = False
            result.errors.append("Syntax validation failed")

        # Layer 3: Security compliance
        security_issues = await self._check_security_compliance(config)
        for issue in security_issues:
            result.warnings.append(f"Security: {issue}")

        # Layer 4: Business rules
        business_violations = await self._check_business_rules(config)
        for violation in business_violations:
            result.is_valid = False
            result.errors.append(f"Business rule: {violation}")

        # Layer 5: Conflict detection
        conflicts = await self._detect_conflicts(config)
        for conflict in conflicts:
            result.warnings.append(f"Conflict: {conflict}")

        return result

    def _validate_schema(self, config: Dict[str, Any]) -> bool:
        """Validate configuration schema"""
        required_fields = ['vendor', 'devices', 'configuration']
        return all(field in config for field in required_fields)

    async def _validate_cisco_syntax(self, config: Dict[str, Any]) -> bool:
        """Validate Cisco configuration syntax"""
        # Simplified validation - in production would use actual parser
        return True

    async def _validate_juniper_syntax(self, config: Dict[str, Any]) -> bool:
        """Validate Juniper configuration syntax"""
        # Simplified validation - in production would use actual parser
        return True

    async def _check_security_compliance(self, config: Dict[str, Any]) -> List[str]:
        """Check security compliance"""
        issues = []

        # Example security checks
        config_text = str(config.get('configuration', ''))

        if 'telnet' in config_text.lower():
            issues.append("Telnet is not allowed - use SSH")

        if 'snmp community public' in config_text.lower():
            issues.append("Default SNMP community detected")

        if 'password 0' in config_text.lower():
            issues.append("Unencrypted password detected")

        return issues

    async def _check_business_rules(self, config: Dict[str, Any]) -> List[str]:
        """Check business rules"""
        violations = []

        # Example business rule checks
        # In production, these would be configurable

        return violations

    async def _detect_conflicts(self, config: Dict[str, Any]) -> List[str]:
        """Detect configuration conflicts"""
        conflicts = []

        # Example conflict detection
        # Would check against current device configurations

        return conflicts

    async def notify_validation_failure(
        self,
        validation: ValidationResult,
        repository: GitRepository,
        user: User
    ) -> None:
        """Notify about validation failure"""
        logger.warning(
            f"Configuration validation failed for repository {repository.name}",
            extra={
                'repository': repository.name,
                'user': user.username,
                'errors': validation.errors,
                'warnings': validation.warnings
            }
        )

    async def check_approval_required(self, configs: List[Dict[str, Any]]) -> bool:
        """Check if deployment requires approval"""
        # Check if any config affects critical devices
        for config in configs:
            devices = config.get('devices', [])
            for device in devices:
                if device.get('is_critical', False):
                    return True

        # Check if configuration contains risky changes
        risky_keywords = ['shutdown', 'no interface', 'clear', 'erase']
        for config in configs:
            config_text = str(config.get('configuration', '')).lower()
            if any(keyword in config_text for keyword in risky_keywords):
                return True

        return False

    async def create_deployment(
        self,
        db: AsyncSession,
        repository: GitRepository,
        configs: List[Dict[str, Any]],
        validation_results: List[ValidationResult],
        user: User,
        requires_approval: bool
    ) -> Deployment:
        """
        Create deployment record

        Args:
            db: Database session
            repository: Repository configuration
            configs: Parsed configurations
            validation_results: Validation results
            user: User creating deployment
            requires_approval: Whether approval is required

        Returns:
            Created deployment
        """
        # Calculate configuration hash
        config_str = json.dumps(configs, sort_keys=True)
        config_hash = encryption_manager.generate_hash(config_str)

        # Generate digital signature
        signature = encryption_manager.generate_signature(config_str)

        # Create deployment
        deployment = Deployment(
            name=f"Deployment from {repository.name}",
            description=f"GitOps deployment from repository {repository.name}",
            repository_id=repository.id,
            config_hash=config_hash,
            signature=signature,
            state=DeploymentState.AWAITING_APPROVAL if requires_approval else DeploymentState.PENDING,
            strategy=DeploymentStrategy.CANARY,
            approval_required=requires_approval,
            min_approvers=2 if requires_approval else 0,
            auto_rollback=True,
            rollback_on_error_percentage=5,
            health_check_wait_seconds=60,
            deployment_timeout_seconds=3600,
            created_by=user.id,
            metadata={
                'configs': configs,
                'source': 'gitops',
                'repository': repository.name
            },
            audit_log={
                'created': {
                    'timestamp': datetime.utcnow().isoformat(),
                    'user': user.username,
                    'action': 'deployment_created'
                }
            }
        )

        db.add(deployment)

        # Add validation results
        for validation in validation_results:
            validation.deployment_id = deployment.id
            db.add(validation)

        await db.commit()
        await db.refresh(deployment)

        return deployment

    async def trigger_deployment(self, deployment: Deployment) -> None:
        """Trigger deployment execution"""
        # In production, would send message to Deployment Service
        logger.info(f"Triggering deployment {deployment.id}")


class GitRepositoryManager:
    """Manage Git repository operations"""

    def __init__(self):
        """Initialize repository manager"""
        self.repos_path = Path("/var/catnet/repos")
        self.repos_path.mkdir(parents=True, exist_ok=True)

    async def clone_repository(
        self,
        repository: GitRepository
    ) -> git.Repo:
        """Clone or update repository"""
        repo_path = self.repos_path / repository.name

        try:
            if repo_path.exists():
                # Update existing repository
                repo = git.Repo(repo_path)
                origin = repo.remote('origin')
                origin.pull(repository.branch)
            else:
                # Clone new repository
                # Get SSH key from Vault if configured
                ssh_key = None
                if repository.ssh_key_vault_path:
                    ssh_key = await vault_client.get_secret(repository.ssh_key_vault_path)

                repo = git.Repo.clone_from(
                    repository.url,
                    repo_path,
                    branch=repository.branch
                )

            # Update last commit hash
            repository.last_commit_hash = repo.head.commit.hexsha
            repository.last_sync_at = datetime.utcnow()

            return repo

        except Exception as e:
            logger.error(f"Failed to clone/update repository {repository.name}: {e}")
            raise

    async def get_config_files(
        self,
        repository: GitRepository,
        pattern: Optional[str] = None
    ) -> List[Path]:
        """Get configuration files from repository"""
        repo_path = self.repos_path / repository.name
        pattern = pattern or repository.config_path_pattern or "**/*.yaml"

        config_files = []
        for file_path in repo_path.glob(pattern):
            if file_path.is_file():
                config_files.append(file_path)

        return config_files

    async def verify_commit_signature(
        self,
        repository: GitRepository,
        commit_hash: str
    ) -> bool:
        """Verify GPG signature of commit"""
        if not repository.gpg_verification:
            return True

        repo_path = self.repos_path / repository.name
        repo = git.Repo(repo_path)

        try:
            commit = repo.commit(commit_hash)
            # In production, would verify GPG signature
            return True
        except Exception as e:
            logger.error(f"Failed to verify commit signature: {e}")
            return False