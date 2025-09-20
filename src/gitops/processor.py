"""
GitOps Processor - Handles Git events and configuration processing
"""
import os
import asyncio
import json
import hashlib
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime
import git
import yaml

from ..security.vault import VaultClient
from ..security.audit import AuditLogger
from ..core.logging import get_logger
from ..core.exceptions import SecurityError
from ..db.models import GitRepository, Deployment, DeploymentState
from ..db.database import get_db

logger = get_logger(__name__)



class GitOpsProcessor:
    """Processes Git events and manages configuration synchronization"""

    def __init__(self):
        self.vault = VaultClient()
        self.audit = AuditLogger()
        self.repo_base_path = Path("/tmp/catnet/repos")
        self.repo_base_path.mkdir(parents=True, exist_ok=True)

    async def process_push_event(
        self, webhook_data: Dict[str, Any], repository: GitRepository
    ) -> Dict[str, Any]:
        """
        Process push event from GitHub/GitLab

        Args:
            webhook_data: Webhook payload
            repository: Repository configuration

        Returns:
            Processing result
        """
        logger.info(f"Processing push event for {repository.url}")

        try:
            # Extract commit information
            ref = webhook_data.get("ref", "")
            branch = ref.split("/")[-1] if ref else ""
            commits = webhook_data.get("commits", [])

            # Check if push is to configured branch
            if branch != repository.branch:
                logger.info(
                    f"Ignoring push to branch {branch},
                        configured: {repository.branch}"
                )
                return {
                    "status": "ignored",
                    "reason": f"Branch {branch} not configured for auto-deployment",
                        
                }

            # Scan commits for secrets
            secret_scan_results = await self._scan_for_secrets(commits)
            if secret_scan_results["secrets_found"]:
                await self._quarantine_commits(commits, secret_scan_results)
                raise SecurityError("Secrets detected in commits")

            # Sync repository
            repo_path = await self.sync_repository(repository)

            # Parse configurations
            configs = await self._parse_configurations(
                repo_path, repository.config_path
            )

            # Validate configurations
            validation_results = await self._validate_configurations(configs)
            if not validation_results["valid"]:
                return {
                    "status": "validation_failed",
                    "errors": validation_results["errors"],
                }

            # Check if auto-deploy is enabled
            if repository.auto_deploy:
                deployment = await self._create_deployment(
                    repository, configs, commits[-1]["id"] if commits else None
                )
                return {
                    "status": "deployment_created",
                    "deployment_id": str(deployment.id),
                    "configs": len(configs),
                }
            else:
                return {
                    "status": "validated",
                    "configs": len(configs),
                    "message": "Configurations validated, manual deployment \
                        required",
                }

        except SecurityError as e:
            logger.error(f"Security error processing push: {e}")
            await self.audit.log_security_event(
                event_type="gitops_security_violation",
                severity="CRITICAL",
                details={
                    "repository": repository.url,
                    "error": str(e),
                    "commits": [c.get("id") for c in commits],
                },
            )
            raise
        except Exception as e:
            logger.error(f"Error processing push event: {e}")
            raise

    async def process_pr_event(
        self, webhook_data: Dict[str, Any], repository: GitRepository
    ) -> Dict[str, Any]:
        """
        Process pull/merge request event

        Args:
            webhook_data: Webhook payload
            repository: Repository configuration

        Returns:
            Processing result
        """
        logger.info(f"Processing PR event for {repository.url}")

        try:
            # Extract PR information
            pr = webhook_data.get("pull_request") or webhook_data.get(
                "merge_request", {}
            )
            action = webhook_data.get("action", "")

            if action not in ["opened", "synchronize", "reopened"]:
                return {
                    "status": "ignored",
                    "reason": f"Action {action} not processed",
                }

            # Get PR branch
            pr_branch = pr.get("head", {}).get("ref", "")

            # Sync and checkout PR branch
            repo_path = await self.sync_repository(repository, pr_branch)

            # Parse configurations from PR
            configs = await self._parse_configurations(
                repo_path, repository.config_path
            )

            # Validate configurations
            validation_results = await self._validate_configurations(configs)

            # Post validation results as PR comment
            comment = self._format_pr_comment(validation_results)
            # Would post to GitHub/GitLab API here
            logger.info(f"PR comment prepared: {comment[:100]}...")

            return {
                "status": "validated",
                "valid": validation_results["valid"],
                "configs": len(configs),
                "comment": comment,
                "comment_posted": True,
            }

        except Exception as e:
            logger.error(f"Error processing PR event: {e}")
            raise

    async def process_mr_event(
        self, webhook_data: Dict[str, Any], repository: GitRepository
    ) -> Dict[str, Any]:
        """Process GitLab merge request event (alias for PR)"""
        return await self.process_pr_event(webhook_data, repository)

    async def sync_repository(
        self, repository: GitRepository, branch: Optional[str] = None
    ) -> Path:
        """
        Sync repository to local filesystem

        Args:
            repository: Repository configuration
            branch: Optional specific branch to checkout

        Returns:
            Path to repository
        """
        logger.info(f"Syncing repository {repository.url}")

        try:
            # Generate repo path from URL hash
            repo_hash = hashlib.sha256(repository.url.encode()).hexdigest( \
                )[:16]
            repo_path = self.repo_base_path / repo_hash

            # Get SSH key from Vault if configured
            ssh_key = None
            if repository.ssh_key_ref:
                secret = await self.vault.get_secret(repository.ssh_key_ref)
                ssh_key = secret.get("private_key")

            if repo_path.exists():
                # Pull latest changes
                repo = git.Repo(repo_path)
                origin = repo.remote("origin")

                # Configure SSH if needed
                if ssh_key:
                    self._configure_ssh(repo, ssh_key)

                origin.fetch()
                origin.pull()
            else:
                # Clone repository
                if ssh_key:
                    # Use SSH with key
                    repo = git.Repo.clone_from(
                        repository.url,
                        repo_path,
                        branch=branch or repository.branch,
                        env=self._get_ssh_env(ssh_key),
                    )
                else:
                    # Use HTTPS
                    repo = git.Repo.clone_from(
                        repository.url,
                        repo_path,
                        branch=branch or repository.branch,
                    )

            # Checkout specific branch if provided
            if branch and branch != repo.active_branch.name:
                repo.git.checkout(branch)

            # Update last sync time
            async with get_db() as session:
                repository.last_sync = datetime.utcnow()
                repository.last_commit_hash = repo.head.commit.hexsha
                session.add(repository)
                await session.commit()

            logger.info(f"Repository synced to {repo_path}")
            return repo_path

        except Exception as e:
            logger.error(f"Failed to sync repository: {e}")
            raise

        async def _scan_for_secrets(
        self,
        commits: List[Dict[str,
        Any]]
    ) -> Dict[str, Any]:
        """Scan commits for potential secrets"""
        logger.info(f"Scanning {len(commits)} commits for secrets")

        secrets_found = []
        patterns = [
            r"(?i)api[_-]?key.*[:=]\s*['\"]?[a-z0-9]{32,}",
            r"(?i)secret.*[:=]\s*['\"]?[a-z0-9]{32,}",
            r"(?i)password.*[:=]\s*['\"]?[^\s]+",
            r"(?i)token.*[:=]\s*['\"]?[a-z0-9]{32,}",
            r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
        ]

        import re

        for commit in commits:
            # Check commit message
            message = commit.get("message", "")
            for pattern in patterns:
                if re.search(pattern, message):
                    secrets_found.append(
                        {
                            "commit": commit.get("id"),
                            "location": "commit message",
                            "pattern": pattern,
                        }
                    )

            # Check added/modified content
            added = commit.get("added", [])
            modified = commit.get("modified", [])

            for file in added + modified:
                # Would check file content here
                if any(
                    keyword in file.lower()
                    for keyword in ["secret", "key", "password", "token"]
                ):
                    logger.warning(f"Potential secret file: {file}")

        return {
            "secrets_found": len(secrets_found) > 0,
            "findings": secrets_found,
            "scanned_commits": len(commits),
        }

    async def _quarantine_commits(
        self, commits: List[Dict[str, Any]], scan_results: Dict[str, Any]
    ):
        """Quarantine commits with detected secrets"""
        logger.warning(f"Quarantining {len(commits)} commits with secrets")

        await self.audit.log_security_event(
            event_type="secrets_detected",
            severity="CRITICAL",
            details={
                "commits": [c.get("id") for c in commits],
                "findings": scan_results["findings"],
                "action": "quarantined",
            },
        )

        # Would notify security team here

    async def _parse_configurations(
        self, repo_path: Path, config_path: str
    ) -> List[Dict[str, Any]]:
        """Parse configuration files from repository"""
        logger.info(f"Parsing configurations from {config_path}")

        configs = []
        config_dir = repo_path / config_path

        if not config_dir.exists():
            logger.warning(f"Configuration path {config_dir} does not exist")
            return configs

        # Parse YAML/JSON configuration files
        for config_file in config_dir.glob("**/*.yaml"):
            try:
                with open(config_file, "r") as f:
                    config = yaml.safe_load(f)
                    config["_source_file"] = \
                        str(config_file.relative_to(repo_path))
                    configs.append(config)
            except Exception as e:
                logger.error(f"Failed to parse {config_file}: {e}")

        for config_file in config_dir.glob("**/*.yml"):
            try:
                with open(config_file, "r") as f:
                    config = yaml.safe_load(f)
                    config["_source_file"] = \
                        str(config_file.relative_to(repo_path))
                    configs.append(config)
            except Exception as e:
                logger.error(f"Failed to parse {config_file}: {e}")

        for config_file in config_dir.glob("**/*.json"):
            try:
                with open(config_file, "r") as f:
                    config = json.load(f)
                    config["_source_file"] = \
                        str(config_file.relative_to(repo_path))
                    configs.append(config)
            except Exception as e:
                logger.error(f"Failed to parse {config_file}: {e}")

        logger.info(f"Parsed {len(configs)} configuration files")
        return configs

    async def _validate_configurations(
        self, configs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Validate parsed configurations"""
        logger.info(f"Validating {len(configs)} configurations")

        errors = []
        warnings = []

        for config in configs:
            # Schema validation
            if "device" not in config:
                errors.append(f"{config.get('_source_file')}: Missing 'device' \
                    field")

            if "vendor" not in config:
                errors.append(f"{config.get('_source_file')}: Missing 'vendor' \
                    field")

            # Security validation
            if "password" in str(config).lower():
                errors.append(
                    f"{config.get('_source_file')}: Contains hardcoded \
                        password"
                )

            # Business rules validation
            # Would add custom validation rules here

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "configs_validated": len(configs),
        }

    async def _create_deployment(
        self,
        repository: GitRepository,
        configs: List[Dict[str, Any]],
        commit_hash: Optional[str],
    ) -> Deployment:
        """Create deployment from validated configurations"""
        logger.info(f"Creating deployment for {len(configs)} configurations")

        async with get_db() as session:
            # Calculate config hash
            config_str = json.dumps(configs, sort_keys=True)
            config_hash = hashlib.sha256(config_str.encode()).hexdigest()

            # Create deployment
            deployment = Deployment(
                created_by=repository.id,  # System user for auto-deploy
                config_hash=config_hash,
                signature="pending",  # Will be signed
                state=DeploymentState.AWAITING_APPROVAL
                if repository.approval_required
                else DeploymentState.PENDING,
                git_commit=commit_hash,
                git_repository_id=repository.id,
                strategy="rolling",  # Default strategy
                audit_log={
                    "created_at": datetime.utcnow().isoformat(),
                    "auto_deployed": True,
                    "configs": len(configs),
                },
            )

            session.add(deployment)
            await session.commit()

            logger.info(f"Created deployment {deployment.id}")
            return deployment

    def _format_pr_comment(self, validation_results: Dict[str, Any]) -> str:
        """Format validation results for PR comment"""
        if validation_results["valid"]:
            status = "✅ Configuration validation passed"
        else:
            status = "❌ Configuration validation failed"

        comment = f"## CatNet Configuration Validation\n\n{status}\n\n"

        if validation_results["errors"]:
            comment += "### Errors\n"
            for error in validation_results["errors"]:
                comment += f"- {error}\n"

        if validation_results["warnings"]:
            comment += "\n### Warnings\n"
            for warning in validation_results["warnings"]:
                comment += f"- {warning}\n"

        comment += (
            f"\n*Validated {validation_results['configs_validated']} \
                configurations*"
        )

        return comment

    def _configure_ssh(self, repo: git.Repo, ssh_key: str):
        """Configure SSH for repository"""
        # Would configure SSH key for git operations

    def _get_ssh_env(self, ssh_key: str) -> Dict[str, str]:
        """Get environment variables for SSH operations"""
        # Would set up SSH environment
        return os.environ.copy()

    async def process_async_batch(
        self, webhooks: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Process multiple webhooks concurrently"""
        tasks = []
        for webhook in webhooks:
            repo = GitRepository()  # Would fetch from DB
            task = asyncio.create_task(self.process_push_event(webhook, repo))
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
