from typing import Optional, List, Dict, Any
from datetime import datetime
import git
from git import Repo, Remote
import pygit2
import structlog
import os
import tempfile
import hashlib
from pathlib import Path
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException, status

from ..db.models import GitRepository, WebhookEvent, Deployment, DeploymentState
from ..db.database import database
from ..security.vault import VaultClient
from ..security.audit import AuditLogger
from .secret_scanner import SecretScanner
from .config_parser import ConfigParser

logger = structlog.get_logger()

class GitOpsService:
    def __init__(self):
        self.vault = VaultClient()
        self.audit = AuditLogger()
        self.secret_scanner = SecretScanner()
        self.config_parser = ConfigParser()
        self.workspace_dir = os.getenv("GIT_WORKSPACE", "/var/catnet/git-workspace")
        os.makedirs(self.workspace_dir, exist_ok=True)

    async def connect_repository(
        self,
        url: str,
        branch: str = "main",
        name: str = None,
        webhook_secret: str = None,
        auto_deploy: bool = False,
        gpg_verification: bool = True,
        user_id: str = None
    ) -> GitRepository:
        try:
            async with database.get_session() as db:
                existing = await db.execute(
                    select(GitRepository).where(GitRepository.url == url)
                )
                if existing.scalar_one_or_none():
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="Repository already connected"
                    )

                repo_name = name or self._extract_repo_name(url)

                ssh_key = await self._generate_deploy_key(repo_name)
                ssh_key_ref = f"git-keys/{repo_name}/deploy-key"
                await self.vault.store_secret(ssh_key_ref, {"private_key": ssh_key})

                if webhook_secret:
                    webhook_secret_ref = f"git-webhooks/{repo_name}/secret"
                    await self.vault.store_secret(
                        webhook_secret_ref,
                        {"secret": webhook_secret}
                    )
                else:
                    webhook_secret_ref = None

                repo_path = await self._clone_repository(url, repo_name, ssh_key)

                last_commit = await self._get_last_commit_hash(repo_path)

                repository = GitRepository(
                    name=repo_name,
                    url=url,
                    branch=branch,
                    webhook_secret_ref=webhook_secret_ref,
                    ssh_key_ref=ssh_key_ref,
                    last_commit_hash=last_commit,
                    last_sync=datetime.utcnow(),
                    gpg_verification=gpg_verification,
                    auto_deploy=auto_deploy,
                    is_active=True
                )

                db.add(repository)
                await db.commit()
                await db.refresh(repository)

                await self.audit.log_git_webhook_received(
                    repository_id=str(repository.id),
                    event_type="repository_connected",
                    signature_verified=True,
                    source_ip="internal"
                )

                return repository

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to connect repository: {e}")
            raise

    async def sync_repository(
        self,
        repository_id: str,
        force: bool = False
    ) -> Dict[str, Any]:
        try:
            async with database.get_session() as db:
                result = await db.execute(
                    select(GitRepository).where(GitRepository.id == repository_id)
                )
                repository = result.scalar_one_or_none()

                if not repository:
                    raise ValueError(f"Repository {repository_id} not found")

                repo_path = os.path.join(self.workspace_dir, repository.name)

                if not os.path.exists(repo_path):
                    ssh_key_data = await self.vault.get_secret(repository.ssh_key_ref)
                    repo_path = await self._clone_repository(
                        repository.url,
                        repository.name,
                        ssh_key_data["private_key"]
                    )

                repo = Repo(repo_path)
                origin = repo.remotes.origin

                old_commit = repo.head.commit.hexsha

                origin.fetch()

                if force:
                    origin.pull(force=True)
                else:
                    origin.pull()

                new_commit = repo.head.commit.hexsha

                if old_commit != new_commit:
                    changes = await self._analyze_changes(repo, old_commit, new_commit)

                    secrets_found = await self.secret_scanner.scan_commits(
                        repo_path, old_commit, new_commit
                    )

                    if secrets_found:
                        await self._quarantine_repository(repository_id, secrets_found)
                        return {
                            "status": "quarantined",
                            "reason": "secrets_detected",
                            "secrets": len(secrets_found)
                        }

                    configs = await self._extract_configs(repo_path, changes)

                    repository.last_commit_hash = new_commit
                    repository.last_sync = datetime.utcnow()
                    await db.commit()

                    if repository.auto_deploy and configs:
                        deployment_id = await self._create_auto_deployment(
                            repository_id, configs, new_commit
                        )
                        return {
                            "status": "synced",
                            "old_commit": old_commit,
                            "new_commit": new_commit,
                            "changes": len(changes),
                            "configs": len(configs),
                            "deployment_id": deployment_id
                        }

                    return {
                        "status": "synced",
                        "old_commit": old_commit,
                        "new_commit": new_commit,
                        "changes": len(changes),
                        "configs": len(configs)
                    }
                else:
                    return {
                        "status": "no_changes",
                        "commit": old_commit
                    }

        except Exception as e:
            logger.error(f"Failed to sync repository {repository_id}: {e}")
            raise

    async def _generate_deploy_key(self, repo_name: str) -> str:
        import subprocess
        key_path = tempfile.mktemp()
        subprocess.run([
            "ssh-keygen", "-t", "ed25519",
            "-f", key_path,
            "-N", "",
            "-C", f"catnet-deploy-{repo_name}"
        ], check=True, capture_output=True)

        with open(key_path, 'r') as f:
            private_key = f.read()

        os.remove(key_path)
        os.remove(f"{key_path}.pub")

        return private_key

    async def _clone_repository(
        self,
        url: str,
        repo_name: str,
        ssh_key: str
    ) -> str:
        repo_path = os.path.join(self.workspace_dir, repo_name)

        if os.path.exists(repo_path):
            return repo_path

        ssh_command = self._setup_ssh_command(ssh_key)

        with git.Git().custom_environment(GIT_SSH_COMMAND=ssh_command):
            repo = Repo.clone_from(url, repo_path)

        return repo_path

    def _setup_ssh_command(self, ssh_key: str) -> str:
        key_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        key_file.write(ssh_key)
        key_file.flush()

        return f"ssh -i {key_file.name} -o StrictHostKeyChecking=no"

    def _extract_repo_name(self, url: str) -> str:
        if url.endswith('.git'):
            url = url[:-4]
        return os.path.basename(url)

    async def _get_last_commit_hash(self, repo_path: str) -> str:
        repo = Repo(repo_path)
        return repo.head.commit.hexsha

    async def _analyze_changes(
        self,
        repo: Repo,
        old_commit: str,
        new_commit: str
    ) -> List[Dict[str, Any]]:
        changes = []

        diff = repo.git.diff(f"{old_commit}..{new_commit}", name_status=True)

        for line in diff.split('\n'):
            if line:
                parts = line.split('\t')
                if len(parts) == 2:
                    status, filename = parts
                    changes.append({
                        "status": status,
                        "file": filename,
                        "is_config": self._is_config_file(filename)
                    })

        return changes

    def _is_config_file(self, filename: str) -> bool:
        config_extensions = ['.yaml', '.yml', '.json', '.conf', '.cfg', '.ini']
        config_dirs = ['configs/', 'config/', 'deployments/', 'devices/']

        for ext in config_extensions:
            if filename.endswith(ext):
                return True

        for dir_pattern in config_dirs:
            if dir_pattern in filename:
                return True

        return False

    async def _extract_configs(
        self,
        repo_path: str,
        changes: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        configs = []

        for change in changes:
            if change["is_config"] and change["status"] in ["A", "M"]:
                file_path = os.path.join(repo_path, change["file"])
                if os.path.exists(file_path):
                    config = await self.config_parser.parse_file(file_path)
                    if config:
                        configs.append({
                            "file": change["file"],
                            "content": config,
                            "hash": self._calculate_hash(str(config))
                        })

        return configs

    def _calculate_hash(self, content: str) -> str:
        return hashlib.sha256(content.encode()).hexdigest()

    async def _quarantine_repository(
        self,
        repository_id: str,
        secrets: List[Dict[str, Any]]
    ):
        async with database.get_session() as db:
            result = await db.execute(
                select(GitRepository).where(GitRepository.id == repository_id)
            )
            repository = result.scalar_one_or_none()

            if repository:
                repository.is_active = False
                await db.commit()

            from ..db.models import SecurityEvent

            event = SecurityEvent(
                event_type="secrets_detected_in_repo",
                severity="critical",
                target_resource=str(repository_id),
                description=f"Secrets detected in repository {repository.name}",
                details={
                    "secrets_count": len(secrets),
                    "files": list(set(s["file"] for s in secrets))
                }
            )
            db.add(event)
            await db.commit()

            await self.audit.log_git_webhook_received(
                repository_id=str(repository_id),
                event_type="repository_quarantined",
                signature_verified=True,
                source_ip="internal"
            )

    async def _create_auto_deployment(
        self,
        repository_id: str,
        configs: List[Dict[str, Any]],
        commit_hash: str
    ) -> str:
        async with database.get_session() as db:
            deployment = Deployment(
                repository_id=repository_id,
                created_by=None,
                config_hash=self._calculate_hash(str(configs)),
                signature="auto-deployment",
                state=DeploymentState.PENDING,
                strategy="rolling",
                approval_required=True,
                min_approvals=2,
                canary_percentage=5,
                rollback_on_failure=True,
                dry_run=False,
                commit_hash=commit_hash,
                commit_message="Auto-deployment from GitOps sync",
                audit_log={"auto_created": True}
            )

            db.add(deployment)
            await db.commit()

            return str(deployment.id)

    async def verify_commit_signature(
        self,
        repository_id: str,
        commit_hash: str
    ) -> bool:
        try:
            async with database.get_session() as db:
                result = await db.execute(
                    select(GitRepository).where(GitRepository.id == repository_id)
                )
                repository = result.scalar_one_or_none()

                if not repository or not repository.gpg_verification:
                    return True

                repo_path = os.path.join(self.workspace_dir, repository.name)
                repo = Repo(repo_path)

                commit = repo.commit(commit_hash)

                try:
                    repo.git.verify_commit(commit_hash)
                    return True
                except git.GitCommandError:
                    logger.warning(f"GPG signature verification failed for commit {commit_hash}")
                    return False

        except Exception as e:
            logger.error(f"Failed to verify commit signature: {e}")
            return False

    async def list_configs(
        self,
        repository_id: str
    ) -> List[Dict[str, Any]]:
        try:
            async with database.get_session() as db:
                result = await db.execute(
                    select(GitRepository).where(GitRepository.id == repository_id)
                )
                repository = result.scalar_one_or_none()

                if not repository:
                    raise ValueError(f"Repository {repository_id} not found")

                repo_path = os.path.join(self.workspace_dir, repository.name)

                if not os.path.exists(repo_path):
                    ssh_key_data = await self.vault.get_secret(repository.ssh_key_ref)
                    repo_path = await self._clone_repository(
                        repository.url,
                        repository.name,
                        ssh_key_data["private_key"]
                    )

                configs = []
                for root, dirs, files in os.walk(repo_path):
                    dirs[:] = [d for d in dirs if not d.startswith('.')]

                    for file in files:
                        file_path = os.path.join(root, file)
                        relative_path = os.path.relpath(file_path, repo_path)

                        if self._is_config_file(relative_path):
                            config = await self.config_parser.parse_file(file_path)
                            if config:
                                configs.append({
                                    "path": relative_path,
                                    "type": self._detect_config_type(config),
                                    "devices": config.get("devices", []),
                                    "hash": self._calculate_hash(str(config))
                                })

                return configs

        except Exception as e:
            logger.error(f"Failed to list configs: {e}")
            raise

    def _detect_config_type(self, config: Dict[str, Any]) -> str:
        if "devices" in config:
            return "device_config"
        elif "deployment" in config:
            return "deployment_config"
        elif "acl" in config or "firewall" in config:
            return "security_config"
        elif "routing" in config or "bgp" in config:
            return "routing_config"
        elif "vlan" in config or "interface" in config:
            return "network_config"
        else:
            return "general_config"

    async def rollback_to_commit(
        self,
        repository_id: str,
        target_commit: str,
        user_id: str
    ) -> Dict[str, Any]:
        try:
            async with database.get_session() as db:
                result = await db.execute(
                    select(GitRepository).where(GitRepository.id == repository_id)
                )
                repository = result.scalar_one_or_none()

                if not repository:
                    raise ValueError(f"Repository {repository_id} not found")

                repo_path = os.path.join(self.workspace_dir, repository.name)
                repo = Repo(repo_path)

                current_commit = repo.head.commit.hexsha

                repo.git.reset('--hard', target_commit)

                repository.last_commit_hash = target_commit
                repository.last_sync = datetime.utcnow()
                await db.commit()

                await self.audit.log_git_webhook_received(
                    repository_id=str(repository_id),
                    event_type="manual_rollback",
                    signature_verified=True,
                    source_ip="internal"
                )

                return {
                    "status": "rolled_back",
                    "from_commit": current_commit,
                    "to_commit": target_commit
                }

        except Exception as e:
            logger.error(f"Failed to rollback repository: {e}")
            raise

    async def get_commit_history(
        self,
        repository_id: str,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        try:
            async with database.get_session() as db:
                result = await db.execute(
                    select(GitRepository).where(GitRepository.id == repository_id)
                )
                repository = result.scalar_one_or_none()

                if not repository:
                    raise ValueError(f"Repository {repository_id} not found")

                repo_path = os.path.join(self.workspace_dir, repository.name)

                if not os.path.exists(repo_path):
                    ssh_key_data = await self.vault.get_secret(repository.ssh_key_ref)
                    repo_path = await self._clone_repository(
                        repository.url,
                        repository.name,
                        ssh_key_data["private_key"]
                    )

                repo = Repo(repo_path)
                commits = []

                for commit in repo.iter_commits(max_count=limit):
                    commits.append({
                        "hash": commit.hexsha,
                        "author": commit.author.name,
                        "email": commit.author.email,
                        "date": commit.committed_datetime.isoformat(),
                        "message": commit.message.strip(),
                        "files_changed": len(commit.stats.files),
                        "signed": await self.verify_commit_signature(repository_id, commit.hexsha)
                    })

                return commits

        except Exception as e:
            logger.error(f"Failed to get commit history: {e}")
            raise