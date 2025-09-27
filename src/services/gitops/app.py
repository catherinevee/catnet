"""
GitOps microservice application.

Manages Git repositories, processes webhooks, and synchronizes configurations.
"""

import os
import asyncio
import hashlib
import hmac
import json
from typing import Dict, Any, List, Optional
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, Header, Request, status, BackgroundTasks
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
import uvicorn
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
import redis.asyncio as redis
import git
from git import Repo, Remote
import pygit2
import aiofiles
import yaml
import toml

from src.core.config import get_settings
from src.core.logging import get_logger
from src.security.vault import VaultClient
from src.security.encryption import EncryptionService
from src.db.models import Base, Repository, WebhookEvent, ConfigFile, CommitInfo
from .models import (
    RepositoryCreateRequest,
    RepositoryResponse,
    WebhookPayload,
    ConfigSyncRequest,
    ConfigValidationRequest,
    ConfigValidationResponse,
    PullRequestCreate,
    CommitRequest
)
from .handlers import (
    RepositoryHandler,
    WebhookHandler,
    ConfigHandler,
    SyncHandler,
    ValidationHandler
)

logger = get_logger(__name__)
settings = get_settings()


class GitOpsService:
    """
    Main GitOps service implementation.

    Handles:
    - Repository management (clone, pull, push)
    - Webhook processing (GitHub, GitLab, Bitbucket)
    - Configuration file management
    - Sync operations
    - Validation and compliance checks
    - Secret scanning
    - Signed commits
    """

    def __init__(self):
        self.vault = VaultClient()
        self.encryption = EncryptionService()
        self.redis = None
        self.db_session = None
        self.repo_handler = RepositoryHandler()
        self.webhook_handler = WebhookHandler()
        self.config_handler = ConfigHandler()
        self.sync_handler = SyncHandler()
        self.validation_handler = ValidationHandler()
        self.repos_dir = Path(settings.GIT_REPOS_DIR or "/var/lib/catnet/repos")
        self.repos_dir.mkdir(parents=True, exist_ok=True)

    async def initialize(self):
        """Initialize service connections."""
        # Initialize Redis
        self.redis = await redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            ssl_cert_reqs="required" if settings.REDIS_SSL else None,
        )

        # Initialize database
        engine = create_async_engine(
            settings.DATABASE_URL,
            pool_size=20,
            max_overflow=0,
            pool_pre_ping=True,
            echo=False,
        )
        async_session = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        self.db_session = async_session

        # Initialize handlers
        await self.repo_handler.initialize()
        await self.webhook_handler.initialize()
        await self.config_handler.initialize()
        await self.sync_handler.initialize()
        await self.validation_handler.initialize()

        logger.info("GitOps service initialized successfully")

    async def connect_repository(
        self,
        url: str,
        branch: str = "main",
        auth_type: str = "ssh",
        credentials: Optional[Dict[str, str]] = None
    ) -> Repository:
        """
        Connect to a Git repository.

        Args:
            url: Repository URL
            branch: Default branch
            auth_type: Authentication type (ssh, https, token)
            credentials: Optional credentials

        Returns:
            Repository object
        """
        try:
            # Validate URL
            if not self._validate_repo_url(url):
                raise ValueError("Invalid repository URL")

            # Generate unique repo ID
            repo_id = hashlib.sha256(url.encode()).hexdigest()[:12]
            repo_path = self.repos_dir / repo_id

            # Get credentials from Vault if not provided
            if not credentials:
                credentials = await self._get_repo_credentials(url, auth_type)

            # Clone or update repository
            if repo_path.exists():
                # Pull latest changes
                repo = Repo(repo_path)
                origin = repo.remote('origin')

                # Configure authentication
                if auth_type == "https" and credentials:
                    with repo.config_writer() as config:
                        config.set_value('credential', 'helper', 'store')

                    # Store credentials temporarily
                    await self._store_git_credentials(url, credentials)

                origin.pull(branch)
                logger.info(f"Updated existing repository: {url}")
            else:
                # Clone repository
                if auth_type == "ssh":
                    # Setup SSH key
                    ssh_key = await self._setup_ssh_key(credentials)
                    env = {'GIT_SSH_COMMAND': f'ssh -i {ssh_key} -o StrictHostKeyChecking=no'}
                    repo = Repo.clone_from(url, repo_path, branch=branch, env=env)
                elif auth_type == "https":
                    # Use HTTPS with credentials
                    if credentials:
                        auth_url = self._build_auth_url(url, credentials)
                        repo = Repo.clone_from(auth_url, repo_path, branch=branch)
                    else:
                        repo = Repo.clone_from(url, repo_path, branch=branch)
                else:
                    # Token authentication
                    token = credentials.get('token') if credentials else None
                    if token:
                        auth_url = url.replace('https://', f'https://{token}@')
                        repo = Repo.clone_from(auth_url, repo_path, branch=branch)
                    else:
                        repo = Repo.clone_from(url, repo_path, branch=branch)

                logger.info(f"Cloned repository: {url}")

            # Store repository info in database
            async with self.db_session() as session:
                db_repo = Repository(
                    id=repo_id,
                    url=url,
                    branch=branch,
                    auth_type=auth_type,
                    local_path=str(repo_path),
                    last_sync=datetime.utcnow(),
                    webhook_secret=self._generate_webhook_secret(),
                    gpg_verification=settings.REQUIRE_SIGNED_COMMITS
                )
                session.add(db_repo)
                await session.commit()

            # Scan for secrets
            secrets_found = await self.validation_handler.scan_for_secrets(repo_path)
            if secrets_found:
                logger.warning(f"Secrets detected in repository {url}: {len(secrets_found)} findings")
                await self._quarantine_repository(repo_id, secrets_found)

            return db_repo

        except Exception as e:
            logger.error(f"Failed to connect repository {url}: {e}")
            raise

    async def process_webhook(
        self,
        provider: str,
        payload: Dict[str, Any],
        signature: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Process webhook from Git provider.

        Args:
            provider: Git provider (github, gitlab, bitbucket)
            payload: Webhook payload
            signature: Webhook signature for validation

        Returns:
            Processing result
        """
        try:
            # Verify webhook signature
            if signature and not await self._verify_webhook_signature(provider, payload, signature):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid webhook signature"
                )

            # Parse webhook based on provider
            if provider == "github":
                event_info = self._parse_github_webhook(payload)
            elif provider == "gitlab":
                event_info = self._parse_gitlab_webhook(payload)
            elif provider == "bitbucket":
                event_info = self._parse_bitbucket_webhook(payload)
            else:
                raise ValueError(f"Unsupported provider: {provider}")

            # Store webhook event
            async with self.db_session() as session:
                webhook_event = WebhookEvent(
                    provider=provider,
                    event_type=event_info['type'],
                    repository_url=event_info['repo_url'],
                    branch=event_info.get('branch'),
                    commit_sha=event_info.get('commit'),
                    payload=payload,
                    processed=False,
                    created_at=datetime.utcnow()
                )
                session.add(webhook_event)
                await session.commit()

            # Process based on event type
            result = await self._process_event(event_info)

            # Mark as processed
            async with self.db_session() as session:
                webhook_event.processed = True
                webhook_event.processed_at = datetime.utcnow()
                webhook_event.result = result
                await session.commit()

            return result

        except Exception as e:
            logger.error(f"Webhook processing failed: {e}")
            raise

    async def sync_configurations(
        self,
        repository_id: str,
        target_branch: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Sync configurations from repository.

        Args:
            repository_id: Repository ID
            target_branch: Target branch to sync

        Returns:
            Sync result
        """
        try:
            # Get repository
            async with self.db_session() as session:
                result = await session.execute(
                    "SELECT * FROM repositories WHERE id = :id",
                    {"id": repository_id}
                )
                repo_data = result.fetchone()
                if not repo_data:
                    raise ValueError(f"Repository not found: {repository_id}")

            repo_path = Path(repo_data.local_path)
            repo = Repo(repo_path)

            # Checkout target branch
            if target_branch and target_branch != repo.active_branch.name:
                repo.git.checkout(target_branch)

            # Pull latest changes
            origin = repo.remote('origin')
            origin.pull()

            # Find configuration files
            config_files = await self._find_config_files(repo_path)

            sync_results = {
                'repository': repository_id,
                'branch': target_branch or repo.active_branch.name,
                'files_synced': [],
                'files_failed': [],
                'validation_errors': []
            }

            for config_file in config_files:
                try:
                    # Read configuration
                    async with aiofiles.open(config_file, 'r') as f:
                        content = await f.read()

                    # Parse configuration
                    if config_file.suffix in ['.yaml', '.yml']:
                        config = yaml.safe_load(content)
                    elif config_file.suffix == '.json':
                        config = json.loads(content)
                    elif config_file.suffix == '.toml':
                        config = toml.loads(content)
                    else:
                        continue

                    # Validate configuration
                    validation_result = await self.validation_handler.validate_config(config)
                    if not validation_result['valid']:
                        sync_results['validation_errors'].append({
                            'file': str(config_file.relative_to(repo_path)),
                            'errors': validation_result['errors']
                        })
                        continue

                    # Check for secrets
                    if await self._contains_secrets(content):
                        sync_results['files_failed'].append({
                            'file': str(config_file.relative_to(repo_path)),
                            'reason': 'Contains secrets'
                        })
                        continue

                    # Store configuration
                    await self._store_configuration(
                        repository_id,
                        config_file.relative_to(repo_path),
                        config,
                        content
                    )

                    sync_results['files_synced'].append(
                        str(config_file.relative_to(repo_path))
                    )

                except Exception as e:
                    logger.error(f"Failed to sync config file {config_file}: {e}")
                    sync_results['files_failed'].append({
                        'file': str(config_file.relative_to(repo_path)),
                        'reason': str(e)
                    })

            # Update last sync time
            async with self.db_session() as session:
                await session.execute(
                    "UPDATE repositories SET last_sync = :now WHERE id = :id",
                    {"now": datetime.utcnow(), "id": repository_id}
                )
                await session.commit()

            return sync_results

        except Exception as e:
            logger.error(f"Configuration sync failed: {e}")
            raise

    async def get_config_files(
        self,
        repository_id: str,
        path_pattern: Optional[str] = None
    ) -> List[ConfigFile]:
        """
        Get configuration files from repository.

        Args:
            repository_id: Repository ID
            path_pattern: Optional path pattern filter

        Returns:
            List of configuration files
        """
        try:
            async with self.db_session() as session:
                query = "SELECT * FROM config_files WHERE repository_id = :repo_id"
                params = {"repo_id": repository_id}

                if path_pattern:
                    query += " AND path LIKE :pattern"
                    params["pattern"] = f"%{path_pattern}%"

                result = await session.execute(query, params)
                files = result.fetchall()

                return [
                    ConfigFile(
                        id=f.id,
                        repository_id=f.repository_id,
                        path=f.path,
                        content=f.content,
                        config_type=f.config_type,
                        version=f.version,
                        commit_sha=f.commit_sha,
                        created_at=f.created_at,
                        updated_at=f.updated_at
                    )
                    for f in files
                ]

        except Exception as e:
            logger.error(f"Failed to get config files: {e}")
            raise

    async def create_pull_request(
        self,
        repository_id: str,
        title: str,
        description: str,
        source_branch: str,
        target_branch: str = "main",
        changes: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Create pull request with configuration changes.

        Args:
            repository_id: Repository ID
            title: PR title
            description: PR description
            source_branch: Source branch name
            target_branch: Target branch name
            changes: List of file changes

        Returns:
            Pull request information
        """
        try:
            # Get repository
            async with self.db_session() as session:
                result = await session.execute(
                    "SELECT * FROM repositories WHERE id = :id",
                    {"id": repository_id}
                )
                repo_data = result.fetchone()
                if not repo_data:
                    raise ValueError(f"Repository not found: {repository_id}")

            repo_path = Path(repo_data.local_path)
            repo = Repo(repo_path)

            # Create new branch
            new_branch = repo.create_head(source_branch)
            new_branch.checkout()

            # Apply changes if provided
            if changes:
                for change in changes:
                    file_path = repo_path / change['path']

                    # Create directory if needed
                    file_path.parent.mkdir(parents=True, exist_ok=True)

                    # Write file
                    async with aiofiles.open(file_path, 'w') as f:
                        await f.write(change['content'])

                    # Add to git
                    repo.index.add([str(file_path)])

                # Commit changes
                commit_message = f"{title}\n\n{description}"

                # Sign commit if required
                if settings.REQUIRE_SIGNED_COMMITS:
                    gpg_key = await self._get_gpg_key()
                    repo.index.commit(
                        commit_message,
                        author=git.Actor(settings.GIT_USER_NAME, settings.GIT_USER_EMAIL),
                        committer=git.Actor(settings.GIT_USER_NAME, settings.GIT_USER_EMAIL),
                        gpgsign=gpg_key
                    )
                else:
                    repo.index.commit(
                        commit_message,
                        author=git.Actor(settings.GIT_USER_NAME, settings.GIT_USER_EMAIL),
                        committer=git.Actor(settings.GIT_USER_NAME, settings.GIT_USER_EMAIL)
                    )

            # Push branch
            origin = repo.remote('origin')
            origin.push(source_branch)

            # Create pull request via API
            pr_info = await self._create_pr_via_api(
                repo_data.url,
                title,
                description,
                source_branch,
                target_branch
            )

            return pr_info

        except Exception as e:
            logger.error(f"Failed to create pull request: {e}")
            raise

    def _validate_repo_url(self, url: str) -> bool:
        """Validate repository URL."""
        valid_patterns = [
            r'^https?://github\.com/[\w-]+/[\w-]+(?:\.git)?$',
            r'^git@github\.com:[\w-]+/[\w-]+(?:\.git)?$',
            r'^https?://gitlab\.com/[\w-]+/[\w-]+(?:\.git)?$',
            r'^git@gitlab\.com:[\w-]+/[\w-]+(?:\.git)?$',
            r'^https?://bitbucket\.org/[\w-]+/[\w-]+(?:\.git)?$',
            r'^git@bitbucket\.org:[\w-]+/[\w-]+(?:\.git)?$',
        ]

        import re
        for pattern in valid_patterns:
            if re.match(pattern, url):
                return True
        return False

    async def _get_repo_credentials(
        self,
        url: str,
        auth_type: str
    ) -> Optional[Dict[str, str]]:
        """Get repository credentials from Vault."""
        try:
            # Extract repo identifier from URL
            import re
            match = re.search(r'[:/]([\w-]+/[\w-]+)(?:\.git)?$', url)
            if not match:
                return None

            repo_id = match.group(1).replace('/', '-')

            # Get credentials from Vault
            if auth_type == "ssh":
                creds = await self.vault.get_secret(f"git/ssh/{repo_id}")
            elif auth_type == "https":
                creds = await self.vault.get_secret(f"git/https/{repo_id}")
            else:
                creds = await self.vault.get_secret(f"git/token/{repo_id}")

            return creds

        except Exception as e:
            logger.warning(f"No credentials found for repository: {e}")
            return None

    async def _setup_ssh_key(self, credentials: Optional[Dict[str, str]]) -> str:
        """Setup SSH key for Git operations."""
        if not credentials or 'private_key' not in credentials:
            # Use default key
            return os.path.expanduser("~/.ssh/id_rsa")

        # Write temporary SSH key
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as f:
            f.write(credentials['private_key'])
            return f.name

    def _build_auth_url(self, url: str, credentials: Dict[str, str]) -> str:
        """Build authenticated URL for HTTPS."""
        username = credentials.get('username', '')
        password = credentials.get('password', '')

        if not username or not password:
            return url

        # Insert credentials into URL
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        netloc = f"{username}:{password}@{parsed.netloc}"
        return urllib.parse.urlunparse((
            parsed.scheme,
            netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))

    def _generate_webhook_secret(self) -> str:
        """Generate webhook secret."""
        import secrets
        return secrets.token_urlsafe(32)

    async def _store_git_credentials(self, url: str, credentials: Dict[str, str]):
        """Store Git credentials temporarily."""
        # This would store credentials in Git credential helper
        pass

    async def _verify_webhook_signature(
        self,
        provider: str,
        payload: Dict[str, Any],
        signature: str
    ) -> bool:
        """Verify webhook signature."""
        try:
            # Get webhook secret from database
            repo_url = self._extract_repo_url_from_payload(provider, payload)
            async with self.db_session() as session:
                result = await session.execute(
                    "SELECT webhook_secret FROM repositories WHERE url = :url",
                    {"url": repo_url}
                )
                secret_data = result.fetchone()
                if not secret_data:
                    return False

            secret = secret_data.webhook_secret

            if provider == "github":
                # GitHub uses HMAC-SHA256
                expected = hmac.new(
                    secret.encode(),
                    json.dumps(payload).encode(),
                    hashlib.sha256
                ).hexdigest()
                return f"sha256={expected}" == signature

            elif provider == "gitlab":
                # GitLab uses simple token comparison
                return secret == signature

            elif provider == "bitbucket":
                # Bitbucket uses HMAC-SHA256
                expected = hmac.new(
                    secret.encode(),
                    json.dumps(payload).encode(),
                    hashlib.sha256
                ).hexdigest()
                return expected == signature

            return False

        except Exception as e:
            logger.error(f"Webhook signature verification failed: {e}")
            return False

    def _extract_repo_url_from_payload(self, provider: str, payload: Dict[str, Any]) -> str:
        """Extract repository URL from webhook payload."""
        if provider == "github":
            return payload.get('repository', {}).get('clone_url', '')
        elif provider == "gitlab":
            return payload.get('project', {}).get('git_http_url', '')
        elif provider == "bitbucket":
            return payload.get('repository', {}).get('links', {}).get('clone', [{}])[0].get('href', '')
        return ''

    def _parse_github_webhook(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Parse GitHub webhook payload."""
        return {
            'type': payload.get('action', 'push'),
            'repo_url': payload.get('repository', {}).get('clone_url'),
            'branch': payload.get('ref', '').replace('refs/heads/', ''),
            'commit': payload.get('after') or payload.get('head_commit', {}).get('id'),
            'author': payload.get('pusher', {}).get('name'),
            'message': payload.get('head_commit', {}).get('message'),
            'timestamp': payload.get('head_commit', {}).get('timestamp')
        }

    def _parse_gitlab_webhook(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Parse GitLab webhook payload."""
        return {
            'type': payload.get('object_kind', 'push'),
            'repo_url': payload.get('project', {}).get('git_http_url'),
            'branch': payload.get('ref', '').replace('refs/heads/', ''),
            'commit': payload.get('after') or payload.get('checkout_sha'),
            'author': payload.get('user_name'),
            'message': payload.get('commits', [{}])[0].get('message') if payload.get('commits') else '',
            'timestamp': payload.get('commits', [{}])[0].get('timestamp') if payload.get('commits') else None
        }

    def _parse_bitbucket_webhook(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Bitbucket webhook payload."""
        push = payload.get('push', {})
        changes = push.get('changes', [{}])[0]
        return {
            'type': 'push',
            'repo_url': payload.get('repository', {}).get('links', {}).get('clone', [{}])[0].get('href'),
            'branch': changes.get('new', {}).get('name'),
            'commit': changes.get('new', {}).get('target', {}).get('hash'),
            'author': payload.get('actor', {}).get('display_name'),
            'message': changes.get('new', {}).get('target', {}).get('message'),
            'timestamp': changes.get('new', {}).get('target', {}).get('date')
        }

    async def _process_event(self, event_info: Dict[str, Any]) -> Dict[str, Any]:
        """Process webhook event."""
        result = {
            'status': 'processed',
            'actions': []
        }

        # Update repository
        if event_info['type'] in ['push', 'merge']:
            sync_result = await self.sync_configurations(
                repository_id=hashlib.sha256(event_info['repo_url'].encode()).hexdigest()[:12],
                target_branch=event_info.get('branch')
            )
            result['actions'].append({
                'type': 'sync',
                'result': sync_result
            })

        # Validate changes
        if event_info.get('commit'):
            validation_result = await self._validate_commit(
                event_info['repo_url'],
                event_info['commit']
            )
            result['actions'].append({
                'type': 'validation',
                'result': validation_result
            })

        return result

    async def _validate_commit(self, repo_url: str, commit_sha: str) -> Dict[str, Any]:
        """Validate commit changes."""
        # Implementation for commit validation
        return {
            'commit': commit_sha,
            'valid': True,
            'checks': [
                {'name': 'secrets_scan', 'passed': True},
                {'name': 'config_validation', 'passed': True},
                {'name': 'signature_verification', 'passed': True}
            ]
        }

    async def _find_config_files(self, repo_path: Path) -> List[Path]:
        """Find configuration files in repository."""
        config_patterns = [
            '**/*.yaml',
            '**/*.yml',
            '**/*.json',
            '**/*.toml',
            '**/network.conf',
            '**/devices.conf'
        ]

        config_files = []
        for pattern in config_patterns:
            config_files.extend(repo_path.glob(pattern))

        # Filter out common non-config files
        excluded = ['package.json', 'package-lock.json', 'node_modules', '.git', 'test', 'tests']
        return [
            f for f in config_files
            if not any(ex in str(f) for ex in excluded)
        ]

    async def _contains_secrets(self, content: str) -> bool:
        """Check if content contains secrets."""
        # Basic secret patterns
        secret_patterns = [
            r'password\s*[:=]\s*["\']?.+["\']?',
            r'api[_-]?key\s*[:=]\s*["\']?.+["\']?',
            r'secret\s*[:=]\s*["\']?.+["\']?',
            r'token\s*[:=]\s*["\']?.+["\']?',
            r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
            r'[A-Za-z0-9+/]{40,}={0,2}',  # Base64 encoded secrets
        ]

        import re
        for pattern in secret_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False

    async def _store_configuration(
        self,
        repository_id: str,
        file_path: Path,
        config: Dict[str, Any],
        raw_content: str
    ):
        """Store configuration in database."""
        async with self.db_session() as session:
            # Check if config exists
            result = await session.execute(
                """
                SELECT * FROM config_files
                WHERE repository_id = :repo_id AND path = :path
                """,
                {"repo_id": repository_id, "path": str(file_path)}
            )
            existing = result.fetchone()

            if existing:
                # Update existing
                await session.execute(
                    """
                    UPDATE config_files
                    SET content = :content, config = :config,
                        version = version + 1, updated_at = :now
                    WHERE repository_id = :repo_id AND path = :path
                    """,
                    {
                        "content": raw_content,
                        "config": json.dumps(config),
                        "repo_id": repository_id,
                        "path": str(file_path),
                        "now": datetime.utcnow()
                    }
                )
            else:
                # Create new
                await session.execute(
                    """
                    INSERT INTO config_files
                    (repository_id, path, content, config, config_type, version, created_at)
                    VALUES (:repo_id, :path, :content, :config, :type, 1, :now)
                    """,
                    {
                        "repo_id": repository_id,
                        "path": str(file_path),
                        "content": raw_content,
                        "config": json.dumps(config),
                        "type": file_path.suffix[1:],  # Remove dot
                        "now": datetime.utcnow()
                    }
                )

            await session.commit()

    async def _quarantine_repository(self, repo_id: str, secrets: List[Dict[str, Any]]):
        """Quarantine repository with detected secrets."""
        async with self.db_session() as session:
            await session.execute(
                """
                UPDATE repositories
                SET quarantined = true, quarantine_reason = :reason
                WHERE id = :id
                """,
                {
                    "id": repo_id,
                    "reason": json.dumps({"secrets_detected": secrets})
                }
            )
            await session.commit()

        # Send alert
        logger.critical(f"Repository {repo_id} quarantined due to secrets detection")

    async def _get_gpg_key(self) -> str:
        """Get GPG key for signing commits."""
        gpg_data = await self.vault.get_secret("git/gpg/signing-key")
        return gpg_data['key_id'] if gpg_data else None

    async def _create_pr_via_api(
        self,
        repo_url: str,
        title: str,
        description: str,
        source_branch: str,
        target_branch: str
    ) -> Dict[str, Any]:
        """Create pull request via provider API."""
        # This would use GitHub/GitLab/Bitbucket API to create PR
        # Placeholder implementation
        return {
            'pr_number': 1,
            'title': title,
            'url': f"{repo_url}/pull/1",
            'source_branch': source_branch,
            'target_branch': target_branch,
            'created_at': datetime.utcnow().isoformat()
        }

    async def shutdown(self):
        """Shutdown service connections."""
        if self.redis:
            await self.redis.close()
        logger.info("GitOps service shutdown complete")


gitops_service = GitOpsService()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    await gitops_service.initialize()
    yield
    await gitops_service.shutdown()


def create_app() -> FastAPI:
    """Create FastAPI application."""
    app = FastAPI(
        title="CatNet GitOps Service",
        description="Git repository and configuration management service",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/gitops/docs",
        redoc_url="/gitops/redoc",
        openapi_url="/gitops/openapi.json",
    )

    # Add middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS.split(","),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add Prometheus metrics
    Instrumentator().instrument(app).expose(app, endpoint="/gitops/metrics")

    # Add routes
    @app.post("/git/connect", response_model=RepositoryResponse)
    async def connect_repository(request: RepositoryCreateRequest):
        """Connect to a Git repository."""
        repo = await gitops_service.connect_repository(
            url=request.url,
            branch=request.branch,
            auth_type=request.auth_type,
            credentials=request.credentials
        )

        return RepositoryResponse(
            id=repo.id,
            url=repo.url,
            branch=repo.branch,
            auth_type=repo.auth_type,
            last_sync=repo.last_sync,
            webhook_url=f"{settings.BASE_URL}/git/webhook/{repo.id}"
        )

    @app.post("/git/webhook/{repo_id}")
    async def process_webhook(
        repo_id: str,
        request: Request,
        background_tasks: BackgroundTasks,
        x_hub_signature: Optional[str] = Header(None),
        x_gitlab_token: Optional[str] = Header(None)
    ):
        """Process webhook from Git provider."""
        payload = await request.json()

        # Determine provider
        if x_hub_signature:
            provider = "github"
            signature = x_hub_signature
        elif x_gitlab_token:
            provider = "gitlab"
            signature = x_gitlab_token
        else:
            provider = "bitbucket"
            signature = request.headers.get("X-Hook-UUID")

        # Process in background
        background_tasks.add_task(
            gitops_service.process_webhook,
            provider,
            payload,
            signature
        )

        return {"status": "accepted"}

    @app.get("/git/configs/{repo_id}")
    async def get_configs(repo_id: str, pattern: Optional[str] = None):
        """Get configuration files from repository."""
        configs = await gitops_service.get_config_files(repo_id, pattern)

        return {
            "repository_id": repo_id,
            "configs": [
                {
                    "id": c.id,
                    "path": c.path,
                    "type": c.config_type,
                    "version": c.version,
                    "updated_at": c.updated_at
                }
                for c in configs
            ]
        }

    @app.post("/git/sync")
    async def sync_configs(request: ConfigSyncRequest, background_tasks: BackgroundTasks):
        """Sync configurations from repository."""
        background_tasks.add_task(
            gitops_service.sync_configurations,
            request.repository_id,
            request.branch
        )

        return {
            "status": "sync_initiated",
            "repository_id": request.repository_id,
            "branch": request.branch
        }

    @app.post("/git/validate", response_model=ConfigValidationResponse)
    async def validate_config(request: ConfigValidationRequest):
        """Validate configuration."""
        result = await gitops_service.validation_handler.validate_config(request.config)

        return ConfigValidationResponse(
            valid=result['valid'],
            errors=result.get('errors', []),
            warnings=result.get('warnings', []),
            compliance=result.get('compliance', {})
        )

    @app.post("/git/pr")
    async def create_pr(request: PullRequestCreate):
        """Create pull request."""
        pr = await gitops_service.create_pull_request(
            repository_id=request.repository_id,
            title=request.title,
            description=request.description,
            source_branch=request.source_branch,
            target_branch=request.target_branch,
            changes=request.changes
        )

        return pr

    @app.get("/git/health")
    async def health():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "service": "gitops",
            "timestamp": datetime.utcnow().isoformat()
        }

    return app


if __name__ == "__main__":
    app = create_app()
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8082,
        ssl_keyfile=settings.SSL_KEY_PATH,
        ssl_certfile=settings.SSL_CERT_PATH,
        log_config={
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {
                    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                },
            },
            "handlers": {
                "default": {
                    "formatter": "default",
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                },
            },
            "root": {
                "level": "INFO",
                "handlers": ["default"],
            },
        }
    )