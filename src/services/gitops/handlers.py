"""
Request handlers for GitOps service.
"""

import os
import json
import hashlib
import tempfile
import shutil
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from pathlib import Path
import asyncio
import re

import git
from git import Repo
import aiofiles
import yaml
import toml
from jsonschema import validate, ValidationError

from src.core.logging import get_logger
from src.core.config import get_settings
from src.security.vault import VaultClient
from src.security.encryption import EncryptionService

logger = get_logger(__name__)
settings = get_settings()


class RepositoryHandler:
    """Handles repository operations."""

    def __init__(self):
        self.vault = VaultClient()
        self.encryption = EncryptionService()
        self.repos_dir = Path(settings.GIT_REPOS_DIR or "/var/lib/catnet/repos")

    async def initialize(self):
        """Initialize handler."""
        self.repos_dir.mkdir(parents=True, exist_ok=True)

    async def clone_repository(
        self,
        url: str,
        branch: str = "main",
        auth: Optional[Dict[str, str]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> Repo:
        """
        Clone a Git repository.

        Args:
            url: Repository URL
            branch: Branch to clone
            auth: Authentication credentials
            options: Clone options

        Returns:
            Repository object
        """
        try:
            repo_id = hashlib.sha256(url.encode()).hexdigest()[:12]
            repo_path = self.repos_dir / repo_id

            # Setup authentication
            env = os.environ.copy()
            if auth:
                if auth.get('ssh_key'):
                    ssh_key_path = await self._write_ssh_key(auth['ssh_key'])
                    env['GIT_SSH_COMMAND'] = f'ssh -i {ssh_key_path} -o StrictHostKeyChecking=no'
                elif auth.get('token'):
                    url = self._inject_token(url, auth['token'])
                elif auth.get('username') and auth.get('password'):
                    url = self._inject_credentials(url, auth['username'], auth['password'])

            # Clone options
            clone_args = {
                'branch': branch,
                'env': env
            }

            if options:
                if options.get('depth'):
                    clone_args['depth'] = options['depth']
                if options.get('single_branch'):
                    clone_args['single-branch'] = True
                if options.get('no_checkout'):
                    clone_args['no-checkout'] = True

            # Clone repository
            if repo_path.exists():
                shutil.rmtree(repo_path)

            repo = Repo.clone_from(url, repo_path, **clone_args)

            logger.info(f"Successfully cloned repository: {url}")
            return repo

        except Exception as e:
            logger.error(f"Failed to clone repository {url}: {e}")
            raise

    async def pull_repository(
        self,
        repo_path: Path,
        branch: Optional[str] = None,
        auth: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Pull latest changes from repository.

        Args:
            repo_path: Local repository path
            branch: Branch to pull
            auth: Authentication credentials

        Returns:
            Pull result
        """
        try:
            repo = Repo(repo_path)

            # Switch branch if specified
            if branch and repo.active_branch.name != branch:
                repo.git.checkout(branch)

            # Setup authentication
            env = os.environ.copy()
            if auth and auth.get('ssh_key'):
                ssh_key_path = await self._write_ssh_key(auth['ssh_key'])
                env['GIT_SSH_COMMAND'] = f'ssh -i {ssh_key_path} -o StrictHostKeyChecking=no'

            # Get current commit
            old_commit = repo.head.commit.hexsha

            # Pull changes
            origin = repo.remote('origin')
            pull_info = origin.pull(env=env)

            # Get new commit
            new_commit = repo.head.commit.hexsha

            # Get changed files
            changed_files = []
            if old_commit != new_commit:
                diff = repo.git.diff(old_commit, new_commit, '--name-status')
                for line in diff.split('\n'):
                    if line:
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            changed_files.append({
                                'action': parts[0],
                                'path': parts[1]
                            })

            return {
                'success': True,
                'old_commit': old_commit,
                'new_commit': new_commit,
                'changed_files': changed_files,
                'pull_info': str(pull_info)
            }

        except Exception as e:
            logger.error(f"Failed to pull repository {repo_path}: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    async def push_changes(
        self,
        repo_path: Path,
        message: str,
        files: List[Dict[str, str]],
        branch: Optional[str] = None,
        auth: Optional[Dict[str, str]] = None,
        sign: bool = False
    ) -> Dict[str, Any]:
        """
        Push changes to repository.

        Args:
            repo_path: Local repository path
            message: Commit message
            files: Files to commit
            branch: Target branch
            auth: Authentication credentials
            sign: Sign commit

        Returns:
            Push result
        """
        try:
            repo = Repo(repo_path)

            # Switch branch if specified
            if branch and repo.active_branch.name != branch:
                if branch in [b.name for b in repo.branches]:
                    repo.git.checkout(branch)
                else:
                    repo.git.checkout('-b', branch)

            # Apply file changes
            for file_info in files:
                file_path = repo_path / file_info['path']
                file_path.parent.mkdir(parents=True, exist_ok=True)

                if file_info.get('content') is not None:
                    # Write file
                    async with aiofiles.open(file_path, 'w') as f:
                        await f.write(file_info['content'])
                    repo.index.add([file_info['path']])
                elif file_info.get('delete'):
                    # Delete file
                    if file_path.exists():
                        file_path.unlink()
                        repo.index.remove([file_info['path']])

            # Commit changes
            if repo.is_dirty():
                commit_args = {'message': message}

                if sign:
                    gpg_key = await self._get_gpg_key()
                    if gpg_key:
                        commit_args['gpgsign'] = True

                commit = repo.index.commit(**commit_args)

                # Setup authentication for push
                env = os.environ.copy()
                if auth and auth.get('ssh_key'):
                    ssh_key_path = await self._write_ssh_key(auth['ssh_key'])
                    env['GIT_SSH_COMMAND'] = f'ssh -i {ssh_key_path} -o StrictHostKeyChecking=no'

                # Push changes
                origin = repo.remote('origin')
                push_info = origin.push(env=env)

                return {
                    'success': True,
                    'commit': commit.hexsha,
                    'message': message,
                    'files_changed': len(files),
                    'push_info': str(push_info)
                }
            else:
                return {
                    'success': False,
                    'error': 'No changes to commit'
                }

        except Exception as e:
            logger.error(f"Failed to push changes to {repo_path}: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    async def create_branch(
        self,
        repo_path: Path,
        branch_name: str,
        from_branch: str = "main"
    ) -> bool:
        """Create new branch."""
        try:
            repo = Repo(repo_path)
            source = repo.branches[from_branch]
            repo.create_head(branch_name, source)
            logger.info(f"Created branch {branch_name} from {from_branch}")
            return True
        except Exception as e:
            logger.error(f"Failed to create branch {branch_name}: {e}")
            return False

    async def list_branches(self, repo_path: Path) -> List[str]:
        """List repository branches."""
        try:
            repo = Repo(repo_path)
            return [b.name for b in repo.branches]
        except Exception as e:
            logger.error(f"Failed to list branches: {e}")
            return []

    async def get_file_history(
        self,
        repo_path: Path,
        file_path: str,
        max_count: int = 10
    ) -> List[Dict[str, Any]]:
        """Get file history."""
        try:
            repo = Repo(repo_path)
            commits = list(repo.iter_commits(paths=file_path, max_count=max_count))

            history = []
            for commit in commits:
                history.append({
                    'sha': commit.hexsha,
                    'message': commit.message.strip(),
                    'author': commit.author.name,
                    'email': commit.author.email,
                    'date': datetime.fromtimestamp(commit.committed_date).isoformat()
                })

            return history

        except Exception as e:
            logger.error(f"Failed to get file history: {e}")
            return []

    async def _write_ssh_key(self, key_content: str) -> str:
        """Write SSH key to temporary file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as f:
            f.write(key_content)
            os.chmod(f.name, 0o600)
            return f.name

    async def _get_gpg_key(self) -> Optional[str]:
        """Get GPG key for signing."""
        try:
            gpg_data = await self.vault.get_secret("git/gpg/signing-key")
            return gpg_data.get('key_id') if gpg_data else None
        except Exception:
            return None

    def _inject_token(self, url: str, token: str) -> str:
        """Inject token into URL."""
        if url.startswith('https://'):
            return url.replace('https://', f'https://{token}@')
        return url

    def _inject_credentials(self, url: str, username: str, password: str) -> str:
        """Inject credentials into URL."""
        if url.startswith('https://'):
            return url.replace('https://', f'https://{username}:{password}@')
        return url


class WebhookHandler:
    """Handles webhook processing."""

    def __init__(self):
        self.vault = VaultClient()
        self.supported_events = {
            'github': ['push', 'pull_request', 'release', 'tag'],
            'gitlab': ['push', 'merge_request', 'tag_push', 'release'],
            'bitbucket': ['repo:push', 'pullrequest:created', 'pullrequest:updated']
        }

    async def initialize(self):
        """Initialize handler."""
        pass

    async def validate_webhook(
        self,
        provider: str,
        payload: Dict[str, Any],
        signature: Optional[str] = None,
        secret: Optional[str] = None
    ) -> bool:
        """
        Validate webhook authenticity.

        Args:
            provider: Git provider
            payload: Webhook payload
            signature: Webhook signature
            secret: Webhook secret

        Returns:
            True if valid
        """
        if not signature or not secret:
            return False

        try:
            import hmac

            if provider == "github":
                # GitHub uses HMAC-SHA256
                expected = hmac.new(
                    secret.encode(),
                    json.dumps(payload, separators=(',', ':')).encode(),
                    hashlib.sha256
                ).hexdigest()
                return f"sha256={expected}" == signature

            elif provider == "gitlab":
                # GitLab uses simple token
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
            logger.error(f"Webhook validation error: {e}")
            return False

    async def parse_event(
        self,
        provider: str,
        payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Parse webhook event.

        Args:
            provider: Git provider
            payload: Webhook payload

        Returns:
            Parsed event information
        """
        try:
            if provider == "github":
                return self._parse_github_event(payload)
            elif provider == "gitlab":
                return self._parse_gitlab_event(payload)
            elif provider == "bitbucket":
                return self._parse_bitbucket_event(payload)
            else:
                raise ValueError(f"Unsupported provider: {provider}")

        except Exception as e:
            logger.error(f"Event parsing error: {e}")
            raise

    def _parse_github_event(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Parse GitHub webhook event."""
        event = {
            'provider': 'github',
            'repository': payload.get('repository', {}).get('full_name'),
            'clone_url': payload.get('repository', {}).get('clone_url'),
            'event_type': self._get_github_event_type(payload)
        }

        if event['event_type'] == 'push':
            event.update({
                'branch': payload.get('ref', '').replace('refs/heads/', ''),
                'commit': payload.get('after'),
                'author': payload.get('pusher', {}).get('name'),
                'commits': [
                    {
                        'sha': c['id'],
                        'message': c['message'],
                        'author': c['author']['name']
                    }
                    for c in payload.get('commits', [])
                ]
            })
        elif event['event_type'] == 'pull_request':
            pr = payload.get('pull_request', {})
            event.update({
                'action': payload.get('action'),
                'pr_number': pr.get('number'),
                'pr_title': pr.get('title'),
                'source_branch': pr.get('head', {}).get('ref'),
                'target_branch': pr.get('base', {}).get('ref')
            })

        return event

    def _parse_gitlab_event(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Parse GitLab webhook event."""
        event = {
            'provider': 'gitlab',
            'repository': payload.get('project', {}).get('path_with_namespace'),
            'clone_url': payload.get('project', {}).get('git_http_url'),
            'event_type': payload.get('object_kind', 'push')
        }

        if event['event_type'] == 'push':
            event.update({
                'branch': payload.get('ref', '').replace('refs/heads/', ''),
                'commit': payload.get('after'),
                'author': payload.get('user_name'),
                'commits': [
                    {
                        'sha': c['id'],
                        'message': c['message'],
                        'author': c['author']['name']
                    }
                    for c in payload.get('commits', [])
                ]
            })
        elif event['event_type'] == 'merge_request':
            mr = payload.get('object_attributes', {})
            event.update({
                'action': mr.get('action'),
                'mr_number': mr.get('iid'),
                'mr_title': mr.get('title'),
                'source_branch': mr.get('source_branch'),
                'target_branch': mr.get('target_branch')
            })

        return event

    def _parse_bitbucket_event(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Bitbucket webhook event."""
        event = {
            'provider': 'bitbucket',
            'repository': payload.get('repository', {}).get('full_name'),
            'clone_url': self._get_bitbucket_clone_url(payload),
            'event_type': self._get_bitbucket_event_type(payload)
        }

        if 'push' in event['event_type']:
            changes = payload.get('push', {}).get('changes', [])
            if changes:
                change = changes[0]
                event.update({
                    'branch': change.get('new', {}).get('name'),
                    'commit': change.get('new', {}).get('target', {}).get('hash'),
                    'author': payload.get('actor', {}).get('display_name')
                })
        elif 'pullrequest' in event['event_type']:
            pr = payload.get('pullrequest', {})
            event.update({
                'pr_number': pr.get('id'),
                'pr_title': pr.get('title'),
                'source_branch': pr.get('source', {}).get('branch', {}).get('name'),
                'target_branch': pr.get('destination', {}).get('branch', {}).get('name')
            })

        return event

    def _get_github_event_type(self, payload: Dict[str, Any]) -> str:
        """Get GitHub event type."""
        if 'pull_request' in payload:
            return 'pull_request'
        elif 'release' in payload:
            return 'release'
        elif 'ref' in payload and payload.get('ref', '').startswith('refs/tags/'):
            return 'tag'
        else:
            return 'push'

    def _get_bitbucket_event_type(self, payload: Dict[str, Any]) -> str:
        """Get Bitbucket event type."""
        if 'pullrequest' in payload:
            return 'pullrequest'
        elif 'push' in payload:
            return 'push'
        else:
            return 'unknown'

    def _get_bitbucket_clone_url(self, payload: Dict[str, Any]) -> str:
        """Get Bitbucket clone URL."""
        links = payload.get('repository', {}).get('links', {}).get('clone', [])
        for link in links:
            if link.get('name') == 'https':
                return link.get('href', '')
        return ''


class ConfigHandler:
    """Handles configuration file operations."""

    def __init__(self):
        self.supported_types = {
            '.yaml': self._parse_yaml,
            '.yml': self._parse_yaml,
            '.json': self._parse_json,
            '.toml': self._parse_toml,
            '.ini': self._parse_ini,
            '.properties': self._parse_properties
        }

    async def initialize(self):
        """Initialize handler."""
        pass

    async def find_config_files(
        self,
        repo_path: Path,
        patterns: Optional[List[str]] = None
    ) -> List[Path]:
        """
        Find configuration files in repository.

        Args:
            repo_path: Repository path
            patterns: File patterns to search

        Returns:
            List of configuration files
        """
        if not patterns:
            patterns = [
                '**/*.yaml',
                '**/*.yml',
                '**/*.json',
                '**/*.toml',
                '**/network.conf',
                '**/devices.conf',
                '**/config.*'
            ]

        config_files = []
        for pattern in patterns:
            config_files.extend(repo_path.glob(pattern))

        # Filter out common non-config files
        excluded = [
            'package.json',
            'package-lock.json',
            'composer.json',
            'node_modules',
            '.git',
            'test',
            'tests',
            '__pycache__',
            '.pytest_cache'
        ]

        return [
            f for f in config_files
            if not any(ex in str(f) for ex in excluded)
        ]

    async def parse_config_file(
        self,
        file_path: Path
    ) -> Optional[Dict[str, Any]]:
        """
        Parse configuration file.

        Args:
            file_path: Configuration file path

        Returns:
            Parsed configuration
        """
        try:
            suffix = file_path.suffix.lower()
            if suffix in self.supported_types:
                async with aiofiles.open(file_path, 'r') as f:
                    content = await f.read()
                return self.supported_types[suffix](content)
            else:
                logger.warning(f"Unsupported config type: {suffix}")
                return None

        except Exception as e:
            logger.error(f"Failed to parse config file {file_path}: {e}")
            return None

    def _parse_yaml(self, content: str) -> Dict[str, Any]:
        """Parse YAML content."""
        return yaml.safe_load(content)

    def _parse_json(self, content: str) -> Dict[str, Any]:
        """Parse JSON content."""
        return json.loads(content)

    def _parse_toml(self, content: str) -> Dict[str, Any]:
        """Parse TOML content."""
        return toml.loads(content)

    def _parse_ini(self, content: str) -> Dict[str, Any]:
        """Parse INI content."""
        import configparser
        config = configparser.ConfigParser()
        config.read_string(content)
        return {section: dict(config.items(section)) for section in config.sections()}

    def _parse_properties(self, content: str) -> Dict[str, Any]:
        """Parse properties file."""
        props = {}
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    props[key.strip()] = value.strip()
        return props

    async def generate_config(
        self,
        template: Dict[str, Any],
        values: Dict[str, Any],
        format: str = "yaml"
    ) -> str:
        """
        Generate configuration from template.

        Args:
            template: Configuration template
            values: Values to fill in
            format: Output format

        Returns:
            Generated configuration
        """
        try:
            # Simple template substitution
            config = self._substitute_template(template, values)

            # Format output
            if format == "yaml":
                return yaml.dump(config, default_flow_style=False)
            elif format == "json":
                return json.dumps(config, indent=2)
            elif format == "toml":
                return toml.dumps(config)
            else:
                raise ValueError(f"Unsupported format: {format}")

        except Exception as e:
            logger.error(f"Failed to generate config: {e}")
            raise

    def _substitute_template(
        self,
        template: Any,
        values: Dict[str, Any]
    ) -> Any:
        """Substitute template variables."""
        if isinstance(template, dict):
            return {
                key: self._substitute_template(value, values)
                for key, value in template.items()
            }
        elif isinstance(template, list):
            return [
                self._substitute_template(item, values)
                for item in template
            ]
        elif isinstance(template, str):
            # Replace ${var} patterns
            for key, value in values.items():
                template = template.replace(f'${{{key}}}', str(value))
            return template
        else:
            return template


class SyncHandler:
    """Handles configuration synchronization."""

    def __init__(self):
        self.vault = VaultClient()
        self.config_handler = ConfigHandler()

    async def initialize(self):
        """Initialize handler."""
        pass

    async def sync_configs(
        self,
        repo_path: Path,
        target_path: Path,
        patterns: Optional[List[str]] = None,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Sync configurations from repository to target.

        Args:
            repo_path: Repository path
            target_path: Target path for configs
            patterns: File patterns to sync
            dry_run: Don't actually sync, just report

        Returns:
            Sync result
        """
        try:
            # Find config files
            config_files = await self.config_handler.find_config_files(repo_path, patterns)

            result = {
                'synced': [],
                'failed': [],
                'skipped': []
            }

            for config_file in config_files:
                try:
                    # Calculate relative path
                    rel_path = config_file.relative_to(repo_path)
                    target_file = target_path / rel_path

                    # Check if file needs syncing
                    if await self._needs_sync(config_file, target_file):
                        if not dry_run:
                            # Create target directory
                            target_file.parent.mkdir(parents=True, exist_ok=True)

                            # Copy file
                            shutil.copy2(config_file, target_file)

                        result['synced'].append(str(rel_path))
                    else:
                        result['skipped'].append(str(rel_path))

                except Exception as e:
                    logger.error(f"Failed to sync {config_file}: {e}")
                    result['failed'].append({
                        'file': str(rel_path),
                        'error': str(e)
                    })

            return result

        except Exception as e:
            logger.error(f"Sync failed: {e}")
            raise

    async def _needs_sync(self, source: Path, target: Path) -> bool:
        """Check if file needs syncing."""
        if not target.exists():
            return True

        # Compare modification times
        source_mtime = source.stat().st_mtime
        target_mtime = target.stat().st_mtime

        if source_mtime > target_mtime:
            return True

        # Compare content hash
        source_hash = await self._file_hash(source)
        target_hash = await self._file_hash(target)

        return source_hash != target_hash

    async def _file_hash(self, file_path: Path) -> str:
        """Calculate file hash."""
        hash_obj = hashlib.sha256()
        async with aiofiles.open(file_path, 'rb') as f:
            while True:
                chunk = await f.read(8192)
                if not chunk:
                    break
                hash_obj.update(chunk)
        return hash_obj.hexdigest()

    async def detect_drift(
        self,
        repo_configs: List[Dict[str, Any]],
        deployed_configs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Detect configuration drift.

        Args:
            repo_configs: Configurations from repository
            deployed_configs: Currently deployed configurations

        Returns:
            List of drifted configurations
        """
        drifts = []

        for repo_config in repo_configs:
            config_id = repo_config.get('id') or repo_config.get('name')

            # Find corresponding deployed config
            deployed = next(
                (c for c in deployed_configs if c.get('id') == config_id or c.get('name') == config_id),
                None
            )

            if not deployed:
                drifts.append({
                    'config': config_id,
                    'type': 'missing',
                    'message': 'Configuration not deployed'
                })
            elif repo_config != deployed:
                # Find differences
                diffs = self._find_differences(repo_config, deployed)
                if diffs:
                    drifts.append({
                        'config': config_id,
                        'type': 'modified',
                        'differences': diffs
                    })

        # Check for extra deployed configs
        repo_ids = [c.get('id') or c.get('name') for c in repo_configs]
        for deployed in deployed_configs:
            deployed_id = deployed.get('id') or deployed.get('name')
            if deployed_id not in repo_ids:
                drifts.append({
                    'config': deployed_id,
                    'type': 'extra',
                    'message': 'Configuration not in repository'
                })

        return drifts

    def _find_differences(
        self,
        dict1: Dict[str, Any],
        dict2: Dict[str, Any],
        path: str = ""
    ) -> List[Dict[str, Any]]:
        """Find differences between two dictionaries."""
        differences = []

        # Check for changed/removed keys
        for key in dict1:
            current_path = f"{path}.{key}" if path else key

            if key not in dict2:
                differences.append({
                    'path': current_path,
                    'type': 'removed',
                    'expected': dict1[key],
                    'actual': None
                })
            elif dict1[key] != dict2[key]:
                if isinstance(dict1[key], dict) and isinstance(dict2[key], dict):
                    differences.extend(
                        self._find_differences(dict1[key], dict2[key], current_path)
                    )
                else:
                    differences.append({
                        'path': current_path,
                        'type': 'changed',
                        'expected': dict1[key],
                        'actual': dict2[key]
                    })

        # Check for added keys
        for key in dict2:
            if key not in dict1:
                current_path = f"{path}.{key}" if path else key
                differences.append({
                    'path': current_path,
                    'type': 'added',
                    'expected': None,
                    'actual': dict2[key]
                })

        return differences


class ValidationHandler:
    """Handles configuration validation."""

    def __init__(self):
        self.secret_patterns = [
            re.compile(r'password\s*[:=]\s*["\']?[^\s"\']+', re.IGNORECASE),
            re.compile(r'api[_-]?key\s*[:=]\s*["\']?[^\s"\']+', re.IGNORECASE),
            re.compile(r'secret\s*[:=]\s*["\']?[^\s"\']+', re.IGNORECASE),
            re.compile(r'token\s*[:=]\s*["\']?[^\s"\']+', re.IGNORECASE),
            re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'),
            re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'),  # Base64
        ]

    async def initialize(self):
        """Initialize handler."""
        pass

    async def validate_config(
        self,
        config: Dict[str, Any],
        schema: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Validate configuration.

        Args:
            config: Configuration to validate
            schema: Optional JSON schema

        Returns:
            Validation result
        """
        result = {
            'valid': True,
            'errors': [],
            'warnings': []
        }

        # Schema validation
        if schema:
            try:
                validate(config, schema)
            except ValidationError as e:
                result['valid'] = False
                result['errors'].append(f"Schema validation: {e.message}")

        # Business rules validation
        business_errors = await self._validate_business_rules(config)
        if business_errors:
            result['valid'] = False
            result['errors'].extend(business_errors)

        # Security validation
        security_issues = await self._validate_security(config)
        if security_issues:
            result['warnings'].extend(security_issues)

        # Compliance validation
        compliance = await self._validate_compliance(config)
        result['compliance'] = compliance

        return result

    async def _validate_business_rules(
        self,
        config: Dict[str, Any]
    ) -> List[str]:
        """Validate business rules."""
        errors = []

        # Example business rules
        if config.get('max_retries', 0) > 10:
            errors.append("max_retries cannot exceed 10")

        if config.get('timeout', 0) < 1:
            errors.append("timeout must be at least 1 second")

        # Network-specific rules
        if 'network' in config:
            network = config['network']
            if network.get('mtu', 1500) > 9000:
                errors.append("MTU cannot exceed 9000")

        return errors

    async def _validate_security(
        self,
        config: Dict[str, Any]
    ) -> List[str]:
        """Validate security aspects."""
        issues = []

        # Check for weak protocols
        if config.get('protocol') in ['telnet', 'http', 'ftp']:
            issues.append(f"Insecure protocol: {config['protocol']}")

        # Check for default credentials
        if config.get('username') in ['admin', 'root', 'user']:
            issues.append("Default username detected")

        # Check for weak encryption
        if config.get('encryption') in ['des', 'rc4']:
            issues.append(f"Weak encryption: {config['encryption']}")

        return issues

    async def _validate_compliance(
        self,
        config: Dict[str, Any]
    ) -> Dict[str, bool]:
        """Validate compliance requirements."""
        compliance = {
            'encryption_required': config.get('encryption') is not None,
            'audit_logging': config.get('audit_log', False),
            'mfa_enabled': config.get('mfa', False),
            'secure_protocols': config.get('protocol') not in ['telnet', 'http', 'ftp']
        }
        return compliance

    async def scan_for_secrets(
        self,
        path: Path
    ) -> List[Dict[str, Any]]:
        """
        Scan path for secrets.

        Args:
            path: Path to scan

        Returns:
            List of detected secrets
        """
        secrets = []

        # Scan files
        for file_path in path.rglob('*'):
            if file_path.is_file() and not self._should_skip(file_path):
                try:
                    async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = await f.read()
                        file_secrets = await self._scan_content(content, file_path)
                        secrets.extend(file_secrets)
                except Exception as e:
                    logger.warning(f"Failed to scan {file_path}: {e}")

        return secrets

    async def _scan_content(
        self,
        content: str,
        file_path: Path
    ) -> List[Dict[str, Any]]:
        """Scan content for secrets."""
        secrets = []

        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern in self.secret_patterns:
                matches = pattern.finditer(line)
                for match in matches:
                    secrets.append({
                        'file': str(file_path),
                        'line': line_num,
                        'type': self._identify_secret_type(match.group()),
                        'match': match.group()[:50] + '...' if len(match.group()) > 50 else match.group()
                    })

        return secrets

    def _identify_secret_type(self, secret: str) -> str:
        """Identify type of secret."""
        lower = secret.lower()
        if 'password' in lower:
            return 'password'
        elif 'api' in lower and 'key' in lower:
            return 'api_key'
        elif 'token' in lower:
            return 'token'
        elif 'BEGIN' in secret and 'PRIVATE KEY' in secret:
            return 'private_key'
        elif 'secret' in lower:
            return 'secret'
        else:
            return 'unknown'

    def _should_skip(self, file_path: Path) -> bool:
        """Check if file should be skipped."""
        skip_dirs = ['.git', '__pycache__', 'node_modules', '.venv', 'venv']
        skip_extensions = ['.pyc', '.pyo', '.so', '.dll', '.exe']

        # Check directory
        for skip_dir in skip_dirs:
            if skip_dir in str(file_path):
                return True

        # Check extension
        if file_path.suffix in skip_extensions:
            return True

        # Check if binary
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                if b'\0' in chunk:
                    return True
        except:
            pass

        return False