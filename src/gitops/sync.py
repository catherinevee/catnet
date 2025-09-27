"""
Repository synchronization for GitOps integration.
Handles Git repository operations, synchronization, and state management.
"""

import asyncio
import hashlib
import shutil
import tempfile
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from datetime import datetime, timedelta
from enum import Enum
import git
from git import Repo, Remote, GitCommandError
import aiofiles

from src.core.exceptions import GitOpsError, SynchronizationError
from src.security.vault import VaultClient
from src.security.encryption import EncryptionManager
from src.security.audit import AuditLogger
from src.core.config import get_settings


class SyncStatus(Enum):
    """Repository synchronization status."""
    SYNCED = "synced"
    OUT_OF_SYNC = "out_of_sync"
    SYNCING = "syncing"
    ERROR = "error"
    QUARANTINED = "quarantined"


class SyncStrategy(Enum):
    """Repository synchronization strategy."""
    PULL_ONLY = "pull_only"
    PUSH_ONLY = "push_only"
    BIDIRECTIONAL = "bidirectional"
    MIRROR = "mirror"


class RepositorySynchronizer:
    """
    Manages Git repository synchronization for GitOps workflows.
    Handles cloning, pulling, pushing, and state management.
    """

    def __init__(self):
        """Initialize repository synchronizer."""
        self.settings = get_settings()
        self.vault = VaultClient()
        self.encryption = EncryptionManager()
        self.audit = AuditLogger()

        # Repository storage configuration
        self.repo_base_path = Path(self.settings.GITOPS_REPO_PATH)
        self.repo_base_path.mkdir(parents=True, exist_ok=True)

        # Cache for repository instances
        self._repo_cache = {}
        self._sync_locks = {}

    async def sync_repository(
        self,
        repo_config: Dict[str, Any],
        strategy: SyncStrategy = SyncStrategy.PULL_ONLY,
        force: bool = False
    ) -> Dict[str, Any]:
        """
        Synchronize repository with remote.

        Args:
            repo_config: Repository configuration
            strategy: Synchronization strategy
            force: Force synchronization even if up to date

        Returns:
            Synchronization result
        """
        repo_id = repo_config.get('id')
        repo_url = repo_config.get('url')
        repo_branch = repo_config.get('branch', 'main')

        # Acquire lock for this repository
        async with self._get_sync_lock(repo_id):
            try:
                # Log sync attempt
                await self.audit.log_event(
                    event_type="REPOSITORY_SYNC_START",
                    details={
                        'repository_id': repo_id,
                        'url': repo_url,
                        'strategy': strategy.value
                    }
                )

                # Get or create repository
                repo = await self._get_or_clone_repository(repo_config)

                # Check current status
                status = await self._check_repository_status(repo, repo_branch)

                if status == SyncStatus.SYNCED and not force:
                    return {
                        'status': SyncStatus.SYNCED.value,
                        'message': 'Repository already up to date',
                        'commit': repo.head.commit.hexsha,
                        'timestamp': datetime.utcnow().isoformat()
                    }

                # Perform synchronization based on strategy
                if strategy == SyncStrategy.PULL_ONLY:
                    result = await self._sync_pull_only(repo, repo_branch)
                elif strategy == SyncStrategy.PUSH_ONLY:
                    result = await self._sync_push_only(repo, repo_branch)
                elif strategy == SyncStrategy.BIDIRECTIONAL:
                    result = await self._sync_bidirectional(repo, repo_branch)
                elif strategy == SyncStrategy.MIRROR:
                    result = await self._sync_mirror(repo, repo_branch)
                else:
                    raise ValueError(f"Unknown sync strategy: {strategy}")

                # Update cache
                self._repo_cache[repo_id] = repo

                # Log successful sync
                await self.audit.log_event(
                    event_type="REPOSITORY_SYNC_SUCCESS",
                    details={
                        'repository_id': repo_id,
                        'strategy': strategy.value,
                        'result': result
                    }
                )

                return result

            except Exception as e:
                # Log sync failure
                await self.audit.log_event(
                    event_type="REPOSITORY_SYNC_FAILED",
                    details={
                        'repository_id': repo_id,
                        'error': str(e)
                    }
                )
                raise SynchronizationError(f"Repository sync failed: {e}")

    async def clone_repository(
        self,
        repo_config: Dict[str, Any]
    ) -> Repo:
        """
        Clone a Git repository.

        Args:
            repo_config: Repository configuration

        Returns:
            Cloned repository instance
        """
        repo_id = repo_config.get('id')
        repo_url = repo_config.get('url')
        repo_branch = repo_config.get('branch', 'main')
        repo_path = self.repo_base_path / str(repo_id)

        try:
            # Remove existing repository if present
            if repo_path.exists():
                shutil.rmtree(repo_path)

            # Setup authentication if needed
            clone_url = await self._prepare_authenticated_url(repo_url, repo_config)

            # Clone repository
            repo = Repo.clone_from(
                clone_url,
                repo_path,
                branch=repo_branch,
                depth=1 if repo_config.get('shallow', False) else None
            )

            # Configure repository
            await self._configure_repository(repo, repo_config)

            return repo

        except GitCommandError as e:
            raise GitOpsError(f"Failed to clone repository: {e}")

    async def pull_changes(
        self,
        repo: Repo,
        branch: str = "main",
        rebase: bool = False
    ) -> Dict[str, Any]:
        """
        Pull changes from remote repository.

        Args:
            repo: Repository instance
            branch: Branch to pull
            rebase: Use rebase instead of merge

        Returns:
            Pull result
        """
        try:
            # Fetch latest changes
            origin = repo.remotes.origin
            origin.fetch()

            # Get current and remote commits
            current_commit = repo.head.commit.hexsha
            remote_ref = f"origin/{branch}"

            # Check if update needed
            remote_commit = repo.commit(remote_ref).hexsha
            if current_commit == remote_commit:
                return {
                    'status': 'up_to_date',
                    'current_commit': current_commit
                }

            # Pull changes
            if rebase:
                repo.git.rebase(remote_ref)
            else:
                origin.pull(branch)

            new_commit = repo.head.commit.hexsha

            # Get changed files
            changed_files = self._get_changed_files(repo, current_commit, new_commit)

            return {
                'status': 'updated',
                'previous_commit': current_commit,
                'current_commit': new_commit,
                'changed_files': changed_files,
                'timestamp': datetime.utcnow().isoformat()
            }

        except GitCommandError as e:
            raise SynchronizationError(f"Failed to pull changes: {e}")

    async def push_changes(
        self,
        repo: Repo,
        branch: str = "main",
        message: str = None
    ) -> Dict[str, Any]:
        """
        Push changes to remote repository.

        Args:
            repo: Repository instance
            branch: Branch to push
            message: Commit message if there are uncommitted changes

        Returns:
            Push result
        """
        try:
            # Check for uncommitted changes
            if repo.is_dirty():
                if not message:
                    message = f"Auto-commit from CatNet at {datetime.utcnow().isoformat()}"

                # Stage all changes
                repo.git.add(all=True)

                # Commit changes
                repo.index.commit(message)

            # Push to remote
            origin = repo.remotes.origin
            push_info = origin.push(branch)

            return {
                'status': 'pushed',
                'branch': branch,
                'commit': repo.head.commit.hexsha,
                'message': message,
                'timestamp': datetime.utcnow().isoformat()
            }

        except GitCommandError as e:
            raise SynchronizationError(f"Failed to push changes: {e}")

    async def get_commit_history(
        self,
        repo: Repo,
        branch: str = "main",
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Get commit history for repository.

        Args:
            repo: Repository instance
            branch: Branch to get history from
            limit: Maximum number of commits to return

        Returns:
            List of commit information
        """
        commits = []

        try:
            for commit in repo.iter_commits(branch, max_count=limit):
                commits.append({
                    'hash': commit.hexsha,
                    'author': str(commit.author),
                    'email': commit.author.email,
                    'message': commit.message.strip(),
                    'timestamp': commit.committed_datetime.isoformat(),
                    'files_changed': len(commit.stats.files),
                    'insertions': commit.stats.total['insertions'],
                    'deletions': commit.stats.total['deletions']
                })

        except Exception as e:
            raise GitOpsError(f"Failed to get commit history: {e}")

        return commits

    async def get_diff(
        self,
        repo: Repo,
        from_commit: str = None,
        to_commit: str = "HEAD"
    ) -> Dict[str, Any]:
        """
        Get diff between commits.

        Args:
            repo: Repository instance
            from_commit: Starting commit (None for working directory)
            to_commit: Ending commit

        Returns:
            Diff information
        """
        try:
            if from_commit:
                diff = repo.git.diff(from_commit, to_commit, name_status=True)
            else:
                diff = repo.git.diff(to_commit, name_status=True)

            # Parse diff output
            changes = []
            for line in diff.split('\n'):
                if line:
                    parts = line.split('\t')
                    if len(parts) == 2:
                        status, filename = parts
                        changes.append({
                            'status': self._parse_git_status(status),
                            'filename': filename
                        })

            return {
                'from_commit': from_commit or 'working_directory',
                'to_commit': to_commit,
                'changes': changes,
                'total_changes': len(changes)
            }

        except Exception as e:
            raise GitOpsError(f"Failed to get diff: {e}")

    async def verify_repository_integrity(
        self,
        repo: Repo
    ) -> Dict[str, Any]:
        """
        Verify repository integrity and security.

        Args:
            repo: Repository instance

        Returns:
            Verification result
        """
        issues = []
        warnings = []

        try:
            # Check for unsigned commits
            unsigned_commits = await self._check_unsigned_commits(repo)
            if unsigned_commits:
                warnings.append(f"Found {len(unsigned_commits)} unsigned commits")

            # Check for large files
            large_files = await self._check_large_files(repo)
            if large_files:
                warnings.append(f"Found {len(large_files)} large files (>10MB)")

            # Check for sensitive files
            sensitive_files = await self._check_sensitive_files(repo)
            if sensitive_files:
                issues.append(f"Found {len(sensitive_files)} potentially sensitive files")

            # Verify repository configuration
            config_issues = await self._verify_repository_config(repo)
            issues.extend(config_issues)

            return {
                'status': 'failed' if issues else 'passed',
                'issues': issues,
                'warnings': warnings,
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }

    async def _get_or_clone_repository(
        self,
        repo_config: Dict[str, Any]
    ) -> Repo:
        """Get repository from cache or clone it."""
        repo_id = repo_config.get('id')
        repo_path = self.repo_base_path / str(repo_id)

        # Check cache first
        if repo_id in self._repo_cache:
            return self._repo_cache[repo_id]

        # Check if repository exists on disk
        if repo_path.exists():
            try:
                repo = Repo(repo_path)
                self._repo_cache[repo_id] = repo
                return repo
            except:
                # Repository corrupted, remove and re-clone
                shutil.rmtree(repo_path)

        # Clone repository
        return await self.clone_repository(repo_config)

    async def _check_repository_status(
        self,
        repo: Repo,
        branch: str
    ) -> SyncStatus:
        """Check repository synchronization status."""
        try:
            # Fetch latest from remote
            repo.remotes.origin.fetch()

            # Compare local and remote
            local_commit = repo.head.commit.hexsha
            remote_commit = repo.commit(f"origin/{branch}").hexsha

            if local_commit == remote_commit:
                return SyncStatus.SYNCED
            else:
                return SyncStatus.OUT_OF_SYNC

        except Exception:
            return SyncStatus.ERROR

    async def _sync_pull_only(
        self,
        repo: Repo,
        branch: str
    ) -> Dict[str, Any]:
        """Synchronize using pull-only strategy."""
        # Discard local changes
        repo.git.reset('--hard', f'origin/{branch}')

        # Pull latest changes
        result = await self.pull_changes(repo, branch)

        return {
            'status': SyncStatus.SYNCED.value,
            'strategy': 'pull_only',
            'commit': repo.head.commit.hexsha,
            'result': result
        }

    async def _sync_push_only(
        self,
        repo: Repo,
        branch: str
    ) -> Dict[str, Any]:
        """Synchronize using push-only strategy."""
        # Push local changes
        result = await self.push_changes(repo, branch)

        return {
            'status': SyncStatus.SYNCED.value,
            'strategy': 'push_only',
            'commit': repo.head.commit.hexsha,
            'result': result
        }

    async def _sync_bidirectional(
        self,
        repo: Repo,
        branch: str
    ) -> Dict[str, Any]:
        """Synchronize using bidirectional strategy."""
        # Pull first
        pull_result = await self.pull_changes(repo, branch, rebase=True)

        # Then push if there are local changes
        push_result = None
        if repo.is_dirty() or repo.head.commit != repo.remotes.origin.refs[branch].commit:
            push_result = await self.push_changes(repo, branch)

        return {
            'status': SyncStatus.SYNCED.value,
            'strategy': 'bidirectional',
            'commit': repo.head.commit.hexsha,
            'pull_result': pull_result,
            'push_result': push_result
        }

    async def _sync_mirror(
        self,
        repo: Repo,
        branch: str
    ) -> Dict[str, Any]:
        """Synchronize using mirror strategy."""
        # Force push to make remote match local exactly
        repo.remotes.origin.push(force=True, refspec=f'{branch}:{branch}')

        return {
            'status': SyncStatus.SYNCED.value,
            'strategy': 'mirror',
            'commit': repo.head.commit.hexsha,
            'message': 'Remote mirrored to match local'
        }

    async def _prepare_authenticated_url(
        self,
        url: str,
        repo_config: Dict[str, Any]
    ) -> str:
        """Prepare authenticated URL for cloning."""
        # Get credentials from Vault if configured
        if repo_config.get('credentials_vault_path'):
            credentials = await self.vault.get_secret(
                repo_config['credentials_vault_path']
            )

            if credentials:
                # Insert credentials into URL
                if url.startswith('https://'):
                    username = credentials.get('username')
                    password = credentials.get('password')
                    url = url.replace('https://', f'https://{username}:{password}@')

        return url

    async def _configure_repository(
        self,
        repo: Repo,
        repo_config: Dict[str, Any]
    ):
        """Configure repository settings."""
        with repo.config_writer() as config:
            # Set user information
            if repo_config.get('user_name'):
                config.set_value('user', 'name', repo_config['user_name'])
            if repo_config.get('user_email'):
                config.set_value('user', 'email', repo_config['user_email'])

            # Set GPG signing if configured
            if repo_config.get('gpg_sign'):
                config.set_value('commit', 'gpgsign', 'true')
                if repo_config.get('gpg_key'):
                    config.set_value('user', 'signingkey', repo_config['gpg_key'])

    def _get_changed_files(
        self,
        repo: Repo,
        from_commit: str,
        to_commit: str
    ) -> List[str]:
        """Get list of changed files between commits."""
        try:
            diff = repo.git.diff(from_commit, to_commit, name_only=True)
            return diff.split('\n') if diff else []
        except:
            return []

    def _parse_git_status(self, status: str) -> str:
        """Parse Git status code to human-readable format."""
        status_map = {
            'A': 'added',
            'M': 'modified',
            'D': 'deleted',
            'R': 'renamed',
            'C': 'copied',
            'U': 'updated'
        }
        return status_map.get(status[0], 'unknown')

    async def _check_unsigned_commits(self, repo: Repo) -> List[str]:
        """Check for unsigned commits."""
        unsigned = []
        try:
            # Check last 10 commits
            for commit in repo.iter_commits(max_count=10):
                # Check if commit is signed
                try:
                    repo.git.verify_commit(commit.hexsha)
                except:
                    unsigned.append(commit.hexsha)
        except:
            pass
        return unsigned

    async def _check_large_files(self, repo: Repo) -> List[str]:
        """Check for large files in repository."""
        large_files = []
        max_size = 10 * 1024 * 1024  # 10MB

        try:
            for item in repo.tree().traverse():
                if item.type == 'blob' and item.size > max_size:
                    large_files.append({
                        'path': item.path,
                        'size': item.size
                    })
        except:
            pass

        return large_files

    async def _check_sensitive_files(self, repo: Repo) -> List[str]:
        """Check for potentially sensitive files."""
        sensitive_patterns = [
            '*.key', '*.pem', '*.p12', '*.pfx',
            '.env', '.aws', '.ssh', 'credentials',
            'password*', 'secret*', '*.sqlite', '*.db'
        ]

        sensitive_files = []
        try:
            for pattern in sensitive_patterns:
                files = repo.git.ls_files(pattern).split('\n')
                sensitive_files.extend([f for f in files if f])
        except:
            pass

        return sensitive_files

    async def _verify_repository_config(self, repo: Repo) -> List[str]:
        """Verify repository configuration."""
        issues = []

        try:
            config = repo.config_reader()

            # Check for required configurations
            if not config.get_value('user', 'name', default=None):
                issues.append("User name not configured")
            if not config.get_value('user', 'email', default=None):
                issues.append("User email not configured")

        except:
            issues.append("Failed to read repository configuration")

        return issues

    def _get_sync_lock(self, repo_id: str):
        """Get or create async lock for repository."""
        if repo_id not in self._sync_locks:
            self._sync_locks[repo_id] = asyncio.Lock()
        return self._sync_locks[repo_id]


class RepositoryStateManager:
    """
    Manages repository state and metadata.
    Tracks synchronization history, conflicts, and health.
    """

    def __init__(self):
        """Initialize repository state manager."""
        self.audit = AuditLogger()
        self.state_file_name = '.catnet_state.json'

    async def save_state(
        self,
        repo_path: Path,
        state: Dict[str, Any]
    ):
        """Save repository state to file."""
        state_file = repo_path / self.state_file_name

        state_data = {
            'version': '1.0.0',
            'timestamp': datetime.utcnow().isoformat(),
            **state
        }

        try:
            async with aiofiles.open(state_file, 'w') as f:
                await f.write(json.dumps(state_data, indent=2))
        except Exception as e:
            raise GitOpsError(f"Failed to save repository state: {e}")

    async def load_state(self, repo_path: Path) -> Optional[Dict[str, Any]]:
        """Load repository state from file."""
        state_file = repo_path / self.state_file_name

        if not state_file.exists():
            return None

        try:
            async with aiofiles.open(state_file, 'r') as f:
                content = await f.read()
            return json.loads(content)
        except Exception:
            return None

    async def track_sync(
        self,
        repo_path: Path,
        sync_result: Dict[str, Any]
    ):
        """Track synchronization in state."""
        state = await self.load_state(repo_path) or {'sync_history': []}

        # Add to sync history
        state['sync_history'].append({
            'timestamp': datetime.utcnow().isoformat(),
            **sync_result
        })

        # Keep only last 100 sync records
        state['sync_history'] = state['sync_history'][-100:]

        # Update last sync info
        state['last_sync'] = sync_result
        state['last_sync_timestamp'] = datetime.utcnow().isoformat()

        await self.save_state(repo_path, state)


# Export main components
__all__ = [
    'RepositorySynchronizer',
    'RepositoryStateManager',
    'SyncStatus',
    'SyncStrategy'
]