"""
Git Repository Manager for CatNet GitOps

Handles Git repository operations:
- Clone, pull, push operations
- Branch management
- Commit verification
- GPG signature validation
"""

import os
import shutil
import tempfile
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import hashlib
import subprocess

from git import Repo, GitCommandError

# pygit2 is optional, use GitPython as fallback
try:
    import pygit2

    HAS_PYGIT2 = True
except ImportError:
    HAS_PYGIT2 = False


@dataclass
class GitRepository:
    """Represents a Git repository configuration"""

    id: str
    url: str
    branch: str = "main"
    local_path: Optional[str] = None
    ssh_key_path: Optional[str] = None
    gpg_verify: bool = True
    auto_sync: bool = True
    sync_interval: int = 300  # seconds
    last_commit: Optional[str] = None
    last_sync: Optional[datetime] = None


class GitManager:
    """
    Manages Git repository operations for GitOps
    """

    def __init__(
        self,
        workspace_dir: Optional[str] = None,
        max_repo_size: int = 100 * 1024 * 1024,  # 100MB
        allowed_hosts: Optional[List[str]] = None,
    ):
        """
        Initialize Git manager

        Args:
            workspace_dir: Directory for cloned repositories
            max_repo_size: Maximum allowed repository size in bytes
            allowed_hosts: List of allowed Git hosts
        """
        self.workspace_dir = workspace_dir or tempfile.mkdtemp(prefix="catnet_gitops_")
        self.max_repo_size = max_repo_size
        self.allowed_hosts = allowed_hosts or [
            "github.com",
            "gitlab.com",
            "bitbucket.org",
        ]
        self.repositories: Dict[str, GitRepository] = {}
        self.repo_locks: Dict[str, bool] = {}  # Simple locking mechanism

        # Ensure workspace exists
        Path(self.workspace_dir).mkdir(parents=True, exist_ok=True)

    def add_repository(
        self,
        url: str,
        branch: str = "main",
        ssh_key_path: Optional[str] = None,
        gpg_verify: bool = True,
    ) -> GitRepository:
        """
        Add a new repository to manage

        Args:
            url: Repository URL (HTTPS or SSH)
            branch: Branch to track
            ssh_key_path: Path to SSH key for authentication
            gpg_verify: Verify GPG signatures on commits

        Returns:
            GitRepository instance
        """
        # Validate URL
        if not self._validate_repository_url(url):
            raise ValueError(f"Invalid or unauthorized repository URL: {url}")

        # Generate repository ID
        repo_id = hashlib.sha256(f"{url}:{branch}".encode()).hexdigest()[:12]

        # Create local path
        local_path = os.path.join(self.workspace_dir, repo_id)

        repo = GitRepository(
            id=repo_id,
            url=url,
            branch=branch,
            local_path=local_path,
            ssh_key_path=ssh_key_path,
            gpg_verify=gpg_verify,
        )

        self.repositories[repo_id] = repo
        return repo

    def clone_repository(self, repo_id: str) -> Tuple[bool, Optional[str]]:
        """
        Clone a repository

        Args:
            repo_id: Repository identifier

        Returns:
            Tuple of (success, error_message)
        """
        if repo_id not in self.repositories:
            return False, f"Repository {repo_id} not found"

        repo_config = self.repositories[repo_id]

        # Check if already cloned
        if os.path.exists(repo_config.local_path):
            return True, None

        # Acquire lock
        if self.repo_locks.get(repo_id, False):
            return False, "Repository operation in progress"

        self.repo_locks[repo_id] = True

        try:
            # Setup SSH if needed
            env = self._setup_git_environment(repo_config)

            # Clone repository
            if repo_config.ssh_key_path:
                # Use pygit2 for SSH key authentication
                callbacks = pygit2.RemoteCallbacks(
                    credentials=self._ssh_key_credentials(repo_config.ssh_key_path)
                )
                pygit2.clone_repository(
                    repo_config.url,
                    repo_config.local_path,
                    checkout_branch=repo_config.branch,
                    callbacks=callbacks,
                )
            else:
                # Use GitPython for HTTPS
                Repo.clone_from(
                    repo_config.url,
                    repo_config.local_path,
                    branch=repo_config.branch,
                    env=env,
                )

            # Check repository size
            repo_size = self._get_directory_size(repo_config.local_path)
            if repo_size > self.max_repo_size:
                shutil.rmtree(repo_config.local_path)
                return (
                    False,
                    f"Repository exceeds size limit ({repo_size} > {self.max_repo_size})",
                )

            # Get latest commit
            repo = Repo(repo_config.local_path)
            repo_config.last_commit = repo.head.commit.hexsha
            repo_config.last_sync = datetime.utcnow()

            return True, None

        except Exception as e:
            # Clean up on failure
            if os.path.exists(repo_config.local_path):
                shutil.rmtree(repo_config.local_path)
            return False, str(e)

        finally:
            self.repo_locks[repo_id] = False

    def pull_repository(
        self, repo_id: str, force: bool = False
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Pull latest changes from repository

        Args:
            repo_id: Repository identifier
            force: Force pull even with local changes

        Returns:
            Tuple of (success, changes_dict)
        """
        if repo_id not in self.repositories:
            return False, {"error": f"Repository {repo_id} not found"}

        repo_config = self.repositories[repo_id]

        if not os.path.exists(repo_config.local_path):
            # Clone if not exists
            success, error = self.clone_repository(repo_id)
            if not success:
                return False, {"error": error}
            return True, {"cloned": True}

        # Acquire lock
        if self.repo_locks.get(repo_id, False):
            return False, {"error": "Repository operation in progress"}

        self.repo_locks[repo_id] = True

        try:
            repo = Repo(repo_config.local_path)
            origin = repo.remotes.origin

            # Check for local changes
            if repo.is_dirty() and not force:
                return False, {"error": "Repository has local changes"}

            # Fetch changes
            fetch_info = origin.fetch()

            # Get current commit
            old_commit = repo.head.commit.hexsha

            # Pull changes
            if force:
                repo.git.reset("--hard", f"origin/{repo_config.branch}")
            else:
                origin.pull(repo_config.branch)

            # Get new commit
            new_commit = repo.head.commit.hexsha

            # Verify GPG signatures if enabled
            if repo_config.gpg_verify and old_commit != new_commit:
                if not self._verify_commit_signature(repo, new_commit):
                    # Rollback to previous commit
                    repo.git.reset("--hard", old_commit)
                    return False, {"error": "GPG signature verification failed"}

            # Get changed files
            changed_files = []
            if old_commit != new_commit:
                diff = repo.git.diff(old_commit, new_commit, "--name-only")
                changed_files = diff.split("\n") if diff else []

            # Update repository info
            repo_config.last_commit = new_commit
            repo_config.last_sync = datetime.utcnow()

            return True, {
                "old_commit": old_commit,
                "new_commit": new_commit,
                "changed_files": changed_files,
                "fetch_info": [str(f) for f in fetch_info],
            }

        except GitCommandError as e:
            return False, {"error": f"Git error: {str(e)}"}
        except Exception as e:
            return False, {"error": str(e)}

        finally:
            self.repo_locks[repo_id] = False

    def get_file_content(
        self, repo_id: str, file_path: str, commit: Optional[str] = None
    ) -> Optional[str]:
        """
        Get content of a file from repository

        Args:
            repo_id: Repository identifier
            file_path: Relative path to file
            commit: Specific commit to read from (default: HEAD)

        Returns:
            File content or None
        """
        if repo_id not in self.repositories:
            return None

        repo_config = self.repositories[repo_id]

        if not os.path.exists(repo_config.local_path):
            return None

        try:
            repo = Repo(repo_config.local_path)

            if commit:
                # Get file from specific commit
                commit_obj = repo.commit(commit)
                try:
                    blob = commit_obj.tree / file_path
                    return blob.data_stream.read().decode("utf-8")
                except KeyError:
                    return None
            else:
                # Get file from working directory
                full_path = os.path.join(repo_config.local_path, file_path)
                if os.path.exists(full_path):
                    with open(full_path, "r") as f:
                        return f.read()
                return None

        except Exception:
            return None

    def list_files(
        self,
        repo_id: str,
        pattern: Optional[str] = None,
        directory: Optional[str] = None,
    ) -> List[str]:
        """
        List files in repository

        Args:
            repo_id: Repository identifier
            pattern: File pattern to match (e.g., "*.yaml")
            directory: Directory to list from

        Returns:
            List of file paths
        """
        if repo_id not in self.repositories:
            return []

        repo_config = self.repositories[repo_id]

        if not os.path.exists(repo_config.local_path):
            return []

        try:
            repo = Repo(repo_config.local_path)

            # Get all files from git
            if pattern:
                files = repo.git.ls_files(pattern).split("\n")
            elif directory:
                files = repo.git.ls_files(directory).split("\n")
            else:
                files = repo.git.ls_files().split("\n")

            return [f for f in files if f]  # Filter empty strings

        except Exception:
            return []

    def get_commit_history(
        self, repo_id: str, limit: int = 10, file_path: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get commit history

        Args:
            repo_id: Repository identifier
            limit: Maximum number of commits
            file_path: Get history for specific file

        Returns:
            List of commit information
        """
        if repo_id not in self.repositories:
            return []

        repo_config = self.repositories[repo_id]

        if not os.path.exists(repo_config.local_path):
            return []

        try:
            repo = Repo(repo_config.local_path)

            commits = []
            commit_iter = repo.iter_commits(
                repo_config.branch, max_count=limit, paths=file_path
            )

            for commit in commit_iter:
                commits.append(
                    {
                        "sha": commit.hexsha,
                        "author": str(commit.author),
                        "email": commit.author.email,
                        "message": commit.message.strip(),
                        "timestamp": commit.committed_datetime.isoformat(),
                        "files": list(commit.stats.files.keys()),
                    }
                )

            return commits

        except Exception:
            return []

    def create_branch(
        self, repo_id: str, branch_name: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Create a new branch

        Args:
            repo_id: Repository identifier
            branch_name: Name of the new branch

        Returns:
            Tuple of (success, error_message)
        """
        if repo_id not in self.repositories:
            return False, f"Repository {repo_id} not found"

        repo_config = self.repositories[repo_id]

        if not os.path.exists(repo_config.local_path):
            return False, "Repository not cloned"

        try:
            repo = Repo(repo_config.local_path)

            # Create new branch
            new_branch = repo.create_head(branch_name)
            new_branch.checkout()

            return True, None

        except Exception as e:
            return False, str(e)

    def _validate_repository_url(self, url: str) -> bool:
        """
        Validate repository URL

        Args:
            url: Repository URL

        Returns:
            Validation status
        """
        # Extract host from URL
        if url.startswith("git@"):
            # SSH URL
            host = url.split("@")[1].split(":")[0]
        elif url.startswith("https://") or url.startswith("http://"):
            # HTTPS URL
            from urllib.parse import urlparse

            parsed = urlparse(url)
            host = parsed.netloc
        else:
            return False

        # Check if host is allowed
        return any(allowed in host for allowed in self.allowed_hosts)

    def _setup_git_environment(self, repo_config: GitRepository) -> Dict[str, str]:
        """
        Setup Git environment variables

        Args:
            repo_config: Repository configuration

        Returns:
            Environment variables dict
        """
        env = os.environ.copy()

        if repo_config.ssh_key_path:
            # Setup SSH command with specific key
            ssh_cmd = f"ssh -i {repo_config.ssh_key_path} -o StrictHostKeyChecking=no"
            env["GIT_SSH_COMMAND"] = ssh_cmd

        return env

    def _ssh_key_credentials(self, ssh_key_path: str):
        """
        Create SSH key credentials callback for pygit2

        Args:
            ssh_key_path: Path to SSH private key

        Returns:
            Credentials callback
        """

        def credentials(url, username_from_url, allowed_types):
            if allowed_types & pygit2.credentials.GIT_CREDENTIAL_SSH_KEY:
                return pygit2.Keypair(
                    username_from_url, ssh_key_path + ".pub", ssh_key_path, ""
                )
            return None

        return credentials

    def _verify_commit_signature(self, repo: Repo, commit_sha: str) -> bool:
        """
        Verify GPG signature of a commit

        Args:
            repo: Git repository
            commit_sha: Commit SHA to verify

        Returns:
            Verification status
        """
        try:
            # Run git verify-commit
            result = subprocess.run(
                ["git", "verify-commit", commit_sha],
                cwd=repo.working_dir,
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _get_directory_size(self, path: str) -> int:
        """
        Get total size of a directory

        Args:
            path: Directory path

        Returns:
            Size in bytes
        """
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if os.path.exists(filepath):
                    total_size += os.path.getsize(filepath)
        return total_size

    def cleanup(self) -> None:
        """
        Clean up all cloned repositories
        """
        if os.path.exists(self.workspace_dir):
            shutil.rmtree(self.workspace_dir)
        self.repositories.clear()
        self.repo_locks.clear()
