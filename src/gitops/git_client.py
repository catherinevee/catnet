from typing import Optional, List, Dict, Any, Tuple
import os
import tempfile
import shutil
from datetime import datetime
import asyncio
import aiofiles
import git
from git import Repo, Remote
import pygit2
from pathlib import Path
import hashlib
import gnupg
from .models import GitRepository, GitCommit, GitDiff, GitCredentials, ConfigFile
from ..security.vault import VaultClient
import structlog
import re
import yaml
import json


logger = structlog.get_logger()


class SecureGitClient:
    def __init__(self, vault_client: Optional[VaultClient] = None):
        self.vault_client = vault_client or VaultClient()
        self.temp_dirs = []
        self.gpg = gnupg.GPG()
        self._credential_cache = {}

    async def clone_repository(
        self,
        repository: GitRepository,
        target_path: Optional[str] = None,
        depth: int = 1
    ) -> str:
        if not target_path:
            target_path = tempfile.mkdtemp(prefix="catnet_repo_")
            self.temp_dirs.append(target_path)

        try:
            credentials = await self._get_credentials(repository)
            clone_url = await self._build_authenticated_url(repository.url, credentials)

            env = os.environ.copy()
            env['GIT_SSL_NO_VERIFY'] = '0'

            if credentials and credentials.ssh_private_key:
                ssh_command = await self._setup_ssh_command(credentials)
                env['GIT_SSH_COMMAND'] = ssh_command

            await asyncio.get_event_loop().run_in_executor(
                None,
                self._clone_with_retry,
                clone_url,
                target_path,
                repository.branch,
                depth,
                env
            )

            if repository.gpg_verification_enabled:
                await self._verify_signatures(target_path, repository.allowed_signers)

            return target_path

        except Exception as e:
            logger.error(f"Failed to clone repository: {str(e)}")
            if target_path in self.temp_dirs:
                self.cleanup_temp_dir(target_path)
            raise

    def _clone_with_retry(
        self,
        url: str,
        target_path: str,
        branch: str,
        depth: int,
        env: dict,
        max_retries: int = 3
    ):
        for attempt in range(max_retries):
            try:
                repo = Repo.clone_from(
                    url,
                    target_path,
                    branch=branch,
                    depth=depth,
                    env=env
                )
                return repo
            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                logger.warning(f"Clone attempt {attempt + 1} failed, retrying...")
                time.sleep(2 ** attempt)

    async def pull_latest(
        self,
        repo_path: str,
        repository: GitRepository,
        force: bool = False
    ) -> List[GitCommit]:
        try:
            repo = Repo(repo_path)
            origin = repo.remotes.origin

            credentials = await self._get_credentials(repository)
            if credentials:
                await self._configure_remote_credentials(repo, credentials)

            old_head = repo.head.commit

            if force:
                origin.fetch(force=True)
                repo.git.reset('--hard', f'origin/{repository.branch}')
            else:
                origin.pull(repository.branch)

            new_head = repo.head.commit

            commits = []
            for commit in repo.iter_commits(f'{old_head.hexsha}..{new_head.hexsha}'):
                commits.append(await self._parse_commit(commit))

            if repository.gpg_verification_enabled:
                await self._verify_commit_signatures(repo, commits, repository.allowed_signers)

            return commits

        except Exception as e:
            logger.error(f"Failed to pull latest: {str(e)}")
            raise

    async def get_config_files(
        self,
        repo_path: str,
        patterns: Optional[List[str]] = None
    ) -> List[ConfigFile]:
        if not patterns:
            patterns = [
                "**/*.cfg",
                "**/*.conf",
                "**/*.yaml",
                "**/*.yml",
                "**/*.json",
                "**/Juniper*.txt",
                "**/Cisco*.txt",
                "**/configs/*"
            ]

        config_files = []
        repo = Repo(repo_path)
        current_commit = repo.head.commit

        for pattern in patterns:
            path = Path(repo_path)
            for file_path in path.glob(pattern):
                if file_path.is_file() and not self._is_ignored(file_path, repo):
                    relative_path = file_path.relative_to(repo_path)

                    async with aiofiles.open(file_path, 'r') as f:
                        content = await f.read()

                    config_file = ConfigFile(
                        repository_id=None,
                        file_path=str(relative_path),
                        content=content,
                        content_hash=hashlib.sha256(content.encode()).hexdigest(),
                        format=self._detect_format(file_path),
                        vendor=self._detect_vendor(content),
                        device_type=self._detect_device_type(content),
                        commit_hash=current_commit.hexsha,
                        commit_message=current_commit.message,
                        commit_author=current_commit.author.name,
                        committed_at=datetime.fromtimestamp(current_commit.committed_date)
                    )

                    config_files.append(config_file)

        return config_files

    async def scan_for_secrets(
        self,
        repo_path: str,
        commit_range: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        secrets = []
        patterns = [
            (r'(?i)(api[_\s-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', 'API Key'),
            (r'(?i)(secret|password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\'\n]{8,})["\']?', 'Password/Secret'),
            (r'(?i)aws[_\s-]?access[_\s-]?key[_\s-]?id\s*[:=]\s*["\']?([A-Z0-9]{20})["\']?', 'AWS Access Key'),
            (r'(?i)aws[_\s-]?secret[_\s-]?access[_\s-]?key\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?', 'AWS Secret Key'),
            (r'-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----', 'Private Key'),
            (r'(?i)bearer\s+[a-zA-Z0-9_\-\.=]+', 'Bearer Token'),
            (r'(?i)basic\s+[a-zA-Z0-9_\-\.=]+', 'Basic Auth'),
            (r'mongodb(\+srv)?://[^\s]+', 'MongoDB Connection String'),
            (r'postgres(ql)?://[^\s]+', 'PostgreSQL Connection String'),
            (r'mysql://[^\s]+', 'MySQL Connection String'),
            (r'redis://[^\s]+', 'Redis Connection String'),
            (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Access Token'),
            (r'ghs_[a-zA-Z0-9]{36}', 'GitHub OAuth Access Token'),
            (r'sk_live_[a-zA-Z0-9]{24,}', 'Stripe Live Key'),
            (r'xox[baprs]-[0-9a-zA-Z]{10,48}', 'Slack Token'),
        ]

        repo = Repo(repo_path)

        if commit_range:
            commits = list(repo.iter_commits(commit_range))
        else:
            commits = [repo.head.commit]

        for commit in commits:
            for diff_item in commit.diff(commit.parents[0] if commit.parents else None):
                if diff_item.b_blob and not diff_item.b_blob.path.endswith(('.pyc', '.exe', '.dll', '.so')):
                    try:
                        content = diff_item.b_blob.data_stream.read().decode('utf-8', errors='ignore')

                        for pattern, secret_type in patterns:
                            import re
                            matches = re.finditer(pattern, content, re.MULTILINE)
                            for match in matches:
                                secrets.append({
                                    'type': secret_type,
                                    'file': diff_item.b_blob.path,
                                    'commit': commit.hexsha,
                                    'line': content[:match.start()].count('\n') + 1,
                                    'match': match.group(0)[:50] + '...' if len(match.group(0)) > 50 else match.group(0),
                                    'severity': 'critical' if 'key' in secret_type.lower() or 'password' in secret_type.lower() else 'high'
                                })
                    except Exception as e:
                        logger.warning(f"Could not scan file {diff_item.b_blob.path}: {str(e)}")

        return secrets

    async def verify_commit_signature(
        self,
        repo_path: str,
        commit_hash: str,
        allowed_signers: List[str]
    ) -> Tuple[bool, Optional[str]]:
        try:
            repo = Repo(repo_path)
            commit = repo.commit(commit_hash)

            signature_info = repo.git.show(
                commit_hash,
                '--show-signature',
                '--no-patch'
            )

            if 'Good signature' in signature_info:
                for line in signature_info.split('\n'):
                    if 'using' in line:
                        signer = line.split('"')[1] if '"' in line else None
                        if signer and (not allowed_signers or signer in allowed_signers):
                            return True, signer
                return False, "Signer not in allowed list"
            else:
                return False, "Invalid or missing signature"

        except Exception as e:
            logger.error(f"Failed to verify signature: {str(e)}")
            return False, str(e)

    async def get_diff(
        self,
        repo_path: str,
        from_commit: str,
        to_commit: str = "HEAD"
    ) -> List[GitDiff]:
        repo = Repo(repo_path)
        diffs = []

        commit_from = repo.commit(from_commit)
        commit_to = repo.commit(to_commit)

        for diff_item in commit_from.diff(commit_to):
            diff = GitDiff(
                file_path=diff_item.b_path or diff_item.a_path,
                change_type=diff_item.change_type,
                additions=0,
                deletions=0,
                is_binary=diff_item.b_blob.is_binary if diff_item.b_blob else False
            )

            if not diff.is_binary:
                if diff_item.a_blob:
                    diff.old_content = diff_item.a_blob.data_stream.read().decode('utf-8', errors='ignore')
                if diff_item.b_blob:
                    diff.new_content = diff_item.b_blob.data_stream.read().decode('utf-8', errors='ignore')

                if diff.old_content and diff.new_content:
                    old_lines = diff.old_content.count('\n')
                    new_lines = diff.new_content.count('\n')
                    diff.additions = max(0, new_lines - old_lines)
                    diff.deletions = max(0, old_lines - new_lines)

            diffs.append(diff)

        return diffs

    async def create_branch(
        self,
        repo_path: str,
        branch_name: str,
        from_branch: str = "main"
    ) -> bool:
        try:
            repo = Repo(repo_path)
            new_branch = repo.create_head(branch_name, repo.heads[from_branch])
            new_branch.checkout()
            return True
        except Exception as e:
            logger.error(f"Failed to create branch: {str(e)}")
            return False

    async def commit_changes(
        self,
        repo_path: str,
        message: str,
        author_name: str,
        author_email: str,
        sign: bool = True
    ) -> str:
        try:
            repo = Repo(repo_path)
            repo.git.add(A=True)

            if sign:
                commit = repo.index.commit(
                    message,
                    author=git.Actor(author_name, author_email),
                    gpgsign=True
                )
            else:
                commit = repo.index.commit(
                    message,
                    author=git.Actor(author_name, author_email)
                )

            return commit.hexsha

        except Exception as e:
            logger.error(f"Failed to commit changes: {str(e)}")
            raise

    async def push_changes(
        self,
        repo_path: str,
        repository: GitRepository,
        branch: Optional[str] = None,
        force: bool = False
    ) -> bool:
        try:
            repo = Repo(repo_path)
            credentials = await self._get_credentials(repository)

            if credentials:
                await self._configure_remote_credentials(repo, credentials)

            origin = repo.remotes.origin
            push_branch = branch or repository.branch

            if force:
                push_info = origin.push(push_branch, force=True)
            else:
                push_info = origin.push(push_branch)

            for info in push_info:
                if info.flags & info.ERROR:
                    logger.error(f"Push failed: {info.summary}")
                    return False

            return True

        except Exception as e:
            logger.error(f"Failed to push changes: {str(e)}")
            return False

    async def _get_credentials(self, repository: GitRepository) -> Optional[GitCredentials]:
        if repository.id in self._credential_cache:
            creds = self._credential_cache[repository.id]
            if not creds.is_expired():
                return creds

        if repository.access_token_ref:
            token = await self.vault_client.get_secret(repository.access_token_ref)
            creds = GitCredentials(
                name=f"{repository.name}_token",
                type="token",
                token=token
            )
        elif repository.ssh_key_id:
            ssh_key = await self.vault_client.get_secret(f"git/ssh/{repository.ssh_key_id}")
            creds = GitCredentials(
                name=f"{repository.name}_ssh",
                type="ssh",
                ssh_private_key=ssh_key
            )
        else:
            return None

        self._credential_cache[repository.id] = creds
        return creds

    async def _build_authenticated_url(self, url: str, credentials: Optional[GitCredentials]) -> str:
        if not credentials:
            return url

        if credentials.token:
            if 'github.com' in url:
                return url.replace('https://', f'https://{credentials.token}@')
            elif 'gitlab' in url:
                return url.replace('https://', f'https://oauth2:{credentials.token}@')
            elif 'bitbucket' in url:
                return url.replace('https://', f'https://x-token-auth:{credentials.token}@')

        return url

    async def _setup_ssh_command(self, credentials: GitCredentials) -> str:
        ssh_key_path = tempfile.mktemp(suffix='.key')

        async with aiofiles.open(ssh_key_path, 'w') as f:
            await f.write(credentials.ssh_private_key)

        os.chmod(ssh_key_path, 0o600)

        return f'ssh -i {ssh_key_path} -o StrictHostKeyChecking=no'

    async def _configure_remote_credentials(self, repo: Repo, credentials: GitCredentials):
        if credentials.token:
            with repo.config_writer() as config:
                config.set_value('credential', 'helper', 'store')
                config.set_value('http', 'extraheader', f'Authorization: Bearer {credentials.token}')

    async def _verify_signatures(self, repo_path: str, allowed_signers: List[str]):
        repo = Repo(repo_path)
        for commit in repo.iter_commits():
            valid, signer = await self.verify_commit_signature(repo_path, commit.hexsha, allowed_signers)
            if not valid:
                logger.warning(f"Commit {commit.hexsha} has invalid signature: {signer}")

    async def _verify_commit_signatures(self, repo: Repo, commits: List[GitCommit], allowed_signers: List[str]):
        for commit in commits:
            valid, signer = await self.verify_commit_signature(repo.working_dir, commit.hash, allowed_signers)
            commit.signed = valid
            commit.signature_valid = valid
            commit.signer = signer

    async def _parse_commit(self, commit) -> GitCommit:
        return GitCommit(
            hash=commit.hexsha,
            message=commit.message,
            author=commit.author.name,
            author_email=commit.author.email,
            timestamp=datetime.fromtimestamp(commit.committed_date),
            branch=commit.repo.active_branch.name,
            files_added=[d.b_path for d in commit.diff(commit.parents[0] if commit.parents else None) if d.change_type == 'A'],
            files_modified=[d.b_path for d in commit.diff(commit.parents[0] if commit.parents else None) if d.change_type == 'M'],
            files_deleted=[d.a_path for d in commit.diff(commit.parents[0] if commit.parents else None) if d.change_type == 'D']
        )

    def _is_ignored(self, file_path: Path, repo: Repo) -> bool:
        try:
            repo.git.check_ignore(str(file_path))
            return True
        except:
            return False

    def _detect_format(self, file_path: Path) -> str:
        suffix = file_path.suffix.lower()
        if suffix in ['.yaml', '.yml']:
            return 'yaml'
        elif suffix == '.json':
            return 'json'
        elif suffix in ['.cfg', '.conf']:
            return 'config'
        elif suffix == '.xml':
            return 'xml'
        else:
            return 'text'

    def _detect_vendor(self, content: str) -> Optional[str]:
        cisco_patterns = [
            r'hostname\s+\S+',
            r'interface\s+(GigabitEthernet|FastEthernet|Vlan)',
            r'router\s+(ospf|eigrp|bgp)',
            r'spanning-tree\s+mode'
        ]

        juniper_patterns = [
            r'set\s+system\s+host-name',
            r'set\s+interfaces\s+',
            r'set\s+protocols\s+',
            r'set\s+security\s+'
        ]

        for pattern in cisco_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return 'cisco'

        for pattern in juniper_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return 'juniper'

        return None

    def _detect_device_type(self, content: str) -> Optional[str]:
        if 'router' in content.lower():
            return 'router'
        elif 'switch' in content.lower() or 'vlan' in content.lower():
            return 'switch'
        elif 'firewall' in content.lower() or 'security' in content.lower():
            return 'firewall'
        elif 'load' in content.lower() and 'balanc' in content.lower():
            return 'loadbalancer'
        return None

    def cleanup_temp_dir(self, path: str):
        if path in self.temp_dirs:
            try:
                shutil.rmtree(path)
                self.temp_dirs.remove(path)
            except Exception as e:
                logger.warning(f"Failed to cleanup temp dir {path}: {str(e)}")

    def cleanup_all_temp_dirs(self):
        for path in self.temp_dirs[:]:
            self.cleanup_temp_dir(path)