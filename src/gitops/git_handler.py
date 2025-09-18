import os
import tempfile
import shutil
from typing import Dict, Any, List, Optional
from datetime import datetime
from git import Repo
import git
from pathlib import Path
import yaml
import json
import asyncio
import hashlib
from ..security.vault import VaultClient
from ..security.encryption import EncryptionManager
from ..core.logging import get_logger

logger = get_logger(__name__)


class GitHandler:
    def __init__(self, vault_client: Optional[VaultClient] = None):
        self.vault = vault_client or VaultClient()
        self.encryption = EncryptionManager()
        self.temp_dirs = []

    async def clone_repository(
        self,
        repo_url: str,
        branch: str = "main",
        ssh_key_ref: Optional[str] = None,
    ) -> str:
        temp_dir = tempfile.mkdtemp(prefix="catnet_repo_")
        self.temp_dirs.append(temp_dir)

        try:
            if ssh_key_ref:
                # Get SSH key from vault
                ssh_key = await self.vault.get_secret(ssh_key_ref)
                ssh_key_path = os.path.join(temp_dir, "ssh_key")

                with open(ssh_key_path, "w") as f:
                    f.write(ssh_key.get("private_key"))
                os.chmod(ssh_key_path, 0o600)

                # Configure git to use SSH key
                ssh_command = (
                    f"ssh -i {ssh_key_path} -o StrictHostKeyChecking=no"
                )
                repo = Repo.clone_from(
                    repo_url,
                    temp_dir,
                    branch=branch,
                    env={"GIT_SSH_COMMAND": ssh_command},
                )
            else:
                repo = Repo.clone_from(repo_url, temp_dir, branch=branch)

            # Log repository information
            logger.info(f"Repository cloned successfully to {temp_dir}")
            logger.debug(f"Current branch: {repo.active_branch}")
            logger.debug(f"Remote URL: {repo.remotes.origin.url}")

            return temp_dir

        except Exception as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise Exception(f"Failed to clone repository: {str(e)}")

    async def pull_latest(
        self, repo_path: str, branch: str = "main"
    ) -> Dict[str, Any]:
        try:
            repo = Repo(repo_path)
            origin = repo.remotes.origin

            # Fetch latest changes
            origin.fetch()

            # Get current commit
            current_commit = repo.head.commit.hexsha

            # Pull latest changes
            origin.pull(branch)

            # Get new commit
            new_commit = repo.head.commit.hexsha

            # Get changed files
            changed_files = []
            if current_commit != new_commit:
                diff = repo.git.diff(current_commit, new_commit, "--name-only")
                changed_files = diff.split("\n") if diff else []

            return {
                "previous_commit": current_commit,
                "current_commit": new_commit,
                "changed_files": changed_files,
                "updated": current_commit != new_commit,
            }

        except Exception as e:
            raise Exception(f"Failed to pull latest changes: {str(e)}")

    async def get_configs(
        self, repo_path: str, config_path: str = "configs/"
    ) -> List[Dict[str, Any]]:
        configs = []
        config_dir = Path(repo_path) / config_path

        if not config_dir.exists():
            return configs

        for file_path in config_dir.rglob("*"):
            if file_path.is_file() and file_path.suffix in [
                ".yaml",
                ".yml",
                ".json",
            ]:
                config = await self.parse_config_file(str(file_path))
                if config:
                    configs.append(
                        {
                            "file": str(file_path.relative_to(repo_path)),
                            "config": config,
                            "hash": self.calculate_file_hash(str(file_path)),
                        }
                    )

        return configs

    async def parse_config_file(
        self, file_path: str
    ) -> Optional[Dict[str, Any]]:
        try:
            with open(file_path, "r") as f:
                content = f.read()

            if file_path.endswith((".yaml", ".yml")):
                return yaml.safe_load(content)
            elif file_path.endswith(".json"):
                return json.loads(content)

        except Exception as e:
            print(f"Failed to parse config file {file_path}: {str(e)}")
            return None

    def calculate_file_hash(self, file_path: str) -> str:
        with open(file_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    async def verify_commit_signature(
        self, repo_path: str, commit_sha: str
    ) -> bool:
        try:
            repo = Repo(repo_path)
            commit = repo.commit(commit_sha)

            # Verify commit exists and log details
            logger.debug(f"Verifying signature for commit: {commit.hexsha}")
            logger.debug(f"Commit message: {commit.message.strip()}")
            logger.debug(f"Commit author: {commit.author.name}")

            # Check if commit is signed
            signature = repo.git.show(
                commit_sha, "--show-signature", "--no-patch"
            )

            # Look for GPG signature verification
            if "gpg:" in signature.lower():
                return "Good signature" in signature

            return False

        except Exception:
            return False

    async def scan_for_secrets(self, repo_path: str) -> List[Dict[str, Any]]:
        secrets_found = []
        patterns = [
            r"(?i)(api[_\-\s]?key|apikey)[\"']?\s*[:=]\s*[\"']?[\w\-]+",
            r"(?i)(secret|password|passwd|pwd)[\"']?\s*[:=]\s*[\"']?[\w\-]+",
            r"(?i)(token)[\"']?\s*[:=]\s*[\"']?[\w\-]+",
            r"(?i)bearer\s+[\w\-\.]+",
            r"(?i)aws_?access_?key_?id[\"']?\s*[:=]\s*[\"']?[\w]+",
            r"(?i)aws_?secret_?access_?key[\"']?\s*[:=]\s*[\"']?[\w]+",
            r"-----BEGIN RSA PRIVATE KEY-----",
            r"-----BEGIN OPENSSH PRIVATE KEY-----",
        ]

        import re

        for root, dirs, files in os.walk(repo_path):
            # Skip .git directory
            if ".git" in root:
                continue

            for file in files:
                file_path = os.path.join(root, file)

                # Skip binary files
                if file.endswith((".pyc", ".so", ".dll", ".exe", ".bin")):
                    continue

                try:
                    with open(
                        file_path, "r", encoding="utf-8", errors="ignore"
                    ) as f:
                        content = f.read()

                    for pattern in patterns:
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            line_num = content[: match.start()].count("\n") + 1
                            secrets_found.append(
                                {
                                    "file": file_path.replace(repo_path, ""),
                                    "line": line_num,
                                    "pattern": pattern[
                                        :30
                                    ],  # Truncate pattern for display
                                    "match": match.group()[
                                        :50
                                    ],  # Truncate match for security
                                }
                            )

                except Exception:
                    continue

        return secrets_found

    async def get_commit_info(
        self, repo_path: str, commit_sha: str
    ) -> Dict[str, Any]:
        try:
            repo = Repo(repo_path)
            commit = repo.commit(commit_sha)

            return {
                "sha": commit.hexsha,
                "author": {
                    "name": commit.author.name,
                    "email": commit.author.email,
                },
                "committer": {
                    "name": commit.committer.name,
                    "email": commit.committer.email,
                },
                "message": commit.message,
                "timestamp": commit.committed_datetime.isoformat(),
                "files_changed": len(commit.stats.files),
                "signed": await self.verify_commit_signature(
                    repo_path, commit_sha
                ),
            }

        except Exception as e:
            raise Exception(f"Failed to get commit info: {str(e)}")

    async def create_deployment_manifest(
        self, configs: List[Dict[str, Any]], metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        manifest = {
            "version": "1.0",
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": metadata,
            "configs": [],
            "validation": {"passed": True, "errors": [], "warnings": []},
        }

        for config in configs:
            # Calculate hash for each config
            config_hash = hashlib.sha256(
                json.dumps(config, sort_keys=True).encode()
            ).hexdigest()

            manifest["configs"].append(
                {
                    "file": config.get("file"),
                    "hash": config_hash,
                    "devices": config.get("devices", []),
                    "vendor": config.get("vendor"),
                    "type": config.get("type", "configuration"),
                }
            )

        # Sign the manifest
        manifest_json = json.dumps(manifest, sort_keys=True)
        manifest["signature"] = self.encryption.calculate_hash(
            manifest_json.encode()
        )

        return manifest

    def cleanup(self):
        for temp_dir in self.temp_dirs:
            shutil.rmtree(temp_dir, ignore_errors=True)
        self.temp_dirs.clear()

    def __del__(self):
        self.cleanup()
