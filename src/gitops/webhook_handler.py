from typing import Optional, Dict, Any, List
from datetime import datetime
import hmac
import hashlib
import json
import asyncio
from uuid import UUID
import aiohttp
import base64

from .models import WebhookPayload, WebhookEventType, GitProvider, GitRepository, SyncOperation
from .git_client import SecureGitClient
from ..core.config_parser import ConfigParser
from ..core.validation import ConfigValidator
from ..security.scanner import SecurityScanner
from ..security.vault import VaultClient
from ..db.database import get_db
from ..db.models import ConfigFile
import structlog
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession


logger = structlog.get_logger()


class WebhookHandler:
    def __init__(self,
                 git_client: SecureGitClient,
                 config_parser: ConfigParser,
                 config_validator: ConfigValidator,
                 security_scanner: SecurityScanner,
                 vault_client: VaultClient):

        self.git_client = git_client
        self.config_parser = config_parser
        self.config_validator = config_validator
        self.security_scanner = security_scanner
        self.vault = vault_client
        self.processing_queue = asyncio.Queue()
        self.processing_tasks = {}

    async def process_webhook(
        self,
        provider: GitProvider,
        headers: Dict[str, str],
        body: bytes,
        repository: GitRepository
    ) -> WebhookPayload:

        payload = await self._parse_webhook_payload(provider, headers, body)

        if not await self._verify_webhook_signature(provider, headers, body, repository.webhook_secret):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid webhook signature"
            )

        webhook_payload = WebhookPayload(
            repository_id=repository.id,
            event_type=await self._determine_event_type(provider, headers, payload),
            provider=provider,
            raw_payload=payload,
            signature=headers.get(self._get_signature_header(provider)),
            headers=headers,
            sender=await self._extract_sender(provider, payload),
            branch=await self._extract_branch(provider, payload),
            commit_hash=await self._extract_commit_hash(provider, payload),
            commit_message=await self._extract_commit_message(provider, payload),
            commit_author=await self._extract_commit_author(provider, payload),
            files_changed=await self._extract_changed_files(provider, payload)
        )

        await self.processing_queue.put(webhook_payload)

        task_id = webhook_payload.id
        task = asyncio.create_task(self._process_webhook_async(webhook_payload, repository))
        self.processing_tasks[task_id] = task

        return webhook_payload

    async def _process_webhook_async(
        self,
        payload: WebhookPayload,
        repository: GitRepository
    ):
        sync_operation = SyncOperation(
            repository_id=repository.id,
            trigger="webhook",
            triggered_by=None
        )

        try:
            sync_operation.start()

            if payload.event_type == WebhookEventType.PUSH:
                await self._handle_push_event(payload, repository, sync_operation)
            elif payload.event_type == WebhookEventType.PULL_REQUEST:
                await self._handle_pull_request_event(payload, repository, sync_operation)
            elif payload.event_type == WebhookEventType.TAG:
                await self._handle_tag_event(payload, repository, sync_operation)
            elif payload.event_type == WebhookEventType.RELEASE:
                await self._handle_release_event(payload, repository, sync_operation)

            sync_operation.complete(success=True)
            payload.processed = True
            payload.processed_at = datetime.utcnow()

        except Exception as e:
            logger.error(f"Failed to process webhook: {str(e)}")
            sync_operation.add_error(str(e))
            sync_operation.complete(success=False)
            payload.processing_error = str(e)

        finally:
            if payload.id in self.processing_tasks:
                del self.processing_tasks[payload.id]

    async def _handle_push_event(
        self,
        payload: WebhookPayload,
        repository: GitRepository,
        sync_operation: SyncOperation
    ):
        repo_path = None
        try:
            repo_path = await self.git_client.clone_repository(repository)

            commits = await self.git_client.pull_latest(repo_path, repository)
            sync_operation.commits_processed = len(commits)

            secrets = await self.git_client.scan_for_secrets(repo_path)
            if secrets:
                sync_operation.add_error(f"Found {len(secrets)} secrets in repository")
                await self._quarantine_repository(repository, secrets)
                return

            config_files = await self.git_client.get_config_files(repo_path, repository.path_filters)
            sync_operation.files_processed = len(config_files)

            for config_file in config_files:
                validation_result = await self.config_validator.validate(config_file)

                if not validation_result.is_valid:
                    sync_operation.warnings.extend(validation_result.errors)
                    config_file.validation_errors = validation_result.errors
                else:
                    config_file.validated = True

                await self._store_config_file(config_file, repository)
                sync_operation.configs_extracted += 1

            repository.last_sync = datetime.utcnow()
            repository.last_commit_hash = payload.commit_hash

        finally:
            if repo_path:
                self.git_client.cleanup_temp_dir(repo_path)

    async def _handle_pull_request_event(
        self,
        payload: WebhookPayload,
        repository: GitRepository,
        sync_operation: SyncOperation
    ):
        pr_data = payload.raw_payload.get('pull_request', {})

        if pr_data.get('state') == 'open' or pr_data.get('action') == 'opened':
            repo_path = None
            try:
                repo_path = await self.git_client.clone_repository(repository)

                base_branch = pr_data.get('base', {}).get('ref', 'main')
                head_branch = pr_data.get('head', {}).get('ref')

                if head_branch:
                    diffs = await self.git_client.get_diff(
                        repo_path,
                        base_branch,
                        head_branch
                    )

                    for diff in diffs:
                        if diff.new_content:
                            validation_result = await self.config_validator.validate_content(
                                diff.new_content,
                                diff.file_path
                            )

                            if not validation_result.is_valid:
                                await self._post_pr_comment(
                                    repository,
                                    pr_data.get('number'),
                                    f"Configuration validation failed for {diff.file_path}:\n"
                                    + "\n".join(validation_result.errors)
                                )
                                sync_operation.warnings.extend(validation_result.errors)

                    security_issues = await self.security_scanner.scan_pr(
                        repo_path,
                        base_branch,
                        head_branch
                    )

                    if security_issues:
                        await self._post_pr_comment(
                            repository,
                            pr_data.get('number'),
                            "Security issues found:\n" +
                            "\n".join([f"- {issue}" for issue in security_issues])
                        )
                        sync_operation.add_error("Security issues found in PR")

            finally:
                if repo_path:
                    self.git_client.cleanup_temp_dir(repo_path)

    async def _handle_tag_event(
        self,
        payload: WebhookPayload,
        repository: GitRepository,
        sync_operation: SyncOperation
    ):
        tag_name = payload.raw_payload.get('ref', '').replace('refs/tags/', '')

        if tag_name:
            repo_path = None
            try:
                repo_path = await self.git_client.clone_repository(repository)

                config_files = await self.git_client.get_config_files(repo_path)

                for config_file in config_files:
                    config_file.tags.append(tag_name)
                    config_file.metadata['tagged_at'] = datetime.utcnow().isoformat()
                    await self._store_config_file(config_file, repository)

                sync_operation.details['tag'] = tag_name
                sync_operation.configs_extracted = len(config_files)

            finally:
                if repo_path:
                    self.git_client.cleanup_temp_dir(repo_path)

    async def _handle_release_event(
        self,
        payload: WebhookPayload,
        repository: GitRepository,
        sync_operation: SyncOperation
    ):
        release_data = payload.raw_payload.get('release', {})

        if release_data.get('action') == 'published':
            release_tag = release_data.get('tag_name')
            release_name = release_data.get('name')

            repo_path = None
            try:
                repo_path = await self.git_client.clone_repository(repository)

                config_files = await self.git_client.get_config_files(repo_path)

                for config_file in config_files:
                    config_file.metadata['release'] = {
                        'tag': release_tag,
                        'name': release_name,
                        'published_at': release_data.get('published_at')
                    }

                    await self._create_deployment_from_release(
                        config_file,
                        repository,
                        release_tag
                    )

                sync_operation.details['release'] = release_name
                sync_operation.configs_extracted = len(config_files)

            finally:
                if repo_path:
                    self.git_client.cleanup_temp_dir(repo_path)

    async def _verify_webhook_signature(
        self,
        provider: GitProvider,
        headers: Dict[str, str],
        body: bytes,
        secret: Optional[str]
    ) -> bool:

        if not secret:
            logger.warning("No webhook secret configured")
            return False

        if provider == GitProvider.GITHUB:
            signature = headers.get('X-Hub-Signature-256', '')
            if not signature.startswith('sha256='):
                return False
            expected = 'sha256=' + hmac.new(
                secret.encode(),
                body,
                hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(signature, expected)

        elif provider == GitProvider.GITLAB:
            token = headers.get('X-Gitlab-Token', '')
            return token == secret

        elif provider == GitProvider.BITBUCKET:
            signature = headers.get('X-Hub-Signature', '')
            if not signature.startswith('sha256='):
                return False
            expected = 'sha256=' + hmac.new(
                secret.encode(),
                body,
                hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(signature, expected)

        elif provider == GitProvider.AZURE_DEVOPS:
            auth_header = headers.get('Authorization', '')
            if auth_header.startswith('Basic '):
                import base64
                decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
                username, password = decoded.split(':', 1)
                return password == secret

        return False

    async def _parse_webhook_payload(
        self,
        provider: GitProvider,
        headers: Dict[str, str],
        body: bytes
    ) -> Dict[str, Any]:

        try:
            return json.loads(body.decode('utf-8'))
        except json.JSONDecodeError:
            logger.error("Failed to parse webhook payload")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid JSON payload"
            )

    async def _determine_event_type(
        self,
        provider: GitProvider,
        headers: Dict[str, str],
        payload: Dict[str, Any]
    ) -> WebhookEventType:

        if provider == GitProvider.GITHUB:
            event = headers.get('X-GitHub-Event', '')
            if event == 'push':
                return WebhookEventType.PUSH
            elif event == 'pull_request':
                return WebhookEventType.PULL_REQUEST
            elif event == 'create' and payload.get('ref_type') == 'tag':
                return WebhookEventType.TAG
            elif event == 'release':
                return WebhookEventType.RELEASE

        elif provider == GitProvider.GITLAB:
            object_kind = payload.get('object_kind', '')
            if object_kind == 'push':
                return WebhookEventType.PUSH
            elif object_kind == 'merge_request':
                return WebhookEventType.PULL_REQUEST
            elif object_kind == 'tag_push':
                return WebhookEventType.TAG

        elif provider == GitProvider.BITBUCKET:
            event_key = headers.get('X-Event-Key', '')
            if 'repo:refs_changed' in event_key:
                return WebhookEventType.PUSH
            elif 'pullrequest' in event_key:
                return WebhookEventType.PULL_REQUEST

        elif provider == GitProvider.AZURE_DEVOPS:
            event_type = headers.get('X-VSS-EventType', '')
            if event_type == 'git.push':
                return WebhookEventType.PUSH
            elif event_type == 'git.pullrequest.created' or event_type == 'git.pullrequest.updated':
                return WebhookEventType.PULL_REQUEST

        return WebhookEventType.PUSH

    def _get_signature_header(self, provider: GitProvider) -> str:
        headers_map = {
            GitProvider.GITHUB: 'X-Hub-Signature-256',
            GitProvider.GITLAB: 'X-Gitlab-Token',
            GitProvider.BITBUCKET: 'X-Hub-Signature',
            GitProvider.AZURE_DEVOPS: 'Authorization'
        }
        return headers_map.get(provider, '')

    async def _extract_sender(self, provider: GitProvider, payload: Dict[str, Any]) -> Optional[str]:
        if provider == GitProvider.GITHUB:
            return payload.get('sender', {}).get('login')
        elif provider == GitProvider.GITLAB:
            return payload.get('user_username')
        elif provider == GitProvider.BITBUCKET:
            return payload.get('actor', {}).get('username')
        return None

    async def _extract_branch(self, provider: GitProvider, payload: Dict[str, Any]) -> Optional[str]:
        if provider == GitProvider.GITHUB:
            ref = payload.get('ref', '')
            return ref.replace('refs/heads/', '') if ref.startswith('refs/heads/') else None
        elif provider == GitProvider.GITLAB:
            return payload.get('ref', '').replace('refs/heads/', '')
        elif provider == GitProvider.BITBUCKET:
            changes = payload.get('changes', [])
            if changes:
                return changes[0].get('ref', {}).get('displayId')
        return None

    async def _extract_commit_hash(self, provider: GitProvider, payload: Dict[str, Any]) -> Optional[str]:
        if provider == GitProvider.GITHUB:
            return payload.get('after') or payload.get('head_commit', {}).get('id')
        elif provider == GitProvider.GITLAB:
            return payload.get('after') or payload.get('checkout_sha')
        elif provider == GitProvider.BITBUCKET:
            changes = payload.get('changes', [])
            if changes:
                return changes[0].get('toHash')
        return None

    async def _extract_commit_message(self, provider: GitProvider, payload: Dict[str, Any]) -> Optional[str]:
        if provider == GitProvider.GITHUB:
            return payload.get('head_commit', {}).get('message')
        elif provider == GitProvider.GITLAB:
            commits = payload.get('commits', [])
            if commits:
                return commits[-1].get('message')
        elif provider == GitProvider.BITBUCKET:
            changeset = payload.get('changeset')
            if changeset:
                return changeset.get('toCommit', {}).get('message')
        return None

    async def _extract_commit_author(self, provider: GitProvider, payload: Dict[str, Any]) -> Optional[str]:
        if provider == GitProvider.GITHUB:
            return payload.get('head_commit', {}).get('author', {}).get('name')
        elif provider == GitProvider.GITLAB:
            commits = payload.get('commits', [])
            if commits:
                return commits[-1].get('author', {}).get('name')
        elif provider == GitProvider.BITBUCKET:
            changeset = payload.get('changeset')
            if changeset:
                return changeset.get('toCommit', {}).get('author', {}).get('name')
        return None

    async def _extract_changed_files(self, provider: GitProvider, payload: Dict[str, Any]) -> List[str]:
        files = []

        if provider == GitProvider.GITHUB:
            commits = payload.get('commits', [])
            for commit in commits:
                files.extend(commit.get('added', []))
                files.extend(commit.get('modified', []))
                files.extend(commit.get('removed', []))

        elif provider == GitProvider.GITLAB:
            commits = payload.get('commits', [])
            for commit in commits:
                files.extend(commit.get('added', []))
                files.extend(commit.get('modified', []))
                files.extend(commit.get('removed', []))

        elif provider == GitProvider.BITBUCKET:
            changes = payload.get('changes', [])
            for change in changes:
                values = change.get('values', [])
                for value in values:
                    path = value.get('path', {})
                    if path:
                        files.append(path.get('toString', ''))

        return list(set(files))

    async def _quarantine_repository(self, repository: GitRepository, secrets: List[Dict[str, Any]]):
        repository.status = 'quarantined'
        repository.metadata['quarantine_reason'] = 'Secrets detected'
        repository.metadata['quarantine_details'] = secrets
        repository.metadata['quarantined_at'] = datetime.utcnow().isoformat()

        logger.critical(
            f"Repository {repository.name} quarantined due to secrets",
            repository_id=str(repository.id),
            secrets_count=len(secrets)
        )

    async def _store_config_file(self, config_file: ConfigFile, repository: GitRepository):
        """
        Store configuration file in database
        """
        try:
            async with get_db() as db:
                # Create or update config file record
                existing = await db.execute(
                    select(ConfigFile).where(
                        ConfigFile.repository_id == repository.id,
                        ConfigFile.file_path == config_file.file_path
                    )
                )
                existing_config = existing.scalar_one_or_none()

                if existing_config:
                    # Update existing
                    existing_config.content = config_file.content
                    existing_config.hash = config_file.hash
                    existing_config.validated = config_file.validated
                    existing_config.validation_errors = config_file.validation_errors
                    existing_config.metadata = config_file.metadata
                    existing_config.updated_at = datetime.utcnow()
                else:
                    # Create new
                    db.add(config_file)

                await db.commit()
                logger.info(
                    "Config file stored",
                    repository_id=str(repository.id),
                    file_path=config_file.file_path
                )

        except Exception as e:
            logger.error(
                "Failed to store config file",
                repository_id=str(repository.id),
                file_path=config_file.file_path,
                error=str(e)
            )

    async def _post_pr_comment(
        self,
        repository: GitRepository,
        pr_number: int,
        comment: str
    ) -> bool:
        """
        Post comment on pull request
        """
        try:
            if repository.provider == GitProvider.GITHUB:
                return await self._post_github_pr_comment(repository, pr_number, comment)
            elif repository.provider == GitProvider.GITLAB:
                return await self._post_gitlab_mr_comment(repository, pr_number, comment)
            elif repository.provider == GitProvider.BITBUCKET:
                return await self._post_bitbucket_pr_comment(repository, pr_number, comment)
            elif repository.provider == GitProvider.AZURE_DEVOPS:
                return await self._post_azure_pr_comment(repository, pr_number, comment)
            else:
                logger.warning(
                    "PR comments not supported for provider",
                    provider=repository.provider.value
                )
                return False

        except Exception as e:
            logger.error(
                "Failed to post PR comment",
                repository_id=str(repository.id),
                pr_number=pr_number,
                error=str(e)
            )
            return False

    async def _post_github_pr_comment(
        self,
        repository: GitRepository,
        pr_number: int,
        comment: str
    ) -> bool:
        """
        Post comment on GitHub pull request
        """
        try:
            # Get access token from Vault
            token_path = f"git/{repository.id}/token"
            token_data = await self.vault.get_secret(token_path)
            access_token = token_data.get("access_token")

            if not access_token:
                logger.error("No GitHub access token found")
                return False

            # Parse repository URL to get owner/repo
            repo_parts = repository.url.replace("https://github.com/", "").replace(".git", "").split("/")
            if len(repo_parts) != 2:
                logger.error("Invalid GitHub repository URL")
                return False

            owner, repo_name = repo_parts

            # Format comment with CatNet branding
            formatted_comment = f"""## 🐱 CatNet Configuration Analysis

{comment}

---
*This comment was automatically generated by CatNet - Network Configuration Deployment System*
*Analysis performed at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}*"""

            # GitHub API endpoint for PR comments
            api_url = f"https://api.github.com/repos/{owner}/{repo_name}/issues/{pr_number}/comments"

            headers = {
                "Authorization": f"token {access_token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "CatNet-Webhook-Handler"
            }

            payload = {
                "body": formatted_comment
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(api_url, json=payload, headers=headers) as response:
                    if response.status == 201:
                        comment_data = await response.json()
                        logger.info(
                            "GitHub PR comment posted successfully",
                            repository_id=str(repository.id),
                            pr_number=pr_number,
                            comment_id=comment_data.get("id")
                        )
                        return True
                    else:
                        error_data = await response.json()
                        logger.error(
                            "Failed to post GitHub PR comment",
                            repository_id=str(repository.id),
                            pr_number=pr_number,
                            status=response.status,
                            error=error_data.get("message", "Unknown error")
                        )
                        return False

        except Exception as e:
            logger.error(
                "Exception posting GitHub PR comment",
                repository_id=str(repository.id),
                pr_number=pr_number,
                error=str(e)
            )
            return False

    async def _post_gitlab_mr_comment(
        self,
        repository: GitRepository,
        pr_number: int,
        comment: str
    ) -> bool:
        """
        Post comment on GitLab merge request
        """
        try:
            # Get access token from Vault
            token_path = f"git/{repository.id}/token"
            token_data = await self.vault.get_secret(token_path)
            access_token = token_data.get("access_token")

            if not access_token:
                logger.error("No GitLab access token found")
                return False

            # Get project ID from repository metadata
            project_id = repository.metadata.get("project_id")
            if not project_id:
                # Try to extract from URL
                url_parts = repository.url.replace("https://gitlab.com/", "").replace(".git", "")
                project_id = url_parts.replace("/", "%2F")  # URL encode the slash

            # Format comment
            formatted_comment = f"""## 🐱 CatNet Configuration Analysis

{comment}

---
*This comment was automatically generated by CatNet*
*Analysis performed at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}*"""

            # GitLab API endpoint for MR notes
            api_url = f"https://gitlab.com/api/v4/projects/{project_id}/merge_requests/{pr_number}/notes"

            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }

            payload = {
                "body": formatted_comment
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(api_url, json=payload, headers=headers) as response:
                    if response.status == 201:
                        note_data = await response.json()
                        logger.info(
                            "GitLab MR comment posted successfully",
                            repository_id=str(repository.id),
                            mr_number=pr_number,
                            note_id=note_data.get("id")
                        )
                        return True
                    else:
                        error_data = await response.json()
                        logger.error(
                            "Failed to post GitLab MR comment",
                            repository_id=str(repository.id),
                            mr_number=pr_number,
                            status=response.status,
                            error=error_data.get("message", "Unknown error")
                        )
                        return False

        except Exception as e:
            logger.error(
                "Exception posting GitLab MR comment",
                repository_id=str(repository.id),
                mr_number=pr_number,
                error=str(e)
            )
            return False

    async def _post_bitbucket_pr_comment(
        self,
        repository: GitRepository,
        pr_number: int,
        comment: str
    ) -> bool:
        """
        Post comment on Bitbucket pull request
        """
        try:
            # Get access token from Vault
            token_path = f"git/{repository.id}/token"
            token_data = await self.vault.get_secret(token_path)
            access_token = token_data.get("access_token")

            if not access_token:
                logger.error("No Bitbucket access token found")
                return False

            # Parse repository URL
            url_parts = repository.url.replace("https://bitbucket.org/", "").replace(".git", "").split("/")
            if len(url_parts) != 2:
                logger.error("Invalid Bitbucket repository URL")
                return False

            workspace, repo_name = url_parts

            # Format comment
            formatted_comment = f"""## 🐱 CatNet Configuration Analysis

{comment}

---
*This comment was automatically generated by CatNet*
*Analysis performed at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}*"""

            # Bitbucket API endpoint for PR comments
            api_url = f"https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_name}/pullrequests/{pr_number}/comments"

            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }

            payload = {
                "content": {
                    "raw": formatted_comment
                }
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(api_url, json=payload, headers=headers) as response:
                    if response.status == 201:
                        comment_data = await response.json()
                        logger.info(
                            "Bitbucket PR comment posted successfully",
                            repository_id=str(repository.id),
                            pr_number=pr_number,
                            comment_id=comment_data.get("id")
                        )
                        return True
                    else:
                        error_data = await response.json()
                        logger.error(
                            "Failed to post Bitbucket PR comment",
                            repository_id=str(repository.id),
                            pr_number=pr_number,
                            status=response.status,
                            error=error_data.get("error", {}).get("message", "Unknown error")
                        )
                        return False

        except Exception as e:
            logger.error(
                "Exception posting Bitbucket PR comment",
                repository_id=str(repository.id),
                pr_number=pr_number,
                error=str(e)
            )
            return False

    async def _post_azure_pr_comment(
        self,
        repository: GitRepository,
        pr_number: int,
        comment: str
    ) -> bool:
        """
        Post comment on Azure DevOps pull request
        """
        try:
            # Get PAT token from Vault
            token_path = f"git/{repository.id}/token"
            token_data = await self.vault.get_secret(token_path)
            pat_token = token_data.get("pat_token")

            if not pat_token:
                logger.error("No Azure DevOps PAT token found")
                return False

            # Get organization and project from metadata
            organization = repository.metadata.get("organization")
            project = repository.metadata.get("project")
            repo_id = repository.metadata.get("repository_id")

            if not all([organization, project, repo_id]):
                logger.error("Missing Azure DevOps metadata")
                return False

            # Format comment
            formatted_comment = f"""## 🐱 CatNet Configuration Analysis

{comment}

---
*This comment was automatically generated by CatNet*
*Analysis performed at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}*"""

            # Azure DevOps API endpoint for PR comments
            api_url = f"https://dev.azure.com/{organization}/{project}/_apis/git/repositories/{repo_id}/pullRequests/{pr_number}/threads?api-version=6.0"

            # Basic auth with PAT
            auth = base64.b64encode(f":{pat_token}".encode()).decode()
            headers = {
                "Authorization": f"Basic {auth}",
                "Content-Type": "application/json"
            }

            payload = {
                "comments": [
                    {
                        "parentCommentId": 0,
                        "content": formatted_comment,
                        "commentType": "text"
                    }
                ],
                "status": "active"
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(api_url, json=payload, headers=headers) as response:
                    if response.status == 200:
                        thread_data = await response.json()
                        logger.info(
                            "Azure DevOps PR comment posted successfully",
                            repository_id=str(repository.id),
                            pr_number=pr_number,
                            thread_id=thread_data.get("id")
                        )
                        return True
                    else:
                        error_data = await response.json()
                        logger.error(
                            "Failed to post Azure DevOps PR comment",
                            repository_id=str(repository.id),
                            pr_number=pr_number,
                            status=response.status,
                            error=error_data.get("message", "Unknown error")
                        )
                        return False

        except Exception as e:
            logger.error(
                "Exception posting Azure DevOps PR comment",
                repository_id=str(repository.id),
                pr_number=pr_number,
                error=str(e)
            )
            return False

    async def _create_deployment_from_release(
        self,
        config_file: ConfigFile,
        repository: GitRepository,
        release_tag: str
    ):
        """
        Create deployment from release
        """
        try:
            from ..deployment.deployment_service import DeploymentService
            from ..db.models import Deployment, DeploymentStrategy

            async with get_db() as db:
                # Create deployment record
                deployment = Deployment(
                    name=f"Release {release_tag} - {repository.name}",
                    description=f"Auto-deployment from release {release_tag}",
                    repository_id=repository.id,
                    config_file_id=config_file.id,
                    strategy=DeploymentStrategy.ROLLING,
                    trigger="release",
                    triggered_by=None,
                    metadata={
                        "release_tag": release_tag,
                        "auto_created": True,
                        "created_from": "webhook_release_event"
                    }
                )

                db.add(deployment)
                await db.commit()

                logger.info(
                    "Deployment created from release",
                    repository_id=str(repository.id),
                    deployment_id=str(deployment.id),
                    release_tag=release_tag
                )

        except Exception as e:
            logger.error(
                "Failed to create deployment from release",
                repository_id=str(repository.id),
                release_tag=release_tag,
                error=str(e)
            )