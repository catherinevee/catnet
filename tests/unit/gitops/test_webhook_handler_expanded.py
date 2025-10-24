"""
Expanded unit tests for GitOps Webhook Handler
Comprehensive tests for webhook processing, signature verification, and Git event handling
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
import hmac
import hashlib
import json
import base64
from uuid import uuid4
from datetime import datetime

from src.gitops.webhook_handler import WebhookHandler
from src.gitops.models import WebhookPayload, WebhookEventType, GitProvider, GitRepository, SyncOperation
from fastapi import HTTPException


@pytest.fixture
def mock_git_client():
    """Mock Git client."""
    client = AsyncMock()
    client.clone_repository = AsyncMock(return_value="/tmp/repo_path")
    client.pull_latest = AsyncMock(return_value=["commit1", "commit2"])
    client.scan_for_secrets = AsyncMock(return_value=[])
    client.get_config_files = AsyncMock(return_value=[])
    client.get_diff = AsyncMock(return_value=[])
    client.cleanup_temp_dir = Mock()
    return client


@pytest.fixture
def mock_config_parser():
    """Mock config parser."""
    return AsyncMock()


@pytest.fixture
def mock_config_validator():
    """Mock config validator."""
    validator = AsyncMock()
    validator.validate = AsyncMock(return_value=Mock(is_valid=True, errors=[]))
    validator.validate_content = AsyncMock(return_value=Mock(is_valid=True, errors=[]))
    return validator


@pytest.fixture
def mock_security_scanner():
    """Mock security scanner."""
    scanner = AsyncMock()
    scanner.scan_pr = AsyncMock(return_value=[])
    return scanner


@pytest.fixture
def mock_vault_client():
    """Mock Vault client."""
    vault = AsyncMock()
    vault.get_secret = AsyncMock(return_value={"access_token": "test_token", "pat_token": "test_pat"})
    return vault


@pytest.fixture
def webhook_handler(mock_git_client, mock_config_parser, mock_config_validator,
                    mock_security_scanner, mock_vault_client):
    """Provide webhook handler instance."""
    return WebhookHandler(
        git_client=mock_git_client,
        config_parser=mock_config_parser,
        config_validator=mock_config_validator,
        security_scanner=mock_security_scanner,
        vault_client=mock_vault_client
    )


@pytest.fixture
def mock_repository():
    """Provide mock Git repository."""
    repo = Mock(spec=GitRepository)
    repo.id = uuid4()
    repo.name = "network-configs"
    repo.webhook_secret = "test_secret_key_123"
    repo.provider = GitProvider.GITHUB
    repo.url = "https://github.com/testorg/network-configs.git"
    repo.path_filters = ["*.conf", "*.cfg"]
    repo.metadata = {}
    repo.status = "active"
    return repo


class TestWebhookSignatureVerification:
    """Test webhook signature verification for all Git providers."""

    @pytest.mark.asyncio
    async def test_verify_github_signature_valid(self, webhook_handler):
        """Test valid GitHub webhook signature."""
        body = b'{"ref": "refs/heads/main"}'
        secret = "test_secret"

        signature = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        headers = {"X-Hub-Signature-256": signature}

        is_valid = await webhook_handler._verify_webhook_signature(
            provider=GitProvider.GITHUB,
            headers=headers,
            body=body,
            secret=secret
        )

        assert is_valid is True

    @pytest.mark.asyncio
    async def test_verify_github_signature_invalid(self, webhook_handler):
        """Test invalid GitHub webhook signature."""
        body = b'{"ref": "refs/heads/main"}'
        headers = {"X-Hub-Signature-256": "sha256=invalid_signature"}

        is_valid = await webhook_handler._verify_webhook_signature(
            provider=GitProvider.GITHUB,
            headers=headers,
            body=body,
            secret="test_secret"
        )

        assert is_valid is False

    @pytest.mark.asyncio
    async def test_verify_github_signature_no_prefix(self, webhook_handler):
        """Test GitHub signature without sha256= prefix."""
        body = b'{"ref": "refs/heads/main"}'
        headers = {"X-Hub-Signature-256": "invalid_no_prefix"}

        is_valid = await webhook_handler._verify_webhook_signature(
            provider=GitProvider.GITHUB,
            headers=headers,
            body=body,
            secret="test_secret"
        )

        assert is_valid is False

    @pytest.mark.asyncio
    async def test_verify_gitlab_signature_valid(self, webhook_handler):
        """Test valid GitLab webhook signature."""
        secret = "gitlab_secret_token"
        headers = {"X-Gitlab-Token": secret}

        is_valid = await webhook_handler._verify_webhook_signature(
            provider=GitProvider.GITLAB,
            headers=headers,
            body=b'{}',
            secret=secret
        )

        assert is_valid is True

    @pytest.mark.asyncio
    async def test_verify_gitlab_signature_invalid(self, webhook_handler):
        """Test invalid GitLab webhook signature."""
        headers = {"X-Gitlab-Token": "wrong_token"}

        is_valid = await webhook_handler._verify_webhook_signature(
            provider=GitProvider.GITLAB,
            headers=headers,
            body=b'{}',
            secret="gitlab_secret_token"
        )

        assert is_valid is False

    @pytest.mark.asyncio
    async def test_verify_bitbucket_signature_valid(self, webhook_handler):
        """Test valid Bitbucket webhook signature."""
        body = b'{"repository": {"name": "test"}}'
        secret = "bitbucket_secret"

        signature = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        headers = {"X-Hub-Signature": signature}

        is_valid = await webhook_handler._verify_webhook_signature(
            provider=GitProvider.BITBUCKET,
            headers=headers,
            body=body,
            secret=secret
        )

        assert is_valid is True

    @pytest.mark.asyncio
    async def test_verify_azure_devops_signature_valid(self, webhook_handler):
        """Test valid Azure DevOps webhook signature."""
        secret = "azure_secret"
        auth = base64.b64encode(f"username:{secret}".encode()).decode()
        headers = {"Authorization": f"Basic {auth}"}

        is_valid = await webhook_handler._verify_webhook_signature(
            provider=GitProvider.AZURE_DEVOPS,
            headers=headers,
            body=b'{}',
            secret=secret
        )

        assert is_valid is True

    @pytest.mark.asyncio
    async def test_verify_signature_no_secret(self, webhook_handler):
        """Test signature verification with no secret configured."""
        headers = {"X-Hub-Signature-256": "sha256=somehash"}

        is_valid = await webhook_handler._verify_webhook_signature(
            provider=GitProvider.GITHUB,
            headers=headers,
            body=b'{}',
            secret=None
        )

        assert is_valid is False


class TestWebhookPayloadParsing:
    """Test webhook payload parsing."""

    @pytest.mark.asyncio
    async def test_parse_valid_json_payload(self, webhook_handler):
        """Test parsing valid JSON payload."""
        payload = {"ref": "refs/heads/main", "after": "abc123"}
        body = json.dumps(payload).encode()

        parsed = await webhook_handler._parse_webhook_payload(
            provider=GitProvider.GITHUB,
            headers={},
            body=body
        )

        assert parsed == payload

    @pytest.mark.asyncio
    async def test_parse_invalid_json_payload(self, webhook_handler):
        """Test parsing invalid JSON payload."""
        body = b'{"invalid json'

        with pytest.raises(HTTPException) as exc_info:
            await webhook_handler._parse_webhook_payload(
                provider=GitProvider.GITHUB,
                headers={},
                body=body
            )

        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_parse_empty_payload(self, webhook_handler):
        """Test parsing empty payload."""
        body = b'{}'

        parsed = await webhook_handler._parse_webhook_payload(
            provider=GitProvider.GITHUB,
            headers={},
            body=body
        )

        assert parsed == {}


class TestEventTypeDetection:
    """Test webhook event type detection."""

    @pytest.mark.asyncio
    async def test_github_push_event(self, webhook_handler):
        """Test GitHub push event detection."""
        headers = {"X-GitHub-Event": "push"}
        payload = {"ref": "refs/heads/main"}

        event_type = await webhook_handler._determine_event_type(
            provider=GitProvider.GITHUB,
            headers=headers,
            payload=payload
        )

        assert event_type == WebhookEventType.PUSH

    @pytest.mark.asyncio
    async def test_github_pull_request_event(self, webhook_handler):
        """Test GitHub pull request event detection."""
        headers = {"X-GitHub-Event": "pull_request"}
        payload = {"action": "opened"}

        event_type = await webhook_handler._determine_event_type(
            provider=GitProvider.GITHUB,
            headers=headers,
            payload=payload
        )

        assert event_type == WebhookEventType.PULL_REQUEST

    @pytest.mark.asyncio
    async def test_github_tag_event(self, webhook_handler):
        """Test GitHub tag event detection."""
        headers = {"X-GitHub-Event": "create"}
        payload = {"ref_type": "tag", "ref": "v1.0.0"}

        event_type = await webhook_handler._determine_event_type(
            provider=GitProvider.GITHUB,
            headers=headers,
            payload=payload
        )

        assert event_type == WebhookEventType.TAG

    @pytest.mark.asyncio
    async def test_github_release_event(self, webhook_handler):
        """Test GitHub release event detection."""
        headers = {"X-GitHub-Event": "release"}
        payload = {"action": "published"}

        event_type = await webhook_handler._determine_event_type(
            provider=GitProvider.GITHUB,
            headers=headers,
            payload=payload
        )

        assert event_type == WebhookEventType.RELEASE

    @pytest.mark.asyncio
    async def test_gitlab_push_event(self, webhook_handler):
        """Test GitLab push event detection."""
        headers = {}
        payload = {"object_kind": "push"}

        event_type = await webhook_handler._determine_event_type(
            provider=GitProvider.GITLAB,
            headers=headers,
            payload=payload
        )

        assert event_type == WebhookEventType.PUSH

    @pytest.mark.asyncio
    async def test_gitlab_merge_request_event(self, webhook_handler):
        """Test GitLab merge request event detection."""
        headers = {}
        payload = {"object_kind": "merge_request"}

        event_type = await webhook_handler._determine_event_type(
            provider=GitProvider.GITLAB,
            headers=headers,
            payload=payload
        )

        assert event_type == WebhookEventType.PULL_REQUEST

    @pytest.mark.asyncio
    async def test_gitlab_tag_event(self, webhook_handler):
        """Test GitLab tag push event detection."""
        headers = {}
        payload = {"object_kind": "tag_push"}

        event_type = await webhook_handler._determine_event_type(
            provider=GitProvider.GITLAB,
            headers=headers,
            payload=payload
        )

        assert event_type == WebhookEventType.TAG

    @pytest.mark.asyncio
    async def test_bitbucket_push_event(self, webhook_handler):
        """Test Bitbucket push event detection."""
        headers = {"X-Event-Key": "repo:refs_changed"}
        payload = {}

        event_type = await webhook_handler._determine_event_type(
            provider=GitProvider.BITBUCKET,
            headers=headers,
            payload=payload
        )

        assert event_type == WebhookEventType.PUSH

    @pytest.mark.asyncio
    async def test_bitbucket_pullrequest_event(self, webhook_handler):
        """Test Bitbucket pull request event detection."""
        headers = {"X-Event-Key": "pullrequest:created"}
        payload = {}

        event_type = await webhook_handler._determine_event_type(
            provider=GitProvider.BITBUCKET,
            headers=headers,
            payload=payload
        )

        assert event_type == WebhookEventType.PULL_REQUEST

    @pytest.mark.asyncio
    async def test_azure_push_event(self, webhook_handler):
        """Test Azure DevOps push event detection."""
        headers = {"X-VSS-EventType": "git.push"}
        payload = {}

        event_type = await webhook_handler._determine_event_type(
            provider=GitProvider.AZURE_DEVOPS,
            headers=headers,
            payload=payload
        )

        assert event_type == WebhookEventType.PUSH

    @pytest.mark.asyncio
    async def test_azure_pullrequest_event(self, webhook_handler):
        """Test Azure DevOps pull request event detection."""
        headers = {"X-VSS-EventType": "git.pullrequest.created"}
        payload = {}

        event_type = await webhook_handler._determine_event_type(
            provider=GitProvider.AZURE_DEVOPS,
            headers=headers,
            payload=payload
        )

        assert event_type == WebhookEventType.PULL_REQUEST

    @pytest.mark.asyncio
    async def test_unknown_event_defaults_to_push(self, webhook_handler):
        """Test unknown event type defaults to PUSH."""
        headers = {"X-GitHub-Event": "unknown_event"}
        payload = {}

        event_type = await webhook_handler._determine_event_type(
            provider=GitProvider.GITHUB,
            headers=headers,
            payload=payload
        )

        assert event_type == WebhookEventType.PUSH


class TestPayloadExtraction:
    """Test extraction of information from webhook payloads."""

    @pytest.mark.asyncio
    async def test_extract_github_sender(self, webhook_handler):
        """Test extracting sender from GitHub payload."""
        payload = {"sender": {"login": "octocat"}}

        sender = await webhook_handler._extract_sender(GitProvider.GITHUB, payload)

        assert sender == "octocat"

    @pytest.mark.asyncio
    async def test_extract_gitlab_sender(self, webhook_handler):
        """Test extracting sender from GitLab payload."""
        payload = {"user_username": "gitlabuser"}

        sender = await webhook_handler._extract_sender(GitProvider.GITLAB, payload)

        assert sender == "gitlabuser"

    @pytest.mark.asyncio
    async def test_extract_bitbucket_sender(self, webhook_handler):
        """Test extracting sender from Bitbucket payload."""
        payload = {"actor": {"username": "bbuser"}}

        sender = await webhook_handler._extract_sender(GitProvider.BITBUCKET, payload)

        assert sender == "bbuser"

    @pytest.mark.asyncio
    async def test_extract_github_branch(self, webhook_handler):
        """Test extracting branch from GitHub payload."""
        payload = {"ref": "refs/heads/feature/new-config"}

        branch = await webhook_handler._extract_branch(GitProvider.GITHUB, payload)

        assert branch == "feature/new-config"

    @pytest.mark.asyncio
    async def test_extract_github_tag_ref_returns_none(self, webhook_handler):
        """Test extracting tag ref returns None for branch."""
        payload = {"ref": "refs/tags/v1.0.0"}

        branch = await webhook_handler._extract_branch(GitProvider.GITHUB, payload)

        assert branch is None

    @pytest.mark.asyncio
    async def test_extract_github_commit_hash(self, webhook_handler):
        """Test extracting commit hash from GitHub payload."""
        payload = {"after": "abc123def456"}

        commit_hash = await webhook_handler._extract_commit_hash(GitProvider.GITHUB, payload)

        assert commit_hash == "abc123def456"

    @pytest.mark.asyncio
    async def test_extract_github_commit_hash_from_head_commit(self, webhook_handler):
        """Test extracting commit hash from head_commit."""
        payload = {"head_commit": {"id": "xyz789"}}

        commit_hash = await webhook_handler._extract_commit_hash(GitProvider.GITHUB, payload)

        assert commit_hash == "xyz789"

    @pytest.mark.asyncio
    async def test_extract_gitlab_commit_hash(self, webhook_handler):
        """Test extracting commit hash from GitLab payload."""
        payload = {"checkout_sha": "gitlab123"}

        commit_hash = await webhook_handler._extract_commit_hash(GitProvider.GITLAB, payload)

        assert commit_hash == "gitlab123"

    @pytest.mark.asyncio
    async def test_extract_github_commit_message(self, webhook_handler):
        """Test extracting commit message from GitHub payload."""
        payload = {"head_commit": {"message": "Fix router config"}}

        message = await webhook_handler._extract_commit_message(GitProvider.GITHUB, payload)

        assert message == "Fix router config"

    @pytest.mark.asyncio
    async def test_extract_gitlab_commit_message(self, webhook_handler):
        """Test extracting commit message from GitLab payload."""
        payload = {"commits": [
            {"message": "First commit"},
            {"message": "Second commit"}
        ]}

        message = await webhook_handler._extract_commit_message(GitProvider.GITLAB, payload)

        assert message == "Second commit"

    @pytest.mark.asyncio
    async def test_extract_github_commit_author(self, webhook_handler):
        """Test extracting commit author from GitHub payload."""
        payload = {"head_commit": {"author": {"name": "John Doe"}}}

        author = await webhook_handler._extract_commit_author(GitProvider.GITHUB, payload)

        assert author == "John Doe"

    @pytest.mark.asyncio
    async def test_extract_changed_files_github(self, webhook_handler):
        """Test extracting changed files from GitHub payload."""
        payload = {
            "commits": [
                {
                    "added": ["file1.conf"],
                    "modified": ["file2.cfg"],
                    "removed": ["old.conf"]
                }
            ]
        }

        files = await webhook_handler._extract_changed_files(GitProvider.GITHUB, payload)

        assert len(files) == 3
        assert "file1.conf" in files
        assert "file2.cfg" in files
        assert "old.conf" in files

    @pytest.mark.asyncio
    async def test_extract_changed_files_deduplication(self, webhook_handler):
        """Test changed files are deduplicated."""
        payload = {
            "commits": [
                {"added": ["file1.conf"], "modified": [], "removed": []},
                {"added": [], "modified": ["file1.conf"], "removed": []}
            ]
        }

        files = await webhook_handler._extract_changed_files(GitProvider.GITHUB, payload)

        assert len(files) == 1
        assert "file1.conf" in files


class TestSignatureHeaders:
    """Test signature header retrieval."""

    def test_get_github_signature_header(self, webhook_handler):
        """Test GitHub signature header name."""
        header = webhook_handler._get_signature_header(GitProvider.GITHUB)
        assert header == "X-Hub-Signature-256"

    def test_get_gitlab_signature_header(self, webhook_handler):
        """Test GitLab signature header name."""
        header = webhook_handler._get_signature_header(GitProvider.GITLAB)
        assert header == "X-Gitlab-Token"

    def test_get_bitbucket_signature_header(self, webhook_handler):
        """Test Bitbucket signature header name."""
        header = webhook_handler._get_signature_header(GitProvider.BITBUCKET)
        assert header == "X-Hub-Signature"

    def test_get_azure_signature_header(self, webhook_handler):
        """Test Azure DevOps signature header name."""
        header = webhook_handler._get_signature_header(GitProvider.AZURE_DEVOPS)
        assert header == "Authorization"


class TestPushEventHandling:
    """Test push event handling."""

    @pytest.mark.asyncio
    async def test_handle_push_event_success(self, webhook_handler, mock_repository, mock_git_client):
        """Test successful push event handling."""
        payload = Mock(spec=WebhookPayload)
        payload.commit_hash = "abc123"
        sync_operation = SyncOperation(repository_id=mock_repository.id, trigger="webhook")

        config_file = Mock()
        config_file.validation_errors = []
        config_file.validated = False
        mock_git_client.get_config_files.return_value = [config_file]

        with patch.object(webhook_handler, '_store_config_file', new_callable=AsyncMock):
            await webhook_handler._handle_push_event(payload, mock_repository, sync_operation)

        assert sync_operation.commits_processed == 2
        assert sync_operation.files_processed == 1
        assert mock_git_client.cleanup_temp_dir.called

    @pytest.mark.asyncio
    async def test_handle_push_event_with_secrets(self, webhook_handler, mock_repository, mock_git_client):
        """Test push event with secrets detected."""
        payload = Mock(spec=WebhookPayload)
        sync_operation = SyncOperation(repository_id=mock_repository.id, trigger="webhook")

        # Simulate secrets found
        mock_git_client.scan_for_secrets.return_value = [
            {"type": "api_key", "line": 10}
        ]

        with patch.object(webhook_handler, '_quarantine_repository', new_callable=AsyncMock) as mock_quarantine:
            await webhook_handler._handle_push_event(payload, mock_repository, sync_operation)

        assert mock_quarantine.called
        assert len(sync_operation.errors) > 0

    @pytest.mark.asyncio
    async def test_handle_push_event_cleanup_on_exception(self, webhook_handler, mock_repository, mock_git_client):
        """Test cleanup happens even on exception."""
        payload = Mock(spec=WebhookPayload)
        sync_operation = SyncOperation(repository_id=mock_repository.id, trigger="webhook")

        # Simulate exception
        mock_git_client.pull_latest.side_effect = Exception("Git error")

        with pytest.raises(Exception):
            await webhook_handler._handle_push_event(payload, mock_repository, sync_operation)

        # Cleanup should still be called
        assert mock_git_client.cleanup_temp_dir.called


class TestPullRequestEventHandling:
    """Test pull request event handling."""

    @pytest.mark.asyncio
    async def test_handle_pr_opened_event(self, webhook_handler, mock_repository, mock_git_client):
        """Test handling opened pull request."""
        payload = Mock(spec=WebhookPayload)
        payload.raw_payload = {
            "pull_request": {
                "state": "open",
                "action": "opened",
                "number": 42,
                "base": {"ref": "main"},
                "head": {"ref": "feature-branch"}
            }
        }
        sync_operation = SyncOperation(repository_id=mock_repository.id, trigger="webhook")

        diff = Mock()
        diff.file_path = "router.conf"
        diff.new_content = "interface GigabitEthernet0/1\n"
        mock_git_client.get_diff.return_value = [diff]

        with patch.object(webhook_handler, '_post_pr_comment', new_callable=AsyncMock):
            await webhook_handler._handle_pull_request_event(payload, mock_repository, sync_operation)

        assert mock_git_client.get_diff.called

    @pytest.mark.asyncio
    async def test_handle_pr_with_validation_errors(self, webhook_handler, mock_repository,
                                                     mock_git_client, mock_config_validator):
        """Test PR with configuration validation errors."""
        payload = Mock(spec=WebhookPayload)
        payload.raw_payload = {
            "pull_request": {
                "state": "open",
                "number": 42,
                "base": {"ref": "main"},
                "head": {"ref": "feature-branch"}
            }
        }
        sync_operation = SyncOperation(repository_id=mock_repository.id, trigger="webhook")

        diff = Mock()
        diff.file_path = "router.conf"
        diff.new_content = "invalid config"
        mock_git_client.get_diff.return_value = [diff]

        # Simulate validation failure
        mock_config_validator.validate_content.return_value = Mock(
            is_valid=False,
            errors=["Invalid syntax on line 5"]
        )

        with patch.object(webhook_handler, '_post_pr_comment', new_callable=AsyncMock) as mock_comment:
            await webhook_handler._handle_pull_request_event(payload, mock_repository, sync_operation)

        assert mock_comment.called
        assert len(sync_operation.warnings) > 0

    @pytest.mark.asyncio
    async def test_handle_pr_with_security_issues(self, webhook_handler, mock_repository,
                                                   mock_git_client, mock_security_scanner):
        """Test PR with security issues detected."""
        payload = Mock(spec=WebhookPayload)
        payload.raw_payload = {
            "pull_request": {
                "state": "open",
                "number": 42,
                "base": {"ref": "main"},
                "head": {"ref": "feature-branch"}
            }
        }
        sync_operation = SyncOperation(repository_id=mock_repository.id, trigger="webhook")

        # Simulate security issues
        mock_security_scanner.scan_pr.return_value = [
            "Hardcoded password found",
            "Insecure protocol used"
        ]

        with patch.object(webhook_handler, '_post_pr_comment', new_callable=AsyncMock) as mock_comment:
            await webhook_handler._handle_pull_request_event(payload, mock_repository, sync_operation)

        assert mock_comment.called
        assert len(sync_operation.errors) > 0


class TestTagEventHandling:
    """Test tag event handling."""

    @pytest.mark.asyncio
    async def test_handle_tag_event(self, webhook_handler, mock_repository, mock_git_client):
        """Test tag event handling."""
        payload = Mock(spec=WebhookPayload)
        payload.raw_payload = {"ref": "refs/tags/v1.2.3"}
        sync_operation = SyncOperation(repository_id=mock_repository.id, trigger="webhook")

        config_file = Mock()
        config_file.tags = []
        config_file.metadata = {}
        mock_git_client.get_config_files.return_value = [config_file]

        with patch.object(webhook_handler, '_store_config_file', new_callable=AsyncMock):
            await webhook_handler._handle_tag_event(payload, mock_repository, sync_operation)

        assert "v1.2.3" in config_file.tags
        assert "tagged_at" in config_file.metadata
        assert sync_operation.configs_extracted == 1


class TestReleaseEventHandling:
    """Test release event handling."""

    @pytest.mark.asyncio
    async def test_handle_release_published(self, webhook_handler, mock_repository, mock_git_client):
        """Test handling published release."""
        payload = Mock(spec=WebhookPayload)
        payload.raw_payload = {
            "release": {
                "action": "published",
                "tag_name": "v2.0.0",
                "name": "Release 2.0.0",
                "published_at": "2025-10-10T12:00:00Z"
            }
        }
        sync_operation = SyncOperation(repository_id=mock_repository.id, trigger="webhook")

        config_file = Mock()
        config_file.metadata = {}
        config_file.id = uuid4()
        mock_git_client.get_config_files.return_value = [config_file]

        with patch.object(webhook_handler, '_create_deployment_from_release', new_callable=AsyncMock) as mock_deploy:
            await webhook_handler._handle_release_event(payload, mock_repository, sync_operation)

        assert "release" in config_file.metadata
        assert config_file.metadata["release"]["tag"] == "v2.0.0"
        assert mock_deploy.called


class TestRepositoryQuarantine:
    """Test repository quarantine functionality."""

    @pytest.mark.asyncio
    async def test_quarantine_repository_with_secrets(self, webhook_handler, mock_repository):
        """Test quarantining repository when secrets are detected."""
        secrets = [
            {"type": "api_key", "file": "config.py", "line": 42},
            {"type": "password", "file": "settings.conf", "line": 10}
        ]

        await webhook_handler._quarantine_repository(mock_repository, secrets)

        assert mock_repository.status == "quarantined"
        assert mock_repository.metadata["quarantine_reason"] == "Secrets detected"
        assert len(mock_repository.metadata["quarantine_details"]) == 2


class TestProcessWebhookIntegration:
    """Integration tests for complete webhook processing."""

    @pytest.mark.asyncio
    async def test_process_webhook_valid_signature(self, webhook_handler, mock_repository):
        """Test processing webhook with valid signature."""
        body = b'{"ref": "refs/heads/main", "after": "abc123"}'
        secret = mock_repository.webhook_secret.encode()
        signature = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()

        headers = {
            "X-Hub-Signature-256": signature,
            "X-GitHub-Event": "push"
        }

        with patch.object(webhook_handler, '_process_webhook_async', new_callable=AsyncMock):
            result = await webhook_handler.process_webhook(
                provider=GitProvider.GITHUB,
                headers=headers,
                body=body,
                repository=mock_repository
            )

        assert isinstance(result, WebhookPayload)
        assert result.repository_id == mock_repository.id
        assert result.event_type == WebhookEventType.PUSH

    @pytest.mark.asyncio
    async def test_process_webhook_invalid_signature_raises_exception(self, webhook_handler, mock_repository):
        """Test webhook processing fails with invalid signature."""
        body = b'{"ref": "refs/heads/main"}'
        headers = {
            "X-Hub-Signature-256": "sha256=invalid_signature",
            "X-GitHub-Event": "push"
        }

        with pytest.raises(HTTPException) as exc_info:
            await webhook_handler.process_webhook(
                provider=GitProvider.GITHUB,
                headers=headers,
                body=body,
                repository=mock_repository
            )

        assert exc_info.value.status_code == 401
        assert "Invalid webhook signature" in str(exc_info.value.detail)
