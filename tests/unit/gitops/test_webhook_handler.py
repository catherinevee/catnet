"""
Unit tests for GitOps Webhook Handler
Tests webhook processing, signature verification, and Git event handling
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
import hmac
import hashlib
import json
from uuid import uuid4

from src.gitops.webhook_handler import WebhookHandler
from src.gitops.models import WebhookPayload, WebhookEventType, GitProvider


@pytest.fixture
def mock_components():
    """Provide mock components for webhook handler."""
    return {
        'git_client': AsyncMock(),
        'config_parser': AsyncMock(),
        'config_validator': AsyncMock(),
        'security_scanner': AsyncMock(),
        'vault_client': AsyncMock()
    }


@pytest.fixture
def webhook_handler(mock_components):
    """Provide webhook handler instance."""
    return WebhookHandler(**mock_components)


@pytest.fixture
def mock_repository():
    """Provide mock Git repository."""
    repo = Mock()
    repo.id = uuid4()
    repo.name = "network-configs"
    repo.webhook_secret = "test_secret_key_123"
    return repo


class TestWebhookSignatureVerification:
    """Test webhook signature verification."""

    @pytest.mark.asyncio
    async def test_verify_github_signature_valid(self, webhook_handler, mock_repository):
        """Test valid GitHub webhook signature."""
        body = b'{"ref": "refs/heads/main"}'
        secret = mock_repository.webhook_secret.encode()
        
        signature = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
        headers = {"X-Hub-Signature-256": signature}
        
        is_valid = await webhook_handler._verify_webhook_signature(
            provider=GitProvider.GITHUB,
            headers=headers,
            body=body,
            secret=mock_repository.webhook_secret
        )
        
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_verify_github_signature_invalid(self, webhook_handler, mock_repository):
        """Test invalid GitHub webhook signature."""
        body = b'{"ref": "refs/heads/main"}'
        headers = {"X-Hub-Signature-256": "sha256=invalid_signature"}
        
        is_valid = await webhook_handler._verify_webhook_signature(
            provider=GitProvider.GITHUB,
            headers=headers,
            body=body,
            secret=mock_repository.webhook_secret
        )
        
        assert is_valid is False


class TestWebhookPayloadParsing:
    """Test webhook payload parsing."""

    @pytest.mark.asyncio
    async def test_parse_github_push_event(self, webhook_handler):
        """Test parsing GitHub push event."""
        payload = {
            "ref": "refs/heads/main",
            "after": "abc123def456",
            "commits": [{
                "id": "abc123",
                "message": "Update router config",
                "author": {"name": "Test User", "email": "test@example.com"}
            }]
        }
        
        headers = {"X-GitHub-Event": "push"}
        body = json.dumps(payload).encode()
        
        parsed = await webhook_handler._parse_webhook_payload(
            provider=GitProvider.GITHUB,
            headers=headers,
            body=body
        )
        
        assert parsed["ref"] == "refs/heads/main"
        assert parsed["after"] == "abc123def456"

    @pytest.mark.asyncio
    async def test_determine_push_event_type(self, webhook_handler):
        """Test determining push event type."""
        headers = {"X-GitHub-Event": "push"}
        payload = {"ref": "refs/heads/main"}
        
        event_type = await webhook_handler._determine_event_type(
            provider=GitProvider.GITHUB,
            headers=headers,
            payload=payload
        )
        
        assert event_type == WebhookEventType.PUSH


# More test classes would follow...
