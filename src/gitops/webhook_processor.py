"""
Webhook Processor for CatNet GitOps

Processes webhooks from Git providers:
- GitHub webhooks
- GitLab webhooks
- Bitbucket webhooks
- Generic Git webhooks
"""

import hmac
import hashlib
import json
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import re


class WebhookProvider(Enum):
    """Supported webhook providers"""

    GITHUB = "github"
    GITLAB = "gitlab"
    BITBUCKET = "bitbucket"
    GENERIC = "generic"


class EventType(Enum):
    """Git webhook event types"""

    PUSH = "push"
    PULL_REQUEST = "pull_request"
    TAG = "tag"
    RELEASE = "release"
    BRANCH_CREATE = "branch_create"
    BRANCH_DELETE = "branch_delete"
    COMMIT_COMMENT = "commit_comment"
    ISSUE = "issue"


@dataclass
class WebhookEvent:
    """Represents a processed webhook event"""

    id: str
    provider: WebhookProvider
    event_type: EventType
    repository: str
    branch: Optional[str]
    commit: Optional[str]
    author: Optional[str]
    timestamp: datetime
    files_changed: List[str]
    raw_payload: Dict[str, Any]
    verified: bool = False
    metadata: Dict[str, Any] = None


class WebhookProcessor:
    """
    Processes webhooks from various Git providers
    """

    def __init__(self):
        """Initialize webhook processor"""
        self.webhook_secrets: Dict[str, str] = {}  # repo_url -> secret
        self.processed_events: List[str] = []  # Track processed event IDs
        self.event_handlers: Dict[EventType, List[callable]] = {}

    def register_webhook_secret(self, repository_url: str, secret: str) -> None:
        """
        Register webhook secret for repository

        Args:
            repository_url: Repository URL
            secret: Webhook secret for verification
        """
        # Normalize repository URL
        normalized_url = self._normalize_repository_url(repository_url)
        self.webhook_secrets[normalized_url] = secret

    def process_webhook(
        self,
        headers: Dict[str, str],
        body: str,
        provider: Optional[WebhookProvider] = None,
    ) -> Tuple[bool, Optional[WebhookEvent]]:
        """
        Process incoming webhook

        Args:
            headers: HTTP headers
            body: Request body (JSON string)
            provider: Webhook provider (auto-detect if None)

        Returns:
            Tuple of (success, WebhookEvent)
        """
        try:
            # Auto-detect provider if not specified
            if provider is None:
                provider = self._detect_provider(headers)

            if provider is None:
                return False, None

            # Parse payload
            payload = json.loads(body) if isinstance(body, str) else body

            # Verify webhook signature
            repo_url = self._extract_repository_url(payload, provider)
            if repo_url:
                normalized_url = self._normalize_repository_url(repo_url)
                secret = self.webhook_secrets.get(normalized_url)

                if secret:
                    is_valid = self._verify_signature(headers, body, secret, provider)
                    if not is_valid:
                        return False, None
                else:
                    # No secret registered, consider unverified
                    is_valid = False
            else:
                is_valid = False

            # Process based on provider
            if provider == WebhookProvider.GITHUB:
                event = self._process_github_webhook(headers, payload, is_valid)
            elif provider == WebhookProvider.GITLAB:
                event = self._process_gitlab_webhook(headers, payload, is_valid)
            elif provider == WebhookProvider.BITBUCKET:
                event = self._process_bitbucket_webhook(headers, payload, is_valid)
            else:
                event = self._process_generic_webhook(headers, payload, is_valid)

            if event:
                # Check for duplicate events
                if event.id not in self.processed_events:
                    self.processed_events.append(event.id)
                    # Keep only last 1000 events
                    if len(self.processed_events) > 1000:
                        self.processed_events = self.processed_events[-1000:]

                    # Trigger event handlers
                    self._trigger_handlers(event)

                    return True, event
                else:
                    return False, None  # Duplicate event

            return False, None

        except Exception as e:
            print(f"Webhook processing error: {str(e)}")
            return False, None

    def register_handler(self, event_type: EventType, handler: callable) -> None:
        """
        Register event handler

        Args:
            event_type: Type of event to handle
            handler: Handler function
        """
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler)

    def _detect_provider(self, headers: Dict[str, str]) -> Optional[WebhookProvider]:
        """
        Detect webhook provider from headers

        Args:
            headers: HTTP headers

        Returns:
            Detected provider or None
        """
        # Convert headers to lowercase for case-insensitive comparison
        headers_lower = {k.lower(): v for k, v in headers.items()}

        if "x-github-event" in headers_lower:
            return WebhookProvider.GITHUB
        elif "x-gitlab-event" in headers_lower:
            return WebhookProvider.GITLAB
        elif "x-event-key" in headers_lower:  # Bitbucket
            return WebhookProvider.BITBUCKET
        else:
            return WebhookProvider.GENERIC

    def _verify_signature(
        self, headers: Dict[str, str], body: str, secret: str, provider: WebhookProvider
    ) -> bool:
        """
        Verify webhook signature

        Args:
            headers: HTTP headers
            body: Request body
            secret: Webhook secret
            provider: Webhook provider

        Returns:
            Verification status
        """
        headers_lower = {k.lower(): v for k, v in headers.items()}

        if provider == WebhookProvider.GITHUB:
            signature_header = headers_lower.get("x-hub-signature-256")
            if not signature_header:
                return False

            # GitHub uses HMAC-SHA256
            expected_signature = (
                "sha256="
                + hmac.new(
                    secret.encode(),
                    body.encode() if isinstance(body, str) else body,
                    hashlib.sha256,
                ).hexdigest()
            )

            return hmac.compare_digest(signature_header, expected_signature)

        elif provider == WebhookProvider.GITLAB:
            token_header = headers_lower.get("x-gitlab-token")
            return token_header == secret if token_header else False

        elif provider == WebhookProvider.BITBUCKET:
            signature_header = headers_lower.get("x-hub-signature")
            if not signature_header:
                return False

            # Bitbucket uses HMAC-SHA256
            expected_signature = (
                "sha256="
                + hmac.new(
                    secret.encode(),
                    body.encode() if isinstance(body, str) else body,
                    hashlib.sha256,
                ).hexdigest()
            )

            return hmac.compare_digest(signature_header, expected_signature)

        else:
            # Generic verification using HMAC-SHA256
            signature_header = headers_lower.get("x-webhook-signature")
            if not signature_header:
                return False

            expected_signature = hmac.new(
                secret.encode(),
                body.encode() if isinstance(body, str) else body,
                hashlib.sha256,
            ).hexdigest()

            return hmac.compare_digest(signature_header, expected_signature)

    def _process_github_webhook(
        self, headers: Dict[str, str], payload: Dict[str, Any], verified: bool
    ) -> Optional[WebhookEvent]:
        """
        Process GitHub webhook

        Args:
            headers: HTTP headers
            payload: Webhook payload
            verified: Signature verification status

        Returns:
            WebhookEvent or None
        """
        headers_lower = {k.lower(): v for k, v in headers.items()}
        event_name = headers_lower.get("x-github-event", "")

        # Map GitHub events to our event types
        event_type_map = {
            "push": EventType.PUSH,
            "pull_request": EventType.PULL_REQUEST,
            "create": EventType.TAG
            if payload.get("ref_type") == "tag"
            else EventType.BRANCH_CREATE,
            "delete": EventType.BRANCH_DELETE,
            "release": EventType.RELEASE,
            "commit_comment": EventType.COMMIT_COMMENT,
            "issues": EventType.ISSUE,
        }

        event_type = event_type_map.get(event_name)
        if not event_type:
            return None

        # Extract common fields
        repository = payload.get("repository", {})
        repo_url = repository.get("clone_url", "")

        # Handle push events
        if event_type == EventType.PUSH:
            branch = payload.get("ref", "").replace("refs/heads/", "")
            commits = payload.get("commits", [])
            latest_commit = commits[-1] if commits else {}

            files_changed = []
            for commit in commits:
                files_changed.extend(commit.get("added", []))
                files_changed.extend(commit.get("modified", []))
                files_changed.extend(commit.get("removed", []))

            return WebhookEvent(
                id=headers_lower.get("x-github-delivery", ""),
                provider=WebhookProvider.GITHUB,
                event_type=event_type,
                repository=repo_url,
                branch=branch,
                commit=latest_commit.get("id"),
                author=latest_commit.get("author", {}).get("username"),
                timestamp=datetime.fromisoformat(
                    latest_commit.get("timestamp", datetime.utcnow().isoformat())
                ),
                files_changed=list(set(files_changed)),
                raw_payload=payload,
                verified=verified,
                metadata={
                    "pusher": payload.get("pusher", {}).get("name"),
                    "forced": payload.get("forced", False),
                },
            )

        # Handle pull request events
        elif event_type == EventType.PULL_REQUEST:
            pr = payload.get("pull_request", {})
            return WebhookEvent(
                id=headers_lower.get("x-github-delivery", ""),
                provider=WebhookProvider.GITHUB,
                event_type=event_type,
                repository=repo_url,
                branch=pr.get("base", {}).get("ref"),
                commit=pr.get("head", {}).get("sha"),
                author=pr.get("user", {}).get("login"),
                timestamp=datetime.utcnow(),
                files_changed=[],
                raw_payload=payload,
                verified=verified,
                metadata={
                    "action": payload.get("action"),
                    "pr_number": pr.get("number"),
                    "title": pr.get("title"),
                },
            )

        return None

    def _process_gitlab_webhook(
        self, headers: Dict[str, str], payload: Dict[str, Any], verified: bool
    ) -> Optional[WebhookEvent]:
        """
        Process GitLab webhook

        Args:
            headers: HTTP headers
            payload: Webhook payload
            verified: Token verification status

        Returns:
            WebhookEvent or None
        """
        headers_lower = {k.lower(): v for k, v in headers.items()}
        event_name = headers_lower.get("x-gitlab-event", "")

        # Map GitLab events
        event_type_map = {
            "Push Hook": EventType.PUSH,
            "Merge Request Hook": EventType.PULL_REQUEST,
            "Tag Push Hook": EventType.TAG,
            "Issue Hook": EventType.ISSUE,
        }

        event_type = event_type_map.get(event_name)
        if not event_type:
            return None

        # Extract repository URL
        project = payload.get("project", {})
        repo_url = project.get("git_http_url", "")

        if event_type == EventType.PUSH:
            branch = payload.get("ref", "").replace("refs/heads/", "")
            commits = payload.get("commits", [])
            latest_commit = commits[-1] if commits else {}

            files_changed = []
            for commit in commits:
                files_changed.extend(commit.get("added", []))
                files_changed.extend(commit.get("modified", []))
                files_changed.extend(commit.get("removed", []))

            return WebhookEvent(
                id=str(payload.get("checkout_sha", "")),
                provider=WebhookProvider.GITLAB,
                event_type=event_type,
                repository=repo_url,
                branch=branch,
                commit=latest_commit.get("id"),
                author=latest_commit.get("author", {}).get("name"),
                timestamp=datetime.fromisoformat(
                    latest_commit.get("timestamp", datetime.utcnow().isoformat())
                ),
                files_changed=list(set(files_changed)),
                raw_payload=payload,
                verified=verified,
            )

        return None

    def _process_bitbucket_webhook(
        self, headers: Dict[str, str], payload: Dict[str, Any], verified: bool
    ) -> Optional[WebhookEvent]:
        """
        Process Bitbucket webhook

        Args:
            headers: HTTP headers
            payload: Webhook payload
            verified: Signature verification status

        Returns:
            WebhookEvent or None
        """
        headers_lower = {k.lower(): v for k, v in headers.items()}
        event_key = headers_lower.get("x-event-key", "")

        # Map Bitbucket events
        if "push" in event_key:
            event_type = EventType.PUSH
        elif "pullrequest" in event_key:
            event_type = EventType.PULL_REQUEST
        else:
            return None

        repository = payload.get("repository", {})
        repo_url = repository.get("links", {}).get("clone", [{}])[0].get("href", "")

        if event_type == EventType.PUSH:
            push = payload.get("push", {})
            changes = push.get("changes", [])

            if changes:
                change = changes[0]
                branch = change.get("new", {}).get("name", "")
                commit_hash = change.get("new", {}).get("target", {}).get("hash", "")
                author = (
                    change.get("new", {})
                    .get("target", {})
                    .get("author", {})
                    .get("raw", "")
                )

                return WebhookEvent(
                    id=headers_lower.get("x-request-uuid", ""),
                    provider=WebhookProvider.BITBUCKET,
                    event_type=event_type,
                    repository=repo_url,
                    branch=branch,
                    commit=commit_hash,
                    author=author,
                    timestamp=datetime.utcnow(),
                    files_changed=[],
                    raw_payload=payload,
                    verified=verified,
                )

        return None

    def _process_generic_webhook(
        self, headers: Dict[str, str], payload: Dict[str, Any], verified: bool
    ) -> Optional[WebhookEvent]:
        """
        Process generic Git webhook

        Args:
            headers: HTTP headers
            payload: Webhook payload
            verified: Signature verification status

        Returns:
            WebhookEvent or None
        """
        # Try to extract common fields
        repo_url = payload.get("repository", {}).get("url", "")
        branch = payload.get("ref", "").replace("refs/heads/", "")

        commits = payload.get("commits", [])
        if commits:
            latest_commit = commits[-1]
            commit_id = latest_commit.get("id", "")
            author = latest_commit.get("author", {}).get("name", "")
        else:
            commit_id = payload.get("after", "")
            author = payload.get("pusher", {}).get("name", "")

        return WebhookEvent(
            id=payload.get("after", ""),
            provider=WebhookProvider.GENERIC,
            event_type=EventType.PUSH,
            repository=repo_url,
            branch=branch,
            commit=commit_id,
            author=author,
            timestamp=datetime.utcnow(),
            files_changed=[],
            raw_payload=payload,
            verified=verified,
        )

    def _extract_repository_url(
        self, payload: Dict[str, Any], provider: WebhookProvider
    ) -> Optional[str]:
        """
        Extract repository URL from payload

        Args:
            payload: Webhook payload
            provider: Webhook provider

        Returns:
            Repository URL or None
        """
        if provider == WebhookProvider.GITHUB:
            return payload.get("repository", {}).get("clone_url")
        elif provider == WebhookProvider.GITLAB:
            return payload.get("project", {}).get("git_http_url")
        elif provider == WebhookProvider.BITBUCKET:
            return (
                payload.get("repository", {})
                .get("links", {})
                .get("clone", [{}])[0]
                .get("href")
            )
        else:
            return payload.get("repository", {}).get("url")

    def _normalize_repository_url(self, url: str) -> str:
        """
        Normalize repository URL for comparison

        Args:
            url: Repository URL

        Returns:
            Normalized URL
        """
        # Remove protocol
        url = re.sub(r"^https?://", "", url)
        # Remove .git suffix
        url = re.sub(r"\.git$", "", url)
        # Convert to lowercase
        url = url.lower()
        return url

    def _trigger_handlers(self, event: WebhookEvent) -> None:
        """
        Trigger registered event handlers

        Args:
            event: Webhook event
        """
        handlers = self.event_handlers.get(event.event_type, [])
        for handler in handlers:
            try:
                handler(event)
            except Exception as e:
                print(f"Handler error: {str(e)}")
