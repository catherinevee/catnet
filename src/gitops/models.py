from typing import Optional, List, Dict, Any
from datetime import datetime
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, HttpUrl, validator
from enum import Enum
import hashlib


class GitProvider(str, Enum):
    GITHUB = "github"
    GITLAB = "gitlab"
    BITBUCKET = "bitbucket"
    AZURE_DEVOPS = "azure_devops"
    GENERIC = "generic"


class WebhookEventType(str, Enum):
    PUSH = "push"
    PULL_REQUEST = "pull_request"
    TAG = "tag"
    RELEASE = "release"
    BRANCH_CREATE = "branch_create"
    BRANCH_DELETE = "branch_delete"


class RepositoryStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SYNCING = "syncing"
    ERROR = "error"
    INITIALIZED = "initialized"


class SyncStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"


class GitRepository(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    name: str
    url: HttpUrl
    branch: str = "main"
    provider: GitProvider = GitProvider.GENERIC
    webhook_secret: Optional[str] = None
    webhook_url: Optional[HttpUrl] = None
    ssh_key_id: Optional[str] = None
    access_token_ref: Optional[str] = None
    status: RepositoryStatus = RepositoryStatus.INITIALIZED
    last_sync: Optional[datetime] = None
    last_commit_hash: Optional[str] = None
    auto_sync: bool = True
    sync_interval_minutes: int = 15
    gpg_verification_enabled: bool = True
    allowed_signers: List[str] = Field(default_factory=list)
    path_filters: List[str] = Field(default_factory=list)
    ignore_patterns: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @validator('branch')
    def validate_branch(cls, v):
        if not v:
            return "main"
        return v


class WebhookPayload(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    repository_id: UUID
    event_type: WebhookEventType
    provider: GitProvider
    raw_payload: Dict[str, Any]
    signature: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    sender: Optional[str] = None
    branch: Optional[str] = None
    commit_hash: Optional[str] = None
    commit_message: Optional[str] = None
    commit_author: Optional[str] = None
    commit_timestamp: Optional[datetime] = None
    files_changed: List[str] = Field(default_factory=list)
    received_at: datetime = Field(default_factory=datetime.utcnow)
    processed: bool = False
    processed_at: Optional[datetime] = None
    processing_error: Optional[str] = None

    def verify_signature(self, secret: str) -> bool:
        if not self.signature or not secret:
            return False

        if self.provider == GitProvider.GITHUB:
            return self._verify_github_signature(secret)
        elif self.provider == GitProvider.GITLAB:
            return self._verify_gitlab_signature(secret)
        elif self.provider == GitProvider.BITBUCKET:
            return self._verify_bitbucket_signature(secret)
        else:
            return False

    def _verify_github_signature(self, secret: str) -> bool:
        import hmac
        expected_signature = "sha256=" + hmac.new(
            secret.encode(),
            str(self.raw_payload).encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(self.signature, expected_signature)

    def _verify_gitlab_signature(self, secret: str) -> bool:
        return self.headers.get("X-Gitlab-Token") == secret

    def _verify_bitbucket_signature(self, secret: str) -> bool:
        import hmac
        expected_signature = hmac.new(
            secret.encode(),
            str(self.raw_payload).encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(self.signature, expected_signature)


class GitCommit(BaseModel):
    hash: str
    message: str
    author: str
    author_email: str
    timestamp: datetime
    branch: str
    files_added: List[str] = Field(default_factory=list)
    files_modified: List[str] = Field(default_factory=list)
    files_deleted: List[str] = Field(default_factory=list)
    signed: bool = False
    signature_valid: bool = False
    signer: Optional[str] = None


class GitDiff(BaseModel):
    file_path: str
    old_content: Optional[str] = None
    new_content: Optional[str] = None
    additions: int = 0
    deletions: int = 0
    is_binary: bool = False
    change_type: str


class SyncOperation(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    repository_id: UUID
    status: SyncStatus = SyncStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    trigger: str
    triggered_by: Optional[UUID] = None
    commits_processed: int = 0
    files_processed: int = 0
    configs_extracted: int = 0
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)

    def start(self):
        self.status = SyncStatus.IN_PROGRESS
        self.started_at = datetime.utcnow()

    def complete(self, success: bool = True):
        self.status = SyncStatus.SUCCESS if success else SyncStatus.FAILED
        self.completed_at = datetime.utcnow()

    def add_error(self, error: str):
        self.errors.append(error)
        self.status = SyncStatus.FAILED


class ConfigFile(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    repository_id: UUID
    file_path: str
    content: str
    content_hash: str
    format: str
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    environment: Optional[str] = None
    version: int = 1
    commit_hash: str
    commit_message: str
    commit_author: str
    committed_at: datetime
    validated: bool = False
    validation_errors: List[str] = Field(default_factory=list)
    encrypted: bool = False
    encryption_key_id: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @validator('content_hash')
    def compute_hash(cls, v, values):
        if 'content' in values:
            return hashlib.sha256(values['content'].encode()).hexdigest()
        return v


class GitCredentials(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    name: str
    type: str
    username: Optional[str] = None
    password: Optional[str] = None
    ssh_private_key: Optional[str] = None
    ssh_public_key: Optional[str] = None
    token: Optional[str] = None
    vault_path: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    last_used: Optional[datetime] = None

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at


class BranchProtectionRule(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    repository_id: UUID
    branch_pattern: str
    require_pull_request: bool = True
    required_approvals: int = 2
    dismiss_stale_reviews: bool = True
    require_code_owner_review: bool = True
    require_signed_commits: bool = True
    enforce_admins: bool = False
    require_status_checks: bool = True
    required_status_checks: List[str] = Field(default_factory=list)
    restrict_push_access: bool = True
    allowed_users: List[str] = Field(default_factory=list)
    allowed_teams: List[str] = Field(default_factory=list)


class GitScanResult(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    repository_id: UUID
    commit_hash: str
    scan_type: str
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    secrets_found: int = 0
    vulnerabilities_found: int = 0
    policy_violations: int = 0
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    quarantined: bool = False
    quarantine_reason: Optional[str] = None
    approved_by: Optional[UUID] = None
    approval_timestamp: Optional[datetime] = None


class GitWorkflow(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    name: str
    repository_id: UUID
    trigger_events: List[WebhookEventType]
    trigger_branches: List[str] = Field(default_factory=list)
    trigger_paths: List[str] = Field(default_factory=list)
    steps: List[Dict[str, Any]]
    enabled: bool = True
    timeout_minutes: int = 30
    retry_on_failure: bool = False
    max_retries: int = 3
    notifications: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)