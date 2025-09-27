"""
Data models for GitOps service.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
import uuid

from pydantic import BaseModel, Field, validator, HttpUrl


class AuthType(str, Enum):
    """Repository authentication types."""
    SSH = "ssh"
    HTTPS = "https"
    TOKEN = "token"
    OAUTH = "oauth"


class Provider(str, Enum):
    """Git providers."""
    GITHUB = "github"
    GITLAB = "gitlab"
    BITBUCKET = "bitbucket"
    AZURE_DEVOPS = "azure_devops"
    CUSTOM = "custom"


class EventType(str, Enum):
    """Webhook event types."""
    PUSH = "push"
    PULL_REQUEST = "pull_request"
    MERGE = "merge"
    TAG = "tag"
    RELEASE = "release"
    BRANCH_CREATE = "branch_create"
    BRANCH_DELETE = "branch_delete"
    ISSUE = "issue"
    COMMENT = "comment"


class ConfigType(str, Enum):
    """Configuration file types."""
    YAML = "yaml"
    JSON = "json"
    TOML = "toml"
    INI = "ini"
    XML = "xml"
    PROPERTIES = "properties"
    CUSTOM = "custom"


class Repository(BaseModel):
    """Repository model."""
    id: str
    url: str
    name: str
    provider: Provider
    branch: str = "main"
    auth_type: AuthType
    local_path: Optional[str] = None
    webhook_secret: Optional[str] = None
    webhook_url: Optional[str] = None
    gpg_verification: bool = False
    auto_sync: bool = True
    sync_interval: int = 300  # seconds
    last_sync: Optional[datetime] = None
    last_commit: Optional[str] = None
    quarantined: bool = False
    quarantine_reason: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime


class RepositoryCreateRequest(BaseModel):
    """Repository creation request."""
    url: str
    branch: str = "main"
    auth_type: AuthType = AuthType.SSH
    credentials: Optional[Dict[str, str]] = None
    gpg_verification: bool = False
    auto_sync: bool = True
    sync_interval: int = Field(default=300, ge=60, le=3600)


class RepositoryUpdateRequest(BaseModel):
    """Repository update request."""
    branch: Optional[str] = None
    auth_type: Optional[AuthType] = None
    credentials: Optional[Dict[str, str]] = None
    gpg_verification: Optional[bool] = None
    auto_sync: Optional[bool] = None
    sync_interval: Optional[int] = Field(None, ge=60, le=3600)


class RepositoryResponse(BaseModel):
    """Repository response model."""
    id: str
    url: str
    name: str
    provider: Provider
    branch: str
    auth_type: AuthType
    webhook_url: str
    webhook_secret: Optional[str] = None
    gpg_verification: bool
    auto_sync: bool
    sync_interval: int
    last_sync: Optional[datetime] = None
    last_commit: Optional[str] = None
    quarantined: bool
    created_at: datetime
    updated_at: datetime


class WebhookEvent(BaseModel):
    """Webhook event model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    provider: Provider
    event_type: EventType
    repository_url: str
    repository_id: Optional[str] = None
    branch: Optional[str] = None
    commit_sha: Optional[str] = None
    author: Optional[str] = None
    message: Optional[str] = None
    payload: Dict[str, Any]
    signature: Optional[str] = None
    processed: bool = False
    processed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class WebhookPayload(BaseModel):
    """Webhook payload model."""
    provider: Provider
    payload: Dict[str, Any]
    signature: Optional[str] = None
    headers: Optional[Dict[str, str]] = None


class ConfigFile(BaseModel):
    """Configuration file model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    repository_id: str
    path: str
    content: str
    config: Optional[Dict[str, Any]] = None
    config_type: ConfigType
    version: int = 1
    commit_sha: Optional[str] = None
    author: Optional[str] = None
    validated: bool = False
    validation_errors: Optional[List[str]] = None
    compliance_status: Optional[Dict[str, Any]] = None
    encrypted: bool = False
    created_at: datetime
    updated_at: datetime


class ConfigSyncRequest(BaseModel):
    """Configuration sync request."""
    repository_id: str
    branch: Optional[str] = None
    force: bool = False
    validate: bool = True
    dry_run: bool = False


class ConfigSyncResponse(BaseModel):
    """Configuration sync response."""
    repository_id: str
    branch: str
    files_synced: List[str]
    files_failed: List[Dict[str, str]]
    validation_errors: List[Dict[str, Any]]
    sync_time: datetime
    duration_seconds: float


class ConfigValidationRequest(BaseModel):
    """Configuration validation request."""
    config: Dict[str, Any]
    config_type: ConfigType = ConfigType.YAML
    schema: Optional[Dict[str, Any]] = None
    strict: bool = True


class ConfigValidationResponse(BaseModel):
    """Configuration validation response."""
    valid: bool
    errors: List[str] = []
    warnings: List[str] = []
    compliance: Dict[str, bool] = {}
    suggestions: List[str] = []


class CommitInfo(BaseModel):
    """Commit information model."""
    sha: str
    message: str
    author: str
    author_email: str
    timestamp: datetime
    branch: str
    signed: bool = False
    verified: bool = False
    gpg_key_id: Optional[str] = None
    files_changed: List[str] = []
    additions: int = 0
    deletions: int = 0


class CommitRequest(BaseModel):
    """Commit request model."""
    repository_id: str
    branch: str
    message: str
    files: List[Dict[str, str]]  # [{"path": "file.yaml", "content": "..."}]
    author_name: Optional[str] = None
    author_email: Optional[str] = None
    sign: bool = True


class PullRequest(BaseModel):
    """Pull request model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    repository_id: str
    number: int
    title: str
    description: str
    source_branch: str
    target_branch: str
    state: str = "open"  # open, closed, merged
    author: str
    reviewers: List[str] = []
    approved_by: List[str] = []
    labels: List[str] = []
    created_at: datetime
    updated_at: datetime
    merged_at: Optional[datetime] = None
    merge_commit_sha: Optional[str] = None


class PullRequestCreate(BaseModel):
    """Pull request creation request."""
    repository_id: str
    title: str
    description: str
    source_branch: str
    target_branch: str = "main"
    changes: Optional[List[Dict[str, Any]]] = None
    reviewers: Optional[List[str]] = None
    labels: Optional[List[str]] = None


class BranchInfo(BaseModel):
    """Branch information model."""
    name: str
    commit_sha: str
    protected: bool = False
    default: bool = False
    ahead: int = 0
    behind: int = 0
    last_commit: CommitInfo


class TagInfo(BaseModel):
    """Tag information model."""
    name: str
    commit_sha: str
    message: Optional[str] = None
    tagger: Optional[str] = None
    created_at: datetime
    signed: bool = False
    verified: bool = False


class DiffEntry(BaseModel):
    """Diff entry model."""
    path: str
    action: str  # added, modified, deleted, renamed
    old_path: Optional[str] = None  # For renamed files
    additions: int = 0
    deletions: int = 0
    binary: bool = False
    diff: Optional[str] = None


class ComparisonResult(BaseModel):
    """Comparison result between branches/commits."""
    base: str
    compare: str
    ahead_by: int
    behind_by: int
    total_commits: int
    files_changed: int
    additions: int
    deletions: int
    diffs: List[DiffEntry]


class SecretScanResult(BaseModel):
    """Secret scan result model."""
    file_path: str
    line_number: int
    secret_type: str
    confidence: float
    matched_pattern: str
    remediation: str
    severity: str  # critical, high, medium, low


class ComplianceCheck(BaseModel):
    """Compliance check result model."""
    name: str
    passed: bool
    message: str
    severity: str  # critical, high, medium, low
    details: Optional[Dict[str, Any]] = None


class ValidationResult(BaseModel):
    """Configuration validation result."""
    config_path: str
    valid: bool
    schema_valid: bool
    syntax_valid: bool
    business_rules_valid: bool
    security_compliant: bool
    errors: List[str] = []
    warnings: List[str] = []
    compliance_checks: List[ComplianceCheck] = []
    secret_scan_results: List[SecretScanResult] = []


class SyncStatus(BaseModel):
    """Repository sync status."""
    repository_id: str
    syncing: bool
    last_sync: Optional[datetime] = None
    next_sync: Optional[datetime] = None
    last_error: Optional[str] = None
    consecutive_failures: int = 0
    files_synced: int = 0
    files_pending: int = 0


class GitCredentials(BaseModel):
    """Git credentials model."""
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    private_key: Optional[str] = None
    public_key: Optional[str] = None
    passphrase: Optional[str] = None

    @validator('private_key')
    def validate_private_key(cls, v):
        if v and not (v.startswith('-----BEGIN') and 'PRIVATE KEY-----' in v):
            raise ValueError('Invalid private key format')
        return v


class WebhookConfig(BaseModel):
    """Webhook configuration model."""
    url: str
    events: List[EventType]
    secret: str
    active: bool = True
    ssl_verification: bool = True
    content_type: str = "json"  # json, form


class CloneOptions(BaseModel):
    """Repository clone options."""
    depth: Optional[int] = None  # Shallow clone depth
    single_branch: bool = False
    no_checkout: bool = False
    mirror: bool = False
    bare: bool = False
    recurse_submodules: bool = False
    tags: bool = True