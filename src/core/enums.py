"""
Enumerations for CatNet System
"""

from enum import Enum

class DeploymentState(Enum):
    """Deployment state enumeration"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    DEPLOYING = "deploying"
    VALIDATING = "validating"
    HEALTH_CHECK = "health_check"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    CANCELLED = "cancelled"
    PAUSED = "paused"

class DeviceVendor(Enum):
    """Supported device vendors"""
    CISCO_IOS = "cisco_ios"
    CISCO_IOSXE = "cisco_iosxe"
    CISCO_IOSXR = "cisco_iosxr"
    CISCO_NXOS = "cisco_nxos"
    CISCO_ASA = "cisco_asa"
    JUNIPER_JUNOS = "juniper_junos"
    ARISTA_EOS = "arista_eos"
    FORTINET = "fortinet"
    PALOALTO = "paloalto"

class DeploymentStrategy(Enum):
    """Deployment strategies"""
    CANARY = "canary"
    ROLLING = "rolling"
    BLUE_GREEN = "blue_green"
    IMMEDIATE = "immediate"
    ALL_AT_ONCE = "all_at_once"
    CUSTOM = "custom"

class ValidationLevel(Enum):
    """Configuration validation levels"""
    SYNTAX = "syntax"
    SEMANTIC = "semantic"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    BUSINESS = "business"
    FULL = "full"

class ApprovalType(Enum):
    """Deployment approval types"""
    TECHNICAL = "technical"
    BUSINESS = "business"
    SECURITY = "security"
    EMERGENCY = "emergency"
    AUTOMATED = "automated"

class BackupType(Enum):
    """Configuration backup types"""
    SCHEDULED = "scheduled"
    PRE_DEPLOYMENT = "pre_deployment"
    POST_DEPLOYMENT = "post_deployment"
    MANUAL = "manual"
    EMERGENCY = "emergency"
    DRIFT_DETECTION = "drift_detection"

class IncidentSeverity(Enum):
    """Security incident severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

class IncidentStatus(Enum):
    """Security incident status"""
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"

class SecurityZone(Enum):
    """Network security zones"""
    DMZ = "dmz"
    INTERNAL = "internal"
    MANAGEMENT = "management"
    PRODUCTION = "production"
    DEVELOPMENT = "development"
    STAGING = "staging"
    QUARANTINE = "quarantine"
    INTERNET = "internet"

class SecretType(Enum):
    """Types of secrets in Vault"""
    CREDENTIAL = "credential"
    API_KEY = "api_key"
    CERTIFICATE = "certificate"
    SSH_KEY = "ssh_key"
    TOKEN = "token"
    WEBHOOK_SECRET = "webhook_secret"
    ENCRYPTION_KEY = "encryption_key"
    SIGNING_KEY = "signing_key"

class CertificatePurpose(Enum):
    """Certificate usage purposes"""
    CLIENT = "client"
    SERVER = "server"
    CA = "ca"
    CODE_SIGNING = "code_signing"
    EMAIL = "email"
    MTLS = "mtls"

class HealthCheckType(Enum):
    """Types of health checks"""
    CONNECTIVITY = "connectivity"
    PERFORMANCE = "performance"
    SECURITY = "security"
    CONFIGURATION = "configuration"
    RESOURCE = "resource"
    SERVICE = "service"
    COMPLIANCE = "compliance"

class TokenType(Enum):
    """Authentication token types"""
    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"
    HARDWARE = "hardware"
    PUSH = "push"
    BIOMETRIC = "biometric"
    BACKUP_CODE = "backup_code"

class RotationPolicy(Enum):
    """Secret rotation policies"""
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    ANNUAL = "annual"
    ON_DEMAND = "on_demand"
    NEVER = "never"

class AuditAction(Enum):
    """Audit log action types"""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    DEPLOY = "deploy"
    ROLLBACK = "rollback"
    APPROVE = "approve"
    REJECT = "reject"
    LOGIN = "login"
    LOGOUT = "logout"
    EXPORT = "export"
    IMPORT = "import"
    BACKUP = "backup"
    RESTORE = "restore"
    VALIDATE = "validate"

class ConfigChangeType(Enum):
    """Types of configuration changes"""
    ADD = "add"
    MODIFY = "modify"
    DELETE = "delete"
    REPLACE = "replace"
    REORDER = "reorder"

class NotificationChannel(Enum):
    """Notification delivery channels"""
    EMAIL = "email"
    SMS = "sms"
    SLACK = "slack"
    TEAMS = "teams"
    WEBHOOK = "webhook"
    PAGERDUTY = "pagerduty"
    OPSGENIE = "opsgenie"

class ComplianceStandard(Enum):
    """Compliance standards"""
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    GDPR = "gdpr"
    CCPA = "ccpa"
    NIST = "nist"
    CIS = "cis"

class DeviceStatus(Enum):
    """Device operational status"""
    ONLINE = "online"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"
    DECOMMISSIONED = "decommissioned"

class TaskStatus(Enum):
    """Async task status"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILURE = "failure"
    RETRY = "retry"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"

class EncryptionAlgorithm(Enum):
    """Encryption algorithms"""
    AES_256_GCM = "aes_256_gcm"
    AES_256_CBC = "aes_256_cbc"
    CHACHA20_POLY1305 = "chacha20_poly1305"
    RSA_4096 = "rsa_4096"
    ED25519 = "ed25519"

class HashAlgorithm(Enum):
    """Hashing algorithms"""
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"
    BLAKE2B = "blake2b"
    ARGON2ID = "argon2id"
    BCRYPT = "bcrypt"

class RateLimitType(Enum):
    """API rate limiting types"""
    PER_USER = "per_user"
    PER_IP = "per_ip"
    PER_API_KEY = "per_api_key"
    GLOBAL = "global"

class WebhookEventType(Enum):
    """Git webhook event types"""
    PUSH = "push"
    PULL_REQUEST = "pull_request"
    MERGE = "merge"
    TAG = "tag"
    RELEASE = "release"
    BRANCH_CREATE = "branch_create"
    BRANCH_DELETE = "branch_delete"

class ValidationRuleType(Enum):
    """Configuration validation rule types"""
    REGEX = "regex"
    SCHEMA = "schema"
    CUSTOM = "custom"
    SYNTAX = "syntax"
    SEMANTIC = "semantic"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    BUSINESS = "business"

class DriftSeverity(Enum):
    """Configuration drift severity"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"