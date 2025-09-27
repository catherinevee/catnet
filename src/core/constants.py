from enum import Enum, IntEnum


class DeploymentState(str, Enum):
    """Deployment state enumeration"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    VALIDATING = "validating"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    DEPLOYING = "deploying"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    CANCELLED = "cancelled"


class DeploymentStrategy(str, Enum):
    """Deployment strategy types"""
    CANARY = "canary"
    ROLLING = "rolling"
    BLUE_GREEN = "blue_green"
    ALL_AT_ONCE = "all_at_once"


class DeviceVendor(str, Enum):
    """Supported network device vendors"""
    CISCO_IOS = "cisco_ios"
    CISCO_IOS_XE = "cisco_ios_xe"
    CISCO_NX_OS = "cisco_nx_os"
    JUNIPER_JUNOS = "juniper_junos"
    ARISTA_EOS = "arista_eos"


class DeviceConnectionType(str, Enum):
    """Device connection types"""
    SSH = "ssh"
    TELNET = "telnet"
    NETCONF = "netconf"
    RESTCONF = "restconf"
    GRPC = "grpc"


class AuthMethod(str, Enum):
    """Authentication methods"""
    LOCAL = "local"
    LDAP = "ldap"
    OAUTH2 = "oauth2"
    SAML = "saml"
    MFA = "mfa"
    CERTIFICATE = "certificate"


class AuditEventType(str, Enum):
    """Audit event types"""
    LOGIN = "login"
    LOGOUT = "logout"
    MFA_VERIFY = "mfa_verify"
    DEPLOYMENT_CREATE = "deployment_create"
    DEPLOYMENT_APPROVE = "deployment_approve"
    DEPLOYMENT_REJECT = "deployment_reject"
    DEPLOYMENT_EXECUTE = "deployment_execute"
    DEPLOYMENT_ROLLBACK = "deployment_rollback"
    DEVICE_CONNECT = "device_connect"
    DEVICE_DISCONNECT = "device_disconnect"
    DEVICE_BACKUP = "device_backup"
    CONFIG_CHANGE = "config_change"
    SECURITY_VIOLATION = "security_violation"
    ACCESS_DENIED = "access_denied"
    SECRET_ACCESS = "secret_access"


class PermissionLevel(IntEnum):
    """Permission levels for role-based access control"""
    NONE = 0
    READ = 10
    WRITE = 20
    EXECUTE = 30
    APPROVE = 40
    ADMIN = 100


class ConfigValidationLevel(str, Enum):
    """Configuration validation severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class GitEventType(str, Enum):
    """Git webhook event types"""
    PUSH = "push"
    PULL_REQUEST = "pull_request"
    MERGE = "merge"
    TAG = "tag"
    RELEASE = "release"


class EncryptionAlgorithm(str, Enum):
    """Supported encryption algorithms"""
    AES_256_GCM = "AES-256-GCM"
    AES_256_CBC = "AES-256-CBC"
    CHACHA20_POLY1305 = "ChaCha20-Poly1305"


class HashAlgorithm(str, Enum):
    """Supported hash algorithms"""
    SHA256 = "SHA256"
    SHA384 = "SHA384"
    SHA512 = "SHA512"
    BLAKE2B = "BLAKE2b"


class SessionState(str, Enum):
    """Session states"""
    ACTIVE = "active"
    IDLE = "idle"
    EXPIRED = "expired"
    TERMINATED = "terminated"


class BackupType(str, Enum):
    """Configuration backup types"""
    MANUAL = "manual"
    SCHEDULED = "scheduled"
    PRE_DEPLOYMENT = "pre_deployment"
    POST_DEPLOYMENT = "post_deployment"
    EMERGENCY = "emergency"


class NotificationChannel(str, Enum):
    """Notification delivery channels"""
    EMAIL = "email"
    SLACK = "slack"
    TEAMS = "teams"
    WEBHOOK = "webhook"
    SMS = "sms"
    PAGERDUTY = "pagerduty"


class HealthCheckStatus(str, Enum):
    """Health check statuses"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class TaskStatus(str, Enum):
    """Background task status"""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRYING = "retrying"


# Configuration limits
MAX_CONFIG_SIZE_BYTES = 10 * 1024 * 1024  # 10MB
MAX_DEVICES_PER_DEPLOYMENT = 1000
MAX_PARALLEL_CONNECTIONS = 50
MAX_RETRY_ATTEMPTS = 3
MAX_ROLLBACK_HISTORY = 10

# Timeouts (seconds)
DEFAULT_CONNECTION_TIMEOUT = 30
DEFAULT_COMMAND_TIMEOUT = 60
DEFAULT_DEPLOYMENT_TIMEOUT = 3600  # 1 hour
DEFAULT_ROLLBACK_TIMEOUT = 300  # 5 minutes
DEFAULT_HEALTH_CHECK_TIMEOUT = 10

# Security constants
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
PASSWORD_EXPIRY_DAYS = 90
SESSION_EXPIRY_MINUTES = 30
MFA_TOKEN_LENGTH = 6
MFA_TOKEN_EXPIRY_SECONDS = 30
JWT_EXPIRY_MINUTES = 30
API_KEY_LENGTH = 32

# Rate limiting
DEFAULT_RATE_LIMIT = 100
DEFAULT_RATE_WINDOW_MINUTES = 1
BURST_RATE_LIMIT = 10

# Audit retention
AUDIT_LOG_RETENTION_DAYS = 2555  # 7 years
SESSION_RECORDING_RETENTION_DAYS = 90

# Backup retention
DEFAULT_BACKUP_RETENTION_COUNT = 100
EMERGENCY_BACKUP_RETENTION_DAYS = 30

# Vendor-specific command templates
CISCO_IOS_COMMANDS = {
    "backup": "show running-config",
    "save": "write memory",
    "rollback": "configure replace flash:backup.cfg force",
    "health_check": "show version",
    "interface_status": "show ip interface brief",
}

CISCO_NXOS_COMMANDS = {
    "backup": "show running-config",
    "save": "copy running-config startup-config",
    "rollback": "rollback running-config checkpoint {checkpoint}",
    "health_check": "show version",
    "interface_status": "show interface brief",
}

JUNIPER_JUNOS_COMMANDS = {
    "backup": "show configuration | display set",
    "save": "commit",
    "rollback": "rollback {rollback_id}",
    "health_check": "show version",
    "interface_status": "show interfaces terse",
}

# Regular expressions for validation
import re

# Regex patterns for validation
IPV4_REGEX = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

IPV6_REGEX = re.compile(
    r'^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|'
    r'([0-9a-fA-F]{1,4}:){1,7}:|'
    r'([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
    r'([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|'
    r'([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|'
    r'([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|'
    r'([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|'
    r'[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'
    r':((:[0-9a-fA-F]{1,4}){1,7}|:)|'
    r'fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'
    r'::(ffff(:0{1,4}){0,1}:){0,1}'
    r'((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'
    r'(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|'
    r'([0-9a-fA-F]{1,4}:){1,4}:'
    r'((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'
    r'(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$'
)

HOSTNAME_REGEX = re.compile(
    r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)'
    r'(\.[A-Za-z0-9-]{1,63})*$'
)

# Secret scanning patterns (simplified for security)
SECRET_PATTERNS = [
    re.compile(r'password\s*=\s*["\']?[^\s"\']+', re.IGNORECASE),
    re.compile(r'secret\s*=\s*["\']?[^\s"\']+', re.IGNORECASE),
    re.compile(r'api[_-]?key\s*=\s*["\']?[^\s"\']+', re.IGNORECASE),
    re.compile(r'token\s*=\s*["\']?[^\s"\']+', re.IGNORECASE),
    re.compile(r'private[_-]?key\s*=\s*["\']?[^\s"\']+', re.IGNORECASE),
]

# HTTP Status codes
HTTP_200_OK = 200
HTTP_201_CREATED = 201
HTTP_202_ACCEPTED = 202
HTTP_204_NO_CONTENT = 204
HTTP_400_BAD_REQUEST = 400
HTTP_401_UNAUTHORIZED = 401
HTTP_403_FORBIDDEN = 403
HTTP_404_NOT_FOUND = 404
HTTP_409_CONFLICT = 409
HTTP_422_UNPROCESSABLE_ENTITY = 422
HTTP_429_TOO_MANY_REQUESTS = 429
HTTP_500_INTERNAL_SERVER_ERROR = 500
HTTP_502_BAD_GATEWAY = 502
HTTP_503_SERVICE_UNAVAILABLE = 503

# Database table names
TABLE_USERS = "users"
TABLE_DEPLOYMENTS = "deployments"
TABLE_DEVICES = "devices"
TABLE_CONFIGURATIONS = "configurations"
TABLE_AUDIT_LOGS = "audit_logs"
TABLE_SESSIONS = "sessions"
TABLE_GIT_REPOSITORIES = "git_repositories"
TABLE_DEVICE_CONFIGS = "device_configs"
TABLE_BACKUPS = "backups"
TABLE_TASKS = "tasks"