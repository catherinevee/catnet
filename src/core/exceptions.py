"""
CatNet Custom Exceptions
Following CLAUDE.md error handling patterns
"""


class CatNetError(Exception):
    """Base exception for CatNet"""


class SecurityError(CatNetError):
    """Security-related errors"""


class DeploymentError(CatNetError):
    """Deployment-related errors"""


class ValidationError(CatNetError):
    """Configuration validation errors"""


class DeviceConnectionError(CatNetError):
    """Device connection errors"""


class GitOpsError(CatNetError):
    """GitOps operation errors"""


class RollbackError(DeploymentError):
    """Rollback operation errors"""


class AuthenticationError(SecurityError):
    """Authentication failures"""


class AuthorizationError(SecurityError):
    """Authorization failures"""


class EncryptionError(SecurityError):
    """Encryption/decryption errors"""


class VaultError(SecurityError):
    """Vault operation errors"""


class WebhookVerificationError(SecurityError):
    """Webhook signature verification errors"""


class ConfigurationDriftError(ValidationError):
    """Configuration drift detected"""


class ComplianceError(ValidationError):
    """Compliance validation failures"""
