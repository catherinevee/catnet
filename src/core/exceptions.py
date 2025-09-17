"""
CatNet Custom Exceptions
Following CLAUDE.md error handling patterns
"""


class CatNetError(Exception):
    """Base exception for CatNet"""

    pass


class SecurityError(CatNetError):
    """Security-related errors"""

    pass


class DeploymentError(CatNetError):
    """Deployment-related errors"""

    pass


class ValidationError(CatNetError):
    """Configuration validation errors"""

    pass


class DeviceConnectionError(CatNetError):
    """Device connection errors"""

    pass


class GitOpsError(CatNetError):
    """GitOps operation errors"""

    pass


class RollbackError(DeploymentError):
    """Rollback operation errors"""

    pass


class AuthenticationError(SecurityError):
    """Authentication failures"""

    pass


class AuthorizationError(SecurityError):
    """Authorization failures"""

    pass


class EncryptionError(SecurityError):
    """Encryption/decryption errors"""

    pass


class VaultError(SecurityError):
    """Vault operation errors"""

    pass


class WebhookVerificationError(SecurityError):
    """Webhook signature verification errors"""

    pass


class ConfigurationDriftError(ValidationError):
    """Configuration drift detected"""

    pass


class ComplianceError(ValidationError):
    """Compliance validation failures"""

    pass
