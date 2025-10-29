from typing import Optional, Any, Dict
import traceback
import logging

logger = logging.getLogger(__name__)


class CatNetError(Exception):
    """Base exception for CatNet"""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None, code: Optional[str] = None):
        self.message = message
        self.details = details or {}
        self.code = code or self.__class__.__name__
        super().__init__(self.message)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error": self.code,
            "message": self.message,
            "details": self.details
        }


class SecurityError(CatNetError):
    """Security-related errors"""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details, "SECURITY_ERROR")
        logger.critical(f"Security error: {message}", extra={"details": details})


class AuthenticationError(SecurityError):
    """Authentication failures"""
    def __init__(self, message: str = "Authentication failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details)
        self.code = "AUTH_ERROR"


class AuthorizationError(SecurityError):
    """Authorization failures"""
    def __init__(self, message: str = "Insufficient permissions", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details)
        self.code = "AUTHZ_ERROR"


class MFARequiredError(AuthenticationError):
    """MFA verification required"""
    def __init__(self, message: str = "MFA verification required", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details)
        self.code = "MFA_REQUIRED"


class DeploymentError(CatNetError):
    """Deployment-related errors"""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details, "DEPLOYMENT_ERROR")
        logger.error(f"Deployment error: {message}", extra={"details": details})


class DeploymentFailed(DeploymentError):
    """Deployment execution failed"""
    def __init__(self, message: str, device_id: Optional[str] = None, stage: Optional[str] = None):
        details = {}
        if device_id:
            details["device_id"] = device_id
        if stage:
            details["stage"] = stage
        super().__init__(message, details)
        self.code = "DEPLOYMENT_FAILED"


class RollbackError(DeploymentError):
    """Rollback operation failed"""
    def __init__(self, message: str, deployment_id: str, reason: Optional[str] = None):
        details = {"deployment_id": deployment_id}
        if reason:
            details["reason"] = reason
        super().__init__(message, details)
        self.code = "ROLLBACK_ERROR"


class ValidationError(CatNetError):
    """Validation errors"""
    def __init__(self, message: str, field: Optional[str] = None, value: Optional[Any] = None):
        details = {}
        if field:
            details["field"] = field
        if value is not None:
            details["value"] = str(value)
        super().__init__(message, details, "VALIDATION_ERROR")


class ConfigurationError(ValidationError):
    """Configuration validation errors"""
    def __init__(self, message: str, config_section: Optional[str] = None):
        super().__init__(message)
        if config_section:
            self.details["config_section"] = config_section
        self.code = "CONFIG_ERROR"


class DeviceConnectionError(CatNetError):
    """Device connection failures"""
    def __init__(self, message: str, device_id: str, vendor: Optional[str] = None):
        details = {"device_id": device_id}
        if vendor:
            details["vendor"] = vendor
        super().__init__(message, details, "DEVICE_CONNECTION_ERROR")


class DeviceTimeoutError(DeviceConnectionError):
    """Device operation timeout"""
    def __init__(self, device_id: str, operation: str, timeout: int):
        message = f"Device {device_id} timed out during {operation} (timeout: {timeout}s)"
        super().__init__(message, device_id)
        self.details["operation"] = operation
        self.details["timeout"] = timeout
        self.code = "DEVICE_TIMEOUT"


class GitOperationError(CatNetError):
    """Git operation failures"""
    def __init__(self, message: str, repository: Optional[str] = None, operation: Optional[str] = None):
        details = {}
        if repository:
            details["repository"] = repository
        if operation:
            details["operation"] = operation
        super().__init__(message, details, "GIT_ERROR")


class WebhookVerificationError(SecurityError):
    """Webhook signature verification failed"""
    def __init__(self, message: str = "Webhook signature verification failed", source: Optional[str] = None):
        details = {}
        if source:
            details["source"] = source
        super().__init__(message, details)
        self.code = "WEBHOOK_VERIFICATION_ERROR"


class VaultError(CatNetError):
    """HashiCorp Vault operation failures"""
    def __init__(self, message: str, operation: Optional[str] = None):
        details = {}
        if operation:
            details["operation"] = operation
        super().__init__(message, details, "VAULT_ERROR")


class EncryptionError(SecurityError):
    """Encryption/Decryption failures"""
    def __init__(self, message: str, algorithm: Optional[str] = None):
        details = {}
        if algorithm:
            details["algorithm"] = algorithm
        super().__init__(message, details)
        self.code = "ENCRYPTION_ERROR"


class AuditError(CatNetError):
    """Audit logging failures"""
    def __init__(self, message: str, event_type: Optional[str] = None):
        details = {}
        if event_type:
            details["event_type"] = event_type
        super().__init__(message, details, "AUDIT_ERROR")
        logger.critical(f"Audit logging failed: {message}")


class RateLimitError(CatNetError):
    """Rate limit exceeded"""
    def __init__(self, message: str = "Rate limit exceeded", limit: Optional[int] = None, window: Optional[str] = None):
        details = {}
        if limit:
            details["limit"] = limit
        if window:
            details["window"] = window
        super().__init__(message, details, "RATE_LIMIT_ERROR")


class DatabaseError(CatNetError):
    """Database operation failures"""
    def __init__(self, message: str, operation: Optional[str] = None):
        details = {}
        if operation:
            details["operation"] = operation
        super().__init__(message, details, "DATABASE_ERROR")


class MessageQueueError(CatNetError):
    """Message queue operation failures"""
    def __init__(self, message: str, queue: Optional[str] = None):
        details = {}
        if queue:
            details["queue"] = queue
        super().__init__(message, details, "MESSAGE_QUEUE_ERROR")


class CertificateError(SecurityError):
    """Certificate validation failures"""
    def __init__(self, message: str, subject: Optional[str] = None):
        details = {}
        if subject:
            details["subject"] = subject
        super().__init__(message, details)
        self.code = "CERTIFICATE_ERROR"


class SecretScanError(SecurityError):
    """Secrets detected in configuration"""
    def __init__(self, message: str = "Secrets detected in configuration", locations: Optional[List[str]] = None):
        details = {}
        if locations:
            details["locations"] = locations
        super().__init__(message, details)
        self.code = "SECRET_SCAN_ERROR"


class BusinessRuleViolation(ValidationError):
    """Business rule violation"""
    def __init__(self, message: str, rule: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.details["rule"] = rule
        if context:
            self.details["context"] = context
        self.code = "BUSINESS_RULE_VIOLATION"


class ConflictError(CatNetError):
    """Resource conflict errors"""
    def __init__(self, message: str, resource_type: str, resource_id: str):
        details = {
            "resource_type": resource_type,
            "resource_id": resource_id
        }
        super().__init__(message, details, "CONFLICT_ERROR")


class ResourceNotFoundError(CatNetError):
    """Resource not found"""
    def __init__(self, resource_type: str, resource_id: str):
        message = f"{resource_type} with ID {resource_id} not found"
        details = {
            "resource_type": resource_type,
            "resource_id": resource_id
        }
        super().__init__(message, details, "NOT_FOUND")


class ServiceUnavailableError(CatNetError):
    """Service temporarily unavailable"""
    def __init__(self, service: str, reason: Optional[str] = None):
        message = f"Service {service} is temporarily unavailable"
        if reason:
            message += f": {reason}"
        details = {"service": service}
        if reason:
            details["reason"] = reason
        super().__init__(message, details, "SERVICE_UNAVAILABLE")


class UnauthorizedException(AuthorizationError):
    """Alias for authorization error"""
    pass


def handle_errors(func):
    """Decorator for consistent error handling"""
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except SecurityError as e:
            logger.critical(f"Security incident in {func.__name__}: {e.message}",
                          extra={"traceback": traceback.format_exc()})
            raise
        except DeploymentError as e:
            logger.error(f"Deployment failure in {func.__name__}: {e.message}",
                        extra={"traceback": traceback.format_exc()})
            raise
        except ValidationError as e:
            logger.warning(f"Validation error in {func.__name__}: {e.message}")
            raise
        except CatNetError as e:
            logger.error(f"CatNet error in {func.__name__}: {e.message}",
                        extra={"traceback": traceback.format_exc()})
            raise
        except Exception as e:
            logger.exception(f"Unexpected error in {func.__name__}")
            raise CatNetError("Operation failed", {"original_error": str(e)})
    return wrapper

class DeploymentNotFoundError(DeploymentError):
    """Deployment not found in database."""
    def __init__(self, deployment_id: str):
        message = (
            f"Deployment {deployment_id} not found. "
            "Verify the deployment ID or check your permissions. "
            "Use 'catnet deployments list' to see available deployments."
        )
        super().__init__(message, {"deployment_id": deployment_id})
        self.code = "DEPLOYMENT_NOT_FOUND"
        self.deployment_id = deployment_id


class DeploymentStateError(DeploymentError):
    """Deployment is in invalid state for requested operation."""
    def __init__(
        self,
        deployment_id: str,
        current_state: str,
        required_state: str,
        operation: str
    ):
        message = (
            f"Cannot {operation} deployment {deployment_id}. "
            f"Current state: {current_state}, required state: {required_state}. "
            f"Check deployment status with: catnet deployment status {deployment_id}"
        )
        details = {
            "deployment_id": deployment_id,
            "current_state": current_state,
            "required_state": required_state,
            "operation": operation
        }
        super().__init__(message, details)
        self.code = "DEPLOYMENT_STATE_ERROR"
        self.deployment_id = deployment_id
        self.current_state = current_state
        self.required_state = required_state


class DeviceNotFoundError(DeviceConnectionError):
    """Device not found in inventory."""
    def __init__(self, device_id: str):
        message = (
            f"Device {device_id} not found in inventory. "
            "Verify the device ID or check if device was decommissioned. "
            "Use 'catnet devices list' to see available devices."
        )
        super().__init__(message, device_id)
        self.code = "DEVICE_NOT_FOUND"


class SecretExposedError(SecurityError):
    """CRITICAL: Secrets detected in Git commit."""
    def __init__(
        self,
        repository: str,
        commit_hash: str,
        secrets_found: List[str],
        affected_files: List[str]
    ):
        message = (
            f"SECURITY ALERT: {len(secrets_found)} secret(s) detected in commit {commit_hash}. "
            f"Repository: {repository}. Commit has been quarantined. "
            "Immediate action required: 1) Rotate exposed credentials, "
            "2) Remove secrets from Git history, 3) Review security procedures."
        )
        details = {
            "repository": repository,
            "commit_hash": commit_hash,
            "secrets_count": len(secrets_found),
            "affected_files": affected_files,
            "severity": "CRITICAL"
        }
        super().__init__(message, details)
        self.code = "SECRET_EXPOSED"
        self.repository = repository
        self.commit_hash = commit_hash
        self.secrets_found = secrets_found
