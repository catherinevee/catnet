"""
Unit tests for core exceptions module
Tests custom exception classes and error handling
"""

import pytest
from unittest.mock import patch, Mock
import logging

from src.core.exceptions import (
    CatNetError, SecurityError, AuthenticationError, AuthorizationError,
    MFARequiredError, DeploymentError, DeploymentFailed, RollbackError,
    ValidationError, ConfigurationError, DeviceConnectionError, DeviceTimeoutError,
    GitOperationError, WebhookVerificationError, VaultError, EncryptionError,
    AuditError, RateLimitError, DatabaseError, MessageQueueError,
    CertificateError, SecretScanError, BusinessRuleViolation, ConflictError,
    ResourceNotFoundError, ServiceUnavailableError, UnauthorizedException,
    handle_errors
)


class TestCatNetError:
    """Test base CatNetError exception."""

    def test_basic_catnet_error(self):
        """Test basic CatNetError creation."""
        error = CatNetError("Test error message")

        assert str(error) == "Test error message"
        assert error.message == "Test error message"
        assert error.details == {}
        assert error.code == "CatNetError"

    def test_catnet_error_with_details(self):
        """Test CatNetError with details."""
        details = {"user_id": "user_123", "action": "login"}
        error = CatNetError("Login failed", details=details)

        assert error.details == details
        assert error.details['user_id'] == "user_123"

    def test_catnet_error_with_custom_code(self):
        """Test CatNetError with custom error code."""
        error = CatNetError("Custom error", code="CUSTOM_ERROR_CODE")

        assert error.code == "CUSTOM_ERROR_CODE"

    def test_catnet_error_to_dict(self):
        """Test CatNetError to_dict method."""
        details = {"field": "email", "value": "invalid"}
        error = CatNetError("Validation failed", details=details, code="VAL_ERROR")

        error_dict = error.to_dict()

        assert error_dict['error'] == 'VAL_ERROR'
        assert error_dict['message'] == 'Validation failed'
        assert error_dict['details'] == details


class TestSecurityErrors:
    """Test security-related exceptions."""

    def test_security_error(self, caplog):
        """Test SecurityError creation and logging."""
        with caplog.at_level(logging.CRITICAL):
            error = SecurityError("Unauthorized access attempt")

            assert error.message == "Unauthorized access attempt"
            assert error.code == "SECURITY_ERROR"
            assert "Security error: Unauthorized access attempt" in caplog.text

    def test_authentication_error(self, caplog):
        """Test AuthenticationError."""
        with caplog.at_level(logging.CRITICAL):
            error = AuthenticationError()

            assert error.message == "Authentication failed"
            assert error.code == "AUTH_ERROR"

    def test_authentication_error_custom_message(self):
        """Test AuthenticationError with custom message."""
        error = AuthenticationError("Invalid credentials")

        assert error.message == "Invalid credentials"
        assert error.code == "AUTH_ERROR"

    def test_authorization_error(self):
        """Test AuthorizationError."""
        error = AuthorizationError()

        assert error.message == "Insufficient permissions"
        assert error.code == "AUTHZ_ERROR"

    def test_mfa_required_error(self):
        """Test MFARequiredError."""
        error = MFARequiredError()

        assert error.message == "MFA verification required"
        assert error.code == "MFA_REQUIRED"

    def test_mfa_required_error_with_details(self):
        """Test MFARequiredError with details."""
        details = {"user_id": "user_123", "mfa_type": "totp"}
        error = MFARequiredError("Please provide MFA code", details=details)

        assert error.details == details
        assert error.code == "MFA_REQUIRED"


class TestDeploymentErrors:
    """Test deployment-related exceptions."""

    def test_deployment_error(self, caplog):
        """Test DeploymentError creation and logging."""
        with caplog.at_level(logging.ERROR):
            error = DeploymentError("Deployment validation failed")

            assert error.message == "Deployment validation failed"
            assert error.code == "DEPLOYMENT_ERROR"
            assert "Deployment error: Deployment validation failed" in caplog.text

    def test_deployment_failed(self):
        """Test DeploymentFailed exception."""
        error = DeploymentFailed(
            "Configuration push failed",
            device_id="device_001",
            stage="canary_5"
        )

        assert error.message == "Configuration push failed"
        assert error.code == "DEPLOYMENT_FAILED"
        assert error.details['device_id'] == "device_001"
        assert error.details['stage'] == "canary_5"

    def test_deployment_failed_without_optional_params(self):
        """Test DeploymentFailed without optional parameters."""
        error = DeploymentFailed("Deployment failed")

        assert error.details == {}

    def test_rollback_error(self):
        """Test RollbackError exception."""
        error = RollbackError(
            "Rollback failed",
            deployment_id="deploy_123",
            reason="Backup not found"
        )

        assert error.message == "Rollback failed"
        assert error.code == "ROLLBACK_ERROR"
        assert error.details['deployment_id'] == "deploy_123"
        assert error.details['reason'] == "Backup not found"


class TestValidationErrors:
    """Test validation-related exceptions."""

    def test_validation_error(self):
        """Test ValidationError creation."""
        error = ValidationError("Invalid email format")

        assert error.message == "Invalid email format"
        assert error.code == "VALIDATION_ERROR"

    def test_validation_error_with_field(self):
        """Test ValidationError with field information."""
        error = ValidationError(
            "Invalid email format",
            field="email",
            value="not-an-email"
        )

        assert error.details['field'] == "email"
        assert error.details['value'] == "not-an-email"

    def test_configuration_error(self):
        """Test ConfigurationError."""
        error = ConfigurationError(
            "Missing required setting",
            config_section="database"
        )

        assert error.message == "Missing required setting"
        assert error.code == "CONFIG_ERROR"
        assert error.details['config_section'] == "database"


class TestDeviceErrors:
    """Test device-related exceptions."""

    def test_device_connection_error(self):
        """Test DeviceConnectionError."""
        error = DeviceConnectionError(
            "SSH connection refused",
            device_id="device_001",
            vendor="cisco"
        )

        assert error.message == "SSH connection refused"
        assert error.code == "DEVICE_CONNECTION_ERROR"
        assert error.details['device_id'] == "device_001"
        assert error.details['vendor'] == "cisco"

    def test_device_timeout_error(self):
        """Test DeviceTimeoutError."""
        error = DeviceTimeoutError(
            device_id="device_002",
            operation="config_backup",
            timeout=60
        )

        assert "timed out during config_backup" in error.message
        assert error.code == "DEVICE_TIMEOUT"
        assert error.details['operation'] == "config_backup"
        assert error.details['timeout'] == 60


class TestGitErrors:
    """Test Git operation exceptions."""

    def test_git_operation_error(self):
        """Test GitOperationError."""
        error = GitOperationError(
            "Failed to clone repository",
            repository="https://github.com/example/repo.git",
            operation="clone"
        )

        assert error.message == "Failed to clone repository"
        assert error.code == "GIT_ERROR"
        assert error.details['repository'] == "https://github.com/example/repo.git"
        assert error.details['operation'] == "clone"

    def test_webhook_verification_error(self):
        """Test WebhookVerificationError."""
        error = WebhookVerificationError(source="github")

        assert error.message == "Webhook signature verification failed"
        assert error.code == "WEBHOOK_VERIFICATION_ERROR"
        assert error.details['source'] == "github"


class TestVaultAndEncryptionErrors:
    """Test Vault and encryption exceptions."""

    def test_vault_error(self):
        """Test VaultError."""
        error = VaultError(
            "Failed to retrieve secret",
            operation="read_secret"
        )

        assert error.message == "Failed to retrieve secret"
        assert error.code == "VAULT_ERROR"
        assert error.details['operation'] == "read_secret"

    def test_encryption_error(self):
        """Test EncryptionError."""
        error = EncryptionError(
            "Decryption failed",
            algorithm="AES-256-GCM"
        )

        assert error.message == "Decryption failed"
        assert error.code == "ENCRYPTION_ERROR"
        assert error.details['algorithm'] == "AES-256-GCM"


class TestAuditAndRateLimitErrors:
    """Test audit and rate limiting exceptions."""

    def test_audit_error(self, caplog):
        """Test AuditError creation and critical logging."""
        with caplog.at_level(logging.CRITICAL):
            error = AuditError(
                "Audit log write failed",
                event_type="user_login"
            )

            assert error.message == "Audit log write failed"
            assert error.code == "AUDIT_ERROR"
            assert error.details['event_type'] == "user_login"
            assert "Audit logging failed" in caplog.text

    def test_rate_limit_error(self):
        """Test RateLimitError."""
        error = RateLimitError(limit=100, window="1 minute")

        assert error.message == "Rate limit exceeded"
        assert error.code == "RATE_LIMIT_ERROR"
        assert error.details['limit'] == 100
        assert error.details['window'] == "1 minute"


class TestDatabaseAndMessageQueueErrors:
    """Test database and message queue exceptions."""

    def test_database_error(self):
        """Test DatabaseError."""
        error = DatabaseError(
            "Connection pool exhausted",
            operation="query"
        )

        assert error.message == "Connection pool exhausted"
        assert error.code == "DATABASE_ERROR"
        assert error.details['operation'] == "query"

    def test_message_queue_error(self):
        """Test MessageQueueError."""
        error = MessageQueueError(
            "Failed to publish message",
            queue="deployments"
        )

        assert error.message == "Failed to publish message"
        assert error.code == "MESSAGE_QUEUE_ERROR"
        assert error.details['queue'] == "deployments"


class TestCertificateAndSecretErrors:
    """Test certificate and secret scanning exceptions."""

    def test_certificate_error(self):
        """Test CertificateError."""
        error = CertificateError(
            "Certificate expired",
            subject="CN=device001.example.com"
        )

        assert error.message == "Certificate expired"
        assert error.code == "CERTIFICATE_ERROR"
        assert error.details['subject'] == "CN=device001.example.com"

    def test_secret_scan_error(self):
        """Test SecretScanError."""
        locations = ["config.yaml:line 42", "deploy.sh:line 15"]
        error = SecretScanError(locations=locations)

        assert error.message == "Secrets detected in configuration"
        assert error.code == "SECRET_SCAN_ERROR"
        assert error.details['locations'] == locations


class TestBusinessAndResourceErrors:
    """Test business rule and resource exceptions."""

    def test_business_rule_violation(self):
        """Test BusinessRuleViolation."""
        context = {"deployment_time": "outside_window"}
        error = BusinessRuleViolation(
            "Deployment not allowed during business hours",
            rule="deployment_window",
            context=context
        )

        assert error.code == "BUSINESS_RULE_VIOLATION"
        assert error.details['rule'] == "deployment_window"
        assert error.details['context'] == context

    def test_conflict_error(self):
        """Test ConflictError."""
        error = ConflictError(
            "Resource already exists",
            resource_type="Device",
            resource_id="device_001"
        )

        assert error.message == "Resource already exists"
        assert error.code == "CONFLICT_ERROR"
        assert error.details['resource_type'] == "Device"
        assert error.details['resource_id'] == "device_001"

    def test_resource_not_found_error(self):
        """Test ResourceNotFoundError."""
        error = ResourceNotFoundError(
            resource_type="Deployment",
            resource_id="deploy_999"
        )

        assert "Deployment with ID deploy_999 not found" in error.message
        assert error.code == "NOT_FOUND"
        assert error.details['resource_type'] == "Deployment"
        assert error.details['resource_id'] == "deploy_999"

    def test_service_unavailable_error(self):
        """Test ServiceUnavailableError."""
        error = ServiceUnavailableError(
            service="vault",
            reason="Connection timeout"
        )

        assert "Service vault is temporarily unavailable" in error.message
        assert "Connection timeout" in error.message
        assert error.code == "SERVICE_UNAVAILABLE"
        assert error.details['service'] == "vault"
        assert error.details['reason'] == "Connection timeout"


class TestUnauthorizedException:
    """Test UnauthorizedException alias."""

    def test_unauthorized_exception_is_authorization_error(self):
        """Test UnauthorizedException is an alias for AuthorizationError."""
        error = UnauthorizedException("Access denied")

        assert isinstance(error, AuthorizationError)
        assert error.message == "Access denied"


class TestHandleErrorsDecorator:
    """Test handle_errors decorator."""

    @pytest.mark.asyncio
    async def test_handle_errors_no_exception(self):
        """Test handle_errors when no exception is raised."""
        @handle_errors
        async def successful_function():
            return "success"

        result = await successful_function()
        assert result == "success"

    @pytest.mark.asyncio
    async def test_handle_errors_security_error(self, caplog):
        """Test handle_errors with SecurityError."""
        @handle_errors
        async def function_with_security_error():
            raise SecurityError("Security incident")

        with caplog.at_level(logging.CRITICAL):
            with pytest.raises(SecurityError) as exc_info:
                await function_with_security_error()

            assert "Security incident in function_with_security_error" in caplog.text

    @pytest.mark.asyncio
    async def test_handle_errors_deployment_error(self, caplog):
        """Test handle_errors with DeploymentError."""
        @handle_errors
        async def function_with_deployment_error():
            raise DeploymentError("Deployment failed")

        with caplog.at_level(logging.ERROR):
            with pytest.raises(DeploymentError):
                await function_with_deployment_error()

            assert "Deployment failure in function_with_deployment_error" in caplog.text

    @pytest.mark.asyncio
    async def test_handle_errors_validation_error(self, caplog):
        """Test handle_errors with ValidationError."""
        @handle_errors
        async def function_with_validation_error():
            raise ValidationError("Invalid input")

        with caplog.at_level(logging.WARNING):
            with pytest.raises(ValidationError):
                await function_with_validation_error()

            assert "Validation error in function_with_validation_error" in caplog.text

    @pytest.mark.asyncio
    async def test_handle_errors_catnet_error(self, caplog):
        """Test handle_errors with CatNetError."""
        @handle_errors
        async def function_with_catnet_error():
            raise CatNetError("Generic error")

        with caplog.at_level(logging.ERROR):
            with pytest.raises(CatNetError):
                await function_with_catnet_error()

            assert "CatNet error in function_with_catnet_error" in caplog.text

    @pytest.mark.asyncio
    async def test_handle_errors_unexpected_exception(self, caplog):
        """Test handle_errors with unexpected exception."""
        @handle_errors
        async def function_with_unexpected_error():
            raise ValueError("Unexpected error")

        with caplog.at_level(logging.ERROR):
            with pytest.raises(CatNetError) as exc_info:
                await function_with_unexpected_error()

            assert exc_info.value.message == "Operation failed"
            assert "Unexpected error" in caplog.text


class TestExceptionInheritance:
    """Test exception inheritance hierarchy."""

    def test_authentication_error_is_security_error(self):
        """Test AuthenticationError inherits from SecurityError."""
        error = AuthenticationError()
        assert isinstance(error, SecurityError)
        assert isinstance(error, CatNetError)

    def test_deployment_failed_is_deployment_error(self):
        """Test DeploymentFailed inherits from DeploymentError."""
        error = DeploymentFailed("Failed")
        assert isinstance(error, DeploymentError)
        assert isinstance(error, CatNetError)

    def test_configuration_error_is_validation_error(self):
        """Test ConfigurationError inherits from ValidationError."""
        error = ConfigurationError("Config invalid")
        assert isinstance(error, ValidationError)
        assert isinstance(error, CatNetError)

    def test_device_timeout_is_device_connection_error(self):
        """Test DeviceTimeoutError inherits from DeviceConnectionError."""
        error = DeviceTimeoutError("device_001", "backup", 30)
        assert isinstance(error, DeviceConnectionError)
        assert isinstance(error, CatNetError)


class TestErrorSerialization:
    """Test error serialization to dict."""

    def test_complex_error_to_dict(self):
        """Test complex error serialization."""
        details = {
            "user_id": "user_123",
            "device_id": "device_001",
            "action": "configuration_push",
            "timestamp": "2025-01-01T00:00:00Z"
        }
        error = DeploymentFailed(
            "Configuration deployment failed",
            device_id="device_001",
            stage="production"
        )
        error.details.update(details)

        error_dict = error.to_dict()

        assert error_dict['error'] == 'DEPLOYMENT_FAILED'
        assert error_dict['message'] == 'Configuration deployment failed'
        assert 'user_id' in error_dict['details']
        assert 'device_id' in error_dict['details']
        assert 'stage' in error_dict['details']
