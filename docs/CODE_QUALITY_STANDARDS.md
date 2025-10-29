# CatNet Code Quality Standards

## Overview

This document defines code quality standards for the CatNet project, including documentation requirements, type hinting conventions, error handling patterns, and best practices.

## Table of Contents

- [Documentation Standards](#documentation-standards)
- [Type Hinting Requirements](#type-hinting-requirements)
- [Error Handling Patterns](#error-handling-patterns)
- [Code Style Guidelines](#code-style-guidelines)
- [Testing Requirements](#testing-requirements)
- [Security Best Practices](#security-best-practices)

## Documentation Standards

### Module-Level Docstrings

Every Python module must include a comprehensive module-level docstring:

```python
"""
Module Name and Purpose.

Detailed description of what this module does, its main responsibilities,
and how it fits into the overall application architecture.

Key Components:
    - Component1: Brief description
    - Component2: Brief description

Dependencies:
    - External services (Vault, Redis, PostgreSQL)
    - Internal modules

Security Considerations:
    - Authentication requirements
    - Authorization checks
    - Sensitive data handling

Example:
    >>> from src.module import SomeClass
    >>> instance = SomeClass()
    >>> result = instance.method()
"""
```

**Example from src/auth/authentication.py:**

```python
"""
Authentication Service for CatNet.

Handles OAuth2, SAML, MFA, JWT tokens with high security standards.
Integrates with HashiCorp Vault for secret management and supports
multiple authentication backends including LDAP/AD.

Key Components:
    - AuthenticationService: Main authentication handler
    - AuthenticationConfig: Configuration management
    - EncryptionManager: Sensitive data encryption

Dependencies:
    - Vault: Secret and credential management
    - PostgreSQL: User and session storage
    - Redis: Token blacklisting and rate limiting

Security:
    - Argon2 password hashing
    - JWT with configurable algorithms (RS256/HS256)
    - MFA support with TOTP and backup codes
    - Account lockout after failed attempts
"""
```

### Class Docstrings

All classes must include comprehensive docstrings using Google style:

```python
class DeploymentService:
    """
    Manages network configuration deployments with multi-stage approval.

    This service handles the entire deployment lifecycle including creation,
    validation, approval workflow, execution, and rollback capabilities.
    It supports multiple deployment strategies (rolling, canary, blue-green).

    Attributes:
        db: Database session for persistence
        vault: Vault client for credential management
        audit: Audit logger for compliance tracking
        encryption: Encryption service for sensitive data
        validator: Configuration validator
        rollback_manager: Handles deployment rollbacks

    Security:
        - All configurations are encrypted at rest
        - Digital signatures verify configuration integrity
        - Audit logs track all deployment activities
        - Role-based access control for approvals

    Example:
        >>> service = DeploymentService(db, vault_client, audit_logger)
        >>> deployment = await service.create_deployment(
        ...     name="ACL Update",
        ...     configs=[config1, config2],
        ...     user_id="user123",
        ...     strategy="canary"
        ... )
        >>> await service.approve_deployment(deployment['id'], "approver1")
        >>> await service.execute_deployment(deployment['id'], "executor1")

    See Also:
        - DeploymentExecutor: Handles actual deployment execution
        - RollbackManager: Manages rollback operations
        - ConfigValidator: Validates configurations before deployment
    """
```

### Method/Function Docstrings

All public methods and functions must include comprehensive docstrings:

```python
async def create_deployment(
    self,
    name: str,
    configs: List[Dict[str, Any]],
    user_id: str,
    strategy: str = "rolling",
    requires_approval: bool = True,
    approval_count_required: int = 2,
    canary_percentage: Optional[int] = None,
    max_parallel: int = 5,
    scheduled_at: Optional[datetime] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Create a new configuration deployment with approval workflow.

    This method creates a deployment record, validates all configurations,
    encrypts sensitive data, generates digital signatures, and initializes
    the approval workflow if required.

    Args:
        name: Human-readable deployment name
        configs: List of configuration dictionaries, each containing:
            - device_id: Target device UUID
            - type: Configuration type (device, vlan, acl, etc.)
            - content: Configuration content
            - sequence: Deployment sequence order (optional)
        user_id: UUID of user creating the deployment
        strategy: Deployment strategy (rolling, canary, blue_green)
        requires_approval: Whether approval workflow is required
        approval_count_required: Number of approvals needed (if required)
        canary_percentage: Percentage for canary deployments (5-100)
        max_parallel: Maximum parallel device deployments (1-50)
        scheduled_at: Future datetime for scheduled deployment
        metadata: Additional metadata for tracking/auditing

    Returns:
        Dictionary containing deployment details:
            - id: Deployment UUID
            - name: Deployment name
            - state: Current state (pending, approved, etc.)
            - created_at: Creation timestamp (ISO 8601)
            - requires_approval: Approval requirement status
            - approval_count_required: Number of approvals needed

    Raises:
        ValueError: If configs list is empty or invalid
        ValidationError: If configuration validation fails
        EncryptionError: If encryption of sensitive data fails
        DatabaseError: If database operation fails

    Security:
        - Configurations are validated before acceptance
        - All configs encrypted using Vault encryption
        - Digital signatures generated for integrity
        - Audit log entry created for compliance

    Example:
        >>> deployment = await service.create_deployment(
        ...     name="Emergency ACL Update",
        ...     configs=[
        ...         {
        ...             "device_id": "device-uuid-1",
        ...             "type": "acl",
        ...             "content": "access-list 100 permit tcp any any eq 443"
        ...         }
        ...     ],
        ...     user_id="user-123",
        ...     strategy="rolling",
        ...     requires_approval=True,
        ...     approval_count_required=2
        ... )
        >>> print(deployment['id'])
        '550e8400-e29b-41d4-a716-446655440000'

    Note:
        - Deployments with critical device targets always require approval
        - Configurations are not decrypted until deployment execution
        - Failed validations block deployment creation

    See Also:
        - approve_deployment: Approve a pending deployment
        - execute_deployment: Execute an approved deployment
        - ConfigValidator.validate_configuration: Validation logic
    """
```

### Property Docstrings

All properties should include brief but informative docstrings:

```python
@property
def is_production(self) -> bool:
    """
    Check if running in production environment.

    Returns:
        True if environment is set to "production", False otherwise.

    Example:
        >>> if settings.is_production:
        ...     # Enable strict security measures
        ...     enable_mtls()
    """
    return self.environment == "production"
```

### Validator Docstrings

Pydantic validators should explain their validation logic:

```python
@validator("canary_stages", pre=True)
def parse_canary_stages(cls, v):
    """
    Parse canary deployment stages from string or list.

    Converts comma-separated string values to list of integers.
    Allows both "5,25,50,100" and [5, 25, 50, 100] formats.

    Args:
        v: Input value (str or List[int])

    Returns:
        List of integers representing canary stage percentages

    Raises:
        ValueError: If string contains non-numeric values

    Example:
        >>> Settings(canary_stages="5,25,50,100")
        Settings(canary_stages=[5, 25, 50, 100])
    """
    if isinstance(v, str):
        return [int(x) for x in v.split(",")]
    return v
```

## Type Hinting Requirements

### Function Signatures

All function signatures must include complete type hints:

```python
from typing import Dict, List, Optional, Union, Any, Tuple
from datetime import datetime
from uuid import UUID

async def execute_rolling_deployment(
    self,
    deployment: Deployment,
    max_parallel: int = 5,
    timeout: int = 3600
) -> Dict[str, Any]:
    """Execute rolling deployment strategy."""
    pass

def validate_config(
    config: Dict[str, Any],
    vendor: str
) -> Tuple[bool, List[str]]:
    """
    Validate device configuration.

    Args:
        config: Configuration dictionary
        vendor: Device vendor (cisco, juniper, arista)

    Returns:
        Tuple of (is_valid, error_messages)
    """
    pass
```

### Complex Types

Use TypedDict or Pydantic models for complex data structures:

```python
from typing import TypedDict, Literal
from pydantic import BaseModel, Field

# Option 1: TypedDict for simple structures
class DeviceConfig(TypedDict):
    device_id: str
    hostname: str
    ip_address: str
    vendor: Literal["cisco", "juniper", "arista"]
    config_content: str

# Option 2: Pydantic models for validation
class DeploymentConfig(BaseModel):
    """Configuration for deployment creation."""
    device_id: UUID
    type: Literal["device", "vlan", "acl", "routing"]
    content: str
    sequence: int = Field(default=0, ge=0)
    metadata: Optional[Dict[str, Any]] = None

    class Config:
        json_schema_extra = {
            "example": {
                "device_id": "550e8400-e29b-41d4-a716-446655440000",
                "type": "acl",
                "content": "access-list 100 permit tcp any any eq 443",
                "sequence": 1
            }
        }
```

### Generic Types

Use generics for reusable components:

```python
from typing import TypeVar, Generic, List, Callable, Awaitable

T = TypeVar('T')
ConfigType = TypeVar('ConfigType', bound='BaseConfig')

class Repository(Generic[T]):
    """Generic repository pattern implementation."""

    async def get(self, id: UUID) -> Optional[T]:
        """Get entity by ID."""
        pass

    async def list(self, filters: Dict[str, Any]) -> List[T]:
        """List entities with filters."""
        pass

    async def create(self, entity: T) -> T:
        """Create new entity."""
        pass
```

### Return Type Annotations

Always specify return types, including for async functions:

```python
async def connect_to_device(
    self,
    device_id: str,
    user_context: Dict[str, Any]
) -> Optional[DeviceConnection]:
    """
    Establish secure connection to network device.

    Returns:
        DeviceConnection instance if successful, None if unauthorized
    """
    pass

def _get_netmiko_device_type(self) -> str:
    """
    Map vendor enum to Netmiko device type string.

    Returns:
        Netmiko device type (e.g., "cisco_ios", "juniper_junos")
    """
    pass
```

## Error Handling Patterns

### Exception Hierarchy

Define custom exceptions with clear hierarchy:

```python
# src/core/exceptions.py
"""Custom exceptions for CatNet."""

class CatNetError(Exception):
    """Base exception for all CatNet errors."""
    pass

class AuthenticationError(CatNetError):
    """Authentication failed."""
    pass

class AuthorizationError(CatNetError):
    """User not authorized for operation."""
    pass

class ValidationError(CatNetError):
    """Configuration validation failed."""

    def __init__(self, errors: List[str], warnings: List[str] = None):
        self.errors = errors
        self.warnings = warnings or []
        super().__init__(f"Validation failed: {', '.join(errors)}")

class DeploymentError(CatNetError):
    """Deployment execution failed."""

    def __init__(self, deployment_id: str, message: str, failed_devices: List[str] = None):
        self.deployment_id = deployment_id
        self.failed_devices = failed_devices or []
        super().__init__(message)

class VaultError(CatNetError):
    """HashiCorp Vault operation failed."""
    pass

class DeviceConnectionError(CatNetError):
    """Device connection failed."""

    def __init__(self, device_id: str, reason: str):
        self.device_id = device_id
        self.reason = reason
        super().__init__(f"Connection to device {device_id} failed: {reason}")
```

### Error Handling Best Practices

#### 1. Specific Exception Handling

```python
async def execute_deployment(self, deployment_id: str) -> Dict[str, Any]:
    """Execute deployment with comprehensive error handling."""
    try:
        deployment = await self._get_deployment(deployment_id)

        if not deployment:
            raise DeploymentError(deployment_id, "Deployment not found")

        # Execute deployment
        result = await self._do_deployment(deployment)

        return result

    except ValidationError as e:
        logger.error(f"Deployment {deployment_id} validation failed", extra={
            "errors": e.errors,
            "warnings": e.warnings
        })
        await self._update_deployment_state(deployment_id, "validation_failed")
        raise

    except DeviceConnectionError as e:
        logger.error(f"Device connection failed during deployment", extra={
            "deployment_id": deployment_id,
            "device_id": e.device_id,
            "reason": e.reason
        })
        await self._trigger_rollback(deployment_id, reason=str(e))
        raise DeploymentError(deployment_id, "Device connection failed") from e

    except VaultError as e:
        logger.critical(f"Vault error during deployment", extra={
            "deployment_id": deployment_id,
            "error": str(e)
        })
        await self._quarantine_deployment(deployment_id)
        raise

    except Exception as e:
        logger.exception(f"Unexpected error in deployment {deployment_id}")
        await self._trigger_rollback(deployment_id, reason="Unexpected error")
        raise DeploymentError(deployment_id, "Deployment failed") from e
```

#### 2. Context Managers for Resource Management

```python
from contextlib import asynccontextmanager

@asynccontextmanager
async def device_connection(self, device_id: str, user_context: Dict[str, Any]):
    """
    Context manager for secure device connections.

    Ensures connections are properly closed and credentials are rotated.

    Example:
        >>> async with service.device_connection(device_id, user_ctx) as conn:
        ...     config = await conn.get_running_config()
    """
    connection = None
    try:
        # Establish connection
        connection = await self.connect_to_device(device_id, user_context)

        # Audit connection start
        await self.audit.log_connection(device_id, user_context['user_id'], "opened")

        yield connection

    except DeviceConnectionError as e:
        logger.error(f"Connection failed: {e}")
        await self.audit.log_connection_failure(device_id, user_context['user_id'], str(e))
        raise

    finally:
        if connection:
            try:
                await connection.disconnect()
                await self.audit.log_connection(device_id, user_context['user_id'], "closed")
            except Exception as e:
                logger.error(f"Error closing connection: {e}")

        # Rotate temporary credentials
        await self.vault.rotate_temporary_credentials(device_id)
```

#### 3. Retry Logic with Exponential Backoff

```python
import asyncio
from functools import wraps
from typing import Type

def retry_async(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: Tuple[Type[Exception], ...] = (Exception,)
):
    """
    Decorator for async functions with retry logic.

    Args:
        max_attempts: Maximum retry attempts
        delay: Initial delay between retries (seconds)
        backoff: Backoff multiplier for exponential delay
        exceptions: Tuple of exceptions to catch and retry

    Example:
        >>> @retry_async(max_attempts=3, delay=1.0, backoff=2.0)
        ... async def fetch_config(device_id: str):
        ...     return await vault.get_device_config(device_id)
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            attempt = 1
            current_delay = delay

            while attempt <= max_attempts:
                try:
                    return await func(*args, **kwargs)

                except exceptions as e:
                    if attempt == max_attempts:
                        logger.error(f"{func.__name__} failed after {max_attempts} attempts")
                        raise

                    logger.warning(
                        f"{func.__name__} attempt {attempt} failed, retrying in {current_delay}s",
                        extra={"error": str(e), "attempt": attempt}
                    )

                    await asyncio.sleep(current_delay)
                    current_delay *= backoff
                    attempt += 1

        return wrapper
    return decorator

# Usage example
@retry_async(max_attempts=3, delay=2.0, exceptions=(VaultError, ConnectionError))
async def get_device_credentials(device_id: str) -> Dict[str, str]:
    """Get device credentials from Vault with retry logic."""
    return await vault_client.get_credentials(f"devices/{device_id}")
```

## Code Style Guidelines

### Imports

Organize imports in the following order:

```python
"""Module docstring."""

# Standard library imports
import asyncio
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from uuid import UUID

# Third-party imports
import jwt
import pyotp
from fastapi import HTTPException, Depends
from pydantic import BaseModel, Field, validator
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

# Local application imports
from src.core.config import settings
from src.core.exceptions import AuthenticationError, AuthorizationError
from src.db.models import User, UserSession, Role
from src.security.vault import vault_client
from src.utils.logging import get_logger

logger = get_logger(__name__)
```

### Constants

Define constants at module level with descriptive names:

```python
# Authentication constants
MAX_LOGIN_ATTEMPTS = 5
ACCOUNT_LOCKOUT_MINUTES = 30
JWT_EXPIRY_MINUTES = 30
REFRESH_TOKEN_EXPIRY_DAYS = 7

# Deployment constants
DEFAULT_DEPLOYMENT_TIMEOUT = 3600
MAX_PARALLEL_DEPLOYMENTS = 50
CANARY_DEFAULT_STAGES = [5, 25, 50, 100]
CANARY_DEFAULT_WAIT_MINUTES = [5, 10, 15, 0]

# Network device constants
DEVICE_CONNECTION_TIMEOUT = 30
DEVICE_COMMAND_TIMEOUT = 60
SSH_PORT = 22
TELNET_PORT = 23  # Discouraged, use SSH
```

### Naming Conventions

```python
# Classes: PascalCase
class DeploymentService:
    pass

class GitOpsWorkflow:
    pass

# Functions/methods: snake_case
async def execute_deployment(deployment_id: str):
    pass

def validate_configuration(config: Dict[str, Any]):
    pass

# Constants: SCREAMING_SNAKE_CASE
MAX_RETRY_ATTEMPTS = 3
DEFAULT_TIMEOUT = 60

# Private methods: leading underscore
def _internal_helper(data: str):
    pass

async def _backup_device_config(device: Device):
    pass

# Type variables: PascalCase with T suffix
from typing import TypeVar
ConfigT = TypeVar('ConfigT', bound='BaseConfig')
DeploymentT = TypeVar('DeploymentT')
```

## Testing Requirements

### Test Documentation

All test files should include module docstrings:

```python
"""
Unit tests for DeploymentService.

Tests cover:
- Deployment creation with various strategies
- Approval workflow (single/multi-approver)
- Deployment execution (rolling, canary, blue-green)
- Rollback mechanisms
- Error handling and edge cases

Fixtures:
    - db_session: Test database session
    - vault_client: Mocked Vault client
    - sample_deployment: Standard deployment fixture

Security Tests:
    - Unauthorized deployment creation attempts
    - Approval bypass attempts
    - Configuration tampering detection
"""
```

### Test Function Documentation

```python
@pytest.mark.asyncio
async def test_canary_deployment_rollback_on_failure(
    deployment_service,
    sample_deployment,
    mock_devices
):
    """
    Test canary deployment automatic rollback when device health check fails.

    Scenario:
        1. Create canary deployment with 4 stages (5%, 25%, 50%, 100%)
        2. First stage (5%) deploys successfully
        3. Second stage (25%) device health check fails
        4. Automatic rollback is triggered
        5. All devices from first stage are rolled back

    Assertions:
        - Deployment state is ROLLED_BACK
        - All devices show rollback_performed=True
        - Audit log contains rollback entry
        - Original configuration is restored on all devices

    See Also:
        - test_canary_deployment_success: Successful canary flow
        - test_rollback_manager: Rollback mechanism tests
    """
    # Test implementation
    pass
```

## Security Best Practices

### Sensitive Data Handling

```python
from pydantic import SecretStr

class Config:
    """Never log or expose sensitive fields."""
    database_password: SecretStr
    vault_token: SecretStr
    api_key: SecretStr

    def __repr__(self):
        """Redact sensitive fields in repr."""
        return f"Config(database_password='***', vault_token='***')"

# Logging sensitive data
logger.info("User login", extra={
    "username": username,  # OK
    "password": "REDACTED",  # Never log actual password
    "ip_address": request.client.host  # OK for security audit
})
```

### Input Validation

```python
from pydantic import BaseModel, Field, validator

class DeploymentCreate(BaseModel):
    """Validated deployment creation request."""

    name: str = Field(..., min_length=1, max_length=200, regex=r'^[a-zA-Z0-9\s\-_]+$')
    strategy: Literal["rolling", "canary", "blue_green"]
    configs: List[ConfigItem] = Field(..., min_items=1, max_items=1000)

    @validator('name')
    def sanitize_name(cls, v):
        """Prevent XSS and injection attacks."""
        # Remove potential HTML/script tags
        clean_name = v.strip()
        if '<' in clean_name or '>' in clean_name:
            raise ValueError("Name contains invalid characters")
        return clean_name
```

---

**Last Updated:** 2025-10-28
**Maintained By:** CatNet Development Team

