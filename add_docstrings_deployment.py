#!/usr/bin/env python3
"""
Sprint 2: Add comprehensive docstrings to deployment.py
"""
import re
from pathlib import Path


def add_deployment_service_docstring():
    """Add docstring to DeploymentService class and its methods."""

    file_path = Path("src/core/deployment.py")
    content = file_path.read_text(encoding='utf-8')

    # DeploymentService class docstring
    class_pattern = r'(class DeploymentService:)\n(    def __init__\()'
    class_replacement = r'''\1
    """
    Service for managing network device configuration deployments.

    Handles the complete deployment lifecycle including creation, approval,
    execution, and rollback of configuration changes. Supports multiple
    deployment strategies (rolling, canary, blue-green) with built-in
    security features like encryption, audit logging, and approval workflows.

    Attributes:
        db: SQLAlchemy database session for persistence
        vault: HashiCorp Vault client for credential management
        audit: Audit logger for compliance tracking
        encryption: Service for encrypting sensitive configuration data
        validator: Configuration validator for syntax/semantic checks
        rollback_manager: Manager for automated rollback operations
        device_connector: Secure connector for device communication

    Example:
        >>> service = DeploymentService(db_session)
        >>> deployment = await service.create_deployment(
        ...     name="Router Config Update",
        ...     configs=[{"device_id": "device-123", "content": "..."}],
        ...     user_id="user-456",
        ...     strategy="rolling"
        ... )
    """
\2'''
    content = re.sub(class_pattern, class_replacement, content)

    # __init__ docstring
    init_pattern = r'(    def __init__\(\n        self,\n        db: Session,\n        vault_client: Optional\[VaultClient\] = None,\n        audit_logger: Optional\[AuditLogger\] = None\n    \):)\n(        self\.db = db)'
    init_replacement = r'''\1
        """
        Initialize deployment service with required dependencies.

        Args:
            db: SQLAlchemy session for database operations
            vault_client: Optional Vault client (creates default if not provided)
            audit_logger: Optional audit logger (creates default if not provided)
        """
\2'''
    content = re.sub(init_pattern, init_replacement, content)

    # create_deployment docstring
    create_pattern = r'(    async def create_deployment\(\n        self,\n        name: str,\n        configs: List\[Dict\[str, Any\]\],\n        user_id: str,\n        strategy: str = "rolling",\n        requires_approval: bool = True,\n        approval_count_required: int = 2,\n        canary_percentage: Optional\[int\] = None,\n        max_parallel: int = 5,\n        scheduled_at: Optional\[datetime\] = None,\n        metadata: Optional\[Dict\[str, Any\]\] = None\n    \) -> Dict\[str, Any\]:)\n(        configs_json)'
    create_replacement = r'''\1
        """
        Create a new configuration deployment with approval workflow.

        Creates a deployment record with encrypted configuration data, cryptographic
        signatures, and validation results. Supports multiple deployment strategies
        and optional approval workflows for production changes.

        Args:
            name: Human-readable deployment name
            configs: List of device configurations to deploy
            user_id: UUID of user creating the deployment
            strategy: Deployment strategy ("rolling", "canary", "blue_green")
            requires_approval: Whether deployment requires approval
            approval_count_required: Number of approvals needed
            canary_percentage: For canary deployments, percentage of devices
            max_parallel: Maximum parallel device connections
            scheduled_at: Optional scheduled execution time
            metadata: Optional metadata dictionary

        Returns:
            Dictionary containing:
                - id: Deployment UUID
                - name: Deployment name
                - state: Current deployment state
                - created_at: ISO timestamp
                - requires_approval: Approval requirement flag
                - approval_count_required: Required approval count

        Raises:
            ValueError: If configs list is empty or invalid
            ValidationError: If configuration validation fails
            EncryptionError: If configuration encryption fails
            VaultError: If Vault operations fail

        Example:
            >>> deployment = await service.create_deployment(
            ...     name="Emergency Security Patch",
            ...     configs=[
            ...         {"device_id": "rtr-01", "content": "interface GigabitEthernet0/1\\n shutdown"},
            ...         {"device_id": "rtr-02", "content": "interface GigabitEthernet0/1\\n shutdown"}
            ...     ],
            ...     user_id="admin-123",
            ...     strategy="rolling",
            ...     requires_approval=True,
            ...     approval_count_required=2
            ... )
        """
\2'''
    content = re.sub(create_pattern, create_replacement, content, flags=re.DOTALL)

    # approve_deployment docstring
    approve_pattern = r'(    async def approve_deployment\(\n        self,\n        deployment_id: str,\n        user_id: str,\n        comment: Optional\[str\] = None\n    \) -> bool:)\n(        deployment = self\.db\.query)'
    approve_replacement = r'''\1
        """
        Approve a pending deployment.

        Records user approval and automatically executes the deployment once
        the required approval count is reached. Prevents duplicate approvals
        from the same user.

        Args:
            deployment_id: UUID of deployment to approve
            user_id: UUID of approving user
            comment: Optional approval comment for audit trail

        Returns:
            bool: True if deployment is fully approved, False if more approvals needed

        Raises:
            ValueError: If deployment not found, already approved by user,
                       or in invalid state for approval

        Example:
            >>> approved = await service.approve_deployment(
            ...     deployment_id="deploy-123",
            ...     user_id="admin-456",
            ...     comment="Reviewed and approved for production"
            ... )
        """
\2'''
    content = re.sub(approve_pattern, approve_replacement, content)

    # execute_deployment docstring
    execute_pattern = r'(    async def execute_deployment\(\n        self,\n        deployment_id: str,\n        executor_user_id: str\n    \) -> Dict\[str, Any\]:)\n(        deployment = self\.db\.query)'
    execute_replacement = r'''\1
        """
        Execute an approved deployment using the configured strategy.

        Executes the deployment according to its strategy (rolling, canary, or
        blue-green). Monitors progress, handles failures, and triggers automatic
        rollback if necessary.

        Args:
            deployment_id: UUID of deployment to execute
            executor_user_id: UUID of user executing deployment

        Returns:
            Dictionary containing:
                - deployment_id: UUID of deployment
                - state: Final deployment state
                - success_count: Number of successful device updates
                - failed_count: Number of failed device updates
                - rollback_triggered: Whether rollback was triggered
                - duration_seconds: Total execution time

        Raises:
            ValueError: If deployment not found or not approved
            DeploymentError: If execution fails
            DeviceConnectionError: If device connection fails

        Example:
            >>> result = await service.execute_deployment(
            ...     deployment_id="deploy-123",
            ...     executor_user_id="admin-456"
            ... )
            >>> print(f"Success: {result['success_count']}/{result['total_devices']}")
        """
\2'''
    content = re.sub(execute_pattern, execute_replacement, content)

    file_path.write_text(content, encoding='utf-8')
    print(f"✓ Added docstrings to {file_path}")


def main():
    """Main execution."""
    print("Adding docstrings to deployment.py...")
    add_deployment_service_docstring()
    print("✓ Complete!")


if __name__ == "__main__":
    main()
