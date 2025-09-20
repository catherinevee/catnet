#!/usr/bin/env python3
"""
Final comprehensive fix for all remaining syntax issues.
"""
import os
import re
from pathlib import Path


def fix_deployment_endpoints():
    """Fix the deployment_endpoints.py file specifically."""
    file_path = Path("src/api/deployment_endpoints.py")
    if not file_path.exists():
        return False

    content = file_path.read_text(encoding="utf-8")

    # Fix broken string concatenations
    fixes = [
        (
            'status_code=status.HTTP_404_NOT_FOUND," \\\n        "detail="One or more devices not found",',
            'status_code=status.HTTP_404_NOT_FOUND,\n                detail="One or more devices not found",',
        ),
        (
            'warnings.append(f"Device {device.hostname} certificate not "\n                    active")',
            'warnings.append(f"Device {device.hostname} certificate not active")',
        ),
        (
            'f"Device {device_id}"\n                            device.hostname} backup is {backup_age} days \\',
            'f"Device {device.hostname} backup is {backup_age} days "',
        ),
        (
            'f"Rolling deployment will update {len(devices)} devices "\n                    sequentially"',
            'f"Rolling deployment will update {len(devices)} devices sequentially"',
        ),
        (
            'warnings.append("Deployment during business hours may impact "\n                users")',
            'warnings.append("Deployment during business hours may impact users")',
        ),
        (
            'recommendations.append("Consider scheduling for maintenance "\n                window")',
            'recommendations.append("Consider scheduling for maintenance window")',
        ),
        (
            'status_code=status.HTTP_500_INTERNAL_SERVER_ERROR," \\\n        "detail="Dry-run simulation failed",',
            'status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,\n            detail="Dry-run simulation failed",',
        ),
        (
            '# Check permissions" \\\n        "if not await check_permission(current_user, "deployment.metrics"):',
            '# Check permissions\n        if not await check_permission(current_user, "deployment.metrics"):',
        ),
        (
            'status_code=status.HTTP_500_INTERNAL_SERVER_ERROR," \\\n        "detail="Failed to retrieve metrics",',
            'status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,\n            detail="Failed to retrieve metrics",',
        ),
        (
            '# Check permissions" \\\n        "if not await check_permission(current_user, "deployment.schedule"):',
            '# Check permissions\n        if not await check_permission(current_user, "deployment.schedule"):',
        ),
        (
            'f"Validating maintenance window "\n                    {request.maintenance_window_id}"',
            'f"Validating maintenance window {request.maintenance_window_id}"',
        ),
        (
            'created_by=current_user.id," \\\n        "config_hash="pending",  # Will be calculated when configs are \\',
            'created_by=current_user.id,\n            config_hash="pending",  # Will be calculated when configs are',
        ),
        (
            'f"Sending notifications to" \\\n    f"{len(request.notification_emails)} recipients"',
            'f"Sending notifications to {len(request.notification_emails)} recipients"',
        ),
        (
            'await audit.log_event(" \\\n        "event_type="deployment_scheduled",',
            'await audit.log_event(\n            event_type="deployment_scheduled",',
        ),
        (
            'status_code=status.HTTP_500_INTERNAL_SERVER_ERROR," \\\n        "detail="Failed to schedule deployment",',
            'status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,\n            detail="Failed to schedule deployment",',
        ),
        (
            'if not deployment:" \\\n        "logger.error(f"Scheduled deployment {deployment_id} not found")',
            'if not deployment:\n                logger.error(f"Scheduled deployment {deployment_id} not found")',
        ),
        (
            'except Exception as e:" \\\n        "logger.error(f"Scheduled deployment execution failed: {e}")',
            'except Exception as e:\n        logger.error(f"Scheduled deployment execution failed: {e}")',
        ),
    ]

    for old, new in fixes:
        content = content.replace(old, new)

    # Fix missing docstring quotes
    content = content.replace(
        "    Get deployment metrics and statistics\n\n    Provides:",
        '    """\n    Get deployment metrics and statistics\n\n    Provides:',
    )
    content = content.replace(
        "    - Recent deployment history\n    logger.info",
        '    - Recent deployment history\n    """\n    logger.info',
    )

    content = content.replace(
        "    Schedule a deployment for future execution\n\n    Features:",
        '    """\n    Schedule a deployment for future execution\n\n    Features:',
    )
    content = content.replace(
        "    - Automatic execution\n    logger.info",
        '    - Automatic execution\n    """\n    logger.info',
    )

    content = content.replace(
        "    Enroll user in Multi - Factor Authentication\n\n    Methods supported:",
        '    """\n    Enroll user in Multi-Factor Authentication\n\n    Methods supported:',
    )

    content = content.replace(
        "    Validate X.509 certificate for device or service authentication\n\n    This endpoint:",
        '    """\n    Validate X.509 certificate for device or service authentication\n\n    This endpoint:',
    )

    content = content.replace(
        "    Get all active sessions for the current user\n\n    Returns list of active sessions with:",
        '    """\n    Get all active sessions for the current user\n\n    Returns list of active sessions with:',
    )

    content = content.replace(
        "    Terminate a specific session\n\n    Allows users to remotely log out sessions",
        '    """\n    Terminate a specific session\n\n    Allows users to remotely log out sessions\n    """',
    )

    file_path.write_text(content, encoding="utf-8")
    return True


def fix_auth_endpoints():
    """Fix the auth_endpoints.py file."""
    file_path = Path("src/api/auth_endpoints.py")
    if not file_path.exists():
        return False

    content = file_path.read_text(encoding="utf-8")

    # Fix broken strings
    content = content.replace(
        'f"Validating maintenance window \\"\n                    {session_id}"',
        'f"Validating maintenance window {session_id}"',
    )

    content = content.replace(
        'f"Session termination requested by {current_user.username} for \\"\n            {session_id}"',
        'f"Session termination requested by {current_user.username} for {session_id}"',
    )

    # Add missing docstrings
    content = content.replace(
        '    """User login endpoint\n\n    Authenticates user with username / password.\n    Returns JWT tokens on success.\n    logger.info',
        '    """User login endpoint\n\n    Authenticates user with username/password.\n    Returns JWT tokens on success.\n    """\n    logger.info',
    )

    content = content.replace(
        '    """User logout endpoint\n\n    Invalidates the current session.\n    logger.info',
        '    """User logout endpoint\n\n    Invalidates the current session.\n    """\n    logger.info',
    )

    content = content.replace(
        '    """Refresh access token\n\n    Exchanges a refresh token for a new access token.\n    try:',
        '    """Refresh access token\n\n    Exchanges a refresh token for a new access token.\n    """\n    try:',
    )

    file_path.write_text(content, encoding="utf-8")
    return True


def main():
    """Main function to apply all fixes."""
    print("Applying final fixes...")

    # Fix specific files with known issues
    if fix_deployment_endpoints():
        print("✓ Fixed src/api/deployment_endpoints.py")
    else:
        print("✗ Could not fix src/api/deployment_endpoints.py")

    if fix_auth_endpoints():
        print("✓ Fixed src/api/auth_endpoints.py")
    else:
        print("✗ Could not fix src/api/auth_endpoints.py")

    print("\nDone!")


if __name__ == "__main__":
    main()
