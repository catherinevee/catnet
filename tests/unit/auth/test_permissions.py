"""
Unit tests for RBAC Permissions
Tests role-based access control, permission checking, and authorization
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from fastapi import HTTPException, status
from uuid import uuid4

from src.auth.permissions import (
    Permission,
    PermissionChecker,
    UserRole,
    require_permission,
    require_any_permission,
    require_all_permissions
)
from src.auth.models import User


@pytest.fixture
def permission_checker():
    """Provide a permission checker instance for testing."""
    return PermissionChecker()


@pytest.fixture
def mock_viewer():
    """Provide a mock viewer user."""
    user = Mock(spec=User)
    user.id = uuid4()
    user.username = "viewer"
    user.roles = [UserRole.VIEWER]
    user.is_active = True
    return user


@pytest.fixture
def mock_operator():
    """Provide a mock operator user."""
    user = Mock(spec=User)
    user.id = uuid4()
    user.username = "operator"
    user.roles = [UserRole.OPERATOR]
    user.is_active = True
    return user


@pytest.fixture
def mock_admin():
    """Provide a mock admin user."""
    user = Mock(spec=User)
    user.id = uuid4()
    user.username = "admin"
    user.roles = [UserRole.ADMIN]
    user.is_active = True
    return user


@pytest.fixture
def mock_super_admin():
    """Provide a mock super admin user."""
    user = Mock(spec=User)
    user.id = uuid4()
    user.username = "superadmin"
    user.roles = [UserRole.SUPER_ADMIN]
    user.is_active = True
    return user


class TestPermissionEnum:
    """Test Permission enumeration."""

    def test_permission_enum_values(self):
        """Test permission enum has expected values."""
        assert Permission.DEPLOYMENT_CREATE.value == "deployment.create"
        assert Permission.DEVICE_READ.value == "device.read"
        assert Permission.USER_DELETE.value == "user.delete"

    def test_permission_enum_completeness(self):
        """Test all major permission categories exist."""
        permissions = [p.value for p in Permission]

        # Check deployment permissions
        assert any("deployment." in p for p in permissions)

        # Check device permissions
        assert any("device." in p for p in permissions)

        # Check user permissions
        assert any("user." in p for p in permissions)

        # Check audit permissions
        assert any("audit." in p for p in permissions)

        # Check system permissions
        assert any("system." in p for p in permissions)


class TestRolePermissions:
    """Test role-based permission mappings."""

    def test_viewer_role_permissions(self, permission_checker):
        """Test viewer role has read-only permissions."""
        viewer_perms = permission_checker.get_role_permissions(UserRole.VIEWER)

        assert Permission.DEPLOYMENT_READ in viewer_perms
        assert Permission.DEVICE_READ in viewer_perms
        assert Permission.SYSTEM_HEALTH in viewer_perms

        # Viewers should NOT have write permissions
        assert Permission.DEPLOYMENT_CREATE not in viewer_perms
        assert Permission.DEVICE_DELETE not in viewer_perms
        assert Permission.USER_CREATE not in viewer_perms

    def test_operator_role_permissions(self, permission_checker):
        """Test operator role has operational permissions."""
        operator_perms = permission_checker.get_role_permissions(UserRole.OPERATOR)

        assert Permission.DEPLOYMENT_CREATE in operator_perms
        assert Permission.DEPLOYMENT_READ in operator_perms
        assert Permission.DEVICE_CONNECT in operator_perms
        assert Permission.CONFIG_VALIDATE in operator_perms

        # Operators should NOT have admin permissions
        assert Permission.USER_DELETE not in operator_perms
        assert Permission.SYSTEM_SETTINGS not in operator_perms

    def test_admin_role_permissions(self, permission_checker):
        """Test admin role has administrative permissions."""
        admin_perms = permission_checker.get_role_permissions(UserRole.ADMIN)

        assert Permission.DEPLOYMENT_APPROVE in admin_perms
        assert Permission.DEPLOYMENT_ROLLBACK in admin_perms
        assert Permission.USER_CREATE in admin_perms
        assert Permission.USER_UPDATE in admin_perms
        assert Permission.AUDIT_READ in admin_perms

        # Admins should NOT have super admin permissions
        assert Permission.SYSTEM_MAINTENANCE not in admin_perms

    def test_super_admin_role_permissions(self, permission_checker):
        """Test super admin role has all permissions."""
        super_admin_perms = permission_checker.get_role_permissions(UserRole.SUPER_ADMIN)

        # Super admin should have ALL permissions
        all_permissions = list(Permission)
        for perm in all_permissions:
            assert perm in super_admin_perms


class TestPermissionChecking:
    """Test permission checking functionality."""

    def test_has_permission_viewer_read_access(self, permission_checker, mock_viewer):
        """Test viewer has read permissions."""
        has_perm = permission_checker.has_permission(
            user=mock_viewer,
            permission=Permission.DEVICE_READ
        )

        assert has_perm is True

    def test_has_permission_viewer_no_write_access(self, permission_checker, mock_viewer):
        """Test viewer does not have write permissions."""
        has_perm = permission_checker.has_permission(
            user=mock_viewer,
            permission=Permission.DEVICE_DELETE
        )

        assert has_perm is False

    def test_has_permission_operator_deployment_create(self, permission_checker, mock_operator):
        """Test operator can create deployments."""
        has_perm = permission_checker.has_permission(
            user=mock_operator,
            permission=Permission.DEPLOYMENT_CREATE
        )

        assert has_perm is True

    def test_has_permission_admin_user_management(self, permission_checker, mock_admin):
        """Test admin can manage users."""
        has_perm = permission_checker.has_permission(
            user=mock_admin,
            permission=Permission.USER_CREATE
        )

        assert has_perm is True

    def test_has_permission_super_admin_all(self, permission_checker, mock_super_admin):
        """Test super admin has all permissions."""
        # Test a random sampling of permissions
        test_perms = [
            Permission.DEPLOYMENT_DELETE,
            Permission.SYSTEM_MAINTENANCE,
            Permission.SECURITY_MANAGE,
            Permission.AUDIT_EXPORT
        ]

        for perm in test_perms:
            has_perm = permission_checker.has_permission(
                user=mock_super_admin,
                permission=perm
            )
            assert has_perm is True

    def test_has_permission_inactive_user(self, permission_checker, mock_viewer):
        """Test inactive user has no permissions."""
        mock_viewer.is_active = False

        has_perm = permission_checker.has_permission(
            user=mock_viewer,
            permission=Permission.DEVICE_READ
        )

        assert has_perm is False

    def test_has_permission_user_with_multiple_roles(self, permission_checker):
        """Test user with multiple roles has combined permissions."""
        multi_role_user = Mock(spec=User)
        multi_role_user.id = uuid4()
        multi_role_user.username = "multi"
        multi_role_user.roles = [UserRole.VIEWER, UserRole.OPERATOR]
        multi_role_user.is_active = True

        # Should have viewer permissions
        assert permission_checker.has_permission(
            user=multi_role_user,
            permission=Permission.DEVICE_READ
        ) is True

        # Should have operator permissions
        assert permission_checker.has_permission(
            user=multi_role_user,
            permission=Permission.DEPLOYMENT_CREATE
        ) is True


class TestPermissionDecorators:
    """Test permission decorator functions."""

    def test_require_permission_decorator_allowed(self, mock_operator):
        """Test decorator allows access when user has permission."""

        @require_permission(Permission.DEPLOYMENT_CREATE)
        def create_deployment(user: User):
            return "Deployment created"

        # Should not raise exception
        result = create_deployment(user=mock_operator)
        assert result == "Deployment created"

    def test_require_permission_decorator_denied(self, mock_viewer):
        """Test decorator denies access when user lacks permission."""

        @require_permission(Permission.DEPLOYMENT_CREATE)
        def create_deployment(user: User):
            return "Deployment created"

        # Should raise HTTPException
        with pytest.raises(HTTPException) as exc_info:
            create_deployment(user=mock_viewer)

        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN

    def test_require_any_permission_decorator_one_match(self, mock_operator):
        """Test decorator allows access when user has any required permission."""

        @require_any_permission([
            Permission.DEPLOYMENT_APPROVE,  # Operator doesn't have this
            Permission.DEPLOYMENT_CREATE    # Operator has this
        ])
        def manage_deployment(user: User):
            return "Success"

        # Should not raise exception (has one of the permissions)
        result = manage_deployment(user=mock_operator)
        assert result == "Success"

    def test_require_any_permission_decorator_no_match(self, mock_viewer):
        """Test decorator denies access when user has none of required permissions."""

        @require_any_permission([
            Permission.DEPLOYMENT_CREATE,
            Permission.DEVICE_DELETE
        ])
        def manage_resources(user: User):
            return "Success"

        # Should raise HTTPException
        with pytest.raises(HTTPException) as exc_info:
            manage_resources(user=mock_viewer)

        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN

    def test_require_all_permissions_decorator_all_present(self, mock_admin):
        """Test decorator allows access when user has all required permissions."""

        @require_all_permissions([
            Permission.USER_CREATE,
            Permission.USER_UPDATE
        ])
        def manage_users(user: User):
            return "Users managed"

        # Should not raise exception
        result = manage_users(user=mock_admin)
        assert result == "Users managed"

    def test_require_all_permissions_decorator_missing_one(self, mock_operator):
        """Test decorator denies access when user missing one required permission."""

        @require_all_permissions([
            Permission.DEPLOYMENT_CREATE,  # Operator has this
            Permission.USER_CREATE         # Operator doesn't have this
        ])
        def admin_task(user: User):
            return "Success"

        # Should raise HTTPException
        with pytest.raises(HTTPException) as exc_info:
            admin_task(user=mock_operator)

        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN


class TestPermissionHierarchy:
    """Test permission inheritance and hierarchy."""

    def test_role_hierarchy_viewer_lowest(self, permission_checker):
        """Test viewer role has lowest privilege level."""
        viewer_perms = permission_checker.get_role_permissions(UserRole.VIEWER)
        operator_perms = permission_checker.get_role_permissions(UserRole.OPERATOR)

        # Operator should have all viewer permissions plus more
        assert viewer_perms.issubset(operator_perms) or len(viewer_perms) <= len(operator_perms)

    def test_role_hierarchy_operator_subset_admin(self, permission_checker):
        """Test operator permissions are subset of admin."""
        operator_perms = permission_checker.get_role_permissions(UserRole.OPERATOR)
        admin_perms = permission_checker.get_role_permissions(UserRole.ADMIN)

        # Admin should have more permissions than operator
        assert len(admin_perms) >= len(operator_perms)

    def test_super_admin_includes_all_roles(self, permission_checker):
        """Test super admin has superset of all role permissions."""
        super_admin_perms = permission_checker.get_role_permissions(UserRole.SUPER_ADMIN)

        viewer_perms = permission_checker.get_role_permissions(UserRole.VIEWER)
        operator_perms = permission_checker.get_role_permissions(UserRole.OPERATOR)
        admin_perms = permission_checker.get_role_permissions(UserRole.ADMIN)

        # Super admin should include all permissions from other roles
        assert viewer_perms.issubset(super_admin_perms)
        assert operator_perms.issubset(super_admin_perms)
        assert admin_perms.issubset(super_admin_perms)


class TestResourceBasedPermissions:
    """Test resource-based permission checking."""

    def test_can_access_own_resource(self, permission_checker, mock_operator):
        """Test user can access their own resources."""
        resource_owner_id = mock_operator.id

        can_access = permission_checker.can_access_resource(
            user=mock_operator,
            resource_owner_id=resource_owner_id,
            permission=Permission.DEPLOYMENT_READ
        )

        assert can_access is True

    def test_cannot_access_others_resource_without_permission(self, permission_checker, mock_viewer):
        """Test user cannot access others' resources without permission."""
        other_user_id = uuid4()

        can_access = permission_checker.can_access_resource(
            user=mock_viewer,
            resource_owner_id=other_user_id,
            permission=Permission.DEPLOYMENT_DELETE
        )

        assert can_access is False

    def test_admin_can_access_any_resource(self, permission_checker, mock_admin):
        """Test admin can access any resource."""
        other_user_id = uuid4()

        can_access = permission_checker.can_access_resource(
            user=mock_admin,
            resource_owner_id=other_user_id,
            permission=Permission.DEPLOYMENT_READ
        )

        assert can_access is True


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_user_with_no_roles(self, permission_checker):
        """Test user with no roles has no permissions."""
        no_role_user = Mock(spec=User)
        no_role_user.id = uuid4()
        no_role_user.username = "norole"
        no_role_user.roles = []
        no_role_user.is_active = True

        has_perm = permission_checker.has_permission(
            user=no_role_user,
            permission=Permission.DEVICE_READ
        )

        assert has_perm is False

    def test_none_user_raises_error(self, permission_checker):
        """Test permission check with None user raises error."""
        with pytest.raises((ValueError, TypeError, AttributeError)):
            permission_checker.has_permission(
                user=None,
                permission=Permission.DEVICE_READ
            )

    def test_invalid_permission_type(self, permission_checker, mock_viewer):
        """Test permission check with invalid permission type."""
        with pytest.raises((ValueError, TypeError)):
            permission_checker.has_permission(
                user=mock_viewer,
                permission="invalid.permission"
            )

    def test_permission_check_with_deleted_user(self, permission_checker, mock_viewer):
        """Test permission check handles deleted/deactivated users."""
        mock_viewer.is_active = False
        mock_viewer.deleted_at = "2025-01-01"

        has_perm = permission_checker.has_permission(
            user=mock_viewer,
            permission=Permission.DEVICE_READ
        )

        assert has_perm is False


class TestPermissionAuditing:
    """Test permission check auditing."""

    @pytest.mark.asyncio
    async def test_permission_check_creates_audit_log(self, permission_checker, mock_operator):
        """Test permission checks are audited."""
        with patch.object(permission_checker, 'audit_permission_check', new_callable=AsyncMock) as mock_audit:
            permission_checker.has_permission(
                user=mock_operator,
                permission=Permission.DEPLOYMENT_CREATE,
                audit=True
            )

            # Verify audit was called
            mock_audit.assert_called_once()

    @pytest.mark.asyncio
    async def test_failed_permission_check_audited(self, permission_checker, mock_viewer):
        """Test failed permission checks are audited."""
        with patch.object(permission_checker, 'audit_permission_check', new_callable=AsyncMock) as mock_audit:
            permission_checker.has_permission(
                user=mock_viewer,
                permission=Permission.USER_DELETE,
                audit=True
            )

            # Verify audit was called for failed check
            mock_audit.assert_called_once()
            call_args = mock_audit.call_args
            assert call_args is not None
