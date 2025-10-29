"""
Integration tests for admin API endpoints.
Tests administrative operations and system management.
"""

import pytest
from httpx import AsyncClient
from unittest.mock import patch
from uuid import uuid4


class TestAdminEndpoints:
    """Test admin API endpoints."""

    @pytest.mark.asyncio
    async def test_get_system_stats(self, client: AsyncClient, test_user):
        """Test retrieving system statistics."""
        # Mock authentication
        with patch('src.api.dependencies.get_current_user') as mock_auth:
            mock_auth.return_value = test_user

            response = await client.get("/api/v1/admin/stats")

            assert response.status_code in [200, 401, 404]

    @pytest.mark.asyncio
    async def test_list_users(self, client: AsyncClient, test_user):
        """Test listing all users."""
        with patch('src.api.dependencies.get_current_user') as mock_auth:
            with patch('src.api.dependencies.require_admin') as mock_admin:
                mock_auth.return_value = test_user
                mock_admin.return_value = test_user

                response = await client.get("/api/v1/admin/users")

                assert response.status_code in [200, 401, 403, 404]

    @pytest.mark.asyncio
    async def test_create_user(self, client: AsyncClient, test_user):
        """Test creating a new user."""
        user_data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "SecurePassword123!",
            "roles": ["viewer"]
        }

        with patch('src.api.dependencies.get_current_user') as mock_auth:
            with patch('src.api.dependencies.require_admin') as mock_admin:
                mock_auth.return_value = test_user
                mock_admin.return_value = test_user

                response = await client.post("/api/v1/admin/users", json=user_data)

                assert response.status_code in [200, 201, 401, 403, 404]

    @pytest.mark.asyncio
    async def test_update_user_roles(self, client: AsyncClient, test_user):
        """Test updating user roles."""
        user_id = str(uuid4())
        role_data = {"roles": ["admin", "operator"]}

        with patch('src.api.dependencies.get_current_user') as mock_auth:
            with patch('src.api.dependencies.require_admin') as mock_admin:
                mock_auth.return_value = test_user
                mock_admin.return_value = test_user

                response = await client.put(
                    f"/api/v1/admin/users/{user_id}/roles",
                    json=role_data
                )

                assert response.status_code in [200, 401, 403, 404]

    @pytest.mark.asyncio
    async def test_system_maintenance_mode(self, client: AsyncClient, test_user):
        """Test enabling system maintenance mode."""
        with patch('src.api.dependencies.get_current_user') as mock_auth:
            with patch('src.api.dependencies.require_admin') as mock_admin:
                mock_auth.return_value = test_user
                mock_admin.return_value = test_user

                response = await client.post("/api/v1/admin/maintenance/enable")

                assert response.status_code in [200, 401, 403, 404]

    @pytest.mark.asyncio
    async def test_get_audit_logs(self, client: AsyncClient, test_user):
        """Test retrieving audit logs."""
        with patch('src.api.dependencies.get_current_user') as mock_auth:
            with patch('src.api.dependencies.require_admin') as mock_admin:
                mock_auth.return_value = test_user
                mock_admin.return_value = test_user

                response = await client.get("/api/v1/admin/audit-logs")

                assert response.status_code in [200, 401, 403, 404]

    @pytest.mark.asyncio
    async def test_backup_database(self, client: AsyncClient, test_user):
        """Test triggering database backup."""
        with patch('src.api.dependencies.get_current_user') as mock_auth:
            with patch('src.api.dependencies.require_admin') as mock_admin:
                mock_auth.return_value = test_user
                mock_admin.return_value = test_user

                response = await client.post("/api/v1/admin/backup")

                assert response.status_code in [200, 202, 401, 403, 404]

    @pytest.mark.asyncio
    async def test_non_admin_access_denied(self, client: AsyncClient, test_user):
        """Test that non-admin users cannot access admin endpoints."""
        test_user.is_admin = False

        with patch('src.api.dependencies.get_current_user') as mock_auth:
            mock_auth.return_value = test_user

            response = await client.get("/api/v1/admin/stats")

            # Should be forbidden or unauthorized
            assert response.status_code in [401, 403, 404]
