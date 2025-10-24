"""
Integration tests for Health Check API endpoints
Tests health, readiness, and liveness endpoints
"""

import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch, Mock
import json
from datetime import datetime

from src.api.app import app


@pytest.fixture
async def client():
    """Async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def mock_db_session():
    """Mock database session."""
    with patch('src.api.routes.health.get_db_session') as mock:
        yield mock


@pytest.fixture
def mock_vault_client():
    """Mock Vault client."""
    with patch('src.api.routes.health.VaultClient') as mock:
        yield mock


class TestBasicHealthCheck:
    """Test basic health check endpoint."""

    @pytest.mark.asyncio
    async def test_health_check_success(self, client):
        """Test basic health check returns healthy status."""
        response = await client.get("/api/health/")

        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'healthy'
        assert 'timestamp' in data
        assert data['service'] == 'catnet-api'

    @pytest.mark.asyncio
    async def test_health_check_timestamp_format(self, client):
        """Test health check timestamp is in ISO format."""
        response = await client.get("/api/health/")

        assert response.status_code == 200
        data = response.json()

        # Verify timestamp can be parsed
        timestamp = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
        assert isinstance(timestamp, datetime)


class TestDetailedHealthCheck:
    """Test detailed health check endpoint."""

    @pytest.mark.asyncio
    async def test_detailed_health_check_all_healthy(self, client, mock_db_session, mock_vault_client):
        """Test detailed health check with all systems healthy."""
        # Mock authentication
        with patch('src.api.routes.health.get_current_user') as mock_auth:
            mock_auth.return_value = {
                'sub': 'user_123',
                'email': 'test@example.com'
            }

            # Mock database check
            mock_session = AsyncMock()
            mock_session.execute = AsyncMock()
            mock_db_session.return_value.__aenter__.return_value = mock_session

            # Mock Vault check
            mock_vault_instance = Mock()
            mock_vault_instance.health_check = AsyncMock()
            mock_vault_client.return_value = mock_vault_instance

            response = await client.get(
                "/api/health/detailed",
                headers={"Authorization": "Bearer valid_token"}
            )

            assert response.status_code == 200
            data = response.json()
            assert data['status'] == 'healthy'
            assert 'checks' in data
            assert data['checks']['database']['status'] == 'healthy'
            assert data['checks']['vault']['status'] == 'healthy'
            assert data['checks']['system']['status'] == 'healthy'
            assert 'response_time_ms' in data

    @pytest.mark.asyncio
    async def test_detailed_health_check_database_unhealthy(self, client, mock_db_session, mock_vault_client):
        """Test detailed health check with database failure."""
        with patch('src.api.routes.health.get_current_user') as mock_auth:
            mock_auth.return_value = {
                'sub': 'user_123',
                'email': 'test@example.com'
            }

            # Mock database failure
            mock_session = AsyncMock()
            mock_session.execute = AsyncMock(side_effect=Exception("Connection refused"))
            mock_db_session.return_value.__aenter__.return_value = mock_session

            # Mock Vault healthy
            mock_vault_instance = Mock()
            mock_vault_instance.health_check = AsyncMock()
            mock_vault_client.return_value = mock_vault_instance

            response = await client.get(
                "/api/health/detailed",
                headers={"Authorization": "Bearer valid_token"}
            )

            assert response.status_code == 503
            data = response.json()['detail']
            assert data['status'] == 'degraded'
            assert data['checks']['database']['status'] == 'unhealthy'
            assert 'error' in data['checks']['database']

    @pytest.mark.asyncio
    async def test_detailed_health_check_vault_unhealthy(self, client, mock_db_session, mock_vault_client):
        """Test detailed health check with Vault failure."""
        with patch('src.api.routes.health.get_current_user') as mock_auth:
            mock_auth.return_value = {
                'sub': 'user_123',
                'email': 'test@example.com'
            }

            # Mock database healthy
            mock_session = AsyncMock()
            mock_session.execute = AsyncMock()
            mock_db_session.return_value.__aenter__.return_value = mock_session

            # Mock Vault failure
            mock_vault_instance = Mock()
            mock_vault_instance.health_check = AsyncMock(side_effect=Exception("Vault sealed"))
            mock_vault_client.return_value = mock_vault_instance

            response = await client.get(
                "/api/health/detailed",
                headers={"Authorization": "Bearer valid_token"}
            )

            assert response.status_code == 503
            data = response.json()['detail']
            assert data['status'] == 'degraded'
            assert data['checks']['vault']['status'] == 'unhealthy'

    @pytest.mark.asyncio
    async def test_detailed_health_check_requires_auth(self, client):
        """Test detailed health check requires authentication."""
        response = await client.get("/api/health/detailed")

        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_detailed_health_check_performance_metrics(self, client, mock_db_session, mock_vault_client):
        """Test detailed health check includes performance metrics."""
        with patch('src.api.routes.health.get_current_user') as mock_auth:
            mock_auth.return_value = {
                'sub': 'user_123',
                'email': 'test@example.com'
            }

            mock_session = AsyncMock()
            mock_session.execute = AsyncMock()
            mock_db_session.return_value.__aenter__.return_value = mock_session

            mock_vault_instance = Mock()
            mock_vault_instance.health_check = AsyncMock()
            mock_vault_client.return_value = mock_vault_instance

            response = await client.get(
                "/api/health/detailed",
                headers={"Authorization": "Bearer valid_token"}
            )

            assert response.status_code == 200
            data = response.json()
            assert 'response_time_ms' in data
            assert isinstance(data['response_time_ms'], float)
            assert data['response_time_ms'] > 0


class TestReadinessProbe:
    """Test Kubernetes readiness probe endpoint."""

    @pytest.mark.asyncio
    async def test_readiness_check_ready(self, client, mock_db_session):
        """Test readiness check when application is ready."""
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_db_session.return_value.__aenter__.return_value = mock_session

        response = await client.get("/api/health/readiness")

        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'ready'

    @pytest.mark.asyncio
    async def test_readiness_check_not_ready(self, client, mock_db_session):
        """Test readiness check when application is not ready."""
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(side_effect=Exception("Database not available"))
        mock_db_session.return_value.__aenter__.return_value = mock_session

        response = await client.get("/api/health/readiness")

        assert response.status_code == 503
        data = response.json()['detail']
        assert data['status'] == 'not_ready'
        assert 'error' in data

    @pytest.mark.asyncio
    async def test_readiness_check_no_auth_required(self, client, mock_db_session):
        """Test readiness check doesn't require authentication."""
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_db_session.return_value.__aenter__.return_value = mock_session

        response = await client.get("/api/health/readiness")

        assert response.status_code == 200


class TestLivenessProbe:
    """Test Kubernetes liveness probe endpoint."""

    @pytest.mark.asyncio
    async def test_liveness_check_alive(self, client):
        """Test liveness check returns alive status."""
        response = await client.get("/api/health/liveness")

        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'alive'
        assert 'timestamp' in data

    @pytest.mark.asyncio
    async def test_liveness_check_no_auth_required(self, client):
        """Test liveness check doesn't require authentication."""
        response = await client.get("/api/health/liveness")

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_liveness_check_always_succeeds(self, client):
        """Test liveness check always returns 200 (used for container restart)."""
        # Make multiple requests
        for _ in range(5):
            response = await client.get("/api/health/liveness")
            assert response.status_code == 200
            assert response.json()['status'] == 'alive'


class TestHealthCheckIntegration:
    """Test health check integration scenarios."""

    @pytest.mark.asyncio
    async def test_health_endpoints_without_dependencies(self, client):
        """Test that basic health and liveness work without external dependencies."""
        # These endpoints should work even if database/vault are down
        basic_health = await client.get("/api/health/")
        liveness = await client.get("/api/health/liveness")

        assert basic_health.status_code == 200
        assert liveness.status_code == 200

    @pytest.mark.asyncio
    async def test_health_check_version_info(self, client, mock_db_session, mock_vault_client):
        """Test health check includes version information."""
        with patch('src.api.routes.health.get_current_user') as mock_auth:
            mock_auth.return_value = {
                'sub': 'user_123',
                'email': 'test@example.com'
            }

            mock_session = AsyncMock()
            mock_session.execute = AsyncMock()
            mock_db_session.return_value.__aenter__.return_value = mock_session

            mock_vault_instance = Mock()
            mock_vault_instance.health_check = AsyncMock()
            mock_vault_client.return_value = mock_vault_instance

            response = await client.get(
                "/api/health/detailed",
                headers={"Authorization": "Bearer valid_token"}
            )

            assert response.status_code == 200
            data = response.json()
            assert 'version' in data
            assert data['version'] == '1.0.0'

    @pytest.mark.asyncio
    async def test_health_check_service_name(self, client):
        """Test health check includes correct service name."""
        response = await client.get("/api/health/")

        assert response.status_code == 200
        data = response.json()
        assert data['service'] == 'catnet-api'

    @pytest.mark.asyncio
    async def test_multiple_health_checks_consistency(self, client, mock_db_session, mock_vault_client):
        """Test multiple health checks return consistent results."""
        with patch('src.api.routes.health.get_current_user') as mock_auth:
            mock_auth.return_value = {
                'sub': 'user_123',
                'email': 'test@example.com'
            }

            mock_session = AsyncMock()
            mock_session.execute = AsyncMock()
            mock_db_session.return_value.__aenter__.return_value = mock_session

            mock_vault_instance = Mock()
            mock_vault_instance.health_check = AsyncMock()
            mock_vault_client.return_value = mock_vault_instance

            # Make multiple requests
            responses = []
            for _ in range(3):
                response = await client.get(
                    "/api/health/detailed",
                    headers={"Authorization": "Bearer valid_token"}
                )
                responses.append(response)

            # All should succeed
            for response in responses:
                assert response.status_code == 200
                data = response.json()
                assert data['status'] == 'healthy'


class TestHealthCheckErrorHandling:
    """Test health check error handling."""

    @pytest.mark.asyncio
    async def test_detailed_health_check_exception_handling(self, client, mock_db_session, mock_vault_client):
        """Test detailed health check handles unexpected exceptions."""
        with patch('src.api.routes.health.get_current_user') as mock_auth:
            mock_auth.return_value = {
                'sub': 'user_123',
                'email': 'test@example.com'
            }

            # Mock database to raise unexpected error
            mock_db_session.side_effect = RuntimeError("Unexpected error")

            response = await client.get(
                "/api/health/detailed",
                headers={"Authorization": "Bearer valid_token"}
            )

            assert response.status_code == 500
            data = response.json()['detail']
            assert data['status'] == 'unhealthy'
            assert 'error' in data

    @pytest.mark.asyncio
    async def test_readiness_check_logs_errors(self, client, mock_db_session):
        """Test readiness check logs errors when not ready."""
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(side_effect=Exception("Connection timeout"))
        mock_db_session.return_value.__aenter__.return_value = mock_session

        with patch('src.api.routes.health.logger') as mock_logger:
            response = await client.get("/api/health/readiness")

            assert response.status_code == 503
            # Verify error was logged
            mock_logger.error.assert_called_once()
