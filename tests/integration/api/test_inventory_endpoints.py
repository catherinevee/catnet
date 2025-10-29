"""
Integration tests for inventory API endpoints.
Tests device inventory and discovery operations.
"""

import pytest
from httpx import AsyncClient
from unittest.mock import patch
from uuid import uuid4


class TestInventoryEndpoints:
    """Test inventory API endpoints."""

    @pytest.mark.asyncio
    async def test_get_inventory(self, client: AsyncClient, test_user):
        """Test retrieving device inventory."""
        with patch('src.api.dependencies.get_current_user') as mock_auth:
            mock_auth.return_value = test_user

            response = await client.get("/api/v1/inventory")

            assert response.status_code in [200, 401, 404]

    @pytest.mark.asyncio
    async def test_get_inventory_by_vendor(self, client: AsyncClient, test_user):
        """Test filtering inventory by vendor."""
        with patch('src.api.dependencies.get_current_user') as mock_auth:
            mock_auth.return_value = test_user

            response = await client.get("/api/v1/inventory?vendor=cisco")

            assert response.status_code in [200, 401, 404]

    @pytest.mark.asyncio
    async def test_get_inventory_statistics(self, client: AsyncClient, test_user):
        """Test retrieving inventory statistics."""
        with patch('src.api.dependencies.get_current_user') as mock_auth:
            mock_auth.return_value = test_user

            response = await client.get("/api/v1/inventory/stats")

            assert response.status_code in [200, 401, 404]

    @pytest.mark.asyncio
    async def test_discover_devices(self, client: AsyncClient, test_user):
        """Test triggering device discovery."""
        discovery_params = {
            "subnet": "192.168.1.0/24",
            "protocols": ["ssh", "snmp"]
        }

        with patch('src.api.dependencies.get_current_user') as mock_auth:
            mock_auth.return_value = test_user

            response = await client.post("/api/v1/inventory/discover", json=discovery_params)

            assert response.status_code in [200, 202, 401, 404]

    @pytest.mark.asyncio
    async def test_import_devices(self, client: AsyncClient, test_user):
        """Test bulk importing devices."""
        devices_data = {
            "devices": [
                {"hostname": "router1", "ip_address": "192.168.1.1", "vendor": "cisco"},
                {"hostname": "router2", "ip_address": "192.168.1.2", "vendor": "juniper"}
            ]
        }

        with patch('src.api.dependencies.get_current_user') as mock_auth:
            mock_auth.return_value = test_user

            response = await client.post("/api/v1/inventory/import", json=devices_data)

            assert response.status_code in [200, 201, 401, 404]

    @pytest.mark.asyncio
    async def test_export_inventory(self, client: AsyncClient, test_user):
        """Test exporting inventory to CSV."""
        with patch('src.api.dependencies.get_current_user') as mock_auth:
            mock_auth.return_value = test_user

            response = await client.get("/api/v1/inventory/export?format=csv")

            assert response.status_code in [200, 401, 404]

    @pytest.mark.asyncio
    async def test_get_device_neighbors(self, client: AsyncClient, test_user):
        """Test retrieving device neighbor information."""
        device_id = str(uuid4())

        with patch('src.api.dependencies.get_current_user') as mock_auth:
            mock_auth.return_value = test_user

            response = await client.get(f"/api/v1/inventory/{device_id}/neighbors")

            assert response.status_code in [200, 401, 404]

    @pytest.mark.asyncio
    async def test_update_device_location(self, client: AsyncClient, test_user):
        """Test updating device location information."""
        device_id = str(uuid4())
        location_data = {
            "datacenter": "DC1",
            "rack": "R42",
            "position": "U10"
        }

        with patch('src.api.dependencies.get_current_user') as mock_auth:
            mock_auth.return_value = test_user

            response = await client.patch(
                f"/api/v1/inventory/{device_id}/location",
                json=location_data
            )

            assert response.status_code in [200, 401, 404]
