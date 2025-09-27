"""
End-to-end tests for complete deployment workflow.
Tests the entire process from Git commit to device configuration deployment.
"""

import pytest
import asyncio
import json
import tempfile
import os
from typing import Dict, Any
from unittest.mock import Mock, AsyncMock, patch

from httpx import AsyncClient
from fastapi import status


class TestDeploymentWorkflow:
    """Test complete deployment workflow end-to-end."""

    @pytest.fixture
    def sample_device_config(self):
        """Sample device configuration for testing."""
        return {
            "version": "1.0",
            "vendor": "cisco",
            "platform": "ios",
            "hostname": "test-switch-01",
            "global": {
                "hostname": "test-switch-01",
                "ip": "domain-lookup",
                "logging": {
                    "buffered": "4096"
                }
            },
            "interfaces": {
                "GigabitEthernet0/1": {
                    "description": "Uplink to Core",
                    "no shutdown": True,
                    "switchport": {
                        "mode": "trunk",
                        "allowed_vlans": "1,10,20,30"
                    }
                },
                "GigabitEthernet0/2": {
                    "description": "Server Connection",
                    "no shutdown": True,
                    "switchport": {
                        "mode": "access",
                        "access_vlan": 20
                    }
                }
            },
            "vlans": {
                "10": {"name": "USERS"},
                "20": {"name": "SERVERS"},
                "30": {"name": "MANAGEMENT"}
            }
        }

    @pytest.fixture
    def git_webhook_payload(self, sample_device_config):
        """Git webhook payload for testing."""
        return {
            "ref": "refs/heads/main",
            "after": "abc123def456",
            "before": "def456ghi789",
            "commits": [
                {
                    "id": "abc123def456",
                    "message": "Update switch configuration for VLAN changes",
                    "author": {
                        "name": "Network Engineer",
                        "email": "engineer@catnet.local"
                    },
                    "modified": ["devices/switches/test-switch-01.yml"],
                    "added": [],
                    "removed": []
                }
            ],
            "repository": {
                "name": "catnet-configs",
                "full_name": "company/catnet-configs",
                "clone_url": "https://github.com/company/catnet-configs.git"
            }
        }

    @pytest.mark.e2e
    @pytest.mark.asyncio
    async def test_complete_gitops_deployment_workflow(
        self,
        async_test_client: AsyncClient,
        admin_auth_headers,
        git_webhook_payload,
        sample_device_config,
        test_device
    ):
        """Test complete GitOps deployment workflow."""

        # Step 1: Setup Git repository
        repo_response = await async_test_client.post(
            "/api/v1/gitops/repositories",
            json={
                "name": "test-configs",
                "url": "https://github.com/company/catnet-configs.git",
                "branch": "main",
                "auto_deploy": False,
                "require_approval": True
            },
            headers=admin_auth_headers
        )

        assert repo_response.status_code == status.HTTP_201_CREATED
        repo_data = repo_response.json()
        repo_id = repo_data["id"]

        # Step 2: Process webhook (simulating Git commit)
        webhook_response = await async_test_client.post(
            f"/api/v1/gitops/repositories/{repo_id}/webhook",
            json=git_webhook_payload,
            headers={"X-Hub-Signature-256": "sha256=test_signature"}
        )

        assert webhook_response.status_code == status.HTTP_200_OK
        webhook_data = webhook_response.json()
        assert "deployment_id" in webhook_data

        deployment_id = webhook_data["deployment_id"]

        # Step 3: Check deployment was created in pending state
        deployment_response = await async_test_client.get(
            f"/api/v1/deployments/{deployment_id}",
            headers=admin_auth_headers
        )

        assert deployment_response.status_code == status.HTTP_200_OK
        deployment_data = deployment_response.json()
        assert deployment_data["status"] == "pending"
        assert deployment_data["approval_required"] is True

        # Step 4: Approve deployment
        approval_response = await async_test_client.post(
            f"/api/v1/deployments/{deployment_id}/approve",
            json={"comment": "Approved for deployment"},
            headers=admin_auth_headers
        )

        assert approval_response.status_code == status.HTTP_200_OK

        # Step 5: Execute deployment
        execution_response = await async_test_client.post(
            f"/api/v1/deployments/{deployment_id}/execute",
            headers=admin_auth_headers
        )

        assert execution_response.status_code == status.HTTP_202_ACCEPTED

        # Step 6: Monitor deployment progress
        max_wait_time = 300  # 5 minutes
        start_time = asyncio.get_event_loop().time()

        while True:
            status_response = await async_test_client.get(
                f"/api/v1/deployments/{deployment_id}",
                headers=admin_auth_headers
            )

            status_data = status_response.json()
            deployment_status = status_data["status"]

            if deployment_status in ["completed", "failed", "rolled_back"]:
                break

            if asyncio.get_event_loop().time() - start_time > max_wait_time:
                pytest.fail("Deployment timed out")

            await asyncio.sleep(5)  # Wait 5 seconds before checking again

        # Step 7: Verify deployment completed successfully
        assert deployment_status == "completed"
        assert status_data["successful_devices"] > 0
        assert status_data["failed_devices"] == 0

        # Step 8: Verify device configuration was updated
        device_config_response = await async_test_client.get(
            f"/api/v1/devices/{test_device.id}/config",
            headers=admin_auth_headers
        )

        assert device_config_response.status_code == status.HTTP_200_OK

    @pytest.mark.e2e
    @pytest.mark.asyncio
    async def test_canary_deployment_workflow(
        self,
        async_test_client: AsyncClient,
        admin_auth_headers,
        sample_device_config
    ):
        """Test canary deployment workflow."""

        # Step 1: Create multiple test devices
        devices = []
        for i in range(5):
            device_response = await async_test_client.post(
                "/api/v1/devices",
                json={
                    "name": f"test-device-{i}",
                    "hostname": f"device{i}.test.com",
                    "ip_address": f"192.168.1.{i + 10}",
                    "vendor": "cisco",
                    "platform": "ios"
                },
                headers=admin_auth_headers
            )
            devices.append(device_response.json())

        # Step 2: Create canary deployment
        deployment_response = await async_test_client.post(
            "/api/v1/deployments",
            json={
                "name": "Canary Test Deployment",
                "strategy": "canary",
                "device_filter": {"vendor": "cisco"},
                "config": sample_device_config,
                "canary_percentage": 20,  # Start with 20%
                "auto_rollback": True,
                "approval_required": False
            },
            headers=admin_auth_headers
        )

        assert deployment_response.status_code == status.HTTP_201_CREATED
        deployment_id = deployment_response.json()["id"]

        # Step 3: Execute canary deployment
        execution_response = await async_test_client.post(
            f"/api/v1/deployments/{deployment_id}/execute",
            headers=admin_auth_headers
        )

        assert execution_response.status_code == status.HTTP_202_ACCEPTED

        # Step 4: Monitor canary phases
        phases_completed = []
        max_wait_time = 600  # 10 minutes for canary deployment
        start_time = asyncio.get_event_loop().time()

        while True:
            status_response = await async_test_client.get(
                f"/api/v1/deployments/{deployment_id}",
                headers=admin_auth_headers
            )

            status_data = status_response.json()
            deployment_status = status_data["status"]

            # Track canary phases
            if "canary_phase" in status_data:
                phase = status_data["canary_phase"]
                if phase not in phases_completed:
                    phases_completed.append(phase)
                    print(f"Canary phase {phase} completed")

            if deployment_status in ["completed", "failed", "rolled_back"]:
                break

            if asyncio.get_event_loop().time() - start_time > max_wait_time:
                pytest.fail("Canary deployment timed out")

            await asyncio.sleep(10)  # Wait 10 seconds between checks

        # Step 5: Verify canary deployment succeeded
        assert deployment_status == "completed"
        assert len(phases_completed) >= 2  # Should have multiple phases

    @pytest.mark.e2e
    @pytest.mark.asyncio
    async def test_rollback_workflow(
        self,
        async_test_client: AsyncClient,
        admin_auth_headers,
        test_device
    ):
        """Test deployment rollback workflow."""

        # Step 1: Create initial successful deployment
        initial_config = {
            "version": "1.0",
            "vendor": "cisco",
            "platform": "ios",
            "hostname": test_device.hostname,
            "vlans": {
                "10": {"name": "INITIAL_VLAN"}
            }
        }

        initial_deployment_response = await async_test_client.post(
            "/api/v1/deployments",
            json={
                "name": "Initial Configuration",
                "strategy": "immediate",
                "device_filter": {"id": str(test_device.id)},
                "config": initial_config,
                "approval_required": False
            },
            headers=admin_auth_headers
        )

        initial_deployment_id = initial_deployment_response.json()["id"]

        # Execute initial deployment
        await async_test_client.post(
            f"/api/v1/deployments/{initial_deployment_id}/execute",
            headers=admin_auth_headers
        )

        # Wait for completion
        await self._wait_for_deployment_completion(
            async_test_client, admin_auth_headers, initial_deployment_id
        )

        # Step 2: Create problematic deployment
        problematic_config = {
            "version": "1.0",
            "vendor": "cisco",
            "platform": "ios",
            "hostname": test_device.hostname,
            "vlans": {
                "10": {"name": "PROBLEMATIC_VLAN"}
            },
            "interfaces": {
                "InvalidInterface": {  # Invalid interface name
                    "description": "This will cause issues"
                }
            }
        }

        problem_deployment_response = await async_test_client.post(
            "/api/v1/deployments",
            json={
                "name": "Problematic Configuration",
                "strategy": "rolling",
                "device_filter": {"id": str(test_device.id)},
                "config": problematic_config,
                "auto_rollback": True,
                "approval_required": False
            },
            headers=admin_auth_headers
        )

        problem_deployment_id = problem_deployment_response.json()["id"]

        # Step 3: Execute problematic deployment (should fail and rollback)
        await async_test_client.post(
            f"/api/v1/deployments/{problem_deployment_id}/execute",
            headers=admin_auth_headers
        )

        # Wait for completion or rollback
        final_status = await self._wait_for_deployment_completion(
            async_test_client, admin_auth_headers, problem_deployment_id
        )

        # Step 4: Verify rollback occurred
        assert final_status in ["rolled_back", "failed"]

        # Step 5: Verify device is back to previous configuration
        device_config_response = await async_test_client.get(
            f"/api/v1/devices/{test_device.id}/config",
            headers=admin_auth_headers
        )

        # Should be back to initial configuration
        config_data = device_config_response.json()
        assert "INITIAL_VLAN" in str(config_data)
        assert "PROBLEMATIC_VLAN" not in str(config_data)

    @pytest.mark.e2e
    @pytest.mark.asyncio
    async def test_multi_vendor_deployment(
        self,
        async_test_client: AsyncClient,
        admin_auth_headers
    ):
        """Test deployment across multiple vendor devices."""

        # Step 1: Create devices from different vendors
        cisco_device_response = await async_test_client.post(
            "/api/v1/devices",
            json={
                "name": "cisco-switch-01",
                "hostname": "cisco01.test.com",
                "ip_address": "192.168.1.100",
                "vendor": "cisco",
                "platform": "ios"
            },
            headers=admin_auth_headers
        )

        juniper_device_response = await async_test_client.post(
            "/api/v1/devices",
            json={
                "name": "juniper-router-01",
                "hostname": "juniper01.test.com",
                "ip_address": "192.168.1.101",
                "vendor": "juniper",
                "platform": "junos"
            },
            headers=admin_auth_headers
        )

        # Step 2: Create vendor-specific configurations
        multi_vendor_config = {
            "version": "1.0",
            "devices": {
                "cisco-switch-01": {
                    "vendor": "cisco",
                    "platform": "ios",
                    "config": {
                        "vlans": {
                            "100": {"name": "CISCO_VLAN"}
                        }
                    }
                },
                "juniper-router-01": {
                    "vendor": "juniper",
                    "platform": "junos",
                    "config": {
                        "interfaces": {
                            "ge-0/0/1": {
                                "description": "Juniper Interface"
                            }
                        }
                    }
                }
            }
        }

        # Step 3: Create multi-vendor deployment
        deployment_response = await async_test_client.post(
            "/api/v1/deployments",
            json={
                "name": "Multi-Vendor Deployment",
                "strategy": "rolling",
                "config": multi_vendor_config,
                "approval_required": False
            },
            headers=admin_auth_headers
        )

        deployment_id = deployment_response.json()["id"]

        # Step 4: Execute deployment
        await async_test_client.post(
            f"/api/v1/deployments/{deployment_id}/execute",
            headers=admin_auth_headers
        )

        # Step 5: Monitor deployment
        final_status = await self._wait_for_deployment_completion(
            async_test_client, admin_auth_headers, deployment_id
        )

        # Step 6: Verify successful deployment to both vendors
        assert final_status == "completed"

    @pytest.mark.e2e
    @pytest.mark.asyncio
    async def test_secret_scanning_in_deployment(
        self,
        async_test_client: AsyncClient,
        admin_auth_headers
    ):
        """Test secret scanning prevents deployment of configurations with secrets."""

        # Step 1: Create configuration with secrets
        config_with_secrets = {
            "version": "1.0",
            "vendor": "cisco",
            "platform": "ios",
            "hostname": "test-device",
            "users": {
                "admin": {
                    "password": "SuperSecretPassword123!",  # Plaintext password
                    "privilege": 15
                }
            },
            "snmp": {
                "community": "private secret_community_string"  # Secret in community
            },
            "crypto": {
                "key": "AKIA1234567890ABCDEF"  # Looks like AWS key
            }
        }

        # Step 2: Attempt to create deployment with secrets
        deployment_response = await async_test_client.post(
            "/api/v1/deployments",
            json={
                "name": "Deployment with Secrets",
                "strategy": "immediate",
                "config": config_with_secrets,
                "approval_required": False
            },
            headers=admin_auth_headers
        )

        # Should be rejected due to secrets
        assert deployment_response.status_code == status.HTTP_400_BAD_REQUEST

        error_data = deployment_response.json()
        assert "secret" in error_data["detail"].lower()

    @pytest.mark.e2e
    @pytest.mark.asyncio
    async def test_audit_trail_throughout_deployment(
        self,
        async_test_client: AsyncClient,
        admin_auth_headers,
        test_device
    ):
        """Test audit trail is properly maintained throughout deployment."""

        # Step 1: Create and execute deployment
        deployment_response = await async_test_client.post(
            "/api/v1/deployments",
            json={
                "name": "Audit Trail Test",
                "strategy": "immediate",
                "device_filter": {"id": str(test_device.id)},
                "config": {
                    "version": "1.0",
                    "vendor": "cisco",
                    "platform": "ios",
                    "hostname": test_device.hostname
                },
                "approval_required": False
            },
            headers=admin_auth_headers
        )

        deployment_id = deployment_response.json()["id"]

        await async_test_client.post(
            f"/api/v1/deployments/{deployment_id}/execute",
            headers=admin_auth_headers
        )

        await self._wait_for_deployment_completion(
            async_test_client, admin_auth_headers, deployment_id
        )

        # Step 2: Check audit logs were created
        audit_response = await async_test_client.get(
            "/api/v1/admin/audit-logs",
            params={
                "resource_type": "deployment",
                "resource_id": deployment_id
            },
            headers=admin_auth_headers
        )

        assert audit_response.status_code == status.HTTP_200_OK

        audit_logs = audit_response.json()
        assert len(audit_logs) > 0

        # Should have logs for creation, execution, and completion
        log_actions = [log["action"] for log in audit_logs]
        assert "deployment.create" in log_actions
        assert "deployment.execute" in log_actions

    async def _wait_for_deployment_completion(
        self,
        client: AsyncClient,
        headers: Dict[str, str],
        deployment_id: str,
        max_wait_time: int = 300
    ) -> str:
        """Helper method to wait for deployment completion."""
        start_time = asyncio.get_event_loop().time()

        while True:
            status_response = await client.get(
                f"/api/v1/deployments/{deployment_id}",
                headers=headers
            )

            status_data = status_response.json()
            deployment_status = status_data["status"]

            if deployment_status in ["completed", "failed", "rolled_back"]:
                return deployment_status

            if asyncio.get_event_loop().time() - start_time > max_wait_time:
                pytest.fail(f"Deployment {deployment_id} timed out")

            await asyncio.sleep(5)


class TestIntegrationScenarios:
    """Test various integration scenarios."""

    @pytest.mark.e2e
    @pytest.mark.asyncio
    async def test_disaster_recovery_scenario(
        self,
        async_test_client: AsyncClient,
        admin_auth_headers
    ):
        """Test disaster recovery scenario."""

        # Simulate multiple device failures and recovery
        # This would involve:
        # 1. Device health monitoring detecting failures
        # 2. Automatic backup restoration
        # 3. Alert notifications
        # 4. Recovery validation

        # Create devices
        devices = []
        for i in range(3):
            device_response = await async_test_client.post(
                "/api/v1/devices",
                json={
                    "name": f"critical-device-{i}",
                    "hostname": f"critical{i}.test.com",
                    "ip_address": f"192.168.100.{i + 1}",
                    "vendor": "cisco",
                    "platform": "ios"
                },
                headers=admin_auth_headers
            )
            devices.append(device_response.json())

        # Simulate device failures
        for device in devices:
            # Mark device as unreachable
            await async_test_client.patch(
                f"/api/v1/devices/{device['id']}",
                json={"status": "unreachable"},
                headers=admin_auth_headers
            )

        # Trigger recovery procedure
        recovery_response = await async_test_client.post(
            "/api/v1/admin/disaster-recovery",
            json={"action": "restore_from_backup"},
            headers=admin_auth_headers
        )

        assert recovery_response.status_code == status.HTTP_202_ACCEPTED

    @pytest.mark.e2e
    @pytest.mark.asyncio
    async def test_compliance_validation_workflow(
        self,
        async_test_client: AsyncClient,
        admin_auth_headers
    ):
        """Test compliance validation throughout workflow."""

        # Test configuration meets compliance requirements
        compliant_config = {
            "version": "1.0",
            "vendor": "cisco",
            "platform": "ios",
            "hostname": "compliant-device",
            "global": {
                "logging": {
                    "host": "syslog.company.com"  # Required for compliance
                },
                "ntp": {
                    "server": "ntp.company.com"  # Required for compliance
                }
            },
            "aaa": {
                "authentication": "required",  # Security compliance
                "authorization": "required"
            }
        }

        deployment_response = await async_test_client.post(
            "/api/v1/deployments",
            json={
                "name": "Compliance Test Deployment",
                "config": compliant_config,
                "compliance_check": True,
                "approval_required": True
            },
            headers=admin_auth_headers
        )

        assert deployment_response.status_code == status.HTTP_201_CREATED

        # Test non-compliant configuration is rejected
        non_compliant_config = {
            "version": "1.0",
            "vendor": "cisco",
            "platform": "ios",
            "hostname": "non-compliant-device",
            "users": {
                "admin": {
                    "password": "admin123"  # Weak password - compliance violation
                }
            }
        }

        non_compliant_response = await async_test_client.post(
            "/api/v1/deployments",
            json={
                "name": "Non-Compliant Deployment",
                "config": non_compliant_config,
                "compliance_check": True
            },
            headers=admin_auth_headers
        )

        assert non_compliant_response.status_code == status.HTTP_400_BAD_REQUEST