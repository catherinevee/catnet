"""
Comprehensive tests for CatNet CLI
"""
import pytest
import click
from click.testing import CliRunner
from unittest.mock import Mock, patch, AsyncMock
import json
import os
from pathlib import Path

from catnet_cli.cli import cli
from catnet_cli.config import ConfigManager


@pytest.fixture
def runner():
    """Create a Click CLI test runner"""
    return CliRunner()


@pytest.fixture
def mock_config(tmp_path):
    """Create a temporary configuration file"""
    config_file = tmp_path / ".catnet.yml"
    config_file.write_text(
        """
api:
  base_url: http://localhost:8000
  timeout: 30
security:
  mfa_required: false
"""
    )
    return str(config_file)


@pytest.fixture
def mock_token_file(tmp_path):
    """Create a temporary token file"""
    token_dir = tmp_path / ".catnet"
    token_dir.mkdir()
    token_file = token_dir / "tokens.json"
    token_file.write_text(
        json.dumps(
            {
                "access_token": "test_token_123",
                "refresh_token": "refresh_token_456",
                "expires_at": "2025-12-31T23:59:59",
            }
        )
    )
    return str(token_file)


class TestCLICore:
    """Test core CLI functionality"""

    def test_cli_help(self, runner):
        """Test CLI help display"""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "CatNet Network Configuration Management" in result.output
        assert "Commands:" in result.output
        assert "auth" in result.output
        assert "device" in result.output
        assert "deploy" in result.output

    def test_cli_version(self, runner):
        """Test version display"""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "catnet version" in result.output.lower()

    def test_cli_debug_mode(self, runner):
        """Test debug mode activation"""
        result = runner.invoke(cli, ["--debug", "auth", "--help"])
        assert result.exit_code == 0

    def test_cli_config_option(self, runner, mock_config):
        """Test custom config file option"""
        result = runner.invoke(cli, ["--config", mock_config, "device", "--help"])
        assert result.exit_code == 0


class TestAuthCommands:
    """Test authentication commands"""

    @patch("catnet_cli.commands.auth.CatNetAPIClient")
    def test_auth_login(self, mock_client_class, runner):
        """Test login command"""
        mock_client = AsyncMock()
        mock_client.login = AsyncMock(
            return_value={
                "token": "new_token",
                "expires_at": "2025-01-01T00:00:00",
                "roles": ["admin"],
            }
        )
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_class.return_value.__aexit__ = AsyncMock()

        result = runner.invoke(cli, ["auth", "login"], input="testuser\ntestpass\n")
        assert result.exit_code == 0
        assert "Successfully logged in" in result.output

    @patch("catnet_cli.commands.auth.CatNetAPIClient")
    def test_auth_logout(self, mock_client_class, runner):
        """Test logout command"""
        mock_client = AsyncMock()
        mock_client.logout = AsyncMock(return_value={"success": True})
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_class.return_value.__aexit__ = AsyncMock()

        result = runner.invoke(cli, ["auth", "logout"])
        assert result.exit_code == 0
        assert "Successfully logged out" in result.output

    @patch("catnet_cli.commands.auth.CatNetAPIClient")
    def test_auth_whoami(self, mock_client_class, runner):
        """Test whoami command"""
        mock_client = AsyncMock()
        mock_client.token = "test_token"
        mock_client.request = AsyncMock(
            return_value={
                "username": "testuser",
                "email": "test@example.com",
                "roles": ["admin", "operator"],
            }
        )
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_class.return_value.__aexit__ = AsyncMock()

        result = runner.invoke(cli, ["auth", "whoami"])
        assert result.exit_code == 0
        assert "Username: testuser" in result.output
        assert "Email: test@example.com" in result.output


class TestDeviceCommands:
    """Test device management commands"""

    @patch("catnet_cli.commands.device.CatNetAPIClient")
    def test_device_list(self, mock_client_class, runner):
        """Test device list command"""
        mock_client = AsyncMock()
        mock_client.list_devices = AsyncMock(
            return_value=[
                {
                    "id": "dev-123",
                    "hostname": "router1",
                    "ip_address": "192.168.1.1",
                    "vendor": "cisco",
                    "model": "ISR4451",
                    "status": "online",
                }
            ]
        )
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_class.return_value.__aexit__ = AsyncMock()

        result = runner.invoke(cli, ["device", "list"])
        assert result.exit_code == 0
        assert "router1" in result.output
        assert "192.168.1.1" in result.output

    @patch("catnet_cli.commands.device.CatNetAPIClient")
    @patch("getpass.getpass")
    def test_device_add(self, mock_getpass, mock_client_class, runner):
        """Test device add command"""
        mock_getpass.return_value = "securepass"
        mock_client = AsyncMock()
        mock_client.add_device = AsyncMock(return_value={"id": "dev-new-123"})
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_class.return_value.__aexit__ = AsyncMock()

        result = runner.invoke(
            cli,
            [
                "device",
                "add",
                "--hostname",
                "newrouter",
                "--ip",
                "10.0.0.1",
                "--vendor",
                "cisco",
                "--model",
                "ISR4451",
            ],
            input="admin\n",
        )

        assert result.exit_code == 0
        assert "Device 'newrouter' added successfully" in result.output

    @patch("catnet_cli.commands.device.CatNetAPIClient")
    def test_device_health(self, mock_client_class, runner):
        """Test device health command"""
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(
            return_value={
                "status": "healthy",
                "metrics": {
                    "cpu_usage": 45,
                    "memory_usage": 60,
                    "uptime": "30 days",
                    "temperature": "35C",
                },
            }
        )
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_class.return_value.__aexit__ = AsyncMock()

        result = runner.invoke(cli, ["device", "health", "dev-123"])
        assert result.exit_code == 0
        assert "Status: HEALTHY" in result.output
        assert "CPU Usage: 45%" in result.output


class TestDeployCommands:
    """Test deployment commands"""

    @patch("catnet_cli.commands.deploy.CatNetAPIClient")
    def test_deploy_create(self, mock_client_class, runner, tmp_path):
        """Test deployment creation"""
        # Create a temporary config file
        config_file = tmp_path / "config.yml"
        config_file.write_text("config: test")

        mock_client = AsyncMock()
        mock_client.create_deployment = AsyncMock(
            return_value={"id": "dep-123", "status": "pending"}
        )
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_class.return_value.__aexit__ = AsyncMock()

        result = runner.invoke(
            cli,
            [
                "deploy",
                "create",
                "--config-file",
                str(config_file),
                "--target",
                "device1",
                "--target",
                "device2",
                "--dry-run",
            ],
        )

        assert result.exit_code == 0
        assert "Dry run completed successfully" in result.output

    @patch("catnet_cli.commands.deploy.CatNetAPIClient")
    def test_deploy_status(self, mock_client_class, runner):
        """Test deployment status command"""
        mock_client = AsyncMock()
        mock_client.get_deployment_status = AsyncMock(
            return_value={
                "status": "in_progress",
                "progress": 75,
                "strategy": "rolling",
                "started_at": "2025-01-01T00:00:00",
            }
        )
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_class.return_value.__aexit__ = AsyncMock()

        result = runner.invoke(cli, ["deploy", "status", "dep-123"])
        assert result.exit_code == 0
        assert "Status: in_progress" in result.output
        assert "Progress: 75%" in result.output

    @patch("catnet_cli.commands.deploy.CatNetAPIClient")
    def test_deploy_rollback(self, mock_client_class, runner):
        """Test deployment rollback"""
        mock_client = AsyncMock()
        mock_client.rollback_deployment = AsyncMock(
            return_value={
                "rollback_id": "roll-456",
                "devices_rolled_back": ["device1", "device2"],
            }
        )
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_class.return_value.__aexit__ = AsyncMock()

        result = runner.invoke(
            cli,
            ["deploy", "rollback", "dep-123", "--reason", "Test rollback", "--force"],
        )

        assert result.exit_code == 0
        assert "Rollback initiated successfully" in result.output


class TestGitOpsCommands:
    """Test GitOps commands"""

    @patch("catnet_cli.commands.gitops.CatNetAPIClient")
    def test_gitops_connect(self, mock_client_class, runner):
        """Test repository connection"""
        mock_client = AsyncMock()
        mock_client.connect_repository = AsyncMock(
            return_value={
                "id": "repo-123",
                "webhook_url": "https://api.catnet/webhook/123",
            }
        )
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_class.return_value.__aexit__ = AsyncMock()

        result = runner.invoke(
            cli,
            [
                "gitops",
                "connect",
                "--url",
                "https://github.com/org/configs",
                "--branch",
                "main",
            ],
        )

        assert result.exit_code == 0
        assert "Repository connected successfully" in result.output
        assert "Webhook Configuration" in result.output

    @patch("catnet_cli.commands.gitops.CatNetAPIClient")
    def test_gitops_sync(self, mock_client_class, runner):
        """Test repository sync"""
        mock_client = AsyncMock()
        mock_client.sync_repository = AsyncMock(
            return_value={
                "status": "synced",
                "files_synced": ["config1.yml", "config2.yml"],
                "validation": {"valid": 2, "invalid": 0},
            }
        )
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_class.return_value.__aexit__ = AsyncMock()

        result = runner.invoke(cli, ["gitops", "sync", "--repo-id", "repo-123"])
        assert result.exit_code == 0
        assert "Repository synchronized successfully" in result.output
        assert "Files synced: 2" in result.output


class TestVaultCommands:
    """Test Vault commands"""

    @patch("catnet_cli.commands.vault.CatNetAPIClient")
    def test_vault_store(self, mock_client_class, runner):
        """Test secret storage"""
        mock_client = AsyncMock()
        mock_client.store_secret = AsyncMock(return_value={"version": 1})
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_class.return_value.__aexit__ = AsyncMock()

        result = runner.invoke(
            cli,
            ["vault", "store", "--path", "devices/router1", "--key", "password"],
            input="secretpass\n",
        )

        assert result.exit_code == 0
        assert "Secret stored successfully" in result.output

    @patch("catnet_cli.commands.vault.CatNetAPIClient")
    def test_vault_get(self, mock_client_class, runner):
        """Test secret retrieval"""
        mock_client = AsyncMock()
        mock_client.get_secret = AsyncMock(
            return_value={"username": "admin", "password": "secret123"}
        )
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_class.return_value.__aexit__ = AsyncMock()

        result = runner.invoke(cli, ["vault", "get", "devices/router1"])
        assert result.exit_code == 0
        assert "username:" in result.output
        assert "***" in result.output  # Password should be masked

    @patch("catnet_cli.commands.vault.CatNetAPIClient")
    def test_vault_rotate(self, mock_client_class, runner):
        """Test credential rotation"""
        mock_client = AsyncMock()
        mock_client.rotate_credentials = AsyncMock(
            return_value={
                "new_version": 2,
                "old_version": 1,
                "updated_devices": ["router1"],
            }
        )
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_class.return_value.__aexit__ = AsyncMock()

        result = runner.invoke(cli, ["vault", "rotate", "devices/router1", "--force"])

        assert result.exit_code == 0
        assert "Credentials rotated successfully" in result.output
        assert "New version: 2" in result.output


class TestConfigManager:
    """Test configuration management"""

    def test_config_load(self, tmp_path):
        """Test configuration loading"""
        config_file = tmp_path / ".catnet.yml"
        config_file.write_text(
            """
api:
  base_url: http://test.local
  timeout: 60
"""
        )

        manager = ConfigManager(str(config_file))
        assert manager.config["api"]["base_url"] == "http://test.local"
        assert manager.config["api"]["timeout"] == 60

    def test_config_env_override(self, tmp_path, monkeypatch):
        """Test environment variable override"""
        config_file = tmp_path / ".catnet.yml"
        config_file.write_text(
            """
api:
  base_url: http://test.local
"""
        )

        monkeypatch.setenv("CATNET_API_BASE_URL", "http://env.local")

        manager = ConfigManager(str(config_file))
        assert manager.config["api"]["base_url"] == "http://env.local"

    def test_token_storage(self, tmp_path):
        """Test token storage and retrieval"""
        manager = ConfigManager()
        manager.config_dir = tmp_path / ".catnet"
        manager.config_dir.mkdir()

        token_data = {
            "access_token": "test_token",
            "refresh_token": "refresh_token",
            "expires_at": "2025-12-31T00:00:00",
        }

        manager.save_token(token_data)
        retrieved = manager.get_token()

        assert retrieved["access_token"] == "test_token"
        assert retrieved["refresh_token"] == "refresh_token"


class TestErrorHandling:
    """Test error handling and edge cases"""

    @patch("catnet_cli.commands.auth.CatNetAPIClient")
    def test_auth_error(self, mock_client_class, runner):
        """Test authentication error handling"""
        mock_client = AsyncMock()
        mock_client.login = AsyncMock(side_effect=Exception("Auth failed"))
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_class.return_value.__aexit__ = AsyncMock()

        result = runner.invoke(cli, ["auth", "login"], input="user\npass\n")
        assert result.exit_code == 1
        assert "Error" in result.output or "failed" in result.output.lower()

    def test_invalid_command(self, runner):
        """Test invalid command handling"""
        result = runner.invoke(cli, ["invalid-command"])
        assert result.exit_code != 0
        assert "Error" in result.output or "No such command" in result.output

    def test_missing_required_option(self, runner):
        """Test missing required option"""
        result = runner.invoke(cli, ["device", "add"])
        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()


class TestIntegration:
    """Integration tests for complete workflows"""

    @patch("catnet_cli.client.aiohttp.ClientSession")
    async def test_full_deployment_workflow(self, mock_session):
        """Test complete deployment workflow"""
        # This would test the full flow from login to deployment
        # For now, this is a placeholder for integration testing
        pass

    @patch("catnet_cli.client.aiohttp.ClientSession")
    async def test_gitops_to_deployment(self, mock_session):
        """Test GitOps to deployment workflow"""
        # This would test connecting a repo, syncing, and deploying
        # For now, this is a placeholder for integration testing
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
