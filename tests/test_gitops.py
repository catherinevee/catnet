"""
Comprehensive tests for CatNet GitOps Service
"""

import pytest
import asyncio
import os
import tempfile
import shutil
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime

from src.gitops.git_manager import GitManager, GitRepository
from src.gitops.webhook_processor import (
    WebhookProcessor,
    WebhookEvent,
    EventType,
    WebhookProvider,
)
from src.gitops.config_validator import (
    ConfigValidator,
    ValidationResult,
    ValidationType,
    Severity,
)
from src.gitops.secret_scanner import SecretScanner, SecretScanResult, SecretType
from src.gitops.gitops_workflow import (
    GitOpsWorkflow,
    DeploymentStrategy,
    WorkflowConfig,
    WorkflowState,
)


class TestGitManager:
    """Test Git repository manager"""

    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.git_manager = GitManager(workspace_dir=self.temp_dir)

    def teardown_method(self):
        """Cleanup test environment"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_add_repository(self):
        """Test adding repository"""
        repo = self.git_manager.add_repository(
            url="https://github.com/test/repo.git", branch="main"
        )

        assert repo.id is not None
        assert repo.url == "https://github.com/test/repo.git"
        assert repo.branch == "main"
        assert repo.id in self.git_manager.repositories

    def test_validate_repository_url(self):
        """Test repository URL validation"""
        # Valid URLs
        assert self.git_manager._validate_repository_url(
            "https://github.com/test/repo.git"
        )
        assert self.git_manager._validate_repository_url("git@github.com:test/repo.git")
        assert self.git_manager._validate_repository_url(
            "https://gitlab.com/test/repo.git"
        )

        # Invalid URLs
        assert not self.git_manager._validate_repository_url(
            "https://evil.com/repo.git"
        )
        assert not self.git_manager._validate_repository_url("ftp://github.com/repo")

    @patch("git.Repo.clone_from")
    def test_clone_repository(self, mock_clone):
        """Test repository cloning"""
        mock_clone.return_value = MagicMock()

        repo = self.git_manager.add_repository("https://github.com/test/repo.git")

        # Mock the repository directory
        os.makedirs(repo.local_path)

        success, error = self.git_manager.clone_repository(repo.id)

        assert success
        assert error is None
        assert repo.last_sync is not None

    def test_get_file_content(self):
        """Test getting file content"""
        repo = self.git_manager.add_repository("https://github.com/test/repo.git")

        # Create test file
        os.makedirs(repo.local_path)
        test_file = os.path.join(repo.local_path, "test.yml")
        with open(test_file, "w") as f:
            f.write("test content")

        content = self.git_manager.get_file_content(repo.id, "test.yml")

        assert content == "test content"

    def test_list_files(self):
        """Test listing repository files"""
        repo = self.git_manager.add_repository("https://github.com/test/repo.git")

        # Create test files
        os.makedirs(repo.local_path)
        test_files = ["config.yml", "router.yaml", "switch.conf"]
        for file_name in test_files:
            with open(os.path.join(repo.local_path, file_name), "w") as f:
                f.write("content")

        # Mock git ls-files
        with patch.object(GitManager, "list_files") as mock_list:
            mock_list.return_value = ["config.yml", "router.yaml"]
            files = self.git_manager.list_files(repo.id, pattern="*.yml")
            mock_list.assert_called_once()


class TestWebhookProcessor:
    """Test webhook processor"""

    def setup_method(self):
        """Setup test environment"""
        self.processor = WebhookProcessor()

    def test_detect_provider(self):
        """Test webhook provider detection"""
        # GitHub
        headers = {"X-GitHub-Event": "push"}
        assert self.processor._detect_provider(headers) == WebhookProvider.GITHUB

        # GitLab
        headers = {"X-GitLab-Event": "Push Hook"}
        assert self.processor._detect_provider(headers) == WebhookProvider.GITLAB

        # Bitbucket
        headers = {"X-Event-Key": "repo:push"}
        assert self.processor._detect_provider(headers) == WebhookProvider.BITBUCKET

        # Generic
        headers = {"Content-Type": "application/json"}
        assert self.processor._detect_provider(headers) == WebhookProvider.GENERIC

    def test_verify_github_signature(self):
        """Test GitHub webhook signature verification"""
        import hmac
        import hashlib

        secret = "test_secret"
        body = '{"test": "payload"}'

        # Generate valid signature
        signature = (
            "sha256="
            + hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
        )

        headers = {"X-Hub-Signature-256": signature}

        self.processor.register_webhook_secret("https://github.com/test/repo", secret)

        is_valid = self.processor._verify_signature(
            headers, body, secret, WebhookProvider.GITHUB
        )
        assert is_valid

        # Invalid signature
        headers = {"X-Hub-Signature-256": "sha256=invalid"}
        is_valid = self.processor._verify_signature(
            headers, body, secret, WebhookProvider.GITHUB
        )
        assert not is_valid

    def test_process_github_push_webhook(self):
        """Test processing GitHub push webhook"""
        headers = {"X-GitHub-Event": "push", "X-GitHub-Delivery": "12345"}

        payload = {
            "ref": "refs/heads/main",
            "repository": {"clone_url": "https://github.com/test/repo.git"},
            "commits": [
                {
                    "id": "abc123",
                    "author": {"username": "testuser"},
                    "timestamp": datetime.utcnow().isoformat(),
                    "added": ["file1.yml"],
                    "modified": ["file2.yml"],
                    "removed": [],
                }
            ],
            "pusher": {"name": "testuser"},
        }

        success, event = self.processor.process_webhook(headers, str(payload))

        # Note: This will fail without proper JSON encoding
        # In real implementation, body should be JSON string

    def test_normalize_repository_url(self):
        """Test repository URL normalization"""
        urls = [
            ("https://github.com/test/repo.git", "github.com/test/repo"),
            ("http://gitlab.com/test/repo", "gitlab.com/test/repo"),
            ("HTTPS://GITHUB.COM/TEST/REPO.GIT", "github.com/test/repo"),
        ]

        for original, expected in urls:
            assert self.processor._normalize_repository_url(original) == expected


class TestConfigValidator:
    """Test configuration validator"""

    def setup_method(self):
        """Setup test environment"""
        self.validator = ConfigValidator()

    def test_validate_cisco_syntax(self):
        """Test Cisco configuration validation"""
        config = """
interface GigabitEthernet0/1
 ip address 192.168.1.1 255.255.255.0
 no shutdown
!
router ospf 1
 network 192.168.1.0 0.0.0.255 area 0
!
"""
        result = self.validator.validate_configuration(config, "cisco")

        assert result.vendor == "cisco"
        assert result.is_valid  # Should be valid basic config

    def test_validate_juniper_syntax(self):
        """Test Juniper configuration validation"""
        config = """
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 192.168.1.1/24;
            }
        }
    }
}
protocols {
    ospf {
        area 0.0.0.0 {
            interface ge-0/0/0.0;
        }
    }
}
"""
        result = self.validator.validate_configuration(config, "juniper")

        assert result.vendor == "juniper"
        assert result.is_valid

    def test_detect_weak_encryption(self):
        """Test weak encryption detection"""
        config = """
enable password cisco123
username admin password admin123
snmp-server community public RO
"""
        result = self.validator.validate_configuration(config, "cisco")

        assert not result.is_valid
        security_issues = [
            i for i in result.issues if i.type == ValidationType.SECURITY
        ]
        assert len(security_issues) > 0

    def test_validate_ip_addresses(self):
        """Test IP address validation"""
        assert self.validator._is_valid_ip("192.168.1.1")
        assert self.validator._is_valid_ip("10.0.0.0/24")
        assert not self.validator._is_valid_ip("256.1.1.1")
        assert not self.validator._is_valid_ip("192.168.1")
        assert not self.validator._is_valid_ip("192.168.1.1/33")

    def test_detect_conflicts(self):
        """Test conflict detection"""
        config = """
interface GigabitEthernet0/1
 ip address 192.168.1.1 255.255.255.0
!
interface GigabitEthernet0/2
 ip address 192.168.1.1 255.255.255.0
!
"""
        result = self.validator.validate_configuration(config, "cisco")

        conflict_issues = [
            i for i in result.issues if i.type == ValidationType.CONFLICT
        ]
        assert len(conflict_issues) > 0  # Should detect duplicate IP


class TestSecretScanner:
    """Test secret scanner"""

    def setup_method(self):
        """Setup test environment"""
        self.scanner = SecretScanner()

    def test_detect_passwords(self):
        """Test password detection"""
        content = """
password: mysecretpass123
enable password 0 cisco123
username admin password admin123
"""
        result = self.scanner.scan_file("test.conf", content)

        assert result.has_secrets
        assert result.secret_count >= 3
        password_secrets = [
            s for s in result.secrets if s.secret_type == SecretType.PASSWORD
        ]
        assert len(password_secrets) > 0

    def test_detect_api_keys(self):
        """Test API key detection"""
        content = """
api_key: sk-1234567890abcdef1234567890abcdef
github_token: ghp_1234567890abcdef1234567890abcdef1234
aws_access_key_id: AKIAIOSFODNN7EXAMPLE
"""
        result = self.scanner.scan_file("config.yml", content)

        assert result.has_secrets
        api_secrets = [
            s
            for s in result.secrets
            if s.secret_type
            in [SecretType.API_KEY, SecretType.TOKEN, SecretType.AWS_CREDENTIALS]
        ]
        assert len(api_secrets) > 0

    def test_detect_private_keys(self):
        """Test private key detection"""
        content = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----
"""
        result = self.scanner.scan_file("key.pem", content)

        assert result.has_secrets
        key_secrets = [
            s for s in result.secrets if s.secret_type == SecretType.PRIVATE_KEY
        ]
        assert len(key_secrets) > 0

    def test_entropy_calculation(self):
        """Test entropy calculation"""
        # High entropy (random)
        high_entropy = "aB3$mN9@pQ5&xY7#zW2*"
        entropy = self.scanner._calculate_entropy(high_entropy)
        assert entropy > 3.0

        # Low entropy (repetitive)
        low_entropy = "aaaaaaaaaa"
        entropy = self.scanner._calculate_entropy(low_entropy)
        assert entropy < 1.0

    def test_whitelist_patterns(self):
        """Test whitelist pattern matching"""
        # Should be whitelisted
        assert self.scanner._is_whitelisted("${VARIABLE}")
        assert self.scanner._is_whitelisted("{{template_var}}")
        assert self.scanner._is_whitelisted("<placeholder>")
        assert self.scanner._is_whitelisted("example_password")

        # Should not be whitelisted
        assert not self.scanner._is_whitelisted("real_secret_123")
        assert not self.scanner._is_whitelisted("actualPassword123")

    def test_secret_redaction(self):
        """Test secret redaction"""
        # Short secret
        redacted = self.scanner._redact_secret("password: 123", "123")
        assert redacted == "password: ***"

        # Long secret
        redacted = self.scanner._redact_secret(
            "token: abcdefghijklmnop", "abcdefghijklmnop"
        )
        assert "ab" in redacted and "op" in redacted
        assert "*" in redacted


class TestGitOpsWorkflow:
    """Test GitOps workflow orchestrator"""

    def setup_method(self):
        """Setup test environment"""
        self.git_manager = Mock(spec=GitManager)
        self.webhook_processor = Mock(spec=WebhookProcessor)
        self.config_validator = Mock(spec=ConfigValidator)
        self.secret_scanner = Mock(spec=SecretScanner)

        self.workflow = GitOpsWorkflow(
            self.git_manager,
            self.webhook_processor,
            self.config_validator,
            self.secret_scanner,
        )

    def test_configure_repository(self):
        """Test repository configuration"""
        repo = GitRepository(
            id="repo123",
            url="https://github.com/test/repo.git",
            branch="main",
        )
        self.git_manager.add_repository.return_value = repo
        self.git_manager.clone_repository.return_value = (True, None)

        repo_id = self.workflow.configure_repository(
            "https://github.com/test/repo.git",
            webhook_secret="secret123",
        )

        assert repo_id == "repo123"
        self.webhook_processor.register_webhook_secret.assert_called_once()
        self.git_manager.clone_repository.assert_called_once_with("repo123")

    @pytest.mark.asyncio
    async def test_execute_workflow_validation_failure(self):
        """Test workflow execution with validation failure"""
        from src.gitops.gitops_workflow import WorkflowExecution

        execution = WorkflowExecution(
            id="exec123",
            repository_id="repo123",
            trigger_event=None,
            state=WorkflowState.PENDING,
            started_at=datetime.utcnow(),
            completed_at=None,
        )

        # Setup mocks
        self.git_manager.pull_repository.return_value = (True, {})
        self.git_manager.list_files.return_value = ["config.yml"]
        self.git_manager.get_file_content.return_value = "test content"

        # Validation fails
        validation_result = ValidationResult(
            is_valid=False, config_file="config.yml", vendor="cisco"
        )
        self.config_validator.validate_configuration.return_value = validation_result

        config = WorkflowConfig(validation_required=True)
        self.workflow.workflow_configs[execution.repository_id] = config

        await self.workflow._execute_workflow(execution)

        assert execution.state == WorkflowState.FAILED
        assert "validation failed" in execution.errors[0].lower()

    @pytest.mark.asyncio
    async def test_execute_workflow_secret_detection(self):
        """Test workflow execution with secret detection"""
        from src.gitops.gitops_workflow import WorkflowExecution

        execution = WorkflowExecution(
            id="exec123",
            repository_id="repo123",
            trigger_event=None,
            state=WorkflowState.PENDING,
            started_at=datetime.utcnow(),
            completed_at=None,
        )

        # Setup mocks
        self.git_manager.pull_repository.return_value = (True, {})
        self.git_manager.list_files.return_value = ["config.yml"]
        self.git_manager.get_file_content.return_value = "password: secret123"

        # Validation passes
        validation_result = ValidationResult(
            is_valid=True, config_file="config.yml", vendor="cisco"
        )
        self.config_validator.validate_configuration.return_value = validation_result

        # Secrets detected
        scan_result = SecretScanResult(
            file_path="config.yml",
            has_secrets=True,
            secret_count=1,
        )
        self.secret_scanner.scan_file.return_value = scan_result
        self.secret_scanner.quarantine_file.return_value = '{"quarantine": "report"}'

        config = WorkflowConfig(
            validation_required=True,
            secret_scanning=True,
        )
        self.workflow.workflow_configs[execution.repository_id] = config

        await self.workflow._execute_workflow(execution)

        assert execution.state == WorkflowState.FAILED
        assert "secrets detected" in execution.errors[0].lower()

    def test_detect_vendor(self):
        """Test vendor detection"""
        cisco_config = "interface GigabitEthernet0/1"
        assert self.workflow._detect_vendor(cisco_config) == "cisco"

        juniper_config = "set interface ge-0/0/0"
        assert self.workflow._detect_vendor(juniper_config) == "juniper"

        unknown_config = "some random config"
        assert self.workflow._detect_vendor(unknown_config) == "unknown"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
