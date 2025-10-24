"""
Unit tests for core configuration module
Tests settings validation, environment handling, and configuration loading
"""

import pytest
from unittest.mock import patch, Mock
from pathlib import Path
from pydantic import ValidationError as PydanticValidationError

from src.core.config import Settings


@pytest.fixture
def base_env_vars():
    """Base environment variables required for Settings."""
    return {
        'DATABASE_URL': 'postgresql://localhost/catnet',
        'REDIS_URL': 'redis://localhost:6379',
        'SECRET_KEY': 'test_secret_key_min_32_chars_long',
        'VAULT_URL': 'http://localhost:8200',
        'VAULT_TOKEN': 'test_vault_token',
        'GIT_WEBHOOK_SECRET': 'test_webhook_secret'
    }


@pytest.fixture
def production_env_vars(base_env_vars):
    """Production environment variables."""
    env = base_env_vars.copy()
    env['ENVIRONMENT'] = 'production'
    return env


@pytest.fixture
def development_env_vars(base_env_vars):
    """Development environment variables."""
    env = base_env_vars.copy()
    env['ENVIRONMENT'] = 'development'
    return env


class TestSettingsInitialization:
    """Test Settings class initialization."""

    def test_settings_with_required_fields(self, base_env_vars):
        """Test Settings initialization with required fields."""
        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()

            assert settings.database_url == 'postgresql://localhost/catnet'
            assert settings.redis_url == 'redis://localhost:6379'
            assert str(settings.secret_key) == 'test_secret_key_min_32_chars_long'
            assert settings.vault_url == 'http://localhost:8200'
            assert str(settings.vault_token) == 'test_vault_token'
            assert str(settings.git_webhook_secret) == 'test_webhook_secret'

    def test_settings_missing_required_field(self):
        """Test Settings fails when required field is missing."""
        with patch.dict('os.environ', {}, clear=True):
            with pytest.raises(PydanticValidationError) as exc_info:
                Settings()

            error_dict = exc_info.value.errors()
            assert any(e['loc'] == ('database_url',) for e in error_dict)

    def test_settings_default_values(self, base_env_vars):
        """Test Settings default values."""
        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()

            assert settings.jwt_algorithm == 'RS256'
            assert settings.jwt_expire_minutes == 30
            assert settings.mfa_issuer == 'CatNet'
            assert settings.environment == 'development'
            assert settings.log_level == 'INFO'
            assert settings.log_format == 'json'


class TestDatabaseConfiguration:
    """Test database configuration."""

    def test_database_url_postgresql(self, base_env_vars):
        """Test PostgreSQL database URL."""
        base_env_vars['DATABASE_URL'] = 'postgresql://user:pass@localhost:5432/catnet'

        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()
            assert 'postgresql://' in settings.database_url

    def test_redis_url_configuration(self, base_env_vars):
        """Test Redis URL configuration."""
        base_env_vars['REDIS_URL'] = 'redis://localhost:6379/0'

        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()
            assert settings.redis_url == 'redis://localhost:6379/0'


class TestSecurityConfiguration:
    """Test security configuration."""

    def test_secret_key_as_secret_str(self, base_env_vars):
        """Test secret key is stored as SecretStr."""
        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()

            # SecretStr should not print the actual value
            assert repr(settings.secret_key) == "SecretStr('**********')"
            # But get_secret_value() should return the actual value
            assert settings.secret_key.get_secret_value() == 'test_secret_key_min_32_chars_long'

    def test_jwt_configuration(self, base_env_vars):
        """Test JWT configuration."""
        base_env_vars['JWT_ALGORITHM'] = 'HS256'
        base_env_vars['JWT_EXPIRE_MINUTES'] = '60'

        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()
            assert settings.jwt_algorithm == 'HS256'
            assert settings.jwt_expire_minutes == 60

    def test_mfa_configuration(self, base_env_vars):
        """Test MFA configuration."""
        base_env_vars['MFA_ISSUER'] = 'TestCatNet'

        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()
            assert settings.mfa_issuer == 'TestCatNet'


class TestVaultConfiguration:
    """Test HashiCorp Vault configuration."""

    def test_vault_basic_configuration(self, base_env_vars):
        """Test basic Vault configuration."""
        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()

            assert settings.vault_url == 'http://localhost:8200'
            assert settings.vault_mount_point == 'secret'
            assert settings.vault_namespace == 'catnet'

    def test_vault_custom_configuration(self, base_env_vars):
        """Test custom Vault configuration."""
        base_env_vars['VAULT_URL'] = 'https://vault.example.com:8200'
        base_env_vars['VAULT_MOUNT_POINT'] = 'kv-v2'
        base_env_vars['VAULT_NAMESPACE'] = 'production'

        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()

            assert settings.vault_url == 'https://vault.example.com:8200'
            assert settings.vault_mount_point == 'kv-v2'
            assert settings.vault_namespace == 'production'


class TestLDAPConfiguration:
    """Test LDAP/AD configuration."""

    def test_ldap_optional_configuration(self, base_env_vars):
        """Test LDAP is optional."""
        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()

            assert settings.ldap_server is None
            assert settings.ldap_bind_dn is None
            assert settings.ldap_bind_password is None
            assert settings.ldap_base_dn is None

    def test_ldap_configured(self, base_env_vars):
        """Test LDAP when configured."""
        base_env_vars['LDAP_SERVER'] = 'ldap://ldap.example.com'
        base_env_vars['LDAP_BIND_DN'] = 'cn=admin,dc=example,dc=com'
        base_env_vars['LDAP_BIND_PASSWORD'] = 'ldap_password'
        base_env_vars['LDAP_BASE_DN'] = 'ou=users,dc=example,dc=com'

        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()

            assert settings.ldap_server == 'ldap://ldap.example.com'
            assert settings.ldap_bind_dn == 'cn=admin,dc=example,dc=com'
            assert settings.ldap_bind_password.get_secret_value() == 'ldap_password'
            assert settings.ldap_base_dn == 'ou=users,dc=example,dc=com'


class TestOAuthSAMLConfiguration:
    """Test OAuth2 and SAML configuration."""

    def test_oauth_optional(self, base_env_vars):
        """Test OAuth is optional."""
        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()

            assert settings.oauth_client_id is None
            assert settings.oauth_client_secret is None

    def test_oauth_configured(self, base_env_vars):
        """Test OAuth when configured."""
        base_env_vars['OAUTH_CLIENT_ID'] = 'oauth_client_id_123'
        base_env_vars['OAUTH_CLIENT_SECRET'] = 'oauth_client_secret_456'

        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()

            assert settings.oauth_client_id == 'oauth_client_id_123'
            assert settings.oauth_client_secret.get_secret_value() == 'oauth_client_secret_456'

    def test_saml_optional(self, base_env_vars):
        """Test SAML is optional."""
        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()

            assert settings.saml_idp_url is None
            assert settings.saml_sp_entity_id is None

    def test_saml_configured(self, base_env_vars):
        """Test SAML when configured."""
        base_env_vars['SAML_IDP_URL'] = 'https://idp.example.com/saml'
        base_env_vars['SAML_SP_ENTITY_ID'] = 'catnet-sp'

        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()

            assert settings.saml_idp_url == 'https://idp.example.com/saml'
            assert settings.saml_sp_entity_id == 'catnet-sp'


class TestMessageQueueConfiguration:
    """Test message queue configuration."""

    def test_rabbitmq_optional(self, base_env_vars):
        """Test RabbitMQ is optional."""
        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()
            assert settings.rabbitmq_url is None

    def test_rabbitmq_configured(self, base_env_vars):
        """Test RabbitMQ when configured."""
        base_env_vars['RABBITMQ_URL'] = 'amqp://guest:guest@localhost:5672/'

        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()
            assert settings.rabbitmq_url == 'amqp://guest:guest@localhost:5672/'

    def test_kafka_optional(self, base_env_vars):
        """Test Kafka is optional."""
        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()
            assert settings.kafka_bootstrap_servers is None

    def test_kafka_configured(self, base_env_vars):
        """Test Kafka when configured."""
        base_env_vars['KAFKA_BOOTSTRAP_SERVERS'] = 'localhost:9092,localhost:9093'

        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()
            assert settings.kafka_bootstrap_servers == 'localhost:9092,localhost:9093'


class TestServicePortsConfiguration:
    """Test service ports configuration."""

    def test_default_service_ports(self, base_env_vars):
        """Test default service ports."""
        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()

            assert settings.auth_service_port == 8081
            assert settings.gitops_service_port == 8082
            assert settings.deployment_service_port == 8083
            assert settings.device_service_port == 8084

    def test_custom_service_ports(self, base_env_vars):
        """Test custom service ports."""
        base_env_vars['AUTH_SERVICE_PORT'] = '9001'
        base_env_vars['GITOPS_SERVICE_PORT'] = '9002'

        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()

            assert settings.auth_service_port == 9001
            assert settings.gitops_service_port == 9002


class TestTLSConfiguration:
    """Test TLS/mTLS configuration."""

    def test_default_tls_paths(self, base_env_vars):
        """Test default TLS certificate paths."""
        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()

            assert settings.tls_cert_path == Path('/etc/catnet/certs/server.crt')
            assert settings.tls_key_path == Path('/etc/catnet/certs/server.key')
            assert settings.tls_ca_path == Path('/etc/catnet/certs/ca.crt')

    def test_mtls_enabled_by_default(self, base_env_vars):
        """Test mTLS is enabled by default."""
        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()

            assert settings.mtls_enabled is True
            assert settings.verify_client_cert is True

    def test_mtls_can_be_disabled(self, base_env_vars):
        """Test mTLS can be disabled."""
        base_env_vars['MTLS_ENABLED'] = 'false'
        base_env_vars['VERIFY_CLIENT_CERT'] = 'false'

        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()

            assert settings.mtls_enabled is False
            assert settings.verify_client_cert is False


class TestMonitoringConfiguration:
    """Test monitoring configuration."""

    def test_prometheus_port(self, base_env_vars):
        """Test Prometheus port configuration."""
        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()
            assert settings.prometheus_port == 9090

    def test_grafana_optional(self, base_env_vars):
        """Test Grafana URL is optional."""
        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()
            assert settings.grafana_url is None

    def test_grafana_configured(self, base_env_vars):
        """Test Grafana when configured."""
        base_env_vars['GRAFANA_URL'] = 'http://grafana.example.com:3000'

        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()
            assert settings.grafana_url == 'http://grafana.example.com:3000'


class TestGitConfiguration:
    """Test Git configuration."""

    def test_git_default_branch(self, base_env_vars):
        """Test Git default branch."""
        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()
            assert settings.git_default_branch == 'main'

    def test_git_webhook_secret(self, base_env_vars):
        """Test Git webhook secret."""
        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()
            assert settings.git_webhook_secret.get_secret_value() == 'test_webhook_secret'

    def test_gpg_verification_enabled(self, base_env_vars):
        """Test GPG verification is enabled by default."""
        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()
            assert settings.gpg_verification_enabled is True


class TestDeploymentConfiguration:
    """Test deployment configuration."""

    def test_default_canary_stages(self, base_env_vars):
        """Test default canary deployment stages."""
        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()
            assert settings.canary_stages == [5, 25, 50, 100]
            assert settings.canary_wait_minutes == [5, 10, 15, 0]

    def test_custom_canary_stages_from_string(self, base_env_vars):
        """Test parsing canary stages from string."""
        base_env_vars['CANARY_STAGES'] = '10,20,50,100'
        base_env_vars['CANARY_WAIT_MINUTES'] = '2,5,10,0'

        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()
            assert settings.canary_stages == [10, 20, 50, 100]
            assert settings.canary_wait_minutes == [2, 5, 10, 0]

    def test_rollback_timeout(self, base_env_vars):
        """Test rollback timeout configuration."""
        base_env_vars['ROLLBACK_TIMEOUT_SECONDS'] = '600'

        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()
            assert settings.rollback_timeout_seconds == 600

    def test_max_parallel_deployments(self, base_env_vars):
        """Test max parallel deployments."""
        base_env_vars['MAX_PARALLEL_DEPLOYMENTS'] = '20'

        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()
            assert settings.max_parallel_deployments == 20


class TestLoggingConfiguration:
    """Test logging configuration."""

    def test_default_logging(self, base_env_vars):
        """Test default logging configuration."""
        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()

            assert settings.log_level == 'INFO'
            assert settings.log_format == 'json'
            assert settings.audit_log_path == Path('/var/log/catnet/audit.log')

    def test_custom_logging(self, base_env_vars):
        """Test custom logging configuration."""
        base_env_vars['LOG_LEVEL'] = 'DEBUG'
        base_env_vars['LOG_FORMAT'] = 'text'
        base_env_vars['AUDIT_LOG_PATH'] = '/custom/path/audit.log'

        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()

            assert settings.log_level == 'DEBUG'
            assert settings.log_format == 'text'
            assert settings.audit_log_path == Path('/custom/path/audit.log')


class TestEncryptionConfiguration:
    """Test encryption configuration."""

    def test_default_encryption(self, base_env_vars):
        """Test default encryption configuration."""
        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()

            assert settings.encryption_algorithm == 'AES-256-GCM'
            assert settings.kms_key_id is None

    def test_kms_configured(self, base_env_vars):
        """Test KMS key configuration."""
        base_env_vars['KMS_KEY_ID'] = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'

        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()
            assert settings.kms_key_id.startswith('arn:aws:kms')


class TestNetworkDeviceConfiguration:
    """Test network device configuration."""

    def test_default_device_settings(self, base_env_vars):
        """Test default device settings."""
        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()

            assert settings.default_device_timeout == 30
            assert settings.default_device_port_ssh == 22
            assert settings.default_device_port_telnet == 23
            assert settings.enable_telnet is False

    def test_telnet_can_be_enabled(self, base_env_vars):
        """Test Telnet can be enabled."""
        base_env_vars['ENABLE_TELNET'] = 'true'

        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()
            assert settings.enable_telnet is True


class TestSessionRecordingConfiguration:
    """Test session recording configuration."""

    def test_session_recording_enabled_by_default(self, base_env_vars):
        """Test session recording is enabled by default."""
        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()

            assert settings.session_recording_enabled is True
            assert settings.session_recording_path == Path('/var/log/catnet/sessions/')

    def test_session_recording_can_be_disabled(self, base_env_vars):
        """Test session recording can be disabled."""
        base_env_vars['SESSION_RECORDING_ENABLED'] = 'false'

        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()
            assert settings.session_recording_enabled is False


class TestRateLimitingConfiguration:
    """Test rate limiting configuration."""

    def test_rate_limiting_enabled_by_default(self, base_env_vars):
        """Test rate limiting is enabled by default."""
        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()

            assert settings.rate_limit_enabled is True
            assert settings.rate_limit_requests_per_minute == 100

    def test_custom_rate_limit(self, base_env_vars):
        """Test custom rate limit."""
        base_env_vars['RATE_LIMIT_REQUESTS_PER_MINUTE'] = '200'

        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()
            assert settings.rate_limit_requests_per_minute == 200


class TestEnvironmentValidation:
    """Test environment validation."""

    def test_valid_environments(self, base_env_vars):
        """Test valid environment values."""
        for env in ['development', 'staging', 'production']:
            base_env_vars['ENVIRONMENT'] = env

            with patch.dict('os.environ', base_env_vars, clear=True):
                settings = Settings()
                assert settings.environment == env

    def test_invalid_environment(self, base_env_vars):
        """Test invalid environment raises error."""
        base_env_vars['ENVIRONMENT'] = 'invalid_env'

        with patch.dict('os.environ', base_env_vars, clear=True):
            with pytest.raises(PydanticValidationError) as exc_info:
                Settings()

            assert 'Environment must be one of' in str(exc_info.value)

    def test_is_production_property(self, production_env_vars):
        """Test is_production property."""
        with patch.dict('os.environ', production_env_vars, clear=True):
            settings = Settings()
            assert settings.is_production is True
            assert settings.is_development is False

    def test_is_development_property(self, development_env_vars):
        """Test is_development property."""
        with patch.dict('os.environ', development_env_vars, clear=True):
            settings = Settings()
            assert settings.is_production is False
            assert settings.is_development is True


class TestConfigClass:
    """Test Config class settings."""

    def test_env_file_configuration(self, base_env_vars):
        """Test .env file configuration."""
        with patch.dict('os.environ', base_env_vars, clear=True):
            settings = Settings()

            # Config class should be properly set
            assert settings.Config.env_file == '.env'
            assert settings.Config.env_file_encoding == 'utf-8'
            assert settings.Config.case_sensitive is False
