from typing import Optional, List
from pydantic_settings import BaseSettings
from pydantic import Field, SecretStr, validator
import os
from pathlib import Path


class Settings(BaseSettings):
    # Database
    database_url: str = Field(..., env="DATABASE_URL")
    redis_url: str = Field(..., env="REDIS_URL")

    # Security
    secret_key: SecretStr = Field(..., env="SECRET_KEY")
    jwt_algorithm: str = Field(default="RS256", env="JWT_ALGORITHM")
    jwt_expire_minutes: int = Field(default=30, env="JWT_EXPIRE_MINUTES")
    mfa_issuer: str = Field(default="CatNet", env="MFA_ISSUER")

    # HashiCorp Vault
    vault_url: str = Field(..., env="VAULT_URL")
    vault_token: SecretStr = Field(..., env="VAULT_TOKEN")
    vault_mount_point: str = Field(default="secret", env="VAULT_MOUNT_POINT")
    vault_namespace: str = Field(default="catnet", env="VAULT_NAMESPACE")

    # LDAP/AD
    ldap_server: Optional[str] = Field(None, env="LDAP_SERVER")
    ldap_bind_dn: Optional[str] = Field(None, env="LDAP_BIND_DN")
    ldap_bind_password: Optional[SecretStr] = Field(None, env="LDAP_BIND_PASSWORD")
    ldap_base_dn: Optional[str] = Field(None, env="LDAP_BASE_DN")

    # OAuth2/SAML
    oauth_client_id: Optional[str] = Field(None, env="OAUTH_CLIENT_ID")
    oauth_client_secret: Optional[SecretStr] = Field(None, env="OAUTH_CLIENT_SECRET")
    saml_idp_url: Optional[str] = Field(None, env="SAML_IDP_URL")
    saml_sp_entity_id: Optional[str] = Field(None, env="SAML_SP_ENTITY_ID")

    # Message Queue
    rabbitmq_url: Optional[str] = Field(None, env="RABBITMQ_URL")
    kafka_bootstrap_servers: Optional[str] = Field(None, env="KAFKA_BOOTSTRAP_SERVERS")

    # Service Ports
    auth_service_port: int = Field(default=8081, env="AUTH_SERVICE_PORT")
    gitops_service_port: int = Field(default=8082, env="GITOPS_SERVICE_PORT")
    deployment_service_port: int = Field(default=8083, env="DEPLOYMENT_SERVICE_PORT")
    device_service_port: int = Field(default=8084, env="DEVICE_SERVICE_PORT")

    # TLS/mTLS
    tls_cert_path: Path = Field(default=Path("/etc/catnet/certs/server.crt"), env="TLS_CERT_PATH")
    tls_key_path: Path = Field(default=Path("/etc/catnet/certs/server.key"), env="TLS_KEY_PATH")
    tls_ca_path: Path = Field(default=Path("/etc/catnet/certs/ca.crt"), env="TLS_CA_PATH")
    mtls_enabled: bool = Field(default=True, env="MTLS_ENABLED")
    verify_client_cert: bool = Field(default=True, env="VERIFY_CLIENT_CERT")

    # Monitoring
    prometheus_port: int = Field(default=9090, env="PROMETHEUS_PORT")
    grafana_url: Optional[str] = Field(None, env="GRAFANA_URL")

    # Git Settings
    git_default_branch: str = Field(default="main", env="GIT_DEFAULT_BRANCH")
    git_webhook_secret: SecretStr = Field(..., env="GIT_WEBHOOK_SECRET")
    gpg_verification_enabled: bool = Field(default=True, env="GPG_VERIFICATION_ENABLED")
    gpg_home_dir: Path = Field(default=Path("/var/catnet/.gnupg"), env="GPG_HOME_DIR")
    gpg_trusted_keys: List[str] = Field(default=[], env="GPG_TRUSTED_KEYS")
    gpg_reject_untrusted: bool = Field(default=True, env="GPG_REJECT_UNTRUSTED")
    gpg_require_signatures: bool = Field(default=True, env="GPG_REQUIRE_SIGNATURES")

    # Deployment Settings
    canary_stages: List[int] = Field(default=[5, 25, 50, 100], env="CANARY_STAGES")
    canary_wait_minutes: List[int] = Field(default=[5, 10, 15, 0], env="CANARY_WAIT_MINUTES")
    rollback_timeout_seconds: int = Field(default=300, env="ROLLBACK_TIMEOUT_SECONDS")
    max_parallel_deployments: int = Field(default=10, env="MAX_PARALLEL_DEPLOYMENTS")

    # Logging
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_format: str = Field(default="json", env="LOG_FORMAT")
    audit_log_path: Path = Field(default=Path("/var/log/catnet/audit.log"), env="AUDIT_LOG_PATH")

    # Encryption
    encryption_algorithm: str = Field(default="AES-256-GCM", env="ENCRYPTION_ALGORITHM")
    kms_key_id: Optional[str] = Field(None, env="KMS_KEY_ID")

    # Network Device Defaults
    default_device_timeout: int = Field(default=30, env="DEFAULT_DEVICE_TIMEOUT")
    default_device_port_ssh: int = Field(default=22, env="DEFAULT_DEVICE_PORT_SSH")
    # Telnet support removed for security compliance (NIST 800-53, CIS, PCI DSS)

    # Session Recording
    session_recording_enabled: bool = Field(default=True, env="SESSION_RECORDING_ENABLED")
    session_recording_path: Path = Field(default=Path("/var/log/catnet/sessions/"), env="SESSION_RECORDING_PATH")

    # Rate Limiting
    rate_limit_enabled: bool = Field(default=True, env="RATE_LIMIT_ENABLED")
    rate_limit_requests_per_minute: int = Field(default=100, env="RATE_LIMIT_REQUESTS_PER_MINUTE")

    # Environment
    environment: str = Field(default="development", env="ENVIRONMENT")

    @validator("canary_stages", pre=True)
    def parse_canary_stages(cls, v):
        if isinstance(v, str):
            return [int(x) for x in v.split(",")]
        return v

    @validator("canary_wait_minutes", pre=True)
    def parse_canary_wait(cls, v):
        if isinstance(v, str):
            return [int(x) for x in v.split(",")]
        return v

    @validator("environment")
    def validate_environment(cls, v):
        allowed_envs = ["development", "staging", "production"]
        if v not in allowed_envs:
            raise ValueError(f"Environment must be one of {allowed_envs}")
        return v

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_development(self) -> bool:
        return self.environment == "development"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


settings = Settings()