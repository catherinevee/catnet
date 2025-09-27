"""
CatNet Configuration Settings
Comprehensive configuration management for all environments
"""

import os
import secrets
from typing import Dict, List, Optional, Any
from pathlib import Path
from enum import Enum

from pydantic import BaseSettings, validator, Field
from pydantic.networks import PostgresDsn, RedisDsn


class Environment(str, Enum):
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"


class SecurityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DatabaseSettings(BaseSettings):
    """Database configuration settings"""

    # PostgreSQL settings
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "catnet"
    POSTGRES_USER: str = "catnet"
    POSTGRES_PASSWORD: str = ""
    POSTGRES_SSL_MODE: str = "require"
    POSTGRES_MAX_CONNECTIONS: int = 50
    POSTGRES_MIN_CONNECTIONS: int = 5
    POSTGRES_ACQUIRE_TIMEOUT: int = 30
    POSTGRES_QUERY_TIMEOUT: int = 60

    # Redis settings
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: Optional[str] = None
    REDIS_SSL: bool = False
    REDIS_MAX_CONNECTIONS: int = 20

    @property
    def postgres_dsn(self) -> str:
        return f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}?ssl={self.POSTGRES_SSL_MODE}"

    @property
    def redis_dsn(self) -> str:
        protocol = "rediss" if self.REDIS_SSL else "redis"
        auth = f":{self.REDIS_PASSWORD}@" if self.REDIS_PASSWORD else ""
        return f"{protocol}://{auth}{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"


class VaultSettings(BaseSettings):
    """HashiCorp Vault configuration"""

    VAULT_URL: str = "https://vault.local:8200"
    VAULT_TOKEN: Optional[str] = None
    VAULT_ROLE_ID: Optional[str] = None
    VAULT_SECRET_ID: Optional[str] = None
    VAULT_NAMESPACE: Optional[str] = None
    VAULT_MOUNT_POINT: str = "catnet"
    VAULT_KV_VERSION: int = 2
    VAULT_SSL_VERIFY: bool = True
    VAULT_TIMEOUT: int = 30
    VAULT_RETRY_ATTEMPTS: int = 3

    # Encryption settings
    ENCRYPTION_KEY_PATH: str = "secret/catnet/encryption"
    DEVICE_CREDENTIALS_PATH: str = "secret/catnet/devices"
    API_KEYS_PATH: str = "secret/catnet/api-keys"


class SecuritySettings(BaseSettings):
    """Security configuration settings"""

    # JWT settings
    JWT_SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    JWT_ISSUER: str = "catnet"
    JWT_AUDIENCE: str = "catnet-api"

    # Password settings
    PASSWORD_MIN_LENGTH: int = 12
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGITS: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True
    PASSWORD_BCRYPT_ROUNDS: int = 12

    # MFA settings
    MFA_ISSUER: str = "CatNet"
    MFA_WINDOW: int = 2
    MFA_BACKUP_CODES_COUNT: int = 10

    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 100
    RATE_LIMIT_BURST: int = 200
    RATE_LIMIT_BAN_DURATION: int = 3600  # seconds

    # Security headers
    SECURITY_HEADERS_ENABLED: bool = True
    HSTS_MAX_AGE: int = 31536000
    CSP_POLICY: str = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"

    # SSL/TLS settings
    SSL_REDIRECT: bool = True
    SSL_CERT_PATH: Optional[str] = None
    SSL_KEY_PATH: Optional[str] = None
    SSL_CA_CERTS: Optional[str] = None

    # Audit settings
    AUDIT_LOG_RETENTION_DAYS: int = 2555  # 7 years
    AUDIT_LOG_ENCRYPTION: bool = True
    AUDIT_LOG_SIGNING: bool = True

    # Session settings
    SESSION_TIMEOUT_MINUTES: int = 480  # 8 hours
    SESSION_ABSOLUTE_TIMEOUT_HOURS: int = 24
    MAX_CONCURRENT_SESSIONS: int = 5


class NetworkSettings(BaseSettings):
    """Network and device connectivity settings"""

    # SSH settings
    SSH_TIMEOUT: int = 30
    SSH_CONNECT_TIMEOUT: int = 10
    SSH_BANNER_TIMEOUT: int = 5
    SSH_MAX_CONNECTIONS_PER_DEVICE: int = 3
    SSH_KEY_PATH: str = "/etc/catnet/ssh/catnet_key"
    SSH_KNOWN_HOSTS_PATH: str = "/etc/catnet/ssh/known_hosts"

    # Device settings
    DEVICE_COMMAND_TIMEOUT: int = 60
    DEVICE_HEALTH_CHECK_INTERVAL: int = 300  # 5 minutes
    DEVICE_CONNECTION_POOL_SIZE: int = 100
    DEVICE_MAX_RETRY_ATTEMPTS: int = 3
    DEVICE_BACKUP_RETENTION_DAYS: int = 90

    # Network discovery
    DISCOVERY_TIMEOUT: int = 30
    DISCOVERY_MAX_CONCURRENT: int = 50
    DISCOVERY_PING_TIMEOUT: int = 2

    # Bastion/Jump host settings
    BASTION_ENABLED: bool = True
    BASTION_HOSTS: List[str] = ["bastion1.catnet.local", "bastion2.catnet.local"]
    BASTION_SSH_PORT: int = 22
    BASTION_TIMEOUT: int = 10


class DeploymentSettings(BaseSettings):
    """Deployment and GitOps configuration"""

    # Deployment settings
    MAX_CONCURRENT_DEPLOYMENTS: int = 10
    DEPLOYMENT_TIMEOUT_HOURS: int = 4
    DEPLOYMENT_LOG_RETENTION_DAYS: int = 365

    # Rollback settings
    AUTO_ROLLBACK_ENABLED: bool = True
    ROLLBACK_TIMEOUT_MINUTES: int = 15
    ROLLBACK_MAX_ATTEMPTS: int = 3

    # Canary deployment settings
    CANARY_INITIAL_PERCENTAGE: int = 5
    CANARY_STEP_PERCENTAGE: int = 25
    CANARY_WAIT_MINUTES: int = 10
    CANARY_SUCCESS_THRESHOLD: float = 0.95

    # GitOps settings
    GIT_CLONE_TIMEOUT: int = 300
    GIT_POLL_INTERVAL: int = 60
    GIT_WEBHOOK_SECRET_LENGTH: int = 32
    GIT_SIGNATURE_VERIFICATION: bool = True

    # Configuration validation
    CONFIG_VALIDATION_STRICT: bool = True
    CONFIG_SYNTAX_CHECK: bool = True
    CONFIG_SECURITY_SCAN: bool = True
    CONFIG_MAX_SIZE_MB: int = 10


class MonitoringSettings(BaseSettings):
    """Monitoring and observability configuration"""

    # Metrics settings
    METRICS_ENABLED: bool = True
    METRICS_PORT: int = 9090
    METRICS_PATH: str = "/metrics"
    METRICS_RETENTION_DAYS: int = 30

    # Prometheus settings
    PROMETHEUS_URL: Optional[str] = None
    PROMETHEUS_QUERY_TIMEOUT: int = 30
    PROMETHEUS_MAX_SAMPLES: int = 50000

    # Alert settings
    ALERTS_ENABLED: bool = True
    ALERT_EVALUATION_INTERVAL: int = 60
    ALERT_MANAGER_URL: Optional[str] = None

    # Health check settings
    HEALTH_CHECK_INTERVAL: int = 30
    HEALTH_CHECK_TIMEOUT: int = 10
    HEALTH_CHECK_RETRIES: int = 3

    # Logging settings
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    LOG_ROTATION_SIZE: str = "100MB"
    LOG_RETENTION_DAYS: int = 30
    STRUCTURED_LOGGING: bool = True


class APISettings(BaseSettings):
    """API server configuration"""

    # Server settings
    HOST: str = "0.0.0.0"
    PORT: int = 8080
    WORKERS: int = 4
    WORKER_CLASS: str = "uvicorn.workers.UvicornWorker"
    WORKER_TIMEOUT: int = 120

    # Request settings
    MAX_REQUEST_SIZE: int = 10 * 1024 * 1024  # 10MB
    REQUEST_TIMEOUT: int = 60
    KEEP_ALIVE_TIMEOUT: int = 5

    # CORS settings
    CORS_ENABLED: bool = True
    CORS_ORIGINS: List[str] = ["https://localhost:3000", "https://catnet.local"]
    CORS_METHODS: List[str] = ["GET", "POST", "PUT", "DELETE", "PATCH"]
    CORS_HEADERS: List[str] = ["*"]

    # Documentation settings
    DOCS_ENABLED: bool = True
    DOCS_URL: str = "/docs"
    REDOC_URL: str = "/redoc"
    OPENAPI_URL: str = "/openapi.json"


class CatNetSettings(BaseSettings):
    """Main CatNet application settings"""

    # Application info
    APP_NAME: str = "CatNet"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = "Secure Network Configuration Deployment System"

    # Environment
    ENVIRONMENT: Environment = Environment.PRODUCTION
    DEBUG: bool = False
    TESTING: bool = False

    # Security level
    SECURITY_LEVEL: SecurityLevel = SecurityLevel.CRITICAL

    # Component settings
    database: DatabaseSettings = DatabaseSettings()
    vault: VaultSettings = VaultSettings()
    security: SecuritySettings = SecuritySettings()
    network: NetworkSettings = NetworkSettings()
    deployment: DeploymentSettings = DeploymentSettings()
    monitoring: MonitoringSettings = MonitoringSettings()
    api: APISettings = APISettings()

    # Feature flags
    FEATURES_ENABLED: Dict[str, bool] = {
        "mfa_required": True,
        "audit_logging": True,
        "device_discovery": True,
        "gitops": True,
        "canary_deployments": True,
        "rollback_automation": True,
        "secret_scanning": True,
        "compliance_reporting": True,
        "real_time_monitoring": True,
        "alert_notifications": True
    }

    # Integration settings
    INTEGRATIONS: Dict[str, Dict[str, Any]] = {
        "slack": {
            "enabled": False,
            "webhook_url": None,
            "channel": "#catnet-alerts"
        },
        "pagerduty": {
            "enabled": False,
            "api_key": None,
            "service_key": None
        },
        "email": {
            "enabled": True,
            "smtp_host": "localhost",
            "smtp_port": 587,
            "smtp_user": None,
            "smtp_password": None,
            "from_address": "catnet@company.com"
        }
    }

    @validator('ENVIRONMENT', pre=True)
    def validate_environment(cls, v):
        if isinstance(v, str):
            return Environment(v.lower())
        return v

    @validator('SECURITY_LEVEL', pre=True)
    def validate_security_level(cls, v):
        if isinstance(v, str):
            return SecurityLevel(v.lower())
        return v

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == Environment.PRODUCTION

    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT == Environment.DEVELOPMENT

    @property
    def is_testing(self) -> bool:
        return self.ENVIRONMENT == Environment.TESTING or self.TESTING

    @property
    def requires_high_security(self) -> bool:
        return self.SECURITY_LEVEL in [SecurityLevel.HIGH, SecurityLevel.CRITICAL]

    class Config:
        env_file = ".env"
        env_prefix = "CATNET_"
        case_sensitive = True
        env_nested_delimiter = "__"


# Configuration factory
def get_settings() -> CatNetSettings:
    """Get application settings with environment-specific overrides"""

    # Base settings
    settings = CatNetSettings()

    # Environment-specific overrides
    if settings.is_development:
        settings.DEBUG = True
        settings.security.SSL_REDIRECT = False
        settings.security.SECURITY_HEADERS_ENABLED = False
        settings.vault.VAULT_SSL_VERIFY = False

    elif settings.is_testing:
        settings.TESTING = True
        settings.DEBUG = True
        settings.database.POSTGRES_DB = "catnet_test"
        settings.database.REDIS_DB = 1
        settings.security.JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 1

    elif settings.is_production:
        settings.DEBUG = False
        settings.api.DOCS_ENABLED = False
        settings.security.SSL_REDIRECT = True
        settings.security.SECURITY_HEADERS_ENABLED = True

    # Security level overrides
    if settings.requires_high_security:
        settings.security.PASSWORD_MIN_LENGTH = 16
        settings.security.PASSWORD_BCRYPT_ROUNDS = 14
        settings.security.JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 5
        settings.security.SESSION_TIMEOUT_MINUTES = 240  # 4 hours
        settings.FEATURES_ENABLED["mfa_required"] = True
        settings.deployment.AUTO_ROLLBACK_ENABLED = True
        settings.monitoring.ALERTS_ENABLED = True

    return settings


# Global settings instance
settings = get_settings()


# Export main components
__all__ = [
    "CatNetSettings",
    "DatabaseSettings",
    "VaultSettings",
    "SecuritySettings",
    "NetworkSettings",
    "DeploymentSettings",
    "MonitoringSettings",
    "APISettings",
    "Environment",
    "SecurityLevel",
    "get_settings",
    "settings"
]