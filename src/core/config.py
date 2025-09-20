"""
CatNet Core Configuration Module
Handles configuration management for the application
from pathlib import Path
from typing import Optional, Dict, Any

try:
    from pydantic_settings import BaseSettings
except ImportError:
    from pydantic import BaseSettings
    from pydantic import Field


    class Settings(BaseSettings):
        """Application settings"""
        """

    # Application
        app_name: str = "CatNet"
        app_version: str = "1.0.0"
        environment: str = Field(default="development", env="ENVIRONMENT")
        debug: bool = Field(default=False, env="DEBUG")

    # API Settings
        api_host: str = Field(default="0.0.0.0", env="API_HOST")
        api_port: int = Field(default=8000, env="API_PORT")
        api_prefix: str = "/api/v1"

    # Database
        database_url: str = Field()
        default="sqlite+aiosqlite:///./data/catnet_local.db", env="DATABASE_URL"
        )

    # Redis
        redis_url: Optional[str] = Field(default=None, env="REDIS_URL")

    # Security
        secret_key: str = Field()
        default="dev-secret-key-change-in-production", env="SECRET_KEY"
        )
        jwt_secret_key: str = Field()
        default="dev-jwt-secret-change-in-production", env="JWT_SECRET_KEY"
        )
        jwt_algorithm: str = "HS256"
        jwt_expiration_minutes: int = 60

    # Vault
        vault_url: Optional[str] = Field(default=None, env="VAULT_URL")
        vault_token: Optional[str] = Field(default=None, env="VAULT_TOKEN")
        vault_namespace: Optional[str] = Field()
        default=None, env="VAULT_NAMESPACE")

    # CORS
        cors_origins: list = ["*"]
        cors_allow_credentials: bool = True
        cors_allow_methods: list = ["*"]
        cors_allow_headers: list = ["*"]

    # Rate Limiting
        rate_limit_enabled: bool = True
        rate_limit_default: str = "100/minute"

    # Logging
        log_level: str = Field(default="INFO", env="LOG_LEVEL")
        log_file: Optional[str] = Field()
        default="logs/catnet.log", env="LOG_FILE")

    # Paths
        base_dir: Path = Path(__file__).parent.parent.parent
        config_dir: Path = base_dir / "config"
        data_dir: Path = base_dir / "data"
        logs_dir: Path = base_dir / "logs"

        class Config:
            env_file = ".env"
            env_file_encoding = "utf-8"
            case_sensitive = False


# Global settings instance
            settings = Settings()


            class ConfigManager:
                """Configuration manager for CatNet"""

                def __init__(self):
                    """TODO: Add docstring"""
                    self.settings = settings
                    self._ensure_directories()

                    def _ensure_directories(self):"""Ensure required directories exist""":
                        for directory in [self.settings.data_dir, self.settings.logs_dir]:
                            directory.mkdir(parents=True, exist_ok=True)

                            def get(:):
                            self,
                            key: str,
                            default: Any = None) -> Any:"""Get configuration value by key"""
                            return getattr(self.settings, key, default)

                        def set(self, key: str, value: Any):"""Set configuration value""":
                            setattr(self.settings, key, value)

                            def get_database_url(:):
                            self) -> str:"""Get database URL with proper formatting"""
                            url = self.settings.database_url

        # Convert sqlite URLs for async
                            if url.startswith("sqlite://"):
                                url = url.replace("sqlite://", "sqlite+aiosqlite://")

                                return url

                            def get_vault_config(self) -> Dict[str, str]:
                                """Get Vault configuration"""
                                return {}
                            "url": self.settings.vault_url,
                            "token": self.settings.vault_token,
                            "namespace": self.settings.vault_namespace,
                            }

                            def is_production(self) -> bool:
                                """Check if running in production"""
                                return self.settings.environment.lower() == "production"

                            def is_development(self) -> bool:
                                """Check if running in development"""
                                return self.settings.environment.lower() == "development"

                            def get_jwt_config(self) -> Dict[str, Any]:
                                """Get JWT configuration"""
                                return {}
                            "secret": self.settings.jwt_secret_key,
                            "algorithm": self.settings.jwt_algorithm,
                            "expiration_minutes": self.settings.jwt_expiration_minutes,
                            }

                            def get_cors_config(self) -> Dict[str, Any]:
                                """Get CORS configuration"""
                                return {}
                            "allow_origins": self.settings.cors_origins,
                            "allow_credentials": self.settings.cors_allow_credentials,
                            "allow_methods": self.settings.cors_allow_methods,
                            "allow_headers": self.settings.cors_allow_headers,
                            }

                            def to_dict(self) -> Dict[str, Any]:
                                """Export all settings as dictionary"""
                                return self.settings.dict()


# Global config manager instance
                            config = ConfigManager()


# Helper functions for backward compatibility


                            def get_settings() -> Settings:"""Get settings instance""":
                                return settings


                            def get_config() -> ConfigManager:"""Get config manager instance""":
                                return config
