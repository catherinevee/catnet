"""
Configuration management for CatNet CLI
"""
import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)



class ConfigManager:
    """Manage CLI configuration from files and environment"""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._find_config_file()
        self.config: Dict[str, Any] = {}

    def _find_config_file(self) -> Optional[Path]:
        """Find configuration file in standard locations"""
        search_paths = [
            Path.home() / '.catnet.yml',
            Path.home() / '.catnet.yaml',
            Path.home() / '.catnet' / 'config.yml',
            Path.home() / '.catnet' / 'config.yaml',
            Path.cwd() / '.catnet.yml',
            Path.cwd() / '.catnet.yaml',
        ]

        for path in search_paths:
            if path.exists():
                logger.debug(f"Found config file: {path}")
                return path

        return None

    def load(self) -> Dict[str, Any]:
        """Load configuration from file and environment"""
        config = self._load_defaults()

        # Load from file if exists
        if self.config_path:
            file_config = self._load_file(self.config_path)
            config = self._merge_config(config, file_config)

        # Override with environment variables
        env_config = self._load_environment()
        config = self._merge_config(config, env_config)

        self.config = config
        return config

    def _load_defaults(self) -> Dict[str, Any]:
        """Load default configuration"""
        return {
            'api': {
                'base_url': 'http://localhost:8000',
                'auth_url': 'http://localhost:8081',
                'gitops_url': 'http://localhost:8082',
                'deploy_url': 'http://localhost:8083',
                'device_url': 'http://localhost:8084',
                'timeout': 30,
            },
            'vault': {
                'url': 'http://localhost:8200',
                'namespace': 'catnet',
            },
            'defaults': {
                'deployment_strategy': 'canary',
                'backup_before_deploy': True,
                'require_approval': True,
            },
            'logging': {
                'level': 'INFO',
                'format': 'json',
            },
            'security': {
                'verify_ssl': True,
                'mfa_required': True,
            }
        }

    def _load_file(self, path: Path) -> Dict[str, Any]:
        """Load configuration from file"""
        try:
            path = Path(path)
            if not path.exists():
                logger.warning(f"Config file not found: {path}")
                return {}

            with open(path, 'r') as f:
                if path.suffix in ['.yml', '.yaml']:
                    return yaml.safe_load(f) or {}
                elif path.suffix == '.json':
                    return json.load(f)
                else:
                    logger.warning(f"Unknown config file format: {path}")
                    return {}

        except Exception as e:
            logger.error(f"Error loading config file: {e}")
            return {}

    def _load_environment(self) -> Dict[str, Any]:
        """Load configuration from environment variables"""
        config = {}

        # API URLs
        if url:= os.getenv('CATNET_API_URL'):
            config.setdefault('api', {})['base_url'] = url
        if url:= os.getenv('CATNET_AUTH_URL'):
            config.setdefault('api', {})['auth_url'] = url
        if url:= os.getenv('CATNET_GITOPS_URL'):
            config.setdefault('api', {})['gitops_url'] = url
        if url:= os.getenv('CATNET_DEPLOY_URL'):
            config.setdefault('api', {})['deploy_url'] = url
        if url:= os.getenv('CATNET_DEVICE_URL'):
            config.setdefault('api', {})['device_url'] = url

        # Vault
        if url:= os.getenv('CATNET_VAULT_URL'):
            config.setdefault('vault', {})['url'] = url
        if namespace:= os.getenv('CATNET_VAULT_NAMESPACE'):
            config.setdefault('vault', {})['namespace'] = namespace

        # Debug
        if debug:= os.getenv('CATNET_DEBUG'):
            config['debug'] = debug.lower() in ['1', 'true', 'yes']

        return config

        def _merge_config(
        self,
        base: Dict[str,
        Any],
        override: Dict[str,
        Any]
    ) -> Dict[str, Any]:
        """Merge two configuration dictionaries"""
        result = base.copy()

        for key, value in override.items():
                        if key in result and isinstance(
                result[key],
                dict) and isinstance(value,
                dict
            ):
                result[key] = self._merge_config(result[key], value)
            else:
                result[key] = value

        return result

    def save_token(self, token_data: Dict[str, Any]):
        """Save authentication token securely"""
        token_dir = Path.home() / '.catnet'
        token_dir.mkdir(exist_ok=True)
        token_file = token_dir / 'tokens.json'

        # Set restrictive permissions (Unix-like systems)
        if hasattr(os, 'chmod'):
            os.chmod(token_dir, 0o700)

        # Encrypt token data before saving
        # Note: In production, use proper encryption
        with open(token_file, 'w') as f:
            json.dump(token_data, f, indent=2)

        if hasattr(os, 'chmod'):
            os.chmod(token_file, 0o600)

    def get_token(self) -> Optional[Dict[str, Any]]:
        """Retrieve saved authentication token"""
        token_file = Path.home() / '.catnet' / 'tokens.json'

        if not token_file.exists():
            return None

        try:
            with open(token_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading token: {e}")
            return None

    def clear_token(self):
        """Clear saved authentication token"""
        token_file = Path.home() / '.catnet' / 'tokens.json'
        if token_file.exists():
            token_file.unlink()
            logger.debug("Authentication token cleared")
