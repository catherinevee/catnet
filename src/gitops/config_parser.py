from typing import Dict, Any, Optional, List
import yaml
import json
import os
import structlog
from pathlib import Path

logger = structlog.get_logger()

class ConfigParser:
    def __init__(self):
        self.supported_formats = ['.yaml', '.yml', '.json', '.conf']

    async def parse_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        try:
            if not os.path.exists(file_path):
                logger.warning(f"Config file not found: {file_path}")
                return None

            file_ext = Path(file_path).suffix.lower()

            if file_ext not in self.supported_formats:
                logger.warning(f"Unsupported config format: {file_ext}")
                return None

            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            if file_ext in ['.yaml', '.yml']:
                return yaml.safe_load(content)
            elif file_ext == '.json':
                return json.loads(content)
            else:
                return self._parse_conf_file(content)

        except Exception as e:
            logger.error(f"Failed to parse config file {file_path}: {e}")
            return None

    def _parse_conf_file(self, content: str) -> Dict[str, Any]:
        config = {}
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip()
        return config

    async def validate_schema(self, config: Dict[str, Any]) -> bool:
        required_fields = ['version', 'metadata']
        return all(field in config for field in required_fields)

    def extract_devices(self, config: Dict[str, Any]) -> List[str]:
        devices = []
        if 'devices' in config:
            if isinstance(config['devices'], list):
                devices.extend(config['devices'])
            elif isinstance(config['devices'], dict):
                devices.extend(config['devices'].keys())
        return devices