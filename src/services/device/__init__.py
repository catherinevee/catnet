"""
CatNet Device Microservice.

Handles device connections, command execution, and configuration management.
Runs on port 8084.
"""

from .app import create_app
from .models import (
    Device,
    DeviceType,
    DeviceStatus,
    DeviceConnection,
    DeviceCommand,
    DeviceConfiguration,
    BackupRequest,
    BackupResponse,
    ExecuteRequest,
    ExecuteResponse
)
from .connectors import (
    DeviceConnector,
    CiscoConnector,
    JuniperConnector,
    get_connector
)
from .managers import (
    ConnectionManager,
    ConfigurationManager,
    BackupManager,
    CommandExecutor
)

__all__ = [
    'create_app',
    'Device',
    'DeviceType',
    'DeviceStatus',
    'DeviceConnection',
    'DeviceCommand',
    'DeviceConfiguration',
    'BackupRequest',
    'BackupResponse',
    'ExecuteRequest',
    'ExecuteResponse',
    'DeviceConnector',
    'CiscoConnector',
    'JuniperConnector',
    'get_connector',
    'ConnectionManager',
    'ConfigurationManager',
    'BackupManager',
    'CommandExecutor',
]

__version__ = '1.0.0'