#!/usr/bin/env python3
"""
Sprint 2: Add comprehensive docstrings to device_connector.py
"""
import re
from pathlib import Path


def add_device_connector_docstrings():
    """Add docstrings to DeviceConnection and SecureDeviceConnector classes."""

    file_path = Path("src/devices/device_connector.py")
    content = file_path.read_text(encoding='utf-8')

    # DeviceConnection class docstring
    class_pattern = r'(class DeviceConnection:)\n(    def __init__\()'
    class_replacement = r'''\1
    """
    Manages a secure connection to a network device.

    Handles both Netmiko (CLI) and NAPALM (API) connections to network devices
    with session logging, bastion host support, and credential management.

    Attributes:
        device: Device model instance with connection details
        credentials: Dictionary containing username/password from Vault
        session_id: Unique session identifier for audit logging
        connection: Netmiko connection handler
        napalm_driver: NAPALM driver for vendor-agnostic operations

    Example:
        >>> conn = DeviceConnection(device, credentials, session_id)
        >>> await conn.connect()
        >>> output = await conn.send_config("interface GigabitEthernet0/1\\nshutdown")
        >>> await conn.disconnect()
    """
\2'''
    content = re.sub(class_pattern, class_replacement, content)

    # DeviceConnection.__init__ docstring
    init_pattern = r'(    def __init__\(\n        self,\n        device: Device,\n        credentials: Dict\[str, Any\],\n        session_id: str\n    \):)\n(        self\.device = device)'
    init_replacement = r'''\1
        """
        Initialize device connection with credentials.

        Args:
            device: Device model instance containing connection details
            credentials: Dictionary with 'username' and 'password' keys
            session_id: Unique session ID for logging and audit trail
        """
\2'''
    content = re.sub(init_pattern, init_replacement, content)

    # connect method docstring
    connect_pattern = r'(    async def connect\(\self\):)\n(        device_params = \{)'
    connect_replacement = r'''\1
        """
        Establish connection to network device.

        Creates both Netmiko (CLI) and NAPALM (API) connections. Falls back
        to Netmiko-only if NAPALM fails. Handles SSH config for bastion hosts.

        Raises:
            DeviceConnectionError: If connection fails
            DeviceTimeoutError: If connection times out
            AuthenticationError: If credentials are invalid

        Example:
            >>> await conn.connect()
        """
\2'''
    content = re.sub(connect_pattern, connect_replacement, content)

    # _get_netmiko_device_type docstring
    netmiko_pattern = r'(    def _get_netmiko_device_type\(\self\) -> str:)\n(        mapping = \{)'
    netmiko_replacement = r'''\1
        """
        Map device vendor enum to Netmiko device type string.

        Returns:
            str: Netmiko device type (e.g., "cisco_ios", "juniper_junos")
        """
\2'''
    content = re.sub(netmiko_pattern, netmiko_replacement, content)

    # _get_napalm_driver docstring
    napalm_pattern = r'(    def _get_napalm_driver\(\self\) -> str:)\n(        mapping = \{)'
    napalm_replacement = r'''\1
        """
        Map device vendor enum to NAPALM driver name.

        Returns:
            str: NAPALM driver name (e.g., "ios", "junos", "nxos")
        """
\2'''
    content = re.sub(napalm_pattern, napalm_replacement, content)

    file_path.write_text(content, encoding='utf-8')
    print("Added docstrings to device_connector.py")


def add_secure_device_connector_docstring():
    """Add docstring to SecureDeviceConnector class."""

    file_path = Path("src/devices/device_connector.py")
    content = file_path.read_text(encoding='utf-8')

    # Find SecureDeviceConnector class and add docstring
    pattern = r'(class SecureDeviceConnector:)\n(    def __init__\()'
    replacement = r'''\1
    """
    Secure wrapper for device connections with credential management.

    Provides high-level interface for device connections with automatic
    credential retrieval from Vault, audit logging, and session management.
    Handles connection pooling and cleanup.

    Attributes:
        db: SQLAlchemy database session
        vault: HashiCorp Vault client for credential retrieval
        audit: Audit logger for compliance tracking
        _connections: Dictionary of active connections by session ID

    Example:
        >>> connector = SecureDeviceConnector(db, vault, audit)
        >>> async with connector.connect_device(device_id) as conn:
        ...     output = await conn.send_config("show version")
    """
\2'''
    content = re.sub(pattern, replacement, content)

    file_path.write_text(content, encoding='utf-8')
    print("Added SecureDeviceConnector docstring")


def main():
    """Main execution."""
    print("Adding docstrings to device_connector.py...")
    add_device_connector_docstrings()
    add_secure_device_connector_docstring()
    print("Complete!")


if __name__ == "__main__":
    main()
