"""
Device management components.
"""

import asyncio
import json
import hashlib
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import re
import uuid

import redis.asyncio as redis
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.core.config import get_settings
from src.security.vault import VaultClient
from src.security.encryption import EncryptionService

logger = get_logger(__name__)
settings = get_settings()


class ConnectionManager:
    """Manages device connections."""

    def __init__(self):
        self.vault = VaultClient()
        self.redis = None
        self.connections = {}
        self.connection_pool = {}
        self.max_pool_size = 100
        self.connection_timeout = 300  # 5 minutes

    async def initialize(self):
        """Initialize connection manager."""
        self.redis = await redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True
        )

    async def create_connection(
        self,
        device_id: str,
        connector: Any,
        persistent: bool = False
    ) -> str:
        """
        Create and manage device connection.

        Args:
            device_id: Device ID
            connector: Device connector instance
            persistent: Keep connection persistent

        Returns:
            Connection ID
        """
        try:
            connection_id = str(uuid.uuid4())

            # Store connection
            connection_info = {
                'id': connection_id,
                'device_id': device_id,
                'connector': connector,
                'persistent': persistent,
                'created_at': datetime.utcnow(),
                'last_activity': datetime.utcnow(),
                'usage_count': 0
            }

            self.connections[connection_id] = connection_info

            # Add to pool if persistent
            if persistent:
                if device_id not in self.connection_pool:
                    self.connection_pool[device_id] = []
                self.connection_pool[device_id].append(connection_id)

                # Enforce pool size limit
                if len(self.connection_pool[device_id]) > self.max_pool_size:
                    # Remove oldest connection
                    oldest_id = self.connection_pool[device_id].pop(0)
                    await self.close_connection(oldest_id)

            # Store in Redis
            await self.redis.setex(
                f"connection:{connection_id}",
                self.connection_timeout,
                json.dumps({
                    'device_id': device_id,
                    'persistent': persistent,
                    'created_at': connection_info['created_at'].isoformat()
                })
            )

            logger.info(f"Created connection {connection_id} for device {device_id}")
            return connection_id

        except Exception as e:
            logger.error(f"Failed to create connection: {e}")
            raise

    async def get_connection(
        self,
        connection_id: str
    ) -> Optional[Any]:
        """Get connection by ID."""
        connection_info = self.connections.get(connection_id)
        if connection_info:
            # Update last activity
            connection_info['last_activity'] = datetime.utcnow()
            connection_info['usage_count'] += 1

            # Refresh Redis TTL
            await self.redis.expire(f"connection:{connection_id}", self.connection_timeout)

            return connection_info['connector']
        return None

    async def get_device_connection(
        self,
        device_id: str
    ) -> Optional[Any]:
        """Get existing connection for device."""
        # Check connection pool
        if device_id in self.connection_pool:
            for connection_id in self.connection_pool[device_id]:
                connection = await self.get_connection(connection_id)
                if connection and connection.is_alive():
                    return connection

        # Check all connections
        for connection_id, info in self.connections.items():
            if info['device_id'] == device_id:
                connector = info['connector']
                if connector.is_alive():
                    return connector

        return None

    async def close_connection(
        self,
        connection_id: str
    ):
        """Close connection."""
        try:
            connection_info = self.connections.get(connection_id)
            if connection_info:
                connector = connection_info['connector']
                await connector.disconnect()

                # Remove from pool
                device_id = connection_info['device_id']
                if device_id in self.connection_pool:
                    if connection_id in self.connection_pool[device_id]:
                        self.connection_pool[device_id].remove(connection_id)

                # Remove from connections
                del self.connections[connection_id]

                # Remove from Redis
                await self.redis.delete(f"connection:{connection_id}")

                logger.info(f"Closed connection {connection_id}")

        except Exception as e:
            logger.error(f"Failed to close connection: {e}")

    async def cleanup_stale_connections(self):
        """Clean up stale connections."""
        try:
            current_time = datetime.utcnow()
            stale_connections = []

            for connection_id, info in self.connections.items():
                # Check if connection is stale
                if not info['persistent']:
                    time_since_activity = current_time - info['last_activity']
                    if time_since_activity.total_seconds() > self.connection_timeout:
                        stale_connections.append(connection_id)

            # Close stale connections
            for connection_id in stale_connections:
                await self.close_connection(connection_id)

            if stale_connections:
                logger.info(f"Cleaned up {len(stale_connections)} stale connections")

        except Exception as e:
            logger.error(f"Failed to cleanup stale connections: {e}")

    async def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection statistics."""
        stats = {
            'total_connections': len(self.connections),
            'persistent_connections': sum(
                1 for c in self.connections.values() if c['persistent']
            ),
            'devices_connected': len(self.connection_pool),
            'pool_usage': {
                device_id: len(connections)
                for device_id, connections in self.connection_pool.items()
            }
        }
        return stats


class ConfigurationManager:
    """Manages device configurations."""

    def __init__(self):
        self.vault = VaultClient()
        self.encryption = EncryptionService()
        self.redis = None
        self.validation_rules = {}

    async def initialize(self):
        """Initialize configuration manager."""
        self.redis = await redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True
        )
        self._load_validation_rules()

    def _load_validation_rules(self):
        """Load configuration validation rules."""
        self.validation_rules = {
            'cisco_ios': {
                'required_sections': ['version', 'hostname'],
                'forbidden_commands': ['no service password-encryption'],
                'required_features': ['service password-encryption', 'logging']
            },
            'juniper_junos': {
                'required_sections': ['system', 'interfaces'],
                'forbidden_commands': ['delete system'],
                'required_features': ['system services']
            }
        }

    async def get_config(
        self,
        connection: Any,
        device_type: str,
        config_type: str = "running"
    ) -> str:
        """
        Get device configuration.

        Args:
            connection: Device connection
            device_type: Device type
            config_type: Configuration type

        Returns:
            Configuration content
        """
        try:
            config = await connection.get_config(config_type)

            # Clean and normalize configuration
            config = self._normalize_config(config, device_type)

            return config

        except Exception as e:
            logger.error(f"Failed to get configuration: {e}")
            raise

    async def apply_config(
        self,
        connection: Any,
        device_type: str,
        configuration: str,
        save_to_startup: bool = False,
        commit: bool = True
    ) -> Dict[str, Any]:
        """
        Apply configuration to device.

        Args:
            connection: Device connection
            device_type: Device type
            configuration: Configuration to apply
            save_to_startup: Save to startup config
            commit: Commit configuration

        Returns:
            Apply result
        """
        try:
            # Parse configuration into commands
            commands = self._parse_config_commands(configuration, device_type)

            if not commands:
                return {
                    'success': False,
                    'error': 'No valid commands to apply'
                }

            # Send configuration commands
            output = await connection.send_config_commands(commands, save=False)

            # Save configuration if requested
            if save_to_startup and commit:
                save_success = await connection.save_config()
                if not save_success:
                    logger.warning("Configuration applied but save failed")

            return {
                'success': True,
                'output': output,
                'commands_applied': len(commands),
                'saved': save_to_startup and commit
            }

        except Exception as e:
            logger.error(f"Failed to apply configuration: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    async def validate_config(
        self,
        configuration: str,
        device_type: str
    ) -> Dict[str, Any]:
        """
        Validate configuration.

        Args:
            configuration: Configuration to validate
            device_type: Device type

        Returns:
            Validation result
        """
        result = {
            'valid': True,
            'errors': [],
            'warnings': []
        }

        try:
            # Get validation rules for device type
            rules = self.validation_rules.get(device_type.lower(), {})

            # Check required sections
            if 'required_sections' in rules:
                for section in rules['required_sections']:
                    if section not in configuration.lower():
                        result['errors'].append(f"Missing required section: {section}")
                        result['valid'] = False

            # Check forbidden commands
            if 'forbidden_commands' in rules:
                for forbidden in rules['forbidden_commands']:
                    if forbidden in configuration.lower():
                        result['errors'].append(f"Forbidden command detected: {forbidden}")
                        result['valid'] = False

            # Check required features
            if 'required_features' in rules:
                for feature in rules['required_features']:
                    if feature not in configuration.lower():
                        result['warnings'].append(f"Recommended feature missing: {feature}")

            # Syntax validation
            if not self._validate_syntax(configuration, device_type):
                result['errors'].append("Configuration syntax errors detected")
                result['valid'] = False

            # Security validation
            security_issues = self._validate_security(configuration)
            if security_issues:
                result['warnings'].extend(security_issues)

        except Exception as e:
            logger.error(f"Configuration validation error: {e}")
            result['valid'] = False
            result['errors'].append(str(e))

        return result

    def _normalize_config(self, config: str, device_type: str) -> str:
        """Normalize configuration format."""
        # Remove command prompts and unnecessary whitespace
        lines = config.split('\n')
        normalized = []

        for line in lines:
            # Remove prompts
            line = re.sub(r'^[#>]\s*', '', line)
            line = re.sub(r'^.*[#>]\s*', '', line)

            # Skip empty lines
            if line.strip():
                normalized.append(line.rstrip())

        return '\n'.join(normalized)

    def _parse_config_commands(
        self,
        configuration: str,
        device_type: str
    ) -> List[str]:
        """Parse configuration into commands."""
        commands = []

        # Split into lines
        lines = configuration.split('\n')

        # Process based on device type
        if 'cisco' in device_type.lower():
            commands = self._parse_cisco_config(lines)
        elif 'juniper' in device_type.lower():
            commands = self._parse_juniper_config(lines)
        else:
            # Default: use lines as-is
            commands = [line.strip() for line in lines if line.strip()]

        return commands

    def _parse_cisco_config(self, lines: List[str]) -> List[str]:
        """Parse Cisco configuration."""
        commands = []
        in_interface = False
        interface_commands = []

        for line in lines:
            line = line.strip()
            if not line or line.startswith('!'):
                continue

            # Handle interface blocks
            if line.startswith('interface '):
                if interface_commands:
                    commands.extend(interface_commands)
                    interface_commands = []
                in_interface = True
                interface_commands.append(line)
            elif in_interface:
                if line.startswith(' ') or not line.startswith('interface'):
                    interface_commands.append(line)
                else:
                    if interface_commands:
                        commands.extend(interface_commands)
                        interface_commands = []
                    in_interface = False
                    commands.append(line)
            else:
                commands.append(line)

        # Add remaining interface commands
        if interface_commands:
            commands.extend(interface_commands)

        return commands

    def _parse_juniper_config(self, lines: List[str]) -> List[str]:
        """Parse Juniper configuration."""
        commands = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Convert to set commands if needed
            if not line.startswith('set '):
                line = f"set {line}"

            commands.append(line)

        return commands

    def _validate_syntax(self, configuration: str, device_type: str) -> bool:
        """Validate configuration syntax."""
        # Basic syntax validation
        if 'cisco' in device_type.lower():
            # Check for unclosed blocks
            interface_count = configuration.count('interface ')
            exit_count = configuration.count('\nexit\n')
            if interface_count > 0 and exit_count < interface_count:
                return False

        elif 'juniper' in device_type.lower():
            # Check for matching braces
            open_braces = configuration.count('{')
            close_braces = configuration.count('}')
            if open_braces != close_braces:
                return False

        return True

    def _validate_security(self, configuration: str) -> List[str]:
        """Validate security aspects of configuration."""
        issues = []

        # Check for plaintext passwords
        if re.search(r'password\s+[0-9]\s+\S+', configuration):
            issues.append("Plaintext passwords detected")

        # Check for weak SNMP communities
        if re.search(r'snmp-server community (public|private)', configuration, re.IGNORECASE):
            issues.append("Default SNMP community strings detected")

        # Check for Telnet
        if 'transport input telnet' in configuration.lower():
            issues.append("Telnet is enabled (insecure)")

        # Check for HTTP
        if 'ip http server' in configuration and 'no ip http server' not in configuration:
            issues.append("HTTP server is enabled (use HTTPS instead)")

        return issues

    async def compare_configs(
        self,
        config1: str,
        config2: str,
        device_type: str
    ) -> Dict[str, Any]:
        """
        Compare two configurations.

        Args:
            config1: First configuration
            config2: Second configuration
            device_type: Device type

        Returns:
            Comparison result
        """
        try:
            # Normalize both configs
            config1_norm = self._normalize_config(config1, device_type)
            config2_norm = self._normalize_config(config2, device_type)

            # Split into lines
            lines1 = set(config1_norm.split('\n'))
            lines2 = set(config2_norm.split('\n'))

            # Find differences
            added = lines2 - lines1
            removed = lines1 - lines2
            common = lines1 & lines2

            return {
                'identical': lines1 == lines2,
                'added_lines': list(added),
                'removed_lines': list(removed),
                'common_lines': len(common),
                'total_changes': len(added) + len(removed)
            }

        except Exception as e:
            logger.error(f"Configuration comparison error: {e}")
            raise


class BackupManager:
    """Manages device configuration backups."""

    def __init__(self):
        self.vault = VaultClient()
        self.encryption = EncryptionService()
        self.redis = None

    async def initialize(self):
        """Initialize backup manager."""
        self.redis = await redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True
        )

    async def create_backup(
        self,
        device_id: str,
        configuration: str,
        backup_type: str = "manual",
        description: Optional[str] = None,
        deployment_id: Optional[str] = None,
        retention_days: int = 30
    ) -> str:
        """
        Create configuration backup.

        Args:
            device_id: Device ID
            configuration: Configuration content
            backup_type: Type of backup
            description: Backup description
            deployment_id: Associated deployment ID
            retention_days: Retention period in days

        Returns:
            Backup ID
        """
        try:
            backup_id = str(uuid.uuid4())

            # Calculate hash
            config_hash = hashlib.sha256(configuration.encode()).hexdigest()

            # Check for duplicate
            existing = await self._find_duplicate_backup(device_id, config_hash)
            if existing:
                logger.info(f"Duplicate backup found: {existing}")
                return existing

            # Encrypt configuration
            encrypted_config = await self.encryption.encrypt(configuration)

            # Store in Vault
            backup_path = f"backups/{device_id}/{backup_id}"
            await self.vault.put_secret(
                backup_path,
                {
                    'device_id': device_id,
                    'configuration': configuration,
                    'encrypted': encrypted_config,
                    'hash': config_hash,
                    'type': backup_type,
                    'description': description,
                    'deployment_id': deployment_id,
                    'created_at': datetime.utcnow().isoformat(),
                    'expires_at': (datetime.utcnow() + timedelta(days=retention_days)).isoformat()
                },
                ttl=retention_days * 86400  # Convert to seconds
            )

            # Index in Redis
            await self.redis.zadd(
                f"device:{device_id}:backups",
                {backup_id: datetime.utcnow().timestamp()}
            )

            # Store metadata
            await self.redis.hset(
                f"backup:{backup_id}",
                mapping={
                    'device_id': device_id,
                    'type': backup_type,
                    'hash': config_hash,
                    'size': len(configuration),
                    'created_at': datetime.utcnow().isoformat()
                }
            )

            # Set expiration
            await self.redis.expire(f"backup:{backup_id}", retention_days * 86400)

            logger.info(f"Created backup {backup_id} for device {device_id}")
            return backup_id

        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            raise

    async def get_backup(
        self,
        backup_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get backup by ID.

        Args:
            backup_id: Backup ID

        Returns:
            Backup data
        """
        try:
            # Get metadata from Redis
            metadata = await self.redis.hgetall(f"backup:{backup_id}")
            if not metadata:
                return None

            device_id = metadata['device_id']

            # Get from Vault
            backup_path = f"backups/{device_id}/{backup_id}"
            backup_data = await self.vault.get_secret(backup_path)

            if backup_data:
                # Decrypt configuration
                if 'encrypted' in backup_data:
                    backup_data['configuration'] = await self.encryption.decrypt(
                        backup_data['encrypted']
                    )

            return backup_data

        except Exception as e:
            logger.error(f"Failed to get backup: {e}")
            return None

    async def list_backups(
        self,
        device_id: str,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        List device backups.

        Args:
            device_id: Device ID
            limit: Maximum number of backups to return

        Returns:
            List of backups
        """
        try:
            # Get backup IDs from Redis (sorted by timestamp)
            backup_ids = await self.redis.zrevrange(
                f"device:{device_id}:backups",
                0,
                limit - 1
            )

            backups = []
            for backup_id in backup_ids:
                metadata = await self.redis.hgetall(f"backup:{backup_id}")
                if metadata:
                    backups.append({
                        'backup_id': backup_id,
                        **metadata
                    })

            return backups

        except Exception as e:
            logger.error(f"Failed to list backups: {e}")
            return []

    async def delete_backup(
        self,
        backup_id: str
    ) -> bool:
        """
        Delete backup.

        Args:
            backup_id: Backup ID

        Returns:
            True if deleted
        """
        try:
            # Get metadata
            metadata = await self.redis.hgetall(f"backup:{backup_id}")
            if not metadata:
                return False

            device_id = metadata['device_id']

            # Delete from Vault
            backup_path = f"backups/{device_id}/{backup_id}"
            await self.vault.delete_secret(backup_path)

            # Remove from Redis
            await self.redis.zrem(f"device:{device_id}:backups", backup_id)
            await self.redis.delete(f"backup:{backup_id}")

            logger.info(f"Deleted backup {backup_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete backup: {e}")
            return False

    async def cleanup_expired_backups(self):
        """Clean up expired backups."""
        try:
            # This would be handled by Vault TTL
            # But we can also clean up Redis entries

            # Get all backup keys
            backup_keys = await self.redis.keys("backup:*")

            expired_count = 0
            for key in backup_keys:
                ttl = await self.redis.ttl(key)
                if ttl < 0:  # Key doesn't exist or has no TTL
                    await self.redis.delete(key)
                    expired_count += 1

            if expired_count > 0:
                logger.info(f"Cleaned up {expired_count} expired backups")

        except Exception as e:
            logger.error(f"Failed to cleanup expired backups: {e}")

    async def _find_duplicate_backup(
        self,
        device_id: str,
        config_hash: str
    ) -> Optional[str]:
        """Find duplicate backup by hash."""
        try:
            # Get recent backups
            backup_ids = await self.redis.zrevrange(
                f"device:{device_id}:backups",
                0,
                9  # Check last 10 backups
            )

            for backup_id in backup_ids:
                metadata = await self.redis.hget(f"backup:{backup_id}", 'hash')
                if metadata == config_hash:
                    return backup_id

            return None

        except Exception as e:
            logger.error(f"Failed to find duplicate backup: {e}")
            return None


class CommandExecutor:
    """Executes commands on devices."""

    def __init__(self):
        self.redis = None
        self.command_timeout = 30
        self.max_output_size = 1000000  # 1MB

    async def initialize(self):
        """Initialize command executor."""
        self.redis = await redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True
        )

    async def execute(
        self,
        connection: Any,
        command: str,
        timeout: int = 30
    ) -> 'CommandResult':
        """
        Execute command on device.

        Args:
            connection: Device connection
            command: Command to execute
            timeout: Command timeout

        Returns:
            Command result
        """
        result = CommandResult()
        result.command = command

        try:
            start_time = datetime.utcnow()

            # Execute command with timeout
            output = await asyncio.wait_for(
                connection.send_command(command),
                timeout=timeout
            )

            end_time = datetime.utcnow()

            # Truncate output if too large
            if len(output) > self.max_output_size:
                output = output[:self.max_output_size] + "\n[OUTPUT TRUNCATED]"

            result.output = output
            result.success = True
            result.execution_time = (end_time - start_time).total_seconds()

            # Check for error indicators
            if self._contains_error(output):
                result.error = "Command execution completed with errors"

        except asyncio.TimeoutError:
            result.success = False
            result.error = f"Command timed out after {timeout} seconds"
        except Exception as e:
            result.success = False
            result.error = str(e)

        return result

    async def execute_batch(
        self,
        connection: Any,
        commands: List[str],
        stop_on_error: bool = False,
        timeout: int = 30
    ) -> List['CommandResult']:
        """
        Execute multiple commands.

        Args:
            connection: Device connection
            commands: Commands to execute
            stop_on_error: Stop execution on first error
            timeout: Timeout per command

        Returns:
            List of command results
        """
        results = []

        for command in commands:
            result = await self.execute(connection, command, timeout)
            results.append(result)

            if not result.success and stop_on_error:
                logger.warning(f"Stopping batch execution due to error: {result.error}")
                break

        return results

    def _contains_error(self, output: str) -> bool:
        """Check if output contains error indicators."""
        error_patterns = [
            r'% Invalid',
            r'% Incomplete',
            r'% Ambiguous',
            r'% Error',
            r'Syntax error',
            r'Error:',
            r'Failed',
            r'Unable to'
        ]

        output_lower = output.lower()
        for pattern in error_patterns:
            if re.search(pattern, output, re.IGNORECASE):
                return True

        return False


class CommandResult:
    """Command execution result."""

    def __init__(self):
        self.command = None
        self.output = None
        self.error = None
        self.success = False
        self.execution_time = None