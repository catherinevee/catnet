"""
Deployment Executor - Handles the actual deployment execution on devices
"""
import asyncio
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import logging
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from ..core.exceptions import DeploymentFailed, DeviceConnectionError, DeviceTimeoutError
from ..core.constants import (
    DeviceVendor, BackupType, DeviceConnectionType,
    CISCO_IOS_COMMANDS, CISCO_NXOS_COMMANDS, JUNIPER_JUNOS_COMMANDS,
    DEFAULT_CONNECTION_TIMEOUT, DEFAULT_COMMAND_TIMEOUT
)
from ..db.models import Device, DeviceConfig, Deployment, Task, deployment_devices
import hashlib

logger = logging.getLogger(__name__)


class DeploymentExecutor:
    """
    Executes deployment commands on network devices
    """

    def __init__(self):
        self.command_maps = {
            DeviceVendor.CISCO_IOS: CISCO_IOS_COMMANDS,
            DeviceVendor.CISCO_IOS_XE: CISCO_IOS_COMMANDS,
            DeviceVendor.CISCO_NX_OS: CISCO_NXOS_COMMANDS,
            DeviceVendor.JUNIPER_JUNOS: JUNIPER_JUNOS_COMMANDS
        }

    async def deploy_to_device(
        self,
        device: Device,
        configuration: str,
        deployment_id: str,
        db: AsyncSession,
        dry_run: bool = False,
        verify_after: bool = True,
        backup_first: bool = True
    ) -> Dict[str, Any]:
        """
        Deploy configuration to a single device

        Args:
            device: Target device
            configuration: Configuration to deploy
            deployment_id: Deployment ID
            db: Database session
            dry_run: If True, only validate without applying
            verify_after: If True, verify configuration after deployment
            backup_first: If True, backup current configuration first

        Returns:
            Deployment result dictionary
        """
        result = {
            'device_id': str(device.id),
            'hostname': device.hostname,
            'success': False,
            'backup_id': None,
            'error': None,
            'start_time': datetime.utcnow(),
            'end_time': None,
            'commands_executed': [],
            'verification_passed': False
        }

        try:
            # Step 1: Create backup if required
            if backup_first and not dry_run:
                logger.info(f"Creating backup for device {device.hostname}")
                backup_id = await self.backup_device_config(device, deployment_id, db)
                result['backup_id'] = backup_id
                logger.info(f"Backup created with ID: {backup_id}")

            # Step 2: Simulate device connection and deployment
            logger.info(f"Connecting to device {device.hostname}")

            # Simulate configuration deployment
            await asyncio.sleep(0.5)  # Simulate network delay

            config_lines = configuration.strip().split('\n')
            for line in config_lines:
                if line.strip():
                    result['commands_executed'].append({
                        'command': line,
                        'output': 'OK',
                        'timestamp': datetime.utcnow().isoformat()
                    })

            # Step 3: Update device status in database
            if not dry_run:
                await self._update_device_deployment_status(
                    db, deployment_id, device.id, 'success'
                )

                # Store new config hash
                device.current_config_hash = hashlib.sha256(configuration.encode()).hexdigest()
                device.last_seen = datetime.utcnow()
                await db.commit()

            result['success'] = True
            result['verification_passed'] = True
            result['end_time'] = datetime.utcnow()

            logger.info(f"Successfully deployed configuration to device {device.hostname}")

        except Exception as e:
            result['success'] = False
            result['error'] = str(e)
            result['end_time'] = datetime.utcnow()

            logger.error(f"Failed to deploy to device {device.hostname}: {e}")

            # Update device status as failed
            if not dry_run:
                await self._update_device_deployment_status(
                    db, deployment_id, device.id, 'failed', str(e)
                )

        return result

    async def backup_device_config(
        self,
        device: Device,
        deployment_id: str,
        db: AsyncSession
    ) -> str:
        """
        Create a backup of device configuration

        Args:
            device: Device to backup
            deployment_id: Associated deployment ID
            db: Database session

        Returns:
            Backup ID
        """
        try:
            # Simulate getting current configuration
            config_output = f"! Configuration backup for {device.hostname}\n"
            config_output += f"! Generated at {datetime.utcnow()}\n"
            config_output += "interface GigabitEthernet0/0\n"
            config_output += " ip address {device.management_ip} 255.255.255.0\n"

            # Encrypt and store configuration
            config_hash = hashlib.sha256(config_output.encode()).hexdigest()
            encrypted_config = config_output.encode()

            # Get current version number
            stmt = select(DeviceConfig).where(
                DeviceConfig.device_id == device.id
            ).order_by(DeviceConfig.version.desc()).limit(1)
            result = await db.execute(stmt)
            last_config = result.scalar_one_or_none()
            version = (last_config.version + 1) if last_config else 1

            # Create backup record
            backup = DeviceConfig(
                id=uuid.uuid4(),
                device_id=device.id,
                config_encrypted=encrypted_config,
                config_hash=config_hash,
                encryption_key_id=f"backup-{device.id}-{version}",
                version=version,
                is_current=False,
                backup_type=BackupType.PRE_DEPLOYMENT.value,
                backup_location=f"vault://backups/{device.id}/{version}",
                backup_size=len(config_output),
                change_description=f"Pre-deployment backup for deployment {deployment_id}",
                deployment_id=deployment_id
            )

            db.add(backup)
            await db.commit()

            logger.info(f"Created backup {backup.id} for device {device.hostname}")
            return str(backup.id)

        except Exception as e:
            logger.error(f"Failed to backup device {device.hostname}: {e}")
            raise DeploymentFailed(f"Backup failed for device {device.hostname}: {str(e)}")

    async def rollback_device(
        self,
        device: Device,
        backup_id: str,
        db: AsyncSession
    ) -> Dict[str, Any]:
        """
        Rollback device to a previous configuration

        Args:
            device: Device to rollback
            backup_id: Backup configuration ID
            db: Database session

        Returns:
            Rollback result
        """
        result = {
            'device_id': str(device.id),
            'hostname': device.hostname,
            'backup_id': backup_id,
            'success': False,
            'error': None,
            'start_time': datetime.utcnow(),
            'end_time': None
        }

        try:
            # Get backup configuration
            stmt = select(DeviceConfig).where(DeviceConfig.id == backup_id)
            result_query = await db.execute(stmt)
            backup = result_query.scalar_one_or_none()

            if not backup:
                raise DeploymentFailed(f"Backup {backup_id} not found")

            # Decrypt configuration
            config = backup.config_encrypted.decode()

            # Simulate rollback
            await asyncio.sleep(0.5)

            result['success'] = True
            result['end_time'] = datetime.utcnow()

            logger.info(f"Successfully rolled back device {device.hostname} to backup {backup_id}")

        except Exception as e:
            result['success'] = False
            result['error'] = str(e)
            result['end_time'] = datetime.utcnow()

            logger.error(f"Failed to rollback device {device.hostname}: {e}")
            raise

        return result

    async def rollback_devices(
        self,
        devices: List[Device],
        deployment_id: str,
        db: AsyncSession
    ) -> Dict[str, Any]:
        """
        Rollback multiple devices

        Args:
            devices: List of devices to rollback
            deployment_id: Deployment ID
            db: Database session

        Returns:
            Rollback results
        """
        results = {
            'total': len(devices),
            'succeeded': 0,
            'failed': 0,
            'devices': []
        }

        for device in devices:
            try:
                # Get the backup created for this deployment
                stmt = select(DeviceConfig).where(
                    DeviceConfig.device_id == device.id,
                    DeviceConfig.deployment_id == deployment_id,
                    DeviceConfig.backup_type == BackupType.PRE_DEPLOYMENT.value
                ).order_by(DeviceConfig.created_at.desc()).limit(1)

                result = await db.execute(stmt)
                backup = result.scalar_one_or_none()

                if backup:
                    rollback_result = await self.rollback_device(
                        device, str(backup.id), db
                    )
                    results['devices'].append(rollback_result)

                    if rollback_result['success']:
                        results['succeeded'] += 1
                    else:
                        results['failed'] += 1
                else:
                    logger.warning(f"No backup found for device {device.hostname} in deployment {deployment_id}")
                    results['failed'] += 1
                    results['devices'].append({
                        'device_id': str(device.id),
                        'hostname': device.hostname,
                        'success': False,
                        'error': 'No backup found'
                    })

            except Exception as e:
                logger.error(f"Failed to rollback device {device.hostname}: {e}")
                results['failed'] += 1
                results['devices'].append({
                    'device_id': str(device.id),
                    'hostname': device.hostname,
                    'success': False,
                    'error': str(e)
                })

        return results

    async def verify_deployment(
        self,
        device: Device,
        expected_config: str
    ) -> Dict[str, Any]:
        """
        Verify deployment was successful

        Args:
            device: Device to verify
            expected_config: Expected configuration

        Returns:
            Verification result
        """
        result = {
            'passed': True,
            'checks': [],
            'timestamp': datetime.utcnow().isoformat()
        }

        try:
            # Simulate verification checks
            result['checks'].append({
                'name': 'configuration_match',
                'passed': True,
                'details': 'Configuration matches expected'
            })

            result['checks'].append({
                'name': 'device_health',
                'passed': True,
                'details': 'Device is healthy'
            })

            result['checks'].append({
                'name': 'interface_status',
                'passed': True,
                'details': 'All interfaces operational'
            })

            # Overall result
            result['passed'] = all(check['passed'] for check in result['checks'])

        except Exception as e:
            logger.error(f"Verification failed for device {device.hostname}: {e}")
            result['error'] = str(e)
            result['passed'] = False

        return result

    async def _update_device_deployment_status(
        self,
        db: AsyncSession,
        deployment_id: str,
        device_id: str,
        status: str,
        error: Optional[str] = None
    ):
        """Update device status in deployment"""
        stmt = update(deployment_devices).where(
            deployment_devices.c.deployment_id == deployment_id,
            deployment_devices.c.device_id == device_id
        ).values(
            status=status,
            deployed_at=datetime.utcnow() if status == 'success' else None
        )
        await db.execute(stmt)