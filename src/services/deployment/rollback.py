"""
Deployment rollback manager.
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
import json

import httpx
import redis.asyncio as redis

from src.core.logging import get_logger
from src.core.config import get_settings
from src.security.vault import VaultClient

logger = get_logger(__name__)
settings = get_settings()


class RollbackManager:
    """Manages deployment rollbacks."""

    def __init__(self):
        self.vault = VaultClient()
        self.redis = None
        self.rollback_strategies = {
            'restore_backup': self._rollback_restore_backup,
            'reverse_changes': self._rollback_reverse_changes,
            'apply_previous': self._rollback_apply_previous,
            'custom_script': self._rollback_custom_script
        }

    async def initialize(self):
        """Initialize rollback manager."""
        self.redis = await redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True
        )

    async def rollback(
        self,
        deployment_id: str,
        devices: List[str],
        strategy: str = "restore_backup",
        force: bool = False
    ) -> Dict[str, Any]:
        """
        Perform deployment rollback.

        Args:
            deployment_id: Deployment ID
            devices: Devices to rollback
            strategy: Rollback strategy
            force: Force rollback even if validation fails

        Returns:
            Rollback result
        """
        start_time = datetime.utcnow()
        result = {
            'deployment_id': deployment_id,
            'strategy': strategy,
            'started_at': start_time.isoformat(),
            'devices': {
                'total': len(devices),
                'successful': [],
                'failed': []
            },
            'errors': []
        }

        try:
            logger.info(f"Starting rollback for deployment {deployment_id} using {strategy}")

            # Get deployment information
            deployment_info = await self._get_deployment_info(deployment_id)
            if not deployment_info:
                raise ValueError(f"Deployment {deployment_id} not found")

            # Validate rollback is possible
            if not force:
                validation = await self._validate_rollback(deployment_id, devices)
                if not validation['valid']:
                    raise ValueError(f"Rollback validation failed: {validation['errors']}")

            # Get rollback strategy
            rollback_func = self.rollback_strategies.get(strategy)
            if not rollback_func:
                raise ValueError(f"Unknown rollback strategy: {strategy}")

            # Execute rollback for each device
            rollback_tasks = []
            for device_id in devices:
                rollback_tasks.append(
                    rollback_func(deployment_id, device_id, deployment_info)
                )

            # Execute in parallel with limit
            max_parallel = 10
            for i in range(0, len(rollback_tasks), max_parallel):
                batch = rollback_tasks[i:i + max_parallel]
                batch_results = await asyncio.gather(*batch, return_exceptions=True)

                for device_id, device_result in zip(devices[i:i + max_parallel], batch_results):
                    if isinstance(device_result, Exception):
                        result['devices']['failed'].append(device_id)
                        result['errors'].append(f"Device {device_id}: {str(device_result)}")
                    elif device_result.get('success'):
                        result['devices']['successful'].append(device_id)
                    else:
                        result['devices']['failed'].append(device_id)
                        result['errors'].append(
                            f"Device {device_id}: {device_result.get('error', 'Unknown error')}"
                        )

            # Calculate metrics
            duration = (datetime.utcnow() - start_time).total_seconds()
            result['completed_at'] = datetime.utcnow().isoformat()
            result['duration_seconds'] = duration
            result['success_rate'] = (
                len(result['devices']['successful']) / len(devices)
                if devices else 0
            )

            # Update deployment record
            await self._update_deployment_status(
                deployment_id,
                'rolled_back',
                result
            )

            logger.info(
                f"Rollback completed for deployment {deployment_id}. "
                f"Success: {len(result['devices']['successful'])}, "
                f"Failed: {len(result['devices']['failed'])}"
            )

        except Exception as e:
            logger.error(f"Rollback failed for deployment {deployment_id}: {e}")
            result['errors'].append(str(e))
            result['status'] = 'failed'

        return result

    async def _rollback_restore_backup(
        self,
        deployment_id: str,
        device_id: str,
        deployment_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Rollback by restoring from backup.

        Args:
            deployment_id: Deployment ID
            device_id: Device ID
            deployment_info: Deployment information

        Returns:
            Rollback result for device
        """
        try:
            logger.info(f"Restoring backup for device {device_id}")

            # Get backup ID for device
            backup_id = await self._get_device_backup(deployment_id, device_id)
            if not backup_id:
                raise ValueError(f"No backup found for device {device_id}")

            # Call device service to restore backup
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://device-service:8084/devices/{device_id}/restore",
                    json={
                        "backup_id": backup_id,
                        "deployment_id": deployment_id
                    },
                    headers={"Authorization": f"Bearer {await self._get_service_token()}"},
                    timeout=300
                )

                if response.status_code == 200:
                    logger.info(f"Successfully restored backup for device {device_id}")
                    return {'success': True, 'device_id': device_id, 'method': 'backup_restore'}
                else:
                    error = response.json().get('error', 'Restore failed')
                    return {'success': False, 'device_id': device_id, 'error': error}

        except Exception as e:
            logger.error(f"Failed to restore backup for device {device_id}: {e}")
            return {'success': False, 'device_id': device_id, 'error': str(e)}

    async def _rollback_reverse_changes(
        self,
        deployment_id: str,
        device_id: str,
        deployment_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Rollback by reversing configuration changes.

        Args:
            deployment_id: Deployment ID
            device_id: Device ID
            deployment_info: Deployment information

        Returns:
            Rollback result for device
        """
        try:
            logger.info(f"Reversing changes for device {device_id}")

            # Get the changes made during deployment
            changes = await self._get_deployment_changes(deployment_id, device_id)
            if not changes:
                return {'success': True, 'device_id': device_id, 'message': 'No changes to reverse'}

            # Generate reverse configuration
            reverse_config = self._generate_reverse_config(changes)

            # Apply reverse configuration
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://device-service:8084/devices/{device_id}/configure",
                    json={
                        "config": reverse_config,
                        "deployment_id": deployment_id,
                        "rollback": True
                    },
                    headers={"Authorization": f"Bearer {await self._get_service_token()}"},
                    timeout=300
                )

                if response.status_code == 200:
                    logger.info(f"Successfully reversed changes for device {device_id}")
                    return {'success': True, 'device_id': device_id, 'method': 'reverse_changes'}
                else:
                    error = response.json().get('error', 'Reverse failed')
                    return {'success': False, 'device_id': device_id, 'error': error}

        except Exception as e:
            logger.error(f"Failed to reverse changes for device {device_id}: {e}")
            return {'success': False, 'device_id': device_id, 'error': str(e)}

    async def _rollback_apply_previous(
        self,
        deployment_id: str,
        device_id: str,
        deployment_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Rollback by applying previous configuration.

        Args:
            deployment_id: Deployment ID
            device_id: Device ID
            deployment_info: Deployment information

        Returns:
            Rollback result for device
        """
        try:
            logger.info(f"Applying previous configuration for device {device_id}")

            # Get previous configuration
            previous_config = await self._get_previous_config(device_id, deployment_id)
            if not previous_config:
                raise ValueError(f"No previous configuration found for device {device_id}")

            # Apply previous configuration
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://device-service:8084/devices/{device_id}/configure",
                    json={
                        "config": previous_config,
                        "deployment_id": deployment_id,
                        "rollback": True
                    },
                    headers={"Authorization": f"Bearer {await self._get_service_token()}"},
                    timeout=300
                )

                if response.status_code == 200:
                    logger.info(f"Successfully applied previous config for device {device_id}")
                    return {'success': True, 'device_id': device_id, 'method': 'apply_previous'}
                else:
                    error = response.json().get('error', 'Apply failed')
                    return {'success': False, 'device_id': device_id, 'error': error}

        except Exception as e:
            logger.error(f"Failed to apply previous config for device {device_id}: {e}")
            return {'success': False, 'device_id': device_id, 'error': str(e)}

    async def _rollback_custom_script(
        self,
        deployment_id: str,
        device_id: str,
        deployment_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Rollback using custom script.

        Args:
            deployment_id: Deployment ID
            device_id: Device ID
            deployment_info: Deployment information

        Returns:
            Rollback result for device
        """
        try:
            logger.info(f"Running custom rollback script for device {device_id}")

            # Get custom rollback script
            script = deployment_info.get('rollback_script')
            if not script:
                raise ValueError("No rollback script defined")

            # Execute script via device service
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://device-service:8084/devices/{device_id}/execute",
                    json={
                        "commands": script,
                        "deployment_id": deployment_id,
                        "rollback": True
                    },
                    headers={"Authorization": f"Bearer {await self._get_service_token()}"},
                    timeout=300
                )

                if response.status_code == 200:
                    logger.info(f"Successfully executed rollback script for device {device_id}")
                    return {'success': True, 'device_id': device_id, 'method': 'custom_script'}
                else:
                    error = response.json().get('error', 'Script execution failed')
                    return {'success': False, 'device_id': device_id, 'error': error}

        except Exception as e:
            logger.error(f"Failed to execute rollback script for device {device_id}: {e}")
            return {'success': False, 'device_id': device_id, 'error': str(e)}

    async def _validate_rollback(
        self,
        deployment_id: str,
        devices: List[str]
    ) -> Dict[str, Any]:
        """
        Validate rollback is possible.

        Args:
            deployment_id: Deployment ID
            devices: Devices to rollback

        Returns:
            Validation result
        """
        validation = {
            'valid': True,
            'errors': [],
            'warnings': []
        }

        try:
            # Check if deployment exists
            deployment_info = await self._get_deployment_info(deployment_id)
            if not deployment_info:
                validation['valid'] = False
                validation['errors'].append(f"Deployment {deployment_id} not found")
                return validation

            # Check if already rolled back
            if deployment_info.get('rollback_performed'):
                validation['warnings'].append("Deployment already rolled back")

            # Check device connectivity
            unreachable_devices = []
            for device_id in devices:
                if not await self._check_device_reachable(device_id):
                    unreachable_devices.append(device_id)

            if unreachable_devices:
                validation['valid'] = False
                validation['errors'].append(f"Unreachable devices: {unreachable_devices}")

            # Check backup availability
            devices_without_backup = []
            for device_id in devices:
                backup_id = await self._get_device_backup(deployment_id, device_id)
                if not backup_id:
                    devices_without_backup.append(device_id)

            if devices_without_backup:
                validation['warnings'].append(
                    f"No backup available for devices: {devices_without_backup}"
                )

        except Exception as e:
            logger.error(f"Rollback validation error: {e}")
            validation['valid'] = False
            validation['errors'].append(str(e))

        return validation

    async def _get_deployment_info(
        self,
        deployment_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get deployment information."""
        try:
            # Check cache
            cached = await self.redis.get(f"deployment:{deployment_id}")
            if cached:
                return json.loads(cached)

            # Get from database via deployment service
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://localhost:8083/deploy/{deployment_id}/status",
                    headers={"Authorization": f"Bearer {await self._get_service_token()}"}
                )

                if response.status_code == 200:
                    return response.json()

            return None

        except Exception as e:
            logger.error(f"Failed to get deployment info: {e}")
            return None

    async def _get_device_backup(
        self,
        deployment_id: str,
        device_id: str
    ) -> Optional[str]:
        """Get backup ID for device."""
        try:
            backup_key = f"deployment:{deployment_id}:device:{device_id}:backup"
            backup_id = await self.redis.get(backup_key)
            return backup_id

        except Exception as e:
            logger.error(f"Failed to get device backup: {e}")
            return None

    async def _get_deployment_changes(
        self,
        deployment_id: str,
        device_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get changes made during deployment."""
        try:
            changes_key = f"deployment:{deployment_id}:device:{device_id}:changes"
            changes = await self.redis.get(changes_key)
            return json.loads(changes) if changes else None

        except Exception as e:
            logger.error(f"Failed to get deployment changes: {e}")
            return None

    def _generate_reverse_config(
        self,
        changes: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate configuration to reverse changes."""
        reverse_config = {}

        # Reverse interface changes
        if 'interfaces' in changes:
            reverse_config['interfaces'] = []
            for interface_change in changes['interfaces']:
                if interface_change.get('action') == 'add':
                    # Remove added interface
                    reverse_config['interfaces'].append({
                        'name': interface_change['name'],
                        'action': 'remove'
                    })
                elif interface_change.get('action') == 'modify':
                    # Restore original values
                    reverse_config['interfaces'].append({
                        'name': interface_change['name'],
                        'action': 'modify',
                        'config': interface_change.get('original', {})
                    })
                elif interface_change.get('action') == 'remove':
                    # Re-add removed interface
                    reverse_config['interfaces'].append({
                        'name': interface_change['name'],
                        'action': 'add',
                        'config': interface_change.get('original', {})
                    })

        # Reverse routing changes
        if 'routing' in changes:
            reverse_config['routing'] = self._reverse_routing_changes(changes['routing'])

        # Reverse ACL changes
        if 'acl' in changes:
            reverse_config['acl'] = self._reverse_acl_changes(changes['acl'])

        return reverse_config

    def _reverse_routing_changes(
        self,
        routing_changes: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Reverse routing configuration changes."""
        reverse_routing = {}

        if 'static_routes' in routing_changes:
            reverse_routing['static_routes'] = []
            for route_change in routing_changes['static_routes']:
                if route_change.get('action') == 'add':
                    reverse_routing['static_routes'].append({
                        'action': 'remove',
                        'route': route_change['route']
                    })
                elif route_change.get('action') == 'remove':
                    reverse_routing['static_routes'].append({
                        'action': 'add',
                        'route': route_change['route']
                    })

        return reverse_routing

    def _reverse_acl_changes(
        self,
        acl_changes: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Reverse ACL configuration changes."""
        reverse_acl = []

        for acl_change in acl_changes:
            if acl_change.get('action') == 'add':
                reverse_acl.append({
                    'action': 'remove',
                    'name': acl_change['name']
                })
            elif acl_change.get('action') == 'remove':
                reverse_acl.append({
                    'action': 'add',
                    'name': acl_change['name'],
                    'rules': acl_change.get('original_rules', [])
                })
            elif acl_change.get('action') == 'modify':
                reverse_acl.append({
                    'action': 'modify',
                    'name': acl_change['name'],
                    'rules': acl_change.get('original_rules', [])
                })

        return reverse_acl

    async def _get_previous_config(
        self,
        device_id: str,
        deployment_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get previous configuration for device."""
        try:
            # Get from device service
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://device-service:8084/devices/{device_id}/config/previous",
                    params={"before_deployment": deployment_id},
                    headers={"Authorization": f"Bearer {await self._get_service_token()}"}
                )

                if response.status_code == 200:
                    return response.json()['config']

            return None

        except Exception as e:
            logger.error(f"Failed to get previous config: {e}")
            return None

    async def _check_device_reachable(
        self,
        device_id: str
    ) -> bool:
        """Check if device is reachable."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://device-service:8084/devices/{device_id}/status",
                    headers={"Authorization": f"Bearer {await self._get_service_token()}"},
                    timeout=5
                )
                return response.status_code == 200

        except Exception:
            return False

    async def _update_deployment_status(
        self,
        deployment_id: str,
        status: str,
        rollback_result: Dict[str, Any]
    ):
        """Update deployment status after rollback."""
        try:
            await self.redis.set(
                f"deployment:{deployment_id}:rollback",
                json.dumps(rollback_result),
                ex=86400  # 24 hours
            )

        except Exception as e:
            logger.error(f"Failed to update deployment status: {e}")

    async def _get_service_token(self) -> str:
        """Get service authentication token."""
        token = await self.vault.get_secret("service/tokens/deployment")
        return token['token'] if token else ""