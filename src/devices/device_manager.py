from typing import Dict, List, Optional, Any, Tuple
import asyncio
import uuid
import structlog
from datetime import datetime, timedelta
from contextlib import asynccontextmanager

from .device_service import DeviceService, ConnectionStatus
from .device_factory import DeviceHandlerFactory, BaseDeviceHandler
from ..db.models import Device, DeviceVendor, DeploymentStatus
from ..db.database import get_db_session
from ..security.vault import VaultClient
from ..security.audit import AuditLogger
from ..core.exceptions import (
    DeviceConnectionError, DeploymentError, ValidationError,
    SecurityError, NetworkError
)

logger = structlog.get_logger()

class DeviceManager:
    def __init__(self):
        self.device_service = DeviceService()
        self.vault = VaultClient()
        self.audit = AuditLogger()
        self.active_handlers: Dict[str, BaseDeviceHandler] = {}
        self.deployment_locks: Dict[str, asyncio.Lock] = {}
        self.health_check_interval = 300  # 5 minutes
        self.max_concurrent_deployments = 5

    async def initialize_device_pool(
        self,
        device_ids: List[str],
        user_context: Dict[str, Any]
    ) -> Dict[str, bool]:
        """Initialize connection pool for multiple devices"""
        results = {}
        semaphore = asyncio.Semaphore(self.max_concurrent_deployments)

        async def connect_single_device(device_id: str) -> Tuple[str, bool]:
            async with semaphore:
                try:
                    await self.get_device_handler(device_id, user_context)
                    return device_id, True
                except Exception as e:
                    logger.error(f"Failed to initialize device {device_id}: {e}")
                    return device_id, False

        tasks = [connect_single_device(device_id) for device_id in device_ids]
        connection_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in connection_results:
            if isinstance(result, Exception):
                logger.error(f"Device initialization exception: {result}")
                continue
            device_id, success = result
            results[device_id] = success

        await self.audit.log_device_pool_initialization(
            user_id=user_context['user_id'],
            device_count=len(device_ids),
            successful_connections=sum(results.values())
        )

        return results

    @asynccontextmanager
    async def get_device_handler(
        self,
        device_id: str,
        user_context: Dict[str, Any],
        auto_connect: bool = True
    ):
        """Context manager for device handler with automatic cleanup"""
        handler = None
        try:
            # Check if handler already exists
            if device_id in self.active_handlers:
                handler = self.active_handlers[device_id]
                yield handler
                return

            # Get device information
            async with get_db_session() as session:
                device = await session.get(Device, device_id)
                if not device:
                    raise ValidationError(f"Device {device_id} not found")

                # Get temporary credentials from Vault
                credentials = await self.vault.get_device_credentials(
                    device_id=device_id,
                    user_id=user_context['user_id'],
                    ttl_seconds=3600
                )

                # Prepare connection parameters
                connection_params = {
                    'device_type': self._get_netmiko_device_type(device.vendor),
                    'host': device.ip_address,
                    'username': credentials['username'],
                    'password': credentials['password'],
                    'timeout': 60,
                    'session_log': f"/tmp/catnet_session_{device_id}_{uuid.uuid4().hex[:8]}.log"
                }

                if device.ssh_port and device.ssh_port != 22:
                    connection_params['port'] = device.ssh_port

                # Create device handler
                handler = DeviceHandlerFactory.create_handler(
                    vendor=device.vendor,
                    connection_params=connection_params
                )

                if auto_connect:
                    await handler.connect()

                self.active_handlers[device_id] = handler
                yield handler

        except Exception as e:
            logger.error(f"Device handler error for {device_id}: {e}")
            raise
        finally:
            # Cleanup handler
            if handler and device_id in self.active_handlers:
                try:
                    await handler.disconnect()
                except Exception as e:
                    logger.warning(f"Error disconnecting handler for {device_id}: {e}")
                finally:
                    if device_id in self.active_handlers:
                        del self.active_handlers[device_id]

    async def deploy_configuration_to_device(
        self,
        device_id: str,
        config_content: str,
        deployment_method: str,
        user_context: Dict[str, Any],
        backup_first: bool = True
    ) -> Dict[str, Any]:
        """Deploy configuration to a single device with comprehensive error handling"""

        # Ensure only one deployment per device at a time
        if device_id not in self.deployment_locks:
            self.deployment_locks[device_id] = asyncio.Lock()

        async with self.deployment_locks[device_id]:
            deployment_result = {
                'device_id': device_id,
                'success': False,
                'backup_id': None,
                'deployment_details': None,
                'rollback_performed': False,
                'error': None,
                'start_time': datetime.utcnow().isoformat(),
                'end_time': None
            }

            try:
                logger.info(f"Starting configuration deployment to device {device_id}")

                async with self.get_device_handler(device_id, user_context) as handler:
                    # Step 1: Create backup if requested
                    if backup_first:
                        try:
                            backup_id = await self.device_service.backup_device_config(
                                device_id, user_context, "running"
                            )
                            deployment_result['backup_id'] = backup_id
                            logger.info(f"Created backup {backup_id} for device {device_id}")
                        except Exception as e:
                            logger.error(f"Backup failed for device {device_id}: {e}")
                            raise DeploymentError(
                                f"Pre-deployment backup failed: {str(e)}",
                                device_id=device_id,
                                stage="backup"
                            )

                    # Step 2: Validate current device state
                    try:
                        pre_deployment_health = await handler.get_health_metrics()
                        if not self._validate_device_health(pre_deployment_health):
                            raise DeploymentError(
                                "Device health check failed before deployment",
                                device_id=device_id,
                                stage="pre_health_check"
                            )
                    except Exception as e:
                        logger.warning(f"Pre-deployment health check failed: {e}")

                    # Step 3: Deploy configuration
                    try:
                        deployment_details = await handler.deploy_config(
                            config_content, deployment_method
                        )
                        deployment_result['deployment_details'] = deployment_details

                        if not deployment_details.get('success', False):
                            raise DeploymentError(
                                f"Configuration deployment failed: {deployment_details.get('errors', [])}",
                                device_id=device_id,
                                stage="deployment"
                            )

                    except Exception as e:
                        logger.error(f"Configuration deployment failed for {device_id}: {e}")

                        # Attempt rollback if backup was created
                        if deployment_result['backup_id'] and backup_first:
                            try:
                                await self._perform_emergency_rollback(
                                    device_id, deployment_result['backup_id'], user_context
                                )
                                deployment_result['rollback_performed'] = True
                            except Exception as rollback_error:
                                logger.error(f"Emergency rollback failed: {rollback_error}")

                        raise DeploymentError(
                            f"Configuration deployment failed: {str(e)}",
                            device_id=device_id,
                            stage="deployment"
                        )

                    # Step 4: Post-deployment validation
                    try:
                        await asyncio.sleep(5)  # Allow device to process changes

                        post_deployment_health = await handler.get_health_metrics()
                        if not self._validate_device_health(post_deployment_health):
                            # Rollback due to health check failure
                            if deployment_result['backup_id'] and backup_first:
                                await self._perform_emergency_rollback(
                                    device_id, deployment_result['backup_id'], user_context
                                )
                                deployment_result['rollback_performed'] = True

                            raise DeploymentError(
                                "Device health check failed after deployment",
                                device_id=device_id,
                                stage="post_health_check"
                            )

                    except Exception as e:
                        logger.error(f"Post-deployment validation failed: {e}")
                        deployment_result['error'] = str(e)
                        raise

                    # Step 5: Verify configuration persistence
                    try:
                        await asyncio.sleep(2)
                        current_config = await handler.get_config("running")

                        # Basic validation that some changes were applied
                        if len(current_config) < 100:  # Sanity check
                            raise DeploymentError(
                                "Configuration appears incomplete after deployment",
                                device_id=device_id,
                                stage="verification"
                            )

                    except Exception as e:
                        logger.warning(f"Configuration verification warning: {e}")

                    deployment_result['success'] = True
                    deployment_result['end_time'] = datetime.utcnow().isoformat()

                    await self.audit.log_configuration_deployment(
                        user_id=user_context['user_id'],
                        device_id=device_id,
                        deployment_method=deployment_method,
                        success=True,
                        backup_id=deployment_result['backup_id'],
                        config_size=len(config_content)
                    )

                    logger.info(f"Configuration deployment successful for device {device_id}")
                    return deployment_result

            except Exception as e:
                deployment_result['success'] = False
                deployment_result['error'] = str(e)
                deployment_result['end_time'] = datetime.utcnow().isoformat()

                await self.audit.log_configuration_deployment(
                    user_id=user_context['user_id'],
                    device_id=device_id,
                    deployment_method=deployment_method,
                    success=False,
                    error=str(e),
                    backup_id=deployment_result['backup_id']
                )

                logger.error(f"Configuration deployment failed for device {device_id}: {e}")
                return deployment_result

    async def parallel_device_deployment(
        self,
        deployment_targets: List[Dict[str, Any]],
        user_context: Dict[str, Any],
        max_concurrent: int = 5
    ) -> Dict[str, Any]:
        """Deploy configurations to multiple devices in parallel"""

        semaphore = asyncio.Semaphore(max_concurrent)
        deployment_results = {
            'total_devices': len(deployment_targets),
            'successful_deployments': 0,
            'failed_deployments': 0,
            'device_results': {},
            'start_time': datetime.utcnow().isoformat(),
            'end_time': None
        }

        async def deploy_to_single_device(target: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
            async with semaphore:
                device_id = target['device_id']
                config_content = target['config_content']
                deployment_method = target.get('deployment_method', 'merge')

                try:
                    result = await self.deploy_configuration_to_device(
                        device_id=device_id,
                        config_content=config_content,
                        deployment_method=deployment_method,
                        user_context=user_context,
                        backup_first=target.get('backup_first', True)
                    )
                    return device_id, result

                except Exception as e:
                    logger.error(f"Parallel deployment failed for {device_id}: {e}")
                    return device_id, {
                        'device_id': device_id,
                        'success': False,
                        'error': str(e),
                        'start_time': datetime.utcnow().isoformat(),
                        'end_time': datetime.utcnow().isoformat()
                    }

        # Execute deployments in parallel
        tasks = [deploy_to_single_device(target) for target in deployment_targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Parallel deployment exception: {result}")
                deployment_results['failed_deployments'] += 1
                continue

            device_id, device_result = result
            deployment_results['device_results'][device_id] = device_result

            if device_result.get('success', False):
                deployment_results['successful_deployments'] += 1
            else:
                deployment_results['failed_deployments'] += 1

        deployment_results['end_time'] = datetime.utcnow().isoformat()

        await self.audit.log_parallel_deployment(
            user_id=user_context['user_id'],
            total_devices=deployment_results['total_devices'],
            successful_devices=deployment_results['successful_deployments'],
            failed_devices=deployment_results['failed_deployments']
        )

        logger.info(
            f"Parallel deployment completed: {deployment_results['successful_deployments']}"
            f"/{deployment_results['total_devices']} successful"
        )

        return deployment_results

    async def perform_device_health_checks(
        self,
        device_ids: List[str],
        user_context: Dict[str, Any]
    ) -> Dict[str, Dict[str, Any]]:
        """Perform health checks on multiple devices"""

        health_results = {}
        semaphore = asyncio.Semaphore(10)  # Allow more concurrent health checks

        async def check_single_device(device_id: str) -> Tuple[str, Dict[str, Any]]:
            async with semaphore:
                try:
                    health_data = await self.device_service.get_device_health(
                        device_id, user_context
                    )
                    return device_id, health_data
                except Exception as e:
                    logger.error(f"Health check failed for {device_id}: {e}")
                    return device_id, {
                        'device_id': device_id,
                        'status': 'error',
                        'error': str(e),
                        'timestamp': datetime.utcnow().isoformat()
                    }

        tasks = [check_single_device(device_id) for device_id in device_ids]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Health check exception: {result}")
                continue
            device_id, health_data = result
            health_results[device_id] = health_data

        return health_results

    async def cleanup_stale_handlers(self):
        """Clean up stale device handlers and connections"""
        current_time = datetime.utcnow()
        stale_threshold = timedelta(hours=1)

        stale_device_ids = []

        for device_id, handler in self.active_handlers.items():
            # Check if handler is stale (implementation would track last activity)
            try:
                # Attempt a simple command to verify connection
                await handler.get_config("running")
            except Exception:
                stale_device_ids.append(device_id)

        for device_id in stale_device_ids:
            try:
                handler = self.active_handlers.get(device_id)
                if handler:
                    await handler.disconnect()
                del self.active_handlers[device_id]
                logger.info(f"Cleaned up stale handler for device {device_id}")
            except Exception as e:
                logger.error(f"Error cleaning up handler for {device_id}: {e}")

        # Clean up deployment locks
        active_devices = set(self.active_handlers.keys())
        lock_devices = set(self.deployment_locks.keys())
        stale_locks = lock_devices - active_devices

        for device_id in stale_locks:
            del self.deployment_locks[device_id]

        logger.info(f"Cleaned up {len(stale_device_ids)} stale handlers and {len(stale_locks)} locks")

    def _get_netmiko_device_type(self, vendor: DeviceVendor) -> str:
        """Map device vendor to netmiko device type"""
        mapping = {
            DeviceVendor.CISCO_IOS: "cisco_ios",
            DeviceVendor.CISCO_IOS_XE: "cisco_xe",
            DeviceVendor.CISCO_NX_OS: "cisco_nxos",
            DeviceVendor.JUNIPER_JUNOS: "juniper_junos",
            DeviceVendor.PALO_ALTO: "paloalto_panos",
            DeviceVendor.FORTINET: "fortinet",
            DeviceVendor.ARUBA: "aruba_os"
        }
        return mapping.get(vendor, "generic")

    def _validate_device_health(self, health_metrics: Dict[str, Any]) -> bool:
        """Validate device health metrics"""
        try:
            # CPU utilization check
            cpu_5sec = health_metrics.get('cpu_5sec', 0)
            if cpu_5sec > 90:
                logger.warning(f"High CPU utilization: {cpu_5sec}%")
                return False

            # Memory utilization check
            memory_util = health_metrics.get('memory_utilization', 0)
            if memory_util > 95:
                logger.warning(f"High memory utilization: {memory_util}%")
                return False

            # Interface status check
            interfaces = health_metrics.get('interfaces', {})
            total_interfaces = interfaces.get('total', 0)
            down_interfaces = interfaces.get('down', 0)

            if total_interfaces > 0 and (down_interfaces / total_interfaces) > 0.5:
                logger.warning(f"Many interfaces down: {down_interfaces}/{total_interfaces}")
                return False

            return True

        except Exception as e:
            logger.error(f"Health validation error: {e}")
            return False

    async def _perform_emergency_rollback(
        self,
        device_id: str,
        backup_id: str,
        user_context: Dict[str, Any]
    ) -> bool:
        """Perform emergency rollback using backup configuration"""
        try:
            logger.warning(f"Performing emergency rollback for device {device_id}")

            # Get backup configuration
            async with get_db_session() as session:
                from ..db.models import ConfigBackup
                backup = await session.get(ConfigBackup, backup_id)
                if not backup:
                    raise ValidationError(f"Backup {backup_id} not found")

                # Decrypt backup content
                backup_content = await self.vault.decrypt_config(backup.content_encrypted)

            # Deploy backup configuration
            async with self.get_device_handler(device_id, user_context) as handler:
                rollback_result = await handler.deploy_config(backup_content, "replace")

                if rollback_result.get('success', False):
                    await self.audit.log_emergency_rollback(
                        user_id=user_context['user_id'],
                        device_id=device_id,
                        backup_id=backup_id,
                        success=True
                    )
                    logger.info(f"Emergency rollback successful for device {device_id}")
                    return True
                else:
                    raise DeploymentError(
                        f"Rollback deployment failed: {rollback_result.get('errors', [])}",
                        device_id=device_id,
                        stage="rollback"
                    )

        except Exception as e:
            await self.audit.log_emergency_rollback(
                user_id=user_context['user_id'],
                device_id=device_id,
                backup_id=backup_id,
                success=False,
                error=str(e)
            )
            logger.error(f"Emergency rollback failed for device {device_id}: {e}")
            raise DeviceConnectionError(
                f"Emergency rollback failed: {str(e)}",
                device_id=device_id,
                operation="rollback"
            )