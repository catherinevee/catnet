"""
Async Device Connector
Provides non-blocking device operations using asyncio
"""
import asyncio
import concurrent.futures
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging
from datetime import datetime

from .device_connector import device_connector
from .device_store import device_store

logger = logging.getLogger(__name__)


class AsyncDeviceConnector:
    """
    Async wrapper for device operations
    Prevents blocking operations from timing out
    """

    def __init__(self, max_workers: int = 5):
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers)
        self.active_connections: Dict[str, Any] = {}

        async def connect_to_device_async(
            self,
            device_info: Dict[str,
                              Any]
        ) -> Optional[Any]:
        """
        Connect to device asynchronously
        NEVER use synchronous blocking operations!
        """
        loop = asyncio.get_event_loop()

        try:
            # Run blocking connection in thread pool
            connection = await loop.run_in_executor(
                self.executor,
                device_connector.connect_to_device,
                device_info
            )

            if connection:
                self.active_connections[device_info['id']] = connection
                logger.info(f"Async connection established to {device_info.get(
                    'hostname')}")

            return connection

        except Exception as e:
            logger.error(f"Async connection failed: {e}")
            return None

        async def execute_commands_async(
            self,
            device_id: str,
            commands: List[str]
        ) -> Dict[str, Any]:
        """
        Execute commands on device asynchronously
        Returns results without blocking
        """
        connection = self.active_connections.get(device_id)

        if not connection:
            device = device_store.get_device(device_id)
            if not device:
                return {'success': False, 'error': 'Device not found'}

            # Connect asynchronously
            connection = await self.connect_to_device_async(device.to_dict())
            if not connection:
                return {'success': False, 'error': 'Connection failed'}

        loop = asyncio.get_event_loop()

        try:
            # Execute commands in thread pool
            output = await loop.run_in_executor(
                self.executor,
                connection.send_config_commands,
                commands
            )

            return {
                'success': True,
                'output': output,
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    async def backup_device_async(self, device_id: str) -> Dict[str, Any]:
        """
        Backup device configuration asynchronously
        """
        connection = self.active_connections.get(device_id)

        if not connection:
            device = device_store.get_device(device_id)
            if not device:
                return {'success': False, 'error': 'Device not found'}

            connection = await self.connect_to_device_async(device.to_dict())
            if not connection:
                return {'success': False, 'error': 'Connection failed'}

        loop = asyncio.get_event_loop()

        try:
            # Backup in thread pool
            config = await loop.run_in_executor(
                self.executor,
                connection.backup_config
            )

            # Save backup
            backup_dir = Path("data/backups")
            backup_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            backup_file = backup_dir / f"{device_id}_backup_{timestamp}.cfg"

            with open(backup_file, 'w') as f:
                f.write(config)

            return {
                'success': True,
                'backup_file': str(backup_file),
                'size': len(config),
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Backup failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }

        async def deploy_to_devices_parallel(
            self,
            devices: List[str],
            commands: List[str]
        ) -> Dict[str, Any]:
        """
        Deploy to multiple devices in parallel
        Much faster than sequential deployment!
        """
        tasks = []

        for device_id in devices:
            task = self.execute_commands_async(device_id, commands)
            tasks.append(task)

        # Execute all deployments in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        deployment_results = {}
        success_count = 0

        for device_id, result in zip(devices, results):
            if isinstance(result, Exception):
                deployment_results[device_id] = {
                    'success': False,
                    'error': str(result)
                }
            else:
                deployment_results[device_id] = result
                if result.get('success'):
                    success_count += 1

        return {
            'total': len(devices),
            'successful': success_count,
            'failed': len(devices) - success_count,
            'results': deployment_results,
            'timestamp': datetime.utcnow().isoformat()
        }

        async def health_check_parallel(
            self,
            devices: List[str]
        ) -> Dict[str, Any]:
        """
        Perform health checks on multiple devices in parallel
        """
        async def check_device(device_id: str) -> Dict[str, Any]:
            try:
                # Simple connectivity check
                device = device_store.get_device(device_id)
                if not device:
                    return {'device_id': device_id, 'status': 'not_found'}

                connection = await self.connect_to_device_async(device.to_dict(
                ))

                if connection:
                    # Disconnect after check
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(
                        self.executor,
                        connection.disconnect
                    )
                    return {'device_id': device_id, 'status': 'healthy'}
                else:
                    return {'device_id': device_id, 'status': 'unreachable'}

            except Exception as e:
                return {
                    'device_id': device_id,
                    'status': 'error',
                    'error': str(e)}

        # Check all devices in parallel
        tasks = [check_device(device_id) for device_id in devices]
        results = await asyncio.gather(*tasks)

        # Summary
        healthy = sum(1 for r in results if r['status'] == 'healthy')
        unreachable = sum(1 for r in results if r['status'] == 'unreachable')
        errors = sum(1 for r in results if r['status'] == 'error')

        return {
            'total': len(devices),
            'healthy': healthy,
            'unreachable': unreachable,
            'errors': errors,
            'devices': results,
            'timestamp': datetime.utcnow().isoformat()
        }

    def cleanup(self):
        """Clean up connections and executor"""
        # Disconnect all active connections
        for connection in self.active_connections.values():
            try:
                connection.disconnect()
            except Exception:
                pass

        self.active_connections.clear()
        self.executor.shutdown(wait=False)


# Global async connector instance
async_device_connector = AsyncDeviceConnector()


async def example_usage():
    """
    Example of using async device operations
    """
    # Deploy to multiple devices in parallel
    devices = ['device1', 'device2', 'device3']
    commands = ['interface eth0', 'description Updated', 'no shutdown']

    print("Starting parallel deployment...")
    result = await async_device_connector.deploy_to_devices_parallel(
        devices,
        commands
    )
    print(f"Deployment complete: {result['successful']}/{result['total']} \
        successful")

    # Health check all devices
    print("\nPerforming parallel health checks...")
    health = await async_device_connector.health_check_parallel(devices)
    print(f"Health check: {health['healthy']}/{health['total']} devices \
        healthy")


if __name__ == "__main__":
    # Test async operations
    asyncio.run(example_usage())
