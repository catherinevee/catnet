"""
Health check worker for monitoring device and system health.
Performs periodic health checks and alerts on issues.
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from uuid import UUID
from enum import Enum

from src.workers.base import BaseWorker, WorkerTask
from src.devices.connector import SecureDeviceConnector
from src.core.exceptions import HealthCheckError
from src.db.models import Device, HealthCheck, Alert
from src.security.audit import AuditLogger


class HealthStatus(Enum):
    """Health status levels."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class HealthCheckWorker(BaseWorker):
    """
    Worker for processing health check tasks.
    Monitors device and system health, generates alerts.
    """

    def __init__(self, **kwargs):
        """Initialize health check worker."""
        super().__init__(**kwargs)
        self.device_connector = SecureDeviceConnector()
        self.audit = AuditLogger()

        # Health check thresholds
        self.thresholds = {
            'cpu_usage': {'warning': 70, 'critical': 90},
            'memory_usage': {'warning': 80, 'critical': 95},
            'disk_usage': {'warning': 75, 'critical': 90},
            'interface_errors': {'warning': 100, 'critical': 1000},
            'packet_loss': {'warning': 1, 'critical': 5},
            'latency_ms': {'warning': 100, 'critical': 500}
        }

    def get_worker_type(self) -> str:
        """Get worker type identifier."""
        return "health_check"

    async def process_task(self, task: WorkerTask) -> Dict[str, Any]:
        """
        Process health check task.

        Args:
            task: Health check task

        Returns:
            Task result
        """
        task_type = task.task_type
        payload = task.payload

        if task_type == "device_health_check":
            return await self._device_health_check(payload)

        elif task_type == "batch_health_check":
            return await self._batch_health_check(payload)

        elif task_type == "interface_health_check":
            return await self._interface_health_check(payload)

        elif task_type == "routing_health_check":
            return await self._routing_health_check(payload)

        elif task_type == "service_health_check":
            return await self._service_health_check(payload)

        elif task_type == "connectivity_check":
            return await self._connectivity_check(payload)

        else:
            raise ValueError(f"Unknown task type: {task_type}")

    async def _device_health_check(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive device health check."""
        device_id = UUID(payload['device_id'])
        check_type = payload.get('check_type', 'full')

        try:
            async with get_db() as db:
                device = await db.get(Device, device_id)
                if not device:
                    raise HealthCheckError(f"Device {device_id} not found")

                # Connect to device
                connection = await self.device_connector.connect_to_device(
                    device_id=str(device_id),
                    user_context={'system': True}
                )

                # Perform health checks
                health_data = {}

                if check_type in ['full', 'resources']:
                    health_data['resources'] = await self._check_resources(connection, device)

                if check_type in ['full', 'interfaces']:
                    health_data['interfaces'] = await self._check_interfaces(connection, device)

                if check_type in ['full', 'routing']:
                    health_data['routing'] = await self._check_routing(connection, device)

                if check_type in ['full', 'services']:
                    health_data['services'] = await self._check_services(connection, device)

                if check_type in ['full', 'configuration']:
                    health_data['configuration'] = await self._check_configuration(connection, device)

                # Calculate overall health status
                overall_status = self._calculate_overall_status(health_data)

                # Create health check record
                health_check = HealthCheck(
                    device_id=device_id,
                    check_type=check_type,
                    status=overall_status.value,
                    metrics=health_data,
                    checked_at=datetime.utcnow(),
                    response_time_ms=health_data.get('response_time_ms', 0)
                )

                db.add(health_check)

                # Update device health status
                device.health_status = overall_status.value
                device.last_health_check = datetime.utcnow()

                # Generate alerts if needed
                alerts = await self._generate_alerts(device, health_data, overall_status)
                for alert in alerts:
                    db.add(alert)

                await db.commit()

                await self.audit.log_event(
                    event_type="HEALTH_CHECK_COMPLETED",
                    details={
                        'device_id': str(device_id),
                        'status': overall_status.value,
                        'check_type': check_type,
                        'alerts_generated': len(alerts)
                    }
                )

                return {
                    'status': 'success',
                    'device_id': str(device_id),
                    'health_status': overall_status.value,
                    'health_data': health_data,
                    'alerts': len(alerts),
                    'timestamp': datetime.utcnow().isoformat()
                }

        except Exception as e:
            raise HealthCheckError(f"Health check failed: {e}")

    async def _batch_health_check(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Perform health checks on multiple devices."""
        device_ids = payload.get('device_ids', [])
        check_type = payload.get('check_type', 'basic')

        results = []
        batch_size = 10

        for i in range(0, len(device_ids), batch_size):
            batch = device_ids[i:i + batch_size]

            # Check devices in parallel
            batch_tasks = [
                self._device_health_check({
                    'device_id': device_id,
                    'check_type': check_type
                })
                for device_id in batch
            ]

            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)

            # Process results
            for device_id, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    results.append({
                        'device_id': device_id,
                        'status': 'failed',
                        'error': str(result)
                    })
                else:
                    results.append({
                        'device_id': device_id,
                        'status': 'success',
                        'health_status': result['health_status']
                    })

        # Calculate statistics
        healthy = len([r for r in results if r.get('health_status') == 'healthy'])
        unhealthy = len([r for r in results if r.get('health_status') in ['unhealthy', 'critical']])
        failed = len([r for r in results if r['status'] == 'failed'])

        return {
            'status': 'completed',
            'total': len(device_ids),
            'healthy': healthy,
            'unhealthy': unhealthy,
            'failed': failed,
            'results': results
        }

    async def _interface_health_check(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Check health of specific interfaces."""
        device_id = UUID(payload['device_id'])
        interface_names = payload.get('interfaces', [])

        try:
            connection = await self.device_connector.connect_to_device(
                device_id=str(device_id),
                user_context={'system': True}
            )

            interface_health = []

            for interface in interface_names:
                # Get interface statistics
                stats = await connection.get_interface_stats(interface)

                # Check for issues
                health_status = HealthStatus.HEALTHY
                issues = []

                if stats.get('errors_in', 0) > self.thresholds['interface_errors']['critical']:
                    health_status = HealthStatus.CRITICAL
                    issues.append(f"High input errors: {stats['errors_in']}")
                elif stats.get('errors_in', 0) > self.thresholds['interface_errors']['warning']:
                    health_status = HealthStatus.DEGRADED
                    issues.append(f"Input errors: {stats['errors_in']}")

                if stats.get('errors_out', 0) > self.thresholds['interface_errors']['critical']:
                    health_status = HealthStatus.CRITICAL
                    issues.append(f"High output errors: {stats['errors_out']}")

                interface_health.append({
                    'interface': interface,
                    'status': health_status.value,
                    'state': stats.get('state', 'unknown'),
                    'speed': stats.get('speed'),
                    'utilization_in': stats.get('utilization_in'),
                    'utilization_out': stats.get('utilization_out'),
                    'errors_in': stats.get('errors_in'),
                    'errors_out': stats.get('errors_out'),
                    'issues': issues
                })

            return {
                'status': 'success',
                'device_id': str(device_id),
                'interfaces': interface_health,
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            raise HealthCheckError(f"Interface health check failed: {e}")

    async def _routing_health_check(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Check routing protocol health."""
        device_id = UUID(payload['device_id'])

        try:
            connection = await self.device_connector.connect_to_device(
                device_id=str(device_id),
                user_context={'system': True}
            )

            routing_health = {}

            # Check BGP sessions
            bgp_sessions = await connection.get_bgp_sessions()
            routing_health['bgp'] = {
                'total_sessions': len(bgp_sessions),
                'established': len([s for s in bgp_sessions if s['state'] == 'Established']),
                'down': len([s for s in bgp_sessions if s['state'] != 'Established']),
                'sessions': bgp_sessions
            }

            # Check OSPF neighbors
            ospf_neighbors = await connection.get_ospf_neighbors()
            routing_health['ospf'] = {
                'total_neighbors': len(ospf_neighbors),
                'full': len([n for n in ospf_neighbors if n['state'] == 'Full']),
                'other': len([n for n in ospf_neighbors if n['state'] != 'Full']),
                'neighbors': ospf_neighbors
            }

            # Determine health status
            health_status = HealthStatus.HEALTHY
            if routing_health['bgp']['down'] > 0:
                health_status = HealthStatus.DEGRADED
            if routing_health['bgp']['down'] > routing_health['bgp']['established']:
                health_status = HealthStatus.CRITICAL

            return {
                'status': 'success',
                'device_id': str(device_id),
                'health_status': health_status.value,
                'routing': routing_health,
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            raise HealthCheckError(f"Routing health check failed: {e}")

    async def _service_health_check(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Check health of services running on device."""
        device_id = UUID(payload['device_id'])
        services = payload.get('services', ['ssh', 'snmp', 'ntp'])

        try:
            connection = await self.device_connector.connect_to_device(
                device_id=str(device_id),
                user_context={'system': True}
            )

            service_health = []

            for service in services:
                service_status = await connection.check_service(service)

                service_health.append({
                    'service': service,
                    'running': service_status.get('running', False),
                    'port': service_status.get('port'),
                    'process_id': service_status.get('pid'),
                    'memory_usage': service_status.get('memory_usage'),
                    'cpu_usage': service_status.get('cpu_usage')
                })

            # Determine overall service health
            running_services = len([s for s in service_health if s['running']])
            health_status = HealthStatus.HEALTHY
            if running_services < len(services):
                health_status = HealthStatus.DEGRADED
            if running_services == 0:
                health_status = HealthStatus.CRITICAL

            return {
                'status': 'success',
                'device_id': str(device_id),
                'health_status': health_status.value,
                'services': service_health,
                'running': running_services,
                'total': len(services),
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            raise HealthCheckError(f"Service health check failed: {e}")

    async def _connectivity_check(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Check network connectivity from device."""
        device_id = UUID(payload['device_id'])
        targets = payload.get('targets', [])

        try:
            connection = await self.device_connector.connect_to_device(
                device_id=str(device_id),
                user_context={'system': True}
            )

            connectivity_results = []

            for target in targets:
                # Ping target
                ping_result = await connection.ping(
                    target['address'],
                    count=target.get('count', 5)
                )

                # Evaluate result
                packet_loss = ping_result.get('packet_loss', 100)
                avg_latency = ping_result.get('avg_latency', 0)

                health_status = HealthStatus.HEALTHY
                if packet_loss > self.thresholds['packet_loss']['critical']:
                    health_status = HealthStatus.CRITICAL
                elif packet_loss > self.thresholds['packet_loss']['warning']:
                    health_status = HealthStatus.DEGRADED
                elif avg_latency > self.thresholds['latency_ms']['critical']:
                    health_status = HealthStatus.DEGRADED

                connectivity_results.append({
                    'target': target['address'],
                    'name': target.get('name', target['address']),
                    'reachable': packet_loss < 100,
                    'packet_loss': packet_loss,
                    'min_latency': ping_result.get('min_latency'),
                    'avg_latency': avg_latency,
                    'max_latency': ping_result.get('max_latency'),
                    'health_status': health_status.value
                })

            # Overall connectivity health
            unreachable = len([r for r in connectivity_results if not r['reachable']])
            health_status = HealthStatus.HEALTHY
            if unreachable > 0:
                health_status = HealthStatus.DEGRADED
            if unreachable > len(connectivity_results) // 2:
                health_status = HealthStatus.CRITICAL

            return {
                'status': 'success',
                'device_id': str(device_id),
                'health_status': health_status.value,
                'connectivity': connectivity_results,
                'reachable': len(connectivity_results) - unreachable,
                'unreachable': unreachable,
                'total': len(connectivity_results),
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            raise HealthCheckError(f"Connectivity check failed: {e}")

    async def _check_resources(self, connection, device: Device) -> Dict[str, Any]:
        """Check device resource utilization."""
        resources = await connection.get_resource_utilization()

        # Evaluate resource health
        issues = []
        if resources.get('cpu_usage', 0) > self.thresholds['cpu_usage']['critical']:
            issues.append(f"Critical CPU usage: {resources['cpu_usage']}%")
        elif resources.get('cpu_usage', 0) > self.thresholds['cpu_usage']['warning']:
            issues.append(f"High CPU usage: {resources['cpu_usage']}%")

        if resources.get('memory_usage', 0) > self.thresholds['memory_usage']['critical']:
            issues.append(f"Critical memory usage: {resources['memory_usage']}%")
        elif resources.get('memory_usage', 0) > self.thresholds['memory_usage']['warning']:
            issues.append(f"High memory usage: {resources['memory_usage']}%")

        return {
            'cpu_usage': resources.get('cpu_usage'),
            'memory_usage': resources.get('memory_usage'),
            'disk_usage': resources.get('disk_usage'),
            'temperature': resources.get('temperature'),
            'uptime_seconds': resources.get('uptime'),
            'issues': issues
        }

    async def _check_interfaces(self, connection, device: Device) -> Dict[str, Any]:
        """Check interface health."""
        interfaces = await connection.get_interfaces()

        interface_stats = {
            'total': len(interfaces),
            'up': 0,
            'down': 0,
            'errors': 0,
            'high_utilization': 0
        }

        for interface in interfaces:
            if interface.get('state') == 'up':
                interface_stats['up'] += 1
            else:
                interface_stats['down'] += 1

            if interface.get('errors_in', 0) > 0 or interface.get('errors_out', 0) > 0:
                interface_stats['errors'] += 1

            if interface.get('utilization', 0) > 80:
                interface_stats['high_utilization'] += 1

        return interface_stats

    async def _check_routing(self, connection, device: Device) -> Dict[str, Any]:
        """Check routing protocol health."""
        routing_info = {
            'routes_total': 0,
            'bgp_sessions': 0,
            'bgp_established': 0,
            'ospf_neighbors': 0,
            'ospf_full': 0
        }

        try:
            # Get routing table size
            routes = await connection.get_routes()
            routing_info['routes_total'] = len(routes)

            # Check BGP
            bgp_sessions = await connection.get_bgp_sessions()
            routing_info['bgp_sessions'] = len(bgp_sessions)
            routing_info['bgp_established'] = len([s for s in bgp_sessions if s['state'] == 'Established'])

            # Check OSPF
            ospf_neighbors = await connection.get_ospf_neighbors()
            routing_info['ospf_neighbors'] = len(ospf_neighbors)
            routing_info['ospf_full'] = len([n for n in ospf_neighbors if n['state'] == 'Full'])

        except:
            pass  # Some devices may not have all protocols

        return routing_info

    async def _check_services(self, connection, device: Device) -> Dict[str, Any]:
        """Check device services."""
        services = {
            'ssh': False,
            'snmp': False,
            'ntp': False,
            'syslog': False
        }

        for service in services.keys():
            try:
                status = await connection.check_service(service)
                services[service] = status.get('running', False)
            except:
                pass

        return services

    async def _check_configuration(self, connection, device: Device) -> Dict[str, Any]:
        """Check configuration compliance."""
        config_info = {
            'last_change': None,
            'unsaved_changes': False,
            'config_size': 0
        }

        try:
            config_status = await connection.get_config_status()
            config_info.update(config_status)
        except:
            pass

        return config_info

    def _calculate_overall_status(self, health_data: Dict[str, Any]) -> HealthStatus:
        """Calculate overall health status from component health data."""
        # Check for critical issues
        if health_data.get('resources', {}).get('issues'):
            for issue in health_data['resources']['issues']:
                if 'Critical' in issue:
                    return HealthStatus.CRITICAL

        # Check interface health
        interfaces = health_data.get('interfaces', {})
        if interfaces.get('down', 0) > interfaces.get('up', 0):
            return HealthStatus.CRITICAL
        if interfaces.get('errors', 0) > 0:
            return HealthStatus.DEGRADED

        # Check routing health
        routing = health_data.get('routing', {})
        if routing.get('bgp_sessions', 0) > 0:
            if routing.get('bgp_established', 0) == 0:
                return HealthStatus.CRITICAL
            if routing.get('bgp_established', 0) < routing.get('bgp_sessions', 0):
                return HealthStatus.DEGRADED

        # Check services
        services = health_data.get('services', {})
        if not services.get('ssh', True):
            return HealthStatus.DEGRADED

        return HealthStatus.HEALTHY

    async def _generate_alerts(
        self,
        device: Device,
        health_data: Dict[str, Any],
        status: HealthStatus
    ) -> List[Alert]:
        """Generate alerts based on health check results."""
        alerts = []

        if status == HealthStatus.CRITICAL:
            alerts.append(Alert(
                device_id=device.id,
                severity='critical',
                title=f"Device {device.hostname} in critical state",
                description=f"Health check detected critical issues",
                metadata=health_data,
                created_at=datetime.utcnow()
            ))

        # Check specific issues
        resources = health_data.get('resources', {})
        if resources.get('cpu_usage', 0) > self.thresholds['cpu_usage']['critical']:
            alerts.append(Alert(
                device_id=device.id,
                severity='high',
                title=f"High CPU usage on {device.hostname}",
                description=f"CPU usage is {resources['cpu_usage']}%",
                metadata={'cpu_usage': resources['cpu_usage']},
                created_at=datetime.utcnow()
            ))

        return alerts


# Export main components
__all__ = ['HealthCheckWorker', 'HealthStatus']