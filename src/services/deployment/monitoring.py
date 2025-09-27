"""
Deployment monitoring component.
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import json
import statistics

import redis.asyncio as redis
import httpx

from src.core.logging import get_logger
from src.core.config import get_settings

logger = get_logger(__name__)
settings = get_settings()


class DeploymentMonitor:
    """Monitors deployment progress and health."""

    def __init__(self):
        self.redis = None
        self.monitoring_interval = 10  # seconds
        self.alert_thresholds = {
            'error_rate': 0.1,  # 10%
            'response_time': 300,  # 5 minutes
            'cpu_usage': 80,  # 80%
            'memory_usage': 85,  # 85%
            'device_failure_rate': 0.2  # 20%
        }
        self.active_monitors = {}

    async def initialize(self):
        """Initialize deployment monitor."""
        self.redis = await redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True
        )

    async def monitor_deployment(
        self,
        deployment_id: str,
        stop_event: Optional[asyncio.Event] = None
    ):
        """
        Monitor deployment progress.

        Args:
            deployment_id: Deployment ID
            stop_event: Optional event to stop monitoring
        """
        try:
            logger.info(f"Starting monitoring for deployment {deployment_id}")

            self.active_monitors[deployment_id] = {
                'started_at': datetime.utcnow(),
                'metrics': [],
                'alerts': []
            }

            while True:
                # Check if should stop
                if stop_event and stop_event.is_set():
                    break

                # Check if deployment is cancelled
                cancelled = await self.redis.get(f"deployment:cancel:{deployment_id}")
                if cancelled:
                    logger.info(f"Deployment {deployment_id} cancelled, stopping monitor")
                    break

                # Collect metrics
                metrics = await self._collect_metrics(deployment_id)
                self.active_monitors[deployment_id]['metrics'].append(metrics)

                # Store metrics
                await self._store_metrics(deployment_id, metrics)

                # Check for alerts
                alerts = await self._check_alerts(deployment_id, metrics)
                if alerts:
                    self.active_monitors[deployment_id]['alerts'].extend(alerts)
                    await self._send_alerts(deployment_id, alerts)

                # Check deployment status
                status = await self._get_deployment_status(deployment_id)
                if status in ['completed', 'failed', 'rolled_back', 'cancelled']:
                    logger.info(f"Deployment {deployment_id} {status}, stopping monitor")
                    break

                # Wait before next check
                await asyncio.sleep(self.monitoring_interval)

        except asyncio.CancelledError:
            logger.info(f"Monitoring cancelled for deployment {deployment_id}")
        except Exception as e:
            logger.error(f"Monitoring error for deployment {deployment_id}: {e}")
        finally:
            # Cleanup
            if deployment_id in self.active_monitors:
                del self.active_monitors[deployment_id]

    async def get_health(
        self,
        deployment_id: str
    ) -> 'DeploymentHealth':
        """
        Get deployment health status.

        Args:
            deployment_id: Deployment ID

        Returns:
            Deployment health
        """
        from .models import DeploymentHealth

        try:
            # Get deployment status
            status_data = await self._get_deployment_details(deployment_id)
            if not status_data:
                return DeploymentHealth(
                    deployment_id=deployment_id,
                    overall_health='unknown',
                    device_health={},
                    progress_percentage=0.0
                )

            # Calculate progress
            total_devices = status_data.get('devices', {}).get('total', 0)
            completed = (
                status_data.get('devices', {}).get('successful', 0) +
                status_data.get('devices', {}).get('failed', 0)
            )
            progress = (completed / total_devices * 100) if total_devices > 0 else 0

            # Check device health
            device_health = await self._get_device_health(
                status_data.get('device_details', [])
            )

            # Determine overall health
            failed_count = status_data.get('devices', {}).get('failed', 0)
            failure_rate = (failed_count / total_devices) if total_devices > 0 else 0

            if failure_rate > 0.2:
                overall_health = 'unhealthy'
            elif failure_rate > 0.1:
                overall_health = 'degraded'
            else:
                overall_health = 'healthy'

            # Get recent alerts
            alerts = await self._get_recent_alerts(deployment_id)

            # Estimate time remaining
            time_remaining = None
            if progress > 0 and progress < 100:
                # Get average device deployment time
                metrics = self.active_monitors.get(deployment_id, {}).get('metrics', [])
                if metrics:
                    avg_time = statistics.mean([m.get('avg_device_time', 30) for m in metrics[-5:]])
                    remaining_devices = total_devices - completed
                    time_remaining = int(avg_time * remaining_devices)

            return DeploymentHealth(
                deployment_id=deployment_id,
                overall_health=overall_health,
                device_health=device_health,
                progress_percentage=progress,
                estimated_time_remaining=time_remaining,
                current_phase=self._determine_phase(progress),
                alerts=alerts
            )

        except Exception as e:
            logger.error(f"Failed to get deployment health: {e}")
            return DeploymentHealth(
                deployment_id=deployment_id,
                overall_health='error',
                device_health={},
                progress_percentage=0.0,
                alerts=[{'type': 'error', 'message': str(e)}]
            )

    async def get_metrics(
        self,
        deployment_id: str,
        time_range: Optional[timedelta] = None
    ) -> List[Dict[str, Any]]:
        """
        Get deployment metrics.

        Args:
            deployment_id: Deployment ID
            time_range: Optional time range for metrics

        Returns:
            List of metrics
        """
        try:
            # Get from Redis
            metrics_key = f"deployment:{deployment_id}:metrics"
            metrics_data = await self.redis.lrange(metrics_key, 0, -1)

            metrics = [json.loads(m) for m in metrics_data]

            # Filter by time range if specified
            if time_range:
                cutoff = datetime.utcnow() - time_range
                metrics = [
                    m for m in metrics
                    if datetime.fromisoformat(m['timestamp']) > cutoff
                ]

            return metrics

        except Exception as e:
            logger.error(f"Failed to get metrics: {e}")
            return []

    async def _collect_metrics(
        self,
        deployment_id: str
    ) -> Dict[str, Any]:
        """Collect deployment metrics."""
        try:
            # Get deployment status
            status_data = await self._get_deployment_details(deployment_id)

            # Get device metrics
            device_metrics = await self._collect_device_metrics(
                status_data.get('device_details', [])
            )

            # Calculate aggregated metrics
            metrics = {
                'deployment_id': deployment_id,
                'timestamp': datetime.utcnow().isoformat(),
                'devices': {
                    'total': status_data.get('devices', {}).get('total', 0),
                    'completed': (
                        status_data.get('devices', {}).get('successful', 0) +
                        status_data.get('devices', {}).get('failed', 0)
                    ),
                    'successful': status_data.get('devices', {}).get('successful', 0),
                    'failed': status_data.get('devices', {}).get('failed', 0),
                    'in_progress': status_data.get('devices', {}).get('in_progress', 0),
                    'pending': status_data.get('devices', {}).get('pending', 0)
                },
                'success_rate': self._calculate_success_rate(status_data),
                'error_rate': self._calculate_error_rate(status_data),
                'avg_device_time': self._calculate_avg_device_time(status_data),
                'device_health': device_metrics.get('health', {}),
                'resource_usage': device_metrics.get('resources', {}),
                'network_stats': device_metrics.get('network', {})
            }

            return metrics

        except Exception as e:
            logger.error(f"Failed to collect metrics: {e}")
            return {
                'deployment_id': deployment_id,
                'timestamp': datetime.utcnow().isoformat(),
                'error': str(e)
            }

    async def _collect_device_metrics(
        self,
        device_details: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Collect metrics from devices."""
        metrics = {
            'health': {},
            'resources': {},
            'network': {}
        }

        try:
            # Get metrics from monitoring service
            for device in device_details:
                device_id = device['device_id']

                # Get device health
                async with httpx.AsyncClient() as client:
                    try:
                        response = await client.get(
                            f"http://monitoring-service:8085/devices/{device_id}/metrics",
                            headers={"Authorization": f"Bearer {await self._get_service_token()}"},
                            timeout=5
                        )

                        if response.status_code == 200:
                            device_metrics = response.json()
                            metrics['health'][device_id] = device_metrics.get('health', 'unknown')
                            metrics['resources'][device_id] = {
                                'cpu': device_metrics.get('cpu_usage', 0),
                                'memory': device_metrics.get('memory_usage', 0)
                            }
                            metrics['network'][device_id] = {
                                'bandwidth': device_metrics.get('bandwidth_usage', 0),
                                'packet_loss': device_metrics.get('packet_loss', 0)
                            }
                    except Exception:
                        metrics['health'][device_id] = 'unreachable'

        except Exception as e:
            logger.error(f"Failed to collect device metrics: {e}")

        return metrics

    async def _store_metrics(
        self,
        deployment_id: str,
        metrics: Dict[str, Any]
    ):
        """Store metrics in Redis."""
        try:
            metrics_key = f"deployment:{deployment_id}:metrics"
            await self.redis.lpush(metrics_key, json.dumps(metrics))

            # Keep only last 1000 metrics (about 3 hours at 10s interval)
            await self.redis.ltrim(metrics_key, 0, 999)

            # Set expiration
            await self.redis.expire(metrics_key, 86400)  # 24 hours

        except Exception as e:
            logger.error(f"Failed to store metrics: {e}")

    async def _check_alerts(
        self,
        deployment_id: str,
        metrics: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Check for alert conditions."""
        alerts = []

        try:
            # Check error rate
            error_rate = metrics.get('error_rate', 0)
            if error_rate > self.alert_thresholds['error_rate']:
                alerts.append({
                    'type': 'error_rate',
                    'severity': 'high',
                    'message': f"Error rate {error_rate:.1%} exceeds threshold",
                    'value': error_rate,
                    'threshold': self.alert_thresholds['error_rate']
                })

            # Check device failure rate
            devices = metrics.get('devices', {})
            total = devices.get('total', 0)
            failed = devices.get('failed', 0)
            if total > 0:
                failure_rate = failed / total
                if failure_rate > self.alert_thresholds['device_failure_rate']:
                    alerts.append({
                        'type': 'device_failure',
                        'severity': 'critical',
                        'message': f"Device failure rate {failure_rate:.1%} exceeds threshold",
                        'value': failure_rate,
                        'threshold': self.alert_thresholds['device_failure_rate']
                    })

            # Check resource usage
            resources = metrics.get('resource_usage', {})
            for device_id, usage in resources.items():
                if usage.get('cpu', 0) > self.alert_thresholds['cpu_usage']:
                    alerts.append({
                        'type': 'cpu_usage',
                        'severity': 'medium',
                        'message': f"Device {device_id} CPU usage {usage['cpu']}% exceeds threshold",
                        'device_id': device_id,
                        'value': usage['cpu'],
                        'threshold': self.alert_thresholds['cpu_usage']
                    })

                if usage.get('memory', 0) > self.alert_thresholds['memory_usage']:
                    alerts.append({
                        'type': 'memory_usage',
                        'severity': 'medium',
                        'message': f"Device {device_id} memory usage {usage['memory']}% exceeds threshold",
                        'device_id': device_id,
                        'value': usage['memory'],
                        'threshold': self.alert_thresholds['memory_usage']
                    })

            # Check deployment time
            avg_device_time = metrics.get('avg_device_time', 0)
            if avg_device_time > self.alert_thresholds['response_time']:
                alerts.append({
                    'type': 'slow_deployment',
                    'severity': 'low',
                    'message': f"Average device deployment time {avg_device_time}s exceeds threshold",
                    'value': avg_device_time,
                    'threshold': self.alert_thresholds['response_time']
                })

        except Exception as e:
            logger.error(f"Failed to check alerts: {e}")

        return alerts

    async def _send_alerts(
        self,
        deployment_id: str,
        alerts: List[Dict[str, Any]]
    ):
        """Send alerts via notification service."""
        try:
            async with httpx.AsyncClient() as client:
                for alert in alerts:
                    # Determine recipients based on severity
                    if alert['severity'] == 'critical':
                        recipients = await self._get_oncall_users()
                    else:
                        recipients = await self._get_deployment_owner(deployment_id)

                    for recipient in recipients:
                        await client.post(
                            "http://monitoring-service:8085/notify",
                            json={
                                "recipient": recipient,
                                "type": "deployment_alert",
                                "subject": f"Deployment Alert: {deployment_id}",
                                "message": alert['message'],
                                "priority": alert['severity'],
                                "metadata": {
                                    "deployment_id": deployment_id,
                                    "alert": alert
                                }
                            },
                            headers={"Authorization": f"Bearer {await self._get_service_token()}"}
                        )

        except Exception as e:
            logger.error(f"Failed to send alerts: {e}")

    async def _get_deployment_status(
        self,
        deployment_id: str
    ) -> str:
        """Get deployment status."""
        try:
            # Check cache
            cached = await self.redis.get(f"deployment:{deployment_id}:status")
            if cached:
                return cached

            # Get from service
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://localhost:8083/deploy/{deployment_id}/status",
                    headers={"Authorization": f"Bearer {await self._get_service_token()}"}
                )

                if response.status_code == 200:
                    data = response.json()
                    return data.get('status', 'unknown')

            return 'unknown'

        except Exception as e:
            logger.error(f"Failed to get deployment status: {e}")
            return 'error'

    async def _get_deployment_details(
        self,
        deployment_id: str
    ) -> Dict[str, Any]:
        """Get detailed deployment information."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://localhost:8083/deploy/{deployment_id}/status",
                    headers={"Authorization": f"Bearer {await self._get_service_token()}"}
                )

                if response.status_code == 200:
                    return response.json()

            return {}

        except Exception as e:
            logger.error(f"Failed to get deployment details: {e}")
            return {}

    async def _get_device_health(
        self,
        device_details: List[Dict[str, Any]]
    ) -> Dict[str, str]:
        """Get health status for devices."""
        health = {}

        for device in device_details:
            device_id = device['device_id']
            status = device.get('status', 'unknown')

            if status == 'completed':
                health[device_id] = 'healthy'
            elif status == 'failed':
                health[device_id] = 'unhealthy'
            elif status == 'in_progress':
                health[device_id] = 'deploying'
            else:
                health[device_id] = 'unknown'

        return health

    def _determine_phase(self, progress: float) -> str:
        """Determine deployment phase based on progress."""
        if progress == 0:
            return 'initialization'
        elif progress < 25:
            return 'early_deployment'
        elif progress < 50:
            return 'mid_deployment'
        elif progress < 75:
            return 'late_deployment'
        elif progress < 100:
            return 'finalization'
        else:
            return 'completed'

    def _calculate_success_rate(self, status_data: Dict[str, Any]) -> float:
        """Calculate deployment success rate."""
        devices = status_data.get('devices', {})
        successful = devices.get('successful', 0)
        total = devices.get('total', 0)
        return (successful / total) if total > 0 else 0

    def _calculate_error_rate(self, status_data: Dict[str, Any]) -> float:
        """Calculate deployment error rate."""
        devices = status_data.get('devices', {})
        failed = devices.get('failed', 0)
        completed = devices.get('successful', 0) + failed
        return (failed / completed) if completed > 0 else 0

    def _calculate_avg_device_time(self, status_data: Dict[str, Any]) -> float:
        """Calculate average device deployment time."""
        device_details = status_data.get('device_details', [])

        times = []
        for device in device_details:
            if device.get('started_at') and device.get('completed_at'):
                started = datetime.fromisoformat(device['started_at'])
                completed = datetime.fromisoformat(device['completed_at'])
                duration = (completed - started).total_seconds()
                times.append(duration)

        return statistics.mean(times) if times else 0

    async def _get_recent_alerts(
        self,
        deployment_id: str,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get recent alerts for deployment."""
        if deployment_id in self.active_monitors:
            alerts = self.active_monitors[deployment_id].get('alerts', [])
            return alerts[-limit:]
        return []

    async def _get_oncall_users(self) -> List[str]:
        """Get on-call users for critical alerts."""
        # Placeholder - would integrate with on-call schedule
        return ['oncall_user']

    async def _get_deployment_owner(
        self,
        deployment_id: str
    ) -> List[str]:
        """Get deployment owner for notifications."""
        try:
            status = await self._get_deployment_details(deployment_id)
            owner = status.get('created_by')
            return [owner] if owner else []
        except Exception:
            return []

    async def _get_service_token(self) -> str:
        """Get service authentication token."""
        # Placeholder - would get from vault
        return "service_token"

    async def shutdown(self):
        """Shutdown monitor."""
        # Cancel all active monitors
        for deployment_id in list(self.active_monitors.keys()):
            logger.info(f"Stopping monitor for deployment {deployment_id}")
            # Monitoring tasks are cancelled when deployment completes