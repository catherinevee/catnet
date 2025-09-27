"""
Dashboard service for CatNet monitoring.
Provides real-time metrics visualization and monitoring dashboards.
"""

import asyncio
import json
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from enum import Enum

from src.monitoring.metrics import MetricsCollector
from src.core.config import get_settings
from src.security.audit import AuditLogger
from src.core.exceptions import DashboardError


class DashboardType(Enum):
    """Dashboard type enumeration."""
    SYSTEM = "system"
    DEVICES = "devices"
    DEPLOYMENTS = "deployments"
    SECURITY = "security"
    OPERATIONS = "operations"
    EXECUTIVE = "executive"


class MetricWidget:
    """
    Base widget for dashboard metrics.
    """

    def __init__(
        self,
        widget_id: str,
        title: str,
        widget_type: str,
        metrics: List[str],
        refresh_interval: int = 60
    ):
        """
        Initialize metric widget.

        Args:
            widget_id: Unique widget identifier
            title: Widget title
            widget_type: Type of widget (gauge, chart, table, etc.)
            metrics: List of metric names to display
            refresh_interval: Refresh interval in seconds
        """
        self.widget_id = widget_id
        self.title = title
        self.widget_type = widget_type
        self.metrics = metrics
        self.refresh_interval = refresh_interval
        self.last_update = None
        self.data = {}

    async def update(self, metrics_collector: MetricsCollector):
        """Update widget data from metrics."""
        self.data = {}
        for metric_name in self.metrics:
            if metric_name in metrics_collector.metrics:
                metric = metrics_collector.metrics[metric_name]
                if hasattr(metric, 'collect'):
                    self.data[metric_name] = metric.collect()
                elif hasattr(metric, 'get'):
                    self.data[metric_name] = metric.get()

        self.last_update = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        """Convert widget to dictionary."""
        return {
            'id': self.widget_id,
            'title': self.title,
            'type': self.widget_type,
            'data': self.data,
            'last_update': self.last_update.isoformat() if self.last_update else None,
            'refresh_interval': self.refresh_interval
        }


class MetricsDashboard:
    """
    Dashboard containing multiple widgets.
    """

    def __init__(
        self,
        dashboard_id: str,
        name: str,
        dashboard_type: DashboardType,
        description: str = ""
    ):
        """
        Initialize metrics dashboard.

        Args:
            dashboard_id: Unique dashboard identifier
            name: Dashboard name
            dashboard_type: Type of dashboard
            description: Dashboard description
        """
        self.dashboard_id = dashboard_id
        self.name = name
        self.dashboard_type = dashboard_type
        self.description = description
        self.widgets: List[MetricWidget] = []
        self.created_at = datetime.utcnow()
        self.updated_at = None

    def add_widget(self, widget: MetricWidget):
        """Add widget to dashboard."""
        self.widgets.append(widget)

    def remove_widget(self, widget_id: str):
        """Remove widget from dashboard."""
        self.widgets = [w for w in self.widgets if w.widget_id != widget_id]

    async def update_all_widgets(self, metrics_collector: MetricsCollector):
        """Update all widgets in dashboard."""
        tasks = [widget.update(metrics_collector) for widget in self.widgets]
        await asyncio.gather(*tasks)
        self.updated_at = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        """Convert dashboard to dictionary."""
        return {
            'id': self.dashboard_id,
            'name': self.name,
            'type': self.dashboard_type.value,
            'description': self.description,
            'widgets': [w.to_dict() for w in self.widgets],
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class DashboardService:
    """
    Service for managing and serving dashboards.
    """

    def __init__(self, metrics_collector: MetricsCollector):
        """
        Initialize dashboard service.

        Args:
            metrics_collector: Metrics collector instance
        """
        self.metrics_collector = metrics_collector
        self.dashboards: Dict[str, MetricsDashboard] = {}
        self.audit = AuditLogger()
        self.settings = get_settings()

        # Create default dashboards
        self._create_default_dashboards()

    def _create_default_dashboards(self):
        """Create default system dashboards."""
        # System Dashboard
        system_dashboard = MetricsDashboard(
            "system",
            "System Overview",
            DashboardType.SYSTEM,
            "Real-time system metrics and health"
        )

        # CPU Widget
        cpu_widget = MetricWidget(
            "cpu_usage",
            "CPU Usage",
            "gauge",
            ["catnet_system_cpu_usage_percent"],
            refresh_interval=10
        )
        system_dashboard.add_widget(cpu_widget)

        # Memory Widget
        memory_widget = MetricWidget(
            "memory_usage",
            "Memory Usage",
            "gauge",
            ["catnet_system_memory_usage_percent"],
            refresh_interval=10
        )
        system_dashboard.add_widget(memory_widget)

        # Disk Usage Widget
        disk_widget = MetricWidget(
            "disk_usage",
            "Disk Usage",
            "multi_gauge",
            ["catnet_system_disk_usage_percent"],
            refresh_interval=60
        )
        system_dashboard.add_widget(disk_widget)

        # Network I/O Widget
        network_widget = MetricWidget(
            "network_io",
            "Network I/O",
            "line_chart",
            [
                "catnet_system_network_bytes_sent_total",
                "catnet_system_network_bytes_recv_total"
            ],
            refresh_interval=5
        )
        system_dashboard.add_widget(network_widget)

        # System Load Widget
        load_widget = MetricWidget(
            "system_load",
            "System Load",
            "line_chart",
            [
                "catnet_system_load_1min",
                "catnet_system_load_5min",
                "catnet_system_load_15min"
            ],
            refresh_interval=30
        )
        system_dashboard.add_widget(load_widget)

        self.dashboards["system"] = system_dashboard

        # Devices Dashboard
        devices_dashboard = MetricsDashboard(
            "devices",
            "Network Devices",
            DashboardType.DEVICES,
            "Device health and connectivity monitoring"
        )

        # Device Count Widget
        device_count_widget = MetricWidget(
            "device_count",
            "Total Devices",
            "number",
            ["catnet_devices_total"],
            refresh_interval=60
        )
        devices_dashboard.add_widget(device_count_widget)

        # Device Health Widget
        device_health_widget = MetricWidget(
            "device_health",
            "Device Health Status",
            "pie_chart",
            ["catnet_devices_by_health"],
            refresh_interval=60
        )
        devices_dashboard.add_widget(device_health_widget)

        # Device by Vendor Widget
        vendor_widget = MetricWidget(
            "devices_by_vendor",
            "Devices by Vendor",
            "bar_chart",
            ["catnet_devices_by_vendor"],
            refresh_interval=300
        )
        devices_dashboard.add_widget(vendor_widget)

        # Critical Devices Widget
        critical_widget = MetricWidget(
            "critical_devices",
            "Critical Devices",
            "number",
            ["catnet_critical_devices_total"],
            refresh_interval=60
        )
        devices_dashboard.add_widget(critical_widget)

        # Health Checks Widget
        health_checks_widget = MetricWidget(
            "health_checks",
            "Recent Health Checks",
            "number",
            ["catnet_health_checks_last_hour"],
            refresh_interval=60
        )
        devices_dashboard.add_widget(health_checks_widget)

        self.dashboards["devices"] = devices_dashboard

        # Deployments Dashboard
        deployments_dashboard = MetricsDashboard(
            "deployments",
            "Deployment Operations",
            DashboardType.DEPLOYMENTS,
            "Deployment status and performance metrics"
        )

        # Active Deployments Widget
        active_deployments_widget = MetricWidget(
            "active_deployments",
            "Active Deployments",
            "number",
            ["catnet_active_deployments"],
            refresh_interval=10
        )
        deployments_dashboard.add_widget(active_deployments_widget)

        # Deployment Success Rate Widget
        success_rate_widget = MetricWidget(
            "deployment_success_rate",
            "24h Success Rate",
            "percentage",
            ["catnet_deployment_success_rate_percent"],
            refresh_interval=60
        )
        deployments_dashboard.add_widget(success_rate_widget)

        # Deployments by State Widget
        state_widget = MetricWidget(
            "deployments_by_state",
            "Deployments by State",
            "stacked_bar",
            ["catnet_deployments_by_state"],
            refresh_interval=30
        )
        deployments_dashboard.add_widget(state_widget)

        # Deployment Duration Widget
        duration_widget = MetricWidget(
            "deployment_duration",
            "Deployment Duration",
            "histogram",
            ["catnet_deployment_duration_seconds"],
            refresh_interval=60
        )
        deployments_dashboard.add_widget(duration_widget)

        # Rollback Count Widget
        rollback_widget = MetricWidget(
            "rollbacks",
            "Total Rollbacks",
            "number",
            ["catnet_deployment_rollbacks_total"],
            refresh_interval=300
        )
        deployments_dashboard.add_widget(rollback_widget)

        self.dashboards["deployments"] = deployments_dashboard

        # Security Dashboard
        security_dashboard = MetricsDashboard(
            "security",
            "Security Monitoring",
            DashboardType.SECURITY,
            "Security events and authentication metrics"
        )

        # Active Sessions Widget
        sessions_widget = MetricWidget(
            "active_sessions",
            "Active Sessions",
            "number",
            ["catnet_active_sessions"],
            refresh_interval=30
        )
        security_dashboard.add_widget(sessions_widget)

        # Auth Attempts Widget
        auth_widget = MetricWidget(
            "auth_attempts",
            "Authentication Attempts",
            "stacked_line",
            ["catnet_auth_attempts_last_hour"],
            refresh_interval=60
        )
        security_dashboard.add_widget(auth_widget)

        # MFA Users Widget
        mfa_widget = MetricWidget(
            "mfa_users",
            "MFA Enabled Users",
            "number",
            ["catnet_users_mfa_enabled"],
            refresh_interval=300
        )
        security_dashboard.add_widget(mfa_widget)

        # Security Violations Widget
        violations_widget = MetricWidget(
            "security_violations",
            "Security Violations",
            "area_chart",
            ["catnet_security_violations_last_hour"],
            refresh_interval=60
        )
        security_dashboard.add_widget(violations_widget)

        # Suspicious Activity Widget
        suspicious_widget = MetricWidget(
            "suspicious_activity",
            "Suspicious Users",
            "number",
            ["catnet_users_with_suspicious_activity"],
            refresh_interval=60
        )
        security_dashboard.add_widget(suspicious_widget)

        self.dashboards["security"] = security_dashboard

        # Operations Dashboard
        operations_dashboard = MetricsDashboard(
            "operations",
            "Operations Overview",
            DashboardType.OPERATIONS,
            "Operational metrics and performance indicators"
        )

        # Request Rate Widget
        request_rate_widget = MetricWidget(
            "request_rate",
            "Request Rate",
            "line_chart",
            ["catnet_requests_total"],
            refresh_interval=5
        )
        operations_dashboard.add_widget(request_rate_widget)

        # Request Latency Widget
        latency_widget = MetricWidget(
            "request_latency",
            "Request Latency",
            "histogram",
            ["catnet_request_duration_seconds"],
            refresh_interval=10
        )
        operations_dashboard.add_widget(latency_widget)

        # Database Connections Widget
        db_widget = MetricWidget(
            "database_connections",
            "Database Pool",
            "stacked_area",
            [
                "catnet_db_pool_size",
                "catnet_db_pool_available",
                "catnet_db_pool_in_use"
            ],
            refresh_interval=30
        )
        operations_dashboard.add_widget(db_widget)

        # Redis Metrics Widget
        redis_widget = MetricWidget(
            "redis_metrics",
            "Redis Memory",
            "line_chart",
            [
                "catnet_redis_memory_used_bytes",
                "catnet_redis_memory_peak_bytes"
            ],
            refresh_interval=60
        )
        operations_dashboard.add_widget(redis_widget)

        # Worker Queue Widget
        queue_widget = MetricWidget(
            "worker_queues",
            "Worker Queue Sizes",
            "bar_chart",
            ["catnet_deployment_queue_size"],
            refresh_interval=30
        )
        operations_dashboard.add_widget(queue_widget)

        self.dashboards["operations"] = operations_dashboard

        # Executive Dashboard
        executive_dashboard = MetricsDashboard(
            "executive",
            "Executive Summary",
            DashboardType.EXECUTIVE,
            "High-level KPIs and business metrics"
        )

        # Total Devices KPI
        devices_kpi = MetricWidget(
            "total_devices_kpi",
            "Total Managed Devices",
            "kpi",
            ["catnet_devices_total"],
            refresh_interval=300
        )
        executive_dashboard.add_widget(devices_kpi)

        # Deployment Success KPI
        deployment_kpi = MetricWidget(
            "deployment_success_kpi",
            "Deployment Success Rate",
            "kpi",
            ["catnet_deployment_success_rate_percent"],
            refresh_interval=300
        )
        executive_dashboard.add_widget(deployment_kpi)

        # System Uptime KPI
        uptime_kpi = MetricWidget(
            "system_uptime_kpi",
            "System Uptime",
            "kpi",
            ["catnet_system_uptime_seconds"],
            refresh_interval=300
        )
        executive_dashboard.add_widget(uptime_kpi)

        # Security Score KPI
        security_kpi = MetricWidget(
            "security_score_kpi",
            "Security Score",
            "kpi",
            ["catnet_users_mfa_enabled", "catnet_security_violations_last_hour"],
            refresh_interval=300
        )
        executive_dashboard.add_widget(security_kpi)

        # Operational Efficiency KPI
        efficiency_kpi = MetricWidget(
            "operational_efficiency_kpi",
            "Operational Efficiency",
            "kpi",
            ["catnet_deployment_avg_duration_seconds", "catnet_deployment_rollbacks_total"],
            refresh_interval=300
        )
        executive_dashboard.add_widget(efficiency_kpi)

        self.dashboards["executive"] = executive_dashboard

    async def get_dashboard(
        self,
        dashboard_id: str,
        refresh: bool = True
    ) -> Optional[Dict[str, Any]]:
        """
        Get dashboard by ID.

        Args:
            dashboard_id: Dashboard ID
            refresh: Whether to refresh widget data

        Returns:
            Dashboard data or None
        """
        if dashboard_id not in self.dashboards:
            return None

        dashboard = self.dashboards[dashboard_id]

        if refresh:
            await dashboard.update_all_widgets(self.metrics_collector)

        return dashboard.to_dict()

    async def get_all_dashboards(self) -> List[Dict[str, Any]]:
        """Get list of all dashboards."""
        return [
            {
                'id': dashboard.dashboard_id,
                'name': dashboard.name,
                'type': dashboard.dashboard_type.value,
                'description': dashboard.description,
                'widget_count': len(dashboard.widgets)
            }
            for dashboard in self.dashboards.values()
        ]

    async def create_custom_dashboard(
        self,
        name: str,
        dashboard_type: DashboardType,
        description: str = "",
        widgets: List[Dict[str, Any]] = None
    ) -> str:
        """
        Create custom dashboard.

        Args:
            name: Dashboard name
            dashboard_type: Type of dashboard
            description: Dashboard description
            widgets: List of widget configurations

        Returns:
            Dashboard ID
        """
        import uuid

        dashboard_id = str(uuid.uuid4())
        dashboard = MetricsDashboard(
            dashboard_id,
            name,
            dashboard_type,
            description
        )

        if widgets:
            for widget_config in widgets:
                widget = MetricWidget(
                    widget_config.get('id', str(uuid.uuid4())),
                    widget_config.get('title', 'Untitled'),
                    widget_config.get('type', 'number'),
                    widget_config.get('metrics', []),
                    widget_config.get('refresh_interval', 60)
                )
                dashboard.add_widget(widget)

        self.dashboards[dashboard_id] = dashboard

        await self.audit.log_event(
            event_type="DASHBOARD_CREATED",
            details={
                'dashboard_id': dashboard_id,
                'name': name,
                'type': dashboard_type.value
            }
        )

        return dashboard_id

    async def delete_dashboard(self, dashboard_id: str) -> bool:
        """
        Delete dashboard.

        Args:
            dashboard_id: Dashboard ID

        Returns:
            True if deleted successfully
        """
        if dashboard_id in ['system', 'devices', 'deployments', 'security', 'operations', 'executive']:
            raise DashboardError("Cannot delete default dashboard")

        if dashboard_id in self.dashboards:
            del self.dashboards[dashboard_id]

            await self.audit.log_event(
                event_type="DASHBOARD_DELETED",
                details={'dashboard_id': dashboard_id}
            )

            return True

        return False

    async def export_dashboard(self, dashboard_id: str) -> Optional[str]:
        """
        Export dashboard configuration as JSON.

        Args:
            dashboard_id: Dashboard ID

        Returns:
            JSON string or None
        """
        if dashboard_id not in self.dashboards:
            return None

        dashboard = self.dashboards[dashboard_id]
        return json.dumps(dashboard.to_dict(), indent=2, default=str)

    async def import_dashboard(self, dashboard_json: str) -> str:
        """
        Import dashboard from JSON.

        Args:
            dashboard_json: Dashboard JSON configuration

        Returns:
            Dashboard ID
        """
        try:
            data = json.loads(dashboard_json)

            dashboard_type = DashboardType(data.get('type', 'operations'))
            dashboard = MetricsDashboard(
                data.get('id', str(uuid.uuid4())),
                data.get('name', 'Imported Dashboard'),
                dashboard_type,
                data.get('description', '')
            )

            for widget_data in data.get('widgets', []):
                widget = MetricWidget(
                    widget_data.get('id'),
                    widget_data.get('title'),
                    widget_data.get('type'),
                    widget_data.get('metrics', []),
                    widget_data.get('refresh_interval', 60)
                )
                dashboard.add_widget(widget)

            self.dashboards[dashboard.dashboard_id] = dashboard

            await self.audit.log_event(
                event_type="DASHBOARD_IMPORTED",
                details={
                    'dashboard_id': dashboard.dashboard_id,
                    'name': dashboard.name
                }
            )

            return dashboard.dashboard_id

        except Exception as e:
            raise DashboardError(f"Failed to import dashboard: {e}")

    async def get_widget_data(
        self,
        dashboard_id: str,
        widget_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get data for specific widget.

        Args:
            dashboard_id: Dashboard ID
            widget_id: Widget ID

        Returns:
            Widget data or None
        """
        if dashboard_id not in self.dashboards:
            return None

        dashboard = self.dashboards[dashboard_id]
        for widget in dashboard.widgets:
            if widget.widget_id == widget_id:
                await widget.update(self.metrics_collector)
                return widget.to_dict()

        return None

    async def get_dashboard_snapshot(
        self,
        dashboard_id: str,
        time_range: Optional[Tuple[datetime, datetime]] = None
    ) -> Dict[str, Any]:
        """
        Get dashboard snapshot with historical data.

        Args:
            dashboard_id: Dashboard ID
            time_range: Optional time range for historical data

        Returns:
            Dashboard snapshot
        """
        if dashboard_id not in self.dashboards:
            raise DashboardError(f"Dashboard {dashboard_id} not found")

        dashboard = self.dashboards[dashboard_id]
        await dashboard.update_all_widgets(self.metrics_collector)

        snapshot = dashboard.to_dict()
        snapshot['snapshot_time'] = datetime.utcnow().isoformat()

        if time_range:
            # Would query time-series database for historical data
            # Simplified for now
            snapshot['time_range'] = {
                'start': time_range[0].isoformat(),
                'end': time_range[1].isoformat()
            }

        return snapshot


# Export main components
__all__ = [
    'DashboardService',
    'MetricsDashboard',
    'MetricWidget',
    'DashboardType'
]