"""
Unit tests for dashboard service.
Tests real-time metrics visualization and monitoring dashboards.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timedelta
from uuid import uuid4

from src.monitoring.dashboard import (
    DashboardType,
    MetricWidget,
    Dashboard,
    DashboardManager,
)
from src.monitoring.metrics import MetricsCollector
from src.core.exceptions import DashboardError


class TestMetricWidget:
    """Test metric widget functionality."""

    def test_widget_initialization(self):
        """Test widget initialization."""
        widget = MetricWidget(
            widget_id="cpu_gauge",
            title="CPU Usage",
            widget_type="gauge",
            metrics=["catnet_system_cpu_usage_percent"],
            refresh_interval=30
        )

        assert widget.widget_id == "cpu_gauge"
        assert widget.title == "CPU Usage"
        assert widget.widget_type == "gauge"
        assert widget.metrics == ["catnet_system_cpu_usage_percent"]
        assert widget.refresh_interval == 30
        assert widget.last_update is None
        assert widget.data == {}

    @pytest.mark.asyncio
    async def test_widget_update(self):
        """Test widget data update."""
        widget = MetricWidget(
            widget_id="test_widget",
            title="Test Widget",
            widget_type="gauge",
            metrics=["test_metric"],
            refresh_interval=60
        )

        # Mock metrics collector
        metrics_collector = Mock(spec=MetricsCollector)
        mock_metric = Mock()
        mock_metric.get.return_value = 42.5
        metrics_collector.metrics = {"test_metric": mock_metric}

        await widget.update(metrics_collector)

        assert "test_metric" in widget.data
        assert widget.data["test_metric"] == 42.5
        assert widget.last_update is not None

    @pytest.mark.asyncio
    async def test_widget_update_with_collect_method(self):
        """Test widget update with metric that has collect method."""
        widget = MetricWidget(
            widget_id="test_widget",
            title="Test Widget",
            widget_type="histogram",
            metrics=["test_histogram"],
            refresh_interval=60
        )

        metrics_collector = Mock(spec=MetricsCollector)
        mock_metric = Mock()
        mock_metric.collect.return_value = {"count": 100, "sum": 5000}
        metrics_collector.metrics = {"test_histogram": mock_metric}

        await widget.update(metrics_collector)

        assert "test_histogram" in widget.data
        assert widget.data["test_histogram"]["count"] == 100

    def test_widget_to_dict(self):
        """Test widget serialization to dictionary."""
        widget = MetricWidget(
            widget_id="test_widget",
            title="Test Widget",
            widget_type="gauge",
            metrics=["test_metric"],
            refresh_interval=60
        )
        widget.data = {"test_metric": 100}
        widget.last_update = datetime(2025, 1, 1, 12, 0, 0)

        result = widget.to_dict()

        assert result["id"] == "test_widget"
        assert result["title"] == "Test Widget"
        assert result["type"] == "gauge"
        assert result["data"] == {"test_metric": 100}
        assert result["refresh_interval"] == 60
        assert "2025-01-01" in result["last_update"]


class TestDashboard:
    """Test dashboard functionality."""

    def test_dashboard_initialization(self):
        """Test dashboard initialization."""
        dashboard = Dashboard(
            dashboard_id="system_dash",
            name="System Dashboard",
            dashboard_type=DashboardType.SYSTEM,
            description="System metrics dashboard"
        )

        assert dashboard.dashboard_id == "system_dash"
        assert dashboard.name == "System Dashboard"
        assert dashboard.dashboard_type == DashboardType.SYSTEM
        assert dashboard.description == "System metrics dashboard"
        assert dashboard.widgets == []
        assert dashboard.layout is None

    def test_add_widget(self):
        """Test adding widget to dashboard."""
        dashboard = Dashboard(
            dashboard_id="test_dash",
            name="Test Dashboard",
            dashboard_type=DashboardType.SYSTEM
        )

        widget = MetricWidget(
            widget_id="widget1",
            title="Widget 1",
            widget_type="gauge",
            metrics=["metric1"]
        )

        dashboard.add_widget(widget)

        assert len(dashboard.widgets) == 1
        assert dashboard.widgets[0] == widget

    def test_remove_widget(self):
        """Test removing widget from dashboard."""
        dashboard = Dashboard(
            dashboard_id="test_dash",
            name="Test Dashboard",
            dashboard_type=DashboardType.SYSTEM
        )

        widget1 = MetricWidget("widget1", "Widget 1", "gauge", ["metric1"])
        widget2 = MetricWidget("widget2", "Widget 2", "gauge", ["metric2"])

        dashboard.add_widget(widget1)
        dashboard.add_widget(widget2)
        dashboard.remove_widget("widget1")

        assert len(dashboard.widgets) == 1
        assert dashboard.widgets[0].widget_id == "widget2"

    def test_get_widget(self):
        """Test getting widget by ID."""
        dashboard = Dashboard(
            dashboard_id="test_dash",
            name="Test Dashboard",
            dashboard_type=DashboardType.SYSTEM
        )

        widget = MetricWidget("widget1", "Widget 1", "gauge", ["metric1"])
        dashboard.add_widget(widget)

        retrieved = dashboard.get_widget("widget1")
        assert retrieved == widget

        # Test non-existent widget
        assert dashboard.get_widget("nonexistent") is None

    @pytest.mark.asyncio
    async def test_update_all_widgets(self):
        """Test updating all widgets in dashboard."""
        dashboard = Dashboard(
            dashboard_id="test_dash",
            name="Test Dashboard",
            dashboard_type=DashboardType.SYSTEM
        )

        widget1 = MetricWidget("widget1", "Widget 1", "gauge", ["metric1"])
        widget2 = MetricWidget("widget2", "Widget 2", "gauge", ["metric2"])
        dashboard.add_widget(widget1)
        dashboard.add_widget(widget2)

        metrics_collector = Mock(spec=MetricsCollector)
        mock_metric1 = Mock()
        mock_metric1.get.return_value = 10
        mock_metric2 = Mock()
        mock_metric2.get.return_value = 20
        metrics_collector.metrics = {
            "metric1": mock_metric1,
            "metric2": mock_metric2
        }

        await dashboard.update(metrics_collector)

        assert widget1.last_update is not None
        assert widget2.last_update is not None

    def test_dashboard_to_dict(self):
        """Test dashboard serialization."""
        dashboard = Dashboard(
            dashboard_id="test_dash",
            name="Test Dashboard",
            dashboard_type=DashboardType.SYSTEM,
            description="Test description"
        )

        widget = MetricWidget("widget1", "Widget 1", "gauge", ["metric1"])
        dashboard.add_widget(widget)

        result = dashboard.to_dict()

        assert result["id"] == "test_dash"
        assert result["name"] == "Test Dashboard"
        assert result["type"] == "system"
        assert result["description"] == "Test description"
        assert len(result["widgets"]) == 1


class TestDashboardManager:
    """Test dashboard manager."""

    @pytest.fixture
    def metrics_collector(self):
        """Create metrics collector mock."""
        return Mock(spec=MetricsCollector)

    @pytest.fixture
    def dashboard_manager(self, metrics_collector):
        """Create dashboard manager."""
        return DashboardManager(metrics_collector)

    def test_manager_initialization(self, dashboard_manager):
        """Test dashboard manager initialization."""
        assert dashboard_manager.metrics is not None
        assert dashboard_manager.dashboards == {}

    def test_register_dashboard(self, dashboard_manager):
        """Test registering a dashboard."""
        dashboard = Dashboard(
            dashboard_id="test_dash",
            name="Test Dashboard",
            dashboard_type=DashboardType.SYSTEM
        )

        dashboard_manager.register_dashboard(dashboard)

        assert "test_dash" in dashboard_manager.dashboards
        assert dashboard_manager.dashboards["test_dash"] == dashboard

    def test_unregister_dashboard(self, dashboard_manager):
        """Test unregistering a dashboard."""
        dashboard = Dashboard(
            dashboard_id="test_dash",
            name="Test Dashboard",
            dashboard_type=DashboardType.SYSTEM
        )

        dashboard_manager.register_dashboard(dashboard)
        dashboard_manager.unregister_dashboard("test_dash")

        assert "test_dash" not in dashboard_manager.dashboards

    def test_get_dashboard(self, dashboard_manager):
        """Test getting dashboard by ID."""
        dashboard = Dashboard(
            dashboard_id="test_dash",
            name="Test Dashboard",
            dashboard_type=DashboardType.SYSTEM
        )

        dashboard_manager.register_dashboard(dashboard)
        retrieved = dashboard_manager.get_dashboard("test_dash")

        assert retrieved == dashboard

    def test_get_dashboard_not_found(self, dashboard_manager):
        """Test getting non-existent dashboard."""
        with pytest.raises(DashboardError, match="Dashboard .* not found"):
            dashboard_manager.get_dashboard("nonexistent")

    def test_list_dashboards(self, dashboard_manager):
        """Test listing all dashboards."""
        dashboard1 = Dashboard("dash1", "Dashboard 1", DashboardType.SYSTEM)
        dashboard2 = Dashboard("dash2", "Dashboard 2", DashboardType.DEVICES)

        dashboard_manager.register_dashboard(dashboard1)
        dashboard_manager.register_dashboard(dashboard2)

        dashboards = dashboard_manager.list_dashboards()

        assert len(dashboards) == 2
        assert dash1 in dashboards or dashboard1 in dashboards

    def test_list_dashboards_by_type(self, dashboard_manager):
        """Test filtering dashboards by type."""
        dashboard1 = Dashboard("dash1", "Dashboard 1", DashboardType.SYSTEM)
        dashboard2 = Dashboard("dash2", "Dashboard 2", DashboardType.DEVICES)
        dashboard3 = Dashboard("dash3", "Dashboard 3", DashboardType.SYSTEM)

        dashboard_manager.register_dashboard(dashboard1)
        dashboard_manager.register_dashboard(dashboard2)
        dashboard_manager.register_dashboard(dashboard3)

        system_dashboards = dashboard_manager.list_dashboards(
            dashboard_type=DashboardType.SYSTEM
        )

        assert len(system_dashboards) == 2

    @pytest.mark.asyncio
    async def test_update_all_dashboards(self, dashboard_manager, metrics_collector):
        """Test updating all dashboards."""
        dashboard = Dashboard("test_dash", "Test", DashboardType.SYSTEM)
        widget = MetricWidget("widget1", "Widget", "gauge", ["metric1"])
        dashboard.add_widget(widget)
        dashboard_manager.register_dashboard(dashboard)

        mock_metric = Mock()
        mock_metric.get.return_value = 100
        metrics_collector.metrics = {"metric1": mock_metric}

        await dashboard_manager.update_all()

        assert widget.last_update is not None

    @pytest.mark.asyncio
    async def test_create_system_dashboard(self, dashboard_manager):
        """Test creating default system dashboard."""
        dashboard = await dashboard_manager.create_system_dashboard()

        assert dashboard.dashboard_type == DashboardType.SYSTEM
        assert len(dashboard.widgets) > 0
        assert dashboard.dashboard_id in dashboard_manager.dashboards

    @pytest.mark.asyncio
    async def test_create_device_dashboard(self, dashboard_manager):
        """Test creating default device dashboard."""
        dashboard = await dashboard_manager.create_device_dashboard()

        assert dashboard.dashboard_type == DashboardType.DEVICES
        assert len(dashboard.widgets) > 0

    @pytest.mark.asyncio
    async def test_create_deployment_dashboard(self, dashboard_manager):
        """Test creating default deployment dashboard."""
        dashboard = await dashboard_manager.create_deployment_dashboard()

        assert dashboard.dashboard_type == DashboardType.DEPLOYMENTS
        assert len(dashboard.widgets) > 0
