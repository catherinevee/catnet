"""
Comprehensive tests for CatNet Deployment Service
"""

import pytest
from datetime import datetime
from unittest.mock import Mock, AsyncMock

from src.deployment.deployment_manager import (
    DeploymentManager,
    Deployment,
    DeploymentConfig,
    DeploymentStrategy,
    DeploymentState,
    DeviceDeployment,
)
from src.deployment.rollback import (
    RollbackManager,
)
from src.deployment.validation import (
    DeploymentValidator,
    ValidationStatus,
)
from src.deployment.health_check import (
    HealthCheckService,
    HealthCheckConfig,
    HealthCheckResult,
    HealthCheckType,
    HealthStatus,
    HealthMetric,
    MetricType,
)
from src.deployment.history import (
    DeploymentHistory,
    HistoryEventType,
)



class TestDeploymentManager:
    """Test deployment manager"""

    def setup_method(self):
        """Setup test environment"""
        self.device_service = Mock()
        self.backup_service = Mock()
        self.health_service = Mock()

        self.manager = DeploymentManager(
            device_service=self.device_service,
            backup_service=self.backup_service,
            health_service=self.health_service,
        )

    @pytest.mark.asyncio
    async def test_create_deployment(self):
        """Test deployment creation"""
        # Setup mocks
        self.manager._get_device_info = AsyncMock(return_value={"hostname": \
            "router1"})

        # Create deployment
        deployment_id = await self.manager.create_deployment(
            name="Test Deployment",
            description="Test deployment description",
            devices=["device1", "device2"],
            configuration=(
                "interface GigabitEthernet0/1\n" " ip address 192.168.1.1 \
                    255.255.255.0"
            ),
            config=DeploymentConfig(strategy=DeploymentStrategy.CANARY),
            created_by="testuser",
        )

        assert deployment_id is not None
        assert deployment_id in self.manager.deployments

        deployment = self.manager.deployments[deployment_id]
        assert deployment.name == "Test Deployment"
        assert len(deployment.devices) == 2
        assert deployment.config.strategy == DeploymentStrategy.CANARY
        assert deployment.state == DeploymentState.PENDING

    @pytest.mark.asyncio
    async def test_execute_canary_deployment(self):
        """Test canary deployment execution"""
        # Create deployment
        deployment = Deployment(
            id="test-dep-1",
            name="Canary Test",
            description="Test canary deployment",
            config=DeploymentConfig(
                strategy=DeploymentStrategy.CANARY,
                canary_percentage=50,
                canary_duration_minutes=0,  # No wait for testing
            ),
            devices=["device1", "device2", "device3", "device4"],
            configuration="test config",
            state=DeploymentState.PENDING,
            created_by="testuser",
            created_at=datetime.utcnow(),
        )

        # Setup device deployments
        for device_id in deployment.devices:
            deployment.device_deployments[device_id] = DeviceDeployment(
                device_id=device_id,
                device_hostname=f"host-{device_id}",
                deployment_id=deployment.id,
                state=DeploymentState.PENDING,
            )

        self.manager.deployments[deployment.id] = deployment

        # Mock methods
        self.manager._pre_flight_checks = AsyncMock(return_value=True)
        self.manager._deploy_to_devices = AsyncMock(return_value=True)
        self.manager._check_deployment_health = AsyncMock(return_value=True)

        # Execute deployment
        success = await self.manager.execute_deployment(deployment.id)

        assert success
        assert deployment.state == DeploymentState.COMPLETED

        # Verify canary deployment was executed
        assert self.manager._deploy_to_devices.call_count == 2  # Canary + \
            remaining

        # Check canary batch size
        first_call_devices = self.manager._deploy_to_devices.call_args_list[0][ \
            0][1]
        assert len(first_call_devices) == 2  # 50% of 4 devices



class TestRollbackManager:
    """Test rollback manager"""

    def setup_method(self):
        """Setup test environment"""
        self.device_service = Mock()
        self.backup_service = Mock()

        self.manager = RollbackManager(
            device_service=self.device_service,
            backup_service=self.backup_service,
        )

    @pytest.mark.asyncio
    async def test_create_rollback_point(self):
        """Test creating rollback point"""
        # Mock backup verification
        self.backup_service.verify_backup = AsyncMock(return_value=True)

        # Create rollback point
        point = await self.manager.create_rollback_point(
            device_id="device1",
            configuration="current config",
            backup_location="/backups/device1/backup1",
            metadata={"deployment_id": "dep1"},
        )

        assert point is not None
        assert point.device_id == "device1"
        assert point.configuration == "current config"
        assert point.verified is True
        assert "device1" in self.manager.rollback_points



class TestDeploymentValidator:
    """Test deployment validator"""

    def setup_method(self):
        """Setup test environment"""
        self.device_service = Mock()
        self.config_validator = Mock()

        self.validator = DeploymentValidator(
            device_service=self.device_service,
            config_validator=self.config_validator,
        )

    @pytest.mark.asyncio
    async def test_validate_deployment(self):
        """Test deployment validation"""
        # Mock device checks
        self.validator._check_device_accessible = AsyncMock(return_value=True)
        self.validator._check_maintenance_window = AsyncMock(return_value=True)
        self.validator._get_device_vendor = AsyncMock(return_value="cisco")
        self.validator._get_device_info = AsyncMock(
            return_value={"model": "ISR4451", "os_version": "16.9.1"}
        )
        self.validator._check_compatibility = AsyncMock(return_value=True)
        self.validator._get_device_resources = AsyncMock(
            return_value={
                "cpu_usage": 50,
                "memory_usage": 60,
                "storage_free_mb": 500,
            }
        )

        # Mock config validation
        mock_validation = Mock()
        mock_validation.is_valid = True
        mock_validation.errors = []
        self.config_validator.validate_configuration = Mock(
            return_value=mock_validation
        )

        # Validate deployment
        result = await self.validator.validate_deployment(
            deployment_id="dep1",
            devices=["device1", "device2"],
            configuration=(
                "interface GigabitEthernet0/1\n" " ip address 192.168.1.1 \
                    255.255.255.0"
            ),
            deployment_config={},
        )

        assert result is not None
        assert result.status == ValidationStatus.PASSED
        assert result.failed_checks == 0
        assert result.total_checks > 0



class TestHealthCheckService:
    """Test health check service"""

    def setup_method(self):
        """Setup test environment"""
        self.device_service = Mock()
        self.service = HealthCheckService(device_service=self.device_service)

    @pytest.mark.asyncio
    async def test_check_device_health(self):
        """Test device health check"""
        # Mock health check methods
        self.service._check_connectivity = AsyncMock(
            return_value=HealthCheckResult(
                check_type=HealthCheckType.CONNECTIVITY,
                status=HealthStatus.HEALTHY,
                timestamp=datetime.utcnow(),
                device_id="device1",
                message="Device is reachable",
            )
        )

        self.service._check_protocols = AsyncMock(
            return_value=HealthCheckResult(
                check_type=HealthCheckType.PROTOCOL,
                status=HealthStatus.HEALTHY,
                timestamp=datetime.utcnow(),
                device_id="device1",
                message="All protocols operational",
            )
        )

        self.service._check_performance = AsyncMock(
            return_value=HealthCheckResult(
                check_type=HealthCheckType.PERFORMANCE,
                status=HealthStatus.HEALTHY,
                timestamp=datetime.utcnow(),
                device_id="device1",
                message="Performance metrics within normal range",
                metrics=[
                    HealthMetric(
                        name="CPU Usage",
                        type=MetricType.CPU_USAGE,
                        value=45.0,
                        threshold_warning=70,
                        threshold_critical=90,
                        unit="%",
                        timestamp=datetime.utcnow(),
                        status=HealthStatus.HEALTHY,
                    )
                ],
            )
        )

        # Run health check
        config = HealthCheckConfig(
            checks=[
                HealthCheckType.CONNECTIVITY,
                HealthCheckType.PROTOCOL,
                HealthCheckType.PERFORMANCE,
            ]
        )

        result = await self.service.check_device_health("device1", config)

        assert result is not None
        assert result.status == HealthStatus.HEALTHY
        assert result.device_id == "device1"
        assert result.duration_ms is not None



class TestDeploymentHistory:
    """Test deployment history tracking"""

    def setup_method(self):
        """Setup test environment"""
        self.history = DeploymentHistory()

    def test_record_event(self):
        """Test recording history event"""
        event_id = self.history.record_event(
            event_type=HistoryEventType.DEPLOYMENT_STARTED,
            deployment_id="dep1",
            user="testuser",
            device_id="device1",
            details={"action": "started"},
        )

        assert event_id is not None
        assert len(self.history.events) == 1

        event = self.history.events[0]
        assert event.event_type == HistoryEventType.DEPLOYMENT_STARTED
        assert event.deployment_id == "dep1"
        assert event.user == "testuser"

    def test_record_deployment_lifecycle(self):
        """Test recording deployment lifecycle"""
        # Record deployment start
        self.history.record_deployment_start(
            deployment_id="dep1",
            name="Test Deployment",
            devices=["device1", "device2"],
            strategy="canary",
            created_by="testuser",
            configuration_size=1024,
        )

        assert "dep1" in self.history.deployment_summaries
        summary = self.history.deployment_summaries["dep1"]
        assert summary.name == "Test Deployment"
        assert summary.devices_total == 2

        # Record completion
        self.history.record_deployment_completion(
            deployment_id="dep1",
            status="completed",
            successful_devices=["device1", "device2"],
            failed_devices=[],
        )

        assert summary.status == "completed"
        assert summary.devices_successful == 2
        assert summary.devices_failed == 0

    def test_get_statistics(self):
        """Test getting deployment statistics"""
        # Create some deployment history
        for i in range(5):
            self.history.record_deployment_start(
                deployment_id=f"dep{i}",
                name=f"Deployment {i}",
                devices=["device1", "device2"],
                strategy="canary" if i % 2 == 0 else "rolling",
                created_by="testuser",
                configuration_size=1024,
            )

            # Complete 4 successfully, 1 failed
            if i < 4:
                self.history.record_deployment_completion(
                    deployment_id=f"dep{i}",
                    status="completed",
                    successful_devices=["device1", "device2"],
                    failed_devices=[],
                )
            else:
                self.history.record_deployment_completion(
                    deployment_id=f"dep{i}",
                    status="failed",
                    successful_devices=["device1"],
                    failed_devices=["device2"],
                )

        # Get statistics
        stats = self.history.get_statistics()

        assert stats["total_deployments"] == 5
        assert stats["successful_deployments"] == 4
        assert stats["failed_deployments"] == 1
        assert stats["success_rate"] == 80.0
        assert stats["total_devices_deployed"] == 10


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
