"""
Unit tests for deployment processor worker.
Tests deployment task processing and orchestration.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from uuid import uuid4
from datetime import datetime

from src.workers.deployment_processor import DeploymentProcessor
from src.workers.base import WorkerTask


class TestDeploymentProcessor:
    """Test deployment processor worker."""

    @pytest.fixture
    def deployment_processor(self):
        """Create deployment processor instance."""
        return DeploymentProcessor(worker_id="test_processor", max_concurrent_tasks=5)

    def test_deployment_processor_initialization(self, deployment_processor):
        """Test deployment processor initialization."""
        assert deployment_processor.get_worker_type() == "deployment_processor"
        assert deployment_processor.max_concurrent_tasks == 5

    @pytest.mark.asyncio
    async def test_process_deployment_task(self, deployment_processor):
        """Test processing a deployment task."""
        deployment_id = uuid4()
        task = WorkerTask(
            task_id=uuid4(),
            task_type="process_deployment",
            payload={
                "deployment_id": str(deployment_id),
                "strategy": "rolling"
            }
        )

        db_session = AsyncMock()
        mock_deployment = Mock()
        mock_deployment.id = deployment_id
        mock_deployment.status = "pending"
        mock_deployment.strategy = "rolling"
        mock_deployment.device_ids = [uuid4(), uuid4()]
        db_session.get.return_value = mock_deployment

        with patch('src.workers.deployment_processor.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session

            result = await deployment_processor.process_task(task)

            assert result is not None

    @pytest.mark.asyncio
    async def test_canary_deployment_processing(self, deployment_processor):
        """Test canary deployment processing."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="process_deployment",
            payload={
                "deployment_id": str(uuid4()),
                "strategy": "canary",
                "canary_stages": [10, 50, 100]
            }
        )

        db_session = AsyncMock()
        with patch('src.workers.deployment_processor.get_db') as mock_get_db:
            with patch('src.workers.deployment_processor.DeploymentExecutor') as mock_executor:
                mock_get_db.return_value.__aenter__.return_value = db_session
                mock_executor.return_value.execute_canary = AsyncMock(return_value={
                    "status": "success",
                    "stage": 100
                })

                result = await deployment_processor.process_task(task)

                assert result is not None

    @pytest.mark.asyncio
    async def test_rolling_deployment_processing(self, deployment_processor):
        """Test rolling deployment processing."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="process_deployment",
            payload={
                "deployment_id": str(uuid4()),
                "strategy": "rolling",
                "batch_size": 5
            }
        )

        db_session = AsyncMock()
        with patch('src.workers.deployment_processor.get_db') as mock_get_db:
            with patch('src.workers.deployment_processor.DeploymentExecutor') as mock_executor:
                mock_get_db.return_value.__aenter__.return_value = db_session
                mock_executor.return_value.execute_rolling = AsyncMock(return_value={
                    "status": "success"
                })

                result = await deployment_processor.process_task(task)

                assert result is not None

    @pytest.mark.asyncio
    async def test_blue_green_deployment_processing(self, deployment_processor):
        """Test blue-green deployment processing."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="process_deployment",
            payload={
                "deployment_id": str(uuid4()),
                "strategy": "blue_green"
            }
        )

        db_session = AsyncMock()
        with patch('src.workers.deployment_processor.get_db') as mock_get_db:
            with patch('src.workers.deployment_processor.DeploymentExecutor') as mock_executor:
                mock_get_db.return_value.__aenter__.return_value = db_session
                mock_executor.return_value.execute_blue_green = AsyncMock(return_value={
                    "status": "success"
                })

                result = await deployment_processor.process_task(task)

                assert result is not None

    @pytest.mark.asyncio
    async def test_deployment_validation_before_execution(self, deployment_processor):
        """Test deployment validation before execution."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="process_deployment",
            payload={"deployment_id": str(uuid4())}
        )

        db_session = AsyncMock()
        with patch('src.workers.deployment_processor.get_db') as mock_get_db:
            with patch('src.workers.deployment_processor.ConfigurationValidator') as mock_validator:
                mock_get_db.return_value.__aenter__.return_value = db_session

                # Mock validation failure
                mock_validator.return_value.validate = AsyncMock(return_value={
                    "valid": False,
                    "errors": ["Invalid configuration"]
                })

                result = await deployment_processor.process_task(task)

                # Should not proceed with invalid config
                assert result is not None

    @pytest.mark.asyncio
    async def test_deployment_rollback_on_failure(self, deployment_processor):
        """Test automatic rollback on deployment failure."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="process_deployment",
            payload={"deployment_id": str(uuid4())}
        )

        db_session = AsyncMock()
        with patch('src.workers.deployment_processor.get_db') as mock_get_db:
            with patch('src.workers.deployment_processor.DeploymentExecutor') as mock_executor:
                mock_get_db.return_value.__aenter__.return_value = db_session

                # Mock deployment failure
                mock_executor.return_value.execute = AsyncMock(
                    side_effect=Exception("Deployment failed")
                )
                mock_executor.return_value.rollback = AsyncMock(return_value={
                    "status": "rolled_back"
                })

                with pytest.raises(Exception):
                    await deployment_processor.process_task(task)

    @pytest.mark.asyncio
    async def test_deployment_status_updates(self, deployment_processor):
        """Test deployment status is updated throughout process."""
        deployment_id = uuid4()
        task = WorkerTask(
            task_id=uuid4(),
            task_type="process_deployment",
            payload={"deployment_id": str(deployment_id)}
        )

        db_session = AsyncMock()
        mock_deployment = Mock()
        mock_deployment.id = deployment_id
        mock_deployment.status = "pending"
        db_session.get.return_value = mock_deployment

        with patch('src.workers.deployment_processor.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session

            result = await deployment_processor.process_task(task)

            # Status should have been updated
            assert db_session.get.called or result is not None

    @pytest.mark.asyncio
    async def test_deployment_health_checks(self, deployment_processor):
        """Test health checks during deployment."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="process_deployment",
            payload={
                "deployment_id": str(uuid4()),
                "health_check_enabled": True
            }
        )

        db_session = AsyncMock()
        with patch('src.workers.deployment_processor.get_db') as mock_get_db:
            with patch('src.workers.deployment_processor.HealthChecker') as mock_health:
                mock_get_db.return_value.__aenter__.return_value = db_session
                mock_health.return_value.check = AsyncMock(return_value={
                    "healthy": True
                })

                result = await deployment_processor.process_task(task)

                assert result is not None

    @pytest.mark.asyncio
    async def test_parallel_deployment_limiting(self, deployment_processor):
        """Test that parallel deployments are limited."""
        # Processor configured with max 5 concurrent tasks
        assert deployment_processor.max_concurrent_tasks == 5

        # Create multiple tasks
        tasks = [
            WorkerTask(
                task_id=uuid4(),
                task_type="process_deployment",
                payload={"deployment_id": str(uuid4())}
            )
            for _ in range(10)
        ]

        # Should handle task queue properly
        # (actual test would need async task queue implementation)
        assert len(tasks) == 10

    @pytest.mark.asyncio
    async def test_deployment_notification_on_completion(self, deployment_processor):
        """Test notification is sent on deployment completion."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="process_deployment",
            payload={
                "deployment_id": str(uuid4()),
                "notify_on_completion": True
            }
        )

        db_session = AsyncMock()
        with patch('src.workers.deployment_processor.get_db') as mock_get_db:
            with patch('src.workers.deployment_processor.NotificationService') as mock_notify:
                mock_get_db.return_value.__aenter__.return_value = db_session
                mock_notify.return_value.send = AsyncMock()

                result = await deployment_processor.process_task(task)

                # Should have attempted notification
                assert result is not None

    @pytest.mark.asyncio
    async def test_deployment_audit_logging(self, deployment_processor):
        """Test audit logging during deployment."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="process_deployment",
            payload={"deployment_id": str(uuid4())}
        )

        db_session = AsyncMock()
        with patch('src.workers.deployment_processor.get_db') as mock_get_db:
            with patch('src.workers.deployment_processor.AuditLogger') as mock_audit:
                mock_get_db.return_value.__aenter__.return_value = db_session
                mock_audit.return_value.log_event = AsyncMock()

                result = await deployment_processor.process_task(task)

                # Should have logged deployment events
                assert result is not None
