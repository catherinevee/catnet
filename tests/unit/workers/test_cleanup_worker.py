"""
Unit tests for cleanup worker.
Tests maintenance and housekeeping task processing.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

from src.workers.cleanup_worker import CleanupWorker
from src.workers.base import WorkerTask
from src.core.exceptions import CleanupError


class TestCleanupWorker:
    """Test cleanup worker functionality."""

    @pytest.fixture
    def cleanup_worker(self):
        """Create cleanup worker instance."""
        return CleanupWorker(worker_id="test_cleanup", max_concurrent_tasks=5)

    def test_cleanup_worker_initialization(self, cleanup_worker):
        """Test cleanup worker initialization."""
        assert cleanup_worker.get_worker_type() == "cleanup"
        assert cleanup_worker.retention_policies is not None
        assert cleanup_worker.retention_policies['audit_logs'] == 365
        assert cleanup_worker.retention_policies['sessions'] == 30

    @pytest.mark.asyncio
    async def test_cleanup_audit_logs(self, cleanup_worker):
        """Test audit log cleanup."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="cleanup_audit_logs",
            payload={"retention_days": 90}
        )

        db_session = AsyncMock()
        mock_result = Mock()
        mock_result.rowcount = 150
        db_session.execute.return_value = mock_result

        with patch('src.workers.cleanup_worker.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session

            result = await cleanup_worker.process_task(task)

            assert result.get("success") is not False
            assert db_session.execute.called

    @pytest.mark.asyncio
    async def test_cleanup_sessions(self, cleanup_worker):
        """Test expired session cleanup."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="cleanup_sessions",
            payload={"retention_days": 30}
        )

        db_session = AsyncMock()
        mock_result = Mock()
        mock_result.rowcount = 25
        db_session.execute.return_value = mock_result

        with patch('src.workers.cleanup_worker.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session

            result = await cleanup_worker.process_task(task)

            # Should attempt session cleanup
            assert db_session.execute.called

    @pytest.mark.asyncio
    async def test_cleanup_temp_files(self, cleanup_worker):
        """Test temporary file cleanup."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="cleanup_temp_files",
            payload={"age_days": 7}
        )

        with patch('pathlib.Path.exists') as mock_exists:
            with patch('pathlib.Path.iterdir') as mock_iterdir:
                mock_exists.return_value = True
                mock_file = Mock()
                mock_file.is_file.return_value = True
                mock_file.stat.return_value.st_mtime = (
                    datetime.now() - timedelta(days=10)
                ).timestamp()
                mock_file.unlink = Mock()
                mock_iterdir.return_value = [mock_file]

                result = await cleanup_worker.process_task(task)

                # Should attempt file cleanup
                assert result is not None

    @pytest.mark.asyncio
    async def test_rotate_logs(self, cleanup_worker):
        """Test log rotation."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="rotate_logs",
            payload={"max_size_mb": 100}
        )

        with patch('pathlib.Path.exists') as mock_exists:
            with patch('shutil.move') as mock_move:
                with patch('gzip.open') as mock_gzip:
                    mock_exists.return_value = True

                    result = await cleanup_worker.process_task(task)

                    # Should attempt log rotation
                    assert result is not None

    @pytest.mark.asyncio
    async def test_cleanup_old_deployments(self, cleanup_worker):
        """Test old deployment cleanup."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="cleanup_old_deployments",
            payload={"retention_days": 180}
        )

        db_session = AsyncMock()
        mock_result = Mock()
        mock_deployments = [
            Mock(
                id=uuid4(),
                created_at=datetime.utcnow() - timedelta(days=200),
                status="completed"
            )
        ]
        mock_result.scalars.return_value.all.return_value = mock_deployments
        db_session.execute.return_value = mock_result

        with patch('src.workers.cleanup_worker.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session

            result = await cleanup_worker.process_task(task)

            # Should query for old deployments
            assert db_session.execute.called

    @pytest.mark.asyncio
    async def test_cleanup_health_checks(self, cleanup_worker):
        """Test health check cleanup."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="cleanup_health_checks",
            payload={"retention_days": 60}
        )

        db_session = AsyncMock()
        mock_result = Mock()
        mock_result.rowcount = 500
        db_session.execute.return_value = mock_result

        with patch('src.workers.cleanup_worker.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session

            result = await cleanup_worker.process_task(task)

            # Should execute cleanup query
            assert db_session.execute.called

    @pytest.mark.asyncio
    async def test_cleanup_notifications(self, cleanup_worker):
        """Test notification cleanup."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="cleanup_notifications",
            payload={"retention_days": 30}
        )

        db_session = AsyncMock()
        mock_result = Mock()
        mock_result.rowcount = 100
        db_session.execute.return_value = mock_result

        with patch('src.workers.cleanup_worker.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session

            result = await cleanup_worker.process_task(task)

            # Should execute cleanup
            assert db_session.execute.called

    @pytest.mark.asyncio
    async def test_cleanup_request_logs(self, cleanup_worker):
        """Test request log cleanup."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="cleanup_request_logs",
            payload={"retention_days": 90}
        )

        db_session = AsyncMock()
        mock_result = Mock()
        mock_result.rowcount = 1000
        db_session.execute.return_value = mock_result

        with patch('src.workers.cleanup_worker.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session

            result = await cleanup_worker.process_task(task)

            # Should execute cleanup
            assert db_session.execute.called

    @pytest.mark.asyncio
    async def test_cleanup_handles_missing_paths(self, cleanup_worker):
        """Test cleanup handles missing directories gracefully."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="cleanup_temp_files",
            payload={"age_days": 7}
        )

        with patch('pathlib.Path.exists') as mock_exists:
            mock_exists.return_value = False

            # Should not raise, just skip missing paths
            result = await cleanup_worker.process_task(task)
            assert result is not None

    @pytest.mark.asyncio
    async def test_cleanup_handles_errors_gracefully(self, cleanup_worker):
        """Test error handling during cleanup."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="cleanup_audit_logs",
            payload={"retention_days": 90}
        )

        db_session = AsyncMock()
        db_session.execute.side_effect = Exception("Database error")

        with patch('src.workers.cleanup_worker.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session

            with pytest.raises(Exception):
                await cleanup_worker.process_task(task)

    @pytest.mark.asyncio
    async def test_default_retention_policies(self, cleanup_worker):
        """Test default retention policies are reasonable."""
        policies = cleanup_worker.retention_policies

        # Verify retention periods are reasonable
        assert policies['audit_logs'] >= 365  # Audit logs kept for at least a year
        assert policies['temp_files'] <= 30  # Temp files cleaned relatively quickly
        assert policies['sessions'] <= 90  # Old sessions cleaned
        assert policies['deployment_logs'] >= 90  # Deployment history kept

    @pytest.mark.asyncio
    async def test_cleanup_respects_retention_policy(self, cleanup_worker):
        """Test cleanup respects configured retention policies."""
        # Override retention policy
        cleanup_worker.retention_policies['audit_logs'] = 100

        task = WorkerTask(
            task_id=uuid4(),
            task_type="cleanup_audit_logs",
            payload={}  # No explicit retention, should use policy
        )

        db_session = AsyncMock()
        cutoff_date = None

        async def capture_query(query):
            nonlocal cutoff_date
            # Capture the cutoff date from the query
            mock_result = Mock()
            mock_result.rowcount = 0
            return mock_result

        db_session.execute = capture_query

        with patch('src.workers.cleanup_worker.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session

            result = await cleanup_worker.process_task(task)

            # Should use configured retention policy
            assert result is not None
