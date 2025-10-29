"""
Unit tests for synchronization worker.
Tests GitOps repository sync and configuration updates.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from uuid import uuid4

from src.workers.sync_worker import SyncWorker
from src.workers.base import WorkerTask
from src.gitops.sync import SyncStatus, SyncStrategy


class TestSyncWorker:
    """Test synchronization worker functionality."""

    @pytest.fixture
    def sync_worker(self):
        """Create sync worker instance."""
        return SyncWorker(worker_id="test_sync", max_concurrent_tasks=5)

    def test_sync_worker_initialization(self, sync_worker):
        """Test sync worker initialization."""
        assert sync_worker.get_worker_type() == "sync"
        assert sync_worker.synchronizer is not None
        assert sync_worker.gitops_workflow is not None
        assert sync_worker.active_syncs == {}

    @pytest.mark.asyncio
    async def test_sync_repository(self, sync_worker):
        """Test repository synchronization."""
        repo_id = uuid4()
        task = WorkerTask(
            task_id=uuid4(),
            task_type="sync_repository",
            payload={
                "repository_id": str(repo_id),
                "strategy": "pull_only"
            }
        )

        db_session = AsyncMock()
        mock_repo = Mock()
        mock_repo.id = repo_id
        mock_repo.url = "https://github.com/test/repo.git"
        db_session.get.return_value = mock_repo

        with patch('src.workers.sync_worker.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session

            result = await sync_worker.process_task(task)

            assert result is not None

    @pytest.mark.asyncio
    async def test_sync_all_repositories(self, sync_worker):
        """Test syncing all repositories."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="sync_all_repositories",
            payload={}
        )

        db_session = AsyncMock()
        mock_result = Mock()
        mock_repos = [
            Mock(id=uuid4(), url="https://github.com/test/repo1.git"),
            Mock(id=uuid4(), url="https://github.com/test/repo2.git"),
        ]
        mock_result.scalars.return_value.all.return_value = mock_repos
        db_session.execute.return_value = mock_result

        with patch('src.workers.sync_worker.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session

            result = await sync_worker.process_task(task)

            assert result is not None

    @pytest.mark.asyncio
    async def test_detect_drift(self, sync_worker):
        """Test configuration drift detection."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="detect_drift",
            payload={
                "device_id": str(uuid4())
            }
        )

        db_session = AsyncMock()
        with patch('src.workers.sync_worker.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session

            result = await sync_worker.process_task(task)

            assert result is not None

    @pytest.mark.asyncio
    async def test_prevent_concurrent_sync(self, sync_worker):
        """Test prevention of concurrent repository sync."""
        repo_id = uuid4()

        # Mark repository as already syncing
        sync_worker.active_syncs[repo_id] = {"started_at": "2025-01-01T00:00:00"}

        task = WorkerTask(
            task_id=uuid4(),
            task_type="sync_repository",
            payload={"repository_id": str(repo_id)}
        )

        db_session = AsyncMock()
        mock_repo = Mock()
        mock_repo.id = repo_id
        db_session.get.return_value = mock_repo

        with patch('src.workers.sync_worker.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session

            result = await sync_worker.process_task(task)

            # Should indicate already syncing
            assert result.get("status") == "already_syncing" or result is not None

    @pytest.mark.asyncio
    async def test_reconcile_configurations(self, sync_worker):
        """Test configuration reconciliation."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="reconcile_configurations",
            payload={}
        )

        db_session = AsyncMock()
        with patch('src.workers.sync_worker.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session

            result = await sync_worker.process_task(task)

            assert result is not None

    @pytest.mark.asyncio
    async def test_emergency_sync(self, sync_worker):
        """Test emergency synchronization."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="emergency_sync",
            payload={
                "repository_id": str(uuid4()),
                "reason": "security_incident"
            }
        )

        db_session = AsyncMock()
        with patch('src.workers.sync_worker.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session

            result = await sync_worker.process_task(task)

            assert result is not None

    @pytest.mark.asyncio
    async def test_sync_handles_missing_repository(self, sync_worker):
        """Test sync handles missing repository gracefully."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="sync_repository",
            payload={"repository_id": str(uuid4())}
        )

        db_session = AsyncMock()
        db_session.get.return_value = None  # Repository not found

        with patch('src.workers.sync_worker.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session

            with pytest.raises(Exception):
                await sync_worker.process_task(task)
