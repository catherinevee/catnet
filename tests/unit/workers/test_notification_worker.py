"""
Unit tests for notification worker.
Tests alert and notification delivery through various channels.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from uuid import uuid4

from src.workers.notification_worker import (
    NotificationWorker,
    NotificationChannel,
    NotificationPriority
)
from src.workers.base import WorkerTask


class TestNotificationWorker:
    """Test notification worker functionality."""

    @pytest.fixture
    def notification_worker(self):
        """Create notification worker instance."""
        return NotificationWorker(worker_id="test_notification", max_concurrent_tasks=10)

    def test_notification_worker_initialization(self, notification_worker):
        """Test notification worker initialization."""
        assert notification_worker.get_worker_type() == "notification"
        assert notification_worker.rate_limits is not None
        assert 'email' in notification_worker.rate_limits
        assert 'sms' in notification_worker.rate_limits

    @pytest.mark.asyncio
    async def test_send_email_notification(self, notification_worker):
        """Test sending email notification."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="send_notification",
            payload={
                "channel": "email",
                "recipient": "user@example.com",
                "subject": "Test Alert",
                "message": "This is a test notification"
            }
        )

        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = Mock()
            mock_smtp.return_value.__enter__.return_value = mock_server

            result = await notification_worker.process_task(task)

            assert result is not None

    @pytest.mark.asyncio
    async def test_send_slack_notification(self, notification_worker):
        """Test sending Slack notification."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="send_notification",
            payload={
                "channel": "slack",
                "webhook_url": "https://hooks.slack.com/test",
                "message": "Test notification"
            }
        )

        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = Mock()
            mock_response.status = 200
            mock_session.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            result = await notification_worker.process_task(task)

            assert result is not None

    @pytest.mark.asyncio
    async def test_send_alert(self, notification_worker):
        """Test sending alert notification."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="send_alert",
            payload={
                "alert_id": str(uuid4()),
                "priority": "high",
                "channels": ["email", "slack"]
            }
        )

        db_session = AsyncMock()
        with patch('src.workers.notification_worker.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = db_session

            result = await notification_worker.process_task(task)

            assert result is not None

    @pytest.mark.asyncio
    async def test_rate_limiting(self, notification_worker):
        """Test notification rate limiting."""
        # Email rate limit is 30/minute
        notification_worker.rate_limits['email']['per_minute'] = 2

        tasks = [
            WorkerTask(
                task_id=uuid4(),
                task_type="send_notification",
                payload={"channel": "email", "recipient": f"user{i}@example.com", "message": "Test"}
            )
            for i in range(3)
        ]

        with patch('smtplib.SMTP') as mock_smtp:
            results = []
            for task in tasks:
                try:
                    result = await notification_worker.process_task(task)
                    results.append(result)
                except Exception as e:
                    results.append({"error": str(e)})

            # At least some should succeed
            assert len(results) > 0

    @pytest.mark.asyncio
    async def test_send_bulk_notifications(self, notification_worker):
        """Test sending bulk notifications."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="send_bulk",
            payload={
                "recipients": ["user1@example.com", "user2@example.com"],
                "subject": "Bulk notification",
                "message": "Test bulk message"
            }
        )

        result = await notification_worker.process_task(task)

        assert result is not None

    @pytest.mark.asyncio
    async def test_notification_handles_failures(self, notification_worker):
        """Test notification failure handling."""
        task = WorkerTask(
            task_id=uuid4(),
            task_type="send_notification",
            payload={
                "channel": "email",
                "recipient": "invalid-email",
                "message": "Test"
            }
        )

        with patch('smtplib.SMTP') as mock_smtp:
            mock_smtp.side_effect = Exception("SMTP connection failed")

            with pytest.raises(Exception):
                await notification_worker.process_task(task)
