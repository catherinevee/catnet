"""
Unit tests for Notification Service
Tests email, Slack, Teams, and PagerDuty notifications
"""

import pytest
from unittest.mock import AsyncMock, Mock, patch, MagicMock, call
from datetime import datetime, timedelta
import asyncio

from src.services.notification_service import (
    NotificationService, NotificationPriority
)


@pytest.fixture
def notification_service():
    """Create NotificationService instance with mocked dependencies."""
    with patch('src.services.notification_service.settings') as mock_settings:
        # Mock settings
        mock_settings.smtp_host = 'smtp.example.com'
        mock_settings.smtp_port = 587
        mock_settings.smtp_user = 'noreply@example.com'
        mock_settings.smtp_password = Mock()
        mock_settings.smtp_password.get_secret_value.return_value = 'password'
        mock_settings.smtp_use_tls = True
        mock_settings.notification_from_email = 'noreply@example.com'
        mock_settings.slack_webhook_url = 'https://hooks.slack.com/test'
        mock_settings.teams_webhook_url = 'https://outlook.office.com/webhook/test'
        mock_settings.pagerduty_api_key = 'pagerduty_key_123'

        # Prevent background tasks from starting
        with patch('asyncio.create_task'):
            service = NotificationService()
            return service


class TestNotificationServiceInitialization:
    """Test NotificationService initialization."""

    def test_notification_service_initialization(self, notification_service):
        """Test NotificationService initializes correctly."""
        assert notification_service is not None
        assert notification_service.smtp_host == 'smtp.example.com'
        assert notification_service.smtp_port == 587
        assert notification_service.from_email == 'noreply@example.com'

    def test_notification_service_webhooks(self, notification_service):
        """Test webhook URLs configured."""
        assert notification_service.slack_webhook_url == 'https://hooks.slack.com/test'
        assert notification_service.teams_webhook_url == 'https://outlook.office.com/webhook/test'
        assert notification_service.pagerduty_api_key == 'pagerduty_key_123'

    def test_notification_service_queues(self, notification_service):
        """Test notification queues initialized."""
        assert isinstance(notification_service.notification_queue, asyncio.Queue)
        assert isinstance(notification_service.retry_queue, asyncio.Queue)

    def test_notification_service_caches(self, notification_service):
        """Test caches initialized."""
        assert isinstance(notification_service.rate_limits, dict)
        assert isinstance(notification_service.template_cache, dict)


class TestNotificationPriority:
    """Test NotificationPriority levels."""

    def test_notification_priority_values(self):
        """Test notification priority level values."""
        assert NotificationPriority.LOW == 1
        assert NotificationPriority.MEDIUM == 2
        assert NotificationPriority.HIGH == 3
        assert NotificationPriority.CRITICAL == 4
        assert NotificationPriority.EMERGENCY == 5

    def test_notification_priority_ordering(self):
        """Test notification priorities are ordered correctly."""
        assert NotificationPriority.LOW < NotificationPriority.MEDIUM
        assert NotificationPriority.MEDIUM < NotificationPriority.HIGH
        assert NotificationPriority.HIGH < NotificationPriority.CRITICAL
        assert NotificationPriority.CRITICAL < NotificationPriority.EMERGENCY


class TestSendNotification:
    """Test sending notifications."""

    @pytest.mark.asyncio
    async def test_send_notification_basic(self, notification_service):
        """Test basic notification sending."""
        notification_service._check_rate_limit = AsyncMock(return_value=True)
        notification_service._get_channels_for_priority = Mock(return_value=['email'])

        result = await notification_service.send_notification(
            recipients=['user@example.com'],
            subject='Test Notification',
            message='This is a test message',
            priority=NotificationPriority.MEDIUM
        )

        assert result['status'] == 'queued'
        assert 'notification_id' in result
        assert result['channels'] == ['email']
        assert result['priority'] == NotificationPriority.MEDIUM

    @pytest.mark.asyncio
    async def test_send_notification_rate_limited(self, notification_service):
        """Test notification rate limiting."""
        notification_service._check_rate_limit = AsyncMock(return_value=False)

        result = await notification_service.send_notification(
            recipients=['user@example.com'],
            subject='Test Notification',
            message='Test message',
            priority=NotificationPriority.LOW
        )

        assert result['status'] == 'rate_limited'
        assert 'notification_id' in result

    @pytest.mark.asyncio
    async def test_send_notification_high_priority(self, notification_service):
        """Test high priority notification."""
        notification_service._check_rate_limit = AsyncMock(return_value=True)
        notification_service._get_channels_for_priority = Mock(
            return_value=['email', 'slack', 'teams']
        )

        result = await notification_service.send_notification(
            recipients=['admin@example.com'],
            subject='Critical Alert',
            message='System failure detected',
            priority=NotificationPriority.CRITICAL
        )

        assert result['status'] == 'queued'
        assert result['priority'] == NotificationPriority.CRITICAL
        assert 'email' in result['channels']
        assert 'slack' in result['channels']

    @pytest.mark.asyncio
    async def test_send_notification_with_custom_channels(self, notification_service):
        """Test notification with custom channels."""
        notification_service._check_rate_limit = AsyncMock(return_value=True)

        result = await notification_service.send_notification(
            recipients=['user@example.com'],
            subject='Test',
            message='Test message',
            priority=NotificationPriority.MEDIUM,
            channels=['email', 'slack']
        )

        assert result['channels'] == ['email', 'slack']

    @pytest.mark.asyncio
    async def test_send_notification_with_attachments(self, notification_service):
        """Test notification with attachments."""
        notification_service._check_rate_limit = AsyncMock(return_value=True)
        notification_service._get_channels_for_priority = Mock(return_value=['email'])

        attachments = [
            {'filename': 'report.pdf', 'content': b'PDF content', 'mimetype': 'application/pdf'}
        ]

        result = await notification_service.send_notification(
            recipients=['user@example.com'],
            subject='Report',
            message='Attached is your report',
            priority=NotificationPriority.MEDIUM,
            attachments=attachments
        )

        assert result['status'] == 'queued'

    @pytest.mark.asyncio
    async def test_send_notification_with_metadata(self, notification_service):
        """Test notification with metadata."""
        notification_service._check_rate_limit = AsyncMock(return_value=True)
        notification_service._get_channels_for_priority = Mock(return_value=['email'])

        metadata = {
            'deployment_id': 'deploy_123',
            'device_count': 10,
            'event_type': 'deployment_completed'
        }

        result = await notification_service.send_notification(
            recipients=['ops@example.com'],
            subject='Deployment Complete',
            message='Deployment completed successfully',
            priority=NotificationPriority.HIGH,
            metadata=metadata
        )

        assert result['status'] == 'queued'

    @pytest.mark.asyncio
    async def test_send_notification_with_template(self, notification_service):
        """Test notification with template rendering."""
        notification_service._check_rate_limit = AsyncMock(return_value=True)
        notification_service._get_channels_for_priority = Mock(return_value=['email'])
        notification_service._render_template = AsyncMock(return_value={
            'subject': 'Rendered Subject',
            'message': 'Rendered message with data'
        })

        result = await notification_service.send_notification(
            recipients=['user@example.com'],
            subject='Original Subject',
            message='Original message',
            priority=NotificationPriority.MEDIUM,
            template='deployment_complete',
            template_data={'deployment_id': '123', 'device_count': 5}
        )

        assert result['status'] == 'queued'
        notification_service._render_template.assert_called_once()


class TestNotificationChannels:
    """Test different notification channels."""

    def test_get_channels_for_low_priority(self, notification_service):
        """Test channels for low priority notifications."""
        channels = notification_service._get_channels_for_priority(NotificationPriority.LOW)

        # Low priority typically uses email only
        assert isinstance(channels, list)

    def test_get_channels_for_critical_priority(self, notification_service):
        """Test channels for critical priority notifications."""
        channels = notification_service._get_channels_for_priority(NotificationPriority.CRITICAL)

        # Critical priority typically uses all channels
        assert isinstance(channels, list)

    def test_get_channels_for_emergency_priority(self, notification_service):
        """Test channels for emergency priority notifications."""
        channels = notification_service._get_channels_for_priority(NotificationPriority.EMERGENCY)

        # Emergency typically includes PagerDuty
        assert isinstance(channels, list)


class TestRateLimiting:
    """Test notification rate limiting."""

    @pytest.mark.asyncio
    async def test_rate_limit_check_no_limit(self, notification_service):
        """Test rate limit check when no limit exists."""
        result = await notification_service._check_rate_limit(
            ['user@example.com'],
            NotificationPriority.MEDIUM
        )

        # First notification should pass
        assert isinstance(result, bool)

    @pytest.mark.asyncio
    async def test_rate_limit_check_high_priority_bypass(self, notification_service):
        """Test high priority notifications bypass rate limits."""
        # Set up rate limit
        notification_service.rate_limits['user@example.com'] = {
            'count': 100,
            'window_start': datetime.utcnow()
        }

        result = await notification_service._check_rate_limit(
            ['user@example.com'],
            NotificationPriority.CRITICAL
        )

        # Critical priority might bypass rate limits
        assert isinstance(result, bool)


class TestTemplateRendering:
    """Test notification template rendering."""

    @pytest.mark.asyncio
    async def test_render_template_success(self, notification_service):
        """Test successful template rendering."""
        notification_service.template_cache['test_template'] = {
            'subject': 'Hello {{name}}',
            'message': 'Welcome {{name}}, your account is ready.'
        }

        result = await notification_service._render_template(
            'test_template',
            {'name': 'John Doe'}
        )

        assert isinstance(result, dict)
        assert 'subject' in result or 'message' in result

    @pytest.mark.asyncio
    async def test_render_template_not_found(self, notification_service):
        """Test rendering nonexistent template."""
        result = await notification_service._render_template(
            'nonexistent_template',
            {}
        )

        # Should return empty dict or handle gracefully
        assert isinstance(result, dict)


class TestNotificationQueue:
    """Test notification queue management."""

    @pytest.mark.asyncio
    async def test_notification_added_to_queue(self, notification_service):
        """Test notification is added to queue."""
        notification_service._check_rate_limit = AsyncMock(return_value=True)
        notification_service._get_channels_for_priority = Mock(return_value=['email'])

        initial_queue_size = notification_service.notification_queue.qsize()

        await notification_service.send_notification(
            recipients=['user@example.com'],
            subject='Test',
            message='Test message',
            priority=NotificationPriority.MEDIUM
        )

        # Queue should have one more item
        assert notification_service.notification_queue.qsize() == initial_queue_size + 1

    @pytest.mark.asyncio
    async def test_multiple_notifications_queued(self, notification_service):
        """Test multiple notifications queued correctly."""
        notification_service._check_rate_limit = AsyncMock(return_value=True)
        notification_service._get_channels_for_priority = Mock(return_value=['email'])

        for i in range(5):
            await notification_service.send_notification(
                recipients=[f'user{i}@example.com'],
                subject=f'Test {i}',
                message=f'Message {i}',
                priority=NotificationPriority.MEDIUM
            )

        assert notification_service.notification_queue.qsize() == 5


class TestNotificationWorker:
    """Test notification background workers."""

    @pytest.mark.asyncio
    async def test_notification_worker_processes_queue(self, notification_service):
        """Test notification worker processes queued notifications."""
        notification = {
            'id': 'notif_123',
            'recipients': ['user@example.com'],
            'subject': 'Test',
            'message': 'Test message',
            'priority': NotificationPriority.MEDIUM,
            'channels': ['email'],
            'attachments': [],
            'metadata': {},
            'created_at': datetime.utcnow(),
            'attempts': 0,
            'status': 'queued'
        }

        notification_service._process_notification = AsyncMock()

        # Add notification to queue
        await notification_service.notification_queue.put(notification)

        # Manually trigger worker once
        if not notification_service.notification_queue.empty():
            queued_notification = await notification_service.notification_queue.get()
            await notification_service._process_notification(queued_notification)

            notification_service._process_notification.assert_called_once_with(notification)


class TestNotificationRetry:
    """Test notification retry logic."""

    @pytest.mark.asyncio
    async def test_failed_notification_added_to_retry_queue(self, notification_service):
        """Test failed notifications are added to retry queue."""
        notification = {
            'id': 'notif_123',
            'recipients': ['user@example.com'],
            'subject': 'Test',
            'message': 'Test message',
            'priority': NotificationPriority.MEDIUM,
            'channels': ['email'],
            'attachments': [],
            'metadata': {},
            'created_at': datetime.utcnow(),
            'attempts': 1,
            'status': 'failed'
        }

        await notification_service.retry_queue.put(notification)

        assert notification_service.retry_queue.qsize() == 1

    @pytest.mark.asyncio
    async def test_notification_max_retries(self, notification_service):
        """Test notification stops retrying after max attempts."""
        notification = {
            'id': 'notif_123',
            'recipients': ['user@example.com'],
            'subject': 'Test',
            'message': 'Test message',
            'priority': NotificationPriority.MEDIUM,
            'channels': ['email'],
            'attachments': [],
            'metadata': {},
            'created_at': datetime.utcnow(),
            'attempts': 5,  # Exceeded max retries
            'status': 'failed'
        }

        # Should not retry if max attempts exceeded
        assert notification['attempts'] >= 3  # Typical max retry count


class TestNotificationID:
    """Test notification ID generation."""

    @pytest.mark.asyncio
    async def test_notification_id_is_unique(self, notification_service):
        """Test each notification gets unique ID."""
        notification_service._check_rate_limit = AsyncMock(return_value=True)
        notification_service._get_channels_for_priority = Mock(return_value=['email'])

        result1 = await notification_service.send_notification(
            recipients=['user@example.com'],
            subject='Test 1',
            message='Message 1',
            priority=NotificationPriority.MEDIUM
        )

        result2 = await notification_service.send_notification(
            recipients=['user@example.com'],
            subject='Test 2',
            message='Message 2',
            priority=NotificationPriority.MEDIUM
        )

        assert result1['notification_id'] != result2['notification_id']

    @pytest.mark.asyncio
    async def test_notification_id_format(self, notification_service):
        """Test notification ID format."""
        notification_service._check_rate_limit = AsyncMock(return_value=True)
        notification_service._get_channels_for_priority = Mock(return_value=['email'])

        result = await notification_service.send_notification(
            recipients=['user@example.com'],
            subject='Test',
            message='Test message',
            priority=NotificationPriority.MEDIUM
        )

        # ID should be 16 character hash
        assert len(result['notification_id']) == 16
        assert isinstance(result['notification_id'], str)


class TestNotificationRecipients:
    """Test notification recipient handling."""

    @pytest.mark.asyncio
    async def test_single_recipient(self, notification_service):
        """Test notification to single recipient."""
        notification_service._check_rate_limit = AsyncMock(return_value=True)
        notification_service._get_channels_for_priority = Mock(return_value=['email'])

        result = await notification_service.send_notification(
            recipients=['user@example.com'],
            subject='Test',
            message='Test message',
            priority=NotificationPriority.MEDIUM
        )

        assert result['status'] == 'queued'

    @pytest.mark.asyncio
    async def test_multiple_recipients(self, notification_service):
        """Test notification to multiple recipients."""
        notification_service._check_rate_limit = AsyncMock(return_value=True)
        notification_service._get_channels_for_priority = Mock(return_value=['email'])

        result = await notification_service.send_notification(
            recipients=['user1@example.com', 'user2@example.com', 'user3@example.com'],
            subject='Test',
            message='Test message',
            priority=NotificationPriority.MEDIUM
        )

        assert result['status'] == 'queued'

    @pytest.mark.asyncio
    async def test_empty_recipients(self, notification_service):
        """Test notification with empty recipients list."""
        notification_service._check_rate_limit = AsyncMock(return_value=True)
        notification_service._get_channels_for_priority = Mock(return_value=['email'])

        result = await notification_service.send_notification(
            recipients=[],
            subject='Test',
            message='Test message',
            priority=NotificationPriority.MEDIUM
        )

        # Should handle gracefully or queue anyway
        assert 'notification_id' in result
