"""
Notification Service - Handles alerts and notifications for CatNet
"""
import asyncio
import smtplib
import aiohttp
import json
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import logging
from pathlib import Path
import hashlib
from jinja2 import Template

from ..core.config import settings
from ..core.exceptions import NotificationError
from ..db.models import User, NotificationChannel, NotificationHistory
from ..core.logger import get_logger

logger = get_logger(__name__)


class NotificationPriority:
    """Notification priority levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5


class NotificationService:
    """
    Centralized notification service for all alerts
    """

    def __init__(self):
        self.smtp_host = settings.smtp_host
        self.smtp_port = settings.smtp_port
        self.smtp_user = settings.smtp_user
        self.smtp_password = settings.smtp_password.get_secret_value() if settings.smtp_password else None
        self.smtp_use_tls = settings.smtp_use_tls
        self.from_email = settings.notification_from_email

        self.slack_webhook_url = settings.slack_webhook_url
        self.teams_webhook_url = settings.teams_webhook_url
        self.pagerduty_api_key = settings.pagerduty_api_key

        self.rate_limits = {}
        self.notification_queue = asyncio.Queue()
        self.retry_queue = asyncio.Queue()
        self.template_cache = {}

        # Start notification worker
        asyncio.create_task(self._notification_worker())
        asyncio.create_task(self._retry_worker())

    async def send_notification(
        self,
        recipients: List[str],
        subject: str,
        message: str,
        priority: int = NotificationPriority.MEDIUM,
        channels: List[str] = None,
        attachments: List[Dict[str, Any]] = None,
        metadata: Dict[str, Any] = None,
        template: str = None,
        template_data: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Send notification through multiple channels

        Args:
            recipients: List of recipient identifiers (emails, user IDs, etc.)
            subject: Notification subject
            message: Notification message
            priority: Notification priority level
            channels: List of channels to use (email, slack, teams, sms, pagerduty)
            attachments: Optional attachments
            metadata: Additional metadata
            template: Template name to use
            template_data: Data for template rendering

        Returns:
            Notification status and delivery information
        """
        notification_id = hashlib.sha256(
            f"{subject}{message}{datetime.utcnow()}".encode()
        ).hexdigest()[:16]

        # Apply rate limiting
        if not await self._check_rate_limit(recipients, priority):
            logger.warning(f"Rate limit exceeded for notification {notification_id}")
            return {
                'notification_id': notification_id,
                'status': 'rate_limited',
                'message': 'Notification rate limit exceeded'
            }

        # Determine channels based on priority if not specified
        if not channels:
            channels = self._get_channels_for_priority(priority)

        # Render template if provided
        if template:
            rendered = await self._render_template(template, template_data or {})
            message = rendered.get('message', message)
            subject = rendered.get('subject', subject)

        # Queue notification
        notification = {
            'id': notification_id,
            'recipients': recipients,
            'subject': subject,
            'message': message,
            'priority': priority,
            'channels': channels,
            'attachments': attachments or [],
            'metadata': metadata or {},
            'created_at': datetime.utcnow(),
            'attempts': 0,
            'status': 'queued'
        }

        await self.notification_queue.put(notification)

        logger.info(f"Notification {notification_id} queued for delivery")

        return {
            'notification_id': notification_id,
            'status': 'queued',
            'channels': channels,
            'priority': priority
        }

    async def _notification_worker(self):
        """Background worker to process notification queue"""
        while True:
            try:
                notification = await self.notification_queue.get()
                await self._process_notification(notification)
            except Exception as e:
                logger.error(f"Error processing notification: {e}")
                await asyncio.sleep(1)

    async def _retry_worker(self):
        """Background worker to retry failed notifications"""
        while True:
            try:
                # Process retry queue with delay
                await asyncio.sleep(60)  # Check every minute

                retry_notifications = []
                while not self.retry_queue.empty():
                    notification = await self.retry_queue.get()

                    # Check if ready for retry
                    retry_after = notification.get('retry_after', datetime.utcnow())
                    if datetime.utcnow() >= retry_after:
                        notification['attempts'] += 1
                        await self._process_notification(notification)
                    else:
                        retry_notifications.append(notification)

                # Put back notifications not ready for retry
                for notification in retry_notifications:
                    await self.retry_queue.put(notification)

            except Exception as e:
                logger.error(f"Error in retry worker: {e}")
                await asyncio.sleep(5)

    async def _process_notification(self, notification: Dict[str, Any]):
        """Process a single notification"""
        notification_id = notification['id']
        channels = notification['channels']

        logger.info(f"Processing notification {notification_id} (attempt {notification['attempts'] + 1})")

        delivery_results = {}
        overall_success = False

        for channel in channels:
            try:
                if channel == 'email':
                    result = await self._send_email(notification)
                elif channel == 'slack':
                    result = await self._send_slack(notification)
                elif channel == 'teams':
                    result = await self._send_teams(notification)
                elif channel == 'sms':
                    result = await self._send_sms(notification)
                elif channel == 'pagerduty':
                    result = await self._send_pagerduty(notification)
                elif channel == 'webhook':
                    result = await self._send_webhook(notification)
                else:
                    logger.warning(f"Unknown channel: {channel}")
                    continue

                delivery_results[channel] = result
                if result.get('success'):
                    overall_success = True

            except Exception as e:
                logger.error(f"Failed to send notification via {channel}: {e}")
                delivery_results[channel] = {
                    'success': False,
                    'error': str(e)
                }

        # Update notification status
        notification['status'] = 'delivered' if overall_success else 'failed'
        notification['delivery_results'] = delivery_results
        notification['delivered_at'] = datetime.utcnow() if overall_success else None

        # Retry if failed and attempts < max
        if not overall_success and notification['attempts'] < 3:
            retry_delay = 2 ** notification['attempts'] * 60  # Exponential backoff
            notification['retry_after'] = datetime.utcnow() + timedelta(seconds=retry_delay)
            await self.retry_queue.put(notification)
            logger.info(f"Notification {notification_id} queued for retry in {retry_delay} seconds")

        # Store in history
        await self._store_notification_history(notification)

    async def _send_email(self, notification: Dict[str, Any]) -> Dict[str, Any]:
        """Send email notification"""
        try:
            msg = MIMEMultipart('alternative')
            msg['From'] = self.from_email
            msg['To'] = ', '.join(notification['recipients'])
            msg['Subject'] = notification['subject']

            # Add priority header
            priority_map = {
                NotificationPriority.CRITICAL: '1 (Highest)',
                NotificationPriority.HIGH: '2 (High)',
                NotificationPriority.MEDIUM: '3 (Normal)',
                NotificationPriority.LOW: '4 (Low)'
            }
            msg['X-Priority'] = priority_map.get(notification['priority'], '3 (Normal)')

            # Create HTML version
            html_content = self._format_html_email(
                notification['subject'],
                notification['message'],
                notification.get('metadata', {})
            )

            # Add text and HTML parts
            text_part = MIMEText(notification['message'], 'plain')
            html_part = MIMEText(html_content, 'html')
            msg.attach(text_part)
            msg.attach(html_part)

            # Add attachments
            for attachment in notification.get('attachments', []):
                await self._add_email_attachment(msg, attachment)

            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.smtp_use_tls:
                    server.starttls()
                if self.smtp_user and self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)

            logger.info(f"Email sent to {notification['recipients']}")
            return {'success': True, 'channel': 'email'}

        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return {'success': False, 'channel': 'email', 'error': str(e)}

    async def _send_slack(self, notification: Dict[str, Any]) -> Dict[str, Any]:
        """Send Slack notification"""
        if not self.slack_webhook_url:
            return {'success': False, 'channel': 'slack', 'error': 'Slack webhook not configured'}

        try:
            # Format message for Slack
            slack_message = {
                'text': notification['subject'],
                'attachments': [
                    {
                        'color': self._get_slack_color(notification['priority']),
                        'title': notification['subject'],
                        'text': notification['message'],
                        'footer': 'CatNet Notification Service',
                        'ts': int(datetime.utcnow().timestamp()),
                        'fields': [
                            {
                                'title': key,
                                'value': str(value),
                                'short': True
                            }
                            for key, value in notification.get('metadata', {}).items()
                        ]
                    }
                ]
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.slack_webhook_url,
                    json=slack_message,
                    headers={'Content-Type': 'application/json'}
                ) as response:
                    if response.status == 200:
                        logger.info("Slack notification sent successfully")
                        return {'success': True, 'channel': 'slack'}
                    else:
                        error = await response.text()
                        logger.error(f"Slack notification failed: {error}")
                        return {'success': False, 'channel': 'slack', 'error': error}

        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return {'success': False, 'channel': 'slack', 'error': str(e)}

    async def _send_teams(self, notification: Dict[str, Any]) -> Dict[str, Any]:
        """Send Microsoft Teams notification"""
        if not self.teams_webhook_url:
            return {'success': False, 'channel': 'teams', 'error': 'Teams webhook not configured'}

        try:
            # Format message for Teams
            teams_message = {
                '@type': 'MessageCard',
                '@context': 'http://schema.org/extensions',
                'themeColor': self._get_teams_color(notification['priority']),
                'summary': notification['subject'],
                'sections': [
                    {
                        'activityTitle': notification['subject'],
                        'activitySubtitle': f"Priority: {self._get_priority_name(notification['priority'])}",
                        'text': notification['message'],
                        'facts': [
                            {
                                'name': key,
                                'value': str(value)
                            }
                            for key, value in notification.get('metadata', {}).items()
                        ]
                    }
                ]
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.teams_webhook_url,
                    json=teams_message,
                    headers={'Content-Type': 'application/json'}
                ) as response:
                    if response.status == 200:
                        logger.info("Teams notification sent successfully")
                        return {'success': True, 'channel': 'teams'}
                    else:
                        error = await response.text()
                        logger.error(f"Teams notification failed: {error}")
                        return {'success': False, 'channel': 'teams', 'error': error}

        except Exception as e:
            logger.error(f"Failed to send Teams notification: {e}")
            return {'success': False, 'channel': 'teams', 'error': str(e)}

    async def _send_sms(self, notification: Dict[str, Any]) -> Dict[str, Any]:
        """Send SMS notification"""
        # This would integrate with SMS providers like Twilio, AWS SNS, etc.
        try:
            # Placeholder for SMS implementation
            if settings.sms_provider == 'twilio':
                return await self._send_twilio_sms(notification)
            elif settings.sms_provider == 'aws_sns':
                return await self._send_aws_sns(notification)
            else:
                return {'success': False, 'channel': 'sms', 'error': 'SMS provider not configured'}

        except Exception as e:
            logger.error(f"Failed to send SMS: {e}")
            return {'success': False, 'channel': 'sms', 'error': str(e)}

    async def _send_pagerduty(self, notification: Dict[str, Any]) -> Dict[str, Any]:
        """Send PagerDuty alert"""
        if not self.pagerduty_api_key:
            return {'success': False, 'channel': 'pagerduty', 'error': 'PagerDuty not configured'}

        try:
            # Create PagerDuty incident
            pagerduty_event = {
                'routing_key': self.pagerduty_api_key,
                'event_action': 'trigger',
                'payload': {
                    'summary': notification['subject'],
                    'source': 'CatNet',
                    'severity': self._get_pagerduty_severity(notification['priority']),
                    'custom_details': {
                        'message': notification['message'],
                        **notification.get('metadata', {})
                    }
                }
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    'https://events.pagerduty.com/v2/enqueue',
                    json=pagerduty_event,
                    headers={'Content-Type': 'application/json'}
                ) as response:
                    if response.status in [200, 202]:
                        logger.info("PagerDuty alert created successfully")
                        return {'success': True, 'channel': 'pagerduty'}
                    else:
                        error = await response.text()
                        logger.error(f"PagerDuty alert failed: {error}")
                        return {'success': False, 'channel': 'pagerduty', 'error': error}

        except Exception as e:
            logger.error(f"Failed to send PagerDuty alert: {e}")
            return {'success': False, 'channel': 'pagerduty', 'error': str(e)}

    async def _send_webhook(self, notification: Dict[str, Any]) -> Dict[str, Any]:
        """Send webhook notification"""
        webhook_url = notification.get('metadata', {}).get('webhook_url')
        if not webhook_url:
            return {'success': False, 'channel': 'webhook', 'error': 'Webhook URL not provided'}

        try:
            webhook_payload = {
                'notification_id': notification['id'],
                'subject': notification['subject'],
                'message': notification['message'],
                'priority': notification['priority'],
                'metadata': notification.get('metadata', {}),
                'timestamp': datetime.utcnow().isoformat()
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    webhook_url,
                    json=webhook_payload,
                    headers={'Content-Type': 'application/json'},
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status in [200, 201, 202, 204]:
                        logger.info(f"Webhook notification sent to {webhook_url}")
                        return {'success': True, 'channel': 'webhook'}
                    else:
                        error = await response.text()
                        logger.error(f"Webhook notification failed: {error}")
                        return {'success': False, 'channel': 'webhook', 'error': error}

        except Exception as e:
            logger.error(f"Failed to send webhook notification: {e}")
            return {'success': False, 'channel': 'webhook', 'error': str(e)}

    async def _send_twilio_sms(self, notification: Dict[str, Any]) -> Dict[str, Any]:
        """Send SMS via Twilio"""
        try:
            from twilio.rest import Client

            client = Client(settings.twilio_account_sid, settings.twilio_auth_token)

            # Send SMS to each recipient
            for recipient in notification['recipients']:
                message = client.messages.create(
                    body=f"{notification['subject']}\n{notification['message'][:140]}",
                    from_=settings.twilio_phone_number,
                    to=recipient
                )
                logger.info(f"SMS sent to {recipient}: {message.sid}")

            return {'success': True, 'channel': 'sms', 'provider': 'twilio'}

        except Exception as e:
            logger.error(f"Failed to send Twilio SMS: {e}")
            return {'success': False, 'channel': 'sms', 'provider': 'twilio', 'error': str(e)}

    async def _send_aws_sns(self, notification: Dict[str, Any]) -> Dict[str, Any]:
        """Send SMS via AWS SNS"""
        try:
            import boto3

            sns_client = boto3.client('sns', region_name=settings.aws_region)

            # Send SMS to each recipient
            for recipient in notification['recipients']:
                response = sns_client.publish(
                    PhoneNumber=recipient,
                    Message=f"{notification['subject']}\n{notification['message'][:140]}",
                    MessageAttributes={
                        'AWS.SNS.SMS.SMSType': {
                            'DataType': 'String',
                            'StringValue': 'Transactional'
                        }
                    }
                )
                logger.info(f"SMS sent via AWS SNS: {response['MessageId']}")

            return {'success': True, 'channel': 'sms', 'provider': 'aws_sns'}

        except Exception as e:
            logger.error(f"Failed to send AWS SNS SMS: {e}")
            return {'success': False, 'channel': 'sms', 'provider': 'aws_sns', 'error': str(e)}

    def _format_html_email(self, subject: str, message: str, metadata: Dict[str, Any]) -> str:
        """Format HTML email content"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background-color: #2c3e50; color: white; padding: 20px; text-align: center; }
                .content { background-color: #f4f4f4; padding: 20px; margin-top: 20px; }
                .metadata { background-color: white; padding: 15px; margin-top: 20px; border-left: 4px solid #3498db; }
                .footer { text-align: center; color: #888; font-size: 12px; margin-top: 20px; }
                .metadata-item { margin: 10px 0; }
                .metadata-key { font-weight: bold; color: #2c3e50; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>{{ subject }}</h1>
                </div>
                <div class="content">
                    <p>{{ message | replace('\n', '<br>') }}</p>
                </div>
                {% if metadata %}
                <div class="metadata">
                    <h3>Additional Information:</h3>
                    {% for key, value in metadata.items() %}
                    <div class="metadata-item">
                        <span class="metadata-key">{{ key }}:</span> {{ value }}
                    </div>
                    {% endfor %}
                </div>
                {% endif %}
                <div class="footer">
                    <p>This is an automated notification from CatNet Network Configuration System</p>
                    <p>&copy; {{ year }} CatNet. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """

        template = Template(html_template)
        return template.render(
            subject=subject,
            message=message,
            metadata=metadata,
            year=datetime.utcnow().year
        )

    async def _add_email_attachment(self, msg: MIMEMultipart, attachment: Dict[str, Any]):
        """Add attachment to email"""
        try:
            file_path = attachment.get('path')
            file_name = attachment.get('name', Path(file_path).name if file_path else 'attachment')

            if file_path and Path(file_path).exists():
                with open(file_path, 'rb') as f:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(f.read())
                    encoders.encode_base64(part)
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename= {file_name}'
                    )
                    msg.attach(part)
            elif attachment.get('content'):
                # Attachment provided as content
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment['content'])
                encoders.encode_base64(part)
                part.add_header(
                    'Content-Disposition',
                    f'attachment; filename= {file_name}'
                )
                msg.attach(part)

        except Exception as e:
            logger.error(f"Failed to add attachment: {e}")

    async def _check_rate_limit(self, recipients: List[str], priority: int) -> bool:
        """Check if notification is within rate limits"""
        # Higher priority notifications bypass rate limiting
        if priority >= NotificationPriority.CRITICAL:
            return True

        # Check per-recipient rate limits
        current_time = datetime.utcnow()
        for recipient in recipients:
            if recipient in self.rate_limits:
                last_sent = self.rate_limits[recipient]

                # Allow 1 notification per minute for medium priority
                if priority == NotificationPriority.MEDIUM:
                    if (current_time - last_sent).total_seconds() < 60:
                        return False
                # Allow 1 notification per 5 minutes for low priority
                elif priority == NotificationPriority.LOW:
                    if (current_time - last_sent).total_seconds() < 300:
                        return False

            self.rate_limits[recipient] = current_time

        return True

    def _get_channels_for_priority(self, priority: int) -> List[str]:
        """Determine notification channels based on priority"""
        if priority == NotificationPriority.EMERGENCY:
            return ['email', 'slack', 'teams', 'sms', 'pagerduty']
        elif priority == NotificationPriority.CRITICAL:
            return ['email', 'slack', 'teams', 'pagerduty']
        elif priority == NotificationPriority.HIGH:
            return ['email', 'slack', 'teams']
        elif priority == NotificationPriority.MEDIUM:
            return ['email', 'slack']
        else:
            return ['email']

    def _get_slack_color(self, priority: int) -> str:
        """Get Slack attachment color based on priority"""
        colors = {
            NotificationPriority.EMERGENCY: '#FF0000',  # Red
            NotificationPriority.CRITICAL: '#FF4500',   # Orange Red
            NotificationPriority.HIGH: '#FFA500',       # Orange
            NotificationPriority.MEDIUM: '#FFD700',     # Gold
            NotificationPriority.LOW: '#00FF00'         # Green
        }
        return colors.get(priority, '#808080')  # Gray default

    def _get_teams_color(self, priority: int) -> str:
        """Get Teams theme color based on priority"""
        return self._get_slack_color(priority).replace('#', '')

    def _get_priority_name(self, priority: int) -> str:
        """Get human-readable priority name"""
        names = {
            NotificationPriority.EMERGENCY: 'Emergency',
            NotificationPriority.CRITICAL: 'Critical',
            NotificationPriority.HIGH: 'High',
            NotificationPriority.MEDIUM: 'Medium',
            NotificationPriority.LOW: 'Low'
        }
        return names.get(priority, 'Unknown')

    def _get_pagerduty_severity(self, priority: int) -> str:
        """Map priority to PagerDuty severity"""
        severities = {
            NotificationPriority.EMERGENCY: 'critical',
            NotificationPriority.CRITICAL: 'critical',
            NotificationPriority.HIGH: 'error',
            NotificationPriority.MEDIUM: 'warning',
            NotificationPriority.LOW: 'info'
        }
        return severities.get(priority, 'info')

    async def _render_template(self, template_name: str, data: Dict[str, Any]) -> Dict[str, str]:
        """Render notification template"""
        # Check template cache
        if template_name in self.template_cache:
            template_content = self.template_cache[template_name]
        else:
            # Load template from file
            template_path = Path(f"templates/notifications/{template_name}.json")
            if template_path.exists():
                with open(template_path, 'r') as f:
                    template_content = json.load(f)
                    self.template_cache[template_name] = template_content
            else:
                logger.warning(f"Template not found: {template_name}")
                return {}

        # Render template with Jinja2
        subject_template = Template(template_content.get('subject', ''))
        message_template = Template(template_content.get('message', ''))

        return {
            'subject': subject_template.render(**data),
            'message': message_template.render(**data)
        }

    async def _store_notification_history(self, notification: Dict[str, Any]):
        """Store notification in history database"""
        try:
            # This would store to the database
            logger.info(f"Storing notification {notification['id']} in history")
            # Implementation would use SQLAlchemy to store in NotificationHistory table
        except Exception as e:
            logger.error(f"Failed to store notification history: {e}")

    async def get_notification_status(self, notification_id: str) -> Dict[str, Any]:
        """Get status of a notification"""
        # This would query the database for notification status
        return {
            'notification_id': notification_id,
            'status': 'unknown',
            'message': 'Status tracking not implemented'
        }

    async def cancel_notification(self, notification_id: str) -> bool:
        """Cancel a pending notification"""
        # This would remove notification from queue if still pending
        logger.info(f"Attempting to cancel notification {notification_id}")
        return False

    async def get_notification_history(
        self,
        user_id: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get notification history"""
        # This would query the database for notification history
        return []


# Global notification service instance
notification_service = NotificationService()


# Convenience functions for different types of notifications
async def send_alert(
    message: str,
    severity: str = 'medium',
    recipients: List[str] = None,
    metadata: Dict[str, Any] = None
):
    """Send an alert notification"""
    priority_map = {
        'low': NotificationPriority.LOW,
        'medium': NotificationPriority.MEDIUM,
        'high': NotificationPriority.HIGH,
        'critical': NotificationPriority.CRITICAL,
        'emergency': NotificationPriority.EMERGENCY
    }

    return await notification_service.send_notification(
        recipients=recipients or [settings.admin_email],
        subject=f"[CatNet Alert - {severity.upper()}]",
        message=message,
        priority=priority_map.get(severity, NotificationPriority.MEDIUM),
        metadata=metadata
    )


async def send_deployment_notification(
    deployment_id: str,
    status: str,
    message: str,
    recipients: List[str],
    details: Dict[str, Any] = None
):
    """Send deployment status notification"""
    priority = NotificationPriority.HIGH if status == 'failed' else NotificationPriority.MEDIUM

    return await notification_service.send_notification(
        recipients=recipients,
        subject=f"Deployment {deployment_id} - {status.upper()}",
        message=message,
        priority=priority,
        metadata={
            'deployment_id': deployment_id,
            'status': status,
            **(details or {})
        },
        template='deployment_status',
        template_data={
            'deployment_id': deployment_id,
            'status': status,
            'details': details
        }
    )


async def send_device_alert(
    device_id: str,
    device_name: str,
    alert_type: str,
    message: str,
    severity: str = 'medium'
):
    """Send device-related alert"""
    priority_map = {
        'low': NotificationPriority.LOW,
        'medium': NotificationPriority.MEDIUM,
        'high': NotificationPriority.HIGH,
        'critical': NotificationPriority.CRITICAL
    }

    return await notification_service.send_notification(
        recipients=[settings.noc_email],
        subject=f"Device Alert: {device_name} - {alert_type}",
        message=message,
        priority=priority_map.get(severity, NotificationPriority.MEDIUM),
        metadata={
            'device_id': device_id,
            'device_name': device_name,
            'alert_type': alert_type
        }
    )