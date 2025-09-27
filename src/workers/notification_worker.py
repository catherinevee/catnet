"""
Notification worker for handling alerts and notifications.
Sends notifications via email, SMS, Slack, and other channels.
"""

import asyncio
import json
import smtplib
import aiohttp
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from uuid import UUID
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from enum import Enum

from src.workers.base import BaseWorker, WorkerTask
from src.core.exceptions import NotificationError
from src.db.models import Notification, User, Alert
from src.security.vault import VaultClient
from src.security.audit import AuditLogger
from src.core.config import get_settings


class NotificationChannel(Enum):
    """Notification delivery channels."""
    EMAIL = "email"
    SMS = "sms"
    SLACK = "slack"
    TEAMS = "teams"
    WEBHOOK = "webhook"
    PAGERDUTY = "pagerduty"
    OPSGENIE = "opsgenie"


class NotificationPriority(Enum):
    """Notification priority levels."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"
    CRITICAL = "critical"


class NotificationWorker(BaseWorker):
    """
    Worker for processing notification tasks.
    Handles delivery of notifications through various channels.
    """

    def __init__(self, **kwargs):
        """Initialize notification worker."""
        super().__init__(**kwargs)
        self.vault = VaultClient()
        self.audit = AuditLogger()
        self.settings = get_settings()

        # Channel configurations
        self.channel_configs = {}
        self.rate_limits = {
            'email': {'per_minute': 30, 'per_hour': 500},
            'sms': {'per_minute': 10, 'per_hour': 100},
            'slack': {'per_minute': 60, 'per_hour': 1000}
        }

        # Track sent notifications for rate limiting
        self.sent_notifications = {
            channel.value: [] for channel in NotificationChannel
        }

    def get_worker_type(self) -> str:
        """Get worker type identifier."""
        return "notification"

    async def process_task(self, task: WorkerTask) -> Dict[str, Any]:
        """
        Process notification task.

        Args:
            task: Notification task

        Returns:
            Task result
        """
        task_type = task.task_type
        payload = task.payload

        if task_type == "send_notification":
            return await self._send_notification(payload)

        elif task_type == "send_alert":
            return await self._send_alert(payload)

        elif task_type == "send_bulk":
            return await self._send_bulk_notifications(payload)

        elif task_type == "send_deployment_notification":
            return await self._send_deployment_notification(payload)

        elif task_type == "send_health_alert":
            return await self._send_health_alert(payload)

        elif task_type == "send_security_alert":
            return await self._send_security_alert(payload)

        else:
            raise ValueError(f"Unknown task type: {task_type}")

    async def _send_notification(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send a single notification."""
        recipient_id = payload.get('recipient_id')
        channel = NotificationChannel(payload.get('channel', 'email'))
        subject = payload.get('subject')
        message = payload.get('message')
        priority = NotificationPriority(payload.get('priority', 'normal'))
        metadata = payload.get('metadata', {})

        try:
            # Check rate limits
            if not await self._check_rate_limit(channel):
                raise NotificationError(f"Rate limit exceeded for {channel.value}")

            # Get recipient information
            async with get_db() as db:
                if recipient_id:
                    user = await db.get(User, UUID(recipient_id))
                    if not user:
                        raise NotificationError(f"User {recipient_id} not found")
                    recipient = self._get_user_contact(user, channel)
                else:
                    recipient = payload.get('recipient')

                if not recipient:
                    raise NotificationError("No recipient specified")

                # Send notification based on channel
                if channel == NotificationChannel.EMAIL:
                    result = await self._send_email(recipient, subject, message, priority)
                elif channel == NotificationChannel.SMS:
                    result = await self._send_sms(recipient, message, priority)
                elif channel == NotificationChannel.SLACK:
                    result = await self._send_slack(recipient, subject, message, priority)
                elif channel == NotificationChannel.TEAMS:
                    result = await self._send_teams(recipient, subject, message, priority)
                elif channel == NotificationChannel.WEBHOOK:
                    result = await self._send_webhook(recipient, payload)
                elif channel == NotificationChannel.PAGERDUTY:
                    result = await self._send_pagerduty(recipient, subject, message, priority)
                elif channel == NotificationChannel.OPSGENIE:
                    result = await self._send_opsgenie(recipient, subject, message, priority)
                else:
                    raise NotificationError(f"Unsupported channel: {channel}")

                # Record notification
                notification = Notification(
                    recipient_id=UUID(recipient_id) if recipient_id else None,
                    channel=channel.value,
                    subject=subject,
                    message=message,
                    priority=priority.value,
                    status='sent' if result['success'] else 'failed',
                    sent_at=datetime.utcnow() if result['success'] else None,
                    error=result.get('error'),
                    metadata=metadata
                )

                db.add(notification)
                await db.commit()

                # Track for rate limiting
                self.sent_notifications[channel.value].append(datetime.utcnow())

                await self.audit.log_event(
                    event_type="NOTIFICATION_SENT",
                    details={
                        'channel': channel.value,
                        'recipient': recipient if isinstance(recipient, str) else str(recipient),
                        'priority': priority.value,
                        'success': result['success']
                    }
                )

                return {
                    'status': 'sent' if result['success'] else 'failed',
                    'channel': channel.value,
                    'recipient': recipient,
                    'message_id': result.get('message_id'),
                    'error': result.get('error')
                }

        except Exception as e:
            raise NotificationError(f"Failed to send notification: {e}")

    async def _send_alert(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send alert notification."""
        alert_id = UUID(payload['alert_id'])

        try:
            async with get_db() as db:
                alert = await db.get(Alert, alert_id)
                if not alert:
                    raise NotificationError(f"Alert {alert_id} not found")

                # Get recipients based on alert severity
                recipients = await self._get_alert_recipients(alert, db)

                # Format alert message
                subject = f"[{alert.severity.upper()}] {alert.title}"
                message = self._format_alert_message(alert)

                # Determine channels based on severity
                channels = self._get_alert_channels(alert.severity)

                # Send to all recipients through all channels
                results = []
                for recipient in recipients:
                    for channel in channels:
                        try:
                            result = await self._send_notification({
                                'recipient_id': str(recipient.id),
                                'channel': channel.value,
                                'subject': subject,
                                'message': message,
                                'priority': self._severity_to_priority(alert.severity).value,
                                'metadata': {'alert_id': str(alert_id)}
                            })
                            results.append(result)
                        except Exception as e:
                            results.append({
                                'status': 'failed',
                                'recipient': str(recipient.id),
                                'channel': channel.value,
                                'error': str(e)
                            })

                # Update alert status
                alert.notified = True
                alert.notified_at = datetime.utcnow()
                await db.commit()

                successful = len([r for r in results if r['status'] == 'sent'])
                total = len(results)

                return {
                    'status': 'completed',
                    'alert_id': str(alert_id),
                    'successful': successful,
                    'total': total,
                    'results': results
                }

        except Exception as e:
            raise NotificationError(f"Failed to send alert: {e}")

    async def _send_bulk_notifications(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send notifications to multiple recipients."""
        recipients = payload.get('recipients', [])
        channel = NotificationChannel(payload.get('channel', 'email'))
        subject = payload.get('subject')
        message = payload.get('message')
        priority = NotificationPriority(payload.get('priority', 'normal'))

        results = []
        batch_size = 10

        for i in range(0, len(recipients), batch_size):
            batch = recipients[i:i + batch_size]

            # Send in parallel
            batch_tasks = [
                self._send_notification({
                    'recipient': recipient if isinstance(recipient, str) else recipient.get('id'),
                    'channel': channel.value,
                    'subject': subject,
                    'message': message,
                    'priority': priority.value
                })
                for recipient in batch
            ]

            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)

            for recipient, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    results.append({
                        'recipient': recipient,
                        'status': 'failed',
                        'error': str(result)
                    })
                else:
                    results.append({
                        'recipient': recipient,
                        'status': result['status']
                    })

        successful = len([r for r in results if r['status'] == 'sent'])
        failed = len([r for r in results if r['status'] == 'failed'])

        return {
            'status': 'completed',
            'total': len(recipients),
            'successful': successful,
            'failed': failed,
            'results': results
        }

    async def _send_deployment_notification(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send deployment-related notification."""
        deployment_id = UUID(payload['deployment_id'])
        event = payload.get('event', 'started')  # started, completed, failed, rolled_back

        try:
            async with get_db() as db:
                deployment = await db.get(Deployment, deployment_id)
                if not deployment:
                    raise NotificationError(f"Deployment {deployment_id} not found")

                # Get stakeholders
                stakeholders = await self._get_deployment_stakeholders(deployment, db)

                # Format message based on event
                subject, message = self._format_deployment_notification(deployment, event)

                # Send notifications
                results = []
                for stakeholder in stakeholders:
                    result = await self._send_notification({
                        'recipient_id': str(stakeholder.id),
                        'channel': 'email',
                        'subject': subject,
                        'message': message,
                        'priority': 'high' if event == 'failed' else 'normal',
                        'metadata': {
                            'deployment_id': str(deployment_id),
                            'event': event
                        }
                    })
                    results.append(result)

                return {
                    'status': 'completed',
                    'deployment_id': str(deployment_id),
                    'event': event,
                    'notifications_sent': len(results)
                }

        except Exception as e:
            raise NotificationError(f"Failed to send deployment notification: {e}")

    async def _send_health_alert(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send health check alert."""
        device_id = UUID(payload['device_id'])
        health_status = payload.get('health_status')
        issues = payload.get('issues', [])

        # Format health alert
        subject = f"Device Health Alert: {health_status}"
        message = self._format_health_alert(device_id, health_status, issues)

        # Determine priority based on health status
        priority = 'critical' if health_status == 'critical' else 'high'

        # Get device owners/operators
        recipients = await self._get_device_operators(device_id)

        # Send notifications
        results = []
        for recipient in recipients:
            result = await self._send_notification({
                'recipient_id': str(recipient),
                'channel': 'email',
                'subject': subject,
                'message': message,
                'priority': priority,
                'metadata': {
                    'device_id': str(device_id),
                    'health_status': health_status
                }
            })
            results.append(result)

        return {
            'status': 'completed',
            'device_id': str(device_id),
            'health_status': health_status,
            'notifications_sent': len(results)
        }

    async def _send_security_alert(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send security alert with high priority."""
        alert_type = payload.get('alert_type')  # intrusion, breach, vulnerability
        severity = payload.get('severity', 'high')
        details = payload.get('details', {})

        # Format security alert
        subject = f"[SECURITY] {alert_type.upper()}: {severity.upper()} severity"
        message = self._format_security_alert(alert_type, severity, details)

        # Get security team
        recipients = await self._get_security_team()

        # Send through multiple channels for critical alerts
        channels = ['email', 'sms', 'slack'] if severity == 'critical' else ['email', 'slack']

        results = []
        for recipient in recipients:
            for channel in channels:
                result = await self._send_notification({
                    'recipient_id': str(recipient),
                    'channel': channel,
                    'subject': subject,
                    'message': message,
                    'priority': 'critical',
                    'metadata': {
                        'alert_type': alert_type,
                        'severity': severity,
                        'details': details
                    }
                })
                results.append(result)

        # Log security alert
        await self.audit.log_event(
            event_type="SECURITY_ALERT_SENT",
            details={
                'alert_type': alert_type,
                'severity': severity,
                'recipients': len(recipients),
                'channels': channels
            }
        )

        return {
            'status': 'completed',
            'alert_type': alert_type,
            'severity': severity,
            'notifications_sent': len(results)
        }

    async def _send_email(
        self,
        recipient: str,
        subject: str,
        message: str,
        priority: NotificationPriority
    ) -> Dict[str, Any]:
        """Send email notification."""
        try:
            # Get SMTP configuration from Vault
            smtp_config = await self.vault.get_secret('smtp/config')

            # Create message
            msg = MIMEMultipart()
            msg['From'] = smtp_config['from_address']
            msg['To'] = recipient
            msg['Subject'] = subject
            msg['X-Priority'] = str(self._priority_to_smtp_priority(priority))

            # Add body
            msg.attach(MIMEText(message, 'plain'))

            # Send email
            with smtplib.SMTP(smtp_config['host'], smtp_config['port']) as server:
                if smtp_config.get('use_tls'):
                    server.starttls()
                if smtp_config.get('username'):
                    server.login(smtp_config['username'], smtp_config['password'])
                server.send_message(msg)

            return {
                'success': True,
                'message_id': msg['Message-ID']
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    async def _send_sms(
        self,
        recipient: str,
        message: str,
        priority: NotificationPriority
    ) -> Dict[str, Any]:
        """Send SMS notification."""
        try:
            # Get SMS configuration from Vault
            sms_config = await self.vault.get_secret('sms/config')

            # Use provider API (e.g., Twilio)
            async with aiohttp.ClientSession() as session:
                url = f"{sms_config['api_url']}/messages"
                data = {
                    'To': recipient,
                    'From': sms_config['from_number'],
                    'Body': message[:160]  # SMS length limit
                }

                auth = aiohttp.BasicAuth(
                    sms_config['account_sid'],
                    sms_config['auth_token']
                )

                async with session.post(url, data=data, auth=auth) as response:
                    if response.status == 200:
                        result = await response.json()
                        return {
                            'success': True,
                            'message_id': result.get('sid')
                        }
                    else:
                        return {
                            'success': False,
                            'error': f"SMS API error: {response.status}"
                        }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    async def _send_slack(
        self,
        recipient: str,
        subject: str,
        message: str,
        priority: NotificationPriority
    ) -> Dict[str, Any]:
        """Send Slack notification."""
        try:
            # Get Slack configuration from Vault
            slack_config = await self.vault.get_secret('slack/config')

            # Format Slack message
            slack_message = {
                'channel': recipient,
                'text': subject,
                'attachments': [
                    {
                        'color': self._priority_to_slack_color(priority),
                        'text': message,
                        'footer': 'CatNet Notification',
                        'ts': int(datetime.utcnow().timestamp())
                    }
                ]
            }

            # Send to Slack
            async with aiohttp.ClientSession() as session:
                headers = {
                    'Authorization': f"Bearer {slack_config['bot_token']}",
                    'Content-Type': 'application/json'
                }

                async with session.post(
                    'https://slack.com/api/chat.postMessage',
                    headers=headers,
                    json=slack_message
                ) as response:
                    result = await response.json()
                    if result.get('ok'):
                        return {
                            'success': True,
                            'message_id': result.get('ts')
                        }
                    else:
                        return {
                            'success': False,
                            'error': result.get('error')
                        }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    async def _send_teams(
        self,
        recipient: str,
        subject: str,
        message: str,
        priority: NotificationPriority
    ) -> Dict[str, Any]:
        """Send Microsoft Teams notification."""
        try:
            # Get Teams webhook URL from Vault
            teams_config = await self.vault.get_secret('teams/config')

            # Format Teams message
            teams_message = {
                '@type': 'MessageCard',
                '@context': 'http://schema.org/extensions',
                'themeColor': self._priority_to_hex_color(priority),
                'summary': subject,
                'sections': [
                    {
                        'activityTitle': subject,
                        'text': message
                    }
                ]
            }

            # Send to Teams
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    teams_config['webhook_url'],
                    json=teams_message
                ) as response:
                    if response.status == 200:
                        return {'success': True}
                    else:
                        return {
                            'success': False,
                            'error': f"Teams API error: {response.status}"
                        }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    async def _send_webhook(self, url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send webhook notification."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    if response.status in [200, 201, 202]:
                        return {'success': True}
                    else:
                        return {
                            'success': False,
                            'error': f"Webhook error: {response.status}"
                        }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    async def _send_pagerduty(
        self,
        recipient: str,
        subject: str,
        message: str,
        priority: NotificationPriority
    ) -> Dict[str, Any]:
        """Send PagerDuty alert."""
        try:
            # Get PagerDuty configuration from Vault
            pd_config = await self.vault.get_secret('pagerduty/config')

            # Create incident
            incident = {
                'incident': {
                    'type': 'incident',
                    'title': subject,
                    'body': {
                        'type': 'incident_body',
                        'details': message
                    },
                    'urgency': 'high' if priority in [NotificationPriority.CRITICAL, NotificationPriority.URGENT] else 'low',
                    'service': {
                        'id': pd_config['service_id'],
                        'type': 'service_reference'
                    }
                }
            }

            async with aiohttp.ClientSession() as session:
                headers = {
                    'Authorization': f"Token token={pd_config['api_token']}",
                    'Accept': 'application/vnd.pagerduty+json;version=2'
                }

                async with session.post(
                    'https://api.pagerduty.com/incidents',
                    headers=headers,
                    json=incident
                ) as response:
                    if response.status == 201:
                        result = await response.json()
                        return {
                            'success': True,
                            'message_id': result['incident']['id']
                        }
                    else:
                        return {
                            'success': False,
                            'error': f"PagerDuty API error: {response.status}"
                        }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    async def _send_opsgenie(
        self,
        recipient: str,
        subject: str,
        message: str,
        priority: NotificationPriority
    ) -> Dict[str, Any]:
        """Send OpsGenie alert."""
        try:
            # Get OpsGenie configuration from Vault
            og_config = await self.vault.get_secret('opsgenie/config')

            # Create alert
            alert = {
                'message': subject,
                'description': message,
                'priority': self._priority_to_opsgenie_priority(priority),
                'responders': [
                    {
                        'type': 'team',
                        'id': og_config['team_id']
                    }
                ]
            }

            async with aiohttp.ClientSession() as session:
                headers = {
                    'Authorization': f"GenieKey {og_config['api_key']}"
                }

                async with session.post(
                    'https://api.opsgenie.com/v2/alerts',
                    headers=headers,
                    json=alert
                ) as response:
                    if response.status == 202:
                        result = await response.json()
                        return {
                            'success': True,
                            'message_id': result['requestId']
                        }
                    else:
                        return {
                            'success': False,
                            'error': f"OpsGenie API error: {response.status}"
                        }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    async def _check_rate_limit(self, channel: NotificationChannel) -> bool:
        """Check if rate limit allows sending notification."""
        limits = self.rate_limits.get(channel.value, {})
        if not limits:
            return True

        now = datetime.utcnow()
        sent = self.sent_notifications[channel.value]

        # Clean old entries
        hour_ago = now - timedelta(hours=1)
        sent[:] = [t for t in sent if t > hour_ago]

        # Check per minute limit
        minute_ago = now - timedelta(minutes=1)
        recent_minute = len([t for t in sent if t > minute_ago])
        if recent_minute >= limits.get('per_minute', float('inf')):
            return False

        # Check per hour limit
        recent_hour = len(sent)
        if recent_hour >= limits.get('per_hour', float('inf')):
            return False

        return True

    def _get_user_contact(self, user: User, channel: NotificationChannel) -> Optional[str]:
        """Get user contact information for channel."""
        if channel == NotificationChannel.EMAIL:
            return user.email
        elif channel == NotificationChannel.SMS:
            return user.phone
        elif channel == NotificationChannel.SLACK:
            return user.slack_id
        return None

    async def _get_alert_recipients(self, alert: Alert, db) -> List[User]:
        """Get recipients for alert based on severity."""
        # This would query based on alert rules and escalation policies
        # Simplified for now
        return await db.query(User).filter(User.is_active == True).all()

    def _get_alert_channels(self, severity: str) -> List[NotificationChannel]:
        """Determine notification channels based on alert severity."""
        if severity == 'critical':
            return [NotificationChannel.EMAIL, NotificationChannel.SMS, NotificationChannel.SLACK]
        elif severity == 'high':
            return [NotificationChannel.EMAIL, NotificationChannel.SLACK]
        else:
            return [NotificationChannel.EMAIL]

    def _severity_to_priority(self, severity: str) -> NotificationPriority:
        """Convert alert severity to notification priority."""
        mapping = {
            'critical': NotificationPriority.CRITICAL,
            'high': NotificationPriority.HIGH,
            'medium': NotificationPriority.NORMAL,
            'low': NotificationPriority.LOW
        }
        return mapping.get(severity, NotificationPriority.NORMAL)

    def _priority_to_smtp_priority(self, priority: NotificationPriority) -> int:
        """Convert priority to SMTP X-Priority header value."""
        mapping = {
            NotificationPriority.CRITICAL: 1,
            NotificationPriority.URGENT: 1,
            NotificationPriority.HIGH: 2,
            NotificationPriority.NORMAL: 3,
            NotificationPriority.LOW: 5
        }
        return mapping.get(priority, 3)

    def _priority_to_slack_color(self, priority: NotificationPriority) -> str:
        """Convert priority to Slack attachment color."""
        mapping = {
            NotificationPriority.CRITICAL: 'danger',
            NotificationPriority.URGENT: 'danger',
            NotificationPriority.HIGH: 'warning',
            NotificationPriority.NORMAL: 'good',
            NotificationPriority.LOW: '#808080'
        }
        return mapping.get(priority, 'good')

    def _priority_to_hex_color(self, priority: NotificationPriority) -> str:
        """Convert priority to hex color for Teams."""
        mapping = {
            NotificationPriority.CRITICAL: 'FF0000',
            NotificationPriority.URGENT: 'FF0000',
            NotificationPriority.HIGH: 'FFA500',
            NotificationPriority.NORMAL: '00FF00',
            NotificationPriority.LOW: '808080'
        }
        return mapping.get(priority, '00FF00')

    def _priority_to_opsgenie_priority(self, priority: NotificationPriority) -> str:
        """Convert priority to OpsGenie priority."""
        mapping = {
            NotificationPriority.CRITICAL: 'P1',
            NotificationPriority.URGENT: 'P1',
            NotificationPriority.HIGH: 'P2',
            NotificationPriority.NORMAL: 'P3',
            NotificationPriority.LOW: 'P5'
        }
        return mapping.get(priority, 'P3')

    def _format_alert_message(self, alert: Alert) -> str:
        """Format alert into notification message."""
        return f"""
Alert Details:
--------------
Title: {alert.title}
Severity: {alert.severity}
Description: {alert.description}
Created: {alert.created_at}

Device: {alert.device_id}

Please investigate and take appropriate action.
        """

    def _format_deployment_notification(self, deployment, event: str) -> tuple[str, str]:
        """Format deployment notification."""
        if event == 'started':
            subject = f"Deployment Started: {deployment.name}"
            message = f"Deployment {deployment.id} has been started."
        elif event == 'completed':
            subject = f"Deployment Completed: {deployment.name}"
            message = f"Deployment {deployment.id} completed successfully."
        elif event == 'failed':
            subject = f"Deployment Failed: {deployment.name}"
            message = f"Deployment {deployment.id} failed. Error: {deployment.error_message}"
        elif event == 'rolled_back':
            subject = f"Deployment Rolled Back: {deployment.name}"
            message = f"Deployment {deployment.id} has been rolled back. Reason: {deployment.rollback_reason}"
        else:
            subject = f"Deployment Update: {deployment.name}"
            message = f"Deployment {deployment.id} status: {event}"

        return subject, message

    def _format_health_alert(self, device_id: UUID, health_status: str, issues: List[str]) -> str:
        """Format health alert message."""
        issues_text = '\n'.join(f"- {issue}" for issue in issues)
        return f"""
Device Health Alert
-------------------
Device ID: {device_id}
Health Status: {health_status}
Time: {datetime.utcnow().isoformat()}

Issues Detected:
{issues_text}

Please review the device status and take corrective action if needed.
        """

    def _format_security_alert(self, alert_type: str, severity: str, details: Dict) -> str:
        """Format security alert message."""
        details_text = '\n'.join(f"{k}: {v}" for k, v in details.items())
        return f"""
SECURITY ALERT
--------------
Type: {alert_type}
Severity: {severity}
Time: {datetime.utcnow().isoformat()}

Details:
{details_text}

IMMEDIATE ACTION REQUIRED
Please investigate this security event immediately and follow incident response procedures.
        """

    async def _get_deployment_stakeholders(self, deployment, db) -> List[User]:
        """Get stakeholders for deployment notifications."""
        # This would query based on deployment configuration
        # Simplified for now
        return await db.query(User).filter(User.is_active == True).all()

    async def _get_device_operators(self, device_id: UUID) -> List[UUID]:
        """Get operators responsible for device."""
        # This would query based on device ownership
        # Simplified for now
        async with get_db() as db:
            users = await db.query(User).filter(User.is_active == True).all()
            return [user.id for user in users]

    async def _get_security_team(self) -> List[UUID]:
        """Get security team members."""
        # This would query users with security role
        # Simplified for now
        async with get_db() as db:
            users = await db.query(User).filter(
                User.is_active == True,
                User.role.in_(['security', 'admin'])
            ).all()
            return [user.id for user in users]


# Export main components
__all__ = ['NotificationWorker', 'NotificationChannel', 'NotificationPriority']