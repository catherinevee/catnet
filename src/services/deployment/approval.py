"""
Deployment approval manager.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import json
import asyncio

import redis.asyncio as redis
import httpx

from src.core.logging import get_logger
from src.core.config import get_settings
from src.security.vault import VaultClient

logger = get_logger(__name__)
settings = get_settings()


class ApprovalManager:
    """Manages deployment approval workflows."""

    def __init__(self):
        self.vault = VaultClient()
        self.redis = None
        self.approval_timeout = timedelta(hours=24)

    async def initialize(self):
        """Initialize approval manager."""
        self.redis = await redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True
        )

    async def request_approval(
        self,
        deployment_id: str,
        required_approvals: int,
        approvers: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Request approval for deployment.

        Args:
            deployment_id: Deployment ID
            required_approvals: Number of approvals required
            approvers: Optional list of specific approvers
            metadata: Additional metadata for approval

        Returns:
            True if request created successfully
        """
        try:
            logger.info(f"Requesting approval for deployment {deployment_id}")

            # Get eligible approvers
            if not approvers:
                approvers = await self._get_eligible_approvers(deployment_id)

            if len(approvers) < required_approvals:
                logger.error(f"Not enough approvers available. Required: {required_approvals}, Available: {len(approvers)}")
                return False

            # Create approval request
            approval_request = {
                'deployment_id': deployment_id,
                'required_approvals': required_approvals,
                'approvers': approvers,
                'created_at': datetime.utcnow().isoformat(),
                'expires_at': (datetime.utcnow() + self.approval_timeout).isoformat(),
                'approvals': [],
                'rejections': [],
                'status': 'pending',
                'metadata': metadata or {}
            }

            # Store in Redis
            await self.redis.setex(
                f"approval:request:{deployment_id}",
                int(self.approval_timeout.total_seconds()),
                json.dumps(approval_request)
            )

            # Send notifications to approvers
            await self._notify_approvers(deployment_id, approvers, metadata)

            logger.info(f"Approval request created for deployment {deployment_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to request approval: {e}")
            return False

    async def check_approval(
        self,
        deployment_id: str,
        required_count: int
    ) -> bool:
        """
        Check if deployment has required approvals.

        Args:
            deployment_id: Deployment ID
            required_count: Required number of approvals

        Returns:
            True if approved
        """
        try:
            # Get approval request
            request_data = await self.redis.get(f"approval:request:{deployment_id}")
            if not request_data:
                logger.warning(f"No approval request found for deployment {deployment_id}")
                return False

            approval_request = json.loads(request_data)

            # Check expiration
            expires_at = datetime.fromisoformat(approval_request['expires_at'])
            if expires_at < datetime.utcnow():
                logger.warning(f"Approval request expired for deployment {deployment_id}")
                await self._mark_expired(deployment_id)
                return False

            # Check approval count
            approval_count = len(approval_request.get('approvals', []))
            return approval_count >= required_count

        except Exception as e:
            logger.error(f"Failed to check approval: {e}")
            return False

    async def record_approval(
        self,
        deployment_id: str,
        approver_id: str,
        action: str,
        comment: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Record approval decision.

        Args:
            deployment_id: Deployment ID
            approver_id: Approver user ID
            action: Approval action (approve/reject/defer)
            comment: Optional comment

        Returns:
            Approval result
        """
        try:
            # Get approval request
            request_data = await self.redis.get(f"approval:request:{deployment_id}")
            if not request_data:
                return {
                    'success': False,
                    'error': 'No approval request found'
                }

            approval_request = json.loads(request_data)

            # Check if approver is eligible
            if approver_id not in approval_request.get('approvers', []):
                return {
                    'success': False,
                    'error': 'User not authorized to approve this deployment'
                }

            # Check if already approved/rejected
            existing_approvals = approval_request.get('approvals', [])
            existing_rejections = approval_request.get('rejections', [])

            for approval in existing_approvals + existing_rejections:
                if approval.get('approver_id') == approver_id:
                    return {
                        'success': False,
                        'error': 'User has already voted on this deployment'
                    }

            # Record decision
            decision = {
                'approver_id': approver_id,
                'action': action,
                'comment': comment,
                'timestamp': datetime.utcnow().isoformat()
            }

            if action == 'approve':
                approval_request['approvals'].append(decision)
            elif action == 'reject':
                approval_request['rejections'].append(decision)
                approval_request['status'] = 'rejected'
            elif action == 'defer':
                # Defer to another approver
                pass

            # Check if deployment is now approved
            if len(approval_request['approvals']) >= approval_request['required_approvals']:
                approval_request['status'] = 'approved'
                approval_request['approved_at'] = datetime.utcnow().isoformat()

            # Update in Redis
            await self.redis.setex(
                f"approval:request:{deployment_id}",
                int((datetime.fromisoformat(approval_request['expires_at']) - datetime.utcnow()).total_seconds()),
                json.dumps(approval_request)
            )

            # Notify other approvers if approved/rejected
            if approval_request['status'] in ['approved', 'rejected']:
                await self._notify_decision(deployment_id, approval_request['status'], approver_id)

            logger.info(f"Approval recorded for deployment {deployment_id}: {action} by {approver_id}")

            return {
                'success': True,
                'status': approval_request['status'],
                'approvals': len(approval_request['approvals']),
                'required': approval_request['required_approvals']
            }

        except Exception as e:
            logger.error(f"Failed to record approval: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    async def get_approval_status(
        self,
        deployment_id: str
    ) -> Dict[str, Any]:
        """
        Get approval status for deployment.

        Args:
            deployment_id: Deployment ID

        Returns:
            Approval status
        """
        try:
            # Get approval request
            request_data = await self.redis.get(f"approval:request:{deployment_id}")
            if not request_data:
                return {
                    'status': 'no_request',
                    'message': 'No approval request found'
                }

            approval_request = json.loads(request_data)

            # Check expiration
            expires_at = datetime.fromisoformat(approval_request['expires_at'])
            time_remaining = expires_at - datetime.utcnow()

            return {
                'deployment_id': deployment_id,
                'status': approval_request['status'],
                'required_approvals': approval_request['required_approvals'],
                'current_approvals': len(approval_request.get('approvals', [])),
                'rejections': len(approval_request.get('rejections', [])),
                'approvers': approval_request.get('approvers', []),
                'expires_at': approval_request['expires_at'],
                'time_remaining_seconds': int(time_remaining.total_seconds()) if time_remaining > timedelta() else 0,
                'approvals': approval_request.get('approvals', []),
                'rejection_details': approval_request.get('rejections', [])
            }

        except Exception as e:
            logger.error(f"Failed to get approval status: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }

    async def escalate_approval(
        self,
        deployment_id: str,
        escalation_level: int = 1
    ) -> bool:
        """
        Escalate approval request to higher level.

        Args:
            deployment_id: Deployment ID
            escalation_level: Level of escalation

        Returns:
            True if escalated successfully
        """
        try:
            logger.info(f"Escalating approval for deployment {deployment_id} to level {escalation_level}")

            # Get current approval request
            request_data = await self.redis.get(f"approval:request:{deployment_id}")
            if not request_data:
                return False

            approval_request = json.loads(request_data)

            # Get escalation approvers
            escalation_approvers = await self._get_escalation_approvers(escalation_level)
            if not escalation_approvers:
                logger.error(f"No escalation approvers found for level {escalation_level}")
                return False

            # Add escalation approvers
            current_approvers = set(approval_request.get('approvers', []))
            current_approvers.update(escalation_approvers)
            approval_request['approvers'] = list(current_approvers)
            approval_request['escalation_level'] = escalation_level
            approval_request['escalated_at'] = datetime.utcnow().isoformat()

            # Extend expiration time
            approval_request['expires_at'] = (
                datetime.utcnow() + timedelta(hours=12)
            ).isoformat()

            # Update in Redis
            await self.redis.setex(
                f"approval:request:{deployment_id}",
                43200,  # 12 hours
                json.dumps(approval_request)
            )

            # Notify escalation approvers
            await self._notify_escalation(deployment_id, escalation_approvers, escalation_level)

            return True

        except Exception as e:
            logger.error(f"Failed to escalate approval: {e}")
            return False

    async def auto_approve(
        self,
        deployment_id: str,
        criteria: Dict[str, Any]
    ) -> bool:
        """
        Auto-approve deployment based on criteria.

        Args:
            deployment_id: Deployment ID
            criteria: Auto-approval criteria

        Returns:
            True if auto-approved
        """
        try:
            # Check criteria
            if not await self._check_auto_approval_criteria(deployment_id, criteria):
                return False

            # Record auto-approval
            result = await self.record_approval(
                deployment_id,
                'system',
                'approve',
                f"Auto-approved based on criteria: {criteria}"
            )

            return result.get('success', False)

        except Exception as e:
            logger.error(f"Auto-approval failed: {e}")
            return False

    async def _get_eligible_approvers(
        self,
        deployment_id: str
    ) -> List[str]:
        """Get list of eligible approvers."""
        try:
            # Get from auth service
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "http://auth-service:8081/auth/users",
                    params={"role": "deployment_approver"},
                    headers={"Authorization": f"Bearer {await self._get_service_token()}"}
                )

                if response.status_code == 200:
                    users = response.json()
                    return [u['id'] for u in users]

            return []

        except Exception as e:
            logger.error(f"Failed to get eligible approvers: {e}")
            return []

    async def _get_escalation_approvers(
        self,
        level: int
    ) -> List[str]:
        """Get escalation approvers for level."""
        escalation_roles = {
            1: "senior_approver",
            2: "manager_approver",
            3: "director_approver"
        }

        role = escalation_roles.get(level, "senior_approver")

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "http://auth-service:8081/auth/users",
                    params={"role": role},
                    headers={"Authorization": f"Bearer {await self._get_service_token()}"}
                )

                if response.status_code == 200:
                    users = response.json()
                    return [u['id'] for u in users]

            return []

        except Exception as e:
            logger.error(f"Failed to get escalation approvers: {e}")
            return []

    async def _notify_approvers(
        self,
        deployment_id: str,
        approvers: List[str],
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Send notifications to approvers."""
        try:
            # Send via notification service
            async with httpx.AsyncClient() as client:
                for approver_id in approvers:
                    await client.post(
                        "http://monitoring-service:8085/notify",
                        json={
                            "recipient": approver_id,
                            "type": "approval_request",
                            "subject": f"Deployment Approval Required: {deployment_id}",
                            "message": f"Please review and approve deployment {deployment_id}",
                            "priority": "high",
                            "metadata": metadata
                        },
                        headers={"Authorization": f"Bearer {await self._get_service_token()}"}
                    )

        except Exception as e:
            logger.error(f"Failed to notify approvers: {e}")

    async def _notify_decision(
        self,
        deployment_id: str,
        decision: str,
        approver_id: str
    ):
        """Notify about approval decision."""
        try:
            # Get approval request for approvers list
            request_data = await self.redis.get(f"approval:request:{deployment_id}")
            if not request_data:
                return

            approval_request = json.loads(request_data)
            approvers = approval_request.get('approvers', [])

            # Notify all approvers
            async with httpx.AsyncClient() as client:
                for approver in approvers:
                    if approver != approver_id:
                        await client.post(
                            "http://monitoring-service:8085/notify",
                            json={
                                "recipient": approver,
                                "type": "approval_decision",
                                "subject": f"Deployment {deployment_id} {decision}",
                                "message": f"Deployment {deployment_id} has been {decision} by {approver_id}",
                                "priority": "normal"
                            },
                            headers={"Authorization": f"Bearer {await self._get_service_token()}"}
                        )

        except Exception as e:
            logger.error(f"Failed to notify decision: {e}")

    async def _notify_escalation(
        self,
        deployment_id: str,
        approvers: List[str],
        level: int
    ):
        """Notify escalation approvers."""
        try:
            async with httpx.AsyncClient() as client:
                for approver in approvers:
                    await client.post(
                        "http://monitoring-service:8085/notify",
                        json={
                            "recipient": approver,
                            "type": "escalation",
                            "subject": f"ESCALATION: Deployment {deployment_id} requires approval",
                            "message": f"Deployment {deployment_id} has been escalated to level {level}",
                            "priority": "urgent"
                        },
                        headers={"Authorization": f"Bearer {await self._get_service_token()}"}
                    )

        except Exception as e:
            logger.error(f"Failed to notify escalation: {e}")

    async def _mark_expired(
        self,
        deployment_id: str
    ):
        """Mark approval request as expired."""
        try:
            request_data = await self.redis.get(f"approval:request:{deployment_id}")
            if request_data:
                approval_request = json.loads(request_data)
                approval_request['status'] = 'expired'
                approval_request['expired_at'] = datetime.utcnow().isoformat()

                await self.redis.set(
                    f"approval:request:{deployment_id}:expired",
                    json.dumps(approval_request),
                    ex=86400  # Keep for 24 hours
                )

                await self.redis.delete(f"approval:request:{deployment_id}")

        except Exception as e:
            logger.error(f"Failed to mark expired: {e}")

    async def _check_auto_approval_criteria(
        self,
        deployment_id: str,
        criteria: Dict[str, Any]
    ) -> bool:
        """Check if deployment meets auto-approval criteria."""
        try:
            # Get deployment info
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://localhost:8083/deploy/{deployment_id}/status",
                    headers={"Authorization": f"Bearer {await self._get_service_token()}"}
                )

                if response.status_code != 200:
                    return False

                deployment = response.json()

            # Check criteria
            if criteria.get('max_devices'):
                if len(deployment.get('devices', [])) > criteria['max_devices']:
                    return False

            if criteria.get('allowed_strategies'):
                if deployment.get('strategy') not in criteria['allowed_strategies']:
                    return False

            if criteria.get('dry_run_only'):
                if not deployment.get('dry_run', False):
                    return False

            if criteria.get('time_window'):
                current_hour = datetime.utcnow().hour
                allowed_hours = criteria['time_window']
                if current_hour not in allowed_hours:
                    return False

            return True

        except Exception as e:
            logger.error(f"Failed to check auto-approval criteria: {e}")
            return False

    async def _get_service_token(self) -> str:
        """Get service authentication token."""
        token = await self.vault.get_secret("service/tokens/deployment")
        return token['token'] if token else ""