"""
CatNet Audit Logging System
Provides immutable, cryptographically signed audit logs for compliance
CRITICAL: Audit logging is MANDATORY for all operations
"""

import os
import json
import hashlib
import hmac
import uuid
import asyncio
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import aiofiles
import structlog

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..db.models import AuditLog, AuditAction
from ..core.exceptions import AuditLogFailureError


logger = structlog.get_logger()


class AuditSeverity(Enum):
    """Audit event severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    SECURITY = "security"


@dataclass
class AuditEvent:
    """Audit event data structure"""
    timestamp: str
    correlation_id: str
    action: str
    actor: str  # User or service
    resource_type: Optional[str]
    resource_id: Optional[str]
    ip_address: Optional[str]
    session_id: Optional[str]
    success: bool
    severity: str
    details: Dict[str, Any]
    signature: Optional[str] = None
    previous_hash: Optional[str] = None


class ImmutableAuditLogger:
    """
    Immutable audit logger with cryptographic integrity
    Implements blockchain-like hash chaining for tamper evidence
    """

    def __init__(self, audit_path: str = "/var/log/catnet/audit"):
        self.audit_path = Path(audit_path)
        self.audit_path.mkdir(parents=True, exist_ok=True)

        # Cryptographic signing key (should come from Vault in production)
        self.signing_key = os.environ.get("CATNET_AUDIT_KEY", "").encode()
        if not self.signing_key:
            self.signing_key = os.urandom(32)

        # Hash chain state
        self._previous_hash = None
        self._hash_chain_file = self.audit_path / "hash_chain.json"
        self._load_hash_chain()

        # Session recording
        self.session_path = self.audit_path / "sessions"
        self.session_path.mkdir(parents=True, exist_ok=True)

        # Write buffer for performance
        self._write_buffer = []
        self._buffer_size = 10
        self._flush_task = None

    def _load_hash_chain(self):
        """Load the previous hash from chain file"""
        try:
            if self._hash_chain_file.exists():
                with open(self._hash_chain_file, 'r') as f:
                    chain_data = json.load(f)
                    self._previous_hash = chain_data.get('last_hash')
        except Exception as e:
            logger.error(f"Failed to load hash chain: {e}")

    def _save_hash_chain(self, new_hash: str):
        """Save the current hash to chain file"""
        try:
            chain_data = {
                'last_hash': new_hash,
                'updated_at': datetime.utcnow().isoformat()
            }
            with open(self._hash_chain_file, 'w') as f:
                json.dump(chain_data, f)
            self._previous_hash = new_hash
        except Exception as e:
            logger.error(f"Failed to save hash chain: {e}")

    def _compute_signature(self, data: str) -> str:
        """Compute HMAC-SHA256 signature for audit entry"""
        h = hmac.new(self.signing_key, data.encode('utf-8'), hashlib.sha256)
        return h.hexdigest()

    def _compute_hash(self, event: AuditEvent) -> str:
        """Compute SHA-256 hash including previous hash for chaining"""
        event_dict = asdict(event)
        event_dict.pop('signature', None)  # Don't include signature in hash

        # Include previous hash for chaining
        if self._previous_hash:
            event_dict['previous_hash'] = self._previous_hash

        event_json = json.dumps(event_dict, sort_keys=True)
        return hashlib.sha256(event_json.encode('utf-8')).hexdigest()

    async def log_event(
        self,
        action: str,
        actor: str,
        success: bool,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        severity: AuditSeverity = AuditSeverity.INFO,
        ip_address: Optional[str] = None,
        session_id: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> str:
        """
        Log an audit event with cryptographic integrity
        Returns: Event ID
        """
        try:
            # Create audit event
            event = AuditEvent(
                timestamp=datetime.utcnow().isoformat(),
                correlation_id=correlation_id or str(uuid.uuid4()),
                action=action,
                actor=actor,
                resource_type=resource_type,
                resource_id=resource_id,
                ip_address=ip_address,
                session_id=session_id,
                success=success,
                severity=severity.value,
                details=details or {},
                previous_hash=self._previous_hash
            )

            # Compute hash and signature
            event_hash = self._compute_hash(event)
            event.signature = self._compute_signature(event_hash)

            # Add to buffer
            self._write_buffer.append(event)

            # Flush if buffer is full
            if len(self._write_buffer) >= self._buffer_size:
                await self._flush_buffer()

            # Update hash chain
            self._save_hash_chain(event_hash)

            # For critical events, flush immediately
            if severity in [AuditSeverity.CRITICAL, AuditSeverity.SECURITY]:
                await self._flush_buffer()

            return event.correlation_id

        except Exception as e:
            # Audit logging failure is CRITICAL
            raise AuditLogFailureError(
                message=f"Failed to log audit event: {str(e)}",
                event_type=action
            )

    async def _flush_buffer(self):
        """Flush write buffer to disk"""
        if not self._write_buffer:
            return

        try:
            # Generate filename based on date
            date_str = datetime.utcnow().strftime("%Y%m%d")
            log_file = self.audit_path / f"audit_{date_str}.jsonl"

            # Write events to file
            async with aiofiles.open(log_file, 'a') as f:
                for event in self._write_buffer:
                    event_json = json.dumps(asdict(event))
                    await f.write(event_json + '\n')

                # Ensure data is written to disk
                await f.flush()
                os.fsync(f.fileno())

            # Clear buffer
            self._write_buffer.clear()

        except Exception as e:
            logger.error(f"Failed to flush audit buffer: {e}")
            raise AuditLogFailureError(
                message=f"Failed to write audit log to disk: {str(e)}",
                event_type="flush_buffer"
            )

    async def start_session_recording(self, session_id: str, user_id: str, device_id: str) -> str:
        """Start recording a device session"""
        try:
            session_file = self.session_path / f"session_{session_id}.json"

            session_data = {
                'session_id': session_id,
                'user_id': user_id,
                'device_id': device_id,
                'started_at': datetime.utcnow().isoformat(),
                'commands': []
            }

            async with aiofiles.open(session_file, 'w') as f:
                await f.write(json.dumps(session_data))

            # Log session start
            await self.log_event(
                action="session.start",
                actor=user_id,
                success=True,
                resource_type="device",
                resource_id=device_id,
                details={'session_id': session_id},
                session_id=session_id
            )

            return session_file.as_posix()

        except Exception as e:
            raise AuditLogFailureError(
                message=f"Failed to start session recording: {str(e)}",
                event_type="session_start"
            )

    async def record_session_command(
        self,
        session_id: str,
        command: str,
        output: Optional[str] = None,
        success: bool = True
    ):
        """Record a command in the session"""
        try:
            session_file = self.session_path / f"session_{session_id}.json"

            if not session_file.exists():
                raise ValueError(f"Session {session_id} not found")

            # Read existing session data
            async with aiofiles.open(session_file, 'r') as f:
                content = await f.read()
                session_data = json.loads(content)

            # Add command
            command_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'command': command,
                'output': output[:1000] if output else None,  # Limit output size
                'success': success
            }
            session_data['commands'].append(command_entry)

            # Write updated session
            async with aiofiles.open(session_file, 'w') as f:
                await f.write(json.dumps(session_data))

        except Exception as e:
            logger.error(f"Failed to record session command: {e}")

    async def end_session_recording(self, session_id: str):
        """End a device session recording"""
        try:
            session_file = self.session_path / f"session_{session_id}.json"

            if not session_file.exists():
                return

            # Update session end time
            async with aiofiles.open(session_file, 'r') as f:
                content = await f.read()
                session_data = json.loads(content)

            session_data['ended_at'] = datetime.utcnow().isoformat()
            session_data['duration'] = (
                datetime.fromisoformat(session_data['ended_at']) -
                datetime.fromisoformat(session_data['started_at'])
            ).total_seconds()

            # Write final session data
            async with aiofiles.open(session_file, 'w') as f:
                await f.write(json.dumps(session_data))

            # Archive session
            archive_path = self.session_path / "archive" / datetime.utcnow().strftime("%Y%m")
            archive_path.mkdir(parents=True, exist_ok=True)

            archive_file = archive_path / f"session_{session_id}.json"
            session_file.rename(archive_file)

        except Exception as e:
            logger.error(f"Failed to end session recording: {e}")

    async def verify_audit_integrity(self, date: str) -> bool:
        """Verify the integrity of audit logs for a given date"""
        try:
            log_file = self.audit_path / f"audit_{date}.jsonl"

            if not log_file.exists():
                return False

            previous_hash = None

            async with aiofiles.open(log_file, 'r') as f:
                async for line in f:
                    event_data = json.loads(line)

                    # Verify signature
                    signature = event_data.pop('signature', None)
                    event_hash = hashlib.sha256(
                        json.dumps(event_data, sort_keys=True).encode('utf-8')
                    ).hexdigest()

                    expected_signature = self._compute_signature(event_hash)
                    if signature != expected_signature:
                        logger.error(f"Invalid signature for event: {event_data['correlation_id']}")
                        return False

                    # Verify hash chain
                    if previous_hash and event_data.get('previous_hash') != previous_hash:
                        logger.error(f"Broken hash chain at event: {event_data['correlation_id']}")
                        return False

                    previous_hash = event_hash

            return True

        except Exception as e:
            logger.error(f"Failed to verify audit integrity: {e}")
            return False


class AuditLogger:
    """
    High-level audit logger that integrates with database and immutable logger
    """

    def __init__(self, db_session: Optional[AsyncSession] = None):
        self.db_session = db_session
        self.immutable_logger = ImmutableAuditLogger()
        self._audit_queue = asyncio.Queue()
        self._processing_task = None

    async def start(self):
        """Start the audit logger background tasks"""
        self._processing_task = asyncio.create_task(self._process_audit_queue())

    async def stop(self):
        """Stop the audit logger"""
        if self._processing_task:
            self._processing_task.cancel()
            await self._processing_task

    async def _process_audit_queue(self):
        """Process audit events from queue"""
        while True:
            try:
                event = await self._audit_queue.get()
                await self._persist_audit_event(event)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error processing audit event: {e}")

    async def _persist_audit_event(self, event: Dict[str, Any]):
        """Persist audit event to database"""
        if not self.db_session:
            return

        try:
            audit_log = AuditLog(
                timestamp=datetime.fromisoformat(event['timestamp']),
                user_id=event.get('user_id'),
                service_name=event.get('service_name'),
                ip_address=event.get('ip_address'),
                user_agent=event.get('user_agent'),
                session_id=event.get('session_id'),
                action=AuditAction[event['action'].upper()] if event.get('action') else None,
                resource_type=event.get('resource_type'),
                resource_id=event.get('resource_id'),
                resource_name=event.get('resource_name'),
                request_data=event.get('request_data'),
                response_data=event.get('response_data'),
                changes=event.get('changes'),
                success=event['success'],
                error_code=event.get('error_code'),
                error_message=event.get('error_message'),
                duration_ms=event.get('duration_ms'),
                threat_detected=event.get('threat_detected', False),
                threat_details=event.get('threat_details'),
                compliance_relevant=event.get('compliance_relevant', False),
                compliance_tags=event.get('compliance_tags', []),
                signature=event['signature']
            )

            self.db_session.add(audit_log)
            await self.db_session.commit()

        except Exception as e:
            logger.error(f"Failed to persist audit event: {e}")

    # Authentication and Authorization Logging
    async def log_login(
        self,
        user_id: str,
        ip_address: str,
        success: bool,
        mfa_used: bool = False,
        error_reason: Optional[str] = None
    ):
        """Log user login attempt"""
        await self.immutable_logger.log_event(
            action="auth.login",
            actor=user_id,
            success=success,
            resource_type="user",
            resource_id=user_id,
            details={
                'mfa_used': mfa_used,
                'error_reason': error_reason
            },
            severity=AuditSeverity.SECURITY if not success else AuditSeverity.INFO,
            ip_address=ip_address
        )

    async def log_logout(self, user_id: str, session_id: str):
        """Log user logout"""
        await self.immutable_logger.log_event(
            action="auth.logout",
            actor=user_id,
            success=True,
            resource_type="session",
            resource_id=session_id,
            session_id=session_id
        )

    async def log_permission_check(
        self,
        user_id: str,
        resource_type: str,
        resource_id: str,
        permission: str,
        granted: bool
    ):
        """Log permission check"""
        await self.immutable_logger.log_event(
            action="auth.permission_check",
            actor=user_id,
            success=granted,
            resource_type=resource_type,
            resource_id=resource_id,
            details={'permission': permission},
            severity=AuditSeverity.WARNING if not granted else AuditSeverity.INFO
        )

    # Deployment Logging
    async def log_deployment_created(
        self,
        deployment_id: str,
        user_id: str,
        target_devices: List[str],
        strategy: str
    ):
        """Log deployment creation"""
        await self.immutable_logger.log_event(
            action="deployment.create",
            actor=user_id,
            success=True,
            resource_type="deployment",
            resource_id=deployment_id,
            details={
                'target_devices': target_devices,
                'strategy': strategy,
                'device_count': len(target_devices)
            }
        )

    async def log_deployment_approved(
        self,
        deployment_id: str,
        approver_id: str,
        approval_count: int,
        required_count: int
    ):
        """Log deployment approval"""
        await self.immutable_logger.log_event(
            action="deployment.approve",
            actor=approver_id,
            success=True,
            resource_type="deployment",
            resource_id=deployment_id,
            details={
                'approval_count': approval_count,
                'required_count': required_count,
                'fully_approved': approval_count >= required_count
            }
        )

    async def log_deployment_executed(
        self,
        deployment_id: str,
        device_id: str,
        success: bool,
        error: Optional[str] = None
    ):
        """Log deployment execution on device"""
        await self.immutable_logger.log_event(
            action="deployment.execute",
            actor="system",
            success=success,
            resource_type="device",
            resource_id=device_id,
            details={
                'deployment_id': deployment_id,
                'error': error
            },
            severity=AuditSeverity.ERROR if not success else AuditSeverity.INFO
        )

    async def log_deployment_rollback(
        self,
        deployment_id: str,
        user_id: str,
        reason: str,
        affected_devices: List[str]
    ):
        """Log deployment rollback"""
        await self.immutable_logger.log_event(
            action="deployment.rollback",
            actor=user_id,
            success=True,
            resource_type="deployment",
            resource_id=deployment_id,
            details={
                'reason': reason,
                'affected_devices': affected_devices,
                'device_count': len(affected_devices)
            },
            severity=AuditSeverity.CRITICAL
        )

    # Device Operations Logging
    async def log_device_connection(
        self,
        device_id: str,
        user_id: str,
        success: bool,
        connection_type: str = "ssh",
        error: Optional[str] = None
    ):
        """Log device connection attempt"""
        await self.immutable_logger.log_event(
            action="device.connect",
            actor=user_id,
            success=success,
            resource_type="device",
            resource_id=device_id,
            details={
                'connection_type': connection_type,
                'error': error
            },
            severity=AuditSeverity.WARNING if not success else AuditSeverity.INFO
        )

    async def log_device_command(
        self,
        device_id: str,
        user_id: str,
        command: str,
        success: bool,
        session_id: Optional[str] = None
    ):
        """Log device command execution"""
        # Check if command is sensitive
        sensitive_patterns = ['password', 'secret', 'key', 'credential']
        is_sensitive = any(pattern in command.lower() for pattern in sensitive_patterns)

        await self.immutable_logger.log_event(
            action="device.command",
            actor=user_id,
            success=success,
            resource_type="device",
            resource_id=device_id,
            details={
                'command': command if not is_sensitive else "[REDACTED]",
                'sensitive': is_sensitive
            },
            session_id=session_id,
            severity=AuditSeverity.SECURITY if is_sensitive else AuditSeverity.INFO
        )

    async def log_device_backup(
        self,
        device_id: str,
        user_id: str,
        backup_location: str,
        success: bool
    ):
        """Log device configuration backup"""
        await self.immutable_logger.log_event(
            action="device.backup",
            actor=user_id,
            success=success,
            resource_type="device",
            resource_id=device_id,
            details={'backup_location': backup_location}
        )

    # GitOps Logging
    async def log_webhook_received(
        self,
        repository_id: str,
        event_type: str,
        signature_valid: bool,
        source_ip: str
    ):
        """Log Git webhook reception"""
        await self.immutable_logger.log_event(
            action="gitops.webhook",
            actor="webhook",
            success=signature_valid,
            resource_type="repository",
            resource_id=repository_id,
            details={'event_type': event_type},
            ip_address=source_ip,
            severity=AuditSeverity.SECURITY if not signature_valid else AuditSeverity.INFO
        )

    async def log_config_scan(
        self,
        repository_id: str,
        commit_hash: str,
        secrets_found: bool,
        issues: List[str]
    ):
        """Log configuration security scan"""
        await self.immutable_logger.log_event(
            action="gitops.scan",
            actor="system",
            success=not secrets_found,
            resource_type="repository",
            resource_id=repository_id,
            details={
                'commit_hash': commit_hash,
                'secrets_found': secrets_found,
                'issues': issues
            },
            severity=AuditSeverity.CRITICAL if secrets_found else AuditSeverity.INFO
        )

    # Validation Logging
    async def log_validation(
        self,
        config_hash: str,
        validation_type: str,
        passed: bool,
        errors: List[str],
        warnings: List[str]
    ):
        """Log configuration validation"""
        await self.immutable_logger.log_event(
            action="validation.check",
            actor="system",
            success=passed,
            resource_type="config",
            resource_id=config_hash,
            details={
                'validation_type': validation_type,
                'errors': errors,
                'warnings': warnings,
                'error_count': len(errors),
                'warning_count': len(warnings)
            },
            severity=AuditSeverity.WARNING if not passed else AuditSeverity.INFO
        )

    # Secret Access Logging
    async def log_secret_access(
        self,
        user_id: str,
        secret_path: str,
        action: str,
        success: bool
    ):
        """Log secret access from Vault"""
        await self.immutable_logger.log_event(
            action=f"secret.{action}",
            actor=user_id,
            success=success,
            resource_type="secret",
            resource_id=secret_path,
            severity=AuditSeverity.SECURITY
        )

    # Compliance Logging
    async def log_compliance_check(
        self,
        device_id: str,
        check_type: str,
        passed: bool,
        findings: List[str]
    ):
        """Log compliance check result"""
        await self.immutable_logger.log_event(
            action="compliance.check",
            actor="system",
            success=passed,
            resource_type="device",
            resource_id=device_id,
            details={
                'check_type': check_type,
                'findings': findings,
                'finding_count': len(findings)
            },
            severity=AuditSeverity.WARNING if not passed else AuditSeverity.INFO
        )

    # Threat Detection Logging
    async def log_threat_detected(
        self,
        threat_type: str,
        severity: str,
        source_ip: Optional[str],
        user_id: Optional[str],
        details: Dict[str, Any]
    ):
        """Log detected security threat"""
        await self.immutable_logger.log_event(
            action="threat.detected",
            actor=user_id or "system",
            success=False,
            resource_type="security",
            resource_id=threat_type,
            details=details,
            ip_address=source_ip,
            severity=AuditSeverity.CRITICAL
        )


# Singleton instance
_audit_logger = None

def get_audit_logger(db_session: Optional[AsyncSession] = None) -> AuditLogger:
    """Get or create audit logger singleton"""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger(db_session)
    return _audit_logger