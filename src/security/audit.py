import asyncio
import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from enum import Enum
import uuid
from pathlib import Path
import aiofiles
import logging
from sqlalchemy.ext.asyncio import AsyncSession


class AuditLevel(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    SECURITY = "SECURITY"


class AuditEvent:
    def __init__(
        self,
        event_type: str,
        user_id: Optional[str],
        details: Dict[str, Any],
        level: AuditLevel = AuditLevel.INFO,
    ):
        self.id = str(uuid.uuid4())
        self.timestamp = datetime.now(timezone.utc)
        self.event_type = event_type
        self.user_id = user_id
        self.details = details
        self.level = level
        self.hash = self._calculate_hash()

    def _calculate_hash(self) -> str:
        data = json.dumps(
            {
                "id": self.id,
                "timestamp": self.timestamp.isoformat(),
                "event_type": self.event_type,
                "user_id": self.user_id,
                "details": self.details,
                "level": self.level.value,
            },
            sort_keys=True,
        )
        return hashlib.sha256(data.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "user_id": self.user_id,
            "details": self.details,
            "level": self.level.value,
            "hash": self.hash,
        }


class AuditLogger:
    def __init__(
        self,
        log_file: Optional[str] = None,
        db_session: Optional[AsyncSession] = None,
        enable_console: bool = True,
    ):
        self.log_file = Path(log_file) if log_file else Path("logs/audit.jsonl")
        self.db_session = db_session
        self.enable_console = enable_console
        self.logger = logging.getLogger("audit")
        self._setup_logger()
        self.event_queue = asyncio.Queue()
        self.session_recordings = {}
        self._ensure_log_dir()

    def _ensure_log_dir(self):
        """TODO: Add docstring"""
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def _setup_logger(self):
        """TODO: Add docstring"""
        if self.enable_console:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    async def log_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        level: AuditLevel = AuditLevel.INFO,
    ) -> str:
        event = AuditEvent(
            event_type=event_type,
            user_id=user_id,
            details=details or {},
            level=level,
        )

        await self.event_queue.put(event)

        # Write to file
        await self._write_to_file(event)

        # Write to database if available
        if self.db_session:
            await self._write_to_db(event)

        # Log to console if enabled
        if self.enable_console:
            # Map our custom levels to standard logging levels
            level_map = {
                "INFO": logging.INFO,
                "WARNING": logging.WARNING,
                "ERROR": logging.ERROR,
                "CRITICAL": logging.CRITICAL,
                "SECURITY": logging.WARNING,  # Map SECURITY to WARNING
            }
            log_level = level_map.get(level.value, logging.INFO)
            self.logger.log(
                log_level,
                f"[{event_type}] User: {user_id} - {json.dumps(details)}",
            )

        return event.id

    async def _write_to_file(self, event: AuditEvent):
        """TODO: Add docstring"""
        async with aiofiles.open(self.log_file, "a") as f:
            await f.write(json.dumps(event.to_dict()) + "\n")

    async def _write_to_db(self, event: AuditEvent):
        """TODO: Add docstring"""
        # This would write to database - implementation depends on your ORM
        pass

    async def log_authentication(
        self,
        user_id: str,
        success: bool,
        method: str,
        ip_address: str,
        user_agent: Optional[str] = None,
    ):
        level = AuditLevel.INFO if success else AuditLevel.WARNING
        await self.log_event(
            event_type="authentication",
            user_id=user_id,
            details={
                "success": success,
                "method": method,
                "ip_address": ip_address,
                "user_agent": user_agent,
            },
            level=level,
        )

    async def log_deployment(
        self,
        deployment_id: str,
        user_id: str,
        action: str,
        devices: List[str],
        status: str,
    ):
        await self.log_event(
            event_type="deployment",
            user_id=user_id,
            details={
                "deployment_id": deployment_id,
                "action": action,
                "devices": devices,
                "status": status,
            },
            level=AuditLevel.INFO,
        )

    async def log_security_incident(
        self,
        incident_type: str,
        user_id: Optional[str],
        details: Dict[str, Any],
    ):
        await self.log_event(
            event_type="security_incident",
            user_id=user_id,
            details={"incident_type": incident_type, **details},
            level=AuditLevel.SECURITY,
        )

    async def log_unauthorized_attempt(
        self, user_context: Dict[str, Any], resource: str, action: str
    ):
        await self.log_event(
            event_type="unauthorized_access",
            user_id=user_context.get("user_id"),
            details={
                "resource": resource,
                "action": action,
                "user_context": user_context,
            },
            level=AuditLevel.SECURITY,
        )

    async def log_configuration_change(
        self,
        user_id: str,
        device_id: str,
        change_type: str,
        old_config_hash: Optional[str],
        new_config_hash: str,
    ):
        await self.log_event(
            event_type="configuration_change",
            user_id=user_id,
            details={
                "device_id": device_id,
                "change_type": change_type,
                "old_config_hash": old_config_hash,
                "new_config_hash": new_config_hash,
            },
            level=AuditLevel.INFO,
        )

    async def start_session_recording(
        self, session_id: str, user_id: str, device_id: str
    ):
        self.session_recordings[session_id] = {
            "user_id": user_id,
            "device_id": device_id,
            "start_time": datetime.now(timezone.utc),
            "commands": [],
        }

        await self.log_event(
            event_type="session_started",
            user_id=user_id,
            details={"session_id": session_id, "device_id": device_id},
            level=AuditLevel.INFO,
        )

    async def record_command(self, session_id: str, command: str, output: str):
        """TODO: Add docstring"""
        if session_id in self.session_recordings:
            self.session_recordings[session_id]["commands"].append(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "command": command,
                    "output": output[:1000],  # Limit output size
                }
            )

    async def end_session_recording(self, session_id: str):
        """TODO: Add docstring"""
        if session_id in self.session_recordings:
            session = self.session_recordings[session_id]
            await self.log_event(
                event_type="session_ended",
                user_id=session["user_id"],
                details={
                    "session_id": session_id,
                    "device_id": session["device_id"],
                    "duration": (
                        datetime.now(timezone.utc) - session["start_time"]
                    ).total_seconds(),
                    "command_count": len(session["commands"]),
                },
                level=AuditLevel.INFO,
            )
            del self.session_recordings[session_id]

    async def search_logs(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        event_type: Optional[str] = None,
        user_id: Optional[str] = None,
        level: Optional[AuditLevel] = None,
    ) -> List[Dict[str, Any]]:
        results = []

        async with aiofiles.open(self.log_file, "r") as f:
            async for line in f:
                try:
                    event = json.loads(line)

                    # Apply filters
                    if (
                        start_date
                        and datetime.fromisoformat(event["timestamp"]) < start_date
                    ):
                        continue
                    if (
                        end_date
                        and datetime.fromisoformat(event["timestamp"]) > end_date
                    ):
                        continue
                    if event_type and event["event_type"] != event_type:
                        continue
                    if user_id and event["user_id"] != user_id:
                        continue
                    if level and event["level"] != level.value:
                        continue

                    results.append(event)
                except json.JSONDecodeError:
                    continue

        return results

    async def verify_log_integrity(self) -> bool:
        async with aiofiles.open(self.log_file, "r") as f:
            async for line in f:
                try:
                    event_dict = json.loads(line)
                    stored_hash = event_dict.pop("hash")

                    # Recalculate hash
                    data = json.dumps(event_dict, sort_keys=True)
                    calculated_hash = hashlib.sha256(data.encode()).hexdigest()

                    if stored_hash != calculated_hash:
                        return False
                except (json.JSONDecodeError, KeyError):
                    return False

        return True
