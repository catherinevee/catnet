"""
Centralized logging configuration for CatNet
"""
import logging
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
import traceback
import hashlib
from pythonjsonlogger import jsonlogger


class SecurityFilter(logging.Filter):
    """Filter to redact sensitive information from logs"""

    def __init__(self):
        super().__init__()
        self.sensitive_patterns = [
            'password', 'passwd', 'pwd', 'secret', 'token',
            'api_key', 'apikey', 'auth', 'credential', 'private'
        ]

    def filter(self, record: logging.LogRecord) -> bool:
        """Filter and redact sensitive information"""
        # Redact sensitive data from the message
        if hasattr(record, 'msg'):
            record.msg = self._redact_message(str(record.msg))

        # Redact sensitive data from extra fields
        for key in record.__dict__:
            if any(pattern in key.lower() for pattern in self.sensitive_patterns):
                record.__dict__[key] = '***REDACTED***'
            elif isinstance(record.__dict__[key], dict):
                record.__dict__[key] = self._redact_dict(record.__dict__[key])

        return True

    def _redact_message(self, message: str) -> str:
        """Redact sensitive patterns from message"""
        for pattern in self.sensitive_patterns:
            # Case-insensitive replacement
            import re
            regex = re.compile(f'({pattern}[\\s=:]+)([^\\s]+)', re.IGNORECASE)
            message = regex.sub(r'\1***REDACTED***', message)
        return message

    def _redact_dict(self, data: Dict) -> Dict:
        """Recursively redact sensitive data from dictionary"""
        redacted = {}
        for key, value in data.items():
            if any(pattern in key.lower() for pattern in self.sensitive_patterns):
                redacted[key] = '***REDACTED***'
            elif isinstance(value, dict):
                redacted[key] = self._redact_dict(value)
            elif isinstance(value, list):
                redacted[key] = [
                    self._redact_dict(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                redacted[key] = value
        return redacted


class AuditFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter for audit logs"""

    def add_fields(self, log_record: Dict, record: logging.LogRecord, message_dict: Dict):
        """Add custom fields to audit log records"""
        super().add_fields(log_record, record, message_dict)

        # Add timestamp
        log_record['timestamp'] = datetime.utcnow().isoformat()

        # Add log level
        log_record['level'] = record.levelname

        # Add source information
        log_record['module'] = record.module
        log_record['function'] = record.funcName
        log_record['line'] = record.lineno

        # Add process/thread information
        log_record['process_id'] = record.process
        log_record['thread_id'] = record.thread
        log_record['thread_name'] = record.threadName

        # Calculate log hash for integrity
        log_content = json.dumps(log_record, sort_keys=True)
        log_record['integrity_hash'] = hashlib.sha256(log_content.encode()).hexdigest()

        # Add exception information if present
        if record.exc_info:
            log_record['exception'] = {
                'type': record.exc_info[0].__name__ if record.exc_info[0] else None,
                'message': str(record.exc_info[1]) if record.exc_info[1] else None,
                'traceback': traceback.format_exception(*record.exc_info)
            }


class CatNetLogger:
    """Centralized logger configuration for CatNet"""

    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._initialized:
            self._initialized = True
            self.loggers = {}
            self.log_dir = Path('/var/log/catnet')
            self.setup_logging()

    def setup_logging(self):
        """Setup logging configuration"""
        # Create log directory if it doesn't exist
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)

        # Clear existing handlers
        root_logger.handlers = []

        # Console Handler with colored output
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_format)
        console_handler.addFilter(SecurityFilter())
        root_logger.addHandler(console_handler)

        # Application Log File (Rotating)
        app_log_file = self.log_dir / 'catnet.log'
        app_handler = RotatingFileHandler(
            app_log_file,
            maxBytes=100 * 1024 * 1024,  # 100MB
            backupCount=10
        )
        app_handler.setLevel(logging.DEBUG)
        app_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        app_handler.setFormatter(app_format)
        app_handler.addFilter(SecurityFilter())
        root_logger.addHandler(app_handler)

        # Error Log File (Time-based rotation)
        error_log_file = self.log_dir / 'error.log'
        error_handler = TimedRotatingFileHandler(
            error_log_file,
            when='midnight',
            interval=1,
            backupCount=30
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(app_format)
        error_handler.addFilter(SecurityFilter())
        root_logger.addHandler(error_handler)

        # Audit Log File (JSON format, immutable)
        audit_log_file = self.log_dir / 'audit.jsonl'
        audit_handler = RotatingFileHandler(
            audit_log_file,
            maxBytes=500 * 1024 * 1024,  # 500MB
            backupCount=100
        )
        audit_handler.setLevel(logging.INFO)
        audit_formatter = AuditFormatter(
            '%(timestamp)s %(level)s %(name)s %(message)s'
        )
        audit_handler.setFormatter(audit_formatter)
        # No security filter for audit logs - need complete record
        audit_logger = logging.getLogger('audit')
        audit_logger.addHandler(audit_handler)
        audit_logger.setLevel(logging.INFO)
        audit_logger.propagate = False  # Don't propagate to root logger

        # Security Log File (JSON format)
        security_log_file = self.log_dir / 'security.jsonl'
        security_handler = RotatingFileHandler(
            security_log_file,
            maxBytes=200 * 1024 * 1024,  # 200MB
            backupCount=50
        )
        security_handler.setLevel(logging.WARNING)
        security_handler.setFormatter(audit_formatter)
        security_logger = logging.getLogger('security')
        security_logger.addHandler(security_handler)
        security_logger.setLevel(logging.WARNING)
        security_logger.propagate = False

        # Performance Log File
        perf_log_file = self.log_dir / 'performance.log'
        perf_handler = TimedRotatingFileHandler(
            perf_log_file,
            when='hourly',
            interval=1,
            backupCount=168  # 1 week
        )
        perf_handler.setLevel(logging.INFO)
        perf_format = logging.Formatter(
            '%(asctime)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S.%f'
        )
        perf_handler.setFormatter(perf_format)
        perf_logger = logging.getLogger('performance')
        perf_logger.addHandler(perf_handler)
        perf_logger.setLevel(logging.INFO)
        perf_logger.propagate = False

        # Device Communication Log
        device_log_file = self.log_dir / 'device_communication.log'
        device_handler = RotatingFileHandler(
            device_log_file,
            maxBytes=200 * 1024 * 1024,  # 200MB
            backupCount=20
        )
        device_handler.setLevel(logging.DEBUG)
        device_handler.setFormatter(app_format)
        device_handler.addFilter(SecurityFilter())
        device_logger = logging.getLogger('device')
        device_logger.addHandler(device_handler)
        device_logger.setLevel(logging.DEBUG)
        device_logger.propagate = False

        # Deployment Log
        deployment_log_file = self.log_dir / 'deployment.log'
        deployment_handler = RotatingFileHandler(
            deployment_log_file,
            maxBytes=300 * 1024 * 1024,  # 300MB
            backupCount=30
        )
        deployment_handler.setLevel(logging.INFO)
        deployment_handler.setFormatter(app_format)
        deployment_handler.addFilter(SecurityFilter())
        deployment_logger = logging.getLogger('deployment')
        deployment_logger.addHandler(deployment_handler)
        deployment_logger.setLevel(logging.INFO)
        deployment_logger.propagate = False

        # Store logger references
        self.loggers = {
            'root': root_logger,
            'audit': audit_logger,
            'security': security_logger,
            'performance': perf_logger,
            'device': device_logger,
            'deployment': deployment_logger
        }

    def get_logger(self, name: str) -> logging.Logger:
        """Get a logger instance"""
        if name in self.loggers:
            return self.loggers[name]
        return logging.getLogger(name)

    def log_audit_event(
        self,
        event_type: str,
        user: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        resource_id: Optional[str] = None,
        outcome: str = 'success'
    ):
        """Log an audit event"""
        audit_logger = self.get_logger('audit')
        audit_logger.info(
            'Audit Event',
            extra={
                'event_type': event_type,
                'user': user,
                'resource_id': resource_id,
                'outcome': outcome,
                'details': details or {}
            }
        )

    def log_security_event(
        self,
        event_type: str,
        severity: str,
        description: str,
        source_ip: Optional[str] = None,
        user: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log a security event"""
        security_logger = self.get_logger('security')

        log_method = getattr(security_logger, severity.lower(), security_logger.warning)
        log_method(
            'Security Event',
            extra={
                'event_type': event_type,
                'severity': severity,
                'description': description,
                'source_ip': source_ip,
                'user': user,
                'details': details or {}
            }
        )

    def log_performance_metric(
        self,
        operation: str,
        duration_ms: float,
        success: bool,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Log a performance metric"""
        perf_logger = self.get_logger('performance')
        perf_logger.info(
            f"PERF: {operation} - {duration_ms:.2f}ms - {'SUCCESS' if success else 'FAILED'}",
            extra={
                'operation': operation,
                'duration_ms': duration_ms,
                'success': success,
                'metadata': metadata or {}
            }
        )

    def log_device_communication(
        self,
        device_id: str,
        device_name: str,
        action: str,
        command: Optional[str] = None,
        output: Optional[str] = None,
        success: bool = True,
        error: Optional[str] = None
    ):
        """Log device communication"""
        device_logger = self.get_logger('device')

        if success:
            device_logger.info(
                f"Device {device_name}: {action}",
                extra={
                    'device_id': device_id,
                    'device_name': device_name,
                    'action': action,
                    'command': command,
                    'output_length': len(output) if output else 0
                }
            )
        else:
            device_logger.error(
                f"Device {device_name}: {action} failed",
                extra={
                    'device_id': device_id,
                    'device_name': device_name,
                    'action': action,
                    'command': command,
                    'error': error
                }
            )

    def log_deployment_event(
        self,
        deployment_id: str,
        event: str,
        stage: str,
        devices_affected: int,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log deployment event"""
        deployment_logger = self.get_logger('deployment')

        if success:
            deployment_logger.info(
                f"Deployment {deployment_id}: {event} at {stage}",
                extra={
                    'deployment_id': deployment_id,
                    'event': event,
                    'stage': stage,
                    'devices_affected': devices_affected,
                    'details': details or {}
                }
            )
        else:
            deployment_logger.error(
                f"Deployment {deployment_id}: {event} failed at {stage}",
                extra={
                    'deployment_id': deployment_id,
                    'event': event,
                    'stage': stage,
                    'devices_affected': devices_affected,
                    'details': details or {}
                }
            )

    def rotate_logs(self):
        """Force rotation of all log files"""
        for logger in self.loggers.values():
            for handler in logger.handlers:
                if isinstance(handler, (RotatingFileHandler, TimedRotatingFileHandler)):
                    handler.doRollover()

    def get_log_stats(self) -> Dict[str, Any]:
        """Get statistics about log files"""
        stats = {}
        for log_file in self.log_dir.glob('*.log*'):
            stats[log_file.name] = {
                'size_bytes': log_file.stat().st_size,
                'size_mb': round(log_file.stat().st_size / (1024 * 1024), 2),
                'modified': datetime.fromtimestamp(log_file.stat().st_mtime).isoformat()
            }
        return stats


# Global logger instance
catnet_logger = CatNetLogger()


# Convenience functions
def get_logger(name: str) -> logging.Logger:
    """Get a logger instance"""
    return catnet_logger.get_logger(name)


def log_audit(
    event_type: str,
    user: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    resource_id: Optional[str] = None,
    outcome: str = 'success'
):
    """Log an audit event"""
    catnet_logger.log_audit_event(event_type, user, details, resource_id, outcome)


def log_security(
    event_type: str,
    severity: str,
    description: str,
    source_ip: Optional[str] = None,
    user: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
):
    """Log a security event"""
    catnet_logger.log_security_event(event_type, severity, description, source_ip, user, details)


def log_performance(
    operation: str,
    duration_ms: float,
    success: bool,
    metadata: Optional[Dict[str, Any]] = None
):
    """Log a performance metric"""
    catnet_logger.log_performance_metric(operation, duration_ms, success, metadata)


def log_device(
    device_id: str,
    device_name: str,
    action: str,
    command: Optional[str] = None,
    output: Optional[str] = None,
    success: bool = True,
    error: Optional[str] = None
):
    """Log device communication"""
    catnet_logger.log_device_communication(
        device_id, device_name, action, command, output, success, error
    )


def log_deployment(
    deployment_id: str,
    event: str,
    stage: str,
    devices_affected: int,
    success: bool = True,
    details: Optional[Dict[str, Any]] = None
):
    """Log deployment event"""
    catnet_logger.log_deployment_event(
        deployment_id, event, stage, devices_affected, success, details
    )


# Configure logging on module import
catnet_logger.setup_logging()