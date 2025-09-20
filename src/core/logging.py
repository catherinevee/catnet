"""
Logging configuration for CatNet
import logging
import sys
from typing import Optional
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
import json
from datetime import datetime
from pathlib import Path


class StructuredFormatter(logging.Formatter):
    """JSON structured logging formatter"""TODO: Add docstring"""
        log_obj = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        if hasattr(record, "user_id"):
            log_obj["user_id"] = record.user_id

        if hasattr(record, "device_id"):
            log_obj["device_id"] = record.device_id

        if hasattr(record, "deployment_id"):
            log_obj["deployment_id"] = record.deployment_id

        return json.dumps(log_obj)


def setup_logging(
        log_level: str = "INFO",
        log_file: Optional[str] = None,
        structured: bool = True,
) -> None:
    """
    Setup logging configuration
    Args:
        log_level: Logging level(DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Optional log file path
            structured: Use structured JSON logging"""
    level = getattr(logging, log_level.upper(), logging.INFO)

    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove default handlers
    root_logger.handlers = []

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)

    if structured:
        console_handler.setFormatter(StructuredFormatter())
        else:
        console_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        console_handler.setFormatter(console_formatter)

    root_logger.addHandler(console_handler)

    # File handler if specified
    if log_file:
        # Create log directory if needed
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Choose handler based on configuration
        # Use TimedRotatingFileHandler for daily rotation
        use_timed_rotation = log_file.endswith(".daily.log")

        if use_timed_rotation:
            # Daily rotation at midnight
            file_handler = TimedRotatingFileHandler(
                log_file,
                when="midnight",
                interval=1,
                backupCount=30,  # Keep 30 days
                encoding="utf-8",
            )
        else:
            # Size-based rotation (10MB max, keep 5 backups)
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=5,
            )
        file_handler.setLevel(level)

        if structured:
            file_handler.setFormatter(StructuredFormatter())
            else:
            file_formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            file_handler.setFormatter(file_formatter)

        root_logger.addHandler(file_handler)

    # Set specific loggers
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    logging.getLogger("netmiko").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    Get a logger instance
    Args:
        name: Logger name(usually __name__)
    Returns:
        Logger instance"""
    return logging.getLogger(name)


class AuditLogAdapter(logging.LoggerAdapter):
    Logger adapter for adding context to audit logs"""

    def process(self, msg, kwargs):
        """TODO: Add docstring"""
        if "extra" not in kwargs:
            kwargs["extra"] = {}

        # Add context from adapter
        if hasattr(self, "user_id"):
            kwargs["extra"]["user_id"] = self.user_id

        if hasattr(self, "device_id"):
            kwargs["extra"]["device_id"] = self.device_id

        if hasattr(self, "deployment_id"):
            kwargs["extra"]["deployment_id"] = self.deployment_id

        return msg, kwargs


# Initialize logging on module import
setup_logging()

# Export commonly used logger
logger = get_logger(__name__)
