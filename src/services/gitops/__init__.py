"""
CatNet GitOps Microservice.

Handles repository connections, webhook processing, and configuration management.
Runs on port 8082.
"""

from .app import create_app
from .models import (
    Repository,
    WebhookEvent,
    ConfigFile,
    CommitInfo,
    PullRequest,
    ConfigSync
)
from .handlers import (
    RepositoryHandler,
    WebhookHandler,
    ConfigHandler,
    SyncHandler,
    ValidationHandler
)

__all__ = [
    'create_app',
    'Repository',
    'WebhookEvent',
    'ConfigFile',
    'CommitInfo',
    'PullRequest',
    'ConfigSync',
    'RepositoryHandler',
    'WebhookHandler',
    'ConfigHandler',
    'SyncHandler',
    'ValidationHandler',
]

__version__ = '1.0.0'