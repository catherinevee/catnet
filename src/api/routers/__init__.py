"""
CatNet API Routers Package
Secure network configuration deployment system API endpoints
"""

from .auth import router as auth_router
from .devices import router as devices_router
from .deployments import router as deployments_router
from .git import router as git_router
from .health import router as health_router
from .admin import router as admin_router

__all__ = [
    'auth_router',
    'devices_router',
    'deployments_router',
    'git_router',
    'health_router',
    'admin_router'
]