"""CatNet API module - Router exports."""

# Import routers from routes
from .routes.auth_endpoints import router as auth_router
from .routes.deployment_endpoints import router as deployments_router
from .routes.device_endpoints import router as devices_router
from .routes.gitops_endpoints import router as git_router
from .routes.health_endpoints import router as health_router
from .routes.admin import router as admin_router

__all__ = [
    "auth_router",
    "deployments_router",
    "devices_router",
    "git_router",
    "health_router",
    "admin_router",
]
