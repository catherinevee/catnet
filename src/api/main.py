from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer
import structlog
from contextlib import asynccontextmanager

from .middleware.security import SecurityMiddleware, RateLimitMiddleware
from .middleware.audit import AuditMiddleware
from .routes import (
    auth, devices, deployments, gitops, health,
    inventory, monitoring, admin
)
from ..db.database import init_db
from ..services.deployment_scheduler import DeploymentScheduler

logger = structlog.get_logger()

# Global instances
deployment_scheduler = DeploymentScheduler()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    logger.info("Starting CatNet API server")

    # Initialize database
    await init_db()

    # Start deployment scheduler
    await deployment_scheduler.start_scheduler()

    logger.info("CatNet API server started successfully")

    yield

    # Shutdown
    logger.info("Shutting down CatNet API server")

    # Stop deployment scheduler
    await deployment_scheduler.stop_scheduler()

    logger.info("CatNet API server shut down")

# Create FastAPI app
app = FastAPI(
    title="CatNet API",
    description="Secure Network Configuration Deployment System",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)

# Security scheme
security = HTTPBearer()

# Add security middleware
app.add_middleware(
    SecurityMiddleware,
    enforce_https=True,
    max_request_size=10 * 1024 * 1024,  # 10MB
    allowed_content_types=[
        "application/json",
        "multipart/form-data",
        "application/x-www-form-urlencoded"
    ]
)

# Add rate limiting middleware
app.add_middleware(
    RateLimitMiddleware,
    calls_per_minute=100,
    burst_limit=200
)

# Add audit middleware
app.add_middleware(AuditMiddleware)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://localhost:3000", "https://catnet.local"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-RateLimit-Remaining"]
)

# Add trusted host middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "catnet.local", "*.catnet.local"]
)

# Include routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(devices.router, prefix="/api/v1/devices", tags=["Devices"])
app.include_router(deployments.router, prefix="/api/v1/deployments", tags=["Deployments"])
app.include_router(gitops.router, prefix="/api/v1/gitops", tags=["GitOps"])
app.include_router(inventory.router, prefix="/api/v1/inventory", tags=["Inventory"])
app.include_router(monitoring.router, prefix="/api/v1/monitoring", tags=["Monitoring"])
app.include_router(admin.router, prefix="/api/v1/admin", tags=["Administration"])
app.include_router(health.router, prefix="/health", tags=["Health"])

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    from ..core.exceptions import CatNetError
    from fastapi import HTTPException
    from fastapi.responses import JSONResponse

    logger.error(f"Unhandled exception: {exc}", exc_info=True)

    if isinstance(exc, CatNetError):
        return JSONResponse(
            status_code=400,
            content={
                "error": "operation_failed",
                "message": "The requested operation failed",
                "request_id": getattr(request.state, "request_id", "unknown")
            }
        )
    elif isinstance(exc, HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": "http_error",
                "message": exc.detail,
                "request_id": getattr(request.state, "request_id", "unknown")
            }
        )
    else:
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_error",
                "message": "An internal error occurred",
                "request_id": getattr(request.state, "request_id", "unknown")
            }
        )

# Root endpoint
@app.get("/")
async def root():
    return {
        "name": "CatNet API",
        "version": "1.0.0",
        "description": "Secure Network Configuration Deployment System",
        "status": "operational",
        "documentation": "/docs"
    }

# Make deployment scheduler available to routes
app.state.deployment_scheduler = deployment_scheduler