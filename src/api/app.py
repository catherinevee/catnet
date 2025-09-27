from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import structlog
import time
import uuid
from typing import Optional
from prometheus_client import make_asgi_app, Counter, Histogram, Gauge
import asyncio

from ..db.database import database, init_db
from ..security.vault import VaultClient
from .routes import (
    auth_endpoints,
    deployment_endpoints,
    device_endpoints,
    gitops_endpoints,
    admin_endpoints,
    health_endpoints
)
from .middleware.security import SecurityMiddleware
from .middleware.rate_limit import RateLimitMiddleware
from .middleware.audit import AuditMiddleware

logger = structlog.get_logger()

# Prometheus metrics
request_count = Counter(
    'catnet_requests_total',
    'Total requests',
    ['method', 'endpoint', 'status']
)

request_duration = Histogram(
    'catnet_request_duration_seconds',
    'Request duration',
    ['method', 'endpoint']
)

active_connections = Gauge(
    'catnet_active_connections',
    'Active connections'
)

deployment_count = Counter(
    'catnet_deployments_total',
    'Total deployments',
    ['status', 'strategy']
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""

    # Startup
    logger.info("Starting CatNet application...")

    try:
        # Initialize database
        await init_db()
        logger.info("Database initialized successfully")

        # Initialize Vault connection
        vault = VaultClient()
        if vault.health_check():
            logger.info("Vault connection established")
        else:
            logger.warning("Vault connection failed - running in degraded mode")

        # Start background tasks
        app.state.background_tasks = []

        # Start device session cleanup task
        from ..devices.secure_connector import secure_device_connector
        cleanup_task = asyncio.create_task(device_session_cleanup())
        app.state.background_tasks.append(cleanup_task)

        # Start metric collection
        metric_task = asyncio.create_task(collect_metrics())
        app.state.background_tasks.append(metric_task)

        logger.info("CatNet application started successfully")

    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        raise

    yield

    # Shutdown
    logger.info("Shutting down CatNet application...")

    try:
        # Cancel background tasks
        for task in app.state.background_tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # Close database connections
        await database.close()

        # Clean up device connections
        from ..devices.secure_connector import secure_device_connector
        await secure_device_connector.cleanup_stale_sessions()

        # Clean up GitOps temporary directories
        from ..gitops.gitops_service import gitops_service
        await gitops_service.cleanup()

        logger.info("CatNet application shutdown complete")

    except Exception as e:
        logger.error(f"Error during shutdown: {e}")


# Create FastAPI application
app = FastAPI(
    title="CatNet - Network Configuration Deployment System",
    description="Security-first, GitOps-enabled network configuration deployment",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://localhost:3000"],  # Configure based on environment
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"]
)

# Add security headers
app.add_middleware(SecurityMiddleware)

# Add trusted host validation
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "*.catnet.local"]
)

# Add compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Add rate limiting
app.add_middleware(RateLimitMiddleware)

# Add audit logging
app.add_middleware(AuditMiddleware)

# Mount Prometheus metrics endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# Include routers
app.include_router(auth_endpoints.router)
app.include_router(deployment_endpoints.router)
app.include_router(device_endpoints.router)
app.include_router(gitops_endpoints.router)
app.include_router(admin_endpoints.router)
app.include_router(health_endpoints.router)


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Add unique request ID to each request"""
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = request_id

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id

    return response


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests with timing"""
    start_time = time.time()

    # Log request
    logger.info(
        "Request received",
        method=request.method,
        path=request.url.path,
        client=request.client.host if request.client else None,
        request_id=getattr(request.state, "request_id", None)
    )

    try:
        response = await call_next(request)

        # Calculate duration
        duration = time.time() - start_time

        # Log response
        logger.info(
            "Request completed",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration=duration,
            request_id=getattr(request.state, "request_id", None)
        )

        # Update metrics
        request_count.labels(
            method=request.method,
            endpoint=request.url.path,
            status=response.status_code
        ).inc()

        request_duration.labels(
            method=request.method,
            endpoint=request.url.path
        ).observe(duration)

        return response

    except Exception as e:
        duration = time.time() - start_time

        logger.error(
            "Request failed",
            method=request.method,
            path=request.url.path,
            error=str(e),
            duration=duration,
            request_id=getattr(request.state, "request_id", None)
        )

        # Update error metrics
        request_count.labels(
            method=request.method,
            endpoint=request.url.path,
            status=500
        ).inc()

        raise


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors"""

    logger.warning(
        "Validation error",
        path=request.url.path,
        errors=exc.errors(),
        request_id=getattr(request.state, "request_id", None)
    )

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": exc.errors(),
            "message": "Validation error",
            "request_id": getattr(request.state, "request_id", None)
        }
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""

    logger.warning(
        "HTTP exception",
        path=request.url.path,
        status_code=exc.status_code,
        detail=exc.detail,
        request_id=getattr(request.state, "request_id", None)
    )

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "request_id": getattr(request.state, "request_id", None)
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions"""

    logger.error(
        "Unhandled exception",
        path=request.url.path,
        error=str(exc),
        request_id=getattr(request.state, "request_id", None),
        exc_info=exc
    )

    # Don't expose internal errors to client
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error",
            "request_id": getattr(request.state, "request_id", None)
        }
    )


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "CatNet",
        "version": "1.0.0",
        "status": "operational",
        "description": "Network Configuration Deployment System"
    }


@app.get("/api/v1/info")
async def api_info():
    """API information endpoint"""
    return {
        "api_version": "1.0.0",
        "supported_vendors": [
            "cisco_ios",
            "cisco_ios_xe",
            "cisco_nx_os",
            "juniper_junos"
        ],
        "deployment_strategies": [
            "rolling",
            "canary",
            "blue_green",
            "all_at_once"
        ],
        "authentication_methods": [
            "jwt",
            "oauth2",
            "saml"
        ],
        "features": {
            "mfa_enabled": True,
            "vault_integration": True,
            "gitops_enabled": True,
            "auto_rollback": True,
            "encryption": "AES-256-GCM"
        }
    }


async def device_session_cleanup():
    """Background task to clean up stale device sessions"""

    while True:
        try:
            from ..devices.secure_connector import secure_device_connector
            await secure_device_connector.cleanup_stale_sessions()

        except Exception as e:
            logger.error(f"Device session cleanup error: {e}")

        # Run every 5 minutes
        await asyncio.sleep(300)


async def collect_metrics():
    """Background task to collect system metrics"""

    while True:
        try:
            # Update active connections metric
            from ..devices.secure_connector import secure_device_connector
            sessions = await secure_device_connector.get_active_sessions()
            active_connections.set(len(sessions))

        except Exception as e:
            logger.error(f"Metric collection error: {e}")

        # Collect every 30 seconds
        await asyncio.sleep(30)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8080,
        reload=False,
        log_config={
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {
                    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                },
            },
            "handlers": {
                "default": {
                    "formatter": "default",
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                },
            },
            "root": {
                "level": "INFO",
                "handlers": ["default"],
            },
        }
    )