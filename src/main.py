"""
CatNet Main Application
Enterprise-grade network configuration management system
"""

import sys
import os
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Any, Dict
import time
import asyncio

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from prometheus_fastapi_instrumentator import Instrumentator
from prometheus_client import Counter, Histogram, Gauge
import structlog
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from src.core.config import get_settings
from src.core.exceptions import CatNetError
from src.db.database import init_database, get_database_manager
from src.api import (
    auth_router,
    devices_router,
    deployments_router,
    git_router,
    health_router,
    admin_router
)
from src.api.routes import discovery_endpoints, monitoring_endpoints
from src.cache.redis_cache import redis_cache
from src.api.middleware.cache_middleware import (
    CacheMiddleware,
    CacheInvalidationMiddleware,
    ConditionalCacheMiddleware
)
from src.monitoring.health_monitor import health_monitor, sla_monitor
from src.security.audit import AuditLogger
from src.api.routes import security_audit_endpoints
from src.security.security_scanner import security_scanner
from src.auth.mfa import mfa_manager
from src.auth.api_key_manager import api_key_manager
from src.middleware import (
    SecurityMiddleware,
    RequestLoggingMiddleware,
    MTLSMiddleware
)

# Initialize settings
settings = get_settings()

# Initialize structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)
# Custom Prometheus metrics
custom_request_count = Counter(
    'catnet_requests_total',
    'Total requests by method, endpoint, and status',
    ['method', 'endpoint', 'status']
)

custom_request_duration = Histogram(
    'catnet_request_duration_seconds',
    'Request duration in seconds',
    ['method', 'endpoint']
)

active_device_connections = Gauge(
    'catnet_active_device_connections',
    'Number of active device connections'
)

deployment_total = Counter(
    'catnet_deployments_total',
    'Total deployments by status and strategy',
    ['status', 'strategy']
)

# Week 5: Security metrics
security_scan_total = Counter(
    'catnet_security_scans_total',
    'Total security scans by type and status',
    ['scan_type', 'status']
)

vulnerability_count = Gauge(
    'catnet_vulnerabilities_total',
    'Current number of vulnerabilities by severity',
    ['severity']
)

security_incidents_total = Counter(
    'catnet_security_incidents_total',
    'Total security incidents by type and severity',
    ['incident_type', 'severity']
)

mfa_verification_total = Counter(
    'catnet_mfa_verifications_total',
    'Total MFA verification attempts by result',
    ['result']
)


async def device_session_cleanup():
    """Background task to clean up stale device sessions"""
    while True:
        try:
            from src.devices.secure_connector import secure_device_connector
            await secure_device_connector.cleanup_stale_sessions()
            logger.debug("Device session cleanup completed")
        except Exception as e:
            logger.error("Device session cleanup error", error=str(e))

        # Run every 5 minutes
        await asyncio.sleep(300)


async def collect_metrics():
    """Background task to collect system metrics"""
    while True:
        try:
            # Update active connections metric
            from src.devices.secure_connector import secure_device_connector
            sessions = await secure_device_connector.get_active_sessions()
            active_device_connections.set(len(sessions))
            logger.debug("Metrics collected", active_sessions=len(sessions))
        except Exception as e:
            logger.error("Metric collection error", error=str(e))

        # Collect every 30 seconds
        await asyncio.sleep(30)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager
    """
    # Startup
    logger.info("Starting CatNet application", environment=settings.environment)

    try:
        # Initialize database
        db_manager = init_database(
            str(settings.database_url),
            pool_size=settings.database_pool_size,
            max_overflow=settings.database_max_overflow,
            echo=settings.database_echo,
            ssl_required=settings.database_ssl_mode == "require"
        )

        # Initialize database tables
        await db_manager.init_database()

        # Initialize audit logger
        audit_logger = AuditLogger()
        await audit_logger.initialize()

        # Log successful startup
        logger.info(
            "CatNet started successfully",
            version="1.0.0",
            environment=settings.environment,
            features={
                "mfa": settings.feature_mfa_enabled,
                "canary": settings.feature_canary_deployment,
                "compliance": settings.feature_compliance_scanning,
                "auto_remediation": settings.feature_auto_remediation
            }
        )

        # Start background tasks
        app.state.background_tasks = []

        # Device session cleanup task
        try:
            cleanup_task = asyncio.create_task(device_session_cleanup())
            app.state.background_tasks.append(cleanup_task)
            logger.info("Background task started: device_session_cleanup")
        except Exception as e:
            logger.warning("Failed to start device cleanup task", error=str(e))

        # Metric collection task
        try:
            metric_task = asyncio.create_task(collect_metrics())
            app.state.background_tasks.append(metric_task)
            logger.info("Background task started: collect_metrics")
        except Exception as e:
            logger.warning("Failed to start metric collection task", error=str(e))

        # Week 4: Initialize Redis cache
        try:
            await redis_cache.connect()
            logger.info("Redis cache connected")
        except Exception as e:
            logger.warning("Failed to connect to Redis cache", error=str(e))

        # Week 4: Start health monitoring
        try:
            health_monitor_task = asyncio.create_task(health_monitor.start_monitoring())
            app.state.background_tasks.append(health_monitor_task)
            logger.info("Background task started: health_monitor")
        except Exception as e:
            logger.warning("Failed to start health monitor", error=str(e))

        # Week 4: Start SLA monitoring (every 5 minutes)
        async def sla_monitoring_loop():
            while True:
                try:
                    await sla_monitor.evaluate_slas()
                    logger.debug("SLA evaluation completed")
                except Exception as e:
                    logger.error("SLA monitoring error", error=str(e))
                await asyncio.sleep(300)

        try:
            sla_monitor_task = asyncio.create_task(sla_monitoring_loop())
            app.state.background_tasks.append(sla_monitor_task)
            logger.info("Background task started: sla_monitor")
        except Exception as e:
            logger.warning("Failed to start SLA monitor", error=str(e))

        yield

    except Exception as e:
        logger.error("Failed to start CatNet", error=str(e))
        raise

    finally:
        # Shutdown
        logger.info("Shutting down CatNet application")

        # Cancel background tasks
        if hasattr(app.state, 'background_tasks'):
            logger.info("Cancelling background tasks")
            for task in app.state.background_tasks:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            logger.info("Background tasks cancelled")

        # Close database connections
        if db_manager:
            await db_manager.close()

        # Week 4: Stop health monitoring
        try:
            await health_monitor.stop_monitoring()
            logger.info("Health monitor stopped")
        except Exception as e:
            logger.warning("Error stopping health monitor", error=str(e))

        # Week 4: Disconnect Redis cache
        try:
            await redis_cache.disconnect()
            logger.info("Redis cache disconnected")
        except Exception as e:
            logger.warning("Error disconnecting Redis cache", error=str(e))

        logger.info("CatNet shutdown complete")

# Create FastAPI application
app = FastAPI(
    title="CatNet API",
    description="Secure Network Configuration Management System",
    version="1.0.0",
    docs_url="/api/docs" if not settings.is_production() else None,
    redoc_url="/api/redoc" if not settings.is_production() else None,
    openapi_url="/api/openapi.json" if not settings.is_production() else None,
    lifespan=lifespan
)

# Add exception handlers
@app.exception_handler(CatNetError)
async def catnet_exception_handler(request: Request, exc: CatNetError):
    """Handle CatNet custom exceptions"""
    logger.error(
        "CatNet error",
        error_code=exc.error_code,
        message=exc.message,
        details=exc.details,
        path=request.url.path
    )

    return JSONResponse(
        status_code=exc.status_code,
        content=exc.to_dict()
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors"""
    logger.warning(
        "Validation error",
        errors=exc.errors(),
        path=request.url.path
    )

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "VALIDATION_ERROR",
            "message": "Request validation failed",
            "details": exc.errors()
        }
    )

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Handle HTTP exceptions"""
    logger.warning(
        "HTTP exception",
        status_code=exc.status_code,
        detail=exc.detail,
        path=request.url.path
    )

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": f"HTTP_{exc.status_code}",
            "message": exc.detail
        }
    )

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """Handle rate limit exceeded"""
    logger.warning(
        "Rate limit exceeded",
        path=request.url.path,
        client=request.client.host if request.client else None
    )

    response = JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={
            "error": "RATE_LIMIT_EXCEEDED",
            "message": f"Rate limit exceeded: {exc.detail}"
        }
    )
    response.headers["Retry-After"] = str(60)
    return response

# Add middleware
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security middleware
app.add_middleware(SecurityMiddleware)

# mTLS middleware (if enabled)
if settings.mtls_enabled:
    app.add_middleware(
        MTLSMiddleware,
        ca_path=str(settings.tls_ca_path),
        verify_mode=settings.mtls_verify_mode
    )

# Request logging
app.add_middleware(RequestLoggingMiddleware)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=settings.cors_allow_methods,
    allow_headers=settings.cors_allow_headers,
)

# Trusted host middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"] if settings.is_development() else settings.cors_origins
)

# Gzip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Custom metrics middleware
@app.middleware("http")
async def custom_metrics_middleware(request: Request, call_next):
    """Collect custom Prometheus metrics"""
    start_time = time.time()

    try:
        response = await call_next(request)
        duration = time.time() - start_time

        # Update metrics
        custom_request_count.labels(
            method=request.method,
            endpoint=request.url.path,
            status=response.status_code
        ).inc()

        custom_request_duration.labels(
            method=request.method,
            endpoint=request.url.path
        ).observe(duration)

        return response

    except Exception as e:
        # Update error metrics
        custom_request_count.labels(
            method=request.method,
            endpoint=request.url.path,
            status=500
        ).inc()
        raise

# Prometheus metrics
if settings.metrics_enabled:
    instrumentator = Instrumentator()
    instrumentator.instrument(app).expose(app, endpoint="/metrics")

# Include routers
app.include_router(
    auth_router,
    prefix="/api/v1/auth",
    tags=["Authentication"]
)

app.include_router(
    devices_router,
    prefix="/api/v1/devices",
    tags=["Devices"]
)

app.include_router(
    deployments_router,
    prefix="/api/v1/deployments",
    tags=["Deployments"]
)

app.include_router(
    git_router,
    prefix="/api/v1/git",
    tags=["GitOps"]
)

app.include_router(
    health_router,
    prefix="/api/v1/health",
    tags=["Health"]
)

app.include_router(
    admin_router,
    prefix="/api/v1/admin",
    tags=["Admin"]
)

# Week 4: Discovery and monitoring routers
app.include_router(
    discovery_endpoints.router,
    tags=["Discovery"]
)

app.include_router(
    monitoring_endpoints.router,
    tags=["Monitoring"]
)

# Week 5: Security audit router
app.include_router(
    security_audit_endpoints.router,
    tags=["Security"]
)

# Week 4: Add cache middleware
app.add_middleware(CacheMiddleware, default_ttl=300)
app.add_middleware(CacheInvalidationMiddleware)
app.add_middleware(ConditionalCacheMiddleware)

# Root endpoint
@app.get("/", include_in_schema=False)
async def root():
    """Root endpoint"""
    return {
        "application": "CatNet",
        "version": "1.0.0",
        "status": "operational",
        "environment": settings.environment
    }

# Health check endpoint
@app.get("/health", include_in_schema=False)
async def health_check():
    """Basic health check"""
    return {"status": "healthy"}

# Ready check endpoint
@app.get("/ready", include_in_schema=False)
async def ready_check():
    """Readiness check"""
    try:
        # Check database connection
        db_manager = get_database_manager()
        db_healthy = await db_manager.health_check()

        if not db_healthy:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"status": "not_ready", "reason": "database_unavailable"}
            )

        return {"status": "ready"}

    except Exception as e:
        logger.error("Readiness check failed", error=str(e))
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "not_ready", "reason": str(e)}
        )

if __name__ == "__main__":
    import uvicorn

    # Run with uvicorn
    uvicorn.run(
        "src.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.is_development(),
        log_level=settings.log_level.lower(),
        ssl_keyfile=str(settings.tls_key_path) if settings.tls_key_path.exists() else None,
        ssl_certfile=str(settings.tls_cert_path) if settings.tls_cert_path.exists() else None,
        ssl_ca_certs=str(settings.tls_ca_path) if settings.tls_ca_path.exists() else None,
        ssl_cert_reqs=2 if settings.mtls_enabled else 0  # 2 = CERT_REQUIRED
    )