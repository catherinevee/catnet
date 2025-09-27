"""
CatNet Main Application
Enterprise-grade network configuration management system
"""

import sys
import os
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Any, Dict

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
from src.security.audit import AuditLogger
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

        yield

    except Exception as e:
        logger.error("Failed to start CatNet", error=str(e))
        raise

    finally:
        # Shutdown
        logger.info("Shutting down CatNet application")

        # Close database connections
        if db_manager:
            await db_manager.close()

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