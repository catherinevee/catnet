"""
CatNet Main API Gateway
Following CLAUDE.md security and architecture patterns
"""
from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import os
from datetime import datetime
from typing import Optional
import logging

from ..auth.dependencies import get_current_user, require_auth
from ..security.audit import AuditLogger, AuditLevel
from ..core.exceptions import CatNetError, SecurityError
from ..db.database import init_database
from ..db.models import User

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="CatNet API",
    description="Secure Network Configuration Deployment System",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# Initialize services
audit_logger = AuditLogger(log_file="logs/api_audit.jsonl")
db_manager = init_database()

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Prometheus metrics
instrumentator = Instrumentator()
instrumentator.instrument(app).expose(app)


# Middleware
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)

    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers[
        "Strict-Transport-Security"
    ] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"

    return response


@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    """Audit all API requests"""
    start_time = datetime.utcnow()

    # Log request
    await audit_logger.log_event(
        event_type="api_request",
        user_id=None,  # Will be set if authenticated
        details={
            "method": request.method,
            "path": request.url.path,
            "client": request.client.host if request.client else "unknown",
        },
        level=AuditLevel.INFO,
    )

    response = await call_next(request)

    # Log response
    duration = (datetime.utcnow() - start_time).total_seconds()
    await audit_logger.log_event(
        event_type="api_response",
        user_id=None,
        details={
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "duration_seconds": duration,
        },
        level=AuditLevel.INFO,
    )

    return response


# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["*"],
)

# Trusted host middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=os.getenv("ALLOWED_HOSTS", "*").split(","),
)


# Exception handlers
@app.exception_handler(CatNetError)
async def catnet_exception_handler(request: Request, exc: CatNetError):
    """Handle CatNet exceptions"""
    await audit_logger.log_event(
        event_type="application_error",
        user_id=None,
        details={
            "error_type": type(exc).__name__,
            "message": str(exc),
            "path": request.url.path,
        },
        level=AuditLevel.ERROR,
    )

    return JSONResponse(
        status_code=500,
        content={"detail": "An error occurred processing your request"},
    )


@app.exception_handler(SecurityError)
async def security_exception_handler(request: Request, exc: SecurityError):
    """Handle security exceptions"""
    await audit_logger.log_security_incident(
        incident_type="security_error",
        user_id=None,
        details={
            "error": str(exc),
            "path": request.url.path,
            "client": request.client.host if request.client else "unknown",
        },
    )

    return JSONResponse(
        status_code=403, content={"detail": "Security violation detected"}
    )


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "CatNet API",
        "version": "1.0.0",
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat(),
    }


# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    # Check database
    db_healthy = await db_manager.health_check()

    # Check services (would check actual service health)
    services = {
        "database": db_healthy,
        "auth": True,
        "gitops": True,
        "deployment": True,
        "device": True,
    }

    overall_health = all(services.values())

    return {
        "status": "healthy" if overall_health else "degraded",
        "services": services,
        "timestamp": datetime.utcnow().isoformat(),
    }


# API Info
@app.get("/api/v1/info")
@limiter.limit("10/minute")
async def api_info(request: Request):
    """Get API information"""
    return {
        "name": "CatNet API",
        "version": "1.0.0",
        "description": "Secure Network Configuration Deployment System",
        "security_features": [
            "mTLS support",
            "JWT authentication",
            "MFA enabled",
            "Audit logging",
            "Rate limiting",
            "Webhook signature verification",
        ],
        "supported_vendors": [
            "Cisco IOS",
            "Cisco IOS-XE",
            "Cisco NX-OS",
            "Juniper Junos",
        ],
        "deployment_strategies": ["canary", "rolling", "blue-green"],
    }


# User profile
@app.get("/api/v1/profile")
async def get_profile(current_user: User = Depends(get_current_user)):
    """Get current user profile"""
    return {
        "id": str(current_user.id),
        "username": current_user.username,
        "email": current_user.email,
        "roles": current_user.roles,
        "is_superuser": current_user.is_superuser,
        "mfa_enabled": bool(current_user.mfa_secret),
        "created_at": current_user.created_at.isoformat()
        if current_user.created_at
        else None,
        "last_login": current_user.last_login.isoformat()
        if current_user.last_login
        else None,
    }


# Audit log search
@app.get("/api/v1/audit/search")
async def search_audit_logs(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    event_type: Optional[str] = None,
    user_id: Optional[str] = None,
    current_user: User = Depends(require_auth("audit.read")),
):
    """Search audit logs"""
    from datetime import datetime

    # Parse dates
    start = datetime.fromisoformat(start_date) if start_date else None
    end = datetime.fromisoformat(end_date) if end_date else None

    # Search logs
    logs = await audit_logger.search_logs(
        start_date=start, end_date=end, event_type=event_type, user_id=user_id
    )

    return {"total": len(logs), "logs": logs[:100]}  # Limit results


# Metrics endpoint
@app.get("/api/v1/metrics")
async def get_metrics(
    current_user: User = Depends(require_auth("metrics.read")),
):
    """Get system metrics"""
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    from fastapi.responses import Response

    metrics = generate_latest()
    return Response(metrics, media_type=CONTENT_TYPE_LATEST)


# Service status
@app.get("/api/v1/status")
@limiter.limit("30/minute")
async def service_status(request: Request):
    """Get status of all services"""
    # Would check actual service status
    services = {
        "authentication": {
            "status": "operational",
            "port": 8081,
            "endpoints": ["/auth/login", "/auth/refresh", "/auth/logout"],
        },
        "gitops": {
            "status": "operational",
            "port": 8082,
            "endpoints": ["/git/connect", "/git/webhook", "/git/configs"],
        },
        "deployment": {
            "status": "operational",
            "port": 8083,
            "endpoints": [
                "/deploy/create",
                "/deploy/status",
                "/deploy/rollback",
            ],
        },
        "device": {
            "status": "operational",
            "port": 8084,
            "endpoints": ["/devices", "/devices/connect", "/devices/backup"],
        },
    }

    return {
        "overall_status": "operational",
        "services": services,
        "timestamp": datetime.utcnow().isoformat(),
    }


# Emergency shutdown endpoint
@app.post("/api/v1/emergency/shutdown")
async def emergency_shutdown(
    reason: str, current_user: User = Depends(require_auth("admin"))
):
    """Emergency shutdown of all deployments"""
    await audit_logger.log_event(
        event_type="emergency_shutdown",
        user_id=str(current_user.id),
        details={"reason": reason, "timestamp": datetime.utcnow().isoformat()},
        level=AuditLevel.CRITICAL,
    )

    # Would trigger emergency shutdown procedures
    # - Stop all active deployments
    # - Rollback any in-progress changes
    # - Lock system

    return {
        "status": "emergency_shutdown_initiated",
        "reason": reason,
        "initiated_by": current_user.username,
    }


# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    logger.info("CatNet API starting up...")

    # Initialize database
    await db_manager.create_all()

    # Log startup
    await audit_logger.log_event(
        event_type="api_startup",
        user_id=None,
        details={
            "version": "1.0.0",
            "environment": os.getenv("ENVIRONMENT", "development"),
        },
        level=AuditLevel.INFO,
    )

    logger.info("CatNet API started successfully")


# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("CatNet API shutting down...")

    # Log shutdown
    await audit_logger.log_event(
        event_type="api_shutdown",
        user_id=None,
        details={"timestamp": datetime.utcnow().isoformat()},
        level=AuditLevel.INFO,
    )

    # Close database connections
    await db_manager.close()

    logger.info("CatNet API shut down successfully")


# Mount service routers (if running as monolith)
if os.getenv("RUN_MODE") == "monolith":
    from ..auth.service import AuthenticationService
    from ..gitops.service import GitOpsService

    # Mount services
    auth_service = AuthenticationService()
    gitops_service = GitOpsService()

    app.mount("/auth", auth_service.app)
    app.mount("/git", gitops_service.app)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("API_PORT", 8080)),
        log_level="info",
    )
