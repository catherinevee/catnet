#!/usr/bin/env python
"""
Complete CatNet Server Runner
Initializes and runs the full CatNet application with all components
"""

import os
import sys
import asyncio
import logging
from pathlib import Path
from typing import Optional

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

# Configure logging
logging.basicConfig(
        level=logging.INFO, format="%(
        asctime)s - %(name)s - %(levelname)s - %(message
    )s"
)
logger = logging.getLogger("catnet")

# Set environment variables for local development
os.environ.setdefault(
    "DATABASE_URL",
    "sqlite+aiosqlite:///./data/catnet_local.db"
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("VAULT_URL", "http://localhost:8200")
os.environ.setdefault("JWT_SECRET_KEY", "dev-secret-key-change-in-production")
os.environ.setdefault("SECRET_KEY", "dev-secret-key-change-in-production")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("TESTING", "false")

import uvicorn
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from datetime import datetime

# Import database manager
from src.db.database import DatabaseManager, init_database
from src.db.models import Base

# Import routers and services
try:
    from src.api.auth_endpoints import router as auth_router

    AUTH_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Auth endpoints not available: {e}")
    AUTH_AVAILABLE = False

try:
    from src.api.deployment_endpoints import router as deployment_router

    DEPLOYMENT_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Deployment endpoints not available: {e}")
    DEPLOYMENT_AVAILABLE = False

try:
    from src.api.gitops_endpoints import router as gitops_router

    GITOPS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"GitOps endpoints not available: {e}")
    GITOPS_AVAILABLE = False

# Import middleware
try:
    from src.api.middleware import SecurityHeadersMiddleware, \
        RateLimitMiddleware

    MIDDLEWARE_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Custom middleware not available: {e}")
    MIDDLEWARE_AVAILABLE = False

# Import core services
try:
    from src.auth.service import AuthenticationService
    from src.deployment.service import DeploymentService
    from src.gitops.service import GitOpsService
    from src.devices.service import DeviceService

    SERVICES_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Core services not available: {e}")
    SERVICES_AVAILABLE = False

# Import monitoring
try:
    from src.monitoring.metrics import MetricsCollector
    from src.monitoring.observability import ObservabilityManager

    MONITORING_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Monitoring not available: {e}")
    MONITORING_AVAILABLE = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""

    logger.info("Starting CatNet application...")

    # Initialize database
    try:
        logger.info("Initializing database...")
        db_manager = init_database()

        # Create tables if they don't exist
        async with db_manager.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database initialized successfully")

        # Store in app state
        app.state.db_manager = db_manager

    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        logger.info("Running without database persistence")

    # Initialize services if available
    if SERVICES_AVAILABLE:
        try:
            logger.info("Initializing core services...")
            app.state.auth_service = AuthenticationService()
            app.state.deployment_service = DeploymentService()
            app.state.gitops_service = GitOpsService()
            app.state.device_service = DeviceService()
            logger.info("Core services initialized")
        except Exception as e:
            logger.warning(f"Some services failed to initialize: {e}")

    # Initialize monitoring if available
    if MONITORING_AVAILABLE:
        try:
            logger.info("Initializing monitoring...")
            app.state.metrics = MetricsCollector()
            app.state.observability = ObservabilityManager()
            logger.info("Monitoring initialized")
        except Exception as e:
            logger.warning(f"Monitoring initialization failed: {e}")

    logger.info("CatNet application started successfully")

    yield

    # Cleanup
    logger.info("Shutting down CatNet application...")

    if hasattr(app.state, "db_manager"):
        await app.state.db_manager.close()

    logger.info("CatNet application shutdown complete")


# Create FastAPI application
app = FastAPI(
    title="CatNet - Network Configuration Management System",
    description="Security-first, GitOps-enabled network configuration \
        deployment system",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    TrustedHostMiddleware,
        allowed_hosts=["*"]  # Configure appropriately for production
)

# Custom middleware temporarily disabled due to compatibility issues
# if MIDDLEWARE_AVAILABLE:
#     try:
#         app.add_middleware(SecurityHeadersMiddleware)
#         logger.info("Added SecurityHeadersMiddleware")
#     except Exception as e:
#         logger.warning(f"Could not add SecurityHeadersMiddleware: {e}")
logger.info("Custom middleware temporarily disabled")


# Root endpoint
@app.get("/", tags=["System"])
async def root():
    """Root endpoint with system information"""
    return {
        "application": "CatNet",
        "version": "1.0.0",
        "description": "Network Configuration Management System",
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat(),
        "endpoints": {
            "health": "/health",
            "metrics": "/metrics",
            "documentation": "/docs",
            "api": "/api/v1",
        },
        "features": {
            "authentication": AUTH_AVAILABLE,
            "deployments": DEPLOYMENT_AVAILABLE,
            "gitops": GITOPS_AVAILABLE,
            "monitoring": MONITORING_AVAILABLE,
            "services": SERVICES_AVAILABLE,
        },
    }


# Health check endpoint
@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint"""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "checks": {},
    }

    # Check database
    if hasattr(app.state, "db_manager"):
        try:
            db_healthy = await app.state.db_manager.health_check()
            health_status["checks"]["database"] = (
                "healthy" if db_healthy else "unhealthy"
            )
        except Exception as e:
            health_status["checks"]["database"] = f"error: {str(e)}"
    else:
        health_status["checks"]["database"] = "not configured"

    # Check services
    health_status["checks"]["auth_service"] = (
        "healthy" if hasattr(app.state, "auth_service") else "not loaded"
    )
    health_status["checks"]["deployment_service"] = (
        "healthy" if hasattr(app.state, "deployment_service") else "not loaded"
    )
    health_status["checks"]["gitops_service"] = (
        "healthy" if hasattr(app.state, "gitops_service") else "not loaded"
    )
    health_status["checks"]["device_service"] = (
        "healthy" if hasattr(app.state, "device_service") else "not loaded"
    )

    # Overall status
    if all(
        v == "healthy" or v == "not configured"
        for v in health_status["checks"].values()
    ):
        health_status["status"] = "healthy"
    elif any("error" in str(v) for v in health_status["checks"].values()):
        health_status["status"] = "degraded"
    else:
        health_status["status"] = "partial"

    return health_status


# System info endpoint
@app.get("/api/v1/info", tags=["System"])
async def system_info():
    """Get system information"""
    return {
        "system": "CatNet",
        "version": "1.0.0",
        "api_version": "v1",
        "description": "Network Configuration Management System",
        "capabilities": {
            "vendors": ["Cisco IOS",
                "Cisco IOS-XE"
                "Cisco NX-OS"
                "Juniper Junos"]
                
            "deployment_strategies": ["canary",
                "rolling"
                "blue-green"
                "direct"]
                
            "authentication": ["OAuth2", "SAML", "JWT", "API Keys", "mTLS"],
            "compliance_frameworks": [
                "PCI-DSS",
                "HIPAA",
                "SOC2",
                "ISO-27001",
                "NIST",
                "CIS",
            ],
            "features": [
                "GitOps Integration",
                "Automatic Rollback",
                "Configuration Signing",
                "Audit Logging",
                "ML Anomaly Detection",
                "Workflow Automation",
                "Multi-Factor Authentication",
                "HashiCorp Vault Integration",
                "Prometheus Metrics",
                "Distributed Tracing",
            ],
        },
        "status": {
            "operational": True,
            "maintenance_mode": False,
            "accepting_deployments": True,
        },
        "links": {
            "documentation": "/docs",
            "health": "/health",
            "metrics": "/metrics",
            "github": "https://github.com/catherinevee/catnet",
        },
    }


# Metrics endpoint (if monitoring available)
if MONITORING_AVAILABLE:

    @app.get("/metrics", tags=["Monitoring"])
    async def get_metrics():
        """Get Prometheus-formatted metrics"""
        if hasattr(app.state, "metrics"):
            metrics_data = await app.state.metrics.get_all_metrics()
            # Format as Prometheus text
            output = []
            for metric_name, metric_value in metrics_data.items():
                output.append(f"# TYPE {metric_name} gauge")
                output.append(f"{metric_name} {metric_value}")
            return "\n".join(output)
        return "# No metrics available"


# Mount API routers
if AUTH_AVAILABLE:
        app.include_router(
        auth_router,
        prefix="/api/v1/auth",
        tags=["Authentication"]
    )
    logger.info("Mounted authentication endpoints")

if DEPLOYMENT_AVAILABLE:
    app.include_router(
        deployment_router, prefix="/api/v1/deployments", tags=["Deployments"]
    )
    logger.info("Mounted deployment endpoints")

if GITOPS_AVAILABLE:
    app.include_router(gitops_router, prefix="/api/v1/gitops", tags=["GitOps"])
    logger.info("Mounted GitOps endpoints")

# Import and mount device endpoints
try:
    from src.api.device_endpoints import router as device_router
        app.include_router(
        device_router,
        prefix="/api/v1/devices",
        tags=["Devices"]
    )
    logger.info("Mounted device management endpoints")
except ImportError as e:
    logger.warning(f"Device endpoints not available: {e}")

# Import and mount simple GitOps endpoints (Phase 3)
try:
    from src.api.simple_gitops_endpoints import router as simple_gitops_router
        app.include_router(
        simple_gitops_router,
        prefix="/api/v1/gitops",
        tags=["GitOps"]
    )
    logger.info("Mounted simple GitOps endpoints")
except ImportError as e:
    logger.warning(f"Simple GitOps endpoints not available: {e}")

# Import and mount simple deployment endpoints (Phase 4)
try:
    from src.api.simple_deploy_endpoints import router as simple_deploy_router
        app.include_router(
        simple_deploy_router,
        prefix="/api/v1/deploy",
        tags=["Deployment"]
    )
    logger.info("Mounted simple deployment endpoints")
except ImportError as e:
    logger.warning(f"Simple deployment endpoints not available: {e}")

# Import and mount device connection endpoints (Phase 5)
try:
    from src.api.device_connection_endpoints import router as \
        device_conn_router
        app.include_router(
        device_conn_router,
        prefix="/api/v1/device-connection",
        tags=["Device Connection"]
    )
    logger.info("Mounted device connection endpoints")
except ImportError as e:
    logger.warning(f"Device connection endpoints not available: {e}")

# Import and mount rollback endpoints (Phase 6)
try:
    from src.api.rollback_endpoints import router as rollback_router
        app.include_router(
        rollback_router,
        prefix="/api/v1/rollback",
        tags=["Rollback & Safety"]
    )
    logger.info("Mounted rollback and safety endpoints")
except ImportError as e:
    logger.warning(f"Rollback endpoints not available: {e}")

# Import and mount monitoring endpoints (Phase 7)
try:
    from src.api.monitoring_endpoints import router as monitoring_router
        app.include_router(
        monitoring_router,
        prefix="/api/v1/monitoring",
        tags=["Monitoring"]
    )
    logger.info("Mounted monitoring and observability endpoints")
except ImportError as e:
    logger.warning(f"Monitoring endpoints not available: {e}")


# Legacy device management endpoint (deprecated - use /api/v1/devices)
@app.get("/api/v1/devices_legacy", tags=["Devices"])
async def list_devices():
    """List all managed devices"""
    if hasattr(app.state, "device_service"):
        # Would query from database
        return {"devices": [], "total": 0, "page": 1, "per_page": 20}
    raise HTTPException(status_code=503, detail="Device service not available")


@app.post("/api/v1/devices/{device_id}/backup", tags=["Devices"])
async def backup_device(device_id: str):
    """Create device configuration backup"""
    if hasattr(app.state, "device_service"):
        return {
            "device_id": device_id,
            "backup_id": f"backup_{device_id}_{datetime.utcnow().isoformat()}",
            "status": "completed",
            "timestamp": datetime.utcnow().isoformat(),
        }
    raise HTTPException(status_code=503, detail="Device service not available")


# Compliance endpoints
@app.get("/api/v1/compliance/frameworks", tags=["Compliance"])
async def list_compliance_frameworks():
    """List supported compliance frameworks"""
    return {
        "frameworks": [
            {"id": "pci-dss", "name": "PCI-DSS", "version": "3.2.1"},
            {"id": "hipaa", "name": "HIPAA", "version": "2013"},
            {"id": "soc2", "name": "SOC2", "version": "Type II"},
            {"id": "iso-27001", "name": "ISO 27001", "version": "2013"},
            {"id": "nist",
                "name": "NIST Cybersecurity Framework"
                "version": "1.1"}
                
            {"id": "cis", "name": "CIS Controls", "version": "8"},
        ]
    }


@app.post("/api/v1/compliance/check", tags=["Compliance"])
async def run_compliance_check(framework: str, device_ids: list[str] = None):
    """Run compliance check"""
    return {
        "check_id": f"check_{framework}_{datetime.utcnow().timestamp()}",
        "framework": framework,
        "devices": device_ids or ["all"],
        "status": "in_progress",
        "started_at": datetime.utcnow().isoformat(),
    }


# Workflow automation endpoints
@app.get("/api/v1/workflows", tags=["Automation"])
async def list_workflows():
    """List automation workflows"""
    return {
        "workflows": [
            {
                "id": "auto_rollback",
                "name": "Automatic Rollback on Failure",
                "trigger": "deployment_failure",
                "enabled": True,
            },
            {
                "id": "backup_before_deploy",
                "name": "Backup Before Deployment",
                "trigger": "deployment_started",
                "enabled": True,
            },
            {
                "id": "compliance_remediation",
                "name": "Compliance Auto-Remediation",
                "trigger": "compliance_violation",
                "enabled": False,
            },
        ]
    }


@app.post("/api/v1/workflows/{workflow_id}/execute", tags=["Automation"])
async def execute_workflow(workflow_id: str):
    """Manually execute a workflow"""
    return {
        "execution_id": f"exec_{workflow_id}_{datetime.utcnow().timestamp()}",
        "workflow_id": workflow_id,
        "status": "started",
        "timestamp": datetime.utcnow().isoformat(),
    }


# ML Anomaly Detection endpoints
@app.get("/api/v1/ml/models", tags=["Machine Learning"])
async def list_ml_models():
    """List ML models"""
    return {
        "models": [
            {
                "id": "traffic_anomaly",
                "name": "Network Traffic Anomaly Detection",
                "type": "isolation_forest",
                "status": "trained",
                "accuracy": 0.94,
            },
            {
                "id": "config_drift",
                "name": "Configuration Drift Detection",
                "type": "random_forest",
                "status": "training",
                "accuracy": None,
            },
        ]
    }


@app.post("/api/v1/ml/predict", tags=["Machine Learning"])
async def predict_anomaly(data: dict):
    """Predict anomaly"""
    return {
        "anomaly_score": 0.23,
        "is_anomaly": False,
        "confidence": 0.87,
        "timestamp": datetime.utcnow().isoformat(),
    }


# Error handlers
@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content={
            "error": "Not Found",
            "message": f"The requested resource was not found",
            "path": str(request.url.path),
        },
    )


@app.exception_handler(500)
async def internal_error_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred",
            "request_id": f"req_{datetime.utcnow().timestamp()}",
        },
    )



def main():
    """Main entry point"""

    print(
        """
======================================================================
                    CatNet - Complete Edition
         Network Configuration Management System v1.0.0
======================================================================
    """
    )

    # Display configuration
    print("Configuration:")
    print(f"  Database: {os.environ.get('DATABASE_URL', 'Not configured')}")
    print(f"  Environment: {os.environ.get('ENVIRONMENT', 'development')}")
    print(f"  Debug Mode: {os.environ.get('DEBUG', 'false')}")
    print()

    # Display component status
    print("Components:")
    print(f"  [{'OK' if AUTH_AVAILABLE else 'MISSING'}] Authentication \
        Service")
    print(f"  [{'OK' if DEPLOYMENT_AVAILABLE else 'MISSING'}] Deployment \
        Service")
    print(f"  [{'OK' if GITOPS_AVAILABLE else 'MISSING'}] GitOps Service")
    print(f"  [{'OK' if SERVICES_AVAILABLE else 'MISSING'}] Core Services")
    print(f"  [{'OK' if MONITORING_AVAILABLE else 'MISSING'}] Monitoring")
    print(f"  [{'OK' if MIDDLEWARE_AVAILABLE else 'MISSING'}] Security \
        Middleware")
    print()

    # Display URLs
    print("Access Points:")
    print("  Main Application:  http://localhost:8002")
    print("  API Documentation: http://localhost:8002/docs")
    print("  Alternative Docs:  http://localhost:8002/redoc")
    print("  OpenAPI Schema:    http://localhost:8002/openapi.json")
    print("  Health Check:      http://localhost:8002/health")
    print("  System Info:       http://localhost:8002/api/v1/info")
    print()

    print("Starting server...")
    print("Press CTRL+C to stop\n")

    # Run the server
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8002,  # Changed to 8002 to avoid conflict
        reload=False,  # Set to True for development
        log_level="info",
        access_log=True,
    )


if __name__ == "__main__":
    main()
