from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
import structlog
import time
from datetime import datetime
import asyncio

from ...db.database import get_db_session
from ...security.vault import VaultClient
from .auth import get_current_user

logger = structlog.get_logger()
router = APIRouter()

@router.get("/")
async def health_check():
    """Basic health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "catnet-api"
    }

@router.get("/detailed")
async def detailed_health_check(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Detailed health check requiring authentication"""
    try:
        start_time = time.time()
        health_status = {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "service": "catnet-api",
            "version": "1.0.0",
            "checks": {}
        }

        # Database connectivity check
        try:
            async with get_db_session() as session:
                await session.execute("SELECT 1")
            health_status["checks"]["database"] = {"status": "healthy", "latency_ms": 0}
        except Exception as e:
            health_status["checks"]["database"] = {"status": "unhealthy", "error": str(e)}
            health_status["status"] = "degraded"

        # Vault connectivity check
        try:
            vault = VaultClient()
            await vault.health_check()
            health_status["checks"]["vault"] = {"status": "healthy"}
        except Exception as e:
            health_status["checks"]["vault"] = {"status": "unhealthy", "error": str(e)}
            health_status["status"] = "degraded"

        # System metrics
        health_status["checks"]["system"] = {
            "status": "healthy",
            "uptime_seconds": time.time() - start_time
        }

        # Overall health
        total_time = time.time() - start_time
        health_status["response_time_ms"] = round(total_time * 1000, 2)

        if health_status["status"] == "healthy":
            return health_status
        else:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=health_status
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Health check error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
        )

@router.get("/readiness")
async def readiness_check():
    """Kubernetes readiness probe"""
    try:
        # Check if application is ready to serve requests
        async with get_db_session() as session:
            await session.execute("SELECT 1")

        return {"status": "ready"}

    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"status": "not_ready", "error": str(e)}
        )

@router.get("/liveness")
async def liveness_check():
    """Kubernetes liveness probe"""
    return {"status": "alive", "timestamp": datetime.utcnow().isoformat()}