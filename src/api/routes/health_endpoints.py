"""
Health Check Endpoints
Production-ready health, readiness, and liveness probes
"""
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel
from typing import Dict, List
import structlog
from datetime import datetime

from src.db.database import get_db
from src.cache.redis_cache import redis_cache

logger = structlog.get_logger()

router = APIRouter(prefix="/health", tags=["health"])


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    timestamp: str
    version: str = "1.0.0"


class ReadinessResponse(BaseModel):
    """Readiness check response"""
    status: str
    checks: Dict[str, Dict]
    timestamp: str


class DependencyHealth(BaseModel):
    """Individual dependency health"""
    status: str
    response_time_ms: float
    details: Dict = {}


@router.get("/", response_model=HealthResponse)
async def health_check():
    """
    Basic liveness check
    
    Returns 200 if application is running.
    Used by orchestrators to determine if pod should be restarted.
    """
    return HealthResponse(
        status="healthy",
        timestamp=datetime.utcnow().isoformat()
    )


@router.get("/ready", response_model=ReadinessResponse)
async def readiness_check(db = Depends(get_db)):
    """
    Readiness check
    
    Returns 200 if application is ready to serve traffic.
    Checks all critical dependencies.
    """
    checks = {}
    overall_status = "ready"
    
    # Check database
    try:
        start = datetime.utcnow()
        result = await db.execute("SELECT 1")
        duration = (datetime.utcnow() - start).total_seconds() * 1000
        
        checks["database"] = {
            "status": "healthy",
            "response_time_ms": duration
        }
    except Exception as e:
        checks["database"] = {
            "status": "unhealthy",
            "error": str(e)
        }
        overall_status = "not_ready"
    
    # Check Redis
    try:
        if redis_cache._connected:
            start = datetime.utcnow()
            await redis_cache.redis.ping()
            duration = (datetime.utcnow() - start).total_seconds() * 1000
            
            checks["redis"] = {
                "status": "healthy",
                "response_time_ms": duration
            }
        else:
            checks["redis"] = {
                "status": "disconnected"
            }
            overall_status = "not_ready"
    except Exception as e:
        checks["redis"] = {
            "status": "unhealthy",
            "error": str(e)
        }
        overall_status = "not_ready"
    
    response_status = status.HTTP_200_OK if overall_status == "ready" else status.HTTP_503_SERVICE_UNAVAILABLE
    
    return ReadinessResponse(
        status=overall_status,
        checks=checks,
        timestamp=datetime.utcnow().isoformat()
    )


@router.get("/startup")
async def startup_check(db = Depends(get_db)):
    """
    Startup probe
    
    Returns 200 when application has completed startup.
    More lenient than readiness check during startup.
    """
    try:
        # Just verify database is accessible
        await db.execute("SELECT 1")
        return {"status": "started", "timestamp": datetime.utcnow().isoformat()}
    except Exception as e:
        logger.error(f"Startup check failed: {e}")
        return {
            "status": "starting",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }


@router.get("/dependencies")
async def dependency_health(db = Depends(get_db)):
    """
    Detailed dependency health
    
    Returns health status of all external dependencies.
    """
    dependencies = {}
    
    # Database
    try:
        start = datetime.utcnow()
        result = await db.execute("SELECT version()")
        version = result.scalar()
        duration = (datetime.utcnow() - start).total_seconds() * 1000
        
        dependencies["database"] = {
            "status": "healthy",
            "response_time_ms": duration,
            "version": version
        }
    except Exception as e:
        dependencies["database"] = {
            "status": "unhealthy",
            "error": str(e)
        }
    
    # Redis
    try:
        if redis_cache._connected:
            start = datetime.utcnow()
            info = await redis_cache.get_stats()
            duration = (datetime.utcnow() - start).total_seconds() * 1000
            
            dependencies["redis"] = {
                "status": "healthy",
                "response_time_ms": duration,
                "used_memory": info.get("used_memory"),
                "total_keys": info.get("total_keys")
            }
        else:
            dependencies["redis"] = {
                "status": "disconnected"
            }
    except Exception as e:
        dependencies["redis"] = {
            "status": "unhealthy",
            "error": str(e)
        }
    
    return {
        "dependencies": dependencies,
        "timestamp": datetime.utcnow().isoformat()
    }
