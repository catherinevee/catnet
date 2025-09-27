"""
CatNet Health Check and Readiness Endpoints

Provides comprehensive health monitoring for all components
"""

from fastapi import APIRouter, Depends, status, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from typing import Dict, Any, Optional, List
import asyncio
import aiohttp
import time
import psutil
import redis.asyncio as redis
from datetime import datetime, timedelta
import structlog
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
import traceback
import hashlib
import json

from ...db.database import get_db
from ...auth.dependencies import get_current_user_optional
from ...security.vault import VaultClient
from ...monitoring.metrics import registry, service_info
from ...core.config import get_settings

logger = structlog.get_logger()
router = APIRouter(prefix="/health", tags=["health"])
settings = get_settings()

# =============================================================================
# Health Check Models
# =============================================================================

class HealthStatus:
    """Health status constants"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    CRITICAL = "critical"


class ComponentHealth:
    """Component health information"""

    def __init__(
        self,
        name: str,
        status: str,
        latency_ms: Optional[float] = None,
        message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.name = name
        self.status = status
        self.latency_ms = latency_ms
        self.message = message
        self.metadata = metadata or {}
        self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "name": self.name,
            "status": self.status,
            "latency_ms": self.latency_ms,
            "message": self.message,
            "metadata": self.metadata,
            "timestamp": self.timestamp
        }


# =============================================================================
# Basic Health Endpoints
# =============================================================================

@router.get("/", status_code=status.HTTP_200_OK)
async def health_check() -> Dict[str, Any]:
    """
    Basic health check endpoint

    Returns 200 if service is running
    """
    return {
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "catnet-api",
        "version": settings.APP_VERSION
    }


@router.get("/live", status_code=status.HTTP_200_OK)
async def liveness_check() -> Dict[str, Any]:
    """
    Kubernetes liveness probe endpoint

    Returns 200 if service is alive
    """
    return {
        "status": "alive",
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/ready")
async def readiness_check(
    response: Response,
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """
    Kubernetes readiness probe endpoint

    Checks if service is ready to accept traffic
    """
    checks_passed = []
    checks_failed = []

    # Check database
    try:
        start_time = time.time()
        result = await db.execute(text("SELECT 1"))
        latency = (time.time() - start_time) * 1000

        checks_passed.append({
            "component": "database",
            "latency_ms": latency
        })
    except Exception as e:
        checks_failed.append({
            "component": "database",
            "error": str(e)
        })

    # Check Redis if configured
    if settings.REDIS_URL:
        try:
            start_time = time.time()
            redis_client = await redis.from_url(settings.REDIS_URL)
            await redis_client.ping()
            latency = (time.time() - start_time) * 1000

            checks_passed.append({
                "component": "redis",
                "latency_ms": latency
            })
            await redis_client.close()
        except Exception as e:
            checks_failed.append({
                "component": "redis",
                "error": str(e)
            })

    # Determine overall status
    if checks_failed:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        ready_status = "not_ready"
    else:
        response.status_code = status.HTTP_200_OK
        ready_status = "ready"

    return {
        "status": ready_status,
        "timestamp": datetime.utcnow().isoformat(),
        "checks_passed": checks_passed,
        "checks_failed": checks_failed
    }


# =============================================================================
# Comprehensive Health Endpoints
# =============================================================================

@router.get("/detailed")
async def detailed_health_check(
    db: AsyncSession = Depends(get_db),
    current_user: Optional[Dict] = Depends(get_current_user_optional)
) -> Dict[str, Any]:
    """
    Detailed health check with component status

    Requires authentication for sensitive information
    """
    components = []
    overall_status = HealthStatus.HEALTHY

    # Database health
    db_health = await check_database_health(db)
    components.append(db_health.to_dict())
    if db_health.status != HealthStatus.HEALTHY:
        overall_status = HealthStatus.DEGRADED

    # Redis health
    redis_health = await check_redis_health()
    components.append(redis_health.to_dict())
    if redis_health.status == HealthStatus.UNHEALTHY:
        overall_status = HealthStatus.DEGRADED

    # Vault health
    vault_health = await check_vault_health()
    components.append(vault_health.to_dict())
    if vault_health.status == HealthStatus.UNHEALTHY:
        overall_status = HealthStatus.DEGRADED

    # System health
    system_health = await check_system_health()
    components.append(system_health.to_dict())
    if system_health.status == HealthStatus.CRITICAL:
        overall_status = HealthStatus.CRITICAL

    # Include sensitive info only for authenticated users
    response = {
        "status": overall_status,
        "timestamp": datetime.utcnow().isoformat(),
        "components": components
    }

    if current_user:
        # Add detailed system info for authenticated users
        response["system"] = {
            "cpu_count": psutil.cpu_count(),
            "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            "disk_total_gb": round(psutil.disk_usage('/').total / (1024**3), 2),
            "python_version": f"{psutil.Process().memory_info().rss / (1024**2):.2f} MB",
            "uptime_seconds": time.time() - psutil.Process().create_time()
        }

    return response


@router.get("/dependencies")
async def dependency_health_check(
    current_user: Dict = Depends(get_current_user_optional)
) -> Dict[str, Any]:
    """
    Check health of external dependencies
    """
    dependencies = []

    # Check Git providers
    git_providers = [
        {"name": "github", "url": "https://api.github.com/"},
        {"name": "gitlab", "url": "https://gitlab.com/api/v4/"},
        {"name": "bitbucket", "url": "https://api.bitbucket.org/2.0/"}
    ]

    async with aiohttp.ClientSession() as session:
        for provider in git_providers:
            try:
                start_time = time.time()
                async with session.get(
                    provider["url"],
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    latency = (time.time() - start_time) * 1000
                    dependencies.append({
                        "name": provider["name"],
                        "status": "available" if response.status < 500 else "degraded",
                        "latency_ms": latency,
                        "status_code": response.status
                    })
            except Exception as e:
                dependencies.append({
                    "name": provider["name"],
                    "status": "unavailable",
                    "error": str(e)
                })

    # Check DNS resolution for critical domains
    import socket
    critical_domains = ["vault.hashicorp.com", "pypi.org", "docker.io"]

    for domain in critical_domains:
        try:
            start_time = time.time()
            socket.gethostbyname(domain)
            latency = (time.time() - start_time) * 1000
            dependencies.append({
                "name": f"dns_{domain}",
                "status": "available",
                "latency_ms": latency
            })
        except Exception as e:
            dependencies.append({
                "name": f"dns_{domain}",
                "status": "unavailable",
                "error": str(e)
            })

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "dependencies": dependencies
    }


# =============================================================================
# Metrics Endpoints
# =============================================================================

@router.get("/metrics", response_class=PlainTextResponse)
async def prometheus_metrics() -> str:
    """
    Prometheus metrics endpoint

    Returns metrics in Prometheus exposition format
    """
    return generate_latest(registry)


@router.get("/metrics/json")
async def json_metrics() -> Dict[str, Any]:
    """
    JSON formatted metrics for debugging
    """
    from prometheus_client.parser import text_string_to_metric_families

    metrics_text = generate_latest(registry).decode('utf-8')
    metrics = {}

    for family in text_string_to_metric_families(metrics_text):
        metrics[family.name] = {
            "type": family.type,
            "help": family.documentation,
            "samples": [
                {
                    "labels": dict(sample.labels),
                    "value": sample.value
                }
                for sample in family.samples
            ]
        }

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "metrics": metrics
    }


# =============================================================================
# System Information Endpoints
# =============================================================================

@router.get("/info")
async def system_info(
    current_user: Dict = Depends(get_current_user_optional)
) -> Dict[str, Any]:
    """
    System information endpoint

    Returns basic info, detailed for authenticated users
    """
    info = {
        "service": "catnet-api",
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.utcnow().isoformat()
    }

    if current_user:
        # Add detailed info for authenticated users
        process = psutil.Process()

        info.update({
            "system": {
                "platform": psutil.LINUX if hasattr(psutil, 'LINUX') else "unknown",
                "cpu_count": psutil.cpu_count(),
                "cpu_percent": psutil.cpu_percent(interval=0.1),
                "memory": {
                    "total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
                    "available_gb": round(psutil.virtual_memory().available / (1024**3), 2),
                    "percent": psutil.virtual_memory().percent
                },
                "disk": {
                    "total_gb": round(psutil.disk_usage('/').total / (1024**3), 2),
                    "free_gb": round(psutil.disk_usage('/').free / (1024**3), 2),
                    "percent": psutil.disk_usage('/').percent
                }
            },
            "process": {
                "pid": process.pid,
                "memory_mb": round(process.memory_info().rss / (1024**2), 2),
                "cpu_percent": process.cpu_percent(),
                "threads": process.num_threads(),
                "uptime_seconds": time.time() - process.create_time(),
                "open_files": process.num_fds() if hasattr(process, 'num_fds') else None
            }
        })

    return info


@router.get("/status")
async def service_status(
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """
    Service status endpoint with recent metrics
    """
    # Get deployment statistics
    deployment_stats = await get_deployment_statistics(db)

    # Get device statistics
    device_stats = await get_device_statistics(db)

    # Get recent errors
    recent_errors = await get_recent_errors(db)

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "status": HealthStatus.HEALTHY,
        "statistics": {
            "deployments": deployment_stats,
            "devices": device_stats,
            "errors": recent_errors
        }
    }


# =============================================================================
# Debug Endpoints (Development Only)
# =============================================================================

@router.get("/debug/config")
async def debug_config(
    current_user: Dict = Depends(get_current_user_optional)
) -> Dict[str, Any]:
    """
    Debug endpoint to view configuration (dev only)
    """
    if settings.ENVIRONMENT != "development":
        return {"error": "Debug endpoints disabled in production"}

    if not current_user:
        return {"error": "Authentication required"}

    # Return sanitized config
    config = {
        "environment": settings.ENVIRONMENT,
        "debug": settings.DEBUG,
        "database_url": "***" if settings.DATABASE_URL else None,
        "redis_url": "***" if settings.REDIS_URL else None,
        "vault_url": settings.VAULT_URL if settings.VAULT_URL else None,
        "cors_origins": settings.CORS_ORIGINS,
        "api_version": settings.API_VERSION,
        "app_version": settings.APP_VERSION
    }

    return config


@router.get("/debug/connections")
async def debug_connections(
    current_user: Dict = Depends(get_current_user_optional),
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """
    Debug endpoint to view active connections
    """
    if settings.ENVIRONMENT != "development":
        return {"error": "Debug endpoints disabled in production"}

    if not current_user:
        return {"error": "Authentication required"}

    connections = {
        "database": {
            "active": True,
            "pool_size": getattr(db.bind.pool, 'size', None),
            "overflow": getattr(db.bind.pool, 'overflow', None)
        }
    }

    # Check Redis connections
    if settings.REDIS_URL:
        try:
            redis_client = await redis.from_url(settings.REDIS_URL)
            info = await redis_client.info()
            connections["redis"] = {
                "active": True,
                "connected_clients": info.get('connected_clients', 0),
                "used_memory_mb": round(info.get('used_memory', 0) / (1024**2), 2)
            }
            await redis_client.close()
        except Exception as e:
            connections["redis"] = {
                "active": False,
                "error": str(e)
            }

    return connections


# =============================================================================
# Helper Functions
# =============================================================================

async def check_database_health(db: AsyncSession) -> ComponentHealth:
    """Check database health"""
    try:
        start_time = time.time()

        # Check connection
        result = await db.execute(text("SELECT 1"))

        # Check table count
        table_count = await db.execute(
            text("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public'")
        )
        table_count = table_count.scalar()

        latency = (time.time() - start_time) * 1000

        return ComponentHealth(
            name="database",
            status=HealthStatus.HEALTHY,
            latency_ms=latency,
            message="Database is operational",
            metadata={"table_count": table_count}
        )

    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return ComponentHealth(
            name="database",
            status=HealthStatus.UNHEALTHY,
            message=f"Database connection failed: {str(e)}"
        )


async def check_redis_health() -> ComponentHealth:
    """Check Redis health"""
    if not settings.REDIS_URL:
        return ComponentHealth(
            name="redis",
            status=HealthStatus.HEALTHY,
            message="Redis not configured"
        )

    try:
        start_time = time.time()
        redis_client = await redis.from_url(settings.REDIS_URL)

        # Ping Redis
        await redis_client.ping()

        # Get info
        info = await redis_client.info()
        latency = (time.time() - start_time) * 1000

        await redis_client.close()

        return ComponentHealth(
            name="redis",
            status=HealthStatus.HEALTHY,
            latency_ms=latency,
            message="Redis is operational",
            metadata={
                "version": info.get('redis_version', 'unknown'),
                "used_memory_mb": round(info.get('used_memory', 0) / (1024**2), 2)
            }
        )

    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        return ComponentHealth(
            name="redis",
            status=HealthStatus.UNHEALTHY,
            message=f"Redis connection failed: {str(e)}"
        )


async def check_vault_health() -> ComponentHealth:
    """Check Vault health"""
    if not settings.VAULT_URL:
        return ComponentHealth(
            name="vault",
            status=HealthStatus.HEALTHY,
            message="Vault not configured"
        )

    try:
        start_time = time.time()
        vault_client = VaultClient()

        # Check Vault health
        health = await vault_client.health_check()
        latency = (time.time() - start_time) * 1000

        if health:
            return ComponentHealth(
                name="vault",
                status=HealthStatus.HEALTHY,
                latency_ms=latency,
                message="Vault is operational"
            )
        else:
            return ComponentHealth(
                name="vault",
                status=HealthStatus.DEGRADED,
                latency_ms=latency,
                message="Vault is sealed or not initialized"
            )

    except Exception as e:
        logger.error(f"Vault health check failed: {e}")
        return ComponentHealth(
            name="vault",
            status=HealthStatus.UNHEALTHY,
            message=f"Vault connection failed: {str(e)}"
        )


async def check_system_health() -> ComponentHealth:
    """Check system resource health"""
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory_percent = psutil.virtual_memory().percent
        disk_percent = psutil.disk_usage('/').percent

        # Determine status based on thresholds
        if cpu_percent > 90 or memory_percent > 90 or disk_percent > 90:
            status = HealthStatus.CRITICAL
            message = "System resources critically high"
        elif cpu_percent > 75 or memory_percent > 75 or disk_percent > 75:
            status = HealthStatus.DEGRADED
            message = "System resources elevated"
        else:
            status = HealthStatus.HEALTHY
            message = "System resources normal"

        return ComponentHealth(
            name="system",
            status=status,
            message=message,
            metadata={
                "cpu_percent": cpu_percent,
                "memory_percent": memory_percent,
                "disk_percent": disk_percent
            }
        )

    except Exception as e:
        logger.error(f"System health check failed: {e}")
        return ComponentHealth(
            name="system",
            status=HealthStatus.UNHEALTHY,
            message=f"System check failed: {str(e)}"
        )


async def get_deployment_statistics(db: AsyncSession) -> Dict[str, Any]:
    """Get deployment statistics"""
    try:
        # Get total deployments
        total_query = await db.execute(
            text("SELECT COUNT(*) FROM deployments")
        )
        total = total_query.scalar() or 0

        # Get recent deployments
        recent_query = await db.execute(
            text("""
                SELECT COUNT(*) FROM deployments
                WHERE created_at > NOW() - INTERVAL '24 HOURS'
            """)
        )
        recent = recent_query.scalar() or 0

        # Get pending approvals
        pending_query = await db.execute(
            text("""
                SELECT COUNT(*) FROM deployments
                WHERE state = 'pending_approval'
            """)
        )
        pending = pending_query.scalar() or 0

        return {
            "total": total,
            "last_24h": recent,
            "pending_approval": pending
        }

    except Exception as e:
        logger.error(f"Failed to get deployment statistics: {e}")
        return {
            "total": 0,
            "last_24h": 0,
            "pending_approval": 0
        }


async def get_device_statistics(db: AsyncSession) -> Dict[str, Any]:
    """Get device statistics"""
    try:
        # Get total devices
        total_query = await db.execute(
            text("SELECT COUNT(*) FROM devices")
        )
        total = total_query.scalar() or 0

        # Get online devices (connected in last 5 minutes)
        online_query = await db.execute(
            text("""
                SELECT COUNT(*) FROM devices
                WHERE last_seen > NOW() - INTERVAL '5 MINUTES'
            """)
        )
        online = online_query.scalar() or 0

        return {
            "total": total,
            "online": online,
            "offline": total - online
        }

    except Exception as e:
        logger.error(f"Failed to get device statistics: {e}")
        return {
            "total": 0,
            "online": 0,
            "offline": 0
        }


async def get_recent_errors(db: AsyncSession) -> List[Dict[str, Any]]:
    """Get recent error events"""
    try:
        query = await db.execute(
            text("""
                SELECT
                    created_at,
                    error_type,
                    message
                FROM audit_logs
                WHERE level = 'ERROR'
                    AND created_at > NOW() - INTERVAL '1 HOUR'
                ORDER BY created_at DESC
                LIMIT 10
            """)
        )

        errors = []
        for row in query:
            errors.append({
                "timestamp": row.created_at.isoformat() if row.created_at else None,
                "type": row.error_type,
                "message": row.message[:200] if row.message else None  # Truncate message
            })

        return errors

    except Exception as e:
        logger.error(f"Failed to get recent errors: {e}")
        return []