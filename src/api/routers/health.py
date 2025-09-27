"""
Health Router
System health monitoring, metrics, and diagnostics endpoints
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import psutil
import asyncio
import platform
import os
import aiohttp
import json

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text, func
from pydantic import BaseModel, Field
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from fastapi.responses import Response

from src.db.models import (
    Device, Deployment, User, UserSession,
    AuditLog, SecurityIncident, GitRepository
)
from src.core.config import settings
from src.core.dependencies import (
    get_db,
    get_redis,
    get_vault,
    get_current_user_optional
)
from src.monitoring.metrics import (
    deployment_duration,
    deployments_total,
    auth_failures,
    service_health,
    api_request_duration,
    api_requests_total,
    device_connections_active,
    database_connections_active
)

router = APIRouter(prefix="/api/v1/health", tags=["health"])


class HealthStatus(BaseModel):
    status: str = Field(..., regex="^(healthy|degraded|unhealthy)$")
    timestamp: datetime
    version: str
    uptime_seconds: int
    checks: Dict[str, Dict[str, Any]]


class ServiceHealth(BaseModel):
    service: str
    status: str
    latency_ms: Optional[int]
    error: Optional[str]
    last_check: datetime


class SystemMetrics(BaseModel):
    cpu_percent: float
    memory_percent: float
    memory_used_gb: float
    memory_total_gb: float
    disk_usage_percent: float
    disk_used_gb: float
    disk_total_gb: float
    network_connections: int
    process_count: int
    load_average: List[float]


class DatabaseHealth(BaseModel):
    status: str
    connection_pool_size: int
    active_connections: int
    idle_connections: int
    response_time_ms: int
    database_size_mb: float
    oldest_transaction_age_seconds: Optional[int]


class ComponentStatus(BaseModel):
    component: str
    status: str
    version: Optional[str]
    last_heartbeat: Optional[datetime]
    error_count: int
    warning_count: int
    metadata: Optional[Dict[str, Any]]


class PerformanceMetrics(BaseModel):
    avg_response_time_ms: float
    p50_response_time_ms: float
    p95_response_time_ms: float
    p99_response_time_ms: float
    requests_per_second: float
    error_rate: float
    success_rate: float


@router.get("/", response_model=HealthStatus)
async def health_check(
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis),
    vault = Depends(get_vault)
) -> HealthStatus:
    """
    Comprehensive health check endpoint
    """

    checks = {}
    overall_status = "healthy"
    start_time = datetime.utcnow()

    # Database health check
    db_check = await check_database_health(db)
    checks["database"] = db_check
    if db_check["status"] != "healthy":
        overall_status = "degraded" if overall_status == "healthy" else "unhealthy"

    # Redis health check
    redis_check = await check_redis_health(redis)
    checks["redis"] = redis_check
    if redis_check["status"] != "healthy":
        overall_status = "degraded" if overall_status == "healthy" else "unhealthy"

    # Vault health check
    vault_check = await check_vault_health(vault)
    checks["vault"] = vault_check
    if vault_check["status"] != "healthy":
        overall_status = "unhealthy"  # Vault is critical

    # Message queue health check
    mq_check = await check_message_queue_health()
    checks["message_queue"] = mq_check
    if mq_check["status"] != "healthy":
        overall_status = "degraded" if overall_status == "healthy" else "unhealthy"

    # Calculate uptime
    uptime_seconds = int((datetime.utcnow() - settings.APP_START_TIME).total_seconds())

    # Update Prometheus metric
    service_health.labels(service="api").set(1 if overall_status == "healthy" else 0)

    return HealthStatus(
        status=overall_status,
        timestamp=datetime.utcnow(),
        version=settings.APP_VERSION,
        uptime_seconds=uptime_seconds,
        checks=checks
    )


@router.get("/liveness")
async def liveness_probe() -> Dict[str, str]:
    """
    Kubernetes liveness probe endpoint
    Simple check to verify the application is running
    """
    return {"status": "alive", "timestamp": datetime.utcnow().isoformat()}


@router.get("/readiness")
async def readiness_probe(
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis)
) -> Dict[str, Any]:
    """
    Kubernetes readiness probe endpoint
    Checks if the application is ready to serve requests
    """

    ready = True
    checks = []

    # Check database connection
    try:
        await db.execute(text("SELECT 1"))
        checks.append({"database": "ready"})
    except Exception as e:
        ready = False
        checks.append({"database": f"not_ready: {str(e)}"})

    # Check Redis connection
    try:
        await redis.ping()
        checks.append({"redis": "ready"})
    except Exception as e:
        ready = False
        checks.append({"redis": f"not_ready: {str(e)}"})

    if not ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"status": "not_ready", "checks": checks}
        )

    return {
        "status": "ready",
        "timestamp": datetime.utcnow().isoformat(),
        "checks": checks
    }


@router.get("/metrics")
async def prometheus_metrics() -> Response:
    """
    Prometheus metrics endpoint
    Returns metrics in Prometheus format
    """

    metrics_output = generate_latest()
    return Response(
        content=metrics_output,
        media_type=CONTENT_TYPE_LATEST
    )


@router.get("/system", response_model=SystemMetrics)
async def system_metrics() -> SystemMetrics:
    """
    System resource metrics
    """

    # CPU metrics
    cpu_percent = psutil.cpu_percent(interval=1)

    # Memory metrics
    memory = psutil.virtual_memory()
    memory_percent = memory.percent
    memory_used_gb = memory.used / (1024 ** 3)
    memory_total_gb = memory.total / (1024 ** 3)

    # Disk metrics
    disk = psutil.disk_usage('/')
    disk_usage_percent = disk.percent
    disk_used_gb = disk.used / (1024 ** 3)
    disk_total_gb = disk.total / (1024 ** 3)

    # Network metrics
    network_connections = len(psutil.net_connections())

    # Process metrics
    process_count = len(psutil.pids())

    # Load average (Unix only)
    try:
        load_average = list(os.getloadavg())
    except AttributeError:
        # Windows doesn't have getloadavg
        load_average = [cpu_percent / 100.0] * 3

    return SystemMetrics(
        cpu_percent=cpu_percent,
        memory_percent=memory_percent,
        memory_used_gb=round(memory_used_gb, 2),
        memory_total_gb=round(memory_total_gb, 2),
        disk_usage_percent=disk_usage_percent,
        disk_used_gb=round(disk_used_gb, 2),
        disk_total_gb=round(disk_total_gb, 2),
        network_connections=network_connections,
        process_count=process_count,
        load_average=load_average
    )


@router.get("/database", response_model=DatabaseHealth)
async def database_health(
    db: AsyncSession = Depends(get_db)
) -> DatabaseHealth:
    """
    Database health and metrics
    """

    start_time = datetime.utcnow()
    status = "healthy"
    error = None

    try:
        # Test database connection
        await db.execute(text("SELECT 1"))

        # Get database size
        size_result = await db.execute(
            text("SELECT pg_database_size(current_database()) / 1024 / 1024 as size_mb")
        )
        db_size_mb = size_result.scalar()

        # Get connection stats
        conn_result = await db.execute(
            text("""
                SELECT
                    count(*) as total,
                    count(*) FILTER (WHERE state = 'active') as active,
                    count(*) FILTER (WHERE state = 'idle') as idle
                FROM pg_stat_activity
                WHERE datname = current_database()
            """)
        )
        conn_stats = conn_result.first()

        # Get oldest transaction
        age_result = await db.execute(
            text("""
                SELECT EXTRACT(EPOCH FROM (now() - xact_start))::int as age
                FROM pg_stat_activity
                WHERE xact_start IS NOT NULL
                ORDER BY xact_start
                LIMIT 1
            """)
        )
        oldest_tx = age_result.scalar()

        response_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)

        # Update Prometheus metric
        database_connections_active.set(conn_stats.active if conn_stats else 0)

    except Exception as e:
        status = "unhealthy"
        error = str(e)
        response_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)

        return DatabaseHealth(
            status=status,
            connection_pool_size=0,
            active_connections=0,
            idle_connections=0,
            response_time_ms=response_time,
            database_size_mb=0,
            oldest_transaction_age_seconds=None
        )

    return DatabaseHealth(
        status=status,
        connection_pool_size=conn_stats.total if conn_stats else 0,
        active_connections=conn_stats.active if conn_stats else 0,
        idle_connections=conn_stats.idle if conn_stats else 0,
        response_time_ms=response_time,
        database_size_mb=float(db_size_mb) if db_size_mb else 0,
        oldest_transaction_age_seconds=oldest_tx
    )


@router.get("/services", response_model=List[ServiceHealth])
async def services_health(
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis),
    vault = Depends(get_vault)
) -> List[ServiceHealth]:
    """
    Individual service health status
    """

    services = []

    # Check each microservice
    service_endpoints = [
        ("authentication", f"http://localhost:8081/health"),
        ("gitops", f"http://localhost:8082/health"),
        ("deployment", f"http://localhost:8083/health"),
        ("device", f"http://localhost:8084/health")
    ]

    for service_name, endpoint in service_endpoints:
        health = await check_service_health(service_name, endpoint)
        services.append(ServiceHealth(
            service=service_name,
            status=health["status"],
            latency_ms=health.get("latency_ms"),
            error=health.get("error"),
            last_check=datetime.utcnow()
        ))

    # Check infrastructure services
    # Database
    db_health = await check_database_health(db)
    services.append(ServiceHealth(
        service="postgresql",
        status=db_health["status"],
        latency_ms=db_health.get("response_time_ms"),
        error=db_health.get("error"),
        last_check=datetime.utcnow()
    ))

    # Redis
    redis_health = await check_redis_health(redis)
    services.append(ServiceHealth(
        service="redis",
        status=redis_health["status"],
        latency_ms=redis_health.get("response_time_ms"),
        error=redis_health.get("error"),
        last_check=datetime.utcnow()
    ))

    # Vault
    vault_health = await check_vault_health(vault)
    services.append(ServiceHealth(
        service="vault",
        status=vault_health["status"],
        latency_ms=vault_health.get("response_time_ms"),
        error=vault_health.get("error"),
        last_check=datetime.utcnow()
    ))

    return services


@router.get("/components", response_model=List[ComponentStatus])
async def components_status(
    db: AsyncSession = Depends(get_db)
) -> List[ComponentStatus]:
    """
    Application components status
    """

    components = []

    # Device connectivity
    device_result = await db.execute(
        select(
            func.count(Device.id).label("total"),
            func.count(Device.id).filter(Device.status == "connected").label("connected"),
            func.count(Device.id).filter(Device.health_status == "critical").label("critical")
        )
    )
    device_stats = device_result.first()

    components.append(ComponentStatus(
        component="device_manager",
        status="healthy" if device_stats.critical == 0 else "degraded",
        version="1.0.0",
        last_heartbeat=datetime.utcnow(),
        error_count=device_stats.critical if device_stats else 0,
        warning_count=0,
        metadata={
            "total_devices": device_stats.total if device_stats else 0,
            "connected_devices": device_stats.connected if device_stats else 0
        }
    ))

    # Deployment engine
    deployment_result = await db.execute(
        select(
            func.count(Deployment.id).filter(Deployment.status == "running").label("running"),
            func.count(Deployment.id).filter(Deployment.status == "failed").label("failed")
        ).where(Deployment.created_at >= datetime.utcnow() - timedelta(hours=24))
    )
    deployment_stats = deployment_result.first()

    components.append(ComponentStatus(
        component="deployment_engine",
        status="healthy",
        version="1.0.0",
        last_heartbeat=datetime.utcnow(),
        error_count=deployment_stats.failed if deployment_stats else 0,
        warning_count=0,
        metadata={
            "running_deployments": deployment_stats.running if deployment_stats else 0,
            "failed_last_24h": deployment_stats.failed if deployment_stats else 0
        }
    ))

    # GitOps sync
    git_result = await db.execute(
        select(
            func.count(GitRepository.id).label("total"),
            func.count(GitRepository.id).filter(GitRepository.sync_status == "failed").label("failed")
        )
    )
    git_stats = git_result.first()

    components.append(ComponentStatus(
        component="gitops_sync",
        status="healthy" if git_stats.failed == 0 else "degraded",
        version="1.0.0",
        last_heartbeat=datetime.utcnow(),
        error_count=git_stats.failed if git_stats else 0,
        warning_count=0,
        metadata={
            "total_repositories": git_stats.total if git_stats else 0,
            "sync_failures": git_stats.failed if git_stats else 0
        }
    ))

    # Security monitoring
    incident_result = await db.execute(
        select(func.count(SecurityIncident.id))
        .where(
            SecurityIncident.created_at >= datetime.utcnow() - timedelta(hours=1)
        )
    )
    incident_count = incident_result.scalar()

    components.append(ComponentStatus(
        component="security_monitor",
        status="healthy" if incident_count < 10 else "warning",
        version="1.0.0",
        last_heartbeat=datetime.utcnow(),
        error_count=0,
        warning_count=incident_count,
        metadata={
            "incidents_last_hour": incident_count
        }
    ))

    return components


@router.get("/performance", response_model=PerformanceMetrics)
async def performance_metrics(
    time_range: str = Query("1h", regex="^(1h|6h|24h|7d|30d)$"),
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis)
) -> PerformanceMetrics:
    """
    API performance metrics
    """

    # Calculate time window
    time_windows = {
        "1h": timedelta(hours=1),
        "6h": timedelta(hours=6),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30)
    }

    since = datetime.utcnow() - time_windows[time_range]

    # Get metrics from Redis (assuming we're storing them there)
    metrics_key = f"performance_metrics:{time_range}"
    cached_metrics = await redis.get(metrics_key)

    if cached_metrics:
        import json
        metrics = json.loads(cached_metrics)
    else:
        # Calculate metrics from audit logs
        result = await db.execute(
            text("""
                SELECT
                    AVG(response_time_ms) as avg_response_time,
                    PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY response_time_ms) as p50,
                    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY response_time_ms) as p95,
                    PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY response_time_ms) as p99,
                    COUNT(*) / EXTRACT(EPOCH FROM (MAX(created_at) - MIN(created_at))) as rps,
                    SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END)::float / COUNT(*) as error_rate
                FROM audit_logs
                WHERE created_at >= :since
                AND response_time_ms IS NOT NULL
            """),
            {"since": since}
        )

        stats = result.first()

        if stats and stats.avg_response_time:
            metrics = {
                "avg_response_time_ms": float(stats.avg_response_time),
                "p50_response_time_ms": float(stats.p50) if stats.p50 else 0,
                "p95_response_time_ms": float(stats.p95) if stats.p95 else 0,
                "p99_response_time_ms": float(stats.p99) if stats.p99 else 0,
                "requests_per_second": float(stats.rps) if stats.rps else 0,
                "error_rate": float(stats.error_rate) if stats.error_rate else 0,
                "success_rate": 1.0 - (float(stats.error_rate) if stats.error_rate else 0)
            }
        else:
            # Default values if no data
            metrics = {
                "avg_response_time_ms": 0,
                "p50_response_time_ms": 0,
                "p95_response_time_ms": 0,
                "p99_response_time_ms": 0,
                "requests_per_second": 0,
                "error_rate": 0,
                "success_rate": 1.0
            }

        # Cache metrics for 1 minute
        await redis.set(metrics_key, json.dumps(metrics), ex=60)

    return PerformanceMetrics(**metrics)


async def check_database_health(db: AsyncSession) -> Dict[str, Any]:
    """
    Check database health
    """

    start_time = datetime.utcnow()

    try:
        await db.execute(text("SELECT 1"))
        response_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)

        return {
            "status": "healthy",
            "response_time_ms": response_time,
            "checked_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "checked_at": datetime.utcnow().isoformat()
        }


async def check_redis_health(redis) -> Dict[str, Any]:
    """
    Check Redis health
    """

    start_time = datetime.utcnow()

    try:
        await redis.ping()
        response_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)

        # Get Redis info
        info = await redis.info()

        return {
            "status": "healthy",
            "response_time_ms": response_time,
            "version": info.get("redis_version"),
            "used_memory_mb": info.get("used_memory") / 1024 / 1024 if "used_memory" in info else None,
            "connected_clients": info.get("connected_clients"),
            "checked_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "checked_at": datetime.utcnow().isoformat()
        }


async def check_vault_health(vault) -> Dict[str, Any]:
    """
    Check Vault health
    """

    try:
        health_status = await vault.check_health()

        return {
            "status": "healthy" if health_status else "unhealthy",
            "sealed": False,
            "checked_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "checked_at": datetime.utcnow().isoformat()
        }


async def check_message_queue_health() -> Dict[str, Any]:
    """
    Check message queue health (RabbitMQ/Kafka)
    """
    start_time = datetime.utcnow()

    # Try RabbitMQ first
    rabbitmq_result = await _check_rabbitmq_health()
    if rabbitmq_result["status"] == "healthy":
        return rabbitmq_result

    # If RabbitMQ is not available, try Kafka
    kafka_result = await _check_kafka_health()
    if kafka_result["status"] == "healthy":
        return kafka_result

    # If both fail, check Redis pub/sub as fallback
    redis_pubsub_result = await _check_redis_pubsub_health()

    return redis_pubsub_result


async def _check_rabbitmq_health() -> Dict[str, Any]:
    """
    Check RabbitMQ health via management API
    """
    start_time = datetime.utcnow()

    try:
        # RabbitMQ management API endpoint
        rabbitmq_host = getattr(settings, 'RABBITMQ_HOST', 'localhost')
        rabbitmq_port = getattr(settings, 'RABBITMQ_MGMT_PORT', 15672)
        rabbitmq_user = getattr(settings, 'RABBITMQ_USER', 'guest')
        rabbitmq_pass = getattr(settings, 'RABBITMQ_PASS', 'guest')

        management_url = f"http://{rabbitmq_host}:{rabbitmq_port}/api/overview"

        # Basic auth for RabbitMQ management API
        import base64
        auth_string = base64.b64encode(f"{rabbitmq_user}:{rabbitmq_pass}".encode()).decode()

        headers = {
            'Authorization': f'Basic {auth_string}',
            'Content-Type': 'application/json'
        }

        async with aiohttp.ClientSession() as session:
            async with session.get(
                management_url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                response_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)

                if response.status == 200:
                    data = await response.json()

                    # Get queue information
                    queues_url = f"http://{rabbitmq_host}:{rabbitmq_port}/api/queues"
                    async with session.get(
                        queues_url,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as queues_response:
                        if queues_response.status == 200:
                            queues_data = await queues_response.json()
                            total_messages = sum(queue.get('messages', 0) for queue in queues_data)
                            total_consumers = sum(queue.get('consumers', 0) for queue in queues_data)

                            return {
                                "status": "healthy",
                                "type": "rabbitmq",
                                "response_time_ms": response_time,
                                "version": data.get('rabbitmq_version'),
                                "cluster_name": data.get('cluster_name'),
                                "total_queues": len(queues_data),
                                "total_messages": total_messages,
                                "total_consumers": total_consumers,
                                "node_name": data.get('node'),
                                "memory_mb": data.get('mem_used', 0) / 1024 / 1024,
                                "checked_at": datetime.utcnow().isoformat()
                            }
                        else:
                            return {
                                "status": "degraded",
                                "type": "rabbitmq",
                                "response_time_ms": response_time,
                                "error": "Could not fetch queue information",
                                "checked_at": datetime.utcnow().isoformat()
                            }
                else:
                    return {
                        "status": "unhealthy",
                        "type": "rabbitmq",
                        "error": f"HTTP {response.status}",
                        "response_time_ms": response_time,
                        "checked_at": datetime.utcnow().isoformat()
                    }

    except aiohttp.ClientError as e:
        return {
            "status": "unhealthy",
            "type": "rabbitmq",
            "error": f"Connection error: {str(e)}",
            "checked_at": datetime.utcnow().isoformat()
        }
    except asyncio.TimeoutError:
        return {
            "status": "unhealthy",
            "type": "rabbitmq",
            "error": "Timeout",
            "checked_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "type": "rabbitmq",
            "error": str(e),
            "checked_at": datetime.utcnow().isoformat()
        }


async def _check_kafka_health() -> Dict[str, Any]:
    """
    Check Kafka health
    """
    start_time = datetime.utcnow()

    try:
        # Try to import aiokafka
        try:
            from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
        except ImportError:
            return {
                "status": "unavailable",
                "type": "kafka",
                "error": "aiokafka library not installed",
                "checked_at": datetime.utcnow().isoformat()
            }

        kafka_bootstrap_servers = getattr(settings, 'KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092')

        # Create a producer to test connectivity
        producer = AIOKafkaProducer(
            bootstrap_servers=kafka_bootstrap_servers,
            request_timeout_ms=5000,
            api_version='auto'
        )

        try:
            await producer.start()

            # Get cluster metadata
            cluster = producer.client.cluster
            brokers = list(cluster.brokers())

            response_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)

            # Try to get topic metadata
            try:
                topics = await producer.list_consumer_groups()
                topic_count = len(topics) if topics else 0
            except:
                topic_count = 0

            return {
                "status": "healthy",
                "type": "kafka",
                "response_time_ms": response_time,
                "bootstrap_servers": kafka_bootstrap_servers,
                "broker_count": len(brokers),
                "topic_count": topic_count,
                "brokers": [f"{broker.host}:{broker.port}" for broker in brokers[:3]],  # Limit to first 3
                "checked_at": datetime.utcnow().isoformat()
            }

        finally:
            await producer.stop()

    except asyncio.TimeoutError:
        return {
            "status": "unhealthy",
            "type": "kafka",
            "error": "Connection timeout",
            "checked_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "type": "kafka",
            "error": str(e),
            "checked_at": datetime.utcnow().isoformat()
        }


async def _check_redis_pubsub_health() -> Dict[str, Any]:
    """
    Check Redis pub/sub health as fallback message queue
    """
    start_time = datetime.utcnow()

    try:
        import aioredis

        redis_url = getattr(settings, 'REDIS_URL', 'redis://localhost:6379')

        redis = aioredis.from_url(redis_url)

        try:
            # Test basic Redis connectivity
            await redis.ping()

            # Test pub/sub functionality
            pubsub = redis.pubsub()
            test_channel = "catnet:health:test"

            try:
                await pubsub.subscribe(test_channel)
                await redis.publish(test_channel, "health_check")

                # Try to receive the message with timeout
                message = await asyncio.wait_for(
                    pubsub.get_message(ignore_subscribe_messages=True),
                    timeout=2.0
                )

                pubsub_working = message is not None and message.get('data') == b'health_check'

            except asyncio.TimeoutError:
                pubsub_working = False
            finally:
                await pubsub.unsubscribe(test_channel)
                await pubsub.close()

            response_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)

            # Get Redis info for additional metrics
            info = await redis.info()

            return {
                "status": "healthy" if pubsub_working else "degraded",
                "type": "redis_pubsub",
                "response_time_ms": response_time,
                "pubsub_working": pubsub_working,
                "redis_version": info.get('redis_version'),
                "connected_clients": info.get('connected_clients'),
                "used_memory_mb": info.get('used_memory', 0) / 1024 / 1024,
                "pubsub_channels": info.get('pubsub_channels', 0),
                "pubsub_patterns": info.get('pubsub_patterns', 0),
                "checked_at": datetime.utcnow().isoformat()
            }

        finally:
            await redis.close()

    except Exception as e:
        return {
            "status": "unhealthy",
            "type": "redis_pubsub",
            "error": str(e),
            "checked_at": datetime.utcnow().isoformat()
        }


async def check_service_health(service_name: str, endpoint: str) -> Dict[str, Any]:
    """
    Check individual microservice health
    """
    start_time = datetime.utcnow()

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(endpoint, timeout=5) as response:
                latency_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

                if response.status == 200:
                    return {
                        "status": "healthy",
                        "latency_ms": latency_ms
                    }
                else:
                    return {
                        "status": "unhealthy",
                        "error": f"HTTP {response.status}",
                        "latency_ms": latency_ms
                    }
    except asyncio.TimeoutError:
        return {
            "status": "unhealthy",
            "error": "Timeout"
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e)
        }


@router.get("/debug")
async def debug_info(
    current_user: User = Depends(get_current_user_optional)
) -> Dict[str, Any]:
    """
    Debug information (only in development mode)
    """

    if settings.ENVIRONMENT != "development":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Debug endpoint only available in development"
        )

    return {
        "environment": settings.ENVIRONMENT,
        "version": settings.APP_VERSION,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "current_user": current_user.username if current_user else None,
        "config": {
            "database_url": "***hidden***",
            "redis_url": "***hidden***",
            "vault_url": settings.VAULT_URL,
            "debug_mode": settings.DEBUG,
            "log_level": settings.LOG_LEVEL
        }
    }