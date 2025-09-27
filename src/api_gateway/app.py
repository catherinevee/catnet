"""
API Gateway application.
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta

from fastapi import FastAPI, Request, Response, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware as FastAPICORS
from fastapi.responses import JSONResponse
import uvicorn
from prometheus_client import Counter, Histogram, Gauge, generate_latest
import redis.asyncio as redis
import httpx
from starlette.middleware.base import BaseHTTPMiddleware

from .models import (
    GatewayConfig, GatewayRequest, GatewayResponse, ServiceRegistration,
    RouteRule, RateLimitRule, CacheRule, SecurityRule, GatewayMetrics,
    ErrorResponse, AdminRequest, AdminResponse
)
from .router import ServiceRouter, LoadBalancer, HealthChecker, CircuitBreaker
from .middleware import (
    AuthenticationMiddleware, RateLimitMiddleware, LoggingMiddleware,
    MetricsMiddleware, TracingMiddleware, CompressionMiddleware,
    SecurityHeadersMiddleware, RequestValidationMiddleware,
    ResponseCacheMiddleware, RequestIdMiddleware, TimeoutMiddleware
)
from .auth import TokenValidator, PermissionChecker, ServiceAuthenticator
from .ratelimit import RateLimiter, UserRateLimiter, IPRateLimiter
from .cache import ResponseCache, CacheManager
from .monitoring import GatewayMonitor, RequestTracer, PerformanceMonitor
from .security import WAF, DDoSProtection, IPWhitelist, IPBlacklist
from .discovery import ServiceRegistry, ServiceDiscovery, HealthCheckScheduler

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Prometheus metrics
gateway_requests_total = Counter(
    'catnet_gateway_requests_total',
    'Total gateway requests',
    ['method', 'path', 'service', 'status']
)
gateway_request_duration = Histogram(
    'catnet_gateway_request_duration_seconds',
    'Gateway request duration',
    ['method', 'path', 'service']
)
gateway_active_connections = Gauge(
    'catnet_gateway_active_connections',
    'Active gateway connections'
)
gateway_cache_hits = Counter(
    'catnet_gateway_cache_hits_total',
    'Cache hits'
)
gateway_cache_misses = Counter(
    'catnet_gateway_cache_misses_total',
    'Cache misses'
)
gateway_rate_limited = Counter(
    'catnet_gateway_rate_limited_total',
    'Rate limited requests'
)
gateway_circuit_breaker_state = Gauge(
    'catnet_gateway_circuit_breaker_state',
    'Circuit breaker state',
    ['service']
)

# Global instances
config: Optional[GatewayConfig] = None
redis_client: Optional[redis.Redis] = None
service_router: Optional[ServiceRouter] = None
service_registry: Optional[ServiceRegistry] = None
service_discovery: Optional[ServiceDiscovery] = None
load_balancers: Dict[str, LoadBalancer] = {}
circuit_breakers: Dict[str, CircuitBreaker] = {}
health_checker: Optional[HealthChecker] = None
rate_limiter: Optional[RateLimiter] = None
response_cache: Optional[ResponseCache] = None
cache_manager: Optional[CacheManager] = None
token_validator: Optional[TokenValidator] = None
permission_checker: Optional[PermissionChecker] = None
waf: Optional[WAF] = None
ddos_protection: Optional[DDoSProtection] = None
gateway_monitor: Optional[GatewayMonitor] = None
request_tracer: Optional[RequestTracer] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("Starting API Gateway...")

    # Load configuration
    global config
    config = await load_configuration()

    # Initialize Redis
    global redis_client
    redis_client = redis.Redis(
        host='localhost',
        port=6379,
        decode_responses=True,
        ssl=True,
        ssl_cert_reqs='required',
        ssl_keyfile=config.ssl_key,
        ssl_certfile=config.ssl_cert
    )

    # Initialize service discovery
    global service_registry, service_discovery
    service_registry = ServiceRegistry(redis_client)
    service_discovery = ServiceDiscovery(service_registry)

    # Register default services
    await register_default_services()

    # Initialize router
    global service_router
    service_router = ServiceRouter(service_discovery)
    await service_router.initialize()

    # Initialize load balancers
    await initialize_load_balancers()

    # Initialize circuit breakers
    await initialize_circuit_breakers()

    # Initialize health checker
    global health_checker
    health_checker = HealthChecker(service_discovery)
    asyncio.create_task(health_checker.start())

    # Initialize rate limiter
    global rate_limiter
    rate_limiter = RateLimiter(redis_client)
    await rate_limiter.initialize()

    # Initialize cache
    global response_cache, cache_manager
    response_cache = ResponseCache(redis_client)
    cache_manager = CacheManager(response_cache)
    await cache_manager.initialize()

    # Initialize authentication
    global token_validator, permission_checker
    token_validator = TokenValidator(redis_client)
    permission_checker = PermissionChecker()

    # Initialize security
    global waf, ddos_protection
    waf = WAF()
    ddos_protection = DDoSProtection(redis_client)
    await waf.initialize()
    await ddos_protection.initialize()

    # Initialize monitoring
    global gateway_monitor, request_tracer
    gateway_monitor = GatewayMonitor()
    request_tracer = RequestTracer()

    # Start background tasks
    asyncio.create_task(refresh_service_registry())
    asyncio.create_task(cleanup_cache())
    asyncio.create_task(update_metrics())

    logger.info("API Gateway started successfully")

    yield

    # Cleanup
    logger.info("Shutting down API Gateway...")
    await health_checker.stop()
    await redis_client.close()
    logger.info("API Gateway stopped")


async def load_configuration() -> GatewayConfig:
    """Load gateway configuration."""
    # In production, load from file or environment
    return GatewayConfig(
        host="0.0.0.0",
        port=8080,
        ssl_enabled=True,
        ssl_cert="/etc/catnet/certs/gateway-cert.pem",
        ssl_key="/etc/catnet/certs/gateway-key.pem"
    )


async def register_default_services():
    """Register default microservices."""
    services = [
        ServiceRegistration(
            name="authentication",
            type="authentication",
            version="1.0.0",
            endpoints=[{
                "service_name": "authentication",
                "url": "https://localhost:8081",
                "host": "localhost",
                "port": 8081
            }]
        ),
        ServiceRegistration(
            name="gitops",
            type="gitops",
            version="1.0.0",
            endpoints=[{
                "service_name": "gitops",
                "url": "https://localhost:8082",
                "host": "localhost",
                "port": 8082
            }]
        ),
        ServiceRegistration(
            name="deployment",
            type="deployment",
            version="1.0.0",
            endpoints=[{
                "service_name": "deployment",
                "url": "https://localhost:8083",
                "host": "localhost",
                "port": 8083
            }]
        ),
        ServiceRegistration(
            name="device",
            type="device",
            version="1.0.0",
            endpoints=[{
                "service_name": "device",
                "url": "https://localhost:8084",
                "host": "localhost",
                "port": 8084
            }]
        ),
        ServiceRegistration(
            name="monitoring",
            type="monitoring",
            version="1.0.0",
            endpoints=[{
                "service_name": "monitoring",
                "url": "https://localhost:8085",
                "host": "localhost",
                "port": 8085
            }]
        )
    ]

    for service in services:
        await service_registry.register(service)


async def initialize_load_balancers():
    """Initialize load balancers for services."""
    services = await service_registry.list_services()

    for service in services:
        load_balancers[service.name] = LoadBalancer(
            strategy=service.load_balancer,
            endpoints=service.endpoints
        )


async def initialize_circuit_breakers():
    """Initialize circuit breakers for services."""
    services = await service_registry.list_services()

    for service in services:
        if service.circuit_breaker:
            circuit_breakers[service.name] = CircuitBreaker(
                service.name,
                service.circuit_breaker
            )


async def refresh_service_registry():
    """Refresh service registry periodically."""
    while True:
        try:
            await service_discovery.refresh()
            await initialize_load_balancers()
            await asyncio.sleep(30)
        except Exception as e:
            logger.error(f"Error refreshing service registry: {e}")
            await asyncio.sleep(60)


async def cleanup_cache():
    """Clean up expired cache entries."""
    while True:
        try:
            await cache_manager.cleanup()
            await asyncio.sleep(300)  # Every 5 minutes
        except Exception as e:
            logger.error(f"Error cleaning cache: {e}")
            await asyncio.sleep(600)


async def update_metrics():
    """Update gateway metrics."""
    while True:
        try:
            # Update circuit breaker metrics
            for name, cb in circuit_breakers.items():
                state_value = {"closed": 0, "open": 1, "half_open": 0.5}
                gateway_circuit_breaker_state.labels(service=name).set(
                    state_value.get(cb.state, 0)
                )

            await asyncio.sleep(10)
        except Exception as e:
            logger.error(f"Error updating metrics: {e}")
            await asyncio.sleep(30)


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="CatNet API Gateway",
        description="Central API gateway for CatNet microservices",
        version="1.0.0",
        lifespan=lifespan
    )

    # Add CORS middleware
    app.add_middleware(
        FastAPICORS,
        allow_origins=["https://catnet.local"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add custom middleware
    app.add_middleware(RequestIdMiddleware)
    app.add_middleware(TimeoutMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(CompressionMiddleware)
    app.add_middleware(ResponseCacheMiddleware)
    app.add_middleware(RequestValidationMiddleware)
    app.add_middleware(TracingMiddleware)
    app.add_middleware(MetricsMiddleware)
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(AuthenticationMiddleware)

    return app


# Create application instance
app = create_app()


# Main gateway handler
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def gateway_handler(
    request: Request,
    path: str,
    response: Response
) -> Any:
    """Main gateway request handler."""
    gateway_active_connections.inc()

    try:
        # Create gateway request
        gateway_request = await create_gateway_request(request, path)

        # Check WAF
        if waf and not await waf.check_request(gateway_request):
            gateway_requests_total.labels(
                method=request.method,
                path=path,
                service="blocked",
                status="403"
            ).inc()
            raise HTTPException(403, "Request blocked by WAF")

        # Check DDoS protection
        if ddos_protection and await ddos_protection.is_attack_detected(gateway_request.client_ip):
            gateway_requests_total.labels(
                method=request.method,
                path=path,
                service="blocked",
                status="429"
            ).inc()
            raise HTTPException(429, "Too many requests")

        # Route request
        route = await service_router.match_route(path, request.method)
        if not route:
            raise HTTPException(404, "Route not found")

        # Get service endpoint
        service_name = route.service
        if service_name not in load_balancers:
            raise HTTPException(503, f"Service {service_name} not available")

        # Check circuit breaker
        if service_name in circuit_breakers:
            cb = circuit_breakers[service_name]
            if not await cb.call_allowed():
                gateway_requests_total.labels(
                    method=request.method,
                    path=path,
                    service=service_name,
                    status="503"
                ).inc()
                raise HTTPException(503, f"Service {service_name} circuit breaker open")

        # Check cache
        cache_key = await cache_manager.generate_key(gateway_request)
        cached_response = await response_cache.get(cache_key)

        if cached_response:
            gateway_cache_hits.inc()
            gateway_requests_total.labels(
                method=request.method,
                path=path,
                service=service_name,
                status="200"
            ).inc()
            return JSONResponse(
                content=cached_response,
                headers={"X-Cache": "HIT"}
            )

        gateway_cache_misses.inc()

        # Select endpoint
        endpoint = await load_balancers[service_name].select_endpoint()
        if not endpoint:
            raise HTTPException(503, f"No healthy endpoints for {service_name}")

        # Transform request
        transformed_request = await transform_request(gateway_request, route)

        # Forward request
        start_time = datetime.utcnow()

        try:
            service_response = await forward_request(
                transformed_request,
                endpoint,
                route.timeout_override or config.request_timeout
            )

            # Record success
            if service_name in circuit_breakers:
                await circuit_breakers[service_name].record_success()

            # Transform response
            gateway_response = await transform_response(service_response, route)

            # Cache response if cacheable
            if request.method in ["GET", "HEAD"] and service_response.status_code == 200:
                await response_cache.set(cache_key, gateway_response.body, ttl=300)

            # Record metrics
            latency = (datetime.utcnow() - start_time).total_seconds()
            gateway_request_duration.labels(
                method=request.method,
                path=path,
                service=service_name
            ).observe(latency)
            gateway_requests_total.labels(
                method=request.method,
                path=path,
                service=service_name,
                status=str(service_response.status_code)
            ).inc()

            # Set response headers
            response.headers.update(gateway_response.headers)

            return gateway_response.body

        except httpx.TimeoutException:
            if service_name in circuit_breakers:
                await circuit_breakers[service_name].record_failure()
            raise HTTPException(504, "Gateway timeout")

        except Exception as e:
            if service_name in circuit_breakers:
                await circuit_breakers[service_name].record_failure()
            logger.error(f"Error forwarding request: {e}")
            raise HTTPException(502, "Bad gateway")

    finally:
        gateway_active_connections.dec()


async def create_gateway_request(request: Request, path: str) -> GatewayRequest:
    """Create gateway request from FastAPI request."""
    body = None
    if request.method not in ["GET", "HEAD", "OPTIONS"]:
        body = await request.body()
        if body:
            try:
                import json
                body = json.loads(body)
            except:
                body = body.decode('utf-8')

    return GatewayRequest(
        method=request.method,
        path=path,
        headers=dict(request.headers),
        query_params=dict(request.query_params),
        body=body,
        client_ip=request.client.host,
        user_agent=request.headers.get("user-agent"),
        auth_token=request.headers.get("authorization"),
        api_key=request.headers.get("x-api-key"),
        session_id=request.cookies.get("session_id"),
        trace_id=request.headers.get("x-trace-id", str(uuid.uuid4())),
        span_id=str(uuid.uuid4())
    )


async def transform_request(request: GatewayRequest, route: RouteRule) -> GatewayRequest:
    """Transform request based on route rules."""
    # Rewrite path
    if route.rewrite_path:
        request.path = route.rewrite_path.format(path=request.path)

    # Strip path prefix
    if route.strip_path:
        prefix = route.path_pattern.replace("*", "").replace("$", "")
        request.path = request.path.replace(prefix, "", 1)

    # Add headers
    request.headers.update(route.add_headers)

    # Remove headers
    for header in route.remove_headers:
        request.headers.pop(header, None)

    # Add query params
    request.query_params.update(route.add_query_params)

    return request


async def forward_request(
    request: GatewayRequest,
    endpoint: Dict[str, Any],
    timeout: int
) -> httpx.Response:
    """Forward request to service endpoint."""
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        verify=False  # In production, use proper SSL verification
    ) as client:
        url = f"{endpoint['url']}{request.path}"

        # Prepare request
        kwargs = {
            "method": request.method,
            "url": url,
            "headers": request.headers,
            "params": request.query_params
        }

        if request.body:
            if isinstance(request.body, dict):
                kwargs["json"] = request.body
            else:
                kwargs["content"] = request.body

        # Send request
        response = await client.request(**kwargs)

        return response


async def transform_response(response: httpx.Response, route: RouteRule) -> GatewayResponse:
    """Transform response based on route rules."""
    # Parse response body
    body = None
    content_type = response.headers.get("content-type", "")

    if "application/json" in content_type:
        try:
            body = response.json()
        except:
            body = response.text
    else:
        body = response.text

    gateway_response = GatewayResponse(
        status_code=response.status_code,
        headers=dict(response.headers),
        body=body
    )

    # Add gateway headers
    gateway_response.headers["X-Gateway"] = "CatNet"
    gateway_response.headers["X-Service"] = route.service

    return gateway_response


# Health check endpoints
@app.get("/health")
async def health_check() -> Dict[str, Any]:
    """Gateway health check."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": config.version if config else "unknown"
    }


@app.get("/ready")
async def ready_check() -> Dict[str, Any]:
    """Gateway readiness check."""
    # Check critical components
    checks = {
        "redis": redis_client is not None and await redis_client.ping(),
        "service_registry": service_registry is not None,
        "router": service_router is not None
    }

    if all(checks.values()):
        return {
            "status": "ready",
            "checks": checks,
            "timestamp": datetime.utcnow().isoformat()
        }
    else:
        raise HTTPException(503, detail={"status": "not ready", "checks": checks})


@app.get("/metrics")
async def metrics() -> str:
    """Prometheus metrics endpoint."""
    return generate_latest()


# Admin endpoints
@app.post("/admin/reload")
async def reload_configuration(
    request: AdminRequest,
    authorized: bool = Depends(check_admin_auth)
) -> AdminResponse:
    """Reload gateway configuration."""
    if not authorized:
        raise HTTPException(403, "Unauthorized")

    try:
        # Reload configuration
        global config
        config = await load_configuration()

        # Refresh services
        await service_discovery.refresh()
        await initialize_load_balancers()
        await initialize_circuit_breakers()

        return AdminResponse(
            success=True,
            action="reload",
            message="Configuration reloaded successfully"
        )
    except Exception as e:
        return AdminResponse(
            success=False,
            action="reload",
            message=f"Failed to reload: {str(e)}"
        )


@app.post("/admin/cache/purge")
async def purge_cache(
    request: AdminRequest,
    authorized: bool = Depends(check_admin_auth)
) -> AdminResponse:
    """Purge response cache."""
    if not authorized:
        raise HTTPException(403, "Unauthorized")

    try:
        count = await cache_manager.purge(request.target)

        return AdminResponse(
            success=True,
            action="cache_purge",
            message=f"Purged {count} cache entries",
            result={"purged_count": count}
        )
    except Exception as e:
        return AdminResponse(
            success=False,
            action="cache_purge",
            message=f"Failed to purge cache: {str(e)}"
        )


@app.get("/admin/services")
async def list_services(
    authorized: bool = Depends(check_admin_auth)
) -> Dict[str, Any]:
    """List registered services."""
    if not authorized:
        raise HTTPException(403, "Unauthorized")

    services = await service_registry.list_services()

    return {
        "services": [
            {
                "name": s.name,
                "type": s.type,
                "version": s.version,
                "endpoints": len(s.endpoints),
                "healthy_endpoints": sum(1 for e in s.endpoints if e.healthy)
            }
            for s in services
        ],
        "total": len(services)
    }


@app.get("/admin/metrics")
async def get_gateway_metrics(
    authorized: bool = Depends(check_admin_auth)
) -> GatewayMetrics:
    """Get gateway metrics."""
    if not authorized:
        raise HTTPException(403, "Unauthorized")

    # Collect metrics
    metrics = await gateway_monitor.collect_metrics()

    return metrics


async def check_admin_auth(request: Request) -> bool:
    """Check admin authorization."""
    if not config or not config.admin_auth_required:
        return True

    # Check API key
    api_key = request.headers.get("x-admin-api-key")
    if api_key and await validate_admin_api_key(api_key):
        return True

    # Check JWT token
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:]
        if await token_validator.validate(token):
            user = await token_validator.get_user(token)
            if "admin" in user.get("roles", []):
                return True

    return False


async def validate_admin_api_key(api_key: str) -> bool:
    """Validate admin API key."""
    # Implementation would check against stored admin keys
    return False


if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8080,
        ssl_keyfile="/etc/catnet/certs/gateway-key.pem",
        ssl_certfile="/etc/catnet/certs/gateway-cert.pem",
        log_level="info",
        reload=False
    )