"""
Service router for API gateway.
"""

import asyncio
import logging
import random
import hashlib
import re
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from enum import Enum

from .models import (
    RouteRule, ServiceEndpoint, LoadBalancerStrategy,
    CircuitBreakerConfig, RetryConfig, CircuitState
)

logger = logging.getLogger(__name__)


class ServiceRouter:
    """Routes requests to appropriate services."""

    def __init__(self, service_discovery):
        self.service_discovery = service_discovery
        self.routes = []
        self.route_cache = {}
        self.patterns = {}

    async def initialize(self):
        """Initialize router."""
        await self.load_routes()
        self.compile_patterns()

    async def load_routes(self):
        """Load routing rules."""
        # Default routes for microservices
        self.routes = [
            RouteRule(
                name="auth_routes",
                path_pattern="/api/v1/auth/*",
                service="authentication",
                strip_path=True,
                priority=100
            ),
            RouteRule(
                name="gitops_routes",
                path_pattern="/api/v1/git/*",
                service="gitops",
                strip_path=True,
                priority=100
            ),
            RouteRule(
                name="deployment_routes",
                path_pattern="/api/v1/deployments/*",
                service="deployment",
                strip_path=True,
                priority=100
            ),
            RouteRule(
                name="device_routes",
                path_pattern="/api/v1/devices/*",
                service="device",
                strip_path=True,
                priority=100
            ),
            RouteRule(
                name="monitoring_routes",
                path_pattern="/api/v1/monitoring/*",
                service="monitoring",
                strip_path=True,
                priority=100
            ),
            RouteRule(
                name="metrics_route",
                path_pattern="/api/v1/metrics/*",
                service="monitoring",
                strip_path=True,
                priority=90
            ),
            RouteRule(
                name="alerts_route",
                path_pattern="/api/v1/alerts/*",
                service="monitoring",
                strip_path=True,
                priority=90
            )
        ]

        # Sort by priority
        self.routes.sort(key=lambda r: r.priority, reverse=True)

    def compile_patterns(self):
        """Compile route patterns to regex."""
        for route in self.routes:
            # Convert glob pattern to regex
            pattern = route.path_pattern
            pattern = pattern.replace("*", ".*")
            pattern = f"^{pattern}$"
            self.patterns[route.name] = re.compile(pattern)

    async def match_route(self, path: str, method: str) -> Optional[RouteRule]:
        """Match request to route."""
        # Check cache
        cache_key = f"{method}:{path}"
        if cache_key in self.route_cache:
            return self.route_cache[cache_key]

        # Find matching route
        for route in self.routes:
            if not route.is_enabled:
                continue

            # Check method
            if "*" not in route.methods and method not in route.methods:
                continue

            # Check path pattern
            if self.patterns[route.name].match(path):
                self.route_cache[cache_key] = route
                return route

        return None

    def add_route(self, route: RouteRule):
        """Add new route."""
        self.routes.append(route)
        self.routes.sort(key=lambda r: r.priority, reverse=True)

        # Compile pattern
        pattern = route.path_pattern.replace("*", ".*")
        pattern = f"^{pattern}$"
        self.patterns[route.name] = re.compile(pattern)

        # Clear cache
        self.route_cache.clear()

    def remove_route(self, route_name: str):
        """Remove route."""
        self.routes = [r for r in self.routes if r.name != route_name]
        self.patterns.pop(route_name, None)
        self.route_cache.clear()

    def update_route(self, route: RouteRule):
        """Update existing route."""
        for i, r in enumerate(self.routes):
            if r.name == route.name:
                self.routes[i] = route
                break

        # Re-compile pattern
        pattern = route.path_pattern.replace("*", ".*")
        pattern = f"^{pattern}$"
        self.patterns[route.name] = re.compile(pattern)

        # Clear cache
        self.route_cache.clear()

    def clear_cache(self):
        """Clear route cache."""
        self.route_cache.clear()


class LoadBalancer:
    """Load balances requests across service endpoints."""

    def __init__(self, strategy: LoadBalancerStrategy, endpoints: List[ServiceEndpoint]):
        self.strategy = strategy
        self.endpoints = endpoints
        self.current_index = 0
        self.connections = {}  # endpoint_id -> connection_count
        self.weights = {}  # endpoint_id -> weight
        self._initialize_weights()

    def _initialize_weights(self):
        """Initialize endpoint weights."""
        for endpoint in self.endpoints:
            self.weights[endpoint.id] = endpoint.weight
            self.connections[endpoint.id] = 0

    async def select_endpoint(self) -> Optional[ServiceEndpoint]:
        """Select next endpoint based on strategy."""
        healthy_endpoints = [e for e in self.endpoints if e.healthy]

        if not healthy_endpoints:
            return None

        if self.strategy == LoadBalancerStrategy.ROUND_ROBIN:
            return self._round_robin(healthy_endpoints)
        elif self.strategy == LoadBalancerStrategy.LEAST_CONNECTIONS:
            return self._least_connections(healthy_endpoints)
        elif self.strategy == LoadBalancerStrategy.WEIGHTED_ROUND_ROBIN:
            return self._weighted_round_robin(healthy_endpoints)
        elif self.strategy == LoadBalancerStrategy.IP_HASH:
            # Requires client IP, using random for now
            return self._random(healthy_endpoints)
        elif self.strategy == LoadBalancerStrategy.RANDOM:
            return self._random(healthy_endpoints)
        elif self.strategy == LoadBalancerStrategy.CONSISTENT_HASH:
            return self._consistent_hash(healthy_endpoints)
        else:
            return self._round_robin(healthy_endpoints)

    def _round_robin(self, endpoints: List[ServiceEndpoint]) -> ServiceEndpoint:
        """Round-robin selection."""
        endpoint = endpoints[self.current_index % len(endpoints)]
        self.current_index += 1
        return endpoint

    def _least_connections(self, endpoints: List[ServiceEndpoint]) -> ServiceEndpoint:
        """Select endpoint with least connections."""
        return min(endpoints, key=lambda e: self.connections.get(e.id, 0))

    def _weighted_round_robin(self, endpoints: List[ServiceEndpoint]) -> ServiceEndpoint:
        """Weighted round-robin selection."""
        weighted_list = []
        for endpoint in endpoints:
            weight = self.weights.get(endpoint.id, 1)
            weighted_list.extend([endpoint] * weight)

        if weighted_list:
            endpoint = weighted_list[self.current_index % len(weighted_list)]
            self.current_index += 1
            return endpoint

        return endpoints[0]

    def _random(self, endpoints: List[ServiceEndpoint]) -> ServiceEndpoint:
        """Random selection."""
        return random.choice(endpoints)

    def _consistent_hash(self, endpoints: List[ServiceEndpoint], key: str = None) -> ServiceEndpoint:
        """Consistent hashing selection."""
        if not key:
            key = str(datetime.utcnow().timestamp())

        # Create hash ring
        ring = {}
        for endpoint in endpoints:
            for i in range(150):  # Virtual nodes
                hash_key = hashlib.md5(f"{endpoint.id}:{i}".encode()).hexdigest()
                ring[hash_key] = endpoint

        # Find endpoint
        sorted_keys = sorted(ring.keys())
        hash_value = hashlib.md5(key.encode()).hexdigest()

        for ring_key in sorted_keys:
            if hash_value <= ring_key:
                return ring[ring_key]

        return ring[sorted_keys[0]]

    def mark_healthy(self, endpoint_id: str):
        """Mark endpoint as healthy."""
        for endpoint in self.endpoints:
            if endpoint.id == endpoint_id:
                endpoint.healthy = True
                endpoint.last_health_check = datetime.utcnow()

    def mark_unhealthy(self, endpoint_id: str):
        """Mark endpoint as unhealthy."""
        for endpoint in self.endpoints:
            if endpoint.id == endpoint_id:
                endpoint.healthy = False
                endpoint.last_health_check = datetime.utcnow()

    def increment_connections(self, endpoint_id: str):
        """Increment connection count."""
        self.connections[endpoint_id] = self.connections.get(endpoint_id, 0) + 1

    def decrement_connections(self, endpoint_id: str):
        """Decrement connection count."""
        if endpoint_id in self.connections and self.connections[endpoint_id] > 0:
            self.connections[endpoint_id] -= 1

    def update_response_time(self, endpoint_id: str, response_time_ms: float):
        """Update endpoint response time."""
        for endpoint in self.endpoints:
            if endpoint.id == endpoint_id:
                endpoint.response_time_ms = response_time_ms

    def update_success_rate(self, endpoint_id: str, success: bool):
        """Update endpoint success rate."""
        for endpoint in self.endpoints:
            if endpoint.id == endpoint_id:
                # Simple moving average
                current_rate = endpoint.success_rate
                new_rate = 100.0 if success else 0.0
                endpoint.success_rate = current_rate * 0.9 + new_rate * 0.1


class HealthChecker:
    """Performs health checks on service endpoints."""

    def __init__(self, service_discovery):
        self.service_discovery = service_discovery
        self.check_interval = 30  # seconds
        self.timeout = 10
        self.running = False

    async def start(self):
        """Start health checking."""
        self.running = True
        await self._health_check_loop()

    async def stop(self):
        """Stop health checking."""
        self.running = False

    async def _health_check_loop(self):
        """Main health check loop."""
        while self.running:
            try:
                await self.check_all_endpoints()
                await asyncio.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"Health check error: {e}")
                await asyncio.sleep(self.check_interval)

    async def check_all_endpoints(self):
        """Check health of all endpoints."""
        services = await self.service_discovery.get_all_services()

        tasks = []
        for service in services:
            for endpoint in service.endpoints:
                if service.health_check:
                    tasks.append(self.check_endpoint(endpoint, service.health_check))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def check_endpoint(self, endpoint: ServiceEndpoint, config: Dict[str, Any]) -> bool:
        """Check health of single endpoint."""
        try:
            if config['type'] == 'http' or config['type'] == 'https':
                return await self._http_health_check(endpoint, config)
            elif config['type'] == 'tcp':
                return await self._tcp_health_check(endpoint, config)
            elif config['type'] == 'grpc':
                return await self._grpc_health_check(endpoint, config)
            else:
                logger.warning(f"Unknown health check type: {config['type']}")
                return True

        except Exception as e:
            logger.error(f"Health check failed for {endpoint.id}: {e}")
            endpoint.healthy = False
            endpoint.last_health_check = datetime.utcnow()
            return False

    async def _http_health_check(self, endpoint: ServiceEndpoint, config: Dict[str, Any]) -> bool:
        """Perform HTTP health check."""
        import httpx

        url = f"{endpoint.protocol}://{endpoint.host}:{endpoint.port}{config['endpoint']}"

        try:
            async with httpx.AsyncClient(timeout=config.get('timeout', self.timeout)) as client:
                response = await client.get(url, headers=config.get('headers', {}))

                # Check status code
                expected_status = config.get('expected_status', [200, 204])
                if response.status_code not in expected_status:
                    endpoint.healthy = False
                    return False

                # Check response body if configured
                if config.get('expected_body'):
                    if config['expected_body'] not in response.text:
                        endpoint.healthy = False
                        return False

                endpoint.healthy = True
                endpoint.last_health_check = datetime.utcnow()
                endpoint.response_time_ms = response.elapsed.total_seconds() * 1000
                return True

        except Exception as e:
            logger.debug(f"HTTP health check failed for {endpoint.id}: {e}")
            endpoint.healthy = False
            return False

    async def _tcp_health_check(self, endpoint: ServiceEndpoint, config: Dict[str, Any]) -> bool:
        """Perform TCP health check."""
        import socket

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(config.get('timeout', self.timeout))

            result = sock.connect_ex((endpoint.host, endpoint.port))
            sock.close()

            if result == 0:
                endpoint.healthy = True
                endpoint.last_health_check = datetime.utcnow()
                return True
            else:
                endpoint.healthy = False
                return False

        except Exception as e:
            logger.debug(f"TCP health check failed for {endpoint.id}: {e}")
            endpoint.healthy = False
            return False

    async def _grpc_health_check(self, endpoint: ServiceEndpoint, config: Dict[str, Any]) -> bool:
        """Perform gRPC health check."""
        # Implementation would use grpc.aio for health check
        endpoint.healthy = True
        endpoint.last_health_check = datetime.utcnow()
        return True


class CircuitBreaker:
    """Circuit breaker for service calls."""

    def __init__(self, service_name: str, config: CircuitBreakerConfig):
        self.service_name = service_name
        self.config = config
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self.half_open_requests = 0
        self.state_changed_at = datetime.utcnow()

    async def call_allowed(self) -> bool:
        """Check if call is allowed."""
        if self.state == CircuitState.CLOSED:
            return True

        elif self.state == CircuitState.OPEN:
            # Check if timeout has passed
            if self.last_failure_time:
                elapsed = (datetime.utcnow() - self.last_failure_time).total_seconds()
                if elapsed >= self.config.timeout:
                    self._transition_to_half_open()
                    return True
            return False

        elif self.state == CircuitState.HALF_OPEN:
            # Allow limited requests
            if self.half_open_requests < self.config.half_open_requests:
                self.half_open_requests += 1
                return True
            return False

        return False

    async def record_success(self):
        """Record successful call."""
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1

            if self.success_count >= self.config.success_threshold:
                self._transition_to_closed()

        elif self.state == CircuitState.CLOSED:
            # Reset failure count on success
            self.failure_count = 0

    async def record_failure(self, status_code: int = 500):
        """Record failed call."""
        # Check if error should trip circuit
        if status_code in self.config.exclude_codes:
            return

        if status_code not in self.config.error_codes:
            return

        self.last_failure_time = datetime.utcnow()

        if self.state == CircuitState.CLOSED:
            self.failure_count += 1

            if self.failure_count >= self.config.failure_threshold:
                self._transition_to_open()

        elif self.state == CircuitState.HALF_OPEN:
            # Single failure in half-open trips to open
            self._transition_to_open()

    def _transition_to_open(self):
        """Transition to open state."""
        logger.warning(f"Circuit breaker opened for {self.service_name}")
        self.state = CircuitState.OPEN
        self.state_changed_at = datetime.utcnow()
        self.half_open_requests = 0

    def _transition_to_half_open(self):
        """Transition to half-open state."""
        logger.info(f"Circuit breaker half-opened for {self.service_name}")
        self.state = CircuitState.HALF_OPEN
        self.state_changed_at = datetime.utcnow()
        self.success_count = 0
        self.half_open_requests = 0

    def _transition_to_closed(self):
        """Transition to closed state."""
        logger.info(f"Circuit breaker closed for {self.service_name}")
        self.state = CircuitState.CLOSED
        self.state_changed_at = datetime.utcnow()
        self.failure_count = 0
        self.success_count = 0

    def get_state(self) -> str:
        """Get current state."""
        return self.state.value

    def is_open(self) -> bool:
        """Check if circuit is open."""
        return self.state == CircuitState.OPEN

    def is_closed(self) -> bool:
        """Check if circuit is closed."""
        return self.state == CircuitState.CLOSED


class RetryPolicy:
    """Retry policy for failed requests."""

    def __init__(self, config: RetryConfig):
        self.config = config

    async def should_retry(self, attempt: int, status_code: int, method: str) -> bool:
        """Check if request should be retried."""
        # Check max attempts
        if attempt >= self.config.max_attempts:
            return False

        # Check method
        if method not in self.config.retry_on_methods:
            return False

        # Check status code
        if status_code not in self.config.retry_on_codes:
            return False

        return True

    def get_delay(self, attempt: int) -> float:
        """Get retry delay in seconds."""
        # Exponential backoff with jitter
        base_delay = self.config.initial_delay_ms / 1000
        max_delay = self.config.max_delay_ms / 1000

        delay = min(
            base_delay * (self.config.exponential_base ** attempt),
            max_delay
        )

        # Add jitter (±10%)
        jitter = delay * 0.1 * (2 * random.random() - 1)

        return delay + jitter

    async def execute_with_retry(self, func, *args, **kwargs):
        """Execute function with retry."""
        last_exception = None

        for attempt in range(self.config.max_attempts):
            try:
                result = await func(*args, **kwargs)
                return result

            except Exception as e:
                last_exception = e

                # Check if should retry
                status_code = getattr(e, 'status_code', 500)
                method = kwargs.get('method', 'GET')

                if await self.should_retry(attempt + 1, status_code, method):
                    delay = self.get_delay(attempt)
                    logger.info(f"Retrying after {delay:.2f}s (attempt {attempt + 1})")
                    await asyncio.sleep(delay)
                else:
                    break

        # All retries failed
        raise last_exception


class RouteConfig:
    """Route configuration manager."""

    def __init__(self):
        self.routes = {}
        self.patterns = {}

    def add_route(self, route: RouteRule):
        """Add route configuration."""
        self.routes[route.name] = route
        self._compile_pattern(route)

    def remove_route(self, route_name: str):
        """Remove route configuration."""
        self.routes.pop(route_name, None)
        self.patterns.pop(route_name, None)

    def get_route(self, route_name: str) -> Optional[RouteRule]:
        """Get route configuration."""
        return self.routes.get(route_name)

    def list_routes(self) -> List[RouteRule]:
        """List all routes."""
        return list(self.routes.values())

    def _compile_pattern(self, route: RouteRule):
        """Compile route pattern."""
        pattern = route.path_pattern
        pattern = pattern.replace("*", ".*")
        pattern = f"^{pattern}$"
        self.patterns[route.name] = re.compile(pattern)

    def match(self, path: str, method: str) -> Optional[RouteRule]:
        """Match path and method to route."""
        for route in self.routes.values():
            if not route.is_enabled:
                continue

            # Check method
            if "*" not in route.methods and method not in route.methods:
                continue

            # Check pattern
            if self.patterns[route.name].match(path):
                return route

        return None