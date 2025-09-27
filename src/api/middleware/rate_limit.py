from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import time
import asyncio
import hashlib
from typing import Dict, Optional, Tuple
from collections import defaultdict, deque
from datetime import datetime, timedelta
import structlog
import redis.asyncio as redis
import json

logger = structlog.get_logger()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware with multiple strategies

    Implements:
    - Token bucket algorithm
    - Sliding window counter
    - Per-user rate limiting
    - Per-IP rate limiting
    - Endpoint-specific limits
    - Distributed rate limiting with Redis
    """

    def __init__(
        self,
        app,
        redis_url: Optional[str] = None,
        default_limit: int = 100,
        window_size: int = 60,
        burst_size: int = 10
    ):
        super().__init__(app)
        self.redis_url = redis_url or "redis://localhost:6379/2"
        self.redis_client = None
        self.default_limit = default_limit
        self.window_size = window_size  # seconds
        self.burst_size = burst_size

        # In-memory fallback storage
        self.local_storage: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))

        # Endpoint-specific limits
        self.endpoint_limits = {
            '/api/v1/auth/login': (10, 60),  # 10 requests per minute
            '/api/v1/auth/register': (5, 60),  # 5 requests per minute
            '/api/v1/deployments': (30, 60),  # 30 requests per minute
            '/api/v1/devices/*/execute': (10, 60),  # 10 commands per minute
            '/api/v1/gitops/webhook': (50, 60),  # 50 webhooks per minute
        }

        # Exempted paths
        self.exempted_paths = [
            '/health',
            '/metrics',
            '/api/docs',
            '/api/redoc',
            '/api/openapi.json'
        ]

        # Initialize Redis connection
        asyncio.create_task(self._init_redis())

    async def _init_redis(self):
        """Initialize Redis connection"""
        try:
            self.redis_client = await redis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True
            )
            await self.redis_client.ping()
            logger.info("Rate limiter Redis connection established")
        except Exception as e:
            logger.warning(f"Rate limiter Redis connection failed: {e}, using local storage")
            self.redis_client = None

    async def dispatch(self, request: Request, call_next):
        # Check if path is exempted
        if self._is_exempted(request.url.path):
            return await call_next(request)

        # Get rate limit key and limits
        key = await self._get_rate_limit_key(request)
        limit, window = self._get_limits_for_endpoint(request.url.path)

        # Check rate limit
        allowed, retry_after = await self._check_rate_limit(key, limit, window)

        if not allowed:
            # Log rate limit violation
            await self._log_rate_limit_violation(request, key)

            # Return 429 Too Many Requests
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded",
                    "retry_after": retry_after
                },
                headers={
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(time.time()) + retry_after),
                    "Retry-After": str(retry_after)
                }
            )

        # Process request
        response = await call_next(request)

        # Add rate limit headers to response
        remaining = await self._get_remaining_requests(key, limit, window)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(time.time()) + window)

        return response

    def _is_exempted(self, path: str) -> bool:
        """Check if path is exempted from rate limiting"""
        return any(path.startswith(exempt) for exempt in self.exempted_paths)

    async def _get_rate_limit_key(self, request: Request) -> str:
        """Generate rate limit key for request"""

        # Try to get authenticated user
        user_id = None
        if hasattr(request.state, 'user_id'):
            user_id = request.state.user_id
        elif 'authorization' in request.headers:
            # Extract user from JWT token
            try:
                from ...auth.jwt_handler import JWTHandler
                jwt_handler = JWTHandler()
                token = request.headers['authorization'].replace('Bearer ', '')
                payload = jwt_handler.decode_token(token)
                user_id = payload.get('sub')
            except:
                pass

        # Use user ID if authenticated, otherwise use IP
        if user_id:
            identifier = f"user:{user_id}"
        else:
            client_ip = request.client.host if request.client else "unknown"
            # Check for proxy headers
            if 'x-forwarded-for' in request.headers:
                client_ip = request.headers['x-forwarded-for'].split(',')[0].strip()
            identifier = f"ip:{client_ip}"

        # Include endpoint in key
        endpoint = request.url.path
        key = f"rate_limit:{identifier}:{endpoint}"

        return key

    def _get_limits_for_endpoint(self, path: str) -> Tuple[int, int]:
        """Get rate limits for specific endpoint"""

        # Check exact matches first
        if path in self.endpoint_limits:
            return self.endpoint_limits[path]

        # Check pattern matches
        for pattern, limits in self.endpoint_limits.items():
            if '*' in pattern:
                # Simple wildcard matching
                pattern_regex = pattern.replace('*', '.*')
                import re
                if re.match(pattern_regex, path):
                    return limits

        # Return default limits
        return (self.default_limit, self.window_size)

    async def _check_rate_limit(
        self,
        key: str,
        limit: int,
        window: int
    ) -> Tuple[bool, int]:
        """Check if request is within rate limit"""

        current_time = time.time()

        if self.redis_client:
            # Use Redis for distributed rate limiting
            return await self._check_redis_rate_limit(key, limit, window, current_time)
        else:
            # Use local storage as fallback
            return self._check_local_rate_limit(key, limit, window, current_time)

    async def _check_redis_rate_limit(
        self,
        key: str,
        limit: int,
        window: int,
        current_time: float
    ) -> Tuple[bool, int]:
        """Check rate limit using Redis (sliding window)"""

        try:
            # Use Redis sorted sets for sliding window
            pipeline = self.redis_client.pipeline()

            # Remove old entries outside window
            min_time = current_time - window
            pipeline.zremrangebyscore(key, 0, min_time)

            # Count requests in current window
            pipeline.zcard(key)

            # Add current request
            pipeline.zadd(key, {str(current_time): current_time})

            # Set expiry
            pipeline.expire(key, window + 1)

            results = await pipeline.execute()
            request_count = results[1]

            if request_count >= limit:
                # Calculate retry after
                oldest_request = await self.redis_client.zrange(key, 0, 0, withscores=True)
                if oldest_request:
                    oldest_time = oldest_request[0][1]
                    retry_after = int(window - (current_time - oldest_time)) + 1
                else:
                    retry_after = window

                return False, retry_after

            return True, 0

        except Exception as e:
            logger.error(f"Redis rate limit check failed: {e}")
            # Fall back to allowing the request
            return True, 0

    def _check_local_rate_limit(
        self,
        key: str,
        limit: int,
        window: int,
        current_time: float
    ) -> Tuple[bool, int]:
        """Check rate limit using local storage"""

        # Get request history for key
        requests = self.local_storage[key]

        # Remove old requests outside window
        min_time = current_time - window
        while requests and requests[0] < min_time:
            requests.popleft()

        # Check if limit exceeded
        if len(requests) >= limit:
            # Calculate retry after
            oldest_time = requests[0]
            retry_after = int(window - (current_time - oldest_time)) + 1
            return False, retry_after

        # Add current request
        requests.append(current_time)
        return True, 0

    async def _get_remaining_requests(
        self,
        key: str,
        limit: int,
        window: int
    ) -> int:
        """Get remaining requests for key"""

        current_time = time.time()

        if self.redis_client:
            try:
                # Count requests in window
                min_time = current_time - window
                count = await self.redis_client.zcount(key, min_time, current_time)
                return max(0, limit - count)
            except:
                return limit
        else:
            # Use local storage
            requests = self.local_storage[key]
            min_time = current_time - window
            valid_requests = [r for r in requests if r >= min_time]
            return max(0, limit - len(valid_requests))

    async def _log_rate_limit_violation(self, request: Request, key: str):
        """Log rate limit violations for monitoring"""

        logger.warning(
            "Rate limit exceeded",
            key=key,
            path=request.url.path,
            method=request.method,
            client=request.client.host if request.client else None,
            user_agent=request.headers.get('user-agent'),
            request_id=getattr(request.state, 'request_id', None)
        )


class AdaptiveRateLimiter:
    """
    Adaptive rate limiter that adjusts limits based on system load

    Features:
    - Dynamic limit adjustment
    - System resource monitoring
    - Gradual backoff
    - Priority-based limiting
    """

    def __init__(
        self,
        base_limit: int = 100,
        min_limit: int = 10,
        max_limit: int = 1000
    ):
        self.base_limit = base_limit
        self.min_limit = min_limit
        self.max_limit = max_limit
        self.current_limit = base_limit
        self.adjustment_factor = 0.1

        # System metrics
        self.cpu_threshold = 80  # percent
        self.memory_threshold = 80  # percent
        self.response_time_threshold = 1.0  # seconds

        # Priority levels
        self.priority_multipliers = {
            'high': 2.0,
            'normal': 1.0,
            'low': 0.5
        }

    async def get_adaptive_limit(
        self,
        endpoint: str,
        priority: str = 'normal'
    ) -> int:
        """Get adaptive rate limit based on system load"""

        # Get system metrics
        cpu_usage = await self._get_cpu_usage()
        memory_usage = await self._get_memory_usage()
        avg_response_time = await self._get_average_response_time()

        # Calculate load factor (0.0 to 1.0)
        load_factor = self._calculate_load_factor(
            cpu_usage,
            memory_usage,
            avg_response_time
        )

        # Adjust limit based on load
        if load_factor > 0.8:
            # High load - decrease limit
            self.current_limit = max(
                self.min_limit,
                int(self.current_limit * (1 - self.adjustment_factor))
            )
        elif load_factor < 0.4:
            # Low load - increase limit
            self.current_limit = min(
                self.max_limit,
                int(self.current_limit * (1 + self.adjustment_factor))
            )

        # Apply priority multiplier
        priority_multiplier = self.priority_multipliers.get(priority, 1.0)
        adjusted_limit = int(self.current_limit * priority_multiplier)

        return adjusted_limit

    async def _get_cpu_usage(self) -> float:
        """Get current CPU usage"""
        try:
            import psutil
            return psutil.cpu_percent(interval=0.1)
        except:
            return 0.0

    async def _get_memory_usage(self) -> float:
        """Get current memory usage"""
        try:
            import psutil
            return psutil.virtual_memory().percent
        except:
            return 0.0

    async def _get_average_response_time(self) -> float:
        """Get average response time from metrics"""
        # This would query Prometheus or internal metrics
        return 0.5  # placeholder

    def _calculate_load_factor(
        self,
        cpu_usage: float,
        memory_usage: float,
        response_time: float
    ) -> float:
        """Calculate overall system load factor"""

        cpu_load = min(1.0, cpu_usage / self.cpu_threshold)
        memory_load = min(1.0, memory_usage / self.memory_threshold)
        response_load = min(1.0, response_time / self.response_time_threshold)

        # Weighted average
        load_factor = (
            cpu_load * 0.4 +
            memory_load * 0.3 +
            response_load * 0.3
        )

        return load_factor


class DistributedRateLimiter:
    """
    Distributed rate limiter for multi-instance deployments

    Uses Redis for coordination across instances
    """

    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.lua_script = """
        local key = KEYS[1]
        local limit = tonumber(ARGV[1])
        local window = tonumber(ARGV[2])
        local current_time = tonumber(ARGV[3])

        -- Remove old entries
        redis.call('ZREMRANGEBYSCORE', key, 0, current_time - window)

        -- Count current entries
        local count = redis.call('ZCARD', key)

        if count < limit then
            -- Add current request
            redis.call('ZADD', key, current_time, current_time)
            redis.call('EXPIRE', key, window + 1)
            return {1, limit - count - 1}
        else
            -- Get oldest entry
            local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
            local retry_after = 0
            if oldest[2] then
                retry_after = window - (current_time - oldest[2])
            end
            return {0, retry_after}
        end
        """
        self.script_sha = None

    async def check_limit(
        self,
        key: str,
        limit: int,
        window: int
    ) -> Tuple[bool, int]:
        """Check rate limit atomically"""

        current_time = time.time()

        try:
            # Load script if not loaded
            if not self.script_sha:
                self.script_sha = await self.redis.script_load(self.lua_script)

            # Execute script
            result = await self.redis.evalsha(
                self.script_sha,
                1,
                key,
                limit,
                window,
                current_time
            )

            allowed = result[0] == 1
            retry_after = int(result[1]) if not allowed else 0

            return allowed, retry_after

        except Exception as e:
            logger.error(f"Distributed rate limit check failed: {e}")
            # Fail open
            return True, 0