"""
Cache Middleware
Automatic caching for API responses
"""
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.datastructures import Headers
from typing import Optional
import structlog
import hashlib
import json
from datetime import datetime

from src.cache.redis_cache import redis_cache, CacheKeys

logger = structlog.get_logger()


class CacheMiddleware(BaseHTTPMiddleware):
    """
    HTTP Cache Middleware

    Automatically caches GET request responses based on URL and query parameters.
    Supports cache invalidation via headers and configurable TTL.
    """

    def __init__(
        self,
        app,
        default_ttl: int = 300,
        cache_prefix: str = "http_cache",
        excluded_paths: Optional[list] = None
    ):
        """
        Initialize cache middleware

        Args:
            app: FastAPI application
            default_ttl: Default cache TTL in seconds
            cache_prefix: Prefix for cache keys
            excluded_paths: List of path patterns to exclude from caching
        """
        super().__init__(app)
        self.default_ttl = default_ttl
        self.cache_prefix = cache_prefix
        self.excluded_paths = excluded_paths or [
            "/api/docs",
            "/api/redoc",
            "/api/openapi.json",
            "/metrics",
            "/health"
        ]

    async def dispatch(self, request: Request, call_next):
        """Process request with caching"""

        # Only cache GET requests
        if request.method != "GET":
            return await call_next(request)

        # Check if path is excluded
        if self._is_excluded(request.url.path):
            return await call_next(request)

        # Build cache key
        cache_key = self._build_cache_key(request)

        # Check for cache control headers
        cache_control = request.headers.get("Cache-Control", "")

        if "no-cache" in cache_control or "no-store" in cache_control:
            # Client requested fresh data
            logger.debug(f"Cache bypass requested: {request.url.path}")
            response = await call_next(request)
            return response

        # Try to get cached response
        cached_response = await redis_cache.get(cache_key)

        if cached_response is not None:
            logger.debug(f"Cache hit: {request.url.path}")

            # Return cached response
            return self._build_response_from_cache(cached_response)

        # Cache miss - execute request
        logger.debug(f"Cache miss: {request.url.path}")
        response = await call_next(request)

        # Cache successful responses (2xx status codes)
        if 200 <= response.status_code < 300:
            await self._cache_response(cache_key, response, request)

        return response

    def _is_excluded(self, path: str) -> bool:
        """Check if path should be excluded from caching"""
        for excluded_path in self.excluded_paths:
            if path.startswith(excluded_path):
                return True
        return False

    def _build_cache_key(self, request: Request) -> str:
        """
        Build cache key from request

        Includes: method, path, query parameters, and user ID (if authenticated)
        """
        # Get user ID from request state (set by auth middleware)
        user_id = getattr(request.state, "user_id", "anonymous")

        # Build key components
        components = [
            self.cache_prefix,
            request.method,
            request.url.path,
            str(request.query_params),
            user_id
        ]

        # Hash for consistent key length
        key_string = ":".join(components)
        key_hash = hashlib.md5(key_string.encode()).hexdigest()

        return f"{self.cache_prefix}:{key_hash}"

    async def _cache_response(
        self,
        cache_key: str,
        response: Response,
        request: Request
    ):
        """Cache response data"""
        try:
            # Read response body
            response_body = b""
            async for chunk in response.body_iterator:
                response_body += chunk

            # Build cache data
            cache_data = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response_body.decode("utf-8"),
                "cached_at": datetime.utcnow().isoformat()
            }

            # Determine TTL
            ttl = self._get_cache_ttl(request, response)

            # Cache the response
            await redis_cache.set(cache_key, cache_data, ttl=ttl)

            logger.debug(
                f"Response cached: {request.url.path}",
                ttl=ttl,
                size=len(response_body)
            )

            # Recreate response with original body
            response.body_iterator = self._create_body_iterator(response_body)

        except Exception as e:
            logger.error(f"Failed to cache response: {e}")

    def _build_response_from_cache(self, cached_data: dict) -> Response:
        """Build Response object from cached data"""
        # Add custom header to indicate cached response
        headers = dict(cached_data["headers"])
        headers["X-Cache"] = "HIT"
        headers["X-Cached-At"] = cached_data["cached_at"]

        return Response(
            content=cached_data["body"],
            status_code=cached_data["status_code"],
            headers=headers
        )

    def _get_cache_ttl(self, request: Request, response: Response) -> int:
        """Determine cache TTL from request/response"""

        # Check response Cache-Control header
        cache_control = response.headers.get("Cache-Control", "")

        if "max-age=" in cache_control:
            try:
                max_age = int(cache_control.split("max-age=")[1].split(",")[0])
                return max_age
            except (ValueError, IndexError):
                pass

        # Check for custom X-Cache-TTL header
        custom_ttl = response.headers.get("X-Cache-TTL")
        if custom_ttl:
            try:
                return int(custom_ttl)
            except ValueError:
                pass

        # Use path-based TTL
        path = request.url.path

        if "/inventory" in path:
            return 600  # 10 minutes
        elif "/topology" in path:
            return 300  # 5 minutes
        elif "/health-checks" in path:
            return 60  # 1 minute
        elif "/slas" in path:
            return 300  # 5 minutes
        elif "/devices" in path:
            return 180  # 3 minutes

        # Default TTL
        return self.default_ttl

    async def _create_body_iterator(self, body: bytes):
        """Create async iterator for response body"""
        yield body


class CacheInvalidationMiddleware(BaseHTTPMiddleware):
    """
    Cache Invalidation Middleware

    Automatically invalidates related cache entries on write operations
    """

    def __init__(self, app):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        """Process request and invalidate cache if needed"""

        # Execute request
        response = await call_next(request)

        # Invalidate cache on successful write operations
        if request.method in ["POST", "PUT", "PATCH", "DELETE"]:
            if 200 <= response.status_code < 300:
                await self._invalidate_related_cache(request)

        return response

    async def _invalidate_related_cache(self, request: Request):
        """Invalidate cache entries related to the request"""
        try:
            path = request.url.path

            # Determine what to invalidate based on path
            patterns = []

            if "/devices" in path:
                patterns.extend([
                    "http_cache:*:/api/v1/devices*",
                    "http_cache:*:/api/v1/discovery/inventory*"
                ])

            elif "/deployments" in path:
                patterns.append("http_cache:*:/api/v1/deployments*")

            elif "/health-checks" in path:
                patterns.extend([
                    "http_cache:*:/api/v1/monitoring/health-checks*",
                    "http_cache:*:/api/v1/monitoring/dashboard*"
                ])

            elif "/slas" in path:
                patterns.extend([
                    "http_cache:*:/api/v1/monitoring/slas*",
                    "http_cache:*:/api/v1/monitoring/dashboard*"
                ])

            elif "/discovery" in path:
                patterns.extend([
                    "http_cache:*:/api/v1/discovery*",
                    "http_cache:*:/api/v1/devices*"
                ])

            # Invalidate matching patterns
            total_invalidated = 0
            for pattern in patterns:
                count = await redis_cache.delete_pattern(pattern)
                total_invalidated += count

            if total_invalidated > 0:
                logger.info(
                    f"Cache invalidated: {path}",
                    patterns=len(patterns),
                    keys_deleted=total_invalidated
                )

        except Exception as e:
            logger.error(f"Cache invalidation error: {e}")


class ConditionalCacheMiddleware(BaseHTTPMiddleware):
    """
    Conditional Cache Middleware

    Implements ETag and Last-Modified headers for efficient caching
    """

    def __init__(self, app):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        """Process request with conditional caching"""

        # Only process GET requests
        if request.method != "GET":
            return await call_next(request)

        # Build ETag from request
        cache_key = self._build_cache_key(request)

        # Check if client sent If-None-Match (ETag)
        if_none_match = request.headers.get("If-None-Match")

        if if_none_match:
            # Get cached ETag
            cached_etag = await redis_cache.get(f"etag:{cache_key}")

            if cached_etag == if_none_match:
                # Resource hasn't changed
                logger.debug(f"ETag match - returning 304: {request.url.path}")
                return Response(status_code=304)  # Not Modified

        # Execute request
        response = await call_next(request)

        # Generate and cache ETag for successful responses
        if response.status_code == 200:
            # Read response body to generate ETag
            response_body = b""
            async for chunk in response.body_iterator:
                response_body += chunk

            # Generate ETag (MD5 hash of body)
            etag = hashlib.md5(response_body).hexdigest()

            # Cache ETag (24 hour TTL)
            await redis_cache.set(f"etag:{cache_key}", etag, ttl=86400)

            # Add ETag header
            response.headers["ETag"] = f'"{etag}"'
            response.headers["Cache-Control"] = "private, must-revalidate"

            # Recreate response body iterator
            response.body_iterator = self._create_body_iterator(response_body)

        return response

    def _build_cache_key(self, request: Request) -> str:
        """Build cache key for ETag lookup"""
        user_id = getattr(request.state, "user_id", "anonymous")
        key_string = f"{request.method}:{request.url.path}:{str(request.query_params)}:{user_id}"
        return hashlib.md5(key_string.encode()).hexdigest()

    async def _create_body_iterator(self, body: bytes):
        """Create async iterator for response body"""
        yield body


class RateLimitCacheMiddleware(BaseHTTPMiddleware):
    """
    Rate Limit Cache Middleware

    Uses Redis for distributed rate limiting
    """

    def __init__(
        self,
        app,
        default_rate_limit: int = 100,  # requests per minute
        rate_limit_window: int = 60  # seconds
    ):
        super().__init__(app)
        self.default_rate_limit = default_rate_limit
        self.rate_limit_window = rate_limit_window

    async def dispatch(self, request: Request, call_next):
        """Apply rate limiting"""

        # Get user/client identifier
        identifier = self._get_identifier(request)

        # Build rate limit key
        rate_key = f"rate_limit:{identifier}"

        # Get current count
        current_count = await redis_cache.get(rate_key) or 0

        # Check if limit exceeded
        if current_count >= self.default_rate_limit:
            logger.warning(f"Rate limit exceeded: {identifier}")

            return Response(
                content=json.dumps({
                    "detail": "Rate limit exceeded",
                    "retry_after": await redis_cache.get_ttl(rate_key)
                }),
                status_code=429,
                headers={
                    "Content-Type": "application/json",
                    "X-RateLimit-Limit": str(self.default_rate_limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(await redis_cache.get_ttl(rate_key))
                }
            )

        # Increment counter
        new_count = await redis_cache.increment(rate_key)

        # Set expiration on first request
        if new_count == 1:
            await redis_cache.redis.expire(rate_key, self.rate_limit_window)

        # Execute request
        response = await call_next(request)

        # Add rate limit headers
        remaining = max(0, self.default_rate_limit - new_count)
        response.headers["X-RateLimit-Limit"] = str(self.default_rate_limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(await redis_cache.get_ttl(rate_key))

        return response

    def _get_identifier(self, request: Request) -> str:
        """Get unique identifier for rate limiting"""
        # Use user ID if authenticated
        user_id = getattr(request.state, "user_id", None)
        if user_id:
            return f"user:{user_id}"

        # Fall back to IP address
        client_host = request.client.host if request.client else "unknown"
        return f"ip:{client_host}"
