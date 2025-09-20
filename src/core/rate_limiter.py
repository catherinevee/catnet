"""
Rate Limiting for API Endpoints
"""

import time

import asyncio
from typing import Dict, Optional, Callable
from functools import wraps
from datetime import datetime, timedelta
import redis.asyncio as redis
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse

from ..core.logging import get_logger
from ..security.audit import AuditLogger

logger = get_logger(__name__)


class RateLimiter: """
    Rate limiter implementation using Token Bucket algorithm
    Supports per-user and per-IP rate limiting with Redis backend
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        default_rate: int = 100,
        default_period: int = 60,
    ):
        """
        Initialize rate limiter
    Args:
            redis_url: Redis connection URL
            default_rate: Default requests per period
            default_period: Default period in seconds"""
        self.redis_url = redis_url
        self.redis_client = None
        self.default_rate = default_rate
        self.default_period = default_period
        self.audit = AuditLogger()

    async def initialize(self):
        """Initialize Redis connection"""
        try:
            self.redis_client = await redis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True,
            )
            await self.redis_client.ping()
            logger.info("Rate limiter initialized with Redis backend")
        except Exception as e:
                        logger.warning(
                f"Redis not available,"
                using in -memory rate limiting: {e}"
            )
            self.redis_client = None
            self._local_buckets = {}

    async def close(self):
        """Close Redis connection"""
        if self.redis_client:
            await self.redis_client.close()

    async def check_rate_limit(
        self,
        key: str,
        rate: Optional[int] = None,
        period: Optional[int] = None,
    ) -> Dict[str, any]:"""
        Check if request is within rate limit
    Args:
            key: Unique identifier (user_id, IP, etc.)
            rate: Max requests per period (overrides default)
            period: Period in seconds (overrides default)
    Returns:
            Dictionary with rate limit info
        """
        rate = rate or self.default_rate
        period = period or self.default_period

        if self.redis_client:
            return await self._check_redis_limit(key, rate, period)
        else:
            return await self._check_local_limit(key, rate, period)

    async def _check_redis_limit(
        self, key: str, rate: int, period: int
    ) -> Dict[str, any]:"""Check rate limit using Redis"""
        try:
            # Use sliding window algorithm
            now = time.time()
            window_start = now - period
            redis_key = f"rate_limit:{key}"

            # Remove old entries outside the window
                        await self.redis_client.zremrangebyscore(
                redis_key,
                0,
                window_start
            )

            # Count requests in current window
            current_requests = await self.redis_client.zcard(redis_key)

            if current_requests < rate:
                # Add current request
                await self.redis_client.zadd(redis_key, {str(now): now})
                await self.redis_client.expire(redis_key, period)

                remaining = rate - current_requests - 1
                reset_time = datetime.utcnow() + timedelta(seconds=period)

                return {
                    "allowed": True,
                    "limit": rate,
                    "remaining": remaining,
                    "reset": reset_time.timestamp(),
                }
            else:
                # Rate limit exceeded
                reset_time = datetime.utcnow() + timedelta(seconds=period)

                return {
                    "allowed": False,
                    "limit": rate,
                    "remaining": 0,
                    "reset": reset_time.timestamp(),
                    "retry_after": period,
                }

        except Exception as e:
            logger.error(f"Redis rate limit check failed: {e}")
            # Fail open - allow request if Redis fails
            return {"allowed": True, "limit": rate, "remaining": rate}

    async def _check_local_limit(
        self, key: str, rate: int, period: int
    ) -> Dict[str, any]:
        """Check rate limit using local memory (fallback)"""
        now = time.time()
        window_start = now - period

        if key not in self._local_buckets:
            self._local_buckets[key] = []

        # Remove old entries
        self._local_buckets[key] = [
            ts for ts in self._local_buckets[key] if ts > window_start
        ]

        current_requests = len(self._local_buckets[key])

        if current_requests < rate:
            self._local_buckets[key].append(now)
            remaining = rate - current_requests - 1
            reset_time = datetime.utcnow() + timedelta(seconds=period)

            return {
                "allowed": True,
                "limit": rate,
                "remaining": remaining,
                "reset": reset_time.timestamp(),
            }
        else:
            reset_time = datetime.utcnow() + timedelta(seconds=period)

            return {
                "allowed": False,
                "limit": rate,
                "remaining": 0,
                "reset": reset_time.timestamp(),
                "retry_after": period,
            }

    def limit(
        self,
        rate: int = 100,
        period: int = 60,
        key_func: Optional[Callable] = None,
        error_message: str = "Rate limit exceeded",
    ):
        """
        Decorator for rate limiting endpoints
    Args:
            rate: Max requests per period
            period: Period in seconds
            key_func: Function to generate rate limit key from request
            error_message: Error message when rate limited

        Example:
            @rate_limiter.limit(rate=10, period=60)
            async def my_endpoint(request: Request):
                """TODO: Add docstring"""
                return {"message": "success"}
        """

        def decorator(func):
            """TODO: Add docstring"""
            @wraps(func)
            async def wrapper(request: Request, *args, **kwargs):
                """TODO: Add docstring"""
                # Generate rate limit key
                if key_func:
                    key = key_func(request)
                else:
                    # Default to IP address
                    key = request.client.host if request.client else "unknown"

                # Check rate limit
                result = await self.check_rate_limit(key, rate, period)

                # Add rate limit headers
                headers = {
                    "X-RateLimit-Limit": str(result["limit"]),
                    "X-RateLimit-Remaining": str(result.get("remaining", 0)),
                    "X-RateLimit-Reset": str(int(result.get("reset", 0))),
                }

                if not result["allowed"]:
                    # Rate limited - log and return 429
                    # Use asyncio to log asynchronously without blocking
                    asyncio.create_task(
                        self.audit.log_event(
                            event_type="rate_limit_exceeded",
                            details={
                                "key": key,
                                "endpoint": request.url.path,
                                "method": request.method,
                            },
                        )
                    )

                                        headers["Retry-After"] = str(
                        result.get("retry_after",
                        period)
                    )

                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=error_message,
                        headers=headers,
                    )

                # Add headers to response
                response = await func(request, *args, **kwargs)
                if isinstance(response, JSONResponse):
                    for header, value in headers.items():
                        response.headers[header] = value

                return response

            return wrapper

        return decorator



class EndpointRateLimits:
    """
    Predefined rate limits for different endpoint categories"""

    # Authentication endpoints - strict limits
    AUTH_LOGIN = {"rate": 5, "period": 60}  # 5 per minute
    AUTH_MFA = {"rate": 10, "period": 60}  # 10 per minute
    AUTH_PASSWORD_RESET = {"rate": 3, "period": 3600}  # 3 per hour

    # API endpoints - moderate limits
    API_READ = {"rate": 100, "period": 60}  # 100 per minute
    API_WRITE = {"rate": 50, "period": 60}  # 50 per minute
    API_DELETE = {"rate": 20, "period": 60}  # 20 per minute

    # Webhook endpoints - higher limits
    WEBHOOK = {"rate": 1000, "period": 60}  # 1000 per minute

    # Admin endpoints - relaxed limits
    ADMIN_READ = {"rate": 200, "period": 60}  # 200 per minute
    ADMIN_WRITE = {"rate": 100, "period": 60}  # 100 per minute

    # Deployment endpoints - careful limits
    DEPLOYMENT_CREATE = {"rate": 10, "period": 300}  # 10 per 5 minutes
    DEPLOYMENT_EXECUTE = {"rate": 5, "period": 300}  # 5 per 5 minutes


# Global rate limiter instance
rate_limiter = RateLimiter()



def get_user_key(request: Request) -> str:
    """Extract user ID from request for rate limiting"""
    # Would extract from JWT token or session
    user = getattr(request.state, "user", None)
    if user:
        return f"user:{user.id}"
    return f"ip:{request.client.host if request.client else 'unknown'}"



def get_ip_key(request: Request) -> str:
    """Extract IP address from request for rate limiting"""
    # Check for proxy headers
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return f"ip:{forwarded.split(',')[0].strip()}"
    return f"ip:{request.client.host if request.client else 'unknown'}"


# Example usage decorators

def limit_auth_endpoint(rate: int = 5, period: int = 60):
    """Rate limit authentication endpoints"""
    return rate_limiter.limit(
        rate=rate,
        period=period,
        key_func=get_ip_key,
        error_message="Too many authentication attempts. Please try again \
            later.",
    )



def limit_api_endpoint(rate: int = 100, period: int = 60):
    """Rate limit API endpoints"""
    return rate_limiter.limit(
        rate=rate,
        period=period,
        key_func=get_user_key,
        error_message="API rate limit exceeded. Please slow down.",
    )



def limit_deployment_endpoint(rate: int = 10, period: int = 300):
    """Rate limit deployment endpoints"""
    return rate_limiter.limit(
        rate=rate,
        period=period,
        key_func=get_user_key,
        error_message="Deployment rate limit exceeded. "
        "Please wait before creating more deployments.",
    )
