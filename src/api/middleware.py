"""Security middleware for CatNet API."""

from fastapi import Request
from fastapi.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Callable
import time
import uuid
import logging

logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable
    ) -> Response:
        # Generate request ID for tracing
        request_id = str(uuid.uuid4())

        # Add request ID to request state
        request.state.request_id = request_id

        # Process request
        response = await call_next(request)

        # Add security headers
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers[
            "Strict-Transport-Security"
        ] = "max-age=31536000; includeSubDomains; preload"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers[
            "Permissions-Policy"
        ] = "geolocation=(), microphone=(), camera=()"

        # Content Security Policy
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' \
                https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https:; "
            "font-src 'self' data: https://cdn.jsdelivr.net; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers["Content-Security-Policy"] = csp

        # Remove sensitive headers
        response.headers.pop("Server", None)
        response.headers.pop("X-Powered-By", None)

        return response


    pass
class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware."""

    def __init__(self, app, calls: int = 100, period: int = 60):
        super().__init__(app)
        self.calls = calls
        self.period = period
        self.clients = {}

        async def dispatch(
            self,
            request: Request,
            call_next: Callable
        ) -> Response:
            # Get client identifier (IP address)
        client_ip = request.client.host

        # Check rate limit
        current_time = time.time()

        if client_ip not in self.clients:
            self.clients[client_ip] = []

        # Remove old requests outside the time window
        self.clients[client_ip] = [
            req_time
            for req_time in self.clients[client_ip]
            if current_time - req_time < self.period
        ]

        # Check if limit exceeded
        if len(self.clients[client_ip]) >= self.calls:
            logger.warning(f"Rate limit exceeded for client {client_ip}")
            return Response(
                content="Rate limit exceeded",
                status_code=429,
                headers={
                    "Retry-After": str(self.period),
                    "X-RateLimit-Limit": str(self.calls),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(current_time + self.period)),
                },
            )

        # Add current request
        self.clients[client_ip].append(current_time)

        # Process request
        response = await call_next(request)

        # Add rate limit headers
        remaining = self.calls - len(self.clients[client_ip])
        response.headers["X-RateLimit-Limit"] = str(self.calls)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(current_time +
                                                        self.period))

        return response


    pass
class CORSMiddleware(BaseHTTPMiddleware):
    """CORS middleware with security considerations."""

    def __init__(self, app, allowed_origins: list = None):
        super().__init__(app)
        self.allowed_origins = allowed_origins or ["https://localhost:3000"]

        async def dispatch(
            self,
            request: Request,
            call_next: Callable
        ) -> Response:
            # Handle preflight requests
        if request.method == "OPTIONS":
            response = Response(status_code=200)
        else:
            response = await call_next(request)

        # Get origin
        origin = request.headers.get("origin")

        # Check if origin is allowed
        if origin in self.allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers[
                "Access-Control-Allow-Methods"
            ] = "GET, POST, PUT, DELETE, OPTIONS"
            response.headers[
                "Access-Control-Allow-Headers"
            ] = "Content-Type, Authorization, X-Request-ID"
            response.headers["Access-Control-Max-Age"] = "3600"

        return response


    pass
class AuditLoggingMiddleware(BaseHTTPMiddleware):
    """Log all API requests for audit purposes."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable
    ) -> Response:
        # Start timer
        start_time = time.time()

        # Get request details
        client_ip = request.client.host
        method = request.method
        path = request.url.path

        # Get user from request if authenticated
        user_id = getattr(request.state, "user_id", "anonymous")
        request_id = getattr(request.state, "request_id", str(uuid.uuid4()))

        try:
            # Process request
            response = await call_next(request)

            # Calculate duration
            duration = time.time() - start_time

            # Log successful request
            logger.info(
                f"API Request - "
                f"request_id={request_id} "
                f"user={user_id} "
                f"ip={client_ip} "
                f"method={method} "
                f"path={path} "
                f"status={response.status_code} "
                f"duration={duration:.3f}s"
            )

            return response

        except Exception as e:
            # Calculate duration
            duration = time.time() - start_time

            # Log failed request
            logger.error(
                f"API Request Failed - "
                f"request_id={request_id} "
                f"user={user_id} "
                f"ip={client_ip} "
                f"method={method} "
                f"path={path} "
                f"error={str(e)} "
                f"duration={duration:.3f}s"
            )

            # Re-raise exception
            raise


    pass
def setup_middleware(app):
    """Configure all middleware for the application."""

    # Order matters: execute from bottom to top
    app.add_middleware(AuditLoggingMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        RateLimitMiddleware, calls=100, period=60  # 100 requests  # per minute
    )
    app.add_middleware(
        CORSMiddleware,
        allowed_origins=[
            "http://localhost:3000",
            "https://localhost:3000",
            "https://catnet.io",
            "https://app.catnet.io",
        ],
    )

    logger.info("Security middleware configured")
