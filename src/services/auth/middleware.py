"""
Middleware components for authentication service.
"""

import time
import json
import hashlib
from typing import Optional, Dict, Any, List, Callable
from datetime import datetime, timedelta
import asyncio
from collections import defaultdict

from fastapi import Request, Response, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import jwt
import redis.asyncio as redis

from src.core.logging import get_logger
from src.core.config import get_settings
from src.security.vault import VaultClient

logger = get_logger(__name__)
settings = get_settings()


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """
    Authentication middleware for validating tokens and sessions.

    Validates JWT tokens, checks session validity, and enforces
    authentication requirements on protected endpoints.
    """

    # Paths that don't require authentication
    EXEMPT_PATHS = [
        "/auth/login",
        "/auth/register",
        "/auth/password/reset",
        "/auth/health",
        "/auth/metrics",
        "/auth/docs",
        "/auth/redoc",
        "/auth/openapi.json"
    ]

    def __init__(self, app):
        super().__init__(app)
        self.vault = VaultClient()
        self.redis_client = None
        self.security = HTTPBearer()

    async def dispatch(self, request: Request, call_next):
        """Process authentication for each request."""
        try:
            # Initialize Redis connection if needed
            if not self.redis_client:
                self.redis_client = await redis.from_url(
                    settings.REDIS_URL,
                    encoding="utf-8",
                    decode_responses=True
                )

            # Check if path is exempt
            if self._is_exempt_path(request.url.path):
                return await call_next(request)

            # Extract token from header
            token = await self._extract_token(request)
            if not token:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Missing authentication token"}
                )

            # Validate token
            user_info = await self._validate_token(token)
            if not user_info:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Invalid or expired token"}
                )

            # Check if token is blacklisted
            if await self._is_token_blacklisted(token):
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Token has been revoked"}
                )

            # Validate session
            if not await self._validate_session(user_info['session_id'], request):
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Invalid session"}
                )

            # Add user info to request state
            request.state.user = user_info
            request.state.token = token

            # Update session activity
            await self._update_session_activity(user_info['session_id'])

            # Process request
            response = await call_next(request)

            # Add security headers
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"

            return response

        except HTTPException as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"detail": e.detail}
            )
        except Exception as e:
            logger.error(f"Authentication middleware error: {e}")
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Authentication error"}
            )

    def _is_exempt_path(self, path: str) -> bool:
        """Check if path is exempt from authentication."""
        for exempt in self.EXEMPT_PATHS:
            if path.startswith(exempt):
                return True
        return False

    async def _extract_token(self, request: Request) -> Optional[str]:
        """Extract token from request."""
        # Check Authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header:
            parts = auth_header.split()
            if len(parts) == 2 and parts[0].lower() == "bearer":
                return parts[1]

        # Check cookie
        token = request.cookies.get("access_token")
        if token:
            return token

        # Check query parameter (for WebSocket connections)
        token = request.query_params.get("token")
        if token:
            return token

        return None

    async def _validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate JWT token."""
        try:
            # Decode token
            payload = jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=["HS256"]
            )

            # Check expiration
            if payload['exp'] < datetime.utcnow().timestamp():
                return None

            # Get user info from cache
            user_info = await self.redis_client.get(f"session:{payload['session_id']}")
            if not user_info:
                return None

            return json.loads(user_info) if isinstance(user_info, str) else user_info

        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return None
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return None

    async def _is_token_blacklisted(self, token: str) -> bool:
        """Check if token is blacklisted."""
        blacklisted = await self.redis_client.get(f"blacklist:{token}")
        return blacklisted is not None

    async def _validate_session(self, session_id: str, request: Request) -> bool:
        """Validate session."""
        session = await self.redis_client.get(f"session:{session_id}")
        if not session:
            return False

        session_data = json.loads(session) if isinstance(session, str) else session

        # Check IP address if configured
        if settings.VALIDATE_SESSION_IP:
            client_ip = request.client.host
            if session_data.get('ip_address') != client_ip:
                logger.warning(f"Session IP mismatch for session {session_id}")
                return False

        # Check user agent if configured
        if settings.VALIDATE_SESSION_USER_AGENT:
            user_agent = request.headers.get('User-Agent')
            if session_data.get('user_agent') != user_agent:
                logger.warning(f"Session user agent mismatch for session {session_id}")
                return False

        return True

    async def _update_session_activity(self, session_id: str):
        """Update session last activity time."""
        session = await self.redis_client.get(f"session:{session_id}")
        if session:
            session_data = json.loads(session) if isinstance(session, str) else session
            session_data['last_activity'] = datetime.utcnow().isoformat()
            await self.redis_client.setex(
                f"session:{session_id}",
                settings.SESSION_TIMEOUT_HOURS * 3600,
                json.dumps(session_data)
            )


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware to prevent abuse.

    Implements token bucket algorithm for rate limiting
    with per-user and per-IP limits.
    """

    def __init__(self, app):
        super().__init__(app)
        self.redis_client = None
        self.limits = {
            '/auth/login': {'requests': 5, 'window': 300},  # 5 requests per 5 minutes
            '/auth/mfa/verify': {'requests': 10, 'window': 300},  # 10 requests per 5 minutes
            '/auth/password/reset': {'requests': 3, 'window': 3600},  # 3 requests per hour
            'default': {'requests': 100, 'window': 60}  # 100 requests per minute
        }
        self.blocked_ips = set()

    async def dispatch(self, request: Request, call_next):
        """Apply rate limiting."""
        try:
            # Initialize Redis connection if needed
            if not self.redis_client:
                self.redis_client = await redis.from_url(
                    settings.REDIS_URL,
                    encoding="utf-8",
                    decode_responses=True
                )

            # Get client identifier
            client_ip = request.client.host
            user_id = getattr(request.state, 'user', {}).get('id')
            identifier = user_id if user_id else client_ip

            # Check if IP is blocked
            if client_ip in self.blocked_ips:
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={"detail": "IP address blocked due to excessive requests"}
                )

            # Get rate limit for path
            path = request.url.path
            limit_config = self._get_limit_config(path)

            # Check rate limit
            allowed = await self._check_rate_limit(identifier, path, limit_config)
            if not allowed:
                # Block IP after excessive violations
                violations = await self._increment_violations(client_ip)
                if violations > 10:
                    self.blocked_ips.add(client_ip)
                    logger.warning(f"Blocked IP due to excessive rate limit violations: {client_ip}")

                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "detail": "Rate limit exceeded",
                        "retry_after": limit_config['window']
                    },
                    headers={
                        "Retry-After": str(limit_config['window']),
                        "X-RateLimit-Limit": str(limit_config['requests']),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(int(time.time()) + limit_config['window'])
                    }
                )

            # Process request
            response = await call_next(request)

            # Add rate limit headers
            remaining = await self._get_remaining_requests(identifier, path, limit_config)
            response.headers["X-RateLimit-Limit"] = str(limit_config['requests'])
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            response.headers["X-RateLimit-Reset"] = str(int(time.time()) + limit_config['window'])

            return response

        except Exception as e:
            logger.error(f"Rate limit middleware error: {e}")
            return await call_next(request)

    def _get_limit_config(self, path: str) -> Dict[str, int]:
        """Get rate limit configuration for path."""
        for pattern, config in self.limits.items():
            if pattern == 'default':
                continue
            if path.startswith(pattern):
                return config
        return self.limits['default']

    async def _check_rate_limit(
        self,
        identifier: str,
        path: str,
        config: Dict[str, int]
    ) -> bool:
        """Check if request is within rate limit."""
        key = f"rate_limit:{identifier}:{path}"

        # Get current count
        count = await self.redis_client.get(key)
        if count is None:
            # First request
            await self.redis_client.setex(key, config['window'], 1)
            return True

        count = int(count)
        if count >= config['requests']:
            return False

        # Increment count
        await self.redis_client.incr(key)
        return True

    async def _get_remaining_requests(
        self,
        identifier: str,
        path: str,
        config: Dict[str, int]
    ) -> int:
        """Get remaining requests in window."""
        key = f"rate_limit:{identifier}:{path}"
        count = await self.redis_client.get(key)
        if count is None:
            return config['requests']
        return max(0, config['requests'] - int(count))

    async def _increment_violations(self, ip: str) -> int:
        """Increment rate limit violations for IP."""
        key = f"rate_limit:violations:{ip}"
        violations = await self.redis_client.incr(key)
        await self.redis_client.expire(key, 3600)  # Reset after 1 hour
        return violations


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Security headers middleware.

    Adds various security headers to responses to protect
    against common web vulnerabilities.
    """

    def __init__(self, app):
        super().__init__(app)
        self.csp_policy = self._build_csp_policy()

    async def dispatch(self, request: Request, call_next):
        """Add security headers to response."""
        response = await call_next(request)

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        # Content Security Policy
        response.headers["Content-Security-Policy"] = self.csp_policy

        # Strict Transport Security (if HTTPS)
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

        # Remove sensitive headers
        response.headers.pop("Server", None)
        response.headers.pop("X-Powered-By", None)

        return response

    def _build_csp_policy(self) -> str:
        """Build Content Security Policy."""
        directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline'",  # Allow inline scripts for now
            "style-src 'self' 'unsafe-inline'",  # Allow inline styles for now
            "img-src 'self' data: https:",
            "font-src 'self' data:",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "upgrade-insecure-requests"
        ]
        return "; ".join(directives)


class AuditLoggingMiddleware(BaseHTTPMiddleware):
    """
    Audit logging middleware.

    Logs all authentication-related actions for compliance
    and security monitoring.
    """

    def __init__(self, app):
        super().__init__(app)
        self.audit_logger = get_logger("audit.auth")
        self.vault = VaultClient()

    async def dispatch(self, request: Request, call_next):
        """Log authentication actions."""
        start_time = time.time()

        # Extract request information
        client_ip = request.client.host
        user_agent = request.headers.get("User-Agent", "Unknown")
        method = request.method
        path = request.url.path

        # Get user information if authenticated
        user_id = None
        username = None
        if hasattr(request.state, 'user'):
            user_id = request.state.user.get('id')
            username = request.state.user.get('username')

        # Process request
        response = await call_next(request)

        # Calculate response time
        response_time = time.time() - start_time

        # Log based on path and response
        if self._should_audit(path):
            await self._log_audit_event(
                event_type=self._get_event_type(path, method),
                user_id=user_id,
                username=username,
                ip_address=client_ip,
                user_agent=user_agent,
                path=path,
                method=method,
                status_code=response.status_code,
                response_time=response_time
            )

        return response

    def _should_audit(self, path: str) -> bool:
        """Check if path should be audited."""
        audit_paths = [
            '/auth/login',
            '/auth/logout',
            '/auth/mfa',
            '/auth/password',
            '/auth/users',
            '/auth/roles',
            '/auth/permissions'
        ]
        return any(path.startswith(p) for p in audit_paths)

    def _get_event_type(self, path: str, method: str) -> str:
        """Get audit event type from path and method."""
        event_map = {
            ('/auth/login', 'POST'): 'LOGIN_ATTEMPT',
            ('/auth/logout', 'DELETE'): 'LOGOUT',
            ('/auth/mfa/verify', 'POST'): 'MFA_VERIFICATION',
            ('/auth/password/reset', 'POST'): 'PASSWORD_RESET',
            ('/auth/users', 'POST'): 'USER_CREATED',
            ('/auth/users', 'PUT'): 'USER_UPDATED',
            ('/auth/users', 'DELETE'): 'USER_DELETED',
        }

        for (p, m), event in event_map.items():
            if path.startswith(p) and method == m:
                return event

        return f"{method}_{path.replace('/', '_').upper()}"

    async def _log_audit_event(self, **kwargs):
        """Log audit event."""
        try:
            event = {
                'timestamp': datetime.utcnow().isoformat(),
                'service': 'authentication',
                **kwargs
            }

            # Log to file/stdout
            self.audit_logger.info(json.dumps(event))

            # Store in database/vault for compliance
            await self.vault.put_secret(
                f"audit/auth/{datetime.utcnow().strftime('%Y%m%d')}/{kwargs['event_type']}/{time.time()}",
                event,
                ttl=settings.AUDIT_LOG_RETENTION_DAYS * 86400
            )

        except Exception as e:
            logger.error(f"Audit logging error: {e}")


class CORSMiddleware(BaseHTTPMiddleware):
    """
    CORS middleware with security considerations.

    Handles Cross-Origin Resource Sharing with proper
    security validations.
    """

    def __init__(self, app):
        super().__init__(app)
        self.allowed_origins = settings.ALLOWED_ORIGINS.split(",")
        self.allowed_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
        self.allowed_headers = ["Authorization", "Content-Type", "X-Request-ID"]

    async def dispatch(self, request: Request, call_next):
        """Handle CORS."""
        # Handle preflight requests
        if request.method == "OPTIONS":
            return self._handle_preflight(request)

        # Process request
        response = await call_next(request)

        # Add CORS headers
        origin = request.headers.get("Origin")
        if origin and self._is_allowed_origin(origin):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Allow-Methods"] = ", ".join(self.allowed_methods)
            response.headers["Access-Control-Allow-Headers"] = ", ".join(self.allowed_headers)
            response.headers["Access-Control-Max-Age"] = "3600"

        return response

    def _handle_preflight(self, request: Request) -> Response:
        """Handle preflight OPTIONS request."""
        origin = request.headers.get("Origin")
        if not origin or not self._is_allowed_origin(origin):
            return Response(status_code=403)

        return Response(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Methods": ", ".join(self.allowed_methods),
                "Access-Control-Allow-Headers": ", ".join(self.allowed_headers),
                "Access-Control-Max-Age": "3600",
                "Access-Control-Allow-Credentials": "true"
            }
        )

    def _is_allowed_origin(self, origin: str) -> bool:
        """Check if origin is allowed."""
        # Check exact match
        if origin in self.allowed_origins:
            return True

        # Check wildcard
        if "*" in self.allowed_origins:
            return True

        # Check pattern matching
        for allowed in self.allowed_origins:
            if allowed.startswith("*."):
                domain = allowed[2:]
                if origin.endswith(domain):
                    return True

        return False