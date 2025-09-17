"""
Security Headers Middleware for Production Hardening
"""
from typing import Dict, Optional, List
from fastapi import Request
from fastapi.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware
import hashlib
import secrets
import json
import time
import hmac

from ..core.logging import get_logger

logger = get_logger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all responses
    Implements OWASP security best practices
    """

    def __init__(
        self,
        app,
        enable_hsts: bool = True,
        enable_csp: bool = True,
        enable_cors: bool = True,
        allowed_origins: List[str] = None,
        csp_directives: Dict[str, str] = None,
    ):
        super().__init__(app)
        self.enable_hsts = enable_hsts
        self.enable_csp = enable_csp
        self.enable_cors = enable_cors
        self.allowed_origins = allowed_origins or ["https://catnet.local"]
        self.csp_directives = csp_directives or self._default_csp_directives()

    def _default_csp_directives(self) -> Dict[str, str]:
        """Get default Content Security Policy directives"""
        return {
            "default-src": "'self'",
            "script-src": "'self' 'unsafe-inline' https://cdn.jsdelivr.net",
            "style-src": "'self' 'unsafe-inline' https://fonts.googleapis.com",
            "font-src": "'self' https://fonts.gstatic.com",
            "img-src": "'self' data: https:",
            "connect-src": "'self'",
            "frame-ancestors": "'none'",
            "base-uri": "'self'",
            "form-action": "'self'",
            "upgrade-insecure-requests": "",
        }

    async def dispatch(self, request: Request, call_next):
        """Add security headers to response"""
        # Generate nonce for CSP
        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce

        # Process request
        response = await call_next(request)

        # Add security headers
        self._add_security_headers(response, request, nonce)

        return response

    def _add_security_headers(self, response: Response, request: Request, nonce: str):
        """Add security headers to response"""

        # X-Content-Type-Options
        response.headers["X-Content-Type-Options"] = "nosniff"

        # X-Frame-Options
        response.headers["X-Frame-Options"] = "DENY"

        # X-XSS-Protection (for older browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Referrer-Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions-Policy (formerly Feature-Policy)
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), "
            "camera=(), "
            "geolocation=(), "
            "gyroscope=(), "
            "magnetometer=(), "
            "microphone=(), "
            "payment=(), "
            "usb=()"
        )

        # Strict-Transport-Security (HSTS)
        if self.enable_hsts and request.url.scheme == "https":
            response.headers[
                "Strict-Transport-Security"
            ] = "max-age=31536000; includeSubDomains; preload"

        # Content-Security-Policy
        if self.enable_csp:
            csp_header = self._build_csp_header(nonce)
            response.headers["Content-Security-Policy"] = csp_header

        # CORS headers (if enabled)
        if self.enable_cors:
            self._add_cors_headers(response, request)

        # Cache-Control for sensitive endpoints
        if self._is_sensitive_endpoint(request.url.path):
            response.headers[
                "Cache-Control"
            ] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"

        # Remove potentially dangerous headers
        headers_to_remove = ["Server", "X-Powered-By", "X-AspNet-Version"]
        for header in headers_to_remove:
            response.headers.pop(header, None)

    def _build_csp_header(self, nonce: str) -> str:
        """Build Content Security Policy header"""
        directives = []
        for key, value in self.csp_directives.items():
            if value:
                # Add nonce to script-src if present
                if key == "script-src" and nonce:
                    value = value.replace("'unsafe-inline'", f"'nonce-{nonce}'")
                directives.append(f"{key} {value}")
            else:
                directives.append(key)
        return "; ".join(directives)

    def _add_cors_headers(self, response: Response, request: Request):
        """Add CORS headers"""
        origin = request.headers.get("Origin")

        if origin in self.allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers[
                "Access-Control-Allow-Methods"
            ] = "GET, POST, PUT, DELETE, OPTIONS"
            response.headers[
                "Access-Control-Allow-Headers"
            ] = "Content-Type, Authorization, X-Request-ID, X-CSRF-Token"
            response.headers["Access-Control-Max-Age"] = "86400"
        else:
            # Default to most restrictive
            response.headers["Access-Control-Allow-Origin"] = self.allowed_origins[0]

    def _is_sensitive_endpoint(self, path: str) -> bool:
        """Check if endpoint handles sensitive data"""
        sensitive_patterns = [
            "/auth",
            "/api/v1/users",
            "/api/v1/devices",
            "/api/v1/deployments",
            "/admin",
        ]
        return any(pattern in path for pattern in sensitive_patterns)


class CSRFProtection:
    """
    CSRF Protection implementation
    Uses double-submit cookie pattern
    """

    def __init__(
        self,
        secret_key: str,
        cookie_name: str = "csrf_token",
        header_name: str = "X-CSRF-Token",
        excluded_paths: List[str] = None,
    ):
        self.secret_key = secret_key
        self.cookie_name = cookie_name
        self.header_name = header_name
        self.excluded_paths = excluded_paths or ["/docs", "/openapi.json", "/health"]

    def generate_token(self) -> str:
        """Generate CSRF token"""
        random_data = secrets.token_urlsafe(32)
        timestamp = str(int(time.time()))

        # Create signed token
        payload = f"{random_data}.{timestamp}"
        signature = hashlib.sha256(f"{payload}.{self.secret_key}".encode()).hexdigest()

        return f"{payload}.{signature}"

    def verify_token(self, token: str) -> bool:
        """Verify CSRF token"""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return False

            random_data, timestamp, signature = parts

            # Recreate signature
            payload = f"{random_data}.{timestamp}"
            expected_signature = hashlib.sha256(
                f"{payload}.{self.secret_key}".encode()
            ).hexdigest()

            # Verify signature
            if not secrets.compare_digest(signature, expected_signature):
                return False

            # Check token age (max 1 hour)
            token_age = int(time.time()) - int(timestamp)
            if token_age > 3600:
                return False

            return True

        except Exception as e:
            logger.error(f"CSRF token verification failed: {e}")
            return False

    async def __call__(self, request: Request, call_next):
        """CSRF protection middleware"""
        # Skip for excluded paths
        if any(path in request.url.path for path in self.excluded_paths):
            return await call_next(request)

        # Skip for safe methods
        if request.method in ["GET", "HEAD", "OPTIONS"]:
            return await call_next(request)

        # Get token from cookie
        cookie_token = request.cookies.get(self.cookie_name)

        # Get token from header
        header_token = request.headers.get(self.header_name)

        # Verify tokens match and are valid
        if not cookie_token or not header_token:
            logger.warning(f"Missing CSRF token for {request.url.path}")
            return Response(
                content=json.dumps({"error": "CSRF token missing"}),
                status_code=403,
                media_type="application/json",
            )

        if cookie_token != header_token:
            logger.warning(f"CSRF token mismatch for {request.url.path}")
            return Response(
                content=json.dumps({"error": "CSRF token mismatch"}),
                status_code=403,
                media_type="application/json",
            )

        if not self.verify_token(cookie_token):
            logger.warning(f"Invalid CSRF token for {request.url.path}")
            return Response(
                content=json.dumps({"error": "Invalid CSRF token"}),
                status_code=403,
                media_type="application/json",
            )

        # Token valid, continue
        response = await call_next(request)

        # Generate new token for response
        new_token = self.generate_token()
        response.set_cookie(
            key=self.cookie_name,
            value=new_token,
            httponly=True,
            secure=True,
            samesite="strict",
            max_age=3600,
        )

        return response


class RequestSignatureVerification:
    """
    Request signature verification for API calls
    Implements HMAC-SHA256 signing
    """

    def __init__(
        self,
        secret_key: str,
        header_name: str = "X-Signature",
        timestamp_header: str = "X-Timestamp",
        max_age: int = 300,  # 5 minutes
    ):
        self.secret_key = secret_key
        self.header_name = header_name
        self.timestamp_header = timestamp_header
        self.max_age = max_age

    def generate_signature(
        self, method: str, path: str, body: bytes, timestamp: str
    ) -> str:
        """Generate request signature"""
        # Create canonical request
        canonical = f"{method}\n{path}\n{body.decode('utf-8')}\n{timestamp}"

        # Generate HMAC-SHA256
        signature = hmac.new(
            self.secret_key.encode(),
            canonical.encode(),
            hashlib.sha256,
        ).hexdigest()

        return signature

    async def verify_request(self, request: Request) -> bool:
        """Verify request signature"""
        try:
            # Get signature and timestamp from headers
            signature = request.headers.get(self.header_name)
            timestamp = request.headers.get(self.timestamp_header)

            if not signature or not timestamp:
                return False

            # Check timestamp age
            current_time = int(time.time())
            request_time = int(timestamp)

            if abs(current_time - request_time) > self.max_age:
                logger.warning("Request signature expired")
                return False

            # Get request body
            body = await request.body()

            # Generate expected signature
            expected_signature = self.generate_signature(
                request.method,
                request.url.path,
                body,
                timestamp,
            )

            # Verify signature
            if not secrets.compare_digest(signature, expected_signature):
                logger.warning("Invalid request signature")
                return False

            return True

        except Exception as e:
            logger.error(f"Request signature verification failed: {e}")
            return False


def configure_security_headers(app, config: Dict[str, any] = None):
    """
    Configure all security headers for the application

    Args:
        app: FastAPI application instance
        config: Security configuration
    """
    config = config or {}

    # Add security headers middleware
    app.add_middleware(
        SecurityHeadersMiddleware,
        enable_hsts=config.get("enable_hsts", True),
        enable_csp=config.get("enable_csp", True),
        enable_cors=config.get("enable_cors", True),
        allowed_origins=config.get("allowed_origins", ["https://catnet.local"]),
    )

    # Add CSRF protection if enabled
    if config.get("enable_csrf", True):
        csrf_protection = CSRFProtection(
            secret_key=config.get("csrf_secret", secrets.token_urlsafe(32)),
        )
        app.middleware("http")(csrf_protection)

    logger.info("Security headers configured")
