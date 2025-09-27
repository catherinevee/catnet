"""
Request Logging Middleware
Comprehensive logging of all API requests for audit and debugging
"""

import time
import json
import traceback
from typing import Callable, Optional, Dict, Any
from datetime import datetime
import uuid
import hashlib

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from sqlalchemy.ext.asyncio import AsyncSession
import aioredis

from src.core.config import settings
from src.db.models import AuditLog, APIRequestLog
from src.security.audit import AuditLogger


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Comprehensive request logging middleware that:
    - Logs all API requests and responses
    - Tracks request/response times
    - Records errors and exceptions
    - Maintains audit trail
    - Supports log correlation
    - Implements log sanitization
    """

    def __init__(
        self,
        app: ASGIApp,
        db_session: Optional[AsyncSession] = None,
        redis_client: Optional[aioredis.Redis] = None,
        audit_logger: Optional[AuditLogger] = None
    ):
        super().__init__(app)
        self.db = db_session
        self.redis = redis_client
        self.audit = audit_logger

        # Sensitive fields to mask in logs
        self.sensitive_fields = {
            "password", "secret", "token", "api_key", "private_key",
            "credential", "auth", "authorization", "cookie",
            "ssn", "credit_card", "card_number", "cvv", "pin"
        }

        # Paths to exclude from detailed logging
        self.excluded_paths = {
            "/health", "/metrics", "/favicon.ico", "/docs", "/openapi.json"
        }

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process and log request/response
        """

        # Generate or get request ID
        request_id = getattr(request.state, "request_id", None) or str(uuid.uuid4())
        request.state.request_id = request_id

        # Skip logging for excluded paths
        if request.url.path in self.excluded_paths:
            return await call_next(request)

        # Capture request details
        start_time = time.time()
        request_time = datetime.utcnow()

        # Get request body (for logging)
        request_body = None
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                # Store original body
                body_bytes = await request.body()
                request_body = body_bytes.decode("utf-8") if body_bytes else None

                # Recreate request with body for downstream processing
                async def receive():
                    return {"type": "http.request", "body": body_bytes}
                request._receive = receive

            except Exception as e:
                request_body = f"Error reading body: {str(e)}"

        # Extract request metadata
        request_meta = {
            "request_id": request_id,
            "method": request.method,
            "path": str(request.url.path),
            "query": dict(request.query_params),
            "headers": self._sanitize_headers(dict(request.headers)),
            "client_ip": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
            "content_type": request.headers.get("content-type"),
            "content_length": request.headers.get("content-length"),
            "body": self._sanitize_body(request_body) if request_body else None
        }

        # Get user info if available
        user_info = None
        if hasattr(request.state, "user"):
            user_info = {
                "user_id": str(request.state.user.id),
                "username": request.state.user.username
            }

        response = None
        error_details = None
        status_code = 500

        try:
            # Process request
            response = await call_next(request)
            status_code = response.status_code

            # Capture response body for logging (if not streaming)
            response_body = None
            if status_code < 400:  # Only log successful response bodies
                response_body = b""
                async for chunk in response.body_iterator:
                    response_body += chunk

                # Create new response with captured body
                response = Response(
                    content=response_body,
                    status_code=status_code,
                    headers=dict(response.headers),
                    media_type=response.media_type
                )

                # Sanitize response body for logging
                try:
                    response_content = response_body.decode("utf-8")
                    response_meta = self._sanitize_body(response_content)
                except:
                    response_meta = "Binary content"
            else:
                response_meta = None

        except Exception as e:
            # Capture exception details
            error_details = {
                "error_type": type(e).__name__,
                "error_message": str(e),
                "traceback": traceback.format_exc()
            }

            # Log to audit logger immediately
            if self.audit:
                await self.audit.log_error(
                    error_type="request_processing_error",
                    error_message=str(e),
                    context={
                        "request_id": request_id,
                        **request_meta
                    }
                )

            # Return error response
            response = JSONResponse(
                status_code=500,
                content={
                    "error": "Internal server error",
                    "request_id": request_id
                }
            )
            status_code = 500

        finally:
            # Calculate processing time
            process_time = (time.time() - start_time) * 1000  # Convert to milliseconds

            # Create log entry
            log_entry = {
                "request_id": request_id,
                "timestamp": request_time.isoformat(),
                "method": request.method,
                "path": str(request.url.path),
                "status_code": status_code,
                "process_time_ms": round(process_time, 2),
                "client_ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
                "user": user_info,
                "request": request_meta,
                "response": {"status_code": status_code, "body": response_meta} if response else None,
                "error": error_details
            }

            # Store in different locations based on configuration
            await self._store_log(log_entry)

            # Add correlation ID to response headers
            if response:
                response.headers["X-Request-ID"] = request_id
                response.headers["X-Process-Time"] = f"{process_time:.2f}ms"

            # Update metrics
            await self._update_metrics(request.method, str(request.url.path), status_code, process_time)

        return response

    def _sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Sanitize sensitive information from headers
        """

        sanitized = {}
        for key, value in headers.items():
            key_lower = key.lower()

            # Mask sensitive headers
            if any(sensitive in key_lower for sensitive in ["authorization", "cookie", "api-key", "token"]):
                if len(value) > 10:
                    sanitized[key] = f"{value[:6]}...{value[-4:]}"
                else:
                    sanitized[key] = "***"
            else:
                sanitized[key] = value

        return sanitized

    def _sanitize_body(self, body: str) -> Any:
        """
        Sanitize sensitive information from request/response body
        """

        if not body:
            return None

        try:
            # Try to parse as JSON
            data = json.loads(body)
            return self._sanitize_dict(data)
        except json.JSONDecodeError:
            # If not JSON, check for sensitive patterns
            for field in self.sensitive_fields:
                if field in body.lower():
                    # Found sensitive field, return masked version
                    return "***SANITIZED***"
            return body[:1000] if len(body) > 1000 else body  # Truncate large bodies

    def _sanitize_dict(self, data: Any) -> Any:
        """
        Recursively sanitize dictionary/list structures
        """

        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                key_lower = key.lower()

                # Check if key contains sensitive field name
                if any(sensitive in key_lower for sensitive in self.sensitive_fields):
                    if isinstance(value, str) and len(value) > 0:
                        sanitized[key] = "***REDACTED***"
                    else:
                        sanitized[key] = "***"
                else:
                    sanitized[key] = self._sanitize_dict(value)
            return sanitized

        elif isinstance(data, list):
            return [self._sanitize_dict(item) for item in data]

        elif isinstance(data, str):
            # Check for patterns that look like sensitive data
            if len(data) > 20 and data.replace("-", "").isalnum():
                # Might be a token or key
                return f"{data[:4]}...{data[-4:]}"
            return data

        else:
            return data

    async def _store_log(self, log_entry: Dict[str, Any]):
        """
        Store log entry in configured destinations
        """

        # Store in database if available
        if self.db:
            try:
                api_log = APIRequestLog(
                    request_id=log_entry["request_id"],
                    method=log_entry["method"],
                    path=log_entry["path"],
                    status_code=log_entry["status_code"],
                    process_time_ms=log_entry["process_time_ms"],
                    client_ip=log_entry["client_ip"],
                    user_agent=log_entry["user_agent"],
                    user_id=uuid.UUID(log_entry["user"]["user_id"]) if log_entry.get("user") else None,
                    request_headers=log_entry["request"]["headers"],
                    request_body=log_entry["request"].get("body"),
                    response_body=log_entry["response"]["body"] if log_entry.get("response") else None,
                    error_message=log_entry["error"]["error_message"] if log_entry.get("error") else None,
                    created_at=datetime.fromisoformat(log_entry["timestamp"])
                )
                self.db.add(api_log)
                await self.db.commit()
            except Exception as e:
                # Log error but don't fail the request
                print(f"Failed to store log in database: {e}")

        # Store in Redis for real-time monitoring
        if self.redis:
            try:
                # Store recent requests
                await self.redis.lpush(
                    "api_logs:recent",
                    json.dumps(log_entry)
                )
                await self.redis.ltrim("api_logs:recent", 0, 999)  # Keep last 1000

                # Store by status code for monitoring
                if log_entry["status_code"] >= 400:
                    await self.redis.lpush(
                        f"api_logs:errors:{log_entry['status_code']}",
                        json.dumps(log_entry)
                    )
                    await self.redis.ltrim(f"api_logs:errors:{log_entry['status_code']}", 0, 99)

            except Exception as e:
                print(f"Failed to store log in Redis: {e}")

        # Log to audit logger
        if self.audit:
            try:
                await self.audit.log_api_request(
                    request_id=log_entry["request_id"],
                    method=log_entry["method"],
                    path=log_entry["path"],
                    status_code=log_entry["status_code"],
                    user_id=log_entry["user"]["user_id"] if log_entry.get("user") else None,
                    process_time_ms=log_entry["process_time_ms"],
                    client_ip=log_entry["client_ip"]
                )
            except Exception as e:
                print(f"Failed to log to audit logger: {e}")

        # Log to stdout in development
        if settings.ENVIRONMENT == "development":
            print(json.dumps({
                "request_id": log_entry["request_id"],
                "method": log_entry["method"],
                "path": log_entry["path"],
                "status": log_entry["status_code"],
                "time_ms": log_entry["process_time_ms"]
            }))

    async def _update_metrics(self, method: str, path: str, status_code: int, process_time: float):
        """
        Update performance metrics
        """

        if self.redis:
            try:
                # Increment request counter
                await self.redis.incr(f"metrics:requests:total")
                await self.redis.incr(f"metrics:requests:{method}:{status_code}")

                # Track response times
                await self.redis.lpush(f"metrics:response_times:{path}", process_time)
                await self.redis.ltrim(f"metrics:response_times:{path}", 0, 999)

                # Track error rates
                if status_code >= 400:
                    await self.redis.incr(f"metrics:errors:total")
                    await self.redis.incr(f"metrics:errors:{status_code}")

                # Update hourly stats
                hour_key = datetime.utcnow().strftime("%Y%m%d%H")
                await self.redis.hincrby(f"metrics:hourly:{hour_key}", "requests", 1)
                await self.redis.hincrby(f"metrics:hourly:{hour_key}", f"status_{status_code}", 1)
                await self.redis.expire(f"metrics:hourly:{hour_key}", 86400)  # Expire after 24 hours

            except Exception as e:
                print(f"Failed to update metrics: {e}")


class AccessLogMiddleware:
    """
    Lightweight access log middleware for basic logging
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start_time = time.time()
        client = scope.get("client", ["unknown", None])

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                process_time = time.time() - start_time
                status_code = message.get("status", 0)

                # Log access
                log_message = (
                    f"{client[0]} - "
                    f"{scope['method']} {scope['path']} "
                    f"HTTP/{scope['http_version']} "
                    f"{status_code} "
                    f"{process_time:.3f}s"
                )

                if settings.LOG_LEVEL == "DEBUG":
                    print(log_message)

            await send(message)

        await self.app(scope, receive, send_wrapper)