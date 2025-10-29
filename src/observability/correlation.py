"""
Correlation ID Management for CatNet

Provides automatic correlation ID propagation across all services
and requests for complete request tracing.

Features:
- Automatic correlation ID generation
- Propagation via HTTP headers and logs
- Integration with OpenTelemetry traces
- Async context support
- Thread-safe storage

Usage:
    from src.observability.correlation import (
        CorrelationMiddleware,
        get_correlation_id,
        set_correlation_id,
    )

    # Add to FastAPI app
    app.add_middleware(CorrelationMiddleware)

    # Get current correlation ID in any handler
    correlation_id = get_correlation_id()
    logger.info("Processing request", correlation_id=correlation_id)
"""

import uuid
import logging
from typing import Optional, Dict, Any
from contextvars import ContextVar
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.datastructures import MutableHeaders
import structlog

# Context variable for storing correlation ID
_correlation_id: ContextVar[Optional[str]] = ContextVar("correlation_id", default=None)
_request_id: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
_user_id: ContextVar[Optional[str]] = ContextVar("user_id", default=None)
_session_id: ContextVar[Optional[str]] = ContextVar("session_id", default=None)

# HTTP header names
CORRELATION_ID_HEADER = "X-Correlation-ID"
REQUEST_ID_HEADER = "X-Request-ID"
SESSION_ID_HEADER = "X-Session-ID"

logger = structlog.get_logger(__name__)


class CorrelationMiddleware(BaseHTTPMiddleware):
    """
    Middleware to manage correlation IDs for requests.

    Automatically:
    - Extracts correlation ID from request headers
    - Generates new ID if not present
    - Propagates ID through context
    - Adds ID to response headers
    - Logs correlation ID with all log messages
    """

    async def dispatch(self, request: Request, call_next):
        # Extract or generate correlation ID
        correlation_id = (
            request.headers.get(CORRELATION_ID_HEADER)
            or request.headers.get(REQUEST_ID_HEADER)
            or str(uuid.uuid4())
        )

        # Generate unique request ID
        request_id = str(uuid.uuid4())

        # Extract session ID if present
        session_id = request.headers.get(SESSION_ID_HEADER)

        # Set context variables
        _correlation_id.set(correlation_id)
        _request_id.set(request_id)
        if session_id:
            _session_id.set(session_id)

        # Store in request state for easy access
        request.state.correlation_id = correlation_id
        request.state.request_id = request_id
        if session_id:
            request.state.session_id = session_id

        # Bind to logger context
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            correlation_id=correlation_id,
            request_id=request_id,
            session_id=session_id,
            method=request.method,
            path=request.url.path,
            client_ip=request.client.host if request.client else None,
        )

        # Add to OpenTelemetry span if tracing enabled
        try:
            from opentelemetry import trace

            span = trace.get_current_span()
            if span.is_recording():
                span.set_attribute("correlation.id", correlation_id)
                span.set_attribute("request.id", request_id)
                if session_id:
                    span.set_attribute("session.id", session_id)
        except ImportError:
            pass  # OpenTelemetry not installed

        # Log request start
        logger.info(
            "Request started",
            method=request.method,
            path=request.url.path,
            query_params=dict(request.query_params),
        )

        # Process request
        try:
            response = await call_next(request)

            # Add correlation headers to response
            response.headers[CORRELATION_ID_HEADER] = correlation_id
            response.headers[REQUEST_ID_HEADER] = request_id

            # Log request completion
            logger.info(
                "Request completed",
                status_code=response.status_code,
                method=request.method,
                path=request.url.path,
            )

            return response

        except Exception as e:
            # Log error with correlation context
            logger.error(
                "Request failed",
                error=str(e),
                error_type=type(e).__name__,
                method=request.method,
                path=request.url.path,
            )
            raise

        finally:
            # Clear context variables
            _correlation_id.set(None)
            _request_id.set(None)
            _session_id.set(None)
            _user_id.set(None)


def get_correlation_id() -> Optional[str]:
    """
    Get the current correlation ID.

    Returns:
        Correlation ID string or None if not in request context
    """
    return _correlation_id.get()


def get_request_id() -> Optional[str]:
    """
    Get the current request ID.

    Returns:
        Request ID string or None if not in request context
    """
    return _request_id.get()


def get_session_id() -> Optional[str]:
    """
    Get the current session ID.

    Returns:
        Session ID string or None if not set
    """
    return _session_id.get()


def get_user_id() -> Optional[str]:
    """
    Get the current user ID.

    Returns:
        User ID string or None if not authenticated
    """
    return _user_id.get()


def set_correlation_id(correlation_id: str) -> None:
    """
    Manually set the correlation ID.

    Args:
        correlation_id: Correlation ID to set
    """
    _correlation_id.set(correlation_id)
    structlog.contextvars.bind_contextvars(correlation_id=correlation_id)


def set_user_id(user_id: str) -> None:
    """
    Set the current user ID in context.

    Args:
        user_id: User ID to set
    """
    _user_id.set(user_id)
    structlog.contextvars.bind_contextvars(user_id=user_id)

    # Add to OpenTelemetry span
    try:
        from opentelemetry import trace

        span = trace.get_current_span()
        if span.is_recording():
            span.set_attribute("user.id", user_id)
    except ImportError:
        pass


def get_correlation_context() -> Dict[str, Optional[str]]:
    """
    Get all correlation context as a dictionary.

    Returns:
        Dictionary with correlation_id, request_id, session_id, user_id
    """
    return {
        "correlation_id": get_correlation_id(),
        "request_id": get_request_id(),
        "session_id": get_session_id(),
        "user_id": get_user_id(),
    }


def inject_correlation_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Inject correlation context into HTTP headers for external requests.

    Args:
        headers: Existing headers dictionary

    Returns:
        Headers with correlation context injected
    """
    correlation_id = get_correlation_id()
    if correlation_id:
        headers[CORRELATION_ID_HEADER] = correlation_id

    request_id = get_request_id()
    if request_id:
        headers[REQUEST_ID_HEADER] = request_id

    session_id = get_session_id()
    if session_id:
        headers[SESSION_ID_HEADER] = session_id

    return headers


# Structured logging processor to add correlation context
def add_correlation_context(
    logger: logging.Logger, method_name: str, event_dict: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Structlog processor to add correlation context to all log messages.

    Usage in structlog configuration:
        structlog.configure(
            processors=[
                add_correlation_context,
                ...
            ]
        )
    """
    context = get_correlation_context()

    # Only add non-None values
    for key, value in context.items():
        if value is not None:
            event_dict[key] = value

    return event_dict


# Async context manager for manual correlation
from contextlib import asynccontextmanager


@asynccontextmanager
async def correlation_context(correlation_id: Optional[str] = None):
    """
    Async context manager for manual correlation ID management.

    Args:
        correlation_id: Optional correlation ID (generates new if not provided)

    Usage:
        async with correlation_context() as corr_id:
            # All operations here will have the same correlation ID
            await some_operation()
    """
    # Save current context
    old_correlation_id = _correlation_id.get()
    old_request_id = _request_id.get()

    # Set new context
    new_correlation_id = correlation_id or str(uuid.uuid4())
    new_request_id = str(uuid.uuid4())

    _correlation_id.set(new_correlation_id)
    _request_id.set(new_request_id)

    structlog.contextvars.bind_contextvars(
        correlation_id=new_correlation_id,
        request_id=new_request_id,
    )

    try:
        yield new_correlation_id
    finally:
        # Restore old context
        _correlation_id.set(old_correlation_id)
        _request_id.set(old_request_id)

        if old_correlation_id:
            structlog.contextvars.bind_contextvars(
                correlation_id=old_correlation_id,
                request_id=old_request_id,
            )
        else:
            structlog.contextvars.clear_contextvars()


# Helper for background tasks
def propagate_correlation(func):
    """
    Decorator to propagate correlation context to background tasks.

    Usage:
        @propagate_correlation
        async def background_task():
            # This task will have the same correlation ID as the caller
            logger.info("Background task started")
    """
    import asyncio
    from functools import wraps

    @wraps(func)
    async def async_wrapper(*args, **kwargs):
        # Capture current correlation context
        correlation_id = get_correlation_id()
        request_id = get_request_id()
        session_id = get_session_id()
        user_id = get_user_id()

        # Restore context in background task
        _correlation_id.set(correlation_id)
        _request_id.set(request_id)
        _session_id.set(session_id)
        _user_id.set(user_id)

        if correlation_id:
            structlog.contextvars.bind_contextvars(
                correlation_id=correlation_id,
                request_id=request_id,
                session_id=session_id,
                user_id=user_id,
            )

        try:
            return await func(*args, **kwargs)
        finally:
            # Clear context after task
            _correlation_id.set(None)
            _request_id.set(None)
            _session_id.set(None)
            _user_id.set(None)

    @wraps(func)
    def sync_wrapper(*args, **kwargs):
        correlation_id = get_correlation_id()
        request_id = get_request_id()
        session_id = get_session_id()
        user_id = get_user_id()

        _correlation_id.set(correlation_id)
        _request_id.set(request_id)
        _session_id.set(session_id)
        _user_id.set(user_id)

        if correlation_id:
            structlog.contextvars.bind_contextvars(
                correlation_id=correlation_id,
                request_id=request_id,
                session_id=session_id,
                user_id=user_id,
            )

        try:
            return func(*args, **kwargs)
        finally:
            _correlation_id.set(None)
            _request_id.set(None)
            _session_id.set(None)
            _user_id.set(None)

    if asyncio.iscoroutinefunction(func):
        return async_wrapper
    else:
        return sync_wrapper


# Celery integration
def get_celery_correlation_context():
    """
    Get correlation context for Celery tasks.

    Usage in Celery task:
        from celery import current_task
        context = get_celery_correlation_context()
        current_task.update_state(meta=context)
    """
    return {
        "correlation_id": get_correlation_id(),
        "request_id": get_request_id(),
        "session_id": get_session_id(),
        "user_id": get_user_id(),
    }


def set_celery_correlation_context(context: Dict[str, Optional[str]]):
    """
    Restore correlation context in Celery tasks.

    Usage in Celery task:
        @app.task
        def my_task(context, ...):
            set_celery_correlation_context(context)
            # Now all logs will have correlation context
    """
    if context.get("correlation_id"):
        _correlation_id.set(context["correlation_id"])
    if context.get("request_id"):
        _request_id.set(context["request_id"])
    if context.get("session_id"):
        _session_id.set(context["session_id"])
    if context.get("user_id"):
        _user_id.set(context["user_id"])

    # Bind to structlog
    structlog.contextvars.bind_contextvars(**{k: v for k, v in context.items() if v})
