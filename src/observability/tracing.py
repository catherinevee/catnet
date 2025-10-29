"""
OpenTelemetry Distributed Tracing for CatNet

Provides comprehensive distributed tracing across all CatNet services
with automatic instrumentation for FastAPI, PostgreSQL, Redis, and HTTP clients.

Usage:
    from src.observability.tracing import setup_tracing, trace_function, get_tracer

    # In main.py
    setup_tracing(app, service_name="catnet-api")

    # Decorator for custom spans
    @trace_function(span_name="deploy_configuration")
    async def deploy_config(device_id: str):
        ...

    # Manual span creation
    tracer = get_tracer(__name__)
    with tracer.start_as_current_span("custom_operation") as span:
        span.set_attribute("device.id", device_id)
        # ... operation
"""

import os
import logging
from typing import Optional, Dict, Any, Callable
from functools import wraps
from contextlib import contextmanager

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
)
from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.asyncpg import AsyncPGInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.trace import Status, StatusCode, SpanKind
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

from fastapi import FastAPI, Request
import structlog

logger = structlog.get_logger(__name__)

# Global tracer provider
_tracer_provider: Optional[TracerProvider] = None
_propagator = TraceContextTextMapPropagator()


def setup_tracing(
    app: FastAPI,
    service_name: str = "catnet",
    service_version: str = "1.0.0",
    jaeger_endpoint: Optional[str] = None,
    otlp_endpoint: Optional[str] = None,
    console_export: bool = False,
    sample_rate: float = 1.0,
) -> None:
    """
    Setup OpenTelemetry distributed tracing for CatNet.

    Args:
        app: FastAPI application instance
        service_name: Name of the service (e.g., "catnet-api", "catnet-worker")
        service_version: Version of the service
        jaeger_endpoint: Jaeger collector endpoint (e.g., "localhost:6831")
        otlp_endpoint: OTLP collector endpoint (e.g., "localhost:4317")
        console_export: Export traces to console (useful for debugging)
        sample_rate: Sampling rate (0.0 to 1.0)
    """
    global _tracer_provider

    # Create resource with service information
    resource = Resource.create(
        {
            SERVICE_NAME: service_name,
            SERVICE_VERSION: service_version,
            "deployment.environment": os.getenv("ENVIRONMENT", "development"),
            "service.namespace": "catnet",
        }
    )

    # Create tracer provider
    _tracer_provider = TracerProvider(
        resource=resource,
        sampler=_create_sampler(sample_rate),
    )

    # Add span processors
    if jaeger_endpoint:
        jaeger_exporter = JaegerExporter(
            agent_host_name=jaeger_endpoint.split(":")[0],
            agent_port=int(jaeger_endpoint.split(":")[1]),
        )
        _tracer_provider.add_span_processor(BatchSpanProcessor(jaeger_exporter))
        logger.info("Jaeger tracing enabled", endpoint=jaeger_endpoint)

    if otlp_endpoint:
        otlp_exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
        _tracer_provider.add_span_processor(BatchSpanProcessor(otlp_exporter))
        logger.info("OTLP tracing enabled", endpoint=otlp_endpoint)

    if console_export:
        console_exporter = ConsoleSpanExporter()
        _tracer_provider.add_span_processor(BatchSpanProcessor(console_exporter))
        logger.info("Console tracing enabled")

    # Set global tracer provider
    trace.set_tracer_provider(_tracer_provider)

    # Instrument FastAPI
    FastAPIInstrumentor.instrument_app(app, tracer_provider=_tracer_provider)
    logger.info("FastAPI instrumented for tracing")

    # Instrument database (PostgreSQL)
    AsyncPGInstrumentor().instrument(tracer_provider=_tracer_provider)
    logger.info("PostgreSQL instrumented for tracing")

    # Instrument Redis
    RedisInstrumentor().instrument(tracer_provider=_tracer_provider)
    logger.info("Redis instrumented for tracing")

    # Instrument HTTP clients
    HTTPXClientInstrumentor().instrument(tracer_provider=_tracer_provider)
    RequestsInstrumentor().instrument(tracer_provider=_tracer_provider)
    logger.info("HTTP clients instrumented for tracing")

    # Add middleware for correlation
    app.middleware("http")(_correlation_middleware)

    logger.info(
        "Distributed tracing setup complete",
        service_name=service_name,
        service_version=service_version,
        sample_rate=sample_rate,
    )


def _create_sampler(sample_rate: float):
    """Create a sampler based on sample rate."""
    from opentelemetry.sdk.trace.sampling import TraceIdRatioBased

    return TraceIdRatioBased(sample_rate)


async def _correlation_middleware(request: Request, call_next):
    """
    Middleware to add correlation ID to requests.
    """
    # Extract trace context from headers
    ctx = _propagator.extract(carrier=request.headers)

    # Get current span
    span = trace.get_current_span()

    # Add request metadata to span
    if span.is_recording():
        span.set_attribute("http.method", request.method)
        span.set_attribute("http.url", str(request.url))
        span.set_attribute("http.client_ip", request.client.host if request.client else "unknown")

        # Add user context if authenticated
        if hasattr(request.state, "user") and request.state.user:
            span.set_attribute("user.id", str(request.state.user.id))
            span.set_attribute("user.username", request.state.user.username)

    # Process request
    response = await call_next(request)

    # Add response metadata
    if span.is_recording():
        span.set_attribute("http.status_code", response.status_code)

        # Mark error spans
        if response.status_code >= 500:
            span.set_status(Status(StatusCode.ERROR, f"HTTP {response.status_code}"))
        elif response.status_code >= 400:
            span.set_status(Status(StatusCode.ERROR, f"Client error {response.status_code}"))

    return response


def get_tracer(name: str) -> trace.Tracer:
    """
    Get a tracer for the given name.

    Args:
        name: Tracer name (usually __name__ of the module)

    Returns:
        Tracer instance
    """
    if _tracer_provider is None:
        # Return a no-op tracer if tracing not set up
        return trace.get_tracer(name)

    return trace.get_tracer(name, tracer_provider=_tracer_provider)


def trace_function(span_name: Optional[str] = None, span_kind: SpanKind = SpanKind.INTERNAL):
    """
    Decorator to automatically trace a function.

    Args:
        span_name: Name of the span (defaults to function name)
        span_kind: Kind of span (INTERNAL, CLIENT, SERVER, PRODUCER, CONSUMER)

    Usage:
        @trace_function(span_name="deploy_configuration")
        async def deploy_config(device_id: str):
            ...
    """

    def decorator(func: Callable) -> Callable:
        tracer = get_tracer(func.__module__)
        name = span_name or f"{func.__module__}.{func.__name__}"

        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            with tracer.start_as_current_span(name, kind=span_kind) as span:
                try:
                    # Add function arguments as attributes
                    _add_function_attributes(span, func, args, kwargs)

                    # Execute function
                    result = await func(*args, **kwargs)

                    # Mark success
                    span.set_status(Status(StatusCode.OK))
                    return result

                except Exception as e:
                    # Record exception
                    span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    raise

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            with tracer.start_as_current_span(name, kind=span_kind) as span:
                try:
                    _add_function_attributes(span, func, args, kwargs)
                    result = func(*args, **kwargs)
                    span.set_status(Status(StatusCode.OK))
                    return result
                except Exception as e:
                    span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    raise

        # Return appropriate wrapper based on function type
        import asyncio

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


def _add_function_attributes(span: trace.Span, func: Callable, args: tuple, kwargs: dict) -> None:
    """Add function arguments as span attributes."""
    # Add function name
    span.set_attribute("code.function", func.__name__)
    span.set_attribute("code.namespace", func.__module__)

    # Add safe arguments (exclude passwords, tokens, etc.)
    safe_kwargs = {
        k: v
        for k, v in kwargs.items()
        if not any(secret in k.lower() for secret in ["password", "token", "secret", "key"])
    }

    for key, value in safe_kwargs.items():
        # Only add simple types
        if isinstance(value, (str, int, float, bool)):
            span.set_attribute(f"args.{key}", value)


@contextmanager
def trace_span(
    span_name: str,
    attributes: Optional[Dict[str, Any]] = None,
    span_kind: SpanKind = SpanKind.INTERNAL,
):
    """
    Context manager for creating custom spans.

    Args:
        span_name: Name of the span
        attributes: Additional attributes to add to span
        span_kind: Kind of span

    Usage:
        with trace_span("database_query", {"query": "SELECT ..."}) as span:
            result = await db.execute(query)
            span.set_attribute("rows_returned", len(result))
    """
    tracer = get_tracer(__name__)

    with tracer.start_as_current_span(span_name, kind=span_kind) as span:
        # Add initial attributes
        if attributes:
            for key, value in attributes.items():
                if isinstance(value, (str, int, float, bool)):
                    span.set_attribute(key, value)

        try:
            yield span
            span.set_status(Status(StatusCode.OK))
        except Exception as e:
            span.record_exception(e)
            span.set_status(Status(StatusCode.ERROR, str(e)))
            raise


def add_span_attributes(**attributes: Any) -> None:
    """
    Add attributes to the current span.

    Args:
        **attributes: Key-value pairs to add as span attributes

    Usage:
        add_span_attributes(device_id="router-1", vendor="cisco")
    """
    span = trace.get_current_span()
    if span.is_recording():
        for key, value in attributes.items():
            if isinstance(value, (str, int, float, bool)):
                span.set_attribute(key, value)


def add_span_event(name: str, attributes: Optional[Dict[str, Any]] = None) -> None:
    """
    Add an event to the current span.

    Args:
        name: Event name
        attributes: Event attributes

    Usage:
        add_span_event("config_validated", {"valid": True, "rules_passed": 10})
    """
    span = trace.get_current_span()
    if span.is_recording():
        span.add_event(name, attributes=attributes or {})


def get_trace_context() -> Dict[str, str]:
    """
    Get current trace context as a dictionary.

    Useful for propagating trace context to external services.

    Returns:
        Dictionary with traceparent and tracestate headers
    """
    carrier = {}
    _propagator.inject(carrier)
    return carrier


def inject_trace_context(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Inject trace context into HTTP headers.

    Args:
        headers: Existing headers dictionary

    Returns:
        Headers with trace context injected
    """
    _propagator.inject(headers)
    return headers


# Convenience functions for common operations

@trace_function(span_name="device.connect")
async def trace_device_connect(device_id: str, func: Callable, *args, **kwargs):
    """Trace device connection operations."""
    add_span_attributes(device_id=device_id, operation="connect")
    return await func(*args, **kwargs)


@trace_function(span_name="deployment.execute")
async def trace_deployment_execute(deployment_id: str, func: Callable, *args, **kwargs):
    """Trace deployment execution."""
    add_span_attributes(deployment_id=deployment_id, operation="execute")
    return await func(*args, **kwargs)


@trace_function(span_name="vault.get_secret")
async def trace_vault_operation(secret_path: str, func: Callable, *args, **kwargs):
    """Trace Vault operations."""
    add_span_attributes(secret_path=secret_path, operation="get_secret")
    return await func(*args, **kwargs)


# Metrics integration
class TracingMetrics:
    """Collect metrics from tracing data."""

    @staticmethod
    def record_span_duration(span_name: str, duration_ms: float) -> None:
        """Record span duration as a metric."""
        from prometheus_client import Histogram

        SPAN_DURATION = Histogram(
            "catnet_span_duration_seconds",
            "Duration of traced operations",
            ["span_name"],
        )
        SPAN_DURATION.labels(span_name=span_name).observe(duration_ms / 1000)

    @staticmethod
    def record_span_error(span_name: str, error_type: str) -> None:
        """Record span errors as metrics."""
        from prometheus_client import Counter

        SPAN_ERRORS = Counter(
            "catnet_span_errors_total",
            "Total span errors",
            ["span_name", "error_type"],
        )
        SPAN_ERRORS.labels(span_name=span_name, error_type=error_type).inc()
