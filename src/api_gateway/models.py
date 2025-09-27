"""
Data models for API gateway.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any, Union
from enum import Enum
import uuid

from pydantic import BaseModel, Field, validator, HttpUrl


class ServiceType(str, Enum):
    """Service types."""
    AUTHENTICATION = "authentication"
    GITOPS = "gitops"
    DEPLOYMENT = "deployment"
    DEVICE = "device"
    MONITORING = "monitoring"
    INTERNAL = "internal"
    EXTERNAL = "external"


class LoadBalancerStrategy(str, Enum):
    """Load balancer strategies."""
    ROUND_ROBIN = "round_robin"
    LEAST_CONNECTIONS = "least_connections"
    WEIGHTED_ROUND_ROBIN = "weighted_round_robin"
    IP_HASH = "ip_hash"
    RANDOM = "random"
    CONSISTENT_HASH = "consistent_hash"


class HealthCheckType(str, Enum):
    """Health check types."""
    HTTP = "http"
    HTTPS = "https"
    TCP = "tcp"
    GRPC = "grpc"
    EXEC = "exec"


class CircuitState(str, Enum):
    """Circuit breaker states."""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class RateLimitType(str, Enum):
    """Rate limit types."""
    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"
    LEAKY_BUCKET = "leaky_bucket"


class CacheStrategy(str, Enum):
    """Cache strategies."""
    TTL = "ttl"
    LRU = "lru"
    LFU = "lfu"
    FIFO = "fifo"


class AuthenticationType(str, Enum):
    """Authentication types."""
    JWT = "jwt"
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    SAML = "saml"
    MTLS = "mtls"
    BASIC = "basic"
    CUSTOM = "custom"


class GatewayRequest(BaseModel):
    """Gateway request model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    method: str
    path: str
    headers: Dict[str, str] = {}
    query_params: Dict[str, str] = {}
    body: Optional[Union[str, Dict[str, Any]]] = None
    client_ip: str
    user_agent: Optional[str] = None
    auth_token: Optional[str] = None
    api_key: Optional[str] = None
    session_id: Optional[str] = None
    trace_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    span_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    timeout: int = 30  # seconds
    retry_count: int = 0
    metadata: Dict[str, Any] = {}


class GatewayResponse(BaseModel):
    """Gateway response model."""
    status_code: int
    headers: Dict[str, str] = {}
    body: Optional[Union[str, Dict[str, Any]]] = None
    error: Optional[str] = None
    latency_ms: Optional[float] = None
    cached: bool = False
    cache_key: Optional[str] = None
    service_name: Optional[str] = None
    service_endpoint: Optional[str] = None
    trace_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ServiceEndpoint(BaseModel):
    """Service endpoint model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_name: str
    url: str
    host: str
    port: int
    path: Optional[str] = "/"
    protocol: str = "https"
    weight: int = 1
    healthy: bool = True
    last_health_check: Optional[datetime] = None
    response_time_ms: Optional[float] = None
    success_rate: float = 100.0
    metadata: Dict[str, Any] = {}


class ServiceRegistration(BaseModel):
    """Service registration model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    type: ServiceType
    version: str
    endpoints: List[ServiceEndpoint]
    health_check: Optional['HealthCheckConfig'] = None
    load_balancer: LoadBalancerStrategy = LoadBalancerStrategy.ROUND_ROBIN
    circuit_breaker: Optional['CircuitBreakerConfig'] = None
    retry_policy: Optional['RetryConfig'] = None
    timeout: int = 30
    tags: List[str] = []
    metadata: Dict[str, Any] = {}
    registered_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class HealthCheckConfig(BaseModel):
    """Health check configuration."""
    type: HealthCheckType
    endpoint: str
    interval: int = 30  # seconds
    timeout: int = 10
    healthy_threshold: int = 2
    unhealthy_threshold: int = 3
    expected_status: Optional[List[int]] = [200, 204]
    expected_body: Optional[str] = None
    headers: Dict[str, str] = {}


class CircuitBreakerConfig(BaseModel):
    """Circuit breaker configuration."""
    failure_threshold: int = 5
    success_threshold: int = 2
    timeout: int = 60  # seconds
    half_open_requests: int = 3
    error_codes: List[int] = [500, 502, 503, 504]
    exclude_codes: List[int] = []


class RetryConfig(BaseModel):
    """Retry configuration."""
    max_attempts: int = 3
    initial_delay_ms: int = 100
    max_delay_ms: int = 10000
    exponential_base: float = 2
    retry_on_codes: List[int] = [502, 503, 504]
    retry_on_methods: List[str] = ["GET", "HEAD", "OPTIONS"]


class RouteRule(BaseModel):
    """Route rule model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    priority: int = 100
    path_pattern: str  # Regex or glob pattern
    methods: List[str] = ["*"]
    service: str
    rewrite_path: Optional[str] = None
    add_headers: Dict[str, str] = {}
    remove_headers: List[str] = []
    add_query_params: Dict[str, str] = {}
    strip_path: bool = False
    preserve_host: bool = False
    timeout_override: Optional[int] = None
    is_enabled: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = {}


class RateLimitRule(BaseModel):
    """Rate limit rule model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    type: RateLimitType
    limit: int  # requests
    window: int  # seconds
    burst: Optional[int] = None  # burst allowance
    key_by: str = "client_ip"  # client_ip, user_id, api_key, custom
    path_pattern: Optional[str] = None
    methods: List[str] = ["*"]
    apply_to: str = "all"  # all, authenticated, unauthenticated
    exclude_paths: List[str] = []
    custom_key_extractor: Optional[str] = None
    response_headers: bool = True  # Include rate limit headers in response
    is_enabled: bool = True


class CacheRule(BaseModel):
    """Cache rule model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    strategy: CacheStrategy
    ttl: int = 300  # seconds
    max_size: Optional[int] = None
    path_pattern: str
    methods: List[str] = ["GET", "HEAD"]
    vary_by_headers: List[str] = []
    vary_by_query_params: List[str] = []
    vary_by_auth: bool = False
    ignore_query_params: List[str] = []
    cache_control_override: Optional[str] = None
    is_enabled: bool = True


class SecurityRule(BaseModel):
    """Security rule model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    type: str  # ip_whitelist, ip_blacklist, geo_block, waf, etc.
    action: str  # allow, deny, challenge
    conditions: List[Dict[str, Any]]
    priority: int = 100
    path_pattern: Optional[str] = None
    methods: List[str] = ["*"]
    custom_response: Optional[Dict[str, Any]] = None
    log_level: str = "info"
    is_enabled: bool = True


class TransformRule(BaseModel):
    """Transform rule model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    type: str  # request, response
    path_pattern: str
    transformations: List[Dict[str, Any]]
    priority: int = 100
    is_enabled: bool = True


class ProxyConfig(BaseModel):
    """Proxy configuration."""
    forward_headers: List[str] = ["X-Real-IP", "X-Forwarded-For", "X-Forwarded-Proto"]
    trust_proxy: bool = True
    proxy_protocol: bool = False
    preserve_host_header: bool = True
    add_x_forwarded_headers: bool = True
    upstream_timeout: int = 30
    upstream_keepalive: int = 60
    max_request_body_size: int = 10485760  # 10MB
    buffer_request: bool = True
    buffer_response: bool = True


class GatewayConfig(BaseModel):
    """Gateway configuration model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "CatNet API Gateway"
    version: str = "1.0.0"
    host: str = "0.0.0.0"
    port: int = 8080
    ssl_enabled: bool = True
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    ssl_ca: Optional[str] = None
    workers: int = 4
    max_connections: int = 10000
    request_timeout: int = 30
    keepalive_timeout: int = 60
    graceful_shutdown_timeout: int = 30
    proxy_config: ProxyConfig = Field(default_factory=ProxyConfig)
    cors_enabled: bool = True
    cors_origins: List[str] = ["https://catnet.local"]
    cors_methods: List[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    cors_headers: List[str] = ["*"]
    cors_credentials: bool = True
    compression_enabled: bool = True
    compression_min_size: int = 1024
    compression_types: List[str] = ["text/html", "text/css", "application/javascript", "application/json"]
    metrics_enabled: bool = True
    metrics_path: str = "/metrics"
    health_path: str = "/health"
    ready_path: str = "/ready"
    admin_enabled: bool = True
    admin_path: str = "/admin"
    admin_auth_required: bool = True
    log_level: str = "info"
    log_format: str = "json"
    audit_log_enabled: bool = True
    trace_enabled: bool = True
    trace_sample_rate: float = 0.1


class ServiceMetrics(BaseModel):
    """Service metrics model."""
    service_name: str
    total_requests: int
    success_count: int
    error_count: int
    avg_response_time_ms: float
    p50_response_time_ms: float
    p95_response_time_ms: float
    p99_response_time_ms: float
    requests_per_second: float
    error_rate: float
    success_rate: float
    active_connections: int
    circuit_breaker_state: Optional[str] = None
    last_updated: datetime = Field(default_factory=datetime.utcnow)


class GatewayMetrics(BaseModel):
    """Gateway metrics model."""
    total_requests: int
    success_count: int
    error_count: int
    cache_hits: int
    cache_misses: int
    rate_limited_requests: int
    blocked_requests: int
    avg_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    requests_per_second: float
    active_connections: int
    service_metrics: Dict[str, ServiceMetrics] = {}
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class RateLimitStatus(BaseModel):
    """Rate limit status model."""
    key: str
    limit: int
    remaining: int
    reset_time: datetime
    retry_after: Optional[int] = None  # seconds


class AuthenticationResult(BaseModel):
    """Authentication result model."""
    authenticated: bool
    user_id: Optional[str] = None
    username: Optional[str] = None
    roles: List[str] = []
    permissions: List[str] = []
    session_id: Optional[str] = None
    token_expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = {}


class AuthorizationResult(BaseModel):
    """Authorization result model."""
    authorized: bool
    required_permissions: List[str] = []
    user_permissions: List[str] = []
    missing_permissions: List[str] = []
    reason: Optional[str] = None


class ValidationError(BaseModel):
    """Validation error model."""
    field: str
    message: str
    code: str
    value: Optional[Any] = None


class ErrorResponse(BaseModel):
    """Error response model."""
    error: str
    message: str
    status_code: int
    trace_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    details: Optional[List[ValidationError]] = None


class AdminRequest(BaseModel):
    """Admin API request model."""
    action: str  # reload, refresh, purge_cache, etc.
    target: Optional[str] = None
    parameters: Dict[str, Any] = {}
    force: bool = False


class AdminResponse(BaseModel):
    """Admin API response model."""
    success: bool
    action: str
    message: str
    result: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)