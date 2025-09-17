"""
API Configuration - CORS, Versioning, and Request Validation
"""
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import re
from datetime import datetime

from ..core.logging import get_logger

logger = get_logger(__name__)


class CORSConfig:
    """
    CORS configuration for production environment
    """

    def __init__(
        self,
        allowed_origins: List[str] = None,
        allowed_methods: List[str] = None,
        allowed_headers: List[str] = None,
        exposed_headers: List[str] = None,
        allow_credentials: bool = True,
        max_age: int = 86400,
    ):
        """
        Initialize CORS configuration

        Args:
            allowed_origins: List of allowed origins
            allowed_methods: List of allowed HTTP methods
            allowed_headers: List of allowed headers
            exposed_headers: List of headers to expose
            allow_credentials: Allow credentials in requests
            max_age: Max age for preflight cache
        """
        self.allowed_origins = allowed_origins or [
            "https://catnet.local",
            "https://api.catnet.local",
            "https://admin.catnet.local",
        ]

        # Add localhost for development (remove in production)
        if self._is_development():
            self.allowed_origins.extend(
                [
                    "http://localhost:3000",
                    "http://localhost:8080",
                    "http://127.0.0.1:3000",
                    "http://127.0.0.1:8080",
                ]
            )

        self.allowed_methods = allowed_methods or [
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "PATCH",
            "OPTIONS",
            "HEAD",
        ]

        self.allowed_headers = allowed_headers or [
            "Content-Type",
            "Authorization",
            "X-Request-ID",
            "X-CSRF-Token",
            "X-API-Version",
            "Accept",
            "Accept-Language",
            "Content-Language",
            "Cache-Control",
        ]

        self.exposed_headers = exposed_headers or [
            "X-Request-ID",
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "X-Total-Count",
            "Link",
            "Location",
        ]

        self.allow_credentials = allow_credentials
        self.max_age = max_age

    def _is_development(self) -> bool:
        """Check if running in development mode"""
        import os

        return os.getenv("ENVIRONMENT", "production").lower() in ["development", "dev"]

    def configure_cors(self, app):
        """Configure CORS for FastAPI application"""
        app.add_middleware(
            CORSMiddleware,
            allow_origins=self.allowed_origins,
            allow_credentials=self.allow_credentials,
            allow_methods=self.allowed_methods,
            allow_headers=self.allowed_headers,
            expose_headers=self.exposed_headers,
            max_age=self.max_age,
        )

        logger.info(f"CORS configured with {len(self.allowed_origins)} allowed origins")

    def is_origin_allowed(self, origin: str) -> bool:
        """Check if origin is allowed"""
        if not origin:
            return False

        # Check exact match
        if origin in self.allowed_origins:
            return True

        # Check wildcard patterns
        for allowed in self.allowed_origins:
            if "*" in allowed:
                pattern = allowed.replace("*", ".*")
                if re.match(pattern, origin):
                    return True

        return False


class APIVersioning:
    """
    API versioning implementation
    """

    def __init__(
        self,
        default_version: str = "v1",
        supported_versions: List[str] = None,
        deprecated_versions: List[str] = None,
        version_header: str = "X-API-Version",
    ):
        """
        Initialize API versioning

        Args:
            default_version: Default API version
            supported_versions: List of supported versions
            deprecated_versions: List of deprecated versions
            version_header: Header name for version
        """
        self.default_version = default_version
        self.supported_versions = supported_versions or ["v1", "v2"]
        self.deprecated_versions = deprecated_versions or []
        self.version_header = version_header
        self.version_routers: Dict[str, APIRouter] = {}

    def create_versioned_app(self, app):
        """Create versioned API structure"""
        for version in self.supported_versions:
            # Create router for each version
            router = APIRouter(
                prefix=f"/api/{version}",
                tags=[f"API {version}"],
                responses={
                    404: {"description": "Not found"},
                    429: {"description": "Rate limit exceeded"},
                    500: {"description": "Internal server error"},
                },
            )

            # Add deprecation warning for deprecated versions
            if version in self.deprecated_versions:
                router.add_event_handler(
                    "startup", self._log_deprecation_warning(version)
                )

            self.version_routers[version] = router
            app.include_router(router)

        # Add version middleware
        app.middleware("http")(self._version_middleware)

        logger.info(
            f"API versioning configured with versions: {self.supported_versions}"
        )

    def _log_deprecation_warning(self, version: str):
        """Log deprecation warning"""

        def log_warning():
            logger.warning(
                f"API version {version} is deprecated and will be removed in future releases"
            )

        return log_warning

    async def _version_middleware(self, request: Request, call_next):
        """Middleware to handle API versioning"""
        # Extract version from URL path
        path_parts = request.url.path.split("/")
        version = None

        if len(path_parts) > 2 and path_parts[1] == "api":
            version = path_parts[2]

        # Check header for version override
        header_version = request.headers.get(self.version_header)
        if header_version:
            version = header_version

        # Default to latest version if not specified
        if not version:
            version = self.default_version

        # Validate version
        if version not in self.supported_versions:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "error": f"Unsupported API version: {version}",
                    "supported_versions": self.supported_versions,
                },
            )

        # Add version to request state
        request.state.api_version = version

        # Add deprecation warning header if applicable
        response = await call_next(request)

        if version in self.deprecated_versions:
            response.headers["X-API-Deprecated"] = "true"
            response.headers["X-API-Sunset-Date"] = "2026-01-01"
            response.headers[
                "X-API-Migration-Guide"
            ] = "https://docs.catnet.local/api/migration"

        return response

    def get_router(self, version: str) -> APIRouter:
        """Get router for specific version"""
        return self.version_routers.get(version)


class RequestValidation:
    """
    Request validation and sanitization
    """

    # Common patterns for validation
    PATTERNS = {
        "uuid": re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        ),
        "ipv4": re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"),
        "ipv6": re.compile(r"^(?:[0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$"),
        "hostname": re.compile(
            r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
            r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
        ),
        "email": re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"),
        "alphanumeric": re.compile(r"^[a-zA-Z0-9]+$"),
        "safe_string": re.compile(r"^[a-zA-Z0-9\s\-_.,!?]+$"),
    }

    @classmethod
    def validate_uuid(cls, value: str) -> bool:
        """Validate UUID format"""
        return bool(cls.PATTERNS["uuid"].match(value))

    @classmethod
    def validate_ip(cls, value: str) -> bool:
        """Validate IP address (v4 or v6)"""
        return bool(
            cls.PATTERNS["ipv4"].match(value) or cls.PATTERNS["ipv6"].match(value)
        )

    @classmethod
    def validate_hostname(cls, value: str) -> bool:
        """Validate hostname"""
        return bool(cls.PATTERNS["hostname"].match(value))

    @classmethod
    def validate_email(cls, value: str) -> bool:
        """Validate email address"""
        return bool(cls.PATTERNS["email"].match(value))

    @classmethod
    def sanitize_input(cls, value: str, max_length: int = 1000) -> str:
        """
        Sanitize user input

        Args:
            value: Input value
            max_length: Maximum allowed length

        Returns:
            Sanitized value
        """
        if not value:
            return ""

        # Truncate to max length
        value = value[:max_length]

        # Remove null bytes
        value = value.replace("\x00", "")

        # Remove control characters
        value = "".join(char for char in value if ord(char) >= 32 or char in "\n\r\t")

        # Escape HTML entities
        value = (
            value.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )

        return value

    @classmethod
    def validate_request_size(cls, request: Request, max_size: int = 10485760):  # 10MB
        """Validate request body size"""
        content_length = request.headers.get("content-length")

        if content_length:
            if int(content_length) > max_size:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Request body too large. Maximum size: {max_size} bytes",
                )


class PaginationParams(BaseModel):
    """Standard pagination parameters"""

    page: int = Field(1, ge=1, le=10000, description="Page number")
    per_page: int = Field(20, ge=1, le=100, description="Items per page")
    sort_by: Optional[str] = Field(None, description="Sort field")
    sort_order: Optional[str] = Field(
        "asc", regex="^(asc|desc)$", description="Sort order"
    )

    def get_offset(self) -> int:
        """Calculate offset for database query"""
        return (self.page - 1) * self.per_page

    def get_limit(self) -> int:
        """Get limit for database query"""
        return self.per_page


class APIResponse(BaseModel):
    """Standard API response format"""

    success: bool = Field(True, description="Request success status")
    data: Optional[Any] = Field(None, description="Response data")
    error: Optional[str] = Field(None, description="Error message")
    message: Optional[str] = Field(None, description="Status message")
    timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="Response timestamp"
    )
    request_id: Optional[str] = Field(None, description="Request tracking ID")

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }


def configure_api(app, config: Dict[str, Any] = None):
    """
    Configure all API settings

    Args:
        app: FastAPI application
        config: API configuration
    """
    config = config or {}

    # Configure CORS
    cors_config = CORSConfig(
        allowed_origins=config.get("cors_origins"),
        allow_credentials=config.get("cors_credentials", True),
    )
    cors_config.configure_cors(app)

    # Configure API versioning
    versioning = APIVersioning(
        default_version=config.get("default_version", "v1"),
        supported_versions=config.get("supported_versions", ["v1", "v2"]),
        deprecated_versions=config.get("deprecated_versions", []),
    )
    versioning.create_versioned_app(app)

    logger.info("API configuration completed")
