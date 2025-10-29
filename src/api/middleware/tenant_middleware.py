"""
Tenant Middleware
Enforces tenant isolation and context management
"""
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Optional
import structlog

logger = structlog.get_logger()


class TenantMiddleware(BaseHTTPMiddleware):
    """
    Enforces tenant isolation and context management

    Features:
    - Extracts tenant context from JWT or headers
    - Validates tenant exists and is active
    - Enforces tenant isolation at middleware level
    - Tracks tenant for audit logging
    - Validates resource quotas
    """

    def __init__(self, app):
        super().__init__(app)
        self.public_paths = [
            "/api/v1/health",
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/docs",
            "/openapi.json",
            "/metrics"
        ]

    async def dispatch(self, request: Request, call_next):
        """Process request with tenant context"""

        # Skip tenant check for public paths
        if self._is_public_path(request.url.path):
            return await call_next(request)

        # Extract tenant context
        tenant_id = await self._extract_tenant_id(request)

        if tenant_id:
            # Validate tenant
            is_valid, error_message = await self._validate_tenant(tenant_id)

            if not is_valid:
                logger.warning(
                    "Invalid tenant access attempt",
                    tenant_id=tenant_id,
                    error=error_message,
                    path=request.url.path
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=error_message or "Invalid tenant"
                )

            # Store tenant context in request state
            request.state.tenant_id = tenant_id

            # Log tenant access
            logger.debug(
                "Tenant context set",
                tenant_id=tenant_id,
                path=request.url.path,
                method=request.method
            )
        else:
            # No tenant context (might be admin/system request)
            request.state.tenant_id = None

        # Process request
        response = await call_next(request)

        # Add tenant ID to response headers for debugging
        if tenant_id:
            response.headers["X-Tenant-ID"] = tenant_id

        return response

    def _is_public_path(self, path: str) -> bool:
        """Check if path is public (no tenant required)"""
        return any(path.startswith(public) for public in self.public_paths)

    async def _extract_tenant_id(self, request: Request) -> Optional[str]:
        """
        Extract tenant ID from request

        Priority:
        1. X-Tenant-ID header
        2. User's default tenant from JWT
        3. Subdomain (if using subdomain-based tenancy)
        """
        # Check header first
        tenant_id = request.headers.get("X-Tenant-ID")
        if tenant_id:
            return tenant_id

        # Extract from authenticated user
        if hasattr(request.state, "user") and request.state.user:
            user = request.state.user

            # User might have default tenant
            if hasattr(user, "default_tenant_id"):
                return user.default_tenant_id

            # Or get from TenantUser relationship
            if hasattr(user, "tenant_memberships") and user.tenant_memberships:
                # Use first active membership
                active_memberships = [
                    tm for tm in user.tenant_memberships
                    if tm.enabled
                ]
                if active_memberships:
                    return active_memberships[0].tenant_id

        # Extract from subdomain (e.g., acme.catnet.io)
        host = request.headers.get("host", "")
        if "." in host:
            subdomain = host.split(".")[0]
            # Look up tenant by subdomain/slug
            tenant_id = await self._get_tenant_by_slug(subdomain)
            if tenant_id:
                return tenant_id

        return None

    async def _validate_tenant(self, tenant_id: str) -> tuple[bool, Optional[str]]:
        """
        Validate tenant is active and accessible

        Returns:
            Tuple of (is_valid, error_message)
        """
        from src.db.session import get_db
        from src.db.models.tenant import Tenant

        try:
            async with get_db() as db:
                tenant = await db.query(Tenant).filter(
                    Tenant.id == tenant_id
                ).first()

                if not tenant:
                    return False, f"Tenant {tenant_id} not found"

                if not tenant.enabled:
                    return False, "Tenant is disabled"

                if tenant.locked:
                    return False, f"Tenant is locked: {tenant.lock_reason or 'No reason provided'}"

                # Check subscription expiry
                if tenant.subscription_expires_at:
                    from datetime import datetime
                    if datetime.utcnow() > tenant.subscription_expires_at:
                        return False, "Tenant subscription has expired"

                return True, None

        except Exception as e:
            logger.error(f"Error validating tenant {tenant_id}", error=str(e))
            return False, "Error validating tenant"

    async def _get_tenant_by_slug(self, slug: str) -> Optional[str]:
        """Get tenant ID by slug/subdomain"""
        from src.db.session import get_db
        from src.db.models.tenant import Tenant

        try:
            async with get_db() as db:
                tenant = await db.query(Tenant).filter(
                    Tenant.slug == slug,
                    Tenant.enabled == True
                ).first()

                return tenant.id if tenant else None

        except Exception as e:
            logger.error(f"Error looking up tenant by slug {slug}", error=str(e))
            return None


class TenantResourceQuotaMiddleware(BaseHTTPMiddleware):
    """
    Enforces tenant resource quotas

    Checks API rate limits and resource quotas before processing requests.
    """

    def __init__(self, app):
        super().__init__(app)
        self.quota_exempt_paths = [
            "/api/v1/health",
            "/metrics",
            "/docs"
        ]

    async def dispatch(self, request: Request, call_next):
        """Check quotas before processing request"""

        # Skip quota check for exempt paths
        if self._is_exempt_path(request.url.path):
            return await call_next(request)

        # Get tenant ID from request state (set by TenantMiddleware)
        tenant_id = getattr(request.state, "tenant_id", None)

        if tenant_id:
            # Check API rate limit
            can_proceed, error_message = await self._check_api_quota(tenant_id)

            if not can_proceed:
                logger.warning(
                    "Tenant quota exceeded",
                    tenant_id=tenant_id,
                    path=request.url.path
                )
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=error_message
                )

            # Increment API call counter
            await self._increment_api_calls(tenant_id)

        # Process request
        response = await call_next(request)

        return response

    def _is_exempt_path(self, path: str) -> bool:
        """Check if path is exempt from quota enforcement"""
        return any(path.startswith(exempt) for exempt in self.quota_exempt_paths)

    async def _check_api_quota(self, tenant_id: str) -> tuple[bool, Optional[str]]:
        """
        Check if tenant has remaining API quota

        Returns:
            Tuple of (can_proceed, error_message)
        """
        from src.db.session import get_db
        from src.db.models.tenant import Tenant, TenantResourceQuota
        from datetime import datetime, timedelta

        try:
            async with get_db() as db:
                # Get tenant
                tenant = await db.query(Tenant).filter(
                    Tenant.id == tenant_id
                ).first()

                if not tenant:
                    return False, "Tenant not found"

                # Get or create API quota for current hour
                now = datetime.utcnow()
                hour_start = now.replace(minute=0, second=0, microsecond=0)
                hour_end = hour_start + timedelta(hours=1)

                quota = await db.query(TenantResourceQuota).filter(
                    TenantResourceQuota.tenant_id == tenant_id,
                    TenantResourceQuota.resource_type == "api_calls",
                    TenantResourceQuota.period_start == hour_start
                ).first()

                if not quota:
                    # Create new quota for this hour
                    quota = TenantResourceQuota(
                        tenant_id=tenant_id,
                        resource_type="api_calls",
                        quota_limit=tenant.max_api_calls_per_hour,
                        current_usage=0,
                        period_start=hour_start,
                        period_end=hour_end
                    )
                    db.add(quota)
                    await db.commit()

                # Check if quota exceeded
                if quota.is_exceeded():
                    return False, f"API quota exceeded. Limit: {quota.quota_limit}/hour. Try again at {hour_end.isoformat()}"

                return True, None

        except Exception as e:
            logger.error(f"Error checking API quota for tenant {tenant_id}", error=str(e))
            # Fail open - allow request if quota check fails
            return True, None

    async def _increment_api_calls(self, tenant_id: str):
        """Increment API call counter for tenant"""
        from src.db.session import get_db
        from src.db.models.tenant import TenantResourceQuota
        from datetime import datetime

        try:
            async with get_db() as db:
                now = datetime.utcnow()
                hour_start = now.replace(minute=0, second=0, microsecond=0)

                quota = await db.query(TenantResourceQuota).filter(
                    TenantResourceQuota.tenant_id == tenant_id,
                    TenantResourceQuota.resource_type == "api_calls",
                    TenantResourceQuota.period_start == hour_start
                ).first()

                if quota:
                    quota.current_usage += 1

                    # Mark as exceeded if limit reached
                    if quota.current_usage >= quota.quota_limit and not quota.quota_exceeded:
                        quota.quota_exceeded = True
                        quota.exceeded_at = datetime.utcnow()

                    await db.commit()

        except Exception as e:
            logger.error(f"Error incrementing API calls for tenant {tenant_id}", error=str(e))


class TenantAuditMiddleware(BaseHTTPMiddleware):
    """
    Logs tenant actions for audit trail

    Records significant actions in the tenant audit log.
    """

    def __init__(self, app):
        super().__init__(app)
        self.audited_methods = ["POST", "PUT", "PATCH", "DELETE"]

    async def dispatch(self, request: Request, call_next):
        """Log request to audit trail"""

        # Process request
        response = await call_next(request)

        # Log audit entry for write operations
        if request.method in self.audited_methods:
            tenant_id = getattr(request.state, "tenant_id", None)
            user_id = None

            if hasattr(request.state, "user") and request.state.user:
                user_id = request.state.user.id

            if tenant_id and user_id:
                await self._create_audit_log(
                    tenant_id=tenant_id,
                    user_id=user_id,
                    action=request.method.lower(),
                    path=request.url.path,
                    success=response.status_code < 400,
                    ip_address=request.client.host if request.client else None,
                    user_agent=request.headers.get("user-agent")
                )

        return response

    async def _create_audit_log(
        self,
        tenant_id: str,
        user_id: str,
        action: str,
        path: str,
        success: bool,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ):
        """Create audit log entry"""
        from src.db.session import get_db
        from src.db.models.tenant import TenantAuditLog

        try:
            async with get_db() as db:
                # Extract resource type and ID from path
                resource_type, resource_id = self._extract_resource_from_path(path)

                audit_log = TenantAuditLog(
                    tenant_id=tenant_id,
                    user_id=user_id,
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    success=success
                )

                db.add(audit_log)
                await db.commit()

        except Exception as e:
            logger.error(
                "Error creating audit log",
                tenant_id=tenant_id,
                error=str(e)
            )

    def _extract_resource_from_path(self, path: str) -> tuple[Optional[str], Optional[str]]:
        """Extract resource type and ID from API path"""
        # e.g., /api/v1/devices/device-123 -> ("devices", "device-123")
        parts = path.split("/")

        if len(parts) >= 4:
            resource_type = parts[3]  # After /api/v1/
            resource_id = parts[4] if len(parts) >= 5 else None
            return resource_type, resource_id

        return None, None
