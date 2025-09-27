"""
Security Middleware
Implements comprehensive security controls for all requests
"""

import time
import hashlib
import hmac
import secrets
import json
from typing import Callable, Optional, Dict, Any, List
from datetime import datetime, timedelta
import re
import xml.etree.ElementTree as ET
from xml.parsers.expat import ExpatError
import defusedxml.ElementTree as SafeET
from defusedxml.common import EntitiesForbidden, ExternalReferenceForbidden

from fastapi import Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import aioredis

from src.core.config import settings
from src.security.audit import AuditLogger
from src.db.models import SecurityIncident


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Comprehensive security middleware implementing:
    - CSRF protection
    - XSS prevention
    - SQL injection detection
    - Path traversal prevention
    - Command injection detection
    - Security headers
    - Request sanitization
    """

    def __init__(
        self,
        app: ASGIApp,
        redis_client: aioredis.Redis = None,
        audit_logger: AuditLogger = None
    ):
        super().__init__(app)
        self.redis = redis_client
        self.audit = audit_logger

        # Security patterns
        self.sql_injection_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE)\b)",
            r"(-{2}|\/\*|\*\/)",
            r"(;|\||&&)",
            r"(xp_|sp_|exec|execute)",
            r"(script|javascript|vbscript|onload|onerror|onclick)",
        ]

        self.path_traversal_patterns = [
            r"\.\./",
            r"\.\.",
            r"%2e%2e",
            r"\.\.\\",
            r"%252e%252e",
        ]

        self.command_injection_patterns = [
            r"[;&|`$]",
            r"\$\(",
            r"`.*`",
            r"\|{1,2}",
            r"&&",
        ]

        # Compile patterns for performance
        self.sql_regex = re.compile(
            "|".join(self.sql_injection_patterns),
            re.IGNORECASE
        )
        self.path_regex = re.compile(
            "|".join(self.path_traversal_patterns),
            re.IGNORECASE
        )
        self.cmd_regex = re.compile(
            "|".join(self.command_injection_patterns)
        )

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request through security checks
        """

        start_time = time.time()
        request_id = request.headers.get("X-Request-ID") or self._generate_request_id()

        # Store request ID for downstream use
        request.state.request_id = request_id

        try:
            # 1. Check if maintenance mode
            if await self._is_maintenance_mode():
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={"detail": "System under maintenance"},
                    headers={"Retry-After": "3600"}
                )

            # 2. Validate request method
            if not self._validate_method(request.method):
                await self._log_security_incident(
                    request,
                    "invalid_http_method",
                    {"method": request.method}
                )
                return JSONResponse(
                    status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
                    content={"detail": "Method not allowed"}
                )

            # 3. Check request size
            if not await self._validate_request_size(request):
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={"detail": "Request entity too large"}
                )

            # 4. Validate content type
            if request.method in ["POST", "PUT", "PATCH"]:
                if not self._validate_content_type(request):
                    return JSONResponse(
                        status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                        content={"detail": "Unsupported media type"}
                    )

            # 5. Check for malicious patterns
            security_check = await self._check_security_threats(request)
            if not security_check["safe"]:
                await self._log_security_incident(
                    request,
                    security_check["threat_type"],
                    security_check["details"]
                )

                # Block request
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"detail": "Security validation failed"}
                )

            # 6. CSRF protection for state-changing operations
            if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
                if not await self._validate_csrf_token(request):
                    await self._log_security_incident(
                        request,
                        "csrf_validation_failed",
                        {}
                    )
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content={"detail": "CSRF validation failed"}
                    )

            # 7. Check IP reputation
            client_ip = request.client.host
            if await self._is_ip_blocked(client_ip):
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Access denied"}
                )

            # Process request
            response = await call_next(request)

            # Add security headers
            response = self._add_security_headers(response, request_id)

            # Log request metrics
            process_time = time.time() - start_time
            await self._log_request_metrics(request, response, process_time)

            return response

        except Exception as e:
            # Log security error
            if self.audit:
                await self.audit.log_error(
                    error_type="security_middleware_error",
                    error_message=str(e),
                    context={
                        "request_id": request_id,
                        "path": str(request.url.path),
                        "method": request.method
                    }
                )

            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Internal server error"},
                headers={"X-Request-ID": request_id}
            )

    def _generate_request_id(self) -> str:
        """Generate unique request ID"""
        return f"req_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(8)}"

    async def _is_maintenance_mode(self) -> bool:
        """Check if system is in maintenance mode"""
        if self.redis:
            maintenance = await self.redis.get("system:maintenance")
            return maintenance is not None
        return False

    def _validate_method(self, method: str) -> bool:
        """Validate HTTP method"""
        allowed_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
        return method in allowed_methods

    async def _validate_request_size(self, request: Request) -> bool:
        """Validate request size"""
        content_length = request.headers.get("content-length")
        if content_length:
            max_size = settings.MAX_REQUEST_SIZE_BYTES  # Default 10MB
            return int(content_length) <= max_size
        return True

    def _validate_content_type(self, request: Request) -> bool:
        """Validate content type"""
        content_type = request.headers.get("content-type", "")
        allowed_types = [
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "text/plain"
        ]
        return any(allowed in content_type for allowed in allowed_types)

    async def _check_security_threats(self, request: Request) -> Dict[str, Any]:
        """
        Check for various security threats in request
        """

        # Check URL path
        path = str(request.url.path)
        query = str(request.url.query)

        # SQL Injection check
        if self.sql_regex.search(path) or self.sql_regex.search(query):
            return {
                "safe": False,
                "threat_type": "sql_injection",
                "details": {"path": path, "query": query}
            }

        # Path traversal check
        if self.path_regex.search(path):
            return {
                "safe": False,
                "threat_type": "path_traversal",
                "details": {"path": path}
            }

        # Command injection check
        if self.cmd_regex.search(query):
            return {
                "safe": False,
                "threat_type": "command_injection",
                "details": {"query": query}
            }

        # Check headers for injection
        suspicious_headers = []
        for header_name, header_value in request.headers.items():
            if self.sql_regex.search(header_value) or self.cmd_regex.search(header_value):
                suspicious_headers.append(header_name)

        if suspicious_headers:
            return {
                "safe": False,
                "threat_type": "header_injection",
                "details": {"headers": suspicious_headers}
            }

        # Check for XXE in XML content
        content_type = request.headers.get("content-type", "").lower()
        if "xml" in content_type:
            xxe_check = await self._check_xxe_vulnerabilities(request)
            if not xxe_check["safe"]:
                return {
                    "safe": False,
                    "threat_type": "xxe_attack",
                    "details": xxe_check["details"]
                }

        return {"safe": True, "threat_type": None, "details": {}}

    async def _validate_csrf_token(self, request: Request) -> bool:
        """
        Validate CSRF token for state-changing operations
        """

        # Skip CSRF for API endpoints with valid API key
        if request.headers.get("X-API-Key"):
            return True

        # Get CSRF token from header or form data
        csrf_token = request.headers.get("X-CSRF-Token")

        if not csrf_token:
            # Try to get from form data for form submissions
            if request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
                form = await request.form()
                csrf_token = form.get("csrf_token")

        if not csrf_token:
            return False

        # Validate token from session/redis
        if self.redis:
            session_id = request.cookies.get("session_id")
            if session_id:
                stored_token = await self.redis.get(f"csrf:{session_id}")
                return stored_token and stored_token.decode() == csrf_token

        return False

    async def _is_ip_blocked(self, ip_address: str) -> bool:
        """
        Check if IP address is blocked
        """

        if self.redis:
            # Check permanent blocklist
            blocked = await self.redis.sismember("blocked_ips", ip_address)
            if blocked:
                return True

            # Check temporary blocks (rate limiting, failed attempts)
            temp_block = await self.redis.get(f"ip_block:{ip_address}")
            if temp_block:
                return True

        return False

    def _add_security_headers(self, response: Response, request_id: str) -> Response:
        """
        Add comprehensive security headers to response
        """

        # Basic security headers
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), "
            "magnetometer=(), gyroscope=(), fullscreen=(self)"
        )

        # Content Security Policy
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )

        # Strict Transport Security (HSTS)
        if settings.ENVIRONMENT == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        # Remove sensitive headers
        headers_to_remove = ["Server", "X-Powered-By", "X-AspNet-Version"]
        for header in headers_to_remove:
            response.headers.pop(header, None)

        return response

    async def _log_security_incident(
        self,
        request: Request,
        incident_type: str,
        details: Dict[str, Any]
    ):
        """
        Log security incident
        """

        if self.audit:
            await self.audit.log_security_event(
                event_type=incident_type,
                severity="high",
                details={
                    "ip_address": request.client.host,
                    "path": str(request.url.path),
                    "method": request.method,
                    "user_agent": request.headers.get("user-agent"),
                    **details
                }
            )

        # Track IP for potential blocking
        if self.redis:
            ip_address = request.client.host
            incident_key = f"security_incidents:{ip_address}"

            await self.redis.incr(incident_key)
            await self.redis.expire(incident_key, 3600)  # 1 hour window

            # Auto-block after threshold
            incident_count = await self.redis.get(incident_key)
            if incident_count and int(incident_count) >= settings.SECURITY_INCIDENT_THRESHOLD:
                await self.redis.setex(
                    f"ip_block:{ip_address}",
                    3600,  # Block for 1 hour
                    "auto_blocked"
                )

    async def _log_request_metrics(
        self,
        request: Request,
        response: Response,
        process_time: float
    ):
        """
        Log request metrics for monitoring
        """

        if self.redis:
            # Store metrics in Redis for aggregation
            metrics = {
                "path": str(request.url.path),
                "method": request.method,
                "status_code": response.status_code,
                "process_time": process_time,
                "timestamp": datetime.utcnow().isoformat()
            }

            await self.redis.lpush(
                "request_metrics",
                json.dumps(metrics)
            )

            # Trim list to last 10000 entries
            await self.redis.ltrim("request_metrics", 0, 9999)

    async def _check_xxe_vulnerabilities(self, request: Request) -> Dict[str, Any]:
        """
        Check for XXE (XML External Entity) vulnerabilities in XML content
        """
        try:
            # Get request body
            body = await request.body()
            if not body:
                return {"safe": True, "details": {}}

            xml_content = body.decode('utf-8', errors='ignore')

            # Check for suspicious XML patterns
            xxe_patterns = [
                r'<!ENTITY[^>]*SYSTEM[^>]*>',  # External entity declarations
                r'<!ENTITY[^>]*PUBLIC[^>]*>',  # Public entity declarations
                r'<!DOCTYPE[^>]*\[[^\]]*ENTITY[^\]]*\]>',  # DTD with entities
                r'<!DOCTYPE[^>]*SYSTEM[^>]*>',  # External DTD
                r'<!DOCTYPE[^>]*PUBLIC[^>]*>',  # Public DTD
                r'&[a-zA-Z][a-zA-Z0-9]*;',     # Entity references
                r'%[a-zA-Z][a-zA-Z0-9]*;',     # Parameter entity references
                r'file://',                     # File protocol
                r'http://',                     # HTTP protocol in DTD
                r'https://',                    # HTTPS protocol in DTD
                r'ftp://',                      # FTP protocol
                r'gopher://',                   # Gopher protocol
                r'data:',                       # Data URI scheme
            ]

            suspicious_patterns = []
            for pattern in xxe_patterns:
                if re.search(pattern, xml_content, re.IGNORECASE):
                    suspicious_patterns.append(pattern)

            # If suspicious patterns found, perform deeper analysis
            if suspicious_patterns:
                # Try to parse with unsafe parser to detect actual XXE
                try:
                    # This is intentionally unsafe to detect XXE attempts
                    # We're just parsing, not executing
                    tree = ET.fromstring(xml_content)

                    # If it parses successfully with suspicious patterns, it's likely XXE
                    return {
                        "safe": False,
                        "details": {
                            "suspicious_patterns": suspicious_patterns,
                            "xml_content_preview": xml_content[:500],
                            "reason": "XML contains external entity references"
                        }
                    }
                except ET.ParseError:
                    # If parsing fails, check if it's due to XXE restrictions
                    pass
                except ExpatError:
                    # Expat parser error, likely due to malformed XML
                    pass

            # Try parsing with defusedxml (safe parser)
            try:
                # Use defusedxml to safely parse and detect XXE attempts
                SafeET.fromstring(xml_content)

                # Check for specific XXE indicators in content
                xxe_indicators = [
                    '<!ENTITY',
                    '<!DOCTYPE',
                    'SYSTEM "',
                    'PUBLIC "',
                    '&lt;!ENTITY',
                    '&lt;!DOCTYPE',
                    '%',  # Parameter entities
                    'CDATA['
                ]

                found_indicators = []
                for indicator in xxe_indicators:
                    if indicator.lower() in xml_content.lower():
                        found_indicators.append(indicator)

                if found_indicators:
                    # Additional checks for common XXE payloads
                    xxe_payloads = [
                        '/etc/passwd',
                        '/etc/shadow',
                        '/etc/hosts',
                        '/proc/version',
                        '/proc/self/environ',
                        'file:///etc/',
                        'file:///proc/',
                        'file:///dev/',
                        'file:///var/',
                        'c:\\windows\\',
                        'c:/windows/',
                        '..\\..\\..\\',
                        '../../../',
                    ]

                    found_payloads = []
                    for payload in xxe_payloads:
                        if payload.lower() in xml_content.lower():
                            found_payloads.append(payload)

                    if found_payloads:
                        return {
                            "safe": False,
                            "details": {
                                "xxe_indicators": found_indicators,
                                "xxe_payloads": found_payloads,
                                "xml_content_preview": xml_content[:500],
                                "reason": "XML contains potential XXE attack payloads"
                            }
                        }

                return {"safe": True, "details": {}}

            except EntitiesForbidden as e:
                # defusedxml detected forbidden entities
                return {
                    "safe": False,
                    "details": {
                        "error": str(e),
                        "xml_content_preview": xml_content[:500],
                        "reason": "XML contains forbidden entities (XXE attempt detected)"
                    }
                }
            except ExternalReferenceForbidden as e:
                # defusedxml detected external references
                return {
                    "safe": False,
                    "details": {
                        "error": str(e),
                        "xml_content_preview": xml_content[:500],
                        "reason": "XML contains external references (XXE attempt detected)"
                    }
                }
            except Exception as e:
                # Other XML parsing errors
                # Check if error message indicates XXE-related issues
                error_str = str(e).lower()
                xxe_error_indicators = [
                    'entity',
                    'external',
                    'dtd',
                    'system',
                    'public',
                    'forbidden'
                ]

                if any(indicator in error_str for indicator in xxe_error_indicators):
                    return {
                        "safe": False,
                        "details": {
                            "parse_error": str(e),
                            "xml_content_preview": xml_content[:500],
                            "reason": "XML parsing failed with XXE-related error"
                        }
                    }

                # If it's just a regular parsing error, continue
                pass

            # Additional heuristic checks
            # Check for encoded XXE attempts
            encoded_patterns = [
                '&lt;!ENTITY',
                '&lt;!DOCTYPE',
                '&#x3C;!ENTITY',
                '&#60;!ENTITY',
                '%3C!ENTITY',
                '%3C!DOCTYPE',
            ]

            found_encoded = []
            for pattern in encoded_patterns:
                if pattern.lower() in xml_content.lower():
                    found_encoded.append(pattern)

            if found_encoded:
                return {
                    "safe": False,
                    "details": {
                        "encoded_xxe_patterns": found_encoded,
                        "xml_content_preview": xml_content[:500],
                        "reason": "XML contains encoded XXE attack patterns"
                    }
                }

            # Check XML size - extremely large XML might be XXE billion laughs attack
            if len(xml_content) > 1024 * 1024:  # 1MB
                # Count entity references
                entity_refs = len(re.findall(r'&[a-zA-Z][a-zA-Z0-9]*;', xml_content))
                if entity_refs > 100:  # Arbitrary threshold
                    return {
                        "safe": False,
                        "details": {
                            "xml_size": len(xml_content),
                            "entity_references": entity_refs,
                            "reason": "XML contains excessive entity references (potential billion laughs attack)"
                        }
                    }

            return {"safe": True, "details": {}}

        except UnicodeDecodeError:
            # Can't decode request body as UTF-8
            return {
                "safe": False,
                "details": {
                    "reason": "Request body contains invalid UTF-8 encoding"
                }
            }
        except Exception as e:
            # Log unexpected error but don't block request
            if self.audit:
                await self.audit.log_error(
                    error_type="xxe_check_error",
                    error_message=str(e),
                    context={"path": str(request.url.path)}
                )

            # On error, allow request but log it
            return {"safe": True, "details": {"check_error": str(e)}}


class SecurityHeadersMiddleware:
    """
    Lightweight middleware for adding security headers only
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    @staticmethod
    def is_xxe_safe_xml(xml_content: str) -> bool:
        """
        Static method to check if XML content is safe from XXE attacks
        """
        try:
            # Use defusedxml for safe parsing
            SafeET.fromstring(xml_content)

            # Additional pattern checks
            dangerous_patterns = [
                r'<!ENTITY[^>]*SYSTEM[^>]*>',
                r'<!ENTITY[^>]*PUBLIC[^>]*>',
                r'<!DOCTYPE[^>]*\[[^\]]*ENTITY[^\]]*\]>',
                r'&[a-zA-Z][a-zA-Z0-9]*;',
                r'%[a-zA-Z][a-zA-Z0-9]*;',
                r'file://',
                r'http://.*\.dtd',
                r'https://.*\.dtd'
            ]

            for pattern in dangerous_patterns:
                if re.search(pattern, xml_content, re.IGNORECASE):
                    return False

            return True

        except (EntitiesForbidden, ExternalReferenceForbidden):
            return False
        except Exception:
            return False

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))

                # Add security headers
                security_headers = [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"x-xss-protection", b"1; mode=block"),
                    (b"referrer-policy", b"strict-origin-when-cross-origin"),
                ]

                for header_name, header_value in security_headers:
                    if header_name not in headers:
                        message["headers"].append((header_name, header_value))

            await send(message)

        await self.app(scope, receive, send_wrapper)