from typing import Dict, Any, Optional
import time
import uuid
import structlog
from datetime import datetime

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from ...security.audit import AuditLogger
from ...core.exceptions import AuditError

logger = structlog.get_logger()

class AuditMiddleware(BaseHTTPMiddleware):
    """Audit middleware for comprehensive request/response logging"""

    def __init__(self, app):
        super().__init__(app)
        self.audit = AuditLogger()

        # Sensitive data patterns to redact
        self.sensitive_patterns = [
            'password', 'secret', 'token', 'key', 'credential',
            'auth', 'session', 'cookie', 'signature'
        ]

        # Endpoints that should be audited more thoroughly
        self.high_value_endpoints = [
            '/api/v1/deployments',
            '/api/v1/devices',
            '/api/v1/admin',
            '/api/v1/auth'
        ]

    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        request_id = getattr(request.state, 'request_id', str(uuid.uuid4()))

        # Extract request information
        request_info = await self._extract_request_info(request)

        try:
            # Process the request
            response = await call_next(request)

            # Calculate processing time
            process_time = time.time() - start_time

            # Extract response information
            response_info = self._extract_response_info(response)

            # Log the audit event
            await self._log_audit_event(
                request_id=request_id,
                request_info=request_info,
                response_info=response_info,
                process_time=process_time,
                success=True
            )

            return response

        except Exception as e:
            # Log failed request
            process_time = time.time() - start_time

            await self._log_audit_event(
                request_id=request_id,
                request_info=request_info,
                response_info={'error': str(e)},
                process_time=process_time,
                success=False
            )

            raise

    async def _extract_request_info(self, request: Request) -> Dict[str, Any]:
        """Extract relevant information from the request"""
        try:
            request_info = {
                'method': request.method,
                'url': str(request.url),
                'path': request.url.path,
                'query_params': dict(request.query_params),
                'headers': self._sanitize_headers(dict(request.headers)),
                'client_ip': request.client.host if request.client else 'unknown',
                'user_agent': request.headers.get('user-agent', 'unknown'),
                'timestamp': datetime.utcnow().isoformat(),
                'content_type': request.headers.get('content-type'),
                'content_length': request.headers.get('content-length')
            }

            # Add user information if available
            if hasattr(request.state, 'user') and request.state.user:
                request_info['user_id'] = request.state.user.get('sub')
                request_info['user_email'] = request.state.user.get('email')
                request_info['user_roles'] = request.state.user.get('roles', [])

            # Add request body for certain endpoints (with sanitization)
            if (request.method in ['POST', 'PUT', 'PATCH'] and
                any(endpoint in request.url.path for endpoint in self.high_value_endpoints)):

                try:
                    # Only log JSON bodies to avoid binary data
                    content_type = request.headers.get('content-type', '')
                    if 'application/json' in content_type:
                        body = await self._get_request_body(request)
                        if body:
                            request_info['body'] = self._sanitize_body(body)
                except Exception as e:
                    logger.warning(f"Failed to extract request body: {e}")
                    request_info['body_extraction_error'] = str(e)

            return request_info

        except Exception as e:
            logger.error(f"Failed to extract request info: {e}")
            return {
                'method': request.method,
                'path': request.url.path,
                'error': 'Failed to extract request info',
                'timestamp': datetime.utcnow().isoformat()
            }

    def _extract_response_info(self, response: Response) -> Dict[str, Any]:
        """Extract relevant information from the response"""
        return {
            'status_code': response.status_code,
            'headers': self._sanitize_headers(dict(response.headers)),
            'content_type': response.headers.get('content-type'),
            'content_length': response.headers.get('content-length')
        }

    def _sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Sanitize headers by redacting sensitive information"""
        sanitized = {}

        for key, value in headers.items():
            key_lower = key.lower()

            # Redact sensitive headers
            if any(pattern in key_lower for pattern in self.sensitive_patterns):
                sanitized[key] = '[REDACTED]'
            else:
                sanitized[key] = value

        return sanitized

    async def _get_request_body(self, request: Request) -> Optional[str]:
        """Safely extract request body"""
        try:
            # Check if body was already read
            if hasattr(request, '_body'):
                return request._body.decode('utf-8')

            # Read body (this consumes the stream)
            body = await request.body()

            # Store for potential reuse
            request._body = body

            return body.decode('utf-8') if body else None

        except Exception as e:
            logger.warning(f"Failed to read request body: {e}")
            return None

    def _sanitize_body(self, body: str) -> Dict[str, Any]:
        """Sanitize request body by redacting sensitive fields"""
        try:
            import json

            # Parse JSON body
            data = json.loads(body)

            # Recursively sanitize
            sanitized = self._sanitize_dict(data)

            return sanitized

        except json.JSONDecodeError:
            # Return truncated string for non-JSON bodies
            return {'raw_body': body[:500] + '...' if len(body) > 500 else body}
        except Exception as e:
            return {'sanitization_error': str(e)}

    def _sanitize_dict(self, data: Any) -> Any:
        """Recursively sanitize dictionary data"""
        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                key_lower = key.lower()

                # Redact sensitive fields
                if any(pattern in key_lower for pattern in self.sensitive_patterns):
                    sanitized[key] = '[REDACTED]'
                else:
                    sanitized[key] = self._sanitize_dict(value)

            return sanitized

        elif isinstance(data, list):
            return [self._sanitize_dict(item) for item in data]

        else:
            return data

    async def _log_audit_event(
        self,
        request_id: str,
        request_info: Dict[str, Any],
        response_info: Dict[str, Any],
        process_time: float,
        success: bool
    ):
        """Log comprehensive audit event"""
        try:
            audit_data = {
                'event_type': 'api_request',
                'request_id': request_id,
                'timestamp': datetime.utcnow().isoformat(),
                'success': success,
                'process_time_seconds': round(process_time, 4),
                'request': request_info,
                'response': response_info
            }

            # Determine audit level based on endpoint and outcome
            audit_level = self._determine_audit_level(request_info, response_info, success)

            # Log to audit system
            await self.audit.log_api_request(
                request_id=request_id,
                method=request_info.get('method'),
                path=request_info.get('path'),
                status_code=response_info.get('status_code'),
                user_id=request_info.get('user_id'),
                client_ip=request_info.get('client_ip'),
                process_time=process_time,
                success=success,
                audit_level=audit_level,
                details=audit_data
            )

            # Log security-relevant events with higher priority
            if self._is_security_relevant(request_info, response_info):
                await self.audit.log_security_event(
                    event_type='security_api_access',
                    severity='medium' if success else 'high',
                    details=audit_data
                )

            # Log to structured logging
            log_level = 'info' if success else 'warning'
            getattr(logger, log_level)(
                f"API request {request_info.get('method')} {request_info.get('path')}",
                request_id=request_id,
                status_code=response_info.get('status_code'),
                process_time=process_time,
                user_id=request_info.get('user_id'),
                client_ip=request_info.get('client_ip')
            )

        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
            # Don't raise exception to avoid breaking the request flow

    def _determine_audit_level(
        self,
        request_info: Dict[str, Any],
        response_info: Dict[str, Any],
        success: bool
    ) -> str:
        """Determine the appropriate audit level for this request"""

        path = request_info.get('path', '')
        method = request_info.get('method', '')
        status_code = response_info.get('status_code', 200)

        # High audit level for critical operations
        if any(endpoint in path for endpoint in ['/api/v1/admin', '/api/v1/auth/login']):
            return 'high'

        # High audit level for deployment operations
        if '/api/v1/deployments' in path and method in ['POST', 'PUT', 'DELETE']:
            return 'high'

        # High audit level for device management
        if '/api/v1/devices' in path and method in ['POST', 'PUT', 'DELETE']:
            return 'high'

        # High audit level for failed requests
        if not success or status_code >= 400:
            return 'high'

        # Medium audit level for state-changing operations
        if method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            return 'medium'

        # Low audit level for read operations
        return 'low'

    def _is_security_relevant(
        self,
        request_info: Dict[str, Any],
        response_info: Dict[str, Any]
    ) -> bool:
        """Determine if this request is security-relevant"""

        path = request_info.get('path', '')
        method = request_info.get('method', '')
        status_code = response_info.get('status_code', 200)

        # Authentication and authorization endpoints
        if any(endpoint in path for endpoint in ['/api/v1/auth', '/api/v1/admin']):
            return True

        # Failed authentication attempts
        if status_code in [401, 403]:
            return True

        # Administrative operations
        if '/api/v1/admin' in path:
            return True

        # Device access and management
        if '/api/v1/devices' in path and method in ['POST', 'PUT', 'DELETE']:
            return True

        # Deployment operations
        if '/api/v1/deployments' in path and method in ['POST', 'PUT', 'DELETE']:
            return True

        return False

class PerformanceAuditMiddleware(BaseHTTPMiddleware):
    """Lightweight middleware focused on performance metrics"""

    def __init__(self, app):
        super().__init__(app)
        self.audit = AuditLogger()

        # Performance thresholds (in seconds)
        self.slow_request_threshold = 2.0
        self.very_slow_request_threshold = 5.0

    async def dispatch(self, request: Request, call_next):
        start_time = time.time()

        # Add performance tracking to request state
        request.state.start_time = start_time

        try:
            response = await call_next(request)

            # Calculate processing time
            process_time = time.time() - start_time

            # Log performance metrics
            await self._log_performance_metrics(
                request=request,
                response=response,
                process_time=process_time
            )

            # Add performance header
            response.headers['X-Process-Time'] = str(round(process_time, 4))

            return response

        except Exception as e:
            process_time = time.time() - start_time

            # Log failed request performance
            await self._log_performance_metrics(
                request=request,
                response=None,
                process_time=process_time,
                error=str(e)
            )

            raise

    async def _log_performance_metrics(
        self,
        request: Request,
        response: Optional[Response],
        process_time: float,
        error: Optional[str] = None
    ):
        """Log performance metrics"""
        try:
            metrics = {
                'path': request.url.path,
                'method': request.method,
                'process_time': round(process_time, 4),
                'timestamp': datetime.utcnow().isoformat(),
                'client_ip': request.client.host if request.client else 'unknown'
            }

            if response:
                metrics['status_code'] = response.status_code
                metrics['content_length'] = response.headers.get('content-length')

            if error:
                metrics['error'] = error

            # Add user info if available
            if hasattr(request.state, 'user') and request.state.user:
                metrics['user_id'] = request.state.user.get('sub')

            # Log slow requests with higher priority
            if process_time > self.very_slow_request_threshold:
                await self.audit.log_performance_issue(
                    issue_type='very_slow_request',
                    severity='high',
                    details=metrics
                )
                logger.warning(
                    f"Very slow request: {request.method} {request.url.path}",
                    process_time=process_time
                )
            elif process_time > self.slow_request_threshold:
                await self.audit.log_performance_issue(
                    issue_type='slow_request',
                    severity='medium',
                    details=metrics
                )
                logger.info(
                    f"Slow request: {request.method} {request.url.path}",
                    process_time=process_time
                )

            # Log general performance metrics
            await self.audit.log_performance_metrics(
                path=request.url.path,
                method=request.method,
                process_time=process_time,
                status_code=response.status_code if response else None,
                user_id=metrics.get('user_id'),
                client_ip=metrics['client_ip']
            )

        except Exception as e:
            logger.error(f"Failed to log performance metrics: {e}")

class ComplianceAuditMiddleware(BaseHTTPMiddleware):
    """Middleware for compliance and regulatory audit requirements"""

    def __init__(self, app):
        super().__init__(app)
        self.audit = AuditLogger()

        # Compliance-relevant endpoints
        self.compliance_endpoints = [
            '/api/v1/deployments',
            '/api/v1/devices',
            '/api/v1/admin',
            '/api/v1/auth',
            '/api/v1/gitops'
        ]

    async def dispatch(self, request: Request, call_next):
        # Check if this request requires compliance auditing
        if not self._requires_compliance_audit(request):
            return await call_next(request)

        start_time = time.time()
        request_id = getattr(request.state, 'request_id', str(uuid.uuid4()))

        # Create compliance audit record
        compliance_record = await self._create_compliance_record(request, request_id)

        try:
            response = await call_next(request)

            # Update compliance record with response
            await self._complete_compliance_record(
                compliance_record,
                response,
                time.time() - start_time,
                success=True
            )

            return response

        except Exception as e:
            # Complete compliance record for failed request
            await self._complete_compliance_record(
                compliance_record,
                None,
                time.time() - start_time,
                success=False,
                error=str(e)
            )

            raise

    def _requires_compliance_audit(self, request: Request) -> bool:
        """Check if request requires compliance auditing"""
        path = request.url.path

        # All compliance-relevant endpoints
        if any(endpoint in path for endpoint in self.compliance_endpoints):
            return True

        # All state-changing operations
        if request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            return True

        return False

    async def _create_compliance_record(
        self,
        request: Request,
        request_id: str
    ) -> Dict[str, Any]:
        """Create initial compliance audit record"""
        record = {
            'audit_id': str(uuid.uuid4()),
            'request_id': request_id,
            'timestamp': datetime.utcnow().isoformat(),
            'action': f"{request.method} {request.url.path}",
            'actor': 'anonymous',
            'source_ip': request.client.host if request.client else 'unknown',
            'user_agent': request.headers.get('user-agent', 'unknown'),
            'status': 'in_progress'
        }

        # Add user information if available
        if hasattr(request.state, 'user') and request.state.user:
            record['actor'] = request.state.user.get('sub', 'unknown')
            record['actor_email'] = request.state.user.get('email')
            record['actor_roles'] = request.state.user.get('roles', [])

        # Log initial compliance record
        await self.audit.log_compliance_event(
            event_type='action_initiated',
            actor=record['actor'],
            action=record['action'],
            details=record
        )

        return record

    async def _complete_compliance_record(
        self,
        record: Dict[str, Any],
        response: Optional[Response],
        process_time: float,
        success: bool,
        error: Optional[str] = None
    ):
        """Complete compliance audit record"""
        record['completion_timestamp'] = datetime.utcnow().isoformat()
        record['process_time'] = round(process_time, 4)
        record['status'] = 'completed' if success else 'failed'

        if response:
            record['response_status'] = response.status_code

        if error:
            record['error'] = error

        # Log completion
        await self.audit.log_compliance_event(
            event_type='action_completed',
            actor=record['actor'],
            action=record['action'],
            success=success,
            details=record
        )

        # Log to structured logging for compliance officers
        logger.info(
            f"Compliance audit: {record['action']}",
            audit_id=record['audit_id'],
            actor=record['actor'],
            success=success,
            process_time=process_time
        )