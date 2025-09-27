"""
mTLS (Mutual TLS) Middleware
Implements certificate-based authentication for inter-service communication
"""

import ssl
import base64
import hashlib
from typing import Optional, Dict, Any, List, Callable
from datetime import datetime, timedelta
from pathlib import Path
import re
import urllib.parse
from urllib.request import urlopen
import asyncio

from fastapi import Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.ocsp import OCSPRequestBuilder, OCSPResponseStatus
import aioredis
import aiohttp

from src.core.config import settings
from src.security.audit import AuditLogger
from src.db.models import ClientCertificate, ServiceIdentity


class MTLSMiddleware(BaseHTTPMiddleware):
    """
    mTLS middleware for secure service-to-service communication
    Enforces mutual TLS authentication and authorization
    """

    def __init__(
        self,
        app: ASGIApp,
        redis_client: Optional[aioredis.Redis] = None,
        audit_logger: Optional[AuditLogger] = None,
        ca_cert_path: Optional[str] = None,
        cert_path: Optional[str] = None,
        key_path: Optional[str] = None,
        enforce_mtls: bool = True,
        allowed_dns: Optional[List[str]] = None,
        allowed_ips: Optional[List[str]] = None
    ):
        super().__init__(app)
        self.redis = redis_client
        self.audit = audit_logger
        self.enforce_mtls = enforce_mtls

        # Certificate paths
        self.ca_cert_path = ca_cert_path or settings.MTLS_CA_CERT_PATH
        self.cert_path = cert_path or settings.MTLS_CERT_PATH
        self.key_path = key_path or settings.MTLS_KEY_PATH

        # Allowed identities
        self.allowed_dns = allowed_dns or settings.MTLS_ALLOWED_DNS or []
        self.allowed_ips = allowed_ips or settings.MTLS_ALLOWED_IPS or []

        # Load CA certificate for validation
        self.ca_cert = None
        if self.ca_cert_path and Path(self.ca_cert_path).exists():
            with open(self.ca_cert_path, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        # Certificate cache for performance
        self.cert_cache = {}

        # Paths that require mTLS
        self.mtls_required_paths = [
            "/api/v1/internal/",
            "/api/v1/service/",
            "/api/v1/admin/"
        ]

        # Paths that are exempt from mTLS
        self.mtls_exempt_paths = [
            "/health",
            "/metrics",
            "/api/v1/auth/login",
            "/api/v1/auth/refresh"
        ]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request through mTLS validation
        """

        # Check if mTLS is required for this path
        if not self._is_mtls_required(request.url.path):
            return await call_next(request)

        # Get client certificate from request
        client_cert = self._get_client_certificate(request)

        if not client_cert and self.enforce_mtls:
            await self._log_security_event(
                request,
                "mtls_missing_certificate",
                {"path": request.url.path}
            )
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Client certificate required"}
            )

        if client_cert:
            # Validate certificate
            validation_result = await self._validate_certificate(client_cert)

            if not validation_result["valid"]:
                await self._log_security_event(
                    request,
                    "mtls_invalid_certificate",
                    {
                        "reason": validation_result["reason"],
                        "subject": validation_result.get("subject")
                    }
                )
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": f"Certificate validation failed: {validation_result['reason']}"}
                )

            # Extract service identity
            service_identity = self._extract_service_identity(client_cert)

            # Authorize service
            if not await self._authorize_service(service_identity, request):
                await self._log_security_event(
                    request,
                    "mtls_authorization_failed",
                    {
                        "service": service_identity["service_name"],
                        "path": request.url.path
                    }
                )
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Service not authorized for this endpoint"}
                )

            # Store service identity in request state
            request.state.service_identity = service_identity
            request.state.mtls_verified = True

            # Log successful mTLS authentication
            await self._log_mtls_success(request, service_identity)

        # Process request
        response = await call_next(request)

        # Add mTLS response headers
        if client_cert:
            response.headers["X-Client-Cert-Subject"] = service_identity.get("subject", "")
            response.headers["X-Client-Cert-Serial"] = service_identity.get("serial", "")

        return response

    def _is_mtls_required(self, path: str) -> bool:
        """
        Check if mTLS is required for the given path
        """

        # Check exempt paths
        for exempt_path in self.mtls_exempt_paths:
            if path.startswith(exempt_path):
                return False

        # Check required paths
        for required_path in self.mtls_required_paths:
            if path.startswith(required_path):
                return True

        # Default based on configuration
        return self.enforce_mtls and path.startswith("/api/")

    def _get_client_certificate(self, request: Request) -> Optional[x509.Certificate]:
        """
        Extract client certificate from request
        """

        # Try to get certificate from different sources

        # 1. From request headers (when behind proxy)
        cert_header = request.headers.get("X-Client-Cert")
        if cert_header:
            try:
                # Decode from base64
                cert_data = base64.b64decode(cert_header)
                return x509.load_pem_x509_certificate(cert_data, default_backend())
            except Exception:
                pass

        # 2. From TLS connection (direct connection)
        # This requires the ASGI server to pass the client certificate
        if hasattr(request, "scope") and "extensions" in request.scope:
            tls_info = request.scope["extensions"].get("tls", {})
            client_cert_data = tls_info.get("client_cert_chain")
            if client_cert_data:
                try:
                    return x509.load_pem_x509_certificate(
                        client_cert_data[0],
                        default_backend()
                    )
                except Exception:
                    pass

        # 3. From environment (for testing)
        if settings.ENVIRONMENT == "development":
            test_cert = request.headers.get("X-Test-Client-Cert")
            if test_cert:
                try:
                    cert_data = base64.b64decode(test_cert)
                    return x509.load_pem_x509_certificate(cert_data, default_backend())
                except Exception:
                    pass

        return None

    async def _validate_certificate(self, cert: x509.Certificate) -> Dict[str, Any]:
        """
        Validate client certificate
        """

        result = {"valid": False, "reason": ""}

        try:
            # Extract certificate details
            subject = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            serial = str(cert.serial_number)

            # Cache check
            cache_key = f"cert:{serial}"
            if cache_key in self.cert_cache:
                cached = self.cert_cache[cache_key]
                if cached["expiry"] > datetime.utcnow():
                    return cached["result"]

            # 1. Check expiration
            now = datetime.utcnow()
            if cert.not_valid_before > now:
                result["reason"] = "Certificate not yet valid"
                result["subject"] = subject
                return result

            if cert.not_valid_after < now:
                result["reason"] = "Certificate expired"
                result["subject"] = subject
                return result

            # 2. Verify certificate chain (if CA cert available)
            if self.ca_cert:
                try:
                    # Verify signature
                    self.ca_cert.public_key().verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        cert.signature_algorithm_parameters
                    )
                except Exception:
                    result["reason"] = "Certificate not signed by trusted CA"
                    result["subject"] = subject
                    return result

            # 3. Check revocation (CRL or OCSP)
            if await self._is_certificate_revoked(cert):
                result["reason"] = "Certificate has been revoked"
                result["subject"] = subject
                return result

            # 4. Validate certificate extensions
            try:
                key_usage = cert.extensions.get_extension_for_oid(
                    ExtensionOID.KEY_USAGE
                ).value

                # Check for required key usage
                if not key_usage.digital_signature or not key_usage.key_agreement:
                    result["reason"] = "Invalid key usage"
                    result["subject"] = subject
                    return result
            except x509.ExtensionNotFound:
                # Key usage extension not found (may be okay for some certs)
                pass

            # 5. Validate subject alternative names
            try:
                san_ext = cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                ).value

                # Check if any SAN matches allowed patterns
                san_valid = False
                for san in san_ext:
                    if isinstance(san, x509.DNSName):
                        for allowed_dns in self.allowed_dns:
                            if re.match(allowed_dns, san.value):
                                san_valid = True
                                break
                    elif isinstance(san, x509.IPAddress):
                        if str(san.value) in self.allowed_ips:
                            san_valid = True

                if not san_valid and self.allowed_dns:
                    result["reason"] = "No matching SAN found"
                    result["subject"] = subject
                    return result

            except x509.ExtensionNotFound:
                # No SAN extension (check CN instead)
                if self.allowed_dns:
                    cn_valid = False
                    for allowed_dns in self.allowed_dns:
                        if re.match(allowed_dns, subject):
                            cn_valid = True
                            break

                    if not cn_valid:
                        result["reason"] = "CN does not match allowed patterns"
                        result["subject"] = subject
                        return result

            # Certificate is valid
            result["valid"] = True
            result["subject"] = subject
            result["serial"] = serial

            # Cache result
            self.cert_cache[cache_key] = {
                "result": result,
                "expiry": datetime.utcnow() + timedelta(minutes=5)
            }

            return result

        except Exception as e:
            result["reason"] = f"Certificate validation error: {str(e)}"
            return result

    async def _is_certificate_revoked(self, cert: x509.Certificate) -> bool:
        """
        Check if certificate has been revoked using CRL or OCSP
        """

        # Check Redis cache for revoked certificates
        if self.redis:
            serial = str(cert.serial_number)
            cache_key = f"cert_revocation:{serial}"

            # Check cache first
            cached_result = await self.redis.get(cache_key)
            if cached_result is not None:
                return cached_result == b"revoked"

            # Check global revocation list
            is_revoked = await self.redis.sismember("revoked_certificates", serial)
            if is_revoked:
                # Cache the result for 1 hour
                await self.redis.setex(cache_key, 3600, "revoked")
                return True

        # Try CRL checking first
        try:
            crl_result = await self._check_certificate_crl(cert)
            if crl_result is not None:
                # Cache the result
                if self.redis:
                    cache_key = f"cert_revocation:{cert.serial_number}"
                    status_value = "revoked" if crl_result else "valid"
                    await self.redis.setex(cache_key, 3600, status_value)
                return crl_result
        except Exception as e:
            # Log CRL check failure but continue to OCSP
            if self.audit:
                await self.audit.log_event(
                    action="crl_check_failed",
                    resource_type="certificate",
                    resource_id=str(cert.serial_number),
                    details={"error": str(e)}
                )

        # Try OCSP checking as fallback
        try:
            ocsp_result = await self._check_certificate_ocsp(cert)
            if ocsp_result is not None:
                # Cache the result
                if self.redis:
                    cache_key = f"cert_revocation:{cert.serial_number}"
                    status_value = "revoked" if ocsp_result else "valid"
                    await self.redis.setex(cache_key, 1800, status_value)  # Cache OCSP for 30 minutes
                return ocsp_result
        except Exception as e:
            # Log OCSP check failure
            if self.audit:
                await self.audit.log_event(
                    action="ocsp_check_failed",
                    resource_type="certificate",
                    resource_id=str(cert.serial_number),
                    details={"error": str(e)}
                )

        # If both CRL and OCSP fail, assume certificate is valid
        # but log the inability to check revocation
        if self.audit:
            await self.audit.log_event(
                action="revocation_check_unavailable",
                resource_type="certificate",
                resource_id=str(cert.serial_number),
                details={"reason": "Both CRL and OCSP checks failed"}
            )

        return False

    async def _check_certificate_crl(self, cert: x509.Certificate) -> Optional[bool]:
        """
        Check certificate against Certificate Revocation List (CRL)
        """
        try:
            # Extract CRL distribution points from certificate
            crl_urls = self._extract_crl_urls(cert)

            if not crl_urls:
                return None

            # Check each CRL URL
            for crl_url in crl_urls:
                try:
                    # Download and parse CRL
                    crl = await self._download_crl(crl_url)
                    if crl is None:
                        continue

                    # Check if certificate is in the CRL
                    for revoked_cert in crl:
                        if revoked_cert.serial_number == cert.serial_number:
                            # Certificate is revoked
                            if self.audit:
                                await self.audit.log_security_event(
                                    event_type="certificate_revoked_crl",
                                    severity="high",
                                    details={
                                        "serial": str(cert.serial_number),
                                        "crl_url": crl_url,
                                        "revocation_date": revoked_cert.revocation_date.isoformat()
                                    }
                                )
                            return True

                    # Certificate not found in this CRL, continue checking others

                except Exception as e:
                    # Log individual CRL check failure but continue
                    if self.audit:
                        await self.audit.log_event(
                            action="crl_download_failed",
                            resource_type="crl",
                            resource_id=crl_url,
                            details={"error": str(e)}
                        )
                    continue

            # Certificate not found in any CRL
            return False

        except Exception:
            # CRL checking failed entirely
            return None

    def _extract_crl_urls(self, cert: x509.Certificate) -> List[str]:
        """
        Extract CRL distribution point URLs from certificate
        """
        crl_urls = []

        try:
            crl_dist_points = cert.extensions.get_extension_for_oid(
                ExtensionOID.CRL_DISTRIBUTION_POINTS
            ).value

            for dist_point in crl_dist_points:
                if dist_point.full_name:
                    for name in dist_point.full_name:
                        if isinstance(name, x509.UniformResourceIdentifier):
                            crl_urls.append(name.value)

        except x509.ExtensionNotFound:
            pass
        except Exception:
            pass

        return crl_urls

    async def _download_crl(self, crl_url: str) -> Optional[x509.CertificateRevocationList]:
        """
        Download and parse CRL from URL
        """
        try:
            # Check cache first
            if self.redis:
                cache_key = f"crl_cache:{hashlib.sha256(crl_url.encode()).hexdigest()}"
                cached_crl = await self.redis.get(cache_key)
                if cached_crl:
                    try:
                        return x509.load_der_x509_crl(cached_crl, default_backend())
                    except:
                        # Invalid cached CRL, remove it
                        await self.redis.delete(cache_key)

            # Download CRL with timeout
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            ) as session:
                async with session.get(crl_url) as response:
                    if response.status == 200:
                        crl_data = await response.read()

                        # Try parsing as DER first
                        try:
                            crl = x509.load_der_x509_crl(crl_data, default_backend())
                        except:
                            # Try parsing as PEM
                            try:
                                crl = x509.load_pem_x509_crl(crl_data, default_backend())
                            except:
                                return None

                        # Cache the CRL for 1 hour
                        if self.redis:
                            cache_key = f"crl_cache:{hashlib.sha256(crl_url.encode()).hexdigest()}"
                            # Store as DER for caching
                            crl_der = crl.public_bytes(serialization.Encoding.DER)
                            await self.redis.setex(cache_key, 3600, crl_der)

                        return crl

        except Exception:
            pass

        return None

    async def _check_certificate_ocsp(self, cert: x509.Certificate) -> Optional[bool]:
        """
        Check certificate status using Online Certificate Status Protocol (OCSP)
        """
        try:
            # Extract OCSP URL from certificate
            ocsp_url = self._extract_ocsp_url(cert)
            if not ocsp_url:
                return None

            # We need the issuer certificate for OCSP request
            issuer_cert = self.ca_cert
            if not issuer_cert:
                return None

            # Build OCSP request
            builder = OCSPRequestBuilder()
            builder = builder.add_certificate(
                cert, issuer_cert, hashes.SHA256()
            )
            ocsp_request = builder.build()

            # Send OCSP request
            ocsp_response = await self._send_ocsp_request(ocsp_url, ocsp_request)
            if not ocsp_response:
                return None

            # Parse OCSP response
            response_status = ocsp_response.response_status

            if response_status == OCSPResponseStatus.SUCCESSFUL:
                # Get the certificate status
                single_response = ocsp_response.single_extensions[0] if ocsp_response.single_extensions else None

                if single_response:
                    cert_status = single_response.cert_status

                    if hasattr(cert_status, 'revocation_time'):
                        # Certificate is revoked
                        if self.audit:
                            await self.audit.log_security_event(
                                event_type="certificate_revoked_ocsp",
                                severity="high",
                                details={
                                    "serial": str(cert.serial_number),
                                    "ocsp_url": ocsp_url,
                                    "revocation_time": cert_status.revocation_time.isoformat()
                                }
                            )
                        return True
                    else:
                        # Certificate is good
                        return False

            # Unknown status or failed response
            return None

        except Exception:
            return None

    def _extract_ocsp_url(self, cert: x509.Certificate) -> Optional[str]:
        """
        Extract OCSP URL from certificate Authority Information Access extension
        """
        try:
            aia = cert.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            ).value

            for access_desc in aia:
                if access_desc.access_method == x509.AuthorityInformationAccessOID.OCSP:
                    if isinstance(access_desc.access_location, x509.UniformResourceIdentifier):
                        return access_desc.access_location.value

        except x509.ExtensionNotFound:
            pass
        except Exception:
            pass

        return None

    async def _send_ocsp_request(self, ocsp_url: str, ocsp_request) -> Optional[Any]:
        """
        Send OCSP request to the OCSP responder
        """
        try:
            # Serialize OCSP request
            request_data = ocsp_request.public_bytes(serialization.Encoding.DER)

            # Send HTTP POST request
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=15)
            ) as session:
                headers = {
                    'Content-Type': 'application/ocsp-request',
                    'Content-Length': str(len(request_data))
                }

                async with session.post(
                    ocsp_url,
                    data=request_data,
                    headers=headers
                ) as response:
                    if response.status == 200:
                        response_data = await response.read()

                        # Parse OCSP response
                        try:
                            from cryptography.x509.ocsp import load_der_ocsp_response
                            return load_der_ocsp_response(response_data)
                        except:
                            return None

        except Exception:
            pass

        return None

    def _extract_service_identity(self, cert: x509.Certificate) -> Dict[str, Any]:
        """
        Extract service identity from certificate
        """

        identity = {}

        # Extract common name
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            identity["service_name"] = cn
            identity["subject"] = cn
        except:
            identity["service_name"] = "unknown"
            identity["subject"] = "unknown"

        # Extract organization
        try:
            org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
            identity["organization"] = org
        except:
            identity["organization"] = None

        # Extract organizational unit
        try:
            ou = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
            identity["organizational_unit"] = ou
        except:
            identity["organizational_unit"] = None

        # Serial number
        identity["serial"] = str(cert.serial_number)

        # Certificate fingerprint
        fingerprint = cert.fingerprint(hashes.SHA256())
        identity["fingerprint"] = fingerprint.hex()

        # Validity period
        identity["not_before"] = cert.not_valid_before.isoformat()
        identity["not_after"] = cert.not_valid_after.isoformat()

        # Extract custom extensions (if any)
        try:
            for ext in cert.extensions:
                if ext.oid._name == "Unknown OID":
                    # Custom extension for service metadata
                    pass
        except:
            pass

        return identity

    async def _authorize_service(self, service_identity: Dict[str, Any], request: Request) -> bool:
        """
        Authorize service for the requested endpoint
        """

        service_name = service_identity.get("service_name", "")
        path = request.url.path
        method = request.method

        # Check Redis for service permissions
        if self.redis:
            # Check if service is explicitly allowed
            permission_key = f"service_permissions:{service_name}:{method}:{path}"
            is_allowed = await self.redis.get(permission_key)

            if is_allowed is not None:
                return is_allowed == b"1"

            # Check wildcard permissions
            path_parts = path.split("/")
            for i in range(len(path_parts), 0, -1):
                wildcard_path = "/".join(path_parts[:i]) + "/*"
                wildcard_key = f"service_permissions:{service_name}:{method}:{wildcard_path}"
                is_allowed = await self.redis.get(wildcard_key)
                if is_allowed is not None:
                    return is_allowed == b"1"

        # Default authorization rules
        authorization_rules = {
            "deployment-service": ["/api/v1/devices/", "/api/v1/internal/deploy"],
            "gitops-service": ["/api/v1/internal/git", "/api/v1/deployments/"],
            "monitoring-service": ["/api/v1/health", "/metrics"],
            "admin-service": ["*"]  # Admin service has access to all endpoints
        }

        # Check authorization rules
        if service_name in authorization_rules:
            allowed_paths = authorization_rules[service_name]
            for allowed_path in allowed_paths:
                if allowed_path == "*":
                    return True
                if path.startswith(allowed_path):
                    return True

        return False

    async def _log_security_event(self, request: Request, event_type: str, details: Dict[str, Any]):
        """
        Log mTLS security events
        """

        if self.audit:
            await self.audit.log_security_event(
                event_type=event_type,
                severity="high",
                details={
                    "ip_address": request.client.host if request.client else None,
                    "path": request.url.path,
                    "method": request.method,
                    **details
                }
            )

    async def _log_mtls_success(self, request: Request, service_identity: Dict[str, Any]):
        """
        Log successful mTLS authentication
        """

        if self.audit:
            await self.audit.log_event(
                action="mtls_authentication_success",
                resource_type="service",
                resource_id=service_identity.get("service_name"),
                details={
                    "serial": service_identity.get("serial"),
                    "fingerprint": service_identity.get("fingerprint"),
                    "path": request.url.path
                }
            )

        # Store in Redis for monitoring
        if self.redis:
            metric_key = f"mtls_auth:success:{datetime.utcnow().strftime('%Y%m%d%H')}"
            await self.redis.incr(metric_key)
            await self.redis.expire(metric_key, 86400)  # Expire after 24 hours


class CertificateValidator:
    """
    Utility class for certificate validation operations
    """

    @staticmethod
    def validate_certificate_chain(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
        """
        Validate certificate chain
        """

        try:
            ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_algorithm_parameters
            )
            return True
        except Exception:
            return False

    @staticmethod
    async def check_certificate_revocation_crl(cert: x509.Certificate, crl_url: str) -> bool:
        """
        Check certificate against CRL
        """
        try:
            # Download CRL
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            ) as session:
                async with session.get(crl_url) as response:
                    if response.status == 200:
                        crl_data = await response.read()

                        # Parse CRL
                        try:
                            crl = x509.load_der_x509_crl(crl_data, default_backend())
                        except:
                            try:
                                crl = x509.load_pem_x509_crl(crl_data, default_backend())
                            except:
                                return False

                        # Check if certificate is revoked
                        for revoked_cert in crl:
                            if revoked_cert.serial_number == cert.serial_number:
                                return True

                        return False
        except Exception:
            pass

        return False

    @staticmethod
    async def check_certificate_revocation_ocsp(cert: x509.Certificate, issuer_cert: x509.Certificate, ocsp_url: str) -> bool:
        """
        Check certificate status using OCSP
        """
        try:
            # Build OCSP request
            builder = OCSPRequestBuilder()
            builder = builder.add_certificate(
                cert, issuer_cert, hashes.SHA256()
            )
            ocsp_request = builder.build()

            # Serialize request
            request_data = ocsp_request.public_bytes(serialization.Encoding.DER)

            # Send OCSP request
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=15)
            ) as session:
                headers = {
                    'Content-Type': 'application/ocsp-request',
                    'Content-Length': str(len(request_data))
                }

                async with session.post(
                    ocsp_url,
                    data=request_data,
                    headers=headers
                ) as response:
                    if response.status == 200:
                        response_data = await response.read()

                        try:
                            from cryptography.x509.ocsp import load_der_ocsp_response
                            ocsp_response = load_der_ocsp_response(response_data)

                            if ocsp_response.response_status == OCSPResponseStatus.SUCCESSFUL:
                                single_response = ocsp_response.single_extensions[0] if ocsp_response.single_extensions else None
                                if single_response and hasattr(single_response.cert_status, 'revocation_time'):
                                    return True

                            return False
                        except:
                            pass
        except Exception:
            pass

        return False

    @staticmethod
    def extract_certificate_metadata(cert: x509.Certificate) -> Dict[str, Any]:
        """
        Extract metadata from certificate
        """

        metadata = {}

        # Subject details
        for attribute in cert.subject:
            metadata[attribute.oid._name] = attribute.value

        # Issuer details
        for attribute in cert.issuer:
            metadata[f"issuer_{attribute.oid._name}"] = attribute.value

        # Extensions
        for extension in cert.extensions:
            try:
                metadata[extension.oid._name] = str(extension.value)
            except:
                pass

        return metadata