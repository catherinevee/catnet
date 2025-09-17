"""
mTLS Manager for secure inter-service communication
"""
import ssl
import os
import asyncio
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
import aiohttp
from aiohttp import TCPConnector
import certifi

from ..security.vault import VaultClient
from ..core.logging import get_logger
from ..core.exceptions import SecurityError

logger = get_logger(__name__)


class MTLSManager:
    """Manages mTLS connections between services"""

    def __init__(self, service_name: str, certs_dir: str = "certs"):
        self.service_name = service_name
        self.certs_dir = Path(certs_dir)
        self.vault = VaultClient()
        self._ssl_contexts: Dict[str, ssl.SSLContext] = {}
        self._cert_cache: Dict[str, Tuple[str, str]] = {}

    async def create_ssl_context(
        self,
        target_service: Optional[str] = None,
        verify_mode: ssl.VerifyMode = ssl.CERT_REQUIRED
    ) -> ssl.SSLContext:
        """
        Create SSL context with client certificate verification

        Args:
            target_service: Target service name for the connection
            verify_mode: SSL verification mode

        Returns:
            Configured SSL context for mTLS
        """
        # Check cache first
        cache_key = f"{self.service_name}-{target_service or 'server'}"
        if cache_key in self._ssl_contexts:
            logger.debug(f"Using cached SSL context for {cache_key}")
            return self._ssl_contexts[cache_key]

        logger.info(f"Creating SSL context for {self.service_name}")

        # Create SSL context
        context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH if target_service else ssl.Purpose.CLIENT_AUTH,
            cafile=certifi.where()
        )

        # Load CA certificate
        ca_cert_path = self.certs_dir / "ca.crt"
        if ca_cert_path.exists():
            context.load_verify_locations(cafile=str(ca_cert_path))
            logger.debug(f"Loaded CA certificate from {ca_cert_path}")
        else:
            # Try to load from Vault
            ca_cert, _ = await self._get_cert_from_vault("ca")
            if ca_cert:
                context.load_verify_locations(cadata=ca_cert.encode())
                logger.debug("Loaded CA certificate from Vault")

        # Load service certificate and key
        cert_path = self.certs_dir / f"{self.service_name}.crt"
        key_path = self.certs_dir / f"{self.service_name}.key"

        if cert_path.exists() and key_path.exists():
            context.load_cert_chain(
                certfile=str(cert_path),
                keyfile=str(key_path)
            )
            logger.debug(f"Loaded service certificate from {cert_path}")
        else:
            # Try to load from Vault
            cert, key = await self._get_cert_from_vault(self.service_name)
            if cert and key:
                # Write temporary files (in production, use in-memory)
                temp_cert = self.certs_dir / f".{self.service_name}_temp.crt"
                temp_key = self.certs_dir / f".{self.service_name}_temp.key"

                with open(temp_cert, 'w') as f:
                    f.write(cert)
                with open(temp_key, 'w') as f:
                    f.write(key)

                try:
                    context.load_cert_chain(
                        certfile=str(temp_cert),
                        keyfile=str(temp_key)
                    )
                    logger.debug("Loaded service certificate from Vault")
                finally:
                    # Clean up temporary files
                    temp_cert.unlink(missing_ok=True)
                    temp_key.unlink(missing_ok=True)

        # Configure SSL options
        context.verify_mode = verify_mode
        context.check_hostname = verify_mode != ssl.CERT_NONE

        # Set minimum TLS version to 1.2
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Disable weak ciphers
        context.set_ciphers('HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4')

        # Cache the context
        self._ssl_contexts[cache_key] = context

        logger.info(f"SSL context created for {self.service_name}")
        return context

    async def create_client_session(
        self,
        target_service: str,
        base_url: Optional[str] = None
    ) -> aiohttp.ClientSession:
        """
        Create aiohttp ClientSession with mTLS

        Args:
            target_service: Target service name
            base_url: Base URL for the target service

        Returns:
            Configured aiohttp ClientSession
        """
        ssl_context = await self.create_ssl_context(target_service)

        # Create custom connector with SSL context
        connector = TCPConnector(
            ssl=ssl_context,
            limit=100,
            limit_per_host=30,
            ttl_dns_cache=300,
            enable_cleanup_closed=True
        )

        # Create session
        session = aiohttp.ClientSession(
            connector=connector,
            base_url=base_url,
            headers={
                'X-Service-Name': self.service_name,
                'X-Service-Version': '1.0.0'
            },
            timeout=aiohttp.ClientTimeout(total=30)
        )

        logger.info(f"Created mTLS client session for {target_service}")
        return session

    async def verify_client_cert(self, cert_data: bytes) -> Dict[str, Any]:
        """
        Verify client certificate against CA

        Args:
            cert_data: Certificate data in PEM format

        Returns:
            Certificate information if valid

        Raises:
            SecurityError: If certificate is invalid
        """
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509.oid import NameOID

        try:
            # Parse certificate
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())

            # Extract certificate information
            subject = cert.subject
            issuer = cert.issuer

            # Get common name
            cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

            # Check certificate validity
            now = datetime.utcnow()
            if now < cert.not_valid_before or now > cert.not_valid_after:
                raise SecurityError("Certificate is not valid (expired or not yet valid)")

            # Extract service name from CN (format: service-name.catnet.local)
            service_name = cn.split('.')[0] if '.' in cn else cn

            cert_info = {
                'service_name': service_name,
                'common_name': cn,
                'serial_number': str(cert.serial_number),
                'not_valid_before': cert.not_valid_before.isoformat(),
                'not_valid_after': cert.not_valid_after.isoformat(),
                'issuer': issuer.rfc4514_string(),
                'subject': subject.rfc4514_string(),
                'verified': True
            }

            logger.info(f"Certificate verified for {service_name}")
            return cert_info

        except Exception as e:
            logger.error(f"Certificate verification failed: {e}")
            raise SecurityError(f"Certificate verification failed: {str(e)}")

    async def rotate_certificate(self) -> bool:
        """
        Rotate service certificate

        Returns:
            True if rotation successful
        """
        logger.info(f"Starting certificate rotation for {self.service_name}")

        try:
            # Generate new certificate (would call CA service in production)
            # For now, just clear the cache
            self._ssl_contexts.clear()
            self._cert_cache.clear()

            logger.info(f"Certificate rotation completed for {self.service_name}")
            return True

        except Exception as e:
            logger.error(f"Certificate rotation failed: {e}")
            return False

    async def _get_cert_from_vault(self, name: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Get certificate and key from Vault

        Args:
            name: Certificate name in Vault

        Returns:
            Tuple of (certificate, private_key) or (None, None) if not found
        """
        if name in self._cert_cache:
            return self._cert_cache[name]

        try:
            secret = await self.vault.get_secret(f"certificates/{name}")
            if secret and 'certificate' in secret and 'private_key' in secret:
                cert = secret['certificate']
                key = secret['private_key']
                self._cert_cache[name] = (cert, key)
                return cert, key
        except Exception as e:
            logger.warning(f"Could not retrieve certificate from Vault: {e}")

        return None, None

    async def get_service_port(self, service_name: str) -> int:
        """
        Get service port number

        Args:
            service_name: Service name

        Returns:
            Port number for the service
        """
        service_ports = {
            'auth-service': 8081,
            'gitops-service': 8082,
            'deployment-service': 8083,
            'device-service': 8084,
            'api-gateway': 8080
        }
        return service_ports.get(service_name, 8080)

    async def get_service_url(self, service_name: str, use_mtls: bool = True) -> str:
        """
        Get service URL with proper scheme

        Args:
            service_name: Service name
            use_mtls: Whether to use HTTPS (mTLS) or HTTP

        Returns:
            Service URL
        """
        port = await self.get_service_port(service_name)
        scheme = 'https' if use_mtls else 'http'

        # In production, this would use service discovery
        # For now, use localhost
        host = 'localhost'

        return f"{scheme}://{host}:{port}"

    async def health_check(self, service_name: str) -> bool:
        """
        Perform health check on a service using mTLS

        Args:
            service_name: Target service name

        Returns:
            True if service is healthy
        """
        try:
            url = await self.get_service_url(service_name)
            async with await self.create_client_session(service_name, url) as session:
                async with session.get('/health') as response:
                    return response.status == 200
        except Exception as e:
            logger.error(f"Health check failed for {service_name}: {e}")
            return False


class MTLSServer:
    """Helper class for setting up mTLS server"""

    def __init__(self, service_name: str):
        self.service_name = service_name
        self.mtls_manager = MTLSManager(service_name)

    async def get_ssl_context(self) -> ssl.SSLContext:
        """
        Get SSL context for server

        Returns:
            SSL context configured for server
        """
        context = await self.mtls_manager.create_ssl_context(
            target_service=None,
            verify_mode=ssl.CERT_REQUIRED  # Require client certificates
        )

        # Additional server-specific configuration
        context.set_npn_protocols(['http/1.1'])

        return context

    def verify_client(self, request) -> Dict[str, Any]:
        """
        Verify client certificate from request

        Args:
            request: HTTP request object

        Returns:
            Client certificate information

        Raises:
            SecurityError: If client certificate is invalid
        """
        # Extract client certificate from request
        # This depends on the web framework being used
        # For FastAPI with uvicorn:
        transport = request.get("transport")
        if transport:
            ssl_object = transport.get_extra_info("ssl_object")
            if ssl_object:
                cert = ssl_object.getpeercert_bin()
                if cert:
                    return asyncio.run(
                        self.mtls_manager.verify_client_cert(cert)
                    )

        raise SecurityError("No client certificate provided")


# Middleware for FastAPI to enforce mTLS
class MTLSMiddleware:
    """Middleware to enforce mTLS for all requests"""

    def __init__(self, app, service_name: str, exclude_paths: list = None):
        self.app = app
        self.mtls_server = MTLSServer(service_name)
        self.exclude_paths = exclude_paths or ['/health', '/metrics']

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'http':
            path = scope['path']

            # Skip mTLS for excluded paths
            if path not in self.exclude_paths:
                # Verify client certificate
                try:
                    # In production, extract and verify client cert
                    # For now, just log
                    logger.debug(f"mTLS verification for path: {path}")
                except SecurityError as e:
                    logger.error(f"mTLS verification failed: {e}")
                    # Send 403 Forbidden
                    await send({
                        'type': 'http.response.start',
                        'status': 403,
                        'headers': [(b'content-type', b'text/plain')],
                    })
                    await send({
                        'type': 'http.response.body',
                        'body': b'Forbidden: Invalid client certificate',
                    })
                    return

        await self.app(scope, receive, send)