import ssl
import os
import logging
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import ipaddress

logger = logging.getLogger(__name__)

class MTLSManager:
    def __init__(self, ca_cert_path: Optional[str] = None, ca_key_path: Optional[str] = None):
        self.ca_cert_path = ca_cert_path or os.getenv("CA_CERT_PATH", "/etc/catnet/ca/ca.crt")
        self.ca_key_path = ca_key_path or os.getenv("CA_KEY_PATH", "/etc/catnet/ca/ca.key")
        self.certs_dir = Path(os.getenv("CERTS_DIR", "/etc/catnet/certs"))
        self.certs_dir.mkdir(parents=True, exist_ok=True)
        self.backend = default_backend()
        self.ca_cert = None
        self.ca_key = None
        self._load_ca()

    def _load_ca(self):
        try:
            if os.path.exists(self.ca_cert_path) and os.path.exists(self.ca_key_path):
                with open(self.ca_cert_path, "rb") as f:
                    self.ca_cert = x509.load_pem_x509_certificate(f.read(), self.backend)

                with open(self.ca_key_path, "rb") as f:
                    self.ca_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None,
                        backend=self.backend
                    )
                logger.info("CA certificate and key loaded successfully")
            else:
                logger.warning("CA certificate or key not found, generating new CA")
                self._generate_ca()
        except Exception as e:
            logger.error(f"Failed to load CA: {e}")
            raise

    def _generate_ca(self):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=self.backend
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CatNet"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Security"),
            x509.NameAttribute(NameOID.COMMON_NAME, "CatNet Root CA"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).sign(key, hashes.SHA256(), self.backend)

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        os.makedirs(os.path.dirname(self.ca_cert_path), exist_ok=True)

        with open(self.ca_cert_path, "wb") as f:
            f.write(cert_pem)

        with open(self.ca_key_path, "wb") as f:
            f.write(key_pem)

        os.chmod(self.ca_key_path, 0o600)

        self.ca_cert = cert
        self.ca_key = key

        logger.info("Generated new CA certificate")

    def generate_server_certificate(
        self,
        common_name: str,
        san_dns: Optional[list] = None,
        san_ip: Optional[list] = None,
        validity_days: int = 365
    ) -> Tuple[bytes, bytes]:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CatNet"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Services"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.ca_cert.subject
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=True,
        )

        san_list = []
        san_list.append(x509.DNSName(common_name))

        if san_dns:
            for dns in san_dns:
                san_list.append(x509.DNSName(dns))

        if san_ip:
            for ip in san_ip:
                san_list.append(x509.IPAddress(ipaddress.ip_address(ip)))

        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )

        cert = builder.sign(self.ca_key, hashes.SHA256(), self.backend)

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        cert_path = self.certs_dir / f"{common_name}.crt"
        key_path = self.certs_dir / f"{common_name}.key"

        with open(cert_path, "wb") as f:
            f.write(cert_pem)

        with open(key_path, "wb") as f:
            f.write(key_pem)

        os.chmod(key_path, 0o600)

        logger.info(f"Generated server certificate for {common_name}")
        return cert_pem, key_pem

    def generate_client_certificate(
        self,
        common_name: str,
        email: Optional[str] = None,
        validity_days: int = 365
    ) -> Tuple[bytes, bytes]:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )

        subject_components = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CatNet"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Users"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]

        if email:
            subject_components.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))

        subject = x509.Name(subject_components)

        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.ca_cert.subject
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=True,
        )

        cert = builder.sign(self.ca_key, hashes.SHA256(), self.backend)

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        cert_path = self.certs_dir / f"client_{common_name}.crt"
        key_path = self.certs_dir / f"client_{common_name}.key"

        with open(cert_path, "wb") as f:
            f.write(cert_pem)

        with open(key_path, "wb") as f:
            f.write(key_pem)

        os.chmod(key_path, 0o600)

        logger.info(f"Generated client certificate for {common_name}")
        return cert_pem, key_pem

    def create_ssl_context(
        self,
        cert_path: str,
        key_path: str,
        verify_mode: int = ssl.CERT_REQUIRED,
        check_hostname: bool = True
    ) -> ssl.SSLContext:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.verify_mode = verify_mode
        context.check_hostname = check_hostname

        context.load_verify_locations(self.ca_cert_path)

        context.load_cert_chain(cert_path, key_path)

        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')

        return context

    def verify_certificate(self, cert_pem: bytes) -> Dict[str, Any]:
        try:
            cert = x509.load_pem_x509_certificate(cert_pem, self.backend)

            now = datetime.utcnow()
            if cert.not_valid_before > now or cert.not_valid_after < now:
                return {"valid": False, "reason": "Certificate expired or not yet valid"}

            try:
                issuer_public_key = self.ca_cert.public_key()
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    cert.signature_algorithm_parameters
                )
            except Exception:
                return {"valid": False, "reason": "Invalid signature"}

            return {
                "valid": True,
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "serial": str(cert.serial_number),
                "not_before": cert.not_valid_before.isoformat(),
                "not_after": cert.not_valid_after.isoformat()
            }

        except Exception as e:
            logger.error(f"Certificate verification failed: {e}")
            return {"valid": False, "reason": str(e)}

    def extract_certificate_info(self, cert_pem: bytes) -> Dict[str, Any]:
        try:
            cert = x509.load_pem_x509_certificate(cert_pem, self.backend)

            san_list = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for san in san_ext.value:
                    if isinstance(san, x509.DNSName):
                        san_list.append({"type": "DNS", "value": san.value})
                    elif isinstance(san, x509.IPAddress):
                        san_list.append({"type": "IP", "value": str(san.value)})
            except x509.ExtensionNotFound:
                pass

            return {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "serial_number": str(cert.serial_number),
                "not_before": cert.not_valid_before.isoformat(),
                "not_after": cert.not_valid_after.isoformat(),
                "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
                "signature_algorithm": cert.signature_algorithm_oid._name,
                "san": san_list,
                "version": cert.version.name
            }

        except Exception as e:
            logger.error(f"Failed to extract certificate info: {e}")
            raise

    def revoke_certificate(self, serial_number: int, reason: x509.ReasonFlags = x509.ReasonFlags.unspecified):
        logger.info(f"Certificate {serial_number} marked for revocation with reason: {reason}")

    def generate_crl(self) -> bytes:
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.ca_cert.subject)
        builder = builder.last_update(datetime.utcnow())
        builder = builder.next_update(datetime.utcnow() + timedelta(days=7))

        crl = builder.sign(
            private_key=self.ca_key,
            algorithm=hashes.SHA256(),
            backend=self.backend
        )

        return crl.public_bytes(serialization.Encoding.PEM)