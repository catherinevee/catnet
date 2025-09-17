#!/usr/bin/env python3
"""
Generate Certificate Authority and service certificates for mTLS
"""
import os
import sys
import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from typing import Tuple, Optional

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from src.security.vault import VaultClient


class CertificateAuthority:
    def __init__(self, ca_name: str = "CatNet Internal CA"):
        self.ca_name = ca_name
        self.ca_key = None
        self.ca_cert = None
        self.certs_dir = Path("certs")
        self.certs_dir.mkdir(exist_ok=True)
        self.vault = VaultClient()

    def generate_ca(self) -> Tuple[bytes, bytes]:
        """Generate CA certificate and private key"""
        print(f"Generating CA: {self.ca_name}")

        # Generate CA private key
        self.ca_key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend()
        )

        # Generate CA certificate
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CatNet"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Security"),
                x509.NameAttribute(NameOID.COMMON_NAME, self.ca_name),
            ]
        )

        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))  # 10 years
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    key_agreement=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_encipherment=False,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key()),
                critical=False,
            )
            .sign(self.ca_key, hashes.SHA256(), default_backend())
        )

        # Serialize CA certificate and key
        ca_cert_pem = self.ca_cert.public_bytes(encoding=serialization.Encoding.PEM)
        ca_key_pem = self.ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Save CA files
        ca_cert_path = self.certs_dir / "ca.crt"
        ca_key_path = self.certs_dir / "ca.key"

        with open(ca_cert_path, "wb") as f:
            f.write(ca_cert_pem)

        with open(ca_key_path, "wb") as f:
            f.write(ca_key_pem)

        # Secure the private key
        os.chmod(ca_key_path, 0o600)

        print(f"CA certificate saved to: {ca_cert_path}")
        print(f"CA private key saved to: {ca_key_path}")

        return ca_cert_pem, ca_key_pem

    def generate_service_cert(
        self, service_name: str, san_list: Optional[list] = None
    ) -> Tuple[bytes, bytes]:
        """Generate certificate for a service"""
        print(f"Generating certificate for service: {service_name}")

        if not self.ca_cert or not self.ca_key:
            # Load CA from files if not in memory
            self._load_ca()

        # Generate service private key
        service_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        # Certificate subject
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CatNet"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, service_name),
                x509.NameAttribute(NameOID.COMMON_NAME, f"{service_name}.catnet.local"),
            ]
        )

        # Build certificate
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.issuer)
            .public_key(service_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))  # 1 year
        )

        # Add Subject Alternative Names
        if not san_list:
            san_list = [
                f"{service_name}.catnet.local",
                f"{service_name}",
                "localhost",
                "127.0.0.1",
            ]

        san_ext = x509.SubjectAlternativeName(
            [
                x509.DNSName(name)
                for name in san_list
                if not name.replace(".", "").isdigit()
            ]
            + [
                x509.IPAddress(ipaddress.ip_address(name))
                for name in san_list
                if name.replace(".", "").isdigit()
            ]
        )

        cert_builder = cert_builder.add_extension(san_ext, critical=False)

        # Add extensions for client and server auth
        cert_builder = cert_builder.add_extension(
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
            x509.ExtendedKeyUsage(
                [
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]
            ),
            critical=True,
        )

        # Sign the certificate
        service_cert = cert_builder.sign(
            self.ca_key, hashes.SHA256(), default_backend()
        )

        # Serialize certificate and key
        cert_pem = service_cert.public_bytes(encoding=serialization.Encoding.PEM)
        key_pem = service_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Save service certificate and key
        cert_path = self.certs_dir / f"{service_name}.crt"
        key_path = self.certs_dir / f"{service_name}.key"

        with open(cert_path, "wb") as f:
            f.write(cert_pem)

        with open(key_path, "wb") as f:
            f.write(key_pem)

        # Secure the private key
        os.chmod(key_path, 0o600)

        print(f"Service certificate saved to: {cert_path}")
        print(f"Service private key saved to: {key_path}")

        return cert_pem, key_pem

    def _load_ca(self):
        """Load CA certificate and key from files"""
        ca_cert_path = self.certs_dir / "ca.crt"
        ca_key_path = self.certs_dir / "ca.key"

        with open(ca_cert_path, "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        with open(ca_key_path, "rb") as f:
            self.ca_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )

    async def store_in_vault(self, service_name: str, cert_pem: bytes, key_pem: bytes):
        """Store certificate and key in Vault"""
        try:
            await self.vault.store_secret(
                f"certificates/{service_name}",
                {
                    "certificate": cert_pem.decode("utf-8"),
                    "private_key": key_pem.decode("utf-8"),
                    "created_at": datetime.utcnow().isoformat(),
                },
            )
            print(f"Stored {service_name} certificate in Vault")
        except Exception as e:
            print(f"Warning: Could not store in Vault: {e}")


async def main():
    """Generate all certificates for CatNet services"""
    ca = CertificateAuthority()

    # Generate CA
    print("=" * 60)
    print("CatNet mTLS Certificate Generation")
    print("=" * 60)

    ca_cert, ca_key = ca.generate_ca()

    # Generate certificates for each service
    services = [
        ("auth-service", ["auth.catnet.local", "localhost", "127.0.0.1"]),
        ("gitops-service", ["gitops.catnet.local", "localhost", "127.0.0.1"]),
        ("deployment-service", ["deploy.catnet.local", "localhost", "127.0.0.1"]),
        ("device-service", ["devices.catnet.local", "localhost", "127.0.0.1"]),
        ("api-gateway", ["api.catnet.local", "localhost", "127.0.0.1"]),
    ]

    print("\n" + "=" * 60)
    print("Generating Service Certificates")
    print("=" * 60)

    for service_name, san_list in services:
        cert_pem, key_pem = ca.generate_service_cert(service_name, san_list)
        await ca.store_in_vault(service_name, cert_pem, key_pem)

    # Store CA in Vault as well
    await ca.store_in_vault("ca", ca_cert, ca_key)

    print("\n" + "=" * 60)
    print("Certificate Generation Complete!")
    print("=" * 60)
    print(f"\nCertificates stored in: {ca.certs_dir.absolute()}")
    print("\nServices can now use these certificates for mTLS communication.")
    print("\nIMPORTANT: Keep the CA private key secure!")

    # Verify certificates
    print("\n" + "=" * 60)
    print("Certificate Verification")
    print("=" * 60)

    for service_name, _ in services:
        cert_path = ca.certs_dir / f"{service_name}.crt"
        result = os.system(
            f"openssl verify -CAfile {ca.certs_dir}/ca.crt {cert_path} 2>/dev/null"
        )
        if result == 0:
            print(f"✅ {service_name}: Certificate valid")
        else:
            print(f"❌ {service_name}: Certificate validation failed")


if __name__ == "__main__":
    # Import ipaddress for IP SANs
    import ipaddress

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nCertificate generation cancelled.")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
