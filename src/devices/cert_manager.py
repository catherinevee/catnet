"""
Device Certificate Manager for certificate-based authentication
"""
import os
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Tuple
from pathlib import Path
import uuid

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Device
from ..db.database import get_db
from ..security.vault import VaultClient
from ..security.audit import AuditLogger
from ..core.logging import get_logger
from ..core.exceptions import SecurityError

logger = get_logger(__name__)


class DeviceCertificateManager:
    """Manages device certificates for authentication"""

    def __init__(self):
        self.vault = VaultClient()
        self.audit = AuditLogger()
        self.ca_cert = None
        self.ca_key = None
        self.certs_dir = Path("certs/devices")
        self.certs_dir.mkdir(parents=True, exist_ok=True)
        self._load_ca()

    def _load_ca(self):
        """Load CA certificate and key"""
        ca_cert_path = Path("certs/ca.crt")
        ca_key_path = Path("certs/ca.key")

        if ca_cert_path.exists() and ca_key_path.exists():
            with open(ca_cert_path, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(
                    f.read(), default_backend()
                )

            with open(ca_key_path, "rb") as f:
                self.ca_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            logger.info("Loaded CA certificate and key")

    async def issue_device_cert(
        self,
        device_id: str,
        device_hostname: str,
        device_ip: str,
        validity_days: int = 365
    ) -> Dict[str, str]:
        """
        Issue certificate for network device

        Args:
            device_id: Device UUID
            device_hostname: Device hostname
            device_ip: Device IP address
            validity_days: Certificate validity in days

        Returns:
            Dictionary containing certificate details
        """
        logger.info(f"Issuing certificate for device {device_id}")

        if not self.ca_cert or not self.ca_key:
            raise SecurityError("CA certificate not available")

        # Generate device private key
        device_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Certificate subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CatNet"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Network Devices"),
            x509.NameAttribute(NameOID.COMMON_NAME, device_hostname),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, device_id),
        ])

        # Build certificate
        cert_builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.ca_cert.issuer
        ).public_key(
            device_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        )

        # Add Subject Alternative Names
        san_list = [device_hostname, device_ip]
        san_ext = x509.SubjectAlternativeName([
            x509.DNSName(device_hostname),
            x509.IPAddress(ipaddress.ip_address(device_ip))
        ])
        cert_builder = cert_builder.add_extension(san_ext, critical=False)

        # Add device authentication extension
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
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=True,
        )

        # Add custom extension for device metadata
        device_info = f"device_id:{device_id},type:network_device"
        cert_builder = cert_builder.add_extension(
            x509.UnrecognizedExtension(
                oid=x509.ObjectIdentifier("1.2.3.4.5.6.7.8.1"),  # Custom OID
                value=device_info.encode()
            ),
            critical=False,
        )

        # Sign the certificate
        device_cert = cert_builder.sign(
            self.ca_key, hashes.SHA256(), default_backend()
        )

        # Serialize certificate and key
        cert_pem = device_cert.public_bytes(
            encoding=serialization.Encoding.PEM
        )
        key_pem = device_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Calculate fingerprint
        fingerprint = hashes.Hash(hashes.SHA256(), backend=default_backend())
        fingerprint.update(cert_pem)
        cert_fingerprint = fingerprint.finalize().hex()

        # Save to file
        cert_path = self.certs_dir / f"{device_id}.crt"
        key_path = self.certs_dir / f"{device_id}.key"

        with open(cert_path, "wb") as f:
            f.write(cert_pem)

        with open(key_path, "wb") as f:
            f.write(key_pem)

        os.chmod(key_path, 0o600)

        # Store in Vault
        await self.vault.store_secret(
            f"devices/certificates/{device_id}",
            {
                "certificate": cert_pem.decode('utf-8'),
                "private_key": key_pem.decode('utf-8'),
                "fingerprint": cert_fingerprint,
                "serial_number": str(device_cert.serial_number),
                "not_valid_before": device_cert.not_valid_before.isoformat(),
                "not_valid_after": device_cert.not_valid_after.isoformat(),
                "issued_at": datetime.utcnow().isoformat()
            }
        )

        # Update database
        async with get_db() as session:
            await session.execute(
                update(Device).
                where(Device.id == device_id).
                values(
                    certificate_serial=str(device_cert.serial_number),
                    certificate_fingerprint=cert_fingerprint,
                    certificate_expires_at=device_cert.not_valid_after,
                    certificate_status='active'
                )
            )
            await session.commit()

        # Audit log
        await self.audit.log_security_event(
            event_type="device_certificate_issued",
            severity="INFO",
            details={
                "device_id": device_id,
                "hostname": device_hostname,
                "serial_number": str(device_cert.serial_number),
                "fingerprint": cert_fingerprint,
                "validity_days": validity_days
            }
        )

        logger.info(f"Certificate issued for device {device_id}")

        return {
            "certificate": cert_pem.decode('utf-8'),
            "private_key": key_pem.decode('utf-8'),
            "fingerprint": cert_fingerprint,
            "serial_number": str(device_cert.serial_number),
            "not_valid_before": device_cert.not_valid_before.isoformat(),
            "not_valid_after": device_cert.not_valid_after.isoformat()
        }

    async def revoke_device_cert(
        self,
        device_id: str,
        reason: str = "unspecified"
    ) -> bool:
        """
        Revoke device certificate

        Args:
            device_id: Device UUID
            reason: Revocation reason

        Returns:
            True if revocation successful
        """
        logger.info(f"Revoking certificate for device {device_id}")

        try:
            # Update database
            async with get_db() as session:
                await session.execute(
                    update(Device).
                    where(Device.id == device_id).
                    values(
                        certificate_status='revoked',
                        certificate_revoked_at=datetime.utcnow(),
                        certificate_revocation_reason=reason
                    )
                )
                await session.commit()

            # Mark as revoked in Vault
            await self.vault.store_secret(
                f"devices/certificates/{device_id}/revoked",
                {
                    "revoked_at": datetime.utcnow().isoformat(),
                    "reason": reason
                }
            )

            # Add to CRL (Certificate Revocation List)
            await self._add_to_crl(device_id)

            # Audit log
            await self.audit.log_security_event(
                event_type="device_certificate_revoked",
                severity="WARNING",
                details={
                    "device_id": device_id,
                    "reason": reason
                }
            )

            logger.info(f"Certificate revoked for device {device_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to revoke certificate: {e}")
            return False

    async def validate_device_cert(
        self,
        cert_data: bytes,
        device_ip: Optional[str] = None
    ) -> Optional[Device]:
        """
        Validate device certificate and return device info

        Args:
            cert_data: Certificate data in PEM format
            device_ip: Optional IP address to verify

        Returns:
            Device object if valid, None otherwise
        """
        try:
            # Parse certificate
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())

            # Check validity period
            now = datetime.utcnow()
            if now < cert.not_valid_before or now > cert.not_valid_after:
                logger.warning("Certificate expired or not yet valid")
                return None

            # Extract device ID from serial number attribute
            subject = cert.subject
            device_id = None
            for attribute in subject:
                if attribute.oid == NameOID.SERIAL_NUMBER:
                    device_id = attribute.value
                    break

            if not device_id:
                logger.warning("No device ID in certificate")
                return None

            # Check if certificate is revoked
            if await self._is_cert_revoked(device_id):
                logger.warning(f"Certificate for device {device_id} is revoked")
                return None

            # Verify certificate chain
            # In production, this would verify against the CA chain
            # For now, just check fingerprint

            fingerprint = hashes.Hash(hashes.SHA256(), backend=default_backend())
            fingerprint.update(cert_data)
            cert_fingerprint = fingerprint.finalize().hex()

            # Get device from database
            async with get_db() as session:
                result = await session.execute(
                    select(Device).where(
                        Device.id == device_id,
                        Device.certificate_fingerprint == cert_fingerprint,
                        Device.certificate_status == 'active'
                    )
                )
                device = result.scalar_one_or_none()

                if device:
                    # Verify IP if provided
                    if device_ip and device.ip_address != device_ip:
                        logger.warning(f"IP mismatch for device {device_id}")
                        return None

                    logger.info(f"Certificate validated for device {device_id}")
                    return device

            logger.warning(f"Device {device_id} not found or certificate mismatch")
            return None

        except Exception as e:
            logger.error(f"Certificate validation failed: {e}")
            return None

    async def rotate_device_certs(self, force: bool = False) -> Dict[str, int]:
        """
        Rotate expiring device certificates

        Args:
            force: Force rotation regardless of expiry

        Returns:
            Statistics of rotated certificates
        """
        logger.info("Starting device certificate rotation")

        stats = {
            "checked": 0,
            "rotated": 0,
            "failed": 0
        }

        # Get devices with certificates
        async with get_db() as session:
            result = await session.execute(
                select(Device).where(
                    Device.certificate_status == 'active'
                )
            )
            devices = result.scalars().all()

            for device in devices:
                stats["checked"] += 1

                # Check if certificate needs rotation
                if force or self._needs_rotation(device.certificate_expires_at):
                    try:
                        # Issue new certificate
                        new_cert = await self.issue_device_cert(
                            str(device.id),
                            device.hostname,
                            device.ip_address
                        )

                        # Deploy to device (would be done via secure channel)
                        # For now, just log
                        logger.info(f"Rotated certificate for {device.hostname}")
                        stats["rotated"] += 1

                    except Exception as e:
                        logger.error(f"Failed to rotate cert for {device.hostname}: {e}")
                        stats["failed"] += 1

        logger.info(f"Certificate rotation complete: {stats}")
        return stats

    def _needs_rotation(self, expires_at: datetime, days_before: int = 30) -> bool:
        """Check if certificate needs rotation"""
        if not expires_at:
            return True
        return (expires_at - datetime.utcnow()).days <= days_before

    async def _add_to_crl(self, device_id: str):
        """Add certificate to CRL"""
        # In production, this would update the CRL file/service
        crl_path = self.certs_dir / "crl.json"

        crl_data = {}
        if crl_path.exists():
            with open(crl_path, 'r') as f:
                import json
                crl_data = json.load(f)

        crl_data[device_id] = {
            "revoked_at": datetime.utcnow().isoformat()
        }

        with open(crl_path, 'w') as f:
            import json
            json.dump(crl_data, f, indent=2)

    async def _is_cert_revoked(self, device_id: str) -> bool:
        """Check if certificate is in CRL"""
        crl_path = self.certs_dir / "crl.json"

        if crl_path.exists():
            with open(crl_path, 'r') as f:
                import json
                crl_data = json.load(f)
                return device_id in crl_data

        return False

    async def get_certificate_status(self, device_id: str) -> Dict[str, any]:
        """
        Get certificate status for a device

        Args:
            device_id: Device UUID

        Returns:
            Certificate status information
        """
        async with get_db() as session:
            result = await session.execute(
                select(Device).where(Device.id == device_id)
            )
            device = result.scalar_one_or_none()

            if device:
                return {
                    "device_id": str(device.id),
                    "hostname": device.hostname,
                    "certificate_status": device.certificate_status,
                    "certificate_serial": device.certificate_serial,
                    "certificate_fingerprint": device.certificate_fingerprint,
                    "certificate_expires_at": device.certificate_expires_at.isoformat() if device.certificate_expires_at else None,
                    "needs_rotation": self._needs_rotation(device.certificate_expires_at) if device.certificate_expires_at else True
                }

        return None


# Import ipaddress for IP SANs
import ipaddress