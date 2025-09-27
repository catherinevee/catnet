"""
SAML Authentication Provider for CatNet
Implements SAML 2.0 Service Provider functionality
"""

from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import base64
import zlib
import uuid
from urllib.parse import urlencode, quote
import xmltodict
from lxml import etree
from signxml import XMLSigner, XMLVerifier
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509 import load_pem_x509_certificate
from fastapi import HTTPException, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import hashlib

from src.core.config import settings
from src.db.models import User, SAMLConfiguration, SAMLSession
from src.security.encryption import EncryptionManager
from src.security.audit import AuditLogger

class SAMLProvider:
    """
    SAML 2.0 Service Provider implementation
    Supports SP-initiated and IdP-initiated flows
    """

    def __init__(self):
        self.encryption_manager = EncryptionManager()
        self.audit_logger = AuditLogger()
        self.entity_id = settings.saml_sp_entity_id
        self.acs_url = settings.saml_sp_acs_url
        self.sls_url = settings.saml_sp_sls_url
        self._load_certificates()

    def _load_certificates(self):
        """
        Load SP certificates and keys
        """
        if settings.saml_sp_cert_path and settings.saml_sp_key_path:
            with open(settings.saml_sp_cert_path, 'rb') as f:
                self.sp_cert = f.read()
            with open(settings.saml_sp_key_path, 'rb') as f:
                self.sp_key = serialization.load_pem_private_key(f.read(), password=None)
        else:
            self.sp_cert = None
            self.sp_key = None

    async def register_idp(
        self,
        db: AsyncSession,
        idp_name: str,
        metadata_url: Optional[str] = None,
        metadata_xml: Optional[str] = None,
        entity_id: str = None,
        sso_url: str = None,
        slo_url: Optional[str] = None,
        x509_cert: str = None,
        attribute_mapping: Dict[str, str] = None
    ) -> SAMLConfiguration:
        """
        Register a SAML Identity Provider
        """
        if metadata_url or metadata_xml:
            metadata = await self._parse_metadata(metadata_url, metadata_xml)
            entity_id = metadata.get('entity_id', entity_id)
            sso_url = metadata.get('sso_url', sso_url)
            slo_url = metadata.get('slo_url', slo_url)
            x509_cert = metadata.get('x509_cert', x509_cert)

        if not all([entity_id, sso_url, x509_cert]):
            raise ValueError("Missing required IdP configuration")

        config = SAMLConfiguration(
            name=idp_name,
            entity_id=entity_id,
            sso_url=sso_url,
            slo_url=slo_url,
            x509_cert=x509_cert,
            metadata_url=metadata_url,
            attribute_mapping=attribute_mapping or {
                'email': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
                'name': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
                'groups': 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups'
            },
            is_active=True
        )

        db.add(config)
        await db.commit()
        await db.refresh(config)

        await self.audit_logger.log_event(
            db=db,
            action="saml.idp.register",
            details={
                "idp_name": idp_name,
                "entity_id": entity_id
            }
        )

        return config

    async def create_authn_request(
        self,
        db: AsyncSession,
        idp_name: str,
        relay_state: Optional[str] = None,
        force_authn: bool = False,
        name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    ) -> str:
        """
        Create SAML AuthnRequest for SP-initiated SSO
        """
        stmt = select(SAMLConfiguration).where(
            SAMLConfiguration.name == idp_name,
            SAMLConfiguration.is_active == True
        )
        result = await db.execute(stmt)
        idp = result.scalar_one_or_none()

        if not idp:
            raise HTTPException(status_code=404, detail="IdP not found")

        request_id = f"_{uuid.uuid4().hex}"
        issue_instant = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        authn_request = f"""
        <samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="{request_id}"
            Version="2.0"
            IssueInstant="{issue_instant}"
            Destination="{idp.sso_url}"
            AssertionConsumerServiceURL="{self.acs_url}"
            ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
            <saml:Issuer>{self.entity_id}</saml:Issuer>
            <samlp:NameIDPolicy Format="{name_id_format}" AllowCreate="true"/>
        </samlp:AuthnRequest>
        """

        if self.sp_key:
            authn_request = self._sign_request(authn_request)

        encoded_request = base64.b64encode(authn_request.encode()).decode()

        session = SAMLSession(
            session_id=request_id,
            idp_entity_id=idp.entity_id,
            relay_state=relay_state,
            request_id=request_id,
            expires_at=datetime.utcnow() + timedelta(minutes=5)
        )

        db.add(session)
        await db.commit()

        params = {
            'SAMLRequest': encoded_request
        }
        if relay_state:
            params['RelayState'] = relay_state

        redirect_url = f"{idp.sso_url}?{urlencode(params)}"

        await self.audit_logger.log_event(
            db=db,
            action="saml.authn.request",
            details={
                "idp": idp_name,
                "request_id": request_id
            }
        )

        return redirect_url

    async def process_saml_response(
        self,
        db: AsyncSession,
        saml_response: str,
        relay_state: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Process SAML Response from IdP
        """
        try:
            decoded_response = base64.b64decode(saml_response)
            response_xml = etree.fromstring(decoded_response)

            assertion = response_xml.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')
            if assertion is None:
                raise ValueError("No assertion found in SAML response")

            issuer = assertion.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Issuer').text

            stmt = select(SAMLConfiguration).where(
                SAMLConfiguration.entity_id == issuer,
                SAMLConfiguration.is_active == True
            )
            result = await db.execute(stmt)
            idp = result.scalar_one_or_none()

            if not idp:
                raise HTTPException(status_code=400, detail="Unknown IdP")

            if idp.x509_cert:
                self._verify_signature(response_xml, idp.x509_cert)

            conditions = assertion.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Conditions')
            if conditions is not None:
                not_before = conditions.get('NotBefore')
                not_on_or_after = conditions.get('NotOnOrAfter')
                if not self._validate_conditions(not_before, not_on_or_after):
                    raise ValueError("SAML assertion conditions not met")

            attributes = self._extract_attributes(assertion, idp.attribute_mapping)

            name_id = assertion.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Subject/'
                                    '{urn:oasis:names:tc:SAML:2.0:assertion}NameID').text

            user = await self._get_or_create_user(db, attributes, name_id)

            in_response_to = response_xml.get('InResponseTo')
            if in_response_to:
                stmt = select(SAMLSession).where(
                    SAMLSession.request_id == in_response_to
                )
                result = await db.execute(stmt)
                session = result.scalar_one_or_none()
                if session:
                    session.authenticated = True
                    session.user_id = user.id
                    await db.commit()

            await self.audit_logger.log_event(
                db=db,
                user=user,
                action="saml.login.success",
                details={
                    "idp": idp.name,
                    "name_id": name_id
                }
            )

            return {
                "user": user,
                "attributes": attributes,
                "name_id": name_id,
                "session_index": assertion.get('SessionIndex')
            }

        except Exception as e:
            await self.audit_logger.log_event(
                db=db,
                action="saml.login.failure",
                details={
                    "error": str(e)
                }
            )
            raise HTTPException(status_code=400, detail=f"SAML processing failed: {str(e)}")

    async def create_logout_request(
        self,
        db: AsyncSession,
        user: User,
        idp_name: str,
        name_id: str,
        session_index: Optional[str] = None
    ) -> str:
        """
        Create SAML LogoutRequest for Single Logout
        """
        stmt = select(SAMLConfiguration).where(
            SAMLConfiguration.name == idp_name,
            SAMLConfiguration.is_active == True
        )
        result = await db.execute(stmt)
        idp = result.scalar_one_or_none()

        if not idp or not idp.slo_url:
            raise HTTPException(status_code=400, detail="SLO not supported by IdP")

        request_id = f"_{uuid.uuid4().hex}"
        issue_instant = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        logout_request = f"""
        <samlp:LogoutRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="{request_id}"
            Version="2.0"
            IssueInstant="{issue_instant}"
            Destination="{idp.slo_url}">
            <saml:Issuer>{self.entity_id}</saml:Issuer>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>
            {"<samlp:SessionIndex>" + session_index + "</samlp:SessionIndex>" if session_index else ""}
        </samlp:LogoutRequest>
        """

        if self.sp_key:
            logout_request = self._sign_request(logout_request)

        encoded_request = base64.b64encode(logout_request.encode()).decode()

        params = {
            'SAMLRequest': encoded_request
        }

        redirect_url = f"{idp.slo_url}?{urlencode(params)}"

        await self.audit_logger.log_event(
            db=db,
            user=user,
            action="saml.logout.request",
            details={
                "idp": idp_name,
                "request_id": request_id
            }
        )

        return redirect_url

    async def get_sp_metadata(self) -> str:
        """
        Generate SP metadata XML
        """
        metadata = f"""
        <EntityDescriptor
            xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
            entityID="{self.entity_id}">
            <SPSSODescriptor
                AuthnRequestsSigned="{'true' if self.sp_key else 'false'}"
                WantAssertionsSigned="true"
                protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">

                {self._get_key_descriptor() if self.sp_cert else ""}

                <SingleLogoutService
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                    Location="{self.sls_url}"/>

                <AssertionConsumerService
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    Location="{self.acs_url}"
                    index="0"
                    isDefault="true"/>

                <AttributeConsumingService index="0">
                    <ServiceName xml:lang="en">CatNet</ServiceName>
                    <RequestedAttribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" isRequired="true"/>
                    <RequestedAttribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name" isRequired="true"/>
                    <RequestedAttribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/groups" isRequired="false"/>
                </AttributeConsumingService>
            </SPSSODescriptor>
        </EntityDescriptor>
        """

        return metadata

    async def _parse_metadata(
        self,
        metadata_url: Optional[str],
        metadata_xml: Optional[str]
    ) -> Dict[str, Any]:
        """
        Parse IdP metadata from URL or XML
        """
        if metadata_url:
            import httpx
            async with httpx.AsyncClient() as client:
                response = await client.get(metadata_url)
                metadata_xml = response.text

        if not metadata_xml:
            raise ValueError("No metadata provided")

        try:
            root = etree.fromstring(metadata_xml.encode())

            entity_id = root.get('entityID')

            sso_service = root.find('.//{urn:oasis:names:tc:SAML:2.0:metadata}SingleSignOnService')
            sso_url = sso_service.get('Location') if sso_service is not None else None

            slo_service = root.find('.//{urn:oasis:names:tc:SAML:2.0:metadata}SingleLogoutService')
            slo_url = slo_service.get('Location') if slo_service is not None else None

            cert_elem = root.find('.//{http://www.w3.org/2000/09/xmldsig#}X509Certificate')
            x509_cert = cert_elem.text.strip() if cert_elem is not None else None

            return {
                'entity_id': entity_id,
                'sso_url': sso_url,
                'slo_url': slo_url,
                'x509_cert': x509_cert
            }
        except Exception as e:
            raise ValueError(f"Failed to parse metadata: {str(e)}")

    def _sign_request(self, request_xml: str) -> str:
        """
        Sign SAML request with SP private key
        """
        if not self.sp_key:
            return request_xml

        root = etree.fromstring(request_xml.encode())
        signer = XMLSigner(
            method="detached",
            signature_algorithm="rsa-sha256",
            digest_algorithm="sha256"
        )
        signed = signer.sign(root, key=self.sp_key)
        return etree.tostring(signed, encoding='unicode')

    def _verify_signature(self, xml_element, x509_cert: str):
        """
        Verify XML signature with IdP certificate
        """
        cert_pem = f"-----BEGIN CERTIFICATE-----\n{x509_cert}\n-----END CERTIFICATE-----"
        cert = load_pem_x509_certificate(cert_pem.encode())

        verifier = XMLVerifier()
        try:
            verifier.verify(xml_element, x509_cert=cert)
        except Exception as e:
            raise ValueError(f"Signature verification failed: {str(e)}")

    def _validate_conditions(self, not_before: str, not_on_or_after: str) -> bool:
        """
        Validate SAML assertion time conditions
        """
        now = datetime.utcnow()

        if not_before:
            nb = datetime.strptime(not_before, "%Y-%m-%dT%H:%M:%SZ")
            if now < nb:
                return False

        if not_on_or_after:
            noa = datetime.strptime(not_on_or_after, "%Y-%m-%dT%H:%M:%SZ")
            if now >= noa:
                return False

        return True

    def _extract_attributes(
        self,
        assertion,
        attribute_mapping: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Extract attributes from SAML assertion
        """
        attributes = {}
        attribute_statement = assertion.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement')

        if attribute_statement is not None:
            for attribute in attribute_statement.findall('.//{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
                name = attribute.get('Name')
                values = [v.text for v in attribute.findall('.//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue')]

                for mapped_name, saml_name in attribute_mapping.items():
                    if saml_name == name:
                        attributes[mapped_name] = values[0] if len(values) == 1 else values

        return attributes

    async def _get_or_create_user(
        self,
        db: AsyncSession,
        attributes: Dict[str, Any],
        name_id: str
    ) -> User:
        """
        Get existing user or create new one from SAML attributes
        """
        email = attributes.get('email', name_id)

        stmt = select(User).where(User.email == email)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
            username = email.split('@')[0] if '@' in email else name_id
            full_name = attributes.get('name', username)

            user = User(
                username=username,
                email=email,
                full_name=full_name,
                is_active=True,
                is_superuser=False,
                saml_name_id=name_id,
                hashed_password=self.encryption_manager.encrypt(uuid.uuid4().hex)
            )

            db.add(user)
            await db.commit()
            await db.refresh(user)

        else:
            user.saml_name_id = name_id
            user.last_login_at = datetime.utcnow()
            await db.commit()

        return user

    def _get_key_descriptor(self) -> str:
        """
        Generate KeyDescriptor for SP certificate
        """
        if not self.sp_cert:
            return ""

        cert_content = self.sp_cert.decode().replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").strip()

        return f"""
        <KeyDescriptor use="signing">
            <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509Certificate>{cert_content}</X509Certificate>
                </X509Data>
            </KeyInfo>
        </KeyDescriptor>
        """


saml_provider = SAMLProvider()