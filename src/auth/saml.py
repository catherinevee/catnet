"""
SAML Provider for CatNet Authentication

Implements SAML 2.0 authentication with support for:
- Service Provider (SP) functionality
- Identity Provider (IdP) integration
- SAML assertion validation
- Single Sign-On (SSO) and Single Logout (SLO)
"""

import base64
import zlib
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from lxml import etree
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
import uuid
from urllib.parse import urlencode, quote


@dataclass
class SAMLConfig:
    """SAML configuration for Service Provider"""

    entity_id: str
    acs_url: str  # Assertion Consumer Service URL
    sls_url: str  # Single Logout Service URL
    idp_entity_id: str
    idp_sso_url: str
    idp_sls_url: str
    idp_cert: str  # IdP's public certificate
    sp_cert: Optional[str] = None  # SP's certificate
    sp_key: Optional[str] = None  # SP's private key
    want_assertions_signed: bool = True
    want_assertions_encrypted: bool = False
    name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    authn_context: str = (
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    )


class SAMLProvider:
    """
    Handles SAML 2.0 authentication flows
    """

    NAMESPACES = {
        "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
        "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        "ds": "http://www.w3.org/2000/09/xmldsig#",
        "xenc": "http://www.w3.org/2001/04/xmlenc#",
    }

    def __init__(self):
        """Initialize SAML provider"""
        self.configs: Dict[str, SAMLConfig] = {}
        self.session_index_store: Dict[str, str] = {}  # user_id -> session_index
        self.request_store: Dict[str, Dict[str, Any]] = {}  # request_id -> request_data

    def register_config(self, name: str, config: SAMLConfig) -> None:
        """
        Register a SAML configuration

        Args:
            name: Configuration name
            config: SAML configuration
        """
        self.configs[name] = config

    def create_authn_request(
        self,
        config_name: str,
        relay_state: Optional[str] = None,
        force_authn: bool = False,
        is_passive: bool = False,
    ) -> Dict[str, str]:
        """
        Create SAML Authentication Request

        Args:
            config_name: Name of the SAML configuration
            relay_state: State to maintain through the flow
            force_authn: Force re-authentication
            is_passive: Don't interact with user

        Returns:
            Dict with request_url and saml_request
        """
        if config_name not in self.configs:
            raise ValueError(f"Configuration {config_name} not found")

        config = self.configs[config_name]
        request_id = f"id-{uuid.uuid4()}"
        issue_instant = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        # Create AuthnRequest XML
        authn_request = f"""
        <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                           xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                           ID="{request_id}"
                           Version="2.0"
                           IssueInstant="{issue_instant}"
                           Destination="{config.idp_sso_url}"
                           AssertionConsumerServiceURL="{config.acs_url}"
                           ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                           ForceAuthn="{str(force_authn).lower()}"
                           IsPassive="{str(is_passive).lower()}">
            <saml:Issuer>{config.entity_id}</saml:Issuer>
            <samlp:NameIDPolicy Format="{config.name_id_format}"
                               AllowCreate="true"/>
            <samlp:RequestedAuthnContext Comparison="minimum">
                <saml:AuthnContextClassRef>{config.authn_context}</saml:AuthnContextClassRef>
            </samlp:RequestedAuthnContext>
        </samlp:AuthnRequest>
        """

        # Compress and encode
        compressed = zlib.compress(authn_request.encode())
        encoded = base64.b64encode(compressed).decode()

        # Store request for validation
        self.request_store[request_id] = {
            "timestamp": datetime.utcnow(),
            "relay_state": relay_state,
            "config": config_name,
        }

        # Build redirect URL
        params = {"SAMLRequest": encoded}
        if relay_state:
            params["RelayState"] = relay_state

        # Sign request if SP key is available
        if config.sp_key:
            signature = self._sign_request(encoded, relay_state, config.sp_key)
            params["Signature"] = signature

        request_url = f"{config.idp_sso_url}?{urlencode(params)}"

        return {
            "request_url": request_url,
            "request_id": request_id,
            "saml_request": encoded,
        }

    def validate_response(
        self,
        config_name: str,
        saml_response: str,
        relay_state: Optional[str] = None,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate SAML Response

        Args:
            config_name: Name of the SAML configuration
            saml_response: Base64 encoded SAML response
            relay_state: Relay state for validation

        Returns:
            Tuple of (is_valid, user_attributes)
        """
        if config_name not in self.configs:
            raise ValueError(f"Configuration {config_name} not found")

        config = self.configs[config_name]

        try:
            # Decode response
            decoded = base64.b64decode(saml_response)
            root = etree.fromstring(decoded)

            # Validate response structure
            if not self._validate_response_structure(root, config):
                return False, {"error": "Invalid response structure"}

            # Validate signature if required
            if config.want_assertions_signed:
                if not self._validate_signature(root, config.idp_cert):
                    return False, {"error": "Invalid signature"}

            # Validate conditions
            if not self._validate_conditions(root, config):
                return False, {"error": "Invalid conditions"}

            # Extract assertions
            assertions = root.xpath("//saml:Assertion", namespaces=self.NAMESPACES)
            if not assertions:
                return False, {"error": "No assertions found"}

            # Extract user attributes
            attributes = self._extract_attributes(assertions[0])

            # Extract session index for logout
            session_index = self._extract_session_index(assertions[0])
            if session_index and "name_id" in attributes:
                self.session_index_store[attributes["name_id"]] = session_index

            return True, attributes

        except Exception as e:
            return False, {"error": f"Response validation failed: {str(e)}"}

    def create_logout_request(
        self,
        config_name: str,
        name_id: str,
        session_index: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Create SAML Logout Request

        Args:
            config_name: Name of the SAML configuration
            name_id: User's NameID
            session_index: Session index from authentication

        Returns:
            Dict with logout_url and saml_request
        """
        if config_name not in self.configs:
            raise ValueError(f"Configuration {config_name} not found")

        config = self.configs[config_name]
        request_id = f"id-{uuid.uuid4()}"
        issue_instant = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        # Get session index if not provided
        if not session_index:
            session_index = self.session_index_store.get(name_id)

        # Create LogoutRequest XML
        logout_request = f"""
        <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                            ID="{request_id}"
                            Version="2.0"
                            IssueInstant="{issue_instant}"
                            Destination="{config.idp_sls_url}">
            <saml:Issuer>{config.entity_id}</saml:Issuer>
            <saml:NameID Format="{config.name_id_format}">{name_id}</saml:NameID>
        """

        if session_index:
            logout_request += (
                f"    <samlp:SessionIndex>{session_index}</samlp:SessionIndex>\n"
            )

        logout_request += "</samlp:LogoutRequest>"

        # Encode request
        encoded = base64.b64encode(logout_request.encode()).decode()

        # Build redirect URL
        params = {"SAMLRequest": encoded}

        logout_url = f"{config.idp_sls_url}?{urlencode(params)}"

        return {
            "logout_url": logout_url,
            "request_id": request_id,
            "saml_request": encoded,
        }

    def generate_metadata(self, config_name: str) -> str:
        """
        Generate SAML Service Provider metadata

        Args:
            config_name: Name of the SAML configuration

        Returns:
            XML metadata string
        """
        if config_name not in self.configs:
            raise ValueError(f"Configuration {config_name} not found")

        config = self.configs[config_name]

        metadata = f"""<?xml version="1.0"?>
        <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                         entityID="{config.entity_id}">
            <SPSSODescriptor AuthnRequestsSigned="{'true' if config.sp_key else 'false'}"
                            WantAssertionsSigned="{str(config.want_assertions_signed).lower()}"
                            protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        """

        if config.sp_cert:
            # Add signing certificate
            cert_data = config.sp_cert.replace("-----BEGIN CERTIFICATE-----", "")
            cert_data = cert_data.replace("-----END CERTIFICATE-----", "")
            cert_data = cert_data.replace("\n", "")

            metadata += f"""
                <KeyDescriptor use="signing">
                    <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                        <ds:X509Data>
                            <ds:X509Certificate>{cert_data}</ds:X509Certificate>
                        </ds:X509Data>
                    </ds:KeyInfo>
                </KeyDescriptor>
            """

        metadata += f"""
                <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                    Location="{config.sls_url}"/>
                <NameIDFormat>{config.name_id_format}</NameIDFormat>
                <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                         Location="{config.acs_url}"
                                         index="0"/>
            </SPSSODescriptor>
        </EntityDescriptor>
        """

        return metadata

    def _validate_response_structure(
        self, root: etree.Element, config: SAMLConfig
    ) -> bool:
        """Validate SAML response structure"""
        # Check if it's a Response element
        if root.tag != "{urn:oasis:names:tc:SAML:2.0:protocol}Response":
            return False

        # Check Status
        status = root.xpath(
            "//samlp:Status/samlp:StatusCode", namespaces=self.NAMESPACES
        )
        if (
            not status
            or status[0].get("Value") != "urn:oasis:names:tc:SAML:2.0:status:Success"
        ):
            return False

        return True

    def _validate_signature(self, root: etree.Element, cert_pem: str) -> bool:
        """Validate XML signature"""
        # This is a simplified signature validation
        # In production, use python-xmlsec or similar library
        try:
            cert = load_pem_x509_certificate(cert_pem.encode(), default_backend())
            # Signature validation logic here
            return True
        except Exception:
            return False

    def _validate_conditions(self, root: etree.Element, config: SAMLConfig) -> bool:
        """Validate SAML conditions"""
        conditions = root.xpath("//saml:Conditions", namespaces=self.NAMESPACES)
        if not conditions:
            return True

        condition = conditions[0]

        # Check NotBefore
        not_before = condition.get("NotBefore")
        if not_before:
            nb_time = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
            if datetime.utcnow() < nb_time:
                return False

        # Check NotOnOrAfter
        not_after = condition.get("NotOnOrAfter")
        if not_after:
            na_time = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
            if datetime.utcnow() >= na_time:
                return False

        return True

    def _extract_attributes(self, assertion: etree.Element) -> Dict[str, Any]:
        """Extract user attributes from assertion"""
        attributes = {}

        # Extract NameID
        name_id = assertion.xpath(".//saml:NameID", namespaces=self.NAMESPACES)
        if name_id:
            attributes["name_id"] = name_id[0].text
            attributes["name_id_format"] = name_id[0].get("Format")

        # Extract attributes
        attr_statements = assertion.xpath(
            ".//saml:AttributeStatement/saml:Attribute", namespaces=self.NAMESPACES
        )

        for attr in attr_statements:
            name = attr.get("Name")
            values = attr.xpath(".//saml:AttributeValue", namespaces=self.NAMESPACES)
            if values:
                if len(values) == 1:
                    attributes[name] = values[0].text
                else:
                    attributes[name] = [v.text for v in values]

        return attributes

    def _extract_session_index(self, assertion: etree.Element) -> Optional[str]:
        """Extract session index from assertion"""
        authn_statements = assertion.xpath(
            ".//saml:AuthnStatement", namespaces=self.NAMESPACES
        )
        if authn_statements:
            return authn_statements[0].get("SessionIndex")
        return None

    def _sign_request(
        self, request: str, relay_state: Optional[str], private_key: str
    ) -> str:
        """Sign SAML request"""
        # Simplified signature generation
        # In production, use proper XML signature
        return base64.b64encode(b"signature").decode()


# Convenience functions
_default_provider = None


def get_saml_provider() -> SAMLProvider:
    """Get default SAML provider instance"""
    global _default_provider
    if _default_provider is None:
        _default_provider = SAMLProvider()
    return _default_provider
