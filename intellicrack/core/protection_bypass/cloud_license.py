"""Cloud-based licensing protocol interception and bypass module.

This module provides comprehensive TLS interception, protocol state management,
and response synthesis capabilities for defeating cloud-based software licensing
systems including FlexNet Cloud, Sentinel Cloud, Azure AD, Google OAuth, AWS Cognito,
Adobe Creative Cloud, and Microsoft 365.

Supports multiple protocols: HTTP REST, SOAP, gRPC, WebSocket, and proprietary
binary protocols with sophisticated certificate generation, JWT manipulation,
and cryptographic signature synthesis.

Copyright (C) 2025 Zachary Flint.

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import base64
import json
import os
import re
import struct
import threading
import time
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any


try:
    import jwt

    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    jwt = None

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    x509 = None
    default_backend = None
    hashes = None
    serialization = None
    rsa = None
    NameOID = None

try:
    from mitmproxy import http
    from mitmproxy.addons import anticache
    from mitmproxy.options import Options
    from mitmproxy.tools.dump import DumpMaster

    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False
    http = None
    anticache = None
    Options = None
    DumpMaster = None

from intellicrack.utils.logger import get_logger


logger = get_logger(__name__)


class ProtocolType(Enum):
    """Cloud licensing protocol types supported for interception and bypass."""

    HTTP_REST = "http_rest"
    SOAP = "soap"
    GRPC = "grpc"
    WEBSOCKET = "websocket"
    FLEXNET = "flexnet"
    SENTINEL = "sentinel"
    AZURE_AD = "azure_ad"
    AWS_COGNITO = "aws_cognito"
    GOOGLE_OAUTH = "google_oauth"
    ADOBE_IMS = "adobe_ims"
    MICROSOFT_365 = "microsoft_365"
    CUSTOM = "custom"


class LicenseState(Enum):
    """License validation state machine states for cloud licensing protocols."""

    INITIAL = "initial"
    AUTHENTICATING = "authenticating"
    AUTHENTICATED = "authenticated"
    VALIDATING = "validating"
    VALIDATED = "validated"
    ACTIVE = "active"
    RENEWING = "renewing"
    EXPIRED = "expired"
    ERROR = "error"


class TLSInterceptor:
    """TLS/SSL traffic interceptor with dynamic certificate generation for MITM attacks on cloud license servers."""

    def __init__(self, target_host: str, target_port: int = 443) -> None:
        """Initialize TLS interceptor with target configuration.

        Args:
            target_host: Target cloud license server hostname to intercept
            target_port: Target HTTPS port (default 443)

        Raises:
            ImportError: If cryptography library is not available

        """
        if not CRYPTOGRAPHY_AVAILABLE:
            error_msg = "cryptography library is required for TLS interception. Install with: pip install cryptography"
            logger.error(error_msg)
            raise ImportError(error_msg)

        self.target_host = target_host
        self.target_port = target_port
        self.certificate = None
        self.private_key = None
        self.ca_cert = None
        self.ca_key = None
        self.backend = default_backend()
        self._init_ca()

    def _init_ca(self) -> None:
        """Initialize or load CA certificate and private key for signing intercepted certificates.

        Generates a new 4096-bit RSA CA certificate if one doesn't exist, or loads existing CA from disk.
        """
        ca_path = Path.home() / ".intellicrack" / "certs"
        ca_path.mkdir(parents=True, exist_ok=True)

        ca_cert_file = ca_path / "intellicrack-ca.crt"
        ca_key_file = ca_path / "intellicrack-ca.key"

        if ca_cert_file.exists() and ca_key_file.exists():
            with open(ca_cert_file, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read(), self.backend)
            with open(ca_key_file, "rb") as f:
                self.ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=self.backend)
        else:
            self.ca_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=self.backend,
            )

            subject = issuer = x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intellicrack Research"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "Intellicrack CA"),
                ]
            )

            self.ca_cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(self.ca_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.utcnow())
                .not_valid_after(datetime.utcnow() + timedelta(days=3650))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=None),
                    critical=True,
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=True,
                        crl_sign=True,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .sign(self.ca_key, hashes.SHA256(), backend=self.backend)
            )

            with open(ca_cert_file, "wb") as f:
                f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))
            with open(ca_key_file, "wb") as f:
                f.write(
                    self.ca_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )

    def generate_certificate(self, hostname: str) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Generate a signed TLS certificate for intercepting the target hostname.

        Args:
            hostname: Target hostname to generate certificate for (e.g., "license.example.com")

        Returns:
            Tuple of (X.509 certificate, RSA private key) valid for 1 year with wildcard SAN

        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend,
        )

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, hostname),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName(hostname),
                        x509.DNSName(f"*.{hostname}"),
                    ]
                ),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                    ]
                ),
                critical=False,
            )
            .sign(self.ca_key, hashes.SHA256(), backend=self.backend)
        )

        return cert, private_key

    def get_ca_cert_path(self) -> Path:
        """Get path to CA certificate file for installing as trusted root.

        Returns:
            Path to Intellicrack CA certificate in user's home directory

        """
        return Path.home() / ".intellicrack" / "certs" / "intellicrack-ca.crt"


class ProtocolStateMachine:
    """State machine for tracking cloud license protocol authentication and validation flows."""

    def __init__(self, protocol_type: ProtocolType) -> None:
        """Initialize protocol state machine.

        Args:
            protocol_type: Type of cloud licensing protocol to manage state for

        """
        self.protocol_type = protocol_type
        self.state = LicenseState.INITIAL
        self.session_data = {}
        self.tokens = {}
        self.transitions = {}
        self._init_transitions()

    def _init_transitions(self) -> None:
        """Initialize valid state transition mappings for license protocol flows."""
        self.transitions = {
            LicenseState.INITIAL: [LicenseState.AUTHENTICATING],
            LicenseState.AUTHENTICATING: [LicenseState.AUTHENTICATED, LicenseState.ERROR],
            LicenseState.AUTHENTICATED: [LicenseState.VALIDATING],
            LicenseState.VALIDATING: [LicenseState.VALIDATED, LicenseState.ERROR],
            LicenseState.VALIDATED: [LicenseState.ACTIVE],
            LicenseState.ACTIVE: [LicenseState.RENEWING, LicenseState.EXPIRED],
            LicenseState.RENEWING: [LicenseState.ACTIVE, LicenseState.ERROR],
            LicenseState.EXPIRED: [LicenseState.AUTHENTICATING],
            LicenseState.ERROR: [LicenseState.INITIAL],
        }

    def transition(self, new_state: LicenseState) -> bool:
        """Attempt to transition to a new state if valid.

        Args:
            new_state: Target license state to transition to

        Returns:
            True if transition successful, False if invalid transition

        """
        if new_state in self.transitions.get(self.state, []):
            logger.debug(f"State transition: {self.state} -> {new_state}")
            self.state = new_state
            return True
        logger.warning(f"Invalid state transition: {self.state} -> {new_state}")
        return False

    def store_token(self, token_type: str, token: str) -> None:
        """Store an authentication/authorization token with expiration tracking.

        Args:
            token_type: Type of token (access_token, refresh_token, id_token, etc.)
            token: Token value to store

        """
        self.tokens[token_type] = {
            "token": token,
            "timestamp": time.time(),
            "expires_at": time.time() + 3600,
        }

    def get_token(self, token_type: str) -> str | None:
        """Retrieve a stored token if not expired.

        Args:
            token_type: Type of token to retrieve

        Returns:
            Token value if exists and not expired, None otherwise

        """
        token_data = self.tokens.get(token_type)
        if token_data and token_data["expires_at"] > time.time():
            return token_data["token"]
        return None

    def store_session_data(self, key: str, value: object) -> None:
        """Store arbitrary session data for protocol context.

        Args:
            key: Data key identifier
            value: Data value to store

        """
        self.session_data[key] = value

    def get_session_data(self, key: str) -> object | None:
        """Retrieve stored session data.

        Args:
            key: Data key identifier

        Returns:
            Stored value or None if not found

        """
        return self.session_data.get(key)


class ResponseSynthesizer:
    """Synthesizes authentic-looking license validation responses for various cloud protocols."""

    def __init__(self) -> None:
        """Initialize response synthesizer with RSA key generation and response templates.

        Raises:
            ImportError: If cryptography library is not available

        """
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("cryptography library is required for response synthesis. Install with: pip install cryptography")

        self.backend = default_backend()
        self.rsa_keys = {}
        self.templates = {}
        self._init_templates()

    def _init_templates(self) -> None:
        """Initialize response templates for HTTP REST, SOAP, and other protocols."""
        self.templates = {
            ProtocolType.HTTP_REST: {
                "license_validate": {
                    "valid": True,
                    "status": "active",
                    "type": "enterprise",
                    "expires": int(time.time() + 365 * 86400),
                    "features": ["all"],
                    "seats": 999999,
                    "user_id": "intellicrack-user",
                },
                "subscription_status": {
                    "active": True,
                    "plan": "enterprise",
                    "renewal_date": int(time.time() + 365 * 86400),
                    "auto_renew": True,
                    "payment_method": "valid",
                },
                "entitlements": {
                    "products": [],
                    "quota": {"used": 0, "total": 999999},
                    "features": {"all": True},
                },
            },
            ProtocolType.SOAP: {
                "license_check": """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <LicenseCheckResponse>
            <Status>ACTIVE</Status>
            <Valid>true</Valid>
            <ExpiryDate>{expiry_date}</ExpiryDate>
            <LicenseType>ENTERPRISE</LicenseType>
            <Features>ALL</Features>
        </LicenseCheckResponse>
    </soap:Body>
</soap:Envelope>""",
            },
        }

    def get_rsa_key(self, key_id: str = "default") -> rsa.RSAPrivateKey:
        """Get or generate an RSA private key for JWT signing.

        Args:
            key_id: Key identifier for managing multiple keys

        Returns:
            RSA private key (2048-bit) for signing tokens

        """
        if key_id not in self.rsa_keys:
            self.rsa_keys[key_id] = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=self.backend,
            )
        return self.rsa_keys[key_id]

    def generate_jwt(self, payload: dict[str, Any], algorithm: str = "RS256", key_id: str = "default") -> str:
        """Generate a signed JWT token for authentication/authorization.

        Args:
            payload: JWT claims dictionary
            algorithm: Signing algorithm (RS256, RS512, HS256, etc.)
            key_id: Key identifier for RS algorithms

        Returns:
            Encoded JWT string with signature

        Raises:
            ImportError: If PyJWT library is not available

        """
        if not JWT_AVAILABLE:
            error_msg = "PyJWT library is required for JWT generation. Install with: pip install PyJWT"
            logger.error(error_msg)
            raise ImportError(error_msg)

        if "iat" not in payload:
            payload["iat"] = int(time.time())
        if "exp" not in payload:
            payload["exp"] = int(time.time()) + 3600

        if algorithm.startswith("RS") or not algorithm.startswith("HS"):
            key = self.get_rsa_key(key_id)
        else:
            key = os.urandom(32)
        return jwt.encode(payload, key, algorithm=algorithm)

    def synthesize_oauth_response(self, provider: str, config: dict[str, Any]) -> dict[str, Any]:
        """Synthesize OAuth 2.0 response for various cloud identity providers.

        Args:
            provider: Provider type (azure, google, cognito, or generic)
            config: Provider-specific configuration parameters

        Returns:
            Dictionary containing access_token, token_type, expires_in, and provider-specific fields

        """
        if provider == "azure":
            return self._synthesize_azure_ad(config)
        if provider == "google":
            return self._synthesize_google_oauth(config)
        if provider == "cognito":
            return self._synthesize_aws_cognito(config)
        return self._synthesize_generic_oauth(config)

    def _synthesize_azure_ad(self, config: dict[str, Any]) -> dict[str, Any]:
        """Synthesize Azure AD OAuth 2.0 token response with proper JWT claims.

        Args:
            config: Azure AD configuration (tenant_id, client_id, resource)

        Returns:
            Azure AD token response with access_token and refresh_token

        """
        tenant_id = config.get("tenant_id", "common")
        client_id = config.get("client_id", self._generate_uuid())

        token_payload = {
            "aud": config.get("resource", "https://graph.microsoft.com"),
            "iss": f"https://sts.windows.net/{tenant_id}/",
            "iat": int(time.time()),
            "nbf": int(time.time()),
            "exp": int(time.time()) + 3600,
            "aio": base64.b64encode(os.urandom(48)).decode(),
            "appid": client_id,
            "appidacr": "1",
            "idp": f"https://sts.windows.net/{tenant_id}/",
            "oid": self._generate_uuid(),
            "sub": self._generate_uuid(),
            "tid": tenant_id,
            "uti": base64.b64encode(os.urandom(16)).decode().rstrip("="),
            "ver": "1.0",
        }

        access_token = self.generate_jwt(token_payload)

        return {
            "token_type": "Bearer",
            "access_token": access_token,
            "expires_in": 3600,
            "refresh_token": base64.b64encode(os.urandom(128)).decode(),
        }

    def _synthesize_google_oauth(self, config: dict[str, Any]) -> dict[str, Any]:
        """Synthesize Google OAuth 2.0 token response with id_token.

        Args:
            config: Google OAuth configuration (client_id, email)

        Returns:
            Google OAuth response with access_token, id_token, and refresh_token

        """
        client_id = config.get("client_id", self._generate_uuid())

        token_payload = {
            "iss": "https://accounts.google.com",
            "sub": str(abs(hash(config.get("email", "user@gmail.com")))),
            "azp": client_id,
            "aud": client_id,
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "email": config.get("email", "user@gmail.com"),
            "email_verified": True,
        }

        id_token = self.generate_jwt(token_payload)
        access_token = f"ya29.{base64.b64encode(os.urandom(64)).decode().rstrip('=')}"

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": id_token,
            "refresh_token": f"1//{base64.b64encode(os.urandom(32)).decode().rstrip('=')}",
        }

    def _synthesize_aws_cognito(self, config: dict[str, Any]) -> dict[str, Any]:
        """Synthesize AWS Cognito token response with IdToken and AccessToken.

        Args:
            config: Cognito configuration (region, user_pool_id, client_id, username)

        Returns:
            Cognito token response with IdToken, AccessToken, and RefreshToken

        """
        region = config.get("region", "us-east-1")
        user_pool_id = config.get("user_pool_id", f"{region}_Example")
        client_id = config.get("client_id", self._generate_uuid())

        id_token_payload = {
            "sub": self._generate_uuid(),
            "aud": client_id,
            "email_verified": True,
            "iss": f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}",
            "cognito:username": config.get("username", "testuser"),
            "token_use": "id",
            "auth_time": int(time.time()),
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }

        access_token_payload = {
            "sub": id_token_payload["sub"],
            "iss": id_token_payload["iss"],
            "client_id": client_id,
            "token_use": "access",
            "scope": "aws.cognito.signin.user.admin",
            "auth_time": id_token_payload["auth_time"],
            "exp": id_token_payload["exp"],
            "iat": id_token_payload["iat"],
            "jti": self._generate_uuid(),
        }

        return {
            "IdToken": self.generate_jwt(id_token_payload),
            "AccessToken": self.generate_jwt(access_token_payload),
            "RefreshToken": base64.b64encode(os.urandom(256)).decode(),
            "ExpiresIn": 3600,
            "TokenType": "Bearer",
        }

    def _synthesize_generic_oauth(self, config: dict[str, Any]) -> dict[str, Any]:
        """Synthesize generic OAuth 2.0 token response.

        Args:
            config: OAuth configuration (issuer, audience, scope)

        Returns:
            Generic OAuth response with access_token and refresh_token

        """
        token_payload = {
            "sub": self._generate_uuid(),
            "iss": config.get("issuer", "https://auth.example.com"),
            "aud": config.get("audience", "api.example.com"),
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "scope": config.get("scope", "read write"),
        }

        return {
            "access_token": self.generate_jwt(token_payload),
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": base64.b64encode(os.urandom(32)).decode(),
        }

    def synthesize_rest_response(self, endpoint: str, method: str, request_data: dict) -> dict[str, Any]:
        """Synthesize REST API license validation response.

        Args:
            endpoint: API endpoint path
            method: HTTP method
            request_data: Request payload

        Returns:
            Synthesized REST response dictionary

        """
        endpoint_patterns = {
            r"/api/license/validate": self.templates[ProtocolType.HTTP_REST]["license_validate"],
            r"/api/subscription/status": self.templates[ProtocolType.HTTP_REST]["subscription_status"],
            r"/api/entitlements": self.templates[ProtocolType.HTTP_REST]["entitlements"],
            r"/api/auth/token": {
                "access_token": self.generate_jwt({}),
                "token_type": "Bearer",
                "expires_in": 3600,
            },
            r"/api/features": {
                "features": ["all"],
                "enabled": True,
                "limits": {"users": 999999, "api_calls": -1},
            },
        }

        return next(
            (
                response.copy() if isinstance(response, dict) else response
                for pattern, response in endpoint_patterns.items()
                if re.search(pattern, endpoint)
            ),
            {"success": True, "status": "active", "valid": True},
        )

    def synthesize_soap_response(self, action: str, request_body: str) -> str:
        """Synthesize SOAP XML license validation response.

        Args:
            action: SOAP action name
            request_body: SOAP request XML

        Returns:
            SOAP response XML string

        """
        soap_patterns = {
            "CheckLicense": "license_check",
            "ValidateLicense": "license_check",
            "GetLicenseStatus": "license_check",
        }

        template_key = next(
            (key for pattern, key in soap_patterns.items() if pattern in action or pattern in request_body),
            None,
        )
        if template_key and template_key in self.templates[ProtocolType.SOAP]:
            template = self.templates[ProtocolType.SOAP][template_key]
            expiry_date = (datetime.utcnow() + timedelta(days=365)).isoformat()
            return template.format(expiry_date=expiry_date)

        return """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <Response>
            <Status>SUCCESS</Status>
            <Valid>true</Valid>
        </Response>
    </soap:Body>
</soap:Envelope>"""

    def synthesize_grpc_response(self, method: str, request_data: bytes) -> bytes:
        """Synthesize gRPC license validation response.

        Args:
            method: gRPC method name
            request_data: Protobuf encoded request

        Returns:
            Protobuf encoded response bytes

        """
        response_data = {
            "license": {
                "id": self._generate_uuid(),
                "status": "ACTIVE",
                "type": "ENTERPRISE",
                "expires_at": int(time.time() + 31536000),
                "features": [],
                "limits": {"users": 999999, "api_calls": -1, "storage": -1},
            },
        }

        return self._encode_protobuf(response_data)

    def _encode_protobuf(self, data: dict) -> bytes:
        """Encode dictionary to protobuf binary format.

        Args:
            data: Dictionary to encode

        Returns:
            Protobuf encoded bytes

        """
        result = bytearray()

        def encode_varint(value: int) -> bytes:
            buf = bytearray()
            while value > 127:
                buf.append((value & 0x7F) | 0x80)
                value >>= 7
            buf.append(value)
            return bytes(buf)

        def encode_field(field_num: int, value: object) -> None:
            if isinstance(value, str):
                wire_type = 2
                tag = (field_num << 3) | wire_type
                result.extend(encode_varint(tag))
                encoded = value.encode()
                result.extend(encode_varint(len(encoded)))
                result.extend(encoded)
            elif isinstance(value, int):
                wire_type = 0
                tag = (field_num << 3) | wire_type
                result.extend(encode_varint(tag))
                result.extend(encode_varint(value))
            elif isinstance(value, dict):
                nested = self._encode_protobuf(value)
                wire_type = 2
                tag = (field_num << 3) | wire_type
                result.extend(encode_varint(tag))
                result.extend(encode_varint(len(nested)))
                result.extend(nested)
            elif isinstance(value, list):
                for item in value:
                    encode_field(field_num, item)
                return

        field_num = 1
        for _key, value in data.items():
            encode_field(field_num, value)
            field_num += 1

        return bytes(result)

    def synthesize_websocket_frame(self, message_type: str) -> bytes:
        """Synthesize WebSocket frame for license updates.

        Args:
            message_type: Message type (license_valid, heartbeat, auth_success)

        Returns:
            WebSocket frame bytes

        """
        frames = {
            "license_valid": {
                "op": 1,
                "type": "LICENSE_UPDATE",
                "data": {
                    "status": "active",
                    "valid": True,
                    "expires": int(time.time() + 365 * 86400),
                },
            },
            "heartbeat": {"op": 11, "type": "HEARTBEAT_ACK"},
            "auth_success": {
                "op": 0,
                "type": "AUTH_SUCCESS",
                "data": {"token": self.generate_jwt({}), "user_id": "intellicrack"},
            },
        }

        message = frames.get(message_type, frames["license_valid"])
        return self._encode_websocket_frame(json.dumps(message))

    def _encode_websocket_frame(self, data: str) -> bytes:
        """Encode data as WebSocket frame.

        Args:
            data: String data to encode

        Returns:
            WebSocket frame bytes

        """
        payload = data.encode()
        frame = bytearray()

        frame.append(0x81)

        length = len(payload)
        if length <= 125:
            frame.append(length)
        elif length <= 65535:
            frame.append(126)
            frame.extend(struct.pack(">H", length))
        else:
            frame.append(127)
            frame.extend(struct.pack(">Q", length))

        frame.extend(payload)
        return bytes(frame)

    def _generate_uuid(self) -> str:
        """Generate RFC 4122 compliant UUID v4.

        Returns:
            UUID string in canonical format

        """
        random_bytes = bytearray(os.urandom(16))
        random_bytes[6] = (random_bytes[6] & 0x0F) | 0x40
        random_bytes[8] = (random_bytes[8] & 0x3F) | 0x80
        hex_str = random_bytes.hex()
        return f"{hex_str[:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:32]}"


class MITMProxyAddon:
    """mitmproxy addon for intercepting and modifying license server traffic."""

    def __init__(
        self,
        intercept_rules: dict[str, Any],
        state_machine: ProtocolStateMachine,
        synthesizer: ResponseSynthesizer,
    ) -> None:
        """Initialize MITM proxy addon with interception rules.

        Args:
            intercept_rules: Dictionary of block/modify rules
            state_machine: Protocol state machine instance
            synthesizer: Response synthesizer instance

        """
        self.intercept_rules = intercept_rules
        self.state_machine = state_machine
        self.synthesizer = synthesizer
        self.request_count = 0
        self.intercepted_requests = []

    def request(self, flow: http.HTTPFlow) -> None:
        """Handle intercepted HTTP request.

        Args:
            flow: mitmproxy HTTPFlow object

        """
        self.request_count += 1

        url = flow.request.pretty_url
        method = flow.request.method
        headers = dict(flow.request.headers)

        logger.debug(f"Intercepted request: {method} {url}")

        if should_block := self._check_block_rules(url, method, headers):
            logger.info(f"Blocking request to {url} (rule match: {should_block})")
            flow.response = http.Response.make(
                403,
                b"Blocked by Intellicrack",
                {"Content-Type": "text/plain"},
            )
            return

        self._apply_request_modifications(flow)

        self.intercepted_requests.append(
            {
                "url": url,
                "method": method,
                "timestamp": time.time(),
                "headers": headers,
            }
        )

    def response(self, flow: http.HTTPFlow) -> None:
        """Handle intercepted HTTP response.

        Args:
            flow: mitmproxy HTTPFlow object

        """
        url = flow.request.pretty_url

        if should_modify := self._check_modify_rules(url):
            logger.info(f"Modifying response for {url} (rule match: {should_modify})")
            self._synthesize_response(flow)

    def _check_block_rules(self, url: str, method: str, headers: dict) -> bool:
        """Check if request should be blocked.

        Args:
            url: Request URL
            method: HTTP method
            headers: Request headers

        Returns:
            True if should block, False otherwise

        """
        block_rules = self.intercept_rules.get("block", [])
        for rule in block_rules:
            if "url_pattern" in rule and re.search(rule["url_pattern"], url):
                return True
            if "method" in rule and rule["method"] == method:
                return True
        return False

    def _check_modify_rules(self, url: str) -> bool:
        """Check if response should be modified.

        Args:
            url: Request URL

        Returns:
            True if should modify, False otherwise

        """
        modify_rules = self.intercept_rules.get("modify", [])
        return any("url_pattern" in rule and re.search(rule["url_pattern"], url) for rule in modify_rules)

    def _apply_request_modifications(self, flow: http.HTTPFlow) -> None:
        """Apply modifications to intercepted request.

        Args:
            flow: mitmproxy HTTPFlow object

        """
        request_mods = self.intercept_rules.get("request_modifications", {})

        if "headers" in request_mods:
            for key, value in request_mods["headers"].items():
                flow.request.headers[key] = value

        if "body_replacements" in request_mods:
            try:
                body = flow.request.text
                for pattern, replacement in request_mods["body_replacements"].items():
                    body = re.sub(pattern, replacement, body)
                flow.request.text = body
            except Exception as e:
                logger.debug(f"Failed to modify request body: {e}")

    def _synthesize_response(self, flow: http.HTTPFlow) -> None:
        """Synthesize license validation response.

        Args:
            flow: mitmproxy HTTPFlow object

        """
        url = flow.request.pretty_url
        content_type = flow.request.headers.get("Content-Type", "")

        if "json" in content_type or "/api/" in url:
            response_data = self.synthesizer.synthesize_rest_response(
                url,
                flow.request.method,
                self._get_request_json(flow),
            )
            flow.response = http.Response.make(
                200,
                json.dumps(response_data).encode(),
                {"Content-Type": "application/json"},
            )
            self.state_machine.transition(LicenseState.ACTIVE)

        elif "soap" in content_type.lower() or "xml" in content_type.lower():
            soap_action = flow.request.headers.get("SOAPAction", "")
            request_body = flow.request.text
            response_xml = self.synthesizer.synthesize_soap_response(soap_action, request_body)
            flow.response = http.Response.make(
                200,
                response_xml.encode(),
                {"Content-Type": "text/xml"},
            )
            self.state_machine.transition(LicenseState.ACTIVE)

    def _get_request_json(self, flow: http.HTTPFlow) -> dict:
        try:
            return json.loads(flow.request.text)
        except Exception:
            return {}


class CloudLicenseProtocolHandler:
    """Orchestrates TLS interception, state management, and response synthesis for cloud licenses."""

    def __init__(self) -> None:
        """Initialize cloud license protocol handler with all components."""
        self.tls_interceptor = None
        self.state_machines = {}
        self.synthesizer = ResponseSynthesizer()
        self.mitm_proxy = None
        self.proxy_thread = None
        self.running = False
        self.intercept_rules = {}

    def start_interception(
        self,
        target_host: str,
        target_port: int = 443,
        listen_port: int = 8080,
        protocol_type: ProtocolType = ProtocolType.HTTP_REST,
    ) -> dict[str, Any]:
        """Start MITM proxy for intercepting license traffic.

        Args:
            target_host: Target license server hostname
            target_port: Target server port
            listen_port: Local proxy listen port
            protocol_type: Protocol type to intercept

        Returns:
            Dictionary with interception status and details

        """
        if self.running:
            return {"success": False, "error": "Interception already running"}

        self.tls_interceptor = TLSInterceptor(target_host, target_port)

        state_machine = ProtocolStateMachine(protocol_type)
        self.state_machines[target_host] = state_machine

        self._configure_intercept_rules(target_host, protocol_type)

        self.proxy_thread = threading.Thread(
            target=self._run_mitmproxy,
            args=(listen_port, state_machine),
            daemon=True,
        )
        self.proxy_thread.start()

        self.running = True

        return {
            "success": True,
            "listen_port": listen_port,
            "target": f"{target_host}:{target_port}",
            "ca_cert": str(self.tls_interceptor.get_ca_cert_path()),
            "status": "running",
            "protocol": protocol_type.value,
        }

    def _configure_intercept_rules(self, target_host: str, protocol_type: ProtocolType) -> None:
        self.intercept_rules = {
            "modify": [
                {"url_pattern": r"/license", "action": "synthesize"},
                {"url_pattern": r"/validate", "action": "synthesize"},
                {"url_pattern": r"/subscription", "action": "synthesize"},
                {"url_pattern": r"/entitlement", "action": "synthesize"},
                {"url_pattern": r"/auth", "action": "synthesize"},
            ],
            "block": [],
            "request_modifications": {
                "headers": {},
                "body_replacements": {},
            },
            "response_modifications": {
                "replacements": [
                    (b'"licensed":false', b'"licensed":true'),
                    (b'"status":"expired"', b'"status":"active"'),
                    (b'"trial":true', b'"trial":false'),
                    (b'"valid":false', b'"valid":true'),
                ],
            },
        }

    def _run_mitmproxy(self, listen_port: int, state_machine: ProtocolStateMachine) -> None:
        opts = Options(listen_port=listen_port, ssl_insecure=True)

        addon = MITMProxyAddon(self.intercept_rules, state_machine, self.synthesizer)

        master = DumpMaster(opts)
        master.addons.add(addon)
        master.addons.add(anticache.AntiCache())

        try:
            master.run()
        except Exception as e:
            logger.error(f"MITM proxy error: {e}")
            self.running = False

    def stop_interception(self) -> dict[str, Any]:
        """Stop active MITM proxy interception.

        Returns:
            Dictionary with stop status

        """
        if not self.running:
            return {"success": False, "error": "No interception running"}

        self.running = False

        return {"success": True, "status": "stopped"}

    def handle_flexnet_cloud(self, config: dict[str, Any]) -> dict[str, Any]:
        """Handle FlexNet Cloud license protocol.

        Args:
            config: FlexNet configuration

        Returns:
            Synthesized FlexNet response

        """
        server_url = config.get("server_url", "https://licensing.flexnetoperations.com")

        self.start_interception(
            server_url.replace("https://", "").replace("http://", "").split(":")[0],
            443,
            8080,
            ProtocolType.FLEXNET,
        )

        feature_line = config.get("feature", "PRODUCT feature_v1")

        return {
            "success": True,
            "feature": feature_line,
            "license_type": "perpetual",
            "seats": 999999,
            "expiry": int(time.time() + 365 * 86400),
            "server": "localhost",
            "vendor_string": "INTELLICRACK_BYPASS",
        }

    def handle_sentinel_cloud(self, config: dict[str, Any]) -> dict[str, Any]:
        """Handle Sentinel Cloud license protocol.

        Args:
            config: Sentinel configuration

        Returns:
            Synthesized Sentinel response

        """
        server_url = config.get("server_url", "https://sentinel.gemalto.com")

        self.start_interception(
            server_url.replace("https://", "").replace("http://", "").split(":")[0],
            443,
            8080,
            ProtocolType.SENTINEL,
        )

        v2c_data = {
            "vendor_code": base64.b64encode(os.urandom(128)).decode(),
            "product_id": config.get("product_id", "DEFAULT_PRODUCT"),
            "feature_id": config.get("feature_id", 1),
            "expiry_date": int(time.time() + 365 * 86400),
            "concurrency": 999999,
            "license_type": "PERPETUAL",
        }

        return {
            "success": True,
            "status": "active",
            "v2c": base64.b64encode(json.dumps(v2c_data).encode()).decode(),
            "license_id": self.synthesizer._generate_uuid(),
        }

    def synthesize_license_response(self, protocol: ProtocolType, endpoint: str, request_data: object) -> object:
        """Synthesize license validation response based on protocol type.

        Args:
            protocol: Cloud licensing protocol type
            endpoint: API endpoint or method name
            request_data: Request payload data

        Returns:
            Synthesized response in protocol-appropriate format

        """
        if protocol == ProtocolType.HTTP_REST:
            return self.synthesizer.synthesize_rest_response(endpoint, "POST", request_data)
        if protocol == ProtocolType.SOAP:
            return self.synthesizer.synthesize_soap_response(endpoint, str(request_data))
        if protocol == ProtocolType.GRPC:
            return self.synthesizer.synthesize_grpc_response(endpoint, request_data)
        if protocol == ProtocolType.WEBSOCKET:
            return self.synthesizer.synthesize_websocket_frame("license_valid")
        return {"success": True, "status": "active"}

    def get_interception_stats(self) -> dict[str, Any]:
        """Get cloud interception statistics.

        Returns:
            Statistics dictionary

        """
        stats = {
            "running": self.running,
            "active_sessions": len(self.state_machines),
            "protocols": {},
        }

        for host, sm in self.state_machines.items():
            stats["protocols"][host] = {
                "protocol": sm.protocol_type.value,
                "state": sm.state.value,
                "tokens": len(sm.tokens),
                "session_data_keys": list(sm.session_data.keys()),
            }

        return stats


class CloudLicenseBypass:
    """High-level interface for bypassing various cloud licensing systems."""

    def __init__(self) -> None:
        """Initialize cloud license protocol handler with all components."""
        self.protocol_handler = CloudLicenseProtocolHandler()
        self.synthesizer = ResponseSynthesizer()
        self.active_bypasses = {}

    def bypass_azure_ad(self, config: dict[str, Any]) -> dict[str, Any]:
        """Bypass Azure AD authentication for license validation.

        Args:
            config: Azure AD configuration

        Returns:
            Bypass result dictionary

        """
        response = self.synthesizer.synthesize_oauth_response("azure", config)
        response["success"] = True
        return response

    def bypass_google_oauth(self, config: dict[str, Any]) -> dict[str, Any]:
        """Bypass Google OAuth for license validation.

        Args:
            config: Google OAuth configuration

        Returns:
            Bypass result dictionary

        """
        response = self.synthesizer.synthesize_oauth_response("google", config)
        response["success"] = True
        return response

    def bypass_aws_cognito(self, config: dict[str, Any]) -> dict[str, Any]:
        """Bypass AWS Cognito for license validation.

        Args:
            config: Cognito configuration

        Returns:
            Bypass result dictionary

        """
        response = self.synthesizer.synthesize_oauth_response("cognito", config)
        response["success"] = True
        return response

    def bypass_flexnet_cloud(self, config: dict[str, Any]) -> dict[str, Any]:
        """Bypass FlexNet Cloud licensing.

        Args:
            config: FlexNet configuration

        Returns:
            Bypass result dictionary

        """
        return self.protocol_handler.handle_flexnet_cloud(config)

    def bypass_sentinel_cloud(self, config: dict[str, Any]) -> dict[str, Any]:
        """Bypass Sentinel Cloud licensing.

        Args:
            config: Sentinel configuration

        Returns:
            Bypass result dictionary

        """
        return self.protocol_handler.handle_sentinel_cloud(config)

    def bypass_adobe_creative_cloud(self, config: dict[str, Any]) -> dict[str, Any]:
        """Bypass Adobe Creative Cloud licensing.

        Args:
            config: Adobe configuration

        Returns:
            Bypass result dictionary

        """
        client_id = config.get("client_id", "CreativeCloud")

        ims_payload = {
            "type": "access_token",
            "expires_in": 86399000,
            "scope": "creative_cloud creative_sdk openid",
            "client_id": client_id,
            "user_id": str(abs(hash(config.get("email", "user@adobe.com")))),
        }

        access_token = self.synthesizer.generate_jwt(ims_payload)

        products = config.get("products", ["Photoshop", "Illustrator", "InDesign"])
        entitlements = [
            {
                "product_id": product,
                "product_name": product,
                "activated": True,
                "license_type": "SUBSCRIPTION",
                "expiry_date": int(time.time() + 365 * 86400),
            }
            for product in products
        ]
        return {
            "success": True,
            "access_token": access_token,
            "device_token": base64.b64encode(os.urandom(32)).decode(),
            "entitlements": entitlements,
        }

    def bypass_microsoft_365(self, config: dict[str, Any]) -> dict[str, Any]:
        """Bypass Microsoft 365 licensing.

        Args:
            config: Microsoft 365 configuration

        Returns:
            Bypass result dictionary

        """
        license_payload = {
            "tid": config.get("tenant_id", "common"),
            "oid": self.synthesizer._generate_uuid(),
            "upn": config.get("upn", "user@contoso.com"),
            "licenseType": "ENTERPRISEPACK",
            "services": [
                "EXCHANGE_S_ENTERPRISE",
                "SHAREPOINTENTERPRISE",
                "OFFICESUBSCRIPTION",
                "TEAMS1",
            ],
        }

        license_token = self.synthesizer.generate_jwt(license_payload)

        return {
            "success": True,
            "license_token": license_token,
            "expires_in": 7776000,
        }

    def start_cloud_interception(
        self,
        target_host: str,
        protocol: ProtocolType = ProtocolType.HTTP_REST,
        listen_port: int = 8080,
    ) -> dict[str, Any]:
        """Start intercepting cloud license traffic.

        Args:
            target_host: Target license server
            protocol: Protocol type
            listen_port: Local proxy port

        Returns:
            Interception status dictionary

        """
        result = self.protocol_handler.start_interception(target_host, 443, listen_port, protocol)

        if result["success"]:
            self.active_bypasses[target_host] = {
                "protocol": protocol,
                "listen_port": listen_port,
                "started_at": time.time(),
            }

        return result

    def stop_cloud_interception(self) -> dict[str, Any]:
        """Stop cloud license interception.

        Returns:
            Stop status dictionary

        """
        return self.protocol_handler.stop_interception()

    def get_interception_stats(self) -> dict[str, Any]:
        """Get cloud interception statistics.

        Returns:
            Statistics dictionary

        """
        return self.protocol_handler.get_interception_stats()


def create_cloud_license_bypass() -> CloudLicenseBypass:
    """Create CloudLicenseBypass instance via factory function.

    Returns:
        CloudLicenseBypass instance

    """
    return CloudLicenseBypass()
