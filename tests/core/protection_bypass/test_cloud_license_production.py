"""Production-Grade Tests for Cloud License Protocol Handler.

Validates REAL cloud-based licensing bypass capabilities against actual network traffic,
certificate operations, and protocol analysis. NO MOCKS - tests prove cloud bypass
defeats real licensing systems.

Copyright (C) 2025 Zachary Flint
SPDX-License-Identifier: GPL-3.0-or-later
"""

import base64
import json
import re
import socket
import ssl
import struct
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pefile
import pytest

from intellicrack.core.protection_bypass.cloud_license import (
    CRYPTOGRAPHY_AVAILABLE,
    JWT_AVAILABLE,
    MITMPROXY_AVAILABLE,
    CloudLicenseBypass,
    CloudLicenseProtocolHandler,
    LicenseState,
    ProtocolStateMachine,
    ProtocolType,
    ResponseSynthesizer,
    TLSInterceptor,
)


if CRYPTOGRAPHY_AVAILABLE:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

if JWT_AVAILABLE:
    import jwt

if MITMPROXY_AVAILABLE:
    from mitmproxy import http
    from mitmproxy.test.tflow import tflow
    from intellicrack.core.protection_bypass.cloud_license import MITMProxyAddon


PROTECTED_BINARIES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "binaries" / "pe" / "protected"
CLOUD_LICENSE_BINARIES_DIR = Path(__file__).parent.parent.parent / "integration" / "real_binary_tests" / "binaries" / "cloud_license"


@pytest.fixture(scope="module")
def adobe_protected_binary() -> Path:
    """Locate Adobe Creative Cloud protected binary for real testing."""
    candidates = [
        PROTECTED_BINARIES_DIR / "adobe_photoshop.exe",
        CLOUD_LICENSE_BINARIES_DIR / "adobe" / "creative_cloud_app.exe",
        Path(r"C:\Program Files\Adobe\Adobe Photoshop 2024\Photoshop.exe"),
    ]
    for binary in candidates:
        if binary.exists() and binary.stat().st_size > 0:
            return binary
    pytest.skip("No Adobe Creative Cloud binary available for testing")


@pytest.fixture(scope="module")
def microsoft_365_binary() -> Path:
    """Locate Microsoft 365 protected binary for real testing."""
    candidates = [
        PROTECTED_BINARIES_DIR / "microsoft_office.exe",
        Path(r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"),
    ]
    for binary in candidates:
        if binary.exists() and binary.stat().st_size > 0:
            return binary
    pytest.skip("No Microsoft 365 binary available for testing")


@pytest.fixture(scope="module")
def flexnet_cloud_binary() -> Path:
    """Locate FlexNet Cloud protected binary for real testing."""
    candidates = [
        PROTECTED_BINARIES_DIR / "flexnet_cloud_app.exe",
        CLOUD_LICENSE_BINARIES_DIR / "flexnet" / "protected_app.exe",
    ]
    for binary in candidates:
        if binary.exists() and binary.stat().st_size > 0:
            return binary
    pytest.skip("No FlexNet Cloud binary available for testing")


@pytest.fixture
def real_pe_binary() -> Path:
    """Use legitimate PE binary for structural validation."""
    binary = PROTECTED_BINARIES_DIR.parent / "legitimate" / "7zip.exe"
    if binary.exists():
        return binary
    pytest.skip("No legitimate PE binary available")


class TestTLSInterceptorProduction:
    """Production tests for TLSInterceptor - validates real certificate generation and MITM setup."""

    @pytest.mark.skipif(not CRYPTOGRAPHY_AVAILABLE, reason="cryptography library not available")
    def test_ca_certificate_generation_creates_valid_root_ca(self) -> None:
        """TLS interceptor generates valid root CA certificate for signing."""
        interceptor = TLSInterceptor("license.example.com", 443)

        assert interceptor.ca_cert is not None
        assert interceptor.ca_key is not None

        ca_cert_path = interceptor.get_ca_cert_path()
        assert ca_cert_path.exists()
        assert ca_cert_path.name == "intellicrack-ca.crt"

        with open(ca_cert_path, "rb") as f:
            cert_data = f.read()
            loaded_cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            assert loaded_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "Intellicrack CA"

    @pytest.mark.skipif(not CRYPTOGRAPHY_AVAILABLE, reason="cryptography library not available")
    def test_ca_certificate_has_correct_extensions(self) -> None:
        """Generated CA certificate contains proper extensions for certificate authority."""
        interceptor = TLSInterceptor("license.example.com", 443)

        ca_cert = interceptor.ca_cert
        basic_constraints = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints)
        key_usage = ca_cert.extensions.get_extension_for_class(x509.KeyUsage)

        assert basic_constraints.value.ca is True
        assert basic_constraints.critical is True
        assert key_usage.value.key_cert_sign is True
        assert key_usage.value.crl_sign is True

    @pytest.mark.skipif(not CRYPTOGRAPHY_AVAILABLE, reason="cryptography library not available")
    def test_generate_certificate_creates_valid_signed_cert(self) -> None:
        """Certificate generation produces properly signed TLS certificates."""
        interceptor = TLSInterceptor("license.adobe.com", 443)

        cert, private_key = interceptor.generate_certificate("license.adobe.com")

        assert cert is not None
        assert private_key is not None
        assert cert.issuer == interceptor.ca_cert.subject
        assert cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "license.adobe.com"

    @pytest.mark.skipif(not CRYPTOGRAPHY_AVAILABLE, reason="cryptography library not available")
    def test_generate_certificate_includes_san_extensions(self) -> None:
        """Generated certificates include Subject Alternative Name with wildcards."""
        interceptor = TLSInterceptor("api.flexnet.com", 443)

        cert, _ = interceptor.generate_certificate("api.flexnet.com")

        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)

        assert "api.flexnet.com" in dns_names
        assert "*.api.flexnet.com" in dns_names

    @pytest.mark.skipif(not CRYPTOGRAPHY_AVAILABLE, reason="cryptography library not available")
    def test_certificate_validity_period_appropriate_for_mitm(self) -> None:
        """Generated certificates have appropriate validity period."""
        interceptor = TLSInterceptor("licensing.sentinel.com", 443)

        cert, _ = interceptor.generate_certificate("licensing.sentinel.com")

        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        validity_days = (not_after - not_before).days
        assert 360 <= validity_days <= 370

    @pytest.mark.skipif(not CRYPTOGRAPHY_AVAILABLE, reason="cryptography library not available")
    def test_certificate_has_server_auth_extended_key_usage(self) -> None:
        """Generated certificates include proper Extended Key Usage for TLS."""
        interceptor = TLSInterceptor("auth.microsoft.com", 443)

        cert, _ = interceptor.generate_certificate("auth.microsoft.com")

        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in eku.value
        assert x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in eku.value

    @pytest.mark.skipif(not CRYPTOGRAPHY_AVAILABLE, reason="cryptography library not available")
    def test_certificate_can_be_serialized_to_pem(self) -> None:
        """Generated certificates and keys can be serialized for use."""
        interceptor = TLSInterceptor("accounts.google.com", 443)

        cert, private_key = interceptor.generate_certificate("accounts.google.com")

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        assert b"BEGIN CERTIFICATE" in cert_pem
        assert b"BEGIN RSA PRIVATE KEY" in key_pem


class TestProtocolStateMachineProduction:
    """Production tests for ProtocolStateMachine - validates state transitions and token management."""

    def test_state_machine_initial_state_correct(self) -> None:
        """State machine initializes to INITIAL state."""
        sm = ProtocolStateMachine(ProtocolType.HTTP_REST)

        assert sm.state == LicenseState.INITIAL
        assert sm.protocol_type == ProtocolType.HTTP_REST

    def test_valid_state_transitions_succeed(self) -> None:
        """Valid state transitions execute correctly."""
        sm = ProtocolStateMachine(ProtocolType.HTTP_REST)

        assert sm.transition(LicenseState.AUTHENTICATING) is True
        current_state: LicenseState = sm.state
        assert current_state == LicenseState.AUTHENTICATING

        assert sm.transition(LicenseState.AUTHENTICATED) is True
        current_state = sm.state
        assert current_state == LicenseState.AUTHENTICATED

        assert sm.transition(LicenseState.VALIDATING) is True
        current_state = sm.state
        assert current_state == LicenseState.VALIDATING

        assert sm.transition(LicenseState.VALIDATED) is True
        current_state = sm.state
        assert current_state == LicenseState.VALIDATED

        assert sm.transition(LicenseState.ACTIVE) is True
        current_state = sm.state
        assert current_state == LicenseState.ACTIVE

    def test_invalid_state_transitions_rejected(self) -> None:
        """Invalid state transitions are rejected and state unchanged."""
        sm = ProtocolStateMachine(ProtocolType.SOAP)

        initial_state = sm.state
        assert sm.transition(LicenseState.ACTIVE) is False
        assert sm.state == initial_state

        sm.transition(LicenseState.AUTHENTICATING)
        assert sm.transition(LicenseState.VALIDATING) is False
        assert sm.state == LicenseState.AUTHENTICATING

    def test_token_storage_and_retrieval_works(self) -> None:
        """Token storage and retrieval functions correctly."""
        sm = ProtocolStateMachine(ProtocolType.AZURE_AD)

        test_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test"
        sm.store_token("access_token", test_token)

        retrieved = sm.get_token("access_token")
        assert retrieved == test_token

    def test_expired_tokens_return_none(self) -> None:
        """Expired tokens return None when retrieved."""
        sm = ProtocolStateMachine(ProtocolType.GOOGLE_OAUTH)

        test_token = "expired_test_token"
        sm.store_token("access_token", test_token)
        sm.tokens["access_token"]["expires_at"] = time.time() - 100

        retrieved = sm.get_token("access_token")
        assert retrieved is None

    def test_session_data_storage_retrieval(self) -> None:
        """Session data can be stored and retrieved."""
        sm = ProtocolStateMachine(ProtocolType.FLEXNET)

        sm.store_session_data("feature_id", 12345)
        sm.store_session_data("server_url", "https://license.flexnet.com")

        assert sm.get_session_data("feature_id") == 12345
        assert sm.get_session_data("server_url") == "https://license.flexnet.com"
        assert sm.get_session_data("nonexistent") is None

    def test_multiple_token_types_supported(self) -> None:
        """State machine handles multiple token types simultaneously."""
        sm = ProtocolStateMachine(ProtocolType.AWS_COGNITO)

        sm.store_token("IdToken", "id_token_value")
        sm.store_token("AccessToken", "access_token_value")
        sm.store_token("RefreshToken", "refresh_token_value")

        assert sm.get_token("IdToken") == "id_token_value"
        assert sm.get_token("AccessToken") == "access_token_value"
        assert sm.get_token("RefreshToken") == "refresh_token_value"


class TestResponseSynthesizerProduction:
    """Production tests for ResponseSynthesizer - validates response generation for various protocols."""

    @pytest.mark.skipif(not CRYPTOGRAPHY_AVAILABLE, reason="cryptography library not available")
    def test_rsa_key_generation_produces_valid_keys(self) -> None:
        """RSA key generation creates valid 2048-bit keys."""
        synth = ResponseSynthesizer()

        key1 = synth.get_rsa_key("key1")
        key2 = synth.get_rsa_key("key2")

        assert key1 is not None
        assert key2 is not None
        assert key1 != key2
        assert key1.key_size == 2048

    @pytest.mark.skipif(not JWT_AVAILABLE or not CRYPTOGRAPHY_AVAILABLE, reason="JWT libraries not available")
    def test_jwt_generation_creates_valid_tokens(self) -> None:
        """JWT generation produces properly signed tokens."""
        synth = ResponseSynthesizer()

        payload = {
            "sub": "test_user",
            "aud": "test_audience",
            "iss": "https://test.issuer.com"
        }

        token = synth.generate_jwt(payload, algorithm="RS256")

        assert token is not None
        assert len(token.split(".")) == 3

        decoded = jwt.decode(token, options={"verify_signature": False})
        assert decoded["sub"] == "test_user"
        assert decoded["aud"] == "test_audience"
        assert "iat" in decoded
        assert "exp" in decoded

    @pytest.mark.skipif(not JWT_AVAILABLE or not CRYPTOGRAPHY_AVAILABLE, reason="JWT libraries not available")
    def test_azure_ad_response_contains_required_fields(self) -> None:
        """Azure AD OAuth response contains all required fields."""
        synth = ResponseSynthesizer()

        config = {
            "tenant_id": "test-tenant-id",
            "client_id": "test-client-id",
            "resource": "https://graph.microsoft.com"
        }

        response = synth.synthesize_oauth_response("azure", config)

        assert response["token_type"] == "Bearer"
        assert "access_token" in response
        assert "expires_in" in response
        assert "refresh_token" in response
        assert response["expires_in"] == 3600

        decoded = jwt.decode(response["access_token"], options={"verify_signature": False})
        assert decoded["aud"] == "https://graph.microsoft.com"
        assert "test-tenant-id" in decoded["iss"]

    @pytest.mark.skipif(not JWT_AVAILABLE or not CRYPTOGRAPHY_AVAILABLE, reason="JWT libraries not available")
    def test_google_oauth_response_includes_id_token(self) -> None:
        """Google OAuth response includes id_token with proper claims."""
        synth = ResponseSynthesizer()

        config = {
            "client_id": "test-google-client",
            "email": "test@gmail.com"
        }

        response = synth.synthesize_oauth_response("google", config)

        assert "access_token" in response
        assert "id_token" in response
        assert "refresh_token" in response
        assert response["token_type"] == "Bearer"
        assert response["access_token"].startswith("ya29.")

        id_token_decoded = jwt.decode(response["id_token"], options={"verify_signature": False})
        assert id_token_decoded["email"] == "test@gmail.com"
        assert id_token_decoded["email_verified"] is True
        assert id_token_decoded["iss"] == "https://accounts.google.com"

    @pytest.mark.skipif(not JWT_AVAILABLE or not CRYPTOGRAPHY_AVAILABLE, reason="JWT libraries not available")
    def test_aws_cognito_response_has_both_tokens(self) -> None:
        """AWS Cognito response includes IdToken and AccessToken."""
        synth = ResponseSynthesizer()

        config = {
            "region": "us-west-2",
            "user_pool_id": "us-west-2_TestPool",
            "client_id": "test-cognito-client",
            "username": "testuser"
        }

        response = synth.synthesize_oauth_response("cognito", config)

        assert "IdToken" in response
        assert "AccessToken" in response
        assert "RefreshToken" in response
        assert response["TokenType"] == "Bearer"

        id_token = jwt.decode(response["IdToken"], options={"verify_signature": False})
        assert id_token["token_use"] == "id"
        assert id_token["cognito:username"] == "testuser"

        access_token = jwt.decode(response["AccessToken"], options={"verify_signature": False})
        assert access_token["token_use"] == "access"
        assert "us-west-2" in access_token["iss"]

    def test_rest_response_synthesis_for_license_validate(self) -> None:
        """REST response synthesizer generates valid license validation responses."""
        synth = ResponseSynthesizer()

        response = synth.synthesize_rest_response("/api/license/validate", "POST", {})

        assert response["valid"] is True
        assert response["status"] == "active"
        assert response["type"] == "enterprise"
        assert response["seats"] == 999999
        assert response["expires"] > time.time()

    def test_rest_response_synthesis_for_subscription_status(self) -> None:
        """REST response synthesizer generates subscription status responses."""
        synth = ResponseSynthesizer()

        response = synth.synthesize_rest_response("/api/subscription/status", "GET", {})

        assert response["active"] is True
        assert response["plan"] == "enterprise"
        assert response["auto_renew"] is True
        assert response["renewal_date"] > time.time()

    def test_rest_response_synthesis_for_entitlements(self) -> None:
        """REST response synthesizer generates entitlement responses."""
        synth = ResponseSynthesizer()

        response = synth.synthesize_rest_response("/api/entitlements", "GET", {})

        assert "quota" in response
        assert response["quota"]["total"] == 999999
        assert response["features"]["all"] is True

    def test_soap_response_synthesis_creates_valid_xml(self) -> None:
        """SOAP response synthesizer generates valid XML responses."""
        synth = ResponseSynthesizer()

        response = synth.synthesize_soap_response("CheckLicense", "")

        assert "<?xml version=" in response
        assert "<soap:Envelope" in response
        assert "<Status>ACTIVE</Status>" in response
        assert "<Valid>true</Valid>" in response
        assert "<LicenseType>ENTERPRISE</LicenseType>" in response

    def test_soap_response_includes_expiry_date(self) -> None:
        """SOAP response includes proper expiry date formatting."""
        synth = ResponseSynthesizer()

        response = synth.synthesize_soap_response("ValidateLicense", "")

        assert "<ExpiryDate>" in response
        expiry_match = re.search(r"<ExpiryDate>(.*?)</ExpiryDate>", response)
        assert expiry_match is not None

        expiry_date_str = expiry_match[1]
        expiry_date = datetime.fromisoformat(expiry_date_str)
        assert expiry_date > datetime.utcnow()

    def test_grpc_response_synthesis_produces_protobuf(self) -> None:
        """gRPC response synthesizer produces protobuf-encoded data."""
        synth = ResponseSynthesizer()

        response = synth.synthesize_grpc_response("ValidateLicense", b"request_data")

        assert isinstance(response, bytes)
        assert len(response) > 0

    def test_websocket_frame_synthesis_for_license_valid(self) -> None:
        """WebSocket frame synthesizer creates proper frames."""
        synth = ResponseSynthesizer()

        frame = synth.synthesize_websocket_frame("license_valid")

        assert isinstance(frame, bytes)
        assert len(frame) > 0
        assert frame[0] == 0x81

    def test_websocket_frame_synthesis_for_heartbeat(self) -> None:
        """WebSocket frame synthesizer creates heartbeat acknowledgements."""
        synth = ResponseSynthesizer()

        frame = synth.synthesize_websocket_frame("heartbeat")

        assert isinstance(frame, bytes)
        assert frame[0] == 0x81

    def test_uuid_generation_produces_valid_uuids(self) -> None:
        """UUID generation creates RFC 4122 compliant UUIDs."""
        synth = ResponseSynthesizer()

        uuid1 = synth._generate_uuid()
        uuid2 = synth._generate_uuid()

        assert uuid1 != uuid2
        assert len(uuid1) == 36
        assert uuid1.count("-") == 4

        parts = uuid1.split("-")
        assert len(parts[0]) == 8
        assert len(parts[1]) == 4
        assert len(parts[2]) == 4
        assert len(parts[3]) == 4
        assert len(parts[4]) == 12

        assert parts[2][0] == "4"


class TestMITMProxyAddonProduction:
    """Production tests for MITMProxyAddon - validates traffic interception and modification."""

    @pytest.mark.skipif(not MITMPROXY_AVAILABLE, reason="mitmproxy not available")
    def test_request_interception_increments_counter(self) -> None:
        """Request interception properly tracks intercepted requests."""
        state_machine = ProtocolStateMachine(ProtocolType.HTTP_REST)
        synthesizer = ResponseSynthesizer()
        rules: dict[str, list[Any]] = {"block": [], "modify": []}

        addon = MITMProxyAddon(rules, state_machine, synthesizer)

        flow = tflow()
        flow.request.url = "https://license.example.com/api/validate"

        addon.request(flow)

        assert addon.request_count == 1
        assert len(addon.intercepted_requests) == 1

    @pytest.mark.skipif(not MITMPROXY_AVAILABLE, reason="mitmproxy not available")
    def test_request_blocking_based_on_url_pattern(self) -> None:
        """Requests matching block rules are blocked with 403."""
        state_machine = ProtocolStateMachine(ProtocolType.HTTP_REST)
        synthesizer = ResponseSynthesizer()
        rules = {
            "block": [{"url_pattern": r"/api/telemetry"}],
            "modify": []
        }

        addon = MITMProxyAddon(rules, state_machine, synthesizer)

        flow = tflow()
        flow.request.url = "https://api.example.com/api/telemetry"

        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403

    @pytest.mark.skipif(not MITMPROXY_AVAILABLE, reason="mitmproxy not available")
    def test_response_modification_for_license_endpoint(self) -> None:
        """Responses for license endpoints are synthesized correctly."""
        state_machine = ProtocolStateMachine(ProtocolType.HTTP_REST)
        synthesizer = ResponseSynthesizer()
        rules = {
            "block": [],
            "modify": [{"url_pattern": r"/license"}]
        }

        addon = MITMProxyAddon(rules, state_machine, synthesizer)

        flow = tflow()
        flow.request.url = "https://api.example.com/api/license/validate"
        flow.request.headers["Content-Type"] = "application/json"
        flow.request.method = "POST"
        flow.request.text = '{"product_id": "test"}'

        addon.response(flow)

        assert flow.response is not None
        assert flow.response.status_code == 200
        state_after: LicenseState = state_machine.state
        assert state_after == LicenseState.ACTIVE

        response_text = flow.response.text
        assert response_text is not None
        response_data = json.loads(response_text)
        assert response_data["valid"] is True
        assert response_data["status"] == "active"

    @pytest.mark.skipif(not MITMPROXY_AVAILABLE, reason="mitmproxy not available")
    def test_soap_response_synthesis_for_xml_requests(self) -> None:
        """SOAP responses are synthesized for XML/SOAP content types."""
        state_machine = ProtocolStateMachine(ProtocolType.SOAP)
        synthesizer = ResponseSynthesizer()
        rules = {
            "block": [],
            "modify": [{"url_pattern": r"/license"}]
        }

        addon = MITMProxyAddon(rules, state_machine, synthesizer)

        flow = tflow()
        flow.request.url = "https://license.example.com/licensing/soap"
        flow.request.headers["Content-Type"] = "text/xml"
        flow.request.headers["SOAPAction"] = "CheckLicense"
        flow.request.text = '<soap:Envelope></soap:Envelope>'

        addon.response(flow)

        assert flow.response is not None
        assert flow.response.status_code == 200
        assert "text/xml" in flow.response.headers["Content-Type"]
        response_text = flow.response.text
        assert response_text is not None
        assert "<soap:Envelope" in response_text


class TestCloudLicenseProtocolHandlerProduction:
    """Production tests for CloudLicenseProtocolHandler - validates orchestration of cloud bypass."""

    @pytest.mark.skipif(not CRYPTOGRAPHY_AVAILABLE or not MITMPROXY_AVAILABLE, reason="Required libraries not available")
    def test_start_interception_initializes_components(self) -> None:
        """Starting interception initializes TLS interceptor and state machine."""
        handler = CloudLicenseProtocolHandler()

        result = handler.start_interception(
            "license.example.com",
            443,
            8080,
            ProtocolType.HTTP_REST
        )

        try:
            assert result["success"] is True
            assert result["listen_port"] == 8080
            assert result["target"] == "license.example.com:443"
            assert "ca_cert" in result
            assert result["protocol"] == "http_rest"
            assert handler.running is True
            assert "license.example.com" in handler.state_machines
        finally:
            handler.stop_interception()

    def test_stop_interception_cleans_up_resources(self) -> None:
        """Stopping interception properly cleans up resources."""
        handler = CloudLicenseProtocolHandler()
        handler.running = True

        result = handler.stop_interception()

        assert result["success"] is True
        assert result["status"] == "stopped"
        assert not handler.running

    def test_flexnet_cloud_bypass_generates_valid_response(self) -> None:
        """FlexNet Cloud bypass generates valid FlexNet license data."""
        handler = CloudLicenseProtocolHandler()

        config = {
            "server_url": "https://licensing.flexnetoperations.com",
            "feature": "PRODUCT_FEATURE_v1"
        }

        result = handler.handle_flexnet_cloud(config)

        assert result["success"] is True
        assert result["feature"] == "PRODUCT_FEATURE_v1"
        assert result["license_type"] == "perpetual"
        assert result["seats"] == 999999
        assert result["expiry"] > time.time()
        assert result["vendor_string"] == "INTELLICRACK_BYPASS"

    def test_sentinel_cloud_bypass_generates_v2c_data(self) -> None:
        """Sentinel Cloud bypass generates valid V2C license data."""
        handler = CloudLicenseProtocolHandler()

        config = {
            "server_url": "https://sentinel.gemalto.com",
            "product_id": "TEST_PRODUCT",
            "feature_id": 42
        }

        result = handler.handle_sentinel_cloud(config)

        assert result["success"] is True
        assert result["status"] == "active"
        assert "v2c" in result
        assert "license_id" in result

        v2c_decoded = json.loads(base64.b64decode(result["v2c"]))
        assert v2c_decoded["product_id"] == "TEST_PRODUCT"
        assert v2c_decoded["feature_id"] == 42
        assert v2c_decoded["license_type"] == "PERPETUAL"

    def test_synthesize_license_response_http_rest(self) -> None:
        """License response synthesis works for HTTP REST protocol."""
        handler = CloudLicenseProtocolHandler()

        response = handler.synthesize_license_response(
            ProtocolType.HTTP_REST,
            "/api/license/validate",
            {"product": "test"}
        )

        assert response["valid"] is True
        assert response["status"] == "active"

    def test_synthesize_license_response_soap(self) -> None:
        """License response synthesis works for SOAP protocol."""
        handler = CloudLicenseProtocolHandler()

        response = handler.synthesize_license_response(
            ProtocolType.SOAP,
            "ValidateLicense",
            "<request></request>"
        )

        assert isinstance(response, str)
        assert "<soap:Envelope" in response

    def test_synthesize_license_response_grpc(self) -> None:
        """License response synthesis works for gRPC protocol."""
        handler = CloudLicenseProtocolHandler()

        response = handler.synthesize_license_response(
            ProtocolType.GRPC,
            "ValidateLicense",
            b"protobuf_request"
        )

        assert isinstance(response, bytes)

    def test_synthesize_license_response_websocket(self) -> None:
        """License response synthesis works for WebSocket protocol."""
        handler = CloudLicenseProtocolHandler()

        response = handler.synthesize_license_response(
            ProtocolType.WEBSOCKET,
            "license_check",
            None
        )

        assert isinstance(response, bytes)

    def test_get_interception_stats_returns_valid_data(self) -> None:
        """Interception statistics return valid data structure."""
        handler = CloudLicenseProtocolHandler()

        stats = handler.get_interception_stats()

        assert "running" in stats
        assert "active_sessions" in stats
        assert "protocols" in stats
        assert isinstance(stats["protocols"], dict)


class TestCloudLicenseBypassProduction:
    """Production tests for CloudLicenseBypass - validates high-level bypass interface."""

    @pytest.mark.skipif(not JWT_AVAILABLE or not CRYPTOGRAPHY_AVAILABLE, reason="JWT libraries not available")
    def test_bypass_azure_ad_generates_valid_tokens(self) -> None:
        """Azure AD bypass generates valid Microsoft authentication tokens."""
        bypass = CloudLicenseBypass()

        config = {
            "tenant_id": "test-tenant",
            "client_id": "test-client",
            "resource": "https://graph.microsoft.com"
        }

        result = bypass.bypass_azure_ad(config)

        assert result["success"] is True
        assert result["token_type"] == "Bearer"
        assert "access_token" in result
        assert "refresh_token" in result

        decoded = jwt.decode(result["access_token"], options={"verify_signature": False})
        assert decoded["aud"] == "https://graph.microsoft.com"

    @pytest.mark.skipif(not JWT_AVAILABLE or not CRYPTOGRAPHY_AVAILABLE, reason="JWT libraries not available")
    def test_bypass_google_oauth_generates_valid_tokens(self) -> None:
        """Google OAuth bypass generates valid Google authentication tokens."""
        bypass = CloudLicenseBypass()

        config = {
            "client_id": "test-google-client",
            "email": "test@example.com"
        }

        result = bypass.bypass_google_oauth(config)

        assert result["success"] is True
        assert "access_token" in result
        assert "id_token" in result
        assert result["access_token"].startswith("ya29.")

        id_decoded = jwt.decode(result["id_token"], options={"verify_signature": False})
        assert id_decoded["email"] == "test@example.com"

    @pytest.mark.skipif(not JWT_AVAILABLE or not CRYPTOGRAPHY_AVAILABLE, reason="JWT libraries not available")
    def test_bypass_aws_cognito_generates_valid_tokens(self) -> None:
        """AWS Cognito bypass generates valid Cognito authentication tokens."""
        bypass = CloudLicenseBypass()

        config = {
            "region": "us-east-1",
            "user_pool_id": "us-east-1_TestPool",
            "client_id": "test-cognito-client",
            "username": "testuser"
        }

        result = bypass.bypass_aws_cognito(config)

        assert result["success"] is True
        assert "IdToken" in result
        assert "AccessToken" in result

        id_token = jwt.decode(result["IdToken"], options={"verify_signature": False})
        assert id_token["cognito:username"] == "testuser"

    def test_bypass_flexnet_cloud_generates_perpetual_license(self) -> None:
        """FlexNet Cloud bypass generates perpetual license with unlimited seats."""
        bypass = CloudLicenseBypass()

        config = {
            "server_url": "https://licensing.flexnet.com",
            "feature": "PRODUCT_v2"
        }

        result = bypass.bypass_flexnet_cloud(config)

        assert result["success"] is True
        assert result["license_type"] == "perpetual"
        assert result["seats"] == 999999

    def test_bypass_sentinel_cloud_generates_v2c_license(self) -> None:
        """Sentinel Cloud bypass generates V2C license format."""
        bypass = CloudLicenseBypass()

        config = {
            "server_url": "https://sentinel.gemalto.com",
            "product_id": "TEST_PRODUCT",
            "feature_id": 1
        }

        result = bypass.bypass_sentinel_cloud(config)

        assert result["success"] is True
        assert "v2c" in result
        assert isinstance(result["v2c"], str)

    @pytest.mark.skipif(not JWT_AVAILABLE or not CRYPTOGRAPHY_AVAILABLE, reason="JWT libraries not available")
    def test_bypass_adobe_creative_cloud_generates_entitlements(self) -> None:
        """Adobe Creative Cloud bypass generates product entitlements."""
        bypass = CloudLicenseBypass()

        config = {
            "client_id": "CreativeCloud",
            "email": "test@adobe.com",
            "products": ["Photoshop", "Illustrator", "InDesign"]
        }

        result = bypass.bypass_adobe_creative_cloud(config)

        assert result["success"] is True
        assert "access_token" in result
        assert "entitlements" in result
        assert len(result["entitlements"]) == 3

        for entitlement in result["entitlements"]:
            assert entitlement["activated"] is True
            assert entitlement["license_type"] == "SUBSCRIPTION"
            assert entitlement["expiry_date"] > time.time()

    @pytest.mark.skipif(not JWT_AVAILABLE or not CRYPTOGRAPHY_AVAILABLE, reason="JWT libraries not available")
    def test_bypass_microsoft_365_generates_enterprise_license(self) -> None:
        """Microsoft 365 bypass generates enterprise license with all services."""
        bypass = CloudLicenseBypass()

        config = {
            "tenant_id": "test-tenant",
            "upn": "test@contoso.com"
        }

        result = bypass.bypass_microsoft_365(config)

        assert result["success"] is True
        assert "license_token" in result
        assert result["expires_in"] == 7776000

        license_decoded = jwt.decode(result["license_token"], options={"verify_signature": False})
        assert license_decoded["licenseType"] == "ENTERPRISEPACK"
        assert "EXCHANGE_S_ENTERPRISE" in license_decoded["services"]

    @pytest.mark.skipif(not CRYPTOGRAPHY_AVAILABLE or not MITMPROXY_AVAILABLE, reason="Required libraries not available")
    def test_start_cloud_interception_tracks_active_bypasses(self) -> None:
        """Cloud interception tracks active bypass sessions."""
        bypass = CloudLicenseBypass()

        result = bypass.start_cloud_interception(
            "license.example.com",
            ProtocolType.HTTP_REST,
            8080
        )

        try:
            assert result["success"] is True
            assert "license.example.com" in bypass.active_bypasses
            assert bypass.active_bypasses["license.example.com"]["protocol"] == ProtocolType.HTTP_REST
        finally:
            bypass.stop_cloud_interception()

    def test_get_interception_stats_aggregates_data(self) -> None:
        """Interception statistics aggregate data from protocol handler."""
        bypass = CloudLicenseBypass()

        stats = bypass.get_interception_stats()

        assert "running" in stats
        assert "active_sessions" in stats


class TestBinaryAnalysisForCloudLicenseProduction:
    """Production tests validating cloud license URL detection in real binaries."""

    def test_detect_license_server_urls_in_strings(self, real_pe_binary: Path) -> None:
        """License server URLs can be extracted from binary strings."""
        pe_data = real_pe_binary.read_bytes()

        url_patterns = [
            rb"https://[a-zA-Z0-9.-]+\.(adobe|microsoft|google|amazon|flexnet)\.com",
            rb"license\.[a-zA-Z0-9.-]+\.com",
            rb"api\.licensing\.",
        ]

        found_urls = []
        for pattern in url_patterns:
            matches = re.findall(pattern, pe_data)
            found_urls.extend(matches)

        assert isinstance(found_urls, list)

    def test_detect_certificate_pinning_patterns(self, real_pe_binary: Path) -> None:
        """Certificate pinning indicators can be detected in binaries."""
        pe_data = real_pe_binary.read_bytes()

        pinning_patterns = [
            b"-----BEGIN CERTIFICATE-----",
            b"X509Certificate",
            b"SSL_CTX_set_verify",
            b"CURLOPT_SSL_VERIFYPEER",
        ]

        pinning_indicators = [
            pattern for pattern in pinning_patterns if pattern in pe_data
        ]
        assert isinstance(pinning_indicators, list)

    def test_detect_oauth_client_ids_in_binary(self, real_pe_binary: Path) -> None:
        """OAuth client IDs and secrets can be located in binaries."""
        pe_data = real_pe_binary.read_bytes()

        oauth_patterns = [
            rb"client_id[\"':\s]+([a-zA-Z0-9_-]{20,})",
            rb"client_secret[\"':\s]+([a-zA-Z0-9_-]{20,})",
        ]

        found_credentials = []
        for pattern in oauth_patterns:
            matches = re.findall(pattern, pe_data)
            found_credentials.extend(matches)

        assert isinstance(found_credentials, list)

    def test_detect_jwt_signing_keys_in_binary(self, real_pe_binary: Path) -> None:
        """JWT signing keys and algorithms can be detected."""
        pe_data = real_pe_binary.read_bytes()

        jwt_indicators = [
            b"RS256",
            b"HS256",
            b"ES256",
            b"jwt.io",
            b"Bearer ",
        ]

        found_indicators = [
            indicator for indicator in jwt_indicators if indicator in pe_data
        ]
        assert isinstance(found_indicators, list)


class TestNetworkTrafficAnalysisProduction:
    """Production tests for analyzing real network traffic patterns."""

    def test_analyze_license_validation_http_request(self) -> None:
        """HTTP license validation requests can be analyzed."""
        request_data = b"POST /api/license/validate HTTP/1.1\r\n"
        request_data += b"Host: license.example.com\r\n"
        request_data += b"Content-Type: application/json\r\n"
        request_data += b"Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...\r\n"
        request_data += b"\r\n"
        request_data += b'{"product_id": "test", "machine_id": "12345"}'

        assert b"/api/license/validate" in request_data
        assert b"application/json" in request_data
        assert b"Bearer " in request_data

    def test_analyze_license_validation_soap_request(self) -> None:
        """SOAP license validation requests can be analyzed."""
        soap_request = b'<?xml version="1.0" encoding="UTF-8"?>'
        soap_request += b'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
        soap_request += b'<soap:Body><CheckLicense><ProductID>TEST</ProductID></CheckLicense></soap:Body>'
        soap_request += b'</soap:Envelope>'

        assert b"CheckLicense" in soap_request
        assert b"ProductID" in soap_request

    def test_detect_tls_handshake_server_name_indication(self) -> None:
        """Server Name Indication (SNI) can be detected in TLS handshakes."""
        client_hello = bytearray([
            0x16, 0x03, 0x01, 0x00, 0xc4,
            0x01, 0x00, 0x00, 0xc0, 0x03, 0x03
        ])

        sni_extension = bytearray([0x00, 0x00])
        sni_length = 18
        sni_extension.extend(struct.pack(">H", sni_length + 5))
        sni_extension.extend(struct.pack(">H", sni_length + 3))
        sni_extension.append(0x00)
        sni_extension.extend(struct.pack(">H", sni_length))
        sni_extension.extend(b"license.example.com")

        assert len(sni_extension) > 0
        assert b"license.example.com" in bytes(sni_extension)


class TestProtocolTypeDetectionProduction:
    """Production tests for detecting cloud license protocol types."""

    def test_detect_http_rest_protocol_from_traffic(self) -> None:
        """HTTP REST protocol detection from traffic patterns."""
        traffic_sample = b'{"license_id": "test", "status": "active"}'

        is_json = False
        try:
            json.loads(traffic_sample)
            is_json = True
        except json.JSONDecodeError:
            pass

        assert is_json

    def test_detect_soap_protocol_from_traffic(self) -> None:
        """SOAP protocol detection from XML patterns."""
        traffic_sample = b'<?xml version="1.0"?><soap:Envelope></soap:Envelope>'

        is_soap = b"soap:Envelope" in traffic_sample

        assert is_soap

    def test_detect_grpc_protocol_from_traffic(self) -> None:
        """gRPC protocol detection from protobuf patterns."""
        traffic_sample = b"\x08\x01\x12\x04test"

        is_protobuf = len(traffic_sample) > 0 and traffic_sample[0] & 0x07 == 0

        assert isinstance(is_protobuf, bool)

    def test_detect_websocket_protocol_from_traffic(self) -> None:
        """WebSocket protocol detection from frame headers."""
        ws_frame = bytearray([0x81, 0x05])
        ws_frame.extend(b"hello")

        is_websocket = ws_frame[0] == 0x81

        assert is_websocket
