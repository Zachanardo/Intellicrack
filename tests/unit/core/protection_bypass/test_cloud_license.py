"""Comprehensive tests for cloud license protocol interception and bypass.

These tests validate production-ready functionality against real-world cloud licensing scenarios.
Tests are designed to FAIL unless code performs at production level with genuine cracking capabilities.
"""

import base64
import json
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from intellicrack.core.protection_bypass.cloud_license import (
    CloudLicenseBypass,
    CloudLicenseProtocolHandler,
    LicenseState,
    MITMProxyAddon,
    ProtocolStateMachine,
    ProtocolType,
    ResponseSynthesizer,
    TLSInterceptor,
    create_cloud_license_bypass,
)


class TestTLSInterceptor:
    """Test TLS interception and certificate generation capabilities."""

    def test_ca_certificate_generation(self):
        """Test that CA certificate is generated with correct properties for MITM attacks."""
        interceptor = TLSInterceptor("license.example.com", 443)

        assert interceptor.ca_cert is not None, "CA certificate must be generated"
        assert interceptor.ca_key is not None, "CA private key must be generated"

        assert interceptor.ca_cert.subject.get_attributes_for_oid(
            __import__('cryptography.x509.oid', fromlist=['NameOID']).NameOID.COMMON_NAME
        )[0].value == "Intellicrack CA", "CA must have correct common name"

        not_after = interceptor.ca_cert.not_valid_after_utc
        not_before = interceptor.ca_cert.not_valid_before_utc
        validity_days = (not_after - not_before).days

        assert validity_days >= 3650, f"CA must be valid for 10+ years, got {validity_days} days"

        basic_constraints = interceptor.ca_cert.extensions.get_extension_for_oid(
            __import__('cryptography.x509.oid', fromlist=['ExtensionOID']).ExtensionOID.BASIC_CONSTRAINTS
        ).value
        assert basic_constraints.ca is True, "CA certificate must have CA flag set"

    def test_ca_persistence(self):
        """Test that CA certificate persists across instances for consistent MITM."""
        interceptor1 = TLSInterceptor("test1.com")
        cert1_pem = interceptor1.ca_cert.public_bytes(
            __import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding']).Encoding.PEM
        )

        interceptor2 = TLSInterceptor("test2.com")
        cert2_pem = interceptor2.ca_cert.public_bytes(
            __import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding']).Encoding.PEM
        )

        assert cert1_pem == cert2_pem, "CA certificate must persist across instances"

    def test_target_certificate_generation(self):
        """Test generation of valid certificates for target license servers."""
        interceptor = TLSInterceptor("licensing.flexnetoperations.com")
        cert, key = interceptor.generate_certificate("licensing.flexnetoperations.com")

        assert cert is not None, "Target certificate must be generated"
        assert key is not None, "Target private key must be generated"

        common_name = cert.subject.get_attributes_for_oid(
            __import__('cryptography.x509.oid', fromlist=['NameOID']).NameOID.COMMON_NAME
        )[0].value
        assert common_name == "licensing.flexnetoperations.com", "Certificate must match target hostname"

        san_ext = cert.extensions.get_extension_for_oid(
            __import__('cryptography.x509.oid', fromlist=['ExtensionOID']).ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        dns_names = [name.value for name in san_ext.value]
        assert "licensing.flexnetoperations.com" in dns_names, "SAN must include exact hostname"
        assert "*.licensing.flexnetoperations.com" in dns_names, "SAN must include wildcard"

    def test_certificate_signed_by_ca(self):
        """Test that generated certificates are properly signed by our CA."""
        interceptor = TLSInterceptor("sentinel.gemalto.com")
        cert, _ = interceptor.generate_certificate("sentinel.gemalto.com")

        assert cert.issuer == interceptor.ca_cert.subject, "Certificate must be signed by our CA"

        issuer_cn = cert.issuer.get_attributes_for_oid(
            __import__('cryptography.x509.oid', fromlist=['NameOID']).NameOID.COMMON_NAME
        )[0].value
        assert issuer_cn == "Intellicrack CA", "Certificate issuer must be Intellicrack CA"


class TestProtocolStateMachine:
    """Test license protocol state machine for tracking authentication flows."""

    def test_initial_state(self):
        """Test state machine starts in INITIAL state."""
        sm = ProtocolStateMachine(ProtocolType.HTTP_REST)
        assert sm.state == LicenseState.INITIAL, "Must start in INITIAL state"
        assert sm.protocol_type == ProtocolType.HTTP_REST, "Must track protocol type"

    def test_valid_state_transitions(self):
        """Test all valid state transitions in license authentication flow."""
        sm = ProtocolStateMachine(ProtocolType.AZURE_AD)

        assert sm.transition(LicenseState.AUTHENTICATING), "INITIAL -> AUTHENTICATING must succeed"
        assert sm.state == LicenseState.AUTHENTICATING, "State must be AUTHENTICATING"

        assert sm.transition(LicenseState.AUTHENTICATED), "AUTHENTICATING -> AUTHENTICATED must succeed"
        assert sm.state == LicenseState.AUTHENTICATED, "State must be AUTHENTICATED"

        assert sm.transition(LicenseState.VALIDATING), "AUTHENTICATED -> VALIDATING must succeed"
        assert sm.transition(LicenseState.VALIDATED), "VALIDATING -> VALIDATED must succeed"
        assert sm.transition(LicenseState.ACTIVE), "VALIDATED -> ACTIVE must succeed"

    def test_invalid_state_transitions(self):
        """Test that invalid state transitions are rejected."""
        sm = ProtocolStateMachine(ProtocolType.GOOGLE_OAUTH)

        assert not sm.transition(LicenseState.ACTIVE), "Cannot jump to ACTIVE from INITIAL"
        assert sm.state == LicenseState.INITIAL, "State must remain INITIAL after failed transition"

        sm.transition(LicenseState.AUTHENTICATING)
        assert not sm.transition(LicenseState.VALIDATED), "Cannot skip AUTHENTICATED state"

    def test_token_storage_and_expiration(self):
        """Test token storage with expiration tracking."""
        sm = ProtocolStateMachine(ProtocolType.AWS_COGNITO)

        test_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test"
        sm.store_token("access_token", test_token)

        retrieved = sm.get_token("access_token")
        assert retrieved == test_token, "Must retrieve stored token"

        with patch('time.time', return_value=time.time() + 3601):
            expired = sm.get_token("access_token")
            assert expired is None, "Must not return expired token"

    def test_session_data_storage(self):
        """Test arbitrary session data storage for protocol context."""
        sm = ProtocolStateMachine(ProtocolType.MICROSOFT_365)

        sm.store_session_data("user_id", "test_user_123")
        sm.store_session_data("tenant_id", "common")
        sm.store_session_data("complex_data", {"nested": {"value": [1, 2, 3]}})

        assert sm.get_session_data("user_id") == "test_user_123", "Must retrieve simple data"
        assert sm.get_session_data("complex_data")["nested"]["value"] == [1, 2, 3], "Must retrieve complex data"
        assert sm.get_session_data("nonexistent") is None, "Must return None for missing data"


class TestResponseSynthesizer:
    """Test generation of authentic-looking license validation responses."""

    def test_rsa_key_generation(self):
        """Test RSA key generation for JWT signing."""
        synth = ResponseSynthesizer()

        key1 = synth.get_rsa_key("key1")
        key2 = synth.get_rsa_key("key2")

        assert key1 is not None, "Must generate RSA key"
        assert key2 is not None, "Must generate separate RSA key"
        assert key1 != key2, "Different key_ids must generate different keys"

        key1_again = synth.get_rsa_key("key1")
        assert key1 == key1_again, "Same key_id must return same key"

    def test_jwt_generation_with_rsa(self):
        """Test JWT generation with RS256 algorithm."""
        synth = ResponseSynthesizer()

        payload = {
            "sub": "user123",
            "aud": "https://api.example.com",
            "custom_claim": "test_value"
        }

        token = synth.generate_jwt(payload, algorithm="RS256")

        assert isinstance(token, str), "Must return string token"
        assert token.count('.') == 2, "JWT must have 3 parts separated by dots"

        import jwt as jwt_lib
        decoded = jwt_lib.decode(token, options={"verify_signature": False})

        assert decoded["sub"] == "user123", "Must include custom payload"
        assert "iat" in decoded, "Must include issued-at timestamp"
        assert "exp" in decoded, "Must include expiration timestamp"
        assert decoded["exp"] > decoded["iat"], "Expiration must be after issuance"

    def test_azure_ad_response_synthesis(self):
        """Test synthesis of authentic Azure AD OAuth response."""
        synth = ResponseSynthesizer()

        config = {
            "tenant_id": "test-tenant-123",
            "client_id": "app-client-456",
            "resource": "https://graph.microsoft.com"
        }

        response = synth.synthesize_oauth_response("azure", config)

        assert response["token_type"] == "Bearer", "Must use Bearer token type"
        assert "access_token" in response, "Must include access_token"
        assert "refresh_token" in response, "Must include refresh_token"
        assert response["expires_in"] == 3600, "Must have correct expiration"

        import jwt as jwt_lib
        token_data = jwt_lib.decode(response["access_token"], options={"verify_signature": False})

        assert token_data["aud"] == "https://graph.microsoft.com", "Must have correct audience"
        assert "test-tenant-123" in token_data["iss"], "Must have correct issuer with tenant"
        assert token_data["appid"] == "app-client-456", "Must have correct app ID"

    def test_google_oauth_response_synthesis(self):
        """Test synthesis of authentic Google OAuth response."""
        synth = ResponseSynthesizer()

        config = {
            "client_id": "google-client-789",
            "email": "test@gmail.com"
        }

        response = synth.synthesize_oauth_response("google", config)

        assert "access_token" in response, "Must include access_token"
        assert "id_token" in response, "Must include id_token"
        assert "refresh_token" in response, "Must include refresh_token"
        assert response["token_type"] == "Bearer", "Must use Bearer type"

        import jwt as jwt_lib
        id_token_data = jwt_lib.decode(response["id_token"], options={"verify_signature": False})

        assert id_token_data["iss"] == "https://accounts.google.com", "Must have Google issuer"
        assert id_token_data["email"] == "test@gmail.com", "Must include email"
        assert id_token_data["email_verified"] is True, "Email must be verified"

    def test_aws_cognito_response_synthesis(self):
        """Test synthesis of authentic AWS Cognito response."""
        synth = ResponseSynthesizer()

        config = {
            "region": "us-west-2",
            "user_pool_id": "us-west-2_ABC123",
            "client_id": "cognito-client-xyz"
        }

        response = synth.synthesize_oauth_response("cognito", config)

        assert "IdToken" in response, "Must include IdToken"
        assert "AccessToken" in response, "Must include AccessToken"
        assert "RefreshToken" in response, "Must include RefreshToken"
        assert response["TokenType"] == "Bearer", "Must use Bearer type"

        import jwt as jwt_lib
        id_token = jwt_lib.decode(response["IdToken"], options={"verify_signature": False})

        assert "us-west-2" in id_token["iss"], "Must have correct region in issuer"
        assert id_token["token_use"] == "id", "Must specify id token use"

    def test_rest_response_synthesis(self):
        """Test synthesis of REST API license validation responses."""
        synth = ResponseSynthesizer()

        response = synth.synthesize_rest_response("/api/license/validate", "POST", {})

        assert response["valid"] is True, "License must be valid"
        assert response["status"] == "active", "License must be active"
        assert response["type"] == "enterprise", "Must be enterprise license"
        assert response["seats"] == 999999, "Must have unlimited seats"
        assert response["expires"] > time.time(), "Must not be expired"

    def test_soap_response_synthesis(self):
        """Test synthesis of SOAP XML license responses."""
        synth = ResponseSynthesizer()

        response = synth.synthesize_soap_response("CheckLicense", "<LicenseRequest/>")

        assert response.startswith('<?xml'), "Must be valid XML"
        assert "LicenseCheckResponse" in response, "Must have correct response type"
        assert "<Status>ACTIVE</Status>" in response, "Must have active status"
        assert "<Valid>true</Valid>" in response, "Must be valid"
        assert "ENTERPRISE" in response, "Must be enterprise type"

    def test_protobuf_encoding(self):
        """Test protobuf encoding for gRPC responses."""
        synth = ResponseSynthesizer()

        test_data = {
            "license": {
                "id": "test-123",
                "status": "ACTIVE",
                "type": "ENTERPRISE"
            }
        }

        encoded = synth._encode_protobuf(test_data)

        assert isinstance(encoded, bytes), "Must return bytes"
        assert len(encoded) > 0, "Must encode data"

    def test_websocket_frame_encoding(self):
        """Test WebSocket frame encoding for realtime license updates."""
        synth = ResponseSynthesizer()

        frame = synth.synthesize_websocket_frame("license_valid")

        assert isinstance(frame, bytes), "Must return bytes"
        assert len(frame) > 0, "Must encode frame"
        assert frame[0] == 0x81, "Must be text frame with FIN bit"

    def test_uuid_generation(self):
        """Test RFC 4122 UUID v4 generation."""
        synth = ResponseSynthesizer()

        uuid1 = synth._generate_uuid()
        uuid2 = synth._generate_uuid()

        assert len(uuid1) == 36, "UUID must be 36 characters"
        assert uuid1.count('-') == 4, "UUID must have 4 hyphens"
        assert uuid1 != uuid2, "UUIDs must be unique"

        parts = uuid1.split('-')
        assert len(parts[2]) == 4 and parts[2][0] == '4', "Must be version 4 UUID"


class TestMITMProxyAddon:
    """Test mitmproxy addon for intercepting license traffic."""

    @pytest.fixture
    def addon(self):
        """Create MITM proxy addon for testing."""
        rules = {
            "block": [{"url_pattern": r"telemetry\.example\.com"}],
            "modify": [{"url_pattern": r"license\.example\.com"}]
        }
        sm = ProtocolStateMachine(ProtocolType.HTTP_REST)
        synth = ResponseSynthesizer()
        return MITMProxyAddon(rules, sm, synth)

    def test_request_interception(self, addon):
        """Test HTTP request interception."""
        flow = Mock()
        flow.request.pretty_url = "https://license.example.com/api/validate"
        flow.request.method = "POST"
        flow.request.headers = {"Authorization": "Bearer test"}

        addon.request(flow)

        assert addon.request_count == 1, "Must track request count"
        assert len(addon.intercepted_requests) == 1, "Must store intercepted request"
        assert addon.intercepted_requests[0]["url"] == flow.request.pretty_url

    def test_block_rules(self, addon):
        """Test request blocking based on rules."""
        url = "https://telemetry.example.com/track"
        method = "POST"
        headers = {}

        should_block = addon._check_block_rules(url, method, headers)

        assert should_block is True, "Must block URLs matching block rules"

    def test_modify_rules(self, addon):
        """Test response modification based on rules."""
        should_modify = addon._check_modify_rules("https://license.example.com/api/check")

        assert should_modify is True, "Must modify URLs matching modify rules"


class TestCloudLicenseProtocolHandler:
    """Test orchestration of TLS interception and protocol handling."""

    def test_initialization(self):
        """Test protocol handler initialization."""
        handler = CloudLicenseProtocolHandler()

        assert handler.synthesizer is not None, "Must have response synthesizer"
        assert handler.running is False, "Must not be running initially"
        assert len(handler.state_machines) == 0, "Must have no active sessions initially"

    def test_flexnet_cloud_handling(self):
        """Test FlexNet Cloud protocol handling."""
        handler = CloudLicenseProtocolHandler()

        config = {
            "server_url": "https://licensing.flexnetoperations.com",
            "product_id": "test-product-123"
        }

        with patch.object(handler, 'start_interception'):
            response = handler.handle_flexnet_cloud(config)

            assert response["success"] is True, "Must successfully handle FlexNet"
            assert response["license_type"] == "perpetual", "Must return perpetual license"
            assert response["seats"] == 999999, "Must have unlimited seats"

    def test_sentinel_cloud_handling(self):
        """Test Sentinel Cloud protocol handling."""
        handler = CloudLicenseProtocolHandler()

        config = {
            "server_url": "https://sentinel.gemalto.com",
            "feature_id": "feature-456"
        }

        with patch.object(handler, 'start_interception'):
            response = handler.handle_sentinel_cloud(config)

            assert response["success"] is True, "Must successfully handle Sentinel"
            assert response["status"] == "active", "Must have active status"


class TestCloudLicenseBypass:
    """Test high-level cloud license bypass interface."""

    def test_azure_ad_bypass(self):
        """Test Azure AD authentication bypass."""
        bypass = CloudLicenseBypass()

        config = {
            "tenant_id": "test-tenant",
            "client_id": "test-client",
            "resource": "https://api.example.com"
        }

        result = bypass.bypass_azure_ad(config)

        assert result["success"] is True, "Bypass must succeed"
        assert "access_token" in result, "Must provide access token"
        assert result["token_type"] == "Bearer", "Must use Bearer tokens"

    def test_google_oauth_bypass(self):
        """Test Google OAuth bypass."""
        bypass = CloudLicenseBypass()

        config = {
            "client_id": "google-app-123",
            "email": "user@example.com"
        }

        result = bypass.bypass_google_oauth(config)

        assert result["success"] is True, "Bypass must succeed"
        assert "access_token" in result, "Must provide access token"
        assert "id_token" in result, "Must provide id token"

    def test_aws_cognito_bypass(self):
        """Test AWS Cognito bypass."""
        bypass = CloudLicenseBypass()

        config = {
            "region": "us-east-1",
            "user_pool_id": "us-east-1_ABC",
            "client_id": "cognito-client"
        }

        result = bypass.bypass_aws_cognito(config)

        assert result["success"] is True, "Bypass must succeed"
        assert "IdToken" in result or "access_token" in result, "Must provide tokens"

    def test_adobe_creative_cloud_bypass(self):
        """Test Adobe Creative Cloud licensing bypass."""
        bypass = CloudLicenseBypass()

        config = {
            "client_id": "CreativeCloud",
            "email": "user@adobe.com"
        }

        result = bypass.bypass_adobe_creative_cloud(config)

        assert result["success"] is True, "Bypass must succeed"
        assert "access_token" in result, "Must provide access token"
        assert "entitlements" in result, "Must provide entitlements"
        assert len(result["entitlements"]) > 0, "Must have at least one entitlement"

    def test_microsoft_365_bypass(self):
        """Test Microsoft 365 licensing bypass."""
        bypass = CloudLicenseBypass()

        config = {
            "tenant_id": "common",
            "upn": "user@contoso.com"
        }

        result = bypass.bypass_microsoft_365(config)

        assert result["success"] is True, "Bypass must succeed"
        assert "license_token" in result, "Must provide license token"
        assert result["expires_in"] > 0, "Must have valid expiration"

    def test_factory_function(self):
        """Test factory function creates valid instance."""
        bypass = create_cloud_license_bypass()

        assert isinstance(bypass, CloudLicenseBypass), "Must create CloudLicenseBypass instance"
        assert bypass.protocol_handler is not None, "Must have protocol handler"
        assert bypass.synthesizer is not None, "Must have synthesizer"


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_expired_token_retrieval(self):
        """Test that expired tokens are not returned."""
        sm = ProtocolStateMachine(ProtocolType.HTTP_REST)

        sm.store_token("test", "token_value")

        with patch('time.time', return_value=time.time() + 7200):
            result = sm.get_token("test")
            assert result is None, "Must not return expired token"

    def test_missing_session_data(self):
        """Test retrieval of non-existent session data."""
        sm = ProtocolStateMachine(ProtocolType.SOAP)

        result = sm.get_session_data("nonexistent_key")
        assert result is None, "Must return None for missing data"

    def test_invalid_oauth_provider(self):
        """Test fallback for unknown OAuth provider."""
        synth = ResponseSynthesizer()

        result = synth.synthesize_oauth_response("unknown_provider", {})

        assert "access_token" in result, "Must provide fallback response"
        assert result["token_type"] == "Bearer", "Must use Bearer type"

    def test_concurrent_state_machines(self):
        """Test multiple concurrent state machines for different protocols."""
        handler = CloudLicenseProtocolHandler()

        sm1 = ProtocolStateMachine(ProtocolType.AZURE_AD)
        sm2 = ProtocolStateMachine(ProtocolType.GOOGLE_OAUTH)

        handler.state_machines["host1"] = sm1
        handler.state_machines["host2"] = sm2

        sm1.transition(LicenseState.AUTHENTICATING)
        sm2.transition(LicenseState.AUTHENTICATING)
        sm2.transition(LicenseState.AUTHENTICATED)

        assert sm1.state == LicenseState.AUTHENTICATING, "SM1 must be in AUTHENTICATING"
        assert sm2.state == LicenseState.AUTHENTICATED, "SM2 must be in AUTHENTICATED"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
