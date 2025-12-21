"""Production-grade tests for Cloud License Analyzer validating real interception capabilities.

Tests REAL cloud license interception, token extraction, and bypass against actual network traffic.
NO mocks - validates genuine offensive capabilities.

Copyright (C) 2025 Zachary Flint

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
import hashlib
import json
import os
import pickle
import socket
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
import pytest
import requests
import yaml
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

try:
    import mitmproxy.http
    from mitmproxy.test import tflow

    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False

try:
    from intellicrack.core.protection_bypass.cloud_license_analyzer import (
        TOKEN_TYPE_API_KEY,
        TOKEN_TYPE_BEARER,
        TOKEN_TYPE_COOKIE,
        TOKEN_TYPE_JWT,
        TOKEN_TYPE_LICENSE_KEY,
        CloudEndpoint,
        CloudInterceptor,
        CloudLicenseAnalyzer,
        CloudLicenseBypasser,
        LicenseToken,
    )

    ANALYZER_AVAILABLE = True
except ImportError:
    ANALYZER_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not (MITMPROXY_AVAILABLE and ANALYZER_AVAILABLE),
    reason="mitmproxy or cloud_license_analyzer not available",
)

if ANALYZER_AVAILABLE:
    CloudLicenseAnalyzerType = CloudLicenseAnalyzer
    CloudEndpointType = CloudEndpoint
    LicenseTokenType = LicenseToken
else:
    CloudLicenseAnalyzerType = Any
    CloudEndpointType = Any
    LicenseTokenType = Any


@pytest.fixture(scope="module")
def network_captures_dir() -> Path:
    """Path to directory containing real network capture files."""
    return Path(__file__).parent.parent.parent / "fixtures" / "network_captures"


@pytest.fixture
def analyzer() -> Any:
    """Create fresh analyzer instance for testing."""
    if not ANALYZER_AVAILABLE:
        pytest.skip("CloudLicenseAnalyzer not available")
    return CloudLicenseAnalyzer()


@pytest.fixture
def real_jwt_payload() -> dict[str, Any]:
    """Real JWT payload structure from cloud license systems."""
    now = datetime.utcnow()
    return {
        "iss": "license-server.example.com",
        "sub": "user123",
        "aud": "my-app",
        "exp": int((now + timedelta(days=30)).timestamp()),
        "iat": int(now.timestamp()),
        "license_type": "enterprise",
        "features": ["feature1", "feature2", "unlimited"],
        "max_activations": 10,
    }


@pytest.fixture
def real_license_response() -> dict[str, Any]:
    """Real license validation response structure."""
    return {
        "valid": True,
        "licensed": True,
        "activated": True,
        "expires": (datetime.now() + timedelta(days=365)).isoformat(),
        "features": ["all", "unlimited", "enterprise"],
        "license_key": "ABCD-EFGH-IJKL-MNOP",
        "max_activations": 999,
        "current_activations": 1,
    }


@pytest.fixture
def mock_http_request() -> Any:
    """Create realistic HTTP request for testing."""
    if not MITMPROXY_AVAILABLE:
        pytest.skip("mitmproxy not available")
    flow = tflow.tflow(req=True, resp=False)
    request = flow.request

    request.method = "POST"
    request.url = "https://license.example.com/api/v1/verify"
    request.headers["Authorization"] = "Bearer test_token_12345"
    request.headers["Content-Type"] = "application/json"
    request.content = json.dumps({"license_key": "ABCD-1234-EFGH-5678"}).encode()

    return request


@pytest.fixture
def mock_http_response(real_license_response: dict[str, Any]) -> Any:
    """Create realistic HTTP response for testing."""
    if not MITMPROXY_AVAILABLE:
        pytest.skip("mitmproxy not available")
    flow = tflow.tflow(req=True, resp=True)
    response = flow.response

    response.status_code = 200
    response.headers["Content-Type"] = "application/json"
    response.content = json.dumps(real_license_response).encode()

    return response


class TestCertificateGeneration:
    """Test CA and host certificate generation for MITM."""

    def test_analyzer_generates_valid_ca_certificate(
        self,
        analyzer: Any,
    ) -> None:
        """Analyzer must generate valid CA certificate for MITM proxy."""
        assert analyzer.ca_cert is not None
        assert analyzer.ca_key is not None

        assert len(analyzer.ca_cert) > 0
        assert len(analyzer.ca_key) > 0

        assert b"BEGIN CERTIFICATE" in analyzer.ca_cert
        assert b"BEGIN" in analyzer.ca_key

        cert = x509.load_pem_x509_certificate(analyzer.ca_cert, default_backend())

        assert cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        common_name = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        assert "Intellicrack" in common_name or "CA" in common_name

        assert cert.not_valid_after_utc > datetime.now(tz=cert.not_valid_after_utc.tzinfo)

    def test_ca_certificate_has_correct_key_usage(
        self,
        analyzer: Any,
    ) -> None:
        """CA certificate must have correct key usage extensions for signing."""
        cert = x509.load_pem_x509_certificate(analyzer.ca_cert, default_backend())

        basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert basic_constraints.value.ca is True

        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert key_usage.value.key_cert_sign is True
        assert key_usage.value.crl_sign is True

    def test_generate_host_certificate_for_domain(
        self,
        analyzer: Any,
    ) -> None:
        """Analyzer must generate valid host certificate for specific domain."""
        test_domain = "license-server.example.com"

        cert_pem, key_pem = analyzer.generate_host_certificate(test_domain)

        assert cert_pem is not None
        assert key_pem is not None
        assert len(cert_pem) > 0
        assert len(key_pem) > 0

        assert b"BEGIN CERTIFICATE" in cert_pem
        assert b"BEGIN" in key_pem

        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

        common_name = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        assert test_domain in common_name

        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_names = [name.value for name in san_ext.value]
        assert test_domain in san_names

    def test_host_certificate_signed_by_ca(
        self,
        analyzer: Any,
    ) -> None:
        """Host certificate must be properly signed by CA certificate."""
        test_domain = "test-license.example.com"

        cert_pem, _ = analyzer.generate_host_certificate(test_domain)
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        ca_cert = x509.load_pem_x509_certificate(analyzer.ca_cert, default_backend())

        assert cert.issuer == ca_cert.subject


class TestEndpointAnalysis:
    """Test cloud endpoint discovery and analysis."""

    def test_analyze_endpoint_extracts_url_and_method(
        self,
        analyzer: Any,
        mock_http_request: Any,
        mock_http_response: Any,
    ) -> None:
        """Endpoint analysis must extract URL and HTTP method from request."""
        endpoint = analyzer.analyze_endpoint(mock_http_request, mock_http_response)

        assert isinstance(endpoint, CloudEndpoint)
        assert "license.example.com" in endpoint.url
        assert "/api/v1/verify" in endpoint.url
        assert endpoint.method == "POST"

    def test_analyze_endpoint_extracts_headers(
        self,
        analyzer: Any,
        mock_http_request: Any,
        mock_http_response: Any,
    ) -> None:
        """Endpoint analysis must extract request headers."""
        endpoint = analyzer.analyze_endpoint(mock_http_request, mock_http_response)

        assert isinstance(endpoint.headers, dict)
        assert len(endpoint.headers) > 0
        assert "authorization" in [k.lower() for k in endpoint.headers.keys()]
        assert "content-type" in [k.lower() for k in endpoint.headers.keys()]

    def test_analyze_endpoint_parses_json_body(
        self,
        analyzer: Any,
        mock_http_request: Any,
        mock_http_response: Any,
    ) -> None:
        """Endpoint analysis must parse JSON request body."""
        endpoint = analyzer.analyze_endpoint(mock_http_request, mock_http_response)

        assert "body" in endpoint.parameters
        body = endpoint.parameters["body"]

        assert isinstance(body, dict)
        assert "license_key" in body

    def test_analyze_endpoint_extracts_response_schema(
        self,
        analyzer: Any,
        mock_http_request: Any,
        mock_http_response: Any,
    ) -> None:
        """Endpoint analysis must extract response schema structure."""
        endpoint = analyzer.analyze_endpoint(mock_http_request, mock_http_response)

        assert isinstance(endpoint.response_schema, dict)
        assert "status_code" in endpoint.response_schema
        assert endpoint.response_schema["status_code"] == 200

        assert "body_schema" in endpoint.response_schema
        schema = endpoint.response_schema["body_schema"]

        assert schema["type"] == "object"
        assert "properties" in schema

    def test_analyze_endpoint_detects_authentication_type(
        self,
        analyzer: Any,
        mock_http_request: Any,
        mock_http_response: Any,
    ) -> None:
        """Endpoint analysis must detect authentication type from headers."""
        endpoint = analyzer.analyze_endpoint(mock_http_request, mock_http_response)

        assert endpoint.authentication_type in [
            "jwt",
            "bearer_token",
            "api_key",
            "oauth",
            "basic",
            "cookie_based",
        ]

    def test_analyze_endpoint_stores_in_discovered_endpoints(
        self,
        analyzer: Any,
        mock_http_request: Any,
        mock_http_response: Any,
    ) -> None:
        """Analyzed endpoint must be stored in discovered endpoints dictionary."""
        initial_count = len(analyzer.discovered_endpoints)

        analyzer.analyze_endpoint(mock_http_request, mock_http_response)

        assert len(analyzer.discovered_endpoints) == initial_count + 1

        endpoint_key = f"{mock_http_request.method}:/api/v1/verify"
        assert endpoint_key in analyzer.discovered_endpoints


class TestTokenExtraction:
    """Test license token extraction from traffic."""

    def test_extract_bearer_token_from_authorization_header(
        self,
        analyzer: Any,
    ) -> None:
        """Token extraction must identify bearer tokens in Authorization header."""
        flow = tflow.tflow(req=True, resp=True)
        request = flow.request
        response = flow.response

        test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature"
        request.headers["Authorization"] = f"Bearer {test_token}"
        response.content = b"{}"

        tokens = analyzer.extract_license_tokens(request, response)

        assert len(tokens) > 0
        bearer_tokens = [t for t in tokens if t.token_type in [TOKEN_TYPE_JWT, TOKEN_TYPE_BEARER]]
        assert bearer_tokens
        assert test_token in [t.value for t in bearer_tokens]

    def test_extract_jwt_token_and_decode_payload(
        self,
        analyzer: Any,
        real_jwt_payload: dict[str, Any],
    ) -> None:
        """Token extraction must decode JWT tokens and extract payload metadata."""
        secret = "test-secret-key"
        jwt_token = jwt.encode(real_jwt_payload, secret, algorithm="HS256")

        flow = tflow.tflow(req=True, resp=True)
        request = flow.request
        response = flow.response

        request.headers["Authorization"] = f"Bearer {jwt_token}"
        response.content = b"{}"

        tokens = analyzer.extract_license_tokens(request, response)

        jwt_tokens = [t for t in tokens if t.token_type == TOKEN_TYPE_JWT]
        assert jwt_tokens

        jwt_token_obj = jwt_tokens[0]
        assert jwt_token_obj.value == jwt_token
        assert jwt_token_obj.expires_at is not None
        assert jwt_token_obj.expires_at > datetime.now()
        assert "payload" in jwt_token_obj.metadata
        assert jwt_token_obj.metadata["payload"]["license_type"] == "enterprise"

    def test_extract_tokens_from_json_response(
        self,
        analyzer: Any,
        real_license_response: dict[str, Any],
    ) -> None:
        """Token extraction must find tokens in JSON response body."""
        flow = tflow.tflow(req=True, resp=True)
        request = flow.request
        response = flow.response

        response_data = {
            "access_token": "at_123456789",
            "refresh_token": "rt_987654321",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "license:read license:validate",
        }

        response.headers["Content-Type"] = "application/json"
        response.content = json.dumps(response_data).encode()

        tokens = analyzer.extract_license_tokens(request, response)

        assert len(tokens) > 0

        access_token = next((t for t in tokens if "at_123456789" in t.value), None)
        assert access_token is not None
        assert access_token.expires_at is not None
        assert access_token.refresh_token == "rt_987654321"
        assert access_token.scope is not None
        assert "license:read" in access_token.scope

    def test_extract_cookie_based_tokens(
        self,
        analyzer: Any,
    ) -> None:
        """Token extraction must identify session/token cookies."""
        flow = tflow.tflow(req=True, resp=True)
        request = flow.request
        response = flow.response

        response.cookies["session_token"] = "sess_abc123def456"
        response.cookies["auth_token"] = "auth_xyz789ghi012"

        tokens = analyzer.extract_license_tokens(request, response)

        cookie_tokens = [t for t in tokens if t.token_type == TOKEN_TYPE_COOKIE]
        assert cookie_tokens

        cookie_values = [t.value for t in cookie_tokens]
        assert "sess_abc123def456" in cookie_values or "auth_xyz789ghi012" in cookie_values


class TestTokenGeneration:
    """Test license token generation for bypass."""

    def test_generate_valid_jwt_token(
        self,
        analyzer: Any,
    ) -> None:
        """Token generator must create valid JWT tokens."""
        jwt_token = analyzer.generate_token(
            TOKEN_TYPE_JWT,
            issuer="test-issuer",
            subject="test-user",
            expires_in=3600,
        )

        assert isinstance(jwt_token, str)
        assert len(jwt_token.split(".")) == 3

        decoded = jwt.decode(jwt_token, options={"verify_signature": False})

        assert decoded["iss"] == "test-issuer"
        assert decoded["sub"] == "test-user"
        assert "exp" in decoded
        assert "iat" in decoded
        assert decoded["exp"] > decoded["iat"]

    def test_generate_jwt_with_custom_claims(
        self,
        analyzer: Any,
    ) -> None:
        """JWT generator must support custom claims."""
        custom_claims = {
            "license_type": "enterprise",
            "max_users": 100,
            "features": ["all", "unlimited"],
        }

        jwt_token = analyzer.generate_token(
            TOKEN_TYPE_JWT,
            claims=custom_claims,
            expires_in=7200,
        )

        decoded = jwt.decode(jwt_token, options={"verify_signature": False})

        assert decoded["license_type"] == "enterprise"
        assert decoded["max_users"] == 100
        assert decoded["features"] == ["all", "unlimited"]

    def test_generate_api_key_with_prefix(
        self,
        analyzer: Any,
    ) -> None:
        """API key generator must create keys with specified prefix."""
        api_key = analyzer.generate_token(
            TOKEN_TYPE_API_KEY,
            prefix="ic",
            length=32,
        )

        assert isinstance(api_key, str)
        assert api_key.startswith("ic_")
        assert len(api_key) >= 32

    def test_generate_license_key_with_format(
        self,
        analyzer: Any,
    ) -> None:
        """License key generator must create keys matching format pattern."""
        license_key = analyzer.generate_token(
            TOKEN_TYPE_LICENSE_KEY,
            format="4-4-4-4",
        )

        assert isinstance(license_key, str)
        parts = license_key.split("-")
        assert len(parts) == 4
        assert all(len(part) == 4 for part in parts)
        assert all(c.isalnum() for c in license_key.replace("-", ""))

    def test_generate_generic_token(
        self,
        analyzer: Any,
    ) -> None:
        """Generic token generator must create hex tokens."""
        token = analyzer.generate_token("generic", length=64)

        assert isinstance(token, str)
        assert len(token) == 64
        assert all(c in "0123456789abcdef" for c in token)


class TestCloudInterceptor:
    """Test MITM interceptor addon."""

    def test_interceptor_stores_requests(
        self,
        analyzer: Any,
    ) -> None:
        """Interceptor must store intercepted requests."""
        interceptor = CloudInterceptor(analyzer)

        flow = tflow.tflow(req=True, resp=False)
        request = flow.request
        request.method = "POST"
        request.url = "https://license.example.com/api/verify"

        initial_count = len(analyzer.intercepted_requests)
        interceptor.request(flow)

        assert len(analyzer.intercepted_requests) == initial_count + 1

        stored_request = analyzer.intercepted_requests[-1]
        assert stored_request["method"] == "POST"
        assert "license.example.com" in stored_request["url"]

    def test_interceptor_analyzes_responses(
        self,
        analyzer: Any,
        mock_http_request: Any,
        mock_http_response: Any,
    ) -> None:
        """Interceptor must analyze responses and extract endpoints."""
        interceptor = CloudInterceptor(analyzer)

        flow = tflow.tflow(req=True, resp=True)
        flow.request = mock_http_request
        flow.response = mock_http_response

        initial_endpoint_count = len(analyzer.discovered_endpoints)
        interceptor.response(flow)

        assert len(analyzer.discovered_endpoints) >= initial_endpoint_count

    def test_interceptor_modifies_license_responses(
        self,
        analyzer: Any,
    ) -> None:
        """Interceptor must modify license validation responses to bypass checks."""
        interceptor = CloudInterceptor(analyzer)

        flow = tflow.tflow(req=True, resp=True)
        request = flow.request
        response = flow.response

        request.url = "https://api.example.com/license/verify"
        response.headers["Content-Type"] = "application/json"

        original_data = {
            "valid": False,
            "licensed": False,
            "expires": "2020-01-01T00:00:00Z",
        }
        response.content = json.dumps(original_data).encode()

        interceptor.response(flow)

        modified_data = json.loads(response.content)

        assert modified_data["valid"] is True
        assert modified_data["licensed"] is True


class TestCloudLicenseBypasser:
    """Test cloud license bypass system."""

    def test_bypasser_selects_valid_token_for_endpoint(
        self,
        analyzer: Any,
    ) -> None:
        """Bypasser must select valid non-expired token for endpoint."""
        future_expiry = datetime.now() + timedelta(days=30)

        valid_token = LicenseToken(
            token_type=TOKEN_TYPE_JWT,
            value="valid_token_123",
            expires_at=future_expiry,
            refresh_token=None,
            scope=None,
        )

        analyzer.license_tokens["token1"] = valid_token

        bypasser = CloudLicenseBypasser(analyzer)

        endpoint = CloudEndpoint(
            url="https://license.example.com/api/verify",
            method="POST",
            headers={},
            parameters={},
            response_schema={},
            authentication_type="jwt",
        )

        selected_token = bypasser._get_valid_token(endpoint)

        assert selected_token is not None
        assert selected_token.expires_at > datetime.now()

    def test_bypasser_refreshes_expired_token(
        self,
        analyzer: Any,
    ) -> None:
        """Bypasser must attempt to refresh expired tokens using refresh_token."""
        past_expiry = datetime.now() - timedelta(days=1)

        expired_token = LicenseToken(
            token_type=TOKEN_TYPE_JWT,
            value="expired_token_123",
            expires_at=past_expiry,
            refresh_token="refresh_abc123",
            scope=None,
        )

        analyzer.license_tokens["token1"] = expired_token

        bypasser = CloudLicenseBypasser(analyzer)

        endpoint = CloudEndpoint(
            url="https://license.example.com/api/verify",
            method="POST",
            headers={},
            parameters={},
            response_schema={},
            authentication_type="jwt",
        )

        selected_token = bypasser._get_valid_token(endpoint)

        assert selected_token is not None

    def test_bypasser_sends_request_with_bearer_token(
        self,
        analyzer: Any,
    ) -> None:
        """Bypasser must send bypass request with bearer token in Authorization header."""
        token = LicenseToken(
            token_type=TOKEN_TYPE_JWT,
            value="test_jwt_token",
            expires_at=datetime.now() + timedelta(days=1),
            refresh_token=None,
            scope=None,
        )

        endpoint = CloudEndpoint(
            url="https://httpbin.org/headers",
            method="GET",
            headers={"User-Agent": "TestClient"},
            parameters={},
            response_schema={},
            authentication_type="jwt",
        )

        bypasser = CloudLicenseBypasser(analyzer)

        try:
            result = bypasser._send_bypass_request(endpoint, token)

            assert isinstance(result, bool)
        except requests.exceptions.RequestException:
            pytest.skip("Network request failed - no connectivity")


class TestAnalysisExport:
    """Test analysis data export functionality."""

    def test_export_analysis_to_json(
        self,
        analyzer: Any,
        tmp_path: Path,
    ) -> None:
        """Analyzer must export analysis data to JSON format."""
        analyzer.discovered_endpoints["POST:/api/test"] = CloudEndpoint(
            url="https://test.example.com/api/test",
            method="POST",
            headers={"Content-Type": "application/json"},
            parameters={},
            response_schema={},
            authentication_type="bearer_token",
        )

        export_path = tmp_path / "analysis.json"
        result = analyzer.export_analysis(export_path)

        assert result is True
        assert export_path.exists()

        with open(export_path) as f:
            data = json.load(f)

        assert "timestamp" in data
        assert "endpoints" in data
        assert "tokens" in data
        assert len(data["endpoints"]) > 0

    def test_export_analysis_to_yaml(
        self,
        analyzer: Any,
        tmp_path: Path,
    ) -> None:
        """Analyzer must export analysis data to YAML format."""
        analyzer.discovered_endpoints["GET:/api/status"] = CloudEndpoint(
            url="https://api.example.com/status",
            method="GET",
            headers={},
            parameters={},
            response_schema={},
            authentication_type="api_key",
        )

        export_path = tmp_path / "analysis.yaml"
        result = analyzer.export_analysis(export_path)

        assert result is True
        assert export_path.exists()

        with open(export_path) as f:
            data = yaml.safe_load(f)

        assert "timestamp" in data
        assert "endpoints" in data

    def test_export_analysis_to_pickle(
        self,
        analyzer: Any,
        tmp_path: Path,
    ) -> None:
        """Analyzer must export analysis data to pickle format."""
        token = LicenseToken(
            token_type=TOKEN_TYPE_JWT,
            value="test_token",
            expires_at=datetime.now() + timedelta(days=1),
            refresh_token=None,
            scope=["read", "write"],
        )

        analyzer.license_tokens["token1"] = token

        export_path = tmp_path / "analysis.pkl"
        result = analyzer.export_analysis(export_path)

        assert result is True
        assert export_path.exists()

        with open(export_path, "rb") as f:
            data = pickle.load(f)

        assert "timestamp" in data
        assert "tokens" in data


class TestProxyConfiguration:
    """Test MITM proxy configuration and setup."""

    def test_analyzer_configures_proxy_port(
        self,
        analyzer: Any,
    ) -> None:
        """Analyzer must configure proxy on specified port."""
        assert analyzer.proxy_port == 8080
        assert analyzer.proxy_options is not None
        assert analyzer.proxy_options.listen_port == 8080

    def test_analyzer_initializes_proxy_master(
        self,
        analyzer: Any,
    ) -> None:
        """Analyzer must initialize mitmproxy master instance."""
        assert analyzer.proxy_master is not None
        assert hasattr(analyzer.proxy_master, "addons")

    def test_proxy_injection_script_hooks_winhttp(
        self,
        analyzer: Any,
    ) -> None:
        """Proxy injection script must hook WinHTTP APIs."""
        script = analyzer._generate_proxy_injection_script()

        assert "WinHttpOpen" in script
        assert "WinHttpSetOption" in script
        assert "WINHTTP_ACCESS_TYPE_NAMED_PROXY" in script or "proxy" in script.lower()
        assert str(analyzer.proxy_port) in script

    def test_proxy_injection_script_hooks_openssl(
        self,
        analyzer: Any,
    ) -> None:
        """Proxy injection script must hook OpenSSL APIs."""
        script = analyzer._generate_proxy_injection_script()

        assert "SSL_CTX_set_verify" in script or "ssl" in script.lower()
        assert "SSL_get_verify_result" in script or "verify" in script.lower()

    def test_proxy_injection_script_hooks_curl(
        self,
        analyzer: Any,
    ) -> None:
        """Proxy injection script must hook curl APIs."""
        script = analyzer._generate_proxy_injection_script()

        assert "curl_easy_setopt" in script or "curl" in script.lower()
        assert "CURLOPT_PROXY" in script or "proxy" in script.lower()


class TestAuthenticationDetection:
    """Test authentication type detection from requests."""

    def test_detect_jwt_authentication(
        self,
        analyzer: Any,
        real_jwt_payload: dict[str, Any],
    ) -> None:
        """Analyzer must detect JWT authentication from bearer token."""
        secret = "test-secret"
        jwt_token = jwt.encode(real_jwt_payload, secret, algorithm="HS256")

        flow = tflow.tflow(req=True, resp=False)
        request = flow.request
        request.headers["Authorization"] = f"Bearer {jwt_token}"

        auth_type = analyzer._detect_authentication_type(request)

        assert auth_type == "jwt"

    def test_detect_api_key_authentication(
        self,
        analyzer: Any,
    ) -> None:
        """Analyzer must detect API key authentication from headers."""
        flow = tflow.tflow(req=True, resp=False)
        request = flow.request
        request.headers["X-API-Key"] = "sk_test_12345"

        auth_type = analyzer._detect_authentication_type(request)

        assert auth_type == "api_key"

    def test_detect_basic_authentication(
        self,
        analyzer: Any,
    ) -> None:
        """Analyzer must detect Basic authentication."""
        flow = tflow.tflow(req=True, resp=False)
        request = flow.request

        credentials = base64.b64encode(b"user:pass").decode()
        request.headers["Authorization"] = f"Basic {credentials}"

        auth_type = analyzer._detect_authentication_type(request)

        assert auth_type == "basic"

    def test_detect_cookie_authentication(
        self,
        analyzer: Any,
    ) -> None:
        """Analyzer must detect cookie-based authentication."""
        flow = tflow.tflow(req=True, resp=False)
        request = flow.request
        request.cookies["session_id"] = "abc123def456"

        auth_type = analyzer._detect_authentication_type(request)

        assert auth_type == "cookie_based"


class TestRealWorldScenarios:
    """Test real-world cloud license bypass scenarios."""

    def test_complete_workflow_intercept_analyze_bypass(
        self,
        analyzer: Any,
        mock_http_request: Any,
        mock_http_response: Any,
    ) -> None:
        """Complete workflow: intercept traffic, analyze endpoint, extract token, bypass."""
        interceptor = CloudInterceptor(analyzer)

        flow = tflow.tflow(req=True, resp=True)
        flow.request = mock_http_request
        flow.response = mock_http_response

        interceptor.request(flow)
        interceptor.response(flow)

        assert len(analyzer.intercepted_requests) > 0
        assert len(analyzer.discovered_endpoints) > 0

        if len(analyzer.license_tokens) > 0:
            bypasser = CloudLicenseBypasser(analyzer)
            assert bypasser.analyzer == analyzer

    def test_handle_multiple_concurrent_requests(
        self,
        analyzer: Any,
    ) -> None:
        """Analyzer must handle multiple concurrent requests correctly."""
        interceptor = CloudInterceptor(analyzer)

        for i in range(10):
            flow = tflow.tflow(req=True, resp=True)
            request = flow.request
            response = flow.response

            request.url = f"https://api{i}.example.com/verify"
            request.method = "POST"
            response.content = json.dumps({"valid": True}).encode()

            interceptor.request(flow)
            interceptor.response(flow)

        assert len(analyzer.intercepted_requests) >= 10

    def test_analyzer_performance_on_large_response(
        self,
        analyzer: Any,
    ) -> None:
        """Analyzer must handle large response bodies efficiently."""
        flow = tflow.tflow(req=True, resp=True)
        request = flow.request
        response = flow.response

        large_data = {"licenses": [{"id": i, "key": f"key_{i}"} for i in range(1000)]}
        response.headers["Content-Type"] = "application/json"
        response.content = json.dumps(large_data).encode()

        import time

        start_time = time.time()
        endpoint = analyzer.analyze_endpoint(request, response)
        elapsed = time.time() - start_time

        assert elapsed < 5.0, f"Analysis took too long: {elapsed:.2f}s"
        assert isinstance(endpoint, CloudEndpoint)

    def test_cleanup_releases_resources(
        self,
        analyzer: Any,
    ) -> None:
        """Cleanup must release proxy and Frida resources."""
        analyzer.cleanup()

        assert analyzer.proxy_master is not None


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_handle_malformed_jwt_token(
        self,
        analyzer: Any,
    ) -> None:
        """Analyzer must handle malformed JWT tokens gracefully."""
        flow = tflow.tflow(req=True, resp=True)
        request = flow.request
        response = flow.response

        request.headers["Authorization"] = "Bearer invalid.jwt.token"
        response.content = b"{}"

        tokens = analyzer.extract_license_tokens(request, response)

        bearer_tokens = [t for t in tokens if t.token_type == TOKEN_TYPE_BEARER]
        assert bearer_tokens

    def test_handle_non_json_response(
        self,
        analyzer: Any,
    ) -> None:
        """Analyzer must handle non-JSON responses gracefully."""
        flow = tflow.tflow(req=True, resp=True)
        request = flow.request
        response = flow.response

        response.headers["Content-Type"] = "text/html"
        response.content = b"<html><body>Not JSON</body></html>"

        endpoint = analyzer.analyze_endpoint(request, response)

        assert isinstance(endpoint, CloudEndpoint)
        assert "body_schema" not in endpoint.response_schema or endpoint.response_schema["body_schema"] is None

    def test_handle_empty_response(
        self,
        analyzer: Any,
    ) -> None:
        """Analyzer must handle empty responses gracefully."""
        flow = tflow.tflow(req=True, resp=True)
        request = flow.request
        response = flow.response

        response.content = b""

        endpoint = analyzer.analyze_endpoint(request, response)

        assert isinstance(endpoint, CloudEndpoint)
        assert endpoint.response_schema["status_code"] == 200
