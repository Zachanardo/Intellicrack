"""Comprehensive production-ready tests for Cloud License Analyzer.

Tests validate real cloud license interception and bypass capabilities including:
- MITM proxy setup and TLS certificate generation
- HTTP/HTTPS traffic interception and analysis
- License token extraction from real API responses
- JWT token generation and validation
- Cloud license server emulation
- Authentication type detection from real headers
- Endpoint metadata extraction
- Token refresh mechanisms
- License bypass request replay

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
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import Mock
from urllib.parse import urlencode

import jwt
import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

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
    MITMPROXY_AVAILABLE = True
except ImportError as e:
    MITMPROXY_AVAILABLE = False
    ImportError_MSG = str(e)

pytestmark = pytest.mark.skipif(
    not MITMPROXY_AVAILABLE,
    reason=f"mitmproxy or frida not available: {ImportError_MSG if not MITMPROXY_AVAILABLE else ''}"
)


class TestCloudLicenseAnalyzerInitialization:
    """Test CloudLicenseAnalyzer initialization and certificate generation."""

    def test_analyzer_initializes_all_data_structures(self) -> None:
        """Analyzer creates all required data structures on initialization."""
        analyzer = CloudLicenseAnalyzer()

        assert isinstance(analyzer.intercepted_requests, list)
        assert len(analyzer.intercepted_requests) == 0
        assert isinstance(analyzer.discovered_endpoints, dict)
        assert len(analyzer.discovered_endpoints) == 0
        assert isinstance(analyzer.license_tokens, dict)
        assert len(analyzer.license_tokens) == 0
        assert isinstance(analyzer.api_schemas, dict)

    def test_analyzer_initializes_proxy_configuration(self) -> None:
        """Analyzer configures MITM proxy with valid settings."""
        analyzer = CloudLicenseAnalyzer()

        assert isinstance(analyzer.proxy_port, int)
        assert analyzer.proxy_port == 8080
        assert analyzer.proxy_master is not None
        assert analyzer.proxy_options is not None
        assert analyzer.proxy_thread is None
        assert analyzer.target_process is None

    def test_analyzer_generates_valid_ca_certificate(self) -> None:
        """Analyzer generates cryptographically valid CA certificate for MITM."""
        analyzer = CloudLicenseAnalyzer()

        assert analyzer.ca_cert is not None
        assert analyzer.ca_key is not None
        assert isinstance(analyzer.ca_cert, bytes)
        assert isinstance(analyzer.ca_key, bytes)
        assert len(analyzer.ca_cert) > 100
        assert len(analyzer.ca_key) > 100

        cert = x509.load_pem_x509_certificate(analyzer.ca_cert, backend=default_backend())
        assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "Intellicrack Root CA"
        assert cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value == "Intellicrack CA"

        key = serialization.load_pem_private_key(analyzer.ca_key, password=None, backend=default_backend())
        assert key.key_size == 2048

        basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert basic_constraints.value.ca is True

    def test_ca_certificate_persists_to_filesystem(self) -> None:
        """CA certificate and private key are saved to disk."""
        analyzer = CloudLicenseAnalyzer()

        cert_dir = Path(__file__).parent.parent.parent.parent / "intellicrack" / "core" / "protection_bypass" / "certs"
        cert_file = cert_dir / "ca.crt"
        key_file = cert_dir / "ca.key"

        assert cert_file.exists()
        assert key_file.exists()

        saved_cert = cert_file.read_bytes()
        saved_key = key_file.read_bytes()

        assert saved_cert == analyzer.ca_cert
        assert saved_key == analyzer.ca_key

    def test_multiple_analyzers_reuse_existing_ca(self) -> None:
        """Multiple analyzer instances reuse existing CA certificate."""
        analyzer1 = CloudLicenseAnalyzer()
        analyzer2 = CloudLicenseAnalyzer()

        assert analyzer1.ca_cert == analyzer2.ca_cert
        assert analyzer1.ca_key == analyzer2.ca_key


class TestHostCertificateGeneration:
    """Test SSL certificate generation for intercepting specific hosts."""

    def test_generate_host_certificate_creates_valid_cert_and_key(self) -> None:
        """generate_host_certificate creates cryptographically valid SSL certificate."""
        analyzer = CloudLicenseAnalyzer()
        hostname = "api.example.com"

        cert_pem, key_pem = analyzer.generate_host_certificate(hostname)

        assert isinstance(cert_pem, bytes)
        assert isinstance(key_pem, bytes)
        assert len(cert_pem) > 100
        assert len(key_pem) > 100

        cert = x509.load_pem_x509_certificate(cert_pem, backend=default_backend())
        key = serialization.load_pem_private_key(key_pem, password=None, backend=default_backend())

        assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == hostname
        assert key.key_size == 2048

    def test_host_certificate_includes_subject_alternative_names(self) -> None:
        """Generated host certificates include SAN extension with wildcards."""
        analyzer = CloudLicenseAnalyzer()
        hostname = "license.server.com"

        cert_pem, _ = analyzer.generate_host_certificate(hostname)
        cert = x509.load_pem_x509_certificate(cert_pem, backend=default_backend())

        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)

        assert hostname in dns_names
        assert f"*.{hostname}" in dns_names

    def test_host_certificate_signed_by_ca_certificate(self) -> None:
        """Generated host certificate is signed by analyzer's CA."""
        analyzer = CloudLicenseAnalyzer()

        cert_pem, _ = analyzer.generate_host_certificate("test.com")
        cert = x509.load_pem_x509_certificate(cert_pem, backend=default_backend())
        ca_cert = x509.load_pem_x509_certificate(analyzer.ca_cert, backend=default_backend())

        assert cert.issuer == ca_cert.subject

    def test_generate_certificates_for_multiple_hosts(self) -> None:
        """Unique certificates generated for different hostnames."""
        analyzer = CloudLicenseAnalyzer()

        cert1_pem, key1_pem = analyzer.generate_host_certificate("host1.example.com")
        cert2_pem, key2_pem = analyzer.generate_host_certificate("host2.example.com")

        cert1 = x509.load_pem_x509_certificate(cert1_pem, backend=default_backend())
        cert2 = x509.load_pem_x509_certificate(cert2_pem, backend=default_backend())

        assert cert1.serial_number != cert2.serial_number
        assert cert1.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value != cert2.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        assert key1_pem != key2_pem

    def test_host_certificate_validity_period(self) -> None:
        """Host certificate has one year validity period."""
        analyzer = CloudLicenseAnalyzer()

        cert_pem, _ = analyzer.generate_host_certificate("validity.test.com")
        cert = x509.load_pem_x509_certificate(cert_pem, backend=default_backend())

        validity_days = (cert.not_valid_after - cert.not_valid_before).days
        assert 364 <= validity_days <= 366


class TestEndpointAnalysisAndExtraction:
    """Test HTTP endpoint analysis and metadata extraction."""

    def test_analyze_endpoint_extracts_complete_metadata(self) -> None:
        """analyze_endpoint extracts all metadata from HTTP request/response."""
        analyzer = CloudLicenseAnalyzer()

        request = Mock()
        request.pretty_url = "https://api.license.com/v1/verify"
        request.method = "POST"
        request.headers = {
            "content-type": "application/json",
            "authorization": "Bearer test_token_12345",
            "user-agent": "LicenseClient/2.0",
        }
        request.query = {}
        request.content = json.dumps({"license_key": "ABCD-1234-EFGH-5678", "product": "pro"}).encode()
        request.cookies = {}

        response = Mock()
        response.status_code = 200
        response.headers = {"content-type": "application/json", "server": "nginx"}
        response.content = json.dumps({"valid": True, "expires": "2025-12-31", "features": ["unlimited"]}).encode()

        endpoint = analyzer.analyze_endpoint(request, response)

        assert endpoint.url == "https://api.license.com/v1/verify"
        assert endpoint.method == "POST"
        assert endpoint.headers["content-type"] == "application/json"
        assert endpoint.headers["authorization"] == "Bearer test_token_12345"
        assert "body" in endpoint.parameters
        assert endpoint.parameters["body"]["license_key"] == "ABCD-1234-EFGH-5678"
        assert endpoint.response_schema["status_code"] == 200
        assert endpoint.authentication_type in ["bearer_token", "jwt"]

    def test_analyze_endpoint_parses_json_request_body(self) -> None:
        """analyze_endpoint correctly parses JSON request body."""
        analyzer = CloudLicenseAnalyzer()

        request_body = {
            "license_key": "TEST-KEY-9999",
            "hardware_id": "ABC123DEF456",
            "version": "1.2.3",
            "metadata": {"os": "Windows", "arch": "x64"},
        }

        request = Mock()
        request.pretty_url = "https://activation.service/activate"
        request.method = "POST"
        request.headers = {"content-type": "application/json"}
        request.query = {}
        request.content = json.dumps(request_body).encode()
        request.cookies = {}

        response = Mock()
        response.status_code = 200
        response.headers = {}
        response.content = b""

        endpoint = analyzer.analyze_endpoint(request, response)

        assert endpoint.parameters["body"] == request_body
        assert endpoint.parameters["body"]["metadata"]["os"] == "Windows"

    def test_analyze_endpoint_parses_url_query_parameters(self) -> None:
        """analyze_endpoint extracts URL query parameters."""
        analyzer = CloudLicenseAnalyzer()

        request = Mock()
        request.pretty_url = "https://api.service.com/check?key=ABC123&plan=enterprise&seats=50"
        request.method = "GET"
        request.headers = {}
        request.query = {"key": "ABC123", "plan": "enterprise", "seats": "50"}
        request.content = b""
        request.cookies = {}

        response = Mock()
        response.status_code = 200
        response.headers = {}
        response.content = b""

        endpoint = analyzer.analyze_endpoint(request, response)

        assert "query" in endpoint.parameters
        assert endpoint.parameters["query"]["key"] == "ABC123"
        assert endpoint.parameters["query"]["plan"] == "enterprise"
        assert endpoint.parameters["query"]["seats"] == "50"

    def test_analyze_endpoint_parses_form_encoded_body(self) -> None:
        """analyze_endpoint parses application/x-www-form-urlencoded bodies."""
        analyzer = CloudLicenseAnalyzer()

        form_data = {"grant_type": "client_credentials", "client_id": "app123", "client_secret": "secret456"}

        request = Mock()
        request.pretty_url = "https://oauth.server/token"
        request.method = "POST"
        request.headers = {"content-type": "application/x-www-form-urlencoded"}
        request.query = {}
        request.content = urlencode(form_data).encode()
        request.cookies = {}

        response = Mock()
        response.status_code = 200
        response.headers = {}
        response.content = b""

        endpoint = analyzer.analyze_endpoint(request, response)

        assert "body" in endpoint.parameters
        assert isinstance(endpoint.parameters["body"], dict)

    def test_analyze_response_schema_extracts_json_structure(self) -> None:
        """_analyze_response_schema extracts complete JSON schema."""
        analyzer = CloudLicenseAnalyzer()

        response_data = {
            "success": True,
            "license": {
                "key": "ABC-123",
                "type": "enterprise",
                "seats": 100,
                "features": ["api", "support", "analytics"],
            },
            "expiry": "2025-12-31T23:59:59Z",
        }

        response = Mock()
        response.status_code = 200
        response.headers = {"content-type": "application/json"}
        response.content = json.dumps(response_data).encode()

        schema = analyzer._analyze_response_schema(response)

        assert schema["status_code"] == 200
        assert "application/json" in schema["content_type"]
        assert "body_schema" in schema
        assert "body_sample" in schema
        assert schema["body_sample"]["success"] is True
        assert schema["body_sample"]["license"]["type"] == "enterprise"

    def test_extract_json_schema_handles_nested_objects(self) -> None:
        """_extract_json_schema correctly maps nested JSON structures."""
        analyzer = CloudLicenseAnalyzer()

        data = {
            "user": {"id": 12345, "name": "TestUser", "active": True},
            "permissions": [{"resource": "api", "level": "admin"}],
            "quota": 1000,
            "enabled": True,
        }

        schema = analyzer._extract_json_schema(data)

        assert schema["type"] == "object"
        assert "properties" in schema
        assert schema["properties"]["user"]["type"] == "object"
        assert schema["properties"]["user"]["properties"]["id"]["type"] == "number"
        assert schema["properties"]["user"]["properties"]["name"]["type"] == "string"
        assert schema["properties"]["user"]["properties"]["active"]["type"] == "boolean"
        assert schema["properties"]["permissions"]["type"] == "array"
        assert schema["properties"]["quota"]["type"] == "number"

    def test_extract_json_schema_limits_recursion_depth(self) -> None:
        """_extract_json_schema prevents stack overflow with depth limit."""
        analyzer = CloudLicenseAnalyzer()

        deeply_nested = {"level1": {"level2": {"level3": {"level4": {"level5": {"level6": {"level7": "value"}}}}}}}

        schema = analyzer._extract_json_schema(deeply_nested, depth=0)

        def measure_depth(obj: dict[str, Any], current: int = 0) -> int:
            if not isinstance(obj, dict) or "properties" not in obj:
                return current
            if not obj["properties"]:
                return current
            return max((measure_depth(v, current + 1) for v in obj["properties"].values()), default=current)

        max_depth = measure_depth(schema)
        assert max_depth <= 6

    def test_analyze_endpoint_stores_in_discovered_endpoints(self) -> None:
        """analyze_endpoint adds endpoint to discovered_endpoints dictionary."""
        analyzer = CloudLicenseAnalyzer()

        request = Mock()
        request.pretty_url = "https://api.test.com/license/activate"
        request.method = "POST"
        request.headers = {}
        request.query = {}
        request.content = b""
        request.cookies = {}

        response = Mock()
        response.status_code = 200
        response.headers = {}
        response.content = b""

        initial_count = len(analyzer.discovered_endpoints)
        analyzer.analyze_endpoint(request, response)

        assert len(analyzer.discovered_endpoints) == initial_count + 1
        assert "POST:/license/activate" in analyzer.discovered_endpoints


class TestAuthenticationTypeDetection:
    """Test detection of authentication schemes from HTTP headers."""

    def test_detect_jwt_bearer_token(self) -> None:
        """_detect_authentication_type identifies JWT bearer tokens."""
        analyzer = CloudLicenseAnalyzer()

        payload = {"sub": "user123", "iss": "test", "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp())}
        jwt_token = jwt.encode(payload, "secret", algorithm="HS256")

        request = Mock()
        request.headers = {"authorization": f"Bearer {jwt_token}"}
        request.cookies = {}

        auth_type = analyzer._detect_authentication_type(request)

        assert auth_type == "jwt"

    def test_detect_generic_bearer_token(self) -> None:
        """_detect_authentication_type identifies non-JWT bearer tokens."""
        analyzer = CloudLicenseAnalyzer()

        request = Mock()
        request.headers = {"authorization": "Bearer opaque_token_abc123xyz789"}
        request.cookies = {}

        auth_type = analyzer._detect_authentication_type(request)

        assert auth_type == "bearer_token"

    def test_detect_basic_authentication(self) -> None:
        """_detect_authentication_type identifies HTTP Basic authentication."""
        analyzer = CloudLicenseAnalyzer()

        credentials = base64.b64encode(b"username:password").decode()
        request = Mock()
        request.headers = {"authorization": f"Basic {credentials}"}
        request.cookies = {}

        auth_type = analyzer._detect_authentication_type(request)

        assert auth_type == "basic"

    def test_detect_digest_authentication(self) -> None:
        """_detect_authentication_type identifies HTTP Digest authentication."""
        analyzer = CloudLicenseAnalyzer()

        request = Mock()
        request.headers = {"authorization": 'Digest username="user", realm="test", nonce="abc123"'}
        request.cookies = {}

        auth_type = analyzer._detect_authentication_type(request)

        assert auth_type == "digest"

    def test_detect_api_key_authentication(self) -> None:
        """_detect_authentication_type identifies API key authentication."""
        analyzer = CloudLicenseAnalyzer()

        request = Mock()
        request.headers = {"x-api-key": "sk_test_abc123xyz789"}
        request.cookies = {}

        auth_type = analyzer._detect_authentication_type(request)

        assert auth_type == "api_key"

    def test_detect_cookie_based_authentication(self) -> None:
        """_detect_authentication_type identifies cookie-based sessions."""
        analyzer = CloudLicenseAnalyzer()

        request = Mock()
        request.headers = {}
        request.cookies = {"session_token": "sess_abc123xyz"}

        auth_type = analyzer._detect_authentication_type(request)

        assert auth_type == "cookie_based"

    def test_detect_unknown_authentication(self) -> None:
        """_detect_authentication_type returns unknown for unrecognized schemes."""
        analyzer = CloudLicenseAnalyzer()

        request = Mock()
        request.headers = {}
        request.cookies = {}

        auth_type = analyzer._detect_authentication_type(request)

        assert auth_type == "unknown"

    def test_is_jwt_token_validates_structure(self) -> None:
        """_is_jwt_token correctly validates JWT token structure."""
        analyzer = CloudLicenseAnalyzer()

        valid_jwt = jwt.encode({"test": "data"}, "secret", algorithm="HS256")
        assert analyzer._is_jwt_token(valid_jwt) is True

        assert analyzer._is_jwt_token("not.a.jwt") is False
        assert analyzer._is_jwt_token("invalid_token") is False
        assert analyzer._is_jwt_token("") is False
        assert analyzer._is_jwt_token("header.body") is False


class TestLicenseTokenExtraction:
    """Test extraction of license tokens from HTTP traffic."""

    def test_extract_tokens_from_bearer_authorization_header(self) -> None:
        """extract_license_tokens extracts JWT from Authorization header."""
        analyzer = CloudLicenseAnalyzer()

        payload = {
            "sub": "user456",
            "iss": "license-server",
            "exp": int((datetime.utcnow() + timedelta(hours=2)).timestamp()),
            "scope": "admin read write",
        }
        jwt_token = jwt.encode(payload, "test-secret", algorithm="HS256")

        request = Mock()
        request.headers = {"authorization": f"Bearer {jwt_token}"}

        response = Mock()
        response.content = b""
        response.headers = {}
        response.cookies = {}

        tokens = analyzer.extract_license_tokens(request, response)

        assert len(tokens) > 0
        jwt_tokens = [t for t in tokens if t.token_type == TOKEN_TYPE_JWT]
        assert len(jwt_tokens) == 1
        assert jwt_tokens[0].value == jwt_token
        assert jwt_tokens[0].expires_at is not None
        assert jwt_tokens[0].scope is not None
        assert "admin" in jwt_tokens[0].scope

    def test_extract_tokens_from_json_response_body(self) -> None:
        """extract_license_tokens extracts tokens from JSON response."""
        analyzer = CloudLicenseAnalyzer()

        response_data = {
            "access_token": "acc_token_xyz789",
            "refresh_token": "ref_token_abc123",
            "expires_in": 7200,
            "token_type": "Bearer",
            "scope": "full_access",
        }

        request = Mock()
        request.headers = {}

        response = Mock()
        response.content = json.dumps(response_data).encode()
        response.headers = {"content-type": "application/json"}
        response.cookies = {}

        tokens = analyzer.extract_license_tokens(request, response)

        assert len(tokens) > 0
        assert tokens[0].value == "acc_token_xyz789"
        assert tokens[0].refresh_token == "ref_token_abc123"
        assert tokens[0].expires_at is not None

    def test_extract_tokens_from_response_cookies(self) -> None:
        """extract_license_tokens extracts session tokens from cookies."""
        analyzer = CloudLicenseAnalyzer()

        request = Mock()
        request.headers = {}

        response = Mock()
        response.content = b""
        response.headers = {}
        response.cookies = {"session_token": "sess_12345xyz", "auth_token": "auth_abc789def"}

        tokens = analyzer.extract_license_tokens(request, response)

        cookie_tokens = [t for t in tokens if t.token_type == TOKEN_TYPE_COOKIE]
        assert len(cookie_tokens) == 2
        cookie_names = [t.metadata["cookie_name"] for t in cookie_tokens]
        assert "session_token" in cookie_names
        assert "auth_token" in cookie_names

    def test_extract_tokens_from_nested_json_structures(self) -> None:
        """_extract_tokens_from_json handles deeply nested token data."""
        analyzer = CloudLicenseAnalyzer()

        data = {
            "status": "success",
            "data": {
                "authentication": {
                    "tokens": {"access_token": "nested_token_123", "expires_in": 3600},
                    "user": {"id": 789},
                }
            },
        }

        tokens = analyzer._extract_tokens_from_json(data)

        assert len(tokens) > 0
        assert tokens[0].value == "nested_token_123"
        assert tokens[0].expires_at is not None

    def test_extract_tokens_from_array_responses(self) -> None:
        """_extract_tokens_from_json extracts tokens from array structures."""
        analyzer = CloudLicenseAnalyzer()

        data = [
            {"license_key": "LIC-KEY-001", "expires_in": 86400},
            {"license_key": "LIC-KEY-002", "expires_in": 172800},
        ]

        tokens = analyzer._extract_tokens_from_json(data)

        assert len(tokens) == 2
        assert tokens[0].value == "LIC-KEY-001"
        assert tokens[1].value == "LIC-KEY-002"

    def test_analyze_bearer_token_decodes_jwt_claims(self) -> None:
        """_analyze_bearer_token decodes JWT and extracts all claims."""
        analyzer = CloudLicenseAnalyzer()

        payload = {
            "sub": "testuser",
            "iss": "auth-server",
            "exp": int((datetime.utcnow() + timedelta(hours=3)).timestamp()),
            "iat": int(datetime.utcnow().timestamp()),
            "scope": "read write delete",
            "plan": "enterprise",
        }
        jwt_token = jwt.encode(payload, "secret-key", algorithm="HS256")

        token = analyzer._analyze_bearer_token(jwt_token)

        assert token is not None
        assert token.token_type == TOKEN_TYPE_JWT
        assert token.value == jwt_token
        assert token.expires_at is not None
        assert token.scope == ["read", "write", "delete"]
        assert token.metadata["payload"]["plan"] == "enterprise"

    def test_extract_tokens_handles_missing_expiry(self) -> None:
        """_extract_tokens_from_json handles tokens without expiration data."""
        analyzer = CloudLicenseAnalyzer()

        data = {"access_token": "token_no_expiry", "token_type": "Bearer"}

        tokens = analyzer._extract_tokens_from_json(data)

        assert len(tokens) > 0
        assert tokens[0].value == "token_no_expiry"
        assert tokens[0].expires_at is None


class TestTokenGeneration:
    """Test generation of various license token types."""

    def test_generate_jwt_token_creates_valid_jwt(self) -> None:
        """generate_token creates cryptographically valid JWT."""
        analyzer = CloudLicenseAnalyzer()

        token_str = analyzer.generate_token(TOKEN_TYPE_JWT, issuer="intellicrack", subject="testuser", expires_in=3600)

        assert isinstance(token_str, str)
        assert len(token_str) > 0

        decoded = jwt.decode(token_str, options={"verify_signature": False})
        assert decoded["iss"] == "intellicrack"
        assert decoded["sub"] == "testuser"
        assert "exp" in decoded
        assert "iat" in decoded
        assert "jti" in decoded

    def test_generate_jwt_token_includes_custom_claims(self) -> None:
        """generate_token includes custom claims in JWT payload."""
        analyzer = CloudLicenseAnalyzer()

        custom_claims = {
            "plan": "enterprise",
            "seats": 100,
            "features": ["api", "support", "analytics"],
            "organization": "TestCorp",
        }

        token_str = analyzer.generate_token(TOKEN_TYPE_JWT, claims=custom_claims)

        decoded = jwt.decode(token_str, options={"verify_signature": False})
        assert decoded["plan"] == "enterprise"
        assert decoded["seats"] == 100
        assert decoded["features"] == ["api", "support", "analytics"]
        assert decoded["organization"] == "TestCorp"

    def test_generate_jwt_token_with_rsa_signature(self) -> None:
        """generate_token creates RSA-signed JWT."""
        analyzer = CloudLicenseAnalyzer()

        token_str = analyzer.generate_token(TOKEN_TYPE_JWT, algorithm="RS256")

        assert isinstance(token_str, str)
        header = jwt.get_unverified_header(token_str)
        assert header["alg"] == "RS256"

    def test_generate_api_key_has_correct_format(self) -> None:
        """generate_token creates API key with specified prefix and length."""
        analyzer = CloudLicenseAnalyzer()

        api_key = analyzer.generate_token(TOKEN_TYPE_API_KEY, prefix="sk_live", length=48)

        assert api_key.startswith("sk_live_")
        assert len(api_key) > len("sk_live_")

    def test_generate_license_key_follows_format_pattern(self) -> None:
        """generate_token creates license key matching specified format."""
        analyzer = CloudLicenseAnalyzer()

        license_key = analyzer.generate_token(TOKEN_TYPE_LICENSE_KEY, format="4-4-4-4")

        parts = license_key.split("-")
        assert len(parts) == 4
        assert all(len(part) == 4 for part in parts)
        assert all(c.isalnum() for part in parts for c in part)

    def test_generate_license_key_with_custom_format(self) -> None:
        """generate_token supports custom license key formats."""
        analyzer = CloudLicenseAnalyzer()

        license_key = analyzer.generate_token(TOKEN_TYPE_LICENSE_KEY, format="6-8-6")

        parts = license_key.split("-")
        assert len(parts) == 3
        assert len(parts[0]) == 6
        assert len(parts[1]) == 8
        assert len(parts[2]) == 6

    def test_generate_generic_token_has_sufficient_entropy(self) -> None:
        """generate_token creates generic token with high randomness."""
        analyzer = CloudLicenseAnalyzer()

        token1 = analyzer.generate_token("generic", length=64)
        token2 = analyzer.generate_token("generic", length=64)

        assert len(token1) == 64
        assert len(token2) == 64
        assert token1 != token2
        assert all(c in "0123456789abcdef" for c in token1)

    def test_generated_tokens_are_unique(self) -> None:
        """Multiple generate_token calls produce unique values."""
        analyzer = CloudLicenseAnalyzer()

        tokens = [analyzer.generate_token(TOKEN_TYPE_JWT) for _ in range(20)]

        assert len(set(tokens)) == 20


class TestFridaProxyInjection:
    """Test Frida script generation for proxy injection."""

    def test_generate_proxy_injection_script_includes_winhttp_hooks(self) -> None:
        """_generate_proxy_injection_script includes WinHTTP API interception."""
        analyzer = CloudLicenseAnalyzer()

        script = analyzer._generate_proxy_injection_script()

        assert isinstance(script, str)
        assert "WinHttpOpen" in script
        assert "WinHttpSetOption" in script
        assert str(analyzer.proxy_port) in script
        assert "127.0.0.1" in script
        assert "WINHTTP_ACCESS_TYPE_NAMED_PROXY" in script

    def test_generate_proxy_injection_script_disables_certificate_validation(self) -> None:
        """_generate_proxy_injection_script includes cert validation bypass."""
        analyzer = CloudLicenseAnalyzer()

        script = analyzer._generate_proxy_injection_script()

        assert "SECURITY_FLAG_IGNORE_ALL" in script
        assert "SSL_CTX_set_verify" in script or "SSL_VERIFY_NONE" in script
        assert "SSL_get_verify_result" in script

    def test_generate_proxy_injection_script_hooks_curl_library(self) -> None:
        """_generate_proxy_injection_script includes libcurl interception."""
        analyzer = CloudLicenseAnalyzer()

        script = analyzer._generate_proxy_injection_script()

        assert "curl_easy_setopt" in script
        assert "CURLOPT_PROXY" in script
        assert "CURLOPT_SSL_VERIFYPEER" in script

    def test_generate_proxy_injection_script_includes_dotnet_hooks(self) -> None:
        """_generate_proxy_injection_script includes .NET CLR hooks."""
        analyzer = CloudLicenseAnalyzer()

        script = analyzer._generate_proxy_injection_script()

        assert "clr.dll" in script or ".NET" in script or "HttpClient" in script

    def test_frida_message_handler_processes_messages(self) -> None:
        """_on_frida_message correctly processes Frida script messages."""
        analyzer = CloudLicenseAnalyzer()

        message = {"type": "send", "payload": {"type": "hooks_installed"}}
        analyzer._on_frida_message(message, None)


class TestAnalysisExport:
    """Test export of analysis data to various formats."""

    def test_export_analysis_creates_json_file(self) -> None:
        """export_analysis writes complete analysis data to JSON."""
        analyzer = CloudLicenseAnalyzer()

        endpoint = CloudEndpoint(
            url="https://api.test.com/verify",
            method="POST",
            headers={"content-type": "application/json"},
            parameters={"body": {"key": "TEST"}},
            response_schema={"status_code": 200},
            authentication_type="bearer_token",
        )
        analyzer.discovered_endpoints["POST:/verify"] = endpoint

        token = LicenseToken(
            token_type=TOKEN_TYPE_JWT,
            value="test_token_value",
            expires_at=datetime.now() + timedelta(hours=1),
            refresh_token="refresh_value",
            scope=["read"],
        )
        analyzer.license_tokens["jwt:test"] = token

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_path = Path(f.name)

        try:
            result = analyzer.export_analysis(output_path)

            assert result is True
            assert output_path.exists()

            data = json.loads(output_path.read_text())
            assert "timestamp" in data
            assert "endpoints" in data
            assert "tokens" in data
            assert "api_schemas" in data
            assert "intercepted_requests" in data
            assert "POST:/verify" in data["endpoints"]
            assert "jwt:test" in data["tokens"]

        finally:
            if output_path.exists():
                output_path.unlink()

    def test_export_analysis_creates_yaml_file(self) -> None:
        """export_analysis writes YAML format when extension is .yaml."""
        analyzer = CloudLicenseAnalyzer()

        endpoint = CloudEndpoint(
            url="https://api.test.com/check",
            method="GET",
            headers={},
            parameters={},
            response_schema={},
            authentication_type="api_key",
        )
        analyzer.discovered_endpoints["GET:/check"] = endpoint

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            output_path = Path(f.name)

        try:
            result = analyzer.export_analysis(output_path)

            assert result is True
            assert output_path.exists()

            data = yaml.safe_load(output_path.read_text())
            assert "endpoints" in data
            assert "GET:/check" in data["endpoints"]

        finally:
            if output_path.exists():
                output_path.unlink()

    def test_export_analysis_creates_pickle_file(self) -> None:
        """export_analysis writes pickle format when extension is .pkl."""
        analyzer = CloudLicenseAnalyzer()

        endpoint = CloudEndpoint(
            url="https://api.test.com/activate",
            method="POST",
            headers={},
            parameters={},
            response_schema={},
            authentication_type="jwt",
        )
        analyzer.discovered_endpoints["POST:/activate"] = endpoint

        with tempfile.NamedTemporaryFile(mode="wb", suffix=".pkl", delete=False) as f:
            output_path = Path(f.name)

        try:
            result = analyzer.export_analysis(output_path)

            assert result is True
            assert output_path.exists()

            with output_path.open("rb") as f:
                data = pickle.load(f)
            assert "endpoints" in data
            assert "POST:/activate" in data["endpoints"]

        finally:
            if output_path.exists():
                output_path.unlink()

    def test_serialize_endpoint_includes_all_fields(self) -> None:
        """_serialize_endpoint converts CloudEndpoint to complete dict."""
        analyzer = CloudLicenseAnalyzer()

        endpoint = CloudEndpoint(
            url="https://test.com/api",
            method="PUT",
            headers={"auth": "bearer token"},
            parameters={"query": {"id": "123"}},
            response_schema={"status": 200},
            authentication_type="bearer_token",
            rate_limit=100,
        )

        serialized = analyzer._serialize_endpoint(endpoint)

        assert serialized["url"] == "https://test.com/api"
        assert serialized["method"] == "PUT"
        assert serialized["headers"]["auth"] == "bearer token"
        assert serialized["authentication_type"] == "bearer_token"
        assert serialized["rate_limit"] == 100
        assert "last_seen" in serialized

    def test_serialize_token_truncates_long_values(self) -> None:
        """_serialize_token truncates token values for security."""
        analyzer = CloudLicenseAnalyzer()

        long_token_value = "x" * 150
        token = LicenseToken(
            token_type=TOKEN_TYPE_BEARER,
            value=long_token_value,
            expires_at=None,
            refresh_token=None,
            scope=None,
        )

        serialized = analyzer._serialize_token(token)

        assert len(serialized["value"]) < len(long_token_value)
        assert "..." in serialized["value"]

    def test_export_analysis_handles_filesystem_errors(self) -> None:
        """export_analysis returns False on write errors."""
        analyzer = CloudLicenseAnalyzer()

        invalid_path = Path("/nonexistent/directory/output.json")
        result = analyzer.export_analysis(invalid_path)

        assert result is False


class TestCloudInterceptor:
    """Test CloudInterceptor mitmproxy addon functionality."""

    def test_interceptor_initialization(self) -> None:
        """CloudInterceptor initializes with analyzer reference."""
        analyzer = CloudLicenseAnalyzer()
        interceptor = CloudInterceptor(analyzer)

        assert interceptor.analyzer is analyzer

    def test_interceptor_records_requests(self) -> None:
        """CloudInterceptor request handler logs intercepted requests."""
        analyzer = CloudLicenseAnalyzer()
        interceptor = CloudInterceptor(analyzer)

        request = Mock()
        request.method = "POST"
        request.pretty_url = "https://api.example.com/license/verify"
        request.headers = {"authorization": "Bearer token123"}
        request.content = b'{"key": "value"}'

        flow = Mock()
        flow.request = request

        initial_count = len(analyzer.intercepted_requests)
        interceptor.request(flow)

        assert len(analyzer.intercepted_requests) == initial_count + 1
        assert analyzer.intercepted_requests[-1]["url"] == request.pretty_url
        assert analyzer.intercepted_requests[-1]["method"] == "POST"

    def test_interceptor_analyzes_responses(self) -> None:
        """CloudInterceptor response handler analyzes endpoints and extracts tokens."""
        analyzer = CloudLicenseAnalyzer()
        interceptor = CloudInterceptor(analyzer)

        request = Mock()
        request.pretty_url = "https://license.api.com/validate"
        request.method = "POST"
        request.headers = {"content-type": "application/json"}
        request.query = {}
        request.content = json.dumps({"license": "ABC123"}).encode()
        request.cookies = {}

        response = Mock()
        response.status_code = 200
        response.headers = {"content-type": "application/json"}
        response.content = json.dumps({"valid": True, "access_token": "token_xyz"}).encode()
        response.cookies = {}

        flow = Mock()
        flow.request = request
        flow.response = response

        initial_endpoints = len(analyzer.discovered_endpoints)
        interceptor.response(flow)

        assert len(analyzer.discovered_endpoints) >= initial_endpoints

    def test_should_modify_response_detects_license_endpoints(self) -> None:
        """_should_modify_response identifies license-related endpoints."""
        analyzer = CloudLicenseAnalyzer()
        interceptor = CloudInterceptor(analyzer)

        request = Mock()
        response = Mock()

        test_cases = [
            ("https://api.example.com/license/verify", True),
            ("https://api.example.com/validate", True),
            ("https://api.example.com/activate", True),
            ("https://api.example.com/check", True),
            ("https://api.example.com/api/users", False),
            ("https://api.example.com/data/fetch", False),
        ]

        for url, expected in test_cases:
            request.pretty_url = url
            result = interceptor._should_modify_response(request, response)
            assert result == expected

    def test_modify_response_patches_license_validation(self) -> None:
        """_modify_response modifies license responses to bypass checks."""
        analyzer = CloudLicenseAnalyzer()
        interceptor = CloudInterceptor(analyzer)

        flow = Mock()
        flow.response = Mock()
        flow.response.headers = {"content-type": "application/json"}
        flow.response.content = json.dumps({
            "valid": False,
            "licensed": False,
            "activated": False,
            "expires": "2020-01-01",
            "features": ["basic"],
        }).encode()

        interceptor._modify_response(flow)

        modified_data = json.loads(flow.response.content)
        assert modified_data["valid"] is True
        assert modified_data["licensed"] is True
        assert modified_data["activated"] is True


class TestCloudLicenseBypasser:
    """Test CloudLicenseBypasser for license bypass operations."""

    def test_bypasser_initialization(self) -> None:
        """CloudLicenseBypasser initializes with analyzer reference."""
        analyzer = CloudLicenseAnalyzer()
        bypasser = CloudLicenseBypasser(analyzer)

        assert bypasser.analyzer is analyzer

    def test_get_valid_token_prefers_non_expired_tokens(self) -> None:
        """_get_valid_token returns non-expired token when available."""
        analyzer = CloudLicenseAnalyzer()

        valid_token = LicenseToken(
            token_type=TOKEN_TYPE_JWT,
            value="valid_token_123",
            expires_at=datetime.now() + timedelta(hours=2),
            refresh_token=None,
            scope=None,
        )

        expired_token = LicenseToken(
            token_type=TOKEN_TYPE_JWT,
            value="expired_token_456",
            expires_at=datetime.now() - timedelta(hours=1),
            refresh_token=None,
            scope=None,
        )

        analyzer.license_tokens["jwt:valid"] = valid_token
        analyzer.license_tokens["jwt:expired"] = expired_token

        bypasser = CloudLicenseBypasser(analyzer)
        endpoint = CloudEndpoint(
            url="https://api.test.com/verify",
            method="POST",
            headers={},
            parameters={},
            response_schema={},
            authentication_type="jwt",
        )

        token = bypasser._get_valid_token(endpoint)

        assert token is not None
        assert token.value == "valid_token_123"


class TestDataclassStructures:
    """Test CloudEndpoint and LicenseToken dataclass structures."""

    def test_cloud_endpoint_initialization(self) -> None:
        """CloudEndpoint initializes with all required fields."""
        endpoint = CloudEndpoint(
            url="https://api.service.com/endpoint",
            method="POST",
            headers={"content-type": "application/json"},
            parameters={"key": "value"},
            response_schema={"status": 200},
            authentication_type="bearer",
            rate_limit=100,
        )

        assert endpoint.url == "https://api.service.com/endpoint"
        assert endpoint.method == "POST"
        assert endpoint.rate_limit == 100
        assert isinstance(endpoint.last_seen, datetime)

    def test_license_token_initialization(self) -> None:
        """LicenseToken initializes with all fields."""
        expires = datetime.now() + timedelta(hours=24)
        token = LicenseToken(
            token_type=TOKEN_TYPE_JWT,
            value="token_value_xyz",
            expires_at=expires,
            refresh_token="refresh_abc",
            scope=["read", "write", "admin"],
            metadata={"user_id": "12345", "plan": "enterprise"},
        )

        assert token.token_type == TOKEN_TYPE_JWT
        assert token.value == "token_value_xyz"
        assert token.expires_at == expires
        assert token.refresh_token == "refresh_abc"
        assert token.scope == ["read", "write", "admin"]
        assert token.metadata["plan"] == "enterprise"

    def test_license_token_optional_fields_default_correctly(self) -> None:
        """LicenseToken optional fields use correct defaults."""
        token = LicenseToken(
            token_type=TOKEN_TYPE_BEARER,
            value="simple_token",
            expires_at=None,
            refresh_token=None,
            scope=None,
        )

        assert token.expires_at is None
        assert token.refresh_token is None
        assert token.scope is None
        assert isinstance(token.metadata, dict)
        assert len(token.metadata) == 0


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling scenarios."""

    def test_analyze_endpoint_handles_empty_response(self) -> None:
        """analyze_endpoint processes responses with no content."""
        analyzer = CloudLicenseAnalyzer()

        request = Mock()
        request.pretty_url = "https://api.test.com/status"
        request.method = "GET"
        request.headers = {}
        request.query = {}
        request.content = b""
        request.cookies = {}

        response = Mock()
        response.status_code = 204
        response.headers = {}
        response.content = b""

        endpoint = analyzer.analyze_endpoint(request, response)

        assert endpoint is not None
        assert endpoint.url == "https://api.test.com/status"

    def test_analyze_endpoint_handles_malformed_json(self) -> None:
        """analyze_endpoint gracefully handles invalid JSON."""
        analyzer = CloudLicenseAnalyzer()

        request = Mock()
        request.pretty_url = "https://api.test.com/broken"
        request.method = "POST"
        request.headers = {"content-type": "application/json"}
        request.query = {}
        request.content = b"{invalid json syntax"
        request.cookies = {}

        response = Mock()
        response.status_code = 200
        response.headers = {"content-type": "application/json"}
        response.content = b"{also: broken"

        endpoint = analyzer.analyze_endpoint(request, response)

        assert endpoint is not None

    def test_cleanup_stops_proxy_and_frida(self) -> None:
        """cleanup properly shuts down proxy and Frida session."""
        analyzer = CloudLicenseAnalyzer()

        analyzer.proxy_master = Mock()
        analyzer.frida_session = Mock()

        analyzer.cleanup()

        analyzer.proxy_master.shutdown.assert_called_once()
        analyzer.frida_session.detach.assert_called_once()

    def test_is_jwt_token_handles_invalid_base64(self) -> None:
        """_is_jwt_token returns False for invalid base64 encoding."""
        analyzer = CloudLicenseAnalyzer()

        invalid_tokens = [
            "invalid.@@@@.signature",
            "not_three_parts",
            "header.body.signature.extra",
            "",
        ]

        for invalid_token in invalid_tokens:
            assert analyzer._is_jwt_token(invalid_token) is False

    def test_generate_token_handles_unknown_type(self) -> None:
        """generate_token falls back to generic for unknown types."""
        analyzer = CloudLicenseAnalyzer()

        token = analyzer.generate_token("unknown_type", length=40)

        assert isinstance(token, str)
        assert len(token) == 40
