"""Production tests for cloud license response generator and hooker.

These tests validate that cloud_license_hooker correctly intercepts network traffic,
generates valid license responses, and handles real-world license server protocols.
Tests MUST FAIL if license response generation is broken or produces invalid responses.

Copyright (C) 2025 Zachary Flint
"""

import json
import socket
import struct
import threading
import time
from collections.abc import Generator
from datetime import datetime, timedelta
from typing import Any

import pytest

from intellicrack.core.network.cloud_license_hooker import CloudLicenseResponseGenerator, run_cloud_license_hooker


class TestCloudLicenseHookerProduction:
    """Production tests for cloud license hooker with real network interception."""

    @pytest.fixture
    def free_port(self) -> int:
        """Find an available port for testing."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port: int = sock.getsockname()[1]
            return port

    @pytest.fixture
    def hooker(self, free_port: int) -> CloudLicenseResponseGenerator:
        """Create cloud license hooker with test configuration."""
        config = {
            "target_ports": [free_port],
            "intercept_mode": "passive",
            "network_delay": 0.01,
            "response_delay": 0.01,
        }
        return CloudLicenseResponseGenerator(config)

    @pytest.fixture
    def active_hooker(self, hooker: CloudLicenseResponseGenerator) -> Generator[CloudLicenseResponseGenerator, None, None]:
        """Create and activate cloud license hooker."""
        hooker.enable_network_api_hooks()
        time.sleep(0.5)
        yield hooker
        hooker.disable_network_api_hooks()
        time.sleep(0.2)

    def test_response_generator_initialization_with_defaults(self) -> None:
        """Response generator initializes with default templates and ports."""
        generator = CloudLicenseResponseGenerator()

        assert generator.target_ports == [443, 8443, 5000, 8080], "Must have default license server ports"
        assert "valid_license" in generator.response_templates, "Must have valid license template"
        assert "trial_license" in generator.response_templates, "Must have trial license template"
        assert "expired_license" in generator.response_templates, "Must have expired license template"
        assert generator.intercept_mode == "passive", "Must default to passive mode"

    def test_response_template_contains_valid_license_fields(self) -> None:
        """Valid license template contains all required fields for bypass."""
        generator = CloudLicenseResponseGenerator()
        valid_template = generator.response_templates["valid_license"]

        assert valid_template["status"] == "valid", "Status must be valid"
        assert valid_template["license_type"] == "professional", "Must be professional license"
        assert valid_template["features"] == ["all"], "Must have all features enabled"
        assert valid_template["max_users"] == "unlimited", "Must allow unlimited users"

        expiry_str = valid_template["expiry_date"]
        expiry_date = datetime.fromisoformat(expiry_str)
        assert expiry_date > datetime.now(), "Expiry date must be in future"
        assert (expiry_date - datetime.now()).days >= 360, "Must be valid for at least 360 days"

    def test_network_hooks_enable_successfully(self, hooker: CloudLicenseResponseGenerator) -> None:
        """Network API hooks enable and create listener threads."""
        assert not hooker.hooks_enabled, "Hooks must be disabled initially"
        assert not hooker.active, "Must not be active initially"

        hooker.enable_network_api_hooks()
        time.sleep(0.3)

        try:
            assert hooker.hooks_enabled, "Hooks must be enabled"
            assert hooker.active, "Must be active after enabling"  # type: ignore[unreachable]
            assert len(hooker.listener_threads) == len(hooker.target_ports), "Must create listener for each port"
        finally:
            hooker.disable_network_api_hooks()

    def test_http_license_request_generates_valid_response(
        self,
        active_hooker: CloudLicenseResponseGenerator,
        free_port: int,
    ) -> None:
        """HTTP license validation request receives valid JSON response."""
        request = (
            b"POST /api/license/verify HTTP/1.1\r\n"
            b"Host: license.example.com\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 45\r\n"
            b"\r\n"
            b'{"product": "TestApp", "version": "1.0.0"}'
        )

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(5.0)
            client.connect(("127.0.0.1", free_port))
            client.sendall(request)

            response_data = b""
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                if b"\r\n\r\n" in response_data:
                    header_end = response_data.index(b"\r\n\r\n") + 4
                    content_length_pos = response_data.find(b"Content-Length: ")
                    if content_length_pos != -1:
                        content_length_line = response_data[content_length_pos:response_data.find(b"\r\n", content_length_pos)]
                        content_length = int(content_length_line.split(b": ")[1])
                        if len(response_data) >= header_end + content_length:
                            break
                    break

        assert b"HTTP/1.1 200 OK" in response_data, "Must return 200 OK status"
        assert b"Content-Type: application/json" in response_data, "Must have JSON content type"

        body_start = response_data.index(b"\r\n\r\n") + 4
        body = response_data[body_start:]
        license_data = json.loads(body.decode())

        assert license_data["status"] in ["valid", "trial"], "Must have valid status"
        assert "expiry_date" in license_data, "Must include expiry date"
        assert "signature" in license_data, "Must include signature"
        assert "server" in license_data, "Must include server info"

    def test_premium_license_request_detection(
        self,
        active_hooker: CloudLicenseResponseGenerator,
        free_port: int,
    ) -> None:
        """Premium license request in HTTP body triggers appropriate response."""
        request = (
            b"POST /api/license/verify HTTP/1.1\r\n"
            b"Host: license.example.com\r\n"
            b"Content-Length: 50\r\n"
            b"\r\n"
            b'{"product": "TestApp", "type": "premium"}'
        )

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(5.0)
            client.connect(("127.0.0.1", free_port))
            client.sendall(request)

            response_data = b""
            while True:
                chunk = client.recv(4096)
                if not chunk or len(response_data) > 1024:
                    break
                response_data += chunk
                if b"\r\n\r\n" in response_data:
                    break

        assert b"HTTP/1.1 200 OK" in response_data, "Must respond to premium request"

    def test_websocket_license_response_format(self, hooker: CloudLicenseResponseGenerator) -> None:
        """WebSocket license response uses correct frame format."""
        request_info = {
            "timestamp": datetime.now().isoformat(),
            "source": "127.0.0.1:12345",
            "port": 443,
            "data": b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n",
            "protocol": "websocket",
            "connection_time": time.time(),
            "processing_delay": 0.1,
        }

        response = hooker._handle_websocket_request(request_info)

        assert response is not None, "WebSocket response must be generated"
        assert len(response) > 2, "Must have valid WebSocket frame"
        assert response[0] == 0x81, "Must be FIN + text frame"

        payload_len = response[1]
        if payload_len < 126:
            payload_start = 2
        elif payload_len == 126:
            payload_start = 4
            payload_len = struct.unpack(">H", response[2:4])[0]
        else:
            payload_start = 10
            payload_len = struct.unpack(">Q", response[2:10])[0]

        payload = response[payload_start:payload_start + payload_len]
        license_data = json.loads(payload.decode())

        assert "status" in license_data, "WebSocket payload must contain license status"
        assert "signature" in license_data, "WebSocket payload must contain signature"

    def test_grpc_license_response_structure(self, hooker: CloudLicenseResponseGenerator) -> None:
        """GRPC license response uses correct message format."""
        request_info = {
            "timestamp": datetime.now().isoformat(),
            "source": "127.0.0.1:12345",
            "port": 8443,
            "data": b"PRI * HTTP/2.0\r\n\r\n",
            "protocol": "grpc",
            "connection_time": time.time(),
            "processing_delay": 0.1,
        }

        response = hooker._handle_grpc_request(request_info)

        assert response is not None, "gRPC response must be generated"
        assert len(response) >= 5, "Must have gRPC message header"
        assert response[0] == 0x00, "Must have no compression flag"

        length = struct.unpack(">I", response[1:5])[0]
        assert length > 0, "Must have payload length"

        payload = response[5:5 + length]
        license_data = json.loads(payload.decode())

        assert "status" in license_data, "gRPC payload must contain license status"

    def test_custom_protocol_license_response(self, hooker: CloudLicenseResponseGenerator) -> None:
        """Custom protocol license response includes magic and version."""
        request_info = {
            "timestamp": datetime.now().isoformat(),
            "source": "127.0.0.1:12345",
            "port": 5000,
            "data": b"\x00\x01\x02\x03custom_data",
            "protocol": "custom",
            "connection_time": time.time(),
            "processing_delay": 0.1,
        }

        response = hooker._handle_custom_protocol(request_info)

        assert response is not None, "Custom protocol response must be generated"
        assert response.startswith(b"LICR"), "Must have magic bytes"

        version = struct.unpack(">H", response[4:6])[0]
        assert version == 0x0001, "Must have version field"

        length = struct.unpack(">I", response[6:10])[0]
        assert length > 0, "Must have payload length"

        payload = response[10:10 + length]
        license_data = json.loads(payload.decode())

        assert "status" in license_data, "Custom protocol payload must contain license status"

    def test_signature_generation_consistency(self, hooker: CloudLicenseResponseGenerator) -> None:
        """Signature generation produces consistent hashes for identical data."""
        license_data = {
            "status": "valid",
            "license_type": "professional",
            "expiry_date": "2025-12-31",
        }

        signature1 = hooker._generate_signature(license_data.copy())
        signature2 = hooker._generate_signature(license_data.copy())

        assert signature1 == signature2, "Signatures must be consistent"
        assert len(signature1) == 64, "Signature must be SHA256 hex string"
        assert all(c in "0123456789abcdef" for c in signature1), "Must be valid hex"

    def test_protocol_detection_http(self, hooker: CloudLicenseResponseGenerator) -> None:
        """Protocol detection correctly identifies HTTP requests."""
        http_get = b"GET /api/license HTTP/1.1\r\nHost: example.com\r\n"
        http_post = b"POST /verify HTTP/1.1\r\nHost: example.com\r\n"

        assert hooker._detect_protocol(http_get) == "http", "Must detect HTTP GET"
        assert hooker._detect_protocol(http_post) == "http", "Must detect HTTP POST"

    def test_protocol_detection_https_tls(self, hooker: CloudLicenseResponseGenerator) -> None:
        """Protocol detection identifies TLS/SSL handshake for HTTPS."""
        tls_handshake = b"\x16\x03\x01\x00\x05hello"
        tls_handshake_alt = b"\x16\x03\x03\x00\x05hello"

        assert hooker._detect_protocol(tls_handshake) == "https", "Must detect TLS 1.0 handshake"
        assert hooker._detect_protocol(tls_handshake_alt) == "https", "Must detect TLS 1.2 handshake"

    def test_protocol_detection_websocket(self, hooker: CloudLicenseResponseGenerator) -> None:
        """Protocol detection identifies WebSocket upgrade requests."""
        ws_upgrade = b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n"

        assert hooker._detect_protocol(ws_upgrade) == "websocket", "Must detect WebSocket upgrade"

    def test_protocol_detection_grpc(self, hooker: CloudLicenseResponseGenerator) -> None:
        """Protocol detection identifies gRPC HTTP/2 preface."""
        grpc_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

        assert hooker._detect_protocol(grpc_preface) == "grpc", "Must detect gRPC/HTTP2"

    def test_intercepted_requests_logging(
        self,
        active_hooker: CloudLicenseResponseGenerator,
        free_port: int,
    ) -> None:
        """Intercepted requests are logged with complete metadata."""
        request = b"GET /license HTTP/1.1\r\nHost: test.com\r\n\r\n"

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(3.0)
            client.connect(("127.0.0.1", free_port))
            client.sendall(request)
            time.sleep(0.5)

        intercepted = active_hooker.get_intercepted_requests()

        assert len(intercepted) > 0, "Must log intercepted request"
        logged_request = intercepted[0]

        assert "timestamp" in logged_request, "Must include timestamp"
        assert "source" in logged_request, "Must include source address"
        assert logged_request["port"] == free_port, "Must log correct port"
        assert "protocol" in logged_request, "Must include detected protocol"
        assert "connection_time" in logged_request, "Must log connection time"

    def test_generated_responses_logging(
        self,
        active_hooker: CloudLicenseResponseGenerator,
        free_port: int,
    ) -> None:
        """Generated responses are logged with request correlation."""
        request = b"POST /api/verify HTTP/1.1\r\n\r\n"

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(3.0)
            client.connect(("127.0.0.1", free_port))
            client.sendall(request)
            client.recv(1024)
            time.sleep(0.3)

        responses = active_hooker.get_generated_responses()

        assert len(responses) > 0, "Must log generated response"
        logged_response = responses[0]

        assert "timestamp" in logged_response, "Must include timestamp"
        assert "request" in logged_response, "Must correlate with request"
        assert "response" in logged_response, "Must include response data"

    def test_custom_response_template(self, hooker: CloudLicenseResponseGenerator) -> None:
        """Custom response templates can be set and used."""
        custom_template = {
            "status": "enterprise",
            "license_type": "enterprise_unlimited",
            "expiry_date": "2099-12-31",
            "features": ["all", "premium", "enterprise"],
            "max_users": "unlimited",
            "custom_field": "custom_value",
        }

        hooker.set_response_template("enterprise", custom_template)

        assert "enterprise" in hooker.response_templates, "Custom template must be registered"

        response_data = hooker._create_license_response("enterprise")

        assert response_data["status"] == "enterprise", "Must use custom template"
        assert response_data["custom_field"] == "custom_value", "Must include custom fields"
        assert "signature" in response_data, "Must add signature to custom template"

    def test_network_delay_simulation(
        self,
        active_hooker: CloudLicenseResponseGenerator,
        free_port: int,
    ) -> None:
        """Network delay configuration affects response timing."""
        request = b"GET /license HTTP/1.1\r\n\r\n"

        start_time = time.time()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(5.0)
            client.connect(("127.0.0.1", free_port))
            client.sendall(request)
            client.recv(1024)
        elapsed = time.time() - start_time

        assert elapsed >= 0.01, "Must respect network delay configuration"

    def test_clear_logs_functionality(self, hooker: CloudLicenseResponseGenerator) -> None:
        """Clear logs removes all intercepted requests and responses."""
        hooker.intercepted_requests.append({"test": "data1"})
        hooker.generated_responses.append({"test": "data2"})

        assert len(hooker.intercepted_requests) > 0, "Must have requests before clear"
        assert len(hooker.generated_responses) > 0, "Must have responses before clear"

        hooker.clear_logs()

        assert len(hooker.intercepted_requests) == 0, "Requests must be cleared"
        assert len(hooker.generated_responses) == 0, "Responses must be cleared"

    def test_concurrent_connections_handling(
        self,
        active_hooker: CloudLicenseResponseGenerator,
        free_port: int,
    ) -> None:
        """Hooker handles multiple concurrent license requests."""
        request = b"GET /license HTTP/1.1\r\n\r\n"
        num_connections = 5
        responses_received = []

        def send_request() -> None:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                    client.settimeout(5.0)
                    client.connect(("127.0.0.1", free_port))
                    client.sendall(request)
                    response = client.recv(1024)
                    if response:
                        responses_received.append(response)
            except (TimeoutError, ConnectionError):
                pass

        threads = [threading.Thread(target=send_request) for _ in range(num_connections)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10.0)

        assert len(responses_received) >= 3, "Must handle multiple concurrent connections"

    def test_disable_hooks_stops_interception(
        self,
        hooker: CloudLicenseResponseGenerator,
        free_port: int,
    ) -> None:
        """Disabling hooks stops license request interception."""
        hooker.enable_network_api_hooks()
        time.sleep(0.3)
        assert hooker.active, "Must be active after enabling"

        hooker.disable_network_api_hooks()
        time.sleep(0.2)

        assert not hooker.active, "Must be inactive after disabling"
        assert not hooker.hooks_enabled, "Hooks must be disabled"  # type: ignore[unreachable]

    def test_run_cloud_license_hooker_initializes(self) -> None:
        """Run function creates and activates hooker instance."""
        hooker_started = []

        def wrapped_run() -> None:
            hooker_started.append(True)
            run_cloud_license_hooker(None)

        hooker_thread = threading.Thread(target=wrapped_run, daemon=True)
        hooker_thread.start()
        time.sleep(1.0)

        assert hooker_started, "Hooker function must be called"

    def test_trial_license_response_fields(self, hooker: CloudLicenseResponseGenerator) -> None:
        """Trial license template has appropriate trial restrictions."""
        trial_template = hooker.response_templates["trial_license"]

        assert trial_template["status"] == "trial", "Status must be trial"
        assert trial_template["license_type"] == "evaluation", "Must be evaluation type"
        assert trial_template["max_users"] == 5, "Must have user limit"
        assert trial_template["features"] == ["basic"], "Must have limited features"

        expiry_str = trial_template["expiry_date"]
        expiry_date = datetime.fromisoformat(expiry_str)
        trial_days = (expiry_date - datetime.now()).days

        assert 25 <= trial_days <= 35, "Trial must be approximately 30 days"

    def test_expired_license_response_fields(self, hooker: CloudLicenseResponseGenerator) -> None:
        """Expired license template has past expiry date."""
        expired_template = hooker.response_templates["expired_license"]

        assert expired_template["status"] == "expired", "Status must be expired"
        assert expired_template["max_users"] == 0, "Must allow no users"
        assert expired_template["features"] == [], "Must have no features"

        expiry_str = expired_template["expiry_date"]
        expiry_date = datetime.fromisoformat(expiry_str)

        assert expiry_date < datetime.now(), "Expiry date must be in past"

    def test_response_includes_timestamp_and_server_info(self, hooker: CloudLicenseResponseGenerator) -> None:
        """Generated license responses include timestamp and server metadata."""
        response_data = hooker._create_license_response("valid_license")

        assert "timestamp" in response_data, "Must include generation timestamp"
        assert "server" in response_data, "Must include server information"

        server_info = response_data["server"]
        assert "name" in server_info, "Server must have name"
        assert "version" in server_info, "Server must have version"
        assert "region" in server_info, "Server must have region"

        timestamp = datetime.fromisoformat(response_data["timestamp"])
        assert abs((timestamp - datetime.now()).total_seconds()) < 5, "Timestamp must be recent"
