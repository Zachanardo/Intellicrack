"""Comprehensive tests for license protocol handler functionality.

Tests validate real license protocol parsing, manipulation, and exploitation
capabilities for FlexLM and HASP protocols without any mocks or placeholders.
"""

import asyncio
import os
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Tuple

import pytest

from intellicrack.core.network.license_protocol_handler import (
    FlexLMProtocolHandler,
    HASPProtocolHandler,
    LicenseProtocolHandler,
)


class TestLicenseProtocolHandlerBase:
    """Test base LicenseProtocolHandler functionality."""

    def test_base_handler_initialization(self):
        """Test base handler initializes with default configuration."""

        class ConcreteHandler(LicenseProtocolHandler):
            def _run_proxy(self, port: int) -> None:
                pass

            def handle_connection(self, socket: Any, initial_data: bytes) -> None:
                pass

            def generate_response(self, request_data: bytes) -> bytes:
                return b"test_response"

        handler = ConcreteHandler()
        assert handler.config == {}
        assert handler.running is False
        assert handler.proxy_thread is None
        assert handler.port == 8080  # Default port
        assert handler.host == "localhost"  # Default host for security
        assert handler.timeout == 30

    def test_base_handler_custom_configuration(self):
        """Test base handler with custom configuration."""

        class ConcreteHandler(LicenseProtocolHandler):
            def _run_proxy(self, port: int) -> None:
                pass

            def handle_connection(self, socket: Any, initial_data: bytes) -> None:
                pass

            def generate_response(self, request_data: bytes) -> bytes:
                return b"test_response"

        config = {
            "port": 9999,
            "host": "0.0.0.0",
            "bind_host": "127.0.0.1",
            "timeout": 60,
        }
        handler = ConcreteHandler(config)
        assert handler.config == config
        assert handler.port == 9999
        assert handler.host == "0.0.0.0"
        assert handler.bind_host == "127.0.0.1"
        assert handler.timeout == 60

    def test_base_handler_environment_variables(self):
        """Test base handler reads from environment variables."""
        original_port = os.environ.get("LICENSE_PROTOCOL_PORT")
        original_host = os.environ.get("LICENSE_PROTOCOL_HOST")
        original_timeout = os.environ.get("LICENSE_PROTOCOL_TIMEOUT")

        try:
            os.environ["LICENSE_PROTOCOL_PORT"] = "7777"
            os.environ["LICENSE_PROTOCOL_HOST"] = "192.168.1.1"
            os.environ["LICENSE_PROTOCOL_TIMEOUT"] = "120"

            class ConcreteHandler(LicenseProtocolHandler):
                def _run_proxy(self, port: int) -> None:
                    pass

                def handle_connection(self, socket: Any, initial_data: bytes) -> None:
                    pass

                def generate_response(self, request_data: bytes) -> bytes:
                    return b"test_response"

            handler = ConcreteHandler()
            assert handler.port == 7777
            assert handler.host == "192.168.1.1"
            assert handler.timeout == 120

        finally:
            # Restore original environment variables
            if original_port is not None:
                os.environ["LICENSE_PROTOCOL_PORT"] = original_port
            elif "LICENSE_PROTOCOL_PORT" in os.environ:
                del os.environ["LICENSE_PROTOCOL_PORT"]

            if original_host is not None:
                os.environ["LICENSE_PROTOCOL_HOST"] = original_host
            elif "LICENSE_PROTOCOL_HOST" in os.environ:
                del os.environ["LICENSE_PROTOCOL_HOST"]

            if original_timeout is not None:
                os.environ["LICENSE_PROTOCOL_TIMEOUT"] = original_timeout
            elif "LICENSE_PROTOCOL_TIMEOUT" in os.environ:
                del os.environ["LICENSE_PROTOCOL_TIMEOUT"]

    def test_clear_data_functionality(self):
        """Test clear_data method functionality."""

        class ConcreteHandler(LicenseProtocolHandler):
            def __init__(self, config: dict[str, Any] | None = None):
                super().__init__(config)
                self.captured_requests = ["request1", "request2"]
                self.captured_responses = ["response1"]
                self.session_data = {"session1": "data"}
                self.client_connections = {"client1": "connection"}

            def _run_proxy(self, port: int) -> None:
                pass

            def handle_connection(self, socket: Any, initial_data: bytes) -> None:
                pass

            def generate_response(self, request_data: bytes) -> bytes:
                return b"test_response"

        handler = ConcreteHandler()

        # Verify data exists before clearing
        assert len(handler.captured_requests) == 2
        assert len(handler.captured_responses) == 1
        assert len(handler.session_data) == 1
        assert len(handler.client_connections) == 1

        # Clear data
        handler.clear_data()

        # Verify all data is cleared
        assert len(handler.captured_requests) == 0
        assert len(handler.captured_responses) == 0
        assert len(handler.session_data) == 0
        assert len(handler.client_connections) == 0

    def test_status_information(self):
        """Test get_status method returns correct information."""

        class ConcreteHandler(LicenseProtocolHandler):
            def _run_proxy(self, port: int) -> None:
                pass

            def handle_connection(self, socket: Any, initial_data: bytes) -> None:
                pass

            def generate_response(self, request_data: bytes) -> bytes:
                return b"test_response"

        handler = ConcreteHandler({"port": 5555, "host": "test.example.com"})
        status = handler.get_status()

        assert status["protocol"] == "ConcreteHandler"
        assert status["running"] is False
        assert status["port"] == 5555
        assert status["host"] == "test.example.com"
        assert status["thread_active"] is False

    def test_logging_methods(self):
        """Test request and response logging functionality."""

        class ConcreteHandler(LicenseProtocolHandler):
            def _run_proxy(self, port: int) -> None:
                pass

            def handle_connection(self, socket: Any, initial_data: bytes) -> None:
                pass

            def generate_response(self, request_data: bytes) -> bytes:
                return b"test_response"

        handler = ConcreteHandler()

        # Test request logging
        test_request = b"\x01\x02\x03\x04\x05"
        handler.log_request(test_request, "test_client")

        # Test response logging
        test_response = b"\xFF\xFE\xFD\xFC\xFB"
        handler.log_response(test_response, "test_client")

        # These should not raise exceptions and log appropriate messages
        # Real validation would require log inspection, but this tests the methods execute


class TestFlexLMProtocolHandler:
    """Test FlexLM license protocol handler."""

    def test_flexlm_initialization(self):
        """Test FlexLM handler initialization with defaults."""
        handler = FlexLMProtocolHandler()

        assert handler.flexlm_port == 27000
        assert handler.vendor_daemon_port == 27001
        assert handler.flexlm_version == "11.16.2"
        assert handler.license_count == 9999
        assert handler.license_type == "permanent"
        assert handler.feature_version == "2.0"
        assert handler.server_status == "UP"
        assert isinstance(handler.captured_requests, list)
        assert isinstance(handler.captured_responses, list)
        assert isinstance(handler.session_data, dict)
        assert isinstance(handler.client_connections, dict)

    def test_flexlm_custom_configuration(self):
        """Test FlexLM handler with custom configuration."""
        config = {
            "flexlm_port": 28000,
            "vendor_daemon_port": 28001,
            "flexlm_version": "12.0.0",
            "license_count": 100,
            "license_type": "floating",
            "feature_version": "3.0",
            "server_status": "DOWN",
        }
        handler = FlexLMProtocolHandler(config)

        assert handler.flexlm_port == 28000
        assert handler.vendor_daemon_port == 28001
        assert handler.flexlm_version == "12.0.0"
        assert handler.license_count == 100
        assert handler.license_type == "floating"
        assert handler.feature_version == "3.0"
        assert handler.server_status == "DOWN"

    def test_flexlm_hello_response(self):
        """Test FlexLM HELLO command response generation."""
        handler = FlexLMProtocolHandler()

        hello_request = b"HELLO\n"
        response = handler.generate_response(hello_request)

        # Should return version and vendor daemon port
        response_str = response.decode("utf-8")
        assert "HELLO" in response_str
        assert "11" in response_str  # Major version
        assert "16" in response_str  # Minor version
        assert "27001" in response_str  # Vendor daemon port

    def test_flexlm_getlic_response(self):
        """Test FlexLM license checkout (GETLIC) response."""
        handler = FlexLMProtocolHandler()

        getlic_request = b"GETLIC AUTOCAD 2024 user1 workstation1 :0.0\n"
        response = handler.generate_response(getlic_request)

        response_str = response.decode("utf-8")
        assert "GRANT" in response_str
        assert "AUTOCAD" in response_str
        assert "2.0" in response_str  # Feature version
        assert "permanent" in response_str
        assert "HOSTID=ANY" in response_str

    def test_flexlm_getlic_floating_license(self):
        """Test FlexLM floating license response."""
        config = {"license_type": "floating", "feature_version": "1.5"}
        handler = FlexLMProtocolHandler(config)

        getlic_request = b"GETLIC MAYA 2024 artist1 render-farm :0.0\n"
        response = handler.generate_response(getlic_request)

        response_str = response.decode("utf-8")
        assert "GRANT" in response_str
        assert "MAYA" in response_str
        assert "1.5" in response_str
        assert "floating" in response_str

    def test_flexlm_checkin_response(self):
        """Test FlexLM license checkin response."""
        handler = FlexLMProtocolHandler()

        checkin_request = b"CHECKIN AUTOCAD user1 workstation1 handle123\n"
        response = handler.generate_response(checkin_request)

        assert response == b"CHECKIN_OK\n"

    def test_flexlm_heartbeat_response(self):
        """Test FlexLM heartbeat response."""
        handler = FlexLMProtocolHandler()

        heartbeat_request = b"HEARTBEAT\n"
        response = handler.generate_response(heartbeat_request)

        assert response == b"HEARTBEAT_OK\n"

    def test_flexlm_status_response(self):
        """Test FlexLM status query response."""
        config = {"server_status": "UP", "license_count": 5000}
        handler = FlexLMProtocolHandler(config)

        status_request = b"STATUS\n"
        response = handler.generate_response(status_request)

        response_str = response.decode("utf-8")
        assert "STATUS OK" in response_str
        assert "SERVER UP" in response_str
        assert "LICENSES AVAILABLE: 5000" in response_str

    def test_flexlm_unknown_command(self):
        """Test FlexLM unknown command handling."""
        handler = FlexLMProtocolHandler()

        unknown_request = b"UNKNOWN_COMMAND param1 param2\n"
        response = handler.generate_response(unknown_request)

        assert response == b"OK\n"

    def test_flexlm_invalid_request(self):
        """Test FlexLM invalid/malformed request handling."""
        handler = FlexLMProtocolHandler()

        # Too short request
        invalid_request = b"HI"
        response = handler.generate_response(invalid_request)

        assert b"ERROR" in response

    def test_flexlm_request_capture(self):
        """Test FlexLM request capture functionality."""
        handler = FlexLMProtocolHandler()

        # Initial state - no captured requests
        assert len(handler.captured_requests) == 0

        # Generate some responses to capture requests
        handler.generate_response(b"HELLO\n")
        handler.generate_response(b"GETLIC AUTOCAD 2024 user1 host1 :0.0\n")
        handler.generate_response(b"STATUS\n")

        # Verify requests are captured
        assert len(handler.captured_requests) == 3

        # Verify captured data structure
        for captured in handler.captured_requests:
            assert "timestamp" in captured
            assert "data" in captured
            assert "hex" in captured
            assert isinstance(captured["timestamp"], float)
            assert isinstance(captured["data"], bytes)
            assert isinstance(captured["hex"], str)


class TestHASPProtocolHandler:
    """Test HASP/Sentinel license protocol handler."""

    def test_hasp_initialization(self):
        """Test HASP handler initialization with defaults."""
        handler = HASPProtocolHandler()

        assert handler.hasp_port == 1947
        assert handler.hasp_memory_size == 0x20000  # 128KB
        assert handler.hasp_version == "7.50"
        assert handler.hasp_vendor_id == 0x1234
        assert handler.license_features == ["PROFESSIONAL", "ENTERPRISE", "DEVELOPER", "RUNTIME"]
        assert handler.hasp_emulator_version == "HASP_EMU_v2.1"
        assert isinstance(handler.captured_requests, list)
        assert isinstance(handler.captured_responses, list)
        assert isinstance(handler.session_data, dict)
        assert isinstance(handler.client_connections, dict)

    def test_hasp_custom_configuration(self):
        """Test HASP handler with custom configuration."""
        config = {
            "hasp_port": 1948,
            "hasp_memory_size": 0x10000,  # 64KB
            "hasp_version": "8.00",
            "hasp_vendor_id": 0x5678,
            "license_features": ["CUSTOM_FEATURE"],
            "hasp_emulator_version": "HASP_EMU_v3.0",
        }
        handler = HASPProtocolHandler(config)

        assert handler.hasp_port == 1948
        assert handler.hasp_memory_size == 0x10000
        assert handler.hasp_version == "8.00"
        assert handler.hasp_vendor_id == 0x5678
        assert handler.license_features == ["CUSTOM_FEATURE"]
        assert handler.hasp_emulator_version == "HASP_EMU_v3.0"

    def test_hasp_login_response(self):
        """Test HASP login command response."""
        handler = HASPProtocolHandler()

        # HASP_LOGIN command (0x01)
        login_request = struct.pack("<II", 0x01, 0x00)
        response = handler.generate_response(login_request)

        # Should return success status and handle
        assert len(response) == 8
        status, handle = struct.unpack("<II", response)
        assert status == 0x00000000  # Success
        assert handle >= 0x10000000  # Valid handle range
        assert handle <= 0x7FFFFFFF

        # Verify handle is stored in session
        assert "handle" in handler.session_data
        assert handler.session_data["handle"] == handle

    def test_hasp_logout_response(self):
        """Test HASP logout command response."""
        handler = HASPProtocolHandler()

        # HASP_LOGOUT command (0x02)
        logout_request = struct.pack("<II", 0x02, 0x00)
        response = handler.generate_response(logout_request)

        # Should return success status
        assert len(response) == 4
        status = struct.unpack("<I", response)[0]
        assert status == 0x00000000  # Success

    def test_hasp_encrypt_response(self):
        """Test HASP encryption command response."""
        handler = HASPProtocolHandler()

        # Test data to encrypt
        test_data = b"This is test data for encryption"

        # HASP_ENCRYPT command (0x03) with data
        encrypt_request = struct.pack("<II", 0x03, len(test_data)) + test_data
        response = handler.generate_response(encrypt_request)

        # Should return success status + encrypted data
        assert len(response) >= 4
        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000  # Success

        encrypted_data = response[4:]
        assert len(encrypted_data) == len(test_data)
        assert encrypted_data != test_data  # Should be different (encrypted)

    def test_hasp_decrypt_response(self):
        """Test HASP decryption command response."""
        handler = HASPProtocolHandler()

        # First encrypt some data to get encrypted version
        test_data = b"This is test data for round-trip encryption"
        encrypt_request = struct.pack("<II", 0x03, len(test_data)) + test_data
        encrypt_response = handler.generate_response(encrypt_request)
        encrypted_data = encrypt_response[4:]  # Skip status

        # Now decrypt the encrypted data
        decrypt_request = struct.pack("<II", 0x04, len(encrypted_data)) + encrypted_data
        response = handler.generate_response(decrypt_request)

        # Should return success status + decrypted data
        assert len(response) >= 4
        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000  # Success

        decrypted_data = response[4:]
        assert decrypted_data == test_data  # Should match original

    def test_hasp_get_size_response(self):
        """Test HASP get memory size command response."""
        config = {"hasp_memory_size": 0x8000}  # 32KB
        handler = HASPProtocolHandler(config)

        # HASP_GET_SIZE command (0x05)
        get_size_request = struct.pack("<II", 0x05, 0x00)
        response = handler.generate_response(get_size_request)

        # Should return success status + memory size
        assert len(response) == 8
        status, size = struct.unpack("<II", response)
        assert status == 0x00000000  # Success
        assert size == 0x8000  # Configured size

    def test_hasp_read_memory_response(self):
        """Test HASP read memory command response."""
        handler = HASPProtocolHandler()

        # HASP_READ command (0x06) - read from license header area
        offset = 0
        size = 64
        read_request = struct.pack("<IIII", 0x06, 8, offset, size)
        response = handler.generate_response(read_request)

        # Should return success status + memory data
        assert len(response) >= 4
        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000  # Success

        memory_data = response[4:]
        assert len(memory_data) == size

        # Should contain license signature
        assert b"HASP_LIC_" in memory_data

    def test_hasp_read_feature_area(self):
        """Test HASP read from feature area."""
        config = {"license_features": ["CUSTOM", "SPECIAL", "ADVANCED"]}
        handler = HASPProtocolHandler(config)

        # Read from feature area (offset 16-255)
        offset = 32
        size = 128
        read_request = struct.pack("<IIII", 0x06, 8, offset, size)
        response = handler.generate_response(read_request)

        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000

        memory_data = response[4:]
        memory_str = memory_data.decode("utf-8", errors="ignore")

        # Should contain configured features
        assert "CUSTOM" in memory_str
        assert "SPECIAL" in memory_str
        assert "ADVANCED" in memory_str

    def test_hasp_read_data_area(self):
        """Test HASP read from general data area."""
        handler = HASPProtocolHandler()

        # Read from data area (offset > 256)
        offset = 1024
        size = 256
        read_request = struct.pack("<IIII", 0x06, 8, offset, size)
        response = handler.generate_response(read_request)

        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000

        memory_data = response[4:]
        assert len(memory_data) == size

        # Should contain pattern based on offset
        expected_data = bytes((i + offset) % 256 for i in range(size))
        assert memory_data == expected_data

    def test_hasp_write_memory_response(self):
        """Test HASP write memory command response."""
        handler = HASPProtocolHandler()

        # HASP_WRITE command (0x07)
        write_data = b"Test write data"
        write_request = struct.pack("<IIII", 0x07, 8 + len(write_data), 0, len(write_data)) + write_data
        response = handler.generate_response(write_request)

        # Should return success status
        assert len(response) == 4
        status = struct.unpack("<I", response)[0]
        assert status == 0x00000000  # Success

    def test_hasp_get_rtc_response(self):
        """Test HASP get real-time clock command response."""
        handler = HASPProtocolHandler()

        before_time = int(time.time())

        # HASP_GET_RTC command (0x08)
        get_rtc_request = struct.pack("<II", 0x08, 0x00)
        response = handler.generate_response(get_rtc_request)

        after_time = int(time.time())

        # Should return success status + current timestamp
        assert len(response) == 8
        status, timestamp = struct.unpack("<II", response)
        assert status == 0x00000000  # Success
        assert before_time <= timestamp <= after_time

    def test_hasp_get_info_response(self):
        """Test HASP get info command response."""
        config = {"hasp_emulator_version": "HASP_CUSTOM_v4.2"}
        handler = HASPProtocolHandler(config)

        # HASP_GET_INFO command (0x09)
        get_info_request = struct.pack("<II", 0x09, 0x00)
        response = handler.generate_response(get_info_request)

        # Should return success status + version info
        assert len(response) >= 4
        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000  # Success

        info_data = response[4:]
        info_str = info_data.decode("utf-8", errors="ignore")
        assert "HASP_CUSTOM_v4.2" in info_str

    def test_hasp_unknown_command(self):
        """Test HASP unknown command handling."""
        handler = HASPProtocolHandler()

        # Unknown command (0xFF)
        unknown_request = struct.pack("<II", 0xFF, 0x00)
        response = handler.generate_response(unknown_request)

        # Should return success status (generic)
        assert len(response) == 4
        status = struct.unpack("<I", response)[0]
        assert status == 0x00000000  # Generic success

    def test_hasp_malformed_request(self):
        """Test HASP malformed request handling."""
        handler = HASPProtocolHandler()

        # Too short request
        malformed_request = b"\x01\x02\x03"
        response = handler.generate_response(malformed_request)

        # Should return error response
        assert response == b"\xff\xff\xff\xff"

    def test_hasp_request_capture(self):
        """Test HASP request capture functionality."""
        handler = HASPProtocolHandler()

        # Generate some responses to capture requests
        handler.generate_response(struct.pack("<II", 0x01, 0x00))  # Login
        handler.generate_response(struct.pack("<II", 0x05, 0x00))  # Get size
        handler.generate_response(struct.pack("<II", 0x09, 0x00))  # Get info

        # Verify requests are captured
        assert len(handler.captured_requests) == 3

        # Verify captured data structure
        for captured in handler.captured_requests:
            assert "timestamp" in captured
            assert "data" in captured
            assert "hex" in captured
            assert isinstance(captured["timestamp"], float)
            assert isinstance(captured["data"], bytes)
            assert isinstance(captured["hex"], str)


class TestLicenseProtocolIntegration:
    """Integration tests for license protocol handlers."""

    def test_flexlm_concurrent_connections(self):
        """Test FlexLM handler with concurrent client connections."""
        handler = FlexLMProtocolHandler()

        def simulate_client_request(request_data: bytes) -> bytes:
            """Simulate a client making a request."""
            return handler.generate_response(request_data)

        # Simulate multiple concurrent requests
        requests = [
            b"HELLO\n",
            b"GETLIC AUTOCAD 2024 user1 host1 :0.0\n",
            b"GETLIC MAYA 2024 user2 host2 :0.0\n",
            b"STATUS\n",
            b"CHECKIN AUTOCAD user1 host1 handle1\n",
            b"HEARTBEAT\n",
        ]

        # Process requests concurrently
        with ThreadPoolExecutor(max_workers=6) as executor:
            future_to_request = {
                executor.submit(simulate_client_request, req): req
                for req in requests
            }

            responses = {}
            for future in as_completed(future_to_request):
                request = future_to_request[future]
                response = future.result()
                responses[request] = response

        # Verify all requests got responses
        assert len(responses) == len(requests)

        # Verify specific response content
        assert b"HELLO" in responses[b"HELLO\n"]
        assert b"GRANT" in responses[b"GETLIC AUTOCAD 2024 user1 host1 :0.0\n"]
        assert b"GRANT" in responses[b"GETLIC MAYA 2024 user2 host2 :0.0\n"]
        assert b"STATUS OK" in responses[b"STATUS\n"]
        assert responses[b"CHECKIN AUTOCAD user1 host1 handle1\n"] == b"CHECKIN_OK\n"
        assert responses[b"HEARTBEAT\n"] == b"HEARTBEAT_OK\n"

    def test_hasp_concurrent_connections(self):
        """Test HASP handler with concurrent client connections."""
        handler = HASPProtocolHandler()

        def simulate_client_request(request_data: bytes) -> bytes:
            """Simulate a client making a request."""
            return handler.generate_response(request_data)

        # Simulate multiple concurrent HASP requests
        requests = [
            struct.pack("<II", 0x01, 0x00),  # Login
            struct.pack("<II", 0x05, 0x00),  # Get size
            struct.pack("<IIII", 0x06, 8, 0, 64),  # Read memory
            struct.pack("<II", 0x08, 0x00),  # Get RTC
            struct.pack("<II", 0x09, 0x00),  # Get info
            struct.pack("<II", 0x02, 0x00),  # Logout
        ]

        # Process requests concurrently
        with ThreadPoolExecutor(max_workers=6) as executor:
            future_to_request = {
                executor.submit(simulate_client_request, req): req
                for req in requests
            }

            responses = {}
            for future in as_completed(future_to_request):
                request = future_to_request[future]
                response = future.result()
                responses[request] = response

        # Verify all requests got responses
        assert len(responses) == len(requests)

        # Verify response structure for each request type
        for request, response in responses.items():
            command_id = struct.unpack("<I", request[:4])[0]
            if command_id == 0x01:  # Login
                assert len(response) == 8
                status = struct.unpack("<I", response[:4])[0]
                assert status == 0x00000000
            elif command_id in [0x02, 0x05, 0x08, 0x09]:  # Other commands
                assert len(response) >= 4
                status = struct.unpack("<I", response[:4])[0]
                assert status == 0x00000000

    def test_protocol_handler_performance(self):
        """Test protocol handler performance under load."""
        flexlm_handler = FlexLMProtocolHandler()
        hasp_handler = HASPProtocolHandler()

        # Performance test parameters
        num_requests = 100
        max_response_time = 0.1  # 100ms max per request

        # Test FlexLM performance
        start_time = time.time()
        for i in range(num_requests):
            request = f"GETLIC FEATURE{i} 1.0 user{i} host{i} :0.0\n".encode()
            response = flexlm_handler.generate_response(request)
            assert len(response) > 0
        flexlm_total_time = time.time() - start_time

        flexlm_avg_time = flexlm_total_time / num_requests
        assert flexlm_avg_time < max_response_time, f"FlexLM avg response time {flexlm_avg_time:.4f}s exceeds {max_response_time}s"

        # Test HASP performance
        start_time = time.time()
        for i in range(num_requests):
            request = struct.pack("<IIII", 0x06, 8, i * 64, 64)  # Read different memory areas
            response = hasp_handler.generate_response(request)
            assert len(response) > 0
        hasp_total_time = time.time() - start_time

        hasp_avg_time = hasp_total_time / num_requests
        assert hasp_avg_time < max_response_time, f"HASP avg response time {hasp_avg_time:.4f}s exceeds {max_response_time}s"

    def test_protocol_handler_memory_usage(self):
        """Test protocol handler memory usage with large requests."""
        handler = HASPProtocolHandler()

        # Generate large read request
        large_size = 4096  # 4KB read
        read_request = struct.pack("<IIII", 0x06, 8, 1024, large_size)
        response = handler.generate_response(read_request)

        # Verify response is correct size
        assert len(response) == 4 + large_size  # Status + data
        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000

        # Verify data pattern is correct
        memory_data = response[4:]
        expected_data = bytes((i + 1024) % 256 for i in range(large_size))
        assert memory_data == expected_data

    def test_protocol_data_validation(self):
        """Test protocol handlers validate and process real license data structures."""
        # FlexLM real-world feature request
        flexlm_handler = FlexLMProtocolHandler()
        real_flexlm_request = b"GETLIC solidworks_prem 2024.0100 engineer1 CAD-WORKSTATION-01 :0.0\n"
        response = flexlm_handler.generate_response(real_flexlm_request)

        response_str = response.decode("utf-8")
        assert "GRANT solidworks_prem" in response_str
        assert "2024.0100" not in response_str  # Should use configured version
        assert handler.feature_version in response_str
        assert "HOSTID=ANY" in response_str

        # HASP real-world binary data structure
        hasp_handler = HASPProtocolHandler()

        # Simulate real HASP login with vendor-specific data
        login_data = struct.pack("<II", 0x01, 4) + struct.pack("<I", 0x12345678)  # Vendor ID
        response = hasp_handler.generate_response(login_data)

        assert len(response) == 8
        status, handle = struct.unpack("<II", response)
        assert status == 0x00000000
        assert 0x10000000 <= handle <= 0x7FFFFFFF  # Valid handle range

    def test_protocol_error_recovery(self):
        """Test protocol handlers recover gracefully from malformed requests."""
        flexlm_handler = FlexLMProtocolHandler()
        hasp_handler = HASPProtocolHandler()

        # Test various malformed FlexLM requests
        malformed_flexlm = [
            b"",  # Empty
            b"INVALID",  # Too short
            b"GETLIC\x00\xff\xfe",  # Binary data in text protocol
            b"HELLO" * 1000,  # Very long request
        ]

        for malformed in malformed_flexlm:
            response = flexlm_handler.generate_response(malformed)
            assert len(response) > 0  # Should not crash
            if len(malformed) < 4:
                assert b"ERROR" in response
            else:
                assert response in [b"OK\n", b"HELLO 11 16 27001\n"]  # Valid fallback responses

        # Test various malformed HASP requests
        malformed_hasp = [
            b"",  # Empty
            b"\x01",  # Too short
            b"\xff" * 20,  # Invalid command with data
            b"\x01\x00\x00\x00" + b"\x00" * 10000,  # Very long data
        ]

        for malformed in malformed_hasp:
            response = hasp_handler.generate_response(malformed)
            assert len(response) > 0  # Should not crash
            if len(malformed) < 8:
                assert response == b"\xff\xff\xff\xff"  # Error response
            else:
                # Should handle gracefully
                status = struct.unpack("<I", response[:4])[0]
                assert status in [0x00000000, 0xFFFFFFFF]  # Valid status codes

    def test_thread_safety(self):
        """Test protocol handlers are thread-safe."""
        handler = FlexLMProtocolHandler()
        results = []
        errors = []

        def worker_thread(thread_id: int):
            """Worker thread that makes multiple requests."""
            try:
                for i in range(50):
                    request = f"GETLIC FEATURE_T{thread_id}_R{i} 1.0 user{thread_id} host{thread_id} :0.0\n".encode()
                    response = handler.generate_response(request)
                    results.append((thread_id, i, len(response)))
            except Exception as e:
                errors.append((thread_id, str(e)))

        # Start multiple threads
        threads = []
        for tid in range(10):
            thread = threading.Thread(target=worker_thread, args=(tid,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Verify no errors occurred
        assert not errors, f"Thread safety errors: {errors}"

        # Verify all requests were processed
        assert len(results) == 500  # 10 threads * 50 requests each

        # Verify responses have reasonable lengths
        for thread_id, request_id, response_length in results:
            assert response_length > 10  # Reasonable response size


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
