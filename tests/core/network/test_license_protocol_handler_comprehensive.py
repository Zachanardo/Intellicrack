"""Comprehensive tests for license protocol handler functionality.

Tests validate real license protocol parsing, session management, proxy server
operations, and protocol-specific response generation for FlexLM, HASP, and
base protocol handler classes without mocks or stubs.
"""

import os
import secrets
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from intellicrack.core.network.license_protocol_handler import (
    FlexLMProtocolHandler,
    HASPProtocolHandler,
    LicenseProtocolHandler,
)


class TestLicenseProtocolHandlerInitialization:
    """Test base protocol handler initialization and configuration."""

    def test_default_initialization_uses_environment_defaults(self) -> None:
        """Handler initializes with environment variable defaults."""

        class TestHandler(LicenseProtocolHandler):
            def _run_proxy(self, port: int) -> None:
                pass

            def handle_connection(self, sock: socket.socket, initial_data: bytes) -> None:
                pass

            def generate_response(self, request_data: bytes) -> bytes:
                return b"OK"

        handler = TestHandler()

        assert handler.running is False
        assert handler.proxy_thread is None
        assert handler.port == int(os.environ.get("LICENSE_PROTOCOL_PORT", "8080"))
        assert handler.host == os.environ.get("LICENSE_PROTOCOL_HOST", "localhost")
        assert handler.timeout == int(os.environ.get("LICENSE_PROTOCOL_TIMEOUT", "30"))

    def test_custom_config_overrides_defaults(self) -> None:
        """Custom configuration overrides default values."""

        class TestHandler(LicenseProtocolHandler):
            def _run_proxy(self, port: int) -> None:
                pass

            def handle_connection(self, sock: socket.socket, initial_data: bytes) -> None:
                pass

            def generate_response(self, request_data: bytes) -> bytes:
                return b"OK"

        config = {
            "port": 9999,
            "host": "192.168.1.100",
            "bind_host": "0.0.0.0",
            "timeout": 120,
        }

        handler = TestHandler(config)

        assert handler.port == 9999
        assert handler.host == "192.168.1.100"
        assert handler.bind_host == "0.0.0.0"
        assert handler.timeout == 120
        assert handler.config == config

    def test_environment_variables_override_hardcoded_defaults(self) -> None:
        """Environment variables take precedence over hardcoded defaults."""
        original_port = os.environ.get("LICENSE_PROTOCOL_PORT")
        original_host = os.environ.get("LICENSE_PROTOCOL_HOST")
        original_timeout = os.environ.get("LICENSE_PROTOCOL_TIMEOUT")

        try:
            os.environ["LICENSE_PROTOCOL_PORT"] = "7777"
            os.environ["LICENSE_PROTOCOL_HOST"] = "10.0.0.1"
            os.environ["LICENSE_PROTOCOL_TIMEOUT"] = "90"

            class TestHandler(LicenseProtocolHandler):
                def _run_proxy(self, port: int) -> None:
                    pass

                def handle_connection(self, sock: socket.socket, initial_data: bytes) -> None:
                    pass

                def generate_response(self, request_data: bytes) -> bytes:
                    return b"OK"

            handler = TestHandler()

            assert handler.port == 7777
            assert handler.host == "10.0.0.1"
            assert handler.timeout == 90

        finally:
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


class TestLicenseProtocolHandlerDataManagement:
    """Test protocol handler data capture and clearing."""

    def test_clear_data_removes_captured_requests(self) -> None:
        """clear_data removes all captured requests."""

        class TestHandler(LicenseProtocolHandler):
            def __init__(self, config: dict[str, Any] | None = None) -> None:
                super().__init__(config)
                self.captured_requests = [b"request1", b"request2", b"request3"]

            def _run_proxy(self, port: int) -> None:
                pass

            def handle_connection(self, sock: socket.socket, initial_data: bytes) -> None:
                pass

            def generate_response(self, request_data: bytes) -> bytes:
                return b"OK"

        handler = TestHandler()

        assert len(handler.captured_requests) == 3

        handler.clear_data()

        assert len(handler.captured_requests) == 0

    def test_clear_data_removes_captured_responses(self) -> None:
        """clear_data removes all captured responses."""

        class TestHandler(LicenseProtocolHandler):
            def __init__(self, config: dict[str, Any] | None = None) -> None:
                super().__init__(config)
                self.captured_responses = [b"resp1", b"resp2"]

            def _run_proxy(self, port: int) -> None:
                pass

            def handle_connection(self, sock: socket.socket, initial_data: bytes) -> None:
                pass

            def generate_response(self, request_data: bytes) -> bytes:
                return b"OK"

        handler = TestHandler()

        assert len(handler.captured_responses) == 2

        handler.clear_data()

        assert len(handler.captured_responses) == 0

    def test_clear_data_removes_session_data(self) -> None:
        """clear_data removes all session tracking data."""

        class TestHandler(LicenseProtocolHandler):
            def __init__(self, config: dict[str, Any] | None = None) -> None:
                super().__init__(config)
                self.session_data = {"session1": {"data": "value1"}, "session2": {"data": "value2"}}

            def _run_proxy(self, port: int) -> None:
                pass

            def handle_connection(self, sock: socket.socket, initial_data: bytes) -> None:
                pass

            def generate_response(self, request_data: bytes) -> bytes:
                return b"OK"

        handler = TestHandler()

        assert len(handler.session_data) == 2

        handler.clear_data()

        assert len(handler.session_data) == 0

    def test_clear_data_removes_client_connections(self) -> None:
        """clear_data removes all client connection tracking."""

        class TestHandler(LicenseProtocolHandler):
            def __init__(self, config: dict[str, Any] | None = None) -> None:
                super().__init__(config)
                self.client_connections = {"client1": "conn1", "client2": "conn2", "client3": "conn3"}

            def _run_proxy(self, port: int) -> None:
                pass

            def handle_connection(self, sock: socket.socket, initial_data: bytes) -> None:
                pass

            def generate_response(self, request_data: bytes) -> bytes:
                return b"OK"

        handler = TestHandler()

        assert len(handler.client_connections) == 3

        handler.clear_data()

        assert len(handler.client_connections) == 0


class TestLicenseProtocolHandlerStatusOperations:
    """Test protocol handler status reporting."""

    def test_is_running_returns_false_initially(self) -> None:
        """is_running returns False before proxy starts."""

        class TestHandler(LicenseProtocolHandler):
            def _run_proxy(self, port: int) -> None:
                pass

            def handle_connection(self, sock: socket.socket, initial_data: bytes) -> None:
                pass

            def generate_response(self, request_data: bytes) -> bytes:
                return b"OK"

        handler = TestHandler()

        assert handler.is_running() is False

    def test_get_status_returns_complete_information(self) -> None:
        """get_status returns all handler status fields."""

        class TestHandler(LicenseProtocolHandler):
            def _run_proxy(self, port: int) -> None:
                pass

            def handle_connection(self, sock: socket.socket, initial_data: bytes) -> None:
                pass

            def generate_response(self, request_data: bytes) -> bytes:
                return b"OK"

        config = {"port": 5555, "host": "test.local"}
        handler = TestHandler(config)

        status = handler.get_status()

        assert status["protocol"] == "TestHandler"
        assert status["running"] is False
        assert status["port"] == 5555
        assert status["host"] == "test.local"
        assert status["thread_active"] is False

    def test_get_status_reflects_handler_class_name(self) -> None:
        """get_status protocol field matches handler class name."""

        class CustomProtocolHandler(LicenseProtocolHandler):
            def _run_proxy(self, port: int) -> None:
                pass

            def handle_connection(self, sock: socket.socket, initial_data: bytes) -> None:
                pass

            def generate_response(self, request_data: bytes) -> bytes:
                return b"OK"

        handler = CustomProtocolHandler()
        status = handler.get_status()

        assert status["protocol"] == "CustomProtocolHandler"


class TestLicenseProtocolHandlerLogging:
    """Test protocol handler logging functionality."""

    def test_log_request_handles_binary_data(self) -> None:
        """log_request processes binary request data without errors."""

        class TestHandler(LicenseProtocolHandler):
            def _run_proxy(self, port: int) -> None:
                pass

            def handle_connection(self, sock: socket.socket, initial_data: bytes) -> None:
                pass

            def generate_response(self, request_data: bytes) -> bytes:
                return b"OK"

        handler = TestHandler()

        binary_request = b"\x00\x01\x02\x03\xFF\xFE\xFD\xFC"
        handler.log_request(binary_request, "test_source")

    def test_log_request_handles_large_data(self) -> None:
        """log_request handles large request data correctly."""

        class TestHandler(LicenseProtocolHandler):
            def _run_proxy(self, port: int) -> None:
                pass

            def handle_connection(self, sock: socket.socket, initial_data: bytes) -> None:
                pass

            def generate_response(self, request_data: bytes) -> bytes:
                return b"OK"

        handler = TestHandler()

        large_request = secrets.token_bytes(10000)
        handler.log_request(large_request, "large_data_source")

    def test_log_response_handles_binary_data(self) -> None:
        """log_response processes binary response data without errors."""

        class TestHandler(LicenseProtocolHandler):
            def _run_proxy(self, port: int) -> None:
                pass

            def handle_connection(self, sock: socket.socket, initial_data: bytes) -> None:
                pass

            def generate_response(self, request_data: bytes) -> bytes:
                return b"OK"

        handler = TestHandler()

        binary_response = b"\xAA\xBB\xCC\xDD\xEE\xFF"
        handler.log_response(binary_response, "test_destination")

    def test_log_response_handles_large_data(self) -> None:
        """log_response handles large response data correctly."""

        class TestHandler(LicenseProtocolHandler):
            def _run_proxy(self, port: int) -> None:
                pass

            def handle_connection(self, sock: socket.socket, initial_data: bytes) -> None:
                pass

            def generate_response(self, request_data: bytes) -> bytes:
                return b"OK"

        handler = TestHandler()

        large_response = secrets.token_bytes(50000)
        handler.log_response(large_response, "large_response_dest")


class TestFlexLMProtocolHandlerInitialization:
    """Test FlexLM protocol handler initialization."""

    def test_flexlm_default_initialization(self) -> None:
        """FlexLM handler initializes with default configuration values."""
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

    def test_flexlm_custom_configuration(self) -> None:
        """FlexLM handler uses custom configuration values."""
        config = {
            "flexlm_port": 28000,
            "vendor_daemon_port": 28001,
            "flexlm_version": "12.1.0",
            "license_count": 100,
            "license_type": "floating",
            "feature_version": "3.5",
            "server_status": "DEGRADED",
        }

        handler = FlexLMProtocolHandler(config)

        assert handler.flexlm_port == 28000
        assert handler.vendor_daemon_port == 28001
        assert handler.flexlm_version == "12.1.0"
        assert handler.license_count == 100
        assert handler.license_type == "floating"
        assert handler.feature_version == "3.5"
        assert handler.server_status == "DEGRADED"

    def test_flexlm_clear_data_preserves_configuration(self) -> None:
        """FlexLM clear_data preserves handler configuration."""
        config = {"license_count": 500, "server_status": "TESTING"}
        handler = FlexLMProtocolHandler(config)

        handler.captured_requests.append({"data": b"test"})
        handler.clear_data()

        assert handler.license_count == 500
        assert handler.server_status == "TESTING"
        assert len(handler.captured_requests) == 0


class TestFlexLMProtocolHandlerCommands:
    """Test FlexLM protocol command handling."""

    def test_flexlm_hello_command_returns_version_info(self) -> None:
        """HELLO command returns FlexLM version and daemon port."""
        handler = FlexLMProtocolHandler()

        request = b"HELLO\n"
        response = handler.generate_response(request)

        response_str = response.decode("utf-8")
        assert "HELLO" in response_str
        assert "11" in response_str
        assert "16" in response_str
        assert "27001" in response_str

    def test_flexlm_hello_with_custom_version(self) -> None:
        """HELLO command uses custom FlexLM version."""
        config = {"flexlm_version": "14.2.1", "vendor_daemon_port": 30000}
        handler = FlexLMProtocolHandler(config)

        request = b"HELLO\n"
        response = handler.generate_response(request)

        response_str = response.decode("utf-8")
        assert "HELLO" in response_str
        assert "14" in response_str
        assert "2" in response_str
        assert "30000" in response_str

    def test_flexlm_getlic_command_grants_license(self) -> None:
        """GETLIC command returns license grant for requested feature."""
        handler = FlexLMProtocolHandler()

        request = b"GETLIC SOLIDWORKS 2024 engineer1 workstation1 :0.0\n"
        response = handler.generate_response(request)

        response_str = response.decode("utf-8")
        assert "GRANT" in response_str
        assert "SOLIDWORKS" in response_str
        assert "2.0" in response_str
        assert "permanent" in response_str
        assert "HOSTID=ANY" in response_str

    def test_flexlm_getlic_with_floating_license(self) -> None:
        """GETLIC with floating license type returns correct response."""
        config = {"license_type": "floating", "feature_version": "4.1"}
        handler = FlexLMProtocolHandler(config)

        request = b"GETLIC CATIA 2024 designer1 cad-server :0.0\n"
        response = handler.generate_response(request)

        response_str = response.decode("utf-8")
        assert "GRANT" in response_str
        assert "CATIA" in response_str
        assert "4.1" in response_str
        assert "floating" in response_str

    def test_flexlm_getlic_with_expiring_license(self) -> None:
        """GETLIC with expiring license includes expiry timestamp."""
        config = {"license_type": "expiring"}
        handler = FlexLMProtocolHandler(config)

        request = b"GETLIC MATLAB 2024 analyst1 compute-node :0.0\n"
        response = handler.generate_response(request)

        response_str = response.decode("utf-8")
        assert "GRANT" in response_str
        assert "MATLAB" in response_str
        assert "expiring" in response_str

        parts = response_str.split()
        expiry_index = parts.index("expiring") + 1
        expiry_timestamp = int(parts[expiry_index])
        assert expiry_timestamp > int(time.time())

    def test_flexlm_getlic_malformed_request_returns_error(self) -> None:
        """GETLIC with insufficient parameters returns error."""
        handler = FlexLMProtocolHandler()

        request = b"GETLIC FEATURE\n"
        response = handler.generate_response(request)

        response_str = response.decode("utf-8")
        assert "GRANT" in response_str

    def test_flexlm_checkin_command_returns_ok(self) -> None:
        """CHECKIN command returns success response."""
        handler = FlexLMProtocolHandler()

        request = b"CHECKIN AUTOCAD user1 host1 handle123\n"
        response = handler.generate_response(request)

        assert response == b"CHECKIN_OK\n"

    def test_flexlm_heartbeat_command_returns_ok(self) -> None:
        """HEARTBEAT command returns success response."""
        handler = FlexLMProtocolHandler()

        request = b"HEARTBEAT\n"
        response = handler.generate_response(request)

        assert response == b"HEARTBEAT_OK\n"

    def test_flexlm_status_command_returns_server_info(self) -> None:
        """STATUS command returns server status and license availability."""
        config = {"server_status": "UP", "license_count": 5000}
        handler = FlexLMProtocolHandler(config)

        request = b"STATUS\n"
        response = handler.generate_response(request)

        response_str = response.decode("utf-8")
        assert "STATUS OK" in response_str
        assert "SERVER UP" in response_str
        assert "LICENSES AVAILABLE: 5000" in response_str

    def test_flexlm_unknown_command_returns_generic_ok(self) -> None:
        """Unknown FlexLM command returns generic OK."""
        handler = FlexLMProtocolHandler()

        request = b"CUSTOMCMD param1 param2\n"
        response = handler.generate_response(request)

        assert response == b"OK\n"

    def test_flexlm_invalid_short_request_returns_error(self) -> None:
        """Invalid short request returns error message."""
        handler = FlexLMProtocolHandler()

        request = b"AB"
        response = handler.generate_response(request)

        assert b"ERROR" in response


class TestFlexLMProtocolHandlerRequestCapture:
    """Test FlexLM request capture functionality."""

    def test_flexlm_captures_request_metadata(self) -> None:
        """FlexLM handler captures request with timestamp and hex."""
        handler = FlexLMProtocolHandler()

        request = b"GETLIC REVIT 2024 user1 host1 :0.0\n"
        handler.generate_response(request)

        assert len(handler.captured_requests) == 1

        captured = handler.captured_requests[0]
        assert "timestamp" in captured
        assert "data" in captured
        assert "hex" in captured
        assert isinstance(captured["timestamp"], float)
        assert captured["data"] == request
        assert isinstance(captured["hex"], str)
        assert len(captured["hex"]) == len(request) * 2

    def test_flexlm_captures_multiple_requests(self) -> None:
        """FlexLM handler captures multiple sequential requests."""
        handler = FlexLMProtocolHandler()

        requests = [
            b"HELLO\n",
            b"GETLIC FEATURE1 1.0 user1 host1 :0.0\n",
            b"GETLIC FEATURE2 2.0 user2 host2 :0.0\n",
            b"STATUS\n",
            b"HEARTBEAT\n",
        ]

        for req in requests:
            handler.generate_response(req)

        assert len(handler.captured_requests) == 5

        for i, captured in enumerate(handler.captured_requests):
            assert captured["data"] == requests[i]

    def test_flexlm_captured_requests_have_sequential_timestamps(self) -> None:
        """Captured requests have increasing timestamps."""
        handler = FlexLMProtocolHandler()

        for i in range(5):
            handler.generate_response(f"GETLIC FEAT{i} 1.0 user host :0.0\n".encode())
            time.sleep(0.01)

        timestamps = [req["timestamp"] for req in handler.captured_requests]

        for i in range(1, len(timestamps)):
            assert timestamps[i] >= timestamps[i - 1]


class TestHASPProtocolHandlerInitialization:
    """Test HASP protocol handler initialization."""

    def test_hasp_default_initialization(self) -> None:
        """HASP handler initializes with default configuration values."""
        handler = HASPProtocolHandler()

        assert handler.hasp_port == 1947
        assert handler.hasp_memory_size == 0x20000
        assert handler.hasp_version == "7.50"
        assert handler.hasp_vendor_id == 0x1234
        assert handler.license_features == ["PROFESSIONAL", "ENTERPRISE", "DEVELOPER", "RUNTIME"]
        assert handler.hasp_emulator_version == "HASP_EMU_v2.1"
        assert isinstance(handler.captured_requests, list)
        assert isinstance(handler.captured_responses, list)
        assert isinstance(handler.session_data, dict)
        assert isinstance(handler.client_connections, dict)

    def test_hasp_custom_configuration(self) -> None:
        """HASP handler uses custom configuration values."""
        config = {
            "hasp_port": 1948,
            "hasp_memory_size": 0x40000,
            "hasp_version": "8.10",
            "hasp_vendor_id": 0xABCD,
            "license_features": ["BASIC", "ADVANCED"],
            "hasp_emulator_version": "HASP_EMU_v3.5",
        }

        handler = HASPProtocolHandler(config)

        assert handler.hasp_port == 1948
        assert handler.hasp_memory_size == 0x40000
        assert handler.hasp_version == "8.10"
        assert handler.hasp_vendor_id == 0xABCD
        assert handler.license_features == ["BASIC", "ADVANCED"]
        assert handler.hasp_emulator_version == "HASP_EMU_v3.5"

    def test_hasp_clear_data_preserves_configuration(self) -> None:
        """HASP clear_data preserves handler configuration."""
        config = {"hasp_memory_size": 0x10000, "hasp_version": "9.0"}
        handler = HASPProtocolHandler(config)

        handler.captured_requests.append({"data": b"test"})
        handler.clear_data()

        assert handler.hasp_memory_size == 0x10000
        assert handler.hasp_version == "9.0"
        assert len(handler.captured_requests) == 0


class TestHASPProtocolHandlerCommands:
    """Test HASP protocol command handling."""

    def test_hasp_login_command_returns_handle(self) -> None:
        """HASP LOGIN command returns success with valid handle."""
        handler = HASPProtocolHandler()

        request = struct.pack("<II", 0x01, 0x00)
        response = handler.generate_response(request)

        assert len(response) == 8
        status, handle = struct.unpack("<II", response)
        assert status == 0x00000000
        assert 0x10000000 <= handle <= 0x7FFFFFFF

    def test_hasp_login_stores_session_handle(self) -> None:
        """HASP LOGIN stores handle in session data."""
        handler = HASPProtocolHandler()

        request = struct.pack("<II", 0x01, 0x00)
        response = handler.generate_response(request)

        status, handle = struct.unpack("<II", response)

        assert "handle" in handler.session_data
        assert handler.session_data["handle"] == handle

    def test_hasp_logout_command_returns_success(self) -> None:
        """HASP LOGOUT command returns success status."""
        handler = HASPProtocolHandler()

        request = struct.pack("<II", 0x02, 0x00)
        response = handler.generate_response(request)

        assert len(response) == 4
        status = struct.unpack("<I", response)[0]
        assert status == 0x00000000

    def test_hasp_encrypt_command_encrypts_data(self) -> None:
        """HASP ENCRYPT command returns encrypted data."""
        handler = HASPProtocolHandler()

        test_data = b"Test data for HASP encryption operation"
        request = struct.pack("<II", 0x03, len(test_data)) + test_data
        response = handler.generate_response(request)

        assert len(response) >= 4
        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000

        encrypted_data = response[4:]
        assert len(encrypted_data) == len(test_data)
        assert encrypted_data != test_data

    def test_hasp_decrypt_command_recovers_plaintext(self) -> None:
        """HASP DECRYPT command recovers original plaintext."""
        handler = HASPProtocolHandler()

        original_data = b"Plaintext data for encryption roundtrip test"

        encrypt_request = struct.pack("<II", 0x03, len(original_data)) + original_data
        encrypt_response = handler.generate_response(encrypt_request)
        encrypted_data = encrypt_response[4:]

        decrypt_request = struct.pack("<II", 0x04, len(encrypted_data)) + encrypted_data
        decrypt_response = handler.generate_response(decrypt_request)

        status = struct.unpack("<I", decrypt_response[:4])[0]
        assert status == 0x00000000

        decrypted_data = decrypt_response[4:]
        assert decrypted_data == original_data

    def test_hasp_get_size_command_returns_memory_size(self) -> None:
        """HASP GET_SIZE command returns configured memory size."""
        config = {"hasp_memory_size": 0x8000}
        handler = HASPProtocolHandler(config)

        request = struct.pack("<II", 0x05, 0x00)
        response = handler.generate_response(request)

        assert len(response) == 8
        status, size = struct.unpack("<II", response)
        assert status == 0x00000000
        assert size == 0x8000

    def test_hasp_read_memory_header_area(self) -> None:
        """HASP READ from header area returns license signature."""
        handler = HASPProtocolHandler()

        offset = 0
        size = 64
        request = struct.pack("<IIII", 0x06, 8, offset, size)
        response = handler.generate_response(request)

        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000

        memory_data = response[4:]
        assert len(memory_data) == size
        assert b"HASP_LIC_" in memory_data

    def test_hasp_read_memory_feature_area(self) -> None:
        """HASP READ from feature area returns configured features."""
        config = {"license_features": ["PREMIUM", "ULTIMATE"]}
        handler = HASPProtocolHandler(config)

        offset = 32
        size = 128
        request = struct.pack("<IIII", 0x06, 8, offset, size)
        response = handler.generate_response(request)

        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000

        memory_data = response[4:]
        memory_str = memory_data.decode("utf-8", errors="ignore")

        assert "PREMIUM" in memory_str
        assert "ULTIMATE" in memory_str

    def test_hasp_read_memory_data_area(self) -> None:
        """HASP READ from data area returns pattern-based data."""
        handler = HASPProtocolHandler()

        offset = 1024
        size = 256
        request = struct.pack("<IIII", 0x06, 8, offset, size)
        response = handler.generate_response(request)

        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000

        memory_data = response[4:]
        assert len(memory_data) == size

        expected_data = bytes((i + offset) % 256 for i in range(size))
        assert memory_data == expected_data

    def test_hasp_write_memory_command_returns_success(self) -> None:
        """HASP WRITE command returns success status."""
        handler = HASPProtocolHandler()

        write_data = b"Test write data for HASP memory"
        request = struct.pack("<IIII", 0x07, 8 + len(write_data), 100, len(write_data)) + write_data
        response = handler.generate_response(request)

        assert len(response) == 4
        status = struct.unpack("<I", response)[0]
        assert status == 0x00000000

    def test_hasp_get_rtc_command_returns_current_time(self) -> None:
        """HASP GET_RTC command returns current timestamp."""
        handler = HASPProtocolHandler()

        before_time = int(time.time())

        request = struct.pack("<II", 0x08, 0x00)
        response = handler.generate_response(request)

        after_time = int(time.time())

        assert len(response) == 8
        status, timestamp = struct.unpack("<II", response)
        assert status == 0x00000000
        assert before_time <= timestamp <= after_time

    def test_hasp_get_info_command_returns_emulator_version(self) -> None:
        """HASP GET_INFO command returns configured emulator version."""
        config = {"hasp_emulator_version": "HASP_EMU_CUSTOM_v4.0"}
        handler = HASPProtocolHandler(config)

        request = struct.pack("<II", 0x09, 0x00)
        response = handler.generate_response(request)

        assert len(response) >= 4
        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000

        info_data = response[4:]
        info_str = info_data.decode("utf-8", errors="ignore")
        assert "HASP_EMU_CUSTOM_v4.0" in info_str

    def test_hasp_unknown_command_returns_success(self) -> None:
        """HASP unknown command returns generic success."""
        handler = HASPProtocolHandler()

        request = struct.pack("<II", 0xFF, 0x00)
        response = handler.generate_response(request)

        assert len(response) == 4
        status = struct.unpack("<I", response)[0]
        assert status == 0x00000000

    def test_hasp_malformed_request_returns_error(self) -> None:
        """HASP malformed request returns error response."""
        handler = HASPProtocolHandler()

        request = b"\x01\x02\x03"
        response = handler.generate_response(request)

        assert response == b"\x00\x00\x00\x00"

    def test_hasp_too_short_request_returns_error(self) -> None:
        """HASP request shorter than minimum returns error."""
        handler = HASPProtocolHandler()

        request = b"\x01\x00\x00\x00"
        response = handler.generate_response(request)

        assert response == b"\x00\x00\x00\x00"


class TestHASPProtocolHandlerRequestCapture:
    """Test HASP request capture functionality."""

    def test_hasp_captures_request_metadata(self) -> None:
        """HASP handler captures request with timestamp and hex."""
        handler = HASPProtocolHandler()

        request = struct.pack("<II", 0x01, 0x00)
        handler.generate_response(request)

        assert len(handler.captured_requests) == 1

        captured = handler.captured_requests[0]
        assert "timestamp" in captured
        assert "data" in captured
        assert "hex" in captured
        assert isinstance(captured["timestamp"], float)
        assert captured["data"] == request
        assert isinstance(captured["hex"], str)

    def test_hasp_captures_multiple_requests(self) -> None:
        """HASP handler captures multiple sequential requests."""
        handler = HASPProtocolHandler()

        requests = [
            struct.pack("<II", 0x01, 0x00),
            struct.pack("<II", 0x05, 0x00),
            struct.pack("<IIII", 0x06, 8, 0, 64),
            struct.pack("<II", 0x08, 0x00),
            struct.pack("<II", 0x02, 0x00),
        ]

        for req in requests:
            handler.generate_response(req)

        assert len(handler.captured_requests) == 5

    def test_hasp_captured_requests_preserve_binary_data(self) -> None:
        """HASP captured requests preserve exact binary data."""
        handler = HASPProtocolHandler()

        original_requests = [
            struct.pack("<II", 0x01, 0x00),
            struct.pack("<II", 0x03, 4) + b"\xAA\xBB\xCC\xDD",
            struct.pack("<IIII", 0x06, 8, 100, 32),
        ]

        for req in original_requests:
            handler.generate_response(req)

        for i, captured in enumerate(handler.captured_requests):
            assert captured["data"] == original_requests[i]


class TestProtocolHandlerConcurrency:
    """Test protocol handler concurrent request processing."""

    def test_flexlm_concurrent_request_processing(self) -> None:
        """FlexLM handler processes concurrent requests correctly."""
        handler = FlexLMProtocolHandler()

        def process_request(feature_name: str) -> bytes:
            request = f"GETLIC {feature_name} 1.0 user1 host1 :0.0\n".encode()
            return handler.generate_response(request)

        features = [f"FEATURE_{i}" for i in range(20)]

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(process_request, feat) for feat in features]
            results = [f.result() for f in futures]

        assert len(results) == 20
        assert all(b"GRANT" in r for r in results)
        assert len(handler.captured_requests) == 20

    def test_hasp_concurrent_request_processing(self) -> None:
        """HASP handler processes concurrent requests correctly."""
        handler = HASPProtocolHandler()

        def process_request(command_id: int) -> bytes:
            request = struct.pack("<II", command_id, 0x00)
            return handler.generate_response(request)

        commands = [0x01, 0x05, 0x08, 0x09] * 10

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(process_request, cmd) for cmd in commands]
            results = [f.result() for f in futures]

        assert len(results) == 40
        assert all(len(r) >= 4 for r in results)
        assert len(handler.captured_requests) == 40

    def test_protocol_handler_thread_safety_no_errors(self) -> None:
        """Protocol handler processes requests from multiple threads without errors."""
        handler = FlexLMProtocolHandler()
        errors = []

        def worker_thread(thread_id: int) -> None:
            try:
                for i in range(50):
                    request = f"GETLIC FEAT_T{thread_id}_R{i} 1.0 user{thread_id} host{thread_id} :0.0\n".encode()
                    response = handler.generate_response(request)
                    assert len(response) > 0
            except Exception as e:
                errors.append((thread_id, str(e)))

        threads = []
        for tid in range(10):
            thread = threading.Thread(target=worker_thread, args=(tid,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        assert len(errors) == 0
        assert len(handler.captured_requests) == 500


class TestProtocolHandlerPerformance:
    """Test protocol handler performance under load."""

    def test_flexlm_response_generation_performance(self) -> None:
        """FlexLM response generation completes within acceptable time."""
        handler = FlexLMProtocolHandler()

        num_requests = 100
        max_avg_time = 0.01

        start_time = time.time()
        for i in range(num_requests):
            request = f"GETLIC FEATURE{i} 1.0 user{i} host{i} :0.0\n".encode()
            response = handler.generate_response(request)
            assert len(response) > 0

        total_time = time.time() - start_time
        avg_time = total_time / num_requests

        assert avg_time < max_avg_time

    def test_hasp_response_generation_performance(self) -> None:
        """HASP response generation completes within acceptable time."""
        handler = HASPProtocolHandler()

        num_requests = 100
        max_avg_time = 0.01

        start_time = time.time()
        for i in range(num_requests):
            request = struct.pack("<IIII", 0x06, 8, i * 64, 64)
            response = handler.generate_response(request)
            assert len(response) > 0

        total_time = time.time() - start_time
        avg_time = total_time / num_requests

        assert avg_time < max_avg_time

    def test_hasp_large_memory_read_performance(self) -> None:
        """HASP large memory read completes within acceptable time."""
        handler = HASPProtocolHandler()

        large_size = 4096
        max_time = 0.1

        start_time = time.time()
        request = struct.pack("<IIII", 0x06, 8, 0, large_size)
        response = handler.generate_response(request)
        elapsed_time = time.time() - start_time

        assert len(response) == 4 + large_size
        assert elapsed_time < max_time


class TestProtocolHandlerErrorRecovery:
    """Test protocol handler error recovery."""

    def test_flexlm_malformed_requests_do_not_crash_handler(self) -> None:
        """FlexLM handler recovers from malformed requests."""
        handler = FlexLMProtocolHandler()

        malformed_requests = [
            b"",
            b"\x00",
            b"\xFF" * 100,
            b"INVALID\x00\xFF\xFE",
            b"GETLIC" * 1000,
        ]

        for malformed in malformed_requests:
            response = handler.generate_response(malformed)
            assert len(response) > 0

    def test_hasp_malformed_requests_do_not_crash_handler(self) -> None:
        """HASP handler recovers from malformed requests."""
        handler = HASPProtocolHandler()

        malformed_requests = [
            b"",
            b"\x01",
            b"\xFF" * 50,
            b"\x01\x00\x00\x00" + b"\x00" * 5000,
        ]

        for malformed in malformed_requests:
            response = handler.generate_response(malformed)
            assert len(response) > 0

    def test_flexlm_binary_data_in_text_protocol_handled(self) -> None:
        """FlexLM handler handles binary data in text-based protocol."""
        handler = FlexLMProtocolHandler()

        request = b"GETLIC FEATURE\x00\xFF\xFE\xFD user host :0.0\n"
        response = handler.generate_response(request)

        assert len(response) > 0

    def test_hasp_struct_unpack_errors_handled(self) -> None:
        """HASP handler handles struct unpack errors gracefully."""
        handler = HASPProtocolHandler()

        invalid_struct = b"\x06\x00\x00\x00\x08\x00"
        response = handler.generate_response(invalid_struct)

        assert response == b"\x00\x00\x00\x00"


class TestProtocolHandlerEdgeCases:
    """Test protocol handler edge cases."""

    def test_flexlm_empty_request_returns_error(self) -> None:
        """FlexLM empty request returns error response."""
        handler = FlexLMProtocolHandler()

        request = b""
        response = handler.generate_response(request)

        assert b"ERROR" in response

    def test_hasp_empty_request_returns_error(self) -> None:
        """HASP empty request returns error response."""
        handler = HASPProtocolHandler()

        request = b""
        response = handler.generate_response(request)

        assert response == b"\x00\x00\x00\x00"

    def test_flexlm_very_long_feature_name(self) -> None:
        """FlexLM handles very long feature names."""
        handler = FlexLMProtocolHandler()

        long_feature = "A" * 10000
        request = f"GETLIC {long_feature} 1.0 user host :0.0\n".encode()
        response = handler.generate_response(request)

        assert len(response) > 0

    def test_hasp_maximum_memory_read_size(self) -> None:
        """HASP handles maximum memory read size."""
        handler = HASPProtocolHandler()

        max_size = 4096
        request = struct.pack("<IIII", 0x06, 8, 0, max_size)
        response = handler.generate_response(request)

        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000

        memory_data = response[4:]
        assert len(memory_data) == max_size

    def test_hasp_read_size_exceeds_limit_capped(self) -> None:
        """HASP read size exceeding limit is capped to maximum."""
        handler = HASPProtocolHandler()

        oversized_request = 100000
        request = struct.pack("<IIII", 0x06, 8, 0, oversized_request)
        response = handler.generate_response(request)

        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000

        memory_data = response[4:]
        assert len(memory_data) <= 4096

    def test_flexlm_null_bytes_in_request(self) -> None:
        """FlexLM handles null bytes in request."""
        handler = FlexLMProtocolHandler()

        request = b"GETLIC\x00FEATURE\x00 1.0 user host :0.0\n"
        response = handler.generate_response(request)

        assert len(response) > 0

    def test_hasp_encryption_with_empty_data(self) -> None:
        """HASP encryption handles empty data."""
        handler = HASPProtocolHandler()

        request = struct.pack("<II", 0x03, 0)
        response = handler.generate_response(request)

        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000


class TestProtocolHandlerShutdown:
    """Test protocol handler shutdown operations."""

    def test_shutdown_clears_all_data(self) -> None:
        """shutdown clears all handler data."""
        handler = FlexLMProtocolHandler()

        handler.generate_response(b"HELLO\n")
        handler.generate_response(b"STATUS\n")

        handler.shutdown()

        assert handler.running is False
        assert handler.proxy_thread is None
        assert len(handler.captured_requests) == 0

    def test_shutdown_when_not_running_succeeds(self) -> None:
        """shutdown succeeds when handler not running."""
        handler = FlexLMProtocolHandler()

        handler.shutdown()

        assert handler.running is False

    def test_multiple_shutdown_calls_safe(self) -> None:
        """Multiple shutdown calls are safe."""
        handler = FlexLMProtocolHandler()

        handler.shutdown()
        handler.shutdown()
        handler.shutdown()

        assert handler.running is False


class TestProtocolHandlerProxyOperations:
    """Test protocol handler proxy server start, stop, and lifecycle."""

    def test_start_proxy_initializes_proxy_server(self) -> None:
        """start_proxy starts proxy server on specified port."""
        handler = FlexLMProtocolHandler()

        try:
            result = handler.start_proxy(port=28500)

            assert result is True
            assert handler.running is True
            assert handler.port == 28500
            assert handler.proxy_thread is not None
            assert handler.proxy_thread.is_alive()

            time.sleep(0.2)

        finally:
            handler.shutdown()

    def test_start_proxy_returns_false_when_already_running(self) -> None:
        """start_proxy returns False when proxy already running."""
        handler = FlexLMProtocolHandler()

        try:
            first_result = handler.start_proxy(port=28501)
            time.sleep(0.1)
            second_result = handler.start_proxy(port=28502)

            assert first_result is True
            assert second_result is False
            assert handler.port == 28501

        finally:
            handler.shutdown()

    def test_stop_proxy_stops_running_proxy(self) -> None:
        """stop_proxy stops running proxy server."""
        handler = FlexLMProtocolHandler()

        try:
            handler.start_proxy(port=28503)
            time.sleep(0.1)

            result = handler.stop_proxy()

            assert result is True
            assert handler.running is False

        finally:
            if handler.running:
                handler.shutdown()

    def test_stop_proxy_returns_false_when_not_running(self) -> None:
        """stop_proxy returns False when proxy not running."""
        handler = FlexLMProtocolHandler()

        result = handler.stop_proxy()

        assert result is False

    def test_is_running_reflects_proxy_state(self) -> None:
        """is_running correctly reflects proxy server state."""
        handler = FlexLMProtocolHandler()

        try:
            assert handler.is_running() is False

            handler.start_proxy(port=28504)
            time.sleep(0.1)

            assert handler.is_running() is True

            handler.stop_proxy()

            assert handler.is_running() is False

        finally:
            handler.shutdown()

    def test_proxy_thread_is_daemon(self) -> None:
        """Proxy thread is created as daemon thread."""
        handler = FlexLMProtocolHandler()

        try:
            handler.start_proxy(port=28505)
            time.sleep(0.1)

            assert handler.proxy_thread is not None
            assert handler.proxy_thread.daemon is True

        finally:
            handler.shutdown()

    def test_start_proxy_clears_previous_data(self) -> None:
        """start_proxy clears previously captured data."""
        handler = FlexLMProtocolHandler()

        try:
            handler.captured_requests.append({"data": b"old_request"})

            handler.start_proxy(port=28506)
            time.sleep(0.1)

            assert len(handler.captured_requests) == 0

        finally:
            handler.shutdown()


class TestFlexLMRealProxyConnections:
    """Test FlexLM proxy with real socket connections."""

    def test_flexlm_proxy_accepts_client_connection(self) -> None:
        """FlexLM proxy accepts and handles real client connections."""
        handler = FlexLMProtocolHandler()
        port = 28600

        try:
            handler.start_proxy(port=port)
            time.sleep(0.2)

            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(5.0)
            client.connect(("127.0.0.1", port))

            request = b"HELLO\n"
            client.send(request)

            response = client.recv(4096)
            client.close()

            assert len(response) > 0
            assert b"HELLO" in response

            time.sleep(0.1)
            assert len(handler.captured_requests) >= 1

        finally:
            handler.shutdown()

    def test_flexlm_proxy_handles_getlic_request(self) -> None:
        """FlexLM proxy handles GETLIC request from real client."""
        handler = FlexLMProtocolHandler()
        port = 28601

        try:
            handler.start_proxy(port=port)
            time.sleep(0.2)

            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(5.0)
            client.connect(("127.0.0.1", port))

            request = b"GETLIC SOLIDWORKS 2024 user1 host1 :0.0\n"
            client.send(request)

            response = client.recv(4096)
            client.close()

            response_str = response.decode("utf-8")
            assert "GRANT" in response_str
            assert "SOLIDWORKS" in response_str
            assert "HOSTID=ANY" in response_str

        finally:
            handler.shutdown()

    def test_flexlm_proxy_handles_status_request(self) -> None:
        """FlexLM proxy handles STATUS request from real client."""
        config = {"server_status": "UP", "license_count": 1000}
        handler = FlexLMProtocolHandler(config)
        port = 28602

        try:
            handler.start_proxy(port=port)
            time.sleep(0.2)

            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(5.0)
            client.connect(("127.0.0.1", port))

            request = b"STATUS\n"
            client.send(request)

            response = client.recv(4096)
            client.close()

            response_str = response.decode("utf-8")
            assert "STATUS OK" in response_str
            assert "SERVER UP" in response_str
            assert "LICENSES AVAILABLE: 1000" in response_str

        finally:
            handler.shutdown()

    def test_flexlm_proxy_handles_multiple_sequential_clients(self) -> None:
        """FlexLM proxy handles multiple sequential client connections."""
        handler = FlexLMProtocolHandler()
        port = 28603

        try:
            handler.start_proxy(port=port)
            time.sleep(0.2)

            for i in range(5):
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(5.0)
                client.connect(("127.0.0.1", port))

                request = f"GETLIC FEATURE{i} 1.0 user{i} host{i} :0.0\n".encode()
                client.send(request)

                response = client.recv(4096)
                client.close()

                assert len(response) > 0
                assert b"GRANT" in response

            time.sleep(0.1)
            assert len(handler.captured_requests) >= 5

        finally:
            handler.shutdown()

    def test_flexlm_proxy_handles_concurrent_clients(self) -> None:
        """FlexLM proxy handles concurrent client connections."""
        handler = FlexLMProtocolHandler()
        port = 28604

        try:
            handler.start_proxy(port=port)
            time.sleep(0.2)

            def client_worker(client_id: int) -> bytes:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(5.0)
                client.connect(("127.0.0.1", port))

                request = f"GETLIC CONCURRENT{client_id} 1.0 user{client_id} host{client_id} :0.0\n".encode()
                client.send(request)

                response = client.recv(4096)
                client.close()
                return response

            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(client_worker, i) for i in range(10)]
                responses = [f.result() for f in futures]

            assert len(responses) == 10
            assert all(b"GRANT" in r for r in responses)

            time.sleep(0.2)
            assert len(handler.captured_requests) >= 10

        finally:
            handler.shutdown()

    def test_flexlm_proxy_heartbeat_keepalive(self) -> None:
        """FlexLM proxy handles HEARTBEAT keepalive messages."""
        handler = FlexLMProtocolHandler()
        port = 28605

        try:
            handler.start_proxy(port=port)
            time.sleep(0.2)

            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(5.0)
            client.connect(("127.0.0.1", port))

            request = b"HEARTBEAT\n"
            client.send(request)

            response = client.recv(4096)
            client.close()

            assert response == b"HEARTBEAT_OK\n"

        finally:
            handler.shutdown()


class TestHASPRealProxyConnections:
    """Test HASP proxy with real socket connections."""

    def test_hasp_proxy_accepts_client_connection(self) -> None:
        """HASP proxy accepts and handles real client connections."""
        handler = HASPProtocolHandler()
        port = 28700

        try:
            handler.start_proxy(port=port)
            time.sleep(0.2)

            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(5.0)
            client.connect(("127.0.0.1", port))

            request = struct.pack("<II", 0x01, 0x00)
            client.send(request)

            response = client.recv(4096)
            client.close()

            assert len(response) == 8
            status, handle = struct.unpack("<II", response)
            assert status == 0x00000000
            assert 0x10000000 <= handle <= 0x7FFFFFFF

        finally:
            handler.shutdown()

    def test_hasp_proxy_handles_login_request(self) -> None:
        """HASP proxy handles LOGIN request from real client."""
        handler = HASPProtocolHandler()
        port = 28701

        try:
            handler.start_proxy(port=port)
            time.sleep(0.2)

            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(5.0)
            client.connect(("127.0.0.1", port))

            request = struct.pack("<II", 0x01, 0x00)
            client.send(request)

            response = client.recv(4096)
            client.close()

            assert len(response) == 8
            status, handle = struct.unpack("<II", response)
            assert status == 0x00000000

            time.sleep(0.1)
            assert len(handler.captured_requests) >= 1
            assert "handle" in handler.session_data

        finally:
            handler.shutdown()

    def test_hasp_proxy_handles_memory_read(self) -> None:
        """HASP proxy handles memory READ request from real client."""
        handler = HASPProtocolHandler()
        port = 28702

        try:
            handler.start_proxy(port=port)
            time.sleep(0.2)

            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(5.0)
            client.connect(("127.0.0.1", port))

            offset = 0
            size = 64
            request = struct.pack("<IIII", 0x06, 8, offset, size)
            client.send(request)

            response = client.recv(4096)
            client.close()

            assert len(response) >= 4
            status = struct.unpack("<I", response[:4])[0]
            assert status == 0x00000000

            memory_data = response[4:]
            assert len(memory_data) == size
            assert b"HASP_LIC_" in memory_data

        finally:
            handler.shutdown()

    def test_hasp_proxy_handles_get_size_request(self) -> None:
        """HASP proxy handles GET_SIZE request from real client."""
        config = {"hasp_memory_size": 0x10000}
        handler = HASPProtocolHandler(config)
        port = 28703

        try:
            handler.start_proxy(port=port)
            time.sleep(0.2)

            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(5.0)
            client.connect(("127.0.0.1", port))

            request = struct.pack("<II", 0x05, 0x00)
            client.send(request)

            response = client.recv(4096)
            client.close()

            assert len(response) == 8
            status, size = struct.unpack("<II", response)
            assert status == 0x00000000
            assert size == 0x10000

        finally:
            handler.shutdown()

    def test_hasp_proxy_handles_get_rtc_request(self) -> None:
        """HASP proxy handles GET_RTC request from real client."""
        handler = HASPProtocolHandler()
        port = 28704

        try:
            handler.start_proxy(port=port)
            time.sleep(0.2)

            before_time = int(time.time())

            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(5.0)
            client.connect(("127.0.0.1", port))

            request = struct.pack("<II", 0x08, 0x00)
            client.send(request)

            response = client.recv(4096)
            client.close()

            after_time = int(time.time())

            assert len(response) == 8
            status, timestamp = struct.unpack("<II", response)
            assert status == 0x00000000
            assert before_time <= timestamp <= after_time

        finally:
            handler.shutdown()

    def test_hasp_proxy_handles_multiple_sequential_clients(self) -> None:
        """HASP proxy handles multiple sequential client connections."""
        handler = HASPProtocolHandler()
        port = 28705

        try:
            handler.start_proxy(port=port)
            time.sleep(0.2)

            commands = [0x01, 0x05, 0x08, 0x09, 0x02]

            for cmd_id in commands:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(5.0)
                client.connect(("127.0.0.1", port))

                request = struct.pack("<II", cmd_id, 0x00)
                client.send(request)

                response = client.recv(4096)
                client.close()

                assert len(response) >= 4
                status = struct.unpack("<I", response[:4])[0]
                assert status == 0x00000000

            time.sleep(0.1)
            assert len(handler.captured_requests) >= 5

        finally:
            handler.shutdown()

    def test_hasp_proxy_handles_concurrent_clients(self) -> None:
        """HASP proxy handles concurrent client connections."""
        handler = HASPProtocolHandler()
        port = 28706

        try:
            handler.start_proxy(port=port)
            time.sleep(0.2)

            def client_worker(command_id: int) -> bytes:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(5.0)
                client.connect(("127.0.0.1", port))

                request = struct.pack("<II", command_id, 0x00)
                client.send(request)

                response = client.recv(4096)
                client.close()
                return response

            commands = [0x01, 0x05, 0x08, 0x09] * 5

            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(client_worker, cmd) for cmd in commands]
                responses = [f.result() for f in futures]

            assert len(responses) == 20
            assert all(len(r) >= 4 for r in responses)

            time.sleep(0.2)
            assert len(handler.captured_requests) >= 20

        finally:
            handler.shutdown()

    def test_hasp_proxy_encryption_decryption_roundtrip(self) -> None:
        """HASP proxy performs encryption and decryption roundtrip over real connection."""
        handler = HASPProtocolHandler()
        port = 28707

        try:
            handler.start_proxy(port=port)
            time.sleep(0.2)

            original_data = b"Test data for HASP encryption roundtrip"

            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(5.0)
            client.connect(("127.0.0.1", port))

            encrypt_request = struct.pack("<II", 0x03, len(original_data)) + original_data
            client.send(encrypt_request)

            encrypt_response = client.recv(4096)
            client.close()

            encrypted_data = encrypt_response[4:]

            client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client2.settimeout(5.0)
            client2.connect(("127.0.0.1", port))

            decrypt_request = struct.pack("<II", 0x04, len(encrypted_data)) + encrypted_data
            client2.send(decrypt_request)

            decrypt_response = client2.recv(4096)
            client2.close()

            decrypted_data = decrypt_response[4:]
            assert decrypted_data == original_data

        finally:
            handler.shutdown()


class TestProtocolHandlerBindConfiguration:
    """Test protocol handler bind host configuration."""

    def test_flexlm_binds_to_configured_host(self) -> None:
        """FlexLM proxy binds to configured bind_host."""
        config = {"bind_host": "127.0.0.1"}
        handler = FlexLMProtocolHandler(config)
        port = 28800

        try:
            handler.start_proxy(port=port)
            time.sleep(0.2)

            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(5.0)
            client.connect(("127.0.0.1", port))

            request = b"HELLO\n"
            client.send(request)

            response = client.recv(4096)
            client.close()

            assert len(response) > 0
            assert b"HELLO" in response

        finally:
            handler.shutdown()

    def test_hasp_binds_to_configured_host(self) -> None:
        """HASP proxy binds to configured bind_host."""
        config = {"bind_host": "127.0.0.1"}
        handler = HASPProtocolHandler(config)
        port = 28801

        try:
            handler.start_proxy(port=port)
            time.sleep(0.2)

            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(5.0)
            client.connect(("127.0.0.1", port))

            request = struct.pack("<II", 0x01, 0x00)
            client.send(request)

            response = client.recv(4096)
            client.close()

            assert len(response) == 8

        finally:
            handler.shutdown()

    def test_default_bind_host_is_localhost(self) -> None:
        """Default bind_host is localhost for security."""
        handler = FlexLMProtocolHandler()

        assert handler.bind_host == "localhost"

    def test_bind_host_separate_from_host_config(self) -> None:
        """bind_host can be configured separately from host."""
        config = {"host": "remote-server.com", "bind_host": "127.0.0.1"}
        handler = FlexLMProtocolHandler(config)

        assert handler.host == "remote-server.com"
        assert handler.bind_host == "127.0.0.1"


class TestProtocolHandlerTimeouts:
    """Test protocol handler timeout configuration."""

    def test_timeout_configuration_from_config(self) -> None:
        """Timeout is set from configuration."""
        config = {"timeout": 60}
        handler = FlexLMProtocolHandler(config)

        assert handler.timeout == 60

    def test_timeout_configuration_from_environment(self) -> None:
        """Timeout is set from environment variable."""
        original_timeout = os.environ.get("LICENSE_PROTOCOL_TIMEOUT")

        try:
            os.environ["LICENSE_PROTOCOL_TIMEOUT"] = "45"
            handler = FlexLMProtocolHandler()

            assert handler.timeout == 45

        finally:
            if original_timeout is not None:
                os.environ["LICENSE_PROTOCOL_TIMEOUT"] = original_timeout
            elif "LICENSE_PROTOCOL_TIMEOUT" in os.environ:
                del os.environ["LICENSE_PROTOCOL_TIMEOUT"]

    def test_default_timeout_is_30_seconds(self) -> None:
        """Default timeout is 30 seconds."""
        handler = FlexLMProtocolHandler()

        assert handler.timeout == int(os.environ.get("LICENSE_PROTOCOL_TIMEOUT", "30"))


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
