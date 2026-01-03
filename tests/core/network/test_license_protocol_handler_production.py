import socket
import struct
import threading
import time
from collections.abc import Generator
from typing import Any, Protocol

import pytest

from intellicrack.core.network.license_protocol_handler import FlexLMProtocolHandler, HASPProtocolHandler, LicenseProtocolHandler


class SocketLike(Protocol):
    """Protocol for socket-like objects used in testing."""

    def send(self, data: bytes) -> int:
        """Send data through the socket."""
        ...


class TestLicenseProtocolHandlerBase:
    def test_initialization_default_config(self) -> None:
        handler = LicenseProtocolHandler()

        assert handler.config == {}
        assert handler.running is False
        assert handler.proxy_thread is None
        assert handler.port == 8080
        assert handler.host == "localhost"

    def test_initialization_custom_config(self) -> None:
        config = {
            "port": 9090,
            "host": "0.0.0.0",
            "bind_host": "127.0.0.1",
            "timeout": 60,
        }

        handler = LicenseProtocolHandler(config=config)

        assert handler.port == 9090
        assert handler.host == "0.0.0.0"
        assert handler.bind_host == "127.0.0.1"
        assert handler.timeout == 60

    def test_initialization_from_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("LICENSE_PROTOCOL_PORT", "7777")
        monkeypatch.setenv("LICENSE_PROTOCOL_HOST", "test.local")
        monkeypatch.setenv("LICENSE_PROTOCOL_TIMEOUT", "45")

        handler = LicenseProtocolHandler()

        assert handler.port == 7777
        assert handler.host == "test.local"
        assert handler.timeout == 45

    def test_is_running_initial_state(self) -> None:
        handler = LicenseProtocolHandler()
        assert handler.is_running() is False

    def test_get_status_not_running(self) -> None:
        handler = LicenseProtocolHandler()
        status = handler.get_status()

        assert status["protocol"] == "LicenseProtocolHandler"
        assert status["running"] is False
        assert status["port"] == 8080
        assert status["host"] == "localhost"
        assert status["thread_active"] is False

    def test_clear_data_with_attributes(self) -> None:
        handler = LicenseProtocolHandler()
        captured_requests: list[bytes] = [b"request1", b"request2"]
        captured_responses: list[bytes] = [b"response1"]
        session_data: dict[str, str] = {"key": "value"}
        client_connections: dict[str, str] = {"client1": "data"}

        setattr(handler, "captured_requests", captured_requests)
        setattr(handler, "captured_responses", captured_responses)
        setattr(handler, "session_data", session_data)
        setattr(handler, "client_connections", client_connections)

        handler.clear_data()

        assert not getattr(handler, "captured_requests", None)
        assert not getattr(handler, "captured_responses", None)
        assert not getattr(handler, "session_data", None)
        assert not getattr(handler, "client_connections", None)

    def test_clear_data_without_attributes(self) -> None:
        handler = LicenseProtocolHandler()
        handler.clear_data()


class TestLicenseProtocolHandlerProxyLifecycle:
    def test_start_proxy_success(self) -> None:
        handler = LicenseProtocolHandler()

        result = handler.start_proxy(port=0)

        assert result is True
        assert handler.running is True
        assert handler.proxy_thread is not None
        assert handler.proxy_thread.is_alive()

        handler.stop_proxy()

    def test_start_proxy_already_running(self) -> None:
        handler = LicenseProtocolHandler()
        handler.start_proxy(port=0)

        result = handler.start_proxy(port=0)

        assert result is False

        handler.stop_proxy()

    def test_stop_proxy_success(self) -> None:
        handler = LicenseProtocolHandler()
        handler.start_proxy(port=0)
        time.sleep(0.1)

        result = handler.stop_proxy()

        assert result is True
        assert handler.running is False

    def test_stop_proxy_not_running(self) -> None:
        handler = LicenseProtocolHandler()

        result = handler.stop_proxy()

        assert result is False

    def test_shutdown_cleans_all_resources(self) -> None:
        handler = LicenseProtocolHandler()
        setattr(handler, "captured_requests", [b"data"])
        handler.start_proxy(port=0)
        time.sleep(0.1)

        handler.shutdown()

        assert handler.running is False
        assert handler.proxy_thread is None
        assert not getattr(handler, "captured_requests", [])

    def test_proxy_thread_is_daemon(self) -> None:
        handler = LicenseProtocolHandler()
        handler.start_proxy(port=0)

        assert handler.proxy_thread is not None
        assert handler.proxy_thread.daemon is True

        handler.stop_proxy()

    def test_proxy_thread_naming(self) -> None:
        handler = LicenseProtocolHandler()
        handler.start_proxy(port=0)

        assert handler.proxy_thread is not None
        assert "LicenseProtocolHandlerProxy" in handler.proxy_thread.name

        handler.stop_proxy()


class TestLicenseProtocolHandlerNetworkOperations:
    @pytest.fixture
    def handler_with_proxy(self) -> Generator[LicenseProtocolHandler, None, None]:
        handler = LicenseProtocolHandler(config={"bind_host": "127.0.0.1"})
        handler.start_proxy(port=0)
        time.sleep(0.2)
        yield handler
        handler.shutdown()

    def test_handle_connection_sends_response(
        self, handler_with_proxy: LicenseProtocolHandler
    ) -> None:
        test_request = b"TEST_REQUEST_DATA"
        received_response: list[bytes] = []

        class MockSocket:
            def send(self, data: bytes) -> int:
                received_response.append(data)
                return len(data)

        mock_sock = MockSocket()

        handler_with_proxy.handle_connection(mock_sock, test_request)  # type: ignore[arg-type]

        assert len(received_response) == 1
        assert received_response[0] == b"OK\n"

    def test_generate_response_returns_default(self) -> None:
        handler = LicenseProtocolHandler()
        request_data = b"SOME_REQUEST"

        response = handler.generate_response(request_data)

        assert response == b"OK\n"

    def test_log_request_captures_data(self) -> None:
        handler = LicenseProtocolHandler()
        test_data = b"TEST_REQUEST"

        handler.log_request(test_data, "test_client")

    def test_log_response_captures_data(self) -> None:
        handler = LicenseProtocolHandler()
        test_data = b"TEST_RESPONSE"

        handler.log_response(test_data, "test_client")

    def test_log_request_with_long_data(self) -> None:
        handler = LicenseProtocolHandler()
        long_data = b"A" * 1024

        handler.log_request(long_data, "test_client")

    def test_handle_connection_error_recovery(self) -> None:
        handler = LicenseProtocolHandler()

        class FailingSocket:
            def send(self, data: bytes) -> int:
                raise OSError("Network error")

        failing_sock = FailingSocket()

        handler.handle_connection(failing_sock, b"request")  # type: ignore[arg-type]


class TestFlexLMProtocolHandler:
    def test_initialization_default_config(self) -> None:
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

    def test_initialization_custom_config(self) -> None:
        config = {
            "flexlm_port": 27500,
            "vendor_daemon_port": 27501,
            "flexlm_version": "12.0.0",
            "license_count": 100,
            "license_type": "trial",
            "feature_version": "3.0",
            "server_status": "DEGRADED",
        }

        handler = FlexLMProtocolHandler(config=config)

        assert handler.flexlm_port == 27500
        assert handler.vendor_daemon_port == 27501
        assert handler.flexlm_version == "12.0.0"
        assert handler.license_count == 100
        assert handler.license_type == "trial"
        assert handler.feature_version == "3.0"
        assert handler.server_status == "DEGRADED"

    def test_clear_data_clears_flexlm_data(self) -> None:
        handler = FlexLMProtocolHandler()
        handler.captured_requests.append({"data": b"test", "timestamp": 0.0, "hex": ""})
        handler.captured_responses.append({"data": b"response", "timestamp": 0.0, "hex": ""})
        handler.session_data["key"] = "value"

        handler.clear_data()

        assert len(handler.captured_requests) == 0
        assert len(handler.captured_responses) == 0
        assert len(handler.session_data) == 0


class TestFlexLMProtocolHandlerProtocol:
    def test_generate_response_hello_command(self) -> None:
        handler = FlexLMProtocolHandler()
        request = b"HELLO"

        response = handler.generate_response(request)

        assert response.startswith(b"HELLO")
        assert b"11" in response
        assert b"16" in response
        assert b"27001" in response

    def test_generate_response_hello_custom_version(self) -> None:
        handler = FlexLMProtocolHandler(
            config={"flexlm_version": "10.5.3", "vendor_daemon_port": 28000}
        )
        request = b"HELLO"

        response = handler.generate_response(request)

        assert b"HELLO 10 5 28000" in response

    def test_generate_response_getlic_command(self) -> None:
        handler = FlexLMProtocolHandler()
        request = b"GETLIC MATLAB 2023 user1 host1 display1"

        response = handler.generate_response(request)

        assert response.startswith(b"GRANT")
        assert b"MATLAB" in response
        assert b"2.0" in response
        assert b"permanent" in response
        assert b"HOSTID=ANY" in response

    def test_generate_response_getlic_with_trial_license(self) -> None:
        handler = FlexLMProtocolHandler(config={"license_type": "trial"})
        request = b"GETLIC AUTOCAD 2024 user1 host1 display1"

        response = handler.generate_response(request)

        assert b"GRANT" in response
        assert b"AUTOCAD" in response
        assert b"trial" in response

    def test_generate_response_checkin_command(self) -> None:
        handler = FlexLMProtocolHandler()
        request = b"CHECKIN FEATURE"

        response = handler.generate_response(request)

        assert response == b"CHECKIN_OK\n"

    def test_generate_response_heartbeat_command(self) -> None:
        handler = FlexLMProtocolHandler()
        request = b"HEARTBEAT"

        response = handler.generate_response(request)

        assert response == b"HEARTBEAT_OK\n"

    def test_generate_response_status_command(self) -> None:
        handler = FlexLMProtocolHandler(
            config={"server_status": "UP", "license_count": 500}
        )
        request = b"STATUS"

        response = handler.generate_response(request)

        assert b"STATUS OK" in response
        assert b"SERVER UP" in response
        assert b"500" in response

    def test_generate_response_unknown_command(self) -> None:
        handler = FlexLMProtocolHandler()
        request = b"UNKNOWN_CMD"

        response = handler.generate_response(request)

        assert response == b"OK\n"

    def test_generate_response_invalid_short_request(self) -> None:
        handler = FlexLMProtocolHandler()
        request = b"ABC"

        response = handler.generate_response(request)

        assert b"ERROR" in response

    def test_generate_response_invalid_getlic_format(self) -> None:
        handler = FlexLMProtocolHandler()
        request = b"GETLIC"

        response = handler.generate_response(request)

        assert b"ERROR" in response

    def test_generate_response_stores_requests(self) -> None:
        handler = FlexLMProtocolHandler()
        request1 = b"HELLO"
        request2 = b"GETLIC FEATURE1 1.0 user host display"

        handler.generate_response(request1)
        handler.generate_response(request2)

        assert len(handler.captured_requests) == 2
        assert handler.captured_requests[0]["data"] == request1
        assert handler.captured_requests[1]["data"] == request2
        assert "timestamp" in handler.captured_requests[0]
        assert "hex" in handler.captured_requests[0]


class TestFlexLMProtocolHandlerNetworkOperations:
    @pytest.fixture
    def flexlm_server(self) -> Generator[FlexLMProtocolHandler, None, None]:
        handler = FlexLMProtocolHandler(config={"bind_host": "127.0.0.1", "port": 0})
        handler.start_proxy(port=0)
        time.sleep(0.2)
        yield handler
        handler.shutdown()

    def test_start_proxy_binds_to_port(self) -> None:
        handler = FlexLMProtocolHandler(config={"bind_host": "127.0.0.1"})

        result = handler.start_proxy(port=0)

        assert result is True
        assert handler.running is True

        handler.stop_proxy()

    def test_proxy_lifecycle(self) -> None:
        handler = FlexLMProtocolHandler(config={"bind_host": "127.0.0.1"})

        handler.start_proxy(port=0)
        time.sleep(0.1)
        assert handler.is_running() is True

        handler.stop_proxy()
        time.sleep(0.1)
        assert handler.is_running() is False


class TestHASPProtocolHandler:
    def test_initialization_default_config(self) -> None:
        handler = HASPProtocolHandler()

        assert handler.hasp_port == 1947
        assert handler.hasp_memory_size == 0x20000
        assert handler.hasp_version == "7.50"
        assert handler.hasp_vendor_id == 0x1234
        assert handler.license_features == [
            "PROFESSIONAL",
            "ENTERPRISE",
            "DEVELOPER",
            "RUNTIME",
        ]
        assert handler.hasp_emulator_version == "HASP_EMU_v2.1"
        assert isinstance(handler.captured_requests, list)
        assert isinstance(handler.captured_responses, list)

    def test_initialization_custom_config(self) -> None:
        config = {
            "hasp_port": 2000,
            "hasp_memory_size": 0x10000,
            "hasp_version": "8.0",
            "hasp_vendor_id": 0x5678,
            "license_features": ["BASIC", "PREMIUM"],
            "hasp_emulator_version": "CUSTOM_EMU_v1.0",
        }

        handler = HASPProtocolHandler(config=config)

        assert handler.hasp_port == 2000
        assert handler.hasp_memory_size == 0x10000
        assert handler.hasp_version == "8.0"
        assert handler.hasp_vendor_id == 0x5678
        assert handler.license_features == ["BASIC", "PREMIUM"]
        assert handler.hasp_emulator_version == "CUSTOM_EMU_v1.0"

    def test_clear_data_clears_hasp_data(self) -> None:
        handler = HASPProtocolHandler()
        handler.captured_requests.append({"data": b"test", "timestamp": 0.0, "hex": ""})
        handler.session_data["key"] = "value"

        handler.clear_data()

        assert len(handler.captured_requests) == 0
        assert len(handler.session_data) == 0


class TestHASPProtocolHandlerProtocol:
    def test_generate_response_login_command(self) -> None:
        handler = HASPProtocolHandler()
        request = struct.pack("<II", 0x01, 0)

        response = handler.generate_response(request)

        assert len(response) == 8
        status, handle = struct.unpack("<II", response)
        assert status == 0
        assert 0x10000000 <= handle <= 0x7FFFFFFF
        assert "handle" in handler.session_data
        assert handler.session_data["handle"] == handle

    def test_generate_response_logout_command(self) -> None:
        handler = HASPProtocolHandler()
        request = struct.pack("<II", 0x02, 0)

        response = handler.generate_response(request)

        assert len(response) == 4
        status = struct.unpack("<I", response)[0]
        assert status == 0

    def test_generate_response_encrypt_command(self) -> None:
        handler = HASPProtocolHandler()
        data_to_encrypt = b"TESTDATA1234567890"
        request = struct.pack("<II", 0x03, len(data_to_encrypt)) + data_to_encrypt

        response = handler.generate_response(request)

        assert len(response) >= 4
        status = struct.unpack("<I", response[:4])[0]
        assert status == 0
        encrypted_data = response[4:]
        assert len(encrypted_data) == len(data_to_encrypt)
        assert encrypted_data != data_to_encrypt

    def test_generate_response_decrypt_command(self) -> None:
        handler = HASPProtocolHandler()

        data_to_encrypt = b"SECRET_LICENSE_KEY"
        encrypt_request = struct.pack("<II", 0x03, len(data_to_encrypt)) + data_to_encrypt
        encrypt_response = handler.generate_response(encrypt_request)
        encrypted_data = encrypt_response[4:]

        decrypt_request = struct.pack("<II", 0x04, len(encrypted_data)) + encrypted_data
        decrypt_response = handler.generate_response(decrypt_request)

        assert len(decrypt_response) >= 4
        status = struct.unpack("<I", decrypt_response[:4])[0]
        assert status == 0
        decrypted_data = decrypt_response[4:]
        assert decrypted_data == data_to_encrypt

    def test_generate_response_get_size_command(self) -> None:
        handler = HASPProtocolHandler(config={"hasp_memory_size": 0x40000})
        request = struct.pack("<II", 0x05, 0)

        response = handler.generate_response(request)

        assert len(response) == 8
        status, size = struct.unpack("<II", response)
        assert status == 0
        assert size == 0x40000

    def test_generate_response_read_command_header_area(self) -> None:
        handler = HASPProtocolHandler(config={"hasp_version": "7.50"})
        request = struct.pack("<IIII", 0x06, 8, 0, 64)

        response = handler.generate_response(request)

        assert len(response) >= 4
        status = struct.unpack("<I", response[:4])[0]
        assert status == 0
        license_data = response[4:]
        assert b"HASP_LIC_7_50" in license_data

    def test_generate_response_read_command_feature_area(self) -> None:
        handler = HASPProtocolHandler(
            config={"license_features": ["FEATURE1", "FEATURE2"]}
        )
        request = struct.pack("<IIII", 0x06, 8, 100, 128)

        response = handler.generate_response(request)

        assert len(response) >= 4
        status = struct.unpack("<I", response[:4])[0]
        assert status == 0
        license_data = response[4:]
        assert b"FEATURE1" in license_data
        assert b"FEATURE2" in license_data

    def test_generate_response_read_command_data_area(self) -> None:
        handler = HASPProtocolHandler()
        request = struct.pack("<IIII", 0x06, 8, 1000, 64)

        response = handler.generate_response(request)

        assert len(response) >= 4
        status = struct.unpack("<I", response[:4])[0]
        assert status == 0
        license_data = response[4:]
        assert len(license_data) == 64

    def test_generate_response_write_command(self) -> None:
        handler = HASPProtocolHandler()
        request = struct.pack("<II", 0x07, 0)

        response = handler.generate_response(request)

        assert len(response) == 4
        status = struct.unpack("<I", response)[0]
        assert status == 0

    def test_generate_response_get_rtc_command(self) -> None:
        handler = HASPProtocolHandler()
        request = struct.pack("<II", 0x08, 0)

        response = handler.generate_response(request)

        assert len(response) == 8
        status, current_time = struct.unpack("<II", response)
        assert status == 0
        assert current_time > 0
        assert abs(current_time - int(time.time())) < 2

    def test_generate_response_get_info_command(self) -> None:
        handler = HASPProtocolHandler(config={"hasp_emulator_version": "TEST_EMU_v3"})
        request = struct.pack("<II", 0x09, 0)

        response = handler.generate_response(request)

        assert len(response) >= 4
        status = struct.unpack("<I", response[:4])[0]
        assert status == 0
        info = response[4:]
        assert b"TEST_EMU_v3" in info

    def test_generate_response_unknown_command(self) -> None:
        handler = HASPProtocolHandler()
        request = struct.pack("<II", 0xFF, 0)

        response = handler.generate_response(request)

        assert len(response) >= 4
        status = struct.unpack("<I", response[:4])[0]
        assert status == 0

    def test_generate_response_invalid_short_request(self) -> None:
        handler = HASPProtocolHandler()
        request = b"SHORT"

        response = handler.generate_response(request)

        assert response == b"\x00\x00\x00\x00"

    def test_generate_response_stores_requests(self) -> None:
        handler = HASPProtocolHandler()
        request1 = struct.pack("<II", 0x01, 0)
        request2 = struct.pack("<II", 0x05, 0)

        handler.generate_response(request1)
        handler.generate_response(request2)

        assert len(handler.captured_requests) == 2
        assert handler.captured_requests[0]["data"] == request1
        assert handler.captured_requests[1]["data"] == request2
        assert "timestamp" in handler.captured_requests[0]
        assert "hex" in handler.captured_requests[0]

    def test_generate_response_read_command_size_limit(self) -> None:
        handler = HASPProtocolHandler()
        request = struct.pack("<IIII", 0x06, 8, 0, 100000)

        response = handler.generate_response(request)

        assert len(response) >= 4
        status = struct.unpack("<I", response[:4])[0]
        assert status == 0
        license_data = response[4:]
        assert len(license_data) <= 4096


class TestHASPProtocolHandlerNetworkOperations:
    def test_start_proxy_binds_to_port(self) -> None:
        handler = HASPProtocolHandler(config={"bind_host": "127.0.0.1"})

        result = handler.start_proxy(port=0)

        assert result is True
        assert handler.running is True

        handler.stop_proxy()

    def test_proxy_lifecycle(self) -> None:
        handler = HASPProtocolHandler(config={"bind_host": "127.0.0.1"})

        handler.start_proxy(port=0)
        time.sleep(0.1)
        assert handler.is_running() is True

        handler.stop_proxy()
        time.sleep(0.1)
        assert handler.is_running() is False


class TestCryptographicOperations:
    def test_hasp_encryption_decryption_with_cryptography(self) -> None:
        pytest.importorskip("cryptography")

        handler = HASPProtocolHandler()
        original_data = b"SENSITIVE_LICENSE_DATA_12345678"

        encrypt_request = struct.pack("<II", 0x03, len(original_data)) + original_data
        encrypt_response = handler.generate_response(encrypt_request)
        encrypted = encrypt_response[4:]

        decrypt_request = struct.pack("<II", 0x04, len(encrypted)) + encrypted
        decrypt_response = handler.generate_response(decrypt_request)
        decrypted = decrypt_response[4:]

        assert decrypted == original_data
        assert encrypted != original_data

    def test_hasp_multiple_encryption_operations(self) -> None:
        handler = HASPProtocolHandler()

        data1 = b"DATA_SET_1"
        data2 = b"DATA_SET_2"

        enc1_req = struct.pack("<II", 0x03, len(data1)) + data1
        enc1_resp = handler.generate_response(enc1_req)

        enc2_req = struct.pack("<II", 0x03, len(data2)) + data2
        enc2_resp = handler.generate_response(enc2_req)

        assert enc1_resp[4:] != enc2_resp[4:]


class TestConcurrentConnections:
    def test_multiple_flexlm_requests_concurrent(self) -> None:
        handler = FlexLMProtocolHandler(config={"bind_host": "127.0.0.1"})
        handler.start_proxy(port=0)
        time.sleep(0.2)

        try:
            requests = [
                b"HELLO",
                b"GETLIC FEATURE1 1.0 user host display",
                b"HEARTBEAT",
                b"STATUS",
            ]

            for req in requests:
                handler.generate_response(req)

            assert len(handler.captured_requests) == len(requests)

        finally:
            handler.shutdown()

    def test_multiple_hasp_sessions(self) -> None:
        handler = HASPProtocolHandler()

        login1 = struct.pack("<II", 0x01, 0)
        resp1 = handler.generate_response(login1)
        handle1 = struct.unpack("<II", resp1)[1]

        login2 = struct.pack("<II", 0x01, 0)
        resp2 = handler.generate_response(login2)
        handle2 = struct.unpack("<II", resp2)[1]

        assert handle1 != handle2


class TestErrorHandling:
    def test_flexlm_malformed_getlic(self) -> None:
        handler = FlexLMProtocolHandler()
        request = b"GETLIC"

        response = handler.generate_response(request)

        assert b"ERROR" in response

    def test_hasp_read_malformed_packet(self) -> None:
        handler = HASPProtocolHandler()
        request = struct.pack("<II", 0x06, 4)

        response = handler.generate_response(request)

        assert len(response) >= 4

    def test_hasp_struct_error_recovery(self) -> None:
        handler = HASPProtocolHandler()
        request = b"\x06\x00\x00"

        response = handler.generate_response(request)

        assert response == b"\x00\x00\x00\x00"
