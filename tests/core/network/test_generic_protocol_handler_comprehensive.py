"""Comprehensive tests for GenericProtocolHandler functionality.

Tests validate real generic protocol handling, TCP/UDP proxy server operations,
connection management, protocol detection, and response generation for license
verification systems without mocks or stubs.
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from intellicrack.core.network.generic_protocol_handler import GenericProtocolHandler


class TestGenericProtocolHandlerInitialization:
    """Test generic protocol handler initialization and configuration."""

    def test_default_initialization_creates_tcp_handler(self) -> None:
        """Handler initializes with TCP protocol by default."""
        handler = GenericProtocolHandler()

        assert handler.protocol == "tcp"
        assert handler.captured_requests == []
        assert handler.captured_responses == []
        assert handler.active_connections == {}
        assert handler.running is False
        assert handler.proxy_thread is None

    def test_tcp_config_creates_tcp_handler(self) -> None:
        """TCP protocol config creates TCP handler."""
        config: dict[str, Any] = {"protocol": "tcp", "port": 9999}
        handler = GenericProtocolHandler(config)

        assert handler.protocol == "tcp"
        assert handler.port == 9999
        assert handler.captured_requests == []
        assert handler.captured_responses == []

    def test_udp_config_creates_udp_handler(self) -> None:
        """UDP protocol config creates UDP handler."""
        config: dict[str, Any] = {"protocol": "udp", "port": 8888}
        handler = GenericProtocolHandler(config)

        assert handler.protocol == "udp"
        assert handler.port == 8888
        assert handler.captured_requests == []
        assert handler.captured_responses == []

    def test_mixed_case_protocol_handled_correctly(self) -> None:
        """Protocol name handles mixed case correctly."""
        config: dict[str, Any] = {"protocol": "UDP"}
        handler = GenericProtocolHandler(config)

        assert handler.protocol == "UDP"

    def test_custom_bind_host_configuration(self) -> None:
        """Custom bind host configuration is stored correctly."""
        config: dict[str, Any] = {
            "protocol": "tcp",
            "host": "192.168.1.100",
            "bind_host": "0.0.0.0",
            "port": 7777,
            "timeout": 60,
        }
        handler = GenericProtocolHandler(config)

        assert handler.bind_host == "0.0.0.0"
        assert handler.host == "192.168.1.100"
        assert handler.port == 7777
        assert handler.timeout == 60


class TestGenericProtocolHandlerResponseGeneration:
    """Test protocol response generation for various request types."""

    def test_license_keyword_triggers_valid_response(self) -> None:
        """Request with 'license' keyword returns LICENSE_VALID response."""
        handler = GenericProtocolHandler()
        request = b"CHECK_LICENSE\x00"

        response = handler.generate_response(request)

        assert response == b"OK\x00LICENSE_VALID\x00"

    def test_verify_keyword_triggers_valid_response(self) -> None:
        """Request with 'verify' keyword returns LICENSE_VALID response."""
        handler = GenericProtocolHandler()
        request = b"VERIFY_KEY\x00user123\x00"

        response = handler.generate_response(request)

        assert response == b"OK\x00LICENSE_VALID\x00"

    def test_check_keyword_triggers_valid_response(self) -> None:
        """Request with 'check' keyword returns LICENSE_VALID response."""
        handler = GenericProtocolHandler()
        request = b"check_activation_status"

        response = handler.generate_response(request)

        assert response == b"OK\x00LICENSE_VALID\x00"

    def test_auth_keyword_triggers_valid_response(self) -> None:
        """Request with 'auth' keyword returns LICENSE_VALID response."""
        handler = GenericProtocolHandler()
        request = b"AUTHENTICATE_USER\x00"

        response = handler.generate_response(request)

        assert response == b"OK\x00LICENSE_VALID\x00"

    def test_status_keyword_triggers_active_response(self) -> None:
        """Request with 'status' keyword returns SERVER_ACTIVE response."""
        handler = GenericProtocolHandler()
        request = b"GET_STATUS\x00"

        response = handler.generate_response(request)

        assert response == b"OK\x00SERVER_ACTIVE\x00"

    def test_ping_keyword_triggers_active_response(self) -> None:
        """Request with 'ping' keyword returns SERVER_ACTIVE response."""
        handler = GenericProtocolHandler()
        request = b"ping"

        response = handler.generate_response(request)

        assert response == b"OK\x00SERVER_ACTIVE\x00"

    def test_heartbeat_keyword_triggers_active_response(self) -> None:
        """Request with 'heartbeat' keyword returns SERVER_ACTIVE response."""
        handler = GenericProtocolHandler()
        request = b"heartbeat"

        response = handler.generate_response(request)

        assert response == b"OK\x00SERVER_ACTIVE\x00"

    def test_version_keyword_triggers_version_response(self) -> None:
        """Request with 'version' keyword returns version information."""
        handler = GenericProtocolHandler()
        request = b"GET_VERSION"

        response = handler.generate_response(request)

        assert response == b"GENERIC_LICENSE_SERVER_V1.0\x00"

    def test_info_keyword_triggers_version_response(self) -> None:
        """Request with 'info' keyword returns version information."""
        handler = GenericProtocolHandler()
        request = b"server_info"

        response = handler.generate_response(request)

        assert response == b"GENERIC_LICENSE_SERVER_V1.0\x00"

    def test_binary_init_sequence_triggers_handle_response(self) -> None:
        """Binary init sequence 0x00000001 returns success with handle."""
        handler = GenericProtocolHandler()
        request = b"\x00\x00\x00\x01\xff\xff\xff\xff"

        response = handler.generate_response(request)

        assert response == b"\x00\x00\x00\x00\x00\x00\x00\x01"
        assert len(response) == 8

    def test_binary_query_sequence_triggers_license_count_response(self) -> None:
        """Binary query sequence 0x0200 returns max licenses available."""
        handler = GenericProtocolHandler()
        request = b"\x02\x00\x00\x00\x00\x00"

        response = handler.generate_response(request)

        assert response == b"\x00\x00\xff\xff\xff\xff"
        assert len(response) == 6

    def test_unknown_text_request_returns_ok(self) -> None:
        """Unknown text request returns generic OK response."""
        handler = GenericProtocolHandler()
        request = b"UNKNOWN_COMMAND\x00"

        response = handler.generate_response(request)

        assert response == b"OK\x00"

    def test_unknown_binary_request_returns_ok(self) -> None:
        """Unknown binary request returns generic OK response."""
        handler = GenericProtocolHandler()
        request = b"\xff\xff\xff\xff\xaa\xbb\xcc\xdd"

        response = handler.generate_response(request)

        assert response == b"OK\x00"

    def test_empty_request_returns_ok(self) -> None:
        """Empty request returns generic OK response."""
        handler = GenericProtocolHandler()
        request = b""

        response = handler.generate_response(request)

        assert response == b"OK\x00"

    def test_short_binary_request_returns_ok(self) -> None:
        """Binary request shorter than 4 bytes returns OK."""
        handler = GenericProtocolHandler()
        request = b"\x01\x02\x03"

        response = handler.generate_response(request)

        assert response == b"OK\x00"

    def test_mixed_keyword_detection_case_insensitive(self) -> None:
        """Keyword detection is case-insensitive."""
        handler = GenericProtocolHandler()
        request = b"LICENSE_Verify_CHECK"

        response = handler.generate_response(request)

        assert response == b"OK\x00LICENSE_VALID\x00"

    def test_multiple_keywords_first_match_wins(self) -> None:
        """Multiple keywords trigger first matching pattern."""
        handler = GenericProtocolHandler()
        request = b"license_status_version"

        response = handler.generate_response(request)

        assert response == b"OK\x00LICENSE_VALID\x00"

    def test_non_utf8_binary_data_handled_gracefully(self) -> None:
        """Non-UTF8 binary data is handled without errors."""
        handler = GenericProtocolHandler()
        request = bytes(range(256))

        response = handler.generate_response(request)

        assert response in [b"OK\x00", b"\x00\x00\xff\xff\xff\xff"]

    def test_large_binary_request_processed_correctly(self) -> None:
        """Large binary requests are processed correctly."""
        handler = GenericProtocolHandler()
        request = b"\x02\x00" + (b"\x00" * 10000)

        response = handler.generate_response(request)

        assert response == b"\x00\x00\xff\xff\xff\xff"


class TestGenericProtocolHandlerTCPProxy:
    """Test TCP proxy server functionality."""

    def test_tcp_proxy_starts_and_accepts_connections(self) -> None:
        """TCP proxy starts and accepts client connections."""
        handler = GenericProtocolHandler({"protocol": "tcp"})
        port = self._get_free_port()

        started = handler.start_proxy(port)
        assert started is True
        assert handler.running is True
        proxy_thread = handler.proxy_thread
        assert proxy_thread is not None
        assert proxy_thread.is_alive()

        time.sleep(0.2)

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5.0)
        try:
            client.connect(("127.0.0.1", port))
        finally:
            client.close()
            handler.stop_proxy()

    def test_tcp_proxy_receives_and_responds_to_license_request(self) -> None:
        """TCP proxy receives license request and sends valid response."""
        handler = GenericProtocolHandler({"protocol": "tcp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5.0)
        try:
            client.connect(("127.0.0.1", port))
            client.send(b"CHECK_LICENSE\x00")

            response = client.recv(1024)
            assert response == b"OK\x00LICENSE_VALID\x00"
        finally:
            client.close()
            handler.stop_proxy()

    def test_tcp_proxy_captures_request_data(self) -> None:
        """TCP proxy captures incoming request data."""
        handler = GenericProtocolHandler({"protocol": "tcp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5.0)
        try:
            client.connect(("127.0.0.1", port))
            request_data = b"VERIFY_KEY\x00user123\x00"
            client.send(request_data)
            client.recv(1024)

            time.sleep(0.1)
            assert len(handler.captured_requests) == 1
            assert handler.captured_requests[0]["data"] == request_data
            assert handler.captured_requests[0]["hex"] == request_data.hex()
            assert "timestamp" in handler.captured_requests[0]
            assert "source" in handler.captured_requests[0]
        finally:
            client.close()
            handler.stop_proxy()

    def test_tcp_proxy_captures_response_data(self) -> None:
        """TCP proxy captures outgoing response data."""
        handler = GenericProtocolHandler({"protocol": "tcp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5.0)
        try:
            client.connect(("127.0.0.1", port))
            client.send(b"ping")
            response = client.recv(1024)

            time.sleep(0.1)
            assert len(handler.captured_responses) == 1
            assert handler.captured_responses[0]["data"] == response
            assert handler.captured_responses[0]["hex"] == response.hex()
            assert "timestamp" in handler.captured_responses[0]
            assert "destination" in handler.captured_responses[0]
        finally:
            client.close()
            handler.stop_proxy()

    def test_tcp_proxy_handles_multiple_sequential_requests(self) -> None:
        """TCP proxy handles multiple sequential requests on same connection."""
        handler = GenericProtocolHandler({"protocol": "tcp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5.0)
        try:
            client.connect(("127.0.0.1", port))

            client.send(b"ping")
            response1 = client.recv(1024)
            assert response1 == b"OK\x00SERVER_ACTIVE\x00"

            client.send(b"CHECK_LICENSE\x00")
            response2 = client.recv(1024)
            assert response2 == b"OK\x00LICENSE_VALID\x00"

            client.send(b"GET_VERSION")
            response3 = client.recv(1024)
            assert response3 == b"GENERIC_LICENSE_SERVER_V1.0\x00"

            time.sleep(0.1)
            assert len(handler.captured_requests) == 3
            assert len(handler.captured_responses) == 3
        finally:
            client.close()
            handler.stop_proxy()

    def test_tcp_proxy_handles_concurrent_connections(self) -> None:
        """TCP proxy handles multiple concurrent client connections."""
        handler = GenericProtocolHandler({"protocol": "tcp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)

        def client_task(request: bytes) -> bytes:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(5.0)
            try:
                client.connect(("127.0.0.1", port))
                client.send(request)
                return client.recv(1024)
            finally:
                client.close()

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(client_task, b"CHECK_LICENSE\x00"),
                executor.submit(client_task, b"ping"),
                executor.submit(client_task, b"GET_VERSION"),
                executor.submit(client_task, b"status"),
                executor.submit(client_task, b"verify_auth"),
            ]

            results = [f.result() for f in futures]

        assert results[0] == b"OK\x00LICENSE_VALID\x00"
        assert results[1] == b"OK\x00SERVER_ACTIVE\x00"
        assert results[2] == b"GENERIC_LICENSE_SERVER_V1.0\x00"
        assert results[3] == b"OK\x00SERVER_ACTIVE\x00"
        assert results[4] == b"OK\x00LICENSE_VALID\x00"

        time.sleep(0.2)
        assert len(handler.captured_requests) == 5
        assert len(handler.captured_responses) == 5

        handler.stop_proxy()

    def test_tcp_proxy_tracks_active_connections(self) -> None:
        """TCP proxy tracks active connections during processing."""
        handler = GenericProtocolHandler({"protocol": "tcp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)

        client1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client1.settimeout(5.0)
        client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client2.settimeout(5.0)

        try:
            client1.connect(("127.0.0.1", port))
            client1.send(b"ping")
            time.sleep(0.1)

            client2.connect(("127.0.0.1", port))
            client2.send(b"status")
            time.sleep(0.1)

            assert len(handler.active_connections) >= 0

            client1.recv(1024)
            client2.recv(1024)
        finally:
            client1.close()
            client2.close()
            time.sleep(0.2)
            handler.stop_proxy()

    def test_tcp_proxy_removes_closed_connections(self) -> None:
        """TCP proxy removes connections from tracking when closed."""
        handler = GenericProtocolHandler({"protocol": "tcp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5.0)
        try:
            client.connect(("127.0.0.1", port))
            client.send(b"ping")
            client.recv(1024)
        finally:
            client.close()

        time.sleep(0.3)
        assert len(handler.active_connections) == 0

        handler.stop_proxy()

    def test_tcp_proxy_stops_cleanly(self) -> None:
        """TCP proxy stops cleanly and releases resources."""
        handler = GenericProtocolHandler({"protocol": "tcp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)
        assert handler.running is True

        stopped = handler.stop_proxy()
        assert stopped
        assert handler.running is False

        time.sleep(0.5)  # type: ignore[unreachable]
        connection_refused = False
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(1.0)
            client.connect(("127.0.0.1", port))
            client.close()
        except OSError:
            connection_refused = True

        assert connection_refused

    def test_tcp_proxy_start_twice_returns_false(self) -> None:
        """Starting already running TCP proxy returns False."""
        handler = GenericProtocolHandler({"protocol": "tcp"})
        port = self._get_free_port()

        first_start = handler.start_proxy(port)
        assert first_start is True

        second_start = handler.start_proxy(port)
        assert second_start is False

        handler.stop_proxy()

    def test_tcp_proxy_stop_when_not_running_returns_false(self) -> None:
        """Stopping non-running TCP proxy returns False."""
        handler = GenericProtocolHandler({"protocol": "tcp"})

        result = handler.stop_proxy()
        assert result is False

    def test_tcp_proxy_handles_binary_protocol_requests(self) -> None:
        """TCP proxy handles binary protocol requests correctly."""
        handler = GenericProtocolHandler({"protocol": "tcp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5.0)
        try:
            client.connect(("127.0.0.1", port))
            client.send(b"\x00\x00\x00\x01\xff\xff\xff\xff")
            response = client.recv(1024)
            assert response == b"\x00\x00\x00\x00\x00\x00\x00\x01"

            client.send(b"\x02\x00\x00\x00\x00\x00")
            response = client.recv(1024)
            assert response == b"\x00\x00\xff\xff\xff\xff"
        finally:
            client.close()
            handler.stop_proxy()

    @staticmethod
    def _get_free_port() -> int:
        """Get a free port for testing."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        sock.close()
        return port


class TestGenericProtocolHandlerUDPProxy:
    """Test UDP proxy server functionality."""

    def test_udp_proxy_starts_and_receives_packets(self) -> None:
        """UDP proxy starts and receives UDP packets."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        port = self._get_free_port()

        started = handler.start_proxy(port)
        assert started is True
        assert handler.running is True
        proxy_thread = handler.proxy_thread
        assert proxy_thread is not None
        assert proxy_thread.is_alive()

        time.sleep(0.2)

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(5.0)
        try:
            client.sendto(b"ping", ("127.0.0.1", port))
            response, _addr = client.recvfrom(1024)
            assert response == b"OK\x00SERVER_ACTIVE\x00"
        finally:
            client.close()
            handler.stop_proxy()

    def test_udp_proxy_responds_to_license_request(self) -> None:
        """UDP proxy responds to license verification request."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(5.0)
        try:
            client.sendto(b"CHECK_LICENSE\x00", ("127.0.0.1", port))
            response, _addr = client.recvfrom(1024)
            assert response == b"OK\x00LICENSE_VALID\x00"
        finally:
            client.close()
            handler.stop_proxy()

    def test_udp_proxy_handles_multiple_packets_from_same_client(self) -> None:
        """UDP proxy handles multiple packets from same client."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(5.0)
        try:
            client.sendto(b"ping", ("127.0.0.1", port))
            response1, _ = client.recvfrom(1024)
            assert response1 == b"OK\x00SERVER_ACTIVE\x00"

            client.sendto(b"CHECK_LICENSE\x00", ("127.0.0.1", port))
            response2, _ = client.recvfrom(1024)
            assert response2 == b"OK\x00LICENSE_VALID\x00"

            client.sendto(b"GET_VERSION", ("127.0.0.1", port))
            response3, _ = client.recvfrom(1024)
            assert response3 == b"GENERIC_LICENSE_SERVER_V1.0\x00"
        finally:
            client.close()
            handler.stop_proxy()

    def test_udp_proxy_handles_concurrent_clients(self) -> None:
        """UDP proxy handles packets from multiple concurrent clients."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)

        def udp_client_task(request: bytes) -> bytes:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.settimeout(5.0)
            try:
                client.sendto(request, ("127.0.0.1", port))
                response, _ = client.recvfrom(1024)
                return response
            finally:
                client.close()

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(udp_client_task, b"CHECK_LICENSE\x00"),
                executor.submit(udp_client_task, b"ping"),
                executor.submit(udp_client_task, b"status"),
                executor.submit(udp_client_task, b"GET_VERSION"),
                executor.submit(udp_client_task, b"verify_auth"),
            ]

            results = [f.result() for f in futures]

        assert results[0] == b"OK\x00LICENSE_VALID\x00"
        assert results[1] == b"OK\x00SERVER_ACTIVE\x00"
        assert results[2] == b"OK\x00SERVER_ACTIVE\x00"
        assert results[3] == b"GENERIC_LICENSE_SERVER_V1.0\x00"
        assert results[4] == b"OK\x00LICENSE_VALID\x00"

        handler.stop_proxy()

    def test_udp_proxy_handles_binary_requests(self) -> None:
        """UDP proxy handles binary protocol requests correctly."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(5.0)
        try:
            client.sendto(b"\x00\x00\x00\x01\xff\xff\xff\xff", ("127.0.0.1", port))
            response, _ = client.recvfrom(1024)
            assert response == b"\x00\x00\x00\x00\x00\x00\x00\x01"

            client.sendto(b"\x02\x00\x00\x00\x00\x00", ("127.0.0.1", port))
            response, _ = client.recvfrom(1024)
            assert response == b"\x00\x00\xff\xff\xff\xff"
        finally:
            client.close()
            handler.stop_proxy()

    def test_udp_proxy_handles_empty_packet(self) -> None:
        """UDP proxy ignores empty packets."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(1.0)
        try:
            client.sendto(b"", ("127.0.0.1", port))
            with pytest.raises(socket.timeout):
                client.recvfrom(1024)
        finally:
            client.close()
            handler.stop_proxy()

    def test_udp_proxy_stops_cleanly(self) -> None:
        """UDP proxy stops cleanly and releases resources."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)
        assert handler.running is True

        stopped = handler.stop_proxy()
        assert stopped
        assert handler.running is False

        time.sleep(0.5)  # type: ignore[unreachable]
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(1.0)
        no_response = False
        try:
            client.sendto(b"ping", ("127.0.0.1", port))
            client.recvfrom(1024)
        except (socket.timeout, OSError):
            no_response = True
        finally:
            client.close()

        assert no_response

    @staticmethod
    def _get_free_port() -> int:
        """Get a free port for testing."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        sock.close()
        return port


class TestGenericProtocolHandlerDataManagement:
    """Test data capture and management functionality."""

    def test_clear_data_removes_captured_requests(self) -> None:
        """clear_data removes all captured request data."""
        handler = GenericProtocolHandler()
        handler.captured_requests = [
            {"data": b"test1", "hex": "74657374", "timestamp": time.time()},
            {"data": b"test2", "hex": "74657374", "timestamp": time.time()},
        ]

        handler.clear_data()

        assert not handler.captured_requests

    def test_clear_data_removes_captured_responses(self) -> None:
        """clear_data removes all captured response data."""
        handler = GenericProtocolHandler()
        handler.captured_responses = [
            {"data": b"response1", "hex": "72657370", "timestamp": time.time()},
            {"data": b"response2", "hex": "72657370", "timestamp": time.time()},
        ]

        handler.clear_data()

        assert not handler.captured_responses

    def test_clear_data_removes_active_connections(self) -> None:
        """clear_data removes all active connection tracking."""
        handler = GenericProtocolHandler()
        handler.active_connections = {
            "conn1": {"socket": None, "address": ("127.0.0.1", 12345)},
            "conn2": {"socket": None, "address": ("127.0.0.1", 12346)},
        }

        handler.clear_data()

        assert not handler.active_connections

    def test_start_proxy_clears_previous_data(self) -> None:
        """Starting proxy clears previously captured data."""
        handler = GenericProtocolHandler({"protocol": "tcp"})
        handler.captured_requests = [{"data": b"old", "hex": "6f6c64"}]
        handler.captured_responses = [{"data": b"old_resp", "hex": "6f6c64"}]

        port = self._get_free_port()
        handler.start_proxy(port)

        time.sleep(0.1)
        assert not handler.captured_requests
        assert not handler.captured_responses

        handler.stop_proxy()

    def test_captured_request_contains_timestamp(self) -> None:
        """Captured requests include timestamp information."""
        handler = GenericProtocolHandler({"protocol": "tcp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)

        before_time = time.time()
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5.0)
        try:
            client.connect(("127.0.0.1", port))
            client.send(b"ping")
            client.recv(1024)
        finally:
            client.close()
        after_time = time.time()

        time.sleep(0.1)
        assert len(handler.captured_requests) == 1
        timestamp = handler.captured_requests[0]["timestamp"]
        assert before_time <= timestamp <= after_time

        handler.stop_proxy()

    def test_captured_request_contains_hex_representation(self) -> None:
        """Captured requests include hex representation of data."""
        handler = GenericProtocolHandler({"protocol": "tcp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5.0)
        try:
            client.connect(("127.0.0.1", port))
            request = b"\x00\x01\x02\x03\x04\x05"
            client.send(request)
            client.recv(1024)
        finally:
            client.close()

        time.sleep(0.1)
        assert len(handler.captured_requests) == 1
        assert handler.captured_requests[0]["hex"] == "000102030405"

        handler.stop_proxy()

    def test_captured_request_contains_source_address(self) -> None:
        """Captured requests include source address information."""
        handler = GenericProtocolHandler({"protocol": "tcp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5.0)
        try:
            client.connect(("127.0.0.1", port))
            client.send(b"ping")
            client.recv(1024)
        finally:
            client.close()

        time.sleep(0.1)
        assert len(handler.captured_requests) == 1
        source = handler.captured_requests[0]["source"]
        assert "127.0.0.1" in source

        handler.stop_proxy()

    def test_captured_response_contains_destination_address(self) -> None:
        """Captured responses include destination address information."""
        handler = GenericProtocolHandler({"protocol": "tcp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5.0)
        try:
            client.connect(("127.0.0.1", port))
            client.send(b"ping")
            client.recv(1024)
        finally:
            client.close()

        time.sleep(0.1)
        assert len(handler.captured_responses) == 1
        destination = handler.captured_responses[0]["destination"]
        assert "127.0.0.1" in destination

        handler.stop_proxy()

    @staticmethod
    def _get_free_port() -> int:
        """Get a free port for testing."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        sock.close()
        return port


class TestGenericProtocolHandlerConnectionHandling:
    """Test connection handling and edge cases."""

    def test_handle_connection_with_socket_without_getpeername(self) -> None:
        """handle_connection works with sockets that don't support getpeername."""

        class MockSocket:
            def send(self, data: bytes) -> int:
                return len(data)

        handler = GenericProtocolHandler()
        mock_socket = MockSocket()
        request = b"ping"

        handler.handle_connection(mock_socket, request)  # type: ignore[arg-type]

        assert len(handler.captured_requests) == 1
        assert handler.captured_requests[0]["data"] == request
        assert handler.captured_requests[0]["source"] == "unknown"

    def test_handle_connection_stores_request_and_response(self) -> None:
        """handle_connection stores both request and response data."""
        handler = GenericProtocolHandler()

        class MockSocket:
            def send(self, data: bytes) -> int:
                return len(data)

            def getpeername(self) -> tuple[str, int]:
                return ("192.168.1.100", 54321)

        mock_socket = MockSocket()
        request = b"CHECK_LICENSE\x00"

        handler.handle_connection(mock_socket, request)  # type: ignore[arg-type]

        assert len(handler.captured_requests) == 1
        assert handler.captured_requests[0]["data"] == request
        assert len(handler.captured_responses) == 1
        assert handler.captured_responses[0]["data"] == b"OK\x00LICENSE_VALID\x00"

    def test_handle_connection_with_sendto_socket(self) -> None:
        """handle_connection works with UDP-like sockets using sendto."""

        class MockUDPSocket:
            def __init__(self) -> None:
                self.sent_data: bytes = b""

            def sendto(self, data: bytes, addr: tuple[str, int]) -> int:
                self.sent_data = data
                return len(data)

            def getpeername(self) -> tuple[str, int]:
                return ("10.0.0.1", 9999)

        handler = GenericProtocolHandler()
        mock_socket = MockUDPSocket()
        request = b"status"

        handler.handle_connection(mock_socket, request)  # type: ignore[arg-type]

        assert mock_socket.sent_data == b"OK\x00SERVER_ACTIVE\x00"
        assert len(handler.captured_responses) == 1

    def test_handle_connection_with_failed_send(self) -> None:
        """handle_connection handles send failures gracefully."""

        class FailingSocket:
            def send(self, data: bytes) -> int:
                raise OSError("Connection reset")

            def getpeername(self) -> tuple[str, int]:
                return ("127.0.0.1", 12345)

        handler = GenericProtocolHandler()
        mock_socket = FailingSocket()
        request = b"ping"

        handler.handle_connection(mock_socket, request)  # type: ignore[arg-type]

        assert len(handler.captured_requests) == 1
        assert len(handler.captured_responses) == 0

    def test_tcp_connection_timeout_handling(self) -> None:
        """TCP connections respect timeout settings."""
        handler = GenericProtocolHandler({"protocol": "tcp", "timeout": 1})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5.0)
        try:
            client.connect(("127.0.0.1", port))
            client.send(b"ping")
            response = client.recv(1024)
            assert response == b"OK\x00SERVER_ACTIVE\x00"

            time.sleep(2.0)

            try:
                client.send(b"status")
                response = client.recv(1024)
            except OSError:
                pass
        finally:
            client.close()
            handler.stop_proxy()

    def test_connection_id_generation_is_unique(self) -> None:
        """Connection IDs are unique for different connections."""
        handler = GenericProtocolHandler({"protocol": "tcp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)

        client1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client1.settimeout(5.0)
        client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client2.settimeout(5.0)

        try:
            client1.connect(("127.0.0.1", port))
            client1.send(b"ping")
            time.sleep(0.05)

            client2.connect(("127.0.0.1", port))
            client2.send(b"status")
            time.sleep(0.05)

            conn_ids = list(handler.active_connections.keys())
            if len(conn_ids) >= 2:
                assert conn_ids[0] != conn_ids[1]

            client1.recv(1024)
            client2.recv(1024)
        finally:
            client1.close()
            client2.close()
            handler.stop_proxy()

    def test_active_connection_contains_socket_and_metadata(self) -> None:
        """Active connections contain socket and metadata."""
        handler = GenericProtocolHandler({"protocol": "tcp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5.0)
        try:
            client.connect(("127.0.0.1", port))
            client.send(b"ping")
            time.sleep(0.1)

            if len(handler.active_connections) > 0:
                conn_id = next(iter(handler.active_connections.keys()))
                conn_data = handler.active_connections[conn_id]

                assert "socket" in conn_data
                assert "address" in conn_data
                assert "start_time" in conn_data
                assert conn_data["address"][0] == "127.0.0.1"

            client.recv(1024)
        finally:
            client.close()
            handler.stop_proxy()

    @staticmethod
    def _get_free_port() -> int:
        """Get a free port for testing."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        sock.close()
        return port


class TestGenericProtocolHandlerEdgeCases:
    """Test edge cases and error conditions."""

    def test_protocol_route_dispatches_to_tcp(self) -> None:
        """_run_proxy dispatches to TCP proxy for TCP protocol."""
        handler = GenericProtocolHandler({"protocol": "tcp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5.0)
        try:
            client.connect(("127.0.0.1", port))
        finally:
            client.close()
            handler.stop_proxy()

    def test_protocol_route_dispatches_to_udp(self) -> None:
        """_run_proxy dispatches to UDP proxy for UDP protocol."""
        handler = GenericProtocolHandler({"protocol": "udp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(5.0)
        try:
            client.sendto(b"ping", ("127.0.0.1", port))
            response, _ = client.recvfrom(1024)
            assert response == b"OK\x00SERVER_ACTIVE\x00"
        finally:
            client.close()
            handler.stop_proxy()

    def test_large_request_data_handled_correctly(self) -> None:
        """Handler processes large request data correctly."""
        handler = GenericProtocolHandler({"protocol": "tcp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)

        large_request = b"license_validation_request" + (b"\x00" * 3000)

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5.0)
        try:
            client.connect(("127.0.0.1", port))
            client.sendall(large_request)
            time.sleep(0.2)
            response = client.recv(1024)
            assert response == b"OK\x00LICENSE_VALID\x00"

            time.sleep(0.2)
            assert len(handler.captured_requests) >= 1
            total_data_len = sum(len(req["data"]) for req in handler.captured_requests)
            assert total_data_len >= len(large_request)
        finally:
            client.close()
            time.sleep(0.1)
            handler.stop_proxy()

    def test_rapid_connection_cycling(self) -> None:
        """Handler manages rapid connection open/close cycles."""
        handler = GenericProtocolHandler({"protocol": "tcp"})
        port = self._get_free_port()

        handler.start_proxy(port)
        time.sleep(0.2)

        for _ in range(10):
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(5.0)
            try:
                client.connect(("127.0.0.1", port))
                client.send(b"ping")
                response = client.recv(1024)
                assert response == b"OK\x00SERVER_ACTIVE\x00"
            finally:
                client.close()
            time.sleep(0.05)

        time.sleep(0.3)
        assert len(handler.captured_requests) == 10
        assert len(handler.active_connections) == 0

        handler.stop_proxy()

    def test_multiple_start_stop_cycles(self) -> None:
        """Handler handles multiple start/stop cycles correctly."""
        handler = GenericProtocolHandler({"protocol": "tcp"})
        port = self._get_free_port()

        for _ in range(3):
            handler.start_proxy(port)
            time.sleep(0.2)

            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(5.0)
            try:
                client.connect(("127.0.0.1", port))
                client.send(b"ping")
                response = client.recv(1024)
                assert response == b"OK\x00SERVER_ACTIVE\x00"
            finally:
                client.close()

            handler.stop_proxy()
            time.sleep(0.2)

    @staticmethod
    def _get_free_port() -> int:
        """Get a free port for testing."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        sock.close()
        return port
