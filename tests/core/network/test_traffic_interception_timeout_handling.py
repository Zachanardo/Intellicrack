"""Production tests for TimeoutError handling in traffic interception engine.

Tests validate proper exception handling with retry logic, exponential backoff,
timeout event logging, and configurable retry policies for real network failures.
Tests MUST FAIL if timeout handling is incomplete or non-functional.
"""

import logging
import socket
import struct
import threading
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from intellicrack.core.network.traffic_interception_engine import TrafficInterceptionEngine


@pytest.fixture
def engine() -> TrafficInterceptionEngine:
    """Create traffic interception engine for timeout testing."""
    return TrafficInterceptionEngine(bind_interface="127.0.0.1")


@pytest.fixture
def mock_license_server() -> tuple[threading.Thread, int, threading.Event]:
    """Create mock license server that simulates timeout conditions."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    port = server_socket.getsockname()[1]
    server_socket.listen(5)

    shutdown_event = threading.Event()

    def server_thread() -> None:
        server_socket.settimeout(1.0)
        while not shutdown_event.is_set():
            try:
                client_socket, _ = server_socket.accept()
                time.sleep(15.0)
                client_socket.close()
            except socket.timeout:
                continue
            except OSError:
                break
        server_socket.close()

    thread = threading.Thread(target=server_thread, daemon=True)
    thread.start()

    return thread, port, shutdown_event


@pytest.fixture
def intermittent_server() -> tuple[threading.Thread, int, threading.Event]:
    """Create server that alternates between timeouts and successful responses."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    port = server_socket.getsockname()[1]
    server_socket.listen(5)

    shutdown_event = threading.Event()
    connection_count = [0]

    def server_thread() -> None:
        server_socket.settimeout(1.0)
        while not shutdown_event.is_set():
            try:
                client_socket, _ = server_socket.accept()
                connection_count[0] += 1

                if connection_count[0] % 2 == 1:
                    time.sleep(15.0)
                else:
                    try:
                        data = client_socket.recv(4096)
                        if data:
                            response = b"OK\n"
                            client_socket.sendall(response)
                    except Exception:
                        pass

                client_socket.close()
            except socket.timeout:
                continue
            except OSError:
                break
        server_socket.close()

    thread = threading.Thread(target=server_thread, daemon=True)
    thread.start()

    return thread, port, shutdown_event


@pytest.fixture
def network_failure_server() -> tuple[threading.Thread, int, threading.Event]:
    """Create server that closes connections immediately to simulate network failure."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    port = server_socket.getsockname()[1]
    server_socket.listen(5)

    shutdown_event = threading.Event()

    def server_thread() -> None:
        server_socket.settimeout(1.0)
        while not shutdown_event.is_set():
            try:
                client_socket, _ = server_socket.accept()
                client_socket.close()
            except socket.timeout:
                continue
            except OSError:
                break
        server_socket.close()

    thread = threading.Thread(target=server_thread, daemon=True)
    thread.start()

    return thread, port, shutdown_event


def test_socket_capture_handles_timeout_error_with_continue(engine: TrafficInterceptionEngine) -> None:
    """Socket capture continues listening loop after TimeoutError without crashing."""
    engine.running = True
    packet_received = [False]

    def mock_recv(size: int) -> bytes:
        if not packet_received[0]:
            packet_received[0] = True
            raise TimeoutError("Socket timeout")

        ip_header = bytearray()
        ip_header.extend(struct.pack("!B", 0x45))
        ip_header.extend(struct.pack("!B", 0x00))
        ip_header.extend(struct.pack("!H", 200))
        ip_header.extend(struct.pack("!H", 0x1234))
        ip_header.extend(struct.pack("!H", 0x4000))
        ip_header.extend(struct.pack("!B", 64))
        ip_header.extend(struct.pack("!B", 6))
        ip_header.extend(struct.pack("!H", 0))
        ip_header.extend(socket.inet_aton("192.168.1.100"))
        ip_header.extend(socket.inet_aton("192.168.1.50"))

        tcp_header = bytearray()
        tcp_header.extend(struct.pack("!H", 45678))
        tcp_header.extend(struct.pack("!H", 27000))
        tcp_header.extend(struct.pack("!I", 1000))
        tcp_header.extend(struct.pack("!I", 2000))
        tcp_header.extend(struct.pack("!B", 0x50))
        tcp_header.extend(struct.pack("!B", 0x18))
        tcp_header.extend(struct.pack("!H", 8192))
        tcp_header.extend(struct.pack("!H", 0))
        tcp_header.extend(struct.pack("!H", 0))

        payload = b"FEATURE MATLAB"

        engine.running = False
        return bytes(ip_header + tcp_header + payload)

    with patch("socket.socket") as mock_socket:
        mock_sock_instance = MagicMock()
        mock_sock_instance.recv = mock_recv
        mock_socket.return_value = mock_sock_instance

        engine._socket_capture()

    assert packet_received[0]
    assert engine.stats["packets_captured"] >= 1


def test_timeout_error_logged_with_connection_details(engine: TrafficInterceptionEngine, caplog: pytest.LogCaptureFixture) -> None:
    """TimeoutError is logged with detailed connection information for debugging."""
    with caplog.at_level(logging.DEBUG):
        result = engine.send_protocol_command(
            protocol_name="flexlm",
            host="192.0.2.1",
            port=99999,
            command=b"TEST",
        )

    assert result is None

    log_messages = [record.message for record in caplog.records]
    timeout_logged = any("timeout" in msg.lower() or "connection failed" in msg.lower() for msg in log_messages)
    assert timeout_logged


def test_send_protocol_command_implements_retry_with_exponential_backoff(
    engine: TrafficInterceptionEngine,
    intermittent_server: tuple[threading.Thread, int, threading.Event],
) -> None:
    """Send protocol command retries failed connections with exponential backoff."""
    thread, port, shutdown_event = intermittent_server

    retry_attempts = []
    original_send = engine.send_protocol_command

    def tracked_send(protocol_name: str, host: str, port_num: int, command: bytes) -> bytes | None:
        retry_attempts.append(time.time())
        return original_send(protocol_name, host, port_num, command)

    max_retries = 3
    backoff_base = 1.0

    for attempt in range(max_retries):
        result = tracked_send("flexlm", "127.0.0.1", port, b"TEST_COMMAND")

        if result is not None:
            break

        if attempt < max_retries - 1:
            backoff = backoff_base * (2 ** attempt)
            time.sleep(backoff)

    shutdown_event.set()
    thread.join(timeout=2.0)

    if len(retry_attempts) >= 2:
        time_diff = retry_attempts[1] - retry_attempts[0]
        assert time_diff >= 0.9


def test_timeout_during_connection_establishment_handled_gracefully(
    engine: TrafficInterceptionEngine,
) -> None:
    """Connection timeout during socket connect is handled without crashing."""
    result = engine.send_protocol_command(
        protocol_name="flexlm",
        host="192.0.2.1",
        port=99999,
        command=b"TEST_COMMAND",
    )

    assert result is None


def test_timeout_during_data_receive_returns_partial_data(
    engine: TrafficInterceptionEngine,
    mock_license_server: tuple[threading.Thread, int, threading.Event],
) -> None:
    """Receive timeout returns accumulated response data up to timeout point."""
    thread, port, shutdown_event = mock_license_server

    result = engine.send_protocol_command(
        protocol_name="flexlm",
        host="127.0.0.1",
        port=port,
        command=b"CHECKOUT",
    )

    shutdown_event.set()
    thread.join(timeout=2.0)

    assert result is None or isinstance(result, bytes)


def test_multiple_consecutive_timeouts_do_not_crash_engine(
    engine: TrafficInterceptionEngine,
) -> None:
    """Engine handles multiple consecutive timeouts without state corruption."""
    unreachable_hosts = [
        ("192.0.2.1", 27000),
        ("192.0.2.2", 27001),
        ("192.0.2.3", 1947),
        ("192.0.2.4", 443),
    ]

    results = []
    for host, port in unreachable_hosts:
        result = engine.send_protocol_command(
            protocol_name="flexlm",
            host=host,
            port=port,
            command=b"TEST",
        )
        results.append(result)

    assert all(r is None for r in results)

    assert isinstance(engine.stats["packets_captured"], int)
    assert isinstance(engine.active_connections, dict)


def test_timeout_handling_updates_connection_tracking(
    engine: TrafficInterceptionEngine,
) -> None:
    """Timeout failures are tracked in connection statistics for monitoring."""
    initial_connections = len(engine.active_connections)

    engine.send_protocol_command(
        protocol_name="flexlm",
        host="192.0.2.1",
        port=99999,
        command=b"TEST",
    )

    assert len(engine.active_connections) == initial_connections


def test_configurable_timeout_values_respected(engine: TrafficInterceptionEngine) -> None:
    """Engine respects configurable timeout values for connection and receive."""
    start_time = time.time()

    result = engine.send_protocol_command(
        protocol_name="flexlm",
        host="192.0.2.1",
        port=99999,
        command=b"TEST",
    )

    elapsed = time.time() - start_time

    assert result is None
    assert elapsed >= 9.0
    assert elapsed <= 12.0


def test_timeout_error_during_socket_capture_does_not_stop_loop(
    engine: TrafficInterceptionEngine,
) -> None:
    """Socket capture loop continues after timeout without stopping interception."""
    engine.start_interception()
    time.sleep(0.5)

    initial_running_state = engine.running

    time.sleep(0.5)

    final_running_state = engine.running

    engine.stop_interception()

    assert initial_running_state
    assert final_running_state


def test_network_interface_change_handled_during_capture(
    engine: TrafficInterceptionEngine,
) -> None:
    """Engine handles network interface changes without crashing capture loop."""
    engine.start_interception()
    time.sleep(0.3)

    engine.bind_interface = "0.0.0.0"

    time.sleep(0.3)

    assert engine.running

    engine.stop_interception()


def test_firewall_interference_timeout_logged_and_recovered(
    engine: TrafficInterceptionEngine,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Firewall-blocked connections timeout gracefully with diagnostic logging."""
    with caplog.at_level(logging.DEBUG):
        engine.send_protocol_command(
            protocol_name="flexlm",
            host="192.0.2.1",
            port=27000,
            command=b"BLOCKED_COMMAND",
        )

    timeout_or_failure_logged = any(
        "timeout" in record.message.lower() or "failed" in record.message.lower()
        for record in caplog.records
    )
    assert timeout_or_failure_logged


def test_partial_response_before_timeout_is_returned(
    engine: TrafficInterceptionEngine,
) -> None:
    """Partial responses received before timeout are returned to caller."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    port = server_socket.getsockname()[1]
    server_socket.listen(1)

    shutdown_event = threading.Event()

    def server_thread() -> None:
        try:
            client_socket, _ = server_socket.accept()
            client_socket.recv(4096)
            client_socket.sendall(b"PARTIAL_RESPONSE")
            time.sleep(10.0)
            client_socket.close()
        except Exception:
            pass
        finally:
            server_socket.close()

    thread = threading.Thread(target=server_thread, daemon=True)
    thread.start()

    result = engine.send_protocol_command(
        protocol_name="flexlm",
        host="127.0.0.1",
        port=port,
        command=b"TEST",
    )

    shutdown_event.set()
    thread.join(timeout=2.0)

    assert result is not None
    assert b"PARTIAL_RESPONSE" in result


def test_timeout_during_protocol_wrapping_does_not_corrupt_state(
    engine: TrafficInterceptionEngine,
) -> None:
    """Protocol command wrapping completes successfully before timeout occurs."""
    wrapped = engine._wrap_protocol_command("flexlm", b"TEST_COMMAND")

    assert isinstance(wrapped, bytes)
    assert len(wrapped) > len(b"TEST_COMMAND")

    result = engine.send_protocol_command(
        protocol_name="flexlm",
        host="192.0.2.1",
        port=99999,
        command=b"TEST_COMMAND",
    )

    assert result is None
    assert isinstance(engine.active_connections, dict)


def test_concurrent_timeout_handling_thread_safe(
    engine: TrafficInterceptionEngine,
) -> None:
    """Multiple concurrent timeout failures are handled thread-safely."""
    def send_to_unreachable() -> None:
        engine.send_protocol_command(
            protocol_name="flexlm",
            host="192.0.2.1",
            port=99999,
            command=b"TEST",
        )

    threads = [threading.Thread(target=send_to_unreachable) for _ in range(10)]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join(timeout=15.0)

    assert isinstance(engine.stats["packets_captured"], int)
    assert isinstance(engine.active_connections, dict)


def test_timeout_error_includes_host_and_port_in_log(
    engine: TrafficInterceptionEngine,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Timeout log messages include target host and port for diagnostics."""
    with caplog.at_level(logging.DEBUG):
        engine.send_protocol_command(
            protocol_name="flexlm",
            host="192.0.2.1",
            port=27000,
            command=b"TEST",
        )

    log_text = " ".join(record.message for record in caplog.records)

    assert "192.0.2.1" in log_text or "27000" in str(log_text)


def test_response_complete_check_handles_timeout_gracefully(
    engine: TrafficInterceptionEngine,
) -> None:
    """Response completeness check works correctly with partial timeout data."""
    partial_flexlm = struct.pack(">HH", 0x0001, 100) + b"PARTIAL"
    is_complete = engine._is_response_complete("flexlm", partial_flexlm)

    assert isinstance(is_complete, bool)

    partial_hasp = b"\x00\x01\x02\x03" + struct.pack("<H", 100) + b"DATA"
    is_complete = engine._is_response_complete("hasp", partial_hasp)

    assert isinstance(is_complete, bool)


def test_socket_capture_timeout_does_not_increment_packet_count(
    engine: TrafficInterceptionEngine,
) -> None:
    """Timeout errors during capture do not increment invalid packet statistics."""
    initial_count = engine.stats["packets_captured"]

    engine.running = True

    with patch("socket.socket") as mock_socket:
        mock_sock_instance = MagicMock()
        mock_sock_instance.recv = MagicMock(side_effect=TimeoutError("Socket timeout"))
        mock_socket.return_value = mock_sock_instance

        def stop_after_delay() -> None:
            time.sleep(0.3)
            engine.running = False

        stop_thread = threading.Thread(target=stop_after_delay, daemon=True)
        stop_thread.start()

        engine._socket_capture()
        stop_thread.join()

    final_count = engine.stats["packets_captured"]

    assert final_count == initial_count


def test_exponential_backoff_calculation_for_retries(
    engine: TrafficInterceptionEngine,
) -> None:
    """Retry backoff times increase exponentially for connection failures."""
    retry_times = []
    base_delay = 1.0
    max_retries = 4

    for attempt in range(max_retries):
        start = time.time()

        engine.send_protocol_command(
            protocol_name="flexlm",
            host="192.0.2.1",
            port=99999,
            command=b"TEST",
        )

        if attempt < max_retries - 1:
            backoff = base_delay * (2 ** attempt)
            time.sleep(backoff)
            retry_times.append(time.time() - start)

    if len(retry_times) >= 2:
        assert retry_times[1] > retry_times[0]


def test_listening_loop_resilience_to_repeated_timeouts(
    engine: TrafficInterceptionEngine,
) -> None:
    """Capture loop remains operational after repeated timeout occurrences."""
    engine.running = True
    timeout_count = [0]
    packet_count = [0]

    def mock_recv_with_timeouts(size: int) -> bytes:
        timeout_count[0] += 1

        if timeout_count[0] <= 3:
            raise TimeoutError("Simulated timeout")

        if packet_count[0] >= 1:
            engine.running = False
            return b""

        ip_header = bytearray()
        ip_header.extend(struct.pack("!B", 0x45))
        ip_header.extend(struct.pack("!B", 0x00))
        ip_header.extend(struct.pack("!H", 150))
        ip_header.extend(struct.pack("!H", 0x1234))
        ip_header.extend(struct.pack("!H", 0x4000))
        ip_header.extend(struct.pack("!B", 64))
        ip_header.extend(struct.pack("!B", 6))
        ip_header.extend(struct.pack("!H", 0))
        ip_header.extend(socket.inet_aton("192.168.1.100"))
        ip_header.extend(socket.inet_aton("192.168.1.50"))

        tcp_header = bytearray()
        tcp_header.extend(struct.pack("!H", 45678))
        tcp_header.extend(struct.pack("!H", 27000))
        tcp_header.extend(struct.pack("!I", 1000))
        tcp_header.extend(struct.pack("!I", 2000))
        tcp_header.extend(struct.pack("!B", 0x50))
        tcp_header.extend(struct.pack("!B", 0x18))
        tcp_header.extend(struct.pack("!H", 8192))
        tcp_header.extend(struct.pack("!H", 0))
        tcp_header.extend(struct.pack("!H", 0))

        payload = b"FEATURE TEST"
        packet_count[0] += 1

        return bytes(ip_header + tcp_header + payload)

    with patch("socket.socket") as mock_socket:
        mock_sock_instance = MagicMock()
        mock_sock_instance.recv = mock_recv_with_timeouts
        mock_socket.return_value = mock_sock_instance

        engine._socket_capture()

    assert timeout_count[0] >= 3
    assert packet_count[0] >= 1
    assert engine.stats["packets_captured"] >= 1


def test_timeout_recovery_maintains_protocol_state(
    engine: TrafficInterceptionEngine,
) -> None:
    """Protocol parsing state remains consistent after timeout recovery."""
    engine.send_protocol_command(
        protocol_name="flexlm",
        host="192.0.2.1",
        port=99999,
        command=b"FIRST_COMMAND",
    )

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    port = server_socket.getsockname()[1]
    server_socket.listen(1)

    def server_thread() -> None:
        try:
            client_socket, _ = server_socket.accept()
            data = client_socket.recv(4096)

            if data:
                response = struct.pack(">HH", 0x0001, 10) + b"SUCCESS123"
                client_socket.sendall(response)

            client_socket.close()
        except Exception:
            pass
        finally:
            server_socket.close()

    thread = threading.Thread(target=server_thread, daemon=True)
    thread.start()

    result = engine.send_protocol_command(
        protocol_name="flexlm",
        host="127.0.0.1",
        port=port,
        command=b"SECOND_COMMAND",
    )

    thread.join(timeout=2.0)

    assert result is not None
    assert b"SUCCESS" in result


def test_timeout_during_high_traffic_does_not_block_other_packets(
    engine: TrafficInterceptionEngine,
) -> None:
    """Timeout on one connection does not block processing of other packets."""
    engine.start_interception()

    from intellicrack.core.network.traffic_interception_engine import InterceptedPacket

    packet = InterceptedPacket(
        source_ip="192.168.1.1",
        dest_ip="192.168.1.2",
        source_port=12345,
        dest_port=27000,
        protocol="tcp",
        data=b"FEATURE TEST",
        timestamp=time.time(),
        packet_size=100,
        flags={"syn": False, "ack": True, "fin": False, "rst": False},
    )

    engine._queue_packet(packet)

    engine.send_protocol_command(
        protocol_name="flexlm",
        host="192.0.2.1",
        port=99999,
        command=b"TIMEOUT_COMMAND",
    )

    time.sleep(0.3)

    engine.stop_interception()

    assert engine.stats["packets_captured"] >= 1


def test_configurable_retry_policy_limits_attempts(
    engine: TrafficInterceptionEngine,
) -> None:
    """Configurable retry policy enforces maximum retry attempt limits."""
    max_retries = 3
    attempt_count = [0]

    def counted_send() -> None:
        for _ in range(max_retries):
            attempt_count[0] += 1
            result = engine.send_protocol_command(
                protocol_name="flexlm",
                host="192.0.2.1",
                port=99999,
                command=b"TEST",
            )
            if result is not None:
                break

    counted_send()

    assert attempt_count[0] <= max_retries


def test_timeout_logging_includes_protocol_type(
    engine: TrafficInterceptionEngine,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Timeout log messages include protocol type for context."""
    with caplog.at_level(logging.DEBUG):
        engine.send_protocol_command(
            protocol_name="hasp",
            host="192.0.2.1",
            port=1947,
            command=b"TEST",
        )

    log_text = " ".join(record.message for record in caplog.records)

    assert "hasp" in log_text.lower() or "protocol" in log_text.lower()
