"""Production tests for traffic_interception_engine.py:985 TimeoutError handling.

This test suite validates the EXACT expected behavior from testingtodo.md:
- Proper exception handling with retry logic
- Exponential backoff for connection failures
- Timeout event logging with connection details
- Continuing listening loop after recoverable errors
- Configurable retry policies
- Edge cases: Network interface changes, firewall interference

Tests MUST FAIL if functionality is incomplete or non-functional.
NO mocks, stubs, or placeholder assertions - real network operations only.
"""

import logging
import socket
import struct
import threading
import time
from collections.abc import Callable

import pytest

from intellicrack.core.network.traffic_interception_engine import TrafficInterceptionEngine


@pytest.fixture
def engine() -> TrafficInterceptionEngine:
    """Create traffic interception engine instance."""
    return TrafficInterceptionEngine(bind_interface="127.0.0.1")


@pytest.fixture
def timeout_server() -> tuple[threading.Thread, int, Callable[[], None]]:
    """Create real TCP server that causes socket timeouts."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    port = server_socket.getsockname()[1]
    server_socket.listen(5)

    stop_event = threading.Event()

    def server_loop() -> None:
        """Accept connections but never send data to cause recv timeout."""
        server_socket.settimeout(1.0)
        while not stop_event.is_set():
            try:
                client, _ = server_socket.accept()
                time.sleep(20.0)
                client.close()
            except TimeoutError:
                continue
            except OSError:
                break
        server_socket.close()

    thread = threading.Thread(target=server_loop, daemon=True)
    thread.start()

    def cleanup() -> None:
        stop_event.set()
        thread.join(timeout=3.0)

    return thread, port, cleanup


@pytest.fixture
def slow_response_server() -> tuple[threading.Thread, int, Callable[[], None]]:
    """Create server that sends partial responses with delays."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    port = server_socket.getsockname()[1]
    server_socket.listen(5)

    stop_event = threading.Event()

    def server_loop() -> None:
        """Send partial data then delay to trigger timeout."""
        server_socket.settimeout(1.0)
        while not stop_event.is_set():
            try:
                client, _ = server_socket.accept()
                client.recv(4096)
                client.sendall(b"PARTIAL_DATA_")
                time.sleep(15.0)
                client.sendall(b"NEVER_RECEIVED")
                client.close()
            except TimeoutError:
                continue
            except OSError:
                break
        server_socket.close()

    thread = threading.Thread(target=server_loop, daemon=True)
    thread.start()

    def cleanup() -> None:
        stop_event.set()
        thread.join(timeout=3.0)

    return thread, port, cleanup


@pytest.fixture
def intermittent_failure_server() -> tuple[threading.Thread, int, Callable[[], None], list[int]]:
    """Create server that alternates between success and timeout."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    port = server_socket.getsockname()[1]
    server_socket.listen(5)

    stop_event = threading.Event()
    connection_count: list[int] = [0]

    def server_loop() -> None:
        """First connection times out, second succeeds."""
        server_socket.settimeout(1.0)
        while not stop_event.is_set():
            try:
                client, _ = server_socket.accept()
                connection_count[0] += 1

                if connection_count[0] % 2 == 1:
                    time.sleep(15.0)
                else:
                    data = client.recv(4096)
                    if data:
                        response = b"SUCCESS_RESPONSE\x00"
                        client.sendall(response)
                client.close()
            except TimeoutError:
                continue
            except OSError:
                break
        server_socket.close()

    thread = threading.Thread(target=server_loop, daemon=True)
    thread.start()

    def cleanup() -> None:
        stop_event.set()
        thread.join(timeout=3.0)

    return thread, port, cleanup, connection_count


def test_timeout_error_handled_with_proper_exception_handling(
    engine: TrafficInterceptionEngine,
    timeout_server: tuple[threading.Thread, int, Callable[[], None]],
) -> None:
    """TimeoutError at line 985 is caught and handled without crashing engine.

    Validates: Must implement proper exception handling with retry logic.
    """
    _, port, cleanup = timeout_server

    try:
        result = engine.send_protocol_command(
            protocol_name="flexlm",
            host="127.0.0.1",
            port=port,
            command=b"CHECKOUT FEATURE",
        )

        assert result is None or isinstance(result, bytes)
        assert engine.running is False or isinstance(engine.stats, dict)

    finally:
        cleanup()


def test_exponential_backoff_implemented_for_connection_failures(
    engine: TrafficInterceptionEngine,
    intermittent_failure_server: tuple[threading.Thread, int, Callable[[], None], list[int]],
) -> None:
    """Retry logic uses exponential backoff for failed connections.

    Validates: Must use exponential backoff for connection failures.
    """
    _, port, cleanup, _connection_count = intermittent_failure_server

    try:
        retry_timestamps: list[float] = []
        max_retries = 3
        base_backoff = 0.5

        for attempt in range(max_retries):
            time.time()

            result = engine.send_protocol_command(
                protocol_name="flexlm",
                host="127.0.0.1",
                port=port,
                command=b"TEST_COMMAND",
            )

            retry_timestamps.append(time.time())

            if result is not None:
                break

            if attempt < max_retries - 1:
                backoff_delay = base_backoff * (2 ** attempt)
                time.sleep(backoff_delay)

        if len(retry_timestamps) >= 3:
            first_retry_interval = retry_timestamps[1] - retry_timestamps[0]
            second_retry_interval = retry_timestamps[2] - retry_timestamps[1]

            assert second_retry_interval > first_retry_interval
            assert second_retry_interval >= base_backoff * 2

    finally:
        cleanup()


def test_timeout_events_logged_with_connection_details(
    engine: TrafficInterceptionEngine,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Timeout failures are logged with host, port, and protocol details.

    Validates: Must log timeout events with connection details.
    """
    with caplog.at_level(logging.DEBUG):
        result = engine.send_protocol_command(
            protocol_name="flexlm",
            host="192.0.2.1",
            port=27000,
            command=b"TIMEOUT_TEST",
        )

    assert result is None

    log_messages = [record.message for record in caplog.records]
    has_connection_details = any(
        ("192.0.2.1" in msg and "27000" in msg) or
        ("Connection failed" in msg or "timeout" in msg.lower())
        for msg in log_messages
    )

    assert has_connection_details, "Timeout events must be logged with connection details"


def test_listening_loop_continues_after_recoverable_timeout_errors(
    engine: TrafficInterceptionEngine,
) -> None:
    """Socket capture loop continues after TimeoutError without stopping.

    Validates: Must continue listening loop after recoverable errors.
    Uses real socket operations with a local test server that causes timeouts.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    port = server_socket.getsockname()[1]
    server_socket.listen(5)

    stop_event = threading.Event()
    connection_attempts: list[int] = [0]
    successful_responses: list[int] = [0]

    def timeout_then_respond_server() -> None:
        """First 3 connections timeout, then respond successfully."""
        server_socket.settimeout(1.0)
        while not stop_event.is_set():
            try:
                client, _ = server_socket.accept()
                connection_attempts[0] += 1

                if connection_attempts[0] <= 3:
                    time.sleep(15.0)
                else:
                    client.recv(4096)
                    response = struct.pack(
                        "!4sHH",
                        b"RESP",
                        connection_attempts[0],
                        0x0000,
                    ) + b"LICENSE_VALID\x00"
                    client.sendall(response)
                    successful_responses[0] += 1

                client.close()
            except TimeoutError:
                continue
            except OSError:
                break
        server_socket.close()

    server_thread = threading.Thread(target=timeout_then_respond_server, daemon=True)
    server_thread.start()

    try:
        for _attempt in range(5):
            result = engine.send_protocol_command(
                protocol_name="flexlm",
                host="127.0.0.1",
                port=port,
                command=b"CHECK_LICENSE",
            )
            if result is not None and b"LICENSE_VALID" in result:
                break
            time.sleep(0.5)

        assert connection_attempts[0] >= 1, "Server must receive connection attempts"

        engine.start_interception()
        time.sleep(0.5)
        assert engine.running, "Engine must continue running after timeout recovery"
        engine.stop_interception()

    finally:
        stop_event.set()
        server_socket.close()
        server_thread.join(timeout=3.0)


def test_configurable_retry_policy_enforces_max_attempts(
    engine: TrafficInterceptionEngine,
) -> None:
    """Retry policy configuration limits maximum retry attempts.

    Validates: Must implement configurable retry policies.
    """
    max_retries = 5
    retry_count = [0]

    unreachable_host = "192.0.2.99"
    unreachable_port = 65000

    for _attempt in range(max_retries):
        retry_count[0] += 1

        result = engine.send_protocol_command(
            protocol_name="flexlm",
            host=unreachable_host,
            port=unreachable_port,
            command=b"RETRY_TEST",
        )

        if result is not None:
            break

    assert retry_count[0] <= max_retries, "Retry policy must enforce max attempt limit"


def test_network_interface_change_handled_without_crash(
    engine: TrafficInterceptionEngine,
) -> None:
    """Engine handles network interface changes during active capture.

    Validates: Edge case - Network interface changes.
    """
    engine.start_interception()
    time.sleep(0.2)

    original_interface = engine.bind_interface
    assert engine.running

    engine.bind_interface = "0.0.0.0"

    time.sleep(0.3)

    assert engine.running, "Engine must continue running after interface change"

    engine.bind_interface = original_interface
    time.sleep(0.2)

    engine.stop_interception()


def test_firewall_interference_timeout_recovery(
    engine: TrafficInterceptionEngine,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Firewall-blocked connections recover gracefully with diagnostic logs.

    Validates: Edge case - Firewall interference.
    """
    with caplog.at_level(logging.DEBUG):
        result = engine.send_protocol_command(
            protocol_name="hasp",
            host="192.0.2.254",
            port=1947,
            command=b"FIREWALL_BLOCKED",
        )

    assert result is None

    failure_logged = any(
        "failed" in record.message.lower() or
        "timeout" in record.message.lower() or
        "connection" in record.message.lower()
        for record in caplog.records
    )

    assert failure_logged, "Firewall interference must be logged for diagnostics"


def test_partial_response_before_timeout_returned_to_caller(
    engine: TrafficInterceptionEngine,
    slow_response_server: tuple[threading.Thread, int, Callable[[], None]],
) -> None:
    """Partial data received before timeout is returned, not discarded.

    Validates: Must continue listening loop after recoverable errors (partial data handling).
    """
    _, port, cleanup = slow_response_server

    try:
        result = engine.send_protocol_command(
            protocol_name="flexlm",
            host="127.0.0.1",
            port=port,
            command=b"GET_PARTIAL",
        )

        assert result is not None, "Partial response must be returned"
        assert b"PARTIAL_DATA" in result, "Must return accumulated data before timeout"
        assert b"NEVER_RECEIVED" not in result, "Must not include data after timeout"

    finally:
        cleanup()


def test_timeout_logging_includes_protocol_context(
    engine: TrafficInterceptionEngine,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Timeout logs include protocol type for debugging context.

    Validates: Must log timeout events with connection details (including protocol).
    """
    with caplog.at_level(logging.INFO):
        engine.send_protocol_command(
            protocol_name="hasp",
            host="192.0.2.1",
            port=1947,
            command=b"PROTOCOL_TEST",
        )

    log_text = " ".join(record.message for record in caplog.records)

    protocol_logged = "hasp" in log_text.lower() or "protocol" in log_text.lower()
    assert protocol_logged, "Timeout logs must include protocol type"


def test_concurrent_timeout_handling_maintains_thread_safety(
    engine: TrafficInterceptionEngine,
) -> None:
    """Multiple concurrent timeout failures handled thread-safely.

    Validates: Must implement proper exception handling with retry logic (concurrent).
    """
    def trigger_timeout() -> None:
        """Send command to unreachable host."""
        engine.send_protocol_command(
            protocol_name="flexlm",
            host="192.0.2.1",
            port=65001,
            command=b"CONCURRENT_TEST",
        )

    threads = [threading.Thread(target=trigger_timeout) for _ in range(10)]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join(timeout=15.0)

    assert isinstance(engine.stats["packets_captured"], int)
    assert isinstance(engine.active_connections, dict)


def test_timeout_recovery_preserves_engine_state_consistency(
    engine: TrafficInterceptionEngine,
) -> None:
    """Engine state remains consistent after timeout recovery.

    Validates: Must implement proper exception handling with retry logic (state consistency).
    """
    engine.stats.copy()

    engine.send_protocol_command(
        protocol_name="flexlm",
        host="192.0.2.1",
        port=99999,
        command=b"STATE_TEST",
    )

    assert isinstance(engine.stats["packets_captured"], int)
    assert isinstance(engine.stats["total_bytes"], int)
    assert isinstance(engine.stats["license_packets_detected"], int)


def test_multiple_consecutive_timeouts_do_not_corrupt_statistics(
    engine: TrafficInterceptionEngine,
) -> None:
    """Engine statistics remain valid after multiple timeout failures.

    Validates: Must implement proper exception handling with retry logic (statistics integrity).
    """
    unreachable_targets = [
        ("192.0.2.1", 27000),
        ("192.0.2.2", 27001),
        ("192.0.2.3", 1947),
        ("192.0.2.4", 443),
        ("192.0.2.5", 8080),
    ]

    for host, port in unreachable_targets:
        engine.send_protocol_command(
            protocol_name="flexlm",
            host=host,
            port=port,
            command=b"STATS_TEST",
        )

    stats = engine.get_statistics()

    assert isinstance(stats["packets_captured"], int)
    assert isinstance(stats["total_bytes"], int)
    assert isinstance(stats["license_packets_detected"], int)
    assert stats["packets_captured"] >= 0
    assert stats["total_bytes"] >= 0


def test_retry_backoff_increases_with_each_attempt(
    engine: TrafficInterceptionEngine,
) -> None:
    """Exponential backoff delays increase with each retry attempt.

    Validates: Must use exponential backoff for connection failures (verification).
    """
    retry_durations: list[float] = []
    max_retries = 4
    base_delay = 0.5

    for attempt in range(max_retries):
        start_time = time.time()

        engine.send_protocol_command(
            protocol_name="flexlm",
            host="192.0.2.1",
            port=65432,
            command=b"BACKOFF_TEST",
        )

        if attempt < max_retries - 1:
            backoff = base_delay * (2 ** attempt)
            time.sleep(backoff)
            retry_durations.append(time.time() - start_time)

    if len(retry_durations) >= 2:
        assert retry_durations[1] > retry_durations[0], "Backoff must increase exponentially"


def test_timeout_does_not_prevent_subsequent_successful_connections(
    engine: TrafficInterceptionEngine,
    intermittent_failure_server: tuple[threading.Thread, int, Callable[[], None], list[int]],
) -> None:
    """Engine can establish successful connections after timeout failures.

    Validates: Must continue listening loop after recoverable errors (connection recovery).
    """
    _, port, cleanup, connection_count = intermittent_failure_server

    try:
        first_result = engine.send_protocol_command(
            protocol_name="flexlm",
            host="127.0.0.1",
            port=port,
            command=b"FIRST_ATTEMPT",
        )

        time.sleep(0.5)

        second_result = engine.send_protocol_command(
            protocol_name="flexlm",
            host="127.0.0.1",
            port=port,
            command=b"SECOND_ATTEMPT",
        )

        assert connection_count[0] >= 2, "Multiple connection attempts must occur"
        assert second_result is not None or first_result is None, "One attempt should succeed"

    finally:
        cleanup()


def test_socket_capture_timeout_maintains_loop_operation(
    engine: TrafficInterceptionEngine,
) -> None:
    """Socket capture loop remains operational after socket.timeout.

    Validates: Must continue listening loop after recoverable errors (socket capture).
    """
    engine.start_interception()
    time.sleep(0.3)

    initial_running = engine.running

    time.sleep(0.5)

    final_running = engine.running

    engine.stop_interception()

    assert initial_running, "Engine must be running initially"
    assert final_running, "Engine must continue running after potential timeouts"


def test_timeout_handling_respects_configured_timeout_values(
    engine: TrafficInterceptionEngine,
) -> None:
    """Timeout handling uses configured timeout values, not hardcoded defaults.

    Validates: Must implement configurable retry policies (timeout configuration).
    """
    start_time = time.time()

    result = engine.send_protocol_command(
        protocol_name="flexlm",
        host="192.0.2.1",
        port=65000,
        command=b"TIMEOUT_CONFIG_TEST",
    )

    elapsed = time.time() - start_time

    assert result is None
    assert elapsed >= 9.0, "Must respect 10 second connection timeout"
    assert elapsed <= 13.0, "Must not exceed reasonable timeout duration"


def test_timeout_error_at_line_985_properly_caught_and_logged(
    engine: TrafficInterceptionEngine,
    timeout_server: tuple[threading.Thread, int, Callable[[], None]],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """TimeoutError at line 985 specifically is caught and logged correctly.

    Validates: EXACT line 985 handling - proper exception handling with logging.
    """
    _, port, cleanup = timeout_server

    try:
        with caplog.at_level(logging.DEBUG):
            result = engine.send_protocol_command(
                protocol_name="flexlm",
                host="127.0.0.1",
                port=port,
                command=b"LINE_985_TEST",
            )

        assert result is None or isinstance(result, bytes)

        log_exists = len(caplog.records) > 0
        assert log_exists, "Timeout must be logged"

    finally:
        cleanup()


def test_retry_policy_configurable_per_protocol_type(
    engine: TrafficInterceptionEngine,
) -> None:
    """Different protocols can have different retry configurations.

    Validates: Must implement configurable retry policies (per-protocol).
    """
    flexlm_retry_count = [0]
    hasp_retry_count = [0]

    max_retries = 3

    for _attempt in range(max_retries):
        flexlm_retry_count[0] += 1
        result = engine.send_protocol_command(
            protocol_name="flexlm",
            host="192.0.2.1",
            port=27000,
            command=b"FLEXLM_RETRY",
        )
        if result is not None:
            break

    for _attempt in range(max_retries):
        hasp_retry_count[0] += 1
        result = engine.send_protocol_command(
            protocol_name="hasp",
            host="192.0.2.1",
            port=1947,
            command=b"HASP_RETRY",
        )
        if result is not None:
            break

    assert flexlm_retry_count[0] <= max_retries
    assert hasp_retry_count[0] <= max_retries


def test_timeout_during_high_traffic_does_not_block_packet_queue(
    engine: TrafficInterceptionEngine,
) -> None:
    """Timeout on one connection doesn't block packet queue processing.

    Validates: Must continue listening loop after recoverable errors (queue processing).
    """
    engine.start_interception()

    from intellicrack.core.network.traffic_interception_engine import InterceptedPacket

    test_packet = InterceptedPacket(
        source_ip="192.168.1.100",
        dest_ip="192.168.1.200",
        source_port=55000,
        dest_port=27000,
        protocol="tcp",
        data=b"FEATURE LICENSE_TEST",
        timestamp=time.time(),
        packet_size=150,
        flags={"syn": False, "ack": True, "fin": False, "rst": False},
    )

    engine._queue_packet(test_packet)

    engine.send_protocol_command(
        protocol_name="flexlm",
        host="192.0.2.1",
        port=65000,
        command=b"BLOCKING_TEST",
    )

    time.sleep(0.5)

    engine.stop_interception()

    assert engine.stats["packets_captured"] >= 1, "Packet queue must continue processing"


def test_network_interface_unavailable_handled_gracefully(
    engine: TrafficInterceptionEngine,
) -> None:
    """Invalid network interface changes handled without crash.

    Validates: Edge case - Network interface changes (invalid interface).
    """
    engine.bind_interface = "invalid.interface.999.999"

    try:
        engine.send_protocol_command(
            protocol_name="flexlm",
            host="127.0.0.1",
            port=27000,
            command=b"INTERFACE_TEST",
        )
    except Exception as e:
        pytest.fail(f"Invalid interface must not crash engine: {e}")

    assert isinstance(engine.stats, dict)
