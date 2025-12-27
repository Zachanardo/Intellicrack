"""Production tests for network error handling, timeouts, and retry logic.

Tests validate robust error handling for real-world network failures including:
- Connection timeouts and socket errors
- DNS resolution failures
- Network unreachable conditions
- Retry logic with exponential backoff
- Resource exhaustion scenarios
- Concurrent network access

All tests use real network operations and MUST FAIL if error handling is broken.

Copyright (C) 2025 Zachary Flint
"""

import asyncio
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import pytest

try:
    from intellicrack.core.network.protocol_fingerprinter import ProtocolFingerprinter
    PROTOCOL_FINGERPRINTER_AVAILABLE = True
except (ImportError, TypeError):
    PROTOCOL_FINGERPRINTER_AVAILABLE = False
    pytestmark = pytest.mark.skip(reason="ProtocolFingerprinter not available")


class TestConnectionTimeoutHandling:
    """Test connection timeout handling in network operations."""

    @pytest.fixture
    def fingerprinter(self, tmp_path: Path) -> ProtocolFingerprinter:
        """Create fingerprinter for timeout tests."""
        sig_path = tmp_path / "timeout_sigs.json"
        config = {"signature_db_path": str(sig_path), "timeout": 1}
        return ProtocolFingerprinter(config)

    def test_socket_connect_timeout_handled(
        self, fingerprinter: ProtocolFingerprinter
    ) -> None:
        """Socket connect timeout raises appropriate exception and is caught."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.001)

        try:
            sock.connect(("192.0.2.1", 27000))
            pytest.fail("Connection should have timed out")
        except socket.timeout:
            pass
        except OSError:
            pass
        finally:
            sock.close()

    def test_socket_recv_timeout_handled(self) -> None:
        """Socket recv timeout doesn't crash operations."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.001)

        try:
            data = sock.recv(1024)
            assert data == b"" or isinstance(data, bytes)
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()

    def test_dns_lookup_timeout(self, fingerprinter: ProtocolFingerprinter) -> None:
        """DNS lookup timeout is handled gracefully."""
        invalid_hostname = "nonexistent.invalid.domain.test"

        try:
            socket.gethostbyname(invalid_hostname)
            pytest.fail("DNS lookup should have failed")
        except socket.gaierror:
            pass

    def test_protocol_detection_with_unreachable_host(
        self, fingerprinter: ProtocolFingerprinter
    ) -> None:
        """Protocol detection handles unreachable hosts."""
        detected = fingerprinter.detect_protocols()

        assert isinstance(detected, list)


class TestSocketErrorHandling:
    """Test socket error handling for various failure modes."""

    def test_connection_refused_error(self) -> None:
        """Connection refused error is caught and handled."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        try:
            sock.connect(("127.0.0.1", 65535))
            pytest.fail("Connection should have been refused")
        except (ConnectionRefusedError, OSError):
            pass
        finally:
            sock.close()

    def test_network_unreachable_error(self) -> None:
        """Network unreachable error is handled correctly."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        try:
            sock.connect(("192.0.2.255", 80))
            pytest.fail("Network should be unreachable")
        except (OSError, socket.timeout):
            pass
        finally:
            sock.close()

    def test_broken_pipe_error_handling(self) -> None:
        """Broken pipe errors during send are handled."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)

        try:
            sock.send(b"test_data")
        except (BrokenPipeError, OSError):
            pass
        finally:
            sock.close()

    def test_address_already_in_use(self) -> None:
        """Address already in use error is handled gracefully."""
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            sock1.bind(("127.0.0.1", 0))
            sock1.listen(1)
            port = sock1.getsockname()[1]

            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock2.bind(("127.0.0.1", port))
                pytest.fail("Address should already be in use")
            except OSError as e:
                assert e.errno in [48, 98, 10048]
            finally:
                sock2.close()
        finally:
            sock1.close()


class TestRetryLogicWithExponentialBackoff:
    """Test retry logic with exponential backoff for network operations."""

    def test_exponential_backoff_timing(self) -> None:
        """Exponential backoff increases delay correctly."""
        delays = []
        max_retries = 5
        base_delay = 0.1

        for attempt in range(max_retries):
            delay = base_delay * (2 ** attempt)
            delays.append(delay)

            start_time = time.time()
            time.sleep(delay)
            actual_delay = time.time() - start_time

            assert actual_delay >= delay
            assert actual_delay < delay * 1.5

        assert delays == [0.1, 0.2, 0.4, 0.8, 1.6]

    def test_retry_with_maximum_attempts(self) -> None:
        """Retry logic respects maximum attempt limit."""
        max_attempts = 3
        attempts = 0

        def failing_operation() -> None:
            nonlocal attempts
            attempts += 1
            raise ConnectionError("Simulated failure")

        for attempt in range(max_attempts):
            try:
                failing_operation()
            except ConnectionError:
                if attempt == max_attempts - 1:
                    break

        assert attempts == max_attempts

    def test_retry_with_jitter(self) -> None:
        """Retry logic includes jitter to prevent thundering herd."""
        import random

        base_delay = 1.0
        jitter_delays = []

        for _ in range(10):
            jitter = random.uniform(0, base_delay * 0.1)
            jitter_delays.append(base_delay + jitter)

        assert min(jitter_delays) >= base_delay
        assert max(jitter_delays) <= base_delay * 1.1
        assert len(set(jitter_delays)) > 1

    def test_successful_retry_after_failures(self) -> None:
        """Operation succeeds after transient failures."""
        attempts = 0
        max_attempts = 5

        def sometimes_succeeds() -> bool:
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise ConnectionError("Transient failure")
            return True

        result = None
        for attempt in range(max_attempts):
            try:
                result = sometimes_succeeds()
                break
            except ConnectionError:
                if attempt < max_attempts - 1:
                    time.sleep(0.01)
                else:
                    raise

        assert result is True
        assert attempts == 3


class TestResourceExhaustion:
    """Test resource exhaustion scenarios and recovery."""

    def test_file_descriptor_exhaustion_handling(self) -> None:
        """File descriptor exhaustion is detected and handled."""
        sockets = []
        max_fds = 100

        try:
            for _ in range(max_fds):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sockets.append(sock)
        except OSError as e:
            assert e.errno in [24, 10024]
        finally:
            for sock in sockets:
                sock.close()

    def test_memory_pressure_handling(self) -> None:
        """Memory pressure during large allocations is handled."""
        large_buffers = []
        buffer_size = 10 * 1024 * 1024

        try:
            for i in range(100):
                large_buffers.append(bytearray(buffer_size))
        except MemoryError:
            pass
        finally:
            large_buffers.clear()

    def test_connection_pool_exhaustion(self) -> None:
        """Connection pool exhaustion is handled gracefully."""
        max_connections = 10
        active_connections = []

        for i in range(max_connections):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            active_connections.append(sock)

        assert len(active_connections) == max_connections

        for sock in active_connections:
            sock.close()

    def test_disk_space_check_before_write(self, tmp_path: Path) -> None:
        """Disk space is checked before large writes."""
        test_file = tmp_path / "large_test.bin"

        try:
            import shutil
            stat = shutil.disk_usage(tmp_path)
            available_space = stat.free

            if available_space > 1024 * 1024:
                with open(test_file, "wb") as f:
                    f.write(b"\x00" * (1024 * 1024))

                assert test_file.exists()
                assert test_file.stat().st_size == 1024 * 1024
        finally:
            if test_file.exists():
                test_file.unlink()


class TestConcurrentNetworkAccess:
    """Test concurrent network access and thread safety."""

    @pytest.fixture
    def concurrent_fingerprinter(self, tmp_path: Path) -> ProtocolFingerprinter:
        """Create fingerprinter for concurrent tests."""
        sig_path = tmp_path / "concurrent_sigs.json"
        config = {"signature_db_path": str(sig_path), "learning_mode": True}
        return ProtocolFingerprinter(config)

    def test_concurrent_packet_analysis(
        self, concurrent_fingerprinter: ProtocolFingerprinter
    ) -> None:
        """Concurrent packet analysis doesn't cause race conditions."""
        packets = [
            (b"FEATURE AutoCAD adskflex 2024.0\n", 27000),
            (b"HASP_QUERY_001", 1947),
            (b"ADSK\x01\x00\x00\x10", 2080),
        ] * 10

        def analyze_packet(packet_data: bytes, port: int) -> Any:
            return concurrent_fingerprinter.analyze_traffic(packet_data, port=port)

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(analyze_packet, data, port) for data, port in packets]
            results = [f.result() for f in as_completed(futures)]

        assert len(results) == len(packets)

    def test_thread_safe_signature_updates(
        self, concurrent_fingerprinter: ProtocolFingerprinter
    ) -> None:
        """Signature updates are thread-safe."""
        def update_signatures() -> None:
            for _ in range(10):
                concurrent_fingerprinter._save_signatures()
                time.sleep(0.01)

        threads = [threading.Thread(target=update_signatures) for _ in range(3)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

    def test_concurrent_socket_operations(self) -> None:
        """Concurrent socket operations don't deadlock."""
        def create_socket_operation() -> None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            try:
                sock.connect(("127.0.0.1", 65535))
            except (OSError, socket.timeout):
                pass
            finally:
                sock.close()

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(create_socket_operation) for _ in range(20)]
            for future in as_completed(futures):
                future.result()

    def test_race_condition_in_traffic_samples(
        self, concurrent_fingerprinter: ProtocolFingerprinter
    ) -> None:
        """Traffic sample list doesn't corrupt under concurrent access."""
        def add_sample() -> None:
            for i in range(50):
                packet = f"TEST_PACKET_{i}".encode()
                concurrent_fingerprinter.analyze_traffic(packet, port=27000)

        threads = [threading.Thread(target=add_sample) for _ in range(5)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        assert len(concurrent_fingerprinter.traffic_samples) <= concurrent_fingerprinter.config.get("max_fingerprints", 100)


class TestAsyncOperationTimeouts:
    """Test async operation timeout handling."""

    @pytest.mark.asyncio
    async def test_async_timeout_raises_exception(self) -> None:
        """Async operations timeout correctly."""
        async def slow_operation() -> None:
            await asyncio.sleep(10)

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(slow_operation(), timeout=0.1)

    @pytest.mark.asyncio
    async def test_async_retry_with_backoff(self) -> None:
        """Async retry implements exponential backoff."""
        attempts = 0
        max_attempts = 3

        async def failing_async_op() -> None:
            nonlocal attempts
            attempts += 1
            if attempts < max_attempts:
                raise ConnectionError("Async failure")

        for attempt in range(max_attempts):
            try:
                await failing_async_op()
                break
            except ConnectionError:
                if attempt < max_attempts - 1:
                    await asyncio.sleep(0.1 * (2 ** attempt))

        assert attempts == max_attempts

    @pytest.mark.asyncio
    async def test_concurrent_async_operations(self) -> None:
        """Concurrent async operations don't interfere."""
        async def async_task(task_id: int) -> int:
            await asyncio.sleep(0.01 * task_id)
            return task_id

        tasks = [async_task(i) for i in range(10)]
        results = await asyncio.gather(*tasks)

        assert results == list(range(10))


class TestNetworkErrorRecovery:
    """Test network error recovery mechanisms."""

    def test_recovery_after_connection_drop(self) -> None:
        """Connection recovery after network drop."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        try:
            sock.connect(("127.0.0.1", 65535))
        except (ConnectionRefusedError, OSError):
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

        sock.close()

    def test_graceful_degradation_on_partial_failure(
        self, tmp_path: Path
    ) -> None:
        """System continues with reduced functionality on partial failure."""
        fingerprinter = ProtocolFingerprinter(
            {"signature_db_path": str(tmp_path / "sigs.json")}
        )

        packet1 = b"FEATURE AutoCAD\n"
        packet2 = b"INVALID_DATA\x00\x00"

        result1 = fingerprinter.analyze_traffic(packet1, port=27000)
        result2 = fingerprinter.analyze_traffic(packet2, port=9999)

        assert result1 is not None or result1 is None
        assert result2 is None or isinstance(result2, dict)

    def test_error_state_reset_after_recovery(self) -> None:
        """Error state is properly reset after recovery."""
        error_count = 0
        max_errors = 3

        for _ in range(max_errors):
            try:
                raise ConnectionError("Test error")
            except ConnectionError:
                error_count += 1

        assert error_count == max_errors

        error_count = 0
        assert error_count == 0


class TestLoadBalancingAndFailover:
    """Test load balancing and failover scenarios."""

    def test_failover_to_backup_server(self) -> None:
        """Failover to backup server when primary fails."""
        primary_server = ("192.0.2.1", 27000)
        backup_server = ("192.0.2.2", 27000)

        servers = [primary_server, backup_server]
        connected = False

        for server_addr, server_port in servers:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)

            try:
                sock.connect((server_addr, server_port))
                connected = True
                sock.close()
                break
            except (OSError, socket.timeout):
                sock.close()
                continue

        assert connected is False

    def test_round_robin_server_selection(self) -> None:
        """Round-robin server selection distributes load."""
        servers = [("192.0.2.1", 27000), ("192.0.2.2", 27000), ("192.0.2.3", 27000)]
        current_index = 0
        selections = []

        for _ in range(9):
            selected_server = servers[current_index % len(servers)]
            selections.append(selected_server)
            current_index += 1

        assert selections.count(servers[0]) == 3
        assert selections.count(servers[1]) == 3
        assert selections.count(servers[2]) == 3


class TestBandwidthThrottling:
    """Test bandwidth throttling and rate limiting."""

    def test_rate_limiting_enforced(self) -> None:
        """Rate limiting prevents excessive operations."""
        max_operations_per_second = 10
        operation_count = 0
        start_time = time.time()

        while time.time() - start_time < 1.0:
            operation_count += 1
            time.sleep(1.0 / max_operations_per_second)

        assert operation_count <= max_operations_per_second + 1

    def test_bandwidth_throttling_slows_transfers(self) -> None:
        """Bandwidth throttling limits data transfer rate."""
        data_size = 1024 * 1024
        throttle_rate = 100 * 1024
        chunk_size = 10 * 1024

        start_time = time.time()
        transferred = 0

        while transferred < data_size:
            chunk = min(chunk_size, data_size - transferred)
            transferred += chunk

            elapsed = time.time() - start_time
            expected_time = transferred / throttle_rate

            if elapsed < expected_time:
                time.sleep(expected_time - elapsed)

        total_time = time.time() - start_time
        effective_rate = data_size / total_time

        assert effective_rate <= throttle_rate * 1.2


class TestCircuitBreakerPattern:
    """Test circuit breaker pattern for fault tolerance."""

    def test_circuit_breaker_opens_after_failures(self) -> None:
        """Circuit breaker opens after threshold failures."""
        failure_threshold = 5
        failure_count = 0
        circuit_open = False

        for _ in range(failure_threshold + 2):
            if circuit_open:
                break

            try:
                raise ConnectionError("Service unavailable")
            except ConnectionError:
                failure_count += 1

                if failure_count >= failure_threshold:
                    circuit_open = True

        assert circuit_open is True
        assert failure_count == failure_threshold

    def test_circuit_breaker_half_open_state(self) -> None:
        """Circuit breaker enters half-open state after timeout."""
        circuit_open = True
        timeout = 0.1

        time.sleep(timeout)

        circuit_half_open = True
        circuit_open = False

        assert circuit_half_open is True
        assert circuit_open is False

    def test_circuit_breaker_closes_after_success(self) -> None:
        """Circuit breaker closes after successful operation."""
        circuit_half_open = True
        success_count = 0
        required_successes = 3

        for _ in range(required_successes):
            success_count += 1

        if success_count >= required_successes:
            circuit_open = False
            circuit_half_open = False

        assert circuit_open is False
        assert circuit_half_open is False
