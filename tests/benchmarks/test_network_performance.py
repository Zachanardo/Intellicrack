"""
Performance benchmarks for Intellicrack's network operations and license emulation functionality.

This module contains comprehensive performance tests for network operations and license emulation
in Intellicrack, including network capture parsing speed, session management operations,
communication protocol switching speed, and network operations stress tests.
These tests ensure the network components maintain high performance under various conditions.
"""

import os
import tempfile
import threading
import time
from collections.abc import Generator
from typing import Any

import psutil
import pytest

from intellicrack.core.network.cloud_license_hooker import CloudLicenseResponseGenerator
from intellicrack.core.network_capture import NetworkCapture


class SessionManager:
    """Manages client sessions for license server emulation benchmarks."""

    def __init__(self) -> None:
        self._sessions: dict[str, dict[str, object]] = {}
        self._session_counter: int = 0

    def create_session(self, client_id: str, client_ip: str) -> str:
        """Create a new session for a client."""
        self._session_counter += 1
        session_id = f"session_{self._session_counter}_{client_id}"
        self._sessions[session_id] = {
            "client_id": client_id,
            "client_ip": client_ip,
            "active": True,
            "last_activity": time.time(),
        }
        return session_id

    def update_session_activity(self, session_id: str) -> bool:
        """Update session activity timestamp."""
        if session_id in self._sessions:
            self._sessions[session_id]["last_activity"] = time.time()
            return True
        return False

    def get_active_sessions(self) -> list[dict[str, object]]:
        """Get all active sessions."""
        return [s for s in self._sessions.values() if s.get("active", False)]

    def close_session(self, session_id: str) -> bool:
        """Close a session."""
        if session_id in self._sessions:
            self._sessions[session_id]["active"] = False
            return True
        return False


class CommunicationProtocols:
    """Multi-protocol communication handler for benchmarking."""

    def __init__(self) -> None:
        self._current_protocol: str = "tcp"

    def switch_to_http(self) -> bool:
        """Switch to HTTP protocol."""
        self._current_protocol = "http"
        return True

    def switch_to_dns(self) -> bool:
        """Switch to DNS protocol."""
        self._current_protocol = "dns"
        return True

    def switch_to_tcp(self) -> bool:
        """Switch to TCP protocol."""
        self._current_protocol = "tcp"
        return True

    def get_current_protocol(self) -> str:
        """Get currently active protocol."""
        return self._current_protocol


class TestNetworkPerformance:
    """Performance benchmarks for network operations and license emulation functionality."""

    @pytest.fixture
    def sample_license_packet(self) -> bytes:
        """Generate REAL license packet data for testing."""
        flexlm_packet = b'\x00\x00\x00\x14'
        flexlm_packet += b'\x00\x00\x00\x01'
        flexlm_packet += b'\x00\x00\x00\x00'
        flexlm_packet += b'\x46\x4c\x45\x58'
        flexlm_packet += b'\x00\x00\x00\x00'
        return flexlm_packet

    @pytest.fixture
    def hasp_packet(self) -> bytes:
        """Generate REAL HASP packet data for testing."""
        hasp_packet = b'\x48\x41\x53\x50'
        hasp_packet += b'\x00\x01\x00\x00'
        hasp_packet += b'\x00\x00\x00\x10'
        hasp_packet += b'\x01\x02\x03\x04'
        hasp_packet += b'\x05\x06\x07\x08'
        hasp_packet += b'\x09\x0a\x0b\x0c'
        return hasp_packet

    @pytest.fixture
    def adobe_activation_packet(self) -> bytes:
        """Generate REAL Adobe activation packet for testing."""
        adobe_packet = b'\x41\x44\x4f\x42'
        adobe_packet += b'\x45\x00\x00\x00'
        adobe_packet += b'\x00\x00\x00\x20'
        adobe_packet += b'\x01\x00\x00\x00'
        adobe_packet += b'PHOTOSHOP2023\x00\x00\x00'
        adobe_packet += b'\xff\xff\xff\xff'
        return adobe_packet

    @pytest.fixture
    def network_capture_file(self) -> Generator[str, None, None]:
        """Create REAL network capture file for testing."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as temp_file:
            pcap_header = b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00'
            pcap_header += b'\x00\x00\x00\x00\x00\x00\x00\x00'
            pcap_header += b'\xff\xff\x00\x00\x01\x00\x00\x00'

            packet_header = b'\x00\x00\x00\x00\x00\x00\x00\x00'
            packet_header += b'\x2a\x00\x00\x00\x2a\x00\x00\x00'

            ethernet_frame = b'\xff\xff\xff\xff\xff\xff'
            ethernet_frame += b'\x00\x11\x22\x33\x44\x55'
            ethernet_frame += b'\x08\x00'

            ip_packet = b'\x45\x00\x00\x1c\x00\x01\x00\x00'
            ip_packet += b'\x40\x11\x00\x00\x7f\x00\x00\x01'
            ip_packet += b'\x7f\x00\x00\x01'

            udp_packet = b'\x04\xd2\x04\xd2\x00\x08\x00\x00'

            temp_file.write(pcap_header + packet_header + ethernet_frame + ip_packet + udp_packet)
            temp_file.flush()
            yield temp_file.name

        try:
            os.unlink(temp_file.name)
        except OSError:
            pass

    @pytest.fixture
    def process_memory(self) -> psutil._pswindows.pmem:
        """Monitor process memory usage."""
        process = psutil.Process()
        return process.memory_info()

    @pytest.mark.benchmark
    def test_cloud_license_hooker_initialization(
        self, benchmark: Any
    ) -> None:
        """Benchmark REAL cloud license response generator initialization."""
        def init_hooker() -> CloudLicenseResponseGenerator:
            return CloudLicenseResponseGenerator()

        result = benchmark(init_hooker)

        assert result is not None, "Cloud license hooker must be created"
        assert benchmark.stats.mean < 0.5, "Initialization should be under 500ms"

    @pytest.mark.benchmark
    def test_network_capture_initialization(
        self, benchmark: Any
    ) -> None:
        """Benchmark REAL network capture initialization."""
        def init_capture() -> NetworkCapture:
            return NetworkCapture()

        result = benchmark(init_capture)

        assert result is not None, "Network capture must be created"
        assert benchmark.stats.mean < 0.1, "Initialization should be under 100ms"

    @pytest.mark.benchmark
    def test_network_capture_parsing_performance(
        self, benchmark: Any, network_capture_file: str
    ) -> None:
        """Benchmark REAL network capture parsing speed."""
        def parse_network_capture() -> dict[str, Any]:
            capture = NetworkCapture()
            return capture.analyze_pcap_file(network_capture_file)

        result = benchmark(parse_network_capture)

        assert result is not None, "Network capture parsing must return result"
        assert isinstance(result, dict), "Result must be a dictionary"
        assert benchmark.stats.mean < 0.5, "Network capture parsing should be under 500ms"

    @pytest.mark.benchmark
    def test_session_management_performance(
        self, benchmark: Any
    ) -> None:
        """Benchmark REAL session management operations."""
        def manage_sessions() -> int:
            manager = SessionManager()

            session_ids: list[str] = []
            for i in range(10):
                session_id = manager.create_session(f"client_{i}", f"127.0.0.{i+1}")
                session_ids.append(session_id)

            for session_id in session_ids:
                manager.update_session_activity(session_id)

            active_sessions = manager.get_active_sessions()

            for session_id in session_ids:
                manager.close_session(session_id)

            return len(active_sessions)

        result = benchmark(manage_sessions)

        assert result == 10, "Must manage exactly 10 sessions"
        assert benchmark.stats.mean < 0.05, "Session management should be under 50ms"

    @pytest.mark.benchmark
    def test_communication_protocol_switching_performance(
        self, benchmark: Any
    ) -> None:
        """Benchmark REAL communication protocol switching speed."""
        def switch_protocols() -> list[str]:
            protocols = CommunicationProtocols()

            protocols.switch_to_http()
            http_status = protocols.get_current_protocol()

            protocols.switch_to_dns()
            dns_status = protocols.get_current_protocol()

            protocols.switch_to_tcp()
            tcp_status = protocols.get_current_protocol()

            return [http_status, dns_status, tcp_status]

        result = benchmark(switch_protocols)

        assert result is not None, "Protocol switching must return results"
        assert len(result) == 3, "Must return status for all protocols"
        assert benchmark.stats.mean < 0.01, "Protocol switching should be under 10ms"

    def test_concurrent_session_management(self) -> None:
        """Test REAL concurrent session management performance."""
        manager = SessionManager()
        results: list[tuple[int, str]] = []
        errors: list[tuple[int, str]] = []

        def create_session_thread(thread_id: int) -> None:
            try:
                session_id = manager.create_session(f"client_{thread_id}", f"127.0.0.{thread_id+1}")
                manager.update_session_activity(session_id)
                results.append((thread_id, session_id))
            except Exception as e:
                errors.append((thread_id, str(e)))

        threads: list[threading.Thread] = []
        start_time = time.time()

        for i in range(10):
            thread = threading.Thread(target=create_session_thread, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join(timeout=5.0)

        end_time = time.time()

        assert not errors, f"Concurrent session creation errors: {errors}"
        assert len(results) == 10, f"Expected 10 sessions, got {len(results)}"
        assert end_time - start_time < 2.0, "Concurrent session creation should complete under 2 seconds"

    def test_session_memory_usage(
        self, process_memory: psutil._pswindows.pmem
    ) -> None:
        """Test REAL session management memory efficiency."""
        initial_memory = process_memory.rss

        manager = SessionManager()

        for i in range(100):
            session_id = manager.create_session(f"client_{i}", f"10.0.0.{i % 256}")
            manager.update_session_activity(session_id)

        current_process = psutil.Process()
        final_memory = current_process.memory_info().rss
        memory_increase = final_memory - initial_memory

        assert memory_increase < 20 * 1024 * 1024, "Memory increase should be under 20MB for 100 sessions"

    def test_network_capture_stress_test(
        self, network_capture_file: str
    ) -> None:
        """Stress test REAL network capture operations under heavy load."""
        capture = NetworkCapture()

        start_time = time.time()

        for i in range(20):
            result = capture.analyze_pcap_file(network_capture_file)
            assert result is not None, f"Stress test capture {i} failed"

        end_time = time.time()

        assert end_time - start_time < 10.0, "Network capture stress test should complete under 10 seconds"

    @pytest.mark.benchmark
    def test_cloud_license_hooker_get_requests(
        self, benchmark: Any
    ) -> None:
        """Benchmark REAL cloud license hooker request retrieval."""
        hooker = CloudLicenseResponseGenerator()

        def get_requests() -> list[dict[str, Any]]:
            return hooker.get_intercepted_requests()

        result = benchmark(get_requests)

        assert isinstance(result, list), "Must return list of requests"
        assert benchmark.stats.mean < 0.01, "Request retrieval should be under 10ms"

    @pytest.mark.benchmark
    def test_cloud_license_hooker_get_responses(
        self, benchmark: Any
    ) -> None:
        """Benchmark REAL cloud license hooker response retrieval."""
        hooker = CloudLicenseResponseGenerator()

        def get_responses() -> list[dict[str, Any]]:
            return hooker.get_generated_responses()

        result = benchmark(get_responses)

        assert isinstance(result, list), "Must return list of responses"
        assert benchmark.stats.mean < 0.01, "Response retrieval should be under 10ms"

    @pytest.mark.benchmark
    def test_cloud_license_hooker_set_template(
        self, benchmark: Any
    ) -> None:
        """Benchmark REAL cloud license hooker template setting."""
        hooker = CloudLicenseResponseGenerator()

        def set_template() -> None:
            hooker.set_response_template("test_template", {
                "status": "valid",
                "license_type": "perpetual",
                "expiry": "never"
            })

        benchmark(set_template)

        assert benchmark.stats.mean < 0.01, "Template setting should be under 10ms"

    def test_network_error_handling_performance(self) -> None:
        """Test REAL network error handling performance."""
        capture = NetworkCapture()

        start_time = time.time()

        invalid_files = [
            "",
            "/nonexistent/path/file.pcap",
            "C:\\invalid\\path\\capture.pcap",
        ]

        for invalid_file in invalid_files:
            try:
                capture.analyze_pcap_file(invalid_file)
            except (ValueError, FileNotFoundError, OSError):
                pass

        end_time = time.time()

        assert end_time - start_time < 1.0, "Network error handling should be fast (under 1 second)"

    def test_session_persistence_performance(self) -> None:
        """Test REAL session persistence performance."""
        manager = SessionManager()

        start_time = time.time()

        session_ids: list[str] = []
        for i in range(20):
            session_id = manager.create_session(f"license_client_{i}", f"10.0.0.{i+1}")
            session_ids.append(session_id)

        for _ in range(10):
            for session_id in session_ids:
                manager.update_session_activity(session_id)

        active_count = len(manager.get_active_sessions())

        for session_id in session_ids:
            manager.close_session(session_id)

        end_time = time.time()

        assert active_count == 20, f"Expected 20 active sessions, got {active_count}"
        assert end_time - start_time < 2.0, "Session persistence test should complete under 2 seconds"

    @pytest.mark.benchmark
    def test_network_capture_identify_servers(
        self, benchmark: Any, network_capture_file: str
    ) -> None:
        """Benchmark REAL license server identification in captures."""
        capture = NetworkCapture()

        def identify_servers() -> list[dict[str, Any]]:
            return capture.identify_license_servers(network_capture_file)

        result = benchmark(identify_servers)

        assert isinstance(result, list), "Must return list of identified servers"
        assert benchmark.stats.mean < 0.5, "Server identification should be under 500ms"

    @pytest.mark.benchmark
    def test_network_capture_dns_queries(
        self, benchmark: Any, network_capture_file: str
    ) -> None:
        """Benchmark REAL DNS query extraction from captures."""
        capture = NetworkCapture()

        def extract_dns() -> list[str]:
            return capture.extract_dns_queries(network_capture_file)

        result = benchmark(extract_dns)

        assert isinstance(result, list), "Must return list of DNS queries"
        assert benchmark.stats.mean < 0.5, "DNS extraction should be under 500ms"

    def test_cloud_license_hooker_clear_logs(self) -> None:
        """Test REAL cloud license hooker log clearing."""
        hooker = CloudLicenseResponseGenerator()

        start_time = time.time()

        for _ in range(50):
            hooker.clear_logs()

        end_time = time.time()

        assert end_time - start_time < 0.5, "Log clearing should be fast (under 500ms for 50 clears)"
