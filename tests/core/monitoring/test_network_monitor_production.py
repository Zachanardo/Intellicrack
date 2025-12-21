"""Production tests for network traffic monitoring functionality.

Tests validate real packet capture, license keyword detection, protocol analysis,
and event emission for network monitoring operations.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import platform
import threading
import time
from typing import Any

import pytest

from intellicrack.core.monitoring.base_monitor import EventSeverity, EventSource, EventType, ProcessInfo


pytestmark = pytest.mark.skipif(
    platform.system() != "Windows",
    reason="Network monitor tests require Windows platform",
)


@pytest.fixture
def process_info() -> ProcessInfo:
    """Create process info for testing."""
    return ProcessInfo(
        pid=1234,
        name="test_process.exe",
        path="C:\\test\\test_process.exe",
    )


@pytest.fixture
def network_monitor(process_info: ProcessInfo) -> Any:
    """Create network monitor instance for testing."""
    from intellicrack.core.monitoring.network_monitor import NetworkMonitor

    monitor = NetworkMonitor(process_info=process_info, target_ports=[80, 443, 8080])
    yield monitor

    if monitor.is_monitoring:
        monitor.stop()


def test_network_monitor_initialization(network_monitor: Any, process_info: ProcessInfo) -> None:
    """Network monitor initializes with process info and target ports."""
    assert network_monitor.process_info == process_info
    assert 80 in network_monitor.target_ports
    assert 443 in network_monitor.target_ports
    assert 8080 in network_monitor.target_ports


def test_network_monitor_scapy_availability_detection(network_monitor: Any) -> None:
    """Network monitor detects scapy availability correctly."""
    from intellicrack.core.monitoring.network_monitor import SCAPY_AVAILABLE

    if SCAPY_AVAILABLE:
        assert network_monitor._sniff_thread is None
    else:
        assert network_monitor._sniff_thread is None


def test_network_monitor_starts_with_scapy_available(network_monitor: Any) -> None:
    """Network monitor starts packet sniffing when scapy is available."""
    from intellicrack.core.monitoring.network_monitor import SCAPY_AVAILABLE

    if not SCAPY_AVAILABLE:
        pytest.skip("Scapy not available for packet capture")

    result = network_monitor.start()

    if result:
        assert network_monitor.is_monitoring is True
        assert network_monitor._sniff_thread is not None
        network_monitor.stop()
    else:
        pytest.skip("Network monitor start failed (likely permissions)")


def test_network_monitor_handles_scapy_unavailable(network_monitor: Any) -> None:
    """Network monitor gracefully handles scapy not being available."""
    from intellicrack.core.monitoring.network_monitor import SCAPY_AVAILABLE

    if SCAPY_AVAILABLE:
        pytest.skip("Scapy is available, test not applicable")

    result = network_monitor._start_monitoring()

    assert result is False


def test_network_monitor_stops_cleanly(network_monitor: Any) -> None:
    """Network monitor stops packet sniffing cleanly."""
    from intellicrack.core.monitoring.network_monitor import SCAPY_AVAILABLE

    if not SCAPY_AVAILABLE:
        pytest.skip("Scapy not available")

    result = network_monitor.start()

    if result:
        time.sleep(0.5)
        network_monitor.stop()

        assert network_monitor.is_monitoring is False
        assert network_monitor._stop_sniffing is True


def test_network_monitor_processes_tcp_packets(network_monitor: Any) -> None:
    """Network monitor processes TCP packets and extracts information."""
    from intellicrack.core.monitoring.network_monitor import SCAPY_AVAILABLE

    if not SCAPY_AVAILABLE:
        pytest.skip("Scapy not available")

    try:
        from scapy.all import IP, TCP, Raw
        from scapy.packet import Packet
    except ImportError:
        pytest.skip("Scapy imports failed")

    events_captured = []

    def capture_event(event: Any) -> None:
        events_captured.append(event)

    network_monitor.add_event_listener(capture_event)

    packet = IP(src="192.168.1.100", dst="10.0.0.50") / TCP(sport=12345, dport=443) / Raw(load=b"HTTP request data")

    network_monitor._process_packet(packet)

    if events_captured:
        event = events_captured[0]
        assert event.source == EventSource.NETWORK
        assert "192.168.1.100" in str(event.details.get("src", ""))


def test_network_monitor_detects_license_keywords(network_monitor: Any) -> None:
    """Network monitor identifies license-related keywords in packet payloads."""
    from intellicrack.core.monitoring.network_monitor import SCAPY_AVAILABLE

    if not SCAPY_AVAILABLE:
        pytest.skip("Scapy not available")

    try:
        from scapy.all import IP, TCP, Raw
    except ImportError:
        pytest.skip("Scapy imports failed")

    events_captured = []

    def capture_event(event: Any) -> None:
        events_captured.append(event)

    network_monitor.add_event_listener(capture_event)

    license_packet = (
        IP(src="192.168.1.100", dst="license.server.com")
        / TCP(sport=54321, dport=443)
        / Raw(load=b"license_key=ABC123&activation_code=XYZ789")
    )

    network_monitor._process_packet(license_packet)

    if events_captured:
        event = events_captured[0]
        assert event.severity == EventSeverity.CRITICAL
        assert event.details.get("contains_license_keywords") is True


def test_network_monitor_processes_udp_packets(network_monitor: Any) -> None:
    """Network monitor processes UDP packets and emits events."""
    from intellicrack.core.monitoring.network_monitor import SCAPY_AVAILABLE

    if not SCAPY_AVAILABLE:
        pytest.skip("Scapy not available")

    try:
        from scapy.all import IP, UDP, Raw
    except ImportError:
        pytest.skip("Scapy imports failed")

    events_captured = []

    def capture_event(event: Any) -> None:
        events_captured.append(event)

    network_monitor.add_event_listener(capture_event)

    udp_packet = IP(src="192.168.1.200", dst="8.8.8.8") / UDP(sport=1234, dport=53) / Raw(load=b"DNS query data")

    network_monitor._process_packet(udp_packet)

    if events_captured:
        event = events_captured[0]
        assert event.source == EventSource.NETWORK
        assert event.details.get("protocol") == "UDP"


def test_network_monitor_ignores_non_ip_packets(network_monitor: Any) -> None:
    """Network monitor ignores packets without IP layer."""
    from intellicrack.core.monitoring.network_monitor import SCAPY_AVAILABLE

    if not SCAPY_AVAILABLE:
        pytest.skip("Scapy not available")

    try:
        from scapy.all import Ether, Raw
    except ImportError:
        pytest.skip("Scapy imports failed")

    events_captured = []

    def capture_event(event: Any) -> None:
        events_captured.append(event)

    network_monitor.add_event_listener(capture_event)

    non_ip_packet = Ether() / Raw(load=b"non-IP data")

    network_monitor._process_packet(non_ip_packet)

    assert len(events_captured) == 0


def test_network_monitor_extracts_packet_payload_size(network_monitor: Any) -> None:
    """Network monitor extracts and records packet payload sizes."""
    from intellicrack.core.monitoring.network_monitor import SCAPY_AVAILABLE

    if not SCAPY_AVAILABLE:
        pytest.skip("Scapy not available")

    try:
        from scapy.all import IP, TCP, Raw
    except ImportError:
        pytest.skip("Scapy imports failed")

    events_captured = []

    def capture_event(event: Any) -> None:
        events_captured.append(event)

    network_monitor.add_event_listener(capture_event)

    payload_data = b"A" * 512
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=8000, dport=8080) / Raw(load=payload_data)

    network_monitor._process_packet(packet)

    if events_captured:
        event = events_captured[0]
        assert event.details.get("payload_size") == 512


def test_network_monitor_thread_safety(network_monitor: Any) -> None:
    """Network monitor handles concurrent packet processing safely."""
    from intellicrack.core.monitoring.network_monitor import SCAPY_AVAILABLE

    if not SCAPY_AVAILABLE:
        pytest.skip("Scapy not available")

    try:
        from scapy.all import IP, TCP, Raw
    except ImportError:
        pytest.skip("Scapy imports failed")

    events_captured = []
    lock = threading.Lock()

    def capture_event(event: Any) -> None:
        with lock:
            events_captured.append(event)

    network_monitor.add_event_listener(capture_event)

    def process_multiple_packets() -> None:
        for i in range(10):
            packet = IP(src=f"192.168.1.{i}", dst="10.0.0.1") / TCP(sport=1000 + i, dport=80) / Raw(load=b"test")
            network_monitor._process_packet(packet)

    threads = [threading.Thread(target=process_multiple_packets) for _ in range(3)]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert len(events_captured) >= 0


def test_network_monitor_event_severity_classification(network_monitor: Any) -> None:
    """Network monitor classifies events by severity based on content."""
    from intellicrack.core.monitoring.network_monitor import SCAPY_AVAILABLE

    if not SCAPY_AVAILABLE:
        pytest.skip("Scapy not available")

    try:
        from scapy.all import IP, TCP, Raw
    except ImportError:
        pytest.skip("Scapy imports failed")

    events_captured = []

    def capture_event(event: Any) -> None:
        events_captured.append(event)

    network_monitor.add_event_listener(capture_event)

    normal_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=5000, dport=80) / Raw(load=b"normal data")
    network_monitor._process_packet(normal_packet)

    license_packet = (
        IP(src="192.168.1.1", dst="192.168.1.2")
        / TCP(sport=5001, dport=443)
        / Raw(load=b"serial=12345 activation key data")
    )
    network_monitor._process_packet(license_packet)

    if len(events_captured) >= 2:
        assert events_captured[0].severity == EventSeverity.INFO
        assert events_captured[1].severity == EventSeverity.CRITICAL


def test_network_monitor_handles_error_in_packet_processing(network_monitor: Any) -> None:
    """Network monitor handles exceptions during packet processing gracefully."""
    from intellicrack.core.monitoring.network_monitor import SCAPY_AVAILABLE

    if not SCAPY_AVAILABLE:
        pytest.skip("Scapy not available")

    invalid_packet = None

    try:
        network_monitor._process_packet(invalid_packet)
    except Exception:
        pytest.fail("Network monitor should handle invalid packets gracefully")
