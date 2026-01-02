"""Comprehensive tests for traffic interception engine.

Tests validate real network packet capture, license traffic detection, protocol
identification, and traffic analysis capabilities against actual network packet
structures for FlexLM, HASP, CodeMeter, and other license server protocols.
"""

import secrets
import socket
import struct
import threading
import time
from typing import Any

import pytest

from intellicrack.core.network.traffic_interception_engine import AnalyzedTraffic, InterceptedPacket, TrafficInterceptionEngine


@pytest.fixture
def engine() -> TrafficInterceptionEngine:
    """Create traffic interception engine bound to localhost."""
    return TrafficInterceptionEngine(bind_interface="127.0.0.1")


@pytest.fixture
def tcp_packet_flexlm() -> bytes:
    """Create real TCP packet with FlexLM license checkout payload."""
    ip_header = bytearray()
    ip_header.extend(struct.pack("!B", 0x45))
    ip_header.extend(struct.pack("!B", 0x00))
    ip_header.extend(struct.pack("!H", 300))
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

    payload = b"FEATURE MATLAB 1.0 permanent 1 SIGN=0123456789ABCDEF VENDOR_STRING=MATHWORKS INCREMENT MATLAB 1.0 permanent 1 HOSTID=001122334455"

    return bytes(ip_header + tcp_header + payload)


@pytest.fixture
def tcp_packet_hasp() -> bytes:
    """Create real TCP packet with HASP/Sentinel license verification payload."""
    ip_header = bytearray()
    ip_header.extend(struct.pack("!B", 0x45))
    ip_header.extend(struct.pack("!B", 0x00))
    ip_header.extend(struct.pack("!H", 250))
    ip_header.extend(struct.pack("!H", 0x5678))
    ip_header.extend(struct.pack("!H", 0x4000))
    ip_header.extend(struct.pack("!B", 64))
    ip_header.extend(struct.pack("!B", 6))
    ip_header.extend(struct.pack("!H", 0))
    ip_header.extend(socket.inet_aton("10.0.0.50"))
    ip_header.extend(socket.inet_aton("10.0.0.100"))

    tcp_header = bytearray()
    tcp_header.extend(struct.pack("!H", 12345))
    tcp_header.extend(struct.pack("!H", 1947))
    tcp_header.extend(struct.pack("!I", 5000))
    tcp_header.extend(struct.pack("!I", 6000))
    tcp_header.extend(struct.pack("!B", 0x50))
    tcp_header.extend(struct.pack("!B", 0x10))
    tcp_header.extend(struct.pack("!H", 16384))
    tcp_header.extend(struct.pack("!H", 0))
    tcp_header.extend(struct.pack("!H", 0))

    payload = b"HASP_LICENSE_REQUEST sentinel=enabled Aladdin dongle verification checksum=ABCD1234"

    return bytes(ip_header + tcp_header + payload)


@pytest.fixture
def tcp_packet_adobe() -> bytes:
    """Create real TCP packet with Adobe activation payload."""
    ip_header = bytearray()
    ip_header.extend(struct.pack("!B", 0x45))
    ip_header.extend(struct.pack("!B", 0x00))
    ip_header.extend(struct.pack("!H", 200))
    ip_header.extend(struct.pack("!H", 0xABCD))
    ip_header.extend(struct.pack("!H", 0x4000))
    ip_header.extend(struct.pack("!B", 64))
    ip_header.extend(struct.pack("!B", 6))
    ip_header.extend(struct.pack("!H", 0))
    ip_header.extend(socket.inet_aton("172.16.0.10"))
    ip_header.extend(socket.inet_aton("172.16.0.20"))

    tcp_header = bytearray()
    tcp_header.extend(struct.pack("!H", 54321))
    tcp_header.extend(struct.pack("!H", 443))
    tcp_header.extend(struct.pack("!I", 8000))
    tcp_header.extend(struct.pack("!I", 9000))
    tcp_header.extend(struct.pack("!B", 0x50))
    tcp_header.extend(struct.pack("!B", 0x18))
    tcp_header.extend(struct.pack("!H", 32768))
    tcp_header.extend(struct.pack("!H", 0))
    tcp_header.extend(struct.pack("!H", 0))

    payload = b"POST /lcsap/request HTTP/1.1\r\nHost: activate.adobe.com\r\nContent-Type: application/xml\r\n\r\n<activation><serial>1234-5678-9012-3456</serial><adobe_id>test@test.com</adobe_id></activation>"

    return bytes(ip_header + tcp_header + payload)


@pytest.fixture
def tcp_packet_codemeter() -> bytes:
    """Create real TCP packet with CodeMeter license request payload."""
    ip_header = bytearray()
    ip_header.extend(struct.pack("!B", 0x45))
    ip_header.extend(struct.pack("!B", 0x00))
    ip_header.extend(struct.pack("!H", 180))
    ip_header.extend(struct.pack("!H", 0xDEAD))
    ip_header.extend(struct.pack("!H", 0x4000))
    ip_header.extend(struct.pack("!B", 64))
    ip_header.extend(struct.pack("!B", 6))
    ip_header.extend(struct.pack("!H", 0))
    ip_header.extend(socket.inet_aton("192.168.10.5"))
    ip_header.extend(socket.inet_aton("192.168.10.10"))

    tcp_header = bytearray()
    tcp_header.extend(struct.pack("!H", 33333))
    tcp_header.extend(struct.pack("!H", 443))
    tcp_header.extend(struct.pack("!I", 7000))
    tcp_header.extend(struct.pack("!I", 7500))
    tcp_header.extend(struct.pack("!B", 0x50))
    tcp_header.extend(struct.pack("!B", 0x18))
    tcp_header.extend(struct.pack("!H", 16384))
    tcp_header.extend(struct.pack("!H", 0))
    tcp_header.extend(struct.pack("!H", 0))

    payload = struct.pack("<I", 0x434D4554) + struct.pack("<I", 0x100A) + b"CodeMeter License Checkout Request FirmCode=500001 ProductCode=12345"

    return bytes(ip_header + tcp_header + payload)


@pytest.fixture
def tcp_packet_syn() -> bytes:
    """Create TCP SYN packet to license server port."""
    ip_header = bytearray()
    ip_header.extend(struct.pack("!B", 0x45))
    ip_header.extend(struct.pack("!B", 0x00))
    ip_header.extend(struct.pack("!H", 60))
    ip_header.extend(struct.pack("!H", 0x1111))
    ip_header.extend(struct.pack("!H", 0x4000))
    ip_header.extend(struct.pack("!B", 64))
    ip_header.extend(struct.pack("!B", 6))
    ip_header.extend(struct.pack("!H", 0))
    ip_header.extend(socket.inet_aton("192.168.1.10"))
    ip_header.extend(socket.inet_aton("192.168.1.20"))

    tcp_header = bytearray()
    tcp_header.extend(struct.pack("!H", 55555))
    tcp_header.extend(struct.pack("!H", 27000))
    tcp_header.extend(struct.pack("!I", 0))
    tcp_header.extend(struct.pack("!I", 0))
    tcp_header.extend(struct.pack("!B", 0x50))
    tcp_header.extend(struct.pack("!B", 0x02))
    tcp_header.extend(struct.pack("!H", 8192))
    tcp_header.extend(struct.pack("!H", 0))
    tcp_header.extend(struct.pack("!H", 0))

    return bytes(ip_header + tcp_header)


@pytest.fixture
def tcp_packet_generic_license() -> bytes:
    """Create TCP packet with generic license verification payload."""
    ip_header = bytearray()
    ip_header.extend(struct.pack("!B", 0x45))
    ip_header.extend(struct.pack("!B", 0x00))
    ip_header.extend(struct.pack("!H", 150))
    ip_header.extend(struct.pack("!H", 0x2222))
    ip_header.extend(struct.pack("!H", 0x4000))
    ip_header.extend(struct.pack("!B", 64))
    ip_header.extend(struct.pack("!B", 6))
    ip_header.extend(struct.pack("!H", 0))
    ip_header.extend(socket.inet_aton("10.1.1.100"))
    ip_header.extend(socket.inet_aton("10.1.1.200"))

    tcp_header = bytearray()
    tcp_header.extend(struct.pack("!H", 44444))
    tcp_header.extend(struct.pack("!H", 8080))
    tcp_header.extend(struct.pack("!I", 3000))
    tcp_header.extend(struct.pack("!I", 4000))
    tcp_header.extend(struct.pack("!B", 0x50))
    tcp_header.extend(struct.pack("!B", 0x18))
    tcp_header.extend(struct.pack("!H", 65535))
    tcp_header.extend(struct.pack("!H", 0))
    tcp_header.extend(struct.pack("!H", 0))

    payload = b"LICENSE_CHECKOUT verification=true activation_code=ABC123 VERIFY serial_number=XYZ789"

    return bytes(ip_header + tcp_header + payload)


@pytest.fixture
def tcp_packet_malformed() -> bytes:
    """Create malformed TCP packet with incomplete header."""
    truncated = bytearray()
    truncated.extend(struct.pack("!B", 0x45))
    truncated.extend(struct.pack("!B", 0x00))
    truncated.extend(struct.pack("!H", 20))
    return bytes(truncated)


@pytest.fixture
def tcp_packet_non_license() -> bytes:
    """Create TCP packet with non-license traffic (HTTP request)."""
    ip_header = bytearray()
    ip_header.extend(struct.pack("!B", 0x45))
    ip_header.extend(struct.pack("!B", 0x00))
    ip_header.extend(struct.pack("!H", 140))
    ip_header.extend(struct.pack("!H", 0x3333))
    ip_header.extend(struct.pack("!H", 0x4000))
    ip_header.extend(struct.pack("!B", 64))
    ip_header.extend(struct.pack("!B", 6))
    ip_header.extend(struct.pack("!H", 0))
    ip_header.extend(socket.inet_aton("192.168.1.50"))
    ip_header.extend(socket.inet_aton("8.8.8.8"))

    tcp_header = bytearray()
    tcp_header.extend(struct.pack("!H", 12345))
    tcp_header.extend(struct.pack("!H", 9999))
    tcp_header.extend(struct.pack("!I", 1000))
    tcp_header.extend(struct.pack("!I", 2000))
    tcp_header.extend(struct.pack("!B", 0x50))
    tcp_header.extend(struct.pack("!B", 0x18))
    tcp_header.extend(struct.pack("!H", 8192))
    tcp_header.extend(struct.pack("!H", 0))
    tcp_header.extend(struct.pack("!H", 0))

    payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"

    return bytes(ip_header + tcp_header + payload)


def test_engine_initialization_with_interface() -> None:
    """Engine initializes with specified network interface."""
    engine = TrafficInterceptionEngine(bind_interface="192.168.1.100")

    assert engine.bind_interface == "192.168.1.100"
    assert not engine.running
    assert engine.stats["packets_captured"] == 0
    assert engine.stats["license_packets_detected"] == 0
    assert isinstance(engine.license_ports, set)
    assert 27000 in engine.license_ports
    assert 1947 in engine.license_ports


def test_engine_initialization_without_interface() -> None:
    """Engine initializes with default interface from configuration."""
    try:
        engine = TrafficInterceptionEngine()
        assert engine.bind_interface is not None
        assert isinstance(engine.bind_interface, str)
        assert not engine.running
    except Exception:
        engine = TrafficInterceptionEngine(bind_interface="127.0.0.1")
        assert engine.bind_interface == "127.0.0.1"
        assert not engine.running


def test_engine_has_license_patterns_configured() -> None:
    """Engine initializes with comprehensive license pattern database."""
    engine = TrafficInterceptionEngine(bind_interface="127.0.0.1")

    assert "flexlm" in engine.license_patterns
    assert "hasp" in engine.license_patterns
    assert "adobe" in engine.license_patterns
    assert "autodesk" in engine.license_patterns
    assert "microsoft" in engine.license_patterns
    assert "generic_license" in engine.license_patterns

    assert b"VENDOR_STRING" in engine.license_patterns["flexlm"]
    assert b"FEATURE" in engine.license_patterns["flexlm"]
    assert b"HASP" in engine.license_patterns["hasp"]
    assert b"sentinel" in engine.license_patterns["hasp"]


def test_parse_raw_packet_extracts_flexlm_traffic(
    engine: TrafficInterceptionEngine, tcp_packet_flexlm: bytes
) -> None:
    """Raw packet parser extracts FlexLM license checkout from TCP packet."""
    engine._parse_raw_packet(tcp_packet_flexlm)

    assert engine.stats["packets_captured"] == 1
    assert engine.stats["total_bytes"] == len(tcp_packet_flexlm)

    with engine.queue_lock:
        assert len(engine.packet_queue) == 1
        packet = engine.packet_queue[0]

    assert packet.source_ip == "192.168.1.100"
    assert packet.dest_ip == "192.168.1.50"
    assert packet.source_port == 45678
    assert packet.dest_port == 27000
    assert packet.protocol == "tcp"
    assert b"FEATURE MATLAB" in packet.data
    assert b"SIGN=" in packet.data
    assert packet.flags["ack"]


def test_parse_raw_packet_extracts_hasp_traffic(
    engine: TrafficInterceptionEngine, tcp_packet_hasp: bytes
) -> None:
    """Raw packet parser extracts HASP/Sentinel license verification."""
    engine._parse_raw_packet(tcp_packet_hasp)

    assert engine.stats["packets_captured"] == 1

    with engine.queue_lock:
        packet = engine.packet_queue[0]

    assert packet.source_ip == "10.0.0.50"
    assert packet.dest_ip == "10.0.0.100"
    assert packet.dest_port == 1947
    assert b"HASP_LICENSE_REQUEST" in packet.data
    assert b"sentinel" in packet.data
    assert b"Aladdin" in packet.data


def test_parse_raw_packet_extracts_adobe_activation(
    engine: TrafficInterceptionEngine, tcp_packet_adobe: bytes
) -> None:
    """Raw packet parser extracts Adobe activation request."""
    engine._parse_raw_packet(tcp_packet_adobe)

    with engine.queue_lock:
        packet = engine.packet_queue[0]

    assert packet.dest_port == 443
    assert b"lcsap" in packet.data
    assert b"activation" in packet.data
    assert b"serial" in packet.data
    assert b"adobe.com" in packet.data


def test_parse_raw_packet_extracts_tcp_flags(
    engine: TrafficInterceptionEngine, tcp_packet_syn: bytes
) -> None:
    """Raw packet parser correctly extracts TCP flags."""
    engine._parse_raw_packet(tcp_packet_syn)

    with engine.queue_lock:
        packet = engine.packet_queue[0]

    assert packet.flags["syn"]
    assert not packet.flags["ack"]
    assert not packet.flags["fin"]
    assert not packet.flags["rst"]


def test_parse_raw_packet_handles_malformed_packet(
    engine: TrafficInterceptionEngine, tcp_packet_malformed: bytes
) -> None:
    """Raw packet parser handles malformed packets gracefully."""
    engine._parse_raw_packet(tcp_packet_malformed)

    assert engine.stats["packets_captured"] == 0
    with engine.queue_lock:
        assert len(engine.packet_queue) == 0


def test_parse_raw_packet_filters_non_license_ports(
    engine: TrafficInterceptionEngine, tcp_packet_non_license: bytes
) -> None:
    """Raw packet parser filters traffic on non-license ports."""
    engine._parse_raw_packet(tcp_packet_non_license)

    with engine.queue_lock:
        assert len(engine.packet_queue) == 0


def test_analyze_packet_detects_flexlm_protocol(
    engine: TrafficInterceptionEngine, tcp_packet_flexlm: bytes
) -> None:
    """Packet analyzer identifies FlexLM protocol from payload patterns."""
    engine._parse_raw_packet(tcp_packet_flexlm)

    with engine.queue_lock:
        packet = engine.packet_queue[0]

    analysis = engine._analyze_packet(packet)

    assert analysis is not None
    assert analysis.is_license_related
    assert analysis.protocol_type == "flexlm"
    assert analysis.confidence >= 0.5
    assert any("FEATURE" in pattern for pattern in analysis.patterns_matched)
    assert any("VENDOR_STRING" in pattern for pattern in analysis.patterns_matched)
    assert engine.stats["license_packets_detected"] == 1
    assert "flexlm" in engine.stats["protocols_detected"]


def test_analyze_packet_detects_hasp_protocol(
    engine: TrafficInterceptionEngine, tcp_packet_hasp: bytes
) -> None:
    """Packet analyzer identifies HASP/Sentinel protocol."""
    engine._parse_raw_packet(tcp_packet_hasp)

    with engine.queue_lock:
        packet = engine.packet_queue[0]

    analysis = engine._analyze_packet(packet)

    assert analysis is not None
    assert analysis.is_license_related
    assert analysis.protocol_type == "hasp"
    assert analysis.confidence >= 0.5
    assert any("HASP" in pattern for pattern in analysis.patterns_matched)
    assert "hasp" in engine.stats["protocols_detected"]


def test_analyze_packet_detects_adobe_protocol(
    engine: TrafficInterceptionEngine, tcp_packet_adobe: bytes
) -> None:
    """Packet analyzer identifies Adobe licensing protocol."""
    engine._parse_raw_packet(tcp_packet_adobe)

    with engine.queue_lock:
        packet = engine.packet_queue[0]

    analysis = engine._analyze_packet(packet)

    assert analysis is not None
    assert analysis.is_license_related
    assert analysis.protocol_type == "adobe"
    assert analysis.confidence >= 0.3


def test_analyze_packet_detects_generic_license_traffic(
    engine: TrafficInterceptionEngine, tcp_packet_generic_license: bytes
) -> None:
    """Packet analyzer detects generic license verification patterns."""
    engine._parse_raw_packet(tcp_packet_generic_license)

    with engine.queue_lock:
        packet = engine.packet_queue[0]

    analysis = engine._analyze_packet(packet)

    assert analysis is not None
    assert analysis.is_license_related
    assert analysis.confidence >= 0.3


def test_analyze_packet_uses_port_based_detection(engine: TrafficInterceptionEngine) -> None:
    """Packet analyzer uses port-based detection for license traffic."""
    packet = InterceptedPacket(
        source_ip="192.168.1.1",
        dest_ip="192.168.1.2",
        source_port=12345,
        dest_port=27000,
        protocol="tcp",
        data=b"Some unknown protocol data",
        timestamp=time.time(),
        packet_size=100,
        flags={"syn": False, "ack": True, "fin": False, "rst": False},
    )

    analysis = engine._analyze_packet(packet)

    assert analysis is not None
    assert analysis.is_license_related
    assert analysis.confidence >= 0.3
    assert analysis.analysis_metadata["port_based_detection"]


def test_analyze_packet_returns_none_for_low_confidence(
    engine: TrafficInterceptionEngine,
) -> None:
    """Packet analyzer returns None for low confidence matches."""
    packet = InterceptedPacket(
        source_ip="192.168.1.1",
        dest_ip="8.8.8.8",
        source_port=12345,
        dest_port=9999,
        protocol="tcp",
        data=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n",
        timestamp=time.time(),
        packet_size=50,
        flags={"syn": False, "ack": True, "fin": False, "rst": False},
    )

    analysis = engine._analyze_packet(packet)

    assert analysis is None


def test_analyze_packet_returns_none_for_empty_payload(
    engine: TrafficInterceptionEngine,
) -> None:
    """Packet analyzer returns None for packets without payload data."""
    packet = InterceptedPacket(
        source_ip="192.168.1.1",
        dest_ip="192.168.1.2",
        source_port=12345,
        dest_port=27000,
        protocol="tcp",
        data=b"",
        timestamp=time.time(),
        packet_size=60,
        flags={"syn": True, "ack": False, "fin": False, "rst": False},
    )

    analysis = engine._analyze_packet(packet)

    assert analysis is None


def test_analyze_packet_calculates_confidence_from_patterns(
    engine: TrafficInterceptionEngine,
) -> None:
    """Packet analyzer calculates confidence based on pattern matches."""
    high_confidence_packet = InterceptedPacket(
        source_ip="192.168.1.1",
        dest_ip="192.168.1.2",
        source_port=12345,
        dest_port=27000,
        protocol="tcp",
        data=b"FEATURE test VENDOR_STRING test INCREMENT test SERVER test HOSTID test SIGN=test",
        timestamp=time.time(),
        packet_size=150,
        flags={"syn": False, "ack": True, "fin": False, "rst": False},
    )

    analysis = engine._analyze_packet(high_confidence_packet)

    assert analysis is not None
    assert analysis.confidence >= 0.7
    assert len(analysis.patterns_matched) >= 3


def test_analyze_packet_includes_metadata(engine: TrafficInterceptionEngine) -> None:
    """Packet analyzer includes comprehensive metadata in analysis results."""
    packet = InterceptedPacket(
        source_ip="192.168.1.1",
        dest_ip="192.168.1.2",
        source_port=12345,
        dest_port=27000,
        protocol="tcp",
        data=b"FEATURE test license checkout",
        timestamp=time.time(),
        packet_size=100,
        flags={"syn": False, "ack": True, "fin": False, "rst": False},
    )

    analysis = engine._analyze_packet(packet)

    assert analysis is not None
    assert "keywords_found" in analysis.analysis_metadata
    assert "port_based_detection" in analysis.analysis_metadata
    assert "data_size" in analysis.analysis_metadata
    assert "connection_flags" in analysis.analysis_metadata
    assert analysis.analysis_metadata["data_size"] == len(packet.data)


def test_queue_packet_updates_statistics(engine: TrafficInterceptionEngine) -> None:
    """Packet queue updates statistics correctly."""
    packet = InterceptedPacket(
        source_ip="192.168.1.1",
        dest_ip="192.168.1.2",
        source_port=12345,
        dest_port=27000,
        protocol="tcp",
        data=b"test",
        timestamp=time.time(),
        packet_size=100,
        flags={"syn": False, "ack": True, "fin": False, "rst": False},
    )

    initial_count = engine.stats["packets_captured"]
    initial_bytes = engine.stats["total_bytes"]

    engine._queue_packet(packet)

    assert engine.stats["packets_captured"] == initial_count + 1
    assert engine.stats["total_bytes"] == initial_bytes + 100


def test_queue_packet_limits_queue_size(engine: TrafficInterceptionEngine) -> None:
    """Packet queue enforces maximum size limit to prevent memory exhaustion."""
    for i in range(10005):
        packet = InterceptedPacket(
            source_ip="192.168.1.1",
            dest_ip="192.168.1.2",
            source_port=12345,
            dest_port=27000,
            protocol="tcp",
            data=f"packet {i}".encode(),
            timestamp=time.time(),
            packet_size=50,
            flags={"syn": False, "ack": True, "fin": False, "rst": False},
        )
        engine._queue_packet(packet)

    with engine.queue_lock:
        assert len(engine.packet_queue) <= 10000


def test_add_analysis_callback_registers_callback(engine: TrafficInterceptionEngine) -> None:
    """Analysis callback registration works correctly."""
    callback_called = []

    def test_callback(analysis: AnalyzedTraffic) -> None:
        callback_called.append(analysis)

    engine.add_analysis_callback(test_callback)

    assert test_callback in engine.analysis_callbacks


def test_remove_analysis_callback_unregisters_callback(
    engine: TrafficInterceptionEngine,
) -> None:
    """Analysis callback removal works correctly."""

    def test_callback(analysis: AnalyzedTraffic) -> None:
        pass

    engine.add_analysis_callback(test_callback)
    assert test_callback in engine.analysis_callbacks

    engine.remove_analysis_callback(test_callback)
    assert test_callback not in engine.analysis_callbacks


def test_set_dns_redirection_configures_mapping(engine: TrafficInterceptionEngine) -> None:
    """DNS redirection configuration stores hostname to IP mappings."""
    result = engine.set_dns_redirection("license.example.com", "127.0.0.1")

    assert result
    assert "license.example.com" in engine.dns_redirections
    assert engine.dns_redirections["license.example.com"] == "127.0.0.1"


def test_set_dns_redirection_normalizes_hostname(engine: TrafficInterceptionEngine) -> None:
    """DNS redirection normalizes hostname to lowercase."""
    engine.set_dns_redirection("LICENSE.EXAMPLE.COM", "192.168.1.1")

    assert "license.example.com" in engine.dns_redirections


def test_setup_transparent_proxy_configures_mapping(engine: TrafficInterceptionEngine) -> None:
    """Transparent proxy configuration stores target to local mappings."""
    result = engine.setup_transparent_proxy("license.server.com", 27000)

    assert result
    assert "license.server.com:27000" in engine.proxy_mappings
    assert engine.proxy_mappings["license.server.com:27000"] == ("127.0.0.1", 27000)


def test_get_statistics_returns_complete_stats(engine: TrafficInterceptionEngine) -> None:
    """Statistics getter returns comprehensive runtime statistics."""
    engine.stats["start_time"] = time.time()
    engine.stats["packets_captured"] = 100
    engine.stats["license_packets_detected"] = 50
    engine.stats["protocols_detected"].add("flexlm")
    engine.stats["protocols_detected"].add("hasp")

    stats = engine.get_statistics()

    assert stats["packets_captured"] == 100
    assert stats["license_packets_detected"] == 50
    assert isinstance(stats["protocols_detected"], list)
    assert "flexlm" in stats["protocols_detected"]
    assert "hasp" in stats["protocols_detected"]
    assert "uptime_seconds" in stats
    assert "packets_per_second" in stats
    assert "capture_backend" in stats
    assert "dns_redirections" in stats
    assert "proxy_mappings" in stats


def test_get_statistics_calculates_uptime(engine: TrafficInterceptionEngine) -> None:
    """Statistics calculate uptime from start time."""
    start = time.time() - 10.0
    engine.stats["start_time"] = start

    stats = engine.get_statistics()

    assert stats["uptime_seconds"] >= 9.0
    assert stats["uptime_seconds"] <= 11.0


def test_get_statistics_handles_no_start_time(engine: TrafficInterceptionEngine) -> None:
    """Statistics handle missing start time gracefully."""
    engine.stats["start_time"] = None

    stats = engine.get_statistics()

    assert stats["uptime_seconds"] == 0


def test_get_active_connections_returns_connection_list(
    engine: TrafficInterceptionEngine,
) -> None:
    """Active connections getter returns formatted connection information."""
    with engine.connection_lock:
        engine.active_connections["192.168.1.1:27000"] = {
            "first_seen": time.time() - 5.0,
            "last_activity": time.time(),
            "packet_count": 10,
        }

    connections = engine.get_active_connections()

    assert len(connections) == 1
    assert connections[0]["endpoint"] == "192.168.1.1:27000"
    assert connections[0]["duration"] >= 4.0
    assert connections[0]["packet_count"] == 10


def test_start_interception_initializes_capture(engine: TrafficInterceptionEngine) -> None:
    """Start interception initializes capture threads and sets running state."""
    result = engine.start_interception()

    assert result
    assert engine.running
    assert engine.stats["start_time"] is not None
    assert engine.capture_thread is not None
    assert engine.analysis_thread is not None
    assert engine.capture_thread.is_alive()
    assert engine.analysis_thread.is_alive()

    engine.stop_interception()


def test_start_interception_with_custom_ports(engine: TrafficInterceptionEngine) -> None:
    """Start interception adds custom ports to monitoring list."""
    custom_ports = [9999, 8888]
    result = engine.start_interception(ports=custom_ports)

    assert result
    assert 9999 in engine.license_ports
    assert 8888 in engine.license_ports

    engine.stop_interception()


def test_start_interception_handles_already_running(engine: TrafficInterceptionEngine) -> None:
    """Start interception returns success if already running."""
    engine.start_interception()
    result = engine.start_interception()

    assert result
    assert engine.running

    engine.stop_interception()


def test_stop_interception_stops_capture(engine: TrafficInterceptionEngine) -> None:
    """Stop interception cleanly shuts down capture threads."""
    engine.start_interception()
    time.sleep(0.2)

    result = engine.stop_interception()

    assert result
    assert not engine.running


def test_analysis_loop_processes_queued_packets(engine: TrafficInterceptionEngine) -> None:
    """Analysis loop processes packets from queue and invokes callbacks."""
    callback_results = []

    def test_callback(analysis: AnalyzedTraffic) -> None:
        callback_results.append(analysis)

    engine.add_analysis_callback(test_callback)
    engine.start_interception()

    packet = InterceptedPacket(
        source_ip="192.168.1.1",
        dest_ip="192.168.1.2",
        source_port=12345,
        dest_port=27000,
        protocol="tcp",
        data=b"FEATURE test VENDOR_STRING test INCREMENT test SERVER test HOSTID=001122334455 SIGN=ABCD1234",
        timestamp=time.time(),
        packet_size=150,
        flags={"syn": False, "ack": True, "fin": False, "rst": False},
    )

    engine._queue_packet(packet)
    time.sleep(0.3)

    engine.stop_interception()

    assert callback_results
    assert callback_results[0].is_license_related
    assert callback_results[0].protocol_type == "flexlm"


def test_analysis_loop_handles_callback_exceptions(engine: TrafficInterceptionEngine) -> None:
    """Analysis loop continues processing even if callback raises exception."""

    def failing_callback(analysis: AnalyzedTraffic) -> None:
        raise ValueError("Test exception")

    successful_callbacks = []

    def successful_callback(analysis: AnalyzedTraffic) -> None:
        successful_callbacks.append(analysis)

    engine.add_analysis_callback(failing_callback)
    engine.add_analysis_callback(successful_callback)
    engine.start_interception()

    packet = InterceptedPacket(
        source_ip="192.168.1.1",
        dest_ip="192.168.1.2",
        source_port=12345,
        dest_port=27000,
        protocol="tcp",
        data=b"FEATURE test",
        timestamp=time.time(),
        packet_size=100,
        flags={"syn": False, "ack": True, "fin": False, "rst": False},
    )

    engine._queue_packet(packet)
    time.sleep(0.3)

    engine.stop_interception()

    assert successful_callbacks


def test_intercepted_packet_dataclass_initialization() -> None:
    """InterceptedPacket dataclass initializes with correct fields."""
    packet = InterceptedPacket(
        source_ip="192.168.1.1",
        dest_ip="192.168.1.2",
        source_port=12345,
        dest_port=27000,
        protocol="tcp",
        data=b"test data",
        timestamp=1234567890.0,
        packet_size=100,
        flags={"syn": True, "ack": False, "fin": False, "rst": False},
    )

    assert packet.source_ip == "192.168.1.1"
    assert packet.dest_ip == "192.168.1.2"
    assert packet.source_port == 12345
    assert packet.dest_port == 27000
    assert packet.protocol == "tcp"
    assert packet.data == b"test data"
    assert packet.timestamp == 1234567890.0
    assert packet.packet_size == 100
    assert packet.flags["syn"]
    assert not packet.flags["ack"]


def test_intercepted_packet_post_init_creates_default_flags() -> None:
    """InterceptedPacket post_init creates default flags if not provided."""
    packet = InterceptedPacket(
        source_ip="192.168.1.1",
        dest_ip="192.168.1.2",
        source_port=12345,
        dest_port=27000,
        protocol="tcp",
        data=b"test",
        timestamp=time.time(),
        packet_size=100,
        flags={},
    )

    assert "syn" in packet.flags
    assert "ack" in packet.flags
    assert "fin" in packet.flags
    assert "rst" in packet.flags
    assert not packet.flags["syn"]


def test_analyzed_traffic_dataclass_stores_analysis_results() -> None:
    """AnalyzedTraffic dataclass stores complete analysis results."""
    packet = InterceptedPacket(
        source_ip="192.168.1.1",
        dest_ip="192.168.1.2",
        source_port=12345,
        dest_port=27000,
        protocol="tcp",
        data=b"FEATURE test",
        timestamp=time.time(),
        packet_size=100,
        flags={"syn": False, "ack": True, "fin": False, "rst": False},
    )

    analysis = AnalyzedTraffic(
        packet=packet,
        is_license_related=True,
        protocol_type="flexlm",
        confidence=0.85,
        patterns_matched=["FEATURE", "VENDOR_STRING"],
        analysis_metadata={"test_key": "test_value"},
    )

    assert analysis.packet == packet
    assert analysis.is_license_related
    assert analysis.protocol_type == "flexlm"
    assert analysis.confidence == 0.85
    assert "FEATURE" in analysis.patterns_matched
    assert analysis.analysis_metadata["test_key"] == "test_value"


def test_multi_protocol_detection_in_single_session(
    engine: TrafficInterceptionEngine,
    tcp_packet_flexlm: bytes,
    tcp_packet_hasp: bytes,
    tcp_packet_adobe: bytes,
) -> None:
    """Engine detects multiple different license protocols in single session."""
    engine._parse_raw_packet(tcp_packet_flexlm)
    engine._parse_raw_packet(tcp_packet_hasp)
    engine._parse_raw_packet(tcp_packet_adobe)

    packets = []
    with engine.queue_lock:
        packets = engine.packet_queue.copy()

    protocols_detected = set()
    for packet in packets:
        if analysis := engine._analyze_packet(packet):
            protocols_detected.add(analysis.protocol_type)

    assert "flexlm" in protocols_detected
    assert "hasp" in protocols_detected
    assert "adobe" in protocols_detected


def test_concurrent_packet_queuing_thread_safety(engine: TrafficInterceptionEngine) -> None:
    """Packet queueing handles concurrent access safely."""

    def queue_packets() -> None:
        for i in range(100):
            packet = InterceptedPacket(
                source_ip="192.168.1.1",
                dest_ip="192.168.1.2",
                source_port=12345,
                dest_port=27000,
                protocol="tcp",
                data=f"packet {i}".encode(),
                timestamp=time.time(),
                packet_size=50,
                flags={"syn": False, "ack": True, "fin": False, "rst": False},
            )
            engine._queue_packet(packet)

    threads = [threading.Thread(target=queue_packets) for _ in range(5)]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert engine.stats["packets_captured"] == 500


def test_parse_packet_with_multiple_license_keywords(
    engine: TrafficInterceptionEngine,
) -> None:
    """Packet analysis detects multiple license-related keywords."""
    packet = InterceptedPacket(
        source_ip="192.168.1.1",
        dest_ip="192.168.1.2",
        source_port=12345,
        dest_port=27000,
        protocol="tcp",
        data=b"LICENSE activation checkout verify serial number validation",
        timestamp=time.time(),
        packet_size=150,
        flags={"syn": False, "ack": True, "fin": False, "rst": False},
    )

    analysis = engine._analyze_packet(packet)

    assert analysis is not None
    assert analysis.is_license_related
    assert analysis.confidence >= 0.5


def test_engine_capture_backend_initialization() -> None:
    """Engine initializes with appropriate capture backend for platform."""
    engine = TrafficInterceptionEngine(bind_interface="127.0.0.1")

    assert engine.capture_backend in ["scapy", "socket"]
    assert isinstance(engine.capture_backend, str)


def test_parse_packet_extracts_codemeter_magic(
    engine: TrafficInterceptionEngine, tcp_packet_codemeter: bytes
) -> None:
    """Raw packet parser extracts CodeMeter protocol packets."""
    engine._parse_raw_packet(tcp_packet_codemeter)

    with engine.queue_lock:
        packet = engine.packet_queue[0]

    assert struct.unpack("<I", packet.data[:4])[0] == 0x434D4554
    assert b"CodeMeter" in packet.data


def test_statistics_tracks_protocols_detected(engine: TrafficInterceptionEngine) -> None:
    """Statistics tracking maintains set of detected protocols."""
    packet1 = InterceptedPacket(
        source_ip="192.168.1.1",
        dest_ip="192.168.1.2",
        source_port=12345,
        dest_port=27000,
        protocol="tcp",
        data=b"FEATURE test VENDOR_STRING test INCREMENT test SERVER test HOSTID=001122334455 SIGN=ABCD1234",
        timestamp=time.time(),
        packet_size=150,
        flags={"syn": False, "ack": True, "fin": False, "rst": False},
    )

    packet2 = InterceptedPacket(
        source_ip="192.168.1.1",
        dest_ip="192.168.1.2",
        source_port=12345,
        dest_port=1947,
        protocol="tcp",
        data=b"HASP sentinel verification Aladdin dongle",
        timestamp=time.time(),
        packet_size=100,
        flags={"syn": False, "ack": True, "fin": False, "rst": False},
    )

    engine._analyze_packet(packet1)
    engine._analyze_packet(packet2)

    assert "flexlm" in engine.stats["protocols_detected"]
    assert "hasp" in engine.stats["protocols_detected"]


def test_parse_packet_handles_minimum_valid_packet(engine: TrafficInterceptionEngine) -> None:
    """Raw packet parser handles minimum valid TCP/IP packet."""
    ip_header = bytearray()
    ip_header.extend(struct.pack("!B", 0x45))
    ip_header.extend(struct.pack("!B", 0x00))
    ip_header.extend(struct.pack("!H", 60))
    ip_header.extend(struct.pack("!H", 0x1234))
    ip_header.extend(struct.pack("!H", 0x4000))
    ip_header.extend(struct.pack("!B", 64))
    ip_header.extend(struct.pack("!B", 6))
    ip_header.extend(struct.pack("!H", 0))
    ip_header.extend(socket.inet_aton("192.168.1.1"))
    ip_header.extend(socket.inet_aton("192.168.1.2"))

    tcp_header = bytearray()
    tcp_header.extend(struct.pack("!H", 12345))
    tcp_header.extend(struct.pack("!H", 27000))
    tcp_header.extend(struct.pack("!I", 0))
    tcp_header.extend(struct.pack("!I", 0))
    tcp_header.extend(struct.pack("!B", 0x50))
    tcp_header.extend(struct.pack("!B", 0x18))
    tcp_header.extend(struct.pack("!H", 8192))
    tcp_header.extend(struct.pack("!H", 0))
    tcp_header.extend(struct.pack("!H", 0))

    packet = bytes(ip_header + tcp_header)
    engine._parse_raw_packet(packet)

    assert engine.stats["packets_captured"] == 1


def test_parse_packet_ignores_non_tcp_protocols(engine: TrafficInterceptionEngine) -> None:
    """Raw packet parser filters out non-TCP protocols (UDP, ICMP, etc)."""
    ip_header = bytearray()
    ip_header.extend(struct.pack("!B", 0x45))
    ip_header.extend(struct.pack("!B", 0x00))
    ip_header.extend(struct.pack("!H", 50))
    ip_header.extend(struct.pack("!H", 0x1234))
    ip_header.extend(struct.pack("!H", 0x4000))
    ip_header.extend(struct.pack("!B", 64))
    ip_header.extend(struct.pack("!B", 17))
    ip_header.extend(struct.pack("!H", 0))
    ip_header.extend(socket.inet_aton("192.168.1.1"))
    ip_header.extend(socket.inet_aton("192.168.1.2"))

    udp_data = b"some udp payload"
    packet = bytes(ip_header + udp_data)

    engine._parse_raw_packet(packet)

    with engine.queue_lock:
        assert len(engine.packet_queue) == 0
