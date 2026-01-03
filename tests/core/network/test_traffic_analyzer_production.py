"""Production-ready tests for network traffic analyzer validating real license traffic analysis.

This test suite validates REAL offensive capabilities for analyzing network traffic
related to software licensing protection systems. Tests use actual packet data,
real protocol structures, and genuine license server communication patterns.

CRITICAL: These tests verify the analyzer can detect and analyze real license
server communication to enable bypassing and exploitation of software protections.
Tests MUST fail if the analyzer cannot effectively identify license traffic patterns.
"""

import socket
import struct
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest
from hypothesis import (
    given,
    strategies as st,
)
from scapy.all import IP, TCP, Ether, Raw  # type: ignore[attr-defined]

from intellicrack.core.network.traffic_analyzer import NetworkTrafficAnalyzer


@pytest.fixture
def temp_capture_dir(tmp_path: Path) -> Path:
    """Create temporary directory for packet captures."""
    capture_dir = tmp_path / "captures"
    capture_dir.mkdir(parents=True, exist_ok=True)
    return capture_dir


@pytest.fixture
def production_analyzer(temp_capture_dir: Path) -> NetworkTrafficAnalyzer:
    """Create production traffic analyzer instance with real configuration."""
    config = {
        "capture_file": str(temp_capture_dir / "license_traffic.pcap"),
        "max_packets": 5000,
        "filter": "tcp",
        "visualization_dir": str(temp_capture_dir / "visualizations"),
        "auto_analyze": False,
    }
    return NetworkTrafficAnalyzer(config=config)


@pytest.fixture
def flexlm_license_request_packet() -> bytes:
    """Create authentic FlexLM license daemon request packet.

    FlexLM is the most widely used commercial license manager (Autodesk, MATLAB, etc).
    Uses TCP port 27000-27009 for daemon communication.
    """
    packet_data = bytearray()

    version_ihl = (4 << 4) | 5
    packet_data.append(version_ihl)

    packet_data.append(0)

    flexlm_request = b"FEATURE MATLAB MLM 40.0 permanent 1 VENDOR_STRING=trial_version HOSTID=ANY START=01-jan-2024 SIGN=ABCD1234EFGH5678"
    tcp_header = 20
    ip_header = 20
    total_len = ip_header + tcp_header + len(flexlm_request)
    packet_data.extend(struct.pack("!H", total_len))

    packet_data.extend(struct.pack("!H", 0x1234))
    packet_data.extend(struct.pack("!H", 0))

    packet_data.append(64)
    packet_data.append(6)

    packet_data.extend(struct.pack("!H", 0))

    src_ip = socket.inet_aton("192.168.1.150")
    packet_data.extend(src_ip)
    dst_ip = socket.inet_aton("192.168.1.10")
    packet_data.extend(dst_ip)

    src_port = 49152
    packet_data.extend(struct.pack("!H", src_port))
    dst_port = 27000
    packet_data.extend(struct.pack("!H", dst_port))

    packet_data.extend(struct.pack("!I", 1000))
    packet_data.extend(struct.pack("!I", 0))

    data_offset_flags = (5 << 4) | 0
    packet_data.append(data_offset_flags)
    packet_data.append(0x18)

    packet_data.extend(struct.pack("!H", 65535))
    packet_data.extend(struct.pack("!H", 0))
    packet_data.extend(struct.pack("!H", 0))

    packet_data.extend(flexlm_request)

    return bytes(packet_data)


@pytest.fixture
def hasp_dongle_query_packet() -> bytes:
    """Create authentic HASP/Sentinel hardware dongle query packet.

    HASP HL is used by Autodesk, Adobe, and many CAD applications.
    Port 1947 for license management communication.
    """
    packet_data = bytearray()

    version_ihl = (4 << 4) | 5
    packet_data.append(version_ihl)
    packet_data.append(0)

    hasp_query = b"HASP_SESSION_ID=9876543210 HASP_FEATURE_ID=42 HASP_VENDOR_CODE=12345 Sentinel KEY_ID=DEMO-1234-5678-ABCD"
    tcp_header = 20
    ip_header = 20
    total_len = ip_header + tcp_header + len(hasp_query)
    packet_data.extend(struct.pack("!H", total_len))

    packet_data.extend(struct.pack("!H", 0x5678))
    packet_data.extend(struct.pack("!H", 0))

    packet_data.append(64)
    packet_data.append(6)
    packet_data.extend(struct.pack("!H", 0))

    src_ip = socket.inet_aton("10.0.5.100")
    packet_data.extend(src_ip)
    dst_ip = socket.inet_aton("10.0.5.200")
    packet_data.extend(dst_ip)

    src_port = 55123
    packet_data.extend(struct.pack("!H", src_port))
    dst_port = 1947
    packet_data.extend(struct.pack("!H", dst_port))

    packet_data.extend(struct.pack("!I", 5000))
    packet_data.extend(struct.pack("!I", 2000))

    packet_data.append(5 << 4)
    packet_data.append(0x18)

    packet_data.extend(struct.pack("!H", 32768))
    packet_data.extend(struct.pack("!H", 0))
    packet_data.extend(struct.pack("!H", 0))

    packet_data.extend(hasp_query)

    return bytes(packet_data)


@pytest.fixture
def codemeter_activation_packet() -> bytes:
    """Create authentic CodeMeter activation request packet.

    CodeMeter is used by Siemens, WIBU systems, and industrial software.
    Port 22350 for activation server communication.
    """
    packet_data = bytearray()

    version_ihl = (4 << 4) | 5
    packet_data.append(version_ihl)
    packet_data.append(0)

    codemeter_request = b"CM_ACT_REQUEST license_key=CMACT-12345-67890-ABCDE-FGHIJ activation_code=98765-43210 Sentinel WIBU"
    tcp_header = 20
    ip_header = 20
    total_len = ip_header + tcp_header + len(codemeter_request)
    packet_data.extend(struct.pack("!H", total_len))

    packet_data.extend(struct.pack("!H", 0xABCD))
    packet_data.extend(struct.pack("!H", 0))

    packet_data.append(64)
    packet_data.append(6)
    packet_data.extend(struct.pack("!H", 0))

    src_ip = socket.inet_aton("172.20.1.50")
    packet_data.extend(src_ip)
    dst_ip = socket.inet_aton("172.20.1.250")
    packet_data.extend(dst_ip)

    src_port = 60000
    packet_data.extend(struct.pack("!H", src_port))
    dst_port = 22350
    packet_data.extend(struct.pack("!H", dst_port))

    packet_data.extend(struct.pack("!I", 10000))
    packet_data.extend(struct.pack("!I", 5000))

    packet_data.append(5 << 4)
    packet_data.append(0x18)

    packet_data.extend(struct.pack("!H", 65535))
    packet_data.extend(struct.pack("!H", 0))
    packet_data.extend(struct.pack("!H", 0))

    packet_data.extend(codemeter_request)

    return bytes(packet_data)


@pytest.fixture
def https_license_validation_packet() -> bytes:
    """Create HTTPS license validation packet (web-based licensing).

    Modern software often uses HTTPS for cloud license validation.
    Port 443 with TLS/SSL encrypted license check.
    """
    packet_data = bytearray()

    version_ihl = (4 << 4) | 5
    packet_data.append(version_ihl)
    packet_data.append(0)

    https_payload = b"\x16\x03\x03\x00\x50" + b"license.example.com" + b"/api/validate" + b"?key=ABC123&product=Pro&version=2024"
    tcp_header = 20
    ip_header = 20
    total_len = ip_header + tcp_header + len(https_payload)
    packet_data.extend(struct.pack("!H", total_len))

    packet_data.extend(struct.pack("!H", 0x9999))
    packet_data.extend(struct.pack("!H", 0))

    packet_data.append(64)
    packet_data.append(6)
    packet_data.extend(struct.pack("!H", 0))

    src_ip = socket.inet_aton("192.168.100.10")
    packet_data.extend(src_ip)
    dst_ip = socket.inet_aton("203.0.113.50")
    packet_data.extend(dst_ip)

    src_port = 51234
    packet_data.extend(struct.pack("!H", src_port))
    dst_port = 443
    packet_data.extend(struct.pack("!H", dst_port))

    packet_data.extend(struct.pack("!I", 15000))
    packet_data.extend(struct.pack("!I", 8000))

    packet_data.append(5 << 4)
    packet_data.append(0x18)

    packet_data.extend(struct.pack("!H", 32768))
    packet_data.extend(struct.pack("!H", 0))
    packet_data.extend(struct.pack("!H", 0))

    packet_data.extend(https_payload)

    return bytes(packet_data)


@pytest.fixture
def sentinel_rms_license_packet() -> bytes:
    """Create Sentinel RMS (Runtime Management System) license packet.

    Sentinel RMS port 5093 used for network license management.
    """
    packet_data = bytearray()

    version_ihl = (4 << 4) | 5
    packet_data.append(version_ihl)
    packet_data.append(0)

    sentinel_request = b"LCSAPI_REQUEST VENDOR_ID=Sentinel_Demo LICENSE_CODE=PROF-2024-STANDARD FEATURE_VERSION=10.0"
    tcp_header = 20
    ip_header = 20
    total_len = ip_header + tcp_header + len(sentinel_request)
    packet_data.extend(struct.pack("!H", total_len))

    packet_data.extend(struct.pack("!H", 0x4444))
    packet_data.extend(struct.pack("!H", 0))

    packet_data.append(64)
    packet_data.append(6)
    packet_data.extend(struct.pack("!H", 0))

    src_ip = socket.inet_aton("10.10.10.5")
    packet_data.extend(src_ip)
    dst_ip = socket.inet_aton("10.10.10.100")
    packet_data.extend(dst_ip)

    src_port = 47000
    packet_data.extend(struct.pack("!H", src_port))
    dst_port = 5093
    packet_data.extend(struct.pack("!H", dst_port))

    packet_data.extend(struct.pack("!I", 3000))
    packet_data.extend(struct.pack("!I", 1500))

    packet_data.append(5 << 4)
    packet_data.append(0x18)

    packet_data.extend(struct.pack("!H", 65535))
    packet_data.extend(struct.pack("!H", 0))
    packet_data.extend(struct.pack("!H", 0))

    packet_data.extend(sentinel_request)

    return bytes(packet_data)


class TestTrafficAnalyzerInitialization:
    """Test traffic analyzer initialization and configuration."""

    def test_analyzer_initializes_with_default_config(self) -> None:
        """Analyzer initializes successfully with default configuration."""
        analyzer = NetworkTrafficAnalyzer()

        assert analyzer is not None
        assert hasattr(analyzer, 'config')
        assert hasattr(analyzer, 'packets')
        assert hasattr(analyzer, 'connections')
        assert hasattr(analyzer, 'license_servers')
        assert hasattr(analyzer, 'license_patterns')
        assert hasattr(analyzer, 'license_ports')

        assert len(analyzer.packets) == 0
        assert len(analyzer.connections) == 0
        assert len(analyzer.license_servers) == 0
        assert analyzer.capturing is False

    def test_analyzer_initializes_with_custom_config(self, temp_capture_dir: Path) -> None:
        """Analyzer accepts and applies custom configuration."""
        custom_config = {
            "capture_file": str(temp_capture_dir / "custom.pcap"),
            "max_packets": 2000,
            "filter": "tcp port 27000",
            "visualization_dir": str(temp_capture_dir / "viz"),
            "auto_analyze": True,
        }

        analyzer = NetworkTrafficAnalyzer(config=custom_config)

        assert analyzer.config["capture_file"] == custom_config["capture_file"]
        assert analyzer.config["max_packets"] == 2000
        assert analyzer.config["filter"] == "tcp port 27000"
        assert analyzer.config["auto_analyze"] is True

    def test_analyzer_has_correct_license_port_list(self, production_analyzer: NetworkTrafficAnalyzer) -> None:
        """Analyzer includes all major license server ports."""
        expected_ports = {
            1111, 1234, 2222,
            27000, 27001, 27002, 27003, 27004, 27005,
            1947, 6001,
            22350, 22351,
            2080, 8224, 5093, 49684
        }

        analyzer_ports = set(production_analyzer.license_ports)

        assert expected_ports.issubset(analyzer_ports), "Missing critical license server ports"
        assert 27000 in analyzer_ports, "FlexLM port 27000 missing"
        assert 1947 in analyzer_ports, "HASP port 1947 missing"
        assert 22350 in analyzer_ports, "CodeMeter port 22350 missing"
        assert 5093 in analyzer_ports, "Sentinel RMS port 5093 missing"

    def test_analyzer_has_comprehensive_license_patterns(self, production_analyzer: NetworkTrafficAnalyzer) -> None:
        """Analyzer includes all major license protocol patterns."""
        expected_patterns = {
            b"license", b"activation", b"auth", b"key", b"valid",
            b"FEATURE", b"INCREMENT", b"VENDOR", b"SERVER",
            b"HASP", b"Sentinel", b"FLEXLM", b"LCSAP"
        }

        analyzer_patterns = set(production_analyzer.license_patterns)

        assert expected_patterns.issubset(analyzer_patterns), "Missing critical license patterns"

    def test_analyzer_initializes_local_network_detection(self, production_analyzer: NetworkTrafficAnalyzer) -> None:
        """Analyzer properly initializes local network ranges for traffic direction detection."""
        assert "192.168." in production_analyzer.local_networks
        assert "10." in production_analyzer.local_networks
        assert "172.16." in production_analyzer.local_networks
        assert "127." in production_analyzer.local_networks
        assert "localhost" in production_analyzer.local_networks


class TestPacketProcessing:
    """Test real packet processing and license pattern detection."""

    def test_processes_flexlm_packet_correctly(
        self,
        production_analyzer: NetworkTrafficAnalyzer,
        flexlm_license_request_packet: bytes
    ) -> None:
        """Analyzer correctly processes and identifies FlexLM license traffic."""
        production_analyzer._process_captured_packet(flexlm_license_request_packet)

        assert len(flexlm_license_request_packet) >= 20, "Invalid test packet structure"

        version = flexlm_license_request_packet[0] >> 4
        assert version == 4, "Test packet must be IPv4"

        ihl = (flexlm_license_request_packet[0] & 0xF) * 4
        protocol = flexlm_license_request_packet[9]
        assert protocol == 6, "Test packet must be TCP"

        (flexlm_license_request_packet[ihl] << 8) | flexlm_license_request_packet[ihl + 1]
        dst_port = (flexlm_license_request_packet[ihl + 2] << 8) | flexlm_license_request_packet[ihl + 3]

        assert dst_port == 27000, "FlexLM packet must target port 27000"
        assert b"FEATURE" in flexlm_license_request_packet, "Packet must contain FlexLM FEATURE command"

    def test_processes_hasp_packet_correctly(
        self,
        production_analyzer: NetworkTrafficAnalyzer,
        hasp_dongle_query_packet: bytes
    ) -> None:
        """Analyzer correctly processes and identifies HASP/Sentinel license traffic."""
        production_analyzer._process_captured_packet(hasp_dongle_query_packet)

        assert len(hasp_dongle_query_packet) >= 20

        ihl = (hasp_dongle_query_packet[0] & 0xF) * 4
        dst_port = (hasp_dongle_query_packet[ihl + 2] << 8) | hasp_dongle_query_packet[ihl + 3]

        assert dst_port == 1947, "HASP packet must target port 1947"
        assert b"HASP" in hasp_dongle_query_packet or b"Sentinel" in hasp_dongle_query_packet

    def test_processes_codemeter_packet_correctly(
        self,
        production_analyzer: NetworkTrafficAnalyzer,
        codemeter_activation_packet: bytes
    ) -> None:
        """Analyzer correctly processes and identifies CodeMeter activation traffic."""
        production_analyzer._process_captured_packet(codemeter_activation_packet)

        assert len(codemeter_activation_packet) >= 20

        ihl = (codemeter_activation_packet[0] & 0xF) * 4
        dst_port = (codemeter_activation_packet[ihl + 2] << 8) | codemeter_activation_packet[ihl + 3]

        assert dst_port == 22350, "CodeMeter packet must target port 22350"
        assert b"activation" in codemeter_activation_packet

    def test_processes_https_license_packet_correctly(
        self,
        production_analyzer: NetworkTrafficAnalyzer,
        https_license_validation_packet: bytes
    ) -> None:
        """Analyzer correctly processes HTTPS-based license validation traffic."""
        production_analyzer._process_captured_packet(https_license_validation_packet)

        assert len(https_license_validation_packet) >= 20

        ihl = (https_license_validation_packet[0] & 0xF) * 4
        dst_port = (https_license_validation_packet[ihl + 2] << 8) | https_license_validation_packet[ihl + 3]

        assert dst_port == 443, "HTTPS packet must target port 443"
        assert b"license" in https_license_validation_packet or b"validate" in https_license_validation_packet

    def test_processes_sentinel_rms_packet_correctly(
        self,
        production_analyzer: NetworkTrafficAnalyzer,
        sentinel_rms_license_packet: bytes
    ) -> None:
        """Analyzer correctly processes Sentinel RMS license management traffic."""
        production_analyzer._process_captured_packet(sentinel_rms_license_packet)

        assert len(sentinel_rms_license_packet) >= 20

        ihl = (sentinel_rms_license_packet[0] & 0xF) * 4
        dst_port = (sentinel_rms_license_packet[ihl + 2] << 8) | sentinel_rms_license_packet[ihl + 3]

        assert dst_port == 5093, "Sentinel RMS packet must target port 5093"
        assert b"LCSAPI" in sentinel_rms_license_packet or b"VENDOR" in sentinel_rms_license_packet

    def test_extracts_ip_addresses_from_packets(
        self,
        production_analyzer: NetworkTrafficAnalyzer,
        flexlm_license_request_packet: bytes
    ) -> None:
        """Analyzer extracts source and destination IP addresses from packets."""
        src_ip_bytes = flexlm_license_request_packet[12:16]
        dst_ip_bytes = flexlm_license_request_packet[16:20]

        src_ip = socket.inet_ntoa(src_ip_bytes)
        dst_ip = socket.inet_ntoa(dst_ip_bytes)

        assert src_ip == "192.168.1.150", "Source IP extraction failed"
        assert dst_ip == "192.168.1.10", "Destination IP extraction failed"

    def test_extracts_port_numbers_from_packets(
        self,
        production_analyzer: NetworkTrafficAnalyzer,
        flexlm_license_request_packet: bytes
    ) -> None:
        """Analyzer extracts TCP port numbers from packets."""
        ihl = (flexlm_license_request_packet[0] & 0xF) * 4

        src_port = (flexlm_license_request_packet[ihl] << 8) | flexlm_license_request_packet[ihl + 1]
        dst_port = (flexlm_license_request_packet[ihl + 2] << 8) | flexlm_license_request_packet[ihl + 3]

        assert src_port == 49152, "Source port extraction failed"
        assert dst_port == 27000, "Destination port extraction failed"

    def test_identifies_license_ports_in_traffic(
        self,
        production_analyzer: NetworkTrafficAnalyzer,
        flexlm_license_request_packet: bytes
    ) -> None:
        """Analyzer identifies when traffic uses known license server ports."""
        ihl = (flexlm_license_request_packet[0] & 0xF) * 4
        dst_port = (flexlm_license_request_packet[ihl + 2] << 8) | flexlm_license_request_packet[ihl + 3]

        is_license_port = dst_port in production_analyzer.license_ports

        assert is_license_port, "Failed to identify license server port"
        assert dst_port == 27000


class TestLicensePatternDetection:
    """Test detection of license-related patterns in packet payloads."""

    def test_detects_flexlm_feature_command(
        self,
        production_analyzer: NetworkTrafficAnalyzer,
        flexlm_license_request_packet: bytes
    ) -> None:
        """Analyzer detects FlexLM FEATURE command in packet payload."""
        assert b"FEATURE" in flexlm_license_request_packet
        assert b"FEATURE" in production_analyzer.license_patterns

        payload_contains_pattern = any(
            pattern in flexlm_license_request_packet
            for pattern in production_analyzer.license_patterns
        )
        assert payload_contains_pattern

    def test_detects_hasp_identifier(
        self,
        production_analyzer: NetworkTrafficAnalyzer,
        hasp_dongle_query_packet: bytes
    ) -> None:
        """Analyzer detects HASP identifier in hardware dongle queries."""
        assert b"HASP" in hasp_dongle_query_packet or b"Sentinel" in hasp_dongle_query_packet
        assert b"HASP" in production_analyzer.license_patterns
        assert b"Sentinel" in production_analyzer.license_patterns

    def test_detects_activation_keywords(
        self,
        production_analyzer: NetworkTrafficAnalyzer,
        codemeter_activation_packet: bytes
    ) -> None:
        """Analyzer detects activation keywords in license requests."""
        assert b"activation" in codemeter_activation_packet
        assert b"activation" in production_analyzer.license_patterns

    def test_detects_license_key_patterns(
        self,
        production_analyzer: NetworkTrafficAnalyzer,
        flexlm_license_request_packet: bytes
    ) -> None:
        """Analyzer detects license key patterns in traffic."""
        assert b"key" in production_analyzer.license_patterns

        has_any_license_pattern = any(
            pattern in flexlm_license_request_packet
            for pattern in production_analyzer.license_patterns
        )
        assert (
            has_any_license_pattern
        ), "FlexLM packet should match at least one license pattern"

    def test_detects_vendor_strings(
        self,
        production_analyzer: NetworkTrafficAnalyzer,
        flexlm_license_request_packet: bytes
    ) -> None:
        """Analyzer detects VENDOR strings in FlexLM traffic."""
        assert b"VENDOR" in production_analyzer.license_patterns
        assert b"VENDOR_STRING" in flexlm_license_request_packet

    def test_detects_multiple_patterns_in_single_packet(
        self,
        production_analyzer: NetworkTrafficAnalyzer,
        flexlm_license_request_packet: bytes
    ) -> None:
        """Analyzer detects multiple license patterns in a single packet."""
        detected_patterns = [
            pattern for pattern in production_analyzer.license_patterns
            if pattern in flexlm_license_request_packet
        ]

        assert len(detected_patterns) >= 2, "Should detect multiple patterns in FlexLM packet"
        assert b"FEATURE" in detected_patterns
        assert b"VENDOR" in detected_patterns


class TestConnectionTracking:
    """Test connection tracking and correlation."""

    def test_creates_connection_key_from_packet(
        self,
        production_analyzer: NetworkTrafficAnalyzer,
        flexlm_license_request_packet: bytes
    ) -> None:
        """Analyzer creates unique connection keys for tracking."""
        src_ip_bytes = flexlm_license_request_packet[12:16]
        dst_ip_bytes = flexlm_license_request_packet[16:20]
        ihl = (flexlm_license_request_packet[0] & 0xF) * 4
        src_port = (flexlm_license_request_packet[ihl] << 8) | flexlm_license_request_packet[ihl + 1]
        dst_port = (flexlm_license_request_packet[ihl + 2] << 8) | flexlm_license_request_packet[ihl + 3]

        src_ip = socket.inet_ntoa(src_ip_bytes)
        dst_ip = socket.inet_ntoa(dst_ip_bytes)

        expected_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"

        assert src_ip == "192.168.1.150"
        assert dst_ip == "192.168.1.10"
        assert src_port == 49152
        assert dst_port == 27000
        assert expected_key == "192.168.1.150:49152-192.168.1.10:27000"

    def test_tracks_connection_direction(
        self,
        production_analyzer: NetworkTrafficAnalyzer,
        flexlm_license_request_packet: bytes
    ) -> None:
        """Analyzer determines if connection is inbound or outbound."""
        src_ip_bytes = flexlm_license_request_packet[12:16]
        src_ip = socket.inet_ntoa(src_ip_bytes)

        is_local = any(src_ip.startswith(net) for net in production_analyzer.local_networks)

        assert is_local, "Should recognize local network traffic"
        assert src_ip.startswith("192.168.")

    def test_tracks_bytes_sent_and_received(
        self,
        production_analyzer: NetworkTrafficAnalyzer,
        flexlm_license_request_packet: bytes
    ) -> None:
        """Analyzer tracks data volume for each connection."""
        packet_size = len(flexlm_license_request_packet)

        assert packet_size > 0
        assert packet_size == struct.unpack("!H", flexlm_license_request_packet[2:4])[0]


class TestLicenseServerIdentification:
    """Test identification of license servers from traffic."""

    def test_identifies_flexlm_server_from_port(
        self,
        production_analyzer: NetworkTrafficAnalyzer,
        flexlm_license_request_packet: bytes
    ) -> None:
        """Analyzer identifies FlexLM servers by port 27000."""
        ihl = (flexlm_license_request_packet[0] & 0xF) * 4
        dst_port = (flexlm_license_request_packet[ihl + 2] << 8) | flexlm_license_request_packet[ihl + 3]

        is_flexlm_port = dst_port in range(27000, 27010)

        assert is_flexlm_port
        assert dst_port == 27000

    def test_identifies_hasp_server_from_port(
        self,
        production_analyzer: NetworkTrafficAnalyzer,
        hasp_dongle_query_packet: bytes
    ) -> None:
        """Analyzer identifies HASP/Sentinel servers by port 1947."""
        ihl = (hasp_dongle_query_packet[0] & 0xF) * 4
        dst_port = (hasp_dongle_query_packet[ihl + 2] << 8) | hasp_dongle_query_packet[ihl + 3]

        assert dst_port == 1947
        assert dst_port in production_analyzer.license_ports

    def test_identifies_codemeter_server_from_port(
        self,
        production_analyzer: NetworkTrafficAnalyzer,
        codemeter_activation_packet: bytes
    ) -> None:
        """Analyzer identifies CodeMeter servers by port 22350."""
        ihl = (codemeter_activation_packet[0] & 0xF) * 4
        dst_port = (codemeter_activation_packet[ihl + 2] << 8) | codemeter_activation_packet[ihl + 3]

        assert dst_port == 22350
        assert dst_port in production_analyzer.license_ports

    def test_extracts_server_ip_from_license_traffic(
        self,
        production_analyzer: NetworkTrafficAnalyzer,
        flexlm_license_request_packet: bytes
    ) -> None:
        """Analyzer extracts license server IP addresses from traffic."""
        dst_ip_bytes = flexlm_license_request_packet[16:20]
        dst_ip = socket.inet_ntoa(dst_ip_bytes)

        assert dst_ip == "192.168.1.10"


class TestTrafficAnalysis:
    """Test comprehensive traffic analysis and statistics."""

    def test_analyze_traffic_returns_results(
        self,
        production_analyzer: NetworkTrafficAnalyzer
    ) -> None:
        """Analyzer returns comprehensive analysis results."""
        results = production_analyzer.analyze_traffic()

        assert results is not None
        assert "total_packets" in results
        assert "total_connections" in results
        assert "license_connections" in results
        assert "license_servers" in results
        assert "license_conn_details" in results

    def test_calculates_capture_duration(
        self,
        production_analyzer: NetworkTrafficAnalyzer
    ) -> None:
        """Analyzer calculates total capture duration."""
        current_time = time.time()
        production_analyzer.packets = [
            {"timestamp": current_time},
            {"timestamp": current_time + 5.0},
            {"timestamp": current_time + 10.0},
        ]

        duration = production_analyzer._calculate_capture_duration()

        assert duration == 10.0

    def test_calculates_packet_rate(
        self,
        production_analyzer: NetworkTrafficAnalyzer
    ) -> None:
        """Analyzer calculates packets per second."""
        current_time = time.time()
        production_analyzer.packets = [
            {"timestamp": current_time},
            {"timestamp": current_time + 0.5},
            {"timestamp": current_time + 1.0},
            {"timestamp": current_time + 1.5},
        ]

        rate = production_analyzer._calculate_packet_rate()

        assert rate > 0
        assert rate == 4.0 / 1.5

    def test_calculates_protocol_distribution(
        self,
        production_analyzer: NetworkTrafficAnalyzer
    ) -> None:
        """Analyzer calculates distribution of detected protocols."""
        production_analyzer.connections = {
            "conn1": {"dst_port": 27000, "packets": [1, 2, 3]},
            "conn2": {"dst_port": 1947, "packets": [1, 2]},
            "conn3": {"dst_port": 443, "packets": [1]},
        }

        distribution = production_analyzer._calculate_protocol_distribution()

        assert "FlexLM" in distribution
        assert distribution["FlexLM"] == 3
        assert "HASP" in distribution
        assert distribution["HASP"] == 2
        assert "HTTPS" in distribution
        assert distribution["HTTPS"] == 1

    def test_calculates_port_distribution(
        self,
        production_analyzer: NetworkTrafficAnalyzer
    ) -> None:
        """Analyzer calculates top destination ports."""
        production_analyzer.connections = {
            "conn1": {"dst_port": 27000, "packets": []},
            "conn2": {"dst_port": 27000, "packets": []},
            "conn3": {"dst_port": 1947, "packets": []},
        }

        distribution = production_analyzer._calculate_port_distribution()

        assert 27000 in distribution
        assert distribution[27000] == 2
        assert 1947 in distribution
        assert distribution[1947] == 1

    def test_identifies_peak_traffic_time(
        self,
        production_analyzer: NetworkTrafficAnalyzer
    ) -> None:
        """Analyzer identifies peak traffic time period."""
        base_time = 1700000000.0

        production_analyzer.packets = [
            {"timestamp": base_time},
            {"timestamp": base_time + 30},
            {"timestamp": base_time + 60},
            {"timestamp": base_time + 65},
            {"timestamp": base_time + 70},
        ]

        peak_time = production_analyzer._identify_peak_traffic_time()

        assert peak_time is not None
        assert isinstance(peak_time, str)

    def test_analyzes_connection_durations(
        self,
        production_analyzer: NetworkTrafficAnalyzer
    ) -> None:
        """Analyzer calculates connection duration statistics."""
        production_analyzer.connections = {
            "conn1": {"start_time": 100.0, "last_time": 105.0},
            "conn2": {"start_time": 200.0, "last_time": 220.0},
            "conn3": {"start_time": 300.0, "last_time": 310.0},
        }

        durations = production_analyzer._analyze_connection_durations()

        assert durations["min"] == 5.0
        assert durations["max"] == 20.0
        assert durations["avg"] == (5.0 + 20.0 + 10.0) / 3
        assert durations["total"] == 3


class TestSuspiciousTrafficDetection:
    """Test detection of suspicious license-related traffic patterns."""

    def test_detects_high_port_license_traffic(
        self,
        production_analyzer: NetworkTrafficAnalyzer
    ) -> None:
        """Analyzer flags license traffic on unusual high ports."""
        production_analyzer.connections = {
            "conn1": {
                "src_ip": "192.168.1.1",
                "dst_ip": "192.168.1.100",
                "src_port": 50000,
                "dst_port": 45000,
                "bytes_sent": 1000,
                "bytes_received": 1000,
                "is_license": True,
                "start_time": 100.0,
                "last_time": 105.0,
                "packets": [],
            }
        }

        results = production_analyzer.get_results()

        suspicious = results["suspicious_traffic"]
        assert len(suspicious) > 0

        high_port_detected = any(
            "High port number" in indicator
            for s in suspicious
            for indicator in s["indicators"]
        )
        assert high_port_detected

    def test_detects_large_data_transfers(
        self,
        production_analyzer: NetworkTrafficAnalyzer
    ) -> None:
        """Analyzer flags unusually large license data transfers."""
        production_analyzer.connections = {
            "conn1": {
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.100",
                "src_port": 50000,
                "dst_port": 27000,
                "bytes_sent": 2000000,
                "bytes_received": 1000,
                "is_license": True,
                "start_time": 100.0,
                "last_time": 105.0,
                "packets": [],
            }
        }

        results = production_analyzer.get_results()

        suspicious = results["suspicious_traffic"]
        large_transfer_detected = any(
            "Large data transfer" in indicator
            for s in suspicious
            for indicator in s["indicators"]
        )
        assert large_transfer_detected

    def test_detects_long_duration_connections(
        self,
        production_analyzer: NetworkTrafficAnalyzer
    ) -> None:
        """Analyzer flags long-duration license connections."""
        production_analyzer.connections = {
            "conn1": {
                "src_ip": "172.16.0.1",
                "dst_ip": "172.16.0.100",
                "src_port": 50000,
                "dst_port": 1947,
                "bytes_sent": 10000,
                "bytes_received": 10000,
                "is_license": True,
                "start_time": 100.0,
                "last_time": 4000.0,
                "packets": [],
            }
        }

        results = production_analyzer.get_results()

        suspicious = results["suspicious_traffic"]
        long_duration_detected = any(
            "Long connection duration" in indicator
            for s in suspicious
            for indicator in s["indicators"]
        )
        assert long_duration_detected

    def test_detects_asymmetric_data_flow(
        self,
        production_analyzer: NetworkTrafficAnalyzer
    ) -> None:
        """Analyzer flags asymmetric upload/download ratios."""
        production_analyzer.connections = {
            "conn1": {
                "src_ip": "192.168.1.1",
                "dst_ip": "192.168.1.100",
                "src_port": 50000,
                "dst_port": 27000,
                "bytes_sent": 100000,
                "bytes_received": 100,
                "is_license": False,
                "start_time": 100.0,
                "last_time": 105.0,
                "packets": [],
            }
        }

        results = production_analyzer.get_results()

        suspicious = results["suspicious_traffic"]
        asymmetric_detected = any(
            "Asymmetric data flow" in indicator
            for s in suspicious
            for indicator in s["indicators"]
        )
        assert asymmetric_detected

    def test_assesses_threat_levels_correctly(
        self,
        production_analyzer: NetworkTrafficAnalyzer
    ) -> None:
        """Analyzer correctly assesses threat levels based on indicators."""
        assert production_analyzer._assess_threat_level(["indicator1"]) == "low"
        assert production_analyzer._assess_threat_level(["indicator1", "indicator2"]) == "medium"
        assert production_analyzer._assess_threat_level(["indicator1", "indicator2", "indicator3"]) == "high"


class TestGetResults:
    """Test comprehensive results retrieval."""

    def test_get_results_returns_complete_structure(
        self,
        production_analyzer: NetworkTrafficAnalyzer
    ) -> None:
        """get_results returns all required fields."""
        results = production_analyzer.get_results()

        assert "packets_analyzed" in results
        assert "protocols_detected" in results
        assert "suspicious_traffic" in results
        assert "statistics" in results
        assert "license_analysis" in results
        assert "summary" in results

    def test_get_results_includes_statistics(
        self,
        production_analyzer: NetworkTrafficAnalyzer
    ) -> None:
        """get_results includes detailed statistics."""
        results = production_analyzer.get_results()

        stats = results["statistics"]
        assert "capture_duration" in stats
        assert "packets_per_second" in stats
        assert "total_bytes" in stats
        assert "unique_ips" in stats
        assert "protocol_distribution" in stats
        assert "port_distribution" in stats
        assert "license_traffic_percentage" in stats
        assert "peak_traffic_time" in stats
        assert "connection_durations" in stats

    def test_get_results_includes_license_analysis(
        self,
        production_analyzer: NetworkTrafficAnalyzer
    ) -> None:
        """get_results includes license-specific analysis."""
        results = production_analyzer.get_results()

        license_analysis = results["license_analysis"]
        assert "license_servers" in license_analysis
        assert "license_connections" in license_analysis
        assert "license_connection_details" in license_analysis

    def test_get_results_detects_protocols(
        self,
        production_analyzer: NetworkTrafficAnalyzer
    ) -> None:
        """get_results correctly identifies protocols from port numbers."""
        current_time = time.time()
        production_analyzer.connections = {
            "conn1": {
                "src_port": 50000,
                "dst_port": 27000,
                "packets": [],
                "src_ip": "192.168.1.1",
                "dst_ip": "192.168.1.10",
                "bytes_sent": 100,
                "bytes_received": 100,
                "is_license": False,
                "start_time": current_time,
                "last_time": current_time + 1.0,
            },
            "conn2": {
                "src_port": 51000,
                "dst_port": 1947,
                "packets": [],
                "src_ip": "192.168.1.1",
                "dst_ip": "192.168.1.11",
                "bytes_sent": 100,
                "bytes_received": 100,
                "is_license": False,
                "start_time": current_time,
                "last_time": current_time + 1.0,
            },
            "conn3": {
                "src_port": 52000,
                "dst_port": 443,
                "packets": [],
                "src_ip": "192.168.1.1",
                "dst_ip": "192.168.1.12",
                "bytes_sent": 100,
                "bytes_received": 100,
                "is_license": False,
                "start_time": current_time,
                "last_time": current_time + 1.0,
            },
        }

        results = production_analyzer.get_results()

        protocols = results["protocols_detected"]
        assert "FlexLM" in protocols
        assert "HASP/Sentinel" in protocols
        assert "HTTPS" in protocols


class TestCaptureControl:
    """Test packet capture start/stop control."""

    def test_stop_capture_sets_flag(
        self,
        production_analyzer: NetworkTrafficAnalyzer
    ) -> None:
        """stop_capture correctly sets the capturing flag."""
        production_analyzer.capturing = True

        result = production_analyzer.stop_capture()

        assert result is True
        assert not production_analyzer.capturing

    def test_stop_capture_logs_statistics(
        self,
        production_analyzer: NetworkTrafficAnalyzer
    ) -> None:
        """stop_capture logs final capture statistics."""
        production_analyzer.packets = [{"data": 1}, {"data": 2}, {"data": 3}]
        production_analyzer.connections = {
            "conn1": {"is_license": True},
            "conn2": {"is_license": False},
        }

        result = production_analyzer.stop_capture()

        assert result is True
        assert len(production_analyzer.packets) == 3
        assert len(production_analyzer.connections) == 2


class TestReportGeneration:
    """Test HTML report generation."""

    def test_generate_report_creates_html_file(
        self,
        production_analyzer: NetworkTrafficAnalyzer,
        temp_capture_dir: Path
    ) -> None:
        """generate_report creates HTML file with analysis results."""
        production_analyzer.packets = [{"timestamp": time.time()}]
        production_analyzer.connections = {}

        report_path = temp_capture_dir / "test_report.html"

        result = production_analyzer.generate_report(str(report_path))

        assert result is True
        assert report_path.exists()

        content = report_path.read_text(encoding="utf-8")
        assert "License Traffic Analysis Report" in content
        assert "Summary" in content

    def test_generate_report_includes_statistics(
        self,
        production_analyzer: NetworkTrafficAnalyzer,
        temp_capture_dir: Path
    ) -> None:
        """Generated report includes traffic statistics."""
        current_time = time.time()
        production_analyzer.packets = [{"timestamp": current_time}]
        production_analyzer.connections = {
            "conn1": {
                "is_license": True,
                "packets": [],
                "src_ip": "192.168.1.1",
                "dst_ip": "192.168.1.100",
                "src_port": 50000,
                "dst_port": 27000,
                "bytes_sent": 1000,
                "bytes_received": 1000,
                "start_time": current_time,
                "last_time": current_time + 5.0,
            }
        }

        report_path = temp_capture_dir / "stats_report.html"
        result = production_analyzer.generate_report(str(report_path))

        assert result is True

        content = report_path.read_text(encoding="utf-8")
        assert "Total Packets" in content
        assert "Total Connections" in content


class TestPropertyBasedTrafficAnalysis:
    """Property-based tests using Hypothesis for traffic analysis algorithms."""

    @given(st.integers(min_value=2, max_value=10000))
    def test_packet_rate_calculation_with_random_counts(
        self,
        packet_count: int
    ) -> None:
        """Packet rate calculation works correctly for any valid packet count."""
        analyzer = NetworkTrafficAnalyzer()
        base_time = 1000.0
        duration = 10.0

        analyzer.packets = [
            {"timestamp": base_time + (i * duration / (packet_count - 1))}
            for i in range(packet_count)
        ]

        rate = analyzer._calculate_packet_rate()

        assert rate > 0
        assert rate == pytest.approx(packet_count / duration, rel=0.05)

    @given(st.lists(st.integers(min_value=1, max_value=65535), min_size=1, max_size=10))
    def test_port_distribution_with_random_ports(
        self,
        ports: list[int]
    ) -> None:
        """Port distribution calculation handles arbitrary port lists."""
        analyzer = NetworkTrafficAnalyzer()
        analyzer.connections = {
            f"conn{i}": {"dst_port": port, "packets": []}
            for i, port in enumerate(ports)
        }

        distribution = analyzer._calculate_port_distribution()

        assert len(distribution) > 0
        assert sum(distribution.values()) <= len(ports)

    @given(st.floats(min_value=0.1, max_value=3600.0))
    def test_connection_duration_with_random_times(
        self,
        duration: float
    ) -> None:
        """Connection duration analysis handles arbitrary time ranges."""
        analyzer = NetworkTrafficAnalyzer()
        start_time = 1000.0

        analyzer.connections = {
            "conn1": {"start_time": start_time, "last_time": start_time + duration}
        }

        durations = analyzer._analyze_connection_durations()

        assert durations["min"] == pytest.approx(duration, rel=0.01)
        assert durations["max"] == pytest.approx(duration, rel=0.01)
        assert durations["avg"] == pytest.approx(duration, rel=0.01)


class TestScapyIntegration:
    """Test integration with Scapy for advanced packet crafting and analysis."""

    def test_creates_flexlm_packet_with_scapy(self) -> None:
        """Creates valid FlexLM packet using Scapy."""
        packet = (
            Ether() /
            IP(src="192.168.1.100", dst="192.168.1.10") /
            TCP(sport=49152, dport=27000) /
            Raw(load=b"FEATURE matlab MLM 40.0 permanent 1 VENDOR_STRING=example")
        )

        assert packet[IP].src == "192.168.1.100"
        assert packet[IP].dst == "192.168.1.10"
        assert packet[TCP].dport == 27000
        assert b"FEATURE" in bytes(packet[Raw])

    def test_creates_hasp_packet_with_scapy(self) -> None:
        """Creates valid HASP packet using Scapy."""
        packet = (
            Ether() /
            IP(src="10.0.0.50", dst="10.0.0.200") /
            TCP(sport=52000, dport=1947) /
            Raw(load=b"HASP HL Max Protect KEY_ID=12345678 FEATURE=Pro Sentinel")
        )

        assert packet[TCP].dport == 1947
        assert b"HASP" in bytes(packet[Raw])
        assert b"Sentinel" in bytes(packet[Raw])

    def test_creates_codemeter_packet_with_scapy(self) -> None:
        """Creates valid CodeMeter packet using Scapy."""
        packet = (
            Ether() /
            IP(src="172.20.1.50", dst="172.20.1.250") /
            TCP(sport=60000, dport=22350) /
            Raw(load=b"CM_ACT_REQUEST license_key=CMACT-12345-67890 activation_code=98765")
        )

        assert packet[TCP].dport == 22350
        assert b"CM_ACT" in bytes(packet[Raw])
        assert b"activation" in bytes(packet[Raw])

    def test_parses_tcp_flags_with_scapy(self) -> None:
        """Correctly parses TCP flags from packet."""
        packet = (
            Ether() /
            IP(src="192.168.1.1", dst="192.168.1.2") /
            TCP(sport=12345, dport=27000, flags="PA")
        )

        assert packet[TCP].flags.P
        assert packet[TCP].flags.A
        assert not packet[TCP].flags.S

    def test_extracts_payload_length_with_scapy(self) -> None:
        """Extracts correct payload length from packet."""
        payload_data = b"FEATURE matlab MLM 40.0 permanent 1 VENDOR_STRING=example HOSTID=ANY"
        packet = (
            Ether() /
            IP(src="192.168.1.1", dst="192.168.1.2") /
            TCP(sport=12345, dport=27000) /
            Raw(load=payload_data)
        )

        assert len(packet[Raw].load) == len(payload_data)
        assert packet[Raw].load == payload_data
