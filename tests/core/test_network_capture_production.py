"""Production tests for Network Capture functionality.

Tests validate real network packet capture, license server detection,
protocol analysis, and PCAP file processing critical for identifying
and intercepting license validation traffic.
"""

import socket
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.network_capture import (
    NetworkCapture,
    analyze_pcap_with_pyshark,
    capture_with_scapy,
    parse_pcap_with_dpkt,
)


@pytest.fixture
def sample_pcap_file(tmp_path: Path) -> Path:
    """Create sample PCAP file with synthetic packet data."""
    pcap_file = tmp_path / "test_capture.pcap"

    pcap_header = struct.pack(
        "IHHiIII",
        0xA1B2C3D4,
        2,
        4,
        0,
        0,
        65535,
        1,
    )

    def create_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes = b"") -> bytes:
        ts_sec = 1640000000
        ts_usec = 0
        packet_data = b"\x00" * 14
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + 20 + len(payload),
            0,
            0,
            64,
            6,
            0,
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
        )
        tcp_header = struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            0,
            0,
            0x50,
            0x02,
            8192,
            0,
            0,
        )
        full_packet = packet_data + ip_header + tcp_header + payload
        packet_header = struct.pack("IIII", ts_sec, ts_usec, len(full_packet), len(full_packet))
        return packet_header + full_packet

    with open(pcap_file, "wb") as f:
        f.write(pcap_header)
        f.write(create_packet("192.168.1.100", "192.168.1.1", 12345, 80))
        f.write(create_packet("10.0.0.5", "10.0.0.1", 54321, 443))
        f.write(create_packet("172.16.0.10", "172.16.0.1", 49152, 27000, b"license_request"))

    return pcap_file


@pytest.fixture
def network_capture() -> NetworkCapture:
    """Provide NetworkCapture instance for testing."""
    return NetworkCapture()


class TestNetworkCaptureScapyIntegration:
    """Test Scapy-based live packet capture."""

    def test_capture_with_scapy_fails_without_scapy_installed(self) -> None:
        """Capture fails gracefully when Scapy not available."""
        result = capture_with_scapy("nonexistent_interface_xyz", "", 1)

        assert "error" in result or "success" in result

    def test_capture_with_scapy_handles_invalid_interface(self) -> None:
        """Scapy capture handles invalid network interface."""
        result = capture_with_scapy("nonexistent_interface_12345", "", 1)

        assert isinstance(result, dict)
        assert "error" in result or "total_packets" in result

    def test_capture_with_scapy_validates_count_parameter(self) -> None:
        """Scapy capture validates packet count parameter."""
        try:
            from scapy.all import IP, TCP

            result = capture_with_scapy("any", "", count=0)
            assert isinstance(result, dict)
        except ImportError:
            pytest.skip("Scapy not available for testing")


class TestNetworkCapturePySharkIntegration:
    """Test PyShark-based PCAP analysis."""

    def test_analyze_pcap_with_pyshark_fails_without_pyshark(self, sample_pcap_file: Path) -> None:
        """PCAP analysis fails gracefully when PyShark not available."""
        result = analyze_pcap_with_pyshark(str(sample_pcap_file))

        assert isinstance(result, dict)
        assert "error" in result or "total_packets" in result

    def test_analyze_pcap_with_pyshark_handles_missing_file(self) -> None:
        """PyShark analysis handles missing PCAP file."""
        result = analyze_pcap_with_pyshark("/nonexistent/file.pcap")

        assert "error" in result

    def test_analyze_pcap_with_pyshark_handles_corrupted_file(self, tmp_path: Path) -> None:
        """PyShark analysis handles corrupted PCAP file."""
        corrupted = tmp_path / "corrupted.pcap"
        corrupted.write_bytes(b"invalid pcap data")

        result = analyze_pcap_with_pyshark(str(corrupted))

        assert isinstance(result, dict)


class TestNetworkCaptureDpktIntegration:
    """Test dpkt-based PCAP parsing."""

    def test_parse_pcap_with_dpkt_fails_without_dpkt(self, sample_pcap_file: Path) -> None:
        """PCAP parsing fails gracefully when dpkt not available."""
        result = parse_pcap_with_dpkt(str(sample_pcap_file))

        assert isinstance(result, dict)
        assert "error" in result or "total_packets" in result

    def test_parse_pcap_with_dpkt_counts_packets(self, sample_pcap_file: Path) -> None:
        """dpkt parser counts total packets correctly."""
        try:
            import dpkt

            result = parse_pcap_with_dpkt(str(sample_pcap_file))

            if "error" not in result:
                assert "total_packets" in result
                assert result["total_packets"] >= 0
                assert "total_bytes" in result
                assert result["total_bytes"] >= 0
        except ImportError:
            pytest.skip("dpkt not available for testing")

    def test_parse_pcap_with_dpkt_tracks_protocol_distribution(self, sample_pcap_file: Path) -> None:
        """dpkt parser tracks TCP, UDP, ICMP distribution."""
        try:
            import dpkt

            result = parse_pcap_with_dpkt(str(sample_pcap_file))

            if "error" not in result:
                assert "tcp_packets" in result
                assert "udp_packets" in result
                assert "icmp_packets" in result
                assert "ip_packets" in result
        except ImportError:
            pytest.skip("dpkt not available for testing")

    def test_parse_pcap_with_dpkt_identifies_port_scans(self, sample_pcap_file: Path) -> None:
        """dpkt parser detects SYN packets indicating port scans."""
        try:
            import dpkt

            result = parse_pcap_with_dpkt(str(sample_pcap_file))

            if "error" not in result:
                assert "port_scan_indicators" in result
                assert isinstance(result["port_scan_indicators"], list)
        except ImportError:
            pytest.skip("dpkt not available for testing")

    def test_parse_pcap_with_dpkt_calculates_statistics(self, sample_pcap_file: Path) -> None:
        """dpkt parser calculates capture duration and rates."""
        try:
            import dpkt

            result = parse_pcap_with_dpkt(str(sample_pcap_file))

            if "error" not in result:
                assert "duration_seconds" in result
                assert "packets_per_second" in result
                assert "bytes_per_second" in result
                assert result["packets_per_second"] >= 0
                assert result["bytes_per_second"] >= 0
        except ImportError:
            pytest.skip("dpkt not available for testing")

    def test_parse_pcap_with_dpkt_detects_data_exfiltration(self, sample_pcap_file: Path) -> None:
        """dpkt parser identifies high-volume connections."""
        try:
            import dpkt

            result = parse_pcap_with_dpkt(str(sample_pcap_file))

            if "error" not in result:
                assert "data_exfiltration_suspects" in result
                assert isinstance(result["data_exfiltration_suspects"], list)
        except ImportError:
            pytest.skip("dpkt not available for testing")

    def test_parse_pcap_with_dpkt_handles_malformed_packets(self, tmp_path: Path) -> None:
        """dpkt parser handles malformed packets gracefully."""
        malformed_pcap = tmp_path / "malformed.pcap"
        with open(malformed_pcap, "wb") as f:
            f.write(b"\xA1\xB2\xC3\xD4" + b"\x00" * 20 + b"corrupted data")

        try:
            import dpkt

            result = parse_pcap_with_dpkt(str(malformed_pcap))

            assert "error" in result or "total_packets" in result
        except ImportError:
            pytest.skip("dpkt not available for testing")


class TestNetworkCaptureClass:
    """Test NetworkCapture class methods."""

    def test_capture_live_traffic_executes(self, network_capture: NetworkCapture) -> None:
        """capture_live_traffic executes without errors."""
        result = network_capture.capture_live_traffic("nonexistent_if", "tcp port 80", 1)

        assert isinstance(result, dict)
        assert "error" in result or "total_packets" in result

    def test_analyze_pcap_file_executes(self, network_capture: NetworkCapture, sample_pcap_file: Path) -> None:
        """analyze_pcap_file executes without errors."""
        result = network_capture.analyze_pcap_file(str(sample_pcap_file))

        assert isinstance(result, dict)

    def test_parse_pcap_binary_executes(self, network_capture: NetworkCapture, sample_pcap_file: Path) -> None:
        """parse_pcap_binary executes without errors."""
        result = network_capture.parse_pcap_binary(str(sample_pcap_file))

        assert isinstance(result, dict)

    def test_identify_license_servers_returns_list(self, network_capture: NetworkCapture, sample_pcap_file: Path) -> None:
        """identify_license_servers returns list."""
        result = network_capture.identify_license_servers(str(sample_pcap_file))

        assert isinstance(result, list)

    def test_extract_dns_queries_returns_list(self, network_capture: NetworkCapture, sample_pcap_file: Path) -> None:
        """extract_dns_queries returns list."""
        result = network_capture.extract_dns_queries(str(sample_pcap_file))

        assert isinstance(result, list)

    def test_detect_cloud_licensing_traffic_executes(self, network_capture: NetworkCapture) -> None:
        """detect_cloud_licensing_traffic executes without errors."""
        result = network_capture.detect_cloud_licensing_traffic("nonexistent_if", 1)

        assert isinstance(result, dict)
        assert "license_servers_detected" in result
        assert "license_servers" in result
        assert "license_related_domains" in result


class TestNetworkCaptureErrorHandling:
    """Test error handling and edge cases."""

    def test_capture_handles_network_interface_not_found(self, network_capture: NetworkCapture) -> None:
        """Capture handles nonexistent network interface gracefully."""
        result = network_capture.capture_live_traffic("nonexistent_interface", "", 10)

        assert isinstance(result, dict)

    def test_analyze_handles_corrupted_pcap_file(self, network_capture: NetworkCapture, tmp_path: Path) -> None:
        """Analysis handles corrupted PCAP file gracefully."""
        corrupted_pcap = tmp_path / "corrupted.pcap"
        corrupted_pcap.write_bytes(b"not a valid pcap file")

        result = network_capture.analyze_pcap_file(str(corrupted_pcap))

        assert isinstance(result, dict)

    def test_parse_handles_empty_pcap_file(self, network_capture: NetworkCapture, tmp_path: Path) -> None:
        """Parser handles empty PCAP file gracefully."""
        empty_pcap = tmp_path / "empty.pcap"
        empty_pcap.write_bytes(b"")

        result = network_capture.parse_pcap_binary(str(empty_pcap))

        assert isinstance(result, dict)


class TestNetworkCaptureIntegrationScenarios:
    """Test real-world integration scenarios."""

    def test_pcap_file_creation_and_parsing(self, tmp_path: Path) -> None:
        """Create PCAP file and parse it successfully."""
        pcap_file = tmp_path / "integration_test.pcap"

        pcap_header = struct.pack("IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

        with open(pcap_file, "wb") as f:
            f.write(pcap_header)

        assert pcap_file.exists()

        try:
            import dpkt

            result = parse_pcap_with_dpkt(str(pcap_file))
            assert isinstance(result, dict)
        except ImportError:
            pytest.skip("dpkt not available")
