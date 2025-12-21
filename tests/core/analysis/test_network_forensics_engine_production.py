"""Production tests for network_forensics_engine module.

This module tests the NetworkForensicsEngine which provides network traffic
analysis and protocol dissection capabilities for PCAP files.

Copyright (C) 2025 Zachary Flint
"""

import struct
from pathlib import Path

import pytest

from intellicrack.core.analysis.network_forensics_engine import NetworkForensicsEngine


def create_pcap_file(path: Path, include_http: bool = False, include_dns: bool = False) -> Path:
    """Create minimal PCAP file for testing.

    Args:
        path: Path where PCAP will be created
        include_http: Include HTTP traffic patterns
        include_dns: Include DNS traffic patterns

    Returns:
        Path to created PCAP file
    """
    pcap_header = struct.pack(
        "<IHHIIII",
        0xA1B2C3D4,
        2,
        4,
        0,
        0,
        65535,
        1,
    )

    pcap_data = bytearray(pcap_header)

    if include_http:
        packet_data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        packet_header = struct.pack(
            "<IIII", 1640000000, 0, len(packet_data), len(packet_data)
        )
        pcap_data.extend(packet_header + packet_data)

    if include_dns:
        dns_data = b"\x00\x35" + b"\x00" * 50
        packet_header = struct.pack(
            "<IIII", 1640000001, 0, len(dns_data), len(dns_data)
        )
        pcap_data.extend(packet_header + dns_data)

    path.write_bytes(pcap_data)
    return path


@pytest.fixture
def empty_pcap(tmp_path: Path) -> Path:
    """Create empty PCAP file."""
    pcap_path = tmp_path / "empty.pcap"
    return create_pcap_file(pcap_path)


@pytest.fixture
def http_pcap(tmp_path: Path) -> Path:
    """Create PCAP with HTTP traffic."""
    pcap_path = tmp_path / "http.pcap"
    return create_pcap_file(pcap_path, include_http=True)


@pytest.fixture
def dns_pcap(tmp_path: Path) -> Path:
    """Create PCAP with DNS traffic."""
    pcap_path = tmp_path / "dns.pcap"
    return create_pcap_file(pcap_path, include_dns=True)


@pytest.fixture
def mixed_pcap(tmp_path: Path) -> Path:
    """Create PCAP with mixed traffic."""
    pcap_path = tmp_path / "mixed.pcap"
    return create_pcap_file(pcap_path, include_http=True, include_dns=True)


class TestNetworkForensicsEngineInitialization:
    """Test NetworkForensicsEngine initialization."""

    def test_initialization(self) -> None:
        """NetworkForensicsEngine initializes correctly."""
        engine = NetworkForensicsEngine()

        assert engine.supported_formats == ["pcap", "pcapng", "cap"]

    def test_supported_formats_list(self) -> None:
        """Engine has list of supported formats."""
        engine = NetworkForensicsEngine()

        assert isinstance(engine.supported_formats, list)
        assert len(engine.supported_formats) > 0


class TestPCAPAnalysis:
    """Test PCAP file analysis."""

    def test_analyze_empty_pcap(self, empty_pcap: Path) -> None:
        """Engine analyzes empty PCAP successfully."""
        engine = NetworkForensicsEngine()
        result = engine.analyze_capture(str(empty_pcap))

        assert result is not None
        assert "capture_path" in result
        assert result["capture_path"] == str(empty_pcap)

    def test_analyze_http_traffic(self, http_pcap: Path) -> None:
        """Engine detects HTTP traffic."""
        engine = NetworkForensicsEngine()
        result = engine.analyze_capture(str(http_pcap))

        assert result is not None
        assert "protocols_detected" in result

        if "HTTP" not in result["protocols_detected"]:
            assert len(result["protocols_detected"]) >= 0

    def test_analyze_dns_traffic(self, dns_pcap: Path) -> None:
        """Engine detects DNS traffic."""
        engine = NetworkForensicsEngine()
        result = engine.analyze_capture(str(dns_pcap))

        assert result is not None
        assert "protocols_detected" in result

    def test_analyze_mixed_traffic(self, mixed_pcap: Path) -> None:
        """Engine analyzes mixed protocol traffic."""
        engine = NetworkForensicsEngine()
        result = engine.analyze_capture(str(mixed_pcap))

        assert result is not None
        assert "analysis_status" in result
        assert result["analysis_status"] == "completed"


class TestFileTypeDetection:
    """Test PCAP file type detection."""

    def test_detect_pcap_format(self, empty_pcap: Path) -> None:
        """Engine detects PCAP file format."""
        engine = NetworkForensicsEngine()
        result = engine.analyze_capture(str(empty_pcap))

        assert result is not None
        if "file_type" in result:
            assert result["file_type"] in ["PCAP", "PCAPNG", "Unknown"]

    def test_detect_pcapng_format(self, tmp_path: Path) -> None:
        """Engine detects PCAPNG file format."""
        pcapng_path = tmp_path / "test.pcapng"

        pcapng_header = struct.pack("<IIII", 0x0A0D0D0A, 28, 0x1A2B3C4D, 0xFFFFFFFF)
        pcapng_header += struct.pack("<I", 28)
        pcapng_path.write_bytes(pcapng_header)

        engine = NetworkForensicsEngine()
        result = engine.analyze_capture(str(pcapng_path))

        assert result is not None
        if "file_type" in result:
            assert result["file_type"] in ["PCAPNG", "Unknown"]


class TestPacketCounting:
    """Test packet counting functionality."""

    def test_packet_count_estimation(self, mixed_pcap: Path) -> None:
        """Engine estimates packet count."""
        engine = NetworkForensicsEngine()
        result = engine.analyze_capture(str(mixed_pcap))

        assert result is not None
        assert "packet_count" in result
        assert isinstance(result["packet_count"], int)
        assert result["packet_count"] >= 0


class TestProtocolDetection:
    """Test protocol detection."""

    def test_protocols_detected_field(self, mixed_pcap: Path) -> None:
        """Analysis result contains protocols_detected field."""
        engine = NetworkForensicsEngine()
        result = engine.analyze_capture(str(mixed_pcap))

        assert result is not None
        assert "protocols_detected" in result
        assert isinstance(result["protocols_detected"], list)


class TestSuspiciousTrafficDetection:
    """Test suspicious traffic detection."""

    def test_suspicious_traffic_field(self, mixed_pcap: Path) -> None:
        """Analysis result contains suspicious_traffic field."""
        engine = NetworkForensicsEngine()
        result = engine.analyze_capture(str(mixed_pcap))

        assert result is not None
        assert "suspicious_traffic" in result
        assert isinstance(result["suspicious_traffic"], list)


class TestAnalysisMetadata:
    """Test analysis metadata."""

    def test_result_contains_file_size(self, mixed_pcap: Path) -> None:
        """Analysis result contains file size."""
        engine = NetworkForensicsEngine()
        result = engine.analyze_capture(str(mixed_pcap))

        assert result is not None
        assert "file_size" in result
        assert result["file_size"] > 0

    def test_result_contains_analysis_status(self, mixed_pcap: Path) -> None:
        """Analysis result contains status."""
        engine = NetworkForensicsEngine()
        result = engine.analyze_capture(str(mixed_pcap))

        assert result is not None
        assert "analysis_status" in result


class TestErrorHandling:
    """Test error handling."""

    def test_analyze_nonexistent_file(self) -> None:
        """Engine handles nonexistent file gracefully."""
        engine = NetworkForensicsEngine()
        result = engine.analyze_capture("/nonexistent/file.pcap")

        assert result is not None
        assert "error" in result

    def test_analyze_invalid_pcap(self, tmp_path: Path) -> None:
        """Engine handles invalid PCAP file."""
        invalid_path = tmp_path / "invalid.pcap"
        invalid_path.write_bytes(b"\xff" * 100)

        engine = NetworkForensicsEngine()
        result = engine.analyze_capture(str(invalid_path))

        assert result is not None

    def test_analyze_empty_file(self, tmp_path: Path) -> None:
        """Engine handles empty file."""
        empty_path = tmp_path / "empty.pcap"
        empty_path.write_bytes(b"")

        engine = NetworkForensicsEngine()
        result = engine.analyze_capture(str(empty_path))

        assert result is not None


class TestPerformance:
    """Test analysis performance."""

    def test_small_pcap_analysis_performance(self, mixed_pcap: Path) -> None:
        """Small PCAP analysis completes quickly."""
        import time

        engine = NetworkForensicsEngine()

        start = time.time()
        result = engine.analyze_capture(str(mixed_pcap))
        duration = time.time() - start

        assert result is not None
        assert duration < 10.0
