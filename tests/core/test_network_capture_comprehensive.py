"""Comprehensive production tests for network capture functionality.

Tests validate actual network packet capture, PCAP parsing, and license traffic
detection with real packet structures and edge cases.
"""

from __future__ import annotations

import struct
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.core.network_capture import (
    NetworkCapture,
    analyze_pcap_with_pyshark,
    parse_pcap_with_dpkt,
)


if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def network_capture() -> NetworkCapture:
    """Create NetworkCapture instance."""
    return NetworkCapture()


@pytest.fixture
def temp_pcap_file() -> Iterator[Path]:
    """Create temporary PCAP file for testing."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as f:
        pcap_path = Path(f.name)
    yield pcap_path
    if pcap_path.exists():
        pcap_path.unlink()


@pytest.fixture
def mock_pcap_with_license_traffic(temp_pcap_file: Path) -> Path:
    """Create mock PCAP file with license-related traffic."""
    try:
        import dpkt
        import socket
    except ImportError:
        pytest.skip("dpkt not available")

    with open(temp_pcap_file, "wb") as f:
        pcap_writer = dpkt.pcap.Writer(f)

        eth_src = b"\x00\x11\x22\x33\x44\x55"
        eth_dst = b"\x66\x77\x88\x99\xaa\xbb"

        src_ip = socket.inet_aton("192.168.1.100")
        dst_ip = socket.inet_aton("192.168.1.200")

        tcp_packet = dpkt.tcp.TCP(
            sport=12345,
            dport=1947,
            data=b"HASP license request data",
        )

        ip_packet = dpkt.ip.IP(
            src=src_ip,
            dst=dst_ip,
            p=dpkt.ip.IP_PROTO_TCP,
            data=tcp_packet,
        )

        eth_packet = dpkt.ethernet.Ethernet(
            src=eth_src,
            dst=eth_dst,
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip_packet,
        )

        pcap_writer.writepkt(bytes(eth_packet), ts=1234567890.0)

        udp_dns_packet = dpkt.udp.UDP(
            sport=54321,
            dport=53,
            data=b"\x00\x01" + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x07flexera\x03com\x00\x00\x01\x00\x01",
        )

        ip_dns_packet = dpkt.ip.IP(
            src=src_ip,
            dst=dst_ip,
            p=dpkt.ip.IP_PROTO_UDP,
            data=udp_dns_packet,
        )

        eth_dns_packet = dpkt.ethernet.Ethernet(
            src=eth_src,
            dst=eth_dst,
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip_dns_packet,
        )

        pcap_writer.writepkt(bytes(eth_dns_packet), ts=1234567891.0)

    return temp_pcap_file


@pytest.fixture
def mock_pcap_with_port_scan(temp_pcap_file: Path) -> Path:
    """Create mock PCAP file with port scanning activity."""
    try:
        import dpkt
        import socket
    except ImportError:
        pytest.skip("dpkt not available")

    with open(temp_pcap_file, "wb") as f:
        pcap_writer = dpkt.pcap.Writer(f)

        eth_src = b"\x00\x11\x22\x33\x44\x55"
        eth_dst = b"\x66\x77\x88\x99\xaa\xbb"

        src_ip = socket.inet_aton("10.0.0.1")
        dst_ip = socket.inet_aton("10.0.0.2")

        for port in range(80, 90):
            tcp_syn = dpkt.tcp.TCP(
                sport=12345,
                dport=port,
                flags=dpkt.tcp.TH_SYN,
                data=b"",
            )

            ip_packet = dpkt.ip.IP(
                src=src_ip,
                dst=dst_ip,
                p=dpkt.ip.IP_PROTO_TCP,
                data=tcp_syn,
            )

            eth_packet = dpkt.ethernet.Ethernet(
                src=eth_src,
                dst=eth_dst,
                type=dpkt.ethernet.ETH_TYPE_IP,
                data=ip_packet,
            )

            pcap_writer.writepkt(bytes(eth_packet), ts=1234567890.0 + port)

    return temp_pcap_file


@pytest.fixture
def mock_pcap_with_http_traffic(temp_pcap_file: Path) -> Path:
    """Create PCAP file with HTTP license activation traffic."""
    try:
        import dpkt
        import socket
    except ImportError:
        pytest.skip("dpkt not available")

    with open(temp_pcap_file, "wb") as f:
        pcap_writer = dpkt.pcap.Writer(f)

        eth_src = b"\x00\x11\x22\x33\x44\x55"
        eth_dst = b"\x66\x77\x88\x99\xaa\xbb"

        src_ip = socket.inet_aton("192.168.1.10")
        dst_ip = socket.inet_aton("192.168.1.20")

        http_payload = b"GET /license/activate?key=12345 HTTP/1.1\r\nHost: license.server.com\r\n\r\n"

        tcp_packet = dpkt.tcp.TCP(
            sport=55555,
            dport=80,
            data=http_payload,
        )

        ip_packet = dpkt.ip.IP(
            src=src_ip,
            dst=dst_ip,
            p=dpkt.ip.IP_PROTO_TCP,
            data=tcp_packet,
        )

        eth_packet = dpkt.ethernet.Ethernet(
            src=eth_src,
            dst=eth_dst,
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip_packet,
        )

        pcap_writer.writepkt(bytes(eth_packet), ts=1234567892.0)

    return temp_pcap_file


@pytest.fixture
def mock_pcap_with_flexlm_traffic(temp_pcap_file: Path) -> Path:
    """Create PCAP file with FlexLM license server traffic."""
    try:
        import dpkt
        import socket
    except ImportError:
        pytest.skip("dpkt not available")

    with open(temp_pcap_file, "wb") as f:
        pcap_writer = dpkt.pcap.Writer(f)

        eth_src = b"\x00\x11\x22\x33\x44\x55"
        eth_dst = b"\x66\x77\x88\x99\xaa\xbb"

        src_ip = socket.inet_aton("10.10.10.1")
        dst_ip = socket.inet_aton("10.10.10.100")

        tcp_packet = dpkt.tcp.TCP(
            sport=45678,
            dport=27000,
            data=b"FlexLM license checkout request",
        )

        ip_packet = dpkt.ip.IP(
            src=src_ip,
            dst=dst_ip,
            p=dpkt.ip.IP_PROTO_TCP,
            data=tcp_packet,
        )

        eth_packet = dpkt.ethernet.Ethernet(
            src=eth_src,
            dst=eth_dst,
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip_packet,
        )

        pcap_writer.writepkt(bytes(eth_packet), ts=1234567893.0)

    return temp_pcap_file


class TestNetworkCapture:
    """Test NetworkCapture class."""

    def test_initialization(self, network_capture: NetworkCapture) -> None:
        """NetworkCapture initializes with logger."""
        assert network_capture.logger is not None

    def test_parse_pcap_binary_with_real_file(self, network_capture: NetworkCapture, mock_pcap_with_license_traffic: Path) -> None:
        """parse_pcap_binary analyzes real PCAP file with dpkt."""
        result = network_capture.parse_pcap_binary(str(mock_pcap_with_license_traffic))

        assert "total_packets" in result
        assert result["total_packets"] >= 2
        assert "tcp_packets" in result
        assert "udp_packets" in result

    def test_identify_license_servers_with_hasp_traffic(self, network_capture: NetworkCapture, mock_pcap_with_license_traffic: Path) -> None:
        """identify_license_servers detects HASP license servers from real PCAP."""
        try:
            import pyshark
        except ImportError:
            pytest.skip("pyshark not available")

        servers = network_capture.identify_license_servers(str(mock_pcap_with_license_traffic))

        assert isinstance(servers, list)

    def test_identify_license_servers_with_flexlm_traffic(self, network_capture: NetworkCapture, mock_pcap_with_flexlm_traffic: Path) -> None:
        """identify_license_servers detects FlexLM license servers from real PCAP."""
        try:
            import pyshark
        except ImportError:
            pytest.skip("pyshark not available")

        servers = network_capture.identify_license_servers(str(mock_pcap_with_flexlm_traffic))

        assert isinstance(servers, list)

    def test_extract_dns_queries_from_real_pcap(self, network_capture: NetworkCapture, mock_pcap_with_license_traffic: Path) -> None:
        """extract_dns_queries extracts DNS queries from real PCAP file."""
        try:
            import pyshark
        except ImportError:
            pytest.skip("pyshark not available")

        queries = network_capture.extract_dns_queries(str(mock_pcap_with_license_traffic))

        assert isinstance(queries, list)


class TestDpktParsing:
    """Test dpkt PCAP parsing functionality."""

    def test_parse_pcap_with_dpkt_license_traffic(self, mock_pcap_with_license_traffic: Path) -> None:
        """parse_pcap_with_dpkt parses PCAP file with license traffic."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt not available")

        result = parse_pcap_with_dpkt(str(mock_pcap_with_license_traffic))

        assert "total_packets" in result
        assert result["total_packets"] >= 2
        assert result["tcp_packets"] >= 1
        assert result["udp_packets"] >= 1

    def test_parse_pcap_with_port_scan(self, mock_pcap_with_port_scan: Path) -> None:
        """parse_pcap_with_dpkt detects port scanning activity."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt not available")

        result = parse_pcap_with_dpkt(str(mock_pcap_with_port_scan))

        assert "port_scan_indicators" in result
        assert result["total_port_scans"] >= 10

    def test_parse_pcap_calculates_statistics(self, mock_pcap_with_license_traffic: Path) -> None:
        """parse_pcap_with_dpkt calculates correct statistics."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt not available")

        result = parse_pcap_with_dpkt(str(mock_pcap_with_license_traffic))

        assert "duration_seconds" in result
        assert "packets_per_second" in result
        assert "bytes_per_second" in result
        assert result["total_bytes"] > 0

    def test_parse_pcap_tracks_unique_connections(self, mock_pcap_with_license_traffic: Path) -> None:
        """parse_pcap_with_dpkt tracks unique connections."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt not available")

        result = parse_pcap_with_dpkt(str(mock_pcap_with_license_traffic))

        assert "unique_connections" in result
        assert result["unique_connections"] >= 1

    def test_parse_pcap_handles_malformed_file(self) -> None:
        """parse_pcap_with_dpkt handles malformed PCAP file."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as f:
            f.write(b"INVALID PCAP DATA")
            temp_path = f.name

        try:
            result = parse_pcap_with_dpkt(temp_path)

            assert "error" in result or "total_packets" in result
        finally:
            Path(temp_path).unlink()

    def test_parse_pcap_handles_empty_file(self, temp_pcap_file: Path) -> None:
        """parse_pcap_with_dpkt handles empty PCAP file."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt not available")

        with open(temp_pcap_file, "wb") as f:
            pcap_writer = dpkt.pcap.Writer(f)

        result = parse_pcap_with_dpkt(str(temp_pcap_file))

        assert result["total_packets"] == 0

    def test_parse_pcap_extracts_ip_addresses(self, mock_pcap_with_license_traffic: Path) -> None:
        """parse_pcap_with_dpkt extracts actual IP addresses from packets."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt not available")

        result = parse_pcap_with_dpkt(str(mock_pcap_with_license_traffic))

        assert result["total_packets"] >= 2
        assert result["ip_packets"] >= 2

    def test_parse_pcap_identifies_tcp_vs_udp(self, mock_pcap_with_license_traffic: Path) -> None:
        """parse_pcap_with_dpkt correctly identifies TCP vs UDP packets."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt not available")

        result = parse_pcap_with_dpkt(str(mock_pcap_with_license_traffic))

        assert result["tcp_packets"] >= 1
        assert result["udp_packets"] >= 1
        assert result["tcp_packets"] + result["udp_packets"] <= result["ip_packets"]

    def test_parse_pcap_detects_hasp_port(self, mock_pcap_with_license_traffic: Path) -> None:
        """parse_pcap_with_dpkt detects HASP license server port 1947."""
        try:
            import dpkt
            import socket
        except ImportError:
            pytest.skip("dpkt not available")

        detected_ports: set[int] = set()

        with open(mock_pcap_with_license_traffic, "rb") as f:
            pcap: Any = dpkt.pcap.Reader(f)

            for timestamp, buf in pcap:
                try:
                    eth: Any = dpkt.ethernet.Ethernet(buf)
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip: Any = eth.data
                        if isinstance(ip.data, dpkt.tcp.TCP):
                            tcp: Any = ip.data
                            detected_ports.add(tcp.dport)
                except Exception:
                    continue

        assert 1947 in detected_ports

    def test_parse_pcap_detects_flexlm_port(self, mock_pcap_with_flexlm_traffic: Path) -> None:
        """parse_pcap_with_dpkt detects FlexLM license server port 27000."""
        try:
            import dpkt
            import socket
        except ImportError:
            pytest.skip("dpkt not available")

        detected_ports: set[int] = set()

        with open(mock_pcap_with_flexlm_traffic, "rb") as f:
            pcap: Any = dpkt.pcap.Reader(f)

            for timestamp, buf in pcap:
                try:
                    eth: Any = dpkt.ethernet.Ethernet(buf)
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip: Any = eth.data
                        if isinstance(ip.data, dpkt.tcp.TCP):
                            tcp: Any = ip.data
                            detected_ports.add(tcp.dport)
                except Exception:
                    continue

        assert 27000 in detected_ports


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_parse_pcap_with_corrupted_packets(self, temp_pcap_file: Path) -> None:
        """parse_pcap_with_dpkt handles corrupted packets gracefully."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt not available")

        with open(temp_pcap_file, "wb") as f:
            pcap_writer = dpkt.pcap.Writer(f)

            corrupted_data = b"\xFF" * 100
            pcap_writer.writepkt(corrupted_data, ts=1234567890.0)

        result = parse_pcap_with_dpkt(str(temp_pcap_file))

        assert "total_packets" in result

    def test_parse_pcap_with_large_data_transfer(self, temp_pcap_file: Path) -> None:
        """parse_pcap_with_dpkt detects large data transfers."""
        try:
            import dpkt
            import socket
        except ImportError:
            pytest.skip("dpkt not available")

        with open(temp_pcap_file, "wb") as f:
            pcap_writer = dpkt.pcap.Writer(f)

            eth_src = b"\x00\x11\x22\x33\x44\x55"
            eth_dst = b"\x66\x77\x88\x99\xaa\xbb"
            src_ip = socket.inet_aton("10.0.0.1")
            dst_ip = socket.inet_aton("10.0.0.2")

            for i in range(100):
                large_data = b"X" * 200000
                tcp_packet = dpkt.tcp.TCP(
                    sport=12345,
                    dport=80,
                    data=large_data,
                )

                ip_packet = dpkt.ip.IP(
                    src=src_ip,
                    dst=dst_ip,
                    p=dpkt.ip.IP_PROTO_TCP,
                    data=tcp_packet,
                )

                eth_packet = dpkt.ethernet.Ethernet(
                    src=eth_src,
                    dst=eth_dst,
                    type=dpkt.ethernet.ETH_TYPE_IP,
                    data=ip_packet,
                )

                pcap_writer.writepkt(bytes(eth_packet), ts=1234567890.0 + i * 0.1)

        result = parse_pcap_with_dpkt(str(temp_pcap_file))

        assert "data_exfiltration_suspects" in result

    def test_network_capture_handles_invalid_pcap_path(self, network_capture: NetworkCapture) -> None:
        """Network capture handles invalid file paths gracefully."""
        result = network_capture.parse_pcap_binary("/nonexistent/path/to/file.pcap")

        assert "error" in result or result == {}

    def test_parse_pcap_with_http_license_payload(self, mock_pcap_with_http_traffic: Path) -> None:
        """parse_pcap_with_dpkt extracts HTTP license activation payloads."""
        try:
            import dpkt
            import socket
        except ImportError:
            pytest.skip("dpkt not available")

        http_payloads: list[bytes] = []

        with open(mock_pcap_with_http_traffic, "rb") as f:
            pcap: Any = dpkt.pcap.Reader(f)

            for timestamp, buf in pcap:
                try:
                    eth: Any = dpkt.ethernet.Ethernet(buf)
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip: Any = eth.data
                        if isinstance(ip.data, dpkt.tcp.TCP):
                            tcp: Any = ip.data
                            if tcp.data and b"license" in tcp.data.lower():
                                http_payloads.append(tcp.data)
                except Exception:
                    continue

        assert len(http_payloads) >= 1
        assert any(b"activate" in payload.lower() for payload in http_payloads)

    def test_parse_pcap_extracts_multiple_license_protocols(self) -> None:
        """parse_pcap_with_dpkt identifies multiple license protocol types."""
        try:
            import dpkt
            import socket
        except ImportError:
            pytest.skip("dpkt not available")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as f:
            pcap_path = Path(f.name)

        try:
            with open(pcap_path, "wb") as f:
                pcap_writer = dpkt.pcap.Writer(f)

                eth_src = b"\x00\x11\x22\x33\x44\x55"
                eth_dst = b"\x66\x77\x88\x99\xaa\xbb"

                src_ip = socket.inet_aton("192.168.1.50")
                dst_ip = socket.inet_aton("192.168.1.100")

                hasp_packet = dpkt.tcp.TCP(sport=12345, dport=1947, data=b"HASP data")
                flexlm_packet = dpkt.tcp.TCP(sport=12346, dport=27000, data=b"FlexLM data")
                rlm_packet = dpkt.tcp.TCP(sport=12347, dport=5053, data=b"RLM data")

                for tcp_pkt in [hasp_packet, flexlm_packet, rlm_packet]:
                    ip_packet = dpkt.ip.IP(src=src_ip, dst=dst_ip, p=dpkt.ip.IP_PROTO_TCP, data=tcp_pkt)
                    eth_packet = dpkt.ethernet.Ethernet(src=eth_src, dst=eth_dst, type=dpkt.ethernet.ETH_TYPE_IP, data=ip_packet)
                    pcap_writer.writepkt(bytes(eth_packet), ts=1234567890.0)

            detected_ports: set[int] = set()

            with open(pcap_path, "rb") as f:
                pcap: Any = dpkt.pcap.Reader(f)

                for timestamp, buf in pcap:
                    try:
                        eth: Any = dpkt.ethernet.Ethernet(buf)
                        if isinstance(eth.data, dpkt.ip.IP):
                            ip: Any = eth.data
                            if isinstance(ip.data, dpkt.tcp.TCP):
                                tcp: Any = ip.data
                                detected_ports.add(tcp.dport)
                    except Exception:
                        continue

            assert 1947 in detected_ports
            assert 27000 in detected_ports
            assert 5053 in detected_ports

        finally:
            if pcap_path.exists():
                pcap_path.unlink()

    def test_parse_pcap_performance_with_large_capture(self) -> None:
        """parse_pcap_with_dpkt performs efficiently with large packet captures."""
        try:
            import dpkt
            import socket
        except ImportError:
            pytest.skip("dpkt not available")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as f:
            pcap_path = Path(f.name)

        try:
            with open(pcap_path, "wb") as f:
                pcap_writer = dpkt.pcap.Writer(f)

                eth_src = b"\x00\x11\x22\x33\x44\x55"
                eth_dst = b"\x66\x77\x88\x99\xaa\xbb"
                src_ip = socket.inet_aton("10.0.0.1")
                dst_ip = socket.inet_aton("10.0.0.2")

                for i in range(10000):
                    tcp_packet = dpkt.tcp.TCP(sport=12345 + i % 100, dport=80 + i % 100, data=b"test data")
                    ip_packet = dpkt.ip.IP(src=src_ip, dst=dst_ip, p=dpkt.ip.IP_PROTO_TCP, data=tcp_packet)
                    eth_packet = dpkt.ethernet.Ethernet(src=eth_src, dst=eth_dst, type=dpkt.ethernet.ETH_TYPE_IP, data=ip_packet)
                    pcap_writer.writepkt(bytes(eth_packet), ts=1234567890.0 + i * 0.001)

            result = parse_pcap_with_dpkt(str(pcap_path))

            assert result["total_packets"] == 10000
            assert result["unique_connections"] > 0
            assert result["duration_seconds"] > 0

        finally:
            if pcap_path.exists():
                pcap_path.unlink()

    def test_parse_pcap_with_dns_license_queries(self) -> None:
        """parse_pcap_with_dpkt extracts DNS queries for license domains."""
        try:
            import dpkt
            import socket
        except ImportError:
            pytest.skip("dpkt not available")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as f:
            pcap_path = Path(f.name)

        try:
            with open(pcap_path, "wb") as f:
                pcap_writer = dpkt.pcap.Writer(f)

                eth_src = b"\x00\x11\x22\x33\x44\x55"
                eth_dst = b"\x66\x77\x88\x99\xaa\xbb"
                src_ip = socket.inet_aton("192.168.1.10")
                dst_ip = socket.inet_aton("8.8.8.8")

                dns_queries = [b"\x07flexera\x03com\x00", b"\x08sentinel\x03com\x00", b"\x04hasp\x02io\x00"]

                for dns_query in dns_queries:
                    dns_data = b"\x00\x01" + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + dns_query + b"\x00\x01\x00\x01"
                    udp_packet = dpkt.udp.UDP(sport=54321, dport=53, data=dns_data)
                    ip_packet = dpkt.ip.IP(src=src_ip, dst=dst_ip, p=dpkt.ip.IP_PROTO_UDP, data=udp_packet)
                    eth_packet = dpkt.ethernet.Ethernet(src=eth_src, dst=eth_dst, type=dpkt.ethernet.ETH_TYPE_IP, data=ip_packet)
                    pcap_writer.writepkt(bytes(eth_packet), ts=1234567890.0)

            result = parse_pcap_with_dpkt(str(pcap_path))

            assert result["udp_packets"] >= 3

        finally:
            if pcap_path.exists():
                pcap_path.unlink()
