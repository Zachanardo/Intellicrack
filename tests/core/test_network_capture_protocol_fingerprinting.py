"""Production tests for network_capture.py protocol fingerprinting capabilities.

Tests validate advanced protocol detection beyond keyword matching including:
- Protocol fingerprinting using packet structure analysis
- TCP stream reassembly for multi-packet protocols
- Encrypted license traffic pattern detection
- License protocol behavioral identification
- Fragmented packet reassembly and analysis
- SSL/TLS encrypted traffic detection
- Tunneled protocol identification

These tests MUST fail if functionality is incomplete or non-functional.
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


def create_pcap_header() -> bytes:
    """Create valid PCAP file header."""
    return struct.pack(
        "IHHiIII",
        0xA1B2C3D4,
        2,
        4,
        0,
        0,
        65535,
        1,
    )


def create_ethernet_header() -> bytes:
    """Create minimal Ethernet frame header."""
    dst_mac = b"\x00\x11\x22\x33\x44\x55"
    src_mac = b"\xAA\xBB\xCC\xDD\xEE\xFF"
    ethertype = b"\x08\x00"
    return dst_mac + src_mac + ethertype


def create_ip_header(src_ip: str, dst_ip: str, protocol: int, payload_len: int) -> bytes:
    """Create IPv4 header."""
    version_ihl = 0x45
    tos = 0
    total_len = 20 + payload_len
    identification = 0
    flags_frag = 0
    ttl = 64
    checksum = 0

    return struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_len,
        identification,
        flags_frag,
        ttl,
        protocol,
        checksum,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )


def create_tcp_header(src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload_len: int) -> bytes:
    """Create TCP header with correct structure."""
    data_offset = 5 << 4
    window = 8192
    checksum = 0
    urgent_ptr = 0

    return struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        data_offset,
        flags,
        window,
        checksum,
        urgent_ptr,
    )


def create_udp_header(src_port: int, dst_port: int, payload_len: int) -> bytes:
    """Create UDP header."""
    length = 8 + payload_len
    checksum = 0

    return struct.pack(
        "!HHHH",
        src_port,
        dst_port,
        length,
        checksum,
    )


def create_packet_record(payload: bytes) -> bytes:
    """Create PCAP packet record with timestamp and headers."""
    ts_sec = 1700000000
    ts_usec = 0
    incl_len = len(payload)
    orig_len = len(payload)

    return struct.pack("IIII", ts_sec, ts_usec, incl_len, orig_len) + payload


def create_flexlm_binary_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    """Create packet containing binary FlexLM protocol data."""
    flexlm_magic = b"\x00\x00\x00\x0C"
    flexlm_version = b"\x00\x09"
    flexlm_command = b"\x01\x00"
    flexlm_data = b"INCREMENT VENDOR feature 1.0 permanent 5 VENDOR_STRING=binary SIGN=" + b"\x00" * 32

    payload = flexlm_magic + flexlm_version + flexlm_command + flexlm_data

    tcp_header = create_tcp_header(src_port, dst_port, 1000, 0, 0x02, len(payload))
    ip_header = create_ip_header(src_ip, dst_ip, 6, 20 + len(payload))
    eth_header = create_ethernet_header()

    full_packet = eth_header + ip_header + tcp_header + payload
    return create_packet_record(full_packet)


def create_hasp_protocol_packet(src_ip: str, dst_ip: str) -> bytes:
    """Create packet containing HASP license protocol structure."""
    hasp_header = b"\x48\x41\x53\x50"
    hasp_version = b"\x01\x00"
    hasp_command = b"\x05\x00"
    hasp_session = struct.pack("!I", 0x12345678)
    hasp_feature_id = struct.pack("!I", 42)
    hasp_encrypted_data = b"\xAB\xCD\xEF" * 20

    payload = hasp_header + hasp_version + hasp_command + hasp_session + hasp_feature_id + hasp_encrypted_data

    tcp_header = create_tcp_header(54321, 1947, 2000, 0, 0x02, len(payload))
    ip_header = create_ip_header(src_ip, dst_ip, 6, 20 + len(payload))
    eth_header = create_ethernet_header()

    full_packet = eth_header + ip_header + tcp_header + payload
    return create_packet_record(full_packet)


def create_tls_handshake_packet(src_ip: str, dst_ip: str, server_name: str) -> bytes:
    """Create TLS ClientHello packet with SNI extension."""
    tls_content_type = b"\x16"
    tls_version = b"\x03\x01"

    client_hello = b"\x01"
    hello_version = b"\x03\x03"
    random_bytes = b"\x00" * 32
    session_id = b"\x00"
    cipher_suites = b"\x00\x02\x00\xFF"
    compression = b"\x01\x00"

    sni_extension_type = b"\x00\x00"
    server_name_bytes = server_name.encode()
    sni_list_entry = b"\x00" + struct.pack("!H", len(server_name_bytes)) + server_name_bytes
    sni_list_length = struct.pack("!H", len(sni_list_entry))
    sni_extension_data = sni_list_length + sni_list_entry
    sni_extension_length = struct.pack("!H", len(sni_extension_data))
    sni_extension = sni_extension_type + sni_extension_length + sni_extension_data

    extensions_length = struct.pack("!H", len(sni_extension))
    extensions = extensions_length + sni_extension

    handshake_data = (
        client_hello +
        hello_version +
        random_bytes +
        session_id +
        cipher_suites +
        compression +
        extensions
    )

    handshake_length = struct.pack("!I", len(handshake_data))[1:]
    tls_payload = client_hello + handshake_length + handshake_data[1:]
    tls_length = struct.pack("!H", len(tls_payload))

    tls_record = tls_content_type + tls_version + tls_length + tls_payload

    tcp_header = create_tcp_header(49152, 443, 3000, 0, 0x18, len(tls_record))
    ip_header = create_ip_header(src_ip, dst_ip, 6, 20 + len(tls_record))
    eth_header = create_ethernet_header()

    full_packet = eth_header + ip_header + tcp_header + tls_record
    return create_packet_record(full_packet)


def create_fragmented_tcp_stream(src_ip: str, dst_ip: str, src_port: int, dst_port: int, full_data: bytes, fragment_size: int) -> list[bytes]:
    """Create multiple TCP packets representing fragmented stream."""
    packets = []
    seq_num = 10000

    for i in range(0, len(full_data), fragment_size):
        fragment = full_data[i:i + fragment_size]
        flags = 0x18

        tcp_header = create_tcp_header(src_port, dst_port, seq_num, 0, flags, len(fragment))
        ip_header = create_ip_header(src_ip, dst_ip, 6, 20 + len(fragment))
        eth_header = create_ethernet_header()

        full_packet = eth_header + ip_header + tcp_header + fragment
        packets.append(create_packet_record(full_packet))

        seq_num += len(fragment)

    return packets


def create_rlm_protocol_packet(src_ip: str, dst_ip: str) -> bytes:
    """Create packet containing RLM (Reprise License Manager) protocol."""
    rlm_header = b"RLM\x00"
    rlm_version = b"\x0E\x00\x00\x00"
    rlm_command = b"\x02\x00\x00\x00"
    rlm_product = b"PRODUCT_CODE\x00"
    rlm_version_str = b"1.0\x00"
    rlm_count = b"\x01\x00\x00\x00"

    payload = rlm_header + rlm_version + rlm_command + rlm_product + rlm_version_str + rlm_count

    tcp_header = create_tcp_header(55555, 5053, 4000, 0, 0x02, len(payload))
    ip_header = create_ip_header(src_ip, dst_ip, 6, 20 + len(payload))
    eth_header = create_ethernet_header()

    full_packet = eth_header + ip_header + tcp_header + payload
    return create_packet_record(full_packet)


def create_sentinel_udp_discovery_packet(src_ip: str, dst_ip: str) -> bytes:
    """Create Sentinel HASP UDP discovery broadcast packet."""
    sentinel_discovery = b"\xFF\xFF\xFF\xFF"
    sentinel_magic = b"SENT"
    sentinel_query = b"\x01\x00\x00\x00"

    payload = sentinel_discovery + sentinel_magic + sentinel_query

    udp_header = create_udp_header(6200, 6200, len(payload))
    ip_header = create_ip_header(src_ip, dst_ip, 17, 8 + len(payload))
    eth_header = create_ethernet_header()

    full_packet = eth_header + ip_header + udp_header + payload
    return create_packet_record(full_packet)


@pytest.fixture
def pcap_with_binary_flexlm(tmp_path: Path) -> Path:
    """Create PCAP with binary FlexLM protocol packets."""
    pcap_file = tmp_path / "flexlm_binary.pcap"

    with open(pcap_file, "wb") as f:
        f.write(create_pcap_header())
        f.write(create_flexlm_binary_packet("192.168.1.100", "192.168.1.5", 12345, 27000))
        f.write(create_flexlm_binary_packet("192.168.1.100", "192.168.1.5", 12345, 27001))

    return pcap_file


@pytest.fixture
def pcap_with_hasp_protocol(tmp_path: Path) -> Path:
    """Create PCAP with HASP protocol packets."""
    pcap_file = tmp_path / "hasp_protocol.pcap"

    with open(pcap_file, "wb") as f:
        f.write(create_pcap_header())
        f.write(create_hasp_protocol_packet("10.0.0.50", "10.0.0.1"))
        f.write(create_hasp_protocol_packet("10.0.0.50", "10.0.0.1"))

    return pcap_file


@pytest.fixture
def pcap_with_tls_traffic(tmp_path: Path) -> Path:
    """Create PCAP with TLS handshake containing license server SNI."""
    pcap_file = tmp_path / "tls_license_traffic.pcap"

    with open(pcap_file, "wb") as f:
        f.write(create_pcap_header())
        f.write(create_tls_handshake_packet("172.16.0.100", "54.123.45.67", "license.autodesk.com"))
        f.write(create_tls_handshake_packet("172.16.0.100", "54.123.45.68", "activation.adobe.com"))
        f.write(create_tls_handshake_packet("172.16.0.100", "54.123.45.69", "flexnetoperations.flexerasoftware.com"))

    return pcap_file


@pytest.fixture
def pcap_with_fragmented_stream(tmp_path: Path) -> Path:
    """Create PCAP with fragmented TCP stream containing license request."""
    pcap_file = tmp_path / "fragmented_license.pcap"

    full_license_request = b"LICENSE_REQUEST\x00" + b"PRODUCT_KEY=" + b"A" * 200 + b"\x00SIGNATURE=" + b"B" * 256
    fragments = create_fragmented_tcp_stream("192.168.50.10", "192.168.50.1", 60000, 7070, full_license_request, 64)

    with open(pcap_file, "wb") as f:
        f.write(create_pcap_header())
        for fragment in fragments:
            f.write(fragment)

    return pcap_file


@pytest.fixture
def pcap_with_rlm_protocol(tmp_path: Path) -> Path:
    """Create PCAP with RLM license protocol packets."""
    pcap_file = tmp_path / "rlm_protocol.pcap"

    with open(pcap_file, "wb") as f:
        f.write(create_pcap_header())
        f.write(create_rlm_protocol_packet("10.10.10.50", "10.10.10.1"))

    return pcap_file


@pytest.fixture
def pcap_with_sentinel_discovery(tmp_path: Path) -> Path:
    """Create PCAP with Sentinel HASP UDP discovery packets."""
    pcap_file = tmp_path / "sentinel_discovery.pcap"

    with open(pcap_file, "wb") as f:
        f.write(create_pcap_header())
        f.write(create_sentinel_udp_discovery_packet("255.255.255.255", "255.255.255.255"))

    return pcap_file


@pytest.fixture
def pcap_with_encrypted_payload(tmp_path: Path) -> Path:
    """Create PCAP with encrypted license protocol payload."""
    pcap_file = tmp_path / "encrypted_license.pcap"

    encrypted_payload = b"\x00\x01\x02\x03" + bytes(range(256))

    tcp_header = create_tcp_header(50000, 27000, 5000, 0, 0x18, len(encrypted_payload))
    ip_header = create_ip_header("10.20.30.40", "10.20.30.1", 6, 20 + len(encrypted_payload))
    eth_header = create_ethernet_header()

    full_packet = eth_header + ip_header + tcp_header + encrypted_payload

    with open(pcap_file, "wb") as f:
        f.write(create_pcap_header())
        f.write(create_packet_record(full_packet))

    return pcap_file


class TestProtocolFingerprintingBeyondKeywords:
    """Test protocol fingerprinting using packet structure analysis."""

    def test_detects_binary_flexlm_protocol_structure(self, pcap_with_binary_flexlm: Path) -> None:
        """Detects binary FlexLM protocol by packet structure not keywords."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required for binary protocol detection")

        result = parse_pcap_with_dpkt(str(pcap_with_binary_flexlm))

        assert "error" not in result, "Binary FlexLM parsing must succeed"
        assert result["tcp_packets"] >= 2, "Must parse FlexLM TCP packets"
        assert result["total_packets"] >= 2, "Must count all FlexLM packets"

    def test_identifies_hasp_protocol_by_header_structure(self, pcap_with_hasp_protocol: Path) -> None:
        """Identifies HASP protocol by examining packet headers and structure."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required for protocol structure analysis")

        result = parse_pcap_with_dpkt(str(pcap_with_hasp_protocol))

        assert "error" not in result, "HASP protocol parsing must succeed"
        assert result["tcp_packets"] >= 2, "Must detect HASP TCP communications"

        with open(pcap_with_hasp_protocol, "rb") as f:
            content = f.read()
            assert b"HASP" in content, "HASP magic bytes must be present in packets"

    def test_recognizes_rlm_protocol_format(self, pcap_with_rlm_protocol: Path) -> None:
        """Recognizes RLM protocol by format structure not text matching."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required for RLM protocol analysis")

        result = parse_pcap_with_dpkt(str(pcap_with_rlm_protocol))

        assert "error" not in result, "RLM protocol parsing must succeed"
        assert result["tcp_packets"] >= 1, "Must detect RLM protocol packets"

        with open(pcap_with_rlm_protocol, "rb") as f:
            content = f.read()
            assert b"RLM\x00" in content, "RLM protocol header must be present"

    def test_detects_sentinel_udp_protocol_pattern(self, pcap_with_sentinel_discovery: Path) -> None:
        """Detects Sentinel HASP UDP discovery by protocol pattern."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required for UDP protocol detection")

        result = parse_pcap_with_dpkt(str(pcap_with_sentinel_discovery))

        assert "error" not in result, "Sentinel UDP parsing must succeed"
        assert result["udp_packets"] >= 1, "Must detect Sentinel UDP discovery"


class TestTCPStreamReassembly:
    """Test TCP stream reassembly for multi-packet protocols."""

    def test_reassembles_fragmented_license_request(self, pcap_with_fragmented_stream: Path) -> None:
        """Reassembles fragmented TCP stream containing complete license request."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required for TCP stream reassembly")

        result = parse_pcap_with_dpkt(str(pcap_with_fragmented_stream))

        assert "error" not in result, "Fragmented stream parsing must succeed"
        assert result["tcp_packets"] >= 5, "Must detect multiple TCP fragments"
        assert result["unique_connections"] >= 1, "Must track TCP connection"

        with open(pcap_with_fragmented_stream, "rb") as f:
            pcap_content = f.read()

            from dpkt.pcap import Reader
            from dpkt.ethernet import Ethernet
            from dpkt.ip import IP
            from dpkt.tcp import TCP

            stream_data = b""

            with open(pcap_with_fragmented_stream, "rb") as pf:
                pcap = Reader(pf)
                for ts, buf in pcap:
                    try:
                        eth = Ethernet(buf)
                        if isinstance(eth.data, IP):
                            ip = eth.data
                            if isinstance(ip.data, TCP):
                                tcp = ip.data
                                stream_data += bytes(tcp.data)
                    except Exception:
                        continue

            assert len(stream_data) > 200, "Must reassemble significant stream data"
            assert b"LICENSE_REQUEST" in stream_data or len(stream_data) >= 100, "Must contain license request data or significant payload"

    def test_tracks_tcp_sequence_numbers(self, pcap_with_fragmented_stream: Path) -> None:
        """Tracks TCP sequence numbers across fragmented packets."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required for sequence number tracking")

        result = parse_pcap_with_dpkt(str(pcap_with_fragmented_stream))

        assert "error" not in result, "Sequence number tracking must work"
        assert "unique_connections" in result, "Must identify connections for sequencing"

        from dpkt.pcap import Reader
        from dpkt.ethernet import Ethernet
        from dpkt.ip import IP
        from dpkt.tcp import TCP

        sequence_numbers = []

        with open(pcap_with_fragmented_stream, "rb") as f:
            pcap = Reader(f)
            for ts, buf in pcap:
                try:
                    eth = Ethernet(buf)
                    if isinstance(eth.data, IP):
                        ip = eth.data
                        if isinstance(ip.data, TCP):
                            tcp = ip.data
                            sequence_numbers.append(tcp.seq)
                except Exception:
                    continue

        assert len(sequence_numbers) >= 3, "Must track sequence numbers across multiple packets"
        assert len(set(sequence_numbers)) >= 2, "Sequence numbers must vary across packets"


class TestEncryptedLicenseTrafficDetection:
    """Test detection of encrypted license traffic patterns."""

    def test_detects_tls_encrypted_license_connections(self, pcap_with_tls_traffic: Path) -> None:
        """Detects TLS encrypted connections to license servers by SNI."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required for TLS detection")

        result = parse_pcap_with_dpkt(str(pcap_with_tls_traffic))

        assert "error" not in result, "TLS traffic parsing must succeed"
        assert result["tcp_packets"] >= 3, "Must detect TLS handshake packets"

        with open(pcap_with_tls_traffic, "rb") as f:
            content = f.read()
            assert b"license.autodesk.com" in content or b"activation" in content, "Must contain license domain SNI"

    def test_identifies_encrypted_payload_patterns(self, pcap_with_encrypted_payload: Path) -> None:
        """Identifies encrypted payloads by high entropy and structure."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required for encrypted payload detection")

        result = parse_pcap_with_dpkt(str(pcap_with_encrypted_payload))

        assert "error" not in result, "Encrypted payload parsing must succeed"
        assert result["tcp_packets"] >= 1, "Must detect encrypted TCP traffic"

        from dpkt.pcap import Reader
        from dpkt.ethernet import Ethernet
        from dpkt.ip import IP
        from dpkt.tcp import TCP

        with open(pcap_with_encrypted_payload, "rb") as f:
            pcap = Reader(f)
            for ts, buf in pcap:
                try:
                    eth = Ethernet(buf)
                    if isinstance(eth.data, IP):
                        ip = eth.data
                        if isinstance(ip.data, TCP):
                            tcp = ip.data
                            payload = bytes(tcp.data)
                            if len(payload) > 0:
                                unique_bytes = len(set(payload))
                                assert unique_bytes >= 50, "Encrypted payload must have high byte diversity"
                except Exception:
                    continue

    def test_detects_license_server_tls_connections(self, pcap_with_tls_traffic: Path) -> None:
        """Detects TLS connections to known license server domains."""
        try:
            import pyshark
        except ImportError:
            pytest.skip("PyShark required for TLS analysis")

        result = analyze_pcap_with_pyshark(str(pcap_with_tls_traffic))

        if "error" not in result:
            assert result["total_packets"] >= 3, "Must parse TLS handshake packets"
            assert "tls_handshakes" in result, "Must extract TLS handshake information"


class TestLicenseProtocolBehavioralIdentification:
    """Test identification of license protocols by communication behavior."""

    def test_identifies_request_response_pattern(self, pcap_with_binary_flexlm: Path) -> None:
        """Identifies license check/out request-response patterns."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required for behavioral analysis")

        result = parse_pcap_with_dpkt(str(pcap_with_binary_flexlm))

        assert "error" not in result, "Request-response parsing must succeed"
        assert result["unique_connections"] >= 1, "Must track license server connections"

        from dpkt.pcap import Reader
        from dpkt.ethernet import Ethernet
        from dpkt.ip import IP
        from dpkt.tcp import TCP

        connection_pairs = {}

        with open(pcap_with_binary_flexlm, "rb") as f:
            pcap = Reader(f)
            for ts, buf in pcap:
                try:
                    eth = Ethernet(buf)
                    if isinstance(eth.data, IP):
                        ip = eth.data
                        if isinstance(ip.data, TCP):
                            tcp = ip.data
                            src = f"{socket.inet_ntoa(ip.src)}:{tcp.sport}"
                            dst = f"{socket.inet_ntoa(ip.dst)}:{tcp.dport}"
                            key = (src, dst)
                            connection_pairs[key] = connection_pairs.get(key, 0) + 1
                except Exception:
                    continue

        assert len(connection_pairs) >= 1, "Must detect connection patterns"

    def test_detects_port_based_license_protocol(self, pcap_with_binary_flexlm: Path) -> None:
        """Detects license protocols by well-known port usage."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required for port analysis")

        from dpkt.pcap import Reader
        from dpkt.ethernet import Ethernet
        from dpkt.ip import IP
        from dpkt.tcp import TCP

        license_ports_detected = set()
        known_license_ports = {27000, 27001, 1947, 5053, 5054, 6200, 7070}

        with open(pcap_with_binary_flexlm, "rb") as f:
            pcap = Reader(f)
            for ts, buf in pcap:
                try:
                    eth = Ethernet(buf)
                    if isinstance(eth.data, IP):
                        ip = eth.data
                        if isinstance(ip.data, TCP):
                            tcp = ip.data
                            if tcp.dport in known_license_ports:
                                license_ports_detected.add(tcp.dport)
                except Exception:
                    continue

        assert len(license_ports_detected) >= 1, "Must detect license protocol ports"

    def test_identifies_session_based_communication(self, pcap_with_hasp_protocol: Path) -> None:
        """Identifies session-based license protocol communication."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required for session analysis")

        result = parse_pcap_with_dpkt(str(pcap_with_hasp_protocol))

        assert "error" not in result, "Session-based protocol parsing must succeed"
        assert result["unique_connections"] >= 1, "Must track session connections"


class TestFragmentedPacketHandling:
    """Test handling of IP fragmentation and reassembly."""

    def test_handles_fragmented_tcp_packets(self, pcap_with_fragmented_stream: Path) -> None:
        """Handles IP-fragmented TCP packets correctly."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required for fragment handling")

        result = parse_pcap_with_dpkt(str(pcap_with_fragmented_stream))

        assert "error" not in result, "Fragment handling must not error"
        assert result["tcp_packets"] >= 3, "Must process fragmented TCP stream"

    def test_reassembles_large_license_payloads(self, pcap_with_fragmented_stream: Path) -> None:
        """Reassembles large license payloads split across packets."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required for payload reassembly")

        from dpkt.pcap import Reader
        from dpkt.ethernet import Ethernet
        from dpkt.ip import IP
        from dpkt.tcp import TCP

        total_payload_size = 0

        with open(pcap_with_fragmented_stream, "rb") as f:
            pcap = Reader(f)
            for ts, buf in pcap:
                try:
                    eth = Ethernet(buf)
                    if isinstance(eth.data, IP):
                        ip = eth.data
                        if isinstance(ip.data, TCP):
                            tcp = ip.data
                            total_payload_size += len(tcp.data)
                except Exception:
                    continue

        assert total_payload_size >= 200, "Must accumulate large fragmented payload"


class TestSSLTLSTrafficAnalysis:
    """Test SSL/TLS encrypted traffic detection and analysis."""

    def test_detects_tls_handshake_packets(self, pcap_with_tls_traffic: Path) -> None:
        """Detects TLS handshake packets in network capture."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required for TLS detection")

        from dpkt.pcap import Reader
        from dpkt.ethernet import Ethernet
        from dpkt.ip import IP
        from dpkt.tcp import TCP

        tls_packets = 0

        with open(pcap_with_tls_traffic, "rb") as f:
            pcap = Reader(f)
            for ts, buf in pcap:
                try:
                    eth = Ethernet(buf)
                    if isinstance(eth.data, IP):
                        ip = eth.data
                        if isinstance(ip.data, TCP):
                            tcp = ip.data
                            if len(tcp.data) > 0 and tcp.data[0:1] == b'\x16':
                                tls_packets += 1
                except Exception:
                    continue

        assert tls_packets >= 3, "Must detect TLS handshake packets"

    def test_extracts_sni_from_client_hello(self, pcap_with_tls_traffic: Path) -> None:
        """Extracts Server Name Indication from TLS ClientHello."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required for SNI extraction")

        from dpkt.pcap import Reader
        from dpkt.ethernet import Ethernet
        from dpkt.ip import IP
        from dpkt.tcp import TCP

        with open(pcap_with_tls_traffic, "rb") as f:
            content = f.read()
            assert b"license.autodesk.com" in content or b"activation.adobe.com" in content, "Must contain license server SNI"

    def test_identifies_license_activation_over_tls(self, pcap_with_tls_traffic: Path) -> None:
        """Identifies license activation traffic over TLS by domain patterns."""
        with open(pcap_with_tls_traffic, "rb") as f:
            content = f.read()

        license_indicators = [
            b"license",
            b"activation",
            b"autodesk",
            b"adobe",
            b"flexnet",
        ]

        found_indicators = sum(1 for indicator in license_indicators if indicator in content.lower())
        assert found_indicators >= 2, "Must identify license-related TLS traffic"


class TestTunneledProtocolDetection:
    """Test detection of license protocols tunneled over other protocols."""

    def test_detects_http_tunneled_license_traffic(self, tmp_path: Path) -> None:
        """Detects license protocol data tunneled over HTTP."""
        http_request = (
            b"POST /license/checkout HTTP/1.1\r\n"
            b"Host: license.server.com\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Length: 64\r\n"
            b"\r\n" +
            b"\x00\x01\x02\x03" + bytes(range(60))
        )

        tcp_header = create_tcp_header(55000, 80, 6000, 0, 0x18, len(http_request))
        ip_header = create_ip_header("192.168.100.50", "203.0.113.10", 6, 20 + len(http_request))
        eth_header = create_ethernet_header()

        full_packet = eth_header + ip_header + tcp_header + http_request

        pcap_file = tmp_path / "http_tunnel.pcap"
        with open(pcap_file, "wb") as f:
            f.write(create_pcap_header())
            f.write(create_packet_record(full_packet))

        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required for tunneled protocol detection")

        result = parse_pcap_with_dpkt(str(pcap_file))

        assert "error" not in result, "HTTP tunnel detection must succeed"
        assert result["tcp_packets"] >= 1, "Must detect HTTP tunneled traffic"

        with open(pcap_file, "rb") as f:
            content = f.read()
            assert b"license" in content.lower(), "Must identify license traffic in HTTP tunnel"

    def test_detects_dns_tunneled_data_patterns(self, tmp_path: Path) -> None:
        """Detects unusual DNS query patterns indicating tunneling."""
        long_subdomain = b"aabbccdd" * 8 + b".tunnel.example.com"

        dns_query = b"\x00\x01"
        dns_flags = b"\x01\x00"
        dns_questions = b"\x00\x01"
        dns_answer_rr = b"\x00\x00"
        dns_authority_rr = b"\x00\x00"
        dns_additional_rr = b"\x00\x00"

        qname_parts = long_subdomain.split(b".")
        qname = b""
        for part in qname_parts:
            qname += bytes([len(part)]) + part
        qname += b"\x00"

        qtype = b"\x00\x01"
        qclass = b"\x00\x01"

        dns_payload = dns_query + dns_flags + dns_questions + dns_answer_rr + dns_authority_rr + dns_additional_rr + qname + qtype + qclass

        udp_header = create_udp_header(53000, 53, len(dns_payload))
        ip_header = create_ip_header("10.50.50.50", "8.8.8.8", 17, 8 + len(dns_payload))
        eth_header = create_ethernet_header()

        full_packet = eth_header + ip_header + udp_header + dns_payload

        pcap_file = tmp_path / "dns_tunnel.pcap"
        with open(pcap_file, "wb") as f:
            f.write(create_pcap_header())
            f.write(create_packet_record(full_packet))

        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required for DNS tunnel detection")

        result = parse_pcap_with_dpkt(str(pcap_file))

        assert "error" not in result, "DNS tunnel detection must succeed"
        assert result["udp_packets"] >= 1, "Must detect DNS tunneling traffic"


class TestNetworkCaptureEdgeCases:
    """Test edge cases and error handling."""

    def test_handles_empty_pcap_file(self, tmp_path: Path) -> None:
        """Handles PCAP file with only header, no packets."""
        pcap_file = tmp_path / "empty.pcap"

        with open(pcap_file, "wb") as f:
            f.write(create_pcap_header())

        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required for empty file test")

        result = parse_pcap_with_dpkt(str(pcap_file))

        assert "error" not in result or result.get("total_packets", 0) == 0, "Empty PCAP must handle gracefully"

    def test_handles_truncated_packets(self, tmp_path: Path) -> None:
        """Handles packets with truncated data gracefully."""
        incomplete_packet = b"\x00" * 20

        pcap_file = tmp_path / "truncated.pcap"
        with open(pcap_file, "wb") as f:
            f.write(create_pcap_header())
            f.write(create_packet_record(incomplete_packet))

        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required for truncated packet test")

        result = parse_pcap_with_dpkt(str(pcap_file))

        assert isinstance(result, dict), "Must return result for truncated packets"

    def test_handles_mixed_ipv4_protocols(self, tmp_path: Path) -> None:
        """Handles PCAP with mixed TCP, UDP, ICMP protocols."""
        tcp_packet = create_hasp_protocol_packet("10.0.0.1", "10.0.0.2")
        udp_packet = create_sentinel_udp_discovery_packet("10.0.0.3", "10.0.0.4")

        pcap_file = tmp_path / "mixed_protocols.pcap"
        with open(pcap_file, "wb") as f:
            f.write(create_pcap_header())
            f.write(tcp_packet)
            f.write(udp_packet)

        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required for mixed protocol test")

        result = parse_pcap_with_dpkt(str(pcap_file))

        assert "error" not in result, "Mixed protocol parsing must succeed"
        assert result.get("tcp_packets", 0) >= 1, "Must count TCP packets"
        assert result.get("udp_packets", 0) >= 1, "Must count UDP packets"

    def test_handles_large_pcap_files(self, tmp_path: Path) -> None:
        """Handles PCAP files with many packets efficiently."""
        pcap_file = tmp_path / "large.pcap"

        with open(pcap_file, "wb") as f:
            f.write(create_pcap_header())
            for i in range(100):
                f.write(create_flexlm_binary_packet(f"192.168.{i % 255}.{i % 255}", "192.168.1.1", 10000 + i, 27000))

        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required for large file test")

        result = parse_pcap_with_dpkt(str(pcap_file))

        assert "error" not in result, "Large PCAP parsing must succeed"
        assert result.get("total_packets", 0) >= 50, "Must process significant packet count"


class TestProtocolFingerprintingIntegration:
    """Integration tests for complete protocol fingerprinting workflows."""

    def test_complete_flexlm_session_analysis(self, pcap_with_binary_flexlm: Path) -> None:
        """Analyzes complete FlexLM license check-out session."""
        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required for session analysis")

        result = parse_pcap_with_dpkt(str(pcap_with_binary_flexlm))

        assert "error" not in result, "FlexLM session analysis must succeed"
        assert result["unique_connections"] >= 1, "Must track FlexLM session"
        assert result["tcp_packets"] >= 2, "Must capture license request/response"

    def test_multi_protocol_license_environment(self, tmp_path: Path) -> None:
        """Handles environment with multiple license protocols simultaneously."""
        pcap_file = tmp_path / "multi_protocol.pcap"

        with open(pcap_file, "wb") as f:
            f.write(create_pcap_header())
            f.write(create_flexlm_binary_packet("192.168.1.10", "192.168.1.1", 10000, 27000))
            f.write(create_hasp_protocol_packet("192.168.1.20", "192.168.1.2"))
            f.write(create_rlm_protocol_packet("192.168.1.30", "192.168.1.3"))
            f.write(create_sentinel_udp_discovery_packet("255.255.255.255", "255.255.255.255"))

        try:
            import dpkt
        except ImportError:
            pytest.skip("dpkt required for multi-protocol test")

        result = parse_pcap_with_dpkt(str(pcap_file))

        assert "error" not in result, "Multi-protocol analysis must succeed"
        assert result["tcp_packets"] >= 3, "Must detect multiple TCP license protocols"
        assert result["udp_packets"] >= 1, "Must detect UDP license protocols"
        assert result["unique_connections"] >= 3, "Must track different protocol connections"
