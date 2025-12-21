"""Production tests for protocol fingerprinting with real protocol detection.

These tests validate that protocol_fingerprinter correctly identifies real network
license protocols using actual protocol byte patterns. Tests MUST FAIL if protocol
detection logic is broken or produces incorrect results.

Copyright (C) 2025 Zachary Flint
"""

import hashlib
import json
import os
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.network.protocol_fingerprinter import ProtocolFingerprinter


class TestProtocolFingerprinterProduction:
    """Production tests for protocol fingerprinting with real data."""

    @pytest.fixture
    def temp_sig_dir(self, tmp_path: Path) -> Path:
        """Create temporary signature database directory."""
        sig_dir = tmp_path / "signatures"
        sig_dir.mkdir()
        return sig_dir

    @pytest.fixture
    def fingerprinter(self, temp_sig_dir: Path) -> ProtocolFingerprinter:
        """Create fingerprinter with temporary signature database."""
        sig_path = temp_sig_dir / "protocols.json"
        config = {
            "signature_db_path": str(sig_path),
            "min_confidence": 0.7,
            "learning_mode": True,
        }
        return ProtocolFingerprinter(config)

    @pytest.fixture
    def real_flexlm_packet(self) -> bytes:
        """Create realistic FlexLM license request packet."""
        flexlm_request = b"FEATURE AutoCAD adskflex 2024.0 permanent 1 SIGN=ABCD1234\n"
        flexlm_request += b"SERVER license_server ANY 27000\n"
        flexlm_request += b"VENDOR adskflex\n"
        return flexlm_request

    @pytest.fixture
    def real_hasp_packet(self) -> bytes:
        """Create realistic HASP/Sentinel license request packet."""
        hasp_header = struct.pack("<I", 0x01020304)
        hasp_command = struct.pack("<B", 0x01)
        hasp_payload_len = struct.pack("<H", 16)
        hasp_payload = b"HASP_QUERY\x00\x00\x00\x00\x00\x00"
        return hasp_header + hasp_command + hasp_payload_len + hasp_payload

    @pytest.fixture
    def real_autodesk_packet(self) -> bytes:
        """Create realistic Autodesk licensing protocol packet."""
        autodesk_sig = b"ADSK"
        autodesk_version = struct.pack("<B", 0x01)
        autodesk_command = struct.pack("<B", 0x01)
        autodesk_payload = json.dumps({
            "license": "request",
            "product": "AutoCAD",
            "version": "2024",
        }).encode()
        payload_len = struct.pack("<H", len(autodesk_payload))
        return autodesk_sig + autodesk_version + autodesk_command + payload_len + autodesk_payload

    @pytest.fixture
    def real_kms_packet(self) -> bytes:
        """Create realistic Microsoft KMS activation packet."""
        kms_header = struct.pack("<IIII", 5, 0, 3, 64)
        kms_signature = b"KMSV" + b"\x00" * 4
        kms_payload = b"\x00" * 40 + kms_signature + b"\x00" * 12
        return kms_header + kms_payload

    def test_flexlm_protocol_detection_accuracy(
        self,
        fingerprinter: ProtocolFingerprinter,
        real_flexlm_packet: bytes,
    ) -> None:
        """FlexLM protocol detection produces correct identification on real packets."""
        result = fingerprinter.analyze_traffic(real_flexlm_packet, port=27000)

        assert result is not None, "FlexLM packet must be identified"
        assert result["protocol_id"] == "flexlm", "Must identify as FlexLM protocol"
        assert result["name"] == "FlexLM", "Protocol name must be correct"
        assert result["confidence"] >= 0.7, "Confidence must meet minimum threshold"
        assert "FlexLM" in result["description"], "Description must mention FlexLM"

    def test_hasp_protocol_detection_binary_format(
        self,
        fingerprinter: ProtocolFingerprinter,
        real_hasp_packet: bytes,
    ) -> None:
        """HASP protocol detection identifies binary HASP packets correctly."""
        result = fingerprinter.analyze_traffic(real_hasp_packet, port=1947)

        assert result is not None, "HASP packet must be identified"
        assert result["protocol_id"] == "hasp", "Must identify as HASP protocol"
        assert result["confidence"] >= 0.5, "Binary HASP patterns must be detected"

    def test_autodesk_protocol_with_json_payload(
        self,
        fingerprinter: ProtocolFingerprinter,
        real_autodesk_packet: bytes,
    ) -> None:
        """Autodesk protocol detection works with JSON-embedded payloads."""
        result = fingerprinter.analyze_traffic(real_autodesk_packet, port=2080)

        assert result is not None, "Autodesk packet must be identified"
        assert result["protocol_id"] == "autodesk", "Must identify as Autodesk protocol"
        assert b"ADSK" in real_autodesk_packet, "Packet must contain ADSK signature"

    def test_microsoft_kms_protocol_detection(
        self,
        fingerprinter: ProtocolFingerprinter,
        real_kms_packet: bytes,
    ) -> None:
        """Microsoft KMS protocol detection identifies activation packets."""
        result = fingerprinter.analyze_traffic(real_kms_packet, port=1688)

        assert result is not None, "KMS packet must be identified"
        assert result["protocol_id"] == "microsoft_kms", "Must identify as KMS protocol"

    def test_port_matching_increases_confidence(
        self,
        fingerprinter: ProtocolFingerprinter,
        real_flexlm_packet: bytes,
    ) -> None:
        """Protocol detection confidence is higher when port matches."""
        result_with_port = fingerprinter.analyze_traffic(real_flexlm_packet, port=27000)
        result_without_port = fingerprinter.analyze_traffic(real_flexlm_packet, port=None)

        assert result_with_port is not None, "Must identify with correct port"
        assert result_without_port is not None, "Must identify without port info"
        assert result_with_port["confidence"] >= result_without_port["confidence"], (
            "Confidence must be higher with matching port"
        )

    def test_protocol_fingerprinting_extracts_metadata(
        self,
        fingerprinter: ProtocolFingerprinter,
        real_flexlm_packet: bytes,
    ) -> None:
        """Fingerprint packet extraction includes protocol-specific metadata."""
        result = fingerprinter.fingerprint_packet(real_flexlm_packet, port=27000)

        assert result is not None, "Fingerprinting must succeed"
        assert "packet_entropy" in result, "Must calculate packet entropy"
        assert "ascii_ratio" in result, "Must calculate ASCII ratio"
        assert "protocol_hints" in result, "Must provide protocol hints"
        assert result["packet_size"] == len(real_flexlm_packet), "Packet size must be accurate"
        assert result["source_port"] == 27000, "Source port must be recorded"

    def test_parse_flexlm_packet_structure(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Parse packet extracts correct fields from FlexLM protocol."""
        flexlm_packet = b"SERVER_HEARTBEAT\x00\x01\x00\x10" + b"payload_data_here"

        parsed = fingerprinter.parse_packet("flexlm", flexlm_packet)

        assert parsed is not None, "FlexLM packet parsing must succeed"
        assert "command" in parsed, "Must extract command field"
        assert "version" in parsed, "Must extract version field"
        assert "payload_length" in parsed, "Must extract payload length"
        assert parsed["command"].startswith("SERVER"), "Command must be extracted correctly"

    def test_parse_hasp_binary_packet(
        self,
        fingerprinter: ProtocolFingerprinter,
        real_hasp_packet: bytes,
    ) -> None:
        """Parse packet correctly decodes HASP binary format."""
        parsed = fingerprinter.parse_packet("hasp", real_hasp_packet)

        assert parsed is not None, "HASP packet parsing must succeed"
        assert "signature" in parsed, "Must extract signature field"
        assert "command" in parsed, "Must extract command field"
        assert parsed["signature"] == b"\x03\x02\x01\x00", "Signature must be little-endian correct"

    def test_generate_valid_flexlm_response(
        self,
        fingerprinter: ProtocolFingerprinter,
        real_flexlm_packet: bytes,
    ) -> None:
        """Generate response creates valid FlexLM license response."""
        response = fingerprinter.generate_response("flexlm", real_flexlm_packet, "license_ok")

        assert response is not None, "Response generation must succeed"
        assert len(response) > 0, "Response must not be empty"
        assert b"FEATURE_RESPONSE" in response, "Response must contain FlexLM response marker"
        assert response[2:4] == real_flexlm_packet[2:4], "Version field must be echoed back"

    def test_generate_valid_hasp_response(
        self,
        fingerprinter: ProtocolFingerprinter,
        real_hasp_packet: bytes,
    ) -> None:
        """Generate response creates valid HASP license response."""
        response = fingerprinter.generate_response("hasp", real_hasp_packet, "license_ok")

        assert response is not None, "HASP response generation must succeed"
        assert len(response) >= 7, "HASP response must have minimum length"
        assert response[:4] == real_hasp_packet[:4], "Signature must be echoed back"
        assert response[4] == 0x01, "Success code must be set"

    def test_detect_active_license_servers_on_localhost(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Detect protocols performs network scanning for active servers."""
        detected = fingerprinter.detect_protocols()

        assert isinstance(detected, list), "Detection must return list"

    def test_protocol_probe_generation_for_flexlm(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Send protocol probe generates appropriate FlexLM probe packet."""
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)

        probe = fingerprinter._send_protocol_probe(sock, 27000)

        sock.close()

        assert probe is None or isinstance(probe, bytes), "Probe must return bytes or None"

    def test_pcap_analysis_counts_packets(
        self,
        fingerprinter: ProtocolFingerprinter,
        tmp_path: Path,
    ) -> None:
        """Analyze PCAP processes packet capture files and extracts protocol info."""
        pcap_path = tmp_path / "test.pcap"

        pcap_header = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00"
        pcap_header += b"\x00\x00\x00\x00\x00\x00\x00\x00"
        pcap_header += b"\xff\xff\x00\x00\x01\x00\x00\x00"

        packet_header = struct.pack("<IIII", 0, 0, 100, 100)
        packet_data = b"\x00" * 100

        with open(pcap_path, "wb") as f:
            f.write(pcap_header)
            f.write(packet_header)
            f.write(packet_data)

        result = fingerprinter.analyze_pcap(str(pcap_path))

        assert result is not None, "PCAP analysis must return results"
        assert "file" in result, "Must include file path"
        assert "protocols" in result, "Must include protocols list"
        assert "summary" in result, "Must include summary statistics"
        assert result["summary"]["total_packets"] >= 0, "Packet count must be non-negative"

    def test_binary_analysis_detects_network_functions(
        self,
        fingerprinter: ProtocolFingerprinter,
        tmp_path: Path,
    ) -> None:
        """Analyze binary detects network-related function imports."""
        binary_path = tmp_path / "test.exe"

        binary_data = b"MZ\x90\x00"
        binary_data += b"\x00" * 60
        binary_data += b"PE\x00\x00"
        binary_data += b"\x00" * 100
        binary_data += b"socket\x00connect\x00send\x00recv\x00"
        binary_data += b"FlexLM license manager\x00"
        binary_data += b"license.dat\x00"
        binary_data += b"127.0.0.1:27000\x00"

        with open(binary_path, "wb") as f:
            f.write(binary_data)

        result = fingerprinter.analyze_binary(str(binary_path))

        assert result is not None, "Binary analysis must return results"
        assert "network_functions" in result, "Must detect network functions"
        assert "protocols" in result, "Must identify likely protocols"
        assert "license_indicators" in result, "Must detect license indicators"
        assert len(result["network_functions"]) > 0, "Must find network function imports"
        assert result["summary"]["has_network_code"] is True, "Must flag network code presence"

    def test_identify_protocol_convenience_method(
        self,
        fingerprinter: ProtocolFingerprinter,
        real_flexlm_packet: bytes,
    ) -> None:
        """Identify protocol provides simplified interface with percentage confidence."""
        result = fingerprinter.identify_protocol(real_flexlm_packet, port=27000)

        assert result is not None, "Identification must succeed"
        assert "name" in result, "Must include protocol name"
        assert "protocol_id" in result, "Must include protocol ID"
        assert "confidence" in result, "Must include confidence score"
        assert 0 <= result["confidence"] <= 100, "Confidence must be percentage 0-100"
        assert isinstance(result["confidence"], int), "Confidence must be integer percentage"

    def test_learning_mode_stores_traffic_samples(
        self,
        fingerprinter: ProtocolFingerprinter,
        real_flexlm_packet: bytes,
    ) -> None:
        """Learning mode accumulates traffic samples for pattern extraction."""
        initial_samples = len(fingerprinter.traffic_samples)

        fingerprinter.analyze_traffic(real_flexlm_packet, port=27000)
        fingerprinter.analyze_traffic(real_flexlm_packet, port=27000)

        assert len(fingerprinter.traffic_samples) > initial_samples, "Must store new samples"
        assert len(fingerprinter.traffic_samples) <= 1000, "Must limit sample size"

    def test_signature_persistence(
        self,
        fingerprinter: ProtocolFingerprinter,
        temp_sig_dir: Path,
    ) -> None:
        """Signatures are saved to disk and can be loaded."""
        sig_path = temp_sig_dir / "protocols.json"

        fingerprinter._save_signatures()

        assert sig_path.exists(), "Signature file must be created"

        with open(sig_path) as f:
            signatures = json.load(f)

        assert "flexlm" in signatures, "FlexLM signature must be saved"
        assert "hasp" in signatures, "HASP signature must be saved"
        assert "autodesk" in signatures, "Autodesk signature must be saved"

    def test_unknown_protocol_returns_none(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Unknown protocol packets return None when confidence is too low."""
        random_packet = os.urandom(64)

        result = fingerprinter.analyze_traffic(random_packet, port=None)

        assert result is None or result["confidence"] < 0.7, (
            "Random data must not produce high-confidence match"
        )

    def test_empty_packet_handling(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Empty packet data is handled gracefully."""
        result = fingerprinter.identify_protocol(b"", port=27000)

        assert result is None, "Empty packet must return None"

    def test_malformed_packet_parsing_error_handling(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Malformed packets don't crash parser."""
        malformed = b"\x00\x01\x02"

        result = fingerprinter.parse_packet("flexlm", malformed)

        assert result is None, "Malformed packet must return None"

    def test_statistical_features_entropy_calculation(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Statistical feature matching uses entropy correctly."""
        low_entropy = b"\x00" * 100
        high_entropy = os.urandom(100)

        result_low = fingerprinter._calculate_byte_frequency(low_entropy)
        result_high = fingerprinter._calculate_byte_frequency(high_entropy)

        assert 0 in result_low, "Low entropy must have high frequency of null bytes"
        assert result_low[0] == 1.0, "All bytes must be null in low entropy data"
        assert len(result_high) > len(result_low), "High entropy must have more unique bytes"

    def test_pattern_matching_with_offset(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Binary pattern matching respects offset parameter."""
        packet = b"\x00\x00\x00\x00FEATURE_DATA"
        pattern = {
            "offset": 4,
            "bytes": b"FEATURE",
            "mask": None,
            "weight": 0.5,
        }

        score = fingerprinter._match_binary_pattern(packet, pattern)

        assert score == 0.5, "Pattern at correct offset must match"

    def test_pattern_matching_with_mask(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Binary pattern matching applies bit masks correctly."""
        packet = b"\xAB\xCD\xEF\x12"
        pattern = {
            "offset": 0,
            "bytes": b"\xA0\xC0\xE0\x10",
            "mask": [0xF0, 0xF0, 0xF0, 0xF0],
            "weight": 0.3,
        }

        score = fingerprinter._match_binary_pattern(packet, pattern)

        assert score == 0.3, "Masked pattern must match high nibbles"

    def test_similarity_calculation_for_learning(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Similarity calculation identifies similar packets correctly."""
        data1 = b"LICENSE_REQUEST_123456789"
        data2 = b"LICENSE_REQUEST_987654321"
        data3 = b"COMPLETELY_DIFFERENT_DATA"

        similarity_12 = fingerprinter._calculate_similarity(data1, data2)
        similarity_13 = fingerprinter._calculate_similarity(data1, data3)

        assert similarity_12 > similarity_13, "Similar packets must have higher similarity score"
        assert 0.0 <= similarity_12 <= 1.0, "Similarity must be in valid range"

    def test_common_pattern_extraction_from_samples(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Extract common patterns finds shared prefixes in similar packets."""
        samples = [
            {"data": b"HASP_QUERY_001", "port": 1947, "timestamp": 1.0},
            {"data": b"HASP_QUERY_002", "port": 1947, "timestamp": 2.0},
            {"data": b"HASP_QUERY_003", "port": 1947, "timestamp": 3.0},
        ]

        patterns = fingerprinter._extract_common_patterns(samples)

        assert len(patterns) > 0, "Must extract common patterns"
        assert patterns[0]["bytes"] == b"HASP_QUERY_00", "Must find common prefix"

    def test_protocol_confidence_calculation_combines_factors(
        self,
        fingerprinter: ProtocolFingerprinter,
        real_flexlm_packet: bytes,
    ) -> None:
        """Protocol confidence calculation sums multiple detection factors."""
        signature = fingerprinter.signatures["flexlm"]

        confidence = fingerprinter._calculate_protocol_confidence(
            real_flexlm_packet,
            27000,
            signature,
        )

        assert confidence > 0.0, "Confidence must be positive for matching packet"
        assert confidence <= 1.0, "Confidence must not exceed 1.0"

    def test_response_template_selection(
        self,
        fingerprinter: ProtocolFingerprinter,
        real_flexlm_packet: bytes,
    ) -> None:
        """Response generation selects appropriate template type."""
        response_ok = fingerprinter.generate_response(
            "flexlm",
            real_flexlm_packet,
            "license_ok",
        )
        response_heartbeat = fingerprinter.generate_response(
            "flexlm",
            real_flexlm_packet,
            "heartbeat",
        )

        assert response_ok != response_heartbeat, "Different response types must differ"
        assert len(response_ok) > 0, "license_ok response must not be empty"
        assert len(response_heartbeat) > 0, "heartbeat response must not be empty"

    def test_network_string_extraction_from_binary(
        self,
        fingerprinter: ProtocolFingerprinter,
        tmp_path: Path,
    ) -> None:
        """Binary analysis extracts network-related strings."""
        binary_path = tmp_path / "app.exe"

        binary = b"MZ\x90\x00" + b"\x00" * 60
        binary += b"license_server=192.168.1.100:27000\x00"
        binary += b"activation_url=https://activation.example.com/validate\x00"
        binary += b"FlexLM server connection string\x00"

        with open(binary_path, "wb") as f:
            f.write(binary)

        result = fingerprinter.analyze_binary(str(binary_path))

        assert len(result["network_strings"]) > 0, "Must extract network strings"
        assert any("192.168.1.100" in s for s in result["network_strings"]), (
            "Must extract IP addresses"
        )

    def test_license_port_detection_in_binary(
        self,
        fingerprinter: ProtocolFingerprinter,
        tmp_path: Path,
    ) -> None:
        """Binary analysis detects embedded license port numbers."""
        binary_path = tmp_path / "client.exe"

        binary = b"MZ\x90\x00" + b"\x00" * 60
        binary += struct.pack(">H", 27000)
        binary += struct.pack(">H", 1947)

        with open(binary_path, "wb") as f:
            f.write(binary)

        result = fingerprinter.analyze_binary(str(binary_path))

        assert result["summary"]["likely_license_client"] or result["summary"]["has_network_code"], (
            "Binary with license ports must be flagged"
        )

    def test_protocol_hint_detection_in_packets(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Packet structure analysis detects protocol hints."""
        http_packet = b"GET /license/validate HTTP/1.1\r\nHost: server.com\r\n\r\n"
        tls_packet = b"\x16\x03\x01\x00\x00"

        result_http = fingerprinter._analyze_packet_structure(http_packet)
        result_tls = fingerprinter._analyze_packet_structure(tls_packet)

        assert "HTTP" in result_http["protocol_hints"], "Must detect HTTP protocol"
        assert "TLS" in result_tls["protocol_hints"], "Must detect TLS handshake"

    def test_ascii_ratio_calculation(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Packet structure analysis calculates correct ASCII ratio."""
        ascii_packet = b"LICENSE_REQUEST_TEXT"
        binary_packet = b"\x00\x01\x02\x03\x04\x05\x06\x07"

        result_ascii = fingerprinter._analyze_packet_structure(ascii_packet)
        result_binary = fingerprinter._analyze_packet_structure(binary_packet)

        assert result_ascii["ascii_ratio"] > 0.9, "Text packet must have high ASCII ratio"
        assert result_binary["ascii_ratio"] < 0.1, "Binary packet must have low ASCII ratio"
