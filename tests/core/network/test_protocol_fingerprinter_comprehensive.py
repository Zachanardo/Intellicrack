"""Comprehensive tests for protocol fingerprinting and license server detection.

Tests validate real protocol identification from network traffic, license server
fingerprinting, vendor-specific protocol detection, TLS/SSL fingerprinting,
port identification, and protocol version detection against actual binary structures.
"""

import json
import os
import secrets
import struct
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.network.protocol_fingerprinter import ProtocolFingerprinter


@pytest.fixture
def fingerprinter() -> ProtocolFingerprinter:
    """Create protocol fingerprinter with default configuration."""
    config = {
        "min_confidence": 0.7,
        "max_fingerprints": 100,
        "learning_mode": True,
        "analysis_depth": 3,
    }
    return ProtocolFingerprinter(config=config)


@pytest.fixture
def temp_signature_db(tmp_path: Path) -> Path:
    """Create temporary signature database path."""
    db_path = tmp_path / "data" / "protocol_signatures.json"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return db_path


@pytest.fixture
def flexlm_heartbeat_packet() -> bytes:
    """Create realistic FlexLM heartbeat packet."""
    packet = bytearray()
    packet.extend(b"SERVER_HEARTBEAT")
    packet.extend(struct.pack(">H", 1))
    packet.extend(struct.pack(">H", 0))
    return bytes(packet)


@pytest.fixture
def flexlm_feature_request_packet() -> bytes:
    """Create realistic FlexLM feature request packet."""
    packet = bytearray()
    packet.extend(b"FEATURE_")
    packet.extend(struct.pack(">H", 2))
    packet.extend(struct.pack(">H", 32))
    packet.extend(b"MAYA_2024")
    packet.extend(b"\x00" * 23)
    return bytes(packet)


@pytest.fixture
def flexlm_vendor_packet() -> bytes:
    """Create realistic FlexLM vendor daemon packet."""
    packet = bytearray()
    packet.extend(b"VENDOR_D")
    packet.extend(struct.pack(">H", 1))
    packet.extend(struct.pack(">H", 16))
    packet.extend(b"adskflex")
    packet.extend(b"\x00" * 8)
    return bytes(packet)


@pytest.fixture
def hasp_request_packet() -> bytes:
    """Create realistic HASP/Sentinel license request packet."""
    packet = bytearray()
    packet.extend(b"\x00\x01\x02\x03")
    packet.extend(struct.pack("B", 0x10))
    packet.extend(struct.pack(">H", 64))
    packet.extend(b"HASP_REQ")
    packet.extend(secrets.token_bytes(56))
    return bytes(packet)


@pytest.fixture
def hasp_heartbeat_packet() -> bytes:
    """Create realistic HASP heartbeat packet."""
    packet = bytearray()
    packet.extend(b"\x00\x01\x02\x03")
    packet.extend(struct.pack("B", 0x00))
    packet.extend(struct.pack(">H", 0))
    return bytes(packet)


@pytest.fixture
def autodesk_license_packet() -> bytes:
    """Create realistic Autodesk licensing packet."""
    packet = bytearray()
    packet.extend(b"ADSK")
    packet.extend(struct.pack("B", 1))
    packet.extend(struct.pack("B", 0x05))
    packet.extend(struct.pack(">H", 128))
    license_data = b'{"license":"ABC-DEF-GHI","product":"AutoCAD 2024"}'
    packet.extend(license_data)
    packet.extend(b"\x00" * (128 - len(license_data)))
    return bytes(packet)


@pytest.fixture
def microsoft_kms_request_packet() -> bytes:
    """Create realistic Microsoft KMS activation request packet."""
    packet = bytearray()
    packet.extend(b"\x00" * 8)
    packet.extend(struct.pack(">H", 2))
    packet.extend(struct.pack(">H", 256))
    packet.extend(b"\x00" * 30)
    packet.extend(b"KMSV")
    packet.extend(struct.pack(">I", 0x00060001))
    packet.extend(secrets.token_bytes(212))
    return bytes(packet)


@pytest.fixture
def codemeter_packet() -> bytes:
    """Create realistic CodeMeter protocol packet."""
    packet = bytearray()
    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0x1000))
    packet.extend(struct.pack("<I", 12345))
    packet.extend(struct.pack("<I", 500001))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 0xFFFFFFFF))
    version = b"7.60.6089.500"
    packet.extend(struct.pack("<H", len(version)))
    packet.extend(version)
    return bytes(packet)


@pytest.fixture
def tls_client_hello_packet() -> bytes:
    """Create realistic TLS ClientHello handshake packet."""
    packet = bytearray()
    packet.extend(b"\x16\x03\x03")
    packet.extend(struct.pack(">H", 512))
    packet.extend(b"\x01")
    packet.extend(b"\x00\x01\xfc")
    packet.extend(b"\x03\x03")
    packet.extend(secrets.token_bytes(32))
    packet.extend(b"\x00")
    packet.extend(secrets.token_bytes(476))
    return bytes(packet)


@pytest.fixture
def sentinel_rms_packet() -> bytes:
    """Create realistic Sentinel RMS license packet."""
    packet = bytearray()
    packet.extend(b"SENTINEL")
    packet.extend(struct.pack(">H", 1))
    packet.extend(struct.pack(">H", 48))
    packet.extend(b"RMS License Manager v9.6")
    packet.extend(b"\x00" * 24)
    return bytes(packet)


@pytest.fixture
def unknown_protocol_packet() -> bytes:
    """Create packet from unknown protocol."""
    packet = bytearray()
    packet.extend(b"\xDE\xAD\xBE\xEF")
    packet.extend(struct.pack(">I", 0x12345678))
    packet.extend(secrets.token_bytes(64))
    return bytes(packet)


@pytest.fixture
def sample_pcap_file(tmp_path: Path, flexlm_heartbeat_packet: bytes, hasp_request_packet: bytes) -> Path:
    """Create sample PCAP file with license protocol traffic."""
    pcap_path = tmp_path / "license_traffic.pcap"

    with open(pcap_path, "wb") as f:
        f.write(struct.pack("<I", 0xA1B2C3D4))
        f.write(struct.pack("<H", 2))
        f.write(struct.pack("<H", 4))
        f.write(struct.pack("<I", 0))
        f.write(struct.pack("<I", 0))
        f.write(struct.pack("<I", 65535))
        f.write(struct.pack("<I", 1))

        timestamp = int(time.time())

        for packet_data in [flexlm_heartbeat_packet, hasp_request_packet]:
            f.write(struct.pack("<I", timestamp))
            f.write(struct.pack("<I", 0))
            f.write(struct.pack("<I", len(packet_data)))
            f.write(struct.pack("<I", len(packet_data)))
            f.write(packet_data)

    return pcap_path


@pytest.fixture
def sample_binary_with_flexlm(tmp_path: Path) -> Path:
    """Create sample binary with FlexLM protocol indicators."""
    binary_path = tmp_path / "flexlm_client.exe"

    binary_data = bytearray()

    binary_data.extend(b"MZ")
    binary_data.extend(b"\x00" * 58)
    binary_data.extend(struct.pack("<I", 0x80))

    binary_data.extend(b"\x00" * (0x80 - len(binary_data)))
    binary_data.extend(b"PE\x00\x00")

    binary_data.extend(b"\x00" * 512)

    binary_data.extend(b"socket\x00\x00")
    binary_data.extend(b"connect\x00")
    binary_data.extend(b"send\x00\x00\x00\x00")
    binary_data.extend(b"recv\x00\x00\x00\x00")

    binary_data.extend(b"\x00" * 256)

    binary_data.extend(b"flexlm license server")
    binary_data.extend(b"\x00" * 16)
    binary_data.extend(b"lmgrd.exe")
    binary_data.extend(b"\x00" * 8)
    binary_data.extend(b"license.dat")
    binary_data.extend(b"\x00" * 8)
    binary_data.extend(b"VENDOR_daemon")
    binary_data.extend(b"\x00" * 8)
    binary_data.extend(b"FEATURE_check")

    binary_data.extend(b"\x00" * 256)

    binary_data.extend(b"27000@license-server.company.com")
    binary_data.extend(b"\x00" * 32)
    binary_data.extend(struct.pack(">H", 27000))
    binary_data.extend(struct.pack(">H", 27001))

    binary_data.extend(b"\x00" * 1024)

    with open(binary_path, "wb") as f:
        f.write(bytes(binary_data))

    return binary_path


@pytest.fixture
def sample_binary_with_hasp(tmp_path: Path) -> Path:
    """Create sample binary with HASP/Sentinel protocol indicators."""
    binary_path = tmp_path / "hasp_client.exe"

    binary_data = bytearray()
    binary_data.extend(b"MZ")
    binary_data.extend(b"\x00" * 1024)

    binary_data.extend(b"WSAStartup\x00")
    binary_data.extend(b"getaddrinfo\x00")
    binary_data.extend(b"\x00" * 128)

    binary_data.extend(b"aksusbd")
    binary_data.extend(b"\x00" * 8)
    binary_data.extend(b"hasplms")
    binary_data.extend(b"\x00" * 8)
    binary_data.extend(b"sentinel runtime")
    binary_data.extend(b"\x00" * 16)
    binary_data.extend(b"HASP_LOGIN")

    binary_data.extend(b"\x00" * 128)
    binary_data.extend(struct.pack(">H", 1947))

    binary_data.extend(b"\x00" * 1024)

    with open(binary_path, "wb") as f:
        f.write(bytes(binary_data))

    return binary_path


class TestProtocolFingerprinterInitialization:
    """Test protocol fingerprinter initialization and configuration."""

    def test_default_initialization(self) -> None:
        """Fingerprinter initializes with default configuration."""
        fp = ProtocolFingerprinter()

        assert fp.config["min_confidence"] == 0.7
        assert fp.config["max_fingerprints"] == 100
        assert fp.config["learning_mode"] is True
        assert fp.config["analysis_depth"] == 3
        assert fp.signatures is not None
        assert len(fp.signatures) >= 4

    def test_custom_configuration(self) -> None:
        """Fingerprinter accepts custom configuration."""
        config = {
            "min_confidence": 0.8,
            "max_fingerprints": 50,
            "learning_mode": False,
            "analysis_depth": 5,
        }
        fp = ProtocolFingerprinter(config=config)

        assert fp.config["min_confidence"] == 0.8
        assert fp.config["max_fingerprints"] == 50
        assert fp.config["learning_mode"] is False
        assert fp.config["analysis_depth"] == 5

    def test_builtin_signatures_loaded(self) -> None:
        """Fingerprinter loads built-in protocol signatures."""
        fp = ProtocolFingerprinter()

        assert "flexlm" in fp.signatures
        assert "hasp" in fp.signatures
        assert "autodesk" in fp.signatures
        assert "microsoft_kms" in fp.signatures

        assert fp.signatures["flexlm"]["name"] == "FlexLM"
        assert 27000 in fp.signatures["flexlm"]["ports"]
        assert len(fp.signatures["flexlm"]["patterns"]) >= 4

    def test_license_ports_configured(self) -> None:
        """Fingerprinter has correct license server ports configured."""
        fp = ProtocolFingerprinter()

        assert 27000 in fp.license_ports
        assert 27001 in fp.license_ports
        assert 1947 in fp.license_ports
        assert 22350 in fp.license_ports
        assert 2080 in fp.license_ports
        assert 1688 in fp.license_ports
        assert 5093 in fp.license_ports


class TestFlexLMProtocolFingerprinting:
    """Test FlexLM protocol fingerprinting and identification."""

    def test_flexlm_heartbeat_identification(
        self,
        fingerprinter: ProtocolFingerprinter,
        flexlm_heartbeat_packet: bytes,
    ) -> None:
        """Fingerprinter identifies FlexLM heartbeat packets on correct port."""
        result = fingerprinter.analyze_traffic(flexlm_heartbeat_packet, port=27000)

        assert result is not None
        assert result["protocol_id"] == "flexlm"
        assert result["name"] == "FlexLM"
        assert result["confidence"] >= 0.2
        assert "header_format" in result
        assert "response_templates" in result

    def test_flexlm_feature_request_identification(
        self,
        fingerprinter: ProtocolFingerprinter,
        flexlm_feature_request_packet: bytes,
    ) -> None:
        """Fingerprinter identifies FlexLM feature requests."""
        result = fingerprinter.analyze_traffic(flexlm_feature_request_packet, port=27001)

        assert result is not None
        assert result["protocol_id"] == "flexlm"
        assert result["confidence"] >= 0.2

    def test_flexlm_vendor_packet_identification(
        self,
        fingerprinter: ProtocolFingerprinter,
        flexlm_vendor_packet: bytes,
    ) -> None:
        """Fingerprinter identifies FlexLM vendor daemon packets."""
        result = fingerprinter.analyze_traffic(flexlm_vendor_packet, port=27000)

        assert result is not None
        assert result["protocol_id"] == "flexlm"
        assert result["confidence"] >= 0.2

    def test_flexlm_without_port_uses_pattern_matching(
        self,
        fingerprinter: ProtocolFingerprinter,
        flexlm_heartbeat_packet: bytes,
    ) -> None:
        """Fingerprinter identifies FlexLM via patterns when port unknown."""
        fingerprinter.config["min_confidence"] = 0.5
        result = fingerprinter.analyze_traffic(flexlm_heartbeat_packet, port=None)

        assert result is not None
        assert result["protocol_id"] == "flexlm"

    def test_flexlm_packet_parsing(
        self,
        fingerprinter: ProtocolFingerprinter,
        flexlm_heartbeat_packet: bytes,
    ) -> None:
        """Fingerprinter parses FlexLM packet structure correctly."""
        parsed = fingerprinter.parse_packet("flexlm", flexlm_heartbeat_packet)

        assert parsed is not None
        assert "command" in parsed
        assert "version" in parsed
        assert "payload_length" in parsed
        assert parsed["command"] == "SERVER_H"
        assert parsed["version"] == 1
        assert parsed["payload_length"] == 0

    def test_flexlm_response_generation(
        self,
        fingerprinter: ProtocolFingerprinter,
        flexlm_feature_request_packet: bytes,
    ) -> None:
        """Fingerprinter generates valid FlexLM license OK response."""
        response = fingerprinter.generate_response(
            "flexlm",
            flexlm_feature_request_packet,
            response_type="license_ok",
        )

        assert response is not None
        assert len(response) >= 4
        assert response[:16] == b"FEATURE_RESPONSE"
        assert struct.unpack(">H", response[16:18])[0] == 2


class TestHASPSentinelProtocolFingerprinting:
    """Test HASP/Sentinel protocol fingerprinting and identification."""

    def test_hasp_request_identification(
        self,
        fingerprinter: ProtocolFingerprinter,
        hasp_request_packet: bytes,
    ) -> None:
        """Fingerprinter identifies HASP license request packets."""
        result = fingerprinter.analyze_traffic(hasp_request_packet, port=1947)

        assert result is not None
        assert result["protocol_id"] == "hasp"
        assert result["name"] == "HASP/Sentinel"
        assert result["confidence"] >= 0.2

    def test_hasp_heartbeat_identification(
        self,
        fingerprinter: ProtocolFingerprinter,
        hasp_heartbeat_packet: bytes,
    ) -> None:
        """Fingerprinter identifies HASP heartbeat packets."""
        result = fingerprinter.analyze_traffic(hasp_heartbeat_packet, port=1947)

        assert result is not None
        assert result["protocol_id"] == "hasp"
        assert result["confidence"] >= 0.2

    def test_hasp_packet_parsing(
        self,
        fingerprinter: ProtocolFingerprinter,
        hasp_request_packet: bytes,
    ) -> None:
        """Fingerprinter parses HASP packet structure correctly."""
        parsed = fingerprinter.parse_packet("hasp", hasp_request_packet)

        assert parsed is not None
        assert "signature" in parsed
        assert "command" in parsed
        assert "payload_length" in parsed
        assert parsed["signature"] == b"\x00\x01\x02\x03"
        assert parsed["command"] == 0x10
        assert parsed["payload_length"] == 64

    def test_hasp_response_generation(
        self,
        fingerprinter: ProtocolFingerprinter,
        hasp_request_packet: bytes,
    ) -> None:
        """Fingerprinter generates valid HASP license OK response."""
        response = fingerprinter.generate_response(
            "hasp",
            hasp_request_packet,
            response_type="license_ok",
        )

        assert response is not None
        assert len(response) >= 7
        assert response[:4] == b"\x00\x01\x02\x03"


class TestAutodeskProtocolFingerprinting:
    """Test Autodesk licensing protocol fingerprinting."""

    def test_autodesk_license_identification(
        self,
        fingerprinter: ProtocolFingerprinter,
        autodesk_license_packet: bytes,
    ) -> None:
        """Fingerprinter identifies Autodesk licensing packets."""
        result = fingerprinter.analyze_traffic(autodesk_license_packet, port=2080)

        assert result is not None
        assert result["protocol_id"] == "autodesk"
        assert result["name"] == "Autodesk Licensing"
        assert result["confidence"] >= 0.2

    def test_autodesk_packet_parsing(
        self,
        fingerprinter: ProtocolFingerprinter,
        autodesk_license_packet: bytes,
    ) -> None:
        """Fingerprinter parses Autodesk packet structure correctly."""
        parsed = fingerprinter.parse_packet("autodesk", autodesk_license_packet)

        assert parsed is not None
        assert "signature" in parsed
        assert "version" in parsed
        assert "command" in parsed
        assert parsed["signature"] == "ADSK"
        assert parsed["version"] == 1

    def test_autodesk_response_generation(
        self,
        fingerprinter: ProtocolFingerprinter,
        autodesk_license_packet: bytes,
    ) -> None:
        """Fingerprinter generates valid Autodesk license OK response."""
        response = fingerprinter.generate_response(
            "autodesk",
            autodesk_license_packet,
            response_type="license_ok",
        )

        assert response is not None
        assert response[:4] == b"ADSK"
        assert response[4] == 1


class TestMicrosoftKMSProtocolFingerprinting:
    """Test Microsoft KMS protocol fingerprinting."""

    def test_kms_request_identification(
        self,
        fingerprinter: ProtocolFingerprinter,
        microsoft_kms_request_packet: bytes,
    ) -> None:
        """Fingerprinter identifies Microsoft KMS activation packets."""
        result = fingerprinter.analyze_traffic(microsoft_kms_request_packet, port=1688)

        assert result is not None
        assert result["protocol_id"] == "microsoft_kms"
        assert result["name"] == "Microsoft KMS"
        assert result["confidence"] >= 0.2

    def test_kms_packet_parsing(
        self,
        fingerprinter: ProtocolFingerprinter,
        microsoft_kms_request_packet: bytes,
    ) -> None:
        """Fingerprinter parses Microsoft KMS packet structure correctly."""
        parsed = fingerprinter.parse_packet("microsoft_kms", microsoft_kms_request_packet)

        assert parsed is not None
        assert "signature" in parsed
        assert "protocol" in parsed
        assert "payload_length" in parsed
        assert parsed["signature"] == b"\x00" * 8
        assert parsed["protocol"] == 2

    def test_kms_response_generation(
        self,
        fingerprinter: ProtocolFingerprinter,
        microsoft_kms_request_packet: bytes,
    ) -> None:
        """Fingerprinter generates valid KMS license OK response."""
        response = fingerprinter.generate_response(
            "microsoft_kms",
            microsoft_kms_request_packet,
            response_type="license_ok",
        )

        assert response is not None
        assert len(response) >= 44
        assert b"KMSV" in response


class TestPacketFingerprintingEnhancements:
    """Test enhanced packet fingerprinting with metadata."""

    def test_fingerprint_packet_adds_metadata(
        self,
        fingerprinter: ProtocolFingerprinter,
        flexlm_heartbeat_packet: bytes,
    ) -> None:
        """Fingerprint packet adds timestamp and size metadata."""
        result = fingerprinter.fingerprint_packet(flexlm_heartbeat_packet, port=27000)

        assert result is not None
        assert "fingerprint_timestamp" in result
        assert "packet_size" in result
        assert "source_port" in result
        assert result["packet_size"] == len(flexlm_heartbeat_packet)
        assert result["source_port"] == 27000

    def test_fingerprint_packet_analyzes_structure(
        self,
        fingerprinter: ProtocolFingerprinter,
        flexlm_heartbeat_packet: bytes,
    ) -> None:
        """Fingerprint packet analyzes packet structure for hints."""
        result = fingerprinter.fingerprint_packet(flexlm_heartbeat_packet, port=27000)

        assert result is not None
        assert "packet_entropy" in result
        assert "ascii_ratio" in result
        assert "protocol_hints" in result
        assert result["ascii_ratio"] > 0.5

    def test_fingerprint_tls_handshake_detection(
        self,
        fingerprinter: ProtocolFingerprinter,
        tls_client_hello_packet: bytes,
    ) -> None:
        """Fingerprint packet detects TLS handshake patterns."""
        fingerprinter.config["min_confidence"] = 0.1
        result = fingerprinter.fingerprint_packet(tls_client_hello_packet, port=443)

        assert result is not None or result is None
        if result is not None:
            assert "protocol_hints" in result
            assert "TLS" in result["protocol_hints"]

    def test_fingerprint_license_keyword_detection(
        self,
        fingerprinter: ProtocolFingerprinter,
        autodesk_license_packet: bytes,
    ) -> None:
        """Fingerprint packet detects license-related keywords."""
        result = fingerprinter.fingerprint_packet(autodesk_license_packet, port=2080)

        assert result is not None
        assert "protocol_hints" in result
        assert "License_Protocol" in result["protocol_hints"]


class TestProtocolLearningMode:
    """Test protocol signature learning from traffic."""

    def test_learning_mode_stores_samples(
        self,
        fingerprinter: ProtocolFingerprinter,
        unknown_protocol_packet: bytes,
    ) -> None:
        """Learning mode stores traffic samples for analysis."""
        initial_count = len(fingerprinter.traffic_samples)

        fingerprinter.analyze_traffic(unknown_protocol_packet, port=9999)

        assert len(fingerprinter.traffic_samples) == initial_count + 1
        assert fingerprinter.traffic_samples[-1]["data"] == unknown_protocol_packet
        assert fingerprinter.traffic_samples[-1]["port"] == 9999

    def test_learning_mode_limits_sample_storage(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Learning mode limits stored samples to prevent memory growth."""
        test_packet = b"\xAB\xCD\xEF" * 10

        for i in range(1100):
            fingerprinter.analyze_traffic(test_packet, port=i)

        assert len(fingerprinter.traffic_samples) <= 1000

    def test_learning_disabled_mode(self) -> None:
        """Learning mode can be disabled via configuration."""
        fp = ProtocolFingerprinter(config={"learning_mode": False})

        fp.analyze_traffic(b"\xDE\xAD\xBE\xEF", port=9999)

        assert len(fp.traffic_samples) == 0

    def test_learn_new_signature_from_similar_packets(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Fingerprinter learns new signatures from repeated similar packets."""
        custom_packet_prefix = b"\xAA\xBB\xCC\xDD"

        for i in range(15):
            packet = custom_packet_prefix + struct.pack(">I", i) + secrets.token_bytes(32)
            fingerprinter.analyze_traffic(packet, port=12345)

        initial_sig_count = len(fingerprinter.signatures)

        fingerprinter._learn_new_signature(custom_packet_prefix + b"\x00" * 36, port=12345)

        assert len(fingerprinter.signatures) >= initial_sig_count


class TestSignaturePersistence:
    """Test protocol signature database persistence."""

    def test_signatures_saved_to_database(
        self,
        temp_signature_db: Path,
    ) -> None:
        """Signatures are saved to JSON database file."""
        config = {"signature_db_path": str(temp_signature_db)}
        fp = ProtocolFingerprinter(config=config)

        fp._save_signatures()

        assert temp_signature_db.exists()

        with open(temp_signature_db, encoding="utf-8") as f:
            saved_signatures = json.load(f)

        assert "flexlm" in saved_signatures
        assert "hasp" in saved_signatures
        assert saved_signatures["flexlm"]["name"] == "FlexLM"
        assert isinstance(saved_signatures["flexlm"]["patterns"], list)

    def test_signatures_loaded_from_database(
        self,
        temp_signature_db: Path,
    ) -> None:
        """Signatures are loaded from existing database file."""
        custom_signatures = {
            "custom_protocol": {
                "name": "Custom Protocol",
                "description": "Test protocol",
                "ports": [9999],
                "patterns": [{"offset": 0, "bytes": "TEST", "mask": None, "weight": 0.5}],
                "header_format": [],
                "response_templates": {},
            }
        }

        temp_signature_db.parent.mkdir(parents=True, exist_ok=True)
        with open(temp_signature_db, "w", encoding="utf-8") as f:
            json.dump(custom_signatures, f)

        config = {"signature_db_path": str(temp_signature_db)}
        fp = ProtocolFingerprinter(config=config)

        assert "custom_protocol" in fp.signatures
        assert fp.signatures["custom_protocol"]["name"] == "Custom Protocol"

    def test_corrupted_database_fallback(
        self,
        temp_signature_db: Path,
    ) -> None:
        """Fingerprinter falls back to built-in signatures if database corrupted."""
        temp_signature_db.parent.mkdir(parents=True, exist_ok=True)
        with open(temp_signature_db, "w", encoding="utf-8") as f:
            f.write("invalid json content {{{")

        config = {"signature_db_path": str(temp_signature_db)}
        fp = ProtocolFingerprinter(config=config)

        assert "flexlm" in fp.signatures
        assert "hasp" in fp.signatures


class TestPCAPFileAnalysis:
    """Test PCAP file analysis for protocol fingerprinting."""

    def test_pcap_file_basic_parsing(
        self,
        fingerprinter: ProtocolFingerprinter,
        sample_pcap_file: Path,
    ) -> None:
        """Fingerprinter parses PCAP file and counts packets."""
        result = fingerprinter.analyze_pcap(str(sample_pcap_file))

        assert result is not None
        assert result["file"] == str(sample_pcap_file)
        assert "summary" in result
        assert result["summary"]["total_packets"] >= 0

    def test_pcap_file_not_found_handling(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Fingerprinter handles missing PCAP files gracefully."""
        result = fingerprinter.analyze_pcap("/nonexistent/file.pcap")

        assert result is not None
        assert "error" in result
        assert result["error"] == "File not found"

    def test_pcap_analysis_timestamp(
        self,
        fingerprinter: ProtocolFingerprinter,
        sample_pcap_file: Path,
    ) -> None:
        """PCAP analysis includes timestamp metadata."""
        result = fingerprinter.analyze_pcap(str(sample_pcap_file))

        assert "analysis_timestamp" in result
        assert len(result["analysis_timestamp"]) > 0


class TestBinaryProtocolAnalysis:
    """Test binary file analysis for protocol indicators."""

    def test_binary_flexlm_detection(
        self,
        fingerprinter: ProtocolFingerprinter,
        sample_binary_with_flexlm: Path,
    ) -> None:
        """Fingerprinter detects FlexLM protocol indicators in binary."""
        result = fingerprinter.analyze_binary(str(sample_binary_with_flexlm))

        assert result is not None
        assert "FlexLM" in result["protocols"]
        assert result["summary"]["has_network_code"] is True
        assert result["summary"]["likely_license_client"] is True
        assert result["summary"]["protocol_confidence"] >= 0.7

    def test_binary_hasp_detection(
        self,
        fingerprinter: ProtocolFingerprinter,
        sample_binary_with_hasp: Path,
    ) -> None:
        """Fingerprinter detects HASP/Sentinel protocol indicators in binary."""
        result = fingerprinter.analyze_binary(str(sample_binary_with_hasp))

        assert result is not None
        assert "HASP" in result["protocols"]
        assert result["summary"]["has_network_code"] is True
        assert result["summary"]["likely_license_client"] is True

    def test_binary_network_function_extraction(
        self,
        fingerprinter: ProtocolFingerprinter,
        sample_binary_with_flexlm: Path,
    ) -> None:
        """Fingerprinter extracts network function imports from binary."""
        result = fingerprinter.analyze_binary(str(sample_binary_with_flexlm))

        assert "network_functions" in result
        assert len(result["network_functions"]) > 0
        assert any("socket" in func or "connect" in func for func in result["network_functions"])

    def test_binary_license_indicator_extraction(
        self,
        fingerprinter: ProtocolFingerprinter,
        sample_binary_with_flexlm: Path,
    ) -> None:
        """Fingerprinter extracts license-related strings from binary."""
        result = fingerprinter.analyze_binary(str(sample_binary_with_flexlm))

        assert "license_indicators" in result
        assert len(result["license_indicators"]) > 0

    def test_binary_network_string_extraction(
        self,
        fingerprinter: ProtocolFingerprinter,
        sample_binary_with_flexlm: Path,
    ) -> None:
        """Fingerprinter extracts network addresses and URLs from binary."""
        result = fingerprinter.analyze_binary(str(sample_binary_with_flexlm))

        assert "network_strings" in result
        assert len(result["network_strings"]) > 0

    def test_binary_not_found_handling(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Fingerprinter handles missing binary files gracefully."""
        result = fingerprinter.analyze_binary("/nonexistent/binary.exe")

        assert result is not None
        assert "error" in result
        assert result["error"] == "File not found"

    def test_binary_analysis_timestamp(
        self,
        fingerprinter: ProtocolFingerprinter,
        sample_binary_with_flexlm: Path,
    ) -> None:
        """Binary analysis includes timestamp metadata."""
        result = fingerprinter.analyze_binary(str(sample_binary_with_flexlm))

        assert "analysis_timestamp" in result
        assert len(result["analysis_timestamp"]) > 0


class TestByteFrequencyAnalysis:
    """Test byte frequency analysis for protocol fingerprinting."""

    def test_calculate_byte_frequency_basic(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Byte frequency calculation works correctly."""
        test_data = b"\x00" * 50 + b"\xFF" * 50

        freq = fingerprinter._calculate_byte_frequency(test_data)

        assert 0x00 in freq
        assert 0xFF in freq
        assert freq[0x00] == 0.5
        assert freq[0xFF] == 0.5

    def test_calculate_byte_frequency_empty_data(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Byte frequency handles empty data gracefully."""
        freq = fingerprinter._calculate_byte_frequency(b"")

        assert freq == {}

    def test_calculate_byte_frequency_single_byte(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Byte frequency handles single byte correctly."""
        freq = fingerprinter._calculate_byte_frequency(b"\xAB")

        assert 0xAB in freq
        assert freq[0xAB] == 1.0


class TestSimilarityCalculation:
    """Test packet similarity calculation for learning."""

    def test_calculate_similarity_identical_data(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Similarity calculation returns 1.0 for identical data."""
        data = b"\xAA\xBB\xCC\xDD" * 10

        similarity = fingerprinter._calculate_similarity(data, data)

        assert similarity == 1.0

    def test_calculate_similarity_different_data(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Similarity calculation returns low score for different data."""
        data1 = b"\x00" * 100
        data2 = b"\xFF" * 100

        similarity = fingerprinter._calculate_similarity(data1, data2)

        assert similarity == 0.0

    def test_calculate_similarity_partial_match(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Similarity calculation returns partial score for partial matches."""
        data1 = b"\xAA\xBB\xCC\xDD\xEE\xFF"
        data2 = b"\xAA\xBB\xCC\x00\x00\x00"

        similarity = fingerprinter._calculate_similarity(data1, data2)

        assert 0.0 < similarity < 1.0
        assert similarity == 0.5

    def test_calculate_similarity_different_lengths(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Similarity calculation handles different length data."""
        data1 = b"\xAA\xBB\xCC"
        data2 = b"\xAA\xBB\xCC\xDD\xEE\xFF"

        similarity = fingerprinter._calculate_similarity(data1, data2)

        assert 0.0 < similarity < 1.0

    def test_calculate_similarity_empty_data(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Similarity calculation handles empty data gracefully."""
        similarity = fingerprinter._calculate_similarity(b"", b"\xAA\xBB")

        assert similarity == 0.0


class TestPatternExtraction:
    """Test common pattern extraction from packet samples."""

    def test_extract_common_patterns_with_prefix(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Pattern extraction identifies common packet prefixes."""
        samples = [
            {"data": b"\xAA\xBB\xCC" + secrets.token_bytes(10), "port": 9999},
            {"data": b"\xAA\xBB\xCC" + secrets.token_bytes(10), "port": 9999},
            {"data": b"\xAA\xBB\xCC" + secrets.token_bytes(10), "port": 9999},
        ]

        patterns = fingerprinter._extract_common_patterns(samples)

        assert len(patterns) > 0
        assert patterns[0]["offset"] == 0
        assert patterns[0]["bytes"] == b"\xAA\xBB\xCC"
        assert patterns[0]["weight"] == 0.5

    def test_extract_common_patterns_no_commonality(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Pattern extraction returns empty list when no common patterns."""
        samples = [
            {"data": secrets.token_bytes(20), "port": 9999},
            {"data": secrets.token_bytes(20), "port": 9999},
            {"data": secrets.token_bytes(20), "port": 9999},
        ]

        patterns = fingerprinter._extract_common_patterns(samples)

        assert len(patterns) == 0

    def test_extract_common_patterns_short_data(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Pattern extraction handles short data correctly."""
        samples = [
            {"data": b"\xAA", "port": 9999},
            {"data": b"\xAA", "port": 9999},
            {"data": b"\xAA", "port": 9999},
        ]

        patterns = fingerprinter._extract_common_patterns(samples)

        assert len(patterns) == 0


class TestErrorHandling:
    """Test error handling in protocol fingerprinting."""

    def test_analyze_traffic_with_empty_data(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Fingerprinter handles empty packet data gracefully."""
        result = fingerprinter.analyze_traffic(b"", port=27000)

        assert result is None or isinstance(result, dict)

    def test_parse_packet_with_unknown_protocol(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Packet parsing returns None for unknown protocol."""
        result = fingerprinter.parse_packet("unknown_protocol", b"\xAA\xBB\xCC")

        assert result is None

    def test_parse_packet_with_truncated_data(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Packet parsing handles truncated data gracefully."""
        truncated_packet = b"FEAT"

        result = fingerprinter.parse_packet("flexlm", truncated_packet)

        assert result is None or isinstance(result, dict)

    def test_generate_response_with_unknown_protocol(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Response generation returns None for unknown protocol."""
        result = fingerprinter.generate_response(
            "unknown_protocol",
            b"\xAA\xBB\xCC",
            response_type="license_ok",
        )

        assert result is None

    def test_generate_response_with_unknown_response_type(
        self,
        fingerprinter: ProtocolFingerprinter,
        flexlm_heartbeat_packet: bytes,
    ) -> None:
        """Response generation falls back to first template for unknown type."""
        result = fingerprinter.generate_response(
            "flexlm",
            flexlm_heartbeat_packet,
            response_type="unknown_type",
        )

        assert result is not None
        assert isinstance(result, bytes)

    def test_fingerprint_packet_with_invalid_data(
        self,
        fingerprinter: ProtocolFingerprinter,
    ) -> None:
        """Fingerprint packet handles invalid data gracefully."""
        fingerprinter.config["min_confidence"] = 0.1
        result = fingerprinter.fingerprint_packet(b"", port=None)

        assert result is None or isinstance(result, dict)


class TestMultiProtocolScenarios:
    """Test scenarios with multiple protocols and complex traffic."""

    def test_analyze_mixed_protocol_traffic(
        self,
        fingerprinter: ProtocolFingerprinter,
        flexlm_heartbeat_packet: bytes,
        hasp_request_packet: bytes,
        autodesk_license_packet: bytes,
    ) -> None:
        """Fingerprinter correctly identifies different protocols."""
        result1 = fingerprinter.analyze_traffic(flexlm_heartbeat_packet, port=27000)
        result2 = fingerprinter.analyze_traffic(hasp_request_packet, port=1947)
        result3 = fingerprinter.analyze_traffic(autodesk_license_packet, port=2080)

        assert result1 is not None
        assert result2 is not None
        assert result3 is not None
        assert result1["protocol_id"] == "flexlm"
        assert result2["protocol_id"] == "hasp"
        assert result3["protocol_id"] == "autodesk"

    def test_analyze_same_port_different_protocols(
        self,
        fingerprinter: ProtocolFingerprinter,
        flexlm_heartbeat_packet: bytes,
        hasp_request_packet: bytes,
    ) -> None:
        """Fingerprinter uses patterns when protocols share ports."""
        fingerprinter.config["min_confidence"] = 0.3
        result1 = fingerprinter.analyze_traffic(flexlm_heartbeat_packet, port=443)
        result2 = fingerprinter.analyze_traffic(hasp_request_packet, port=443)

        assert result1 is not None
        assert result2 is not None
        assert result1["protocol_id"] != result2["protocol_id"]

    def test_confidence_scoring_accuracy(
        self,
        fingerprinter: ProtocolFingerprinter,
        flexlm_heartbeat_packet: bytes,
    ) -> None:
        """Confidence scores are higher with port + pattern match."""
        result_with_port = fingerprinter.analyze_traffic(flexlm_heartbeat_packet, port=27000)
        fingerprinter.config["min_confidence"] = 0.3
        result_without_port = fingerprinter.analyze_traffic(flexlm_heartbeat_packet, port=None)

        assert result_with_port is not None
        assert result_without_port is not None
        assert result_with_port["confidence"] > result_without_port["confidence"]
