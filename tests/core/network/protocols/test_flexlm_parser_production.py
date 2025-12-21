"""Production tests for intellicrack/core/network/protocols/flexlm_parser.py.

Validates FlexLM protocol parsing, license server emulation, and traffic analysis
for bypassing FlexLM licensing protections used by CAD/CAM/CAE software.

NO MOCKS - All tests use real FlexLM protocol structures and packet formats.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import struct
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.network.protocols.flexlm_parser import (
    FlexLMLicenseGenerator,
    FlexLMProtocolParser,
    FlexLMRequest,
    FlexLMResponse,
    FlexLMTrafficCapture,
)


class TestFlexLMProtocolParser:
    """Test FlexLM protocol parser with real packet structures."""

    def test_parser_initialization(self) -> None:
        """FlexLM parser initializes with default features and encryption seed."""
        parser = FlexLMProtocolParser()

        assert len(parser.server_features) > 0
        assert len(parser.encryption_seed) == 32
        assert len(parser.active_checkouts) == 0

        assert "AUTOCAD" in parser.server_features
        assert "MATLAB" in parser.server_features
        assert "SOLIDWORKS" in parser.server_features

    def test_parse_valid_checkout_request(self) -> None:
        """Parser correctly parses FlexLM CHECKOUT request with real packet structure."""
        parser = FlexLMProtocolParser()

        packet = bytearray()
        packet.extend(struct.pack(">I", 0x464C4558))
        packet.extend(struct.pack(">H", 0x01))
        packet.extend(struct.pack(">H", 0x01))
        packet.extend(struct.pack(">I", 12345))
        packet.extend(struct.pack(">I", 128))
        packet.extend(b"CLIENT001\x00")
        packet.extend(b"AUTOCAD\x00")
        packet.extend(b"2024.0\x00")
        packet.extend(b"win64\x00")
        packet.extend(b"workstation1\x00")
        packet.extend(b"user1\x00")
        packet.extend(struct.pack(">I", 5678))
        packet.extend(struct.pack(">I", int(time.time())))

        request = parser.parse_request(bytes(packet))

        assert request is not None
        assert request.command == 0x01
        assert request.version == 0x01
        assert request.sequence == 12345
        assert request.client_id == "CLIENT001"
        assert request.feature == "AUTOCAD"
        assert request.version_requested == "2024.0"
        assert request.platform == "win64"
        assert request.hostname == "workstation1"
        assert request.username == "user1"
        assert request.pid == 5678

    def test_parse_request_validates_magic_number(self) -> None:
        """Parser rejects packets with invalid FlexLM magic numbers."""
        parser = FlexLMProtocolParser()

        invalid_packet = struct.pack(">I", 0xDEADBEEF) + b"\x00" * 100

        request = parser.parse_request(invalid_packet)

        assert request is None

    def test_parse_request_handles_short_packets(self) -> None:
        """Parser rejects packets shorter than minimum header size."""
        parser = FlexLMProtocolParser()

        short_packet = b"FLEX"

        request = parser.parse_request(short_packet)

        assert request is None

    def test_generate_checkout_response_for_existing_feature(self) -> None:
        """Parser generates valid CHECKOUT response for known features."""
        parser = FlexLMProtocolParser()

        request = FlexLMRequest(
            command=0x01,
            version=1,
            sequence=1,
            client_id="CLIENT001",
            feature="AUTOCAD",
            version_requested="2024.0",
            platform="win64",
            hostname="workstation1",
            username="user1",
            pid=1234,
            checkout_time=int(time.time()),
            additional_data={},
        )

        response = parser.generate_response(request)

        assert response.status == 0x00
        assert response.feature == "AUTOCAD"
        assert len(response.license_key) > 0
        assert response.expiry_date == "31-dec-2025"
        assert response.server_id == "intellicrack-flexlm"

    def test_generate_checkout_response_feature_not_found(self) -> None:
        """Parser returns FEATURE_NOT_FOUND for unknown features."""
        parser = FlexLMProtocolParser()

        request = FlexLMRequest(
            command=0x01,
            version=1,
            sequence=1,
            client_id="CLIENT001",
            feature="NONEXISTENT",
            version_requested="1.0",
            platform="win64",
            hostname="workstation1",
            username="user1",
            pid=1234,
            checkout_time=int(time.time()),
            additional_data={},
        )

        response = parser.generate_response(request)

        assert response.status == 0x01

    def test_generate_checkout_tracks_active_sessions(self) -> None:
        """CHECKOUT generates unique keys and tracks active sessions."""
        parser = FlexLMProtocolParser()

        request = FlexLMRequest(
            command=0x01,
            version=1,
            sequence=1,
            client_id="CLIENT001",
            feature="AUTOCAD",
            version_requested="2024.0",
            platform="win64",
            hostname="workstation1",
            username="user1",
            pid=1234,
            checkout_time=int(time.time()),
            additional_data={},
        )

        initial_checkouts = len(parser.active_checkouts)
        response = parser.generate_response(request)

        assert len(parser.active_checkouts) == initial_checkouts + 1
        assert response.license_key.startswith("S") or response.license_key.startswith("P") or response.license_key.startswith("T")
        assert len(response.license_key) == 32

    def test_generate_checkin_removes_active_session(self) -> None:
        """CHECKIN removes session from active checkouts."""
        parser = FlexLMProtocolParser()

        checkout_req = FlexLMRequest(
            command=0x01,
            version=1,
            sequence=1,
            client_id="CLIENT001",
            feature="AUTOCAD",
            version_requested="2024.0",
            platform="win64",
            hostname="workstation1",
            username="user1",
            pid=1234,
            checkout_time=int(time.time()),
            additional_data={},
        )

        parser.generate_response(checkout_req)
        initial_count = len(parser.active_checkouts)

        checkin_req = FlexLMRequest(
            command=0x02,
            version=1,
            sequence=2,
            client_id="CLIENT001",
            feature="AUTOCAD",
            version_requested="2024.0",
            platform="win64",
            hostname="workstation1",
            username="user1",
            pid=1234,
            checkout_time=int(time.time()),
            additional_data={},
        )

        response = parser.generate_response(checkin_req)

        assert response.status == 0x00
        assert len(parser.active_checkouts) == initial_count - 1

    def test_generate_status_response(self) -> None:
        """STATUS request returns server status with active checkout count."""
        parser = FlexLMProtocolParser()

        request = FlexLMRequest(
            command=0x03,
            version=1,
            sequence=1,
            client_id="CLIENT001",
            feature="",
            version_requested="",
            platform="win64",
            hostname="workstation1",
            username="user1",
            pid=1234,
            checkout_time=int(time.time()),
            additional_data={},
        )

        response = parser.generate_response(request)

        assert response.status == 0x00
        assert "server_status" in response.additional_data
        assert response.additional_data["server_status"] == "UP"
        assert "active_checkouts" in response.additional_data
        assert "features_available" in response.additional_data

    def test_generate_heartbeat_updates_session(self) -> None:
        """HEARTBEAT updates last heartbeat timestamp for active sessions."""
        parser = FlexLMProtocolParser()

        checkout_req = FlexLMRequest(
            command=0x01,
            version=1,
            sequence=1,
            client_id="CLIENT001",
            feature="AUTOCAD",
            version_requested="2024.0",
            platform="win64",
            hostname="workstation1",
            username="user1",
            pid=1234,
            checkout_time=int(time.time()),
            additional_data={},
        )

        parser.generate_response(checkout_req)

        heartbeat_req = FlexLMRequest(
            command=0x04,
            version=1,
            sequence=2,
            client_id="CLIENT001",
            feature="AUTOCAD",
            version_requested="2024.0",
            platform="win64",
            hostname="workstation1",
            username="user1",
            pid=1234,
            checkout_time=int(time.time()),
            additional_data={},
        )

        response = parser.generate_response(heartbeat_req)

        assert response.status == 0x00
        assert "heartbeat_time" in response.additional_data

    def test_serialize_response_creates_valid_packet(self) -> None:
        """serialize_response creates valid FlexLM response packet."""
        parser = FlexLMProtocolParser()

        response = FlexLMResponse(
            status=0x00,
            sequence=1,
            server_version="11.18.0",
            feature="AUTOCAD",
            expiry_date="31-dec-2025",
            license_key="ABC123",
            server_id="intellicrack-flexlm",
            additional_data={"vendor": "ADSKFLEX"},
        )

        packet = parser.serialize_response(response)

        assert len(packet) > 0
        assert packet[:4] == struct.pack(">I", 0x464C4558)

    def test_add_custom_feature(self) -> None:
        """add_custom_feature adds new feature to server catalog."""
        parser = FlexLMProtocolParser()

        initial_count = len(parser.server_features)

        parser.add_custom_feature(
            name="CUSTOM_APP",
            version="1.0",
            vendor="CUSTOM",
            count=50,
            expiry="31-dec-2026",
        )

        assert len(parser.server_features) == initial_count + 1
        assert "CUSTOM_APP" in parser.server_features
        assert parser.server_features["CUSTOM_APP"]["vendor"] == "CUSTOM"
        assert parser.server_features["CUSTOM_APP"]["count"] == 50

    def test_remove_feature(self) -> None:
        """remove_feature removes feature from server catalog."""
        parser = FlexLMProtocolParser()

        parser.add_custom_feature("TEST_FEATURE", "1.0", "TEST")
        assert "TEST_FEATURE" in parser.server_features

        parser.remove_feature("TEST_FEATURE")

        assert "TEST_FEATURE" not in parser.server_features

    def test_get_server_statistics(self) -> None:
        """get_server_statistics returns accurate server metrics."""
        parser = FlexLMProtocolParser()

        stats = parser.get_server_statistics()

        assert "total_features" in stats
        assert "active_checkouts" in stats
        assert "features" in stats
        assert "server_version" in stats

        assert stats["total_features"] > 0
        assert stats["server_version"] == "11.18.0"


class TestFlexLMTrafficCapture:
    """Test FlexLM traffic capture and analysis."""

    def test_traffic_capture_initialization(self) -> None:
        """FlexLM traffic capture initializes with empty state."""
        parser = FlexLMProtocolParser()
        capture = FlexLMTrafficCapture(parser)

        assert len(capture.captured_requests) == 0
        assert len(capture.captured_responses) == 0
        assert len(capture.server_endpoints) == 0
        assert len(capture.client_endpoints) == 0

    def test_capture_packet_parses_flexlm_request(self) -> None:
        """capture_packet parses and stores valid FlexLM requests."""
        parser = FlexLMProtocolParser()
        capture = FlexLMTrafficCapture(parser)

        packet = bytearray()
        packet.extend(struct.pack(">I", 0x464C4558))
        packet.extend(struct.pack(">H", 0x01))
        packet.extend(struct.pack(">H", 0x01))
        packet.extend(struct.pack(">I", 1))
        packet.extend(struct.pack(">I", 100))
        packet.extend(b"CLIENT\x00FEATURE\x001.0\x00win64\x00host\x00user\x00")
        packet.extend(struct.pack(">II", 1234, int(time.time())))

        result = capture.capture_packet(
            bytes(packet),
            ("192.168.1.100", 5000),
            ("192.168.1.1", 27000),
        )

        assert result is True
        assert len(capture.captured_requests) == 1
        assert ("192.168.1.100", 5000) in capture.client_endpoints
        assert ("192.168.1.1", 27000) in capture.server_endpoints

    def test_analyze_traffic_patterns_empty(self) -> None:
        """analyze_traffic_patterns handles empty capture gracefully."""
        parser = FlexLMProtocolParser()
        capture = FlexLMTrafficCapture(parser)

        result = capture.analyze_traffic_patterns()

        assert "error" in result

    def test_analyze_traffic_patterns_with_data(self) -> None:
        """analyze_traffic_patterns provides statistics on captured traffic."""
        parser = FlexLMProtocolParser()
        capture = FlexLMTrafficCapture(parser)

        for i in range(5):
            packet = bytearray()
            packet.extend(struct.pack(">I", 0x464C4558))
            packet.extend(struct.pack(">H", 0x01))
            packet.extend(struct.pack(">H", 0x01))
            packet.extend(struct.pack(">I", i))
            packet.extend(struct.pack(">I", 100))
            packet.extend(b"CLIENT\x00AUTOCAD\x002024.0\x00win64\x00host\x00user\x00")
            packet.extend(struct.pack(">II", 1234, int(time.time())))

            capture.capture_packet(bytes(packet), ("192.168.1.100", 5000), ("192.168.1.1", 27000))

        result = capture.analyze_traffic_patterns()

        assert "total_packets" in result
        assert result["total_packets"] == 5
        assert "unique_clients" in result
        assert "unique_servers" in result
        assert "command_distribution" in result

    def test_extract_license_info(self) -> None:
        """extract_license_info extracts license details from checkouts."""
        parser = FlexLMProtocolParser()
        capture = FlexLMTrafficCapture(parser)

        packet = bytearray()
        packet.extend(struct.pack(">I", 0x464C4558))
        packet.extend(struct.pack(">H", 0x01))
        packet.extend(struct.pack(">H", 0x01))
        packet.extend(struct.pack(">I", 1))
        packet.extend(struct.pack(">I", 100))
        packet.extend(b"CLIENT\x00AUTOCAD\x002024.0\x00win64\x00workstation1\x00user1\x00")
        packet.extend(struct.pack(">II", 1234, int(time.time())))

        capture.capture_packet(bytes(packet), ("192.168.1.100", 5000), ("192.168.1.1", 27000))

        licenses = capture.extract_license_info()

        assert len(licenses) == 1
        assert licenses[0]["feature"] == "AUTOCAD"
        assert licenses[0]["version"] == "2024.0"
        assert licenses[0]["client"] == "workstation1"
        assert licenses[0]["username"] == "user1"


class TestFlexLMLicenseGenerator:
    """Test FlexLM license file generation."""

    def test_generate_license_file_basic(self) -> None:
        """generate_license_file creates valid FlexLM license format."""
        generator = FlexLMLicenseGenerator()

        features = [
            {
                "name": "AUTOCAD",
                "version": "2024.0",
                "vendor": "ADSKFLEX",
                "expiry": "31-dec-2025",
                "count": 100,
            }
        ]

        license_content = generator.generate_license_file(
            features=features,
            server_host="license.example.com",
            server_port=27000,
            vendor_daemon="ADSKFLEX",
            vendor_port=27001,
        )

        assert "SERVER license.example.com" in license_content
        assert "27000" in license_content
        assert "VENDOR ADSKFLEX PORT=27001" in license_content
        assert "FEATURE AUTOCAD" in license_content
        assert "2024.0" in license_content
        assert "31-dec-2025" in license_content

    def test_generate_license_file_multiple_features(self) -> None:
        """generate_license_file handles multiple features."""
        generator = FlexLMLicenseGenerator()

        features = [
            {"name": "FEATURE1", "version": "1.0", "vendor": "VENDOR1"},
            {"name": "FEATURE2", "version": "2.0", "vendor": "VENDOR2"},
            {"name": "FEATURE3", "version": "3.0", "vendor": "VENDOR3"},
        ]

        license_content = generator.generate_license_file(
            features=features, server_host="localhost"
        )

        assert license_content.count("FEATURE") >= 3
        assert "FEATURE1" in license_content
        assert "FEATURE2" in license_content
        assert "FEATURE3" in license_content

    def test_parse_license_file(self) -> None:
        """parse_license_file extracts license information correctly."""
        generator = FlexLMLicenseGenerator()

        license_text = """
SERVER license.example.com ANY 27000
VENDOR ADSKFLEX PORT=27001

FEATURE AUTOCAD ADSKFLEX 2024.0 31-dec-2025 100 HOSTID=ANY SIGN="ABC123"
FEATURE INVENTOR ADSKFLEX 2024.0 31-dec-2025 50 HOSTID=ANY SIGN="DEF456"
"""

        parsed = generator.parse_license_file(license_text)

        assert len(parsed["servers"]) == 1
        assert parsed["servers"][0]["hostname"] == "license.example.com"
        assert parsed["servers"][0]["port"] == 27000

        assert len(parsed["vendors"]) == 1
        assert parsed["vendors"][0]["name"] == "ADSKFLEX"
        assert parsed["vendors"][0]["port"] == 27001

        assert len(parsed["features"]) == 2
        assert parsed["features"][0]["name"] == "AUTOCAD"
        assert parsed["features"][1]["name"] == "INVENTOR"


class TestFlexLMProtocolIntegration:
    """Integration tests for FlexLM protocol operations."""

    def test_complete_license_checkout_workflow(self) -> None:
        """Complete license checkout workflow from request to response."""
        parser = FlexLMProtocolParser()

        packet = bytearray()
        packet.extend(struct.pack(">I", 0x464C4558))
        packet.extend(struct.pack(">H", 0x01))
        packet.extend(struct.pack(">H", 0x01))
        packet.extend(struct.pack(">I", 1))
        packet.extend(struct.pack(">I", 100))
        packet.extend(b"CLIENT001\x00AUTOCAD\x002024.0\x00win64\x00workstation1\x00user1\x00")
        packet.extend(struct.pack(">II", 1234, int(time.time())))

        request = parser.parse_request(bytes(packet))
        assert request is not None

        response = parser.generate_response(request)
        assert response.status == 0x00

        response_packet = parser.serialize_response(response)
        assert len(response_packet) > 0

    def test_license_file_generation_and_parsing_roundtrip(self) -> None:
        """License file can be generated and parsed correctly."""
        generator = FlexLMLicenseGenerator()

        features = [
            {
                "name": "TEST_FEATURE",
                "version": "1.0",
                "vendor": "TEST_VENDOR",
                "expiry": "31-dec-2025",
                "count": 10,
            }
        ]

        generated = generator.generate_license_file(
            features=features, server_host="test.server", vendor_daemon="TEST_VENDOR"
        )

        parsed = generator.parse_license_file(generated)

        assert len(parsed["features"]) == 1
        assert parsed["features"][0]["name"] == "TEST_FEATURE"
        assert parsed["features"][0]["version"] == "1.0"

    def test_traffic_capture_and_analysis_workflow(self) -> None:
        """Complete traffic capture and analysis workflow."""
        parser = FlexLMProtocolParser()
        capture = FlexLMTrafficCapture(parser)

        for i in range(10):
            packet = bytearray()
            packet.extend(struct.pack(">I", 0x464C4558))
            packet.extend(struct.pack(">H", 0x01))
            packet.extend(struct.pack(">H", 0x01))
            packet.extend(struct.pack(">I", i))
            packet.extend(struct.pack(">I", 100))
            packet.extend(f"CLIENT{i:03d}\x00AUTOCAD\x002024.0\x00win64\x00host{i}\x00user{i}\x00".encode())
            packet.extend(struct.pack(">II", 1000 + i, int(time.time())))

            capture.capture_packet(
                bytes(packet),
                (f"192.168.1.{100 + i}", 5000 + i),
                ("192.168.1.1", 27000),
            )

        analysis = capture.analyze_traffic_patterns()
        assert analysis["total_packets"] == 10
        assert analysis["unique_clients"] == 10
        assert analysis["unique_servers"] == 1

        licenses = capture.extract_license_info()
        assert len(licenses) == 10
