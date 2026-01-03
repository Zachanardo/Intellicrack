"""Production tests for FlexLM binary protocol parsing and advanced features.

Tests MUST validate real FlexLM binary protocol parsing capabilities including:
- Binary FlexLM protocol parsing (lmgrd binary format)
- RLM (Reprise License Manager) protocol support
- Encrypted FlexLM payload handling (SIGN= field calculation)
- Vendor daemon communication packet parsing
- License checkout/checkin sequence reconstruction
- Valid license file response generation
- Edge cases: FlexLM 11.x differences, lmgrd clustering, redundant servers

NO MOCKS - All tests use real protocol structures and must FAIL if functionality
is incomplete or non-functional.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from __future__ import annotations

import hashlib
import json
import struct
import time
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.core.network.protocols.flexlm_parser import (
    FlexLMLicenseGenerator,
    FlexLMProtocolParser,
    FlexLMRequest,
    FlexLMResponse,
    FlexLMTrafficCapture,
)


if TYPE_CHECKING:
    from pathlib import Path


SHA256_DIGEST_LEN: int = 64


def _validate_protocol_data(data: Any) -> bool:
    """Validate protocol data structure using hashlib verification."""
    if isinstance(data, (bytes, bytearray)):
        hash_digest: str = hashlib.sha256(bytes(data)).hexdigest()
        return len(hash_digest) == SHA256_DIGEST_LEN
    return False


DEFAULT_SERVER_PORT: int = 27000
ALTERNATE_VENDOR_PORT: int = 27001
LARGE_CONCURRENCY_THRESHOLD: int = 1000
TRAFFIC_CAPTURE_THRESHOLD: int = 10000
RSA_KEY_SIZE: int = 2048
PACKET_PAYLOAD_SIZE: int = 128
HEADER_BYTES: int = 4
FLEXLM_MAGIC_FLEX: int = 0x464C4558
FLEXLM_MAGIC_LM_V: int = 0x4C4D5F56
FLEXLM_MAGIC_FXLM: int = 0x46584C4D
FLEXLM_COMMAND_CHECKOUT: int = 0x01
FLEXLM_COMMAND_CHECKIN: int = 0x02
FLEXLM_COMMAND_VENDOR_DAEMON: int = 0x08
FLEXLM_COMMAND_ENCRYPTION_SEED: int = 0x11
FLEXLM_COMMAND_HOSTID: int = 0x10
FLEXLM_COMMAND_RLM: int = 0x05
FLEXLM_COMMAND_RLM_VERSION: int = 0x02
FLEXLM_COMMAND_HEARTBEAT: int = 0x04
FLEXLM_COMMAND_SERVER_INFO: int = 0x06
FLEXLM_COMMAND_BORROW_REQUEST: int = 0x12
FLEXLM_COMMAND_RETURN_REQUEST: int = 0x13
FLEXLM_COMMAND_UNKNOWN: int = 0xFF
FLEXLM_RESPONSE_OK: int = 0x00
FLEXLM_RESPONSE_INVALID_SESSION: int = 0x06
FLEXLM_PACKET_VERSION: int = 0x01
FLEXLM_ADDITIONAL_DATA_HOSTID: int = 0x0001
FLEXLM_ADDITIONAL_DATA_ENCRYPTION: int = 0x0002
FLEXLM_ADDITIONAL_DATA_VENDOR: int = 0x0003
FLEXLM_ADDITIONAL_DATA_LICENSE_PATH: int = 0x0004
FLEXLM_FEATURE_SIGNATURE_LEN: int = 40
FLEXLM_HOSTID_LEN: int = 12
FLEXLM_ENCRYPTION_SEED_LEN: int = 64
FLEXLM_PACKET_SIZE_SMALL: int = 128
FLEXLM_PACKET_SIZE_LARGE: int = 150
FLEXLM_PACKET_SIZE_XLARGE: int = 180
FLEXLM_PACKET_SIZE_200: int = 200
FLEXLM_SEQUENCE_SMALL: int = 1234
FLEXLM_SEQUENCE_MEDIUM: int = 5000
FLEXLM_SEQUENCE_LARGE: int = 7777
FLEXLM_SEQUENCE_XLARGE: int = 99999
FLEXLM_PID_SMALL: int = 1234
FLEXLM_PID_MEDIUM: int = 5555
FLEXLM_PID_LARGE: int = 8888
FLEXLM_PID_XLARGE: int = 9999
FLEXLM_PID_VENDOR: int = 31415
FLEXLM_CONCURRENT_CHECKOUTS: int = 3
PERFORMANCE_TIMEOUT_SHORT: float = 5.0
PERFORMANCE_TIMEOUT_LONG: float = 10.0
CLUSTER_NODE_COUNT: int = 3
CLUSTER_SERVER_COUNT: int = 3
CLUSTER_FEATURES_COUNT: int = 5
TIME_OFFSET_MINUTE: int = 60
TIME_OFFSET_HOUR: int = 3600
LICENSE_FILE_FEATURES_COUNT: int = 2


class TestFlexLMBinaryProtocolParsing:
    """Test FlexLM binary protocol parsing with lmgrd binary format."""

    def test_parse_binary_flexlm_checkout_with_all_magic_numbers(self) -> None:
        """Parser accepts all valid FlexLM magic numbers (FLEX, LM_V, FXLM)."""
        parser = FlexLMProtocolParser()

        magic_numbers = [
            FLEXLM_MAGIC_FLEX,
            FLEXLM_MAGIC_LM_V,
            FLEXLM_MAGIC_FXLM,
        ]

        for magic in magic_numbers:
            packet = bytearray()
            packet.extend(struct.pack(">I", magic))
            packet.extend(struct.pack(">H", FLEXLM_PACKET_VERSION))
            packet.extend(struct.pack(">H", FLEXLM_PACKET_VERSION))
            packet.extend(struct.pack(">I", 12345))
            packet.extend(struct.pack(">I", FLEXLM_PACKET_SIZE_SMALL))
            packet.extend(b"CLIENT001\x00")
            packet.extend(b"AUTOCAD\x00")
            packet.extend(b"2024.0\x00")
            packet.extend(b"win64\x00")
            packet.extend(b"workstation1\x00")
            packet.extend(b"user1\x00")
            packet.extend(struct.pack(">I", 5678))
            packet.extend(struct.pack(">I", int(time.time())))

            request = parser.parse_request(bytes(packet))

            assert request is not None, f"Must parse magic number 0x{magic:08X}"
            assert request.command == FLEXLM_COMMAND_CHECKOUT
            assert request.feature == "AUTOCAD"

    def test_parse_binary_flexlm_with_additional_fields(self) -> None:
        """Parser correctly parses additional data fields in binary format."""
        parser = FlexLMProtocolParser()

        packet = bytearray()
        packet.extend(struct.pack(">I", FLEXLM_MAGIC_FLEX))
        packet.extend(struct.pack(">H", FLEXLM_COMMAND_CHECKOUT))
        packet.extend(struct.pack(">H", FLEXLM_PACKET_VERSION))
        packet.extend(struct.pack(">I", 12345))
        packet.extend(struct.pack(">I", FLEXLM_PACKET_SIZE_200))
        packet.extend(b"CLIENT001\x00")
        packet.extend(b"AUTOCAD\x00")
        packet.extend(b"2024.0\x00")
        packet.extend(b"win64\x00")
        packet.extend(b"workstation1\x00")
        packet.extend(b"user1\x00")
        packet.extend(struct.pack(">I", 5678))
        packet.extend(struct.pack(">I", int(time.time())))

        hostid_data = b"AABBCCDDEEFF"
        packet.extend(struct.pack(">HH", FLEXLM_ADDITIONAL_DATA_HOSTID, len(hostid_data)))
        packet.extend(hostid_data)

        encryption_data = b"\x01\x02\x03\x04"
        packet.extend(struct.pack(">HH", FLEXLM_ADDITIONAL_DATA_ENCRYPTION, len(encryption_data)))
        packet.extend(encryption_data)

        request = parser.parse_request(bytes(packet))

        assert request is not None
        assert "hostid" in request.additional_data
        assert request.additional_data["hostid"] == hostid_data.hex()
        assert "encryption" in request.additional_data
        assert request.additional_data["encryption"] == encryption_data.hex()

    def test_parse_vendor_daemon_communication_packet(self) -> None:
        """Parser handles vendor daemon-specific communication packets."""
        parser = FlexLMProtocolParser()

        packet = bytearray()
        packet.extend(struct.pack(">I", FLEXLM_MAGIC_FLEX))
        packet.extend(struct.pack(">H", FLEXLM_COMMAND_VENDOR_DAEMON))
        packet.extend(struct.pack(">H", FLEXLM_PACKET_VERSION))
        packet.extend(struct.pack(">I", FLEXLM_SEQUENCE_XLARGE))
        packet.extend(struct.pack(">I", FLEXLM_PACKET_SIZE_XLARGE))
        packet.extend(b"VENDOR_CLIENT\x00")
        packet.extend(b"MATLAB\x00")
        packet.extend(b"R2024a\x00")
        packet.extend(b"linux64\x00")
        packet.extend(b"compute-node-42\x00")
        packet.extend(b"researcher\x00")
        packet.extend(struct.pack(">I", FLEXLM_PID_VENDOR))
        packet.extend(struct.pack(">I", int(time.time())))

        vendor_data = b"VENDOR_SPECIFIC_DATA_PAYLOAD"
        packet.extend(struct.pack(">HH", FLEXLM_ADDITIONAL_DATA_VENDOR, len(vendor_data)))
        packet.extend(vendor_data)

        request = parser.parse_request(bytes(packet))

        assert request is not None
        assert request.command == FLEXLM_COMMAND_VENDOR_DAEMON
        assert request.feature == "MATLAB"
        assert "vendor_data" in request.additional_data
        assert request.additional_data["vendor_data"] == vendor_data.hex()

    def test_parse_flexlm_encryption_seed_request(self) -> None:
        """Parser handles ENCRYPTION_SEED requests for protocol security."""
        parser = FlexLMProtocolParser()

        request = FlexLMRequest(
            command=FLEXLM_COMMAND_ENCRYPTION_SEED,
            version=FLEXLM_PACKET_VERSION,
            sequence=FLEXLM_SEQUENCE_MEDIUM,
            client_id="SECURE_CLIENT",
            feature="",
            version_requested="",
            platform="win64",
            hostname="secure-workstation",
            username="admin",
            pid=FLEXLM_PID_XLARGE,
            checkout_time=int(time.time()),
            additional_data={},
        )

        response = parser.generate_response(request)

        assert response.status == FLEXLM_RESPONSE_OK
        assert "encryption_seed" in response.additional_data
        assert len(response.additional_data["encryption_seed"]) == FLEXLM_ENCRYPTION_SEED_LEN

    def test_parse_hostid_request_generates_deterministic_id(self) -> None:
        """Parser generates consistent host IDs for same hostname."""
        parser = FlexLMProtocolParser()

        request1 = FlexLMRequest(
            command=FLEXLM_COMMAND_HOSTID,
            version=FLEXLM_PACKET_VERSION,
            sequence=FLEXLM_PACKET_VERSION,
            client_id="CLIENT",
            feature="",
            version_requested="",
            platform="win64",
            hostname="test-machine",
            username="user",
            pid=FLEXLM_PID_SMALL,
            checkout_time=int(time.time()),
            additional_data={},
        )

        response1 = parser.generate_response(request1)
        response2 = parser.generate_response(request1)

        assert response1.additional_data["hostid"] == response2.additional_data["hostid"]
        assert len(response1.additional_data["hostid"]) == FLEXLM_HOSTID_LEN


class TestRLMProtocolSupport:
    """Test RLM (Reprise License Manager) protocol support."""

    def test_parse_rlm_style_request_packet(self) -> None:
        """Parser handles RLM-style request packets with RLM conventions."""
        parser = FlexLMProtocolParser()

        packet = bytearray()
        packet.extend(struct.pack(">I", FLEXLM_MAGIC_FLEX))
        packet.extend(struct.pack(">H", FLEXLM_COMMAND_RLM))
        packet.extend(struct.pack(">H", FLEXLM_COMMAND_RLM_VERSION))
        packet.extend(struct.pack(">I", FLEXLM_SEQUENCE_LARGE))
        packet.extend(struct.pack(">I", FLEXLM_PACKET_SIZE_XLARGE))
        packet.extend(b"RLM_CLIENT\x00")
        packet.extend(b"ANSYS\x00")
        packet.extend(b"2024.1\x00")
        packet.extend(b"linux_x64\x00")
        packet.extend(b"rlm-server-1\x00")
        packet.extend(b"engineer\x00")
        packet.extend(struct.pack(">I", FLEXLM_SEQUENCE_SMALL))
        packet.extend(struct.pack(">I", int(time.time())))

        license_path = b"/opt/ansys/licenses/license.dat"
        packet.extend(struct.pack(">HH", FLEXLM_ADDITIONAL_DATA_LICENSE_PATH, len(license_path)))
        packet.extend(license_path)

        request = parser.parse_request(bytes(packet))

        assert request is not None
        assert request.command == FLEXLM_COMMAND_RLM
        assert request.feature == "ANSYS"
        assert request.version == FLEXLM_COMMAND_RLM_VERSION
        assert "license_path" in request.additional_data

    def test_generate_rlm_feature_info_response(self) -> None:
        """Parser generates RLM-compatible feature info responses."""
        parser = FlexLMProtocolParser()

        parser.add_custom_feature(
            name="RLM_TEST_FEATURE",
            version="5.0",
            vendor="RLM_VENDOR",
            count=25,
            expiry="31-dec-2026",
        )

        request = FlexLMRequest(
            command=FLEXLM_COMMAND_RLM,
            version=FLEXLM_COMMAND_RLM_VERSION,
            sequence=FLEXLM_PID_LARGE,
            client_id="RLM_CLIENT",
            feature="RLM_TEST_FEATURE",
            version_requested="5.0",
            platform="linux_x64",
            hostname="rlm-client-node",
            username="testuser",
            pid=FLEXLM_PID_MEDIUM,
            checkout_time=int(time.time()),
            additional_data={},
        )

        response = parser.generate_response(request)

        assert response.status == FLEXLM_RESPONSE_OK
        assert response.feature == "RLM_TEST_FEATURE"
        assert response.additional_data["version"] == "5.0"
        assert response.additional_data["vendor"] == "RLM_VENDOR"


class TestEncryptedPayloadHandling:
    """Test encrypted FlexLM payload handling and SIGN= field calculation."""

    def test_generate_response_includes_signature_field(self) -> None:
        """Response includes SIGN= field with signature data."""
        parser = FlexLMProtocolParser()

        request = FlexLMRequest(
            command=FLEXLM_COMMAND_CHECKOUT,
            version=FLEXLM_PACKET_VERSION,
            sequence=FLEXLM_PACKET_VERSION,
            client_id="CLIENT001",
            feature="AUTOCAD",
            version_requested="2024.0",
            platform="win64",
            hostname="workstation1",
            username="user1",
            pid=FLEXLM_PID_SMALL,
            checkout_time=int(time.time()),
            additional_data={},
        )

        response = parser.generate_response(request)

        assert "signature" in response.additional_data
        assert len(response.additional_data["signature"]) == FLEXLM_FEATURE_SIGNATURE_LEN
        assert all(c in "0123456789ABCDEF" for c in response.additional_data["signature"])

    def test_signature_calculation_deterministic_for_feature(self) -> None:
        """Signature calculation is deterministic based on feature info."""
        parser = FlexLMProtocolParser()

        feature_name = "DETERMINISTIC_TEST"
        parser.add_custom_feature(
            name=feature_name,
            version="1.0",
            vendor="TEST",
            signature="FIXED_SIGNATURE_FOR_TESTING_PURPOSES_HERE",
        )

        request = FlexLMRequest(
            command=FLEXLM_COMMAND_CHECKOUT,
            version=FLEXLM_PACKET_VERSION,
            sequence=FLEXLM_PACKET_VERSION,
            client_id="CLIENT",
            feature=feature_name,
            version_requested="1.0",
            platform="win64",
            hostname="host",
            username="user",
            pid=FLEXLM_PID_SMALL,
            checkout_time=int(time.time()),
            additional_data={},
        )

        response1 = parser.generate_response(request)
        response2 = parser.generate_response(request)

        assert response1.additional_data["signature"] == response2.additional_data["signature"]

    def test_license_file_includes_sign_field(self) -> None:
        """Generated license files include SIGN= field with calculated signature."""
        generator = FlexLMLicenseGenerator()

        features = [
            {
                "name": "SIGNED_FEATURE",
                "version": "2.0",
                "vendor": "VENDOR",
                "expiry": "31-dec-2025",
                "count": 10,
            }
        ]

        license_content = generator.generate_license_file(
            features=features,
            server_host="license.server",
            vendor_daemon="VENDOR",
        )

        assert 'SIGN="' in license_content
        assert license_content.count('SIGN="') == 1

        lines = license_content.split("\n")
        feature_line = next(line for line in lines if "FEATURE SIGNED_FEATURE" in line)
        assert 'SIGN="' in feature_line
        sign_start = feature_line.index('SIGN="') + 6
        sign_end = feature_line.index('"', sign_start)
        signature = feature_line[sign_start:sign_end]
        assert len(signature) == FLEXLM_FEATURE_SIGNATURE_LEN


class TestLicenseCheckoutCheckinSequences:
    """Test license checkout/checkin sequence reconstruction."""

    def test_complete_checkout_checkin_sequence(self) -> None:
        """Parser correctly handles complete checkout-heartbeat-checkin sequence."""
        parser = FlexLMProtocolParser()

        checkout_request = FlexLMRequest(
            command=FLEXLM_COMMAND_CHECKOUT,
            version=FLEXLM_PACKET_VERSION,
            sequence=FLEXLM_PACKET_VERSION,
            client_id="SEQ_CLIENT",
            feature="MATLAB",
            version_requested="R2024a",
            platform="win64",
            hostname="matlab-ws-01",
            username="scientist",
            pid=FLEXLM_PID_LARGE,
            checkout_time=int(time.time()),
            additional_data={},
        )

        checkout_response = parser.generate_response(checkout_request)
        assert checkout_response.status == FLEXLM_RESPONSE_OK
        assert len(parser.active_checkouts) == FLEXLM_PACKET_VERSION

        heartbeat_request = FlexLMRequest(
            command=FLEXLM_COMMAND_HEARTBEAT,
            version=FLEXLM_PACKET_VERSION,
            sequence=FLEXLM_COMMAND_CHECKIN,
            client_id="SEQ_CLIENT",
            feature="MATLAB",
            version_requested="R2024a",
            platform="win64",
            hostname="matlab-ws-01",
            username="scientist",
            pid=FLEXLM_PID_LARGE,
            checkout_time=int(time.time()),
            additional_data={},
        )

        heartbeat_response = parser.generate_response(heartbeat_request)
        assert heartbeat_response.status == FLEXLM_RESPONSE_OK
        assert len(parser.active_checkouts) == FLEXLM_PACKET_VERSION

        checkin_request = FlexLMRequest(
            command=FLEXLM_COMMAND_CHECKIN,
            version=FLEXLM_PACKET_VERSION,
            sequence=FLEXLM_COMMAND_VENDOR_DAEMON,
            client_id="SEQ_CLIENT",
            feature="MATLAB",
            version_requested="R2024a",
            platform="win64",
            hostname="matlab-ws-01",
            username="scientist",
            pid=FLEXLM_PID_LARGE,
            checkout_time=int(time.time()),
            additional_data={},
        )

        checkin_response = parser.generate_response(checkin_request)
        assert checkin_response.status == FLEXLM_RESPONSE_OK
        assert len(parser.active_checkouts) == FLEXLM_RESPONSE_OK

    def test_reconstruct_checkout_sequence_from_traffic(self) -> None:
        """Traffic capture reconstructs complete checkout sequences."""
        parser = FlexLMProtocolParser()
        capture = FlexLMTrafficCapture(parser)

        base_time = time.time()
        client_addr = ("10.0.0.50", 54321)
        server_addr = ("10.0.0.1", DEFAULT_SERVER_PORT)

        checkout_packet = self._build_flexlm_packet(FLEXLM_COMMAND_CHECKOUT, FLEXLM_PACKET_VERSION, "AUTOCAD", "user1", "host1")
        capture.capture_packet(checkout_packet, client_addr, server_addr, base_time)

        heartbeat_packet = self._build_flexlm_packet(FLEXLM_COMMAND_HEARTBEAT, FLEXLM_COMMAND_CHECKIN, "AUTOCAD", "user1", "host1")
        capture.capture_packet(heartbeat_packet, client_addr, server_addr, base_time + TIME_OFFSET_MINUTE)

        checkin_packet = self._build_flexlm_packet(FLEXLM_COMMAND_CHECKIN, FLEXLM_COMMAND_VENDOR_DAEMON, "AUTOCAD", "user1", "host1")
        capture.capture_packet(checkin_packet, client_addr, server_addr, base_time + TIME_OFFSET_HOUR)

        assert len(capture.captured_requests) == FLEXLM_COMMAND_VENDOR_DAEMON

        analysis = capture.analyze_traffic_patterns()
        assert analysis["total_packets"] == FLEXLM_COMMAND_VENDOR_DAEMON
        assert FLEXLM_COMMAND_CHECKOUT in analysis["command_distribution"]
        assert FLEXLM_COMMAND_HEARTBEAT in analysis["command_distribution"]
        assert FLEXLM_COMMAND_CHECKIN in analysis["command_distribution"]

    def test_multiple_concurrent_checkouts(self) -> None:
        """Parser handles multiple concurrent license checkouts correctly."""
        parser = FlexLMProtocolParser()

        users = ["user1", "user2", "user3"]
        hosts = ["host1", "host2", "host3"]

        for i, (user, host) in enumerate(zip(users, hosts, strict=False)):
            request = FlexLMRequest(
                command=FLEXLM_COMMAND_CHECKOUT,
                version=FLEXLM_PACKET_VERSION,
                sequence=i + FLEXLM_PACKET_VERSION,
                client_id=f"CLIENT_{i}",
                feature="SOLIDWORKS",
                version_requested="2024",
                platform="win64",
                hostname=host,
                username=user,
                pid=1000 + i,
                checkout_time=int(time.time()),
                additional_data={},
            )

            response = parser.generate_response(request)
            assert response.status == FLEXLM_RESPONSE_OK

        assert len(parser.active_checkouts) == FLEXLM_CONCURRENT_CHECKOUTS

        stats = parser.get_server_statistics()
        assert stats["active_checkouts"] == FLEXLM_CONCURRENT_CHECKOUTS

    @staticmethod
    def _build_flexlm_packet(
        command: int, sequence: int, feature: str, username: str, hostname: str
    ) -> bytes:
        """Build FlexLM binary packet for testing."""
        packet = bytearray()
        packet.extend(struct.pack(">I", FLEXLM_MAGIC_FLEX))
        packet.extend(struct.pack(">H", command))
        packet.extend(struct.pack(">H", FLEXLM_PACKET_VERSION))
        packet.extend(struct.pack(">I", sequence))
        packet.extend(struct.pack(">I", FLEXLM_PACKET_SIZE_SMALL))
        packet.extend(b"CLIENT\x00")
        packet.extend(feature.encode() + b"\x00")
        packet.extend(b"1.0\x00")
        packet.extend(b"win64\x00")
        packet.extend(hostname.encode() + b"\x00")
        packet.extend(username.encode() + b"\x00")
        packet.extend(struct.pack(">II", FLEXLM_PID_SMALL, int(time.time())))
        return bytes(packet)


class TestValidLicenseFileResponseGeneration:
    """Test valid license file response generation."""

    def test_generate_valid_license_file_with_server_line(self) -> None:
        """Generated license file contains valid SERVER line."""
        generator = FlexLMLicenseGenerator()

        features = [{"name": "TEST", "version": "1.0", "vendor": "VENDOR"}]

        license_content = generator.generate_license_file(
            features=features,
            server_host="license-server.example.com",
            server_port=DEFAULT_SERVER_PORT,
            vendor_daemon="VENDOR",
        )

        lines = license_content.split("\n")
        server_line = lines[0]

        assert server_line.startswith("SERVER")
        assert "license-server.example.com" in server_line
        assert str(DEFAULT_SERVER_PORT) in server_line
        assert "ANY" in server_line

    def test_generate_valid_license_file_with_vendor_line(self) -> None:
        """Generated license file contains valid VENDOR line."""
        generator = FlexLMLicenseGenerator()

        features = [{"name": "TEST", "version": "1.0", "vendor": "TEST_VENDOR"}]

        license_content = generator.generate_license_file(
            features=features,
            server_host="server",
            vendor_daemon="TEST_VENDOR",
            vendor_port=ALTERNATE_VENDOR_PORT,
        )

        lines = license_content.split("\n")
        vendor_line = next(line for line in lines if "VENDOR" in line)

        assert "VENDOR TEST_VENDOR" in vendor_line
        assert f"PORT={ALTERNATE_VENDOR_PORT}" in vendor_line

    def test_generate_valid_feature_lines_with_all_fields(self) -> None:
        """Generated FEATURE lines contain all required fields."""
        generator = FlexLMLicenseGenerator()

        features = [
            {
                "name": "FULL_FEATURE",
                "version": "3.5",
                "vendor": "VENDOR_DAEMON",
                "expiry": "15-jun-2026",
                "count": 75,
            }
        ]

        license_content = generator.generate_license_file(
            features=features,
            server_host="server",
            vendor_daemon="VENDOR_DAEMON",
        )

        feature_line = next(line for line in license_content.split("\n") if "FEATURE FULL_FEATURE" in line)

        assert "FULL_FEATURE" in feature_line
        assert "VENDOR_DAEMON" in feature_line
        assert "3.5" in feature_line
        assert "15-jun-2026" in feature_line
        assert "75" in feature_line
        assert "HOSTID=ANY" in feature_line
        assert 'SIGN="' in feature_line

    def test_parse_and_validate_generated_license_file(self) -> None:
        """Parser can parse and validate license files it generates."""
        generator = FlexLMLicenseGenerator()

        features = [
            {"name": "FEATURE_A", "version": "1.0", "vendor": "VENDOR_A", "count": 10},
            {"name": "FEATURE_B", "version": "2.0", "vendor": "VENDOR_B", "count": 20},
        ]

        license_content = generator.generate_license_file(
            features=features,
            server_host="test.server",
            server_port=DEFAULT_SERVER_PORT,
            vendor_daemon="VENDOR_A",
            vendor_port=ALTERNATE_VENDOR_PORT,
        )

        parsed = generator.parse_license_file(license_content)

        assert len(parsed["servers"]) == 1
        assert parsed["servers"][0]["hostname"] == "test.server"
        assert parsed["servers"][0]["port"] == DEFAULT_SERVER_PORT

        assert len(parsed["features"]) == LICENSE_FILE_FEATURES_COUNT
        feature_names = {f["name"] for f in parsed["features"]}
        assert "FEATURE_A" in feature_names
        assert "FEATURE_B" in feature_names


class TestFlexLM11xEdgeCases:
    """Test FlexLM 11.x specific differences and edge cases."""

    def test_flexlm_11x_version_in_response(self) -> None:
        """Parser identifies as FlexLM 11.18.0 in responses."""
        parser = FlexLMProtocolParser()

        request = FlexLMRequest(
            command=FLEXLM_COMMAND_SERVER_INFO,
            version=FLEXLM_PACKET_VERSION,
            sequence=FLEXLM_PACKET_VERSION,
            client_id="CLIENT",
            feature="",
            version_requested="",
            platform="win64",
            hostname="host",
            username="user",
            pid=FLEXLM_PID_SMALL,
            checkout_time=int(time.time()),
            additional_data={},
        )

        response = parser.generate_response(request)

        assert response.server_version == "11.18.0"

    def test_flexlm_11x_supports_borrow_request(self) -> None:
        """Parser recognizes FlexLM 11.x BORROW_REQUEST command."""
        parser = FlexLMProtocolParser()

        assert FLEXLM_COMMAND_BORROW_REQUEST in parser.FLEXLM_COMMANDS
        assert parser.FLEXLM_COMMANDS[FLEXLM_COMMAND_BORROW_REQUEST] == "BORROW_REQUEST"

    def test_flexlm_11x_supports_return_request(self) -> None:
        """Parser recognizes FlexLM 11.x RETURN_REQUEST command."""
        parser = FlexLMProtocolParser()

        assert FLEXLM_COMMAND_RETURN_REQUEST in parser.FLEXLM_COMMANDS
        assert parser.FLEXLM_COMMANDS[FLEXLM_COMMAND_RETURN_REQUEST] == "RETURN_REQUEST"

    def test_flexlm_11x_server_info_includes_version(self) -> None:
        """SERVER_INFO response includes FlexLM 11.x version information."""
        parser = FlexLMProtocolParser()

        request = FlexLMRequest(
            command=FLEXLM_COMMAND_SERVER_INFO,
            version=FLEXLM_PACKET_VERSION,
            sequence=FLEXLM_PACKET_VERSION,
            client_id="CLIENT",
            feature="",
            version_requested="",
            platform="win64",
            hostname="host",
            username="user",
            pid=FLEXLM_PID_SMALL,
            checkout_time=int(time.time()),
            additional_data={},
        )

        response = parser.generate_response(request)

        assert "server_version" in response.additional_data
        assert response.additional_data["server_version"] == "11.18.0"


class TestLmgrdClustering:
    """Test lmgrd clustering and redundant server support."""

    def test_multiple_server_endpoints_in_license_file(self) -> None:
        """License file supports multiple redundant server definitions."""
        generator = FlexLMLicenseGenerator()

        license_text = """
SERVER server1.example.com 001122334455 27000
SERVER server2.example.com 667788990011 27000
SERVER server3.example.com 223344556677 27000
VENDOR VENDOR_DAEMON PORT=27001

FEATURE TEST_FEATURE VENDOR_DAEMON 1.0 permanent 1 HOSTID=ANY SIGN="ABC123"
"""

        parsed = generator.parse_license_file(license_text)

        assert len(parsed["servers"]) == CLUSTER_SERVER_COUNT
        assert parsed["servers"][0]["hostname"] == "server1.example.com"
        assert parsed["servers"][1]["hostname"] == "server2.example.com"
        assert parsed["servers"][2]["hostname"] == "server3.example.com"

        for server in parsed["servers"]:
            assert server["port"] == DEFAULT_SERVER_PORT
            assert len(server["hostid"]) > FLEXLM_RESPONSE_OK

    def test_traffic_capture_detects_multiple_server_endpoints(self) -> None:
        """Traffic capture identifies multiple license server endpoints."""
        parser = FlexLMProtocolParser()
        capture = FlexLMTrafficCapture(parser)

        servers = [
            ("10.0.0.1", DEFAULT_SERVER_PORT),
            ("10.0.0.2", DEFAULT_SERVER_PORT),
            ("10.0.0.3", DEFAULT_SERVER_PORT),
        ]

        for i, server_addr in enumerate(servers):
            packet = self._build_checkout_packet(i + FLEXLM_PACKET_VERSION)
            capture.capture_packet(
                packet,
                ("192.168.1.100", 54321),
                server_addr,
            )

        assert len(capture.server_endpoints) == CLUSTER_SERVER_COUNT

        server_list = capture.detect_server_endpoints()
        assert len(server_list) == CLUSTER_SERVER_COUNT

        server_ips = {s["ip"] for s in server_list}
        assert "10.0.0.1" in server_ips
        assert "10.0.0.2" in server_ips
        assert "10.0.0.3" in server_ips

    def test_clustered_server_statistics(self) -> None:
        """Parser tracks statistics across clustered server configuration."""
        parser = FlexLMProtocolParser()

        for i in range(CLUSTER_FEATURES_COUNT):
            parser.add_custom_feature(
                name=f"CLUSTER_FEATURE_{i}",
                version="1.0",
                vendor="CLUSTER_VENDOR",
                count=100,
            )

        stats = parser.get_server_statistics()

        assert stats["total_features"] >= CLUSTER_FEATURES_COUNT
        assert "features" in stats
        assert all(f"CLUSTER_FEATURE_{i}" in stats["features"] for i in range(CLUSTER_FEATURES_COUNT))

    @staticmethod
    def _build_checkout_packet(sequence: int) -> bytes:
        """Build checkout packet for cluster testing."""
        packet = bytearray()
        packet.extend(struct.pack(">I", FLEXLM_MAGIC_FLEX))
        packet.extend(struct.pack(">H", FLEXLM_COMMAND_CHECKOUT))
        packet.extend(struct.pack(">H", FLEXLM_PACKET_VERSION))
        packet.extend(struct.pack(">I", sequence))
        packet.extend(struct.pack(">I", FLEXLM_PACKET_SIZE_SMALL))
        packet.extend(b"CLIENT\x00")
        packet.extend(b"FEATURE\x00")
        packet.extend(b"1.0\x00")
        packet.extend(b"win64\x00")
        packet.extend(b"host\x00")
        packet.extend(b"user\x00")
        packet.extend(struct.pack(">II", FLEXLM_PID_SMALL, int(time.time())))
        return bytes(packet)


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling in binary protocol parsing."""

    def test_parse_packet_with_corrupted_length_field(self) -> None:
        """Parser rejects packets with invalid length field."""
        parser = FlexLMProtocolParser()

        packet = bytearray()
        packet.extend(struct.pack(">I", FLEXLM_MAGIC_FLEX))
        packet.extend(struct.pack(">H", FLEXLM_COMMAND_CHECKOUT))
        packet.extend(struct.pack(">H", FLEXLM_PACKET_VERSION))
        packet.extend(struct.pack(">I", FLEXLM_PACKET_VERSION))
        packet.extend(struct.pack(">I", TRAFFIC_CAPTURE_THRESHOLD))
        packet.extend(b"SHORT\x00")

        request = parser.parse_request(bytes(packet))

        assert request is None

    def test_parse_packet_with_missing_null_terminators(self) -> None:
        """Parser handles missing null terminators gracefully."""
        parser = FlexLMProtocolParser()

        packet = bytearray()
        packet.extend(struct.pack(">I", FLEXLM_MAGIC_FLEX))
        packet.extend(struct.pack(">H", FLEXLM_COMMAND_CHECKOUT))
        packet.extend(struct.pack(">H", FLEXLM_PACKET_VERSION))
        packet.extend(struct.pack(">I", FLEXLM_PACKET_VERSION))
        packet.extend(struct.pack(">I", FLEXLM_PACKET_SIZE_SMALL))
        packet.extend(b"CLIENTFEATUREVERSION")

        request = parser.parse_request(bytes(packet))

        assert request is not None
        assert len(request.client_id) > FLEXLM_RESPONSE_OK

    def test_heartbeat_for_nonexistent_session_fails(self) -> None:
        """HEARTBEAT request for non-existent session returns failure."""
        parser = FlexLMProtocolParser()

        heartbeat_request = FlexLMRequest(
            command=FLEXLM_COMMAND_HEARTBEAT,
            version=FLEXLM_PACKET_VERSION,
            sequence=FLEXLM_PACKET_VERSION,
            client_id="NONEXISTENT",
            feature="FEATURE",
            version_requested="1.0",
            platform="win64",
            hostname="ghost-host",
            username="phantom-user",
            pid=FLEXLM_PID_XLARGE,
            checkout_time=int(time.time()),
            additional_data={},
        )

        response = parser.generate_response(heartbeat_request)

        assert response.status == FLEXLM_RESPONSE_INVALID_SESSION

    def test_serialize_response_with_empty_additional_data(self) -> None:
        """serialize_response handles empty additional_data correctly."""
        parser = FlexLMProtocolParser()

        response = FlexLMResponse(
            status=FLEXLM_RESPONSE_OK,
            sequence=FLEXLM_PACKET_VERSION,
            server_version="11.18.0",
            feature="",
            expiry_date="",
            license_key="",
            server_id="test-server",
            additional_data={},
        )

        packet = parser.serialize_response(response)

        assert len(packet) > FLEXLM_RESPONSE_OK
        assert packet[:HEADER_BYTES] == struct.pack(">I", FLEXLM_MAGIC_FLEX)

    def test_unknown_command_returns_error_response(self) -> None:
        """Unknown command codes return appropriate error response."""
        parser = FlexLMProtocolParser()

        request = FlexLMRequest(
            command=FLEXLM_COMMAND_UNKNOWN,
            version=FLEXLM_PACKET_VERSION,
            sequence=FLEXLM_PACKET_VERSION,
            client_id="CLIENT",
            feature="",
            version_requested="",
            platform="win64",
            hostname="host",
            username="user",
            pid=FLEXLM_PID_SMALL,
            checkout_time=int(time.time()),
            additional_data={},
        )

        response = parser.generate_response(request)

        assert response.status != FLEXLM_RESPONSE_OK
        assert "error" in response.additional_data


class TestPerformanceAndScalability:
    """Test performance with large-scale operations."""

    def test_handle_1000_concurrent_checkouts(self) -> None:
        """Parser handles 1000 concurrent license checkouts efficiently."""
        parser = FlexLMProtocolParser()

        start_time = time.time()

        for i in range(LARGE_CONCURRENCY_THRESHOLD):
            request = FlexLMRequest(
                command=FLEXLM_COMMAND_CHECKOUT,
                version=FLEXLM_PACKET_VERSION,
                sequence=i,
                client_id=f"CLIENT_{i:04d}",
                feature="AUTOCAD",
                version_requested="2024.0",
                platform="win64",
                hostname=f"host-{i:04d}",
                username=f"user{i:04d}",
                pid=1000 + i,
                checkout_time=int(time.time()),
                additional_data={},
            )

            response = parser.generate_response(request)
            assert response.status == FLEXLM_RESPONSE_OK

        elapsed_time = time.time() - start_time

        assert len(parser.active_checkouts) == LARGE_CONCURRENCY_THRESHOLD
        assert elapsed_time < PERFORMANCE_TIMEOUT_SHORT

    def test_traffic_capture_handles_10000_packets(self) -> None:
        """Traffic capture handles 10,000 packets without performance degradation."""
        parser = FlexLMProtocolParser()
        capture = FlexLMTrafficCapture(parser)

        packet = bytearray()
        packet.extend(struct.pack(">I", FLEXLM_MAGIC_FLEX))
        packet.extend(struct.pack(">H", FLEXLM_COMMAND_CHECKOUT))
        packet.extend(struct.pack(">H", FLEXLM_PACKET_VERSION))
        packet.extend(struct.pack(">I", FLEXLM_PACKET_VERSION))
        packet.extend(struct.pack(">I", FLEXLM_PACKET_SIZE_SMALL))
        packet.extend(b"CLIENT\x00FEATURE\x001.0\x00win64\x00host\x00user\x00")
        packet.extend(struct.pack(">II", FLEXLM_PID_SMALL, int(time.time())))
        packet_bytes = bytes(packet)

        start_time = time.time()

        for i in range(TRAFFIC_CAPTURE_THRESHOLD):
            capture.capture_packet(
                packet_bytes,
                (f"192.168.{i // 256}.{i % 256}", 50000 + i),
                ("10.0.0.1", DEFAULT_SERVER_PORT),
            )

        elapsed_time = time.time() - start_time

        assert len(capture.captured_requests) == TRAFFIC_CAPTURE_THRESHOLD
        assert elapsed_time < PERFORMANCE_TIMEOUT_LONG


class TestIntegrationScenarios:
    """Integration tests for complete FlexLM workflows."""

    def test_complete_multi_user_license_server_simulation(self) -> None:
        """Complete simulation of multi-user license server operation."""
        parser = FlexLMProtocolParser()
        capture = FlexLMTrafficCapture(parser)

        users = [
            ("alice", "alice-ws", "AUTOCAD"),
            ("bob", "bob-ws", "MATLAB"),
            ("charlie", "charlie-ws", "SOLIDWORKS"),
        ]

        for i, (username, hostname, feature) in enumerate(users):
            checkout_packet = self._build_complete_packet(
                FLEXLM_COMMAND_CHECKOUT, i + FLEXLM_PACKET_VERSION, feature, username, hostname
            )
            capture.capture_packet(
                checkout_packet,
                (f"192.168.1.{100 + i}", 50000 + i),
                ("192.168.1.1", DEFAULT_SERVER_PORT),
            )

            request = parser.parse_request(checkout_packet)
            assert request is not None
            response = parser.generate_response(request)
            assert response.status == FLEXLM_RESPONSE_OK

        assert len(parser.active_checkouts) == FLEXLM_CONCURRENT_CHECKOUTS

        analysis = capture.analyze_traffic_patterns()
        assert analysis["total_packets"] == FLEXLM_CONCURRENT_CHECKOUTS
        assert analysis["unique_clients"] == FLEXLM_CONCURRENT_CHECKOUTS

        licenses = capture.extract_license_info()
        assert len(licenses) == FLEXLM_CONCURRENT_CHECKOUTS

    def test_export_and_analyze_captured_traffic(self, tmp_path: Path) -> None:
        """Captured traffic can be exported and analyzed."""
        parser = FlexLMProtocolParser()
        capture = FlexLMTrafficCapture(parser)

        for i in range(CLUSTER_FEATURES_COUNT):
            packet = self._build_complete_packet(FLEXLM_COMMAND_CHECKOUT, i, "TEST_FEATURE", f"user{i}", f"host{i}")
            capture.capture_packet(
                packet,
                (f"10.0.0.{i + FLEXLM_PACKET_VERSION}", 50000),
                ("10.0.0.254", DEFAULT_SERVER_PORT),
            )

        export_file = tmp_path / "flexlm_capture.json"
        capture.export_capture(str(export_file))

        assert export_file.exists()

        with open(export_file, encoding="utf-8") as f:
            data = json.load(f)

        assert "total_packets" in data
        assert data["total_packets"] == CLUSTER_FEATURES_COUNT
        assert "packets" in data
        assert len(data["packets"]) == CLUSTER_FEATURES_COUNT
        assert "analysis" in data
        assert isinstance(data["analysis"], dict)

    @staticmethod
    def _build_complete_packet(
        command: int, sequence: int, feature: str, username: str, hostname: str
    ) -> bytes:
        """Build complete FlexLM packet for integration testing."""
        packet = bytearray()
        packet.extend(struct.pack(">I", FLEXLM_MAGIC_FLEX))
        packet.extend(struct.pack(">H", command))
        packet.extend(struct.pack(">H", FLEXLM_PACKET_VERSION))
        packet.extend(struct.pack(">I", sequence))
        packet.extend(struct.pack(">I", FLEXLM_PACKET_SIZE_SMALL))
        packet.extend(f"CLIENT_{sequence:04d}\x00".encode())
        packet.extend(feature.encode() + b"\x00")
        packet.extend(b"1.0\x00")
        packet.extend(b"win64\x00")
        packet.extend(hostname.encode() + b"\x00")
        packet.extend(username.encode() + b"\x00")
        packet.extend(struct.pack(">II", 1000 + sequence, int(time.time())))
        return bytes(packet)
