"""Comprehensive FlexLM Protocol Parser Tests.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import struct
import time

import pytest

from intellicrack.core.network.protocols.flexlm_parser import (
    FlexLMProtocolParser,
    FlexLMRequest,
    FlexLMResponse,
)


class TestFlexLMProtocolParser:
    """Test FlexLM protocol parser functionality."""

    @pytest.fixture
    def parser(self) -> FlexLMProtocolParser:
        """Create FlexLM parser instance."""
        return FlexLMProtocolParser()

    def test_parser_initialization(self, parser: FlexLMProtocolParser) -> None:
        """Test parser initializes correctly with default features."""
        assert parser is not None
        assert len(parser.server_features) > 0
        assert "AUTOCAD" in parser.server_features
        assert "MATLAB" in parser.server_features
        assert "SOLIDWORKS" in parser.server_features
        assert parser.encryption_seed is not None
        assert len(parser.encryption_seed) == 32

    def test_checkout_request_parsing(self, parser: FlexLMProtocolParser) -> None:
        """Test parsing checkout request."""
        packet = bytearray()
        packet.extend(struct.pack(">I", 0x464C4558))
        packet.extend(struct.pack(">H", 0x01))
        packet.extend(struct.pack(">H", 0x0B12))
        packet.extend(struct.pack(">I", 12345))

        data_section = bytearray()
        client_id = b"CLIENT123\x00"
        feature = b"AUTOCAD\x00"
        version = b"2024.0\x00"
        platform = b"win64\x00"
        hostname = b"testhost\x00"
        username = b"testuser\x00"

        data_section.extend(client_id)
        data_section.extend(feature)
        data_section.extend(version)
        data_section.extend(platform)
        data_section.extend(hostname)
        data_section.extend(username)
        data_section.extend(struct.pack(">I", 1234))
        data_section.extend(struct.pack(">I", int(time.time())))

        total_length = 16 + len(data_section)
        packet.extend(struct.pack(">I", total_length))
        packet.extend(data_section)

        request = parser.parse_request(bytes(packet))

        assert request is not None
        assert request.command == 0x01
        assert request.version == 0x0B12
        assert request.sequence == 12345
        assert request.client_id == "CLIENT123"
        assert request.feature == "AUTOCAD"
        assert request.version_requested == "2024.0"
        assert request.platform == "win64"
        assert request.hostname == "testhost"
        assert request.username == "testuser"
        assert request.pid == 1234

    def test_checkout_response_generation(self, parser: FlexLMProtocolParser) -> None:
        """Test generating checkout response for valid feature."""
        request = FlexLMRequest(
            command=0x01,
            version=0x0B12,
            sequence=12345,
            client_id="CLIENT123",
            feature="AUTOCAD",
            version_requested="2024.0",
            platform="win64",
            hostname="testhost",
            username="testuser",
            pid=1234,
            checkout_time=int(time.time()),
            additional_data={},
        )

        response = parser.generate_response(request)

        assert response.status == 0x00
        assert response.sequence == request.sequence
        assert response.feature == "AUTOCAD"
        assert response.expiry_date == "31-dec-2025"
        assert len(response.license_key) > 0
        assert response.server_id == "intellicrack-flexlm"
        assert "vendor" in response.additional_data
        assert response.additional_data["vendor"] == "ADSKFLEX"

    def test_checkout_unknown_feature(self, parser: FlexLMProtocolParser) -> None:
        """Test checkout request for unknown feature."""
        request = FlexLMRequest(
            command=0x01,
            version=0x0B12,
            sequence=12345,
            client_id="CLIENT123",
            feature="UNKNOWN_FEATURE",
            version_requested="1.0",
            platform="win64",
            hostname="testhost",
            username="testuser",
            pid=1234,
            checkout_time=int(time.time()),
            additional_data={},
        )

        response = parser.generate_response(request)

        assert response.status == 0x01
        assert "error" in response.additional_data

    def test_checkin_request(self, parser: FlexLMProtocolParser) -> None:
        """Test license checkin."""
        checkout_request = FlexLMRequest(
            command=0x01,
            version=0x0B12,
            sequence=1,
            client_id="CLIENT123",
            feature="MATLAB",
            version_requested="R2024a",
            platform="win64",
            hostname="testhost",
            username="testuser",
            pid=1234,
            checkout_time=int(time.time()),
            additional_data={},
        )

        checkout_response = parser.generate_response(checkout_request)
        assert checkout_response.status == 0x00

        checkin_request = FlexLMRequest(
            command=0x02,
            version=0x0B12,
            sequence=2,
            client_id="CLIENT123",
            feature="MATLAB",
            version_requested="R2024a",
            platform="win64",
            hostname="testhost",
            username="testuser",
            pid=1234,
            checkout_time=int(time.time()),
            additional_data={},
        )

        checkin_response = parser.generate_response(checkin_request)
        assert checkin_response.status == 0x00

    def test_status_request(self, parser: FlexLMProtocolParser) -> None:
        """Test server status request."""
        request = FlexLMRequest(
            command=0x03,
            version=0x0B12,
            sequence=1,
            client_id="CLIENT123",
            feature="",
            version_requested="",
            platform="win64",
            hostname="testhost",
            username="testuser",
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

    def test_heartbeat_request(self, parser: FlexLMProtocolParser) -> None:
        """Test heartbeat for active checkout."""
        checkout_request = FlexLMRequest(
            command=0x01,
            version=0x0B12,
            sequence=1,
            client_id="CLIENT123",
            feature="INVENTOR",
            version_requested="2024.0",
            platform="win64",
            hostname="testhost",
            username="testuser",
            pid=1234,
            checkout_time=int(time.time()),
            additional_data={},
        )

        parser.generate_response(checkout_request)

        heartbeat_request = FlexLMRequest(
            command=0x04,
            version=0x0B12,
            sequence=2,
            client_id="CLIENT123",
            feature="INVENTOR",
            version_requested="2024.0",
            platform="win64",
            hostname="testhost",
            username="testuser",
            pid=1234,
            checkout_time=int(time.time()),
            additional_data={},
        )

        response = parser.generate_response(heartbeat_request)
        assert response.status == 0x00

    def test_feature_info_request(self, parser: FlexLMProtocolParser) -> None:
        """Test feature information request."""
        request = FlexLMRequest(
            command=0x05,
            version=0x0B12,
            sequence=1,
            client_id="CLIENT123",
            feature="ANSYS",
            version_requested="",
            platform="win64",
            hostname="testhost",
            username="testuser",
            pid=1234,
            checkout_time=int(time.time()),
            additional_data={},
        )

        response = parser.generate_response(request)

        assert response.status == 0x00
        assert response.feature == "ANSYS"
        assert "vendor" in response.additional_data
        assert "version" in response.additional_data

    def test_server_info_request(self, parser: FlexLMProtocolParser) -> None:
        """Test server information request."""
        request = FlexLMRequest(
            command=0x06,
            version=0x0B12,
            sequence=1,
            client_id="CLIENT123",
            feature="",
            version_requested="",
            platform="win64",
            hostname="testhost",
            username="testuser",
            pid=1234,
            checkout_time=int(time.time()),
            additional_data={},
        )

        response = parser.generate_response(request)

        assert response.status == 0x00
        assert "server_name" in response.additional_data
        assert "features" in response.additional_data
        assert "max_connections" in response.additional_data

    def test_hostid_request(self, parser: FlexLMProtocolParser) -> None:
        """Test host ID generation."""
        request = FlexLMRequest(
            command=0x10,
            version=0x0B12,
            sequence=1,
            client_id="CLIENT123",
            feature="",
            version_requested="",
            platform="win64",
            hostname="testhost",
            username="testuser",
            pid=1234,
            checkout_time=int(time.time()),
            additional_data={},
        )

        response = parser.generate_response(request)

        assert response.status == 0x00
        assert "hostid" in response.additional_data
        assert len(response.additional_data["hostid"]) == 12

    def test_encryption_seed_request(self, parser: FlexLMProtocolParser) -> None:
        """Test encryption seed request."""
        request = FlexLMRequest(
            command=0x11,
            version=0x0B12,
            sequence=1,
            client_id="CLIENT123",
            feature="",
            version_requested="",
            platform="win64",
            hostname="testhost",
            username="testuser",
            pid=1234,
            checkout_time=int(time.time()),
            additional_data={},
        )

        response = parser.generate_response(request)

        assert response.status == 0x00
        assert "encryption_seed" in response.additional_data
        assert len(response.additional_data["encryption_seed"]) == 64

    def test_response_serialization(self, parser: FlexLMProtocolParser) -> None:
        """Test response serialization to bytes."""
        response = FlexLMResponse(
            status=0x00,
            sequence=12345,
            server_version="11.18.0",
            feature="AUTOCAD",
            expiry_date="31-dec-2025",
            license_key="ABC123DEF456",
            server_id="intellicrack-flexlm",
            additional_data={"vendor": "ADSKFLEX"},
        )

        serialized = parser.serialize_response(response)

        assert len(serialized) > 0
        assert serialized[:4] == struct.pack(">I", 0x464C4558)
        status = struct.unpack(">H", serialized[4:6])[0]
        assert status == 0x00

    def test_round_trip_serialization(self, parser: FlexLMProtocolParser) -> None:
        """Test parsing and serializing maintains data integrity."""
        original_packet = bytearray()
        original_packet.extend(struct.pack(">I", 0x464C4558))
        original_packet.extend(struct.pack(">H", 0x01))
        original_packet.extend(struct.pack(">H", 0x0B12))
        original_packet.extend(struct.pack(">I", 99999))

        data_section = bytearray()
        data_section.extend(b"CLIENT999\x00")
        data_section.extend(b"SOLIDWORKS\x00")
        data_section.extend(b"2024\x00")
        data_section.extend(b"win64\x00")
        data_section.extend(b"workstation\x00")
        data_section.extend(b"engineer\x00")
        data_section.extend(struct.pack(">I", 5678))
        data_section.extend(struct.pack(">I", int(time.time())))

        total_length = 16 + len(data_section)
        original_packet.extend(struct.pack(">I", total_length))
        original_packet.extend(data_section)

        request = parser.parse_request(bytes(original_packet))
        assert request is not None

        response = parser.generate_response(request)
        serialized_response = parser.serialize_response(response)

        assert len(serialized_response) > 0
        assert response.sequence == request.sequence

    def test_invalid_magic_number(self, parser: FlexLMProtocolParser) -> None:
        """Test rejection of invalid magic number."""
        packet = struct.pack(">I", 0xDEADBEEF)
        packet += b"\x00" * 100

        request = parser.parse_request(packet)
        assert request is None

    def test_short_packet(self, parser: FlexLMProtocolParser) -> None:
        """Test handling of too-short packets."""
        packet = b"\x46\x4C\x45\x58"
        request = parser.parse_request(packet)
        assert request is None

    def test_malformed_string_fields(self, parser: FlexLMProtocolParser) -> None:
        """Test handling of malformed string fields."""
        packet = bytearray()
        packet.extend(struct.pack(">I", 0x464C4558))
        packet.extend(struct.pack(">H", 0x01))
        packet.extend(struct.pack(">H", 0x0B12))
        packet.extend(struct.pack(">I", 1))
        packet.extend(struct.pack(">I", 50))
        packet.extend(b"\xFF\xFE\xFD\x00")

        request = parser.parse_request(bytes(packet))
        if request:
            assert isinstance(request.client_id, str)

    def test_additional_data_parsing(self, parser: FlexLMProtocolParser) -> None:
        """Test parsing of additional TLV data fields."""
        packet = bytearray()
        packet.extend(struct.pack(">I", 0x464C4558))
        packet.extend(struct.pack(">H", 0x01))
        packet.extend(struct.pack(">H", 0x0B12))
        packet.extend(struct.pack(">I", 1))

        data_section = bytearray()
        data_section.extend(b"CLIENT\x00")
        data_section.extend(b"FEATURE\x00")
        data_section.extend(b"1.0\x00")
        data_section.extend(b"platform\x00")
        data_section.extend(b"host\x00")
        data_section.extend(b"user\x00")
        data_section.extend(struct.pack(">I", 100))
        data_section.extend(struct.pack(">I", int(time.time())))

        data_section.extend(struct.pack(">H", 0x0001))
        hostid_data = b"AABBCCDD"
        data_section.extend(struct.pack(">H", len(hostid_data)))
        data_section.extend(hostid_data)

        total_length = 16 + len(data_section)
        packet.extend(struct.pack(">I", total_length))
        packet.extend(data_section)

        request = parser.parse_request(bytes(packet))
        assert request is not None
        assert "hostid" in request.additional_data

    def test_concurrent_checkouts(self, parser: FlexLMProtocolParser) -> None:
        """Test multiple concurrent license checkouts."""
        requests = []
        for i in range(5):
            req = FlexLMRequest(
                command=0x01,
                version=0x0B12,
                sequence=i,
                client_id=f"CLIENT{i}",
                feature="GENERIC_CAD",
                version_requested="1.0",
                platform="win64",
                hostname=f"host{i}",
                username=f"user{i}",
                pid=1000 + i,
                checkout_time=int(time.time()),
                additional_data={},
            )
            requests.append(req)

        for req in requests:
            response = parser.generate_response(req)
            assert response.status == 0x00
            assert len(response.license_key) > 0

        assert len(parser.active_checkouts) == 5

    def test_partial_feature_matching(self, parser: FlexLMProtocolParser) -> None:
        """Test partial feature name matching."""
        request = FlexLMRequest(
            command=0x01,
            version=0x0B12,
            sequence=1,
            client_id="CLIENT123",
            feature="auto",
            version_requested="2024.0",
            platform="win64",
            hostname="testhost",
            username="testuser",
            pid=1234,
            checkout_time=int(time.time()),
            additional_data={},
        )

        response = parser.generate_response(request)
        assert response.status == 0x00 or response.status == 0x01

    def test_checkout_key_generation(self, parser: FlexLMProtocolParser) -> None:
        """Test checkout key generation is unique and deterministic."""
        request = FlexLMRequest(
            command=0x01,
            version=0x0B12,
            sequence=1,
            client_id="CLIENT123",
            feature="MATLAB",
            version_requested="R2024a",
            platform="win64",
            hostname="testhost",
            username="testuser",
            pid=1234,
            checkout_time=int(time.time()),
            additional_data={},
        )

        response1 = parser.generate_response(request)
        time.sleep(0.1)
        response2 = parser.generate_response(request)

        assert len(response1.license_key) == 32
        assert len(response2.license_key) == 32
        assert response1.license_key != response2.license_key

    def test_multiple_magic_numbers(self, parser: FlexLMProtocolParser) -> None:
        """Test parser accepts multiple valid FlexLM magic numbers."""
        magic_numbers = [0x464C4558, 0x4C4D5F56, 0x46584C4D]

        for magic in magic_numbers:
            packet = bytearray()
            packet.extend(struct.pack(">I", magic))
            packet.extend(struct.pack(">H", 0x01))
            packet.extend(struct.pack(">H", 0x0B12))
            packet.extend(struct.pack(">I", 1))
            packet.extend(struct.pack(">I", 50))
            packet.extend(b"CLIENT\x00FEATURE\x00v1\x00plat\x00host\x00user\x00")
            packet.extend(struct.pack(">II", 100, int(time.time())))

            request = parser.parse_request(bytes(packet))
            assert request is not None

    def test_command_constants(self, parser: FlexLMProtocolParser) -> None:
        """Test FlexLM command constants are defined."""
        assert 0x01 in parser.FLEXLM_COMMANDS
        assert parser.FLEXLM_COMMANDS[0x01] == "CHECKOUT"
        assert 0x02 in parser.FLEXLM_COMMANDS
        assert parser.FLEXLM_COMMANDS[0x02] == "CHECKIN"
        assert 0x03 in parser.FLEXLM_COMMANDS
        assert parser.FLEXLM_COMMANDS[0x03] == "STATUS"

    def test_status_codes(self, parser: FlexLMProtocolParser) -> None:
        """Test FlexLM status codes are defined."""
        assert 0x00 in parser.FLEXLM_STATUS_CODES
        assert parser.FLEXLM_STATUS_CODES[0x00] == "SUCCESS"
        assert 0x01 in parser.FLEXLM_STATUS_CODES
        assert parser.FLEXLM_STATUS_CODES[0x01] == "FEATURE_NOT_FOUND"

    def test_active_checkout_tracking(self, parser: FlexLMProtocolParser) -> None:
        """Test active checkouts are tracked correctly."""
        request = FlexLMRequest(
            command=0x01,
            version=0x0B12,
            sequence=1,
            client_id="CLIENT123",
            feature="MAYA",
            version_requested="2024.0",
            platform="win64",
            hostname="rendernode",
            username="artist",
            pid=9999,
            checkout_time=int(time.time()),
            additional_data={},
        )

        initial_count = len(parser.active_checkouts)
        parser.generate_response(request)
        assert len(parser.active_checkouts) == initial_count + 1

        checkout_id = f"{request.hostname}:{request.username}:{request.feature}"
        assert checkout_id in parser.active_checkouts
        assert parser.active_checkouts[checkout_id]["request"].feature == "MAYA"


class TestFlexLMRealWorldScenarios:
    """Test FlexLM parser with real-world usage scenarios."""

    @pytest.fixture
    def parser(self) -> FlexLMProtocolParser:
        """Create FlexLM parser instance."""
        return FlexLMProtocolParser()

    def test_autodesk_autocad_workflow(self, parser: FlexLMProtocolParser) -> None:
        """Test complete AutoCAD checkout workflow."""
        hostid_req = FlexLMRequest(
            command=0x10,
            version=0x0B12,
            sequence=1,
            client_id="AUTOCAD_CLIENT",
            feature="",
            version_requested="",
            platform="win64",
            hostname="cad-workstation",
            username="designer",
            pid=2048,
            checkout_time=int(time.time()),
            additional_data={},
        )
        hostid_resp = parser.generate_response(hostid_req)
        assert hostid_resp.status == 0x00

        checkout_req = FlexLMRequest(
            command=0x01,
            version=0x0B12,
            sequence=2,
            client_id="AUTOCAD_CLIENT",
            feature="AUTOCAD",
            version_requested="2024.0",
            platform="win64",
            hostname="cad-workstation",
            username="designer",
            pid=2048,
            checkout_time=int(time.time()),
            additional_data={},
        )
        checkout_resp = parser.generate_response(checkout_req)
        assert checkout_resp.status == 0x00
        assert checkout_resp.additional_data["vendor"] == "ADSKFLEX"

        for i in range(3):
            hb_req = FlexLMRequest(
                command=0x04,
                version=0x0B12,
                sequence=3 + i,
                client_id="AUTOCAD_CLIENT",
                feature="AUTOCAD",
                version_requested="2024.0",
                platform="win64",
                hostname="cad-workstation",
                username="designer",
                pid=2048,
                checkout_time=int(time.time()),
                additional_data={},
            )
            hb_resp = parser.generate_response(hb_req)
            assert hb_resp.status == 0x00

        checkin_req = FlexLMRequest(
            command=0x02,
            version=0x0B12,
            sequence=6,
            client_id="AUTOCAD_CLIENT",
            feature="AUTOCAD",
            version_requested="2024.0",
            platform="win64",
            hostname="cad-workstation",
            username="designer",
            pid=2048,
            checkout_time=int(time.time()),
            additional_data={},
        )
        checkin_resp = parser.generate_response(checkin_req)
        assert checkin_resp.status == 0x00

    def test_matlab_cluster_usage(self, parser: FlexLMProtocolParser) -> None:
        """Test MATLAB usage across multiple cluster nodes."""
        nodes = [f"compute-{i:02d}" for i in range(1, 11)]

        for idx, node in enumerate(nodes):
            req = FlexLMRequest(
                command=0x01,
                version=0x0B12,
                sequence=idx + 1,
                client_id=f"MATLAB_{node}",
                feature="MATLAB",
                version_requested="R2024a",
                platform="linux64",
                hostname=node,
                username="researcher",
                pid=10000 + idx,
                checkout_time=int(time.time()),
                additional_data={},
            )
            resp = parser.generate_response(req)
            assert resp.status == 0x00
            assert resp.additional_data["vendor"] == "MLM"

        assert len([k for k in parser.active_checkouts.keys() if "MATLAB" in k]) == 10

    def test_ansys_floating_license(self, parser: FlexLMProtocolParser) -> None:
        """Test ANSYS floating license behavior."""
        feature_req = FlexLMRequest(
            command=0x05,
            version=0x0B12,
            sequence=1,
            client_id="ANSYS_CLIENT",
            feature="ANSYS",
            version_requested="",
            platform="win64",
            hostname="analysis-node",
            username="analyst",
            pid=5000,
            checkout_time=int(time.time()),
            additional_data={},
        )
        feature_resp = parser.generate_response(feature_req)
        assert feature_resp.status == 0x00
        assert "version" in feature_resp.additional_data

        checkout_req = FlexLMRequest(
            command=0x01,
            version=0x0B12,
            sequence=2,
            client_id="ANSYS_CLIENT",
            feature="ANSYS",
            version_requested="2024.1",
            platform="win64",
            hostname="analysis-node",
            username="analyst",
            pid=5000,
            checkout_time=int(time.time()),
            additional_data={},
        )
        checkout_resp = parser.generate_response(checkout_req)
        assert checkout_resp.status == 0x00


class TestFlexLMNetworkCapture:
    """Test FlexLM traffic capture and analysis capabilities."""

    @pytest.fixture
    def parser(self) -> FlexLMProtocolParser:
        """Create FlexLM parser instance."""
        return FlexLMProtocolParser()

    def test_capture_checkout_traffic(self, parser: FlexLMProtocolParser) -> None:
        """Test capturing and analyzing checkout traffic."""
        packet = bytearray()
        packet.extend(struct.pack(">I", 0x464C4558))
        packet.extend(struct.pack(">H", 0x01))
        packet.extend(struct.pack(">H", 0x0B12))
        packet.extend(struct.pack(">I", 54321))

        data_section = bytearray()
        data_section.extend(b"CAPTURED_CLIENT\x00")
        data_section.extend(b"SOLIDWORKS\x00")
        data_section.extend(b"2024\x00")
        data_section.extend(b"win64\x00")
        data_section.extend(b"engineering-ws\x00")
        data_section.extend(b"engineer\x00")
        data_section.extend(struct.pack(">I", 4096))
        data_section.extend(struct.pack(">I", int(time.time())))

        total_length = 16 + len(data_section)
        packet.extend(struct.pack(">I", total_length))
        packet.extend(data_section)

        captured_traffic = bytes(packet)

        request = parser.parse_request(captured_traffic)
        assert request is not None
        assert request.command == 0x01
        assert request.feature == "SOLIDWORKS"

        response = parser.generate_response(request)
        response_bytes = parser.serialize_response(response)

        assert len(response_bytes) > 0
        assert response.status == 0x00

    def test_traffic_interception_and_replay(self, parser: FlexLMProtocolParser) -> None:
        """Test intercepting traffic and replaying with modifications."""
        original_packet = bytearray()
        original_packet.extend(struct.pack(">I", 0x464C4558))
        original_packet.extend(struct.pack(">H", 0x01))
        original_packet.extend(struct.pack(">H", 0x0B12))
        original_packet.extend(struct.pack(">I", 1000))

        data_section = bytearray()
        data_section.extend(b"INTERCEPT_CLIENT\x00")
        data_section.extend(b"INVENTOR\x00")
        data_section.extend(b"2024.0\x00")
        data_section.extend(b"win64\x00")
        data_section.extend(b"original-host\x00")
        data_section.extend(b"original-user\x00")
        data_section.extend(struct.pack(">II", 2000, int(time.time())))

        total_length = 16 + len(data_section)
        original_packet.extend(struct.pack(">I", total_length))
        original_packet.extend(data_section)

        intercepted_request = parser.parse_request(bytes(original_packet))
        assert intercepted_request is not None

        modified_request = FlexLMRequest(
            command=intercepted_request.command,
            version=intercepted_request.version,
            sequence=intercepted_request.sequence,
            client_id=intercepted_request.client_id,
            feature=intercepted_request.feature,
            version_requested=intercepted_request.version_requested,
            platform=intercepted_request.platform,
            hostname="modified-host",
            username="modified-user",
            pid=intercepted_request.pid,
            checkout_time=intercepted_request.checkout_time,
            additional_data=intercepted_request.additional_data,
        )

        modified_response = parser.generate_response(modified_request)
        assert modified_response.status == 0x00


class TestFlexLMServerEmulation:
    """Test FlexLM server emulation capabilities."""

    @pytest.fixture
    def parser(self) -> FlexLMProtocolParser:
        """Create FlexLM parser instance."""
        return FlexLMProtocolParser()

    def test_server_handles_multiple_clients(self, parser: FlexLMProtocolParser) -> None:
        """Test server emulation with multiple simultaneous clients."""
        clients = []
        for i in range(20):
            client_req = FlexLMRequest(
                command=0x01,
                version=0x0B12,
                sequence=i + 1,
                client_id=f"MULTI_CLIENT_{i:03d}",
                feature="GENERIC_CAD",
                version_requested="1.0",
                platform="win64",
                hostname=f"workstation-{i:02d}",
                username=f"user{i:02d}",
                pid=3000 + i,
                checkout_time=int(time.time()),
                additional_data={},
            )
            clients.append(client_req)

        for client in clients:
            response = parser.generate_response(client)
            assert response.status == 0x00
            assert len(response.license_key) > 0

    def test_server_license_pool_management(self, parser: FlexLMProtocolParser) -> None:
        """Test license pool management with count tracking."""
        status_req = FlexLMRequest(
            command=0x03,
            version=0x0B12,
            sequence=1,
            client_id="ADMIN",
            feature="",
            version_requested="",
            platform="win64",
            hostname="admin-console",
            username="admin",
            pid=1,
            checkout_time=int(time.time()),
            additional_data={},
        )

        status_resp = parser.generate_response(status_req)
        assert status_resp.status == 0x00
        initial_checkouts = status_resp.additional_data["active_checkouts"]

        checkout_req = FlexLMRequest(
            command=0x01,
            version=0x0B12,
            sequence=2,
            client_id="POOL_CLIENT",
            feature="SIMULINK",
            version_requested="R2024a",
            platform="win64",
            hostname="matlab-node",
            username="user",
            pid=5000,
            checkout_time=int(time.time()),
            additional_data={},
        )
        parser.generate_response(checkout_req)

        status_req.sequence = 3
        status_resp = parser.generate_response(status_req)
        assert status_resp.additional_data["active_checkouts"] == initial_checkouts + 1

    def test_server_vendor_daemon_emulation(self, parser: FlexLMProtocolParser) -> None:
        """Test vendor daemon emulation for different vendors."""
        vendors = [
            ("AUTOCAD", "ADSKFLEX"),
            ("MATLAB", "MLM"),
            ("SOLIDWORKS", "SW_D"),
            ("ANSYS", "ANSYS"),
        ]

        for feature, expected_vendor in vendors:
            req = FlexLMRequest(
                command=0x05,
                version=0x0B12,
                sequence=1,
                client_id="VENDOR_TEST",
                feature=feature,
                version_requested="",
                platform="win64",
                hostname="test",
                username="test",
                pid=1,
                checkout_time=int(time.time()),
                additional_data={},
            )

            resp = parser.generate_response(req)
            assert resp.status == 0x00
            assert resp.additional_data["vendor"] == expected_vendor
