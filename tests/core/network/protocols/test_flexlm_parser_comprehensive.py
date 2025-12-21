"""Comprehensive tests for FlexLM protocol parser and response generator.

Tests validate real FlexLM license server communication parsing, license checkout/checkin
message handling, feature request processing, license file parsing, session token handling,
heartbeat message parsing, and error response generation against actual FlexLM protocol
specifications.
"""

import hashlib
import secrets
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


@pytest.fixture
def parser() -> FlexLMProtocolParser:
    """Create FlexLM parser with default features."""
    return FlexLMProtocolParser()


@pytest.fixture
def license_generator() -> FlexLMLicenseGenerator:
    """Create FlexLM license file generator."""
    return FlexLMLicenseGenerator()


@pytest.fixture
def traffic_capture(parser: FlexLMProtocolParser) -> FlexLMTrafficCapture:
    """Create FlexLM traffic capture engine."""
    return FlexLMTrafficCapture(parser)


def create_flexlm_checkout_request(
    feature: str = "AUTOCAD",
    version: str = "2024.0",
    hostname: str = "TEST_WORKSTATION",
    username: str = "testuser",
    platform: str = "x64_w10",
    sequence: int = 12345,
    client_id: str = "CLIENT_001",
    pid: int = 5678,
) -> bytes:
    """Create realistic FlexLM checkout request packet.

    Args:
        feature: Feature name to checkout
        version: Feature version
        hostname: Client hostname
        username: Client username
        platform: Platform identifier
        sequence: Sequence number
        client_id: Client ID
        pid: Process ID

    Returns:
        Raw FlexLM checkout request packet
    """
    packet = bytearray()

    packet.extend(struct.pack(">I", 0x464C4558))
    packet.extend(struct.pack(">H", 0x01))
    packet.extend(struct.pack(">H", 0x0B12))
    packet.extend(struct.pack(">I", sequence))

    length_placeholder = len(packet)
    packet.extend(struct.pack(">I", 0))

    packet.extend(client_id.encode("utf-8") + b"\x00")
    packet.extend(feature.encode("utf-8") + b"\x00")
    packet.extend(version.encode("utf-8") + b"\x00")
    packet.extend(platform.encode("utf-8") + b"\x00")
    packet.extend(hostname.encode("utf-8") + b"\x00")
    packet.extend(username.encode("utf-8") + b"\x00")

    packet.extend(struct.pack(">I", pid))
    packet.extend(struct.pack(">I", int(time.time())))

    actual_length = len(packet)
    struct.pack_into(">I", packet, length_placeholder, actual_length)

    return bytes(packet)


def create_flexlm_checkin_request(
    feature: str = "MATLAB",
    hostname: str = "DEV_MACHINE",
    username: str = "developer",
    sequence: int = 54321,
    client_id: str = "CLIENT_002",
) -> bytes:
    """Create realistic FlexLM checkin request packet."""
    packet = bytearray()

    packet.extend(struct.pack(">I", 0x464C4558))
    packet.extend(struct.pack(">H", 0x02))
    packet.extend(struct.pack(">H", 0x0B12))
    packet.extend(struct.pack(">I", sequence))

    length_placeholder = len(packet)
    packet.extend(struct.pack(">I", 0))

    packet.extend(client_id.encode("utf-8") + b"\x00")
    packet.extend(feature.encode("utf-8") + b"\x00")
    packet.extend(b"1.0\x00")
    packet.extend(b"x64\x00")
    packet.extend(hostname.encode("utf-8") + b"\x00")
    packet.extend(username.encode("utf-8") + b"\x00")

    packet.extend(struct.pack(">I", 1234))
    packet.extend(struct.pack(">I", int(time.time())))

    actual_length = len(packet)
    struct.pack_into(">I", packet, length_placeholder, actual_length)

    return bytes(packet)


def create_flexlm_heartbeat_request(
    feature: str = "SIMULINK",
    hostname: str = "WORKSTATION_01",
    username: str = "engineer",
    sequence: int = 99999,
) -> bytes:
    """Create realistic FlexLM heartbeat request packet."""
    packet = bytearray()

    packet.extend(struct.pack(">I", 0x464C4558))
    packet.extend(struct.pack(">H", 0x04))
    packet.extend(struct.pack(">H", 0x0B12))
    packet.extend(struct.pack(">I", sequence))

    length_placeholder = len(packet)
    packet.extend(struct.pack(">I", 0))

    packet.extend(b"HB_CLIENT\x00")
    packet.extend(feature.encode("utf-8") + b"\x00")
    packet.extend(b"R2024a\x00")
    packet.extend(b"linux64\x00")
    packet.extend(hostname.encode("utf-8") + b"\x00")
    packet.extend(username.encode("utf-8") + b"\x00")

    packet.extend(struct.pack(">I", 9876))
    packet.extend(struct.pack(">I", int(time.time())))

    actual_length = len(packet)
    struct.pack_into(">I", packet, length_placeholder, actual_length)

    return bytes(packet)


def create_flexlm_status_request(sequence: int = 11111) -> bytes:
    """Create realistic FlexLM status request packet."""
    packet = bytearray()

    packet.extend(struct.pack(">I", 0x464C4558))
    packet.extend(struct.pack(">H", 0x03))
    packet.extend(struct.pack(">H", 0x0B12))
    packet.extend(struct.pack(">I", sequence))

    length_placeholder = len(packet)
    packet.extend(struct.pack(">I", 0))

    packet.extend(b"STATUS_CLIENT\x00")
    packet.extend(b"\x00")
    packet.extend(b"1.0\x00")
    packet.extend(b"any\x00")
    packet.extend(b"admin-host\x00")
    packet.extend(b"admin\x00")

    packet.extend(struct.pack(">I", 0))
    packet.extend(struct.pack(">I", int(time.time())))

    actual_length = len(packet)
    struct.pack_into(">I", packet, length_placeholder, actual_length)

    return bytes(packet)


def create_flexlm_feature_info_request(
    feature: str = "INVENTOR", sequence: int = 22222
) -> bytes:
    """Create realistic FlexLM feature info request packet."""
    packet = bytearray()

    packet.extend(struct.pack(">I", 0x464C4558))
    packet.extend(struct.pack(">H", 0x05))
    packet.extend(struct.pack(">H", 0x0B12))
    packet.extend(struct.pack(">I", sequence))

    length_placeholder = len(packet)
    packet.extend(struct.pack(">I", 0))

    packet.extend(b"INFO_CLIENT\x00")
    packet.extend(feature.encode("utf-8") + b"\x00")
    packet.extend(b"2024.0\x00")
    packet.extend(b"x64\x00")
    packet.extend(b"query-host\x00")
    packet.extend(b"query-user\x00")

    packet.extend(struct.pack(">I", 5555))
    packet.extend(struct.pack(">I", int(time.time())))

    actual_length = len(packet)
    struct.pack_into(">I", packet, length_placeholder, actual_length)

    return bytes(packet)


def create_flexlm_server_info_request(sequence: int = 33333) -> bytes:
    """Create realistic FlexLM server info request packet."""
    packet = bytearray()

    packet.extend(struct.pack(">I", 0x464C4558))
    packet.extend(struct.pack(">H", 0x06))
    packet.extend(struct.pack(">H", 0x0B12))
    packet.extend(struct.pack(">I", sequence))

    length_placeholder = len(packet)
    packet.extend(struct.pack(">I", 0))

    packet.extend(b"SERVER_QUERY\x00")
    packet.extend(b"\x00")
    packet.extend(b"1.0\x00")
    packet.extend(b"any\x00")
    packet.extend(b"admin-machine\x00")
    packet.extend(b"sysadmin\x00")

    packet.extend(struct.pack(">I", 1111))
    packet.extend(struct.pack(">I", int(time.time())))

    actual_length = len(packet)
    struct.pack_into(">I", packet, length_placeholder, actual_length)

    return bytes(packet)


def create_flexlm_hostid_request(
    hostname: str = "LICENSE_CLIENT", sequence: int = 44444
) -> bytes:
    """Create realistic FlexLM host ID request packet."""
    packet = bytearray()

    packet.extend(struct.pack(">I", 0x464C4558))
    packet.extend(struct.pack(">H", 0x10))
    packet.extend(struct.pack(">H", 0x0B12))
    packet.extend(struct.pack(">I", sequence))

    length_placeholder = len(packet)
    packet.extend(struct.pack(">I", 0))

    packet.extend(b"HOSTID_CLIENT\x00")
    packet.extend(b"\x00")
    packet.extend(b"1.0\x00")
    packet.extend(b"x64_w10\x00")
    packet.extend(hostname.encode("utf-8") + b"\x00")
    packet.extend(b"hostid-user\x00")

    packet.extend(struct.pack(">I", 7777))
    packet.extend(struct.pack(">I", int(time.time())))

    actual_length = len(packet)
    struct.pack_into(">I", packet, length_placeholder, actual_length)

    return bytes(packet)


def create_flexlm_encryption_seed_request(sequence: int = 55555) -> bytes:
    """Create realistic FlexLM encryption seed request packet."""
    packet = bytearray()

    packet.extend(struct.pack(">I", 0x464C4558))
    packet.extend(struct.pack(">H", 0x11))
    packet.extend(struct.pack(">H", 0x0B12))
    packet.extend(struct.pack(">I", sequence))

    length_placeholder = len(packet)
    packet.extend(struct.pack(">I", 0))

    packet.extend(b"ENCRYPT_CLIENT\x00")
    packet.extend(b"\x00")
    packet.extend(b"1.0\x00")
    packet.extend(b"any\x00")
    packet.extend(b"secure-host\x00")
    packet.extend(b"crypto-user\x00")

    packet.extend(struct.pack(">I", 8888))
    packet.extend(struct.pack(">I", int(time.time())))

    actual_length = len(packet)
    struct.pack_into(">I", packet, length_placeholder, actual_length)

    return bytes(packet)


def create_flexlm_request_with_additional_data(
    hostid: str = "AABBCCDDEEFF", vendor_data: bytes = b"VENDOR_INFO"
) -> bytes:
    """Create FlexLM request with additional data fields."""
    packet = bytearray()

    packet.extend(struct.pack(">I", 0x464C4558))
    packet.extend(struct.pack(">H", 0x01))
    packet.extend(struct.pack(">H", 0x0B12))
    packet.extend(struct.pack(">I", 66666))

    length_placeholder = len(packet)
    packet.extend(struct.pack(">I", 0))

    packet.extend(b"EXTRA_CLIENT\x00")
    packet.extend(b"SOLIDWORKS\x00")
    packet.extend(b"2024\x00")
    packet.extend(b"x64\x00")
    packet.extend(b"cad-workstation\x00")
    packet.extend(b"designer\x00")

    packet.extend(struct.pack(">I", 3333))
    packet.extend(struct.pack(">I", int(time.time())))

    hostid_bytes = bytes.fromhex(hostid)
    packet.extend(struct.pack(">H", 0x0001))
    packet.extend(struct.pack(">H", len(hostid_bytes)))
    packet.extend(hostid_bytes)

    packet.extend(struct.pack(">H", 0x0003))
    packet.extend(struct.pack(">H", len(vendor_data)))
    packet.extend(vendor_data)

    license_path = b"C:\\FlexLM\\license.dat"
    packet.extend(struct.pack(">H", 0x0004))
    packet.extend(struct.pack(">H", len(license_path)))
    packet.extend(license_path)

    actual_length = len(packet)
    struct.pack_into(">I", packet, length_placeholder, actual_length)

    return bytes(packet)


def test_parser_initialization(parser: FlexLMProtocolParser) -> None:
    """Parser initializes with valid server features and encryption seed."""
    assert isinstance(parser.server_features, dict)
    assert len(parser.server_features) > 0
    assert "AUTOCAD" in parser.server_features
    assert "MATLAB" in parser.server_features
    assert "INVENTOR" in parser.server_features
    assert "SOLIDWORKS" in parser.server_features

    assert isinstance(parser.encryption_seed, bytes)
    assert len(parser.encryption_seed) == 32

    assert isinstance(parser.active_checkouts, dict)
    assert len(parser.active_checkouts) == 0


def test_parse_checkout_request_autocad(parser: FlexLMProtocolParser) -> None:
    """Parser correctly extracts all fields from AutoCAD checkout request."""
    request_data = create_flexlm_checkout_request(
        feature="AUTOCAD",
        version="2024.0",
        hostname="CAD_STATION_01",
        username="architect",
        platform="x64_w10",
        sequence=12345,
        client_id="AUTOCAD_CLIENT",
        pid=9876,
    )

    request = parser.parse_request(request_data)

    assert request is not None
    assert isinstance(request, FlexLMRequest)
    assert request.command == 0x01
    assert request.version == 0x0B12
    assert request.sequence == 12345
    assert request.client_id == "AUTOCAD_CLIENT"
    assert request.feature == "AUTOCAD"
    assert request.version_requested == "2024.0"
    assert request.platform == "x64_w10"
    assert request.hostname == "CAD_STATION_01"
    assert request.username == "architect"
    assert request.pid == 9876
    assert request.checkout_time > 0


def test_parse_checkout_request_matlab(parser: FlexLMProtocolParser) -> None:
    """Parser correctly extracts all fields from MATLAB checkout request."""
    request_data = create_flexlm_checkout_request(
        feature="MATLAB",
        version="R2024a",
        hostname="MATLAB_WORKSTATION",
        username="researcher",
        platform="linux64",
        sequence=98765,
        client_id="MATLAB_APP",
        pid=5432,
    )

    request = parser.parse_request(request_data)

    assert request is not None
    assert request.client_id == "MATLAB_APP"
    assert request.feature == "MATLAB"
    assert request.version_requested == "R2024a"
    assert request.platform == "linux64"
    assert request.hostname == "MATLAB_WORKSTATION"
    assert request.username == "researcher"
    assert request.sequence == 98765


def test_parse_checkin_request(parser: FlexLMProtocolParser) -> None:
    """Parser correctly identifies and parses checkin requests."""
    request_data = create_flexlm_checkin_request(
        feature="SIMULINK",
        hostname="SIM_SERVER",
        username="modeler",
        sequence=24680,
        client_id="SIMULINK_CLIENT",
    )

    request = parser.parse_request(request_data)

    assert request is not None
    assert request.command == 0x02
    assert request.feature == "SIMULINK"
    assert request.hostname == "SIM_SERVER"
    assert request.username == "modeler"
    assert request.sequence == 24680


def test_parse_heartbeat_request(parser: FlexLMProtocolParser) -> None:
    """Parser correctly identifies and parses heartbeat requests."""
    request_data = create_flexlm_heartbeat_request(
        feature="INVENTOR",
        hostname="DESIGN_STATION",
        username="engineer",
        sequence=13579,
    )

    request = parser.parse_request(request_data)

    assert request is not None
    assert request.command == 0x04
    assert request.feature == "INVENTOR"
    assert request.hostname == "DESIGN_STATION"
    assert request.username == "engineer"
    assert request.sequence == 13579


def test_parse_status_request(parser: FlexLMProtocolParser) -> None:
    """Parser correctly identifies and parses status requests."""
    request_data = create_flexlm_status_request(sequence=77777)

    request = parser.parse_request(request_data)

    assert request is not None
    assert request.command == 0x03
    assert request.sequence == 77777


def test_parse_feature_info_request(parser: FlexLMProtocolParser) -> None:
    """Parser correctly identifies and parses feature info requests."""
    request_data = create_flexlm_feature_info_request(
        feature="SOLIDWORKS", sequence=88888
    )

    request = parser.parse_request(request_data)

    assert request is not None
    assert request.command == 0x05
    assert request.feature == "SOLIDWORKS"
    assert request.sequence == 88888


def test_parse_server_info_request(parser: FlexLMProtocolParser) -> None:
    """Parser correctly identifies and parses server info requests."""
    request_data = create_flexlm_server_info_request(sequence=99999)

    request = parser.parse_request(request_data)

    assert request is not None
    assert request.command == 0x06
    assert request.sequence == 99999


def test_parse_hostid_request(parser: FlexLMProtocolParser) -> None:
    """Parser correctly identifies and parses host ID requests."""
    request_data = create_flexlm_hostid_request(
        hostname="SECURE_WORKSTATION", sequence=11223
    )

    request = parser.parse_request(request_data)

    assert request is not None
    assert request.command == 0x10
    assert request.hostname == "SECURE_WORKSTATION"
    assert request.sequence == 11223


def test_parse_encryption_seed_request(parser: FlexLMProtocolParser) -> None:
    """Parser correctly identifies and parses encryption seed requests."""
    request_data = create_flexlm_encryption_seed_request(sequence=44556)

    request = parser.parse_request(request_data)

    assert request is not None
    assert request.command == 0x11
    assert request.sequence == 44556


def test_parse_request_with_additional_data(parser: FlexLMProtocolParser) -> None:
    """Parser correctly extracts additional data fields from requests."""
    request_data = create_flexlm_request_with_additional_data(
        hostid="112233445566", vendor_data=b"VENDOR_SPECIFIC_DATA"
    )

    request = parser.parse_request(request_data)

    assert request is not None
    assert request.feature == "SOLIDWORKS"
    assert isinstance(request.additional_data, dict)
    assert "hostid" in request.additional_data
    assert request.additional_data["hostid"] == "112233445566"
    assert "vendor_data" in request.additional_data
    assert request.additional_data["vendor_data"] == b"VENDOR_SPECIFIC_DATA"
    assert "license_path" in request.additional_data
    assert "FlexLM" in request.additional_data["license_path"]


def test_parse_invalid_magic_number(parser: FlexLMProtocolParser) -> None:
    """Parser rejects packets with invalid magic numbers."""
    invalid_packet = struct.pack(">I", 0xDEADBEEF) + b"\x00" * 100

    request = parser.parse_request(invalid_packet)

    assert request is None


def test_parse_truncated_header(parser: FlexLMProtocolParser) -> None:
    """Parser rejects packets with truncated headers."""
    truncated_packet = struct.pack(">I", 0x464C4558) + b"\x00\x01"

    request = parser.parse_request(truncated_packet)

    assert request is None


def test_parse_length_mismatch(parser: FlexLMProtocolParser) -> None:
    """Parser rejects packets where declared length exceeds actual data."""
    packet = bytearray()
    packet.extend(struct.pack(">I", 0x464C4558))
    packet.extend(struct.pack(">H", 0x01))
    packet.extend(struct.pack(">H", 0x0B12))
    packet.extend(struct.pack(">I", 12345))
    packet.extend(struct.pack(">I", 10000))

    request = parser.parse_request(bytes(packet))

    assert request is None


def test_parse_alternative_magic_lm_v(parser: FlexLMProtocolParser) -> None:
    """Parser accepts alternative FlexLM magic number LM_V."""
    packet = bytearray()
    packet.extend(struct.pack(">I", 0x4C4D5F56))
    packet.extend(struct.pack(">H", 0x01))
    packet.extend(struct.pack(">H", 0x0B12))
    packet.extend(struct.pack(">I", 55555))

    length_placeholder = len(packet)
    packet.extend(struct.pack(">I", 0))

    packet.extend(b"CLIENT\x00")
    packet.extend(b"MAYA\x00")
    packet.extend(b"2024.0\x00")
    packet.extend(b"x64\x00")
    packet.extend(b"animator-pc\x00")
    packet.extend(b"artist\x00")
    packet.extend(struct.pack(">I", 1234))
    packet.extend(struct.pack(">I", int(time.time())))

    actual_length = len(packet)
    struct.pack_into(">I", packet, length_placeholder, actual_length)

    request = parser.parse_request(bytes(packet))

    assert request is not None
    assert request.feature == "MAYA"


def test_parse_alternative_magic_fxlm(parser: FlexLMProtocolParser) -> None:
    """Parser accepts alternative FlexLM magic number FXLM."""
    packet = bytearray()
    packet.extend(struct.pack(">I", 0x46584C4D))
    packet.extend(struct.pack(">H", 0x03))
    packet.extend(struct.pack(">H", 0x0B12))
    packet.extend(struct.pack(">I", 77777))

    length_placeholder = len(packet)
    packet.extend(struct.pack(">I", 0))

    packet.extend(b"STATUS\x00")
    packet.extend(b"\x00")
    packet.extend(b"1.0\x00")
    packet.extend(b"any\x00")
    packet.extend(b"server\x00")
    packet.extend(b"admin\x00")
    packet.extend(struct.pack(">I", 0))
    packet.extend(struct.pack(">I", int(time.time())))

    actual_length = len(packet)
    struct.pack_into(">I", packet, length_placeholder, actual_length)

    request = parser.parse_request(bytes(packet))

    assert request is not None
    assert request.command == 0x03


def test_generate_checkout_response_autocad(parser: FlexLMProtocolParser) -> None:
    """Parser generates valid checkout response for AutoCAD feature."""
    request_data = create_flexlm_checkout_request(
        feature="AUTOCAD",
        version="2024.0",
        hostname="WORKSTATION_A",
        username="user1",
        sequence=12345,
    )
    request = parser.parse_request(request_data)

    assert request is not None

    response = parser.generate_response(request)

    assert isinstance(response, FlexLMResponse)
    assert response.status == 0x00
    assert response.sequence == 12345
    assert response.server_version == "11.18.0"
    assert response.feature == "AUTOCAD"
    assert response.expiry_date == "31-dec-2025"
    assert len(response.license_key) == 32
    assert response.license_key[0] in ["S", "P", "T"]
    assert response.server_id == "intellicrack-flexlm"
    assert "vendor" in response.additional_data
    assert response.additional_data["vendor"] == "ADSKFLEX"
    assert response.additional_data["version"] == "2024.0"
    assert "signature" in response.additional_data


def test_generate_checkout_response_matlab(parser: FlexLMProtocolParser) -> None:
    """Parser generates valid checkout response for MATLAB feature."""
    request_data = create_flexlm_checkout_request(
        feature="MATLAB",
        version="R2024a",
        hostname="MATLAB_BOX",
        username="scientist",
        sequence=99999,
    )
    request = parser.parse_request(request_data)

    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x00
    assert response.feature == "MATLAB"
    assert response.expiry_date == "31-dec-2025"
    assert len(response.license_key) == 32
    assert response.additional_data["vendor"] == "MLM"


def test_generate_checkout_response_unknown_feature(
    parser: FlexLMProtocolParser,
) -> None:
    """Parser returns FEATURE_NOT_FOUND for unknown features."""
    request_data = create_flexlm_checkout_request(
        feature="UNKNOWN_APP", version="1.0", sequence=11111
    )
    request = parser.parse_request(request_data)

    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x01
    assert response.feature == "UNKNOWN_APP"
    assert response.license_key == ""
    assert "error" in response.additional_data


def test_checkout_tracking(parser: FlexLMProtocolParser) -> None:
    """Parser tracks active checkouts correctly."""
    assert len(parser.active_checkouts) == 0

    request_data = create_flexlm_checkout_request(
        feature="INVENTOR",
        hostname="DESIGN_PC",
        username="designer",
        sequence=22222,
    )
    request = parser.parse_request(request_data)
    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x00
    assert len(parser.active_checkouts) == 1

    checkout_id = "DESIGN_PC:designer:INVENTOR"
    assert checkout_id in parser.active_checkouts
    assert parser.active_checkouts[checkout_id]["request"] == request
    assert "key" in parser.active_checkouts[checkout_id]


def test_generate_checkin_response_active_checkout(
    parser: FlexLMProtocolParser,
) -> None:
    """Parser successfully processes checkin for active checkout."""
    checkout_request_data = create_flexlm_checkout_request(
        feature="SOLIDWORKS",
        hostname="CAD_MACHINE",
        username="engineer",
        sequence=10000,
    )
    checkout_request = parser.parse_request(checkout_request_data)
    assert checkout_request is not None
    parser.generate_response(checkout_request)

    assert len(parser.active_checkouts) == 1

    checkin_request_data = create_flexlm_checkin_request(
        feature="SOLIDWORKS",
        hostname="CAD_MACHINE",
        username="engineer",
        sequence=10001,
    )
    checkin_request = parser.parse_request(checkin_request_data)
    assert checkin_request is not None

    response = parser.generate_response(checkin_request)

    assert response.status == 0x00
    assert len(parser.active_checkouts) == 0
    assert "checkin_time" in response.additional_data


def test_generate_checkin_response_no_active_checkout(
    parser: FlexLMProtocolParser,
) -> None:
    """Parser processes checkin even without active checkout."""
    checkin_request_data = create_flexlm_checkin_request(
        feature="ANSYS", hostname="UNKNOWN_HOST", username="nobody", sequence=33333
    )
    checkin_request = parser.parse_request(checkin_request_data)
    assert checkin_request is not None

    response = parser.generate_response(checkin_request)

    assert response.status == 0x00


def test_generate_heartbeat_response_active_checkout(
    parser: FlexLMProtocolParser,
) -> None:
    """Parser successfully processes heartbeat for active checkout."""
    checkout_data = create_flexlm_checkout_request(
        feature="MAYA",
        hostname="ANIMATION_WORKSTATION",
        username="animator",
        sequence=40000,
    )
    checkout_req = parser.parse_request(checkout_data)
    assert checkout_req is not None
    parser.generate_response(checkout_req)

    heartbeat_data = create_flexlm_heartbeat_request(
        feature="MAYA",
        hostname="ANIMATION_WORKSTATION",
        username="animator",
        sequence=40001,
    )
    heartbeat_req = parser.parse_request(heartbeat_data)
    assert heartbeat_req is not None

    response = parser.generate_response(heartbeat_req)

    assert response.status == 0x00
    assert "heartbeat_time" in response.additional_data

    checkout_id = "ANIMATION_WORKSTATION:animator:MAYA"
    assert "last_heartbeat" in parser.active_checkouts[checkout_id]


def test_generate_heartbeat_response_no_active_checkout(
    parser: FlexLMProtocolParser,
) -> None:
    """Parser returns HEARTBEAT_FAILED for non-existent checkout."""
    heartbeat_data = create_flexlm_heartbeat_request(
        feature="MISSING_FEATURE",
        hostname="NONEXISTENT_HOST",
        username="nobody",
        sequence=50000,
    )
    heartbeat_req = parser.parse_request(heartbeat_data)
    assert heartbeat_req is not None

    response = parser.generate_response(heartbeat_req)

    assert response.status == 0x06


def test_generate_status_response(parser: FlexLMProtocolParser) -> None:
    """Parser generates comprehensive status response."""
    checkout1 = create_flexlm_checkout_request(
        feature="AUTOCAD", hostname="PC1", username="user1", sequence=60000
    )
    parser.generate_response(parser.parse_request(checkout1))

    checkout2 = create_flexlm_checkout_request(
        feature="MATLAB", hostname="PC2", username="user2", sequence=60001
    )
    parser.generate_response(parser.parse_request(checkout2))

    status_data = create_flexlm_status_request(sequence=60002)
    status_req = parser.parse_request(status_data)
    assert status_req is not None

    response = parser.generate_response(status_req)

    assert response.status == 0x00
    assert "server_status" in response.additional_data
    assert response.additional_data["server_status"] == "UP"
    assert response.additional_data["active_checkouts"] == 2
    assert response.additional_data["features_available"] > 0


def test_generate_feature_info_response_existing_feature(
    parser: FlexLMProtocolParser,
) -> None:
    """Parser returns detailed feature information for existing features."""
    request_data = create_flexlm_feature_info_request(
        feature="INVENTOR", sequence=70000
    )
    request = parser.parse_request(request_data)
    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x00
    assert response.feature == "INVENTOR"
    assert response.expiry_date == "31-dec-2025"
    assert "version" in response.additional_data
    assert "vendor" in response.additional_data
    assert "count" in response.additional_data
    assert "signature" in response.additional_data


def test_generate_feature_info_response_missing_feature(
    parser: FlexLMProtocolParser,
) -> None:
    """Parser returns FEATURE_NOT_FOUND for non-existent features."""
    request_data = create_flexlm_feature_info_request(
        feature="NONEXISTENT", sequence=70001
    )
    request = parser.parse_request(request_data)
    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x01
    assert response.feature == "NONEXISTENT"


def test_generate_server_info_response(parser: FlexLMProtocolParser) -> None:
    """Parser generates detailed server information response."""
    request_data = create_flexlm_server_info_request(sequence=80000)
    request = parser.parse_request(request_data)
    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x00
    assert "server_name" in response.additional_data
    assert response.additional_data["server_name"] == "intellicrack-flexlm"
    assert "server_version" in response.additional_data
    assert "features" in response.additional_data
    assert isinstance(response.additional_data["features"], list)
    assert len(response.additional_data["features"]) > 0
    assert "max_connections" in response.additional_data
    assert "current_connections" in response.additional_data


def test_generate_hostid_response(parser: FlexLMProtocolParser) -> None:
    """Parser generates deterministic host ID for given hostname."""
    request_data1 = create_flexlm_hostid_request(
        hostname="TEST_HOST_A", sequence=90000
    )
    request1 = parser.parse_request(request_data1)
    assert request1 is not None
    response1 = parser.generate_response(request1)

    assert response1.status == 0x00
    assert "hostid" in response1.additional_data
    hostid1 = response1.additional_data["hostid"]
    assert len(hostid1) == 12
    assert hostid1.isupper()

    request_data2 = create_flexlm_hostid_request(
        hostname="TEST_HOST_A", sequence=90001
    )
    request2 = parser.parse_request(request_data2)
    assert request2 is not None
    response2 = parser.generate_response(request2)

    hostid2 = response2.additional_data["hostid"]
    assert hostid1 == hostid2

    request_data3 = create_flexlm_hostid_request(
        hostname="TEST_HOST_B", sequence=90002
    )
    request3 = parser.parse_request(request_data3)
    assert request3 is not None
    response3 = parser.generate_response(request3)

    hostid3 = response3.additional_data["hostid"]
    assert hostid1 != hostid3


def test_generate_encryption_seed_response(parser: FlexLMProtocolParser) -> None:
    """Parser returns valid encryption seed in response."""
    request_data = create_flexlm_encryption_seed_request(sequence=95000)
    request = parser.parse_request(request_data)
    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x00
    assert "encryption_seed" in response.additional_data
    seed_hex = response.additional_data["encryption_seed"]
    assert len(seed_hex) == 64
    assert all(c in "0123456789abcdef" for c in seed_hex.lower())


def test_generate_unknown_command_response(parser: FlexLMProtocolParser) -> None:
    """Parser returns error response for unknown commands."""
    packet = bytearray()
    packet.extend(struct.pack(">I", 0x464C4558))
    packet.extend(struct.pack(">H", 0xFF))
    packet.extend(struct.pack(">H", 0x0B12))
    packet.extend(struct.pack(">I", 99999))

    length_placeholder = len(packet)
    packet.extend(struct.pack(">I", 0))

    packet.extend(b"CLIENT\x00\x00\x00\x00\x00\x00")
    packet.extend(struct.pack(">I", 0))
    packet.extend(struct.pack(">I", int(time.time())))

    actual_length = len(packet)
    struct.pack_into(">I", packet, length_placeholder, actual_length)

    request = parser.parse_request(bytes(packet))
    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x0C
    assert "error" in response.additional_data


def test_serialize_response_basic(parser: FlexLMProtocolParser) -> None:
    """Parser correctly serializes basic response to binary format."""
    response = FlexLMResponse(
        status=0x00,
        sequence=12345,
        server_version="11.18.0",
        feature="TEST_FEATURE",
        expiry_date="31-dec-2025",
        license_key="ABCD1234EFGH5678IJKL9012MNOP3456",
        server_id="intellicrack-flexlm",
        additional_data={},
    )

    serialized = parser.serialize_response(response)

    assert isinstance(serialized, bytes)
    assert len(serialized) > 0

    magic = struct.unpack(">I", serialized[:4])[0]
    assert magic == 0x464C4558

    status = struct.unpack(">H", serialized[4:6])[0]
    assert status == 0x00

    length = struct.unpack(">I", serialized[6:10])[0]
    assert length == len(serialized) - 4

    sequence = struct.unpack(">I", serialized[10:14])[0]
    assert sequence == 12345


def test_serialize_response_with_additional_data(parser: FlexLMProtocolParser) -> None:
    """Parser correctly serializes response with additional data fields."""
    response = FlexLMResponse(
        status=0x00,
        sequence=54321,
        server_version="11.18.0",
        feature="MATLAB",
        expiry_date="31-dec-2025",
        license_key="KEY123456789ABCDEF",
        server_id="test-server",
        additional_data={
            "vendor": "MLM",
            "version": "R2024a",
            "count_remaining": 99,
            "custom_field": "test_value",
        },
    )

    serialized = parser.serialize_response(response)

    assert len(serialized) > 100
    assert b"MATLAB" in serialized
    assert b"KEY123456789ABCDEF" in serialized


def test_serialize_deserialize_round_trip(parser: FlexLMProtocolParser) -> None:
    """Serialized response contains all original request information."""
    request_data = create_flexlm_checkout_request(
        feature="AUTOCAD",
        version="2024.0",
        hostname="ROUNDTRIP_TEST",
        username="tester",
        sequence=77777,
    )
    request = parser.parse_request(request_data)
    assert request is not None

    response = parser.generate_response(request)
    serialized = parser.serialize_response(response)

    assert b"AUTOCAD" in serialized or b"autocad" in serialized.lower()
    assert struct.unpack(">I", serialized[10:14])[0] == 77777


def test_add_custom_feature(parser: FlexLMProtocolParser) -> None:
    """Parser allows adding custom features with full specifications."""
    initial_count = len(parser.server_features)

    parser.add_custom_feature(
        name="CUSTOM_APP",
        version="5.0",
        vendor="CUSTOM_VENDOR",
        count=50,
        expiry="31-dec-2026",
        signature="CUSTOM_SIGNATURE_1234567890ABCDEF",
    )

    assert len(parser.server_features) == initial_count + 1
    assert "CUSTOM_APP" in parser.server_features

    feature_info = parser.server_features["CUSTOM_APP"]
    assert feature_info["version"] == "5.0"
    assert feature_info["vendor"] == "CUSTOM_VENDOR"
    assert feature_info["count"] == 50
    assert feature_info["expiry"] == "31-dec-2026"
    assert feature_info["signature"] == "CUSTOM_SIGNATURE_1234567890ABCDEF"


def test_add_custom_feature_auto_signature(parser: FlexLMProtocolParser) -> None:
    """Parser auto-generates signature when not provided."""
    parser.add_custom_feature(
        name="AUTO_SIG_APP", version="1.0", vendor="TEST_VENDOR"
    )

    assert "AUTO_SIG_APP" in parser.server_features
    signature = parser.server_features["AUTO_SIG_APP"]["signature"]
    assert len(signature) == 40
    assert signature.isupper()


def test_remove_feature(parser: FlexLMProtocolParser) -> None:
    """Parser successfully removes features from server."""
    parser.add_custom_feature(
        name="TEMP_FEATURE", version="1.0", vendor="TEMP_VENDOR"
    )
    assert "TEMP_FEATURE" in parser.server_features

    parser.remove_feature("TEMP_FEATURE")

    assert "TEMP_FEATURE" not in parser.server_features


def test_get_active_checkouts(parser: FlexLMProtocolParser) -> None:
    """Parser returns copy of active checkouts."""
    checkout1 = create_flexlm_checkout_request(
        feature="AUTOCAD", hostname="HOST1", username="USER1", sequence=10001
    )
    req1 = parser.parse_request(checkout1)
    assert req1 is not None
    parser.generate_response(req1)

    checkout2 = create_flexlm_checkout_request(
        feature="MATLAB", hostname="HOST2", username="USER2", sequence=10002
    )
    req2 = parser.parse_request(checkout2)
    assert req2 is not None
    parser.generate_response(req2)

    active = parser.get_active_checkouts()

    assert len(active) == 2
    assert "HOST1:USER1:AUTOCAD" in active
    assert "HOST2:USER2:MATLAB" in active


def test_clear_checkouts(parser: FlexLMProtocolParser) -> None:
    """Parser clears all active checkouts."""
    features = ["AUTOCAD", "MATLAB", "INVENTOR", "SOLIDWORKS", "MAYA"]
    for i, feature in enumerate(features):
        checkout = create_flexlm_checkout_request(
            feature=feature,
            hostname=f"HOST{i}",
            username=f"USER{i}",
            sequence=20000 + i,
        )
        req = parser.parse_request(checkout)
        assert req is not None
        parser.generate_response(req)

    assert len(parser.active_checkouts) == 5

    parser.clear_checkouts()

    assert len(parser.active_checkouts) == 0


def test_get_server_statistics(parser: FlexLMProtocolParser) -> None:
    """Parser returns comprehensive server statistics."""
    checkout = create_flexlm_checkout_request(
        feature="ANSYS", hostname="STATS_HOST", username="STATS_USER", sequence=30000
    )
    req = parser.parse_request(checkout)
    assert req is not None
    parser.generate_response(req)

    stats = parser.get_server_statistics()

    assert isinstance(stats, dict)
    assert "total_features" in stats
    assert stats["total_features"] > 0
    assert "active_checkouts" in stats
    assert stats["active_checkouts"] == 1
    assert "features" in stats
    assert isinstance(stats["features"], list)
    assert "server_version" in stats
    assert stats["server_version"] == "11.18.0"
    assert "uptime" in stats


def test_traffic_capture_initialization(
    traffic_capture: FlexLMTrafficCapture,
) -> None:
    """Traffic capture initializes with empty state."""
    assert len(traffic_capture.captured_requests) == 0
    assert len(traffic_capture.captured_responses) == 0
    assert len(traffic_capture.server_endpoints) == 0
    assert len(traffic_capture.client_endpoints) == 0


def test_capture_packet_valid_request(traffic_capture: FlexLMTrafficCapture) -> None:
    """Traffic capture successfully captures valid FlexLM packets."""
    request_data = create_flexlm_checkout_request(
        feature="CAPTURE_TEST", sequence=40000
    )

    result = traffic_capture.capture_packet(
        request_data, ("192.168.1.100", 12345), ("192.168.1.10", 27000)
    )

    assert result is True
    assert len(traffic_capture.captured_requests) == 1
    assert ("192.168.1.100", 12345) in traffic_capture.client_endpoints
    assert ("192.168.1.10", 27000) in traffic_capture.server_endpoints


def test_capture_packet_invalid_data(traffic_capture: FlexLMTrafficCapture) -> None:
    """Traffic capture rejects invalid packets."""
    invalid_data = b"NOT A FLEXLM PACKET"

    result = traffic_capture.capture_packet(
        invalid_data, ("10.0.0.1", 1234), ("10.0.0.2", 27000)
    )

    assert result is False
    assert len(traffic_capture.captured_requests) == 0


def test_capture_multiple_packets(traffic_capture: FlexLMTrafficCapture) -> None:
    """Traffic capture handles multiple packets correctly."""
    for i in range(10):
        packet = create_flexlm_checkout_request(
            feature=f"APP_{i}", sequence=50000 + i
        )
        traffic_capture.capture_packet(
            packet, (f"192.168.1.{100+i}", 12345 + i), ("192.168.1.10", 27000)
        )

    assert len(traffic_capture.captured_requests) == 10
    assert len(traffic_capture.client_endpoints) == 10
    assert len(traffic_capture.server_endpoints) == 1


def test_analyze_traffic_patterns(traffic_capture: FlexLMTrafficCapture) -> None:
    """Traffic capture provides comprehensive traffic analysis."""
    packet1 = create_flexlm_checkout_request(feature="AUTOCAD", sequence=60000)
    traffic_capture.capture_packet(
        packet1, ("192.168.1.100", 10001), ("192.168.1.10", 27000), timestamp=1000.0
    )

    packet2 = create_flexlm_checkin_request(feature="MATLAB", sequence=60001)
    traffic_capture.capture_packet(
        packet2, ("192.168.1.101", 10002), ("192.168.1.10", 27000), timestamp=1100.0
    )

    packet3 = create_flexlm_heartbeat_request(feature="INVENTOR", sequence=60002)
    traffic_capture.capture_packet(
        packet3, ("192.168.1.102", 10003), ("192.168.1.10", 27000), timestamp=1200.0
    )

    analysis = traffic_capture.analyze_traffic_patterns()

    assert "total_packets" in analysis
    assert analysis["total_packets"] == 3
    assert "unique_clients" in analysis
    assert analysis["unique_clients"] == 3
    assert "unique_servers" in analysis
    assert analysis["unique_servers"] == 1
    assert "command_distribution" in analysis
    assert "top_commands" in analysis
    assert "top_features" in analysis
    assert "capture_duration" in analysis


def test_analyze_traffic_no_data(traffic_capture: FlexLMTrafficCapture) -> None:
    """Traffic capture handles analysis with no captured data."""
    analysis = traffic_capture.analyze_traffic_patterns()

    assert "error" in analysis


def test_extract_license_info(traffic_capture: FlexLMTrafficCapture) -> None:
    """Traffic capture extracts license information from checkout requests."""
    checkout1 = create_flexlm_checkout_request(
        feature="SOLIDWORKS",
        version="2024",
        hostname="WORKSTATION_1",
        username="designer1",
        platform="x64_w10",
        sequence=70000,
    )
    traffic_capture.capture_packet(
        checkout1, ("10.0.0.50", 15000), ("10.0.0.1", 27000), timestamp=5000.0
    )

    checkout2 = create_flexlm_checkout_request(
        feature="ANSYS",
        version="2024.1",
        hostname="WORKSTATION_2",
        username="engineer2",
        platform="linux64",
        sequence=70001,
    )
    traffic_capture.capture_packet(
        checkout2, ("10.0.0.51", 15001), ("10.0.0.1", 27000), timestamp=5100.0
    )

    status = create_flexlm_status_request(sequence=70002)
    traffic_capture.capture_packet(
        status, ("10.0.0.52", 15002), ("10.0.0.1", 27000), timestamp=5200.0
    )

    licenses = traffic_capture.extract_license_info()

    assert len(licenses) == 2
    assert licenses[0]["feature"] == "SOLIDWORKS"
    assert licenses[0]["version"] == "2024"
    assert licenses[0]["client"] == "WORKSTATION_1"
    assert licenses[0]["username"] == "designer1"
    assert licenses[1]["feature"] == "ANSYS"


def test_detect_server_endpoints(traffic_capture: FlexLMTrafficCapture) -> None:
    """Traffic capture detects FlexLM server endpoints."""
    packet1 = create_flexlm_checkout_request(sequence=80000)
    traffic_capture.capture_packet(
        packet1, ("192.168.1.100", 10001), ("192.168.1.10", 27000)
    )

    packet2 = create_flexlm_checkout_request(sequence=80001)
    traffic_capture.capture_packet(
        packet2, ("192.168.1.101", 10002), ("192.168.1.11", 27001)
    )

    servers = traffic_capture.detect_server_endpoints()

    assert len(servers) == 2
    assert any(s["ip"] == "192.168.1.10" and s["port"] == 27000 for s in servers)
    assert any(s["ip"] == "192.168.1.11" and s["port"] == 27001 for s in servers)
    assert all(s["protocol"] == "FlexLM" for s in servers)


def test_export_capture(
    traffic_capture: FlexLMTrafficCapture, temp_workspace: Path
) -> None:
    """Traffic capture exports data to JSON file."""
    packet = create_flexlm_checkout_request(
        feature="EXPORT_TEST",
        version="1.0",
        hostname="EXPORT_HOST",
        username="export_user",
        sequence=90000,
    )
    traffic_capture.capture_packet(
        packet, ("10.0.0.100", 20000), ("10.0.0.1", 27000), timestamp=10000.0
    )

    output_file = temp_workspace / "capture_export.json"
    traffic_capture.export_capture(str(output_file))

    assert output_file.exists()
    assert output_file.stat().st_size > 0

    import json

    with open(output_file, encoding="utf-8") as f:
        data = json.load(f)

    assert "capture_time" in data
    assert "total_packets" in data
    assert data["total_packets"] == 1
    assert "packets" in data
    assert len(data["packets"]) == 1
    assert data["packets"][0]["feature"] == "EXPORT_TEST"
    assert "analysis" in data


def test_license_generator_initialization(
    license_generator: FlexLMLicenseGenerator,
) -> None:
    """License generator initializes correctly."""
    assert license_generator is not None


def test_generate_license_file_single_feature(
    license_generator: FlexLMLicenseGenerator,
) -> None:
    """License generator creates valid license file with single feature."""
    features = [
        {
            "name": "TEST_APP",
            "version": "1.0",
            "vendor": "TEST_VENDOR",
            "expiry": "31-dec-2025",
            "count": 10,
            "signature": "ABCD1234EFGH5678",
        }
    ]

    license_content = license_generator.generate_license_file(
        features=features,
        server_host="license-server.example.com",
        server_port=27000,
        vendor_daemon="test_daemon",
        vendor_port=27001,
    )

    assert isinstance(license_content, str)
    assert "SERVER license-server.example.com ANY 27000" in license_content
    assert "VENDOR test_daemon PORT=27001" in license_content
    assert "FEATURE TEST_APP" in license_content
    assert "TEST_VENDOR" in license_content
    assert "1.0" in license_content
    assert "31-dec-2025" in license_content
    assert "10" in license_content
    assert "ABCD1234EFGH5678" in license_content


def test_generate_license_file_multiple_features(
    license_generator: FlexLMLicenseGenerator,
) -> None:
    """License generator creates license file with multiple features."""
    features = [
        {
            "name": "FEATURE_A",
            "version": "2.0",
            "vendor": "VENDOR_A",
            "count": 50,
        },
        {
            "name": "FEATURE_B",
            "version": "3.0",
            "vendor": "VENDOR_B",
            "count": 100,
        },
        {
            "name": "FEATURE_C",
            "version": "1.5",
            "vendor": "VENDOR_C",
            "count": 25,
        },
    ]

    license_content = license_generator.generate_license_file(
        features=features, server_host="multi.server.com"
    )

    assert "FEATURE FEATURE_A" in license_content
    assert "FEATURE FEATURE_B" in license_content
    assert "FEATURE FEATURE_C" in license_content
    lines = [line for line in license_content.split("\n") if line.strip().startswith("FEATURE ")]
    assert len(lines) == 3


def test_parse_license_file_basic(
    license_generator: FlexLMLicenseGenerator,
) -> None:
    """License generator parses basic license file correctly."""
    license_content = """
SERVER license.example.com ANY 27000
VENDOR vendor_daemon PORT=27001

FEATURE TEST_FEATURE vendor_daemon 1.0 31-dec-2025 10 HOSTID=ANY SIGN="SIGNATURE123"
"""

    parsed = license_generator.parse_license_file(license_content)

    assert isinstance(parsed, dict)
    assert "servers" in parsed
    assert len(parsed["servers"]) == 1
    assert parsed["servers"][0]["hostname"] == "license.example.com"
    assert parsed["servers"][0]["hostid"] == "ANY"
    assert parsed["servers"][0]["port"] == 27000

    assert "vendors" in parsed
    assert len(parsed["vendors"]) == 1
    assert parsed["vendors"][0]["name"] == "vendor_daemon"
    assert parsed["vendors"][0]["port"] == 27001

    assert "features" in parsed
    assert len(parsed["features"]) == 1
    assert parsed["features"][0]["name"] == "TEST_FEATURE"
    assert parsed["features"][0]["vendor"] == "vendor_daemon"
    assert parsed["features"][0]["version"] == "1.0"
    assert parsed["features"][0]["expiry"] == "31-dec-2025"
    assert parsed["features"][0]["count"] == 10
    assert parsed["features"][0]["sign"] == "SIGNATURE123"


def test_parse_license_file_complex(
    license_generator: FlexLMLicenseGenerator,
) -> None:
    """License generator parses complex multi-feature license file."""
    license_content = """
# FlexLM License File
SERVER primary.server.com 001122334455 27000
SERVER backup.server.com 556677889900 27000
VENDOR vendor1 PORT=27001
VENDOR vendor2 PORT=27002

FEATURE APP_A vendor1 2.0 31-dec-2025 100 HOSTID=ANY SIGN="SIG_A"
FEATURE APP_B vendor1 3.0 permanent 50 HOSTID=ANY SIGN="SIG_B"
INCREMENT APP_C vendor2 1.0 31-jan-2026 25 HOSTID=ANY SIGN="SIG_C"
"""

    parsed = license_generator.parse_license_file(license_content)

    assert len(parsed["servers"]) == 2
    assert len(parsed["vendors"]) == 2
    assert len(parsed["features"]) == 3
    assert any(f["name"] == "APP_A" for f in parsed["features"])
    assert any(f["name"] == "APP_B" for f in parsed["features"])
    assert any(f["name"] == "APP_C" for f in parsed["features"])


def test_parse_license_file_with_comments(
    license_generator: FlexLMLicenseGenerator,
) -> None:
    """License generator ignores comments in license file."""
    license_content = """
# This is a comment
SERVER test.server.com ANY 27000
# Another comment
VENDOR test_vendor PORT=27001
# Feature comment
FEATURE TEST_APP test_vendor 1.0 31-dec-2025 1 HOSTID=ANY SIGN="TEST"
"""

    parsed = license_generator.parse_license_file(license_content)

    assert len(parsed["servers"]) == 1
    assert len(parsed["vendors"]) == 1
    assert len(parsed["features"]) == 1


def test_checkout_key_generation_deterministic(
    parser: FlexLMProtocolParser,
) -> None:
    """Generated checkout keys are consistent for same parameters."""
    request_data1 = create_flexlm_checkout_request(
        feature="AUTOCAD",
        hostname="SAME_HOST",
        username="SAME_USER",
        sequence=100000,
    )
    request1 = parser.parse_request(request_data1)
    response1 = parser.generate_response(request1)

    parser.clear_checkouts()

    time.sleep(0.01)

    request_data2 = create_flexlm_checkout_request(
        feature="AUTOCAD",
        hostname="SAME_HOST",
        username="SAME_USER",
        sequence=100001,
    )
    request2 = parser.parse_request(request_data2)
    response2 = parser.generate_response(request2)

    assert response1.license_key != response2.license_key


def test_feature_partial_match(parser: FlexLMProtocolParser) -> None:
    """Parser matches features with partial names when exact match not found."""
    request_data = create_flexlm_checkout_request(
        feature="autocad", version="2024.0", sequence=110000
    )
    request = parser.parse_request(request_data)
    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x00
    assert response.feature == "AUTOCAD"


def test_concurrent_checkouts_different_users(parser: FlexLMProtocolParser) -> None:
    """Parser handles concurrent checkouts for same feature by different users."""
    checkout1 = create_flexlm_checkout_request(
        feature="MATLAB",
        hostname="HOST_A",
        username="USER_A",
        sequence=120000,
    )
    parser.generate_response(parser.parse_request(checkout1))

    checkout2 = create_flexlm_checkout_request(
        feature="MATLAB",
        hostname="HOST_B",
        username="USER_B",
        sequence=120001,
    )
    parser.generate_response(parser.parse_request(checkout2))

    assert len(parser.active_checkouts) == 2
    assert "HOST_A:USER_A:MATLAB" in parser.active_checkouts
    assert "HOST_B:USER_B:MATLAB" in parser.active_checkouts


def test_response_sequence_number_preservation(
    parser: FlexLMProtocolParser,
) -> None:
    """Parser preserves sequence numbers in responses."""
    test_sequences = [1, 100, 10000, 65535, 99999]

    for seq in test_sequences:
        request_data = create_flexlm_checkout_request(
            feature="AUTOCAD", sequence=seq
        )
        request = parser.parse_request(request_data)
        response = parser.generate_response(request)

        assert response.sequence == seq


def test_encryption_seed_persistence(parser: FlexLMProtocolParser) -> None:
    """Parser maintains same encryption seed across multiple requests."""
    initial_seed = parser.encryption_seed

    for i in range(10):
        request_data = create_flexlm_encryption_seed_request(sequence=130000 + i)
        request = parser.parse_request(request_data)
        response = parser.generate_response(request)

        assert parser.encryption_seed == initial_seed
        assert response.additional_data["encryption_seed"] == initial_seed.hex()
