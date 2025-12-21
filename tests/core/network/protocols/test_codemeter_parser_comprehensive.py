"""Comprehensive tests for CodeMeter protocol parser and response generator.

Tests validate real CodeMeter protocol parsing, license container extraction,
activation handling, feature extraction, dongle communication, and response
generation capabilities against actual protocol specifications.
"""

import hashlib
import secrets
import struct
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.network.protocols.codemeter_parser import (
    CodeMeterProtocolParser,
    CodeMeterRequest,
    CodeMeterResponse,
)


@pytest.fixture
def parser() -> CodeMeterProtocolParser:
    """Create CodeMeter parser with default products."""
    return CodeMeterProtocolParser()


@pytest.fixture
def sample_login_request() -> bytes:
    """Create realistic CodeMeter login request packet."""
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

    client_id = b"TEST_CLIENT_001"
    packet.extend(struct.pack("<H", len(client_id)))
    packet.extend(client_id)

    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))

    return bytes(packet)


@pytest.fixture
def sample_challenge_request() -> bytes:
    """Create realistic CodeMeter challenge request packet."""
    packet = bytearray()

    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0x1002))
    packet.extend(struct.pack("<I", 54321))
    packet.extend(struct.pack("<I", 500001))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 0xFFFFFFFF))

    version = b"7.60"
    packet.extend(struct.pack("<H", len(version)))
    packet.extend(version)

    client_id = b"CLIENT_123"
    packet.extend(struct.pack("<H", len(client_id)))
    packet.extend(client_id)

    packet.extend(struct.pack("<H", 0))

    challenge_data = secrets.token_bytes(32)
    packet.extend(struct.pack("<H", len(challenge_data)))
    packet.extend(challenge_data)

    return bytes(packet)


@pytest.fixture
def sample_get_license_request() -> bytes:
    """Create realistic CodeMeter get license request packet."""
    packet = bytearray()

    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0x100A))
    packet.extend(struct.pack("<I", 99999))
    packet.extend(struct.pack("<I", 500001))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 0xFFFFFFFF))

    version = b"7.60.6089.500"
    packet.extend(struct.pack("<H", len(version)))
    packet.extend(version)

    client_id = b"LICENSED_CLIENT"
    packet.extend(struct.pack("<H", len(client_id)))
    packet.extend(client_id)

    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))

    return bytes(packet)


@pytest.fixture
def sample_encrypt_request() -> bytes:
    """Create realistic CodeMeter encryption request packet."""
    packet = bytearray()

    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0x1006))
    packet.extend(struct.pack("<I", 11111))
    packet.extend(struct.pack("<I", 500001))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 0xFFFFFFFF))

    version = b"7.60"
    packet.extend(struct.pack("<H", len(version)))
    packet.extend(version)

    client_id = b"ENCRYPT_CLIENT"
    packet.extend(struct.pack("<H", len(client_id)))
    packet.extend(client_id)

    packet.extend(struct.pack("<H", 0))

    plaintext_data = b"Secret data to encrypt" * 10
    packet.extend(struct.pack("<H", len(plaintext_data)))
    packet.extend(plaintext_data)

    return bytes(packet)


@pytest.fixture
def sample_get_container_info_request() -> bytes:
    """Create realistic CodeMeter get container info request packet."""
    packet = bytearray()

    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0x100D))
    packet.extend(struct.pack("<I", 77777))
    packet.extend(struct.pack("<I", 500001))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 0x0))

    version = b"7.60.6089.500"
    packet.extend(struct.pack("<H", len(version)))
    packet.extend(version)

    client_id = b"INFO_CLIENT"
    packet.extend(struct.pack("<H", len(client_id)))
    packet.extend(client_id)

    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))

    return bytes(packet)


@pytest.fixture
def sample_enum_products_request() -> bytes:
    """Create realistic CodeMeter enumerate products request packet."""
    packet = bytearray()

    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0x100E))
    packet.extend(struct.pack("<I", 88888))
    packet.extend(struct.pack("<I", 0))
    packet.extend(struct.pack("<I", 0))
    packet.extend(struct.pack("<I", 0x0))

    version = b"7.60"
    packet.extend(struct.pack("<H", len(version)))
    packet.extend(version)

    client_id = b"ENUM_CLIENT"
    packet.extend(struct.pack("<H", len(client_id)))
    packet.extend(client_id)

    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))

    return bytes(packet)


def test_parser_initialization() -> None:
    """Parser initializes with valid container info and products."""
    parser = CodeMeterProtocolParser()

    assert isinstance(parser.container_info, dict)
    assert "serial_number" in parser.container_info
    assert "firm_code" in parser.container_info
    assert "container_type" in parser.container_info
    assert "firmware_version" in parser.container_info
    assert parser.container_info["serial_number"] >= 1000000
    assert parser.container_info["serial_number"] < 10000000

    assert isinstance(parser.products, dict)
    assert len(parser.products) > 0
    assert (500001, 1) in parser.products
    assert parser.products[(500001, 1)]["name"] == "CAD_PROFESSIONAL"


def test_parse_login_request_valid_packet(parser: CodeMeterProtocolParser, sample_login_request: bytes) -> None:
    """Parser correctly extracts login request fields from valid packet."""
    request = parser.parse_request(sample_login_request)

    assert request is not None
    assert isinstance(request, CodeMeterRequest)
    assert request.command == 0x1000
    assert request.request_id == 12345
    assert request.firm_code == 500001
    assert request.product_code == 1
    assert request.feature_map == 0xFFFFFFFF
    assert request.version == "7.60.6089.500"
    assert request.client_id == "TEST_CLIENT_001"


def test_parse_challenge_request_valid_packet(parser: CodeMeterProtocolParser, sample_challenge_request: bytes) -> None:
    """Parser correctly extracts challenge request with challenge data."""
    request = parser.parse_request(sample_challenge_request)

    assert request is not None
    assert isinstance(request, CodeMeterRequest)
    assert request.command == 0x1002
    assert request.request_id == 54321
    assert request.firm_code == 500001
    assert request.product_code == 1
    assert len(request.challenge_data) == 32
    assert request.version == "7.60"
    assert request.client_id == "CLIENT_123"


def test_parse_request_invalid_magic_rejected(parser: CodeMeterProtocolParser) -> None:
    """Parser rejects packets with invalid magic signature."""
    invalid_packet = bytearray()
    invalid_packet.extend(struct.pack("<I", 0xDEADBEEF))
    invalid_packet.extend(struct.pack("<I", 0x1000))
    invalid_packet.extend(struct.pack("<I", 1))
    invalid_packet.extend(struct.pack("<I", 500001))
    invalid_packet.extend(struct.pack("<I", 1))
    invalid_packet.extend(struct.pack("<I", 0))

    request = parser.parse_request(bytes(invalid_packet))

    assert request is None


def test_parse_request_too_short_rejected(parser: CodeMeterProtocolParser) -> None:
    """Parser rejects packets shorter than minimum header size."""
    short_packet = struct.pack("<III", 0x434D4554, 0x1000, 123)

    request = parser.parse_request(short_packet)

    assert request is None


def test_parse_request_truncated_version_rejected(parser: CodeMeterProtocolParser) -> None:
    """Parser rejects packets with truncated version string."""
    packet = bytearray()
    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0x1000))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 500001))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 0))
    packet.extend(struct.pack("<H", 100))

    request = parser.parse_request(bytes(packet))

    assert request is None


def test_parse_request_truncated_client_id_rejected(parser: CodeMeterProtocolParser) -> None:
    """Parser rejects packets with truncated client ID."""
    packet = bytearray()
    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0x1000))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 500001))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 0))

    version = b"7.60"
    packet.extend(struct.pack("<H", len(version)))
    packet.extend(version)

    packet.extend(struct.pack("<H", 50))

    request = parser.parse_request(bytes(packet))

    assert request is None


def test_parse_request_with_session_context(parser: CodeMeterProtocolParser) -> None:
    """Parser correctly extracts session context key-value pairs."""
    packet = bytearray()
    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0x1000))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 500001))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 0))

    version = b"7.60"
    packet.extend(struct.pack("<H", len(version)))
    packet.extend(version)

    client_id = b"TEST"
    packet.extend(struct.pack("<H", len(client_id)))
    packet.extend(client_id)

    context_data = bytearray()
    key1 = b"session_id"
    value1 = b"abc123"
    context_data.extend(struct.pack("<H", len(key1)))
    context_data.extend(key1)
    context_data.extend(struct.pack("<H", len(value1)))
    context_data.extend(value1)

    packet.extend(struct.pack("<H", len(context_data)))
    packet.extend(context_data)

    packet.extend(struct.pack("<H", 0))

    request = parser.parse_request(bytes(packet))

    assert request is not None
    assert "session_id" in request.session_context
    assert request.session_context["session_id"] == "abc123"


def test_parse_request_with_additional_data(parser: CodeMeterProtocolParser) -> None:
    """Parser correctly extracts additional data fields."""
    packet = bytearray()
    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0x1000))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 500001))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 0))

    version = b"7.60"
    packet.extend(struct.pack("<H", len(version)))
    packet.extend(version)

    client_id = b"TEST"
    packet.extend(struct.pack("<H", len(client_id)))
    packet.extend(client_id)

    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))

    hostname_data = b"testhost.local"
    packet.extend(struct.pack("<H", 0x0001))
    packet.extend(struct.pack("<H", len(hostname_data)))
    packet.extend(hostname_data)

    process_name = b"app.exe"
    packet.extend(struct.pack("<H", 0x0002))
    packet.extend(struct.pack("<H", len(process_name)))
    packet.extend(process_name)

    process_id = struct.pack("<I", 1234)
    packet.extend(struct.pack("<H", 0x0003))
    packet.extend(struct.pack("<H", len(process_id)))
    packet.extend(process_id)

    request = parser.parse_request(bytes(packet))

    assert request is not None
    assert "hostname" in request.additional_data
    assert request.additional_data["hostname"] == "testhost.local"
    assert "process_name" in request.additional_data
    assert request.additional_data["process_name"] == "app.exe"
    assert "process_id" in request.additional_data
    assert request.additional_data["process_id"] == 1234


def test_parse_request_alternative_magic_signatures(parser: CodeMeterProtocolParser) -> None:
    """Parser accepts alternative valid magic signatures."""
    for magic in [0x434D4554, 0x57495553, 0x434D5354]:
        packet = bytearray()
        packet.extend(struct.pack("<I", magic))
        packet.extend(struct.pack("<I", 0x1000))
        packet.extend(struct.pack("<I", 1))
        packet.extend(struct.pack("<I", 500001))
        packet.extend(struct.pack("<I", 1))
        packet.extend(struct.pack("<I", 0))

        version = b"7.60"
        packet.extend(struct.pack("<H", len(version)))
        packet.extend(version)

        client_id = b"TEST"
        packet.extend(struct.pack("<H", len(client_id)))
        packet.extend(client_id)

        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))

        request = parser.parse_request(bytes(packet))

        assert request is not None
        assert request.command == 0x1000


def test_generate_login_response_valid_product(parser: CodeMeterProtocolParser, sample_login_request: bytes) -> None:
    """Parser generates successful login response for known product."""
    request = parser.parse_request(sample_login_request)
    assert request is not None

    response = parser.generate_response(request)

    assert isinstance(response, CodeMeterResponse)
    assert response.status == 0x00000000
    assert response.request_id == request.request_id
    assert response.firm_code == request.firm_code
    assert response.product_code == request.product_code
    assert "session_id" in response.license_info
    assert "features_granted" in response.license_info
    assert len(response.response_data) == 16
    assert len(response.container_info) > 0
    assert "expiry_date" in response.expiry_data


def test_generate_login_response_unknown_product(parser: CodeMeterProtocolParser) -> None:
    """Parser generates error response for unknown product."""
    packet = bytearray()
    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0x1000))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 999998))
    packet.extend(struct.pack("<I", 999))
    packet.extend(struct.pack("<I", 0))

    version = b"7.60"
    packet.extend(struct.pack("<H", len(version)))
    packet.extend(version)

    client_id = b"TEST"
    packet.extend(struct.pack("<H", len(client_id)))
    packet.extend(client_id)

    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))

    request = parser.parse_request(bytes(packet))
    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x00000006
    assert len(response.license_info) == 0
    assert len(response.response_data) == 0


def test_generate_login_response_creates_session(parser: CodeMeterProtocolParser, sample_login_request: bytes) -> None:
    """Login response creates active session in parser."""
    request = parser.parse_request(sample_login_request)
    assert request is not None

    session_count_before = len(parser.active_sessions)
    response = parser.generate_response(request)

    assert len(parser.active_sessions) == session_count_before + 1
    assert response.status == 0x00000000
    session_id = response.license_info["session_id"]
    assert session_id in parser.active_sessions
    assert "login_time" in parser.active_sessions[session_id]


def test_generate_logout_response_removes_session(parser: CodeMeterProtocolParser) -> None:
    """Logout response removes active session from parser."""
    login_packet = bytearray()
    login_packet.extend(struct.pack("<I", 0x434D4554))
    login_packet.extend(struct.pack("<I", 0x1000))
    login_packet.extend(struct.pack("<I", 1))
    login_packet.extend(struct.pack("<I", 500001))
    login_packet.extend(struct.pack("<I", 1))
    login_packet.extend(struct.pack("<I", 0))

    version = b"7.60"
    login_packet.extend(struct.pack("<H", len(version)))
    login_packet.extend(version)

    client_id = b"TEST"
    login_packet.extend(struct.pack("<H", len(client_id)))
    login_packet.extend(client_id)

    login_packet.extend(struct.pack("<H", 0))
    login_packet.extend(struct.pack("<H", 0))

    login_request = parser.parse_request(bytes(login_packet))
    assert login_request is not None
    login_response = parser.generate_response(login_request)
    session_id = login_response.license_info["session_id"]

    assert session_id in parser.active_sessions

    logout_packet = bytearray()
    logout_packet.extend(struct.pack("<I", 0x434D4554))
    logout_packet.extend(struct.pack("<I", 0x1001))
    logout_packet.extend(struct.pack("<I", 2))
    logout_packet.extend(struct.pack("<I", 500001))
    logout_packet.extend(struct.pack("<I", 1))
    logout_packet.extend(struct.pack("<I", 0))

    logout_packet.extend(struct.pack("<H", len(version)))
    logout_packet.extend(version)

    logout_packet.extend(struct.pack("<H", len(client_id)))
    logout_packet.extend(client_id)

    context_data = bytearray()
    session_key = b"session_id"
    session_value = session_id.encode()
    context_data.extend(struct.pack("<H", len(session_key)))
    context_data.extend(session_key)
    context_data.extend(struct.pack("<H", len(session_value)))
    context_data.extend(session_value)

    logout_packet.extend(struct.pack("<H", len(context_data)))
    logout_packet.extend(context_data)

    logout_packet.extend(struct.pack("<H", 0))

    logout_request = parser.parse_request(bytes(logout_packet))
    assert logout_request is not None
    logout_response = parser.generate_response(logout_request)

    assert logout_response.status == 0x00000000
    assert session_id not in parser.active_sessions


def test_generate_challenge_response_computes_valid_hash(parser: CodeMeterProtocolParser, sample_challenge_request: bytes) -> None:
    """Challenge response computes SHA256 hash of challenge data."""
    request = parser.parse_request(sample_challenge_request)
    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x00000000
    assert len(response.response_data) == 32

    expected_hash = hashlib.sha256(
        request.challenge_data + str(request.firm_code).encode() + str(request.product_code).encode(),
    ).digest()

    assert response.response_data == expected_hash


def test_generate_get_info_response_contains_runtime_info(parser: CodeMeterProtocolParser) -> None:
    """Get info response contains CodeMeter runtime information."""
    packet = bytearray()
    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0x1004))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 500001))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 0))

    version = b"7.60"
    packet.extend(struct.pack("<H", len(version)))
    packet.extend(version)

    client_id = b"TEST"
    packet.extend(struct.pack("<H", len(client_id)))
    packet.extend(client_id)

    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))

    request = parser.parse_request(bytes(packet))
    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x00000000
    assert "runtime_version" in response.license_info
    assert "api_version" in response.license_info
    assert "containers_found" in response.license_info
    assert "server_running" in response.license_info
    assert response.license_info["server_running"] is True


def test_generate_encrypt_response_encrypts_data(parser: CodeMeterProtocolParser, sample_encrypt_request: bytes) -> None:
    """Encrypt response generates encrypted data using XOR cipher."""
    request = parser.parse_request(sample_encrypt_request)
    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x00000000
    assert len(response.response_data) == len(request.challenge_data)
    assert response.response_data != request.challenge_data

    key = struct.pack("<II", request.firm_code, request.product_code)
    expected_encrypted = bytearray()
    for i, byte in enumerate(request.challenge_data):
        expected_encrypted.append(byte ^ key[i % len(key)])

    assert response.response_data == bytes(expected_encrypted)


def test_generate_decrypt_response_decrypts_data(parser: CodeMeterProtocolParser) -> None:
    """Decrypt response decrypts data using XOR cipher."""
    plaintext = b"Test data to encrypt and decrypt" * 5
    firm_code = 500001
    product_code = 1

    key = struct.pack("<II", firm_code, product_code)
    encrypted = bytearray()
    for i, byte in enumerate(plaintext):
        encrypted.append(byte ^ key[i % len(key)])

    packet = bytearray()
    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0x1007))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", firm_code))
    packet.extend(struct.pack("<I", product_code))
    packet.extend(struct.pack("<I", 0))

    version = b"7.60"
    packet.extend(struct.pack("<H", len(version)))
    packet.extend(version)

    client_id = b"TEST"
    packet.extend(struct.pack("<H", len(client_id)))
    packet.extend(client_id)

    packet.extend(struct.pack("<H", 0))

    packet.extend(struct.pack("<H", len(encrypted)))
    packet.extend(bytes(encrypted))

    request = parser.parse_request(bytes(packet))
    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x00000000
    assert response.response_data == plaintext


def test_generate_sign_response_creates_signature(parser: CodeMeterProtocolParser) -> None:
    """Sign response creates SHA256 signature of data."""
    data_to_sign = b"Important document content" * 10
    firm_code = 500001
    product_code = 1

    packet = bytearray()
    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0x1008))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", firm_code))
    packet.extend(struct.pack("<I", product_code))
    packet.extend(struct.pack("<I", 0))

    version = b"7.60"
    packet.extend(struct.pack("<H", len(version)))
    packet.extend(version)

    client_id = b"TEST"
    packet.extend(struct.pack("<H", len(client_id)))
    packet.extend(client_id)

    packet.extend(struct.pack("<H", 0))

    packet.extend(struct.pack("<H", len(data_to_sign)))
    packet.extend(data_to_sign)

    request = parser.parse_request(bytes(packet))
    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x00000000
    assert len(response.response_data) == 32
    assert "signature_algorithm" in response.license_info
    assert response.license_info["signature_algorithm"] == "SHA256"

    expected_signature = hashlib.sha256(
        data_to_sign + struct.pack("<II", firm_code, product_code),
    ).digest()

    assert response.response_data == expected_signature


def test_generate_verify_response_validates_signature(parser: CodeMeterProtocolParser) -> None:
    """Verify response validates digital signature."""
    packet = bytearray()
    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0x1009))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 500001))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 0))

    version = b"7.60"
    packet.extend(struct.pack("<H", len(version)))
    packet.extend(version)

    client_id = b"TEST"
    packet.extend(struct.pack("<H", len(client_id)))
    packet.extend(client_id)

    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))

    request = parser.parse_request(bytes(packet))
    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x00000000
    assert response.response_data == b"\x01"
    assert "verification" in response.license_info
    assert response.license_info["verification"] == "valid"


def test_generate_get_license_response_returns_product_info(parser: CodeMeterProtocolParser, sample_get_license_request: bytes) -> None:
    """Get license response returns complete product information."""
    request = parser.parse_request(sample_get_license_request)
    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x00000000
    assert "name" in response.license_info
    assert response.license_info["name"] == "CAD_PROFESSIONAL"
    assert "features" in response.license_info
    assert "max_users" in response.license_info
    assert "expiry" in response.license_info
    assert "license_type" in response.license_info
    assert "encryption_supported" in response.license_info
    assert "signing_supported" in response.license_info
    assert len(response.container_info) > 0


def test_generate_get_license_response_unknown_product_fails(parser: CodeMeterProtocolParser) -> None:
    """Get license response fails for unknown product."""
    packet = bytearray()
    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0x100A))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 888888))
    packet.extend(struct.pack("<I", 999))
    packet.extend(struct.pack("<I", 0))

    version = b"7.60"
    packet.extend(struct.pack("<H", len(version)))
    packet.extend(version)

    client_id = b"TEST"
    packet.extend(struct.pack("<H", len(client_id)))
    packet.extend(client_id)

    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))

    request = parser.parse_request(bytes(packet))
    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x00000002
    assert len(response.license_info) == 0


def test_generate_release_license_response_succeeds(parser: CodeMeterProtocolParser) -> None:
    """Release license response succeeds."""
    packet = bytearray()
    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0x100B))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 500001))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 0))

    version = b"7.60"
    packet.extend(struct.pack("<H", len(version)))
    packet.extend(version)

    client_id = b"TEST"
    packet.extend(struct.pack("<H", len(client_id)))
    packet.extend(client_id)

    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))

    request = parser.parse_request(bytes(packet))
    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x00000000
    assert "release_time" in response.license_info


def test_generate_heartbeat_response_updates_session(parser: CodeMeterProtocolParser) -> None:
    """Heartbeat response updates session timestamp."""
    login_packet = bytearray()
    login_packet.extend(struct.pack("<I", 0x434D4554))
    login_packet.extend(struct.pack("<I", 0x1000))
    login_packet.extend(struct.pack("<I", 1))
    login_packet.extend(struct.pack("<I", 500001))
    login_packet.extend(struct.pack("<I", 1))
    login_packet.extend(struct.pack("<I", 0))

    version = b"7.60"
    login_packet.extend(struct.pack("<H", len(version)))
    login_packet.extend(version)

    client_id = b"TEST"
    login_packet.extend(struct.pack("<H", len(client_id)))
    login_packet.extend(client_id)

    login_packet.extend(struct.pack("<H", 0))
    login_packet.extend(struct.pack("<H", 0))

    login_request = parser.parse_request(bytes(login_packet))
    assert login_request is not None
    login_response = parser.generate_response(login_request)
    session_id = login_response.license_info["session_id"]

    heartbeat_packet = bytearray()
    heartbeat_packet.extend(struct.pack("<I", 0x434D4554))
    heartbeat_packet.extend(struct.pack("<I", 0x100C))
    heartbeat_packet.extend(struct.pack("<I", 2))
    heartbeat_packet.extend(struct.pack("<I", 500001))
    heartbeat_packet.extend(struct.pack("<I", 1))
    heartbeat_packet.extend(struct.pack("<I", 0))

    heartbeat_packet.extend(struct.pack("<H", len(version)))
    heartbeat_packet.extend(version)

    heartbeat_packet.extend(struct.pack("<H", len(client_id)))
    heartbeat_packet.extend(client_id)

    context_data = bytearray()
    session_key = b"session_id"
    session_value = session_id.encode()
    context_data.extend(struct.pack("<H", len(session_key)))
    context_data.extend(session_key)
    context_data.extend(struct.pack("<H", len(session_value)))
    context_data.extend(session_value)

    heartbeat_packet.extend(struct.pack("<H", len(context_data)))
    heartbeat_packet.extend(context_data)

    heartbeat_packet.extend(struct.pack("<H", 0))

    heartbeat_request = parser.parse_request(bytes(heartbeat_packet))
    assert heartbeat_request is not None
    heartbeat_response = parser.generate_response(heartbeat_request)

    assert heartbeat_response.status == 0x00000000
    assert "heartbeat_time" in heartbeat_response.license_info
    assert "last_heartbeat" in parser.active_sessions[session_id]


def test_generate_get_container_info_response_returns_container_details(
    parser: CodeMeterProtocolParser, sample_get_container_info_request: bytes,
) -> None:
    """Get container info response returns container details."""
    request = parser.parse_request(sample_get_container_info_request)
    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x00000000
    assert len(response.container_info) > 0
    assert "serial_number" in response.container_info
    assert "container_type" in response.container_info
    assert "firmware_version" in response.container_info
    assert "memory_total" in response.container_info
    assert "memory_free" in response.container_info


def test_generate_enum_products_response_lists_all_products(parser: CodeMeterProtocolParser, sample_enum_products_request: bytes) -> None:
    """Enumerate products response lists all available products."""
    request = parser.parse_request(sample_enum_products_request)
    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x00000000
    assert "products" in response.license_info
    products_list = response.license_info["products"]
    assert len(products_list) > 0

    for product in products_list:
        assert "firm_code" in product
        assert "product_code" in product
        assert "name" in product
        assert "features" in product
        assert "max_users" in product


def test_generate_enum_products_response_filters_by_firm_code(parser: CodeMeterProtocolParser) -> None:
    """Enumerate products response filters by specific firm code."""
    packet = bytearray()
    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0x100E))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 500001))
    packet.extend(struct.pack("<I", 0))
    packet.extend(struct.pack("<I", 0))

    version = b"7.60"
    packet.extend(struct.pack("<H", len(version)))
    packet.extend(version)

    client_id = b"TEST"
    packet.extend(struct.pack("<H", len(client_id)))
    packet.extend(client_id)

    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))

    request = parser.parse_request(bytes(packet))
    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x00000000
    products_list = response.license_info["products"]

    for product in products_list:
        assert product["firm_code"] == 500001


def test_generate_transfer_receipt_response_creates_receipt(parser: CodeMeterProtocolParser) -> None:
    """Transfer receipt response creates and stores receipt."""
    packet = bytearray()
    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0x100F))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 500001))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 0))

    version = b"7.60"
    packet.extend(struct.pack("<H", len(version)))
    packet.extend(version)

    client_id = b"TEST_CLIENT"
    packet.extend(struct.pack("<H", len(client_id)))
    packet.extend(client_id)

    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))

    request = parser.parse_request(bytes(packet))
    assert request is not None

    receipts_before = len(parser.license_receipts)
    response = parser.generate_response(request)

    assert response.status == 0x00000000
    assert len(parser.license_receipts) == receipts_before + 1
    assert "receipt_id" in response.license_info
    receipt_id = response.license_info["receipt_id"]
    assert receipt_id in parser.license_receipts
    assert parser.license_receipts[receipt_id]["firm_code"] == 500001
    assert parser.license_receipts[receipt_id]["product_code"] == 1
    assert parser.license_receipts[receipt_id]["client_id"] == "TEST_CLIENT"


def test_generate_check_receipt_response_validates_receipt(parser: CodeMeterProtocolParser) -> None:
    """Check receipt response validates existing receipt."""
    transfer_packet = bytearray()
    transfer_packet.extend(struct.pack("<I", 0x434D4554))
    transfer_packet.extend(struct.pack("<I", 0x100F))
    transfer_packet.extend(struct.pack("<I", 1))
    transfer_packet.extend(struct.pack("<I", 500001))
    transfer_packet.extend(struct.pack("<I", 1))
    transfer_packet.extend(struct.pack("<I", 0))

    version = b"7.60"
    transfer_packet.extend(struct.pack("<H", len(version)))
    transfer_packet.extend(version)

    client_id = b"TEST"
    transfer_packet.extend(struct.pack("<H", len(client_id)))
    transfer_packet.extend(client_id)

    transfer_packet.extend(struct.pack("<H", 0))
    transfer_packet.extend(struct.pack("<H", 0))

    transfer_request = parser.parse_request(bytes(transfer_packet))
    assert transfer_request is not None
    transfer_response = parser.generate_response(transfer_request)
    receipt_id = transfer_response.license_info["receipt_id"]

    check_packet = bytearray()
    check_packet.extend(struct.pack("<I", 0x434D4554))
    check_packet.extend(struct.pack("<I", 0x1010))
    check_packet.extend(struct.pack("<I", 2))
    check_packet.extend(struct.pack("<I", 500001))
    check_packet.extend(struct.pack("<I", 1))
    check_packet.extend(struct.pack("<I", 0))

    check_packet.extend(struct.pack("<H", len(version)))
    check_packet.extend(version)

    check_packet.extend(struct.pack("<H", len(client_id)))
    check_packet.extend(client_id)

    context_data = bytearray()
    receipt_key = b"receipt_id"
    receipt_value = receipt_id.encode()
    context_data.extend(struct.pack("<H", len(receipt_key)))
    context_data.extend(receipt_key)
    context_data.extend(struct.pack("<H", len(receipt_value)))
    context_data.extend(receipt_value)

    check_packet.extend(struct.pack("<H", len(context_data)))
    check_packet.extend(context_data)

    check_packet.extend(struct.pack("<H", 0))

    check_request = parser.parse_request(bytes(check_packet))
    assert check_request is not None

    check_response = parser.generate_response(check_request)

    assert check_response.status == 0x00000000
    assert "firm_code" in check_response.license_info
    assert check_response.license_info["firm_code"] == 500001


def test_generate_check_receipt_response_fails_invalid_receipt(parser: CodeMeterProtocolParser) -> None:
    """Check receipt response fails for invalid receipt."""
    packet = bytearray()
    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0x1010))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 500001))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 0))

    version = b"7.60"
    packet.extend(struct.pack("<H", len(version)))
    packet.extend(version)

    client_id = b"TEST"
    packet.extend(struct.pack("<H", len(client_id)))
    packet.extend(client_id)

    context_data = bytearray()
    receipt_key = b"receipt_id"
    receipt_value = b"nonexistent_receipt_id"
    context_data.extend(struct.pack("<H", len(receipt_key)))
    context_data.extend(receipt_key)
    context_data.extend(struct.pack("<H", len(receipt_value)))
    context_data.extend(receipt_value)

    packet.extend(struct.pack("<H", len(context_data)))
    packet.extend(context_data)

    packet.extend(struct.pack("<H", 0))

    request = parser.parse_request(bytes(packet))
    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x00000002


def test_generate_unknown_command_response_returns_error(parser: CodeMeterProtocolParser) -> None:
    """Unknown command generates error response."""
    packet = bytearray()
    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0xFFFF))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 500001))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 0))

    version = b"7.60"
    packet.extend(struct.pack("<H", len(version)))
    packet.extend(version)

    client_id = b"TEST"
    packet.extend(struct.pack("<H", len(client_id)))
    packet.extend(client_id)

    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))

    request = parser.parse_request(bytes(packet))
    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x00000012


def test_serialize_response_creates_valid_packet(parser: CodeMeterProtocolParser, sample_login_request: bytes) -> None:
    """Serialized response creates valid CodeMeter packet."""
    request = parser.parse_request(sample_login_request)
    assert request is not None
    response = parser.generate_response(request)

    serialized = parser.serialize_response(response)

    assert len(serialized) >= 12

    magic = struct.unpack("<I", serialized[:4])[0]
    assert magic == 0x434D4554

    status = struct.unpack("<I", serialized[4:8])[0]
    assert status == response.status

    request_id = struct.unpack("<I", serialized[8:12])[0]
    assert request_id == response.request_id


def test_serialize_response_includes_all_fields(parser: CodeMeterProtocolParser) -> None:
    """Serialized response includes all response fields."""
    response = CodeMeterResponse(
        status=0x00000000,
        request_id=12345,
        firm_code=500001,
        product_code=1,
        license_info={"test_key": "test_value", "feature_count": 10},
        response_data=b"test_response_data",
        container_info={"serial_number": 1234567},
        expiry_data={"expiry_date": "31-dec-2025"},
    )

    serialized = parser.serialize_response(response)

    assert len(serialized) > 20

    offset = 0
    magic = struct.unpack("<I", serialized[offset:offset + 4])[0]
    offset += 4
    assert magic == 0x434D4554

    status = struct.unpack("<I", serialized[offset:offset + 4])[0]
    offset += 4
    assert status == 0x00000000

    request_id = struct.unpack("<I", serialized[offset:offset + 4])[0]
    offset += 4
    assert request_id == 12345

    firm_code = struct.unpack("<I", serialized[offset:offset + 4])[0]
    offset += 4
    assert firm_code == 500001

    product_code = struct.unpack("<I", serialized[offset:offset + 4])[0]
    offset += 4
    assert product_code == 1


def test_roundtrip_parse_generate_serialize(parser: CodeMeterProtocolParser, sample_login_request: bytes) -> None:
    """Full roundtrip: parse request, generate response, serialize response."""
    request = parser.parse_request(sample_login_request)
    assert request is not None

    response = parser.generate_response(request)
    assert response is not None

    serialized = parser.serialize_response(response)
    assert len(serialized) > 0

    magic = struct.unpack("<I", serialized[:4])[0]
    assert magic == 0x434D4554

    status = struct.unpack("<I", serialized[4:8])[0]
    assert status == 0x00000000


def test_parser_handles_multiple_products(parser: CodeMeterProtocolParser) -> None:
    """Parser correctly handles requests for different products."""
    products_to_test = [
        (500001, 1, "CAD_PROFESSIONAL"),
        (500001, 2, "CAD_STANDARD"),
        (500002, 1, "ENGINEERING_SUITE"),
        (500003, 1, "MEDIA_EDITOR_PRO"),
    ]

    for firm_code, product_code, expected_name in products_to_test:
        packet = bytearray()
        packet.extend(struct.pack("<I", 0x434D4554))
        packet.extend(struct.pack("<I", 0x100A))
        packet.extend(struct.pack("<I", 1))
        packet.extend(struct.pack("<I", firm_code))
        packet.extend(struct.pack("<I", product_code))
        packet.extend(struct.pack("<I", 0))

        version = b"7.60"
        packet.extend(struct.pack("<H", len(version)))
        packet.extend(version)

        client_id = b"TEST"
        packet.extend(struct.pack("<H", len(client_id)))
        packet.extend(client_id)

        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))

        request = parser.parse_request(bytes(packet))
        assert request is not None

        response = parser.generate_response(request)

        assert response.status == 0x00000000
        assert response.license_info["name"] == expected_name


def test_parser_feature_map_filtering(parser: CodeMeterProtocolParser) -> None:
    """Parser correctly filters features based on feature map."""
    packet = bytearray()
    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0x1000))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 500001))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 0x0000000F))

    version = b"7.60"
    packet.extend(struct.pack("<H", len(version)))
    packet.extend(version)

    client_id = b"TEST"
    packet.extend(struct.pack("<H", len(client_id)))
    packet.extend(client_id)

    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))

    request = parser.parse_request(bytes(packet))
    assert request is not None

    response = parser.generate_response(request)

    assert response.status == 0x00000000
    features_granted = response.license_info["features_granted"]
    assert features_granted == (0xFFFFFFFF & 0x0000000F)
    assert features_granted == 0x0000000F


def test_parser_container_info_consistency(parser: CodeMeterProtocolParser) -> None:
    """Parser returns consistent container info across requests."""
    initial_container_info = parser.container_info.copy()

    for command in [0x1004, 0x100D, 0x100A]:
        packet = bytearray()
        packet.extend(struct.pack("<I", 0x434D4554))
        packet.extend(struct.pack("<I", command))
        packet.extend(struct.pack("<I", 1))
        packet.extend(struct.pack("<I", 500001))
        packet.extend(struct.pack("<I", 1))
        packet.extend(struct.pack("<I", 0))

        version = b"7.60"
        packet.extend(struct.pack("<H", len(version)))
        packet.extend(version)

        client_id = b"TEST"
        packet.extend(struct.pack("<H", len(client_id)))
        packet.extend(client_id)

        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))

        request = parser.parse_request(bytes(packet))
        assert request is not None

        response = parser.generate_response(request)

        if len(response.container_info) > 0:
            assert response.container_info == initial_container_info


def test_parser_session_isolation(parser: CodeMeterProtocolParser) -> None:
    """Parser maintains isolated sessions for different clients."""
    sessions = []

    for i in range(3):
        packet = bytearray()
        packet.extend(struct.pack("<I", 0x434D4554))
        packet.extend(struct.pack("<I", 0x1000))
        packet.extend(struct.pack("<I", i))
        packet.extend(struct.pack("<I", 500001))
        packet.extend(struct.pack("<I", 1))
        packet.extend(struct.pack("<I", 0xFFFFFFFF))

        version = b"7.60"
        packet.extend(struct.pack("<H", len(version)))
        packet.extend(version)

        client_id = f"CLIENT_{i}".encode()
        packet.extend(struct.pack("<H", len(client_id)))
        packet.extend(client_id)

        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))

        request = parser.parse_request(bytes(packet))
        assert request is not None

        response = parser.generate_response(request)
        sessions.append(response.license_info["session_id"])

    assert len(sessions) == 3
    assert len(set(sessions)) == 3


def test_parser_command_constants_coverage(parser: CodeMeterProtocolParser) -> None:
    """Parser defines all expected CodeMeter command constants."""
    expected_commands = {
        0x1000: "CM_LOGIN",
        0x1001: "CM_LOGOUT",
        0x1002: "CM_CHALLENGE",
        0x1003: "CM_RESPONSE",
        0x1004: "CM_GET_INFO",
        0x1006: "CM_ENCRYPT",
        0x1007: "CM_DECRYPT",
        0x1008: "CM_SIGN",
        0x1009: "CM_VERIFY",
        0x100A: "CM_GET_LICENSE",
        0x100B: "CM_RELEASE_LICENSE",
        0x100C: "CM_HEARTBEAT",
        0x100D: "CM_GET_CONTAINER_INFO",
        0x100E: "CM_ENUM_PRODUCTS",
        0x100F: "CM_TRANSFER_RECEIPT",
        0x1010: "CM_CHECK_RECEIPT",
    }

    for command_code, command_name in expected_commands.items():
        assert command_code in parser.CODEMETER_COMMANDS
        assert parser.CODEMETER_COMMANDS[command_code] == command_name


def test_parser_status_codes_coverage(parser: CodeMeterProtocolParser) -> None:
    """Parser defines all expected CodeMeter status codes."""
    expected_status_codes = {
        0x00000000: "CM_GCM_OK",
        0x00000001: "CM_GCM_NO_CODEMETER",
        0x00000002: "CM_GCM_NO_LICENSE",
        0x00000006: "CM_GCM_UNKNOWN_PRODUCT_CODE",
        0x00000012: "CM_GCM_ENCRYPTION_ERROR",
    }

    for status_code, status_name in expected_status_codes.items():
        assert status_code in parser.CODEMETER_STATUS_CODES
        assert parser.CODEMETER_STATUS_CODES[status_code] == status_name


def test_encryption_decryption_symmetry(parser: CodeMeterProtocolParser) -> None:
    """Encryption and decryption are symmetric operations."""
    original_data = b"Test data for encryption symmetry" * 20
    firm_code = 500001
    product_code = 1

    encrypt_packet = bytearray()
    encrypt_packet.extend(struct.pack("<I", 0x434D4554))
    encrypt_packet.extend(struct.pack("<I", 0x1006))
    encrypt_packet.extend(struct.pack("<I", 1))
    encrypt_packet.extend(struct.pack("<I", firm_code))
    encrypt_packet.extend(struct.pack("<I", product_code))
    encrypt_packet.extend(struct.pack("<I", 0))

    version = b"7.60"
    encrypt_packet.extend(struct.pack("<H", len(version)))
    encrypt_packet.extend(version)

    client_id = b"TEST"
    encrypt_packet.extend(struct.pack("<H", len(client_id)))
    encrypt_packet.extend(client_id)

    encrypt_packet.extend(struct.pack("<H", 0))

    encrypt_packet.extend(struct.pack("<H", len(original_data)))
    encrypt_packet.extend(original_data)

    encrypt_request = parser.parse_request(bytes(encrypt_packet))
    assert encrypt_request is not None

    encrypt_response = parser.generate_response(encrypt_request)
    encrypted_data = encrypt_response.response_data

    decrypt_packet = bytearray()
    decrypt_packet.extend(struct.pack("<I", 0x434D4554))
    decrypt_packet.extend(struct.pack("<I", 0x1007))
    decrypt_packet.extend(struct.pack("<I", 2))
    decrypt_packet.extend(struct.pack("<I", firm_code))
    decrypt_packet.extend(struct.pack("<I", product_code))
    decrypt_packet.extend(struct.pack("<I", 0))

    decrypt_packet.extend(struct.pack("<H", len(version)))
    decrypt_packet.extend(version)

    decrypt_packet.extend(struct.pack("<H", len(client_id)))
    decrypt_packet.extend(client_id)

    decrypt_packet.extend(struct.pack("<H", 0))

    decrypt_packet.extend(struct.pack("<H", len(encrypted_data)))
    decrypt_packet.extend(encrypted_data)

    decrypt_request = parser.parse_request(bytes(decrypt_packet))
    assert decrypt_request is not None

    decrypt_response = parser.generate_response(decrypt_request)
    decrypted_data = decrypt_response.response_data

    assert decrypted_data == original_data


def test_parser_handles_empty_optional_fields(parser: CodeMeterProtocolParser) -> None:
    """Parser handles packets with empty optional fields."""
    packet = bytearray()
    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0x1000))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 500001))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 0))

    version = b""
    packet.extend(struct.pack("<H", len(version)))

    client_id = b""
    packet.extend(struct.pack("<H", len(client_id)))

    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))

    request = parser.parse_request(bytes(packet))

    assert request is not None
    assert request.version == ""
    assert request.client_id == ""
    assert len(request.session_context) == 0
    assert len(request.challenge_data) == 0


def test_parser_handles_large_challenge_data(parser: CodeMeterProtocolParser) -> None:
    """Parser handles large challenge data correctly."""
    large_challenge = secrets.token_bytes(8192)

    packet = bytearray()
    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0x1002))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 500001))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 0))

    version = b"7.60"
    packet.extend(struct.pack("<H", len(version)))
    packet.extend(version)

    client_id = b"TEST"
    packet.extend(struct.pack("<H", len(client_id)))
    packet.extend(client_id)

    packet.extend(struct.pack("<H", 0))

    packet.extend(struct.pack("<H", len(large_challenge)))
    packet.extend(large_challenge)

    request = parser.parse_request(bytes(packet))

    assert request is not None
    assert len(request.challenge_data) == 8192
    assert request.challenge_data == large_challenge


def test_parser_rejects_corrupted_session_context(parser: CodeMeterProtocolParser) -> None:
    """Parser handles corrupted session context gracefully."""
    packet = bytearray()
    packet.extend(struct.pack("<I", 0x434D4554))
    packet.extend(struct.pack("<I", 0x1000))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 500001))
    packet.extend(struct.pack("<I", 1))
    packet.extend(struct.pack("<I", 0))

    version = b"7.60"
    packet.extend(struct.pack("<H", len(version)))
    packet.extend(version)

    client_id = b"TEST"
    packet.extend(struct.pack("<H", len(client_id)))
    packet.extend(client_id)

    context_data = bytearray()
    context_data.extend(struct.pack("<H", 100))
    context_data.extend(b"short")

    packet.extend(struct.pack("<H", len(context_data)))
    packet.extend(context_data)

    packet.extend(struct.pack("<H", 0))

    request = parser.parse_request(bytes(packet))

    assert request is not None
    assert len(request.session_context) == 0
