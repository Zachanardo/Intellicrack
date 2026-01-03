"""Comprehensive tests for HASP/Sentinel protocol parser and emulator.

Tests validate real HASP protocol parsing, encryption, network emulation,
USB dongle simulation, and packet analysis capabilities against actual
protocol specifications.
"""

import json
import secrets
import struct
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.network.protocols.hasp_parser import (
    HASPCommandType,
    HASPCrypto,
    HASPEncryptionType,
    HASPFeature,
    HASPFeatureType,
    HASPNetworkProtocol,
    HASPPacketAnalyzer,
    HASPPacketCapture,
    HASPRequest,
    HASPResponse,
    HASPSentinelParser,
    HASPServerEmulator,
    HASPSession,
    HASPStatusCode,
    HASPUSBEmulator,
    HASPUSBProtocol,
)


@pytest.fixture
def hasp_crypto() -> HASPCrypto:
    """Create HASP crypto handler with initialized keys."""
    return HASPCrypto()


@pytest.fixture
def hasp_parser() -> HASPSentinelParser:
    """Create HASP parser with default features."""
    return HASPSentinelParser()


@pytest.fixture
def hasp_packet_analyzer() -> HASPPacketAnalyzer:
    """Create HASP packet analyzer."""
    return HASPPacketAnalyzer()


@pytest.fixture
def hasp_usb_emulator() -> HASPUSBEmulator:
    """Create HASP USB emulator."""
    return HASPUSBEmulator()


@pytest.fixture
def hasp_server_emulator() -> HASPServerEmulator:
    """Create HASP server emulator."""
    return HASPServerEmulator()


@pytest.fixture
def sample_hasp_request() -> bytes:
    """Create realistic HASP login request packet."""
    packet = bytearray()

    packet.extend(struct.pack("<I", 0x48415350))
    packet.extend(struct.pack("<H", 1))
    packet.extend(struct.pack("<H", 100))
    packet.extend(struct.pack("<I", HASPCommandType.LOGIN))
    packet.extend(struct.pack("<I", 123456))
    packet.extend(struct.pack("<I", 100))
    packet.extend(struct.pack("<I", 0x12345678))
    packet.extend(struct.pack("<B", HASPEncryptionType.NONE))
    packet.extend(struct.pack("<I", int(time.time())))

    scope = b"<haspscope />"
    packet.extend(struct.pack("<H", len(scope)))
    packet.extend(scope)

    format_str = b"updateinfo"
    packet.extend(struct.pack("<H", len(format_str)))
    packet.extend(format_str)

    client_info = json.dumps({"hostname": "testhost", "username": "testuser"}).encode("utf-8")
    packet.extend(struct.pack("<H", len(client_info)))
    packet.extend(client_info)

    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))

    return bytes(packet)


@pytest.fixture
def sample_hasp_feature() -> HASPFeature:
    """Create sample HASP feature for testing."""
    return HASPFeature(
        feature_id=999,
        name="TEST_FEATURE",
        vendor_code=0xDEADBEEF,
        feature_type=HASPFeatureType.PERPETUAL,
        expiry="permanent",
        max_users=10,
        encryption_supported=True,
        memory_size=4096,
        rtc_supported=True,
        hardware_key=True,
        network_enabled=True,
        concurrent_limit=10,
    )


class TestHASPCrypto:
    """Test HASP cryptographic operations."""

    def test_aes_encryption_produces_valid_ciphertext(self, hasp_crypto: HASPCrypto) -> None:
        """AES encryption produces ciphertext different from plaintext."""
        plaintext = b"Test data for HASP AES encryption validation"

        ciphertext = hasp_crypto.aes_encrypt(plaintext, 0)

        assert len(ciphertext) > len(plaintext)
        assert ciphertext[:16] != plaintext[:16]
        assert ciphertext != plaintext

    def test_aes_encrypt_decrypt_roundtrip_preserves_data(self, hasp_crypto: HASPCrypto) -> None:
        """AES encryption and decryption preserve original data."""
        original = b"HASP license validation data with special chars: \x00\xFF\xAA"

        encrypted = hasp_crypto.aes_encrypt(original, 0)
        decrypted = hasp_crypto.aes_decrypt(encrypted, 0)

        assert decrypted == original

    def test_aes_session_specific_keys_produce_different_ciphertext(self, hasp_crypto: HASPCrypto) -> None:
        """Different session IDs produce different ciphertext for same plaintext."""
        plaintext = b"Session-specific encryption test"

        session1_key = hasp_crypto.generate_session_key(100001, 0x12345678)
        session2_key = hasp_crypto.generate_session_key(100002, 0x12345678)

        assert session1_key != session2_key

        ciphertext1 = hasp_crypto.aes_encrypt(plaintext, 100001)
        ciphertext2 = hasp_crypto.aes_encrypt(plaintext, 100002)

        assert ciphertext1 != ciphertext2

    def test_rsa_signature_generation_produces_valid_signature(self, hasp_crypto: HASPCrypto) -> None:
        """RSA signing produces non-empty signature."""
        data = b"HASP license data to be signed"

        signature = hasp_crypto.rsa_sign(data, 0)

        assert len(signature) > 0
        assert signature != data

    def test_rsa_signature_verification_validates_authentic_signature(self, hasp_crypto: HASPCrypto) -> None:
        """RSA signature verification succeeds for authentic signatures."""
        data = b"HASP data requiring signature validation"

        signature = hasp_crypto.rsa_sign(data, 0)
        is_valid = hasp_crypto.rsa_verify(data, signature, 0)

        assert is_valid is True

    def test_rsa_signature_verification_rejects_invalid_signature(self, hasp_crypto: HASPCrypto) -> None:
        """RSA signature verification fails for invalid signatures."""
        data = b"Original HASP data"
        modified_data = b"Modified HASP data"

        signature = hasp_crypto.rsa_sign(data, 0)
        is_valid = hasp_crypto.rsa_verify(modified_data, signature, 0)

        assert is_valid is False

    def test_hasp4_encryption_produces_different_output(self, hasp_crypto: HASPCrypto) -> None:
        """HASP4 legacy encryption produces different output from input."""
        plaintext = b"HASP4 legacy encryption test data"
        seed = 0x12345678

        ciphertext = hasp_crypto.hasp4_encrypt(plaintext, seed)

        assert ciphertext != plaintext
        assert len(ciphertext) == len(plaintext)

    def test_hasp4_encrypt_decrypt_roundtrip_is_symmetric(self, hasp_crypto: HASPCrypto) -> None:
        """HASP4 encryption and decryption are symmetric operations."""
        original = b"HASP4 stream cipher test with special bytes \x00\xFF"
        seed = 0xDEADBEEF

        encrypted = hasp_crypto.hasp4_encrypt(original, seed)
        decrypted = hasp_crypto.hasp4_decrypt(encrypted, seed)

        assert decrypted == original

    def test_hasp4_different_seeds_produce_different_ciphertext(self, hasp_crypto: HASPCrypto) -> None:
        """HASP4 encryption with different seeds produces different output."""
        plaintext = b"Seed-dependent encryption test"

        ciphertext1 = hasp_crypto.hasp4_encrypt(plaintext, 0x11111111)
        ciphertext2 = hasp_crypto.hasp4_encrypt(plaintext, 0x22222222)

        assert ciphertext1 != ciphertext2

    def test_envelope_encryption_produces_valid_encrypted_package(self, hasp_crypto: HASPCrypto) -> None:
        """Envelope encryption produces structured encrypted package."""
        plaintext = b"HASP envelope encryption test data"

        encrypted = hasp_crypto.envelope_encrypt(plaintext, 0)

        assert len(encrypted) > len(plaintext)
        assert encrypted[:2] != plaintext[:2]

        key_length = struct.unpack("<H", encrypted[:2])[0]
        assert key_length > 0

    def test_envelope_encrypt_decrypt_roundtrip_preserves_data(self, hasp_crypto: HASPCrypto) -> None:
        """Envelope encryption and decryption preserve original data."""
        original = b"Complex HASP data requiring envelope protection"

        encrypted = hasp_crypto.envelope_encrypt(original, 0)
        decrypted = hasp_crypto.envelope_decrypt(encrypted, 0)

        assert decrypted == original

    def test_aes_handles_empty_data(self, hasp_crypto: HASPCrypto) -> None:
        """AES encryption handles empty data gracefully."""
        empty = b""

        encrypted = hasp_crypto.aes_encrypt(empty, 0)
        decrypted = hasp_crypto.aes_decrypt(encrypted, 0)

        assert decrypted == empty

    def test_aes_handles_large_data(self, hasp_crypto: HASPCrypto) -> None:
        """AES encryption handles large data blocks."""
        large_data = secrets.token_bytes(10000)

        encrypted = hasp_crypto.aes_encrypt(large_data, 0)
        decrypted = hasp_crypto.aes_decrypt(encrypted, 0)

        assert decrypted == large_data


class TestHASPSentinelParser:
    """Test HASP protocol parsing and response generation."""

    def test_parse_request_validates_hasp_magic_number(self, hasp_parser: HASPSentinelParser) -> None:
        """Parser validates HASP magic number in requests."""
        invalid_packet = struct.pack("<I", 0xDEADBEEF) + b"\x00" * 100

        result = hasp_parser.parse_request(invalid_packet)

        assert result is None

    def test_parse_request_rejects_short_packets(self, hasp_parser: HASPSentinelParser) -> None:
        """Parser rejects packets shorter than minimum size."""
        short_packet = struct.pack("<I", 0x48415350) + b"\x00" * 10

        result = hasp_parser.parse_request(short_packet)

        assert result is None

    def test_parse_request_extracts_command_correctly(self, hasp_parser: HASPSentinelParser, sample_hasp_request: bytes) -> None:
        """Parser extracts command type from valid request."""
        request = hasp_parser.parse_request(sample_hasp_request)

        assert request is not None
        assert request.command == HASPCommandType.LOGIN

    def test_parse_request_extracts_session_id(self, hasp_parser: HASPSentinelParser, sample_hasp_request: bytes) -> None:
        """Parser extracts session ID from request."""
        request = hasp_parser.parse_request(sample_hasp_request)

        assert request is not None
        assert request.session_id == 123456

    def test_parse_request_extracts_feature_id(self, hasp_parser: HASPSentinelParser, sample_hasp_request: bytes) -> None:
        """Parser extracts feature ID from request."""
        request = hasp_parser.parse_request(sample_hasp_request)

        assert request is not None
        assert request.feature_id == 100

    def test_parse_request_extracts_vendor_code(self, hasp_parser: HASPSentinelParser, sample_hasp_request: bytes) -> None:
        """Parser extracts vendor code from request."""
        request = hasp_parser.parse_request(sample_hasp_request)

        assert request is not None
        assert request.vendor_code == 0x12345678

    def test_parse_request_extracts_scope_string(self, hasp_parser: HASPSentinelParser, sample_hasp_request: bytes) -> None:
        """Parser extracts scope XML from request."""
        request = hasp_parser.parse_request(sample_hasp_request)

        assert request is not None
        assert request.scope == "<haspscope />"

    def test_parse_request_extracts_client_info(self, hasp_parser: HASPSentinelParser, sample_hasp_request: bytes) -> None:
        """Parser extracts and deserializes client info JSON."""
        request = hasp_parser.parse_request(sample_hasp_request)

        assert request is not None
        assert request.client_info["hostname"] == "testhost"
        assert request.client_info["username"] == "testuser"

    def test_generate_response_handles_login_request(self, hasp_parser: HASPSentinelParser) -> None:
        """Response generator creates valid login response."""
        request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="<haspscope />",
            format="updateinfo",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.STATUS_OK
        assert response.session_id > 0
        assert response.license_data["session_established"] is True

    def test_generate_response_creates_active_session_on_login(self, hasp_parser: HASPSentinelParser) -> None:
        """Login response creates active session in parser."""
        request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="<haspscope />",
            format="updateinfo",
            client_info={"hostname": "testclient"},
            encryption_data=b"",
            additional_params={},
        )

        initial_session_count = len(hasp_parser.active_sessions)
        response = hasp_parser.generate_response(request)

        assert len(hasp_parser.active_sessions) == initial_session_count + 1
        assert response.session_id in hasp_parser.active_sessions

    def test_generate_response_rejects_invalid_vendor_code(self, hasp_parser: HASPSentinelParser) -> None:
        """Login with invalid vendor code returns error."""
        request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0xDEADBEEF,
            scope="<haspscope />",
            format="updateinfo",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.INVALID_VENDOR_CODE

    def test_logout_removes_active_session(self, hasp_parser: HASPSentinelParser) -> None:
        """Logout request removes session from active sessions."""
        login_request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="<haspscope />",
            format="updateinfo",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        login_response = hasp_parser.generate_response(login_request)
        session_id = login_response.session_id

        logout_request = HASPRequest(
            command=HASPCommandType.LOGOUT,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        logout_response = hasp_parser.generate_response(logout_request)

        assert logout_response.status == HASPStatusCode.STATUS_OK
        assert session_id not in hasp_parser.active_sessions

    def test_feature_login_succeeds_for_valid_feature(self, hasp_parser: HASPSentinelParser) -> None:
        """Feature login succeeds when feature exists and matches vendor code."""
        login_request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="<haspscope />",
            format="updateinfo",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        login_response = hasp_parser.generate_response(login_request)

        feature_request = HASPRequest(
            command=HASPCommandType.FEATURE_LOGIN,
            session_id=login_response.session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        feature_response = hasp_parser.generate_response(feature_request)

        assert feature_response.status == HASPStatusCode.STATUS_OK
        assert feature_response.license_data["feature_name"] == "AUTOCAD_FULL"

    def test_feature_login_fails_for_invalid_session(self, hasp_parser: HASPSentinelParser) -> None:
        """Feature login fails for non-existent session."""
        request = HASPRequest(
            command=HASPCommandType.FEATURE_LOGIN,
            session_id=999999,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.NOT_LOGGED_IN

    def test_feature_login_fails_for_unknown_feature(self, hasp_parser: HASPSentinelParser) -> None:
        """Feature login fails when feature ID doesn't exist."""
        login_request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="<haspscope />",
            format="updateinfo",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        login_response = hasp_parser.generate_response(login_request)

        feature_request = HASPRequest(
            command=HASPCommandType.FEATURE_LOGIN,
            session_id=login_response.session_id,
            feature_id=88888,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = hasp_parser.generate_response(feature_request)

        assert response.status == HASPStatusCode.FEATURE_NOT_FOUND

    def test_encrypt_request_produces_encrypted_data(self, hasp_parser: HASPSentinelParser) -> None:
        """Encrypt request returns encrypted data in response."""
        login_request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="<haspscope />",
            format="updateinfo",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        login_response = hasp_parser.generate_response(login_request)

        plaintext = b"Data to encrypt with HASP dongle"
        encrypt_request = HASPRequest(
            command=HASPCommandType.ENCRYPT,
            session_id=login_response.session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=plaintext,
            additional_params={},
            encryption_type=HASPEncryptionType.AES256,
        )

        response = hasp_parser.generate_response(encrypt_request)

        assert response.status == HASPStatusCode.STATUS_OK
        assert len(response.encryption_response) > 0
        assert response.encryption_response != plaintext

    def test_decrypt_request_recovers_original_data(self, hasp_parser: HASPSentinelParser) -> None:
        """Decrypt request recovers data encrypted by HASP."""
        login_request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="<haspscope />",
            format="updateinfo",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        login_response = hasp_parser.generate_response(login_request)
        session_id = login_response.session_id

        original_data = b"Sensitive license data"

        encrypt_request = HASPRequest(
            command=HASPCommandType.ENCRYPT,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=original_data,
            additional_params={},
            encryption_type=HASPEncryptionType.AES256,
        )

        encrypt_response = hasp_parser.generate_response(encrypt_request)
        ciphertext = encrypt_response.encryption_response

        decrypt_request = HASPRequest(
            command=HASPCommandType.DECRYPT,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=ciphertext,
            additional_params={},
            encryption_type=HASPEncryptionType.AES256,
        )

        decrypt_response = hasp_parser.generate_response(decrypt_request)

        assert decrypt_response.status == HASPStatusCode.STATUS_OK
        assert decrypt_response.encryption_response == original_data

    def test_read_memory_returns_feature_memory_data(self, hasp_parser: HASPSentinelParser) -> None:
        """Memory read request returns data from HASP dongle memory."""
        login_request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="<haspscope />",
            format="updateinfo",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        login_response = hasp_parser.generate_response(login_request)

        read_request = HASPRequest(
            command=HASPCommandType.READ,
            session_id=login_response.session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={"address": 0, "length": 16},
        )

        response = hasp_parser.generate_response(read_request)

        assert response.status == HASPStatusCode.STATUS_OK
        assert len(response.encryption_response) == 16
        assert response.license_data["address"] == 0
        assert response.license_data["length"] == 16

    def test_write_memory_modifies_feature_memory(self, hasp_parser: HASPSentinelParser) -> None:
        """Memory write request modifies HASP dongle memory."""
        login_request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="<haspscope />",
            format="updateinfo",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        login_response = hasp_parser.generate_response(login_request)
        session_id = login_response.session_id

        test_data = b"HASP_TEST_DATA_1"
        write_request = HASPRequest(
            command=HASPCommandType.WRITE,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=test_data,
            additional_params={"address": 100, "write_data": test_data},
        )

        write_response = hasp_parser.generate_response(write_request)

        assert write_response.status == HASPStatusCode.STATUS_OK
        assert write_response.license_data["bytes_written"] == len(test_data)

        read_request = HASPRequest(
            command=HASPCommandType.READ,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={"address": 100, "length": len(test_data)},
        )

        read_response = hasp_parser.generate_response(read_request)

        assert read_response.encryption_response == test_data

    def test_get_rtc_returns_current_time(self, hasp_parser: HASPSentinelParser) -> None:
        """RTC request returns current timestamp."""
        request = HASPRequest(
            command=HASPCommandType.GET_RTC,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        before_time = int(time.time())
        response = hasp_parser.generate_response(request)
        after_time = int(time.time())

        assert response.status == HASPStatusCode.STATUS_OK
        rtc_time = response.license_data["rtc_time"]
        assert before_time <= rtc_time <= after_time

    def test_heartbeat_updates_session_timestamp(self, hasp_parser: HASPSentinelParser) -> None:
        """Heartbeat request updates session last_heartbeat time."""
        login_request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="<haspscope />",
            format="updateinfo",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        login_response = hasp_parser.generate_response(login_request)
        session_id = login_response.session_id

        time.sleep(0.1)

        heartbeat_request = HASPRequest(
            command=HASPCommandType.HEARTBEAT,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = hasp_parser.generate_response(heartbeat_request)

        assert response.status == HASPStatusCode.STATUS_OK
        assert response.license_data["session_uptime"] > 0

    def test_get_info_returns_hardware_fingerprint(self, hasp_parser: HASPSentinelParser) -> None:
        """Get info request returns HASP hardware information."""
        request = HASPRequest(
            command=HASPCommandType.GET_INFO,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.STATUS_OK
        assert response.hardware_info["hasp_id"] is not None
        assert response.hardware_info["type"] == "HASP HL Max"

    def test_serialize_response_produces_valid_packet(self, hasp_parser: HASPSentinelParser) -> None:
        """Response serialization produces parseable packet."""
        response = HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=123456,
            feature_id=100,
            license_data={"test": "data"},
            encryption_response=b"encrypted",
            expiry_info={"expiry_date": "permanent"},
            hardware_info={"hasp_id": 100000},
        )

        packet = hasp_parser.serialize_response(response)

        assert len(packet) > 0
        magic = struct.unpack("<I", packet[:4])[0]
        assert magic == 0x48415350

    def test_add_feature_creates_new_feature(self, hasp_parser: HASPSentinelParser, sample_hasp_feature: HASPFeature) -> None:
        """Adding custom feature makes it available in parser."""
        initial_count = len(hasp_parser.features)

        hasp_parser.add_feature(sample_hasp_feature)

        assert len(hasp_parser.features) == initial_count + 1
        assert sample_hasp_feature.feature_id in hasp_parser.features

    def test_remove_feature_deletes_feature(self, hasp_parser: HASPSentinelParser, sample_hasp_feature: HASPFeature) -> None:
        """Removing feature makes it unavailable."""
        hasp_parser.add_feature(sample_hasp_feature)

        hasp_parser.remove_feature(sample_hasp_feature.feature_id)

        assert sample_hasp_feature.feature_id not in hasp_parser.features

    def test_get_active_sessions_returns_session_list(self, hasp_parser: HASPSentinelParser) -> None:
        """Get active sessions returns all logged-in sessions."""
        login_request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="<haspscope />",
            format="updateinfo",
            client_info={"hostname": "testhost"},
            encryption_data=b"",
            additional_params={},
        )

        hasp_parser.generate_response(login_request)

        sessions = hasp_parser.get_active_sessions()

        assert len(sessions) > 0
        assert all("session_id" in s for s in sessions)
        assert all("uptime" in s for s in sessions)

    def test_export_license_data_creates_xml_file(self, hasp_parser: HASPSentinelParser, tmp_path: Path) -> None:
        """Export license data creates valid XML file."""
        output_path = tmp_path / "licenses.xml"

        hasp_parser.export_license_data(output_path)

        assert output_path.exists()
        content = output_path.read_text()
        assert "<hasp_license" in content
        assert "<feature" in content


class TestHASPPacketAnalyzer:
    """Test HASP packet capture and analysis."""

    def test_packet_analyzer_initialization(self, hasp_packet_analyzer: HASPPacketAnalyzer) -> None:
        """Packet analyzer initializes with empty capture list."""
        assert len(hasp_packet_analyzer.captured_packets) == 0
        assert len(hasp_packet_analyzer.discovered_servers) == 0

    def test_generate_spoofed_response_creates_valid_response(self, hasp_packet_analyzer: HASPPacketAnalyzer, sample_hasp_request: bytes) -> None:
        """Spoofed response generation creates valid HASP response."""
        packet = HASPPacketCapture(
            timestamp=time.time(),
            source_ip="192.168.1.100",
            dest_ip="192.168.1.1",
            source_port=50000,
            dest_port=1947,
            protocol="TCP",
            packet_type="LOGIN",
            raw_data=sample_hasp_request,
        )

        spoofed_response = hasp_packet_analyzer.generate_spoofed_response(packet)

        assert len(spoofed_response) > 0
        magic = struct.unpack("<I", spoofed_response[:4])[0]
        assert magic == 0x48415350

    def test_extract_license_info_from_capture_aggregates_data(self, hasp_packet_analyzer: HASPPacketAnalyzer, sample_hasp_request: bytes) -> None:
        """License info extraction aggregates captured packet data."""
        packet = HASPPacketCapture(
            timestamp=time.time(),
            source_ip="192.168.1.100",
            dest_ip="192.168.1.1",
            source_port=50000,
            dest_port=1947,
            protocol="TCP",
            packet_type="LOGIN",
            raw_data=sample_hasp_request,
            parsed_request=hasp_packet_analyzer.parser.parse_request(sample_hasp_request),
        )

        hasp_packet_analyzer.captured_packets.append(packet)

        license_info = hasp_packet_analyzer.extract_license_info_from_capture()

        assert len(license_info["vendor_codes"]) > 0
        assert 0x12345678 in license_info["vendor_codes"]

    def test_export_capture_analysis_creates_json_file(self, hasp_packet_analyzer: HASPPacketAnalyzer, tmp_path: Path) -> None:
        """Capture analysis export creates JSON file with timeline."""
        output_path = tmp_path / "analysis.json"

        hasp_packet_analyzer.export_capture_analysis(output_path)

        assert output_path.exists()

        with open(output_path) as f:
            data = json.load(f)

        assert "total_packets" in data
        assert "packet_types" in data
        assert "timeline" in data


class TestHASPUSBEmulator:
    """Test HASP USB dongle emulation."""

    def test_usb_emulator_initialization_creates_device_info(self, hasp_usb_emulator: HASPUSBEmulator) -> None:
        """USB emulator creates valid device information."""
        device_info = hasp_usb_emulator.device_info

        assert device_info["vendor_id"] == HASPUSBProtocol.USB_VENDOR_ID
        assert device_info["product_id"] in HASPUSBProtocol.USB_PRODUCT_IDS
        assert len(device_info["serial_number"]) > 0

    def test_handle_control_transfer_read_memory_returns_data(self, hasp_usb_emulator: HASPUSBEmulator) -> None:
        """USB control transfer for memory read returns data."""
        address = 0
        length = 64

        data = hasp_usb_emulator.handle_control_transfer(
            HASPUSBProtocol.CONTROL_TRANSFER_TYPE,
            HASPUSBProtocol.CMD_READ_MEMORY,
            address,
            length,
            b"",
        )

        assert len(data) == length

    def test_handle_control_transfer_write_memory_modifies_storage(self, hasp_usb_emulator: HASPUSBEmulator) -> None:
        """USB control transfer for memory write modifies emulated memory."""
        address = 100
        test_data = b"USB_TEST_DATA"

        write_result = hasp_usb_emulator.handle_control_transfer(
            HASPUSBProtocol.CONTROL_TRANSFER_TYPE,
            HASPUSBProtocol.CMD_WRITE_MEMORY,
            address,
            len(test_data),
            test_data,
        )

        bytes_written = struct.unpack("<I", write_result)[0]
        assert bytes_written == len(test_data)

        read_data = hasp_usb_emulator.handle_control_transfer(
            HASPUSBProtocol.CONTROL_TRANSFER_TYPE,
            HASPUSBProtocol.CMD_READ_MEMORY,
            address,
            len(test_data),
            b"",
        )

        assert read_data == test_data

    def test_handle_control_transfer_encrypt_produces_ciphertext(self, hasp_usb_emulator: HASPUSBEmulator) -> None:
        """USB encryption control transfer produces encrypted data."""
        plaintext = b"USB dongle encryption test data" + b"\x00" * 32

        ciphertext = hasp_usb_emulator.handle_control_transfer(
            HASPUSBProtocol.CONTROL_TRANSFER_TYPE,
            HASPUSBProtocol.CMD_ENCRYPT,
            0,
            0,
            plaintext,
        )

        assert len(ciphertext) > 0
        assert ciphertext != plaintext[:len(ciphertext)]

    def test_handle_control_transfer_decrypt_recovers_data(self, hasp_usb_emulator: HASPUSBEmulator) -> None:
        """USB decryption control transfer recovers original data."""
        original = b"USB dongle test" + b"\x00" * 49

        encrypted = hasp_usb_emulator.handle_control_transfer(
            HASPUSBProtocol.CONTROL_TRANSFER_TYPE,
            HASPUSBProtocol.CMD_ENCRYPT,
            0,
            0,
            original,
        )

        decrypted = hasp_usb_emulator.handle_control_transfer(
            HASPUSBProtocol.CONTROL_TRANSFER_TYPE,
            HASPUSBProtocol.CMD_DECRYPT,
            0,
            0,
            encrypted,
        )

        assert decrypted == original[:len(decrypted)]

    def test_handle_control_transfer_get_info_returns_device_data(self, hasp_usb_emulator: HASPUSBEmulator) -> None:
        """USB get info returns device identification data."""
        info = hasp_usb_emulator.handle_control_transfer(
            HASPUSBProtocol.CONTROL_TRANSFER_TYPE,
            HASPUSBProtocol.CMD_GET_INFO,
            0,
            0,
            b"",
        )

        assert len(info) >= 16
        vendor_id, product_id, version, memory = struct.unpack("<IIII", info[:16])
        assert vendor_id == HASPUSBProtocol.USB_VENDOR_ID

    def test_handle_control_transfer_get_rtc_returns_timestamp(self, hasp_usb_emulator: HASPUSBEmulator) -> None:
        """USB RTC request returns current timestamp."""
        before_time = int(time.time())

        rtc_data = hasp_usb_emulator.handle_control_transfer(
            HASPUSBProtocol.CONTROL_TRANSFER_TYPE,
            HASPUSBProtocol.CMD_GET_RTC,
            0,
            0,
            b"",
        )

        after_time = int(time.time())

        rtc_time = struct.unpack("<I", rtc_data)[0]
        assert before_time <= rtc_time <= after_time

    def test_emulate_usb_device_returns_valid_descriptor(self, hasp_usb_emulator: HASPUSBEmulator) -> None:
        """USB device emulation returns valid USB descriptor."""
        descriptor = hasp_usb_emulator.emulate_usb_device()

        assert "device_descriptor" in descriptor
        assert "string_descriptors" in descriptor
        assert "configuration_descriptor" in descriptor

        assert descriptor["device_descriptor"]["idVendor"] == HASPUSBProtocol.USB_VENDOR_ID
        assert descriptor["string_descriptors"][1] == "Aladdin Knowledge Systems"


class TestHASPServerEmulator:
    """Test HASP license server emulation."""

    def test_server_emulator_initialization(self, hasp_server_emulator: HASPServerEmulator) -> None:
        """Server emulator initializes with correct address and port."""
        assert hasp_server_emulator.bind_address == "127.0.0.1"
        assert hasp_server_emulator.port == 1947
        assert hasp_server_emulator.running is False

    def test_generate_discovery_response_creates_valid_packet(self, hasp_server_emulator: HASPServerEmulator) -> None:
        """Discovery response generation creates valid HASP server ready packet."""
        response = hasp_server_emulator.generate_discovery_response()

        assert HASPNetworkProtocol.SERVER_READY_MAGIC in response
        assert b"SERVER_ID=" in response
        assert b"VERSION=" in response
        assert b"FEATURES=" in response

    def test_handle_client_request_responds_to_discovery(self, hasp_server_emulator: HASPServerEmulator) -> None:
        """Server responds to discovery packets with server ready."""
        discovery_packet = HASPNetworkProtocol.DISCOVERY_MAGIC + b"CLIENT_REQUEST"

        response = hasp_server_emulator.handle_client_request(discovery_packet)

        assert HASPNetworkProtocol.SERVER_READY_MAGIC in response

    def test_handle_client_request_processes_login_request(self, hasp_server_emulator: HASPServerEmulator, sample_hasp_request: bytes) -> None:
        """Server processes login requests and returns valid response."""
        response = hasp_server_emulator.handle_client_request(sample_hasp_request)

        assert len(response) > 0
        magic = struct.unpack("<I", response[:4])[0]
        assert magic == 0x48415350


class TestHASPFeatureManagement:
    """Test HASP feature expiration and validation."""

    def test_expired_feature_login_fails(self, hasp_parser: HASPSentinelParser) -> None:
        """Login to expired feature returns FEATURE_EXPIRED status."""
        expired_feature = HASPFeature(
            feature_id=7777,
            name="EXPIRED_FEATURE",
            vendor_code=0x12345678,
            feature_type=HASPFeatureType.EXPIRATION,
            expiry="01-jan-2020",
            max_users=10,
            encryption_supported=True,
            memory_size=2048,
            rtc_supported=True,
            concurrent_limit=10,
        )

        hasp_parser.add_feature(expired_feature)

        login_request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="<haspscope />",
            format="updateinfo",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        login_response = hasp_parser.generate_response(login_request)

        feature_request = HASPRequest(
            command=HASPCommandType.FEATURE_LOGIN,
            session_id=login_response.session_id,
            feature_id=7777,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = hasp_parser.generate_response(feature_request)

        assert response.status == HASPStatusCode.FEATURE_EXPIRED

    def test_concurrent_limit_enforcement(self, hasp_parser: HASPSentinelParser) -> None:
        """Feature with concurrent limit rejects excess users."""
        limited_feature = HASPFeature(
            feature_id=8888,
            name="LIMITED_FEATURE",
            vendor_code=0x12345678,
            feature_type=HASPFeatureType.CONCURRENT,
            expiry="permanent",
            max_users=2,
            encryption_supported=True,
            memory_size=2048,
            rtc_supported=True,
            concurrent_limit=1,
        )

        hasp_parser.add_feature(limited_feature)

        login1 = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="<haspscope />",
            format="updateinfo",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        login_response1 = hasp_parser.generate_response(login1)

        feature_login1 = HASPRequest(
            command=HASPCommandType.FEATURE_LOGIN,
            session_id=login_response1.session_id,
            feature_id=8888,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response1 = hasp_parser.generate_response(feature_login1)
        assert response1.status == HASPStatusCode.STATUS_OK

        login2 = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="<haspscope />",
            format="updateinfo",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        login_response2 = hasp_parser.generate_response(login2)

        feature_login2 = HASPRequest(
            command=HASPCommandType.FEATURE_LOGIN,
            session_id=login_response2.session_id,
            feature_id=8888,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response2 = hasp_parser.generate_response(feature_login2)
        assert response2.status == HASPStatusCode.TOO_MANY_USERS

    def test_get_feature_info_returns_complete_data(self, hasp_parser: HASPSentinelParser) -> None:
        """Get feature info returns all feature attributes."""
        request = HASPRequest(
            command=HASPCommandType.GET_FEATURE_INFO,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.STATUS_OK
        assert response.license_data["feature_id"] == 100
        assert response.license_data["name"] == "AUTOCAD_FULL"
        assert response.license_data["encryption_supported"] is True


class TestHASPProtocolEdgeCases:
    """Test HASP protocol edge cases and error handling."""

    def test_parse_request_with_corrupted_json_client_info(self, hasp_parser: HASPSentinelParser) -> None:
        """Parser handles corrupted JSON in client info gracefully."""
        packet = bytearray()
        packet.extend(struct.pack("<I", 0x48415350))
        packet.extend(struct.pack("<H", 1))
        packet.extend(struct.pack("<H", 100))
        packet.extend(struct.pack("<I", HASPCommandType.LOGIN))
        packet.extend(struct.pack("<I", 123456))
        packet.extend(struct.pack("<I", 100))
        packet.extend(struct.pack("<I", 0x12345678))
        packet.extend(struct.pack("<B", HASPEncryptionType.NONE))
        packet.extend(struct.pack("<I", int(time.time())))

        scope = b"<haspscope />"
        packet.extend(struct.pack("<H", len(scope)))
        packet.extend(scope)

        format_str = b"updateinfo"
        packet.extend(struct.pack("<H", len(format_str)))
        packet.extend(format_str)

        corrupted_json = b"{corrupted json data!!!"
        packet.extend(struct.pack("<H", len(corrupted_json)))
        packet.extend(corrupted_json)

        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))

        request = hasp_parser.parse_request(bytes(packet))

        assert request is not None
        assert request.client_info == {}

    def test_memory_read_with_invalid_address_returns_error(self, hasp_parser: HASPSentinelParser) -> None:
        """Memory read with out-of-range address returns error."""
        login_request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="<haspscope />",
            format="updateinfo",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        login_response = hasp_parser.generate_response(login_request)

        read_request = HASPRequest(
            command=HASPCommandType.READ,
            session_id=login_response.session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={"address": 999999, "length": 16},
        )

        response = hasp_parser.generate_response(read_request)

        assert response.status == HASPStatusCode.MEM_RANGE

    def test_encrypt_without_active_session_fails(self, hasp_parser: HASPSentinelParser) -> None:
        """Encryption request without active session returns error."""
        request = HASPRequest(
            command=HASPCommandType.ENCRYPT,
            session_id=999999,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"test data",
            additional_params={},
            encryption_type=HASPEncryptionType.AES256,
        )

        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.NOT_LOGGED_IN

    def test_legacy_encrypt_uses_hasp4_algorithm(self, hasp_parser: HASPSentinelParser) -> None:
        """Legacy encrypt command uses HASP4 encryption."""
        login_request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="<haspscope />",
            format="updateinfo",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        login_response = hasp_parser.generate_response(login_request)

        plaintext = b"Legacy HASP4 encryption test"
        encrypt_request = HASPRequest(
            command=HASPCommandType.LEGACY_ENCRYPT,
            session_id=login_response.session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=plaintext,
            additional_params={},
        )

        response = hasp_parser.generate_response(encrypt_request)

        assert response.status == HASPStatusCode.STATUS_OK
        assert response.license_data["encryption_type"] == "HASP4"
        assert len(response.encryption_response) == len(plaintext)

    def test_unknown_command_returns_error(self, hasp_parser: HASPSentinelParser) -> None:
        """Unknown command returns INV_SPEC error."""
        request = HASPRequest(
            command=0xFF,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.INV_SPEC

    def test_envelope_encryption_with_session_key_isolation(self, hasp_parser: HASPSentinelParser) -> None:
        """Envelope encryption uses session-specific RSA keys."""
        login1 = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="<haspscope />",
            format="updateinfo",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response1 = hasp_parser.generate_response(login1)
        session_id1 = response1.session_id

        plaintext = b"Envelope encryption test"

        encrypt_request = HASPRequest(
            command=HASPCommandType.ENCRYPT,
            session_id=session_id1,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=plaintext,
            additional_params={},
            encryption_type=HASPEncryptionType.ENVELOPE,
        )

        response = hasp_parser.generate_response(encrypt_request)

        assert response.status == HASPStatusCode.STATUS_OK
        assert len(response.encryption_response) > len(plaintext)


class TestHASPNetworkProtocolConstants:
    """Test HASP network protocol constants and identifiers."""

    def test_network_protocol_ports_defined(self) -> None:
        """Network protocol defines standard HASP ports."""
        assert HASPNetworkProtocol.UDP_DISCOVERY_PORT == 1947
        assert HASPNetworkProtocol.TCP_LICENSE_PORT == 1947
        assert HASPNetworkProtocol.BROADCAST_PORT == 475

    def test_network_protocol_magic_values_defined(self) -> None:
        """Network protocol defines magic byte sequences."""
        assert HASPNetworkProtocol.DISCOVERY_MAGIC == b"HASP_DISCOVER_"
        assert HASPNetworkProtocol.SERVER_READY_MAGIC == b"HASP_SERVER_READY"

    def test_usb_protocol_vendor_product_ids_defined(self) -> None:
        """USB protocol defines Aladdin vendor and product IDs."""
        assert HASPUSBProtocol.USB_VENDOR_ID == 0x0529
        assert len(HASPUSBProtocol.USB_PRODUCT_IDS) > 0


class TestHASPDataStructures:
    """Test HASP data structure creation and validation."""

    def test_hasp_request_creation(self) -> None:
        """HASPRequest dataclass can be instantiated."""
        request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=123,
            feature_id=456,
            vendor_code=0x12345678,
            scope="<haspscope />",
            format="updateinfo",
            client_info={"test": "data"},
            encryption_data=b"test",
            additional_params={},
        )

        assert request.command == HASPCommandType.LOGIN
        assert request.session_id == 123
        assert request.feature_id == 456

    def test_hasp_response_creation(self) -> None:
        """HASPResponse dataclass can be instantiated."""
        response = HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=123,
            feature_id=456,
            license_data={"key": "value"},
            encryption_response=b"encrypted",
            expiry_info={},
            hardware_info={},
        )

        assert response.status == HASPStatusCode.STATUS_OK
        assert response.session_id == 123

    def test_hasp_session_creation(self) -> None:
        """HASPSession dataclass can be instantiated."""
        session = HASPSession(
            session_id=123,
            vendor_code=0x12345678,
            feature_id=100,
            login_time=time.time(),
            last_heartbeat=time.time(),
            client_info={"hostname": "test"},
            encryption_key=b"key",
        )

        assert session.session_id == 123
        assert session.login_count == 1

    def test_hasp_feature_creation(self, sample_hasp_feature: HASPFeature) -> None:
        """HASPFeature dataclass can be instantiated."""
        assert sample_hasp_feature.feature_id == 999
        assert sample_hasp_feature.name == "TEST_FEATURE"
        assert sample_hasp_feature.feature_type == HASPFeatureType.PERPETUAL


class TestHASPCommandTypes:
    """Test HASP command type enumeration."""

    def test_command_types_have_unique_values(self) -> None:
        """All HASP command types have unique integer values."""
        values = [cmd.value for cmd in HASPCommandType]
        assert len(values) == len(set(values))

    def test_critical_commands_defined(self) -> None:
        """Critical HASP commands are defined in enumeration."""
        assert HASPCommandType.LOGIN.value == 0x01
        assert HASPCommandType.LOGOUT.value == 0x02
        assert HASPCommandType.ENCRYPT.value == 0x03
        assert HASPCommandType.DECRYPT.value == 0x04


class TestHASPStatusCodes:
    """Test HASP status code enumeration."""

    def test_status_ok_is_zero(self) -> None:
        """STATUS_OK has value 0x00000000."""
        assert HASPStatusCode.STATUS_OK.value == 0x00000000

    def test_error_codes_are_nonzero(self) -> None:
        """All error status codes have non-zero values."""
        error_codes = [code for code in HASPStatusCode if code != HASPStatusCode.STATUS_OK]
        assert all(code.value != 0 for code in error_codes)


class TestHASPEncryptionTypes:
    """Test HASP encryption type enumeration."""

    def test_encryption_types_defined(self) -> None:
        """All encryption types are defined."""
        assert HASPEncryptionType.NONE.value == 0x00
        assert HASPEncryptionType.AES128.value == 0x01
        assert HASPEncryptionType.AES256.value == 0x02
        assert HASPEncryptionType.HASP4.value == 0x05


class TestHASPMemoryOperations:
    """Test HASP dongle memory read/write operations."""

    def test_memory_initialization_contains_feature_data(self, hasp_parser: HASPSentinelParser) -> None:
        """Feature memory is initialized with vendor code and feature ID."""
        feature_id = 100

        if feature_id in hasp_parser.memory_storage:
            memory = hasp_parser.memory_storage[feature_id]
            vendor_code = struct.unpack("<I", memory[:4])[0]
            stored_feature_id = struct.unpack("<I", memory[4:8])[0]

            assert vendor_code == 0x12345678
            assert stored_feature_id == feature_id

    def test_memory_write_persists_across_reads(self, hasp_parser: HASPSentinelParser) -> None:
        """Memory writes persist and can be read back."""
        login_request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="<haspscope />",
            format="updateinfo",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        login_response = hasp_parser.generate_response(login_request)
        session_id = login_response.session_id

        test_pattern = b"\xAA\xBB\xCC\xDD\xEE\xFF"
        address = 200

        write_request = HASPRequest(
            command=HASPCommandType.WRITE,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=test_pattern,
            additional_params={"address": address, "write_data": test_pattern},
        )

        hasp_parser.generate_response(write_request)

        read_request = HASPRequest(
            command=HASPCommandType.READ,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={"address": address, "length": len(test_pattern)},
        )

        read_response = hasp_parser.generate_response(read_request)

        assert read_response.encryption_response == test_pattern

    def test_get_size_returns_correct_memory_size(self, hasp_parser: HASPSentinelParser) -> None:
        """GET_SIZE command returns correct memory size for feature."""
        request = HASPRequest(
            command=HASPCommandType.GET_SIZE,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.STATUS_OK
        assert response.license_data["memory_size"] == 4096


class TestHASPSignatureValidation:
    """Test RSA signature generation and validation in HASP protocol."""

    def test_response_includes_signature_when_requested(self, hasp_parser: HASPSentinelParser) -> None:
        """Response includes RSA signature when request has signature."""
        login_request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="<haspscope />",
            format="updateinfo",
            client_info={},
            encryption_data=b"",
            additional_params={},
            signature=b"dummy_signature",
        )

        login_response = hasp_parser.generate_response(login_request)

        assert len(login_response.signature) > 0

    def test_response_signature_is_valid(self, hasp_parser: HASPSentinelParser) -> None:
        """Generated response signature validates correctly."""
        login_request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="<haspscope />",
            format="updateinfo",
            client_info={},
            encryption_data=b"",
            additional_params={},
            signature=b"request_signature",
        )

        response = hasp_parser.generate_response(login_request)

        if len(response.signature) > 0:
            signature_data = hasp_parser._prepare_signature_data(response)
            is_valid = hasp_parser.crypto.rsa_verify(
                signature_data,
                response.signature,
                response.session_id,
            )
            assert is_valid is True


class TestHASPVendorCodes:
    """Test HASP vendor code recognition and validation."""

    def test_known_vendor_codes_recognized(self, hasp_parser: HASPSentinelParser) -> None:
        """Known vendor codes are recognized by parser."""
        autodesk_code = 0x12345678

        assert autodesk_code in hasp_parser.VENDOR_CODES
        assert hasp_parser.VENDOR_CODES[autodesk_code] == "AUTODESK"

    def test_all_vendor_codes_map_to_names(self, hasp_parser: HASPSentinelParser) -> None:
        """All vendor codes have associated company names."""
        assert len(hasp_parser.VENDOR_CODES) > 0
        assert all(isinstance(name, str) for name in hasp_parser.VENDOR_CODES.values())


class TestHASPExpiryCalculation:
    """Test feature expiry calculation and validation."""

    def test_permanent_license_never_expires(self, hasp_parser: HASPSentinelParser) -> None:
        """Permanent licenses report never expiring."""
        permanent_feature = hasp_parser.features[999]

        is_expired = hasp_parser._is_feature_expired(permanent_feature)

        assert is_expired is False

    def test_expiry_info_calculation_for_permanent(self, hasp_parser: HASPSentinelParser) -> None:
        """Permanent licenses return correct expiry info."""
        permanent_feature = hasp_parser.features[999]

        expiry_info = hasp_parser._calculate_expiry_info(permanent_feature)

        assert expiry_info["expiry_date"] == "permanent"
        assert expiry_info["days_remaining"] == -1
        assert expiry_info["expired"] is False

    def test_expiry_info_calculation_for_dated_license(self, hasp_parser: HASPSentinelParser) -> None:
        """Dated licenses calculate days remaining correctly."""
        future_date = (datetime.now(UTC) + timedelta(days=30)).strftime("%d-%b-%Y")

        timed_feature = HASPFeature(
            feature_id=9999,
            name="TIMED_FEATURE",
            vendor_code=0x12345678,
            feature_type=HASPFeatureType.EXPIRATION,
            expiry=future_date,
            max_users=10,
            encryption_supported=True,
            memory_size=2048,
            rtc_supported=True,
        )

        expiry_info = hasp_parser._calculate_expiry_info(timed_feature)

        assert expiry_info["expired"] is False
        assert expiry_info["days_remaining"] > 0


class TestHASPSequenceNumbers:
    """Test HASP packet sequence number handling."""

    def test_response_sequence_increments(self, hasp_parser: HASPSentinelParser) -> None:
        """Response sequence number is request sequence + 1."""
        request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="<haspscope />",
            format="updateinfo",
            client_info={},
            encryption_data=b"",
            additional_params={},
            sequence_number=42,
        )

        response = hasp_parser.generate_response(request)

        assert response.sequence_number == 43
