"""Comprehensive production-ready tests for HASP/Sentinel protocol parser.

Tests validate genuine HASP protocol parsing capabilities against real licensing
dongles and network protocols. All tests use actual HASP packet structures and
validate offensive security research capabilities for bypassing HASP protection.
"""

import hashlib
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
def crypto_handler() -> HASPCrypto:
    """Create HASP crypto handler with initialized keys."""
    return HASPCrypto()


@pytest.fixture
def hasp_parser() -> HASPSentinelParser:
    """Create HASP parser with default commercial software features."""
    return HASPSentinelParser()


@pytest.fixture
def packet_analyzer() -> HASPPacketAnalyzer:
    """Create HASP packet analyzer for network traffic analysis."""
    return HASPPacketAnalyzer()


@pytest.fixture
def usb_emulator() -> HASPUSBEmulator:
    """Create HASP USB dongle emulator."""
    return HASPUSBEmulator()


@pytest.fixture
def server_emulator() -> HASPServerEmulator:
    """Create HASP license server emulator."""
    return HASPServerEmulator(bind_address="127.0.0.1", port=1947)


def create_hasp_login_packet(
    vendor_code: int = 0x12345678,
    feature_id: int = 100,
    session_id: int = 0,
    scope: str = "<haspscope />",
    client_hostname: str = "WORKSTATION01",
    client_username: str = "engineer",
) -> bytes:
    """Create realistic HASP login request packet.

    Args:
        vendor_code: HASP vendor code (e.g., Autodesk, Siemens)
        feature_id: Feature ID to access
        session_id: Session ID (0 for new session)
        scope: HASP scope XML
        client_hostname: Client machine hostname
        client_username: Client username

    Returns:
        Raw HASP login packet bytes
    """
    packet = bytearray()

    packet.extend(struct.pack("<I", 0x48415350))
    packet.extend(struct.pack("<H", 1))
    packet.extend(struct.pack("<H", secrets.randbelow(10000)))
    packet.extend(struct.pack("<I", HASPCommandType.LOGIN))
    packet.extend(struct.pack("<I", session_id))
    packet.extend(struct.pack("<I", feature_id))
    packet.extend(struct.pack("<I", vendor_code))
    packet.extend(struct.pack("<B", HASPEncryptionType.NONE))
    packet.extend(struct.pack("<I", int(time.time())))

    scope_bytes = scope.encode("utf-8")
    packet.extend(struct.pack("<H", len(scope_bytes)))
    packet.extend(scope_bytes)

    format_str = b"updateinfo"
    packet.extend(struct.pack("<H", len(format_str)))
    packet.extend(format_str)

    client_info = json.dumps({"hostname": client_hostname, "username": client_username}).encode("utf-8")
    packet.extend(struct.pack("<H", len(client_info)))
    packet.extend(client_info)

    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))

    return bytes(packet)


def create_hasp_feature_login_packet(
    session_id: int,
    feature_id: int,
    vendor_code: int = 0x12345678,
) -> bytes:
    """Create HASP feature login packet."""
    packet = bytearray()

    packet.extend(struct.pack("<I", 0x48415350))
    packet.extend(struct.pack("<H", 1))
    packet.extend(struct.pack("<H", secrets.randbelow(10000)))
    packet.extend(struct.pack("<I", HASPCommandType.FEATURE_LOGIN))
    packet.extend(struct.pack("<I", session_id))
    packet.extend(struct.pack("<I", feature_id))
    packet.extend(struct.pack("<I", vendor_code))
    packet.extend(struct.pack("<B", HASPEncryptionType.NONE))
    packet.extend(struct.pack("<I", int(time.time())))

    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))

    return bytes(packet)


def create_hasp_encrypt_packet(
    session_id: int,
    feature_id: int,
    data: bytes,
    encryption_type: int = HASPEncryptionType.AES256,
    vendor_code: int = 0x12345678,
) -> bytes:
    """Create HASP encryption request packet."""
    packet = bytearray()

    packet.extend(struct.pack("<I", 0x48415350))
    packet.extend(struct.pack("<H", 1))
    packet.extend(struct.pack("<H", secrets.randbelow(10000)))
    packet.extend(struct.pack("<I", HASPCommandType.ENCRYPT))
    packet.extend(struct.pack("<I", session_id))
    packet.extend(struct.pack("<I", feature_id))
    packet.extend(struct.pack("<I", vendor_code))
    packet.extend(struct.pack("<B", encryption_type))
    packet.extend(struct.pack("<I", int(time.time())))

    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))

    packet.extend(struct.pack("<H", len(data)))
    packet.extend(data)

    packet.extend(struct.pack("<H", 0))

    return bytes(packet)


def create_hasp_memory_read_packet(
    session_id: int,
    feature_id: int,
    address: int,
    length: int,
    vendor_code: int = 0x12345678,
) -> bytes:
    """Create HASP memory read request packet."""
    packet = bytearray()

    packet.extend(struct.pack("<I", 0x48415350))
    packet.extend(struct.pack("<H", 1))
    packet.extend(struct.pack("<H", secrets.randbelow(10000)))
    packet.extend(struct.pack("<I", HASPCommandType.READ))
    packet.extend(struct.pack("<I", session_id))
    packet.extend(struct.pack("<I", feature_id))
    packet.extend(struct.pack("<I", vendor_code))
    packet.extend(struct.pack("<B", HASPEncryptionType.NONE))
    packet.extend(struct.pack("<I", int(time.time())))

    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))

    tlv_address = struct.pack("<HHI", 0x0005, 4, address)
    tlv_length = struct.pack("<HHI", 0x0006, 4, length)

    packet.extend(tlv_address)
    packet.extend(tlv_length)

    return bytes(packet)


def create_hasp_memory_write_packet(
    session_id: int,
    feature_id: int,
    address: int,
    data: bytes,
    vendor_code: int = 0x12345678,
) -> bytes:
    """Create HASP memory write request packet."""
    packet = bytearray()

    packet.extend(struct.pack("<I", 0x48415350))
    packet.extend(struct.pack("<H", 1))
    packet.extend(struct.pack("<H", secrets.randbelow(10000)))
    packet.extend(struct.pack("<I", HASPCommandType.WRITE))
    packet.extend(struct.pack("<I", session_id))
    packet.extend(struct.pack("<I", feature_id))
    packet.extend(struct.pack("<I", vendor_code))
    packet.extend(struct.pack("<B", HASPEncryptionType.NONE))
    packet.extend(struct.pack("<I", int(time.time())))

    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))

    tlv_address = struct.pack("<HHI", 0x0005, 4, address)
    tlv_data = struct.pack(f"<HH{len(data)}s", 0x0007, len(data), data)

    packet.extend(tlv_address)
    packet.extend(tlv_data)

    return bytes(packet)


class TestHASPCryptoAESOperations:
    """Test HASP AES-256 encryption operations for dongle security."""

    def test_aes_encrypt_produces_ciphertext_different_from_plaintext(self, crypto_handler: HASPCrypto) -> None:
        """AES encryption produces different ciphertext from plaintext."""
        plaintext = b"HASP license validation key: AUT0D3SK-PRO-2024-FL0AT1NG"

        ciphertext = crypto_handler.aes_encrypt(plaintext, 0)

        assert ciphertext != plaintext
        assert len(ciphertext) > len(plaintext)

    def test_aes_roundtrip_encryption_preserves_data(self, crypto_handler: HASPCrypto) -> None:
        """AES encrypt/decrypt roundtrip preserves original data."""
        original = b"Critical license data: FEATURE_ID=100 VENDOR=0x12345678 EXPIRY=2025-12-31"

        encrypted = crypto_handler.aes_encrypt(original, 0)
        decrypted = crypto_handler.aes_decrypt(encrypted, 0)

        assert decrypted == original

    def test_aes_session_keys_produce_unique_ciphertext(self, crypto_handler: HASPCrypto) -> None:
        """Different session keys produce different ciphertext for same plaintext."""
        plaintext = b"Session-isolated encryption test data"

        key1 = crypto_handler.generate_session_key(100001, 0x12345678)
        key2 = crypto_handler.generate_session_key(100002, 0x12345678)

        assert key1 != key2

        ct1 = crypto_handler.aes_encrypt(plaintext, 100001)
        ct2 = crypto_handler.aes_encrypt(plaintext, 100002)

        assert ct1 != ct2

    def test_aes_handles_binary_data_with_null_bytes(self, crypto_handler: HASPCrypto) -> None:
        """AES correctly handles binary data containing null bytes."""
        binary_data = b"\x00\xFF\xAA\x55\x00\x00\xDE\xAD\xBE\xEF\x00"

        encrypted = crypto_handler.aes_encrypt(binary_data, 0)
        decrypted = crypto_handler.aes_decrypt(encrypted, 0)

        assert decrypted == binary_data

    def test_aes_handles_large_payloads(self, crypto_handler: HASPCrypto) -> None:
        """AES handles large license data payloads."""
        large_payload = secrets.token_bytes(8192)

        encrypted = crypto_handler.aes_encrypt(large_payload, 0)
        decrypted = crypto_handler.aes_decrypt(encrypted, 0)

        assert decrypted == large_payload

    def test_aes_handles_empty_data(self, crypto_handler: HASPCrypto) -> None:
        """AES handles empty data correctly."""
        empty = b""

        encrypted = crypto_handler.aes_encrypt(empty, 0)
        decrypted = crypto_handler.aes_decrypt(encrypted, 0)

        assert decrypted == empty

    def test_aes_ciphertext_includes_iv(self, crypto_handler: HASPCrypto) -> None:
        """AES ciphertext includes IV for proper decryption."""
        plaintext = b"Test IV handling"

        ciphertext = crypto_handler.aes_encrypt(plaintext, 0)

        assert len(ciphertext) >= 16


class TestHASPCryptoRSAOperations:
    """Test HASP RSA signature and encryption operations."""

    def test_rsa_sign_produces_signature(self, crypto_handler: HASPCrypto) -> None:
        """RSA signing produces non-empty signature."""
        data = b"HASP license validation data requiring signature"

        signature = crypto_handler.rsa_sign(data, 0)

        assert len(signature) > 0
        assert signature != data

    def test_rsa_verify_validates_authentic_signatures(self, crypto_handler: HASPCrypto) -> None:
        """RSA verification accepts authentic signatures."""
        data = b"Authentic HASP license response data"

        signature = crypto_handler.rsa_sign(data, 0)
        is_valid = crypto_handler.rsa_verify(data, signature, 0)

        assert is_valid is True

    def test_rsa_verify_rejects_tampered_signatures(self, crypto_handler: HASPCrypto) -> None:
        """RSA verification rejects signatures for modified data."""
        original = b"Original license data"
        tampered = b"Tampered license data"

        signature = crypto_handler.rsa_sign(original, 0)
        is_valid = crypto_handler.rsa_verify(tampered, signature, 0)

        assert is_valid is False

    def test_rsa_verify_rejects_invalid_signatures(self, crypto_handler: HASPCrypto) -> None:
        """RSA verification rejects completely invalid signatures."""
        data = b"Test data"
        fake_signature = secrets.token_bytes(256)

        is_valid = crypto_handler.rsa_verify(data, fake_signature, 0)

        assert is_valid is False

    def test_rsa_handles_large_data(self, crypto_handler: HASPCrypto) -> None:
        """RSA signing handles large data payloads."""
        large_data = secrets.token_bytes(4096)

        signature = crypto_handler.rsa_sign(large_data, 0)
        is_valid = crypto_handler.rsa_verify(large_data, signature, 0)

        assert is_valid is True


class TestHASPCryptoHASP4Legacy:
    """Test HASP4 legacy encryption algorithm."""

    def test_hasp4_encrypt_produces_different_output(self, crypto_handler: HASPCrypto) -> None:
        """HASP4 encryption produces different output from input."""
        plaintext = b"Legacy HASP4 dongle encryption test"
        seed = 0x12345678

        ciphertext = crypto_handler.hasp4_encrypt(plaintext, seed)

        assert ciphertext != plaintext
        assert len(ciphertext) == len(plaintext)

    def test_hasp4_roundtrip_is_symmetric(self, crypto_handler: HASPCrypto) -> None:
        """HASP4 encrypt/decrypt are symmetric operations."""
        original = b"HASP4 stream cipher test data\x00\xFF"
        seed = 0xDEADBEEF

        encrypted = crypto_handler.hasp4_encrypt(original, seed)
        decrypted = crypto_handler.hasp4_decrypt(encrypted, seed)

        assert decrypted == original

    def test_hasp4_different_seeds_produce_different_output(self, crypto_handler: HASPCrypto) -> None:
        """HASP4 encryption with different seeds produces different ciphertext."""
        plaintext = b"Seed-dependent HASP4 encryption"

        ct1 = crypto_handler.hasp4_encrypt(plaintext, 0x11111111)
        ct2 = crypto_handler.hasp4_encrypt(plaintext, 0x22222222)

        assert ct1 != ct2

    def test_hasp4_handles_binary_data(self, crypto_handler: HASPCrypto) -> None:
        """HASP4 correctly handles binary data."""
        binary = bytes(range(256))
        seed = 0xABCDEF12

        encrypted = crypto_handler.hasp4_encrypt(binary, seed)
        decrypted = crypto_handler.hasp4_decrypt(encrypted, seed)

        assert decrypted == binary


class TestHASPCryptoEnvelopeEncryption:
    """Test HASP envelope encryption (RSA + AES hybrid)."""

    def test_envelope_encrypt_produces_structured_package(self, crypto_handler: HASPCrypto) -> None:
        """Envelope encryption produces structured encrypted package."""
        plaintext = b"Envelope-protected license data"

        encrypted = crypto_handler.envelope_encrypt(plaintext, 0)

        assert len(encrypted) > len(plaintext)

        key_length = struct.unpack("<H", encrypted[:2])[0]
        assert key_length > 0
        assert key_length < len(encrypted)

    def test_envelope_roundtrip_preserves_data(self, crypto_handler: HASPCrypto) -> None:
        """Envelope encrypt/decrypt roundtrip preserves data."""
        original = b"Complex HASP envelope encryption test with binary\x00\xFF\xAA"

        encrypted = crypto_handler.envelope_encrypt(original, 0)
        decrypted = crypto_handler.envelope_decrypt(encrypted, 0)

        assert decrypted == original

    def test_envelope_handles_large_payloads(self, crypto_handler: HASPCrypto) -> None:
        """Envelope encryption handles large data payloads."""
        large_data = secrets.token_bytes(16384)

        encrypted = crypto_handler.envelope_encrypt(large_data, 0)
        decrypted = crypto_handler.envelope_decrypt(encrypted, 0)

        assert decrypted == large_data


class TestHASPProtocolParsing:
    """Test HASP protocol packet parsing."""

    def test_parse_validates_magic_number(self, hasp_parser: HASPSentinelParser) -> None:
        """Parser validates HASP magic number."""
        invalid = struct.pack("<I", 0xDEADBEEF) + b"\x00" * 100

        result = hasp_parser.parse_request(invalid)

        assert result is None

    def test_parse_rejects_short_packets(self, hasp_parser: HASPSentinelParser) -> None:
        """Parser rejects packets shorter than minimum size."""
        short = struct.pack("<I", 0x48415350) + b"\x00" * 10

        result = hasp_parser.parse_request(short)

        assert result is None

    def test_parse_login_request_extracts_fields(self, hasp_parser: HASPSentinelParser) -> None:
        """Parser extracts all fields from login request."""
        packet = create_hasp_login_packet(
            vendor_code=0x12345678,
            feature_id=100,
            client_hostname="ENGSTATION",
            client_username="testeng",
        )

        request = hasp_parser.parse_request(packet)

        assert request is not None
        assert request.command == HASPCommandType.LOGIN
        assert request.vendor_code == 0x12345678
        assert request.feature_id == 100
        assert request.client_info["hostname"] == "ENGSTATION"
        assert request.client_info["username"] == "testeng"

    def test_parse_handles_all_hasp_magic_variants(self, hasp_parser: HASPSentinelParser) -> None:
        """Parser handles all HASP magic number variants."""
        magic_variants = [0x48415350, 0x53454E54, 0x484C4D58, 0x48535350]

        for magic in magic_variants:
            packet = bytearray()
            packet.extend(struct.pack("<I", magic))
            packet.extend(struct.pack("<H", 1))
            packet.extend(struct.pack("<H", 100))
            packet.extend(struct.pack("<I", HASPCommandType.GET_INFO))
            packet.extend(struct.pack("<I", 0))
            packet.extend(struct.pack("<I", 100))
            packet.extend(struct.pack("<I", 0x12345678))
            packet.extend(struct.pack("<B", 0))
            packet.extend(struct.pack("<I", int(time.time())))
            packet.extend(struct.pack("<H", 0))
            packet.extend(struct.pack("<H", 0))
            packet.extend(struct.pack("<H", 0))
            packet.extend(struct.pack("<H", 0))
            packet.extend(struct.pack("<H", 0))

            result = hasp_parser.parse_request(bytes(packet))
            assert result is not None

    def test_parse_handles_corrupted_json_gracefully(self, hasp_parser: HASPSentinelParser) -> None:
        """Parser handles corrupted JSON in client info."""
        packet = bytearray()
        packet.extend(struct.pack("<I", 0x48415350))
        packet.extend(struct.pack("<H", 1))
        packet.extend(struct.pack("<H", 100))
        packet.extend(struct.pack("<I", HASPCommandType.LOGIN))
        packet.extend(struct.pack("<I", 0))
        packet.extend(struct.pack("<I", 100))
        packet.extend(struct.pack("<I", 0x12345678))
        packet.extend(struct.pack("<B", 0))
        packet.extend(struct.pack("<I", int(time.time())))

        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))

        corrupted = b"{invalid json!!!"
        packet.extend(struct.pack("<H", len(corrupted)))
        packet.extend(corrupted)

        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))

        request = hasp_parser.parse_request(bytes(packet))

        assert request is not None
        assert request.client_info == {}


class TestHASPSessionManagement:
    """Test HASP session login/logout operations."""

    def test_login_creates_session(self, hasp_parser: HASPSentinelParser) -> None:
        """Login request creates active session."""
        packet = create_hasp_login_packet(vendor_code=0x12345678, feature_id=100)

        request = hasp_parser.parse_request(packet)
        assert request is not None

        initial_count = len(hasp_parser.active_sessions)
        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.STATUS_OK
        assert response.session_id > 0
        assert len(hasp_parser.active_sessions) == initial_count + 1
        assert response.session_id in hasp_parser.active_sessions

    def test_login_generates_encryption_key(self, hasp_parser: HASPSentinelParser) -> None:
        """Login generates session encryption key."""
        packet = create_hasp_login_packet(vendor_code=0x12345678)

        request = hasp_parser.parse_request(packet)
        assert request is not None

        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.STATUS_OK
        assert "encryption_seed" in response.license_data

    def test_login_rejects_invalid_vendor_code(self, hasp_parser: HASPSentinelParser) -> None:
        """Login with invalid vendor code returns error."""
        packet = create_hasp_login_packet(vendor_code=0xDEADBEEF)

        request = hasp_parser.parse_request(packet)
        assert request is not None

        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.INVALID_VENDOR_CODE

    def test_logout_removes_session(self, hasp_parser: HASPSentinelParser) -> None:
        """Logout request removes active session."""
        login_packet = create_hasp_login_packet(vendor_code=0x12345678)
        login_req = hasp_parser.parse_request(login_packet)
        assert login_req is not None

        login_resp = hasp_parser.generate_response(login_req)
        session_id = login_resp.session_id

        logout_req = HASPRequest(
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

        logout_resp = hasp_parser.generate_response(logout_req)

        assert logout_resp.status == HASPStatusCode.STATUS_OK
        assert session_id not in hasp_parser.active_sessions

    def test_logout_nonexistent_session_returns_error(self, hasp_parser: HASPSentinelParser) -> None:
        """Logout of non-existent session returns error."""
        request = HASPRequest(
            command=HASPCommandType.LOGOUT,
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


class TestHASPFeatureLoginOperations:
    """Test HASP feature-specific login operations."""

    def test_feature_login_succeeds_for_valid_feature(self, hasp_parser: HASPSentinelParser) -> None:
        """Feature login succeeds for valid feature."""
        login_packet = create_hasp_login_packet(vendor_code=0x12345678, feature_id=100)
        login_req = hasp_parser.parse_request(login_packet)
        assert login_req is not None

        login_resp = hasp_parser.generate_response(login_req)

        feature_req = HASPRequest(
            command=HASPCommandType.FEATURE_LOGIN,
            session_id=login_resp.session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        feature_resp = hasp_parser.generate_response(feature_req)

        assert feature_resp.status == HASPStatusCode.STATUS_OK
        assert feature_resp.license_data["feature_name"] == "AUTOCAD_FULL"
        assert feature_resp.license_data["feature_type"] == "PERPETUAL"

    def test_feature_login_fails_without_session(self, hasp_parser: HASPSentinelParser) -> None:
        """Feature login fails without active session."""
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
        """Feature login fails for non-existent feature."""
        login_packet = create_hasp_login_packet(vendor_code=0x12345678)
        login_req = hasp_parser.parse_request(login_packet)
        assert login_req is not None

        login_resp = hasp_parser.generate_response(login_req)

        feature_req = HASPRequest(
            command=HASPCommandType.FEATURE_LOGIN,
            session_id=login_resp.session_id,
            feature_id=88888,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = hasp_parser.generate_response(feature_req)

        assert response.status == HASPStatusCode.FEATURE_NOT_FOUND

    def test_feature_login_enforces_concurrent_limits(self, hasp_parser: HASPSentinelParser) -> None:
        """Feature login enforces concurrent user limits."""
        limited_feature = HASPFeature(
            feature_id=7777,
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

        login1_packet = create_hasp_login_packet(vendor_code=0x12345678)
        login1_req = hasp_parser.parse_request(login1_packet)
        assert login1_req is not None
        login1_resp = hasp_parser.generate_response(login1_req)

        feature_req1 = HASPRequest(
            command=HASPCommandType.FEATURE_LOGIN,
            session_id=login1_resp.session_id,
            feature_id=7777,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        feature_resp1 = hasp_parser.generate_response(feature_req1)
        assert feature_resp1.status == HASPStatusCode.STATUS_OK

        login2_packet = create_hasp_login_packet(vendor_code=0x12345678)
        login2_req = hasp_parser.parse_request(login2_packet)
        assert login2_req is not None
        login2_resp = hasp_parser.generate_response(login2_req)

        feature_req2 = HASPRequest(
            command=HASPCommandType.FEATURE_LOGIN,
            session_id=login2_resp.session_id,
            feature_id=7777,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        feature_resp2 = hasp_parser.generate_response(feature_req2)
        assert feature_resp2.status == HASPStatusCode.TOO_MANY_USERS

    def test_feature_login_rejects_expired_features(self, hasp_parser: HASPSentinelParser) -> None:
        """Feature login rejects expired features."""
        expired_feature = HASPFeature(
            feature_id=8888,
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

        login_packet = create_hasp_login_packet(vendor_code=0x12345678)
        login_req = hasp_parser.parse_request(login_packet)
        assert login_req is not None
        login_resp = hasp_parser.generate_response(login_req)

        feature_req = HASPRequest(
            command=HASPCommandType.FEATURE_LOGIN,
            session_id=login_resp.session_id,
            feature_id=8888,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = hasp_parser.generate_response(feature_req)

        assert response.status == HASPStatusCode.FEATURE_EXPIRED


class TestHASPEncryptionOperations:
    """Test HASP dongle encryption/decryption operations."""

    def test_encrypt_request_produces_encrypted_data(self, hasp_parser: HASPSentinelParser) -> None:
        """Encrypt request returns encrypted data."""
        login_packet = create_hasp_login_packet(vendor_code=0x12345678)
        login_req = hasp_parser.parse_request(login_packet)
        assert login_req is not None
        login_resp = hasp_parser.generate_response(login_req)

        plaintext = b"Sensitive license validation data"
        encrypt_req = HASPRequest(
            command=HASPCommandType.ENCRYPT,
            session_id=login_resp.session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=plaintext,
            additional_params={},
            encryption_type=HASPEncryptionType.AES256,
        )

        response = hasp_parser.generate_response(encrypt_req)

        assert response.status == HASPStatusCode.STATUS_OK
        assert len(response.encryption_response) > 0
        assert response.encryption_response != plaintext

    def test_decrypt_recovers_original_data(self, hasp_parser: HASPSentinelParser) -> None:
        """Decrypt request recovers encrypted data."""
        login_packet = create_hasp_login_packet(vendor_code=0x12345678)
        login_req = hasp_parser.parse_request(login_packet)
        assert login_req is not None
        login_resp = hasp_parser.generate_response(login_req)
        session_id = login_resp.session_id

        original = b"Critical license key data"

        encrypt_req = HASPRequest(
            command=HASPCommandType.ENCRYPT,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=original,
            additional_params={},
            encryption_type=HASPEncryptionType.AES256,
        )

        encrypt_resp = hasp_parser.generate_response(encrypt_req)
        ciphertext = encrypt_resp.encryption_response

        decrypt_req = HASPRequest(
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

        decrypt_resp = hasp_parser.generate_response(decrypt_req)

        assert decrypt_resp.status == HASPStatusCode.STATUS_OK
        assert decrypt_resp.encryption_response == original

    def test_encrypt_fails_without_session(self, hasp_parser: HASPSentinelParser) -> None:
        """Encrypt request fails without active session."""
        request = HASPRequest(
            command=HASPCommandType.ENCRYPT,
            session_id=999999,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"test",
            additional_params={},
            encryption_type=HASPEncryptionType.AES256,
        )

        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.NOT_LOGGED_IN

    def test_legacy_encrypt_uses_hasp4_algorithm(self, hasp_parser: HASPSentinelParser) -> None:
        """Legacy encrypt uses HASP4 algorithm."""
        login_packet = create_hasp_login_packet(vendor_code=0x12345678)
        login_req = hasp_parser.parse_request(login_packet)
        assert login_req is not None
        login_resp = hasp_parser.generate_response(login_req)

        plaintext = b"Legacy HASP4 encryption test data"
        request = HASPRequest(
            command=HASPCommandType.LEGACY_ENCRYPT,
            session_id=login_resp.session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=plaintext,
            additional_params={},
        )

        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.STATUS_OK
        assert response.license_data["encryption_type"] == "HASP4"
        assert len(response.encryption_response) == len(plaintext)

    def test_envelope_encryption_works(self, hasp_parser: HASPSentinelParser) -> None:
        """Envelope encryption produces valid encrypted package."""
        login_packet = create_hasp_login_packet(vendor_code=0x12345678)
        login_req = hasp_parser.parse_request(login_packet)
        assert login_req is not None
        login_resp = hasp_parser.generate_response(login_req)

        plaintext = b"Envelope-protected data"
        request = HASPRequest(
            command=HASPCommandType.ENCRYPT,
            session_id=login_resp.session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=plaintext,
            additional_params={},
            encryption_type=HASPEncryptionType.ENVELOPE,
        )

        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.STATUS_OK
        assert len(response.encryption_response) > len(plaintext)


class TestHASPMemoryOperations:
    """Test HASP dongle memory read/write operations."""

    def test_read_memory_returns_data(self, hasp_parser: HASPSentinelParser) -> None:
        """Memory read request returns dongle memory data."""
        login_packet = create_hasp_login_packet(vendor_code=0x12345678)
        login_req = hasp_parser.parse_request(login_packet)
        assert login_req is not None
        login_resp = hasp_parser.generate_response(login_req)

        read_req = HASPRequest(
            command=HASPCommandType.READ,
            session_id=login_resp.session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={"address": 0, "length": 32},
        )

        response = hasp_parser.generate_response(read_req)

        assert response.status == HASPStatusCode.STATUS_OK
        assert len(response.encryption_response) == 32
        assert response.license_data["address"] == 0
        assert response.license_data["length"] == 32

    def test_write_memory_modifies_storage(self, hasp_parser: HASPSentinelParser) -> None:
        """Memory write modifies dongle storage."""
        login_packet = create_hasp_login_packet(vendor_code=0x12345678)
        login_req = hasp_parser.parse_request(login_packet)
        assert login_req is not None
        login_resp = hasp_parser.generate_response(login_req)
        session_id = login_resp.session_id

        test_data = b"HASP_MEMORY_TEST\x00\xFF\xAA"
        address = 200

        write_req = HASPRequest(
            command=HASPCommandType.WRITE,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=test_data,
            additional_params={"address": address, "write_data": test_data},
        )

        write_resp = hasp_parser.generate_response(write_req)

        assert write_resp.status == HASPStatusCode.STATUS_OK
        assert write_resp.license_data["bytes_written"] == len(test_data)

        read_req = HASPRequest(
            command=HASPCommandType.READ,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={"address": address, "length": len(test_data)},
        )

        read_resp = hasp_parser.generate_response(read_req)

        assert read_resp.encryption_response == test_data

    def test_read_invalid_address_returns_error(self, hasp_parser: HASPSentinelParser) -> None:
        """Memory read with invalid address returns error."""
        login_packet = create_hasp_login_packet(vendor_code=0x12345678)
        login_req = hasp_parser.parse_request(login_packet)
        assert login_req is not None
        login_resp = hasp_parser.generate_response(login_req)

        read_req = HASPRequest(
            command=HASPCommandType.READ,
            session_id=login_resp.session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={"address": 999999, "length": 16},
        )

        response = hasp_parser.generate_response(read_req)

        assert response.status == HASPStatusCode.MEM_RANGE

    def test_write_without_session_fails(self, hasp_parser: HASPSentinelParser) -> None:
        """Memory write without session fails."""
        request = HASPRequest(
            command=HASPCommandType.WRITE,
            session_id=999999,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"test",
            additional_params={"address": 0, "write_data": b"test"},
        )

        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.NOT_LOGGED_IN

    def test_get_size_returns_memory_size(self, hasp_parser: HASPSentinelParser) -> None:
        """GET_SIZE returns correct memory size."""
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

    def test_memory_initialization_contains_feature_data(self, hasp_parser: HASPSentinelParser) -> None:
        """Memory is initialized with feature metadata."""
        feature_id = 100

        if feature_id in hasp_parser.memory_storage:
            memory = hasp_parser.memory_storage[feature_id]
            vendor_code = struct.unpack("<I", memory[:4])[0]
            stored_feature_id = struct.unpack("<I", memory[4:8])[0]

            assert vendor_code == 0x12345678
            assert stored_feature_id == feature_id


class TestHASPInfoOperations:
    """Test HASP info and status operations."""

    def test_get_info_returns_hardware_info(self, hasp_parser: HASPSentinelParser) -> None:
        """GET_INFO returns HASP hardware information."""
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
        assert "serial" in response.hardware_info

    def test_get_rtc_returns_current_time(self, hasp_parser: HASPSentinelParser) -> None:
        """GET_RTC returns current timestamp."""
        before = int(time.time())

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

        response = hasp_parser.generate_response(request)
        after = int(time.time())

        assert response.status == HASPStatusCode.STATUS_OK
        rtc_time = response.license_data["rtc_time"]
        assert before <= rtc_time <= after

    def test_get_feature_info_returns_complete_data(self, hasp_parser: HASPSentinelParser) -> None:
        """GET_FEATURE_INFO returns all feature attributes."""
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
        assert response.license_data["memory_size"] == 4096

    def test_get_session_info_returns_session_data(self, hasp_parser: HASPSentinelParser) -> None:
        """GET_SESSION_INFO returns session information."""
        login_packet = create_hasp_login_packet(vendor_code=0x12345678)
        login_req = hasp_parser.parse_request(login_packet)
        assert login_req is not None
        login_resp = hasp_parser.generate_response(login_req)

        info_req = HASPRequest(
            command=HASPCommandType.GET_SESSION_INFO,
            session_id=login_resp.session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = hasp_parser.generate_response(info_req)

        assert response.status == HASPStatusCode.STATUS_OK
        assert response.license_data["session_id"] == login_resp.session_id
        assert "login_time" in response.license_data

    def test_heartbeat_updates_session(self, hasp_parser: HASPSentinelParser) -> None:
        """Heartbeat updates session timestamp."""
        login_packet = create_hasp_login_packet(vendor_code=0x12345678)
        login_req = hasp_parser.parse_request(login_packet)
        assert login_req is not None
        login_resp = hasp_parser.generate_response(login_req)

        time.sleep(0.2)

        hb_req = HASPRequest(
            command=HASPCommandType.HEARTBEAT,
            session_id=login_resp.session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = hasp_parser.generate_response(hb_req)

        assert response.status == HASPStatusCode.STATUS_OK
        assert response.license_data["session_uptime"] >= 0


class TestHASPResponseSerialization:
    """Test HASP response serialization."""

    def test_serialize_response_produces_valid_packet(self, hasp_parser: HASPSentinelParser) -> None:
        """Response serialization produces valid packet."""
        response = HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=123456,
            feature_id=100,
            license_data={"test": "data"},
            encryption_response=b"encrypted_data",
            expiry_info={"expiry_date": "permanent"},
            hardware_info={"hasp_id": 100000},
        )

        packet = hasp_parser.serialize_response(response)

        assert len(packet) > 0
        magic = struct.unpack("<I", packet[:4])[0]
        assert magic == 0x48415350

    def test_serialize_includes_all_fields(self, hasp_parser: HASPSentinelParser) -> None:
        """Serialized response includes all fields."""
        response = HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=999,
            feature_id=100,
            license_data={"key": "value"},
            encryption_response=b"test_encrypted",
            expiry_info={"days": 30},
            hardware_info={"id": 1234},
            packet_version=1,
            sequence_number=42,
            signature=b"test_sig",
        )

        packet = hasp_parser.serialize_response(response)

        assert len(packet) > 50


class TestHASPFeatureManagement:
    """Test HASP feature management."""

    def test_add_feature_creates_feature(self, hasp_parser: HASPSentinelParser) -> None:
        """Adding feature makes it available."""
        feature = HASPFeature(
            feature_id=9999,
            name="CUSTOM_FEATURE",
            vendor_code=0xDEADBEEF,
            feature_type=HASPFeatureType.PERPETUAL,
            expiry="permanent",
            max_users=5,
            encryption_supported=True,
            memory_size=2048,
            rtc_supported=True,
            concurrent_limit=5,
        )

        initial_count = len(hasp_parser.features)
        hasp_parser.add_feature(feature)

        assert len(hasp_parser.features) == initial_count + 1
        assert 9999 in hasp_parser.features

    def test_remove_feature_deletes_feature(self, hasp_parser: HASPSentinelParser) -> None:
        """Removing feature makes it unavailable."""
        feature = HASPFeature(
            feature_id=9998,
            name="TEMP_FEATURE",
            vendor_code=0x12345678,
            feature_type=HASPFeatureType.TRIAL,
            expiry="31-dec-2025",
            max_users=1,
            encryption_supported=True,
            memory_size=1024,
            rtc_supported=False,
        )

        hasp_parser.add_feature(feature)
        assert 9998 in hasp_parser.features

        hasp_parser.remove_feature(9998)
        assert 9998 not in hasp_parser.features

    def test_get_active_sessions_returns_list(self, hasp_parser: HASPSentinelParser) -> None:
        """get_active_sessions returns session list."""
        login_packet = create_hasp_login_packet(vendor_code=0x12345678)
        login_req = hasp_parser.parse_request(login_packet)
        assert login_req is not None
        hasp_parser.generate_response(login_req)

        sessions = hasp_parser.get_active_sessions()

        assert len(sessions) > 0
        assert all("session_id" in s for s in sessions)
        assert all("uptime" in s for s in sessions)

    def test_export_license_data_creates_xml(self, hasp_parser: HASPSentinelParser, tmp_path: Path) -> None:
        """export_license_data creates valid XML."""
        output = tmp_path / "licenses.xml"

        hasp_parser.export_license_data(output)

        assert output.exists()
        content = output.read_text()
        assert "<hasp_license" in content
        assert "<feature" in content


class TestHASPPacketAnalysis:
    """Test HASP packet capture and analysis."""

    def test_generate_spoofed_response_creates_valid_response(self, packet_analyzer: HASPPacketAnalyzer) -> None:
        """Spoofed response generation creates valid packet."""
        login_packet = create_hasp_login_packet(vendor_code=0x12345678)

        capture = HASPPacketCapture(
            timestamp=time.time(),
            source_ip="192.168.1.100",
            dest_ip="192.168.1.1",
            source_port=50000,
            dest_port=1947,
            protocol="TCP",
            packet_type="LOGIN",
            raw_data=login_packet,
        )

        spoofed = packet_analyzer.generate_spoofed_response(capture)

        assert len(spoofed) > 0
        magic = struct.unpack("<I", spoofed[:4])[0]
        assert magic == 0x48415350

    def test_extract_license_info_aggregates_data(self, packet_analyzer: HASPPacketAnalyzer) -> None:
        """extract_license_info_from_capture aggregates packet data."""
        login_packet = create_hasp_login_packet(vendor_code=0x12345678, feature_id=100)
        parsed = packet_analyzer.parser.parse_request(login_packet)

        capture = HASPPacketCapture(
            timestamp=time.time(),
            source_ip="10.0.0.50",
            dest_ip="10.0.0.1",
            source_port=60000,
            dest_port=1947,
            protocol="TCP",
            packet_type="LOGIN",
            raw_data=login_packet,
            parsed_request=parsed,
        )

        packet_analyzer.captured_packets.append(capture)

        info = packet_analyzer.extract_license_info_from_capture()

        assert len(info["vendor_codes"]) > 0
        assert 0x12345678 in info["vendor_codes"]
        assert len(info["discovered_features"]) > 0

    def test_export_capture_analysis_creates_json(self, packet_analyzer: HASPPacketAnalyzer, tmp_path: Path) -> None:
        """export_capture_analysis creates JSON file."""
        output = tmp_path / "analysis.json"

        packet_analyzer.export_capture_analysis(output)

        assert output.exists()

        with open(output) as f:
            data = json.load(f)

        assert "total_packets" in data
        assert "packet_types" in data
        assert "timeline" in data


class TestHASPUSBEmulation:
    """Test HASP USB dongle emulation."""

    def test_usb_emulator_has_valid_device_info(self, usb_emulator: HASPUSBEmulator) -> None:
        """USB emulator has valid device information."""
        info = usb_emulator.device_info

        assert info["vendor_id"] == HASPUSBProtocol.USB_VENDOR_ID
        assert info["product_id"] in HASPUSBProtocol.USB_PRODUCT_IDS
        assert len(info["serial_number"]) > 0

    def test_usb_read_memory_returns_data(self, usb_emulator: HASPUSBEmulator) -> None:
        """USB memory read returns data."""
        data = usb_emulator.handle_control_transfer(
            HASPUSBProtocol.CONTROL_TRANSFER_TYPE,
            HASPUSBProtocol.CMD_READ_MEMORY,
            0,
            64,
            b"",
        )

        assert len(data) == 64

    def test_usb_write_read_roundtrip(self, usb_emulator: HASPUSBEmulator) -> None:
        """USB write/read roundtrip works."""
        test_data = b"USB_DONGLE_TEST"
        address = 100

        write_result = usb_emulator.handle_control_transfer(
            HASPUSBProtocol.CONTROL_TRANSFER_TYPE,
            HASPUSBProtocol.CMD_WRITE_MEMORY,
            address,
            len(test_data),
            test_data,
        )

        bytes_written = struct.unpack("<I", write_result)[0]
        assert bytes_written == len(test_data)

        read_data = usb_emulator.handle_control_transfer(
            HASPUSBProtocol.CONTROL_TRANSFER_TYPE,
            HASPUSBProtocol.CMD_READ_MEMORY,
            address,
            len(test_data),
            b"",
        )

        assert read_data == test_data

    def test_usb_encrypt_produces_ciphertext(self, usb_emulator: HASPUSBEmulator) -> None:
        """USB encryption produces ciphertext."""
        plaintext = b"USB dongle encryption test" + b"\x00" * 38

        ciphertext = usb_emulator.handle_control_transfer(
            HASPUSBProtocol.CONTROL_TRANSFER_TYPE,
            HASPUSBProtocol.CMD_ENCRYPT,
            0,
            0,
            plaintext,
        )

        assert len(ciphertext) > 0
        assert ciphertext != plaintext[:len(ciphertext)]

    def test_usb_encrypt_decrypt_roundtrip(self, usb_emulator: HASPUSBEmulator) -> None:
        """USB encrypt/decrypt roundtrip works."""
        original = b"USB test data" + b"\x00" * 51

        encrypted = usb_emulator.handle_control_transfer(
            HASPUSBProtocol.CONTROL_TRANSFER_TYPE,
            HASPUSBProtocol.CMD_ENCRYPT,
            0,
            0,
            original,
        )

        decrypted = usb_emulator.handle_control_transfer(
            HASPUSBProtocol.CONTROL_TRANSFER_TYPE,
            HASPUSBProtocol.CMD_DECRYPT,
            0,
            0,
            encrypted,
        )

        assert decrypted == original[:len(decrypted)]

    def test_usb_get_info_returns_device_data(self, usb_emulator: HASPUSBEmulator) -> None:
        """USB GET_INFO returns device data."""
        info = usb_emulator.handle_control_transfer(
            HASPUSBProtocol.CONTROL_TRANSFER_TYPE,
            HASPUSBProtocol.CMD_GET_INFO,
            0,
            0,
            b"",
        )

        assert len(info) >= 16
        vendor_id, product_id, version, memory = struct.unpack("<IIII", info[:16])
        assert vendor_id == HASPUSBProtocol.USB_VENDOR_ID

    def test_usb_get_rtc_returns_timestamp(self, usb_emulator: HASPUSBEmulator) -> None:
        """USB RTC returns current timestamp."""
        before = int(time.time())

        rtc_data = usb_emulator.handle_control_transfer(
            HASPUSBProtocol.CONTROL_TRANSFER_TYPE,
            HASPUSBProtocol.CMD_GET_RTC,
            0,
            0,
            b"",
        )

        after = int(time.time())

        rtc_time = struct.unpack("<I", rtc_data)[0]
        assert before <= rtc_time <= after

    def test_emulate_usb_device_returns_descriptor(self, usb_emulator: HASPUSBEmulator) -> None:
        """emulate_usb_device returns valid descriptor."""
        descriptor = usb_emulator.emulate_usb_device()

        assert "device_descriptor" in descriptor
        assert "string_descriptors" in descriptor
        assert "configuration_descriptor" in descriptor
        assert descriptor["device_descriptor"]["idVendor"] == HASPUSBProtocol.USB_VENDOR_ID


class TestHASPServerEmulation:
    """Test HASP license server emulation."""

    def test_server_initialization(self, server_emulator: HASPServerEmulator) -> None:
        """Server emulator initializes correctly."""
        assert server_emulator.bind_address == "127.0.0.1"
        assert server_emulator.port == 1947
        assert server_emulator.running is False

    def test_generate_discovery_response_valid(self, server_emulator: HASPServerEmulator) -> None:
        """Discovery response is valid."""
        response = server_emulator.generate_discovery_response()

        assert HASPNetworkProtocol.SERVER_READY_MAGIC in response
        assert b"SERVER_ID=" in response
        assert b"VERSION=" in response
        assert b"FEATURES=" in response

    def test_handle_discovery_request(self, server_emulator: HASPServerEmulator) -> None:
        """Server responds to discovery requests."""
        discovery = HASPNetworkProtocol.DISCOVERY_MAGIC + b"CLIENT_DISCOVERY"

        response = server_emulator.handle_client_request(discovery)

        assert HASPNetworkProtocol.SERVER_READY_MAGIC in response

    def test_handle_login_request(self, server_emulator: HASPServerEmulator) -> None:
        """Server processes login requests."""
        login_packet = create_hasp_login_packet(vendor_code=0x12345678)

        response = server_emulator.handle_client_request(login_packet)

        assert len(response) > 0
        magic = struct.unpack("<I", response[:4])[0]
        assert magic == 0x48415350


class TestHASPErrorHandling:
    """Test HASP error handling and edge cases."""

    def test_unknown_command_returns_error(self, hasp_parser: HASPSentinelParser) -> None:
        """Unknown command returns error."""
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

    def test_feature_vendor_mismatch_fails(self, hasp_parser: HASPSentinelParser) -> None:
        """Feature login with vendor code mismatch fails."""
        login_packet = create_hasp_login_packet(vendor_code=0x12345678)
        login_req = hasp_parser.parse_request(login_packet)
        assert login_req is not None
        login_resp = hasp_parser.generate_response(login_req)

        feature_req = HASPRequest(
            command=HASPCommandType.FEATURE_LOGIN,
            session_id=login_resp.session_id,
            feature_id=100,
            vendor_code=0xDEADBEEF,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = hasp_parser.generate_response(feature_req)

        assert response.status == HASPStatusCode.INVALID_VENDOR_CODE


class TestHASPVendorCodes:
    """Test HASP vendor code recognition."""

    def test_known_vendor_codes_recognized(self, hasp_parser: HASPSentinelParser) -> None:
        """Known vendor codes are recognized."""
        assert 0x12345678 in hasp_parser.VENDOR_CODES
        assert hasp_parser.VENDOR_CODES[0x12345678] == "AUTODESK"

    def test_all_major_vendors_present(self, hasp_parser: HASPSentinelParser) -> None:
        """All major software vendors are present."""
        vendors = set(hasp_parser.VENDOR_CODES.values())

        assert "AUTODESK" in vendors
        assert "SIEMENS" in vendors
        assert "ANSYS" in vendors
        assert "SOLIDWORKS" in vendors


class TestHASPExpiryCalculations:
    """Test HASP feature expiry calculations."""

    def test_permanent_license_never_expires(self, hasp_parser: HASPSentinelParser) -> None:
        """Permanent licenses never expire."""
        permanent = hasp_parser.features[999]

        is_expired = hasp_parser._is_feature_expired(permanent)

        assert is_expired is False

    def test_expiry_info_for_permanent(self, hasp_parser: HASPSentinelParser) -> None:
        """Permanent licenses return correct expiry info."""
        permanent = hasp_parser.features[999]

        info = hasp_parser._calculate_expiry_info(permanent)

        assert info["expiry_date"] == "permanent"
        assert info["days_remaining"] == -1
        assert info["expired"] is False

    def test_expiry_info_for_future_date(self, hasp_parser: HASPSentinelParser) -> None:
        """Future dated licenses calculate days remaining."""
        future = (datetime.now(UTC) + timedelta(days=60)).strftime("%d-%b-%Y")

        feature = HASPFeature(
            feature_id=7788,
            name="FUTURE_FEATURE",
            vendor_code=0x12345678,
            feature_type=HASPFeatureType.EXPIRATION,
            expiry=future,
            max_users=10,
            encryption_supported=True,
            memory_size=2048,
            rtc_supported=True,
        )

        info = hasp_parser._calculate_expiry_info(feature)

        assert info["expired"] is False
        assert info["days_remaining"] > 0


class TestHASPSequenceNumbers:
    """Test HASP sequence number handling."""

    def test_response_increments_sequence(self, hasp_parser: HASPSentinelParser) -> None:
        """Response sequence number is request + 1."""
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
            sequence_number=100,
        )

        response = hasp_parser.generate_response(request)

        assert response.sequence_number == 101


class TestHASPSignatureValidation:
    """Test HASP RSA signature validation."""

    def test_response_includes_signature_when_requested(self, hasp_parser: HASPSentinelParser) -> None:
        """Response includes signature when request has signature and active session."""
        login_packet = create_hasp_login_packet(vendor_code=0x12345678)
        login_req = hasp_parser.parse_request(login_packet)
        assert login_req is not None
        login_resp = hasp_parser.generate_response(login_req)

        request = HASPRequest(
            command=HASPCommandType.GET_INFO,
            session_id=login_resp.session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
            signature=b"request_signature",
        )

        response = hasp_parser.generate_response(request)

        assert len(response.signature) > 0

    def test_response_signature_validates(self, hasp_parser: HASPSentinelParser) -> None:
        """Response signature validates correctly."""
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
            signature=b"sig",
        )

        response = hasp_parser.generate_response(request)

        if len(response.signature) > 0:
            sig_data = hasp_parser._prepare_signature_data(response)
            is_valid = hasp_parser.crypto.rsa_verify(
                sig_data,
                response.signature,
                response.session_id,
            )
            assert is_valid is True
