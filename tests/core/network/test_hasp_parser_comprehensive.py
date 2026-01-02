"""Comprehensive production tests for HASP/Sentinel license protocol parser.

Tests validate actual HASP protocol parsing, encryption, and license server emulation
against real packet structures and edge cases.
"""

from __future__ import annotations

import json
import secrets
import struct
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.network.protocols.hasp_parser import (
    HASPCommandType,
    HASPCrypto,
    HASPEncryptionType,
    HASPFeature,
    HASPFeatureType,
    HASPNetworkProtocol,
    HASPPacketAnalyzer,
    HASPRequest,
    HASPResponse,
    HASPSentinelParser,
    HASPServerEmulator,
    HASPStatusCode,
    HASPUSBEmulator,
    HASPUSBProtocol,
)


if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def hasp_parser() -> HASPSentinelParser:
    """Create HASP parser instance."""
    return HASPSentinelParser()


@pytest.fixture
def hasp_crypto() -> HASPCrypto:
    """Create HASP crypto handler instance."""
    return HASPCrypto()


@pytest.fixture
def hasp_usb_emulator() -> HASPUSBEmulator:
    """Create HASP USB emulator instance."""
    return HASPUSBEmulator()


@pytest.fixture
def hasp_server_emulator() -> Iterator[HASPServerEmulator]:
    """Create HASP server emulator instance."""
    server = HASPServerEmulator(bind_address="127.0.0.1", port=19470)
    yield server
    if server.running:
        server.stop_server()


@pytest.fixture
def sample_login_packet() -> bytes:
    """Create realistic HASP login packet."""
    packet = bytearray()

    packet.extend(struct.pack("<I", 0x48415350))
    packet.extend(struct.pack("<H", 1))
    packet.extend(struct.pack("<H", 1))
    packet.extend(struct.pack("<I", HASPCommandType.LOGIN))
    packet.extend(struct.pack("<I", 0))
    packet.extend(struct.pack("<I", 100))
    packet.extend(struct.pack("<I", 0x12345678))
    packet.extend(struct.pack("<B", HASPEncryptionType.NONE))
    packet.extend(struct.pack("<I", int(time.time())))

    scope = b""
    packet.extend(struct.pack("<H", len(scope)))
    packet.extend(scope)

    format_str = b"json"
    packet.extend(struct.pack("<H", len(format_str)))
    packet.extend(format_str)

    client_info = json.dumps({"hostname": "TEST_CLIENT", "username": "test_user"}).encode("utf-8")
    packet.extend(struct.pack("<H", len(client_info)))
    packet.extend(client_info)

    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))

    return bytes(packet)


@pytest.fixture
def sample_feature_login_packet() -> bytes:
    """Create realistic HASP feature login packet."""
    packet = bytearray()

    packet.extend(struct.pack("<I", 0x48415350))
    packet.extend(struct.pack("<H", 1))
    packet.extend(struct.pack("<H", 2))
    packet.extend(struct.pack("<I", HASPCommandType.FEATURE_LOGIN))
    packet.extend(struct.pack("<I", 123456))
    packet.extend(struct.pack("<I", 100))
    packet.extend(struct.pack("<I", 0x12345678))
    packet.extend(struct.pack("<B", HASPEncryptionType.NONE))
    packet.extend(struct.pack("<I", int(time.time())))

    scope = b""
    packet.extend(struct.pack("<H", len(scope)))

    format_str = b"json"
    packet.extend(struct.pack("<H", len(format_str)))
    packet.extend(format_str)

    client_info = b"{}"
    packet.extend(struct.pack("<H", len(client_info)))
    packet.extend(client_info)

    packet.extend(struct.pack("<H", 0))
    packet.extend(struct.pack("<H", 0))

    return bytes(packet)


class TestHASPCrypto:
    """Test HASP cryptographic operations."""

    def test_aes_encryption_decryption_roundtrip(self, hasp_crypto: HASPCrypto) -> None:
        """AES encryption/decryption produces original plaintext."""
        plaintext = b"This is a test message for HASP AES encryption"
        session_id = 12345

        hasp_crypto.generate_session_key(session_id, 0x12345678)

        encrypted = hasp_crypto.aes_encrypt(plaintext, session_id)

        assert len(encrypted) > len(plaintext)
        assert encrypted[:16] != plaintext[:16]

        decrypted = hasp_crypto.aes_decrypt(encrypted, session_id)

        assert decrypted == plaintext

    def test_aes_different_sessions_produce_different_ciphertext(self, hasp_crypto: HASPCrypto) -> None:
        """Different sessions produce different ciphertexts for same plaintext."""
        plaintext = b"Test message"
        session_id_1 = 1000
        session_id_2 = 2000

        hasp_crypto.generate_session_key(session_id_1, 0x12345678)
        hasp_crypto.generate_session_key(session_id_2, 0x12345678)

        encrypted_1 = hasp_crypto.aes_encrypt(plaintext, session_id_1)
        encrypted_2 = hasp_crypto.aes_encrypt(plaintext, session_id_2)

        assert encrypted_1 != encrypted_2

        decrypted_1 = hasp_crypto.aes_decrypt(encrypted_1, session_id_1)
        decrypted_2 = hasp_crypto.aes_decrypt(encrypted_2, session_id_2)

        assert decrypted_1 == plaintext
        assert decrypted_2 == plaintext

    def test_hasp4_legacy_encryption_roundtrip(self, hasp_crypto: HASPCrypto) -> None:
        """HASP4 legacy encryption/decryption works correctly."""
        plaintext = b"HASP4 legacy test data"
        seed = 0x12345678

        encrypted = hasp_crypto.hasp4_encrypt(plaintext, seed)

        assert len(encrypted) == len(plaintext)
        assert encrypted != plaintext

        decrypted = hasp_crypto.hasp4_decrypt(encrypted, seed)

        assert decrypted == plaintext

    def test_hasp4_different_seeds_produce_different_output(self, hasp_crypto: HASPCrypto) -> None:
        """Different HASP4 seeds produce different output."""
        plaintext = b"Test data"
        seed_1 = 0x11111111
        seed_2 = 0x22222222

        encrypted_1 = hasp_crypto.hasp4_encrypt(plaintext, seed_1)
        encrypted_2 = hasp_crypto.hasp4_encrypt(plaintext, seed_2)

        assert encrypted_1 != encrypted_2

        assert hasp_crypto.hasp4_decrypt(encrypted_1, seed_1) == plaintext
        assert hasp_crypto.hasp4_decrypt(encrypted_2, seed_2) == plaintext

    def test_rsa_signature_verification(self, hasp_crypto: HASPCrypto) -> None:
        """RSA signature creation and verification works."""
        message = b"Important HASP license message"
        session_id = 0

        signature = hasp_crypto.rsa_sign(message, session_id)

        assert len(signature) > 0

        is_valid = hasp_crypto.rsa_verify(message, signature, session_id)

        assert is_valid is True

    def test_rsa_signature_detects_tampering(self, hasp_crypto: HASPCrypto) -> None:
        """RSA signature verification detects message tampering."""
        message = b"Original message"
        tampered_message = b"Tampered message"
        session_id = 0

        signature = hasp_crypto.rsa_sign(message, session_id)

        is_valid_original = hasp_crypto.rsa_verify(message, signature, session_id)
        assert is_valid_original is True

        is_valid_tampered = hasp_crypto.rsa_verify(tampered_message, signature, session_id)
        assert is_valid_tampered is False

    def test_envelope_encryption_decryption_roundtrip(self, hasp_crypto: HASPCrypto) -> None:
        """Envelope encryption (RSA + AES) works correctly."""
        plaintext = b"Envelope encrypted data for HASP"
        session_id = 0

        encrypted = hasp_crypto.envelope_encrypt(plaintext, session_id)

        assert len(encrypted) > len(plaintext)

        decrypted = hasp_crypto.envelope_decrypt(encrypted, session_id)

        assert decrypted == plaintext

    def test_aes_handles_empty_data(self, hasp_crypto: HASPCrypto) -> None:
        """AES encryption handles empty data."""
        plaintext = b""
        session_id = 0

        encrypted = hasp_crypto.aes_encrypt(plaintext, session_id)
        decrypted = hasp_crypto.aes_decrypt(encrypted, session_id)

        assert decrypted == plaintext

    def test_aes_handles_large_data(self, hasp_crypto: HASPCrypto) -> None:
        """AES encryption handles large data blocks."""
        plaintext = secrets.token_bytes(10000)
        session_id = 0

        hasp_crypto.generate_session_key(session_id, 0x12345678)

        encrypted = hasp_crypto.aes_encrypt(plaintext, session_id)
        decrypted = hasp_crypto.aes_decrypt(encrypted, session_id)

        assert decrypted == plaintext


class TestHASPSentinelParser:
    """Test HASP/Sentinel protocol parser."""

    def test_parse_valid_login_request(self, hasp_parser: HASPSentinelParser, sample_login_packet: bytes) -> None:
        """Parser correctly parses valid login request packet."""
        request = hasp_parser.parse_request(sample_login_packet)

        assert request is not None
        assert request.command == HASPCommandType.LOGIN
        assert request.feature_id == 100
        assert request.vendor_code == 0x12345678
        assert "hostname" in request.client_info
        assert request.client_info["hostname"] == "TEST_CLIENT"

    def test_parse_invalid_magic_number(self, hasp_parser: HASPSentinelParser) -> None:
        """Parser rejects packets with invalid magic number."""
        invalid_packet = struct.pack("<I", 0xDEADBEEF) + b"\x00" * 50

        request = hasp_parser.parse_request(invalid_packet)

        assert request is None

    def test_parse_truncated_packet(self, hasp_parser: HASPSentinelParser) -> None:
        """Parser handles truncated packets gracefully."""
        truncated_packet = struct.pack("<I", 0x48415350) + b"\x00" * 10

        request = hasp_parser.parse_request(truncated_packet)

        assert request is None

    def test_parse_packet_with_corrupted_json(self, hasp_parser: HASPSentinelParser) -> None:
        """Parser handles corrupted JSON in client_info."""
        packet = bytearray()
        packet.extend(struct.pack("<I", 0x48415350))
        packet.extend(struct.pack("<H", 1))
        packet.extend(struct.pack("<H", 1))
        packet.extend(struct.pack("<I", HASPCommandType.LOGIN))
        packet.extend(struct.pack("<I", 0))
        packet.extend(struct.pack("<I", 100))
        packet.extend(struct.pack("<I", 0x12345678))
        packet.extend(struct.pack("<B", HASPEncryptionType.NONE))
        packet.extend(struct.pack("<I", int(time.time())))

        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))

        corrupted_json = b"{invalid json content"
        packet.extend(struct.pack("<H", len(corrupted_json)))
        packet.extend(corrupted_json)

        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))

        request = hasp_parser.parse_request(bytes(packet))

        assert request is not None
        assert request.client_info == {}

    def test_generate_login_response(self, hasp_parser: HASPSentinelParser, sample_login_packet: bytes) -> None:
        """Parser generates valid login response."""
        request = hasp_parser.parse_request(sample_login_packet)
        assert request is not None

        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.STATUS_OK
        assert response.session_id != 0
        assert "session_established" in response.license_data
        assert response.license_data["session_established"] is True
        assert response.license_data["vendor"] == "AUTODESK"

    def test_login_with_invalid_vendor_code(self, hasp_parser: HASPSentinelParser) -> None:
        """Login with invalid vendor code returns error."""
        packet = bytearray()
        packet.extend(struct.pack("<I", 0x48415350))
        packet.extend(struct.pack("<H", 1))
        packet.extend(struct.pack("<H", 1))
        packet.extend(struct.pack("<I", HASPCommandType.LOGIN))
        packet.extend(struct.pack("<I", 0))
        packet.extend(struct.pack("<I", 100))
        packet.extend(struct.pack("<I", 0xBADC0DE0))
        packet.extend(struct.pack("<B", 0))
        packet.extend(struct.pack("<I", int(time.time())))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))

        request = hasp_parser.parse_request(bytes(packet))
        assert request is not None

        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.INVALID_VENDOR_CODE

    def test_feature_login_workflow(self, hasp_parser: HASPSentinelParser, sample_login_packet: bytes) -> None:
        """Complete feature login workflow succeeds."""
        login_request = hasp_parser.parse_request(sample_login_packet)
        assert login_request is not None

        login_response = hasp_parser.generate_response(login_request)
        assert login_response.status == HASPStatusCode.STATUS_OK
        session_id = login_response.session_id

        feature_packet = bytearray()
        feature_packet.extend(struct.pack("<I", 0x48415350))
        feature_packet.extend(struct.pack("<H", 1))
        feature_packet.extend(struct.pack("<H", 2))
        feature_packet.extend(struct.pack("<I", HASPCommandType.FEATURE_LOGIN))
        feature_packet.extend(struct.pack("<I", session_id))
        feature_packet.extend(struct.pack("<I", 100))
        feature_packet.extend(struct.pack("<I", 0x12345678))
        feature_packet.extend(struct.pack("<B", 0))
        feature_packet.extend(struct.pack("<I", int(time.time())))
        feature_packet.extend(struct.pack("<H", 0))
        feature_packet.extend(struct.pack("<H", 0))
        feature_packet.extend(struct.pack("<H", 0))
        feature_packet.extend(struct.pack("<H", 0))
        feature_packet.extend(struct.pack("<H", 0))

        feature_request = hasp_parser.parse_request(bytes(feature_packet))
        assert feature_request is not None

        feature_response = hasp_parser.generate_response(feature_request)

        assert feature_response.status == HASPStatusCode.STATUS_OK
        assert feature_response.license_data["feature_name"] == "AUTOCAD_FULL"
        assert "feature_handle" in feature_response.license_data

    def test_feature_login_without_session(self, hasp_parser: HASPSentinelParser) -> None:
        """Feature login without active session returns error."""
        packet = bytearray()
        packet.extend(struct.pack("<I", 0x48415350))
        packet.extend(struct.pack("<H", 1))
        packet.extend(struct.pack("<H", 1))
        packet.extend(struct.pack("<I", HASPCommandType.FEATURE_LOGIN))
        packet.extend(struct.pack("<I", 999999))
        packet.extend(struct.pack("<I", 100))
        packet.extend(struct.pack("<I", 0x12345678))
        packet.extend(struct.pack("<B", 0))
        packet.extend(struct.pack("<I", int(time.time())))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))

        request = hasp_parser.parse_request(bytes(packet))
        assert request is not None

        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.NOT_LOGGED_IN

    def test_memory_read_operation(self, hasp_parser: HASPSentinelParser, sample_login_packet: bytes) -> None:
        """Memory read operation returns correct data."""
        login_request = hasp_parser.parse_request(sample_login_packet)
        assert login_request is not None
        login_response = hasp_parser.generate_response(login_request)
        session_id = login_response.session_id

        read_packet = bytearray()
        read_packet.extend(struct.pack("<I", 0x48415350))
        read_packet.extend(struct.pack("<H", 1))
        read_packet.extend(struct.pack("<H", 3))
        read_packet.extend(struct.pack("<I", HASPCommandType.READ))
        read_packet.extend(struct.pack("<I", session_id))
        read_packet.extend(struct.pack("<I", 100))
        read_packet.extend(struct.pack("<I", 0x12345678))
        read_packet.extend(struct.pack("<B", 0))
        read_packet.extend(struct.pack("<I", int(time.time())))
        read_packet.extend(struct.pack("<H", 0))
        read_packet.extend(struct.pack("<H", 0))
        read_packet.extend(struct.pack("<H", 0))
        read_packet.extend(struct.pack("<H", 0))
        read_packet.extend(struct.pack("<H", 0))

        read_packet.extend(struct.pack("<H", 0x0005))
        read_packet.extend(struct.pack("<H", 4))
        read_packet.extend(struct.pack("<I", 0))

        read_packet.extend(struct.pack("<H", 0x0006))
        read_packet.extend(struct.pack("<H", 4))
        read_packet.extend(struct.pack("<I", 16))

        read_request = hasp_parser.parse_request(bytes(read_packet))
        assert read_request is not None

        response = hasp_parser.generate_response(read_request)

        assert response.status == HASPStatusCode.STATUS_OK
        assert len(response.encryption_response) == 16
        assert response.license_data["address"] == 0
        assert response.license_data["length"] == 16

    def test_memory_write_operation(self, hasp_parser: HASPSentinelParser, sample_login_packet: bytes) -> None:
        """Memory write operation updates memory correctly."""
        login_request = hasp_parser.parse_request(sample_login_packet)
        assert login_request is not None
        login_response = hasp_parser.generate_response(login_request)
        session_id = login_response.session_id

        test_data = b"TEST_WRITE_DATA_"

        write_packet = bytearray()
        write_packet.extend(struct.pack("<I", 0x48415350))
        write_packet.extend(struct.pack("<H", 1))
        write_packet.extend(struct.pack("<H", 3))
        write_packet.extend(struct.pack("<I", HASPCommandType.WRITE))
        write_packet.extend(struct.pack("<I", session_id))
        write_packet.extend(struct.pack("<I", 100))
        write_packet.extend(struct.pack("<I", 0x12345678))
        write_packet.extend(struct.pack("<B", 0))
        write_packet.extend(struct.pack("<I", int(time.time())))
        write_packet.extend(struct.pack("<H", 0))
        write_packet.extend(struct.pack("<H", 0))
        write_packet.extend(struct.pack("<H", 0))
        write_packet.extend(struct.pack("<H", 0))
        write_packet.extend(struct.pack("<H", 0))

        write_packet.extend(struct.pack("<H", 0x0005))
        write_packet.extend(struct.pack("<H", 4))
        write_packet.extend(struct.pack("<I", 256))

        write_packet.extend(struct.pack("<H", 0x0007))
        write_packet.extend(struct.pack("<H", len(test_data)))
        write_packet.extend(test_data)

        write_request = hasp_parser.parse_request(bytes(write_packet))
        assert write_request is not None

        write_response = hasp_parser.generate_response(write_request)

        assert write_response.status == HASPStatusCode.STATUS_OK
        assert write_response.license_data["bytes_written"] == len(test_data)

        memory = hasp_parser.memory_storage[100]
        assert memory[256:256 + len(test_data)] == bytearray(test_data)

    def test_encryption_operation(self, hasp_parser: HASPSentinelParser, sample_login_packet: bytes) -> None:
        """Encryption operation encrypts data correctly."""
        login_request = hasp_parser.parse_request(sample_login_packet)
        assert login_request is not None
        login_response = hasp_parser.generate_response(login_request)
        session_id = login_response.session_id

        plaintext = b"Data to encrypt"

        encrypt_packet = bytearray()
        encrypt_packet.extend(struct.pack("<I", 0x48415350))
        encrypt_packet.extend(struct.pack("<H", 1))
        encrypt_packet.extend(struct.pack("<H", 3))
        encrypt_packet.extend(struct.pack("<I", HASPCommandType.ENCRYPT))
        encrypt_packet.extend(struct.pack("<I", session_id))
        encrypt_packet.extend(struct.pack("<I", 100))
        encrypt_packet.extend(struct.pack("<I", 0x12345678))
        encrypt_packet.extend(struct.pack("<B", HASPEncryptionType.AES256))
        encrypt_packet.extend(struct.pack("<I", int(time.time())))
        encrypt_packet.extend(struct.pack("<H", 0))
        encrypt_packet.extend(struct.pack("<H", 0))
        encrypt_packet.extend(struct.pack("<H", 0))
        encrypt_packet.extend(struct.pack("<H", len(plaintext)))
        encrypt_packet.extend(plaintext)
        encrypt_packet.extend(struct.pack("<H", 0))

        encrypt_request = hasp_parser.parse_request(bytes(encrypt_packet))
        assert encrypt_request is not None

        response = hasp_parser.generate_response(encrypt_request)

        assert response.status == HASPStatusCode.STATUS_OK
        assert len(response.encryption_response) > len(plaintext)
        assert response.encryption_response != plaintext

    def test_heartbeat_updates_session(self, hasp_parser: HASPSentinelParser, sample_login_packet: bytes) -> None:
        """Heartbeat updates session last_heartbeat time."""
        login_request = hasp_parser.parse_request(sample_login_packet)
        assert login_request is not None
        login_response = hasp_parser.generate_response(login_request)
        session_id = login_response.session_id

        initial_heartbeat = hasp_parser.active_sessions[session_id].last_heartbeat

        time.sleep(0.1)

        heartbeat_packet = bytearray()
        heartbeat_packet.extend(struct.pack("<I", 0x48415350))
        heartbeat_packet.extend(struct.pack("<H", 1))
        heartbeat_packet.extend(struct.pack("<H", 4))
        heartbeat_packet.extend(struct.pack("<I", HASPCommandType.HEARTBEAT))
        heartbeat_packet.extend(struct.pack("<I", session_id))
        heartbeat_packet.extend(struct.pack("<I", 100))
        heartbeat_packet.extend(struct.pack("<I", 0x12345678))
        heartbeat_packet.extend(struct.pack("<B", 0))
        heartbeat_packet.extend(struct.pack("<I", int(time.time())))
        heartbeat_packet.extend(struct.pack("<H", 0))
        heartbeat_packet.extend(struct.pack("<H", 0))
        heartbeat_packet.extend(struct.pack("<H", 0))
        heartbeat_packet.extend(struct.pack("<H", 0))
        heartbeat_packet.extend(struct.pack("<H", 0))

        heartbeat_request = hasp_parser.parse_request(bytes(heartbeat_packet))
        assert heartbeat_request is not None

        response = hasp_parser.generate_response(heartbeat_request)

        assert response.status == HASPStatusCode.STATUS_OK
        assert hasp_parser.active_sessions[session_id].last_heartbeat > initial_heartbeat

    def test_logout_removes_session(self, hasp_parser: HASPSentinelParser, sample_login_packet: bytes) -> None:
        """Logout removes active session."""
        login_request = hasp_parser.parse_request(sample_login_packet)
        assert login_request is not None
        login_response = hasp_parser.generate_response(login_request)
        session_id = login_response.session_id

        assert session_id in hasp_parser.active_sessions

        logout_packet = bytearray()
        logout_packet.extend(struct.pack("<I", 0x48415350))
        logout_packet.extend(struct.pack("<H", 1))
        logout_packet.extend(struct.pack("<H", 5))
        logout_packet.extend(struct.pack("<I", HASPCommandType.LOGOUT))
        logout_packet.extend(struct.pack("<I", session_id))
        logout_packet.extend(struct.pack("<I", 100))
        logout_packet.extend(struct.pack("<I", 0x12345678))
        logout_packet.extend(struct.pack("<B", 0))
        logout_packet.extend(struct.pack("<I", int(time.time())))
        logout_packet.extend(struct.pack("<H", 0))
        logout_packet.extend(struct.pack("<H", 0))
        logout_packet.extend(struct.pack("<H", 0))
        logout_packet.extend(struct.pack("<H", 0))
        logout_packet.extend(struct.pack("<H", 0))

        logout_request = hasp_parser.parse_request(bytes(logout_packet))
        assert logout_request is not None

        response = hasp_parser.generate_response(logout_request)

        assert response.status == HASPStatusCode.STATUS_OK
        assert session_id not in hasp_parser.active_sessions

    def test_serialize_response_produces_valid_packet(self, hasp_parser: HASPSentinelParser) -> None:
        """Response serialization produces valid packet."""
        response = HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=12345,
            feature_id=100,
            license_data={"test_key": "test_value"},
            encryption_response=b"encrypted_data",
            expiry_info={"expiry_date": "permanent"},
            hardware_info={"hasp_id": 123456},
            packet_version=1,
            sequence_number=10,
            signature=b"",
        )

        serialized = hasp_parser.serialize_response(response)

        assert len(serialized) > 0
        magic = struct.unpack("<I", serialized[:4])[0]
        assert magic == 0x48415350

        version = struct.unpack("<H", serialized[4:6])[0]
        assert version == 1

        seq = struct.unpack("<H", serialized[6:8])[0]
        assert seq == 10

        status = struct.unpack("<I", serialized[8:12])[0]
        assert status == HASPStatusCode.STATUS_OK

    def test_add_custom_feature(self, hasp_parser: HASPSentinelParser) -> None:
        """Adding custom feature creates memory storage."""
        custom_feature = HASPFeature(
            feature_id=9999,
            name="CUSTOM_FEATURE",
            vendor_code=0xDEADBEEF,
            feature_type=HASPFeatureType.PERPETUAL,
            expiry="permanent",
            max_users=10,
            encryption_supported=True,
            memory_size=2048,
            rtc_supported=True,
        )

        hasp_parser.add_feature(custom_feature)

        assert 9999 in hasp_parser.features
        assert hasp_parser.features[9999].name == "CUSTOM_FEATURE"
        assert 9999 in hasp_parser.memory_storage
        assert len(hasp_parser.memory_storage[9999]) == 2048

    def test_remove_feature(self, hasp_parser: HASPSentinelParser) -> None:
        """Removing feature deletes memory storage."""
        feature_id = 100
        assert feature_id in hasp_parser.features

        hasp_parser.remove_feature(feature_id)

        assert feature_id not in hasp_parser.features
        assert feature_id not in hasp_parser.memory_storage

    def test_get_active_sessions(self, hasp_parser: HASPSentinelParser, sample_login_packet: bytes) -> None:
        """Get active sessions returns session information."""
        login_request = hasp_parser.parse_request(sample_login_packet)
        assert login_request is not None
        login_response = hasp_parser.generate_response(login_request)

        sessions = hasp_parser.get_active_sessions()

        assert len(sessions) == 1
        assert sessions[0]["session_id"] == login_response.session_id
        assert "uptime" in sessions[0]


class TestHASPUSBEmulator:
    """Test HASP USB dongle emulator."""

    def test_usb_read_memory(self, hasp_usb_emulator: HASPUSBEmulator) -> None:
        """USB memory read returns data."""
        address = 0
        length = 64

        data = hasp_usb_emulator.handle_control_transfer(
            HASPUSBProtocol.CONTROL_TRANSFER_TYPE,
            HASPUSBProtocol.CMD_READ_MEMORY,
            address,
            length,
            b"",
        )

        assert len(data) <= 64
        assert isinstance(data, bytes)

    def test_usb_write_memory(self, hasp_usb_emulator: HASPUSBEmulator) -> None:
        """USB memory write stores data."""
        address = 256
        test_data = b"USB_TEST_DATA"

        result = hasp_usb_emulator.handle_control_transfer(
            HASPUSBProtocol.CONTROL_TRANSFER_TYPE,
            HASPUSBProtocol.CMD_WRITE_MEMORY,
            address,
            len(test_data),
            test_data,
        )

        bytes_written = struct.unpack("<I", result)[0]
        assert bytes_written == len(test_data)

    def test_usb_encrypt_decrypt_roundtrip(self, hasp_usb_emulator: HASPUSBEmulator) -> None:
        """USB encryption/decryption roundtrip works."""
        plaintext = b"USB encryption test"

        encrypted = hasp_usb_emulator.handle_control_transfer(
            HASPUSBProtocol.CONTROL_TRANSFER_TYPE,
            HASPUSBProtocol.CMD_ENCRYPT,
            0,
            0,
            plaintext,
        )

        assert encrypted != plaintext

        decrypted = hasp_usb_emulator.handle_control_transfer(
            HASPUSBProtocol.CONTROL_TRANSFER_TYPE,
            HASPUSBProtocol.CMD_DECRYPT,
            0,
            0,
            encrypted,
        )

        assert decrypted == plaintext

    def test_usb_get_info_returns_device_info(self, hasp_usb_emulator: HASPUSBEmulator) -> None:
        """USB get info returns device information."""
        info = hasp_usb_emulator.handle_control_transfer(
            HASPUSBProtocol.CONTROL_TRANSFER_TYPE,
            HASPUSBProtocol.CMD_GET_INFO,
            0,
            0,
            b"",
        )

        assert len(info) == 16
        vendor_id, product_id, _version, _memory = struct.unpack("<IIII", info)
        assert vendor_id == HASPUSBProtocol.USB_VENDOR_ID
        assert product_id in HASPUSBProtocol.USB_PRODUCT_IDS

    def test_usb_get_rtc_returns_timestamp(self, hasp_usb_emulator: HASPUSBEmulator) -> None:
        """USB RTC read returns current timestamp."""
        rtc_data = hasp_usb_emulator.handle_control_transfer(
            HASPUSBProtocol.CONTROL_TRANSFER_TYPE,
            HASPUSBProtocol.CMD_GET_RTC,
            0,
            0,
            b"",
        )

        assert len(rtc_data) == 4
        timestamp = struct.unpack("<I", rtc_data)[0]
        current_time = int(time.time())
        assert abs(timestamp - current_time) < 2

    def test_emulate_usb_device_returns_descriptors(self, hasp_usb_emulator: HASPUSBEmulator) -> None:
        """USB device emulation returns complete descriptors."""
        descriptors = hasp_usb_emulator.emulate_usb_device()

        assert "device_descriptor" in descriptors
        assert "string_descriptors" in descriptors
        assert "configuration_descriptor" in descriptors

        device_desc = descriptors["device_descriptor"]
        assert device_desc["idVendor"] == HASPUSBProtocol.USB_VENDOR_ID
        assert device_desc["bDeviceClass"] == 0xFF


class TestHASPServerEmulator:
    """Test HASP server emulator."""

    def test_generate_discovery_response(self, hasp_server_emulator: HASPServerEmulator) -> None:
        """Server generates valid discovery response."""
        response = hasp_server_emulator.generate_discovery_response()

        assert HASPNetworkProtocol.SERVER_READY_MAGIC in response
        assert b"SERVER_ID=" in response
        assert b"VERSION=" in response
        assert b"FEATURES=" in response

    def test_handle_discovery_request(self, hasp_server_emulator: HASPServerEmulator) -> None:
        """Server handles discovery requests."""
        discovery_request = HASPNetworkProtocol.DISCOVERY_MAGIC + b"CLIENT_REQUEST"

        response = hasp_server_emulator.handle_client_request(discovery_request)

        assert HASPNetworkProtocol.SERVER_READY_MAGIC in response

    def test_handle_login_request(self, hasp_server_emulator: HASPServerEmulator, sample_login_packet: bytes) -> None:
        """Server handles login requests."""
        response_bytes = hasp_server_emulator.handle_client_request(sample_login_packet)

        assert len(response_bytes) > 0

        magic = struct.unpack("<I", response_bytes[:4])[0]
        assert magic == 0x48415350

        status = struct.unpack("<I", response_bytes[8:12])[0]
        assert status == HASPStatusCode.STATUS_OK


class TestHASPEdgeCases:
    """Test HASP protocol edge cases and error conditions."""

    def test_concurrent_user_limit_enforcement(self, hasp_parser: HASPSentinelParser) -> None:
        """Feature login enforces concurrent user limits."""
        feature = HASPFeature(
            feature_id=8888,
            name="LIMITED_FEATURE",
            vendor_code=0x12345678,
            feature_type=HASPFeatureType.CONCURRENT,
            expiry="permanent",
            max_users=2,
            encryption_supported=True,
            memory_size=1024,
            rtc_supported=False,
            concurrent_limit=2,
        )
        hasp_parser.add_feature(feature)

        sessions = []
        for _i in range(2):
            packet = self._create_login_packet(0x12345678, 8888)
            request = hasp_parser.parse_request(packet)
            assert request is not None
            response = hasp_parser.generate_response(request)
            assert response.status == HASPStatusCode.STATUS_OK
            sessions.append(response.session_id)

            feature_packet = self._create_feature_login_packet(response.session_id, 0x12345678, 8888)
            feature_request = hasp_parser.parse_request(feature_packet)
            assert feature_request is not None
            feature_response = hasp_parser.generate_response(feature_request)
            assert feature_response.status == HASPStatusCode.STATUS_OK

        packet = self._create_login_packet(0x12345678, 8888)
        request = hasp_parser.parse_request(packet)
        assert request is not None
        response = hasp_parser.generate_response(request)
        assert response.status == HASPStatusCode.STATUS_OK

        feature_packet = self._create_feature_login_packet(response.session_id, 0x12345678, 8888)
        feature_request = hasp_parser.parse_request(feature_packet)
        assert feature_request is not None
        feature_response = hasp_parser.generate_response(feature_request)

        assert feature_response.status == HASPStatusCode.TOO_MANY_USERS

    def test_memory_read_out_of_bounds(self, hasp_parser: HASPSentinelParser, sample_login_packet: bytes) -> None:
        """Memory read with out-of-bounds address returns error."""
        login_request = hasp_parser.parse_request(sample_login_packet)
        assert login_request is not None
        login_response = hasp_parser.generate_response(login_request)
        session_id = login_response.session_id

        read_packet = self._create_memory_read_packet(session_id, 0x12345678, 100, 99999, 16)

        read_request = hasp_parser.parse_request(read_packet)
        assert read_request is not None

        response = hasp_parser.generate_response(read_request)

        assert response.status == HASPStatusCode.MEM_RANGE

    def test_operation_without_login(self, hasp_parser: HASPSentinelParser) -> None:
        """Operations without login return NOT_LOGGED_IN error."""
        encrypt_packet = self._create_encrypt_packet(999999, 0x12345678, 100, b"test")

        request = hasp_parser.parse_request(encrypt_packet)
        assert request is not None

        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.NOT_LOGGED_IN

    def test_large_encryption_data(self, hasp_parser: HASPSentinelParser, sample_login_packet: bytes) -> None:
        """Encryption handles large data correctly."""
        login_request = hasp_parser.parse_request(sample_login_packet)
        assert login_request is not None
        login_response = hasp_parser.generate_response(login_request)
        session_id = login_response.session_id

        large_data = secrets.token_bytes(8192)

        encrypt_packet = self._create_encrypt_packet(session_id, 0x12345678, 100, large_data)

        request = hasp_parser.parse_request(encrypt_packet)
        assert request is not None

        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.STATUS_OK
        assert len(response.encryption_response) > len(large_data)

    def _create_login_packet(self, vendor_code: int, feature_id: int) -> bytes:
        """Helper to create login packet."""
        packet = bytearray()
        packet.extend(struct.pack("<I", 0x48415350))
        packet.extend(struct.pack("<H", 1))
        packet.extend(struct.pack("<H", 1))
        packet.extend(struct.pack("<I", HASPCommandType.LOGIN))
        packet.extend(struct.pack("<I", 0))
        packet.extend(struct.pack("<I", feature_id))
        packet.extend(struct.pack("<I", vendor_code))
        packet.extend(struct.pack("<B", 0))
        packet.extend(struct.pack("<I", int(time.time())))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))
        return bytes(packet)

    def _create_feature_login_packet(self, session_id: int, vendor_code: int, feature_id: int) -> bytes:
        """Helper to create feature login packet."""
        packet = bytearray()
        packet.extend(struct.pack("<I", 0x48415350))
        packet.extend(struct.pack("<H", 1))
        packet.extend(struct.pack("<H", 2))
        packet.extend(struct.pack("<I", HASPCommandType.FEATURE_LOGIN))
        packet.extend(struct.pack("<I", session_id))
        packet.extend(struct.pack("<I", feature_id))
        packet.extend(struct.pack("<I", vendor_code))
        packet.extend(struct.pack("<B", 0))
        packet.extend(struct.pack("<I", int(time.time())))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))
        return bytes(packet)

    def _create_memory_read_packet(self, session_id: int, vendor_code: int, feature_id: int, address: int, length: int) -> bytes:
        """Helper to create memory read packet."""
        packet = bytearray()
        packet.extend(struct.pack("<I", 0x48415350))
        packet.extend(struct.pack("<H", 1))
        packet.extend(struct.pack("<H", 3))
        packet.extend(struct.pack("<I", HASPCommandType.READ))
        packet.extend(struct.pack("<I", session_id))
        packet.extend(struct.pack("<I", feature_id))
        packet.extend(struct.pack("<I", vendor_code))
        packet.extend(struct.pack("<B", 0))
        packet.extend(struct.pack("<I", int(time.time())))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))

        packet.extend(struct.pack("<H", 0x0005))
        packet.extend(struct.pack("<H", 4))
        packet.extend(struct.pack("<I", address))

        packet.extend(struct.pack("<H", 0x0006))
        packet.extend(struct.pack("<H", 4))
        packet.extend(struct.pack("<I", length))

        return bytes(packet)

    def _create_encrypt_packet(self, session_id: int, vendor_code: int, feature_id: int, data: bytes) -> bytes:
        """Helper to create encryption packet."""
        packet = bytearray()
        packet.extend(struct.pack("<I", 0x48415350))
        packet.extend(struct.pack("<H", 1))
        packet.extend(struct.pack("<H", 3))
        packet.extend(struct.pack("<I", HASPCommandType.ENCRYPT))
        packet.extend(struct.pack("<I", session_id))
        packet.extend(struct.pack("<I", feature_id))
        packet.extend(struct.pack("<I", vendor_code))
        packet.extend(struct.pack("<B", HASPEncryptionType.AES256))
        packet.extend(struct.pack("<I", int(time.time())))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", len(data)))
        packet.extend(data)
        packet.extend(struct.pack("<H", 0))
        return bytes(packet)
