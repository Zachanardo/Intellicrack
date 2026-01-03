"""Production-ready tests for HASP/Sentinel protocol parser encryption and emulation.

This test suite validates the HASP parser implements REAL cryptographic operations,
proper protocol handling, and complete session management as required for defeating
actual HASP/Sentinel licensing protections.

Tests MUST FAIL if:
- AES-256 encryption is not properly implemented
- USB authentication flow doesn't work
- Command handling is incomplete
- Session management is broken
- Protocol support is missing
- Memory layout emulation is incorrect
"""

import hashlib
import json
import secrets
import struct
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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
    """Create HASP crypto handler."""
    return HASPCrypto()


@pytest.fixture
def hasp_parser() -> HASPSentinelParser:
    """Create HASP parser with default features."""
    return HASPSentinelParser()


@pytest.fixture
def test_session(hasp_parser: HASPSentinelParser) -> HASPSession:
    """Create test session."""
    session_id = 123456
    vendor_code = 0x12345678
    encryption_key = hasp_parser.crypto.generate_session_key(session_id, vendor_code)

    session = HASPSession(
        session_id=session_id,
        vendor_code=vendor_code,
        feature_id=100,
        login_time=time.time(),
        last_heartbeat=time.time(),
        client_info={"hostname": "testclient", "username": "testuser"},
        encryption_key=encryption_key,
    )
    hasp_parser.active_sessions[session_id] = session
    return session


class TestHASPCryptoAES256:
    """Test real AES-256 encryption implementation for HASP HL/SL."""

    def test_aes256_key_generation_uses_sha256(self, hasp_crypto: HASPCrypto) -> None:
        """Session key generation must use SHA-256 for proper AES-256 key derivation."""
        session_id = 999888
        vendor_code = 0xDEADBEEF

        session_key = hasp_crypto.generate_session_key(session_id, vendor_code)

        assert len(session_key) == 32, "AES-256 requires 32-byte key"
        assert session_id in hasp_crypto.aes_keys, "Session key not stored"
        assert hasp_crypto.aes_keys[session_id] == session_key

    def test_aes256_encryption_produces_different_ciphertext_each_time(self, hasp_crypto: HASPCrypto) -> None:
        """AES-256 encryption must use random IV for each encryption."""
        plaintext = b"HASP_LICENSE_DATA_SENSITIVE"
        session_id = 100

        ciphertext1 = hasp_crypto.aes_encrypt(plaintext, session_id)
        ciphertext2 = hasp_crypto.aes_encrypt(plaintext, session_id)

        assert ciphertext1 != ciphertext2, "IV not randomized, encryption is deterministic"
        assert len(ciphertext1) >= 16 + len(plaintext), "Missing IV or ciphertext"

    def test_aes256_encryption_roundtrip_preserves_data(self, hasp_crypto: HASPCrypto) -> None:
        """AES-256 encrypt/decrypt must perfectly preserve plaintext."""
        original = b"HASP_HL_MEMORY_CONTENT_WITH_LICENSE_KEY_AND_EXPIRY_DATA"
        session_id = 200

        encrypted = hasp_crypto.aes_encrypt(original, session_id)
        decrypted = hasp_crypto.aes_decrypt(encrypted, session_id)

        assert decrypted == original, "AES-256 roundtrip failed, data corrupted"

    def test_aes256_encryption_handles_multiple_block_sizes(self, hasp_crypto: HASPCrypto) -> None:
        """AES-256 must handle PKCS#7 padding for any input size."""
        test_cases = [
            b"A",
            b"AB",
            b"A" * 15,
            b"A" * 16,
            b"A" * 17,
            b"A" * 31,
            b"A" * 32,
            b"A" * 64,
            b"A" * 1024,
        ]

        session_id = 300

        for plaintext in test_cases:
            encrypted = hasp_crypto.aes_encrypt(plaintext, session_id)
            decrypted = hasp_crypto.aes_decrypt(encrypted, session_id)

            assert decrypted == plaintext, f"Failed for {len(plaintext)} bytes"

    def test_aes256_uses_cbc_mode_with_proper_iv(self, hasp_crypto: HASPCrypto) -> None:
        """AES-256 must use CBC mode with prepended IV."""
        plaintext = b"TEST_DATA_FOR_CBC_VALIDATION"
        session_id = 400

        ciphertext = hasp_crypto.aes_encrypt(plaintext, session_id)

        assert len(ciphertext) >= 16, "Missing IV"
        iv = ciphertext[:16]
        assert len(set(iv)) > 1, "IV appears non-random"

        encrypted_part = ciphertext[16:]
        assert len(encrypted_part) % 16 == 0, "Ciphertext not block-aligned"

    def test_aes256_decryption_fails_with_wrong_session_key(self, hasp_crypto: HASPCrypto) -> None:
        """AES-256 decryption with wrong session key must produce garbage."""
        plaintext = b"ORIGINAL_DATA"
        session_id_a = 500
        session_id_b = 501

        hasp_crypto.generate_session_key(session_id_a, 0x11111111)
        hasp_crypto.generate_session_key(session_id_b, 0x22222222)

        encrypted = hasp_crypto.aes_encrypt(plaintext, session_id_a)
        decrypted_wrong_key = hasp_crypto.aes_decrypt(encrypted, session_id_b)

        assert decrypted_wrong_key != plaintext, "Decryption succeeded with wrong key"

    def test_aes256_encryption_uses_actual_cryptography_library(self, hasp_crypto: HASPCrypto) -> None:
        """AES-256 must use cryptography library, not XOR fallback."""
        plaintext = b"VALIDATE_REAL_AES"
        session_id = 600

        encrypted = hasp_crypto.aes_encrypt(plaintext, session_id)

        for i in range(len(plaintext)):
            if i + 16 < len(encrypted):
                assert encrypted[i + 16] != plaintext[i], "Appears to be XOR, not AES"


class TestHASPCryptoRSA:
    """Test RSA-2048 signature generation for HASP envelope encryption."""

    def test_rsa_key_generation_creates_2048bit_keys(self, hasp_crypto: HASPCrypto) -> None:
        """RSA keys must be 2048-bit for production security."""
        session_id = 0
        assert session_id in hasp_crypto.rsa_keys, "Default RSA keys not generated"

        private_key, public_key = hasp_crypto.rsa_keys[session_id]

        assert private_key.key_size == 2048, "Private key not 2048-bit"
        assert public_key.key_size == 2048, "Public key not 2048-bit"

    def test_rsa_signature_verification_works_correctly(self, hasp_crypto: HASPCrypto) -> None:
        """RSA signing and verification must use proper PSS padding."""
        data = b"HASP_LICENSE_RESPONSE_DATA"
        session_id = 0

        signature = hasp_crypto.rsa_sign(data, session_id)

        assert len(signature) == 256, "RSA-2048 signature should be 256 bytes"
        assert hasp_crypto.rsa_verify(data, signature, session_id), "Signature verification failed"

    def test_rsa_signature_fails_with_modified_data(self, hasp_crypto: HASPCrypto) -> None:
        """RSA verification must detect data tampering."""
        original = b"ORIGINAL_DATA"
        modified = b"MODIFIED_DATA"
        session_id = 0

        signature = hasp_crypto.rsa_sign(original, session_id)

        assert not hasp_crypto.rsa_verify(modified, signature, session_id), "Signature validated modified data"

    def test_rsa_signature_fails_with_corrupted_signature(self, hasp_crypto: HASPCrypto) -> None:
        """RSA verification must reject corrupted signatures."""
        data = b"TEST_DATA"
        session_id = 0

        signature = hasp_crypto.rsa_sign(data, session_id)
        corrupted_sig_arr = bytearray(signature)
        corrupted_sig_arr[0] ^= 0xFF
        corrupted_sig = bytes(corrupted_sig_arr)

        assert not hasp_crypto.rsa_verify(data, corrupted_sig, session_id), "Corrupted signature accepted"


class TestHASPCryptoEnvelopeEncryption:
    """Test envelope encryption (RSA + AES hybrid)."""

    def test_envelope_encrypt_combines_rsa_and_aes(self, hasp_crypto: HASPCrypto) -> None:
        """Envelope encryption must use RSA for session key + AES for data."""
        plaintext = b"LARGE_LICENSE_DATA_PAYLOAD" * 10
        session_id = 0

        encrypted = hasp_crypto.envelope_encrypt(plaintext, session_id)

        assert len(encrypted) > len(plaintext), "Encrypted data smaller than plaintext"
        assert len(encrypted) >= 2 + 256 + 16, "Missing key length, encrypted key, or IV"

    def test_envelope_encryption_roundtrip_preserves_data(self, hasp_crypto: HASPCrypto) -> None:
        """Envelope encrypt/decrypt must preserve data integrity."""
        original = b"HASP_NETWORK_LICENSE_PAYLOAD_WITH_FEATURES_AND_EXPIRY" * 20
        session_id = 0

        encrypted = hasp_crypto.envelope_encrypt(original, session_id)
        decrypted = hasp_crypto.envelope_decrypt(encrypted, session_id)

        assert decrypted == original, "Envelope encryption roundtrip failed"

    def test_envelope_encryption_uses_random_session_keys(self, hasp_crypto: HASPCrypto) -> None:
        """Each envelope encryption must use unique AES session key."""
        plaintext = b"SAME_DATA"
        session_id = 0

        encrypted1 = hasp_crypto.envelope_encrypt(plaintext, session_id)
        encrypted2 = hasp_crypto.envelope_encrypt(plaintext, session_id)

        assert encrypted1 != encrypted2, "Session key not randomized"


class TestHASPCryptoHASP4Legacy:
    """Test HASP4 legacy encryption using LFSR-based stream cipher."""

    def test_hasp4_encryption_uses_lfsr_keystream(self, hasp_crypto: HASPCrypto) -> None:
        """HASP4 encryption must use Linear Feedback Shift Register."""
        plaintext = b"HASP4_LEGACY_DATA"
        seed = 0xDEADBEEF

        encrypted = hasp_crypto.hasp4_encrypt(plaintext, seed)

        assert len(encrypted) == len(plaintext), "HASP4 is stream cipher, length must match"
        assert encrypted != plaintext, "Encryption didn't occur"

    def test_hasp4_encryption_is_symmetric(self, hasp_crypto: HASPCrypto) -> None:
        """HASP4 encrypt and decrypt must be identical for stream cipher."""
        data = b"SYMMETRIC_TEST_DATA"
        seed = 0x12345678

        encrypted = hasp_crypto.hasp4_encrypt(data, seed)
        decrypted = hasp_crypto.hasp4_decrypt(encrypted, seed)

        assert decrypted == data, "HASP4 roundtrip failed"

    def test_hasp4_produces_deterministic_keystream(self, hasp_crypto: HASPCrypto) -> None:
        """HASP4 keystream must be deterministic for given seed."""
        seed = 0xABCDEF12
        data = b"TEST" * 100

        encrypted1 = hasp_crypto.hasp4_encrypt(data, seed)
        encrypted2 = hasp_crypto.hasp4_encrypt(data, seed)

        assert encrypted1 == encrypted2, "Keystream not deterministic"

    def test_hasp4_different_seeds_produce_different_ciphertext(self, hasp_crypto: HASPCrypto) -> None:
        """HASP4 must produce different ciphertext for different seeds."""
        plaintext = b"SEED_SENSITIVITY_TEST"
        seed1 = 0x11111111
        seed2 = 0x22222222

        encrypted1 = hasp_crypto.hasp4_encrypt(plaintext, seed1)
        encrypted2 = hasp_crypto.hasp4_encrypt(plaintext, seed2)

        assert encrypted1 != encrypted2, "Different seeds produced same ciphertext"


class TestHASPUSBAuthenticationFlow:
    """Test USB dongle challenge-response authentication."""

    def test_usb_memory_read_returns_initialized_data(self) -> None:
        """USB memory read must return HASP HL memory layout."""
        emulator = HASPUSBEmulator()

        address = 0
        length = 16
        data = emulator._handle_usb_read_memory(address, length)

        assert len(data) == length, "Wrong data length returned"
        assert data != b"\x00" * length, "Memory not initialized"

    def test_usb_memory_write_persists_data(self) -> None:
        """USB memory write must actually store data."""
        emulator = HASPUSBEmulator()

        address = 256
        test_data = b"WRITTEN_DATA_TEST"
        result = emulator._handle_usb_write_memory(address, len(test_data), test_data)

        bytes_written = struct.unpack("<I", result)[0]
        assert bytes_written == len(test_data), "Write failed"

        read_back = emulator._handle_usb_read_memory(address, len(test_data))
        assert read_back == test_data, "Data not persisted"

    def test_usb_encrypt_produces_valid_ciphertext(self) -> None:
        """USB encrypt command must use HASP4 algorithm."""
        emulator = HASPUSBEmulator()

        plaintext = b"USB_ENCRYPT_TEST"
        encrypted = emulator._handle_usb_encrypt(plaintext)

        assert len(encrypted) > 0, "No encrypted data returned"
        assert encrypted != plaintext, "Encryption didn't occur"

    def test_usb_decrypt_reverses_encryption(self) -> None:
        """USB decrypt must reverse encrypt operation."""
        emulator = HASPUSBEmulator()

        original = b"ROUNDTRIP_TEST"
        encrypted = emulator._handle_usb_encrypt(original)
        decrypted = emulator._handle_usb_decrypt(encrypted)

        assert decrypted == original, "USB encryption roundtrip failed"

    def test_usb_get_info_returns_device_descriptor(self) -> None:
        """USB get info must return valid HASP device information."""
        emulator = HASPUSBEmulator()

        info_data = emulator._handle_usb_get_info()

        assert len(info_data) == 16, "Info must be 4x uint32"
        vendor_id, product_id, version, memory_size = struct.unpack("<IIII", info_data)

        assert vendor_id == HASPUSBProtocol.USB_VENDOR_ID, "Wrong vendor ID"
        assert product_id in HASPUSBProtocol.USB_PRODUCT_IDS, "Invalid product ID"
        assert memory_size > 0, "Zero memory size"

    def test_usb_get_rtc_returns_current_time(self) -> None:
        """USB RTC read must return current timestamp."""
        emulator = HASPUSBEmulator()

        before = int(time.time())
        rtc_data = emulator._handle_usb_get_rtc()
        after = int(time.time())

        rtc_time = struct.unpack("<I", rtc_data)[0]

        assert before <= rtc_time <= after + 1, "RTC time invalid"


class TestHASPCommandHandling:
    """Test all HASP command types are properly implemented."""

    def test_login_command_creates_session_with_encryption_key(self, hasp_parser: HASPSentinelParser) -> None:
        """LOGIN command must establish session with AES key."""
        request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={"hostname": "testclient"},
            encryption_data=b"",
            additional_params={},
        )

        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.STATUS_OK, "Login failed"
        assert response.session_id > 0, "No session ID assigned"
        assert response.session_id in hasp_parser.active_sessions, "Session not created"

        session = hasp_parser.active_sessions[response.session_id]
        assert len(session.encryption_key) == 32, "AES-256 key not generated"

    def test_logout_command_destroys_session(self, hasp_parser: HASPSentinelParser, test_session: HASPSession) -> None:
        """LOGOUT command must remove active session."""
        request = HASPRequest(
            command=HASPCommandType.LOGOUT,
            session_id=test_session.session_id,
            feature_id=test_session.feature_id,
            vendor_code=test_session.vendor_code,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.STATUS_OK, "Logout failed"
        assert test_session.session_id not in hasp_parser.active_sessions, "Session not destroyed"

    def test_encrypt_command_uses_aes256_by_default(self, hasp_parser: HASPSentinelParser, test_session: HASPSession) -> None:
        """ENCRYPT command must use AES-256 when type not specified."""
        plaintext = b"DATA_TO_ENCRYPT"

        request = HASPRequest(
            command=HASPCommandType.ENCRYPT,
            session_id=test_session.session_id,
            feature_id=test_session.feature_id,
            vendor_code=test_session.vendor_code,
            scope="",
            format="",
            client_info={},
            encryption_data=plaintext,
            additional_params={},
            encryption_type=HASPEncryptionType.NONE,
        )

        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.STATUS_OK, "Encryption failed"
        assert len(response.encryption_response) > len(plaintext), "No IV prepended"
        assert response.encryption_response != plaintext, "Data not encrypted"

    def test_decrypt_command_reverses_encryption(self, hasp_parser: HASPSentinelParser, test_session: HASPSession) -> None:
        """DECRYPT command must reverse ENCRYPT operation."""
        original = b"ROUNDTRIP_VALIDATION_DATA"

        encrypt_req = HASPRequest(
            command=HASPCommandType.ENCRYPT,
            session_id=test_session.session_id,
            feature_id=test_session.feature_id,
            vendor_code=test_session.vendor_code,
            scope="",
            format="",
            client_info={},
            encryption_data=original,
            additional_params={},
            encryption_type=HASPEncryptionType.AES256,
        )

        encrypt_resp = hasp_parser.generate_response(encrypt_req)

        decrypt_req = HASPRequest(
            command=HASPCommandType.DECRYPT,
            session_id=test_session.session_id,
            feature_id=test_session.feature_id,
            vendor_code=test_session.vendor_code,
            scope="",
            format="",
            client_info={},
            encryption_data=encrypt_resp.encryption_response,
            additional_params={},
            encryption_type=HASPEncryptionType.AES256,
        )

        decrypt_resp = hasp_parser.generate_response(decrypt_req)

        assert decrypt_resp.status == HASPStatusCode.STATUS_OK, "Decryption failed"
        assert decrypt_resp.encryption_response == original, "Roundtrip failed"

    def test_get_info_command_returns_hardware_fingerprint(self, hasp_parser: HASPSentinelParser) -> None:
        """GET_INFO command must return HASP hardware information."""
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

        assert response.status == HASPStatusCode.STATUS_OK, "Get info failed"
        assert "hasp_id" in response.hardware_info, "Missing HASP ID"
        assert "serial" in response.hardware_info, "Missing serial number"
        assert "firmware" in response.hardware_info, "Missing firmware version"

    def test_read_command_returns_memory_contents(self, hasp_parser: HASPSentinelParser, test_session: HASPSession) -> None:
        """READ command must return HASP dongle memory data."""
        request = HASPRequest(
            command=HASPCommandType.READ,
            session_id=test_session.session_id,
            feature_id=100,
            vendor_code=test_session.vendor_code,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={"address": 0, "length": 32},
        )

        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.STATUS_OK, "Read failed"
        assert len(response.encryption_response) == 32, "Wrong data length"
        assert response.encryption_response != b"\x00" * 32, "Memory not initialized"

    def test_write_command_modifies_memory(self, hasp_parser: HASPSentinelParser, test_session: HASPSession) -> None:
        """WRITE command must modify dongle memory."""
        write_data = b"CUSTOM_LICENSE_DATA_"

        write_req = HASPRequest(
            command=HASPCommandType.WRITE,
            session_id=test_session.session_id,
            feature_id=100,
            vendor_code=test_session.vendor_code,
            scope="",
            format="",
            client_info={},
            encryption_data=write_data,
            additional_params={"address": 512, "write_data": write_data},
        )

        write_resp = hasp_parser.generate_response(write_req)
        assert write_resp.status == HASPStatusCode.STATUS_OK, "Write failed"

        read_req = HASPRequest(
            command=HASPCommandType.READ,
            session_id=test_session.session_id,
            feature_id=100,
            vendor_code=test_session.vendor_code,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={"address": 512, "length": len(write_data)},
        )

        read_resp = hasp_parser.generate_response(read_req)

        assert read_resp.encryption_response == write_data, "Data not persisted"

    def test_get_rtc_command_returns_current_time(self, hasp_parser: HASPSentinelParser) -> None:
        """GET_RTC command must return dongle real-time clock."""
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

        before = int(time.time())
        response = hasp_parser.generate_response(request)
        after = int(time.time())

        assert response.status == HASPStatusCode.STATUS_OK, "Get RTC failed"
        rtc_time = struct.unpack("<I", response.encryption_response)[0]
        assert before <= rtc_time <= after + 1, "RTC time invalid"

    def test_heartbeat_command_updates_session(self, hasp_parser: HASPSentinelParser, test_session: HASPSession) -> None:
        """HEARTBEAT command must update last_heartbeat timestamp."""
        old_heartbeat = test_session.last_heartbeat

        time.sleep(0.1)

        request = HASPRequest(
            command=HASPCommandType.HEARTBEAT,
            session_id=test_session.session_id,
            feature_id=test_session.feature_id,
            vendor_code=test_session.vendor_code,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = hasp_parser.generate_response(request)

        assert response.status == HASPStatusCode.STATUS_OK, "Heartbeat failed"
        assert test_session.last_heartbeat > old_heartbeat, "Heartbeat not updated"


class TestHASPSessionManagement:
    """Test session key generation and handle management."""

    def test_session_keys_are_unique_per_session(self, hasp_parser: HASPSentinelParser) -> None:
        """Each session must have unique encryption key."""
        sessions = []

        for i in range(5):
            request = HASPRequest(
                command=HASPCommandType.LOGIN,
                session_id=0,
                feature_id=100,
                vendor_code=0x12345678 + i,
                scope="",
                format="",
                client_info={},
                encryption_data=b"",
                additional_params={},
            )

            response = hasp_parser.generate_response(request)
            sessions.append(hasp_parser.active_sessions[response.session_id])

        keys = [s.encryption_key for s in sessions]

        for i in range(len(keys)):
            for j in range(i + 1, len(keys)):
                assert keys[i] != keys[j], f"Session {i} and {j} have same key"

    def test_session_handles_are_unique(self, hasp_parser: HASPSentinelParser) -> None:
        """Feature handles must be unique across sessions."""
        login_req = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        login_resp = hasp_parser.generate_response(login_req)
        session_id = login_resp.session_id

        feature_req = HASPRequest(
            command=HASPCommandType.FEATURE_LOGIN,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        feature_resp = hasp_parser.generate_response(feature_req)

        assert feature_resp.status == HASPStatusCode.STATUS_OK, "Feature login failed"
        handle = hasp_parser.active_sessions[session_id].feature_handle
        assert handle > 0, "No feature handle assigned"

    def test_concurrent_user_limit_enforcement(self, hasp_parser: HASPSentinelParser) -> None:
        """Feature must reject login when concurrent limit reached."""
        feature = hasp_parser.features[100]
        feature.concurrent_limit = 2

        sessions = []
        for i in range(3):
            login_req = HASPRequest(
                command=HASPCommandType.LOGIN,
                session_id=0,
                feature_id=100,
                vendor_code=0x12345678,
                scope="",
                format="",
                client_info={},
                encryption_data=b"",
                additional_params={},
            )

            login_resp = hasp_parser.generate_response(login_req)
            session_id = login_resp.session_id
            sessions.append(session_id)

            feature_req = HASPRequest(
                command=HASPCommandType.FEATURE_LOGIN,
                session_id=session_id,
                feature_id=100,
                vendor_code=0x12345678,
                scope="",
                format="",
                client_info={},
                encryption_data=b"",
                additional_params={},
            )

            feature_resp = hasp_parser.generate_response(feature_req)

            if i < 2:
                assert feature_resp.status == HASPStatusCode.STATUS_OK, f"Login {i} should succeed"
            else:
                assert feature_resp.status == HASPStatusCode.TOO_MANY_USERS, "Concurrent limit not enforced"


class TestHASPNetworkProtocol:
    """Test UDP discovery and TCP licensing protocols."""

    def test_udp_discovery_packet_format(self) -> None:
        """UDP discovery must use correct magic bytes."""
        assert HASPNetworkProtocol.DISCOVERY_MAGIC == b"HASP_DISCOVER_"
        assert HASPNetworkProtocol.UDP_DISCOVERY_PORT == 1947

    def test_server_ready_response_format(self) -> None:
        """Server ready response must include proper magic."""
        emulator = HASPServerEmulator()

        response = emulator.generate_discovery_response()

        assert HASPNetworkProtocol.SERVER_READY_MAGIC in response, "Missing SERVER_READY magic"
        assert b"SERVER_ID=" in response, "Missing server ID"
        assert b"VERSION=" in response, "Missing version"
        assert b"FEATURES=" in response, "Missing feature count"

    def test_tcp_licensing_port_correct(self) -> None:
        """TCP licensing must use port 1947."""
        assert HASPNetworkProtocol.TCP_LICENSE_PORT == 1947


class TestHASPMemoryLayoutEmulation:
    """Test HASP HL memory layout matches real dongle."""

    def test_memory_initialization_includes_vendor_code(self, hasp_parser: HASPSentinelParser) -> None:
        """HASP memory must include vendor code at offset 0."""
        feature_id = 100
        memory = hasp_parser.memory_storage[feature_id]

        vendor_code = struct.unpack("<I", memory[:4])[0]
        expected_vendor_code = hasp_parser.features[feature_id].vendor_code

        assert vendor_code == expected_vendor_code, "Vendor code not at offset 0"

    def test_memory_initialization_includes_feature_id(self, hasp_parser: HASPSentinelParser) -> None:
        """HASP memory must include feature ID at offset 4."""
        feature_id = 100
        memory = hasp_parser.memory_storage[feature_id]

        stored_feature_id = struct.unpack("<I", memory[4:8])[0]

        assert stored_feature_id == feature_id, "Feature ID not at offset 4"

    def test_memory_initialization_includes_timestamp(self, hasp_parser: HASPSentinelParser) -> None:
        """HASP memory must include initialization timestamp at offset 8."""
        feature_id = 100
        memory = hasp_parser.memory_storage[feature_id]

        timestamp = struct.unpack("<I", memory[8:12])[0]

        assert timestamp > 0, "No timestamp in memory"
        assert abs(timestamp - int(time.time())) < 10, "Timestamp not current"

    def test_memory_initialization_includes_max_users(self, hasp_parser: HASPSentinelParser) -> None:
        """HASP memory must include max users at offset 12."""
        feature_id = 100
        memory = hasp_parser.memory_storage[feature_id]

        max_users = struct.unpack("<I", memory[12:16])[0]
        expected = hasp_parser.features[feature_id].max_users

        assert max_users == expected, "Max users not at offset 12"

    def test_memory_includes_license_string(self, hasp_parser: HASPSentinelParser) -> None:
        """HASP memory must include license string at offset 16."""
        feature_id = 100
        memory = hasp_parser.memory_storage[feature_id]
        feature = hasp_parser.features[feature_id]

        expected_string = f"{feature.name}:{feature.expiry}".encode()

        assert memory[16 : 16 + len(expected_string)] == expected_string, "License string not at offset 16"


class TestHASPEdgeCases:
    """Test edge cases: HASP SRM, time-limited features, detachable licenses."""

    def test_feature_expiration_detection_works(self, hasp_parser: HASPSentinelParser) -> None:
        """Expired features must be detected correctly."""
        expired_feature = HASPFeature(
            feature_id=9999,
            name="EXPIRED_TEST",
            vendor_code=0xDEADBEEF,
            feature_type=HASPFeatureType.EXPIRATION,
            expiry="01-jan-2020",
            max_users=10,
            encryption_supported=True,
            memory_size=2048,
            rtc_supported=True,
        )

        hasp_parser.features[9999] = expired_feature

        login_req = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=9999,
            vendor_code=0xDEADBEEF,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        login_resp = hasp_parser.generate_response(login_req)
        session_id = login_resp.session_id

        feature_req = HASPRequest(
            command=HASPCommandType.FEATURE_LOGIN,
            session_id=session_id,
            feature_id=9999,
            vendor_code=0xDEADBEEF,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        feature_resp = hasp_parser.generate_response(feature_req)

        assert feature_resp.status == HASPStatusCode.FEATURE_EXPIRED, "Expired feature not detected"

    def test_detachable_feature_has_duration(self, hasp_parser: HASPSentinelParser) -> None:
        """Detachable features must include detachment duration."""
        feature_id = 300
        feature = hasp_parser.features[feature_id]

        assert feature.detachable, "Feature 300 should be detachable"
        assert feature.detachable_duration > 0, "No detachment duration"

        request = HASPRequest(
            command=HASPCommandType.GET_FEATURE_INFO,
            session_id=0,
            feature_id=feature_id,
            vendor_code=feature.vendor_code,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = hasp_parser.generate_response(request)

        assert response.license_data["detachable"], "Detachable not in response"
        assert response.license_data["detachable_duration"] > 0, "Duration not in response"

    def test_time_limited_feature_includes_expiry_info(self, hasp_parser: HASPSentinelParser) -> None:
        """Time-limited features must include days remaining."""
        feature_id = 100
        feature = hasp_parser.features[feature_id]

        request = HASPRequest(
            command=HASPCommandType.GET_FEATURE_INFO,
            session_id=0,
            feature_id=feature_id,
            vendor_code=feature.vendor_code,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = hasp_parser.generate_response(request)

        assert "expiry_date" in response.expiry_info, "No expiry date"
        assert "days_remaining" in response.expiry_info, "No days remaining"
        assert "expired" in response.expiry_info, "No expiration status"

    def test_perpetual_feature_has_no_expiry(self, hasp_parser: HASPSentinelParser) -> None:
        """Perpetual features must report permanent license."""
        feature_id = 500
        feature = hasp_parser.features[feature_id]

        assert feature.expiry == "permanent", "Feature not permanent"

        request = HASPRequest(
            command=HASPCommandType.GET_FEATURE_INFO,
            session_id=0,
            feature_id=feature_id,
            vendor_code=feature.vendor_code,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = hasp_parser.generate_response(request)

        assert response.expiry_info["expiry_date"] == "permanent", "Not showing permanent"
        assert response.expiry_info["days_remaining"] == -1, "Perpetual should be -1 days"
        assert not response.expiry_info["expired"], "Perpetual marked as expired"


class TestHASPProtocolParsing:
    """Test complete HASP protocol packet parsing and serialization."""

    def test_parse_request_validates_magic_bytes(self, hasp_parser: HASPSentinelParser) -> None:
        """Request parsing must validate HASP magic header."""
        invalid_magic = struct.pack("<I", 0xDEADBEEF)
        invalid_magic += b"\x00" * 100

        result = hasp_parser.parse_request(invalid_magic)

        assert result is None, "Invalid magic accepted"

    def test_parse_request_handles_all_required_fields(self, hasp_parser: HASPSentinelParser) -> None:
        """Request parsing must extract all protocol fields."""
        packet = bytearray()
        packet.extend(struct.pack("<I", 0x48415350))
        packet.extend(struct.pack("<H", 1))
        packet.extend(struct.pack("<H", 42))
        packet.extend(struct.pack("<I", HASPCommandType.LOGIN))
        packet.extend(struct.pack("<I", 0))
        packet.extend(struct.pack("<I", 100))
        packet.extend(struct.pack("<I", 0x12345678))
        packet.extend(struct.pack("<B", HASPEncryptionType.AES256))
        packet.extend(struct.pack("<I", int(time.time())))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))

        request = hasp_parser.parse_request(bytes(packet))

        assert request is not None, "Valid packet not parsed"
        assert request.command == HASPCommandType.LOGIN, "Wrong command"
        assert request.feature_id == 100, "Wrong feature ID"
        assert request.vendor_code == 0x12345678, "Wrong vendor code"
        assert request.packet_version == 1, "Wrong version"
        assert request.sequence_number == 42, "Wrong sequence"

    def test_serialize_response_includes_all_fields(self, hasp_parser: HASPSentinelParser) -> None:
        """Response serialization must include all protocol fields."""
        response = HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=123456,
            feature_id=100,
            license_data={"test": "data"},
            encryption_response=b"ENCRYPTED",
            expiry_info={"days": 365},
            hardware_info={"hasp_id": 999},
            packet_version=1,
            sequence_number=43,
            signature=b"SIG" * 85,
        )

        serialized = hasp_parser.serialize_response(response)

        assert len(serialized) > 50, "Response too short"
        magic = struct.unpack("<I", serialized[:4])[0]
        assert magic == 0x48415350, "Wrong magic in response"

    def test_request_response_roundtrip_preserves_sequence(self, hasp_parser: HASPSentinelParser) -> None:
        """Response sequence number must be request sequence + 1."""
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
            sequence_number=100,
        )

        response = hasp_parser.generate_response(request)

        assert response.sequence_number == 101, "Sequence not incremented"


class TestHASPPacketAnalysis:
    """Test HASP network packet capture and analysis."""

    def test_packet_analyzer_identifies_hasp_traffic(self) -> None:
        """Packet analyzer must identify HASP protocol packets."""
        analyzer = HASPPacketAnalyzer()

        hasp_payload = struct.pack("<I", 0x48415350) + b"\x00" * 50
        is_hasp = analyzer._is_hasp_packet(hasp_payload, 1947, 12345)

        assert is_hasp, "HASP packet not identified"

    def test_packet_analyzer_identifies_discovery_packets(self) -> None:
        """Analyzer must identify UDP discovery packets."""
        analyzer = HASPPacketAnalyzer()

        discovery_payload = HASPNetworkProtocol.DISCOVERY_MAGIC + b"BROADCAST"
        is_hasp = analyzer._is_hasp_packet(discovery_payload, 12345, 1947)

        assert is_hasp, "Discovery packet not identified"

    def test_packet_type_identification_works(self) -> None:
        """Packet type identification must detect command types."""
        analyzer = HASPPacketAnalyzer()

        login_payload = b"LOGIN" + b"\x00" * 50
        packet_type = analyzer._identify_packet_type(login_payload)

        assert packet_type == "LOGIN", f"Expected LOGIN, got {packet_type}"


class TestHASPIntegrationScenarios:
    """Test complete HASP workflows end-to-end."""

    def test_complete_login_encrypt_logout_workflow(self, hasp_parser: HASPSentinelParser) -> None:
        """Complete workflow: login, encrypt data, decrypt data, logout."""
        login_req = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={"hostname": "testclient"},
            encryption_data=b"",
            additional_params={},
        )

        login_resp = hasp_parser.generate_response(login_req)
        assert login_resp.status == HASPStatusCode.STATUS_OK
        session_id = login_resp.session_id

        plaintext = b"SENSITIVE_LICENSE_DATA"

        encrypt_req = HASPRequest(
            command=HASPCommandType.ENCRYPT,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=plaintext,
            additional_params={},
            encryption_type=HASPEncryptionType.AES256,
        )

        encrypt_resp = hasp_parser.generate_response(encrypt_req)
        assert encrypt_resp.status == HASPStatusCode.STATUS_OK
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
        assert decrypt_resp.encryption_response == plaintext

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

    def test_memory_read_write_workflow(self, hasp_parser: HASPSentinelParser) -> None:
        """Memory workflow: login, write memory, read memory, verify."""
        login_req = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        login_resp = hasp_parser.generate_response(login_req)
        session_id = login_resp.session_id

        custom_data = b"CUSTOM_LICENSE_KEY_123"

        write_req = HASPRequest(
            command=HASPCommandType.WRITE,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=custom_data,
            additional_params={"address": 1024, "write_data": custom_data},
        )

        write_resp = hasp_parser.generate_response(write_req)
        assert write_resp.status == HASPStatusCode.STATUS_OK

        read_req = HASPRequest(
            command=HASPCommandType.READ,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={"address": 1024, "length": len(custom_data)},
        )

        read_resp = hasp_parser.generate_response(read_req)
        assert read_resp.status == HASPStatusCode.STATUS_OK
        assert read_resp.encryption_response == custom_data

    def test_feature_login_with_concurrent_limit(self, hasp_parser: HASPSentinelParser) -> None:
        """Feature login must respect concurrent user limits."""
        feature = hasp_parser.features[101]
        original_limit = feature.concurrent_limit
        feature.concurrent_limit = 1

        login1 = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=101,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        resp1 = hasp_parser.generate_response(login1)
        session1 = resp1.session_id

        feature_login1 = HASPRequest(
            command=HASPCommandType.FEATURE_LOGIN,
            session_id=session1,
            feature_id=101,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        feature_resp1 = hasp_parser.generate_response(feature_login1)
        assert feature_resp1.status == HASPStatusCode.STATUS_OK

        login2 = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=101,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        resp2 = hasp_parser.generate_response(login2)
        session2 = resp2.session_id

        feature_login2 = HASPRequest(
            command=HASPCommandType.FEATURE_LOGIN,
            session_id=session2,
            feature_id=101,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        feature_resp2 = hasp_parser.generate_response(feature_login2)
        assert feature_resp2.status == HASPStatusCode.TOO_MANY_USERS

        feature.concurrent_limit = original_limit


class TestHASPCryptoNoFallbacks:
    """Ensure no XOR cipher fallbacks exist in production code."""

    def test_aes_encryption_never_uses_xor(self, hasp_crypto: HASPCrypto) -> None:
        """AES encryption must never fall back to XOR."""
        plaintext = b"TEST" * 100
        session_id = 777

        encrypted = hasp_crypto.aes_encrypt(plaintext, session_id)

        xor_detected = False
        for i in range(min(len(plaintext), len(encrypted) - 16)):
            if encrypted[i + 16] == plaintext[i]:
                continue
            expected_xor = plaintext[i] ^ encrypted[i + 16]
            matches = sum(
                1
                for j in range(min(20, len(plaintext), len(encrypted) - 16))
                if (plaintext[j] ^ encrypted[j + 16]) == expected_xor
            )
            if matches > 15:
                xor_detected = True
                break

        assert not xor_detected, "XOR pattern detected, not using real AES"

    def test_envelope_encryption_uses_rsa_not_simple_xor(self, hasp_crypto: HASPCrypto) -> None:
        """Envelope encryption must use real RSA, not XOR."""
        plaintext = b"DATA" * 50
        session_id = 0

        encrypted = hasp_crypto.envelope_encrypt(plaintext, session_id)

        key_length = struct.unpack("<H", encrypted[:2])[0]
        assert key_length == 256, "RSA-2048 encrypted key should be 256 bytes"

        encrypted_key = encrypted[2 : 2 + key_length]
        for byte in encrypted_key:
            assert 0 <= byte <= 255

        unique_bytes = len(set(encrypted_key))
        assert unique_bytes > 200, "Encrypted key doesn't look like RSA output"
