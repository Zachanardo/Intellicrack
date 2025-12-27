"""Production tests for HASP protocol parser with real traffic validation.

Tests that validate actual HASP/Sentinel protocol parsing, response generation,
and handling of corrupted/malformed packets. These tests verify genuine protocol
implementation against real HASP license server traffic patterns.
"""

import secrets
import struct
import time
from typing import Any

import pytest

from intellicrack.core.network.protocols.hasp_parser import (
    HASPCommandType,
    HASPCrypto,
    HASPEncryptionType,
    HASPFeature,
    HASPFeatureType,
    HASPRequest,
    HASPResponse,
    HASPSentinelParser,
    HASPStatusCode,
)


class TestHASPProtocolParsing:
    """Test suite for HASP protocol request parsing with real packet validation."""

    @pytest.fixture
    def parser(self) -> HASPSentinelParser:
        """Create HASPSentinelParser instance."""
        return HASPSentinelParser()

    def test_parse_valid_login_request(self, parser: HASPSentinelParser) -> None:
        """Test parsing of valid HASP login request packet.

        Validates that parser correctly extracts all fields from properly formatted
        HASP login request matching real network traffic.
        """
        packet = bytearray()
        packet.extend(struct.pack("<I", 0x48415350))
        packet.extend(struct.pack("<H", 1))
        packet.extend(struct.pack("<H", 1000))
        packet.extend(struct.pack("<I", HASPCommandType.LOGIN))
        packet.extend(struct.pack("<I", 0))
        packet.extend(struct.pack("<I", 100))
        packet.extend(struct.pack("<I", 0x12345678))
        packet.extend(struct.pack("<B", HASPEncryptionType.NONE))
        packet.extend(struct.pack("<I", int(time.time())))

        scope = "<?hasp scope=\"local\" />"
        packet.extend(struct.pack("<H", len(scope)))
        packet.extend(scope.encode("utf-8"))

        format_str = "format"
        packet.extend(struct.pack("<H", len(format_str)))
        packet.extend(format_str.encode("utf-8"))

        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))

        request = parser.parse_request(bytes(packet))

        assert request is not None
        assert request.command == HASPCommandType.LOGIN
        assert request.feature_id == 100
        assert request.vendor_code == 0x12345678
        assert request.scope == scope
        assert request.format == format_str

    def test_parse_request_with_corrupted_magic_number(self, parser: HASPSentinelParser) -> None:
        """Test parsing rejects packet with corrupted magic number.

        Validates that parser correctly identifies and rejects packets with
        invalid magic signatures.
        """
        packet = bytearray()
        packet.extend(struct.pack("<I", 0xDEADBEEF))
        packet.extend(struct.pack("<H", 1))
        packet.extend(struct.pack("<H", 1000))
        packet.extend(struct.pack("<I", HASPCommandType.LOGIN))

        request = parser.parse_request(bytes(packet))

        assert request is None

    def test_parse_request_with_truncated_packet(self, parser: HASPSentinelParser) -> None:
        """Test parsing handles truncated packet gracefully.

        Validates that parser doesn't crash on incomplete packets and returns None.
        """
        packet = bytearray()
        packet.extend(struct.pack("<I", 0x48415350))
        packet.extend(struct.pack("<H", 1))

        request = parser.parse_request(bytes(packet))

        assert request is None

    def test_parse_encrypt_request_with_data(self, parser: HASPSentinelParser) -> None:
        """Test parsing HASP encryption request with actual data payload.

        Validates that encryption data is correctly extracted from request.
        """
        packet = bytearray()
        packet.extend(struct.pack("<I", 0x48415350))
        packet.extend(struct.pack("<H", 1))
        packet.extend(struct.pack("<H", 2000))
        packet.extend(struct.pack("<I", HASPCommandType.ENCRYPT))
        packet.extend(struct.pack("<I", 12345))
        packet.extend(struct.pack("<I", 100))
        packet.extend(struct.pack("<I", 0x12345678))
        packet.extend(struct.pack("<B", HASPEncryptionType.AES256))
        packet.extend(struct.pack("<I", int(time.time())))

        scope = ""
        packet.extend(struct.pack("<H", len(scope)))

        format_str = ""
        packet.extend(struct.pack("<H", len(format_str)))

        packet.extend(struct.pack("<H", 0))

        encryption_data = b"Test encryption data payload"
        packet.extend(struct.pack("<H", len(encryption_data)))
        packet.extend(encryption_data)

        packet.extend(struct.pack("<H", 0))

        request = parser.parse_request(bytes(packet))

        assert request is not None
        assert request.command == HASPCommandType.ENCRYPT
        assert request.session_id == 12345
        assert request.encryption_type == HASPEncryptionType.AES256
        assert request.encryption_data == encryption_data

    def test_parse_request_with_malformed_json_client_info(self, parser: HASPSentinelParser) -> None:
        """Test parsing handles malformed JSON in client_info field.

        Validates that parser handles corrupted client info without crashing.
        """
        packet = bytearray()
        packet.extend(struct.pack("<I", 0x48415350))
        packet.extend(struct.pack("<H", 1))
        packet.extend(struct.pack("<H", 3000))
        packet.extend(struct.pack("<I", HASPCommandType.LOGIN))
        packet.extend(struct.pack("<I", 0))
        packet.extend(struct.pack("<I", 100))
        packet.extend(struct.pack("<I", 0x12345678))
        packet.extend(struct.pack("<B", HASPEncryptionType.NONE))
        packet.extend(struct.pack("<I", int(time.time())))

        scope = ""
        packet.extend(struct.pack("<H", len(scope)))

        format_str = ""
        packet.extend(struct.pack("<H", len(format_str)))

        malformed_json = b"{invalid json syntax"
        packet.extend(struct.pack("<H", len(malformed_json)))
        packet.extend(malformed_json)

        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))

        request = parser.parse_request(bytes(packet))

        assert request is not None
        assert request.client_info == {}

    def test_parse_request_with_oversized_scope_field(self, parser: HASPSentinelParser) -> None:
        """Test parsing handles scope field claiming size larger than packet.

        Validates that parser detects and rejects malformed length fields.
        """
        packet = bytearray()
        packet.extend(struct.pack("<I", 0x48415350))
        packet.extend(struct.pack("<H", 1))
        packet.extend(struct.pack("<H", 4000))
        packet.extend(struct.pack("<I", HASPCommandType.LOGIN))
        packet.extend(struct.pack("<I", 0))
        packet.extend(struct.pack("<I", 100))
        packet.extend(struct.pack("<I", 0x12345678))
        packet.extend(struct.pack("<B", HASPEncryptionType.NONE))
        packet.extend(struct.pack("<I", int(time.time())))

        packet.extend(struct.pack("<H", 0xFFFF))
        packet.extend(b"short")

        request = parser.parse_request(bytes(packet))

        assert request is None


class TestHASPResponseGeneration:
    """Test suite for HASP response generation with real protocol compliance."""

    @pytest.fixture
    def parser(self) -> HASPSentinelParser:
        """Create HASPSentinelParser instance."""
        return HASPSentinelParser()

    def test_login_response_includes_session_id(self, parser: HASPSentinelParser) -> None:
        """Test that login response generates valid session ID.

        Validates that login response contains proper session establishment
        data as expected by real HASP clients.
        """
        request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
            packet_version=1,
            sequence_number=1,
        )

        response = parser.generate_response(request)

        assert response.status == HASPStatusCode.STATUS_OK
        assert response.session_id > 0
        assert "session_established" in response.license_data
        assert response.license_data["session_established"] is True

    def test_login_with_invalid_vendor_code_returns_error(self, parser: HASPSentinelParser) -> None:
        """Test that login with unknown vendor code returns appropriate error.

        Validates proper error handling for invalid vendor codes.
        """
        request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0xDEADBEEF,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = parser.generate_response(request)

        assert response.status == HASPStatusCode.INVALID_VENDOR_CODE

    def test_encrypt_decrypt_roundtrip_preserves_data(self, parser: HASPSentinelParser) -> None:
        """Test that encrypt/decrypt roundtrip preserves original data.

        Validates that HASP encryption/decryption cycle produces correct results
        matching real dongle behavior.
        """
        login_request = HASPRequest(
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

        login_response = parser.generate_response(login_request)
        session_id = login_response.session_id

        original_data = b"Sensitive licensing data to encrypt"

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

        encrypt_response = parser.generate_response(encrypt_request)

        assert encrypt_response.status == HASPStatusCode.STATUS_OK
        encrypted_data = encrypt_response.encryption_response

        decrypt_request = HASPRequest(
            command=HASPCommandType.DECRYPT,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=encrypted_data,
            additional_params={},
            encryption_type=HASPEncryptionType.AES256,
        )

        decrypt_response = parser.generate_response(decrypt_request)

        assert decrypt_response.status == HASPStatusCode.STATUS_OK
        decrypted_data = decrypt_response.encryption_response

        assert decrypted_data == original_data

    def test_feature_login_checks_concurrent_limit(self, parser: HASPSentinelParser) -> None:
        """Test that feature login enforces concurrent user limits.

        Validates that concurrent license limits are properly enforced as in
        real HASP license servers.
        """
        session_ids = []

        for i in range(101):
            login_request = HASPRequest(
                command=HASPCommandType.LOGIN,
                session_id=0,
                feature_id=100,
                vendor_code=0x12345678,
                scope="",
                format="",
                client_info={"client": f"client_{i}"},
                encryption_data=b"",
                additional_params={},
            )

            login_response = parser.generate_response(login_request)

            if login_response.status == HASPStatusCode.STATUS_OK:
                session_ids.append(login_response.session_id)

                feature_login_request = HASPRequest(
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

                feature_response = parser.generate_response(feature_login_request)

                if i < 100:
                    assert feature_response.status == HASPStatusCode.STATUS_OK
                else:
                    assert feature_response.status == HASPStatusCode.TOO_MANY_USERS

    def test_memory_read_write_operations(self, parser: HASPSentinelParser) -> None:
        """Test HASP memory read/write operations work correctly.

        Validates that dongle memory emulation correctly stores and retrieves data.
        """
        login_request = HASPRequest(
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

        login_response = parser.generate_response(login_request)
        session_id = login_response.session_id

        write_data = b"LICENSE_KEY_DATA"
        write_address = 256

        write_request = HASPRequest(
            command=HASPCommandType.WRITE,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={"address": write_address, "write_data": write_data},
        )

        write_response = parser.generate_response(write_request)

        assert write_response.status == HASPStatusCode.STATUS_OK
        assert write_response.license_data["bytes_written"] == len(write_data)

        read_request = HASPRequest(
            command=HASPCommandType.READ,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={"address": write_address, "length": len(write_data)},
        )

        read_response = parser.generate_response(read_request)

        assert read_response.status == HASPStatusCode.STATUS_OK
        assert read_response.encryption_response == write_data


class TestHASPCryptographicOperations:
    """Test suite for HASP cryptographic operations."""

    @pytest.fixture
    def crypto(self) -> HASPCrypto:
        """Create HASPCrypto instance."""
        return HASPCrypto()

    def test_aes_encryption_produces_different_ciphertext(self, crypto: HASPCrypto) -> None:
        """Test that AES encryption produces different ciphertext for same plaintext.

        Validates that IV randomization produces different ciphertext on each call.
        """
        plaintext = b"Test data for encryption"

        ciphertext1 = crypto.aes_encrypt(plaintext, session_id=0)
        ciphertext2 = crypto.aes_encrypt(plaintext, session_id=0)

        assert ciphertext1 != ciphertext2

    def test_aes_decrypt_handles_corrupted_iv(self, crypto: HASPCrypto) -> None:
        """Test AES decryption handles corrupted IV gracefully.

        Validates that corrupted encryption data doesn't crash decryption.
        """
        corrupted_data = b"CORRUPTED_IV_AND_CIPHERTEXT" + secrets.token_bytes(32)

        decrypted = crypto.aes_decrypt(corrupted_data, session_id=0)

        assert isinstance(decrypted, bytes)

    def test_hasp4_encryption_is_reversible(self, crypto: HASPCrypto) -> None:
        """Test that HASP4 legacy encryption is properly reversible.

        Validates that HASP4 stream cipher encryption/decryption works correctly.
        """
        plaintext = b"Legacy HASP4 protected data"
        seed = 0x12345678

        ciphertext = crypto.hasp4_encrypt(plaintext, seed)
        decrypted = crypto.hasp4_decrypt(ciphertext, seed)

        assert decrypted == plaintext

    def test_rsa_signature_verification_accepts_valid_signature(self, crypto: HASPCrypto) -> None:
        """Test that RSA signature verification accepts valid signatures.

        Validates RSA-PSS signature generation and verification.
        """
        data = b"Data to be signed"

        signature = crypto.rsa_sign(data, session_id=0)

        is_valid = crypto.rsa_verify(data, signature, session_id=0)

        assert is_valid is True

    def test_rsa_signature_verification_rejects_invalid_signature(self, crypto: HASPCrypto) -> None:
        """Test that RSA signature verification rejects invalid signatures.

        Validates that signature verification correctly detects tampering.
        """
        data = b"Data to be signed"
        wrong_data = b"Different data"

        signature = crypto.rsa_sign(data, session_id=0)

        is_valid = crypto.rsa_verify(wrong_data, signature, session_id=0)

        assert is_valid is False

    def test_envelope_encryption_preserves_data(self, crypto: HASPCrypto) -> None:
        """Test that envelope encryption (RSA + AES) preserves data integrity.

        Validates hybrid encryption scheme used in modern HASP implementations.
        """
        plaintext = b"Sensitive data for envelope encryption"

        encrypted = crypto.envelope_encrypt(plaintext, session_id=0)

        decrypted = crypto.envelope_decrypt(encrypted, session_id=0)

        assert decrypted == plaintext

    def test_hasp4_keystream_produces_consistent_output(self, crypto: HASPCrypto) -> None:
        """Test that HASP4 LFSR keystream is deterministic.

        Validates that same seed produces same keystream for HASP4 encryption.
        """
        seed = 0xABCDEF12
        length = 256

        keystream1 = crypto._generate_hasp4_keystream(seed, length)
        keystream2 = crypto._generate_hasp4_keystream(seed, length)

        assert keystream1 == keystream2
        assert len(keystream1) == length


class TestHASPResponseSerialization:
    """Test suite for HASP response serialization."""

    @pytest.fixture
    def parser(self) -> HASPSentinelParser:
        """Create HASPSentinelParser instance."""
        return HASPSentinelParser()

    def test_serialize_response_produces_valid_packet(self, parser: HASPSentinelParser) -> None:
        """Test that response serialization produces valid HASP packet.

        Validates that serialized response can be transmitted over network.
        """
        response = HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=12345,
            feature_id=100,
            license_data={"test_key": "test_value"},
            encryption_response=b"encrypted_data",
            expiry_info={"days_remaining": 365},
            hardware_info={"hasp_id": 123456},
        )

        serialized = parser.serialize_response(response)

        assert len(serialized) > 24
        assert serialized[:4] == struct.pack("<I", 0x48415350)

    def test_serialize_response_handles_empty_fields(self, parser: HASPSentinelParser) -> None:
        """Test response serialization handles empty fields correctly.

        Validates that empty dictionaries and bytes are properly serialized.
        """
        response = HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=0,
            feature_id=0,
            license_data={},
            encryption_response=b"",
            expiry_info={},
            hardware_info={},
        )

        serialized = parser.serialize_response(response)

        assert len(serialized) >= 24

    def test_serialize_response_handles_large_license_data(self, parser: HASPSentinelParser) -> None:
        """Test response serialization handles large license data.

        Validates that large license information dictionaries are properly serialized.
        """
        large_license_data = {f"key_{i}": f"value_{i}" * 100 for i in range(50)}

        response = HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=12345,
            feature_id=100,
            license_data=large_license_data,
            encryption_response=b"",
            expiry_info={},
            hardware_info={},
        )

        serialized = parser.serialize_response(response)

        assert len(serialized) > 1000


class TestHASPFeatureManagement:
    """Test suite for HASP feature management operations."""

    @pytest.fixture
    def parser(self) -> HASPSentinelParser:
        """Create HASPSentinelParser instance."""
        return HASPSentinelParser()

    def test_add_custom_feature_available_for_login(self, parser: HASPSentinelParser) -> None:
        """Test that custom added features are available for login.

        Validates that dynamically added features can be used for licensing.
        """
        custom_feature = HASPFeature(
            feature_id=9999,
            name="CUSTOM_FEATURE",
            vendor_code=0xC0510001,
            feature_type=HASPFeatureType.PERPETUAL,
            expiry="permanent",
            max_users=10,
            encryption_supported=True,
            memory_size=2048,
            rtc_supported=True,
        )

        parser.add_feature(custom_feature)

        assert 9999 in parser.features
        assert parser.features[9999].name == "CUSTOM_FEATURE"

    def test_remove_feature_prevents_future_logins(self, parser: HASPSentinelParser) -> None:
        """Test that removing feature prevents new logins.

        Validates that feature removal properly disables access.
        """
        parser.remove_feature(100)

        assert 100 not in parser.features

        request = HASPRequest(
            command=HASPCommandType.FEATURE_LOGIN,
            session_id=12345,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = parser.generate_response(request)

        assert response.status == HASPStatusCode.NOT_LOGGED_IN or response.status == HASPStatusCode.FEATURE_NOT_FOUND
