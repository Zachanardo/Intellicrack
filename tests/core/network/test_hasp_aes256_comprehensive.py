"""Comprehensive production tests for HASP AES-256 encryption and protocol capabilities.

Tests the complete HASP/Sentinel licensing protection bypass implementation focusing on:
- Real AES-256 encryption for HASP HL/SL communication
- USB authentication flow (challenge-response)
- All HASP command types (login, encrypt, decrypt, get info)
- Session key and handle generation
- HASP network protocol (UDP discovery, TCP licensing)
- HASP HL memory layout emulation
- Edge cases: HASP SRM, time-limited features, concurrent user limits

NO MOCKS - All tests use real cryptographic operations and protocol structures.
Tests MUST FAIL if functionality is incomplete or non-functional.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import secrets
import socket
import struct
import time
from typing import Any

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from intellicrack.core.network.protocols.hasp_parser import (
    HASPCommandType,
    HASPCrypto,
    HASPEncryptionType,
    HASPFeature,
    HASPFeatureType,
    HASPNetworkProtocol,
    HASPRequest,
    HASPResponse,
    HASPSentinelParser,
    HASPSession,
    HASPStatusCode,
    HASPUSBProtocol,
)


class TestHASPAES256Encryption:
    """Test real AES-256 encryption for HASP HL/SL communication."""

    def test_aes256_encryption_uses_32_byte_key(self) -> None:
        """AES-256 encryption uses genuine 256-bit (32-byte) keys."""
        crypto = HASPCrypto()

        assert len(crypto.aes_keys[0]) == 32
        assert all(isinstance(byte, int) and 0 <= byte <= 255 for byte in crypto.aes_keys[0])

    def test_aes256_encrypt_produces_different_ciphertext_each_time(self) -> None:
        """AES-256 encryption produces different ciphertext for same plaintext due to random IV."""
        crypto = HASPCrypto()
        plaintext = b"HASP license protection data"

        ciphertext1 = crypto.aes_encrypt(plaintext, 0)
        ciphertext2 = crypto.aes_encrypt(plaintext, 0)

        assert ciphertext1 != ciphertext2
        assert len(ciphertext1) >= 16
        assert len(ciphertext2) >= 16

    def test_aes256_encrypt_includes_iv_prepended(self) -> None:
        """AES-256 encryption includes IV as first 16 bytes."""
        crypto = HASPCrypto()
        plaintext = b"test data"

        ciphertext = crypto.aes_encrypt(plaintext, 0)

        assert len(ciphertext) >= 16
        iv = ciphertext[:16]
        assert len(iv) == 16

    def test_aes256_encrypt_applies_pkcs7_padding(self) -> None:
        """AES-256 encryption applies correct PKCS7 padding."""
        crypto = HASPCrypto()

        plaintext_15_bytes = b"A" * 15
        ciphertext = crypto.aes_encrypt(plaintext_15_bytes, 0)
        iv = ciphertext[:16]
        encrypted_padded = ciphertext[16:]

        assert len(encrypted_padded) % 16 == 0
        assert len(encrypted_padded) == 16

    def test_aes256_decrypt_reverses_encryption(self) -> None:
        """AES-256 decryption successfully reverses encryption."""
        crypto = HASPCrypto()
        plaintext = b"HASP dongle emulation requires correct AES-256 implementation"

        ciphertext = crypto.aes_encrypt(plaintext, 0)
        decrypted = crypto.aes_decrypt(ciphertext, 0)

        assert decrypted == plaintext

    def test_aes256_decrypt_fails_with_wrong_key(self) -> None:
        """AES-256 decryption with wrong key produces garbage data."""
        crypto = HASPCrypto()
        plaintext = b"sensitive license data"

        session_id_1 = 12345
        session_id_2 = 67890
        crypto.generate_session_key(session_id_1, 0x11111111)
        crypto.generate_session_key(session_id_2, 0x22222222)

        ciphertext = crypto.aes_encrypt(plaintext, session_id_1)
        decrypted_wrong_key = crypto.aes_decrypt(ciphertext, session_id_2)

        assert decrypted_wrong_key != plaintext

    def test_aes256_handles_large_data_blocks(self) -> None:
        """AES-256 encryption handles large data blocks correctly."""
        crypto = HASPCrypto()
        plaintext = b"X" * 10000

        ciphertext = crypto.aes_encrypt(plaintext, 0)
        decrypted = crypto.aes_decrypt(ciphertext, 0)

        assert decrypted == plaintext
        assert len(ciphertext) > len(plaintext)

    def test_aes256_handles_empty_data(self) -> None:
        """AES-256 encryption handles empty data with correct padding."""
        crypto = HASPCrypto()
        plaintext = b""

        ciphertext = crypto.aes_encrypt(plaintext, 0)
        decrypted = crypto.aes_decrypt(ciphertext, 0)

        assert decrypted == plaintext

    def test_aes256_session_key_generation_uses_unique_values(self) -> None:
        """Session key generation produces unique keys for different sessions."""
        crypto = HASPCrypto()

        key1 = crypto.generate_session_key(1000, 0x12345678)
        key2 = crypto.generate_session_key(2000, 0x87654321)
        key3 = crypto.generate_session_key(3000, 0x12345678)

        assert key1 != key2
        assert key1 != key3
        assert key2 != key3
        assert len(key1) == 32
        assert len(key2) == 32
        assert len(key3) == 32

    def test_aes256_encryption_mode_is_cbc(self) -> None:
        """AES-256 uses CBC mode with proper IV handling."""
        crypto = HASPCrypto()
        plaintext = b"CBC mode test data for HASP"

        ciphertext = crypto.aes_encrypt(plaintext, 0)

        iv = ciphertext[:16]
        encrypted_data = ciphertext[16:]

        key = crypto.aes_keys[0]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(encrypted_data) + decryptor.finalize()

        padding_length = padded_plaintext[-1]
        recovered_plaintext = padded_plaintext[:-padding_length]

        assert recovered_plaintext == plaintext


class TestHASPUSBAuthenticationFlow:
    """Test USB authentication challenge-response flow."""

    def test_usb_protocol_constants_defined(self) -> None:
        """USB protocol constants are correctly defined for HASP dongles."""
        assert HASPUSBProtocol.USB_VENDOR_ID == 0x0529
        assert 0x0001 in HASPUSBProtocol.USB_PRODUCT_IDS
        assert 0x0002 in HASPUSBProtocol.USB_PRODUCT_IDS

    def test_usb_command_types_complete(self) -> None:
        """All USB command types are defined."""
        assert HASPUSBProtocol.CMD_READ_MEMORY == 0x01
        assert HASPUSBProtocol.CMD_WRITE_MEMORY == 0x02
        assert HASPUSBProtocol.CMD_ENCRYPT == 0x03
        assert HASPUSBProtocol.CMD_DECRYPT == 0x04
        assert HASPUSBProtocol.CMD_GET_INFO == 0x05
        assert HASPUSBProtocol.CMD_GET_RTC == 0x06

    def test_login_generates_session_with_encryption_key(self) -> None:
        """Login generates session with encryption key for challenge-response."""
        parser = HASPSentinelParser()

        request = self._create_login_request(0x12345678, 100)
        response = parser.generate_response(request)

        assert response.status == HASPStatusCode.STATUS_OK
        assert response.session_id > 0
        assert response.session_id in parser.active_sessions

        session = parser.active_sessions[response.session_id]
        assert len(session.encryption_key) == 32

    def test_login_challenge_response_with_encryption(self) -> None:
        """Login implements challenge-response using encryption key."""
        parser = HASPSentinelParser()

        login_request = self._create_login_request(0x12345678, 100)
        login_response = parser.generate_response(login_request)
        session_id = login_response.session_id

        challenge_data = b"HASP_CHALLENGE_DATA_FOR_AUTHENTICATION"
        encrypt_request = self._create_encrypt_request(session_id, 100, challenge_data)
        encrypt_response = parser.generate_response(encrypt_request)

        assert encrypt_response.status == HASPStatusCode.STATUS_OK
        assert len(encrypt_response.encryption_response) > 0
        assert encrypt_response.encryption_response != challenge_data

        decrypt_request = self._create_decrypt_request(
            session_id, 100, encrypt_response.encryption_response
        )
        decrypt_response = parser.generate_response(decrypt_request)

        assert decrypt_response.status == HASPStatusCode.STATUS_OK
        assert decrypt_response.encryption_response == challenge_data

    def test_session_key_unique_per_vendor_code(self) -> None:
        """Session keys are unique based on vendor code."""
        crypto = HASPCrypto()

        key1 = crypto.generate_session_key(12345, 0x11111111)
        key2 = crypto.generate_session_key(12345, 0x22222222)

        assert key1 != key2

    def test_session_key_derived_from_session_and_vendor(self) -> None:
        """Session key derivation uses session ID and vendor code."""
        crypto = HASPCrypto()

        session_id = 100000
        vendor_code = 0x12345678

        key = crypto.generate_session_key(session_id, vendor_code)

        assert key in crypto.aes_keys.values()
        assert session_id in crypto.aes_keys
        assert crypto.aes_keys[session_id] == key

    def _create_login_request(self, vendor_code: int, feature_id: int) -> HASPRequest:
        """Helper to create login request."""
        return HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=feature_id,
            vendor_code=vendor_code,
            scope="",
            format="",
            client_info={"hostname": "test-machine", "username": "researcher"},
            encryption_data=b"",
            additional_params={},
        )

    def _create_encrypt_request(
        self, session_id: int, feature_id: int, data: bytes
    ) -> HASPRequest:
        """Helper to create encrypt request."""
        return HASPRequest(
            command=HASPCommandType.ENCRYPT,
            session_id=session_id,
            feature_id=feature_id,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=data,
            additional_params={},
            encryption_type=HASPEncryptionType.AES256,
        )

    def _create_decrypt_request(
        self, session_id: int, feature_id: int, data: bytes
    ) -> HASPRequest:
        """Helper to create decrypt request."""
        return HASPRequest(
            command=HASPCommandType.DECRYPT,
            session_id=session_id,
            feature_id=feature_id,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=data,
            additional_params={},
            encryption_type=HASPEncryptionType.AES256,
        )


class TestHASPCommandTypes:
    """Test all HASP command types work correctly."""

    def test_login_command_creates_session(self) -> None:
        """LOGIN command creates active session with unique ID."""
        parser = HASPSentinelParser()

        request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={"hostname": "test"},
            encryption_data=b"",
            additional_params={},
        )

        response = parser.generate_response(request)

        assert response.status == HASPStatusCode.STATUS_OK
        assert response.session_id > 0
        assert response.session_id in parser.active_sessions

    def test_logout_command_destroys_session(self) -> None:
        """LOGOUT command destroys active session."""
        parser = HASPSentinelParser()

        login_req = self._create_command_request(HASPCommandType.LOGIN, 0, 100)
        login_resp = parser.generate_response(login_req)
        session_id = login_resp.session_id

        logout_req = self._create_command_request(HASPCommandType.LOGOUT, session_id, 100)
        logout_resp = parser.generate_response(logout_req)

        assert logout_resp.status == HASPStatusCode.STATUS_OK
        assert session_id not in parser.active_sessions

    def test_encrypt_command_encrypts_data(self) -> None:
        """ENCRYPT command encrypts data with session key."""
        parser = HASPSentinelParser()

        session_id = self._establish_session(parser, 100)
        plaintext = b"data to encrypt with HASP dongle"

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

        response = parser.generate_response(encrypt_req)

        assert response.status == HASPStatusCode.STATUS_OK
        assert len(response.encryption_response) > 0
        assert response.encryption_response != plaintext

    def test_decrypt_command_decrypts_data(self) -> None:
        """DECRYPT command decrypts previously encrypted data."""
        parser = HASPSentinelParser()

        session_id = self._establish_session(parser, 100)
        plaintext = b"confidential license information"

        ciphertext = parser.crypto.aes_encrypt(plaintext, session_id)

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

        response = parser.generate_response(decrypt_req)

        assert response.status == HASPStatusCode.STATUS_OK
        assert response.encryption_response == plaintext

    def test_get_info_command_returns_hardware_info(self) -> None:
        """GET_INFO command returns dongle hardware information."""
        parser = HASPSentinelParser()

        session_id = self._establish_session(parser, 100)

        info_req = self._create_command_request(
            HASPCommandType.GET_INFO, session_id, 100
        )
        response = parser.generate_response(info_req)

        assert response.status == HASPStatusCode.STATUS_OK
        assert "hasp_id" in response.hardware_info
        assert "type" in response.hardware_info
        assert "serial" in response.hardware_info

    def test_get_size_command_returns_memory_size(self) -> None:
        """GET_SIZE command returns feature memory size."""
        parser = HASPSentinelParser()

        session_id = self._establish_session(parser, 100)

        size_req = self._create_command_request(
            HASPCommandType.GET_SIZE, session_id, 100
        )
        response = parser.generate_response(size_req)

        assert response.status == HASPStatusCode.STATUS_OK
        assert "memory_size" in response.license_data
        assert response.license_data["memory_size"] > 0

    def test_read_command_reads_memory(self) -> None:
        """READ command reads data from dongle memory."""
        parser = HASPSentinelParser()

        session_id = self._establish_session(parser, 100)

        read_req = HASPRequest(
            command=HASPCommandType.READ,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={"address": 0, "length": 64},
        )

        response = parser.generate_response(read_req)

        assert response.status == HASPStatusCode.STATUS_OK
        assert len(response.encryption_response) == 64

    def test_write_command_writes_memory(self) -> None:
        """WRITE command writes data to dongle memory."""
        parser = HASPSentinelParser()

        session_id = self._establish_session(parser, 100)
        write_data = b"LICENSE_KEY_DATA_12345678"

        write_req = HASPRequest(
            command=HASPCommandType.WRITE,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={"address": 100, "write_data": write_data},
        )

        write_resp = parser.generate_response(write_req)
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
            additional_params={"address": 100, "length": len(write_data)},
        )

        read_resp = parser.generate_response(read_req)
        assert read_resp.encryption_response == write_data

    def test_get_rtc_command_returns_time(self) -> None:
        """GET_RTC command returns real-time clock value."""
        parser = HASPSentinelParser()

        session_id = self._establish_session(parser, 100)

        rtc_req = self._create_command_request(
            HASPCommandType.GET_RTC, session_id, 100
        )
        response = parser.generate_response(rtc_req)

        assert response.status == HASPStatusCode.STATUS_OK
        assert "rtc_time" in response.license_data

    def _establish_session(self, parser: HASPSentinelParser, feature_id: int) -> int:
        """Helper to establish authenticated session."""
        login_req = self._create_command_request(HASPCommandType.LOGIN, 0, feature_id)
        login_resp = parser.generate_response(login_req)
        return login_resp.session_id

    def _create_command_request(
        self, command: HASPCommandType, session_id: int, feature_id: int
    ) -> HASPRequest:
        """Helper to create generic command request."""
        return HASPRequest(
            command=command,
            session_id=session_id,
            feature_id=feature_id,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )


class TestHASPSessionKeyAndHandleGeneration:
    """Test session key and handle generation."""

    def test_session_id_generation_unique(self) -> None:
        """Session IDs are unique for each login."""
        parser = HASPSentinelParser()

        session_ids = set()
        for _ in range(100):
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
            )
            response = parser.generate_response(request)
            session_ids.add(response.session_id)

        assert len(session_ids) == 100

    def test_session_id_in_valid_range(self) -> None:
        """Session IDs are in valid range."""
        parser = HASPSentinelParser()

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
        )

        response = parser.generate_response(request)

        assert 100000 <= response.session_id <= 1000000

    def test_feature_handle_generation_unique(self) -> None:
        """Feature handles are unique per feature login."""
        parser = HASPSentinelParser()

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
        session_id = parser.generate_response(login_req).session_id

        feature_login_req = HASPRequest(
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

        response = parser.generate_response(feature_login_req)

        assert response.status == HASPStatusCode.STATUS_OK
        assert "feature_handle" in response.license_data
        assert response.license_data["feature_handle"] > 0

    def test_encryption_key_stored_in_session(self) -> None:
        """Encryption key is stored with session."""
        parser = HASPSentinelParser()

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
        )

        response = parser.generate_response(request)
        session = parser.active_sessions[response.session_id]

        assert len(session.encryption_key) == 32
        assert session.encryption_key == parser.crypto.aes_keys[response.session_id]


class TestHASPNetworkProtocol:
    """Test HASP network protocol (UDP discovery, TCP licensing)."""

    def test_network_protocol_constants_defined(self) -> None:
        """Network protocol constants are correctly defined."""
        assert HASPNetworkProtocol.UDP_DISCOVERY_PORT == 1947
        assert HASPNetworkProtocol.TCP_LICENSE_PORT == 1947
        assert HASPNetworkProtocol.BROADCAST_PORT == 475

    def test_discovery_magic_correct(self) -> None:
        """UDP discovery uses correct magic bytes."""
        assert HASPNetworkProtocol.DISCOVERY_MAGIC == b"HASP_DISCOVER_"
        assert HASPNetworkProtocol.SERVER_READY_MAGIC == b"HASP_SERVER_READY"

    def test_packet_types_defined(self) -> None:
        """All packet types are defined."""
        assert HASPNetworkProtocol.LOGIN_PACKET_TYPE == b"LOGIN"
        assert HASPNetworkProtocol.LOGOUT_PACKET_TYPE == b"LOGOUT"
        assert HASPNetworkProtocol.HEARTBEAT_PACKET_TYPE == b"HEARTBEAT"
        assert HASPNetworkProtocol.ENCRYPT_PACKET_TYPE == b"ENCRYPT"
        assert HASPNetworkProtocol.DECRYPT_PACKET_TYPE == b"DECRYPT"

    def test_request_parsing_handles_full_packet(self) -> None:
        """Request parser handles complete network packet."""
        parser = HASPSentinelParser()

        packet = self._build_network_packet(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
        )

        request = parser.parse_request(packet)

        assert request is not None
        assert request.command == HASPCommandType.LOGIN
        assert request.feature_id == 100
        assert request.vendor_code == 0x12345678

    def test_request_parsing_validates_magic(self) -> None:
        """Request parser validates magic bytes."""
        parser = HASPSentinelParser()

        invalid_packet = struct.pack("<I", 0xDEADBEEF)
        invalid_packet += b"\x00" * 100

        request = parser.parse_request(invalid_packet)

        assert request is None

    def test_request_parsing_handles_encryption_data(self) -> None:
        """Request parser extracts encryption data from packet."""
        parser = HASPSentinelParser()

        encryption_data = b"sensitive data to encrypt"
        packet = self._build_network_packet(
            command=HASPCommandType.ENCRYPT,
            session_id=12345,
            feature_id=100,
            vendor_code=0x12345678,
            encryption_data=encryption_data,
        )

        request = parser.parse_request(packet)

        assert request is not None
        assert request.encryption_data == encryption_data

    def test_heartbeat_updates_session_timestamp(self) -> None:
        """HEARTBEAT command updates session last_heartbeat."""
        parser = HASPSentinelParser()

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
        session_id = parser.generate_response(login_req).session_id

        initial_heartbeat = parser.active_sessions[session_id].last_heartbeat
        time.sleep(0.1)

        heartbeat_req = HASPRequest(
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

        parser.generate_response(heartbeat_req)

        updated_heartbeat = parser.active_sessions[session_id].last_heartbeat
        assert updated_heartbeat > initial_heartbeat

    def _build_network_packet(
        self,
        command: int,
        session_id: int,
        feature_id: int,
        vendor_code: int,
        encryption_data: bytes = b"",
    ) -> bytes:
        """Helper to build HASP network packet."""
        packet = struct.pack("<I", 0x48415350)
        packet += struct.pack("<H", 1)
        packet += struct.pack("<H", 0)
        packet += struct.pack("<I", command)
        packet += struct.pack("<I", session_id)
        packet += struct.pack("<I", feature_id)
        packet += struct.pack("<I", vendor_code)
        packet += struct.pack("<B", HASPEncryptionType.AES256)
        packet += struct.pack("<I", int(time.time()))

        scope = b""
        packet += struct.pack("<H", len(scope))
        packet += scope

        format_str = b""
        packet += struct.pack("<H", len(format_str))
        packet += format_str

        client_info = b"{}"
        packet += struct.pack("<H", len(client_info))
        packet += client_info

        packet += struct.pack("<H", len(encryption_data))
        packet += encryption_data

        packet += struct.pack("<H", 0)

        return packet


class TestHASPMemoryLayoutEmulation:
    """Test HASP HL memory layout emulation."""

    def test_memory_initialized_with_vendor_code(self) -> None:
        """Memory is initialized with vendor code at offset 0."""
        parser = HASPSentinelParser()

        feature_id = 100
        feature = parser.features[feature_id]
        memory = parser.memory_storage[feature_id]

        vendor_code = struct.unpack("<I", memory[:4])[0]
        assert vendor_code == feature.vendor_code

    def test_memory_contains_feature_id(self) -> None:
        """Memory contains feature ID at offset 4."""
        parser = HASPSentinelParser()

        feature_id = 100
        memory = parser.memory_storage[feature_id]

        stored_feature_id = struct.unpack("<I", memory[4:8])[0]
        assert stored_feature_id == feature_id

    def test_memory_read_returns_correct_data(self) -> None:
        """READ command returns correct memory data."""
        parser = HASPSentinelParser()

        session_id = self._establish_session(parser, 100)

        read_req = HASPRequest(
            command=HASPCommandType.READ,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={"address": 0, "length": 16},
        )

        response = parser.generate_response(read_req)

        assert response.status == HASPStatusCode.STATUS_OK
        assert len(response.encryption_response) == 16

        vendor_code = struct.unpack("<I", response.encryption_response[:4])[0]
        assert vendor_code == 0x12345678

    def test_memory_write_persists_data(self) -> None:
        """WRITE command persistently stores data in memory."""
        parser = HASPSentinelParser()

        session_id = self._establish_session(parser, 100)
        test_data = b"PERSISTENT_LICENSE_DATA_STORAGE_TEST"
        address = 200

        write_req = HASPRequest(
            command=HASPCommandType.WRITE,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={"address": address, "write_data": test_data},
        )

        parser.generate_response(write_req)

        memory = parser.memory_storage[100]
        assert memory[address : address + len(test_data)] == bytearray(test_data)

    def test_memory_size_matches_feature_configuration(self) -> None:
        """Memory size matches feature configuration."""
        parser = HASPSentinelParser()

        for feature_id, feature in parser.features.items():
            memory = parser.memory_storage[feature_id]
            assert len(memory) == feature.memory_size

    def _establish_session(self, parser: HASPSentinelParser, feature_id: int) -> int:
        """Helper to establish session."""
        request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=feature_id,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )
        response = parser.generate_response(request)
        return response.session_id


class TestHASPEdgeCases:
    """Test edge cases: HASP SRM, time-limited features, concurrent users."""

    def test_time_limited_feature_expiration_check(self) -> None:
        """Time-limited features enforce expiration dates."""
        parser = HASPSentinelParser()

        expired_feature = HASPFeature(
            feature_id=999,
            name="EXPIRED_TRIAL",
            vendor_code=0x12345678,
            feature_type=HASPFeatureType.TRIAL,
            expiry="01-jan-2020",
            max_users=10,
            encryption_supported=True,
            memory_size=1024,
            rtc_supported=True,
        )
        parser.features[999] = expired_feature

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
        session_id = parser.generate_response(login_req).session_id

        feature_login_req = HASPRequest(
            command=HASPCommandType.FEATURE_LOGIN,
            session_id=session_id,
            feature_id=999,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = parser.generate_response(feature_login_req)

        assert response.status == HASPStatusCode.FEATURE_EXPIRED

    def test_concurrent_user_limit_enforcement(self) -> None:
        """Concurrent user limits are enforced."""
        parser = HASPSentinelParser()

        limited_feature = HASPFeature(
            feature_id=888,
            name="LIMITED_CONCURRENT",
            vendor_code=0x12345678,
            feature_type=HASPFeatureType.CONCURRENT,
            expiry="31-dec-2025",
            max_users=2,
            encryption_supported=True,
            memory_size=1024,
            rtc_supported=True,
            concurrent_limit=2,
        )
        parser.features[888] = limited_feature
        parser.memory_storage[888] = bytearray(1024)

        session1 = self._establish_and_login_feature(parser, 888)
        session2 = self._establish_and_login_feature(parser, 888)

        login_req3 = HASPRequest(
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
        session3 = parser.generate_response(login_req3).session_id

        feature_login_req3 = HASPRequest(
            command=HASPCommandType.FEATURE_LOGIN,
            session_id=session3,
            feature_id=888,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = parser.generate_response(feature_login_req3)

        assert response.status == HASPStatusCode.TOO_MANY_USERS

    def test_invalid_vendor_code_rejected(self) -> None:
        """Invalid vendor codes are rejected."""
        parser = HASPSentinelParser()

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

    def test_feature_not_found_error(self) -> None:
        """Non-existent feature IDs return error."""
        parser = HASPSentinelParser()

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
        session_id = parser.generate_response(login_req).session_id

        feature_login_req = HASPRequest(
            command=HASPCommandType.FEATURE_LOGIN,
            session_id=session_id,
            feature_id=99999,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        response = parser.generate_response(feature_login_req)

        assert response.status == HASPStatusCode.FEATURE_NOT_FOUND

    def test_not_logged_in_error_for_operations(self) -> None:
        """Operations without login return NOT_LOGGED_IN error."""
        parser = HASPSentinelParser()

        encrypt_req = HASPRequest(
            command=HASPCommandType.ENCRYPT,
            session_id=99999,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"test",
            additional_params={},
        )

        response = parser.generate_response(encrypt_req)

        assert response.status == HASPStatusCode.NOT_LOGGED_IN

    def test_detachable_feature_support(self) -> None:
        """Detachable features allow offline operation."""
        parser = HASPSentinelParser()

        feature = parser.features[300]
        assert feature.detachable is True
        assert feature.detachable_duration > 0

    def test_hasp_srm_feature_configuration(self) -> None:
        """HASP SRM features are properly configured."""
        parser = HASPSentinelParser()

        for feature_id, feature in parser.features.items():
            assert isinstance(feature.vendor_code, int)
            assert isinstance(feature.feature_type, HASPFeatureType)
            assert isinstance(feature.expiry, str)
            assert feature.max_users >= 1

    def test_multiple_encryption_types_supported(self) -> None:
        """Multiple encryption types are supported."""
        parser = HASPSentinelParser()

        session_id = self._establish_session(parser, 100)
        plaintext = b"multi-cipher test data"

        for enc_type in [
            HASPEncryptionType.AES256,
            HASPEncryptionType.HASP4,
            HASPEncryptionType.ENVELOPE,
        ]:
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
                encryption_type=enc_type,
            )

            encrypt_resp = parser.generate_response(encrypt_req)
            assert encrypt_resp.status == HASPStatusCode.STATUS_OK

            decrypt_req = HASPRequest(
                command=HASPCommandType.DECRYPT,
                session_id=session_id,
                feature_id=100,
                vendor_code=0x12345678,
                scope="",
                format="",
                client_info={},
                encryption_data=encrypt_resp.encryption_response,
                additional_params={},
                encryption_type=enc_type,
            )

            decrypt_resp = parser.generate_response(decrypt_req)
            assert decrypt_resp.status == HASPStatusCode.STATUS_OK
            assert decrypt_resp.encryption_response == plaintext

    def _establish_session(self, parser: HASPSentinelParser, feature_id: int) -> int:
        """Helper to establish session."""
        request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=feature_id,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )
        response = parser.generate_response(request)
        return response.session_id

    def _establish_and_login_feature(
        self, parser: HASPSentinelParser, feature_id: int
    ) -> int:
        """Helper to establish session and login to feature."""
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
        session_id = parser.generate_response(login_req).session_id

        feature_login_req = HASPRequest(
            command=HASPCommandType.FEATURE_LOGIN,
            session_id=session_id,
            feature_id=feature_id,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )

        parser.generate_response(feature_login_req)
        return session_id


class TestHASPEnvelopeEncryption:
    """Test HASP envelope encryption (RSA + AES hybrid)."""

    def test_envelope_encrypt_combines_rsa_and_aes(self) -> None:
        """Envelope encryption uses RSA for key + AES for data."""
        crypto = HASPCrypto()
        plaintext = b"envelope encryption test data for HASP"

        envelope_data = crypto.envelope_encrypt(plaintext, 0)

        assert len(envelope_data) > len(plaintext)

        key_length = struct.unpack("<H", envelope_data[:2])[0]
        assert key_length > 0
        assert key_length == 256

    def test_envelope_decrypt_reverses_encryption(self) -> None:
        """Envelope decryption successfully reverses encryption."""
        crypto = HASPCrypto()
        plaintext = b"confidential data protected by envelope encryption"

        envelope_data = crypto.envelope_encrypt(plaintext, 0)
        decrypted = crypto.envelope_decrypt(envelope_data, 0)

        assert decrypted == plaintext

    def test_envelope_encryption_structure(self) -> None:
        """Envelope encryption has correct structure."""
        crypto = HASPCrypto()
        plaintext = b"test"

        envelope_data = crypto.envelope_encrypt(plaintext, 0)

        key_length = struct.unpack("<H", envelope_data[:2])[0]
        encrypted_key = envelope_data[2 : 2 + key_length]
        iv = envelope_data[2 + key_length : 2 + key_length + 16]

        assert len(encrypted_key) == key_length
        assert len(iv) == 16


class TestHASPLegacyEncryption:
    """Test HASP4 legacy encryption."""

    def test_hasp4_keystream_generation(self) -> None:
        """HASP4 generates keystream using LFSR."""
        crypto = HASPCrypto()

        keystream = crypto._generate_hasp4_keystream(0x12345678, 100)

        assert len(keystream) == 100
        assert keystream != b"\x00" * 100

    def test_hasp4_encryption_deterministic_with_seed(self) -> None:
        """HASP4 encryption is deterministic with same seed."""
        crypto = HASPCrypto()
        plaintext = b"legacy HASP4 data"
        seed = 0xABCDEF12

        encrypted1 = crypto.hasp4_encrypt(plaintext, seed)
        encrypted2 = crypto.hasp4_encrypt(plaintext, seed)

        assert encrypted1 == encrypted2

    def test_hasp4_different_seeds_different_output(self) -> None:
        """HASP4 encryption produces different output with different seeds."""
        crypto = HASPCrypto()
        plaintext = b"test data"

        encrypted1 = crypto.hasp4_encrypt(plaintext, 0x11111111)
        encrypted2 = crypto.hasp4_encrypt(plaintext, 0x22222222)

        assert encrypted1 != encrypted2

    def test_legacy_encrypt_command_uses_hasp4(self) -> None:
        """LEGACY_ENCRYPT command uses HASP4 algorithm."""
        parser = HASPSentinelParser()

        session_id = self._establish_session(parser, 100)
        plaintext = b"legacy encryption test"

        legacy_encrypt_req = HASPRequest(
            command=HASPCommandType.LEGACY_ENCRYPT,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=plaintext,
            additional_params={},
        )

        encrypt_resp = parser.generate_response(legacy_encrypt_req)
        assert encrypt_resp.status == HASPStatusCode.STATUS_OK

        legacy_decrypt_req = HASPRequest(
            command=HASPCommandType.LEGACY_DECRYPT,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=encrypt_resp.encryption_response,
            additional_params={},
        )

        decrypt_resp = parser.generate_response(legacy_decrypt_req)
        assert decrypt_resp.encryption_response == plaintext

    def _establish_session(self, parser: HASPSentinelParser, feature_id: int) -> int:
        """Helper to establish session."""
        request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=feature_id,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )
        response = parser.generate_response(request)
        return response.session_id
