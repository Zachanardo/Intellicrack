"""Production tests for intellicrack/core/network/protocols/hasp_parser.py.

Validates HASP/Sentinel protocol parsing, dongle emulation, and license server operations
for bypassing HASP hardware-based licensing protections.

NO MOCKS - All tests use real HASP protocol structures and cryptographic operations.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import struct
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.network.protocols.hasp_parser import (
    HASPCommandType,
    HASPCrypto,
    HASPEncryptionType,
    HASPFeature,
    HASPFeatureType,
    HASPPacketAnalyzer,
    HASPRequest,
    HASPResponse,
    HASPSentinelParser,
    HASPServerEmulator,
    HASPStatusCode,
    HASPUSBEmulator,
)


class TestHASPCrypto:
    """Test HASP cryptographic operations."""

    def test_crypto_initialization(self) -> None:
        """HASP crypto handler initializes with default keys."""
        crypto = HASPCrypto()

        assert 0 in crypto.aes_keys
        assert 0 in crypto.rsa_keys
        assert len(crypto.aes_keys[0]) == 32

    def test_aes_encrypt_decrypt_roundtrip(self) -> None:
        """AES encryption and decryption produce original data."""
        crypto = HASPCrypto()
        plaintext = b"This is sensitive license data for HASP protection bypass"

        encrypted = crypto.aes_encrypt(plaintext, 0)
        decrypted = crypto.aes_decrypt(encrypted, 0)

        assert decrypted == plaintext

    def test_aes_encrypt_different_sessions_different_keys(self) -> None:
        """AES encryption uses different keys for different sessions."""
        crypto = HASPCrypto()
        plaintext = b"license data"

        crypto.generate_session_key(1, 0x12345678)
        crypto.generate_session_key(2, 0x87654321)

        encrypted1 = crypto.aes_encrypt(plaintext, 1)
        encrypted2 = crypto.aes_encrypt(plaintext, 2)

        assert encrypted1 != encrypted2

    def test_rsa_sign_verify(self) -> None:
        """RSA signature can be verified correctly."""
        crypto = HASPCrypto()
        data = b"HASP license verification data"

        signature = crypto.rsa_sign(data, 0)
        valid = crypto.rsa_verify(data, signature, 0)

        assert valid is True

    def test_rsa_verify_fails_tampered_data(self) -> None:
        """RSA verification fails for tampered data."""
        crypto = HASPCrypto()
        data = b"original data"

        signature = crypto.rsa_sign(data, 0)
        tampered = b"tampered data"
        valid = crypto.rsa_verify(tampered, signature, 0)

        assert valid is False

    def test_hasp4_encrypt_decrypt_roundtrip(self) -> None:
        """HASP4 legacy encryption produces reversible ciphertext."""
        crypto = HASPCrypto()
        plaintext = b"Legacy HASP4 protected software data"
        seed = 0x12345678

        encrypted = crypto.hasp4_encrypt(plaintext, seed)
        decrypted = crypto.hasp4_decrypt(encrypted, seed)

        assert decrypted == plaintext

    def test_hasp4_different_seeds_different_ciphertext(self) -> None:
        """HASP4 encryption produces different output for different seeds."""
        crypto = HASPCrypto()
        plaintext = b"test data"

        encrypted1 = crypto.hasp4_encrypt(plaintext, 0x11111111)
        encrypted2 = crypto.hasp4_encrypt(plaintext, 0x22222222)

        assert encrypted1 != encrypted2

    def test_envelope_encrypt_decrypt_roundtrip(self) -> None:
        """Envelope encryption (RSA+AES) produces original data."""
        crypto = HASPCrypto()
        plaintext = b"Highly sensitive HASP license information"

        encrypted = crypto.envelope_encrypt(plaintext, 0)
        decrypted = crypto.envelope_decrypt(encrypted, 0)

        assert decrypted == plaintext


class TestHASPSentinelParser:
    """Test HASP/Sentinel protocol parser."""

    def test_parser_initialization(self) -> None:
        """HASP parser initializes with default features and hardware fingerprint."""
        parser = HASPSentinelParser()

        assert len(parser.features) > 0
        assert len(parser.active_sessions) == 0
        assert parser.hardware_fingerprint["hasp_id"] > 0
        assert parser.hardware_fingerprint["type"] == "HASP HL Max"

    def test_parse_valid_login_request(self) -> None:
        """Parser correctly parses HASP LOGIN request."""
        parser = HASPSentinelParser()

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

        format_str = b""
        packet.extend(struct.pack("<H", len(format_str)))
        packet.extend(format_str)

        client_info = json.dumps({"hostname": "test-pc"}).encode()
        packet.extend(struct.pack("<H", len(client_info)))
        packet.extend(client_info)

        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))

        request = parser.parse_request(bytes(packet))

        assert request is not None
        assert request.command == HASPCommandType.LOGIN
        assert request.vendor_code == 0x12345678
        assert request.feature_id == 100

    def test_parse_request_validates_magic_number(self) -> None:
        """Parser rejects packets with invalid HASP magic numbers."""
        parser = HASPSentinelParser()

        invalid_packet = struct.pack("<I", 0xDEADBEEF) + b"\x00" * 100

        request = parser.parse_request(invalid_packet)

        assert request is None

    def test_generate_login_response_creates_session(self) -> None:
        """LOGIN response creates new session with encryption key."""
        parser = HASPSentinelParser()

        request = HASPRequest(
            command=HASPCommandType.LOGIN,
            session_id=0,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={"hostname": "test-pc"},
            encryption_data=b"",
            additional_params={},
        )

        initial_sessions = len(parser.active_sessions)
        response = parser.generate_response(request)

        assert response.status == HASPStatusCode.STATUS_OK
        assert response.session_id > 0
        assert len(parser.active_sessions) == initial_sessions + 1
        assert "session_established" in response.license_data

    def test_generate_logout_removes_session(self) -> None:
        """LOGOUT response removes active session."""
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

        login_resp = parser.generate_response(login_req)
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

        response = parser.generate_response(logout_req)

        assert response.status == HASPStatusCode.STATUS_OK
        assert session_id not in parser.active_sessions

    def test_generate_feature_login_validates_concurrent_limits(self) -> None:
        """FEATURE_LOGIN enforces concurrent user limits."""
        parser = HASPSentinelParser()

        feature = parser.features[100]
        original_limit = feature.concurrent_limit
        feature.concurrent_limit = 1

        login_req1 = HASPRequest(
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
        resp1 = parser.generate_response(login_req1)
        session1 = resp1.session_id

        feature_login1 = HASPRequest(
            command=HASPCommandType.FEATURE_LOGIN,
            session_id=session1,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )
        resp_fl1 = parser.generate_response(feature_login1)
        assert resp_fl1.status == HASPStatusCode.STATUS_OK

        login_req2 = HASPRequest(
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
        resp2 = parser.generate_response(login_req2)
        session2 = resp2.session_id

        feature_login2 = HASPRequest(
            command=HASPCommandType.FEATURE_LOGIN,
            session_id=session2,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=b"",
            additional_params={},
        )
        resp_fl2 = parser.generate_response(feature_login2)

        assert resp_fl2.status == HASPStatusCode.TOO_MANY_USERS

        feature.concurrent_limit = original_limit

    def test_generate_encrypt_response_aes(self) -> None:
        """ENCRYPT command performs AES encryption."""
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
        login_resp = parser.generate_response(login_req)
        session_id = login_resp.session_id

        plaintext = b"Sensitive license check data"
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
        assert len(response.encryption_response) > len(plaintext)

    def test_generate_decrypt_response_aes(self) -> None:
        """DECRYPT command performs AES decryption."""
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
        login_resp = parser.generate_response(login_req)
        session_id = login_resp.session_id

        plaintext = b"Original data"
        encrypted = parser.crypto.aes_encrypt(plaintext, session_id)

        decrypt_req = HASPRequest(
            command=HASPCommandType.DECRYPT,
            session_id=session_id,
            feature_id=100,
            vendor_code=0x12345678,
            scope="",
            format="",
            client_info={},
            encryption_data=encrypted,
            additional_params={},
            encryption_type=HASPEncryptionType.AES256,
        )

        response = parser.generate_response(decrypt_req)

        assert response.status == HASPStatusCode.STATUS_OK
        assert response.encryption_response == plaintext

    def test_generate_read_response(self) -> None:
        """READ command reads from dongle memory."""
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
        login_resp = parser.generate_response(login_req)
        session_id = login_resp.session_id

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

    def test_serialize_response_creates_valid_packet(self) -> None:
        """serialize_response creates valid HASP response packet."""
        parser = HASPSentinelParser()

        response = HASPResponse(
            status=HASPStatusCode.STATUS_OK,
            session_id=123456,
            feature_id=100,
            license_data={"status": "active"},
            encryption_response=b"",
            expiry_info={},
            hardware_info={},
        )

        packet = parser.serialize_response(response)

        assert len(packet) > 0
        assert packet[:4] == struct.pack("<I", 0x48415350)

    def test_add_feature(self) -> None:
        """add_feature adds custom feature to emulator."""
        parser = HASPSentinelParser()

        initial_count = len(parser.features)

        custom_feature = HASPFeature(
            feature_id=999,
            name="CUSTOM_FEATURE",
            vendor_code=0xAABBCCDD,
            feature_type=HASPFeatureType.PERPETUAL,
            expiry="permanent",
            max_users=10,
            encryption_supported=True,
            memory_size=2048,
            rtc_supported=True,
        )

        parser.add_feature(custom_feature)

        assert len(parser.features) == initial_count + 1
        assert 999 in parser.features
        assert parser.features[999].name == "CUSTOM_FEATURE"


class TestHASPServerEmulator:
    """Test HASP license server emulation."""

    def test_server_initialization(self) -> None:
        """HASP server initializes with bind address and port."""
        server = HASPServerEmulator("127.0.0.1", 1947)

        assert server.bind_address == "127.0.0.1"
        assert server.port == 1947
        assert server.running is False
        assert len(server.server_id) > 0

    def test_generate_discovery_response(self) -> None:
        """Server generates valid discovery response."""
        server = HASPServerEmulator()

        response = server.generate_discovery_response()

        assert b"HASP_SERVER_READY" in response
        assert b"SERVER" in response
        assert b"VERSION=7.50" in response

    def test_handle_client_request_discovery(self) -> None:
        """Server handles discovery requests correctly."""
        server = HASPServerEmulator()

        discovery_request = b"HASP_DISCOVER_"

        response = server.handle_client_request(discovery_request)

        assert b"HASP_SERVER_READY" in response


class TestHASPUSBEmulator:
    """Test HASP USB dongle emulation."""

    def test_usb_emulator_initialization(self) -> None:
        """USB emulator initializes with device information."""
        emulator = HASPUSBEmulator()

        assert emulator.device_info["vendor_id"] == 0x0529
        assert emulator.device_info["manufacturer"] == "Aladdin Knowledge Systems"

    def test_handle_control_transfer_read_memory(self) -> None:
        """USB emulator handles memory read requests."""
        emulator = HASPUSBEmulator()

        data = emulator.handle_control_transfer(0x21, 0x01, 0, 16, b"")

        assert len(data) == 16

    def test_handle_control_transfer_encrypt(self) -> None:
        """USB emulator performs encryption via USB."""
        emulator = HASPUSBEmulator()

        plaintext = b"USB dongle encryption test data"

        encrypted = emulator.handle_control_transfer(0x21, 0x03, 0, 0, plaintext)

        assert len(encrypted) > 0
        assert encrypted != plaintext

    def test_emulate_usb_device(self) -> None:
        """emulate_usb_device returns valid USB descriptors."""
        emulator = HASPUSBEmulator()

        descriptors = emulator.emulate_usb_device()

        assert "device_descriptor" in descriptors
        assert "string_descriptors" in descriptors
        assert "configuration_descriptor" in descriptors

        device = descriptors["device_descriptor"]
        assert device["idVendor"] == 0x0529


class TestHASPProtocolIntegration:
    """Integration tests for HASP protocol operations."""

    def test_complete_login_encrypt_decrypt_logout_workflow(self) -> None:
        """Complete HASP session workflow from login to logout."""
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

        login_resp = parser.generate_response(login_req)
        assert login_resp.status == HASPStatusCode.STATUS_OK
        session_id = login_resp.session_id

        plaintext = b"License validation data"
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

        encrypt_resp = parser.generate_response(encrypt_req)
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

        decrypt_resp = parser.generate_response(decrypt_req)
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

        logout_resp = parser.generate_response(logout_req)
        assert logout_resp.status == HASPStatusCode.STATUS_OK
        assert session_id not in parser.active_sessions
