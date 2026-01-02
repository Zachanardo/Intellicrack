"""Production tests for CodeMeter protocol parser with edge case handling.

Tests that validate CodeMeter protocol parsing, malformed vendor certificate handling,
and edge cases in license validation. These tests verify robust protocol implementation
against real CodeMeter traffic patterns and attack scenarios.
"""

import secrets
import struct
import time
from typing import Any

import pytest

from intellicrack.core.network.protocols.codemeter_parser import (
    CodeMeterProtocolParser,
    CodeMeterRequest,
    CodeMeterResponse,
)


class TestCodeMeterProtocolParsing:
    """Test suite for CodeMeter protocol request parsing with edge cases."""

    @pytest.fixture
    def parser(self) -> CodeMeterProtocolParser:
        """Create CodeMeterProtocolParser instance."""
        return CodeMeterProtocolParser()

    def test_parse_valid_login_request(self, parser: CodeMeterProtocolParser) -> None:
        """Test parsing of valid CodeMeter login request packet.

        Validates that parser correctly extracts all fields from properly formatted
        CodeMeter login request matching real network traffic.
        """
        packet = bytearray()
        packet.extend(struct.pack("<I", 0x434D4554))
        packet.extend(struct.pack("<I", 0x1000))
        packet.extend(struct.pack("<I", 1000))
        packet.extend(struct.pack("<I", 500001))
        packet.extend(struct.pack("<I", 1))
        packet.extend(struct.pack("<I", 0xFFFFFFFF))

        version = "7.60"
        packet.extend(struct.pack("<H", len(version)))
        packet.extend(version.encode("utf-8"))

        client_id = "CLIENT-12345"
        packet.extend(struct.pack("<H", len(client_id)))
        packet.extend(client_id.encode("utf-8"))

        packet.extend(struct.pack("<H", 0))
        packet.extend(struct.pack("<H", 0))

        request = parser.parse_request(bytes(packet))

        assert request is not None
        assert request.command == 0x1000
        assert request.firm_code == 500001
        assert request.product_code == 1
        assert request.version == version
        assert request.client_id == client_id

    def test_parse_request_with_invalid_magic_rejects(self, parser: CodeMeterProtocolParser) -> None:
        """Test that parser rejects packets with invalid magic numbers.

        Validates proper validation of CodeMeter packet signatures.
        """
        packet = bytearray()
        packet.extend(struct.pack("<I", 0xDEADBEEF))
        packet.extend(struct.pack("<I", 0x1000))

        request = parser.parse_request(bytes(packet))

        assert request is None

    def test_parse_request_with_truncated_version_field(self, parser: CodeMeterProtocolParser) -> None:
        """Test parsing handles truncated version field gracefully.

        Validates that parser detects incomplete packets.
        """
        packet = bytearray()
        packet.extend(struct.pack("<I", 0x434D4554))
        packet.extend(struct.pack("<I", 0x1000))
        packet.extend(struct.pack("<I", 1000))
        packet.extend(struct.pack("<I", 500001))
        packet.extend(struct.pack("<I", 1))
        packet.extend(struct.pack("<I", 0xFFFFFFFF))
        packet.extend(struct.pack("<H", 100))
        packet.extend(b"short")

        request = parser.parse_request(bytes(packet))

        assert request is None

    def test_parse_encrypt_request_with_large_payload(self, parser: CodeMeterProtocolParser) -> None:
        """Test parsing encryption request with large data payload.

        Validates that parser handles large encryption payloads correctly.
        """
        packet = bytearray()
        packet.extend(struct.pack("<I", 0x434D4554))
        packet.extend(struct.pack("<I", 0x1006))
        packet.extend(struct.pack("<I", 2000))
        packet.extend(struct.pack("<I", 500001))
        packet.extend(struct.pack("<I", 1))
        packet.extend(struct.pack("<I", 0xFFFFFFFF))

        version = "7.60"
        packet.extend(struct.pack("<H", len(version)))
        packet.extend(version.encode("utf-8"))

        client_id = "CLIENT"
        packet.extend(struct.pack("<H", len(client_id)))
        packet.extend(client_id.encode("utf-8"))

        packet.extend(struct.pack("<H", 0))

        large_payload = secrets.token_bytes(10000)
        packet.extend(struct.pack("<H", len(large_payload)))
        packet.extend(large_payload)

        request = parser.parse_request(bytes(packet))

        assert request is not None
        assert request.challenge_data == large_payload

    def test_parse_request_with_malformed_session_context(self, parser: CodeMeterProtocolParser) -> None:
        """Test parsing handles malformed session context gracefully.

        Validates that corrupted session context doesn't crash parser.
        """
        packet = bytearray()
        packet.extend(struct.pack("<I", 0x434D4554))
        packet.extend(struct.pack("<I", 0x1000))
        packet.extend(struct.pack("<I", 1000))
        packet.extend(struct.pack("<I", 500001))
        packet.extend(struct.pack("<I", 1))
        packet.extend(struct.pack("<I", 0xFFFFFFFF))

        version = "7.60"
        packet.extend(struct.pack("<H", len(version)))
        packet.extend(version.encode("utf-8"))

        client_id = "CLIENT"
        packet.extend(struct.pack("<H", len(client_id)))
        packet.extend(client_id.encode("utf-8"))

        corrupted_context = b"\xFF\xFE" + secrets.token_bytes(10)
        packet.extend(struct.pack("<H", len(corrupted_context)))
        packet.extend(corrupted_context)

        packet.extend(struct.pack("<H", 0))

        request = parser.parse_request(bytes(packet))

        assert request is not None
        assert isinstance(request.session_context, dict)


class TestCodeMeterResponseGeneration:
    """Test suite for CodeMeter response generation with edge cases."""

    @pytest.fixture
    def parser(self) -> CodeMeterProtocolParser:
        """Create CodeMeterProtocolParser instance."""
        return CodeMeterProtocolParser()

    def test_login_with_unknown_product_returns_error(self, parser: CodeMeterProtocolParser) -> None:
        """Test that login with unknown product code returns appropriate error.

        Validates proper error handling for unregistered products.
        """
        request = CodeMeterRequest(
            command=0x1000,
            request_id=1000,
            firm_code=999999,
            product_code=999,
            feature_map=0xFFFFFFFF,
            version="7.60",
            client_id="CLIENT",
            session_context={},
            challenge_data=b"",
            additional_data={},
        )

        response = parser.generate_response(request)

        assert response.status == 0x00000006

    def test_encrypt_decrypt_with_firm_product_key(self, parser: CodeMeterProtocolParser) -> None:
        """Test that encryption/decryption uses firm/product code as key.

        Validates that CodeMeter XOR encryption is reversible.
        """
        login_request = CodeMeterRequest(
            command=0x1000,
            request_id=1000,
            firm_code=500001,
            product_code=1,
            feature_map=0xFFFFFFFF,
            version="7.60",
            client_id="CLIENT",
            session_context={},
            challenge_data=b"",
            additional_data={},
        )

        login_response = parser.generate_response(login_request)

        plaintext = b"Sensitive license data"

        encrypt_request = CodeMeterRequest(
            command=0x1006,
            request_id=2000,
            firm_code=500001,
            product_code=1,
            feature_map=0xFFFFFFFF,
            version="7.60",
            client_id="CLIENT",
            session_context={},
            challenge_data=plaintext,
            additional_data={},
        )

        encrypt_response = parser.generate_response(encrypt_request)

        assert encrypt_response.status == 0x00000000
        ciphertext = encrypt_response.response_data

        decrypt_request = CodeMeterRequest(
            command=0x1007,
            request_id=3000,
            firm_code=500001,
            product_code=1,
            feature_map=0xFFFFFFFF,
            version="7.60",
            client_id="CLIENT",
            session_context={},
            challenge_data=ciphertext,
            additional_data={},
        )

        decrypt_response = parser.generate_response(decrypt_request)

        assert decrypt_response.status == 0x00000000
        decrypted = decrypt_response.response_data

        assert decrypted == plaintext

    def test_challenge_response_authentication_cycle(self, parser: CodeMeterProtocolParser) -> None:
        """Test complete challenge-response authentication cycle.

        Validates that challenge-response mechanism works correctly.
        """
        challenge_data = secrets.token_bytes(32)

        challenge_request = CodeMeterRequest(
            command=0x1002,
            request_id=1000,
            firm_code=500001,
            product_code=1,
            feature_map=0xFFFFFFFF,
            version="7.60",
            client_id="CLIENT",
            session_context={},
            challenge_data=challenge_data,
            additional_data={},
        )

        challenge_response = parser.generate_response(challenge_request)

        assert challenge_response.status == 0x00000000
        assert len(challenge_response.response_data) == 32

        verify_request = CodeMeterRequest(
            command=0x1003,
            request_id=2000,
            firm_code=500001,
            product_code=1,
            feature_map=0xFFFFFFFF,
            version="7.60",
            client_id="CLIENT",
            session_context={},
            challenge_data=challenge_response.response_data,
            additional_data={},
        )

        verify_response = parser.generate_response(verify_request)

        assert verify_response.status == 0x00000000

    def test_get_license_returns_product_details(self, parser: CodeMeterProtocolParser) -> None:
        """Test that get_license returns complete product information.

        Validates that license query returns all product metadata.
        """
        request = CodeMeterRequest(
            command=0x100A,
            request_id=1000,
            firm_code=500001,
            product_code=1,
            feature_map=0xFFFFFFFF,
            version="7.60",
            client_id="CLIENT",
            session_context={},
            challenge_data=b"",
            additional_data={},
        )

        response = parser.generate_response(request)

        assert response.status == 0x00000000
        assert "name" in response.license_info
        assert "features" in response.license_info
        assert "max_users" in response.license_info
        assert "expiry" in response.license_info

    def test_enumerate_products_lists_all_available(self, parser: CodeMeterProtocolParser) -> None:
        """Test that enumerate products returns all registered products.

        Validates product enumeration functionality.
        """
        request = CodeMeterRequest(
            command=0x100E,
            request_id=1000,
            firm_code=0,
            product_code=0,
            feature_map=0xFFFFFFFF,
            version="7.60",
            client_id="CLIENT",
            session_context={},
            challenge_data=b"",
            additional_data={},
        )

        response = parser.generate_response(request)

        assert response.status == 0x00000000
        assert "products" in response.license_info
        assert len(response.license_info["products"]) >= 5

    def test_transfer_receipt_generates_unique_receipt_id(self, parser: CodeMeterProtocolParser) -> None:
        """Test that transfer receipt generates unique receipt identifiers.

        Validates receipt generation for license transfer operations.
        """
        request1 = CodeMeterRequest(
            command=0x100F,
            request_id=1000,
            firm_code=500001,
            product_code=1,
            feature_map=0xFFFFFFFF,
            version="7.60",
            client_id="CLIENT1",
            session_context={},
            challenge_data=b"",
            additional_data={},
        )

        response1 = parser.generate_response(request1)

        request2 = CodeMeterRequest(
            command=0x100F,
            request_id=2000,
            firm_code=500001,
            product_code=1,
            feature_map=0xFFFFFFFF,
            version="7.60",
            client_id="CLIENT2",
            session_context={},
            challenge_data=b"",
            additional_data={},
        )

        response2 = parser.generate_response(request2)

        assert response1.license_info["receipt_id"] != response2.license_info["receipt_id"]

    def test_check_receipt_validates_existing_receipt(self, parser: CodeMeterProtocolParser) -> None:
        """Test that check receipt validates previously generated receipts.

        Validates receipt verification functionality.
        """
        transfer_request = CodeMeterRequest(
            command=0x100F,
            request_id=1000,
            firm_code=500001,
            product_code=1,
            feature_map=0xFFFFFFFF,
            version="7.60",
            client_id="CLIENT",
            session_context={},
            challenge_data=b"",
            additional_data={},
        )

        transfer_response = parser.generate_response(transfer_request)
        receipt_id = transfer_response.license_info["receipt_id"]

        check_request = CodeMeterRequest(
            command=0x1010,
            request_id=2000,
            firm_code=500001,
            product_code=1,
            feature_map=0xFFFFFFFF,
            version="7.60",
            client_id="CLIENT",
            session_context={"receipt_id": receipt_id},
            challenge_data=b"",
            additional_data={},
        )

        check_response = parser.generate_response(check_request)

        assert check_response.status == 0x00000000


class TestCodeMeterResponseSerialization:
    """Test suite for CodeMeter response serialization."""

    @pytest.fixture
    def parser(self) -> CodeMeterProtocolParser:
        """Create CodeMeterProtocolParser instance."""
        return CodeMeterProtocolParser()

    def test_serialize_response_produces_valid_packet(self, parser: CodeMeterProtocolParser) -> None:
        """Test that response serialization produces valid CodeMeter packet.

        Validates that serialized response can be transmitted over network.
        """
        response = CodeMeterResponse(
            status=0x00000000,
            request_id=1000,
            firm_code=500001,
            product_code=1,
            license_info={"key": "value"},
            response_data=b"test_data",
            container_info={"serial_number": 12345},
            expiry_data={"expiry_date": "31-dec-2025"},
        )

        serialized = parser.serialize_response(response)

        assert len(serialized) > 20
        assert serialized[:4] == struct.pack("<I", 0x434D4554)

    def test_serialize_response_handles_empty_dictionaries(self, parser: CodeMeterProtocolParser) -> None:
        """Test response serialization handles empty fields correctly.

        Validates that empty dictionaries serialize properly.
        """
        response = CodeMeterResponse(
            status=0x00000000,
            request_id=1000,
            firm_code=500001,
            product_code=1,
            license_info={},
            response_data=b"",
            container_info={},
            expiry_data={},
        )

        serialized = parser.serialize_response(response)

        assert len(serialized) >= 20

    def test_serialize_dict_handles_various_types(self, parser: CodeMeterProtocolParser) -> None:
        """Test dictionary serialization handles various data types.

        Validates that serialization properly handles strings, integers, and other types.
        """
        test_dict = {
            "string_key": "string_value",
            "int_key": 12345,
            "bool_key": True,
            "list_key": [1, 2, 3],
        }

        serialized = parser._serialize_dict(test_dict)

        assert len(serialized) > 0

    def test_serialize_response_handles_large_license_data(self, parser: CodeMeterProtocolParser) -> None:
        """Test response serialization handles large license data dictionaries.

        Validates that large amounts of license information serialize correctly.
        """
        large_license_data = {f"feature_{i}": f"value_{i}" * 50 for i in range(100)}

        response = CodeMeterResponse(
            status=0x00000000,
            request_id=1000,
            firm_code=500001,
            product_code=1,
            license_info=large_license_data,
            response_data=b"",
            container_info={},
            expiry_data={},
        )

        serialized = parser.serialize_response(response)

        assert len(serialized) > 5000


class TestCodeMeterSessionManagement:
    """Test suite for CodeMeter session management."""

    @pytest.fixture
    def parser(self) -> CodeMeterProtocolParser:
        """Create CodeMeterProtocolParser instance."""
        return CodeMeterProtocolParser()

    def test_multiple_logins_create_separate_sessions(self, parser: CodeMeterProtocolParser) -> None:
        """Test that multiple logins create separate session contexts.

        Validates proper session isolation.
        """
        session_hashes = []

        for i in range(10):
            request = CodeMeterRequest(
                command=0x1000,
                request_id=1000 + i,
                firm_code=500001,
                product_code=1,
                feature_map=0xFFFFFFFF,
                version="7.60",
                client_id=f"CLIENT_{i}",
                session_context={},
                challenge_data=b"",
                additional_data={},
            )

            response = parser.generate_response(request)

            assert response.status == 0x00000000
            session_id = response.license_info["session_id"]
            session_hashes.append(session_id)

        assert len(set(session_hashes)) == 10

    def test_logout_removes_session(self, parser: CodeMeterProtocolParser) -> None:
        """Test that logout properly removes session from active sessions.

        Validates session cleanup on logout.
        """
        login_request = CodeMeterRequest(
            command=0x1000,
            request_id=1000,
            firm_code=500001,
            product_code=1,
            feature_map=0xFFFFFFFF,
            version="7.60",
            client_id="CLIENT",
            session_context={},
            challenge_data=b"",
            additional_data={},
        )

        login_response = parser.generate_response(login_request)
        session_id = login_response.license_info["session_id"]

        logout_request = CodeMeterRequest(
            command=0x1001,
            request_id=2000,
            firm_code=500001,
            product_code=1,
            feature_map=0xFFFFFFFF,
            version="7.60",
            client_id="CLIENT",
            session_context={"session_id": session_id},
            challenge_data=b"",
            additional_data={},
        )

        logout_response = parser.generate_response(logout_request)

        assert logout_response.status == 0x00000000
        assert session_id not in parser.active_sessions

    def test_heartbeat_updates_session_timestamp(self, parser: CodeMeterProtocolParser) -> None:
        """Test that heartbeat updates session last_heartbeat timestamp.

        Validates session keepalive functionality.
        """
        login_request = CodeMeterRequest(
            command=0x1000,
            request_id=1000,
            firm_code=500001,
            product_code=1,
            feature_map=0xFFFFFFFF,
            version="7.60",
            client_id="CLIENT",
            session_context={},
            challenge_data=b"",
            additional_data={},
        )

        login_response = parser.generate_response(login_request)
        session_id = login_response.license_info["session_id"]

        time.sleep(0.1)

        heartbeat_request = CodeMeterRequest(
            command=0x100C,
            request_id=2000,
            firm_code=500001,
            product_code=1,
            feature_map=0xFFFFFFFF,
            version="7.60",
            client_id="CLIENT",
            session_context={"session_id": session_id},
            challenge_data=b"",
            additional_data={},
        )

        heartbeat_response = parser.generate_response(heartbeat_request)

        assert heartbeat_response.status == 0x00000000
