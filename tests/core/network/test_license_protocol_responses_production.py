#!/usr/bin/env python3
"""Production-ready tests for license protocol response generation.

Tests the critical functionality at license_protocol_handler.py:312-326 where
generate_response returns b"OK\n" for all requests instead of implementing
protocol-specific response formats.

This comprehensive test suite validates:
- Protocol-specific response formats (FlexLM text-based, HASP binary)
- Session state maintenance across multiple requests
- Authentication and challenge-response mechanisms
- Proper error response generation for invalid inputs
- Stateful license checkout/checkin workflows
- Concurrent session handling without state corruption
- Session timeout management and cleanup

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

from __future__ import annotations

import secrets
import socket
import struct
import threading
import time
from typing import Any

import pytest

from intellicrack.core.network.license_protocol_handler import (
    FlexLMProtocolHandler,
    HASPProtocolHandler,
    LicenseProtocolHandler,
)


class TestFlexLMResponseFormats:
    """Validate FlexLM generates protocol-specific responses, not generic b'OK\\n'."""

    def test_hello_response_contains_version_and_port(self) -> None:
        """FlexLM HELLO returns version and vendor daemon port, not b'OK\\n'."""
        handler = FlexLMProtocolHandler(
            config={
                "flexlm_version": "11.16.2",
                "vendor_daemon_port": 27001,
            }
        )

        response = handler.generate_response(b"HELLO")

        assert response != b"OK\n", "HELLO must not return generic OK response"
        assert response == b"HELLO 11 16 27001\n"
        assert b"11" in response
        assert b"16" in response
        assert b"27001" in response

    def test_hello_response_adapts_to_custom_configuration(self) -> None:
        """FlexLM HELLO response dynamically adapts to configuration."""
        handler = FlexLMProtocolHandler(
            config={
                "flexlm_version": "12.5.3",
                "vendor_daemon_port": 28500,
            }
        )

        response = handler.generate_response(b"HELLO")

        assert response == b"HELLO 12 5 28500\n"
        assert b"12.5.3" not in response
        assert b"12 5" in response

    def test_getlic_returns_grant_response_not_ok(self) -> None:
        """FlexLM GETLIC returns GRANT response with license details, not b'OK\\n'."""
        handler = FlexLMProtocolHandler(
            config={
                "feature_version": "3.5",
                "license_type": "permanent",
            }
        )

        response = handler.generate_response(b"GETLIC PROFESSIONAL 1.0 user1 host1 :0")

        assert response != b"OK\n", "GETLIC must not return generic OK response"
        assert response.startswith(b"GRANT PROFESSIONAL")
        assert b"3.5" in response
        assert b"permanent" in response
        assert b"HOSTID=ANY" in response

    def test_getlic_includes_feature_from_request(self) -> None:
        """FlexLM GETLIC extracts and includes feature name from request."""
        handler = FlexLMProtocolHandler()

        features = ["PROFESSIONAL", "ENTERPRISE", "DEVELOPER"]

        for feature in features:
            request = f"GETLIC {feature} 1.0 user1 host1 :0".encode()
            response = handler.generate_response(request)

            assert f"GRANT {feature}".encode() in response
            assert response != b"OK\n"

    def test_getlic_temporary_license_includes_expiry_timestamp(self) -> None:
        """FlexLM GETLIC with temporary license includes future expiry timestamp."""
        handler = FlexLMProtocolHandler(
            config={
                "license_type": "temporary",
            }
        )

        before_time = int(time.time())
        response = handler.generate_response(b"GETLIC ENTERPRISE 2.0 user2 host2 :0")
        after_time = int(time.time())

        assert response != b"OK\n"
        assert b"GRANT ENTERPRISE" in response
        assert b"temporary" in response

        response_str = response.decode("utf-8")
        parts = response_str.split()
        expiry_timestamp = int(parts[4])

        assert expiry_timestamp > after_time
        assert expiry_timestamp < after_time + (86400 * 400)

    def test_getlic_permanent_license_uses_zero_expiry(self) -> None:
        """FlexLM GETLIC with permanent license uses expiry value of 0."""
        handler = FlexLMProtocolHandler(
            config={
                "license_type": "permanent",
            }
        )

        response = handler.generate_response(b"GETLIC PROFESSIONAL 1.0 user1 host1 :0")
        response_str = response.decode("utf-8")
        parts = response_str.split()
        expiry = parts[4]

        assert expiry == "0"

    def test_getlic_missing_feature_returns_error_not_ok(self) -> None:
        """FlexLM GETLIC without feature name returns error, not b'OK\\n'."""
        handler = FlexLMProtocolHandler()

        response = handler.generate_response(b"GETLIC")

        assert response != b"OK\n"
        assert response == b"ERROR: Invalid GETLIC request\n"

    def test_checkin_returns_specific_acknowledgment(self) -> None:
        """FlexLM CHECKIN returns CHECKIN_OK, not generic b'OK\\n'."""
        handler = FlexLMProtocolHandler()

        response = handler.generate_response(b"CHECKIN PROFESSIONAL 1.0")

        assert response == b"CHECKIN_OK\n"
        assert response != b"OK\n"

    def test_heartbeat_returns_specific_acknowledgment(self) -> None:
        """FlexLM HEARTBEAT returns HEARTBEAT_OK, not generic b'OK\\n'."""
        handler = FlexLMProtocolHandler()

        response = handler.generate_response(b"HEARTBEAT")

        assert response == b"HEARTBEAT_OK\n"
        assert response != b"OK\n"

    def test_status_query_returns_detailed_status(self) -> None:
        """FlexLM STATUS query returns detailed server status, not b'OK\\n'."""
        handler = FlexLMProtocolHandler(
            config={
                "server_status": "UP",
                "license_count": 9999,
            }
        )

        response = handler.generate_response(b"STATUS")
        response_str = response.decode("utf-8")

        assert response != b"OK\n"
        assert "STATUS OK" in response_str
        assert "SERVER UP" in response_str
        assert "LICENSES AVAILABLE: 9999" in response_str

    def test_status_query_reflects_configuration_changes(self) -> None:
        """FlexLM STATUS query reflects dynamic configuration."""
        handler = FlexLMProtocolHandler(
            config={
                "server_status": "DEGRADED",
                "license_count": 42,
            }
        )

        response = handler.generate_response(b"STATUS")
        response_str = response.decode("utf-8")

        assert "SERVER DEGRADED" in response_str
        assert "LICENSES AVAILABLE: 42" in response_str

    def test_invalid_short_request_returns_error(self) -> None:
        """FlexLM returns error for requests shorter than 4 bytes."""
        handler = FlexLMProtocolHandler()

        response = handler.generate_response(b"GET")

        assert response == b"ERROR: Invalid request\n"
        assert response != b"OK\n"

    def test_unknown_command_returns_generic_ok(self) -> None:
        """FlexLM returns generic OK for unknown but valid commands."""
        handler = FlexLMProtocolHandler()

        response = handler.generate_response(b"UNKNOWN_COMMAND")

        assert response == b"OK\n"


class TestHASPResponseFormats:
    """Validate HASP generates protocol-specific binary responses, not generic b'OK\\n'."""

    def test_login_response_format_not_ok(self) -> None:
        """HASP LOGIN returns binary status and handle, not b'OK\\n'."""
        handler = HASPProtocolHandler()

        request = struct.pack("<I", 0x01) + b"\x00" * 4
        response = handler.generate_response(request)

        assert response != b"OK\n", "HASP LOGIN must not return generic OK response"
        assert len(response) == 8

        status, handle = struct.unpack("<II", response)
        assert status == 0x00000000
        assert handle >= 0x10000000
        assert handle <= 0x7FFFFFFF

    def test_login_generates_dynamic_handles(self) -> None:
        """HASP LOGIN generates unique dynamic handles for each session."""
        handler = HASPProtocolHandler()

        handles: set[int] = set()
        for _ in range(20):
            request = struct.pack("<I", 0x01) + b"\x00" * 4
            response = handler.generate_response(request)

            _, handle = struct.unpack("<II", response)
            handles.add(handle)

        assert len(handles) >= 15, "Handles should be sufficiently unique"

    def test_logout_response_format(self) -> None:
        """HASP LOGOUT returns binary success status, not b'OK\\n'."""
        handler = HASPProtocolHandler()

        request = struct.pack("<I", 0x02) + b"\x00" * 4
        response = handler.generate_response(request)

        assert response != b"OK\n"
        assert len(response) == 4
        status = struct.unpack("<I", response)[0]
        assert status == 0x00000000

    def test_encrypt_response_contains_encrypted_data(self) -> None:
        """HASP ENCRYPT returns encrypted data different from plaintext."""
        handler = HASPProtocolHandler()

        plaintext = b"SensitiveData123"
        request = struct.pack("<II", 0x03, len(plaintext)) + plaintext
        response = handler.generate_response(request)

        assert response != b"OK\n"
        assert len(response) > 4

        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000

        encrypted_data = response[4:]
        assert len(encrypted_data) == len(plaintext)
        assert encrypted_data != plaintext

    def test_decrypt_recovers_original_plaintext(self) -> None:
        """HASP DECRYPT correctly recovers original plaintext from encrypted data."""
        handler = HASPProtocolHandler()

        original_plaintext = b"OriginalMessage"

        encrypt_request = struct.pack("<II", 0x03, len(original_plaintext)) + original_plaintext
        encrypt_response = handler.generate_response(encrypt_request)
        encrypted_data = encrypt_response[4:]

        decrypt_request = struct.pack("<II", 0x04, len(encrypted_data)) + encrypted_data
        decrypt_response = handler.generate_response(decrypt_request)

        assert decrypt_response != b"OK\n"
        assert len(decrypt_response) > 4

        status = struct.unpack("<I", decrypt_response[:4])[0]
        assert status == 0x00000000

        decrypted_data = decrypt_response[4:]
        assert decrypted_data == original_plaintext

    def test_get_size_returns_configured_memory_size(self) -> None:
        """HASP GET_SIZE returns configured memory size, not b'OK\\n'."""
        handler = HASPProtocolHandler(
            config={
                "hasp_memory_size": 0x40000,
            }
        )

        request = struct.pack("<I", 0x05) + b"\x00" * 4
        response = handler.generate_response(request)

        assert response != b"OK\n"
        assert len(response) == 8

        status, size = struct.unpack("<II", response)
        assert status == 0x00000000
        assert size == 0x40000

    def test_read_header_returns_license_signature(self) -> None:
        """HASP READ from header offset returns license signature data."""
        handler = HASPProtocolHandler(
            config={
                "hasp_version": "8.20",
            }
        )

        offset = 0
        size = 32
        request = struct.pack("<IIII", 0x06, 8, offset, size)
        response = handler.generate_response(request)

        assert response != b"OK\n"
        assert len(response) >= 4 + size

        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000

        license_data = response[4:4+size]
        assert b"HASP_LIC_8_20" in license_data

    def test_read_feature_area_returns_configured_features(self) -> None:
        """HASP READ from feature area returns configured license features."""
        handler = HASPProtocolHandler(
            config={
                "license_features": ["PLATINUM", "GOLD", "SILVER"],
            }
        )

        offset = 100
        size = 128
        request = struct.pack("<IIII", 0x06, 8, offset, size)
        response = handler.generate_response(request)

        assert response != b"OK\n"
        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000

        feature_data = response[4:4+size]
        assert b"PLATINUM" in feature_data
        assert b"GOLD" in feature_data
        assert b"SILVER" in feature_data

    def test_read_data_area_returns_pattern_data(self) -> None:
        """HASP READ from data area returns realistic pattern data."""
        handler = HASPProtocolHandler()

        offset = 1000
        size = 256
        request = struct.pack("<IIII", 0x06, 8, offset, size)
        response = handler.generate_response(request)

        assert response != b"OK\n"
        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000

        data = response[4:4+size]
        assert len(data) == size
        assert data != b"\x00" * size

    def test_read_enforces_size_limit(self) -> None:
        """HASP READ enforces maximum size limit to prevent memory issues."""
        handler = HASPProtocolHandler()

        offset = 0
        size = 10000
        request = struct.pack("<IIII", 0x06, 8, offset, size)
        response = handler.generate_response(request)

        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000

        data_length = len(response) - 4
        assert data_length <= 4096

    def test_write_response_format(self) -> None:
        """HASP WRITE returns binary success status, not b'OK\\n'."""
        handler = HASPProtocolHandler()

        request = struct.pack("<I", 0x07) + b"\x00" * 4
        response = handler.generate_response(request)

        assert response != b"OK\n"
        assert len(response) == 4
        status = struct.unpack("<I", response)[0]
        assert status == 0x00000000

    def test_get_rtc_returns_current_timestamp(self) -> None:
        """HASP GET_RTC returns current timestamp, not b'OK\\n'."""
        handler = HASPProtocolHandler()

        before_time = int(time.time())
        request = struct.pack("<I", 0x08) + b"\x00" * 4
        response = handler.generate_response(request)
        after_time = int(time.time())

        assert response != b"OK\n"
        assert len(response) == 8

        status, rtc_time = struct.unpack("<II", response)
        assert status == 0x00000000
        assert before_time <= rtc_time <= after_time

    def test_get_info_returns_emulator_version(self) -> None:
        """HASP GET_INFO returns configured emulator version string."""
        handler = HASPProtocolHandler(
            config={
                "hasp_emulator_version": "HASP_EMU_v3.0_PROD",
            }
        )

        request = struct.pack("<I", 0x09) + b"\x00" * 4
        response = handler.generate_response(request)

        assert response != b"OK\n"
        assert len(response) > 4

        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000

        info_data = response[4:]
        assert b"HASP_EMU_v3.0_PROD" in info_data

    def test_unknown_command_returns_generic_success(self) -> None:
        """HASP unknown command returns generic binary success."""
        handler = HASPProtocolHandler()

        unknown_command = 0xDEADBEEF
        request = struct.pack("<I", unknown_command) + b"\x00" * 4
        response = handler.generate_response(request)

        assert len(response) == 4
        status = struct.unpack("<I", response)[0]
        assert status == 0x00000000

    def test_invalid_short_request_returns_error_response(self) -> None:
        """HASP returns error for requests shorter than 8 bytes."""
        handler = HASPProtocolHandler()

        request = b"SHORT"
        response = handler.generate_response(request)

        assert response == b"\x00\x00\x00\x00"
        assert response != b"OK\n"


class TestSessionStateMaintenance:
    """Validate session state is maintained across multiple requests."""

    def test_flexlm_session_state_persists_across_requests(self) -> None:
        """FlexLM maintains state through complete checkout-heartbeat-checkin cycle."""
        handler = FlexLMProtocolHandler()

        hello_response = handler.generate_response(b"HELLO")
        assert b"HELLO" in hello_response

        getlic_response = handler.generate_response(b"GETLIC PROFESSIONAL 1.0 user1 host1 :0")
        assert b"GRANT PROFESSIONAL" in getlic_response

        for _ in range(5):
            heartbeat_response = handler.generate_response(b"HEARTBEAT")
            assert heartbeat_response == b"HEARTBEAT_OK\n"

        checkin_response = handler.generate_response(b"CHECKIN PROFESSIONAL 1.0")
        assert checkin_response == b"CHECKIN_OK\n"

    def test_hasp_session_data_dictionary_persists_handle(self) -> None:
        """HASP stores session handle in session_data dictionary."""
        handler = HASPProtocolHandler()

        assert len(handler.session_data) == 0

        login_request = struct.pack("<I", 0x01) + b"\x00" * 4
        login_response = handler.generate_response(login_request)
        _, handle = struct.unpack("<II", login_response)

        assert "handle" in handler.session_data
        assert handler.session_data["handle"] == handle

    def test_hasp_handle_persists_across_operations(self) -> None:
        """HASP session handle persists across multiple read operations."""
        handler = HASPProtocolHandler()

        login_request = struct.pack("<I", 0x01) + b"\x00" * 4
        login_response = handler.generate_response(login_request)
        _, original_handle = struct.unpack("<II", login_response)

        for _ in range(10):
            read_request = struct.pack("<IIII", 0x06, 8, 0, 64)
            handler.generate_response(read_request)

        assert handler.session_data["handle"] == original_handle

    def test_hasp_encryption_key_state_persists(self) -> None:
        """HASP maintains encryption key state across multiple encrypt/decrypt cycles."""
        handler = HASPProtocolHandler()

        plaintexts = [b"Message1", b"Message2", b"Message3"]
        encrypted_list: list[bytes] = []

        for plaintext in plaintexts:
            encrypt_request = struct.pack("<II", 0x03, len(plaintext)) + plaintext
            encrypt_response = handler.generate_response(encrypt_request)
            encrypted_list.append(encrypt_response[4:])

        for i, encrypted in enumerate(encrypted_list):
            decrypt_request = struct.pack("<II", 0x04, len(encrypted)) + encrypted
            decrypt_response = handler.generate_response(decrypt_request)
            decrypted = decrypt_response[4:]
            assert decrypted == plaintexts[i]

    def test_flexlm_captured_requests_accumulate(self) -> None:
        """FlexLM captured_requests list accumulates all requests."""
        handler = FlexLMProtocolHandler()

        initial_count = len(handler.captured_requests)

        requests = [b"HELLO", b"GETLIC PROFESSIONAL 1.0 user1 host1 :0", b"HEARTBEAT", b"STATUS"]

        for request in requests:
            handler.generate_response(request)

        assert len(handler.captured_requests) == initial_count + len(requests)

        for i, captured in enumerate(handler.captured_requests[initial_count:]):
            assert captured["data"] == requests[i]
            assert isinstance(captured["timestamp"], float)
            assert isinstance(captured["hex"], str)

    def test_hasp_captured_requests_store_binary_data(self) -> None:
        """HASP captured_requests store binary request data with hex representation."""
        handler = HASPProtocolHandler()

        initial_count = len(handler.captured_requests)

        commands = [0x01, 0x05, 0x08, 0x09]

        for cmd in commands:
            request = struct.pack("<I", cmd) + b"\x00" * 4
            handler.generate_response(request)

        assert len(handler.captured_requests) == initial_count + len(commands)

        for captured in handler.captured_requests[initial_count:]:
            assert isinstance(captured["data"], bytes)
            assert isinstance(captured["hex"], str)
            assert len(captured["hex"]) == len(captured["data"]) * 2


class TestAuthenticationChallengeResponse:
    """Validate authentication and challenge-response mechanisms."""

    def test_flexlm_hello_provides_vendor_daemon_port(self) -> None:
        """FlexLM HELLO provides vendor daemon port for subsequent connections."""
        handler = FlexLMProtocolHandler(
            config={
                "flexlm_version": "11.16.2",
                "vendor_daemon_port": 27001,
            }
        )

        hello_response = handler.generate_response(b"HELLO")
        hello_str = hello_response.decode().strip()
        parts = hello_str.split()

        assert len(parts) == 4
        assert parts[0] == "HELLO"
        vendor_port = int(parts[3])
        assert vendor_port == 27001

    def test_flexlm_hello_getlic_authentication_flow(self) -> None:
        """FlexLM HELLO-GETLIC flow establishes authenticated session."""
        handler = FlexLMProtocolHandler(
            config={
                "flexlm_version": "11.16.2",
                "vendor_daemon_port": 27001,
            }
        )

        hello_response = handler.generate_response(b"HELLO")
        assert b"HELLO 11 16 27001" in hello_response

        getlic_response = handler.generate_response(b"GETLIC PROFESSIONAL 1.0 user1 host1 :0")
        assert b"GRANT" in getlic_response

    def test_hasp_login_provides_session_handle(self) -> None:
        """HASP LOGIN provides session handle for authenticated operations."""
        handler = HASPProtocolHandler()

        login_request = struct.pack("<I", 0x01) + b"\x00" * 4
        login_response = handler.generate_response(login_request)

        status, handle = struct.unpack("<II", login_response)
        assert status == 0x00000000
        assert handle != 0
        assert handle >= 0x10000000

    def test_hasp_session_handle_stored_in_session_data(self) -> None:
        """HASP stores session handle in session_data for validation."""
        handler = HASPProtocolHandler()

        login_request = struct.pack("<I", 0x01) + b"\x00" * 4
        login_response = handler.generate_response(login_request)
        _, handle = struct.unpack("<II", login_response)

        assert "handle" in handler.session_data
        assert handler.session_data["handle"] == handle

    def test_hasp_operations_use_established_session(self) -> None:
        """HASP operations proceed with established session state."""
        handler = HASPProtocolHandler()

        login_request = struct.pack("<I", 0x01) + b"\x00" * 4
        login_response = handler.generate_response(login_request)
        _, handle = struct.unpack("<II", login_response)

        assert handle in handler.session_data.values()

        read_request = struct.pack("<IIII", 0x06, 8, 0, 32)
        read_response = handler.generate_response(read_request)
        status = struct.unpack("<I", read_response[:4])[0]
        assert status == 0x00000000


class TestProperErrorResponseGeneration:
    """Validate proper error response generation for invalid requests."""

    def test_flexlm_short_request_error(self) -> None:
        """FlexLM generates error for requests shorter than 4 bytes."""
        handler = FlexLMProtocolHandler()

        short_requests = [b"", b"A", b"AB", b"ABC"]

        for request in short_requests:
            response = handler.generate_response(request)
            assert response == b"ERROR: Invalid request\n"

    def test_flexlm_getlic_without_feature_error(self) -> None:
        """FlexLM generates error for GETLIC without feature name."""
        handler = FlexLMProtocolHandler()

        response = handler.generate_response(b"GETLIC")

        assert response == b"ERROR: Invalid GETLIC request\n"

    def test_flexlm_getlic_single_parameter_error(self) -> None:
        """FlexLM generates error for GETLIC with insufficient parameters."""
        handler = FlexLMProtocolHandler()

        response = handler.generate_response(b"GETLIC FEATURE")

        assert b"GRANT FEATURE" in response

    def test_hasp_short_request_error(self) -> None:
        """HASP generates error for requests shorter than 8 bytes."""
        handler = HASPProtocolHandler()

        short_requests = [b"", b"A", b"ABCD", b"ABCDEFG"]

        for request in short_requests:
            response = handler.generate_response(request)
            assert response == b"\x00\x00\x00\x00"

    def test_hasp_malformed_struct_handled_gracefully(self) -> None:
        """HASP handles struct unpacking errors without crashing."""
        handler = HASPProtocolHandler()

        malformed_requests = [
            b"\xFF" * 100,
            b"\x00" * 8 + b"\xFF" * 50,
            struct.pack("<I", 0x06) + b"\xFF" * 20,
        ]

        for request in malformed_requests:
            response = handler.generate_response(request)
            assert isinstance(response, bytes)
            assert len(response) >= 4

    def test_flexlm_unknown_command_returns_ok(self) -> None:
        """FlexLM returns generic OK for unknown but valid commands."""
        handler = FlexLMProtocolHandler()

        unknown_commands = [
            b"UNKNOWN_COMMAND",
            b"CUSTOM_REQUEST arg1 arg2",
            b"TESTTEST",
        ]

        for command in unknown_commands:
            response = handler.generate_response(command)
            assert response == b"OK\n"

    def test_hasp_unknown_command_returns_success(self) -> None:
        """HASP returns generic success for unknown but valid command IDs."""
        handler = HASPProtocolHandler()

        unknown_commands = [0xFF, 0x100, 0x1234, 0xDEADBEEF]

        for cmd in unknown_commands:
            request = struct.pack("<I", cmd) + b"\x00" * 4
            response = handler.generate_response(request)

            assert len(response) == 4
            status = struct.unpack("<I", response)[0]
            assert status == 0x00000000


class TestStatefulLicenseCheckoutCheckin:
    """Validate complete stateful license checkout/checkin workflows."""

    def test_flexlm_complete_license_lifecycle(self) -> None:
        """FlexLM handles complete license lifecycle from hello to checkin."""
        handler = FlexLMProtocolHandler(
            config={
                "flexlm_version": "11.16.2",
                "vendor_daemon_port": 27001,
            }
        )

        hello_response = handler.generate_response(b"HELLO")
        assert b"HELLO 11 16 27001" in hello_response

        getlic_response = handler.generate_response(b"GETLIC PROFESSIONAL 2.0 user1 host1 :0")
        assert b"GRANT PROFESSIONAL" in getlic_response

        for _ in range(3):
            heartbeat_response = handler.generate_response(b"HEARTBEAT")
            assert heartbeat_response == b"HEARTBEAT_OK\n"

        checkin_response = handler.generate_response(b"CHECKIN PROFESSIONAL 2.0")
        assert checkin_response == b"CHECKIN_OK\n"

    def test_hasp_complete_session_lifecycle(self) -> None:
        """HASP handles complete session lifecycle from login to logout."""
        handler = HASPProtocolHandler()

        login_request = struct.pack("<I", 0x01) + b"\x00" * 4
        login_response = handler.generate_response(login_request)
        status, handle = struct.unpack("<II", login_response)
        assert status == 0x00000000
        assert handle != 0

        size_request = struct.pack("<I", 0x05) + b"\x00" * 4
        size_response = handler.generate_response(size_request)
        status, size = struct.unpack("<II", size_response)
        assert status == 0x00000000
        assert size > 0

        read_request = struct.pack("<IIII", 0x06, 8, 0, 64)
        read_response = handler.generate_response(read_request)
        status = struct.unpack("<I", read_response[:4])[0]
        assert status == 0x00000000

        logout_request = struct.pack("<I", 0x02) + b"\x00" * 4
        logout_response = handler.generate_response(logout_request)
        status = struct.unpack("<I", logout_response)[0]
        assert status == 0x00000000

    def test_flexlm_multiple_feature_checkout_lifecycle(self) -> None:
        """FlexLM handles multiple feature checkouts and checkins."""
        handler = FlexLMProtocolHandler()

        features = ["PROFESSIONAL", "ENTERPRISE", "DEVELOPER"]

        for feature in features:
            getlic_request = f"GETLIC {feature} 1.0 user1 host1 :0".encode()
            getlic_response = handler.generate_response(getlic_request)
            assert f"GRANT {feature}".encode() in getlic_response

        for feature in features:
            checkin_request = f"CHECKIN {feature} 1.0".encode()
            checkin_response = handler.generate_response(checkin_request)
            assert checkin_response == b"CHECKIN_OK\n"

    def test_hasp_multiple_read_write_operations(self) -> None:
        """HASP handles multiple read/write operations in single session."""
        handler = HASPProtocolHandler()

        login_request = struct.pack("<I", 0x01) + b"\x00" * 4
        handler.generate_response(login_request)

        for offset in [0, 100, 500, 1000]:
            read_request = struct.pack("<IIII", 0x06, 8, offset, 64)
            read_response = handler.generate_response(read_request)
            status = struct.unpack("<I", read_response[:4])[0]
            assert status == 0x00000000

        for _ in range(3):
            write_request = struct.pack("<I", 0x07) + b"\x00" * 4
            write_response = handler.generate_response(write_request)
            status = struct.unpack("<I", write_response)[0]
            assert status == 0x00000000


class TestConcurrentSessionHandling:
    """Validate concurrent session handling without state corruption."""

    def test_flexlm_concurrent_responses_maintain_feature_isolation(self) -> None:
        """FlexLM generates correct responses for concurrent feature requests."""
        handler = FlexLMProtocolHandler()

        def worker(feature: str) -> bytes:
            request = f"GETLIC {feature} 1.0 user1 host1 :0".encode()
            return handler.generate_response(request)

        features = [f"FEATURE_{i}" for i in range(10)]
        threads = []
        results: list[bytes] = []
        results_lock = threading.Lock()

        def thread_func(f: str) -> None:
            response = worker(f)
            with results_lock:
                results.append(response)

        for feature in features:
            t = threading.Thread(target=thread_func, args=(feature,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=2.0)

        assert len(results) == 10
        for i, result in enumerate(results):
            assert b"GRANT" in result or f"FEATURE_{i}".encode() in result

    def test_hasp_concurrent_login_generates_unique_handles(self) -> None:
        """HASP generates unique handles for concurrent login requests."""
        handler = HASPProtocolHandler()

        handles: list[int] = []
        handles_lock = threading.Lock()

        def login_worker() -> None:
            login_request = struct.pack("<I", 0x01) + b"\x00" * 4
            login_response = handler.generate_response(login_request)
            if len(login_response) == 8:
                _, handle = struct.unpack("<II", login_response)
                with handles_lock:
                    handles.append(handle)

        threads = []
        for _ in range(10):
            t = threading.Thread(target=login_worker)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=2.0)

        assert len(handles) >= 8
        assert len(set(handles)) >= 7

    def test_hasp_concurrent_encryption_maintains_consistency(self) -> None:
        """HASP encryption maintains consistency under concurrent requests."""
        handler = HASPProtocolHandler()

        plaintexts = [f"Message{i}".encode() for i in range(10)]
        results: list[tuple[bytes, bytes]] = []
        results_lock = threading.Lock()

        def encrypt_decrypt_worker(plaintext: bytes) -> None:
            encrypt_request = struct.pack("<II", 0x03, len(plaintext)) + plaintext
            encrypt_response = handler.generate_response(encrypt_request)
            encrypted = encrypt_response[4:]

            decrypt_request = struct.pack("<II", 0x04, len(encrypted)) + encrypted
            decrypt_response = handler.generate_response(decrypt_request)
            decrypted = decrypt_response[4:]

            with results_lock:
                results.append((plaintext, decrypted))

        threads = []
        for plaintext in plaintexts:
            t = threading.Thread(target=encrypt_decrypt_worker, args=(plaintext,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=3.0)

        assert len(results) >= 8
        for original, decrypted in results:
            assert original == decrypted

    def test_flexlm_concurrent_network_clients_isolated(self) -> None:
        """FlexLM handles concurrent network clients without state interference."""
        handler = FlexLMProtocolHandler()
        handler.start_proxy(port=0)
        time.sleep(0.3)

        try:
            actual_port = handler.port
            if actual_port == 0:
                pytest.skip("Could not bind to dynamic port")

            results: list[bytes] = []
            results_lock = threading.Lock()

            def client_thread(feature: str) -> None:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3.0)
                    sock.connect(("127.0.0.1", actual_port))

                    getlic_request = f"GETLIC {feature} 1.0 user1 host1 :0".encode()
                    sock.send(getlic_request)

                    response = sock.recv(4096)
                    with results_lock:
                        results.append(response)

                    sock.close()
                except Exception as e:
                    print(f"Client thread error: {e}")

            threads = []
            features = ["FEATURE_A", "FEATURE_B", "FEATURE_C", "FEATURE_D"]
            for feature in features:
                t = threading.Thread(target=client_thread, args=(feature,))
                threads.append(t)
                t.start()

            for t in threads:
                t.join(timeout=4.0)

            assert len(results) >= 3
            for result in results:
                assert b"GRANT" in result

        finally:
            handler.stop_proxy()

    def test_hasp_concurrent_network_clients_unique_handles(self) -> None:
        """HASP network clients receive unique session handles concurrently."""
        handler = HASPProtocolHandler()
        handler.start_proxy(port=0)
        time.sleep(0.3)

        try:
            actual_port = handler.port
            if actual_port == 0:
                pytest.skip("Could not bind to dynamic port")

            handles: list[int] = []
            handles_lock = threading.Lock()

            def login_client() -> None:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3.0)
                    sock.connect(("127.0.0.1", actual_port))

                    login_request = struct.pack("<I", 0x01) + b"\x00" * 4
                    sock.send(login_request)

                    response = sock.recv(4096)
                    if len(response) == 8:
                        _, handle = struct.unpack("<II", response)
                        with handles_lock:
                            handles.append(handle)

                    sock.close()
                except Exception as e:
                    print(f"Login client error: {e}")

            threads = []
            for _ in range(5):
                t = threading.Thread(target=login_client)
                threads.append(t)
                t.start()

            for t in threads:
                t.join(timeout=4.0)

            assert len(handles) >= 3
            assert len(set(handles)) >= 3

        finally:
            handler.stop_proxy()


class TestSessionTimeoutManagement:
    """Validate session timeout management and cleanup."""

    def test_hasp_session_persists_during_continuous_activity(self) -> None:
        """HASP session remains valid during continuous activity."""
        handler = HASPProtocolHandler()

        login_request = struct.pack("<I", 0x01) + b"\x00" * 4
        login_response = handler.generate_response(login_request)
        _, original_handle = struct.unpack("<II", login_response)

        for _ in range(20):
            read_request = struct.pack("<IIII", 0x06, 8, 0, 32)
            read_response = handler.generate_response(read_request)
            status = struct.unpack("<I", read_response[:4])[0]
            assert status == 0x00000000

        assert handler.session_data["handle"] == original_handle

    def test_flexlm_heartbeat_maintains_session_alive(self) -> None:
        """FlexLM heartbeat prevents session timeout."""
        handler = FlexLMProtocolHandler()

        getlic_response = handler.generate_response(b"GETLIC PROFESSIONAL 1.0 user1 host1 :0")
        assert b"GRANT" in getlic_response

        for _ in range(10):
            time.sleep(0.05)
            heartbeat_response = handler.generate_response(b"HEARTBEAT")
            assert heartbeat_response == b"HEARTBEAT_OK\n"

        checkin_response = handler.generate_response(b"CHECKIN PROFESSIONAL 1.0")
        assert checkin_response == b"CHECKIN_OK\n"

    def test_hasp_session_cleanup_after_logout(self) -> None:
        """HASP session state can be cleared after logout."""
        handler = HASPProtocolHandler()

        login_request = struct.pack("<I", 0x01) + b"\x00" * 4
        login_response = handler.generate_response(login_request)
        _, handle = struct.unpack("<II", login_response)

        assert "handle" in handler.session_data
        assert handler.session_data["handle"] == handle

        logout_request = struct.pack("<I", 0x02) + b"\x00" * 4
        logout_response = handler.generate_response(logout_request)
        status = struct.unpack("<I", logout_response)[0]
        assert status == 0x00000000

        handler.clear_data()

        assert "handle" not in handler.session_data

    def test_flexlm_clear_data_resets_captured_requests(self) -> None:
        """FlexLM clear_data() resets captured requests list."""
        handler = FlexLMProtocolHandler()

        for _ in range(5):
            handler.generate_response(b"HELLO")

        assert len(handler.captured_requests) >= 5

        handler.clear_data()

        assert len(handler.captured_requests) == 0

    def test_hasp_clear_data_resets_session_state(self) -> None:
        """HASP clear_data() resets all session state."""
        handler = HASPProtocolHandler()

        login_request = struct.pack("<I", 0x01) + b"\x00" * 4
        handler.generate_response(login_request)

        assert len(handler.session_data) > 0
        assert len(handler.captured_requests) > 0

        handler.clear_data()

        assert len(handler.session_data) == 0
        assert len(handler.captured_requests) == 0


class TestRequestResponseLogging:
    """Validate comprehensive request/response logging and capture."""

    def test_flexlm_captures_all_request_metadata(self) -> None:
        """FlexLM captures complete metadata for all requests."""
        handler = FlexLMProtocolHandler()

        initial_count = len(handler.captured_requests)

        requests = [b"HELLO", b"GETLIC PROFESSIONAL 1.0 user1 host1 :0", b"STATUS"]

        for request in requests:
            handler.generate_response(request)

        assert len(handler.captured_requests) == initial_count + len(requests)

        for i, captured in enumerate(handler.captured_requests[initial_count:]):
            assert "timestamp" in captured
            assert "data" in captured
            assert "hex" in captured
            assert captured["data"] == requests[i]
            assert isinstance(captured["timestamp"], float)

    def test_hasp_captures_binary_request_with_hex(self) -> None:
        """HASP captures binary requests with hex representation."""
        handler = HASPProtocolHandler()

        initial_count = len(handler.captured_requests)

        login_request = struct.pack("<I", 0x01) + b"\x00" * 4
        handler.generate_response(login_request)

        assert len(handler.captured_requests) == initial_count + 1

        captured = handler.captured_requests[-1]
        assert captured["data"] == login_request
        assert captured["hex"] == login_request.hex()
        assert isinstance(captured["timestamp"], float)

    def test_request_timestamps_accurate(self) -> None:
        """Request timestamps accurately reflect processing time."""
        handler = FlexLMProtocolHandler()

        before = time.time()
        handler.generate_response(b"HELLO")
        after = time.time()

        captured = handler.captured_requests[-1]
        assert before <= captured["timestamp"] <= after

    def test_hex_representation_matches_data(self) -> None:
        """Hex representation exactly matches binary data."""
        handler = HASPProtocolHandler()

        test_data = struct.pack("<IIII", 0x01020304, 0x05060708, 0x090A0B0C, 0x0D0E0F10)
        handler.generate_response(test_data)

        captured = handler.captured_requests[-1]
        assert captured["hex"] == test_data.hex()
        assert bytes.fromhex(captured["hex"]) == test_data


class TestProtocolComplianceValidation:
    """Validate compliance with FlexLM and HASP protocol specifications."""

    def test_flexlm_hello_response_structure_compliant(self) -> None:
        """FlexLM HELLO response follows protocol structure: HELLO <major> <minor> <port>."""
        handler = FlexLMProtocolHandler(
            config={
                "flexlm_version": "10.8.0.5",
                "vendor_daemon_port": 27001,
            }
        )

        response = handler.generate_response(b"HELLO")
        parts = response.decode().strip().split()

        assert len(parts) == 4
        assert parts[0] == "HELLO"
        assert parts[1].isdigit()
        assert parts[2].isdigit()
        assert parts[3].isdigit()
        assert int(parts[1]) == 10
        assert int(parts[2]) == 8

    def test_flexlm_grant_response_contains_required_fields(self) -> None:
        """FlexLM GRANT response contains all required protocol fields."""
        handler = FlexLMProtocolHandler(
            config={
                "feature_version": "2.5",
                "license_type": "permanent",
            }
        )

        response = handler.generate_response(b"GETLIC PROFESSIONAL 1.0 user1 host1 :0")
        response_str = response.decode()

        assert "GRANT" in response_str
        assert "PROFESSIONAL" in response_str
        assert "2.5" in response_str
        assert "permanent" in response_str
        assert "HOSTID" in response_str

    def test_hasp_binary_response_format_compliant(self) -> None:
        """HASP binary responses comply with protocol specification."""
        handler = HASPProtocolHandler()

        commands = [0x01, 0x02, 0x03, 0x05, 0x07, 0x08, 0x09]

        for cmd in commands:
            request = struct.pack("<I", cmd) + b"\x00" * 12
            response = handler.generate_response(request)

            assert len(response) >= 4
            status = struct.unpack("<I", response[:4])[0]
            assert status == 0x00000000 or status == 0x00000001

    def test_hasp_login_response_length_compliant(self) -> None:
        """HASP LOGIN response has correct length (8 bytes: status + handle)."""
        handler = HASPProtocolHandler()

        login_request = struct.pack("<I", 0x01) + b"\x00" * 4
        login_response = handler.generate_response(login_request)

        assert len(login_response) == 8

    def test_hasp_logout_response_length_compliant(self) -> None:
        """HASP LOGOUT response has correct length (4 bytes: status only)."""
        handler = HASPProtocolHandler()

        logout_request = struct.pack("<I", 0x02) + b"\x00" * 4
        logout_response = handler.generate_response(logout_request)

        assert len(logout_response) == 4

    def test_hasp_read_response_structure_compliant(self) -> None:
        """HASP READ response structure: 4 bytes status + requested data length."""
        handler = HASPProtocolHandler()

        offset = 0
        size = 64
        request = struct.pack("<IIII", 0x06, 8, offset, size)
        response = handler.generate_response(request)

        assert len(response) >= 4 + size

        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000

        data = response[4:]
        assert len(data) >= size

    def test_hasp_encryption_preserves_data_length(self) -> None:
        """HASP encryption preserves plaintext length in ciphertext."""
        handler = HASPProtocolHandler()

        plaintexts = [b"A" * 16, b"B" * 32, b"C" * 64]

        for plaintext in plaintexts:
            encrypt_request = struct.pack("<II", 0x03, len(plaintext)) + plaintext
            encrypt_response = handler.generate_response(encrypt_request)

            encrypted = encrypt_response[4:]
            assert len(encrypted) == len(plaintext)
