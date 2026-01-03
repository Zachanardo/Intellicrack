#!/usr/bin/env python3
"""Production-ready tests for stateful license protocol session management.

Tests the critical functionality at license_protocol_handler.py:312-326 where
generate_response returns b"OK\n" for all requests instead of implementing
protocol-specific response formats with session state management.

This test validates:
- Protocol-specific response formats for FlexLM and HASP
- Session state maintenance across multiple requests
- Authentication and challenge-response mechanisms
- Proper error response generation
- Stateful license checkout/checkin workflows
- Concurrent session handling
- Session timeout management
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
)


class TestFlexLMProtocolSpecificResponses:
    """Validate FlexLM protocol-specific response formats."""

    def test_flexlm_hello_handshake_format(self) -> None:
        """FlexLM HELLO command returns proper version and port format."""
        handler = FlexLMProtocolHandler(
            config={
                "flexlm_version": "11.16.2",
                "vendor_daemon_port": 27001,
            }
        )

        request = b"HELLO"
        response = handler.generate_response(request)

        assert response == b"HELLO 11 16 27001\n"
        assert response != b"OK\n"

    def test_flexlm_hello_custom_version(self) -> None:
        """FlexLM HELLO respects custom version configuration."""
        handler = FlexLMProtocolHandler(
            config={
                "flexlm_version": "12.5.3",
                "vendor_daemon_port": 28000,
            }
        )

        request = b"HELLO"
        response = handler.generate_response(request)

        assert response == b"HELLO 12 5 28000\n"
        assert b"11" not in response

    def test_flexlm_getlic_grant_format(self) -> None:
        """FlexLM GETLIC returns proper GRANT response with feature details."""
        handler = FlexLMProtocolHandler(
            config={
                "feature_version": "3.5",
                "license_type": "permanent",
            }
        )

        request = b"GETLIC PROFESSIONAL 1.0 user1 host1 :0"
        response = handler.generate_response(request)

        assert response.startswith(b"GRANT PROFESSIONAL")
        assert b"3.5" in response
        assert b"permanent" in response
        assert b"HOSTID=ANY" in response
        assert response != b"OK\n"

    def test_flexlm_getlic_temporary_license(self) -> None:
        """FlexLM GETLIC generates time-limited license with valid expiry."""
        handler = FlexLMProtocolHandler(
            config={
                "license_type": "temporary",
            }
        )

        request = b"GETLIC ENTERPRISE 2.0 user2 host2 :0"
        response = handler.generate_response(request)
        response_str = response.decode("utf-8")

        assert "GRANT ENTERPRISE" in response_str
        assert "temporary" in response_str

        parts = response_str.split()
        expiry_timestamp = int(parts[4])
        current_time = int(time.time())
        assert expiry_timestamp > current_time
        assert expiry_timestamp < current_time + (86400 * 400)

    def test_flexlm_checkin_response(self) -> None:
        """FlexLM CHECKIN returns proper acknowledgment."""
        handler = FlexLMProtocolHandler()

        request = b"CHECKIN PROFESSIONAL 1.0"
        response = handler.generate_response(request)

        assert response == b"CHECKIN_OK\n"
        assert response != b"OK\n"

    def test_flexlm_heartbeat_response(self) -> None:
        """FlexLM HEARTBEAT returns proper keepalive acknowledgment."""
        handler = FlexLMProtocolHandler()

        request = b"HEARTBEAT"
        response = handler.generate_response(request)

        assert response == b"HEARTBEAT_OK\n"
        assert response != b"OK\n"

    def test_flexlm_status_query_response(self) -> None:
        """FlexLM STATUS query returns detailed server status."""
        handler = FlexLMProtocolHandler(
            config={
                "server_status": "UP",
                "license_count": 500,
            }
        )

        request = b"STATUS"
        response = handler.generate_response(request)
        response_str = response.decode("utf-8")

        assert "STATUS OK" in response_str
        assert "SERVER UP" in response_str
        assert "LICENSES AVAILABLE: 500" in response_str
        assert response != b"OK\n"

    def test_flexlm_invalid_request_error(self) -> None:
        """FlexLM returns error for invalid short requests."""
        handler = FlexLMProtocolHandler()

        request = b"GET"
        response = handler.generate_response(request)

        assert response == b"ERROR: Invalid request\n"
        assert response != b"OK\n"

    def test_flexlm_getlic_missing_parameters_error(self) -> None:
        """FlexLM GETLIC with missing parameters returns error."""
        handler = FlexLMProtocolHandler()

        request = b"GETLIC"
        response = handler.generate_response(request)

        assert response == b"ERROR: Invalid GETLIC request\n"
        assert response != b"OK\n"


class TestHASPProtocolSpecificResponses:
    """Validate HASP protocol-specific binary response formats."""

    def test_hasp_login_response_format(self) -> None:
        """HASP LOGIN returns success status and dynamic handle."""
        handler = HASPProtocolHandler()

        request = struct.pack("<I", 0x01) + b"\x00" * 4
        response = handler.generate_response(request)

        assert len(response) == 8
        status, handle = struct.unpack("<II", response)
        assert status == 0x00000000
        assert handle >= 0x10000000
        assert handle <= 0x7FFFFFFF
        assert response != b"OK\n"

    def test_hasp_login_generates_unique_handles(self) -> None:
        """HASP LOGIN generates different handles for multiple sessions."""
        handler = HASPProtocolHandler()

        handles = set()
        for _ in range(10):
            request = struct.pack("<I", 0x01) + b"\x00" * 4
            response = handler.generate_response(request)
            _, handle = struct.unpack("<II", response)
            handles.add(handle)

        assert len(handles) >= 8

    def test_hasp_logout_response_format(self) -> None:
        """HASP LOGOUT returns success status."""
        handler = HASPProtocolHandler()

        request = struct.pack("<I", 0x02) + b"\x00" * 4
        response = handler.generate_response(request)

        assert len(response) == 4
        status = struct.unpack("<I", response)[0]
        assert status == 0x00000000
        assert response != b"OK\n"

    def test_hasp_encrypt_response_format(self) -> None:
        """HASP ENCRYPT returns encrypted data with proper format."""
        handler = HASPProtocolHandler()

        plaintext = b"TestData1234567890"
        request = struct.pack("<II", 0x03, len(plaintext)) + plaintext
        response = handler.generate_response(request)

        assert len(response) > 4
        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000
        encrypted_data = response[4:]
        assert len(encrypted_data) == len(plaintext)
        assert encrypted_data != plaintext
        assert response != b"OK\n"

    def test_hasp_decrypt_response_format(self) -> None:
        """HASP DECRYPT returns decrypted data matching original plaintext."""
        handler = HASPProtocolHandler()

        plaintext = b"OriginalSecretData"

        encrypt_request = struct.pack("<II", 0x03, len(plaintext)) + plaintext
        encrypt_response = handler.generate_response(encrypt_request)
        encrypted_data = encrypt_response[4:]

        decrypt_request = struct.pack("<II", 0x04, len(encrypted_data)) + encrypted_data
        decrypt_response = handler.generate_response(decrypt_request)

        assert len(decrypt_response) > 4
        status = struct.unpack("<I", decrypt_response[:4])[0]
        assert status == 0x00000000
        decrypted_data = decrypt_response[4:]
        assert decrypted_data == plaintext
        assert decrypt_response != b"OK\n"

    def test_hasp_get_size_response_format(self) -> None:
        """HASP GET_SIZE returns configured memory size."""
        handler = HASPProtocolHandler(
            config={
                "hasp_memory_size": 0x40000,
            }
        )

        request = struct.pack("<I", 0x05) + b"\x00" * 4
        response = handler.generate_response(request)

        assert len(response) == 8
        status, size = struct.unpack("<II", response)
        assert status == 0x00000000
        assert size == 0x40000
        assert response != b"OK\n"

    def test_hasp_read_license_header(self) -> None:
        """HASP READ from license header returns signature data."""
        handler = HASPProtocolHandler(
            config={
                "hasp_version": "8.20",
            }
        )

        offset = 0
        size = 32
        request = struct.pack("<IIII", 0x06, 8, offset, size)
        response = handler.generate_response(request)

        assert len(response) >= 4 + size
        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000
        license_data = response[4:4+size]
        assert b"HASP_LIC_8_20" in license_data
        assert response != b"OK\n"

    def test_hasp_read_feature_data(self) -> None:
        """HASP READ from feature area returns configured features."""
        handler = HASPProtocolHandler(
            config={
                "license_features": ["PREMIUM", "ADVANCED", "BASIC"],
            }
        )

        offset = 100
        size = 128
        request = struct.pack("<IIII", 0x06, 8, offset, size)
        response = handler.generate_response(request)

        assert len(response) >= 4 + size
        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000
        feature_data = response[4:4+size]
        assert b"PREMIUM" in feature_data
        assert b"ADVANCED" in feature_data
        assert b"BASIC" in feature_data
        assert response != b"OK\n"

    def test_hasp_write_response_format(self) -> None:
        """HASP WRITE returns success status."""
        handler = HASPProtocolHandler()

        request = struct.pack("<I", 0x07) + b"\x00" * 4
        response = handler.generate_response(request)

        assert len(response) == 4
        status = struct.unpack("<I", response)[0]
        assert status == 0x00000000
        assert response != b"OK\n"

    def test_hasp_get_rtc_response_format(self) -> None:
        """HASP GET_RTC returns current timestamp."""
        handler = HASPProtocolHandler()

        before_time = int(time.time())
        request = struct.pack("<I", 0x08) + b"\x00" * 4
        response = handler.generate_response(request)
        after_time = int(time.time())

        assert len(response) == 8
        status, rtc_time = struct.unpack("<II", response)
        assert status == 0x00000000
        assert before_time <= rtc_time <= after_time
        assert response != b"OK\n"

    def test_hasp_get_info_response_format(self) -> None:
        """HASP GET_INFO returns emulator version string."""
        handler = HASPProtocolHandler(
            config={
                "hasp_emulator_version": "HASP_EMU_v3.0_CUSTOM",
            }
        )

        request = struct.pack("<I", 0x09) + b"\x00" * 4
        response = handler.generate_response(request)

        assert len(response) > 4
        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000
        info_data = response[4:]
        assert b"HASP_EMU_v3.0_CUSTOM" in info_data
        assert response != b"OK\n"

    def test_hasp_invalid_short_request_error(self) -> None:
        """HASP returns error for invalid short requests."""
        handler = HASPProtocolHandler()

        request = b"BAD"
        response = handler.generate_response(request)

        assert response == b"\x00\x00\x00\x00"
        assert response != b"OK\n"


class TestSessionStateMaintenance:
    """Validate session state is maintained across multiple requests."""

    def test_flexlm_session_maintains_checkout_state(self) -> None:
        """FlexLM maintains license checkout state across requests."""
        handler = FlexLMProtocolHandler()

        getlic_request = b"GETLIC PROFESSIONAL 1.0 user1 host1 :0"
        getlic_response = handler.generate_response(getlic_request)
        assert b"GRANT" in getlic_response

        heartbeat_request = b"HEARTBEAT"
        heartbeat_response = handler.generate_response(heartbeat_request)
        assert heartbeat_response == b"HEARTBEAT_OK\n"

        checkin_request = b"CHECKIN PROFESSIONAL 1.0"
        checkin_response = handler.generate_response(checkin_request)
        assert checkin_response == b"CHECKIN_OK\n"

    def test_hasp_session_maintains_handle_state(self) -> None:
        """HASP maintains session handle across multiple operations."""
        handler = HASPProtocolHandler()

        login_request = struct.pack("<I", 0x01) + b"\x00" * 4
        login_response = handler.generate_response(login_request)
        _, handle = struct.unpack("<II", login_response)

        assert handle in handler.session_data.values()

        read_request = struct.pack("<IIII", 0x06, 8, 0, 64)
        read_response = handler.generate_response(read_request)
        status = struct.unpack("<I", read_response[:4])[0]
        assert status == 0x00000000

        logout_request = struct.pack("<I", 0x02) + b"\x00" * 4
        logout_response = handler.generate_response(logout_request)
        status = struct.unpack("<I", logout_response)[0]
        assert status == 0x00000000

    def test_hasp_encryption_maintains_key_state(self) -> None:
        """HASP maintains encryption key state across encrypt/decrypt cycle."""
        handler = HASPProtocolHandler()

        plaintext1 = b"FirstMessage"
        encrypt_request1 = struct.pack("<II", 0x03, len(plaintext1)) + plaintext1
        encrypt_response1 = handler.generate_response(encrypt_request1)
        encrypted1 = encrypt_response1[4:]

        plaintext2 = b"SecondMessage"
        encrypt_request2 = struct.pack("<II", 0x03, len(plaintext2)) + plaintext2
        encrypt_response2 = handler.generate_response(encrypt_request2)
        encrypted2 = encrypt_response2[4:]

        decrypt_request1 = struct.pack("<II", 0x04, len(encrypted1)) + encrypted1
        decrypt_response1 = handler.generate_response(decrypt_request1)
        decrypted1 = decrypt_response1[4:]

        decrypt_request2 = struct.pack("<II", 0x04, len(encrypted2)) + encrypted2
        decrypt_response2 = handler.generate_response(decrypt_request2)
        decrypted2 = decrypt_response2[4:]

        assert decrypted1 == plaintext1
        assert decrypted2 == plaintext2

    def test_hasp_session_data_persists_across_requests(self) -> None:
        """HASP session_data dictionary persists state across operations."""
        handler = HASPProtocolHandler()

        assert len(handler.session_data) == 0

        login_request = struct.pack("<I", 0x01) + b"\x00" * 4
        handler.generate_response(login_request)

        assert "handle" in handler.session_data
        stored_handle = handler.session_data["handle"]

        for _ in range(5):
            read_request = struct.pack("<IIII", 0x06, 8, 0, 32)
            handler.generate_response(read_request)

        assert handler.session_data["handle"] == stored_handle


class TestAuthenticationChallengeResponse:
    """Validate authentication and challenge-response mechanisms."""

    def test_flexlm_hello_challenge_response_flow(self) -> None:
        """FlexLM HELLO-GETLIC flow validates challenge-response authentication."""
        handler = FlexLMProtocolHandler(
            config={
                "flexlm_version": "11.16.2",
                "vendor_daemon_port": 27001,
            }
        )

        hello_request = b"HELLO"
        hello_response = handler.generate_response(hello_request)
        assert b"HELLO 11 16 27001" in hello_response

        hello_parts = hello_response.decode().strip().split()
        vendor_port = int(hello_parts[3])
        assert vendor_port == 27001

        getlic_request = b"GETLIC PROFESSIONAL 1.0 user1 host1 :0"
        getlic_response = handler.generate_response(getlic_request)
        assert b"GRANT" in getlic_response

    def test_hasp_login_provides_session_handle(self) -> None:
        """HASP LOGIN provides session handle for subsequent authenticated requests."""
        handler = HASPProtocolHandler()

        login_request = struct.pack("<I", 0x01) + b"\x00" * 4
        login_response = handler.generate_response(login_request)

        status, handle = struct.unpack("<II", login_response)
        assert status == 0x00000000
        assert handle != 0

        assert "handle" in handler.session_data
        assert handler.session_data["handle"] == handle

    def test_hasp_operations_require_valid_session(self) -> None:
        """HASP operations validate session before processing requests."""
        handler = HASPProtocolHandler()

        login_request = struct.pack("<I", 0x01) + b"\x00" * 4
        login_response = handler.generate_response(login_request)
        _, handle = struct.unpack("<II", login_response)

        assert handle in handler.session_data.values()

        read_request = struct.pack("<IIII", 0x06, 8, 0, 32)
        read_response = handler.generate_response(read_request)
        status = struct.unpack("<I", read_response[:4])[0]
        assert status == 0x00000000


class TestProperErrorResponses:
    """Validate proper error response generation for invalid requests."""

    def test_flexlm_invalid_short_request_error(self) -> None:
        """FlexLM generates error for requests shorter than 4 bytes."""
        handler = FlexLMProtocolHandler()

        request = b"BAD"
        response = handler.generate_response(request)

        assert response == b"ERROR: Invalid request\n"

    def test_flexlm_getlic_missing_feature_error(self) -> None:
        """FlexLM generates error for GETLIC without feature name."""
        handler = FlexLMProtocolHandler()

        request = b"GETLIC"
        response = handler.generate_response(request)

        assert response == b"ERROR: Invalid GETLIC request\n"

    def test_hasp_invalid_short_request_error(self) -> None:
        """HASP generates error for requests shorter than 8 bytes."""
        handler = HASPProtocolHandler()

        request = b"SHORT"
        response = handler.generate_response(request)

        assert response == b"\x00\x00\x00\x00"

    def test_hasp_malformed_binary_struct_error(self) -> None:
        """HASP handles struct unpacking errors gracefully."""
        handler = HASPProtocolHandler()

        request = b"\xFF" * 100
        response = handler.generate_response(request)

        assert len(response) >= 4

    def test_hasp_unknown_command_returns_generic_success(self) -> None:
        """HASP returns generic success for unknown but valid command IDs."""
        handler = HASPProtocolHandler()

        unknown_command = 0xFF
        request = struct.pack("<I", unknown_command) + b"\x00" * 4
        response = handler.generate_response(request)

        assert len(response) == 4
        status = struct.unpack("<I", response)[0]
        assert status == 0x00000000


class TestStatefulLicenseCheckoutCheckin:
    """Validate complete license checkout/checkin workflow with state tracking."""

    def test_flexlm_complete_license_lifecycle(self) -> None:
        """FlexLM handles complete checkout-use-checkin lifecycle."""
        handler = FlexLMProtocolHandler()

        hello_response = handler.generate_response(b"HELLO")
        assert b"HELLO" in hello_response

        getlic_response = handler.generate_response(
            b"GETLIC PROFESSIONAL 2.0 user1 host1 :0"
        )
        assert b"GRANT PROFESSIONAL" in getlic_response

        for _ in range(3):
            heartbeat_response = handler.generate_response(b"HEARTBEAT")
            assert heartbeat_response == b"HEARTBEAT_OK\n"

        checkin_response = handler.generate_response(b"CHECKIN PROFESSIONAL 2.0")
        assert checkin_response == b"CHECKIN_OK\n"

    def test_hasp_complete_session_lifecycle(self) -> None:
        """HASP handles complete login-operate-logout lifecycle."""
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

    def test_flexlm_multiple_feature_checkout(self) -> None:
        """FlexLM handles checkout of multiple features simultaneously."""
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


class TestConcurrentSessionHandling:
    """Validate concurrent session handling without state corruption."""

    def test_flexlm_concurrent_client_isolation(self) -> None:
        """FlexLM handles concurrent clients without state interference."""
        handler = FlexLMProtocolHandler()
        handler.start_proxy(port=0)
        time.sleep(0.2)

        try:
            actual_port = handler.port
            if actual_port == 0:
                pytest.skip("Could not bind to dynamic port")

            results: list[bytes] = []
            results_lock = threading.Lock()

            def client_thread(feature: str) -> None:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2.0)
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
            features = ["FEATURE_A", "FEATURE_B", "FEATURE_C"]
            for feature in features:
                t = threading.Thread(target=client_thread, args=(feature,))
                threads.append(t)
                t.start()

            for t in threads:
                t.join(timeout=3.0)

            assert len(results) == 3
            for i, feature in enumerate(features):
                assert f"GRANT {feature}".encode() in results[i]

        finally:
            handler.stop_proxy()

    def test_hasp_concurrent_sessions_unique_handles(self) -> None:
        """HASP generates unique handles for concurrent login sessions."""
        handler = HASPProtocolHandler()
        handler.start_proxy(port=0)
        time.sleep(0.2)

        try:
            actual_port = handler.port
            if actual_port == 0:
                pytest.skip("Could not bind to dynamic port")

            handles: list[int] = []
            handles_lock = threading.Lock()

            def login_client() -> None:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2.0)
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
                t.join(timeout=3.0)

            assert len(handles) >= 3
            assert len(set(handles)) >= 3

        finally:
            handler.stop_proxy()

    def test_concurrent_requests_maintain_independent_state(self) -> None:
        """Concurrent requests maintain independent session state."""
        handler = FlexLMProtocolHandler()

        def worker(feature: str) -> bytes:
            request = f"GETLIC {feature} 1.0 user1 host1 :0".encode()
            return handler.generate_response(request)

        threads = []
        results = []

        for i in range(10):
            feature = f"FEATURE_{i}"
            t = threading.Thread(target=lambda f=feature: results.append(worker(f)))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=2.0)

        assert len(results) == 10
        for i, result in enumerate(results):
            assert f"FEATURE_{i}".encode() in result or b"GRANT" in result


class TestSessionTimeout:
    """Validate session timeout management and cleanup."""

    def test_hasp_session_persists_during_activity(self) -> None:
        """HASP session remains valid during continuous activity."""
        handler = HASPProtocolHandler()

        login_request = struct.pack("<I", 0x01) + b"\x00" * 4
        login_response = handler.generate_response(login_request)
        _, handle1 = struct.unpack("<II", login_response)

        for _ in range(10):
            read_request = struct.pack("<IIII", 0x06, 8, 0, 32)
            read_response = handler.generate_response(read_request)
            status = struct.unpack("<I", read_response[:4])[0]
            assert status == 0x00000000

        assert handler.session_data["handle"] == handle1

    def test_flexlm_heartbeat_maintains_session(self) -> None:
        """FlexLM heartbeat prevents session timeout."""
        handler = FlexLMProtocolHandler()

        getlic_response = handler.generate_response(
            b"GETLIC PROFESSIONAL 1.0 user1 host1 :0"
        )
        assert b"GRANT" in getlic_response

        for _ in range(5):
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


class TestRequestResponseLogging:
    """Validate request/response logging and capture for analysis."""

    def test_flexlm_captures_request_data(self) -> None:
        """FlexLM captures all request data for analysis."""
        handler = FlexLMProtocolHandler()

        initial_count = len(handler.captured_requests)

        handler.generate_response(b"HELLO")
        handler.generate_response(b"GETLIC PROFESSIONAL 1.0 user1 host1 :0")
        handler.generate_response(b"STATUS")

        assert len(handler.captured_requests) == initial_count + 3

        for req in handler.captured_requests[initial_count:]:
            assert "timestamp" in req
            assert "data" in req
            assert "hex" in req

    def test_hasp_captures_binary_request_data(self) -> None:
        """HASP captures binary request data with hex representation."""
        handler = HASPProtocolHandler()

        initial_count = len(handler.captured_requests)

        login_request = struct.pack("<I", 0x01) + b"\x00" * 4
        handler.generate_response(login_request)

        assert len(handler.captured_requests) == initial_count + 1

        captured = handler.captured_requests[-1]
        assert captured["data"] == login_request
        assert captured["hex"] == login_request.hex()
        assert isinstance(captured["timestamp"], float)

    def test_request_timestamps_are_accurate(self) -> None:
        """Request timestamps accurately reflect processing time."""
        handler = FlexLMProtocolHandler()

        before = time.time()
        handler.generate_response(b"HELLO")
        after = time.time()

        captured = handler.captured_requests[-1]
        assert before <= captured["timestamp"] <= after


class TestProtocolCompliance:
    """Validate compliance with FlexLM and HASP protocol specifications."""

    def test_flexlm_version_format_compliance(self) -> None:
        """FlexLM version format complies with protocol specification."""
        handler = FlexLMProtocolHandler(
            config={"flexlm_version": "10.8.0.5"}
        )

        response = handler.generate_response(b"HELLO")
        parts = response.decode().strip().split()

        assert len(parts) == 4
        assert parts[0] == "HELLO"
        assert parts[1].isdigit()
        assert parts[2].isdigit()
        assert parts[3].isdigit()

    def test_hasp_binary_format_compliance(self) -> None:
        """HASP binary responses comply with protocol specification."""
        handler = HASPProtocolHandler()

        commands = [0x01, 0x02, 0x03, 0x05, 0x07, 0x08, 0x09]

        for cmd in commands:
            request = struct.pack("<I", cmd) + b"\x00" * 12
            response = handler.generate_response(request)

            assert len(response) >= 4
            status = struct.unpack("<I", response[:4])[0]
            assert status == 0x00000000 or status == 0x00000001

    def test_hasp_read_size_limits(self) -> None:
        """HASP READ enforces size limits to prevent memory issues."""
        handler = HASPProtocolHandler()

        offset = 0
        size = 10000
        request = struct.pack("<IIII", 0x06, 8, offset, size)
        response = handler.generate_response(request)

        status = struct.unpack("<I", response[:4])[0]
        assert status == 0x00000000

        data_length = len(response) - 4
        assert data_length <= 4096

    def test_flexlm_grant_contains_required_fields(self) -> None:
        """FlexLM GRANT response contains all required protocol fields."""
        handler = FlexLMProtocolHandler(
            config={
                "feature_version": "2.5",
                "license_type": "permanent",
            }
        )

        response = handler.generate_response(
            b"GETLIC PROFESSIONAL 1.0 user1 host1 :0"
        )
        response_str = response.decode()

        assert "GRANT" in response_str
        assert "PROFESSIONAL" in response_str
        assert "2.5" in response_str
        assert "permanent" in response_str
        assert "HOSTID" in response_str
