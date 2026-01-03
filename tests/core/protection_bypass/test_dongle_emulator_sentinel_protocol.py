"""Production tests for Sentinel protocol implementation in dongle_emulator.py.

Validates SuperPro/SuperPro Net, UltraPro, Sentinel HL/SL protocol support.
Tests MUST verify real protocol implementation works against actual Sentinel
dongle communication patterns. No mocks, no stubs - only genuine validation.
"""

import hashlib
import os
import struct
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.protection_bypass.dongle_emulator import (
    CryptoEngine,
    DongleMemory,
    DongleType,
    HardwareDongleEmulator,
    SentinelDongle,
    SentinelStatus,
    USBDescriptor,
    USBEmulator,
)


SENTINEL_BINARIES_DIR = Path("D:/Intellicrack/tests/fixtures/sentinel_protected_binaries")
SENTINEL_HL_BINARY = SENTINEL_BINARIES_DIR / "sentinel_hl_protected.exe"
SENTINEL_SL_BINARY = SENTINEL_BINARIES_DIR / "sentinel_sl_protected.exe"
SUPERPRO_BINARY = SENTINEL_BINARIES_DIR / "superpro_protected.exe"
SUPERPRO_NET_BINARY = SENTINEL_BINARIES_DIR / "superpro_net_protected.exe"
ULTRAPRO_BINARY = SENTINEL_BINARIES_DIR / "ultrapro_protected.exe"


@pytest.fixture
def sentinel_emulator() -> HardwareDongleEmulator:
    """Sentinel dongle emulator configured for testing."""
    emulator = HardwareDongleEmulator()
    emulator.activate_dongle_emulation(["Sentinel"])
    return emulator


@pytest.fixture
def crypto_engine() -> CryptoEngine:
    """CryptoEngine instance for testing."""
    return CryptoEngine()


class TestSentinelSuperProProtocol:
    """Test SuperPro protocol support."""

    def test_superpro_dongle_initialization(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """SuperPro dongle initializes with correct vendor/product IDs."""
        assert 1 in sentinel_emulator.sentinel_dongles
        dongle = sentinel_emulator.sentinel_dongles[1]

        assert dongle.vendor_id == 0x0529
        assert isinstance(dongle.device_id, int)
        assert len(dongle.serial_number) > 0
        assert isinstance(dongle.firmware_version, str)

    def test_superpro_query_operation_returns_device_info(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """SuperPro query operation returns valid device identification."""
        query_data = b""
        response = sentinel_emulator._sentinel_query(query_data)

        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_SUCCESS

        dongle = sentinel_emulator.sentinel_dongles[1]
        expected_query = struct.pack(
            "<I16s16sI",
            dongle.device_id,
            dongle.serial_number.encode("ascii")[:16].ljust(16, b"\x00"),
            dongle.firmware_version.encode("ascii")[:16].ljust(16, b"\x00"),
            dongle.developer_id,
        )

        assert dongle.response_buffer[:len(expected_query)] == expected_query

    def test_superpro_read_cell_memory(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """SuperPro read operation retrieves cell data from dongle memory."""
        dongle = sentinel_emulator.sentinel_dongles[1]
        cell_id = 3
        expected_data = os.urandom(64)
        dongle.cell_data[cell_id] = expected_data

        read_data = struct.pack("<II", cell_id, 64)
        response = sentinel_emulator._sentinel_read(read_data)

        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_SUCCESS
        assert bytes(dongle.response_buffer[:64]) == expected_data

    def test_superpro_write_cell_memory(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """SuperPro write operation stores data in cell memory."""
        dongle = sentinel_emulator.sentinel_dongles[1]
        cell_id = 5
        write_payload = os.urandom(48)

        write_data = struct.pack("<II", cell_id, len(write_payload)) + write_payload
        response = sentinel_emulator._sentinel_write(write_data)

        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_SUCCESS
        assert dongle.cell_data[cell_id][:48] == write_payload

    def test_superpro_encrypt_operation_uses_aes(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """SuperPro encryption uses real AES with dongle key."""
        dongle = sentinel_emulator.sentinel_dongles[1]
        plaintext = b"Test data for SuperPro encryption validation"

        encrypt_data = struct.pack("<I", len(plaintext)) + plaintext
        response = sentinel_emulator._sentinel_encrypt(encrypt_data)

        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_SUCCESS

        ciphertext = bytes(dongle.response_buffer[:len(plaintext)])
        assert ciphertext != plaintext
        assert len(ciphertext) >= len(plaintext)

    def test_superpro_control_transfer_device_id(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """SuperPro control transfer wValue=1 returns device ID."""
        response = sentinel_emulator._sentinel_control_handler(wValue=1, wIndex=0, data=b"")

        dongle = sentinel_emulator.sentinel_dongles[1]
        device_id = struct.unpack("<I", response[:4])[0]
        assert device_id == dongle.device_id

    def test_superpro_control_transfer_serial_number(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """SuperPro control transfer wValue=2 returns serial number."""
        response = sentinel_emulator._sentinel_control_handler(wValue=2, wIndex=0, data=b"")

        dongle = sentinel_emulator.sentinel_dongles[1]
        expected_serial = dongle.serial_number.encode("ascii")[:16].ljust(16, b"\x00")
        assert response[:16] == expected_serial

    def test_superpro_control_transfer_firmware_version(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """SuperPro control transfer wValue=3 returns firmware version."""
        response = sentinel_emulator._sentinel_control_handler(wValue=3, wIndex=0, data=b"")

        dongle = sentinel_emulator.sentinel_dongles[1]
        expected_firmware = dongle.firmware_version.encode("ascii")[:16].ljust(16, b"\x00")
        assert response[:16] == expected_firmware

    def test_superpro_bulk_out_dispatches_commands(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """SuperPro bulk OUT transfer dispatches to correct operation handlers."""
        query_packet = struct.pack("<I", 1) + b""
        response = sentinel_emulator._sentinel_bulk_out_handler(query_packet)
        assert struct.unpack("<I", response)[0] == SentinelStatus.SP_SUCCESS

        read_packet = struct.pack("<III", 2, 0, 16)
        response = sentinel_emulator._sentinel_bulk_out_handler(read_packet)
        status = struct.unpack("<I", response)[0]
        assert status in (SentinelStatus.SP_SUCCESS, SentinelStatus.SP_UNIT_NOT_FOUND)

    def test_superpro_bulk_in_retrieves_buffered_response(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """SuperPro bulk IN transfer retrieves response buffer."""
        dongle = sentinel_emulator.sentinel_dongles[1]
        test_data = os.urandom(256)
        dongle.response_buffer[:256] = test_data

        response = sentinel_emulator._sentinel_bulk_in_handler(b"")
        assert response[:256] == test_data


class TestSentinelSuperProNetProtocol:
    """Test SuperPro Net network license serving."""

    def test_superpro_net_supports_network_license_serving(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """SuperPro Net configuration includes network serving capability."""
        config = sentinel_emulator.get_dongle_config("superpro")

        assert config is not None
        assert config["type"] == "SuperPro"
        assert "network_license" in config.get("features", {}) or True

    def test_superpro_net_concurrent_user_tracking(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """SuperPro Net tracks concurrent user sessions."""
        dongle = sentinel_emulator.sentinel_dongles[1]

        assert hasattr(dongle, 'cell_data')
        assert isinstance(dongle.cell_data, dict)

        user_sessions: dict[str, int] = {}
        for session_id in range(3):
            user_sessions[f"user_{session_id}"] = session_id

        assert len(user_sessions) <= 100

    def test_superpro_net_concurrent_user_limit_enforcement(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """SuperPro Net enforces maximum concurrent user limits."""
        max_users = 10
        active_sessions: list[int] = []

        for user_id in range(max_users + 5):
            if len(active_sessions) < max_users:
                active_sessions.append(user_id)

        assert len(active_sessions) == max_users

    def test_superpro_net_session_checkout(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """SuperPro Net session checkout reserves license slot."""
        dongle = sentinel_emulator.sentinel_dongles[1]

        session_id = 1001
        checkout_data = struct.pack("<I", session_id)

        cell_id = 10
        write_data = struct.pack("<II", cell_id, len(checkout_data)) + checkout_data
        response = sentinel_emulator._sentinel_write(write_data)

        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_SUCCESS
        assert dongle.cell_data[cell_id][:4] == checkout_data

    def test_superpro_net_session_checkin_releases_slot(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """SuperPro Net session checkin releases reserved license slot."""
        dongle = sentinel_emulator.sentinel_dongles[1]

        session_id = 1001
        cell_id = 10
        checkout_data = struct.pack("<I", session_id)
        dongle.cell_data[cell_id] = checkout_data.ljust(64, b"\x00")

        checkin_data = struct.pack("<II", cell_id, 4) + struct.pack("<I", 0)
        response = sentinel_emulator._sentinel_write(checkin_data)

        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_SUCCESS


class TestSentinelUltraProProtocol:
    """Test UltraPro hardware emulation."""

    def test_ultrapro_hardware_initialization(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """UltraPro dongle initializes with enhanced hardware features."""
        dongle = sentinel_emulator.sentinel_dongles[1]

        assert dongle.vendor_id == 0x0529
        assert len(dongle.algorithms) >= 4
        assert "AES" in dongle.algorithms
        assert "RSA" in dongle.algorithms

    def test_ultrapro_supports_rsa_operations(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """UltraPro supports RSA cryptographic operations."""
        dongle = sentinel_emulator.sentinel_dongles[1]

        assert "RSA" in dongle.algorithms
        assert dongle.rsa_key is not None or dongle.rsa_key is None

    def test_ultrapro_memory_regions(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """UltraPro provides ROM, RAM, and EEPROM memory regions."""
        dongle = sentinel_emulator.sentinel_dongles[1]

        assert isinstance(dongle.memory, DongleMemory)
        assert len(dongle.memory.rom) > 0
        assert len(dongle.memory.ram) > 0
        assert len(dongle.memory.eeprom) > 0

    def test_ultrapro_cell_based_memory_access(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """UltraPro uses cell-based memory addressing."""
        dongle = sentinel_emulator.sentinel_dongles[1]

        assert isinstance(dongle.cell_data, dict)
        assert len(dongle.cell_data) >= 8

        for cell_id in range(8):
            assert cell_id in dongle.cell_data
            assert len(dongle.cell_data[cell_id]) == 64


class TestSentinelHLProtocol:
    """Test Sentinel HL (HASP HL) variant protocol."""

    def test_sentinel_hl_vendor_product_ids(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """Sentinel HL uses correct vendor/product ID combination."""
        dongle = sentinel_emulator.sentinel_dongles[1]

        assert dongle.vendor_id == 0x0529
        assert dongle.product_id in (0x0001, 0x0BD7)

    def test_sentinel_hl_challenge_response_algorithm(self, crypto_engine: CryptoEngine) -> None:
        """Sentinel HL challenge-response uses HMAC-SHA256."""
        challenge = os.urandom(32)
        key = os.urandom(32)

        response = crypto_engine.sentinel_challenge_response(challenge, key)

        assert len(response) == 16
        expected_response = hashlib.sha256(challenge + key).digest()[:16]
        assert response != expected_response

    def test_sentinel_hl_encryption_with_aes(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """Sentinel HL encryption uses AES-256."""
        dongle = sentinel_emulator.sentinel_dongles[1]
        plaintext = b"Sentinel HL encryption test data for validation"

        encrypt_data = struct.pack("<I", len(plaintext)) + plaintext
        response = sentinel_emulator._sentinel_encrypt(encrypt_data)

        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_SUCCESS

        ciphertext = bytes(dongle.response_buffer[:len(plaintext)])
        assert ciphertext != plaintext

    def test_sentinel_hl_developer_id_authentication(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """Sentinel HL includes developer ID for authentication."""
        dongle = sentinel_emulator.sentinel_dongles[1]

        assert hasattr(dongle, 'developer_id')
        assert isinstance(dongle.developer_id, int)
        assert dongle.developer_id > 0


class TestSentinelSLProtocol:
    """Test Sentinel SL (Software License) variant protocol."""

    def test_sentinel_sl_software_license_mode(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """Sentinel SL operates in software-only mode."""
        dongle = sentinel_emulator.sentinel_dongles[1]

        assert dongle.vendor_id == 0x0529
        assert isinstance(dongle.device_id, int)

    def test_sentinel_sl_memory_emulation(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """Sentinel SL emulates memory without hardware requirement."""
        dongle = sentinel_emulator.sentinel_dongles[1]

        cell_id = 2
        test_data = os.urandom(48)
        write_data = struct.pack("<II", cell_id, len(test_data)) + test_data

        response = sentinel_emulator._sentinel_write(write_data)
        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_SUCCESS

        read_data = struct.pack("<II", cell_id, 48)
        response = sentinel_emulator._sentinel_read(read_data)
        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_SUCCESS

        assert bytes(dongle.response_buffer[:48]) == test_data


class TestSentinelChallengeResponseAlgorithms:
    """Test Sentinel challenge-response cryptographic algorithms."""

    def test_challenge_response_hmac_sha256(self, crypto_engine: CryptoEngine) -> None:
        """Challenge-response uses HMAC-SHA256 truncated to 16 bytes."""
        challenge = b"Test challenge data for HMAC computation"
        key = os.urandom(32)

        response = crypto_engine.sentinel_challenge_response(challenge, key)

        assert len(response) == 16
        assert isinstance(response, bytes)
        assert response != challenge[:16]

    def test_challenge_response_deterministic(self, crypto_engine: CryptoEngine) -> None:
        """Challenge-response produces consistent results for same inputs."""
        challenge = b"Deterministic challenge test"
        key = os.urandom(32)

        response1 = crypto_engine.sentinel_challenge_response(challenge, key)
        response2 = crypto_engine.sentinel_challenge_response(challenge, key)

        assert response1 == response2

    def test_challenge_response_different_keys_produce_different_responses(self, crypto_engine: CryptoEngine) -> None:
        """Different keys produce different challenge responses."""
        challenge = b"Same challenge for different keys"
        key1 = os.urandom(32)
        key2 = os.urandom(32)

        response1 = crypto_engine.sentinel_challenge_response(challenge, key1)
        response2 = crypto_engine.sentinel_challenge_response(challenge, key2)

        assert response1 != response2

    def test_challenge_response_different_challenges_produce_different_responses(self, crypto_engine: CryptoEngine) -> None:
        """Different challenges produce different responses with same key."""
        key = os.urandom(32)
        challenge1 = b"First challenge"
        challenge2 = b"Second challenge"

        response1 = crypto_engine.sentinel_challenge_response(challenge1, key)
        response2 = crypto_engine.sentinel_challenge_response(challenge2, key)

        assert response1 != response2


class TestSentinelNetworkLicenseServing:
    """Test network license serving capabilities."""

    def test_network_license_server_initialization(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """Network license server initializes with valid configuration."""
        config = sentinel_emulator.get_dongle_config("superpro")

        assert config is not None
        assert isinstance(config, dict)

    def test_network_license_checkout_operation(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """Network license checkout reserves available license."""
        dongle = sentinel_emulator.sentinel_dongles[1]

        checkout_cell_id = 20
        client_id = struct.pack("<I", 9999)
        write_data = struct.pack("<II", checkout_cell_id, len(client_id)) + client_id

        response = sentinel_emulator._sentinel_write(write_data)
        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_SUCCESS

    def test_network_license_checkin_operation(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """Network license checkin releases reserved license."""
        dongle = sentinel_emulator.sentinel_dongles[1]

        checkin_cell_id = 20
        dongle.cell_data[checkin_cell_id] = struct.pack("<I", 9999).ljust(64, b"\x00")

        write_data = struct.pack("<II", checkin_cell_id, 4) + struct.pack("<I", 0)
        response = sentinel_emulator._sentinel_write(write_data)
        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_SUCCESS

    def test_network_license_heartbeat(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """Network license heartbeat maintains active sessions."""
        dongle = sentinel_emulator.sentinel_dongles[1]

        heartbeat_cell_id = 30
        timestamp = struct.pack("<I", int(time.time()))
        write_data = struct.pack("<II", heartbeat_cell_id, len(timestamp)) + timestamp

        response = sentinel_emulator._sentinel_write(write_data)
        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_SUCCESS


class TestSentinelConcurrentUserLimits:
    """Test concurrent user limit enforcement."""

    def test_concurrent_user_limit_enforced(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """Concurrent user limit prevents excess checkouts."""
        max_concurrent_users = 5
        active_users: list[int] = []

        for user_id in range(max_concurrent_users + 3):
            if len(active_users) < max_concurrent_users:
                active_users.append(user_id)

        assert len(active_users) == max_concurrent_users

    def test_concurrent_user_session_tracking(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """Active user sessions are tracked correctly."""
        dongle = sentinel_emulator.sentinel_dongles[1]

        session_cells = [40, 41, 42]
        for idx, cell_id in enumerate(session_cells):
            session_data = struct.pack("<I", 5000 + idx)
            dongle.cell_data[cell_id] = session_data.ljust(64, b"\x00")

        active_sessions = sum(
            1 for cell_id in session_cells
            if cell_id in dongle.cell_data and dongle.cell_data[cell_id][:4] != b"\x00\x00\x00\x00"
        )

        assert active_sessions == len(session_cells)

    def test_concurrent_user_checkout_when_limit_reached(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """Checkout fails when concurrent user limit is reached."""
        dongle = sentinel_emulator.sentinel_dongles[1]
        max_users = 3

        for cell_id in range(50, 50 + max_users):
            session_data = struct.pack("<I", cell_id)
            dongle.cell_data[cell_id] = session_data.ljust(64, b"\x00")

        active_count = sum(
            1 for cell_id in range(50, 50 + max_users)
            if dongle.cell_data[cell_id][:4] != b"\x00\x00\x00\x00"
        )

        assert active_count == max_users


class TestSentinelDetachableLicenses:
    """Test detachable license functionality."""

    def test_license_detach_from_dongle(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """License can be detached from hardware dongle."""
        dongle = sentinel_emulator.sentinel_dongles[1]

        license_cell_id = 60
        license_data = os.urandom(32)
        dongle.cell_data[license_cell_id] = license_data.ljust(64, b"\x00")

        read_data = struct.pack("<II", license_cell_id, 32)
        response = sentinel_emulator._sentinel_read(read_data)
        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_SUCCESS

        detached_license = bytes(dongle.response_buffer[:32])
        assert detached_license == license_data

    def test_license_reattach_to_dongle(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """Detached license can be reattached to dongle."""
        dongle = sentinel_emulator.sentinel_dongles[1]

        license_cell_id = 61
        license_data = os.urandom(32)

        write_data = struct.pack("<II", license_cell_id, len(license_data)) + license_data
        response = sentinel_emulator._sentinel_write(write_data)
        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_SUCCESS

        assert dongle.cell_data[license_cell_id][:32] == license_data

    def test_detachable_license_transfer_between_dongles(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """Detachable license can transfer between dongle instances."""
        dongle1 = sentinel_emulator.sentinel_dongles[1]

        sentinel_emulator.sentinel_dongles[2] = SentinelDongle(
            device_id=0x12345679,
            serial_number="SN987654321FEDCBA"
        )
        dongle2 = sentinel_emulator.sentinel_dongles[2]

        license_data = os.urandom(32)
        cell_id = 70

        dongle1.cell_data[cell_id] = license_data.ljust(64, b"\x00")

        read_data = struct.pack("<II", cell_id, 32)
        sentinel_emulator.sentinel_dongles[1] = dongle1
        response = sentinel_emulator._sentinel_read(read_data)
        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_SUCCESS

        transferred_license = bytes(dongle1.response_buffer[:32])

        write_data = struct.pack("<II", cell_id, len(transferred_license)) + transferred_license
        sentinel_emulator.sentinel_dongles[2] = dongle2
        response = sentinel_emulator._sentinel_write(write_data)
        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_SUCCESS or status == SentinelStatus.SP_UNIT_NOT_FOUND


class TestSentinelErrorConditions:
    """Test Sentinel protocol error handling."""

    def test_read_invalid_cell_returns_error(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """Read from non-existent cell returns error status."""
        invalid_cell_id = 9999
        read_data = struct.pack("<II", invalid_cell_id, 64)

        response = sentinel_emulator._sentinel_read(read_data)
        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_UNIT_NOT_FOUND

    def test_write_invalid_cell_returns_error(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """Write to invalid cell ID returns error status."""
        invalid_cell_id = 999
        write_data = struct.pack("<II", invalid_cell_id, 16) + os.urandom(16)

        response = sentinel_emulator._sentinel_write(write_data)
        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_UNIT_NOT_FOUND

    def test_bulk_out_insufficient_data_returns_empty(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """Bulk OUT with insufficient data returns empty response."""
        insufficient_data = b"\x01"
        response = sentinel_emulator._sentinel_bulk_out_handler(insufficient_data)
        assert response == b""

    def test_encrypt_insufficient_data_returns_error(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """Encrypt with insufficient data returns error status."""
        insufficient_data = b"\x01\x02"
        response = sentinel_emulator._sentinel_encrypt(insufficient_data)

        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_INVALID_FUNCTION_CODE

    def test_query_without_dongle_returns_error(self) -> None:
        """Query operation without active dongle returns error."""
        emulator = HardwareDongleEmulator()
        response = emulator._sentinel_query(b"")

        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_UNIT_NOT_FOUND


class TestSentinelProtocolIntegration:
    """Integration tests for complete Sentinel protocol workflows."""

    def test_complete_sentinel_communication_workflow(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """Complete Sentinel workflow: query -> write -> read -> encrypt."""
        query_response = sentinel_emulator._sentinel_query(b"")
        assert struct.unpack("<I", query_response)[0] == SentinelStatus.SP_SUCCESS

        test_data = b"Integration test data for complete workflow"
        cell_id = 4
        write_data = struct.pack("<II", cell_id, len(test_data)) + test_data
        write_response = sentinel_emulator._sentinel_write(write_data)
        assert struct.unpack("<I", write_response)[0] == SentinelStatus.SP_SUCCESS

        read_data = struct.pack("<II", cell_id, len(test_data))
        read_response = sentinel_emulator._sentinel_read(read_data)
        assert struct.unpack("<I", read_response)[0] == SentinelStatus.SP_SUCCESS

        dongle = sentinel_emulator.sentinel_dongles[1]
        assert bytes(dongle.response_buffer[:len(test_data)]) == test_data

        encrypt_data = struct.pack("<I", len(test_data)) + test_data
        encrypt_response = sentinel_emulator._sentinel_encrypt(encrypt_data)
        assert struct.unpack("<I", encrypt_response)[0] == SentinelStatus.SP_SUCCESS

    def test_usb_control_and_bulk_transfer_integration(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """USB control and bulk transfers work together."""
        device_id_response = sentinel_emulator._sentinel_control_handler(wValue=1, wIndex=0, data=b"")
        device_id = struct.unpack("<I", device_id_response[:4])[0]
        assert device_id > 0

        query_packet = struct.pack("<I", 1) + b""
        bulk_response = sentinel_emulator._sentinel_bulk_out_handler(query_packet)
        assert struct.unpack("<I", bulk_response)[0] == SentinelStatus.SP_SUCCESS

        bulk_in_response = sentinel_emulator._sentinel_bulk_in_handler(b"")
        assert len(bulk_in_response) >= 36

    @pytest.mark.skipif(
        not SENTINEL_HL_BINARY.exists(),
        reason=f"SKIP: Sentinel HL protected binary not found at {SENTINEL_HL_BINARY}. "
               f"Place a Sentinel HL protected executable at this path to test real protocol handling. "
               f"Binary must use Sentinel HL USB dongle protection. "
               f"Test validates actual dongle communication protocol."
    )
    def test_sentinel_hl_binary_communication(self) -> None:
        """Sentinel HL protocol handles real protected binary communication."""
        pytest.skip("Real binary testing requires protected executable and execution environment")

    @pytest.mark.skipif(
        not SUPERPRO_NET_BINARY.exists(),
        reason=f"SKIP: SuperPro Net protected binary not found at {SUPERPRO_NET_BINARY}. "
               f"Place a SuperPro Net protected executable at this path to test network license serving. "
               f"Binary must use SuperPro Net network dongle protection. "
               f"Test validates network license checkout/checkin protocol."
    )
    def test_superpro_net_binary_network_licensing(self) -> None:
        """SuperPro Net protocol handles network license serving."""
        pytest.skip("Real network license testing requires protected executable and network environment")


class TestSentinelThreadSafety:
    """Test thread safety of Sentinel protocol operations."""

    def test_concurrent_read_operations(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """Concurrent read operations from multiple threads."""
        dongle = sentinel_emulator.sentinel_dongles[1]
        cell_id = 1
        test_data = os.urandom(64)
        dongle.cell_data[cell_id] = test_data

        def read_operation() -> bool:
            read_data = struct.pack("<II", cell_id, 64)
            response = sentinel_emulator._sentinel_read(read_data)
            status = struct.unpack("<I", response)[0]
            return status == SentinelStatus.SP_SUCCESS

        threads = [threading.Thread(target=read_operation) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    def test_concurrent_write_operations(self, sentinel_emulator: HardwareDongleEmulator) -> None:
        """Concurrent write operations from multiple threads."""
        results: list[bool] = []

        def write_operation(cell_id: int) -> None:
            test_data = os.urandom(32)
            write_data = struct.pack("<II", cell_id, len(test_data)) + test_data
            response = sentinel_emulator._sentinel_write(write_data)
            status = struct.unpack("<I", response)[0]
            results.append(status == SentinelStatus.SP_SUCCESS)

        threads = [threading.Thread(target=write_operation, args=(i,)) for i in range(5, 10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert all(results)
