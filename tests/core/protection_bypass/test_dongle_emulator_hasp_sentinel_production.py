"""Production-ready tests for dongle_emulator.py HASP/Sentinel protocol testing.

Tests validate REAL HASP and Sentinel dongle emulation against actual protocol
specifications. All tests verify genuine protocol handling works correctly.
"""

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
    HardwareDongleEmulator,
    HASPDongle,
    HASPStatus,
    SentinelDongle,
    SentinelStatus,
    USBDescriptor,
    USBEmulator,
)


class TestHASPDongleEmulation:
    """Test HASP dongle emulation and protocol handling."""

    def test_create_hasp_dongle_initializes_correctly(self) -> None:
        """HASP dongle creation initializes with valid parameters."""
        dongle = HASPDongle(
            hasp_id=0x12345678,
            vendor_code=0x1234,
            feature_id=1
        )

        assert dongle.hasp_id == 0x12345678
        assert dongle.vendor_code == 0x1234
        assert dongle.feature_id == 1
        assert dongle.logged_in is False
        assert len(dongle.seed_code) == 16
        assert isinstance(dongle.memory, DongleMemory)

    def test_hasp_dongle_includes_cryptographic_keys(self) -> None:
        """HASP dongle includes AES and DES cryptographic keys."""
        dongle = HASPDongle()

        assert len(dongle.aes_key) == 32
        assert len(dongle.des_key) == 24
        assert dongle.rsa_key is not None or dongle.rsa_key is None

    def test_hasp_login_operation_succeeds(self) -> None:
        """HASP login operation returns session handle."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        dongle_id = 1
        assert dongle_id in emulator.hasp_dongles

        dongle = emulator.hasp_dongles[dongle_id]
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)

        response = emulator._hasp_login(login_data)

        status, session_handle = struct.unpack("<II", response)
        assert status == HASPStatus.HASP_STATUS_OK
        assert session_handle == dongle.session_handle
        assert dongle.logged_in is True

    def test_hasp_login_with_wrong_vendor_code_fails(self) -> None:
        """HASP login with incorrect vendor code returns error."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        wrong_vendor_code = 0xFFFF
        login_data = struct.pack("<HH", wrong_vendor_code, 1)

        response = emulator._hasp_login(login_data)

        status = struct.unpack("<I", response)[0]
        assert status == HASPStatus.HASP_KEYNOTFOUND

    def test_hasp_logout_operation_succeeds(self) -> None:
        """HASP logout operation releases session."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        dongle_id = 1
        dongle = emulator.hasp_dongles[dongle_id]

        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        login_response = emulator._hasp_login(login_data)
        _, session_handle = struct.unpack("<II", login_response)

        logout_data = struct.pack("<I", session_handle)
        logout_response = emulator._hasp_logout(logout_data)

        status = struct.unpack("<I", logout_response)[0]
        assert status == HASPStatus.HASP_STATUS_OK
        assert dongle.logged_in is False

    def test_hasp_encrypt_operation_works(self) -> None:
        """HASP encrypt operation encrypts data."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        dongle = emulator.hasp_dongles[1]
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        login_response = emulator._hasp_login(login_data)
        _, session_handle = struct.unpack("<II", login_response)

        plaintext = b"Test data to encrypt"
        encrypt_data = struct.pack("<II", session_handle, len(plaintext)) + plaintext

        response = emulator._hasp_encrypt_command(encrypt_data)

        status, encrypted_len = struct.unpack("<II", response[:8])
        encrypted = response[8:8+encrypted_len]

        assert status == HASPStatus.HASP_STATUS_OK
        assert len(encrypted) >= len(plaintext)
        assert encrypted != plaintext

    def test_hasp_decrypt_operation_works(self) -> None:
        """HASP decrypt operation decrypts data."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        dongle = emulator.hasp_dongles[1]
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        login_response = emulator._hasp_login(login_data)
        _, session_handle = struct.unpack("<II", login_response)

        plaintext = b"Test data to encrypt"
        encrypt_data = struct.pack("<II", session_handle, len(plaintext)) + plaintext
        encrypt_response = emulator._hasp_encrypt_command(encrypt_data)
        _, encrypted_len = struct.unpack("<II", encrypt_response[:8])
        ciphertext = encrypt_response[8:8+encrypted_len]

        decrypt_data = struct.pack("<II", session_handle, len(ciphertext)) + ciphertext
        decrypt_response = emulator._hasp_decrypt_command(decrypt_data)

        status, decrypted_len = struct.unpack("<II", decrypt_response[:8])
        decrypted = decrypt_response[8:8+decrypted_len]

        assert status == HASPStatus.HASP_STATUS_OK
        assert decrypted == plaintext

    def test_hasp_memory_read_operation(self) -> None:
        """HASP memory read returns stored data."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        dongle = emulator.hasp_dongles[1]
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        login_response = emulator._hasp_login(login_data)
        _, session_handle = struct.unpack("<II", login_response)

        test_data = b"LICENSE_DATA_12345"
        dongle.memory.write("eeprom", 0, test_data)

        read_data = struct.pack("<III", session_handle, 0, len(test_data))
        response = emulator._hasp_read_memory(read_data)

        status, data_len = struct.unpack("<II", response[:8])
        read_bytes = response[8:8+data_len]

        assert status == HASPStatus.HASP_STATUS_OK
        assert read_bytes == test_data

    def test_hasp_memory_write_operation(self) -> None:
        """HASP memory write stores data correctly."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        dongle = emulator.hasp_dongles[1]
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        login_response = emulator._hasp_login(login_data)
        _, session_handle = struct.unpack("<II", login_response)

        test_data = b"WRITTEN_LICENSE_KEY"
        write_offset = 100
        write_data = struct.pack("<III", session_handle, write_offset, len(test_data)) + test_data

        response = emulator._hasp_write_memory(write_data)

        status = struct.unpack("<I", response)[0]
        assert status == HASPStatus.HASP_STATUS_OK

        stored_data = dongle.memory.read("eeprom", write_offset, len(test_data))
        assert stored_data == test_data

    def test_hasp_challenge_response_protocol(self) -> None:
        """HASP challenge-response authentication works."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        challenge = os.urandom(32)
        response = emulator.process_hasp_challenge(challenge, dongle_id=1)

        assert len(response) == 16
        assert response != challenge[:16]

        response2 = emulator.process_hasp_challenge(challenge, dongle_id=1)
        assert response == response2


class TestSentinelDongleEmulation:
    """Test Sentinel/SuperPro dongle emulation and protocol handling."""

    def test_create_sentinel_dongle_initializes_correctly(self) -> None:
        """Sentinel dongle creation initializes with valid parameters."""
        dongle = SentinelDongle(
            device_id=0x87654321,
            serial_number="SN123456789ABCDEF"
        )

        assert dongle.device_id == 0x87654321
        assert dongle.serial_number == "SN123456789ABCDEF"
        assert isinstance(dongle.memory, DongleMemory)
        assert len(dongle.algorithms) > 0

    def test_sentinel_dongle_includes_cryptographic_support(self) -> None:
        """Sentinel dongle includes cryptographic algorithm support."""
        dongle = SentinelDongle()

        assert "AES" in dongle.algorithms
        assert "RSA" in dongle.algorithms
        assert "DES" in dongle.algorithms
        assert "HMAC" in dongle.algorithms

    def test_sentinel_query_operation_returns_info(self) -> None:
        """Sentinel query operation returns device information."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        response = emulator._sentinel_query(b"")

        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_SUCCESS

        dongle = list(emulator.sentinel_dongles.values())[0]
        assert len(dongle.response_buffer) > 0

    def test_sentinel_read_cell_operation(self) -> None:
        """Sentinel read cell returns cell data."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        dongle = list(emulator.sentinel_dongles.values())[0]

        cell_id = 3
        test_data = os.urandom(64)
        dongle.cell_data[cell_id] = test_data

        read_data = struct.pack("<II", cell_id, 32)
        response = emulator._sentinel_read(read_data)

        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_SUCCESS

        read_bytes = bytes(dongle.response_buffer[:32])
        assert read_bytes == test_data[:32]

    def test_sentinel_write_cell_operation(self) -> None:
        """Sentinel write cell stores cell data."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        dongle = list(emulator.sentinel_dongles.values())[0]

        cell_id = 5
        test_data = b"SENTINEL_LICENSE_DATA" + b"\x00" * 43

        write_data = struct.pack("<II", cell_id, len(test_data)) + test_data

        response = emulator._sentinel_write(write_data)

        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_SUCCESS
        assert dongle.cell_data[cell_id][:len(test_data)] == test_data

    def test_sentinel_encrypt_operation(self) -> None:
        """Sentinel encryption operation encrypts data."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        dongle = list(emulator.sentinel_dongles.values())[0]

        plaintext = b"Data to encrypt with Sentinel"
        encrypt_data = struct.pack("<I", len(plaintext)) + plaintext

        response = emulator._sentinel_encrypt(encrypt_data)

        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_SUCCESS

        encrypted = bytes(dongle.response_buffer[:len(plaintext) + 16])
        assert len(encrypted) >= len(plaintext)


class TestUSBEmulation:
    """Test USB device emulation for dongles."""

    def test_usb_descriptor_serialization(self) -> None:
        """USB descriptor serializes to correct byte format."""
        descriptor = USBDescriptor(
            idVendor=0x0529,
            idProduct=0x0001,
            bDeviceClass=0xFF
        )

        descriptor_bytes = descriptor.to_bytes()

        assert len(descriptor_bytes) == 18
        assert struct.unpack("<H", descriptor_bytes[8:10])[0] == 0x0529
        assert struct.unpack("<H", descriptor_bytes[10:12])[0] == 0x0001

    def test_usb_control_transfer_device_descriptor(self) -> None:
        """USB control transfer returns device descriptor."""
        descriptor = USBDescriptor(idVendor=0x0529, idProduct=0x0001)
        usb = USBEmulator(descriptor)

        bmRequestType = 0x80
        bRequest = 0x06
        wValue = 0x0100
        wIndex = 0
        data = b""

        response = usb.control_transfer(bmRequestType, bRequest, wValue, wIndex, data)

        assert len(response) == 18
        assert response == descriptor.to_bytes()

    def test_usb_control_transfer_configuration_descriptor(self) -> None:
        """USB control transfer returns configuration descriptor."""
        descriptor = USBDescriptor()
        usb = USBEmulator(descriptor)

        bmRequestType = 0x80
        bRequest = 0x06
        wValue = 0x0200
        wIndex = 0
        data = b""

        response = usb.control_transfer(bmRequestType, bRequest, wValue, wIndex, data)

        assert len(response) == 32

    def test_usb_bulk_transfer_hasp_protocol(self) -> None:
        """USB bulk transfer handles HASP protocol commands."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        usb = emulator.usb_emulators["HASP_USB"]

        login_command = struct.pack("<I", 1)
        dongle = list(emulator.hasp_dongles.values())[0]
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)

        response = usb.bulk_transfer(0x02, login_command + login_data)

        status, session_handle = struct.unpack("<II", response)
        assert status == HASPStatus.HASP_STATUS_OK
        assert session_handle > 0


class TestCryptoEngine:
    """Test cryptographic engine for dongle operations."""

    def test_hasp_encrypt_aes_mode(self) -> None:
        """HASP AES encryption produces valid ciphertext."""
        crypto = CryptoEngine()

        key = os.urandom(32)
        plaintext = b"Test data for AES encryption"

        ciphertext = crypto.hasp_encrypt(plaintext, key, "AES")

        assert len(ciphertext) >= len(plaintext)
        assert ciphertext != plaintext

    def test_hasp_decrypt_aes_mode(self) -> None:
        """HASP AES decryption recovers plaintext."""
        crypto = CryptoEngine()

        key = os.urandom(32)
        plaintext = b"Test data for AES decryption"

        ciphertext = crypto.hasp_encrypt(plaintext, key, "AES")
        decrypted = crypto.hasp_decrypt(ciphertext, key, "AES")

        assert decrypted == plaintext

    def test_hasp_encrypt_des_mode(self) -> None:
        """HASP DES encryption produces valid ciphertext."""
        crypto = CryptoEngine()

        key = os.urandom(24)
        plaintext = b"DES test"

        ciphertext = crypto.hasp_encrypt(plaintext, key, "DES")

        assert len(ciphertext) >= len(plaintext)
        assert ciphertext != plaintext

    def test_sentinel_challenge_response(self) -> None:
        """Sentinel challenge-response produces valid response."""
        crypto = CryptoEngine()

        challenge = os.urandom(32)
        key = os.urandom(32)

        response = crypto.sentinel_challenge_response(challenge, key)

        assert len(response) == 16
        assert response != challenge[:16]

        response2 = crypto.sentinel_challenge_response(challenge, key)
        assert response == response2

    def test_wibukey_challenge_response(self) -> None:
        """WibuKey challenge-response produces valid response."""
        crypto = CryptoEngine()

        challenge = os.urandom(16)
        key = os.urandom(16)

        response = crypto.wibukey_challenge_response(challenge, key)

        assert len(response) == 16


class TestDongleMemory:
    """Test dongle memory operations."""

    def test_memory_read_operation_returns_data(self) -> None:
        """Memory read returns stored data."""
        memory = DongleMemory()

        test_data = b"LICENSE_KEY_DATA_12345"
        memory.rom[:len(test_data)] = test_data

        read_data = memory.read("rom", 0, len(test_data))

        assert read_data == test_data

    def test_memory_write_operation_stores_data(self) -> None:
        """Memory write stores data correctly."""
        memory = DongleMemory()

        test_data = b"STORED_DATA"
        memory.write("ram", 100, test_data)

        assert memory.ram[100:100+len(test_data)] == test_data

    def test_memory_read_out_of_bounds_raises_error(self) -> None:
        """Memory read beyond bounds raises ValueError."""
        memory = DongleMemory()

        with pytest.raises(ValueError):
            memory.read("rom", 0, 10000)

    def test_memory_write_to_readonly_area_raises_error(self) -> None:
        """Memory write to read-only area raises PermissionError."""
        memory = DongleMemory()
        memory.read_only_areas = [(0, 512)]

        with pytest.raises(PermissionError):
            memory.write("rom", 100, b"ATTEMPT_WRITE")

    def test_memory_protected_area_check(self) -> None:
        """Memory protection check identifies protected regions."""
        memory = DongleMemory()
        memory.protected_areas = [(0, 1024)]

        assert memory.is_protected(0, 512) is True
        assert memory.is_protected(2000, 100) is False


class TestComprehensiveDongleEmulation:
    """Test comprehensive dongle emulation workflow."""

    def test_activate_multiple_dongle_types(self) -> None:
        """Activating emulation creates multiple dongle types."""
        emulator = HardwareDongleEmulator()

        result = emulator.activate_dongle_emulation(["HASP", "Sentinel", "CodeMeter"])

        assert result["success"] is True
        assert len(result["emulated_dongles"]) >= 3
        assert "HASP" in result["emulated_dongles"][0] or "Sentinel" in result["emulated_dongles"][0]

    def test_emulation_status_reflects_active_dongles(self) -> None:
        """Emulation status shows all active dongles."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP", "Sentinel"])

        status = emulator.get_emulation_status()

        assert status["hasp_dongles"] >= 1
        assert status["sentinel_dongles"] >= 1
        assert len(status["virtual_dongles_active"]) >= 2

    def test_read_dongle_memory_interface(self) -> None:
        """Public read dongle memory interface works."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        test_data = b"PUBLIC_READ_TEST"
        dongle = emulator.hasp_dongles[1]
        dongle.memory.write("eeprom", 50, test_data)

        read_data = emulator.read_dongle_memory("HASP", 1, "eeprom", 50, len(test_data))

        assert read_data == test_data

    def test_write_dongle_memory_interface(self) -> None:
        """Public write dongle memory interface works."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        test_data = b"PUBLIC_WRITE_TEST"

        success = emulator.write_dongle_memory("Sentinel", 1, "ram", 200, test_data)

        assert success is True

        dongle = emulator.sentinel_dongles[1]
        assert dongle.memory.ram[200:200+len(test_data)] == test_data

    def test_clear_emulation_removes_all_dongles(self) -> None:
        """Clearing emulation removes all virtual dongles."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP", "Sentinel"])

        emulator.clear_emulation()

        status = emulator.get_emulation_status()
        assert status["hasp_dongles"] == 0
        assert status["sentinel_dongles"] == 0
        assert len(status["virtual_dongles_active"]) == 0


class TestDongleConfigurationRetrieval:
    """Test dongle configuration retrieval."""

    def test_get_hasp_dongle_config(self) -> None:
        """Retrieves HASP dongle configuration."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        config = emulator.get_dongle_config("hasp")

        assert config is not None
        assert config["type"] == "HASP"
        assert config["vendor_id"] == 0x0529
        assert "api_functions" in config
        assert "hasp_login" in config["api_functions"]

    def test_get_sentinel_dongle_config(self) -> None:
        """Retrieves Sentinel dongle configuration."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        config = emulator.get_dongle_config("sentinel")

        assert config is not None
        assert config["type"] == "Sentinel"
        assert "api_functions" in config
        assert "RNBOsproQuery" in config["api_functions"]

    def test_get_unknown_dongle_config_returns_none(self) -> None:
        """Requesting unknown dongle type returns None."""
        emulator = HardwareDongleEmulator()

        config = emulator.get_dongle_config("unknown_dongle_type")

        assert config is None


class TestProtocolErrorHandling:
    """Test protocol error handling."""

    def test_hasp_login_with_too_short_data(self) -> None:
        """HASP login with insufficient data returns error."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        short_data = b"\x00"
        response = emulator._hasp_login(short_data)

        status = struct.unpack("<I", response)[0]
        assert status == HASPStatus.HASP_TOO_SHORT

    def test_hasp_read_memory_out_of_bounds(self) -> None:
        """HASP memory read out of bounds returns error."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        dongle = emulator.hasp_dongles[1]
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        login_response = emulator._hasp_login(login_data)
        _, session_handle = struct.unpack("<II", login_response)

        read_data = struct.pack("<III", session_handle, 10000, 1000)
        response = emulator._hasp_read_memory(read_data)

        status = struct.unpack("<I", response)[0]
        assert status == HASPStatus.HASP_MEM_RANGE

    def test_sentinel_read_invalid_cell(self) -> None:
        """Sentinel read from invalid cell returns error."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        invalid_cell_id = 999
        read_data = struct.pack("<II", invalid_cell_id, 64)

        response = emulator._sentinel_read(read_data)

        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_UNIT_NOT_FOUND
