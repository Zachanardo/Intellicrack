"""Comprehensive Tests for Hardware Dongle Emulator.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import hashlib
import hmac
import os
import struct
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from intellicrack.core.protection_bypass.dongle_emulator import (
    CRYPTO_AVAILABLE,
    CryptoEngine,
    DongleMemory,
    DongleType,
    HASPDongle,
    HASPStatus,
    HardwareDongleEmulator,
    SentinelDongle,
    SentinelStatus,
    USBDescriptor,
    USBEmulator,
    WibuKeyDongle,
    activate_hardware_dongle_emulation,
)

if CRYPTO_AVAILABLE:
    from Crypto.Cipher import AES, DES, DES3


@pytest.fixture
def crypto_engine() -> CryptoEngine:
    """Create crypto engine instance."""
    return CryptoEngine()


@pytest.fixture
def dongle_memory() -> DongleMemory:
    """Create dongle memory instance with configured regions."""
    memory = DongleMemory()
    memory.protected_areas = [(0, 1024)]
    memory.read_only_areas = [(0, 512)]
    memory.rom[0:8] = b"DONGLEROM"[:8]
    memory.ram[0:8] = b"DONGLERAM"[:8]
    memory.eeprom[0:8] = b"DONGLEEE"[:8]
    return memory


@pytest.fixture
def hasp_dongle() -> HASPDongle:
    """Create configured HASP dongle instance."""
    dongle = HASPDongle()
    dongle.hasp_id = 0x12345678
    dongle.vendor_code = 0x1234
    dongle.feature_id = 1
    dongle.logged_in = False
    dongle.session_handle = 0
    return dongle


@pytest.fixture
def sentinel_dongle() -> SentinelDongle:
    """Create configured Sentinel dongle instance."""
    dongle = SentinelDongle()
    dongle.device_id = 0x87654321
    dongle.serial_number = "SN123456789ABCDEF"
    dongle.firmware_version = "8.0.0"
    return dongle


@pytest.fixture
def wibukey_dongle() -> WibuKeyDongle:
    """Create configured WibuKey dongle instance."""
    dongle = WibuKeyDongle()
    dongle.firm_code = 101
    dongle.product_code = 1000
    dongle.feature_code = 1
    dongle.serial_number = 1000001
    return dongle


@pytest.fixture
def usb_descriptor() -> USBDescriptor:
    """Create USB device descriptor."""
    return USBDescriptor(
        idVendor=0x0529,
        idProduct=0x0001,
        bDeviceClass=0xFF,
        bDeviceSubClass=0xFF,
    )


@pytest.fixture
def usb_emulator(usb_descriptor: USBDescriptor) -> USBEmulator:
    """Create USB emulator instance."""
    return USBEmulator(usb_descriptor)


@pytest.fixture
def dongle_emulator() -> HardwareDongleEmulator:
    """Create dongle emulator instance."""
    app = MagicMock()
    app.binary_path = None
    return HardwareDongleEmulator(app)


@pytest.fixture
def test_binary_path(tmp_path: Path) -> Path:
    """Create test binary with dongle check patterns."""
    binary_path = tmp_path / "test_protected.exe"

    binary_data = bytearray(b"MZ\x90\x00" + b"\x00" * 60)
    binary_data.extend(b"\x00" * 200)

    binary_data.extend(b"\x85\xc0\x74\x05")
    binary_data.extend(b"\x85\xc0\x75\x06")
    binary_data.extend(b"\x83\xf8\x00\x74\x08")
    binary_data.extend(b"\x48\x85\xc0\x74\x0a")
    binary_data.extend(b"\x3d\x00\x00\x00\x00\x75\x0c")

    binary_data.extend(b"\x00" * 1000)

    binary_path.write_bytes(bytes(binary_data))
    return binary_path


class TestDongleMemory:
    """Test dongle memory operations."""

    def test_memory_read_rom_valid(self, dongle_memory: DongleMemory) -> None:
        """Memory read from ROM returns correct data."""
        data = dongle_memory.read("rom", 0, 8)
        assert data == b"DONGLEROM"[:8]
        assert len(data) == 8

    def test_memory_read_ram_valid(self, dongle_memory: DongleMemory) -> None:
        """Memory read from RAM returns correct data."""
        data = dongle_memory.read("ram", 0, 8)
        assert data == b"DONGLERAM"[:8]
        assert len(data) == 8

    def test_memory_read_eeprom_valid(self, dongle_memory: DongleMemory) -> None:
        """Memory read from EEPROM returns correct data."""
        data = dongle_memory.read("eeprom", 0, 8)
        assert data == b"DONGLEEE"[:8]
        assert len(data) == 8

    def test_memory_read_invalid_region(self, dongle_memory: DongleMemory) -> None:
        """Memory read from invalid region raises ValueError."""
        with pytest.raises(ValueError, match="Invalid memory region"):
            dongle_memory.read("invalid", 0, 8)

    def test_memory_read_beyond_bounds(self, dongle_memory: DongleMemory) -> None:
        """Memory read beyond bounds raises ValueError."""
        with pytest.raises(ValueError, match="Read beyond memory bounds"):
            dongle_memory.read("rom", 8192, 1)

    def test_memory_write_ram_valid(self, dongle_memory: DongleMemory) -> None:
        """Memory write to RAM succeeds and data is readable."""
        test_data = b"TESTDATA"
        dongle_memory.write("ram", 100, test_data)
        read_data = dongle_memory.read("ram", 100, 8)
        assert read_data == test_data

    def test_memory_write_eeprom_valid(self, dongle_memory: DongleMemory) -> None:
        """Memory write to EEPROM succeeds and data is readable."""
        test_data = b"LICENSE1"
        dongle_memory.write("eeprom", 500, test_data)
        read_data = dongle_memory.read("eeprom", 500, 8)
        assert read_data == test_data

    def test_memory_write_readonly_area(self, dongle_memory: DongleMemory) -> None:
        """Memory write to read-only area raises PermissionError."""
        dongle_memory.read_only_areas = [(0, 512)]
        with pytest.raises(PermissionError, match="Cannot write to read-only area"):
            dongle_memory.write("rom", 100, b"TEST")

    def test_memory_write_invalid_region(self, dongle_memory: DongleMemory) -> None:
        """Memory write to invalid region raises ValueError."""
        with pytest.raises(ValueError, match="Invalid memory region"):
            dongle_memory.write("invalid", 0, b"TEST")

    def test_memory_write_beyond_bounds(self, dongle_memory: DongleMemory) -> None:
        """Memory write beyond bounds raises ValueError."""
        with pytest.raises(ValueError, match="Write beyond memory bounds"):
            dongle_memory.write("ram", 4096, b"TEST")

    def test_memory_protected_area_check(self, dongle_memory: DongleMemory) -> None:
        """Protected area check correctly identifies protected regions."""
        dongle_memory.protected_areas = [(100, 200), (500, 600)]
        assert dongle_memory.is_protected(100, 50) is True
        assert dongle_memory.is_protected(150, 10) is True
        assert dongle_memory.is_protected(50, 10) is False
        assert dongle_memory.is_protected(250, 10) is False


class TestCryptoEngine:
    """Test cryptographic operations."""

    def test_hasp_encrypt_aes_produces_ciphertext(self, crypto_engine: CryptoEngine) -> None:
        """HASP AES encryption produces different ciphertext from plaintext."""
        plaintext = b"This is test data for encryption testing"
        key = os.urandom(32)
        ciphertext = crypto_engine.hasp_encrypt(plaintext, key, "AES")

        assert ciphertext != plaintext
        assert len(ciphertext) >= len(plaintext)
        assert len(ciphertext) % 16 == 0

    def test_hasp_encrypt_decrypt_aes_roundtrip(self, crypto_engine: CryptoEngine) -> None:
        """HASP AES encrypt-decrypt roundtrip recovers original data."""
        plaintext = b"Sensitive license data that must be protected"
        key = os.urandom(32)

        ciphertext = crypto_engine.hasp_encrypt(plaintext, key, "AES")
        decrypted = crypto_engine.hasp_decrypt(ciphertext, key, "AES")

        assert decrypted == plaintext

    def test_hasp_encrypt_des_produces_ciphertext(self, crypto_engine: CryptoEngine) -> None:
        """HASP DES encryption produces different ciphertext from plaintext."""
        plaintext = b"DES test data"
        key = os.urandom(24)
        ciphertext = crypto_engine.hasp_encrypt(plaintext, key, "DES")

        assert ciphertext != plaintext
        assert len(ciphertext) >= len(plaintext)
        assert len(ciphertext) % 8 == 0

    def test_hasp_encrypt_decrypt_des_roundtrip(self, crypto_engine: CryptoEngine) -> None:
        """HASP DES encrypt-decrypt roundtrip recovers original data."""
        plaintext = b"Legacy DES protected data"
        key = os.urandom(24)

        ciphertext = crypto_engine.hasp_encrypt(plaintext, key, "DES")
        decrypted = crypto_engine.hasp_decrypt(ciphertext, key, "DES")

        assert decrypted == plaintext

    def test_hasp_encrypt_des3_produces_ciphertext(self, crypto_engine: CryptoEngine) -> None:
        """HASP DES3 encryption produces different ciphertext from plaintext."""
        plaintext = b"Triple DES test data"
        key = os.urandom(24)
        ciphertext = crypto_engine.hasp_encrypt(plaintext, key, "DES3")

        assert ciphertext != plaintext
        assert len(ciphertext) >= len(plaintext)
        assert len(ciphertext) % 8 == 0

    def test_hasp_encrypt_decrypt_des3_roundtrip(self, crypto_engine: CryptoEngine) -> None:
        """HASP DES3 encrypt-decrypt roundtrip recovers original data."""
        plaintext = b"Triple DES protected license"
        key = os.urandom(24)

        ciphertext = crypto_engine.hasp_encrypt(plaintext, key, "DES3")
        decrypted = crypto_engine.hasp_decrypt(ciphertext, key, "DES3")

        assert decrypted == plaintext

    def test_hasp_encrypt_wrong_key_fails_decrypt(self, crypto_engine: CryptoEngine) -> None:
        """HASP decryption with wrong key produces garbage data."""
        plaintext = b"Encrypted with one key"
        key1 = os.urandom(32)
        key2 = os.urandom(32)

        ciphertext = crypto_engine.hasp_encrypt(plaintext, key1, "AES")
        decrypted = crypto_engine.hasp_decrypt(ciphertext, key2, "AES")

        assert decrypted != plaintext

    def test_sentinel_challenge_response_produces_valid_response(self, crypto_engine: CryptoEngine) -> None:
        """Sentinel challenge-response produces deterministic response."""
        challenge = os.urandom(32)
        key = os.urandom(32)

        response1 = crypto_engine.sentinel_challenge_response(challenge, key)
        response2 = crypto_engine.sentinel_challenge_response(challenge, key)

        assert response1 == response2
        assert len(response1) == 16
        assert response1 != challenge[:16]

    def test_sentinel_challenge_response_different_challenges(self, crypto_engine: CryptoEngine) -> None:
        """Sentinel challenge-response produces different responses for different challenges."""
        key = os.urandom(32)
        challenge1 = os.urandom(32)
        challenge2 = os.urandom(32)

        response1 = crypto_engine.sentinel_challenge_response(challenge1, key)
        response2 = crypto_engine.sentinel_challenge_response(challenge2, key)

        assert response1 != response2

    def test_sentinel_challenge_response_uses_hmac(self, crypto_engine: CryptoEngine) -> None:
        """Sentinel challenge-response matches HMAC-SHA256 calculation."""
        challenge = os.urandom(32)
        key = os.urandom(32)

        response = crypto_engine.sentinel_challenge_response(challenge, key)
        expected = hmac.new(key, challenge, hashlib.sha256).digest()[:16]

        assert response == expected

    def test_wibukey_challenge_response_produces_valid_response(self, crypto_engine: CryptoEngine) -> None:
        """WibuKey challenge-response produces deterministic response."""
        challenge = os.urandom(32)
        key = os.urandom(32)

        response1 = crypto_engine.wibukey_challenge_response(challenge, key)
        response2 = crypto_engine.wibukey_challenge_response(challenge, key)

        assert response1 == response2
        assert len(response1) == 16
        assert response1 != challenge[:16]

    def test_wibukey_challenge_response_different_challenges(self, crypto_engine: CryptoEngine) -> None:
        """WibuKey challenge-response produces different responses for different challenges."""
        key = os.urandom(32)
        challenge1 = os.urandom(32)
        challenge2 = os.urandom(32)

        response1 = crypto_engine.wibukey_challenge_response(challenge1, key)
        response2 = crypto_engine.wibukey_challenge_response(challenge2, key)

        assert response1 != response2

    def test_rsa_sign_produces_signature(self, crypto_engine: CryptoEngine) -> None:
        """RSA signing produces valid signature for data."""
        data = b"Data to be signed with RSA"

        if CRYPTO_AVAILABLE:
            from Crypto.PublicKey import RSA
            key = RSA.generate(2048)
            signature = crypto_engine.rsa_sign(data, key)
            assert len(signature) == 256
            assert signature != data
        else:
            signature = crypto_engine.rsa_sign(data, None)
            assert len(signature) == 32

    def test_xor_encrypt_produces_ciphertext(self, crypto_engine: CryptoEngine) -> None:
        """XOR encryption fallback produces different ciphertext."""
        plaintext = b"XOR encryption test data"
        key = b"secret_key_12345"

        ciphertext = crypto_engine._xor_encrypt(plaintext, key)

        assert ciphertext != plaintext
        assert len(ciphertext) == len(plaintext)

    def test_xor_encrypt_decrypt_roundtrip(self, crypto_engine: CryptoEngine) -> None:
        """XOR encrypt-decrypt roundtrip recovers original data."""
        plaintext = b"XOR test data for roundtrip"
        key = b"secret_key"

        ciphertext = crypto_engine._xor_encrypt(plaintext, key)
        decrypted = crypto_engine._xor_encrypt(ciphertext, key)

        assert decrypted == plaintext


class TestUSBDescriptor:
    """Test USB device descriptor."""

    def test_usb_descriptor_to_bytes_structure(self, usb_descriptor: USBDescriptor) -> None:
        """USB descriptor serialization produces valid structure."""
        data = usb_descriptor.to_bytes()

        assert len(data) == 18
        assert data[0] == 18
        assert data[1] == 1

        unpacked = struct.unpack("<BBHBBBBHHHBBBB", data)
        assert unpacked[0] == 18
        assert unpacked[1] == 1
        assert unpacked[7] == 0x0529
        assert unpacked[8] == 0x0001

    def test_usb_descriptor_vendor_product_ids(self, usb_descriptor: USBDescriptor) -> None:
        """USB descriptor contains correct vendor and product IDs."""
        data = usb_descriptor.to_bytes()
        unpacked = struct.unpack("<BBHBBBBHHHBBBB", data)

        vendor_id = unpacked[7]
        product_id = unpacked[8]

        assert vendor_id == 0x0529
        assert product_id == 0x0001


class TestUSBEmulator:
    """Test USB device emulation."""

    def test_usb_emulator_endpoints_configured(self, usb_emulator: USBEmulator) -> None:
        """USB emulator configures standard endpoints."""
        assert 0x00 in usb_emulator.endpoints
        assert 0x81 in usb_emulator.endpoints
        assert 0x02 in usb_emulator.endpoints
        assert 0x83 in usb_emulator.endpoints

        assert usb_emulator.endpoints[0x00]["type"] == "control"
        assert usb_emulator.endpoints[0x81]["type"] == "bulk"
        assert usb_emulator.endpoints[0x02]["type"] == "bulk"
        assert usb_emulator.endpoints[0x83]["type"] == "interrupt"

    def test_usb_control_transfer_get_device_descriptor(self, usb_emulator: USBEmulator) -> None:
        """USB control transfer returns device descriptor."""
        bmRequestType = 0x80
        bRequest = 0x06
        wValue = 0x0100
        wIndex = 0
        data = b""

        response = usb_emulator.control_transfer(bmRequestType, bRequest, wValue, wIndex, data)

        assert len(response) == 18
        assert response[0] == 18
        assert response[1] == 1

    def test_usb_control_transfer_get_configuration_descriptor(self, usb_emulator: USBEmulator) -> None:
        """USB control transfer returns configuration descriptor."""
        bmRequestType = 0x80
        bRequest = 0x06
        wValue = 0x0200
        wIndex = 0
        data = b""

        response = usb_emulator.control_transfer(bmRequestType, bRequest, wValue, wIndex, data)

        assert len(response) > 9
        assert response[1] == 2

    def test_usb_control_transfer_get_string_descriptor(self, usb_emulator: USBEmulator) -> None:
        """USB control transfer returns string descriptor."""
        bmRequestType = 0x80
        bRequest = 0x06
        wValue = 0x0301
        wIndex = 0
        data = b""

        response = usb_emulator.control_transfer(bmRequestType, bRequest, wValue, wIndex, data)

        assert len(response) > 2
        assert b"SafeNet" in response or b"Sentinel" in response

    def test_usb_register_control_handler_called(self, usb_emulator: USBEmulator) -> None:
        """USB control handler registration and invocation works."""
        handler_called = False
        handler_args: tuple[int, int, bytes] = (0, 0, b"")

        def test_handler(wValue: int, wIndex: int, data: bytes) -> bytes:
            nonlocal handler_called, handler_args
            handler_called = True
            handler_args = (wValue, wIndex, data)
            return b"HANDLER_RESPONSE"

        usb_emulator.register_control_handler(0x40, 0x01, test_handler)
        response = usb_emulator.control_transfer(0x40, 0x01, 123, 456, b"TEST")

        assert handler_called is True
        assert handler_args[0] == 123
        assert handler_args[1] == 456
        assert handler_args[2] == b"TEST"
        assert response == b"HANDLER_RESPONSE"

    def test_usb_register_bulk_handler_called(self, usb_emulator: USBEmulator) -> None:
        """USB bulk handler registration and invocation works."""
        handler_called = False
        handler_data: bytes = b""

        def test_handler(data: bytes) -> bytes:
            nonlocal handler_called, handler_data
            handler_called = True
            handler_data = data
            return b"BULK_RESPONSE"

        usb_emulator.register_bulk_handler(0x02, test_handler)
        response = usb_emulator.bulk_transfer(0x02, b"BULK_DATA")

        assert handler_called is True
        assert handler_data == b"BULK_DATA"
        assert response == b"BULK_RESPONSE"


class TestHASPDongle:
    """Test HASP dongle emulation."""

    def test_hasp_dongle_initialization(self, hasp_dongle: HASPDongle) -> None:
        """HASP dongle initializes with correct defaults."""
        assert hasp_dongle.hasp_id == 0x12345678
        assert hasp_dongle.vendor_code == 0x1234
        assert hasp_dongle.feature_id == 1
        assert hasp_dongle.logged_in is False
        assert len(hasp_dongle.seed_code) == 16
        assert len(hasp_dongle.aes_key) == 32
        assert len(hasp_dongle.des_key) == 24

    def test_hasp_dongle_feature_map(self, hasp_dongle: HASPDongle) -> None:
        """HASP dongle feature map contains valid license data."""
        assert 1 in hasp_dongle.feature_map
        feature = hasp_dongle.feature_map[1]

        assert feature["id"] == 1
        assert feature["type"] == "license"
        assert feature["expiration"] == 0xFFFFFFFF
        assert feature["max_users"] == 10
        assert feature["current_users"] == 0

    def test_hasp_dongle_rsa_key_generated(self) -> None:
        """HASP dongle generates RSA key if crypto available."""
        dongle = HASPDongle()

        if CRYPTO_AVAILABLE:
            assert dongle.rsa_key is not None
            assert dongle.rsa_key.size_in_bits() == 2048


class TestSentinelDongle:
    """Test Sentinel dongle emulation."""

    def test_sentinel_dongle_initialization(self, sentinel_dongle: SentinelDongle) -> None:
        """Sentinel dongle initializes with correct defaults."""
        assert sentinel_dongle.device_id == 0x87654321
        assert sentinel_dongle.serial_number == "SN123456789ABCDEF"
        assert sentinel_dongle.firmware_version == "8.0.0"
        assert len(sentinel_dongle.aes_key) == 32
        assert len(sentinel_dongle.des_key) == 24
        assert "AES" in sentinel_dongle.algorithms
        assert "RSA" in sentinel_dongle.algorithms

    def test_sentinel_dongle_cell_data_initialized(self, sentinel_dongle: SentinelDongle) -> None:
        """Sentinel dongle cell data is initialized."""
        assert len(sentinel_dongle.cell_data) >= 8
        for i in range(8):
            assert i in sentinel_dongle.cell_data
            assert len(sentinel_dongle.cell_data[i]) == 64


class TestWibuKeyDongle:
    """Test WibuKey/CodeMeter dongle emulation."""

    def test_wibukey_dongle_initialization(self, wibukey_dongle: WibuKeyDongle) -> None:
        """WibuKey dongle initializes with correct defaults."""
        assert wibukey_dongle.firm_code == 101
        assert wibukey_dongle.product_code == 1000
        assert wibukey_dongle.feature_code == 1
        assert wibukey_dongle.serial_number == 1000001
        assert len(wibukey_dongle.aes_key) == 32
        assert len(wibukey_dongle.challenge_response_key) == 16

    def test_wibukey_dongle_license_entries(self, wibukey_dongle: WibuKeyDongle) -> None:
        """WibuKey dongle license entries are configured."""
        assert 1 in wibukey_dongle.license_entries
        entry = wibukey_dongle.license_entries[1]

        assert entry["firm_code"] == 101
        assert entry["product_code"] == 1000
        assert entry["feature_code"] == 1
        assert entry["quantity"] == 100
        assert entry["expiration"] == 0xFFFFFFFF
        assert entry["enabled"] is True


class TestHardwareDongleEmulator:
    """Test hardware dongle emulator main functionality."""

    def test_activate_dongle_emulation_creates_virtual_dongles(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """Dongle emulator creates virtual dongles on activation."""
        results = dongle_emulator.activate_dongle_emulation(["HASP", "Sentinel", "CodeMeter"])

        assert results["success"] is True
        assert len(results["emulated_dongles"]) > 0
        assert "HASP" in str(results["emulated_dongles"]) or len(dongle_emulator.hasp_dongles) > 0
        assert "Virtual Dongle Creation" in results["methods_applied"]

    def test_activate_dongle_emulation_default_types(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """Dongle emulator uses default types when none specified."""
        results = dongle_emulator.activate_dongle_emulation(None)

        assert results["success"] is True
        assert len(results["emulated_dongles"]) > 0
        assert len(results["methods_applied"]) > 0

    def test_activate_dongle_emulation_usb_setup(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """Dongle emulator sets up USB emulation."""
        results = dongle_emulator.activate_dongle_emulation(["HASP"])

        assert "USB Device Emulation" in results["methods_applied"]
        assert len(dongle_emulator.usb_emulators) > 0

    def test_hasp_login_operation_success(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """HASP login operation returns success with valid handle."""
        dongle_emulator.activate_dongle_emulation(["HASP"])

        dongle = next(iter(dongle_emulator.hasp_dongles.values()))
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)

        response = dongle_emulator._hasp_login(login_data)

        assert len(response) >= 4
        status = struct.unpack("<I", response[:4])[0]
        assert status == HASPStatus.HASP_STATUS_OK

        if len(response) >= 8:
            session_handle = struct.unpack("<I", response[4:8])[0]
            assert session_handle != 0

    def test_hasp_login_operation_sets_logged_in(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """HASP login operation sets dongle to logged in state."""
        dongle_emulator.activate_dongle_emulation(["HASP"])

        dongle = next(iter(dongle_emulator.hasp_dongles.values()))
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)

        assert dongle.logged_in is False
        dongle_emulator._hasp_login(login_data)
        assert dongle.logged_in is True
        assert dongle.session_handle != 0

    def test_hasp_login_invalid_vendor_returns_error(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """HASP login with invalid vendor code returns error."""
        dongle_emulator.activate_dongle_emulation(["HASP"])

        login_data = struct.pack("<HH", 0xFFFF, 1)
        response = dongle_emulator._hasp_login(login_data)

        status = struct.unpack("<I", response[:4])[0]
        assert status == HASPStatus.HASP_KEYNOTFOUND

    def test_hasp_logout_operation_success(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """HASP logout operation succeeds after login."""
        dongle_emulator.activate_dongle_emulation(["HASP"])

        dongle = next(iter(dongle_emulator.hasp_dongles.values()))
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        dongle_emulator._hasp_login(login_data)

        logout_data = struct.pack("<I", dongle.session_handle)
        response = dongle_emulator._hasp_logout(logout_data)

        status = struct.unpack("<I", response[:4])[0]
        assert status == HASPStatus.HASP_STATUS_OK
        assert dongle.logged_in is False

    def test_hasp_encrypt_operation_produces_ciphertext(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """HASP encrypt operation produces ciphertext different from plaintext."""
        dongle_emulator.activate_dongle_emulation(["HASP"])

        dongle = next(iter(dongle_emulator.hasp_dongles.values()))
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        dongle_emulator._hasp_login(login_data)

        plaintext = b"Secret data to encrypt"
        encrypt_data = struct.pack("<II", dongle.session_handle, len(plaintext)) + plaintext
        response = dongle_emulator._hasp_encrypt_command(encrypt_data)

        status = struct.unpack("<I", response[:4])[0]
        assert status == HASPStatus.HASP_STATUS_OK

        if len(response) > 8:
            ciphertext_len = struct.unpack("<I", response[4:8])[0]
            ciphertext = response[8:8+ciphertext_len]
            assert ciphertext != plaintext

    def test_hasp_decrypt_operation_recovers_plaintext(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """HASP decrypt operation recovers original plaintext."""
        dongle_emulator.activate_dongle_emulation(["HASP"])

        dongle = next(iter(dongle_emulator.hasp_dongles.values()))
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        dongle_emulator._hasp_login(login_data)

        plaintext = b"Data for roundtrip test"
        encrypt_data = struct.pack("<II", dongle.session_handle, len(plaintext)) + plaintext
        encrypt_response = dongle_emulator._hasp_encrypt_command(encrypt_data)

        ciphertext_len = struct.unpack("<I", encrypt_response[4:8])[0]
        ciphertext = encrypt_response[8:8+ciphertext_len]

        decrypt_data = struct.pack("<II", dongle.session_handle, len(ciphertext)) + ciphertext
        decrypt_response = dongle_emulator._hasp_decrypt_command(decrypt_data)

        status = struct.unpack("<I", decrypt_response[:4])[0]
        assert status == HASPStatus.HASP_STATUS_OK

        decrypted_len = struct.unpack("<I", decrypt_response[4:8])[0]
        decrypted = decrypt_response[8:8+decrypted_len]
        assert decrypted == plaintext

    def test_hasp_read_memory_returns_data(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """HASP memory read returns data from dongle memory."""
        dongle_emulator.activate_dongle_emulation(["HASP"])

        dongle = next(iter(dongle_emulator.hasp_dongles.values()))
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        dongle_emulator._hasp_login(login_data)

        dongle.memory.write("eeprom", 100, b"LICENSE_DATA_12345")

        read_data = struct.pack("<III", dongle.session_handle, 100, 18)
        response = dongle_emulator._hasp_read_memory(read_data)

        status = struct.unpack("<I", response[:4])[0]
        assert status == HASPStatus.HASP_STATUS_OK

        data_len = struct.unpack("<I", response[4:8])[0]
        data = response[8:8+data_len]
        assert data == b"LICENSE_DATA_12345"

    def test_hasp_write_memory_stores_data(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """HASP memory write stores data in dongle memory."""
        dongle_emulator.activate_dongle_emulation(["HASP"])

        dongle = next(iter(dongle_emulator.hasp_dongles.values()))
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        dongle_emulator._hasp_login(login_data)

        test_data = b"WRITTEN_BY_TEST"
        write_data = struct.pack("<III", dongle.session_handle, 200, len(test_data)) + test_data
        response = dongle_emulator._hasp_write_memory(write_data)

        status = struct.unpack("<I", response[:4])[0]
        assert status == HASPStatus.HASP_STATUS_OK

        read_back = dongle.memory.read("eeprom", 200, len(test_data))
        assert read_back == test_data

    def test_sentinel_query_returns_device_info(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """Sentinel query operation returns device information."""
        dongle_emulator.activate_dongle_emulation(["Sentinel"])

        response = dongle_emulator._sentinel_query(b"")

        status = struct.unpack("<I", response[:4])[0]
        assert status == SentinelStatus.SP_SUCCESS

        dongle = next(iter(dongle_emulator.sentinel_dongles.values()))
        device_id = struct.unpack("<I", dongle.response_buffer[:4])[0]
        assert device_id == dongle.device_id

    def test_sentinel_read_returns_cell_data(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """Sentinel read operation returns cell data."""
        dongle_emulator.activate_dongle_emulation(["Sentinel"])

        dongle = next(iter(dongle_emulator.sentinel_dongles.values()))
        test_cell_data = os.urandom(64)
        dongle.cell_data[5] = test_cell_data

        read_data = struct.pack("<II", 5, 64)
        response = dongle_emulator._sentinel_read(read_data)

        status = struct.unpack("<I", response[:4])[0]
        assert status == SentinelStatus.SP_SUCCESS

        read_back = bytes(dongle.response_buffer[:64])
        assert read_back == test_cell_data

    def test_sentinel_write_stores_cell_data(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """Sentinel write operation stores cell data."""
        dongle_emulator.activate_dongle_emulation(["Sentinel"])

        test_data = b"SENTINEL_CELL_DATA" + b"\x00" * 46
        write_data = struct.pack("<II", 10, len(test_data)) + test_data
        response = dongle_emulator._sentinel_write(write_data)

        status = struct.unpack("<I", response[:4])[0]
        assert status == SentinelStatus.SP_SUCCESS

        dongle = next(iter(dongle_emulator.sentinel_dongles.values()))
        assert 10 in dongle.cell_data
        assert dongle.cell_data[10][:18] == b"SENTINEL_CELL_DATA"

    def test_sentinel_encrypt_produces_ciphertext(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """Sentinel encrypt operation produces ciphertext."""
        dongle_emulator.activate_dongle_emulation(["Sentinel"])

        plaintext = b"Sentinel encryption test data"
        encrypt_data = struct.pack("<I", len(plaintext)) + plaintext
        response = dongle_emulator._sentinel_encrypt(encrypt_data)

        status = struct.unpack("<I", response[:4])[0]
        assert status == SentinelStatus.SP_SUCCESS

        dongle = next(iter(dongle_emulator.sentinel_dongles.values()))
        ciphertext = bytes(dongle.response_buffer[:48])
        assert ciphertext != plaintext.ljust(48, b"\x00")

    def test_wibukey_open_operation_success(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """WibuKey open operation returns success with handle."""
        dongle_emulator.activate_dongle_emulation(["CodeMeter"])

        dongle = next(iter(dongle_emulator.wibukey_dongles.values()))
        open_data = struct.pack("<II", dongle.firm_code, dongle.product_code)

        response = dongle_emulator._wibukey_open(open_data)

        status = struct.unpack("<I", response[:4])[0]
        assert status == 0

        if len(response) >= 8:
            handle = struct.unpack("<I", response[4:8])[0]
            assert handle == dongle.container_handle

    def test_wibukey_access_operation_success(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """WibuKey access operation succeeds for valid license."""
        dongle_emulator.activate_dongle_emulation(["CodeMeter"])

        dongle = next(iter(dongle_emulator.wibukey_dongles.values()))
        access_data = struct.pack("<III", dongle.container_handle, 1, 0)

        response = dongle_emulator._wibukey_access(access_data)

        status = struct.unpack("<I", response[:4])[0]
        assert status == 0
        assert 1 in dongle.active_licenses

    def test_wibukey_encrypt_produces_ciphertext(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """WibuKey encrypt operation produces ciphertext."""
        dongle_emulator.activate_dongle_emulation(["CodeMeter"])

        dongle = next(iter(dongle_emulator.wibukey_dongles.values()))
        plaintext = b"WibuKey encryption test"
        encrypt_data = struct.pack("<II", dongle.container_handle, len(plaintext)) + plaintext

        response = dongle_emulator._wibukey_encrypt(encrypt_data)

        status = struct.unpack("<I", response[:4])[0]
        assert status == 0

        ciphertext_len = struct.unpack("<I", response[4:8])[0]
        ciphertext = response[8:8+ciphertext_len]
        assert ciphertext != plaintext

    def test_wibukey_challenge_response_produces_valid_response(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """WibuKey challenge-response produces valid response."""
        dongle_emulator.activate_dongle_emulation(["CodeMeter"])

        dongle = next(iter(dongle_emulator.wibukey_dongles.values()))
        challenge = os.urandom(32)
        challenge_data = struct.pack("<II", dongle.container_handle, len(challenge)) + challenge

        response = dongle_emulator._wibukey_challenge(challenge_data)

        status = struct.unpack("<I", response[:4])[0]
        assert status == 0

        response_len = struct.unpack("<I", response[4:8])[0]
        challenge_response = response[8:8+response_len]
        assert len(challenge_response) == 16
        assert challenge_response != challenge[:16]

    def test_process_hasp_challenge_valid_response(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """Process HASP challenge produces valid response."""
        dongle_emulator.activate_dongle_emulation(["HASP"])

        challenge = os.urandom(32)
        response = dongle_emulator.process_hasp_challenge(challenge, 1)

        assert len(response) == 16
        assert response != challenge[:16]

    def test_read_dongle_memory_hasp(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """Read dongle memory for HASP returns correct data."""
        dongle_emulator.activate_dongle_emulation(["HASP"])

        dongle = next(iter(dongle_emulator.hasp_dongles.values()))
        test_data = b"HASP_MEMORY_TEST"
        dongle.memory.write("ram", 500, test_data)

        read_data = dongle_emulator.read_dongle_memory("HASP", 1, "ram", 500, 16)

        assert read_data == test_data

    def test_read_dongle_memory_sentinel(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """Read dongle memory for Sentinel returns correct data."""
        dongle_emulator.activate_dongle_emulation(["Sentinel"])

        dongle = next(iter(dongle_emulator.sentinel_dongles.values()))
        test_data = b"SENTINEL_MEM_TEST"
        dongle.memory.write("eeprom", 300, test_data)

        read_data = dongle_emulator.read_dongle_memory("SENTINEL", 1, "eeprom", 300, 17)

        assert read_data == test_data

    def test_write_dongle_memory_hasp(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """Write dongle memory for HASP succeeds."""
        dongle_emulator.activate_dongle_emulation(["HASP"])

        test_data = b"WRITE_HASP_TEST"
        result = dongle_emulator.write_dongle_memory("HASP", 1, "ram", 100, test_data)

        assert result is True

        dongle = next(iter(dongle_emulator.hasp_dongles.values()))
        read_back = dongle.memory.read("ram", 100, 15)
        assert read_back == test_data

    def test_write_dongle_memory_wibukey(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """Write dongle memory for WibuKey succeeds."""
        dongle_emulator.activate_dongle_emulation(["CodeMeter"])

        test_data = b"WRITE_WIBU_TEST"
        result = dongle_emulator.write_dongle_memory("WIBUKEY", 1, "ram", 200, test_data)

        assert result is True

        dongle = next(iter(dongle_emulator.wibukey_dongles.values()))
        read_back = dongle.memory.read("ram", 200, 15)
        assert read_back == test_data

    def test_get_emulation_status(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """Get emulation status returns comprehensive information."""
        dongle_emulator.activate_dongle_emulation(["HASP", "Sentinel"])

        status = dongle_emulator.get_emulation_status()

        assert "hooks_installed" in status
        assert "patches_identified" in status
        assert "virtual_dongles_active" in status
        assert "emulated_dongle_count" in status
        assert "usb_emulators" in status
        assert "hasp_dongles" in status
        assert "sentinel_dongles" in status
        assert "wibukey_dongles" in status
        assert status["emulated_dongle_count"] > 0

    def test_clear_emulation(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """Clear emulation removes all virtual dongles and hooks."""
        dongle_emulator.activate_dongle_emulation(["HASP", "Sentinel", "CodeMeter"])

        assert len(dongle_emulator.virtual_dongles) > 0
        assert len(dongle_emulator.hasp_dongles) > 0

        dongle_emulator.clear_emulation()

        assert len(dongle_emulator.virtual_dongles) == 0
        assert len(dongle_emulator.hasp_dongles) == 0
        assert len(dongle_emulator.sentinel_dongles) == 0
        assert len(dongle_emulator.wibukey_dongles) == 0
        assert len(dongle_emulator.usb_emulators) == 0
        assert len(dongle_emulator.hooks) == 0
        assert len(dongle_emulator.patches) == 0

    def test_patch_dongle_checks_identifies_patterns(self, dongle_emulator: HardwareDongleEmulator, test_binary_path: Path) -> None:
        """Patch dongle checks identifies dongle check patterns in binary."""
        app = MagicMock()
        app.binary_path = str(test_binary_path)
        emulator = HardwareDongleEmulator(app)

        emulator._patch_dongle_checks()

        assert len(emulator.patches) > 0

        patterns_found = set()
        for patch in emulator.patches:
            if b"\x85\xc0\x74" in patch["original"]:
                patterns_found.add("TEST_JZ")
            elif b"\x85\xc0\x75" in patch["original"]:
                patterns_found.add("TEST_JNZ")
            elif b"\x83\xf8\x00\x74" in patch["original"]:
                patterns_found.add("CMP_JZ")

        assert len(patterns_found) > 0

    def test_generate_emulation_script_returns_frida_code(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """Generate emulation script returns Frida JavaScript code."""
        dongle_emulator.activate_dongle_emulation(["HASP"])

        script = dongle_emulator.generate_emulation_script(["HASP"])

        assert len(script) > 0
        assert "console.log" in script
        assert "HASP" in script or "hasp" in script.lower()
        assert "Interceptor.attach" in script


class TestActivateHardwareDongleEmulation:
    """Test standalone activation function."""

    def test_activate_hardware_dongle_emulation_success(self) -> None:
        """Activate hardware dongle emulation function succeeds."""
        app = MagicMock()
        app.binary_path = None

        results = activate_hardware_dongle_emulation(app, ["HASP"])

        assert "success" in results
        assert "emulated_dongles" in results
        assert "methods_applied" in results


class TestDongleEmulationIntegration:
    """Integration tests for complete dongle emulation workflows."""

    def test_hasp_login_encrypt_decrypt_logout_workflow(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """Complete HASP workflow: login, encrypt, decrypt, logout."""
        dongle_emulator.activate_dongle_emulation(["HASP"])
        dongle = next(iter(dongle_emulator.hasp_dongles.values()))

        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        login_response = dongle_emulator._hasp_login(login_data)
        assert struct.unpack("<I", login_response[:4])[0] == HASPStatus.HASP_STATUS_OK

        plaintext = b"Sensitive license data"
        encrypt_data = struct.pack("<II", dongle.session_handle, len(plaintext)) + plaintext
        encrypt_response = dongle_emulator._hasp_encrypt_command(encrypt_data)
        assert struct.unpack("<I", encrypt_response[:4])[0] == HASPStatus.HASP_STATUS_OK

        ciphertext_len = struct.unpack("<I", encrypt_response[4:8])[0]
        ciphertext = encrypt_response[8:8+ciphertext_len]

        decrypt_data = struct.pack("<II", dongle.session_handle, len(ciphertext)) + ciphertext
        decrypt_response = dongle_emulator._hasp_decrypt_command(decrypt_data)
        assert struct.unpack("<I", decrypt_response[:4])[0] == HASPStatus.HASP_STATUS_OK

        decrypted_len = struct.unpack("<I", decrypt_response[4:8])[0]
        decrypted = decrypt_response[8:8+decrypted_len]
        assert decrypted == plaintext

        logout_data = struct.pack("<I", dongle.session_handle)
        logout_response = dongle_emulator._hasp_logout(logout_data)
        assert struct.unpack("<I", logout_response[:4])[0] == HASPStatus.HASP_STATUS_OK

    def test_sentinel_query_read_write_workflow(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """Complete Sentinel workflow: query, read, write."""
        dongle_emulator.activate_dongle_emulation(["Sentinel"])

        query_response = dongle_emulator._sentinel_query(b"")
        assert struct.unpack("<I", query_response[:4])[0] == SentinelStatus.SP_SUCCESS

        dongle = next(iter(dongle_emulator.sentinel_dongles.values()))
        test_data = b"CELL_DATA_TEST" + b"\x00" * 50
        write_data = struct.pack("<II", 7, len(test_data)) + test_data
        write_response = dongle_emulator._sentinel_write(write_data)
        assert struct.unpack("<I", write_response[:4])[0] == SentinelStatus.SP_SUCCESS

        read_data = struct.pack("<II", 7, 64)
        read_response = dongle_emulator._sentinel_read(read_data)
        assert struct.unpack("<I", read_response[:4])[0] == SentinelStatus.SP_SUCCESS

        read_back = bytes(dongle.response_buffer[:64])
        assert read_back[:14] == b"CELL_DATA_TEST"

    def test_wibukey_open_access_encrypt_workflow(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """Complete WibuKey workflow: open, access, encrypt."""
        dongle_emulator.activate_dongle_emulation(["CodeMeter"])
        dongle = next(iter(dongle_emulator.wibukey_dongles.values()))

        open_data = struct.pack("<II", dongle.firm_code, dongle.product_code)
        open_response = dongle_emulator._wibukey_open(open_data)
        assert struct.unpack("<I", open_response[:4])[0] == 0

        access_data = struct.pack("<III", dongle.container_handle, 1, 0)
        access_response = dongle_emulator._wibukey_access(access_data)
        assert struct.unpack("<I", access_response[:4])[0] == 0

        plaintext = b"Protected data"
        encrypt_data = struct.pack("<II", dongle.container_handle, len(plaintext)) + plaintext
        encrypt_response = dongle_emulator._wibukey_encrypt(encrypt_data)
        assert struct.unpack("<I", encrypt_response[:4])[0] == 0

        ciphertext_len = struct.unpack("<I", encrypt_response[4:8])[0]
        assert ciphertext_len > 0

    def test_multiple_dongle_types_simultaneous_emulation(self, dongle_emulator: HardwareDongleEmulator) -> None:
        """Multiple dongle types can be emulated simultaneously."""
        results = dongle_emulator.activate_dongle_emulation(["HASP", "Sentinel", "CodeMeter"])

        assert results["success"] is True
        assert len(dongle_emulator.hasp_dongles) > 0
        assert len(dongle_emulator.sentinel_dongles) > 0
        assert len(dongle_emulator.wibukey_dongles) > 0

        status = dongle_emulator.get_emulation_status()
        assert status["hasp_dongles"] > 0
        assert status["sentinel_dongles"] > 0
        assert status["wibukey_dongles"] > 0
