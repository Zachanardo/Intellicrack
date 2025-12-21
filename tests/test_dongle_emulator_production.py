"""Production-ready tests for Hardware Dongle Emulator.

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

import pytest

from intellicrack.core.protection_bypass.dongle_emulator import (
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

try:
    from Crypto.Cipher import AES, DES, DES3

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class TestUSBDescriptor:
    """Test USB device descriptor functionality."""

    def test_usb_descriptor_initialization_default_values(self) -> None:
        """USB descriptor initializes with correct USB 2.0 specification defaults."""
        descriptor = USBDescriptor()

        assert descriptor.bLength == 18
        assert descriptor.bDescriptorType == 1
        assert descriptor.bcdUSB == 0x0200
        assert descriptor.bDeviceClass == 0xFF
        assert descriptor.bDeviceSubClass == 0xFF
        assert descriptor.bDeviceProtocol == 0xFF
        assert descriptor.bMaxPacketSize0 == 64
        assert descriptor.idVendor == 0x0529
        assert descriptor.idProduct == 0x0001
        assert descriptor.bcdDevice == 0x0100
        assert descriptor.iManufacturer == 1
        assert descriptor.iProduct == 2
        assert descriptor.iSerialNumber == 3
        assert descriptor.bNumConfigurations == 1

    def test_usb_descriptor_serialization_matches_usb_spec_format(self) -> None:
        """USB descriptor serializes to correct binary format per USB 2.0 spec."""
        descriptor = USBDescriptor(
            idVendor=0x0529,
            idProduct=0x0001,
            bcdUSB=0x0200,
            bDeviceClass=0xFF,
        )

        serialized = descriptor.to_bytes()

        assert len(serialized) == 18
        unpacked = struct.unpack("<BBHBBBBHHHBBBB", serialized)
        assert unpacked[0] == 18
        assert unpacked[1] == 1
        assert unpacked[2] == 0x0200
        assert unpacked[3] == 0xFF
        assert unpacked[7] == 0x0529
        assert unpacked[8] == 0x0001

    def test_usb_descriptor_hasp_device_characteristics(self) -> None:
        """USB descriptor for HASP dongle uses correct vendor/product IDs."""
        hasp_descriptor = USBDescriptor(
            idVendor=0x0529,
            idProduct=0x0001,
            bDeviceClass=0xFF,
            bDeviceSubClass=0xFF,
        )

        serialized = hasp_descriptor.to_bytes()
        vendor_id = struct.unpack("<H", serialized[8:10])[0]
        product_id = struct.unpack("<H", serialized[10:12])[0]

        assert vendor_id == 0x0529
        assert product_id == 0x0001

    def test_usb_descriptor_wibukey_device_characteristics(self) -> None:
        """USB descriptor for WibuKey dongle uses correct vendor/product IDs."""
        wibu_descriptor = USBDescriptor(
            idVendor=0x064F,
            idProduct=0x0BD7,
            bDeviceClass=0x00,
        )

        serialized = wibu_descriptor.to_bytes()
        vendor_id = struct.unpack("<H", serialized[8:10])[0]
        product_id = struct.unpack("<H", serialized[10:12])[0]

        assert vendor_id == 0x064F
        assert product_id == 0x0BD7


class TestDongleMemory:
    """Test dongle memory operations with real bounds checking."""

    def test_dongle_memory_initialization_creates_correct_regions(self) -> None:
        """Dongle memory initializes with correct sizes for rom/ram/eeprom."""
        memory = DongleMemory()

        assert len(memory.rom) == 8192
        assert len(memory.ram) == 4096
        assert len(memory.eeprom) == 2048
        assert isinstance(memory.rom, bytearray)
        assert isinstance(memory.ram, bytearray)
        assert isinstance(memory.eeprom, bytearray)

    def test_memory_read_returns_correct_data_from_rom(self) -> None:
        """Memory read operation returns actual data from ROM region."""
        memory = DongleMemory()
        test_data = b"HASP_LICENSE_DATA_12345"
        memory.rom[100 : 100 + len(test_data)] = test_data

        result = memory.read("rom", 100, len(test_data))

        assert result == test_data
        assert isinstance(result, bytes)

    def test_memory_read_returns_correct_data_from_ram(self) -> None:
        """Memory read operation returns actual data from RAM region."""
        memory = DongleMemory()
        test_data = b"TEMP_SESSION_KEY_XYZ"
        memory.ram[50 : 50 + len(test_data)] = test_data

        result = memory.read("ram", 50, len(test_data))

        assert result == test_data

    def test_memory_read_returns_correct_data_from_eeprom(self) -> None:
        """Memory read operation returns actual data from EEPROM region."""
        memory = DongleMemory()
        test_data = b"PERSISTENT_CONFIG"
        memory.eeprom[200 : 200 + len(test_data)] = test_data

        result = memory.read("eeprom", 200, len(test_data))

        assert result == test_data

    def test_memory_read_raises_valueerror_on_bounds_violation(self) -> None:
        """Memory read beyond region bounds raises ValueError."""
        memory = DongleMemory()

        with pytest.raises(ValueError, match="Read beyond memory bounds"):
            memory.read("rom", 8000, 300)

    def test_memory_read_raises_valueerror_on_invalid_region(self) -> None:
        """Memory read from invalid region raises ValueError."""
        memory = DongleMemory()

        with pytest.raises(ValueError, match="Invalid memory region"):
            memory.read("invalid_region", 0, 10)

    def test_memory_write_stores_data_correctly_in_ram(self) -> None:
        """Memory write operation stores actual data in RAM region."""
        memory = DongleMemory()
        test_data = b"WRITE_TEST_DATA_123"

        memory.write("ram", 100, test_data)

        assert memory.ram[100 : 100 + len(test_data)] == test_data

    def test_memory_write_stores_data_correctly_in_eeprom(self) -> None:
        """Memory write operation stores actual data in EEPROM region."""
        memory = DongleMemory()
        test_data = b"EEPROM_DATA"

        memory.write("eeprom", 500, test_data)

        assert memory.eeprom[500 : 500 + len(test_data)] == test_data

    def test_memory_write_raises_permissionerror_for_readonly_areas(self) -> None:
        """Memory write to read-only area raises PermissionError."""
        memory = DongleMemory()
        memory.read_only_areas = [(0, 512)]

        with pytest.raises(PermissionError, match="Cannot write to read-only area"):
            memory.write("rom", 100, b"SHOULD_FAIL")

    def test_memory_write_raises_valueerror_on_bounds_violation(self) -> None:
        """Memory write beyond region bounds raises ValueError."""
        memory = DongleMemory()

        with pytest.raises(ValueError, match="Write beyond memory bounds"):
            memory.write("eeprom", 2000, b"X" * 100)

    def test_memory_write_raises_valueerror_on_invalid_region(self) -> None:
        """Memory write to invalid region raises ValueError."""
        memory = DongleMemory()

        with pytest.raises(ValueError, match="Invalid memory region"):
            memory.write("badregion", 0, b"test")

    def test_memory_protected_areas_detection_works_correctly(self) -> None:
        """Protected area detection identifies ranges correctly."""
        memory = DongleMemory()
        memory.protected_areas = [(100, 200), (500, 600)]

        assert memory.is_protected(150, 20) is True
        assert memory.is_protected(550, 30) is True
        assert memory.is_protected(300, 50) is False
        assert memory.is_protected(0, 50) is False

    def test_memory_read_write_roundtrip_preserves_data(self) -> None:
        """Read after write returns exact data that was written."""
        memory = DongleMemory()
        original_data = os.urandom(128)

        memory.write("ram", 1000, original_data)
        retrieved_data = memory.read("ram", 1000, 128)

        assert retrieved_data == original_data


class TestHASPDongle:
    """Test HASP dongle dataclass initialization and crypto setup."""

    def test_hasp_dongle_initialization_creates_valid_structure(self) -> None:
        """HASP dongle initializes with all required fields."""
        dongle = HASPDongle()

        assert dongle.hasp_id == 0x12345678
        assert dongle.vendor_code == 0x1234
        assert dongle.feature_id == 1
        assert len(dongle.seed_code) == 16
        assert isinstance(dongle.memory, DongleMemory)
        assert dongle.logged_in is False
        assert len(dongle.aes_key) == 32
        assert len(dongle.des_key) == 24
        assert len(dongle.license_data) == 512

    def test_hasp_dongle_feature_map_initialization(self) -> None:
        """HASP dongle feature map contains valid license structure."""
        dongle = HASPDongle()

        assert 1 in dongle.feature_map
        feature = dongle.feature_map[1]
        assert feature["id"] == 1
        assert feature["type"] == "license"
        assert feature["expiration"] == 0xFFFFFFFF
        assert feature["max_users"] == 10
        assert feature["current_users"] == 0

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_hasp_dongle_rsa_key_generation_when_crypto_available(self) -> None:
        """HASP dongle generates valid RSA key when crypto library available."""
        dongle = HASPDongle()

        assert dongle.rsa_key is not None
        assert dongle.rsa_key.has_private()
        assert dongle.rsa_key.size_in_bits() == 2048

    def test_hasp_dongle_custom_initialization_values(self) -> None:
        """HASP dongle accepts custom initialization values."""
        custom_seed = os.urandom(16)
        custom_aes = os.urandom(32)

        dongle = HASPDongle(
            hasp_id=0xABCDEF00,
            vendor_code=0x9999,
            feature_id=42,
            seed_code=custom_seed,
            aes_key=custom_aes,
        )

        assert dongle.hasp_id == 0xABCDEF00
        assert dongle.vendor_code == 0x9999
        assert dongle.feature_id == 42
        assert dongle.seed_code == custom_seed
        assert dongle.aes_key == custom_aes


class TestSentinelDongle:
    """Test Sentinel dongle dataclass initialization."""

    def test_sentinel_dongle_initialization_creates_valid_structure(self) -> None:
        """Sentinel dongle initializes with all required fields."""
        dongle = SentinelDongle()

        assert dongle.device_id == 0x87654321
        assert dongle.vendor_id == 0x0529
        assert dongle.product_id == 0x0001
        assert dongle.serial_number == "SN123456789ABCDEF"
        assert dongle.firmware_version == "8.0.0"
        assert isinstance(dongle.memory, DongleMemory)
        assert "AES" in dongle.algorithms
        assert "RSA" in dongle.algorithms
        assert len(dongle.aes_key) == 32
        assert len(dongle.des_key) == 24

    def test_sentinel_dongle_cell_data_initialization(self) -> None:
        """Sentinel dongle initializes cell data for all cells."""
        dongle = SentinelDongle()

        assert len(dongle.cell_data) == 8
        for i in range(8):
            assert i in dongle.cell_data
            assert len(dongle.cell_data[i]) == 64

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_sentinel_dongle_rsa_key_generation_when_crypto_available(self) -> None:
        """Sentinel dongle generates valid RSA key when crypto library available."""
        dongle = SentinelDongle()

        assert dongle.rsa_key is not None
        assert dongle.rsa_key.has_private()
        assert dongle.rsa_key.size_in_bits() == 2048

    def test_sentinel_dongle_custom_initialization_values(self) -> None:
        """Sentinel dongle accepts custom initialization values."""
        dongle = SentinelDongle(
            device_id=0x11223344,
            vendor_id=0x1234,
            serial_number="CUSTOM_SN_12345",
            firmware_version="9.1.2",
        )

        assert dongle.device_id == 0x11223344
        assert dongle.vendor_id == 0x1234
        assert dongle.serial_number == "CUSTOM_SN_12345"
        assert dongle.firmware_version == "9.1.2"


class TestWibuKeyDongle:
    """Test WibuKey/CodeMeter dongle dataclass initialization."""

    def test_wibukey_dongle_initialization_creates_valid_structure(self) -> None:
        """WibuKey dongle initializes with all required fields."""
        dongle = WibuKeyDongle()

        assert dongle.firm_code == 101
        assert dongle.product_code == 1000
        assert dongle.feature_code == 1
        assert dongle.serial_number == 1000001
        assert dongle.version == "6.90"
        assert isinstance(dongle.memory, DongleMemory)
        assert len(dongle.user_data) == 4096
        assert dongle.container_handle == 0x12345678
        assert len(dongle.aes_key) == 32
        assert len(dongle.challenge_response_key) == 16

    def test_wibukey_dongle_license_entries_initialization(self) -> None:
        """WibuKey dongle initializes license entries correctly."""
        dongle = WibuKeyDongle()

        assert 1 in dongle.license_entries
        entry = dongle.license_entries[1]
        assert entry["firm_code"] == 101
        assert entry["product_code"] == 1000
        assert entry["feature_code"] == 1
        assert entry["quantity"] == 100
        assert entry["expiration"] == 0xFFFFFFFF
        assert entry["enabled"] is True

    def test_wibukey_dongle_custom_initialization_values(self) -> None:
        """WibuKey dongle accepts custom initialization values."""
        dongle = WibuKeyDongle(
            firm_code=999,
            product_code=5555,
            feature_code=77,
            serial_number=8888888,
            version="7.10",
        )

        assert dongle.firm_code == 999
        assert dongle.product_code == 5555
        assert dongle.feature_code == 77
        assert dongle.serial_number == 8888888
        assert dongle.version == "7.10"


class TestUSBEmulator:
    """Test USB device emulation for dongles."""

    def test_usb_emulator_initialization_creates_endpoints(self) -> None:
        """USB emulator initializes with standard endpoint configuration."""
        descriptor = USBDescriptor()
        emulator = USBEmulator(descriptor)

        assert emulator.descriptor == descriptor
        assert 0x00 in emulator.endpoints
        assert 0x81 in emulator.endpoints
        assert 0x02 in emulator.endpoints
        assert 0x83 in emulator.endpoints
        assert emulator.endpoints[0x00]["type"] == "control"
        assert emulator.endpoints[0x81]["type"] == "bulk"
        assert emulator.endpoints[0x02]["type"] == "bulk"
        assert emulator.endpoints[0x83]["type"] == "interrupt"

    def test_usb_emulator_control_transfer_returns_device_descriptor(self) -> None:
        """USB control transfer returns valid device descriptor."""
        descriptor = USBDescriptor(idVendor=0x0529, idProduct=0x0001)
        emulator = USBEmulator(descriptor)

        bRequest = 0x06
        wValue = 0x0100
        result = emulator.control_transfer(0x80, bRequest, wValue, 0, b"")

        assert len(result) == 18
        assert result == descriptor.to_bytes()

    def test_usb_emulator_control_transfer_returns_configuration_descriptor(self) -> None:
        """USB control transfer returns valid configuration descriptor."""
        descriptor = USBDescriptor()
        emulator = USBEmulator(descriptor)

        bRequest = 0x06
        wValue = 0x0200
        result = emulator.control_transfer(0x80, bRequest, wValue, 0, b"")

        assert len(result) > 0
        assert result[0] == 9
        assert result[1] == 2
        config_length = struct.unpack("<H", result[2:4])[0]
        assert config_length > 0

    def test_usb_emulator_control_transfer_returns_string_descriptor(self) -> None:
        """USB control transfer returns valid string descriptors."""
        descriptor = USBDescriptor()
        emulator = USBEmulator(descriptor)

        bRequest = 0x06
        wValue = 0x0301
        result = emulator.control_transfer(0x80, bRequest, wValue, 0, b"")

        assert len(result) > 0
        assert result[1] == 3

    def test_usb_emulator_register_control_handler_works_correctly(self) -> None:
        """Registered control handler gets invoked for matching requests."""
        descriptor = USBDescriptor()
        emulator = USBEmulator(descriptor)
        handler_called = []

        def test_handler(wValue: int, wIndex: int, data: bytes) -> bytes:
            handler_called.append((wValue, wIndex, data))
            return b"HANDLER_RESPONSE"

        emulator.register_control_handler(0x40, 0x01, test_handler)
        result = emulator.control_transfer(0x40, 0x01, 100, 200, b"TEST")

        assert len(handler_called) == 1
        assert handler_called[0] == (100, 200, b"TEST")
        assert result == b"HANDLER_RESPONSE"

    def test_usb_emulator_register_bulk_handler_works_correctly(self) -> None:
        """Registered bulk handler gets invoked for matching endpoint."""
        descriptor = USBDescriptor()
        emulator = USBEmulator(descriptor)
        handler_called = []

        def test_handler(data: bytes) -> bytes:
            handler_called.append(data)
            return b"BULK_RESPONSE"

        emulator.register_bulk_handler(0x02, test_handler)
        result = emulator.bulk_transfer(0x02, b"BULK_DATA")

        assert len(handler_called) == 1
        assert handler_called[0] == b"BULK_DATA"
        assert result == b"BULK_RESPONSE"


class TestCryptoEngine:
    """Test cryptographic operations for dongle emulation."""

    def test_crypto_engine_initialization(self) -> None:
        """Crypto engine initializes successfully."""
        engine = CryptoEngine()

        assert engine is not None
        assert hasattr(engine, "hasp_encrypt")
        assert hasattr(engine, "hasp_decrypt")

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_hasp_encrypt_aes_produces_ciphertext(self) -> None:
        """HASP AES encryption produces valid ciphertext."""
        engine = CryptoEngine()
        key = os.urandom(32)
        plaintext = b"SECRET_LICENSE_DATA_123456"

        ciphertext = engine.hasp_encrypt(plaintext, key, "AES")

        assert ciphertext != plaintext
        assert len(ciphertext) >= len(plaintext)
        assert len(ciphertext) % 16 == 0

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_hasp_decrypt_aes_recovers_plaintext(self) -> None:
        """HASP AES decryption recovers original plaintext."""
        engine = CryptoEngine()
        key = os.urandom(32)
        plaintext = b"LICENSE_KEY_DATA"

        ciphertext = engine.hasp_encrypt(plaintext, key, "AES")
        decrypted = engine.hasp_decrypt(ciphertext, key, "AES")

        assert decrypted == plaintext

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_hasp_encrypt_des_produces_ciphertext(self) -> None:
        """HASP DES encryption produces valid ciphertext."""
        engine = CryptoEngine()
        key = os.urandom(24)
        plaintext = b"TESTDATA"

        ciphertext = engine.hasp_encrypt(plaintext, key, "DES")

        assert ciphertext != plaintext
        assert len(ciphertext) % 8 == 0

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_hasp_decrypt_des_recovers_plaintext(self) -> None:
        """HASP DES decryption recovers original plaintext."""
        engine = CryptoEngine()
        key = os.urandom(24)
        plaintext = b"SECRET12"

        ciphertext = engine.hasp_encrypt(plaintext, key, "DES")
        decrypted = engine.hasp_decrypt(ciphertext, key, "DES")

        assert decrypted == plaintext

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_hasp_encrypt_des3_produces_ciphertext(self) -> None:
        """HASP DES3 encryption produces valid ciphertext."""
        engine = CryptoEngine()
        key = os.urandom(24)
        plaintext = b"CONFIDENTIAL_DATA_XYZ"

        ciphertext = engine.hasp_encrypt(plaintext, key, "DES3")

        assert ciphertext != plaintext
        assert len(ciphertext) % 8 == 0

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_hasp_decrypt_des3_recovers_plaintext(self) -> None:
        """HASP DES3 decryption recovers original plaintext."""
        engine = CryptoEngine()
        key = os.urandom(24)
        plaintext = b"LICENSE_INFO"

        ciphertext = engine.hasp_encrypt(plaintext, key, "DES3")
        decrypted = engine.hasp_decrypt(ciphertext, key, "DES3")

        assert decrypted == plaintext

    def test_hasp_encrypt_fallback_when_crypto_unavailable(self) -> None:
        """HASP encryption falls back to XOR when crypto unavailable."""
        engine = CryptoEngine()
        key = b"testkey123456789"
        plaintext = b"testdata"

        result = engine.hasp_encrypt(plaintext, key, "UNKNOWN")

        assert result != plaintext
        assert len(result) == len(plaintext)

    def test_sentinel_challenge_response_produces_valid_response(self) -> None:
        """Sentinel challenge-response produces deterministic response."""
        engine = CryptoEngine()
        challenge = os.urandom(32)
        key = os.urandom(32)

        response1 = engine.sentinel_challenge_response(challenge, key)
        response2 = engine.sentinel_challenge_response(challenge, key)

        assert response1 == response2
        assert len(response1) == 16
        assert isinstance(response1, bytes)

    def test_sentinel_challenge_response_changes_with_different_challenge(self) -> None:
        """Sentinel challenge-response changes when challenge changes."""
        engine = CryptoEngine()
        challenge1 = os.urandom(32)
        challenge2 = os.urandom(32)
        key = os.urandom(32)

        response1 = engine.sentinel_challenge_response(challenge1, key)
        response2 = engine.sentinel_challenge_response(challenge2, key)

        assert response1 != response2

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_wibukey_challenge_response_produces_valid_response(self) -> None:
        """WibuKey challenge-response produces valid encrypted response."""
        engine = CryptoEngine()
        challenge = os.urandom(16)
        key = os.urandom(16)

        response = engine.wibukey_challenge_response(challenge, key)

        assert len(response) == 16
        assert isinstance(response, bytes)

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_wibukey_challenge_response_deterministic_for_same_inputs(self) -> None:
        """WibuKey challenge-response is deterministic for same inputs."""
        engine = CryptoEngine()
        challenge = os.urandom(16)
        key = os.urandom(16)

        response1 = engine.wibukey_challenge_response(challenge, key)
        response2 = engine.wibukey_challenge_response(challenge, key)

        assert response1 == response2

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_rsa_sign_produces_valid_signature(self) -> None:
        """RSA signing produces valid signature."""
        from Crypto.PublicKey import RSA

        engine = CryptoEngine()
        key = RSA.generate(2048)
        data = b"DATA_TO_SIGN"

        signature = engine.rsa_sign(data, key)

        assert len(signature) > 0
        assert isinstance(signature, bytes)


class TestHardwareDongleEmulator:
    """Test main hardware dongle emulator functionality."""

    def test_emulator_initialization_without_app(self) -> None:
        """Emulator initializes successfully without app instance."""
        emulator = HardwareDongleEmulator()

        assert emulator.app is None
        assert isinstance(emulator.crypto_engine, CryptoEngine)
        assert len(emulator.virtual_dongles) == 0
        assert len(emulator.hasp_dongles) == 0
        assert len(emulator.sentinel_dongles) == 0
        assert len(emulator.wibukey_dongles) == 0

    def test_emulator_initialization_with_app(self) -> None:
        """Emulator initializes successfully with app instance."""

        class MockApp:
            binary_path: str | None = None

        app = MockApp()
        emulator = HardwareDongleEmulator(app)

        assert emulator.app == app
        assert isinstance(emulator.crypto_engine, CryptoEngine)

    def test_activate_dongle_emulation_creates_hasp_dongle(self) -> None:
        """Activating HASP emulation creates functional HASP dongle."""
        emulator = HardwareDongleEmulator()

        result = emulator.activate_dongle_emulation(["HASP"])

        assert result["success"] is True
        assert len(emulator.hasp_dongles) == 1
        assert "Virtual Dongle Creation" in result["methods_applied"]
        assert any("HASP" in name for name in emulator.virtual_dongles.keys())

    def test_activate_dongle_emulation_creates_sentinel_dongle(self) -> None:
        """Activating Sentinel emulation creates functional Sentinel dongle."""
        emulator = HardwareDongleEmulator()

        result = emulator.activate_dongle_emulation(["Sentinel"])

        assert result["success"] is True
        assert len(emulator.sentinel_dongles) == 1
        assert any("Sentinel" in name for name in emulator.virtual_dongles.keys())

    def test_activate_dongle_emulation_creates_codemeter_dongle(self) -> None:
        """Activating CodeMeter emulation creates functional WibuKey dongle."""
        emulator = HardwareDongleEmulator()

        result = emulator.activate_dongle_emulation(["CodeMeter"])

        assert result["success"] is True
        assert len(emulator.wibukey_dongles) == 1
        assert any("WibuKey" in name for name in emulator.virtual_dongles.keys())

    def test_activate_dongle_emulation_creates_multiple_dongles(self) -> None:
        """Activating multiple dongle types creates all requested dongles."""
        emulator = HardwareDongleEmulator()

        result = emulator.activate_dongle_emulation(["HASP", "Sentinel", "CodeMeter"])

        assert result["success"] is True
        assert len(emulator.hasp_dongles) >= 1
        assert len(emulator.sentinel_dongles) >= 1
        assert len(emulator.wibukey_dongles) >= 1
        assert len(emulator.virtual_dongles) >= 3

    def test_activate_dongle_emulation_sets_up_usb_emulation(self) -> None:
        """Dongle activation sets up USB device emulation."""
        emulator = HardwareDongleEmulator()

        result = emulator.activate_dongle_emulation(["HASP"])

        assert "USB Device Emulation" in result["methods_applied"]
        assert len(emulator.usb_emulators) > 0

    def test_hasp_dongle_has_protected_memory_areas(self) -> None:
        """Created HASP dongle has protected memory areas configured."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        dongle = next(iter(emulator.hasp_dongles.values()))

        assert len(dongle.memory.protected_areas) > 0
        assert len(dongle.memory.read_only_areas) > 0
        assert dongle.memory.protected_areas[0] == (0, 1024)
        assert dongle.memory.read_only_areas[0] == (0, 512)

    def test_hasp_dongle_has_license_data_initialized(self) -> None:
        """Created HASP dongle has license data structure initialized."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        dongle = next(iter(emulator.hasp_dongles.values()))
        license_info = dongle.license_data[:16]

        assert len(license_info) == 16
        unpacked = struct.unpack("<IIII", license_info)
        assert unpacked[0] == dongle.feature_id
        assert unpacked[1] == 0xFFFFFFFF

    def test_process_hasp_challenge_produces_valid_response(self) -> None:
        """HASP challenge processing produces valid cryptographic response."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        challenge = os.urandom(32)
        response = emulator.process_hasp_challenge(challenge, 1)

        assert len(response) > 0
        assert response != challenge
        assert isinstance(response, bytes)

    def test_process_hasp_challenge_deterministic_for_same_challenge(self) -> None:
        """HASP challenge response is deterministic for same challenge."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        challenge = os.urandom(32)
        response1 = emulator.process_hasp_challenge(challenge, 1)
        response2 = emulator.process_hasp_challenge(challenge, 1)

        assert response1 == response2

    def test_read_dongle_memory_hasp_returns_correct_data(self) -> None:
        """Reading HASP dongle memory returns actual stored data."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        test_data = b"HASP_TEST_DATA_123"
        emulator.hasp_dongles[1].memory.ram[100 : 100 + len(test_data)] = test_data

        result = emulator.read_dongle_memory("HASP", 1, "ram", 100, len(test_data))

        assert result == test_data

    def test_write_dongle_memory_hasp_stores_data_correctly(self) -> None:
        """Writing HASP dongle memory stores data successfully."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        test_data = b"WRITE_TEST_12345"
        success = emulator.write_dongle_memory("HASP", 1, "ram", 200, test_data)

        assert success is True
        stored = emulator.hasp_dongles[1].memory.ram[200 : 200 + len(test_data)]
        assert stored == test_data

    def test_read_dongle_memory_sentinel_returns_correct_data(self) -> None:
        """Reading Sentinel dongle memory returns actual stored data."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        test_data = b"SENTINEL_DATA"
        emulator.sentinel_dongles[1].memory.eeprom[50 : 50 + len(test_data)] = test_data

        result = emulator.read_dongle_memory("SENTINEL", 1, "eeprom", 50, len(test_data))

        assert result == test_data

    def test_write_dongle_memory_wibukey_stores_data_correctly(self) -> None:
        """Writing WibuKey dongle memory stores data successfully."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["CodeMeter"])

        test_data = b"WIBU_DATA_XYZ"
        success = emulator.write_dongle_memory("WIBUKEY", 1, "ram", 300, test_data)

        assert success is True
        stored = emulator.wibukey_dongles[1].memory.ram[300 : 300 + len(test_data)]
        assert stored == test_data

    def test_get_emulation_status_returns_correct_information(self) -> None:
        """Emulation status returns accurate dongle and hook information."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP", "CodeMeter"])

        status = emulator.get_emulation_status()

        assert "hooks_installed" in status
        assert "patches_identified" in status
        assert "virtual_dongles_active" in status
        assert status["hasp_dongles"] == 1
        assert status["wibukey_dongles"] == 1
        assert "crypto_available" in status

    def test_clear_emulation_removes_all_dongles(self) -> None:
        """Clear emulation removes all virtual dongles and hooks."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP", "Sentinel", "CodeMeter"])

        emulator.clear_emulation()

        assert len(emulator.virtual_dongles) == 0
        assert len(emulator.hasp_dongles) == 0
        assert len(emulator.sentinel_dongles) == 0
        assert len(emulator.wibukey_dongles) == 0
        assert len(emulator.hooks) == 0
        assert len(emulator.patches) == 0
        assert len(emulator.usb_emulators) == 0


class TestHASPProtocol:
    """Test HASP protocol implementation with USB handlers."""

    def test_hasp_control_handler_returns_dongle_id(self) -> None:
        """HASP control handler returns valid dongle ID."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        response = emulator._hasp_control_handler(1, 0, b"")

        assert len(response) >= 4
        hasp_id = struct.unpack("<I", response[:4])[0]
        dongle = next(iter(emulator.hasp_dongles.values()))
        assert hasp_id == dongle.hasp_id

    def test_hasp_control_handler_returns_vendor_and_feature_codes(self) -> None:
        """HASP control handler returns vendor and feature codes."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        response = emulator._hasp_control_handler(2, 0, b"")

        vendor_code, feature_id = struct.unpack("<HH", response[:4])
        dongle = next(iter(emulator.hasp_dongles.values()))
        assert vendor_code == dongle.vendor_code
        assert feature_id == dongle.feature_id

    def test_hasp_control_handler_returns_seed_code(self) -> None:
        """HASP control handler returns seed code."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])
        dongle = next(iter(emulator.hasp_dongles.values()))

        response = emulator._hasp_control_handler(3, 0, b"")

        assert response[:16] == dongle.seed_code

    def test_hasp_login_with_valid_credentials_succeeds(self) -> None:
        """HASP login with valid vendor code succeeds."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])
        dongle = next(iter(emulator.hasp_dongles.values()))

        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        response = emulator._hasp_login(login_data)

        status, session_handle = struct.unpack("<II", response[:8])
        assert status == HASPStatus.HASP_STATUS_OK
        assert session_handle == dongle.session_handle
        assert dongle.logged_in is True

    def test_hasp_login_with_invalid_vendor_code_fails(self) -> None:
        """HASP login with invalid vendor code fails."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        login_data = struct.pack("<HH", 0xFFFF, 1)
        response = emulator._hasp_login(login_data)

        status = struct.unpack("<I", response[:4])[0]
        assert status == HASPStatus.HASP_KEYNOTFOUND

    def test_hasp_logout_with_valid_session_succeeds(self) -> None:
        """HASP logout with valid session handle succeeds."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])
        dongle = next(iter(emulator.hasp_dongles.values()))

        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        emulator._hasp_login(login_data)

        logout_data = struct.pack("<I", dongle.session_handle)
        response = emulator._hasp_logout(logout_data)

        status = struct.unpack("<I", response[:4])[0]
        assert status == HASPStatus.HASP_STATUS_OK
        assert dongle.logged_in is False

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_hasp_encrypt_command_produces_ciphertext(self) -> None:
        """HASP encrypt command produces valid ciphertext."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])
        dongle = next(iter(emulator.hasp_dongles.values()))

        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        emulator._hasp_login(login_data)

        plaintext = b"ENCRYPT_ME_12345"
        encrypt_data = struct.pack("<II", dongle.session_handle, len(plaintext)) + plaintext
        response = emulator._hasp_encrypt_command(encrypt_data)

        status, ciphertext_len = struct.unpack("<II", response[:8])
        assert status == HASPStatus.HASP_STATUS_OK
        assert ciphertext_len > 0
        ciphertext = response[8 : 8 + ciphertext_len]
        assert ciphertext != plaintext

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_hasp_decrypt_command_recovers_plaintext(self) -> None:
        """HASP decrypt command recovers original plaintext."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])
        dongle = next(iter(emulator.hasp_dongles.values()))

        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        emulator._hasp_login(login_data)

        plaintext = b"SECRET_DATA_1234"
        encrypt_data = struct.pack("<II", dongle.session_handle, len(plaintext)) + plaintext
        encrypt_response = emulator._hasp_encrypt_command(encrypt_data)
        _status, ciphertext_len = struct.unpack("<II", encrypt_response[:8])
        ciphertext = encrypt_response[8 : 8 + ciphertext_len]

        decrypt_data = struct.pack("<II", dongle.session_handle, len(ciphertext)) + ciphertext
        decrypt_response = emulator._hasp_decrypt_command(decrypt_data)

        status, plaintext_len = struct.unpack("<II", decrypt_response[:8])
        recovered = decrypt_response[8 : 8 + plaintext_len]
        assert status == HASPStatus.HASP_STATUS_OK
        assert recovered == plaintext

    def test_hasp_read_memory_returns_stored_data(self) -> None:
        """HASP memory read returns actual stored data from dongle."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])
        dongle = next(iter(emulator.hasp_dongles.values()))

        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        emulator._hasp_login(login_data)

        test_data = b"MEMORY_CONTENT_XYZ"
        dongle.memory.eeprom[100 : 100 + len(test_data)] = test_data

        read_data = struct.pack("<III", dongle.session_handle, 100, len(test_data))
        response = emulator._hasp_read_memory(read_data)

        status, data_len = struct.unpack("<II", response[:8])
        retrieved = response[8 : 8 + data_len]
        assert status == HASPStatus.HASP_STATUS_OK
        assert retrieved == test_data

    def test_hasp_write_memory_stores_data_correctly(self) -> None:
        """HASP memory write stores data in dongle memory."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])
        dongle = next(iter(emulator.hasp_dongles.values()))

        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        emulator._hasp_login(login_data)

        test_data = b"WRITE_DATA_ABC"
        write_request = struct.pack("<III", dongle.session_handle, 200, len(test_data)) + test_data
        response = emulator._hasp_write_memory(write_request)

        status = struct.unpack("<I", response[:4])[0]
        assert status == HASPStatus.HASP_STATUS_OK
        stored = dongle.memory.eeprom[200 : 200 + len(test_data)]
        assert stored == test_data


class TestSentinelProtocol:
    """Test Sentinel protocol implementation with USB handlers."""

    def test_sentinel_control_handler_returns_device_id(self) -> None:
        """Sentinel control handler returns valid device ID."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        response = emulator._sentinel_control_handler(1, 0, b"")

        device_id = struct.unpack("<I", response[:4])[0]
        dongle = next(iter(emulator.sentinel_dongles.values()))
        assert device_id == dongle.device_id

    def test_sentinel_control_handler_returns_serial_number(self) -> None:
        """Sentinel control handler returns serial number truncated to 16 chars."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])
        dongle = next(iter(emulator.sentinel_dongles.values()))

        response = emulator._sentinel_control_handler(2, 0, b"")

        assert len(response) >= 16
        serial_number = response[:16].rstrip(b"\x00").decode("ascii")
        assert serial_number == dongle.serial_number[:16]

    def test_sentinel_control_handler_returns_firmware_version(self) -> None:
        """Sentinel control handler returns firmware version."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])
        dongle = next(iter(emulator.sentinel_dongles.values()))

        response = emulator._sentinel_control_handler(3, 0, b"")

        firmware = response[:16].rstrip(b"\x00").decode("ascii")
        assert firmware == dongle.firmware_version

    def test_sentinel_query_returns_device_information(self) -> None:
        """Sentinel query operation returns complete device information."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])
        dongle = next(iter(emulator.sentinel_dongles.values()))

        response = emulator._sentinel_query(b"")

        status = struct.unpack("<I", response[:4])[0]
        assert status == SentinelStatus.SP_SUCCESS
        query_data = bytes(dongle.response_buffer[:52])
        device_id = struct.unpack("<I", query_data[:4])[0]
        assert device_id == dongle.device_id

    def test_sentinel_read_returns_cell_data(self) -> None:
        """Sentinel read operation returns actual cell data."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])
        dongle = next(iter(emulator.sentinel_dongles.values()))

        read_request = struct.pack("<II", 0, 32)
        response = emulator._sentinel_read(read_request)

        status = struct.unpack("<I", response[:4])[0]
        assert status == SentinelStatus.SP_SUCCESS
        cell_data = bytes(dongle.response_buffer[:32])
        assert len(cell_data) == 32
        assert cell_data == dongle.cell_data[0][:32]

    def test_sentinel_write_stores_cell_data(self) -> None:
        """Sentinel write operation stores data in cell."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])
        dongle = next(iter(emulator.sentinel_dongles.values()))

        test_data = b"SENTINEL_CELL_DATA_123"
        write_request = struct.pack("<II", 5, len(test_data)) + test_data
        response = emulator._sentinel_write(write_request)

        status = struct.unpack("<I", response[:4])[0]
        assert status == SentinelStatus.SP_SUCCESS
        assert dongle.cell_data[5][: len(test_data)] == test_data

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_sentinel_encrypt_produces_ciphertext(self) -> None:
        """Sentinel encrypt operation produces valid ciphertext."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])
        dongle = next(iter(emulator.sentinel_dongles.values()))

        plaintext = b"ENCRYPT_THIS_DATA"
        encrypt_request = struct.pack("<I", len(plaintext)) + plaintext
        response = emulator._sentinel_encrypt(encrypt_request)

        status = struct.unpack("<I", response[:4])[0]
        assert status == SentinelStatus.SP_SUCCESS
        ciphertext = bytes(dongle.response_buffer[: len(plaintext) + 16])
        assert ciphertext


class TestWibuKeyProtocol:
    """Test WibuKey/CodeMeter protocol implementation with USB handlers."""

    def test_wibukey_control_handler_returns_device_codes(self) -> None:
        """WibuKey control handler returns firm/product/serial codes."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["CodeMeter"])

        response = emulator._wibukey_control_handler(1, 0, b"")

        firm_code, product_code, serial_number = struct.unpack("<III", response[:12])
        dongle = next(iter(emulator.wibukey_dongles.values()))
        assert firm_code == dongle.firm_code
        assert product_code == dongle.product_code
        assert serial_number == dongle.serial_number

    def test_wibukey_control_handler_returns_version(self) -> None:
        """WibuKey control handler returns version string."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["CodeMeter"])
        dongle = next(iter(emulator.wibukey_dongles.values()))

        response = emulator._wibukey_control_handler(2, 0, b"")

        version = response[:16].rstrip(b"\x00").decode("ascii")
        assert version == dongle.version

    def test_wibukey_open_with_valid_codes_succeeds(self) -> None:
        """WibuKey open operation with valid codes succeeds."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["CodeMeter"])
        dongle = next(iter(emulator.wibukey_dongles.values()))

        open_request = struct.pack("<II", dongle.firm_code, dongle.product_code)
        response = emulator._wibukey_open(open_request)

        status, handle = struct.unpack("<II", response[:8])
        assert status == 0
        assert handle == dongle.container_handle

    def test_wibukey_open_with_invalid_codes_fails(self) -> None:
        """WibuKey open operation with invalid codes fails."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["CodeMeter"])

        open_request = struct.pack("<II", 9999, 9999)
        response = emulator._wibukey_open(open_request)

        status = struct.unpack("<I", response[:4])[0]
        assert status == 1

    def test_wibukey_access_with_valid_feature_succeeds(self) -> None:
        """WibuKey access operation with valid feature code succeeds."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["CodeMeter"])
        dongle = next(iter(emulator.wibukey_dongles.values()))

        access_request = struct.pack("<III", dongle.container_handle, 1, 0)
        response = emulator._wibukey_access(access_request)

        status = struct.unpack("<I", response[:4])[0]
        assert status == 0
        assert 1 in dongle.active_licenses

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_wibukey_encrypt_produces_ciphertext(self) -> None:
        """WibuKey encrypt operation produces valid ciphertext."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["CodeMeter"])
        dongle = next(iter(emulator.wibukey_dongles.values()))

        plaintext = b"WIBUKEY_DATA_123"
        encrypt_request = struct.pack("<II", dongle.container_handle, len(plaintext)) + plaintext
        response = emulator._wibukey_encrypt(encrypt_request)

        status, ciphertext_len = struct.unpack("<II", response[:8])
        ciphertext = response[8 : 8 + ciphertext_len]
        assert status == 0
        assert len(ciphertext) > 0
        assert ciphertext != plaintext

    def test_wibukey_challenge_produces_valid_response(self) -> None:
        """WibuKey challenge-response produces valid response."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["CodeMeter"])
        dongle = next(iter(emulator.wibukey_dongles.values()))

        challenge = os.urandom(16)
        challenge_request = struct.pack("<II", dongle.container_handle, len(challenge)) + challenge
        response = emulator._wibukey_challenge(challenge_request)

        status, response_len = struct.unpack("<II", response[:8])
        challenge_response = response[8 : 8 + response_len]
        assert status == 0
        assert len(challenge_response) == 16


class TestActivateHardwareDongleEmulation:
    """Test top-level activation function."""

    def test_activate_hardware_dongle_emulation_without_app(self) -> None:
        """Activation function works without app instance."""

        class MockApp:
            binary_path: str | None = None

        result = activate_hardware_dongle_emulation(MockApp(), ["HASP"])

        assert result["success"] is True
        assert len(result["emulated_dongles"]) > 0

    def test_activate_hardware_dongle_emulation_with_multiple_types(self) -> None:
        """Activation function creates multiple dongle types."""

        class MockApp:
            binary_path: str | None = None

        result = activate_hardware_dongle_emulation(
            MockApp(),
            ["HASP", "Sentinel", "CodeMeter"],
        )

        assert result["success"] is True
        assert len(result["emulated_dongles"]) >= 3


class TestDongleTypeEnum:
    """Test DongleType enumeration."""

    def test_dongle_type_enum_values(self) -> None:
        """DongleType enum has all expected values."""
        assert DongleType.HASP == 1
        assert DongleType.SENTINEL == 2
        assert DongleType.WIBUKEY == 3
        assert DongleType.SAFENET == 4
        assert DongleType.SUPERPRO == 5
        assert DongleType.ROCKEY == 6
        assert DongleType.DINKEY == 7


class TestHASPStatusEnum:
    """Test HASP status code enumeration."""

    def test_hasp_status_enum_values(self) -> None:
        """HASPStatus enum has all expected status codes."""
        assert HASPStatus.HASP_STATUS_OK == 0
        assert HASPStatus.HASP_MEM_RANGE == 1
        assert HASPStatus.HASP_TOO_SHORT == 2
        assert HASPStatus.HASP_INV_HND == 3
        assert HASPStatus.HASP_KEYNOTFOUND == 7


class TestSentinelStatusEnum:
    """Test Sentinel status code enumeration."""

    def test_sentinel_status_enum_values(self) -> None:
        """SentinelStatus enum has all expected status codes."""
        assert SentinelStatus.SP_SUCCESS == 0
        assert SentinelStatus.SP_INVALID_FUNCTION_CODE == 1
        assert SentinelStatus.SP_UNIT_NOT_FOUND == 2
        assert SentinelStatus.SP_ACCESS_DENIED == 3
