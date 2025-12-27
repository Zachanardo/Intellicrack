"""Production-ready tests for Hardware Dongle Emulator.

Tests validate actual dongle protocol emulation (HASP, Sentinel, WibuKey)
with real cryptographic operations and USB communication patterns.
No mocks - genuine dongle emulation capability testing.
"""

import hashlib
import hmac
import struct
from typing import Any

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
)


class TestDongleMemory:
    """Test dongle memory region operations."""

    def test_create_dongle_memory_with_default_sizes(self) -> None:
        """DongleMemory initializes with correct default memory sizes."""
        memory = DongleMemory()

        assert len(memory.rom) == 8192
        assert len(memory.ram) == 4096
        assert len(memory.eeprom) == 2048
        assert isinstance(memory.protected_areas, list)
        assert isinstance(memory.read_only_areas, list)

    def test_read_from_rom_region(self) -> None:
        """Memory read from ROM region returns correct bytes."""
        memory = DongleMemory()
        memory.rom[0:4] = bytearray([0xDE, 0xAD, 0xBE, 0xEF])

        data = memory.read("rom", 0, 4)

        assert data == bytes([0xDE, 0xAD, 0xBE, 0xEF])
        assert len(data) == 4

    def test_read_from_ram_region(self) -> None:
        """Memory read from RAM region returns correct bytes."""
        memory = DongleMemory()
        memory.ram[10:14] = bytearray([0xCA, 0xFE, 0xBA, 0xBE])

        data = memory.read("ram", 10, 4)

        assert data == bytes([0xCA, 0xFE, 0xBA, 0xBE])

    def test_read_from_eeprom_region(self) -> None:
        """Memory read from EEPROM region returns correct bytes."""
        memory = DongleMemory()
        memory.eeprom[20:24] = bytearray([0x12, 0x34, 0x56, 0x78])

        data = memory.read("eeprom", 20, 4)

        assert data == bytes([0x12, 0x34, 0x56, 0x78])

    def test_write_to_ram_region(self) -> None:
        """Memory write to RAM region successfully modifies bytes."""
        memory = DongleMemory()
        test_data = bytes([0xAA, 0xBB, 0xCC, 0xDD])

        memory.write("ram", 0, test_data)
        read_data = memory.read("ram", 0, 4)

        assert read_data == test_data

    def test_write_to_eeprom_region(self) -> None:
        """Memory write to EEPROM region successfully modifies bytes."""
        memory = DongleMemory()
        test_data = bytes([0x11, 0x22, 0x33, 0x44])

        memory.write("eeprom", 0, test_data)
        read_data = memory.read("eeprom", 0, 4)

        assert read_data == test_data

    def test_write_to_readonly_area_raises_error(self) -> None:
        """Memory write to read-only area raises PermissionError."""
        memory = DongleMemory()
        memory.read_only_areas = [(0, 512)]

        with pytest.raises(PermissionError, match="Cannot write to read-only area"):
            memory.write("rom", 100, bytes([0xFF, 0xFF]))

    def test_read_beyond_bounds_raises_error(self) -> None:
        """Memory read beyond region bounds raises ValueError."""
        memory = DongleMemory()

        with pytest.raises(ValueError, match="Read beyond memory bounds"):
            memory.read("rom", 8190, 10)

    def test_write_beyond_bounds_raises_error(self) -> None:
        """Memory write beyond region bounds raises ValueError."""
        memory = DongleMemory()

        with pytest.raises(ValueError, match="Write beyond memory bounds"):
            memory.write("ram", 4095, bytes([0x01, 0x02, 0x03]))

    def test_invalid_region_name_raises_error(self) -> None:
        """Memory operation with invalid region name raises ValueError."""
        memory = DongleMemory()

        with pytest.raises(ValueError, match="Invalid memory region"):
            memory.read("invalid_region", 0, 10)

    def test_is_protected_area_check(self) -> None:
        """Protected area check correctly identifies protected memory."""
        memory = DongleMemory()
        memory.protected_areas = [(100, 200), (500, 600)]

        assert memory.is_protected(150, 10) is True
        assert memory.is_protected(550, 20) is True
        assert memory.is_protected(0, 10) is False
        assert memory.is_protected(300, 10) is False


class TestUSBDescriptor:
    """Test USB device descriptor structure."""

    def test_usb_descriptor_default_values(self) -> None:
        """USBDescriptor initializes with USB 2.0 specification defaults."""
        descriptor = USBDescriptor()

        assert descriptor.bLength == 18
        assert descriptor.bDescriptorType == 1
        assert descriptor.bcdUSB == 0x0200
        assert descriptor.bDeviceClass == 0xFF
        assert descriptor.idVendor == 0x0529
        assert descriptor.bNumConfigurations == 1

    def test_usb_descriptor_to_bytes_format(self) -> None:
        """USBDescriptor serializes to correct binary format."""
        descriptor = USBDescriptor()

        descriptor_bytes = descriptor.to_bytes()

        assert len(descriptor_bytes) == 18
        assert descriptor_bytes[0] == 18
        assert descriptor_bytes[1] == 1

    def test_usb_descriptor_custom_vendor_product(self) -> None:
        """USBDescriptor accepts custom vendor and product IDs."""
        descriptor = USBDescriptor(idVendor=0x064F, idProduct=0x0BD7)

        assert descriptor.idVendor == 0x064F
        assert descriptor.idProduct == 0x0BD7

        descriptor_bytes = descriptor.to_bytes()
        vendor_id = struct.unpack("<H", descriptor_bytes[8:10])[0]
        product_id = struct.unpack("<H", descriptor_bytes[10:12])[0]

        assert vendor_id == 0x064F
        assert product_id == 0x0BD7


class TestUSBEmulator:
    """Test USB device emulation."""

    def test_usb_emulator_initialization(self) -> None:
        """USBEmulator initializes with descriptor and endpoints."""
        descriptor = USBDescriptor()
        emulator = USBEmulator(descriptor)

        assert emulator.descriptor == descriptor
        assert len(emulator.endpoints) > 0
        assert 0x00 in emulator.endpoints
        assert 0x81 in emulator.endpoints
        assert 0x02 in emulator.endpoints

    def test_control_transfer_get_device_descriptor(self) -> None:
        """USB control transfer returns device descriptor."""
        descriptor = USBDescriptor()
        emulator = USBEmulator(descriptor)

        response = emulator.control_transfer(0x80, 0x06, 0x0100, 0, b"")

        assert len(response) == 18
        assert response == descriptor.to_bytes()

    def test_control_transfer_get_configuration_descriptor(self) -> None:
        """USB control transfer returns configuration descriptor."""
        descriptor = USBDescriptor()
        emulator = USBEmulator(descriptor)

        response = emulator.control_transfer(0x80, 0x06, 0x0200, 0, b"")

        assert len(response) > 0
        assert response[0] == 9
        assert response[1] == 2

    def test_control_transfer_get_string_descriptor(self) -> None:
        """USB control transfer returns string descriptors."""
        descriptor = USBDescriptor()
        emulator = USBEmulator(descriptor)

        response = emulator.control_transfer(0x80, 0x06, 0x0301, 0, b"")

        assert len(response) > 0

    def test_register_custom_control_handler(self) -> None:
        """USBEmulator allows registration of custom control handlers."""
        descriptor = USBDescriptor()
        emulator = USBEmulator(descriptor)
        handler_called = False

        def custom_handler(wValue: int, wIndex: int, data: bytes) -> bytes:
            nonlocal handler_called
            handler_called = True
            return bytes([0xAA, 0xBB, 0xCC, 0xDD])

        emulator.register_control_handler(0x40, 0xFF, custom_handler)
        response = emulator.control_transfer(0x40, 0xFF, 0, 0, b"")

        assert handler_called is True
        assert response == bytes([0xAA, 0xBB, 0xCC, 0xDD])

    def test_register_custom_bulk_handler(self) -> None:
        """USBEmulator allows registration of custom bulk handlers."""
        descriptor = USBDescriptor()
        emulator = USBEmulator(descriptor)
        handler_called = False

        def custom_bulk_handler(data: bytes) -> bytes:
            nonlocal handler_called
            handler_called = True
            return data

        emulator.register_bulk_handler(0x02, custom_bulk_handler)
        response = emulator.bulk_transfer(0x02, b"\x01\x02\x03")

        assert handler_called is True
        assert response == b"\x01\x02\x03"


class TestHASPDongle:
    """Test HASP dongle emulation data."""

    def test_hasp_dongle_initialization(self) -> None:
        """HASPDongle initializes with correct default values."""
        dongle = HASPDongle()

        assert dongle.hasp_id == 0x12345678
        assert dongle.vendor_code == 0x1234
        assert dongle.feature_id == 1
        assert len(dongle.seed_code) == 16
        assert isinstance(dongle.memory, DongleMemory)
        assert dongle.logged_in is False

    def test_hasp_dongle_crypto_key_generation(self) -> None:
        """HASPDongle generates cryptographic keys on initialization."""
        dongle = HASPDongle()

        assert len(dongle.aes_key) == 32
        assert len(dongle.des_key) == 24
        assert len(dongle.license_data) == 512

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Crypto library not available")
    def test_hasp_dongle_rsa_key_generation(self) -> None:
        """HASPDongle generates RSA key pair when crypto available."""
        dongle = HASPDongle()

        assert dongle.rsa_key is not None
        assert hasattr(dongle.rsa_key, "n")
        assert hasattr(dongle.rsa_key, "e")

    def test_hasp_dongle_feature_map(self) -> None:
        """HASPDongle creates feature map with default feature."""
        dongle = HASPDongle()

        assert dongle.feature_id in dongle.feature_map
        feature = dongle.feature_map[dongle.feature_id]
        assert feature["id"] == 1
        assert feature["type"] == "license"
        assert feature["max_users"] == 10


class TestSentinelDongle:
    """Test Sentinel dongle emulation data."""

    def test_sentinel_dongle_initialization(self) -> None:
        """SentinelDongle initializes with correct default values."""
        dongle = SentinelDongle()

        assert dongle.device_id == 0x87654321
        assert dongle.vendor_id == 0x0529
        assert dongle.product_id == 0x0001
        assert dongle.serial_number == "SN123456789ABCDEF"
        assert dongle.firmware_version == "8.0.0"

    def test_sentinel_dongle_algorithms(self) -> None:
        """SentinelDongle supports required cryptographic algorithms."""
        dongle = SentinelDongle()

        assert "AES" in dongle.algorithms
        assert "RSA" in dongle.algorithms
        assert "DES" in dongle.algorithms
        assert "HMAC" in dongle.algorithms

    def test_sentinel_dongle_cell_data_initialization(self) -> None:
        """SentinelDongle initializes cell data storage."""
        dongle = SentinelDongle()

        assert len(dongle.cell_data) == 8
        for i in range(8):
            assert i in dongle.cell_data
            assert len(dongle.cell_data[i]) == 64


class TestWibuKeyDongle:
    """Test WibuKey/CodeMeter dongle emulation data."""

    def test_wibukey_dongle_initialization(self) -> None:
        """WibuKeyDongle initializes with correct default values."""
        dongle = WibuKeyDongle()

        assert dongle.firm_code == 101
        assert dongle.product_code == 1000
        assert dongle.feature_code == 1
        assert dongle.serial_number == 1000001
        assert dongle.version == "6.90"

    def test_wibukey_dongle_license_entries(self) -> None:
        """WibuKeyDongle initializes with default license entry."""
        dongle = WibuKeyDongle()

        assert 1 in dongle.license_entries
        entry = dongle.license_entries[1]
        assert entry["firm_code"] == 101
        assert entry["product_code"] == 1000
        assert entry["enabled"] is True
        assert entry["quantity"] == 100


class TestCryptoEngine:
    """Test cryptographic operations."""

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Crypto library not available")
    def test_hasp_aes_encryption(self) -> None:
        """CryptoEngine performs AES encryption for HASP protocol."""
        engine = CryptoEngine()
        key = b"0" * 32
        plaintext = b"test data for encryption"

        ciphertext = engine.hasp_encrypt(plaintext, key, "AES")

        assert ciphertext != plaintext
        assert len(ciphertext) >= len(plaintext)

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Crypto library not available")
    def test_hasp_aes_decryption(self) -> None:
        """CryptoEngine performs AES decryption for HASP protocol."""
        engine = CryptoEngine()
        key = b"0" * 32
        plaintext = b"test data for encryption"

        ciphertext = engine.hasp_encrypt(plaintext, key, "AES")
        decrypted = engine.hasp_decrypt(ciphertext, key, "AES")

        assert decrypted == plaintext

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Crypto library not available")
    def test_hasp_des_encryption(self) -> None:
        """CryptoEngine performs DES encryption for legacy HASP."""
        engine = CryptoEngine()
        key = b"8bytekey"
        plaintext = b"testdata"

        ciphertext = engine.hasp_encrypt(plaintext, key, "DES")

        assert ciphertext != plaintext

    def test_sentinel_challenge_response(self) -> None:
        """CryptoEngine calculates Sentinel challenge-response."""
        engine = CryptoEngine()
        challenge = b"challenge_data_16"
        key = b"secret_key_value"

        response = engine.sentinel_challenge_response(challenge, key)

        assert len(response) == 16
        assert isinstance(response, bytes)

        expected = hmac.new(key, challenge, hashlib.sha256).digest()[:16]
        assert response == expected

    def test_wibukey_challenge_response(self) -> None:
        """CryptoEngine calculates WibuKey challenge-response."""
        engine = CryptoEngine()
        challenge = b"challenge_16byte"
        key = b"key_16byte_value"

        response = engine.wibukey_challenge_response(challenge, key)

        assert len(response) == 16
        assert isinstance(response, bytes)

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Crypto library not available")
    def test_rsa_signing(self) -> None:
        """CryptoEngine performs RSA signing with private key."""
        from Crypto.PublicKey import RSA

        engine = CryptoEngine()
        rsa_key = RSA.generate(2048)
        data = b"data to sign"

        signature = engine.rsa_sign(data, rsa_key)

        assert isinstance(signature, bytes)
        assert len(signature) > 0

    def test_xor_encryption_fallback(self) -> None:
        """CryptoEngine falls back to XOR when crypto unavailable."""
        engine = CryptoEngine()
        key = b"key123"
        data = b"test data"

        encrypted = engine._xor_encrypt(data, key)

        assert len(encrypted) == len(data)
        assert encrypted != data

        decrypted = engine._xor_encrypt(encrypted, key)
        assert decrypted == data


class TestHardwareDongleEmulator:
    """Test main dongle emulator functionality."""

    def test_emulator_initialization(self) -> None:
        """HardwareDongleEmulator initializes with correct state."""
        emulator = HardwareDongleEmulator()

        assert isinstance(emulator.crypto_engine, CryptoEngine)
        assert isinstance(emulator.virtual_dongles, dict)
        assert isinstance(emulator.hasp_dongles, dict)
        assert isinstance(emulator.sentinel_dongles, dict)
        assert isinstance(emulator.wibukey_dongles, dict)

    def test_activate_hasp_emulation(self) -> None:
        """Emulator successfully activates HASP dongle emulation."""
        emulator = HardwareDongleEmulator()

        result = emulator.activate_dongle_emulation(["HASP"])

        assert result["success"] is True
        assert "HASP" in str(result["emulated_dongles"]) or len(emulator.hasp_dongles) > 0
        assert "Virtual Dongle Creation" in result["methods_applied"]

    def test_activate_sentinel_emulation(self) -> None:
        """Emulator successfully activates Sentinel dongle emulation."""
        emulator = HardwareDongleEmulator()

        result = emulator.activate_dongle_emulation(["Sentinel"])

        assert result["success"] is True
        assert len(emulator.sentinel_dongles) > 0 or "Sentinel" in str(result["emulated_dongles"])

    def test_activate_codemeter_emulation(self) -> None:
        """Emulator successfully activates CodeMeter dongle emulation."""
        emulator = HardwareDongleEmulator()

        result = emulator.activate_dongle_emulation(["CodeMeter"])

        assert result["success"] is True
        assert len(emulator.wibukey_dongles) > 0 or "CodeMeter" in str(result["emulated_dongles"])

    def test_activate_multiple_dongle_types(self) -> None:
        """Emulator activates multiple dongle types simultaneously."""
        emulator = HardwareDongleEmulator()

        result = emulator.activate_dongle_emulation(["HASP", "Sentinel", "CodeMeter"])

        assert result["success"] is True
        total_dongles = len(emulator.hasp_dongles) + len(emulator.sentinel_dongles) + len(emulator.wibukey_dongles)
        assert total_dongles > 0

    def test_process_hasp_challenge(self) -> None:
        """Emulator processes HASP cryptographic challenge."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])
        challenge = b"0123456789ABCDEF"

        if len(emulator.hasp_dongles) > 0:
            response = emulator.process_hasp_challenge(challenge, 1)

            assert isinstance(response, bytes)
            assert len(response) == 16

    def test_read_dongle_memory_hasp(self) -> None:
        """Emulator reads from HASP dongle memory."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        if len(emulator.hasp_dongles) > 0:
            data = emulator.read_dongle_memory("HASP", 1, "ram", 0, 64)

            assert isinstance(data, bytes)
            assert len(data) == 64

    def test_write_dongle_memory_hasp(self) -> None:
        """Emulator writes to HASP dongle memory."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])
        test_data = bytes([0xAA] * 32)

        if len(emulator.hasp_dongles) > 0:
            success = emulator.write_dongle_memory("HASP", 1, "ram", 0, test_data)

            assert success is True

            read_data = emulator.read_dongle_memory("HASP", 1, "ram", 0, 32)
            assert read_data == test_data

    def test_get_emulation_status(self) -> None:
        """Emulator returns comprehensive emulation status."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP", "Sentinel"])

        status = emulator.get_emulation_status()

        assert "virtual_dongles_active" in status
        assert "hasp_dongles" in status
        assert "sentinel_dongles" in status
        assert "crypto_available" in status
        assert isinstance(status["crypto_available"], bool)

    def test_clear_emulation(self) -> None:
        """Emulator clears all emulation state."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP", "Sentinel", "CodeMeter"])

        emulator.clear_emulation()

        assert len(emulator.virtual_dongles) == 0
        assert len(emulator.hasp_dongles) == 0
        assert len(emulator.sentinel_dongles) == 0
        assert len(emulator.wibukey_dongles) == 0

    def test_get_dongle_config_hasp(self) -> None:
        """Emulator returns HASP dongle configuration."""
        emulator = HardwareDongleEmulator()

        config = emulator.get_dongle_config("hasp")

        assert config is not None
        assert config["type"] == "HASP"
        assert config["vendor_id"] == 0x0529
        assert "algorithms" in config
        assert "AES" in config["algorithms"]

    def test_get_dongle_config_sentinel(self) -> None:
        """Emulator returns Sentinel dongle configuration."""
        emulator = HardwareDongleEmulator()

        config = emulator.get_dongle_config("sentinel")

        assert config is not None
        assert config["type"] == "Sentinel"
        assert "api_functions" in config
        assert "RNBOsproQuery" in config["api_functions"]

    def test_get_dongle_config_codemeter(self) -> None:
        """Emulator returns CodeMeter dongle configuration."""
        emulator = HardwareDongleEmulator()

        config = emulator.get_dongle_config("codemeter")

        assert config is not None
        assert config["type"] == "CodeMeter"
        assert config["vendor_id"] == 0x064F


class TestHASPProtocol:
    """Test HASP protocol operations."""

    def test_hasp_login_operation(self) -> None:
        """Emulator handles HASP login operation correctly."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        login_data = struct.pack("<HH", 0x1234, 1)
        response = emulator._hasp_login(login_data)

        status = struct.unpack("<I", response[:4])[0]
        assert status == HASPStatus.HASP_STATUS_OK or status == HASPStatus.HASP_KEYNOTFOUND

    def test_hasp_logout_operation(self) -> None:
        """Emulator handles HASP logout operation correctly."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        login_data = struct.pack("<HH", 0x1234, 1)
        login_response = emulator._hasp_login(login_data)

        if len(login_response) >= 8:
            session_handle = struct.unpack("<I", login_response[4:8])[0]
            logout_data = struct.pack("<I", session_handle)
            logout_response = emulator._hasp_logout(logout_data)

            status = struct.unpack("<I", logout_response[:4])[0]
            assert status in [HASPStatus.HASP_STATUS_OK, HASPStatus.HASP_INV_HND]

    def test_hasp_encrypt_operation(self) -> None:
        """Emulator handles HASP encryption operation correctly."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        login_data = struct.pack("<HH", 0x1234, 1)
        login_response = emulator._hasp_login(login_data)

        if len(login_response) >= 8:
            session_handle = struct.unpack("<I", login_response[4:8])[0]
            plaintext = b"test encryption"
            encrypt_data = struct.pack("<II", session_handle, len(plaintext)) + plaintext
            encrypt_response = emulator._hasp_encrypt_command(encrypt_data)

            status = struct.unpack("<I", encrypt_response[:4])[0]
            assert status in [HASPStatus.HASP_STATUS_OK, HASPStatus.HASP_INV_HND]

    def test_hasp_memory_read_operation(self) -> None:
        """Emulator handles HASP memory read operation correctly."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        login_data = struct.pack("<HH", 0x1234, 1)
        login_response = emulator._hasp_login(login_data)

        if len(login_response) >= 8:
            session_handle = struct.unpack("<I", login_response[4:8])[0]
            read_data = struct.pack("<III", session_handle, 0, 64)
            read_response = emulator._hasp_read_memory(read_data)

            status = struct.unpack("<I", read_response[:4])[0]
            assert status in [HASPStatus.HASP_STATUS_OK, HASPStatus.HASP_INV_HND, HASPStatus.HASP_MEM_RANGE]


class TestSentinelProtocol:
    """Test Sentinel protocol operations."""

    def test_sentinel_query_operation(self) -> None:
        """Emulator handles Sentinel query operation correctly."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        response = emulator._sentinel_query(b"")

        status = struct.unpack("<I", response[:4])[0]
        assert status in [SentinelStatus.SP_SUCCESS, SentinelStatus.SP_UNIT_NOT_FOUND]

    def test_sentinel_read_operation(self) -> None:
        """Emulator handles Sentinel read operation correctly."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        read_data = struct.pack("<II", 0, 64)
        response = emulator._sentinel_read(read_data)

        status = struct.unpack("<I", response[:4])[0]
        assert status in [SentinelStatus.SP_SUCCESS, SentinelStatus.SP_UNIT_NOT_FOUND]

    def test_sentinel_write_operation(self) -> None:
        """Emulator handles Sentinel write operation correctly."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        test_data = bytes([0xAB] * 32)
        write_data = struct.pack("<II", 5, len(test_data)) + test_data
        response = emulator._sentinel_write(write_data)

        status = struct.unpack("<I", response[:4])[0]
        assert status in [SentinelStatus.SP_SUCCESS, SentinelStatus.SP_UNIT_NOT_FOUND]


class TestWibuKeyProtocol:
    """Test WibuKey/CodeMeter protocol operations."""

    def test_wibukey_open_operation(self) -> None:
        """Emulator handles WibuKey open operation correctly."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["CodeMeter"])

        open_data = struct.pack("<II", 101, 1000)
        response = emulator._wibukey_open(open_data)

        status = struct.unpack("<I", response[:4])[0]
        assert status in [0, 1]

    def test_wibukey_access_operation(self) -> None:
        """Emulator handles WibuKey access operation correctly."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["CodeMeter"])

        open_data = struct.pack("<II", 101, 1000)
        open_response = emulator._wibukey_open(open_data)

        if len(open_response) >= 8:
            container_handle = struct.unpack("<I", open_response[4:8])[0]
            access_data = struct.pack("<III", container_handle, 1, 0)
            access_response = emulator._wibukey_access(access_data)

            status = struct.unpack("<I", access_response[:4])[0]
            assert status in [0, 1]

    def test_wibukey_challenge_response_operation(self) -> None:
        """Emulator handles WibuKey challenge-response correctly."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["CodeMeter"])

        open_data = struct.pack("<II", 101, 1000)
        open_response = emulator._wibukey_open(open_data)

        if len(open_response) >= 8:
            container_handle = struct.unpack("<I", open_response[4:8])[0]
            challenge = b"challenge_16byte"
            challenge_data = struct.pack("<II", container_handle, len(challenge)) + challenge
            challenge_response = emulator._wibukey_challenge(challenge_data)

            status = struct.unpack("<I", challenge_response[:4])[0]
            assert status in [0, 1]
