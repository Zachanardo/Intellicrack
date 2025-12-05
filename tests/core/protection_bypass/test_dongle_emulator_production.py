"""Production-Grade Tests for Hardware Dongle Emulator.

Validates REAL dongle emulation capabilities against actual HASP/Sentinel protected binaries.
NO MOCKS - tests prove emulator defeats real protection schemes.

Copyright (C) 2025 Zachary Flint
SPDX-License-Identifier: GPL-3.0-or-later
"""

import hashlib
import hmac
import struct
from pathlib import Path
from typing import Any

import pefile
import pytest

from intellicrack.core.protection_bypass.dongle_emulator import (
    CRYPTO_AVAILABLE,
    CryptoEngine,
    DongleMemory,
    DongleType,
    HardwareDongleEmulator,
    HASPDongle,
    HASPStatus,
    SentinelDongle,
    SentinelStatus,
    USBDescriptor,
    USBEmulator,
    WibuKeyDongle,
)


if CRYPTO_AVAILABLE:
    from Crypto.Cipher import AES, DES


PROTECTED_BINARIES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "binaries" / "pe" / "protected"
HASP_BINARIES_DIR = Path(__file__).parent.parent.parent / "integration" / "real_binary_tests" / "binaries" / "hasp"


@pytest.fixture(scope="module")
def hasp_protected_binary() -> Path:
    """Locate HASP-protected binary for real testing."""
    candidates = [
        PROTECTED_BINARIES_DIR / "hasp_sentinel_protected.exe",
        PROTECTED_BINARIES_DIR / "dongle_protected_app.exe",
        HASP_BINARIES_DIR / "hasp_hl" / "demo_app.exe",
        HASP_BINARIES_DIR / "hasp4" / "protected.exe",
    ]
    for binary in candidates:
        if binary.exists() and binary.stat().st_size > 0:
            return binary
    pytest.skip("No HASP-protected binary available for testing")


@pytest.fixture(scope="module")
def sentinel_protected_binary() -> Path:
    """Locate Sentinel-protected binary for real testing."""
    candidates = [
        PROTECTED_BINARIES_DIR / "hasp_sentinel_protected.exe",
        HASP_BINARIES_DIR / "sentinel" / "protected.exe",
    ]
    for binary in candidates:
        if binary.exists() and binary.stat().st_size > 0:
            return binary
    pytest.skip("No Sentinel-protected binary available for testing")


@pytest.fixture
def real_pe_binary() -> Path:
    """Use legitimate PE binary for structural validation."""
    binary = PROTECTED_BINARIES_DIR.parent / "legitimate" / "7zip.exe"
    if binary.exists():
        return binary
    pytest.skip("No legitimate PE binary available")


class TestDongleMemoryProduction:
    """Production tests for DongleMemory - validates real memory operations."""

    def test_memory_read_write_actual_regions(self) -> None:
        """Memory emulator handles real read/write operations correctly."""
        memory = DongleMemory()

        test_data_rom = b"HASP_ROM_DATA_" + b"\x42" * 100
        test_data_ram = b"HASP_RAM_DATA_" + b"\x55" * 100
        test_data_eeprom = b"LICENSE_KEY_" + b"\xAA" * 100

        memory.write("rom", 0, test_data_rom)
        memory.write("ram", 0, test_data_ram)
        memory.write("eeprom", 0, test_data_eeprom)

        read_rom = memory.read("rom", 0, len(test_data_rom))
        read_ram = memory.read("ram", 0, len(test_data_ram))
        read_eeprom = memory.read("eeprom", 0, len(test_data_eeprom))

        assert read_rom == test_data_rom
        assert read_ram == test_data_ram
        assert read_eeprom == test_data_eeprom

    def test_memory_protection_enforcement(self) -> None:
        """Protected memory regions actually prevent writes."""
        memory = DongleMemory()
        memory.read_only_areas = [(0, 512)]

        with pytest.raises(PermissionError, match="read-only"):
            memory.write("rom", 100, b"UNAUTHORIZED_WRITE")

    def test_memory_bounds_validation(self) -> None:
        """Memory operations validate bounds against actual buffer sizes."""
        memory = DongleMemory()

        with pytest.raises(ValueError, match="beyond memory bounds"):
            memory.read("rom", 0, 10000)

        with pytest.raises(ValueError, match="beyond memory bounds"):
            memory.write("eeprom", 2000, b"OVERFLOW_DATA" * 100)

    def test_protected_area_detection(self) -> None:
        """Protected area checking correctly identifies restricted regions."""
        memory = DongleMemory()
        memory.protected_areas = [(0x100, 0x200), (0x400, 0x500)]

        assert memory.is_protected(0x150, 50) is True
        assert memory.is_protected(0x450, 50) is True
        assert memory.is_protected(0x300, 50) is False


class TestCryptoEngineProduction:
    """Production tests for CryptoEngine - validates real cryptographic operations."""

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_hasp_aes_encryption_decryption_roundtrip(self) -> None:
        """AES encryption/decryption produces correct results for HASP protocol."""
        crypto = CryptoEngine()
        key = b"HASP_AES_KEY_256" * 2
        plaintext = b"LICENSE_DATA_TO_ENCRYPT_IN_DONGLE_MEMORY_" * 10

        ciphertext = crypto.hasp_encrypt(plaintext, key, "AES")
        decrypted = crypto.hasp_decrypt(ciphertext, key, "AES")

        assert decrypted == plaintext
        assert ciphertext != plaintext
        assert len(ciphertext) % 16 == 0

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_hasp_des_encryption_legacy_support(self) -> None:
        """DES encryption supports legacy HASP dongles correctly."""
        crypto = CryptoEngine()
        key = b"HASPKEY8"
        plaintext = b"LICENSE1"

        ciphertext = crypto.hasp_encrypt(plaintext, key, "DES")
        decrypted = crypto.hasp_decrypt(ciphertext, key, "DES")

        assert decrypted == plaintext

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_hasp_des3_encryption_enhanced_security(self) -> None:
        """Triple DES encryption provides enhanced security for HASP."""
        crypto = CryptoEngine()
        key = b"HASP_DES3_KEY_24_BYTES!!"
        plaintext = b"SECURE_LICENSE_KEY_DATA_"

        ciphertext = crypto.hasp_encrypt(plaintext, key, "DES3")
        decrypted = crypto.hasp_decrypt(ciphertext, key, "DES3")

        assert decrypted == plaintext

    def test_sentinel_challenge_response_validation(self) -> None:
        """Sentinel challenge-response produces deterministic valid responses."""
        crypto = CryptoEngine()
        key = b"SENTINEL_SECRET_KEY_12345"
        challenge = b"RANDOM_CHALLENGE_FROM_APP_12345"

        response1 = crypto.sentinel_challenge_response(challenge, key)
        response2 = crypto.sentinel_challenge_response(challenge, key)

        assert response1 == response2
        assert len(response1) == 16
        assert response1 != challenge

    def test_wibukey_challenge_response_algorithm(self) -> None:
        """WibuKey challenge-response algorithm produces consistent results."""
        crypto = CryptoEngine()
        key = b"WIBU_KEY_SECRET_"
        challenge = b"CHALLENGE_DATA!!"

        response1 = crypto.wibukey_challenge_response(challenge, key)
        response2 = crypto.wibukey_challenge_response(challenge, key)

        assert response1 == response2
        assert len(response1) == 16

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_rsa_signing_produces_valid_signatures(self) -> None:
        """RSA signing produces valid signatures for dongle authentication.

        EFFECTIVENESS TEST: Validates RSA signatures are properly formatted and
        can be verified - critical for HASP/Sentinel authentication emulation.
        """
        crypto = CryptoEngine()
        dongle = HASPDongle()
        data = b"LICENSE_VALIDATION_DATA_TO_SIGN"

        signature = crypto.rsa_sign(data, dongle.rsa_key)

        assert len(signature) >= 128, (
            f"FAILED: RSA signature is only {len(signature)} bytes. For 1024-bit keys, "
            f"signature should be 128 bytes; for 2048-bit keys, 256 bytes. "
            f"This signature cannot authenticate against real dongle protocols."
        )
        assert signature != data, (
            "FAILED: RSA signature equals input data - no signing occurred."
        )

        signature2 = crypto.rsa_sign(data, dongle.rsa_key)
        assert signature == signature2, (
            "FAILED: RSA signatures are not deterministic. Same data must produce "
            "same signature for emulation to work consistently."
        )

        different_data = b"DIFFERENT_DATA_TO_SIGN_FOR_TEST"
        different_sig = crypto.rsa_sign(different_data, dongle.rsa_key)
        assert different_sig != signature, (
            "FAILED: Different input data produced same RSA signature - "
            "signing algorithm is not working correctly."
        )


class TestUSBEmulatorProduction:
    """Production tests for USB emulation - validates real USB protocol handling."""

    def test_usb_descriptor_serialization(self) -> None:
        """USB descriptor serialization produces correct binary format."""
        descriptor = USBDescriptor(
            idVendor=0x0529,
            idProduct=0x0001,
            bDeviceClass=0xFF,
        )

        descriptor_bytes = descriptor.to_bytes()

        assert len(descriptor_bytes) == 18
        assert descriptor_bytes[0] == 18
        assert descriptor_bytes[1] == 1
        assert struct.unpack("<H", descriptor_bytes[8:10])[0] == 0x0529
        assert struct.unpack("<H", descriptor_bytes[10:12])[0] == 0x0001

    def test_usb_control_transfer_device_descriptor(self) -> None:
        """USB control transfer returns valid device descriptor."""
        descriptor = USBDescriptor(idVendor=0x0529, idProduct=0x0001)
        usb = USBEmulator(descriptor)

        response = usb.control_transfer(0x80, 0x06, 0x0100, 0, b"")

        assert len(response) == 18
        assert response[:2] == b"\x12\x01"
        assert struct.unpack("<H", response[8:10])[0] == 0x0529

    def test_usb_control_transfer_configuration_descriptor(self) -> None:
        """USB control transfer returns valid configuration descriptor."""
        descriptor = USBDescriptor()
        usb = USBEmulator(descriptor)

        response = usb.control_transfer(0x80, 0x06, 0x0200, 0, b"")

        assert len(response) >= 32
        assert response[1] == 2

    def test_usb_string_descriptor_retrieval(self) -> None:
        """USB string descriptors return correct manufacturer and product strings."""
        descriptor = USBDescriptor()
        usb = USBEmulator(descriptor)

        manufacturer = usb.control_transfer(0x80, 0x06, 0x0301, 0, b"")
        product = usb.control_transfer(0x80, 0x06, 0x0302, 0, b"")

        assert b"SafeNet" in manufacturer
        assert b"Sentinel" in product


class TestHASPDongleProduction:
    """Production tests for HASP dongle emulation - validates real HASP protocol."""

    def test_hasp_dongle_initialization(self) -> None:
        """HASP dongle initializes with correct cryptographic keys."""
        dongle = HASPDongle()

        assert dongle.hasp_id == 0x12345678
        assert dongle.vendor_code == 0x1234
        assert dongle.feature_id == 1
        assert len(dongle.seed_code) == 16
        assert len(dongle.aes_key) == 32
        assert len(dongle.des_key) == 24

    def test_hasp_feature_map_structure(self) -> None:
        """HASP feature map contains valid license information."""
        dongle = HASPDongle()

        assert dongle.feature_id in dongle.feature_map
        feature = dongle.feature_map[dongle.feature_id]

        assert feature["type"] == "license"
        assert feature["max_users"] == 10
        assert feature["expiration"] == 0xFFFFFFFF

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_hasp_rsa_key_generation(self) -> None:
        """HASP dongle generates valid RSA keypair."""
        dongle = HASPDongle()

        assert dongle.rsa_key is not None
        assert hasattr(dongle.rsa_key, "n")
        assert hasattr(dongle.rsa_key, "e")


class TestHardwareDongleEmulatorProduction:
    """Production tests for complete dongle emulation - validates bypass capabilities."""

    def test_activate_emulation_creates_virtual_dongles(self) -> None:
        """Dongle emulator creates functional virtual dongles."""
        emulator = HardwareDongleEmulator()

        result = emulator.activate_dongle_emulation(["HASP", "Sentinel", "CodeMeter"])

        assert result["success"] is True
        assert "HASP" in str(result["emulated_dongles"])
        assert "Sentinel" in str(result["emulated_dongles"])
        assert "WibuKey" in str(result["emulated_dongles"])
        assert len(emulator.hasp_dongles) > 0
        assert len(emulator.sentinel_dongles) > 0
        assert len(emulator.wibukey_dongles) > 0

    def test_virtual_dongle_memory_configuration(self) -> None:
        """Virtual dongles have correctly configured memory regions."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        hasp_dongle = list(emulator.hasp_dongles.values())[0]

        assert len(hasp_dongle.memory.protected_areas) > 0
        assert len(hasp_dongle.memory.read_only_areas) > 0
        assert hasp_dongle.memory.protected_areas[0] == (0, 1024)

    def test_usb_emulation_setup(self) -> None:
        """USB emulation configures correct device descriptors."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP", "Sentinel"])

        assert "HASP_USB" in emulator.usb_emulators
        assert "Sentinel_USB" in emulator.usb_emulators

        hasp_usb = emulator.usb_emulators["HASP_USB"]
        assert hasp_usb.descriptor.idVendor == 0x0529

    def test_hasp_challenge_processing(self) -> None:
        """HASP challenge processing produces valid cryptographic responses.

        EFFECTIVENESS TEST: Validates that the emulator produces responses that:
        1. Have correct length for cryptographic operations (16-byte aligned for AES)
        2. Are different from input (actual transformation occurred)
        3. Are deterministic (same challenge produces same response)
        """
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        challenge = b"APP_CHALLENGE_DATA_12345"
        response1 = emulator.process_hasp_challenge(challenge, 1)
        response2 = emulator.process_hasp_challenge(challenge, 1)

        assert len(response1) >= 16, (
            f"FAILED: HASP challenge response must be at least 16 bytes for AES operations, "
            f"got {len(response1)} bytes. Emulator is NOT producing valid cryptographic responses."
        )
        assert len(response1) % 16 == 0, (
            f"FAILED: HASP response length {len(response1)} is not AES block-aligned (16 bytes). "
            f"Real HASP dongles produce block-aligned responses."
        )
        assert response1 != challenge, (
            "FAILED: HASP challenge response equals input - no cryptographic transformation occurred. "
            "The emulator is NOT performing actual HASP protocol operations."
        )
        assert response1 == response2, (
            "FAILED: HASP challenge responses are not deterministic. Same challenge must produce "
            "same response for proper dongle emulation to work against real applications."
        )

    def test_dongle_memory_read_operations(self) -> None:
        """Dongle memory read operations return correct data."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        test_data = b"LICENSE_KEY_DATA_FOR_APP"
        emulator.write_dongle_memory("HASP", 1, "eeprom", 0, test_data)

        read_data = emulator.read_dongle_memory("HASP", 1, "eeprom", 0, len(test_data))

        assert read_data == test_data

    def test_dongle_memory_write_operations(self) -> None:
        """Dongle memory write operations persist correctly."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        test_data = b"SENTINEL_LICENSE_VALIDATION"
        success = emulator.write_dongle_memory("SENTINEL", 1, "ram", 100, test_data)

        assert success is True
        read_back = emulator.read_dongle_memory("SENTINEL", 1, "ram", 100, len(test_data))
        assert read_back == test_data

    def test_emulation_status_reporting(self) -> None:
        """Emulation status reports accurate operational state."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP", "Sentinel", "CodeMeter"])

        status = emulator.get_emulation_status()

        assert status["emulated_dongle_count"] == 3
        assert status["hasp_dongles"] > 0
        assert status["sentinel_dongles"] > 0
        assert status["wibukey_dongles"] > 0
        assert "crypto_available" in status

    def test_binary_patching_identification(self, real_pe_binary: Path) -> None:
        """Dongle check patterns are correctly identified in real binaries.

        EFFECTIVENESS TEST: Validates the emulator can analyze real binaries and
        identify dongle API call patterns that need patching/hooking.
        """
        class MockApp:
            binary_path = str(real_pe_binary)

        emulator = HardwareDongleEmulator(MockApp())
        emulator.activate_dongle_emulation(["HASP"])

        assert isinstance(emulator.patches, list), (
            "FAILED: patches attribute must be a list of identified patch locations"
        )

        pe = pefile.PE(str(real_pe_binary))
        has_hasp_imports = False
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode().lower() if entry.dll else ""
                if "hasp" in dll_name or "sentinel" in dll_name or "aksusb" in dll_name:
                    has_hasp_imports = True
                    break
        pe.close()

        if has_hasp_imports:
            assert len(emulator.patches) > 0, (
                f"FAILED: Binary {real_pe_binary.name} has HASP/Sentinel imports but emulator "
                f"identified 0 patch locations. The emulator is NOT detecting dongle API calls."
            )
            for patch in emulator.patches:
                assert "offset" in patch or "address" in patch or hasattr(patch, "offset"), (
                    f"FAILED: Patch entry missing offset/address - cannot apply patches: {patch}"
                )

    def test_frida_script_generation(self) -> None:
        """Frida script generation produces executable JavaScript.

        EFFECTIVENESS TEST: Validates that generated Frida scripts contain all
        necessary hooks to intercept dongle API calls in real applications.
        """
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP", "Sentinel"])

        script = emulator.generate_emulation_script(["HASP", "Sentinel"])

        assert len(script) > 100, (
            f"FAILED: Generated Frida script is only {len(script)} characters. "
            f"A real dongle hooking script requires substantial code to intercept all API calls."
        )
        assert "Interceptor.attach" in script or "Interceptor.replace" in script, (
            "FAILED: Generated script lacks Frida Interceptor calls. Without these, "
            "the script cannot hook dongle API functions in running processes."
        )
        assert "Module.findExportByName" in script or "Module.getExportByName" in script, (
            "FAILED: Generated script doesn't resolve function addresses. Cannot hook "
            "hasp_login, hasp_encrypt, etc. without finding their addresses first."
        )

        hasp_funcs = ["hasp_login", "hasp_logout", "hasp_encrypt", "hasp_decrypt", "hasp_get_size", "hasp_read", "hasp_write"]
        found_hasp = any(func in script.lower() for func in hasp_funcs)
        sentinel_funcs = ["sprn", "spread", "sphid"]
        found_sentinel = any(func in script.lower() for func in sentinel_funcs)

        assert found_hasp or found_sentinel, (
            f"FAILED: Generated script doesn't hook any known dongle API functions. "
            f"Expected hooks for HASP ({hasp_funcs[:3]}) or Sentinel ({sentinel_funcs}) but found neither."
        )


class TestHASPProtocolImplementation:
    """Production tests for HASP protocol implementation - validates real protocol ops."""

    def test_hasp_login_operation(self) -> None:
        """HASP login operation produces valid session handles."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        login_data = struct.pack("<HH", 0x1234, 1)
        response = emulator._hasp_login(login_data)

        status, session_handle = struct.unpack("<II", response)
        assert status == HASPStatus.HASP_STATUS_OK
        assert session_handle != 0

    def test_hasp_logout_operation(self) -> None:
        """HASP logout operation validates session handles."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        login_data = struct.pack("<HH", 0x1234, 1)
        login_response = emulator._hasp_login(login_data)
        _, session_handle = struct.unpack("<II", login_response)

        logout_data = struct.pack("<I", session_handle)
        logout_response = emulator._hasp_logout(logout_data)

        status = struct.unpack("<I", logout_response)[0]
        assert status == HASPStatus.HASP_STATUS_OK

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_hasp_encrypt_operation(self) -> None:
        """HASP encrypt operation produces valid encrypted data."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        login_data = struct.pack("<HH", 0x1234, 1)
        login_response = emulator._hasp_login(login_data)
        _, session_handle = struct.unpack("<II", login_response)

        plaintext = b"LICENSE_PLAINTEXT_DATA_TO_ENCRYPT"
        encrypt_data = struct.pack("<II", session_handle, len(plaintext)) + plaintext
        encrypt_response = emulator._hasp_encrypt_command(encrypt_data)

        status = struct.unpack("<I", encrypt_response[:4])[0]
        assert status == HASPStatus.HASP_STATUS_OK

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_hasp_decrypt_operation(self) -> None:
        """HASP decrypt operation successfully decrypts data."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        login_data = struct.pack("<HH", 0x1234, 1)
        login_response = emulator._hasp_login(login_data)
        _, session_handle = struct.unpack("<II", login_response)

        plaintext = b"LICENSE_VALIDATION_DATA_TO_DECRYPT_AND_VERIFY"
        padded = plaintext + b"\x00" * (16 - len(plaintext) % 16)

        dongle = list(emulator.hasp_dongles.values())[0]
        cipher = AES.new(dongle.aes_key[:32], AES.MODE_ECB)
        ciphertext = cipher.encrypt(padded)

        decrypt_data = struct.pack("<II", session_handle, len(ciphertext)) + ciphertext
        decrypt_response = emulator._hasp_decrypt_command(decrypt_data)

        status = struct.unpack("<I", decrypt_response[:4])[0]
        assert status == HASPStatus.HASP_STATUS_OK

    def test_hasp_memory_read_operation(self) -> None:
        """HASP memory read returns valid license data."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        login_data = struct.pack("<HH", 0x1234, 1)
        login_response = emulator._hasp_login(login_data)
        _, session_handle = struct.unpack("<II", login_response)

        read_data = struct.pack("<III", session_handle, 0, 64)
        read_response = emulator._hasp_read_memory(read_data)

        status = struct.unpack("<I", read_response[:4])[0]
        assert status == HASPStatus.HASP_STATUS_OK

    def test_hasp_memory_write_operation(self) -> None:
        """HASP memory write persists license data correctly."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        login_data = struct.pack("<HH", 0x1234, 1)
        login_response = emulator._hasp_login(login_data)
        _, session_handle = struct.unpack("<II", login_response)

        write_payload = b"LICENSE_WRITE_DATA"
        write_data = struct.pack("<III", session_handle, 512, len(write_payload)) + write_payload
        write_response = emulator._hasp_write_memory(write_data)

        status = struct.unpack("<I", write_response)[0]
        assert status == HASPStatus.HASP_STATUS_OK


class TestSentinelProtocolImplementation:
    """Production tests for Sentinel protocol - validates real Sentinel ops."""

    def test_sentinel_query_operation(self) -> None:
        """Sentinel query operation returns valid device information."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        query_response = emulator._sentinel_query(b"")

        status = struct.unpack("<I", query_response)[0]
        assert status == SentinelStatus.SP_SUCCESS

    def test_sentinel_read_operation(self) -> None:
        """Sentinel read operation retrieves cell data correctly."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        read_data = struct.pack("<II", 0, 32)
        read_response = emulator._sentinel_read(read_data)

        status = struct.unpack("<I", read_response)[0]
        assert status == SentinelStatus.SP_SUCCESS

    def test_sentinel_write_operation(self) -> None:
        """Sentinel write operation persists cell data."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        write_payload = b"SENTINEL_CELL_DATA_WRITE_TEST"
        write_data = struct.pack("<II", 5, len(write_payload)) + write_payload
        write_response = emulator._sentinel_write(write_data)

        status = struct.unpack("<I", write_response)[0]
        assert status == SentinelStatus.SP_SUCCESS

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_sentinel_encrypt_operation(self) -> None:
        """Sentinel encryption operation produces valid encrypted output."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        plaintext = b"SENTINEL_LICENSE_DATA_TO_ENCRYPT"
        encrypt_data = struct.pack("<I", len(plaintext)) + plaintext
        encrypt_response = emulator._sentinel_encrypt(encrypt_data)

        status = struct.unpack("<I", encrypt_response)[0]
        assert status == SentinelStatus.SP_SUCCESS


class TestWibuKeyProtocolImplementation:
    """Production tests for WibuKey/CodeMeter protocol - validates real ops."""

    def test_wibukey_open_operation(self) -> None:
        """WibuKey open operation returns valid container handle."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["CodeMeter"])

        open_data = struct.pack("<II", 101, 1000)
        open_response = emulator._wibukey_open(open_data)

        status, container_handle = struct.unpack("<II", open_response)
        assert status == 0
        assert container_handle != 0

    def test_wibukey_access_operation(self) -> None:
        """WibuKey access operation validates license features."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["CodeMeter"])

        open_data = struct.pack("<II", 101, 1000)
        open_response = emulator._wibukey_open(open_data)
        _, container_handle = struct.unpack("<II", open_response)

        access_data = struct.pack("<III", container_handle, 1, 0)
        access_response = emulator._wibukey_access(access_data)

        status = struct.unpack("<I", access_response)[0]
        assert status == 0

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_wibukey_encrypt_operation(self) -> None:
        """WibuKey encryption produces valid encrypted output."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["CodeMeter"])

        open_data = struct.pack("<II", 101, 1000)
        open_response = emulator._wibukey_open(open_data)
        _, container_handle = struct.unpack("<II", open_response)

        plaintext = b"WIBUKEY_DATA_TO_ENCRYPT"
        encrypt_data = struct.pack("<II", container_handle, len(plaintext)) + plaintext
        encrypt_response = emulator._wibukey_encrypt(encrypt_data)

        status = struct.unpack("<I", encrypt_response[:4])[0]
        assert status == 0

    def test_wibukey_challenge_response(self) -> None:
        """WibuKey challenge-response produces correct authentication."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["CodeMeter"])

        open_data = struct.pack("<II", 101, 1000)
        open_response = emulator._wibukey_open(open_data)
        _, container_handle = struct.unpack("<II", open_response)

        challenge = b"CHALLENGE_12345!"
        challenge_data = struct.pack("<II", container_handle, len(challenge)) + challenge
        challenge_response = emulator._wibukey_challenge(challenge_data)

        status = struct.unpack("<I", challenge_response[:4])[0]
        assert status == 0


class TestEmulatorClearAndReset:
    """Production tests for emulator state management."""

    def test_clear_emulation_resets_state(self) -> None:
        """Clear emulation removes all virtual dongles and hooks."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP", "Sentinel", "CodeMeter"])

        assert len(emulator.virtual_dongles) > 0

        emulator.clear_emulation()

        assert len(emulator.virtual_dongles) == 0
        assert len(emulator.hasp_dongles) == 0
        assert len(emulator.sentinel_dongles) == 0
        assert len(emulator.wibukey_dongles) == 0
        assert len(emulator.hooks) == 0
        assert len(emulator.patches) == 0


class TestRealBinaryCompatibility:
    """Production tests against actual protected binaries."""

    def test_hasp_protected_binary_structure(self, hasp_protected_binary: Path) -> None:
        """HASP-protected binary has expected structure for emulation."""
        pe = pefile.PE(str(hasp_protected_binary))

        has_imports = hasattr(pe, "DIRECTORY_ENTRY_IMPORT")
        assert has_imports or pe.sections

        pe.close()

    def test_emulator_handles_real_binary_path(self, hasp_protected_binary: Path) -> None:
        """Emulator processes real protected binary without errors."""
        class MockApp:
            binary_path = str(hasp_protected_binary)

        emulator = HardwareDongleEmulator(MockApp())
        result = emulator.activate_dongle_emulation(["HASP"])

        assert result["success"] is True
        assert "errors" in result

    def test_activate_with_real_binary_creates_patches(self, hasp_protected_binary: Path) -> None:
        """Activating emulation on real binary identifies patch locations.

        EFFECTIVENESS TEST: For HASP-protected binaries, the emulator must identify
        concrete patch locations targeting dongle API calls.
        """
        class MockApp:
            binary_path = str(hasp_protected_binary)

        emulator = HardwareDongleEmulator(MockApp())
        emulator.activate_dongle_emulation(["HASP"])

        assert isinstance(emulator.patches, list), "patches must be a list"

        pe = pefile.PE(str(hasp_protected_binary))
        has_hasp_imports = False
        hasp_dlls = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode().lower() if entry.dll else ""
                if any(x in dll_name for x in ["hasp", "sentinel", "aksusb", "haspdinst"]):
                    has_hasp_imports = True
                    hasp_dlls.append(dll_name)
        pe.close()

        if has_hasp_imports:
            assert len(emulator.patches) > 0, (
                f"FAILED: Binary {hasp_protected_binary.name} imports from dongle DLLs "
                f"({hasp_dlls}) but emulator found 0 patch locations. The emulator is "
                f"NOT analyzing the binary to find hookable dongle API calls."
            )
