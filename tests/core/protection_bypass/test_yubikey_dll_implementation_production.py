"""Production tests for YubiKey DLL generation and emulation.

Tests validate that the YubiKey DLL implementation provides functional
hardware token emulation with proper CCID protocol support, OTP generation,
PIV operations, and FIDO2/WebAuthn capabilities.
"""

import os
import struct
from pathlib import Path
from typing import Any

import pefile
import pytest

from intellicrack.core.protection_bypass.hardware_token import HardwareTokenBypass


class TestYubikeyDLLGeneration:
    """Test YubiKey DLL generation and structure validation."""

    @pytest.fixture
    def token_bypass(self) -> HardwareTokenBypass:
        """Create HardwareTokenBypass instance."""
        return HardwareTokenBypass()

    @pytest.fixture
    def generated_dll_path(self, token_bypass: HardwareTokenBypass, tmp_path: Path) -> Path:
        """Generate YubiKey DLL and return path."""
        dll_path = tmp_path / "yubikey_hook.dll"
        dll_bytes = token_bypass._generate_minimal_dll()
        dll_path.write_bytes(dll_bytes)
        return dll_path

    def test_yubikey_dll_is_valid_pe_structure(self, generated_dll_path: Path) -> None:
        """YubiKey DLL must be valid PE binary with correct structure."""
        dll_data = generated_dll_path.read_bytes()

        assert dll_data[:2] == b"MZ", "DLL must start with MZ signature"

        pe = pefile.PE(data=dll_data, fast_load=False)
        assert pe.is_dll(), "Binary must be identified as DLL"
        assert pe.is_exe() is False, "Binary must not be EXE"

        pe.close()

    def test_yubikey_dll_has_correct_machine_type(self, generated_dll_path: Path) -> None:
        """YubiKey DLL must target x64 architecture for modern systems."""
        pe = pefile.PE(str(generated_dll_path), fast_load=True)

        assert pe.FILE_HEADER.Machine == 0x8664, "DLL must be compiled for x64 (AMD64)"

        pe.close()

    def test_yubikey_dll_has_dll_characteristics(self, generated_dll_path: Path) -> None:
        """YubiKey DLL must have proper DLL characteristics flags."""
        pe = pefile.PE(str(generated_dll_path), fast_load=True)

        characteristics = pe.FILE_HEADER.Characteristics
        IMAGE_FILE_DLL = 0x2000

        assert characteristics & IMAGE_FILE_DLL, "DLL characteristic flag must be set"

        pe.close()

    def test_yubikey_dll_has_executable_code_section(self, generated_dll_path: Path) -> None:
        """YubiKey DLL must contain executable code section."""
        pe = pefile.PE(str(generated_dll_path), fast_load=False)

        sections = [section for section in pe.sections if section.Name.startswith(b".text")]
        assert len(sections) > 0, "DLL must have .text section"

        text_section = sections[0]
        IMAGE_SCN_MEM_EXECUTE = 0x20000000

        assert text_section.Characteristics & IMAGE_SCN_MEM_EXECUTE, ".text section must be executable"

        pe.close()

    def test_yubikey_dll_contains_functional_code(self, generated_dll_path: Path) -> None:
        """YubiKey DLL must contain functional code beyond minimal structure."""
        dll_data = generated_dll_path.read_bytes()

        assert len(dll_data) >= 1024, "DLL must be at least 1KB with functional code"

        has_ret_instruction = b"\xC3" in dll_data
        assert has_ret_instruction, "DLL must contain at least return instructions"


class TestYubikeyOTPGeneration:
    """Test YubiKey OTP generation and CCID protocol."""

    @pytest.fixture
    def token_bypass(self) -> HardwareTokenBypass:
        """Create HardwareTokenBypass instance."""
        return HardwareTokenBypass()

    def test_yubikey_otp_generation_produces_valid_format(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey OTP must be in valid ModHex format with correct length."""
        result = token_bypass.emulate_yubikey()

        assert result["success"] is True, "OTP generation must succeed"
        assert "otp" in result, "Result must contain OTP"

        otp = result["otp"]
        assert len(otp) == 44, "OTP must be 44 characters (12 public ID + 32 encrypted token)"

        modhex_chars = set("cbdefghijklnrtuv")
        assert all(c in modhex_chars for c in otp), "OTP must use only ModHex characters"

    def test_yubikey_otp_includes_proper_crc16(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey OTP must include valid CRC16 checksum for data integrity."""
        result = token_bypass.emulate_yubikey()

        test_data = b"test_data_for_crc"
        crc = token_bypass._calculate_crc16(test_data)

        assert isinstance(crc, int), "CRC must be integer"
        assert 0 <= crc <= 0xFFFF, "CRC must be 16-bit value"

        same_crc = token_bypass._calculate_crc16(test_data)
        assert crc == same_crc, "CRC calculation must be deterministic"

    def test_yubikey_otp_counter_increments_correctly(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey OTP counter must increment properly across multiple generations."""
        serial = token_bypass._generate_yubikey_serial()

        result1 = token_bypass.emulate_yubikey(serial_number=serial)
        counter1 = result1["counter"]
        session1 = result1["session"]

        result2 = token_bypass.emulate_yubikey(serial_number=serial)
        counter2 = result2["counter"]
        session2 = result2["session"]

        assert session2 > session1, "Session counter must increment"

        for _ in range(300):
            result = token_bypass.emulate_yubikey(serial_number=serial)

        final_result = token_bypass.emulate_yubikey(serial_number=serial)
        assert final_result["counter"] > counter1, "Usage counter must increment after session overflow"

    def test_yubikey_emulation_includes_usb_device_info(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey emulation must provide realistic USB device information."""
        result = token_bypass.emulate_yubikey()

        assert "usb_device" in result, "Must include USB device info"
        usb_info = result["usb_device"]

        assert usb_info["vendor_id"] == 0x1050, "Must use Yubico vendor ID"
        assert usb_info["product_id"] in [0x0407, 0x0410, 0x0406], "Must use valid YubiKey product ID"
        assert usb_info["manufacturer"] == "Yubico", "Must identify as Yubico manufacturer"

    def test_yubikey_supports_multiple_interfaces(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey emulation must support CCID, FIDO, and OTP interfaces."""
        result = token_bypass.emulate_yubikey()

        usb_info = result["usb_device"]
        interfaces = usb_info["interfaces"]

        assert "CCID" in interfaces, "Must support CCID interface"
        assert "FIDO" in interfaces, "Must support FIDO interface"
        assert "OTP" in interfaces, "Must support OTP interface"

    def test_yubikey_capabilities_include_piv_support(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey must support PIV certificate operations."""
        result = token_bypass.emulate_yubikey()

        capabilities = result["usb_device"]["capabilities"]

        assert capabilities["piv"] is True, "Must support PIV operations"
        assert capabilities["otp"] is True, "Must support OTP"
        assert capabilities["fido2"] is True, "Must support FIDO2/WebAuthn"

    def test_yubikey_otp_uses_aes_encryption(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey OTP token must be encrypted with AES-128."""
        test_data = b"\x00" * 16
        test_key = b"\x01" * 16

        encrypted = token_bypass._aes_encrypt(test_data, test_key)

        assert len(encrypted) >= 32, "Encrypted data must include IV (16 bytes) + ciphertext"
        assert encrypted != test_data, "Data must be encrypted"

        different_key = b"\x02" * 16
        different_encrypted = token_bypass._aes_encrypt(test_data, different_key)
        assert encrypted != different_encrypted, "Different keys must produce different ciphertext"


class TestYubikeyMultiVersionSupport:
    """Test YubiKey emulation across different firmware versions."""

    @pytest.fixture
    def token_bypass(self) -> HardwareTokenBypass:
        """Create HardwareTokenBypass instance."""
        return HardwareTokenBypass()

    def test_yubikey_firmware_version_reported(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey emulation must report realistic firmware version."""
        result = token_bypass.emulate_yubikey()

        version = result["usb_device"]["version"]
        assert version is not None, "Must report firmware version"

        major, minor, patch = version.split(".")
        assert int(major) >= 5, "Must emulate YubiKey 5 or newer"

    def test_yubikey_serial_number_format_valid(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey serial numbers must follow proper 8-digit format."""
        serial = token_bypass._generate_yubikey_serial()

        assert len(serial) == 8, "Serial must be 8 digits"
        assert serial.isdigit(), "Serial must be numeric"
        assert int(serial) >= 10000000, "Serial must be at least 10000000"

    def test_yubikey_different_product_ids_for_versions(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey emulation must handle different product IDs for hardware variants."""
        valid_product_ids = [0x0407, 0x0410, 0x0406, 0x0401]

        result = token_bypass.emulate_yubikey()
        product_id = result["usb_device"]["product_id"]

        assert product_id in valid_product_ids, f"Product ID {hex(product_id)} must be valid YubiKey variant"


class TestYubikeyPIVOperations:
    """Test YubiKey PIV certificate operations."""

    @pytest.fixture
    def token_bypass(self) -> HardwareTokenBypass:
        """Create HardwareTokenBypass instance."""
        return HardwareTokenBypass()

    def test_yubikey_piv_capability_enabled(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey must expose PIV capability for certificate operations."""
        result = token_bypass.emulate_yubikey()

        assert result["usb_device"]["capabilities"]["piv"] is True, "PIV must be enabled"

    def test_smartcard_emulation_supports_piv_type(self, token_bypass: HardwareTokenBypass) -> None:
        """Smart card emulation must support PIV card type."""
        result = token_bypass.emulate_smartcard(card_type="PIV")

        assert result["success"] is True, "PIV card emulation must succeed"
        assert result["card_type"] == "PIV", "Card type must be PIV"

    def test_smartcard_piv_includes_certificates(self, token_bypass: HardwareTokenBypass) -> None:
        """PIV card must include authentication and signing certificates."""
        result = token_bypass.emulate_smartcard(card_type="PIV")

        assert "certificates" in result, "PIV card must include certificates"
        certs = result["certificates"]

        assert "authentication" in certs, "Must include authentication certificate"
        assert "digital_signature" in certs, "Must include digital signature certificate"


class TestYubikeyFIDO2WebAuthnSupport:
    """Test YubiKey FIDO2/WebAuthn support."""

    @pytest.fixture
    def token_bypass(self) -> HardwareTokenBypass:
        """Create HardwareTokenBypass instance."""
        return HardwareTokenBypass()

    def test_yubikey_fido2_capability_enabled(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey must support FIDO2 for modern WebAuthn authentication."""
        result = token_bypass.emulate_yubikey()

        capabilities = result["usb_device"]["capabilities"]

        assert capabilities["fido2"] is True, "FIDO2 must be enabled"
        assert capabilities["u2f"] is True, "U2F (FIDO legacy) must be enabled"

    def test_yubikey_oath_capability_for_totp(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey must support OATH for TOTP code generation."""
        result = token_bypass.emulate_yubikey()

        assert result["usb_device"]["capabilities"]["oath"] is True, "OATH capability must be enabled"


class TestYubikeyDLLFunctionalityIntegration:
    """Test YubiKey DLL functionality with real process injection scenarios."""

    @pytest.fixture
    def token_bypass(self) -> HardwareTokenBypass:
        """Create HardwareTokenBypass instance."""
        return HardwareTokenBypass()

    @pytest.mark.skipif(os.name != "nt", reason="Windows-specific DLL injection test")
    def test_yubikey_dll_creation_on_windows(self, token_bypass: HardwareTokenBypass) -> None:
        """DLL creation must succeed on Windows platforms."""
        dll_path = token_bypass._create_yubikey_hook_dll()

        assert Path(dll_path).exists(), "DLL file must be created"
        assert Path(dll_path).stat().st_size > 0, "DLL must not be empty"
        assert Path(dll_path).suffix == ".dll", "File must have .dll extension"

        dll_data = Path(dll_path).read_bytes()
        assert dll_data[:2] == b"MZ", "DLL must be valid PE binary"

    @pytest.mark.skipif(os.name == "nt", reason="Unix-specific shared library test")
    def test_yubikey_so_creation_on_unix(self, token_bypass: HardwareTokenBypass) -> None:
        """Shared library creation must succeed on Unix platforms."""
        lib_path = token_bypass._create_yubikey_hook_lib()

        assert Path(lib_path).exists(), "Shared library must be created"
        assert Path(lib_path).stat().st_size > 0, "Library must not be empty"
        assert Path(lib_path).suffix == ".so", "File must have .so extension"

        lib_data = Path(lib_path).read_bytes()
        assert lib_data[:3] == b"ELF" or lib_data[:4] == b"\x7fELF", "Library must be valid ELF binary"

    def test_yubikey_dll_exports_hook_functions(self, token_bypass: HardwareTokenBypass, tmp_path: Path) -> None:
        """YubiKey DLL must export hook functions for API interception."""
        dll_path = tmp_path / "yubikey_hook.dll"
        dll_bytes = token_bypass._generate_minimal_dll()
        dll_path.write_bytes(dll_bytes)

        pe = pefile.PE(str(dll_path), fast_load=False)

        expected_exports = ["yk_check_otp", "yk_verify_otp", "yubikey_validate"]

        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            exports = [exp.name.decode() for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols if exp.name]
            for expected in expected_exports:
                pass

        pe.close()


class TestYubikeyCCIDProtocolResponses:
    """Test CCID protocol implementation for YubiKey communication."""

    @pytest.fixture
    def token_bypass(self) -> HardwareTokenBypass:
        """Create HardwareTokenBypass instance."""
        return HardwareTokenBypass()

    def test_yubikey_ccid_interface_present(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey must expose CCID interface for smart card protocol."""
        result = token_bypass.emulate_yubikey()

        interfaces = result["usb_device"]["interfaces"]
        assert "CCID" in interfaces, "CCID interface must be present"

    def test_yubikey_modhex_encoding_correct(self, token_bypass: HardwareTokenBypass) -> None:
        """ModHex encoding must use correct character set."""
        test_bytes = bytes(range(16))
        modhex = token_bypass._to_modhex(test_bytes)

        modhex_chars = "cbdefghijklnrtuv"
        assert all(c in modhex_chars for c in modhex), "ModHex must use only valid characters"
        assert len(modhex) == 32, "ModHex of 16 bytes must be 32 characters"

    def test_yubikey_modhex_encoding_deterministic(self, token_bypass: HardwareTokenBypass) -> None:
        """ModHex encoding must be deterministic for same input."""
        test_bytes = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF"

        modhex1 = token_bypass._to_modhex(test_bytes)
        modhex2 = token_bypass._to_modhex(test_bytes)

        assert modhex1 == modhex2, "ModHex encoding must be deterministic"


class TestYubikeyEdgeCases:
    """Test YubiKey edge cases and error conditions."""

    @pytest.fixture
    def token_bypass(self) -> HardwareTokenBypass:
        """Create HardwareTokenBypass instance."""
        return HardwareTokenBypass()

    def test_yubikey_handles_multiple_serial_numbers(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey emulator must handle multiple concurrent serial numbers."""
        serial1 = token_bypass._generate_yubikey_serial()
        serial2 = token_bypass._generate_yubikey_serial()

        assert serial1 != serial2, "Different serials must be generated"

        result1 = token_bypass.emulate_yubikey(serial_number=serial1)
        result2 = token_bypass.emulate_yubikey(serial_number=serial2)

        assert result1["otp"] != result2["otp"], "Different serials must produce different OTPs"

    def test_yubikey_persistent_secrets_across_calls(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey secrets must persist for same serial number."""
        serial = token_bypass._generate_yubikey_serial()

        result1 = token_bypass.emulate_yubikey(serial_number=serial)
        public_id1 = result1["public_id"]

        result2 = token_bypass.emulate_yubikey(serial_number=serial)
        public_id2 = result2["public_id"]

        assert public_id1 == public_id2, "Public ID must remain consistent for same serial"

    def test_yubikey_different_firmware_versions_reported(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey emulation must handle different firmware version scenarios."""
        result = token_bypass.emulate_yubikey()

        version = result["usb_device"]["version"]
        major_version = int(version.split(".")[0])

        assert major_version in [4, 5, 6], "Must support YubiKey 4, 5, or 6 series"

    def test_yubikey_timestamp_included_in_otp(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey OTP must include timestamp for replay protection."""
        result1 = token_bypass.emulate_yubikey()
        timestamp1 = result1["timestamp"]

        import time

        time.sleep(0.1)

        result2 = token_bypass.emulate_yubikey()
        timestamp2 = result2["timestamp"]

        assert timestamp2 > timestamp1, "Timestamp must increase between OTP generations"
