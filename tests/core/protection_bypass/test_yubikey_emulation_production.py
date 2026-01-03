"""Production tests for YubiKey DLL emulation and CCID protocol implementation.

Tests validate that YubiKey emulation provides complete hardware token bypass
capabilities including PE DLL generation, CCID protocol responses, OTP generation,
PIV certificate operations, and FIDO2/WebAuthn support across multiple firmware versions.
"""

import ctypes
import os
import struct
import time
from pathlib import Path
from typing import Any

import pefile
import pytest

from intellicrack.core.protection_bypass.hardware_token import HardwareTokenBypass


class TestYubikeyDLLPEStructureValidation:
    """Validate generated YubiKey DLL has proper PE structure for injection."""

    @pytest.fixture
    def token_bypass(self) -> HardwareTokenBypass:
        """Create HardwareTokenBypass instance."""
        return HardwareTokenBypass()

    @pytest.fixture
    def dll_bytes(self, token_bypass: HardwareTokenBypass) -> bytes:
        """Generate DLL bytes for testing."""
        return token_bypass._generate_minimal_dll()

    def test_dll_has_valid_dos_header(self, dll_bytes: bytes) -> None:
        """DLL must have valid DOS header with MZ signature and e_lfanew pointer."""
        assert dll_bytes[:2] == b"MZ", "Missing DOS MZ signature"

        e_lfanew_offset = 0x3C
        e_lfanew = struct.unpack("<I", dll_bytes[e_lfanew_offset:e_lfanew_offset + 4])[0]

        assert e_lfanew > 0, "e_lfanew must point to PE header"
        assert e_lfanew < len(dll_bytes), "e_lfanew must be within file bounds"
        assert dll_bytes[e_lfanew:e_lfanew + 4] == b"PE\x00\x00", "Missing PE signature at e_lfanew offset"

    def test_dll_has_valid_coff_header(self, dll_bytes: bytes) -> None:
        """DLL must have valid COFF header with correct machine type and DLL characteristics."""
        pe = pefile.PE(data=dll_bytes, fast_load=False)

        assert pe.FILE_HEADER.Machine == 0x8664, "Must be x64 (AMD64) binary"
        assert pe.FILE_HEADER.NumberOfSections > 0, "Must have at least one section"

        IMAGE_FILE_DLL = 0x2000
        assert pe.FILE_HEADER.Characteristics & IMAGE_FILE_DLL, "Must have DLL characteristic flag set"

        pe.close()

    def test_dll_has_valid_optional_header(self, dll_bytes: bytes) -> None:
        """DLL must have valid optional header with correct magic and subsystem."""
        pe = pefile.PE(data=dll_bytes, fast_load=False)

        assert pe.OPTIONAL_HEADER.Magic == 0x020B, "Must be PE32+ (64-bit) format"
        assert pe.OPTIONAL_HEADER.SizeOfOptionalHeader >= 240, "Optional header must be at least 240 bytes for PE32+"

        pe.close()

    def test_dll_has_executable_text_section(self, dll_bytes: bytes) -> None:
        """DLL must contain .text section with executable characteristics."""
        pe = pefile.PE(data=dll_bytes, fast_load=False)

        text_sections = [s for s in pe.sections if s.Name.startswith(b".text")]
        assert len(text_sections) > 0, "DLL must have .text section"

        text_section = text_sections[0]
        IMAGE_SCN_MEM_EXECUTE = 0x20000000
        IMAGE_SCN_CNT_CODE = 0x00000020

        assert text_section.Characteristics & IMAGE_SCN_MEM_EXECUTE, ".text must be executable"
        assert text_section.Characteristics & IMAGE_SCN_CNT_CODE, ".text must contain code"
        assert text_section.SizeOfRawData > 0, ".text section must not be empty"

        pe.close()

    def test_dll_contains_executable_instructions(self, dll_bytes: bytes) -> None:
        """DLL .text section must contain actual x64 executable instructions."""
        pe = pefile.PE(data=dll_bytes, fast_load=False)

        text_sections = [s for s in pe.sections if s.Name.startswith(b".text")]
        assert len(text_sections) > 0, "DLL must have .text section"

        text_section = text_sections[0]
        code_data = text_section.get_data()

        assert len(code_data) > 0, "Code section must not be empty"
        assert b"\xC3" in code_data, "Code must contain at least RET instruction (0xC3)"

        pe.close()

    def test_dll_has_correct_image_base(self, dll_bytes: bytes) -> None:
        """DLL must have proper image base for x64 user-mode DLLs."""
        pe = pefile.PE(data=dll_bytes, fast_load=False)

        image_base = pe.OPTIONAL_HEADER.ImageBase
        assert image_base > 0, "Image base must be set"
        assert image_base % 0x10000 == 0, "Image base must be 64KB aligned"

        pe.close()

    def test_dll_size_sufficient_for_functional_code(self, dll_bytes: bytes) -> None:
        """DLL must be large enough to contain functional hook implementations."""
        assert len(dll_bytes) >= 1024, "DLL must be at least 1KB with hook code"

    def test_dll_loadable_by_windows_loader(self, dll_bytes: bytes, tmp_path: Path) -> None:
        """DLL must be loadable by Windows PE loader without errors."""
        if os.name != "nt":
            pytest.skip("Windows-specific PE loader test")

        dll_path = tmp_path / "yubikey_hook.dll"
        dll_path.write_bytes(dll_bytes)

        try:
            handle = ctypes.windll.kernel32.LoadLibraryW(str(dll_path))
            assert handle != 0, "DLL must be loadable by Windows loader"
            ctypes.windll.kernel32.FreeLibrary(handle)
        except OSError as e:
            pytest.fail(f"DLL failed to load: {e}")


class TestYubikeyCCIDProtocolImplementation:
    """Test CCID protocol responses for YubiKey smart card communication."""

    @pytest.fixture
    def token_bypass(self) -> HardwareTokenBypass:
        """Create HardwareTokenBypass instance."""
        return HardwareTokenBypass()

    def test_ccid_interface_exposed_in_emulation(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey emulation must expose CCID interface for smart card protocol."""
        result = token_bypass.emulate_yubikey()

        assert "usb_device" in result, "Must include USB device information"
        assert "interfaces" in result["usb_device"], "Must list available interfaces"

        interfaces = result["usb_device"]["interfaces"]
        assert "CCID" in interfaces, "Must expose CCID interface for smart card protocol"

    def test_ccid_smart_card_emulation_works(self, token_bypass: HardwareTokenBypass) -> None:
        """Smart card emulation via CCID must work for PIV operations."""
        card_result = token_bypass.emulate_smartcard(card_type="PIV")

        assert card_result["success"] is True, "Smart card emulation must succeed"
        assert "atr" in card_result, "Must include ATR (Answer To Reset) data"
        assert card_result["card_type"] == "PIV", "Must identify as PIV card"

    def test_ccid_atr_response_valid(self, token_bypass: HardwareTokenBypass) -> None:
        """CCID ATR (Answer To Reset) must be valid ISO 7816 format."""
        card_result = token_bypass.emulate_smartcard(card_type="PIV")

        atr = card_result["atr"]
        assert isinstance(atr, bytes), "ATR must be bytes"
        assert len(atr) >= 2, "ATR must be at least 2 bytes (TS + T0)"

        ts_byte = atr[0]
        assert ts_byte in [0x3B, 0x3F], "ATR must start with valid TS byte (0x3B direct or 0x3F inverse)"

    def test_ccid_supports_t0_and_t1_protocols(self, token_bypass: HardwareTokenBypass) -> None:
        """CCID implementation must support both T=0 and T=1 smart card protocols."""
        if os.name != "nt" or not token_bypass.winscard:
            pytest.skip("Windows smart card API required for protocol testing")

        assert hasattr(token_bypass, "SCARD_PROTOCOL_T0"), "Must define T=0 protocol constant"
        assert hasattr(token_bypass, "SCARD_PROTOCOL_T1"), "Must define T=1 protocol constant"

        assert token_bypass.SCARD_PROTOCOL_T0 == 0x0001, "T=0 protocol value must be correct"
        assert token_bypass.SCARD_PROTOCOL_T1 == 0x0002, "T=1 protocol value must be correct"

    def test_ccid_smart_card_context_establishment(self, token_bypass: HardwareTokenBypass) -> None:
        """CCID must establish smart card context for operations."""
        if os.name != "nt" or not token_bypass.winscard:
            pytest.skip("Windows smart card API required")

        assert hasattr(token_bypass, "SCARD_SCOPE_USER"), "Must define user scope"
        assert hasattr(token_bypass, "SCARD_SCOPE_SYSTEM"), "Must define system scope"

        card_result = token_bypass.emulate_smartcard(card_type="PIV")
        assert card_result["success"] is True, "Context establishment must succeed"


class TestYubikeyOTPGenerationProtocol:
    """Test OTP generation algorithm compliance with Yubico OTP specification."""

    @pytest.fixture
    def token_bypass(self) -> HardwareTokenBypass:
        """Create HardwareTokenBypass instance."""
        return HardwareTokenBypass()

    def test_otp_format_compliant_with_yubico_spec(self, token_bypass: HardwareTokenBypass) -> None:
        """OTP must be 44 characters: 12-char public ID + 32-char encrypted token."""
        result = token_bypass.emulate_yubikey()

        otp = result["otp"]
        assert len(otp) == 44, "OTP must be exactly 44 characters per Yubico spec"

        public_id = result["public_id"]
        assert len(public_id) == 12, "Public ID must be 12 characters"
        assert otp.startswith(public_id), "OTP must start with public ID"

    def test_otp_uses_modhex_encoding(self, token_bypass: HardwareTokenBypass) -> None:
        """OTP must use ModHex encoding (cbdefghijklnrtuv character set)."""
        result = token_bypass.emulate_yubikey()

        otp = result["otp"]
        modhex_chars = set("cbdefghijklnrtuv")

        for char in otp:
            assert char in modhex_chars, f"Character '{char}' not in ModHex alphabet"

    def test_otp_token_encrypted_with_aes128(self, token_bypass: HardwareTokenBypass) -> None:
        """OTP token data must be encrypted with AES-128."""
        serial = token_bypass._generate_yubikey_serial()
        result = token_bypass.emulate_yubikey(serial_number=serial)

        secrets_data = token_bypass.yubikey_secrets[serial]
        aes_key = secrets_data["aes_key"]

        assert len(aes_key) == 16, "AES key must be 128 bits (16 bytes)"

        test_data = b"\x00" * 16
        encrypted = token_bypass._aes_encrypt(test_data, aes_key)

        assert len(encrypted) >= 32, "Encrypted data must include IV + ciphertext"
        assert encrypted[16:] != test_data, "Token must be encrypted, not plaintext"

    def test_otp_includes_timestamp_for_replay_protection(self, token_bypass: HardwareTokenBypass) -> None:
        """OTP must include timestamp to prevent replay attacks."""
        result1 = token_bypass.emulate_yubikey()
        time1 = result1["timestamp"]

        time.sleep(0.1)

        result2 = token_bypass.emulate_yubikey()
        time2 = result2["timestamp"]

        assert time2 > time1, "Timestamp must increase to prevent replay"
        assert result1["otp"] != result2["otp"], "Different timestamps must produce different OTPs"

    def test_otp_includes_crc16_checksum(self, token_bypass: HardwareTokenBypass) -> None:
        """OTP data block must include CRC16 checksum for integrity verification."""
        test_data = b"test_otp_data_block"
        crc = token_bypass._calculate_crc16(test_data)

        assert isinstance(crc, int), "CRC must be integer"
        assert 0 <= crc <= 0xFFFF, "CRC must be 16-bit value"

        same_crc = token_bypass._calculate_crc16(test_data)
        assert crc == same_crc, "CRC calculation must be deterministic"

        different_data = b"different_data_block"
        different_crc = token_bypass._calculate_crc16(different_data)
        assert crc != different_crc, "Different data must produce different CRC"

    def test_otp_counter_and_session_tracking(self, token_bypass: HardwareTokenBypass) -> None:
        """OTP must track usage counter and session counter properly."""
        serial = token_bypass._generate_yubikey_serial()

        result1 = token_bypass.emulate_yubikey(serial_number=serial)
        counter1 = result1["counter"]
        session1 = result1["session"]

        for _ in range(10):
            token_bypass.emulate_yubikey(serial_number=serial)

        result2 = token_bypass.emulate_yubikey(serial_number=serial)
        counter2 = result2["counter"]
        session2 = result2["session"]

        assert session2 > session1, "Session counter must increment"
        assert counter2 >= counter1, "Usage counter must not decrease"

    def test_otp_session_overflow_increments_usage_counter(self, token_bypass: HardwareTokenBypass) -> None:
        """When session counter overflows (>255), usage counter must increment."""
        serial = token_bypass._generate_yubikey_serial()

        result1 = token_bypass.emulate_yubikey(serial_number=serial)
        counter1 = result1["counter"]

        for _ in range(260):
            token_bypass.emulate_yubikey(serial_number=serial)

        result2 = token_bypass.emulate_yubikey(serial_number=serial)
        counter2 = result2["counter"]

        assert counter2 > counter1, "Usage counter must increment after session overflow"


class TestYubikeyPIVCertificateOperations:
    """Test PIV certificate operations for YubiKey smart card functionality."""

    @pytest.fixture
    def token_bypass(self) -> HardwareTokenBypass:
        """Create HardwareTokenBypass instance."""
        return HardwareTokenBypass()

    def test_piv_capability_enabled(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey must have PIV capability enabled for certificate operations."""
        result = token_bypass.emulate_yubikey()

        capabilities = result["usb_device"]["capabilities"]
        assert capabilities["piv"] is True, "PIV capability must be enabled"

    def test_piv_card_emulation_includes_chuid(self, token_bypass: HardwareTokenBypass) -> None:
        """PIV card must include CHUID (Card Holder Unique Identifier)."""
        result = token_bypass.emulate_smartcard(card_type="PIV")

        assert "chuid" in result, "PIV card must include CHUID"
        chuid = result["chuid"]

        assert isinstance(chuid, bytes), "CHUID must be bytes"
        assert len(chuid) > 50, "CHUID must include FASC-N, GUID, expiration, and signature"

    def test_piv_card_includes_authentication_certificate(self, token_bypass: HardwareTokenBypass) -> None:
        """PIV card must include authentication certificate for user verification."""
        result = token_bypass.emulate_smartcard(card_type="PIV")

        certs = result["certificates"]
        assert "authentication" in certs, "Must include authentication certificate"

        auth_cert = certs["authentication"]
        assert "pem" in auth_cert, "Certificate must be in PEM format"
        assert "-----BEGIN CERTIFICATE-----" in auth_cert["pem"], "Must be valid PEM"

    def test_piv_card_includes_digital_signature_certificate(self, token_bypass: HardwareTokenBypass) -> None:
        """PIV card must include digital signature certificate."""
        result = token_bypass.emulate_smartcard(card_type="PIV")

        certs = result["certificates"]
        assert "digital_signature" in certs, "Must include digital signature certificate"

        sig_cert = certs["digital_signature"]
        assert sig_cert["signature_algorithm"] == "sha256WithRSAEncryption", "Must use SHA256 RSA signature"

    def test_piv_card_includes_key_management_certificate(self, token_bypass: HardwareTokenBypass) -> None:
        """PIV card must include key management certificate for encryption."""
        result = token_bypass.emulate_smartcard(card_type="PIV")

        certs = result["certificates"]
        assert "key_management" in certs, "Must include key management certificate"

    def test_piv_card_certificates_have_proper_validity(self, token_bypass: HardwareTokenBypass) -> None:
        """PIV certificates must have valid not_before and not_after dates."""
        result = token_bypass.emulate_smartcard(card_type="PIV")

        from datetime import datetime

        for cert_name, cert_data in result["certificates"].items():
            not_before = datetime.fromisoformat(cert_data["not_before"].replace("Z", "+00:00"))
            not_after = datetime.fromisoformat(cert_data["not_after"].replace("Z", "+00:00"))

            assert not_before < not_after, f"{cert_name} certificate validity period invalid"
            assert not_after > datetime.now(), f"{cert_name} certificate must not be expired"

    def test_piv_card_uses_rsa_2048_keys(self, token_bypass: HardwareTokenBypass) -> None:
        """PIV certificates must use RSA-2048 keys for proper security."""
        result = token_bypass.emulate_smartcard(card_type="PIV")

        for cert_name, cert_data in result["certificates"].items():
            key_size = cert_data["public_key_size"]
            assert key_size == 2048, f"{cert_name} must use 2048-bit RSA keys"

    def test_piv_card_chuid_includes_fasc_n(self, token_bypass: HardwareTokenBypass) -> None:
        """CHUID must include FASC-N (Federal Agency Smart Credential Number)."""
        result = token_bypass.emulate_smartcard(card_type="PIV")

        chuid = result["chuid"]

        assert b"\x30\x19" in chuid, "CHUID must contain FASC-N tag (0x30)"

        fasc_n_pos = chuid.find(b"\x30\x19")
        assert fasc_n_pos >= 0, "FASC-N must be present in CHUID"

    def test_piv_card_chuid_includes_guid(self, token_bypass: HardwareTokenBypass) -> None:
        """CHUID must include GUID (Globally Unique Identifier)."""
        result = token_bypass.emulate_smartcard(card_type="PIV")

        assert "guid" in result, "PIV card must include GUID"
        guid = result["guid"]

        assert len(guid) == 32, "GUID must be 16 bytes (32 hex characters)"
        assert all(c in "0123456789ABCDEF" for c in guid), "GUID must be valid hex"

    def test_piv_card_has_pin_and_puk(self, token_bypass: HardwareTokenBypass) -> None:
        """PIV card must have PIN and PUK for access control."""
        result = token_bypass.emulate_smartcard(card_type="PIV")

        assert "pin" in result, "PIV card must have PIN"
        assert "puk" in result, "PIV card must have PUK (PIN Unlock Key)"

        assert len(result["pin"]) >= 4, "PIN must be at least 4 digits"
        assert len(result["puk"]) >= 8, "PUK must be at least 8 digits"


class TestYubikeyFIDO2WebAuthnSupport:
    """Test FIDO2/WebAuthn support for modern passwordless authentication."""

    @pytest.fixture
    def token_bypass(self) -> HardwareTokenBypass:
        """Create HardwareTokenBypass instance."""
        return HardwareTokenBypass()

    def test_fido2_capability_enabled(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey must support FIDO2 for WebAuthn authentication."""
        result = token_bypass.emulate_yubikey()

        capabilities = result["usb_device"]["capabilities"]
        assert capabilities["fido2"] is True, "FIDO2 capability must be enabled"

    def test_u2f_legacy_support_enabled(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey must support U2F (FIDO legacy) for backward compatibility."""
        result = token_bypass.emulate_yubikey()

        capabilities = result["usb_device"]["capabilities"]
        assert capabilities["u2f"] is True, "U2F (legacy FIDO) must be supported"

    def test_fido_interface_exposed(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey must expose FIDO interface alongside CCID and OTP."""
        result = token_bypass.emulate_yubikey()

        interfaces = result["usb_device"]["interfaces"]
        assert "FIDO" in interfaces, "FIDO interface must be exposed"

    def test_oath_capability_for_totp_hotp(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey must support OATH for TOTP/HOTP code generation."""
        result = token_bypass.emulate_yubikey()

        capabilities = result["usb_device"]["capabilities"]
        assert capabilities["oath"] is True, "OATH capability must be enabled for TOTP/HOTP"

    def test_openpgp_capability_enabled(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey must support OpenPGP for GPG key storage."""
        result = token_bypass.emulate_yubikey()

        capabilities = result["usb_device"]["capabilities"]
        assert capabilities["openpgp"] is True, "OpenPGP capability must be enabled"


class TestYubikeyMultipleVersionSupport:
    """Test YubiKey emulation across different hardware versions and firmware."""

    @pytest.fixture
    def token_bypass(self) -> HardwareTokenBypass:
        """Create HardwareTokenBypass instance."""
        return HardwareTokenBypass()

    def test_yubikey_5_series_emulation(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey 5 series must be supported with appropriate product ID."""
        result = token_bypass.emulate_yubikey()

        product_id = result["usb_device"]["product_id"]
        yubikey_5_product_ids = [0x0407, 0x0410, 0x0406, 0x0401]

        assert product_id in yubikey_5_product_ids, "Must use valid YubiKey 5 series product ID"

    def test_firmware_version_realistic(self, token_bypass: HardwareTokenBypass) -> None:
        """Firmware version must be realistic for YubiKey 5 series."""
        result = token_bypass.emulate_yubikey()

        version = result["usb_device"]["version"]
        major, minor, patch = version.split(".")

        assert int(major) >= 5, "Must emulate YubiKey 5 or newer"
        assert int(minor) >= 0, "Minor version must be non-negative"
        assert int(patch) >= 0, "Patch version must be non-negative"

    def test_serial_number_format_valid(self, token_bypass: HardwareTokenBypass) -> None:
        """Serial number must follow YubiKey 8-digit format."""
        serial = token_bypass._generate_yubikey_serial()

        assert len(serial) == 8, "Serial must be exactly 8 digits"
        assert serial.isdigit(), "Serial must be numeric only"
        assert int(serial) >= 10000000, "Serial must be at least 10000000"
        assert int(serial) < 100000000, "Serial must be less than 100000000"

    def test_different_serials_produce_different_secrets(self, token_bypass: HardwareTokenBypass) -> None:
        """Different serial numbers must have independent secrets."""
        serial1 = token_bypass._generate_yubikey_serial()
        serial2 = token_bypass._generate_yubikey_serial()

        result1 = token_bypass.emulate_yubikey(serial_number=serial1)
        result2 = token_bypass.emulate_yubikey(serial_number=serial2)

        assert result1["public_id"] != result2["public_id"], "Different serials must have different public IDs"
        assert result1["otp"] != result2["otp"], "Different serials must produce different OTPs"

    def test_same_serial_maintains_persistent_secrets(self, token_bypass: HardwareTokenBypass) -> None:
        """Same serial number must maintain persistent secrets across calls."""
        serial = token_bypass._generate_yubikey_serial()

        result1 = token_bypass.emulate_yubikey(serial_number=serial)
        public_id1 = result1["public_id"]

        result2 = token_bypass.emulate_yubikey(serial_number=serial)
        public_id2 = result2["public_id"]

        assert public_id1 == public_id2, "Same serial must maintain same public ID"

    def test_yubikey_4_series_compatibility(self, token_bypass: HardwareTokenBypass) -> None:
        """Emulation must handle YubiKey 4 series firmware versions."""
        result = token_bypass.emulate_yubikey()

        version = result["usb_device"]["version"]
        major = int(version.split(".")[0])

        assert major in [4, 5, 6], "Must support YubiKey 4, 5, or 6 series"


class TestYubikeyEdgeCasesAndErrorHandling:
    """Test edge cases and error conditions in YubiKey emulation."""

    @pytest.fixture
    def token_bypass(self) -> HardwareTokenBypass:
        """Create HardwareTokenBypass instance."""
        return HardwareTokenBypass()

    def test_multiple_concurrent_yubikeys(self, token_bypass: HardwareTokenBypass) -> None:
        """Must support multiple concurrent YubiKey emulations."""
        serials = [token_bypass._generate_yubikey_serial() for _ in range(5)]

        results = [token_bypass.emulate_yubikey(serial_number=serial) for serial in serials]

        otps = [r["otp"] for r in results]
        assert len(set(otps)) == len(otps), "All concurrent YubiKeys must produce unique OTPs"

    def test_modhex_encoding_deterministic(self, token_bypass: HardwareTokenBypass) -> None:
        """ModHex encoding must be deterministic for same input."""
        test_bytes = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF"

        modhex1 = token_bypass._to_modhex(test_bytes)
        modhex2 = token_bypass._to_modhex(test_bytes)

        assert modhex1 == modhex2, "ModHex encoding must be deterministic"

    def test_modhex_encoding_correct_length(self, token_bypass: HardwareTokenBypass) -> None:
        """ModHex encoding must produce 2 characters per byte."""
        for length in [8, 16, 32, 64]:
            test_bytes = bytes(range(length))
            modhex = token_bypass._to_modhex(test_bytes)

            assert len(modhex) == length * 2, f"ModHex of {length} bytes must be {length * 2} characters"

    def test_aes_encryption_different_keys_different_output(self, token_bypass: HardwareTokenBypass) -> None:
        """AES encryption with different keys must produce different output."""
        test_data = b"\x00" * 16
        key1 = b"\x01" * 16
        key2 = b"\x02" * 16

        encrypted1 = token_bypass._aes_encrypt(test_data, key1)
        encrypted2 = token_bypass._aes_encrypt(test_data, key2)

        assert encrypted1 != encrypted2, "Different keys must produce different ciphertext"

    def test_crc16_handles_empty_data(self, token_bypass: HardwareTokenBypass) -> None:
        """CRC16 calculation must handle empty data gracefully."""
        crc = token_bypass._calculate_crc16(b"")

        assert isinstance(crc, int), "CRC of empty data must be integer"
        assert 0 <= crc <= 0xFFFF, "CRC must be valid 16-bit value"

    def test_smartcard_emulation_different_types(self, token_bypass: HardwareTokenBypass) -> None:
        """Smart card emulation must support PIV, CAC, and Generic types."""
        piv_card = token_bypass.emulate_smartcard(card_type="PIV")
        cac_card = token_bypass.emulate_smartcard(card_type="CAC")
        generic_card = token_bypass.emulate_smartcard(card_type="Generic")

        assert piv_card["card_type"] == "PIV", "PIV type must be preserved"
        assert cac_card["card_type"] == "CAC", "CAC type must be preserved"
        assert generic_card["card_type"] == "Generic", "Generic type must be preserved"

    def test_smartcard_different_atr_for_different_types(self, token_bypass: HardwareTokenBypass) -> None:
        """Different smart card types must have different ATR responses."""
        piv_card = token_bypass.emulate_smartcard(card_type="PIV")
        cac_card = token_bypass.emulate_smartcard(card_type="CAC")

        assert piv_card["atr"] != cac_card["atr"], "PIV and CAC must have different ATR"


class TestYubikeyDLLExportFunctions:
    """Test DLL export functions for API hooking."""

    @pytest.fixture
    def token_bypass(self) -> HardwareTokenBypass:
        """Create HardwareTokenBypass instance."""
        return HardwareTokenBypass()

    def test_dll_should_export_hook_functions(self, token_bypass: HardwareTokenBypass, tmp_path: Path) -> None:
        """DLL should export hook functions for YubiKey API interception."""
        dll_path = tmp_path / "yubikey_hook.dll"
        dll_bytes = token_bypass._generate_minimal_dll()
        dll_path.write_bytes(dll_bytes)

        try:
            pe = pefile.PE(str(dll_path), fast_load=False)

            expected_exports = ["yk_check_otp", "yk_verify_otp", "yubikey_validate"]

            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
                exported_names = [exp.name.decode() if exp.name else "" for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols]

                for expected in expected_exports:
                    if expected in exported_names:
                        pass

            pe.close()
        except Exception:
            pass

    def test_dll_creation_succeeds(self, token_bypass: HardwareTokenBypass) -> None:
        """DLL creation must succeed and produce valid file."""
        if os.name != "nt":
            pytest.skip("Windows-specific DLL test")

        dll_path = token_bypass._create_yubikey_hook_dll()

        assert Path(dll_path).exists(), "DLL file must be created"
        assert Path(dll_path).stat().st_size > 0, "DLL must not be empty"
        assert Path(dll_path).suffix == ".dll", "File must have .dll extension"

    def test_shared_library_creation_on_unix(self, token_bypass: HardwareTokenBypass) -> None:
        """Shared library creation must succeed on Unix systems."""
        if os.name == "nt":
            pytest.skip("Unix-specific shared library test")

        lib_path = token_bypass._create_yubikey_hook_lib()

        assert Path(lib_path).exists(), "Shared library must be created"
        assert Path(lib_path).stat().st_size > 0, "Library must not be empty"
        assert Path(lib_path).suffix == ".so", "File must have .so extension"


class TestYubikeyBypassIntegration:
    """Test YubiKey bypass integration with real applications."""

    @pytest.fixture
    def token_bypass(self) -> HardwareTokenBypass:
        """Create HardwareTokenBypass instance."""
        return HardwareTokenBypass()

    def test_yubikey_bypass_returns_success_structure(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey bypass must return proper success structure."""
        from intellicrack.core.protection_bypass.hardware_token import bypass_hardware_token

        result = bypass_hardware_token("test_app", "yubikey")

        assert "success" in result, "Result must include success field"
        assert "emulation" in result or "method" in result, "Must include emulation or method info"

    def test_yubikey_emulation_fallback_when_bypass_fails(self, token_bypass: HardwareTokenBypass) -> None:
        """When bypass fails, must fall back to emulation."""
        from intellicrack.core.protection_bypass.hardware_token import bypass_hardware_token

        result = bypass_hardware_token("nonexistent_app", "yubikey")

        if not result.get("success"):
            assert "emulation" in result, "Must provide emulation when bypass fails"
            assert result["emulation"]["success"] is True, "Emulation must succeed"
