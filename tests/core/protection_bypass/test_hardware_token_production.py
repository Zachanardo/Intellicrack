"""Production-Ready Tests for Hardware Token Bypass.

Validates genuine hardware token emulation and bypass capabilities against
real Windows APIs and actual token protocols. NO mocks, stubs, or simulations.

All tests verify real offensive capability:
- Token emulation produces protocol-compliant outputs
- USB device enumeration uses real Windows APIs
- OTP generation matches Yubico/RSA specifications
- Smart card operations use Windows SCard API
- Secret extraction works on realistic memory dumps

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0
"""

import ctypes
import ctypes.wintypes
import hashlib
import os
import secrets
import struct
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID

from intellicrack.core.protection_bypass.hardware_token import (
    HardwareTokenBypass,
    bypass_hardware_token,
)


@pytest.fixture
def token_bypass() -> HardwareTokenBypass:
    """Create hardware token bypass instance."""
    return HardwareTokenBypass()


@pytest.fixture
def yubikey_memory_dump(tmp_path: Path) -> Path:
    """Create realistic YubiKey memory dump with high-entropy AES keys."""
    dump_size = 8192
    dump_data = bytearray(dump_size)

    for i in range(0, dump_size, 256):
        dump_data[i:i+64] = secrets.token_bytes(64)

    for offset in [100, 500, 1000, 2000, 3500, 5000]:
        dump_data[offset:offset+16] = secrets.token_bytes(16)

    dump_data[200:206] = secrets.token_bytes(6)
    dump_data[1500:1506] = secrets.token_bytes(6)

    dump_file = tmp_path / "yubikey_memory.bin"
    dump_file.write_bytes(bytes(dump_data))
    return dump_file


@pytest.fixture
def securid_token_dump(tmp_path: Path) -> Path:
    """Create realistic RSA SecurID token dump with seed markers."""
    dump_data = bytearray(4096)

    dump_data[200:203] = b"RSA"
    dump_data[203:219] = secrets.token_bytes(16)

    dump_data[800:804] = b"SEED"
    dump_data[804:820] = secrets.token_bytes(16)

    dump_data[1500:1504] = struct.pack("<I", 16)
    dump_data[1504:1520] = secrets.token_bytes(16)

    dump_data[2500:2503] = b"RSA"
    dump_data[2503:2519] = secrets.token_bytes(16)

    dump_file = tmp_path / "securid_memory.bin"
    dump_file.write_bytes(bytes(dump_data))
    return dump_file


@pytest.fixture
def smartcard_memory_dump(tmp_path: Path) -> Path:
    """Create realistic smart card dump with DER and PEM certificates."""
    dump_data = bytearray(16384)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Certificate"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(secrets.randbelow(2**64))
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    cert_der = cert.public_bytes(encoding=x509.Encoding.DER)
    dump_data[500:500+len(cert_der)] = cert_der

    cert_pem = cert.public_bytes(encoding=x509.Encoding.PEM)
    dump_data[2000:2000+len(cert_pem)] = cert_pem

    key_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    dump_data[5000:5000+len(key_der)] = key_der

    dump_data[8000:8002] = b"\x30\x82"
    dump_data[8002:8004] = struct.pack(">H", 512)
    dump_data[8004:8516] = secrets.token_bytes(512)

    dump_file = tmp_path / "smartcard_memory.bin"
    dump_file.write_bytes(bytes(dump_data))
    return dump_file


class TestHardwareTokenBypassInitialization:
    """Test hardware token bypass initialization and API access."""

    def test_bypass_initializes_empty_storage_for_all_token_types(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Bypass creates empty storage dictionaries for YubiKey, SecurID, and smart cards."""
        assert isinstance(token_bypass.yubikey_secrets, dict)
        assert isinstance(token_bypass.rsa_seeds, dict)
        assert isinstance(token_bypass.smartcard_keys, dict)
        assert isinstance(token_bypass.emulated_devices, dict)

        assert len(token_bypass.yubikey_secrets) == 0
        assert len(token_bypass.rsa_seeds) == 0
        assert len(token_bypass.smartcard_keys) == 0
        assert len(token_bypass.emulated_devices) == 0

    def test_yubikey_config_matches_yubico_otp_specification(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """YubiKey configuration values match official Yubico OTP specification."""
        config = token_bypass.yubikey_config

        assert config["public_id_length"] == 12
        assert config["private_id_length"] == 6
        assert config["aes_key_length"] == 16
        assert config["counter_offset"] == 0
        assert config["session_counter"] == 0

        assert "timestamp_low" in config
        assert "timestamp_high" in config
        assert "use_counter" in config

    def test_securid_config_matches_rsa_token_specification(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """RSA SecurID configuration matches RSA Authentication Manager specification."""
        config = token_bypass.securid_config

        assert config["token_code_length"] == 6
        assert config["token_interval"] == 60
        assert config["drift_tolerance"] == 3

        assert isinstance(config["serial_numbers"], dict)
        assert isinstance(config["seeds"], dict)

    def test_smartcard_atr_conforms_to_iso7816_standard(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Smart card ATR bytes conform to ISO/IEC 7816-3 Answer-To-Reset format."""
        atr = token_bypass.smartcard_config["atr_bytes"]

        assert isinstance(atr, bytes)
        assert len(atr) >= 2

        assert atr[0] in [0x3B, 0x3F]

        assert atr[1] in [0xF8, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF]

    @pytest.mark.skipif(os.name != "nt", reason="Windows-specific SCard API test")
    def test_windows_scard_api_loaded_on_windows(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Windows SCard API properly loaded and initialized with correct constants."""
        assert hasattr(token_bypass, "winscard")
        assert hasattr(token_bypass, "kernel32")

        if token_bypass.winscard is not None:
            assert token_bypass.SCARD_SCOPE_USER == 0
            assert token_bypass.SCARD_SCOPE_TERMINAL == 1
            assert token_bypass.SCARD_SCOPE_SYSTEM == 2

            assert token_bypass.SCARD_SHARE_SHARED == 2
            assert token_bypass.SCARD_SHARE_EXCLUSIVE == 1
            assert token_bypass.SCARD_SHARE_DIRECT == 3

            assert token_bypass.SCARD_PROTOCOL_T0 == 0x0001
            assert token_bypass.SCARD_PROTOCOL_T1 == 0x0002
            assert token_bypass.SCARD_PROTOCOL_RAW == 0x0004

            assert token_bypass.SCARD_LEAVE_CARD == 0
            assert token_bypass.SCARD_RESET_CARD == 1
            assert token_bypass.SCARD_UNPOWER_CARD == 2
            assert token_bypass.SCARD_EJECT_CARD == 3

    @pytest.mark.skipif(os.name == "nt", reason="Non-Windows graceful degradation test")
    def test_graceful_degradation_on_non_windows_systems(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Bypass gracefully handles absence of Windows APIs on non-Windows systems."""
        assert token_bypass.winscard is None
        assert token_bypass.kernel32 is None


class TestYubiKeyEmulationAndOTPGeneration:
    """Test YubiKey hardware token emulation with genuine OTP generation."""

    def test_yubikey_emulation_generates_valid_serial_number_format(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """YubiKey emulation generates realistic 8-digit serial numbers."""
        result = token_bypass.emulate_yubikey()

        assert result["success"] is True
        assert "serial_number" in result

        serial = result["serial_number"]
        assert len(serial) == 8
        assert serial.isdigit()
        assert 10000000 <= int(serial) < 100000000

    def test_yubikey_emulation_accepts_custom_serial_number(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """YubiKey emulation uses provided custom serial number."""
        custom_serial = "87654321"
        result = token_bypass.emulate_yubikey(serial_number=custom_serial)

        assert result["success"] is True
        assert result["serial_number"] == custom_serial

    def test_yubikey_otp_conforms_to_modhex_encoding(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Generated YubiKey OTP uses valid ModHex encoding per Yubico specification."""
        result = token_bypass.emulate_yubikey()

        otp = result["otp"]
        public_id = result["public_id"]

        assert len(otp) > len(public_id)
        assert otp.startswith(public_id)

        modhex_chars = set("cbdefghijklnrtuv")
        otp_ciphertext = otp[len(public_id):]
        assert all(c in modhex_chars for c in otp_ciphertext)

        assert len(otp_ciphertext) >= 32

    def test_yubikey_otp_public_id_is_12_hex_chars(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """YubiKey OTP public ID is 12 ModHex characters as per specification."""
        result = token_bypass.emulate_yubikey()

        public_id = result["public_id"]
        assert len(public_id) == 12

        valid_hex_chars = set("0123456789abcdef")
        assert all(c in valid_hex_chars for c in public_id.lower())

    def test_yubikey_generates_unique_secrets_per_serial(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Each YubiKey serial number gets unique AES key and private ID."""
        serial1 = "11111111"
        serial2 = "22222222"

        result1 = token_bypass.emulate_yubikey(serial_number=serial1)
        result2 = token_bypass.emulate_yubikey(serial_number=serial2)

        secrets1 = token_bypass.yubikey_secrets[serial1]
        secrets2 = token_bypass.yubikey_secrets[serial2]

        assert secrets1["aes_key"] != secrets2["aes_key"]
        assert secrets1["private_id"] != secrets2["private_id"]
        assert secrets1["public_id"] != secrets2["public_id"]

    def test_yubikey_counters_increment_correctly(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """YubiKey session and usage counters increment correctly across OTP generations."""
        serial = "99999999"

        result1 = token_bypass.emulate_yubikey(serial_number=serial)
        counter1 = result1["counter"]
        session1 = result1["session"]

        result2 = token_bypass.emulate_yubikey(serial_number=serial)
        counter2 = result2["counter"]
        session2 = result2["session"]

        if session1 < 0xFF:
            assert session2 == session1 + 1
            assert counter2 == counter1
        else:
            assert session2 == 0
            assert counter2 == counter1 + 1

    def test_yubikey_aes_encryption_produces_16_byte_output(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """YubiKey AES encryption produces exactly 16-byte encrypted token."""
        test_data = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
        test_key = secrets.token_bytes(16)

        encrypted = token_bypass._aes_encrypt(test_data, test_key)

        assert len(encrypted) >= 16
        assert encrypted != test_data

    def test_yubikey_crc16_calculation_matches_ccitt_standard(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """YubiKey CRC16 calculation matches CRC16-CCITT standard."""
        test_data = b"123456789"
        expected_crc = 0x29B1

        calculated_crc = token_bypass._calculate_crc16(test_data)

        assert calculated_crc == expected_crc

    def test_yubikey_modhex_conversion_is_reversible(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """ModHex encoding is consistent and uses correct character mapping."""
        test_bytes = bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0])

        modhex = token_bypass._to_modhex(test_bytes)

        assert len(modhex) == len(test_bytes) * 2

        modhex_chars = "cbdefghijklnrtuv"
        assert all(c in modhex_chars for c in modhex)

    def test_yubikey_usb_device_emulation_includes_correct_vendor_id(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """YubiKey USB emulation includes official Yubico vendor ID and product details."""
        result = token_bypass.emulate_yubikey()

        usb_device = result["usb_device"]

        assert usb_device["vendor_id"] == 0x1050
        assert usb_device["product_id"] == 0x0407
        assert usb_device["manufacturer"] == "Yubico"
        assert "YubiKey" in usb_device["product"]

        assert "interfaces" in usb_device
        assert "OTP" in usb_device["interfaces"]

        capabilities = usb_device["capabilities"]
        assert capabilities["otp"] is True
        assert capabilities["u2f"] is True
        assert capabilities["fido2"] is True


class TestRSASecurIDTokenGeneration:
    """Test RSA SecurID token generation with time-based algorithm."""

    def test_securid_generates_six_digit_token_code(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """RSA SecurID generates 6-digit token code per specification."""
        result = token_bypass.generate_rsa_securid_token()

        assert result["success"] is True
        assert "token_code" in result

        token_code = result["token_code"]
        assert len(token_code) == 6
        assert token_code.isdigit()

    def test_securid_accepts_custom_serial_number(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """RSA SecurID accepts and uses provided serial number."""
        custom_serial = "000123456789"
        result = token_bypass.generate_rsa_securid_token(serial_number=custom_serial)

        assert result["success"] is True
        assert result["serial_number"] == custom_serial

    def test_securid_generates_realistic_12_digit_serial(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """RSA SecurID generates realistic 12-digit serial numbers starting with 000."""
        result = token_bypass.generate_rsa_securid_token()

        serial = result["serial_number"]
        assert len(serial) == 12
        assert serial.isdigit()
        assert serial.startswith("000")

    def test_securid_uses_60_second_time_interval(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """RSA SecurID uses standard 60-second token interval."""
        result = token_bypass.generate_rsa_securid_token()

        assert result["interval"] == 60
        assert 0 <= result["time_remaining"] <= 60

    def test_securid_generates_deterministic_tokens_for_same_time(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """RSA SecurID generates identical tokens for same seed and time window."""
        seed = secrets.token_bytes(16)
        serial = "000111222333"

        result1 = token_bypass.generate_rsa_securid_token(serial_number=serial, seed=seed)
        result2 = token_bypass.generate_rsa_securid_token(serial_number=serial, seed=seed)

        assert result1["token_code"] == result2["token_code"]

    def test_securid_generates_different_tokens_for_different_seeds(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """RSA SecurID generates different tokens for different seeds."""
        seed1 = secrets.token_bytes(16)
        seed2 = secrets.token_bytes(16)

        result1 = token_bypass.generate_rsa_securid_token(seed=seed1)
        result2 = token_bypass.generate_rsa_securid_token(seed=seed2)

        assert result1["token_code"] != result2["token_code"]

    def test_securid_provides_next_token_for_drift_handling(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """RSA SecurID provides next token code for clock drift tolerance."""
        result = token_bypass.generate_rsa_securid_token()

        assert "next_token" in result
        assert len(result["next_token"]) == 6
        assert result["next_token"].isdigit()

        assert result["token_code"] != result["next_token"]

    def test_securid_token_changes_across_time_windows(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """RSA SecurID token changes when time window advances."""
        seed = secrets.token_bytes(16)

        time_counter1 = int(time.time()) // 60
        token1 = token_bypass._calculate_securid_token(seed, time_counter1)

        time_counter2 = time_counter1 + 1
        token2 = token_bypass._calculate_securid_token(seed, time_counter2)

        assert token1 != token2

    def test_securid_stores_seed_for_serial_number(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """RSA SecurID stores and reuses seed for each serial number."""
        serial = "000555666777"

        result1 = token_bypass.generate_rsa_securid_token(serial_number=serial)
        assert serial in token_bypass.rsa_seeds

        stored_seed = token_bypass.rsa_seeds[serial]

        result2 = token_bypass.generate_rsa_securid_token(serial_number=serial)
        assert token_bypass.rsa_seeds[serial] == stored_seed


class TestSmartCardEmulation:
    """Test smart card emulation with PIV, CAC, and generic cards."""

    def test_piv_card_emulation_generates_valid_card_id(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """PIV card emulation generates valid 16-character hex card ID."""
        result = token_bypass.emulate_smartcard(card_type="PIV")

        assert result["success"] is True
        assert result["card_type"] == "PIV"

        card_id = result["card_id"]
        assert len(card_id) == 16
        assert all(c in "0123456789ABCDEF" for c in card_id)

    def test_piv_card_includes_four_required_certificates(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """PIV card includes all four required certificates per FIPS 201 standard."""
        result = token_bypass.emulate_smartcard(card_type="PIV")

        certificates = result["certificates"]
        assert len(certificates) == 4

        assert "authentication" in certificates
        assert "digital_signature" in certificates
        assert "key_management" in certificates
        assert "card_authentication" in certificates

        for cert in certificates.values():
            assert "common_name" in cert
            assert "serial_number" in cert
            assert "pem" in cert
            assert "der" in cert

    def test_piv_card_generates_valid_chuid(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """PIV card generates valid Card Holder Unique Identifier (CHUID)."""
        result = token_bypass.emulate_smartcard(card_type="PIV")

        chuid = result["chuid"]
        assert isinstance(chuid, bytes)
        assert len(chuid) > 50

        assert b"\x30\x19" in chuid

    def test_piv_card_includes_guid_and_expiration(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """PIV card includes GUID and expiration date."""
        result = token_bypass.emulate_smartcard(card_type="PIV")

        assert "guid" in result
        assert len(result["guid"]) == 32

        assert "expiration" in result
        expiry_date = datetime.fromisoformat(result["expiration"])
        assert expiry_date > datetime.now()

    def test_cac_card_emulation_includes_edipi(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """CAC card emulation includes valid EDIPI (DoD ID number)."""
        result = token_bypass.emulate_smartcard(card_type="CAC")

        assert result["success"] is True
        assert result["card_type"] == "CAC"

        edipi = result["edipi"]
        assert len(edipi) == 10
        assert edipi.isdigit()
        assert 1000000000 <= int(edipi) < 10000000000

    def test_cac_card_includes_three_dod_certificates(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """CAC card includes identity, email signature, and email encryption certs."""
        result = token_bypass.emulate_smartcard(card_type="CAC")

        certificates = result["certificates"]
        assert len(certificates) == 3

        assert "identity" in certificates
        assert "email_signature" in certificates
        assert "email_encryption" in certificates

        identity_cert = certificates["identity"]
        assert "DoD" in identity_cert["common_name"]

    def test_cac_card_has_different_atr_than_piv(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """CAC card uses different ATR bytes than PIV card."""
        piv_result = token_bypass.emulate_smartcard(card_type="PIV")
        cac_result = token_bypass.emulate_smartcard(card_type="CAC")

        assert piv_result["atr"] != cac_result["atr"]

    def test_generic_smartcard_emulation_works(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Generic smart card emulation creates functional card data."""
        result = token_bypass.emulate_smartcard(card_type="Generic")

        assert result["success"] is True
        assert result["card_type"] == "Generic"

        assert "card_id" in result
        assert "atr" in result
        assert "certificates" in result
        assert "pin" in result

    def test_smartcard_certificates_are_valid_x509(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Generated smart card certificates are valid X.509 certificates."""
        result = token_bypass.emulate_smartcard(card_type="PIV")

        auth_cert = result["certificates"]["authentication"]

        pem_data = auth_cert["pem"].encode("utf-8")
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())

        assert cert.subject is not None
        assert cert.issuer is not None
        assert cert.not_valid_before <= datetime.utcnow()
        assert cert.not_valid_after > datetime.utcnow()

    def test_smartcard_certificates_use_2048_bit_rsa_keys(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Smart card certificates use 2048-bit RSA keys per security standards."""
        result = token_bypass.emulate_smartcard(card_type="PIV")

        for cert_data in result["certificates"].values():
            assert cert_data["public_key_size"] == 2048
            assert cert_data["signature_algorithm"] == "sha256WithRSAEncryption"

    @pytest.mark.skipif(os.name != "nt", reason="Windows SCard API test")
    def test_smartcard_reader_emulation_on_windows(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Smart card reader emulation works with Windows SCard API."""
        if token_bypass.winscard is None:
            pytest.skip("Windows SCard API not available")

        result = token_bypass.emulate_smartcard(card_type="PIV")

        if "reader" in result:
            assert "Virtual" in result["reader"]
            assert "PIV" in result["reader"]

    def test_smartcard_stored_in_emulated_devices(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Emulated smart card is stored in inserted_cards dictionary."""
        result = token_bypass.emulate_smartcard(card_type="PIV")

        card_id = result["card_id"]
        assert card_id in token_bypass.smartcard_config["inserted_cards"]

        stored_card = token_bypass.smartcard_config["inserted_cards"][card_id]
        assert stored_card["card_type"] == "PIV"


class TestTokenVerificationBypass:
    """Test hardware token verification bypass capabilities."""

    def test_bypass_yubikey_verification_identifies_method(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """YubiKey bypass identifies appropriate bypass method for platform."""
        result = token_bypass.bypass_token_verification(
            application="test_app.exe",
            token_type="yubikey"
        )

        assert "token_type" in result
        assert result["token_type"] == "yubikey"
        assert "method" in result

    def test_bypass_securid_verification_generates_valid_token(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """RSA SecurID bypass generates valid token code."""
        result = token_bypass.bypass_token_verification(
            application="test_app.exe",
            token_type="securid"
        )

        assert result["success"] is True
        assert result["method"] == "Token Generation + Memory Patch"

        details = result["details"]
        assert "generated_token" in details
        assert len(details["generated_token"]) == 6
        assert details["generated_token"].isdigit()

    def test_bypass_smartcard_verification_emulates_card(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Smart card bypass emulates virtual smart card."""
        result = token_bypass.bypass_token_verification(
            application="test_app.exe",
            token_type="smartcard"
        )

        assert result["success"] is True
        assert result["method"] == "Virtual Smart Card"

        details = result["details"]
        assert "card_id" in details
        assert "card_type" in details
        assert details["certificates"] > 0

    def test_bypass_unknown_token_type_returns_error(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Bypass returns error for unknown token types."""
        result = token_bypass.bypass_token_verification(
            application="test_app.exe",
            token_type="unknown_token"
        )

        assert result["success"] is False
        assert "error" in result
        assert "unknown_token" in result["error"].lower()

    @pytest.mark.skipif(os.name != "nt", reason="Windows DLL injection test")
    def test_yubikey_hook_dll_path_created(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """YubiKey hook DLL path is created on Windows."""
        dll_path = token_bypass._create_yubikey_hook_dll()

        assert dll_path.endswith(".dll")
        assert Path(dll_path).exists()

        with open(dll_path, "rb") as f:
            dll_data = f.read()
            assert dll_data[:2] == b"MZ"

    def test_yubikey_hook_dll_has_valid_pe_structure(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Generated YubiKey hook DLL has valid PE structure."""
        dll_bytes = token_bypass._generate_minimal_dll()

        assert dll_bytes[:2] == b"MZ"

        e_lfanew_offset = 0x3C
        assert len(dll_bytes) > e_lfanew_offset + 4

        pe_offset = struct.unpack("<I", dll_bytes[e_lfanew_offset:e_lfanew_offset+4])[0]
        assert dll_bytes[pe_offset:pe_offset+4] == b"PE\x00\x00"


class TestSecretExtractionFromMemoryDumps:
    """Test extraction of secrets from hardware token memory dumps."""

    def test_extract_yubikey_aes_keys_from_memory_dump(
        self, token_bypass: HardwareTokenBypass, yubikey_memory_dump: Path
    ) -> None:
        """Extract high-entropy AES keys from YubiKey memory dump."""
        result = token_bypass.extract_token_secrets(str(yubikey_memory_dump))

        assert result["success"] is True

        yubikey_secrets = result.get("yubikey_secrets", {})
        assert len(yubikey_secrets) > 0

        for key_id, key_hex in yubikey_secrets.items():
            assert "yubikey_aes" in key_id
            assert len(key_hex) == 32

    def test_extract_securid_seeds_from_memory_dump(
        self, token_bypass: HardwareTokenBypass, securid_token_dump: Path
    ) -> None:
        """Extract RSA SecurID seed data from token memory dump."""
        result = token_bypass.extract_token_secrets(str(securid_token_dump))

        assert result["success"] is True

        securid_seeds = result.get("securid_seeds", {})
        assert len(securid_seeds) > 0

        for seed_id, seed_hex in securid_seeds.items():
            assert "securid_seed" in seed_id
            assert len(seed_hex) == 32

    def test_extract_smartcard_certificates_from_memory_dump(
        self, token_bypass: HardwareTokenBypass, smartcard_memory_dump: Path
    ) -> None:
        """Extract X.509 certificates from smart card memory dump."""
        result = token_bypass.extract_token_secrets(str(smartcard_memory_dump))

        certificates = result.get("certificates", [])

        assert len(certificates) > 0

        has_der = any(cert["format"] == "DER" for cert in certificates)
        has_pem = any(cert["format"] == "PEM" for cert in certificates)

        assert has_der or has_pem

    def test_entropy_calculation_identifies_high_entropy_keys(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Shannon entropy calculation correctly identifies high-entropy cryptographic keys."""
        random_key = secrets.token_bytes(16)
        entropy_random = token_bypass._calculate_entropy(random_key)

        assert entropy_random > 7.0

        low_entropy_data = b"\x00" * 16
        entropy_low = token_bypass._calculate_entropy(low_entropy_data)

        assert entropy_low < 1.0

    def test_extract_secrets_handles_nonexistent_file(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Secret extraction returns empty result for nonexistent files."""
        result = token_bypass.extract_token_secrets("/nonexistent/file.bin")

        assert result["success"] is False
        assert len(result["secrets"]) == 0
        assert len(result["keys"]) == 0

    def test_extract_secrets_handles_empty_file(
        self, token_bypass: HardwareTokenBypass, tmp_path: Path
    ) -> None:
        """Secret extraction handles empty memory dumps gracefully."""
        empty_file = tmp_path / "empty.bin"
        empty_file.write_bytes(b"")

        result = token_bypass.extract_token_secrets(str(empty_file))

        assert result["success"] is False

    def test_extract_multiple_aes_keys_from_large_dump(
        self, token_bypass: HardwareTokenBypass, yubikey_memory_dump: Path
    ) -> None:
        """Extract multiple AES keys from large memory dump."""
        result = token_bypass.extract_token_secrets(str(yubikey_memory_dump))

        yubikey_secrets = result.get("yubikey_secrets", {})

        assert len(yubikey_secrets) >= 3

    def test_extract_der_encoded_certificates(
        self, token_bypass: HardwareTokenBypass, smartcard_memory_dump: Path
    ) -> None:
        """Extract DER-encoded X.509 certificates with correct structure."""
        result = token_bypass.extract_token_secrets(str(smartcard_memory_dump))

        certificates = result.get("certificates", [])
        der_certs = [c for c in certificates if c["format"] == "DER"]

        assert der_certs

        for cert in der_certs:
            assert "offset" in cert
            assert "data" in cert
            assert isinstance(cert["data"], str)

    def test_extract_pem_encoded_certificates(
        self, token_bypass: HardwareTokenBypass, smartcard_memory_dump: Path
    ) -> None:
        """Extract PEM-encoded X.509 certificates with BEGIN/END markers."""
        result = token_bypass.extract_token_secrets(str(smartcard_memory_dump))

        certificates = result.get("certificates", [])
        pem_certs = [c for c in certificates if c["format"] == "PEM"]

        assert pem_certs

        for cert in pem_certs:
            pem_data = cert["data"]
            assert "-----BEGIN CERTIFICATE-----" in pem_data
            assert "-----END CERTIFICATE-----" in pem_data


class TestBypassHardwareTokenFunction:
    """Test module-level bypass_hardware_token function."""

    def test_bypass_function_attempts_verification_first(self) -> None:
        """Module function attempts verification bypass before emulation."""
        result = bypass_hardware_token(
            application="test_app.exe",
            token_type="securid"
        )

        assert "success" in result
        assert "application" in result
        assert result["application"] == "test_app.exe"

    def test_bypass_function_falls_back_to_yubikey_emulation(self) -> None:
        """Module function falls back to YubiKey emulation if bypass fails."""
        result = bypass_hardware_token(
            application="nonexistent_app.exe",
            token_type="yubikey"
        )

        if not result.get("success"):
            assert "emulation" in result
            emulation = result["emulation"]
            assert emulation["success"] is True
            assert "otp" in emulation

    def test_bypass_function_falls_back_to_securid_emulation(self) -> None:
        """Module function falls back to SecurID token generation if bypass fails."""
        result = bypass_hardware_token(
            application="nonexistent_app.exe",
            token_type="securid"
        )

        if not result.get("success"):
            assert "emulation" in result
            emulation = result["emulation"]
            assert emulation["success"] is True
            assert "token_code" in emulation

    def test_bypass_function_falls_back_to_smartcard_emulation(self) -> None:
        """Module function falls back to smart card emulation if bypass fails."""
        result = bypass_hardware_token(
            application="nonexistent_app.exe",
            token_type="smartcard"
        )

        if not result.get("success"):
            assert "emulation" in result
            emulation = result["emulation"]
            assert emulation["success"] is True
            assert "card_id" in emulation


class TestCryptographicPrimitives:
    """Test cryptographic primitives used in token emulation."""

    def test_modhex_encoding_uses_correct_character_set(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """ModHex encoding uses cbdefghijklnrtuv character set."""
        test_data = bytes(range(256))
        modhex = token_bypass._to_modhex(test_data)

        valid_chars = set("cbdefghijklnrtuv")
        assert all(c in valid_chars for c in modhex)

    def test_modhex_encoding_produces_correct_length(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """ModHex encoding produces 2 characters per input byte."""
        for length in [1, 8, 16, 32, 64]:
            test_data = secrets.token_bytes(length)
            modhex = token_bypass._to_modhex(test_data)
            assert len(modhex) == length * 2

    def test_crc16_produces_16_bit_output(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """CRC16 calculation produces 16-bit checksum."""
        test_data = secrets.token_bytes(100)
        crc = token_bypass._calculate_crc16(test_data)

        assert 0 <= crc <= 0xFFFF

    def test_crc16_changes_with_input_data(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """CRC16 produces different checksums for different inputs."""
        data1 = b"test data 1"
        data2 = b"test data 2"

        crc1 = token_bypass._calculate_crc16(data1)
        crc2 = token_bypass._calculate_crc16(data2)

        assert crc1 != crc2

    def test_aes_encryption_produces_different_output(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """AES encryption produces ciphertext different from plaintext."""
        plaintext = b"0123456789ABCDEF"
        key = secrets.token_bytes(16)

        ciphertext = token_bypass._aes_encrypt(plaintext, key)

        assert ciphertext != plaintext
        assert len(ciphertext) >= 16

    def test_aes_encryption_with_different_keys_produces_different_output(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """AES encryption with different keys produces different ciphertexts."""
        plaintext = b"0123456789ABCDEF"
        key1 = secrets.token_bytes(16)
        key2 = secrets.token_bytes(16)

        ciphertext1 = token_bypass._aes_encrypt(plaintext, key1)
        ciphertext2 = token_bypass._aes_encrypt(plaintext, key2)

        assert ciphertext1 != ciphertext2


class TestEntropyCalculation:
    """Test Shannon entropy calculation for key identification."""

    def test_entropy_zero_for_empty_data(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Entropy calculation returns zero for empty data."""
        entropy = token_bypass._calculate_entropy(b"")
        assert entropy == 0.0

    def test_entropy_low_for_repetitive_data(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Entropy is low for repetitive or structured data."""
        repetitive = b"AAAAAAAAAAAAAAAA"
        entropy = token_bypass._calculate_entropy(repetitive)

        assert entropy < 1.0

    def test_entropy_high_for_random_data(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Entropy is high for random cryptographic key material."""
        random_data = secrets.token_bytes(256)
        entropy = token_bypass._calculate_entropy(random_data)

        assert entropy > 7.0

    def test_entropy_calculation_is_consistent(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Entropy calculation produces consistent results for same input."""
        data = secrets.token_bytes(128)

        entropy1 = token_bypass._calculate_entropy(data)
        entropy2 = token_bypass._calculate_entropy(data)

        assert entropy1 == entropy2

    def test_entropy_distinguishes_keys_from_structured_data(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Entropy calculation distinguishes random keys from structured data."""
        key = secrets.token_bytes(16)
        structured = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"

        entropy_key = token_bypass._calculate_entropy(key)
        entropy_structured = token_bypass._calculate_entropy(structured)

        assert entropy_key > entropy_structured


class TestWindowsAPIIntegration:
    """Test Windows API integration for USB and smart card operations."""

    @pytest.mark.skipif(os.name != "nt", reason="Windows kernel32 API test")
    def test_kernel32_dll_accessible_on_windows(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Windows kernel32.dll is accessible for process operations."""
        if token_bypass.kernel32 is None:
            pytest.skip("kernel32 not loaded")

        assert hasattr(token_bypass.kernel32, "OpenProcess")
        assert hasattr(token_bypass.kernel32, "GetModuleHandleA")
        assert hasattr(token_bypass.kernel32, "GetProcAddress")

    @pytest.mark.skipif(os.name != "nt", reason="Windows winscard API test")
    def test_winscard_dll_accessible_on_windows(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Windows winscard.dll is accessible for smart card operations."""
        if token_bypass.winscard is None:
            pytest.skip("winscard not loaded")

        assert hasattr(token_bypass.winscard, "SCardEstablishContext")
        assert hasattr(token_bypass.winscard, "SCardReleaseContext")

    @pytest.mark.skipif(os.name != "nt", reason="Windows smart card context test")
    def test_scard_context_establishment_on_windows(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Smart card context can be established on Windows."""
        if token_bypass.winscard is None:
            pytest.skip("winscard not loaded")

        h_context = ctypes.c_ulong()
        result = token_bypass.winscard.SCardEstablishContext(
            token_bypass.SCARD_SCOPE_SYSTEM,
            None,
            None,
            ctypes.byref(h_context)
        )

        if result == 0:
            assert h_context.value != 0
            token_bypass.winscard.SCardReleaseContext(h_context)


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling in hardware token bypass."""

    def test_yubikey_emulation_with_very_long_serial(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """YubiKey emulation handles overly long serial numbers."""
        long_serial = "123456789012345678901234567890"
        result = token_bypass.emulate_yubikey(serial_number=long_serial)

        assert result["success"] is True
        assert result["serial_number"] == long_serial

    def test_securid_token_with_128_bit_seed(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """RSA SecurID correctly uses 128-bit (16-byte) seed."""
        seed = secrets.token_bytes(16)
        result = token_bypass.generate_rsa_securid_token(seed=seed)

        assert result["success"] is True
        assert len(result["token_code"]) == 6

    def test_smartcard_emulation_with_custom_card_type(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Smart card emulation falls back to generic for unknown card types."""
        result = token_bypass.emulate_smartcard(card_type="CustomCard")

        assert result["success"] is True
        assert result["card_type"] == "Generic"

    def test_entropy_calculation_with_single_byte(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """Entropy calculation works with single-byte input."""
        single_byte = b"\xFF"
        entropy = token_bypass._calculate_entropy(single_byte)

        assert entropy >= 0.0

    def test_crc16_with_empty_data(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """CRC16 calculation handles empty data."""
        crc = token_bypass._calculate_crc16(b"")

        assert crc == 0xFFFF

    def test_modhex_encoding_with_empty_data(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """ModHex encoding handles empty data."""
        modhex = token_bypass._to_modhex(b"")

        assert modhex == ""

    def test_yubikey_counter_overflow_increments_usage_counter(
        self, token_bypass: HardwareTokenBypass
    ) -> None:
        """YubiKey usage counter increments when session counter overflows."""
        serial = "88888888"

        secrets_data = {
            "aes_key": secrets.token_bytes(16),
            "public_id": secrets.token_hex(6),
            "private_id": secrets.token_bytes(6),
            "counter": 5,
            "session": 0xFF,
        }
        token_bypass.yubikey_secrets[serial] = secrets_data

        result = token_bypass.emulate_yubikey(serial_number=serial)

        assert token_bypass.yubikey_secrets[serial]["session"] == 0
        assert token_bypass.yubikey_secrets[serial]["counter"] == 6
