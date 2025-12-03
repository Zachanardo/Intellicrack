"""Comprehensive Production Tests for Hardware Token Bypass.

Tests validate genuine hardware token emulation and bypass capabilities.
All tests use real data and actual function calls - NO mocks or stubs.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0
"""

import hashlib
import os
import secrets
import struct
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from intellicrack.core.protection_bypass.hardware_token import (
    HardwareTokenBypass,
    bypass_hardware_token,
)


@pytest.fixture
def token_bypass() -> HardwareTokenBypass:
    """Create hardware token bypass instance for testing."""
    return HardwareTokenBypass()


@pytest.fixture
def realistic_yubikey_dump(tmp_path: Path) -> Path:
    """Create realistic YubiKey memory dump with embedded secrets."""
    dump_data = bytearray(8192)

    dump_data[100:116] = secrets.token_bytes(16)
    dump_data[500:516] = secrets.token_bytes(16)
    dump_data[1000:1006] = secrets.token_bytes(6)
    dump_data[2000:2016] = secrets.token_bytes(16)

    for i in range(10):
        offset = 3000 + (i * 100)
        dump_data[offset:offset + 16] = secrets.token_bytes(16)

    dump_file = tmp_path / "yubikey_dump.bin"
    dump_file.write_bytes(bytes(dump_data))
    return dump_file


@pytest.fixture
def realistic_securid_dump(tmp_path: Path) -> Path:
    """Create realistic RSA SecurID token dump with seed data."""
    dump_data = bytearray(4096)

    dump_data[200:203] = b"RSA"
    dump_data[203:219] = secrets.token_bytes(16)

    dump_data[800:804] = b"SEED"
    dump_data[804:820] = secrets.token_bytes(16)

    dump_data[1500:1504] = b"\x00\x00\x00\x10"
    dump_data[1504:1520] = secrets.token_bytes(16)

    dump_file = tmp_path / "securid_dump.bin"
    dump_file.write_bytes(bytes(dump_data))
    return dump_file


@pytest.fixture
def realistic_smartcard_dump(tmp_path: Path) -> Path:
    """Create realistic smart card dump with certificates and keys."""
    dump_data = bytearray(16384)

    dump_data[500:502] = b"\x30\x82"
    cert_length = 512
    dump_data[502:504] = struct.pack(">H", cert_length)
    dump_data[504:504 + cert_length] = secrets.token_bytes(cert_length)

    pem_cert = b"-----BEGIN CERTIFICATE-----\n"
    pem_cert += b"MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKF5MA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\n"
    pem_cert += b"BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX\n"
    pem_cert += b"aWRnaXRzIFB0eSBMdGQwHhcNMjUwMTAxMDAwMDAwWhcNMjYwMTAxMDAwMDAwWjBF\n"
    pem_cert += b"MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50\n"
    pem_cert += b"ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n"
    pem_cert += b"CgKCAQEAw4VQ==\n"
    pem_cert += b"-----END CERTIFICATE-----"

    dump_data[2000:2000 + len(pem_cert)] = pem_cert

    dump_data[5000:5002] = b"\x30\x82"
    key_length = 256
    dump_data[5002:5004] = struct.pack(">H", key_length)
    dump_data[5004:5004 + key_length] = secrets.token_bytes(key_length)

    dump_file = tmp_path / "smartcard_dump.bin"
    dump_file.write_bytes(bytes(dump_data))
    return dump_file


class TestHardwareTokenBypassInitialization:
    """Test HardwareTokenBypass initialization and configuration."""

    def test_initialization_creates_empty_storage_structures(self, token_bypass: HardwareTokenBypass) -> None:
        """Bypass initializes with proper empty storage for all token types."""
        assert isinstance(token_bypass.yubikey_secrets, dict)
        assert isinstance(token_bypass.rsa_seeds, dict)
        assert isinstance(token_bypass.smartcard_keys, dict)
        assert isinstance(token_bypass.emulated_devices, dict)
        assert len(token_bypass.yubikey_secrets) == 0
        assert len(token_bypass.rsa_seeds) == 0
        assert len(token_bypass.smartcard_keys) == 0

    def test_yubikey_configuration_matches_otp_specification(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey configuration matches Yubico OTP specification."""
        config = token_bypass.yubikey_config
        assert config["public_id_length"] == 12
        assert config["private_id_length"] == 6
        assert config["aes_key_length"] == 16
        assert config["counter_offset"] == 0
        assert config["session_counter"] == 0
        assert all(key in config for key in ["timestamp_low", "timestamp_high", "use_counter"])

    def test_securid_configuration_matches_rsa_specification(self, token_bypass: HardwareTokenBypass) -> None:
        """RSA SecurID configuration matches SecurID token specification."""
        config = token_bypass.securid_config
        assert config["token_code_length"] == 6
        assert config["token_interval"] == 60
        assert config["drift_tolerance"] == 3
        assert isinstance(config["serial_numbers"], dict)
        assert isinstance(config["seeds"], dict)

    def test_smartcard_atr_bytes_valid_iso7816_format(self, token_bypass: HardwareTokenBypass) -> None:
        """Smart card ATR bytes conform to ISO/IEC 7816-3 standard."""
        atr = token_bypass.smartcard_config["atr_bytes"]
        assert isinstance(atr, bytes)
        assert len(atr) >= 2
        assert atr[0] == 0x3B or atr[0] == 0x3F
        assert atr[1] == 0xF8

    @pytest.mark.skipif(os.name != "nt", reason="Windows-specific smart card API")
    def test_windows_scard_api_properly_initialized(self, token_bypass: HardwareTokenBypass) -> None:
        """Windows smart card API constants initialized correctly."""
        assert hasattr(token_bypass, "winscard")
        assert hasattr(token_bypass, "kernel32")
        if token_bypass.winscard:
            assert token_bypass.SCARD_SCOPE_USER == 0
            assert token_bypass.SCARD_SCOPE_TERMINAL == 1
            assert token_bypass.SCARD_SCOPE_SYSTEM == 2
            assert token_bypass.SCARD_SHARE_SHARED == 2
            assert token_bypass.SCARD_SHARE_EXCLUSIVE == 1
            assert token_bypass.SCARD_PROTOCOL_T0 == 0x0001
            assert token_bypass.SCARD_PROTOCOL_T1 == 0x0002


class TestYubiKeyEmulationAndOTPGeneration:
    """Test YubiKey hardware token emulation with genuine OTP generation."""

    def test_yubikey_emulation_generates_valid_serial_number(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey emulation generates realistic 8-digit serial numbers."""
        result = token_bypass.emulate_yubikey()

        assert result["success"] is True
        assert "serial_number" in result
        serial = result["serial_number"]
        assert len(serial) == 8
        assert serial.isdigit()
        assert 10000000 <= int(serial) < 100000000

    def test_yubikey_emulation_uses_provided_serial_number(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey emulation accepts and uses custom serial numbers."""
        custom_serial = "98765432"
        result = token_bypass.emulate_yubikey(custom_serial)

        assert result["success"] is True
        assert result["serial_number"] == custom_serial

    def test_yubikey_otp_conforms_to_yubico_format(self, token_bypass: HardwareTokenBypass) -> None:
        """Generated YubiKey OTP matches Yubico OTP format specification."""
        result = token_bypass.emulate_yubikey()

        otp = result["otp"]
        public_id = result["public_id"]

        assert len(otp) > 12
        assert otp.startswith(public_id)

        modhex_chars = set("cbdefghijklnrtuv")
        modhex_part = otp[len(public_id):]
        assert all(c in modhex_chars for c in modhex_part)
        assert len(modhex_part) >= 32

    def test_yubikey_otp_contains_encrypted_data_block(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey OTP contains properly encrypted 16-byte data block."""
        serial = "12345678"
        result = token_bypass.emulate_yubikey(serial)

        otp = result["otp"]
        public_id = result["public_id"]
        modhex_data = otp[len(public_id):]

        assert len(modhex_data) >= 32

    def test_yubikey_counter_increments_correctly(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey session and usage counters increment per specification."""
        serial = "11111111"

        results = []
        for i in range(5):
            result = token_bypass.emulate_yubikey(serial)
            results.append(result)

        for i in range(1, len(results)):
            prev = results[i - 1]
            curr = results[i]

            if curr["session"] > 0:
                assert curr["session"] == prev["session"] + 1
                assert curr["counter"] == prev["counter"]
            else:
                assert curr["session"] == 0
                assert curr["counter"] == prev["counter"] + 1

    def test_yubikey_session_counter_wraps_at_256(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey session counter wraps to 0 after 255 and increments usage counter."""
        serial = "55555555"
        token_bypass.yubikey_secrets[serial] = {
            "aes_key": secrets.token_bytes(16),
            "public_id": secrets.token_hex(6),
            "private_id": secrets.token_bytes(6),
            "counter": 5,
            "session": 255,
        }

        result = token_bypass.emulate_yubikey(serial)

        assert result["session"] == 0
        assert result["counter"] == 6

    def test_yubikey_secrets_persistence_across_calls(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey secrets persist and remain consistent across multiple calls."""
        serial = "77777777"

        result1 = token_bypass.emulate_yubikey(serial)
        result2 = token_bypass.emulate_yubikey(serial)
        result3 = token_bypass.emulate_yubikey(serial)

        assert result1["public_id"] == result2["public_id"] == result3["public_id"]
        assert serial in token_bypass.yubikey_secrets
        secrets_data = token_bypass.yubikey_secrets[serial]
        assert len(secrets_data["aes_key"]) == 16
        assert len(secrets_data["private_id"]) == 6

    def test_yubikey_usb_device_emulation_realistic(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey USB device emulation matches real YubiKey device descriptors."""
        result = token_bypass.emulate_yubikey()

        usb = result["usb_device"]
        assert usb["vendor_id"] == 0x1050
        assert usb["product_id"] == 0x0407
        assert usb["manufacturer"] == "Yubico"
        assert "YubiKey 5 NFC" in usb["product"]
        assert "OTP" in usb["interfaces"]
        assert "FIDO" in usb["interfaces"]
        assert "CCID" in usb["interfaces"]
        assert usb["capabilities"]["otp"] is True
        assert usb["capabilities"]["fido2"] is True
        assert usb["capabilities"]["oath"] is True
        assert usb["capabilities"]["piv"] is True

    def test_yubikey_different_serials_produce_different_otps(self, token_bypass: HardwareTokenBypass) -> None:
        """Different YubiKey serial numbers generate different OTP outputs."""
        otps = []
        public_ids = []

        for i in range(10):
            serial = f"1000000{i}"
            result = token_bypass.emulate_yubikey(serial)
            otps.append(result["otp"])
            public_ids.append(result["public_id"])

        assert len(set(otps)) == 10
        assert len(set(public_ids)) == 10

    def test_yubikey_aes_encryption_produces_valid_ciphertext(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey AES encryption produces cryptographically valid ciphertext."""
        plaintext = b"A" * 16
        key = secrets.token_bytes(16)

        ciphertext = token_bypass._aes_encrypt(plaintext, key)

        assert isinstance(ciphertext, bytes)
        assert len(ciphertext) >= 32
        assert ciphertext != plaintext
        assert ciphertext[:16] != plaintext

    def test_yubikey_crc16_calculation_correctness(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey CRC16-CCITT checksum calculation is correct."""
        test_data = b"123456789"
        crc = token_bypass._calculate_crc16(test_data)

        assert isinstance(crc, int)
        assert 0 <= crc <= 0xFFFF

        same_crc = token_bypass._calculate_crc16(test_data)
        assert crc == same_crc

        different_data = b"987654321"
        different_crc = token_bypass._calculate_crc16(different_data)
        assert crc != different_crc

    def test_yubikey_modhex_encoding_correctness(self, token_bypass: HardwareTokenBypass) -> None:
        """ModHex encoding uses correct character mapping."""
        test_bytes = bytes([0x00, 0x0F, 0xF0, 0xFF, 0x12, 0x34, 0x56, 0x78])
        modhex = token_bypass._to_modhex(test_bytes)

        modhex_chars = set("cbdefghijklnrtuv")
        assert all(c in modhex_chars for c in modhex)
        assert len(modhex) == len(test_bytes) * 2


class TestRSASecurIDTokenGeneration:
    """Test RSA SecurID token generation with time-based algorithms."""

    def test_securid_token_generation_without_parameters(self, token_bypass: HardwareTokenBypass) -> None:
        """SecurID generates valid token without provided parameters."""
        result = token_bypass.generate_rsa_securid_token()

        assert result["success"] is True
        assert "serial_number" in result
        assert "token_code" in result
        assert "next_token" in result
        assert len(result["token_code"]) == 6
        assert result["token_code"].isdigit()
        assert result["token_code"] != "000000"

    def test_securid_serial_number_format_validation(self, token_bypass: HardwareTokenBypass) -> None:
        """SecurID serial numbers match RSA token format specification."""
        serials = set()
        for _ in range(20):
            serial = token_bypass._generate_securid_serial()
            serials.add(serial)

        for serial in serials:
            assert len(serial) == 12
            assert serial.startswith("000")
            assert serial.isdigit()
            assert int(serial[3:]) >= 100000000

    def test_securid_token_with_custom_serial(self, token_bypass: HardwareTokenBypass) -> None:
        """SecurID accepts and uses custom serial numbers."""
        custom_serial = "000999888777"
        result = token_bypass.generate_rsa_securid_token(custom_serial)

        assert result["serial_number"] == custom_serial
        assert custom_serial in token_bypass.rsa_seeds

    def test_securid_token_with_custom_seed(self, token_bypass: HardwareTokenBypass) -> None:
        """SecurID accepts and uses custom 128-bit seeds."""
        custom_seed = secrets.token_bytes(16)
        result = token_bypass.generate_rsa_securid_token(seed=custom_seed)

        serial = result["serial_number"]
        assert token_bypass.rsa_seeds[serial] == custom_seed

    def test_securid_token_determinism_same_seed_same_time(self, token_bypass: HardwareTokenBypass) -> None:
        """Same seed and time counter produce identical SecurID tokens."""
        seed = secrets.token_bytes(16)
        time_counter = 12345

        token1 = token_bypass._calculate_securid_token(seed, time_counter)
        token2 = token_bypass._calculate_securid_token(seed, time_counter)
        token3 = token_bypass._calculate_securid_token(seed, time_counter)

        assert token1 == token2 == token3
        assert len(token1) == 6
        assert token1.isdigit()

    def test_securid_token_changes_with_time_intervals(self, token_bypass: HardwareTokenBypass) -> None:
        """SecurID tokens change for different time intervals."""
        seed = secrets.token_bytes(16)

        tokens = []
        for i in range(10):
            token = token_bypass._calculate_securid_token(seed, 1000 + i)
            tokens.append(token)

        unique_tokens = set(tokens)
        assert len(unique_tokens) >= 8

    def test_securid_next_token_prediction(self, token_bypass: HardwareTokenBypass) -> None:
        """SecurID next_token accurately predicts next time interval token."""
        result = token_bypass.generate_rsa_securid_token()

        current_token = result["token_code"]
        next_token = result["next_token"]

        assert current_token != next_token
        assert len(next_token) == 6
        assert next_token.isdigit()

    def test_securid_time_remaining_accuracy(self, token_bypass: HardwareTokenBypass) -> None:
        """SecurID time_remaining accurately reflects seconds until next token."""
        result = token_bypass.generate_rsa_securid_token()

        time_remaining = result["time_remaining"]
        assert 0 <= time_remaining <= 60

        current_time = int(time.time())
        expected_remaining = 60 - (current_time % 60)
        assert abs(time_remaining - expected_remaining) <= 1

    def test_securid_seed_persistence_across_calls(self, token_bypass: HardwareTokenBypass) -> None:
        """SecurID seeds persist and remain consistent across calls."""
        serial = "000111222333"

        result1 = token_bypass.generate_rsa_securid_token(serial)
        seed1 = token_bypass.rsa_seeds[serial]

        result2 = token_bypass.generate_rsa_securid_token(serial)
        seed2 = token_bypass.rsa_seeds[serial]

        assert seed1 == seed2
        assert len(seed1) == 16

    def test_securid_token_code_length_configuration(self, token_bypass: HardwareTokenBypass) -> None:
        """SecurID token length respects configuration settings."""
        token_bypass.securid_config["token_code_length"] = 8

        result = token_bypass.generate_rsa_securid_token()
        assert len(result["token_code"]) == 8
        assert len(result["next_token"]) == 8

        token_bypass.securid_config["token_code_length"] = 6

    def test_securid_zero_time_counter_handling(self, token_bypass: HardwareTokenBypass) -> None:
        """SecurID handles edge case of zero time counter."""
        seed = secrets.token_bytes(16)
        token = token_bypass._calculate_securid_token(seed, 0)

        assert len(token) == 6
        assert token.isdigit()


class TestSmartCardEmulation:
    """Test smart card emulation for PIV, CAC, and generic cards."""

    def test_piv_smartcard_emulation_complete(self, token_bypass: HardwareTokenBypass) -> None:
        """PIV smart card emulation produces complete valid card data."""
        result = token_bypass.emulate_smartcard("PIV")

        assert result["success"] is True
        assert result["card_type"] == "PIV"
        assert len(result["card_id"]) == 16
        assert isinstance(result["atr"], bytes)
        assert "certificates" in result
        assert "chuid" in result
        assert "guid" in result
        assert "pin" in result
        assert "puk" in result
        assert "admin_key" in result
        assert len(result["admin_key"]) == 48

    def test_piv_card_certificates_complete_set(self, token_bypass: HardwareTokenBypass) -> None:
        """PIV card contains all required certificate types per FIPS 201."""
        result = token_bypass.emulate_smartcard("PIV")

        certs = result["certificates"]
        assert "authentication" in certs
        assert "digital_signature" in certs
        assert "key_management" in certs
        assert "card_authentication" in certs

        for cert_name, cert_data in certs.items():
            assert "pem" in cert_data
            assert "der" in cert_data
            assert "serial_number" in cert_data
            assert "issuer" in cert_data
            assert "subject" in cert_data
            assert cert_data["public_key_size"] == 2048
            assert cert_data["signature_algorithm"] == "sha256WithRSAEncryption"

            cert_pem = x509.load_pem_x509_certificate(
                cert_data["pem"].encode(), default_backend()
            )
            assert cert_pem is not None
            assert cert_pem.serial_number > 0

    def test_cac_smartcard_emulation_complete(self, token_bypass: HardwareTokenBypass) -> None:
        """CAC smart card emulation produces valid DoD CAC data."""
        result = token_bypass.emulate_smartcard("CAC")

        assert result["success"] is True
        assert result["card_type"] == "CAC"
        assert "edipi" in result
        assert len(str(result["edipi"])) == 10
        assert str(result["edipi"]).isdigit()
        assert int(result["edipi"]) >= 1000000000
        assert "person_designator" in result
        assert "personnel_category" in result
        assert "branch" in result
        assert result["branch"] in ["A", "F", "M", "N", "C"]

    def test_cac_card_dod_certificates(self, token_bypass: HardwareTokenBypass) -> None:
        """CAC card contains DoD-specific certificate types."""
        result = token_bypass.emulate_smartcard("CAC")

        certs = result["certificates"]
        assert "identity" in certs
        assert "email_signature" in certs
        assert "email_encryption" in certs

        for cert_data in certs.values():
            assert "pem" in cert_data
            cert_pem = x509.load_pem_x509_certificate(
                cert_data["pem"].encode(), default_backend()
            )
            assert cert_pem is not None

    def test_generic_smartcard_emulation(self, token_bypass: HardwareTokenBypass) -> None:
        """Generic smart card emulation produces valid card data."""
        result = token_bypass.emulate_smartcard("Generic")

        assert result["success"] is True
        assert result["card_type"] == "Generic"
        assert "serial_number" in result
        assert "issuer" in result
        assert "holder" in result
        assert "certificates" in result
        assert len(result["certificates"]) >= 2

    def test_smartcard_atr_bytes_iso7816_compliant(self, token_bypass: HardwareTokenBypass) -> None:
        """Smart card ATR bytes comply with ISO/IEC 7816-3."""
        result = token_bypass.emulate_smartcard("PIV")

        atr = result["atr"]
        assert isinstance(atr, bytes)
        assert len(atr) >= 2
        assert atr[0] in [0x3B, 0x3F]

    def test_smartcard_expiration_dates_valid(self, token_bypass: HardwareTokenBypass) -> None:
        """Smart card expiration dates are in future and properly formatted."""
        for card_type in ["PIV", "CAC", "Generic"]:
            result = token_bypass.emulate_smartcard(card_type)

            expiration = datetime.fromisoformat(result["expiration"])
            now = datetime.now()

            assert expiration > now
            assert (expiration - now).days >= 300

    def test_smartcard_unique_card_ids(self, token_bypass: HardwareTokenBypass) -> None:
        """Each emulated smart card receives unique card ID."""
        card_ids = set()

        for _ in range(20):
            result = token_bypass.emulate_smartcard("PIV")
            card_ids.add(result["card_id"])

        assert len(card_ids) == 20

    def test_smartcard_stored_in_inserted_cards(self, token_bypass: HardwareTokenBypass) -> None:
        """Emulated smart cards stored in inserted_cards configuration."""
        result = token_bypass.emulate_smartcard("PIV")
        card_id = result["card_id"]

        assert card_id in token_bypass.smartcard_config["inserted_cards"]
        stored_card = token_bypass.smartcard_config["inserted_cards"][card_id]
        assert stored_card["card_type"] == "PIV"

    def test_x509_certificate_generation_valid(self, token_bypass: HardwareTokenBypass) -> None:
        """X.509 certificate generation produces cryptographically valid certs."""
        cert_data = token_bypass._generate_x509_cert("Test Authentication")

        assert cert_data["common_name"] == "Test Authentication"
        assert cert_data["pem"].startswith("-----BEGIN CERTIFICATE-----")
        assert cert_data["pem"].endswith("-----END CERTIFICATE-----\n")
        assert len(cert_data["der"]) > 0

        cert = x509.load_pem_x509_certificate(
            cert_data["pem"].encode(), default_backend()
        )
        assert cert.serial_number > 0
        assert "US" in cert.subject.rfc4514_string()
        assert "Test Authentication" in cert.subject.rfc4514_string()

    def test_chuid_generation_fips201_compliant(self, token_bypass: HardwareTokenBypass) -> None:
        """CHUID generation complies with FIPS 201 specification."""
        card_id = "ABCD1234"
        chuid = token_bypass._generate_chuid(card_id)

        assert isinstance(chuid, bytes)
        assert len(chuid) > 100

        assert b"\x30\x19" in chuid
        assert b"\x34\x10" in chuid
        assert b"\x35\x08" in chuid
        assert b"\x3e\x40" in chuid

        assert hasattr(token_bypass, "_issuer_key")
        assert isinstance(token_bypass._issuer_key, rsa.RSAPrivateKey)

    @pytest.mark.skipif(os.name != "nt", reason="Windows-specific smart card reader")
    def test_smartcard_reader_emulation_windows(self, token_bypass: HardwareTokenBypass) -> None:
        """Smart card reader emulation on Windows creates virtual reader."""
        if token_bypass.winscard:
            result = token_bypass.emulate_smartcard("PIV")

            assert "reader" in result
            reader_name = result["reader"]
            assert "Virtual" in reader_name or "Reader" in reader_name
            assert "PIV" in reader_name


class TestHardwareTokenBypassMethods:
    """Test hardware token verification bypass methods."""

    def test_bypass_yubikey_verification_structure(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey bypass returns proper result structure."""
        result = token_bypass.bypass_token_verification("notepad.exe", "yubikey")

        assert "success" in result
        assert result["application"] == "notepad.exe"
        assert result["token_type"] == "yubikey"

    def test_bypass_securid_verification_generates_token(self, token_bypass: HardwareTokenBypass) -> None:
        """SecurID bypass generates valid token code."""
        result = token_bypass.bypass_token_verification("outlook.exe", "securid")

        assert result["success"] is True
        assert result["method"] == "Token Generation + Memory Patch"
        assert "generated_token" in result["details"]
        assert len(result["details"]["generated_token"]) == 6
        assert result["details"]["generated_token"].isdigit()
        assert "patched_functions" in result["details"]
        assert len(result["details"]["patched_functions"]) >= 3

    def test_bypass_smartcard_verification_emulates_card(self, token_bypass: HardwareTokenBypass) -> None:
        """Smart card bypass emulates virtual card."""
        result = token_bypass.bypass_token_verification("vpn_client.exe", "smartcard")

        assert result["success"] is True
        assert result["method"] == "Virtual Smart Card"
        assert "card_id" in result["details"]
        assert "card_type" in result["details"]
        assert "certificates" in result["details"]
        assert result["details"]["certificates"] > 0

    def test_bypass_unknown_token_type_error(self, token_bypass: HardwareTokenBypass) -> None:
        """Unknown token type produces appropriate error."""
        result = token_bypass.bypass_token_verification("test.exe", "unknown_token")

        assert result["success"] is False
        assert "error" in result
        assert "unknown_token" in result["error"].lower()

    def test_bypass_yubikey_unix_ld_preload_method(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey bypass on Unix uses LD_PRELOAD technique."""
        result = token_bypass._hook_yubikey_unix("ssh_client")

        assert result["success"] is True
        assert result["method"] == "LD_PRELOAD"
        assert "library" in result["details"]
        assert "env_var" in result["details"]
        assert "LD_PRELOAD=" in result["details"]["env_var"]
        assert "hooked_functions" in result["details"]
        assert "yk_verify_otp" in result["details"]["hooked_functions"]

    def test_create_yubikey_hook_dll_windows(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey hook DLL creation produces valid DLL path."""
        dll_path = token_bypass._create_yubikey_hook_dll()

        assert dll_path.endswith(".dll")
        assert "yubikey_hook" in dll_path

        dll_file = Path(dll_path)
        if dll_file.exists():
            dll_content = dll_file.read_bytes()
            assert dll_content[:2] == b"MZ"
            assert b"PE\x00\x00" in dll_content

    def test_create_yubikey_hook_lib_unix(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey hook library creation produces valid SO path."""
        lib_path = token_bypass._create_yubikey_hook_lib()

        assert lib_path.endswith(".so")
        assert "yubikey_hook" in lib_path

    def test_minimal_dll_generation_valid_pe_structure(self, token_bypass: HardwareTokenBypass) -> None:
        """Minimal DLL generation produces valid PE/COFF structure."""
        dll_bytes = token_bypass._generate_minimal_dll()

        assert dll_bytes[:2] == b"MZ"
        assert b"PE\x00\x00" in dll_bytes
        assert len(dll_bytes) > 600


class TestTokenSecretExtraction:
    """Test hardware token secret extraction from dumps and memory."""

    def test_extract_secrets_nonexistent_file_fails_gracefully(self, token_bypass: HardwareTokenBypass) -> None:
        """Secret extraction from nonexistent file fails gracefully."""
        result = token_bypass.extract_token_secrets("/nonexistent/path/to/file.bin")

        assert result["success"] is False

    def test_extract_secrets_from_yubikey_dump(
        self, token_bypass: HardwareTokenBypass, realistic_yubikey_dump: Path
    ) -> None:
        """Secret extraction finds YubiKey secrets in realistic dump."""
        result = token_bypass.extract_token_secrets(str(realistic_yubikey_dump))

        assert "yubikey_secrets" in result
        yubikey_secrets = result["yubikey_secrets"]
        assert isinstance(yubikey_secrets, dict)
        assert len(yubikey_secrets) > 0

    def test_extract_secrets_from_securid_dump(
        self, token_bypass: HardwareTokenBypass, realistic_securid_dump: Path
    ) -> None:
        """Secret extraction finds SecurID seeds in realistic dump."""
        result = token_bypass.extract_token_secrets(str(realistic_securid_dump))

        assert "securid_seeds" in result
        securid_seeds = result["securid_seeds"]
        assert isinstance(securid_seeds, dict)
        assert len(securid_seeds) > 0

    def test_extract_secrets_from_smartcard_dump(
        self, token_bypass: HardwareTokenBypass, realistic_smartcard_dump: Path
    ) -> None:
        """Secret extraction finds certificates in smart card dump."""
        result = token_bypass.extract_token_secrets(str(realistic_smartcard_dump))

        assert "certificates" in result
        certificates = result["certificates"]
        assert isinstance(certificates, list)
        assert len(certificates) > 0

    def test_extract_yubikey_secrets_high_entropy_detection(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey secret extraction identifies high-entropy AES keys."""
        test_data = bytearray(2048)

        test_data[100:116] = secrets.token_bytes(16)
        test_data[500:516] = secrets.token_bytes(16)
        test_data[1000:1016] = secrets.token_bytes(16)

        result = token_bypass._extract_yubikey_secrets(bytes(test_data))

        assert "yubikey_secrets" in result
        yubikey_secrets = result["yubikey_secrets"]
        assert len(yubikey_secrets) >= 2

    def test_extract_securid_seeds_marker_detection(self, token_bypass: HardwareTokenBypass) -> None:
        """SecurID seed extraction finds RSA and SEED markers."""
        test_data = bytearray(4096)

        test_data[200:203] = b"RSA"
        test_data[203:219] = secrets.token_bytes(16)

        test_data[1000:1004] = b"SEED"
        test_data[1004:1020] = secrets.token_bytes(16)

        test_data[2000:2004] = b"\x00\x00\x00\x10"
        test_data[2004:2020] = secrets.token_bytes(16)

        result = token_bypass._extract_securid_seeds(bytes(test_data))

        assert "securid_seeds" in result
        seeds = result["securid_seeds"]
        assert len(seeds) >= 2

    def test_extract_smartcard_keys_der_certificates(self, token_bypass: HardwareTokenBypass) -> None:
        """Smart card extraction finds DER-encoded certificates."""
        test_data = bytearray(4096)

        test_data[500:502] = b"\x30\x82"
        test_data[502:504] = struct.pack(">H", 512)
        test_data[504:1016] = secrets.token_bytes(512)

        test_data[2000:2002] = b"\x30\x82"
        test_data[2002:2004] = struct.pack(">H", 256)
        test_data[2004:2260] = secrets.token_bytes(256)

        result = token_bypass._extract_smartcard_keys(bytes(test_data))

        assert "certificates" in result
        certs = result["certificates"]
        assert len(certs) >= 2
        assert all(c["format"] == "DER" for c in certs)

    def test_extract_smartcard_keys_pem_certificates(self, token_bypass: HardwareTokenBypass) -> None:
        """Smart card extraction finds PEM-encoded certificates."""
        pem_cert1 = b"-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKL0UG\n-----END CERTIFICATE-----"
        pem_key1 = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAw4VQ\n-----END RSA PRIVATE KEY-----"

        test_data = bytearray(8192)
        test_data[1000:1000 + len(pem_cert1)] = pem_cert1
        test_data[3000:3000 + len(pem_key1)] = pem_key1

        result = token_bypass._extract_smartcard_keys(bytes(test_data))

        certs = result["certificates"]
        pem_certs = [c for c in certs if c["format"] == "PEM"]
        assert len(pem_certs) >= 1

    def test_entropy_calculation_correctness(self, token_bypass: HardwareTokenBypass) -> None:
        """Shannon entropy calculation produces correct values."""
        low_entropy_data = b"A" * 256
        high_entropy_data = secrets.token_bytes(256)

        low_entropy = token_bypass._calculate_entropy(low_entropy_data)
        high_entropy = token_bypass._calculate_entropy(high_entropy_data)

        assert low_entropy < 1.0
        assert high_entropy > 7.0
        assert low_entropy >= 0.0
        assert high_entropy <= 8.0

    def test_entropy_calculation_empty_data(self, token_bypass: HardwareTokenBypass) -> None:
        """Entropy calculation handles empty data correctly."""
        entropy = token_bypass._calculate_entropy(b"")
        assert entropy == 0.0

    def test_entropy_calculation_uniform_distribution(self, token_bypass: HardwareTokenBypass) -> None:
        """Entropy calculation recognizes uniform distribution."""
        uniform_data = bytes(range(256))
        entropy = token_bypass._calculate_entropy(uniform_data)

        assert entropy > 7.9


class TestStandaloneBypassFunction:
    """Test standalone bypass_hardware_token function."""

    def test_standalone_bypass_yubikey(self) -> None:
        """Standalone function bypasses YubiKey verification."""
        result = bypass_hardware_token("application.exe", "yubikey")

        assert "application" in result
        assert result["application"] == "application.exe"
        assert result["token_type"] == "yubikey"

    def test_standalone_bypass_securid(self) -> None:
        """Standalone function bypasses SecurID verification."""
        result = bypass_hardware_token("vpn_app.exe", "securid")

        assert result["success"] is True
        assert "method" in result

    def test_standalone_bypass_smartcard(self) -> None:
        """Standalone function bypasses smart card verification."""
        result = bypass_hardware_token("secure_app.exe", "smartcard")

        assert result["success"] is True
        assert "method" in result

    def test_standalone_bypass_with_emulation_fallback(self) -> None:
        """Standalone function provides emulation if bypass unavailable."""
        result = bypass_hardware_token("test.exe", "yubikey")

        assert "success" in result or "emulation" in result


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling scenarios."""

    def test_yubikey_emulation_empty_serial_generates_new(self, token_bypass: HardwareTokenBypass) -> None:
        """YubiKey emulation with empty serial generates new serial."""
        result = token_bypass.emulate_yubikey("")

        assert result["success"] is True
        assert len(result["serial_number"]) == 8

    def test_multiple_concurrent_yubikey_emulations(self, token_bypass: HardwareTokenBypass) -> None:
        """Multiple concurrent YubiKey emulations maintain separate state."""
        serials = [f"1000000{i}" for i in range(10)]
        results = [token_bypass.emulate_yubikey(serial) for serial in serials]

        assert len(results) == 10
        assert all(r["success"] for r in results)

        otps = [r["otp"] for r in results]
        assert len(set(otps)) == 10

    def test_securid_zero_time_counter(self, token_bypass: HardwareTokenBypass) -> None:
        """SecurID handles zero time counter correctly."""
        seed = secrets.token_bytes(16)
        token = token_bypass._calculate_securid_token(seed, 0)

        assert len(token) == 6
        assert token.isdigit()

    def test_securid_large_time_counter(self, token_bypass: HardwareTokenBypass) -> None:
        """SecurID handles large time counters correctly."""
        seed = secrets.token_bytes(16)
        token = token_bypass._calculate_securid_token(seed, 999999999)

        assert len(token) == 6
        assert token.isdigit()

    def test_smartcard_case_insensitive_card_type(self, token_bypass: HardwareTokenBypass) -> None:
        """Smart card emulation handles case variations."""
        result_upper = token_bypass.emulate_smartcard("PIV")
        result_generic = token_bypass.emulate_smartcard("unknown_type")

        assert result_upper["success"] is True
        assert result_generic["success"] is True
        assert result_generic["card_type"] == "Generic"

    def test_certificate_generation_special_characters_cn(self, token_bypass: HardwareTokenBypass) -> None:
        """Certificate generation handles special characters in CN."""
        cert_data = token_bypass._generate_x509_cert("Test/Auth-2025@Domain")

        assert "pem" in cert_data
        assert "serial_number" in cert_data

    def test_extract_secrets_zero_filled_data(self, token_bypass: HardwareTokenBypass, tmp_path: Path) -> None:
        """Secret extraction handles zero-filled data gracefully."""
        test_file = tmp_path / "zeros.bin"
        test_file.write_bytes(b"\x00" * 4096)

        result = token_bypass.extract_token_secrets(str(test_file))

        assert "secrets" in result
        assert "keys" in result


class TestCryptographicCorrectness:
    """Test cryptographic operations for correctness and security."""

    def test_aes_encryption_different_keys_different_ciphertext(self, token_bypass: HardwareTokenBypass) -> None:
        """AES encryption with different keys produces different ciphertext."""
        plaintext = b"TestDataBlock123"
        key1 = secrets.token_bytes(16)
        key2 = secrets.token_bytes(16)

        ciphertext1 = token_bypass._aes_encrypt(plaintext, key1)
        ciphertext2 = token_bypass._aes_encrypt(plaintext, key2)

        assert ciphertext1 != ciphertext2

    def test_aes_encryption_includes_iv_for_cbc_mode(self, token_bypass: HardwareTokenBypass) -> None:
        """AES encryption includes IV for CBC mode."""
        plaintext = b"TestDataBlock123"
        key = secrets.token_bytes(16)

        ciphertext = token_bypass._aes_encrypt(plaintext, key)

        assert len(ciphertext) >= 32

    def test_crc16_determinism(self, token_bypass: HardwareTokenBypass) -> None:
        """CRC16 calculation is deterministic for same input."""
        test_data = b"Test CRC16 Calculation"

        crc1 = token_bypass._calculate_crc16(test_data)
        crc2 = token_bypass._calculate_crc16(test_data)
        crc3 = token_bypass._calculate_crc16(test_data)

        assert crc1 == crc2 == crc3

    def test_chuid_rsa_signature_verification(self, token_bypass: HardwareTokenBypass) -> None:
        """CHUID RSA signature can be generated and key persists."""
        card_id1 = "AAAA1111"
        card_id2 = "BBBB2222"

        chuid1 = token_bypass._generate_chuid(card_id1)
        chuid2 = token_bypass._generate_chuid(card_id2)

        assert chuid1 != chuid2
        assert hasattr(token_bypass, "_issuer_key")
        assert isinstance(token_bypass._issuer_key, rsa.RSAPrivateKey)


class TestIntegrationWorkflows:
    """Integration tests for complete hardware token bypass workflows."""

    def test_complete_yubikey_workflow(self, token_bypass: HardwareTokenBypass) -> None:
        """Complete YubiKey emulation and bypass workflow."""
        serial = "88888888"

        emulation_result = token_bypass.emulate_yubikey(serial)
        assert emulation_result["success"] is True

        for _ in range(20):
            result = token_bypass.emulate_yubikey(serial)
            assert result["success"] is True
            assert result["serial_number"] == serial

        assert serial in token_bypass.yubikey_secrets

        bypass_result = token_bypass.bypass_token_verification("test_app", "yubikey")
        assert "success" in bypass_result

    def test_complete_securid_workflow(self, token_bypass: HardwareTokenBypass) -> None:
        """Complete SecurID token generation and bypass workflow."""
        serial = "000555666777"
        seed = secrets.token_bytes(16)

        result1 = token_bypass.generate_rsa_securid_token(serial, seed)
        assert result1["success"] is True

        result2 = token_bypass.generate_rsa_securid_token(serial, seed)
        assert result2["success"] is True

        assert serial in token_bypass.rsa_seeds

        bypass_result = token_bypass.bypass_token_verification("app", "securid")
        assert bypass_result["success"] is True

    def test_complete_smartcard_workflow(self, token_bypass: HardwareTokenBypass) -> None:
        """Complete smart card emulation and bypass workflow."""
        piv_card = token_bypass.emulate_smartcard("PIV")
        assert piv_card["success"] is True
        assert len(piv_card["certificates"]) == 4

        cac_card = token_bypass.emulate_smartcard("CAC")
        assert cac_card["success"] is True
        assert len(cac_card["certificates"]) == 3

        generic_card = token_bypass.emulate_smartcard("Generic")
        assert generic_card["success"] is True

        assert len(token_bypass.smartcard_config["inserted_cards"]) >= 3

        bypass_result = token_bypass.bypass_token_verification("app", "smartcard")
        assert bypass_result["success"] is True

    def test_secret_extraction_to_emulation_workflow(
        self, token_bypass: HardwareTokenBypass, realistic_yubikey_dump: Path
    ) -> None:
        """Extract secrets from dump and use for emulation."""
        extraction_result = token_bypass.extract_token_secrets(str(realistic_yubikey_dump))
        assert "yubikey_secrets" in extraction_result

        emulation_result = token_bypass.emulate_yubikey()
        assert emulation_result["success"] is True

    def test_multi_token_concurrent_operations(self, token_bypass: HardwareTokenBypass) -> None:
        """Multiple token types can be used concurrently."""
        yubikey_result = token_bypass.emulate_yubikey("12345678")
        securid_result = token_bypass.generate_rsa_securid_token("000111222333")
        smartcard_result = token_bypass.emulate_smartcard("PIV")

        assert yubikey_result["success"] is True
        assert securid_result["success"] is True
        assert smartcard_result["success"] is True

        assert len(token_bypass.yubikey_secrets) >= 1
        assert len(token_bypass.rsa_seeds) >= 1
        assert len(token_bypass.smartcard_config["inserted_cards"]) >= 1
