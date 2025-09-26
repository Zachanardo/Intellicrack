"""Copyright (C) 2025 Zachary Flint.

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

import pytest
import os
import time
import base64
import hashlib
import hmac
import struct
from pathlib import Path
import threading

from intellicrack.core.protection_bypass.hardware_token import (
    HardwareTokenBypass,
    bypass_hardware_token
)


class TestHardwareTokenEmulation:
    """Production tests for hardware token emulation against real protection systems."""

    @pytest.fixture
    def bypasser(self):
        """Create hardware token bypasser instance."""
        return HardwareTokenBypass()

    def test_yubikey_otp_generation(self, bypasser):
        """Test YubiKey OTP generation with real algorithm."""
        result = bypasser.emulate_yubikey()

        assert result['success'] is True
        assert 'otp' in result
        assert len(result['otp']) == 44  # 12 char public ID + 32 char OTP

        # Verify modhex encoding
        modhex_chars = set('cbdefghijklnrtuv')
        assert all(c in modhex_chars for c in result['otp'][12:])

    def test_yubikey_counter_increment(self, bypasser):
        """Test YubiKey session and usage counter increment."""
        serial = "12345678"

        # Generate first OTP
        result1 = bypasser.emulate_yubikey(serial)
        session1 = result1["session"]
        counter1 = result1["counter"]

        # Generate second OTP
        result2 = bypasser.emulate_yubikey(serial)
        session2 = result2["session"]
        counter2 = result2["counter"]

        # Session should increment
        assert session2 == session1 + 1
        assert counter2 == counter1

        # Force session overflow
        bypasser.yubikey_secrets[serial]["session"] = 0xFF
        result3 = bypasser.emulate_yubikey(serial)

        # Counter should increment when session wraps
        assert result3["session"] == 0
        assert result3["counter"] == counter2 + 1

    def test_yubikey_crc16_validation(self, bypasser):
        """Test CRC16-CCITT calculation for YubiKey OTP."""
        test_data = b"test data for crc"
        crc = bypasser._calculate_crc16(test_data)

        # CRC16 should be 16-bit value
        assert isinstance(crc, int)
        assert crc <= 0xFFFF
        assert crc >= 0

    def test_modhex_encoding(self, bypasser):
        """Test ModHex encoding for YubiKey."""
        test_data = b"\x00\xFF\x12\x34\x56\x78\x9A\xBC"
        modhex = bypasser._to_modhex(test_data)

        # Check ModHex length (2 chars per byte)
        assert len(modhex) == len(test_data) * 2

        # Verify all characters are valid ModHex
        valid_chars = set("cbdefghijklnrtuv")
        assert all(c in valid_chars for c in modhex)

    def test_yubikey_usb_device_emulation(self, bypasser):
        """Test YubiKey USB device emulation."""
        usb_device = bypasser._emulate_yubikey_usb("12345678")

        # Verify Yubico vendor ID
        assert usb_device["vendor_id"] == 0x1050

        # Verify YubiKey 5 NFC product ID
        assert usb_device["product_id"] == 0x0407

        # Check all capabilities are present
        capabilities = usb_device["capabilities"]
        expected = ["otp", "u2f", "fido2", "oath", "piv", "openpgp"]
        for cap in expected:
            assert capabilities[cap]

    def test_rsa_securid_token_generation(self, bypasser):
        """Test RSA SecurID token code generation."""
        result = bypasser.generate_rsa_securid_token()

        assert result['success'] is True
        assert 'token_code' in result
        assert 'serial_number' in result

        # Verify token format (6 digits by default)
        token = result['token_code']
        assert len(token) == 6
        assert token.isdigit()

    def test_securid_time_based_tokens(self, bypasser):
        """Test time-based token generation."""
        serial = "000123456789"
        seed = os.urandom(16)

        # Generate tokens at different times
        result1 = bypasser.generate_rsa_securid_token(serial, seed)
        token1 = result1["token_code"]

        # Same seed should generate same token within interval
        result2 = bypasser.generate_rsa_securid_token(serial, seed)
        token2 = result2["token_code"]
        assert token1 == token2

        # Verify next token is different
        next_token = result1["next_token"]
        assert token1 != next_token

    def test_securid_serial_format(self, bypasser):
        """Test RSA SecurID serial number format."""
        serial = bypasser._generate_securid_serial()

        # Should be 12 digits starting with 000
        assert len(serial) == 12
        assert serial.startswith("000")
        assert serial.isdigit()

    def test_securid_aes_algorithm(self, bypasser):
        """Test SecurID AES-based token calculation."""
        seed = b"\x01" * 16
        time_counter = 1234567890

        token = bypasser._calculate_securid_token(seed, time_counter)

        # Should be 6 digits
        assert len(token) == 6
        assert token.isdigit()

        # Same inputs should give same output
        token2 = bypasser._calculate_securid_token(seed, time_counter)
        assert token == token2

    def test_securid_time_remaining(self, bypasser):
        """Test time remaining calculation."""
        result = bypasser.generate_rsa_securid_token()

        time_remaining = result["time_remaining"]
        interval = result["interval"]

        # Time remaining should be less than interval
        assert time_remaining < interval
        assert time_remaining >= 0

    def test_piv_card_generation(self, bypasser):
        """Test PIV card data generation."""
        result = bypasser.emulate_smartcard("PIV")

        assert result['success'] is True
        assert result['card_type'] == 'PIV'

        # Verify certificates are present
        certs = result['certificates']
        expected = ["piv_auth", "piv_sign", "piv_key_mgmt", "piv_card_auth"]
        for cert_type in expected:
            assert cert_type in certs

        # Verify CHUID is present
        assert 'chuid' in result
        chuid = result['chuid']
        assert isinstance(chuid, bytes)
        assert len(chuid) > 0

        # Verify GUID format
        assert 'guid' in result
        assert len(result['guid']) == 32

    def test_cac_card_generation(self, bypasser):
        """Test CAC card data generation."""
        result = bypasser.emulate_smartcard("CAC")

        assert result['success'] is True
        assert result['card_type'] == 'CAC'

        # Verify EDIPI format (10 digits)
        edipi = result['edipi']
        assert len(edipi) == 10
        assert edipi.isdigit()

        # Verify military-specific fields
        assert 'person_designator' in result
        assert 'personnel_category' in result
        assert 'branch' in result

    def test_chuid_structure(self, bypasser):
        """Test CHUID generation with proper structure."""
        card_id = "1234567890ABCDEF"
        chuid = bypasser._generate_chuid(card_id)

        # CHUID should contain specific tags
        assert b'\x30\x19' in chuid  # FASC-N tag
        assert b'\x34\x10' in chuid  # GUID tag
        assert b'\x35\x08' in chuid  # Expiry tag
        assert b'\x3e\x40' in chuid  # Signature tag

        # Verify signature is present (64 bytes after tag)
        sig_pos = chuid.find(b'\x3e\x40')
        assert sig_pos != -1
        # Signature should be at least 64 bytes
        assert len(chuid) - sig_pos - 2 > 63

    def test_x509_certificate_generation(self, bypasser):
        """Test X.509 certificate generation."""
        cert_data = bypasser._generate_x509_cert("Test Authentication")

        # Verify certificate fields
        assert 'common_name' in cert_data
        assert cert_data['common_name'] == "Test Authentication"

        assert 'serial_number' in cert_data
        assert 'issuer' in cert_data
        assert 'subject' in cert_data

        # Verify PEM format
        assert 'pem' in cert_data
        pem = cert_data['pem']
        assert pem.startswith("-----BEGIN CERTIFICATE-----")
        assert pem.endswith("-----END CERTIFICATE-----\n")

        # Verify DER format
        assert 'der' in cert_data
        der_hex = cert_data['der']
        assert all(c in '0123456789abcdef' for c in der_hex.lower())

        # Verify key size
        assert cert_data['public_key_size'] == 2048

    @pytest.mark.skipif(os.name != 'nt', reason="Windows-specific test")
    def test_windows_hook_dll_generation(self, bypasser):
        """Test Windows DLL generation for API hooking."""
        dll_path = bypasser._create_yubikey_hook_dll()

        # DLL should be created
        assert os.path.exists(dll_path)

        # Read DLL and verify PE structure
        with open(dll_path, 'rb') as f:
            dll_data = f.read()

        # Check for PE signature
        assert dll_data.startswith(b'MZ')

        # Find PE header
        pe_offset = struct.unpack('<I', dll_data[0x3C:0x40])[0]
        assert dll_data[pe_offset:pe_offset+4] == b'PE\x00\x00'

    @pytest.mark.skipif(os.name == 'nt', reason="Unix-specific test")
    def test_unix_hook_library_generation(self, bypasser):
        """Test Unix shared library generation for LD_PRELOAD."""
        lib_path = bypasser._create_yubikey_hook_lib()

        # Library should be created
        assert os.path.exists(lib_path)

        # Should have .so extension
        assert lib_path.endswith('.so')

    def test_yubikey_bypass_methods(self, bypasser):
        """Test YubiKey verification bypass methods."""
        result = bypasser._bypass_yubikey_verification("test_app")

        assert 'method' in result

        if os.name == 'nt':
            # Windows should use DLL injection
            if result.get("success"):
                assert result["method"] == "DLL Injection"
        else:
            # Unix should use LD_PRELOAD
            assert result["method"] == "LD_PRELOAD"

    def test_securid_bypass_methods(self, bypasser):
        """Test RSA SecurID bypass methods."""
        result = bypasser._bypass_securid_verification("test_app")

        assert result['success'] is True
        assert result['method'] == "Token Generation + Memory Patch"
        assert 'generated_token' in result['details']

    def test_smartcard_bypass_methods(self, bypasser):
        """Test smart card bypass methods."""
        result = bypasser._bypass_smartcard_verification("test_app")

        assert result['success'] is True
        assert result['method'] == "Virtual Smart Card"
        assert 'card_id' in result['details']
        assert 'card_type' in result['details']

    def test_token_secret_extraction(self, bypasser):
        """Test extraction of token secrets from memory."""
        # Create test data with planted secrets
        test_data = bytearray(1024)

        # Plant YubiKey AES key (high entropy)
        aes_key = os.urandom(16)
        test_data[100:116] = aes_key

        # Plant RSA SecurID seed
        test_data[200:203] = b'RSA'
        seed = os.urandom(16)
        test_data[203:219] = seed

        # Plant certificate marker
        test_data[300:302] = b'\x30\x82'
        test_data[302:304] = struct.pack('>H', 100)

        # Extract secrets
        yubikey_result = bypasser._extract_yubikey_secrets(bytes(test_data))
        securid_result = bypasser._extract_securid_seeds(bytes(test_data))
        smartcard_result = bypasser._extract_smartcard_keys(bytes(test_data))

        # Should find planted secrets
        assert yubikey_result["yubikey_secrets"]
        assert securid_result["securid_seeds"]

    def test_entropy_calculation(self, bypasser):
        """Test Shannon entropy calculation."""
        # Low entropy (repeated bytes)
        low_entropy_data = b'\x00' * 16
        low = bypasser._calculate_entropy(low_entropy_data)
        assert low < 2.0

        # High entropy (random bytes)
        high_entropy_data = os.urandom(16)
        high = bypasser._calculate_entropy(high_entropy_data)
        assert high > 6.0

        # Medium entropy
        medium_entropy_data = b'AAAABBBBCCCCDDDD'
        medium = bypasser._calculate_entropy(medium_entropy_data)
        assert medium > low
        assert medium < high

    def test_bypass_hardware_token_yubikey(self):
        """Test main bypass function for YubiKey."""
        result = bypass_hardware_token("chrome.exe", "yubikey")

        assert 'success' in result
        assert 'application' in result
        assert result['token_type'] == 'yubikey'

        # Should have either bypass or emulation
        if not result.get("success"):
            assert 'emulation' in result

    def test_bypass_hardware_token_securid(self):
        """Test main bypass function for SecurID."""
        result = bypass_hardware_token("vpn_client.exe", "securid")

        assert 'success' in result
        assert 'application' in result
        assert result['token_type'] == 'securid'

    def test_bypass_hardware_token_smartcard(self):
        """Test main bypass function for smart card."""
        result = bypass_hardware_token("outlook.exe", "smartcard")

        assert 'success' in result
        assert 'application' in result
        assert result['token_type'] == 'smartcard'

    def test_bypass_unknown_token_type(self):
        """Test bypass with unknown token type."""
        result = bypass_hardware_token("app.exe", "unknown_token")

        assert result['success'] is False
        assert 'error' in result
        assert "Unknown token type" in result['error']
