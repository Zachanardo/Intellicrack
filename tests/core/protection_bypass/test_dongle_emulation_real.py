"""Production tests for hardware dongle emulation.

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
import struct
from typing import Any, Callable, Dict, List, Optional, Tuple, Type

import pytest

try:
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
        WibuKeyDongle,
    )
    MODULE_AVAILABLE: bool = True
except ImportError:
    CryptoEngine = None  # type: ignore[misc, assignment]
    DongleMemory = None  # type: ignore[misc, assignment]
    HardwareDongleEmulator = None  # type: ignore[misc, assignment]
    HASPDongle = None  # type: ignore[misc, assignment]
    HASPStatus = None  # type: ignore[misc, assignment]
    SentinelDongle = None  # type: ignore[misc, assignment]
    SentinelStatus = None  # type: ignore[misc, assignment]
    USBDescriptor = None  # type: ignore[misc, assignment]
    USBEmulator = None  # type: ignore[misc, assignment]
    WibuKeyDongle = None  # type: ignore[misc, assignment]
    MODULE_AVAILABLE = False

pytestmark = pytest.mark.skipif(not MODULE_AVAILABLE, reason="Module not available")


class TestHardwareDongleEmulator:
    """Production tests for hardware dongle emulation against real protection systems."""

    def test_emulator_initialization(self) -> None:
        """Test that HardwareDongleEmulator initializes correctly."""
        emulator: Any = HardwareDongleEmulator()

        assert emulator is not None
        assert hasattr(emulator, 'activate_dongle_emulation')
        assert hasattr(emulator, 'process_hasp_challenge')
        assert hasattr(emulator, 'read_dongle_memory')
        assert hasattr(emulator, 'write_dongle_memory')
        assert hasattr(emulator, 'crypto_engine')
        assert isinstance(emulator.crypto_engine, type(CryptoEngine))

    def test_activate_dongle_emulation_hasp(self) -> None:
        """Test HASP dongle emulation activation with real validation."""
        emulator: Any = HardwareDongleEmulator()

        result: Any = emulator.activate_dongle_emulation(['HASP'])

        assert result is not None
        assert isinstance(result, dict)
        assert 'success' in result
        assert 'emulated_dongles' in result
        assert 'methods_applied' in result
        assert result['success'] is True
        assert len(result['emulated_dongles']) > 0
        assert 'HASP_1' in result['emulated_dongles']
        assert 'Virtual Dongle Creation' in result['methods_applied']
        assert 'USB Device Emulation' in result['methods_applied']

    def test_activate_dongle_emulation_sentinel(self) -> None:
        """Test Sentinel dongle emulation activation."""
        emulator: Any = HardwareDongleEmulator()

        result: Any = emulator.activate_dongle_emulation(['Sentinel'])

        assert result['success'] is True
        assert any('Sentinel_' in d for d in result['emulated_dongles'])
        assert 1 in emulator.sentinel_dongles
        sentinel: Any = emulator.sentinel_dongles[1]
        assert sentinel.device_id == 0x87654322
        assert sentinel.serial_number == "SN123456789ABCDEF"
        assert sentinel.firmware_version == "8.0.0"

    def test_activate_dongle_emulation_codemeter(self) -> None:
        """Test CodeMeter/WibuKey dongle emulation activation."""
        emulator: Any = HardwareDongleEmulator()

        result: Any = emulator.activate_dongle_emulation(['CodeMeter'])

        assert result['success'] is True
        assert any('WibuKey_' in d for d in result['emulated_dongles'])
        assert 1 in emulator.wibukey_dongles
        wibu: Any = emulator.wibukey_dongles[1]
        assert wibu.firm_code == 101
        assert wibu.product_code == 1000
        assert wibu.serial_number == 1000001

    def test_activate_all_dongles(self) -> None:
        """Test activating multiple dongle types simultaneously."""
        emulator: Any = HardwareDongleEmulator()

        result: Any = emulator.activate_dongle_emulation(['HASP', 'Sentinel', 'CodeMeter'])

        assert result['success'] is True
        assert len(result['emulated_dongles']) >= 3
        assert len(emulator.hasp_dongles) > 0
        assert len(emulator.sentinel_dongles) > 0
        assert len(emulator.wibukey_dongles) > 0

    def test_crypto_engine_hasp_aes_encryption(self) -> None:
        """Test HASP AES encryption produces valid ciphertext."""
        crypto: Any = CryptoEngine()
        plaintext: bytes = b'TestData12345678'
        key: bytes = b'0123456789ABCDEF0123456789ABCDEF'

        ciphertext: Any = crypto.hasp_encrypt(plaintext, key, 'AES')

        assert ciphertext is not None
        assert len(ciphertext) >= len(plaintext)
        assert ciphertext != plaintext

        decrypted: Any = crypto.hasp_decrypt(ciphertext, key, 'AES')
        assert decrypted == plaintext

    def test_crypto_engine_hasp_des_encryption(self) -> None:
        """Test HASP DES encryption for legacy dongle support."""
        crypto: Any = CryptoEngine()
        plaintext: bytes = b'TestData'
        key: bytes = b'01234567'

        ciphertext: Any = crypto.hasp_encrypt(plaintext, key, 'DES')

        assert ciphertext is not None
        assert ciphertext != plaintext

        decrypted: Any = crypto.hasp_decrypt(ciphertext, key, 'DES')
        assert decrypted == plaintext

    def test_crypto_engine_sentinel_challenge_response(self) -> None:
        """Test Sentinel HMAC-based challenge-response."""
        crypto: Any = CryptoEngine()
        challenge: bytes = b'CHALLENGE_DATA_123'
        key: bytes = b'SECRET_KEY_123456789012345678901234'

        response: Any = crypto.sentinel_challenge_response(challenge, key)

        assert response is not None
        assert len(response) == 16
        assert response != challenge

        expected_hmac: bytes = hmac.new(key, challenge, hashlib.sha256).digest()[:16]
        assert response == expected_hmac

    def test_crypto_engine_wibukey_challenge_response(self) -> None:
        """Test WibuKey custom challenge-response algorithm."""
        crypto: Any = CryptoEngine()
        challenge: bytes = b'1234567890ABCDEF'
        key: bytes = b'WIBU_KEY_SECRET_'

        response: Any = crypto.wibukey_challenge_response(challenge, key)

        assert response is not None
        assert len(response) == 16
        assert response != challenge

    def test_dongle_memory_read_write(self) -> None:
        """Test dongle memory operations with bounds checking."""
        memory: Any = DongleMemory()

        test_data: bytes = b'MEMORY_TEST_DATA'
        memory.write('ram', 0x100, test_data)

        read_data: Any = memory.read('ram', 0x100, len(test_data))
        assert read_data == test_data

    def test_dongle_memory_bounds_checking(self) -> None:
        """Test that memory operations enforce bounds."""
        memory: Any = DongleMemory()

        with pytest.raises(ValueError, match="beyond memory bounds"):
            memory.read('ram', 5000, 100)

        with pytest.raises(ValueError, match="beyond memory bounds"):
            memory.write('ram', 5000, b'data')

    def test_dongle_memory_read_only_protection(self) -> None:
        """Test read-only memory area protection."""
        memory: Any = DongleMemory()
        memory.read_only_areas = [(0, 512)]

        with pytest.raises(PermissionError, match="Cannot write to read-only"):
            memory.write('rom', 100, b'data')

    def test_hasp_dongle_creation(self) -> None:
        """Test HASP dongle data structure initialization."""
        dongle: Any = HASPDongle()

        assert dongle.hasp_id == 0x12345678
        assert dongle.vendor_code == 0x1234
        assert dongle.feature_id == 1
        assert len(dongle.seed_code) == 16
        assert len(dongle.aes_key) == 32
        assert len(dongle.des_key) == 24
        assert dongle.feature_id in dongle.feature_map
        assert dongle.feature_map[1]['expiration'] == 0xFFFFFFFF

    def test_sentinel_dongle_creation(self) -> None:
        """Test Sentinel dongle data structure initialization."""
        dongle: Any = SentinelDongle()

        assert dongle.device_id == 0x87654321
        assert dongle.serial_number == "SN123456789ABCDEF"
        assert dongle.firmware_version == "8.0.0"
        assert len(dongle.cell_data) == 8
        for i in range(8):
            assert len(dongle.cell_data[i]) == 64

    def test_wibukey_dongle_creation(self) -> None:
        """Test WibuKey dongle data structure initialization."""
        dongle: Any = WibuKeyDongle()

        assert dongle.firm_code == 101
        assert dongle.product_code == 1000
        assert dongle.feature_code == 1
        assert dongle.serial_number == 1000001
        assert dongle.version == "6.90"
        assert 1 in dongle.license_entries
        assert dongle.license_entries[1]['quantity'] == 100
        assert dongle.license_entries[1]['expiration'] == 0xFFFFFFFF

    def test_usb_descriptor_serialization(self) -> None:
        """Test USB descriptor binary serialization."""
        descriptor: Any = USBDescriptor(
            idVendor=0x0529,
            idProduct=0x0001
        )

        binary: Any = descriptor.to_bytes()

        assert len(binary) == 18
        assert isinstance(binary, bytes)

        unpacked: Tuple[int, ...] = struct.unpack('<BBHBBBBHHHBBBB', binary)
        assert unpacked[7] == 0x0529
        assert unpacked[8] == 0x0001

    def test_usb_emulator_control_transfer(self) -> None:
        """Test USB control transfer handling."""
        descriptor: Any = USBDescriptor()
        usb: Any = USBEmulator(descriptor)

        response: Any = usb.control_transfer(0x80, 0x06, 0x0100, 0, b'')

        assert response is not None
        assert len(response) == 18
        assert response == descriptor.to_bytes()

    def test_usb_emulator_string_descriptor(self) -> None:
        """Test USB string descriptor generation."""
        descriptor: Any = USBDescriptor()
        usb: Any = USBEmulator(descriptor)

        manufacturer: Any = usb.get_string_descriptor(1)
        assert manufacturer is not None
        assert b'SafeNet Inc.' in manufacturer

    def test_hasp_login_logout_protocol(self) -> None:
        """Test HASP login/logout protocol implementation."""
        emulator: Any = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(['HASP'])

        login_data: bytes = struct.pack('<HH', 0x1234, 1)
        login_response: Any = emulator._hasp_login(login_data)

        assert len(login_response) == 8
        status, handle = struct.unpack('<II', login_response)
        assert status == HASPStatus.HASP_STATUS_OK
        assert handle != 0

        logout_data: bytes = struct.pack('<I', handle)
        logout_response: Any = emulator._hasp_logout(logout_data)

        assert len(logout_response) == 4
        status = struct.unpack('<I', logout_response)[0]
        assert status == HASPStatus.HASP_STATUS_OK

    def test_hasp_encrypt_decrypt_protocol(self) -> None:
        """Test HASP encryption/decryption protocol."""
        emulator: Any = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(['HASP'])

        dongle: Any = list(emulator.hasp_dongles.values())[0]
        dongle.logged_in = True
        dongle.session_handle = 0x12345678

        plaintext: bytes = b'TestEncryptData!'
        encrypt_data: bytes = struct.pack('<II', dongle.session_handle, len(plaintext)) + plaintext
        encrypt_response: Any = emulator._hasp_encrypt_command(encrypt_data)

        status, length = struct.unpack('<II', encrypt_response[:8])
        assert status == HASPStatus.HASP_STATUS_OK
        assert length > 0
        ciphertext: bytes = encrypt_response[8:]
        assert ciphertext != plaintext

    def test_hasp_memory_read_write_protocol(self) -> None:
        """Test HASP memory read/write protocol."""
        emulator: Any = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(['HASP'])

        dongle: Any = list(emulator.hasp_dongles.values())[0]
        dongle.logged_in = True
        dongle.session_handle = 0x12345678

        write_data: bytes = b'TEST_MEM_DATA'
        write_cmd: bytes = struct.pack('<III', dongle.session_handle, 0x10, len(write_data)) + write_data
        write_response: Any = emulator._hasp_write_memory(write_cmd)

        status = struct.unpack('<I', write_response)[0]
        assert status == HASPStatus.HASP_STATUS_OK

        read_cmd: bytes = struct.pack('<III', dongle.session_handle, 0x10, len(write_data))
        read_response: Any = emulator._hasp_read_memory(read_cmd)

        status, length = struct.unpack('<II', read_response[:8])
        assert status == HASPStatus.HASP_STATUS_OK
        assert length == len(write_data)

    def test_sentinel_query_protocol(self) -> None:
        """Test Sentinel query protocol implementation."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(['Sentinel'])

        query_response = emulator._sentinel_query(b'')

        status = struct.unpack('<I', query_response)[0]
        assert status == SentinelStatus.SP_SUCCESS

        dongle = list(emulator.sentinel_dongles.values())[0]
        response_data = bytes(dongle.response_buffer[:52])
        device_id = struct.unpack('<I', response_data[:4])[0]
        assert device_id == dongle.device_id

    def test_sentinel_read_write_protocol(self) -> None:
        """Test Sentinel cell read/write protocol."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(['Sentinel'])

        cell_id = 0
        test_data = b'SENTINEL_CELL_DATA' + b'\x00' * 46
        write_cmd = struct.pack('<II', cell_id, len(test_data)) + test_data
        write_response = emulator._sentinel_write(write_cmd)

        status = struct.unpack('<I', write_response)[0]
        assert status == SentinelStatus.SP_SUCCESS

        read_cmd = struct.pack('<II', cell_id, 64)
        read_response = emulator._sentinel_read(read_cmd)

        status = struct.unpack('<I', read_response)[0]
        assert status == SentinelStatus.SP_SUCCESS

    def test_wibukey_access_protocol(self) -> None:
        """Test WibuKey/CodeMeter access protocol."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(['CodeMeter'])

        dongle = list(emulator.wibukey_dongles.values())[0]

        access_cmd = struct.pack('<III', dongle.container_handle, 1, 1)
        access_response = emulator._wibukey_access(access_cmd)

        status = struct.unpack('<I', access_response)[0]
        assert status == 0
        assert 1 in dongle.active_licenses

    def test_wibukey_challenge_response_protocol(self) -> None:
        """Test WibuKey challenge-response protocol."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(['CodeMeter'])

        dongle = list(emulator.wibukey_dongles.values())[0]

        challenge = b'1234567890ABCDEF'
        challenge_cmd = struct.pack('<II', dongle.container_handle, len(challenge)) + challenge
        response = emulator._wibukey_challenge(challenge_cmd)

        status, length = struct.unpack('<II', response[:8])
        assert status == 0
        assert length == 16
        response_data = response[8:]
        assert response_data != challenge

    def test_process_hasp_challenge(self) -> None:
        """Test HASP challenge processing with real crypto."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(['HASP'])

        challenge = b'CHALLENGE_DATA_1234567890ABCDEF'
        response = emulator.process_hasp_challenge(challenge, 1)

        assert response is not None
        assert len(response) == 16
        assert response != challenge

    def test_read_dongle_memory_api(self) -> None:
        """Test public API for reading dongle memory."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(['HASP'])

        data = emulator.read_dongle_memory('HASP', 1, 'ram', 0, 16)

        assert data is not None
        assert len(data) == 16

    def test_write_dongle_memory_api(self) -> None:
        """Test public API for writing dongle memory."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(['HASP'])

        test_data = b'TEST_API_DATA'
        success = emulator.write_dongle_memory('HASP', 1, 'ram', 0x100, test_data)

        assert success is True

        read_data = emulator.read_dongle_memory('HASP', 1, 'ram', 0x100, len(test_data))
        assert read_data == test_data

    def test_emulation_status(self) -> None:
        """Test emulation status reporting."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(['HASP', 'Sentinel'])

        status = emulator.get_emulation_status()

        assert 'hooks_installed' in status
        assert 'virtual_dongles_active' in status
        assert 'hasp_dongles' in status
        assert 'sentinel_dongles' in status
        assert status['hasp_dongles'] > 0
        assert status['sentinel_dongles'] > 0

    def test_frida_script_generation(self) -> None:
        """Test Frida hook script generation."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(['HASP'])

        script = emulator.generate_emulation_script(['HASP'])

        assert script is not None
        assert 'hasp_login' in script
        assert 'hasp_encrypt' in script
        assert 'hasp_decrypt' in script
        assert 'hasp_read' in script
        assert 'Interceptor.attach' in script

    def test_clear_emulation(self) -> None:
        """Test clearing all emulation state."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(['HASP', 'Sentinel', 'CodeMeter'])

        assert len(emulator.virtual_dongles) > 0
        assert len(emulator.hasp_dongles) > 0

        emulator.clear_emulation()

        assert len(emulator.virtual_dongles) == 0
        assert len(emulator.hasp_dongles) == 0
        assert len(emulator.sentinel_dongles) == 0
        assert len(emulator.wibukey_dongles) == 0

    def test_binary_patching_identification(self) -> None:
        """Test identification of dongle check patterns for patching."""
        emulator = HardwareDongleEmulator()

        class MockApp:
            binary_path = None

        emulator.app = MockApp()

        emulator._patch_dongle_checks()

        assert len(emulator.patches) == 0

    def test_crypto_xor_fallback(self) -> None:
        """Test XOR encryption fallback when PyCrypto unavailable."""
        crypto = CryptoEngine()
        plaintext = b'TestDataForXOR'
        key = b'KEY123'

        ciphertext = crypto._xor_encrypt(plaintext, key)

        assert ciphertext is not None
        assert ciphertext != plaintext

        decrypted = crypto._xor_encrypt(ciphertext, key)
        assert decrypted == plaintext

    def test_hasp_status_codes(self) -> None:
        """Test HASP status code enumeration."""
        assert HASPStatus.HASP_STATUS_OK == 0  # type: ignore[comparison-overlap]
        assert HASPStatus.HASP_MEM_RANGE == 1  # type: ignore[comparison-overlap]
        assert HASPStatus.HASP_TOO_SHORT == 2  # type: ignore[comparison-overlap]
        assert HASPStatus.HASP_INV_HND == 3  # type: ignore[comparison-overlap]
        assert HASPStatus.HASP_KEYNOTFOUND == 7  # type: ignore[comparison-overlap]

    def test_sentinel_status_codes(self) -> None:
        """Test Sentinel status code enumeration."""
        assert SentinelStatus.SP_SUCCESS == 0  # type: ignore[comparison-overlap]
        assert SentinelStatus.SP_INVALID_FUNCTION_CODE == 1  # type: ignore[comparison-overlap]
        assert SentinelStatus.SP_UNIT_NOT_FOUND == 2  # type: ignore[comparison-overlap]
        assert SentinelStatus.SP_ACCESS_DENIED == 3  # type: ignore[comparison-overlap]

    def test_multiple_hasp_dongles(self) -> None:
        """Test creation of multiple HASP dongles."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(['HASP', 'HASP'])

        assert len(emulator.hasp_dongles) >= 1

        dongle_ids = [d.hasp_id for d in emulator.hasp_dongles.values()]
        assert len(set(dongle_ids)) == len(dongle_ids)

    def test_dongle_memory_protected_areas(self) -> None:
        """Test protected memory area checking."""
        memory = DongleMemory()
        memory.protected_areas = [(0x100, 0x200)]

        assert memory.is_protected(0x100, 50) is True
        assert memory.is_protected(0x300, 50) is False

    def test_usb_bulk_transfer(self) -> None:
        """Test USB bulk transfer routing."""
        descriptor = USBDescriptor()
        usb = USBEmulator(descriptor)

        handler_called = False

        def test_handler(data: bytes) -> bytes:
            nonlocal handler_called
            handler_called = True
            return b'RESPONSE'

        usb.register_bulk_handler(0x81, test_handler)

        response = usb.bulk_transfer(0x81, b'TEST')
        assert handler_called
        assert response == b'RESPONSE'

    def test_hasp_login_invalid_vendor(self) -> None:
        """Test HASP login with invalid vendor code."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(['HASP'])

        login_data = struct.pack('<HH', 0xFFFF, 1)
        login_response = emulator._hasp_login(login_data)

        status = struct.unpack('<I', login_response)[0]
        assert status == HASPStatus.HASP_KEYNOTFOUND

    def test_hasp_operations_without_login(self) -> None:
        """Test HASP operations fail without valid session."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(['HASP'])

        invalid_session = 0xFFFFFFFF
        plaintext = b'TestData'
        encrypt_data = struct.pack('<II', invalid_session, len(plaintext)) + plaintext
        encrypt_response = emulator._hasp_encrypt_command(encrypt_data)

        status = struct.unpack('<I', encrypt_response)[0]
        assert status == HASPStatus.HASP_INV_HND

    def test_sentinel_encrypt_operation(self) -> None:
        """Test Sentinel encryption operation."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(['Sentinel'])

        plaintext = b'TEST_ENCRYPT_DATA'
        encrypt_cmd = struct.pack('<I', len(plaintext)) + plaintext
        encrypt_response = emulator._sentinel_encrypt(encrypt_cmd)

        status = struct.unpack('<I', encrypt_response)[0]
        assert status == SentinelStatus.SP_SUCCESS

    def test_wibukey_open_operation(self) -> None:
        """Test WibuKey container open operation."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(['CodeMeter'])

        dongle = list(emulator.wibukey_dongles.values())[0]

        open_cmd = struct.pack('<II', dongle.firm_code, dongle.product_code)
        open_response = emulator._wibukey_open(open_cmd)

        status, handle = struct.unpack('<II', open_response)
        assert status == 0
        assert handle == dongle.container_handle

    def test_wibukey_encrypt_operation(self) -> None:
        """Test WibuKey encryption operation."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(['CodeMeter'])

        dongle = list(emulator.wibukey_dongles.values())[0]

        plaintext = b'WIBU_TEST_DATA'
        encrypt_cmd = struct.pack('<II', dongle.container_handle, len(plaintext)) + plaintext
        encrypt_response = emulator._wibukey_encrypt(encrypt_cmd)

        status, length = struct.unpack('<II', encrypt_response[:8])
        assert status == 0
        assert length > 0
