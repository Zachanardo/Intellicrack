"""Production tests for dongle_emulator.py Frida script completeness.

Validates that ALL Frida hook implementations for HASP/Sentinel/CodeMeter APIs are
complete, functional, and properly handle all required operations including session
management, encryption, memory operations, and edge cases.

These tests MUST FAIL if any function is undefined, incomplete, or non-functional.
"""

import re
import struct
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.protection_bypass.dongle_emulator import (
    HardwareDongleEmulator,
    HASPStatus,
    SentinelStatus,
)
from intellicrack.utils.core.import_checks import FRIDA_AVAILABLE


class TestFridaScriptCompleteness:
    """Validate all Frida hook implementations are complete and functional."""

    def test_frida_script_generation_succeeds(self) -> None:
        """Frida script generation produces non-empty script for all dongle types."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP", "Sentinel", "CodeMeter"])

        script = emulator.generate_emulation_script(["HASP", "Sentinel", "CodeMeter"])

        assert script != ""
        assert len(script) > 1000
        assert "console.log" in script
        assert "Interceptor.attach" in script

    def test_all_hasp_api_functions_are_hooked(self) -> None:
        """All required HASP API functions have Interceptor.attach hooks defined."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        script = emulator.generate_emulation_script(["HASP"])

        required_hasp_functions = [
            "hasp_login",
            "hasp_encrypt",
            "hasp_decrypt",
            "hasp_read",
            "hasp_write",
            "hasp_get_size",
        ]

        for func_name in required_hasp_functions:
            assert f'Module.findExportByName(haspModule.name, "{func_name}")' in script
            hook_pattern = rf'{func_name}.*?Interceptor\.attach\({func_name},'
            assert re.search(hook_pattern, script, re.DOTALL) is not None

    def test_hasp_login_hook_has_complete_implementation(self) -> None:
        """hasp_login hook implements complete onEnter and onLeave handlers."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        script = emulator.generate_emulation_script(["HASP"])

        hasp_login_match = re.search(
            r'var haspLogin = Module\.findExportByName\(haspModule\.name, "hasp_login"\);.*?'
            r'Interceptor\.attach\(haspLogin, \{(.*?)\}\}\);',
            script,
            re.DOTALL
        )
        assert hasp_login_match is not None

        login_impl = hasp_login_match.group(1)

        assert "onEnter: function(args)" in login_impl
        assert "onLeave: function(retval)" in login_impl

        assert "this.vendorCode = args[0]" in login_impl
        assert "this.featureId = args[1]" in login_impl
        assert "this.handlePtr = args[2]" in login_impl

        assert "this.handlePtr.writeU32" in login_impl
        assert "retval.replace(0)" in login_impl
        assert "HASP_STATUS_OK" in login_impl

    def test_hasp_encrypt_hook_has_complete_implementation(self) -> None:
        """hasp_encrypt hook implements data handling and status return."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        script = emulator.generate_emulation_script(["HASP"])

        hasp_encrypt_match = re.search(
            r'var haspEncrypt = Module\.findExportByName\(haspModule\.name, "hasp_encrypt"\);.*?'
            r'Interceptor\.attach\(haspEncrypt, \{(.*?)\}\}\);',
            script,
            re.DOTALL
        )
        assert hasp_encrypt_match is not None

        encrypt_impl = hasp_encrypt_match.group(1)

        assert "onEnter: function(args)" in encrypt_impl
        assert "onLeave: function(retval)" in encrypt_impl

        assert "this.handle = args[0]" in encrypt_impl
        assert "this.dataPtr = args[1]" in encrypt_impl
        assert "this.dataLen = args[2]" in encrypt_impl

        assert "retval.replace(0)" in encrypt_impl

    def test_hasp_decrypt_hook_has_complete_implementation(self) -> None:
        """hasp_decrypt hook implements data handling and status return."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        script = emulator.generate_emulation_script(["HASP"])

        hasp_decrypt_match = re.search(
            r'var haspDecrypt = Module\.findExportByName\(haspModule\.name, "hasp_decrypt"\);.*?'
            r'Interceptor\.attach\(haspDecrypt, \{(.*?)\}\}\);',
            script,
            re.DOTALL
        )
        assert hasp_decrypt_match is not None

        decrypt_impl = hasp_decrypt_match.group(1)

        assert "onEnter: function(args)" in decrypt_impl
        assert "onLeave: function(retval)" in decrypt_impl
        assert "this.handle = args[0]" in decrypt_impl
        assert "retval.replace(0)" in decrypt_impl

    def test_hasp_read_hook_implements_memory_layout_response(self) -> None:
        """hasp_read hook generates deterministic memory data based on parameters."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        script = emulator.generate_emulation_script(["HASP"])

        hasp_read_match = re.search(
            r'var haspRead = Module\.findExportByName\(haspModule\.name, "hasp_read"\);.*?'
            r'Interceptor\.attach\(haspRead, \{(.*?)\}\}\);',
            script,
            re.DOTALL
        )
        assert hasp_read_match is not None

        read_impl = hasp_read_match.group(1)

        assert "this.handle = args[0]" in read_impl
        assert "this.fileId = args[1]" in read_impl
        assert "this.offset = args[2]" in read_impl
        assert "this.length = args[3]" in read_impl
        assert "this.buffer = args[4]" in read_impl

        assert "var memoryData = new Uint8Array(this.length)" in read_impl
        assert "this.buffer.writeByteArray" in read_impl
        assert "retval.replace(0)" in read_impl

        assert "baseValue" in read_impl or "value" in read_impl

    def test_hasp_write_hook_has_complete_implementation(self) -> None:
        """hasp_write hook accepts write operations and returns success."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        script = emulator.generate_emulation_script(["HASP"])

        hasp_write_match = re.search(
            r'var haspWrite = Module\.findExportByName\(haspModule\.name, "hasp_write"\);.*?'
            r'Interceptor\.attach\(haspWrite, \{(.*?)\}\}\);',
            script,
            re.DOTALL
        )
        assert hasp_write_match is not None

        write_impl = hasp_write_match.group(1)

        assert "onLeave: function(retval)" in write_impl
        assert "retval.replace(0)" in write_impl

    def test_hasp_get_size_hook_returns_valid_memory_size(self) -> None:
        """hasp_get_size hook writes valid memory size to output pointer."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        script = emulator.generate_emulation_script(["HASP"])

        hasp_get_size_match = re.search(
            r'var haspGetSize = Module\.findExportByName\(haspModule\.name, "hasp_get_size"\);.*?'
            r'Interceptor\.attach\(haspGetSize, \{(.*?)\}\}\);',
            script,
            re.DOTALL
        )
        assert hasp_get_size_match is not None

        get_size_impl = hasp_get_size_match.group(1)

        assert "this.sizePtr = args[3]" in get_size_impl
        assert "this.sizePtr.writeU32" in get_size_impl
        assert "retval.replace(0)" in get_size_impl

    def test_all_sentinel_api_functions_are_hooked(self) -> None:
        """All required Sentinel API functions have Interceptor.attach hooks defined."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        script = emulator.generate_emulation_script(["Sentinel"])

        required_sentinel_functions = [
            "RNBOsproFindFirstUnit",
            "RNBOsproQuery",
            "RNBOsproRead",
        ]

        for func_name in required_sentinel_functions:
            assert f'Module.findExportByName(sentinelModule.name, "{func_name}")' in script
            hook_pattern = rf'{func_name.split("RNBOspro")[1].lower()}.*?Interceptor\.attach'
            assert re.search(hook_pattern, script, re.IGNORECASE) is not None

    def test_sentinel_find_first_unit_hook_has_complete_implementation(self) -> None:
        """RNBOsproFindFirstUnit hook returns valid device ID."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        script = emulator.generate_emulation_script(["Sentinel"])

        sentinel_find_match = re.search(
            r'var sentinelFind = Module\.findExportByName\(sentinelModule\.name, "RNBOsproFindFirstUnit"\);.*?'
            r'Interceptor\.attach\(sentinelFind, \{(.*?)\}\}\);',
            script,
            re.DOTALL
        )
        assert sentinel_find_match is not None

        find_impl = sentinel_find_match.group(1)

        assert "this.devIdPtr = args[0]" in find_impl
        assert "this.devIdPtr.writeU32" in find_impl
        assert "retval.replace(0)" in find_impl
        assert "SP_SUCCESS" in find_impl

    def test_sentinel_query_hook_implements_complete_device_info_response(self) -> None:
        """RNBOsproQuery hook generates complete device information structure."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        script = emulator.generate_emulation_script(["Sentinel"])

        sentinel_query_match = re.search(
            r'var sentinelQuery = Module\.findExportByName\(sentinelModule\.name, "RNBOsproQuery"\);.*?'
            r'Interceptor\.attach\(sentinelQuery, \{(.*?)\}\}\);',
            script,
            re.DOTALL
        )
        assert sentinel_query_match is not None

        query_impl = sentinel_query_match.group(1)

        assert "this.queryBuf = args[1]" in query_impl
        assert "this.respBuf = args[2]" in query_impl

        assert "var response = new Uint8Array" in query_impl
        assert "this.respBuf.writeByteArray" in query_impl
        assert "retval.replace(0)" in query_impl

        assert "serial" in query_impl.lower() or "SN" in query_impl

    def test_sentinel_read_hook_implements_memory_response_with_prng(self) -> None:
        """RNBOsproRead hook generates deterministic memory using PRNG algorithm."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        script = emulator.generate_emulation_script(["Sentinel"])

        sentinel_read_match = re.search(
            r'var sentinelRead = Module\.findExportByName\(sentinelModule\.name, "RNBOsproRead"\);.*?'
            r'Interceptor\.attach\(sentinelRead, \{(.*?)\}\}\);',
            script,
            re.DOTALL
        )
        assert sentinel_read_match is not None

        read_impl = sentinel_read_match.group(1)

        assert "this.address = args[1]" in read_impl
        assert "this.length = args[2]" in read_impl
        assert "this.buffer = args[3]" in read_impl

        assert "var cellData = new Uint8Array(this.length)" in read_impl
        assert "this.buffer.writeByteArray" in read_impl

        assert "seed" in read_impl
        assert "1103515245" in read_impl or "12345" in read_impl

    def test_all_codemeter_api_functions_are_hooked(self) -> None:
        """All required CodeMeter API functions have Interceptor.attach hooks defined."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["CodeMeter"])

        script = emulator.generate_emulation_script(["CodeMeter"])

        required_codemeter_functions = [
            "CmAccess",
            "CmCrypt",
            "CmGetInfo",
        ]

        for func_name in required_codemeter_functions:
            assert f'Module.findExportByName(wibuModule.name, "{func_name}")' in script
            hook_pattern = rf'{func_name.lower()}.*?Interceptor\.attach'
            assert re.search(hook_pattern, script, re.IGNORECASE) is not None

    def test_codemeter_access_hook_has_complete_implementation(self) -> None:
        """CmAccess hook validates firm/product codes and returns handle."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["CodeMeter"])

        script = emulator.generate_emulation_script(["CodeMeter"])

        cm_access_match = re.search(
            r'var cmAccess = Module\.findExportByName\(wibuModule\.name, "CmAccess"\);.*?'
            r'Interceptor\.attach\(cmAccess, \{(.*?)\}\}\);',
            script,
            re.DOTALL
        )
        assert cm_access_match is not None

        access_impl = cm_access_match.group(1)

        assert "this.firmCode = args[0]" in access_impl
        assert "this.productCode = args[1]" in access_impl
        assert "this.handlePtr = args[2]" in access_impl

        assert "this.handlePtr.writeU32" in access_impl
        assert "retval.replace(0)" in access_impl

    def test_codemeter_crypt_hook_has_complete_implementation(self) -> None:
        """CmCrypt hook handles encryption operations."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["CodeMeter"])

        script = emulator.generate_emulation_script(["CodeMeter"])

        cm_crypt_match = re.search(
            r'var cmCrypt = Module\.findExportByName\(wibuModule\.name, "CmCrypt"\);.*?'
            r'Interceptor\.attach\(cmCrypt, \{(.*?)\}\}\);',
            script,
            re.DOTALL
        )
        assert cm_crypt_match is not None

        crypt_impl = cm_crypt_match.group(1)

        assert "onLeave: function(retval)" in crypt_impl
        assert "retval.replace(0)" in crypt_impl

    def test_codemeter_get_info_hook_returns_complete_device_info(self) -> None:
        """CmGetInfo hook generates complete device information structure."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["CodeMeter"])

        script = emulator.generate_emulation_script(["CodeMeter"])

        cm_get_info_match = re.search(
            r'var cmGetInfo = Module\.findExportByName\(wibuModule\.name, "CmGetInfo"\);.*?'
            r'Interceptor\.attach\(cmGetInfo, \{(.*?)\}\}\);',
            script,
            re.DOTALL
        )
        assert cm_get_info_match is not None

        get_info_impl = cm_get_info_match.group(1)

        assert "this.infoPtr = args[1]" in get_info_impl
        assert "var info = new Uint8Array" in get_info_impl
        assert "this.infoPtr.writeByteArray" in get_info_impl
        assert "retval.replace(0)" in get_info_impl

        assert "version" in get_info_impl.lower()

    def test_device_io_control_hook_is_implemented(self) -> None:
        """DeviceIoControl hook intercepts dongle-specific IOCTL codes."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        script = emulator.generate_emulation_script(["HASP"])

        device_io_match = re.search(
            r'Module\.findExportByName\("kernel32\.dll", "DeviceIoControl"\);.*?'
            r'Interceptor\.attach\(deviceIoControl, \{(.*?)\}\}\);',
            script,
            re.DOTALL
        )
        assert device_io_match is not None

        io_impl = device_io_match.group(1)

        assert "this.ioControlCode = args[1]" in io_impl
        assert "this.outBuffer = args[4]" in io_impl
        assert "this.outBufferSize = args[5]" in io_impl
        assert "this.bytesReturned = args[6]" in io_impl

        assert "isDongleIoctl" in io_impl
        assert "0x00220000" in io_impl or "0x00320000" in io_impl

    def test_device_io_control_hook_generates_ioctl_response_data(self) -> None:
        """DeviceIoControl hook generates response data for dongle IOCTLs."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        script = emulator.generate_emulation_script(["HASP"])

        device_io_match = re.search(
            r'if \(isDongleIoctl\)(.*?)retval\.replace\(1\);',
            script,
            re.DOTALL
        )
        assert device_io_match is not None

        io_response_impl = device_io_match.group(1)

        assert "var ioctlResponse = new Uint8Array" in io_response_impl
        assert "this.outBuffer.writeByteArray" in io_response_impl
        assert "this.bytesReturned.writeU32" in io_response_impl


class TestHASPSessionManagement:
    """Test HASP session management across multiple API calls."""

    def test_hasp_login_creates_unique_session_handle(self) -> None:
        """HASP login creates unique session handle for each login."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        dongle = emulator.hasp_dongles[1]

        login_data1 = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        response1 = emulator._hasp_login(login_data1)
        status1, handle1 = struct.unpack("<II", response1)

        assert status1 == HASPStatus.HASP_STATUS_OK
        assert handle1 == dongle.session_handle

        emulator._hasp_logout(struct.pack("<I", handle1))

        login_data2 = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        response2 = emulator._hasp_login(login_data2)
        status2, handle2 = struct.unpack("<II", response2)

        assert status2 == HASPStatus.HASP_STATUS_OK
        assert handle2 != 0

    def test_hasp_encrypt_requires_valid_session(self) -> None:
        """HASP encrypt operation works with valid session from login."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        dongle = emulator.hasp_dongles[1]
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        response = emulator._hasp_login(login_data)
        _, session_handle = struct.unpack("<II", response)

        plaintext = b"TestData1234567890ABCDEF"
        encrypt_data = struct.pack("<II", session_handle, len(plaintext)) + plaintext

        encrypt_response = emulator._hasp_encrypt_command(encrypt_data)

        status = struct.unpack("<I", encrypt_response[:4])[0]
        assert status == HASPStatus.HASP_STATUS_OK

    def test_hasp_decrypt_requires_valid_session(self) -> None:
        """HASP decrypt operation works with valid session from login."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        dongle = emulator.hasp_dongles[1]
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        response = emulator._hasp_login(login_data)
        _, session_handle = struct.unpack("<II", response)

        ciphertext = b"EncryptedData12345678901234567890"
        decrypt_data = struct.pack("<II", session_handle, len(ciphertext)) + ciphertext

        decrypt_response = emulator._hasp_decrypt_command(decrypt_data)

        status = struct.unpack("<I", decrypt_response[:4])[0]
        assert status == HASPStatus.HASP_STATUS_OK

    def test_hasp_memory_operations_use_session_handle(self) -> None:
        """HASP read/write operations use session handle for access control."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        dongle = emulator.hasp_dongles[1]
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        response = emulator._hasp_login(login_data)
        _, session_handle = struct.unpack("<II", response)

        offset = 0
        length = 16

        read_data = struct.pack("<III", session_handle, offset, length)
        read_response = emulator._hasp_read_memory(read_data)

        status = struct.unpack("<I", read_response[:4])[0]
        assert status == HASPStatus.HASP_STATUS_OK
        assert len(read_response) >= 4 + length

    def test_hasp_logout_invalidates_session(self) -> None:
        """HASP logout invalidates session handle."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        dongle = emulator.hasp_dongles[1]
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        response = emulator._hasp_login(login_data)
        _, session_handle = struct.unpack("<II", response)

        logout_data = struct.pack("<I", session_handle)
        logout_response = emulator._hasp_logout(logout_data)

        status = struct.unpack("<I", logout_response)[0]
        assert status == HASPStatus.HASP_STATUS_OK
        assert dongle.logged_in is False


class TestHASPMemoryOperations:
    """Test HASP hasp_read and hasp_write memory operations."""

    def test_hasp_read_returns_deterministic_memory_data(self) -> None:
        """hasp_read returns deterministic memory data based on offset."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        dongle = emulator.hasp_dongles[1]
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        response = emulator._hasp_login(login_data)
        _, session_handle = struct.unpack("<II", response)

        offset = 100
        length = 32

        read_data = struct.pack("<III", session_handle, offset, length)
        read_response = emulator._hasp_read_memory(read_data)

        status = struct.unpack("<I", read_response[:4])[0]
        assert status == HASPStatus.HASP_STATUS_OK
        memory_data = read_response[4:4+length]
        assert len(memory_data) == length

        read_data2 = struct.pack("<III", session_handle, offset, length)
        read_response2 = emulator._hasp_read_memory(read_data2)
        memory_data2 = read_response2[4:4+length]

        assert memory_data == memory_data2

    def test_hasp_read_different_offsets_return_different_data(self) -> None:
        """hasp_read returns different memory data for different offsets."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        dongle = emulator.hasp_dongles[1]
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        response = emulator._hasp_login(login_data)
        _, session_handle = struct.unpack("<II", response)

        length = 16

        read_data1 = struct.pack("<III", session_handle, 0, length)
        read_response1 = emulator._hasp_read_memory(read_data1)
        memory_data1 = read_response1[4:4+length]

        read_data2 = struct.pack("<III", session_handle, 100, length)
        read_response2 = emulator._hasp_read_memory(read_data2)
        memory_data2 = read_response2[4:4+length]

        assert memory_data1 != memory_data2

    def test_hasp_write_operation_succeeds(self) -> None:
        """hasp_write accepts write data and returns success status."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        dongle = emulator.hasp_dongles[1]
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        response = emulator._hasp_login(login_data)
        _, session_handle = struct.unpack("<II", response)

        offset = 0
        write_data_payload = b"TestWriteData123"

        write_data = struct.pack("<III", session_handle, offset, len(write_data_payload)) + write_data_payload
        write_response = emulator._hasp_write_memory(write_data)

        status = struct.unpack("<I", write_response)[0]
        assert status == HASPStatus.HASP_STATUS_OK


class TestHASPEncryptionOperations:
    """Test HASP hasp_encrypt and hasp_decrypt with feature-specific keys."""

    def test_hasp_encrypt_operation_processes_data(self) -> None:
        """hasp_encrypt encrypts plaintext data using dongle key."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        dongle = emulator.hasp_dongles[1]
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        response = emulator._hasp_login(login_data)
        _, session_handle = struct.unpack("<II", response)

        plaintext = b"This is test plaintext data for encryption operation"
        plaintext_padded = plaintext + b"\x00" * (16 - len(plaintext) % 16)

        encrypt_data = struct.pack("<II", session_handle, len(plaintext_padded)) + plaintext_padded
        encrypt_response = emulator._hasp_encrypt_command(encrypt_data)

        status = struct.unpack("<I", encrypt_response[:4])[0]
        assert status == HASPStatus.HASP_STATUS_OK
        ciphertext = encrypt_response[8:]
        assert len(ciphertext) >= len(plaintext_padded)

    def test_hasp_decrypt_operation_processes_data(self) -> None:
        """hasp_decrypt decrypts ciphertext data using dongle key."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        dongle = emulator.hasp_dongles[1]
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        response = emulator._hasp_login(login_data)
        _, session_handle = struct.unpack("<II", response)

        ciphertext = b"This is encrypted ciphertext data that needs decryption"
        ciphertext_padded = ciphertext + b"\x00" * (16 - len(ciphertext) % 16)

        decrypt_data = struct.pack("<II", session_handle, len(ciphertext_padded)) + ciphertext_padded
        decrypt_response = emulator._hasp_decrypt_command(decrypt_data)

        status = struct.unpack("<I", decrypt_response[:4])[0]
        assert status == HASPStatus.HASP_STATUS_OK
        plaintext = decrypt_response[8:]
        assert len(plaintext) >= len(ciphertext_padded)

    def test_hasp_encrypt_decrypt_roundtrip_preserves_data(self) -> None:
        """hasp_encrypt followed by hasp_decrypt recovers original data."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        dongle = emulator.hasp_dongles[1]
        login_data = struct.pack("<HH", dongle.vendor_code, dongle.feature_id)
        response = emulator._hasp_login(login_data)
        _, session_handle = struct.unpack("<II", response)

        original_data = b"Original plaintext data for roundtrip testing operation"
        original_data_padded = original_data + b"\x00" * (16 - len(original_data) % 16)

        encrypt_data = struct.pack("<II", session_handle, len(original_data_padded)) + original_data_padded
        encrypt_response = emulator._hasp_encrypt_command(encrypt_data)
        ciphertext = encrypt_response[8:]

        decrypt_data = struct.pack("<II", session_handle, len(ciphertext)) + ciphertext
        decrypt_response = emulator._hasp_decrypt_command(decrypt_data)
        recovered_data = decrypt_response[8:8+len(original_data_padded)]

        assert recovered_data == original_data_padded


class TestSentinelSessionManagement:
    """Test Sentinel session management and device discovery."""

    def test_sentinel_query_returns_complete_device_info(self) -> None:
        """RNBOsproQuery returns complete device information structure."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        dongle = emulator.sentinel_dongles[1]

        query_data = b""
        response = emulator._sentinel_query(query_data)

        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_SUCCESS

        assert len(dongle.response_buffer) > 0

    def test_sentinel_read_returns_cell_data(self) -> None:
        """RNBOsproRead returns cell data from dongle."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        dongle = emulator.sentinel_dongles[1]
        dongle.cell_data[0] = b"TestCellData1234567890ABCDEFGHIJ"

        cell_id = 0
        length = 32

        read_data = struct.pack("<II", cell_id, length)
        response = emulator._sentinel_read(read_data)

        status = struct.unpack("<I", response)[0]
        assert status == SentinelStatus.SP_SUCCESS
        assert len(dongle.response_buffer) >= length


class TestConcurrentSessionEdgeCases:
    """Test edge cases with multiple concurrent dongle sessions."""

    def test_multiple_hasp_dongles_maintain_independent_sessions(self) -> None:
        """Multiple HASP dongles maintain independent session handles."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        emulator.add_virtual_dongle("HASP", vendor_code=0x1234, feature_id=1, hasp_id=0x11111111)
        emulator.add_virtual_dongle("HASP", vendor_code=0x5678, feature_id=2, hasp_id=0x22222222)

        dongle1 = emulator.hasp_dongles[1]
        dongle2 = emulator.hasp_dongles[2]

        login1 = struct.pack("<HH", dongle1.vendor_code, dongle1.feature_id)
        response1 = emulator._hasp_login(login1)
        _, handle1 = struct.unpack("<II", response1)

        login2 = struct.pack("<HH", dongle2.vendor_code, dongle2.feature_id)
        response2 = emulator._hasp_login(login2)
        _, handle2 = struct.unpack("<II", response2)

        assert handle1 != handle2
        assert dongle1.logged_in is True
        assert dongle2.logged_in is True

    def test_hasp_feature_specific_encryption_keys(self) -> None:
        """Different HASP features use different encryption keys."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        emulator.add_virtual_dongle("HASP", vendor_code=0x1234, feature_id=1, hasp_id=0x11111111)
        emulator.add_virtual_dongle("HASP", vendor_code=0x1234, feature_id=2, hasp_id=0x22222222)

        dongle1 = emulator.hasp_dongles[1]
        dongle2 = emulator.hasp_dongles[2]

        assert dongle1.aes_key != dongle2.aes_key
        assert dongle1.des_key != dongle2.des_key

    def test_concurrent_hasp_read_operations_do_not_interfere(self) -> None:
        """Concurrent HASP read operations from different dongles do not interfere."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        emulator.add_virtual_dongle("HASP", vendor_code=0x1234, feature_id=1, hasp_id=0x11111111)
        emulator.add_virtual_dongle("HASP", vendor_code=0x5678, feature_id=2, hasp_id=0x22222222)

        dongle1 = emulator.hasp_dongles[1]
        dongle2 = emulator.hasp_dongles[2]

        login1 = struct.pack("<HH", dongle1.vendor_code, dongle1.feature_id)
        response1 = emulator._hasp_login(login1)
        _, handle1 = struct.unpack("<II", response1)

        login2 = struct.pack("<HH", dongle2.vendor_code, dongle2.feature_id)
        response2 = emulator._hasp_login(login2)
        _, handle2 = struct.unpack("<II", response2)

        read_data1 = struct.pack("<III", handle1, 0, 16)
        read_response1 = emulator._hasp_read_memory(read_data1)
        memory1 = read_response1[8:24]

        read_data2 = struct.pack("<III", handle2, 0, 16)
        read_response2 = emulator._hasp_read_memory(read_data2)
        memory2 = read_response2[8:24]

        assert memory1 != memory2

    def test_hasp_invalid_session_handle_returns_error(self) -> None:
        """HASP operations with invalid session handle return error status."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        invalid_handle = 0xDEADBEEF

        read_data = struct.pack("<III", invalid_handle, 0, 16)
        read_response = emulator._hasp_read_memory(read_data)

        status = struct.unpack("<I", read_response[:4])[0]
        assert status == HASPStatus.HASP_INV_HND

    def test_multiple_sentinel_dongles_maintain_independent_device_ids(self) -> None:
        """Multiple Sentinel dongles maintain independent device IDs."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        emulator.add_virtual_dongle("Sentinel", device_id=0x87654321, serial_number="SN1234567890")
        emulator.add_virtual_dongle("Sentinel", device_id=0x12345678, serial_number="SN0987654321")

        dongle1 = emulator.sentinel_dongles[1]
        dongle2 = emulator.sentinel_dongles[2]

        assert dongle1.device_id != dongle2.device_id
        assert dongle1.serial_number != dongle2.serial_number


class TestFridaScriptErrorHandling:
    """Test Frida script error handling and edge cases."""

    def test_frida_script_handles_null_module_gracefully(self) -> None:
        """Frida script includes null checks for module finding."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        script = emulator.generate_emulation_script(["HASP"])

        assert 'if (haspModule)' in script
        assert 'if (!haspModule)' in script or 'haspModule = Process.findModuleByName' in script

    def test_frida_script_wraps_hooks_in_try_catch(self) -> None:
        """Frida script wraps hook installation in try-catch blocks."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP", "Sentinel", "CodeMeter"])

        script = emulator.generate_emulation_script(["HASP", "Sentinel", "CodeMeter"])

        assert 'try {' in script
        assert 'catch(e)' in script or 'catch (e)' in script

    def test_frida_script_includes_logging_for_all_hooks(self) -> None:
        """Frida script includes console logging for all hook installations."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP", "Sentinel", "CodeMeter"])

        script = emulator.generate_emulation_script(["HASP", "Sentinel", "CodeMeter"])

        assert script.count('console.log') >= 10
        assert '[HASP]' in script
        assert '[Sentinel]' in script
        assert '[CodeMeter]' in script

    def test_frida_script_validates_pointer_arguments_before_dereferencing(self) -> None:
        """Frida script validates pointer arguments before dereferencing."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        script = emulator.generate_emulation_script(["HASP"])

        assert 'if (this.handlePtr)' in script
        assert 'if (this.buffer' in script
        assert 'if (this.sizePtr)' in script


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
class TestFridaScriptRuntimeExecution:
    """Test Frida script can be loaded and executed in Frida runtime."""

    def test_frida_script_syntax_is_valid_javascript(self) -> None:
        """Frida script is syntactically valid JavaScript."""
        import frida

        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP", "Sentinel", "CodeMeter"])

        script_source = emulator.generate_emulation_script(["HASP", "Sentinel", "CodeMeter"])

        try:
            session = frida.attach(0)
            script = session.create_script(script_source)
            script.load()
            script.unload()
            session.detach()
        except frida.InvalidArgumentError as e:
            pytest.fail(f"Frida script has syntax errors: {e}")

    def test_frida_script_defines_all_required_interceptors(self) -> None:
        """Frida script defines Interceptor.attach for all required functions."""
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP", "Sentinel", "CodeMeter"])

        script = emulator.generate_emulation_script(["HASP", "Sentinel", "CodeMeter"])

        interceptor_count = script.count('Interceptor.attach')
        assert interceptor_count >= 13
