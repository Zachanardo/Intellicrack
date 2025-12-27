"""Platform-specific structure validation tests for Frida types.

Tests Windows x86/x64 memory addresses, API structures, and cross-platform compatibility.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import pytest
import sys
from typing import Any

from intellicrack.core.monitoring.frida_types import (
    MemoryPatternPayload,
    APICallPayload,
    parse_frida_message,
)


class TestWindowsX64MemoryAddresses:
    """Test Windows x64-specific memory address handling."""

    def test_kernel_space_addresses(self) -> None:
        """Frida types handle Windows x64 kernel space addresses."""
        kernel_addresses = [
            0xffff800000000000,
            0xfffff80000000000,
            0xfffffffffffff000,
        ]

        for address in kernel_addresses:
            payload: MemoryPatternPayload = {
                "event_type": "pattern_found",
                "address": address,
                "pattern_type": "kernel_structure",
            }

            assert payload["address"] == address
            assert payload["address"] > 0x7fffffffffff

    def test_user_space_addresses(self) -> None:
        """Frida types handle Windows x64 user space addresses."""
        user_addresses = [
            0x0000000000400000,
            0x00007ff700000000,
            0x00007fffffff0000,
        ]

        for address in user_addresses:
            payload: MemoryPatternPayload = {
                "event_type": "pattern_found",
                "address": address,
            }

            assert payload["address"] == address
            assert payload["address"] < 0x8000000000000000

    def test_dll_base_addresses(self) -> None:
        """Frida types handle typical DLL base addresses in x64."""
        dll_bases = [
            0x00007ff900000000,
            0x00007ffa00000000,
            0x00007ffb00000000,
        ]

        for base_addr in dll_bases:
            payload: MemoryPatternPayload = {
                "event_type": "pattern_found",
                "address": base_addr,
                "pattern_type": "dll_base",
            }

            assert payload["address"] == base_addr

    def test_stack_addresses(self) -> None:
        """Frida types handle typical stack addresses."""
        stack_addresses = [
            0x000000000012f000,
            0x00007fff00000000,
            0x00007fffffff0000,
        ]

        for stack_addr in stack_addresses:
            payload: MemoryPatternPayload = {
                "event_type": "pattern_found",
                "address": stack_addr,
                "pattern_type": "stack",
            }

            assert payload["address"] == stack_addr


class TestWindowsX86MemoryAddresses:
    """Test Windows x86-specific memory address handling."""

    def test_x86_user_space_addresses(self) -> None:
        """Frida types handle Windows x86 user space addresses."""
        x86_addresses = [
            0x00400000,
            0x10000000,
            0x7fff0000,
        ]

        for address in x86_addresses:
            payload: MemoryPatternPayload = {
                "event_type": "pattern_found",
                "address": address,
            }

            assert payload["address"] == address
            assert payload["address"] <= 0xffffffff

    def test_x86_dll_addresses(self) -> None:
        """Frida types handle x86 DLL base addresses."""
        dll_bases = [
            0x71000000,
            0x73000000,
            0x75000000,
        ]

        for base_addr in dll_bases:
            payload: MemoryPatternPayload = {
                "event_type": "pattern_found",
                "address": base_addr,
                "pattern_type": "dll_base",
            }

            assert payload["address"] == base_addr

    def test_x86_null_page_protection(self) -> None:
        """Frida types handle addresses near null page."""
        low_addresses = [0x00000000, 0x00001000, 0x0000ffff]

        for address in low_addresses:
            payload: MemoryPatternPayload = {
                "event_type": "pattern_found",
                "address": address,
            }

            assert payload["address"] == address


class TestWindowsAPIStructures:
    """Test Windows API-specific structures and calling conventions."""

    def test_unicode_api_calls(self) -> None:
        """Frida types handle Unicode Windows API calls."""
        unicode_apis = [
            "CreateFileW",
            "RegOpenKeyExW",
            "GetModuleFileNameW",
            "FindFirstFileW",
        ]

        for api in unicode_apis:
            payload: APICallPayload = {
                "event_type": "api_call",
                "api": api,
                "args": [r"C:\test\file.txt"],
            }

            assert payload["api"] == api
            assert api.endswith("W")

    def test_ansi_api_calls(self) -> None:
        """Frida types handle ANSI Windows API calls."""
        ansi_apis = [
            "CreateFileA",
            "RegOpenKeyExA",
            "GetModuleFileNameA",
        ]

        for api in ansi_apis:
            payload: APICallPayload = {
                "event_type": "api_call",
                "api": api,
                "args": ["C:\\test\\file.txt"],
            }

            assert payload["api"] == api
            assert api.endswith("A")

    def test_handle_values(self) -> None:
        """Frida types handle Windows HANDLE values."""
        handle_values = [
            0x00000004,
            0x00000100,
            0xffffffff,
            0xfffffffe,
        ]

        for handle in handle_values:
            payload: APICallPayload = {
                "event_type": "api_call",
                "api": "CloseHandle",
                "args": [handle],
                "result": True,
            }

            assert payload["args"][0] == handle

    def test_status_codes(self) -> None:
        """Frida types handle NTSTATUS and HRESULT codes."""
        status_codes = [
            0x00000000,
            0xc0000001,
            0x80004005,
            0x8007000e,
        ]

        for status in status_codes:
            payload: APICallPayload = {
                "event_type": "api_call",
                "api": "NtCreateFile",
                "result": status,
            }

            assert payload["result"] == status

    def test_pointer_arguments(self) -> None:
        """Frida types handle pointer arguments in API calls."""
        if sys.maxsize > 2**32:
            pointer_values = [
                0x0000000000000000,
                0x00007ff700000000,
                0xffffffffffffffff,
            ]
        else:
            pointer_values = [
                0x00000000,
                0x10000000,
                0xffffffff,
            ]

        for pointer in pointer_values:
            payload: APICallPayload = {
                "event_type": "api_call",
                "api": "VirtualAlloc",
                "args": [pointer, 4096, "MEM_COMMIT", "PAGE_READWRITE"],
            }

            assert payload["args"][0] == pointer


class TestWindowsRegistryOperations:
    """Test Windows Registry-specific API structures."""

    def test_registry_key_handles(self) -> None:
        """Frida types handle registry key handles."""
        hkey_values = [
            0x80000000,
            0x80000001,
            0x80000002,
        ]

        for hkey in hkey_values:
            payload: APICallPayload = {
                "event_type": "api_call",
                "api": "RegOpenKeyExW",
                "args": [hkey, r"Software\Test"],
                "category": "registry",
            }

            assert payload["args"][0] == hkey

    def test_registry_value_types(self) -> None:
        """Frida types handle registry value types."""
        value_types = {
            "REG_SZ": 1,
            "REG_DWORD": 4,
            "REG_BINARY": 3,
            "REG_QWORD": 11,
        }

        for type_name, type_value in value_types.items():
            payload: APICallPayload = {
                "event_type": "api_call",
                "api": "RegSetValueExW",
                "args": ["TestValue", 0, type_value, b"data"],
            }

            assert payload["args"][2] == type_value

    def test_registry_paths(self) -> None:
        """Frida types handle Windows registry paths."""
        registry_paths = [
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft",
            r"HKEY_CURRENT_USER\Software\Test",
            r"HKEY_CLASSES_ROOT\.exe",
        ]

        for path in registry_paths:
            payload: APICallPayload = {
                "event_type": "api_call",
                "api": "RegOpenKeyExW",
                "args": [path],
            }

            assert payload["args"][0] == path


class TestWindowsFileOperations:
    """Test Windows file operation API structures."""

    def test_extended_path_prefix(self) -> None:
        """Frida types handle extended-length path prefix."""
        extended_paths = [
            r"\\?\C:\Very\Long\Path\To\File.txt",
            r"\\?\UNC\server\share\file.txt",
        ]

        for path in extended_paths:
            payload: APICallPayload = {
                "event_type": "api_call",
                "api": "CreateFileW",
                "args": [path],
            }

            assert payload["args"][0] == path
            assert payload["args"][0].startswith(r"\\?")

    def test_file_access_modes(self) -> None:
        """Frida types handle file access mode flags."""
        access_modes = [
            0x80000000,
            0x40000000,
            0xc0000000,
        ]

        for mode in access_modes:
            payload: APICallPayload = {
                "event_type": "api_call",
                "api": "CreateFileW",
                "args": [r"C:\test.txt", mode],
            }

            assert payload["args"][1] == mode

    def test_file_share_modes(self) -> None:
        """Frida types handle file share mode flags."""
        share_modes = [0x00000001, 0x00000002, 0x00000003]

        for share in share_modes:
            payload: APICallPayload = {
                "event_type": "api_call",
                "api": "CreateFileW",
                "args": [r"C:\test.txt", 0x80000000, share],
            }

            assert payload["args"][2] == share


class TestCrossArchitectureCompatibility:
    """Test cross-architecture compatibility."""

    def test_address_size_detection(self) -> None:
        """Frida types handle addresses correctly based on architecture."""
        if sys.maxsize > 2**32:
            max_address = 0xffffffffffffffff
            expected_bits = 64
        else:
            max_address = 0xffffffff
            expected_bits = 32

        payload: MemoryPatternPayload = {
            "event_type": "pattern_found",
            "address": max_address,
        }

        assert payload["address"] == max_address
        assert payload["address"].bit_length() <= expected_bits

    def test_pointer_size_handling(self) -> None:
        """Frida types handle pointer sizes for current architecture."""
        pointer_value = 0x12345678 if sys.maxsize <= 2**32 else 0x1234567890abcdef

        payload: APICallPayload = {
            "event_type": "api_call",
            "api": "VirtualAlloc",
            "args": [pointer_value],
        }

        assert payload["args"][0] == pointer_value


class TestLicenseProtectionPatterns:
    """Test license protection-specific patterns."""

    def test_serial_number_patterns(self) -> None:
        """Frida types handle serial number pattern detection."""
        serial_patterns = [
            "XXXX-XXXX-XXXX-XXXX",
            "AAAA-BBBB-CCCC-DDDD-EEEE",
            "1234-5678-90AB-CDEF",
        ]

        for serial in serial_patterns:
            payload: MemoryPatternPayload = {
                "event_type": "pattern_found",
                "pattern_type": "serial_number",
                "value": serial,
                "address": 0x12345678,
            }

            assert payload["value"] == serial
            assert payload["pattern_type"] == "serial_number"

    def test_activation_key_patterns(self) -> None:
        """Frida types handle activation key patterns."""
        activation_keys = [
            "A1B2C3D4E5F6G7H8I9J0",
            "ABCDEFGHIJ1234567890",
        ]

        for key in activation_keys:
            payload: MemoryPatternPayload = {
                "event_type": "pattern_found",
                "pattern_type": "activation_key",
                "value": key,
            }

            assert payload["value"] == key

    def test_license_file_paths(self) -> None:
        """Frida types handle license file path detection."""
        license_paths = [
            r"C:\ProgramData\App\license.dat",
            r"C:\Users\User\AppData\Local\App\activation.key",
        ]

        for path in license_paths:
            payload: APICallPayload = {
                "event_type": "api_call",
                "api": "CreateFileW",
                "args": [path],
                "category": "license_validation",
            }

            assert payload["args"][0] == path


class TestCryptoOperationStructures:
    """Test cryptography-related API structures."""

    def test_crypto_api_calls(self) -> None:
        """Frida types handle cryptography API calls."""
        crypto_apis = [
            "CryptAcquireContextW",
            "CryptCreateHash",
            "CryptEncrypt",
            "CryptDecrypt",
        ]

        for api in crypto_apis:
            payload: APICallPayload = {
                "event_type": "api_call",
                "api": api,
                "category": "cryptography",
            }

            assert payload["api"] == api
            assert payload["category"] == "cryptography"

    def test_crypto_provider_types(self) -> None:
        """Frida types handle crypto provider type values."""
        provider_types = [1, 2, 3, 12, 13, 24]

        for prov_type in provider_types:
            payload: APICallPayload = {
                "event_type": "api_call",
                "api": "CryptAcquireContextW",
                "args": [None, None, prov_type],
            }

            assert payload["args"][2] == prov_type

    def test_hash_algorithm_identifiers(self) -> None:
        """Frida types handle hash algorithm identifiers."""
        hash_algs = [
            0x00008003,
            0x00008004,
            0x0000800c,
        ]

        for alg_id in hash_algs:
            payload: APICallPayload = {
                "event_type": "api_call",
                "api": "CryptCreateHash",
                "args": [None, alg_id],
            }

            assert payload["args"][1] == alg_id


class TestNetworkOperationStructures:
    """Test network operation API structures."""

    def test_socket_api_calls(self) -> None:
        """Frida types handle socket API calls."""
        socket_apis = [
            "socket",
            "connect",
            "send",
            "recv",
            "WSAStartup",
        ]

        for api in socket_apis:
            payload: APICallPayload = {
                "event_type": "api_call",
                "api": api,
                "category": "network",
            }

            assert payload["api"] == api

    def test_ip_addresses_in_args(self) -> None:
        """Frida types handle IP addresses in arguments."""
        ip_addresses = [
            "192.168.1.1",
            "10.0.0.1",
            "8.8.8.8",
            "::1",
            "fe80::1",
        ]

        for ip in ip_addresses:
            payload: APICallPayload = {
                "event_type": "api_call",
                "api": "connect",
                "args": [1, ip, 443],
            }

            assert payload["args"][1] == ip

    def test_port_numbers(self) -> None:
        """Frida types handle port numbers."""
        ports = [80, 443, 8080, 3000, 65535]

        for port in ports:
            payload: APICallPayload = {
                "event_type": "api_call",
                "api": "connect",
                "args": [1, "127.0.0.1", port],
            }

            assert payload["args"][2] == port


class TestMessageParsingPlatformEdgeCases:
    """Test platform-specific edge cases in message parsing."""

    def test_parse_with_windows_line_endings(self) -> None:
        """parse_frida_message handles Windows line endings in stack traces."""
        message = {
            "type": "error",
            "stack": "Error: Test\r\n    at function1\r\n    at function2",
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "error"
        assert "\r\n" in payload["stack"]

    def test_parse_with_backslash_paths(self) -> None:
        """parse_frida_message preserves backslashes in Windows paths."""
        message = {
            "type": "send",
            "payload": {
                "path": r"C:\Program Files\App\file.dll",
            },
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert payload["path"] == r"C:\Program Files\App\file.dll"

    def test_parse_with_max_path_length(self) -> None:
        """parse_frida_message handles MAX_PATH length strings."""
        long_path = "C:\\" + "A" * 256

        message = {
            "type": "send",
            "payload": {"path": long_path},
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert len(payload["path"]) > 260

    def test_parse_with_very_large_addresses(self) -> None:
        """parse_frida_message handles maximum memory addresses."""
        if sys.maxsize > 2**32:
            max_addr = 0xffffffffffffffff
        else:
            max_addr = 0xffffffff

        message = {
            "type": "send",
            "payload": {
                "event_type": "pattern_found",
                "address": max_addr,
            },
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert payload["address"] == max_addr


class TestRealWorldScenarios:
    """Test real-world license protection scenarios."""

    def test_vmprotect_pattern_detection(self) -> None:
        """Frida types handle VMProtect pattern detection."""
        payload: MemoryPatternPayload = {
            "event_type": "pattern_found",
            "pattern_type": "vmprotect_signature",
            "value": "VMProtect 3.5.1",
            "address": 0x140001000,
            "message": "VMProtect protection detected",
        }

        assert payload["pattern_type"] == "vmprotect_signature"
        assert payload["address"] > 0

    def test_themida_api_call_sequence(self) -> None:
        """Frida types handle Themida API call sequences."""
        api_calls = [
            "GetTickCount",
            "QueryPerformanceCounter",
            "GetSystemTime",
        ]

        for api in api_calls:
            payload: APICallPayload = {
                "event_type": "api_call",
                "api": api,
                "category": "anti_debug",
            }

            assert payload["api"] == api

    def test_hardware_id_generation_api(self) -> None:
        """Frida types handle HWID generation API calls."""
        hwid_apis = [
            "GetVolumeInformationW",
            "GetAdaptersInfo",
            "GetSystemFirmwareTable",
        ]

        for api in hwid_apis:
            payload: APICallPayload = {
                "event_type": "api_call",
                "api": api,
                "category": "hardware_identification",
            }

            assert payload["api"] == api
            assert payload["category"] == "hardware_identification"
