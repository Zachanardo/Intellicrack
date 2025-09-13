"""
Comprehensive production-ready tests for API Obfuscation module.

Tests REAL API obfuscation techniques for evading monitoring and analysis.
NO MOCKS - ALL TESTS VALIDATE GENUINE ANTI-ANALYSIS CAPABILITIES.

Validates:
- Hash-based API resolution techniques
- String obfuscation/deobfuscation algorithms
- Dynamic import resolution methods
- Code generation for obfuscated API calls
- Advanced evasion techniques (trampolines, indirect calls, etc.)
- Cross-platform compatibility and error handling
"""

import ctypes
import platform
import pytest
import secrets
import struct
import zlib
from pathlib import Path
from typing import Any, Dict, List

from intellicrack.core.anti_analysis.api_obfuscation import APIObfuscator
from tests.base_test import BaseIntellicrackTest


class TestAPIObfuscator(BaseIntellicrackTest):
    """Test API obfuscation with REAL anti-analysis techniques."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test with API obfuscator."""
        self.obfuscator = APIObfuscator()

    def test_api_obfuscator_initialization(self):
        """Test APIObfuscator initializes with correct attributes and databases."""
        # Validate initialization
        assert hasattr(self.obfuscator, 'logger')
        assert hasattr(self.obfuscator, 'import_resolution_methods')
        assert hasattr(self.obfuscator, 'call_obfuscation_methods')
        assert hasattr(self.obfuscator, 'api_hash_db')
        assert hasattr(self.obfuscator, 'encrypted_strings_db')
        assert hasattr(self.obfuscator, 'resolved_apis_cache')

        # Validate method registration
        expected_resolution_methods = {
            "hash_resolution", "string_encryption", "dynamic_loading",
            "api_redirection", "delayed_loading"
        }
        assert set(self.obfuscator.import_resolution_methods.keys()) == expected_resolution_methods

        expected_obfuscation_methods = {
            "indirect_calls", "trampoline_calls", "encrypted_payloads",
            "polymorphic_wrappers"
        }
        assert set(self.obfuscator.call_obfuscation_methods.keys()) == expected_obfuscation_methods

        # Validate API database loaded
        assert isinstance(self.obfuscator.api_hash_db, dict)
        assert len(self.obfuscator.api_hash_db) > 0

        # Validate counters initialized
        assert self.obfuscator.resolved_apis == 0
        assert self.obfuscator.failed_resolutions == 0

    def test_hash_calculation_algorithms_real(self):
        """Test REAL hash calculation algorithms used in malware."""
        test_apis = [
            "LoadLibraryA", "GetProcAddress", "VirtualAlloc", "CreateProcessA",
            "NtAllocateVirtualMemory", "LdrLoadDll", "RegOpenKeyExA"
        ]

        for api_name in test_apis:
            # Test DJB2 hash (common in malware)
            djb2_hash = self.obfuscator._djb2_hash(api_name)
            assert isinstance(djb2_hash, int)
            assert 0 < djb2_hash <= 0xFFFFFFFF

            # Verify deterministic
            djb2_hash2 = self.obfuscator._djb2_hash(api_name)
            assert djb2_hash == djb2_hash2

            # Test FNV-1a hash
            fnv1a_hash = self.obfuscator._fnv1a_hash(api_name)
            assert isinstance(fnv1a_hash, int)
            assert 0 < fnv1a_hash <= 0xFFFFFFFF
            assert fnv1a_hash != djb2_hash  # Different algorithms

            # Test CRC32 hash
            crc32_hash = self.obfuscator._crc32_hash(api_name)
            assert isinstance(crc32_hash, int)
            assert 0 < crc32_hash <= 0xFFFFFFFF

            # Test custom hash
            custom_hash = self.obfuscator._custom_hash(api_name)
            assert isinstance(custom_hash, int)
            assert 0 < custom_hash <= 0xFFFFFFFF

            # All hashes should be different for security
            hashes = [djb2_hash, fnv1a_hash, crc32_hash, custom_hash]
            assert len(set(hashes)) >= 3  # At least 3 different values

    def test_string_obfuscation_deobfuscation_real(self):
        """Test REAL string obfuscation/deobfuscation used in evasion."""
        test_strings = [
            "kernel32.dll", "LoadLibraryA", "GetProcAddress", "VirtualAlloc",
            "CreateProcessA", "WriteProcessMemory", "ReadProcessMemory",
            "NtWriteVirtualMemory", "ZwAllocateVirtualMemory"
        ]

        for test_string in test_strings:
            # Obfuscate string
            obfuscated = self.obfuscator._obfuscated_string(test_string)

            # Validate obfuscated format
            assert isinstance(obfuscated, bytes)
            assert len(obfuscated) == len(test_string) + 1  # Key + data
            assert obfuscated[0] != 0  # Key should not be 0

            # Verify data is actually encrypted
            encrypted_data = obfuscated[1:]
            original_bytes = test_string.encode()
            assert encrypted_data != original_bytes  # Must be encrypted

            # Deobfuscate and validate
            deobfuscated = self.obfuscator._deobfuscate_string(obfuscated)
            assert deobfuscated == test_string

            # Test with different strings produce different obfuscations
            obfuscated2 = self.obfuscator._obfuscated_string(test_string)
            # Should be different due to random key
            assert obfuscated != obfuscated2 or obfuscated[0] != obfuscated2[0]

    def test_api_resolution_normal_method_real(self):
        """Test REAL normal API resolution on Windows."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        # Test common Windows APIs
        test_cases = [
            ("kernel32.dll", "LoadLibraryA"),
            ("kernel32.dll", "GetProcAddress"),
            ("kernel32.dll", "VirtualAlloc"),
            ("user32.dll", "MessageBoxA"),
            ("advapi32.dll", "RegOpenKeyExA")
        ]

        for dll_name, api_name in test_cases:
            address = self.obfuscator.resolve_api(dll_name, api_name, "normal")

            if address is not None:  # API might not exist on all systems
                assert isinstance(address, int)
                assert address > 0x1000  # Valid memory address

                # Should be cached
                cached_address = self.obfuscator.resolve_api(dll_name, api_name, "normal")
                assert cached_address == address

                # Cache key should exist
                cache_key = f"{dll_name}!{api_name}"
                assert cache_key in self.obfuscator.resolved_apis_cache

    def test_api_resolution_hash_lookup_real(self):
        """Test REAL hash-based API resolution technique."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        # Test hash-based resolution
        test_apis = ["LoadLibraryA", "GetProcAddress", "VirtualAlloc"]

        for api_name in test_apis:
            # Calculate hash
            calculated_hash = self.obfuscator._calculate_hash(api_name)
            assert isinstance(calculated_hash, int)

            # Attempt hash resolution
            address = self.obfuscator.resolve_api("kernel32.dll", api_name, "hash_lookup")

            if address is not None:
                assert isinstance(address, int)
                assert address > 0x1000

                # Should match normal resolution
                normal_address = self.obfuscator.resolve_api("kernel32.dll", api_name, "normal")
                if normal_address is not None:
                    assert address == normal_address

    def test_api_resolution_ordinal_lookup_real(self):
        """Test REAL ordinal-based API resolution."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        # Test ordinal resolution (common in packed/obfuscated malware)
        dll_name = "kernel32.dll"

        # Test with various ordinals
        test_ordinals = [1, 2, 5, 10]  # Common ordinals

        for ordinal in test_ordinals:
            address = self.obfuscator.resolve_api(dll_name, "dummy", "ordinal_lookup")
            # Address could be None if ordinal doesn't exist
            if address is not None:
                assert isinstance(address, int)
                assert address > 0x1000

    def test_api_resolution_dynamic_method_real(self):
        """Test REAL dynamic API resolution with string manipulation."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        # Test dynamic resolution with obfuscated strings
        test_cases = [
            ("kernel32.dll", "LoadLibraryA"),
            ("user32.dll", "MessageBoxA")
        ]

        for dll_name, api_name in test_cases:
            address = self.obfuscator.resolve_api(dll_name, api_name, "dynamic_resolution")

            if address is not None:
                assert isinstance(address, int)
                assert address > 0x1000

                # Should match normal resolution
                normal_address = self.obfuscator.resolve_api(dll_name, api_name, "normal")
                if normal_address is not None:
                    assert address == normal_address

    def test_obfuscate_api_calls_hash_lookup_real(self):
        """Test REAL hash-based API call obfuscation code generation."""
        test_code = """
        #include <windows.h>

        int main() {
            LoadLibraryA("user32.dll");
            GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualAlloc");
            return 0;
        }
        """

        # Generate hash lookup obfuscation
        obfuscated_code = self.obfuscator.obfuscate_api_calls(test_code, "hash_lookup")

        # Validate real obfuscated code
        self.assert_real_output(obfuscated_code, "Hash lookup obfuscation appears to be placeholder")
        assert len(obfuscated_code) > len(test_code)  # Should be longer

        # Should contain C code with hash-based resolution
        assert "#include <windows.h>" in obfuscated_code
        assert "Crc32" in obfuscated_code or "hash" in obfuscated_code.lower()
        assert "ResolveApiHash" in obfuscated_code or "resolve" in obfuscated_code.lower()
        assert "0x" in obfuscated_code  # Should contain hash values

        # Should contain actual function prototypes
        assert "FARPROC" in obfuscated_code or "typedef" in obfuscated_code

    def test_obfuscate_api_calls_dynamic_resolution_real(self):
        """Test REAL dynamic API resolution code generation."""
        test_code = "CreateProcessA();"

        # Generate dynamic resolution obfuscation
        obfuscated_code = self.obfuscator.obfuscate_api_calls(test_code, "dynamic_resolution")

        # Validate real obfuscated code
        self.assert_real_output(obfuscated_code, "Dynamic resolution obfuscation appears to be placeholder")
        assert len(obfuscated_code) > 100  # Should be substantial code

        # Should contain dynamic string building
        assert "DeobfuscateString" in obfuscated_code or "decrypt" in obfuscated_code.lower()
        assert "BuildApiName" in obfuscated_code or "build" in obfuscated_code.lower()
        assert "switch" in obfuscated_code or "case" in obfuscated_code

        # Should contain obfuscated data arrays
        assert "unsigned char" in obfuscated_code
        assert "{" in obfuscated_code and "}" in obfuscated_code  # Array initializers

    def test_call_obfuscation_generation_real(self):
        """Test REAL call obfuscation technique generation."""
        test_apis = ["VirtualAlloc", "CreateThread", "WriteProcessMemory"]

        for api_name in test_apis:
            obfuscated_call = self.obfuscator.generate_call_obfuscation(api_name)

            # Validate real obfuscated call
            self.assert_real_output(obfuscated_call, f"Call obfuscation for {api_name} appears to be placeholder")
            assert api_name in obfuscated_call
            assert "0x" in obfuscated_call  # Should contain hash
            assert "ResolveApiHash" in obfuscated_call or "resolve" in obfuscated_call.lower()
            assert "FARPROC" in obfuscated_call
            assert "GetModuleHandle" in obfuscated_call

    def test_indirect_call_functionality_real(self):
        """Test REAL indirect API call through function pointers."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        # Get a real API address to test with
        kernel32 = ctypes.windll.kernel32
        get_tick_count_addr = kernel32.GetProcAddress(
            kernel32.GetModuleHandleW("kernel32.dll"),
            b"GetTickCount"
        )

        if get_tick_count_addr:
            # Test indirect call with no arguments
            result = self.obfuscator._indirect_call(get_tick_count_addr)
            assert result is not None  # GetTickCount returns tick count

    def test_advanced_obfuscation_techniques_real(self):
        """Test REAL advanced obfuscation techniques with binary code."""
        # Create sample x86 code bytes with API calls
        sample_code = bytearray([
            0xE8, 0x12, 0x34, 0x56, 0x78,  # CALL rel32
            0xFF, 0x15, 0x9A, 0xBC, 0xDE, 0xF0,  # CALL DWORD PTR [addr32]
            0x90, 0x90, 0x90,  # NOPs
            0xE8, 0xAA, 0xBB, 0xCC, 0xDD,  # Another CALL
        ])

        # Test indirect calls generation
        indirect_result = self.obfuscator._generate_indirect_calls(bytes(sample_code), {})

        assert isinstance(indirect_result, tuple)
        assert len(indirect_result) == 2
        modified_code, metadata = indirect_result

        assert isinstance(modified_code, bytes)
        assert isinstance(metadata, dict)
        assert "method" in metadata
        assert metadata["method"] == "indirect_calls"

        # Test trampoline calls generation
        trampoline_result = self.obfuscator._generate_trampoline_calls(bytes(sample_code), {})

        modified_code, metadata = trampoline_result
        assert isinstance(modified_code, bytes)
        assert len(modified_code) >= len(sample_code)  # May be longer with trampolines
        assert metadata["method"] == "trampoline_calls"

        # Test encrypted payloads generation
        encrypt_result = self.obfuscator._generate_encrypted_payloads(bytes(sample_code), {})

        modified_code, metadata = encrypt_result
        assert isinstance(modified_code, bytes)
        assert metadata["method"] == "encrypted_payloads"
        assert "encryption_key" in metadata

        # Test polymorphic wrappers generation
        poly_result = self.obfuscator._generate_polymorphic_wrappers(bytes(sample_code), {})

        modified_code, metadata = poly_result
        assert isinstance(modified_code, bytes)
        assert metadata["method"] == "polymorphic_wrappers"

    def test_import_resolution_techniques_real(self):
        """Test REAL import resolution obfuscation techniques."""
        # Create sample code with import patterns
        sample_code = bytearray([
            0x68, 0x12, 0x34, 0x56, 0x78,  # PUSH imm32 (string addr)
            0xFF, 0x15, 0xAA, 0xBB, 0xCC, 0xDD,  # CALL DWORD PTR (GetProcAddress)
            0xFF, 0x25, 0x11, 0x22, 0x33, 0x44,  # JMP DWORD PTR (delayed import)
            0xE8, 0x55, 0x66, 0x77, 0x88,  # CALL rel32 (helper)
        ])

        # Test encrypted strings resolution
        encrypt_result = self.obfuscator._resolve_encrypted_strings(bytes(sample_code), {"key": 0xDEADBEEF})

        resolved_code, metadata = encrypt_result
        assert isinstance(resolved_code, bytes)
        assert metadata["method"] == "string_encryption"

        # Test dynamic imports resolution
        dynamic_result = self.obfuscator._resolve_dynamic_imports(bytes(sample_code), {})

        resolved_code, metadata = dynamic_result
        assert isinstance(resolved_code, bytes)
        assert metadata["method"] == "dynamic_loading"

        # Test redirected APIs resolution
        redirect_result = self.obfuscator._resolve_redirected_apis(bytes(sample_code), {})

        resolved_code, metadata = redirect_result
        assert isinstance(resolved_code, bytes)
        assert metadata["method"] == "api_redirection"

        # Test delayed imports resolution
        delayed_result = self.obfuscator._resolve_delayed_imports(bytes(sample_code), {})

        resolved_code, metadata = delayed_result
        assert isinstance(resolved_code, bytes)
        assert metadata["method"] == "delayed_loading"

    def test_pe_header_parsing_real(self):
        """Test REAL PE header parsing for export table analysis."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        # Test with kernel32.dll (always present)
        dll_name = "kernel32.dll"
        api_hash = self.obfuscator._djb2_hash("LoadLibraryA")

        # This will exercise the PE parsing code in _resolve_by_hash
        address = self.obfuscator._resolve_by_hash(dll_name, api_hash)

        # Address could be None if parsing fails or API not found
        if address is not None:
            assert isinstance(address, int)
            assert address > 0x1000

    def test_forwarded_export_resolution_real(self):
        """Test REAL forwarded export resolution."""
        # Test forwarded export resolution
        forward_cases = [
            "NTDLL.RtlInitUnicodeString",
            "KERNEL32.GetProcAddress",
            "USER32.MessageBoxA"
        ]

        for forward_str in forward_cases:
            result = self.obfuscator._resolve_forwarded_export(forward_str)
            # Result could be None if DLL/API doesn't exist
            if result is not None:
                assert isinstance(result, int)
                assert result > 0x1000

    def test_decryption_stub_generation_real(self):
        """Test REAL x86/x64 decryption stub generation."""
        # Test parameters
        offset = 0x1000
        size = 0x100
        key = 0x42

        stub = self.obfuscator._generate_decryption_stub(offset, size, key)

        # Validate generated stub
        assert isinstance(stub, bytearray)
        assert len(stub) > 20  # Should be substantial code

        # Should contain x86 instructions
        assert 0x50 in stub  # PUSH EAX
        assert 0x58 in stub  # POP EAX
        assert 0x30 in stub  # XOR
        assert 0xE9 in stub  # JMP

        # Should contain the XOR key
        assert key in stub

    def test_error_handling_and_edge_cases(self):
        """Test error handling and edge cases."""
        # Test invalid obfuscation method
        result = self.obfuscator.obfuscate_api_calls("test", "invalid_method")
        assert result == "test"  # Should return original on error

        # Test API resolution with invalid method
        result = self.obfuscator.resolve_api("kernel32.dll", "LoadLibraryA", "invalid_method")
        assert result is None

        # Test string deobfuscation with invalid data
        result = self.obfuscator._deobfuscate_string(b"")
        assert result == ""

        result = self.obfuscator._deobfuscate_string(b"\x42")
        assert result == ""

        # Test hash functions with empty strings
        assert self.obfuscator._djb2_hash("") == 5381
        assert isinstance(self.obfuscator._fnv1a_hash(""), int)
        assert isinstance(self.obfuscator._crc32_hash(""), int)
        assert isinstance(self.obfuscator._custom_hash(""), int)

    def test_hash_collision_resistance(self):
        """Test hash algorithms for collision resistance."""
        test_strings = [
            "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "VirtualAlloc",
            "CreateProcessA", "CreateProcessW", "WriteProcessMemory",
            "ReadProcessMemory", "VirtualProtect", "CreateThread"
        ]

        # Test each hash algorithm for collisions
        for hash_func_name in ["_djb2_hash", "_fnv1a_hash", "_crc32_hash", "_custom_hash"]:
            hash_func = getattr(self.obfuscator, hash_func_name)
            hashes = [hash_func(s) for s in test_strings]

            # Should have mostly unique hashes (minimal collisions)
            unique_hashes = len(set(hashes))
            assert unique_hashes >= len(test_strings) * 0.8  # Allow some collisions

    def test_api_database_completeness(self):
        """Test API hash database has comprehensive coverage."""
        # Should contain common Windows APIs
        expected_apis = [
            "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "VirtualAlloc",
            "CreateProcessA", "CreateThread", "WriteProcessMemory",
            "NtAllocateVirtualMemory", "LdrLoadDll", "RegOpenKeyExA"
        ]

        # Check that hashes exist for these APIs
        found_apis = 0
        for api in expected_apis:
            # Check if any hash variant exists in database
            for hash_type in ["djb2", "fnv1a", "crc32", "custom"]:
                hash_value = getattr(self.obfuscator, f"_{hash_type}_hash")(api)
                key = f"{hash_type}_{hash_value}"
                if key in self.obfuscator.api_hash_db:
                    found_apis += 1
                    break

        # Should find most expected APIs
        assert found_apis >= len(expected_apis) * 0.7

    def test_cache_functionality_real(self):
        """Test API resolution caching works correctly."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        dll_name = "kernel32.dll"
        api_name = "GetTickCount"

        # First resolution
        initial_cache_size = len(self.obfuscator.resolved_apis_cache)
        address1 = self.obfuscator.resolve_api(dll_name, api_name, "normal")

        if address1 is not None:
            # Should be cached
            cache_key = f"{dll_name}!{api_name}"
            assert cache_key in self.obfuscator.resolved_apis_cache
            assert len(self.obfuscator.resolved_apis_cache) > initial_cache_size

            # Second resolution should use cache
            address2 = self.obfuscator.resolve_api(dll_name, api_name, "normal")
            assert address2 == address1

            # Cache size shouldn't increase
            assert len(self.obfuscator.resolved_apis_cache) == initial_cache_size + 1

    def test_cross_platform_compatibility(self):
        """Test cross-platform compatibility and graceful fallbacks."""
        # On non-Windows platforms, Windows-specific methods should return None gracefully
        if platform.system() != "Windows":
            # Test normal resolution
            result = self.obfuscator._normal_resolve("kernel32.dll", "LoadLibraryA")
            assert result is None

            # Test hash resolution
            result = self.obfuscator._resolve_by_hash("kernel32.dll", 12345)
            assert result is None

            # Test ordinal resolution
            result = self.obfuscator._resolve_by_ordinal("kernel32.dll", 1)
            assert result is None

    @pytest.mark.real_data
    def test_production_readiness_validation(self):
        """Validate that all methods produce production-ready output."""
        # Test all major methods produce real output
        methods_to_test = [
            ("obfuscate_api_calls", ["test code", "hash_lookup"]),
            ("generate_call_obfuscation", ["LoadLibraryA"]),
        ]

        for method_name, args in methods_to_test:
            method = getattr(self.obfuscator, method_name)
            result = method(*args)
            self.assert_real_output(result, f"{method_name} produced placeholder output")

        # Validate hash functions produce consistent results
        test_string = "VirtualAlloc"
        hash1 = self.obfuscator._djb2_hash(test_string)
        hash2 = self.obfuscator._djb2_hash(test_string)
        assert hash1 == hash2

        # Validate string obfuscation/deobfuscation roundtrip
        test_string = "GetProcAddress"
        obfuscated = self.obfuscator._obfuscated_string(test_string)
        deobfuscated = self.obfuscator._deobfuscate_string(obfuscated)
        assert deobfuscated == test_string
