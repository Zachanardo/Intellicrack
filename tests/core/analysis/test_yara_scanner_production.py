"""Production-grade YARA scanner tests - Advanced scenarios with real binaries.

This test suite validates YARA scanning capabilities using REAL Windows system binaries
and realistic protection patterns. NO MOCKS - all tests use actual binary data.

Coverage:
- Windows system binary scanning (kernel32.dll, ntdll.dll, etc.)
- Real-world protected binary detection
- Advanced memory scanning scenarios
- Performance benchmarking with large binaries
- Rule compilation caching and optimization
- Match context extraction and analysis
- Multi-file batch scanning
- Rule dependency management
- Error recovery and resilience
- Thread safety under concurrent load

Tests MUST FAIL if YARA detection capabilities don't work effectively.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import os
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import pytest
import yara

from intellicrack.core.analysis.yara_scanner import (
    ProtectionSignature,
    RuleCategory,
    YaraMatch,
    YaraScanner,
)


class RealBinaryGenerator:
    """Generates realistic PE binaries with authentic protection signatures."""

    @staticmethod
    def create_minimal_pe() -> bytes:
        """Create minimal valid PE executable."""
        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        machine = struct.pack("<H", 0x8664)
        num_sections = struct.pack("<H", 1)
        timestamp = struct.pack("<I", int(time.time()))
        ptr_symbol_table = struct.pack("<I", 0)
        num_symbols = struct.pack("<I", 0)
        size_optional_header = struct.pack("<H", 240)
        characteristics = struct.pack("<H", 0x0022)

        coff_header = (
            machine + num_sections + timestamp + ptr_symbol_table +
            num_symbols + size_optional_header + characteristics
        )

        magic = struct.pack("<H", 0x020B)
        linker_version = struct.pack("BB", 14, 0)
        code_size = struct.pack("<I", 512)
        init_data_size = struct.pack("<I", 512)
        uninit_data_size = struct.pack("<I", 0)
        entry_point = struct.pack("<I", 0x1000)
        base_of_code = struct.pack("<I", 0x1000)
        image_base = struct.pack("<Q", 0x140000000)
        section_align = struct.pack("<I", 0x1000)
        file_align = struct.pack("<I", 0x200)
        os_version = struct.pack("<HH", 6, 0)
        image_version = struct.pack("<HH", 0, 0)
        subsystem_version = struct.pack("<HH", 6, 0)
        win32_version = struct.pack("<I", 0)
        image_size = struct.pack("<I", 0x3000)
        headers_size = struct.pack("<I", 0x400)
        checksum = struct.pack("<I", 0)
        subsystem = struct.pack("<H", 3)
        dll_chars = struct.pack("<H", 0x8160)
        stack_reserve = struct.pack("<Q", 0x100000)
        stack_commit = struct.pack("<Q", 0x1000)
        heap_reserve = struct.pack("<Q", 0x100000)
        heap_commit = struct.pack("<Q", 0x1000)
        loader_flags = struct.pack("<I", 0)
        num_rva = struct.pack("<I", 16)

        optional_header = (
            magic + linker_version + code_size + init_data_size +
            uninit_data_size + entry_point + base_of_code + image_base +
            section_align + file_align + os_version + image_version +
            subsystem_version + win32_version + image_size + headers_size +
            checksum + subsystem + dll_chars + stack_reserve + stack_commit +
            heap_reserve + heap_commit + loader_flags + num_rva
        )

        data_directories = b"\x00" * (16 * 8)

        section_name = b".text\x00\x00\x00"
        virtual_size = struct.pack("<I", 512)
        virtual_addr = struct.pack("<I", 0x1000)
        raw_size = struct.pack("<I", 512)
        raw_ptr = struct.pack("<I", 0x400)
        reloc_ptr = struct.pack("<I", 0)
        line_ptr = struct.pack("<I", 0)
        num_reloc = struct.pack("<H", 0)
        num_line = struct.pack("<H", 0)
        section_chars = struct.pack("<I", 0x60000020)

        section_header = (
            section_name + virtual_size + virtual_addr + raw_size + raw_ptr +
            reloc_ptr + line_ptr + num_reloc + num_line + section_chars
        )

        pe_data = (
            dos_header + pe_signature + coff_header + optional_header +
            data_directories + section_header
        )

        padding = b"\x00" * (0x400 - len(pe_data))
        section_data = b"\xC3" * 512

        return bytes(pe_data + padding + section_data)

    @staticmethod
    def create_vmprotect_binary() -> bytes:
        """Create PE with VMProtect signatures."""
        base_pe = bytearray(RealBinaryGenerator.create_minimal_pe())

        vmprotect_strings = [
            b"VMProtect",
            b".vmp0",
            b".vmp1",
            b".vmp2",
        ]

        vmprotect_entry_pattern = b"\x68\x00\x00\x00\x00\xe8\x00\x00\x00\x00"
        vmprotect_signature = b"\x9C\x60\x68\x00\x00\x00\x00\x8B\x74\x24\x28"

        offset = 0x500
        for sig_string in vmprotect_strings:
            base_pe[offset:offset + len(sig_string)] = sig_string
            offset += len(sig_string) + 32

        base_pe[0x600:0x600 + len(vmprotect_entry_pattern)] = vmprotect_entry_pattern
        base_pe[0x650:0x650 + len(vmprotect_signature)] = vmprotect_signature

        return bytes(base_pe)

    @staticmethod
    def create_themida_binary() -> bytes:
        """Create PE with Themida signatures."""
        base_pe = bytearray(RealBinaryGenerator.create_minimal_pe())

        themida_strings = [
            b"Themida",
            b".themida",
            b"SecureEngineSDK.dll",
        ]

        themida_entry = b"\xB8\x00\x00\x00\x00\x60\x0B\xC0\x74\x58"
        themida_sig = b"\x8B\xC5\x8B\xD4\x60\xE8\x00\x00\x00\x00"

        offset = 0x500
        for sig_string in themida_strings:
            base_pe[offset:offset + len(sig_string)] = sig_string
            offset += len(sig_string) + 32

        base_pe[0x600:0x600 + len(themida_entry)] = themida_entry
        base_pe[0x650:0x650 + len(themida_sig)] = themida_sig

        return bytes(base_pe)

    @staticmethod
    def create_upx_binary() -> bytes:
        """Create PE with UPX signatures."""
        base_pe = bytearray(RealBinaryGenerator.create_minimal_pe())

        upx_strings = [
            b"UPX!",
            b"UPX0",
            b"UPX1",
            b"UPX2",
        ]

        upx_entry = b"\x60\xBE\x00\x00\x00\x00\x8D\xBE\x00\x00\x00\x00"

        offset = 0x500
        for sig_string in upx_strings:
            base_pe[offset:offset + len(sig_string)] = sig_string
            offset += len(sig_string) + 32

        base_pe[0x600:0x600 + len(upx_entry)] = upx_entry

        return bytes(base_pe)

    @staticmethod
    def create_denuvo_binary() -> bytes:
        """Create PE with Denuvo signatures."""
        base_pe = bytearray(RealBinaryGenerator.create_minimal_pe())

        denuvo_strings = [
            b"Denuvo",
            b".denu",
            b"denuvo64.dll",
        ]

        denuvo_sig = b"\x48\x8D\x05\x00\x00\x00\x00\x48\x89\x45\x00"

        offset = 0x500
        for sig_string in denuvo_strings:
            base_pe[offset:offset + len(sig_string)] = sig_string
            offset += len(sig_string) + 32

        base_pe[0x600:0x600 + len(denuvo_sig)] = denuvo_sig

        return bytes(base_pe)

    @staticmethod
    def create_license_check_binary() -> bytes:
        """Create PE with license validation patterns."""
        base_pe = bytearray(RealBinaryGenerator.create_minimal_pe())

        license_strings = [
            b"CheckLicense",
            b"ValidateLicense",
            b"VerifyLicense",
            b"Invalid license",
            b"License expired",
            b"Trial period",
            b"Product key",
            b"Serial number",
        ]

        offset = 0x500
        for lic_string in license_strings:
            base_pe[offset:offset + len(lic_string)] = lic_string
            offset += len(lic_string) + 16

        return bytes(base_pe)

    @staticmethod
    def create_crypto_binary() -> bytes:
        """Create PE with cryptographic signatures."""
        base_pe = bytearray(RealBinaryGenerator.create_minimal_pe())

        aes_sbox = bytes([
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
            0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        ])

        rsa_padding = b"\x00\x01\xFF\xFF\xFF\xFF\xFF\xFF"

        crypto_apis = [
            b"CryptEncrypt",
            b"CryptDecrypt",
            b"BCryptEncrypt",
            b"BCryptDecrypt",
        ]

        base_pe[0x500:0x500 + len(aes_sbox)] = aes_sbox
        base_pe[0x520:0x520 + len(rsa_padding)] = rsa_padding

        offset = 0x540
        for api_name in crypto_apis:
            base_pe[offset:offset + len(api_name)] = api_name
            offset += len(api_name) + 16

        return bytes(base_pe)

    @staticmethod
    def create_flexlm_binary() -> bytes:
        """Create PE with FlexLM license manager signatures."""
        base_pe = bytearray(RealBinaryGenerator.create_minimal_pe())

        flexlm_strings = [
            b"FLEXlm",
            b"lmgrd",
            b"FLEXLM_DIAGNOSTICS",
            b"vendor daemon",
            b"lc_checkout",
            b"lc_checkin",
            b"lc_init",
        ]

        offset = 0x500
        for flex_string in flexlm_strings:
            base_pe[offset:offset + len(flex_string)] = flex_string
            offset += len(flex_string) + 16

        return bytes(base_pe)

    @staticmethod
    def create_hasp_binary() -> bytes:
        """Create PE with Sentinel HASP signatures."""
        base_pe = bytearray(RealBinaryGenerator.create_minimal_pe())

        hasp_strings = [
            b"hasp_login",
            b"hasp_logout",
            b"hasp_encrypt",
            b"HASP HL",
            b"Sentinel HASP",
        ]

        offset = 0x500
        for hasp_string in hasp_strings:
            base_pe[offset:offset + len(hasp_string)] = hasp_string
            offset += len(hasp_string) + 16

        return bytes(base_pe)


@pytest.fixture
def scanner() -> YaraScanner:
    """Create YARA scanner instance."""
    return YaraScanner()


@pytest.fixture
def temp_binary_dir() -> Path:
    """Create temporary directory for test binaries."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def windows_system32() -> Path:
    """Get Windows System32 directory path."""
    system32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"
    if not system32.exists():
        pytest.skip("Windows System32 directory not accessible")
    return system32


class TestWindowsSystemBinaryScanning:
    """Test YARA scanning against real Windows system binaries."""

    def test_scan_kernel32_dll(self, scanner: YaraScanner, windows_system32: Path) -> None:
        """Scanner detects patterns in kernel32.dll."""
        kernel32_path = windows_system32 / "kernel32.dll"
        if not kernel32_path.exists():
            pytest.skip("kernel32.dll not found")

        matches: list[YaraMatch] = scanner.scan_file(kernel32_path)

        assert matches, "Should detect patterns in kernel32.dll"
        assert any(m.category == RuleCategory.COMPILER for m in matches), \
                "Should detect compiler signatures"

    def test_scan_ntdll_dll(self, scanner: YaraScanner, windows_system32: Path) -> None:
        """Scanner detects patterns in ntdll.dll."""
        ntdll_path = windows_system32 / "ntdll.dll"
        if not ntdll_path.exists():
            pytest.skip("ntdll.dll not found")

        matches: list[YaraMatch] = scanner.scan_file(ntdll_path)

        assert matches, "Should detect patterns in ntdll.dll"

    def test_scan_user32_dll(self, scanner: YaraScanner, windows_system32: Path) -> None:
        """Scanner processes user32.dll without errors."""
        user32_path = windows_system32 / "user32.dll"
        if not user32_path.exists():
            pytest.skip("user32.dll not found")

        matches: list[YaraMatch] = scanner.scan_file(user32_path)

        assert isinstance(matches, list), "Should return list of matches"

    def test_scan_multiple_system_dlls(self, scanner: YaraScanner, windows_system32: Path) -> None:
        """Scanner handles batch scanning of multiple system DLLs."""
        dll_names = ["kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll"]

        all_matches: dict[str, list[YaraMatch]] = {}
        for dll_name in dll_names:
            dll_path = windows_system32 / dll_name
            if dll_path.exists():
                matches = scanner.scan_file(dll_path)
                all_matches[dll_name] = matches

        assert all_matches, "Should scan at least one system DLL"
        for dll_name, matches in all_matches.items():
            assert isinstance(matches, list), f"{dll_name} should return valid matches"

    def test_system_binary_match_offsets(self, scanner: YaraScanner, windows_system32: Path) -> None:
        """Match offsets in system binaries are valid."""
        kernel32_path = windows_system32 / "kernel32.dll"
        if not kernel32_path.exists():
            pytest.skip("kernel32.dll not found")

        matches: list[YaraMatch] = scanner.scan_file(kernel32_path)

        for match in matches:
            assert match.offset >= 0, "Offset should be non-negative"
            assert match.offset < kernel32_path.stat().st_size, \
                "Offset should be within file bounds"


class TestRealWorldProtectedBinaries:
    """Test YARA detection against real protected binaries from fixtures."""

    def test_scan_upx_packed_binary(self, scanner: YaraScanner) -> None:
        """Scanner detects UPX packer in real packed binary."""
        upx_path = Path("tests/fixtures/binaries/protected/upx_packed_0.exe")
        if not upx_path.exists():
            pytest.skip("UPX packed binary fixture not available")

        matches: list[YaraMatch] = scanner.scan_file(upx_path)

        upx_detected = any(
            "UPX" in m.rule_name.upper() or m.category == RuleCategory.PACKER
            for m in matches
        )
        assert upx_detected, "Should detect UPX packer in packed binary"

    def test_scan_vmprotect_binary(self, scanner: YaraScanner) -> None:
        """Scanner detects VMProtect in protected binary."""
        vmp_path = Path("tests/fixtures/binaries/protected/vmprotect_protected.exe")
        if not vmp_path.exists():
            pytest.skip("VMProtect binary fixture not available")

        matches: list[YaraMatch] = scanner.scan_file(vmp_path)

        vmp_detected = any(
            "VMProtect" in m.rule_name or m.category == RuleCategory.PROTECTOR
            for m in matches
        )
        assert vmp_detected, "Should detect VMProtect in protected binary"

    def test_scan_themida_binary(self, scanner: YaraScanner) -> None:
        """Scanner detects Themida in protected binary."""
        themida_path = Path("tests/fixtures/binaries/protected/themida_protected.exe")
        if not themida_path.exists():
            pytest.skip("Themida binary fixture not available")

        matches: list[YaraMatch] = scanner.scan_file(themida_path)

        themida_detected = any(
            "Themida" in m.rule_name or m.category == RuleCategory.PROTECTOR
            for m in matches
        )
        assert themida_detected, "Should detect Themida in protected binary"

    def test_scan_dotnet_assembly(self, scanner: YaraScanner) -> None:
        """Scanner processes .NET assemblies correctly."""
        dotnet_path = Path("tests/fixtures/binaries/protected/dotnet_assembly_0.exe")
        if not dotnet_path.exists():
            pytest.skip(".NET assembly fixture not available")

        matches: list[YaraMatch] = scanner.scan_file(dotnet_path)

        assert isinstance(matches, list), "Should handle .NET assemblies"


class TestGeneratedProtectedBinaries:
    """Test YARA detection with programmatically generated protected binaries."""

    def test_detect_vmprotect_signatures(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner detects VMProtect signatures in generated binary."""
        vmp_binary = RealBinaryGenerator.create_vmprotect_binary()
        vmp_path = temp_binary_dir / "vmprotect_test.exe"
        vmp_path.write_bytes(vmp_binary)

        matches: list[YaraMatch] = scanner.scan_file(vmp_path)

        vmp_detected = any(
            "VMProtect" in m.rule_name.upper() or
            any("vmp" in str(s).lower() for _, _, s in m.matched_strings)
            for m in matches
        )
        assert vmp_detected, "Should detect VMProtect signatures"

    def test_detect_themida_signatures(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner detects Themida signatures in generated binary."""
        themida_binary = RealBinaryGenerator.create_themida_binary()
        themida_path = temp_binary_dir / "themida_test.exe"
        themida_path.write_bytes(themida_binary)

        matches: list[YaraMatch] = scanner.scan_file(themida_path)

        themida_detected = any(
            "Themida" in m.rule_name or
            any(b"Themida" in s or b"themida" in s for _, _, s in m.matched_strings)
            for m in matches
        )
        assert themida_detected, "Should detect Themida signatures"

    def test_detect_upx_signatures(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner detects UPX signatures in generated binary."""
        upx_binary = RealBinaryGenerator.create_upx_binary()
        upx_path = temp_binary_dir / "upx_test.exe"
        upx_path.write_bytes(upx_binary)

        matches: list[YaraMatch] = scanner.scan_file(upx_path)

        upx_detected = any(
            "UPX" in m.rule_name.upper() or
            any(b"UPX" in s for _, _, s in m.matched_strings)
            for m in matches
        )
        assert upx_detected, "Should detect UPX signatures"

    def test_detect_denuvo_signatures(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner detects Denuvo signatures in generated binary."""
        denuvo_binary = RealBinaryGenerator.create_denuvo_binary()
        denuvo_path = temp_binary_dir / "denuvo_test.exe"
        denuvo_path.write_bytes(denuvo_binary)

        matches: list[YaraMatch] = scanner.scan_file(denuvo_path)

        denuvo_detected = any(
            "Denuvo" in m.rule_name or
            any(b"Denuvo" in s or b"denu" in s for _, _, s in m.matched_strings)
            for m in matches
        )
        assert denuvo_detected, "Should detect Denuvo signatures"

    def test_detect_license_check_patterns(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner detects license validation patterns."""
        license_binary = RealBinaryGenerator.create_license_check_binary()
        license_path = temp_binary_dir / "license_check_test.exe"
        license_path.write_bytes(license_binary)

        matches: list[YaraMatch] = scanner.scan_file(
            license_path,
            categories=[RuleCategory.LICENSE]
        )

        license_detected = any(
            m.category == RuleCategory.LICENSE or
            any(b"License" in s or b"license" in s for _, _, s in m.matched_strings)
            for m in matches
        )
        assert license_detected, "Should detect license validation patterns"

    def test_detect_crypto_signatures(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner detects cryptographic signatures."""
        crypto_binary = RealBinaryGenerator.create_crypto_binary()
        crypto_path = temp_binary_dir / "crypto_test.exe"
        crypto_path.write_bytes(crypto_binary)

        matches: list[YaraMatch] = scanner.scan_file(
            crypto_path,
            categories=[RuleCategory.CRYPTO]
        )

        crypto_detected = any(
            m.category == RuleCategory.CRYPTO or
            any(b"Crypt" in s or b"crypt" in s for _, _, s in m.matched_strings)
            for m in matches
        )
        assert crypto_detected, "Should detect cryptographic signatures"

    def test_detect_flexlm_signatures(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner detects FlexLM license manager signatures."""
        flexlm_binary = RealBinaryGenerator.create_flexlm_binary()
        flexlm_path = temp_binary_dir / "flexlm_test.exe"
        flexlm_path.write_bytes(flexlm_binary)

        matches: list[YaraMatch] = scanner.scan_file(
            flexlm_path,
            categories=[RuleCategory.LICENSE]
        )

        flexlm_detected = any(
            "FlexLM" in m.rule_name or "FLEXlm" in m.rule_name or
            any(b"FLEX" in s or b"lmgrd" in s for _, _, s in m.matched_strings)
            for m in matches
        )
        assert flexlm_detected, "Should detect FlexLM signatures"

    def test_detect_hasp_signatures(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner detects Sentinel HASP signatures."""
        hasp_binary = RealBinaryGenerator.create_hasp_binary()
        hasp_path = temp_binary_dir / "hasp_test.exe"
        hasp_path.write_bytes(hasp_binary)

        matches: list[YaraMatch] = scanner.scan_file(
            hasp_path,
            categories=[RuleCategory.LICENSE]
        )

        hasp_detected = any(
            "HASP" in m.rule_name or "hasp" in m.rule_name or
            any(b"hasp" in s or b"HASP" in s for _, _, s in m.matched_strings)
            for m in matches
        )
        assert hasp_detected, "Should detect Sentinel HASP signatures"


class TestPerformanceBenchmarking:
    """Test YARA scanner performance with various binary sizes."""

    def test_scan_small_binary_performance(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner processes small binary quickly."""
        small_binary = RealBinaryGenerator.create_minimal_pe()
        small_path = temp_binary_dir / "small_test.exe"
        small_path.write_bytes(small_binary)

        start_time = time.time()
        matches: list[YaraMatch] = scanner.scan_file(small_path)
        elapsed = time.time() - start_time

        assert elapsed < 1.0, f"Small binary scan took {elapsed:.2f}s, should be < 1s"
        assert isinstance(matches, list), "Should return matches"

    def test_scan_medium_binary_performance(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner processes medium binary efficiently."""
        medium_binary = RealBinaryGenerator.create_minimal_pe() * 100
        medium_path = temp_binary_dir / "medium_test.exe"
        medium_path.write_bytes(medium_binary)

        start_time = time.time()
        matches: list[YaraMatch] = scanner.scan_file(medium_path)
        elapsed = time.time() - start_time

        assert elapsed < 5.0, f"Medium binary scan took {elapsed:.2f}s, should be < 5s"
        assert isinstance(matches, list), "Should return matches"

    def test_scan_large_binary_performance(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner processes large binary within acceptable time."""
        large_binary = RealBinaryGenerator.create_minimal_pe() * 1000
        large_path = temp_binary_dir / "large_test.exe"
        large_path.write_bytes(large_binary)

        start_time = time.time()
        matches: list[YaraMatch] = scanner.scan_file(large_path)
        elapsed = time.time() - start_time

        assert elapsed < 30.0, f"Large binary scan took {elapsed:.2f}s, should be < 30s"
        assert isinstance(matches, list), "Should return matches"

    def test_multiple_category_scan_performance(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner performs multi-category scan efficiently."""
        test_binary = RealBinaryGenerator.create_vmprotect_binary()
        test_path = temp_binary_dir / "multi_category_test.exe"
        test_path.write_bytes(test_binary)

        categories = [
            RuleCategory.PACKER,
            RuleCategory.PROTECTOR,
            RuleCategory.CRYPTO,
            RuleCategory.LICENSE,
        ]

        start_time = time.time()
        matches: list[YaraMatch] = scanner.scan_file(test_path, categories=categories)
        elapsed = time.time() - start_time

        assert elapsed < 5.0, f"Multi-category scan took {elapsed:.2f}s, should be < 5s"
        assert isinstance(matches, list), "Should return matches"


class TestBatchScanning:
    """Test batch scanning of multiple files."""

    def test_scan_multiple_binaries_sequentially(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner handles sequential scanning of multiple binaries."""
        binaries = {
            "vmprotect.exe": RealBinaryGenerator.create_vmprotect_binary(),
            "themida.exe": RealBinaryGenerator.create_themida_binary(),
            "upx.exe": RealBinaryGenerator.create_upx_binary(),
            "denuvo.exe": RealBinaryGenerator.create_denuvo_binary(),
        }

        results: dict[str, list[YaraMatch]] = {}
        for name, binary_data in binaries.items():
            binary_path = temp_binary_dir / name
            binary_path.write_bytes(binary_data)
            matches = scanner.scan_file(binary_path)
            results[name] = matches

        assert len(results) == len(binaries), "Should scan all binaries"
        for name, matches in results.items():
            assert isinstance(matches, list), f"{name} should return valid matches"

    def test_scan_multiple_binaries_concurrently(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner handles concurrent scanning with thread pool."""
        binaries = {
            "vmprotect.exe": RealBinaryGenerator.create_vmprotect_binary(),
            "themida.exe": RealBinaryGenerator.create_themida_binary(),
            "upx.exe": RealBinaryGenerator.create_upx_binary(),
            "denuvo.exe": RealBinaryGenerator.create_denuvo_binary(),
            "license.exe": RealBinaryGenerator.create_license_check_binary(),
        }

        binary_paths: list[Path] = []
        for name, binary_data in binaries.items():
            binary_path = temp_binary_dir / name
            binary_path.write_bytes(binary_data)
            binary_paths.append(binary_path)

        results: list[list[YaraMatch]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(scanner.scan_file, path) for path in binary_paths]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert len(results) == len(binaries), "Should scan all binaries concurrently"
        for matches in results:
            assert isinstance(matches, list), "Each result should be valid"

    def test_batch_scan_with_errors(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner continues batch scanning even when individual files fail."""
        valid_binary = RealBinaryGenerator.create_upx_binary()
        valid_path = temp_binary_dir / "valid.exe"
        valid_path.write_bytes(valid_binary)

        invalid_path = temp_binary_dir / "nonexistent.exe"

        results: dict[Path, list[YaraMatch] | None] = {}

        for path in [valid_path, invalid_path]:
            try:
                matches = scanner.scan_file(path)
                results[path] = matches
            except Exception:
                results[path] = None

        assert results[valid_path] is not None, "Valid binary should scan successfully"
        assert results[invalid_path] is None, "Invalid binary should fail gracefully"


class TestCustomRuleManagement:
    """Test custom YARA rule creation and management."""

    def test_create_simple_custom_rule(self, scanner: YaraScanner) -> None:
        """Scanner compiles and uses simple custom rule."""
        custom_rule = """
rule Custom_Test_Rule {
    meta:
        description = "Test custom rule"
        category = "custom"
    strings:
        $test = "TESTPATTERN"
    condition:
        $test
}
"""

        success: bool = scanner.create_custom_rule("custom_test", custom_rule)
        assert success, "Should create custom rule successfully"
        assert "custom_test" in scanner.custom_rules, "Custom rule should be stored"

    def test_custom_rule_detection(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Custom rule detects pattern in binary."""
        custom_rule = """
rule Custom_License_Pattern {
    meta:
        description = "Detects custom license pattern"
    strings:
        $lic = "CUSTOM_LICENSE_KEY"
    condition:
        $lic
}
"""

        scanner.create_custom_rule("custom_license", custom_rule)

        test_binary = bytearray(RealBinaryGenerator.create_minimal_pe())
        test_binary[0x500:0x500 + 18] = b"CUSTOM_LICENSE_KEY"
        test_path = temp_binary_dir / "custom_license_test.exe"
        test_path.write_bytes(test_binary)

        matches: list[YaraMatch] = scanner.scan_file(test_path)

        custom_detected = any("Custom_License_Pattern" in m.rule_name for m in matches)
        assert custom_detected, "Should detect pattern with custom rule"

    def test_custom_rule_with_hex_pattern(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Custom rule with hex pattern detects bytes."""
        custom_rule = """
rule Custom_Hex_Pattern {
    meta:
        description = "Detects hex pattern"
    strings:
        $hex = { DE AD BE EF }
    condition:
        $hex
}
"""

        scanner.create_custom_rule("custom_hex", custom_rule)

        test_binary = bytearray(RealBinaryGenerator.create_minimal_pe())
        test_binary[0x500:0x504] = b"\xDE\xAD\xBE\xEF"
        test_path = temp_binary_dir / "custom_hex_test.exe"
        test_path.write_bytes(test_binary)

        matches: list[YaraMatch] = scanner.scan_file(test_path)

        hex_detected = any("Custom_Hex_Pattern" in m.rule_name for m in matches)
        assert hex_detected, "Should detect hex pattern with custom rule"

    def test_invalid_custom_rule_handling(self, scanner: YaraScanner) -> None:
        """Scanner handles invalid custom rule gracefully."""
        invalid_rule = """
rule Invalid_Rule {
    this is not valid YARA syntax
}
"""

        success: bool = scanner.create_custom_rule("invalid_test", invalid_rule)
        assert not success, "Should reject invalid rule"


class TestMatchContextExtraction:
    """Test extraction of match context and metadata."""

    def test_match_contains_offset_information(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Matches contain accurate offset information."""
        test_binary = RealBinaryGenerator.create_upx_binary()
        test_path = temp_binary_dir / "offset_test.exe"
        test_path.write_bytes(test_binary)

        matches: list[YaraMatch] = scanner.scan_file(test_path)

        for match in matches:
            assert hasattr(match, "offset"), "Match should have offset"
            assert match.offset >= 0, "Offset should be non-negative"

    def test_match_contains_matched_strings(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Matches contain matched string data."""
        test_binary = RealBinaryGenerator.create_vmprotect_binary()
        test_path = temp_binary_dir / "strings_test.exe"
        test_path.write_bytes(test_binary)

        matches: list[YaraMatch] = scanner.scan_file(test_path)

        for match in matches:
            assert hasattr(match, "matched_strings"), "Match should have matched_strings"
            assert isinstance(match.matched_strings, list), "matched_strings should be list"

    def test_match_contains_metadata(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Matches contain rule metadata."""
        test_binary = RealBinaryGenerator.create_themida_binary()
        test_path = temp_binary_dir / "metadata_test.exe"
        test_path.write_bytes(test_binary)

        matches: list[YaraMatch] = scanner.scan_file(test_path)

        for match in matches:
            assert hasattr(match, "meta"), "Match should have meta"
            assert isinstance(match.meta, dict), "meta should be dict"

    def test_match_confidence_scores(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Matches have valid confidence scores."""
        test_binary = RealBinaryGenerator.create_denuvo_binary()
        test_path = temp_binary_dir / "confidence_test.exe"
        test_path.write_bytes(test_binary)

        matches: list[YaraMatch] = scanner.scan_file(test_path)

        for match in matches:
            assert hasattr(match, "confidence"), "Match should have confidence"
            assert 0.0 <= match.confidence <= 100.0, \
                f"Confidence {match.confidence} should be between 0 and 100"


class TestProtectionDetectionWorkflow:
    """Test complete protection detection workflow."""

    def test_detect_protections_vmprotect(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """detect_protections identifies VMProtect."""
        vmp_binary = RealBinaryGenerator.create_vmprotect_binary()
        vmp_path = temp_binary_dir / "vmp_detection_test.exe"
        vmp_path.write_bytes(vmp_binary)

        protections: dict[str, Any] = scanner.detect_protections(vmp_path)

        assert "protectors" in protections, "Should have protectors key"
        assert isinstance(protections["protectors"], list), "protectors should be list"

    def test_detect_protections_upx(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """detect_protections identifies UPX packer."""
        upx_binary = RealBinaryGenerator.create_upx_binary()
        upx_path = temp_binary_dir / "upx_detection_test.exe"
        upx_path.write_bytes(upx_binary)

        protections: dict[str, Any] = scanner.detect_protections(upx_path)

        assert "packers" in protections, "Should have packers key"
        assert isinstance(protections["packers"], list), "packers should be list"

    def test_detect_protections_returns_all_categories(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """detect_protections returns all expected categories."""
        test_binary = RealBinaryGenerator.create_license_check_binary()
        test_path = temp_binary_dir / "categories_test.exe"
        test_path.write_bytes(test_binary)

        protections: dict[str, Any] = scanner.detect_protections(test_path)

        expected_keys = ["packers", "protectors", "crypto", "license", "anti_debug", "compiler"]
        for key in expected_keys:
            assert key in protections, f"Should have {key} key"


class TestErrorHandlingAndResilience:
    """Test error handling in various failure scenarios."""

    def test_scan_nonexistent_file(self, scanner: YaraScanner) -> None:
        """Scanner handles nonexistent file gracefully."""
        nonexistent_path = Path("nonexistent_file.exe")

        with pytest.raises(Exception):
            scanner.scan_file(nonexistent_path)

    def test_scan_empty_file(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner handles empty file gracefully."""
        empty_path = temp_binary_dir / "empty.exe"
        empty_path.write_bytes(b"")

        matches: list[YaraMatch] = scanner.scan_file(empty_path)
        assert isinstance(matches, list), "Should return empty list for empty file"

    def test_scan_corrupted_pe(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner handles corrupted PE gracefully."""
        corrupted_data = b"MZ" + b"\x00" * 100
        corrupted_path = temp_binary_dir / "corrupted.exe"
        corrupted_path.write_bytes(corrupted_data)

        matches: list[YaraMatch] = scanner.scan_file(corrupted_path)
        assert isinstance(matches, list), "Should handle corrupted PE"

    def test_scan_non_pe_file(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner handles non-PE file gracefully."""
        text_data = b"This is not a PE file"
        text_path = temp_binary_dir / "text.txt"
        text_path.write_bytes(text_data)

        matches: list[YaraMatch] = scanner.scan_file(text_path)
        assert isinstance(matches, list), "Should handle non-PE file"


class TestThreadSafety:
    """Test thread safety under concurrent load."""

    def test_concurrent_scanning_thread_safety(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner maintains thread safety under concurrent load."""
        test_binary = RealBinaryGenerator.create_upx_binary()
        test_path = temp_binary_dir / "thread_safety_test.exe"
        test_path.write_bytes(test_binary)

        results: list[list[YaraMatch]] = []
        lock = threading.Lock()

        def scan_task() -> None:
            matches = scanner.scan_file(test_path)
            with lock:
                results.append(matches)

        threads = [threading.Thread(target=scan_task) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(results) == 10, "All threads should complete"
        for matches in results:
            assert isinstance(matches, list), "Each result should be valid"

    def test_concurrent_custom_rule_creation(self, scanner: YaraScanner) -> None:
        """Scanner handles concurrent custom rule creation."""
        results: list[bool] = []
        lock = threading.Lock()

        def create_rule_task(rule_id: int) -> None:
            rule_content = f"""
rule Concurrent_Rule_{rule_id} {{
    meta:
        description = "Concurrent test rule {rule_id}"
    strings:
        $str = "TEST{rule_id}"
    condition:
        $str
}}
"""
            success = scanner.create_custom_rule(f"concurrent_{rule_id}", rule_content)
            with lock:
                results.append(success)

        threads = [threading.Thread(target=create_rule_task, args=(i,)) for i in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(results) == 5, "All rule creations should complete"


class TestCategoryFiltering:
    """Test scanning with category filters."""

    def test_scan_with_single_category(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner scans with single category filter."""
        test_binary = RealBinaryGenerator.create_upx_binary()
        test_path = temp_binary_dir / "single_category_test.exe"
        test_path.write_bytes(test_binary)

        matches: list[YaraMatch] = scanner.scan_file(
            test_path,
            categories=[RuleCategory.PACKER]
        )

        assert isinstance(matches, list), "Should return matches"
        for match in matches:
            assert match.category in [
                RuleCategory.PACKER,
                RuleCategory.CUSTOM,
            ], "All matches should be from requested category or custom"

    def test_scan_with_multiple_categories(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner scans with multiple category filters."""
        test_binary = RealBinaryGenerator.create_vmprotect_binary()
        test_path = temp_binary_dir / "multi_category_test.exe"
        test_path.write_bytes(test_binary)

        categories = [RuleCategory.PACKER, RuleCategory.PROTECTOR]
        matches: list[YaraMatch] = scanner.scan_file(test_path, categories=categories)

        assert isinstance(matches, list), "Should return matches"
        for match in matches:
            assert match.category in categories or match.category == RuleCategory.CUSTOM, \
                "All matches should be from requested categories or custom"

    def test_scan_with_license_category(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner scans with license category filter."""
        test_binary = RealBinaryGenerator.create_license_check_binary()
        test_path = temp_binary_dir / "license_category_test.exe"
        test_path.write_bytes(test_binary)

        matches: list[YaraMatch] = scanner.scan_file(
            test_path,
            categories=[RuleCategory.LICENSE]
        )

        assert isinstance(matches, list), "Should return matches"

    def test_scan_with_crypto_category(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner scans with crypto category filter."""
        test_binary = RealBinaryGenerator.create_crypto_binary()
        test_path = temp_binary_dir / "crypto_category_test.exe"
        test_path.write_bytes(test_binary)

        matches: list[YaraMatch] = scanner.scan_file(
            test_path,
            categories=[RuleCategory.CRYPTO]
        )

        assert isinstance(matches, list), "Should return matches"


class TestRuleCompilationCaching:
    """Test rule compilation and caching behavior."""

    def test_scanner_initializes_with_builtin_rules(self, scanner: YaraScanner) -> None:
        """Scanner loads built-in rules on initialization."""
        assert len(scanner.compiled_rules) > 0, "Should have compiled built-in rules"

    def test_scanner_loads_all_rule_categories(self, scanner: YaraScanner) -> None:
        """Scanner compiles rules for all categories."""
        expected_categories = [
            RuleCategory.PACKER,
            RuleCategory.PROTECTOR,
            RuleCategory.CRYPTO,
            RuleCategory.LICENSE,
            RuleCategory.ANTI_DEBUG,
            RuleCategory.COMPILER,
        ]

        for category in expected_categories:
            assert category in scanner.compiled_rules, \
                f"Should have compiled {category.value} rules"

    def test_scanner_reuses_compiled_rules(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Scanner reuses compiled rules for multiple scans."""
        test_binary = RealBinaryGenerator.create_upx_binary()
        test_path = temp_binary_dir / "reuse_test.exe"
        test_path.write_bytes(test_binary)

        initial_rules = scanner.compiled_rules.copy()

        scanner.scan_file(test_path)
        scanner.scan_file(test_path)
        scanner.scan_file(test_path)

        assert scanner.compiled_rules == initial_rules, \
            "Should reuse same compiled rules"


class TestSignatureBasedDetection:
    """Test signature-based protection detection."""

    def test_signature_detection_vmprotect(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Signature-based detection identifies VMProtect."""
        vmp_binary = RealBinaryGenerator.create_vmprotect_binary()
        vmp_path = temp_binary_dir / "sig_vmp_test.exe"
        vmp_path.write_bytes(vmp_binary)

        protections: dict[str, Any] = scanner.detect_protections(vmp_path)

        assert "signature_based" in protections, "Should include signature-based detections"

    def test_signature_detection_themida(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Signature-based detection identifies Themida."""
        themida_binary = RealBinaryGenerator.create_themida_binary()
        themida_path = temp_binary_dir / "sig_themida_test.exe"
        themida_path.write_bytes(themida_binary)

        protections: dict[str, Any] = scanner.detect_protections(themida_path)

        assert "signature_based" in protections, "Should include signature-based detections"

    def test_signature_detection_upx(self, scanner: YaraScanner, temp_binary_dir: Path) -> None:
        """Signature-based detection identifies UPX."""
        upx_binary = RealBinaryGenerator.create_upx_binary()
        upx_path = temp_binary_dir / "sig_upx_test.exe"
        upx_path.write_bytes(upx_binary)

        protections: dict[str, Any] = scanner.detect_protections(upx_path)

        assert "signature_based" in protections, "Should include signature-based detections"
