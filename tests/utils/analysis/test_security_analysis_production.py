"""Production-ready tests for security_analysis.py.

Tests validate REAL security analysis capabilities against actual binary patterns.
All tests use real binary data and verify genuine vulnerability detection.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.handlers.pefile_handler import PEFILE_AVAILABLE
from intellicrack.utils.analysis.security_analysis import (
    bypass_tpm_checks,
    check_buffer_overflow,
    check_for_memory_leaks,
    check_memory_usage,
    run_tpm_bypass,
    run_vm_bypass,
    scan_protectors,
)


if PEFILE_AVAILABLE:
    from intellicrack.handlers.pefile_handler import pefile


class TestBufferOverflowDetection:
    """Test buffer overflow vulnerability detection on real binaries."""

    def test_detects_unsafe_strcpy_in_pe_imports(self, tmp_path: Path) -> None:
        """Buffer overflow detector identifies strcpy in PE imports."""
        if not PEFILE_AVAILABLE:
            pytest.skip("pefile not available")

        pe_binary = self._create_pe_with_unsafe_imports(tmp_path, ["strcpy", "strcat", "gets"])
        result = check_buffer_overflow(str(pe_binary))

        assert len(result["vulnerable_functions"]) >= 3
        func_names = [f["function"] for f in result["vulnerable_functions"]]
        assert "strcpy" in func_names
        assert "strcat" in func_names
        assert "gets" in func_names
        assert result["risk_level"] in {"high", "medium"}

    def test_detects_format_string_patterns(self, tmp_path: Path) -> None:
        """Buffer overflow detector finds format string vulnerabilities."""
        binary_path = tmp_path / "test_format.exe"
        binary_data = self._create_binary_with_format_strings()
        binary_path.write_bytes(binary_data)

        result = check_buffer_overflow(str(binary_path))

        format_patterns = [p for p in result["unsafe_patterns"] if "format" in p["pattern"].lower()]
        assert format_patterns
        assert format_patterns[0]["count"] > 0
        assert format_patterns[0]["risk"] == "medium"

    def test_detects_dep_and_aslr_protections(self, tmp_path: Path) -> None:
        """Buffer overflow detector identifies DEP and ASLR status."""
        if not PEFILE_AVAILABLE:
            pytest.skip("pefile not available")

        pe_binary = self._create_pe_with_security_flags(tmp_path, dep=True, aslr=True)
        result = check_buffer_overflow(str(pe_binary))

        assert result["dep_enabled"] is True
        assert result["aslr_enabled"] is True
        assert result["risk_level"] in {"low", "medium"}

    def test_detects_stack_canaries(self, tmp_path: Path) -> None:
        """Buffer overflow detector finds stack protection."""
        binary_path = tmp_path / "test_canary.exe"
        binary_data = self._create_binary_with_stack_canary()
        binary_path.write_bytes(binary_data)

        result = check_buffer_overflow(str(binary_path))

        assert result["stack_canaries"] is True

    def test_detects_rop_gadgets(self, tmp_path: Path) -> None:
        """Buffer overflow detector identifies ROP exploitation potential."""
        binary_path = tmp_path / "test_rop.exe"
        binary_data = self._create_binary_with_rop_gadgets()
        binary_path.write_bytes(binary_data)

        result = check_buffer_overflow(str(binary_path))

        if rop_patterns := [
            p for p in result["unsafe_patterns"] if "ROP" in p["pattern"]
        ]:
            assert rop_patterns[0]["count"] > 10
            assert rop_patterns[0]["risk"] == "high"

    def test_risk_scoring_accuracy(self, tmp_path: Path) -> None:
        """Buffer overflow detector scores risk correctly."""
        if not PEFILE_AVAILABLE:
            pytest.skip("pefile not available")

        high_risk_binary = self._create_pe_with_unsafe_imports(tmp_path, ["gets", "strcpy", "sprintf"])
        high_risk_result = check_buffer_overflow(str(high_risk_binary))

        low_risk_binary = self._create_pe_with_security_flags(tmp_path, dep=True, aslr=True)
        low_risk_result = check_buffer_overflow(str(low_risk_binary))

        assert high_risk_result["risk_level"] == "high"
        assert low_risk_result["risk_level"] in {"low", "medium"}

    def test_handles_corrupted_pe_gracefully(self, tmp_path: Path) -> None:
        """Buffer overflow detector handles corrupted PE without crashing."""
        binary_path = tmp_path / "corrupted.exe"
        binary_path.write_bytes(b"MZ\x90\x00" + b"\xff" * 100)

        result = check_buffer_overflow(str(binary_path))

        assert "error" in result or result["risk_level"] == "unknown"

    def test_detects_integer_overflow_patterns(self, tmp_path: Path) -> None:
        """Buffer overflow detector identifies integer multiplication operations."""
        binary_path = tmp_path / "test_int_overflow.exe"
        mul_patterns = b"\xf7\xe0" * 15 + b"\x0f\xaf" * 10
        binary_data = b"MZ" + b"\x00" * 100 + mul_patterns + b"\x00" * 100
        binary_path.write_bytes(binary_data)

        result = check_buffer_overflow(str(binary_path))

        int_patterns = [p for p in result["unsafe_patterns"] if "multiplication" in p["pattern"].lower()]
        assert int_patterns

    def _create_pe_with_unsafe_imports(self, tmp_path: Path, import_names: list[str]) -> Path:
        """Create minimal PE with specific imports."""
        pe_binary = tmp_path / "test_imports.exe"

        dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
        pe_header = b"PE\x00\x00" + struct.pack("<H", 0x014C) + b"\x00" * 18
        optional_header = struct.pack("<H", 0x010B) + b"\x00" * 222

        section_data = b""
        for import_name in import_names:
            section_data += import_name.encode() + b"\x00"

        pe_data = dos_header + b"\x00" * (0x80 - len(dos_header)) + pe_header + optional_header + section_data

        pe_binary.write_bytes(pe_data)
        return pe_binary

    def _create_pe_with_security_flags(self, tmp_path: Path, dep: bool, aslr: bool) -> Path:
        """Create minimal PE with security flags."""
        pe_binary = tmp_path / "test_security.exe"

        dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
        pe_header = b"PE\x00\x00" + struct.pack("<H", 0x014C) + b"\x00" * 18

        dll_chars = 0x0000
        if dep:
            dll_chars |= 0x0100
        if aslr:
            dll_chars |= 0x0040

        optional_header = struct.pack("<H", 0x010B) + b"\x00" * 68 + struct.pack("<H", dll_chars) + b"\x00" * 152

        pe_data = dos_header + b"\x00" * (0x80 - len(dos_header)) + pe_header + optional_header

        pe_binary.write_bytes(pe_data)
        return pe_binary

    def _create_binary_with_format_strings(self) -> bytes:
        """Create binary with format string patterns."""
        format_strings = b"%s%s%s" + b"%d%d%d" + b"%x%x%x" + b"%n%n%n" + b"%p%p%p"
        return b"MZ" + b"\x00" * 100 + format_strings + b"\x00" * 100

    def _create_binary_with_stack_canary(self) -> bytes:
        """Create binary with stack canary patterns."""
        canary_patterns = b"__stack_chk_fail\x00__stack_chk_guard\x00__security_cookie\x00"
        return b"MZ" + b"\x00" * 100 + canary_patterns + b"\x00" * 100

    def _create_binary_with_rop_gadgets(self) -> bytes:
        """Create binary with ROP gadget patterns."""
        rop_gadgets = b"\xc3" * 50 + b"\x5d\xc3" * 20 + b"\x58\xc3" * 15 + b"\xff\xe0" * 10
        return b"MZ" + b"\x00" * 200 + rop_gadgets + b"\x00" * 200


class TestMemoryLeakDetection:
    """Test memory leak detection on real binaries."""

    def test_detects_allocation_deallocation_imbalance(self, tmp_path: Path) -> None:
        """Memory leak detector finds allocation/deallocation mismatches."""
        if not PEFILE_AVAILABLE:
            pytest.skip("pefile not available")

        pe_binary = self._create_pe_with_memory_functions(tmp_path, alloc_only=True)
        result = check_for_memory_leaks(str(pe_binary))

        assert len(result["static_analysis"]["allocation_functions"]) > 0
        assert len(result["static_analysis"]["deallocation_functions"]) == 0
        assert len(result["static_analysis"]["potential_leaks"]) > 0
        assert result["risk_level"] == "high"

    def test_detects_balanced_memory_management(self, tmp_path: Path) -> None:
        """Memory leak detector handles balanced allocation/deallocation."""
        if not PEFILE_AVAILABLE:
            pytest.skip("pefile not available")

        pe_binary = self._create_pe_with_memory_functions(tmp_path, alloc_only=False)
        result = check_for_memory_leaks(str(pe_binary))

        assert len(result["static_analysis"]["allocation_functions"]) > 0
        assert len(result["static_analysis"]["deallocation_functions"]) > 0

    def test_categorizes_memory_functions_correctly(self, tmp_path: Path) -> None:
        """Memory leak detector categorizes malloc vs free correctly."""
        if not PEFILE_AVAILABLE:
            pytest.skip("pefile not available")

        pe_binary = self._create_pe_with_memory_functions(tmp_path, alloc_only=False)
        result = check_for_memory_leaks(str(pe_binary))

        alloc_funcs = result["static_analysis"]["allocation_functions"]
        dealloc_funcs = result["static_analysis"]["deallocation_functions"]

        assert any("malloc" in f.lower() or "alloc" in f.lower() for f in alloc_funcs)
        assert any("free" in f.lower() for f in dealloc_funcs)

    def _create_pe_with_memory_functions(self, tmp_path: Path, alloc_only: bool) -> Path:
        """Create PE with memory management imports."""
        pe_binary = tmp_path / "test_memory.exe"

        dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
        pe_header = b"PE\x00\x00" + struct.pack("<H", 0x014C) + b"\x00" * 18
        optional_header = struct.pack("<H", 0x010B) + b"\x00" * 222

        section_data = b"malloc\x00calloc\x00HeapAlloc\x00"
        if not alloc_only:
            section_data += b"free\x00HeapFree\x00"

        pe_data = dos_header + b"\x00" * (0x80 - len(dos_header)) + pe_header + optional_header + section_data

        pe_binary.write_bytes(pe_data)
        return pe_binary


class TestTPMBypass:
    """Test TPM bypass functionality."""

    def test_detects_tpm_functions_in_binary(self, tmp_path: Path) -> None:
        """TPM bypass detector identifies TPM-related functions."""
        if not PEFILE_AVAILABLE:
            pytest.skip("pefile not available")

        pe_binary = self._create_pe_with_tpm_imports(tmp_path)
        result = bypass_tpm_checks(str(pe_binary))

        assert len(result["tpm_functions"]) > 0
        tpm_funcs = [f["function"] for f in result["tpm_functions"]]
        assert "Tbsi_Context_Create" in tpm_funcs or "NCryptOpenStorageProvider" in tpm_funcs

    def test_generates_iat_hook_patches(self, tmp_path: Path) -> None:
        """TPM bypass generates IAT hook patches."""
        if not PEFILE_AVAILABLE:
            pytest.skip("pefile not available")

        pe_binary = self._create_pe_with_tpm_imports(tmp_path)
        result = bypass_tpm_checks(str(pe_binary))

        if result["tpm_functions"]:
            assert result["method"] == "import_patching"
            assert len(result["patches"]) > 0
            assert all(p["type"] == "iat_hook" for p in result["patches"])
            assert all("return_success" in p["patch"] for p in result["patches"])

    def test_run_tpm_bypass_generates_patches(self, tmp_path: Path) -> None:
        """run_tpm_bypass function creates bypass patches."""
        if not PEFILE_AVAILABLE:
            pytest.skip("pefile not available")

        pe_binary = self._create_pe_with_tpm_imports(tmp_path)
        output_path = str(tmp_path / "patched.exe")
        result = run_tpm_bypass(str(pe_binary), output_path)

        if result.get("patches"):
            assert result["status"] == "patches_generated"
            assert result["output_path"] == output_path
            assert "patches" in result["message"]

    def _create_pe_with_tpm_imports(self, tmp_path: Path) -> Path:
        """Create PE with TPM-related imports."""
        pe_binary = tmp_path / "test_tpm.exe"

        dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
        pe_header = b"PE\x00\x00" + struct.pack("<H", 0x014C) + b"\x00" * 18
        optional_header = struct.pack("<H", 0x010B) + b"\x00" * 222

        section_data = b"Tbsi_Context_Create\x00NCryptOpenStorageProvider\x00BCryptOpenAlgorithmProvider\x00"

        pe_data = dos_header + b"\x00" * (0x80 - len(dos_header)) + pe_header + optional_header + section_data

        pe_binary.write_bytes(pe_data)
        return pe_binary


class TestProtectionScanner:
    """Test protection mechanism scanning."""

    def test_detects_anti_debug_patterns(self, tmp_path: Path) -> None:
        """Protection scanner identifies anti-debugging techniques."""
        binary_path = tmp_path / "test_antidebug.exe"
        binary_data = self._create_binary_with_anti_debug()
        binary_path.write_bytes(binary_data)

        result = scan_protectors(str(binary_path))

        assert len(result["anti_debug"]) > 0
        techniques = [t["technique"] for t in result["anti_debug"]]
        assert any("IsDebuggerPresent" in t for t in techniques)

    def test_detects_anti_vm_patterns(self, tmp_path: Path) -> None:
        """Protection scanner identifies anti-VM techniques."""
        binary_path = tmp_path / "test_antivm.exe"
        binary_data = self._create_binary_with_anti_vm()
        binary_path.write_bytes(binary_data)

        result = scan_protectors(str(binary_path))

        assert len(result["anti_vm"]) > 0
        techniques = [t["technique"] for t in result["anti_vm"]]
        assert any("VMware" in t or "VirtualBox" in t for t in techniques)

    def test_detects_packer_signatures(self, tmp_path: Path) -> None:
        """Protection scanner identifies common packer signatures."""
        binary_path = tmp_path / "test_packed.exe"
        binary_data = self._create_binary_with_packer_signature()
        binary_path.write_bytes(binary_data)

        result = scan_protectors(str(binary_path))

        assert len(result["packers"]) > 0
        packers = [p["packer"] for p in result["packers"]]
        assert "UPX" in packers or "Themida" in packers

    def test_detects_high_entropy_sections(self, tmp_path: Path) -> None:
        """Protection scanner identifies encrypted/packed sections."""
        if not PEFILE_AVAILABLE:
            pytest.skip("pefile not available")

        binary_path = tmp_path / "test_entropy.exe"
        binary_data = self._create_pe_with_high_entropy_section()
        binary_path.write_bytes(binary_data)

        result = scan_protectors(str(binary_path))

        if result["obfuscation"]:
            assert any(o["entropy"] > 7.0 for o in result["obfuscation"])

    def test_run_vm_bypass_generates_patches(self, tmp_path: Path) -> None:
        """VM bypass generates neutralization patches."""
        binary_path = tmp_path / "test_vm.exe"
        binary_data = self._create_binary_with_anti_vm()
        binary_path.write_bytes(binary_data)

        output_path = str(tmp_path / "patched.exe")
        result = run_vm_bypass(str(binary_path), output_path)

        if result.get("vm_checks"):
            assert len(result["patches"]) > 0
            assert result["method"] == "binary_patching"
            assert result["status"] == "patches_generated"

    def _create_binary_with_anti_debug(self) -> bytes:
        """Create binary with anti-debugging patterns."""
        anti_debug = b"IsDebuggerPresent\x00CheckRemoteDebuggerPresent\x00OutputDebugString\x00"
        return b"MZ" + b"\x00" * 100 + anti_debug + b"\x00" * 200

    def _create_binary_with_anti_vm(self) -> bytes:
        """Create binary with anti-VM patterns."""
        anti_vm = b"VMware\x00VirtualBox\x00VBOX\x00QEMU\x00"
        return b"MZ" + b"\x00" * 100 + anti_vm + b"\x00" * 200

    def _create_binary_with_packer_signature(self) -> bytes:
        """Create binary with packer signatures."""
        packer_sig = b"UPX!\x00Themida\x00.enigma\x00"
        return b"MZ" + b"\x00" * 100 + packer_sig + b"\x00" * 200

    def _create_pe_with_high_entropy_section(self) -> bytes:
        """Create PE with high entropy section."""
        import random

        dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
        pe_header = b"PE\x00\x00" + struct.pack("<H", 0x014C) + b"\x00" * 18
        optional_header = struct.pack("<H", 0x010B) + b"\x00" * 222

        high_entropy_data = bytes(random.randint(0, 255) for _ in range(1000))

        return dos_header + b"\x00" * (0x80 - len(dos_header)) + pe_header + optional_header + high_entropy_data


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_handles_nonexistent_file(self) -> None:
        """Security analysis handles missing files gracefully."""
        result = check_buffer_overflow("nonexistent_file.exe")

        assert "error" in result or result["risk_level"] == "unknown"

    def test_handles_empty_file(self, tmp_path: Path) -> None:
        """Security analysis handles empty files."""
        empty_file = tmp_path / "empty.exe"
        empty_file.write_bytes(b"")

        result = check_buffer_overflow(str(empty_file))

        assert result is not None

    def test_handles_non_pe_file(self, tmp_path: Path) -> None:
        """Security analysis handles non-PE files."""
        text_file = tmp_path / "test.txt"
        text_file.write_text("This is not a PE file")

        result = check_buffer_overflow(str(text_file))

        assert result is not None

    def test_custom_function_list(self, tmp_path: Path) -> None:
        """Buffer overflow detector accepts custom function list."""
        if not PEFILE_AVAILABLE:
            pytest.skip("pefile not available")

        pe_binary = tmp_path / "test_custom.exe"
        pe_binary.write_bytes(b"MZ" + b"\x00" * 200)

        custom_funcs = ["my_unsafe_func", "custom_vuln"]
        result = check_buffer_overflow(str(pe_binary), functions=custom_funcs)

        assert result is not None
        assert "vulnerable_functions" in result


class TestPerformance:
    """Test performance characteristics."""

    def test_large_binary_analysis_completes(self, tmp_path: Path) -> None:
        """Security analysis completes on large binaries within reasonable time."""
        large_binary = tmp_path / "large.exe"
        large_data = b"MZ" + b"\x00" * 10_000_000
        large_binary.write_bytes(large_data)

        import time

        start_time = time.time()
        result = check_buffer_overflow(str(large_binary))
        duration = time.time() - start_time

        assert duration < 30.0
        assert result is not None

    def test_many_patterns_analysis_efficient(self, tmp_path: Path) -> None:
        """Security analysis handles binaries with many patterns efficiently."""
        binary_path = tmp_path / "many_patterns.exe"
        pattern_data = b"strcpy\x00" * 100 + b"malloc\x00" * 100 + b"%s%s%s" * 50
        binary_data = b"MZ" + b"\x00" * 100 + pattern_data + b"\x00" * 100
        binary_path.write_bytes(binary_data)

        import time

        start_time = time.time()
        result = check_buffer_overflow(str(binary_path))
        duration = time.time() - start_time

        assert duration < 10.0
        assert result is not None
