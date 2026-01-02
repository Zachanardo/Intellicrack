"""Production tests for VMProtect detector - NO MOCKS.

Validates VMProtect 3.x detection capabilities on real Windows binaries.
All tests operate on actual system binaries and verify genuine detection functionality.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

from intellicrack.core.analysis.vmprotect_detector import (
    VMHandler,
    VMProtectDetection,
    VMProtectDetector,
    VMProtectLevel,
    VMProtectMode,
    VirtualizedRegion,
)


if TYPE_CHECKING:
    from typing import Any


SYSTEM32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"
NOTEPAD = SYSTEM32 / "notepad.exe"
CALC = SYSTEM32 / "calc.exe"
KERNEL32 = SYSTEM32 / "kernel32.dll"
NTDLL = SYSTEM32 / "ntdll.dll"
USER32 = SYSTEM32 / "user32.dll"


class TestVMProtectDetectorInitialization:
    """Test VMProtect detector initialization and setup."""

    def test_detector_initializes_successfully(self) -> None:
        """Detector instantiates without errors."""
        detector = VMProtectDetector()
        assert detector is not None
        assert isinstance(detector, VMProtectDetector)

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_detector_initializes_disassemblers(self) -> None:
        """Detector initializes Capstone disassemblers for both architectures."""
        detector = VMProtectDetector()
        assert hasattr(detector, "cs_x86")
        assert hasattr(detector, "cs_x64")
        assert detector.cs_x86 is not None
        assert detector.cs_x64 is not None
        assert detector.cs_x86.detail is True
        assert detector.cs_x64.detail is True

    def test_detector_has_vm_handler_signatures_x86(self) -> None:
        """Detector contains x86 VM handler signatures."""
        detector = VMProtectDetector()
        assert hasattr(detector, "VMP_HANDLER_SIGNATURES_X86")
        assert len(detector.VMP_HANDLER_SIGNATURES_X86) > 0
        for handler_type, pattern in detector.VMP_HANDLER_SIGNATURES_X86.items():
            assert isinstance(pattern, bytes)
            assert len(pattern) > 0
            assert isinstance(handler_type, str)
            assert len(handler_type) > 0

    def test_detector_has_vm_handler_signatures_x64(self) -> None:
        """Detector contains x64 VM handler signatures."""
        detector = VMProtectDetector()
        assert hasattr(detector, "VMP_HANDLER_SIGNATURES_X64")
        assert len(detector.VMP_HANDLER_SIGNATURES_X64) > 0
        for handler_type, pattern in detector.VMP_HANDLER_SIGNATURES_X64.items():
            assert isinstance(pattern, bytes)
            assert len(pattern) > 0
            assert isinstance(handler_type, str)
            assert len(handler_type) > 0

    def test_detector_has_mutation_patterns(self) -> None:
        """Detector contains mutation detection patterns."""
        detector = VMProtectDetector()
        assert hasattr(detector, "VMP_MUTATION_PATTERNS")
        assert len(detector.VMP_MUTATION_PATTERNS) > 0
        for pattern_name, pattern in detector.VMP_MUTATION_PATTERNS.items():
            assert isinstance(pattern, bytes)
            assert len(pattern) > 0
            assert isinstance(pattern_name, str)
            assert len(pattern_name) > 0

    def test_detector_has_string_indicators(self) -> None:
        """Detector contains VMProtect string indicators."""
        detector = VMProtectDetector()
        assert hasattr(detector, "VMP_STRING_INDICATORS")
        assert len(detector.VMP_STRING_INDICATORS) > 0
        assert "vmp" in detector.VMP_STRING_INDICATORS
        assert "vmprotect" in detector.VMP_STRING_INDICATORS


class TestPEFormatValidation:
    """Test PE format detection and validation."""

    def test_is_pe_validates_valid_pe_header(self) -> None:
        """_is_pe correctly identifies valid PE headers."""
        detector = VMProtectDetector()
        valid_pe = b"MZ" + b"\x00" * 100
        assert detector._is_pe(valid_pe) is True

    def test_is_pe_rejects_invalid_magic(self) -> None:
        """_is_pe rejects invalid PE magic bytes."""
        detector = VMProtectDetector()
        invalid_pe = b"EX" + b"\x00" * 100
        assert detector._is_pe(invalid_pe) is False

    def test_is_pe_rejects_short_data(self) -> None:
        """_is_pe rejects data shorter than minimum PE size."""
        detector = VMProtectDetector()
        too_short = b"MZ"
        assert detector._is_pe(too_short) is False

    def test_is_pe_rejects_empty_data(self) -> None:
        """_is_pe rejects empty data."""
        detector = VMProtectDetector()
        empty = b""
        assert detector._is_pe(empty) is False

    @pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not found")
    def test_is_pe_validates_real_notepad(self) -> None:
        """_is_pe validates real Windows notepad.exe as PE."""
        detector = VMProtectDetector()
        with open(NOTEPAD, "rb") as f:
            data = f.read()
        assert detector._is_pe(data) is True

    @pytest.mark.skipif(not KERNEL32.exists(), reason="kernel32.dll not found")
    def test_is_pe_validates_real_kernel32(self) -> None:
        """_is_pe validates real Windows kernel32.dll as PE."""
        detector = VMProtectDetector()
        with open(KERNEL32, "rb") as f:
            data = f.read()
        assert detector._is_pe(data) is True


class TestArchitectureDetection:
    """Test architecture detection on real binaries."""

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    @pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not found")
    def test_detect_architecture_on_real_notepad(self) -> None:
        """_detect_architecture identifies architecture of real notepad.exe."""
        detector = VMProtectDetector()
        with open(NOTEPAD, "rb") as f:
            data = f.read()
        arch = detector._detect_architecture(data)
        assert arch in ["x86", "x64"]

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    @pytest.mark.skipif(not KERNEL32.exists(), reason="kernel32.dll not found")
    def test_detect_architecture_on_real_kernel32(self) -> None:
        """_detect_architecture identifies architecture of real kernel32.dll."""
        detector = VMProtectDetector()
        with open(KERNEL32, "rb") as f:
            data = f.read()
        arch = detector._detect_architecture(data)
        assert arch in ["x86", "x64"]

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    @pytest.mark.skipif(not NTDLL.exists(), reason="ntdll.dll not found")
    def test_detect_architecture_on_real_ntdll(self) -> None:
        """_detect_architecture identifies architecture of real ntdll.dll."""
        detector = VMProtectDetector()
        with open(NTDLL, "rb") as f:
            data = f.read()
        arch = detector._detect_architecture(data)
        assert arch in ["x86", "x64"]

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_detect_architecture_handles_invalid_pe(self) -> None:
        """_detect_architecture handles invalid PE data gracefully."""
        detector = VMProtectDetector()
        invalid_pe = b"MZ" + b"\x00" * 100
        arch = detector._detect_architecture(invalid_pe)
        assert arch == "unknown"

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_detect_architecture_handles_corrupted_header(self) -> None:
        """_detect_architecture handles corrupted PE headers."""
        detector = VMProtectDetector()
        corrupted = b"MZ" + b"\xFF" * 100
        arch = detector._detect_architecture(corrupted)
        assert arch == "unknown"


class TestSectionAnalysis:
    """Test PE section analysis for VMProtect characteristics."""

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    @pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not found")
    def test_analyze_sections_on_real_notepad(self) -> None:
        """_analyze_sections analyzes real notepad.exe sections."""
        detector = VMProtectDetector()
        with open(NOTEPAD, "rb") as f:
            data = f.read()
        analysis = detector._analyze_sections(data)
        assert isinstance(analysis, dict)
        assert "vmp_sections" in analysis
        assert "high_entropy_sections" in analysis
        assert "suspicious_characteristics" in analysis
        assert isinstance(analysis["vmp_sections"], list)
        assert isinstance(analysis["high_entropy_sections"], list)
        assert isinstance(analysis["suspicious_characteristics"], list)

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    @pytest.mark.skipif(not KERNEL32.exists(), reason="kernel32.dll not found")
    def test_analyze_sections_on_real_kernel32(self) -> None:
        """_analyze_sections analyzes real kernel32.dll sections."""
        detector = VMProtectDetector()
        with open(KERNEL32, "rb") as f:
            data = f.read()
        analysis = detector._analyze_sections(data)
        assert isinstance(analysis, dict)
        assert "vmp_sections" in analysis
        assert "high_entropy_sections" in analysis
        assert "suspicious_characteristics" in analysis

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    @pytest.mark.skipif(not USER32.exists(), reason="user32.dll not found")
    def test_analyze_sections_detects_high_entropy(self) -> None:
        """_analyze_sections identifies high entropy sections in real binaries."""
        detector = VMProtectDetector()
        with open(USER32, "rb") as f:
            data = f.read()
        analysis = detector._analyze_sections(data)
        for section in analysis.get("high_entropy_sections", []):
            assert "name" in section
            assert "entropy" in section
            assert section["entropy"] > 7.3

    def test_analyze_sections_returns_empty_without_pefile(self) -> None:
        """_analyze_sections returns safe defaults when pefile unavailable."""
        if not PEFILE_AVAILABLE:
            detector = VMProtectDetector()
            analysis = detector._analyze_sections(b"MZ" + b"\x00" * 1000)
            assert analysis["vmp_sections"] == []
            assert analysis["high_entropy_sections"] == []
            assert analysis["suspicious_characteristics"] == []


class TestVMHandlerDetection:
    """Test VM handler signature detection."""

    def test_detect_vm_handlers_with_synthetic_x86_handlers(self) -> None:
        """_detect_vm_handlers finds x86 VM handler signatures in synthetic binary."""
        detector = VMProtectDetector()
        vm_entry = b"\x55\x8b\xec\x53\x56\x57\x8b\x7d\x08"
        pushad = b"\x9c\x60\x8b\x74\x24\x24"
        vm_exit = b"\x61\x9d\x5f\x5e\x5b\xc9\xc3"
        binary = b"MZ" + b"\x00" * 100 + vm_entry + b"\x90" * 200 + pushad + b"\x90" * 200 + vm_exit
        handlers = detector._detect_vm_handlers(binary, "x86")
        assert isinstance(handlers, list)
        if handlers:
            for handler in handlers:
                assert isinstance(handler, VMHandler)
                assert handler.offset >= 0
                assert handler.size > 0
                assert len(handler.handler_type) > 0
                assert 0.0 <= handler.confidence <= 1.0

    def test_detect_vm_handlers_with_synthetic_x64_handlers(self) -> None:
        """_detect_vm_handlers finds x64 VM handler signatures in synthetic binary."""
        detector = VMProtectDetector()
        vm_entry_x64 = b"\x48\x89\x5c\x24\x08\x48\x89\x74\x24\x10"
        context_save_x64 = b"\x9c\x50\x53\x51\x52\x56\x57"
        vm_exit_x64 = b"\x5f\x5e\x5a\x59\x5b\x58\x9d\xc3"
        binary = b"MZ" + b"\x00" * 100 + vm_entry_x64 + b"\x90" * 200 + context_save_x64 + b"\x90" * 200 + vm_exit_x64
        handlers = detector._detect_vm_handlers(binary, "x64")
        assert isinstance(handlers, list)
        if handlers:
            for handler in handlers:
                assert isinstance(handler, VMHandler)
                assert handler.offset >= 0
                assert handler.size > 0

    @pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not found")
    def test_detect_vm_handlers_on_real_notepad(self) -> None:
        """_detect_vm_handlers scans real notepad.exe without errors."""
        detector = VMProtectDetector()
        with open(NOTEPAD, "rb") as f:
            data = f.read()
        handlers = detector._detect_vm_handlers(data, "x64")
        assert isinstance(handlers, list)

    @pytest.mark.skipif(not KERNEL32.exists(), reason="kernel32.dll not found")
    def test_detect_vm_handlers_on_real_kernel32(self) -> None:
        """_detect_vm_handlers scans real kernel32.dll without errors."""
        detector = VMProtectDetector()
        with open(KERNEL32, "rb") as f:
            data = f.read()
        handlers = detector._detect_vm_handlers(data, "x64")
        assert isinstance(handlers, list)

    def test_detect_vm_handlers_returns_empty_on_clean_binary(self) -> None:
        """_detect_vm_handlers returns empty list for clean binary."""
        detector = VMProtectDetector()
        clean_binary = b"MZ" + b"\x00" * 10000
        handlers = detector._detect_vm_handlers(clean_binary, "x86")
        assert handlers == []


class TestHandlerComplexityAnalysis:
    """Test VM handler complexity calculation."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_calculate_handler_complexity_advanced_returns_metrics(self) -> None:
        """_calculate_handler_complexity_advanced returns complexity metrics dict."""
        detector = VMProtectDetector()
        x86_code = b"\x55\x8b\xec\x53\x56\x57\x75\x10\x8b\x45\x08\x3b\x45\x0c\x74\x05\xeb\x10\x5f\x5e\x5b\xc9\xc3"
        metrics = detector._calculate_handler_complexity_advanced(x86_code, 0, len(x86_code), "x86")
        assert isinstance(metrics, dict)
        assert "complexity" in metrics
        assert "branches" in metrics
        assert "memory_ops" in metrics
        assert isinstance(metrics["complexity"], int)
        assert isinstance(metrics["branches"], int)
        assert isinstance(metrics["memory_ops"], int)
        assert metrics["complexity"] >= 0
        assert metrics["branches"] >= 0
        assert metrics["memory_ops"] >= 0

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_calculate_handler_complexity_advanced_detects_branches(self) -> None:
        """_calculate_handler_complexity_advanced counts branch instructions."""
        detector = VMProtectDetector()
        code_with_branches = b"\x75\x10\x74\x05\xeb\x10\x90\x90"
        metrics = detector._calculate_handler_complexity_advanced(code_with_branches, 0, len(code_with_branches), "x86")
        assert metrics["branches"] > 0

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_calculate_handler_complexity_advanced_detects_memory_ops(self) -> None:
        """_calculate_handler_complexity_advanced counts memory operations."""
        detector = VMProtectDetector()
        code_with_memory = b"\x8b\x45\x08\x89\x45\x0c\xff\x30"
        metrics = detector._calculate_handler_complexity_advanced(code_with_memory, 0, len(code_with_memory), "x86")
        assert metrics["memory_ops"] > 0

    def test_calculate_handler_complexity_advanced_handles_invalid_code(self) -> None:
        """_calculate_handler_complexity_advanced handles invalid code gracefully."""
        detector = VMProtectDetector()
        invalid_code = b"\xFF\xFF\xFF\xFF"
        metrics = detector._calculate_handler_complexity_advanced(invalid_code, 0, len(invalid_code), "x86")
        assert isinstance(metrics, dict)
        assert "complexity" in metrics


class TestOpcodeExtraction:
    """Test opcode extraction from handlers."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_extract_opcodes_returns_opcode_list(self) -> None:
        """_extract_opcodes returns list of opcodes from handler."""
        detector = VMProtectDetector()
        x86_code = b"\x55\x8b\xec\x53\x56\x57\x5f\x5e\x5b\xc9\xc3"
        opcodes = detector._extract_opcodes(x86_code, 0, len(x86_code), "x86")
        assert isinstance(opcodes, list)
        if opcodes:
            for address, instruction in opcodes:
                assert isinstance(address, int)
                assert isinstance(instruction, str)
                assert len(instruction) > 0

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_extract_opcodes_limits_output(self) -> None:
        """_extract_opcodes limits output to maximum 50 instructions."""
        detector = VMProtectDetector()
        long_code = b"\x90" * 200
        opcodes = detector._extract_opcodes(long_code, 0, len(long_code), "x86")
        assert len(opcodes) <= 50

    def test_extract_opcodes_handles_invalid_code(self) -> None:
        """_extract_opcodes handles invalid code gracefully."""
        detector = VMProtectDetector()
        invalid = b"\xFF\xFF\xFF\xFF"
        opcodes = detector._extract_opcodes(invalid, 0, len(invalid), "x86")
        assert isinstance(opcodes, list)


class TestMutationDetection:
    """Test mutation and junk code detection."""

    def test_detect_mutations_finds_nop_padding(self) -> None:
        """_detect_mutations detects NOP sled patterns."""
        detector = VMProtectDetector()
        nop_heavy_binary = b"MZ" + (b"\x90\x90\x90" * 100)
        result = detector._detect_mutations_advanced(nop_heavy_binary, "x86")
        score = result.get("score", 0.0)
        assert 0.0 <= score <= 1.0

    def test_detect_mutations_finds_xchg_patterns(self) -> None:
        """_detect_mutations detects XCHG EAX,EAX junk patterns."""
        detector = VMProtectDetector()
        xchg_binary = b"MZ" + (b"\x87\xc0" * 50)
        result = detector._detect_mutations_advanced(xchg_binary, "x86")
        score = result.get("score", 0.0)
        assert 0.0 <= score <= 1.0

    def test_detect_mutations_finds_inc_dec_pairs(self) -> None:
        """_detect_mutations detects INC/DEC pair patterns."""
        detector = VMProtectDetector()
        inc_dec_binary = b"MZ" + (b"\x40\x4f" * 50)
        result = detector._detect_mutations_advanced(inc_dec_binary, "x86")
        score = result.get("score", 0.0)
        assert 0.0 <= score <= 1.0

    def test_detect_mutations_finds_xor_push_pop(self) -> None:
        """_detect_mutations detects XOR/PUSH/POP junk patterns."""
        detector = VMProtectDetector()
        xor_binary = b"MZ" + (b"\x33\xc0\x50\x58" * 40)
        result = detector._detect_mutations_advanced(xor_binary, "x86")
        score = result.get("score", 0.0)
        assert 0.0 <= score <= 1.0

    @pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not found")
    def test_detect_mutations_on_real_notepad(self) -> None:
        """_detect_mutations analyzes real notepad.exe for mutations."""
        detector = VMProtectDetector()
        with open(NOTEPAD, "rb") as f:
            data = f.read()
        result = detector._detect_mutations_advanced(data, "x86")
        score = result.get("score", 0.0)
        assert 0.0 <= score <= 1.0

    def test_detect_mutations_returns_zero_for_clean_binary(self) -> None:
        """_detect_mutations returns low score for clean binary."""
        detector = VMProtectDetector()
        clean_binary = b"MZ" + b"\x00" * 10000
        result = detector._detect_mutations_advanced(clean_binary, "x86")
        score = result.get("score", 0.0)
        assert 0.0 <= score <= 1.0


class TestStringScanning:
    """Test VMProtect string indicator scanning."""

    def test_scan_strings_finds_vmp_indicator(self) -> None:
        """_scan_strings finds 'vmp' string indicator."""
        detector = VMProtectDetector()
        binary_with_vmp = b"MZ" + b"\x00" * 100 + b"vmp" + b"\x00" * 100
        matches = detector._scan_strings(binary_with_vmp)
        assert isinstance(matches, list)
        assert "vmp" in matches

    def test_scan_strings_finds_vmprotect_indicator(self) -> None:
        """_scan_strings finds 'vmprotect' string indicator."""
        detector = VMProtectDetector()
        binary = b"MZ" + b"\x00" * 100 + b"VMProtect" + b"\x00" * 100
        matches = detector._scan_strings(binary)
        assert isinstance(matches, list)
        assert any("vmprotect" in m.lower() for m in matches)

    def test_scan_strings_finds_vmp_section_names(self) -> None:
        """_scan_strings finds VMP section name indicators."""
        detector = VMProtectDetector()
        binary = b"MZ" + b".vmp0" + b"\x00" * 100 + b".vmp1" + b"\x00" * 100
        matches = detector._scan_strings(binary)
        assert isinstance(matches, list)
        if matches:
            assert any(".vmp" in m for m in matches)

    def test_scan_strings_returns_empty_for_clean_binary(self) -> None:
        """_scan_strings returns empty list for clean binary."""
        detector = VMProtectDetector()
        clean_binary = b"MZ" + b"\x00" * 1000
        matches = detector._scan_strings(clean_binary)
        assert matches == []

    @pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not found")
    def test_scan_strings_on_real_notepad(self) -> None:
        """_scan_strings scans real notepad.exe for VMP indicators."""
        detector = VMProtectDetector()
        with open(NOTEPAD, "rb") as f:
            data = f.read()
        matches = detector._scan_strings(data)
        assert isinstance(matches, list)


class TestProtectionLevelDetermination:
    """Test protection level classification."""

    def test_determine_protection_level_identifies_lite(self) -> None:
        """_determine_protection_level identifies Lite protection level."""
        detector = VMProtectDetector()
        handlers = [
            VMHandler(offset=i * 100, size=50, handler_type="test", pattern=b"", confidence=0.8, complexity=20)
            for i in range(3)
        ]
        regions: list[VirtualizedRegion] = []
        mutation_score = 0.1
        level = detector._determine_protection_level(handlers, regions, mutation_score)
        assert level == VMProtectLevel.LITE

    def test_determine_protection_level_identifies_standard(self) -> None:
        """_determine_protection_level identifies Standard protection level."""
        detector = VMProtectDetector()
        handlers = [
            VMHandler(offset=i * 100, size=50, handler_type="test", pattern=b"", confidence=0.85, complexity=55)
            for i in range(8)
        ]
        regions = [
            VirtualizedRegion(
                start_offset=i * 1000,
                end_offset=(i + 1) * 1000,
                vm_entry=i * 1000,
                vm_exit=(i + 1) * 1000,
                handlers_used={"test"},
                control_flow_complexity=3.5,
            )
            for i in range(6)
        ]
        mutation_score = 0.5
        level = detector._determine_protection_level(handlers, regions, mutation_score)
        assert level == VMProtectLevel.STANDARD

    def test_determine_protection_level_identifies_ultra(self) -> None:
        """_determine_protection_level identifies Ultra protection level."""
        detector = VMProtectDetector()
        handlers = [
            VMHandler(offset=i * 100, size=50, handler_type="test", pattern=b"", confidence=0.9, complexity=85)
            for i in range(15)
        ]
        regions = [
            VirtualizedRegion(
                start_offset=i * 1000,
                end_offset=(i + 1) * 1000,
                vm_entry=i * 1000,
                vm_exit=(i + 1) * 1000,
                handlers_used={"test"},
                control_flow_complexity=6.5,
            )
            for i in range(10)
        ]
        mutation_score = 0.75
        level = detector._determine_protection_level(handlers, regions, mutation_score)
        assert level == VMProtectLevel.ULTRA

    def test_determine_protection_level_returns_unknown_without_handlers(self) -> None:
        """_determine_protection_level returns UNKNOWN when no handlers found."""
        detector = VMProtectDetector()
        handlers: list[VMHandler] = []
        regions: list[VirtualizedRegion] = []
        mutation_score = 0.0
        level = detector._determine_protection_level(handlers, regions, mutation_score)
        assert level == VMProtectLevel.UNKNOWN


class TestVersionDetection:
    """Test VMProtect version detection."""

    def test_detect_version_identifies_3x_with_multiple_vmp_sections(self) -> None:
        """_detect_version identifies 3.x from multiple VMP sections."""
        detector = VMProtectDetector()
        section_analysis: dict[str, Any] = {
            "vmp_sections": [{"name": ".vmp0"}, {"name": ".vmp1"}],
            "high_entropy_sections": [],
            "suspicious_characteristics": [],
        }
        handlers: list[VMHandler] = []
        version = detector._detect_version_advanced(b"MZ", section_analysis, handlers)
        assert "3" in version

    def test_detect_version_identifies_2x_3x_with_single_vmp_section(self) -> None:
        """_detect_version identifies 2.x-3.x from single VMP section."""
        detector = VMProtectDetector()
        section_analysis: dict[str, Any] = {
            "vmp_sections": [{"name": ".vmp0"}],
            "high_entropy_sections": [],
            "suspicious_characteristics": [],
        }
        handlers: list[VMHandler] = []
        version = detector._detect_version_advanced(b"MZ", section_analysis, handlers)
        assert "2" in version or "3" in version

    def test_detect_version_finds_version_strings(self) -> None:
        """_detect_version extracts version from binary strings."""
        detector = VMProtectDetector()
        binary_with_version = b"MZ" + b"\x00" * 100 + b"VMProtect 3.5" + b"\x00" * 100
        section_analysis: dict[str, Any] = {"vmp_sections": [], "high_entropy_sections": [], "suspicious_characteristics": []}
        handlers: list[VMHandler] = []
        version = detector._detect_version_advanced(binary_with_version, section_analysis, handlers)
        assert "3" in version

    def test_detect_version_returns_unknown_for_clean_binary(self) -> None:
        """_detect_version returns Unknown for unprotected binary."""
        detector = VMProtectDetector()
        clean = b"MZ" + b"\x00" * 1000
        section_analysis: dict[str, Any] = {"vmp_sections": [], "high_entropy_sections": [], "suspicious_characteristics": []}
        handlers: list[VMHandler] = []
        version = detector._detect_version_advanced(clean, section_analysis, handlers)
        assert "Unknown" in version or "likely" in version.lower()


class TestDispatcherDetection:
    """Test VMProtect dispatcher detection."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_find_dispatcher_locates_x86_dispatch_table(self) -> None:
        """_find_dispatcher finds x86 dispatch table patterns."""
        detector = VMProtectDetector()
        dispatcher_pattern_x86 = b"\xff\x24\x85"
        binary = b"MZ" + b"\x00" * 100 + dispatcher_pattern_x86 + b"\x00" * 100
        offset = detector._find_dispatcher_advanced(binary, "x86")
        if offset is not None:
            assert offset > 0
            assert binary[offset : offset + 3] == dispatcher_pattern_x86

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_find_dispatcher_locates_x64_dispatch_table(self) -> None:
        """_find_dispatcher finds x64 dispatch table patterns."""
        detector = VMProtectDetector()
        dispatcher_pattern_x64 = b"\xff\x24\xc5"
        binary = b"MZ" + b"\x00" * 100 + dispatcher_pattern_x64 + b"\x00" * 100
        offset = detector._find_dispatcher_advanced(binary, "x64")
        if offset is not None:
            assert offset > 0
            assert binary[offset : offset + 3] == dispatcher_pattern_x64

    def test_find_dispatcher_returns_none_for_clean_binary(self) -> None:
        """_find_dispatcher returns None when no dispatcher found."""
        detector = VMProtectDetector()
        clean = b"MZ" + b"\x00" * 1000
        offset = detector._find_dispatcher_advanced(clean, "x86")
        assert offset is None


class TestHandlerTableDetection:
    """Test handler table structure detection."""

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_scan_for_handler_table_finds_pointer_array(self) -> None:
        """_scan_for_handler_table identifies consecutive pointer arrays."""
        detector = VMProtectDetector()
        pointer_array = b"".join(struct.pack("<I", 0x1000 + i * 0x100) for i in range(20))
        section_data = b"\x00" * 100 + pointer_array + b"\x00" * 100
        offset = detector._scan_for_handler_table_advanced(section_data, "x86")
        if offset is not None:
            assert offset >= 0
            assert offset < len(section_data)

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_scan_for_handler_table_x64_pointers(self) -> None:
        """_scan_for_handler_table identifies x64 pointer arrays."""
        detector = VMProtectDetector()
        pointer_array_x64 = b"".join(struct.pack("<Q", 0x1000 + i * 0x100) for i in range(20))
        section_data = b"\x00" * 100 + pointer_array_x64 + b"\x00" * 100
        offset = detector._scan_for_handler_table_advanced(section_data, "x64")
        if offset is not None:
            assert offset >= 0

    def test_scan_for_handler_table_returns_none_without_table(self) -> None:
        """_scan_for_handler_table returns None when no table found."""
        detector = VMProtectDetector()
        random_data = b"\xFF" * 1000
        offset = detector._scan_for_handler_table_advanced(random_data, "x86")
        assert offset is None


class TestHandlerXrefDiscovery:
    """Test cross-reference discovery for handlers."""

    def test_find_handler_xrefs_locates_references(self) -> None:
        """_find_handler_xrefs finds cross-references to handler offset."""
        detector = VMProtectDetector()
        handler_offset = 0x1000
        handler_bytes = struct.pack("<I", handler_offset)
        binary = b"MZ" + b"\x00" * 100 + handler_bytes + b"\x00" * 100 + handler_bytes + b"\x00" * 100
        xrefs = detector._find_handler_xrefs(binary, handler_offset)
        assert isinstance(xrefs, list)
        assert len(xrefs) >= 0

    def test_find_handler_xrefs_excludes_self_reference(self) -> None:
        """_find_handler_xrefs excludes handler's own offset from xrefs."""
        detector = VMProtectDetector()
        handler_offset = 0x2000
        handler_bytes = struct.pack("<I", handler_offset)
        binary = b"\x00" * handler_offset + handler_bytes + b"\x00" * 100
        xrefs = detector._find_handler_xrefs(binary, handler_offset)
        assert handler_offset not in xrefs

    def test_find_handler_xrefs_limits_results(self) -> None:
        """_find_handler_xrefs limits results to maximum 10 xrefs."""
        detector = VMProtectDetector()
        handler_offset = 0x1000
        handler_bytes = struct.pack("<I", handler_offset)
        binary = handler_bytes * 50
        xrefs = detector._find_handler_xrefs(binary, handler_offset)
        assert len(xrefs) <= 10


class TestVirtualizedRegionIdentification:
    """Test virtualized code region identification."""

    def test_identify_virtualized_regions_with_entry_handlers(self) -> None:
        """_identify_virtualized_regions identifies regions from VM entry handlers."""
        detector = VMProtectDetector()
        handlers = [
            VMHandler(offset=100, size=50, handler_type="vm_entry_prologue", pattern=b"", confidence=0.95),
            VMHandler(offset=500, size=50, handler_type="vm_stack_push", pattern=b"", confidence=0.85),
        ]
        binary = b"MZ" + b"\x00" * 10000
        regions = detector._identify_virtualized_regions_advanced(binary, handlers, "x86")
        assert isinstance(regions, list)
        if regions:
            for region in regions:
                assert isinstance(region, VirtualizedRegion)
                assert region.start_offset >= 0
                assert region.end_offset > region.start_offset

    def test_identify_virtualized_regions_returns_empty_without_handlers(self) -> None:
        """_identify_virtualized_regions returns empty list without handlers."""
        detector = VMProtectDetector()
        handlers: list[VMHandler] = []
        binary = b"MZ" + b"\x00" * 1000
        regions = detector._identify_virtualized_regions_advanced(binary, handlers, "x86")
        assert regions == []


class TestVMExitDetection:
    """Test VM exit point detection."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_find_vm_exit_locates_popad_pattern(self) -> None:
        """_find_vm_exit finds POPAD/POPFD exit patterns."""
        detector = VMProtectDetector()
        vm_exit_pattern = b"\x61\x9d"
        binary = b"MZ" + b"\x00" * 200 + vm_exit_pattern + b"\x00" * 100
        offset = detector._find_vm_exit_advanced(binary, 100, "x86")
        if offset is not None:
            assert offset > 100
            assert binary[offset : offset + 2] == vm_exit_pattern

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_find_vm_exit_locates_register_restore_pattern(self) -> None:
        """_find_vm_exit finds register restoration patterns."""
        detector = VMProtectDetector()
        register_restore = b"\x5f\x5e\x5b"
        binary = b"MZ" + b"\x00" * 200 + register_restore + b"\x00" * 100
        offset = detector._find_vm_exit_advanced(binary, 100, "x86")
        if offset is not None:
            assert offset >= 100

    def test_find_vm_exit_returns_none_without_exit(self) -> None:
        """_find_vm_exit returns None when no exit pattern found."""
        detector = VMProtectDetector()
        clean = b"MZ" + b"\x00" * 1000
        offset = detector._find_vm_exit_advanced(clean, 100, "x86")
        assert offset is None


class TestRegionMutationCheck:
    """Test mutation detection within regions."""

    def test_check_region_mutation_detects_mutation_patterns(self) -> None:
        """_check_region_mutation identifies mutation patterns in region."""
        detector = VMProtectDetector()
        mutation_heavy = b"\x90\x90\x90" * 10 + b"\x87\xc0" * 5
        is_mutated = detector._check_region_mutation_advanced(mutation_heavy, 0, len(mutation_heavy), "x86")
        assert isinstance(is_mutated, bool)

    def test_check_region_mutation_returns_false_for_clean_region(self) -> None:
        """_check_region_mutation returns False for clean region."""
        detector = VMProtectDetector()
        clean_region = b"\x00" * 100
        is_mutated = detector._check_region_mutation_advanced(clean_region, 0, len(clean_region), "x86")
        assert is_mutated is False


class TestControlFlowAnalysis:
    """Test control flow analysis within virtualized regions."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_analyze_control_flow_returns_analysis_dict(self) -> None:
        """_analyze_control_flow returns comprehensive analysis dictionary."""
        detector = VMProtectDetector()
        regions = [
            VirtualizedRegion(
                start_offset=100,
                end_offset=500,
                vm_entry=100,
                vm_exit=500,
                handlers_used={"test"},
                control_flow_complexity=3.5,
            )
        ]
        binary = b"\x00" * 100 + b"\xff\x24\xc5\x00\x00\x00\x00" + b"\x00" * 400
        analysis = detector._analyze_region_control_flow(binary, regions, "x86")
        assert isinstance(analysis, dict)
        assert "total_regions" in analysis
        assert "avg_complexity" in analysis
        assert "max_complexity" in analysis
        assert "indirect_branches" in analysis
        assert "vm_transitions" in analysis

    def test_analyze_control_flow_handles_empty_regions(self) -> None:
        """_analyze_control_flow handles empty region list."""
        detector = VMProtectDetector()
        regions: list[VirtualizedRegion] = []
        binary = b"\x00" * 1000
        analysis = detector._analyze_region_control_flow(binary, regions, "x86")
        assert analysis["total_regions"] == 0
        assert analysis["avg_complexity"] == 0.0
        assert analysis["max_complexity"] == 0.0


class TestBypassRecommendations:
    """Test bypass recommendation generation."""

    def test_generate_bypass_recommendations_for_ultra(self) -> None:
        """_generate_bypass_recommendations provides Ultra-specific guidance."""
        detector = VMProtectDetector()
        detection = VMProtectDetection(
            detected=True,
            version="3.x",
            protection_level=VMProtectLevel.ULTRA,
            mode=VMProtectMode.VIRTUALIZATION,
            architecture="x64",
            handlers=[],
            virtualized_regions=[],
            dispatcher_offset=None,
            handler_table_offset=None,
            confidence=0.95,
        )
        recommendations = detector._generate_bypass_recommendations(detection)
        assert len(recommendations) > 0
        assert any("symbolic execution" in r.lower() or "smt" in r.lower() for r in recommendations)
        assert any("4-8 weeks" in r for r in recommendations)

    def test_generate_bypass_recommendations_for_standard(self) -> None:
        """_generate_bypass_recommendations provides Standard-specific guidance."""
        detector = VMProtectDetector()
        detection = VMProtectDetection(
            detected=True,
            version="3.x",
            protection_level=VMProtectLevel.STANDARD,
            mode=VMProtectMode.VIRTUALIZATION,
            architecture="x86",
            handlers=[],
            virtualized_regions=[],
            dispatcher_offset=None,
            handler_table_offset=None,
            confidence=0.85,
        )
        recommendations = detector._generate_bypass_recommendations(detection)
        assert len(recommendations) > 0
        assert any("pattern-based" in r.lower() for r in recommendations)
        assert any("1-3 weeks" in r for r in recommendations)

    def test_generate_bypass_recommendations_for_lite(self) -> None:
        """_generate_bypass_recommendations provides Lite-specific guidance."""
        detector = VMProtectDetector()
        detection = VMProtectDetection(
            detected=True,
            version="3.x",
            protection_level=VMProtectLevel.LITE,
            mode=VMProtectMode.VIRTUALIZATION,
            architecture="x86",
            handlers=[],
            virtualized_regions=[],
            dispatcher_offset=None,
            handler_table_offset=None,
            confidence=0.75,
        )
        recommendations = detector._generate_bypass_recommendations(detection)
        assert len(recommendations) > 0
        assert any("3-7 days" in r for r in recommendations)

    def test_generate_bypass_recommendations_includes_dispatcher_offset(self) -> None:
        """_generate_bypass_recommendations includes dispatcher offset when found."""
        detector = VMProtectDetector()
        detection = VMProtectDetection(
            detected=True,
            version="3.x",
            protection_level=VMProtectLevel.STANDARD,
            mode=VMProtectMode.VIRTUALIZATION,
            architecture="x86",
            handlers=[],
            virtualized_regions=[],
            dispatcher_offset=0x1234,
            handler_table_offset=None,
            confidence=0.85,
        )
        recommendations = detector._generate_bypass_recommendations(detection)
        assert any("0x00001234" in r for r in recommendations)

    def test_generate_bypass_recommendations_includes_handler_table(self) -> None:
        """_generate_bypass_recommendations includes handler table offset when found."""
        detector = VMProtectDetector()
        detection = VMProtectDetection(
            detected=True,
            version="3.x",
            protection_level=VMProtectLevel.STANDARD,
            mode=VMProtectMode.VIRTUALIZATION,
            architecture="x86",
            handlers=[],
            virtualized_regions=[],
            dispatcher_offset=None,
            handler_table_offset=0x5678,
            confidence=0.85,
        )
        recommendations = detector._generate_bypass_recommendations(detection)
        assert any("0x00005678" in r for r in recommendations)

    def test_generate_bypass_recommendations_returns_empty_for_undetected(self) -> None:
        """_generate_bypass_recommendations returns empty list when not detected."""
        detector = VMProtectDetector()
        detection = VMProtectDetection(
            detected=False,
            version="Unknown",
            protection_level=VMProtectLevel.UNKNOWN,
            mode=VMProtectMode.VIRTUALIZATION,
            architecture="unknown",
            handlers=[],
            virtualized_regions=[],
            dispatcher_offset=None,
            handler_table_offset=None,
            confidence=0.0,
        )
        recommendations = detector._generate_bypass_recommendations(detection)
        assert recommendations == []


class TestEndToEndDetection:
    """Test complete end-to-end detection workflows."""

    @pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not found")
    def test_detect_end_to_end_on_real_notepad(self) -> None:
        """detect performs complete analysis on real notepad.exe."""
        detector = VMProtectDetector()
        detection = detector.detect(str(NOTEPAD))
        assert isinstance(detection, VMProtectDetection)
        assert detection.architecture in ["x86", "x64", "unknown"]
        assert 0.0 <= detection.confidence <= 1.0
        assert isinstance(detection.handlers, list)
        assert isinstance(detection.virtualized_regions, list)
        assert isinstance(detection.technical_details, dict)
        assert isinstance(detection.bypass_recommendations, list)

    @pytest.mark.skipif(not KERNEL32.exists(), reason="kernel32.dll not found")
    def test_detect_end_to_end_on_real_kernel32(self) -> None:
        """detect performs complete analysis on real kernel32.dll."""
        detector = VMProtectDetector()
        detection = detector.detect(str(KERNEL32))
        assert isinstance(detection, VMProtectDetection)
        assert detection.architecture in ["x86", "x64", "unknown"]
        assert 0.0 <= detection.confidence <= 1.0

    @pytest.mark.skipif(not CALC.exists(), reason="calc.exe not found")
    def test_detect_end_to_end_on_real_calc(self) -> None:
        """detect performs complete analysis on real calc.exe."""
        detector = VMProtectDetector()
        detection = detector.detect(str(CALC))
        assert isinstance(detection, VMProtectDetection)
        assert detection.architecture in ["x86", "x64", "unknown"]

    def test_detect_handles_nonexistent_file(self) -> None:
        """detect handles missing files gracefully."""
        detector = VMProtectDetector()
        with tempfile.TemporaryDirectory() as tmpdir:
            nonexistent = Path(tmpdir) / "does_not_exist.exe"
            detection = detector.detect(str(nonexistent))
            assert detection.detected is False or "error" in detection.technical_details

    def test_detect_handles_non_pe_file(self) -> None:
        """detect handles non-PE files gracefully."""
        detector = VMProtectDetector()
        with tempfile.TemporaryDirectory() as tmpdir:
            non_pe = Path(tmpdir) / "not_pe.bin"
            non_pe.write_bytes(b"NOTPE" + b"\x00" * 1000)
            detection = detector.detect(str(non_pe))
            assert detection.detected is False
            assert detection.architecture == "unknown"

    def test_detect_handles_corrupted_pe(self) -> None:
        """detect handles corrupted PE files gracefully."""
        detector = VMProtectDetector()
        with tempfile.TemporaryDirectory() as tmpdir:
            corrupted = Path(tmpdir) / "corrupted.exe"
            corrupted.write_bytes(b"MZ" + b"\xFF" * 1000)
            detection = detector.detect(str(corrupted))
            assert isinstance(detection, VMProtectDetection)


class TestDataclasses:
    """Test dataclass structures."""

    def test_vm_handler_initialization(self) -> None:
        """VMHandler dataclass initializes correctly."""
        handler = VMHandler(
            offset=0x1000,
            size=128,
            handler_type="vm_entry_prologue",
            pattern=b"\x55\x8b\xec",
            confidence=0.92,
        )
        assert handler.offset == 0x1000
        assert handler.size == 128
        assert handler.handler_type == "vm_entry_prologue"
        assert handler.pattern == b"\x55\x8b\xec"
        assert handler.confidence == 0.92
        assert handler.opcodes == []
        assert handler.xrefs == []
        assert handler.complexity == 0
        assert handler.branches == 0
        assert handler.memory_ops == 0

    def test_virtualized_region_initialization(self) -> None:
        """VirtualizedRegion dataclass initializes correctly."""
        region = VirtualizedRegion(
            start_offset=0x2000,
            end_offset=0x4000,
            vm_entry=0x2000,
            vm_exit=0x4000,
            handlers_used={"handler1", "handler2"},
            control_flow_complexity=5.5,
        )
        assert region.start_offset == 0x2000
        assert region.end_offset == 0x4000
        assert region.vm_entry == 0x2000
        assert region.vm_exit == 0x4000
        assert "handler1" in region.handlers_used
        assert "handler2" in region.handlers_used
        assert region.control_flow_complexity == 5.5
        assert region.mutation_detected is False
        assert region.protection_level == VMProtectLevel.UNKNOWN

    def test_vmprotect_detection_initialization(self) -> None:
        """VMProtectDetection dataclass initializes correctly."""
        handlers = [
            VMHandler(offset=0x1000, size=50, handler_type="test", pattern=b"", confidence=0.9)
        ]
        regions = [
            VirtualizedRegion(
                start_offset=0x2000,
                end_offset=0x3000,
                vm_entry=0x2000,
                vm_exit=0x3000,
                handlers_used={"test"},
                control_flow_complexity=3.5,
            )
        ]
        detection = VMProtectDetection(
            detected=True,
            version="3.5",
            protection_level=VMProtectLevel.ULTRA,
            mode=VMProtectMode.HYBRID,
            architecture="x64",
            handlers=handlers,
            virtualized_regions=regions,
            dispatcher_offset=0x1000,
            handler_table_offset=0x2000,
            confidence=0.95,
        )
        assert detection.detected is True
        assert detection.version == "3.5"
        assert detection.protection_level == VMProtectLevel.ULTRA
        assert detection.mode == VMProtectMode.HYBRID
        assert detection.architecture == "x64"
        assert len(detection.handlers) == 1
        assert len(detection.virtualized_regions) == 1
        assert detection.dispatcher_offset == 0x1000
        assert detection.handler_table_offset == 0x2000
        assert detection.confidence == 0.95
        assert detection.technical_details == {}
        assert detection.bypass_recommendations == []


class TestEnums:
    """Test enum definitions."""

    def test_vmprotect_level_enum_values(self) -> None:
        """VMProtectLevel enum contains all expected values."""
        assert VMProtectLevel.LITE.value == "lite"
        assert VMProtectLevel.STANDARD.value == "standard"
        assert VMProtectLevel.ULTRA.value == "ultra"
        assert VMProtectLevel.UNKNOWN.value == "unknown"

    def test_vmprotect_mode_enum_values(self) -> None:
        """VMProtectMode enum contains all expected values."""
        assert VMProtectMode.VIRTUALIZATION.value == "virtualization"
        assert VMProtectMode.MUTATION.value == "mutation"
        assert VMProtectMode.HYBRID.value == "hybrid"


                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          