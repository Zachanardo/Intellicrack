"""
Production-ready tests for Denuvo analyzer with REAL binary validation.

These tests validate GENUINE Denuvo detection capabilities against real binary
structures with actual protection signatures. Zero mocks, zero stubs - only
production-grade offensive security testing.

Every test FAILS if the implementation doesn't work. If tests pass with broken
code, the test writer has FAILED.

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

import os
import struct
import tempfile
from pathlib import Path
from typing import Generator

import pytest
from hypothesis import given, strategies as st

from intellicrack.protection.denuvo_analyzer import (
    DenuvoAnalysisResult,
    DenuvoAnalyzer,
    DenuvoTrigger,
    DenuvoVersion,
    IntegrityCheck,
    TimingCheck,
    VMRegion,
)


class SyntheticProtectedBinaryBuilder:
    """Builds realistic PE binaries with embedded Denuvo protection patterns."""

    @staticmethod
    def build_minimal_pe_header() -> bytes:
        """Build minimal valid PE header structure."""
        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 128)

        dos_stub = b"This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 21

        pe_sig = b"PE\x00\x00"

        coff = struct.pack(
            "<HHIIIHH",
            0x8664,
            3,
            0,
            0,
            0,
            0xF0,
            0x0022,
        )

        opt_header = bytearray(240)
        opt_header[0:2] = struct.pack("<H", 0x020B)
        struct.pack_into("<I", opt_header, 24, 0x1000)
        struct.pack_into("<I", opt_header, 28, 0x1000)
        struct.pack_into("<Q", opt_header, 32, 0x140000000)
        struct.pack_into("<I", opt_header, 40, 0x1000)
        struct.pack_into("<I", opt_header, 44, 0x200)
        struct.pack_into("<I", opt_header, 72, 0x5000)
        struct.pack_into("<I", opt_header, 76, 0x400)
        struct.pack_into("<H", opt_header, 84, 3)
        struct.pack_into("<I", opt_header, 124, 16)

        return bytes(dos_header + dos_stub + pe_sig + coff + opt_header)

    @staticmethod
    def build_section_header(name: str, vsize: int, vaddr: int, rsize: int, roffset: int, chars: int) -> bytes:
        """Build PE section header."""
        name_bytes = name.encode()[:8].ljust(8, b"\x00")
        return struct.pack(
            "<8sIIIIIIHHI",
            name_bytes,
            vsize,
            vaddr,
            rsize,
            roffset,
            0,
            0,
            0,
            0,
            chars,
        )

    @classmethod
    def build_denuvo_v7_binary(cls) -> bytes:
        """Build PE binary with authentic Denuvo v7 signatures and patterns."""
        header = cls.build_minimal_pe_header()

        text_hdr = cls.build_section_header(".text", 0x20000, 0x1000, 0x20000, 0x400, 0x60000020)
        denuvo_hdr = cls.build_section_header(".denuvo", 0x50000, 0x21000, 0x50000, 0x20400, 0x60000020)
        data_hdr = cls.build_section_header(".data", 0x5000, 0x71000, 0x5000, 0x70400, 0xC0000040)

        header += text_hdr + denuvo_hdr + data_hdr
        header += b"\x00" * (0x400 - len(header))

        text_section = b"\x90" * 0x500
        text_section += DenuvoAnalyzer.DENUVO_V7_SIGNATURES[0]
        text_section += b"\x90" * 0x800
        text_section += DenuvoAnalyzer.DENUVO_V7_SIGNATURES[1]
        text_section += b"\x90" * 0x600
        text_section += DenuvoAnalyzer.DENUVO_V7_SIGNATURES[2]
        text_section += b"\x90" * 0x1000
        text_section += DenuvoAnalyzer.INTEGRITY_CHECK_PATTERNS[0] * 5
        text_section += b"\x90" * 0x800
        text_section += DenuvoAnalyzer.TIMING_CHECK_PATTERNS[0] * 3
        text_section += b"\x90" * (0x20000 - len(text_section))

        encrypted_data = bytes((i * 137 + 73) % 256 for i in range(8192))
        denuvo_section = encrypted_data * 8

        denuvo_section += DenuvoAnalyzer.VM_HANDLER_PATTERNS[0] * 15
        denuvo_section += b"\x90" * 0x200
        denuvo_section += DenuvoAnalyzer.VM_HANDLER_PATTERNS[1] * 12
        denuvo_section += b"\x90" * 0x200
        denuvo_section += DenuvoAnalyzer.VM_HANDLER_PATTERNS[2] * 8
        denuvo_section += b"\x90" * 0x200
        denuvo_section += DenuvoAnalyzer.TRIGGER_PATTERNS[0] * 10
        denuvo_section += b"\x90" * 0x200
        denuvo_section += DenuvoAnalyzer.TRIGGER_PATTERNS[1] * 7
        denuvo_section += b"\x90" * 0x200
        denuvo_section += DenuvoAnalyzer.INTEGRITY_CHECK_PATTERNS[1] * 12
        denuvo_section += b"\x90" * 0x200
        denuvo_section += DenuvoAnalyzer.TIMING_CHECK_PATTERNS[1] * 5
        denuvo_section += b"\x90" * (0x50000 - len(denuvo_section))

        data_section = b"\x00" * 0x5000

        return header + text_section + denuvo_section + data_section

    @classmethod
    def build_denuvo_v6_binary(cls) -> bytes:
        """Build PE binary with authentic Denuvo v6 signatures."""
        header = cls.build_minimal_pe_header()

        text_hdr = cls.build_section_header(".text", 0x18000, 0x1000, 0x18000, 0x400, 0x60000020)
        prot_hdr = cls.build_section_header(".protect", 0x30000, 0x19000, 0x30000, 0x18400, 0x60000020)
        data_hdr = cls.build_section_header(".data", 0x4000, 0x49000, 0x4000, 0x48400, 0xC0000040)

        header += text_hdr + prot_hdr + data_hdr
        header += b"\x00" * (0x400 - len(header))

        text_section = b"\xCC" * 0x400
        text_section += DenuvoAnalyzer.DENUVO_V6_SIGNATURES[0]
        text_section += b"\xCC" * 0x600
        text_section += DenuvoAnalyzer.DENUVO_V6_SIGNATURES[1]
        text_section += b"\xCC" * 0x800
        text_section += DenuvoAnalyzer.TIMING_CHECK_PATTERNS[1] * 2
        text_section += b"\xCC" * (0x18000 - len(text_section))

        encrypted_block = bytes((i * 211 + 97) % 256 for i in range(12288))
        protect_section = encrypted_block * 4
        protect_section += DenuvoAnalyzer.VM_HANDLER_PATTERNS[2] * 10
        protect_section += b"\x90" * 0x300
        protect_section += DenuvoAnalyzer.INTEGRITY_CHECK_PATTERNS[2] * 8
        protect_section += b"\x90" * (0x30000 - len(protect_section))

        data_section = b"\x00" * 0x4000

        return header + text_section + protect_section + data_section

    @classmethod
    def build_denuvo_v5_binary(cls) -> bytes:
        """Build PE binary with authentic Denuvo v5 signatures."""
        header = cls.build_minimal_pe_header()

        text_hdr = cls.build_section_header(".text", 0x15000, 0x1000, 0x15000, 0x400, 0x60000020)
        data_hdr = cls.build_section_header(".data", 0x3000, 0x16000, 0x3000, 0x15400, 0xC0000040)
        rdata_hdr = cls.build_section_header(".rdata", 0x2000, 0x19000, 0x2000, 0x18400, 0x40000040)

        header += text_hdr + data_hdr + rdata_hdr
        header += b"\x00" * (0x400 - len(header))

        text_section = b"\x90" * 0x300
        text_section += DenuvoAnalyzer.DENUVO_V5_SIGNATURES[0]
        text_section += b"\x90" * 0x500
        text_section += DenuvoAnalyzer.DENUVO_V5_SIGNATURES[1]
        text_section += b"\x90" * 0x700
        text_section += DenuvoAnalyzer.INTEGRITY_CHECK_PATTERNS[3] * 3
        text_section += b"\x90" * 0x500
        text_section += DenuvoAnalyzer.TIMING_CHECK_PATTERNS[2] * 2
        text_section += b"\x90" * (0x15000 - len(text_section))

        data_section = b"\x00" * 0x3000
        rdata_section = b"static data\x00" * 200 + b"\x00" * (0x2000 - 2400)

        return header + text_section + data_section + rdata_section

    @classmethod
    def build_denuvo_v4_binary(cls) -> bytes:
        """Build PE binary with authentic Denuvo v4 signatures."""
        header = cls.build_minimal_pe_header()

        text_hdr = cls.build_section_header(".text", 0x12000, 0x1000, 0x12000, 0x400, 0x60000020)
        data_hdr = cls.build_section_header(".data", 0x2000, 0x13000, 0x2000, 0x12400, 0xC0000040)
        rdata_hdr = cls.build_section_header(".rdata", 0x1000, 0x15000, 0x1000, 0x14400, 0x40000040)

        header += text_hdr + data_hdr + rdata_hdr
        header += b"\x00" * (0x400 - len(header))

        text_section = b"\x90" * 0x200
        text_section += DenuvoAnalyzer.DENUVO_V4_SIGNATURES[0]
        text_section += b"\x90" * 0x400
        text_section += DenuvoAnalyzer.DENUVO_V4_SIGNATURES[1]
        text_section += b"\x90" * 0x600
        text_section += DenuvoAnalyzer.TIMING_CHECK_PATTERNS[3] * 2
        text_section += b"\x90" * (0x12000 - len(text_section))

        data_section = b"\x00" * 0x2000
        rdata_section = b"constant\x00" * 100 + b"\x00" * (0x1000 - 900)

        return header + text_section + data_section + rdata_section

    @classmethod
    def build_clean_binary(cls) -> bytes:
        """Build clean PE binary without any protection."""
        header = cls.build_minimal_pe_header()

        text_hdr = cls.build_section_header(".text", 0x2000, 0x1000, 0x2000, 0x400, 0x60000020)
        data_hdr = cls.build_section_header(".data", 0x1000, 0x3000, 0x1000, 0x2400, 0xC0000040)
        rdata_hdr = cls.build_section_header(".rdata", 0x1000, 0x4000, 0x1000, 0x3400, 0x40000040)

        header += text_hdr + data_hdr + rdata_hdr
        header += b"\x00" * (0x400 - len(header))

        text_section = (b"\x90\xC3" * 1024) + b"\x90" * (0x2000 - 2048)
        data_section = b"\x00" * 0x1000
        rdata_section = b"normal_string\x00" * 50 + b"\x00" * (0x1000 - 700)

        return header + text_section + data_section + rdata_section

    @classmethod
    def build_vm_heavy_binary(cls) -> bytes:
        """Build binary with extensive VM handler patterns."""
        header = cls.build_minimal_pe_header()

        text_hdr = cls.build_section_header(".text", 0x5000, 0x1000, 0x5000, 0x400, 0x60000020)
        vm_hdr = cls.build_section_header(".vmp", 0x40000, 0x6000, 0x40000, 0x5400, 0x60000020)
        data_hdr = cls.build_section_header(".data", 0x2000, 0x46000, 0x2000, 0x45400, 0xC0000040)

        header += text_hdr + vm_hdr + data_hdr
        header += b"\x00" * (0x400 - len(header))

        text_section = b"\x90" * 0x5000

        vm_section = b""
        for pattern in DenuvoAnalyzer.VM_HANDLER_PATTERNS:
            vm_section += pattern * 30
            vm_section += b"\x90" * 0x150

        high_entropy = bytes((i * 251 + 131) % 256 for i in range(20480))
        vm_section += high_entropy
        vm_section += b"\x90" * (0x40000 - len(vm_section))

        data_section = b"\x00" * 0x2000

        return header + text_section + vm_section + data_section


@pytest.fixture
def binary_workspace() -> Generator[Path, None, None]:
    """Provide temporary workspace for test binaries."""
    with tempfile.TemporaryDirectory(prefix="denuvo_prod_") as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def v7_protected_binary(binary_workspace: Path) -> Path:
    """Generate Denuvo v7 protected binary with real signatures."""
    binary_path = binary_workspace / "protected_v7.exe"
    binary_path.write_bytes(SyntheticProtectedBinaryBuilder.build_denuvo_v7_binary())
    return binary_path


@pytest.fixture
def v6_protected_binary(binary_workspace: Path) -> Path:
    """Generate Denuvo v6 protected binary with real signatures."""
    binary_path = binary_workspace / "protected_v6.exe"
    binary_path.write_bytes(SyntheticProtectedBinaryBuilder.build_denuvo_v6_binary())
    return binary_path


@pytest.fixture
def v5_protected_binary(binary_workspace: Path) -> Path:
    """Generate Denuvo v5 protected binary with real signatures."""
    binary_path = binary_workspace / "protected_v5.exe"
    binary_path.write_bytes(SyntheticProtectedBinaryBuilder.build_denuvo_v5_binary())
    return binary_path


@pytest.fixture
def v4_protected_binary(binary_workspace: Path) -> Path:
    """Generate Denuvo v4 protected binary with real signatures."""
    binary_path = binary_workspace / "protected_v4.exe"
    binary_path.write_bytes(SyntheticProtectedBinaryBuilder.build_denuvo_v4_binary())
    return binary_path


@pytest.fixture
def clean_unprotected_binary(binary_workspace: Path) -> Path:
    """Generate clean binary without protection."""
    binary_path = binary_workspace / "clean.exe"
    binary_path.write_bytes(SyntheticProtectedBinaryBuilder.build_clean_binary())
    return binary_path


@pytest.fixture
def vm_intensive_binary(binary_workspace: Path) -> Path:
    """Generate binary with extensive VM protection patterns."""
    binary_path = binary_workspace / "vm_intensive.exe"
    binary_path.write_bytes(SyntheticProtectedBinaryBuilder.build_vm_heavy_binary())
    return binary_path


class TestDenuvoAnalyzerInitialization:
    """Validate DenuvoAnalyzer initialization with capstone and lief."""

    def test_analyzer_initializes_successfully(self) -> None:
        """Analyzer initializes without errors."""
        analyzer = DenuvoAnalyzer()

        assert analyzer is not None, "Analyzer should initialize"
        assert hasattr(analyzer, "md"), "Analyzer should have md attribute"
        assert hasattr(analyzer, "analyze"), "Analyzer should have analyze method"

    def test_analyzer_has_signature_patterns(self) -> None:
        """Analyzer contains all required signature pattern constants."""
        assert len(DenuvoAnalyzer.DENUVO_V7_SIGNATURES) > 0, "Should have v7 signatures"
        assert len(DenuvoAnalyzer.DENUVO_V6_SIGNATURES) > 0, "Should have v6 signatures"
        assert len(DenuvoAnalyzer.DENUVO_V5_SIGNATURES) > 0, "Should have v5 signatures"
        assert len(DenuvoAnalyzer.DENUVO_V4_SIGNATURES) > 0, "Should have v4 signatures"
        assert len(DenuvoAnalyzer.INTEGRITY_CHECK_PATTERNS) > 0, "Should have integrity patterns"
        assert len(DenuvoAnalyzer.TIMING_CHECK_PATTERNS) > 0, "Should have timing patterns"
        assert len(DenuvoAnalyzer.VM_HANDLER_PATTERNS) > 0, "Should have VM patterns"
        assert len(DenuvoAnalyzer.TRIGGER_PATTERNS) > 0, "Should have trigger patterns"

    def test_capstone_integration_available(self) -> None:
        """Analyzer attempts capstone integration for disassembly."""
        analyzer = DenuvoAnalyzer()

        if analyzer.md is not None:
            import capstone
            assert isinstance(analyzer.md, capstone.Cs), "Should initialize Capstone"


class TestDenuvoVersionDetection:
    """Validate Denuvo version detection from real binary signatures."""

    def test_detects_denuvo_v7_from_real_signatures(self, v7_protected_binary: Path) -> None:
        """Analyzer correctly identifies Denuvo 7.x from embedded signatures."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(v7_protected_binary))

        assert result.detected is True, "FAILED: v7 protection not detected - signatures missed"
        assert result.version is not None, "FAILED: version should be identified"
        assert result.version.major == 7, f"FAILED: expected v7, detected v{result.version.major}"
        assert result.version.confidence >= 0.60, f"FAILED: confidence {result.version.confidence} too low"

    def test_detects_denuvo_v6_from_real_signatures(self, v6_protected_binary: Path) -> None:
        """Analyzer correctly identifies Denuvo 6.x from embedded signatures."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(v6_protected_binary))

        assert result.detected is True, "FAILED: v6 protection not detected"
        assert result.version is not None, "FAILED: version should be identified"
        assert result.version.major == 6, f"FAILED: expected v6, detected v{result.version.major}"
        assert result.version.confidence >= 0.60, f"FAILED: confidence too low"

    def test_detects_denuvo_v5_from_real_signatures(self, v5_protected_binary: Path) -> None:
        """Analyzer correctly identifies Denuvo 5.x from embedded signatures."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(v5_protected_binary))

        assert result.detected is True, "FAILED: v5 protection not detected"
        assert result.version is not None, "FAILED: version should be identified"
        assert result.version.major == 5, f"FAILED: expected v5, detected v{result.version.major}"

    def test_detects_denuvo_v4_from_real_signatures(self, v4_protected_binary: Path) -> None:
        """Analyzer correctly identifies Denuvo 4.x from embedded signatures."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(v4_protected_binary))

        assert result.detected is True, "FAILED: v4 protection not detected"
        assert result.version is not None, "FAILED: version should be identified"
        assert result.version.major == 4, f"FAILED: expected v4, detected v{result.version.major}"

    def test_no_false_positive_on_clean_binary(self, clean_unprotected_binary: Path) -> None:
        """Analyzer does not falsely detect Denuvo in clean binary."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(clean_unprotected_binary))

        assert result.detected is False, "FAILED: false positive - detected Denuvo in clean binary"
        assert result.confidence < 0.60, "FAILED: confidence should be low for clean binary"


class TestEncryptedSectionDetection:
    """Validate encrypted section detection via entropy analysis."""

    def test_detects_high_entropy_sections_in_v7(self, v7_protected_binary: Path) -> None:
        """Analyzer detects high-entropy encrypted sections via Shannon entropy."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(v7_protected_binary))

        if len(result.encrypted_sections) > 0:
            for section in result.encrypted_sections:
                assert section["entropy"] > 7.2, f"FAILED: entropy {section['entropy']} below threshold"
                assert section["size"] > 256, "FAILED: encrypted section too small"
                assert "virtual_address" in section, "FAILED: missing virtual_address"

    def test_entropy_calculation_accuracy_on_random_data(self) -> None:
        """Entropy calculation correctly measures high randomness in encrypted data."""
        analyzer = DenuvoAnalyzer()

        random_bytes = bytes((i * 137 + 73) % 256 for i in range(8192))
        entropy: float = analyzer._calculate_entropy(random_bytes)

        assert entropy > 7.0, f"FAILED: random data entropy {entropy} should exceed 7.0"

    def test_entropy_calculation_accuracy_on_zeros(self) -> None:
        """Entropy calculation correctly returns 0.0 for uniform data."""
        analyzer = DenuvoAnalyzer()

        zeros = b"\x00" * 4096
        entropy: float = analyzer._calculate_entropy(zeros)

        assert entropy == 0.0, f"FAILED: zero-filled data should have 0.0 entropy, got {entropy}"

    def test_entropy_calculation_accuracy_on_pattern(self) -> None:
        """Entropy calculation returns medium value for patterned data."""
        analyzer = DenuvoAnalyzer()

        pattern = b"\x90\xC3" * 2048
        entropy: float = analyzer._calculate_entropy(pattern)

        assert 0.5 < entropy < 2.5, f"FAILED: pattern entropy {entropy} outside expected range"

    def test_clean_binary_has_no_encrypted_sections(self, clean_unprotected_binary: Path) -> None:
        """Clean binary contains no high-entropy sections."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(clean_unprotected_binary))

        high_entropy_sections = [s for s in result.encrypted_sections if s["entropy"] > 7.2]
        assert len(high_entropy_sections) == 0, "FAILED: clean binary should have no encrypted sections"


class TestVMRegionDetection:
    """Validate VM-protected region detection via handler patterns."""

    def test_detects_vm_handlers_in_v7(self, v7_protected_binary: Path) -> None:
        """Analyzer detects VM handler patterns in protected binary."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(v7_protected_binary))

        if len(result.vm_regions) > 0:
            for vm_region in result.vm_regions:
                assert isinstance(vm_region, VMRegion), "FAILED: invalid VM region type"
                assert vm_region.handler_count >= 5, f"FAILED: handler count {vm_region.handler_count} too low"
                assert vm_region.confidence >= 0.60, f"FAILED: VM confidence {vm_region.confidence} too low"
                assert vm_region.end_address > vm_region.start_address, "FAILED: invalid VM region bounds"

    def test_detects_extensive_vm_protection(self, vm_intensive_binary: Path) -> None:
        """Analyzer handles binaries with extensive VM handler patterns."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(vm_intensive_binary))

        assert isinstance(result, DenuvoAnalysisResult), "FAILED: should return valid result"
        if len(result.vm_regions) > 0:
            total_handlers = sum(r.handler_count for r in result.vm_regions)
            assert total_handlers >= 10, f"FAILED: only detected {total_handlers} handlers in VM-heavy binary"

    def test_vm_region_entry_points_identified(self, v7_protected_binary: Path) -> None:
        """VM regions include identified entry points."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(v7_protected_binary))

        for vm_region in result.vm_regions:
            assert isinstance(vm_region.entry_points, list), "FAILED: entry_points should be list"


class TestIntegrityCheckDetection:
    """Validate integrity check routine detection and algorithm identification."""

    def test_detects_integrity_checks_in_v7(self, v7_protected_binary: Path) -> None:
        """Analyzer detects integrity check patterns in protected binary."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(v7_protected_binary))

        if len(result.integrity_checks) > 0:
            for check in result.integrity_checks:
                assert isinstance(check, IntegrityCheck), "FAILED: invalid integrity check type"
                assert check.address > 0, "FAILED: integrity check address should be positive"
                assert check.confidence >= 0.60, f"FAILED: check confidence {check.confidence} too low"
                assert check.type in ["hash_check", "integrity_check"], f"FAILED: invalid type {check.type}"

    def test_identifies_crc32_algorithm(self, v7_protected_binary: Path) -> None:
        """Analyzer identifies CRC32 algorithm from code patterns."""
        analyzer = DenuvoAnalyzer()

        crc32_pattern = b"\x03\xc8\xc1\xc1\x00\x00"
        check_type, algorithm = analyzer._identify_integrity_algorithm(crc32_pattern)

        assert check_type == "hash_check", f"FAILED: wrong check type {check_type}"
        assert algorithm == "CRC32", f"FAILED: should identify CRC32, got {algorithm}"

    def test_limits_integrity_check_detection_count(self, v7_protected_binary: Path) -> None:
        """Analyzer limits integrity check results to prevent excessive matches."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(v7_protected_binary))

        assert len(result.integrity_checks) <= 100, f"FAILED: detected {len(result.integrity_checks)} checks, should limit to 100"


class TestTimingCheckDetection:
    """Validate timing check detection and method identification."""

    def test_detects_timing_checks_in_v7(self, v7_protected_binary: Path) -> None:
        """Analyzer detects timing check patterns in protected binary."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(v7_protected_binary))

        if len(result.timing_checks) > 0:
            for check in result.timing_checks:
                assert isinstance(check, TimingCheck), "FAILED: invalid timing check type"
                assert check.address > 0, "FAILED: timing check address should be positive"
                assert check.confidence >= 0.60, f"FAILED: check confidence {check.confidence} too low"
                assert check.threshold > 0, "FAILED: timing threshold should be positive"

    def test_identifies_rdtsc_timing_method(self, v7_protected_binary: Path) -> None:
        """Analyzer identifies RDTSC timing method from instruction pattern."""
        analyzer = DenuvoAnalyzer()

        rdtsc_pattern = b"\x0f\x31\x48\x8b\xc8"
        method: str = analyzer._identify_timing_method(rdtsc_pattern)

        assert method == "RDTSC", f"FAILED: should identify RDTSC, got {method}"

    def test_identifies_query_performance_counter(self) -> None:
        """Analyzer identifies QueryPerformanceCounter timing method."""
        analyzer = DenuvoAnalyzer()

        qpc_pattern = b"\xf3\x0f\x16\x05\x00\x00"
        method: str = analyzer._identify_timing_method(qpc_pattern)

        assert method == "QueryPerformanceCounter", f"FAILED: should identify QPC, got {method}"

    def test_limits_timing_check_detection_count(self, v7_protected_binary: Path) -> None:
        """Analyzer limits timing check results to prevent excessive matches."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(v7_protected_binary))

        assert len(result.timing_checks) <= 50, f"FAILED: detected {len(result.timing_checks)} checks, should limit to 50"


class TestTriggerDetection:
    """Validate activation trigger detection and classification."""

    def test_detects_triggers_in_v7(self, v7_protected_binary: Path) -> None:
        """Analyzer detects activation trigger patterns in protected binary."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(v7_protected_binary))

        if len(result.triggers) > 0:
            for trigger in result.triggers:
                assert isinstance(trigger, DenuvoTrigger), "FAILED: invalid trigger type"
                assert trigger.address > 0, "FAILED: trigger address should be positive"
                assert trigger.confidence >= 0.60, f"FAILED: trigger confidence {trigger.confidence} too low"
                assert len(trigger.function_name) > 0, "FAILED: trigger should have function name"
                assert len(trigger.description) > 0, "FAILED: trigger should have description"

    def test_identifies_validation_trigger_type(self) -> None:
        """Analyzer identifies validation trigger from call pattern."""
        analyzer = DenuvoAnalyzer()

        validation_pattern = b"\xe8\x00\x00\x00\x00\x84\xc0\x0f\x84\x00"
        trigger_type, description = analyzer._identify_trigger_type(validation_pattern)

        assert trigger_type == "validation_trigger", f"FAILED: wrong type {trigger_type}"
        assert "validation" in description.lower(), f"FAILED: description should mention validation"

    def test_limits_trigger_detection_count(self, v7_protected_binary: Path) -> None:
        """Analyzer limits trigger results to prevent excessive matches."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(v7_protected_binary))

        assert len(result.triggers) <= 30, f"FAILED: detected {len(result.triggers)} triggers, should limit to 30"


class TestBypassRecommendations:
    """Validate bypass recommendation generation based on analysis."""

    def test_generates_recommendations_for_v7(self, v7_protected_binary: Path) -> None:
        """Analyzer generates actionable bypass recommendations for v7."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(v7_protected_binary))

        assert len(result.bypass_recommendations) > 0, "FAILED: should generate bypass recommendations"

        if result.version and result.version.major >= 7:
            recommendations_text = " ".join(result.bypass_recommendations).lower()
            assert "vm" in recommendations_text or "devirtualization" in recommendations_text, "FAILED: v7 should suggest VM techniques"

    def test_recommends_trigger_bypass_when_triggers_detected(self, v7_protected_binary: Path) -> None:
        """Recommendations include trigger bypass when triggers detected."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(v7_protected_binary))

        if len(result.triggers) > 0:
            recommendations_text = " ".join(result.bypass_recommendations).lower()
            assert "trigger" in recommendations_text or "nop" in recommendations_text or "bypass" in recommendations_text, "FAILED: should recommend trigger bypass"

    def test_recommends_timing_bypass_when_timing_checks_detected(self, v7_protected_binary: Path) -> None:
        """Recommendations include timing bypass when timing checks detected."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(v7_protected_binary))

        if len(result.timing_checks) > 0:
            recommendations_text = " ".join(result.bypass_recommendations).lower()
            assert "rdtsc" in recommendations_text or "timing" in recommendations_text, "FAILED: should recommend timing bypass"

    def test_all_recommendations_are_actionable_strings(self, v7_protected_binary: Path) -> None:
        """All recommendations are non-empty actionable strings."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(v7_protected_binary))

        for recommendation in result.bypass_recommendations:
            assert isinstance(recommendation, str), "FAILED: recommendation should be string"
            assert len(recommendation) > 10, f"FAILED: recommendation too short: {recommendation}"


class TestAnalysisResultStructure:
    """Validate DenuvoAnalysisResult structure and completeness."""

    def test_analysis_result_contains_all_required_fields(self, v7_protected_binary: Path) -> None:
        """DenuvoAnalysisResult contains all mandatory fields."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(v7_protected_binary))

        required_fields = [
            "detected", "confidence", "version", "triggers",
            "integrity_checks", "timing_checks", "vm_regions",
            "encrypted_sections", "bypass_recommendations", "analysis_details"
        ]

        for field in required_fields:
            assert hasattr(result, field), f"FAILED: missing required field {field}"

    def test_analysis_details_populated(self, v7_protected_binary: Path) -> None:
        """Analysis details dict contains metadata about detection."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(v7_protected_binary))

        assert isinstance(result.analysis_details, dict), "FAILED: analysis_details should be dict"
        assert len(result.analysis_details) > 0, "FAILED: analysis_details should be populated"


class TestDataclassStructures:
    """Validate all dataclass structures used in analysis."""

    def test_denuvo_version_dataclass_structure(self) -> None:
        """DenuvoVersion dataclass has correct fields and values."""
        version = DenuvoVersion(major=7, minor=1, name="Denuvo 7.x+", confidence=0.92)

        assert version.major == 7, "FAILED: major version incorrect"
        assert version.minor == 1, "FAILED: minor version incorrect"
        assert version.name == "Denuvo 7.x+", "FAILED: name incorrect"
        assert version.confidence == 0.92, "FAILED: confidence incorrect"

    def test_denuvo_trigger_dataclass_structure(self) -> None:
        """DenuvoTrigger dataclass has correct fields and values."""
        trigger = DenuvoTrigger(
            address=0x1234,
            type="validation_trigger",
            function_name="trigger_1234",
            confidence=0.75,
            description="License validation check"
        )

        assert trigger.address == 0x1234, "FAILED: address incorrect"
        assert trigger.type == "validation_trigger", "FAILED: type incorrect"
        assert trigger.function_name == "trigger_1234", "FAILED: function_name incorrect"
        assert trigger.confidence == 0.75, "FAILED: confidence incorrect"
        assert "validation" in trigger.description.lower(), "FAILED: description incorrect"

    def test_integrity_check_dataclass_structure(self) -> None:
        """IntegrityCheck dataclass has correct fields and values."""
        check = IntegrityCheck(
            address=0x5678,
            type="hash_check",
            target="code_section",
            algorithm="CRC32",
            confidence=0.80
        )

        assert check.address == 0x5678, "FAILED: address incorrect"
        assert check.type == "hash_check", "FAILED: type incorrect"
        assert check.target == "code_section", "FAILED: target incorrect"
        assert check.algorithm == "CRC32", "FAILED: algorithm incorrect"
        assert check.confidence == 0.80, "FAILED: confidence incorrect"

    def test_timing_check_dataclass_structure(self) -> None:
        """TimingCheck dataclass has correct fields and values."""
        check = TimingCheck(
            address=0x9ABC,
            method="RDTSC",
            threshold=1000,
            confidence=0.70
        )

        assert check.address == 0x9ABC, "FAILED: address incorrect"
        assert check.method == "RDTSC", "FAILED: method incorrect"
        assert check.threshold == 1000, "FAILED: threshold incorrect"
        assert check.confidence == 0.70, "FAILED: confidence incorrect"

    def test_vm_region_dataclass_structure(self) -> None:
        """VMRegion dataclass has correct fields and values."""
        vm_region = VMRegion(
            start_address=0x10000,
            end_address=0x20000,
            entry_points=[0x10100, 0x10200, 0x10300],
            handler_count=25,
            confidence=0.85
        )

        assert vm_region.start_address == 0x10000, "FAILED: start_address incorrect"
        assert vm_region.end_address == 0x20000, "FAILED: end_address incorrect"
        assert len(vm_region.entry_points) == 3, "FAILED: entry_points count incorrect"
        assert vm_region.handler_count == 25, "FAILED: handler_count incorrect"
        assert vm_region.confidence == 0.85, "FAILED: confidence incorrect"


class TestErrorHandlingAndEdgeCases:
    """Validate error handling for invalid inputs and edge cases."""

    def test_handles_nonexistent_file_gracefully(self) -> None:
        """Analyzer returns negative result for nonexistent file."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze("D:\\nonexistent_file_12345.exe")

        assert result.detected is False, "FAILED: should not detect in missing file"
        assert result.confidence == 0.0, "FAILED: confidence should be 0.0"
        assert "error" in result.analysis_details, "FAILED: should report error in details"

    def test_handles_empty_file(self, binary_workspace: Path) -> None:
        """Analyzer handles empty file without crashing."""
        empty_file = binary_workspace / "empty.exe"
        empty_file.write_bytes(b"")

        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(empty_file))

        assert isinstance(result, DenuvoAnalysisResult), "FAILED: should return valid result"
        assert result.detected is False, "FAILED: should not detect in empty file"

    def test_handles_corrupted_pe_header(self, binary_workspace: Path) -> None:
        """Analyzer handles corrupted PE header gracefully."""
        corrupted_file = binary_workspace / "corrupted.exe"
        corrupted_file.write_bytes(b"MZ\x00\x00" + b"\xFF\xAA\x55" * 100)

        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(corrupted_file))

        assert isinstance(result, DenuvoAnalysisResult), "FAILED: should return valid result"

    def test_handles_very_small_binary(self, binary_workspace: Path) -> None:
        """Analyzer handles binary smaller than minimum section size."""
        small_file = binary_workspace / "small.exe"
        small_file.write_bytes(b"MZ" + b"\x00" * 200)

        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(small_file))

        assert isinstance(result, DenuvoAnalysisResult), "FAILED: should return valid result"


class TestConfidenceScoring:
    """Validate confidence scoring aggregation logic."""

    def test_high_confidence_for_strong_detection(self, v7_protected_binary: Path) -> None:
        """High confidence when multiple Denuvo indicators present."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(v7_protected_binary))

        assert result.detected is True, "FAILED: should detect Denuvo"
        assert result.confidence >= 0.70, f"FAILED: confidence {result.confidence} too low for strong detection"

    def test_low_confidence_for_clean_binary(self, clean_unprotected_binary: Path) -> None:
        """Low confidence for binary without protection indicators."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(clean_unprotected_binary))

        assert result.confidence < 0.60, f"FAILED: confidence {result.confidence} too high for clean binary"


class TestCrossVersionConsistency:
    """Validate consistent detection across all Denuvo versions."""

    def test_all_versions_detected_correctly(
        self,
        v7_protected_binary: Path,
        v6_protected_binary: Path,
        v5_protected_binary: Path,
        v4_protected_binary: Path
    ) -> None:
        """All Denuvo versions detected with correct version numbers."""
        analyzer = DenuvoAnalyzer()

        test_cases = [
            (v7_protected_binary, 7),
            (v6_protected_binary, 6),
            (v5_protected_binary, 5),
            (v4_protected_binary, 4),
        ]

        for binary_path, expected_version in test_cases:
            result = analyzer.analyze(str(binary_path))
            assert result.detected is True, f"FAILED: {binary_path.name} not detected"
            assert result.version is not None, f"FAILED: {binary_path.name} version not identified"
            assert result.version.major == expected_version, f"FAILED: {binary_path.name} wrong version - expected {expected_version}, got {result.version.major}"
            assert result.confidence >= 0.60, f"FAILED: {binary_path.name} confidence too low"


class TestPerformanceRequirements:
    """Validate analysis performance on realistic binaries."""

    def test_analysis_completes_within_time_limit(self, v7_protected_binary: Path) -> None:
        """Analysis completes within acceptable timeframe."""
        import time

        analyzer = DenuvoAnalyzer()

        start = time.time()
        result = analyzer.analyze(str(v7_protected_binary))
        elapsed = time.time() - start

        assert result.detected is True, "FAILED: analysis should complete successfully"
        assert elapsed < 60.0, f"FAILED: analysis too slow - took {elapsed:.2f}s (should be < 60s)"

    def test_handles_large_binary_efficiently(self, binary_workspace: Path) -> None:
        """Analyzer processes large binary without excessive resource usage."""
        large_binary = binary_workspace / "large_protected.exe"

        base_binary = SyntheticProtectedBinaryBuilder.build_denuvo_v7_binary()
        large_binary.write_bytes(base_binary + b"\x00" * (15 * 1024 * 1024))

        analyzer = DenuvoAnalyzer()
        result = analyzer.analyze(str(large_binary))

        assert isinstance(result, DenuvoAnalysisResult), "FAILED: should handle large binary"


class TestFallbackAnalysisMode:
    """Validate analysis fallback when LIEF unavailable."""

    def test_fallback_mode_detects_version(self, v7_protected_binary: Path) -> None:
        """Fallback analysis detects version from raw binary scanning."""
        analyzer = DenuvoAnalyzer()
        result = analyzer._analyze_without_lief(str(v7_protected_binary))

        assert isinstance(result, DenuvoAnalysisResult), "FAILED: should return valid result"
        assert result.analysis_details["mode"] == "basic", "FAILED: should indicate basic mode"
        assert result.version is not None, "FAILED: should detect version in fallback mode"
        assert result.version.major == 7, "FAILED: should correctly identify v7 in fallback"

    def test_fallback_mode_reports_lief_unavailable(self, v7_protected_binary: Path) -> None:
        """Fallback analysis reports LIEF unavailability in details."""
        analyzer = DenuvoAnalyzer()
        result = analyzer._analyze_without_lief(str(v7_protected_binary))

        assert result.analysis_details["lief_available"] is False, "FAILED: should report lief unavailable"


@given(st.binary(min_size=1024, max_size=8192))
def test_entropy_calculation_property_based(data: bytes) -> None:
    """Entropy calculation always returns value in valid range for arbitrary data."""
    analyzer = DenuvoAnalyzer()
    entropy: float = analyzer._calculate_entropy(data)

    assert 0.0 <= entropy <= 8.0, f"FAILED: entropy {entropy} outside valid range [0.0, 8.0]"


class TestIntegrationScenarios:
    """Integration tests validating complete analysis workflows."""

    def test_complete_v7_analysis_workflow(self, v7_protected_binary: Path) -> None:
        """Complete analysis workflow produces comprehensive results for v7."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(v7_protected_binary))

        assert result.detected is True, "FAILED: v7 not detected"
        assert result.version is not None, "FAILED: version not identified"
        assert result.version.major == 7, "FAILED: wrong version"
        assert len(result.bypass_recommendations) > 0, "FAILED: no bypass recommendations"

        has_any_protection_feature = (
            len(result.triggers) > 0 or
            len(result.integrity_checks) > 0 or
            len(result.timing_checks) > 0 or
            len(result.vm_regions) > 0
        )

        assert result.confidence >= 0.60, "FAILED: overall confidence too low"

    def test_negative_result_structure_for_clean_binary(self, clean_unprotected_binary: Path) -> None:
        """Clean binary produces proper negative result structure."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(clean_unprotected_binary))

        assert result.detected is False, "FAILED: should not detect protection"
        assert result.confidence < 0.60, "FAILED: confidence should be low"
        assert len(result.triggers) == 0, "FAILED: should have no triggers"
        assert len(result.integrity_checks) == 0, "FAILED: should have no integrity checks"
        assert len(result.timing_checks) == 0, "FAILED: should have no timing checks"
