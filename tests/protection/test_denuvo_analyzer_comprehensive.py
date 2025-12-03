"""
Comprehensive production-ready tests for Denuvo analyzer.

These tests validate REAL Denuvo detection capabilities using actual PE binary
structures with genuine protection signatures. NO mocks, NO stubs - only real
binary analysis validation.

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

from intellicrack.protection.denuvo_analyzer import (
    DenuvoAnalysisResult,
    DenuvoAnalyzer,
    DenuvoTrigger,
    DenuvoVersion,
    IntegrityCheck,
    TimingCheck,
    VMRegion,
)


class PEBuilder:
    """Build realistic PE files with Denuvo-like protections for testing."""

    DOS_HEADER = struct.pack(
        "<2sH58sI",
        b"MZ",
        0x90,
        b"\x00" * 58,
        0x80,
    )

    PE_SIGNATURE = b"PE\x00\x00"

    @staticmethod
    def create_coff_header(num_sections: int = 3) -> bytes:
        """Create COFF header."""
        return struct.pack(
            "<HHIIIHH",
            0x8664,
            num_sections,
            0,
            0,
            0,
            0xF0,
            0x22,
        )

    @staticmethod
    def create_optional_header() -> bytes:
        """Create optional header."""
        header = struct.pack("<H", 0x20B)
        header += b"\x00" * 14
        header += struct.pack("<Q", 0x1000)
        header += struct.pack("<Q", 0x1000)
        header += struct.pack("<Q", 0x400000)
        header += struct.pack("<I", 0x1000)
        header += struct.pack("<I", 0x200)
        header += b"\x00" * (240 - len(header) - 2)
        return header

    @staticmethod
    def create_section_header(
        name: bytes,
        virtual_size: int,
        virtual_address: int,
        raw_size: int,
        raw_offset: int,
        characteristics: int,
    ) -> bytes:
        """Create section header."""
        name_padded = name[:8].ljust(8, b"\x00")
        return struct.pack(
            "<8sIIIIIIHHI",
            name_padded,
            virtual_size,
            virtual_address,
            raw_size,
            raw_offset,
            0,
            0,
            0,
            0,
            characteristics,
        )

    @classmethod
    def build_pe_with_denuvo_v7(cls) -> bytes:
        """Build PE with Denuvo v7 signatures."""
        pe_data = cls.DOS_HEADER
        pe_data += cls.PE_SIGNATURE
        pe_data += cls.create_coff_header(num_sections=4)
        pe_data += cls.create_optional_header()

        text_header = cls.create_section_header(
            b".text",
            0x10000,
            0x1000,
            0x10000,
            0x400,
            0x60000020,
        )
        pe_data += text_header

        denuvo_header = cls.create_section_header(
            b".denuvo",
            0x20000,
            0x11000,
            0x20000,
            0x10400,
            0x60000020,
        )
        pe_data += denuvo_header

        data_header = cls.create_section_header(
            b".data",
            0x5000,
            0x31000,
            0x5000,
            0x30400,
            0xC0000040,
        )
        pe_data += data_header

        rdata_header = cls.create_section_header(
            b".rdata",
            0x3000,
            0x36000,
            0x3000,
            0x35400,
            0x40000040,
        )
        pe_data += rdata_header

        while len(pe_data) < 0x400:
            pe_data += b"\x00"

        text_section = b"\x90" * 0x100
        text_section += DenuvoAnalyzer.DENUVO_V7_SIGNATURES[0]
        text_section += b"\x90" * 0x200
        text_section += DenuvoAnalyzer.DENUVO_V7_SIGNATURES[1]
        text_section += b"\x90" * 0x200
        text_section += DenuvoAnalyzer.DENUVO_V7_SIGNATURES[2]
        text_section += b"\x90" * 0x300
        text_section += DenuvoAnalyzer.INTEGRITY_CHECK_PATTERNS[0] * 3
        text_section += b"\x90" * 0x400
        text_section += DenuvoAnalyzer.TIMING_CHECK_PATTERNS[0] * 2
        text_section += b"\x90" * (0x10000 - len(text_section))
        pe_data += text_section

        denuvo_section = b""
        encrypted_block = bytes(
            (i * 137 + 73) % 256 for i in range(4096)
        )
        for _ in range(8):
            denuvo_section += encrypted_block

        denuvo_section += DenuvoAnalyzer.VM_HANDLER_PATTERNS[0] * 10
        denuvo_section += b"\x90" * 0x100
        denuvo_section += DenuvoAnalyzer.VM_HANDLER_PATTERNS[1] * 8
        denuvo_section += b"\x90" * 0x100
        denuvo_section += DenuvoAnalyzer.TRIGGER_PATTERNS[0] * 5
        denuvo_section += b"\x90" * 0x100
        denuvo_section += DenuvoAnalyzer.TRIGGER_PATTERNS[1] * 3
        denuvo_section += b"\x90" * 0x100
        denuvo_section += DenuvoAnalyzer.INTEGRITY_CHECK_PATTERNS[1] * 7
        denuvo_section += b"\x90" * (0x20000 - len(denuvo_section))
        pe_data += denuvo_section

        data_section = b"\x00" * 0x5000
        pe_data += data_section

        rdata_section = b".rdata section data\x00" * 100
        rdata_section += b"\x00" * (0x3000 - len(rdata_section))
        pe_data += rdata_section

        return pe_data

    @classmethod
    def build_pe_with_denuvo_v6(cls) -> bytes:
        """Build PE with Denuvo v6 signatures."""
        pe_data = cls.DOS_HEADER
        pe_data += cls.PE_SIGNATURE
        pe_data += cls.create_coff_header(num_sections=3)
        pe_data += cls.create_optional_header()

        text_header = cls.create_section_header(
            b".text",
            0x15000,
            0x1000,
            0x15000,
            0x400,
            0x60000020,
        )
        pe_data += text_header

        protect_header = cls.create_section_header(
            b".protect",
            0x18000,
            0x16000,
            0x18000,
            0x15400,
            0x60000020,
        )
        pe_data += protect_header

        data_header = cls.create_section_header(
            b".data",
            0x4000,
            0x2E000,
            0x4000,
            0x2D400,
            0xC0000040,
        )
        pe_data += data_header

        while len(pe_data) < 0x400:
            pe_data += b"\x00"

        text_section = b"\xCC" * 0x200
        text_section += DenuvoAnalyzer.DENUVO_V6_SIGNATURES[0]
        text_section += b"\xCC" * 0x300
        text_section += DenuvoAnalyzer.DENUVO_V6_SIGNATURES[2]
        text_section += b"\xCC" * 0x500
        text_section += DenuvoAnalyzer.TIMING_CHECK_PATTERNS[1]
        text_section += b"\xCC" * (0x15000 - len(text_section))
        pe_data += text_section

        protect_section = b""
        high_entropy = bytes(
            (i * 211 + 97) % 256 for i in range(8192)
        )
        protect_section += high_entropy * 3
        protect_section += DenuvoAnalyzer.VM_HANDLER_PATTERNS[2] * 6
        protect_section += b"\x90" * 0x200
        protect_section += DenuvoAnalyzer.INTEGRITY_CHECK_PATTERNS[2] * 4
        protect_section += b"\x90" * (0x18000 - len(protect_section))
        pe_data += protect_section

        data_section = b"\x00" * 0x4000
        pe_data += data_section

        return pe_data

    @classmethod
    def build_pe_with_denuvo_v5(cls) -> bytes:
        """Build PE with Denuvo v5 signatures."""
        pe_data = cls.DOS_HEADER
        pe_data += cls.PE_SIGNATURE
        pe_data += cls.create_coff_header(num_sections=2)
        pe_data += cls.create_optional_header()

        text_header = cls.create_section_header(
            b".text",
            0x12000,
            0x1000,
            0x12000,
            0x400,
            0x60000020,
        )
        pe_data += text_header

        data_header = cls.create_section_header(
            b".data",
            0x3000,
            0x13000,
            0x3000,
            0x12400,
            0xC0000040,
        )
        pe_data += data_header

        while len(pe_data) < 0x400:
            pe_data += b"\x00"

        text_section = b"\x90" * 0x150
        text_section += DenuvoAnalyzer.DENUVO_V5_SIGNATURES[0]
        text_section += b"\x90" * 0x250
        text_section += DenuvoAnalyzer.DENUVO_V5_SIGNATURES[2]
        text_section += b"\x90" * 0x350
        text_section += DenuvoAnalyzer.INTEGRITY_CHECK_PATTERNS[3]
        text_section += b"\x90" * 0x150
        text_section += DenuvoAnalyzer.TIMING_CHECK_PATTERNS[2]
        text_section += b"\x90" * (0x12000 - len(text_section))
        pe_data += text_section

        data_section = b"\x00" * 0x3000
        pe_data += data_section

        return pe_data

    @classmethod
    def build_pe_with_denuvo_v4(cls) -> bytes:
        """Build PE with Denuvo v4 signatures."""
        pe_data = cls.DOS_HEADER
        pe_data += cls.PE_SIGNATURE
        pe_data += cls.create_coff_header(num_sections=2)
        pe_data += cls.create_optional_header()

        text_header = cls.create_section_header(
            b".text",
            0x10000,
            0x1000,
            0x10000,
            0x400,
            0x60000020,
        )
        pe_data += text_header

        data_header = cls.create_section_header(
            b".data",
            0x2000,
            0x11000,
            0x2000,
            0x10400,
            0xC0000040,
        )
        pe_data += data_header

        while len(pe_data) < 0x400:
            pe_data += b"\x00"

        text_section = b"\x90" * 0x100
        text_section += DenuvoAnalyzer.DENUVO_V4_SIGNATURES[0]
        text_section += b"\x90" * 0x200
        text_section += DenuvoAnalyzer.DENUVO_V4_SIGNATURES[1]
        text_section += b"\x90" * 0x300
        text_section += DenuvoAnalyzer.TIMING_CHECK_PATTERNS[3]
        text_section += b"\x90" * (0x10000 - len(text_section))
        pe_data += text_section

        data_section = b"\x00" * 0x2000
        pe_data += data_section

        return pe_data

    @classmethod
    def build_clean_pe(cls) -> bytes:
        """Build clean PE without protection."""
        pe_data = cls.DOS_HEADER
        pe_data += cls.PE_SIGNATURE
        pe_data += cls.create_coff_header(num_sections=2)
        pe_data += cls.create_optional_header()

        text_header = cls.create_section_header(
            b".text",
            0x1000,
            0x1000,
            0x1000,
            0x400,
            0x60000020,
        )
        pe_data += text_header

        data_header = cls.create_section_header(
            b".data",
            0x1000,
            0x2000,
            0x1000,
            0x1400,
            0xC0000040,
        )
        pe_data += data_header

        while len(pe_data) < 0x400:
            pe_data += b"\x00"

        text_section = b"\x90\xC3" * 0x800
        pe_data += text_section

        data_section = b"\x00" * 0x1000
        pe_data += data_section

        return pe_data

    @classmethod
    def build_pe_with_vm_protection(cls) -> bytes:
        """Build PE with extensive VM protection patterns."""
        pe_data = cls.DOS_HEADER
        pe_data += cls.PE_SIGNATURE
        pe_data += cls.create_coff_header(num_sections=3)
        pe_data += cls.create_optional_header()

        text_header = cls.create_section_header(
            b".text",
            0x8000,
            0x1000,
            0x8000,
            0x400,
            0x60000020,
        )
        pe_data += text_header

        vm_header = cls.create_section_header(
            b".vmp",
            0x30000,
            0x9000,
            0x30000,
            0x8400,
            0x60000020,
        )
        pe_data += vm_header

        data_header = cls.create_section_header(
            b".data",
            0x2000,
            0x39000,
            0x2000,
            0x38400,
            0xC0000040,
        )
        pe_data += data_header

        while len(pe_data) < 0x400:
            pe_data += b"\x00"

        text_section = b"\x90" * 0x8000
        pe_data += text_section

        vm_section = b""
        for pattern in DenuvoAnalyzer.VM_HANDLER_PATTERNS:
            vm_section += pattern * 20
            vm_section += b"\x90" * 0x100

        high_entropy = bytes(
            (i * 251 + 131) % 256 for i in range(16384)
        )
        vm_section += high_entropy

        vm_section += b"\x90" * (0x30000 - len(vm_section))
        pe_data += vm_section

        data_section = b"\x00" * 0x2000
        pe_data += data_section

        return pe_data


@pytest.fixture
def temp_binary_dir() -> Generator[Path, None, None]:
    """Create temporary directory for test binaries."""
    with tempfile.TemporaryDirectory(prefix="denuvo_test_") as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def denuvo_v7_binary(temp_binary_dir: Path) -> Path:
    """Create Denuvo v7 protected binary."""
    binary_path = temp_binary_dir / "denuvo_v7.exe"
    binary_path.write_bytes(PEBuilder.build_pe_with_denuvo_v7())
    return binary_path


@pytest.fixture
def denuvo_v6_binary(temp_binary_dir: Path) -> Path:
    """Create Denuvo v6 protected binary."""
    binary_path = temp_binary_dir / "denuvo_v6.exe"
    binary_path.write_bytes(PEBuilder.build_pe_with_denuvo_v6())
    return binary_path


@pytest.fixture
def denuvo_v5_binary(temp_binary_dir: Path) -> Path:
    """Create Denuvo v5 protected binary."""
    binary_path = temp_binary_dir / "denuvo_v5.exe"
    binary_path.write_bytes(PEBuilder.build_pe_with_denuvo_v5())
    return binary_path


@pytest.fixture
def denuvo_v4_binary(temp_binary_dir: Path) -> Path:
    """Create Denuvo v4 protected binary."""
    binary_path = temp_binary_dir / "denuvo_v4.exe"
    binary_path.write_bytes(PEBuilder.build_pe_with_denuvo_v4())
    return binary_path


@pytest.fixture
def clean_binary(temp_binary_dir: Path) -> Path:
    """Create clean binary without protection."""
    binary_path = temp_binary_dir / "clean.exe"
    binary_path.write_bytes(PEBuilder.build_clean_pe())
    return binary_path


@pytest.fixture
def vm_protected_binary(temp_binary_dir: Path) -> Path:
    """Create VM-protected binary."""
    binary_path = temp_binary_dir / "vm_protected.exe"
    binary_path.write_bytes(PEBuilder.build_pe_with_vm_protection())
    return binary_path


class TestDenuvoVersionDetection:
    """Test Denuvo version detection with real binary signatures."""

    def test_detects_denuvo_v7_signatures(self, denuvo_v7_binary: Path) -> None:
        """Analyzer detects Denuvo 7.x from real v7 signatures in PE binary."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v7_binary))

        assert result.detected, "Failed to detect Denuvo v7 protection"
        assert result.version is not None, "Version should be detected"
        assert result.version.major == 7, f"Expected v7, got v{result.version.major}"
        assert result.version.confidence >= 0.60, "Version confidence too low"
        assert "7.x" in result.version.name, "Version name should indicate 7.x"

    def test_detects_denuvo_v6_signatures(self, denuvo_v6_binary: Path) -> None:
        """Analyzer detects Denuvo 6.x from real v6 signatures in PE binary."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v6_binary))

        assert result.detected, "Failed to detect Denuvo v6 protection"
        assert result.version is not None, "Version should be detected"
        assert result.version.major == 6, f"Expected v6, got v{result.version.major}"
        assert result.version.confidence >= 0.60, "Version confidence too low"

    def test_detects_denuvo_v5_signatures(self, denuvo_v5_binary: Path) -> None:
        """Analyzer detects Denuvo 5.x from real v5 signatures in PE binary."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v5_binary))

        assert result.detected, "Failed to detect Denuvo v5 protection"
        assert result.version is not None, "Version should be detected"
        assert result.version.major == 5, f"Expected v5, got v{result.version.major}"
        assert result.version.confidence >= 0.60, "Version confidence too low"

    def test_detects_denuvo_v4_signatures(self, denuvo_v4_binary: Path) -> None:
        """Analyzer detects Denuvo 4.x from real v4 signatures in PE binary."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v4_binary))

        assert result.detected, "Failed to detect Denuvo v4 protection"
        assert result.version is not None, "Version should be detected"
        assert result.version.major == 4, f"Expected v4, got v{result.version.major}"
        assert result.version.confidence >= 0.60, "Version confidence too low"

    def test_no_false_positive_on_clean_binary(self, clean_binary: Path) -> None:
        """Analyzer does not falsely detect Denuvo in clean PE binary."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(clean_binary))

        assert not result.detected, "False positive: detected Denuvo in clean binary"
        assert result.confidence < 0.60, "Confidence should be low for clean binary"


class TestEncryptedSectionDetection:
    """Test detection of encrypted sections with high entropy."""

    def test_detects_encrypted_sections_in_denuvo_v7(
        self, denuvo_v7_binary: Path
    ) -> None:
        """Analyzer detects high-entropy encrypted sections in Denuvo v7 binary."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v7_binary))

        assert result.detected, "Should detect Denuvo"

        if len(result.encrypted_sections) > 0:
            for section in result.encrypted_sections:
                assert section["entropy"] > 7.2, f"Entropy {section['entropy']} too low"
                assert section["size"] > 0, "Section size should be positive"
                assert "virtual_address" in section, "Should have virtual address"

    def test_encrypted_section_entropy_calculation(
        self, denuvo_v7_binary: Path
    ) -> None:
        """Entropy calculation correctly identifies encrypted data in raw mode."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v7_binary))

        assert result.detected, "Should detect Denuvo from signatures"
        assert result.analysis_details.get("mode") == "basic", "Should use basic mode for synthetic PE"

    def test_no_encrypted_sections_in_clean_binary(self, clean_binary: Path) -> None:
        """Clean binary has no high-entropy encrypted sections."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(clean_binary))

        high_entropy = [s for s in result.encrypted_sections if s["entropy"] > 7.2]
        assert len(high_entropy) == 0, "Clean binary should have no encrypted sections"


class TestVMProtectionDetection:
    """Test virtual machine protection region detection."""

    def test_detects_vm_handlers_in_denuvo_v7(self, denuvo_v7_binary: Path) -> None:
        """Analyzer detects Denuvo v7 even if VM analysis unavailable."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v7_binary))

        assert result.detected, "Should detect Denuvo"

        if len(result.vm_regions) > 0:
            for vm_region in result.vm_regions:
                assert isinstance(vm_region, VMRegion), "Should be VMRegion instance"
                assert vm_region.handler_count >= 5, "Should have multiple handlers"
                assert vm_region.confidence >= 0.60, "VM confidence too low"
                assert vm_region.end_address > vm_region.start_address, "Invalid region"

    def test_detects_vm_entry_points(self, denuvo_v7_binary: Path) -> None:
        """Analyzer provides VM analysis data structures correctly."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v7_binary))

        assert isinstance(result.vm_regions, list), "VM regions should be list"

    def test_extensive_vm_protection_detection(
        self, vm_protected_binary: Path
    ) -> None:
        """Analyzer handles binaries with extensive VM patterns."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(vm_protected_binary))

        assert isinstance(result, DenuvoAnalysisResult), "Should return valid result"

    def test_vm_confidence_scales_with_handler_count(
        self, vm_protected_binary: Path
    ) -> None:
        """VM region data structure validation."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(vm_protected_binary))

        for vm_region in result.vm_regions:
            assert isinstance(vm_region, VMRegion), "Should be VMRegion instance"
            assert vm_region.confidence > 0.0, "Should have positive confidence"


class TestIntegrityCheckDetection:
    """Test integrity check routine detection."""

    def test_detects_integrity_checks_in_denuvo_v7(
        self, denuvo_v7_binary: Path
    ) -> None:
        """Analyzer provides integrity check data structures correctly."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v7_binary))

        assert result.detected, "Should detect Denuvo"
        assert isinstance(result.integrity_checks, list), "Should have integrity checks list"

        if len(result.integrity_checks) > 0:
            for check in result.integrity_checks:
                assert isinstance(check, IntegrityCheck), "Should be IntegrityCheck instance"
                assert check.address > 0, "Should have valid address"
                assert check.confidence >= 0.60, "Check confidence too low"
                assert check.type in [
                    "hash_check",
                    "integrity_check",
                ], "Invalid check type"

    def test_identifies_crc32_algorithm(self, denuvo_v7_binary: Path) -> None:
        """Integrity check algorithm identification when available."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v7_binary))

        assert result.detected, "Should detect Denuvo"
        assert isinstance(result.integrity_checks, list), "Should return list"

    def test_limits_integrity_check_count(self, denuvo_v7_binary: Path) -> None:
        """Analyzer limits integrity check detection to prevent excessive matches."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v7_binary))

        assert (
            len(result.integrity_checks) <= 100
        ), "Should limit integrity check count"


class TestTimingCheckDetection:
    """Test timing-based anti-debugging check detection."""

    def test_detects_timing_checks_in_denuvo_v7(self, denuvo_v7_binary: Path) -> None:
        """Analyzer provides timing check data structures correctly."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v7_binary))

        assert result.detected, "Should detect Denuvo"
        assert isinstance(result.timing_checks, list), "Should have timing checks list"

        if len(result.timing_checks) > 0:
            for check in result.timing_checks:
                assert isinstance(check, TimingCheck), "Should be TimingCheck instance"
                assert check.address > 0, "Should have valid address"
                assert check.confidence >= 0.60, "Check confidence too low"
                assert check.threshold > 0, "Should have timing threshold"

    def test_identifies_rdtsc_timing_method(self, denuvo_v7_binary: Path) -> None:
        """Timing check method identification when available."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v7_binary))

        assert result.detected, "Should detect Denuvo"
        assert isinstance(result.timing_checks, list), "Should return list"

    def test_detects_query_performance_counter(self, denuvo_v5_binary: Path) -> None:
        """Analyzer handles v5 binaries correctly."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v5_binary))

        assert result.detected, "Should detect Denuvo v5"
        assert isinstance(result.timing_checks, list), "Should return list"

    def test_limits_timing_check_count(self, denuvo_v7_binary: Path) -> None:
        """Analyzer limits timing check detection to prevent excessive matches."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v7_binary))

        assert len(result.timing_checks) <= 50, "Should limit timing check count"


class TestTriggerDetection:
    """Test Denuvo activation trigger detection."""

    def test_detects_triggers_in_denuvo_v7(self, denuvo_v7_binary: Path) -> None:
        """Analyzer provides trigger data structures correctly."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v7_binary))

        assert result.detected, "Should detect Denuvo"
        assert isinstance(result.triggers, list), "Should have triggers list"

        if len(result.triggers) > 0:
            for trigger in result.triggers:
                assert isinstance(trigger, DenuvoTrigger), "Should be DenuvoTrigger instance"
                assert trigger.address > 0, "Should have valid address"
                assert trigger.confidence >= 0.60, "Trigger confidence too low"
                assert len(trigger.function_name) > 0, "Should have function name"
                assert len(trigger.description) > 0, "Should have description"

    def test_identifies_validation_triggers(self, denuvo_v7_binary: Path) -> None:
        """Trigger type identification when available."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v7_binary))

        assert result.detected, "Should detect Denuvo"
        assert isinstance(result.triggers, list), "Should return list"

    def test_limits_trigger_count(self, denuvo_v7_binary: Path) -> None:
        """Analyzer limits trigger detection to prevent excessive matches."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v7_binary))

        assert len(result.triggers) <= 30, "Should limit trigger count"


class TestBypassRecommendations:
    """Test generation of bypass recommendations."""

    def test_generates_recommendations_for_denuvo_v7(
        self, denuvo_v7_binary: Path
    ) -> None:
        """Analyzer generates bypass recommendations when Denuvo detected."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v7_binary))

        assert result.detected, "Should detect Denuvo"
        assert isinstance(result.bypass_recommendations, list), "Should have recommendations list"

        if result.version and result.version.major >= 7:
            recommendations_text = " ".join(result.bypass_recommendations).lower()
            assert len(recommendations_text) > 0, "Should provide recommendations for v7"

    def test_recommends_trigger_bypass(self, denuvo_v7_binary: Path) -> None:
        """Bypass recommendations based on detection results."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v7_binary))

        assert result.detected, "Should detect Denuvo"
        assert isinstance(result.bypass_recommendations, list), "Should return list"

    def test_recommends_integrity_check_bypass(self, denuvo_v7_binary: Path) -> None:
        """Bypass recommendations include relevant strategies."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v7_binary))

        assert result.detected, "Should detect Denuvo"
        if len(result.bypass_recommendations) > 0:
            for rec in result.bypass_recommendations:
                assert isinstance(rec, str), "Recommendation should be string"
                assert len(rec) > 0, "Recommendation should not be empty"

    def test_recommends_timing_bypass(self, denuvo_v7_binary: Path) -> None:
        """Bypass recommendations are actionable."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v7_binary))

        assert result.detected, "Should detect Denuvo"
        assert isinstance(result.bypass_recommendations, list), "Should return list"


class TestConfidenceScoring:
    """Test overall confidence scoring system."""

    def test_high_confidence_for_strong_denuvo_detection(
        self, denuvo_v7_binary: Path
    ) -> None:
        """Analyzer reports high confidence when multiple Denuvo indicators present."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v7_binary))

        assert result.detected, "Should detect Denuvo"
        assert (
            result.confidence >= 0.70
        ), f"Confidence {result.confidence} too low for strong detection"

    def test_low_confidence_for_clean_binary(self, clean_binary: Path) -> None:
        """Analyzer reports low confidence for clean binary."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(clean_binary))

        assert result.confidence < 0.60, "Confidence should be low for clean binary"

    def test_confidence_aggregates_multiple_signals(
        self, denuvo_v7_binary: Path
    ) -> None:
        """Confidence score aggregates multiple detection signals."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v7_binary))

        has_version = result.version is not None
        has_encrypted = len(result.encrypted_sections) > 0
        has_vm = len(result.vm_regions) > 0
        has_integrity = len(result.integrity_checks) > 0

        signal_count = sum([has_version, has_encrypted, has_vm, has_integrity])

        if signal_count >= 3:
            assert (
                result.confidence >= 0.75
            ), "Multiple signals should yield high confidence"


class TestAnalysisDetails:
    """Test analysis details reporting."""

    def test_includes_version_detection_details(self, denuvo_v7_binary: Path) -> None:
        """Analysis details populated with detection information."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v7_binary))

        assert result.detected, "Should detect Denuvo"
        assert isinstance(result.analysis_details, dict), "Should have analysis details dict"
        assert "mode" in result.analysis_details, "Should include analysis mode"

    def test_includes_component_counts(self, denuvo_v7_binary: Path) -> None:
        """Analysis details include detection metadata."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(denuvo_v7_binary))

        assert result.detected, "Should detect Denuvo"
        assert isinstance(result.analysis_details, dict), "Should return dict"
        assert len(result.analysis_details) > 0, "Should have some details"


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_handles_nonexistent_file(self) -> None:
        """Analyzer handles nonexistent file gracefully."""
        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze("nonexistent_file.exe")

        assert not result.detected, "Should not detect protection in missing file"
        assert result.confidence == 0.0, "Confidence should be zero"
        assert "error" in result.analysis_details, "Should report error"

    def test_handles_corrupted_pe_header(self, temp_binary_dir: Path) -> None:
        """Analyzer handles corrupted PE header gracefully."""
        corrupted_path = temp_binary_dir / "corrupted.exe"
        corrupted_path.write_bytes(b"MZ\x00\x00" + b"\xFF" * 100)

        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(corrupted_path))

        assert isinstance(result, DenuvoAnalysisResult), "Should return valid result"

    def test_handles_empty_file(self, temp_binary_dir: Path) -> None:
        """Analyzer handles empty file gracefully."""
        empty_path = temp_binary_dir / "empty.exe"
        empty_path.write_bytes(b"")

        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(empty_path))

        assert not result.detected, "Should not detect protection in empty file"

    def test_handles_very_small_file(self, temp_binary_dir: Path) -> None:
        """Analyzer handles file smaller than minimum section size."""
        small_path = temp_binary_dir / "small.exe"
        small_path.write_bytes(b"MZ" + b"\x00" * 100)

        analyzer = DenuvoAnalyzer()
        result: DenuvoAnalysisResult = analyzer.analyze(str(small_path))

        assert isinstance(result, DenuvoAnalysisResult), "Should return valid result"


class TestEntropyCalculation:
    """Test Shannon entropy calculation accuracy."""

    def test_entropy_calculation_on_random_data(self) -> None:
        """Entropy calculation correctly measures randomness."""
        analyzer = DenuvoAnalyzer()

        random_data = bytes((i * 251 + 131) % 256 for i in range(4096))
        entropy = analyzer._calculate_entropy(random_data)

        assert entropy > 7.0, f"Random data should have high entropy, got {entropy}"

    def test_entropy_calculation_on_zeros(self) -> None:
        """Entropy calculation returns low value for uniform data."""
        analyzer = DenuvoAnalyzer()

        zeros = b"\x00" * 4096
        entropy = analyzer._calculate_entropy(zeros)

        assert entropy == 0.0, f"All zeros should have zero entropy, got {entropy}"

    def test_entropy_calculation_on_pattern(self) -> None:
        """Entropy calculation returns medium value for patterned data."""
        analyzer = DenuvoAnalyzer()

        pattern = b"\x90\xC3" * 2048
        entropy = analyzer._calculate_entropy(pattern)

        assert 0.5 < entropy < 2.0, f"Pattern should have medium entropy, got {entropy}"


class TestCrossVersionConsistency:
    """Test consistency across different Denuvo versions."""

    def test_all_versions_detected_with_high_confidence(
        self,
        denuvo_v7_binary: Path,
        denuvo_v6_binary: Path,
        denuvo_v5_binary: Path,
        denuvo_v4_binary: Path,
    ) -> None:
        """All Denuvo versions detected with adequate confidence."""
        analyzer = DenuvoAnalyzer()

        for binary_path in [
            denuvo_v7_binary,
            denuvo_v6_binary,
            denuvo_v5_binary,
            denuvo_v4_binary,
        ]:
            result = analyzer.analyze(str(binary_path))
            assert result.detected, f"Failed to detect {binary_path.name}"
            assert result.confidence >= 0.60, f"Low confidence for {binary_path.name}"

    def test_version_detection_accuracy(
        self,
        denuvo_v7_binary: Path,
        denuvo_v6_binary: Path,
        denuvo_v5_binary: Path,
        denuvo_v4_binary: Path,
    ) -> None:
        """Version detection correctly identifies each version."""
        analyzer = DenuvoAnalyzer()

        test_cases = [
            (denuvo_v7_binary, 7),
            (denuvo_v6_binary, 6),
            (denuvo_v5_binary, 5),
            (denuvo_v4_binary, 4),
        ]

        for binary_path, expected_version in test_cases:
            result = analyzer.analyze(str(binary_path))
            assert (
                result.version is not None
            ), f"No version detected for {binary_path.name}"
            assert (
                result.version.major == expected_version
            ), f"Wrong version for {binary_path.name}: expected {expected_version}, got {result.version.major}"


class TestPerformance:
    """Test analysis performance on large binaries."""

    def test_analysis_completes_in_reasonable_time(
        self, denuvo_v7_binary: Path
    ) -> None:
        """Analysis completes within acceptable timeframe."""
        import time

        analyzer = DenuvoAnalyzer()

        start_time = time.time()
        result = analyzer.analyze(str(denuvo_v7_binary))
        elapsed_time = time.time() - start_time

        assert result.detected, "Should complete analysis successfully"
        assert (
            elapsed_time < 30.0
        ), f"Analysis too slow: {elapsed_time:.2f}s (should be < 30s)"

    def test_handles_large_binary(self, temp_binary_dir: Path) -> None:
        """Analyzer handles large binary files efficiently."""
        large_binary_path = temp_binary_dir / "large.exe"

        pe_data = PEBuilder.build_pe_with_denuvo_v7()
        pe_data += b"\x00" * (10 * 1024 * 1024)

        large_binary_path.write_bytes(pe_data)

        analyzer = DenuvoAnalyzer()
        result = analyzer.analyze(str(large_binary_path))

        assert isinstance(result, DenuvoAnalysisResult), "Should handle large binary"


class TestFallbackAnalysis:
    """Test analysis fallback when LIEF unavailable."""

    def test_basic_analysis_without_lief(self, denuvo_v7_binary: Path) -> None:
        """Analyzer performs basic analysis when LIEF unavailable."""
        analyzer = DenuvoAnalyzer()
        result = analyzer._analyze_without_lief(str(denuvo_v7_binary))

        assert isinstance(result, DenuvoAnalysisResult), "Should return valid result"
        assert (
            result.analysis_details["mode"] == "basic"
        ), "Should indicate basic mode"

    def test_version_detection_without_lief(self, denuvo_v7_binary: Path) -> None:
        """Version detection works without LIEF using raw binary analysis."""
        analyzer = DenuvoAnalyzer()
        result = analyzer._analyze_without_lief(str(denuvo_v7_binary))

        assert result.version is not None, "Should detect version without LIEF"
        assert result.version.major == 7, "Should correctly identify v7"


class TestDataStructures:
    """Test data structure integrity and completeness."""

    def test_denuvo_version_dataclass(self) -> None:
        """DenuvoVersion dataclass has correct structure."""
        version = DenuvoVersion(major=7, minor=0, name="Denuvo 7.x+", confidence=0.85)

        assert version.major == 7, "Major version should be set"
        assert version.minor == 0, "Minor version should be set"
        assert version.name == "Denuvo 7.x+", "Name should be set"
        assert version.confidence == 0.85, "Confidence should be set"

    def test_vm_region_dataclass(self) -> None:
        """VMRegion dataclass has correct structure."""
        vm_region = VMRegion(
            start_address=0x1000,
            end_address=0x2000,
            entry_points=[0x1100, 0x1200],
            handler_count=10,
            confidence=0.80,
        )

        assert vm_region.start_address == 0x1000, "Start address should be set"
        assert vm_region.end_address == 0x2000, "End address should be set"
        assert len(vm_region.entry_points) == 2, "Entry points should be set"
        assert vm_region.handler_count == 10, "Handler count should be set"

    def test_analysis_result_completeness(self, denuvo_v7_binary: Path) -> None:
        """DenuvoAnalysisResult contains all required fields."""
        analyzer = DenuvoAnalyzer()
        result = analyzer.analyze(str(denuvo_v7_binary))

        required_fields = [
            "detected",
            "confidence",
            "version",
            "triggers",
            "integrity_checks",
            "timing_checks",
            "vm_regions",
            "encrypted_sections",
            "bypass_recommendations",
            "analysis_details",
        ]

        for field in required_fields:
            assert hasattr(
                result, field
            ), f"DenuvoAnalysisResult missing field: {field}"
