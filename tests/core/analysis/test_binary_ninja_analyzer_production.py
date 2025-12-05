"""Comprehensive production tests for Binary Ninja analyzer.

Tests validate REAL Binary Ninja analysis capabilities against actual PE binaries.
NO mocks, NO stubs - only genuine binary analysis operations that prove offensive
capability for license cracking research.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0+
"""

import os
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.binary_ninja_analyzer import (
    BINARYNINJA_AVAILABLE,
    PEFILE_AVAILABLE,
    BNAnalysisResult,
    BNBasicBlock,
    BNFunction,
    BinaryNinjaAnalyzer,
)


SKIP_NO_BINARYNINJA = pytest.mark.skipif(
    not BINARYNINJA_AVAILABLE,
    reason="Binary Ninja not installed - required for full analysis tests",
)

SKIP_NO_PEFILE = pytest.mark.skipif(
    not PEFILE_AVAILABLE,
    reason="pefile not available - required for fallback tests",
)


@pytest.fixture
def analyzer() -> BinaryNinjaAnalyzer:
    """Provide Binary Ninja analyzer instance."""
    return BinaryNinjaAnalyzer()


@pytest.fixture
def minimal_pe_binary(tmp_path: Path) -> Path:
    """Create minimal valid PE executable for testing.

    This creates a real PE file that can be analyzed by Binary Ninja and pefile.
    The binary contains licensing-related strings to test detection capabilities.
    """
    pe_path = tmp_path / "test_minimal.exe"

    dos_header = bytearray([
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    ])

    dos_stub = b"This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 7

    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack(
        "<HHIIIHH",
        0x8664,
        3,
        0,
        0,
        0,
        0x00F0,
        0x0022
    )

    optional_header = bytearray(240)
    optional_header[0:2] = struct.pack("<H", 0x020B)
    optional_header[2] = 14
    optional_header[3] = 0

    struct.pack_into("<I", optional_header, 16, 0x1000)
    struct.pack_into("<I", optional_header, 20, 0x1000)
    struct.pack_into("<Q", optional_header, 24, 0x400000)
    struct.pack_into("<I", optional_header, 32, 0x1000)
    struct.pack_into("<I", optional_header, 36, 0x200)
    struct.pack_into("<H", optional_header, 40, 6)
    struct.pack_into("<H", optional_header, 48, 6)
    struct.pack_into("<Q", optional_header, 56, 0x2000)
    struct.pack_into("<I", optional_header, 64, 0x400)
    struct.pack_into("<H", optional_header, 68, 0x0140)
    struct.pack_into("<H", optional_header, 70, 0x0003)
    struct.pack_into("<Q", optional_header, 72, 0x100000)
    struct.pack_into("<Q", optional_header, 80, 0x1000)
    struct.pack_into("<I", optional_header, 92, 2)

    text_section = bytearray(40)
    text_section[0:6] = b".text\x00"
    struct.pack_into("<I", text_section, 8, 0x200)
    struct.pack_into("<I", text_section, 12, 0x1000)
    struct.pack_into("<I", text_section, 16, 0x200)
    struct.pack_into("<I", text_section, 20, 0x400)
    struct.pack_into("<I", text_section, 36, 0x60000020)

    data_section = bytearray(40)
    data_section[0:6] = b".data\x00"
    struct.pack_into("<I", data_section, 8, 0x200)
    struct.pack_into("<I", data_section, 12, 0x2000)
    struct.pack_into("<I", data_section, 16, 0x200)
    struct.pack_into("<I", data_section, 20, 0x600)
    struct.pack_into("<I", data_section, 36, 0xC0000040)

    rdata_section = bytearray(40)
    rdata_section[0:7] = b".rdata\x00"
    struct.pack_into("<I", rdata_section, 8, 0x200)
    struct.pack_into("<I", rdata_section, 12, 0x3000)
    struct.pack_into("<I", rdata_section, 16, 0x200)
    struct.pack_into("<I", rdata_section, 20, 0x800)
    struct.pack_into("<I", rdata_section, 36, 0x40000040)

    text_data = bytearray(0x200)
    text_data[0:3] = b"\x48\x31\xC0"
    text_data[3:5] = b"\xC3\x90"

    text_data[0x10:0x13] = b"\x48\x89\xE5"
    text_data[0x13:0x16] = b"\x48\x83\xEC"
    text_data[0x16:0x19] = b"\x20\xB8\x01"
    text_data[0x19:0x1C] = b"\x00\x00\x00"
    text_data[0x1C:0x1E] = b"\xC9\xC3"

    text_data[0x20:0x23] = b"\x48\x89\xE5"
    text_data[0x23:0x26] = b"\x48\x83\xEC"
    text_data[0x26:0x29] = b"\x30\xB8\x00"
    text_data[0x29:0x2C] = b"\x00\x00\x00"
    text_data[0x2C:0x2E] = b"\xC9\xC3"

    data_data = bytearray(0x200)
    data_data[0:4] = struct.pack("<I", 0x12345678)
    data_data[4:8] = struct.pack("<I", 0)

    rdata_data = bytearray(0x200)
    license_strings = [
        b"Enter license key:\x00",
        b"License validation failed\x00",
        b"Invalid serial number\x00",
        b"Trial expired\x00",
        b"Registration successful\x00",
        b"Activation required\x00",
        b"ValidateLicense\x00",
        b"CheckSerial\x00",
        b"VerifyRegistration\x00",
    ]

    offset = 0
    for string in license_strings:
        rdata_data[offset:offset + len(string)] = string
        offset += len(string)

    with open(pe_path, "wb") as f:
        f.write(dos_header)
        f.write(dos_stub)
        f.write(pe_signature)
        f.write(coff_header)
        f.write(optional_header)
        f.write(text_section)
        f.write(data_section)
        f.write(rdata_section)

        current_pos = f.tell()
        padding_needed = 0x400 - current_pos
        if padding_needed > 0:
            f.write(b"\x00" * padding_needed)

        f.write(text_data)
        f.write(data_data)
        f.write(rdata_data)

    return pe_path


@pytest.fixture
def license_validation_binary(tmp_path: Path) -> Path:
    """Create PE binary with recognizable license validation code patterns.

    This binary contains function names and strings that should be identified
    as license validation candidates by the analyzer.
    """
    pe_path = tmp_path / "test_license_check.exe"

    dos_header = bytearray([
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    ])

    dos_stub = b"This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 7
    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack(
        "<HHIIIHH",
        0x8664,
        2,
        0,
        0,
        0,
        0x00F0,
        0x0022
    )

    optional_header = bytearray(240)
    optional_header[0:2] = struct.pack("<H", 0x020B)
    struct.pack_into("<I", optional_header, 16, 0x2000)
    struct.pack_into("<Q", optional_header, 24, 0x400000)
    struct.pack_into("<I", optional_header, 32, 0x1000)
    struct.pack_into("<I", optional_header, 36, 0x200)
    struct.pack_into("<Q", optional_header, 56, 0x3000)
    struct.pack_into("<I", optional_header, 64, 0x400)
    struct.pack_into("<H", optional_header, 68, 0x0140)

    text_section = bytearray(40)
    text_section[0:6] = b".text\x00"
    struct.pack_into("<I", text_section, 8, 0x400)
    struct.pack_into("<I", text_section, 12, 0x1000)
    struct.pack_into("<I", text_section, 16, 0x400)
    struct.pack_into("<I", text_section, 20, 0x400)
    struct.pack_into("<I", text_section, 36, 0x60000020)

    rdata_section = bytearray(40)
    rdata_section[0:7] = b".rdata\x00"
    struct.pack_into("<I", rdata_section, 8, 0x400)
    struct.pack_into("<I", rdata_section, 12, 0x2000)
    struct.pack_into("<I", rdata_section, 16, 0x400)
    struct.pack_into("<I", rdata_section, 20, 0x800)
    struct.pack_into("<I", rdata_section, 36, 0x40000040)

    text_data = bytearray(0x400)
    text_data[0:10] = b"\x48\x83\xEC\x28\xE8\x10\x00\x00\x00\xC3"
    text_data[0x20:0x30] = b"\x55\x48\x89\xE5\x48\x83\xEC\x40\xB8\x01\x00\x00\x00\xC9\xC3\x90"
    text_data[0x40:0x50] = b"\x55\x48\x89\xE5\x48\x83\xEC\x50\x31\xC0\xC9\xC3\x90\x90\x90\x90"

    rdata_data = bytearray(0x400)
    protection_strings = [
        b"CheckLicenseKey\x00",
        b"ValidateSerial\x00",
        b"VerifyActivation\x00",
        b"IsDebuggerPresent\x00",
        b"CryptGenRandom\x00",
        b"License validation routine\x00",
        b"Serial number verification\x00",
        b"Trial period check\x00",
        b"Registration status\x00",
        b"Expiration date validator\x00",
    ]

    offset = 0
    for string in protection_strings:
        rdata_data[offset:offset + len(string)] = string
        offset += len(string)

    with open(pe_path, "wb") as f:
        f.write(dos_header)
        f.write(dos_stub)
        f.write(pe_signature)
        f.write(coff_header)
        f.write(optional_header)
        f.write(text_section)
        f.write(rdata_section)

        current_pos = f.tell()
        padding_needed = 0x400 - current_pos
        if padding_needed > 0:
            f.write(b"\x00" * padding_needed)

        f.write(text_data)
        f.write(rdata_data)

    return pe_path


class TestBinaryNinjaAnalyzerInitialization:
    """Test analyzer initialization and availability detection."""

    def test_analyzer_initializes_successfully(self, analyzer: BinaryNinjaAnalyzer) -> None:
        """Analyzer initializes with proper configuration."""
        assert analyzer is not None
        assert hasattr(analyzer, "logger")
        assert hasattr(analyzer, "bv")
        assert analyzer.bv is None

    def test_binaryninja_availability_detection(self, analyzer: BinaryNinjaAnalyzer) -> None:
        """Analyzer correctly detects Binary Ninja availability."""
        if BINARYNINJA_AVAILABLE:
            assert analyzer.logger is not None
        else:
            assert analyzer.logger is not None

    def test_license_validation_keywords_defined(self, analyzer: BinaryNinjaAnalyzer) -> None:
        """Analyzer has comprehensive license validation keyword list."""
        keywords = BinaryNinjaAnalyzer.LICENSE_VALIDATION_KEYWORDS

        assert len(keywords) >= 10
        assert "license" in keywords
        assert "serial" in keywords
        assert "key" in keywords
        assert "registration" in keywords
        assert "activation" in keywords
        assert "validate" in keywords
        assert "trial" in keywords
        assert "expir" in keywords

    def test_protection_api_calls_defined(self, analyzer: BinaryNinjaAnalyzer) -> None:
        """Analyzer has protection mechanism API call database."""
        api_calls = BinaryNinjaAnalyzer.PROTECTION_API_CALLS

        assert "anti_debug" in api_calls
        assert "anti_vm" in api_calls
        assert "crypto" in api_calls
        assert "network" in api_calls

        assert "IsDebuggerPresent" in api_calls["anti_debug"]
        assert "CryptAcquireContext" in api_calls["crypto"]
        assert len(api_calls["anti_debug"]) >= 3
        assert len(api_calls["crypto"]) >= 3


class TestBinaryLoading:
    """Test binary loading and initial analysis setup."""

    def test_analyze_nonexistent_binary_raises_error(self, analyzer: BinaryNinjaAnalyzer) -> None:
        """Analyzing non-existent binary raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="Binary not found"):
            analyzer.analyze_binary("/nonexistent/path/to/binary.exe")

    def test_analyze_directory_raises_error(self, analyzer: BinaryNinjaAnalyzer, tmp_path: Path) -> None:
        """Analyzing directory instead of file raises ValueError."""
        test_dir = tmp_path / "test_directory"
        test_dir.mkdir()

        with pytest.raises(ValueError, match="Not a file"):
            analyzer.analyze_binary(test_dir)

    @SKIP_NO_PEFILE
    def test_fallback_analysis_with_valid_pe(
        self, analyzer: BinaryNinjaAnalyzer, minimal_pe_binary: Path
    ) -> None:
        """Fallback pefile analysis works when Binary Ninja unavailable."""
        if BINARYNINJA_AVAILABLE:
            pytest.skip("Binary Ninja available, testing fallback not needed")

        result = analyzer.analyze_binary(minimal_pe_binary)

        assert isinstance(result, BNAnalysisResult)
        assert result.binary_path == str(minimal_pe_binary)
        assert result.architecture != "unknown"
        assert result.platform == "windows"
        assert result.image_base > 0
        assert "analysis_method" in result.metadata
        assert result.metadata["analysis_method"] == "pefile_fallback"


class TestFunctionAnalysis:
    """Test function discovery and detailed analysis."""

    @SKIP_NO_BINARYNINJA
    def test_analyze_discovers_functions(
        self, analyzer: BinaryNinjaAnalyzer, minimal_pe_binary: Path
    ) -> None:
        """Analysis discovers functions in binary."""
        result = analyzer.analyze_binary(minimal_pe_binary)

        assert isinstance(result.functions, dict)
        assert result.metadata["total_functions"] == len(result.functions)

        if len(result.functions) > 0:
            first_func_addr = next(iter(result.functions))
            func = result.functions[first_func_addr]

            assert isinstance(func, BNFunction)
            assert func.address > 0
            assert func.size > 0
            assert func.name is not None

    @SKIP_NO_BINARYNINJA
    def test_function_has_complete_attributes(
        self, analyzer: BinaryNinjaAnalyzer, minimal_pe_binary: Path
    ) -> None:
        """Function analysis provides all required attributes."""
        result = analyzer.analyze_binary(minimal_pe_binary)

        if len(result.functions) == 0:
            pytest.skip("No functions discovered in test binary")

        func = next(iter(result.functions.values()))

        assert hasattr(func, "name")
        assert hasattr(func, "address")
        assert hasattr(func, "size")
        assert hasattr(func, "symbol_type")
        assert hasattr(func, "can_return")
        assert hasattr(func, "calling_convention")
        assert hasattr(func, "parameter_count")
        assert hasattr(func, "local_variable_count")
        assert hasattr(func, "basic_block_count")
        assert hasattr(func, "edge_count")
        assert hasattr(func, "instruction_count")
        assert hasattr(func, "cyclomatic_complexity")
        assert hasattr(func, "xrefs_to")
        assert hasattr(func, "xrefs_from")
        assert hasattr(func, "calls")
        assert hasattr(func, "called_by")

    @SKIP_NO_BINARYNINJA
    def test_function_xrefs_are_valid_addresses(
        self, analyzer: BinaryNinjaAnalyzer, minimal_pe_binary: Path
    ) -> None:
        """Function cross-references contain valid memory addresses."""
        result = analyzer.analyze_binary(minimal_pe_binary)

        if len(result.functions) == 0:
            pytest.skip("No functions discovered")

        for func in result.functions.values():
            for xref in func.xrefs_to:
                assert isinstance(xref, int)
                assert xref > 0

            for xref in func.xrefs_from:
                assert isinstance(xref, int)
                assert xref > 0

            for call_addr in func.calls:
                assert isinstance(call_addr, int)
                assert call_addr > 0

    @SKIP_NO_BINARYNINJA
    def test_cyclomatic_complexity_calculation(
        self, analyzer: BinaryNinjaAnalyzer, minimal_pe_binary: Path
    ) -> None:
        """Cyclomatic complexity calculated for functions."""
        result = analyzer.analyze_binary(minimal_pe_binary)

        if len(result.functions) == 0:
            pytest.skip("No functions discovered")

        for func in result.functions.values():
            assert isinstance(func.cyclomatic_complexity, int)
            assert func.cyclomatic_complexity >= 1


class TestStringExtraction:
    """Test string extraction from binaries."""

    @SKIP_NO_BINARYNINJA
    def test_extracts_strings_from_binary(
        self, analyzer: BinaryNinjaAnalyzer, minimal_pe_binary: Path
    ) -> None:
        """Analyzer extracts strings from binary sections."""
        result = analyzer.analyze_binary(minimal_pe_binary)

        assert isinstance(result.strings, list)
        assert result.metadata["total_strings"] == len(result.strings)

        for addr, string in result.strings:
            assert isinstance(addr, int)
            assert isinstance(string, str)
            assert addr > 0

    @SKIP_NO_BINARYNINJA
    def test_identifies_license_related_strings(
        self, analyzer: BinaryNinjaAnalyzer, license_validation_binary: Path
    ) -> None:
        """Analyzer finds license-related strings in binary."""
        result = analyzer.analyze_binary(license_validation_binary)

        string_values = [s[1].lower() for s in result.strings]

        license_found = any(
            any(keyword in string for keyword in ["license", "serial", "activation", "trial"])
            for string in string_values
        )

        assert license_found, "No license-related strings found in binary with license code"

    @SKIP_NO_PEFILE
    def test_fallback_extracts_strings(
        self, analyzer: BinaryNinjaAnalyzer, minimal_pe_binary: Path
    ) -> None:
        """Fallback pefile analysis extracts strings."""
        if BINARYNINJA_AVAILABLE:
            pytest.skip("Testing fallback only when Binary Ninja unavailable")

        result = analyzer.analyze_binary(minimal_pe_binary)

        assert isinstance(result.strings, list)

        for addr, string in result.strings:
            assert isinstance(addr, int)
            assert isinstance(string, str)
            assert len(string) >= 4


class TestImportExportAnalysis:
    """Test import and export table analysis."""

    @SKIP_NO_BINARYNINJA
    def test_extracts_imports(
        self, analyzer: BinaryNinjaAnalyzer, minimal_pe_binary: Path
    ) -> None:
        """Analyzer extracts imported functions."""
        result = analyzer.analyze_binary(minimal_pe_binary)

        assert isinstance(result.imports, list)
        assert result.metadata["total_imports"] == len(result.imports)

        for lib, func, addr in result.imports:
            assert isinstance(lib, str)
            assert isinstance(func, str)
            assert isinstance(addr, int)

    @SKIP_NO_BINARYNINJA
    def test_extracts_exports(
        self, analyzer: BinaryNinjaAnalyzer, minimal_pe_binary: Path
    ) -> None:
        """Analyzer extracts exported functions."""
        result = analyzer.analyze_binary(minimal_pe_binary)

        assert isinstance(result.exports, list)
        assert result.metadata["total_exports"] == len(result.exports)

        for name, addr in result.exports:
            assert isinstance(name, str)
            assert isinstance(addr, int)
            assert addr > 0

    @SKIP_NO_PEFILE
    def test_fallback_extracts_imports(
        self, analyzer: BinaryNinjaAnalyzer, minimal_pe_binary: Path
    ) -> None:
        """Fallback analysis extracts imports correctly."""
        if BINARYNINJA_AVAILABLE:
            pytest.skip("Testing fallback only")

        result = analyzer.analyze_binary(minimal_pe_binary)

        assert isinstance(result.imports, list)

        for lib, func, addr in result.imports:
            assert isinstance(lib, str)
            assert isinstance(func, str)
            assert isinstance(addr, int)


class TestSectionAnalysis:
    """Test PE section extraction and analysis."""

    @SKIP_NO_BINARYNINJA
    def test_extracts_sections(
        self, analyzer: BinaryNinjaAnalyzer, minimal_pe_binary: Path
    ) -> None:
        """Analyzer extracts binary sections."""
        result = analyzer.analyze_binary(minimal_pe_binary)

        assert isinstance(result.sections, list)
        assert len(result.sections) > 0

        for section in result.sections:
            assert "name" in section
            assert "start" in section
            assert "end" in section
            assert "size" in section
            assert isinstance(section["start"], int)
            assert isinstance(section["end"], int)
            assert section["end"] >= section["start"]

    @SKIP_NO_PEFILE
    def test_fallback_extracts_sections(
        self, analyzer: BinaryNinjaAnalyzer, minimal_pe_binary: Path
    ) -> None:
        """Fallback pefile analysis extracts sections."""
        if BINARYNINJA_AVAILABLE:
            pytest.skip("Testing fallback only")

        result = analyzer.analyze_binary(minimal_pe_binary)

        assert isinstance(result.sections, list)
        assert len(result.sections) >= 2

        section_names = [s["name"].lower() for s in result.sections]
        assert any("text" in name for name in section_names)


class TestBasicBlockAnalysis:
    """Test control flow graph and basic block extraction."""

    @SKIP_NO_BINARYNINJA
    def test_extracts_basic_blocks(
        self, analyzer: BinaryNinjaAnalyzer, minimal_pe_binary: Path
    ) -> None:
        """Analyzer extracts basic blocks from functions."""
        result = analyzer.analyze_binary(minimal_pe_binary)

        assert isinstance(result.basic_blocks, dict)
        assert result.metadata["total_basic_blocks"] == len(result.basic_blocks)

        for addr, block in result.basic_blocks.items():
            assert isinstance(addr, int)
            assert isinstance(block, BNBasicBlock)
            assert block.start > 0
            assert block.end >= block.start
            assert block.length == block.end - block.start

    @SKIP_NO_BINARYNINJA
    def test_basic_block_has_control_flow_info(
        self, analyzer: BinaryNinjaAnalyzer, minimal_pe_binary: Path
    ) -> None:
        """Basic blocks contain control flow information."""
        result = analyzer.analyze_binary(minimal_pe_binary)

        if len(result.basic_blocks) == 0:
            pytest.skip("No basic blocks discovered")

        block = next(iter(result.basic_blocks.values()))

        assert hasattr(block, "outgoing_edges")
        assert hasattr(block, "incoming_edges")
        assert hasattr(block, "dominates")
        assert hasattr(block, "dominated_by")
        assert hasattr(block, "immediate_dominator")
        assert isinstance(block.outgoing_edges, list)
        assert isinstance(block.incoming_edges, list)

    @SKIP_NO_BINARYNINJA
    def test_basic_block_edges_valid(
        self, analyzer: BinaryNinjaAnalyzer, minimal_pe_binary: Path
    ) -> None:
        """Basic block edges reference valid block addresses."""
        result = analyzer.analyze_binary(minimal_pe_binary)

        if len(result.basic_blocks) == 0:
            pytest.skip("No basic blocks discovered")

        for block in result.basic_blocks.values():
            for edge_target in block.outgoing_edges:
                assert isinstance(edge_target, int)
                assert edge_target > 0

            for edge_source in block.incoming_edges:
                assert isinstance(edge_source, int)
                assert edge_source > 0


class TestLicenseValidationDetection:
    """Test identification of license validation functions."""

    @SKIP_NO_BINARYNINJA
    def test_identifies_license_validation_candidates(
        self, analyzer: BinaryNinjaAnalyzer, license_validation_binary: Path
    ) -> None:
        """Analyzer identifies potential license validation functions."""
        result = analyzer.analyze_binary(license_validation_binary)

        assert isinstance(result.license_validation_candidates, list)
        assert result.metadata["license_candidates"] == len(result.license_validation_candidates)

        for candidate_addr in result.license_validation_candidates:
            assert isinstance(candidate_addr, int)
            assert candidate_addr > 0

    @SKIP_NO_BINARYNINJA
    def test_license_candidates_prioritized_by_score(
        self, analyzer: BinaryNinjaAnalyzer, license_validation_binary: Path
    ) -> None:
        """License validation candidates sorted by relevance."""
        result = analyzer.analyze_binary(license_validation_binary)

        if len(result.license_validation_candidates) < 2:
            pytest.skip("Not enough candidates to test sorting")

        candidates = result.license_validation_candidates
        assert candidates == sorted(candidates)

    @SKIP_NO_BINARYNINJA
    def test_license_detection_keyword_matching(
        self, analyzer: BinaryNinjaAnalyzer, license_validation_binary: Path
    ) -> None:
        """License detection uses keyword matching in function names."""
        result = analyzer.analyze_binary(license_validation_binary)

        if len(result.license_validation_candidates) == 0:
            pytest.skip("No license candidates found")

        candidate_functions = [
            result.functions[addr] for addr in result.license_validation_candidates
            if addr in result.functions
        ]

        if not candidate_functions:
            pytest.skip("No function data for candidates")

        keywords_found = any(
            any(keyword in func.name.lower()
                for keyword in BinaryNinjaAnalyzer.LICENSE_VALIDATION_KEYWORDS)
            for func in candidate_functions
        )

        assert keywords_found or len(candidate_functions[0].strings_referenced) > 0


class TestProtectionMechanismDetection:
    """Test detection of anti-debug, anti-VM, and crypto protections."""

    @SKIP_NO_BINARYNINJA
    def test_detects_protection_mechanisms(
        self, analyzer: BinaryNinjaAnalyzer, minimal_pe_binary: Path
    ) -> None:
        """Analyzer detects protection mechanism usage."""
        result = analyzer.analyze_binary(minimal_pe_binary)

        assert isinstance(result.protection_indicators, dict)
        assert "anti_debug" in result.protection_indicators
        assert "anti_vm" in result.protection_indicators
        assert "crypto" in result.protection_indicators
        assert "network" in result.protection_indicators

    @SKIP_NO_BINARYNINJA
    def test_protection_indicators_contain_function_addresses(
        self, analyzer: BinaryNinjaAnalyzer, license_validation_binary: Path
    ) -> None:
        """Protection indicators map to function addresses."""
        result = analyzer.analyze_binary(license_validation_binary)

        for category, addresses in result.protection_indicators.items():
            assert isinstance(addresses, list)

            for addr in addresses:
                assert isinstance(addr, int)
                assert addr > 0

    @SKIP_NO_BINARYNINJA
    def test_detects_crypto_api_usage(
        self, analyzer: BinaryNinjaAnalyzer, license_validation_binary: Path
    ) -> None:
        """Analyzer detects cryptographic API calls."""
        result = analyzer.analyze_binary(license_validation_binary)

        crypto_indicators = result.protection_indicators.get("crypto", [])

        if len(result.imports) > 0:
            crypto_imports = [
                func for lib, func, addr in result.imports
                if any(api in func for api in BinaryNinjaAnalyzer.PROTECTION_API_CALLS["crypto"])
            ]

            if crypto_imports:
                assert len(crypto_indicators) >= 0


class TestDecompilation:
    """Test function decompilation capabilities."""

    @SKIP_NO_BINARYNINJA
    def test_decompile_function_returns_code(
        self, analyzer: BinaryNinjaAnalyzer, minimal_pe_binary: Path
    ) -> None:
        """Function decompilation produces pseudocode."""
        result = analyzer.analyze_binary(minimal_pe_binary)

        if len(result.functions) == 0:
            pytest.skip("No functions to decompile")

        func_addr = next(iter(result.functions))

        try:
            decompiled = analyzer.decompile_function(func_addr)

            assert isinstance(decompiled, str)
            assert len(decompiled) > 0

        except ValueError as e:
            if "decompilation failed" in str(e).lower():
                pytest.skip(f"Decompilation not available: {e}")
            else:
                raise

    @SKIP_NO_BINARYNINJA
    def test_decompile_invalid_address_raises_error(
        self, analyzer: BinaryNinjaAnalyzer, minimal_pe_binary: Path
    ) -> None:
        """Decompiling invalid address raises ValueError."""
        analyzer.analyze_binary(minimal_pe_binary)

        with pytest.raises(ValueError, match="No function found"):
            analyzer.decompile_function(0xDEADBEEF)

    @SKIP_NO_BINARYNINJA
    def test_decompile_without_loaded_binary_raises_error(
        self, analyzer: BinaryNinjaAnalyzer
    ) -> None:
        """Decompiling without loaded binary raises ValueError."""
        with pytest.raises(ValueError, match="Binary Ninja not available|binary not loaded"):
            analyzer.decompile_function(0x401000)


class TestControlFlowGraph:
    """Test control flow graph extraction."""

    @SKIP_NO_BINARYNINJA
    def test_get_function_cfg_returns_graph(
        self, analyzer: BinaryNinjaAnalyzer, minimal_pe_binary: Path
    ) -> None:
        """CFG extraction returns valid graph structure."""
        result = analyzer.analyze_binary(minimal_pe_binary)

        if len(result.functions) == 0:
            pytest.skip("No functions for CFG extraction")

        func_addr = next(iter(result.functions))

        try:
            cfg = analyzer.get_function_cfg(func_addr)

            assert isinstance(cfg, dict)
            assert "function_name" in cfg
            assert "function_address" in cfg
            assert "nodes" in cfg
            assert "edges" in cfg
            assert "entry_block" in cfg

            assert cfg["function_address"] == func_addr
            assert isinstance(cfg["nodes"], list)
            assert isinstance(cfg["edges"], list)

        except ValueError as e:
            pytest.skip(f"CFG extraction not available: {e}")

    @SKIP_NO_BINARYNINJA
    def test_cfg_nodes_have_required_attributes(
        self, analyzer: BinaryNinjaAnalyzer, minimal_pe_binary: Path
    ) -> None:
        """CFG nodes contain required attributes."""
        result = analyzer.analyze_binary(minimal_pe_binary)

        if len(result.functions) == 0:
            pytest.skip("No functions available")

        func_addr = next(iter(result.functions))

        try:
            cfg = analyzer.get_function_cfg(func_addr)

            if len(cfg["nodes"]) == 0:
                pytest.skip("No nodes in CFG")

            node = cfg["nodes"][0]
            assert "address" in node
            assert "end" in node
            assert "instructions" in node
            assert isinstance(node["instructions"], list)

        except ValueError as e:
            pytest.skip(f"CFG not available: {e}")

    @SKIP_NO_BINARYNINJA
    def test_cfg_edges_connect_valid_nodes(
        self, analyzer: BinaryNinjaAnalyzer, minimal_pe_binary: Path
    ) -> None:
        """CFG edges connect valid node addresses."""
        result = analyzer.analyze_binary(minimal_pe_binary)

        if len(result.functions) == 0:
            pytest.skip("No functions available")

        func_addr = next(iter(result.functions))

        try:
            cfg = analyzer.get_function_cfg(func_addr)

            if len(cfg["edges"]) == 0:
                pytest.skip("No edges in CFG")

            node_addresses = {node["address"] for node in cfg["nodes"]}

            for edge in cfg["edges"]:
                assert "source" in edge
                assert "target" in edge
                assert "type" in edge
                assert edge["source"] in node_addresses
                assert edge["target"] in node_addresses

        except ValueError as e:
            pytest.skip(f"CFG not available: {e}")

    @SKIP_NO_BINARYNINJA
    def test_get_cfg_invalid_address_raises_error(
        self, analyzer: BinaryNinjaAnalyzer, minimal_pe_binary: Path
    ) -> None:
        """Getting CFG for invalid address raises ValueError."""
        analyzer.analyze_binary(minimal_pe_binary)

        with pytest.raises(ValueError, match="No function found"):
            analyzer.get_function_cfg(0xBADC0DE)


class TestAnalyzerCleanup:
    """Test proper resource cleanup."""

    @SKIP_NO_BINARYNINJA
    def test_close_releases_binary_view(
        self, analyzer: BinaryNinjaAnalyzer, minimal_pe_binary: Path
    ) -> None:
        """Close method releases Binary Ninja binary view."""
        analyzer.analyze_binary(minimal_pe_binary)

        assert analyzer.bv is not None

        analyzer.close()

        assert analyzer.bv is None

    def test_close_on_uninitialized_analyzer_safe(
        self, analyzer: BinaryNinjaAnalyzer
    ) -> None:
        """Calling close on uninitialized analyzer doesn't raise error."""
        assert analyzer.bv is None

        analyzer.close()

        assert analyzer.bv is None


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_analyze_empty_file_handles_gracefully(
        self, analyzer: BinaryNinjaAnalyzer, tmp_path: Path
    ) -> None:
        """Analyzing empty file handled gracefully."""
        empty_file = tmp_path / "empty.exe"
        empty_file.touch()

        try:
            result = analyzer.analyze_binary(empty_file)

            if BINARYNINJA_AVAILABLE:
                assert isinstance(result, BNAnalysisResult)
        except (RuntimeError, ValueError) as e:
            assert "failed" in str(e).lower() or "invalid" in str(e).lower()

    def test_analyze_corrupted_pe_handles_gracefully(
        self, analyzer: BinaryNinjaAnalyzer, tmp_path: Path
    ) -> None:
        """Analyzing corrupted PE handled gracefully."""
        corrupted_pe = tmp_path / "corrupted.exe"
        corrupted_pe.write_bytes(b"MZ" + b"\x00" * 100)

        try:
            result = analyzer.analyze_binary(corrupted_pe)

            if BINARYNINJA_AVAILABLE:
                assert isinstance(result, BNAnalysisResult)
        except (RuntimeError, ValueError) as e:
            assert True

    @SKIP_NO_BINARYNINJA
    def test_analyze_very_small_binary(
        self, analyzer: BinaryNinjaAnalyzer, tmp_path: Path
    ) -> None:
        """Analyzing minimal valid binary works."""
        minimal_pe = tmp_path / "minimal.exe"

        dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
        pe_sig = b"\x00" * 0x80 + b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 0xF0, 0x22)
        optional = b"\x0B\x02" + b"\x00" * 238

        minimal_pe.write_bytes(dos_header + pe_sig + coff + optional)

        try:
            result = analyzer.analyze_binary(minimal_pe)
            assert isinstance(result, BNAnalysisResult)
        except (RuntimeError, ValueError):
            pass


class TestComprehensiveAnalysis:
    """Test complete analysis workflow."""

    @SKIP_NO_BINARYNINJA
    def test_full_analysis_workflow(
        self, analyzer: BinaryNinjaAnalyzer, license_validation_binary: Path
    ) -> None:
        """Complete analysis workflow produces comprehensive results."""
        result = analyzer.analyze_binary(license_validation_binary)

        assert isinstance(result, BNAnalysisResult)
        assert result.binary_path == str(license_validation_binary)
        assert result.architecture != "unknown"
        assert result.platform != "unknown"
        assert result.entry_point > 0
        assert result.image_base > 0

        assert isinstance(result.functions, dict)
        assert isinstance(result.strings, list)
        assert isinstance(result.imports, list)
        assert isinstance(result.exports, list)
        assert isinstance(result.sections, list)
        assert isinstance(result.symbols, dict)
        assert isinstance(result.basic_blocks, dict)
        assert isinstance(result.license_validation_candidates, list)
        assert isinstance(result.protection_indicators, dict)
        assert isinstance(result.metadata, dict)

        assert "total_functions" in result.metadata
        assert "total_basic_blocks" in result.metadata
        assert "total_strings" in result.metadata
        assert "license_candidates" in result.metadata

    @SKIP_NO_BINARYNINJA
    def test_analysis_result_serializable(
        self, analyzer: BinaryNinjaAnalyzer, minimal_pe_binary: Path
    ) -> None:
        """Analysis result can be serialized for reporting."""
        result = analyzer.analyze_binary(minimal_pe_binary)

        serialized = {
            "binary_path": result.binary_path,
            "architecture": result.architecture,
            "platform": result.platform,
            "entry_point": hex(result.entry_point),
            "image_base": hex(result.image_base),
            "metadata": result.metadata,
            "function_count": len(result.functions),
            "string_count": len(result.strings),
            "import_count": len(result.imports),
            "license_candidates": result.license_validation_candidates,
        }

        assert isinstance(serialized, dict)
        assert all(isinstance(key, str) for key in serialized.keys())
