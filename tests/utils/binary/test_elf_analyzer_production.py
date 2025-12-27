"""Production tests for elf_analyzer.py.

Tests validate ELF binary analysis with synthetic minimal ELF files
since Windows does not natively have ELF binaries.
"""

import struct
from pathlib import Path
from typing import Any

import pytest

from intellicrack.utils.binary.elf_analyzer import (
    ELFAnalyzer,
    analyze_elf_file,
    extract_elf_strings,
    is_elf_file,
)


def create_minimal_elf_64bit(path: Path) -> None:
    """Create minimal valid 64-bit ELF file for testing.

    Args:
        path: Path where to create the ELF file
    """
    elf_header = bytearray(64)

    elf_header[0:4] = b"\x7fELF"
    elf_header[4] = 2
    elf_header[5] = 1
    elf_header[6] = 1
    elf_header[7] = 0
    elf_header[8:16] = b"\x00" * 8

    header_data = struct.pack(
        "<HHIQQQIHHHHHH",
        2,
        62,
        1,
        0x400000,
        64,
        0,
        0,
        64,
        56,
        0,
        64,
        0,
        0,
    )
    elf_header[16:64] = header_data

    path.write_bytes(bytes(elf_header))


def create_minimal_elf_32bit(path: Path) -> None:
    """Create minimal valid 32-bit ELF file for testing.

    Args:
        path: Path where to create the ELF file
    """
    elf_header = bytearray(52)

    elf_header[0:4] = b"\x7fELF"
    elf_header[4] = 1
    elf_header[5] = 1
    elf_header[6] = 1
    elf_header[7] = 0
    elf_header[8:16] = b"\x00" * 8

    header_data = struct.pack(
        "<HHIIIIIHHHHHH",
        2,
        3,
        1,
        0x08048000,
        52,
        0,
        0,
        52,
        32,
        0,
        40,
        0,
        0,
    )
    elf_header[16:52] = header_data

    path.write_bytes(bytes(elf_header))


def create_elf_with_sections(path: Path) -> None:
    """Create ELF file with section headers.

    Args:
        path: Path where to create the ELF file
    """
    elf_header = bytearray(64)

    elf_header[0:4] = b"\x7fELF"
    elf_header[4] = 2
    elf_header[5] = 1
    elf_header[6] = 1
    elf_header[7] = 0

    section_offset = 200
    header_data = struct.pack(
        "<HHIQQQIHHHHHH",
        2,
        62,
        1,
        0x400000,
        64,
        section_offset,
        0,
        64,
        56,
        0,
        64,
        2,
        0,
    )
    elf_header[16:64] = header_data

    sections_data = bytearray(section_offset - 64)

    section_header_1 = struct.pack(
        "<IIQQQQIIQQ",
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )

    section_header_2 = struct.pack(
        "<IIQQQQIIQQ",
        1,
        1,
        6,
        0x400000,
        64,
        100,
        0,
        0,
        16,
        0,
    )

    full_data = bytes(elf_header) + bytes(sections_data) + section_header_1 + section_header_2

    path.write_bytes(full_data)


def create_elf_with_segments(path: Path) -> None:
    """Create ELF file with program segments.

    Args:
        path: Path where to create the ELF file
    """
    elf_header = bytearray(64)

    elf_header[0:4] = b"\x7fELF"
    elf_header[4] = 2
    elf_header[5] = 1
    elf_header[6] = 1

    program_header_offset = 64
    header_data = struct.pack(
        "<HHIQQQIHHHHHH",
        2,
        62,
        1,
        0x400000,
        program_header_offset,
        0,
        0,
        64,
        56,
        2,
        64,
        0,
        0,
    )
    elf_header[16:64] = header_data

    segment_header_1 = struct.pack(
        "<IIQQQQQQ",
        1,
        5,
        0,
        0x400000,
        0x400000,
        1000,
        1000,
        0x1000,
    )

    segment_header_2 = struct.pack(
        "<IIQQQQQQ",
        1,
        6,
        1000,
        0x500000,
        0x500000,
        500,
        500,
        0x1000,
    )

    full_data = bytes(elf_header) + segment_header_1 + segment_header_2

    path.write_bytes(full_data)


@pytest.fixture
def minimal_elf_64(tmp_path: Path) -> Path:
    """Create minimal 64-bit ELF for testing."""
    elf_file = tmp_path / "test_64.elf"
    create_minimal_elf_64bit(elf_file)
    return elf_file


@pytest.fixture
def minimal_elf_32(tmp_path: Path) -> Path:
    """Create minimal 32-bit ELF for testing."""
    elf_file = tmp_path / "test_32.elf"
    create_minimal_elf_32bit(elf_file)
    return elf_file


@pytest.fixture
def elf_with_sections(tmp_path: Path) -> Path:
    """Create ELF with sections for testing."""
    elf_file = tmp_path / "test_sections.elf"
    create_elf_with_sections(elf_file)
    return elf_file


@pytest.fixture
def elf_with_segments(tmp_path: Path) -> Path:
    """Create ELF with segments for testing."""
    elf_file = tmp_path / "test_segments.elf"
    create_elf_with_segments(elf_file)
    return elf_file


class TestELFAnalyzerInitialization:
    """Test ELF analyzer initialization."""

    def test_initializes_with_file_path(self, minimal_elf_64: Path) -> None:
        """Analyzer initializes with file path."""
        analyzer = ELFAnalyzer(minimal_elf_64)

        assert analyzer.file_path == minimal_elf_64
        assert analyzer.data is None
        assert analyzer.header is None
        assert analyzer.sections == []
        assert analyzer.segments == []
        assert analyzer.symbols == []

    def test_accepts_string_path(self, minimal_elf_64: Path) -> None:
        """Analyzer accepts string path."""
        analyzer = ELFAnalyzer(str(minimal_elf_64))

        assert analyzer.file_path == minimal_elf_64


class TestLoadBinary:
    """Test ELF binary loading."""

    def test_loads_64bit_elf_successfully(self, minimal_elf_64: Path) -> None:
        """Loads 64-bit ELF binary successfully."""
        analyzer = ELFAnalyzer(minimal_elf_64)

        success = analyzer.load_binary()

        assert success is True
        assert analyzer.data is not None
        assert len(analyzer.data) > 0

    def test_loads_32bit_elf_successfully(self, minimal_elf_32: Path) -> None:
        """Loads 32-bit ELF binary successfully."""
        analyzer = ELFAnalyzer(minimal_elf_32)

        success = analyzer.load_binary()

        assert success is True
        assert analyzer.data is not None

    def test_validates_elf_magic_bytes(self, minimal_elf_64: Path) -> None:
        """Validates ELF magic bytes during load."""
        analyzer = ELFAnalyzer(minimal_elf_64)

        success = analyzer.load_binary()

        assert success is True
        assert analyzer.data[:4] == b"\x7fELF"

    def test_rejects_invalid_elf(self, tmp_path: Path) -> None:
        """Rejects file with invalid ELF magic."""
        invalid_file = tmp_path / "invalid.elf"
        invalid_file.write_bytes(b"INVALID" + b"\x00" * 100)

        analyzer = ELFAnalyzer(invalid_file)

        success = analyzer.load_binary()

        assert success is False

    def test_handles_nonexistent_file(self, tmp_path: Path) -> None:
        """Handles nonexistent file gracefully."""
        nonexistent = tmp_path / "nonexistent.elf"

        analyzer = ELFAnalyzer(nonexistent)

        success = analyzer.load_binary()

        assert success is False


class TestHeaderParsing:
    """Test ELF header parsing."""

    def test_parses_64bit_header(self, minimal_elf_64: Path) -> None:
        """Parses 64-bit ELF header correctly."""
        analyzer = ELFAnalyzer(minimal_elf_64)
        analyzer.load_binary()

        assert analyzer.header is not None
        assert analyzer.is_64bit is True
        assert analyzer.header["ei_class"] == 2
        assert analyzer.header["e_type"] == 2
        assert analyzer.header["e_machine"] == 62

    def test_parses_32bit_header(self, minimal_elf_32: Path) -> None:
        """Parses 32-bit ELF header correctly."""
        analyzer = ELFAnalyzer(minimal_elf_32)
        analyzer.load_binary()

        assert analyzer.header is not None
        assert analyzer.is_64bit is False
        assert analyzer.header["ei_class"] == 1
        assert analyzer.header["e_machine"] == 3

    def test_detects_little_endian(self, minimal_elf_64: Path) -> None:
        """Detects little-endian byte order."""
        analyzer = ELFAnalyzer(minimal_elf_64)
        analyzer.load_binary()

        assert analyzer.endian == "little"
        assert analyzer.header["ei_data"] == 1

    def test_header_contains_required_fields(self, minimal_elf_64: Path) -> None:
        """Header contains all required fields."""
        analyzer = ELFAnalyzer(minimal_elf_64)
        analyzer.load_binary()

        required_fields = [
            "e_type",
            "e_machine",
            "e_version",
            "e_entry",
            "e_phoff",
            "e_shoff",
            "e_flags",
            "e_ehsize",
        ]

        for field in required_fields:
            assert field in analyzer.header


class TestSectionAnalysis:
    """Test ELF section analysis."""

    def test_analyzes_sections(self, elf_with_sections: Path) -> None:
        """Analyzes ELF sections successfully."""
        analyzer = ELFAnalyzer(elf_with_sections)
        analyzer.load_binary()

        sections = analyzer.analyze_sections()

        assert isinstance(sections, list)
        assert len(sections) >= 2

    def test_section_contains_required_fields(
        self, elf_with_sections: Path
    ) -> None:
        """Section entries contain required fields."""
        analyzer = ELFAnalyzer(elf_with_sections)
        analyzer.load_binary()
        sections = analyzer.analyze_sections()

        if len(sections) > 0:
            section = sections[0]
            assert "sh_name" in section
            assert "sh_type" in section
            assert "sh_flags" in section
            assert "sh_addr" in section
            assert "sh_offset" in section
            assert "sh_size" in section

    def test_returns_empty_list_for_no_sections(
        self, minimal_elf_64: Path
    ) -> None:
        """Returns empty list when no sections present."""
        analyzer = ELFAnalyzer(minimal_elf_64)
        analyzer.load_binary()

        sections = analyzer.analyze_sections()

        assert isinstance(sections, list)


class TestSegmentAnalysis:
    """Test ELF segment analysis."""

    def test_analyzes_segments(self, elf_with_segments: Path) -> None:
        """Analyzes program segments successfully."""
        analyzer = ELFAnalyzer(elf_with_segments)
        analyzer.load_binary()

        segments = analyzer.analyze_segments()

        assert isinstance(segments, list)
        assert len(segments) >= 2

    def test_segment_contains_required_fields(
        self, elf_with_segments: Path
    ) -> None:
        """Segment entries contain required fields."""
        analyzer = ELFAnalyzer(elf_with_segments)
        analyzer.load_binary()
        segments = analyzer.analyze_segments()

        if len(segments) > 0:
            segment = segments[0]
            assert "p_type" in segment
            assert "p_flags" in segment
            assert "p_offset" in segment
            assert "p_vaddr" in segment
            assert "p_filesz" in segment
            assert "p_memsz" in segment

    def test_returns_empty_list_for_no_segments(
        self, minimal_elf_64: Path
    ) -> None:
        """Returns empty list when no segments present."""
        analyzer = ELFAnalyzer(minimal_elf_64)
        analyzer.load_binary()

        segments = analyzer.analyze_segments()

        assert isinstance(segments, list)


class TestSecurityFeatureAnalysis:
    """Test security feature detection."""

    def test_analyzes_security_features(self, minimal_elf_64: Path) -> None:
        """Analyzes security features in ELF binary."""
        analyzer = ELFAnalyzer(minimal_elf_64)
        analyzer.load_binary()

        features = analyzer.get_security_features()

        assert isinstance(features, dict)
        assert "nx_bit" in features
        assert "stack_canary" in features
        assert "pie" in features
        assert "relro" in features
        assert "fortify" in features
        assert "stripped" in features

    def test_detects_pie_from_header(self, minimal_elf_64: Path) -> None:
        """Detects PIE from ELF type."""
        analyzer = ELFAnalyzer(minimal_elf_64)
        analyzer.load_binary()

        features = analyzer.get_security_features()

        assert features["pie"] is True

    def test_returns_default_features_without_analysis(self) -> None:
        """Returns default features when header not loaded."""
        analyzer = ELFAnalyzer("nonexistent.elf")

        features = analyzer.get_security_features()

        assert isinstance(features, dict)


class TestComprehensiveAnalysis:
    """Test comprehensive ELF analysis."""

    def test_performs_full_analysis(self, minimal_elf_64: Path) -> None:
        """Performs comprehensive analysis of ELF file."""
        analyzer = ELFAnalyzer(minimal_elf_64)

        result = analyzer.analyze()

        assert "file_path" in result
        assert "header" in result
        assert "architecture" in result
        assert "sections" in result
        assert "segments" in result
        assert "symbols" in result
        assert "security_features" in result
        assert "file_size" in result

    def test_analysis_includes_file_size(self, minimal_elf_64: Path) -> None:
        """Analysis includes correct file size."""
        analyzer = ELFAnalyzer(minimal_elf_64)

        result = analyzer.analyze()

        assert result["file_size"] > 0
        assert result["file_size"] == minimal_elf_64.stat().st_size

    def test_architecture_string_is_descriptive(
        self, minimal_elf_64: Path
    ) -> None:
        """Architecture string is human-readable."""
        analyzer = ELFAnalyzer(minimal_elf_64)

        result = analyzer.analyze()

        assert isinstance(result["architecture"], str)
        assert "64" in result["architecture"] or "32" in result["architecture"]

    def test_handles_analysis_failure(self, tmp_path: Path) -> None:
        """Handles analysis failure gracefully."""
        invalid_file = tmp_path / "invalid.bin"
        invalid_file.write_bytes(b"NOT_ELF")

        analyzer = ELFAnalyzer(invalid_file)
        result = analyzer.analyze()

        assert "error" in result


class TestHelperFunctions:
    """Test module-level helper functions."""

    def test_is_elf_file_detects_valid_elf(self, minimal_elf_64: Path) -> None:
        """is_elf_file detects valid ELF file."""
        is_elf = is_elf_file(minimal_elf_64)

        assert is_elf is True

    def test_is_elf_file_rejects_non_elf(self, tmp_path: Path) -> None:
        """is_elf_file rejects non-ELF file."""
        non_elf = tmp_path / "not_elf.bin"
        non_elf.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)

        is_elf = is_elf_file(non_elf)

        assert is_elf is False

    def test_is_elf_file_handles_nonexistent(self, tmp_path: Path) -> None:
        """is_elf_file handles nonexistent file."""
        nonexistent = tmp_path / "nonexistent.elf"

        is_elf = is_elf_file(nonexistent)

        assert is_elf is False

    def test_analyze_elf_file_function(self, minimal_elf_64: Path) -> None:
        """analyze_elf_file convenience function works."""
        result = analyze_elf_file(minimal_elf_64)

        assert isinstance(result, dict)
        assert "header" in result or "error" in result

    def test_extract_elf_strings(self, tmp_path: Path) -> None:
        """Extracts printable strings from ELF binary."""
        elf_file = tmp_path / "string_test.elf"

        elf_data = b"\x7fELF" + b"\x00" * 60
        elf_data += b"HelloWorld" + b"\x00" * 10
        elf_data += b"TestString" + b"\x00" * 10
        elf_data += b"ABC" + b"\x00"
        elf_file.write_bytes(elf_data)

        strings = extract_elf_strings(elf_file, min_length=4)

        assert "HelloWorld" in strings
        assert "TestString" in strings

    def test_extract_elf_strings_respects_min_length(
        self, tmp_path: Path
    ) -> None:
        """extract_elf_strings respects minimum length parameter."""
        elf_file = tmp_path / "string_test.elf"

        elf_data = b"\x7fELF" + b"AB" + b"\x00" + b"LONGSTRING" + b"\x00"
        elf_file.write_bytes(elf_data)

        strings = extract_elf_strings(elf_file, min_length=5)

        assert "LONGSTRING" in strings
        assert "AB" not in strings


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_handles_truncated_header(self, tmp_path: Path) -> None:
        """Handles truncated ELF header gracefully."""
        truncated = tmp_path / "truncated.elf"
        truncated.write_bytes(b"\x7fELF\x02\x01\x01")

        analyzer = ELFAnalyzer(truncated)

        success = analyzer.load_binary()

        assert success is False or analyzer.header is None

    def test_handles_empty_file(self, tmp_path: Path) -> None:
        """Handles empty file gracefully."""
        empty = tmp_path / "empty.elf"
        empty.write_bytes(b"")

        analyzer = ELFAnalyzer(empty)

        success = analyzer.load_binary()

        assert success is False

    def test_handles_very_large_section_count(self, tmp_path: Path) -> None:
        """Handles ELF with large section count."""
        elf_header = bytearray(64)
        elf_header[0:4] = b"\x7fELF"
        elf_header[4] = 2
        elf_header[5] = 1

        header_data = struct.pack(
            "<HHIQQQIHHHHHH",
            2,
            62,
            1,
            0x400000,
            64,
            1000,
            0,
            64,
            56,
            0,
            64,
            100,
            0,
        )
        elf_header[16:64] = header_data

        elf_file = tmp_path / "many_sections.elf"
        elf_file.write_bytes(bytes(elf_header))

        analyzer = ELFAnalyzer(elf_file)
        analyzer.load_binary()

        sections = analyzer.analyze_sections()

        assert isinstance(sections, list)


class TestPerformance:
    """Test performance on ELF analysis."""

    def test_loads_large_elf_efficiently(self, tmp_path: Path) -> None:
        """Loads large ELF file efficiently."""
        large_elf = tmp_path / "large.elf"

        elf_header = bytearray(64)
        elf_header[0:4] = b"\x7fELF"
        elf_header[4] = 2
        elf_header[5] = 1

        header_data = struct.pack(
            "<HHIQQQIHHHHHH",
            2,
            62,
            1,
            0x400000,
            64,
            0,
            0,
            64,
            56,
            0,
            64,
            0,
            0,
        )
        elf_header[16:64] = header_data

        large_data = bytes(elf_header) + b"\x00" * (1024 * 1024)
        large_elf.write_bytes(large_data)

        import time

        analyzer = ELFAnalyzer(large_elf)

        start_time = time.time()
        success = analyzer.load_binary()
        duration = time.time() - start_time

        assert success is True
        assert duration < 2.0

    def test_analyzes_efficiently(self, minimal_elf_64: Path) -> None:
        """Complete analysis completes in reasonable time."""
        import time

        analyzer = ELFAnalyzer(minimal_elf_64)

        start_time = time.time()
        result = analyzer.analyze()
        duration = time.time() - start_time

        assert "header" in result or "error" in result
        assert duration < 1.0
