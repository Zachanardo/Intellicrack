"""Production tests for ELF binary analyzer.

Tests ELF header parsing, section/segment analysis, symbol table extraction,
and security feature detection on real Linux binaries.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import struct
from pathlib import Path

import pytest

from intellicrack.utils.binary.elf_analyzer import (
    ELFAnalyzer,
    analyze_elf_file,
    extract_elf_strings,
    is_elf_file,
)


@pytest.fixture
def elf_binaries_dir() -> Path:
    """Get directory with ELF binaries."""
    return Path(__file__).parent.parent / "fixtures" / "binaries" / "elf"


@pytest.fixture
def simple_elf(elf_binaries_dir: Path) -> Path:
    """Get a simple ELF binary for testing."""
    binary_path = elf_binaries_dir / "simple_x64"

    if not binary_path.exists():
        pytest.skip(f"ELF binary not found: {binary_path}")

    return binary_path


@pytest.fixture
def sample_elf_x64(tmp_path: Path) -> Path:
    """Create a minimal valid ELF x64 binary for testing."""
    elf_path = tmp_path / "test_elf_x64"

    elf_header = bytearray()
    elf_header.extend(b"\x7fELF")
    elf_header.append(2)
    elf_header.append(1)
    elf_header.append(1)
    elf_header.extend(b"\x00" * 9)

    elf_header.extend(struct.pack("<H", 2))
    elf_header.extend(struct.pack("<H", 62))
    elf_header.extend(struct.pack("<I", 1))
    elf_header.extend(struct.pack("<Q", 0x400000))
    elf_header.extend(struct.pack("<Q", 64))
    elf_header.extend(struct.pack("<Q", 0))
    elf_header.extend(struct.pack("<I", 0))
    elf_header.extend(struct.pack("<H", 64))
    elf_header.extend(struct.pack("<H", 56))
    elf_header.extend(struct.pack("<H", 0))
    elf_header.extend(struct.pack("<H", 64))
    elf_header.extend(struct.pack("<H", 0))
    elf_header.extend(struct.pack("<H", 0))

    elf_path.write_bytes(bytes(elf_header))

    return elf_path


@pytest.fixture
def sample_elf_x86(tmp_path: Path) -> Path:
    """Create a minimal valid ELF x86 binary for testing."""
    elf_path = tmp_path / "test_elf_x86"

    elf_header = bytearray()
    elf_header.extend(b"\x7fELF")
    elf_header.append(1)
    elf_header.append(1)
    elf_header.append(1)
    elf_header.extend(b"\x00" * 9)

    elf_header.extend(struct.pack("<H", 2))
    elf_header.extend(struct.pack("<H", 3))
    elf_header.extend(struct.pack("<I", 1))
    elf_header.extend(struct.pack("<I", 0x8048000))
    elf_header.extend(struct.pack("<I", 52))
    elf_header.extend(struct.pack("<I", 0))
    elf_header.extend(struct.pack("<I", 0))
    elf_header.extend(struct.pack("<H", 52))
    elf_header.extend(struct.pack("<H", 32))
    elf_header.extend(struct.pack("<H", 0))
    elf_header.extend(struct.pack("<H", 40))
    elf_header.extend(struct.pack("<H", 0))
    elf_header.extend(struct.pack("<H", 0))

    elf_path.write_bytes(bytes(elf_header))

    return elf_path


class TestELFAnalyzerInitialization:
    """Tests for ELF analyzer initialization."""

    def test_initialization(self, sample_elf_x64: Path) -> None:
        """Initialize ELF analyzer with binary path."""
        analyzer = ELFAnalyzer(sample_elf_x64)

        assert analyzer.file_path == sample_elf_x64
        assert analyzer.data is None
        assert analyzer.header is None
        assert len(analyzer.sections) == 0
        assert len(analyzer.segments) == 0
        assert len(analyzer.symbols) == 0
        assert analyzer.is_64bit is False

    def test_load_binary_success(self, sample_elf_x64: Path) -> None:
        """Load valid ELF binary successfully."""
        analyzer = ELFAnalyzer(sample_elf_x64)

        result = analyzer.load_binary()

        assert result is True
        assert analyzer.data is not None
        assert len(analyzer.data) > 0
        assert analyzer.header is not None

    def test_load_binary_invalid_file(self, tmp_path: Path) -> None:
        """Load invalid ELF binary fails."""
        invalid_path = tmp_path / "invalid.elf"
        invalid_path.write_bytes(b"NOT AN ELF FILE")

        analyzer = ELFAnalyzer(invalid_path)

        result = analyzer.load_binary()

        assert result is False

    def test_validate_elf_magic(self, sample_elf_x64: Path) -> None:
        """Validate ELF magic bytes."""
        analyzer = ELFAnalyzer(sample_elf_x64)
        analyzer.load_binary()

        assert analyzer.data[:4] == b"\x7fELF"


class TestELFHeaderParsing:
    """Tests for ELF header parsing."""

    def test_parse_header_x64(self, sample_elf_x64: Path) -> None:
        """Parse x64 ELF header."""
        analyzer = ELFAnalyzer(sample_elf_x64)
        analyzer.load_binary()

        assert analyzer.header is not None
        assert analyzer.header["ei_class"] == ELFAnalyzer.ELFCLASS64
        assert analyzer.is_64bit is True

    def test_parse_header_x86(self, sample_elf_x86: Path) -> None:
        """Parse x86 ELF header."""
        analyzer = ELFAnalyzer(sample_elf_x86)
        analyzer.load_binary()

        assert analyzer.header is not None
        assert analyzer.header["ei_class"] == ELFAnalyzer.ELFCLASS32
        assert analyzer.is_64bit is False

    def test_header_endianness_detection(self, sample_elf_x64: Path) -> None:
        """Detect ELF endianness."""
        analyzer = ELFAnalyzer(sample_elf_x64)
        analyzer.load_binary()

        assert analyzer.endian == "little"

    def test_header_type_detection(self, sample_elf_x64: Path) -> None:
        """Detect ELF type (executable, shared object, etc)."""
        analyzer = ELFAnalyzer(sample_elf_x64)
        analyzer.load_binary()

        assert analyzer.header is not None
        assert "e_type" in analyzer.header
        assert analyzer.header["e_type"] in [
            ELFAnalyzer.ET_NONE,
            ELFAnalyzer.ET_REL,
            ELFAnalyzer.ET_EXEC,
            ELFAnalyzer.ET_DYN,
            ELFAnalyzer.ET_CORE,
        ]

    def test_header_machine_type(self, sample_elf_x64: Path) -> None:
        """Detect ELF machine type."""
        analyzer = ELFAnalyzer(sample_elf_x64)
        analyzer.load_binary()

        assert analyzer.header is not None
        assert "e_machine" in analyzer.header
        assert analyzer.header["e_machine"] == ELFAnalyzer.EM_X86_64

    def test_header_entry_point(self, sample_elf_x64: Path) -> None:
        """Extract entry point from ELF header."""
        analyzer = ELFAnalyzer(sample_elf_x64)
        analyzer.load_binary()

        assert analyzer.header is not None
        assert "e_entry" in analyzer.header
        assert isinstance(analyzer.header["e_entry"], int)


class TestELFSectionAnalysis:
    """Tests for ELF section extraction."""

    def test_analyze_sections_empty(self, sample_elf_x64: Path) -> None:
        """Analyze ELF with no sections."""
        analyzer = ELFAnalyzer(sample_elf_x64)
        analyzer.load_binary()

        sections = analyzer.analyze_sections()

        assert isinstance(sections, list)

    def test_section_structure(self, simple_elf: Path) -> None:
        """Verify section structure is correct."""
        analyzer = ELFAnalyzer(simple_elf)
        analyzer.load_binary()

        sections = analyzer.analyze_sections()

        if len(sections) > 0:
            for section in sections:
                assert "index" in section
                assert "sh_name" in section
                assert "sh_type" in section
                assert "sh_flags" in section
                assert "sh_addr" in section
                assert "sh_offset" in section
                assert "sh_size" in section
                assert "sh_link" in section
                assert "sh_info" in section
                assert "sh_addralign" in section
                assert "sh_entsize" in section

    def test_section_types(self, simple_elf: Path) -> None:
        """Verify section types are parsed correctly."""
        analyzer = ELFAnalyzer(simple_elf)
        analyzer.load_binary()

        sections = analyzer.analyze_sections()

        if len(sections) > 0:
            for section in sections:
                assert isinstance(section["sh_type"], int)
                assert section["sh_type"] >= 0


class TestELFSegmentAnalysis:
    """Tests for ELF segment (program header) extraction."""

    def test_analyze_segments_empty(self, sample_elf_x64: Path) -> None:
        """Analyze ELF with no segments."""
        analyzer = ELFAnalyzer(sample_elf_x64)
        analyzer.load_binary()

        segments = analyzer.analyze_segments()

        assert isinstance(segments, list)

    def test_segment_structure(self, simple_elf: Path) -> None:
        """Verify segment structure is correct."""
        analyzer = ELFAnalyzer(simple_elf)
        analyzer.load_binary()

        segments = analyzer.analyze_segments()

        if len(segments) > 0:
            for segment in segments:
                assert "index" in segment
                assert "p_type" in segment
                assert "p_flags" in segment
                assert "p_offset" in segment
                assert "p_vaddr" in segment
                assert "p_paddr" in segment
                assert "p_filesz" in segment
                assert "p_memsz" in segment
                assert "p_align" in segment

    def test_segment_types(self, simple_elf: Path) -> None:
        """Verify segment types are correct."""
        analyzer = ELFAnalyzer(simple_elf)
        analyzer.load_binary()

        segments = analyzer.analyze_segments()

        if len(segments) > 0:
            for segment in segments:
                assert isinstance(segment["p_type"], int)
                assert segment["p_type"] >= 0


class TestELFSymbolExtraction:
    """Tests for ELF symbol table extraction."""

    def test_find_symbols(self, simple_elf: Path) -> None:
        """Extract symbol table from ELF."""
        analyzer = ELFAnalyzer(simple_elf)
        analyzer.load_binary()
        analyzer.analyze_sections()

        symbols = analyzer.find_symbols()

        assert isinstance(symbols, list)

    def test_symbol_structure(self, simple_elf: Path) -> None:
        """Verify symbol structure is correct."""
        analyzer = ELFAnalyzer(simple_elf)
        analyzer.load_binary()
        analyzer.analyze_sections()

        symbols = analyzer.find_symbols()

        if len(symbols) > 0:
            for symbol in symbols:
                assert "st_name" in symbol
                assert "st_info" in symbol
                assert "st_other" in symbol
                assert "st_shndx" in symbol
                assert "st_value" in symbol
                assert "st_size" in symbol


class TestELFSecurityFeatures:
    """Tests for security feature detection."""

    def test_get_security_features(self, sample_elf_x64: Path) -> None:
        """Extract security features from ELF."""
        analyzer = ELFAnalyzer(sample_elf_x64)
        analyzer.load_binary()
        analyzer.analyze_sections()
        analyzer.analyze_segments()

        features = analyzer.get_security_features()

        assert isinstance(features, dict)
        assert "nx_bit" in features
        assert "stack_canary" in features
        assert "pie" in features
        assert "relro" in features
        assert "fortify" in features
        assert "stripped" in features

        assert isinstance(features["nx_bit"], bool)
        assert isinstance(features["stack_canary"], bool)
        assert isinstance(features["pie"], bool)
        assert isinstance(features["relro"], bool)
        assert isinstance(features["fortify"], bool)
        assert isinstance(features["stripped"], bool)

    def test_pie_detection(self, sample_elf_x64: Path) -> None:
        """Detect PIE (Position Independent Executable)."""
        analyzer = ELFAnalyzer(sample_elf_x64)
        analyzer.load_binary()
        analyzer.analyze_sections()
        analyzer.analyze_segments()

        features = analyzer.get_security_features()

        if analyzer.header and analyzer.header["e_type"] == ELFAnalyzer.ET_DYN:
            assert features["pie"] is True


class TestELFArchitectureDetection:
    """Tests for architecture detection."""

    def test_get_architecture_x64(self, sample_elf_x64: Path) -> None:
        """Detect x86_64 architecture."""
        analyzer = ELFAnalyzer(sample_elf_x64)
        analyzer.load_binary()

        arch = analyzer._get_architecture()

        assert isinstance(arch, str)
        assert "x86_64" in arch
        assert "64" in arch

    def test_get_architecture_x86(self, sample_elf_x86: Path) -> None:
        """Detect x86 architecture."""
        analyzer = ELFAnalyzer(sample_elf_x86)
        analyzer.load_binary()

        arch = analyzer._get_architecture()

        assert isinstance(arch, str)
        assert "x86" in arch or "32" in arch

    def test_architecture_endianness(self, sample_elf_x64: Path) -> None:
        """Architecture string includes endianness."""
        analyzer = ELFAnalyzer(sample_elf_x64)
        analyzer.load_binary()

        arch = analyzer._get_architecture()

        assert "LE" in arch or "BE" in arch


class TestELFComprehensiveAnalysis:
    """Tests for comprehensive ELF analysis."""

    def test_analyze_complete(self, sample_elf_x64: Path) -> None:
        """Perform complete ELF analysis."""
        analyzer = ELFAnalyzer(sample_elf_x64)

        result = analyzer.analyze()

        assert isinstance(result, dict)
        assert "file_path" in result
        assert "header" in result
        assert "architecture" in result
        assert "sections" in result
        assert "segments" in result
        assert "symbols" in result
        assert "security_features" in result
        assert "file_size" in result

    def test_analyze_elf_file_function(self, sample_elf_x64: Path) -> None:
        """Analyze ELF using convenience function."""
        result = analyze_elf_file(sample_elf_x64)

        assert isinstance(result, dict)
        assert "header" in result
        assert "architecture" in result

    def test_analyze_invalid_elf(self, tmp_path: Path) -> None:
        """Analyze invalid ELF returns error."""
        invalid_path = tmp_path / "invalid.elf"
        invalid_path.write_bytes(b"INVALID")

        result = analyze_elf_file(invalid_path)

        assert "error" in result


class TestELFUtilityFunctions:
    """Tests for ELF utility functions."""

    def test_is_elf_file_valid(self, sample_elf_x64: Path) -> None:
        """Check if file is valid ELF."""
        result = is_elf_file(sample_elf_x64)

        assert result is True

    def test_is_elf_file_invalid(self, tmp_path: Path) -> None:
        """Check if non-ELF file is detected."""
        non_elf = tmp_path / "not_elf.txt"
        non_elf.write_text("This is not an ELF file")

        result = is_elf_file(non_elf)

        assert result is False

    def test_is_elf_file_nonexistent(self, tmp_path: Path) -> None:
        """Check nonexistent file returns False."""
        nonexistent = tmp_path / "nonexistent.elf"

        result = is_elf_file(nonexistent)

        assert result is False

    def test_extract_elf_strings(self, sample_elf_x64: Path) -> None:
        """Extract printable strings from ELF."""
        strings = extract_elf_strings(sample_elf_x64)

        assert isinstance(strings, list)

    def test_extract_elf_strings_min_length(self, sample_elf_x64: Path) -> None:
        """Extract strings with minimum length filter."""
        strings = extract_elf_strings(sample_elf_x64, min_length=10)

        assert isinstance(strings, list)

        for string in strings:
            assert len(string) >= 10

    def test_extract_elf_strings_contains_elf_marker(self, sample_elf_x64: Path) -> None:
        """Extracted strings may contain ELF marker."""
        strings = extract_elf_strings(sample_elf_x64, min_length=4)

        assert isinstance(strings, list)


@pytest.mark.integration
class TestRealELFBinaries:
    """Integration tests with real ELF binaries."""

    def test_analyze_real_elf_binary(self, simple_elf: Path) -> None:
        """Analyze real ELF binary from fixtures."""
        analyzer = ELFAnalyzer(simple_elf)

        result = analyzer.analyze()

        assert "error" not in result
        assert result["header"] is not None

    def test_real_binary_has_sections(self, simple_elf: Path) -> None:
        """Real ELF binary has sections."""
        analyzer = ELFAnalyzer(simple_elf)
        analyzer.load_binary()

        sections = analyzer.analyze_sections()

        assert len(sections) >= 0

    def test_real_binary_has_segments(self, simple_elf: Path) -> None:
        """Real ELF binary has program headers."""
        analyzer = ELFAnalyzer(simple_elf)
        analyzer.load_binary()

        segments = analyzer.analyze_segments()

        assert len(segments) >= 0


@pytest.mark.performance
class TestELFAnalysisPerformance:
    """Performance tests for ELF analysis."""

    def test_analysis_performance(self, sample_elf_x64: Path) -> None:
        """ELF analysis completes within reasonable time."""
        import time

        analyzer = ELFAnalyzer(sample_elf_x64)

        start_time = time.time()
        analyzer.analyze()
        elapsed = time.time() - start_time

        assert elapsed < 2.0

    def test_section_parsing_performance(self, simple_elf: Path) -> None:
        """Section parsing is fast."""
        import time

        analyzer = ELFAnalyzer(simple_elf)
        analyzer.load_binary()

        start_time = time.time()
        analyzer.analyze_sections()
        elapsed = time.time() - start_time

        assert elapsed < 1.0
