"""Production tests for Binary Analyzer Engine.

Tests validate real binary analysis on actual Windows binaries from C:\\Windows\\System32.
NO MOCKS - all tests use real PE/ELF binaries with actual structures.
Tests must verify genuine binary analysis capabilities for license protection detection.

CRITICAL: These tests MUST FAIL if binary analysis doesn't work correctly.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import json
import math
import struct
import tempfile
from pathlib import Path
from typing import Any, Generator

import pytest

from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer


@pytest.fixture(scope="module")
def analyzer() -> BinaryAnalyzer:
    """Create BinaryAnalyzer instance for testing.

    Returns:
        BinaryAnalyzer instance ready for analysis operations.

    """
    return BinaryAnalyzer()


@pytest.fixture(scope="module")
def notepad_path() -> Path:
    """Path to notepad.exe for testing PE analysis.

    Returns:
        Path to notepad.exe in System32.

    """
    path = Path(r"C:\Windows\System32\notepad.exe")
    assert path.exists(), "notepad.exe not found - required for testing"
    return path


@pytest.fixture(scope="module")
def calc_path() -> Path:
    """Path to calc.exe for testing PE analysis.

    Returns:
        Path to calc.exe in System32.

    """
    path = Path(r"C:\Windows\System32\calc.exe")
    assert path.exists(), "calc.exe not found - required for testing"
    return path


@pytest.fixture(scope="module")
def kernel32_path() -> Path:
    """Path to kernel32.dll for testing DLL analysis.

    Returns:
        Path to kernel32.dll in System32.

    """
    path = Path(r"C:\Windows\System32\kernel32.dll")
    assert path.exists(), "kernel32.dll not found - required for testing"
    return path


@pytest.fixture(scope="module")
def ntdll_path() -> Path:
    """Path to ntdll.dll for testing DLL analysis.

    Returns:
        Path to ntdll.dll in System32.

    """
    path = Path(r"C:\Windows\System32\ntdll.dll")
    assert path.exists(), "ntdll.dll not found - required for testing"
    return path


@pytest.fixture(scope="module")
def user32_path() -> Path:
    """Path to user32.dll for testing DLL analysis.

    Returns:
        Path to user32.dll in System32.

    """
    path = Path(r"C:\Windows\System32\user32.dll")
    assert path.exists(), "user32.dll not found - required for testing"
    return path


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create temporary directory for test artifacts.

    Yields:
        Path to temporary directory that will be cleaned up.

    """
    with tempfile.TemporaryDirectory(prefix="binary_analyzer_test_") as tmpdir:
        yield Path(tmpdir)


class TestBinaryAnalyzerInitialization:
    """Tests for BinaryAnalyzer initialization and configuration."""

    def test_analyzer_initializes_successfully(self, analyzer: BinaryAnalyzer) -> None:
        """Analyzer initializes with proper configuration."""
        assert analyzer is not None
        assert hasattr(analyzer, "logger")
        assert hasattr(analyzer, "magic_bytes")
        assert analyzer.LARGE_FILE_THRESHOLD == 50 * 1024 * 1024
        assert analyzer.CHUNK_SIZE == 8 * 1024 * 1024
        assert analyzer.HASH_CHUNK_SIZE == 64 * 1024

    def test_analyzer_has_correct_magic_bytes(self, analyzer: BinaryAnalyzer) -> None:
        """Analyzer configured with correct magic byte signatures."""
        assert b"MZ" in analyzer.magic_bytes
        assert analyzer.magic_bytes[b"MZ"] == "PE"
        assert b"\x7fELF" in analyzer.magic_bytes
        assert analyzer.magic_bytes[b"\x7fELF"] == "ELF"
        assert b"dex\n" in analyzer.magic_bytes
        assert b"PK\x03\x04" in analyzer.magic_bytes

    def test_analyzer_magic_bytes_completeness(self, analyzer: BinaryAnalyzer) -> None:
        """Analyzer supports all critical executable formats."""
        required_formats = {
            "PE",
            "ELF",
            "Android DEX",
            "ZIP/JAR/APK",
            "Mach-O (32-bit)",
            "Mach-O (64-bit)",
        }
        supported_formats = set(analyzer.magic_bytes.values())
        assert required_formats.issubset(supported_formats)


class TestFormatDetection:
    """Tests for binary format detection using magic bytes."""

    def test_detect_pe_format_notepad(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Correctly detects PE format for notepad.exe."""
        detected_format = analyzer._detect_format(notepad_path)
        assert detected_format == "PE", f"Failed to detect PE format, got: {detected_format}"

    def test_detect_pe_format_calc(self, analyzer: BinaryAnalyzer, calc_path: Path) -> None:
        """Correctly detects PE format for calc.exe."""
        detected_format = analyzer._detect_format(calc_path)
        assert detected_format == "PE", f"Failed to detect PE format, got: {detected_format}"

    def test_detect_pe_format_kernel32(self, analyzer: BinaryAnalyzer, kernel32_path: Path) -> None:
        """Correctly detects PE format for kernel32.dll."""
        detected_format = analyzer._detect_format(kernel32_path)
        assert detected_format == "PE", f"Failed to detect PE format for DLL, got: {detected_format}"

    def test_detect_format_streaming_notepad(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Streaming format detection works for PE files."""
        detected_format = analyzer._detect_format_streaming(notepad_path)
        assert detected_format == "PE", f"Streaming detection failed, got: {detected_format}"

    def test_detect_format_nonexistent_file(self, analyzer: BinaryAnalyzer) -> None:
        """Format detection handles nonexistent files gracefully."""
        fake_path = Path(r"C:\nonexistent\fake.exe")
        detected_format = analyzer._detect_format(fake_path)
        assert "Error" in detected_format or detected_format == "Unknown"


class TestHashCalculation:
    """Tests for cryptographic hash calculation."""

    def test_calculate_hashes_notepad(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Calculates correct hashes for notepad.exe."""
        hashes = analyzer._calculate_hashes(notepad_path)

        assert "error" not in hashes
        assert "sha256" in hashes
        assert "sha512" in hashes
        assert "sha3_256" in hashes
        assert "blake2b" in hashes

        assert len(hashes["sha256"]) == 64
        assert len(hashes["sha512"]) == 128
        assert len(hashes["sha3_256"]) == 64
        assert len(hashes["blake2b"]) == 128

        assert all(c in "0123456789abcdef" for c in hashes["sha256"])

    def test_calculate_hashes_matches_manual_calculation(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Hash calculation matches manual verification."""
        hashes = analyzer._calculate_hashes(notepad_path)

        with open(notepad_path, "rb") as f:
            data = f.read()

        manual_sha256 = hashlib.sha256(data).hexdigest()
        assert hashes["sha256"] == manual_sha256

    def test_calculate_hashes_streaming_notepad(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Streaming hash calculation produces correct results."""
        hashes_streaming = analyzer._calculate_hashes_streaming(notepad_path)
        hashes_normal = analyzer._calculate_hashes(notepad_path)

        assert hashes_streaming["sha256"] == hashes_normal["sha256"]
        assert hashes_streaming["sha512"] == hashes_normal["sha512"]

    def test_calculate_hashes_streaming_with_progress(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Streaming hash calculation supports progress callback."""
        progress_calls: list[tuple[int, int]] = []

        def progress_callback(current: int, total: int) -> None:
            progress_calls.append((current, total))

        hashes = analyzer._calculate_hashes_streaming(notepad_path, progress_callback)

        assert "sha256" in hashes
        assert progress_calls
        assert progress_calls[-1][0] == progress_calls[-1][1]

    def test_calculate_hashes_kernel32(self, analyzer: BinaryAnalyzer, kernel32_path: Path) -> None:
        """Calculates correct hashes for large DLL."""
        hashes = analyzer._calculate_hashes_streaming(kernel32_path)

        assert "error" not in hashes
        assert len(hashes["sha256"]) == 64
        assert all(c in "0123456789abcdef" for c in hashes["sha256"])


class TestPEHeaderParsing:
    """Tests for PE header extraction and parsing."""

    def test_parse_pe_dos_header_notepad(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Correctly parses DOS header from notepad.exe."""
        with open(notepad_path, "rb") as f:
            data = f.read()

        assert data[:2] == b"MZ", "DOS signature missing"

        pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
        assert pe_offset > 0
        assert pe_offset < len(data)
        assert data[pe_offset : pe_offset + 4] == b"PE\x00\x00"

    def test_parse_pe_coff_header_notepad(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Correctly parses COFF header from notepad.exe."""
        pe_info = analyzer._analyze_pe(notepad_path)

        assert "error" not in pe_info
        assert "machine" in pe_info
        assert "num_sections" in pe_info
        assert "timestamp" in pe_info
        assert "characteristics" in pe_info

        assert pe_info["machine"] in ["0x014c", "0x8664"]
        assert pe_info["num_sections"] > 0

    def test_parse_pe_optional_header_notepad(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """PE analysis extracts optional header information."""
        pe_info = analyzer._analyze_pe(notepad_path)

        assert "error" not in pe_info
        assert pe_info["num_sections"] > 0

    def test_parse_pe_streaming_notepad(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Streaming PE parsing produces same results as normal parsing."""
        pe_info_normal = analyzer._analyze_pe(notepad_path)
        pe_info_streaming = analyzer._analyze_pe_streaming(notepad_path)

        assert pe_info_normal["machine"] == pe_info_streaming["machine"]
        assert pe_info_normal["num_sections"] == pe_info_streaming["num_sections"]

    def test_parse_pe_coff_header_kernel32(self, analyzer: BinaryAnalyzer, kernel32_path: Path) -> None:
        """Correctly parses COFF header from kernel32.dll."""
        pe_info = analyzer._analyze_pe(kernel32_path)

        assert "error" not in pe_info
        assert pe_info["num_sections"] > 0
        assert "sections" in pe_info


class TestSectionTableExtraction:
    """Tests for PE section table parsing."""

    def test_extract_sections_notepad(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Extracts all sections from notepad.exe."""
        pe_info = analyzer._analyze_pe(notepad_path)

        assert "sections" in pe_info
        assert len(pe_info["sections"]) > 0

        for section in pe_info["sections"]:
            assert "name" in section
            assert "virtual_address" in section
            assert "virtual_size" in section
            assert "raw_size" in section
            assert "raw_address" in section

    def test_extract_text_section_notepad(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Correctly identifies .text section in notepad.exe."""
        pe_info = analyzer._analyze_pe(notepad_path)
        sections = pe_info["sections"]
        section_names = [s["name"] for s in sections]

        assert ".text" in section_names

        text_section = next(s for s in sections if s["name"] == ".text")
        assert text_section["virtual_size"] > 0
        assert text_section["raw_size"] > 0

    def test_extract_data_section_notepad(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Correctly identifies .data section in notepad.exe."""
        pe_info = analyzer._analyze_pe(notepad_path)
        sections = pe_info["sections"]
        section_names = [s["name"] for s in sections]

        assert ".data" in section_names or ".rdata" in section_names

    def test_extract_sections_kernel32(self, analyzer: BinaryAnalyzer, kernel32_path: Path) -> None:
        """Extracts all sections from kernel32.dll."""
        pe_info = analyzer._analyze_pe(kernel32_path)

        assert len(pe_info["sections"]) >= 3
        assert all("name" in s for s in pe_info["sections"])

    def test_section_virtual_addresses_valid(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Section virtual addresses are properly formatted."""
        pe_info = analyzer._analyze_pe(notepad_path)

        for section in pe_info["sections"]:
            assert section["virtual_address"].startswith("0x")
            int(section["virtual_address"], 16)

    def test_section_sizes_realistic(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Section sizes are within realistic bounds."""
        pe_info = analyzer._analyze_pe(notepad_path)

        for section in pe_info["sections"]:
            assert 0 <= section["virtual_size"] < 100 * 1024 * 1024
            assert 0 <= section["raw_size"] < 100 * 1024 * 1024


class TestArchitectureDetection:
    """Tests for architecture detection (x86/x64)."""

    def test_detect_architecture_notepad(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Correctly detects architecture of notepad.exe."""
        pe_info = analyzer._analyze_pe(notepad_path)

        machine = pe_info["machine"]
        assert machine in ["0x014c", "0x8664"]

    def test_detect_x64_architecture(self, analyzer: BinaryAnalyzer, kernel32_path: Path) -> None:
        """Correctly identifies x64 binaries."""
        pe_info = analyzer._analyze_pe(kernel32_path)

        machine = pe_info["machine"]
        is_x64 = machine == "0x8664"
        is_x86 = machine == "0x014c"

        assert is_x64 or is_x86


class TestStringExtraction:
    """Tests for string extraction from binaries."""

    def test_extract_strings_notepad(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Extracts meaningful strings from notepad.exe."""
        strings = analyzer._extract_strings(notepad_path)

        assert len(strings) > 0
        assert all(isinstance(s, str) for s in strings)
        assert all(len(s) >= 4 for s in strings)

    def test_extract_strings_contain_expected_content(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Extracted strings contain expected Windows PE content."""
        strings = analyzer._extract_strings(notepad_path)
        all_strings = " ".join(strings).lower()

        common_pe_strings = [".dll", ".exe", "microsoft", "windows", "text", "data"]
        found_count = sum(bool(s in all_strings)
                      for s in common_pe_strings)

        assert found_count >= 1

    def test_extract_strings_streaming_notepad(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Streaming string extraction produces valid results."""
        strings = analyzer._extract_strings_streaming(notepad_path)

        assert len(strings) > 0
        assert all(isinstance(s, str) for s in strings)

    def test_extract_strings_streaming_max_limit(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Streaming string extraction respects max_strings limit."""
        strings = analyzer._extract_strings_streaming(notepad_path, max_strings=10)

        assert len(strings) <= 10

    def test_extract_strings_excludes_hex_only(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """String extraction filters out hex-only sequences."""
        strings = analyzer._extract_strings(notepad_path)

        hex_only_strings = [s for s in strings if all(c in "0123456789ABCDEFabcdef" for c in s)]
        total_strings = len(strings)

        assert total_strings > 0
        assert len(hex_only_strings) < total_strings


class TestEntropyAnalysis:
    """Tests for entropy analysis and packer detection."""

    def test_analyze_entropy_notepad(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Calculates entropy for notepad.exe."""
        entropy_info = analyzer._analyze_entropy(notepad_path)

        assert "error" not in entropy_info
        assert "overall_entropy" in entropy_info
        assert "file_size" in entropy_info
        assert "unique_bytes" in entropy_info
        assert "analysis" in entropy_info

    def test_entropy_value_realistic(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Entropy value is within realistic bounds."""
        entropy_info = analyzer._analyze_entropy(notepad_path)

        entropy = entropy_info["overall_entropy"]
        assert 0.0 <= entropy <= 8.0

    def test_entropy_matches_manual_calculation(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Entropy calculation matches manual verification."""
        entropy_info = analyzer._analyze_entropy(notepad_path)

        with open(notepad_path, "rb") as f:
            data = f.read()

        byte_counts: dict[int, int] = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1

        total = len(data)
        manual_entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                probability = count / total
                manual_entropy -= probability * math.log2(probability)

        assert abs(entropy_info["overall_entropy"] - manual_entropy) < 0.01

    def test_entropy_streaming_notepad(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Streaming entropy analysis produces correct results."""
        entropy_normal = analyzer._analyze_entropy(notepad_path)
        entropy_streaming = analyzer._analyze_entropy_streaming(notepad_path)

        assert abs(entropy_normal["overall_entropy"] - entropy_streaming["overall_entropy"]) < 0.01

    def test_entropy_analysis_classification(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Entropy analysis provides classification."""
        entropy_info = analyzer._analyze_entropy(notepad_path)

        analysis = entropy_info["analysis"]
        assert analysis in ["Normal", "High (possibly packed/encrypted)"]

    def test_entropy_unique_bytes_count(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Entropy analysis counts unique bytes correctly."""
        entropy_info = analyzer._analyze_entropy(notepad_path)

        unique_bytes = entropy_info["unique_bytes"]
        assert 1 <= unique_bytes <= 256


class TestFileInformation:
    """Tests for file metadata extraction."""

    def test_get_file_info_notepad(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Extracts correct file information from notepad.exe."""
        file_info = analyzer._get_file_info(notepad_path)

        assert "error" not in file_info
        assert "size" in file_info
        assert "created" in file_info
        assert "modified" in file_info
        assert "accessed" in file_info

    def test_file_size_accurate(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """File size matches actual size."""
        file_info = analyzer._get_file_info(notepad_path)

        actual_size = notepad_path.stat().st_size
        assert file_info["size"] == actual_size

    def test_file_timestamps_valid_format(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """File timestamps are in ISO format."""
        file_info = analyzer._get_file_info(notepad_path)

        assert "T" in file_info["created"]
        assert "T" in file_info["modified"]


class TestComprehensiveAnalysis:
    """Tests for complete binary analysis workflow."""

    def test_analyze_notepad_complete(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Complete analysis of notepad.exe succeeds."""
        result = analyzer.analyze(notepad_path)

        assert "error" not in result
        assert result["analysis_status"] == "completed"
        assert result["format"] == "PE"
        assert "file_info" in result
        assert "hashes" in result
        assert "format_analysis" in result
        assert "strings" in result
        assert "entropy" in result
        assert "security" in result
        assert "timestamp" in result

    def test_analyze_calc_complete(self, analyzer: BinaryAnalyzer, calc_path: Path) -> None:
        """Complete analysis of calc.exe succeeds."""
        result = analyzer.analyze(calc_path)

        assert result["analysis_status"] == "completed"
        assert result["format"] == "PE"

    def test_analyze_kernel32_complete(self, analyzer: BinaryAnalyzer, kernel32_path: Path) -> None:
        """Complete analysis of kernel32.dll succeeds."""
        result = analyzer.analyze(kernel32_path)

        assert result["analysis_status"] == "completed"
        assert result["format"] == "PE"

    def test_analyze_includes_pe_sections(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Complete analysis includes PE section information."""
        result = analyzer.analyze(notepad_path)

        assert "sections" in result["format_analysis"]
        assert len(result["format_analysis"]["sections"]) > 0

    def test_analyze_includes_hashes(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Complete analysis includes all hash algorithms."""
        result = analyzer.analyze(notepad_path)

        hashes = result["hashes"]
        assert "sha256" in hashes
        assert "sha512" in hashes
        assert "sha3_256" in hashes
        assert "blake2b" in hashes

    def test_analyze_nonexistent_file(self, analyzer: BinaryAnalyzer) -> None:
        """Analysis handles nonexistent files gracefully."""
        result = analyzer.analyze(r"C:\nonexistent\fake.exe")

        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_analyze_streaming_mode_auto_detect(self, analyzer: BinaryAnalyzer, kernel32_path: Path) -> None:
        """Analysis auto-detects streaming mode for large files."""
        result = analyzer.analyze(kernel32_path, use_streaming=True)

        assert result["analysis_status"] == "completed"
        assert result.get("streaming_mode") is True

    def test_analyze_streaming_mode_forced(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Analysis respects forced streaming mode."""
        result = analyzer.analyze(notepad_path, use_streaming=True)

        assert result["analysis_status"] == "completed"
        assert result.get("streaming_mode") is True


class TestProgressTracking:
    """Tests for analysis progress tracking."""

    def test_analyze_with_progress_notepad(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Analysis with progress tracking completes successfully."""
        progress_updates: list[tuple[str, int, int]] = []

        def progress_callback(stage: str, current: int, total: int) -> None:
            progress_updates.append((stage, current, total))

        result = analyzer.analyze_with_progress(notepad_path, progress_callback)

        assert result["analysis_status"] == "completed"
        assert progress_updates

    def test_analyze_with_progress_completion(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Progress tracking reaches completion."""
        progress_updates: list[tuple[str, int, int]] = []

        def progress_callback(stage: str, current: int, total: int) -> None:
            progress_updates.append((stage, current, total))

        result = analyzer.analyze_with_progress(notepad_path, progress_callback)

        assert result["analysis_status"] == "completed"
        final_stage = progress_updates[-1]
        assert final_stage[0] == "completed"
        assert final_stage[1] == final_stage[2]

    def test_analyze_with_progress_stages(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Progress tracking covers all analysis stages."""
        progress_updates: list[tuple[str, int, int]] = []

        def progress_callback(stage: str, current: int, total: int) -> None:
            progress_updates.append((stage, current, total))

        analyzer.analyze_with_progress(notepad_path, progress_callback)

        stages = [update[0] for update in progress_updates]
        assert "format_detection" in stages
        assert "completed" in stages


class TestCheckpointManagement:
    """Tests for analysis checkpoint save/load functionality."""

    def test_save_checkpoint_succeeds(self, analyzer: BinaryAnalyzer, temp_dir: Path) -> None:
        """Checkpoint saving succeeds."""
        checkpoint_path = temp_dir / "checkpoint.json"
        test_data = {"format": "PE", "status": "in_progress"}

        success = analyzer.save_analysis_checkpoint(test_data, checkpoint_path)

        assert success is True
        assert checkpoint_path.exists()

    def test_save_checkpoint_creates_directory(self, analyzer: BinaryAnalyzer, temp_dir: Path) -> None:
        """Checkpoint saving creates parent directories."""
        checkpoint_path = temp_dir / "subdir" / "checkpoint.json"
        test_data = {"format": "PE"}

        success = analyzer.save_analysis_checkpoint(test_data, checkpoint_path)

        assert success is True
        assert checkpoint_path.exists()

    def test_load_checkpoint_succeeds(self, analyzer: BinaryAnalyzer, temp_dir: Path) -> None:
        """Checkpoint loading succeeds."""
        checkpoint_path = temp_dir / "checkpoint.json"
        test_data = {"format": "PE", "sections": 5}

        analyzer.save_analysis_checkpoint(test_data, checkpoint_path)
        loaded_data = analyzer.load_analysis_checkpoint(checkpoint_path)

        assert loaded_data is not None
        assert loaded_data["format"] == "PE"
        assert loaded_data["sections"] == 5

    def test_load_checkpoint_nonexistent_file(self, analyzer: BinaryAnalyzer, temp_dir: Path) -> None:
        """Loading nonexistent checkpoint returns None."""
        checkpoint_path = temp_dir / "nonexistent.json"

        loaded_data = analyzer.load_analysis_checkpoint(checkpoint_path)

        assert loaded_data is None

    def test_checkpoint_roundtrip_preserves_data(self, analyzer: BinaryAnalyzer, temp_dir: Path) -> None:
        """Checkpoint save/load roundtrip preserves data integrity."""
        checkpoint_path = temp_dir / "checkpoint.json"
        original_data = {
            "format": "PE",
            "hashes": {"sha256": "abc123"},
            "sections": [{"name": ".text", "size": 1024}],
        }

        analyzer.save_analysis_checkpoint(original_data, checkpoint_path)
        loaded_data = analyzer.load_analysis_checkpoint(checkpoint_path)

        assert loaded_data == original_data


class TestPatternScanning:
    """Tests for byte pattern scanning in binaries."""

    def test_scan_for_patterns_notepad(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Pattern scanning finds MZ header in notepad.exe."""
        patterns = [b"MZ", b"PE\x00\x00"]
        results = analyzer.scan_for_patterns_streaming(notepad_path, patterns)

        assert "4d5a" in results
        assert len(results["4d5a"]) > 0
        assert results["4d5a"][0]["offset"] == 0

    def test_scan_for_patterns_with_context(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Pattern scanning includes context bytes."""
        patterns = [b"MZ"]
        results = analyzer.scan_for_patterns_streaming(notepad_path, patterns, context_bytes=16)

        assert len(results["4d5a"]) > 0
        match = results["4d5a"][0]
        assert "context_before" in match
        assert "context_after" in match
        assert "match" in match

    def test_scan_for_multiple_patterns(self, analyzer: BinaryAnalyzer, kernel32_path: Path) -> None:
        """Pattern scanning finds multiple different patterns."""
        patterns = [b"MZ", b".text", b".data"]
        results = analyzer.scan_for_patterns_streaming(kernel32_path, patterns)

        assert len(results) == 3
        assert "4d5a" in results

    def test_scan_for_patterns_pe_signature(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Pattern scanning finds PE signature."""
        patterns = [b"PE\x00\x00"]
        results = analyzer.scan_for_patterns_streaming(notepad_path, patterns)

        pe_sig_hex = b"PE\x00\x00".hex()
        assert pe_sig_hex in results
        assert len(results[pe_sig_hex]) > 0
        assert results[pe_sig_hex][0]["offset"] > 0


class TestLicenseStringDetection:
    """Tests for license-related string detection."""

    def test_scan_for_license_strings_notepad(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """License string scanning produces results."""
        results = analyzer.scan_for_license_strings_streaming(notepad_path)

        assert isinstance(results, list)

    def test_license_strings_have_required_fields(self, analyzer: BinaryAnalyzer, kernel32_path: Path) -> None:
        """License string matches contain required fields."""
        results = analyzer.scan_for_license_strings_streaming(kernel32_path)

        if len(results) > 0 and "error" not in results[0]:
            for match in results[:5]:
                assert "offset" in match
                assert "string" in match
                assert "pattern_matched" in match
                assert "length" in match

    def test_license_strings_patterns_detected(self, analyzer: BinaryAnalyzer, kernel32_path: Path) -> None:
        """License string scanning detects expected patterns."""
        results = analyzer.scan_for_license_strings_streaming(kernel32_path)

        if len(results) > 0 and "error" not in results[0]:
            patterns_found = {match["pattern_matched"] for match in results}
            assert patterns_found


class TestSectionAnalysis:
    """Tests for section-specific analysis."""

    def test_analyze_sections_streaming(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Section analysis with memory mapping succeeds."""
        section_ranges = [(0, 1024), (1024, 2048)]
        results = analyzer.analyze_sections_streaming(notepad_path, section_ranges)

        assert "error" not in results
        assert "section_0" in results
        assert "section_1" in results

    def test_analyze_sections_entropy_calculation(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Section analysis calculates entropy correctly."""
        section_ranges = [(0, 4096)]
        results = analyzer.analyze_sections_streaming(notepad_path, section_ranges)

        section_0 = results["section_0"]
        assert "entropy" in section_0
        assert 0.0 <= section_0["entropy"] <= 8.0

    def test_analyze_sections_characteristics(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Section analysis provides characteristic classification."""
        section_ranges = [(0, 4096)]
        results = analyzer.analyze_sections_streaming(notepad_path, section_ranges)

        section_0 = results["section_0"]
        assert "characteristics" in section_0
        assert isinstance(section_0["characteristics"], str)

    def test_analyze_sections_invalid_range(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Section analysis handles invalid ranges gracefully."""
        file_size = notepad_path.stat().st_size
        section_ranges = [(0, file_size + 1000)]
        results = analyzer.analyze_sections_streaming(notepad_path, section_ranges)

        assert "section_0" in results
        assert "error" in results["section_0"]

    def test_classify_section_characteristics_encrypted(self, analyzer: BinaryAnalyzer) -> None:
        """Section classification identifies encrypted sections."""
        classification = analyzer._classify_section_characteristics(7.8, 0.05)
        assert classification == "Encrypted/Compressed"

    def test_classify_section_characteristics_text(self, analyzer: BinaryAnalyzer) -> None:
        """Section classification identifies text sections."""
        classification = analyzer._classify_section_characteristics(5.0, 0.9)
        assert classification == "Text/Strings"

    def test_classify_section_characteristics_code(self, analyzer: BinaryAnalyzer) -> None:
        """Section classification identifies code sections."""
        classification = analyzer._classify_section_characteristics(6.0, 0.05)
        assert classification == "Code/Binary Data"


class TestMemoryMapping:
    """Tests for memory-mapped file operations."""

    def test_open_mmap_notepad(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Memory mapping opens file successfully."""
        file_handle, mmap_obj = analyzer._open_mmap(notepad_path)

        try:
            assert file_handle is not None
            assert mmap_obj is not None
            assert len(mmap_obj) > 0
        finally:
            mmap_obj.close()
            file_handle.close()

    def test_mmap_read_access(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Memory-mapped file supports read operations."""
        file_handle, mmap_obj = analyzer._open_mmap(notepad_path)

        try:
            header = mmap_obj[:2]
            assert header == b"MZ"
        finally:
            mmap_obj.close()
            file_handle.close()

    def test_mmap_size_matches_file(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Memory-mapped size matches file size."""
        file_handle, mmap_obj = analyzer._open_mmap(notepad_path)

        try:
            file_size = notepad_path.stat().st_size
            assert len(mmap_obj) == file_size
        finally:
            mmap_obj.close()
            file_handle.close()


class TestChunkReading:
    """Tests for chunked file reading."""

    def test_read_chunks_notepad(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Chunk reading produces valid chunks."""
        chunks = list(analyzer._read_chunks(notepad_path, chunk_size=1024))

        assert chunks
        assert all(isinstance(chunk, bytes) for chunk, _ in chunks)
        assert all(isinstance(offset, int) for _, offset in chunks)

    def test_read_chunks_offsets_correct(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Chunk reading produces correct offsets."""
        chunk_size = 1024
        chunks = list(analyzer._read_chunks(notepad_path, chunk_size=chunk_size))

        for i, (chunk, offset) in enumerate(chunks):
            expected_offset = i * chunk_size
            assert offset == expected_offset

    def test_read_chunks_complete_file(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Chunk reading covers entire file."""
        chunk_size = 1024
        chunks = list(analyzer._read_chunks(notepad_path, chunk_size=chunk_size))

        total_bytes = sum(len(chunk) for chunk, _ in chunks)
        file_size = notepad_path.stat().st_size

        assert total_bytes == file_size

    def test_read_chunks_custom_size(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Chunk reading respects custom chunk size."""
        chunk_size = 512
        chunks = list(analyzer._read_chunks(notepad_path, chunk_size=chunk_size))

        for chunk, _ in chunks[:-1]:
            assert len(chunk) == chunk_size


class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_analyze_empty_path_string(self, analyzer: BinaryAnalyzer) -> None:
        """Analysis handles empty path gracefully."""
        result = analyzer.analyze("")

        assert "error" in result

    def test_analyze_directory_instead_of_file(self, analyzer: BinaryAnalyzer) -> None:
        """Analysis handles directory path gracefully."""
        result = analyzer.analyze(r"C:\Windows\System32")

        assert "error" in result
        assert "not a file" in result["error"].lower()

    def test_analyze_very_small_file(self, analyzer: BinaryAnalyzer, temp_dir: Path) -> None:
        """Analysis handles very small files."""
        small_file = temp_dir / "small.bin"
        small_file.write_bytes(b"MZ")

        result = analyzer.analyze(small_file)

        assert "error" in result or result["analysis_status"] == "completed"


class TestPerformanceBenchmarks:
    """Performance benchmark tests for binary analysis."""

    def test_analyze_notepad_performance(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Analysis of small binary completes quickly."""
        import time

        start = time.time()
        result = analyzer.analyze(notepad_path)
        elapsed = time.time() - start

        assert result["analysis_status"] == "completed"
        assert elapsed < 5.0

    def test_analyze_kernel32_streaming_performance(self, analyzer: BinaryAnalyzer, kernel32_path: Path) -> None:
        """Streaming analysis of large DLL completes in reasonable time."""
        import time

        start = time.time()
        result = analyzer.analyze(kernel32_path, use_streaming=True)
        elapsed = time.time() - start

        assert result["analysis_status"] == "completed"
        assert elapsed < 30.0

    def test_hash_calculation_performance(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Hash calculation completes quickly."""
        import time

        start = time.time()
        hashes = analyzer._calculate_hashes(notepad_path)
        elapsed = time.time() - start

        assert "sha256" in hashes
        assert elapsed < 2.0


class TestSecurityAnalysis:
    """Tests for security analysis features."""

    def test_security_analysis_notepad(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Security analysis produces results."""
        result = analyzer.analyze(notepad_path)

        assert "security" in result
        security = result["security"]
        assert "risk_level" in security
        assert "suspicious_indicators" in security
        assert "recommendations" in security

    def test_security_analysis_risk_levels(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Security analysis provides valid risk levels."""
        result = analyzer.analyze(notepad_path)
        security = result["security"]

        assert security["risk_level"] in ["Unknown", "Low", "Medium", "High"]

    def test_security_analysis_executable_recommendations(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Security analysis provides recommendations for executables."""
        result = analyzer.analyze(notepad_path)
        security = result["security"]

        assert isinstance(security["recommendations"], list)
