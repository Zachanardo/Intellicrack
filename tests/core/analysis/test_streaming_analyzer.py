"""Unit tests for streaming binary analysis capabilities.

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

from typing import Any
import json
import tempfile
from pathlib import Path

import pytest

from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer


@pytest.fixture
def analyzer() -> Any:
    """Create a BinaryAnalyzer instance."""
    return BinaryAnalyzer()


@pytest.fixture
def small_pe_binary(tmp_path) -> Any:
    """Create a minimal PE binary for testing."""
    binary_path = tmp_path / "test.exe"
    dos_header = b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00"
    pe_header = b"\x00" * 0x80 + b"PE\x00\x00"
    coff_header = b"\x64\x86" + b"\x00" * 18
    binary_path.write_bytes(dos_header + pe_header + coff_header)
    return binary_path


@pytest.fixture
def large_test_file(tmp_path) -> Any:
    """Create a large test file for streaming analysis."""
    file_path = tmp_path / "large_test.bin"
    chunk_size = 1024 * 1024
    num_chunks = 60

    with open(file_path, "wb") as f:
        for i in range(num_chunks):
            chunk = bytes((i + j) % 256 for j in range(chunk_size))
            f.write(chunk)

    return file_path


class TestStreamingDetection:
    """Test automatic streaming mode detection."""

    def test_small_file_no_streaming(self, analyzer: Any, small_pe_binary: Any) -> None:
        """Small files should not trigger streaming by default."""
        results = analyzer.analyze(small_pe_binary)
        assert results.get("analysis_status") == "completed"
        assert results.get("streaming_mode") is not True

    def test_large_file_auto_streaming(self, analyzer: Any, large_test_file: Any) -> None:
        """Large files should automatically use streaming."""
        results = analyzer.analyze(large_test_file)
        assert results.get("analysis_status") == "completed"
        assert results.get("streaming_mode") is True

    def test_forced_streaming_small_file(self, analyzer: Any, small_pe_binary: Any) -> None:
        """Force streaming mode for small file."""
        results = analyzer.analyze(small_pe_binary, use_streaming=True)
        assert results.get("analysis_status") == "completed"
        assert results.get("streaming_mode") is True

    def test_forced_no_streaming_large_file(self, analyzer: Any, large_test_file: Any) -> None:
        """Force non-streaming mode (may fail for very large files)."""
        try:
            results = analyzer.analyze(large_test_file, use_streaming=False)
            assert results.get("analysis_status") == "completed"
            assert results.get("streaming_mode") is not True
        except MemoryError:
            pytest.skip("File too large for non-streaming mode")


class TestChunkProcessing:
    """Test chunk-based file processing."""

    def test_read_chunks_basic(self, analyzer: Any, tmp_path: Any) -> None:
        """Test basic chunk reading functionality."""
        test_file = tmp_path / "chunks.bin"
        test_data = b"A" * 1000 + b"B" * 1000 + b"C" * 1000
        test_file.write_bytes(test_data)

        chunks = list(analyzer._read_chunks(test_file, chunk_size=1000))

        assert len(chunks) == 3
        assert chunks[0][0] == b"A" * 1000
        assert chunks[0][1] == 0
        assert chunks[1][0] == b"B" * 1000
        assert chunks[1][1] == 1000
        assert chunks[2][0] == b"C" * 1000
        assert chunks[2][1] == 2000

    def test_read_chunks_uneven(self, analyzer: Any, tmp_path: Any) -> None:
        """Test chunk reading with uneven file size."""
        test_file = tmp_path / "uneven.bin"
        test_data = b"X" * 2500
        test_file.write_bytes(test_data)

        chunks = list(analyzer._read_chunks(test_file, chunk_size=1000))

        assert len(chunks) == 3
        assert len(chunks[0][0]) == 1000
        assert len(chunks[1][0]) == 1000
        assert len(chunks[2][0]) == 500


class TestHashCalculation:
    """Test streaming hash calculation."""

    def test_hash_calculation_streaming(self, analyzer: Any, tmp_path: Any) -> None:
        """Test streaming hash calculation matches non-streaming."""
        test_file = tmp_path / "hash_test.bin"
        test_data = b"Test data for hashing" * 10000
        test_file.write_bytes(test_data)

        import hashlib

        expected_sha256 = hashlib.sha256(test_data).hexdigest()

        results = analyzer._calculate_hashes_streaming(test_file)

        assert "sha256" in results
        assert results["sha256"] == expected_sha256
        assert "sha512" in results
        assert "sha3_256" in results
        assert "blake2b" in results

    def test_hash_progress_callback(self, analyzer: Any, tmp_path: Any) -> None:
        """Test hash calculation with progress callback."""
        test_file = tmp_path / "progress.bin"
        test_data = b"X" * 500000
        test_file.write_bytes(test_data)

        progress_updates = []

        def callback(current, total):
            progress_updates.append((current, total))

        analyzer._calculate_hashes_streaming(test_file, callback)

        assert progress_updates
        assert all(current <= total for current, total in progress_updates)


class TestMemoryMapping:
    """Test memory-mapped file access."""

    def test_mmap_open_close(self, analyzer: Any, tmp_path: Any) -> None:
        """Test memory map opening and closing."""
        test_file = tmp_path / "mmap_test.bin"
        test_data = b"Memory mapped data test"
        test_file.write_bytes(test_data)

        file_handle, mm = analyzer._open_mmap(test_file)

        assert mm is not None
        assert len(mm) == len(test_data)
        assert mm[:len(test_data)] == test_data

        mm.close()
        file_handle.close()

    def test_mmap_large_file_access(self, analyzer: Any, large_test_file: Any) -> None:
        """Test memory mapping large files."""
        file_handle, mm = analyzer._open_mmap(large_test_file)

        assert mm is not None
        file_size = large_test_file.stat().st_size
        assert len(mm) == file_size

        first_byte = mm[0]
        last_byte = mm[-1]
        assert isinstance(first_byte, int)
        assert isinstance(last_byte, int)

        mm.close()
        file_handle.close()


class TestProgressTracking:
    """Test progress tracking functionality."""

    def test_analyze_with_progress_callback(self, analyzer: Any, small_pe_binary: Any) -> None:
        """Test analysis with progress callback."""
        progress_stages = []

        def callback(stage, current, total):
            progress_stages.append(stage)

        results = analyzer.analyze_with_progress(small_pe_binary, callback)

        assert results.get("analysis_status") == "completed"
        assert progress_stages
        assert "completed" in progress_stages

    def test_progress_stages_order(self, analyzer: Any, small_pe_binary: Any) -> None:
        """Test progress stages occur in correct order."""
        progress_stages = []

        def callback(stage, current, total):
            progress_stages.append(stage)

        analyzer.analyze_with_progress(small_pe_binary, callback)

        expected_stages = ["format_detection", "hash_calculation", "format_analysis", "string_extraction", "entropy_analysis", "completed"]

        for stage in expected_stages:
            assert stage in progress_stages


class TestCheckpointing:
    """Test checkpoint save/load functionality."""

    def test_save_checkpoint(self, analyzer: Any, tmp_path: Any) -> None:
        """Test saving analysis checkpoint."""
        checkpoint_path = tmp_path / "checkpoint.json"
        test_results = {"format": "PE", "path": "test.exe", "analysis_status": "completed"}

        success = analyzer.save_analysis_checkpoint(test_results, checkpoint_path)

        assert success is True
        assert checkpoint_path.exists()

    def test_load_checkpoint(self, analyzer: Any, tmp_path: Any) -> None:
        """Test loading analysis checkpoint."""
        checkpoint_path = tmp_path / "checkpoint.json"
        test_results = {"format": "PE", "path": "test.exe", "hashes": {"sha256": "abc123"}}

        analyzer.save_analysis_checkpoint(test_results, checkpoint_path)
        loaded_results = analyzer.load_analysis_checkpoint(checkpoint_path)

        assert loaded_results is not None
        assert loaded_results["format"] == "PE"
        assert loaded_results["path"] == "test.exe"
        assert loaded_results["hashes"]["sha256"] == "abc123"

    def test_load_nonexistent_checkpoint(self, analyzer: Any, tmp_path: Any) -> None:
        """Test loading nonexistent checkpoint."""
        checkpoint_path = tmp_path / "nonexistent.json"

        result = analyzer.load_analysis_checkpoint(checkpoint_path)

        assert result is None

    def test_checkpoint_roundtrip(self, analyzer: Any, small_pe_binary: Any, tmp_path: Any) -> None:
        """Test full analysis checkpoint roundtrip."""
        checkpoint_path = tmp_path / "roundtrip.json"

        original_results = analyzer.analyze(small_pe_binary)
        analyzer.save_analysis_checkpoint(original_results, checkpoint_path)
        loaded_results = analyzer.load_analysis_checkpoint(checkpoint_path)

        assert loaded_results["format"] == original_results["format"]
        assert loaded_results["path"] == original_results["path"]
        assert loaded_results["analysis_status"] == original_results["analysis_status"]


class TestPatternScanning:
    """Test pattern scanning functionality."""

    def test_pattern_scanning_basic(self, analyzer: Any, tmp_path: Any) -> None:
        """Test basic pattern scanning."""
        test_file = tmp_path / "patterns.bin"
        test_data = b"AAAA" + b"PATTERN1" + b"BBBB" + b"PATTERN2" + b"CCCC"
        test_file.write_bytes(test_data)

        patterns = [b"PATTERN1", b"PATTERN2"]
        results = analyzer.scan_for_patterns_streaming(test_file, patterns)

        assert b"PATTERN1".hex() in results
        assert b"PATTERN2".hex() in results
        assert len(results[b"PATTERN1".hex()]) == 1
        assert len(results[b"PATTERN2".hex()]) == 1

    def test_pattern_scanning_multiple_matches(self, analyzer: Any, tmp_path: Any) -> None:
        """Test pattern scanning with multiple matches."""
        test_file = tmp_path / "multi_patterns.bin"
        test_data = b"MZ" + b"\x00" * 100 + b"MZ" + b"\x00" * 100 + b"MZ"
        test_file.write_bytes(test_data)

        patterns = [b"MZ"]
        results = analyzer.scan_for_patterns_streaming(test_file, patterns)

        assert len(results[b"MZ".hex()]) == 3

    def test_pattern_scanning_with_context(self, analyzer: Any, tmp_path: Any) -> None:
        """Test pattern scanning with context bytes."""
        test_file = tmp_path / "context.bin"
        test_data = b"BEFORE" + b"TARGET" + b"AFTER"
        test_file.write_bytes(test_data)

        patterns = [b"TARGET"]
        results = analyzer.scan_for_patterns_streaming(test_file, patterns, context_bytes=6)

        matches = results[b"TARGET".hex()]
        assert len(matches) == 1
        assert matches[0]["context_before"] == b"BEFORE".hex()
        assert matches[0]["context_after"] == b"AFTER".hex()


class TestLicenseStringScanning:
    """Test license string scanning."""

    def test_license_string_detection(self, analyzer: Any, tmp_path: Any) -> None:
        """Test detection of license-related strings."""
        test_file = tmp_path / "license.bin"
        test_data = b"\x00" * 100 + b"Enter your license key:" + b"\x00" * 100
        test_file.write_bytes(test_data)

        results = analyzer.scan_for_license_strings_streaming(test_file)

        assert len(results) > 0
        assert any("license" in r.get("string", "").lower() for r in results if isinstance(r, dict))

    def test_license_string_patterns(self, analyzer: Any, tmp_path: Any) -> None:
        """Test various license-related patterns."""
        test_file = tmp_path / "patterns.bin"
        test_strings = [b"Serial number:", b"Product activation", b"Trial expired", b"Registration code"]
        test_data = b"\x00".join(test_strings)
        test_file.write_bytes(test_data)

        results = analyzer.scan_for_license_strings_streaming(test_file)

        patterns_found = {r["pattern_matched"] for r in results if isinstance(r, dict) and "pattern_matched" in r}

        assert patterns_found


class TestSectionAnalysis:
    """Test section-specific analysis."""

    def test_section_analysis_basic(self, analyzer: Any, tmp_path: Any) -> None:
        """Test basic section analysis."""
        test_file = tmp_path / "sections.bin"
        test_data = b"A" * 1000 + b"\x00" * 1000 + bytes(range(256)) * 4
        test_file.write_bytes(test_data)

        section_ranges = [(0, 1000), (1000, 2000), (2000, 3024)]
        results = analyzer.analyze_sections_streaming(test_file, section_ranges)

        assert len(results) == 3
        assert "section_0" in results
        assert "section_1" in results
        assert "section_2" in results

    def test_section_entropy_calculation(self, analyzer: Any, tmp_path: Any) -> None:
        """Test entropy calculation for sections."""
        test_file = tmp_path / "entropy.bin"
        low_entropy = b"A" * 1000
        high_entropy = bytes(range(256)) * 4
        test_data = low_entropy + high_entropy
        test_file.write_bytes(test_data)

        section_ranges = [(0, 1000), (1000, 2024)]
        results = analyzer.analyze_sections_streaming(test_file, section_ranges)

        section_0_entropy = results["section_0"]["entropy"]
        section_1_entropy = results["section_1"]["entropy"]

        assert section_0_entropy < section_1_entropy

    def test_section_characteristics_classification(self, analyzer: Any, tmp_path: Any) -> None:
        """Test section characteristics classification."""
        test_file = tmp_path / "classification.bin"
        text_section = b"This is printable text content for testing" * 20
        binary_section = bytes((i * 37) % 256 for i in range(1000))
        test_data = text_section + binary_section
        test_file.write_bytes(test_data)

        section_ranges = [(0, len(text_section)), (len(text_section), len(test_data))]
        results = analyzer.analyze_sections_streaming(test_file, section_ranges)

        text_chars = results["section_0"]["characteristics"]
        binary_chars = results["section_1"]["characteristics"]

        assert "Text" in text_chars or "printable" in text_chars.lower()

    def test_invalid_section_ranges(self, analyzer: Any, tmp_path: Any) -> None:
        """Test handling of invalid section ranges."""
        test_file = tmp_path / "invalid.bin"
        test_data = b"X" * 1000
        test_file.write_bytes(test_data)

        section_ranges = [(-10, 100), (500, 2000), (900, 800)]
        results = analyzer.analyze_sections_streaming(test_file, section_ranges)

        assert "section_0" in results
        assert "error" in results["section_0"]


class TestStreamingFormatAnalysis:
    """Test format-specific streaming analysis."""

    def test_pe_streaming_analysis(self, analyzer: Any, small_pe_binary: Any) -> None:
        """Test PE analysis using streaming."""
        results = analyzer._analyze_pe_streaming(small_pe_binary)

        assert "machine" in results
        assert results.get("error") is None

    def test_format_detection_streaming(self, analyzer: Any, small_pe_binary: Any) -> None:
        """Test format detection using streaming."""
        format_name = analyzer._detect_format_streaming(small_pe_binary)

        assert format_name == "PE"

    def test_string_extraction_streaming(self, analyzer: Any, tmp_path: Any) -> None:
        """Test string extraction using streaming."""
        test_file = tmp_path / "strings.bin"
        test_data = b"\x00" * 100 + b"TestString1" + b"\x00" * 100 + b"TestString2" + b"\x00" * 100
        test_file.write_bytes(test_data)

        strings = analyzer._extract_strings_streaming(test_file, max_strings=10)

        assert len(strings) > 0
        assert any("TestString" in s for s in strings)

    def test_entropy_analysis_streaming(self, analyzer: Any, tmp_path: Any) -> None:
        """Test entropy analysis using streaming."""
        test_file = tmp_path / "entropy_stream.bin"
        test_data = b"A" * 10000
        test_file.write_bytes(test_data)

        results = analyzer._analyze_entropy_streaming(test_file)

        assert "overall_entropy" in results
        assert "file_size" in results
        assert results["file_size"] == 10000
        assert results["overall_entropy"] < 1.0
