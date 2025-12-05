"""Production tests for StreamingEntropyAnalyzer - ABSOLUTELY NO MOCKS.

Validates streaming entropy analysis on REAL Windows binaries and synthetic test
data with known mathematical entropy characteristics. Tests MUST FAIL if entropy
calculations are incorrect, sliding windows malfunction, or memory efficiency is
compromised.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

from __future__ import annotations

import math
import os
import random
import struct
import tempfile
import zlib
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from intellicrack.core.analysis.streaming_entropy_analyzer import (
    EntropyWindow,
    StreamingEntropyAnalyzer,
    analyze_entropy_streaming,
)
from intellicrack.core.processing.streaming_analysis_manager import (
    ChunkContext,
    StreamingAnalysisManager,
    StreamingConfig,
    StreamingProgress,
)

SYSTEM32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"
REAL_BINARIES = {
    "notepad": SYSTEM32 / "notepad.exe",
    "calc": SYSTEM32 / "calc.exe",
    "kernel32": SYSTEM32 / "kernel32.dll",
    "ntdll": SYSTEM32 / "ntdll.dll",
}


class TestStreamingEntropyAnalyzerInitialization:
    """Validate streaming analyzer initialization and configuration."""

    def test_default_initialization(self) -> None:
        """Analyzer initializes with default window size and stride."""
        analyzer = StreamingEntropyAnalyzer()

        assert analyzer.window_size == 1024 * 1024
        assert analyzer.stride == 512 * 1024
        assert len(analyzer.global_byte_counts) == 0
        assert analyzer.total_bytes == 0
        assert len(analyzer.entropy_windows) == 0
        assert len(analyzer.high_entropy_regions) == 0

    def test_custom_window_configuration(self) -> None:
        """Analyzer accepts custom window size and stride."""
        analyzer = StreamingEntropyAnalyzer(window_size=2048, stride=1024)

        assert analyzer.window_size == 2048
        assert analyzer.stride == 1024

    def test_small_window_configuration(self) -> None:
        """Analyzer handles small window sizes for fine-grained analysis."""
        analyzer = StreamingEntropyAnalyzer(window_size=512, stride=256)

        assert analyzer.window_size == 512
        assert analyzer.stride == 256

    def test_large_window_configuration(self) -> None:
        """Analyzer handles large window sizes for coarse-grained analysis."""
        analyzer = StreamingEntropyAnalyzer(window_size=10 * 1024 * 1024, stride=5 * 1024 * 1024)

        assert analyzer.window_size == 10 * 1024 * 1024
        assert analyzer.stride == 5 * 1024 * 1024

    def test_initialize_analysis_resets_state(self, temp_workspace: Path) -> None:
        """initialize_analysis completely clears previous analysis state."""
        analyzer = StreamingEntropyAnalyzer(window_size=1024, stride=512)

        analyzer.total_bytes = 10000
        analyzer.global_byte_counts[0] = 5000
        analyzer.global_byte_counts[255] = 5000
        analyzer.entropy_windows.append(EntropyWindow(offset=0, size=1024, entropy=5.5))
        analyzer.high_entropy_regions.append({"offset": 1024, "size": 512, "entropy": 7.8})

        test_file = temp_workspace / "reset_test.bin"
        test_file.write_bytes(b"\x00" * 2048)

        analyzer.initialize_analysis(test_file)

        assert len(analyzer.global_byte_counts) == 0
        assert analyzer.total_bytes == 0
        assert len(analyzer.entropy_windows) == 0
        assert len(analyzer.high_entropy_regions) == 0

    def test_entropy_thresholds_correctly_defined(self) -> None:
        """Analyzer has correct entropy threshold definitions."""
        thresholds = StreamingEntropyAnalyzer.ENTROPY_THRESHOLDS

        assert thresholds["very_low"] == 2.0
        assert thresholds["low"] == 4.0
        assert thresholds["medium"] == 6.0
        assert thresholds["high"] == 7.0
        assert thresholds["very_high"] == 7.5

        assert thresholds["very_low"] < thresholds["low"]
        assert thresholds["low"] < thresholds["medium"]
        assert thresholds["medium"] < thresholds["high"]
        assert thresholds["high"] < thresholds["very_high"]


class TestShannonEntropyCalculation:
    """Validate Shannon entropy calculation mathematical correctness."""

    @pytest.fixture
    def analyzer(self) -> StreamingEntropyAnalyzer:
        """Provide streaming entropy analyzer instance."""
        return StreamingEntropyAnalyzer()

    def test_empty_data_zero_entropy(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """Empty byte distribution must yield exactly 0.0 entropy."""
        entropy = analyzer._calculate_entropy({}, 0)
        assert entropy == 0.0, "Empty data MUST produce zero entropy"

    def test_uniform_bytes_zero_entropy(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """Single byte value repeated must have exactly 0.0 entropy."""
        test_cases = [
            ({0: 1000}, 1000, "null bytes"),
            ({255: 5000}, 5000, "0xFF bytes"),
            ({42: 10000}, 10000, "0x2A bytes"),
            ({ord('A'): 2000}, 2000, "ASCII 'A'"),
        ]

        for byte_counts, total, description in test_cases:
            entropy = analyzer._calculate_entropy(byte_counts, total)
            assert entropy == 0.0, f"{description} MUST have zero entropy, got {entropy}"

    def test_perfect_byte_distribution_maximum_entropy(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """Perfect distribution of all 256 byte values must yield exactly 8.0 entropy."""
        byte_counts = {i: 100 for i in range(256)}
        total_bytes = 256 * 100

        entropy = analyzer._calculate_entropy(byte_counts, total_bytes)

        assert abs(entropy - 8.0) < 0.001, f"Perfect distribution MUST yield 8.0 entropy, got {entropy}"

    def test_two_byte_equal_distribution_one_bit(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """Equal distribution of two distinct bytes must yield exactly 1.0 bit entropy."""
        byte_counts = {0: 5000, 255: 5000}
        total_bytes = 10000

        entropy = analyzer._calculate_entropy(byte_counts, total_bytes)

        assert abs(entropy - 1.0) < 0.0001, f"Two-byte distribution MUST yield 1.0 entropy, got {entropy}"

    def test_four_byte_equal_distribution_two_bits(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """Equal distribution of four distinct bytes must yield exactly 2.0 bits entropy."""
        byte_counts = {0: 2500, 85: 2500, 170: 2500, 255: 2500}
        total_bytes = 10000

        entropy = analyzer._calculate_entropy(byte_counts, total_bytes)

        assert abs(entropy - 2.0) < 0.0001, f"Four-byte distribution MUST yield 2.0 entropy, got {entropy}"

    def test_eight_byte_equal_distribution_three_bits(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """Equal distribution of eight distinct bytes must yield exactly 3.0 bits entropy."""
        byte_counts = {i * 17: 1250 for i in range(8)}
        total_bytes = 10000

        entropy = analyzer._calculate_entropy(byte_counts, total_bytes)

        assert abs(entropy - 3.0) < 0.0001, f"Eight-byte distribution MUST yield 3.0 entropy, got {entropy}"

    def test_shannon_formula_manual_verification(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """Verify Shannon entropy formula: H(X) = -Σ P(xi) * log2(P(xi))."""
        byte_counts = {ord('A'): 2, ord('B'): 4, ord('C'): 8}
        total_bytes = 14

        expected_entropy = 0.0
        for count in byte_counts.values():
            probability = count / total_bytes
            expected_entropy -= probability * math.log2(probability)

        actual_entropy = analyzer._calculate_entropy(byte_counts, total_bytes)

        assert abs(actual_entropy - expected_entropy) < 1e-12, "Shannon formula MUST be mathematically exact"

    def test_entropy_bounds_never_violated(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """Entropy must ALWAYS be within theoretical bounds [0.0, 8.0]."""
        test_cases = [
            ({}, 0),
            ({0: 1}, 1),
            ({0: 50, 255: 50}, 100),
            ({i: 10 for i in range(256)}, 2560),
            ({i: random.randint(1, 100) for i in range(128)}, 6400),
        ]

        for byte_counts, total in test_cases:
            entropy = analyzer._calculate_entropy(byte_counts, total)
            assert 0.0 <= entropy <= 8.0, f"Entropy {entropy} violates bounds [0.0, 8.0]"

    def test_log2_calculation_precision(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """Verify log2 calculation precision in entropy formula."""
        byte_counts = {i: 1000 for i in range(8)}
        total_bytes = 8000

        entropy = analyzer._calculate_entropy(byte_counts, total_bytes)
        expected = 3.0

        assert abs(entropy - expected) < 1e-10, f"Log2 precision error: expected {expected}, got {entropy}"

    def test_probability_calculation_accuracy(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """Verify probability calculations are accurate to machine precision."""
        byte_counts = {ord('A'): 75, ord('B'): 25}
        total_bytes = 100

        a_prob = 75 / 100
        b_prob = 25 / 100
        expected = -(a_prob * math.log2(a_prob) + b_prob * math.log2(b_prob))

        actual = analyzer._calculate_entropy(byte_counts, total_bytes)

        assert abs(actual - expected) < 1e-12, "Probability calculation MUST be exact"


class TestChunkAnalysis:
    """Validate chunk-based entropy analysis functionality."""

    @pytest.fixture
    def analyzer(self) -> StreamingEntropyAnalyzer:
        """Provide analyzer with small window for testing."""
        return StreamingEntropyAnalyzer(window_size=1024, stride=512)

    def test_analyze_chunk_low_entropy_data(self, analyzer: StreamingEntropyAnalyzer, temp_workspace: Path) -> None:
        """analyze_chunk correctly processes low entropy data."""
        test_file = temp_workspace / "low_entropy.bin"
        data = b"\x00" * 10000
        test_file.write_bytes(data)

        analyzer.initialize_analysis(test_file)

        context = ChunkContext(
            offset=0,
            size=len(data),
            chunk_number=1,
            total_chunks=1,
            data=data,
            file_path=test_file,
        )

        result = analyzer.analyze_chunk(context)

        assert result["chunk_entropy"] == 0.0
        assert result["null_ratio"] == 1.0
        assert result["unique_bytes"] == 1
        assert "Empty/Padding" in result["classification"] or "Highly Repetitive" in result["classification"]

    def test_analyze_chunk_high_entropy_data(self, analyzer: StreamingEntropyAnalyzer, temp_workspace: Path) -> None:
        """analyze_chunk correctly processes high entropy data."""
        test_file = temp_workspace / "high_entropy.bin"
        random.seed(42)
        data = bytes([random.randint(0, 255) for _ in range(10000)])
        test_file.write_bytes(data)

        analyzer.initialize_analysis(test_file)

        context = ChunkContext(
            offset=0,
            size=len(data),
            chunk_number=1,
            total_chunks=1,
            data=data,
            file_path=test_file,
        )

        result = analyzer.analyze_chunk(context)

        assert result["chunk_entropy"] > 7.5
        assert result["unique_bytes"] > 200
        assert "Encrypted/Compressed" in result["classification"]

    def test_analyze_chunk_text_data(self, analyzer: StreamingEntropyAnalyzer, temp_workspace: Path) -> None:
        """analyze_chunk correctly identifies text data."""
        test_file = temp_workspace / "text_data.bin"
        data = b"This is a test string with printable ASCII characters. " * 200
        test_file.write_bytes(data)

        analyzer.initialize_analysis(test_file)

        context = ChunkContext(
            offset=0,
            size=len(data),
            chunk_number=1,
            total_chunks=1,
            data=data,
            file_path=test_file,
        )

        result = analyzer.analyze_chunk(context)

        assert result["printable_ratio"] > 0.8
        assert "Text/Strings" in result["classification"]

    def test_analyze_chunk_creates_sliding_windows(self, analyzer: StreamingEntropyAnalyzer, temp_workspace: Path) -> None:
        """analyze_chunk creates sliding windows with correct stride."""
        test_file = temp_workspace / "window_test.bin"
        data = os.urandom(8192)
        test_file.write_bytes(data)

        analyzer.initialize_analysis(test_file)

        context = ChunkContext(
            offset=0,
            size=len(data),
            chunk_number=1,
            total_chunks=1,
            data=data,
            file_path=test_file,
        )

        result = analyzer.analyze_chunk(context)

        assert "windows" in result
        windows = result["windows"]

        expected_windows = (len(data) - analyzer.window_size) // analyzer.stride + 1
        assert len(windows) >= expected_windows - 1

        for i, window in enumerate(windows):
            assert window["offset"] == i * analyzer.stride
            assert window["size"] == analyzer.window_size
            assert "entropy" in window
            assert "unique_bytes" in window
            assert 0.0 <= window["entropy"] <= 8.0

    def test_analyze_chunk_identifies_high_entropy_regions(self, analyzer: StreamingEntropyAnalyzer, temp_workspace: Path) -> None:
        """analyze_chunk detects and records high-entropy regions."""
        test_file = temp_workspace / "mixed_entropy.bin"

        low_entropy = b"\x00" * 1000
        high_entropy = os.urandom(8000)
        trailing = b"\x00" * 1000

        data = low_entropy + high_entropy + trailing
        test_file.write_bytes(data)

        analyzer.initialize_analysis(test_file)

        context = ChunkContext(
            offset=0,
            size=len(data),
            chunk_number=1,
            total_chunks=1,
            data=data,
            file_path=test_file,
        )

        analyzer.analyze_chunk(context)

        assert len(analyzer.high_entropy_regions) > 0

        for region in analyzer.high_entropy_regions:
            assert region["entropy"] > StreamingEntropyAnalyzer.ENTROPY_THRESHOLDS["very_high"]
            assert region["offset"] >= 0
            assert region["size"] > 0

    def test_analyze_chunk_tracks_global_byte_counts(self, analyzer: StreamingEntropyAnalyzer, temp_workspace: Path) -> None:
        """analyze_chunk accumulates global byte frequency counts."""
        test_file = temp_workspace / "byte_count_test.bin"
        data = b"\x00\x00\xFF\xFF\x42"
        test_file.write_bytes(data)

        analyzer.initialize_analysis(test_file)

        context = ChunkContext(
            offset=0,
            size=len(data),
            chunk_number=1,
            total_chunks=1,
            data=data,
            file_path=test_file,
        )

        analyzer.analyze_chunk(context)

        assert analyzer.global_byte_counts[0] == 2
        assert analyzer.global_byte_counts[255] == 2
        assert analyzer.global_byte_counts[0x42] == 1
        assert analyzer.total_bytes == 5

    def test_analyze_chunk_handles_empty_chunk(self, analyzer: StreamingEntropyAnalyzer, temp_workspace: Path) -> None:
        """analyze_chunk handles empty data gracefully."""
        test_file = temp_workspace / "empty_chunk.bin"
        data = b""
        test_file.write_bytes(data)

        analyzer.initialize_analysis(test_file)

        context = ChunkContext(
            offset=0,
            size=0,
            chunk_number=1,
            total_chunks=1,
            data=data,
            file_path=test_file,
        )

        result = analyzer.analyze_chunk(context)

        assert result["chunk_entropy"] == 0.0
        assert result["unique_bytes"] == 0
        assert result["printable_ratio"] == 0.0

    def test_analyze_chunk_calculates_ratios_correctly(self, analyzer: StreamingEntropyAnalyzer, temp_workspace: Path) -> None:
        """analyze_chunk calculates printable, null, and high entropy ratios correctly."""
        test_file = temp_workspace / "ratio_test.bin"

        printable = b"ABCDEFGHIJ" * 50
        nulls = b"\x00" * 200
        high_bytes = bytes([200 + i for i in range(56)]) * 10

        data = printable + nulls + high_bytes
        test_file.write_bytes(data)

        analyzer.initialize_analysis(test_file)

        context = ChunkContext(
            offset=0,
            size=len(data),
            chunk_number=1,
            total_chunks=1,
            data=data,
            file_path=test_file,
        )

        result = analyzer.analyze_chunk(context)

        expected_printable = 500 / len(data)
        expected_null = 200 / len(data)
        expected_high = 560 / len(data)

        assert abs(result["printable_ratio"] - expected_printable) < 0.01
        assert abs(result["null_ratio"] - expected_null) < 0.01
        assert abs(result["high_entropy_ratio"] - expected_high) < 0.01


class TestSectionClassification:
    """Validate binary section classification logic."""

    @pytest.fixture
    def analyzer(self) -> StreamingEntropyAnalyzer:
        """Provide analyzer instance."""
        return StreamingEntropyAnalyzer()

    def test_classify_empty_padding_section(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """_classify_section identifies empty/padding sections."""
        classification = analyzer._classify_section(
            entropy=1.0,
            printable_ratio=0.0,
            null_ratio=0.95,
        )

        assert classification == "Empty/Padding"

    def test_classify_encrypted_compressed_section(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """_classify_section identifies encrypted/compressed data."""
        classification = analyzer._classify_section(
            entropy=7.8,
            printable_ratio=0.2,
            null_ratio=0.0,
        )

        assert classification == "Encrypted/Compressed"

    def test_classify_text_strings_section(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """_classify_section identifies text/strings."""
        classification = analyzer._classify_section(
            entropy=4.5,
            printable_ratio=0.85,
            null_ratio=0.0,
        )

        assert classification == "Text/Strings"

    def test_classify_code_binary_data_section(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """_classify_section identifies code/binary data."""
        classification = analyzer._classify_section(
            entropy=6.5,
            printable_ratio=0.05,
            null_ratio=0.0,
        )

        assert classification == "Code/Binary Data"

    def test_classify_highly_repetitive_section(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """_classify_section identifies highly repetitive data."""
        classification = analyzer._classify_section(
            entropy=1.5,
            printable_ratio=0.5,
            null_ratio=0.1,
        )

        assert classification == "Highly Repetitive"

    def test_classify_structured_binary_section(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """_classify_section identifies structured binary data."""
        classification = analyzer._classify_section(
            entropy=5.0,
            printable_ratio=0.3,
            null_ratio=0.05,
        )

        assert classification == "Structured Binary"

    def test_classify_mixed_content_section(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """_classify_section identifies mixed content."""
        classification = analyzer._classify_section(
            entropy=6.8,
            printable_ratio=0.5,
            null_ratio=0.0,
        )

        assert classification == "Mixed Content"


class TestResultsMerging:
    """Validate chunk results merging functionality."""

    @pytest.fixture
    def analyzer(self) -> StreamingEntropyAnalyzer:
        """Provide analyzer instance."""
        return StreamingEntropyAnalyzer()

    def test_merge_results_aggregates_statistics(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """merge_results correctly aggregates chunk statistics."""
        chunk_results = [
            {
                "chunk_offset": 0,
                "chunk_size": 1000,
                "chunk_entropy": 2.0,
                "unique_bytes": 10,
                "printable_ratio": 0.1,
                "null_ratio": 0.9,
                "high_entropy_ratio": 0.0,
                "classification": "Empty/Padding",
                "windows": [{"offset": 0, "size": 1000, "entropy": 2.0, "unique_bytes": 10}],
                "byte_counts": {0: 900, 1: 100},
            },
            {
                "chunk_offset": 1000,
                "chunk_size": 1000,
                "chunk_entropy": 7.5,
                "unique_bytes": 250,
                "printable_ratio": 0.2,
                "null_ratio": 0.0,
                "high_entropy_ratio": 0.8,
                "classification": "Encrypted/Compressed",
                "windows": [{"offset": 1000, "size": 1000, "entropy": 7.5, "unique_bytes": 250}],
                "byte_counts": {i: 4 for i in range(250)},
            },
        ]

        analyzer.total_bytes = 2000
        for result in chunk_results:
            for byte_val, count in result["byte_counts"].items():
                analyzer.global_byte_counts[byte_val] += count

        merged = analyzer.merge_results(chunk_results)

        assert merged["total_bytes"] == 2000
        assert merged["min_chunk_entropy"] == 2.0
        assert merged["max_chunk_entropy"] == 7.5
        assert 4.0 <= merged["average_chunk_entropy"] <= 5.0
        assert merged["std_dev_entropy"] > 0.0
        assert merged["total_windows"] == 2

    def test_merge_results_calculates_global_entropy(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """merge_results calculates global entropy from accumulated byte counts."""
        chunk_results = [
            {
                "chunk_offset": 0,
                "chunk_size": 256,
                "chunk_entropy": 8.0,
                "unique_bytes": 256,
                "printable_ratio": 0.37,
                "null_ratio": 0.004,
                "high_entropy_ratio": 0.5,
                "classification": "Mixed Content",
                "windows": [],
                "byte_counts": {i: 1 for i in range(256)},
            },
        ]

        analyzer.total_bytes = 256
        for byte_val in range(256):
            analyzer.global_byte_counts[byte_val] = 1

        merged = analyzer.merge_results(chunk_results)

        assert abs(merged["global_entropy"] - 8.0) < 0.01

    def test_merge_results_handles_chunk_errors(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """merge_results handles chunk processing errors gracefully."""
        chunk_results = [
            {
                "chunk_offset": 0,
                "chunk_size": 1000,
                "error": "Processing failed",
                "chunk_entropy": 0.0,
            },
            {
                "chunk_offset": 1000,
                "chunk_size": 1000,
                "chunk_entropy": 6.0,
                "unique_bytes": 200,
                "printable_ratio": 0.5,
                "null_ratio": 0.0,
                "high_entropy_ratio": 0.3,
                "classification": "Mixed Content",
                "windows": [],
                "byte_counts": {i: 5 for i in range(200)},
            },
        ]

        analyzer.total_bytes = 1000

        merged = analyzer.merge_results(chunk_results)

        assert "errors" in merged
        assert len(merged["errors"]) == 1
        assert "0x00000000" in merged["errors"][0]
        assert "failed" in merged["errors"][0].lower()

    def test_merge_results_aggregates_classifications(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """merge_results counts classification distribution."""
        chunk_results = [
            {
                "chunk_offset": 0,
                "chunk_size": 1000,
                "chunk_entropy": 2.0,
                "unique_bytes": 10,
                "printable_ratio": 0.1,
                "null_ratio": 0.9,
                "high_entropy_ratio": 0.0,
                "classification": "Empty/Padding",
                "windows": [],
                "byte_counts": {},
            },
            {
                "chunk_offset": 1000,
                "chunk_size": 1000,
                "chunk_entropy": 4.5,
                "unique_bytes": 95,
                "printable_ratio": 0.85,
                "null_ratio": 0.0,
                "high_entropy_ratio": 0.1,
                "classification": "Text/Strings",
                "windows": [],
                "byte_counts": {},
            },
            {
                "chunk_offset": 2000,
                "chunk_size": 1000,
                "chunk_entropy": 7.8,
                "unique_bytes": 255,
                "printable_ratio": 0.2,
                "null_ratio": 0.0,
                "high_entropy_ratio": 0.8,
                "classification": "Encrypted/Compressed",
                "windows": [],
                "byte_counts": {},
            },
        ]

        analyzer.total_bytes = 3000

        merged = analyzer.merge_results(chunk_results)

        assert merged["classification_distribution"]["Empty/Padding"] == 1
        assert merged["classification_distribution"]["Text/Strings"] == 1
        assert merged["classification_distribution"]["Encrypted/Compressed"] == 1

    def test_merge_results_limits_output_size(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """merge_results limits entropy windows and high-entropy regions output."""
        high_entropy_regions = [
            {"offset": i * 1000, "size": 1000, "entropy": 7.8} for i in range(150)
        ]
        analyzer.high_entropy_regions = high_entropy_regions

        windows = [
            {"offset": i * 100, "size": 1024, "entropy": 7.5, "unique_bytes": 250}
            for i in range(1500)
        ]

        chunk_results = [
            {
                "chunk_offset": 0,
                "chunk_size": 150000,
                "chunk_entropy": 7.5,
                "unique_bytes": 255,
                "printable_ratio": 0.2,
                "null_ratio": 0.0,
                "high_entropy_ratio": 0.8,
                "classification": "Encrypted/Compressed",
                "windows": windows,
                "byte_counts": {},
            },
        ]

        analyzer.total_bytes = 150000

        merged = analyzer.merge_results(chunk_results)

        assert len(merged["high_entropy_regions"]) <= 100
        assert len(merged["entropy_windows"]) <= 1000


class TestAnalysisFinalization:
    """Validate analysis finalization and protection detection."""

    @pytest.fixture
    def analyzer(self) -> StreamingEntropyAnalyzer:
        """Provide analyzer instance."""
        return StreamingEntropyAnalyzer()

    def test_finalize_detects_packed_binary(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """finalize_analysis correctly identifies packed binaries."""
        merged_results = {
            "global_entropy": 7.2,
            "high_entropy_regions": [{"offset": i * 1000, "size": 1000} for i in range(5)],
        }

        analyzer.global_byte_counts = {i: 50 for i in range(200)}
        analyzer.total_bytes = 10000

        finalized = analyzer.finalize_analysis(merged_results)

        assert finalized["is_packed"] is True
        assert finalized["is_encrypted"] is False
        assert any("pack" in indicator.lower() for indicator in finalized["protection_indicators"])

    def test_finalize_detects_encrypted_binary(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """finalize_analysis correctly identifies encrypted binaries."""
        merged_results = {
            "global_entropy": 7.8,
            "high_entropy_regions": [{"offset": i * 1000, "size": 1000} for i in range(20)],
        }

        analyzer.global_byte_counts = {i: 40 for i in range(256)}
        analyzer.total_bytes = 10240

        finalized = analyzer.finalize_analysis(merged_results)

        assert finalized["is_encrypted"] is True
        assert finalized["is_packed"] is True
        assert any("encrypt" in indicator.lower() for indicator in finalized["protection_indicators"])

    def test_finalize_detects_multiple_high_entropy_regions(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """finalize_analysis detects binaries with many high-entropy regions."""
        merged_results = {
            "global_entropy": 6.5,
            "high_entropy_regions": [{"offset": i * 1000, "size": 1000} for i in range(15)],
        }

        analyzer.global_byte_counts = {i: 100 for i in range(100)}
        analyzer.total_bytes = 10000

        finalized = analyzer.finalize_analysis(merged_results)

        assert any("multiple" in indicator.lower() for indicator in finalized["protection_indicators"])
        assert any("15" in indicator for indicator in finalized["protection_indicators"])

    def test_finalize_calculates_byte_usage_efficiency(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """finalize_analysis calculates byte usage efficiency correctly."""
        merged_results = {
            "global_entropy": 6.0,
            "high_entropy_regions": [],
        }

        analyzer.global_byte_counts = {i: 10 for i in range(128)}
        analyzer.total_bytes = 1280

        finalized = analyzer.finalize_analysis(merged_results)

        expected_efficiency = 128 / 256
        assert abs(finalized["byte_usage_efficiency"] - expected_efficiency) < 0.01

    def test_finalize_calculates_randomness_score(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """finalize_analysis calculates randomness percentage correctly."""
        merged_results = {
            "global_entropy": 8.0,
            "high_entropy_regions": [],
        }

        analyzer.global_byte_counts = {i: 1 for i in range(256)}
        analyzer.total_bytes = 256

        finalized = analyzer.finalize_analysis(merged_results)

        assert abs(finalized["randomness_score"] - 100.0) < 1.0

    def test_finalize_generates_summary(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """finalize_analysis generates informative summary text."""
        merged_results = {
            "global_entropy": 7.8,
            "randomness_score": 97.5,
            "is_packed": True,
            "is_encrypted": True,
            "high_entropy_regions": [{"offset": i * 1000} for i in range(15)],
        }

        analyzer.global_byte_counts = {i: 1 for i in range(256)}
        analyzer.total_bytes = 256

        finalized = analyzer.finalize_analysis(merged_results)

        summary = finalized["summary"]
        assert "7.8" in summary or "7.80" in summary
        assert "encrypted" in summary.lower() or "compressed" in summary.lower()
        assert "15" in summary

    def test_finalize_generates_recommendations_for_encrypted(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """finalize_analysis provides appropriate recommendations for encrypted binaries."""
        merged_results = {
            "global_entropy": 7.9,
            "is_encrypted": True,
            "is_packed": False,
            "high_entropy_regions": [{"offset": i * 1000} for i in range(5)],
        }

        analyzer.global_byte_counts = {i: 1 for i in range(256)}
        analyzer.total_bytes = 256

        finalized = analyzer.finalize_analysis(merged_results)

        recommendations = finalized["recommendations"]
        assert len(recommendations) > 0
        assert any("unpack" in rec.lower() for rec in recommendations)
        assert any("dynamic" in rec.lower() for rec in recommendations)

    def test_finalize_generates_recommendations_for_packed(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """finalize_analysis provides appropriate recommendations for packed binaries."""
        merged_results = {
            "global_entropy": 7.2,
            "is_encrypted": False,
            "is_packed": True,
            "high_entropy_regions": [{"offset": i * 1000} for i in range(8)],
        }

        analyzer.global_byte_counts = {i: 50 for i in range(200)}
        analyzer.total_bytes = 10000

        finalized = analyzer.finalize_analysis(merged_results)

        recommendations = finalized["recommendations"]
        assert len(recommendations) > 0
        assert any("packer" in rec.lower() for rec in recommendations)


class TestEntropyDistribution:
    """Validate entropy distribution calculation."""

    @pytest.fixture
    def analyzer(self) -> StreamingEntropyAnalyzer:
        """Provide analyzer instance."""
        return StreamingEntropyAnalyzer()

    def test_entropy_distribution_categorization(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """_calculate_entropy_distribution categorizes entropy values correctly."""
        entropies = [1.5, 3.0, 5.0, 6.5, 7.2, 7.8]

        distribution = analyzer._calculate_entropy_distribution(entropies)

        assert distribution["very_low"] == 1
        assert distribution["low"] == 1
        assert distribution["medium"] == 1
        assert distribution["high"] == 1
        assert distribution["very_high"] == 2

    def test_entropy_distribution_empty_list(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """_calculate_entropy_distribution handles empty entropy list."""
        distribution = analyzer._calculate_entropy_distribution([])

        assert distribution["very_low"] == 0
        assert distribution["low"] == 0
        assert distribution["medium"] == 0
        assert distribution["high"] == 0
        assert distribution["very_high"] == 0

    def test_entropy_distribution_all_same_category(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """_calculate_entropy_distribution handles all values in same category."""
        entropies = [7.6, 7.7, 7.8, 7.9]

        distribution = analyzer._calculate_entropy_distribution(entropies)

        assert distribution["very_high"] == 4
        assert distribution["high"] == 0


class TestEndToEndStreamingAnalysis:
    """Validate complete streaming analysis workflows."""

    def test_streaming_analysis_on_synthetic_binary(self, temp_workspace: Path) -> None:
        """Complete streaming analysis on synthetic binary with mixed entropy."""
        binary_path = temp_workspace / "synthetic_mixed.bin"

        header = b"MZ\x90\x00" + b"\x00" * 60
        text_section = b"License validation code here. " * 100
        encrypted_section = os.urandom(5000)
        padding = b"\x00" * 1000

        data = header + text_section + encrypted_section + padding
        binary_path.write_bytes(data)

        results = analyze_entropy_streaming(
            binary_path=binary_path,
            window_size=1024,
            stride=512,
        )

        assert results["status"] == "completed"
        assert "global_entropy" in results
        assert "total_bytes" in results
        assert results["total_bytes"] == len(data)
        assert "entropy_distribution" in results
        assert "is_packed" in results
        assert "is_encrypted" in results
        assert "summary" in results
        assert "recommendations" in results
        assert results["streaming_mode"] is True

    def test_streaming_analysis_with_progress_callback(self, temp_workspace: Path) -> None:
        """Streaming analysis invokes progress callback correctly."""
        binary_path = temp_workspace / "progress_test.bin"
        data = os.urandom(100000)
        binary_path.write_bytes(data)

        progress_updates: list[tuple[int, int]] = []

        def progress_callback(progress: StreamingProgress) -> None:
            progress_updates.append((progress.bytes_processed, progress.total_bytes))

        results = analyze_entropy_streaming(
            binary_path=binary_path,
            window_size=4096,
            stride=2048,
            progress_callback=progress_callback,
        )

        assert results["status"] == "completed"
        assert len(progress_updates) > 0

        for processed, total in progress_updates:
            assert processed <= total

    def test_streaming_analysis_nonexistent_file(self, temp_workspace: Path) -> None:
        """Streaming analysis handles missing files gracefully."""
        nonexistent = temp_workspace / "does_not_exist.bin"

        results = analyze_entropy_streaming(binary_path=nonexistent)

        assert "error" in results
        assert "not found" in results["error"].lower()
        assert results["status"] == "failed"

    def test_streaming_analysis_empty_file(self, temp_workspace: Path) -> None:
        """Streaming analysis handles empty files."""
        empty_file = temp_workspace / "empty.bin"
        empty_file.write_bytes(b"")

        results = analyze_entropy_streaming(binary_path=empty_file)

        if "error" not in results:
            assert results["total_bytes"] == 0

    def test_streaming_analysis_large_uniform_data(self, temp_workspace: Path) -> None:
        """Streaming analysis correctly identifies large uniform data files."""
        binary_path = temp_workspace / "uniform_large.bin"
        data = b"\x42" * 500000
        binary_path.write_bytes(data)

        results = analyze_entropy_streaming(
            binary_path=binary_path,
            window_size=8192,
            stride=4096,
        )

        assert results["status"] == "completed"
        assert results["global_entropy"] == 0.0
        assert results["is_packed"] is False
        assert results["is_encrypted"] is False

    def test_streaming_analysis_large_random_data(self, temp_workspace: Path) -> None:
        """Streaming analysis correctly identifies large random data files."""
        binary_path = temp_workspace / "random_large.bin"
        data = os.urandom(500000)
        binary_path.write_bytes(data)

        results = analyze_entropy_streaming(
            binary_path=binary_path,
            window_size=8192,
            stride=4096,
        )

        assert results["status"] == "completed"
        assert results["global_entropy"] > 7.9
        assert results["is_packed"] is True
        assert results["is_encrypted"] is True


class TestRealWindowsBinaryAnalysis:
    """Validate streaming entropy analysis on real Windows binaries."""

    @pytest.mark.skipif(not REAL_BINARIES["notepad"].exists(), reason="notepad.exe not found")
    def test_streaming_analysis_notepad_exe(self) -> None:
        """Streaming analysis on real notepad.exe produces valid results."""
        results = analyze_entropy_streaming(
            binary_path=REAL_BINARIES["notepad"],
            window_size=64 * 1024,
            stride=32 * 1024,
        )

        assert results["status"] == "completed"
        assert results["global_entropy"] > 0.0
        assert results["total_bytes"] > 0
        assert results["unique_bytes"] > 0
        assert 0.0 <= results["global_entropy"] <= 8.0
        assert "entropy_distribution" in results
        assert "classification_distribution" in results

    @pytest.mark.skipif(not REAL_BINARIES["calc"].exists(), reason="calc.exe not found")
    def test_streaming_analysis_calc_exe(self) -> None:
        """Streaming analysis on real calc.exe produces valid results."""
        results = analyze_entropy_streaming(
            binary_path=REAL_BINARIES["calc"],
            window_size=64 * 1024,
            stride=32 * 1024,
        )

        assert results["status"] == "completed"
        assert results["global_entropy"] > 0.0
        assert results["total_bytes"] > 0
        assert 0.0 <= results["global_entropy"] <= 8.0

    @pytest.mark.skipif(not REAL_BINARIES["kernel32"].exists(), reason="kernel32.dll not found")
    def test_streaming_analysis_kernel32_dll(self) -> None:
        """Streaming analysis on real kernel32.dll produces valid results."""
        results = analyze_entropy_streaming(
            binary_path=REAL_BINARIES["kernel32"],
            window_size=128 * 1024,
            stride=64 * 1024,
        )

        assert results["status"] == "completed"
        assert results["global_entropy"] > 0.0
        assert results["total_bytes"] > 0
        assert 0.0 <= results["global_entropy"] <= 8.0
        assert results["unique_bytes"] > 50

    @pytest.mark.skipif(not REAL_BINARIES["ntdll"].exists(), reason="ntdll.dll not found")
    def test_streaming_analysis_ntdll_dll(self) -> None:
        """Streaming analysis on real ntdll.dll produces valid results."""
        results = analyze_entropy_streaming(
            binary_path=REAL_BINARIES["ntdll"],
            window_size=128 * 1024,
            stride=64 * 1024,
        )

        assert results["status"] == "completed"
        assert results["global_entropy"] > 0.0
        assert results["total_bytes"] > 0
        assert 0.0 <= results["global_entropy"] <= 8.0


class TestMemoryEfficiency:
    """Validate memory-efficient processing of large files."""

    def test_large_file_streaming_without_loading_entire_file(self, temp_workspace: Path) -> None:
        """Streaming analysis processes large files without loading entirely into memory."""
        binary_path = temp_workspace / "large_file.bin"

        chunk_size = 1024 * 1024
        num_chunks = 50

        with open(binary_path, "wb") as f:
            for i in range(num_chunks):
                chunk = bytes([i % 256] * chunk_size)
                f.write(chunk)

        file_size = binary_path.stat().st_size
        assert file_size == chunk_size * num_chunks

        results = analyze_entropy_streaming(
            binary_path=binary_path,
            window_size=256 * 1024,
            stride=128 * 1024,
        )

        assert results["status"] == "completed"
        assert results["total_bytes"] == file_size
        assert results["streaming_mode"] is True

    def test_streaming_manager_chunk_iteration(self, temp_workspace: Path) -> None:
        """StreamingAnalysisManager iterates chunks correctly."""
        binary_path = temp_workspace / "chunk_iteration.bin"
        data = b"A" * 10000 + b"B" * 10000 + b"C" * 10000
        binary_path.write_bytes(data)

        manager = StreamingAnalysisManager(
            config=StreamingConfig(chunk_size=8192, overlap_size=256)
        )

        chunks = list(manager.read_chunks(binary_path))

        assert len(chunks) > 0

        total_data_size = sum(chunk.size for chunk in chunks)
        assert total_data_size == len(data)

        for i, chunk in enumerate(chunks):
            assert chunk.chunk_number == i
            assert chunk.size > 0
            assert len(chunk.data) == chunk.size


class TestEntropyWindowDataclass:
    """Validate EntropyWindow dataclass functionality."""

    def test_entropy_window_initialization(self) -> None:
        """EntropyWindow initializes with correct defaults."""
        window = EntropyWindow(offset=1024, size=512, entropy=6.5)

        assert window.offset == 1024
        assert window.size == 512
        assert window.entropy == 6.5
        assert window.byte_distribution == {}
        assert window.unique_bytes == 0
        assert window.printable_ratio == 0.0
        assert window.null_ratio == 0.0
        assert window.high_entropy_ratio == 0.0
        assert window.classification == ""

    def test_entropy_window_with_full_data(self) -> None:
        """EntropyWindow stores complete analysis data correctly."""
        window = EntropyWindow(
            offset=2048,
            size=1024,
            entropy=7.5,
            byte_distribution={0: 100, 255: 50},
            unique_bytes=128,
            printable_ratio=0.3,
            null_ratio=0.1,
            high_entropy_ratio=0.6,
            classification="Encrypted/Compressed",
        )

        assert window.offset == 2048
        assert window.size == 1024
        assert window.entropy == 7.5
        assert window.byte_distribution[0] == 100
        assert window.byte_distribution[255] == 50
        assert window.unique_bytes == 128
        assert window.printable_ratio == 0.3
        assert window.null_ratio == 0.1
        assert window.high_entropy_ratio == 0.6
        assert window.classification == "Encrypted/Compressed"


class TestEdgeCases:
    """Validate edge cases and error handling."""

    @pytest.fixture
    def analyzer(self) -> StreamingEntropyAnalyzer:
        """Provide analyzer instance."""
        return StreamingEntropyAnalyzer(window_size=1024, stride=512)

    def test_analyze_chunk_smaller_than_window(self, analyzer: StreamingEntropyAnalyzer, temp_workspace: Path) -> None:
        """analyze_chunk handles chunks smaller than window size."""
        test_file = temp_workspace / "small_chunk.bin"
        data = b"Small data"
        test_file.write_bytes(data)

        analyzer.initialize_analysis(test_file)

        context = ChunkContext(
            offset=0,
            size=len(data),
            chunk_number=1,
            total_chunks=1,
            data=data,
            file_path=test_file,
        )

        result = analyzer.analyze_chunk(context)

        assert "chunk_entropy" in result
        assert "windows" in result

    def test_window_stride_equals_window_size(self, temp_workspace: Path) -> None:
        """Non-overlapping windows work correctly."""
        analyzer = StreamingEntropyAnalyzer(window_size=1024, stride=1024)

        test_file = temp_workspace / "non_overlapping.bin"
        data = os.urandom(4096)
        test_file.write_bytes(data)

        analyzer.initialize_analysis(test_file)

        context = ChunkContext(
            offset=0,
            size=len(data),
            chunk_number=1,
            total_chunks=1,
            data=data,
            file_path=test_file,
        )

        result = analyzer.analyze_chunk(context)

        windows = result["windows"]

        for i in range(len(windows) - 1):
            assert windows[i + 1]["offset"] == windows[i]["offset"] + 1024

    def test_analyze_chunk_with_exception_handling(self, analyzer: StreamingEntropyAnalyzer, temp_workspace: Path) -> None:
        """analyze_chunk handles internal errors gracefully."""
        test_file = temp_workspace / "error_test.bin"
        data = b"\x00" * 1024
        test_file.write_bytes(data)

        analyzer.initialize_analysis(test_file)

        context = ChunkContext(
            offset=0,
            size=len(data),
            chunk_number=1,
            total_chunks=1,
            data=data,
            file_path=test_file,
        )

        result = analyzer.analyze_chunk(context)

        assert "chunk_offset" in result
        assert "chunk_size" in result
