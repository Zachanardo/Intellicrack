"""Comprehensive tests for StreamingEntropyAnalyzer.

Tests validate real entropy calculation on actual binary data with known
entropy characteristics. NO mocks - only real functionality validation.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import math
import struct
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from intellicrack.core.analysis.streaming_entropy_analyzer import (
    EntropyWindow,
    StreamingEntropyAnalyzer,
    analyze_entropy_streaming,
)
from intellicrack.core.processing.streaming_analysis_manager import ChunkContext


class TestStreamingEntropyAnalyzer:
    """Test suite for streaming entropy analysis."""

    @pytest.fixture
    def analyzer(self) -> StreamingEntropyAnalyzer:
        """Create analyzer instance with standard window size."""
        return StreamingEntropyAnalyzer(window_size=1024, stride=512)

    @pytest.fixture
    def low_entropy_data(self, temp_workspace: Path) -> Path:
        """Create binary with low entropy (repetitive data)."""
        binary_path = temp_workspace / "low_entropy.bin"
        data = b"\x00" * 10000
        binary_path.write_bytes(data)
        return binary_path

    @pytest.fixture
    def high_entropy_data(self, temp_workspace: Path) -> Path:
        """Create binary with high entropy (random-like data)."""
        import os
        binary_path = temp_workspace / "high_entropy.bin"
        data = os.urandom(10000)
        binary_path.write_bytes(data)
        return binary_path

    @pytest.fixture
    def encrypted_section_binary(self, temp_workspace: Path) -> Path:
        """Create binary simulating encrypted section."""
        import os
        binary_path = temp_workspace / "encrypted_section.bin"

        low_entropy_header = b"\x4D\x5A" + b"\x00" * 1000
        high_entropy_encrypted = os.urandom(8000)
        low_entropy_footer = b"\x00" * 1000

        data = low_entropy_header + high_entropy_encrypted + low_entropy_footer
        binary_path.write_bytes(data)
        return binary_path

    @pytest.fixture
    def text_data_binary(self, temp_workspace: Path) -> Path:
        """Create binary with ASCII text data."""
        binary_path = temp_workspace / "text_data.bin"
        text = b"This is a test string with printable ASCII characters. " * 200
        binary_path.write_bytes(text)
        return binary_path

    def test_analyzer_initialization(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """Analyzer initializes with correct configuration."""
        assert analyzer.window_size == 1024
        assert analyzer.stride == 512
        assert len(analyzer.global_byte_counts) == 0
        assert analyzer.total_bytes == 0
        assert len(analyzer.entropy_windows) == 0
        assert len(analyzer.high_entropy_regions) == 0

    def test_initialize_analysis_resets_state(self, analyzer: StreamingEntropyAnalyzer, temp_workspace: Path) -> None:
        """initialize_analysis clears previous analysis state."""
        analyzer.total_bytes = 5000
        analyzer.entropy_windows.append(EntropyWindow(offset=0, size=1024, entropy=5.0))
        analyzer.high_entropy_regions.append({"offset": 0, "size": 1024})

        test_file = temp_workspace / "test.bin"
        test_file.write_bytes(b"\x00" * 1024)

        analyzer.initialize_analysis(test_file)

        assert analyzer.total_bytes == 0
        assert len(analyzer.entropy_windows) == 0
        assert len(analyzer.high_entropy_regions) == 0

    def test_calculate_entropy_perfect_randomness(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """_calculate_entropy calculates 8.0 for perfectly random data."""
        byte_counts = {i: 1 for i in range(256)}
        total_bytes = 256

        entropy = analyzer._calculate_entropy(byte_counts, total_bytes)

        assert abs(entropy - 8.0) < 0.01

    def test_calculate_entropy_zero_entropy(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """_calculate_entropy calculates 0.0 for identical bytes."""
        byte_counts = {0: 1000}
        total_bytes = 1000

        entropy = analyzer._calculate_entropy(byte_counts, total_bytes)

        assert entropy == 0.0

    def test_calculate_entropy_medium_entropy(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """_calculate_entropy calculates intermediate values correctly."""
        byte_counts = {
            ord('A'): 500,
            ord('B'): 500
        }
        total_bytes = 1000

        entropy = analyzer._calculate_entropy(byte_counts, total_bytes)

        expected_entropy = -2 * (0.5 * math.log2(0.5))
        assert abs(entropy - expected_entropy) < 0.001
        assert abs(entropy - 1.0) < 0.001

    def test_classify_section_empty_padding(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """_classify_section identifies empty/padding sections."""
        classification = analyzer._classify_section(
            entropy=2.0,
            printable_ratio=0.1,
            null_ratio=0.95
        )

        assert classification == "Empty/Padding"

    def test_classify_section_encrypted(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """_classify_section identifies encrypted/compressed data."""
        classification = analyzer._classify_section(
            entropy=7.8,
            printable_ratio=0.2,
            null_ratio=0.0
        )

        assert classification == "Encrypted/Compressed"

    def test_classify_section_text(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """_classify_section identifies text/strings."""
        classification = analyzer._classify_section(
            entropy=5.0,
            printable_ratio=0.85,
            null_ratio=0.0
        )

        assert classification == "Text/Strings"

    def test_classify_section_code(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """_classify_section identifies code/binary data."""
        classification = analyzer._classify_section(
            entropy=6.5,
            printable_ratio=0.05,
            null_ratio=0.0
        )

        assert classification == "Code/Binary Data"

    def test_analyze_chunk_low_entropy_data(self, analyzer: StreamingEntropyAnalyzer, low_entropy_data: Path) -> None:
        """analyze_chunk correctly analyzes low entropy data."""
        data = low_entropy_data.read_bytes()

        analyzer.initialize_analysis(low_entropy_data)

        context = ChunkContext(
            offset=0,
            size=len(data),
            chunk_number=1,
            total_chunks=1,
            data=data,
            file_path=low_entropy_data
        )

        result = analyzer.analyze_chunk(context)

        assert result["chunk_entropy"] < 1.0
        assert result["null_ratio"] > 0.95
        assert "Empty/Padding" in result["classification"] or "Highly Repetitive" in result["classification"]
        assert result["unique_bytes"] == 1

    def test_analyze_chunk_high_entropy_data(self, analyzer: StreamingEntropyAnalyzer, high_entropy_data: Path) -> None:
        """analyze_chunk correctly analyzes high entropy data."""
        data = high_entropy_data.read_bytes()

        analyzer.initialize_analysis(high_entropy_data)

        context = ChunkContext(
            offset=0,
            size=len(data),
            chunk_number=1,
            total_chunks=1,
            data=data,
            file_path=high_entropy_data
        )

        result = analyzer.analyze_chunk(context)

        assert result["chunk_entropy"] > 7.0
        assert result["unique_bytes"] > 200
        assert "Encrypted/Compressed" in result["classification"]

    def test_analyze_chunk_text_data(self, analyzer: StreamingEntropyAnalyzer, text_data_binary: Path) -> None:
        """analyze_chunk identifies text data correctly."""
        data = text_data_binary.read_bytes()

        analyzer.initialize_analysis(text_data_binary)

        context = ChunkContext(
            offset=0,
            size=len(data),
            chunk_number=1,
            total_chunks=1,
            data=data,
            file_path=text_data_binary
        )

        result = analyzer.analyze_chunk(context)

        assert result["printable_ratio"] > 0.8
        assert "Text/Strings" in result["classification"]

    def test_analyze_chunk_creates_windows(self, analyzer: StreamingEntropyAnalyzer, high_entropy_data: Path) -> None:
        """analyze_chunk creates entropy windows with correct stride."""
        data = high_entropy_data.read_bytes()[:8192]

        analyzer.initialize_analysis(high_entropy_data)

        context = ChunkContext(
            offset=0,
            size=len(data),
            chunk_number=1,
            total_chunks=1,
            data=data,
            file_path=high_entropy_data
        )

        result = analyzer.analyze_chunk(context)

        assert "windows" in result
        windows = result["windows"]

        expected_windows = (len(data) - analyzer.window_size) // analyzer.stride + 1
        assert len(windows) >= expected_windows - 1

        for window in windows:
            assert "offset" in window
            assert "size" in window
            assert "entropy" in window
            assert "unique_bytes" in window

    def test_analyze_chunk_identifies_high_entropy_regions(self, analyzer: StreamingEntropyAnalyzer, encrypted_section_binary: Path) -> None:
        """analyze_chunk detects high-entropy regions in binary."""
        data = encrypted_section_binary.read_bytes()

        analyzer.initialize_analysis(encrypted_section_binary)

        context = ChunkContext(
            offset=0,
            size=len(data),
            chunk_number=1,
            total_chunks=1,
            data=data,
            file_path=encrypted_section_binary
        )

        analyzer.analyze_chunk(context)

        assert len(analyzer.high_entropy_regions) > 0

        for region in analyzer.high_entropy_regions:
            assert region["entropy"] > StreamingEntropyAnalyzer.ENTROPY_THRESHOLDS["very_high"]

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
                "windows": [],
                "byte_counts": {0: 900, 1: 100}
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
                "windows": [],
                "byte_counts": {i: 4 for i in range(250)}
            }
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

    def test_merge_results_handles_errors(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """merge_results handles chunk errors gracefully."""
        chunk_results = [
            {
                "chunk_offset": 0,
                "chunk_size": 1000,
                "error": "Processing failed",
                "chunk_entropy": 0.0
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
                "byte_counts": {}
            }
        ]

        analyzer.total_bytes = 1000

        merged = analyzer.merge_results(chunk_results)

        assert "errors" in merged
        assert len(merged["errors"]) == 1
        assert "0x00000000" in merged["errors"][0]

    def test_finalize_analysis_detects_packing(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """finalize_analysis correctly identifies packed binaries."""
        merged_results = {
            "global_entropy": 7.2,
            "high_entropy_regions": [{"offset": i * 1000, "size": 1000} for i in range(5)]
        }

        analyzer.global_byte_counts = {i: 50 for i in range(200)}
        analyzer.total_bytes = 10000

        finalized = analyzer.finalize_analysis(merged_results)

        assert finalized["is_packed"] is True
        assert finalized["is_encrypted"] is False
        assert "packing" in " ".join(finalized["protection_indicators"]).lower()

    def test_finalize_analysis_detects_encryption(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """finalize_analysis correctly identifies encrypted binaries."""
        merged_results = {
            "global_entropy": 7.8,
            "high_entropy_regions": [{"offset": i * 1000, "size": 1000} for i in range(20)]
        }

        analyzer.global_byte_counts = {i: 40 for i in range(256)}
        analyzer.total_bytes = 10240

        finalized = analyzer.finalize_analysis(merged_results)

        assert finalized["is_encrypted"] is True
        assert finalized["is_packed"] is True
        assert "encryption" in " ".join(finalized["protection_indicators"]).lower()

    def test_finalize_analysis_calculates_byte_usage_efficiency(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """finalize_analysis calculates byte usage efficiency correctly."""
        merged_results = {
            "global_entropy": 6.0,
            "high_entropy_regions": []
        }

        analyzer.global_byte_counts = {i: 10 for i in range(128)}
        analyzer.total_bytes = 1280

        finalized = analyzer.finalize_analysis(merged_results)

        assert "byte_usage_efficiency" in finalized
        assert abs(finalized["byte_usage_efficiency"] - 0.5) < 0.01

    def test_finalize_analysis_calculates_randomness_score(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """finalize_analysis calculates randomness percentage."""
        merged_results = {
            "global_entropy": 8.0,
            "high_entropy_regions": []
        }

        analyzer.global_byte_counts = {i: 1 for i in range(256)}
        analyzer.total_bytes = 256

        finalized = analyzer.finalize_analysis(merged_results)

        assert "randomness_score" in finalized
        assert abs(finalized["randomness_score"] - 100.0) < 1.0

    def test_generate_summary_creates_meaningful_text(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """_generate_summary creates informative summary."""
        results: dict[str, Any] = {
            "global_entropy": 7.8,
            "randomness_score": 97.5,
            "is_packed": True,
            "is_encrypted": True,
            "high_entropy_regions": [{"offset": i * 1000} for i in range(15)]
        }

        summary = analyzer._generate_summary(results)

        assert "7.8" in summary or "7.80" in summary
        assert "97" in summary
        assert "encrypted" in summary.lower() or "compressed" in summary.lower()
        assert "15" in summary

    def test_generate_recommendations_for_encrypted_binary(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """_generate_recommendations provides unpacking guidance."""
        results: dict[str, Any] = {
            "is_encrypted": True,
            "is_packed": False,
            "high_entropy_regions": [{"offset": i * 1000} for i in range(5)]
        }

        recommendations = analyzer._generate_recommendations(results)

        assert len(recommendations) > 0
        assert any("unpack" in r.lower() for r in recommendations)
        assert any("dynamic" in r.lower() for r in recommendations)

    def test_generate_recommendations_for_packed_binary(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """_generate_recommendations provides packer identification guidance."""
        results: dict[str, Any] = {
            "is_encrypted": False,
            "is_packed": True,
            "high_entropy_regions": [{"offset": i * 1000} for i in range(8)]
        }

        recommendations = analyzer._generate_recommendations(results)

        assert len(recommendations) > 0
        assert any("packer" in r.lower() for r in recommendations)

    def test_calculate_entropy_distribution(self, analyzer: StreamingEntropyAnalyzer) -> None:
        """_calculate_entropy_distribution categorizes entropy values."""
        entropies = [1.5, 3.0, 5.0, 6.5, 7.2, 7.8]

        distribution = analyzer._calculate_entropy_distribution(entropies)

        assert distribution["very_low"] == 1
        assert distribution["low"] == 1
        assert distribution["medium"] == 1
        assert distribution["high"] == 1
        assert distribution["very_high"] == 2

    def test_streaming_analysis_end_to_end(self, encrypted_section_binary: Path) -> None:
        """Full streaming entropy analysis workflow."""
        results = analyze_entropy_streaming(
            binary_path=encrypted_section_binary,
            window_size=1024,
            stride=512
        )

        assert "global_entropy" in results
        assert "total_bytes" in results
        assert "entropy_distribution" in results
        assert "is_packed" in results
        assert "is_encrypted" in results
        assert "summary" in results
        assert "recommendations" in results

        assert results.get("status") != "failed"

    def test_streaming_analysis_with_nonexistent_file(self, temp_workspace: Path) -> None:
        """analyze_entropy_streaming handles missing files."""
        nonexistent = temp_workspace / "does_not_exist.bin"

        results = analyze_entropy_streaming(binary_path=nonexistent)

        assert "error" in results
        assert "not found" in results["error"].lower()
        assert results["status"] == "failed"

    def test_streaming_analysis_with_empty_file(self, temp_workspace: Path) -> None:
        """analyze_entropy_streaming handles empty files."""
        empty_file = temp_workspace / "empty.bin"
        empty_file.write_bytes(b"")

        results = analyze_entropy_streaming(binary_path=empty_file)

        assert "global_entropy" in results or "error" in results

    def test_analyze_chunk_error_handling(self, analyzer: StreamingEntropyAnalyzer, temp_workspace: Path) -> None:
        """analyze_chunk handles errors gracefully."""
        test_file = temp_workspace / "test.bin"
        test_file.write_bytes(b"\x00" * 1024)

        analyzer.initialize_analysis(test_file)

        context = ChunkContext(
            offset=0,
            size=1024,
            chunk_number=1,
            total_chunks=1,
            data=b"\x00" * 1024,
            file_path=test_file
        )

        result = analyzer.analyze_chunk(context)

        assert "chunk_offset" in result
        assert "chunk_size" in result
        assert "chunk_entropy" in result


class TestEntropyWindow:
    """Test EntropyWindow dataclass."""

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
        """EntropyWindow stores analysis data correctly."""
        window = EntropyWindow(
            offset=2048,
            size=1024,
            entropy=7.5,
            byte_distribution={0: 100, 255: 50},
            unique_bytes=128,
            printable_ratio=0.3,
            null_ratio=0.1,
            high_entropy_ratio=0.6,
            classification="Encrypted/Compressed"
        )

        assert window.byte_distribution[0] == 100
        assert window.unique_bytes == 128
        assert window.classification == "Encrypted/Compressed"
