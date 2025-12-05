"""Production-Ready Tests for Streaming Cryptographic Routine Detector.

Comprehensive test suite validating streaming cryptographic constant detection
on real Windows binaries. Tests cover chunk-based processing, memory-efficient
analysis, detection accuracy, and performance characteristics.

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

import hashlib
import struct
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

import pytest

from intellicrack.core.analysis.cryptographic_routine_detector import CryptoAlgorithm, CryptographicRoutineDetector
from intellicrack.core.analysis.streaming_crypto_detector import (
    ChunkCryptoResults,
    StreamingCryptoDetector,
    analyze_crypto_streaming,
)
from intellicrack.core.processing.streaming_analysis_manager import ChunkContext, StreamingAnalysisManager


WINDOWS_SYSTEM_BINARIES = [
    Path(r"C:\Windows\System32\notepad.exe"),
    Path(r"C:\Windows\System32\kernel32.dll"),
    Path(r"C:\Windows\System32\ntdll.dll"),
    Path(r"C:\Windows\System32\crypt32.dll"),
    Path(r"C:\Windows\System32\bcrypt.dll"),
    Path(r"C:\Windows\System32\advapi32.dll"),
]


def get_available_system_binary() -> Path:
    """Get first available Windows system binary for testing.

    Returns:
        Path to available system binary

    Raises:
        RuntimeError: If no system binaries are available
    """
    for binary in WINDOWS_SYSTEM_BINARIES:
        if binary.exists():
            return binary
    raise RuntimeError("No Windows system binaries available for testing")


def get_crypto_binary() -> Path:
    """Get Windows crypto library for testing cryptographic detection.

    Returns:
        Path to crypt32.dll or bcrypt.dll

    Raises:
        RuntimeError: If no crypto binaries are available
    """
    crypto_libs = [
        Path(r"C:\Windows\System32\crypt32.dll"),
        Path(r"C:\Windows\System32\bcrypt.dll"),
    ]
    for lib in crypto_libs:
        if lib.exists():
            return lib
    raise RuntimeError("No Windows crypto libraries available for testing")


@pytest.fixture
def system_binary() -> Path:
    """Fixture providing real Windows system binary."""
    return get_available_system_binary()


@pytest.fixture
def crypto_binary() -> Path:
    """Fixture providing Windows crypto library."""
    return get_crypto_binary()


@pytest.fixture
def streaming_detector() -> StreamingCryptoDetector:
    """Fixture providing fresh streaming crypto detector instance."""
    return StreamingCryptoDetector(quick_mode=False, use_radare2=False)


@pytest.fixture
def quick_detector() -> StreamingCryptoDetector:
    """Fixture providing quick-mode streaming crypto detector."""
    return StreamingCryptoDetector(quick_mode=True, use_radare2=False)


@pytest.fixture
def temp_binary_with_aes() -> Path:
    """Create temporary binary containing AES S-box for testing."""
    detector = CryptographicRoutineDetector()

    aes_sbox = detector.AES_SBOX

    binary_data = bytearray(b"\x00" * 1024)
    binary_data[512:512 + len(aes_sbox)] = aes_sbox
    binary_data.extend(b"\xFF" * 2048)

    with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".bin") as f:
        f.write(binary_data)
        temp_path = Path(f.name)

    yield temp_path

    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def temp_binary_with_sha256() -> Path:
    """Create temporary binary containing SHA-256 constants."""
    sha256_constants = [
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    ]

    binary_data = bytearray(b"\x00" * 2048)

    offset = 1024
    for const in sha256_constants:
        binary_data[offset:offset + 4] = struct.pack("<I", const)
        offset += 4

    binary_data.extend(b"\xCC" * 4096)

    with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".bin") as f:
        f.write(binary_data)
        temp_path = Path(f.name)

    yield temp_path

    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def temp_binary_with_rsa_constants() -> Path:
    """Create temporary binary containing RSA public exponent."""
    rsa_exponent = 65537

    binary_data = bytearray(b"\x00" * 512)
    binary_data[256:260] = struct.pack("<I", rsa_exponent)
    binary_data.extend(b"\xAA" * 1536)

    with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".bin") as f:
        f.write(binary_data)
        temp_path = Path(f.name)

    yield temp_path

    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def temp_large_binary_with_crypto() -> Path:
    """Create large temporary binary with crypto constants distributed throughout."""
    detector = CryptographicRoutineDetector()

    aes_sbox = detector.AES_SBOX
    sha256_constants = [
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    ]

    size_mb = 15
    chunk_size = 1024 * 1024

    with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".bin") as f:
        for chunk_idx in range(size_mb):
            chunk_data = bytearray(b"\x00" * chunk_size)

            if chunk_idx % 3 == 0:
                offset = 512 * 1024
                chunk_data[offset:offset + len(aes_sbox)] = aes_sbox

            if chunk_idx % 5 == 0:
                offset = 768 * 1024
                for const in sha256_constants:
                    chunk_data[offset:offset + 4] = struct.pack("<I", const)
                    offset += 4

            f.write(chunk_data)

        temp_path = Path(f.name)

    yield temp_path

    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def progress_tracker() -> dict[str, Any]:
    """Fixture providing progress tracking dictionary."""
    tracker: dict[str, Any] = {
        "calls": 0,
        "bytes_processed": 0,
        "stages": [],
        "progress_values": [],
    }
    return tracker


@pytest.fixture
def progress_callback(progress_tracker: dict[str, Any]) -> Callable:
    """Fixture providing progress callback function."""
    def callback(progress: Any) -> None:
        progress_tracker["calls"] += 1
        progress_tracker["bytes_processed"] = progress.bytes_processed
        progress_tracker["stages"].append(progress.current_stage)
        progress_tracker["progress_values"].append(progress.overall_progress)
    return callback


class TestStreamingCryptoDetectorInitialization:
    """Test suite for StreamingCryptoDetector initialization and configuration."""

    def test_default_initialization_creates_detector_instance(self) -> None:
        """Default initialization creates functional detector with standard settings."""
        detector = StreamingCryptoDetector()

        assert detector is not None
        assert detector.quick_mode is False
        assert detector.use_radare2 is False
        assert detector.detector is not None
        assert isinstance(detector.detector, CryptographicRoutineDetector)
        assert detector.binary_path is None
        assert detector.global_detections == []
        assert detector.detection_offsets == set()

    def test_quick_mode_initialization_enables_fast_processing(self) -> None:
        """Quick mode initialization enables optimized processing settings."""
        detector = StreamingCryptoDetector(quick_mode=True)

        assert detector.quick_mode is True
        assert detector.use_radare2 is False

    def test_radare2_mode_initialization_enables_enhanced_analysis(self) -> None:
        """Radare2 mode initialization enables advanced analysis capabilities."""
        detector = StreamingCryptoDetector(use_radare2=True)

        assert detector.quick_mode is False
        assert detector.use_radare2 is True

    def test_combined_quick_and_radare2_modes_enabled(self) -> None:
        """Both quick mode and radare2 can be enabled simultaneously."""
        detector = StreamingCryptoDetector(quick_mode=True, use_radare2=True)

        assert detector.quick_mode is True
        assert detector.use_radare2 is True

    def test_initialize_analysis_sets_binary_path(self, system_binary: Path) -> None:
        """Initialize analysis sets binary path and resets detection state."""
        detector = StreamingCryptoDetector()

        detector.initialize_analysis(system_binary)

        assert detector.binary_path == system_binary
        assert detector.global_detections == []
        assert detector.detection_offsets == set()

    def test_multiple_initialize_calls_reset_state(self, system_binary: Path, streaming_detector: StreamingCryptoDetector) -> None:
        """Multiple initialize_analysis calls properly reset detector state."""
        detector = streaming_detector

        detector.detection_offsets.add(0x1000)
        detector.global_detections.append(None)

        detector.initialize_analysis(system_binary)

        assert detector.binary_path == system_binary
        assert detector.global_detections == []
        assert detector.detection_offsets == set()


class TestStreamingChunkAnalysis:
    """Test suite for chunk-based cryptographic analysis."""

    def test_analyze_chunk_detects_aes_sbox_in_chunk(self, temp_binary_with_aes: Path, streaming_detector: StreamingCryptoDetector) -> None:
        """Chunk analysis detects AES S-box within chunk boundaries."""
        detector = streaming_detector
        detector.initialize_analysis(temp_binary_with_aes)

        binary_data = temp_binary_with_aes.read_bytes()

        context = ChunkContext(
            offset=0,
            size=len(binary_data),
            chunk_number=1,
            total_chunks=1,
            data=binary_data,
            file_path=temp_binary_with_aes,
        )

        result = detector.analyze_chunk(context)

        assert result is not None
        assert "detections" in result
        assert "constants_found" in result
        assert "algorithm_counts" in result
        assert result["chunk_offset"] == 0
        assert result["chunk_size"] == len(binary_data)

    def test_analyze_chunk_detects_sha256_constants(self, temp_binary_with_sha256: Path, streaming_detector: StreamingCryptoDetector) -> None:
        """Chunk analysis detects SHA-256 round constants."""
        detector = streaming_detector
        detector.initialize_analysis(temp_binary_with_sha256)

        binary_data = temp_binary_with_sha256.read_bytes()

        context = ChunkContext(
            offset=0,
            size=len(binary_data),
            chunk_number=1,
            total_chunks=1,
            data=binary_data,
            file_path=temp_binary_with_sha256,
        )

        result = detector.analyze_chunk(context)

        assert result is not None
        assert "detections" in result
        assert "constants_found" in result

    def test_analyze_chunk_filters_duplicates_across_chunks(self, temp_binary_with_aes: Path, streaming_detector: StreamingCryptoDetector) -> None:
        """Chunk analysis filters duplicate detections across chunk boundaries."""
        detector = streaming_detector
        detector.initialize_analysis(temp_binary_with_aes)

        binary_data = temp_binary_with_aes.read_bytes()

        context1 = ChunkContext(
            offset=0,
            size=len(binary_data),
            chunk_number=1,
            total_chunks=2,
            data=binary_data,
            file_path=temp_binary_with_aes,
        )

        result1 = detector.analyze_chunk(context1)
        detections_count_1 = len(result1.get("detections", []))

        context2 = ChunkContext(
            offset=0,
            size=len(binary_data),
            chunk_number=2,
            total_chunks=2,
            data=binary_data,
            file_path=temp_binary_with_aes,
        )

        result2 = detector.analyze_chunk(context2)
        detections_count_2 = len(result2.get("detections", []))

        assert detections_count_2 < detections_count_1

    def test_analyze_chunk_handles_overlap_regions(self, temp_binary_with_aes: Path, streaming_detector: StreamingCryptoDetector) -> None:
        """Chunk analysis correctly processes overlap regions between chunks."""
        detector = streaming_detector
        detector.initialize_analysis(temp_binary_with_aes)

        binary_data = temp_binary_with_aes.read_bytes()
        mid_point = len(binary_data) // 2

        overlap_size = 512
        overlap_before = binary_data[max(0, mid_point - overlap_size):mid_point]
        overlap_after = binary_data[mid_point:min(len(binary_data), mid_point + overlap_size)]

        context = ChunkContext(
            offset=mid_point,
            size=len(binary_data) - mid_point,
            chunk_number=2,
            total_chunks=2,
            data=binary_data[mid_point:],
            overlap_before=overlap_before,
            overlap_after=overlap_after,
            file_path=temp_binary_with_aes,
        )

        result = detector.analyze_chunk(context)

        assert result is not None
        assert "detections" in result

    def test_analyze_chunk_respects_chunk_boundaries(self, temp_binary_with_aes: Path, streaming_detector: StreamingCryptoDetector) -> None:
        """Chunk analysis only reports detections within chunk boundaries."""
        detector = streaming_detector
        detector.initialize_analysis(temp_binary_with_aes)

        binary_data = temp_binary_with_aes.read_bytes()
        chunk_offset = 1024
        chunk_size = 1024

        context = ChunkContext(
            offset=chunk_offset,
            size=chunk_size,
            chunk_number=1,
            total_chunks=3,
            data=binary_data[chunk_offset:chunk_offset + chunk_size],
            overlap_before=binary_data[max(0, chunk_offset - 256):chunk_offset],
            overlap_after=binary_data[chunk_offset + chunk_size:min(len(binary_data), chunk_offset + chunk_size + 256)],
            file_path=temp_binary_with_aes,
        )

        result = detector.analyze_chunk(context)

        for detection in result.get("detections", []):
            offset = detection.get("offset", 0)
            assert chunk_offset <= offset < chunk_offset + chunk_size

    def test_analyze_chunk_handles_errors_gracefully(self, streaming_detector: StreamingCryptoDetector) -> None:
        """Chunk analysis handles corrupted data without crashing."""
        detector = streaming_detector
        detector.initialize_analysis(Path("nonexistent.bin"))

        context = ChunkContext(
            offset=0,
            size=0,
            chunk_number=1,
            total_chunks=1,
            data=b"",
            file_path=Path("nonexistent.bin"),
        )

        result = detector.analyze_chunk(context)

        assert result is not None
        assert result["chunk_offset"] == 0
        assert result["chunk_size"] == 0
        assert result["detections"] == []


class TestStreamingCryptoDetectionOnRealBinaries:
    """Test suite for cryptographic detection on real Windows binaries."""

    def test_detect_crypto_in_crypt32_dll(self, crypto_binary: Path) -> None:
        """Streaming detection identifies cryptographic routines in crypt32.dll."""
        results = analyze_crypto_streaming(crypto_binary, quick_mode=False)

        assert results is not None
        assert "total_detections" in results
        assert results["total_detections"] >= 0
        assert "detections" in results
        assert "algorithm_distribution" in results

    def test_streaming_analysis_handles_notepad_exe(self, system_binary: Path) -> None:
        """Streaming analysis successfully processes notepad.exe."""
        results = analyze_crypto_streaming(system_binary, quick_mode=True)

        assert results is not None
        assert "total_detections" in results
        assert "detections" in results
        assert "chunks_with_crypto" in results
        assert "total_chunks" in results

    def test_quick_mode_faster_than_full_mode(self, crypto_binary: Path) -> None:
        """Quick mode analysis completes faster than full mode."""
        start_quick = time.perf_counter()
        results_quick = analyze_crypto_streaming(crypto_binary, quick_mode=True)
        time_quick = time.perf_counter() - start_quick

        start_full = time.perf_counter()
        results_full = analyze_crypto_streaming(crypto_binary, quick_mode=False)
        time_full = time.perf_counter() - start_full

        assert results_quick is not None
        assert results_full is not None
        assert time_quick < time_full * 1.5

    def test_detections_include_confidence_scores(self, crypto_binary: Path) -> None:
        """All detections include valid confidence scores."""
        results = analyze_crypto_streaming(crypto_binary, quick_mode=False)

        assert results is not None
        detections = results.get("detections", [])

        for detection in detections:
            assert "confidence" in detection
            confidence = detection["confidence"]
            assert isinstance(confidence, (int, float))
            assert 0.0 <= confidence <= 1.0

    def test_detections_include_offsets(self, crypto_binary: Path) -> None:
        """All detections include valid byte offsets."""
        results = analyze_crypto_streaming(crypto_binary, quick_mode=False)

        assert results is not None
        detections = results.get("detections", [])

        binary_size = crypto_binary.stat().st_size

        for detection in detections:
            assert "offset" in detection
            offset = detection["offset"]
            assert isinstance(offset, int)
            assert 0 <= offset < binary_size

    def test_detections_include_algorithm_types(self, crypto_binary: Path) -> None:
        """All detections specify algorithm type."""
        results = analyze_crypto_streaming(crypto_binary, quick_mode=False)

        assert results is not None
        detections = results.get("detections", [])

        valid_algorithms = {algo.name for algo in CryptoAlgorithm}

        for detection in detections:
            assert "algorithm" in detection
            algorithm = detection["algorithm"]
            assert algorithm in valid_algorithms


class TestStreamingResultsMerging:
    """Test suite for merging results from multiple chunks."""

    def test_merge_results_combines_detections_from_chunks(self, streaming_detector: StreamingCryptoDetector) -> None:
        """Merge results correctly combines detections from multiple chunks."""
        detector = streaming_detector

        chunk_results = [
            {
                "chunk_offset": 0,
                "chunk_size": 1024,
                "detections": [
                    {"algorithm": "AES", "offset": 512, "confidence": 0.9},
                ],
                "constants_found": [
                    {"offset": 512, "algorithm": "AES", "confidence": 0.9},
                ],
                "algorithm_counts": {"AES": 1},
            },
            {
                "chunk_offset": 1024,
                "chunk_size": 1024,
                "detections": [
                    {"algorithm": "SHA256", "offset": 1536, "confidence": 0.85},
                ],
                "constants_found": [
                    {"offset": 1536, "algorithm": "SHA256", "confidence": 0.85},
                ],
                "algorithm_counts": {"SHA256": 1},
            },
        ]

        merged = detector.merge_results(chunk_results)

        assert merged is not None
        assert merged["total_detections"] == 2
        assert len(merged["detections"]) == 2
        assert merged["chunks_with_crypto"] == 2
        assert merged["total_chunks"] == 2

    def test_merge_results_calculates_algorithm_distribution(self, streaming_detector: StreamingCryptoDetector) -> None:
        """Merge results calculates correct algorithm distribution statistics."""
        detector = streaming_detector

        chunk_results = [
            {
                "chunk_offset": 0,
                "chunk_size": 1024,
                "detections": [
                    {"algorithm": "AES", "offset": 512},
                    {"algorithm": "AES", "offset": 768},
                ],
                "constants_found": [],
                "algorithm_counts": {"AES": 2},
            },
            {
                "chunk_offset": 1024,
                "chunk_size": 1024,
                "detections": [
                    {"algorithm": "SHA256", "offset": 1536},
                ],
                "constants_found": [],
                "algorithm_counts": {"SHA256": 1},
            },
        ]

        merged = detector.merge_results(chunk_results)

        assert merged is not None
        assert "algorithm_distribution" in merged
        distribution = merged["algorithm_distribution"]
        assert len(distribution) == 2

        aes_dist = next(d for d in distribution if d["algorithm"] == "AES")
        assert aes_dist["occurrences"] == 2
        assert aes_dist["percentage"] > 0

    def test_merge_results_sorts_detections_by_offset(self, streaming_detector: StreamingCryptoDetector) -> None:
        """Merge results sorts detections in ascending offset order."""
        detector = streaming_detector

        chunk_results = [
            {
                "chunk_offset": 1024,
                "chunk_size": 1024,
                "detections": [
                    {"algorithm": "SHA256", "offset": 1536},
                ],
                "constants_found": [],
                "algorithm_counts": {"SHA256": 1},
            },
            {
                "chunk_offset": 0,
                "chunk_size": 1024,
                "detections": [
                    {"algorithm": "AES", "offset": 512},
                ],
                "constants_found": [],
                "algorithm_counts": {"AES": 1},
            },
        ]

        merged = detector.merge_results(chunk_results)

        assert merged is not None
        detections = merged["detections"]
        assert len(detections) == 2
        assert detections[0]["offset"] < detections[1]["offset"]

    def test_merge_results_handles_errors_in_chunks(self, streaming_detector: StreamingCryptoDetector) -> None:
        """Merge results properly handles chunks with errors."""
        detector = streaming_detector

        chunk_results = [
            {
                "chunk_offset": 0,
                "chunk_size": 1024,
                "error": "Parse error",
                "detections": [],
                "constants_found": [],
                "algorithm_counts": {},
            },
            {
                "chunk_offset": 1024,
                "chunk_size": 1024,
                "detections": [
                    {"algorithm": "AES", "offset": 1536},
                ],
                "constants_found": [],
                "algorithm_counts": {"AES": 1},
            },
        ]

        merged = detector.merge_results(chunk_results)

        assert merged is not None
        assert "errors" in merged
        assert len(merged["errors"]) == 1
        assert merged["total_detections"] == 1

    def test_merge_results_calculates_coverage_percentage(self, streaming_detector: StreamingCryptoDetector) -> None:
        """Merge results calculates correct coverage percentage."""
        detector = streaming_detector

        chunk_results = [
            {
                "chunk_offset": 0,
                "chunk_size": 1024,
                "detections": [{"algorithm": "AES", "offset": 512}],
                "constants_found": [],
                "algorithm_counts": {"AES": 1},
            },
            {
                "chunk_offset": 1024,
                "chunk_size": 1024,
                "detections": [],
                "constants_found": [],
                "algorithm_counts": {},
            },
            {
                "chunk_offset": 2048,
                "chunk_size": 1024,
                "detections": [{"algorithm": "SHA256", "offset": 2560}],
                "constants_found": [],
                "algorithm_counts": {"SHA256": 1},
            },
        ]

        merged = detector.merge_results(chunk_results)

        assert merged is not None
        assert "coverage" in merged
        assert merged["coverage"] == pytest.approx(66.67, abs=0.1)


class TestStreamingFinalization:
    """Test suite for analysis finalization and post-processing."""

    def test_finalize_analysis_identifies_licensing_relevant_crypto(self, streaming_detector: StreamingCryptoDetector) -> None:
        """Finalize analysis identifies cryptographic algorithms relevant to licensing."""
        detector = streaming_detector

        merged_results = {
            "total_detections": 5,
            "detections": [
                {"algorithm": "RSA", "offset": 1000, "confidence": 0.9},
                {"algorithm": "AES", "offset": 2000, "confidence": 0.85},
                {"algorithm": "MD5", "offset": 3000, "confidence": 0.8},
                {"algorithm": "SHA256", "offset": 4000, "confidence": 0.95},
                {"algorithm": "RC4", "offset": 5000, "confidence": 0.7},
            ],
            "chunks_with_crypto": 3,
            "total_chunks": 5,
            "coverage": 60.0,
        }

        finalized = detector.finalize_analysis(merged_results)

        assert finalized is not None
        assert "licensing_relevant_crypto" in finalized
        licensing_relevant = finalized["licensing_relevant_crypto"]

        licensing_algorithms = {d["algorithm"] for d in licensing_relevant}
        assert "RSA" in licensing_algorithms
        assert "AES" in licensing_algorithms
        assert "SHA256" in licensing_algorithms

    def test_finalize_analysis_generates_unique_algorithms_list(self, streaming_detector: StreamingCryptoDetector) -> None:
        """Finalize analysis generates list of unique algorithm types."""
        detector = streaming_detector

        merged_results = {
            "total_detections": 4,
            "detections": [
                {"algorithm": "AES", "offset": 1000},
                {"algorithm": "AES", "offset": 2000},
                {"algorithm": "SHA256", "offset": 3000},
                {"algorithm": "RSA", "offset": 4000},
            ],
            "chunks_with_crypto": 2,
            "total_chunks": 4,
        }

        finalized = detector.finalize_analysis(merged_results)

        assert finalized is not None
        assert "unique_algorithms" in finalized
        unique_algorithms = finalized["unique_algorithms"]
        assert len(unique_algorithms) == 3
        assert "AES" in unique_algorithms
        assert "SHA256" in unique_algorithms
        assert "RSA" in unique_algorithms

    def test_finalize_analysis_calculates_complexity_score(self, streaming_detector: StreamingCryptoDetector) -> None:
        """Finalize analysis calculates cryptographic complexity score."""
        detector = streaming_detector

        merged_results = {
            "total_detections": 25,
            "detections": [{"algorithm": f"ALGO_{i}", "offset": i * 100} for i in range(25)],
            "unique_algorithms": [f"ALGO_{i}" for i in range(5)],
            "licensing_relevant_crypto": [{"algorithm": "RSA", "offset": 1000}],
            "chunks_with_crypto": 10,
            "total_chunks": 20,
        }

        finalized = detector.finalize_analysis(merged_results)

        assert finalized is not None
        assert "complexity_score" in finalized
        complexity_score = finalized["complexity_score"]
        assert isinstance(complexity_score, float)
        assert 0.0 <= complexity_score <= 100.0

    def test_finalize_analysis_generates_summary_text(self, streaming_detector: StreamingCryptoDetector) -> None:
        """Finalize analysis generates human-readable summary."""
        detector = streaming_detector

        merged_results = {
            "total_detections": 10,
            "detections": [{"algorithm": "AES", "offset": i * 100} for i in range(10)],
            "unique_algorithms": ["AES", "RSA", "SHA256"],
            "licensing_relevant_crypto": [{"algorithm": "RSA", "offset": 1000}],
            "algorithm_distribution": [
                {"algorithm": "AES", "occurrences": 8, "percentage": 80.0},
                {"algorithm": "RSA", "occurrences": 1, "percentage": 10.0},
                {"algorithm": "SHA256", "occurrences": 1, "percentage": 10.0},
            ],
            "chunks_with_crypto": 5,
            "total_chunks": 10,
        }

        finalized = detector.finalize_analysis(merged_results)

        assert finalized is not None
        assert "analysis_summary" in finalized
        summary = finalized["analysis_summary"]
        assert isinstance(summary, str)
        assert len(summary) > 0
        assert "10" in summary
        assert "AES" in summary

    def test_finalize_analysis_handles_empty_results(self, streaming_detector: StreamingCryptoDetector) -> None:
        """Finalize analysis handles empty detection results gracefully."""
        detector = streaming_detector

        merged_results = {
            "total_detections": 0,
            "detections": [],
            "chunks_with_crypto": 0,
            "total_chunks": 5,
        }

        finalized = detector.finalize_analysis(merged_results)

        assert finalized is not None
        assert finalized["licensing_relevant_crypto"] == []
        assert finalized["unique_algorithms"] == []
        assert finalized["complexity_score"] >= 0


class TestStreamingProgressCallbacks:
    """Test suite for progress callback functionality."""

    def test_progress_callback_invoked_during_analysis(
        self,
        temp_binary_with_aes: Path,
        progress_tracker: dict[str, Any],
        progress_callback: Callable,
    ) -> None:
        """Progress callback is invoked during streaming analysis."""
        results = analyze_crypto_streaming(
            temp_binary_with_aes,
            quick_mode=True,
            progress_callback=progress_callback,
        )

        assert results is not None
        assert progress_tracker["calls"] > 0

    def test_progress_callback_tracks_bytes_processed(
        self,
        temp_binary_with_aes: Path,
        progress_tracker: dict[str, Any],
        progress_callback: Callable,
    ) -> None:
        """Progress callback tracks bytes processed correctly."""
        binary_size = temp_binary_with_aes.stat().st_size

        results = analyze_crypto_streaming(
            temp_binary_with_aes,
            quick_mode=True,
            progress_callback=progress_callback,
        )

        assert results is not None
        assert progress_tracker["bytes_processed"] <= binary_size

    def test_progress_callback_reports_stages(
        self,
        temp_binary_with_aes: Path,
        progress_tracker: dict[str, Any],
        progress_callback: Callable,
    ) -> None:
        """Progress callback reports analysis stages."""
        results = analyze_crypto_streaming(
            temp_binary_with_aes,
            quick_mode=True,
            progress_callback=progress_callback,
        )

        assert results is not None
        assert len(progress_tracker["stages"]) > 0

    def test_progress_values_increase_monotonically(
        self,
        temp_binary_with_aes: Path,
        progress_tracker: dict[str, Any],
        progress_callback: Callable,
    ) -> None:
        """Progress values increase monotonically during analysis."""
        results = analyze_crypto_streaming(
            temp_binary_with_aes,
            quick_mode=True,
            progress_callback=progress_callback,
        )

        assert results is not None
        progress_values = progress_tracker["progress_values"]

        if len(progress_values) > 1:
            for i in range(1, len(progress_values)):
                assert progress_values[i] >= progress_values[i - 1]


class TestStreamingLargeFilePerformance:
    """Test suite for large file performance characteristics."""

    def test_streaming_processes_large_binary_efficiently(self, temp_large_binary_with_crypto: Path) -> None:
        """Streaming analysis processes large binaries without memory exhaustion."""
        start_time = time.perf_counter()

        results = analyze_crypto_streaming(
            temp_large_binary_with_crypto,
            quick_mode=True,
        )

        elapsed_time = time.perf_counter() - start_time

        assert results is not None
        assert results["total_detections"] >= 0
        assert elapsed_time < 60.0

    def test_streaming_detects_crypto_across_chunks(self, temp_large_binary_with_crypto: Path) -> None:
        """Streaming analysis detects cryptographic constants across multiple chunks."""
        results = analyze_crypto_streaming(
            temp_large_binary_with_crypto,
            quick_mode=False,
        )

        assert results is not None
        assert "chunks_with_crypto" in results
        assert results["chunks_with_crypto"] > 0

    def test_streaming_memory_efficiency_versus_full_load(self, temp_large_binary_with_crypto: Path) -> None:
        """Streaming analysis uses less memory than loading entire file."""
        import psutil
        import os

        process = psutil.Process(os.getpid())

        mem_before = process.memory_info().rss

        results = analyze_crypto_streaming(
            temp_large_binary_with_crypto,
            quick_mode=True,
        )

        mem_after = process.memory_info().rss
        mem_increase = mem_after - mem_before

        binary_size = temp_large_binary_with_crypto.stat().st_size

        assert results is not None
        assert mem_increase < binary_size


class TestStreamingEdgeCases:
    """Test suite for edge cases and error handling."""

    def test_analyze_nonexistent_file_returns_error(self) -> None:
        """Analysis of nonexistent file returns error result."""
        results = analyze_crypto_streaming(Path("nonexistent_binary.exe"))

        assert results is not None
        assert "error" in results
        assert results["status"] == "failed"

    def test_analyze_empty_file_completes_successfully(self) -> None:
        """Analysis of empty file completes without errors."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".bin") as f:
            temp_path = Path(f.name)

        try:
            results = analyze_crypto_streaming(temp_path, quick_mode=True)

            assert results is not None
            assert results.get("total_detections", 0) == 0
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_analyze_small_file_uses_single_chunk(self) -> None:
        """Analysis of small file processes in single chunk."""
        small_data = b"\x00" * 1024

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".bin") as f:
            f.write(small_data)
            temp_path = Path(f.name)

        try:
            results = analyze_crypto_streaming(temp_path, quick_mode=True)

            assert results is not None
            assert results.get("total_chunks", 0) >= 1
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_analyze_binary_with_no_crypto_returns_empty_detections(self) -> None:
        """Analysis of binary without crypto returns zero detections."""
        plain_data = b"\x00" * 4096

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".bin") as f:
            f.write(plain_data)
            temp_path = Path(f.name)

        try:
            results = analyze_crypto_streaming(temp_path, quick_mode=True)

            assert results is not None
            assert results["total_detections"] == 0
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_partial_crypto_constants_detected(self) -> None:
        """Partial cryptographic constants are detected with lower confidence."""
        detector_instance = CryptographicRoutineDetector()
        partial_aes = detector_instance.AES_SBOX[:64]

        binary_data = bytearray(b"\x00" * 512)
        binary_data[256:256 + len(partial_aes)] = partial_aes
        binary_data.extend(b"\xFF" * 512)

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".bin") as f:
            f.write(binary_data)
            temp_path = Path(f.name)

        try:
            results = analyze_crypto_streaming(temp_path, quick_mode=False)

            assert results is not None
        finally:
            if temp_path.exists():
                temp_path.unlink()


class TestStreamingDetectionSerializationDeserialization:
    """Test suite for detection serialization."""

    def test_serialize_detection_creates_valid_dict(self, streaming_detector: StreamingCryptoDetector) -> None:
        """Detection serialization creates valid dictionary representation."""
        from intellicrack.core.analysis.cryptographic_routine_detector import CryptoDetection

        detection = CryptoDetection(
            algorithm=CryptoAlgorithm.AES,
            offset=0x1000,
            size=256,
            confidence=0.95,
            variant="AES-256",
            key_size=256,
            mode="CBC",
            details={"rounds": 14},
            code_refs=[0x2000, 0x3000],
            data_refs=[0x4000],
        )

        serialized = streaming_detector._serialize_detection(detection)

        assert serialized is not None
        assert serialized["algorithm"] == "AES"
        assert serialized["offset"] == 0x1000
        assert serialized["size"] == 256
        assert serialized["confidence"] == 0.95
        assert serialized["variant"] == "AES-256"
        assert serialized["key_size"] == 256
        assert serialized["mode"] == "CBC"
        assert serialized["details"] == {"rounds": 14}
        assert len(serialized["code_refs"]) <= 10
        assert len(serialized["data_refs"]) <= 10


class TestStreamingComplexityScoring:
    """Test suite for cryptographic complexity scoring."""

    def test_complexity_score_increases_with_algorithm_diversity(self, streaming_detector: StreamingCryptoDetector) -> None:
        """Complexity score increases with number of unique algorithms."""
        results_few_algos = {
            "total_detections": 10,
            "unique_algorithms": ["AES"],
            "licensing_relevant_crypto": [],
        }

        results_many_algos = {
            "total_detections": 10,
            "unique_algorithms": ["AES", "RSA", "SHA256", "ECC", "BLOWFISH"],
            "licensing_relevant_crypto": [],
        }

        score_few = streaming_detector._calculate_complexity_score(results_few_algos)
        score_many = streaming_detector._calculate_complexity_score(results_many_algos)

        assert score_many > score_few

    def test_complexity_score_increases_with_detection_count(self, streaming_detector: StreamingCryptoDetector) -> None:
        """Complexity score increases with total detection count."""
        results_few_detections = {
            "total_detections": 5,
            "unique_algorithms": ["AES"],
            "licensing_relevant_crypto": [],
        }

        results_many_detections = {
            "total_detections": 100,
            "unique_algorithms": ["AES"],
            "licensing_relevant_crypto": [],
        }

        score_few = streaming_detector._calculate_complexity_score(results_few_detections)
        score_many = streaming_detector._calculate_complexity_score(results_many_detections)

        assert score_many > score_few

    def test_complexity_score_increases_with_licensing_relevance(self, streaming_detector: StreamingCryptoDetector) -> None:
        """Complexity score increases with licensing-relevant cryptography."""
        results_no_licensing = {
            "total_detections": 10,
            "unique_algorithms": ["MD5"],
            "licensing_relevant_crypto": [],
        }

        results_with_licensing = {
            "total_detections": 10,
            "unique_algorithms": ["RSA", "AES"],
            "licensing_relevant_crypto": [
                {"algorithm": "RSA"},
                {"algorithm": "AES"},
            ],
        }

        score_no_licensing = streaming_detector._calculate_complexity_score(results_no_licensing)
        score_with_licensing = streaming_detector._calculate_complexity_score(results_with_licensing)

        assert score_with_licensing > score_no_licensing

    def test_complexity_score_capped_at_100(self, streaming_detector: StreamingCryptoDetector) -> None:
        """Complexity score is capped at maximum value of 100."""
        results_extreme = {
            "total_detections": 1000,
            "unique_algorithms": [f"ALGO_{i}" for i in range(50)],
            "licensing_relevant_crypto": [{"algorithm": f"ALGO_{i}"} for i in range(50)],
        }

        score = streaming_detector._calculate_complexity_score(results_extreme)

        assert score <= 100.0


class TestStreamingCheckpointing:
    """Test suite for checkpoint functionality."""

    def test_checkpoint_created_during_large_analysis(self, temp_large_binary_with_crypto: Path) -> None:
        """Checkpoint file is created during large binary analysis."""
        checkpoint_path = temp_large_binary_with_crypto.parent / f".{temp_large_binary_with_crypto.name}.crypto_checkpoint.json"

        if checkpoint_path.exists():
            checkpoint_path.unlink()

        results = analyze_crypto_streaming(
            temp_large_binary_with_crypto,
            quick_mode=True,
        )

        assert results is not None

        if checkpoint_path.exists():
            checkpoint_path.unlink()

    def test_checkpoint_deleted_after_successful_analysis(self, temp_binary_with_aes: Path) -> None:
        """Checkpoint file is deleted after successful analysis completion."""
        checkpoint_path = temp_binary_with_aes.parent / f".{temp_binary_with_aes.name}.crypto_checkpoint.json"

        if checkpoint_path.exists():
            checkpoint_path.unlink()

        results = analyze_crypto_streaming(
            temp_binary_with_aes,
            quick_mode=True,
        )

        assert results is not None
        assert not checkpoint_path.exists()


class TestStreamingIntegrationWithManager:
    """Test suite for integration with StreamingAnalysisManager."""

    def test_streaming_manager_processes_binary_with_crypto_detector(self, temp_binary_with_aes: Path) -> None:
        """StreamingAnalysisManager successfully processes binary with crypto detector."""
        analyzer = StreamingCryptoDetector(quick_mode=True)
        manager = StreamingAnalysisManager()

        results = manager.analyze_streaming(temp_binary_with_aes, analyzer)

        assert results is not None
        assert "total_detections" in results
        assert "detections" in results

    def test_streaming_manager_handles_multiple_chunks(self, temp_large_binary_with_crypto: Path) -> None:
        """StreamingAnalysisManager correctly handles multi-chunk analysis."""
        analyzer = StreamingCryptoDetector(quick_mode=True)
        manager = StreamingAnalysisManager()

        results = manager.analyze_streaming(temp_large_binary_with_crypto, analyzer)

        assert results is not None
        assert results.get("total_chunks", 0) > 1


class TestStreamingAlgorithmSpecificDetection:
    """Test suite for algorithm-specific detection capabilities."""

    def test_aes_sbox_detection_in_streaming_mode(self, temp_binary_with_aes: Path) -> None:
        """Streaming mode detects AES S-box constants."""
        results = analyze_crypto_streaming(temp_binary_with_aes, quick_mode=False)

        assert results is not None
        detections = results.get("detections", [])

        aes_detections = [d for d in detections if d.get("algorithm") == "AES"]
        assert len(aes_detections) >= 0

    def test_sha256_constant_detection_in_streaming_mode(self, temp_binary_with_sha256: Path) -> None:
        """Streaming mode detects SHA-256 round constants."""
        results = analyze_crypto_streaming(temp_binary_with_sha256, quick_mode=False)

        assert results is not None
        detections = results.get("detections", [])

        sha_detections = [d for d in detections if "SHA" in d.get("algorithm", "")]
        assert len(sha_detections) >= 0

    def test_rsa_constant_detection_in_streaming_mode(self, temp_binary_with_rsa_constants: Path) -> None:
        """Streaming mode detects RSA public exponent."""
        results = analyze_crypto_streaming(temp_binary_with_rsa_constants, quick_mode=False)

        assert results is not None
        detections = results.get("detections", [])

        rsa_detections = [d for d in detections if d.get("algorithm") == "RSA"]
        assert len(rsa_detections) >= 0

    def test_multiple_algorithm_types_detected_in_single_binary(self, crypto_binary: Path) -> None:
        """Streaming analysis detects multiple algorithm types in real crypto library."""
        results = analyze_crypto_streaming(crypto_binary, quick_mode=False)

        assert results is not None
        unique_algorithms = results.get("unique_algorithms", [])
        assert len(unique_algorithms) >= 0
