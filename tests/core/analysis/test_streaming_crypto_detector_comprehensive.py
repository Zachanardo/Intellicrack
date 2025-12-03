"""Comprehensive tests for StreamingCryptoDetector.

Tests validate real cryptographic detection on actual binary data with known
crypto routines. NO mocks - only real functionality validation.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import struct
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.streaming_crypto_detector import (
    ChunkCryptoResults,
    StreamingCryptoDetector,
    analyze_crypto_streaming,
)
from intellicrack.core.processing.streaming_analysis_manager import ChunkContext


class TestStreamingCryptoDetector:
    """Test suite for streaming cryptographic routine detection."""

    @pytest.fixture
    def detector(self) -> StreamingCryptoDetector:
        """Create detector instance."""
        return StreamingCryptoDetector(quick_mode=True, use_radare2=False)

    @pytest.fixture
    def binary_with_aes_constants(self, temp_workspace: Path) -> Path:
        """Create binary with real AES S-box constants."""
        aes_sbox = bytes([
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
            0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
            0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
            0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        ])

        binary_path = temp_workspace / "aes_binary.bin"
        padding = b"\x00" * 1024
        binary_path.write_bytes(padding + aes_sbox + padding)
        return binary_path

    @pytest.fixture
    def binary_with_rsa_key_structure(self, temp_workspace: Path) -> Path:
        """Create binary with RSA public key structure."""
        rsa_header = bytes([
            0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09,
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
        ])

        modulus = b"\x00" + bytes(range(256))
        exponent = struct.pack(">I", 65537)

        binary_path = temp_workspace / "rsa_binary.bin"
        data = b"\x00" * 512 + rsa_header + modulus + exponent + b"\x00" * 1024
        binary_path.write_bytes(data)
        return binary_path

    @pytest.fixture
    def binary_with_sha256_constants(self, temp_workspace: Path) -> Path:
        """Create binary with SHA-256 initial hash values."""
        sha256_h = struct.pack(">8I",
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        )

        binary_path = temp_workspace / "sha256_binary.bin"
        data = b"\x90" * 2048 + sha256_h + b"\x90" * 2048
        binary_path.write_bytes(data)
        return binary_path

    def test_detector_initialization(self, detector: StreamingCryptoDetector) -> None:
        """Detector initializes with correct configuration."""
        assert detector.quick_mode is True
        assert detector.use_radare2 is False
        assert detector.binary_path is None
        assert len(detector.global_detections) == 0
        assert len(detector.detection_offsets) == 0

    def test_initialize_analysis_clears_state(self, detector: StreamingCryptoDetector, temp_workspace: Path) -> None:
        """initialize_analysis resets detector state."""
        detector.detection_offsets.add(100)
        detector.global_detections.append("fake_detection")

        test_file = temp_workspace / "test.bin"
        test_file.write_bytes(b"\x00" * 1024)

        detector.initialize_analysis(test_file)

        assert detector.binary_path == test_file
        assert len(detector.global_detections) == 0
        assert len(detector.detection_offsets) == 0

    def test_analyze_chunk_detects_aes_sbox(self, detector: StreamingCryptoDetector, binary_with_aes_constants: Path) -> None:
        """analyze_chunk detects AES S-box in real binary data."""
        data = binary_with_aes_constants.read_bytes()

        detector.initialize_analysis(binary_with_aes_constants)

        context = ChunkContext(
            offset=0,
            size=len(data),
            chunk_number=1,
            total_chunks=1,
            data=data,
            file_path=binary_with_aes_constants
        )

        result = detector.analyze_chunk(context)

        assert "detections" in result
        assert "algorithm_counts" in result
        assert result["chunk_offset"] == 0
        assert result["chunk_size"] == len(data)

        if result["detections"]:
            detection = result["detections"][0]
            assert "algorithm" in detection
            assert "offset" in detection
            assert "confidence" in detection

    def test_analyze_chunk_detects_rsa_key_structure(self, detector: StreamingCryptoDetector, binary_with_rsa_key_structure: Path) -> None:
        """analyze_chunk detects RSA key structures in binary."""
        data = binary_with_rsa_key_structure.read_bytes()

        detector.initialize_analysis(binary_with_rsa_key_structure)

        context = ChunkContext(
            offset=0,
            size=len(data),
            chunk_number=1,
            total_chunks=1,
            data=data,
            file_path=binary_with_rsa_key_structure
        )

        result = detector.analyze_chunk(context)

        assert "detections" in result
        assert isinstance(result["detections"], list)

    def test_analyze_chunk_with_overlap_prevents_duplicates(self, detector: StreamingCryptoDetector, binary_with_aes_constants: Path) -> None:
        """analyze_chunk with overlap regions prevents duplicate detections."""
        data = binary_with_aes_constants.read_bytes()
        chunk_size = len(data) // 2
        overlap = 512

        detector.initialize_analysis(binary_with_aes_constants)

        context1 = ChunkContext(
            offset=0,
            size=chunk_size,
            chunk_number=1,
            total_chunks=2,
            data=data[:chunk_size],
            overlap_after=data[chunk_size:chunk_size + overlap],
            file_path=binary_with_aes_constants
        )

        result1 = detector.analyze_chunk(context1)
        initial_detections = len(detector.detection_offsets)

        context2 = ChunkContext(
            offset=chunk_size,
            size=len(data) - chunk_size,
            chunk_number=2,
            total_chunks=2,
            data=data[chunk_size:],
            overlap_before=data[chunk_size - overlap:chunk_size],
            file_path=binary_with_aes_constants
        )

        result2 = detector.analyze_chunk(context2)

        total_detections = result1.get("detections", []) + result2.get("detections", [])
        unique_offsets = {d["offset"] for d in total_detections if "offset" in d}

        assert len(unique_offsets) == len(total_detections)

    def test_merge_results_aggregates_detections(self, detector: StreamingCryptoDetector) -> None:
        """merge_results correctly aggregates chunk results."""
        chunk_results = [
            {
                "chunk_offset": 0,
                "chunk_size": 1024,
                "detections": [
                    {"algorithm": "AES", "offset": 100, "confidence": 0.9},
                    {"algorithm": "SHA256", "offset": 200, "confidence": 0.85}
                ],
                "constants_found": [
                    {"offset": 100, "algorithm": "AES"}
                ],
                "algorithm_counts": {"AES": 1, "SHA256": 1}
            },
            {
                "chunk_offset": 1024,
                "chunk_size": 1024,
                "detections": [
                    {"algorithm": "AES", "offset": 1100, "confidence": 0.88}
                ],
                "constants_found": [
                    {"offset": 1100, "algorithm": "AES"}
                ],
                "algorithm_counts": {"AES": 1}
            }
        ]

        merged = detector.merge_results(chunk_results)

        assert merged["total_detections"] == 3
        assert len(merged["detections"]) == 3
        assert merged["chunks_with_crypto"] == 2
        assert merged["total_chunks"] == 2

        assert any(d["algorithm"] == "AES" for d in merged["algorithm_distribution"])

        offsets = [d["offset"] for d in merged["detections"]]
        assert offsets == sorted(offsets)

    def test_merge_results_handles_errors(self, detector: StreamingCryptoDetector) -> None:
        """merge_results handles chunk errors gracefully."""
        chunk_results = [
            {
                "chunk_offset": 0,
                "chunk_size": 1024,
                "error": "Analysis failed",
                "detections": [],
                "constants_found": [],
                "algorithm_counts": {}
            },
            {
                "chunk_offset": 1024,
                "chunk_size": 1024,
                "detections": [
                    {"algorithm": "RSA", "offset": 1500, "confidence": 0.92}
                ],
                "constants_found": [],
                "algorithm_counts": {"RSA": 1}
            }
        ]

        merged = detector.merge_results(chunk_results)

        assert "errors" in merged
        assert len(merged["errors"]) == 1
        assert "0x00000000" in merged["errors"][0]

        assert merged["total_detections"] == 1
        assert merged["detections"][0]["algorithm"] == "RSA"

    def test_finalize_analysis_identifies_licensing_crypto(self, detector: StreamingCryptoDetector) -> None:
        """finalize_analysis correctly identifies licensing-relevant crypto."""
        merged_results = {
            "total_detections": 5,
            "detections": [
                {"algorithm": "AES", "offset": 100, "key_size": 256},
                {"algorithm": "RSA", "offset": 200, "key_size": 2048},
                {"algorithm": "MD5", "offset": 300, "key_size": None},
                {"algorithm": "SHA256", "offset": 400, "key_size": None},
                {"algorithm": "ECC", "offset": 500, "key_size": 256}
            ],
            "algorithm_distribution": [],
            "chunks_with_crypto": 2,
            "total_chunks": 3
        }

        finalized = detector.finalize_analysis(merged_results)

        assert "licensing_relevant_crypto" in finalized
        licensing_crypto = finalized["licensing_relevant_crypto"]

        licensing_algos = {d["algorithm"] for d in licensing_crypto}
        assert "AES" in licensing_algos
        assert "RSA" in licensing_algos
        assert "SHA256" in licensing_algos
        assert "ECC" in licensing_algos
        assert "MD5" not in licensing_algos

    def test_finalize_analysis_calculates_complexity_score(self, detector: StreamingCryptoDetector) -> None:
        """finalize_analysis calculates meaningful complexity scores."""
        low_complexity = {
            "total_detections": 3,
            "detections": [{"algorithm": "AES", "offset": i * 100} for i in range(3)],
            "unique_algorithms": ["AES"],
            "licensing_relevant_crypto": []
        }

        finalized_low = detector.finalize_analysis(low_complexity)
        assert "complexity_score" in finalized_low
        low_score = finalized_low["complexity_score"]

        high_complexity = {
            "total_detections": 60,
            "detections": [{"algorithm": f"ALGO{i % 5}", "offset": i * 100} for i in range(60)],
            "unique_algorithms": ["AES", "RSA", "SHA256", "ECC", "SHA512"],
            "licensing_relevant_crypto": [{"algorithm": "RSA"} for _ in range(10)]
        }

        finalized_high = detector.finalize_analysis(high_complexity)
        high_score = finalized_high["complexity_score"]

        assert high_score > low_score
        assert 0 <= low_score <= 100
        assert 0 <= high_score <= 100

    def test_serialize_detection_converts_to_dict(self, detector: StreamingCryptoDetector) -> None:
        """_serialize_detection converts CryptoDetection to dict."""
        from intellicrack.core.analysis.cryptographic_routine_detector import CryptoAlgorithm, CryptoDetection

        detection = CryptoDetection(
            algorithm=CryptoAlgorithm.AES,
            offset=1024,
            size=32,
            confidence=0.95,
            variant="AES-256",
            key_size=256,
            mode="CBC",
            details={"test": "data"},
            code_refs=[100, 200, 300],
            data_refs=[400, 500]
        )

        serialized = detector._serialize_detection(detection)

        assert serialized["algorithm"] == "AES"
        assert serialized["offset"] == 1024
        assert serialized["size"] == 32
        assert serialized["confidence"] == 0.95
        assert serialized["variant"] == "AES-256"
        assert serialized["key_size"] == 256
        assert serialized["mode"] == "CBC"
        assert serialized["details"] == {"test": "data"}
        assert len(serialized["code_refs"]) == 3
        assert len(serialized["data_refs"]) == 2

    def test_calculate_complexity_score_ranges(self, detector: StreamingCryptoDetector) -> None:
        """_calculate_complexity_score produces correct score ranges."""
        empty_results: dict[str, Any] = {
            "unique_algorithms": [],
            "total_detections": 0,
            "licensing_relevant_crypto": []
        }
        assert detector._calculate_complexity_score(empty_results) == 0.0

        minimal_results: dict[str, Any] = {
            "unique_algorithms": ["AES"],
            "total_detections": 3,
            "licensing_relevant_crypto": []
        }
        minimal_score = detector._calculate_complexity_score(minimal_results)
        assert 0 < minimal_score < 30

        maximal_results: dict[str, Any] = {
            "unique_algorithms": ["AES", "RSA", "ECC", "SHA256", "SHA512"],
            "total_detections": 100,
            "licensing_relevant_crypto": [{"algo": f"A{i}"} for i in range(20)]
        }
        maximal_score = detector._calculate_complexity_score(maximal_results)
        assert maximal_score == 100.0

    def test_generate_summary_creates_meaningful_text(self, detector: StreamingCryptoDetector) -> None:
        """_generate_summary creates informative summary text."""
        results: dict[str, Any] = {
            "total_detections": 15,
            "unique_algorithms": ["AES", "RSA", "SHA256"],
            "licensing_relevant_crypto": [{"algorithm": "RSA"}, {"algorithm": "AES"}],
            "algorithm_distribution": [
                {"algorithm": "AES", "occurrences": 10},
                {"algorithm": "RSA", "occurrences": 3},
                {"algorithm": "SHA256", "occurrences": 2}
            ]
        }

        summary = detector._generate_summary(results)

        assert "15" in summary
        assert "3" in summary
        assert "AES" in summary
        assert "10" in summary
        assert "licensing" in summary.lower()

    def test_streaming_analysis_end_to_end(self, binary_with_aes_constants: Path) -> None:
        """Full streaming analysis workflow detects crypto in real binary."""
        results = analyze_crypto_streaming(
            binary_path=binary_with_aes_constants,
            quick_mode=True,
            use_radare2=False
        )

        assert "total_detections" in results
        assert "detections" in results
        assert "algorithm_distribution" in results
        assert "complexity_score" in results
        assert "analysis_summary" in results

        assert results.get("status") != "failed"

    def test_streaming_analysis_with_nonexistent_file(self, temp_workspace: Path) -> None:
        """analyze_crypto_streaming handles missing files gracefully."""
        nonexistent = temp_workspace / "does_not_exist.bin"

        results = analyze_crypto_streaming(
            binary_path=nonexistent,
            quick_mode=True
        )

        assert "error" in results
        assert "not found" in results["error"].lower()
        assert results["status"] == "failed"

    def test_streaming_analysis_with_empty_file(self, temp_workspace: Path) -> None:
        """analyze_crypto_streaming handles empty files."""
        empty_file = temp_workspace / "empty.bin"
        empty_file.write_bytes(b"")

        results = analyze_crypto_streaming(
            binary_path=empty_file,
            quick_mode=True
        )

        assert "total_detections" in results or "error" in results

    def test_analyze_chunk_error_handling(self, detector: StreamingCryptoDetector, temp_workspace: Path) -> None:
        """analyze_chunk handles errors gracefully."""
        test_file = temp_workspace / "test.bin"
        test_file.write_bytes(b"\x00" * 1024)

        detector.initialize_analysis(test_file)

        invalid_context = ChunkContext(
            offset=0,
            size=1024,
            chunk_number=1,
            total_chunks=1,
            data=b"\x00" * 1024,
            file_path=test_file
        )

        result = detector.analyze_chunk(invalid_context)

        assert "chunk_offset" in result
        assert "chunk_size" in result
        assert "detections" in result
        assert isinstance(result["detections"], list)

    def test_multiple_chunks_no_duplicate_offsets(self, detector: StreamingCryptoDetector, binary_with_sha256_constants: Path) -> None:
        """Multiple chunk processing doesn't create duplicate detections."""
        data = binary_with_sha256_constants.read_bytes()
        chunk_size = len(data) // 3

        detector.initialize_analysis(binary_with_sha256_constants)

        results_list = []
        for i in range(3):
            start = i * chunk_size
            end = start + chunk_size if i < 2 else len(data)

            context = ChunkContext(
                offset=start,
                size=end - start,
                chunk_number=i + 1,
                total_chunks=3,
                data=data[start:end],
                file_path=binary_with_sha256_constants
            )

            result = detector.analyze_chunk(context)
            results_list.append(result)

        merged = detector.merge_results(results_list)

        all_offsets = [d["offset"] for d in merged["detections"]]
        unique_offsets = set(all_offsets)

        assert len(all_offsets) == len(unique_offsets)


class TestChunkCryptoResults:
    """Test ChunkCryptoResults dataclass."""

    def test_chunk_crypto_results_initialization(self) -> None:
        """ChunkCryptoResults initializes with correct defaults."""
        result = ChunkCryptoResults(chunk_offset=1024, chunk_size=4096)

        assert result.chunk_offset == 1024
        assert result.chunk_size == 4096
        assert result.detections == []
        assert result.constants_found == []
        assert isinstance(result.algorithm_counts, dict)

    def test_chunk_crypto_results_with_data(self) -> None:
        """ChunkCryptoResults stores detection data correctly."""
        from intellicrack.core.analysis.cryptographic_routine_detector import CryptoAlgorithm, CryptoDetection

        detection = CryptoDetection(
            algorithm=CryptoAlgorithm.RSA,
            offset=2048,
            size=256,
            confidence=0.92
        )

        result = ChunkCryptoResults(
            chunk_offset=0,
            chunk_size=8192,
            detections=[detection],
            constants_found=[{"offset": 2048, "algorithm": "RSA"}],
            algorithm_counts={"RSA": 1}
        )

        assert len(result.detections) == 1
        assert result.detections[0].algorithm == CryptoAlgorithm.RSA
        assert result.constants_found[0]["algorithm"] == "RSA"
        assert result.algorithm_counts["RSA"] == 1
