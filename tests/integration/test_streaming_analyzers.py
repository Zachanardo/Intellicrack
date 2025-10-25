"""Integration tests for streaming analyzers.

Tests real-world scenarios with actual binary analysis on large files.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""


import pytest

try:
    from intellicrack.core.analysis.streaming_crypto_detector import (
        StreamingCryptoDetector,
        analyze_crypto_streaming,
    )
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

from intellicrack.core.analysis.streaming_entropy_analyzer import (
    StreamingEntropyAnalyzer,
    analyze_entropy_streaming,
)
from intellicrack.core.processing.streaming_analysis_manager import StreamingAnalysisManager

try:
    import yara
    from intellicrack.core.analysis.streaming_yara_scanner import (
        StreamingYaraScanner,
        scan_binary_streaming,
    )

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class TestStreamingCryptoDetector:
    """Integration tests for streaming cryptographic detection."""

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Capstone not available")
    def test_crypto_detector_basic(self, tmp_path):
        """Test basic crypto detection in streaming mode."""
        test_file = tmp_path / "crypto_test.bin"

        aes_sbox = bytes(
            [
                0x63,
                0x7C,
                0x77,
                0x7B,
                0xF2,
                0x6B,
                0x6F,
                0xC5,
                0x30,
                0x01,
                0x67,
                0x2B,
                0xFE,
                0xD7,
                0xAB,
                0x76,
            ]
        )

        test_data = b"\x00" * 10000 + aes_sbox + b"\x00" * 10000

        test_file.write_bytes(test_data)

        results = analyze_crypto_streaming(test_file, quick_mode=True)

        assert results["status"] == "completed"
        assert results["streaming_mode"] is True

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Capstone not available")
    def test_crypto_detector_chunk_processing(self, tmp_path):
        """Test crypto detection across chunk boundaries."""
        test_file = tmp_path / "crypto_chunks.bin"

        detector = StreamingCryptoDetector(quick_mode=True)
        manager = StreamingAnalysisManager()

        crypto_pattern = b"\x01\x00\x01\x00"

        chunk_size = 1000
        test_data = b"X" * (chunk_size - 10) + crypto_pattern + b"Y" * (chunk_size + 10)

        test_file.write_bytes(test_data)

        results = manager.analyze_streaming(test_file, detector)

        assert results["status"] == "completed"

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Capstone not available")
    def test_crypto_detector_large_file(self, tmp_path):
        """Test crypto detection on simulated large file."""
        test_file = tmp_path / "large_crypto.bin"

        with open(test_file, "wb") as f:
            for i in range(100):
                chunk = bytes([i % 256]) * 10000
                f.write(chunk)

        results = analyze_crypto_streaming(test_file, quick_mode=True)

        assert results["status"] == "completed"
        assert results["file_size"] > 900_000


class TestStreamingEntropyAnalyzer:
    """Integration tests for streaming entropy analysis."""

    def test_entropy_analyzer_basic(self, tmp_path):
        """Test basic entropy analysis in streaming mode."""
        test_file = tmp_path / "entropy_test.bin"

        low_entropy = b"\x00" * 5000
        high_entropy = bytes(range(256)) * 20

        test_data = low_entropy + high_entropy + low_entropy

        test_file.write_bytes(test_data)

        results = analyze_entropy_streaming(test_file, window_size=1000, stride=500)

        assert results["status"] == "completed"
        assert results["streaming_mode"] is True
        assert "global_entropy" in results
        assert "entropy_windows" in results

    def test_entropy_analyzer_classifications(self, tmp_path):
        """Test entropy-based section classification."""
        test_file = tmp_path / "classified.bin"

        padding = b"\x00" * 2000
        text = b"The quick brown fox jumps over the lazy dog. " * 50
        code = bytes(range(256)) * 10

        test_data = padding + text + code

        test_file.write_bytes(test_data)

        analyzer = StreamingEntropyAnalyzer(window_size=1000, stride=500)
        manager = StreamingAnalysisManager()

        results = manager.analyze_streaming(test_file, analyzer)

        assert results["status"] == "completed"
        assert "classification_distribution" in results

    def test_entropy_analyzer_high_entropy_detection(self, tmp_path):
        """Test detection of high-entropy regions."""
        test_file = tmp_path / "high_entropy.bin"

        import random

        random.seed(42)

        normal_data = bytes([random.randint(0, 100) for _ in range(5000)])  # noqa: S311
        high_entropy_data = bytes([random.randint(0, 255) for _ in range(5000)])  # noqa: S311

        test_data = normal_data + high_entropy_data + normal_data

        test_file.write_bytes(test_data)

        results = analyze_entropy_streaming(test_file)

        assert results["status"] == "completed"
        assert "high_entropy_regions" in results

    def test_entropy_analyzer_protection_detection(self, tmp_path):
        """Test detection of packing/encryption indicators."""
        test_file = tmp_path / "protected.bin"

        import random

        random.seed(123)

        encrypted_like = bytes([random.randint(0, 255) for _ in range(20000)])  # noqa: S311

        test_file.write_bytes(encrypted_like)

        results = analyze_entropy_streaming(test_file)

        assert results["status"] == "completed"
        assert "is_packed" in results
        assert "is_encrypted" in results
        assert "protection_indicators" in results


@pytest.mark.skipif(not YARA_AVAILABLE, reason="YARA not available")
class TestStreamingYaraScanner:
    """Integration tests for streaming YARA scanner."""

    @pytest.mark.skipif(not YARA_AVAILABLE, reason="YARA not available")
    def test_yara_scanner_basic(self, tmp_path):
        """Test basic YARA scanning in streaming mode."""
        test_file = tmp_path / "yara_test.bin"

        test_data = b"This is a license key validation routine. " * 100 + b"X" * 10000

        test_file.write_bytes(test_data)

        results = scan_binary_streaming(test_file)

        assert results["status"] == "completed"
        assert results["streaming_mode"] is True

    def test_yara_scanner_custom_rules(self, tmp_path):
        """Test YARA scanner with custom rules."""
        test_file = tmp_path / "custom_yara.bin"

        test_data = b"TESTPATTERN" + b"\x00" * 5000 + b"TESTPATTERN" + b"\x00" * 5000

        test_file.write_bytes(test_data)

        custom_rules = """
        rule TestPattern {
            meta:
                description = "Test pattern detection"
            strings:
                $pattern = "TESTPATTERN"
            condition:
                $pattern
        }
        """

        results = scan_binary_streaming(test_file, rules_source=custom_rules)

        assert results["status"] == "completed"

    def test_yara_scanner_chunk_boundaries(self, tmp_path):
        """Test YARA pattern matching across chunk boundaries."""
        test_file = tmp_path / "boundary_test.bin"

        scanner = StreamingYaraScanner(rules_source="rule Test { strings: $a = \"BOUNDARY\" condition: $a }")

        manager = StreamingAnalysisManager()

        pattern_at_boundary = b"X" * 4990 + b"BOUNDARY" + b"Y" * 5000

        test_file.write_bytes(pattern_at_boundary)

        results = manager.analyze_streaming(test_file, scanner)

        assert results["status"] == "completed"


class TestStreamingIntegration:
    """Integration tests combining multiple streaming analyzers."""

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Capstone not available")
    def test_combined_analysis(self, tmp_path):
        """Test running multiple streaming analyzers on same file."""
        test_file = tmp_path / "combined.bin"

        complex_data = (
            b"License validation routine: "
            + bytes(range(256)) * 20
            + b"RSA key: "
            + b"\x30\x82\x01\x22\x30\x0D"
            + b"\x00" * 5000
        )

        test_file.write_bytes(complex_data)

        entropy_results = analyze_entropy_streaming(test_file)
        crypto_results = analyze_crypto_streaming(test_file, quick_mode=True)

        assert entropy_results["status"] == "completed"
        assert crypto_results["status"] == "completed"

        assert "global_entropy" in entropy_results
        assert "total_detections" in crypto_results

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Capstone not available")
    def test_large_file_all_analyzers(self, tmp_path):
        """Test all streaming analyzers on large simulated binary."""
        test_file = tmp_path / "large_combined.bin"

        with open(test_file, "wb") as f:
            for i in range(200):
                chunk_data = bytes([(i * 13 + j) % 256 for j in range(5000)])
                f.write(chunk_data)

        file_size = test_file.stat().st_size
        assert file_size > 900_000

        entropy_results = analyze_entropy_streaming(test_file)
        crypto_results = analyze_crypto_streaming(test_file, quick_mode=True)

        assert entropy_results["status"] == "completed"
        assert crypto_results["status"] == "completed"

        assert entropy_results["file_size"] == file_size
        assert crypto_results["file_size"] == file_size


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
