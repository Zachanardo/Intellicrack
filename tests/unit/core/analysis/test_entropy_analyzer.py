"""Comprehensive test suite for entropy analysis module.

This test suite validates Shannon entropy calculations, packed/encrypted section
detection, and statistical analysis capabilities with mathematical precision
for defensive security research purposes.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import math
import os
import random
import struct
import tempfile
import unittest
from pathlib import Path

import pytest

from intellicrack.core.analysis.entropy_analyzer import EntropyAnalyzer


class TestEntropyCalculation(unittest.TestCase):
    """Test Shannon entropy calculation accuracy and mathematical correctness."""

    def setUp(self):
        """Initialize test environment."""
        self.analyzer = EntropyAnalyzer()

    def test_empty_data_entropy(self):
        """Test entropy of empty data is 0."""
        entropy = self.analyzer.calculate_entropy(b"")
        self.assertEqual(entropy, 0.0)

    def test_single_byte_entropy(self):
        """Test entropy of single repeated byte is 0."""
        data = b"\x00" * 1000
        entropy = self.analyzer.calculate_entropy(data)
        self.assertEqual(entropy, 0.0)

    def test_two_equal_bytes_entropy(self):
        """Test entropy of two equally distributed bytes."""
        data = b"\x00\xFF" * 500
        entropy = self.analyzer.calculate_entropy(data)
        self.assertAlmostEqual(entropy, 1.0, places=5)

    def test_perfect_random_entropy(self):
        """Test entropy of perfectly random data approaches 8.0."""
        data = bytes(range(256)) * 100
        entropy = self.analyzer.calculate_entropy(data)
        self.assertAlmostEqual(entropy, 8.0, places=5)

    def test_known_pattern_entropy_values(self):
        """Test entropy calculations against known values."""
        test_cases = [
            (b"AAAA", 0.0),
            (b"ABAB", 1.0),
            (b"ABCD", 2.0),
            (b"ABCDEFGH", 3.0),
            (bytes(range(16)) * 16, 4.0),
        ]

        for data, expected in test_cases:
            entropy = self.analyzer.calculate_entropy(data)
            self.assertAlmostEqual(entropy, expected, places=2)

    def test_compressed_data_entropy(self):
        """Test entropy of compressed data is high."""
        import zlib

        original = b"This is uncompressed text data. " * 100
        compressed = zlib.compress(original, level=9)
        entropy = self.analyzer.calculate_entropy(compressed)
        self.assertGreater(entropy, 6.0)

    def test_encrypted_data_entropy(self):
        """Test entropy of encrypted-like random data."""
        random.seed(42)
        data = bytes(random.randint(0, 255) for _ in range(1024))
        entropy = self.analyzer.calculate_entropy(data)
        self.assertGreater(entropy, 7.5)

    def test_text_data_entropy(self):
        """Test entropy of ASCII text data."""
        text = b"The quick brown fox jumps over the lazy dog. " * 50
        entropy = self.analyzer.calculate_entropy(text)
        self.assertGreater(entropy, 3.5)
        self.assertLess(entropy, 5.0)

    def test_binary_header_entropy(self):
        """Test entropy of typical PE/ELF headers."""
        pe_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        pe_header += b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
        entropy = self.analyzer.calculate_entropy(pe_header)
        self.assertLess(entropy, 4.0)

    def test_base64_encoded_data_entropy(self):
        """Test entropy of base64 encoded data."""
        import base64

        original = b"Binary data to encode" * 10
        encoded = base64.b64encode(original)
        entropy = self.analyzer.calculate_entropy(encoded)
        self.assertGreater(entropy, 3.0)
        self.assertLess(entropy, 6.0)

    def test_repeating_pattern_entropy(self):
        """Test entropy of repeating patterns."""
        pattern = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"
        data = pattern * 64
        entropy = self.analyzer.calculate_entropy(data)
        self.assertAlmostEqual(entropy, 4.0, places=5)

    def test_gradient_data_entropy(self):
        """Test entropy of gradient data."""
        data = bytes(list(range(256)) + list(range(255, -1, -1))) * 10
        entropy = self.analyzer.calculate_entropy(data)
        self.assertAlmostEqual(entropy, 8.0, places=5)

    def test_unicode_text_entropy(self):
        """Test entropy of Unicode text data."""
        text = "Hello 世界 مرحبا мир! 🌍".encode() * 50
        entropy = self.analyzer.calculate_entropy(text)
        self.assertGreater(entropy, 4.0)
        self.assertLess(entropy, 7.0)

    def test_sparse_data_entropy(self):
        """Test entropy of sparse data with many zeros."""
        data = bytearray(10000)
        for i in range(0, 10000, 100):
            data[i] = random.randint(1, 255)
        entropy = self.analyzer.calculate_entropy(bytes(data))
        self.assertLess(entropy, 1.0)

    def test_mathematical_precision(self):
        """Test mathematical precision of entropy calculation."""
        data = b"\x00" * 256 + b"\xFF" * 256
        expected = 1.0
        entropy = self.analyzer.calculate_entropy(data)
        self.assertAlmostEqual(entropy, expected, places=10)

    def test_large_data_entropy_accuracy(self):
        """Test entropy calculation accuracy on large data."""
        data = bytes(i % 256 for i in range(1000000))
        entropy = self.analyzer.calculate_entropy(data)
        self.assertAlmostEqual(entropy, 8.0, places=5)


class TestEntropyClassification(unittest.TestCase):
    """Test entropy classification thresholds and logic."""

    def setUp(self):
        """Initialize test environment."""
        self.analyzer = EntropyAnalyzer()

    def test_low_entropy_classification(self):
        """Test low entropy classification."""
        result = self.analyzer._classify_entropy(2.0)
        self.assertEqual(result, "low")

    def test_medium_entropy_classification(self):
        """Test medium entropy classification."""
        result = self.analyzer._classify_entropy(6.0)
        self.assertEqual(result, "medium")

    def test_high_entropy_classification(self):
        """Test high entropy classification."""
        result = self.analyzer._classify_entropy(7.5)
        self.assertEqual(result, "high")

    def test_boundary_values(self):
        """Test classification at boundary values."""
        self.assertEqual(self.analyzer._classify_entropy(4.99), "low")
        self.assertEqual(self.analyzer._classify_entropy(5.0), "medium")
        self.assertEqual(self.analyzer._classify_entropy(6.99), "medium")
        self.assertEqual(self.analyzer._classify_entropy(7.0), "high")

    def test_extreme_values(self):
        """Test classification at extreme values."""
        self.assertEqual(self.analyzer._classify_entropy(0.0), "low")
        self.assertEqual(self.analyzer._classify_entropy(8.0), "high")
        self.assertEqual(self.analyzer._classify_entropy(10.0), "high")

    def test_custom_thresholds(self):
        """Test custom threshold configuration."""
        self.analyzer.high_entropy_threshold = 6.5
        self.analyzer.medium_entropy_threshold = 4.5

        self.assertEqual(self.analyzer._classify_entropy(4.0), "low")
        self.assertEqual(self.analyzer._classify_entropy(5.0), "medium")
        self.assertEqual(self.analyzer._classify_entropy(7.0), "high")


class TestBinaryFileAnalysis(unittest.TestCase):
    """Test binary file analysis with real and synthetic samples."""

    def setUp(self):
        """Initialize test environment."""
        self.analyzer = EntropyAnalyzer()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test environment."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_analyze_simple_binary(self):
        """Test analysis of simple binary file."""
        test_file = Path(self.temp_dir) / "test.bin"
        test_data = b"\x00\x11\x22\x33" * 256
        test_file.write_bytes(test_data)

        result = self.analyzer.analyze_entropy(test_file)

        self.assertIn("overall_entropy", result)
        self.assertIn("file_size", result)
        self.assertIn("entropy_classification", result)
        self.assertIn("analysis_status", result)
        self.assertEqual(result["file_size"], len(test_data))
        self.assertEqual(result["analysis_status"], "completed")

    def test_analyze_high_entropy_file(self):
        """Test analysis of high entropy file."""
        test_file = Path(self.temp_dir) / "random.bin"
        random.seed(42)
        test_data = bytes(random.randint(0, 255) for _ in range(4096))
        test_file.write_bytes(test_data)

        result = self.analyzer.analyze_entropy(test_file)

        self.assertGreater(result["overall_entropy"], 7.5)
        self.assertEqual(result["entropy_classification"], "high")

    def test_analyze_low_entropy_file(self):
        """Test analysis of low entropy file."""
        test_file = Path(self.temp_dir) / "zeros.bin"
        test_data = b"\x00" * 10000
        test_file.write_bytes(test_data)

        result = self.analyzer.analyze_entropy(test_file)

        self.assertEqual(result["overall_entropy"], 0.0)
        self.assertEqual(result["entropy_classification"], "low")

    def test_analyze_nonexistent_file(self):
        """Test analysis of nonexistent file."""
        result = self.analyzer.analyze_entropy("nonexistent.bin")

        self.assertIn("error", result)
        self.assertNotIn("overall_entropy", result)

    def test_analyze_empty_file(self):
        """Test analysis of empty file."""
        test_file = Path(self.temp_dir) / "empty.bin"
        test_file.touch()

        result = self.analyzer.analyze_entropy(test_file)

        self.assertEqual(result["overall_entropy"], 0.0)
        self.assertEqual(result["file_size"], 0)

    def test_analyze_permission_denied(self):
        """Test analysis with permission denied error."""
        with patch("builtins.open", side_effect=PermissionError("Access denied")):
            result = self.analyzer.analyze_entropy("protected.bin")

            self.assertIn("error", result)
            self.assertIn("Access denied", result["error"])

    def test_analyze_path_types(self):
        """Test analysis with different path types."""
        test_file = Path(self.temp_dir) / "test.bin"
        test_data = b"Test data"
        test_file.write_bytes(test_data)

        result_str = self.analyzer.analyze_entropy(str(test_file))
        result_path = self.analyzer.analyze_entropy(test_file)

        self.assertEqual(result_str["overall_entropy"], result_path["overall_entropy"])

    def test_analyze_large_file(self):
        """Test analysis of large file."""
        test_file = Path(self.temp_dir) / "large.bin"
        chunk_size = 1024 * 1024
        chunks = []
        for i in range(10):
            random.seed(i)
            chunks.append(bytes(random.randint(0, 255) for _ in range(chunk_size)))
        test_data = b"".join(chunks)
        test_file.write_bytes(test_data)

        result = self.analyzer.analyze_entropy(test_file)

        self.assertEqual(result["file_size"], 10 * chunk_size)
        self.assertGreater(result["overall_entropy"], 7.0)

    def test_analyze_pe_executable_structure(self):
        """Test analysis of PE-like executable structure."""
        test_file = Path(self.temp_dir) / "fake_pe.exe"

        dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
        dos_stub = b"This program cannot be run in DOS mode.\r\r\n$\x00" * 2
        pe_header = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x14C, 3, 0, 0, 0, 224, 0x102)
        optional_header = b"\x0B\x01" + b"\x00" * 222

        sections = [
            b".text\x00\x00\x00" + b"\x00" * 32,
            b".data\x00\x00\x00" + b"\x00" * 32,
            b".rsrc\x00\x00\x00" + b"\x00" * 32,
        ]
        random_code = bytes(random.randint(0, 255) for _ in range(4096))

        pe_data = (
            dos_header
            + dos_stub
            + b"\x00" * (0x80 - len(dos_header) - len(dos_stub))
            + pe_header
            + coff_header
            + optional_header
            + b"".join(sections)
            + random_code
        )

        test_file.write_bytes(pe_data)

        result = self.analyzer.analyze_entropy(test_file)

        self.assertIn("overall_entropy", result)
        self.assertGreater(result["overall_entropy"], 3.0)

    def test_analyze_compressed_executable(self):
        """Test analysis of compressed executable-like data."""
        import zlib

        test_file = Path(self.temp_dir) / "compressed.exe"
        original = b"Original executable code " * 1000
        compressed = b"UPX!" + zlib.compress(original, level=9)
        test_file.write_bytes(compressed)

        result = self.analyzer.analyze_entropy(test_file)

        self.assertGreater(result["overall_entropy"], 6.0)
        self.assertIn(result["entropy_classification"], ["medium", "high"])


class TestRealBinaryAnalysis(unittest.TestCase):
    """Test analysis of real binary samples from fixtures."""

    def setUp(self):
        """Initialize test environment."""
        self.analyzer = EntropyAnalyzer()
        self.fixture_base = Path("tests/fixtures/binaries")

    def test_analyze_legitimate_binaries(self):
        """Test entropy analysis of legitimate binaries."""
        legitimate_dir = self.fixture_base / "pe/legitimate"
        if not legitimate_dir.exists():
            self.skipTest("Legitimate binary fixtures not available")

        for binary_path in legitimate_dir.glob("*.exe"):
            if binary_path.stat().st_size > 0:
                result = self.analyzer.analyze_entropy(binary_path)

                self.assertIn("overall_entropy", result)
                self.assertIn("entropy_classification", result)
                self.assertNotIn("error", result)

                if "notepad" in binary_path.name.lower():
                    self.assertLess(result["overall_entropy"], 7.0)

    def test_analyze_packed_binaries(self):
        """Test entropy analysis of packed binaries."""
        packed_files = [
            self.fixture_base / "protected/upx_packed_0.exe",
            self.fixture_base / "protected/upx_packed_1.exe",
            self.fixture_base / "protected/aspack_packed.exe",
            self.fixture_base / "protected/pecompact_packed.exe",
        ]

        for packed_file in packed_files:
            if packed_file.exists() and packed_file.stat().st_size > 0:
                result = self.analyzer.analyze_entropy(packed_file)

                self.assertIn("overall_entropy", result)
                if "upx" in packed_file.name.lower():
                    self.assertGreater(
                        result["overall_entropy"], 5.5, f"UPX packed file {packed_file} should have higher entropy"
                    )

    def test_analyze_protected_binaries(self):
        """Test entropy analysis of protected binaries."""
        protected_files = [
            self.fixture_base / "protected/themida_protected.exe",
            self.fixture_base / "protected/vmprotect_protected.exe",
            self.fixture_base / "protected/obsidium_packed.exe",
            self.fixture_base / "protected/enigma_packed.exe",
        ]

        for protected_file in protected_files:
            if protected_file.exists() and protected_file.stat().st_size > 0:
                result = self.analyzer.analyze_entropy(protected_file)

                self.assertIn("overall_entropy", result)
                self.assertNotIn("error", result)

                if "vmprotect" in protected_file.name.lower() or "themida" in protected_file.name.lower():
                    self.assertGreaterEqual(
                        result["overall_entropy"],
                        5.0,
                        f"Protected file {protected_file} should have moderate to high entropy",
                    )

    def test_analyze_elf_binaries(self):
        """Test entropy analysis of ELF binaries."""
        elf_file = self.fixture_base / "elf/simple_x64"
        if elf_file.exists() and elf_file.stat().st_size > 0:
            result = self.analyzer.analyze_entropy(elf_file)

            self.assertIn("overall_entropy", result)
            self.assertNotIn("error", result)
            self.assertGreater(result["overall_entropy"], 2.0)
            self.assertLess(result["overall_entropy"], 7.0)

    def test_analyze_different_sizes(self):
        """Test entropy analysis across different file sizes."""
        size_categories = self.fixture_base / "size_categories"
        if not size_categories.exists():
            self.skipTest("Size category fixtures not available")

        size_files = [
            size_categories / "tiny_4kb/tiny_hello.exe",
            size_categories / "small_1mb/small_padded.exe",
            size_categories / "medium_100mb/medium_padded.exe",
        ]

        for size_file in size_files:
            if size_file.exists() and size_file.stat().st_size > 0:
                result = self.analyzer.analyze_entropy(size_file)

                self.assertIn("overall_entropy", result)
                self.assertIn("file_size", result)
                self.assertNotIn("error", result)

                if "tiny" in size_file.name:
                    self.assertLess(result["file_size"], 10 * 1024)
                elif "small" in size_file.name:
                    self.assertLess(result["file_size"], 2 * 1024 * 1024)


class TestPerformanceAndScalability(unittest.TestCase):
    """Test performance and scalability of entropy analysis."""

    def setUp(self):
        """Initialize test environment."""
        self.analyzer = EntropyAnalyzer()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test environment."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_entropy_calculation_performance(self):
        """Test entropy calculation performance on various data sizes."""
        import time

        sizes = [1024, 10 * 1024, 100 * 1024, 1024 * 1024]
        max_times = [0.001, 0.01, 0.1, 1.0]

        for size, max_time in zip(sizes, max_times):
            data = bytes(i % 256 for i in range(size))

            start = time.time()
            entropy = self.analyzer.calculate_entropy(data)
            elapsed = time.time() - start

            self.assertLess(elapsed, max_time, f"Entropy calculation for {size} bytes took {elapsed:.3f}s")
            self.assertIsNotNone(entropy)

    def test_file_analysis_performance(self):
        """Test file analysis performance."""
        import time

        test_file = Path(self.temp_dir) / "perf_test.bin"
        test_data = bytes(i % 256 for i in range(1024 * 1024))
        test_file.write_bytes(test_data)

        start = time.time()
        result = self.analyzer.analyze_entropy(test_file)
        elapsed = time.time() - start

        self.assertLess(elapsed, 2.0)
        self.assertIn("overall_entropy", result)

    def test_memory_efficiency(self):
        """Test memory efficiency with large files."""
        import tracemalloc

        test_file = Path(self.temp_dir) / "memory_test.bin"
        test_data = bytes(i % 256 for i in range(10 * 1024 * 1024))
        test_file.write_bytes(test_data)

        tracemalloc.start()
        initial = tracemalloc.get_traced_memory()[0]

        result = self.analyzer.analyze_entropy(test_file)

        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()

        memory_used = (peak - initial) / (1024 * 1024)
        self.assertLess(memory_used, 50, f"Memory usage {memory_used:.1f}MB exceeds 50MB limit")
        self.assertIn("overall_entropy", result)

    def test_concurrent_analysis(self):
        """Test concurrent entropy analysis."""
        import concurrent.futures

        test_files = []
        for i in range(5):
            test_file = Path(self.temp_dir) / f"concurrent_{i}.bin"
            random.seed(i)
            test_data = bytes(random.randint(0, 255) for _ in range(100 * 1024))
            test_file.write_bytes(test_data)
            test_files.append(test_file)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(self.analyzer.analyze_entropy, f) for f in test_files]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        self.assertEqual(len(results), 5)
        for result in results:
            self.assertIn("overall_entropy", result)
            self.assertNotIn("error", result)


class TestEdgeCasesAndErrorRecovery(unittest.TestCase):
    """Test edge cases and error recovery scenarios."""

    def setUp(self):
        """Initialize test environment."""
        self.analyzer = EntropyAnalyzer()

    def test_single_byte_file(self):
        """Test entropy of single byte file."""
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"\x42")
            tf.flush()

            result = self.analyzer.analyze_entropy(tf.name)

            self.assertEqual(result["overall_entropy"], 0.0)
            self.assertEqual(result["file_size"], 1)

            os.unlink(tf.name)

    def test_all_unique_bytes(self):
        """Test entropy of data with all unique bytes."""
        data = bytes(range(256))
        entropy = self.analyzer.calculate_entropy(data)
        self.assertAlmostEqual(entropy, 8.0, places=5)

    def test_alternating_pattern(self):
        """Test entropy of alternating pattern."""
        patterns = [
            (b"\x00\xFF" * 1000, 1.0),
            (b"\x00\x01\x02\x03" * 1000, 2.0),
            (b"\x00\x01\x02\x03\x04\x05\x06\x07" * 1000, 3.0),
        ]

        for data, expected in patterns:
            entropy = self.analyzer.calculate_entropy(data)
            self.assertAlmostEqual(entropy, expected, places=2)

    def test_unicode_filename_handling(self):
        """Test handling of Unicode filenames."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "测试文件_тест_.bin"
            test_file.write_bytes(b"Test data")

            result = self.analyzer.analyze_entropy(test_file)

            self.assertIn("overall_entropy", result)
            self.assertNotIn("error", result)

    def test_read_only_file(self):
        """Test analysis of read-only file."""
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"Test data")
            tf.flush()

            os.chmod(tf.name, 0o444)

            result = self.analyzer.analyze_entropy(tf.name)

            self.assertIn("overall_entropy", result)
            self.assertNotIn("error", result)

            os.chmod(tf.name, 0o644)
            os.unlink(tf.name)

    def test_symbolic_link_handling(self):
        """Test handling of symbolic links."""
        if os.name == "nt":
            self.skipTest("Symbolic link test skipped on Windows")

        with tempfile.TemporaryDirectory() as tmpdir:
            real_file = Path(tmpdir) / "real.bin"
            real_file.write_bytes(b"Test data")

            link_file = Path(tmpdir) / "link.bin"
            link_file.symlink_to(real_file)

            result = self.analyzer.analyze_entropy(link_file)

            self.assertIn("overall_entropy", result)
            self.assertNotIn("error", result)

    def test_io_error_handling(self):
        """Test I/O error handling during analysis."""
        with patch("builtins.open", side_effect=IOError("Disk error")):
            result = self.analyzer.analyze_entropy("test.bin")

            self.assertIn("error", result)
            self.assertIn("Disk error", result["error"])

    def test_memory_error_handling(self):
        """Test memory error handling."""
        with patch("builtins.open", mock_open(read_data=b"test")):
            with patch.object(self.analyzer, "calculate_entropy", side_effect=MemoryError("Out of memory")):
                result = self.analyzer.analyze_entropy("test.bin")

                self.assertIn("error", result)

    def test_logger_error_reporting(self):
        """Test logger error reporting."""
        with patch.object(self.analyzer.logger, "error") as mock_logger:
            result = self.analyzer.analyze_entropy("nonexistent.bin")

            mock_logger.assert_called_once()
            self.assertIn("error", result)

    def test_extreme_entropy_values(self):
        """Test handling of extreme entropy values."""
        test_cases = [
            (b"", 0.0, "low"),
            (bytes(range(256)), 8.0, "high"),
            (b"\x00" * 1000000, 0.0, "low"),
            (bytes(random.randint(0, 255) for _ in range(1000)), None, "high"),
        ]

        for data, expected_entropy, expected_class in test_cases:
            entropy = self.analyzer.calculate_entropy(data)

            if expected_entropy is not None:
                self.assertAlmostEqual(entropy, expected_entropy, places=5)

            classification = self.analyzer._classify_entropy(entropy)
            self.assertEqual(classification, expected_class)


class TestMathematicalAccuracy(unittest.TestCase):
    """Test mathematical accuracy and precision of entropy calculations."""

    def setUp(self):
        """Initialize test environment."""
        self.analyzer = EntropyAnalyzer()

    def test_shannon_entropy_formula(self):
        """Validate Shannon entropy formula implementation."""

        def manual_shannon_entropy(data):
            if not data:
                return 0.0

            byte_counts = {}
            for byte in data:
                byte_counts[byte] = byte_counts.get(byte, 0) + 1

            entropy = 0.0
            data_len = len(data)

            for count in byte_counts.values():
                if count > 0:
                    p = count / data_len
                    entropy -= p * math.log2(p)

            return entropy

        test_data_sets = [
            b"AAAA",
            b"ABAB",
            b"ABCDEFGH",
            bytes(range(256)),
            bytes(random.randint(0, 255) for _ in range(1000)),
        ]

        for data in test_data_sets:
            expected = manual_shannon_entropy(data)
            actual = self.analyzer.calculate_entropy(data)
            self.assertAlmostEqual(actual, expected, places=10)

    def test_entropy_bounds(self):
        """Test entropy stays within theoretical bounds [0, 8]."""
        test_cases = [
            b"",
            b"A",
            b"A" * 1000,
            bytes(range(256)),
            bytes(random.randint(0, 255) for _ in range(10000)),
        ]

        for data in test_cases:
            entropy = self.analyzer.calculate_entropy(data)
            self.assertGreaterEqual(entropy, 0.0)
            self.assertLessEqual(entropy, 8.0)

    def test_entropy_monotonicity(self):
        """Test entropy increases with more diverse bytes."""
        data_sets = [
            b"\x00" * 100,
            b"\x00\x01" * 50,
            b"\x00\x01\x02\x03" * 25,
            bytes(range(16)) * 6,
            bytes(range(256)),
        ]

        previous_entropy = -1
        for data in data_sets:
            entropy = self.analyzer.calculate_entropy(data[:100])
            self.assertGreaterEqual(entropy, previous_entropy)
            previous_entropy = entropy

    def test_floating_point_precision(self):
        """Test floating point precision in calculations."""
        data = bytes(i % 17 for i in range(1000))
        entropy1 = self.analyzer.calculate_entropy(data)

        data = bytes(i % 17 for i in range(1000))
        entropy2 = self.analyzer.calculate_entropy(data)

        self.assertEqual(entropy1, entropy2)

    def test_kolmogorov_complexity_approximation(self):
        """Test entropy as approximation of Kolmogorov complexity."""
        import zlib

        test_strings = [
            b"A" * 1000,
            b"ABCABC" * 100,
            b"The quick brown fox jumps over the lazy dog" * 10,
            bytes(random.randint(0, 255) for _ in range(1000)),
        ]

        for data in test_strings:
            entropy = self.analyzer.calculate_entropy(data)
            compressed_size = len(zlib.compress(data, level=9))
            original_size = len(data)
            compression_ratio = compressed_size / original_size

            if entropy < 2.0:
                self.assertLess(compression_ratio, 0.3)
            elif entropy > 7.0:
                self.assertGreater(compression_ratio, 0.9)


class TestIntegrationScenarios(unittest.TestCase):
    """Test integration scenarios and real-world use cases."""

    def setUp(self):
        """Initialize test environment."""
        self.analyzer = EntropyAnalyzer()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test environment."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_malware_detection_scenario(self):
        """Test entropy analysis for malware-like characteristics."""
        test_file = Path(self.temp_dir) / "suspicious.exe"

        pe_header = b"MZ" + b"\x00" * 100
        encrypted_payload = bytes(random.randint(0, 255) for _ in range(4096))
        normal_code = b"\x90" * 1000 + b"\xC3" * 100

        suspicious_binary = pe_header + encrypted_payload + normal_code
        test_file.write_bytes(suspicious_binary)

        result = self.analyzer.analyze_entropy(test_file)

        self.assertIn("overall_entropy", result)
        self.assertGreater(result["overall_entropy"], 4.0)

    def test_license_validation_detection(self):
        """Test detection of license validation routines."""
        test_file = Path(self.temp_dir) / "licensed.exe"

        license_check = b"LICENSE_KEY_CHECK" + b"\x00" * 16
        encrypted_key = bytes(i ^ 0xAA for i in range(256))
        validation_code = b"\x48\x8B\x45\x08" * 100

        binary_data = license_check + encrypted_key + validation_code
        test_file.write_bytes(binary_data)

        result = self.analyzer.analyze_entropy(test_file)

        self.assertIn("overall_entropy", result)
        self.assertGreater(result["overall_entropy"], 3.0)

    def test_packer_detection_workflow(self):
        """Test packer detection workflow using entropy."""
        import zlib

        test_file = Path(self.temp_dir) / "packed.exe"

        stub = b"UPX!" + b"\x00" * 60
        original = b"Original executable code and data " * 500
        compressed = zlib.compress(original, level=9)

        packed_binary = stub + compressed
        test_file.write_bytes(packed_binary)

        result = self.analyzer.analyze_entropy(test_file)

        self.assertIn("overall_entropy", result)
        self.assertGreater(result["overall_entropy"], 6.0)
        self.assertIn(result["entropy_classification"], ["medium", "high"])

    def test_obfuscation_analysis(self):
        """Test analysis of obfuscated code sections."""
        test_file = Path(self.temp_dir) / "obfuscated.exe"

        xor_key = 0x5A
        original_code = b"mov eax, 1234h\npush ebx\ncall function\n" * 100
        obfuscated = bytes(b ^ xor_key for b in original_code)

        binary_data = b"MZ\x90\x00" + obfuscated
        test_file.write_bytes(binary_data)

        result = self.analyzer.analyze_entropy(test_file)

        self.assertIn("overall_entropy", result)
        self.assertGreater(result["overall_entropy"], 4.0)

    def test_anti_tampering_detection(self):
        """Test detection of anti-tampering mechanisms."""
        test_file = Path(self.temp_dir) / "protected.exe"

        checksum_data = struct.pack("<IIII", 0xDEADBEEF, 0xCAFEBABE, 0x1337C0DE, 0xFEEDFACE)
        integrity_check = bytes(list(range(256)))
        encrypted_section = bytes(random.randint(0, 255) for _ in range(2048))

        protected_binary = checksum_data + integrity_check + encrypted_section
        test_file.write_bytes(protected_binary)

        result = self.analyzer.analyze_entropy(test_file)

        self.assertIn("overall_entropy", result)
        self.assertGreater(result["overall_entropy"], 5.0)


if __name__ == "__main__":
    unittest.main()
