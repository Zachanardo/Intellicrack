"""Production tests for entropy analyzer - NO MOCKS.

This test suite validates entropy analysis capabilities against REAL Windows
binaries. Tests MUST FAIL if entropy calculations are incorrect or packing
detection is broken. Uses actual system binaries for authentic validation.

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

import pytest

from intellicrack.core.analysis.entropy_analyzer import EntropyAnalyzer

SYSTEM32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"


class TestShannonEntropyCoreAlgorithm:
    """Validate Shannon entropy calculation mathematical correctness."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_empty_bytes_zero_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Empty byte sequence must return exactly 0.0 entropy."""
        entropy = analyzer.calculate_entropy(b"")
        assert entropy == 0.0, "Empty data MUST produce zero entropy"

    def test_uniform_single_byte_zero_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Uniform byte sequences must have exactly 0.0 entropy."""
        test_data = [
            (b"\x00" * 100, "null bytes"),
            (b"\xFF" * 1000, "0xFF bytes"),
            (b"\x42" * 5000, "0x42 bytes"),
            (b"A" * 10000, "ASCII 'A'"),
        ]
        for data, description in test_data:
            entropy = analyzer.calculate_entropy(data)
            assert entropy == 0.0, f"{description} MUST have zero entropy, got {entropy}"

    def test_perfect_byte_distribution_maximum_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Perfect distribution of all 256 byte values must yield exactly 8.0 entropy."""
        data = bytes(range(256)) * 100
        entropy = analyzer.calculate_entropy(data)
        assert abs(entropy - 8.0) < 0.001, f"Perfect distribution MUST yield 8.0 entropy, got {entropy}"

    def test_two_byte_equal_distribution_one_bit(self, analyzer: EntropyAnalyzer) -> None:
        """Equal distribution of two distinct bytes must yield exactly 1.0 bit entropy."""
        data = b"\x00\xFF" * 5000
        entropy = analyzer.calculate_entropy(data)
        assert abs(entropy - 1.0) < 0.0001, f"Two-byte distribution MUST yield 1.0 entropy, got {entropy}"

    def test_four_byte_equal_distribution_two_bits(self, analyzer: EntropyAnalyzer) -> None:
        """Equal distribution of four distinct bytes must yield exactly 2.0 bits entropy."""
        data = b"\x00\x55\xAA\xFF" * 2500
        entropy = analyzer.calculate_entropy(data)
        assert abs(entropy - 2.0) < 0.0001, f"Four-byte distribution MUST yield 2.0 entropy, got {entropy}"

    def test_eight_byte_equal_distribution_three_bits(self, analyzer: EntropyAnalyzer) -> None:
        """Equal distribution of eight distinct bytes must yield exactly 3.0 bits entropy."""
        data = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77] * 1250)
        entropy = analyzer.calculate_entropy(data)
        assert abs(entropy - 3.0) < 0.0001, f"Eight-byte distribution MUST yield 3.0 entropy, got {entropy}"

    def test_sixteen_byte_equal_distribution_four_bits(self, analyzer: EntropyAnalyzer) -> None:
        """Equal distribution of 16 distinct bytes must yield exactly 4.0 bits entropy."""
        data = bytes(list(range(16)) * 625)
        entropy = analyzer.calculate_entropy(data)
        assert abs(entropy - 4.0) < 0.0001, f"16-byte distribution MUST yield 4.0 entropy, got {entropy}"

    def test_shannon_formula_manual_calculation_verification(self, analyzer: EntropyAnalyzer) -> None:
        """Verify Shannon entropy formula: H(X) = -Σ P(xi) * log2(P(xi))."""
        test_data = b"AABBBBCCCCCCCC"

        byte_counts: dict[int, int] = {}
        for byte in test_data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1

        expected_entropy = 0.0
        data_len = len(test_data)
        for count in byte_counts.values():
            if count > 0:
                probability = count / data_len
                expected_entropy -= probability * math.log2(probability)

        actual_entropy = analyzer.calculate_entropy(test_data)
        assert abs(actual_entropy - expected_entropy) < 1e-12, "Shannon formula MUST be mathematically exact"

    def test_entropy_bounds_never_violated(self, analyzer: EntropyAnalyzer) -> None:
        """Entropy must ALWAYS be within theoretical bounds [0.0, 8.0]."""
        test_cases = [
            b"",
            b"\x00",
            b"\x00\xFF",
            bytes(range(256)),
            bytes([random.randint(0, 255) for _ in range(1000)]),
            b"A" * 10000,
            os.urandom(5000),
        ]
        for data in test_cases:
            entropy = analyzer.calculate_entropy(data)
            assert 0.0 <= entropy <= 8.0, f"Entropy {entropy} violates theoretical bounds [0.0, 8.0]"

    def test_log2_calculation_precision(self, analyzer: EntropyAnalyzer) -> None:
        """Verify log2 calculation precision in entropy formula."""
        data = b"\x00\x01\x02\x03\x04\x05\x06\x07" * 1000

        entropy = analyzer.calculate_entropy(data)
        expected = 3.0

        assert abs(entropy - expected) < 1e-10, f"Log2 precision error: expected {expected}, got {entropy}"

    def test_probability_calculation_accuracy(self, analyzer: EntropyAnalyzer) -> None:
        """Verify probability calculations are accurate to machine precision."""
        data = b"A" * 75 + b"B" * 25

        a_prob = 75 / 100
        b_prob = 25 / 100
        expected = -(a_prob * math.log2(a_prob) + b_prob * math.log2(b_prob))

        actual = analyzer.calculate_entropy(data)
        assert abs(actual - expected) < 1e-12, "Probability calculation MUST be exact"

    def test_single_byte_data_zero_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Single byte must have exactly 0.0 entropy."""
        for byte_val in [0, 42, 127, 255]:
            data = bytes([byte_val])
            entropy = analyzer.calculate_entropy(data)
            assert entropy == 0.0, f"Single byte {byte_val} MUST have zero entropy"


class TestCompressedDataEntropy:
    """Test entropy characteristics of compressed data."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_zlib_compressed_high_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Zlib compressed data must exhibit high entropy (>5.0)."""
        original = b"This is highly repetitive and compressible text content. " * 200
        compressed = zlib.compress(original, level=9)
        entropy = analyzer.calculate_entropy(compressed)
        assert entropy > 5.0, f"Zlib compressed data MUST have entropy >5.0, got {entropy}"

    def test_gzip_level9_maximum_compression_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Maximum compression level produces highest entropy."""
        data = b"Repeated pattern data for compression testing. " * 150

        compressed_low = zlib.compress(data, level=1)
        compressed_high = zlib.compress(data, level=9)

        entropy_low = analyzer.calculate_entropy(compressed_low)
        entropy_high = analyzer.calculate_entropy(compressed_high)

        assert entropy_high >= entropy_low, "Higher compression MUST NOT reduce entropy"
        assert entropy_high > 6.0, f"Level 9 compression MUST produce entropy >6.0, got {entropy_high}"

    def test_incompressible_data_maintains_high_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Already high-entropy data remains high after compression."""
        random.seed(42)
        random_data = bytes([random.randint(0, 255) for _ in range(4096)])

        original_entropy = analyzer.calculate_entropy(random_data)
        compressed = zlib.compress(random_data, level=9)
        compressed_entropy = analyzer.calculate_entropy(compressed)

        assert original_entropy > 7.5, "Random data MUST have high entropy"
        assert compressed_entropy > 7.0, "Compressed random data MUST maintain high entropy"

    def test_compressed_vs_uncompressed_entropy_delta(self, analyzer: EntropyAnalyzer) -> None:
        """Compression must significantly increase entropy for compressible data."""
        plaintext = b"Simple ASCII text with repeated patterns. " * 100
        compressed = zlib.compress(plaintext, level=9)

        plain_entropy = analyzer.calculate_entropy(plaintext)
        compressed_entropy = analyzer.calculate_entropy(compressed)

        delta = compressed_entropy - plain_entropy
        assert delta > 2.0, f"Compression MUST increase entropy by >2.0, got delta={delta}"

    def test_repeated_byte_pattern_post_compression(self, analyzer: EntropyAnalyzer) -> None:
        """Highly repetitive patterns compress to very high entropy."""
        repeated = b"\x00" * 10000
        compressed = zlib.compress(repeated, level=9)
        entropy = analyzer.calculate_entropy(compressed)
        assert entropy > 5.0, f"Compressed null bytes MUST have entropy >5.0, got {entropy}"


class TestEncryptedDataEntropy:
    """Test entropy characteristics of encrypted/encrypted-style data."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_simulated_aes_ciphertext_maximum_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Simulated AES ciphertext must exhibit near-maximum entropy (>7.8)."""
        random.seed(12345)
        simulated_aes = bytes([random.randint(0, 255) for _ in range(8192)])
        entropy = analyzer.calculate_entropy(simulated_aes)
        assert entropy > 7.8, f"AES-style ciphertext MUST have entropy >7.8, got {entropy}"

    def test_xor_encryption_increases_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """XOR encryption must increase entropy over plaintext."""
        plaintext = b"This is plaintext data that will be XOR encrypted. " * 50
        xor_key = 0x5A
        encrypted = bytes([b ^ xor_key for b in plaintext])

        plain_entropy = analyzer.calculate_entropy(plaintext)
        encrypted_entropy = analyzer.calculate_entropy(encrypted)

        assert encrypted_entropy > plain_entropy, "XOR encryption MUST increase entropy"
        assert encrypted_entropy > 4.0, f"XOR encrypted data MUST have entropy >4.0, got {encrypted_entropy}"

    def test_multi_byte_xor_key_encryption(self, analyzer: EntropyAnalyzer) -> None:
        """Multi-byte XOR key encryption produces elevated entropy."""
        plaintext = b"Secret license validation code implementation. " * 100
        xor_key = b"\xDE\xAD\xBE\xEF"
        encrypted = bytes([plaintext[i] ^ xor_key[i % len(xor_key)] for i in range(len(plaintext))])

        entropy = analyzer.calculate_entropy(encrypted)
        assert entropy > 4.5, f"Multi-byte XOR encryption MUST produce entropy >4.5, got {entropy}"

    def test_random_bytes_maximum_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Cryptographically random bytes must approach maximum entropy."""
        random_bytes = os.urandom(4096)
        entropy = analyzer.calculate_entropy(random_bytes)
        assert entropy > 7.9, f"Random bytes MUST have entropy >7.9, got {entropy}"

    def test_encrypted_section_detection_threshold(self, analyzer: EntropyAnalyzer) -> None:
        """Encrypted sections must exceed detection threshold of 7.0."""
        random.seed(99999)
        encrypted_section = bytes([random.randint(0, 255) for _ in range(2048)])
        entropy = analyzer.calculate_entropy(encrypted_section)
        assert entropy >= 7.0, f"Encrypted section MUST have entropy >=7.0, got {entropy}"


class TestPlaintextEntropyCharacteristics:
    """Test entropy characteristics of plaintext and unencrypted data."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_english_text_medium_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Natural English text must have medium entropy (3.5-5.5)."""
        english = b"The quick brown fox jumps over the lazy dog. " * 100
        entropy = analyzer.calculate_entropy(english)
        assert 3.5 <= entropy <= 5.5, f"English text MUST have entropy 3.5-5.5, got {entropy}"

    def test_ascii_printable_characters_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """ASCII printable characters exhibit moderate entropy."""
        ascii_data = bytes(range(32, 127)) * 50
        entropy = analyzer.calculate_entropy(ascii_data)
        assert 5.5 <= entropy <= 7.0, f"ASCII printable MUST have entropy 5.5-7.0, got {entropy}"

    def test_source_code_moderate_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Source code text has moderate entropy (4.0-6.0)."""
        source_code = b'int main() { printf("Hello, World!\\n"); return 0; }' * 50
        entropy = analyzer.calculate_entropy(source_code)
        assert 4.0 <= entropy <= 6.0, f"Source code MUST have entropy 4.0-6.0, got {entropy}"

    def test_hex_string_representation_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Hex string representations have lower entropy than raw bytes."""
        hex_string = b"0123456789ABCDEF" * 250
        entropy = analyzer.calculate_entropy(hex_string)
        assert 3.5 <= entropy <= 5.0, f"Hex strings MUST have entropy 3.5-5.0, got {entropy}"

    def test_base64_encoded_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Base64 encoded data has moderate entropy."""
        base64_chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" * 20
        entropy = analyzer.calculate_entropy(base64_chars)
        assert 5.0 <= entropy <= 6.5, f"Base64 MUST have entropy 5.0-6.5, got {entropy}"


class TestPEStructureEntropy:
    """Test entropy characteristics of PE binary structures."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_dos_header_low_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """PE DOS header must have low entropy (<3.0)."""
        dos_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00"
        dos_header += b"\xB8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00" * 2
        entropy = analyzer.calculate_entropy(dos_header)
        assert entropy < 3.0, f"DOS header MUST have entropy <3.0, got {entropy}"

    def test_pe_header_structured_low_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """PE headers with structured data must have low-medium entropy."""
        pe_header = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 3, 0, 0, 0, 224, 0x010F)
        combined = pe_header + coff_header * 10
        entropy = analyzer.calculate_entropy(combined)
        assert entropy < 4.5, f"PE header MUST have entropy <4.5, got {entropy}"

    def test_section_table_low_medium_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """PE section table data has low-medium entropy."""
        section_entry = (
            b".text\x00\x00\x00" + struct.pack("<IIIIIIHHI", 0x1000, 0x1000, 0x1000, 0x400, 0, 0, 0, 0, 0x60000020)
        )
        section_table = section_entry * 5
        entropy = analyzer.calculate_entropy(section_table)
        assert entropy < 5.0, f"Section table MUST have entropy <5.0, got {entropy}"

    def test_import_table_moderate_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Import table with DLL/function names has moderate entropy."""
        import_data = b"kernel32.dll\x00GetProcAddress\x00LoadLibraryA\x00" * 20
        entropy = analyzer.calculate_entropy(import_data)
        assert 3.0 <= entropy <= 5.5, f"Import table MUST have entropy 3.0-5.5, got {entropy}"

    def test_null_padding_zero_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Null padding sections must have zero entropy."""
        null_padding = b"\x00" * 4096
        entropy = analyzer.calculate_entropy(null_padding)
        assert entropy == 0.0, f"Null padding MUST have zero entropy, got {entropy}"


class TestPackedExecutableEntropy:
    """Test entropy patterns in packed executables."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_upx_packed_binary_high_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """UPX packed executable must show high entropy (>6.5)."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            upx_stub = b"UPX0\x00\x00\x00\x00" + b"\x00" * 56
            code = b"mov eax, ebx; push ecx; call func; " * 500
            compressed = zlib.compress(code, level=9)

            binary = upx_stub + compressed
            tf.write(binary)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        assert result["overall_entropy"] > 6.5, f"UPX binary MUST have entropy >6.5, got {result['overall_entropy']}"
        assert result["entropy_classification"] == "high", "UPX MUST be classified as high entropy"

    def test_vmprotect_encrypted_very_high_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """VMProtect encrypted binary must show very high entropy (>7.5)."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            pe_header = b"MZ\x90\x00" + b"\x00" * 60
            random.seed(11111)
            vm_code = bytes([random.randint(0, 255) for _ in range(16384)])

            binary = pe_header + vm_code
            tf.write(binary)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        assert result["overall_entropy"] > 7.5, f"VMProtect MUST have entropy >7.5, got {result['overall_entropy']}"

    def test_themida_protection_high_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Themida protected binary must show high entropy (>7.0)."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            marker = b"THEMIDA_VM" + b"\x00" * 6
            random.seed(22222)
            virtualized = bytes([random.randint(0, 255) for _ in range(12288)])

            binary = marker + virtualized
            tf.write(binary)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        assert result["overall_entropy"] > 7.0, f"Themida MUST have entropy >7.0, got {result['overall_entropy']}"

    def test_unprotected_binary_lower_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Unprotected executable must have lower entropy (<6.0)."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            pe_header = b"MZ\x90\x00" + b"\x00" * 60
            code = b"\x55\x8B\xEC\x83\xEC\x40\x8B\x45\x08\x5D\xC3" * 400
            strings = b"License validation error\x00Registration successful\x00" * 20

            binary = pe_header + code + strings
            tf.write(binary)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        assert result["overall_entropy"] < 6.0, f"Unprotected MUST have entropy <6.0, got {result['overall_entropy']}"

    def test_packed_vs_unpacked_entropy_differential(self, analyzer: EntropyAnalyzer) -> None:
        """Packed binary must have >2.5 higher entropy than unpacked."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as packed:
            packed_data = b"UPX!" + zlib.compress(b"code" * 3000, level=9)
            packed.write(packed_data)
            packed.flush()
            packed_result = analyzer.analyze_entropy(packed.name)
            packed_path = packed.name

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as unpacked:
            unpacked_data = b"MZ\x90\x00" + (b"\x55\x8B\xEC\x5D\xC3" * 1000)
            unpacked.write(unpacked_data)
            unpacked.flush()
            unpacked_result = analyzer.analyze_entropy(unpacked.name)
            unpacked_path = unpacked.name

        Path(packed_path).unlink()
        Path(unpacked_path).unlink()

        delta = packed_result["overall_entropy"] - unpacked_result["overall_entropy"]
        assert delta > 2.5, f"Packed entropy delta MUST be >2.5, got {delta}"


class TestEntropyClassificationAccuracy:
    """Test entropy classification thresholds work correctly."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_low_entropy_classification_boundary(self, analyzer: EntropyAnalyzer) -> None:
        """Low entropy classification must trigger below 5.0."""
        test_values = [0.0, 1.0, 2.5, 4.0, 4.999]
        for entropy in test_values:
            classification = analyzer._classify_entropy(entropy)
            assert classification == "low", f"Entropy {entropy} MUST be classified as low"

    def test_medium_entropy_classification_range(self, analyzer: EntropyAnalyzer) -> None:
        """Medium entropy classification must trigger for 5.0 <= entropy < 7.0."""
        test_values = [5.0, 5.5, 6.0, 6.5, 6.99]
        for entropy in test_values:
            classification = analyzer._classify_entropy(entropy)
            assert classification == "medium", f"Entropy {entropy} MUST be classified as medium"

    def test_high_entropy_classification_boundary(self, analyzer: EntropyAnalyzer) -> None:
        """High entropy classification must trigger at 7.0 and above."""
        test_values = [7.0, 7.5, 7.8, 7.99, 8.0]
        for entropy in test_values:
            classification = analyzer._classify_entropy(entropy)
            assert classification == "high", f"Entropy {entropy} MUST be classified as high"

    def test_classification_boundary_precision(self, analyzer: EntropyAnalyzer) -> None:
        """Classification boundaries must be exact at threshold values."""
        assert analyzer._classify_entropy(4.9999999) == "low"
        assert analyzer._classify_entropy(5.0000000) == "medium"
        assert analyzer._classify_entropy(6.9999999) == "medium"
        assert analyzer._classify_entropy(7.0000000) == "high"

    def test_custom_threshold_modification(self, analyzer: EntropyAnalyzer) -> None:
        """Modified thresholds must correctly reclassify entropy values."""
        analyzer.high_entropy_threshold = 6.5
        analyzer.medium_entropy_threshold = 4.5

        assert analyzer._classify_entropy(4.0) == "low"
        assert analyzer._classify_entropy(5.5) == "medium"
        assert analyzer._classify_entropy(7.0) == "high"


class TestFileAnalysisWorkflow:
    """Test complete file analysis workflow."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_analyze_entropy_complete_results(self, analyzer: EntropyAnalyzer) -> None:
        """File analysis must return all required result fields."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
            tf.write(b"Test data content" * 100)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        assert "overall_entropy" in result, "Result MUST include overall_entropy"
        assert "file_size" in result, "Result MUST include file_size"
        assert "entropy_classification" in result, "Result MUST include entropy_classification"
        assert "analysis_status" in result, "Result MUST include analysis_status"
        assert result["analysis_status"] == "completed", "Status MUST be 'completed'"

    def test_analyze_nonexistent_file_error_handling(self, analyzer: EntropyAnalyzer) -> None:
        """Nonexistent file must return error result."""
        result = analyzer.analyze_entropy("C:\\nonexistent_file_12345678.bin")

        assert "error" in result, "Result MUST contain error field"
        assert "overall_entropy" not in result, "Error result MUST NOT contain entropy"

    def test_analyze_empty_file_zero_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Empty file must yield 0.0 entropy and size 0."""
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.flush()
            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        assert result["overall_entropy"] == 0.0, "Empty file MUST have 0.0 entropy"
        assert result["file_size"] == 0, "Empty file MUST report size 0"

    def test_analyze_string_and_path_object_equivalence(self, analyzer: EntropyAnalyzer) -> None:
        """Analysis must accept both string and Path objects identically."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
            test_data = b"Consistent data for path testing"
            tf.write(test_data)
            tf.flush()

            result_str = analyzer.analyze_entropy(str(tf.name))
            result_path = analyzer.analyze_entropy(Path(tf.name))
            Path(tf.name).unlink()

        assert result_str["overall_entropy"] == result_path["overall_entropy"], "String and Path MUST yield identical results"

    def test_large_file_analysis_memory_efficiency(self, analyzer: EntropyAnalyzer) -> None:
        """Large file analysis must complete without memory errors."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
            chunk_size = 1024 * 1024
            random.seed(42)
            large_data = bytes([random.randint(0, 255) for _ in range(chunk_size * 3)])
            tf.write(large_data)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        assert result["file_size"] == len(large_data), "File size MUST be reported correctly"
        assert "overall_entropy" in result, "Large file analysis MUST complete"
        assert result["overall_entropy"] > 7.5, "Random large file MUST have high entropy"


class TestRealWindowsBinaryEntropy:
    """Test entropy analysis on actual Windows system binaries."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_notepad_exe_entropy_baseline(self, analyzer: EntropyAnalyzer) -> None:
        """Notepad.exe must have typical unprotected binary entropy (4.0-6.5)."""
        notepad = SYSTEM32 / "notepad.exe"
        if not notepad.exists():
            pytest.skip("notepad.exe not found")

        result = analyzer.analyze_entropy(notepad)

        assert "overall_entropy" in result, "notepad.exe analysis MUST succeed"
        assert 4.0 <= result["overall_entropy"] <= 6.5, f"notepad.exe entropy MUST be 4.0-6.5, got {result['overall_entropy']}"
        assert result["entropy_classification"] in ["low", "medium"], "notepad.exe MUST be low/medium entropy"

    def test_calc_exe_entropy_profile(self, analyzer: EntropyAnalyzer) -> None:
        """calc.exe must have normal executable entropy range."""
        calc = SYSTEM32 / "calc.exe"
        if not calc.exists():
            pytest.skip("calc.exe not found")

        result = analyzer.analyze_entropy(calc)

        assert "overall_entropy" in result, "calc.exe analysis MUST succeed"
        assert 3.5 <= result["overall_entropy"] <= 6.5, f"calc.exe entropy MUST be 3.5-6.5, got {result['overall_entropy']}"

    def test_kernel32_dll_entropy_characteristics(self, analyzer: EntropyAnalyzer) -> None:
        """kernel32.dll must have typical DLL entropy (4.0-6.0)."""
        kernel32 = SYSTEM32 / "kernel32.dll"
        if not kernel32.exists():
            pytest.skip("kernel32.dll not found")

        result = analyzer.analyze_entropy(kernel32)

        assert "overall_entropy" in result, "kernel32.dll analysis MUST succeed"
        assert 4.0 <= result["overall_entropy"] <= 6.0, f"kernel32.dll entropy MUST be 4.0-6.0, got {result['overall_entropy']}"

    def test_ntdll_dll_system_library_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """ntdll.dll must have system library entropy characteristics."""
        ntdll = SYSTEM32 / "ntdll.dll"
        if not ntdll.exists():
            pytest.skip("ntdll.dll not found")

        result = analyzer.analyze_entropy(ntdll)

        assert "overall_entropy" in result, "ntdll.dll analysis MUST succeed"
        assert result["overall_entropy"] > 3.0, f"ntdll.dll entropy MUST be >3.0, got {result['overall_entropy']}"

    def test_system_binaries_not_packed(self, analyzer: EntropyAnalyzer) -> None:
        """System binaries must NOT be classified as high entropy (packed)."""
        system_files = [
            SYSTEM32 / "notepad.exe",
            SYSTEM32 / "calc.exe",
            SYSTEM32 / "kernel32.dll",
        ]

        for binary_path in system_files:
            if not binary_path.exists():
                continue

            result = analyzer.analyze_entropy(binary_path)
            assert result["entropy_classification"] != "high", f"{binary_path.name} MUST NOT be high entropy"


class TestObfuscationDetectionCapability:
    """Test detection of code obfuscation through entropy analysis."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_xor_obfuscation_entropy_elevation(self, analyzer: EntropyAnalyzer) -> None:
        """XOR obfuscated code must show higher entropy than plaintext."""
        plaintext = b"mov eax, [ebp+8]; push ebx; call verify_license; " * 100
        xor_key = 0x7F
        obfuscated = bytes([b ^ xor_key for b in plaintext])

        plain_entropy = analyzer.calculate_entropy(plaintext)
        obfuscated_entropy = analyzer.calculate_entropy(obfuscated)

        assert obfuscated_entropy > plain_entropy, "Obfuscation MUST increase entropy"
        assert obfuscated_entropy > 4.5, f"Obfuscated code MUST have entropy >4.5, got {obfuscated_entropy}"

    def test_polymorphic_code_high_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Simulated polymorphic code must exhibit high entropy (>6.0)."""
        random.seed(7777)
        base_ops = [0x90, 0xEB, 0x00, 0x55, 0x8B, 0xEC, 0x5D, 0xC3]
        polymorphic = bytearray()

        for _ in range(500):
            polymorphic.extend(base_ops)
            junk = bytes([random.randint(0, 255) for _ in range(6)])
            polymorphic.extend(junk)

        entropy = analyzer.calculate_entropy(bytes(polymorphic))
        assert entropy > 6.0, f"Polymorphic code MUST have entropy >6.0, got {entropy}"

    def test_control_flow_flattening_detection(self, analyzer: EntropyAnalyzer) -> None:
        """Control flow obfuscation with junk instructions increases entropy."""
        normal = b"\x55\x8B\xEC\x83\xEC\x40\x8B\x45\x08\x5D\xC3" * 200

        random.seed(3333)
        obfuscated = bytearray()
        for i in range(0, len(normal), 11):
            obfuscated.extend(normal[i : i + 11])
            junk = bytes([random.randint(0, 255) for _ in range(8)])
            obfuscated.extend(junk)

        normal_entropy = analyzer.calculate_entropy(normal)
        obfuscated_entropy = analyzer.calculate_entropy(bytes(obfuscated))

        assert obfuscated_entropy > normal_entropy, "Control flow obfuscation MUST increase entropy"

    def test_string_encryption_detection(self, analyzer: EntropyAnalyzer) -> None:
        """Encrypted strings must show significantly higher entropy."""
        plaintext_strings = b"License key invalid\x00Registration successful\x00Trial expired\x00" * 20
        random.seed(5555)
        encrypted_strings = bytes([b ^ random.randint(0, 255) for b in plaintext_strings])

        plain_entropy = analyzer.calculate_entropy(plaintext_strings)
        encrypted_entropy = analyzer.calculate_entropy(encrypted_strings)

        assert encrypted_entropy > plain_entropy + 2.0, "String encryption MUST increase entropy by >2.0"


class TestLicenseProtectionScenarios:
    """Test entropy analysis in license protection contexts."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_encrypted_license_key_storage_high_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Encrypted license key storage must be detectable via high entropy."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            pe_header = b"MZ\x90\x00" + b"\x00" * 60
            lic_section = b".lic\x00\x00\x00\x00"

            random.seed(11111)
            encrypted_keys = bytes([random.randint(0, 255) for _ in range(2048)])

            normal_code = b"\x55\x8B\xEC\x5D\xC3" * 400

            binary = pe_header + lic_section + encrypted_keys + normal_code
            tf.write(binary)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        assert result["overall_entropy"] > 6.0, f"Encrypted license data MUST have entropy >6.0, got {result['overall_entropy']}"

    def test_hardware_id_validation_entropy_signature(self, analyzer: EntropyAnalyzer) -> None:
        """HWID validation with encryption shows entropy signature."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            hwid_marker = b"HWID_VALIDATION" + b"\x00"
            encrypted_table = bytes([i ^ 0xAA for i in range(1024)])
            validation_code = b"\x8B\x45\x08\x33\xC1\x74\x08" * 100

            binary = hwid_marker + encrypted_table + validation_code
            tf.write(binary)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        assert result["overall_entropy"] > 4.5, f"HWID validation MUST have entropy >4.5, got {result['overall_entropy']}"

    def test_trial_period_data_encryption_detection(self, analyzer: EntropyAnalyzer) -> None:
        """Encrypted trial period data must be identifiable."""
        with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as tf:
            marker = b"TRIAL_DATA_V1\x00\x00\x00"

            random.seed(99999)
            encrypted_trial = bytes([random.randint(0, 255) for _ in range(512)])

            checksum = struct.pack("<I", 0xDEADBEEF)

            trial_file = marker + encrypted_trial + checksum
            tf.write(trial_file)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        assert result["overall_entropy"] > 7.0, f"Encrypted trial data MUST have entropy >7.0, got {result['overall_entropy']}"

    def test_activation_request_encryption(self, analyzer: EntropyAnalyzer) -> None:
        """Encrypted activation requests must show very high entropy."""
        header = b"ACTIVATION_REQ\x00\x00"

        random.seed(55555)
        encrypted_payload = bytes([random.randint(0, 255) for _ in range(1024)])

        signature = struct.pack("<Q", 0xCAFEBABEDEADBEEF)

        packet = header + encrypted_payload + signature

        entropy = analyzer.calculate_entropy(packet)
        assert entropy > 7.5, f"Activation packet MUST have entropy >7.5, got {entropy}"


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling robustness."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_very_large_data_processing_correctness(self, analyzer: EntropyAnalyzer) -> None:
        """Very large data sets must be processed correctly."""
        large_data = bytes([i % 256 for i in range(10_000_000)])
        entropy = analyzer.calculate_entropy(large_data)
        assert 7.99 <= entropy <= 8.0, f"Large uniform distribution MUST yield ~8.0, got {entropy}"

    def test_all_byte_values_maximum_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Data with all 256 byte values must achieve 8.0 entropy."""
        all_bytes = bytes(range(256))
        entropy = analyzer.calculate_entropy(all_bytes)
        assert abs(entropy - 8.0) < 0.0001, f"All byte values MUST produce 8.0 entropy, got {entropy}"

    def test_unicode_filename_handling(self, analyzer: EntropyAnalyzer) -> None:
        """Unicode file paths must be handled correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            unicode_file = Path(tmpdir) / "测试_тест_🔒.bin"
            unicode_file.write_bytes(b"Unicode test data" * 50)

            result = analyzer.analyze_entropy(unicode_file)

            assert "overall_entropy" in result, "Unicode paths MUST be supported"
            assert "error" not in result, "Unicode paths MUST NOT cause errors"

    def test_windows_path_with_spaces(self, analyzer: EntropyAnalyzer) -> None:
        """Windows paths with spaces must be handled correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            spaced_dir = Path(tmpdir) / "test directory with spaces"
            spaced_dir.mkdir(exist_ok=True)
            test_file = spaced_dir / "test file.bin"
            test_file.write_bytes(b"Space test" * 100)

            result = analyzer.analyze_entropy(test_file)

            assert "overall_entropy" in result, "Spaced paths MUST work"
            assert result["analysis_status"] == "completed", "Analysis MUST complete"

    def test_readonly_file_analysis(self, analyzer: EntropyAnalyzer) -> None:
        """Read-only files must be analyzable."""
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"readonly test data" * 50)
            tf.flush()

            import stat

            os.chmod(tf.name, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

            result = analyzer.analyze_entropy(tf.name)

            os.chmod(tf.name, stat.S_IRUSR | stat.S_IWUSR)
            Path(tf.name).unlink()

        assert "overall_entropy" in result, "Read-only files MUST be analyzable"


class TestPerformanceRequirements:
    """Test performance requirements for production use."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_1kb_calculation_speed(self, analyzer: EntropyAnalyzer) -> None:
        """1KB entropy calculation must complete in <1ms."""
        import time

        data = bytes([i % 256 for i in range(1024)])

        start = time.perf_counter()
        entropy = analyzer.calculate_entropy(data)
        elapsed = time.perf_counter() - start

        assert elapsed < 0.001, f"1KB calculation took {elapsed * 1000:.2f}ms (must be <1ms)"
        assert entropy is not None

    def test_100kb_calculation_speed(self, analyzer: EntropyAnalyzer) -> None:
        """100KB entropy calculation must complete in <10ms."""
        import time

        data = bytes([i % 256 for i in range(100 * 1024)])

        start = time.perf_counter()
        entropy = analyzer.calculate_entropy(data)
        elapsed = time.perf_counter() - start

        assert elapsed < 0.01, f"100KB calculation took {elapsed * 1000:.2f}ms (must be <10ms)"
        assert entropy is not None

    def test_1mb_file_analysis_speed(self, analyzer: EntropyAnalyzer) -> None:
        """1MB file analysis must complete in <100ms."""
        import time

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            data = bytes([i % 256 for i in range(1024 * 1024)])
            tf.write(data)
            tf.flush()

            start = time.perf_counter()
            result = analyzer.analyze_entropy(tf.name)
            elapsed = time.perf_counter() - start

            Path(tf.name).unlink()

        assert elapsed < 0.1, f"1MB analysis took {elapsed * 1000:.2f}ms (must be <100ms)"
        assert "overall_entropy" in result

    def test_repeated_calculations_consistency(self, analyzer: EntropyAnalyzer) -> None:
        """Repeated calculations on same data must be consistent."""
        data = os.urandom(4096)

        entropies = [analyzer.calculate_entropy(data) for _ in range(10)]

        assert all(abs(e - entropies[0]) < 1e-10 for e in entropies), "Repeated calculations MUST be identical"


class TestRealWorldPackerProfiles:
    """Test detection of real-world packer entropy profiles."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_upx_entropy_profile_range(self, analyzer: EntropyAnalyzer) -> None:
        """UPX packed binaries show 6.5-7.5 entropy range."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            upx_header = b"UPX!\x0D\x0A\x1A\x0A"
            compressed = zlib.compress(b"executable_code_section" * 500, level=9)
            trailer = b"\x00" * 64

            binary = upx_header + compressed + trailer
            tf.write(binary)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        entropy = result["overall_entropy"]
        assert 6.5 <= entropy <= 7.5, f"UPX entropy {entropy} outside range [6.5, 7.5]"

    def test_aspack_entropy_profile_range(self, analyzer: EntropyAnalyzer) -> None:
        """ASPack shows 6.0-7.0 entropy range."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            aspack_sig = b"ASPack v2.12\x00\x00\x00\x00"
            compressed = zlib.compress(b"original_binary_data" * 400, level=6)

            binary = aspack_sig + compressed
            tf.write(binary)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        entropy = result["overall_entropy"]
        assert 6.0 <= entropy <= 7.0, f"ASPack entropy {entropy} outside range [6.0, 7.0]"

    def test_vmprotect_entropy_profile_range(self, analyzer: EntropyAnalyzer) -> None:
        """VMProtect virtualization shows 7.5-8.0 entropy."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            random.seed(77777)
            vm_instructions = bytes([random.randint(0, 255) for _ in range(8192)])

            binary = b"VMProtect\x00\x00\x00\x00\x00\x00\x00" + vm_instructions
            tf.write(binary)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        entropy = result["overall_entropy"]
        assert 7.5 <= entropy <= 8.0, f"VMProtect entropy {entropy} outside range [7.5, 8.0]"

    def test_themida_entropy_profile_range(self, analyzer: EntropyAnalyzer) -> None:
        """Themida protection shows 7.0-8.0 entropy."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            marker = b"Themida"
            random.seed(88888)
            vm_code = bytes([random.randint(0, 255) for _ in range(12288)])

            binary = marker + vm_code
            tf.write(binary)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        entropy = result["overall_entropy"]
        assert 7.0 <= entropy <= 8.0, f"Themida entropy {entropy} outside range [7.0, 8.0]"


class TestProductionReadinessValidation:
    """Validate production readiness with real-world scenarios."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_detect_real_zlib_compression(self, analyzer: EntropyAnalyzer) -> None:
        """Real zlib compression must be detected via entropy."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            license_code = (
                b'int verify(char* key) { if (strlen(key) != 16) return 0; '
                b'unsigned int sum = 0; for (int i = 0; i < 16; i++) sum += key[i]; '
                b'return sum == 0xDEAD; }'
            ) * 50

            compressed = zlib.compress(license_code, level=9)
            tf.write(b"MZ\x00\x00" + compressed)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        assert result["overall_entropy"] > 6.5, "Real zlib MUST show entropy >6.5"
        assert result["entropy_classification"] == "high", "Compressed MUST be high entropy"

    def test_malware_packer_detection_workflow(self, analyzer: EntropyAnalyzer) -> None:
        """Entropy analysis must support malware/packer detection workflow."""
        samples = []

        with tempfile.NamedTemporaryFile(suffix="_benign.exe", delete=False) as f:
            benign = b"MZ\x90\x00" + (b"\x55\x8B\xEC\x33\xC0\x5D\xC3" * 400)
            f.write(benign)
            f.flush()
            samples.append(("benign", f.name, False))

        with tempfile.NamedTemporaryFile(suffix="_packed.exe", delete=False) as f:
            packed = b"UPX0" + zlib.compress(b"malicious_payload" * 500, level=9)
            f.write(packed)
            f.flush()
            samples.append(("packed", f.name, True))

        detections = []
        for label, path, expect_high in samples:
            result = analyzer.analyze_entropy(path)
            is_high = result["entropy_classification"] == "high"
            detections.append((label, is_high, expect_high))
            Path(path).unlink()

        for label, detected, expected in detections:
            assert detected == expected, f"{label} detection failed: expected={expected}, detected={detected}"

    def test_license_protection_analysis_support(self, analyzer: EntropyAnalyzer) -> None:
        """Entropy analysis must support license protection workflows."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            pe_header = b"MZ\x90\x00" + b"\x00" * 60

            validation_code = (b"\x55\x8B\xEC\x83\xEC\x40" b"\x8B\x45\x08" b"\x8B\x4D\x0C") * 50

            random.seed(33333)
            encrypted_licenses = bytes([random.randint(0, 255) for _ in range(1024)])

            trial_routine = b"\x74\x08\xEB\x06" * 100

            protected = pe_header + validation_code + encrypted_licenses + trial_routine
            tf.write(protected)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        assert result["overall_entropy"] > 5.0, "License-protected MUST have entropy >5.0"
        assert result["entropy_classification"] in ["medium", "high"], "Protected MUST be medium/high entropy"
