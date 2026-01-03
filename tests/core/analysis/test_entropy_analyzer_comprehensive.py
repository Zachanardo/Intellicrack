"""Comprehensive production-ready test suite for entropy analysis capabilities.

This test suite validates that entropy analysis effectively identifies packed,
encrypted, and obfuscated binaries in real-world license protection scenarios.
Tests use REAL binary data and MUST fail if entropy detection is broken.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import math
import random
import struct
import tempfile
import zlib
from pathlib import Path
from typing import Any

import pytest
from _pytest.monkeypatch import MonkeyPatch

from intellicrack.core.analysis.entropy_analyzer import EntropyAnalyzer


class TestShannonEntropyCalculation:
    """Test Shannon entropy calculation produces mathematically correct results."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_empty_data_returns_zero_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Empty data must have exactly 0.0 entropy."""
        entropy = analyzer.calculate_entropy(b"")
        assert entropy == 0.0, "Empty data MUST have zero entropy"

    def test_uniform_data_returns_zero_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Uniform byte sequences must have 0.0 entropy."""
        test_cases = [
            b"\x00" * 1000,
            b"\xFF" * 5000,
            b"\x42" * 10000,
        ]
        for data in test_cases:
            entropy = analyzer.calculate_entropy(data)
            assert entropy == 0.0, f"Uniform data {data[:10]}... MUST have zero entropy"

    def test_perfectly_random_data_approaches_maximum_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Perfectly distributed data must approach theoretical maximum of 8.0."""
        data = bytes(range(256)) * 100
        entropy = analyzer.calculate_entropy(data)
        assert 7.999 <= entropy <= 8.0, f"Perfect distribution MUST yield ~8.0 entropy, got {entropy}"

    def test_two_byte_distribution_yields_one_bit_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Equal distribution of two byte values must yield exactly 1.0 entropy."""
        data = b"\x00\xFF" * 1000
        entropy = analyzer.calculate_entropy(data)
        assert abs(entropy - 1.0) < 0.0001, f"Two-byte distribution MUST yield 1.0 entropy, got {entropy}"

    def test_four_byte_distribution_yields_two_bit_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Equal distribution of four byte values must yield exactly 2.0 entropy."""
        data = b"\x00\x01\x02\x03" * 1000
        entropy = analyzer.calculate_entropy(data)
        assert abs(entropy - 2.0) < 0.0001, f"Four-byte distribution MUST yield 2.0 entropy, got {entropy}"

    def test_shannon_formula_mathematical_correctness(self, analyzer: EntropyAnalyzer) -> None:
        """Validate Shannon entropy formula: H(X) = -Σ P(xi) * log2(P(xi))."""
        test_data = b"ABCDABCDABCDABCD"

        byte_counts: dict[int, int] = {}
        for byte in test_data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1

        expected_entropy = 0.0
        data_len = len(test_data)
        for count in byte_counts.values():
            if count > 0:
                prob = count / data_len
                expected_entropy -= prob * math.log2(prob)

        actual_entropy = analyzer.calculate_entropy(test_data)
        assert abs(actual_entropy - expected_entropy) < 1e-10, "Shannon formula implementation MUST be mathematically exact"

    def test_entropy_bounds_never_exceeded(self, analyzer: EntropyAnalyzer) -> None:
        """Entropy must always be within theoretical bounds [0.0, 8.0]."""
        test_cases = [
            b"",
            b"A",
            b"AB" * 50,
            bytes(range(256)),
            bytes(random.randint(0, 255) for _ in range(10000)),
        ]

        for data in test_cases:
            entropy = analyzer.calculate_entropy(data)
            assert 0.0 <= entropy <= 8.0, f"Entropy {entropy} violates bounds [0.0, 8.0]"

    def test_compressed_data_exhibits_high_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Compressed data must exhibit high entropy (>6.0) due to randomness."""
        original = b"This is highly compressible repeated text. " * 200
        compressed = zlib.compress(original, level=9)
        entropy = analyzer.calculate_entropy(compressed)
        assert entropy > 6.0, f"Compressed data MUST have high entropy (>6.0), got {entropy}"

    def test_encrypted_style_random_data_high_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Simulated encrypted data must show very high entropy (>7.5)."""
        random.seed(12345)
        encrypted_data = bytes(random.randint(0, 255) for _ in range(4096))
        entropy = analyzer.calculate_entropy(encrypted_data)
        assert entropy > 7.5, f"Encrypted-style data MUST have very high entropy (>7.5), got {entropy}"

    def test_plaintext_exhibits_medium_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Natural language text must have medium entropy (3.5-5.5)."""
        plaintext = b"The quick brown fox jumps over the lazy dog. " * 100
        entropy = analyzer.calculate_entropy(plaintext)
        assert 3.5 <= entropy <= 5.5, f"Plaintext MUST have medium entropy (3.5-5.5), got {entropy}"

    def test_pe_header_exhibits_low_to_medium_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """PE headers with structured data must have low to medium entropy (<4.5)."""
        dos_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        dos_header += b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00" * 3
        entropy = analyzer.calculate_entropy(dos_header)
        assert entropy < 4.5, f"PE header MUST have low-medium entropy (<4.5), got {entropy}"

    def test_xor_encrypted_data_high_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """XOR-encrypted data must exhibit elevated entropy."""
        plaintext = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 100
        xor_key = 0x5A
        encrypted = bytes(b ^ xor_key for b in plaintext)

        plain_entropy = analyzer.calculate_entropy(plaintext)
        encrypted_entropy = analyzer.calculate_entropy(encrypted)

        assert encrypted_entropy > plain_entropy, "XOR encryption MUST increase entropy"
        assert encrypted_entropy > 4.0, f"XOR encrypted data MUST have elevated entropy (>4.0), got {encrypted_entropy}"


class TestHighEntropyRegionDetection:
    """Test detection of high-entropy regions indicating packed/encrypted sections."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_detect_upx_packed_executable_signature(self, analyzer: EntropyAnalyzer) -> None:
        """UPX packed executables must be detected via high entropy compressed sections."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            upx_stub = b"UPX0\x00\x00\x00\x00" + b"\x00" * 56
            original_code = b"mov eax, ebx\npush ecx\ncall function_123\n" * 500
            compressed_section = zlib.compress(original_code, level=9)

            upx_binary = upx_stub + compressed_section
            tf.write(upx_binary)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        assert result["overall_entropy"] > 6.5, "UPX packed binary MUST show high entropy (>6.5)"
        assert result["entropy_classification"] == "high", "UPX binary MUST be classified as high entropy"

    def test_detect_vmprotect_encrypted_sections(self, analyzer: EntropyAnalyzer) -> None:
        """VMProtect encrypted code must exhibit very high entropy."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            pe_header = b"MZ" + b"\x00" * 100
            random.seed(9999)
            encrypted_vm_code = bytes(random.randint(0, 255) for _ in range(8192))

            vmprotect_binary = pe_header + encrypted_vm_code
            tf.write(vmprotect_binary)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        assert result["overall_entropy"] > 7.0, "VMProtect binary MUST show very high entropy (>7.0)"
        assert result["entropy_classification"] == "high", "VMProtect binary MUST be classified as high entropy"

    def test_detect_themida_protection_high_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Themida protected binaries must show high entropy from virtualization."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            themida_marker = b"THEMIDA_PROTECTED" + b"\x00" * 15
            random.seed(54321)
            virtualized_code = bytes(random.randint(0, 255) for _ in range(16384))

            themida_binary = themida_marker + virtualized_code
            tf.write(themida_binary)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        assert result["overall_entropy"] > 6.8, "Themida binary MUST show high entropy (>6.8)"
        assert result["entropy_classification"] == "high", "Themida binary MUST be classified as high entropy"

    def test_unprotected_executable_shows_lower_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Unprotected executables must show lower entropy than packed versions."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            pe_header = b"MZ\x90\x00" + b"\x00" * 60
            pe_signature = b"PE\x00\x00"

            normal_code = (b"\x55\x8B\xEC\x83\xEC\x40" +
                          b"\x8B\x45\x08" +
                          b"\x8B\x4D\x0C" +
                          b"\x03\xC1" +
                          b"\x5D\xC3") * 500

            string_data = b"License validation failed\x00Software registered to: %s\x00" * 50

            unprotected_binary = pe_header + pe_signature + normal_code + string_data
            tf.write(unprotected_binary)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        assert result["overall_entropy"] < 6.0, "Unprotected binary MUST have lower entropy (<6.0)"
        assert result["entropy_classification"] in ["low", "medium"], "Unprotected binary MUST NOT be classified as high entropy"


class TestPackedExecutableDetection:
    """Test entropy analysis correctly identifies various packer types."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_aspack_packer_detection_via_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """ASPack packed executables must show elevated entropy."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            aspack_signature = b"ASPack" + b"\x00\x00"
            compressed_payload = zlib.compress(b"Original executable code " * 1000, level=9)

            aspack_binary = aspack_signature + compressed_payload
            tf.write(aspack_binary)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        assert result["overall_entropy"] > 6.0, "ASPack binary MUST show high entropy (>6.0)"

    def test_pecompact_detection_via_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """PECompact packed binaries must exhibit high compression entropy."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            pecompact_stub = b"PEC2" + b"\x00" * 28
            original_sections = b".text section code\n.data section data\n.rsrc resources\n" * 200
            compressed = zlib.compress(original_sections, level=9)

            pecompact_binary = pecompact_stub + compressed
            tf.write(pecompact_binary)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        assert result["overall_entropy"] > 6.5, "PECompact binary MUST show high entropy (>6.5)"

    def test_mpress_packer_entropy_signature(self, analyzer: EntropyAnalyzer) -> None:
        """MPRESS packed executables must show compression entropy patterns."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            mpress_marker = b"MPRESS" + b"\x00\x00"
            code_section = b"function_code_" * 500
            compressed_code = zlib.compress(code_section, level=9)

            mpress_binary = mpress_marker + compressed_code
            tf.write(mpress_binary)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        assert result["overall_entropy"] > 6.2, "MPRESS binary MUST show high entropy (>6.2)"

    def test_entropy_distinguishes_packed_vs_unpacked(self, analyzer: EntropyAnalyzer) -> None:
        """Entropy analysis must reliably distinguish packed from unpacked executables."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as packed_file:
            packed_data = b"UPX!" + zlib.compress(b"code" * 2000, level=9)
            packed_file.write(packed_data)
            packed_file.flush()
            packed_result = analyzer.analyze_entropy(packed_file.name)
            packed_path = packed_file.name

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as unpacked_file:
            unpacked_data = b"MZ\x90\x00" + (b"\x55\x8B\xEC\x5D\xC3" * 800)
            unpacked_file.write(unpacked_data)
            unpacked_file.flush()
            unpacked_result = analyzer.analyze_entropy(unpacked_file.name)
            unpacked_path = unpacked_file.name

        Path(packed_path).unlink()
        Path(unpacked_path).unlink()

        entropy_difference = packed_result["overall_entropy"] - unpacked_result["overall_entropy"]
        assert entropy_difference > 2.0, "Packed executable MUST have significantly higher entropy than unpacked (delta >2.0)"


class TestEntropyClassification:
    """Test entropy classification thresholds correctly identify protection levels."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_low_entropy_threshold_correct(self, analyzer: EntropyAnalyzer) -> None:
        """Low entropy classification must trigger below 5.0."""
        test_cases = [0.0, 1.5, 3.0, 4.99]
        for entropy_value in test_cases:
            classification = analyzer._classify_entropy(entropy_value)
            assert classification == "low", f"Entropy {entropy_value} MUST be classified as low"

    def test_medium_entropy_threshold_correct(self, analyzer: EntropyAnalyzer) -> None:
        """Medium entropy classification must trigger between 5.0 and 7.0."""
        test_cases = [5.0, 5.5, 6.0, 6.5, 6.99]
        for entropy_value in test_cases:
            classification = analyzer._classify_entropy(entropy_value)
            assert classification == "medium", f"Entropy {entropy_value} MUST be classified as medium"

    def test_high_entropy_threshold_correct(self, analyzer: EntropyAnalyzer) -> None:
        """High entropy classification must trigger at 7.0 and above."""
        test_cases = [7.0, 7.5, 7.8, 8.0]
        for entropy_value in test_cases:
            classification = analyzer._classify_entropy(entropy_value)
            assert classification == "high", f"Entropy {entropy_value} MUST be classified as high"

    def test_classification_boundary_precision(self, analyzer: EntropyAnalyzer) -> None:
        """Classification boundaries must be exact at threshold values."""
        assert analyzer._classify_entropy(4.999999) == "low"
        assert analyzer._classify_entropy(5.000000) == "medium"
        assert analyzer._classify_entropy(6.999999) == "medium"
        assert analyzer._classify_entropy(7.000000) == "high"

    def test_custom_threshold_configuration(self, analyzer: EntropyAnalyzer) -> None:
        """Custom thresholds must correctly reclassify entropy values."""
        analyzer.high_entropy_threshold = 6.5
        analyzer.medium_entropy_threshold = 4.0

        assert analyzer._classify_entropy(3.5) == "low"
        assert analyzer._classify_entropy(5.0) == "medium"
        assert analyzer._classify_entropy(7.0) == "high"


class TestBinaryFileAnalysis:
    """Test complete file analysis workflow produces actionable results."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_analyze_entropy_returns_complete_results(self, analyzer: EntropyAnalyzer, temp_workspace: Path) -> None:
        """Analysis must return all required result fields."""
        test_file = temp_workspace / "test.bin"
        test_file.write_bytes(b"Test data" * 100)

        result = analyzer.analyze_entropy(test_file)

        assert "overall_entropy" in result, "Result MUST include overall_entropy"
        assert "file_size" in result, "Result MUST include file_size"
        assert "entropy_classification" in result, "Result MUST include entropy_classification"
        assert "analysis_status" in result, "Result MUST include analysis_status"
        assert result["analysis_status"] == "completed", "Status MUST be 'completed' for successful analysis"

    def test_analyze_nonexistent_file_returns_error(self, analyzer: EntropyAnalyzer) -> None:
        """Analyzing nonexistent file must return error result."""
        result = analyzer.analyze_entropy("nonexistent_file_12345.bin")

        assert "error" in result, "Result MUST contain error field"
        assert "overall_entropy" not in result, "Result MUST NOT contain entropy on error"

    def test_analyze_empty_file_returns_zero_entropy(self, analyzer: EntropyAnalyzer, temp_workspace: Path) -> None:
        """Empty file must yield 0.0 entropy."""
        empty_file = temp_workspace / "empty.bin"
        empty_file.touch()

        result = analyzer.analyze_entropy(empty_file)

        assert result["overall_entropy"] == 0.0, "Empty file MUST have 0.0 entropy"
        assert result["file_size"] == 0, "Empty file MUST report size 0"

    def test_analyze_accepts_string_and_path_objects(self, analyzer: EntropyAnalyzer, temp_workspace: Path) -> None:
        """Analysis must accept both string and Path object inputs."""
        test_file = temp_workspace / "test.bin"
        test_data = b"Consistent test data"
        test_file.write_bytes(test_data)

        result_str = analyzer.analyze_entropy(str(test_file))
        result_path = analyzer.analyze_entropy(test_file)

        assert result_str["overall_entropy"] == result_path["overall_entropy"], "String and Path inputs MUST yield identical results"

    def test_large_file_analysis_completes_successfully(self, analyzer: EntropyAnalyzer, temp_workspace: Path) -> None:
        """Large file analysis must complete without memory errors."""
        large_file = temp_workspace / "large.bin"
        chunk_size = 1024 * 1024

        random.seed(42)
        large_data = bytes(random.randint(0, 255) for _ in range(chunk_size * 5))
        large_file.write_bytes(large_data)

        result = analyzer.analyze_entropy(large_file)

        assert result["file_size"] == len(large_data), "File size MUST be reported correctly"
        assert "overall_entropy" in result, "Large file analysis MUST complete successfully"
        assert result["overall_entropy"] > 7.0, "Random large file MUST have high entropy"


class TestObfuscationDetection:
    """Test detection of code obfuscation techniques via entropy analysis."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_xor_obfuscated_code_detection(self, analyzer: EntropyAnalyzer) -> None:
        """XOR-obfuscated code must show elevated entropy vs plaintext."""
        plaintext_code = b"mov eax, [ebp+8]\npush ebx\ncall verify_license\ntest eax, eax\n" * 100
        xor_key = 0x7F
        obfuscated_code = bytes(b ^ xor_key for b in plaintext_code)

        plain_entropy = analyzer.calculate_entropy(plaintext_code)
        obfuscated_entropy = analyzer.calculate_entropy(obfuscated_code)

        assert obfuscated_entropy > plain_entropy, "Obfuscated code MUST have higher entropy than plaintext"
        assert obfuscated_entropy > 4.5, "XOR obfuscation MUST produce entropy >4.5"

    def test_polymorphic_code_high_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Simulated polymorphic code must exhibit high entropy."""
        random.seed(7777)

        base_instructions = [0x90, 0xEB, 0x00, 0x55, 0x8B, 0xEC, 0x5D, 0xC3]
        polymorphic_code = bytearray()

        for _ in range(500):
            polymorphic_code.extend(base_instructions)
            random_junk = bytes(random.randint(0, 255) for _ in range(4))
            polymorphic_code.extend(random_junk)

        entropy = analyzer.calculate_entropy(bytes(polymorphic_code))
        assert entropy > 6.0, "Polymorphic code MUST have high entropy (>6.0)"

    def test_control_flow_obfuscation_detection(self, analyzer: EntropyAnalyzer) -> None:
        """Control flow obfuscation with junk instructions must increase entropy."""
        normal_flow = b"\x55\x8B\xEC\x83\xEC\x40\x8B\x45\x08\x5D\xC3" * 200

        obfuscated_flow = bytearray()
        random.seed(3333)
        for i in range(0, len(normal_flow), 11):
            obfuscated_flow.extend(normal_flow[i:i+11])
            junk = bytes(random.randint(0, 255) for _ in range(8))
            obfuscated_flow.extend(junk)

        normal_entropy = analyzer.calculate_entropy(normal_flow)
        obfuscated_entropy = analyzer.calculate_entropy(bytes(obfuscated_flow))

        assert obfuscated_entropy > normal_entropy, "Control flow obfuscation MUST increase entropy"


class TestLicenseProtectionScenarios:
    """Test entropy analysis in real license protection cracking scenarios."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_encrypted_license_key_storage_detection(self, analyzer: EntropyAnalyzer) -> None:
        """Encrypted license key storage must be detectable via high entropy."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            pe_header = b"MZ\x90\x00" + b"\x00" * 60

            license_section_marker = b".lic\x00\x00\x00\x00"
            random.seed(11111)
            encrypted_keys = bytes(random.randint(0, 255) for _ in range(2048))

            normal_code = b"\x55\x8B\xEC\x5D\xC3" * 400

            binary = pe_header + license_section_marker + encrypted_keys + normal_code
            tf.write(binary)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        assert result["overall_entropy"] > 6.0, "Binary with encrypted license data MUST show high entropy (>6.0)"

    def test_hardware_id_validation_routine_detection(self, analyzer: EntropyAnalyzer) -> None:
        """Hardware ID validation with encryption must show entropy signature."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            hwid_check_code = b"HWID_CHECK_START" + b"\x00" * 16

            encrypted_hwid_table = bytes(i ^ 0xAA for i in range(512))

            validation_logic = b"\x8B\x45\x08\x33\xC1\x74\x08" * 100

            binary = hwid_check_code + encrypted_hwid_table + validation_logic
            tf.write(binary)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        assert result["overall_entropy"] > 4.0, "HWID validation routine MUST show elevated entropy (>4.0)"

    def test_trial_period_encryption_detection(self, analyzer: EntropyAnalyzer) -> None:
        """Encrypted trial period data must be identifiable via entropy."""
        with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as tf:
            trial_marker = b"TRIAL_DATA_ENCRYPTED"

            random.seed(99999)
            encrypted_trial_info = bytes(random.randint(0, 255) for _ in range(256))

            checksum = struct.pack("<I", 0xDEADBEEF)

            trial_file = trial_marker + encrypted_trial_info + checksum
            tf.write(trial_file)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        assert result["overall_entropy"] > 6.5, "Encrypted trial data MUST have high entropy (>6.5)"

    def test_activation_server_communication_encryption(self, analyzer: EntropyAnalyzer) -> None:
        """Encrypted activation requests must show high entropy."""
        activation_header = b"ACT_REQ\x00"

        random.seed(55555)
        encrypted_payload = bytes(random.randint(0, 255) for _ in range(1024))

        signature = struct.pack("<Q", 0xCAFEBABEDEADBEEF)

        activation_packet = activation_header + encrypted_payload + signature

        entropy = analyzer.calculate_entropy(activation_packet)
        assert entropy > 7.0, "Encrypted activation packet MUST have very high entropy (>7.0)"


class TestErrorHandlingAndEdgeCases:
    """Test error handling and edge case robustness."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_single_byte_data_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Single byte data must have 0.0 entropy."""
        entropy = analyzer.calculate_entropy(b"A")
        assert entropy == 0.0, "Single byte MUST have 0.0 entropy"

    def test_very_large_data_processing(self, analyzer: EntropyAnalyzer) -> None:
        """Very large data sets must be processed correctly."""
        large_data = bytes(i % 256 for i in range(10_000_000))
        entropy = analyzer.calculate_entropy(large_data)
        assert 7.99 <= entropy <= 8.0, "Large uniform distribution MUST yield ~8.0 entropy"

    def test_all_byte_values_present_maximum_entropy(self, analyzer: EntropyAnalyzer) -> None:
        """Data containing all 256 byte values must achieve maximum entropy."""
        all_bytes = bytes(range(256))
        entropy = analyzer.calculate_entropy(all_bytes)
        assert abs(entropy - 8.0) < 0.0001, "All byte values MUST produce 8.0 entropy"

    def test_permission_denied_error_handling(self, analyzer: EntropyAnalyzer, monkeypatch: MonkeyPatch) -> None:
        """Permission errors must be caught and returned in result."""

        class PermissionDeniedFileOpener:
            """Test double that simulates permission denied errors on file open."""

            def __init__(self) -> None:
                self.call_count: int = 0
                self.called_paths: list[str] = []

            def __call__(self, path: Any, mode: str = 'r', **kwargs: Any) -> None:
                self.call_count += 1
                self.called_paths.append(str(path))
                raise PermissionError("Access denied")

        opener = PermissionDeniedFileOpener()
        monkeypatch.setattr("builtins.open", opener)

        result = analyzer.analyze_entropy("test_file.bin")

        assert "error" in result, "Permission error MUST be returned in result"
        assert opener.call_count > 0, "File opener MUST have been called"

    def test_unicode_path_handling(self, analyzer: EntropyAnalyzer) -> None:
        """Unicode file paths must be handled correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            unicode_file = Path(tmpdir) / "测试文件_тест_🔒.bin"
            unicode_file.write_bytes(b"Unicode path test" * 50)

            result = analyzer.analyze_entropy(unicode_file)

            assert "overall_entropy" in result, "Unicode paths MUST be supported"
            assert "error" not in result, "Unicode paths MUST NOT cause errors"


class TestPerformanceRequirements:
    """Test performance requirements for production use."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_entropy_calculation_speed_1kb(self, analyzer: EntropyAnalyzer) -> None:
        """1KB entropy calculation must complete in <1ms."""
        import time
        data = bytes(i % 256 for i in range(1024))

        start = time.perf_counter()
        entropy = analyzer.calculate_entropy(data)
        elapsed = time.perf_counter() - start

        assert elapsed < 0.001, f"1KB calculation took {elapsed*1000:.2f}ms (must be <1ms)"
        assert entropy is not None

    def test_entropy_calculation_speed_100kb(self, analyzer: EntropyAnalyzer) -> None:
        """100KB entropy calculation must complete in <10ms."""
        import time
        data = bytes(i % 256 for i in range(100 * 1024))

        start = time.perf_counter()
        entropy = analyzer.calculate_entropy(data)
        elapsed = time.perf_counter() - start

        assert elapsed < 0.01, f"100KB calculation took {elapsed*1000:.2f}ms (must be <10ms)"
        assert entropy is not None

    def test_file_analysis_speed_1mb(self, analyzer: EntropyAnalyzer) -> None:
        """1MB file analysis must complete in <100ms."""
        import time
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            data = bytes(i % 256 for i in range(1024 * 1024))
            tf.write(data)
            tf.flush()

            start = time.perf_counter()
            result = analyzer.analyze_entropy(tf.name)
            elapsed = time.perf_counter() - start

            Path(tf.name).unlink()

        assert elapsed < 0.1, f"1MB analysis took {elapsed*1000:.2f}ms (must be <100ms)"
        assert "overall_entropy" in result

    def test_memory_efficiency_10mb_file(self, analyzer: EntropyAnalyzer) -> None:
        """10MB file analysis must not exceed 50MB memory overhead."""
        import tracemalloc

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            random.seed(12345)
            data = bytes(random.randint(0, 255) for _ in range(10 * 1024 * 1024))
            tf.write(data)
            tf.flush()

            tracemalloc.start()
            initial_mem = tracemalloc.get_traced_memory()[0]

            result = analyzer.analyze_entropy(tf.name)

            peak_mem = tracemalloc.get_traced_memory()[1]
            tracemalloc.stop()

            Path(tf.name).unlink()

        memory_overhead_mb = (peak_mem - initial_mem) / (1024 * 1024)
        assert memory_overhead_mb < 50, f"Memory overhead {memory_overhead_mb:.1f}MB exceeds 50MB limit"
        assert "overall_entropy" in result


class TestRealWorldPackerSignatures:
    """Test detection of real packer entropy signatures."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_upx_entropy_profile(self, analyzer: EntropyAnalyzer) -> None:
        """UPX packed binaries show characteristic 6.5-7.5 entropy range."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            upx_header = b"UPX!\x0D\x0A\x1A\x0A"
            compressed_code = zlib.compress(b"executable_code" * 500, level=9)
            upx_trailer = b"\x00" * 64

            upx_binary = upx_header + compressed_code + upx_trailer
            tf.write(upx_binary)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        entropy = result["overall_entropy"]
        assert 6.5 <= entropy <= 7.5, f"UPX entropy {entropy} outside expected range [6.5, 7.5]"

    def test_aspack_entropy_profile(self, analyzer: EntropyAnalyzer) -> None:
        """ASPack shows slightly lower entropy (6.0-7.0) than UPX."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            aspack_sig = b"ASPack\x00\x00"
            compressed_sections = zlib.compress(b"original_binary" * 400, level=6)

            aspack_binary = aspack_sig + compressed_sections
            tf.write(aspack_binary)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        entropy = result["overall_entropy"]
        assert 6.0 <= entropy <= 7.0, f"ASPack entropy {entropy} outside expected range [6.0, 7.0]"

    def test_vmprotect_entropy_profile(self, analyzer: EntropyAnalyzer) -> None:
        """VMProtect virtualization shows very high entropy (7.5-8.0)."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            random.seed(77777)
            virtualized_instructions = bytes(random.randint(0, 255) for _ in range(8192))

            vmprotect_binary = b"VMProtect" + b"\x00" * 7 + virtualized_instructions
            tf.write(vmprotect_binary)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        entropy = result["overall_entropy"]
        assert 7.5 <= entropy <= 8.0, f"VMProtect entropy {entropy} outside expected range [7.5, 8.0]"

    def test_themida_entropy_profile(self, analyzer: EntropyAnalyzer) -> None:
        """Themida protection shows high entropy from virtualization (7.0-8.0)."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            themida_marker = b"Themida"
            random.seed(88888)
            vm_code = bytes(random.randint(0, 255) for _ in range(12288))

            themida_binary = themida_marker + vm_code
            tf.write(themida_binary)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        entropy = result["overall_entropy"]
        assert 7.0 <= entropy <= 8.0, f"Themida entropy {entropy} outside expected range [7.0, 8.0]"

    def test_unprotected_vs_protected_entropy_differential(self, analyzer: EntropyAnalyzer) -> None:
        """Protected binaries must have >2.0 higher entropy than unprotected."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as unprotected:
            normal_pe = b"MZ\x90\x00" + (b"\x55\x8B\xEC\x5D\xC3" * 500) + b".text\x00\x00\x00" * 100
            unprotected.write(normal_pe)
            unprotected.flush()
            unprotected_result = analyzer.analyze_entropy(unprotected.name)
            unprotected_path = unprotected.name

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as protected:
            random.seed(12121)
            protected_pe = b"MZ\x90\x00" + bytes(
                random.randint(0, 255) for _ in range(5000)
            )
            protected.write(protected_pe)
            protected.flush()
            protected_result = analyzer.analyze_entropy(protected.name)
            protected_path = protected.name

        Path(unprotected_path).unlink()
        Path(protected_path).unlink()

        entropy_delta = protected_result["overall_entropy"] - unprotected_result["overall_entropy"]
        assert entropy_delta > 2.0, f"Protected vs unprotected entropy delta {entropy_delta:.2f} must be >2.0"


@pytest.mark.real_data
class TestProductionValidation:
    """Production validation tests that prove real-world effectiveness."""

    @pytest.fixture
    def analyzer(self) -> EntropyAnalyzer:
        """Provide entropy analyzer instance."""
        return EntropyAnalyzer()

    def test_detect_real_compression_in_executables(self, analyzer: EntropyAnalyzer) -> None:
        """Real zlib compression must be detected via entropy."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            original_code = (
                b"int verify_license(char* key) {\n"
                b"    if (strlen(key) != 16) return 0;\n"
                b"    unsigned int checksum = 0;\n"
                b"    for (int i = 0; i < 16; i++) checksum += key[i];\n"
                b"    return checksum == 0xDEAD;\n"
                b"}\n"
            ) * 100

            compressed = zlib.compress(original_code, level=9)
            tf.write(b"MZ\x00\x00" + compressed)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        assert result["overall_entropy"] > 6.5, "Real zlib compression MUST show high entropy (>6.5)"
        assert result["entropy_classification"] == "high", "Compressed code MUST be classified as high entropy"

    def test_entropy_analysis_supports_malware_detection_workflow(self, analyzer: EntropyAnalyzer) -> None:
        """Entropy analysis must support malware/packer detection workflows."""
        test_samples = []

        with tempfile.NamedTemporaryFile(suffix="_benign.exe", delete=False) as f:
            benign = b"MZ\x90\x00" + (b"\x55\x8B\xEC\x33\xC0\x5D\xC3" * 400)
            f.write(benign)
            f.flush()
            test_samples.append(("benign", f.name, False))

        with tempfile.NamedTemporaryFile(suffix="_packed.exe", delete=False) as f:
            packed = b"UPX0" + zlib.compress(b"malicious_code" * 500, level=9)
            f.write(packed)
            f.flush()
            test_samples.append(("packed", f.name, True))

        detections = []
        for label, path, expected_high_entropy in test_samples:
            result = analyzer.analyze_entropy(path)
            is_high_entropy = result["entropy_classification"] == "high"
            detections.append((label, is_high_entropy, expected_high_entropy))
            Path(path).unlink()

        for label, detected, expected in detections:
            assert detected == expected, f"{label} sample detection failed: expected={expected}, got={detected}"

    def test_supports_license_protection_analysis_workflow(self, analyzer: EntropyAnalyzer) -> None:
        """Entropy analysis must support license protection analysis workflow."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            pe_header = b"MZ\x90\x00" + b"\x00" * 60

            license_validation_code = (
                b"\x55\x8B\xEC\x83\xEC\x40"
                b"\x8B\x45\x08"
                b"\x8B\x4D\x0C"
            ) * 50

            random.seed(33333)
            encrypted_license_table = bytes(random.randint(0, 255) for _ in range(1024))

            trial_check_routine = b"\x74\x08\xEB\x06" * 100

            protected_binary = pe_header + license_validation_code + encrypted_license_table + trial_check_routine
            tf.write(protected_binary)
            tf.flush()

            result = analyzer.analyze_entropy(tf.name)
            Path(tf.name).unlink()

        assert result["overall_entropy"] > 5.0, "License-protected binary MUST show elevated entropy (>5.0)"
        classification = result["entropy_classification"]
        assert classification in ["medium", "high"], f"Protected binary MUST be classified as medium/high, got {classification}"
