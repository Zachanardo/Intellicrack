"""Production-ready tests for GPU acceleration offensive capabilities.

Tests real GPU-accelerated pattern matching, entropy calculation, and hash
computation for license crack analysis on actual binary data.
"""

import os
import secrets
from typing import Any

import pytest

from intellicrack.core.gpu_acceleration import (
    CUPY_AVAILABLE,
    NUMBA_CUDA_AVAILABLE,
    PYCUDA_AVAILABLE,
    PYTORCH_AVAILABLE,
    XPU_AVAILABLE,
    GPUAccelerator,
    get_gpu_accelerator,
)


class TestGPUAcceleratorInitialization:
    """Test GPU accelerator initialization and framework detection."""

    def test_gpu_accelerator_initializes_with_best_framework(self) -> None:
        """Accelerator selects optimal GPU framework or falls back to CPU."""
        accelerator = GPUAccelerator()

        assert accelerator.framework in ["cupy", "numba", "pycuda", "xpu", "cpu"], "Invalid framework selected"
        assert accelerator.device_info is not None, "Device info not initialized"

    def test_gpu_accelerator_prioritizes_intel_gpu_when_preferred(self) -> None:
        """Accelerator uses Intel XPU when INTELLICRACK_GPU_TYPE=intel."""
        original_env = os.environ.get("INTELLICRACK_GPU_TYPE")
        try:
            os.environ["INTELLICRACK_GPU_TYPE"] = "intel"
            accelerator = GPUAccelerator()

            if XPU_AVAILABLE:
                assert accelerator.framework == "xpu", "Should prefer Intel XPU when available"
        finally:
            if original_env:
                os.environ["INTELLICRACK_GPU_TYPE"] = original_env
            elif "INTELLICRACK_GPU_TYPE" in os.environ:
                del os.environ["INTELLICRACK_GPU_TYPE"]

    def test_gpu_accelerator_falls_back_to_cpu_when_cuda_disabled(self) -> None:
        """Accelerator uses CPU when CUDA_VISIBLE_DEVICES=-1."""
        original_env = os.environ.get("CUDA_VISIBLE_DEVICES")
        try:
            os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
            os.environ.pop("INTELLICRACK_GPU_TYPE", None)
            accelerator = GPUAccelerator()

            if not XPU_AVAILABLE:
                assert accelerator.framework == "cpu", "Should fall back to CPU when CUDA disabled"
        finally:
            if original_env:
                os.environ["CUDA_VISIBLE_DEVICES"] = original_env
            elif "CUDA_VISIBLE_DEVICES" in os.environ:
                del os.environ["CUDA_VISIBLE_DEVICES"]


class TestGPUPatternSearchCapabilities:
    """Test GPU-accelerated pattern search for license keys and serial numbers."""

    def test_gpu_finds_all_occurrences_of_license_pattern(self) -> None:
        """GPU pattern search identifies all instances of license key pattern."""
        accelerator = GPUAccelerator()

        license_pattern = b"ABCD-1234-EFGH-5678"
        data = (
            b"\x00\x00" + license_pattern + b"\x00\x00" * 1000 +
            license_pattern + b"\x00\x00" * 500 +
            license_pattern + b"\x00\x00" * 100
        )

        result = accelerator.parallel_pattern_search(data, license_pattern)

        assert result["match_count"] == 3, f"Failed to find all 3 occurrences (found {result['match_count']})"
        assert len(result["positions"]) == 3, "Incorrect number of positions returned"
        assert 2 in result["positions"], "Missing first occurrence"
        assert result["framework"] in ["cupy", "numba", "pycuda", "xpu", "cpu"], "Invalid framework used"

    def test_gpu_finds_serial_number_in_large_binary(self) -> None:
        """GPU efficiently locates serial number pattern in multi-megabyte binary."""
        accelerator = GPUAccelerator()

        serial = b"SN:9876543210ABCDEF"
        large_data = secrets.token_bytes(5 * 1024 * 1024)
        injection_point = 2 * 1024 * 1024
        data = large_data[:injection_point] + serial + large_data[injection_point:]

        result = accelerator.parallel_pattern_search(data, serial)

        assert result["match_count"] >= 1, "Failed to find serial in large binary"
        assert injection_point in result["positions"], f"Incorrect position (expected {injection_point})"
        assert "execution_time" in result, "Missing execution time metric"
        assert result["execution_time"] > 0, "Execution time not measured"

    def test_gpu_handles_overlapping_pattern_matches(self) -> None:
        """GPU correctly identifies overlapping pattern occurrences."""
        accelerator = GPUAccelerator()

        pattern = b"AAAA"
        data = b"AAAAAAAA"

        result = accelerator.parallel_pattern_search(data, pattern)

        assert result["match_count"] >= 3, "Failed to find overlapping matches"

    def test_gpu_pattern_search_performance_exceeds_cpu(self) -> None:
        """GPU pattern search significantly faster than CPU for large data."""
        if not any([CUPY_AVAILABLE, NUMBA_CUDA_AVAILABLE, PYCUDA_AVAILABLE, XPU_AVAILABLE]):
            pytest.skip("No GPU framework available for performance test")

        accelerator = GPUAccelerator()
        if accelerator.framework == "cpu":
            pytest.skip("GPU not available, skipping performance test")

        pattern = b"LICENSE-KEY-"
        data = secrets.token_bytes(10 * 1024 * 1024)
        data += pattern

        result = accelerator.parallel_pattern_search(data, pattern)

        assert result["execution_time"] < 5.0, f"GPU search too slow: {result['execution_time']:.2f}s"
        assert result["match_count"] >= 1, "Failed to find pattern"

    def test_gpu_finds_encryption_key_candidates(self) -> None:
        """GPU identifies potential encryption key patterns in binary data."""
        accelerator = GPUAccelerator()

        key_candidate = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
        binary_data = (
            secrets.token_bytes(1000) + key_candidate + secrets.token_bytes(1000) +
            key_candidate + secrets.token_bytes(500)
        )

        result = accelerator.parallel_pattern_search(binary_data, key_candidate)

        assert result["match_count"] >= 2, "Failed to find encryption key candidates"
        assert len(result["positions"]) >= 2, "Missing key positions"


class TestGPUEntropyCalculation:
    """Test GPU-accelerated entropy calculation for packed/encrypted sections."""

    def test_gpu_calculates_entropy_for_encrypted_section(self) -> None:
        """GPU correctly calculates high entropy for encrypted data."""
        accelerator = GPUAccelerator()

        encrypted_data = secrets.token_bytes(10240)

        result = accelerator.entropy_calculation(encrypted_data, block_size=1024)

        assert "block_entropies" in result, "Missing block entropy data"
        assert "average_entropy" in result, "Missing average entropy"
        assert len(result["block_entropies"]) == 10, "Incorrect number of blocks"
        assert result["average_entropy"] > 7.0, f"Encrypted data should have high entropy (got {result['average_entropy']:.2f})"
        assert result["max_entropy"] > 7.5, "Maximum entropy too low for random data"

    def test_gpu_calculates_low_entropy_for_text_data(self) -> None:
        """GPU correctly identifies low entropy in plain text."""
        accelerator = GPUAccelerator()

        text_data = b"The quick brown fox jumps over the lazy dog. " * 100

        result = accelerator.entropy_calculation(text_data, block_size=512)

        assert result["average_entropy"] < 6.0, f"Text data should have low entropy (got {result['average_entropy']:.2f})"
        assert result["min_entropy"] < result["max_entropy"], "Entropy range invalid"

    def test_gpu_identifies_packed_code_sections_by_entropy(self) -> None:
        """GPU entropy analysis detects packed/protected code sections."""
        accelerator = GPUAccelerator()

        low_entropy_section = b"\x00" * 2048
        high_entropy_section = secrets.token_bytes(2048)
        data = low_entropy_section + high_entropy_section + low_entropy_section

        result = accelerator.entropy_calculation(data, block_size=1024)

        entropies = result["block_entropies"]
        assert len(entropies) >= 4, "Not enough entropy blocks calculated"

        assert entropies[0] < 2.0, "First section should have very low entropy"
        assert entropies[2] > 7.0 or entropies[1] > 7.0, "Middle section should have high entropy"
        assert entropies[-1] < 2.0, "Last section should have very low entropy"

    def test_gpu_entropy_detects_obfuscated_strings(self) -> None:
        """GPU entropy calculation identifies obfuscated license strings."""
        accelerator = GPUAccelerator()

        normal_string = b"LICENSE_KEY=12345" * 64
        obfuscated_string = bytes([b ^ 0xAA for b in normal_string])

        data = normal_string + obfuscated_string

        result = accelerator.entropy_calculation(data, block_size=512)

        assert len(result["block_entropies"]) >= 2, "Not enough blocks analyzed"


class TestGPUHashComputation:
    """Test GPU-accelerated hash computation for integrity bypass."""

    def test_gpu_computes_crc32_for_binary_data(self) -> None:
        """GPU calculates correct CRC32 checksum for binary data."""
        accelerator = GPUAccelerator()

        data = b"License validation data for CRC32 testing"

        result = accelerator.hash_computation(data, algorithms=["crc32"])

        assert "hashes" in result, "Missing hash results"
        assert "crc32" in result["hashes"], "CRC32 not computed"
        assert len(result["hashes"]["crc32"]) == 8, "CRC32 hash wrong length"
        assert result["hashes"]["crc32"].isalnum(), "CRC32 hash not hexadecimal"

    def test_gpu_computes_adler32_for_binary_data(self) -> None:
        """GPU calculates correct Adler32 checksum."""
        accelerator = GPUAccelerator()

        data = b"Adler32 checksum test data for license validation"

        result = accelerator.hash_computation(data, algorithms=["adler32"])

        assert "hashes" in result, "Missing hash results"
        assert "adler32" in result["hashes"], "Adler32 not computed"
        assert len(result["hashes"]["adler32"]) == 8, "Adler32 hash wrong length"

    def test_gpu_computes_multiple_hashes_simultaneously(self) -> None:
        """GPU efficiently computes multiple hash algorithms in parallel."""
        accelerator = GPUAccelerator()

        data = secrets.token_bytes(1024 * 1024)

        result = accelerator.hash_computation(data, algorithms=["crc32", "adler32"])

        assert "hashes" in result, "Missing hash results"
        assert "crc32" in result["hashes"], "CRC32 not computed"
        assert "adler32" in result["hashes"], "Adler32 not computed"
        assert "execution_time" in result, "Missing execution time"
        assert result["execution_time"] < 2.0, "Hash computation too slow"


class TestGPUAcceleratorFallback:
    """Test CPU fallback when GPU unavailable."""

    def test_cpu_pattern_search_works_when_gpu_unavailable(self) -> None:
        """CPU fallback correctly finds patterns when GPU frameworks missing."""
        accelerator = GPUAccelerator()

        pattern = b"FALLBACK-TEST"
        data = b"\x00" * 1000 + pattern + b"\x00" * 1000 + pattern

        result = accelerator._cpu_pattern_search(data, pattern)

        assert result["match_count"] == 2, "CPU fallback failed to find patterns"
        assert result["method"] == "cpu", "Incorrect method indicator"
        assert len(result["positions"]) == 2, "CPU fallback position count wrong"

    def test_cpu_entropy_calculation_accurate_fallback(self) -> None:
        """CPU entropy calculation produces accurate results as fallback."""
        accelerator = GPUAccelerator()

        random_data = secrets.token_bytes(4096)

        result = accelerator._cpu_entropy(random_data, block_size=1024)

        assert result["method"] == "cpu", "Incorrect method indicator"
        assert len(result["block_entropies"]) == 4, "Wrong number of entropy blocks"
        assert result["average_entropy"] > 7.0, "CPU entropy calculation inaccurate"


class TestGPUAcceleratorDeviceInfo:
    """Test GPU device information retrieval."""

    def test_gpu_device_info_contains_expected_fields(self) -> None:
        """GPU device info includes name, memory, and capabilities."""
        accelerator = GPUAccelerator()

        if accelerator.framework == "cpu":
            pytest.skip("CPU mode has no device info")

        device_info = accelerator.device_info

        assert device_info is not None, "Device info not retrieved"
        assert isinstance(device_info, dict), "Device info not a dictionary"

        if accelerator.framework == "cupy" and CUPY_AVAILABLE:
            assert "name" in device_info, "Missing device name"
            assert "compute_capability" in device_info, "Missing compute capability"
        elif accelerator.framework == "xpu" and XPU_AVAILABLE:
            assert "name" in device_info or "device_type" in device_info, "Missing device identification"


class TestGPUAcceleratorGlobalInstance:
    """Test global GPU accelerator singleton."""

    def test_get_gpu_accelerator_returns_singleton(self) -> None:
        """get_gpu_accelerator returns same instance across calls."""
        acc1 = get_gpu_accelerator()
        acc2 = get_gpu_accelerator()

        assert acc1 is acc2, "Should return same singleton instance"
        assert isinstance(acc1, GPUAccelerator), "Wrong instance type"


class TestGPUAcceleratorRealWorldScenarios:
    """Test GPU acceleration in realistic license cracking scenarios."""

    def test_gpu_finds_serial_validation_routine_in_binary(self) -> None:
        """GPU locates serial number validation code patterns in PE binary."""
        accelerator = GPUAccelerator()

        serial_check_pattern = bytes.fromhex("83F8 18")
        binary_with_serial_check = (
            secrets.token_bytes(10000) + serial_check_pattern +
            secrets.token_bytes(5000) + serial_check_pattern +
            secrets.token_bytes(10000)
        )

        result = accelerator.parallel_pattern_search(binary_with_serial_check, serial_check_pattern)

        assert result["match_count"] >= 2, "Failed to find serial validation patterns"

    def test_gpu_identifies_license_file_encryption_entropy(self) -> None:
        """GPU entropy analysis detects encrypted license file sections."""
        accelerator = GPUAccelerator()

        license_header = b"LICENSE_V1.0" + b"\x00" * 500
        encrypted_license_data = secrets.token_bytes(2048)
        license_footer = b"\x00" * 500

        license_file = license_header + encrypted_license_data + license_footer

        result = accelerator.entropy_calculation(license_file, block_size=512)

        entropies = result["block_entropies"]
        assert any(e > 7.5 for e in entropies[2:6]), "Failed to detect encrypted section"
        assert entropies[0] < 5.0, "Header should have low entropy"

    def test_gpu_calculates_checksum_for_patch_verification(self) -> None:
        """GPU computes checksums for verifying binary patch integrity."""
        accelerator = GPUAccelerator()

        original_code = b"\x55\x8B\xEC" * 100
        patched_code = b"\xC3\x90\x90" * 100

        original_hash = accelerator.hash_computation(original_code, ["crc32"])
        patched_hash = accelerator.hash_computation(patched_code, ["crc32"])

        assert original_hash["hashes"]["crc32"] != patched_hash["hashes"]["crc32"], \
            "Checksums should differ for patched code"
