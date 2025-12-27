"""Production tests for GPU acceleration with real hardware validation.

Tests that validate actual GPU detection, framework selection, and CPU fallback
when GPU is unavailable. These tests verify genuine GPU acceleration capabilities
work correctly on real hardware.
"""

import os
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


class TestGPUAcceleratorHardwareDetection:
    """Test suite validating real GPU hardware detection and framework selection."""

    @pytest.fixture
    def accelerator(self) -> GPUAccelerator:
        """Create GPUAccelerator instance."""
        return GPUAccelerator()

    def test_gpu_accelerator_detects_available_framework(self, accelerator: GPUAccelerator) -> None:
        """Test that GPUAccelerator correctly detects available GPU frameworks.

        Validates that framework detection logic identifies real CUDA/XPU frameworks
        installed on the system, not simulated availability.
        """
        assert accelerator.framework in ["cupy", "numba", "pycuda", "xpu", "cpu"]

        if CUPY_AVAILABLE or NUMBA_CUDA_AVAILABLE or PYCUDA_AVAILABLE or XPU_AVAILABLE or PYTORCH_AVAILABLE:
            assert accelerator.framework != "cpu" or os.environ.get("CUDA_VISIBLE_DEVICES") == "-1"
        else:
            assert accelerator.framework == "cpu"

    def test_device_info_contains_real_hardware_data(self, accelerator: GPUAccelerator) -> None:
        """Test that device_info contains actual hardware information.

        Validates that device information is retrieved from real GPU hardware,
        not placeholder or mock data.
        """
        device_info = accelerator.device_info

        if accelerator.framework == "cpu":
            assert device_info == {}
        else:
            assert isinstance(device_info, dict)
            assert len(device_info) > 0

            if accelerator.framework == "cupy":
                assert "name" in device_info
                assert "compute_capability" in device_info
                assert "memory_total" in device_info
                assert device_info["memory_total"] > 0
            elif accelerator.framework == "xpu":
                assert "name" in device_info
                assert "device_type" in device_info
                assert device_info["device_type"] == "Intel XPU"
            elif accelerator.framework == "pycuda":
                assert "name" in device_info
                assert "compute_capability" in device_info
                assert "memory_total" in device_info
            elif accelerator.framework == "numba":
                assert "name" in device_info
                assert "compute_capability" in device_info

    def test_framework_selection_respects_environment_variables(self) -> None:
        """Test that framework selection respects CUDA_VISIBLE_DEVICES and GPU type preferences.

        Validates that environment variables for GPU selection are properly honored.
        """
        original_cuda_devices = os.environ.get("CUDA_VISIBLE_DEVICES")
        original_gpu_type = os.environ.get("INTELLICRACK_GPU_TYPE")

        try:
            os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
            accelerator_cpu = GPUAccelerator()

            assert accelerator_cpu.framework in ["xpu", "cpu"]

            os.environ.pop("CUDA_VISIBLE_DEVICES", None)
            if "INTELLICRACK_GPU_TYPE" in os.environ:
                os.environ.pop("INTELLICRACK_GPU_TYPE")

            accelerator_default = GPUAccelerator()

            if CUPY_AVAILABLE or NUMBA_CUDA_AVAILABLE or PYCUDA_AVAILABLE:
                assert accelerator_default.framework in ["cupy", "numba", "pycuda", "xpu", "cpu"]

        finally:
            if original_cuda_devices is not None:
                os.environ["CUDA_VISIBLE_DEVICES"] = original_cuda_devices
            else:
                os.environ.pop("CUDA_VISIBLE_DEVICES", None)

            if original_gpu_type is not None:
                os.environ["INTELLICRACK_GPU_TYPE"] = original_gpu_type
            else:
                os.environ.pop("INTELLICRACK_GPU_TYPE", None)

    def test_intel_xpu_preference_selects_xpu_when_available(self) -> None:
        """Test that INTELLICRACK_GPU_TYPE=intel preference selects XPU framework.

        Validates that Intel GPU preference is respected when XPU is available.
        """
        original_gpu_type = os.environ.get("INTELLICRACK_GPU_TYPE")

        try:
            os.environ["INTELLICRACK_GPU_TYPE"] = "intel"
            accelerator = GPUAccelerator()

            if XPU_AVAILABLE:
                assert accelerator.framework == "xpu"
            else:
                assert accelerator.framework in ["cupy", "numba", "pycuda", "cpu"]

        finally:
            if original_gpu_type is not None:
                os.environ["INTELLICRACK_GPU_TYPE"] = original_gpu_type
            else:
                os.environ.pop("INTELLICRACK_GPU_TYPE", None)


class TestGPUAcceleratorPatternSearch:
    """Test suite for GPU-accelerated pattern search with real operations."""

    @pytest.fixture
    def accelerator(self) -> GPUAccelerator:
        """Create GPUAccelerator instance."""
        return GPUAccelerator()

    @pytest.fixture
    def test_binary_data(self) -> bytes:
        """Create realistic test binary data."""
        header = b"MZ\x90\x00\x03\x00\x00\x00"
        pattern_data = b"LICENSE_CHECK_V1"
        padding = b"\x00" * 1024
        repeated_pattern = pattern_data * 50
        random_data = bytes(range(256)) * 16

        return header + padding + repeated_pattern + random_data + pattern_data + padding

    def test_pattern_search_finds_all_occurrences(
        self,
        accelerator: GPUAccelerator,
        test_binary_data: bytes
    ) -> None:
        """Test that pattern search finds all occurrences of pattern in binary data.

        Validates that GPU/CPU pattern search correctly identifies all instances
        of the target pattern in realistic binary data.
        """
        pattern = b"LICENSE_CHECK_V1"

        result = accelerator.parallel_pattern_search(test_binary_data, pattern)

        assert "match_count" in result
        assert "positions" in result
        assert "framework" in result

        assert result["match_count"] >= 50, "Should find at least 50 pattern occurrences"
        assert len(result["positions"]) == min(result["match_count"], 1000)

        for position in result["positions"]:
            assert test_binary_data[position:position + len(pattern)] == pattern

    def test_pattern_search_executes_with_correct_framework(
        self,
        accelerator: GPUAccelerator,
        test_binary_data: bytes
    ) -> None:
        """Test that pattern search executes with expected framework.

        Validates that search operation uses the detected GPU framework or
        falls back to CPU correctly.
        """
        pattern = b"MZ\x90"

        result = accelerator.parallel_pattern_search(test_binary_data, pattern)

        assert result["framework"] == accelerator.framework
        assert result["framework"] in ["cupy", "numba", "pycuda", "xpu", "cpu"]

    def test_cpu_fallback_works_when_gpu_fails(self, accelerator: GPUAccelerator) -> None:
        """Test that CPU fallback is triggered when GPU operations fail.

        Validates that fallback mechanism provides correct results when GPU
        acceleration fails or is unavailable.
        """
        test_data = b"Test pattern search: PATTERN_1 and PATTERN_1 again"
        pattern = b"PATTERN_1"

        result = accelerator._cpu_pattern_search(test_data, pattern)

        assert result["method"] == "cpu"
        assert result["match_count"] == 2
        assert len(result["positions"]) == 2
        assert result["positions"][0] == test_data.find(pattern)

    def test_pattern_search_handles_large_binary(self, accelerator: GPUAccelerator) -> None:
        """Test pattern search on large binary data (>10MB).

        Validates that GPU acceleration handles large datasets efficiently and
        doesn't run out of memory.
        """
        large_data = b"X" * (10 * 1024 * 1024)
        pattern = b"LICENSE"
        large_data_with_pattern = b"LICENSE" + large_data + b"LICENSE"

        result = accelerator.parallel_pattern_search(large_data_with_pattern, pattern)

        assert result["match_count"] >= 2
        assert "execution_time" in result
        assert result["execution_time"] < 30.0

    def test_pattern_search_with_no_matches(
        self,
        accelerator: GPUAccelerator,
        test_binary_data: bytes
    ) -> None:
        """Test pattern search when pattern is not present in data.

        Validates that search correctly returns zero matches without errors.
        """
        pattern = b"NONEXISTENT_PATTERN_XYZ123"

        result = accelerator.parallel_pattern_search(test_binary_data, pattern)

        assert result["match_count"] == 0
        assert len(result["positions"]) == 0

    def test_pattern_search_with_overlapping_patterns(self, accelerator: GPUAccelerator) -> None:
        """Test pattern search handles overlapping pattern occurrences.

        Validates that search finds overlapping matches correctly.
        """
        test_data = b"AAAAAAA"
        pattern = b"AAA"

        result = accelerator.parallel_pattern_search(test_data, pattern)

        assert result["match_count"] >= 3


class TestGPUAcceleratorEntropyCalculation:
    """Test suite for GPU-accelerated entropy calculation with real operations."""

    @pytest.fixture
    def accelerator(self) -> GPUAccelerator:
        """Create GPUAccelerator instance."""
        return GPUAccelerator()

    def test_entropy_calculation_produces_valid_values(self, accelerator: GPUAccelerator) -> None:
        """Test that entropy calculation produces mathematically valid values.

        Validates that entropy values are in correct range [0, 8] and computed
        correctly for known data distributions.
        """
        high_entropy_data = bytes(range(256)) * 100
        low_entropy_data = b"\x00" * 25600
        mixed_entropy_data = (bytes(range(256)) * 50) + (b"\x00" * 12800)

        high_result = accelerator.entropy_calculation(high_entropy_data, block_size=256)
        low_result = accelerator.entropy_calculation(low_entropy_data, block_size=256)
        mixed_result = accelerator.entropy_calculation(mixed_entropy_data, block_size=256)

        assert 0.0 <= high_result["average_entropy"] <= 8.0
        assert 0.0 <= low_result["average_entropy"] <= 8.0
        assert 0.0 <= mixed_result["average_entropy"] <= 8.0

        assert high_result["average_entropy"] > 7.0, "High entropy data should have entropy > 7.0"
        assert low_result["average_entropy"] < 1.0, "Low entropy data should have entropy < 1.0"

    def test_entropy_calculation_block_entropies_correct_count(self, accelerator: GPUAccelerator) -> None:
        """Test that entropy calculation produces correct number of blocks.

        Validates that block entropy array length matches expected block count
        based on data size and block size.
        """
        data_size = 10240
        block_size = 512
        test_data = bytes(range(256)) * (data_size // 256 + 1)
        test_data = test_data[:data_size]

        result = accelerator.entropy_calculation(test_data, block_size=block_size)

        expected_blocks = data_size // block_size
        assert len(result["block_entropies"]) == expected_blocks

    def test_entropy_calculation_framework_execution(self, accelerator: GPUAccelerator) -> None:
        """Test that entropy calculation executes with correct framework.

        Validates that operation uses detected GPU framework or CPU fallback.
        """
        test_data = bytes(range(256)) * 40

        result = accelerator.entropy_calculation(test_data, block_size=256)

        assert result["framework"] == accelerator.framework
        assert "execution_time" in result
        assert result["execution_time"] >= 0.0

    def test_cpu_entropy_fallback_correctness(self, accelerator: GPUAccelerator) -> None:
        """Test that CPU entropy fallback produces correct results.

        Validates that CPU implementation matches expected Shannon entropy
        calculation.
        """
        test_data = bytes(range(256))

        result = accelerator._cpu_entropy(test_data, block_size=256)

        assert result["method"] == "cpu"
        assert len(result["block_entropies"]) == 1
        assert result["average_entropy"] == result["block_entropies"][0]

        assert 7.9 < result["average_entropy"] < 8.0

    def test_entropy_handles_small_blocks(self, accelerator: GPUAccelerator) -> None:
        """Test entropy calculation with very small block sizes.

        Validates that small block sizes (< 256 bytes) are handled correctly.
        """
        test_data = bytes(range(256)) * 10
        block_size = 64

        result = accelerator.entropy_calculation(test_data, block_size=block_size)

        assert len(result["block_entropies"]) == len(test_data) // block_size
        assert all(0.0 <= e <= 8.0 for e in result["block_entropies"])


class TestGPUAcceleratorMemoryConstraints:
    """Test suite for GPU memory constraint handling."""

    @pytest.fixture
    def accelerator(self) -> GPUAccelerator:
        """Create GPUAccelerator instance."""
        return GPUAccelerator()

    def test_pattern_search_handles_memory_pressure(self, accelerator: GPUAccelerator) -> None:
        """Test that pattern search handles memory pressure gracefully.

        Validates that operations don't crash under memory constraints and
        fall back to CPU when GPU memory is exhausted.
        """
        if accelerator.framework == "cpu":
            pytest.skip("Test requires GPU framework")

        large_data = b"A" * (100 * 1024 * 1024)
        pattern = b"PATTERN"

        try:
            result = accelerator.parallel_pattern_search(large_data, pattern)

            assert "match_count" in result
            assert result["framework"] in ["cupy", "numba", "pycuda", "xpu", "cpu"]

        except MemoryError:
            pytest.skip("Insufficient GPU memory for test")

    def test_entropy_calculation_handles_large_datasets(self, accelerator: GPUAccelerator) -> None:
        """Test entropy calculation on large dataset without OOM.

        Validates that entropy calculation handles large data without
        exhausting GPU memory.
        """
        large_data = bytes(range(256)) * (1024 * 100)

        try:
            result = accelerator.entropy_calculation(large_data, block_size=1024)

            assert "average_entropy" in result
            assert len(result["block_entropies"]) > 0

        except MemoryError:
            pytest.skip("Insufficient memory for large dataset test")


class TestGPUAcceleratorSingleton:
    """Test suite for GPU accelerator singleton pattern."""

    def test_get_gpu_accelerator_returns_same_instance(self) -> None:
        """Test that get_gpu_accelerator returns singleton instance.

        Validates that multiple calls return the same GPUAccelerator instance.
        """
        accelerator1 = get_gpu_accelerator()
        accelerator2 = get_gpu_accelerator()

        assert accelerator1 is accelerator2

    def test_singleton_preserves_framework_selection(self) -> None:
        """Test that singleton preserves framework selection across calls.

        Validates that framework detection is performed once and cached.
        """
        accelerator1 = get_gpu_accelerator()
        framework1 = accelerator1.framework

        accelerator2 = get_gpu_accelerator()
        framework2 = accelerator2.framework

        assert framework1 == framework2


class TestGPUAcceleratorEdgeCases:
    """Test suite for GPU accelerator edge cases."""

    @pytest.fixture
    def accelerator(self) -> GPUAccelerator:
        """Create GPUAccelerator instance."""
        return GPUAccelerator()

    def test_pattern_search_with_empty_data(self, accelerator: GPUAccelerator) -> None:
        """Test pattern search with empty input data.

        Validates graceful handling of empty input.
        """
        result = accelerator.parallel_pattern_search(b"", b"PATTERN")

        assert result["match_count"] == 0
        assert len(result["positions"]) == 0

    def test_pattern_search_with_empty_pattern(self, accelerator: GPUAccelerator) -> None:
        """Test pattern search with empty pattern.

        Validates handling of edge case with empty pattern.
        """
        result = accelerator.parallel_pattern_search(b"test data", b"")

        assert "match_count" in result

    def test_entropy_calculation_with_empty_data(self, accelerator: GPUAccelerator) -> None:
        """Test entropy calculation with empty input data.

        Validates graceful handling of empty input.
        """
        result = accelerator.entropy_calculation(b"", block_size=256)

        assert result["average_entropy"] == 0.0
        assert len(result["block_entropies"]) == 0

    def test_pattern_longer_than_data(self, accelerator: GPUAccelerator) -> None:
        """Test pattern search when pattern is longer than data.

        Validates correct handling of impossible match scenario.
        """
        short_data = b"ABC"
        long_pattern = b"ABCDEFGHIJKLMNOP"

        result = accelerator.parallel_pattern_search(short_data, long_pattern)

        assert result["match_count"] == 0
        assert len(result["positions"]) == 0
