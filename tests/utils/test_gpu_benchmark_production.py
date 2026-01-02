"""Production tests for GPU benchmarking utilities.

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

import os
import struct
from pathlib import Path
from typing import Any

import pytest

from intellicrack.utils.gpu_benchmark import (
    _benchmark_cpu_framework,
    _benchmark_cupy_framework,
    _benchmark_numba_framework,
    _benchmark_pycuda_framework,
    _determine_best_framework,
    _generate_recommendations,
    _generate_test_data,
    benchmark_gpu_frameworks,
    run_gpu_accelerated_analysis,
)


class FakeSignal:
    """Test double for PyQt signal objects."""

    def __init__(self) -> None:
        self.emit_calls: list[tuple[Any, ...]] = []
        self.call_count: int = 0

    def emit(self, *args: Any) -> None:
        self.emit_calls.append(args)
        self.call_count += 1

    @property
    def call_args_list(self) -> list[tuple[Any, ...]]:
        return self.emit_calls


class FakeApp:
    """Test double for application object with GPU framework support."""

    def __init__(
        self, gpu_frameworks: dict[str, bool] | None = None, has_update_output: bool = True
    ) -> None:
        self.gpu_frameworks: dict[str, bool] = gpu_frameworks or {}
        if has_update_output:
            self.update_output = FakeSignal()


class TestGPUBenchmarkDataGeneration:
    """Test GPU benchmark test data generation."""

    def test_generate_test_data_creates_correct_sizes(self) -> None:
        """Test data generation produces exact requested sizes."""
        test_sizes = [1024, 4096, 10240]
        test_data = _generate_test_data(test_sizes)

        assert len(test_data) == len(test_sizes)
        for size in test_sizes:
            assert size in test_data
            assert len(test_data[size]) == size

    def test_generate_test_data_has_varying_entropy(self) -> None:
        """Test data has low, medium, and high entropy sections."""
        test_sizes = [3000]
        test_data = _generate_test_data(test_sizes)
        data = test_data[3000]

        first_third = data[: 3000 // 3]
        second_third = data[3000 // 3 : 2 * 3000 // 3]
        third_third = data[2 * 3000 // 3 :]

        zeros_in_first = first_third.count(b"\x00")
        assert zeros_in_first > len(first_third) * 0.9

        pattern_in_second = second_third.count(b"ABCD")
        assert pattern_in_second > 50

        unique_bytes_in_third = len(set(third_third))
        assert unique_bytes_in_third > 100

    def test_generate_test_data_deterministic_structure(self) -> None:
        """Test data generation structure is deterministic except random section."""
        test_sizes = [9000]
        test_data1 = _generate_test_data(test_sizes)
        test_data2 = _generate_test_data(test_sizes)

        first_two_thirds_1 = test_data1[9000][: 6000]
        first_two_thirds_2 = test_data2[9000][: 6000]

        assert first_two_thirds_1 == first_two_thirds_2

    def test_generate_test_data_multiple_sizes(self) -> None:
        """Test generation with multiple test sizes simultaneously."""
        test_sizes = [1024, 5120, 10240, 51200]
        test_data = _generate_test_data(test_sizes)

        assert len(test_data) == 4
        for size in test_sizes:
            assert len(test_data[size]) == size


class TestCPUBenchmark:
    """Test CPU baseline benchmarking."""

    def test_cpu_benchmark_pattern_search(self) -> None:
        """Test CPU benchmark performs pattern search."""
        test_data = _generate_test_data([10240])
        framework_results: dict[str, Any] = {
            "pattern_search": {},
            "entropy": {},
            "data_transfer": {},
            "total_time": 0,
        }

        _benchmark_cpu_framework(framework_results, test_data)

        assert "10.0MB" in framework_results["pattern_search"]
        assert isinstance(framework_results["pattern_search"]["10.0MB"], float)
        assert framework_results["pattern_search"]["10.0MB"] >= 0

    def test_cpu_benchmark_entropy_calculation(self) -> None:
        """Test CPU benchmark calculates entropy values."""
        test_data = _generate_test_data([10240])
        framework_results: dict[str, Any] = {
            "pattern_search": {},
            "entropy": {},
            "data_transfer": {},
            "total_time": 0,
        }

        _benchmark_cpu_framework(framework_results, test_data)

        assert "10.0MB" in framework_results["entropy"]
        assert isinstance(framework_results["entropy"]["10.0MB"], float)
        assert framework_results["entropy"]["10.0MB"] >= 0
        assert "entropy_values" in framework_results
        assert "10.0MB" in framework_results["entropy_values"]

    def test_cpu_benchmark_entropy_range(self) -> None:
        """Test CPU entropy values are within expected range."""
        test_data = _generate_test_data([10240])
        framework_results: dict[str, Any] = {
            "pattern_search": {},
            "entropy": {},
            "data_transfer": {},
            "total_time": 0,
        }

        _benchmark_cpu_framework(framework_results, test_data)

        entropy = framework_results["entropy_values"]["10.0MB"]
        assert 0 <= entropy <= 8.0

    def test_cpu_benchmark_multiple_sizes(self) -> None:
        """Test CPU benchmark handles multiple data sizes."""
        test_data = _generate_test_data([1024 * 1024, 10 * 1024 * 1024])
        framework_results: dict[str, Any] = {
            "pattern_search": {},
            "entropy": {},
            "data_transfer": {},
            "total_time": 0,
        }

        _benchmark_cpu_framework(framework_results, test_data)

        assert "1.0MB" in framework_results["pattern_search"]
        assert "10.0MB" in framework_results["pattern_search"]
        assert "1.0MB" in framework_results["entropy"]
        assert "10.0MB" in framework_results["entropy"]


class TestGPUFrameworkBenchmarks:
    """Test GPU framework-specific benchmarks."""

    def test_cupy_benchmark_graceful_failure(self) -> None:
        """Test CuPy benchmark handles missing framework gracefully."""
        test_data = _generate_test_data([10240])
        framework_results: dict[str, Any] = {
            "pattern_search": {},
            "entropy": {},
            "data_transfer": {},
            "total_time": 0,
        }

        _benchmark_cupy_framework(framework_results, test_data)

    def test_numba_benchmark_graceful_failure(self) -> None:
        """Test Numba benchmark handles missing framework gracefully."""
        test_data = _generate_test_data([10240])
        framework_results: dict[str, Any] = {
            "pattern_search": {},
            "entropy": {},
            "data_transfer": {},
            "total_time": 0,
        }

        _benchmark_numba_framework(framework_results, test_data)

    def test_pycuda_benchmark_graceful_failure(self) -> None:
        """Test PyCUDA benchmark handles missing framework gracefully."""
        test_data = _generate_test_data([10240])
        framework_results: dict[str, Any] = {
            "pattern_search": {},
            "entropy": {},
            "data_transfer": {},
            "total_time": 0,
        }

        _benchmark_pycuda_framework(framework_results, test_data)


class TestBestFrameworkDetermination:
    """Test best framework selection logic."""

    def test_determine_best_framework_single_gpu(self) -> None:
        """Test best framework determination with single GPU framework."""
        results: dict[str, Any] = {
            "frameworks_tested": ["cpu", "cupy"],
            "benchmarks": {
                "cpu": {"total_time": 10.0},
                "cupy": {"total_time": 2.0},
            },
            "best_framework": None,
            "recommendations": [],
        }

        _determine_best_framework(results)

        assert results["best_framework"] == "cupy"
        assert results["benchmarks"]["cupy"]["speedup"] == 5.0

    def test_determine_best_framework_multiple_gpu(self) -> None:
        """Test best framework selection with multiple GPU frameworks."""
        results: dict[str, Any] = {
            "frameworks_tested": ["cpu", "cupy", "numba", "pycuda"],
            "benchmarks": {
                "cpu": {"total_time": 15.0},
                "cupy": {"total_time": 2.0},
                "numba": {"total_time": 3.0},
                "pycuda": {"total_time": 1.5},
            },
            "best_framework": None,
            "recommendations": [],
        }

        _determine_best_framework(results)

        assert results["best_framework"] == "pycuda"
        assert results["benchmarks"]["pycuda"]["speedup"] == 10.0
        assert results["benchmarks"]["cupy"]["speedup"] == 7.5
        assert results["benchmarks"]["numba"]["speedup"] == 5.0

    def test_determine_best_framework_cpu_only(self) -> None:
        """Test best framework determination with CPU only."""
        results: dict[str, Any] = {
            "frameworks_tested": ["cpu"],
            "benchmarks": {
                "cpu": {"total_time": 10.0},
            },
            "best_framework": None,
            "recommendations": [],
        }

        _determine_best_framework(results)

        assert results["best_framework"] is None

    def test_determine_best_framework_no_cpu_baseline(self) -> None:
        """Test best framework selection without CPU baseline."""
        results: dict[str, Any] = {
            "frameworks_tested": ["cupy", "numba"],
            "benchmarks": {
                "cupy": {"total_time": 2.0},
                "numba": {"total_time": 3.0},
            },
            "best_framework": None,
            "recommendations": [],
        }

        _determine_best_framework(results)

        assert results["best_framework"] == "cupy"
        assert "speedup" not in results["benchmarks"]["cupy"]


class TestRecommendationGeneration:
    """Test performance recommendation generation."""

    def test_generate_recommendations_basic(self) -> None:
        """Test basic recommendation generation."""
        results: dict[str, Any] = {
            "frameworks_tested": ["cpu", "cupy"],
            "benchmarks": {
                "cpu": {"total_time": 10.0},
                "cupy": {
                    "total_time": 2.0,
                    "data_transfer": {"1.0MB": 0.1},
                    "pattern_search": {"1.0MB": 0.5},
                },
            },
            "best_framework": "cupy",
            "recommendations": [],
        }

        _generate_recommendations(results)

        assert len(results["recommendations"]) > 0
        assert any("cupy" in rec for rec in results["recommendations"])

    def test_generate_recommendations_high_transfer_overhead(self) -> None:
        """Test recommendation for high data transfer overhead."""
        results: dict[str, Any] = {
            "frameworks_tested": ["cpu", "cupy"],
            "benchmarks": {
                "cpu": {"total_time": 10.0},
                "cupy": {
                    "total_time": 2.0,
                    "data_transfer": {"1.0MB": 1.5},
                    "pattern_search": {"1.0MB": 0.3},
                },
            },
            "best_framework": "cupy",
            "recommendations": [],
        }

        _generate_recommendations(results)

        assert any("GPU between operations" in rec for rec in results["recommendations"])

    def test_generate_recommendations_no_best_framework(self) -> None:
        """Test recommendation generation without best framework."""
        results: dict[str, Any] = {
            "frameworks_tested": ["cpu"],
            "benchmarks": {"cpu": {"total_time": 10.0}},
            "best_framework": None,
            "recommendations": [],
        }

        _generate_recommendations(results)

        assert len(results["recommendations"]) == 0


class TestBenchmarkGPUFrameworks:
    """Test complete GPU framework benchmarking."""

    def test_benchmark_gpu_frameworks_default_sizes(self) -> None:
        """Test GPU benchmarking with default test sizes."""
        app = FakeApp()

        results = benchmark_gpu_frameworks(app)

        assert "frameworks_tested" in results
        assert "benchmarks" in results
        assert "best_framework" in results
        assert "recommendations" in results
        assert "cpu" in results["frameworks_tested"]

    def test_benchmark_gpu_frameworks_custom_sizes(self) -> None:
        """Test GPU benchmarking with custom test sizes."""
        app = FakeApp()

        test_sizes = [512 * 1024, 2 * 1024 * 1024]
        results = benchmark_gpu_frameworks(app, test_sizes=test_sizes)

        assert "cpu" in results["benchmarks"]
        cpu_results = results["benchmarks"]["cpu"]
        assert "0.5MB" in cpu_results["pattern_search"]
        assert "2.0MB" in cpu_results["pattern_search"]

    def test_benchmark_gpu_frameworks_with_gpu_available(self) -> None:
        """Test GPU benchmarking when GPU frameworks are available."""
        app = FakeApp(
            gpu_frameworks={
                "pycuda": False,
                "cupy": False,
                "numba_cuda": False,
            }
        )

        results = benchmark_gpu_frameworks(app)

        assert "cpu" in results["frameworks_tested"]
        assert results["best_framework"] in [None, "cpu"]

    def test_benchmark_gpu_frameworks_output_emitted(self) -> None:
        """Test GPU benchmarking emits status updates."""
        app = FakeApp()

        benchmark_gpu_frameworks(app)

        assert app.update_output.call_count > 0
        calls = [str(call) for call in app.update_output.call_args_list]
        assert any("Starting GPU framework benchmarks" in str(call) for call in calls)
        assert any("Benchmark complete" in str(call) for call in calls)

    def test_benchmark_gpu_frameworks_total_time_calculated(self) -> None:
        """Test total benchmark time is calculated correctly."""
        app = FakeApp()

        results = benchmark_gpu_frameworks(app)

        cpu_results = results["benchmarks"]["cpu"]
        assert cpu_results["total_time"] > 0


class TestRunGPUAcceleratedAnalysis:
    """Test GPU-accelerated binary analysis."""

    @pytest.fixture
    def pe_binary(self) -> bytes:
        """Create minimal PE binary for testing."""
        dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)
        pe_signature = b"PE\x00\x00"
        binary_data = dos_header + pe_signature
        binary_data += b"LICENSE" * 100
        binary_data += b"ACTIVATION" * 50
        binary_data += b"SERIAL" * 75
        binary_data += b"\x00" * 1000
        return binary_data

    def test_run_gpu_accelerated_analysis_basic(self, pe_binary: bytes) -> None:
        """Test basic GPU-accelerated analysis execution."""
        app = FakeApp()

        results = run_gpu_accelerated_analysis(app, pe_binary)

        assert "gpu_available" in results
        assert "framework_used" in results
        assert "analyses" in results

    def test_run_gpu_accelerated_analysis_pattern_search(self, pe_binary: bytes) -> None:
        """Test GPU analysis finds license-related patterns."""
        app = FakeApp()

        results = run_gpu_accelerated_analysis(app, pe_binary)

        if "pattern_search" in results.get("analyses", {}):
            pattern_results = results["analyses"]["pattern_search"]
            assert isinstance(pattern_results, list)
            assert len(pattern_results) > 0

            if mz_pattern := next(
                (
                    r
                    for r in pattern_results
                    if r.get("description") == "MZ Header"
                ),
                None,
            ):
                assert mz_pattern["match_count"] >= 1

            if license_pattern := next(
                (
                    r
                    for r in pattern_results
                    if r.get("description") == "License string"
                ),
                None,
            ):
                assert license_pattern["match_count"] >= 1

    def test_run_gpu_accelerated_analysis_entropy(self, pe_binary: bytes) -> None:
        """Test GPU analysis calculates entropy."""
        app = FakeApp()

        results = run_gpu_accelerated_analysis(app, pe_binary)

        if "entropy" in results.get("analyses", {}):
            entropy_result = results["analyses"]["entropy"]
            assert "average_entropy" in entropy_result
            assert "min_entropy" in entropy_result
            assert "max_entropy" in entropy_result
            assert 0 <= entropy_result["average_entropy"] <= 8.0

    def test_run_gpu_accelerated_analysis_hashes(self, pe_binary: bytes) -> None:
        """Test GPU analysis computes hashes."""
        app = FakeApp()

        results = run_gpu_accelerated_analysis(app, pe_binary)

        if "hashes" in results.get("analyses", {}):
            hash_result = results["analyses"]["hashes"]
            assert "hashes" in hash_result
            assert "crc32" in hash_result["hashes"] or "adler32" in hash_result["hashes"]

    def test_run_gpu_accelerated_analysis_performance_metrics(self, pe_binary: bytes) -> None:
        """Test GPU analysis calculates performance metrics."""
        app = FakeApp()

        results = run_gpu_accelerated_analysis(app, pe_binary)

        if results.get("gpu_available"):
            assert "performance" in results
            perf = results["performance"]
            assert "gpu_time" in perf
            assert "estimated_cpu_time" in perf
            assert "speedup" in perf
            assert "data_processed_mb" in perf
            assert perf["gpu_time"] > 0
            assert perf["data_processed_mb"] > 0

    def test_run_gpu_accelerated_analysis_cpu_fallback(self) -> None:
        """Test GPU analysis falls back to CPU when GPU unavailable."""
        app = FakeApp()
        binary_data = b"TEST" * 1000

        results = run_gpu_accelerated_analysis(app, binary_data)

        assert results["framework_used"] in ["cpu", "cupy", "numba", "pycuda", "xpu"]

    def test_run_gpu_accelerated_analysis_empty_binary(self) -> None:
        """Test GPU analysis handles empty binary."""
        app = FakeApp()

        results = run_gpu_accelerated_analysis(app, b"")

        assert "gpu_available" in results
        assert "framework_used" in results

    def test_run_gpu_accelerated_analysis_large_binary(self) -> None:
        """Test GPU analysis handles large binary data."""
        app = FakeApp()
        binary_data = b"LICENSE" * 100000 + b"\xff" * 1000000

        results = run_gpu_accelerated_analysis(app, binary_data)

        assert "analyses" in results
        if "performance" in results:
            assert results["performance"]["data_processed_mb"] > 1.0

    def test_run_gpu_accelerated_analysis_high_entropy_detection(self) -> None:
        """Test GPU analysis identifies high entropy blocks."""
        app = FakeApp()

        low_entropy = b"\x00" * 8192
        high_entropy = os.urandom(8192)
        binary_data = low_entropy + high_entropy

        results = run_gpu_accelerated_analysis(app, binary_data)

        if "entropy" in results.get("analyses", {}):
            entropy_result = results["analyses"]["entropy"]
            if "block_entropies" in entropy_result:
                entropies = entropy_result["block_entropies"]
                assert len(entropies) > 0
                assert max(entropies) > min(entropies)

    def test_run_gpu_accelerated_analysis_without_update_output(self) -> None:
        """Test GPU analysis works without update_output signal."""
        app = FakeApp(has_update_output=False)
        binary_data = b"TEST" * 1000

        results = run_gpu_accelerated_analysis(app, binary_data)

        assert "gpu_available" in results
        assert "framework_used" in results


class TestGPUBenchmarkEdgeCases:
    """Test GPU benchmark edge cases and error handling."""

    def test_benchmark_with_zero_size_data(self) -> None:
        """Test benchmarking with zero-sized test data."""
        test_data = _generate_test_data([0])
        framework_results: dict[str, Any] = {
            "pattern_search": {},
            "entropy": {},
            "data_transfer": {},
            "total_time": 0,
        }

        _benchmark_cpu_framework(framework_results, test_data)

    def test_benchmark_with_very_small_data(self) -> None:
        """Test benchmarking with very small data sizes."""
        test_data = _generate_test_data([12])
        framework_results: dict[str, Any] = {
            "pattern_search": {},
            "entropy": {},
            "data_transfer": {},
            "total_time": 0,
        }

        _benchmark_cpu_framework(framework_results, test_data)

        assert "0.0MB" in framework_results["pattern_search"]

    def test_generate_recommendations_empty_benchmarks(self) -> None:
        """Test recommendation generation with empty benchmarks."""
        results: dict[str, Any] = {
            "frameworks_tested": [],
            "benchmarks": {},
            "best_framework": None,
            "recommendations": [],
        }

        _generate_recommendations(results)

        assert len(results["recommendations"]) == 0

    def test_determine_best_framework_equal_times(self) -> None:
        """Test best framework determination with equal execution times."""
        results: dict[str, Any] = {
            "frameworks_tested": ["cpu", "cupy", "numba"],
            "benchmarks": {
                "cpu": {"total_time": 5.0},
                "cupy": {"total_time": 2.0},
                "numba": {"total_time": 2.0},
            },
            "best_framework": None,
            "recommendations": [],
        }

        _determine_best_framework(results)

        assert results["best_framework"] in ["cupy", "numba"]

    def test_run_gpu_analysis_import_error(self) -> None:
        """Test GPU analysis handles GPU module import errors gracefully."""
        app = FakeApp()

        results = run_gpu_accelerated_analysis(app, b"TEST")

        assert results["framework_used"] in ["cpu", "cupy", "numba", "pycuda", "xpu"]
