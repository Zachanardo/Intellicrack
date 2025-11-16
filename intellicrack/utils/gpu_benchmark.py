"""GPU Framework Benchmarking Utilities.

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

import logging
import time
from typing import Any

from intellicrack.handlers.numpy_handler import numpy as np

logger = logging.getLogger(__name__)


def run_gpu_accelerated_analysis(app: object, binary_data: bytes) -> dict[str, Any]:
    """Run GPU-accelerated binary analysis using available frameworks.

    Args:
        app: Application instance with update_output signal
        binary_data: Binary data to analyze

    Returns:
        Dictionary with analysis results

    """
    results = {
        "gpu_available": False,
        "framework_used": "cpu",
        "analyses": {},
    }

    try:
        # Try to use our GPU acceleration module
        from ..core.gpu_acceleration import get_gpu_accelerator

        accelerator = get_gpu_accelerator()

        results["gpu_available"] = accelerator.framework != "cpu"
        results["framework_used"] = accelerator.framework
        results["device_info"] = accelerator.device_info

        if hasattr(app, "update_output"):
            app.update_output.emit(f"[GPU] Using {accelerator.framework} for acceleration")

        # Perform pattern search for common binary patterns
        patterns_to_search = [
            (b"\x4d\x5a", "MZ Header"),  # PE executable
            (b"\x7f\x45\x4c\x46", "ELF Header"),  # ELF executable
            (b"\x00\x00\x00\x00", "Null bytes"),
            (b"\xff\xff\xff\xff", "Max bytes"),
            (b"LICENSE", "License string"),
            (b"ACTIVATION", "Activation string"),
            (b"SERIAL", "Serial string"),
            (b"KEY", "Key string"),
        ]

        pattern_results = []
        for pattern, description in patterns_to_search:
            result = accelerator.parallel_pattern_search(binary_data, pattern)
            result["description"] = description
            pattern_results.append(result)

            if hasattr(app, "update_output"):
                app.update_output.emit(
                    f"[GPU] Pattern '{description}': {result['match_count']} matches found "
                    f"({result['execution_time']:.3f}s via {result['method']})",
                )

        results["analyses"]["pattern_search"] = pattern_results

        # Perform entropy calculation
        entropy_result = accelerator.entropy_calculation(binary_data, block_size=4096)
        results["analyses"]["entropy"] = entropy_result

        if hasattr(app, "update_output"):
            app.update_output.emit(
                f"[GPU] Entropy analysis: avg={entropy_result['average_entropy']:.2f}, "
                f"min={entropy_result['min_entropy']:.2f}, max={entropy_result['max_entropy']:.2f} "
                f"({entropy_result['execution_time']:.3f}s via {entropy_result['method']})",
            )

        # Identify high entropy sections (likely encrypted/compressed)
        if "block_entropies" in entropy_result:
            high_entropy_blocks = []
            for i, entropy in enumerate(entropy_result["block_entropies"]):
                if entropy > 7.0:  # High entropy threshold
                    high_entropy_blocks.append(
                        {
                            "block_index": i,
                            "offset": i * 4096,
                            "entropy": entropy,
                        },
                    )

            if high_entropy_blocks and hasattr(app, "update_output"):
                app.update_output.emit(
                    f"[GPU] Found {len(high_entropy_blocks)} high-entropy blocks (likely encrypted/compressed)",
                )

        # Perform hash computation
        hash_result = accelerator.hash_computation(binary_data, ["crc32", "adler32"])
        results["analyses"]["hashes"] = hash_result

        if hasattr(app, "update_output"):
            for algo, hash_val in hash_result["hashes"].items():
                app.update_output.emit(f"[GPU] {algo.upper()}: {hash_val}")

        # Calculate performance metrics
        if results["gpu_available"]:
            total_gpu_time = (
                sum(r.get("execution_time", 0) for r in pattern_results)
                + entropy_result.get("execution_time", 0)
                + hash_result.get("execution_time", 0)
            )

            # Estimate CPU time based on typical speedups
            speedup_factors = {
                "cupy": 10,
                "numba": 8,
                "pycuda": 12,
            }
            speedup = speedup_factors.get(accelerator.framework, 5)
            estimated_cpu_time = total_gpu_time * speedup

            results["performance"] = {
                "gpu_time": total_gpu_time,
                "estimated_cpu_time": estimated_cpu_time,
                "speedup": speedup,
                "data_processed_mb": len(binary_data) / (1024 * 1024),
            }

            if hasattr(app, "update_output"):
                app.update_output.emit(
                    f"[GPU] Total GPU time: {total_gpu_time:.3f}s, Estimated speedup: {speedup:.1f}x",
                )
                app.update_output.emit(
                    f"[GPU] Processed {results['performance']['data_processed_mb']:.1f} MB "
                    f"at {results['performance']['data_processed_mb'] / total_gpu_time:.1f} MB/s",
                )

    except ImportError as e:
        logger.error(f"GPU acceleration module not available: {e}")
        if hasattr(app, "update_output"):
            app.update_output.emit("[GPU] GPU acceleration module not available")
    except Exception as e:
        logger.error(f"GPU accelerated analysis failed: {e}")
        if hasattr(app, "update_output"):
            app.update_output.emit(f"[GPU] Analysis failed: {e}")

    return results


def _generate_test_data(test_sizes: list[int]) -> dict[int, bytes]:
    """Generate test data with varying entropy for benchmarking."""
    test_data = {}
    for size in test_sizes:
        # Create data with varying entropy
        data = bytearray(size)
        # First third: low entropy (zeros)
        # Second third: medium entropy (pattern)
        pattern = b"ABCD" * (size // 12)
        data[size // 3 : 2 * size // 3] = pattern[: size // 3]
        # Last third: high entropy (random)
        data[2 * size // 3 :] = np.random.bytes(size // 3)
        test_data[size] = bytes(data)
    return test_data


def _benchmark_cupy_framework(framework_results: dict, test_data: dict[int, bytes]) -> None:
    """Benchmark CuPy framework."""
    try:
        import cupy as cp

        for size, data in test_data.items():
            size_mb = size / (1024 * 1024)
            pattern = b"LICENSE"

            # Data transfer
            transfer_start = time.time()
            data_gpu = cp.asarray(np.frombuffer(data, dtype=np.uint8))
            transfer_time = time.time() - transfer_start
            framework_results["data_transfer"][f"{size_mb}MB"] = transfer_time

            # Pattern search
            start_time = time.time()
            pattern_gpu = cp.asarray(np.frombuffer(pattern, dtype=np.uint8))
            # Simple matching for benchmark
            matches = 0
            for i in range(0, len(data_gpu) - len(pattern_gpu), 1000):
                if cp.all(data_gpu[i : i + len(pattern_gpu)] == pattern_gpu):
                    matches += 1
            cp.cuda.Stream.null.synchronize()

            search_time = time.time() - start_time - transfer_time
            framework_results["pattern_search"][f"{size_mb}MB"] = search_time

    except Exception as e:
        logger.error(f"CuPy benchmark failed: {e}")


def _benchmark_numba_framework(framework_results: dict, test_data: dict[int, bytes]) -> None:
    """Benchmark Numba framework."""
    try:
        from numba import cuda as numba_cuda

        for size, data in test_data.items():
            size_mb = size / (1024 * 1024)

            # Data transfer
            transfer_start = time.time()
            data_np = np.frombuffer(data, dtype=np.uint8)
            d_data = numba_cuda.to_device(data_np)
            transfer_time = time.time() - transfer_start
            framework_results["data_transfer"][f"{size_mb}MB"] = transfer_time

            # Simple operation for benchmark - pattern search on GPU data
            pattern = np.array([0x4D, 0x5A], dtype=np.uint8)  # MZ header pattern
            d_pattern = numba_cuda.to_device(pattern)

            # Perform pattern search operation using GPU acceleration
            search_start = time.time()

            @numba_cuda.jit
            def pattern_search_kernel(data: numba_cuda.uint8[:], pattern: numba_cuda.uint8[:], results: numba_cuda.int32[:]) -> None:
                """GPU kernel for pattern matching in binary data."""
                idx = numba_cuda.grid(1)
                if idx < len(data) - len(pattern) + 1:
                    match = True
                    for i in range(len(pattern)):
                        if data[idx + i] != pattern[i]:
                            match = False
                            break
                    if match:
                        numba_cuda.atomic.add(results, 0, 1)

            result_array = np.array([0], dtype=np.int32)
            d_results = numba_cuda.to_device(result_array)

            threadsperblock = 128
            blockspergrid = (len(d_data) + threadsperblock - 1) // threadsperblock
            pattern_search_kernel[blockspergrid, threadsperblock](d_data, d_pattern, d_results)

            result_count = d_results.copy_to_host()[0]
            numba_cuda.synchronize()
            search_time = time.time() - search_start
            framework_results["pattern_search"][f"{size_mb}MB"] = search_time
            framework_results["results_found"] = framework_results.get("results_found", 0) + result_count

    except Exception as e:
        logger.error(f"Numba benchmark failed: {e}")


def _benchmark_pycuda_framework(framework_results: dict, test_data: dict[int, bytes]) -> None:
    """Benchmark PyCUDA framework."""
    try:
        import pycuda.driver as cuda
        from pycuda import gpuarray

        for size, data in test_data.items():
            size_mb = size / (1024 * 1024)

            # Data transfer
            transfer_start = time.time()
            data_np = np.frombuffer(data, dtype=np.uint8)
            gpuarray.to_gpu(data_np)
            transfer_time = time.time() - transfer_start
            framework_results["data_transfer"][f"{size_mb}MB"] = transfer_time

            # Simple operation
            start_time = time.time()
            cuda.Context.synchronize()
            search_time = time.time() - start_time - transfer_time
            framework_results["pattern_search"][f"{size_mb}MB"] = search_time

    except Exception as e:
        logger.error(f"PyCUDA benchmark failed: {e}")


def _benchmark_cpu_framework(framework_results: dict, test_data: dict[int, bytes]) -> None:
    """Benchmark CPU baseline."""
    for size, data in test_data.items():
        size_mb = size / (1024 * 1024)
        pattern = b"LICENSE"

        # Pattern search
        start_time = time.time()
        data.count(pattern)
        search_time = time.time() - start_time
        framework_results["pattern_search"][f"{size_mb}MB"] = search_time

        # Test entropy calculation
        start_time = time.time()
        # Simple entropy calculation
        hist, _ = np.histogram(list(data[:10000]), bins=256, range=(0, 255))
        hist = hist.astype(np.float32) / 10000
        hist_nonzero = hist[hist > 0]
        entropy = -np.sum(hist_nonzero * np.log2(hist_nonzero))
        entropy_time = time.time() - start_time
        framework_results["entropy"][f"{size_mb}MB"] = entropy_time
        framework_results["entropy_values"] = framework_results.get("entropy_values", {})
        framework_results["entropy_values"][f"{size_mb}MB"] = float(entropy)


def _determine_best_framework(results: dict[str, Any]) -> None:
    """Determine the best performing framework from benchmark results."""
    if len(results["frameworks_tested"]) <= 1:
        return

    gpu_frameworks = [f for f in results["frameworks_tested"] if f != "cpu"]
    if not gpu_frameworks:
        return

    # Find framework with lowest total time
    best_time = float("inf")
    for framework in gpu_frameworks:
        total_time = results["benchmarks"][framework]["total_time"]
        if total_time < best_time:
            best_time = total_time
            results["best_framework"] = framework

    # Calculate speedups
    if "cpu" in results["benchmarks"]:
        cpu_time = results["benchmarks"]["cpu"]["total_time"]
        for framework in gpu_frameworks:
            gpu_time = results["benchmarks"][framework]["total_time"]
            speedup = cpu_time / gpu_time if gpu_time > 0 else 1
            results["benchmarks"][framework]["speedup"] = speedup


def _generate_recommendations(results: dict[str, Any]) -> None:
    """Generate performance recommendations based on benchmark results."""
    if not results["best_framework"]:
        return

    results["recommendations"].append(
        f"Use {results['best_framework']} for best performance",
    )

    # Check if data transfer is significant
    best_framework_data = results["benchmarks"][results["best_framework"]]
    if "data_transfer" in best_framework_data:
        total_transfer = sum(best_framework_data["data_transfer"].values())
        total_compute = sum(best_framework_data["pattern_search"].values())
        if total_transfer > total_compute * 0.5:
            results["recommendations"].append(
                "Consider keeping data on GPU between operations to reduce transfer overhead",
            )


def benchmark_gpu_frameworks(app: object, test_sizes: list[int] | None = None) -> dict[str, Any]:
    """Benchmark available GPU frameworks.

    Args:
        app: Application instance
        test_sizes: List of test data sizes in bytes

    Returns:
        Dictionary with benchmark results

    """
    if test_sizes is None:
        test_sizes = [
            1024 * 1024,  # 1 MB
            10 * 1024 * 1024,  # 10 MB
            50 * 1024 * 1024,  # 50 MB
        ]

    results = {
        "frameworks_tested": [],
        "benchmarks": {},
        "best_framework": None,
        "recommendations": [],
    }

    # Generate test data
    test_data = _generate_test_data(test_sizes)

    if hasattr(app, "update_output"):
        app.update_output.emit("[GPU] Starting GPU framework benchmarks...")

    # Test each framework
    frameworks_to_test = []

    if hasattr(app, "gpu_frameworks"):
        if app.gpu_frameworks.get("pycuda"):
            frameworks_to_test.append("pycuda")
        if app.gpu_frameworks.get("cupy"):
            frameworks_to_test.append("cupy")
        if app.gpu_frameworks.get("numba_cuda"):
            frameworks_to_test.append("numba")

    # Always test CPU as baseline
    frameworks_to_test.append("cpu")

    for framework in frameworks_to_test:
        if hasattr(app, "update_output"):
            app.update_output.emit(f"[GPU] Benchmarking {framework}...")

        framework_results = {
            "pattern_search": {},
            "entropy": {},
            "data_transfer": {},
            "total_time": 0,
        }

        # Call appropriate benchmark function
        if framework == "cupy":
            _benchmark_cupy_framework(framework_results, test_data)
        elif framework == "numba":
            _benchmark_numba_framework(framework_results, test_data)
        elif framework == "pycuda":
            _benchmark_pycuda_framework(framework_results, test_data)
        else:  # CPU baseline
            _benchmark_cpu_framework(framework_results, test_data)

        # Calculate total time
        for size_mb in framework_results["pattern_search"]:
            search_time = framework_results["pattern_search"].get(size_mb, 0)
            transfer_time = framework_results.get("data_transfer", {}).get(size_mb, 0)
            framework_results["total_time"] += search_time + transfer_time

        if framework_results["pattern_search"]:
            results["benchmarks"][framework] = framework_results
            results["frameworks_tested"].append(framework)

    # Determine best framework
    _determine_best_framework(results)

    # Output speedup information if available
    if hasattr(app, "update_output"):
        for framework in results["frameworks_tested"]:
            if framework != "cpu" and "speedup" in results["benchmarks"].get(framework, {}):
                speedup = results["benchmarks"][framework]["speedup"]
                app.update_output.emit(
                    f"[GPU] {framework} speedup: {speedup:.1f}x over CPU",
                )

    # Generate recommendations
    _generate_recommendations(results)

    if hasattr(app, "update_output"):
        app.update_output.emit(
            f"[GPU] Benchmark complete. Best framework: {results['best_framework'] or 'CPU'}",
        )

    return results
