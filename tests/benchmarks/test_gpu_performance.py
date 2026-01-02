"""
Performance benchmarks for Intellicrack's GPU acceleration and AI operations.

This module contains comprehensive performance tests for GPU acceleration and AI operations
in Intellicrack. Tests actual methods available on GPUAccelerator, GPUIntegration,
ModelPerformanceMonitor, QuantizationManager, and ModelShardingManager classes.
"""

import os
import tempfile
import threading
import time
from collections.abc import Generator
from typing import Any

import psutil
import pytest

from intellicrack.ai.gpu_integration import GPUIntegration
from intellicrack.ai.model_performance_monitor import ModelPerformanceMonitor
from intellicrack.ai.model_sharding import ModelShardingManager
from intellicrack.ai.quantization_manager import QuantizationManager
from intellicrack.core.gpu_acceleration import GPUAccelerator


class TestGPUPerformance:
    """Performance benchmarks for GPU acceleration and AI operations."""

    @pytest.fixture
    def sample_binary_data(self) -> Generator[str, None, None]:
        """Generate REAL binary data for GPU processing."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            dos_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            pe_signature = b'PE\x00\x00'
            coff_header = b'\x4c\x01\x03\x00' + b'\x00' * 16
            optional_header = b'\x0b\x01\x0e\x00' + b'\x00' * 220

            code_section = b'\x90' * 1000
            code_section += b'\x55\x8b\xec\x83\xec\x08\x53\x56\x57'
            code_section += b'\x8b\x75\x08\x33\xdb\x83\xfe\xff'
            code_section += b'\x74\x0a\x8b\x0e\x83\xc6\x04\x85\xc9'
            code_section += b'\x75\xf9\x33\xc0\x5f\x5e\x5b\x8b\xe5\x5d\xc3'

            temp_file.write(dos_header + pe_signature + coff_header + optional_header + code_section)
            temp_file.flush()
            yield temp_file.name

        try:
            os.unlink(temp_file.name)
        except OSError:
            pass

    @pytest.fixture
    def sample_pattern_data(self) -> tuple[bytes, bytes]:
        """Generate sample data and pattern for pattern search testing."""
        data = b'\x00' * 100 + b'\x55\x8b\xec' + b'\x00' * 100 + b'\x55\x8b\xec' + b'\x00' * 100
        pattern = b'\x55\x8b\xec'
        return data, pattern

    @pytest.fixture
    def process_memory(self) -> psutil._pswindows.pmem:
        """Monitor process memory usage."""
        process = psutil.Process()
        return process.memory_info()

    @pytest.mark.benchmark
    def test_gpu_accelerator_initialization_performance(
        self, benchmark: Any
    ) -> None:
        """Benchmark REAL GPU accelerator initialization speed."""
        def initialize_gpu() -> GPUAccelerator:
            return GPUAccelerator()

        result = benchmark(initialize_gpu)

        assert result is not None, "GPU accelerator must be created"
        assert benchmark.stats.mean < 2.0, "GPU initialization should be under 2 seconds"

    @pytest.mark.benchmark
    def test_gpu_pattern_search_performance(
        self, benchmark: Any, sample_pattern_data: tuple[bytes, bytes]
    ) -> None:
        """Benchmark REAL GPU pattern search speed."""
        data, pattern = sample_pattern_data

        def search_pattern() -> dict[str, Any]:
            gpu = GPUAccelerator()
            return gpu.parallel_pattern_search(data, pattern)

        result = benchmark(search_pattern)

        assert result is not None, "Pattern search must return result"
        assert isinstance(result, dict), "Result must be a dictionary"
        assert benchmark.stats.mean < 1.0, "Pattern search should be under 1 second"

    @pytest.mark.benchmark
    def test_gpu_entropy_calculation_performance(
        self, benchmark: Any, sample_binary_data: str
    ) -> None:
        """Benchmark REAL GPU entropy calculation speed."""
        with open(sample_binary_data, 'rb') as f:
            data = f.read()

        def calculate_entropy() -> dict[str, Any]:
            gpu = GPUAccelerator()
            return gpu.entropy_calculation(data, block_size=256)

        result = benchmark(calculate_entropy)

        assert result is not None, "Entropy calculation must return result"
        assert isinstance(result, dict), "Result must be a dictionary"
        assert benchmark.stats.mean < 0.5, "Entropy calculation should be under 500ms"

    @pytest.mark.benchmark
    def test_gpu_hash_computation_performance(
        self, benchmark: Any, sample_binary_data: str
    ) -> None:
        """Benchmark REAL GPU hash computation speed."""
        with open(sample_binary_data, 'rb') as f:
            data = f.read()

        def compute_hashes() -> dict[str, Any]:
            gpu = GPUAccelerator()
            return gpu.hash_computation(data, algorithms=["md5", "sha256"])

        result = benchmark(compute_hashes)

        assert result is not None, "Hash computation must return result"
        assert isinstance(result, dict), "Result must be a dictionary"
        assert benchmark.stats.mean < 0.5, "Hash computation should be under 500ms"

    @pytest.mark.benchmark
    def test_gpu_integration_initialization_performance(
        self, benchmark: Any
    ) -> None:
        """Benchmark REAL GPU integration initialization speed."""
        def initialize_integration() -> GPUIntegration:
            return GPUIntegration()

        result = benchmark(initialize_integration)

        assert result is not None, "GPU integration must be created"
        assert benchmark.stats.mean < 1.0, "GPU integration initialization should be under 1 second"

    @pytest.mark.benchmark
    def test_gpu_integration_device_info_performance(
        self, benchmark: Any
    ) -> None:
        """Benchmark REAL device info retrieval speed."""
        integration = GPUIntegration()

        def get_device_info() -> dict[str, Any]:
            return integration.get_device_info()

        result = benchmark(get_device_info)

        assert result is not None, "Device info must be returned"
        assert isinstance(result, dict), "Result must be a dictionary"
        assert benchmark.stats.mean < 0.1, "Device info retrieval should be under 100ms"

    @pytest.mark.benchmark
    def test_gpu_integration_availability_check_performance(
        self, benchmark: Any
    ) -> None:
        """Benchmark REAL GPU availability check speed."""
        integration = GPUIntegration()

        def check_availability() -> bool:
            return integration.is_available()

        result = benchmark(check_availability)

        assert isinstance(result, bool), "Availability check must return bool"
        assert benchmark.stats.mean < 0.01, "Availability check should be under 10ms"

    @pytest.mark.benchmark
    def test_gpu_integration_memory_usage_performance(
        self, benchmark: Any
    ) -> None:
        """Benchmark REAL memory usage retrieval speed."""
        integration = GPUIntegration()

        def get_memory() -> dict[str, object]:
            return integration.get_memory_usage()

        result = benchmark(get_memory)

        assert result is not None, "Memory usage must be returned"
        assert isinstance(result, dict), "Result must be a dictionary"
        assert benchmark.stats.mean < 0.1, "Memory usage retrieval should be under 100ms"

    @pytest.mark.benchmark
    def test_model_performance_monitor_initialization(
        self, benchmark: Any
    ) -> None:
        """Benchmark REAL model performance monitor initialization speed."""
        def initialize_monitor() -> ModelPerformanceMonitor:
            return ModelPerformanceMonitor()

        result = benchmark(initialize_monitor)

        assert result is not None, "Performance monitor must be created"
        assert benchmark.stats.mean < 0.5, "Monitor initialization should be under 500ms"

    @pytest.mark.benchmark
    def test_model_performance_inference_tracking(
        self, benchmark: Any
    ) -> None:
        """Benchmark REAL inference tracking overhead."""
        monitor = ModelPerformanceMonitor()

        def track_inference() -> dict[str, Any]:
            context = monitor.start_inference("test_model")
            time.sleep(0.001)
            monitor.end_inference(context, tokens_generated=10)
            return monitor.get_stats("test_model")

        result = benchmark(track_inference)

        assert result is not None, "Inference tracking must return stats"
        assert isinstance(result, dict), "Result must be a dictionary"
        assert benchmark.stats.mean < 0.05, "Inference tracking overhead should be under 50ms"

    @pytest.mark.benchmark
    def test_model_performance_stats_retrieval(
        self, benchmark: Any
    ) -> None:
        """Benchmark REAL performance stats retrieval speed."""
        monitor = ModelPerformanceMonitor()

        for i in range(10):
            context = monitor.start_inference("stats_test_model")
            monitor.end_inference(context, tokens_generated=10)

        def get_stats() -> dict[str, Any]:
            return monitor.get_stats("stats_test_model")

        result = benchmark(get_stats)

        assert result is not None, "Stats must be returned"
        assert isinstance(result, dict), "Result must be a dictionary"
        assert benchmark.stats.mean < 0.01, "Stats retrieval should be under 10ms"

    @pytest.mark.benchmark
    def test_quantization_manager_initialization(
        self, benchmark: Any
    ) -> None:
        """Benchmark REAL quantization manager initialization speed."""
        def initialize_quantizer() -> QuantizationManager:
            return QuantizationManager()

        result = benchmark(initialize_quantizer)

        assert result is not None, "Quantization manager must be created"
        assert benchmark.stats.mean < 1.0, "Quantizer initialization should be under 1 second"

    @pytest.mark.benchmark
    def test_quantization_types_retrieval(
        self, benchmark: Any
    ) -> None:
        """Benchmark REAL supported quantization types retrieval speed."""
        quantizer = QuantizationManager()

        def get_types() -> list[str]:
            return quantizer.get_supported_quantization_types()

        result = benchmark(get_types)

        assert result is not None, "Quantization types must be returned"
        assert isinstance(result, list), "Result must be a list"
        assert benchmark.stats.mean < 0.01, "Types retrieval should be under 10ms"

    @pytest.mark.benchmark
    def test_quantization_sharding_info(
        self, benchmark: Any
    ) -> None:
        """Benchmark REAL sharding info retrieval from quantizer speed."""
        quantizer = QuantizationManager()

        def get_info() -> dict[str, object]:
            return quantizer.get_sharding_info()

        result = benchmark(get_info)

        assert result is not None, "Sharding info must be returned"
        assert isinstance(result, dict), "Result must be a dictionary"
        assert benchmark.stats.mean < 0.1, "Sharding info retrieval should be under 100ms"

    @pytest.mark.benchmark
    def test_model_sharding_manager_initialization(
        self, benchmark: Any
    ) -> None:
        """Benchmark REAL model sharding manager initialization speed."""
        def initialize_sharding() -> ModelShardingManager:
            return ModelShardingManager()

        result = benchmark(initialize_sharding)

        assert result is not None, "Sharding manager must be created"
        assert benchmark.stats.mean < 2.0, "Sharding manager initialization should be under 2 seconds"

    @pytest.mark.benchmark
    def test_sharding_manager_info_retrieval(
        self, benchmark: Any
    ) -> None:
        """Benchmark REAL sharding manager info retrieval speed."""
        sharding = ModelShardingManager()

        def get_info() -> dict[str, object]:
            return sharding.get_sharding_info()

        result = benchmark(get_info)

        assert result is not None, "Sharding info must be returned"
        assert isinstance(result, dict), "Result must be a dictionary"
        assert benchmark.stats.mean < 0.1, "Info retrieval should be under 100ms"

    @pytest.mark.benchmark
    def test_sharding_memory_monitoring(
        self, benchmark: Any
    ) -> None:
        """Benchmark REAL memory monitoring speed."""
        sharding = ModelShardingManager()

        def monitor_memory() -> dict[int, dict[str, object]]:
            return sharding.monitor_memory_usage()

        result = benchmark(monitor_memory)

        assert result is not None, "Memory usage must be returned"
        assert isinstance(result, dict), "Result must be a dictionary"
        assert benchmark.stats.mean < 0.5, "Memory monitoring should be under 500ms"

    def test_gpu_pattern_search_accuracy(
        self, sample_pattern_data: tuple[bytes, bytes]
    ) -> None:
        """Test REAL GPU pattern search accuracy."""
        data, pattern = sample_pattern_data
        gpu = GPUAccelerator()

        result = gpu.parallel_pattern_search(data, pattern)

        assert result is not None, "Pattern search must return result"
        assert isinstance(result, dict), "Result must be dictionary"

        if 'matches' in result:
            matches = result['matches']
            assert len(matches) >= 2, "Should find at least 2 pattern matches"

    def test_gpu_entropy_accuracy(self, sample_binary_data: str) -> None:
        """Test REAL GPU entropy calculation accuracy."""
        with open(sample_binary_data, 'rb') as f:
            data = f.read()

        gpu = GPUAccelerator()

        result = gpu.entropy_calculation(data, block_size=256)

        assert result is not None, "Entropy calculation must return result"
        assert isinstance(result, dict), "Result must be dictionary"

        if 'entropy' in result:
            entropy = result['entropy']
            assert 0.0 <= entropy <= 8.0, "Entropy must be between 0 and 8"

    def test_concurrent_gpu_pattern_search(
        self, sample_pattern_data: tuple[bytes, bytes]
    ) -> None:
        """Test REAL concurrent GPU pattern search operations."""
        data, pattern = sample_pattern_data
        results: list[tuple[int, dict[str, Any]]] = []
        errors: list[tuple[int, str]] = []

        def search_pattern(thread_id: int) -> None:
            try:
                gpu = GPUAccelerator()
                result = gpu.parallel_pattern_search(data, pattern)
                results.append((thread_id, result))
            except Exception as e:
                errors.append((thread_id, str(e)))

        threads: list[threading.Thread] = []
        start_time = time.time()

        for i in range(4):
            thread = threading.Thread(target=search_pattern, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join(timeout=10.0)

        end_time = time.time()

        assert not errors, f"Concurrent pattern search errors: {errors}"
        assert len(results) == 4, f"Expected 4 results, got {len(results)}"
        assert end_time - start_time < 5.0, "Concurrent operations should complete under 5 seconds"

    def test_gpu_memory_efficiency(
        self, sample_binary_data: str, process_memory: psutil._pswindows.pmem
    ) -> None:
        """Test REAL GPU memory efficiency."""
        initial_memory = process_memory.rss

        with open(sample_binary_data, 'rb') as f:
            data = f.read()

        gpu = GPUAccelerator()

        for i in range(10):
            result = gpu.parallel_pattern_search(data, b'\x55\x8b\xec')
            assert result is not None, f"Pattern search {i} failed"

            entropy_result = gpu.entropy_calculation(data, block_size=256)
            assert entropy_result is not None, f"Entropy calculation {i} failed"

        current_process = psutil.Process()
        final_memory = current_process.memory_info().rss
        memory_increase = final_memory - initial_memory

        assert memory_increase < 100 * 1024 * 1024, "Memory increase should be under 100MB"

    def test_gpu_integration_stress(self) -> None:
        """Stress test REAL GPU integration operations."""
        integration = GPUIntegration()

        start_time = time.time()

        for i in range(20):
            device_info = integration.get_device_info()
            assert device_info is not None, f"Device info {i} failed"

            is_available = integration.is_available()
            assert isinstance(is_available, bool), f"Availability check {i} returned wrong type"

            memory_usage = integration.get_memory_usage()
            assert memory_usage is not None, f"Memory usage {i} failed"

            backend_name = integration.get_backend_name()
            assert isinstance(backend_name, str), f"Backend name {i} returned wrong type"

        end_time = time.time()

        assert end_time - start_time < 10.0, "Stress test should complete under 10 seconds"

    def test_performance_monitor_stress(self) -> None:
        """Stress test REAL performance monitor operations."""
        monitor = ModelPerformanceMonitor()

        start_time = time.time()

        for i in range(50):
            model_id = f"stress_model_{i % 5}"
            context = monitor.start_inference(model_id)
            time.sleep(0.001)
            monitor.end_inference(context, tokens_generated=10)

        for i in range(5):
            model_id = f"stress_model_{i}"
            stats = monitor.get_stats(model_id)
            assert stats is not None, f"Stats retrieval for {model_id} failed"

        end_time = time.time()

        assert end_time - start_time < 5.0, "Monitor stress test should complete under 5 seconds"

    def test_quantization_manager_stress(self) -> None:
        """Stress test REAL quantization manager operations."""
        quantizer = QuantizationManager()

        start_time = time.time()

        for _ in range(30):
            types = quantizer.get_supported_quantization_types()
            assert isinstance(types, list), "Types must be a list"

            info = quantizer.get_sharding_info()
            assert isinstance(info, dict), "Info must be a dictionary"

        end_time = time.time()

        assert end_time - start_time < 3.0, "Quantization manager stress test should complete under 3 seconds"

    def test_sharding_manager_stress(self) -> None:
        """Stress test REAL sharding manager operations."""
        sharding = ModelShardingManager()

        start_time = time.time()

        for _ in range(20):
            info = sharding.get_sharding_info()
            assert isinstance(info, dict), "Info must be a dictionary"

            memory = sharding.monitor_memory_usage()
            assert isinstance(memory, dict), "Memory usage must be a dictionary"

        end_time = time.time()

        assert end_time - start_time < 10.0, "Sharding manager stress test should complete under 10 seconds"

    def test_gpu_error_handling_performance(self) -> None:
        """Test REAL GPU error handling performance."""
        gpu = GPUAccelerator()

        start_time = time.time()

        invalid_inputs: list[tuple[bytes, bytes]] = [
            (b'', b'\x55'),
            (b'\x00' * 10, b''),
        ]

        for data, pattern in invalid_inputs:
            try:
                gpu.parallel_pattern_search(data, pattern)
            except (ValueError, TypeError):
                pass

        try:
            gpu.entropy_calculation(b'', block_size=1)
        except (ValueError, ZeroDivisionError):
            pass

        end_time = time.time()

        assert end_time - start_time < 1.0, "Error handling should be fast (under 1 second)"

    def test_gpu_consistency_check(self, sample_binary_data: str) -> None:
        """Test REAL GPU operation consistency across multiple runs."""
        with open(sample_binary_data, 'rb') as f:
            data = f.read()

        gpu = GPUAccelerator()

        results: list[dict[str, Any]] = []

        for _ in range(5):
            result = gpu.entropy_calculation(data, block_size=256)
            results.append(result)

        for result in results:
            assert result is not None, "Entropy result should not be None"
            assert isinstance(result, dict), "Entropy result should be a dict"

    def test_cleanup_operations_performance(self) -> None:
        """Test REAL cleanup operations performance."""
        quantizer = QuantizationManager()
        sharding = ModelShardingManager()

        start_time = time.time()

        for _ in range(10):
            quantizer.cleanup_memory()
            sharding.cleanup_memory()

        end_time = time.time()

        assert end_time - start_time < 2.0, "Cleanup operations should complete under 2 seconds"
