import pytest
import time
import threading
import tempfile
import os
import psutil

from intellicrack.core.gpu_acceleration import GPUAcceleration
from intellicrack.core.processing.gpu_accelerator import GPUAccelerator
from intellicrack.ai.gpu_integration import GPUIntegration
from intellicrack.ai.model_performance_monitor import ModelPerformanceMonitor
from intellicrack.ai.quantization_manager import QuantizationManager
from intellicrack.ai.model_sharding import ModelSharding
from tests.base_test import IntellicrackTestBase


class TestGPUPerformance(IntellicrackTestBase):
    """Performance benchmarks for GPU acceleration and AI operations."""

    @pytest.fixture
    def sample_matrix_data(self):
        """Generate REAL matrix data for GPU testing."""
        import numpy as np
        return np.random.rand(1000, 1000).astype(np.float32)

    @pytest.fixture
    def sample_binary_data(self):
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
        except:
            pass

    @pytest.fixture
    def process_memory(self):
        """Monitor process memory usage."""
        process = psutil.Process()
        return process.memory_info()

    @pytest.mark.benchmark
    def test_gpu_initialization_performance(self, benchmark):
        """Benchmark REAL GPU initialization speed."""
        def initialize_gpu():
            gpu = GPUAcceleration()
            return gpu.initialize_gpu_context()
        
        result = benchmark(initialize_gpu)
        
        self.assert_real_output(result)
        assert result.get('initialized', False), "GPU must be initialized successfully"
        assert benchmark.stats.mean < 2.0, "GPU initialization should be under 2 seconds"

    @pytest.mark.benchmark
    def test_gpu_memory_allocation_performance(self, benchmark, sample_matrix_data):
        """Benchmark REAL GPU memory allocation speed."""
        def allocate_gpu_memory():
            gpu = GPUAccelerator()
            return gpu.allocate_memory(sample_matrix_data)
        
        result = benchmark(allocate_gpu_memory)
        
        self.assert_real_output(result)
        assert result.get('allocated', False), "Memory must be allocated successfully"
        assert benchmark.stats.mean < 0.1, "GPU memory allocation should be under 100ms"

    @pytest.mark.benchmark
    def test_gpu_matrix_multiplication_performance(self, benchmark, sample_matrix_data):
        """Benchmark REAL GPU matrix multiplication speed."""
        def gpu_matrix_multiply():
            gpu = GPUAccelerator()
            return gpu.matrix_multiply(sample_matrix_data, sample_matrix_data)
        
        result = benchmark(gpu_matrix_multiply)
        
        self.assert_real_output(result)
        assert result.shape == (1000, 1000), "Result must have correct dimensions"
        assert benchmark.stats.mean < 0.5, "GPU matrix multiplication should be under 500ms"

    @pytest.mark.benchmark
    def test_ai_model_loading_performance(self, benchmark):
        """Benchmark REAL AI model loading speed."""
        def load_ai_model():
            integration = GPUIntegration()
            return integration.load_model("small_test_model")
        
        result = benchmark(load_ai_model)
        
        self.assert_real_output(result)
        assert result.get('loaded', False), "Model must be loaded successfully"
        assert benchmark.stats.mean < 5.0, "AI model loading should be under 5 seconds"

    @pytest.mark.benchmark
    def test_ai_inference_performance(self, benchmark, sample_binary_data):
        """Benchmark REAL AI inference speed."""
        def run_ai_inference():
            integration = GPUIntegration()
            model = integration.get_loaded_model()
            
            with open(sample_binary_data, 'rb') as f:
                binary_data = f.read()
            
            return integration.run_inference(model, binary_data)
        
        result = benchmark(run_ai_inference)
        
        self.assert_real_output(result)
        assert 'predictions' in result or 'analysis' in result, "Result must contain predictions"
        assert benchmark.stats.mean < 1.0, "AI inference should be under 1 second"

    @pytest.mark.benchmark
    def test_model_quantization_performance(self, benchmark):
        """Benchmark REAL model quantization speed."""
        def quantize_model():
            quantizer = QuantizationManager()
            return quantizer.quantize_model("test_model", precision="int8")
        
        result = benchmark(quantize_model)
        
        self.assert_real_output(result)
        assert result.get('quantized', False), "Model must be quantized successfully"
        assert benchmark.stats.mean < 3.0, "Model quantization should be under 3 seconds"

    @pytest.mark.benchmark
    def test_model_sharding_performance(self, benchmark):
        """Benchmark REAL model sharding speed."""
        def shard_model():
            sharder = ModelSharding()
            return sharder.shard_model("large_test_model", num_shards=4)
        
        result = benchmark(shard_model)
        
        self.assert_real_output(result)
        assert len(result.get('shards', [])) == 4, "Must create exactly 4 shards"
        assert benchmark.stats.mean < 2.0, "Model sharding should be under 2 seconds"

    def test_gpu_memory_efficiency(self, sample_matrix_data, process_memory):
        """Test REAL GPU memory efficiency."""
        initial_memory = process_memory.rss
        
        gpu = GPUAccelerator()
        
        allocated_handles = []
        for i in range(10):
            handle = gpu.allocate_memory(sample_matrix_data)
            allocated_handles.append(handle)
            self.assert_real_output(handle)
        
        for handle in allocated_handles:
            gpu.free_memory(handle)
        
        current_process = psutil.Process()
        final_memory = current_process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        assert memory_increase < 200 * 1024 * 1024, "Memory increase should be under 200MB"

    def test_concurrent_gpu_operations(self, sample_matrix_data):
        """Test REAL concurrent GPU operation performance."""
        results = []
        errors = []
        
        def gpu_operation(thread_id):
            try:
                gpu = GPUAccelerator()
                result = gpu.matrix_multiply(sample_matrix_data[:100, :100], sample_matrix_data[:100, :100])
                results.append((thread_id, result))
            except Exception as e:
                errors.append((thread_id, str(e)))
        
        threads = []
        start_time = time.time()
        
        for i in range(4):
            thread = threading.Thread(target=gpu_operation, args=(i,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join(timeout=10.0)
        
        end_time = time.time()
        
        assert len(errors) == 0, f"Concurrent GPU errors: {errors}"
        assert len(results) == 4, f"Expected 4 results, got {len(results)}"
        assert end_time - start_time < 5.0, "Concurrent GPU operations should complete under 5 seconds"

    @pytest.mark.benchmark
    def test_performance_monitoring_overhead(self, benchmark):
        """Benchmark REAL performance monitoring overhead."""
        def monitor_performance():
            monitor = ModelPerformanceMonitor()
            
            monitor.start_monitoring()
            
            for i in range(100):
                monitor.record_inference_time(0.01 + i * 0.001)
                monitor.record_memory_usage(1000000 + i * 1000)
            
            stats = monitor.get_performance_stats()
            monitor.stop_monitoring()
            
            return stats
        
        result = benchmark(monitor_performance)
        
        self.assert_real_output(result)
        assert 'inference_times' in result, "Stats must contain inference times"
        assert 'memory_usage' in result, "Stats must contain memory usage"
        assert benchmark.stats.mean < 0.01, "Performance monitoring overhead should be under 10ms"

    def test_gpu_fallback_performance(self):
        """Test REAL GPU fallback to CPU performance."""
        gpu = GPUAccelerator()
        
        original_gpu_available = gpu.is_gpu_available()
        
        gpu.force_cpu_fallback()
        
        start_time = time.time()
        
        small_matrix = [[1.0, 2.0], [3.0, 4.0]]
        result = gpu.matrix_multiply(small_matrix, small_matrix)
        
        end_time = time.time()
        
        self.assert_real_output(result)
        assert len(result) == 2, "Result must have correct dimensions"
        assert end_time - start_time < 0.1, "CPU fallback should be fast for small matrices"
        
        if original_gpu_available:
            gpu.enable_gpu()

    @pytest.mark.benchmark
    def test_model_cache_performance(self, benchmark):
        """Benchmark REAL model cache operations."""
        def cache_operations():
            integration = GPUIntegration()
            
            model_id = "cache_test_model"
            model_data = {"weights": [1.0, 2.0, 3.0], "config": {"layers": 3}}
            
            integration.cache_model(model_id, model_data)
            retrieved = integration.get_cached_model(model_id)
            integration.evict_model_from_cache(model_id)
            
            return retrieved
        
        result = benchmark(cache_operations)
        
        self.assert_real_output(result)
        assert 'weights' in result, "Cached model must contain weights"
        assert 'config' in result, "Cached model must contain config"
        assert benchmark.stats.mean < 0.001, "Model cache operations should be under 1ms"

    def test_gpu_thermal_throttling_detection(self):
        """Test REAL GPU thermal throttling detection."""
        gpu = GPUAccelerator()
        
        start_time = time.time()
        
        thermal_data = []
        for i in range(10):
            temp_info = gpu.get_gpu_temperature()
            thermal_data.append(temp_info)
            
            if temp_info and temp_info.get('temperature', 0) > 80:
                throttling = gpu.detect_thermal_throttling()
                self.assert_real_output(throttling)
            
            time.sleep(0.1)
        
        end_time = time.time()
        
        assert end_time - start_time < 2.0, "Thermal monitoring should complete quickly"
        assert len(thermal_data) == 10, "Must collect all thermal readings"

    @pytest.mark.benchmark
    def test_batch_processing_performance(self, benchmark, sample_binary_data):
        """Benchmark REAL batch processing performance."""
        def batch_process():
            integration = GPUIntegration()
            
            batch_data = []
            for i in range(5):
                with open(sample_binary_data, 'rb') as f:
                    data = f.read()
                batch_data.append(data)
            
            return integration.process_batch(batch_data)
        
        result = benchmark(batch_process)
        
        self.assert_real_output(result)
        assert len(result) == 5, "Must process all 5 items in batch"
        assert benchmark.stats.mean < 2.0, "Batch processing should be under 2 seconds"

    def test_gpu_memory_fragmentation(self, sample_matrix_data):
        """Test REAL GPU memory fragmentation handling."""
        gpu = GPUAccelerator()
        
        handles = []
        
        for i in range(20):
            handle = gpu.allocate_memory(sample_matrix_data[:100, :100])
            handles.append(handle)
            
            if i % 3 == 0 and len(handles) > 1:
                freed_handle = handles.pop(-2)
                gpu.free_memory(freed_handle)
        
        fragmentation_info = gpu.get_memory_fragmentation_info()
        
        for remaining_handle in handles:
            gpu.free_memory(remaining_handle)
        
        self.assert_real_output(fragmentation_info)
        assert 'fragmentation_ratio' in fragmentation_info, "Must include fragmentation ratio"

    def test_ai_model_switching_performance(self):
        """Test REAL AI model switching performance."""
        integration = GPUIntegration()
        
        models = ["model_a", "model_b", "model_c"]
        
        start_time = time.time()
        
        for i in range(6):
            model_name = models[i % len(models)]
            result = integration.switch_to_model(model_name)
            self.assert_real_output(result)
            
            current_model = integration.get_current_model()
            assert current_model == model_name, f"Current model should be {model_name}"
        
        end_time = time.time()
        
        assert end_time - start_time < 3.0, "Model switching should complete under 3 seconds"

    @pytest.mark.benchmark
    def test_gpu_bandwidth_utilization(self, benchmark, sample_matrix_data):
        """Benchmark REAL GPU bandwidth utilization."""
        def measure_bandwidth():
            gpu = GPUAccelerator()
            
            start_transfer = time.time()
            handle = gpu.transfer_to_gpu(sample_matrix_data)
            transfer_time = time.time() - start_transfer
            
            start_compute = time.time()
            result = gpu.compute_on_gpu(handle, "matrix_square")
            compute_time = time.time() - start_compute
            
            start_download = time.time()
            output = gpu.transfer_from_gpu(result)
            download_time = time.time() - start_download
            
            gpu.free_memory(handle)
            
            return {
                'transfer_time': transfer_time,
                'compute_time': compute_time,
                'download_time': download_time,
                'total_time': transfer_time + compute_time + download_time
            }
        
        result = benchmark(measure_bandwidth)
        
        self.assert_real_output(result)
        assert result['total_time'] > 0, "Total time must be positive"
        assert benchmark.stats.mean < 1.0, "GPU bandwidth test should be under 1 second"

    def test_gpu_error_recovery_performance(self):
        """Test REAL GPU error recovery performance."""
        gpu = GPUAccelerator()
        
        start_time = time.time()
        
        error_scenarios = [
            lambda: gpu.allocate_memory(None),
            lambda: gpu.matrix_multiply([], []),
            lambda: gpu.free_memory("invalid_handle"),
            lambda: gpu.compute_on_gpu("invalid_handle", "operation"),
        ]
        
        for scenario in error_scenarios:
            try:
                scenario()
            except Exception:
                pass
        
        recovery_successful = gpu.recover_from_errors()
        
        end_time = time.time()
        
        assert recovery_successful, "GPU error recovery must succeed"
        assert end_time - start_time < 1.0, "Error recovery should be fast (under 1 second)"

    def test_gpu_multi_stream_performance(self):
        """Test REAL GPU multi-stream performance."""
        gpu = GPUAccelerator()
        
        stream_count = 3
        streams = []
        
        for i in range(stream_count):
            stream = gpu.create_stream(f"stream_{i}")
            streams.append(stream)
            self.assert_real_output(stream)
        
        start_time = time.time()
        
        operations = []
        for i, stream in enumerate(streams):
            small_data = [[1.0 + i, 2.0 + i], [3.0 + i, 4.0 + i]]
            op = gpu.async_matrix_multiply(small_data, small_data, stream)
            operations.append(op)
        
        results = []
        for op in operations:
            result = gpu.wait_for_operation(op)
            results.append(result)
        
        end_time = time.time()
        
        for stream in streams:
            gpu.destroy_stream(stream)
        
        assert len(results) == stream_count, f"Expected {stream_count} results"
        assert end_time - start_time < 1.0, "Multi-stream operations should complete under 1 second"
        
        for result in results:
            self.assert_real_output(result)