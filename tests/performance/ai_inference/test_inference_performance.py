"""
Performance tests for AI inference operations.
Tests REAL inference speed, throughput, and resource usage.
NO MOCKS - ALL TESTS MEASURE REAL PERFORMANCE METRICS.
"""

import pytest
import time
import psutil
import statistics
from pathlib import Path

from intellicrack.ai.ai_script_generator import AIScriptGenerator
from intellicrack.ai.model_manager import ModelManager
from tests.base_test import IntellicrackTestBase


class TestAIInferencePerformance(IntellicrackTestBase):
    """Test AI inference performance with REAL measurements."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test with real AI components."""
        self.script_generator = AIScriptGenerator()
        self.model_manager = ModelManager()
        self.process = psutil.Process()
        
    def test_script_generation_speed(self):
        """Test script generation performance."""
        prompts = [
            "Generate Frida script to hook file operations",
            "Create Ghidra script for string analysis",
            "Generate exploit development helper script",
            "Create protection bypass script"
        ]
        
        times = []
        memory_usage = []
        
        for prompt in prompts:
            # Measure memory before
            mem_before = self.process.memory_info().rss / 1024 / 1024  # MB
            
            # Measure generation time
            start = time.perf_counter()
            script = self.script_generator.generate_frida_script(prompt)
            end = time.perf_counter()
            
            generation_time = end - start
            times.append(generation_time)
            
            # Measure memory after
            mem_after = self.process.memory_info().rss / 1024 / 1024  # MB
            memory_usage.append(mem_after - mem_before)
            
            # Validate output
            self.assert_real_output(script)
            assert len(script) > 100  # Real scripts have substance
            
        # Performance metrics
        avg_time = statistics.mean(times)
        max_time = max(times)
        avg_memory = statistics.mean(memory_usage)
        
        # Performance assertions
        assert avg_time < 10.0  # Average under 10 seconds
        assert max_time < 30.0  # Max under 30 seconds
        assert avg_memory < 500  # Less than 500MB increase
        
        # Report metrics
        print(f"\nScript Generation Performance:")
        print(f"  Average time: {avg_time:.2f}s")
        print(f"  Max time: {max_time:.2f}s")
        print(f"  Average memory: {avg_memory:.2f}MB")
        
    def test_model_loading_performance(self):
        """Test model loading and initialization speed."""
        models = self.model_manager.discover_models()
        
        if not models:
            pytest.skip("No models available")
            
        loading_times = []
        
        for model in models[:3]:  # Test first 3 models
            start = time.perf_counter()
            result = self.model_manager.load_model(model['name'])
            end = time.perf_counter()
            
            if result['success']:
                loading_time = end - start
                loading_times.append(loading_time)
                
                # Unload to test next
                self.model_manager.unload_model(model['name'])
                
        if loading_times:
            avg_load_time = statistics.mean(loading_times)
            assert avg_load_time < 30.0  # Under 30 seconds average
            
    def test_concurrent_inference_throughput(self):
        """Test concurrent inference performance."""
        import concurrent.futures
        
        # Load a model
        models = self.model_manager.discover_models()
        if not models:
            pytest.skip("No models available")
            
        self.model_manager.load_model(models[0]['name'])
        
        # Test concurrent requests
        prompts = ["Test prompt " + str(i) for i in range(10)]
        
        start = time.perf_counter()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            for prompt in prompts:
                future = executor.submit(
                    self.model_manager.inference,
                    models[0]['name'],
                    prompt
                )
                futures.append(future)
                
            # Wait for all to complete
            results = [f.result() for f in futures]
            
        end = time.perf_counter()
        
        total_time = end - start
        throughput = len(prompts) / total_time
        
        # Validate results
        for result in results:
            self.assert_real_output(result)
            
        # Performance assertions
        assert throughput > 0.5  # At least 0.5 requests per second
        
        print(f"\nConcurrent Inference Performance:")
        print(f"  Total time: {total_time:.2f}s")
        print(f"  Throughput: {throughput:.2f} requests/second")
        
    def test_memory_efficiency(self):
        """Test memory efficiency during inference."""
        import gc
        
        # Force garbage collection
        gc.collect()
        
        # Baseline memory
        baseline_memory = self.process.memory_info().rss / 1024 / 1024
        
        # Perform multiple inferences
        peak_memory = baseline_memory
        
        for i in range(20):
            script = self.script_generator.generate_frida_script(
                f"Generate script for test {i}"
            )
            
            current_memory = self.process.memory_info().rss / 1024 / 1024
            peak_memory = max(peak_memory, current_memory)
            
            # Force cleanup every 5 iterations
            if i % 5 == 0:
                gc.collect()
                
        # Final memory after cleanup
        gc.collect()
        time.sleep(0.5)
        final_memory = self.process.memory_info().rss / 1024 / 1024
        
        # Memory leak check
        memory_increase = final_memory - baseline_memory
        
        # Assertions
        assert memory_increase < 200  # Less than 200MB increase
        assert (peak_memory - baseline_memory) < 1000  # Peak under 1GB increase
        
        print(f"\nMemory Efficiency:")
        print(f"  Baseline: {baseline_memory:.2f}MB")
        print(f"  Peak: {peak_memory:.2f}MB")
        print(f"  Final: {final_memory:.2f}MB")
        print(f"  Increase: {memory_increase:.2f}MB")
        
    @pytest.mark.benchmark
    def test_inference_latency_distribution(self):
        """Test inference latency distribution."""
        # Multiple inference measurements
        latencies = []
        
        for i in range(50):
            start = time.perf_counter()
            script = self.script_generator.generate_frida_script(
                "Hook MessageBoxA"
            )
            end = time.perf_counter()
            
            latency = (end - start) * 1000  # Convert to ms
            latencies.append(latency)
            
        # Calculate percentiles
        latencies.sort()
        p50 = latencies[int(len(latencies) * 0.50)]
        p90 = latencies[int(len(latencies) * 0.90)]
        p99 = latencies[int(len(latencies) * 0.99)]
        
        # Assertions
        assert p50 < 5000  # 50th percentile under 5s
        assert p90 < 10000  # 90th percentile under 10s
        assert p99 < 20000  # 99th percentile under 20s
        
        print(f"\nLatency Distribution:")
        print(f"  P50: {p50:.0f}ms")
        print(f"  P90: {p90:.0f}ms")
        print(f"  P99: {p99:.0f}ms")