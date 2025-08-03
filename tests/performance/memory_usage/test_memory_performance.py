"""
Performance tests for memory usage across all operations.
Tests REAL memory consumption, leak detection, and optimization.
NO MOCKS - ALL TESTS MEASURE REAL MEMORY METRICS.
"""

import pytest
import psutil
import gc
import time
import tracemalloc
from pathlib import Path

from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer
from intellicrack.ai.ai_script_generator import AIScriptGenerator
from intellicrack.core.network.license_server_emulator import LicenseServerEmulator
from tests.base_test import IntellicrackTestBase


class TestMemoryPerformance(IntellicrackTestBase):
    """Test memory usage and efficiency with REAL measurements."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test with memory monitoring."""
        self.process = psutil.Process()
        gc.collect()
        self.baseline_memory = self.process.memory_info().rss / (1024 * 1024)  # MB
        
    def teardown_method(self):
        """Clean up and report memory usage."""
        gc.collect()
        final_memory = self.process.memory_info().rss / (1024 * 1024)
        increase = final_memory - self.baseline_memory
        print(f"\nMemory increase for test: {increase:.2f}MB")
        
    def test_memory_leak_detection(self):
        """Test for memory leaks in repeated operations."""
        tracemalloc.start()
        
        # Get initial snapshot
        gc.collect()
        snapshot1 = tracemalloc.take_snapshot()
        initial_memory = self.process.memory_info().rss / (1024 * 1024)
        
        # Perform repeated operations
        analyzer = BinaryAnalyzer()
        test_file = Path("tests/fixtures/binaries/simple.exe")
        
        if not test_file.exists():
            # Create a dummy file
            test_file = Path("test_dummy.bin")
            test_file.write_bytes(b"MZ" + b"\x00" * 1000)
            
        try:
            # Repeat operation many times
            for i in range(100):
                result = analyzer.analyze(test_file)
                
                # Force cleanup every 10 iterations
                if i % 10 == 0:
                    gc.collect()
                    
            # Get final snapshot
            gc.collect()
            time.sleep(0.5)  # Allow cleanup
            snapshot2 = tracemalloc.take_snapshot()
            final_memory = self.process.memory_info().rss / (1024 * 1024)
            
            # Analyze memory growth
            memory_growth = final_memory - initial_memory
            
            # Get top memory consumers
            top_stats = snapshot2.compare_to(snapshot1, 'lineno')
            
            # Check for leaks
            assert memory_growth < 50  # Less than 50MB growth after 100 operations
            
            print("\nMemory Leak Detection:")
            print(f"  Operations: 100")
            print(f"  Memory growth: {memory_growth:.2f}MB")
            print(f"  Growth per operation: {memory_growth/100:.2f}MB")
            
            # Report top memory allocations
            print("\nTop memory allocations:")
            for stat in top_stats[:5]:
                print(f"  {stat}")
                
        finally:
            tracemalloc.stop()
            if test_file.name == "test_dummy.bin":
                test_file.unlink()
                
    def test_peak_memory_usage(self):
        """Test peak memory usage during intensive operations."""
        peak_memory = self.baseline_memory
        operations = []
        
        # Test binary analysis
        analyzer = BinaryAnalyzer()
        for i in range(5):
            # Simulate analyzing a binary
            result = analyzer.analyze_bytes(b"MZ" + b"\x00" * 10000)
            current = self.process.memory_info().rss / (1024 * 1024)
            peak_memory = max(peak_memory, current)
            operations.append(("Binary analysis", current - self.baseline_memory))
            
        # Test AI operations
        generator = AIScriptGenerator()
        for i in range(3):
            script = generator.generate_frida_script("Test script generation")
            current = self.process.memory_info().rss / (1024 * 1024)
            peak_memory = max(peak_memory, current)
            operations.append(("AI generation", current - self.baseline_memory))
            
        # Clean up
        gc.collect()
        
        # Report
        print("\nPeak Memory Usage:")
        print(f"  Baseline: {self.baseline_memory:.2f}MB")
        print(f"  Peak: {peak_memory:.2f}MB")
        print(f"  Peak increase: {peak_memory - self.baseline_memory:.2f}MB")
        
        for op, mem in operations:
            print(f"  {op}: +{mem:.2f}MB")
            
        # Assert reasonable memory usage
        assert (peak_memory - self.baseline_memory) < 1000  # Less than 1GB peak increase
        
    def test_memory_fragmentation(self):
        """Test memory fragmentation during allocations."""
        import random
        
        # Track allocations
        allocations = []
        
        # Create many small allocations
        for i in range(1000):
            size = random.randint(1000, 10000)
            data = bytearray(size)
            allocations.append(data)
            
        mid_memory = self.process.memory_info().rss / (1024 * 1024)
        
        # Delete half randomly
        indices = list(range(len(allocations)))
        random.shuffle(indices)
        for i in indices[:500]:
            allocations[i] = None
            
        gc.collect()
        
        # Allocate large block
        try:
            large_block = bytearray(50 * 1024 * 1024)  # 50MB
            allocated = True
        except MemoryError:
            allocated = False
            
        final_memory = self.process.memory_info().rss / (1024 * 1024)
        
        print("\nMemory Fragmentation Test:")
        print(f"  After small allocations: {mid_memory:.2f}MB")
        print(f"  After cleanup: {final_memory:.2f}MB")
        print(f"  Large allocation succeeded: {allocated}")
        
        # Should be able to allocate large block
        assert allocated
        
    def test_concurrent_memory_usage(self):
        """Test memory usage with concurrent operations."""
        import concurrent.futures
        import threading
        
        memory_readings = []
        lock = threading.Lock()
        
        def monitor_memory():
            """Monitor memory in background."""
            while getattr(monitor_memory, 'running', True):
                current = self.process.memory_info().rss / (1024 * 1024)
                with lock:
                    memory_readings.append(current)
                time.sleep(0.1)
                
        # Start memory monitoring
        monitor_memory.running = True
        monitor_thread = threading.Thread(target=monitor_memory)
        monitor_thread.start()
        
        try:
            # Run concurrent operations
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                futures = []
                
                # Mix of operations
                for i in range(20):
                    if i % 2 == 0:
                        # Binary analysis
                        future = executor.submit(
                            BinaryAnalyzer().analyze_bytes,
                            b"MZ" + b"\x00" * 5000
                        )
                    else:
                        # Script generation
                        future = executor.submit(
                            AIScriptGenerator().generate_frida_script,
                            f"Test script {i}"
                        )
                    futures.append(future)
                    
                # Wait for completion
                for future in futures:
                    future.result()
                    
        finally:
            monitor_memory.running = False
            monitor_thread.join()
            
        # Analyze memory usage
        peak_concurrent = max(memory_readings)
        avg_concurrent = sum(memory_readings) / len(memory_readings)
        
        print("\nConcurrent Memory Usage:")
        print(f"  Peak memory: {peak_concurrent:.2f}MB")
        print(f"  Average memory: {avg_concurrent:.2f}MB")
        print(f"  Samples: {len(memory_readings)}")
        
        # Assert reasonable concurrent usage
        assert peak_concurrent < self.baseline_memory + 2000  # Less than 2GB increase
        
    def test_memory_recovery(self):
        """Test memory recovery after intensive operations."""
        # Baseline
        gc.collect()
        baseline = self.process.memory_info().rss / (1024 * 1024)
        
        # Intensive operation
        large_data = []
        for i in range(100):
            # Create large temporary data
            data = bytearray(10 * 1024 * 1024)  # 10MB each
            large_data.append(data)
            
        peak = self.process.memory_info().rss / (1024 * 1024)
        
        # Clear references
        large_data.clear()
        del large_data
        
        # Force cleanup
        gc.collect()
        time.sleep(1)  # Allow OS to reclaim
        
        recovered = self.process.memory_info().rss / (1024 * 1024)
        
        recovery_percent = ((peak - recovered) / (peak - baseline)) * 100
        
        print("\nMemory Recovery Test:")
        print(f"  Baseline: {baseline:.2f}MB")
        print(f"  Peak: {peak:.2f}MB")
        print(f"  Recovered: {recovered:.2f}MB")
        print(f"  Recovery: {recovery_percent:.1f}%")
        
        # Should recover most memory
        assert recovery_percent > 80  # At least 80% recovery
        
    def test_memory_profiling_by_component(self):
        """Profile memory usage by component."""
        components = {}
        
        # Test each component
        gc.collect()
        start_mem = self.process.memory_info().rss / (1024 * 1024)
        
        # Binary analysis
        analyzer = BinaryAnalyzer()
        for i in range(10):
            analyzer.analyze_bytes(b"MZ" + b"\x00" * 1000)
        gc.collect()
        components['Binary Analysis'] = self.process.memory_info().rss / (1024 * 1024) - start_mem
        
        # AI operations
        start_mem = self.process.memory_info().rss / (1024 * 1024)
        generator = AIScriptGenerator()
        for i in range(5):
            generator.generate_frida_script("Test")
        gc.collect()
        components['AI Operations'] = self.process.memory_info().rss / (1024 * 1024) - start_mem
        
        # Network emulation
        start_mem = self.process.memory_info().rss / (1024 * 1024)
        emulator = LicenseServerEmulator()
        emulator.start_server(port=0)  # Random port
        time.sleep(0.5)
        emulator.stop_server()
        gc.collect()
        components['Network Emulation'] = self.process.memory_info().rss / (1024 * 1024) - start_mem
        
        # Report
        print("\nMemory Usage by Component:")
        total = sum(components.values())
        for component, memory in components.items():
            percent = (memory / total * 100) if total > 0 else 0
            print(f"  {component}: {memory:.2f}MB ({percent:.1f}%)")
            
        # All components should use reasonable memory
        for component, memory in components.items():
            assert memory < 500  # Each component under 500MB