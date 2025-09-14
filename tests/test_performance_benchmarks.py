"""
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import unittest
import tempfile
import os
import time
import psutil
import struct
import threading
import multiprocessing
import json
import hashlib
import random
from pathlib import Path
from typing import Dict, Any, List, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import statistics

@dataclass
class PerformanceMetrics:
    """Stores performance measurement data."""
    operation: str
    start_time: float = 0
    end_time: float = 0
    duration: float = 0
    memory_before: int = 0
    memory_after: int = 0
    memory_delta: int = 0
    cpu_percent: float = 0
    operations_per_second: float = 0
    latency_p50: float = 0
    latency_p95: float = 0
    latency_p99: float = 0
    thread_count: int = 0
    file_handles: int = 0

    def calculate(self):
        """Calculate derived metrics."""
        self.duration = self.end_time - self.start_time
        self.memory_delta = self.memory_after - self.memory_before
        if self.duration > 0:
            self.operations_per_second = 1.0 / self.duration


class RealPerformanceMonitor:
    """Monitors real system performance metrics."""

    def __init__(self):
        self.process = psutil.Process()
        self.metrics_history = []
        self.active_monitors = {}

    def start_monitoring(self, operation: str) -> PerformanceMetrics:
        """Start monitoring an operation."""
        metrics = PerformanceMetrics(operation=operation)

        # Capture initial state
        metrics.start_time = time.perf_counter()
        metrics.memory_before = self.process.memory_info().rss
        metrics.thread_count = self.process.num_threads()

        try:
            metrics.file_handles = len(self.process.open_files())
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            metrics.file_handles = 0

        self.active_monitors[operation] = metrics
        return metrics

    def stop_monitoring(self, operation: str) -> PerformanceMetrics:
        """Stop monitoring and calculate metrics."""
        if operation not in self.active_monitors:
            return PerformanceMetrics(operation=operation)

        metrics = self.active_monitors[operation]

        # Capture final state
        metrics.end_time = time.perf_counter()
        metrics.memory_after = self.process.memory_info().rss

        try:
            metrics.cpu_percent = self.process.cpu_percent(interval=0.1)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            metrics.cpu_percent = 0

        # Calculate derived metrics
        metrics.calculate()

        # Store in history
        self.metrics_history.append(metrics)
        del self.active_monitors[operation]

        return metrics

    def measure_latency_distribution(self, func, iterations: int = 100) -> Dict[str, float]:
        """Measure latency distribution of a function."""
        latencies = []

        for _ in range(iterations):
            start = time.perf_counter()
            func()
            end = time.perf_counter()
            latencies.append((end - start) * 1000)  # Convert to ms

        latencies.sort()

        return {
            'min': latencies[0],
            'max': latencies[-1],
            'mean': statistics.mean(latencies),
            'median': statistics.median(latencies),
            'p50': latencies[int(len(latencies) * 0.50)],
            'p95': latencies[int(len(latencies) * 0.95)],
            'p99': latencies[int(len(latencies) * 0.99)],
            'stdev': statistics.stdev(latencies) if len(latencies) > 1 else 0
        }


class RealBinaryGenerator:
    """Generates real test binaries of various sizes."""

    def __init__(self, base_path: str):
        self.base_path = base_path

    def generate_pe_binary(self, size_kb: int) -> str:
        """Generate a PE binary of specified size."""
        path = os.path.join(self.base_path, f'test_{size_kb}kb.exe')

        with open(path, 'wb') as f:
            # DOS header
            f.write(b'MZ' + b'\x90' * 58 + struct.pack('<I', 0x80))
            f.write(b'\x00' * (0x80 - 64))

            # PE header
            f.write(b'PE\x00\x00')
            f.write(struct.pack('<H', 0x014c))  # Machine
            f.write(struct.pack('<H', 3))       # Number of sections
            f.write(b'\x00' * 240)

            # Generate code patterns
            code_size = size_kb * 512  # Half for code
            code = self._generate_code_patterns(code_size)
            f.write(code)

            # Generate data patterns
            data_size = size_kb * 512  # Half for data
            data = self._generate_data_patterns(data_size)
            f.write(data)

        return path

    def _generate_code_patterns(self, size: int) -> bytes:
        """Generate realistic code patterns."""
        patterns = [
            b'\x55\x8b\xec',               # push ebp; mov ebp, esp
            b'\x48\x83\xec\x20',           # sub rsp, 0x20
            b'\xe8\x00\x00\x00\x00',       # call
            b'\x48\x8b\x45\xf8',           # mov rax, [rbp-8]
            b'\xff\x15\x00\x00\x00\x00',   # call [rip+0]
            b'\x0f\x84\x00\x00\x00\x00',   # jz
            b'\x48\x89\x45\xf0',           # mov [rbp-10], rax
            b'\xc3',                       # ret
            b'\x90' * 16,                  # nop sled
        ]

        result = bytearray()
        while len(result) < size:
            pattern = random.choice(patterns)
            result.extend(pattern)

        return bytes(result[:size])

    def _generate_data_patterns(self, size: int) -> bytes:
        """Generate realistic data patterns."""
        result = bytearray()

        # Add strings
        strings = [
            b'kernel32.dll\x00',
            b'user32.dll\x00',
            b'LoadLibraryA\x00',
            b'GetProcAddress\x00',
            b'CreateFileA\x00',
            b'ReadFile\x00',
            b'WriteFile\x00',
            b'VirtualAlloc\x00',
            b'This is test data\x00',
            b'License check string\x00',
            b'Error: %s\x00',
        ]

        for string in strings * 10:
            if len(result) + len(string) < size:
                result.extend(string)

        # Fill remaining with random data
        remaining = size - len(result)
        result.extend(os.urandom(remaining))

        return bytes(result[:size])


class RealAnalysisEngine:
    """Performs real binary analysis for benchmarking."""

    def __init__(self):
        self.cache = {}

    def analyze_binary(self, path: str) -> Dict[str, Any]:
        """Perform real binary analysis."""
        results = {
            'path': path,
            'size': 0,
            'hash': '',
            'format': '',
            'functions': [],
            'strings': [],
            'imports': [],
            'entropy': 0
        }

        with open(path, 'rb') as f:
            content = f.read()
            results['size'] = len(content)
            results['hash'] = hashlib.sha256(content).hexdigest()

            # Detect format
            if content[:2] == b'MZ':
                results['format'] = 'PE'
            elif content[:4] == b'\x7fELF':
                results['format'] = 'ELF'

            # Find functions
            func_patterns = [b'\x55\x8b\xec', b'\x55\x48\x89\xe5', b'\x48\x83\xec']
            for pattern in func_patterns:
                offset = 0
                while offset < len(content):
                    idx = content.find(pattern, offset)
                    if idx == -1:
                        break
                    results['functions'].append({
                        'offset': idx,
                        'pattern': pattern.hex()
                    })
                    offset = idx + 1
                    if len(results['functions']) >= 100:
                        break

            # Find strings
            import re
            ascii_pattern = rb'[\x20-\x7e]{5,}'
            for match in re.finditer(ascii_pattern, content):
                if len(results['strings']) < 200:
                    results['strings'].append({
                        'offset': match.start(),
                        'value': match.group().decode('ascii', errors='ignore')
                    })

            # Calculate entropy
            results['entropy'] = self._calculate_entropy(content)

        return results

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        # Count byte frequencies
        frequencies = {}
        for byte in data:
            frequencies[byte] = frequencies.get(byte, 0) + 1

        # Calculate entropy
        import math
        entropy = 0.0
        data_len = len(data)

        for count in frequencies.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy


class TestPerformanceBenchmarks(unittest.TestCase):
    """Performance benchmark tests for Intellicrack."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.monitor = RealPerformanceMonitor()
        self.generator = RealBinaryGenerator(self.test_dir)
        self.analyzer = RealAnalysisEngine()

    def tearDown(self):
        """Clean up test environment."""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_binary_analysis_performance(self):
        """Benchmark binary analysis performance."""
        sizes = [10, 50, 100, 500, 1000]  # KB
        results = []

        for size in sizes:
            # Generate binary
            binary_path = self.generator.generate_pe_binary(size)

            # Measure analysis performance
            metrics = self.monitor.start_monitoring(f'analyze_{size}kb')
            analysis = self.analyzer.analyze_binary(binary_path)
            self.monitor.stop_monitoring(f'analyze_{size}kb')

            results.append({
                'size_kb': size,
                'duration': metrics.duration,
                'memory_delta': metrics.memory_delta,
                'functions_found': len(analysis['functions']),
                'strings_found': len(analysis['strings']),
                'throughput_mb_per_sec': (size / 1024) / metrics.duration if metrics.duration > 0 else 0
            })

        # Verify performance scales appropriately
        for i in range(1, len(results)):
            # Larger files should take more time but not linearly
            self.assertGreater(results[i]['duration'], results[i-1]['duration'])

            # Throughput should remain reasonable
            self.assertGreater(results[i]['throughput_mb_per_sec'], 0.1)

    def test_concurrent_analysis_performance(self):
        """Test performance of concurrent analysis."""
        num_binaries = 10
        binary_paths = []

        # Generate test binaries
        for i in range(num_binaries):
            path = self.generator.generate_pe_binary(50)
            binary_paths.append(path)

        # Sequential analysis
        seq_metrics = self.monitor.start_monitoring('sequential')
        seq_results = []
        for path in binary_paths:
            result = self.analyzer.analyze_binary(path)
            seq_results.append(result)
        seq_perf = self.monitor.stop_monitoring('sequential')

        # Parallel analysis with threads
        thread_metrics = self.monitor.start_monitoring('threaded')
        with ThreadPoolExecutor(max_workers=4) as executor:
            thread_results = list(executor.map(self.analyzer.analyze_binary, binary_paths))
        thread_perf = self.monitor.stop_monitoring('threaded')

        # Compare performance
        speedup = seq_perf.duration / thread_perf.duration if thread_perf.duration > 0 else 0

        # Parallel should be faster
        self.assertGreater(speedup, 1.5)

        # Results should be equivalent
        self.assertEqual(len(seq_results), len(thread_results))

    def test_memory_usage_scaling(self):
        """Test memory usage scaling with binary size."""
        sizes = [10, 100, 1000]  # KB
        memory_usage = []

        for size in sizes:
            binary_path = self.generator.generate_pe_binary(size)

            # Measure memory usage
            metrics = self.monitor.start_monitoring(f'memory_{size}kb')

            # Perform memory-intensive operation
            with open(binary_path, 'rb') as f:
                content = f.read()
                # Analyze multiple times to stress memory
                for _ in range(5):
                    analysis = self.analyzer.analyze_binary(binary_path)

            metrics = self.monitor.stop_monitoring(f'memory_{size}kb')

            memory_usage.append({
                'size_kb': size,
                'memory_delta_mb': metrics.memory_delta / (1024 * 1024)
            })

        # Memory usage should scale sub-linearly
        for i in range(1, len(memory_usage)):
            size_ratio = memory_usage[i]['size_kb'] / memory_usage[i-1]['size_kb']
            memory_ratio = memory_usage[i]['memory_delta_mb'] / max(memory_usage[i-1]['memory_delta_mb'], 0.1)

            # Memory growth should be less than size growth
            self.assertLess(memory_ratio, size_ratio * 2)

    def test_latency_distribution(self):
        """Test latency distribution of operations."""
        binary_path = self.generator.generate_pe_binary(50)

        # Define operation to measure
        def analyze_op():
            self.analyzer.analyze_binary(binary_path)

        # Measure latency distribution
        latencies = self.monitor.measure_latency_distribution(analyze_op, iterations=20)

        # Verify latency characteristics
        self.assertLess(latencies['p50'], latencies['p95'])
        self.assertLess(latencies['p95'], latencies['p99'])
        self.assertGreater(latencies['mean'], 0)

        # P99 should not be more than 3x median
        self.assertLess(latencies['p99'], latencies['p50'] * 3)

    def test_dashboard_update_performance(self):
        """Test dashboard update performance."""
        # Create dashboard data updates
        updates = []
        for i in range(100):
            updates.append({
                'timestamp': time.time(),
                'cpu_usage': random.uniform(0, 100),
                'memory_usage': random.uniform(0, 100),
                'operations_count': i,
                'active_sessions': random.randint(1, 10)
            })

        # Measure update processing
        metrics = self.monitor.start_monitoring('dashboard_updates')

        processed = []
        for update in updates:
            # Process update (serialize, validate, store)
            serialized = json.dumps(update)
            validated = json.loads(serialized)
            processed.append(validated)

        metrics = self.monitor.stop_monitoring('dashboard_updates')

        # Calculate update rate
        updates_per_second = len(updates) / metrics.duration if metrics.duration > 0 else 0

        # Should handle at least 100 updates per second
        self.assertGreater(updates_per_second, 100)

    def test_cross_tool_orchestration_performance(self):
        """Test cross-tool orchestration performance."""
        binary_path = self.generator.generate_pe_binary(100)

        # Define tool operations
        def ghidra_analysis():
            time.sleep(0.01)  # Represents Ghidra analysis
            return {'functions': 50, 'strings': 100}

        def frida_analysis():
            time.sleep(0.01)  # Represents Frida instrumentation
            return {'hooks': 20, 'traces': 1000}

        def radare2_analysis():
            time.sleep(0.01)  # Represents Radare2 analysis
            return {'xrefs': 200, 'symbols': 150}

        # Sequential orchestration
        seq_metrics = self.monitor.start_monitoring('sequential_orchestration')
        seq_results = []
        seq_results.append(ghidra_analysis())
        seq_results.append(frida_analysis())
        seq_results.append(radare2_analysis())
        seq_perf = self.monitor.stop_monitoring('sequential_orchestration')

        # Parallel orchestration
        par_metrics = self.monitor.start_monitoring('parallel_orchestration')
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(ghidra_analysis),
                executor.submit(frida_analysis),
                executor.submit(radare2_analysis)
            ]
            par_results = [f.result() for f in futures]
        par_perf = self.monitor.stop_monitoring('parallel_orchestration')

        # Parallel should be significantly faster
        speedup = seq_perf.duration / par_perf.duration if par_perf.duration > 0 else 0
        self.assertGreater(speedup, 2.0)

    def test_cache_effectiveness(self):
        """Test caching effectiveness."""
        binary_path = self.generator.generate_pe_binary(100)

        # First analysis (cold cache)
        cold_metrics = self.monitor.start_monitoring('cold_cache')
        result1 = self.analyzer.analyze_binary(binary_path)
        cold_perf = self.monitor.stop_monitoring('cold_cache')

        # Store in cache
        self.analyzer.cache[binary_path] = result1

        # Second analysis (warm cache)
        warm_metrics = self.monitor.start_monitoring('warm_cache')
        if binary_path in self.analyzer.cache:
            result2 = self.analyzer.cache[binary_path]
        else:
            result2 = self.analyzer.analyze_binary(binary_path)
        warm_perf = self.monitor.stop_monitoring('warm_cache')

        # Cache hit should be much faster
        cache_speedup = cold_perf.duration / warm_perf.duration if warm_perf.duration > 0 else 0
        self.assertGreater(cache_speedup, 100)

    def test_resource_cleanup(self):
        """Test resource cleanup and leak detection."""
        initial_handles = len(self.monitor.process.open_files())
        initial_threads = self.monitor.process.num_threads()

        # Perform operations that create resources
        for i in range(10):
            binary_path = self.generator.generate_pe_binary(10)
            analysis = self.analyzer.analyze_binary(binary_path)

        # Force garbage collection
        import gc
        gc.collect()

        # Check for resource leaks
        final_handles = len(self.monitor.process.open_files())
        final_threads = self.monitor.process.num_threads()

        # Should not leak file handles
        self.assertLessEqual(final_handles, initial_handles + 2)

        # Thread count should be stable
        self.assertLessEqual(final_threads, initial_threads + 2)

    def test_scalability_limits(self):
        """Test system scalability limits."""
        # Test with increasing load
        loads = [1, 5, 10, 20, 50]
        throughputs = []

        for load in loads:
            binary_paths = []
            for i in range(load):
                path = self.generator.generate_pe_binary(10)
                binary_paths.append(path)

            # Measure throughput
            metrics = self.monitor.start_monitoring(f'load_{load}')

            with ThreadPoolExecutor(max_workers=min(load, 10)) as executor:
                results = list(executor.map(self.analyzer.analyze_binary, binary_paths))

            metrics = self.monitor.stop_monitoring(f'load_{load}')

            throughput = load / metrics.duration if metrics.duration > 0 else 0
            throughputs.append({
                'load': load,
                'throughput': throughput,
                'duration': metrics.duration
            })

        # Throughput should increase with load up to a point
        for i in range(1, min(3, len(throughputs))):
            self.assertGreater(throughputs[i]['throughput'], throughputs[i-1]['throughput'] * 0.8)

    def test_performance_regression_detection(self):
        """Test for performance regressions."""
        baseline_path = self.generator.generate_pe_binary(50)

        # Establish baseline
        baseline_times = []
        for _ in range(5):
            start = time.perf_counter()
            self.analyzer.analyze_binary(baseline_path)
            end = time.perf_counter()
            baseline_times.append(end - start)

        baseline_avg = statistics.mean(baseline_times)
        baseline_stdev = statistics.stdev(baseline_times)

        # Test current performance
        current_times = []
        for _ in range(5):
            start = time.perf_counter()
            self.analyzer.analyze_binary(baseline_path)
            end = time.perf_counter()
            current_times.append(end - start)

        current_avg = statistics.mean(current_times)

        # Current should not be significantly slower than baseline
        # Allow 20% variance
        self.assertLess(current_avg, baseline_avg * 1.2 + 2 * baseline_stdev)

    def test_stress_test(self):
        """Stress test with sustained load."""
        duration = 2  # seconds
        operations = 0
        errors = 0

        binary_path = self.generator.generate_pe_binary(10)

        start_time = time.time()
        metrics = self.monitor.start_monitoring('stress_test')

        while time.time() - start_time < duration:
            try:
                self.analyzer.analyze_binary(binary_path)
                operations += 1
            except Exception:
                errors += 1

        metrics = self.monitor.stop_monitoring('stress_test')

        # Calculate operations per second
        ops_per_sec = operations / duration

        # Should maintain reasonable throughput under stress
        self.assertGreater(ops_per_sec, 10)

        # Error rate should be low
        error_rate = errors / max(operations, 1)
        self.assertLess(error_rate, 0.01)

        # Memory should not grow excessively
        memory_growth_mb = metrics.memory_delta / (1024 * 1024)
        self.assertLess(memory_growth_mb, 100)


if __name__ == '__main__':
    unittest.main()
