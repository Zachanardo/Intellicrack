"""
This file is part of Intellicrack.
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
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Performance Benchmarking System for Frida Integration

Measures and tracks performance metrics for Frida operations including:
- Hook installation time
- Script loading performance
- Memory usage patterns
- CPU utilization
- Hook execution overhead
"""

import gc
import json
import platform
import statistics
import sys
import time
import unittest
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import psutil

try:
    import frida

    from intellicrack.core.frida_manager import (
        FridaManager,
        FridaPerformanceOptimizer,
        HookCategory,
    )
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False


class PerformanceMetrics:
    """Container for performance metrics"""

    def __init__(self, name: str):
        self.name = name
        self.start_time = None
        self.end_time = None
        self.duration = None
        self.memory_start = None
        self.memory_end = None
        self.memory_delta = None
        self.cpu_percent = None
        self.additional_metrics = {}

    def start(self):
        """Start measuring"""
        gc.collect()  # Clean up before measurement
        self.start_time = time.perf_counter()
        self.memory_start = psutil.Process().memory_info().rss / 1024 / 1024  # MB

    def stop(self):
        """Stop measuring"""
        self.end_time = time.perf_counter()
        self.memory_end = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        self.duration = (self.end_time - self.start_time) * 1000  # ms
        self.memory_delta = self.memory_end - self.memory_start

    def add_metric(self, key: str, value: Any):
        """Add additional metric"""
        self.additional_metrics[key] = value

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'duration_ms': round(self.duration, 2) if self.duration else None,
            'memory_start_mb': round(self.memory_start, 2) if self.memory_start else None,
            'memory_end_mb': round(self.memory_end, 2) if self.memory_end else None,
            'memory_delta_mb': round(self.memory_delta, 2) if self.memory_delta else None,
            'cpu_percent': self.cpu_percent,
            **self.additional_metrics
        }


class FridaBenchmark:
    """Base class for Frida benchmarks"""

    def __init__(self, name: str, iterations: int = 10):
        self.name = name
        self.iterations = iterations
        self.results = []
        self.setup_time = None
        self.teardown_time = None

    def setup(self):
        """Setup benchmark environment"""
        pass

    def teardown(self):
        """Cleanup benchmark environment"""
        pass

    def run_iteration(self) -> PerformanceMetrics:
        """Run single benchmark iteration"""
        raise NotImplementedError

    def run(self) -> Dict[str, Any]:
        """Run complete benchmark"""
        print(f"Running benchmark: {self.name}")

        # Setup
        setup_start = time.perf_counter()
        self.setup()
        self.setup_time = (time.perf_counter() - setup_start) * 1000

        # Run iterations
        for i in range(self.iterations):
            print(f"  Iteration {i+1}/{self.iterations}", end='\r')
            result = self.run_iteration()
            self.results.append(result)
            time.sleep(0.1)  # Brief pause between iterations

        print()  # New line after iterations

        # Teardown
        teardown_start = time.perf_counter()
        self.teardown()
        self.teardown_time = (time.perf_counter() - teardown_start) * 1000

        # Calculate statistics
        return self._calculate_statistics()

    def _calculate_statistics(self) -> Dict[str, Any]:
        """Calculate statistics from results"""
        if not self.results:
            return {}

        durations = [r.duration for r in self.results if r.duration]
        memory_deltas = [r.memory_delta for r in self.results if r.memory_delta is not None]

        stats = {
            'benchmark': self.name,
            'iterations': self.iterations,
            'setup_time_ms': round(self.setup_time, 2),
            'teardown_time_ms': round(self.teardown_time, 2),
            'duration': {
                'mean_ms': round(statistics.mean(durations), 2) if durations else 0,
                'median_ms': round(statistics.median(durations), 2) if durations else 0,
                'min_ms': round(min(durations), 2) if durations else 0,
                'max_ms': round(max(durations), 2) if durations else 0,
                'stdev_ms': round(statistics.stdev(durations), 2) if len(durations) > 1 else 0
            },
            'memory': {
                'mean_delta_mb': round(statistics.mean(memory_deltas), 2) if memory_deltas else 0,
                'max_delta_mb': round(max(memory_deltas), 2) if memory_deltas else 0
            },
            'raw_results': [r.to_dict() for r in self.results]
        }

        return stats


class ProcessAttachmentBenchmark(FridaBenchmark):
    """Benchmark process attachment performance"""

    def __init__(self, target_process: str = "notepad.exe"):
        super().__init__(f"Process Attachment ({target_process})")
        self.target_process = target_process
        self.test_process = None
        self.frida_manager = None

    def setup(self):
        """Start test process"""
        if platform.system() == 'Windows':
            import subprocess
            self.test_process = subprocess.Popen([self.target_process])
            time.sleep(1)  # Let process start

        self.frida_manager = FridaManager()

    def teardown(self):
        """Kill test process"""
        if self.test_process:
            self.test_process.terminate()
            self.test_process.wait()

        if self.frida_manager:
            self.frida_manager.cleanup()

    def run_iteration(self) -> PerformanceMetrics:
        """Measure attachment time"""
        metrics = PerformanceMetrics("attach")

        if self.test_process:
            metrics.start()

            try:
                # Attach to process
                success = self.frida_manager.attach_to_process(self.test_process.pid)
                metrics.add_metric('success', success)

                # Detach
                if success:
                    session_id = f"{self.target_process}_{self.test_process.pid}"
                    if session_id in self.frida_manager.sessions:
                        self.frida_manager.sessions[session_id].detach()

            except Exception as e:
                metrics.add_metric('error', str(e))

            metrics.stop()

        return metrics


class ScriptLoadingBenchmark(FridaBenchmark):
    """Benchmark script loading performance"""

    def __init__(self, script_size_kb: int = 10):
        super().__init__(f"Script Loading ({script_size_kb}KB)")
        self.script_size_kb = script_size_kb
        self.frida_manager = None
        self.session_id = None
        self.test_script = None

    def setup(self):
        """Create test script and attach to current process"""
        # Generate test script of specified size
        script_content = self._generate_test_script(self.script_size_kb)

        # Save test script
        self.test_script = Path("test_benchmark_script.js")
        self.test_script.write_text(script_content)

        # Attach to current process
        self.frida_manager = FridaManager()
        pid = psutil.Process().pid
        self.frida_manager.attach_to_process(pid)
        self.session_id = f"python_{pid}"

    def teardown(self):
        """Clean up"""
        if self.test_script and self.test_script.exists():
            self.test_script.unlink()

        if self.frida_manager:
            self.frida_manager.cleanup()

    def _generate_test_script(self, size_kb: int) -> str:
        """Generate test script of specified size"""
        # Base script
        script = """
        // Benchmark test script
        var hookCount = 0;

        Interceptor.attach(Module.findExportByName('kernel32.dll', 'GetTickCount'), {
            onEnter: function(args) {
                hookCount++;
            }
        });

        """

        # Add padding to reach desired size
        target_bytes = size_kb * 1024
        padding_needed = target_bytes - len(script)

        if padding_needed > 0:
            # Add comments to pad size
            comment_line = "// " + "x" * 77 + "\n"
            lines_needed = padding_needed // len(comment_line)
            script += comment_line * lines_needed

        return script

    def run_iteration(self) -> PerformanceMetrics:
        """Measure script loading time"""
        metrics = PerformanceMetrics("script_load")

        if self.session_id and self.test_script:
            metrics.start()

            try:
                # Load script
                success = self.frida_manager.load_script(
                    self.session_id,
                    str(self.test_script)
                )
                metrics.add_metric('success', success)
                metrics.add_metric('script_size_kb', self.script_size_kb)

                # Unload script (remove from tracking)
                script_key = f"{self.session_id}:{self.test_script.stem}"
                if script_key in self.frida_manager.scripts:
                    del self.frida_manager.scripts[script_key]

            except Exception as e:
                metrics.add_metric('error', str(e))

            metrics.stop()

        return metrics


class HookPerformanceBenchmark(FridaBenchmark):
    """Benchmark hook execution performance"""

    def __init__(self, num_hooks: int = 100):
        super().__init__(f"Hook Performance ({num_hooks} hooks)")
        self.num_hooks = num_hooks
        self.frida_manager = None
        self.session_id = None

    def setup(self):
        """Setup hooks"""
        self.frida_manager = FridaManager()
        pid = psutil.Process().pid
        self.frida_manager.attach_to_process(pid)
        self.session_id = f"python_{pid}"

        # Create script with multiple hooks
        script = self._generate_hook_script(self.num_hooks)

        # Save and load script
        script_path = Path("hook_benchmark.js")
        script_path.write_text(script)

        self.frida_manager.load_script(self.session_id, str(script_path))
        script_path.unlink()

    def teardown(self):
        """Clean up"""
        if self.frida_manager:
            self.frida_manager.cleanup()

    def _generate_hook_script(self, num_hooks: int) -> str:
        """Generate script with specified number of hooks"""
        # Common APIs to hook
        apis = [
            ('kernel32.dll', 'GetTickCount'),
            ('kernel32.dll', 'GetCurrentProcessId'),
            ('kernel32.dll', 'GetCurrentThreadId'),
            ('ntdll.dll', 'RtlGetCurrentPeb'),
            ('kernel32.dll', 'GetModuleHandleW'),
        ]

        script_lines = ["// Hook performance benchmark script"]
        script_lines.append("var hookExecutions = 0;")
        script_lines.append("")

        for i in range(num_hooks):
            api_idx = i % len(apis)
            module, func = apis[api_idx]

            script_lines.append(f"""
            // Hook {i+1}
            {{
                const target = Module.findExportByName('{module}', '{func}');
                if (target) {{
                    Interceptor.attach(target, {{
                        onEnter: function(args) {{
                            hookExecutions++;
                        }}
                    }});
                }}
            }}
            """)

        return "\n".join(script_lines)

    def run_iteration(self) -> PerformanceMetrics:
        """Measure hook execution overhead"""
        metrics = PerformanceMetrics("hook_execution")

        # Call hooked functions to measure overhead
        import ctypes
        kernel32 = ctypes.WinDLL('kernel32')

        metrics.start()

        # Execute hooked functions multiple times
        executions = 1000
        for _ in range(executions):
            kernel32.GetTickCount()
            kernel32.GetCurrentProcessId()
            kernel32.GetCurrentThreadId()

        metrics.stop()

        metrics.add_metric('num_hooks', self.num_hooks)
        metrics.add_metric('executions', executions)
        metrics.add_metric('overhead_per_call_us',
                          (metrics.duration * 1000) / executions)  # microseconds

        return metrics


class MemoryUsageBenchmark(FridaBenchmark):
    """Benchmark memory usage patterns"""

    def __init__(self, script_count: int = 10):
        super().__init__(f"Memory Usage ({script_count} scripts)")
        self.script_count = script_count
        self.frida_manager = None
        self.session_id = None
        self.loaded_scripts = []

    def setup(self):
        """Setup environment"""
        self.frida_manager = FridaManager()
        pid = psutil.Process().pid
        self.frida_manager.attach_to_process(pid)
        self.session_id = f"python_{pid}"

    def teardown(self):
        """Clean up"""
        for script_path in self.loaded_scripts:
            if script_path.exists():
                script_path.unlink()

        if self.frida_manager:
            self.frida_manager.cleanup()

    def run_iteration(self) -> PerformanceMetrics:
        """Measure memory usage with multiple scripts"""
        metrics = PerformanceMetrics("memory_usage")

        # Measure baseline
        gc.collect()
        metrics.start()
        baseline_memory = psutil.Process().memory_info().rss / 1024 / 1024

        # Load multiple scripts
        for i in range(self.script_count):
            script = f"""
            // Memory test script {i}
            var data{i} = [];
            for (var j = 0; j < 1000; j++) {{
                data{i}.push({{
                    id: j,
                    value: 'x'.repeat(100)
                }});
            }}

            Interceptor.attach(Module.findExportByName('kernel32.dll', 'GetTickCount'), {{
                onEnter: function(args) {{
                    // Access data to prevent optimization
                    var x = data{i}[0];
                }}
            }});
            """

            script_path = Path(f"memory_test_{i}.js")
            script_path.write_text(script)
            self.loaded_scripts.append(script_path)

            self.frida_manager.load_script(self.session_id, str(script_path))

        # Measure after loading
        time.sleep(0.5)  # Let memory settle
        after_memory = psutil.Process().memory_info().rss / 1024 / 1024

        metrics.stop()

        metrics.add_metric('baseline_memory_mb', round(baseline_memory, 2))
        metrics.add_metric('after_memory_mb', round(after_memory, 2))
        metrics.add_metric('scripts_loaded', self.script_count)
        metrics.add_metric('memory_per_script_mb',
                          round((after_memory - baseline_memory) / self.script_count, 2))

        # Clean up loaded scripts for next iteration
        for script_path in self.loaded_scripts:
            if script_path.exists():
                script_path.unlink()
        self.loaded_scripts.clear()

        return metrics


class OptimizationBenchmark(FridaBenchmark):
    """Benchmark optimization features"""

    def __init__(self):
        super().__init__("Optimization Features", iterations=5)
        self.frida_manager = None
        self.session_id = None

    def setup(self):
        """Setup environment"""
        self.frida_manager = FridaManager()
        pid = psutil.Process().pid
        self.frida_manager.attach_to_process(pid)
        self.session_id = f"python_{pid}"

    def teardown(self):
        """Clean up"""
        if self.frida_manager:
            self.frida_manager.cleanup()

    def run_iteration(self) -> PerformanceMetrics:
        """Compare optimized vs non-optimized performance"""
        metrics = PerformanceMetrics("optimization")

        # Test without optimization
        self.frida_manager.optimizer.optimization_enabled = False
        metrics.start()

        # Load test script
        script = """
        var count = 0;
        Interceptor.attach(Module.findExportByName('kernel32.dll', 'GetTickCount'), {
            onEnter: function(args) {
                count++;
                if (count % 100 === 0) {
                    send({type: 'count', value: count});
                }
            }
        });
        """

        script_path = Path("opt_test.js")
        script_path.write_text(script)

        start = time.perf_counter()
        self.frida_manager.load_script(self.session_id, str(script_path))
        no_opt_time = (time.perf_counter() - start) * 1000

        # Clean up
        script_key = f"{self.session_id}:opt_test"
        if script_key in self.frida_manager.scripts:
            del self.frida_manager.scripts[script_key]

        # Test with optimization
        self.frida_manager.optimizer.optimization_enabled = True

        start = time.perf_counter()
        self.frida_manager.load_script(self.session_id, str(script_path))
        opt_time = (time.perf_counter() - start) * 1000

        metrics.stop()

        script_path.unlink()

        metrics.add_metric('no_optimization_ms', round(no_opt_time, 2))
        metrics.add_metric('with_optimization_ms', round(opt_time, 2))
        metrics.add_metric('improvement_percent',
                          round(((no_opt_time - opt_time) / no_opt_time) * 100, 2))

        return metrics


class BenchmarkSuite:
    """Complete benchmark suite"""

    def __init__(self):
        self.benchmarks = []
        self.results = {}
        self.report_file = Path("frida_performance_report.json")

    def add_benchmark(self, benchmark: FridaBenchmark):
        """Add benchmark to suite"""
        self.benchmarks.append(benchmark)

    def run_all(self) -> Dict[str, Any]:
        """Run all benchmarks"""
        print("="*60)
        print("Frida Performance Benchmark Suite")
        print("="*60)
        print(f"Platform: {platform.system()} {platform.release()}")
        print(f"Python: {sys.version.split()[0]}")

        if FRIDA_AVAILABLE:
            print(f"Frida: {frida.__version__}")

        print(f"CPU: {psutil.cpu_count()} cores")
        print(f"Memory: {psutil.virtual_memory().total / 1024 / 1024 / 1024:.1f} GB")
        print("="*60)
        print()

        suite_start = time.perf_counter()

        for benchmark in self.benchmarks:
            try:
                result = benchmark.run()
                self.results[benchmark.name] = result
            except Exception as e:
                print(f"Benchmark {benchmark.name} failed: {e}")
                self.results[benchmark.name] = {'error': str(e)}

            print()

        suite_duration = (time.perf_counter() - suite_start)

        # Generate summary
        summary = {
            'timestamp': datetime.now().isoformat(),
            'platform': {
                'system': platform.system(),
                'release': platform.release(),
                'machine': platform.machine(),
                'python': sys.version.split()[0],
                'frida': frida.__version__ if FRIDA_AVAILABLE else 'N/A'
            },
            'hardware': {
                'cpu_count': psutil.cpu_count(),
                'memory_gb': round(psutil.virtual_memory().total / 1024 / 1024 / 1024, 1)
            },
            'suite_duration_seconds': round(suite_duration, 2),
            'benchmarks': self.results
        }

        # Save results
        with open(self.report_file, 'w') as f:
            json.dump(summary, f, indent=2)

        return summary

    def print_summary(self):
        """Print benchmark summary"""
        print("="*60)
        print("Benchmark Summary")
        print("="*60)

        for name, result in self.results.items():
            if 'error' in result:
                print(f"{name}: ERROR - {result['error']}")
                continue

            duration = result.get('duration', {})
            memory = result.get('memory', {})

            print(f"{name}:")
            print(f"  Duration: {duration.get('mean_ms', 'N/A')} ms (mean)")
            print(f"  Memory: {memory.get('mean_delta_mb', 'N/A')} MB (delta)")

            # Print additional metrics
            for r in result.get('raw_results', [])[:1]:  # First result only
                for k, v in r.items():
                    if k not in ['name', 'duration_ms', 'memory_start_mb',
                               'memory_end_mb', 'memory_delta_mb']:
                        print(f"  {k}: {v}")
            print()

        print(f"Report saved to: {self.report_file}")


class TestPerformanceBenchmarks(unittest.TestCase):
    """Unit tests for benchmark system"""

    def setUp(self):
        """Set up test environment"""
        if not FRIDA_AVAILABLE:
            self.skipTest("Frida not available")

    def test_performance_metrics(self):
        """Test PerformanceMetrics class"""
        metrics = PerformanceMetrics("test")

        metrics.start()
        time.sleep(0.1)  # Simulate work
        metrics.stop()

        self.assertIsNotNone(metrics.duration)
        self.assertGreater(metrics.duration, 0)
        self.assertIsNotNone(metrics.memory_delta)

        # Test dict conversion
        data = metrics.to_dict()
        self.assertEqual(data['name'], 'test')
        self.assertIn('duration_ms', data)
        self.assertIn('memory_delta_mb', data)

    def test_benchmark_statistics(self):
        """Test benchmark statistics calculation"""
        benchmark = FridaBenchmark("test", iterations=3)

        # Add mock results
        for i in range(3):
            metrics = PerformanceMetrics(f"test_{i}")
            metrics.duration = 10 + i  # 10, 11, 12
            metrics.memory_delta = i  # 0, 1, 2
            benchmark.results.append(metrics)
            
    def test_frida_performance_optimizer(self):
        """Test FridaPerformanceOptimizer functionality"""
        optimizer = FridaPerformanceOptimizer()
        
        # Test baseline measurement
        optimizer.measure_baseline()
        self.assertGreater(optimizer.baseline_memory, 0)
        self.assertGreaterEqual(optimizer.baseline_cpu, 0)
        
        # Test optimization settings
        optimizer.set_optimization_level("aggressive")
        self.assertEqual(optimizer.optimization_level, "aggressive")
        
        # Test hook filtering based on category
        should_hook_critical = optimizer.should_hook_function(
            "kernel32.dll", "VirtualProtect", HookCategory.CRITICAL
        )
        self.assertTrue(should_hook_critical)  # Critical should always be hooked
        
        # Test memory limit enforcement
        optimizer.memory_limit_mb = 100
        with patch.object(optimizer, 'get_current_memory') as mock_mem:
            mock_mem.return_value = 150  # Over limit
            should_hook_low = optimizer.should_hook_function(
                "user32.dll", "GetWindowText", HookCategory.LOW
            )
            self.assertFalse(should_hook_low)  # Low priority should be skipped when over limit
            
    def test_hook_category_priorities(self):
        """Test HookCategory priority ordering"""
        # Test category values (higher value = higher priority)
        self.assertGreater(HookCategory.CRITICAL.value, HookCategory.HIGH.value)
        self.assertGreater(HookCategory.HIGH.value, HookCategory.MEDIUM.value)
        self.assertGreater(HookCategory.MEDIUM.value, HookCategory.LOW.value)
        
        # Test category filtering in optimizer
        optimizer = FridaPerformanceOptimizer()
        optimizer.minimum_category = HookCategory.MEDIUM
        
        # Should hook medium and above
        self.assertTrue(optimizer.should_hook_category(HookCategory.CRITICAL))
        self.assertTrue(optimizer.should_hook_category(HookCategory.HIGH))
        self.assertTrue(optimizer.should_hook_category(HookCategory.MEDIUM))
        self.assertFalse(optimizer.should_hook_category(HookCategory.LOW))

        stats = benchmark._calculate_statistics()

        self.assertEqual(stats['duration']['mean_ms'], 11.0)
        self.assertEqual(stats['duration']['median_ms'], 11.0)
        self.assertEqual(stats['duration']['min_ms'], 10.0)
        self.assertEqual(stats['duration']['max_ms'], 12.0)
        self.assertEqual(stats['memory']['mean_delta_mb'], 1.0)


def run_performance_benchmarks():
    """Run complete performance benchmark suite"""
    if not FRIDA_AVAILABLE:
        print("Frida not available - skipping benchmarks")
        return False

    if platform.system() != 'Windows':
        print("Performance benchmarks are Windows-specific")
        return False

    # Create benchmark suite
    suite = BenchmarkSuite()

    # Add benchmarks
    # Note: Process attachment benchmark disabled by default to avoid creating processes
    # suite.add_benchmark(ProcessAttachmentBenchmark())

    suite.add_benchmark(ScriptLoadingBenchmark(script_size_kb=1))
    suite.add_benchmark(ScriptLoadingBenchmark(script_size_kb=10))
    suite.add_benchmark(ScriptLoadingBenchmark(script_size_kb=50))

    suite.add_benchmark(HookPerformanceBenchmark(num_hooks=10))
    suite.add_benchmark(HookPerformanceBenchmark(num_hooks=50))
    suite.add_benchmark(HookPerformanceBenchmark(num_hooks=100))

    suite.add_benchmark(MemoryUsageBenchmark(script_count=5))
    suite.add_benchmark(MemoryUsageBenchmark(script_count=20))

    suite.add_benchmark(OptimizationBenchmark())

    # Run benchmarks
    suite.run_all()

    # Print summary
    suite.print_summary()

    return True


def generate_performance_trends(report_files: List[Path]) -> Dict[str, Any]:
    """Generate performance trend analysis from multiple reports"""
    trends = defaultdict(lambda: defaultdict(list))

    for report_file in report_files:
        if not report_file.exists():
            continue

        with open(report_file) as f:
            data = json.load(f)

        timestamp = data['timestamp']

        for benchmark_name, result in data['benchmarks'].items():
            if 'error' not in result:
                duration = result.get('duration', {}).get('mean_ms')
                if duration:
                    trends[benchmark_name]['duration'].append({
                        'timestamp': timestamp,
                        'value': duration
                    })

                memory = result.get('memory', {}).get('mean_delta_mb')
                if memory:
                    trends[benchmark_name]['memory'].append({
                        'timestamp': timestamp,
                        'value': memory
                    })

    return dict(trends)


if __name__ == '__main__':
    import sys

    if '--test' in sys.argv:
        # Run unit tests
        unittest.main(argv=[''], exit=False, verbosity=2)
    else:
        # Run benchmarks
        success = run_performance_benchmarks()
        sys.exit(0 if success else 1)
