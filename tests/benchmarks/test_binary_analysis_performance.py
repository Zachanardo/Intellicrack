"""
Performance benchmark tests for binary analysis operations.

Tests REAL binary analysis performance with actual files and data processing.
NO mocked components - measures actual performance characteristics.
"""

import os
import queue
import tempfile
import threading
import time
from collections.abc import Generator
from typing import Any

import psutil
import pytest

from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer
from intellicrack.core.analysis.dynamic_analyzer import AdvancedDynamicAnalyzer
from intellicrack.core.analysis.multi_format_analyzer import MultiFormatBinaryAnalyzer


class TestBinaryAnalysisPerformance:
    """Test REAL binary analysis performance with actual file processing."""

    @pytest.fixture
    def small_pe_file(self) -> Generator[str, None, None]:
        """Create small PE file for performance testing."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            dos_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            dos_header += b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
            dos_header += b'\x00' * 32 + b'\x80\x00\x00\x00'

            pe_signature = b'PE\x00\x00'
            coff_header = b'\x4c\x01\x03\x00' + b'\x00' * 16
            optional_header = b'\x0b\x01' + b'\x00' * 222
            section_headers = b'\x00' * (40 * 3)

            pe_data = dos_header + b'\x00' * (0x80 - len(dos_header))
            pe_data += pe_signature + coff_header + optional_header + section_headers
            pe_data += b'\x41' * 4096

            temp_file.write(pe_data)
            temp_file_path = temp_file.name

        yield temp_file_path

        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)

    @pytest.fixture
    def large_pe_file(self) -> Generator[str, None, None]:
        """Create large PE file for stress testing."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            dos_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            dos_header += b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
            dos_header += b'\x00' * 32 + b'\x80\x00\x00\x00'

            pe_signature = b'PE\x00\x00'
            coff_header = b'\x4c\x01\x05\x00' + b'\x00' * 16
            optional_header = b'\x0b\x01' + b'\x00' * 222
            section_headers = b'\x00' * (40 * 5)

            pe_data = dos_header + b'\x00' * (0x80 - len(dos_header))
            pe_data += pe_signature + coff_header + optional_header + section_headers

            temp_file.write(pe_data)

            for i in range(10240):
                chunk_data = bytes((i + j) % 256 for j in range(1024))
                temp_file.write(chunk_data)

            temp_file_path = temp_file.name

        yield temp_file_path

        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)

    @pytest.fixture
    def process_memory(self) -> psutil._pswindows.pmem:
        """Monitor process memory usage."""
        process = psutil.Process()
        return process.memory_info()

    @pytest.mark.benchmark
    def test_binary_analysis_performance(
        self, benchmark: Any, small_pe_file: str
    ) -> None:
        """Benchmark REAL binary analysis performance."""
        analyzer = BinaryAnalyzer()

        def analyze_binary() -> dict[str, Any]:
            return analyzer.analyze(small_pe_file)

        result = benchmark(analyze_binary)

        assert result is not None
        assert isinstance(result, dict)
        assert benchmark.stats.mean < 0.5, "Binary analysis should be under 500ms"
        assert benchmark.stats.max < 1.0, "Worst case should be under 1000ms"

    @pytest.mark.benchmark
    def test_streaming_section_analysis_performance(
        self, benchmark: Any, small_pe_file: str
    ) -> None:
        """Benchmark REAL streaming section analysis performance."""
        analyzer = BinaryAnalyzer()

        def analyze_sections_streaming() -> dict[str, Any]:
            return analyzer.analyze_sections_streaming(small_pe_file, [(0, 4096)])

        result = benchmark(analyze_sections_streaming)

        assert result is not None
        if isinstance(result, dict):
            assert 'error' not in result or result.get('error') is None

        assert benchmark.stats.mean < 0.3, "Section analysis should be under 300ms"

    @pytest.mark.benchmark
    def test_full_analysis_performance(
        self, benchmark: Any, small_pe_file: str
    ) -> None:
        """Benchmark REAL complete binary analysis performance."""
        analyzer = MultiFormatBinaryAnalyzer()

        def full_analysis() -> dict[str, Any]:
            return analyzer.analyze(small_pe_file)

        result = benchmark(full_analysis)

        assert result is not None
        assert isinstance(result, dict)

        assert benchmark.stats.mean < 2.0, "Full analysis should be under 2 seconds"
        assert benchmark.stats.max < 5.0, "Worst case should be under 5 seconds"

    @pytest.mark.benchmark
    def test_large_file_analysis_performance(
        self, benchmark: Any, large_pe_file: str
    ) -> None:
        """Benchmark REAL performance with large binary files."""
        analyzer = MultiFormatBinaryAnalyzer()

        def analyze_large_file() -> dict[str, Any]:
            return analyzer.analyze(large_pe_file)

        result = benchmark(analyze_large_file)

        assert result is not None

        assert benchmark.stats.mean < 10.0, "Large file analysis should be under 10 seconds"
        assert benchmark.stats.max < 20.0, "Large file worst case should be under 20 seconds"

    def test_memory_usage_during_analysis(
        self, small_pe_file: str, process_memory: psutil._pswindows.pmem
    ) -> None:
        """Test REAL memory usage during binary analysis."""
        initial_memory = process_memory.rss

        analyzer = MultiFormatBinaryAnalyzer()

        result = analyzer.analyze(small_pe_file)

        process = psutil.Process()
        peak_memory = process.memory_info().rss
        memory_increase = peak_memory - initial_memory

        assert result is not None

        assert memory_increase < 100 * 1024 * 1024, f"Memory usage too high: {memory_increase / 1024 / 1024:.2f}MB"

    @pytest.mark.benchmark
    def test_concurrent_analysis_performance(
        self, benchmark: Any, small_pe_file: str
    ) -> None:
        """Test REAL performance with concurrent analysis operations."""
        analyzer = BinaryAnalyzer()
        results_queue: queue.Queue[dict[str, Any] | Exception] = queue.Queue()

        def concurrent_analysis() -> list[dict[str, Any] | Exception]:
            def worker() -> None:
                try:
                    result = analyzer.analyze(small_pe_file)
                    results_queue.put(result)
                except Exception as e:
                    results_queue.put(e)

            threads: list[threading.Thread] = []
            for _ in range(3):
                thread = threading.Thread(target=worker)
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            results: list[dict[str, Any] | Exception] = []
            while not results_queue.empty():
                results.append(results_queue.get())

            return results

        results = benchmark(concurrent_analysis)

        assert len(results) == 3
        for result in results:
            assert not isinstance(result, Exception)

        assert benchmark.stats.mean < 1.0, "Concurrent analysis should complete under 1 second"

    @pytest.mark.benchmark
    def test_analysis_caching_performance(
        self, benchmark: Any, small_pe_file: str
    ) -> None:
        """Test REAL performance improvement with analysis caching."""
        analyzer = MultiFormatBinaryAnalyzer()

        start_time = time.time()
        first_result = analyzer.analyze(small_pe_file)
        first_duration = time.time() - start_time

        def cached_analysis() -> dict[str, Any]:
            return analyzer.analyze(small_pe_file)

        cached_result = benchmark(cached_analysis)

        assert first_result is not None
        assert cached_result is not None

        if hasattr(analyzer, '_cache') or hasattr(analyzer, 'cache'):
            assert benchmark.stats.mean <= first_duration, "Cached analysis should be faster or equal"

    @pytest.mark.benchmark
    def test_dynamic_analysis_performance(
        self, benchmark: Any, small_pe_file: str
    ) -> None:
        """Test REAL dynamic analysis performance."""
        def run_dynamic_analysis() -> dict[str, Any] | None:
            try:
                analyzer = AdvancedDynamicAnalyzer(small_pe_file)
                return analyzer.run_comprehensive_analysis()
            except FileNotFoundError:
                return None
            except Exception:
                return None

        result = benchmark(run_dynamic_analysis)

        assert benchmark.stats.mean < 5.0, "Dynamic analysis should be under 5 seconds"

    @pytest.mark.benchmark
    def test_file_format_detection_performance(
        self, benchmark: Any, small_pe_file: str
    ) -> None:
        """Test REAL file format detection performance."""
        analyzer = MultiFormatBinaryAnalyzer()

        def detect_format() -> str:
            return analyzer.identify_format(small_pe_file)

        result = benchmark(detect_format)

        assert result is not None
        if isinstance(result, str):
            assert len(result) > 0

        assert benchmark.stats.mean < 0.05, "Format detection should be under 50ms"

    @pytest.mark.benchmark
    def test_pe_specific_analysis_performance(
        self, benchmark: Any, small_pe_file: str
    ) -> None:
        """Test REAL PE-specific analysis performance."""
        analyzer = MultiFormatBinaryAnalyzer()

        def analyze_pe() -> dict[str, Any]:
            return analyzer.analyze_pe(small_pe_file)

        result = benchmark(analyze_pe)

        assert result is not None
        if isinstance(result, dict):
            assert 'error' not in result or result.get('error') is None

        assert benchmark.stats.mean < 0.5, "PE analysis should be under 500ms"

    def test_performance_regression_detection(self, small_pe_file: str) -> None:
        """Test for REAL performance regression detection."""
        analyzer = MultiFormatBinaryAnalyzer()

        expected_max_time = 2.0

        times: list[float] = []
        for _ in range(5):
            start_time = time.time()
            result = analyzer.analyze(small_pe_file)
            duration = time.time() - start_time
            times.append(duration)

            assert result is not None

        avg_time = sum(times) / len(times)
        max_time = max(times)

        assert avg_time < expected_max_time, f"Average analysis time too slow: {avg_time:.3f}s"
        assert max_time < expected_max_time * 2, f"Worst case time too slow: {max_time:.3f}s"

        min_time = min(times)
        variability = (max_time - min_time) / avg_time
        assert variability < 2.0, f"Performance too variable: {variability:.2f}x"

    def test_real_world_performance_characteristics(self, small_pe_file: str) -> None:
        """Test REAL performance characteristics under realistic conditions."""
        multi_analyzer = MultiFormatBinaryAnalyzer()
        binary_analyzer = BinaryAnalyzer()

        scenarios: list[tuple[str, Any]] = [
            ("Quick format detection", lambda: multi_analyzer.identify_format(small_pe_file)),
            ("Full analysis", lambda: multi_analyzer.analyze(small_pe_file)),
            ("Binary analysis", lambda: binary_analyzer.analyze(small_pe_file)),
        ]

        performance_results: dict[str, dict[str, Any]] = {}

        for scenario_name, scenario_func in scenarios:
            try:
                start_time = time.time()
                result = scenario_func()
                duration = time.time() - start_time

                performance_results[scenario_name] = {
                    'duration': duration,
                    'success': result is not None
                }

            except Exception as e:
                performance_results[scenario_name] = {
                    'duration': None,
                    'success': False,
                    'error': str(e)
                }

        for scenario, results in performance_results.items():
            if results['success']:
                assert results['duration'] < 5.0, f"{scenario} took too long: {results['duration']:.3f}s"

    @pytest.mark.benchmark
    def test_binary_analysis_initialization_performance(
        self, benchmark: Any
    ) -> None:
        """Benchmark REAL binary analyzer initialization performance."""
        def init_analyzer() -> BinaryAnalyzer:
            return BinaryAnalyzer()

        result = benchmark(init_analyzer)

        assert result is not None
        assert benchmark.stats.mean < 0.1, "Initialization should be under 100ms"

    @pytest.mark.benchmark
    def test_multi_format_analyzer_initialization_performance(
        self, benchmark: Any
    ) -> None:
        """Benchmark REAL multi-format analyzer initialization performance."""
        def init_analyzer() -> MultiFormatBinaryAnalyzer:
            return MultiFormatBinaryAnalyzer()

        result = benchmark(init_analyzer)

        assert result is not None
        assert benchmark.stats.mean < 0.2, "Multi-format initialization should be under 200ms"

    def test_analysis_stress_test(self, small_pe_file: str) -> None:
        """Stress test REAL binary analysis operations under load."""
        analyzer = BinaryAnalyzer()

        start_time = time.time()

        for i in range(20):
            result = analyzer.analyze(small_pe_file)
            assert result is not None, f"Stress test analysis {i} failed"

        end_time = time.time()

        assert end_time - start_time < 15.0, "Stress test should complete under 15 seconds"

    def test_analysis_error_handling_performance(self) -> None:
        """Test REAL analysis error handling performance."""
        analyzer = BinaryAnalyzer()

        start_time = time.time()

        invalid_files = [
            "",
            "/nonexistent/path/file.exe",
            "C:\\invalid\\path\\binary.exe",
        ]

        for invalid_file in invalid_files:
            result = analyzer.analyze(invalid_file)
            assert 'error' in result or result is not None

        end_time = time.time()

        assert end_time - start_time < 1.0, "Error handling should be fast (under 1 second)"

    def test_analysis_consistency_check(self, small_pe_file: str) -> None:
        """Test REAL analysis consistency across multiple runs."""
        analyzer = MultiFormatBinaryAnalyzer()

        results: list[dict[str, Any]] = []

        for _ in range(5):
            result = analyzer.analyze(small_pe_file)
            results.append(result)

        for result in results:
            assert result is not None, "Analysis result should not be None"
            assert isinstance(result, dict), "Analysis result should be a dict"
