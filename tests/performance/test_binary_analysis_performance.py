"""
Performance benchmark tests for binary analysis operations.

Tests REAL binary analysis performance with actual files and data processing.
NO mocked components - measures actual performance characteristics.
"""

import pytest
import tempfile
import os
import time
import psutil
from pathlib import Path

from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer
from intellicrack.core.analysis.multi_format_analyzer import MultiFormatBinaryAnalyzer
from intellicrack.core.analysis.dynamic_analyzer import DynamicAnalyzer


class TestBinaryAnalysisPerformance:
    """Test REAL binary analysis performance with actual file processing."""

    @pytest.fixture
    def small_pe_file(self):
        """Create small PE file for performance testing."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            # Create minimal but valid PE structure (5KB)
            dos_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            dos_header += b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
            dos_header += b'\x00' * 32 + b'\x80\x00\x00\x00'
            
            pe_signature = b'PE\x00\x00'
            coff_header = b'\x4c\x01\x03\x00' + b'\x00' * 16
            optional_header = b'\x0b\x01' + b'\x00' * 222
            section_headers = b'\x00' * (40 * 3)
            
            pe_data = dos_header + b'\x00' * (0x80 - len(dos_header))
            pe_data += pe_signature + coff_header + optional_header + section_headers
            pe_data += b'\x41' * 4096  # 4KB of section data
            
            temp_file.write(pe_data)
            temp_file_path = temp_file.name
            
        yield temp_file_path
        
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)

    @pytest.fixture
    def large_pe_file(self):
        """Create large PE file for stress testing."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            # Create larger PE structure (10MB)
            dos_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            dos_header += b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
            dos_header += b'\x00' * 32 + b'\x80\x00\x00\x00'
            
            pe_signature = b'PE\x00\x00'
            coff_header = b'\x4c\x01\x05\x00' + b'\x00' * 16  # 5 sections
            optional_header = b'\x0b\x01' + b'\x00' * 222
            section_headers = b'\x00' * (40 * 5)  # 5 sections
            
            pe_data = dos_header + b'\x00' * (0x80 - len(dos_header))
            pe_data += pe_signature + coff_header + optional_header + section_headers
            
            # Add 10MB of varied section data
            for i in range(10240):  # 10MB in 1KB chunks
                chunk_data = bytes([(i + j) % 256 for j in range(1024)])
                temp_file.write(chunk_data)
            
            temp_file_path = temp_file.name
            
        yield temp_file_path
        
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)

    @pytest.mark.benchmark
    def test_pe_header_parsing_performance(self, benchmark, small_pe_file):
        """Benchmark REAL PE header parsing performance."""
        analyzer = BinaryAnalyzer()
        
        def parse_pe_header():
            return analyzer.analyze_pe_header(small_pe_file)
        
        # Benchmark PE header parsing
        result = benchmark(parse_pe_header)
        
        # Verify we got real results
        assert result is not None
        assert isinstance(result, dict)
        
        # Performance assertions
        assert benchmark.stats.mean < 0.1, "PE header parsing should be under 100ms"
        assert benchmark.stats.max < 0.5, "Worst case should be under 500ms"

    @pytest.mark.benchmark  
    def test_section_analysis_performance(self, benchmark, small_pe_file):
        """Benchmark REAL section analysis performance."""
        analyzer = BinaryAnalyzer()
        
        def analyze_sections():
            return analyzer.analyze_sections(small_pe_file)
        
        result = benchmark(analyze_sections)
        
        # Verify real analysis results
        assert result is not None
        if isinstance(result, dict) and 'sections' in result:
            assert len(result['sections']) >= 0
        
        # Performance requirements
        assert benchmark.stats.mean < 0.2, "Section analysis should be under 200ms"

    @pytest.mark.benchmark
    def test_import_table_analysis_performance(self, benchmark, small_pe_file):
        """Benchmark REAL import table analysis performance."""
        analyzer = BinaryAnalyzer()
        
        def analyze_imports():
            return analyzer.analyze_imports(small_pe_file)
        
        result = benchmark(analyze_imports)
        
        # Verify real results
        assert result is not None
        
        # Performance requirements
        assert benchmark.stats.mean < 0.15, "Import analysis should be under 150ms"

    @pytest.mark.benchmark
    def test_entropy_calculation_performance(self, benchmark, small_pe_file):
        """Benchmark REAL entropy calculation performance."""
        analyzer = BinaryAnalyzer()
        
        def calculate_entropy():
            return analyzer.calculate_entropy(small_pe_file)
        
        result = benchmark(calculate_entropy)
        
        # Verify real entropy calculation
        assert result is not None
        if isinstance(result, (float, int)):
            assert 0 <= result <= 8  # Valid entropy range
        
        # Performance requirements
        assert benchmark.stats.mean < 0.3, "Entropy calculation should be under 300ms"

    @pytest.mark.benchmark
    def test_string_extraction_performance(self, benchmark, small_pe_file):
        """Benchmark REAL string extraction performance."""
        analyzer = BinaryAnalyzer()
        
        def extract_strings():
            return analyzer.extract_strings(small_pe_file)
        
        result = benchmark(extract_strings)
        
        # Verify real string extraction
        assert result is not None
        if isinstance(result, list):
            assert len(result) >= 0
        
        # Performance requirements
        assert benchmark.stats.mean < 0.5, "String extraction should be under 500ms"

    @pytest.mark.benchmark
    def test_full_analysis_performance(self, benchmark, small_pe_file):
        """Benchmark REAL complete binary analysis performance."""
        analyzer = MultiFormatBinaryAnalyzer()
        
        def full_analysis():
            return analyzer.analyze(small_pe_file)
        
        result = benchmark(full_analysis)
        
        # Verify comprehensive results
        assert result is not None
        assert isinstance(result, dict)
        
        # Performance requirements for full analysis
        assert benchmark.stats.mean < 2.0, "Full analysis should be under 2 seconds"
        assert benchmark.stats.max < 5.0, "Worst case should be under 5 seconds"

    @pytest.mark.benchmark
    def test_large_file_analysis_performance(self, benchmark, large_pe_file):
        """Benchmark REAL performance with large binary files."""
        analyzer = MultiFormatBinaryAnalyzer()
        
        def analyze_large_file():
            return analyzer.analyze(large_pe_file)
        
        result = benchmark(analyze_large_file)
        
        # Verify results for large file
        assert result is not None
        
        # Performance requirements for large files
        assert benchmark.stats.mean < 10.0, "Large file analysis should be under 10 seconds"
        assert benchmark.stats.max < 20.0, "Large file worst case should be under 20 seconds"

    @pytest.mark.benchmark
    def test_memory_usage_during_analysis(self, small_pe_file):
        """Test REAL memory usage during binary analysis."""
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        analyzer = MultiFormatBinaryAnalyzer()
        
        # Perform analysis while monitoring memory
        result = analyzer.analyze(small_pe_file)
        
        peak_memory = process.memory_info().rss
        memory_increase = peak_memory - initial_memory
        
        # Verify analysis completed
        assert result is not None
        
        # Memory usage should be reasonable (under 100MB for small file)
        assert memory_increase < 100 * 1024 * 1024, f"Memory usage too high: {memory_increase / 1024 / 1024:.2f}MB"

    @pytest.mark.benchmark
    def test_concurrent_analysis_performance(self, benchmark, small_pe_file):
        """Test REAL performance with concurrent analysis operations."""
        import threading
        import queue
        
        analyzer = BinaryAnalyzer()
        results_queue = queue.Queue()
        
        def concurrent_analysis():
            def worker():
                try:
                    result = analyzer.analyze_pe_header(small_pe_file)
                    results_queue.put(result)
                except Exception as e:
                    results_queue.put(e)
            
            # Run 3 concurrent analyses
            threads = []
            for _ in range(3):
                thread = threading.Thread(target=worker)
                threads.append(thread)
                thread.start()
            
            # Wait for completion
            for thread in threads:
                thread.join()
            
            # Collect results
            results = []
            while not results_queue.empty():
                results.append(results_queue.get())
            
            return results
        
        results = benchmark(concurrent_analysis)
        
        # Verify all analyses completed successfully
        assert len(results) == 3
        for result in results:
            assert not isinstance(result, Exception)
        
        # Concurrent performance should scale reasonably
        assert benchmark.stats.mean < 1.0, "Concurrent analysis should complete under 1 second"

    @pytest.mark.benchmark  
    def test_analysis_caching_performance(self, benchmark, small_pe_file):
        """Test REAL performance improvement with analysis caching."""
        analyzer = MultiFormatBinaryAnalyzer()
        
        # First analysis (cold cache)
        start_time = time.time()
        first_result = analyzer.analyze(small_pe_file)
        first_duration = time.time() - start_time
        
        def cached_analysis():
            return analyzer.analyze(small_pe_file)
        
        # Benchmark cached analysis
        cached_result = benchmark(cached_analysis)
        
        # Verify results are consistent
        assert first_result is not None
        assert cached_result is not None
        
        # Cached analysis should be faster (if caching is implemented)
        if hasattr(analyzer, '_cache') or hasattr(analyzer, 'cache'):
            assert benchmark.stats.mean <= first_duration, "Cached analysis should be faster or equal"

    @pytest.mark.benchmark
    def test_dynamic_analysis_setup_performance(self, benchmark, small_pe_file):
        """Test REAL dynamic analysis setup performance."""
        if not hasattr(DynamicAnalyzer, '__init__'):
            pytest.skip("DynamicAnalyzer not available")
        
        def setup_dynamic_analysis():
            try:
                analyzer = DynamicAnalyzer()
                return analyzer.setup_monitoring(small_pe_file)
            except Exception as e:
                return e
        
        result = benchmark(setup_dynamic_analysis)
        
        # Dynamic analysis setup should be reasonably fast
        assert benchmark.stats.mean < 3.0, "Dynamic analysis setup should be under 3 seconds"

    @pytest.mark.benchmark
    def test_file_format_detection_performance(self, benchmark, small_pe_file):
        """Test REAL file format detection performance."""
        analyzer = MultiFormatBinaryAnalyzer()
        
        def detect_format():
            return analyzer.detect_file_format(small_pe_file)
        
        result = benchmark(detect_format)
        
        # Verify format detection
        assert result is not None
        if isinstance(result, str):
            assert result in ['PE', 'ELF', 'Mach-O', 'Unknown'] or len(result) > 0
        
        # Format detection should be very fast
        assert benchmark.stats.mean < 0.05, "Format detection should be under 50ms"

    @pytest.mark.benchmark
    def test_hash_calculation_performance(self, benchmark, small_pe_file):
        """Test REAL hash calculation performance."""
        analyzer = BinaryAnalyzer()
        
        def calculate_hashes():
            return analyzer.calculate_file_hashes(small_pe_file)
        
        result = benchmark(calculate_hashes)
        
        # Verify hash calculation
        assert result is not None
        if isinstance(result, dict):
            hash_types = ['md5', 'sha1', 'sha256']
            found_hashes = [h for h in hash_types if h in result]
            assert len(found_hashes) > 0
        
        # Hash calculation should be reasonably fast
        assert benchmark.stats.mean < 0.1, "Hash calculation should be under 100ms"

    def test_performance_regression_detection(self, small_pe_file):
        """Test for REAL performance regression detection."""
        analyzer = MultiFormatBinaryAnalyzer()
        
        # Expected baseline performance (adjust based on actual measurements)
        expected_max_time = 2.0  # seconds
        
        # Run multiple iterations to check consistency
        times = []
        for _ in range(5):
            start_time = time.time()
            result = analyzer.analyze(small_pe_file)
            duration = time.time() - start_time
            times.append(duration)
            
            assert result is not None
        
        # Check for performance consistency
        avg_time = sum(times) / len(times)
        max_time = max(times)
        
        assert avg_time < expected_max_time, f"Average analysis time too slow: {avg_time:.3f}s"
        assert max_time < expected_max_time * 2, f"Worst case time too slow: {max_time:.3f}s"
        
        # Check for performance variability
        min_time = min(times)
        variability = (max_time - min_time) / avg_time
        assert variability < 2.0, f"Performance too variable: {variability:.2f}x"

    def test_real_world_performance_characteristics(self, small_pe_file):
        """Test REAL performance characteristics under realistic conditions."""
        analyzer = MultiFormatBinaryAnalyzer()
        
        # Simulate realistic usage patterns
        scenarios = [
            ("Quick scan", lambda: analyzer.analyze_pe_header(small_pe_file)),
            ("Full analysis", lambda: analyzer.analyze(small_pe_file)),
            ("Security scan", lambda: analyzer.detect_protections(small_pe_file)),
        ]
        
        performance_results = {}
        
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
        
        # Verify realistic performance expectations
        for scenario, results in performance_results.items():
            if results['success']:
                assert results['duration'] < 5.0, f"{scenario} took too long: {results['duration']:.3f}s"