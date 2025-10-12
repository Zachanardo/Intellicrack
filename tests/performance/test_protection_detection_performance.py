"""
Performance benchmarks for Intellicrack's protection detection and analysis capabilities.

This module contains comprehensive performance tests for protection detection and analysis in Intellicrack,
including basic protection detection speed benchmarks, advanced protection analysis benchmarks,
packer detection speed benchmarks, entropy analysis speed benchmarks,
YARA pattern matching speed benchmarks, analysis cache operations benchmarks,
concurrent protection detection performance tests, protection detection memory efficiency tests,
protection signature database operations benchmarks, protection detection accuracy vs speed tradeoff tests,
Intellicrack protection core operations benchmarks, protection analysis consistency tests,
protection detection error handling performance tests, protection detection stress tests,
protection bypass recommendation generation benchmarks, and protection analysis cache efficiency tests.
These tests ensure the protection detection components maintain high performance under various conditions.
"""

import pytest
import time
import threading
import tempfile
import os
import psutil
from unittest.mock import patch, MagicMock

from intellicrack.protection.protection_detector import ProtectionDetector
from intellicrack.protection.intellicrack_protection_core import IntellicrackProtectionCore
from intellicrack.protection.intellicrack_protection_advanced import IntellicrackProtectionAdvanced
from intellicrack.protection.analysis_cache import AnalysisCache
from intellicrack.core.analysis.yara_pattern_engine import YaraPatternEngine
from intellicrack.core.analysis.entropy_analyzer import EntropyAnalyzer


class TestProtectionDetectionPerformance:
    """Performance benchmarks for protection detection and analysis."""

    @pytest.fixture
    def sample_pe_file(self):
        """Create REAL PE file for testing."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            dos_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            dos_header += b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
            dos_header += b'\x00' * 40
            dos_header += b'\x80\x00\x00\x00'
            dos_header += b'\x00' * 60

            pe_signature = b'PE\x00\x00'
            coff_header = b'\x4c\x01\x03\x00' + b'\x00' * 16
            optional_header = b'\x0b\x01\x0e\x00' + b'\x00' * 220

            section_data = b'\x2e\x74\x65\x78\x74\x00\x00\x00'
            section_data += b'\x00\x10\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x04\x00\x00'
            section_data += b'\x00' * 16
            section_data += b'\x20\x00\x00\x60'

            temp_file.write(dos_header + pe_signature + coff_header + optional_header + section_data)
            temp_file.flush()
            yield temp_file.name

        try:
            os.unlink(temp_file.name)
        except:
            pass

    @pytest.fixture
    def packed_pe_file(self):
        """Create REAL packed PE file for testing."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            dos_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            dos_header += b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
            dos_header += b'\x00' * 40
            dos_header += b'\x80\x00\x00\x00'
            dos_header += b'\x00' * 60

            pe_signature = b'PE\x00\x00'
            coff_header = b'\x4c\x01\x03\x00' + b'\x00' * 16
            optional_header = b'\x0b\x01\x0e\x00' + b'\x00' * 220

            upx_section = b'UPX0\x00\x00\x00\x00'
            upx_section += b'\x00\x10\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00'
            upx_section += b'\x00' * 16
            upx_section += b'\x80\x00\x00\x60'

            upx1_section = b'UPX1\x00\x00\x00\x00'
            upx1_section += b'\x00\x20\x00\x00\x00\x20\x00\x00\x00\x10\x00\x00\x00\x14\x00\x00'
            upx1_section += b'\x00' * 16
            upx1_section += b'\x80\x00\x00\x60'

            temp_file.write(dos_header + pe_signature + coff_header + optional_header + upx_section + upx1_section)
            temp_file.flush()
            yield temp_file.name

        try:
            os.unlink(temp_file.name)
        except:
            pass

    @pytest.fixture
    def vmprotect_pe_file(self):
        """Create REAL VMProtect-like PE file for testing."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            dos_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            dos_header += b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
            dos_header += b'\x00' * 40
            dos_header += b'\x80\x00\x00\x00'
            dos_header += b'\x00' * 60

            pe_signature = b'PE\x00\x00'
            coff_header = b'\x4c\x01\x03\x00' + b'\x00' * 16
            optional_header = b'\x0b\x01\x0e\x00' + b'\x00' * 220

            vmp_section = b'.vmp0\x00\x00\x00'
            vmp_section += b'\x00\x10\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x04\x00\x00'
            vmp_section += b'\x00' * 16
            vmp_section += b'\x60\x00\x00\xe0'

            vmp_signature = b'\x68\x00\x00\x00\x00\xc3'
            vmp_signature += b'\x55\x8b\xec\x83\xec\x08\x53\x56\x57'
            vmp_signature += b'\x8b\x75\x08\x33\xdb\x83\xfe\xff'

            temp_file.write(dos_header + pe_signature + coff_header + optional_header + vmp_section + vmp_signature)
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
    def test_basic_protection_detection_performance(self, benchmark, sample_pe_file):
        """Benchmark REAL basic protection detection speed."""
        def detect_protections():
            detector = ProtectionDetector()
            return detector.analyze_file(sample_pe_file)

        result = benchmark(detect_protections)

        assert result is not None, "Protection detection must return results"
        assert 'protections' in result, "Result must contain protections data"
        assert isinstance(result['protections'], list), "Protections must be a list"
        assert benchmark.stats.mean < 0.5, "Basic protection detection should be under 500ms"

    @pytest.mark.benchmark
    def test_advanced_protection_analysis_performance(self, benchmark, vmprotect_pe_file):
        """Benchmark REAL advanced protection analysis."""
        def analyze_advanced_protections():
            analyzer = IntellicrackProtectionAdvanced()
            return analyzer.deep_analyze(vmprotect_pe_file)

        result = benchmark(analyze_advanced_protections)

        assert result is not None, "Advanced analysis must return results"
        assert 'analysis' in result, "Result must contain analysis data"
        assert 'confidence' in result, "Result must contain confidence score"
        assert benchmark.stats.mean < 2.0, "Advanced analysis should be under 2 seconds"

    @pytest.mark.benchmark
    def test_packer_detection_performance(self, benchmark, packed_pe_file):
        """Benchmark REAL packer detection speed."""
        def detect_packer():
            detector = ProtectionDetector()
            return detector.detect_packer(packed_pe_file)

        result = benchmark(detect_packer)

        assert result is not None, "Packer detection must return results"
        assert 'packer' in result or 'packed' in result, "Result must indicate packer information"
        assert benchmark.stats.mean < 0.3, "Packer detection should be under 300ms"

    @pytest.mark.benchmark
    def test_entropy_analysis_performance(self, benchmark, sample_pe_file):
        """Benchmark REAL entropy analysis speed."""
        def analyze_entropy():
            analyzer = EntropyAnalyzer()
            with open(sample_pe_file, 'rb') as f:
                data = f.read()
            return analyzer.calculate_entropy(data)

        result = benchmark(analyze_entropy)

        assert result is not None, "Entropy analysis must return value"
        assert isinstance(result, (int, float)), "Entropy must be numeric"
        assert 0 <= result <= 8, "Entropy must be between 0 and 8"
        assert benchmark.stats.mean < 0.1, "Entropy analysis should be under 100ms"

    @pytest.mark.benchmark
    def test_yara_pattern_matching_performance(self, benchmark, sample_pe_file):
        """Benchmark REAL YARA pattern matching speed."""
        def run_yara_scan():
            engine = YaraPatternEngine()
            return engine.scan_file(sample_pe_file)

        result = benchmark(run_yara_scan)

        assert result is not None, "YARA scan must return results"
        assert 'matches' in result, "Result must contain matches"
        assert isinstance(result['matches'], list), "Matches must be a list"
        assert benchmark.stats.mean < 1.0, "YARA scanning should be under 1 second"

    @pytest.mark.benchmark
    def test_cache_performance(self, benchmark, sample_pe_file):
        """Benchmark REAL analysis cache operations."""
        def cache_operations():
            cache = AnalysisCache()

            key = f"test_{int(time.time())}"
            data = {'analysis': 'test_data', 'timestamp': time.time()}

            cache.store(key, data)
            retrieved = cache.get(key)
            cache.invalidate(key)

            return retrieved

        result = benchmark(cache_operations)

        assert result is not None, "Cache operations must return data"
        assert 'analysis' in result, "Cached data must contain analysis"
        assert benchmark.stats.mean < 0.01, "Cache operations should be under 10ms"

    def test_concurrent_protection_detection(self, sample_pe_file, packed_pe_file, vmprotect_pe_file):
        """Test REAL concurrent protection detection performance."""
        results = []
        errors = []

        def detect_protection(file_path, thread_id):
            try:
                detector = ProtectionDetector()
                result = detector.analyze_file(file_path)
                results.append((thread_id, result))
            except Exception as e:
                errors.append((thread_id, str(e)))

        files = [sample_pe_file, packed_pe_file, vmprotect_pe_file] * 3
        threads = []
        start_time = time.time()

        for i, file_path in enumerate(files):
            thread = threading.Thread(target=detect_protection, args=(file_path, i))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join(timeout=10.0)

        end_time = time.time()

        assert len(errors) == 0, f"Concurrent detection errors: {errors}"
        assert len(results) == len(files), f"Expected {len(files)} results, got {len(results)}"
        assert end_time - start_time < 5.0, "Concurrent detection should complete under 5 seconds"

        for thread_id, result in results:
            assert result is not None, f"Thread {thread_id} returned None"
            assert 'protections' in result, f"Thread {thread_id} missing protections data"

    def test_protection_detection_memory_usage(self, sample_pe_file, process_memory):
        """Test REAL protection detection memory efficiency."""
        initial_memory = process_memory.rss

        detector = ProtectionDetector()

        for i in range(50):
            result = detector.analyze_file(sample_pe_file)
            assert result is not None, f"Analysis {i} failed"
            assert 'protections' in result, f"Analysis {i} missing protections"

        current_process = psutil.Process()
        final_memory = current_process.memory_info().rss
        memory_increase = final_memory - initial_memory

        assert memory_increase < 100 * 1024 * 1024, "Memory increase should be under 100MB for 50 analyses"

    @pytest.mark.benchmark
    def test_signature_database_performance(self, benchmark):
        """Benchmark REAL protection signature database operations."""
        def load_signatures():
            detector = ProtectionDetector()
            return detector.load_signature_database()

        result = benchmark(load_signatures)

        assert result is not None, "Signature loading must return result"
        assert result.get('signatures_loaded', 0) > 0, "Must load actual signatures"
        assert benchmark.stats.mean < 1.0, "Signature loading should be under 1 second"

    def test_protection_detection_accuracy_vs_speed(self, sample_pe_file, packed_pe_file, vmprotect_pe_file):
        """Test REAL protection detection accuracy vs speed tradeoff."""
        detector = ProtectionDetector()

        test_files = [
            (sample_pe_file, "clean"),
            (packed_pe_file, "packed"),
            (vmprotect_pe_file, "vmprotect")
        ]

        for file_path, expected_type in test_files:
            start_time = time.time()

            quick_result = detector.quick_scan(file_path)
            quick_time = time.time() - start_time

            start_time = time.time()
            detailed_result = detector.detailed_scan(file_path)
            detailed_time = time.time() - start_time

            assert quick_result is not None, f"Quick scan failed for {expected_type}"
            assert detailed_result is not None, f"Detailed scan failed for {expected_type}"

            assert quick_time < 0.5, f"Quick scan too slow for {expected_type}: {quick_time}s"
            assert detailed_time < 3.0, f"Detailed scan too slow for {expected_type}: {detailed_time}s"

            assert detailed_time > quick_time, f"Detailed scan not slower than quick for {expected_type}"

    @pytest.mark.benchmark
    def test_intellicrack_protection_core_performance(self, benchmark, sample_pe_file):
        """Benchmark REAL Intellicrack protection core operations."""
        def run_protection_core():
            core = IntellicrackProtectionCore()
            return core.analyze_protection_mechanisms(sample_pe_file)

        result = benchmark(run_protection_core)

        assert result is not None, "Protection core must return results"
        assert 'mechanisms' in result, "Result must contain mechanisms"
        assert isinstance(result['mechanisms'], list), "Mechanisms must be a list"
        assert benchmark.stats.mean < 1.5, "Protection core should be under 1.5 seconds"

    def test_protection_analysis_consistency(self, sample_pe_file):
        """Test REAL protection analysis consistency across multiple runs."""
        detector = ProtectionDetector()

        results = []
        for _ in range(10):
            result = detector.analyze_file(sample_pe_file)
            results.append(result)

        for result in results:
            assert result is not None, "Analysis must not return None"
            assert 'protections' in result, "Analysis must contain protections"

        first_result = results[0]
        for i, result in enumerate(results[1:], 1):
            assert len(result['protections']) == len(first_result['protections']), \
                f"Inconsistent protection count in run {i}"

    def test_protection_detection_error_handling(self):
        """Test REAL protection detection error handling performance."""
        detector = ProtectionDetector()

        start_time = time.time()

        invalid_files = [
            "/nonexistent/file.exe",
            "",
            None,
            "not_a_file.txt"
        ]

        for invalid_file in invalid_files:
            try:
                result = detector.analyze_file(invalid_file)
                if result is not None:
                    pass
            except Exception:
                pass

        end_time = time.time()

        assert end_time - start_time < 0.5, "Error handling should be fast (under 500ms)"

    def test_protection_detection_stress_test(self, sample_pe_file, packed_pe_file):
        """Stress test REAL protection detection under heavy load."""
        detector = ProtectionDetector()

        start_time = time.time()

        files = [sample_pe_file, packed_pe_file] * 25

        for i, file_path in enumerate(files):
            result = detector.analyze_file(file_path)
            assert result is not None, f"Stress test analysis {i} failed"
            assert 'protections' in result, f"Stress test {i} missing protections"

        end_time = time.time()

        assert end_time - start_time < 30.0, "Stress test should complete under 30 seconds"

    @pytest.mark.benchmark
    def test_protection_bypass_recommendation_performance(self, benchmark, vmprotect_pe_file):
        """Benchmark REAL protection bypass recommendation generation."""
        def generate_bypass_recommendations():
            analyzer = IntellicrackProtectionAdvanced()
            protection_info = analyzer.analyze_protection(vmprotect_pe_file)
            return analyzer.recommend_bypass_strategies(protection_info)

        result = benchmark(generate_bypass_recommendations)

        assert result is not None, "Bypass recommendations must be generated"
        assert 'strategies' in result, "Result must contain strategies"
        assert len(result['strategies']) > 0, "Must recommend at least one strategy"
        assert benchmark.stats.mean < 1.0, "Bypass recommendation should be under 1 second"

    def test_protection_analysis_cache_efficiency(self, sample_pe_file):
        """Test REAL protection analysis cache efficiency."""
        cache = AnalysisCache()
        detector = ProtectionDetector()

        first_analysis_start = time.time()
        first_result = detector.analyze_file_with_cache(sample_pe_file, cache)
        first_analysis_time = time.time() - first_analysis_start

        second_analysis_start = time.time()
        second_result = detector.analyze_file_with_cache(sample_pe_file, cache)
        second_analysis_time = time.time() - second_analysis_start

        assert first_result is not None, "First analysis must return result"
        assert second_result is not None, "Second analysis must return result"
        assert second_analysis_time < first_analysis_time * 0.1, "Cached analysis should be 10x faster"
        assert first_result == second_result, "Cached result must match original"
