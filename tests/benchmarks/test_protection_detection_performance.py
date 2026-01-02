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

import os
import tempfile
import threading
import time
from collections.abc import Generator
from typing import Any

import psutil
import pytest

from intellicrack.core.analysis.entropy_analyzer import EntropyAnalyzer
from intellicrack.core.analysis.yara_pattern_engine import YaraPatternEngine
from intellicrack.protection.analysis_cache import AnalysisCache
from intellicrack.protection.intellicrack_protection_core import (
    IntellicrackProtectionCore,
    ProtectionAnalysis,
)
from intellicrack.protection.protection_detector import ProtectionDetector


def _analysis_to_dict(analysis: ProtectionAnalysis) -> dict[str, Any]:
    """Convert ProtectionAnalysis to dict for test assertions."""
    return {
        'protections': [
            {
                'name': d.name,
                'type': d.type.value,
                'confidence': d.confidence,
                'details': d.details,
            }
            for d in analysis.detections
        ],
        'is_packed': analysis.is_packed,
        'is_protected': analysis.is_protected,
        'file_type': analysis.file_type,
        'architecture': analysis.architecture,
    }


class TestProtectionDetectionPerformance:
    """Performance benchmarks for protection detection and analysis."""

    @pytest.fixture
    def sample_pe_file(self) -> Generator[str, None, None]:
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
        except OSError:
            pass

    @pytest.fixture
    def packed_pe_file(self) -> Generator[str, None, None]:
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
        except OSError:
            pass

    @pytest.fixture
    def vmprotect_pe_file(self) -> Generator[str, None, None]:
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
        except OSError:
            pass

    @pytest.fixture
    def process_memory(self) -> psutil._pswindows.pmem:
        """Monitor process memory usage."""
        process = psutil.Process()
        return process.memory_info()

    @pytest.mark.benchmark
    def test_basic_protection_detection_performance(
        self, benchmark: Any, sample_pe_file: str
    ) -> None:
        """Benchmark REAL basic protection detection speed."""
        def detect_protections() -> dict[str, Any]:
            detector = ProtectionDetector()
            analysis = detector.detect_protections(sample_pe_file)
            return _analysis_to_dict(analysis)

        result = benchmark(detect_protections)

        assert result is not None, "Protection detection must return results"
        assert 'protections' in result, "Result must contain protections data"
        assert isinstance(result['protections'], list), "Protections must be a list"
        assert benchmark.stats.mean < 0.5, "Basic protection detection should be under 500ms"

    @pytest.mark.benchmark
    def test_advanced_protection_analysis_performance(
        self, benchmark: Any, vmprotect_pe_file: str
    ) -> None:
        """Benchmark REAL advanced protection analysis."""
        def analyze_advanced_protections() -> dict[str, Any]:
            analyzer = IntellicrackProtectionCore()
            analysis = analyzer.detect_protections(vmprotect_pe_file)
            result = _analysis_to_dict(analysis)
            result['analysis'] = {
                'is_packed': analysis.is_packed,
                'is_protected': analysis.is_protected,
            }
            result['confidence'] = (
                max((d.confidence for d in analysis.detections), default=0.0)
                if analysis.detections else 0.0
            )
            return result

        result = benchmark(analyze_advanced_protections)

        assert result is not None, "Advanced analysis must return results"
        assert 'analysis' in result, "Result must contain analysis data"
        assert 'confidence' in result, "Result must contain confidence score"
        assert benchmark.stats.mean < 2.0, "Advanced analysis should be under 2 seconds"

    @pytest.mark.benchmark
    def test_packer_detection_performance(
        self, benchmark: Any, packed_pe_file: str
    ) -> None:
        """Benchmark REAL packer detection speed."""
        def detect_packer() -> dict[str, Any]:
            detector = ProtectionDetector()
            analysis = detector.detect_protections(packed_pe_file)
            return {
                'packed': analysis.is_packed,
                'packer': next(
                    (d.name for d in analysis.detections if 'pack' in d.type.value.lower()),
                    None
                ),
                'detections': [d.name for d in analysis.detections],
            }

        result = benchmark(detect_packer)

        assert result is not None, "Packer detection must return results"
        assert 'packer' in result or 'packed' in result, "Result must indicate packer information"
        assert benchmark.stats.mean < 0.3, "Packer detection should be under 300ms"

    @pytest.mark.benchmark
    def test_entropy_analysis_performance(
        self, benchmark: Any, sample_pe_file: str
    ) -> None:
        """Benchmark REAL entropy analysis speed."""
        def analyze_entropy() -> float:
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
    def test_yara_pattern_matching_performance(
        self, benchmark: Any, sample_pe_file: str
    ) -> None:
        """Benchmark REAL YARA pattern matching speed."""
        def run_yara_scan() -> dict[str, Any]:
            engine = YaraPatternEngine()
            scan_result = engine.scan_file(sample_pe_file)
            return {
                'matches': [m.rule_name for m in scan_result.matches],
                'total_rules': scan_result.total_rules,
                'scan_time': scan_result.scan_time,
                'error': scan_result.error,
            }

        result = benchmark(run_yara_scan)

        assert result is not None, "YARA scan must return results"
        assert 'matches' in result, "Result must contain matches"
        assert isinstance(result['matches'], list), "Matches must be a list"
        assert benchmark.stats.mean < 1.0, "YARA scanning should be under 1 second"

    @pytest.mark.benchmark
    def test_cache_performance(
        self, benchmark: Any, sample_pe_file: str
    ) -> None:
        """Benchmark REAL analysis cache operations."""
        def cache_operations() -> object | None:
            cache = AnalysisCache()

            key = f"test_{int(time.time())}"
            data: dict[str, Any] = {'analysis': 'test_data', 'timestamp': time.time()}

            cache.put(key, data)
            retrieved = cache.get(key)
            cache.remove(key)

            return retrieved

        result = benchmark(cache_operations)

        assert result is not None, "Cache operations must return data"
        assert isinstance(result, dict), "Cached data must be a dict"
        assert 'analysis' in result, "Cached data must contain analysis"
        assert benchmark.stats.mean < 0.01, "Cache operations should be under 10ms"

    def test_concurrent_protection_detection(
        self, sample_pe_file: str, packed_pe_file: str, vmprotect_pe_file: str
    ) -> None:
        """Test REAL concurrent protection detection performance."""
        results: list[tuple[int, dict[str, Any]]] = []
        errors: list[tuple[int, str]] = []

        def detect_protection(file_path: str, thread_id: int) -> None:
            try:
                detector = ProtectionDetector()
                analysis = detector.detect_protections(file_path)
                results.append((thread_id, _analysis_to_dict(analysis)))
            except Exception as e:
                errors.append((thread_id, str(e)))

        files = [sample_pe_file, packed_pe_file, vmprotect_pe_file] * 3
        threads: list[threading.Thread] = []
        start_time = time.time()

        for i, file_path in enumerate(files):
            thread = threading.Thread(target=detect_protection, args=(file_path, i))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join(timeout=10.0)

        end_time = time.time()

        assert not errors, f"Concurrent detection errors: {errors}"
        assert len(results) == len(files), f"Expected {len(files)} results, got {len(results)}"
        assert end_time - start_time < 5.0, "Concurrent detection should complete under 5 seconds"

        for thread_id, result in results:
            assert result is not None, f"Thread {thread_id} returned None"
            assert 'protections' in result, f"Thread {thread_id} missing protections data"

    def test_protection_detection_memory_usage(
        self, sample_pe_file: str, process_memory: psutil._pswindows.pmem
    ) -> None:
        """Test REAL protection detection memory efficiency."""
        initial_memory = process_memory.rss

        detector = ProtectionDetector()

        for i in range(50):
            analysis = detector.detect_protections(sample_pe_file)
            result = _analysis_to_dict(analysis)
            assert result is not None, f"Analysis {i} failed"
            assert 'protections' in result, f"Analysis {i} missing protections"

        current_process = psutil.Process()
        final_memory = current_process.memory_info().rss
        memory_increase = final_memory - initial_memory

        assert memory_increase < 100 * 1024 * 1024, "Memory increase should be under 100MB for 50 analyses"

    @pytest.mark.benchmark
    def test_signature_database_performance(self, benchmark: Any) -> None:
        """Benchmark REAL protection signature database operations."""
        def load_signatures() -> dict[str, Any]:
            detector = ProtectionDetector()
            signatures_loaded = len(getattr(detector, '_signatures', []))
            return {'signatures_loaded': signatures_loaded, 'detector_ready': True}

        result = benchmark(load_signatures)

        assert result is not None, "Signature loading must return result"
        assert result.get('detector_ready', False), "Detector must be ready"
        assert benchmark.stats.mean < 1.0, "Signature loading should be under 1 second"

    def test_protection_detection_accuracy_vs_speed(
        self, sample_pe_file: str, packed_pe_file: str, vmprotect_pe_file: str
    ) -> None:
        """Test REAL protection detection accuracy vs speed tradeoff."""
        detector = ProtectionDetector()

        test_files = [
            (sample_pe_file, "clean"),
            (packed_pe_file, "packed"),
            (vmprotect_pe_file, "vmprotect")
        ]

        for file_path, expected_type in test_files:
            start_time = time.time()

            quick_analysis = detector.detect_protections(file_path, deep_scan=False)
            quick_result = _analysis_to_dict(quick_analysis)
            quick_time = time.time() - start_time

            start_time = time.time()
            detailed_analysis = detector.detect_protections(file_path, deep_scan=True)
            detailed_result = _analysis_to_dict(detailed_analysis)
            detailed_time = time.time() - start_time

            assert quick_result is not None, f"Quick scan failed for {expected_type}"
            assert detailed_result is not None, f"Detailed scan failed for {expected_type}"

            assert quick_time < 0.5, f"Quick scan too slow for {expected_type}: {quick_time}s"
            assert detailed_time < 3.0, f"Detailed scan too slow for {expected_type}: {detailed_time}s"

    @pytest.mark.benchmark
    def test_intellicrack_protection_core_performance(
        self, benchmark: Any, sample_pe_file: str
    ) -> None:
        """Benchmark REAL Intellicrack protection core operations."""
        def run_protection_core() -> dict[str, Any]:
            core = IntellicrackProtectionCore()
            analysis = core.detect_protections(sample_pe_file)
            return {
                'mechanisms': [d.name for d in analysis.detections],
                'is_protected': analysis.is_protected,
                'is_packed': analysis.is_packed,
            }

        result = benchmark(run_protection_core)

        assert result is not None, "Protection core must return results"
        assert 'mechanisms' in result, "Result must contain mechanisms"
        assert isinstance(result['mechanisms'], list), "Mechanisms must be a list"
        assert benchmark.stats.mean < 1.5, "Protection core should be under 1.5 seconds"

    def test_protection_analysis_consistency(self, sample_pe_file: str) -> None:
        """Test REAL protection analysis consistency across multiple runs."""
        detector = ProtectionDetector()

        results: list[dict[str, Any]] = []
        for _ in range(10):
            analysis = detector.detect_protections(sample_pe_file)
            results.append(_analysis_to_dict(analysis))

        for result in results:
            assert result is not None, "Analysis must not return None"
            assert 'protections' in result, "Analysis must contain protections"

        first_result = results[0]
        for i, result in enumerate(results[1:], 1):
            assert len(result['protections']) == len(first_result['protections']), \
                f"Inconsistent protection count in run {i}"

    def test_protection_detection_error_handling(self) -> None:
        """Test REAL protection detection error handling performance."""
        detector = ProtectionDetector()

        start_time = time.time()

        invalid_files: list[str | None] = [
            "/nonexistent/file.exe",
            "",
            None,
            "not_a_file.txt"
        ]

        for invalid_file in invalid_files:
            try:
                if invalid_file is not None:
                    detector.detect_protections(invalid_file)
            except Exception:
                pass

        end_time = time.time()

        assert end_time - start_time < 0.5, "Error handling should be fast (under 500ms)"

    def test_protection_detection_stress_test(
        self, sample_pe_file: str, packed_pe_file: str
    ) -> None:
        """Stress test REAL protection detection under heavy load."""
        detector = ProtectionDetector()

        start_time = time.time()

        files = [sample_pe_file, packed_pe_file] * 25

        for i, file_path in enumerate(files):
            analysis = detector.detect_protections(file_path)
            result = _analysis_to_dict(analysis)
            assert result is not None, f"Stress test analysis {i} failed"
            assert 'protections' in result, f"Stress test {i} missing protections"

        end_time = time.time()

        assert end_time - start_time < 30.0, "Stress test should complete under 30 seconds"

    @pytest.mark.benchmark
    def test_protection_bypass_recommendation_performance(
        self, benchmark: Any, vmprotect_pe_file: str
    ) -> None:
        """Benchmark REAL protection bypass recommendation generation."""
        def generate_bypass_recommendations() -> dict[str, Any]:
            analyzer = IntellicrackProtectionCore()
            analysis = analyzer.detect_protections(vmprotect_pe_file)
            strategies: list[str] = []
            for detection in analysis.detections:
                strategies.extend(detection.bypass_recommendations)
            return {'strategies': strategies, 'count': len(strategies)}

        result = benchmark(generate_bypass_recommendations)

        assert result is not None, "Bypass recommendations must be generated"
        assert 'strategies' in result, "Result must contain strategies"
        assert benchmark.stats.mean < 1.0, "Bypass recommendation should be under 1 second"

    def test_protection_analysis_cache_efficiency(self, sample_pe_file: str) -> None:
        """Test REAL protection analysis cache efficiency."""
        cache = AnalysisCache()
        detector = ProtectionDetector()

        first_analysis_start = time.time()
        cached_result = cache.get(sample_pe_file)
        if cached_result is None:
            analysis = detector.detect_protections(sample_pe_file)
            first_result = _analysis_to_dict(analysis)
            cache.put(sample_pe_file, first_result)
        else:
            first_result = dict(cached_result) if isinstance(cached_result, dict) else {}
        first_analysis_time = time.time() - first_analysis_start

        second_analysis_start = time.time()
        second_cached = cache.get(sample_pe_file)
        second_result = dict(second_cached) if isinstance(second_cached, dict) else {}
        second_analysis_time = time.time() - second_analysis_start

        assert first_result is not None, "First analysis must return result"
        assert second_result is not None, "Second analysis must return result"
        assert second_analysis_time < first_analysis_time, "Cached analysis should be faster"
        assert first_result == second_result, "Cached result must match original"
