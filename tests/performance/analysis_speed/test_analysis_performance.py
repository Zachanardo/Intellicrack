"""
Performance tests for binary analysis operations.
Tests REAL analysis speed on various binary types and sizes.
NO MOCKS - ALL TESTS MEASURE REAL PERFORMANCE METRICS.
"""

import pytest
import time
import statistics
import psutil
from pathlib import Path

from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer
from intellicrack.core.analysis.pe_analyzer import PEAnalyzer
from intellicrack.core.analysis.elf_analyzer import ELFAnalyzer
from intellicrack.core.analysis.protection_detector import ProtectionDetector
from tests.base_test import IntellicrackTestBase


class TestAnalysisPerformance(IntellicrackTestBase):
    """Test binary analysis performance with REAL measurements."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test with real analyzers."""
        self.binary_analyzer = BinaryAnalyzer()
        self.pe_analyzer = PEAnalyzer()
        self.elf_analyzer = ELFAnalyzer()
        self.protection_detector = ProtectionDetector()
        self.process = psutil.Process()
        
        # Get test binaries
        self.test_binaries_dir = Path("tests/fixtures/binaries")
        if not self.test_binaries_dir.exists():
            self.test_binaries_dir = Path("C:/Intellicrack/tests/fixtures/binaries")
            
    def test_pe_analysis_speed(self):
        """Test PE file analysis performance."""
        pe_files = list(self.test_binaries_dir.glob("*.exe")) + \
                   list(self.test_binaries_dir.glob("*.dll"))
                   
        if not pe_files:
            pytest.skip("No PE files available for testing")
            
        analysis_times = []
        file_sizes = []
        
        for pe_file in pe_files[:10]:  # Test up to 10 files
            file_size = pe_file.stat().st_size
            file_sizes.append(file_size)
            
            # Measure analysis time
            start = time.perf_counter()
            analysis = self.pe_analyzer.analyze(pe_file)
            end = time.perf_counter()
            
            analysis_time = end - start
            analysis_times.append(analysis_time)
            
            # Validate analysis
            self.assert_real_output(analysis)
            assert 'headers' in analysis
            assert 'sections' in analysis
            assert 'imports' in analysis
            
        # Calculate performance metrics
        avg_time = statistics.mean(analysis_times)
        max_time = max(analysis_times)
        
        # Calculate throughput (MB/s)
        total_size_mb = sum(file_sizes) / (1024 * 1024)
        total_time = sum(analysis_times)
        throughput = total_size_mb / total_time if total_time > 0 else 0
        
        # Assertions
        assert avg_time < 5.0  # Average under 5 seconds
        assert max_time < 10.0  # Max under 10 seconds
        assert throughput > 1.0  # At least 1 MB/s
        
        print(f"\nPE Analysis Performance:")
        print(f"  Files analyzed: {len(pe_files)}")
        print(f"  Average time: {avg_time:.2f}s")
        print(f"  Max time: {max_time:.2f}s")
        print(f"  Throughput: {throughput:.2f} MB/s")
        
    def test_elf_analysis_speed(self):
        """Test ELF file analysis performance."""
        elf_files = list(self.test_binaries_dir.glob("*.elf")) + \
                    list(self.test_binaries_dir.glob("*.so"))
                    
        if not elf_files:
            pytest.skip("No ELF files available for testing")
            
        analysis_times = []
        
        for elf_file in elf_files[:10]:
            start = time.perf_counter()
            analysis = self.elf_analyzer.analyze(elf_file)
            end = time.perf_counter()
            
            analysis_times.append(end - start)
            
            # Validate analysis
            self.assert_real_output(analysis)
            
        if analysis_times:
            avg_time = statistics.mean(analysis_times)
            assert avg_time < 3.0  # ELF analysis should be fast
            
    def test_protection_detection_speed(self):
        """Test protection detection performance."""
        protected_files = list((self.test_binaries_dir / "protected").glob("*"))
        
        if not protected_files:
            protected_files = list(self.test_binaries_dir.glob("*.exe"))[:5]
            
        if not protected_files:
            pytest.skip("No files for protection detection")
            
        detection_times = []
        
        for file in protected_files:
            start = time.perf_counter()
            protections = self.protection_detector.detect_protections(file)
            end = time.perf_counter()
            
            detection_times.append(end - start)
            
            # Validate detection
            self.assert_real_output(protections)
            assert isinstance(protections, list)
            
        avg_detection_time = statistics.mean(detection_times)
        assert avg_detection_time < 2.0  # Under 2 seconds average
        
        print(f"\nProtection Detection Performance:")
        print(f"  Files checked: {len(protected_files)}")
        print(f"  Average time: {avg_detection_time:.2f}s")
        
    def test_large_file_analysis(self):
        """Test analysis performance on large binaries."""
        # Find largest binary
        large_files = []
        for binary in self.test_binaries_dir.rglob("*"):
            if binary.is_file() and binary.stat().st_size > 1024 * 1024:  # > 1MB
                large_files.append(binary)
                
        if not large_files:
            pytest.skip("No large binaries available")
            
        # Sort by size and take largest
        large_files.sort(key=lambda f: f.stat().st_size, reverse=True)
        largest = large_files[0]
        size_mb = largest.stat().st_size / (1024 * 1024)
        
        # Measure analysis time
        start = time.perf_counter()
        analysis = self.binary_analyzer.analyze(largest)
        end = time.perf_counter()
        
        analysis_time = end - start
        
        # Performance metrics
        assert analysis_time < 30.0  # Under 30 seconds even for large files
        
        print(f"\nLarge File Analysis:")
        print(f"  File: {largest.name}")
        print(f"  Size: {size_mb:.2f} MB")
        print(f"  Time: {analysis_time:.2f}s")
        print(f"  Speed: {size_mb/analysis_time:.2f} MB/s")
        
    def test_batch_analysis_throughput(self):
        """Test batch analysis throughput."""
        all_binaries = list(self.test_binaries_dir.rglob("*.exe"))[:20]
        
        if len(all_binaries) < 5:
            pytest.skip("Not enough binaries for batch test")
            
        # Batch analysis
        start = time.perf_counter()
        
        results = []
        for binary in all_binaries:
            result = self.binary_analyzer.quick_analyze(binary)
            results.append(result)
            
        end = time.perf_counter()
        
        total_time = end - start
        files_per_second = len(all_binaries) / total_time
        
        # Validate results
        for result in results:
            self.assert_real_output(result)
            
        # Performance assertions
        assert files_per_second > 1.0  # At least 1 file per second
        
        print(f"\nBatch Analysis Performance:")
        print(f"  Files: {len(all_binaries)}")
        print(f"  Total time: {total_time:.2f}s")
        print(f"  Throughput: {files_per_second:.2f} files/second")
        
    def test_incremental_analysis(self):
        """Test incremental analysis performance."""
        test_file = None
        for f in self.test_binaries_dir.glob("*.exe"):
            test_file = f
            break
            
        if not test_file:
            pytest.skip("No test file available")
            
        # Full analysis
        start = time.perf_counter()
        full_analysis = self.binary_analyzer.analyze(test_file)
        full_time = time.perf_counter() - start
        
        # Incremental analysis (should be faster)
        start = time.perf_counter()
        incremental = self.binary_analyzer.analyze(
            test_file,
            incremental=True,
            previous_analysis=full_analysis
        )
        incremental_time = time.perf_counter() - start
        
        # Incremental should be significantly faster
        assert incremental_time < full_time * 0.5
        
        print(f"\nIncremental Analysis Performance:")
        print(f"  Full analysis: {full_time:.2f}s")
        print(f"  Incremental: {incremental_time:.2f}s")
        print(f"  Speedup: {full_time/incremental_time:.1f}x")
        
    def test_memory_efficiency_during_analysis(self):
        """Test memory usage during analysis."""
        import gc
        
        # Get binaries
        binaries = list(self.test_binaries_dir.glob("*.exe"))[:10]
        
        if not binaries:
            pytest.skip("No binaries available")
            
        # Baseline memory
        gc.collect()
        baseline_memory = self.process.memory_info().rss / (1024 * 1024)
        
        peak_memory = baseline_memory
        
        # Analyze multiple files
        for binary in binaries:
            self.binary_analyzer.analyze(binary)
            
            current_memory = self.process.memory_info().rss / (1024 * 1024)
            peak_memory = max(peak_memory, current_memory)
            
        # Force cleanup
        gc.collect()
        final_memory = self.process.memory_info().rss / (1024 * 1024)
        
        # Memory assertions
        memory_per_file = (peak_memory - baseline_memory) / len(binaries)
        assert memory_per_file < 100  # Less than 100MB per file
        
        print(f"\nMemory Usage During Analysis:")
        print(f"  Files analyzed: {len(binaries)}")
        print(f"  Peak memory increase: {peak_memory - baseline_memory:.2f}MB")
        print(f"  Memory per file: {memory_per_file:.2f}MB")