"""Production tests for MemoryOptimizedBinaryLoader.

Validates memory-mapped file handling, section reading, caching,
chunk iteration, and entropy calculation on real binaries.
"""

import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.processing.memory_loader import (
    MemoryOptimizedBinaryLoader,
    create_memory_loader,
    run_memory_optimized_analysis,
)


class TestMemoryOptimizedBinaryLoader:
    """Test memory-efficient binary loading and analysis."""

    @pytest.fixture
    def sample_pe_binary(self, tmp_path: Path) -> Path:
        """Create sample PE binary file for testing."""
        binary_path = tmp_path / "sample.exe"

        pe_header = (
            b"MZ"
            + b"\x90\x00" * 30
            + b"PE\x00\x00"
            + b"\x4c\x01"
            + b"\x03\x00"
            + b"\x00" * 16
            + b"\xe0\x00"
            + b"\x0f\x01"
            + b"\x0b\x01"
            + b"\x00" * 200
        )

        text_section = b"\x55\x89\xe5\x83\xec\x10" + (b"\x90" * 500) + b"\xc9\xc3"

        data_section = b"License validation failed" + (b"\x00" * 475)

        binary_content = pe_header + text_section + data_section

        binary_path.write_bytes(binary_content)
        return binary_path

    @pytest.fixture
    def large_binary(self, tmp_path: Path) -> Path:
        """Create large binary file for performance testing."""
        binary_path = tmp_path / "large.bin"

        chunk = b"\x4d\x5a\x90\x00" + (b"\x00" * 1020)
        content = chunk * 1000

        binary_path.write_bytes(content)
        return binary_path

    @pytest.fixture
    def high_entropy_binary(self, tmp_path: Path) -> Path:
        """Create high entropy binary simulating packed/encrypted content."""
        binary_path = tmp_path / "packed.exe"

        import random

        random.seed(42)
        content = bytes(random.randint(0, 255) for _ in range(10000))

        binary_path.write_bytes(content)
        return binary_path

    @pytest.fixture
    def loader(self) -> MemoryOptimizedBinaryLoader:
        """Create fresh loader instance."""
        return MemoryOptimizedBinaryLoader()

    def test_loader_initialization(self, loader: MemoryOptimizedBinaryLoader) -> None:
        """Loader initializes with correct default configuration."""
        assert loader.chunk_size == 1024 * 1024
        assert loader.max_memory == 1024 * 1024 * 1024
        assert loader.current_file is None
        assert loader.mapped_file is None
        assert loader.file_size == 0
        assert len(loader.section_cache) == 0

    def test_load_file_success(self, loader: MemoryOptimizedBinaryLoader, sample_pe_binary: Path) -> None:
        """Loading existing file succeeds and creates memory mapping."""
        result = loader.load_file(str(sample_pe_binary))

        assert result is True
        assert loader.current_file is not None
        assert loader.mapped_file is not None
        assert loader.file_size == sample_pe_binary.stat().st_size

        loader.close()

    def test_load_nonexistent_file_fails(self, loader: MemoryOptimizedBinaryLoader) -> None:
        """Loading nonexistent file returns False."""
        result = loader.load_file("/nonexistent/path/file.exe")

        assert result is False
        assert loader.current_file is None
        assert loader.mapped_file is None

    def test_close_cleanup(self, loader: MemoryOptimizedBinaryLoader, sample_pe_binary: Path) -> None:
        """Close properly releases all resources."""
        loader.load_file(str(sample_pe_binary))
        loader.section_cache["test"] = b"\x00\x01\x02"

        loader.close()

        assert loader.current_file is None
        assert loader.mapped_file is None
        assert loader.file_size == 0
        assert len(loader.section_cache) == 0

    def test_read_chunk_valid_offset(self, loader: MemoryOptimizedBinaryLoader, sample_pe_binary: Path) -> None:
        """Reading chunk at valid offset returns correct data."""
        loader.load_file(str(sample_pe_binary))

        chunk = loader.read_chunk(0, 2)

        assert chunk == b"MZ"

        loader.close()

    def test_read_chunk_pe_header(self, loader: MemoryOptimizedBinaryLoader, sample_pe_binary: Path) -> None:
        """Reading PE header chunk returns valid PE signature."""
        loader.load_file(str(sample_pe_binary))

        chunk = loader.read_chunk(0, 64)

        assert chunk is not None
        assert chunk[:2] == b"MZ"
        assert b"PE\x00\x00" in chunk

        loader.close()

    def test_read_chunk_invalid_offset(self, loader: MemoryOptimizedBinaryLoader, sample_pe_binary: Path) -> None:
        """Reading chunk at invalid offset returns None."""
        loader.load_file(str(sample_pe_binary))

        chunk = loader.read_chunk(loader.file_size + 100, 100)

        assert chunk is None

        loader.close()

    def test_read_chunk_adjusts_size_at_eof(self, loader: MemoryOptimizedBinaryLoader, sample_pe_binary: Path) -> None:
        """Reading chunk near EOF adjusts size automatically."""
        loader.load_file(str(sample_pe_binary))

        chunk = loader.read_chunk(loader.file_size - 10, 100)

        assert chunk is not None
        assert len(chunk) == 10

        loader.close()

    def test_read_section_caching(self, loader: MemoryOptimizedBinaryLoader, sample_pe_binary: Path) -> None:
        """Section reading caches data for repeated access."""
        loader.load_file(str(sample_pe_binary))

        section1 = loader.read_section(".text", 100, 256)
        assert section1 is not None
        assert ".text" in loader.section_cache

        section2 = loader.read_section(".text", 100, 256)
        assert section2 == section1

        loader.close()

    def test_read_section_no_cache_large(self, loader: MemoryOptimizedBinaryLoader, sample_pe_binary: Path) -> None:
        """Large sections are not cached to preserve memory."""
        loader.load_file(str(sample_pe_binary))

        large_section = loader.read_section("large_section", 0, loader.chunk_size + 100)

        assert large_section is not None
        assert "large_section" not in loader.section_cache

        loader.close()

    def test_iterate_file_chunks(self, loader: MemoryOptimizedBinaryLoader, sample_pe_binary: Path) -> None:
        """File iteration yields correct chunks."""
        loader.load_file(str(sample_pe_binary))

        chunks = list(loader.iterate_file(chunk_size=128))

        assert len(chunks) > 0

        for offset, chunk in chunks:
            assert isinstance(offset, int)
            assert isinstance(chunk, bytes)
            assert len(chunk) > 0

        loader.close()

    def test_iterate_file_coverage(self, loader: MemoryOptimizedBinaryLoader, sample_pe_binary: Path) -> None:
        """File iteration covers entire file."""
        loader.load_file(str(sample_pe_binary))

        total_bytes = 0
        for _offset, chunk in loader.iterate_file(chunk_size=256):
            total_bytes += len(chunk)

        assert total_bytes == loader.file_size

        loader.close()

    def test_iterate_file_custom_chunk_size(self, loader: MemoryOptimizedBinaryLoader, sample_pe_binary: Path) -> None:
        """File iteration respects custom chunk size."""
        loader.load_file(str(sample_pe_binary))

        chunks = list(loader.iterate_file(chunk_size=64))

        for _offset, chunk in chunks[:-1]:
            assert len(chunk) == 64

        loader.close()

    def test_get_file_info(self, loader: MemoryOptimizedBinaryLoader, sample_pe_binary: Path) -> None:
        """File info returns accurate metadata."""
        loader.load_file(str(sample_pe_binary))

        info = loader.get_file_info()

        assert "file_size" in info
        assert info["file_size"] == loader.file_size
        assert "formatted_size" in info
        assert "chunk_size" in info
        assert info["chunk_size"] == loader.chunk_size
        assert "cached_sections" in info
        assert "memory_usage" in info

        loader.close()

    def test_calculate_entropy_pe_header(self, loader: MemoryOptimizedBinaryLoader, sample_pe_binary: Path) -> None:
        """Entropy calculation on PE header returns reasonable value."""
        loader.load_file(str(sample_pe_binary))

        pe_header = loader.read_chunk(0, 64)
        entropy = loader.calculate_entropy(pe_header)

        assert 0.0 <= entropy <= 8.0
        assert entropy > 0.0

        loader.close()

    def test_calculate_entropy_zero_bytes(self, loader: MemoryOptimizedBinaryLoader) -> None:
        """Entropy of zero bytes is minimal."""
        zero_data = b"\x00" * 1000
        entropy = loader.calculate_entropy(zero_data)

        assert entropy == 0.0

    def test_calculate_entropy_random_data(self, loader: MemoryOptimizedBinaryLoader, high_entropy_binary: Path) -> None:
        """Entropy of random data is high."""
        loader.load_file(str(high_entropy_binary))

        entropy = loader.calculate_entropy()

        assert entropy > 7.0

        loader.close()

    def test_calculate_entropy_entire_file(self, loader: MemoryOptimizedBinaryLoader, sample_pe_binary: Path) -> None:
        """Entropy calculation on entire file processes all chunks."""
        loader.load_file(str(sample_pe_binary))

        entropy = loader.calculate_entropy()

        assert 0.0 <= entropy <= 8.0
        assert entropy > 0.0

        loader.close()

    def test_context_manager_entry(self, sample_pe_binary: Path) -> None:
        """Context manager enters successfully."""
        with MemoryOptimizedBinaryLoader() as loader:
            assert isinstance(loader, MemoryOptimizedBinaryLoader)
            result = loader.load_file(str(sample_pe_binary))
            assert result is True

    def test_context_manager_exit_cleanup(self, sample_pe_binary: Path) -> None:
        """Context manager exit cleans up resources."""
        loader = MemoryOptimizedBinaryLoader()

        with loader:
            loader.load_file(str(sample_pe_binary))
            assert loader.mapped_file is not None

        assert loader.current_file is None
        assert loader.mapped_file is None

    def test_context_manager_exception_cleanup(self, sample_pe_binary: Path) -> None:
        """Context manager cleans up even with exceptions."""
        loader = MemoryOptimizedBinaryLoader()

        try:
            with loader:
                loader.load_file(str(sample_pe_binary))
                raise ValueError("Test exception")
        except ValueError:
            pass

        assert loader.current_file is None
        assert loader.mapped_file is None

    def test_large_file_performance(self, loader: MemoryOptimizedBinaryLoader, large_binary: Path) -> None:
        """Large file loading completes in reasonable time."""
        import time

        start = time.time()
        result = loader.load_file(str(large_binary))
        elapsed = time.time() - start

        assert result is True
        assert elapsed < 1.0

        loader.close()

    def test_chunk_iteration_performance(self, loader: MemoryOptimizedBinaryLoader, large_binary: Path) -> None:
        """Chunk iteration on large file performs efficiently."""
        import time

        loader.load_file(str(large_binary))

        start = time.time()
        chunk_count = 0
        for _offset, _chunk in loader.iterate_file():
            chunk_count += 1
        elapsed = time.time() - start

        assert chunk_count > 0
        assert elapsed < 2.0

        loader.close()

    def test_multiple_file_loads(self, loader: MemoryOptimizedBinaryLoader, sample_pe_binary: Path, tmp_path: Path) -> None:
        """Loading multiple files sequentially works correctly."""
        binary2 = tmp_path / "binary2.exe"
        binary2.write_bytes(b"MZ" + (b"\x00" * 1000))

        result1 = loader.load_file(str(sample_pe_binary))
        assert result1 is True
        size1 = loader.file_size

        result2 = loader.load_file(str(binary2))
        assert result2 is True
        assert loader.file_size != size1

        loader.close()

    def test_section_cache_memory_management(self, loader: MemoryOptimizedBinaryLoader, sample_pe_binary: Path) -> None:
        """Section cache respects memory limits."""
        loader.load_file(str(sample_pe_binary))

        for i in range(10):
            loader.read_section(f"section_{i}", i * 100, 200)

        assert len(loader.section_cache) <= 10

        loader.close()


class TestMemoryLoaderFactory:
    """Test memory loader factory function."""

    def test_create_memory_loader_default(self) -> None:
        """Factory creates loader with default configuration."""
        loader = create_memory_loader()

        assert isinstance(loader, MemoryOptimizedBinaryLoader)
        assert loader.chunk_size == 1024 * 1024
        assert loader.max_memory == 1024 * 1024 * 1024

    def test_create_memory_loader_custom(self) -> None:
        """Factory creates loader with custom configuration."""
        loader = create_memory_loader(chunk_size=512 * 1024, max_memory=512 * 1024 * 1024)

        assert loader.chunk_size == 512 * 1024
        assert loader.max_memory == 512 * 1024 * 1024


class TestMemoryOptimizedAnalysis:
    """Test high-level memory-optimized analysis function."""

    @pytest.fixture
    def packed_binary(self, tmp_path: Path) -> Path:
        """Create simulated packed binary."""
        binary_path = tmp_path / "packed.exe"

        import random

        random.seed(123)
        high_entropy_section = bytes(random.randint(0, 255) for _ in range(5000))

        pe_header = b"MZ" + (b"\x90" * 100) + b"PE\x00\x00" + (b"\x00" * 200)
        content = pe_header + high_entropy_section

        binary_path.write_bytes(content)
        return binary_path

    def test_analysis_full_type(self, packed_binary: Path) -> None:
        """Full analysis type completes successfully."""
        results = run_memory_optimized_analysis(str(packed_binary), analysis_type="full")

        assert results["status"] == "completed"
        assert "file_info" in results
        assert "entropy" in results
        assert "packed_probability" in results
        assert "sections" in results

    def test_analysis_quick_type(self, packed_binary: Path) -> None:
        """Quick analysis type completes successfully."""
        results = run_memory_optimized_analysis(str(packed_binary), analysis_type="quick")

        assert results["status"] == "completed"
        assert "file_info" in results
        assert "entropy" in results

    def test_analysis_entropy_type(self, packed_binary: Path) -> None:
        """Entropy analysis type focuses on entropy metrics."""
        results = run_memory_optimized_analysis(str(packed_binary), analysis_type="entropy")

        assert results["status"] == "completed"
        assert "entropy" in results
        assert "mean" in results["entropy"]
        assert "stdev" in results["entropy"]

    def test_analysis_sections_type(self, packed_binary: Path) -> None:
        """Sections analysis type analyzes section entropy."""
        results = run_memory_optimized_analysis(str(packed_binary), analysis_type="sections")

        assert results["status"] == "completed"
        assert "sections" in results
        assert len(results["sections"]) > 0

    def test_analysis_detects_high_entropy(self, packed_binary: Path) -> None:
        """Analysis detects high entropy indicating packing."""
        results = run_memory_optimized_analysis(str(packed_binary), analysis_type="full")

        assert results["packed_probability"] > 0.5

    def test_analysis_low_entropy_detection(self, tmp_path: Path) -> None:
        """Analysis detects low entropy in normal binary."""
        binary_path = tmp_path / "normal.exe"
        binary_path.write_bytes(b"MZ" + (b"\x00" * 1000))

        results = run_memory_optimized_analysis(str(binary_path), analysis_type="full")

        assert results["packed_probability"] < 0.3

    def test_analysis_anomaly_detection(self, packed_binary: Path) -> None:
        """Analysis detects anomalies in binary structure."""
        results = run_memory_optimized_analysis(str(packed_binary), analysis_type="full")

        assert "anomalies" in results
        assert isinstance(results["anomalies"], list)

    def test_analysis_performance_metrics(self, packed_binary: Path) -> None:
        """Analysis tracks performance metrics."""
        results = run_memory_optimized_analysis(str(packed_binary), analysis_type="full")

        assert "performance" in results
        assert "analysis_time" in results["performance"]
        assert results["performance"]["analysis_time"] < 10.0

    def test_analysis_nonexistent_file(self) -> None:
        """Analysis handles nonexistent file gracefully."""
        results = run_memory_optimized_analysis("/nonexistent/file.exe", analysis_type="full")

        assert results["status"] == "failed"
        assert "error" in results

    def test_analysis_custom_chunk_size(self, packed_binary: Path) -> None:
        """Analysis respects custom chunk size."""
        results = run_memory_optimized_analysis(str(packed_binary), analysis_type="full", chunk_size=256 * 1024)

        assert results["status"] == "completed"

    def test_analysis_suspicious_section_detection(self, tmp_path: Path) -> None:
        """Analysis detects suspicious sections with extreme entropy."""
        binary_path = tmp_path / "suspicious.exe"

        import random

        random.seed(456)
        header = b"MZ" + (b"\x00" * 100)
        normal_section = b"\x55\x89\xe5" + (b"\x90" * 500)
        packed_section = bytes(random.randint(0, 255) for _ in range(500))

        content = header + normal_section + packed_section
        binary_path.write_bytes(content)

        results = run_memory_optimized_analysis(str(binary_path), analysis_type="sections", chunk_size=256)

        assert "sections" in results
        suspicious = [s for s in results["sections"] if "packed" in s.get("flags", [])]
        assert len(suspicious) > 0

    def test_analysis_entropy_statistics(self, packed_binary: Path) -> None:
        """Analysis calculates accurate entropy statistics."""
        results = run_memory_optimized_analysis(str(packed_binary), analysis_type="entropy")

        entropy = results["entropy"]
        assert "mean" in entropy
        assert "stdev" in entropy
        assert "min" in entropy
        assert "max" in entropy
        assert entropy["min"] <= entropy["mean"] <= entropy["max"]

    def test_analysis_section_limit(self, tmp_path: Path) -> None:
        """Analysis limits section count for memory optimization."""
        binary_path = tmp_path / "large_sections.bin"

        content = b"\x00" * (200 * 1024 * 1024)
        binary_path.write_bytes(content)

        results = run_memory_optimized_analysis(str(binary_path), analysis_type="sections", chunk_size=1024 * 1024)

        assert len(results["sections"]) <= 100
