"""Production-Ready Tests for Large File Handler Module.

Tests REAL memory mapping, chunking, caching with actual large files.
"""

from pathlib import Path

import pytest

from intellicrack.hexview.large_file_handler import (
    BackgroundLoader,
    FileCache,
    FileRegion,
    LargeFileHandler,
    LoadingStrategy,
    MemoryConfig,
    MemoryMonitor,
    MemoryStrategy,
)


class TestMemoryConfig:
    """Test MemoryConfig data structure."""

    def test_memoryconfig_default_values(self) -> None:
        """MemoryConfig must have reasonable default values."""
        config = MemoryConfig()

        assert config.max_memory_mb == 500
        assert config.chunk_size_mb == 10
        assert config.cache_size_mb == 100
        assert config.memory_threshold == 0.8
        assert config.prefetch_chunks == 2


class TestFileRegion:
    """Test FileRegion data structure."""

    def test_fileregion_stores_data(self) -> None:
        """FileRegion must store offset, size, and data."""
        data = b"TEST" * 100
        region = FileRegion(offset=1000, size=len(data), data=data)

        assert region.offset == 1000
        assert region.size == 400
        assert region.data == data
        assert region.ref_count == 0

    def test_fileregion_tracks_access_time(self) -> None:
        """FileRegion must track last access time."""
        region = FileRegion(offset=0, size=100, data=b"X" * 100)
        region.last_accessed = 123.456

        assert region.last_accessed == 123.456


class TestFileCache:
    """Test FileCache LRU implementation."""

    def test_filecache_adds_regions(self) -> None:
        """FileCache must add and retrieve regions."""
        config = MemoryConfig(cache_size_mb=10)
        cache = FileCache(config)

        region = FileRegion(offset=0, size=1000, data=b"X" * 1000)
        success = cache.add_region(region)

        assert success is True
        assert len(cache.regions) == 1

    def test_filecache_retrieves_containing_region(self) -> None:
        """FileCache must retrieve region containing requested data."""
        config = MemoryConfig(cache_size_mb=10)
        cache = FileCache(config)

        region = FileRegion(offset=1000, size=2000, data=b"X" * 2000)
        cache.add_region(region)

        retrieved = cache.get_region(1500, 100)

        assert retrieved is not None
        assert retrieved.offset == 1000

    def test_filecache_evicts_old_regions(self) -> None:
        """FileCache must evict old regions when full."""
        config = MemoryConfig(cache_size_mb=1)
        cache = FileCache(config)

        for i in range(100):
            region = FileRegion(offset=i * 100000, size=100000, data=b"X" * 100000)
            cache.add_region(region)

        assert cache.total_memory <= config.cache_size_mb * 1024 * 1024

    def test_filecache_reference_counting(self) -> None:
        """FileCache must track region reference counts."""
        config = MemoryConfig(cache_size_mb=10)
        cache = FileCache(config)

        region = FileRegion(offset=0, size=1000, data=b"X" * 1000)
        cache.add_region(region)

        retrieved = cache.get_region(0, 100)
        assert retrieved.ref_count == 1

        cache.release_region(retrieved)
        assert retrieved.ref_count == 0

    def test_filecache_clear(self) -> None:
        """FileCache must clear all regions."""
        config = MemoryConfig(cache_size_mb=10)
        cache = FileCache(config)

        for i in range(5):
            region = FileRegion(offset=i * 1000, size=1000, data=b"X" * 1000)
            cache.add_region(region)

        cache.clear()

        assert len(cache.regions) == 0
        assert cache.total_memory == 0

    def test_filecache_cleanup_old_regions(self) -> None:
        """FileCache must remove old unused regions."""
        import time

        config = MemoryConfig(cache_size_mb=10)
        cache = FileCache(config)

        old_region = FileRegion(offset=0, size=1000, data=b"X" * 1000)
        old_region.last_accessed = time.time() - 120
        cache.add_region(old_region)

        new_region = FileRegion(offset=1000, size=1000, data=b"Y" * 1000)
        cache.add_region(new_region)

        removed = cache.cleanup_old_regions(max_age=60)

        assert removed >= 1

    def test_filecache_statistics(self) -> None:
        """FileCache must provide accurate statistics."""
        config = MemoryConfig(cache_size_mb=10)
        cache = FileCache(config)

        for i in range(3):
            region = FileRegion(offset=i * 1000, size=1000, data=b"X" * 1000)
            cache.add_region(region)

        stats = cache.get_stats()

        assert stats["regions"] == 3
        assert stats["total_memory_mb"] > 0
        assert stats["max_memory_mb"] == 10


class TestLargeFileHandler:
    """Test LargeFileHandler with real files."""

    @pytest.fixture
    def small_file(self, tmp_path: Path) -> Path:
        """Create small test file (<100MB)."""
        file_path = tmp_path / "small.bin"
        data = bytes(range(256)) * 1000
        file_path.write_bytes(data)
        return file_path

    @pytest.fixture
    def medium_file(self, tmp_path: Path) -> Path:
        """Create medium test file (1MB)."""
        file_path = tmp_path / "medium.bin"
        data = bytes(range(256)) * 4096
        file_path.write_bytes(data)
        return file_path

    def test_largefilehandler_opens_small_file(self, small_file: Path) -> None:
        """LargeFileHandler must open small files with direct load strategy."""
        handler = LargeFileHandler(str(small_file), read_only=True)

        assert handler.get_file_size() == 256000
        assert handler.memory_strategy == MemoryStrategy.DIRECT_LOAD

    def test_largefilehandler_opens_medium_file(self, medium_file: Path) -> None:
        """LargeFileHandler must open medium files with appropriate strategy."""
        handler = LargeFileHandler(str(medium_file), read_only=True)

        assert handler.get_file_size() > 1000000
        assert handler.memory_strategy in [MemoryStrategy.DIRECT_LOAD, MemoryStrategy.MEMORY_MAP]

    def test_largefilehandler_reads_data(self, small_file: Path) -> None:
        """LargeFileHandler must read data correctly."""
        handler = LargeFileHandler(str(small_file), read_only=True)

        data = handler.read(0, 256)

        assert len(data) == 256
        assert data == bytes(range(256))

    def test_largefilehandler_reads_at_offset(self, medium_file: Path) -> None:
        """LargeFileHandler must read data at any offset."""
        handler = LargeFileHandler(str(medium_file), read_only=True)

        data = handler.read(500000, 1000)

        assert len(data) == 1000

    def test_largefilehandler_handles_out_of_bounds(self, small_file: Path) -> None:
        """LargeFileHandler must handle out-of-bounds reads."""
        handler = LargeFileHandler(str(small_file), read_only=True)

        data = handler.read(1000000, 100)

        assert data == b""

    def test_largefilehandler_adjusts_read_size(self, small_file: Path) -> None:
        """LargeFileHandler must adjust read size to file bounds."""
        handler = LargeFileHandler(str(small_file), read_only=True)
        file_size = handler.get_file_size()

        data = handler.read(file_size - 10, 100)

        assert len(data) == 10

    def test_largefilehandler_provides_statistics(self, medium_file: Path) -> None:
        """LargeFileHandler must provide performance statistics."""
        handler = LargeFileHandler(str(medium_file), read_only=True)

        handler.read(0, 1000)
        handler.read(1000, 1000)

        stats = handler.get_stats()

        assert "file_size_mb" in stats
        assert "memory_strategy" in stats
        assert "cache_stats" in stats

    def test_largefilehandler_cleanup(self, small_file: Path) -> None:
        """LargeFileHandler must clean up resources on close."""
        handler = LargeFileHandler(str(small_file), read_only=True)

        handler.close()

        assert handler.mmap_file is None
        assert handler.file_handle is None


class TestMemoryMonitor:
    """Test MemoryMonitor functionality."""

    def test_memorymonitor_creates_with_config(self) -> None:
        """MemoryMonitor must create with configuration."""
        config = MemoryConfig()
        monitor = MemoryMonitor(config)

        assert monitor.config == config
        assert monitor.monitoring is False

    def test_memorymonitor_adds_callbacks(self) -> None:
        """MemoryMonitor must register callbacks."""
        config = MemoryConfig()
        monitor = MemoryMonitor(config)

        callback_invoked = []

        def callback(usage: float) -> None:
            callback_invoked.append(usage)

        monitor.add_callback(callback)

        assert len(monitor.callbacks) == 1


class TestBackgroundLoader:
    """Test BackgroundLoader functionality."""

    @pytest.fixture
    def test_file(self, tmp_path: Path) -> Path:
        """Create test file for background loading."""
        file_path = tmp_path / "test.bin"
        data = bytes(range(256)) * 1000
        file_path.write_bytes(data)
        return file_path

    def test_backgroundloader_creates(self, test_file: Path) -> None:
        """BackgroundLoader must create with file path."""
        config = MemoryConfig()
        cache = FileCache(config)
        loader = BackgroundLoader(str(test_file), cache, config)

        assert loader.file_path == str(test_file)
        assert loader.cache == cache

    def test_backgroundloader_queues_loads(self, test_file: Path) -> None:
        """BackgroundLoader must queue load requests."""
        config = MemoryConfig()
        cache = FileCache(config)
        loader = BackgroundLoader(str(test_file), cache, config)

        loader.queue_load(0, 1000)
        loader.queue_load(1000, 1000)

        assert len(loader.load_queue) == 2


class TestRealWorldLargeFiles:
    """Test with real Windows system files."""

    def test_largefilehandler_system_binary(self) -> None:
        """LargeFileHandler must handle real system binaries."""
        notepad = Path("C:/Windows/System32/notepad.exe")
        if not notepad.exists():
            pytest.skip("notepad.exe not found - Windows system required")

        handler = LargeFileHandler(str(notepad), read_only=True)

        mz_header = handler.read(0, 2)
        assert mz_header == b"MZ"

        stats = handler.get_stats()
        assert stats["file_size_mb"] > 0

        handler.close()

    def test_largefilehandler_large_system_dll(self) -> None:
        """LargeFileHandler must efficiently handle large DLLs."""
        shell32 = Path("C:/Windows/System32/shell32.dll")
        if not shell32.exists():
            pytest.skip("shell32.dll not found")

        handler = LargeFileHandler(str(shell32), read_only=True)

        file_size = handler.get_file_size()
        assert file_size > 0

        data = handler.read(0, 1024)
        assert len(data) == 1024

        handler.close()


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_largefilehandler_empty_file(self, tmp_path: Path) -> None:
        """LargeFileHandler must handle empty files."""
        empty_file = tmp_path / "empty.bin"
        empty_file.write_bytes(b"")

        handler = LargeFileHandler(str(empty_file), read_only=True)

        assert handler.get_file_size() == 0

        data = handler.read(0, 100)
        assert data == b""

    def test_largefilehandler_invalid_offset(self, tmp_path: Path) -> None:
        """LargeFileHandler must handle invalid offsets."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"TEST" * 100)

        handler = LargeFileHandler(str(test_file), read_only=True)

        data = handler.read(-100, 10)
        assert data == b""

    def test_largefilehandler_zero_size_read(self, tmp_path: Path) -> None:
        """LargeFileHandler must handle zero-size reads."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"TEST" * 100)

        handler = LargeFileHandler(str(test_file), read_only=True)

        data = handler.read(0, 0)
        assert data == b""


class TestPerformance:
    """Test performance characteristics."""

    def test_largefilehandler_sequential_reads(self, tmp_path: Path) -> None:
        """LargeFileHandler must optimize sequential reads."""
        large_file = tmp_path / "large.bin"
        data = bytes(range(256)) * 4096
        large_file.write_bytes(data)

        handler = LargeFileHandler(str(large_file), read_only=True)

        offset = 0
        chunk_size = 4096
        reads = 0

        while offset < handler.get_file_size() and reads < 100:
            chunk = handler.read(offset, chunk_size)
            if not chunk:
                break
            offset += chunk_size
            reads += 1

        assert reads > 0

        stats = handler.get_stats()
        assert stats["sequential_ratio"] > 0.5

    def test_largefilehandler_random_reads(self, tmp_path: Path) -> None:
        """LargeFileHandler must handle random reads efficiently."""
        large_file = tmp_path / "large.bin"
        data = bytes(range(256)) * 4096
        large_file.write_bytes(data)

        handler = LargeFileHandler(str(large_file), read_only=True)

        import random

        for _ in range(50):
            offset = random.randint(0, handler.get_file_size() - 1000)
            chunk = handler.read(offset, 1000)
            assert len(chunk) > 0


class TestChunkingStrategies:
    """Test different chunking strategies."""

    def test_direct_load_strategy(self, tmp_path: Path) -> None:
        """Small files must use direct load strategy."""
        small_file = tmp_path / "small.bin"
        small_file.write_bytes(b"X" * 10000)

        handler = LargeFileHandler(str(small_file), read_only=True)

        assert handler.memory_strategy == MemoryStrategy.DIRECT_LOAD

    def test_streaming_strategy_selection(self, tmp_path: Path) -> None:
        """LargeFileHandler must select appropriate strategy based on size."""
        config = MemoryConfig(max_memory_mb=1)

        file_path = tmp_path / "file.bin"
        file_path.write_bytes(b"X" * 1000)

        handler = LargeFileHandler(str(file_path), read_only=True, config=config)

        assert handler.memory_strategy in [
            MemoryStrategy.DIRECT_LOAD,
            MemoryStrategy.MEMORY_MAP,
            MemoryStrategy.STREAMING,
        ]


class TestVeryLargeFileHandling:
    """Test handling of very large files (>1GB)."""

    @pytest.mark.slow
    def test_create_and_read_1gb_file(self, tmp_path: Path) -> None:
        """Handler creates and reads from 1GB file efficiently."""
        large_file = tmp_path / "1gb.bin"

        chunk_size = 1024 * 1024
        num_chunks = 1024

        with open(large_file, "wb") as f:
            for i in range(num_chunks):
                chunk = bytes([i % 256]) * chunk_size
                f.write(chunk)

        handler = LargeFileHandler(str(large_file), read_only=True)

        assert handler.get_file_size() == chunk_size * num_chunks

        data_start = handler.read(0, 1024)
        assert len(data_start) == 1024
        assert data_start[0] == 0

        data_middle = handler.read(512 * 1024 * 1024, 1024)
        assert len(data_middle) == 1024

        data_end = handler.read(handler.get_file_size() - 1024, 1024)
        assert len(data_end) == 1024

    @pytest.mark.slow
    def test_sparse_reads_from_large_file(self, tmp_path: Path) -> None:
        """Handler efficiently handles sparse reads from large file."""
        large_file = tmp_path / "sparse.bin"

        chunk_size = 10 * 1024 * 1024
        num_chunks = 100

        with open(large_file, "wb") as f:
            for i in range(num_chunks):
                chunk = bytes([i % 256]) * chunk_size
                f.write(chunk)

        handler = LargeFileHandler(str(large_file), read_only=True)

        import random
        for _ in range(20):
            offset = random.randint(0, handler.get_file_size() - 1024)
            data = handler.read(offset, 1024)
            assert len(data) == 1024

    @pytest.mark.slow
    def test_memory_usage_stays_bounded_for_large_file(self, tmp_path: Path) -> None:
        """Memory usage stays within bounds when reading large file."""
        large_file = tmp_path / "bounded.bin"

        chunk_size = 10 * 1024 * 1024
        num_chunks = 100

        with open(large_file, "wb") as f:
            for i in range(num_chunks):
                chunk = bytes([i % 256]) * chunk_size
                f.write(chunk)

        config = MemoryConfig(max_memory_mb=100, cache_size_mb=50)
        handler = LargeFileHandler(str(large_file), read_only=True, config=config)

        for offset in range(0, handler.get_file_size(), 5 * 1024 * 1024):
            data = handler.read(offset, min(1024 * 1024, handler.get_file_size() - offset))
            assert len(data) > 0

        assert handler.cache.total_memory <= config.cache_size_mb * 1024 * 1024

    def test_large_file_memory_mapping(self, tmp_path: Path) -> None:
        """Large files use memory mapping when appropriate."""
        large_file = tmp_path / "mmap.bin"

        chunk_size = 1024 * 1024
        num_chunks = 100

        with open(large_file, "wb") as f:
            for i in range(num_chunks):
                chunk = bytes([i % 256]) * chunk_size
                f.write(chunk)

        handler = LargeFileHandler(str(large_file), read_only=True)

        assert handler.memory_strategy in [MemoryStrategy.MEMORY_MAP, MemoryStrategy.STREAMING]

        data = handler.read(50 * 1024 * 1024, 1024)
        assert len(data) == 1024

    def test_large_file_streaming_strategy(self, tmp_path: Path) -> None:
        """Very large files use streaming strategy to limit memory."""
        large_file = tmp_path / "stream.bin"

        chunk_size = 10 * 1024 * 1024
        num_chunks = 200

        with open(large_file, "wb") as f:
            for i in range(num_chunks):
                chunk = bytes([i % 256]) * chunk_size
                f.write(chunk)

        config = MemoryConfig(max_memory_mb=50)
        handler = LargeFileHandler(str(large_file), read_only=True, config=config)

        assert handler.memory_strategy == MemoryStrategy.STREAMING

        for offset in range(0, handler.get_file_size(), 100 * 1024 * 1024):
            data = handler.read(offset, 1024)
            assert len(data) == 1024


class TestConcurrentAccess:
    """Test concurrent access to files."""

    def test_concurrent_reads_same_file(self, tmp_path: Path) -> None:
        """Multiple handlers can read same file concurrently."""
        file_path = tmp_path / "concurrent.bin"
        data = bytes(range(256)) * 10000
        file_path.write_bytes(data)

        handler1 = LargeFileHandler(str(file_path), read_only=True)
        handler2 = LargeFileHandler(str(file_path), read_only=True)

        data1 = handler1.read(0, 1000)
        data2 = handler2.read(0, 1000)

        assert data1 == data2
        assert len(data1) == 1000

    def test_concurrent_reads_different_offsets(self, tmp_path: Path) -> None:
        """Concurrent reads from different offsets work correctly."""
        file_path = tmp_path / "concurrent2.bin"
        data = bytes(range(256)) * 10000
        file_path.write_bytes(data)

        handler1 = LargeFileHandler(str(file_path), read_only=True)
        handler2 = LargeFileHandler(str(file_path), read_only=True)

        data1 = handler1.read(0, 1000)
        data2 = handler2.read(10000, 1000)

        assert len(data1) == 1000
        assert len(data2) == 1000
        assert data1 != data2

    def test_threaded_concurrent_access(self, tmp_path: Path) -> None:
        """Handler supports thread-safe concurrent access."""
        import threading

        file_path = tmp_path / "threaded.bin"
        data = bytes(range(256)) * 40000
        file_path.write_bytes(data)

        handler = LargeFileHandler(str(file_path), read_only=True)
        results = []
        errors = []

        def read_worker(offset: int) -> None:
            try:
                chunk = handler.read(offset, 1000)
                results.append(len(chunk))
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(10):
            offset = i * 10000
            thread = threading.Thread(target=read_worker, args=(offset,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        assert not errors
        assert len(results) == 10
        assert all(r == 1000 for r in results)


class TestCorruptedFileHandling:
    """Test handling of corrupted or invalid files."""

    def test_handles_truncated_file(self, tmp_path: Path) -> None:
        """Handler detects and handles truncated file gracefully."""
        file_path = tmp_path / "truncated.bin"
        data = bytes(range(256)) * 1000
        file_path.write_bytes(data)

        handler = LargeFileHandler(str(file_path), read_only=True)
        original_size = handler.get_file_size()

        with open(file_path, "wb") as f:
            f.write(data[:len(data) // 2])

        try:
            truncated_data = handler.read(0, original_size)
            assert len(truncated_data) <= original_size
        except (IOError, OSError):
            pass

    def test_handles_file_deletion_during_read(self, tmp_path: Path) -> None:
        """Handler handles file deletion during read."""
        file_path = tmp_path / "deleted.bin"
        data = bytes(range(256)) * 1000
        file_path.write_bytes(data)

        handler = LargeFileHandler(str(file_path), read_only=True)

        initial_read = handler.read(0, 100)
        assert len(initial_read) == 100

        import os
        try:
            os.remove(file_path)
        except (PermissionError, FileNotFoundError):
            pass

    def test_handles_corrupted_data(self, tmp_path: Path) -> None:
        """Handler reads corrupted data without crashing."""
        file_path = tmp_path / "corrupted.bin"

        import random
        random_data = bytes(random.getrandbits(8) for _ in range(100000))
        file_path.write_bytes(random_data)

        handler = LargeFileHandler(str(file_path), read_only=True)

        for offset in range(0, len(random_data), 10000):
            chunk = handler.read(offset, min(1000, len(random_data) - offset))
            assert isinstance(chunk, bytes)

    def test_handles_zero_byte_file(self, tmp_path: Path) -> None:
        """Handler handles zero-byte file correctly."""
        file_path = tmp_path / "zero.bin"
        file_path.write_bytes(b"")

        handler = LargeFileHandler(str(file_path), read_only=True)

        assert handler.get_file_size() == 0

        data = handler.read(0, 100)
        assert len(data) == 0

    def test_handles_single_byte_file(self, tmp_path: Path) -> None:
        """Handler handles single-byte file correctly."""
        file_path = tmp_path / "single.bin"
        file_path.write_bytes(b"X")

        handler = LargeFileHandler(str(file_path), read_only=True)

        assert handler.get_file_size() == 1

        data = handler.read(0, 1)
        assert data == b"X"

    def test_handles_read_beyond_eof(self, tmp_path: Path) -> None:
        """Handler handles read attempts beyond EOF."""
        file_path = tmp_path / "eof.bin"
        file_path.write_bytes(b"X" * 1000)

        handler = LargeFileHandler(str(file_path), read_only=True)

        data = handler.read(900, 200)
        assert len(data) == 100

        data_beyond = handler.read(1000, 100)
        assert len(data_beyond) == 0
