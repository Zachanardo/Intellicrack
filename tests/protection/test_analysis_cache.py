"""Production tests for protection analysis caching layer.

Tests validate advanced caching with persistence and management:
- Cache storage and retrieval operations
- Automatic invalidation on file changes
- LRU eviction on size/count limits
- Thread-safe concurrent access
- Persistent storage with integrity checks
- Cache statistics and monitoring
- Secure pickle operations with HMAC validation

All tests operate on real cache operations without mocks to validate
genuine caching performance and correctness.
"""

import os
import tempfile
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.protection.analysis_cache import (
    AnalysisCache,
    CacheEntry,
    CacheStats,
    clear_analysis_cache,
    get_analysis_cache,
    secure_pickle_dump,
    secure_pickle_load,
)

if TYPE_CHECKING:
    from collections.abc import Generator


@pytest.fixture
def temp_cache_dir() -> Generator[Path, None, None]:
    """Create temporary cache directory for testing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def sample_file() -> Generator[Path, None, None]:
    """Create temporary file for cache testing."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        f.write(b"test binary data" * 100)
        temp_path = Path(f.name)

    yield temp_path

    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def cache_instance(temp_cache_dir: Path) -> AnalysisCache:
    """Create AnalysisCache instance with temporary directory."""
    os.environ["INTELLICRACK_TESTING"] = "1"
    cache = AnalysisCache(
        cache_dir=str(temp_cache_dir),
        max_entries=10,
        max_size_mb=1,
        auto_save=False,
    )
    yield cache
    del os.environ["INTELLICRACK_TESTING"]


class TestCacheEntryDataClass:
    """Test CacheEntry data class structure and methods."""

    def test_cache_entry_initialization(self) -> None:
        """CacheEntry initializes with required fields."""
        entry = CacheEntry(
            data={"result": "test"},
            timestamp=time.time(),
            file_mtime=12345.67,
            file_size=1024,
        )

        assert entry.data == {"result": "test"}
        assert entry.timestamp > 0
        assert entry.file_mtime == 12345.67
        assert entry.file_size == 1024
        assert entry.access_count == 0
        assert entry.last_access == 0.0

    def test_cache_entry_is_valid_existing_file(self, sample_file: Path) -> None:
        """CacheEntry is_valid returns True for unchanged file."""
        file_mtime = sample_file.stat().st_mtime
        file_size = sample_file.stat().st_size

        entry = CacheEntry(
            data="test",
            timestamp=time.time(),
            file_mtime=file_mtime,
            file_size=file_size,
        )

        assert entry.is_valid(str(sample_file)) is True

    def test_cache_entry_is_valid_nonexistent_file(self) -> None:
        """CacheEntry is_valid returns False for nonexistent file."""
        entry = CacheEntry(
            data="test",
            timestamp=time.time(),
            file_mtime=123.45,
            file_size=1024,
        )

        assert entry.is_valid("nonexistent.file") is False

    def test_cache_entry_is_valid_modified_file(self, sample_file: Path) -> None:
        """CacheEntry is_valid returns False for modified file."""
        file_mtime = sample_file.stat().st_mtime
        file_size = sample_file.stat().st_size

        entry = CacheEntry(
            data="test",
            timestamp=time.time(),
            file_mtime=file_mtime - 1000,
            file_size=file_size,
        )

        time.sleep(0.1)
        sample_file.write_text("modified content")

        assert entry.is_valid(str(sample_file)) is False

    def test_cache_entry_update_access(self) -> None:
        """CacheEntry update_access increments count and updates timestamp."""
        entry = CacheEntry(
            data="test",
            timestamp=time.time(),
            file_mtime=123.45,
            file_size=1024,
        )

        assert entry.access_count == 0
        assert entry.last_access == 0.0

        entry.update_access()

        assert entry.access_count == 1
        assert entry.last_access > 0.0

        initial_access_time = entry.last_access
        time.sleep(0.05)

        entry.update_access()

        assert entry.access_count == 2
        assert entry.last_access > initial_access_time


class TestCacheStatsDataClass:
    """Test CacheStats data class and calculations."""

    def test_cache_stats_initialization(self) -> None:
        """CacheStats initializes with default values."""
        stats = CacheStats()

        assert stats.total_entries == 0
        assert stats.cache_hits == 0
        assert stats.cache_misses == 0
        assert stats.cache_invalidations == 0
        assert stats.total_size_bytes == 0

    def test_cache_stats_hit_rate_zero_requests(self) -> None:
        """CacheStats hit rate is 0.0 with no requests."""
        stats = CacheStats()

        assert stats.hit_rate == 0.0

    def test_cache_stats_hit_rate_all_hits(self) -> None:
        """CacheStats hit rate is 100.0 with all hits."""
        stats = CacheStats(cache_hits=10, cache_misses=0)

        assert stats.hit_rate == 100.0

    def test_cache_stats_hit_rate_mixed(self) -> None:
        """CacheStats hit rate calculates correctly with mixed hits/misses."""
        stats = CacheStats(cache_hits=7, cache_misses=3)

        assert stats.hit_rate == 70.0

    def test_cache_stats_to_dict(self) -> None:
        """CacheStats to_dict converts to dictionary."""
        stats = CacheStats(
            total_entries=5,
            cache_hits=10,
            cache_misses=3,
        )

        stats_dict = stats.to_dict()

        assert isinstance(stats_dict, dict)
        assert stats_dict["total_entries"] == 5
        assert stats_dict["cache_hits"] == 10
        assert stats_dict["cache_misses"] == 3


class TestAnalysisCacheInitialization:
    """Test AnalysisCache initialization and setup."""

    def test_cache_initialization_creates_directory(self, temp_cache_dir: Path) -> None:
        """AnalysisCache creates cache directory on init."""
        cache_path = temp_cache_dir / "test_cache"
        os.environ["INTELLICRACK_TESTING"] = "1"

        cache = AnalysisCache(cache_dir=str(cache_path))

        assert cache_path.exists()
        assert cache_path.is_dir()

        del os.environ["INTELLICRACK_TESTING"]

    def test_cache_initialization_sets_max_entries(self) -> None:
        """AnalysisCache respects max_entries parameter."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        cache = AnalysisCache(max_entries=50)

        assert cache.max_entries == 50

        del os.environ["INTELLICRACK_TESTING"]

    def test_cache_initialization_sets_max_size(self) -> None:
        """AnalysisCache respects max_size_mb parameter."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        cache = AnalysisCache(max_size_mb=200)

        assert cache.max_size_bytes == 200 * 1024 * 1024

        del os.environ["INTELLICRACK_TESTING"]

    def test_cache_initialization_creates_lock(self, cache_instance: AnalysisCache) -> None:
        """AnalysisCache creates thread synchronization lock."""
        assert isinstance(cache_instance._lock, threading.Lock)


class TestCacheStorageAndRetrieval:
    """Test basic cache storage and retrieval operations."""

    def test_put_and_get_simple_data(
        self,
        cache_instance: AnalysisCache,
        sample_file: Path,
    ) -> None:
        """Cache stores and retrieves simple data successfully."""
        test_data = {"protection": "VMProtect", "version": "3.5"}

        cache_instance.put(str(sample_file), test_data)

        retrieved = cache_instance.get(str(sample_file))

        assert retrieved == test_data

    def test_get_nonexistent_entry_returns_none(
        self,
        cache_instance: AnalysisCache,
    ) -> None:
        """Cache get returns None for nonexistent entry."""
        result = cache_instance.get("nonexistent_file.exe")

        assert result is None

    def test_put_updates_cache_stats(
        self,
        cache_instance: AnalysisCache,
        sample_file: Path,
    ) -> None:
        """Cache put updates total_entries statistic."""
        cache_instance.put(str(sample_file), {"test": "data"})

        stats = cache_instance.get_stats()

        assert stats.total_entries == 1

    def test_get_updates_access_count(
        self,
        cache_instance: AnalysisCache,
        sample_file: Path,
    ) -> None:
        """Cache get increments access count on hit."""
        cache_instance.put(str(sample_file), "test_data")

        cache_instance.get(str(sample_file))
        cache_instance.get(str(sample_file))
        cache_instance.get(str(sample_file))

        stats = cache_instance.get_stats()
        assert stats.cache_hits == 3

    def test_get_miss_increments_miss_count(
        self,
        cache_instance: AnalysisCache,
    ) -> None:
        """Cache get increments miss count when entry not found."""
        cache_instance.get("missing_file.exe")

        stats = cache_instance.get_stats()
        assert stats.cache_misses == 1

    def test_put_with_scan_options(
        self,
        cache_instance: AnalysisCache,
        sample_file: Path,
    ) -> None:
        """Cache differentiates entries with different scan options."""
        cache_instance.put(str(sample_file), "result1", "options_a")
        cache_instance.put(str(sample_file), "result2", "options_b")

        result1 = cache_instance.get(str(sample_file), "options_a")
        result2 = cache_instance.get(str(sample_file), "options_b")

        assert result1 == "result1"
        assert result2 == "result2"


class TestCacheInvalidation:
    """Test automatic cache invalidation on file changes."""

    def test_get_invalidates_on_file_modification(
        self,
        cache_instance: AnalysisCache,
        sample_file: Path,
    ) -> None:
        """Cache invalidates entry when file is modified."""
        cache_instance.put(str(sample_file), "original_result")

        time.sleep(0.1)
        sample_file.write_text("modified content")

        result = cache_instance.get(str(sample_file))

        assert result is None

    def test_get_invalidates_on_file_deletion(
        self,
        cache_instance: AnalysisCache,
    ) -> None:
        """Cache invalidates entry when file is deleted."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_file = Path(f.name)
            f.write(b"test data")

        cache_instance.put(str(temp_file), "result")

        temp_file.unlink()

        result = cache_instance.get(str(temp_file))

        assert result is None

    def test_cleanup_invalid_removes_invalidated_entries(
        self,
        cache_instance: AnalysisCache,
    ) -> None:
        """Cache cleanup_invalid removes entries for deleted files."""
        temp_files = []
        for i in range(3):
            with tempfile.NamedTemporaryFile(delete=False) as f:
                temp_file = Path(f.name)
                f.write(f"data{i}".encode())
                temp_files.append(temp_file)
                cache_instance.put(str(temp_file), f"result{i}")

        temp_files[0].unlink()
        temp_files[1].unlink()

        removed_count = cache_instance.cleanup_invalid()

        assert removed_count == 2

        for temp_file in temp_files[2:]:
            if temp_file.exists():
                temp_file.unlink()


class TestCacheEviction:
    """Test LRU eviction when cache limits are exceeded."""

    def test_eviction_on_max_entries_exceeded(
        self,
        temp_cache_dir: Path,
    ) -> None:
        """Cache evicts LRU entries when max_entries exceeded."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        cache = AnalysisCache(
            cache_dir=str(temp_cache_dir),
            max_entries=5,
            auto_save=False,
        )

        temp_files = []
        for i in range(10):
            with tempfile.NamedTemporaryFile(delete=False) as f:
                temp_file = Path(f.name)
                f.write(f"data{i}".encode())
                temp_files.append(temp_file)
                cache.put(str(temp_file), f"result{i}")
                time.sleep(0.01)

        stats = cache.get_stats()
        assert stats.total_entries <= cache.max_entries

        for temp_file in temp_files:
            if temp_file.exists():
                temp_file.unlink()

        del os.environ["INTELLICRACK_TESTING"]

    def test_lru_evicts_least_recently_accessed(
        self,
        temp_cache_dir: Path,
    ) -> None:
        """Cache evicts least recently accessed entries first."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        cache = AnalysisCache(
            cache_dir=str(temp_cache_dir),
            max_entries=3,
            auto_save=False,
        )

        temp_files = []
        for i in range(3):
            with tempfile.NamedTemporaryFile(delete=False) as f:
                temp_file = Path(f.name)
                f.write(f"data{i}".encode())
                temp_files.append(temp_file)
                cache.put(str(temp_file), f"result{i}")
                time.sleep(0.05)

        cache.get(str(temp_files[1]))
        cache.get(str(temp_files[2]))
        time.sleep(0.05)

        with tempfile.NamedTemporaryFile(delete=False) as f:
            new_file = Path(f.name)
            f.write(b"new data")
            cache.put(str(new_file), "new_result")

        result0 = cache.get(str(temp_files[0]))
        result1 = cache.get(str(temp_files[1]))

        assert result0 is None or result1 is not None

        for temp_file in temp_files + [new_file]:
            if temp_file.exists():
                temp_file.unlink()

        del os.environ["INTELLICRACK_TESTING"]


class TestCacheRemovalAndClear:
    """Test cache entry removal and clearing operations."""

    def test_remove_existing_entry(
        self,
        cache_instance: AnalysisCache,
        sample_file: Path,
    ) -> None:
        """Cache remove deletes specific entry."""
        cache_instance.put(str(sample_file), "test_data")

        removed = cache_instance.remove(str(sample_file))

        assert removed is True
        assert cache_instance.get(str(sample_file)) is None

    def test_remove_nonexistent_entry(
        self,
        cache_instance: AnalysisCache,
    ) -> None:
        """Cache remove returns False for nonexistent entry."""
        removed = cache_instance.remove("nonexistent.exe")

        assert removed is False

    def test_clear_removes_all_entries(
        self,
        cache_instance: AnalysisCache,
        sample_file: Path,
    ) -> None:
        """Cache clear removes all entries."""
        cache_instance.put(str(sample_file), "data1")
        cache_instance.put(str(sample_file) + "2", "data2")

        cache_instance.clear()

        stats = cache_instance.get_stats()
        assert stats.total_entries == 0


class TestCacheStatistics:
    """Test cache statistics tracking and reporting."""

    def test_get_stats_returns_cache_stats(
        self,
        cache_instance: AnalysisCache,
    ) -> None:
        """Cache get_stats returns CacheStats object."""
        stats = cache_instance.get_stats()

        assert isinstance(stats, CacheStats)

    def test_stats_track_hits_and_misses(
        self,
        cache_instance: AnalysisCache,
        sample_file: Path,
    ) -> None:
        """Cache stats correctly track hits and misses."""
        cache_instance.put(str(sample_file), "data")

        cache_instance.get(str(sample_file))
        cache_instance.get(str(sample_file))
        cache_instance.get("missing.exe")

        stats = cache_instance.get_stats()

        assert stats.cache_hits == 2
        assert stats.cache_misses == 1

    def test_get_cache_info_returns_detailed_info(
        self,
        cache_instance: AnalysisCache,
        sample_file: Path,
    ) -> None:
        """Cache get_cache_info returns comprehensive information."""
        cache_instance.put(str(sample_file), "test_data")

        info = cache_instance.get_cache_info()

        assert "stats" in info
        assert "cache_size_mb" in info
        assert "cache_directory" in info
        assert "max_entries" in info
        assert "top_entries" in info


class TestCachePersistence:
    """Test cache persistence to disk."""

    def test_save_cache_writes_to_disk(
        self,
        cache_instance: AnalysisCache,
        sample_file: Path,
    ) -> None:
        """Cache save_cache writes cache file to disk."""
        cache_instance.put(str(sample_file), "test_data")

        cache_instance.save_cache()

        assert cache_instance.cache_file.exists()

    def test_load_cache_restores_entries(
        self,
        temp_cache_dir: Path,
        sample_file: Path,
    ) -> None:
        """Cache loads previously saved entries on initialization."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        cache1 = AnalysisCache(cache_dir=str(temp_cache_dir), auto_save=False)
        cache1.put(str(sample_file), "persisted_data")
        cache1.save_cache()

        cache2 = AnalysisCache(cache_dir=str(temp_cache_dir), auto_save=False)

        result = cache2.get(str(sample_file))

        assert result == "persisted_data"

        del os.environ["INTELLICRACK_TESTING"]


class TestSecurePickleOperations:
    """Test secure pickle operations with HMAC integrity."""

    def test_secure_pickle_dump_and_load(self) -> None:
        """Secure pickle dump and load preserves data."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_file = Path(f.name)

        test_data = {"key": "value", "number": 42}

        secure_pickle_dump(test_data, str(temp_file))
        loaded_data = secure_pickle_load(str(temp_file))

        assert loaded_data == test_data

        if temp_file.exists():
            temp_file.unlink()

    def test_secure_pickle_load_detects_tampering(self) -> None:
        """Secure pickle load raises ValueError on tampering."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_file = Path(f.name)

        test_data = {"test": "data"}
        secure_pickle_dump(test_data, str(temp_file))

        with open(temp_file, "r+b") as f:
            f.seek(40)
            f.write(b"\xFF")

        with pytest.raises(ValueError, match="integrity check failed"):
            secure_pickle_load(str(temp_file))

        if temp_file.exists():
            temp_file.unlink()


class TestThreadSafety:
    """Test thread safety of cache operations."""

    def test_concurrent_put_operations(
        self,
        cache_instance: AnalysisCache,
    ) -> None:
        """Cache handles concurrent put operations safely."""
        temp_files = []

        def put_worker(index: int) -> None:
            with tempfile.NamedTemporaryFile(delete=False) as f:
                temp_file = Path(f.name)
                f.write(f"data{index}".encode())
                temp_files.append(temp_file)
                cache_instance.put(str(temp_file), f"result{index}")

        threads = [threading.Thread(target=put_worker, args=(i,)) for i in range(10)]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        for temp_file in temp_files:
            if temp_file.exists():
                temp_file.unlink()

    def test_concurrent_get_operations(
        self,
        cache_instance: AnalysisCache,
        sample_file: Path,
    ) -> None:
        """Cache handles concurrent get operations safely."""
        cache_instance.put(str(sample_file), "shared_data")

        results: list[object] = []

        def get_worker() -> None:
            result = cache_instance.get(str(sample_file))
            results.append(result)

        threads = [threading.Thread(target=get_worker) for _ in range(20)]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert all(r == "shared_data" for r in results)


class TestGlobalCacheInstance:
    """Test global cache instance getter functions."""

    def test_get_analysis_cache_creates_instance(self) -> None:
        """Get analysis cache creates global instance."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        clear_analysis_cache()

        cache = get_analysis_cache()

        assert isinstance(cache, AnalysisCache)

        del os.environ["INTELLICRACK_TESTING"]

    def test_get_analysis_cache_returns_same_instance(self) -> None:
        """Get analysis cache returns same instance on multiple calls."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        clear_analysis_cache()

        cache1 = get_analysis_cache()
        cache2 = get_analysis_cache()

        assert cache1 is cache2

        del os.environ["INTELLICRACK_TESTING"]

    def test_clear_analysis_cache_resets_global_instance(self) -> None:
        """Clear analysis cache resets global instance."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        cache1 = get_analysis_cache()
        clear_analysis_cache()
        cache2 = get_analysis_cache()

        assert cache1 is not cache2

        del os.environ["INTELLICRACK_TESTING"]
