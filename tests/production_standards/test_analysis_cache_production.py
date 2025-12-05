"""Production-Grade Tests for Analysis Cache Module.

Validates real caching functionality for protection analysis results with
persistence, size management, and automatic invalidation.
"""

import hashlib
import os
import pickle
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.protection.analysis_cache import (
    AnalysisCache,
    CacheEntry,
    CacheStats,
    RestrictedUnpickler,
    clear_analysis_cache,
    get_analysis_cache,
    secure_pickle_dump,
    secure_pickle_load,
)


@pytest.fixture
def temp_cache_dir(tmp_path: Path) -> Path:
    cache_dir = tmp_path / "test_cache"
    cache_dir.mkdir(exist_ok=True)
    return cache_dir


@pytest.fixture
def test_binary_path(tmp_path: Path) -> Path:
    binary_path = tmp_path / "test_binary.exe"
    binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 1024)
    return binary_path


@pytest.fixture
def analysis_cache(temp_cache_dir: Path) -> AnalysisCache:
    os.environ["DISABLE_BACKGROUND_THREADS"] = "1"
    cache = AnalysisCache(
        cache_dir=str(temp_cache_dir),
        max_entries=100,
        max_size_mb=10,
        auto_save=False,
    )
    yield cache
    cache.clear()
    os.environ.pop("DISABLE_BACKGROUND_THREADS", None)


@pytest.fixture
def sample_analysis_result() -> dict[str, Any]:
    return {
        "protections": ["VMProtect", "Themida"],
        "is_packed": True,
        "confidence": 95.0,
        "entropy": 7.8,
        "sections": [".vmp0", ".vmp1"],
    }


class TestSecurePickle:
    def test_secure_pickle_dump_creates_file_with_hmac(self, tmp_path: Path) -> None:
        test_data = {"test": "data", "numbers": [1, 2, 3]}
        file_path = tmp_path / "test_pickle.pkl"

        secure_pickle_dump(test_data, str(file_path))

        assert file_path.exists()
        content = file_path.read_bytes()
        assert len(content) > 32
        assert len(content) == 32 + len(pickle.dumps(test_data))

    def test_secure_pickle_load_validates_integrity(self, tmp_path: Path) -> None:
        test_data = {"analysis": "result", "confidence": 95.5}
        file_path = tmp_path / "test_pickle.pkl"

        secure_pickle_dump(test_data, str(file_path))
        loaded_data = secure_pickle_load(str(file_path))

        assert loaded_data == test_data

    def test_secure_pickle_load_detects_tampering(self, tmp_path: Path) -> None:
        test_data = {"analysis": "result"}
        file_path = tmp_path / "test_pickle.pkl"

        secure_pickle_dump(test_data, str(file_path))

        content = file_path.read_bytes()
        tampered = content[:32] + b"TAMPERED" + content[40:]
        file_path.write_bytes(tampered)

        with pytest.raises(ValueError, match="integrity check failed"):
            secure_pickle_load(str(file_path))

    def test_restricted_unpickler_blocks_unsafe_classes(self, tmp_path: Path) -> None:
        class UnsafeClass:
            def __reduce__(self) -> tuple[type, tuple[str]]:
                return (os.system, ("echo hacked",))

        unsafe_obj = UnsafeClass()
        pickled = pickle.dumps(unsafe_obj)

        file_path = tmp_path / "unsafe.pkl"
        file_path.write_bytes(b"\x00" * 32 + pickled)

        with pytest.raises(pickle.UnpicklingError):
            secure_pickle_load(str(file_path))

    def test_restricted_unpickler_allows_safe_modules(self, tmp_path: Path) -> None:
        import datetime

        safe_data = {
            "timestamp": datetime.datetime.now(),
            "data": [1, 2, 3],
            "dict": {"key": "value"},
        }

        file_path = tmp_path / "safe.pkl"
        secure_pickle_dump(safe_data, str(file_path))

        loaded = secure_pickle_load(str(file_path))
        assert isinstance(loaded["timestamp"], datetime.datetime)
        assert loaded["data"] == [1, 2, 3]


class TestCacheEntry:
    def test_cache_entry_tracks_access_statistics(
        self,
        test_binary_path: Path,
    ) -> None:
        entry = CacheEntry(
            data={"test": "data"},
            timestamp=time.time(),
            file_mtime=test_binary_path.stat().st_mtime,
            file_size=test_binary_path.stat().st_size,
        )

        assert entry.access_count == 0
        assert entry.last_access == 0.0

        entry.update_access()
        assert entry.access_count == 1
        assert entry.last_access > 0

        time.sleep(0.01)
        entry.update_access()
        assert entry.access_count == 2

    def test_cache_entry_validates_file_existence(self, tmp_path: Path) -> None:
        file_path = tmp_path / "test.exe"
        file_path.write_bytes(b"test")

        entry = CacheEntry(
            data={},
            timestamp=time.time(),
            file_mtime=file_path.stat().st_mtime,
            file_size=len(b"test"),
        )

        assert entry.is_valid(str(file_path))

        file_path.unlink()
        assert not entry.is_valid(str(file_path))

    def test_cache_entry_detects_file_modifications(
        self,
        test_binary_path: Path,
    ) -> None:
        original_mtime = test_binary_path.stat().st_mtime

        entry = CacheEntry(
            data={},
            timestamp=time.time(),
            file_mtime=original_mtime,
            file_size=test_binary_path.stat().st_size,
        )

        assert entry.is_valid(str(test_binary_path))

        time.sleep(0.1)
        test_binary_path.write_bytes(b"MZ\x90\x00" + b"\xFF" * 1024)

        assert not entry.is_valid(str(test_binary_path))

    def test_cache_entry_detects_size_changes(self, tmp_path: Path) -> None:
        file_path = tmp_path / "test.exe"
        file_path.write_bytes(b"original")

        entry = CacheEntry(
            data={},
            timestamp=time.time(),
            file_mtime=file_path.stat().st_mtime,
            file_size=len(b"original"),
        )

        assert entry.is_valid(str(file_path))

        file_path.write_bytes(b"modified_longer_content")
        assert not entry.is_valid(str(file_path))


class TestCacheStats:
    def test_cache_stats_calculates_hit_rate(self) -> None:
        stats = CacheStats(cache_hits=75, cache_misses=25)

        assert stats.hit_rate == 75.0

    def test_cache_stats_handles_zero_requests(self) -> None:
        stats = CacheStats(cache_hits=0, cache_misses=0)

        assert stats.hit_rate == 0.0

    def test_cache_stats_converts_to_dict(self) -> None:
        stats = CacheStats(
            total_entries=100,
            cache_hits=80,
            cache_misses=20,
            cache_invalidations=5,
            total_size_bytes=1024000,
        )

        result = stats.to_dict()

        assert isinstance(result, dict)
        assert result["total_entries"] == 100
        assert result["cache_hits"] == 80
        assert "hit_rate" not in result


class TestAnalysisCache:
    def test_cache_initialization_creates_directory(
        self,
        temp_cache_dir: Path,
    ) -> None:
        cache_dir = temp_cache_dir / "new_cache"
        assert not cache_dir.exists()

        cache = AnalysisCache(cache_dir=str(cache_dir))

        assert cache_dir.exists()
        assert cache.cache_dir == cache_dir

    def test_cache_stores_and_retrieves_analysis_results(
        self,
        analysis_cache: AnalysisCache,
        test_binary_path: Path,
        sample_analysis_result: dict[str, Any],
    ) -> None:
        analysis_cache.put(str(test_binary_path), sample_analysis_result)

        result = analysis_cache.get(str(test_binary_path))

        assert result is not None
        assert result == sample_analysis_result
        assert result["protections"] == ["VMProtect", "Themida"]
        assert result["confidence"] == 95.0

    def test_cache_miss_returns_none(self, analysis_cache: AnalysisCache) -> None:
        result = analysis_cache.get("/nonexistent/file.exe")

        assert result is None

    def test_cache_respects_scan_options_in_key(
        self,
        analysis_cache: AnalysisCache,
        test_binary_path: Path,
    ) -> None:
        result1 = {"scan": "quick"}
        result2 = {"scan": "deep"}

        analysis_cache.put(str(test_binary_path), result1, "quick")
        analysis_cache.put(str(test_binary_path), result2, "deep")

        assert analysis_cache.get(str(test_binary_path), "quick") == result1
        assert analysis_cache.get(str(test_binary_path), "deep") == result2
        assert analysis_cache.get(str(test_binary_path), "") != result1

    def test_cache_invalidates_on_file_modification(
        self,
        analysis_cache: AnalysisCache,
        test_binary_path: Path,
        sample_analysis_result: dict[str, Any],
    ) -> None:
        analysis_cache.put(str(test_binary_path), sample_analysis_result)
        assert analysis_cache.get(str(test_binary_path)) is not None

        time.sleep(0.1)
        test_binary_path.write_bytes(b"MZ\x90\x00" + b"\xFF" * 2048)

        result = analysis_cache.get(str(test_binary_path))
        assert result is None

    def test_cache_tracks_statistics(
        self,
        analysis_cache: AnalysisCache,
        test_binary_path: Path,
    ) -> None:
        analysis_cache.put(str(test_binary_path), {"data": "test"})

        analysis_cache.get(str(test_binary_path))
        analysis_cache.get(str(test_binary_path))
        analysis_cache.get("/nonexistent.exe")

        stats = analysis_cache.get_stats()

        assert stats.cache_hits >= 2
        assert stats.cache_misses >= 1
        assert stats.total_entries >= 1

    def test_cache_evicts_lru_entries_when_full(
        self,
        temp_cache_dir: Path,
    ) -> None:
        cache = AnalysisCache(
            cache_dir=str(temp_cache_dir),
            max_entries=10,
            max_size_mb=1,
            auto_save=False,
        )

        for i in range(20):
            cache.put(f"/file_{i}.exe", {"index": i})
            if i < 10:
                time.sleep(0.01)

        stats = cache.get_stats()
        assert stats.total_entries <= 10

    def test_cache_removes_specific_entries(
        self,
        analysis_cache: AnalysisCache,
        test_binary_path: Path,
    ) -> None:
        analysis_cache.put(str(test_binary_path), {"data": "test"})
        assert analysis_cache.get(str(test_binary_path)) is not None

        removed = analysis_cache.remove(str(test_binary_path))

        assert removed is True
        assert analysis_cache.get(str(test_binary_path)) is None

        removed_again = analysis_cache.remove(str(test_binary_path))
        assert removed_again is False

    def test_cache_clears_all_entries(
        self,
        analysis_cache: AnalysisCache,
        test_binary_path: Path,
    ) -> None:
        for i in range(5):
            analysis_cache.put(f"/file_{i}.exe", {"index": i})

        assert analysis_cache.get_stats().total_entries >= 5

        analysis_cache.clear()

        stats = analysis_cache.get_stats()
        assert stats.total_entries == 0
        assert stats.cache_hits == 0
        assert stats.cache_misses == 0

    def test_cache_cleans_up_invalid_entries(
        self,
        analysis_cache: AnalysisCache,
        tmp_path: Path,
    ) -> None:
        file1 = tmp_path / "file1.exe"
        file2 = tmp_path / "file2.exe"
        file1.write_bytes(b"data1")
        file2.write_bytes(b"data2")

        analysis_cache.put(str(file1), {"data": 1})
        analysis_cache.put(str(file2), {"data": 2})

        file1.unlink()

        removed_count = analysis_cache.cleanup_invalid()

        assert removed_count >= 1
        assert analysis_cache.get(str(file1)) is None
        assert analysis_cache.get(str(file2)) is not None

    def test_cache_persists_to_disk(
        self,
        temp_cache_dir: Path,
        test_binary_path: Path,
    ) -> None:
        cache1 = AnalysisCache(
            cache_dir=str(temp_cache_dir),
            auto_save=False,
        )
        cache1.put(str(test_binary_path), {"persisted": "data"})
        cache1.save_cache()

        cache2 = AnalysisCache(cache_dir=str(temp_cache_dir))

        result = cache2.get(str(test_binary_path))
        assert result is not None
        assert result["persisted"] == "data"

    def test_cache_get_cache_info_returns_detailed_information(
        self,
        analysis_cache: AnalysisCache,
        test_binary_path: Path,
    ) -> None:
        analysis_cache.put(str(test_binary_path), {"data": "test"})
        analysis_cache.get(str(test_binary_path))
        analysis_cache.get(str(test_binary_path))

        info = analysis_cache.get_cache_info()

        assert "stats" in info
        assert "cache_size_mb" in info
        assert "cache_directory" in info
        assert "max_entries" in info
        assert "top_entries" in info
        assert len(info["top_entries"]) > 0

    def test_cache_thread_safety(
        self,
        analysis_cache: AnalysisCache,
        test_binary_path: Path,
    ) -> None:
        def worker(thread_id: int) -> None:
            for i in range(10):
                analysis_cache.put(
                    f"/file_{thread_id}_{i}.exe",
                    {"thread": thread_id, "index": i},
                )
                analysis_cache.get(f"/file_{thread_id}_{i}.exe")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        stats = analysis_cache.get_stats()
        assert stats.total_entries > 0
        assert stats.cache_hits > 0


class TestGlobalCacheInstance:
    def test_get_analysis_cache_returns_singleton(self) -> None:
        cache1 = get_analysis_cache()
        cache2 = get_analysis_cache()

        assert cache1 is cache2

    def test_clear_analysis_cache_resets_global_instance(self) -> None:
        cache1 = get_analysis_cache()
        cache1.put("/test.exe", {"data": "test"})

        clear_analysis_cache()

        cache2 = get_analysis_cache()
        assert cache2 is not cache1
        assert cache2.get("/test.exe") is None


class TestCacheKeyGeneration:
    def test_cache_generates_unique_keys_for_different_files(
        self,
        analysis_cache: AnalysisCache,
    ) -> None:
        key1 = analysis_cache._generate_cache_key("/file1.exe", "")
        key2 = analysis_cache._generate_cache_key("/file2.exe", "")

        assert key1 != key2

    def test_cache_generates_unique_keys_for_different_options(
        self,
        analysis_cache: AnalysisCache,
    ) -> None:
        key1 = analysis_cache._generate_cache_key("/file.exe", "quick")
        key2 = analysis_cache._generate_cache_key("/file.exe", "deep")

        assert key1 != key2

    def test_cache_generates_consistent_keys(
        self,
        analysis_cache: AnalysisCache,
    ) -> None:
        key1 = analysis_cache._generate_cache_key("/file.exe", "options")
        key2 = analysis_cache._generate_cache_key("/file.exe", "options")

        assert key1 == key2


class TestCacheSizeManagement:
    def test_cache_calculates_size_accurately(
        self,
        analysis_cache: AnalysisCache,
    ) -> None:
        large_data = {"data": "x" * 10000}

        analysis_cache.put("/file.exe", large_data)

        size_bytes = analysis_cache._calculate_cache_size()
        assert size_bytes > 10000

        size_mb = analysis_cache._get_cache_size_mb()
        assert size_mb > 0

    def test_cache_evicts_when_size_limit_exceeded(
        self,
        temp_cache_dir: Path,
    ) -> None:
        cache = AnalysisCache(
            cache_dir=str(temp_cache_dir),
            max_entries=1000,
            max_size_mb=1,
            auto_save=False,
        )

        large_data = {"data": "x" * 100000}

        for i in range(20):
            cache.put(f"/file_{i}.exe", large_data)

        size_mb = cache._get_cache_size_mb()
        assert size_mb <= 2.0
