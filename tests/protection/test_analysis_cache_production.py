"""Production tests for analysis cache.

Tests validate real caching of analysis results.
Tests verify cache storage, retrieval, and invalidation.
"""

import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.protection.analysis_cache import AnalysisCache


class TestAnalysisCacheInitialization:
    """Test cache initialization."""

    def test_create_analysis_cache(self) -> None:
        """Create analysis cache instance."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(cache_dir=tmpdir)

            assert cache is not None
            assert Path(tmpdir).exists()

    def test_cache_directory_created(self) -> None:
        """Verify cache directory is created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / "cache"
            cache = AnalysisCache(cache_dir=str(cache_path))

            assert cache_path.exists()


class TestCacheStorage:
    """Test cache storage operations."""

    def test_store_analysis_result(self) -> None:
        """Store analysis result in cache."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(cache_dir=tmpdir)

            result = {
                "protection": "VMProtect",
                "version": "3.5",
                "sections": ["UPX0", "UPX1"],
            }

            cache.store("test_binary.exe", "protection_scan", result)

            assert cache.has("test_binary.exe", "protection_scan")

    def test_store_multiple_results(self) -> None:
        """Store multiple analysis results."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(cache_dir=tmpdir)

            cache.store("binary1.exe", "protection", {"protection": "VMProtect"})
            cache.store("binary2.exe", "protection", {"protection": "Themida"})

            assert cache.has("binary1.exe", "protection")
            assert cache.has("binary2.exe", "protection")

    def test_store_large_result(self) -> None:
        """Store large analysis result."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(cache_dir=tmpdir)

            result = {"data": [i for i in range(10000)]}

            cache.store("large_binary.exe", "detailed_scan", result)

            assert cache.has("large_binary.exe", "detailed_scan")


class TestCacheRetrieval:
    """Test cache retrieval operations."""

    def test_retrieve_stored_result(self) -> None:
        """Retrieve previously stored result."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(cache_dir=tmpdir)

            original = {"protection": "VMProtect", "version": "3.5"}
            cache.store("test.exe", "scan", original)

            retrieved = cache.get("test.exe", "scan")

            assert retrieved == original

    def test_retrieve_nonexistent_result(self) -> None:
        """Retrieve nonexistent cache entry."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(cache_dir=tmpdir)

            result = cache.get("nonexistent.exe", "scan")

            assert result is None

    def test_retrieve_with_default(self) -> None:
        """Retrieve with default value."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(cache_dir=tmpdir)

            default = {"protection": "Unknown"}
            result = cache.get("nonexistent.exe", "scan", default=default)

            assert result == default


class TestCacheInvalidation:
    """Test cache invalidation."""

    def test_invalidate_single_entry(self) -> None:
        """Invalidate single cache entry."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(cache_dir=tmpdir)

            cache.store("test.exe", "scan", {"data": "value"})
            assert cache.has("test.exe", "scan")

            cache.invalidate("test.exe", "scan")

            assert not cache.has("test.exe", "scan")

    def test_invalidate_all_for_binary(self) -> None:
        """Invalidate all entries for a binary."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(cache_dir=tmpdir)

            cache.store("test.exe", "scan1", {"data": "value1"})
            cache.store("test.exe", "scan2", {"data": "value2"})

            cache.invalidate_all("test.exe")

            assert not cache.has("test.exe", "scan1")
            assert not cache.has("test.exe", "scan2")

    def test_clear_entire_cache(self) -> None:
        """Clear entire cache."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(cache_dir=tmpdir)

            cache.store("binary1.exe", "scan", {"data": "1"})
            cache.store("binary2.exe", "scan", {"data": "2"})

            cache.clear()

            assert not cache.has("binary1.exe", "scan")
            assert not cache.has("binary2.exe", "scan")


class TestCacheExpiration:
    """Test cache expiration."""

    def test_set_expiration_time(self) -> None:
        """Set cache entry expiration."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(cache_dir=tmpdir)

            cache.store("test.exe", "scan", {"data": "value"}, ttl=3600)

            assert cache.has("test.exe", "scan")

    def test_expired_entry_not_returned(self) -> None:
        """Expired entries are not returned."""
        import time

        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(cache_dir=tmpdir)

            cache.store("test.exe", "scan", {"data": "value"}, ttl=1)

            time.sleep(2)
            result = cache.get("test.exe", "scan")

            assert result is None


class TestCachePersistence:
    """Test cache persistence across instances."""

    def test_cache_persists_across_instances(self) -> None:
        """Cache persists when creating new instance."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache1 = AnalysisCache(cache_dir=tmpdir)
            cache1.store("test.exe", "scan", {"data": "value"})

            cache2 = AnalysisCache(cache_dir=tmpdir)
            result = cache2.get("test.exe", "scan")

            assert result == {"data": "value"}


class TestCacheStatistics:
    """Test cache statistics."""

    def test_get_cache_size(self) -> None:
        """Get total cache size."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(cache_dir=tmpdir)

            cache.store("test1.exe", "scan", {"data": "value1"})
            cache.store("test2.exe", "scan", {"data": "value2"})

            size = cache.get_size()

            assert isinstance(size, int)
            assert size >= 0

    def test_get_entry_count(self) -> None:
        """Get number of cache entries."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(cache_dir=tmpdir)

            cache.store("test1.exe", "scan", {"data": "1"})
            cache.store("test2.exe", "scan", {"data": "2"})

            count = cache.get_count()

            assert count >= 2


class TestEdgeCases:
    """Test edge cases."""

    def test_store_none_value(self) -> None:
        """Store None as cache value."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(cache_dir=tmpdir)

            with pytest.raises((ValueError, TypeError)):
                cache.store("test.exe", "scan", None)

    def test_store_empty_dict(self) -> None:
        """Store empty dictionary."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(cache_dir=tmpdir)

            cache.store("test.exe", "scan", {})

            result = cache.get("test.exe", "scan")

            assert result == {}


class TestPerformance:
    """Test cache performance."""

    def test_bulk_storage_performance(self, benchmark: Any) -> None:
        """Benchmark bulk cache storage."""
        with tempfile.TemporaryDirectory() as tmpdir:
            def store_many() -> int:
                cache = AnalysisCache(cache_dir=tmpdir)
                for i in range(100):
                    cache.store(f"binary{i}.exe", "scan", {"index": i})
                return cache.get_count()

            result = benchmark(store_many)

            assert result >= 100

    def test_bulk_retrieval_performance(self, benchmark: Any) -> None:
        """Benchmark bulk cache retrieval."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(cache_dir=tmpdir)
            for i in range(100):
                cache.store(f"binary{i}.exe", "scan", {"index": i})

            def retrieve_many() -> int:
                count = 0
                for i in range(100):
                    if cache.get(f"binary{i}.exe", "scan"):
                        count += 1
                return count

            result = benchmark(retrieve_many)

            assert result == 100
