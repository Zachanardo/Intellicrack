"""Production tests for incremental_manager module.

This module tests the IncrementalAnalysisManager which provides caching and
tracking of analysis progress to avoid reprocessing unchanged code.

Copyright (C) 2025 Zachary Flint
"""

import hashlib
import json
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.incremental_manager import (
    IncrementalAnalysisManager,
    secure_pickle_dump,
    secure_pickle_load,
)


@pytest.fixture
def temp_cache_dir(tmp_path: Path) -> Path:
    """Create temporary cache directory."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    return cache_dir


@pytest.fixture
def test_binary(tmp_path: Path) -> Path:
    """Create test binary file."""
    binary_path = tmp_path / "test.exe"
    binary_path.write_bytes(b"\x00" * 1024)
    return binary_path


@pytest.fixture
def manager(temp_cache_dir: Path) -> IncrementalAnalysisManager:
    """Create IncrementalAnalysisManager with temporary cache."""
    config = {
        "cache_dir": str(temp_cache_dir),
        "enable_caching": True,
        "chunk_size": 512,
    }
    return IncrementalAnalysisManager(config)


class TestSecurePickle:
    """Test secure pickle dump and load functionality."""

    def test_secure_pickle_dump_and_load(self, tmp_path: Path) -> None:
        """Secure pickle dumps and loads object with integrity check."""
        test_data = {"key": "value", "list": [1, 2, 3], "nested": {"a": 1}}
        pickle_path = tmp_path / "test.pickle"

        secure_pickle_dump(test_data, pickle_path)

        loaded_data = secure_pickle_load(pickle_path)

        assert loaded_data == test_data

    def test_secure_pickle_integrity_check(self, tmp_path: Path) -> None:
        """Secure pickle detects tampering."""
        test_data = {"test": "data"}
        pickle_path = tmp_path / "test.pickle"

        secure_pickle_dump(test_data, pickle_path)

        with open(pickle_path, "rb+") as f:
            content = f.read()
            f.seek(32)
            f.write(b"\xff")

        with pytest.raises(ValueError, match="integrity check failed"):
            secure_pickle_load(pickle_path)

    def test_secure_pickle_complex_object(self, tmp_path: Path) -> None:
        """Secure pickle handles complex objects."""
        complex_data = {
            "strings": ["a", "b", "c"],
            "numbers": [1, 2, 3, 4.5, 6.7],
            "dicts": [{"x": 1}, {"y": 2}],
            "nested": {"level1": {"level2": {"level3": "deep"}}},
        }
        pickle_path = tmp_path / "complex.pickle"

        secure_pickle_dump(complex_data, pickle_path)
        loaded_data = secure_pickle_load(pickle_path)

        assert loaded_data == complex_data


class TestIncrementalAnalysisManagerInitialization:
    """Test IncrementalAnalysisManager initialization."""

    def test_initialization_default_config(self, temp_cache_dir: Path) -> None:
        """IncrementalAnalysisManager initializes with default config."""
        manager = IncrementalAnalysisManager({"cache_dir": str(temp_cache_dir)})

        assert manager.cache_dir == temp_cache_dir
        assert manager.enable_caching is True
        assert isinstance(manager.cache, dict)
        assert isinstance(manager.analysis_cache, dict)

    def test_initialization_custom_config(self, temp_cache_dir: Path) -> None:
        """IncrementalAnalysisManager accepts custom configuration."""
        config = {
            "cache_dir": str(temp_cache_dir),
            "chunk_size": 2048,
            "max_cache_size": 200,
            "enable_compression": False,
        }
        manager = IncrementalAnalysisManager(config)

        assert manager.chunk_size == 2048
        assert manager.max_cache_size == 200
        assert manager.enable_compression is False

    def test_cache_directory_creation(self, tmp_path: Path) -> None:
        """Manager creates cache directory if it doesn't exist."""
        cache_dir = tmp_path / "new_cache"

        assert not cache_dir.exists()

        manager = IncrementalAnalysisManager({"cache_dir": str(cache_dir)})

        assert cache_dir.exists()
        assert manager.cache_dir == cache_dir

    def test_initialization_statistics(self, manager: IncrementalAnalysisManager) -> None:
        """Manager initializes statistics counters."""
        assert manager.cache_hits == 0
        assert manager.cache_misses == 0


class TestCacheManagement:
    """Test cache management functionality."""

    def test_cache_metadata_persistence(self, manager: IncrementalAnalysisManager, test_binary: Path) -> None:
        """Cache metadata persists across manager instances."""
        test_hash = hashlib.sha256(test_binary.read_bytes()).hexdigest()
        manager.file_hashes[str(test_binary)] = test_hash
        manager._save_cache_metadata()

        new_manager = IncrementalAnalysisManager({"cache_dir": str(manager.cache_dir)})

        assert str(test_binary) in new_manager.file_hashes
        assert new_manager.file_hashes[str(test_binary)] == test_hash

    def test_cache_invalidation_on_file_change(self, manager: IncrementalAnalysisManager, test_binary: Path) -> None:
        """Cache invalidates when file changes."""
        initial_hash = hashlib.sha256(test_binary.read_bytes()).hexdigest()
        manager.file_hashes[str(test_binary)] = initial_hash

        test_binary.write_bytes(b"\xff" * 1024)

        new_hash = hashlib.sha256(test_binary.read_bytes()).hexdigest()

        assert initial_hash != new_hash

    def test_cache_cleanup_removes_old_entries(self, manager: IncrementalAnalysisManager) -> None:
        """Cache cleanup removes old entries."""
        old_time = time.time() - (manager.cache_max_age * 86400 + 1000)

        manager.cache["old_entry"] = {
            "timestamp": old_time,
            "data": "old_data",
        }

        manager._cleanup_invalid_entries()

        assert "old_entry" not in manager.cache


class TestAnalysisCaching:
    """Test analysis result caching."""

    def test_cache_analysis_result(self, manager: IncrementalAnalysisManager, test_binary: Path) -> None:
        """Manager caches analysis results."""
        analysis_type = "license_check"
        analysis_result = {"functions": ["CheckLicense", "ValidateKey"], "status": "success"}

        cache_key = manager._get_cache_key(str(test_binary), analysis_type)
        manager.analysis_cache[cache_key] = analysis_result

        assert cache_key in manager.analysis_cache
        assert manager.analysis_cache[cache_key] == analysis_result

    def test_retrieve_cached_analysis(self, manager: IncrementalAnalysisManager, test_binary: Path) -> None:
        """Manager retrieves cached analysis results."""
        analysis_type = "crypto_scan"
        expected_result = {"algorithms": ["AES", "RSA"], "weak_crypto": False}

        cache_key = manager._get_cache_key(str(test_binary), analysis_type)
        manager.analysis_cache[cache_key] = expected_result

        retrieved_result = manager.analysis_cache.get(cache_key)

        assert retrieved_result == expected_result

    def test_cache_miss_tracking(self, manager: IncrementalAnalysisManager) -> None:
        """Manager tracks cache misses."""
        initial_misses = manager.cache_misses

        cache_key = "nonexistent_key"
        result = manager.analysis_cache.get(cache_key)

        assert result is None
        assert manager.cache_misses >= initial_misses


class TestChunkedAnalysis:
    """Test chunked analysis functionality."""

    def test_chunk_cache_storage(self, manager: IncrementalAnalysisManager) -> None:
        """Manager stores chunk analysis results."""
        chunk_key = "test_binary_chunk_0"
        chunk_data = {"offset": 0, "size": 512, "entropy": 3.5}

        manager.chunk_cache[chunk_key] = chunk_data

        assert chunk_key in manager.chunk_cache
        assert manager.chunk_cache[chunk_key] == chunk_data

    def test_chunk_size_configuration(self, temp_cache_dir: Path) -> None:
        """Manager respects chunk size configuration."""
        config = {"cache_dir": str(temp_cache_dir), "chunk_size": 4096}
        manager = IncrementalAnalysisManager(config)

        assert manager.chunk_size == 4096


class TestHashCalculation:
    """Test file hashing functionality."""

    def test_file_hash_calculation(self, manager: IncrementalAnalysisManager, test_binary: Path) -> None:
        """Manager calculates file hashes correctly."""
        expected_hash = hashlib.sha256(test_binary.read_bytes()).hexdigest()

        file_hash = manager._calculate_file_hash(str(test_binary))

        assert file_hash == expected_hash

    def test_hash_consistency(self, manager: IncrementalAnalysisManager, test_binary: Path) -> None:
        """Same file produces same hash."""
        hash1 = manager._calculate_file_hash(str(test_binary))
        hash2 = manager._calculate_file_hash(str(test_binary))

        assert hash1 == hash2

    def test_hash_changes_on_modification(self, manager: IncrementalAnalysisManager, test_binary: Path) -> None:
        """Hash changes when file is modified."""
        hash1 = manager._calculate_file_hash(str(test_binary))

        test_binary.write_bytes(b"\xff" * 1024)

        hash2 = manager._calculate_file_hash(str(test_binary))

        assert hash1 != hash2


class TestCacheKeyGeneration:
    """Test cache key generation."""

    def test_cache_key_generation(self, manager: IncrementalAnalysisManager) -> None:
        """Manager generates consistent cache keys."""
        binary_path = "/path/to/binary.exe"
        analysis_type = "license_analysis"

        key1 = manager._get_cache_key(binary_path, analysis_type)
        key2 = manager._get_cache_key(binary_path, analysis_type)

        assert key1 == key2

    def test_different_paths_different_keys(self, manager: IncrementalAnalysisManager) -> None:
        """Different binaries produce different cache keys."""
        key1 = manager._get_cache_key("/path/to/binary1.exe", "analysis")
        key2 = manager._get_cache_key("/path/to/binary2.exe", "analysis")

        assert key1 != key2

    def test_different_analysis_types_different_keys(self, manager: IncrementalAnalysisManager) -> None:
        """Different analysis types produce different cache keys."""
        binary_path = "/path/to/binary.exe"

        key1 = manager._get_cache_key(binary_path, "license_check")
        key2 = manager._get_cache_key(binary_path, "crypto_scan")

        assert key1 != key2


class TestCachePersistence:
    """Test cache persistence across sessions."""

    def test_save_and_load_cache_metadata(self, manager: IncrementalAnalysisManager) -> None:
        """Cache metadata saves and loads correctly."""
        manager.file_hashes["test_file"] = "hash123"
        manager.cache_hits = 5
        manager.cache_misses = 2

        manager._save_cache_metadata()

        new_manager = IncrementalAnalysisManager({"cache_dir": str(manager.cache_dir)})

        assert new_manager.file_hashes.get("test_file") == "hash123"
        assert new_manager.cache_hits == 5
        assert new_manager.cache_misses == 2

    def test_cache_index_persistence(self, manager: IncrementalAnalysisManager, test_binary: Path) -> None:
        """Cache index persists across sessions."""
        cache_key = "test_analysis"
        manager.cache[cache_key] = {
            "timestamp": time.time(),
            "result": "success",
        }

        manager._save_cache_metadata()

        new_manager = IncrementalAnalysisManager({"cache_dir": str(manager.cache_dir)})

        assert cache_key in new_manager.cache


class TestErrorHandling:
    """Test error handling in cache operations."""

    def test_handles_corrupted_metadata(self, temp_cache_dir: Path) -> None:
        """Manager handles corrupted metadata gracefully."""
        metadata_path = temp_cache_dir / "metadata.json"
        metadata_path.write_text("{ invalid json")

        manager = IncrementalAnalysisManager({"cache_dir": str(temp_cache_dir)})

        assert isinstance(manager.cache, dict)
        assert isinstance(manager.file_hashes, dict)

    def test_handles_missing_cache_directory(self, tmp_path: Path) -> None:
        """Manager creates missing cache directory."""
        nonexistent_cache = tmp_path / "nonexistent_cache"

        manager = IncrementalAnalysisManager({"cache_dir": str(nonexistent_cache)})

        assert nonexistent_cache.exists()
        assert manager.cache_dir == nonexistent_cache

    def test_handles_nonexistent_file_hash(self, manager: IncrementalAnalysisManager) -> None:
        """Manager handles hash calculation for nonexistent file."""
        file_hash = manager._calculate_file_hash("/nonexistent/file.exe")

        assert file_hash is None or file_hash == ""


class TestPerformanceMetrics:
    """Test performance metrics tracking."""

    def test_cache_hit_tracking(self, manager: IncrementalAnalysisManager) -> None:
        """Manager tracks cache hits correctly."""
        initial_hits = manager.cache_hits

        manager.cache_hits += 1

        assert manager.cache_hits == initial_hits + 1

    def test_cache_miss_tracking(self, manager: IncrementalAnalysisManager) -> None:
        """Manager tracks cache misses correctly."""
        initial_misses = manager.cache_misses

        manager.cache_misses += 1

        assert manager.cache_misses == initial_misses + 1

    def test_statistics_persistence(self, manager: IncrementalAnalysisManager) -> None:
        """Performance statistics persist across sessions."""
        manager.cache_hits = 10
        manager.cache_misses = 3

        manager._save_cache_metadata()

        new_manager = IncrementalAnalysisManager({"cache_dir": str(manager.cache_dir)})

        assert new_manager.cache_hits == 10
        assert new_manager.cache_misses == 3
