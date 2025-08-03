"""Advanced Analysis Cache for Protection Engine

Provides efficient caching with persistence, size management, and automatic invalidation.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import json
import logging
import os
import pickle
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Lock
from typing import Any

from ..utils.logger import get_logger

logger = get_logger(__name__)

import hmac

# Security configuration for pickle
PICKLE_SECURITY_KEY = os.environ.get("INTELLICRACK_PICKLE_KEY", "default-key-change-me").encode()
class RestrictedUnpickler(pickle.Unpickler):
    """Restricted unpickler that only allows safe classes."""

    def find_class(self, module, name):
        """Override find_class to restrict allowed classes."""
        # Allow only safe modules and classes
        ALLOWED_MODULES = {
            "numpy", "numpy.core.multiarray", "numpy.core.numeric",
            "pandas", "pandas.core.frame", "pandas.core.series",
            "sklearn", "torch", "tensorflow",
            "__builtin__", "builtins",
            "collections", "collections.abc",
            "datetime",
        }

        # Allow model classes from our own modules
        if module.startswith("intellicrack."):
            return super().find_class(module, name)

        # Check if module is in allowed list
        if any(module.startswith(allowed) for allowed in ALLOWED_MODULES):
            return super().find_class(module, name)

        # Deny everything else
        raise pickle.UnpicklingError(f"Attempted to load unsafe class {module}.{name}")

def secure_pickle_dump(obj, file_path):
    """Securely dump object with integrity check."""
    # Serialize object
    data = pickle.dumps(obj)

    # Calculate HMAC for integrity
    mac = hmac.new(PICKLE_SECURITY_KEY, data, hashlib.sha256).digest()

    # Write MAC + data
    with open(file_path, "wb") as f:
        f.write(mac)
        f.write(data)

def secure_pickle_load(file_path):
    """Securely load object with integrity verification."""
    try:
        # Try joblib first as it's safer for ML models
        import joblib
        return joblib.load(file_path)
    except (ImportError, ValueError):
        # Fallback to pickle with restricted unpickler
        pass

    with open(file_path, "rb") as f:
        # Read MAC
        stored_mac = f.read(32)  # SHA256 produces 32 bytes
        data = f.read()

    # Verify integrity
    expected_mac = hmac.new(PICKLE_SECURITY_KEY, data, hashlib.sha256).digest()
    if not hmac.compare_digest(stored_mac, expected_mac):
        raise ValueError("Pickle file integrity check failed - possible tampering detected")

    # Load object using RestrictedUnpickler
    import io
    return RestrictedUnpickler(io.BytesIO(data)).load()


@dataclass
class CacheEntry:
    """Single cache entry with metadata"""

    data: Any
    timestamp: float
    file_mtime: float
    file_size: int
    access_count: int = 0
    last_access: float = 0.0
    cache_key: str = ""

    def __post_init__(self):
        """Initialize logger after dataclass initialization"""
        self.logger = logging.getLogger(__name__ + ".CacheEntry")

    def is_valid(self, file_path: str) -> bool:
        """Check if cache entry is still valid"""
        try:
            if not os.path.exists(file_path):
                return False

            # Check file modification time
            current_mtime = os.path.getmtime(file_path)
            if current_mtime > self.file_mtime:
                return False

            # Check file size
            current_size = os.path.getsize(file_path)
            if current_size != self.file_size:
                return False

            return True
        except Exception as e:
            self.logger.error("Exception in analysis_cache: %s", e)
            return False

    def update_access(self):
        """Update access statistics"""
        self.access_count += 1
        self.last_access = time.time()


@dataclass
class CacheStats:
    """Cache statistics"""

    total_entries: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    cache_invalidations: int = 0
    total_size_bytes: int = 0
    oldest_entry: float = 0.0
    newest_entry: float = 0.0

    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate"""
        total = self.cache_hits + self.cache_misses
        return (self.cache_hits / total * 100) if total > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


class AnalysisCache:
    """Advanced cache for protection analysis results

    Features:
    - Persistent storage to disk
    - Size-based eviction (LRU)
    - Automatic cache invalidation based on file changes
    - Cache statistics and monitoring
    - Thread-safe operations
    """

    def __init__(
        self,
        cache_dir: str | None = None,
        max_entries: int = 1000,
        max_size_mb: int = 100,
        auto_save: bool = True,
    ):
        """Initialize cache

        Args:
            cache_dir: Directory for persistent cache storage
            max_entries: Maximum number of cache entries
            max_size_mb: Maximum cache size in MB
            auto_save: Automatically save cache to disk

        """
        # Set up cache directory
        if cache_dir is None:
            cache_dir = Path.home() / ".intellicrack" / "cache"

        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Cache settings
        self.max_entries = max_entries
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.auto_save = auto_save

        # Cache storage
        self._cache: dict[str, CacheEntry] = {}
        self._lock = Lock()

        # Statistics
        self._stats = CacheStats()

        # Cache files
        self.cache_file = self.cache_dir / "analysis_cache.pkl"
        self.stats_file = self.cache_dir / "cache_stats.json"

        # Load existing cache
        self._load_cache()

        logger.info(f"Analysis cache initialized: {len(self._cache)} entries, "
                   f"{self._get_cache_size_mb():.1f}MB")

    def get(self, file_path: str, scan_options: str = "") -> Any | None:
        """Get cached analysis result

        Args:
            file_path: Path to analyzed file
            scan_options: Additional scan options for cache key

        Returns:
            Cached result or None if not found/invalid

        """
        cache_key = self._generate_cache_key(file_path, scan_options)

        with self._lock:
            entry = self._cache.get(cache_key)

            if entry is None:
                self._stats.cache_misses += 1
                logger.debug(f"Cache miss: {cache_key}")
                return None

            # Validate cache entry
            if not entry.is_valid(file_path):
                logger.debug(f"Cache invalidated: {cache_key}")
                del self._cache[cache_key]
                self._stats.cache_invalidations += 1
                self._stats.cache_misses += 1
                return None

            # Update access statistics
            entry.update_access()
            self._stats.cache_hits += 1

            logger.debug(f"Cache hit: {cache_key}")
            return entry.data

    def put(self, file_path: str, data: Any, scan_options: str = "") -> None:
        """Store analysis result in cache

        Args:
            file_path: Path to analyzed file
            data: Analysis result to cache
            scan_options: Additional scan options for cache key

        """
        cache_key = self._generate_cache_key(file_path, scan_options)

        try:
            # Get file metadata
            file_mtime = os.path.getmtime(file_path)
            file_size = os.path.getsize(file_path)

            entry = CacheEntry(
                data=data,
                timestamp=time.time(),
                file_mtime=file_mtime,
                file_size=file_size,
                cache_key=cache_key,
            )

            with self._lock:
                # Check if we need to evict entries
                self._evict_if_needed()

                # Store entry
                self._cache[cache_key] = entry
                self._stats.total_entries = len(self._cache)

                # Update stats
                if not self._stats.oldest_entry or entry.timestamp < self._stats.oldest_entry:
                    self._stats.oldest_entry = entry.timestamp
                self._stats.newest_entry = max(self._stats.newest_entry, entry.timestamp)

                logger.debug(f"Cached: {cache_key}")

                # Auto-save if enabled
                if self.auto_save:
                    self._save_cache_async()

        except Exception as e:
            logger.error(f"Failed to cache result for {file_path}: {e}")

    def remove(self, file_path: str, scan_options: str = "") -> bool:
        """Remove specific entry from cache

        Args:
            file_path: Path to analyzed file
            scan_options: Additional scan options for cache key

        Returns:
            True if entry was removed, False if not found

        """
        cache_key = self._generate_cache_key(file_path, scan_options)

        with self._lock:
            if cache_key in self._cache:
                del self._cache[cache_key]
                self._stats.total_entries = len(self._cache)
                logger.debug(f"Removed from cache: {cache_key}")
                return True
            return False

    def clear(self) -> None:
        """Clear all cache entries"""
        with self._lock:
            self._cache.clear()
            self._stats = CacheStats()
            logger.info("Cache cleared")

            # Remove cache files
            try:
                if self.cache_file.exists():
                    self.cache_file.unlink()
                if self.stats_file.exists():
                    self.stats_file.unlink()
            except Exception as e:
                logger.error(f"Failed to remove cache files: {e}")

    def cleanup_invalid(self) -> int:
        """Remove invalid cache entries

        Returns:
            Number of entries removed

        """
        removed_count = 0

        with self._lock:
            invalid_keys = []

            for cache_key, entry in self._cache.items():
                # Extract file path from cache key
                file_path = cache_key.split(":")[0]
                if not entry.is_valid(file_path):
                    invalid_keys.append(cache_key)

            for key in invalid_keys:
                del self._cache[key]
                removed_count += 1

            self._stats.total_entries = len(self._cache)
            self._stats.cache_invalidations += removed_count

        if removed_count > 0:
            logger.info(f"Cleaned up {removed_count} invalid cache entries")

        return removed_count

    def get_stats(self) -> CacheStats:
        """Get cache statistics"""
        with self._lock:
            self._stats.total_entries = len(self._cache)
            self._stats.total_size_bytes = self._calculate_cache_size()
            return self._stats

    def get_cache_info(self) -> dict[str, Any]:
        """Get detailed cache information"""
        stats = self.get_stats()

        with self._lock:
            # Get most accessed entries
            sorted_entries = sorted(
                self._cache.items(),
                key=lambda x: x[1].access_count,
                reverse=True,
            )

            top_entries = []
            for cache_key, entry in sorted_entries[:5]:
                file_path = cache_key.split(":")[0]
                top_entries.append({
                    "file": os.path.basename(file_path),
                    "access_count": entry.access_count,
                    "size_kb": len(str(entry.data)) / 1024,
                    "age_hours": (time.time() - entry.timestamp) / 3600,
                })

        return {
            "stats": stats.to_dict(),
            "cache_size_mb": self._get_cache_size_mb(),
            "cache_directory": str(self.cache_dir),
            "max_entries": self.max_entries,
            "max_size_mb": self.max_size_bytes / (1024 * 1024),
            "top_entries": top_entries,
        }

    def save_cache(self) -> None:
        """Manually save cache to disk"""
        try:
            with self._lock:
                # Save cache data
                secure_pickle_dump(self._cache, self.cache_file)

                # Save statistics
                with open(self.stats_file, "w") as f:
                    json.dump(self._stats.to_dict(), f, indent=2)

                logger.debug(f"Cache saved: {len(self._cache)} entries")

        except Exception as e:
            logger.error(f"Failed to save cache: {e}")

    def _generate_cache_key(self, file_path: str, scan_options: str) -> str:
        """Generate cache key from file path and options"""
        # Use file path + scan options hash for key
        key_data = f"{file_path}:{scan_options}"
        key_hash = hashlib.md5(key_data.encode()).hexdigest()[:16]
        return f"{file_path}:{key_hash}"

    def _evict_if_needed(self) -> None:
        """Evict entries if cache is too large"""
        # Check entry count limit
        if len(self._cache) >= self.max_entries:
            self._evict_lru_entries(self.max_entries // 4)  # Remove 25%

        # Check size limit
        current_size = self._calculate_cache_size()
        if current_size > self.max_size_bytes:
            self._evict_lru_entries(len(self._cache) // 4)  # Remove 25%

    def _evict_lru_entries(self, count: int) -> None:
        """Evict least recently used entries"""
        if not self._cache:
            return

        # Sort by last access time (least recent first)
        sorted_entries = sorted(
            self._cache.items(),
            key=lambda x: x[1].last_access or x[1].timestamp,
        )

        # Remove oldest entries
        for i in range(min(count, len(sorted_entries))):
            cache_key = sorted_entries[i][0]
            del self._cache[cache_key]
            logger.debug(f"Evicted LRU entry: {cache_key}")

    def _calculate_cache_size(self) -> int:
        """Calculate total cache size in bytes"""
        total_size = 0
        for entry in self._cache.values():
            try:
                # Rough estimate using pickle size
                total_size += len(pickle.dumps(entry.data))
            except:
                # Fallback estimate
                total_size += len(str(entry.data)) * 2
        return total_size

    def _get_cache_size_mb(self) -> float:
        """Get cache size in MB"""
        return self._calculate_cache_size() / (1024 * 1024)

    def _load_cache(self) -> None:
        """Load cache from disk"""
        try:
            # Load cache data
            if self.cache_file.exists():
                self._cache = secure_pickle_load(self.cache_file)
                logger.info(f"Loaded cache: {len(self._cache)} entries")

            # Load statistics
            if self.stats_file.exists():
                with open(self.stats_file) as f:
                    stats_data = json.load(f)
                    self._stats = CacheStats(**stats_data)

        except Exception as e:
            logger.warning(f"Failed to load cache: {e}")
            self._cache = {}
            self._stats = CacheStats()

    def _save_cache_async(self) -> None:
        """Save cache asynchronously (non-blocking)"""
        import threading

        def save_worker():
            try:
                self.save_cache()
            except Exception as e:
                logger.error(f"Async cache save failed: {e}")

        thread = threading.Thread(target=save_worker, daemon=True)
        thread.start()


# Global cache instance
_analysis_cache: AnalysisCache | None = None


def get_analysis_cache() -> AnalysisCache:
    """Get or create global analysis cache instance"""
    global _analysis_cache
    if _analysis_cache is None:
        _analysis_cache = AnalysisCache()
    return _analysis_cache


def clear_analysis_cache() -> None:
    """Clear global analysis cache"""
    global _analysis_cache
    if _analysis_cache:
        _analysis_cache.clear()
        _analysis_cache = None
