"""
Large File Optimization for Hex Viewer.

This module provides enhanced file handling capabilities for very large files,
including memory mapping strategies, streaming access, and progressive loading.
"""

import logging
import mmap
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

# Optional psutil for system monitoring
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None

try:
    from PyQt5.QtCore import QObject, QThread, QTimer, pyqtSignal
    PYQT5_AVAILABLE = True
except ImportError:
    PYQT5_AVAILABLE = False
    QObject = object
    QThread = object

logger = logging.getLogger(__name__)

__all__ = [
    'LargeFileHandler', 'MemoryStrategy', 'LoadingStrategy',
    'FileCache', 'MemoryMonitor', 'BackgroundLoader'
]


class MemoryStrategy(Enum):
    """Memory mapping strategies for different file sizes."""
    DIRECT_LOAD = "direct_load"        # < 100MB: Load entirely into memory
    MEMORY_MAP = "memory_map"          # 100MB - 1GB: Use memory mapping
    STREAMING = "streaming"            # > 1GB: Stream with minimal memory
    HYBRID = "hybrid"                  # Adaptive strategy


class LoadingStrategy(Enum):
    """File loading strategies."""
    IMMEDIATE = "immediate"            # Load everything immediately
    PROGRESSIVE = "progressive"        # Load sections as needed
    BACKGROUND = "background"          # Load in background thread
    ON_DEMAND = "on_demand"           # Load only when requested


@dataclass
class MemoryConfig:
    """Configuration for memory usage."""
    max_memory_mb: int = 500           # Maximum memory usage in MB
    chunk_size_mb: int = 10            # Chunk size in MB
    cache_size_mb: int = 100           # Cache size in MB
    memory_threshold: float = 0.8      # Memory usage threshold (80%)
    enable_compression: bool = False    # Enable chunk compression
    prefetch_chunks: int = 2           # Number of chunks to prefetch


@dataclass
class FileRegion:
    """Represents a region of a file."""
    offset: int
    size: int
    data: Optional[bytes] = None
    last_accessed: float = 0.0
    ref_count: int = 0
    compressed: bool = False


class FileCache:
    """LRU cache for file regions with memory management."""

    def __init__(self, config: MemoryConfig):
        self.config = config
        self.regions: OrderedDict[int, FileRegion] = OrderedDict()
        self.total_memory = 0
        self.lock = threading.RLock()

    def get_region(self, offset: int, size: int) -> Optional[FileRegion]:
        """Get a cached region containing the requested data."""
        with self.lock:
            # Check if we have a region that contains this data
            for region_offset, region in self.regions.items():
                if (region_offset <= offset and
                    region_offset + region.size >= offset + size):
                    # Move to end (most recently used)
                    self.regions.move_to_end(region_offset)
                    region.last_accessed = time.time()
                    region.ref_count += 1
                    return region
            return None

    def add_region(self, region: FileRegion) -> bool:
        """Add a region to the cache."""
        with self.lock:
            # Check if we have enough memory
            region_size = len(region.data) if region.data else 0
            max_bytes = self.config.cache_size_mb * 1024 * 1024

            # Evict old regions if necessary
            while (self.total_memory + region_size > max_bytes and
                   len(self.regions) > 0):
                self._evict_oldest()

            # Add the new region
            self.regions[region.offset] = region
            self.total_memory += region_size
            region.last_accessed = time.time()
            region.ref_count = 1

            logger.debug(f"Cached region: offset=0x{region.offset:X}, size={region.size}, "
                        f"total_memory={self.total_memory / (1024*1024):.1f}MB")
            return True

    def _evict_oldest(self):
        """Evict the oldest region from cache."""
        if not self.regions:
            return

        # Find region with lowest reference count and oldest access time
        oldest_key = None
        oldest_time = float('inf')

        for key, region in self.regions.items():
            if region.ref_count == 0 and region.last_accessed < oldest_time:
                oldest_time = region.last_accessed
                oldest_key = key

        # If no unreferenced regions, evict the oldest one anyway
        if oldest_key is None:
            oldest_key = next(iter(self.regions))

        # Remove the region
        region = self.regions.pop(oldest_key)
        region_size = len(region.data) if region.data else 0
        self.total_memory -= region_size

        logger.debug("Evicted region: offset=0x%s, size=%s", region.offset, region.size)

    def release_region(self, region: FileRegion):
        """Release a reference to a region."""
        with self.lock:
            region.ref_count = max(0, region.ref_count - 1)

    def clear(self):
        """Clear all cached regions."""
        with self.lock:
            self.regions.clear()
            self.total_memory = 0

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self.lock:
            return {
                'regions': len(self.regions),
                'total_memory_mb': self.total_memory / (1024 * 1024),
                'max_memory_mb': self.config.cache_size_mb,
                'utilization': self.total_memory / (self.config.cache_size_mb * 1024 * 1024)
            }


class MemoryMonitor:
    """Monitors system memory usage and adjusts caching strategy."""

    def __init__(self, config: MemoryConfig):
        self.config = config
        self.callbacks: List[Callable[[float], None]] = []
        self.monitoring = False
        self.thread: Optional[threading.Thread] = None

    def add_callback(self, callback: Callable[[float], None]):
        """Add a callback for memory usage changes."""
        self.callbacks.append(callback)

    def start_monitoring(self):
        """Start memory monitoring in background thread."""
        if self.monitoring:
            return

        self.monitoring = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.debug("Memory monitoring started")

    def stop_monitoring(self):
        """Stop memory monitoring."""
        self.monitoring = False
        if self.thread:
            self.thread.join(timeout=1.0)
        logger.debug("Memory monitoring stopped")

    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.monitoring:
            try:
                if PSUTIL_AVAILABLE:
                    # Get current memory usage
                    process = psutil.Process()
                    memory_info = process.memory_info()
                    memory_mb = memory_info.rss / (1024 * 1024)

                    # Get system memory
                    system_memory = psutil.virtual_memory()
                    memory_percent = system_memory.percent / 100.0

                    # Check if we exceed thresholds
                    if memory_percent > self.config.memory_threshold:
                        logger.warning("High system memory usage: %s", memory_percent)

                    # Notify callbacks
                    for callback in self.callbacks:
                        try:
                            callback(memory_percent)
                        except Exception as e:
                            logger.error("Memory monitor callback error: %s", e)
                else:
                    # Fallback: use basic estimation
                    memory_percent = 0.5  # Assume 50% usage without psutil
                    for callback in self.callbacks:
                        try:
                            callback(memory_percent)
                        except Exception as e:
                            logger.error("Memory monitor callback error: %s", e)

                time.sleep(1.0)  # Check every second

            except Exception as e:
                logger.error("Memory monitoring error: %s", e)
                time.sleep(5.0)  # Wait longer on error


class BackgroundLoader(QThread if PYQT5_AVAILABLE else threading.Thread):
    """Background thread for loading file data."""

    # Signals for Qt integration
    progress_updated = pyqtSignal(int) if PYQT5_AVAILABLE else None
    region_loaded = pyqtSignal(object) if PYQT5_AVAILABLE else None
    error_occurred = pyqtSignal(str) if PYQT5_AVAILABLE else None

    def __init__(self, file_path: str, cache: FileCache, config: MemoryConfig):
        if PYQT5_AVAILABLE:
            super().__init__()
        else:
            super().__init__(daemon=True)

        self.file_path = file_path
        self.cache = cache
        self.config = config
        self.load_queue: List[Tuple[int, int]] = []
        self.queue_lock = threading.Lock()
        self.should_stop = False

    def queue_load(self, offset: int, size: int):
        """Queue a region for loading."""
        with self.queue_lock:
            # Avoid duplicate requests
            request = (offset, size)
            if request not in self.load_queue:
                self.load_queue.append(request)
                logger.debug("Queued load: offset=0x%s, size=%s", offset, size)

    def run(self):
        """Main loading loop."""
        try:
            with open(self.file_path, 'rb') as file:
                while not self.should_stop:
                    # Get next load request
                    with self.queue_lock:
                        if not self.load_queue:
                            time.sleep(0.1)
                            continue
                        offset, size = self.load_queue.pop(0)

                    # Load the data
                    try:
                        file.seek(offset)
                        data = file.read(size)

                        if data:
                            region = FileRegion(offset=offset, size=len(data), data=data)
                            self.cache.add_region(region)

                            if self.region_loaded:
                                self.region_loaded.emit(region)

                            logger.debug(f"Background loaded: offset=0x{offset:X}, size={len(data)}")

                    except Exception as e:
                        logger.error("Background load error: %s", e)
                        if self.error_occurred:
                            self.error_occurred.emit(str(e))

                    # Small delay to avoid overwhelming the system
                    time.sleep(0.01)

        except Exception as e:
            logger.error("Background loader thread error: %s", e)
            if self.error_occurred:
                self.error_occurred.emit(str(e))

    def stop(self):
        """Stop the background loader."""
        self.should_stop = True


class LargeFileHandler:
    """Enhanced file handler optimized for large files."""

    def __init__(self, file_path: str, read_only: bool = True, config: Optional[MemoryConfig] = None):
        self.file_path = file_path
        self.read_only = read_only
        self.config = config or MemoryConfig()

        # Initialize components
        self.cache = FileCache(self.config)
        self.memory_monitor = MemoryMonitor(self.config)
        self.background_loader: Optional[BackgroundLoader] = None

        # File information
        self.file_size = 0
        self.memory_strategy = MemoryStrategy.HYBRID
        self.loading_strategy = LoadingStrategy.PROGRESSIVE

        # Memory mapped file (for medium-sized files)
        self.mmap_file: Optional[mmap.mmap] = None
        self.file_handle: Optional[object] = None

        # Performance tracking
        self.access_patterns: List[Tuple[int, int, float]] = []  # offset, size, timestamp

        # Initialize the file
        self._initialize_file()

    def _initialize_file(self):
        """Initialize file access based on size and available memory."""
        try:
            # Get file size
            self.file_size = os.path.getsize(self.file_path)

            # Determine optimal strategy based on file size
            size_mb = self.file_size / (1024 * 1024)

            if size_mb < 100:
                self.memory_strategy = MemoryStrategy.DIRECT_LOAD
                self.loading_strategy = LoadingStrategy.IMMEDIATE
            elif size_mb < 1024:  # 1GB
                self.memory_strategy = MemoryStrategy.MEMORY_MAP
                self.loading_strategy = LoadingStrategy.PROGRESSIVE
            else:
                self.memory_strategy = MemoryStrategy.STREAMING
                self.loading_strategy = LoadingStrategy.ON_DEMAND

            logger.info(f"File size: {size_mb:.1f}MB, strategy: {self.memory_strategy.value}")

            # Initialize based on strategy
            if self.memory_strategy == MemoryStrategy.DIRECT_LOAD:
                self._init_direct_load()
            elif self.memory_strategy == MemoryStrategy.MEMORY_MAP:
                self._init_memory_map()
            elif self.memory_strategy == MemoryStrategy.STREAMING:
                self._init_streaming()

            # Start background loader for progressive/on-demand strategies
            if self.loading_strategy in [LoadingStrategy.PROGRESSIVE, LoadingStrategy.BACKGROUND]:
                self.background_loader = BackgroundLoader(self.file_path, self.cache, self.config)
                self.background_loader.start()

            # Start memory monitoring
            self.memory_monitor.add_callback(self._on_memory_pressure)
            self.memory_monitor.start_monitoring()

        except Exception as e:
            logger.error("Failed to initialize large file handler: %s", e)
            raise

    def _init_direct_load(self):
        """Initialize direct loading strategy."""
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()

            # Cache the entire file
            region = FileRegion(offset=0, size=len(data), data=data)
            self.cache.add_region(region)

            logger.debug(f"Direct loaded entire file: {len(data)} bytes")

        except Exception as e:
            logger.error("Direct load failed: %s", e)
            # Fallback to streaming
            self.memory_strategy = MemoryStrategy.STREAMING
            self._init_streaming()

    def _init_memory_map(self):
        """Initialize memory mapping strategy."""
        try:
            self.file_handle = open(self.file_path, 'rb')
            self.mmap_file = mmap.mmap(
                self.file_handle.fileno(),
                length=0,
                access=mmap.ACCESS_READ
            )
            logger.debug("Memory mapped file: %s bytes", self.file_size)

        except Exception as e:
            logger.error("Memory mapping failed: %s", e)
            # Fallback to streaming
            self.memory_strategy = MemoryStrategy.STREAMING
            self._init_streaming()

    def _init_streaming(self):
        """Initialize streaming strategy."""
        # Streaming doesn't require initialization
        # Data is loaded on-demand through the cache
        logger.debug("Initialized streaming mode")

    def read(self, offset: int, size: int) -> bytes:
        """
        Read data from the file using the optimal strategy.

        Args:
            offset: Starting byte offset
            size: Number of bytes to read

        Returns:
            Read binary data
        """
        if offset < 0 or size <= 0 or offset >= self.file_size:
            return b''

        # Adjust size to file bounds
        size = min(size, self.file_size - offset)

        # Track access pattern
        self.access_patterns.append((offset, size, time.time()))
        if len(self.access_patterns) > 1000:
            self.access_patterns = self.access_patterns[-500:]  # Keep recent patterns

        # Try different read strategies
        if self.memory_strategy == MemoryStrategy.DIRECT_LOAD:
            return self._read_direct(offset, size)
        elif self.memory_strategy == MemoryStrategy.MEMORY_MAP:
            return self._read_mmap(offset, size)
        else:
            return self._read_streaming(offset, size)

    def _read_direct(self, offset: int, size: int) -> bytes:
        """Read using direct loading (cached data)."""
        region = self.cache.get_region(offset, size)
        if region and region.data:
            start_in_region = offset - region.offset
            end_in_region = start_in_region + size
            data = region.data[start_in_region:end_in_region]
            self.cache.release_region(region)
            return data

        return b''  # Should not happen with direct loading

    def _read_mmap(self, offset: int, size: int) -> bytes:
        """Read using memory mapping."""
        if not self.mmap_file:
            return self._read_streaming(offset, size)

        try:
            return self.mmap_file[offset:offset + size]
        except Exception as e:
            logger.error("Memory map read error: %s", e)
            return self._read_streaming(offset, size)

    def _read_streaming(self, offset: int, size: int) -> bytes:
        """Read using streaming with cache."""
        # Check cache first
        region = self.cache.get_region(offset, size)
        if region and region.data:
            start_in_region = offset - region.offset
            end_in_region = start_in_region + size
            data = region.data[start_in_region:end_in_region]
            self.cache.release_region(region)

            # Prefetch next chunks if configured
            self._prefetch_chunks(offset + size)

            return data

        # Load from file
        try:
            # Calculate optimal chunk size for loading
            chunk_size = max(size, self.config.chunk_size_mb * 1024 * 1024)
            chunk_offset = (offset // chunk_size) * chunk_size

            with open(self.file_path, 'rb') as f:
                f.seek(chunk_offset)
                chunk_data = f.read(min(chunk_size, self.file_size - chunk_offset))

            if chunk_data:
                # Cache the chunk
                chunk_region = FileRegion(
                    offset=chunk_offset,
                    size=len(chunk_data),
                    data=chunk_data
                )
                self.cache.add_region(chunk_region)

                # Extract requested data
                start_in_chunk = offset - chunk_offset
                end_in_chunk = start_in_chunk + size
                data = chunk_data[start_in_chunk:end_in_chunk]

                # Prefetch next chunks
                self._prefetch_chunks(offset + size)

                return data

        except Exception as e:
            logger.error("Streaming read error: %s", e)

        return b''

    def _prefetch_chunks(self, next_offset: int):
        """Prefetch chunks for better performance."""
        if (self.config.prefetch_chunks > 0 and
            self.background_loader and
            self.loading_strategy == LoadingStrategy.PROGRESSIVE):

            chunk_size = self.config.chunk_size_mb * 1024 * 1024

            for i in range(self.config.prefetch_chunks):
                prefetch_offset = next_offset + (i * chunk_size)
                if prefetch_offset < self.file_size:
                    # Check if already cached
                    if not self.cache.get_region(prefetch_offset, 1):
                        self.background_loader.queue_load(
                            prefetch_offset,
                            min(chunk_size, self.file_size - prefetch_offset)
                        )

    def _on_memory_pressure(self, memory_usage: float):
        """Handle memory pressure by adjusting cache."""
        if memory_usage > self.config.memory_threshold:
            # Reduce cache size
            old_size = self.config.cache_size_mb
            self.config.cache_size_mb = max(50, int(old_size * 0.8))

            # Clear some cache entries
            cache_stats = self.cache.get_stats()
            if cache_stats['utilization'] > 0.9:
                self.cache.clear()

            logger.warning(f"Memory pressure detected: {memory_usage:.1%}, "
                         f"reduced cache from {old_size}MB to {self.config.cache_size_mb}MB")

    def get_file_size(self) -> int:
        """Get the file size."""
        return self.file_size

    def get_stats(self) -> Dict[str, Any]:
        """Get performance and usage statistics."""
        cache_stats = self.cache.get_stats()

        # Analyze access patterns
        recent_patterns = [p for p in self.access_patterns if time.time() - p[2] < 60]
        sequential_ratio = self._calculate_sequential_ratio(recent_patterns)

        return {
            'file_size_mb': self.file_size / (1024 * 1024),
            'memory_strategy': self.memory_strategy.value,
            'loading_strategy': self.loading_strategy.value,
            'cache_stats': cache_stats,
            'access_patterns': len(self.access_patterns),
            'sequential_ratio': sequential_ratio,
            'background_loader_active': self.background_loader is not None and self.background_loader.isAlive() if hasattr(self.background_loader, 'isAlive') else False
        }

    def _calculate_sequential_ratio(self, patterns: List[Tuple[int, int, float]]) -> float:
        """Calculate the ratio of sequential vs random access."""
        if len(patterns) < 2:
            return 0.0

        sequential_count = 0
        total_count = len(patterns) - 1

        for i in range(1, len(patterns)):
            prev_offset, prev_size, _ = patterns[i-1]
            curr_offset, _, _ = patterns[i]

            # Consider sequential if current offset is close to previous end
            if abs(curr_offset - (prev_offset + prev_size)) < 1024:
                sequential_count += 1

        return sequential_count / total_count if total_count > 0 else 0.0

    def close(self):
        """Close the file handler and clean up resources."""
        try:
            # Stop background loader
            if self.background_loader:
                self.background_loader.stop()
                if hasattr(self.background_loader, 'wait'):
                    self.background_loader.wait()

            # Stop memory monitoring
            self.memory_monitor.stop_monitoring()

            # Close memory map
            if self.mmap_file:
                self.mmap_file.close()
                self.mmap_file = None

            # Close file handle
            if self.file_handle:
                self.file_handle.close()
                self.file_handle = None

            # Clear cache
            self.cache.clear()

            logger.debug("Large file handler closed")

        except Exception as e:
            logger.error("Error closing large file handler: %s", e)

    def __del__(self):
        """Cleanup when object is destroyed."""
        self.close()
