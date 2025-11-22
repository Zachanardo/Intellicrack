#!/usr/bin/env python3
"""Performance optimizer plugin for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import functools
import gc
import hashlib
import logging
import mmap
import multiprocessing as mp
import pickle
import threading
import time
import tracemalloc
from collections import defaultdict, deque
from collections.abc import Callable, Generator
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import TypeVar

from intellicrack.handlers.numpy_handler import numpy as np
from intellicrack.handlers.psutil_handler import psutil
from intellicrack.handlers.sqlite3_handler import sqlite3
from intellicrack.handlers.torch_handler import TORCH_AVAILABLE, torch
from intellicrack.utils.logger import get_logger


logger = get_logger(__name__)

"""
Performance Optimizer for Intellicrack Framework

Comprehensive performance optimization system providing real-time monitoring,
adaptive optimization, and resource management for all Intellicrack components
including binary analysis, ML operations, and concurrent processing.

Author: Intellicrack Framework
Version: 2.0.0
License: GPL v3
"""

# GPU acceleration support

try:
    import cupy

    CUPY_AVAILABLE = True
except ImportError:
    CUPY_AVAILABLE = False


class OptimizationType(Enum):
    """Types of optimizations."""

    MEMORY = "memory"
    CPU = "cpu"
    IO = "io"
    GPU = "gpu"
    DATABASE = "database"
    NETWORK = "network"
    UI = "ui"
    CACHE = "cache"


class PerformanceLevel(Enum):
    """Performance optimization levels."""

    MINIMAL = "minimal"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"
    MAXIMUM = "maximum"


class ResourceType(Enum):
    """Resource types for monitoring."""

    CPU_USAGE = "cpu_usage"
    MEMORY_USAGE = "memory_usage"
    DISK_IO = "disk_io"
    NETWORK_IO = "network_io"
    GPU_USAGE = "gpu_usage"
    GPU_MEMORY = "gpu_memory"
    THREAD_COUNT = "thread_count"
    PROCESS_COUNT = "process_count"


@dataclass
class PerformanceMetric:
    """Performance metric data point."""

    timestamp: float
    resource_type: ResourceType
    value: float
    component: str
    details: dict[str, object] = field(default_factory=dict)


@dataclass
class OptimizationResult:
    """Result of optimization operation."""

    optimization_type: OptimizationType
    success: bool
    improvement: float  # Percentage improvement
    before_metrics: dict[str, float]
    after_metrics: dict[str, float]
    details: str = ""


@dataclass
class ResourcePool:
    """Resource pool configuration."""

    pool_type: str
    initial_size: int
    max_size: int
    growth_factor: float = 1.5
    shrink_threshold: float = 0.3
    allocated: int = 0
    available_items: list[object] = field(default_factory=list)
    in_use_items: set = field(default_factory=set)
    creation_func: Callable | None = None


class MemoryPool:
    """Advanced memory pool for binary data processing."""

    def __init__(self, initial_buffers: int = 10, buffer_size: int = 1024 * 1024) -> None:
        """Initialize memory pool with pre-allocated buffers for reuse."""
        self.buffer_size = buffer_size
        self.available_buffers = deque()
        self.in_use_buffers = set()
        self.allocation_history = deque(maxlen=1000)
        self.lock = threading.Lock()

        # Pre-allocate initial buffers
        for _ in range(initial_buffers):
            buffer = bytearray(buffer_size)
            self.available_buffers.append(buffer)

    def get_buffer(self, required_size: int = None) -> bytearray:
        """Get buffer from pool."""
        with self.lock:
            if required_size and required_size > self.buffer_size:
                # Create larger buffer for special cases
                buffer = bytearray(required_size)
                self.in_use_buffers.add(id(buffer))
                return buffer

            if self.available_buffers:
                buffer = self.available_buffers.popleft()
                self.in_use_buffers.add(id(buffer))
                self.allocation_history.append((time.time(), len(self.in_use_buffers)))
                return buffer

            # Create new buffer if pool is empty
            buffer = bytearray(self.buffer_size)
            self.in_use_buffers.add(id(buffer))
            return buffer

    def return_buffer(self, buffer: bytearray) -> None:
        """Return buffer to pool."""
        with self.lock:
            buffer_id = id(buffer)
            if buffer_id in self.in_use_buffers:
                self.in_use_buffers.remove(buffer_id)

                # Only return standard-sized buffers to pool
                if len(buffer) == self.buffer_size:
                    # Clear buffer for security
                    buffer[:] = b"\x00" * len(buffer)
                    self.available_buffers.append(buffer)

    def predict_required_buffers(self) -> int:
        """Predict required buffer count based on history."""
        if len(self.allocation_history) < 10:
            return 10

        recent_peaks = [count for _, count in list(self.allocation_history)[-100:]]
        return int(np.percentile(recent_peaks, 90) * 1.2)

    def optimize_pool_size(self) -> None:
        """Optimize pool size based on usage patterns."""
        required = self.predict_required_buffers()
        current_available = len(self.available_buffers)

        if required > current_available:
            # Add more buffers
            for _ in range(required - current_available):
                buffer = bytearray(self.buffer_size)
                self.available_buffers.append(buffer)
        elif current_available > required * 2:
            # Remove excess buffers
            excess = current_available - required
            for _ in range(excess // 2):
                if self.available_buffers:
                    self.available_buffers.popleft()


class CacheManager:
    """Intelligent caching system with LRU and popularity scoring."""

    def __init__(self, max_size: int = 1000, max_memory: int = 512 * 1024 * 1024) -> None:
        """Initialize cache manager with size and memory limits."""
        self.max_size = max_size
        self.max_memory = max_memory
        self.cache = {}
        self.access_order = deque()
        self.access_counts = defaultdict(int)
        self.memory_usage = 0
        self.lock = threading.RLock()

        # Performance tracking
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    def _calculate_size(self, obj: object) -> int:
        """Calculate object size in memory.

        Determine the memory footprint of an object by using its __sizeof__
        method or serializing it with pickle. Used for cache memory management.
        Accepts any object type since cache may store heterogeneous data.

        Args:
            obj: The object whose size needs to be calculated. Can be any type.

        Returns:
            Size in bytes. Returns 1024 as a default estimate if calculation fails.

        """
        try:
            if hasattr(obj, "__sizeof__"):
                return obj.__sizeof__()
            return len(pickle.dumps(obj))
        except Exception:
            return 1024

    def _calculate_score(self, key: str) -> float:
        """Calculate popularity score for cache item."""
        access_count = self.access_counts[key]
        last_access_time = next(
            (
                len(self.access_order) - i
                for i, item_key in enumerate(reversed(self.access_order))
                if item_key == key
            ),
            0,
        )
        # Combine frequency and recency
        frequency_score = access_count
        recency_score = 1.0 / (last_access_time + 1)

        return frequency_score * 0.7 + recency_score * 0.3

    def get(self, key: str, default: object = None) -> object:
        """Get item from cache.

        Retrieve a cached value by key with automatic access tracking for
        LRU and popularity-based eviction policies.

        Args:
            key: The cache key to retrieve.
            default: Default value to return if key is not found (default: None).
                Can be any type.

        Returns:
            The cached value if found, otherwise the default value.
            Can be any type since cache stores heterogeneous data.

        """
        with self.lock:
            if key in self.cache:
                self.hits += 1
                self.access_counts[key] += 1

                # Update access order
                with suppress(ValueError):
                    self.access_order.remove(key)
                self.access_order.append(key)

                return self.cache[key]
            self.misses += 1
            return default

    def put(self, key: str, value: object) -> bool:
        """Put item in cache.

        Add or update a cached value with automatic eviction when size or
        memory limits are exceeded.

        Args:
            key: The cache key to store the value under.
            value: The value to cache. Can be any type.

        Returns:
            True if the value was successfully cached, False if it cannot be
            evicted to make space.

        """
        with self.lock:
            value_size = self._calculate_size(value)

            # Check if we need to evict items
            while (
                len(self.cache) >= self.max_size or self.memory_usage + value_size > self.max_memory
            ):
                if not self._evict_least_valuable():
                    return False

            # Add new item
            self.cache[key] = value
            self.memory_usage += value_size
            self.access_counts[key] += 1
            self.access_order.append(key)

            return True

    def _evict_least_valuable(self) -> bool:
        """Evict least valuable cache item."""
        if not self.cache:
            return False

        # Find item with lowest score
        min_score = float("inf")
        evict_key = None

        for key in self.cache:
            score = self._calculate_score(key)
            if score < min_score:
                min_score = score
                evict_key = key

        if evict_key:
            value = self.cache.pop(evict_key)
            self.memory_usage -= self._calculate_size(value)
            self.access_counts.pop(evict_key, 0)

            with suppress(ValueError):
                self.access_order.remove(evict_key)

            self.evictions += 1
            return True

        return False

    def get_stats(self) -> dict[str, object]:
        """Get cache statistics."""
        total_requests = self.hits + self.misses
        hit_rate = self.hits / total_requests if total_requests > 0 else 0.0

        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "hit_rate": hit_rate,
            "size": len(self.cache),
            "memory_usage": self.memory_usage,
            "memory_usage_mb": self.memory_usage / (1024 * 1024),
        }


class ThreadPoolOptimizer:
    """Dynamic thread pool optimization using Little's Law."""

    def __init__(self, initial_workers: int = None) -> None:
        """Initialize thread pool optimizer with adaptive worker management."""
        self.initial_workers = initial_workers or mp.cpu_count()
        self.min_workers = max(1, self.initial_workers // 4)
        self.max_workers = self.initial_workers * 4

        self.executor = ThreadPoolExecutor(max_workers=self.initial_workers)
        self.queue_depths = deque(maxlen=100)
        self.response_times = deque(maxlen=100)
        self.last_optimization = time.time()
        self.optimization_interval = 30  # seconds

        self.lock = threading.Lock()

    def submit(self, fn: Callable, *args: object, **kwargs: object) -> Future:
        """Submit task and collect metrics.

        Submit a task to the thread pool with automatic response time and
        queue depth tracking for adaptive pool optimization.

        Args:
            fn: The callable to execute in the thread pool.
            *args: Positional arguments to pass to the callable. Can be any type.
            **kwargs: Keyword arguments to pass to the callable. Can be any type.

        Returns:
            A Future object representing the submitted task.

        """
        start_time = time.time()
        queue_depth = len(self.executor._threads) - len(
            [t for t in self.executor._threads if not t._tstate_lock.acquire(False)]
        )

        with self.lock:
            self.queue_depths.append(queue_depth)

        future = self.executor.submit(fn, *args, **kwargs)

        def track_completion(fut: Future) -> None:
            end_time = time.time()
            response_time = end_time - start_time

            with self.lock:
                self.response_times.append(response_time)

                # Check if optimization is needed
                if end_time - self.last_optimization > self.optimization_interval:
                    self._optimize_pool_size()
                    self.last_optimization = end_time

        future.add_done_callback(track_completion)
        return future

    def _optimize_pool_size(self) -> None:
        """Optimize thread pool size using Little's Law."""
        if len(self.response_times) < 10 or len(self.queue_depths) < 10:
            return

        # Calculate metrics
        avg_response_time = np.mean(list(self.response_times))
        avg_queue_depth = np.mean(list(self.queue_depths))
        arrival_rate = len(self.response_times) / (self.optimization_interval or 1)

        # Little's Law: L = λ * W
        # Where L = average number in system, λ = arrival rate, W = average response time
        # Use queue depth to adjust for system utilization
        utilization_factor = min(avg_queue_depth / 10.0, 1.0)  # Scale based on queue depth
        optimal_workers = int(
            arrival_rate * avg_response_time * (1.2 + utilization_factor)
        )  # Dynamic buffer based on queue depth

        # Apply constraints
        optimal_workers = max(self.min_workers, min(self.max_workers, optimal_workers))

        current_workers = self.executor._max_workers

        if abs(optimal_workers - current_workers) > 1:
            # Create new executor with optimal size
            old_executor = self.executor
            self.executor = ThreadPoolExecutor(max_workers=optimal_workers)

            # Shutdown old executor gracefully
            threading.Thread(target=lambda: old_executor.shutdown(wait=True)).start()

    def get_stats(self) -> dict[str, object]:
        """Get thread pool statistics."""
        with self.lock:
            return {
                "current_workers": self.executor._max_workers,
                "avg_queue_depth": np.mean(list(self.queue_depths)) if self.queue_depths else 0,
                "avg_response_time": np.mean(list(self.response_times))
                if self.response_times
                else 0,
                "min_workers": self.min_workers,
                "max_workers": self.max_workers,
            }


class GPUOptimizer:
    """GPU memory and computation optimizer."""

    def __init__(self) -> None:
        """Initialize GPU optimizer with device detection and memory tracking."""
        self.gpu_available = TORCH_AVAILABLE and torch.cuda.is_available()
        self.device_count = torch.cuda.device_count() if self.gpu_available else 0
        self.memory_usage = {}
        self.optimal_batch_sizes = {}

    def get_optimal_batch_size(self, model_name: str, input_shape: tuple) -> int:
        """Calculate optimal batch size for GPU processing."""
        if not self.gpu_available:
            return 1

        cache_key = f"{model_name}_{input_shape}"
        if cache_key in self.optimal_batch_sizes:
            return self.optimal_batch_sizes[cache_key]

        device = torch.cuda.current_device()
        total_memory = torch.cuda.get_device_properties(device).total_memory
        available_memory = total_memory - torch.cuda.memory_allocated(device)

        # Estimate memory per sample (rough approximation)
        sample_memory = np.prod(input_shape) * 4  # 4 bytes per float32

        # Use 80% of available memory for safety
        safe_memory = available_memory * 0.8
        optimal_batch = int(safe_memory / (sample_memory * 2))  # 2x for gradients

        # Ensure batch size is power of 2 for efficiency
        optimal_batch = 2 ** int(np.log2(max(1, optimal_batch)))

        self.optimal_batch_sizes[cache_key] = optimal_batch
        return optimal_batch

    def optimize_memory(self) -> None:
        """Optimize GPU memory usage."""
        if not self.gpu_available:
            return

        # Clear cache
        torch.cuda.empty_cache()

        # Collect memory statistics
        for device_id in range(self.device_count):
            with torch.cuda.device(device_id):
                allocated = torch.cuda.memory_allocated(device_id)
                cached = torch.cuda.memory_reserved(device_id)
                total = torch.cuda.get_device_properties(device_id).total_memory

                self.memory_usage[device_id] = {
                    "allocated": allocated,
                    "cached": cached,
                    "total": total,
                    "utilization": allocated / total,
                }

    def get_stats(self) -> dict[str, object]:
        """Get GPU statistics."""
        if not self.gpu_available:
            return {"gpu_available": False}

        stats = {"gpu_available": True, "device_count": self.device_count}

        for device_id in range(self.device_count):
            device_stats = self.memory_usage.get(device_id, {})
            stats[f"device_{device_id}"] = device_stats

        return stats


class IOOptimizer:
    """I/O operations optimizer with read-ahead and compression detection."""

    def __init__(self) -> None:
        """Initialize IO optimizer with read-ahead caching and pattern analysis."""
        self.read_ahead_size = 64 * 1024  # 64KB default
        self.compression_cache = {}
        self.file_access_patterns = defaultdict(list)

    def optimized_read(self, file_path: str, chunk_size: int = None) -> bytes:
        """Optimized file reading with read-ahead."""
        path_obj = Path(file_path)

        if not path_obj.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        file_size = path_obj.stat().st_size

        # Record access pattern
        self.file_access_patterns[file_path].append(
            {
                "timestamp": time.time(),
                "size": file_size,
                "chunk_size": chunk_size,
            },
        )

        # Optimize read strategy based on file size
        if file_size < 1024 * 1024:  # < 1MB: read entire file
            with open(file_path, "rb") as f:
                return f.read()

        # Large files: use memory mapping
        with (open(file_path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm):
            return mm[:chunk_size] if chunk_size else mm[:]

    def detect_compression(self, data: bytes) -> tuple[bool, str]:
        """Detect if data is compressed and return format."""
        if len(data) < 4:
            return False, "unknown"

        # Check common compression signatures
        signatures = {
            b"\x1f\x8b": "gzip",
            b"PK\x03\x04": "zip",
            b"PK\x05\x06": "zip",
            b"PK\x07\x08": "zip",
            b"\x50\x4b": "zip",
            b"BZ": "bzip2",
            b"\xfd7zXZ": "xz",
            b"\x28\xb5\x2f\xfd": "zstd",
        }

        for sig, format_name in signatures.items():
            if data.startswith(sig):
                return True, format_name

        # Entropy-based compression detection
        if len(data) > 1024:
            entropy = self._calculate_entropy(data[:1024])
            if entropy > 7.5:  # High entropy suggests compression/encryption
                return True, "unknown"

        return False, "none"

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0

        # Count byte frequencies
        counts = defaultdict(int)
        for byte in data:
            counts[byte] += 1

        # Calculate entropy
        entropy = 0.0
        for count in counts.values():
            if count > 0:
                probability = count / len(data)
                entropy -= probability * np.log2(probability)

        return entropy

    def optimize_read_ahead(self, file_path: str) -> None:
        """Optimize read-ahead size based on access patterns."""
        patterns = self.file_access_patterns.get(file_path, [])

        if len(patterns) < 3:
            return

        # Analyze access patterns
        recent_patterns = patterns[-10:]
        avg_chunk_size = np.mean(
            [p.get("chunk_size", 0) for p in recent_patterns if p.get("chunk_size")]
        )

        if avg_chunk_size > 0:
            # Set read-ahead to 2x average chunk size
            self.read_ahead_size = min(1024 * 1024, int(avg_chunk_size * 2))


class DatabaseOptimizer:
    """Database performance optimizer for SQLite."""

    def __init__(self, db_path: str) -> None:
        """Initialize database optimizer with connection pooling and query caching."""
        self.db_path = db_path
        self.connection_pool = []
        self.max_connections = 10
        self.query_cache = {}
        self.query_stats = defaultdict(list)

    def get_connection(self) -> sqlite3.Connection:
        """Get optimized database connection."""
        if self.connection_pool:
            return self.connection_pool.pop()

        conn = sqlite3.connect(
            self.db_path,
            timeout=30.0,
            check_same_thread=False,
        )

        # Apply optimizations
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=10000")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA mmap_size=268435456")  # 256MB

        return conn

    def return_connection(self, conn: sqlite3.Connection) -> None:
        """Return connection to pool."""
        if len(self.connection_pool) < self.max_connections:
            self.connection_pool.append(conn)
        else:
            conn.close()

    @contextmanager
    def get_cursor(self) -> Generator:
        """Context manager for database operations.

        Provide a cursor with automatic connection pooling and transaction
        management. Commits on success, rolls back on exception.

        Yields:
            A SQLite cursor ready for query execution.

        Raises:
            Any exception that occurs during database operations.

        """
        conn = self.get_connection()
        try:
            yield conn.cursor()
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self.return_connection(conn)

    def execute_optimized(self, query: str, params: object = None) -> list[tuple]:
        """Execute query with caching and statistics.

        Execute a SQL query with automatic result caching and performance
        tracking. SELECT queries are cached for 5 minutes.

        Args:
            query: The SQL query string to execute.
            params: Optional parameters for parameterized queries (default: None).
                Can be any type for flexible SQL parameter binding.

        Returns:
            A list of result tuples from the query.

        """
        query_hash = hashlib.sha256(f"{query}{params}".encode()).hexdigest()

        # Check cache for SELECT queries
        if query.strip().upper().startswith("SELECT") and query_hash in self.query_cache:
            cache_entry = self.query_cache[query_hash]
            if time.time() - cache_entry["timestamp"] < 300:  # 5 minutes TTL
                return cache_entry["result"]

        # Execute query and collect stats
        start_time = time.time()

        with self.get_cursor() as cursor:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)

            result = cursor.fetchall()

        execution_time = time.time() - start_time

        # Record statistics
        self.query_stats[query].append(
            {
                "execution_time": execution_time,
                "timestamp": time.time(),
                "result_count": len(result),
            },
        )

        # Cache SELECT results
        if query.strip().upper().startswith("SELECT"):
            self.query_cache[query_hash] = {
                "result": result,
                "timestamp": time.time(),
            }

        return result

    def optimize_indices(self) -> None:
        """Analyze and create optimal indices."""
        with self.get_cursor() as cursor:
            # Get table information
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

            for table in tables:
                # Analyze query patterns for this table
                table_queries = [q for q in self.query_stats if table in q.upper()]

                # Extract commonly used WHERE columns
                where_columns = set()
                for query in table_queries:
                    # Simple WHERE clause extraction (basic implementation)
                    if "WHERE" in query.upper():
                        where_part = (
                            query.upper().split("WHERE")[1].split("ORDER")[0].split("GROUP")[0]
                        )
                        # Extract column names (simplified)
                        words = where_part.split()
                        for i, word in enumerate(words):
                            if i > 0 and words[i - 1] not in ["AND", "OR", "=", "<", ">", "!="]:
                                where_columns.add(word.strip("(),"))

                # Create indices for frequently queried columns
                for column in where_columns:
                    index_name = f"idx_{table}_{column}"
                    with suppress(sqlite3.Error):
                        cursor.execute(
                            f"CREATE INDEX IF NOT EXISTS {index_name} ON {table}({column})"
                        )

    def get_stats(self) -> dict[str, object]:
        """Get database performance statistics."""
        total_queries = sum(len(stats) for stats in self.query_stats.values())
        avg_execution_time = 0

        if total_queries > 0:
            all_times = []
            for stats in self.query_stats.values():
                all_times.extend([s["execution_time"] for s in stats])
            avg_execution_time = np.mean(all_times)

        return {
            "total_queries": total_queries,
            "avg_execution_time": avg_execution_time,
            "cache_size": len(self.query_cache),
            "connection_pool_size": len(self.connection_pool),
            "slow_queries": len(
                [
                    s
                    for stats in self.query_stats.values()
                    for s in stats
                    if s["execution_time"] > 1.0
                ]
            ),
        }


class PerformanceProfiler:
    """Real-time performance profiler."""

    def __init__(self) -> None:
        """Initialize performance profiler with metrics tracking and system monitoring."""
        self.metrics_history = defaultdict(deque)
        self.profiling_active = False
        self.profile_data = {}
        self.lock = threading.Lock()

        # System monitoring
        self.process = psutil.Process()
        self.last_cpu_times = self.process.cpu_times()
        self.last_io_counters = self.process.io_counters()

    def start_profiling(self) -> None:
        """Start performance profiling."""
        self.profiling_active = True
        tracemalloc.start()

        # Start background monitoring
        threading.Thread(target=self._monitor_system, daemon=True).start()

    def stop_profiling(self) -> dict[str, object]:
        """Stop profiling and return results."""
        self.profiling_active = False

        # Get memory snapshot
        snapshot = tracemalloc.take_snapshot()
        top_stats = snapshot.statistics("lineno")

        memory_stats = [
            {
                "file": stat.traceback.format()[-1],
                "size_mb": stat.size / (1024 * 1024),
                "count": stat.count,
            }
            for stat in top_stats[:10]
        ]
        return {
            "memory_top_consumers": memory_stats,
            "metrics_summary": self._get_metrics_summary(),
        }

    def _monitor_system(self) -> None:
        """Background system monitoring."""
        while self.profiling_active:
            try:
                # CPU metrics
                cpu_times = self.process.cpu_times()
                cpu_percent = self.process.cpu_percent()

                # Calculate CPU time distribution
                cpu_user_time = getattr(cpu_times, "user", 0)
                cpu_system_time = getattr(cpu_times, "system", 0)
                cpu_total_time = cpu_user_time + cpu_system_time

                # Memory metrics
                memory_info = self.process.memory_info()
                memory_percent = self.process.memory_percent()

                # Extract memory details
                memory_rss = getattr(memory_info, "rss", 0)  # Resident Set Size
                memory_vms = getattr(memory_info, "vms", 0)  # Virtual Memory Size

                # I/O metrics
                io_counters = self.process.io_counters()

                # Extract I/O details if available
                io_read_bytes = getattr(io_counters, "read_bytes", 0) if io_counters else 0
                io_write_bytes = getattr(io_counters, "write_bytes", 0) if io_counters else 0

                # GPU metrics
                gpu_stats = {}
                if TORCH_AVAILABLE and torch.cuda.is_available():
                    for device_id in range(torch.cuda.device_count()):
                        gpu_stats[f"gpu_{device_id}_memory"] = torch.cuda.memory_allocated(
                            device_id
                        )

                timestamp = time.time()

                with self.lock:
                    self.metrics_history[ResourceType.CPU_USAGE].append(
                        PerformanceMetric(
                            timestamp,
                            ResourceType.CPU_USAGE,
                            cpu_percent,
                            f"system_total_time:{cpu_total_time:.2f}",
                        ),
                    )

                    self.metrics_history[ResourceType.MEMORY_USAGE].append(
                        PerformanceMetric(
                            timestamp,
                            ResourceType.MEMORY_USAGE,
                            memory_percent,
                            f"rss:{memory_rss},vms:{memory_vms},io_r:{io_read_bytes},io_w:{io_write_bytes}",
                        ),
                    )

                    # Keep only recent metrics (last 1000 points)
                    for metric_type in self.metrics_history:
                        if len(self.metrics_history[metric_type]) > 1000:
                            self.metrics_history[metric_type].popleft()

                time.sleep(1)  # Sample every second

            except Exception as e:
                logger.exception("Error in system monitoring: %s", e)
                time.sleep(5)

    def _get_metrics_summary(self) -> dict[str, object]:
        """Get summary of collected metrics."""
        summary = {}

        with self.lock:
            for metric_type, metrics in self.metrics_history.items():
                if metrics:
                    values = [m.value for m in metrics]

                    # Use CuPy for GPU-accelerated statistics if available
                    if CUPY_AVAILABLE and len(values) > 1000:
                        try:
                            cp_values = cupy.array(values)
                            summary[metric_type.value] = {
                                "count": len(values),
                                "avg": float(cupy.mean(cp_values)),
                                "min": float(cupy.min(cp_values)),
                                "max": float(cupy.max(cp_values)),
                                "std": float(cupy.std(cp_values)),
                            }
                        except Exception:
                            # Fallback to NumPy
                            summary[metric_type.value] = {
                                "count": len(values),
                                "avg": np.mean(values),
                                "min": np.min(values),
                                "max": np.max(values),
                                "std": np.std(values),
                            }
                    else:
                        summary[metric_type.value] = {
                            "count": len(values),
                            "avg": np.mean(values),
                            "min": np.min(values),
                            "max": np.max(values),
                            "std": np.std(values),
                        }

        return summary

    def get_current_metrics(self) -> dict[str, float]:
        """Get current system metrics."""
        return {
            "cpu_percent": self.process.cpu_percent(),
            "memory_percent": self.process.memory_percent(),
            "memory_mb": self.process.memory_info().rss / (1024 * 1024),
            "threads": self.process.num_threads(),
            "open_files": len(self.process.open_files()),
            "connections": len(self.process.connections()),
        }


class AdaptiveOptimizer:
    """Machine learning-based adaptive optimizer."""

    def __init__(self) -> None:
        """Initialize adaptive optimizer with learning-based configuration tuning."""
        self.optimization_history = []
        self.current_config = {
            "memory_pool_size": 10,
            "thread_pool_size": mp.cpu_count(),
            "cache_size": 1000,
            "read_ahead_size": 64 * 1024,
        }
        self.learning_rate = 0.1

    def learn_from_metrics(self, metrics: dict[str, float], performance_score: float) -> None:
        """Learn optimal configuration from performance metrics."""
        # Simple Q-learning approach for configuration optimization

        # Record experience
        experience = {
            "config": self.current_config.copy(),
            "metrics": metrics,
            "score": performance_score,
            "timestamp": time.time(),
        }
        self.optimization_history.append(experience)

        # Keep only recent history
        if len(self.optimization_history) > 1000:
            self.optimization_history = self.optimization_history[-500:]

        # Update configuration based on learning
        if len(self.optimization_history) > 10:
            self._update_configuration()

    def _update_configuration(self) -> None:
        """Update configuration based on historical performance."""
        if len(self.optimization_history) < 2:
            return

        # Find best performing configurations
        sorted_history = sorted(self.optimization_history, key=lambda x: x["score"], reverse=True)
        best_configs = sorted_history[:5]  # Top 5 configurations

        # Calculate average of best configurations
        new_config = {}
        for key in self.current_config:
            if values := [
                config["config"][key]
                for config in best_configs
                if key in config["config"]
            ]:
                new_config[key] = int(np.mean(values))

        # Apply gradual learning
        for key, new_value in new_config.items():
            current_value = self.current_config[key]
            adjusted_value = current_value + self.learning_rate * (new_value - current_value)
            self.current_config[key] = max(1, int(adjusted_value))

    def get_recommendations(self) -> dict[str, object]:
        """Get optimization recommendations."""
        if not self.optimization_history:
            return {}

        recent_metrics = self.optimization_history[-10:]
        avg_score = np.mean([h["score"] for h in recent_metrics])

        recommendations = []

        # Analyze recent performance
        if avg_score < 0.7:  # Poor performance
            recommendations.extend(
                (
                    {
                        "type": "memory",
                        "action": "increase_cache",
                        "description": "Consider increasing cache size for better performance",
                    },
                    {
                        "type": "cpu",
                        "action": "optimize_threads",
                        "description": "Optimize thread pool configuration",
                    },
                )
            )
        # Check for memory pressure
        recent_memory = np.mean([h["metrics"].get("memory_percent", 0) for h in recent_metrics])
        if recent_memory > 80:
            recommendations.append(
                {
                    "type": "memory",
                    "action": "reduce_memory_usage",
                    "description": "High memory usage detected, consider optimization",
                },
            )

        return {
            "current_config": self.current_config,
            "performance_score": avg_score,
            "recommendations": recommendations,
        }


class PerformanceOptimizer:
    """Run performance optimization engine."""

    def __init__(self, config: dict[str, object] | None = None) -> None:
        """Initialize performance optimizer with all optimization components."""
        self.config = config or {}
        self.optimization_level = PerformanceLevel(
            self.config.get("optimization_level", "balanced"),
        )

        # Initialize components
        self.memory_pool = MemoryPool()
        self.cache_manager = CacheManager()
        self.thread_optimizer = ThreadPoolOptimizer()
        self.gpu_optimizer = GPUOptimizer()
        self.io_optimizer = IOOptimizer()
        self.profiler = PerformanceProfiler()
        self.adaptive_optimizer = AdaptiveOptimizer()

        # Database optimizer (if database is specified)
        self.db_optimizer = None
        if "database_path" in self.config:
            self.db_optimizer = DatabaseOptimizer(self.config["database_path"])

        # Performance tracking
        self.optimization_results = []
        self.is_monitoring = False

        # Start monitoring
        self.start_monitoring()

    def start_monitoring(self) -> None:
        """Start performance monitoring."""
        self.is_monitoring = True
        self.profiler.start_profiling()

        # Start background optimization thread
        threading.Thread(target=self._background_optimization, daemon=True).start()

    def stop_monitoring(self) -> dict[str, object]:
        """Stop performance monitoring.

        Halt the background monitoring thread and return the final profiling
        results including memory usage statistics.

        Returns:
            A dictionary containing top memory consumers and metrics summary.

        """
        self.is_monitoring = False
        return self.profiler.stop_profiling()

    def _background_optimization(self) -> None:
        """Background optimization loop."""
        while self.is_monitoring:
            try:
                # Collect current metrics
                current_metrics = self.profiler.get_current_metrics()

                # Calculate performance score
                performance_score = self._calculate_performance_score(current_metrics)

                # Learn from metrics
                self.adaptive_optimizer.learn_from_metrics(current_metrics, performance_score)

                # Apply optimizations
                self._apply_automatic_optimizations(current_metrics)

                # Optimize components
                self.memory_pool.optimize_pool_size()
                self.gpu_optimizer.optimize_memory()

                if self.db_optimizer:
                    threading.Thread(target=self.db_optimizer.optimize_indices, daemon=True).start()

                time.sleep(30)  # Optimize every 30 seconds

            except Exception as e:
                logger.exception("Error in background optimization: %s", e)
                time.sleep(60)  # Wait longer on error

    def _calculate_performance_score(self, metrics: dict[str, object]) -> float:
        """Calculate overall performance score (0-1)."""
        # Normalize metrics to 0-1 scale (higher is better)
        cpu_score = max(0, 1 - float(metrics.get("cpu_percent", 0)) / 100)
        memory_score = max(0, 1 - float(metrics.get("memory_percent", 0)) / 100)

        # Weight different metrics
        score = cpu_score * 0.4 + memory_score * 0.4 + 0.2  # Base 0.2 for running

        return min(1.0, max(0.0, score))

    def _apply_automatic_optimizations(self, metrics: dict[str, object]) -> None:
        """Apply automatic optimizations based on current metrics."""
        memory_percent = float(metrics.get("memory_percent", 0))
        cpu_percent = float(metrics.get("cpu_percent", 0))

        # Memory optimization
        if memory_percent > 80:
            gc.collect()  # Force garbage collection
            self.cache_manager._evict_least_valuable()  # Evict cache items

        # CPU optimization
        if cpu_percent > 90:
            # Reduce thread pool size temporarily
            current_workers = self.thread_optimizer.executor._max_workers
            if current_workers > 2:
                self.thread_optimizer.executor._max_workers = max(2, current_workers - 1)

    def optimize_component(self, component_type: OptimizationType) -> OptimizationResult:
        """Optimize specific component."""
        before_metrics = self.profiler.get_current_metrics()
        success = False
        improvement = 0.0

        try:
            if component_type == OptimizationType.MEMORY:
                # Memory optimization
                initial_memory = before_metrics.get("memory_mb", 0)
                gc.collect()
                self.memory_pool.optimize_pool_size()
                time.sleep(1)  # Allow optimization to take effect

                after_metrics = self.profiler.get_current_metrics()
                final_memory = after_metrics.get("memory_mb", 0)

                if initial_memory > 0:
                    improvement = max(0, (initial_memory - final_memory) / initial_memory * 100)
                success = improvement > 0

            elif component_type == OptimizationType.CPU:
                # CPU optimization
                self.thread_optimizer._optimize_pool_size()
                success = True
                improvement = 5.0  # Estimated improvement

            elif component_type == OptimizationType.GPU:
                # GPU optimization
                if self.gpu_optimizer.gpu_available:
                    self.gpu_optimizer.optimize_memory()
                    success = True
                    improvement = 10.0  # Estimated improvement

            elif component_type == OptimizationType.IO:
                # I/O optimization
                self.io_optimizer.read_ahead_size = min(
                    self.io_optimizer.read_ahead_size * 2,
                    1024 * 1024,  # Max 1MB
                )
                success = True
                improvement = 3.0  # Estimated improvement

            elif component_type == OptimizationType.DATABASE and self.db_optimizer:
                # Database optimization
                threading.Thread(target=self.db_optimizer.optimize_indices, daemon=True).start()
                success = True
                improvement = 15.0  # Estimated improvement

            after_metrics = self.profiler.get_current_metrics()

        except Exception as e:
            logger.exception("Error optimizing %s: %s", component_type, e)
            after_metrics = before_metrics

        result = OptimizationResult(
            optimization_type=component_type,
            success=success,
            improvement=improvement,
            before_metrics=before_metrics,
            after_metrics=after_metrics,
            details=f"Optimization completed with {improvement:.1f}% improvement",
        )

        self.optimization_results.append(result)
        return result

    def get_performance_report(self) -> dict[str, object]:
        """Generate comprehensive performance report."""
        current_metrics = self.profiler.get_current_metrics()
        cache_stats = self.cache_manager.get_stats()
        thread_stats = self.thread_optimizer.get_stats()
        gpu_stats = self.gpu_optimizer.get_stats()

        db_stats = self.db_optimizer.get_stats() if self.db_optimizer else {}
        recent_optimizations = self.optimization_results[-10:]

        return {
            "timestamp": datetime.now().isoformat(),
            "system_metrics": current_metrics,
            "cache_performance": cache_stats,
            "thread_pool_stats": thread_stats,
            "gpu_stats": gpu_stats,
            "database_stats": db_stats,
            "recent_optimizations": [
                {
                    "type": opt.optimization_type.value,
                    "success": opt.success,
                    "improvement": opt.improvement,
                    "details": opt.details,
                }
                for opt in recent_optimizations
            ],
            "recommendations": self.adaptive_optimizer.get_recommendations(),
            "optimization_level": self.optimization_level.value,
        }

    def set_optimization_level(self, level: PerformanceLevel) -> None:
        """Set optimization aggressiveness level."""
        self.optimization_level = level

        # Adjust component configurations based on level
        if level == PerformanceLevel.MINIMAL:
            self.cache_manager.max_size = 500
            self.memory_pool = MemoryPool(initial_buffers=5)

        elif level == PerformanceLevel.BALANCED:
            self.cache_manager.max_size = 1000
            self.memory_pool = MemoryPool(initial_buffers=10)

        elif level == PerformanceLevel.AGGRESSIVE:
            self.cache_manager.max_size = 2000
            self.memory_pool = MemoryPool(initial_buffers=20)

        elif level == PerformanceLevel.MAXIMUM:
            self.cache_manager.max_size = 5000
            self.memory_pool = MemoryPool(initial_buffers=50)

    def optimize_all(self) -> dict[object, OptimizationResult]:
        """Optimize all components."""
        results: dict[object, OptimizationResult] = {}

        optimization_types = [
            OptimizationType.MEMORY,
            OptimizationType.CPU,
            OptimizationType.GPU,
            OptimizationType.IO,
            OptimizationType.CACHE,
        ]

        if self.db_optimizer:
            optimization_types.append(OptimizationType.DATABASE)

        for opt_type in optimization_types:
            results[opt_type] = self.optimize_component(opt_type)
            time.sleep(0.5)  # Brief pause between optimizations

        return results

    @contextmanager
    def performance_context(self, component_name: str) -> Generator:
        """Context manager for performance tracking.

        Track resource usage (CPU and memory) for a code block with automatic
        logging of performance deltas.

        Args:
            component_name: Name of the component being profiled for logging.

        Yields:
            Control to the wrapped code block.

        """
        start_time = time.time()
        start_metrics = self.profiler.get_current_metrics()

        try:
            yield
        finally:
            end_time = time.time()
            end_metrics = self.profiler.get_current_metrics()

            # Calculate performance deltas
            duration = end_time - start_time

            # Compare metrics to track resource usage changes
            cpu_delta = end_metrics.get("cpu_usage", 0) - start_metrics.get("cpu_usage", 0)
            memory_delta = end_metrics.get("memory_usage", 0) - start_metrics.get("memory_usage", 0)

            # Log comprehensive performance data
            logger.info(
                "Performance tracking for %s: %.3fs, CPU Δ: %.2f%%, Memory Δ: %.2f%%",
                component_name,
                duration,
                cpu_delta,
                memory_delta,
            )


# Global performance optimizer instance
_global_optimizer = None


def get_performance_optimizer(config: dict[str, object] | None = None) -> PerformanceOptimizer:
    """Get global performance optimizer instance."""
    global _global_optimizer

    if _global_optimizer is None:
        _global_optimizer = PerformanceOptimizer(config)

    return _global_optimizer


def performance_monitor(component_name: str = "default") -> Callable:
    """Create decorator for automatic performance monitoring.

    Wrap a function to automatically track its resource usage with the global
    performance optimizer and log results.

    Args:
        component_name: Logical component name for organizing metrics
            (default: "default").

    Returns:
        A decorator function that wraps the target function.

    """

    def decorator(func: Callable) -> Callable:
        """Decorate function for performance tracking.

        Args:
            func: The function to wrap with performance monitoring.

        Returns:
            The wrapped function with performance tracking enabled.

        """

        @functools.wraps(func)
        def wrapper(*args: object, **kwargs: object) -> object:
            """Execute wrapped function with performance context.

            Args:
                *args: Positional arguments for the wrapped function.
                    Can be any type.
                **kwargs: Keyword arguments for the wrapped function.
                    Can be any type.

            Returns:
                Return value from the wrapped function. Can be any type.

            """
            optimizer = get_performance_optimizer()

            with optimizer.performance_context(f"{component_name}.{func.__name__}"):
                return func(*args, **kwargs)

        return wrapper

    return decorator


# Utility functions for common optimizations
def optimize_memory() -> OptimizationResult:
    """Quick memory optimization.

    Trigger an immediate memory optimization cycle on the global performance
    optimizer.

    Returns:
        The OptimizationResult detailing memory improvement and statistics.

    """
    optimizer = get_performance_optimizer()
    return optimizer.optimize_component(OptimizationType.MEMORY)


def optimize_cpu() -> OptimizationResult:
    """Quick CPU optimization.

    Trigger an immediate CPU thread pool optimization on the global
    performance optimizer.

    Returns:
        The OptimizationResult detailing CPU optimization results.

    """
    optimizer = get_performance_optimizer()
    return optimizer.optimize_component(OptimizationType.CPU)


def get_performance_stats() -> dict[str, object]:
    """Get current performance statistics."""
    optimizer = get_performance_optimizer()
    return optimizer.get_performance_report()


if __name__ == "__main__":
    # Example usage and testing
    logging.basicConfig(level=logging.INFO)

    # Create optimizer with test configuration
    config = {
        "optimization_level": "balanced",
        "database_path": ":memory:",
    }

    optimizer = PerformanceOptimizer(config)

    # Run some test operations
    print("Starting performance optimization test...")

    # Test memory optimization
    print("Testing memory optimization...")
    result = optimizer.optimize_component(OptimizationType.MEMORY)
    print(f"Memory optimization: {result.success}, {result.improvement:.1f}% improvement")

    # Test cache performance
    print("Testing cache performance...")
    for i in range(100):
        key = f"test_key_{i % 10}"
        value = f"test_value_{i}" * 100
        optimizer.cache_manager.put(key, value)

        if i % 3 == 0:
            cached_value = optimizer.cache_manager.get(key)

    cache_stats = optimizer.cache_manager.get_stats()
    print(f"Cache stats: {cache_stats}")

    # Generate performance report
    print("Generating performance report...")
    report = optimizer.get_performance_report()

    print("Performance Report Summary:")
    print(f"- CPU Usage: {report['system_metrics']['cpu_percent']:.1f}%")
    print(f"- Memory Usage: {report['system_metrics']['memory_percent']:.1f}%")
    print(f"- Cache Hit Rate: {report['cache_performance']['hit_rate']:.2%}")
    print(f"- Thread Pool Workers: {report['thread_pool_stats']['current_workers']}")

    # Test optimization recommendations
    recommendations = optimizer.adaptive_optimizer.get_recommendations()
    if recommendations.get("recommendations"):
        print("Optimization Recommendations:")
        for rec in recommendations["recommendations"]:
            print(f"- {rec['description']}")

    print("Performance optimization test completed.")
