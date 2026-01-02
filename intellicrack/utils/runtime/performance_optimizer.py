"""Performance Optimizer for Large Binary Analysis.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import gc
import hashlib
import logging
import mmap
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)

__all__ = [
    "AdaptiveAnalyzer",
    "BinaryChunker",
    "CacheManager",
    "MemoryManager",
    "PerformanceOptimizer",
]


class MemoryManager:
    """Manages memory usage during large binary analysis."""

    def __init__(self, max_memory_mb: int = 2048) -> None:
        """Initialize memory manager with specified memory limit and usage tracking.

        Args:
            max_memory_mb: Maximum allowed memory usage in megabytes.
        """
        self.max_memory_mb = max_memory_mb
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.current_usage = 0
        self.memory_lock = threading.Lock()

    def check_memory_usage(self) -> dict[str, float]:
        """Check current memory usage and availability.

        Retrieves memory statistics from the current process using psutil,
        including resident set size (RSS), virtual memory size (VMS), and
        percentage of available system memory.

        Returns:
            Memory usage dictionary with keys:
                - rss_mb: Resident set size in megabytes
                - vms_mb: Virtual memory size in megabytes
                - percent: Memory usage percentage
                - available_mb: Available memory in megabytes
        """
        try:
            from intellicrack.handlers.psutil_handler import psutil

            process = psutil.Process()
            memory_info = process.memory_info()

            return {
                "rss_mb": float(memory_info.rss / 1024 / 1024),
                "vms_mb": float(memory_info.vms / 1024 / 1024),
                "percent": float(process.memory_percent()),
                "available_mb": float((self.max_memory_bytes - memory_info.rss) / 1024 / 1024),
            }
        except ImportError as e:
            logger.exception("Import error in performance_optimizer: %s", e, exc_info=True)
            return {
                "rss_mb": 0.0,
                "vms_mb": 0.0,
                "percent": 0.0,
                "available_mb": float(self.max_memory_mb),
            }

    def should_limit_analysis(self) -> bool:
        """Check if analysis should be limited due to memory constraints.

        Compares current resident set size against the configured maximum memory
        threshold (80% of max_memory_mb) to determine if analysis should be
        throttled or limited.

        Returns:
            True if memory usage exceeds 80% threshold, False otherwise.
        """
        memory_info = self.check_memory_usage()
        return memory_info["rss_mb"] > (self.max_memory_mb * 0.8)

    def cleanup_memory(self) -> None:
        """Force garbage collection and memory cleanup.

        Triggers Python garbage collection to reclaim memory from unreferenced
        objects, helping reduce memory pressure during long-running analysis
        tasks.
        """
        gc.collect()

    def get_recommended_chunk_size(self, file_size: int) -> int:
        """Get recommended chunk size based on available memory.

        Calculates an optimal chunk size for binary analysis by considering
        available memory and file size. The recommended size is 1/4 of available
        memory but clamped between 1MB and 100MB, and never exceeds 1/10 of the
        file size.

        Args:
            file_size: Total size of the binary file in bytes.

        Returns:
            Recommended chunk size in bytes.
        """
        memory_info = self.check_memory_usage()
        available_mb = memory_info["available_mb"]

        # Use 1/4 of available memory for chunk size, but limit between 1MB and 100MB
        chunk_size = int(available_mb * 0.25 * 1024 * 1024)
        chunk_size = max(1024 * 1024, min(chunk_size, 100 * 1024 * 1024))

        # Don't exceed 1/10 of file size
        max_chunk = file_size // 10
        if max_chunk > 0:
            chunk_size = min(chunk_size, max_chunk)

        return chunk_size


class BinaryChunker:
    """Efficiently processes large binaries in chunks."""

    def __init__(self, memory_manager: MemoryManager) -> None:
        """Initialize binary chunker with memory manager for efficient data processing.

        Args:
            memory_manager: MemoryManager instance for memory-aware chunking.
        """
        self.memory_manager = memory_manager

    def chunk_binary(self, file_path: str, chunk_size: int | None = None) -> list[dict[str, Any]]:
        """Split binary into manageable chunks for analysis.

        Args:
            file_path: Path to binary file.
            chunk_size: Size of each chunk in bytes (auto-calculated if None).

        Returns:
            List of chunk metadata dictionaries.
        """
        file_path_obj = Path(file_path)
        file_size = file_path_obj.stat().st_size

        if chunk_size is None:
            chunk_size = self.memory_manager.get_recommended_chunk_size(file_size)

        chunks: list[dict[str, Any]] = []
        offset = 0
        chunk_id = 0

        while offset < file_size:
            remaining = file_size - offset
            current_chunk_size = min(chunk_size, remaining)

            chunk_info: dict[str, Any] = {
                "id": chunk_id,
                "offset": offset,
                "size": current_chunk_size,
                "end_offset": offset + current_chunk_size,
                "file_path": str(file_path_obj),
                "file_size": file_size,
                "is_last": (offset + current_chunk_size >= file_size),
            }

            chunks.append(chunk_info)
            offset += current_chunk_size
            chunk_id += 1

        logger.info("Split %s into %s chunks of ~%sMB each", file_path_obj.name, len(chunks), chunk_size // 1024 // 1024)
        return chunks

    def read_chunk(self, chunk_info: dict[str, Any]) -> bytes:
        """Read a specific chunk from the binary.

        Seeks to the specified offset in the binary file and reads the requested
        number of bytes. Returns empty bytes on read failure.

        Args:
            chunk_info: Dictionary containing file_path, offset, and size keys.

        Returns:
            Raw binary data from the chunk, or empty bytes on error.
        """
        try:
            file_path_str = str(chunk_info["file_path"])
            offset_val = int(chunk_info["offset"])
            size_val = int(chunk_info["size"])
            with open(file_path_str, "rb") as f:
                f.seek(offset_val)
                return f.read(size_val)
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error reading chunk %s: %s", chunk_info["id"], e, exc_info=True)
            return b""

    def analyze_chunk_parallel(
        self, chunks: list[dict[str, Any]], analysis_func: Callable[[dict[str, Any]], dict[str, Any]], max_workers: int = 4
    ) -> list[dict[str, Any]]:
        """Analyze chunks in parallel with controlled concurrency.

        Distributes chunk analysis across worker threads, monitors memory usage,
        and gracefully handles failures in individual chunks without stopping
        overall analysis.

        Args:
            chunks: List of chunk metadata dictionaries.
            analysis_func: Function to analyze each chunk, receives chunk dict.
            max_workers: Maximum number of concurrent worker threads.

        Returns:
            Sorted list of analysis results for each chunk,
                with chunk_id added to each result.
        """
        results: list[dict[str, Any]] = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_chunk: dict[Future[dict[str, Any]], dict[str, Any]] = {
                executor.submit(analysis_func, chunk_): chunk_ for chunk_ in chunks
            }

            for future in as_completed(future_to_chunk):
                chunk = future_to_chunk[future]
                try:
                    result = future.result()
                    result["chunk_id"] = chunk["id"]
                    results.append(result)

                    if self.memory_manager.should_limit_analysis():
                        logger.warning("Memory usage high, cleaning up...")
                        self.memory_manager.cleanup_memory()

                except (OSError, ValueError, RuntimeError) as e:
                    logger.exception("Error analyzing chunk %s: %s", chunk["id"], e, exc_info=True)
                    results.append(
                        {
                            "chunk_id": chunk["id"],
                            "error": str(e),
                            "status": "failed",
                        },
                    )

        results.sort(key=lambda x: int(x.get("chunk_id", 0)))
        return results


class CacheManager:
    """Manages caching of analysis results for performance."""

    def __init__(self, cache_dir: str = "cache") -> None:
        """Initialize cache manager with directory setup and threading synchronization.

        Args:
            cache_dir: Directory path for storing cached analysis results.
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.memory_cache: dict[str, dict[str, Any]] = {}
        self.cache_lock = threading.Lock()

    def get_file_hash(self, file_path: str) -> str:
        """Get hash of file for cache key.

        Computes a SHA256-based hash of the file by hashing the first 64KB,
        last 64KB, and file size. This provides a quick but reasonably unique
        identifier for caching purposes.

        Args:
            file_path: Path to the file to hash.

        Returns:
            16-character hexadecimal hash string.
        """
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Hash first and last 64KB + file size for speed
            hasher.update(f.read(65536))  # First 64KB
            f.seek(-min(65536, f.tell()), 2)  # Last 64KB
            hasher.update(f.read())

        file_size = Path(file_path).stat().st_size
        hasher.update(str(file_size).encode())

        return hasher.hexdigest()[:16]  # Use first 16 chars

    def get_cache_key(self, file_path: str, analysis_type: str) -> str:
        """Generate cache key for analysis result.

        Combines the analysis type with the file hash to create a unique cache
        key that identifies a specific analysis result for a file.

        Args:
            file_path: Path to the analyzed file.
            analysis_type: Type or name of the analysis.

        Returns:
            Cache key in format "{analysis_type}_{file_hash}".
        """
        file_hash = self.get_file_hash(file_path)
        return f"{analysis_type}_{file_hash}"

    def get_cached_result(self, file_path: str, analysis_type: str) -> dict[str, Any] | None:
        """Get cached analysis result if available.

        Attempts to retrieve cached analysis results from in-memory cache first,
        then from disk cache if not found in memory. Thread-safe.

        Args:
            file_path: Path to the analyzed file.
            analysis_type: Type or name of the analysis.

        Returns:
            Cached analysis result if found, None otherwise.
        """
        cache_key = self.get_cache_key(file_path, analysis_type)

        with self.cache_lock:
            if cache_key in self.memory_cache:
                return self.memory_cache[cache_key]

        cache_file = self.cache_dir / f"{cache_key}.json"
        if cache_file.exists():
            try:
                import json

                with open(cache_file, encoding="utf-8") as f:
                    result: dict[str, Any] = json.load(f)

                with self.cache_lock:
                    self.memory_cache[cache_key] = result

                return result
            except (OSError, ValueError, RuntimeError) as e:
                logger.warning("Error reading cache file %s: %s", cache_file, e, exc_info=True)

        return None

    def cache_result(self, file_path: str, analysis_type: str, result: dict[str, Any]) -> None:
        """Cache analysis result.

        Stores analysis result in both in-memory and disk cache. Thread-safe
        for in-memory cache updates. Disk cache saves as JSON.

        Args:
            file_path: Path to the analyzed file.
            analysis_type: Type or name of the analysis.
            result: Analysis result dictionary to cache.
        """
        cache_key = self.get_cache_key(file_path, analysis_type)

        # Add to memory cache
        with self.cache_lock:
            self.memory_cache[cache_key] = result

        # Save to disk cache
        cache_file = self.cache_dir / f"{cache_key}.json"
        try:
            import json

            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, default=str)
        except (OSError, ValueError, RuntimeError) as e:
            logger.warning("Error writing cache file %s: %s", cache_file, e, exc_info=True)

    def clear_cache(self) -> None:
        """Clear all cached results.

        Removes all cached analysis results from both in-memory and disk cache.
        Thread-safe for in-memory cache operations.
        """
        with self.cache_lock:
            self.memory_cache.clear()

        # Remove disk cache files
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                cache_file.unlink()
            except (OSError, ValueError, RuntimeError) as e:
                logger.warning("Error removing cache file %s: %s", cache_file, e, exc_info=True)


class AdaptiveAnalyzer:
    """Provides adaptive analysis strategies based on binary characteristics."""

    def __init__(self, memory_manager: MemoryManager, cache_manager: CacheManager) -> None:
        """Initialize adaptive analyzer with memory and cache management for optimized binary analysis.

        Args:
            memory_manager: MemoryManager instance for memory tracking.
            cache_manager: CacheManager instance for result caching.
        """
        self.memory_manager = memory_manager
        self.cache_manager = cache_manager

    def get_analysis_strategy(self, file_path: str) -> dict[str, Any]:
        """Determine optimal analysis strategy for the binary.

        Analyzes file size and available memory to determine whether to use
        chunking, sampling, and other optimizations. Identifies high-priority
        sections like PE headers and licensing code regions.

        Args:
            file_path: Path to binary file to analyze.

        Returns:
            Strategy dictionary with keys: file_size_mb,
                memory_available_mb, use_chunking, chunk_size_mb, max_workers,
                skip_heavy_analysis, use_sampling, sample_rate, priority_sections.
        """
        file_size = Path(file_path).stat().st_size
        memory_info = self.memory_manager.check_memory_usage()

        strategy: dict[str, Any] = {
            "file_size_mb": file_size / 1024 / 1024,
            "memory_available_mb": memory_info["available_mb"],
            "use_chunking": False,
            "chunk_size_mb": 50,
            "max_workers": 4,
            "skip_heavy_analysis": False,
            "use_sampling": False,
            "sample_rate": 1.0,
            "priority_sections": [],
        }

        if file_size > 500 * 1024 * 1024:
            strategy["use_chunking"] = True
            strategy["chunk_size_mb"] = 100
            strategy["skip_heavy_analysis"] = True
            strategy["use_sampling"] = True
            strategy["sample_rate"] = 0.1

        elif file_size > 100 * 1024 * 1024:
            strategy["use_chunking"] = True
            strategy["chunk_size_mb"] = 50
            strategy["use_sampling"] = True
            strategy["sample_rate"] = 0.3

        elif file_size > 50 * 1024 * 1024:
            strategy["use_chunking"] = True
            strategy["chunk_size_mb"] = 25

        if memory_info["available_mb"] < 1024:
            strategy["max_workers"] = 2
            current_chunk_size = int(strategy["chunk_size_mb"])
            strategy["chunk_size_mb"] = min(current_chunk_size, 25)
            strategy["skip_heavy_analysis"] = True

        strategy["priority_sections"] = self._identify_priority_sections(file_path)

        return strategy

    def _identify_priority_sections(self, file_path: str) -> list[dict[str, Any]]:
        """Identify important sections to prioritize during analysis.

        Scans the binary header for PE format markers and searches the end of
        the file for licensing-related keywords to identify high-priority
        analysis regions.

        Args:
            file_path: Path to the binary file to analyze.

        Returns:
            List of priority sections with name, offset,
                size, and priority level.
        """
        priority_sections: list[dict[str, Any]] = []

        try:
            with open(file_path, "rb") as f:
                f.seek(0)
                header_data = f.read(1024)
                if header_data.startswith(b"MZ"):
                    priority_sections.append(
                        {
                            "name": "PE_Header",
                            "offset": 0,
                            "size": 1024,
                            "priority": "high",
                        },
                    )

                file_size = Path(file_path).stat().st_size
                if file_size > 10000:
                    f.seek(max(0, file_size - 10000))
                    end_data = f.read(10000)

                    license_keywords = [b"license", b"serial", b"key", b"activation", b"trial"]
                    for keyword in license_keywords:
                        if keyword in end_data.lower():
                            offset = max(0, file_size - 10000)
                            priority_sections.append(
                                {
                                    "name": f"License_Section_{keyword.decode()}",
                                    "offset": offset,
                                    "size": 10000,
                                    "priority": "high",
                                },
                            )
                            break

        except (OSError, ValueError, RuntimeError) as e:
            logger.warning("Error identifying priority sections: %s", e, exc_info=True)

        return priority_sections


class PerformanceOptimizer:
    """Run performance optimization controller."""

    def __init__(self, max_memory_mb: int = 2048, cache_dir: str = "cache") -> None:
        """Initialize the performance optimizer.

        Args:
            max_memory_mb: Maximum memory limit in MB
            cache_dir: Directory for cache storage

        """
        self.memory_manager = MemoryManager(max_memory_mb)
        self.cache_manager = CacheManager(cache_dir)
        self.binary_chunker = BinaryChunker(self.memory_manager)
        self.adaptive_analyzer = AdaptiveAnalyzer(self.memory_manager, self.cache_manager)

    def optimize_analysis(self, file_path: str, analysis_functions: list[Callable[..., dict[str, Any]]]) -> dict[str, Any]:
        """Perform optimized analysis of a large binary.

        Orchestrates analysis of a binary file with adaptive chunking strategies,
        caching, memory management, and performance tracking. Selects optimal
        analysis strategy based on file size and available memory.

        Args:
            file_path: Path to binary file to analyze.
            analysis_functions: List of analysis functions to run.

        Returns:
            Comprehensive analysis results including strategy,
                analysis_results, performance_metrics, and cache statistics.
        """
        start_time = time.time()

        strategy = self.adaptive_analyzer.get_analysis_strategy(file_path)

        logger.info("Analysis strategy for %s:", Path(file_path).name)
        logger.info("  File size: %.1fMB", float(strategy["file_size_mb"]))
        logger.info("  Use chunking: %s", strategy["use_chunking"])
        logger.info("  Sampling rate: %.1f%%", float(strategy["sample_rate"]) * 100)

        results: dict[str, Any] = {
            "file_path": file_path,
            "strategy": strategy,
            "analysis_results": {},
            "performance_metrics": {},
            "cache_hits": 0,
            "cache_misses": 0,
        }

        for analysis_func in analysis_functions:
            func_name = analysis_func.__name__

            if cached_result := self.cache_manager.get_cached_result(file_path, func_name):
                results["analysis_results"][func_name] = cached_result
                results["cache_hits"] = int(results["cache_hits"]) + 1
                logger.info("Using cached result for %s", func_name)
                continue

            results["cache_misses"] = int(results["cache_misses"]) + 1

            func_start = time.time()

            try:
                use_chunking = bool(strategy["use_chunking"])
                if use_chunking:
                    result = self._run_chunked_analysis(file_path, analysis_func, strategy)
                else:
                    result = self._run_standard_analysis(file_path, analysis_func, strategy)

                results["analysis_results"][func_name] = result

                self.cache_manager.cache_result(file_path, func_name, result)

            except (OSError, ValueError, RuntimeError) as e:
                logger.exception("Error in %s: %s", func_name, e, exc_info=True)
                results["analysis_results"][func_name] = {
                    "error": str(e),
                    "status": "failed",
                }

            func_time = time.time() - func_start
            results["performance_metrics"][func_name] = {
                "execution_time": func_time,
                "memory_peak": self.memory_manager.check_memory_usage()["rss_mb"],
            }

            self.memory_manager.cleanup_memory()

        total_time = time.time() - start_time
        results["performance_metrics"]["total_time"] = total_time
        cache_hits = int(results["cache_hits"])
        cache_misses = int(results["cache_misses"])
        results["performance_metrics"]["cache_efficiency"] = (
            cache_hits / (cache_hits + cache_misses) if (cache_hits + cache_misses) > 0 else 0.0
        )

        logger.info("Analysis completed in %fs", total_time)
        logger.info("Cache efficiency: %.1f%%", float(results["performance_metrics"]["cache_efficiency"]) * 100)

        return results

    def _run_chunked_analysis(
        self, file_path: str, analysis_func: Callable[..., dict[str, Any]], strategy: dict[str, Any]
    ) -> dict[str, Any]:
        """Run analysis on binary chunks.

        Divides the binary into chunks and analyzes each chunk in parallel,
        optionally applying sampling to reduce analysis time on very large
        files. Aggregates results across all chunks.

        Args:
            file_path: Path to binary file to analyze.
            analysis_func: Analysis function to apply to each chunk.
            strategy: Strategy dictionary containing chunk_size_mb, use_sampling,
                sample_rate, and max_workers parameters.

        Returns:
            Aggregated analysis results with chunk_summaries,
                combined_results, chunks_analyzed, and sampling_rate.
        """
        chunk_size_mb = float(strategy["chunk_size_mb"])
        chunk_size = int(chunk_size_mb * 1024 * 1024)
        chunks = self.binary_chunker.chunk_binary(file_path, chunk_size)

        use_sampling = bool(strategy["use_sampling"])
        sample_rate = float(strategy["sample_rate"])
        if use_sampling and sample_rate < 1.0:
            sample_count = max(1, int(len(chunks) * sample_rate))
            step = len(chunks) // sample_count
            chunks = [chunks[i] for i in range(0, len(chunks), step)][:sample_count]

        def analyze_chunk(chunk_info: dict[str, Any]) -> dict[str, Any]:
            """Analyze a single chunk of binary data.

            Reads the chunk from disk and applies the configured analysis function.

            Args:
                chunk_info: Dictionary containing chunk metadata (file_path, offset, size).

            Returns:
                Analysis result from the analysis function, or error dict.
            """
            chunk_data = self.binary_chunker.read_chunk(chunk_info)
            if chunk_data:
                return analysis_func(chunk_data, chunk_info)
            return {"error": "Failed to read chunk", "status": "failed"}

        max_workers = int(strategy["max_workers"])
        chunk_results = self.binary_chunker.analyze_chunk_parallel(
            chunks,
            analyze_chunk,
            max_workers,
        )

        aggregated_result = self._aggregate_chunk_results(chunk_results, analysis_func.__name__)
        aggregated_result["chunks_analyzed"] = len(chunks)
        aggregated_result["sampling_rate"] = sample_rate

        return aggregated_result

    def _run_standard_analysis(
        self, file_path: str, analysis_func: Callable[..., dict[str, Any]], strategy: dict[str, Any]
    ) -> dict[str, Any]:
        """Run standard analysis on entire file.

        Loads the entire file into memory using memory-mapped I/O for efficiency,
        and applies the analysis function to the full binary. Falls back to
        regular file reading if memory mapping fails.

        Args:
            file_path: Path to binary file to analyze.
            analysis_func: Analysis function to apply to the full binary data.
            strategy: Strategy dictionary (unused for standard analysis).

        Returns:
            Analysis results from the analysis function.
        """
        _ = strategy
        try:
            with (
                open(file_path, "rb") as f,
                mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm,
            ):
                return analysis_func(mm)
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error in performance_optimizer: %s", e, exc_info=True)
            with open(file_path, "rb") as f:
                data = f.read()
                return analysis_func(data)

    def _aggregate_chunk_results(self, chunk_results: list[dict[str, Any]], analysis_name: str) -> dict[str, Any]:
        """Aggregate results from multiple chunks.

        Combines individual chunk analysis results into a consolidated report,
        tallying successful chunks and merging findings across all chunks.

        Args:
            chunk_results: List of analysis results from each chunk.
            analysis_name: Name of the analysis type being aggregated.

        Returns:
            Aggregated dictionary with analysis_type,
                chunks_processed, successful_chunks, combined_results,
                and chunk_summaries.
        """
        aggregated: dict[str, Any] = {
            "analysis_type": analysis_name,
            "chunks_processed": len(chunk_results),
            "successful_chunks": len([r for r in chunk_results if r.get("status") != "failed"]),
            "combined_results": {},
            "chunk_summaries": [],
        }

        for result in chunk_results:
            if result.get("status") != "failed":
                findings_val = result.get("findings", [])
                findings_count = len(findings_val) if isinstance(findings_val, list) else 0
                chunk_summary: dict[str, Any] = {
                    "chunk_id": result.get("chunk_id"),
                    "findings_count": findings_count,
                    "notable_items": result.get("notable_items", []),
                }
                aggregated["chunk_summaries"].append(chunk_summary)

                if "findings" not in aggregated["combined_results"]:
                    aggregated["combined_results"]["findings"] = []
                result_findings = result.get("findings", [])
                if isinstance(result_findings, list):
                    aggregated["combined_results"]["findings"].extend(result_findings)

        return aggregated


def create_performance_optimizer(max_memory_mb: int = 2048, cache_dir: str = "cache") -> PerformanceOptimizer:
    """Create a performance optimizer.

    Factory function to instantiate a PerformanceOptimizer with specified memory
    and cache configuration.

    Args:
        max_memory_mb: Maximum memory limit in megabytes for analysis.
        cache_dir: Directory path for storing cached analysis results.

    Returns:
        Configured optimizer instance ready for use.
    """
    return PerformanceOptimizer(max_memory_mb, cache_dir)


def example_string_analysis(data: bytes | mmap.mmap, chunk_info: dict[str, Any] | None = None) -> dict[str, Any]:
    """Demonstrate string analysis function.

    Extracts ASCII strings from binary data, either by scanning mmap objects
    directly or using the core string extraction utility. Returns up to 100
    found strings with metadata.

    Args:
        data: Binary data to analyze as bytes or memory-mapped file.
        chunk_info: Optional chunk metadata for tracking chunk-level analysis.

    Returns:
        Result dictionary with status, findings list, total_strings
            count, and optional chunk metadata (chunk_id, chunk_offset, chunk_size).
    """
    result_metadata: dict[str, Any] = {}
    if chunk_info:
        data_len = len(data) if hasattr(data, "__len__") else 0
        result_metadata = {
            "chunk_id": chunk_info.get("id", "unknown"),
            "chunk_offset": chunk_info.get("offset", 0),
            "chunk_size": chunk_info.get("size", data_len),
        }

    strings: list[str] = []
    if isinstance(data, mmap.mmap):
        for i in range(0, len(data), 1024 * 1024):
            chunk = data[i : i + 1024 * 1024]
            current_string = ""
            for byte in chunk:
                if 32 <= byte <= 126:
                    current_string += chr(byte)
                else:
                    if len(current_string) >= 4:
                        strings.append(current_string)
                    current_string = ""
    else:
        from ..core.string_utils import extract_ascii_strings

        strings = extract_ascii_strings(data)

    result: dict[str, Any] = {
        "status": "success",
        "findings": strings[:100],
        "total_strings": len(strings),
    } | result_metadata
    return result


def example_entropy_analysis(data: bytes | mmap.mmap, chunk_info: dict[str, Any] | None = None) -> dict[str, Any]:
    """Demonstrate entropy analysis function.

    Calculates Shannon entropy of binary data to detect compression or encryption.
    Analyzes up to 1MB of data (sample-based approach). Entropy values closer to
    8.0 indicate high randomness/compression, while low values indicate structured
    or readable data.

    Args:
        data: Binary data to analyze as bytes or memory-mapped file.
        chunk_info: Optional chunk metadata for tracking chunk-level analysis.

    Returns:
        Result dictionary with status, entropy value, sample_size,
            findings list, and optional chunk metadata (chunk_id, chunk_offset,
            chunk_size, analysis_region).
    """
    result_metadata: dict[str, Any] = {}
    if chunk_info:
        data_len = len(data) if hasattr(data, "__len__") else 0
        result_metadata = {
            "chunk_id": chunk_info.get("id", "unknown"),
            "chunk_offset": chunk_info.get("offset", 0),
            "chunk_size": chunk_info.get("size", data_len),
            "analysis_region": f"Offset {chunk_info.get('offset', 0)} - {chunk_info.get('end_offset', 'unknown')}",
        }

    if isinstance(data, mmap.mmap):
        sample_size = min(1024 * 1024, len(data))
        sample_data = data[:sample_size]
    else:
        sample_data = data[: 1024 * 1024]

    if len(sample_data) == 0:
        return {"status": "failed", "error": "No data to analyze"}

    byte_counts = [0] * 256
    for byte in sample_data:
        byte_counts[byte] += 1

    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / len(sample_data)
            import math

            entropy -= p * math.log2(p)

    result: dict[str, Any] = {
        "status": "success",
        "entropy": entropy,
        "sample_size": len(sample_data),
        "findings": [f"Entropy: {entropy:.2f}"],
    } | result_metadata
    return result
