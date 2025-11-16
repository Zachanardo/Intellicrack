"""Memory loader for loading binary data into memory for analysis."""

import logging
import math
import mmap
import os
import types
from collections.abc import Iterator
from typing import Any

from intellicrack.utils.logger import logger

"""
Memory-Optimized Binary Loader

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


try:
    from intellicrack.handlers.psutil_handler import psutil

    HAS_PSUTIL = True
except ImportError as e:
    logger.error("Import error in memory_loader: %s", e)
    HAS_PSUTIL = False

__all__ = ["MemoryOptimizedBinaryLoader", "run_memory_optimized_analysis"]


class MemoryOptimizedBinaryLoader:
    """Memory-efficient binary file loader for analyzing large executables.

    Uses memory mapping, partial loading, and caching strategies to minimize
    memory usage while providing efficient access to binary data.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialize the memory optimized binary loader.

        Args:
            config: Configuration dictionary with optional settings:
                - chunk_size: Size of data chunks in bytes (default: 1MB)
                - max_memory: Maximum memory usage in bytes (default: 1GB)

        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.chunk_size = self.config.get("chunk_size", 1024 * 1024)  # 1MB chunks
        self.max_memory = self.config.get("max_memory", 1024 * 1024 * 1024)  # 1GB max
        self.current_file: object | None = None
        self.file_size = 0
        self.mapped_file: mmap.mmap | None = None
        self.section_cache: dict[str, bytes] = {}

    def load_file(self, file_path: str) -> bool:
        """Load a binary file with memory optimization.

        Args:
            file_path: Path to the binary file to load

        Returns:
            True if file loaded successfully, False otherwise

        """
        if not os.path.exists(file_path):
            self.logger.error("File not found: %s", file_path)
            return False

        try:
            # Close previous file if open
            self.close()

            # Open file (closed in self.close() method)
            self.current_file = open(file_path, "rb")  # noqa: SIM115, pylint: disable=consider-using-with
            self.file_size = os.path.getsize(file_path)

            # Memory map the file
            self.mapped_file = mmap.mmap(
                self.current_file.fileno(),
                0,  # Map entire file
                access=mmap.ACCESS_READ,  # Read-only
            )

            self.logger.info(f"Loaded file: {file_path} ({self._format_size(self.file_size)})")
            return True

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error loading file: %s", e)
            self.close()
            return False

    def close(self) -> None:
        """Close the current file and release resources."""
        # Clear section cache
        self.section_cache.clear()

        # Close memory map
        if self.mapped_file:
            try:
                self.mapped_file.close()
            except (OSError, ValueError, RuntimeError) as e:
                self.logger.error("Error in memory_loader: %s", e)
            self.mapped_file = None

        # Close file
        if self.current_file:
            try:
                self.current_file.close()
            except (OSError, ValueError, RuntimeError) as e:
                self.logger.error("Error in memory_loader: %s", e)
            self.current_file = None

        self.file_size = 0

    def read_chunk(self, offset: int, size: int) -> bytes | None:
        """Read a chunk of data from the file.

        Args:
            offset: Byte offset in the file
            size: Number of bytes to read

        Returns:
            Bytes data if successful, None otherwise

        """
        if not self.mapped_file:
            self.logger.error("No file loaded")
            return None

        if offset < 0 or offset >= self.file_size:
            self.logger.error("Invalid offset: %s", offset)
            return None

        # Adjust size if it would read past end of file
        if offset + size > self.file_size:
            size = self.file_size - offset

        try:
            self.mapped_file.seek(offset)
            return self.mapped_file.read(size)
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error reading chunk: %s", e)
            return None

    def read_section(self, section_name: str, section_offset: int, section_size: int) -> bytes | None:
        """Read a section from the file with caching.

        Args:
            section_name: Name of the section for caching
            section_offset: Byte offset of the section
            section_size: Size of the section in bytes

        Returns:
            Section data if successful, None otherwise

        """
        # Check if section is in cache
        if section_name in self.section_cache:
            self.logger.debug("Using cached section: %s", section_name)
            return self.section_cache[section_name]

        # Read section
        data = self.read_chunk(section_offset, section_size)
        if data:
            # Cache section if it's not too large
            if len(data) <= self.chunk_size:
                self.section_cache[section_name] = data

            return data

        return None

    def iterate_file(self, chunk_size: int | None = None) -> Iterator[tuple[int, bytes]]:
        """Iterate through the file in chunks.

        Args:
            chunk_size: Size of chunks to iterate (default: configured chunk_size)

        Yields:
            Tuples of (offset, chunk_data)

        """
        if not self.mapped_file:
            self.logger.error("No file loaded")
            return

        if chunk_size is None:
            chunk_size = self.chunk_size

        offset = 0
        while offset < self.file_size:
            chunk = self.read_chunk(offset, chunk_size)
            if chunk:
                yield offset, chunk
                offset += len(chunk)
            else:
                break

    def get_memory_usage(self) -> int:
        """Get current memory usage of the process.

        Returns:
            Memory usage in bytes, or 0 if psutil not available

        """
        if not HAS_PSUTIL:
            self.logger.warning("psutil not available for memory monitoring")
            return 0

        try:
            process = psutil.Process(os.getpid())
            return process.memory_info().rss
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error getting memory usage: %s", e)
            return 0

    def get_file_info(self) -> dict[str, Any]:
        """Get information about the currently loaded file.

        Returns:
            Dictionary with file information

        """
        if not self.mapped_file:
            return {}

        return {
            "file_size": self.file_size,
            "formatted_size": self._format_size(self.file_size),
            "chunk_size": self.chunk_size,
            "cached_sections": len(self.section_cache),
            "memory_usage": self.get_memory_usage(),
            "formatted_memory": self._format_size(self.get_memory_usage()),
        }

    def calculate_entropy(self, data: bytes | None = None) -> float:
        """Calculate the entropy of data or the entire file.

        Args:
            data: Optional data to analyze (if None, analyzes entire file)

        Returns:
            Entropy value in bits per byte

        """
        if data is None:
            if not self.mapped_file:
                return 0.0

            # Calculate entropy for entire file in chunks
            byte_counts = [0] * 256
            total_bytes = 0

            for _offset, chunk in self.iterate_file():
                for byte_val in chunk:
                    byte_counts[byte_val] += 1
                    total_bytes += 1
        else:
            # Calculate entropy for provided data
            byte_counts = [0] * 256
            total_bytes = len(data)

            for byte_val in data:
                byte_counts[byte_val] += 1

        # Calculate entropy
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                probability = count / total_bytes
                entropy -= probability * math.log2(probability)

        return entropy

    def _format_size(self, size_bytes: int) -> str:
        """Format size in bytes to human-readable format.

        Args:
            size_bytes: Size in bytes

        Returns:
            Human-readable size string

        """
        from ...utils.core.string_utils import format_bytes

        return format_bytes(size_bytes)

    def __enter__(self) -> "MemoryOptimizedBinaryLoader":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: types.TracebackType | None) -> None:
        """Context manager exit."""
        if exc_type:
            self.logger.error(f"Memory loader exiting due to {exc_type.__name__}: {exc_val}")
            if exc_tb:
                self.logger.debug(f"Exception traceback from {exc_tb.tb_frame.f_code.co_filename}:{exc_tb.tb_lineno}")
        self.close()

    def __del__(self) -> None:
        """Destructor to ensure resources are cleaned up."""
        self.close()


def run_memory_optimized_analysis(
    file_path: str, analysis_type: str = "full", chunk_size: int = 1024 * 1024, max_memory: int = 1024 * 1024 * 1024,
) -> dict[str, Any]:
    """Run memory-optimized analysis on a binary file.

    This function performs comprehensive analysis on large binaries while
    maintaining optimal memory usage through chunked processing and caching.

    Args:
        file_path: Path to the binary file to analyze
        analysis_type: Type of analysis to perform:
            - "full": Complete analysis including entropy, sections, and heuristics
            - "quick": Basic analysis with file info and entropy
            - "sections": Focus on section analysis
            - "entropy": Entropy-focused analysis for packed detection
        chunk_size: Size of data chunks in bytes (default: 1MB)
        max_memory: Maximum memory usage in bytes (default: 1GB)

    Returns:
        Dictionary containing analysis results including:
            - file_info: Basic file information
            - entropy: File entropy metrics
            - packed_probability: Likelihood of packing/compression
            - sections: Section-level analysis (if applicable)
            - anomalies: Detected anomalies and suspicious patterns

    """
    results = {
        "file_path": file_path,
        "analysis_type": analysis_type,
        "status": "pending",
        "file_info": {},
        "entropy": {},
        "packed_probability": 0.0,
        "sections": [],
        "anomalies": [],
        "performance": {},
    }

    import time

    start_time = time.time()

    try:
        # Create memory-optimized loader
        loader = create_memory_loader(chunk_size, max_memory)

        # Load the binary file
        if not loader.load_file(file_path):
            results["status"] = "failed"
            results["error"] = f"Failed to load file: {file_path}"
            return results

        # Get basic file information
        results["file_info"] = loader.get_file_info()

        # Calculate entropy for packing detection
        overall_entropy = loader.calculate_entropy()
        results["entropy"]["overall"] = overall_entropy
        results["entropy"]["bits_per_byte"] = overall_entropy

        # Determine packed probability based on entropy
        if overall_entropy > 7.5:
            results["packed_probability"] = 0.95
            results["anomalies"].append(
                {
                    "type": "high_entropy",
                    "severity": "high",
                    "description": f"Very high entropy ({overall_entropy:.2f} bits/byte) indicates likely packing/encryption",
                },
            )
        elif overall_entropy > 7.0:
            results["packed_probability"] = 0.75
            results["anomalies"].append(
                {
                    "type": "elevated_entropy",
                    "severity": "medium",
                    "description": f"Elevated entropy ({overall_entropy:.2f} bits/byte) suggests possible compression",
                },
            )
        elif overall_entropy > 6.5:
            results["packed_probability"] = 0.50
        else:
            results["packed_probability"] = 0.10

        # Perform type-specific analysis
        if analysis_type in ["full", "sections"]:
            # Analyze sections in chunks
            section_entropies = []
            suspicious_sections = []

            for offset, chunk in loader.iterate_file(chunk_size):
                chunk_entropy = loader.calculate_entropy(chunk)
                section_info = {
                    "offset": offset,
                    "size": len(chunk),
                    "entropy": chunk_entropy,
                    "entropy_ratio": chunk_entropy / 8.0,
                }

                # Detect anomalies in sections
                if chunk_entropy > 7.8:
                    section_info["flags"] = ["packed", "encrypted"]
                    suspicious_sections.append(offset)
                elif chunk_entropy < 1.0:
                    section_info["flags"] = ["padding", "zeros"]
                elif chunk_entropy > 7.0:
                    section_info["flags"] = ["compressed"]
                else:
                    section_info["flags"] = []

                section_entropies.append(section_info)

                # Limit section analysis for memory optimization
                if len(section_entropies) >= 100:
                    break

            results["sections"] = section_entropies

            # Check for section anomalies
            if suspicious_sections:
                results["anomalies"].append(
                    {
                        "type": "suspicious_sections",
                        "severity": "medium",
                        "description": f"Found {len(suspicious_sections)} sections with suspicious entropy patterns",
                        "offsets": suspicious_sections[:10],  # Limit to first 10
                    },
                )

        # Perform entropy distribution analysis
        if analysis_type in ["full", "entropy"]:
            entropy_samples = []
            sample_count = min(100, results["file_info"].get("file_size", 0) // chunk_size)

            for i, (_offset, chunk) in enumerate(loader.iterate_file(chunk_size)):
                if i >= sample_count:
                    break
                entropy_samples.append(loader.calculate_entropy(chunk))

            if entropy_samples:
                import statistics

                results["entropy"]["mean"] = statistics.mean(entropy_samples)
                results["entropy"]["stdev"] = statistics.stdev(entropy_samples) if len(entropy_samples) > 1 else 0
                results["entropy"]["min"] = min(entropy_samples)
                results["entropy"]["max"] = max(entropy_samples)

                # Detect entropy anomalies
                if results["entropy"]["stdev"] < 0.5 and results["entropy"]["mean"] > 7.0:
                    results["anomalies"].append(
                        {
                            "type": "uniform_high_entropy",
                            "severity": "high",
                            "description": "Uniform high entropy across file indicates strong encryption/packing",
                        },
                    )
                elif results["entropy"]["stdev"] > 2.5:
                    results["anomalies"].append(
                        {
                            "type": "variable_entropy",
                            "severity": "low",
                            "description": "Variable entropy suggests mixed content (code + data)",
                        },
                    )

        # Close the loader to free resources
        loader.close()

        # Record performance metrics
        end_time = time.time()
        results["performance"]["analysis_time"] = end_time - start_time
        results["performance"]["memory_used"] = loader.get_memory_usage()
        results["status"] = "completed"

    except Exception as e:
        logger.error(f"Error during memory-optimized analysis: {e}")
        results["status"] = "error"
        results["error"] = str(e)

    return results


def create_memory_loader(chunk_size: int = 1024 * 1024, max_memory: int = 1024 * 1024 * 1024) -> MemoryOptimizedBinaryLoader:
    """Create a MemoryOptimizedBinaryLoader.

    Args:
        chunk_size: Size of data chunks in bytes (default: 1MB)
        max_memory: Maximum memory usage in bytes (default: 1GB)

    Returns:
        Configured MemoryOptimizedBinaryLoader instance

    """
    config = {
        "chunk_size": chunk_size,
        "max_memory": max_memory,
    }
    return MemoryOptimizedBinaryLoader(config)
