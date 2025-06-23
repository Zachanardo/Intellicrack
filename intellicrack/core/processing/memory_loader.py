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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""


import logging
import math
import mmap
import os
from typing import Any, Dict, Iterator, Optional, Tuple, Union

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

__all__ = ['MemoryOptimizedBinaryLoader']


class MemoryOptimizedBinaryLoader:
    """
    Memory-efficient binary file loader for analyzing large executables.

    Uses memory mapping, partial loading, and caching strategies to minimize
    memory usage while providing efficient access to binary data.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the memory optimized binary loader.

        Args:
            config: Configuration dictionary with optional settings:
                - chunk_size: Size of data chunks in bytes (default: 1MB)
                - max_memory: Maximum memory usage in bytes (default: 1GB)
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.chunk_size = self.config.get('chunk_size', 1024 * 1024)  # 1MB chunks
        self.max_memory = self.config.get('max_memory', 1024 * 1024 * 1024)  # 1GB max
        self.current_file: Optional[object] = None
        self.file_size = 0
        self.mapped_file: Optional[mmap.mmap] = None
        self.section_cache: Dict[str, bytes] = {}

    def load_file(self, file_path: str) -> bool:
        """
        Load a binary file with memory optimization.

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
            self.current_file = open(file_path, 'rb')  # pylint: disable=consider-using-with
            self.file_size = os.path.getsize(file_path)

            # Memory map the file
            self.mapped_file = mmap.mmap(
                self.current_file.fileno(),
                0,  # Map entire file
                access=mmap.ACCESS_READ  # Read-only
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
            except (OSError, ValueError, RuntimeError):
                pass
            self.mapped_file = None

        # Close file
        if self.current_file:
            try:
                self.current_file.close()
            except (OSError, ValueError, RuntimeError):
                pass
            self.current_file = None

        self.file_size = 0

    def read_chunk(self, offset: int, size: int) -> Optional[bytes]:
        """
        Read a chunk of data from the file.

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

    def read_section(self, section_name: str, section_offset: int, section_size: int) -> Optional[bytes]:
        """
        Read a section from the file with caching.

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

    def iterate_file(self, chunk_size: Optional[int] = None) -> Iterator[Tuple[int, bytes]]:
        """
        Iterate through the file in chunks.

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
        """
        Get current memory usage of the process.

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

    def get_file_info(self) -> Dict[str, Any]:
        """
        Get information about the currently loaded file.

        Returns:
            Dictionary with file information
        """
        if not self.mapped_file:
            return {}

        return {
            'file_size': self.file_size,
            'formatted_size': self._format_size(self.file_size),
            'chunk_size': self.chunk_size,
            'cached_sections': len(self.section_cache),
            'memory_usage': self.get_memory_usage(),
            'formatted_memory': self._format_size(self.get_memory_usage())
        }

    def calculate_entropy(self, data: Union[bytes, None] = None) -> float:
        """
        Calculate the entropy of data or the entire file.

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
        """
        Format size in bytes to human-readable format.

        Args:
            size_bytes: Size in bytes

        Returns:
            Human-readable size string
        """
        from ...utils.core.string_utils import format_bytes
        return format_bytes(size_bytes)

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if exc_type:
            self.logger.error(f"Memory loader exiting due to {exc_type.__name__}: {exc_val}")
            if exc_tb:
                self.logger.debug(f"Exception traceback from {exc_tb.tb_frame.f_code.co_filename}:{exc_tb.tb_lineno}")
        self.close()

    def __del__(self):
        """Destructor to ensure resources are cleaned up."""
        self.close()


def create_memory_loader(chunk_size: int = 1024 * 1024, max_memory: int = 1024 * 1024 * 1024) -> MemoryOptimizedBinaryLoader:
    """
    Factory function to create a MemoryOptimizedBinaryLoader.

    Args:
        chunk_size: Size of data chunks in bytes (default: 1MB)
        max_memory: Maximum memory usage in bytes (default: 1GB)

    Returns:
        Configured MemoryOptimizedBinaryLoader instance
    """
    config = {
        'chunk_size': chunk_size,
        'max_memory': max_memory
    }
    return MemoryOptimizedBinaryLoader(config)
