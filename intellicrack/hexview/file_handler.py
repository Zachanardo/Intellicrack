"""Memory-efficient file handling for the hex viewer/editor.

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

import contextlib
import logging
import mmap
import os
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar


if TYPE_CHECKING:
    from io import BufferedRandom


logger = logging.getLogger("Intellicrack.HexView")

T = TypeVar("T")

LARGE_FILE_SUPPORT: bool
LargeFileHandler: type[Any] | None
MemoryConfig: type[Any] | None
MemoryStrategy: type[Any] | None

try:
    from .large_file_handler import (
        LargeFileHandler as _LargeFileHandler,
        MemoryConfig as _MemoryConfig,
        MemoryStrategy as _MemoryStrategy,
    )

    LARGE_FILE_SUPPORT = True
    LargeFileHandler = _LargeFileHandler
    MemoryConfig = _MemoryConfig
    MemoryStrategy = _MemoryStrategy
except ImportError as e:
    logger.exception("Import error in file_handler: %s", e)
    LARGE_FILE_SUPPORT = False
    LargeFileHandler = None
    MemoryConfig = None
    MemoryStrategy = None


class LRUCache:
    """A simple Least Recently Used (LRU) cache implementation."""

    def __init__(self, max_size: int = 10) -> None:
        """Initialize an LRU cache.

        Args:
            max_size: Maximum number of items to store in the cache

        """
        self.max_size: int = max_size
        self.cache: OrderedDict[int, bytes | mmap.mmap] = OrderedDict()

    def __getitem__(self, key: int) -> bytes | mmap.mmap:
        """Get an item from the cache and mark it as recently used."""
        value: bytes | mmap.mmap = self.cache.pop(key)
        self.cache[key] = value
        return value

    def __setitem__(self, key: int, value: bytes | mmap.mmap) -> None:
        """Add an item to the cache, evicting least recently used items if necessary."""
        if key in self.cache:
            self.cache.pop(key)
        elif len(self.cache) >= self.max_size:
            self.cache.popitem(last=False)
        self.cache[key] = value

    def __contains__(self, key: int) -> bool:
        """Check if an item is in the cache."""
        return key in self.cache

    def __len__(self) -> int:
        """Get the number of items in the cache."""
        return len(self.cache)


class ChunkManager:
    """Manages file chunks for efficient memory usage with large files.

    This class handles memory-mapped access to files by loading only
    the needed chunks into memory at any given time.
    """

    def __init__(self, file_path: str, chunk_size: int = 1024 * 1024, cache_size: int = 10) -> None:
        """Initialize a chunk manager for a file.

        Args:
            file_path: Path to the file to manage
            chunk_size: Size of each chunk in bytes (default: 1MB)
            cache_size: Number of chunks to keep in memory (default: 10)

        """
        self.file_path = file_path
        self.file_size = os.path.getsize(file_path)
        self.chunk_size = chunk_size
        self.file = open(file_path, "rb")  # noqa: SIM115, pylint: disable=consider-using-with

        # Create LRU cache for active chunks
        self.active_chunks = LRUCache(max_size=cache_size)
        logger.debug("ChunkManager initialized for %s (size: %s bytes)", file_path, self.file_size)

    def __del__(self) -> None:
        """Clean up resources when the object is destroyed."""
        try:
            # Close all memory maps
            for chunk_data in self.active_chunks.cache.values():
                if hasattr(chunk_data, "close"):
                    chunk_data.close()

            # Close the file
            if hasattr(self, "file") and self.file:
                self.file.close()

            logger.debug("ChunkManager resources for %s released", self.file_path)
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error closing ChunkManager resources: %s", e)

    def get_chunk(self, offset: int) -> bytes | mmap.mmap:
        """Get the chunk containing the specified offset.

        Args:
            offset: Byte offset into the file

        Returns:
            Memory-mapped chunk data or raw bytes if memory mapping fails

        """
        chunk_index = offset // self.chunk_size

        if chunk_index in self.active_chunks:
            return self.active_chunks[chunk_index]

        chunk_offset = chunk_index * self.chunk_size
        self.file.seek(chunk_offset)

        actual_chunk_size = min(self.chunk_size, self.file_size - chunk_offset)

        try:
            chunk_data: mmap.mmap = mmap.mmap(-1, actual_chunk_size)
            chunk_data.write(self.file.read(actual_chunk_size))
            chunk_data.seek(0)

            self.active_chunks[chunk_index] = chunk_data
            return chunk_data
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error creating memory map for chunk at offset %s: %s", chunk_offset, e)
            self.file.seek(chunk_offset)
            fallback_data: bytes = self.file.read(actual_chunk_size)
            return fallback_data

    def read_data(self, offset: int, size: int) -> bytes:
        """Read data from the file, potentially spanning multiple chunks.

        Args:
            offset: Starting byte offset
            size: Number of bytes to read

        Returns:
            Read binary data

        """
        try:
            logger.debug(
                "ChunkManager.read_data: offset=%s, size=%s, file_size=%s",
                offset,
                size,
                self.file_size,
            )

            # Validate parameters
            if offset < 0 or size <= 0 or offset >= self.file_size:
                logger.warning(
                    "Invalid read parameters: offset=%s, size=%s, file_size=%s",
                    offset,
                    size,
                    self.file_size,
                )
                return b""

            data = bytearray()
            end_offset = min(offset + size, self.file_size)
            current_offset = offset

            logger.debug("Reading from offset %s to %s (%d bytes)", current_offset, end_offset, end_offset - current_offset)
            chunks_accessed = 0
            while current_offset < end_offset:
                try:
                    chunk = self.get_chunk(current_offset)
                    chunks_accessed += 1

                    chunk_index = current_offset // self.chunk_size
                    local_offset = current_offset - (chunk_index * self.chunk_size)
                    local_size = min(self.chunk_size - local_offset, end_offset - current_offset)

                    if isinstance(chunk, mmap.mmap):
                        chunk.seek(local_offset)
                        chunk_data = chunk.read(local_size)
                        data.extend(chunk_data)
                        logger.debug("Read %d bytes from chunk %s using seek/read", len(chunk_data), chunk_index)
                    else:
                        chunk_data = chunk[local_offset : local_offset + local_size]
                        data.extend(chunk_data)
                        logger.debug("Read %d bytes from chunk %s using slice", len(chunk_data), chunk_index)

                    current_offset += local_size

                except (OSError, ValueError, RuntimeError) as e:
                    logger.exception("Error reading from chunk at offset %s: %s", current_offset, e)
                    break

            result = bytes(data)
            logger.debug("ChunkManager.read_data complete: Read %d bytes using %d chunks", len(result), chunks_accessed)

            # Verify we have data
            if not result:
                logger.warning("ChunkManager.read_data returned empty result!")

            return result

        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Exception in ChunkManager.read_data: %s", e)
            return b""


class VirtualFileAccess:
    """Provides a virtual view of a file with efficient memory usage.

    This class is the main interface for file operations in the hex viewer,
    abstracting away the details of memory mapping and chunk management.
    """

    def __init__(
        self,
        file_path: str,
        read_only: bool = True,
        chunk_size: int = 1024 * 1024,
        cache_size: int = 10,
        use_large_file_optimization: bool = True,
    ) -> None:
        """Initialize virtual file access.

        Args:
            file_path: Path to the file
            read_only: Whether the file should be opened in read-only mode
            chunk_size: Size of each chunk in bytes
            cache_size: Number of chunks to keep in memory
            use_large_file_optimization: Whether to use large file optimization

        """
        self.file_path: str = file_path
        self.read_only: bool = read_only
        self.using_temp_file: bool = False
        self.temp_file_path: str | None = None
        self.use_large_file_optimization: bool = use_large_file_optimization
        self.large_file_handler: Any = None
        self.chunk_manager: ChunkManager
        self.file_size: int
        self.write_file: BufferedRandom | None = None

        try:
            # First try to get file size to test access permissions
            self.file_size = os.path.getsize(file_path)

            # Test if we can open the file directly
            with open(file_path, "rb"):
                pass

            # Initialize chunk manager for reading
            self.chunk_manager = ChunkManager(file_path, chunk_size, cache_size)

            # Open file for writing if needed
            self.write_file = None
            if not read_only:
                # Open in read+write mode for potential edits
                self.write_file = open(file_path, "r+b")  # noqa: SIM115, pylint: disable=consider-using-with

        except PermissionError as e:
            # Handle permission errors - create a temp copy
            logger.warning("Permission error accessing %s, using temporary copy", file_path)
            import random
            import string
            import tempfile
            import time

            # Generate a unique temp file with timestamp and random string
            random_suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))  # noqa: S311 - Temporary file name collision avoidance
            timestamp = int(time.time())
            basename = os.path.basename(file_path)

            # Create a temporary file with a unique name
            temp_dir = tempfile.gettempdir()
            self.temp_file_path = os.path.join(temp_dir, f"intellicrack_hex_{timestamp}_{random_suffix}_{basename}")
            logger.debug("Using temporary file path: %s", self.temp_file_path)

            try:
                # First read the original file completely to memory
                logger.debug("Reading original file into memory: %s", file_path)
                with open(file_path, "rb") as src_file:
                    file_data = src_file.read()
                    logger.debug("Read %d bytes from original file", len(file_data))

                # Write the data to the temporary file
                logger.debug("Writing data to temporary file: %s", self.temp_file_path)
                with open(self.temp_file_path, "wb") as temp_file:
                    temp_file.write(file_data)
                    temp_file.flush()  # Ensure data is written to disk
                    os.fsync(temp_file.fileno())  # Force flush to disk

                # Verify the temp file was created and has the correct size
                if not os.path.exists(self.temp_file_path):
                    error_msg = f"Temp file not created: {self.temp_file_path}"
                    logger.exception(error_msg)
                    raise FileNotFoundError(error_msg) from e

                self.file_size = os.path.getsize(self.temp_file_path)
                logger.debug("Temporary file size: %s bytes", self.file_size)

                if self.file_size != len(file_data):
                    error_msg = f"Temp file size mismatch: {self.file_size} vs {len(file_data)}"
                    logger.exception(error_msg)
                    raise ValueError(error_msg) from e

                # Initialize chunk manager with the temp file path
                logger.debug("Initializing ChunkManager with temp file: %s", self.temp_file_path)
                self.chunk_manager = ChunkManager(self.temp_file_path, chunk_size, cache_size)
                self.using_temp_file = True

                # Test read from the chunk manager
                test_size = min(1024, self.file_size)
                if test_size > 0:
                    test_data = self.chunk_manager.read_data(0, test_size)
                    logger.debug("Test read from chunk manager: %d bytes", len(test_data))
                    if not test_data:
                        error_msg = "Chunk manager returned empty data in test read"
                        logger.exception(error_msg)
                        raise ValueError(error_msg) from e

                # Mark as read-only since we're using a temp copy
                self.read_only = True

                logger.info("Successfully created and verified temporary copy: %s", self.temp_file_path)
            except Exception as copy_error:
                logger.exception("Failed to create temporary copy: %s", copy_error)

                # Try to clean up the temp file if it exists
                if self.temp_file_path and os.path.exists(self.temp_file_path):
                    try:
                        os.remove(self.temp_file_path)
                        logger.debug("Cleaned up failed temp file: %s", self.temp_file_path)
                    except Exception as cleanup_error:
                        logger.warning("Could not clean up temp file: %s", cleanup_error)

                error_msg = f"Could not create temporary copy of {file_path}: {copy_error}"
                logger.exception(error_msg)
                raise ValueError(error_msg) from copy_error
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error loading file: %s", e)
            raise

        self.pending_edits: dict[int, tuple[bytes, bytes]] = {}
        self.applied_edits: list[tuple[int, bytes, bytes]] = []

        if self.use_large_file_optimization and LARGE_FILE_SUPPORT and self.file_size > 50 * 1024 * 1024:
            try:
                if MemoryConfig is not None and LargeFileHandler is not None and MemoryStrategy is not None:
                    config: Any = MemoryConfig()
                    if self.file_size > 1024 * 1024 * 1024:
                        config.max_memory_mb = 1000
                        config.chunk_size_mb = 50
                        config.cache_size_mb = 200
                        if hasattr(MemoryStrategy, "STREAMING"):
                            config.strategy = MemoryStrategy.STREAMING
                    elif self.file_size > 100 * 1024 * 1024:
                        config.max_memory_mb = 500
                        config.chunk_size_mb = 20
                        config.cache_size_mb = 100
                        if hasattr(MemoryStrategy, "ADAPTIVE"):
                            config.strategy = MemoryStrategy.ADAPTIVE

                    file_to_use: str = self.temp_file_path if self.using_temp_file and self.temp_file_path is not None else file_path

                    self.large_file_handler = LargeFileHandler(
                        file_to_use,
                        read_only=read_only,
                        config=config,
                    )
                    logger.info("Large file optimization enabled for %.1fMB file", self.file_size / (1024 * 1024))

            except (OSError, ValueError, RuntimeError) as e:
                logger.warning("Large file optimization failed, using fallback: %s", e)
                self.large_file_handler = None

        logger.info("VirtualFileAccess initialized for %s (size: %d bytes, read_only: %s)", file_path, self.file_size, read_only)

    def __del__(self) -> None:
        """Clean up resources when the object is destroyed."""
        try:
            # Close large file handler if open
            if hasattr(self, "large_file_handler") and self.large_file_handler:
                self.large_file_handler.close()
                self.large_file_handler = None

            # Close write file if open
            if hasattr(self, "write_file") and self.write_file:
                self.write_file.close()

            # Remove temporary file if created
            if hasattr(self, "using_temp_file") and self.using_temp_file and self.temp_file_path and os.path.exists(self.temp_file_path):
                try:
                    os.remove(self.temp_file_path)
                    logger.debug("Removed temporary file: %s", self.temp_file_path)
                except (OSError, ValueError, RuntimeError) as e:
                    logger.warning("Failed to remove temporary file %s: %s", self.temp_file_path, e)

            logger.debug("VirtualFileAccess resources for %s released", self.file_path)
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error closing VirtualFileAccess resources: %s", e)

    def get_file_size(self) -> int:
        """Get the size of the file.

        Returns:
            File size in bytes

        """
        return self.file_size

    def read(self, offset: int, size: int) -> bytes:
        """Read data from the file.

        This method handles reading from the chunks and applies any pending
        edits to the data before returning it.

        Args:
            offset: Starting byte offset
            size: Number of bytes to read

        Returns:
            Read binary data with pending edits applied

        """
        # Basic validation
        if offset < 0 or size <= 0:
            logger.warning("Invalid read parameters: offset=%s, size=%s", offset, size)
            return b""

        if offset >= self.file_size:
            logger.warning("Read offset %s beyond file size %s", offset, self.file_size)
            return b""

        # Adjust size to not read beyond file end
        if offset + size > self.file_size:
            original_size = size
            size = self.file_size - offset
            logger.debug("Adjusted read size from %s to %s to fit file bounds", original_size, size)

        try:
            # Use large file handler if available and efficient
            if self.large_file_handler:
                logger.debug("Reading from large_file_handler: offset=%s, size=%s", offset, size)
                data = self.large_file_handler.read(offset, size)
            else:
                # Read the raw data from chunks (fallback)
                logger.debug("Reading from chunk_manager: offset=%s, size=%s", offset, size)
                data = self.chunk_manager.read_data(offset, size)

            if not data:
                logger.warning(
                    "chunk_manager.read_data returned empty data for offset=%s, size=%s",
                    offset,
                    size,
                )

            if self.pending_edits:
                mutable_data: bytearray = bytearray(data)

                for edit_offset, (_, new_data) in self.pending_edits.items():
                    rel_offset = edit_offset - offset
                    if rel_offset >= 0 and rel_offset < len(mutable_data):
                        edit_size = min(len(new_data), len(mutable_data) - rel_offset)
                        mutable_data[rel_offset : rel_offset + edit_size] = new_data[:edit_size]

                data = bytes(mutable_data)

            logger.debug("Read completed: got %d bytes from offset %s", len(data), offset)

            result: bytes = bytes(data)
            if not result and size > 0:
                logger.warning("Empty result from read operation that expected %s bytes", size)

            return result
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Exception in file_handler.read: %s", e)
            # Return empty data on error
            return b""

    def write(self, offset: int, data: bytes) -> bool:
        """Write data to the file.

        This method stages the edit in the pending_edits dictionary.
        The edit is not applied to the file until apply_edits() is called.

        Args:
            offset: Starting byte offset
            data: Data to write

        Returns:
            True if the edit was successfully staged, False otherwise

        """
        if self.read_only:
            logger.exception("Cannot write to file in read-only mode")
            return False

        # Ensure we don't write beyond the file size
        if offset + len(data) > self.file_size:
            logger.exception(
                "Write operation would extend beyond file size: offset %s, data size %d, file size %d",
                offset,
                len(data),
                self.file_size,
            )
            return False

        # Read original data for undo purposes
        original_data = self.chunk_manager.read_data(offset, len(data))

        # Store the edit
        self.pending_edits[offset] = (original_data, data)
        logger.debug("Staged edit at offset %s, size %d", offset, len(data))

        return True

    def apply_edits(self) -> bool:
        """Apply all pending edits to the file.

        Returns:
            True if all edits were successfully applied, False otherwise

        """
        if self.read_only:
            logger.exception("Cannot apply edits to file in read-only mode")
            return False

        if not self.pending_edits:
            logger.info("No pending edits to apply")
            return True

        if self.write_file is None:
            logger.exception("Write file not available")
            return False

        try:
            for offset, (original_data, new_data) in self.pending_edits.items():
                self.write_file.seek(offset)
                self.write_file.write(new_data)

                self.applied_edits.append((offset, original_data, new_data))

            self.write_file.flush()

            self.pending_edits.clear()

            logger.info("Applied %d edits to %s", len(self.applied_edits), self.file_path)
            return True
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error applying edits to file: %s", e)
            return False

    def undo_last_edit(self) -> bool:
        """Undo the last applied edit.

        Returns:
            True if the edit was successfully undone, False otherwise

        """
        if self.read_only:
            logger.exception("Cannot undo edits in read-only mode")
            return False

        if not self.applied_edits:
            logger.info("No edits to undo")
            return False

        if self.write_file is None:
            logger.exception("Write file not available")
            return False

        try:
            offset, original_data, _ = self.applied_edits.pop()

            self.write_file.seek(offset)
            self.write_file.write(original_data)
            self.write_file.flush()

            logger.info("Undid edit at offset %s, size %d", offset, len(original_data))
            return True
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error undoing edit: %s", e)
            return False

    def discard_edits(self) -> None:
        """Discard all pending edits without applying them."""
        self.pending_edits.clear()
        logger.info("Discarded all pending edits")

    def insert(self, offset: int, data: bytes) -> bool:
        """Insert data at the specified offset.

        This operation increases the file size by the length of the inserted data.
        All subsequent data is shifted right. Uses temporary file for memory efficiency.

        Args:
            offset: Offset where to insert the data
            data: Data to insert

        Returns:
            True if successful, False otherwise

        """
        if self.read_only:
            logger.exception("Cannot insert data in read-only mode")
            return False

        if offset < 0 or offset > self.file_size:
            logger.exception("Insert offset %s is out of bounds (file size: %s)", offset, self.file_size)
            return False

        if not data:
            logger.warning("Insert called with empty data")
            return True

        import shutil
        import tempfile

        if self.write_file is None:
            logger.exception("Write file not available")
            return False

        try:
            temp_fd: int
            temp_path: str
            temp_fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(self.file_path), prefix="intellicrack_insert_")

            with os.fdopen(temp_fd, "wb") as temp_file:
                if offset > 0:
                    read_offset = 0
                    chunk_size = 1024 * 1024
                    while read_offset < offset:
                        to_read = min(chunk_size, offset - read_offset)
                        chunk = self.read(read_offset, to_read)
                        if not chunk:
                            break
                        temp_file.write(chunk)
                        read_offset += len(chunk)

                temp_file.write(data)

                if offset < self.file_size:
                    read_offset = offset
                    chunk_size = 1024 * 1024
                    while read_offset < self.file_size:
                        to_read = min(chunk_size, self.file_size - read_offset)
                        chunk = self.read(read_offset, to_read)
                        if not chunk:
                            break
                        temp_file.write(chunk)
                        read_offset += len(chunk)

            if self.write_file:
                self.write_file.close()

            shutil.move(temp_path, self.file_path)

            self.write_file = open(self.file_path, "r+b")

            self.file_size += len(data)

            del self.chunk_manager
            self.chunk_manager = ChunkManager(self.file_path, 1024 * 1024, 10)

            logger.info("Inserted %d bytes at offset %s, new file size: %d", len(data), offset, self.file_size)
            return True

        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error inserting data at offset %s: %s", offset, e)
            if "temp_path" in locals() and os.path.exists(temp_path):
                with contextlib.suppress(OSError):
                    os.remove(temp_path)
            return False

    def delete(self, offset: int, length: int) -> bool:
        """Delete data at the specified offset.

        This operation decreases the file size by the length of the deleted data.
        All subsequent data is shifted left. Uses temporary file for memory efficiency.

        Args:
            offset: Starting offset to delete from
            length: Number of bytes to delete

        Returns:
            True if successful, False otherwise

        """
        if self.read_only:
            logger.exception("Cannot delete data in read-only mode")
            return False

        if offset < 0 or offset >= self.file_size:
            logger.exception("Delete offset %s is out of bounds (file size: %s)", offset, self.file_size)
            return False

        if length <= 0:
            logger.warning("Delete called with non-positive length")
            return True

        # Clamp length to file bounds
        if offset + length > self.file_size:
            length = self.file_size - offset
            logger.warning("Delete length clamped to %s to fit file bounds", length)

        import shutil
        import tempfile

        if self.write_file is None:
            logger.exception("Write file not available")
            return False

        try:
            temp_fd: int
            temp_path: str
            temp_fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(self.file_path), prefix="intellicrack_delete_")

            with os.fdopen(temp_fd, "wb") as temp_file:
                if offset > 0:
                    read_offset = 0
                    chunk_size = 1024 * 1024
                    while read_offset < offset:
                        to_read = min(chunk_size, offset - read_offset)
                        chunk = self.read(read_offset, to_read)
                        if not chunk:
                            break
                        temp_file.write(chunk)
                        read_offset += len(chunk)

                end_offset = offset + length
                if end_offset < self.file_size:
                    read_offset = end_offset
                    chunk_size = 1024 * 1024
                    while read_offset < self.file_size:
                        to_read = min(chunk_size, self.file_size - read_offset)
                        chunk = self.read(read_offset, to_read)
                        if not chunk:
                            break
                        temp_file.write(chunk)
                        read_offset += len(chunk)

            if self.write_file:
                self.write_file.close()

            shutil.move(temp_path, self.file_path)

            self.write_file = open(self.file_path, "r+b")

            self.file_size -= length

            del self.chunk_manager
            self.chunk_manager = ChunkManager(self.file_path, 1024 * 1024, 10)

            logger.info("Deleted %s bytes at offset %s, new file size: %s", length, offset, self.file_size)
            return True

        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error deleting data at offset %s: %s", offset, e)
            if "temp_path" in locals() and os.path.exists(temp_path):
                with contextlib.suppress(OSError):
                    os.remove(temp_path)
            return False

    def get_modification_time(self) -> float:
        """Get the last modification time of the file.

        Returns:
            Modification time as a timestamp

        """
        try:
            if self.using_temp_file and self.temp_file_path:
                return Path(self.temp_file_path).stat().st_mtime
            return Path(self.file_path).stat().st_mtime
        except (OSError, ValueError, RuntimeError) as e:
            logger.warning("Could not get modification time: %s", e)
            return 0.0

    def save_as(self, new_path: str) -> bool:
        """Save the current file state to a new path.

        Args:
            new_path: Path to save the file to

        Returns:
            True if successful, False otherwise

        """
        try:
            # Apply any pending edits first
            if self.pending_edits and not self.apply_edits():
                logger.exception("Failed to apply pending edits before save")
                return False

            # Read entire file and write to new location
            with open(new_path, "wb") as new_file:
                # Read in chunks to handle large files
                chunk_size = 1024 * 1024  # 1MB chunks
                offset = 0

                while offset < self.file_size:
                    read_size = min(chunk_size, self.file_size - offset)
                    data = self.read(offset, read_size)

                    if not data:
                        break

                    new_file.write(data)
                    offset += len(data)

            logger.info("Saved file to %s (%s bytes)", new_path, self.file_size)
            return True

        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error saving file to %s: %s", new_path, e)
            return False

    def get_performance_stats(self) -> dict[str, Any] | None:
        """Get performance statistics from large file handler.

        Returns:
            Dictionary with performance stats or None if not available

        """
        return self.large_file_handler.get_stats() if self.large_file_handler else None

    def optimize_for_sequential_access(self) -> None:
        """Optimize for sequential file access patterns."""
        if self.large_file_handler:
            # Increase prefetch for sequential access
            self.large_file_handler.config.prefetch_chunks = 4
            logger.debug("Optimized for sequential access")

    def optimize_for_random_access(self) -> None:
        """Optimize for random file access patterns."""
        if self.large_file_handler:
            # Reduce prefetch for random access
            self.large_file_handler.config.prefetch_chunks = 1
            logger.debug("Optimized for random access")
