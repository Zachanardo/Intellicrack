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

logger = logging.getLogger("Intellicrack.HexView")

# Import large file handler for optimization
try:
    from .large_file_handler import LargeFileHandler, MemoryConfig, MemoryStrategy

    LARGE_FILE_SUPPORT = True
except ImportError as e:
    logger.error("Import error in file_handler: %s", e)
    LARGE_FILE_SUPPORT = False
    LargeFileHandler = None


class LRUCache:
    """A simple Least Recently Used (LRU) cache implementation."""

    def __init__(self, max_size: int = 10) -> None:
        """Initialize an LRU cache.

        Args:
            max_size: Maximum number of items to store in the cache

        """
        self.max_size = max_size
        self.cache = OrderedDict()

    def __getitem__(self, key: str) -> object:
        """Get an item from the cache and mark it as recently used."""
        value = self.cache.pop(key)
        self.cache[key] = value  # Move to the end (most recently used)
        return value

    def __setitem__(self, key: str, value: object) -> None:
        """Add an item to the cache, evicting least recently used items if necessary."""
        if key in self.cache:
            self.cache.pop(key)
        elif len(self.cache) >= self.max_size:
            # Remove the first item (least recently used)
            self.cache.popitem(last=False)
        self.cache[key] = value

    def __contains__(self, key: str) -> bool:
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
            logger.error("Error closing ChunkManager resources: %s", e)

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

        # Load chunk into memory
        chunk_offset = chunk_index * self.chunk_size
        self.file.seek(chunk_offset)

        # Calculate actual chunk size (handle end of file)
        actual_chunk_size = min(self.chunk_size, self.file_size - chunk_offset)

        try:
            # Create memory map for this chunk
            chunk_data = mmap.mmap(-1, actual_chunk_size)  # Create in memory
            chunk_data.write(self.file.read(actual_chunk_size))
            chunk_data.seek(0)

            # Store in cache
            self.active_chunks[chunk_index] = chunk_data
            return chunk_data
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error creating memory map for chunk at offset %s: %s", chunk_offset, e)
            # Fallback: return the raw data without memory mapping
            self.file.seek(chunk_offset)
            return self.file.read(actual_chunk_size)

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

            logger.debug(f"Reading from offset {offset} to {end_offset} ({end_offset - offset} bytes)")

            chunks_accessed = 0
            while current_offset < end_offset:
                # Get appropriate chunk
                try:
                    chunk = self.get_chunk(current_offset)
                    chunks_accessed += 1

                    if chunk is None:
                        logger.error("Failed to get chunk for offset %s", current_offset)
                        break

                    # Calculate offsets within chunk
                    chunk_index = current_offset // self.chunk_size
                    local_offset = current_offset - (chunk_index * self.chunk_size)
                    local_size = min(self.chunk_size - local_offset, end_offset - current_offset)

                    # Read from chunk
                    if hasattr(chunk, "seek"):
                        chunk.seek(local_offset)
                        chunk_data = chunk.read(local_size)
                        data.extend(chunk_data)
                        logger.debug(f"Read {len(chunk_data)} bytes from chunk {chunk_index} using seek/read")
                    else:
                        # If we got raw data instead of a memory map
                        chunk_data = chunk[local_offset : local_offset + local_size]
                        data.extend(chunk_data)
                        logger.debug(f"Read {len(chunk_data)} bytes from chunk {chunk_index} using slice")

                    # Move to next chunk
                    current_offset += local_size

                except (OSError, ValueError, RuntimeError) as e:
                    logger.error("Error reading from chunk at offset %s: %s", current_offset, e)
                    break

            result = bytes(data)
            logger.debug(f"ChunkManager.read_data complete: Read {len(result)} bytes using {chunks_accessed} chunks")

            # Verify we have data
            if not result:
                logger.warning("ChunkManager.read_data returned empty result!")

            return result

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Exception in ChunkManager.read_data: %s", e)
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
        self.file_path = file_path
        self.read_only = read_only
        self.using_temp_file = False
        self.temp_file_path = None
        self.use_large_file_optimization = use_large_file_optimization
        self.large_file_handler: LargeFileHandler | None = None

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

        except PermissionError:
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
                    logger.debug(f"Read {len(file_data)} bytes from original file")

                # Write the data to the temporary file
                logger.debug("Writing data to temporary file: %s", self.temp_file_path)
                with open(self.temp_file_path, "wb") as temp_file:
                    temp_file.write(file_data)
                    temp_file.flush()  # Ensure data is written to disk
                    os.fsync(temp_file.fileno())  # Force flush to disk

                # Verify the temp file was created and has the correct size
                if not os.path.exists(self.temp_file_path):
                    error_msg = f"Temp file not created: {self.temp_file_path}"
                    logger.error(error_msg)
                    raise FileNotFoundError(error_msg)

                self.file_size = os.path.getsize(self.temp_file_path)
                logger.debug("Temporary file size: %s bytes", self.file_size)

                if self.file_size != len(file_data):
                    error_msg = f"Temp file size mismatch: {self.file_size} vs {len(file_data)}"
                    logger.error(error_msg)
                    raise ValueError(error_msg)

                # Initialize chunk manager with the temp file path
                logger.debug("Initializing ChunkManager with temp file: %s", self.temp_file_path)
                self.chunk_manager = ChunkManager(self.temp_file_path, chunk_size, cache_size)
                self.using_temp_file = True

                # Test read from the chunk manager
                test_size = min(1024, self.file_size)
                if test_size > 0:
                    test_data = self.chunk_manager.read_data(0, test_size)
                    logger.debug(f"Test read from chunk manager: {len(test_data)} bytes")
                    if not test_data:
                        error_msg = "Chunk manager returned empty data in test read"
                        logger.error(error_msg)
                        raise ValueError(error_msg)

                # Mark as read-only since we're using a temp copy
                self.read_only = True

                logger.info("Successfully created and verified temporary copy: %s", self.temp_file_path)
            except Exception as copy_error:
                logger.error(f"Failed to create temporary copy: {copy_error}", exc_info=True)

                # Try to clean up the temp file if it exists
                if self.temp_file_path and os.path.exists(self.temp_file_path):
                    try:
                        os.remove(self.temp_file_path)
                        logger.debug("Cleaned up failed temp file: %s", self.temp_file_path)
                    except Exception as cleanup_error:
                        logger.warning("Could not clean up temp file: %s", cleanup_error)

                error_msg = f"Could not create temporary copy of {file_path}: {copy_error}"
                logger.error(error_msg)
                raise ValueError(error_msg) from copy_error
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error loading file: %s", e)
            raise

        # Store pending edits
        self.pending_edits = {}  # {offset: (original_data, new_data)}
        self.applied_edits = []

        # Initialize large file optimization if enabled and available
        if self.use_large_file_optimization and LARGE_FILE_SUPPORT and self.file_size > 50 * 1024 * 1024:  # Use for files > 50MB
            try:
                # Create memory configuration based on file size
                config = MemoryConfig()
                if self.file_size > 1024 * 1024 * 1024:  # > 1GB
                    config.max_memory_mb = 1000
                    config.chunk_size_mb = 50
                    config.cache_size_mb = 200
                    config.strategy = MemoryStrategy.STREAMING
                elif self.file_size > 100 * 1024 * 1024:  # > 100MB
                    config.max_memory_mb = 500
                    config.chunk_size_mb = 20
                    config.cache_size_mb = 100
                    config.strategy = MemoryStrategy.ADAPTIVE

                # Use the temp file path if available
                file_to_use = self.temp_file_path if self.using_temp_file else file_path

                self.large_file_handler = LargeFileHandler(
                    file_to_use,
                    read_only=read_only,
                    config=config,
                )
                logger.info(f"Large file optimization enabled for {self.file_size / (1024 * 1024):.1f}MB file")

            except (OSError, ValueError, RuntimeError) as e:
                logger.warning("Large file optimization failed, using fallback: %s", e)
                self.large_file_handler = None

        logger.info(f"VirtualFileAccess initialized for {file_path} (size: {self.file_size} bytes, read_only: {read_only})")

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
            if hasattr(self, "using_temp_file") and self.using_temp_file and self.temp_file_path:
                if os.path.exists(self.temp_file_path):
                    try:
                        os.remove(self.temp_file_path)
                        logger.debug("Removed temporary file: %s", self.temp_file_path)
                    except (OSError, ValueError, RuntimeError) as e:
                        logger.warning("Failed to remove temporary file %s: %s", self.temp_file_path, e)

            logger.debug("VirtualFileAccess resources for %s released", self.file_path)
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error closing VirtualFileAccess resources: %s", e)

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

            # Apply any pending edits that overlap with this region
            if self.pending_edits:
                # Convert to bytearray for mutability
                data = bytearray(data)

                for edit_offset, (_, new_data) in self.pending_edits.items():
                    # Check if the edit overlaps with the read region
                    rel_offset = edit_offset - offset
                    if rel_offset >= 0 and rel_offset < len(data):
                        # Calculate how much of the edit fits in this region
                        edit_size = min(len(new_data), len(data) - rel_offset)
                        # Apply the edit
                        data[rel_offset : rel_offset + edit_size] = new_data[:edit_size]

            logger.debug(f"Read completed: got {len(data)} bytes from offset {offset}")

            # Force conversion to bytes and ensure we don't return None
            if data is None:
                logger.error("Data is None after applying edits")
                return b""

            # Make sure we always return bytes, not bytearray or other type
            result = bytes(data)
            if not result and size > 0:
                logger.warning("Empty result from read operation that expected %s bytes", size)

            return result
        except (OSError, ValueError, RuntimeError) as e:
            logger.error(f"Exception in file_handler.read: {e}", exc_info=True)
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
            logger.error("Cannot write to file in read-only mode")
            return False

        # Ensure we don't write beyond the file size
        if offset + len(data) > self.file_size:
            logger.error(
                f"Write operation would extend beyond file size: offset {offset}, data size {len(data)}, file size {self.file_size}",
            )
            return False

        # Read original data for undo purposes
        original_data = self.chunk_manager.read_data(offset, len(data))

        # Store the edit
        self.pending_edits[offset] = (original_data, data)
        logger.debug(f"Staged edit at offset {offset}, size {len(data)}")

        return True

    def apply_edits(self) -> bool:
        """Apply all pending edits to the file.

        Returns:
            True if all edits were successfully applied, False otherwise

        """
        if self.read_only:
            logger.error("Cannot apply edits to file in read-only mode")
            return False

        if not self.pending_edits:
            logger.info("No pending edits to apply")
            return True

        try:
            # Apply each edit to the file
            for offset, (original_data, new_data) in self.pending_edits.items():
                self.write_file.seek(offset)
                self.write_file.write(new_data)

                # Record the applied edit
                self.applied_edits.append((offset, original_data, new_data))

            # Flush changes to disk
            self.write_file.flush()

            # Clear pending edits
            self.pending_edits.clear()

            logger.info(f"Applied {len(self.applied_edits)} edits to {self.file_path}")
            return True
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error applying edits to file: %s", e)
            return False

    def undo_last_edit(self) -> bool:
        """Undo the last applied edit.

        Returns:
            True if the edit was successfully undone, False otherwise

        """
        if self.read_only:
            logger.error("Cannot undo edits in read-only mode")
            return False

        if not self.applied_edits:
            logger.info("No edits to undo")
            return False

        try:
            # Get the last applied edit
            offset, original_data, _ = self.applied_edits.pop()

            # Revert to the original data
            self.write_file.seek(offset)
            self.write_file.write(original_data)
            self.write_file.flush()

            logger.info(f"Undid edit at offset {offset}, size {len(original_data)}")
            return True
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error undoing edit: %s", e)
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
            logger.error("Cannot insert data in read-only mode")
            return False

        if offset < 0 or offset > self.file_size:
            logger.error("Insert offset %s is out of bounds (file size: %s)", offset, self.file_size)
            return False

        if not data:
            logger.warning("Insert called with empty data")
            return True

        import shutil
        import tempfile

        try:
            # Create a temporary file in the same directory as the original file
            temp_fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(self.file_path), prefix="intellicrack_insert_")

            with os.fdopen(temp_fd, "wb") as temp_file:
                # Copy data up to insertion point
                if offset > 0:
                    self.read_file.seek(0)
                    chunk_size = 1024 * 1024  # 1MB chunks
                    bytes_copied = 0
                    while bytes_copied < offset:
                        to_read = min(chunk_size, offset - bytes_copied)
                        chunk = self.read_file.read(to_read)
                        if not chunk:
                            break
                        temp_file.write(chunk)
                        bytes_copied += len(chunk)

                # Write the new data
                temp_file.write(data)

                # Copy remaining data after insertion point
                if offset < self.file_size:
                    self.read_file.seek(offset)
                    chunk_size = 1024 * 1024  # 1MB chunks
                    while True:
                        chunk = self.read_file.read(chunk_size)
                        if not chunk:
                            break
                        temp_file.write(chunk)

            # Close the original write file
            if self.write_file:
                self.write_file.close()

            # Replace original file with temporary file
            shutil.move(temp_path, self.file_path)

            # Reopen the file for writing
            self.write_file = open(self.file_path, "r+b")  # noqa: SIM115
            self.read_file = self.write_file

            # Update file size
            self.file_size += len(data)

            # Update chunk manager for new file size
            self.chunk_manager.file_size = self.file_size
            self.chunk_manager.file_obj = self.write_file

            logger.info(f"Inserted {len(data)} bytes at offset {offset}, new file size: {self.file_size}")
            return True

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error inserting data at offset %s: %s", offset, e)
            # Clean up temp file if it exists
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
            logger.error("Cannot delete data in read-only mode")
            return False

        if offset < 0 or offset >= self.file_size:
            logger.error("Delete offset %s is out of bounds (file size: %s)", offset, self.file_size)
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

        try:
            # Create a temporary file in the same directory as the original file
            temp_fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(self.file_path), prefix="intellicrack_delete_")

            with os.fdopen(temp_fd, "wb") as temp_file:
                # Copy data up to deletion point
                if offset > 0:
                    self.read_file.seek(0)
                    chunk_size = 1024 * 1024  # 1MB chunks
                    bytes_copied = 0
                    while bytes_copied < offset:
                        to_read = min(chunk_size, offset - bytes_copied)
                        chunk = self.read_file.read(to_read)
                        if not chunk:
                            break
                        temp_file.write(chunk)
                        bytes_copied += len(chunk)

                # Skip the deleted portion and copy remaining data
                end_offset = offset + length
                if end_offset < self.file_size:
                    self.read_file.seek(end_offset)
                    chunk_size = 1024 * 1024  # 1MB chunks
                    while True:
                        chunk = self.read_file.read(chunk_size)
                        if not chunk:
                            break
                        temp_file.write(chunk)

            # Close the original write file
            if self.write_file:
                self.write_file.close()

            # Replace original file with temporary file
            shutil.move(temp_path, self.file_path)

            # Reopen the file for writing
            self.write_file = open(self.file_path, "r+b")  # noqa: SIM115
            self.read_file = self.write_file

            # Update file size
            self.file_size -= length

            # Update chunk manager for new file size
            self.chunk_manager.file_size = self.file_size
            self.chunk_manager.file_obj = self.write_file

            logger.info("Deleted %s bytes at offset %s, new file size: %s", length, offset, self.file_size)
            return True

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error deleting data at offset %s: %s", offset, e)
            # Clean up temp file if it exists
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
            if self.pending_edits:
                if not self.apply_edits():
                    logger.error("Failed to apply pending edits before save")
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
            logger.error("Error saving file to %s: %s", new_path, e)
            return False

    def get_performance_stats(self) -> dict | None:
        """Get performance statistics from large file handler.

        Returns:
            Dictionary with performance stats or None if not available

        """
        if self.large_file_handler:
            return self.large_file_handler.get_stats()
        return None

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
