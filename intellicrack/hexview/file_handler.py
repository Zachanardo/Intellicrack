"""
Memory-efficient file handling for the hex viewer/editor.

This module provides classes for handling arbitrarily large files
through memory mapping and chunk-based access.
"""

import os
import mmap
import logging
from typing import Dict, Optional, Union, BinaryIO
from collections import OrderedDict

logger = logging.getLogger('Intellicrack.HexView')

class LRUCache:
    """A simple Least Recently Used (LRU) cache implementation."""
    
    def __init__(self, max_size: int = 10):
        """
        Initialize an LRU cache.
        
        Args:
            max_size: Maximum number of items to store in the cache
        """
        self.max_size = max_size
        self.cache = OrderedDict()
        
    def __getitem__(self, key):
        """Get an item from the cache and mark it as recently used."""
        value = self.cache.pop(key)
        self.cache[key] = value  # Move to the end (most recently used)
        return value
        
    def __setitem__(self, key, value):
        """Add an item to the cache, evicting least recently used items if necessary."""
        if key in self.cache:
            self.cache.pop(key)
        elif len(self.cache) >= self.max_size:
            # Remove the first item (least recently used)
            self.cache.popitem(last=False)
        self.cache[key] = value
        
    def __contains__(self, key):
        """Check if an item is in the cache."""
        return key in self.cache
        
    def __len__(self):
        """Get the number of items in the cache."""
        return len(self.cache)


class ChunkManager:
    """
    Manages file chunks for efficient memory usage with large files.
    
    This class handles memory-mapped access to files by loading only
    the needed chunks into memory at any given time.
    """
    
    def __init__(self, file_path: str, chunk_size: int = 1024*1024, cache_size: int = 10):
        """
        Initialize a chunk manager for a file.
        
        Args:
            file_path: Path to the file to manage
            chunk_size: Size of each chunk in bytes (default: 1MB)
            cache_size: Number of chunks to keep in memory (default: 10)
        """
        self.file_path = file_path
        self.file_size = os.path.getsize(file_path)
        self.chunk_size = chunk_size
        self.file = open(file_path, 'rb')
        
        # Create LRU cache for active chunks
        self.active_chunks = LRUCache(max_size=cache_size)
        logger.debug(f"ChunkManager initialized for {file_path} (size: {self.file_size} bytes)")
        
    def __del__(self):
        """Clean up resources when the object is destroyed."""
        try:
            # Close all memory maps
            for chunk_data in self.active_chunks.cache.values():
                if hasattr(chunk_data, 'close'):
                    chunk_data.close()
            
            # Close the file
            if hasattr(self, 'file') and self.file:
                self.file.close()
                
            logger.debug(f"ChunkManager resources for {self.file_path} released")
        except Exception as e:
            logger.error(f"Error closing ChunkManager resources: {e}")
        
    def get_chunk(self, offset: int):
        """
        Get the chunk containing the specified offset.
        
        Args:
            offset: Byte offset into the file
            
        Returns:
            Memory-mapped chunk data
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
        except Exception as e:
            logger.error(f"Error creating memory map for chunk at offset {chunk_offset}: {e}")
            # Fallback: return the raw data without memory mapping
            self.file.seek(chunk_offset)
            return self.file.read(actual_chunk_size)
        
    def read_data(self, offset: int, size: int) -> bytes:
        """
        Read data from the file, potentially spanning multiple chunks.
        
        Args:
            offset: Starting byte offset
            size: Number of bytes to read
            
        Returns:
            Read binary data
        """
        try:
            logger.debug(f"ChunkManager.read_data: offset={offset}, size={size}, file_size={self.file_size}")
            
            # Validate parameters
            if offset < 0 or size <= 0 or offset >= self.file_size:
                logger.warning(f"Invalid read parameters: offset={offset}, size={size}, file_size={self.file_size}")
                return b''
                
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
                        logger.error(f"Failed to get chunk for offset {current_offset}")
                        break
                        
                    # Calculate offsets within chunk
                    chunk_index = current_offset // self.chunk_size
                    local_offset = current_offset - (chunk_index * self.chunk_size)
                    local_size = min(self.chunk_size - local_offset, end_offset - current_offset)
                    
                    # Read from chunk
                    if hasattr(chunk, 'seek'):
                        chunk.seek(local_offset)
                        chunk_data = chunk.read(local_size)
                        data.extend(chunk_data)
                        logger.debug(f"Read {len(chunk_data)} bytes from chunk {chunk_index} using seek/read")
                    else:
                        # If we got raw data instead of a memory map
                        chunk_data = chunk[local_offset:local_offset+local_size]
                        data.extend(chunk_data)
                        logger.debug(f"Read {len(chunk_data)} bytes from chunk {chunk_index} using slice")
                    
                    # Move to next chunk
                    current_offset += local_size
                    
                except Exception as e:
                    logger.error(f"Error reading from chunk at offset {current_offset}: {e}")
                    break
            
            result = bytes(data)
            logger.debug(f"ChunkManager.read_data complete: Read {len(result)} bytes using {chunks_accessed} chunks")
            
            # Verify we have data
            if not result:
                logger.warning("ChunkManager.read_data returned empty result!")
                
            return result
            
        except Exception as e:
            logger.error(f"Exception in ChunkManager.read_data: {e}")
            return b''


class VirtualFileAccess:
    """
    Provides a virtual view of a file with efficient memory usage.
    
    This class is the main interface for file operations in the hex viewer,
    abstracting away the details of memory mapping and chunk management.
    """
    
    def __init__(self, file_path: str, read_only: bool = True,
                 chunk_size: int = 1024*1024, cache_size: int = 10):
        """
        Initialize virtual file access.
        
        Args:
            file_path: Path to the file
            read_only: Whether the file should be opened in read-only mode
            chunk_size: Size of each chunk in bytes
            cache_size: Number of chunks to keep in memory
        """
        self.file_path = file_path
        self.read_only = read_only
        self.using_temp_file = False
        self.temp_file_path = None
        
        try:
            # First try to get file size to test access permissions
            self.file_size = os.path.getsize(file_path)
            
            # Test if we can open the file directly
            with open(file_path, 'rb') as test_file:
                pass
                
            # Initialize chunk manager for reading
            self.chunk_manager = ChunkManager(file_path, chunk_size, cache_size)
            
            # Open file for writing if needed
            self.write_file = None
            if not read_only:
                # Open in read+write mode for potential edits
                self.write_file = open(file_path, 'r+b')
                
        except PermissionError as e:
            # Handle permission errors - create a temp copy
            logger.warning(f"Permission error accessing {file_path}, using temporary copy")
            import tempfile
            import shutil
            import random
            import string
            import time
            
            # Generate a unique temp file with timestamp and random string
            random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
            timestamp = int(time.time())
            basename = os.path.basename(file_path)
            
            # Create a temporary file with a unique name
            temp_dir = tempfile.gettempdir()
            self.temp_file_path = os.path.join(temp_dir, f"intellicrack_hex_{timestamp}_{random_suffix}_{basename}")
            logger.debug(f"Using temporary file path: {self.temp_file_path}")
            
            try:
                # First read the original file completely to memory
                logger.debug(f"Reading original file into memory: {file_path}")
                with open(file_path, 'rb') as src_file:
                    file_data = src_file.read()
                    logger.debug(f"Read {len(file_data)} bytes from original file")
                
                # Write the data to the temporary file
                logger.debug(f"Writing data to temporary file: {self.temp_file_path}")
                with open(self.temp_file_path, 'wb') as temp_file:
                    temp_file.write(file_data)
                    temp_file.flush()  # Ensure data is written to disk
                    os.fsync(temp_file.fileno())  # Force flush to disk
                
                # Verify the temp file was created and has the correct size
                if not os.path.exists(self.temp_file_path):
                    raise FileNotFoundError(f"Temp file not created: {self.temp_file_path}")
                    
                self.file_size = os.path.getsize(self.temp_file_path)
                logger.debug(f"Temporary file size: {self.file_size} bytes")
                
                if self.file_size != len(file_data):
                    raise ValueError(f"Temp file size mismatch: {self.file_size} vs {len(file_data)}")
                
                # Initialize chunk manager with the temp file path
                logger.debug(f"Initializing ChunkManager with temp file: {self.temp_file_path}")
                self.chunk_manager = ChunkManager(self.temp_file_path, chunk_size, cache_size)
                self.using_temp_file = True
                
                # Test read from the chunk manager
                test_size = min(1024, self.file_size)
                if test_size > 0:
                    test_data = self.chunk_manager.read_data(0, test_size)
                    logger.debug(f"Test read from chunk manager: {len(test_data)} bytes")
                    if not test_data:
                        raise ValueError("Chunk manager returned empty data in test read")
                
                # Mark as read-only since we're using a temp copy
                self.read_only = True
                
                logger.info(f"Successfully created and verified temporary copy: {self.temp_file_path}")
            except Exception as copy_error:
                logger.error(f"Failed to create temporary copy: {copy_error}", exc_info=True)
                
                # Try to clean up the temp file if it exists
                if self.temp_file_path and os.path.exists(self.temp_file_path):
                    try:
                        os.remove(self.temp_file_path)
                        logger.debug(f"Cleaned up failed temp file: {self.temp_file_path}")
                    except Exception as cleanup_error:
                        logger.warning(f"Could not clean up temp file: {cleanup_error}")
                
                raise ValueError(f"Could not create temporary copy of {file_path}: {copy_error}")
        except Exception as e:
            logger.error(f"Error loading file: {e}")
            raise
        
        # Store pending edits
        self.pending_edits = {}  # {offset: (original_data, new_data)}
        self.applied_edits = []
        
        logger.info(f"VirtualFileAccess initialized for {file_path} " +
                    f"(size: {self.file_size} bytes, read_only: {read_only})")
        
    def __del__(self):
        """Clean up resources when the object is destroyed."""
        try:
            # Close write file if open
            if hasattr(self, 'write_file') and self.write_file:
                self.write_file.close()
            
            # Remove temporary file if created
            if hasattr(self, 'using_temp_file') and self.using_temp_file and self.temp_file_path:
                if os.path.exists(self.temp_file_path):
                    try:
                        os.remove(self.temp_file_path)
                        logger.debug(f"Removed temporary file: {self.temp_file_path}")
                    except Exception as e:
                        logger.warning(f"Failed to remove temporary file {self.temp_file_path}: {e}")
                
            logger.debug(f"VirtualFileAccess resources for {self.file_path} released")
        except Exception as e:
            logger.error(f"Error closing VirtualFileAccess resources: {e}")
            
    def get_file_size(self) -> int:
        """
        Get the size of the file.
        
        Returns:
            File size in bytes
        """
        return self.file_size
        
    def read(self, offset: int, size: int) -> bytes:
        """
        Read data from the file.
        
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
            logger.warning(f"Invalid read parameters: offset={offset}, size={size}")
            return b''
            
        if offset >= self.file_size:
            logger.warning(f"Read offset {offset} beyond file size {self.file_size}")
            return b''
            
        # Adjust size to not read beyond file end
        if offset + size > self.file_size:
            original_size = size
            size = self.file_size - offset
            logger.debug(f"Adjusted read size from {original_size} to {size} to fit file bounds")
        
        try:
            # Read the raw data from chunks
            logger.debug(f"Reading from chunk_manager: offset={offset}, size={size}")
            data = self.chunk_manager.read_data(offset, size)
            
            if not data:
                logger.warning(f"chunk_manager.read_data returned empty data for offset={offset}, size={size}")
                
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
                        data[rel_offset:rel_offset+edit_size] = new_data[:edit_size]
            
            logger.debug(f"Read completed: got {len(data)} bytes from offset {offset}")
            
            # Force conversion to bytes and ensure we don't return None
            if data is None:
                logger.error("Data is None after applying edits")
                return b''
                
            # Make sure we always return bytes, not bytearray or other type
            result = bytes(data)
            if not result and size > 0:
                logger.warning(f"Empty result from read operation that expected {size} bytes")
            
            return result
        except Exception as e:
            logger.error(f"Exception in file_handler.read: {e}", exc_info=True)
            # Return empty data on error
            return b''
        
    def write(self, offset: int, data: bytes) -> bool:
        """
        Write data to the file.
        
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
            logger.error(f"Write operation would extend beyond file size: " +
                        f"offset {offset}, data size {len(data)}, file size {self.file_size}")
            return False
            
        # Read original data for undo purposes
        original_data = self.chunk_manager.read_data(offset, len(data))
        
        # Store the edit
        self.pending_edits[offset] = (original_data, data)
        logger.debug(f"Staged edit at offset {offset}, size {len(data)}")
        
        return True
        
    def apply_edits(self) -> bool:
        """
        Apply all pending edits to the file.
        
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
        except Exception as e:
            logger.error(f"Error applying edits to file: {e}")
            return False
            
    def undo_last_edit(self) -> bool:
        """
        Undo the last applied edit.
        
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
        except Exception as e:
            logger.error(f"Error undoing edit: {e}")
            return False
            
    def discard_edits(self):
        """Discard all pending edits without applying them."""
        self.pending_edits.clear()
        logger.info("Discarded all pending edits")